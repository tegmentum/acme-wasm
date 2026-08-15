//! RFC 8555 §6.5 — replay-nonce handling.
//!
//! Every ACME POST carries a `nonce` in its protected header. The
//! server returns a fresh `Replay-Nonce` header on every response;
//! the client uses that value on the next request. When the client
//! has none, it does a `HEAD` against the `newNonce` URL from the
//! directory (§7.2) to prime the pump.
//!
//! CAs MAY send more than one `Replay-Nonce` in a burst, so we keep a
//! small queue rather than a single slot. Every method takes `&self`
//! so the store can be shared behind an `Arc` across the request
//! handlers that need it.

use crate::error::{AcmeError, Result};
use crate::transport::{HttpClient, HttpResponse};
use std::collections::VecDeque;
use std::sync::Mutex;

/// A source of ACME nonces.
///
/// The trait exists so tests (and any exotic caller) can plug in a
/// deterministic nonce sequence without touching HTTP.
pub trait NonceSource: Send + Sync {
    /// Return one nonce, fetching a fresh one from the CA if the local
    /// pool is empty.
    fn get(&self) -> Result<String>;

    /// Extract every `Replay-Nonce` header from a CA response and add
    /// them to the pool. Called by the request pipeline after every
    /// non-nonce request (§6.5).
    fn absorb(&self, response: &HttpResponse);
}

/// Default [`NonceSource`] implementation: a mutex-guarded FIFO of
/// nonces topped up by HEADing the directory's `newNonce` URL when
/// empty.
pub struct ReplayNonceStore {
    /// The `newNonce` URL from the directory.
    new_nonce_url: String,
    /// Transport used to fetch a fresh nonce.
    transport: std::sync::Arc<dyn HttpClient>,
    /// FIFO of unused nonces.
    pool: Mutex<VecDeque<String>>,
}

impl ReplayNonceStore {
    /// Build a store bound to a specific `newNonce` URL. The store
    /// holds an `Arc` to the transport so it can be shared with the
    /// rest of the request pipeline.
    pub fn new(
        new_nonce_url: impl Into<String>,
        transport: std::sync::Arc<dyn HttpClient>,
    ) -> Self {
        Self {
            new_nonce_url: new_nonce_url.into(),
            transport,
            pool: Mutex::new(VecDeque::new()),
        }
    }

    /// Discard every cached nonce. Called on `badNonce` retry paths.
    pub fn clear(&self) {
        self.pool.lock().unwrap().clear();
    }

    /// Prime the pool by HEADing `newNonce` — §7.2 requires the server
    /// to respond with a `Replay-Nonce` header and a 200 (or 204)
    /// status. Called internally by [`get`] when the pool is empty.
    fn refill(&self) -> Result<()> {
        let response = self.transport.head(&self.new_nonce_url)?;
        if !(200..300).contains(&response.status) {
            return Err(AcmeError::Transport(format!(
                "newNonce HEAD returned status {}",
                response.status
            )));
        }
        self.absorb(&response);
        if self.pool.lock().unwrap().is_empty() {
            return Err(AcmeError::MissingField(
                "Replay-Nonce on newNonce response".into(),
            ));
        }
        Ok(())
    }
}

impl NonceSource for ReplayNonceStore {
    fn get(&self) -> Result<String> {
        if let Some(n) = self.pool.lock().unwrap().pop_front() {
            return Ok(n);
        }
        self.refill()?;
        self.pool
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| AcmeError::MissingField("Replay-Nonce on newNonce response".into()))
    }

    fn absorb(&self, response: &HttpResponse) {
        for value in response.headers_all("Replay-Nonce") {
            if !value.is_empty() {
                self.pool.lock().unwrap().push_back(value.to_string());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::HttpResponse;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct ScriptedTransport {
        head_calls: AtomicUsize,
        responses: Mutex<Vec<HttpResponse>>,
    }

    impl HttpClient for ScriptedTransport {
        fn head(&self, _url: &str) -> Result<HttpResponse> {
            self.head_calls.fetch_add(1, Ordering::SeqCst);
            let mut q = self.responses.lock().unwrap();
            Ok(q.remove(0))
        }
        fn get(&self, _url: &str) -> Result<HttpResponse> {
            unreachable!()
        }
        fn post_jose(&self, _url: &str, _body: &[u8]) -> Result<HttpResponse> {
            unreachable!()
        }
    }

    fn nonce_response(nonces: &[&str]) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: nonces
                .iter()
                .map(|n| ("Replay-Nonce".to_string(), (*n).to_string()))
                .collect(),
            body: vec![],
        }
    }

    #[test]
    fn get_fetches_nonce_on_first_call() {
        let transport = std::sync::Arc::new(ScriptedTransport {
            head_calls: AtomicUsize::new(0),
            responses: Mutex::new(vec![nonce_response(&["one"])]),
        });
        let store = ReplayNonceStore::new("https://ca/nn", transport.clone());
        assert_eq!(store.get().unwrap(), "one");
        assert_eq!(transport.head_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn absorb_pushes_nonces_from_response() {
        let transport = std::sync::Arc::new(ScriptedTransport {
            head_calls: AtomicUsize::new(0),
            responses: Mutex::new(vec![]),
        });
        let store = ReplayNonceStore::new("https://ca/nn", transport);
        store.absorb(&nonce_response(&["a", "b"]));
        assert_eq!(store.get().unwrap(), "a");
        assert_eq!(store.get().unwrap(), "b");
    }

    #[test]
    fn get_only_hits_transport_when_pool_empty() {
        let transport = std::sync::Arc::new(ScriptedTransport {
            head_calls: AtomicUsize::new(0),
            responses: Mutex::new(vec![nonce_response(&["fetched"])]),
        });
        let store = ReplayNonceStore::new("https://ca/nn", transport.clone());
        store.absorb(&nonce_response(&["cached"]));
        assert_eq!(store.get().unwrap(), "cached");
        assert_eq!(transport.head_calls.load(Ordering::SeqCst), 0);
        assert_eq!(store.get().unwrap(), "fetched");
        assert_eq!(transport.head_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn refill_without_replay_nonce_header_errors() {
        let transport = std::sync::Arc::new(ScriptedTransport {
            head_calls: AtomicUsize::new(0),
            responses: Mutex::new(vec![HttpResponse {
                status: 200,
                headers: vec![],
                body: vec![],
            }]),
        });
        let store = ReplayNonceStore::new("https://ca/nn", transport);
        assert!(matches!(
            store.get().unwrap_err(),
            AcmeError::MissingField(_)
        ));
    }
}
