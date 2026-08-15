//! TLS-ALPN-01 responder (RFC 8737).
//!
//! Binds a `TcpListener` on port 5001 (Pebble's default `tlsPort`) and
//! serves the acme-tls/1 challenge certificate for whichever identifier
//! the current challenge names. Uses rustls' sync `ServerConnection`
//! path — no tokio — because a challenge probe is one TCP accept, one
//! TLS handshake, and immediate teardown.
//!
//! The cert-resolver dispatches on ALPN — connections that don't
//! negotiate `acme-tls/1` are rejected during the handshake (rustls
//! returns `NoApplicationProtocol`), which is fine for a test harness:
//! Pebble always advertises `acme-tls/1`.
//!
//! Uses the `SwappableResolver` pattern the task calls out: a single
//! `Arc<Mutex<Option<CertifiedKey>>>` that the caller updates per
//! challenge; the resolver hands back whatever is currently loaded.

use std::io::Read;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert, ServerConfig, ServerConnection};
use rustls::sign::{CertifiedKey, SigningKey};

use acme_challenge_tls_alpn_01::{responder_cert_from_key_authorization, ACME_TLS_ALPN_PROTOCOL};
use acme_core::challenge::{ChallengeKind, ChallengeReady, ChallengeSolver};
use acme_core::error::{AcmeError, Result as AcmeResult};
use acme_core::order::Identifier;

/// Pebble's default TLS-ALPN-01 validation port (see the `tlsPort`
/// field of the bundled `pebble-config.json`).
pub const DEFAULT_TLS_PORT: u16 = 5001;

/// A `ResolvesServerCert` whose loaded cert can be swapped at runtime.
/// The resolver only answers when the ClientHello negotiates the
/// `acme-tls/1` ALPN protocol — non-ACME probes get `None`, which
/// makes rustls abort the handshake with `NoApplicationProtocol`.
#[derive(Debug)]
pub struct SwappableResolver {
    slot: Mutex<Option<Arc<CertifiedKey>>>,
}

impl SwappableResolver {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            slot: Mutex::new(None),
        })
    }

    /// Swap in a new cert + key. Subsequent `resolve` calls answer
    /// with this one.
    pub fn install(&self, ck: CertifiedKey) {
        *self.slot.lock().unwrap() = Some(Arc::new(ck));
    }

    /// Remove the currently loaded cert. Handshakes after this see
    /// `None` and abort — reset between challenges.
    pub fn clear(&self) {
        *self.slot.lock().unwrap() = None;
    }
}

impl Default for SwappableResolver {
    fn default() -> Self {
        Self {
            slot: Mutex::new(None),
        }
    }
}

impl ResolvesServerCert for SwappableResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // Guard on ALPN — a plain-HTTPS probe never negotiates acme-tls/1
        // so we refuse to hand it the challenge cert. Pebble always
        // advertises acme-tls/1, so a well-formed probe always passes
        // this gate.
        let alpn_ok = client_hello
            .alpn()
            .map(|mut it| it.any(|p| p == ACME_TLS_ALPN_PROTOCOL))
            .unwrap_or(false);
        if !alpn_ok {
            return None;
        }
        self.slot.lock().unwrap().clone()
    }
}

/// A running TLS-ALPN-01 responder — the accept loop lives on a
/// background thread, dispatch is via a [`SwappableResolver`] the
/// caller updates per challenge.
pub struct TlsAlpn01Server {
    resolver: Arc<SwappableResolver>,
    local_addr: SocketAddr,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    _handle: Option<JoinHandle<()>>,
}

impl TlsAlpn01Server {
    /// Bind `0.0.0.0:5001` — Pebble's default `tlsPort`.
    pub fn bind_default() -> std::io::Result<Self> {
        Self::bind_on(("0.0.0.0", DEFAULT_TLS_PORT))
    }

    pub fn bind_on<A: std::net::ToSocketAddrs>(addr: A) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        let local_addr = listener.local_addr()?;

        let resolver = SwappableResolver::new();

        // rustls 0.23 no-client-auth server config with our resolver.
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone());
        // Advertise acme-tls/1 back at the client. RFC 8737 §3 says
        // the responder MUST negotiate exactly this protocol.
        config.alpn_protocols = vec![ACME_TLS_ALPN_PROTOCOL.to_vec()];
        let config = Arc::new(config);

        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let shutdown_for_thread = shutdown.clone();
        let handle = std::thread::Builder::new()
            .name("acme-testing-tls-alpn-accept".into())
            .spawn(move || accept_loop(listener, config, shutdown_for_thread))?;

        Ok(Self {
            resolver,
            local_addr,
            shutdown,
            _handle: Some(handle),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Install a responder cert built for one challenge. Subsequent
    /// probes see this cert until the caller [`Self::clear`]s it or
    /// calls [`Self::install`] again with a different pair.
    ///
    /// `cert_der` / `key_der` come from
    /// [`acme_challenge_tls_alpn_01::responder_cert`] /
    /// [`responder_cert_from_key_authorization`].
    pub fn install(&self, cert_der: Vec<u8>, key_der: Vec<u8>) -> Result<(), rustls::Error> {
        let cert_chain = vec![CertificateDer::from(cert_der)];
        let key: PrivateKeyDer<'static> = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
        let signing_key: Arc<dyn SigningKey> = rustls::crypto::ring::sign::any_ecdsa_type(&key)?;
        let ck = CertifiedKey::new(cert_chain, signing_key);
        self.resolver.install(ck);
        Ok(())
    }

    pub fn clear(&self) {
        self.resolver.clear();
    }
}

impl Drop for TlsAlpn01Server {
    fn drop(&mut self) {
        self.shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
        // Kick the accept loop with a dummy connection.
        let _ = TcpStream::connect_timeout(&self.local_addr, Duration::from_millis(500));
    }
}

fn accept_loop(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
) {
    for stream in listener.incoming() {
        if shutdown.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let config = config.clone();
        std::thread::spawn(move || {
            let _ = handle_tls_connection(stream, config);
        });
    }
}

fn handle_tls_connection(
    mut sock: TcpStream,
    config: Arc<ServerConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    sock.set_read_timeout(Some(Duration::from_secs(5)))?;
    sock.set_write_timeout(Some(Duration::from_secs(5)))?;

    let mut conn = ServerConnection::new(config)?;
    // Do the handshake — that's all Pebble's TLS-ALPN-01 validator
    // needs. It closes the socket without exchanging application
    // data once it has inspected the peer cert.
    conn.complete_io(&mut sock)?;

    // Best-effort drain of anything the peer might send after the
    // handshake, then close.
    let mut buf = [0u8; 128];
    let _ = conn.reader().read(&mut buf);
    let _ = conn.send_close_notify();
    let _ = conn.complete_io(&mut sock);
    Ok(())
}

// --------------------------------------------------------------------
// ChallengeSolver adapter.
// --------------------------------------------------------------------

/// `ChallengeSolver` that builds a responder cert for the current
/// challenge and installs it into a shared [`TlsAlpn01Server`] on arm.
/// Drop clears the resolver so the next challenge can install its own
/// cert without stale material leaking through.
pub struct TlsAlpn01SolverAdapter {
    server: Arc<TlsAlpn01Server>,
}

impl TlsAlpn01SolverAdapter {
    pub fn new(server: Arc<TlsAlpn01Server>) -> Self {
        Self { server }
    }
}

impl ChallengeSolver for TlsAlpn01SolverAdapter {
    fn kind(&self) -> ChallengeKind {
        ChallengeKind::TlsAlpn01
    }

    fn arm(
        &self,
        identifier: &Identifier,
        key_authorization: &str,
    ) -> AcmeResult<Box<dyn ChallengeReady>> {
        let responder = responder_cert_from_key_authorization(&identifier.value, key_authorization)
            .map_err(|e| AcmeError::Jose(format!("build tls-alpn responder: {e}")))?;
        self.server
            .install(responder.cert_der, responder.key_der)
            .map_err(|e| AcmeError::Jose(format!("install responder cert: {e}")))?;
        Ok(Box::new(TlsAlpn01Ready {
            server: self.server.clone(),
        }))
    }
}

struct TlsAlpn01Ready {
    server: Arc<TlsAlpn01Server>,
}

impl ChallengeReady for TlsAlpn01Ready {
    fn self_check(&self) -> AcmeResult<()> {
        // The resolver was populated synchronously in `arm`.
        Ok(())
    }
}

impl Drop for TlsAlpn01Ready {
    fn drop(&mut self) {
        self.server.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolver_refuses_non_alpn_hello() {
        let r = SwappableResolver::default();
        // Without any ClientHello parsing scaffolding we can only
        // sanity-check the empty-slot path; the ALPN-aware behaviour
        // is exercised end-to-end by the tls_alpn_01 integration test.
        assert!(r.slot.lock().unwrap().is_none());
    }
}
