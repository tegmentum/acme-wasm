//! `DnsProvider` implementation that talks to
//! [pebble-challtestsrv](https://github.com/letsencrypt/pebble/tree/main/cmd/pebble-challtestsrv)'s
//! HTTP admin API.
//!
//! Purpose: DNS-01 integration tests need somewhere Pebble can
//! actually resolve TXT records from. `pebble-challtestsrv` ships a
//! mock DNS server that Pebble uses (via `-dnsserver challtestsrv:8053`
//! in the compose file) and exposes an HTTP admin API for seeding
//! answers. This provider is a thin blocking `reqwest` client for that
//! API — every `upsert_txt` becomes one `POST /set-txt`, every
//! `delete_txt` a `POST /clear-txt`.
//!
//! The provider stores the record `name` in its `RecordHandle` so
//! `delete_txt` doesn't need to be threaded back through the caller
//! separately.

use std::sync::Arc;

use acme_challenge_dns_01::provider::{DnsProvider, DnsProviderError, RecordHandle};
use acme_challenge_dns_01::{record_name, Dns01Record};
use acme_core::challenge::{ChallengeKind, ChallengeReady, ChallengeSolver};
use acme_core::error::{AcmeError, Result as AcmeResult};
use acme_core::order::Identifier;

/// Blocking HTTP client for pebble-challtestsrv's admin API.
///
/// The admin URL is `http://localhost:8055` by default (see the
/// harness compose file). Every call is a one-shot POST; TTL is
/// silently ignored because the mock server returns whatever value is
/// currently loaded.
pub struct ChallTestSrvProvider {
    base_url: String,
    client: reqwest::blocking::Client,
}

impl ChallTestSrvProvider {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            client: reqwest::blocking::Client::new(),
        }
    }

    fn post(&self, path: &str, body: &serde_json::Value) -> Result<(), DnsProviderError> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .client
            .post(&url)
            .json(body)
            .send()
            .map_err(|e| DnsProviderError::Transport(e.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().unwrap_or_default();
            return Err(DnsProviderError::Rejected(format!(
                "challtestsrv {url} → {status}: {text}"
            )));
        }
        Ok(())
    }
}

impl DnsProvider for ChallTestSrvProvider {
    fn upsert_txt(
        &self,
        name: &str,
        value: &str,
        _ttl_seconds: u32,
    ) -> Result<RecordHandle, DnsProviderError> {
        let fqdn = fqdn(name);
        self.post(
            "/set-txt",
            &serde_json::json!({ "host": fqdn, "value": value }),
        )?;
        // Handle carries the FQDN so delete_txt can undo without
        // recomputing it.
        Ok(RecordHandle::new(fqdn))
    }

    fn delete_txt(&self, handle: &RecordHandle) -> Result<(), DnsProviderError> {
        self.post(
            "/clear-txt",
            &serde_json::json!({ "host": handle.as_str() }),
        )
    }
}

fn fqdn(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    }
}

// --------------------------------------------------------------------
// ChallengeSolver adapter — turns the provider into something the
// acme_core::issue_certificate driver can consume directly.
// --------------------------------------------------------------------

/// `ChallengeSolver` that provisions the DNS-01 TXT record through a
/// [`DnsProvider`] on arm, and cleans it up on drop.
///
/// Kept generic over the provider so the same adapter can drive a real
/// production provider (Cloudflare, Route 53) as well as the
/// challtestsrv mock used here.
pub struct DnsSolverAdapter<P: DnsProvider + 'static> {
    provider: Arc<P>,
}

impl<P: DnsProvider + 'static> DnsSolverAdapter<P> {
    pub fn new(provider: Arc<P>) -> Self {
        Self { provider }
    }
}

impl<P: DnsProvider + 'static> ChallengeSolver for DnsSolverAdapter<P> {
    fn kind(&self) -> ChallengeKind {
        ChallengeKind::Dns01
    }

    fn arm(
        &self,
        identifier: &Identifier,
        key_authorization: &str,
    ) -> AcmeResult<Box<dyn ChallengeReady>> {
        // acme_challenge_dns_01::record() wants the token + account
        // key, but the driver already computed the key authorization
        // for us. Recompute the SHA-256 → base64url step directly.
        use base64::Engine;
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(key_authorization.as_bytes());
        let value = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());
        let name = record_name(&identifier.value);
        let record = Dns01Record {
            name: name.clone(),
            value,
            ttl_seconds: 60,
        };

        let handle = self
            .provider
            .upsert_txt(&record.name, &record.value, record.ttl_seconds)
            .map_err(|e| AcmeError::Transport(format!("dns provider upsert: {e}")))?;

        Ok(Box::new(DnsReady {
            provider: self.provider.clone(),
            handle,
        }))
    }
}

struct DnsReady<P: DnsProvider + 'static> {
    provider: Arc<P>,
    handle: RecordHandle,
}

impl<P: DnsProvider + 'static> ChallengeReady for DnsReady<P> {
    fn self_check(&self) -> AcmeResult<()> {
        // Pebble reads records straight from challtestsrv's in-memory
        // map, so there's no propagation delay to wait on here.
        Ok(())
    }
}

impl<P: DnsProvider + 'static> Drop for DnsReady<P> {
    fn drop(&mut self) {
        let _ = self.provider.delete_txt(&self.handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fqdn_appends_trailing_dot_once() {
        assert_eq!(fqdn("_acme-challenge.example.com"), "_acme-challenge.example.com.");
        assert_eq!(fqdn("_acme-challenge.example.com."), "_acme-challenge.example.com.");
    }
}
