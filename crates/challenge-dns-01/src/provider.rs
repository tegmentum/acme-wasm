//! DNS provider trait — the seam concrete `dns-providers/*` crates
//! implement so DNS-01 stays transport-free.
//!
//! Rationale for a `RecordHandle` opaque type: some provider APIs
//! (Cloudflare, Route 53 with weighted routing) return a stable
//! record id that lets a subsequent delete target exactly the record
//! we created. Others (Route 53 with SIMPLE routing) can only
//! `delete-by-value` and don't have a natural id — those providers
//! return an empty handle and match by `(name, value)` on delete.
//! Encoding this in one shape keeps the trait object-safe.

use std::sync::Mutex;

use thiserror::Error;

/// Opaque per-record cookie the provider hands back from `upsert_txt`
/// and the caller passes to `delete_txt`. The provider decides the
/// interpretation — id, `(name, value)` tuple string, whatever.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecordHandle(pub String);

impl RecordHandle {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Error)]
pub enum DnsProviderError {
    /// The provider rejected the request (auth, quota, malformed).
    #[error("provider rejected request: {0}")]
    Rejected(String),

    /// The provider's transport failed (network, TLS, 5xx).
    #[error("provider transport error: {0}")]
    Transport(String),

    /// The provider does not manage the requested zone.
    #[error("provider does not manage zone for `{0}`")]
    ZoneNotFound(String),

    /// Timed out while waiting for record propagation.
    #[error("timed out waiting for TXT `{name}` to propagate")]
    PropagationTimeout { name: String },
}

/// Provision + tear down DNS TXT records.
///
/// All methods are synchronous — matching `acme-core::HttpClient`,
/// which is `&self` sync too. Async provider crates should expose a
/// sync facade that blocks on their runtime; there is no async ACME
/// state machine to interleave with.
pub trait DnsProvider: Send + Sync {
    /// Publish (or replace) a TXT record. Returns a handle the caller
    /// passes back to [`Self::delete_txt`] for cleanup.
    fn upsert_txt(
        &self,
        name: &str,
        value: &str,
        ttl_seconds: u32,
    ) -> Result<RecordHandle, DnsProviderError>;

    /// Remove a previously-published record. Idempotent — deleting a
    /// missing record must return `Ok(())`.
    fn delete_txt(&self, handle: &RecordHandle) -> Result<(), DnsProviderError>;
}

/// In-memory `DnsProvider` for tests and dry-runs. Records live in a
/// `Vec<(name, value, handle)>` so tests can `snapshot()` the live set
/// at any point.
#[derive(Default)]
pub struct MockDnsProvider {
    inner: Mutex<Vec<(String, String, String)>>,
}

impl MockDnsProvider {
    /// A copy of the current live records as `(name, value)` pairs. Test-only.
    pub fn snapshot(&self) -> Vec<(String, String)> {
        self.inner
            .lock()
            .unwrap()
            .iter()
            .map(|(n, v, _)| (n.clone(), v.clone()))
            .collect()
    }
}

impl DnsProvider for MockDnsProvider {
    fn upsert_txt(
        &self,
        name: &str,
        value: &str,
        _ttl_seconds: u32,
    ) -> Result<RecordHandle, DnsProviderError> {
        let mut records = self.inner.lock().unwrap();
        // Deterministic-per-name handle so tests can assert on it.
        let handle = format!("mock-{}-{}", records.len(), name);
        records.push((name.to_string(), value.to_string(), handle.clone()));
        Ok(RecordHandle::new(handle))
    }

    fn delete_txt(&self, handle: &RecordHandle) -> Result<(), DnsProviderError> {
        let mut records = self.inner.lock().unwrap();
        // Idempotent — silently succeed if the handle is unknown.
        records.retain(|(_, _, h)| h != handle.as_str());
        Ok(())
    }
}
