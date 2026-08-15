//! RFC 8555 §8.4 — DNS-01 challenge solver + [`DnsProvider`] trait.
//!
//! The client provisions a TXT record at
//! `_acme-challenge.<identifier>` whose value is
//! `base64url(SHA-256(key-authorization))` — the same hash TLS-ALPN-01
//! embeds in the responder cert, only base64url-encoded instead of
//! raw DER-wrapped.
//!
//! DNS-01 is the only challenge type that supports wildcard
//! identifiers (`*.example.com`); the record still lives on the base
//! domain, not on the wildcard.
//!
//! The solver is I/O-free: it computes the `(name, value)` pair a
//! [`DnsProvider`] must publish. Cleanup + propagation-wait live on the
//! provider so per-provider APIs (per-record-id vs. delete-by-value,
//! authoritative-server list vs. blind wait) can differ.

use acme_core::jws::AccountKey;

pub mod provider;

pub use provider::{DnsProvider, DnsProviderError, RecordHandle};

/// The TXT record name the ACME validator will resolve, given an
/// identifier. Strips a leading `*.` because the wildcard's underlying
/// domain owns the challenge record (RFC 8555 §8.4).
///
/// ```text
/// example.com     -> _acme-challenge.example.com
/// *.example.com   -> _acme-challenge.example.com
/// ```
pub fn record_name(identifier: &str) -> String {
    let base = identifier.strip_prefix("*.").unwrap_or(identifier);
    format!("_acme-challenge.{base}")
}

/// The exact string the TXT record must serve:
/// `base64url(SHA-256(key-authorization))`. Delegates to the same
/// helper TLS-ALPN-01 uses so the two challenges stay bit-identical
/// on the hash-and-encoding path.
pub fn record_value(token: &str, account_key: &AccountKey) -> String {
    acme_core::challenge::sha256_key_authorization(token, account_key)
}

/// Everything a caller needs to publish one DNS-01 challenge: the FQDN
/// of the TXT record and its exact value. Rendered separately from
/// [`DnsProvider`] because sometimes a caller wants to publish through
/// a channel that isn't a `DnsProvider` (a Terraform-generated zone
/// file, a static-config load, an out-of-band operator).
#[derive(Debug, Clone)]
pub struct Dns01Record {
    pub name: String,
    pub value: String,
    /// TTL to request when writing. 60 seconds is a reasonable default
    /// — long enough that a validator's second lookup hits the same
    /// record, short enough that a delete-and-retry converges quickly.
    pub ttl_seconds: u32,
}

/// Convenience: build a `Dns01Record` from the token + account key in
/// one call.
pub fn record(identifier: &str, token: &str, account_key: &AccountKey) -> Dns01Record {
    Dns01Record {
        name: record_name(identifier),
        value: record_value(token, account_key),
        ttl_seconds: 60,
    }
}

/// End-to-end helper: publish the challenge record, run the caller's
/// verification, and always clean up on the way out (Drop-style).
///
/// Fails fast on `provider.upsert_txt` errors; on `f`'s error the
/// record is still deleted before returning. Delete errors during
/// cleanup are swallowed (best-effort) so the original failure isn't
/// masked.
pub fn with_provisioned_record<P, F, T>(
    provider: &P,
    identifier: &str,
    token: &str,
    account_key: &AccountKey,
    f: F,
) -> Result<T, DnsProviderError>
where
    P: DnsProvider,
    F: FnOnce(&Dns01Record) -> Result<T, DnsProviderError>,
{
    let record = record(identifier, token, account_key);
    let handle = provider.upsert_txt(&record.name, &record.value, record.ttl_seconds)?;
    let result = f(&record);
    let _ = provider.delete_txt(&handle);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use acme_core::jws::{AccountKey, EcdsaKey};

    fn test_account_key() -> AccountKey {
        let signing = p256::ecdsa::SigningKey::from_slice(&[0x11u8; 32]).expect("valid p256 seed");
        AccountKey::Ecdsa(EcdsaKey::P256(signing))
    }

    #[test]
    fn record_name_prepends_underscore_acme_challenge() {
        assert_eq!(record_name("example.com"), "_acme-challenge.example.com");
        assert_eq!(
            record_name("api.example.com"),
            "_acme-challenge.api.example.com"
        );
    }

    #[test]
    fn wildcard_identifier_strips_leading_star_dot() {
        assert_eq!(record_name("*.example.com"), "_acme-challenge.example.com");
    }

    #[test]
    fn record_value_matches_sha256_of_key_authorization() {
        let key = test_account_key();
        let v = record_value("tok-1", &key);
        // Ends up as 43 chars of base64url (SHA-256 → 32 bytes → 43
        // chars unpadded).
        assert_eq!(v.len(), 43);
        assert!(!v.contains('='));
    }

    #[test]
    fn with_provisioned_record_publishes_and_cleans_up() {
        let key = test_account_key();
        let mock = provider::MockDnsProvider::default();
        with_provisioned_record(&mock, "example.com", "tok-1", &key, |rec| {
            // Inside the closure, the record is live.
            assert_eq!(rec.name, "_acme-challenge.example.com");
            let live = mock.snapshot();
            assert_eq!(live.len(), 1);
            assert_eq!(live[0].0, "_acme-challenge.example.com");
            Ok(())
        })
        .expect("with_provisioned_record");
        // After the closure the record is gone.
        assert!(mock.snapshot().is_empty());
    }
}
