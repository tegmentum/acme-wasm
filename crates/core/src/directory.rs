//! RFC 8555 §7.1.1 — the ACME directory object.
//!
//! Every ACME client bootstraps from a single URL: the CA's directory.
//! The response is a JSON object mapping resource names
//! (`newAccount`, `newOrder`, `newNonce`, `revokeCert`, `keyChange`,
//! optionally `renewalInfo` per RFC 9773) to their absolute URLs, plus
//! a `meta` block carrying the terms-of-service URL, the CAA identities
//! list, and any external-account-binding requirement flag.

use crate::error::{AcmeError, Result};
use crate::transport::HttpClient;
use serde::{Deserialize, Serialize};

/// Deserialized directory object.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Directory {
    #[serde(rename = "newNonce")]
    pub new_nonce: String,
    #[serde(rename = "newAccount")]
    pub new_account: String,
    #[serde(rename = "newOrder")]
    pub new_order: String,
    /// `newAuthz` is optional — an ACME server MAY omit it, in which
    /// case the client cannot pre-authorize identifiers (§7.4.1).
    #[serde(rename = "newAuthz", default)]
    pub new_authz: Option<String>,
    #[serde(rename = "revokeCert")]
    pub revoke_cert: String,
    #[serde(rename = "keyChange")]
    pub key_change: String,
    /// ACME Renewal Information (RFC 9773) endpoint, when advertised.
    #[serde(rename = "renewalInfo", default)]
    pub renewal_info: Option<String>,
    #[serde(default)]
    pub meta: Meta,
}

/// The `meta` sub-object (RFC 8555 §7.1.1).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Meta {
    /// URL to the CA's terms of service. Callers must display / accept
    /// this before setting `termsOfServiceAgreed=true` on `newAccount`.
    #[serde(rename = "termsOfService", default)]
    pub terms_of_service: Option<String>,
    /// Website landing page for the CA.
    #[serde(default)]
    pub website: Option<String>,
    /// DNS names the CA recognises as its own for CAA matching.
    #[serde(rename = "caaIdentities", default)]
    pub caa_identities: Vec<String>,
    /// If true, `newAccount` requests MUST include an
    /// `externalAccountBinding` field (§7.3.4).
    #[serde(rename = "externalAccountRequired", default)]
    pub external_account_required: bool,
    /// Free-form profile metadata (Let's Encrypt uses this to advertise
    /// their ARI implementation, for instance).
    #[serde(default, flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// GET the directory URL and deserialize the response body.
///
/// The transport is the seam: pass any [`HttpClient`] — a native
/// reqwest impl, a wasi:http-driven adapter, or an in-crate stub.
pub fn fetch(base_url: &str, transport: &dyn HttpClient) -> Result<Directory> {
    let response = transport.get(base_url)?.ok()?;
    parse(&response.body)
}

/// Parse a directory JSON body without doing any I/O.
pub fn parse(body: &[u8]) -> Result<Directory> {
    serde_json::from_slice(body).map_err(|e| AcmeError::Serialization(format!("directory: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::HttpResponse;
    use std::sync::Mutex;

    /// The Let's Encrypt staging directory JSON, captured 2024-05.
    /// Kept in a fixture file so refreshing it does not touch source.
    const STAGING_FIXTURE: &str = include_str!("../fixtures/lets-encrypt-staging-directory.json");

    #[test]
    fn parses_lets_encrypt_staging_fixture() {
        let dir = parse(STAGING_FIXTURE.as_bytes()).expect("staging fixture parses");
        assert_eq!(
            dir.new_nonce,
            "https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce"
        );
        assert_eq!(
            dir.new_account,
            "https://acme-staging-v02.api.letsencrypt.org/acme/new-acct"
        );
        assert_eq!(
            dir.new_order,
            "https://acme-staging-v02.api.letsencrypt.org/acme/new-order"
        );
        assert_eq!(
            dir.revoke_cert,
            "https://acme-staging-v02.api.letsencrypt.org/acme/revoke-cert"
        );
        assert_eq!(
            dir.key_change,
            "https://acme-staging-v02.api.letsencrypt.org/acme/key-change"
        );
        assert_eq!(
            dir.meta.terms_of_service.as_deref(),
            Some("https://letsencrypt.org/documents/LE-SA-v1.4-April-3-2024.pdf")
        );
        assert!(dir
            .meta
            .caa_identities
            .iter()
            .any(|s| s == "letsencrypt.org"));
    }

    #[test]
    fn missing_required_field_is_serialization_error() {
        let body = br#"{"newNonce":"x"}"#;
        match parse(body) {
            Err(AcmeError::Serialization(_)) => {}
            other => panic!("expected Serialization error, got {other:?}"),
        }
    }

    /// Stub transport that returns a pre-baked response for every GET.
    struct StaticGet {
        response: HttpResponse,
        calls: Mutex<Vec<String>>,
    }

    impl HttpClient for StaticGet {
        fn head(&self, _url: &str) -> Result<HttpResponse> {
            unimplemented!("directory fetch never HEADs")
        }
        fn get(&self, url: &str) -> Result<HttpResponse> {
            self.calls.lock().unwrap().push(url.to_string());
            Ok(self.response.clone())
        }
        fn post_jose(&self, _url: &str, _body: &[u8]) -> Result<HttpResponse> {
            unimplemented!("directory fetch never POSTs")
        }
    }

    #[test]
    fn fetch_uses_transport_get() {
        let transport = StaticGet {
            response: HttpResponse {
                status: 200,
                headers: vec![("Content-Type".into(), "application/json".into())],
                body: STAGING_FIXTURE.as_bytes().to_vec(),
            },
            calls: Mutex::new(vec![]),
        };
        let dir = fetch(
            "https://acme-staging-v02.api.letsencrypt.org/directory",
            &transport,
        )
        .expect("fetch");
        assert!(dir.new_nonce.starts_with("https://"));
        assert_eq!(
            transport.calls.lock().unwrap().as_slice(),
            ["https://acme-staging-v02.api.letsencrypt.org/directory"]
        );
    }
}
