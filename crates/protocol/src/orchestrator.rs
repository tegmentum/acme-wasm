//! wit-bindgen adapter for the `orchestrator` interface.
//!
//! `issue-certificate` is a placeholder in the raw `acme-protocol`
//! component. The protocol crate is I/O-free by design — it holds no
//! `wasi:http` capability of its own, so it cannot fetch the directory,
//! POST-as-GET authorizations, or download the issued chain. Wiring an
//! end-to-end issuance requires a `wac plug` composition against a
//! component that exports `HttpClient` (typically `acme-http-client`);
//! after that step the composed component's `issue-certificate` runs
//! the full RFC 8555 flow via `acme_core::issue_certificate`.
//!
//! Calling into the un-composed component returns
//! `acme-error::other(...)` describing the composition requirement so
//! callers get a clear, machine-inspectable signal instead of an
//! opaque trap.

use crate::exports::tegmentum::acme::orchestrator::{
    AcmeError, Identifier as OrchestratorIdentifier, IssuedCertificate,
};

const NOT_COMPOSED_MESSAGE: &str =
    "acme-protocol orchestrator has no HTTP capability of its own; \
     compose this component with acme-http-client (or any component \
     exporting an HttpClient) via `wac plug` before calling \
     issue-certificate";

pub fn issue_certificate(
    _directory_url: String,
    _contact: Vec<String>,
    _identifiers: Vec<OrchestratorIdentifier>,
    _cert_key_pem: String,
    _account_key_jwk: String,
) -> Result<IssuedCertificate, AcmeError> {
    // Deliberately no work here — see the module doc. When the
    // composition story lands (i.e. this world imports an HTTP-client
    // interface), swap the body for a delegate that translates the
    // JWK-in / PEM-in inputs into `acme_core::AccountKey` /
    // `acme_core::csr::CertificateKey`, picks a solver based on which
    // challenge the CA offers, and calls
    // `acme_core::issue_certificate`.
    Err(AcmeError::Other(NOT_COMPOSED_MESSAGE.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The un-composed orchestrator must surface a clear `other(...)`
    /// error rather than trap or silently return an empty cert.
    #[test]
    fn issue_certificate_returns_composition_hint() {
        let err = issue_certificate(
            "https://ca.example/directory".to_string(),
            vec!["mailto:ops@example.com".to_string()],
            vec![OrchestratorIdentifier {
                kind: "dns".to_string(),
                value: "example.com".to_string(),
            }],
            "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n".to_string(),
            "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"...\",\"y\":\"...\"}".to_string(),
        )
        .unwrap_err();
        match err {
            AcmeError::Other(msg) => {
                assert!(
                    msg.contains("wac plug"),
                    "composition hint should mention wac plug: {msg}"
                );
                assert!(
                    msg.contains("acme-http-client"),
                    "composition hint should name the HTTP component: {msg}"
                );
            }
            other => panic!("expected AcmeError::Other, got {other:?}"),
        }
    }
}
