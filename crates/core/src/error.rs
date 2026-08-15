//! ACME error taxonomy.
//!
//! RFC 8555 §6.7 defines the ACME problem-document error type URIs
//! (`urn:ietf:params:acme:error:*`). Every error the CA returns is a
//! JSON problem document (RFC 7807) whose `type` field maps to one of
//! these codes. This module carries the enum, the URI-to-variant
//! parser, and JOSE / transport failures the client raises locally.
//!
//! Downstream crates return `Result<T, AcmeError>` — this is the only
//! error type in the public surface.

use serde::Deserialize;
use thiserror::Error;

/// Every failure mode the ACME core surfaces.
///
/// The `Problem*` variants correspond one-to-one with the type URIs
/// enumerated in RFC 8555 §6.7. `Transport`, `Serialization`, `Jose`,
/// `Timeout`, `MissingField`, `Http`, and `Other` are locally raised
/// (network, JSON, JWS, polling, missing header/field, non-problem-JSON
/// HTTP failures, and a catch-all respectively).
#[derive(Debug, Error)]
pub enum AcmeError {
    // -- RFC 8555 §6.7 problem-document error codes ----------------------
    //
    // urn:ietf:params:acme:error:badCSR — the CSR is unacceptable
    // (identifier mismatch, weak key, disallowed extension, …).
    #[error("badCSR: {0}")]
    BadCsr(String),

    /// urn:ietf:params:acme:error:badNonce — client-supplied nonce was
    /// rejected (§6.5). The client MUST retry with a fresh nonce.
    #[error("badNonce: {0}")]
    BadNonce(String),

    /// urn:ietf:params:acme:error:badPublicKey — the account or CSR
    /// public key is not on the CA's allow list (algorithm / size).
    #[error("badPublicKey: {0}")]
    BadPublicKey(String),

    /// urn:ietf:params:acme:error:badRevocationReason — the caller
    /// supplied an unsupported revocation reason code.
    #[error("badRevocationReason: {0}")]
    BadRevocationReason(String),

    /// urn:ietf:params:acme:error:badSignatureAlgorithm — the JWS
    /// `alg` is not on the CA's allow list (§6.2).
    #[error("badSignatureAlgorithm: {0}")]
    BadSignatureAlgorithm(String),

    /// urn:ietf:params:acme:error:caa — CAA records forbid this CA
    /// from issuing for the identifier.
    #[error("caa: {0}")]
    Caa(String),

    /// urn:ietf:params:acme:error:compound — several sub-problems
    /// bundled in one problem document (§6.7.1).
    #[error("compound: {0}")]
    Compound(String),

    /// urn:ietf:params:acme:error:connection — CA could not connect
    /// to the identifier's endpoint during validation.
    #[error("connection: {0}")]
    Connection(String),

    /// urn:ietf:params:acme:error:dns — CA hit a DNS failure during
    /// validation (NXDOMAIN, SERVFAIL, DNSSEC bogus, etc.).
    #[error("dns: {0}")]
    Dns(String),

    /// urn:ietf:params:acme:error:externalAccountRequired — this CA
    /// requires an EAB (external account binding, §7.3.4) and the
    /// request did not include one.
    #[error("externalAccountRequired: {0}")]
    ExternalAccountRequired(String),

    /// urn:ietf:params:acme:error:incorrectResponse — validation
    /// probe returned the wrong response (wrong key authorization).
    #[error("incorrectResponse: {0}")]
    IncorrectResponse(String),

    /// urn:ietf:params:acme:error:invalidContact — contact URL failed
    /// server-side validation (RFC 8555 §7.3).
    #[error("invalidContact: {0}")]
    InvalidContact(String),

    /// urn:ietf:params:acme:error:malformed — request violates a
    /// protocol constraint (missing field, wrong shape, JWS not
    /// well-formed, …). Broad catch-all on the CA side.
    #[error("malformed: {0}")]
    Malformed(String),

    /// urn:ietf:params:acme:error:orderNotReady — client asked to
    /// finalize an order that has not reached the `ready` state (§7.4).
    #[error("orderNotReady: {0}")]
    OrderNotReady(String),

    /// urn:ietf:params:acme:error:rateLimited — CA is throttling
    /// this account / IP / identifier.
    #[error("rateLimited: {0}")]
    RateLimited(String),

    /// urn:ietf:params:acme:error:rejectedIdentifier — CA refuses to
    /// issue for this identifier (blocklist, policy, …).
    #[error("rejectedIdentifier: {0}")]
    RejectedIdentifier(String),

    /// urn:ietf:params:acme:error:serverInternal — CA hit an internal
    /// error; clients typically retry with backoff.
    #[error("serverInternal: {0}")]
    ServerInternal(String),

    /// urn:ietf:params:acme:error:tls — validation probe hit a TLS
    /// error (bad cert, wrong ALPN, handshake failure).
    #[error("tls: {0}")]
    Tls(String),

    /// urn:ietf:params:acme:error:unauthorized — client is not
    /// authorized for the requested action.
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// urn:ietf:params:acme:error:unsupportedContact — contact scheme
    /// (e.g. `sms:`) is not supported by this CA.
    #[error("unsupportedContact: {0}")]
    UnsupportedContact(String),

    /// urn:ietf:params:acme:error:unsupportedIdentifier — identifier
    /// type (e.g. `email`) is not supported by this CA.
    #[error("unsupportedIdentifier: {0}")]
    UnsupportedIdentifier(String),

    /// urn:ietf:params:acme:error:userActionRequired — human action
    /// required (usually accepting new ToS after `keyChange` /
    /// account update). Problem document carries an `instance` URL.
    #[error("userActionRequired: {0}")]
    UserActionRequired(String),

    /// urn:ietf:params:acme:error:accountDoesNotExist — CA could not
    /// find the account referenced by the request's `kid`.
    #[error("accountDoesNotExist: {0}")]
    AccountDoesNotExist(String),

    /// urn:ietf:params:acme:error:alreadyRevoked — revoke request
    /// for a certificate already marked revoked.
    #[error("alreadyRevoked: {0}")]
    AlreadyRevoked(String),

    /// urn:ietf:params:acme:error:badRevoked (colloquial "badRevoked")
    /// — CA reports the cert is revoked but the client's operation
    /// depends on it being valid.
    #[error("badRevoked: {0}")]
    BadRevoked(String),

    // -- Locally raised, non-RFC-8555 -----------------------------------
    /// HTTP-layer failure (connection reset, DNS timeout, TLS error,
    /// wasi:http trap) — everything the transport surfaces as "we
    /// never got a well-formed response".
    #[error("transport: {0}")]
    Transport(String),

    /// JSON / PEM / base64 / header-parsing failure. Used when the CA
    /// response is well-formed HTTP but the body cannot be
    /// deserialized into the expected shape.
    #[error("serialization: {0}")]
    Serialization(String),

    /// JWS assembly or signing failure — bad key, wrong signature
    /// length, missing header field. Distinct from `Malformed` (which
    /// is the CA's rejection of a well-formed JWS).
    #[error("jose: {0}")]
    Jose(String),

    /// Polling / long-running operation hit its deadline.
    #[error("timeout: {0}")]
    Timeout(String),

    /// A required response header or JSON field was absent. Captures
    /// the field name so the caller can log which piece is missing.
    #[error("missing field: {0}")]
    MissingField(String),

    /// CA returned an HTTP failure with a body that is NOT an ACME
    /// problem document — status + first chunk of body preserved so
    /// the caller can log or surface.
    #[error("http {status}: {body}")]
    Http { status: u16, body: String },

    /// Catch-all for problem-document type URIs the taxonomy above
    /// does not enumerate. The variant carries the original URI plus
    /// the human `detail` string so downstream callers can still make
    /// policy decisions.
    #[error("{0}")]
    Other(String),
}

/// RFC 7807 problem document — the JSON body the CA returns on any
/// non-2xx response, carried under `Content-Type: application/problem+json`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ProblemDocument {
    /// Problem type URI. For ACME errors this looks like
    /// `urn:ietf:params:acme:error:<code>`.
    #[serde(default)]
    pub r#type: String,
    /// Short human-readable title.
    #[serde(default)]
    pub title: Option<String>,
    /// HTTP status code echoed by the server (may be absent).
    #[serde(default)]
    pub status: Option<u16>,
    /// Long human-readable detail message.
    #[serde(default)]
    pub detail: Option<String>,
    /// URI identifying the specific occurrence (e.g. an ACME order).
    #[serde(default)]
    pub instance: Option<String>,
    /// RFC 8555 §6.7.1 sub-problems (compound errors).
    #[serde(default)]
    pub subproblems: Vec<serde_json::Value>,
}

impl ProblemDocument {
    /// Dispatch on the `type` URI and produce the appropriate
    /// [`AcmeError`] variant. Unknown URIs collapse to `Other` with
    /// the URI preserved in the message.
    pub fn into_acme_error(self) -> AcmeError {
        let detail = self
            .detail
            .clone()
            .unwrap_or_else(|| self.title.clone().unwrap_or_else(|| self.r#type.clone()));
        parse_problem_type(&self.r#type, detail)
    }
}

/// Best-effort parse: given an HTTP body and a `Content-Type`, either
/// deserialize it as an ACME problem document and dispatch it or fall
/// back to [`AcmeError::Http`]. Called by the transport-facing helpers
/// after any non-2xx response.
pub fn problem_from_response(status: u16, content_type: Option<&str>, body: &[u8]) -> AcmeError {
    let is_problem = content_type
        .map(|ct| ct.split(';').next().unwrap_or("").trim() == "application/problem+json")
        .unwrap_or(false);
    if is_problem {
        if let Ok(doc) = serde_json::from_slice::<ProblemDocument>(body) {
            return doc.into_acme_error();
        }
    }
    // Truncate the body so log lines stay readable — 512 bytes captures
    // enough of any CA HTML error page to identify it.
    let body_text = String::from_utf8_lossy(body);
    let body_snippet: String = body_text.chars().take(512).collect();
    AcmeError::Http {
        status,
        body: body_snippet,
    }
}

fn parse_problem_type(type_uri: &str, detail: String) -> AcmeError {
    const PREFIX: &str = "urn:ietf:params:acme:error:";
    let Some(code) = type_uri.strip_prefix(PREFIX) else {
        return AcmeError::Other(format!("{type_uri}: {detail}"));
    };
    match code {
        "badCSR" => AcmeError::BadCsr(detail),
        "badNonce" => AcmeError::BadNonce(detail),
        "badPublicKey" => AcmeError::BadPublicKey(detail),
        "badRevocationReason" => AcmeError::BadRevocationReason(detail),
        "badSignatureAlgorithm" => AcmeError::BadSignatureAlgorithm(detail),
        "caa" => AcmeError::Caa(detail),
        "compound" => AcmeError::Compound(detail),
        "connection" => AcmeError::Connection(detail),
        "dns" => AcmeError::Dns(detail),
        "externalAccountRequired" => AcmeError::ExternalAccountRequired(detail),
        "incorrectResponse" => AcmeError::IncorrectResponse(detail),
        "invalidContact" => AcmeError::InvalidContact(detail),
        "malformed" => AcmeError::Malformed(detail),
        "orderNotReady" => AcmeError::OrderNotReady(detail),
        "rateLimited" => AcmeError::RateLimited(detail),
        "rejectedIdentifier" => AcmeError::RejectedIdentifier(detail),
        "serverInternal" => AcmeError::ServerInternal(detail),
        "tls" => AcmeError::Tls(detail),
        "unauthorized" => AcmeError::Unauthorized(detail),
        "unsupportedContact" => AcmeError::UnsupportedContact(detail),
        "unsupportedIdentifier" => AcmeError::UnsupportedIdentifier(detail),
        "userActionRequired" => AcmeError::UserActionRequired(detail),
        "accountDoesNotExist" => AcmeError::AccountDoesNotExist(detail),
        "alreadyRevoked" => AcmeError::AlreadyRevoked(detail),
        "badRevoked" => AcmeError::BadRevoked(detail),
        other => AcmeError::Other(format!("{PREFIX}{other}: {detail}")),
    }
}

impl From<serde_json::Error> for AcmeError {
    fn from(e: serde_json::Error) -> Self {
        AcmeError::Serialization(e.to_string())
    }
}

impl From<url::ParseError> for AcmeError {
    fn from(e: url::ParseError) -> Self {
        AcmeError::Serialization(format!("url: {e}"))
    }
}

/// Convenience alias — every public function in this crate returns
/// `Result<_, AcmeError>`.
pub type Result<T> = core::result::Result<T, AcmeError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_type_dispatches_to_variant() {
        let doc = ProblemDocument {
            r#type: "urn:ietf:params:acme:error:badNonce".into(),
            detail: Some("nonce reused".into()),
            ..Default::default()
        };
        match doc.into_acme_error() {
            AcmeError::BadNonce(d) => assert_eq!(d, "nonce reused"),
            other => panic!("expected BadNonce, got {other:?}"),
        }
    }

    #[test]
    fn unknown_type_falls_back_to_other() {
        let doc = ProblemDocument {
            r#type: "urn:ietf:params:acme:error:futureThing".into(),
            detail: Some("added in a later RFC".into()),
            ..Default::default()
        };
        match doc.into_acme_error() {
            AcmeError::Other(msg) => {
                assert!(msg.contains("futureThing"));
                assert!(msg.contains("added in a later RFC"));
            }
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn non_acme_type_uri_falls_back_to_other() {
        let doc = ProblemDocument {
            r#type: "https://example.com/errors/something".into(),
            detail: Some("nope".into()),
            ..Default::default()
        };
        assert!(matches!(doc.into_acme_error(), AcmeError::Other(_)));
    }

    #[test]
    fn problem_from_response_parses_json_body() {
        let body =
            br#"{"type":"urn:ietf:params:acme:error:orderNotReady","detail":"still pending"}"#;
        let err = problem_from_response(403, Some("application/problem+json"), body);
        match err {
            AcmeError::OrderNotReady(d) => assert_eq!(d, "still pending"),
            other => panic!("expected OrderNotReady, got {other:?}"),
        }
    }

    #[test]
    fn problem_from_response_tolerates_charset_suffix() {
        let body = br#"{"type":"urn:ietf:params:acme:error:badNonce","detail":"stale"}"#;
        let err = problem_from_response(400, Some("application/problem+json; charset=utf-8"), body);
        assert!(matches!(err, AcmeError::BadNonce(_)));
    }

    #[test]
    fn non_problem_body_becomes_http_variant() {
        let err = problem_from_response(502, Some("text/html"), b"<html>gateway</html>");
        match err {
            AcmeError::Http { status, body } => {
                assert_eq!(status, 502);
                assert!(body.contains("gateway"));
            }
            other => panic!("expected Http, got {other:?}"),
        }
    }
}
