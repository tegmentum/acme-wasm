//! RFC 8555 §8.3 — HTTP-01 challenge solver.
//!
//! The CA GETs
//! `http://<identifier>/.well-known/acme-challenge/<token>` over plain
//! HTTP on port 80 (redirects to HTTPS are permitted). The response
//! body must be exactly the §8.1 key authorization —
//! `token || '.' || base64url(JWK_Thumbprint(accountKey))`. Per §8.3
//! the CA does NOT rely on the `Content-Type`; we still set
//! `application/octet-stream` because that's what the RFC recommends.
//!
//! The solver is I/O-free by design: it computes the `(path, body)`
//! pair and the caller plumbs that into whichever HTTP surface they
//! run (a wasi:http/incoming-handler component, an axum route, a
//! static-file mount under `.well-known/`, whatever).

use acme_core::jws::AccountKey;

/// The `Content-Type` the RFC recommends. The CA does NOT check it
/// (§8.3) but there is no downside to setting it and some clients /
/// intermediaries key off it.
pub const CONTENT_TYPE: &str = "application/octet-stream";

/// The URL path the ACME validator will GET, given a challenge token.
///
/// Always rooted at `/.well-known/acme-challenge/` with the token
/// appended verbatim — tokens are already base64url and safe to embed
/// in a URL path segment.
pub fn path(token: &str) -> String {
    format!("/.well-known/acme-challenge/{token}")
}

/// The exact bytes the well-known URL must serve for the given
/// challenge — the §8.1 key authorization, unmodified.
pub fn response_body(token: &str, account_key: &AccountKey) -> String {
    acme_core::challenge::compute_key_authorization(token, account_key)
}

/// Everything a caller needs to serve one HTTP-01 challenge — path,
/// body, and the recommended `Content-Type`. Ready to drop into a
/// route table.
#[derive(Debug, Clone)]
pub struct Http01Response {
    pub path: String,
    pub body: String,
    pub content_type: &'static str,
}

/// Convenience: compute `Http01Response` in one call from the token +
/// account key.
pub fn respond(token: &str, account_key: &AccountKey) -> Http01Response {
    Http01Response {
        path: path(token),
        body: response_body(token, account_key),
        content_type: CONTENT_TYPE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acme_core::jws::{AccountKey, EcdsaKey};

    fn test_account_key() -> AccountKey {
        // Deterministic P-256 key — sufficient for hash-shape tests.
        // Reduce the 32-byte seed to a non-zero scalar per SEC1 §2.3.4.
        let seed = [0x11u8; 32];
        let signing = p256::ecdsa::SigningKey::from_slice(&seed).expect("valid p256 seed");
        AccountKey::Ecdsa(EcdsaKey::P256(signing))
    }

    #[test]
    fn path_lives_under_well_known_acme_challenge() {
        assert_eq!(
            path("evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA"),
            "/.well-known/acme-challenge/evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA"
        );
    }

    #[test]
    fn response_body_shape_matches_key_authorization_grammar() {
        // Real token/thumbprint round-trip — check the "<token>.<b64>"
        // shape without pinning either half against a fixed vector
        // (thumbprint depends on which fresh keypair we mint here).
        let account_key = test_account_key();
        let token = "some-random-ca-issued-token";
        let body = response_body(token, &account_key);
        let mut parts = body.splitn(2, '.');
        assert_eq!(parts.next(), Some(token));
        let thumbprint = parts.next().expect("dot separator present");
        assert!(!thumbprint.is_empty());
        // base64url is ASCII, no padding.
        assert!(thumbprint.is_ascii());
        assert!(!thumbprint.contains('='));
    }

    #[test]
    fn respond_bundles_path_body_and_content_type() {
        let account_key = test_account_key();
        let r = respond("tok-1", &account_key);
        assert_eq!(r.path, "/.well-known/acme-challenge/tok-1");
        assert!(r.body.starts_with("tok-1."));
        assert_eq!(r.content_type, "application/octet-stream");
    }
}
