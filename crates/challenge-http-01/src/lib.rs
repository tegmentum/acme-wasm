#![allow(unused_imports, dead_code)]

//! RFC 8555 §8.3 — HTTP-01 challenge solver.
//!
//! The CA GETs
//! `http://<identifier>/.well-known/acme-challenge/<token>` over
//! plain HTTP on port 80 (redirects to HTTPS are permitted). The
//! response body must be exactly the §8.1 key authorization —
//! `token || '.' || base64url(JWK_Thumbprint(accountKey))` — served
//! with `Content-Type: application/octet-stream` (or omitted; the CA
//! MUST NOT rely on the content type per §8.3).
//!
//! This crate will hold:
//!
//! - `response_body(token, account_jwk) -> String` — computes the
//!   exact bytes the well-known path must serve.
//! - `path(token) -> String` — returns
//!   `"/.well-known/acme-challenge/<token>"` for callers wiring the
//!   route.
//! - Optional helper that renders both as a `(path, body)` tuple ready
//!   to drop into a static-file responder for validation.

// Silences the "unused external crate" lint until the response-body
// helper actually references acme_core::challenge::key_authorization.
use acme_core as _;
