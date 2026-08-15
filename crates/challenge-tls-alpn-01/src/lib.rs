#![allow(unused_imports, dead_code)]

//! RFC 8737 — TLS Application-Layer Protocol Negotiation (ALPN)
//! Challenge for ACME (`tls-alpn-01`).
//!
//! The CA opens a TLS connection to port 443 of the identifier and
//! advertises the `acme-tls/1` ALPN protocol. The client must
//! present a self-signed certificate that:
//!
//! - Has a Subject Alternative Name matching the identifier.
//! - Carries the `acmeIdentifier` extension (OID 1.3.6.1.5.5.7.1.31),
//!   marked critical, containing the DER OCTET STRING of the SHA-256
//!   hash of the §8.1 key authorization.
//! - Is negotiated with ALPN `acme-tls/1`.
//!
//! This crate will hold:
//!
//! - `responder_cert(identifier, token, account_jwk) -> (der_cert, der_key)`
//!   — builds the self-signed cert bytes and matching keypair.
//! - Helpers to plug that cert into a plain `rustls::ServerConfig`
//!   scoped to the `acme-tls/1` ALPN, for callers running a Rust
//!   TLS listener during validation. The listener itself is out of
//!   scope for this crate — solvers stay I/O-free so they can run
//!   inside a component alongside a wasi:sockets-driven server or
//!   next to a native `tokio-rustls` binding.

// Silences the "unused external crate" lint until the responder-cert
// helper actually references acme_core::challenge::sha256_key_authorization.
use acme_core as _;
