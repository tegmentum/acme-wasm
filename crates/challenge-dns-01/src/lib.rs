#![allow(unused_imports, dead_code)]

//! RFC 8555 §8.4 — DNS-01 challenge solver + `DnsProvider` trait.
//!
//! The client provisions a TXT record at
//! `_acme-challenge.<identifier>` whose value is
//! `base64url(SHA-256(key-authorization))` — the same hash the
//! TLS-ALPN-01 challenge embeds in the responder cert, only
//! base64url-encoded instead of raw DER-wrapped. The CA resolves the
//! record and matches it against the value it computes locally from
//! the challenge token and the account key's thumbprint (RFC 7638).
//!
//! DNS-01 is the only challenge type that supports wildcard
//! identifiers (`*.example.com`).
//!
//! This crate will hold:
//!
//! - `record_name(identifier) -> String` — returns
//!   `_acme-challenge.<identifier>`, stripping a leading `*.` for
//!   wildcards (the record lives on the base domain).
//! - `record_value(token, account_jwk) -> String` — the base64url
//!   TXT contents.
//! - `trait DnsProvider` — the seam concrete providers implement:
//!   `async fn upsert_txt(&self, name, value) -> Result<RecordHandle, DnsProviderError>`
//!   and `async fn delete_txt(&self, handle) -> Result<(), DnsProviderError>`.
//!   The `RecordHandle` type is provider-defined (an opaque record
//!   id) so cleanup after validation is precise; some APIs (e.g.
//!   Route 53 with SIMPLE routing) can only delete-by-value, and
//!   those providers return an empty handle and match by
//!   `(name, value)` on delete.
//! - Propagation-wait helper: `wait_for_propagation(name, value,
//!   resolvers)` — resolves the record against a provided set of
//!   authoritative nameservers until every one returns the expected
//!   value or a caller-supplied timeout elapses. Some CAs (Let's
//!   Encrypt) resolve from multiple vantage points and will fail a
//!   challenge if propagation is uneven at check time.

// Silences the "unused external crate" lint until the record-value
// helper actually references acme_core::challenge::sha256_key_authorization.
use acme_core as _;
