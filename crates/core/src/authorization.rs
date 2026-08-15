//! RFC 8555 §7.5 — authorization objects.
//!
//! Each identifier in an order has a corresponding authorization
//! object listing the challenges the client can complete to prove
//! control of that identifier. The client picks one challenge,
//! provisions the response, POST-as-GETs the challenge URL to signal
//! readiness, and polls the authorization until it flips to `valid`
//! (or `invalid`).
//!
//! This module will hold:
//!
//! - `Authorization` — `identifier`, `status`, `expires`,
//!   `challenges`, `wildcard`.
//! - `AuthorizationStatus` — `pending`, `valid`, `invalid`,
//!   `deactivated`, `expired`, `revoked`.
//! - Deserialization and helpers for picking a challenge by type.
//!
//! The actual challenge response construction (key authorization,
//! `_acme-challenge` TXT contents, TLS-ALPN cert bytes) lives in the
//! per-type solver crates (`challenge-tls-alpn-01`,
//! `challenge-http-01`, `challenge-dns-01`), which each depend on
//! `acme-core` for the shared [`crate::challenge`] record and the
//! §8.1 key-authorization helper.
