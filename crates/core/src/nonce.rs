//! RFC 8555 §6.5 — replay-nonce handling.
//!
//! Every ACME POST carries a `nonce` in its protected header. The
//! server returns a fresh `Replay-Nonce` header on every response;
//! the client uses that value on the next request. When the client
//! has none, it does a `HEAD` (or `GET`) against the `newNonce` URL
//! from the directory (§7.2) to prime the pump.
//!
//! This module will hold:
//!
//! - `NoncePool` — small in-memory holder of the most recent
//!   `Replay-Nonce`; single-flight, not thread-shared (ACME does not
//!   permit reusing a nonce across parallel requests).
//! - Helpers to extract `Replay-Nonce` from a response header list.
//!
//! No I/O — retries on `badNonce` (RFC 8555 §6.7) belong to the
//! caller / http-client layer; this module only carries the value.
