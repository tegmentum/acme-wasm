//! RFC 8555 §7.3 — account lifecycle.
//!
//! An ACME account is identified by a public key. `newAccount`
//! (§7.3) either creates a fresh account (returning the account URL
//! in the `Location` header) or, with `onlyReturnExisting: true`,
//! looks up an existing account for a given key.
//!
//! This module will hold:
//!
//! - `NewAccountRequest` — the request payload (`termsOfServiceAgreed`,
//!   `contact`, `onlyReturnExisting`, optional `externalAccountBinding`
//!   per §7.3.4).
//! - `Account` — the returned record (`status`, `contact`, `orders`).
//! - Helpers to build the request payload; JWS assembly (using the
//!   JWK in the protected header — first-time accounts sign with
//!   `jwk`, subsequent requests with `kid` per §6.2) lives in
//!   [`crate::jws`].
//! - Follow-up: account key rollover (§7.3.5) and deactivation
//!   (§7.3.6) — deferred to v0.3, tracked in the README roadmap.
