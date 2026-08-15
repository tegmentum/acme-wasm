//! RFC 7515 JWS-with-nonce assembly for ACME (RFC 8555 §6.2).
//!
//! ACME uses JWS Flattened Serialization for every authenticated
//! request. The protected header carries:
//!
//! - `alg` — one of RS256 / RS384 / ES256 / ES384 / EdDSA (Ed25519).
//! - `nonce` — the `Replay-Nonce` from the previous response.
//! - `url` — the exact URL the request is going to (bound into the
//!   signature to prevent replay across endpoints).
//! - Either `jwk` (first-time `newAccount`, `revokeCert` when signing
//!   with the cert's key) or `kid` (every other authenticated
//!   request; the value is the account URL returned by
//!   `newAccount`).
//!
//! This module will hold:
//!
//! - `JwsHeader`, `JwsFlattened` — serde types matching the on-wire
//!   shape.
//! - `sign(payload, header, key) -> JwsFlattened` — the assembly
//!   function; delegates the raw RS256 / RS384 / ES256 / ES384
//!   sign step to `oauth2_core::jwt` primitives (the exact seam is
//!   the `SignBackend` trait pair; see `crypto_backend.rs` in
//!   `oauth2-core`).
//! - `JwkThumbprint` helper (RFC 7638) for computing the `kid`-less
//!   thumbprint used to derive the challenge key authorization
//!   (§8.1) and to identify accounts.
//!
//! The Ed25519 signing path uses `ed25519-dalek` directly — `oauth2-core`
//! does not include an EdDSA backend, and ACME account-key EdDSA
//! support is still uneven across CAs, so this crate carries its own
//! implementation until upstream demand justifies moving it into
//! `oauth2-core`.
