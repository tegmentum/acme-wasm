//! RFC 8555 §7.5.1 — challenge object, plus the §8.1 key-authorization
//! helper.
//!
//! A challenge object is `{ type, url, status, token, ... }`. Every
//! challenge type derives its response from the same building block:
//! the **key authorization**, defined in §8.1 as
//! `token || '.' || base64url(JWK_Thumbprint(accountKey))` with the
//! thumbprint per RFC 7638. This module owns that helper and the
//! shared record type; per-type response construction (the actual
//! bytes served on the TLS-ALPN cert / HTTP path / DNS TXT record)
//! lives in the solver crates.
//!
//! This module will hold:
//!
//! - `Challenge` — the shared record.
//! - `ChallengeStatus` — `pending`, `processing`, `valid`, `invalid`.
//! - `key_authorization(token, account_jwk) -> String` — §8.1.
//! - `sha256_key_authorization(...)` — the SHA-256 hash used by both
//!   TLS-ALPN-01 (raw hash → cert extension) and DNS-01 (base64url of
//!   the hash → TXT record contents).
