//! PKCS#10 CSR generation for the finalize step (RFC 8555 §7.4).
//!
//! The `finalize` POST carries a base64url-encoded (RFC 4648 §5, no
//! padding) DER PKCS#10 CertificationRequest. The CSR's Subject
//! Alternative Name extension must exactly match the identifiers in
//! the order — mismatch is a `badCSR` error (§6.7).
//!
//! This module will hold:
//!
//! - `CsrBuilder` — thin wrapper over `rcgen::CertificateParams` that
//!   accepts a list of DNS identifiers and a signing key (RSA,
//!   ECDSA-P256, or ECDSA-P384) and produces a DER-encoded CSR.
//! - Helpers to derive a subject CN from the first SAN entry (some
//!   older CAs still require a non-empty CN even when SAN is present).
//! - base64url encoding of the DER for embedding directly in the
//!   finalize payload.
//!
//! The CSR signing key is separate from the account key. Callers
//! typically generate a fresh keypair per certificate — key rotation
//! on renewal is cheap and reduces blast radius from a leaked key.
