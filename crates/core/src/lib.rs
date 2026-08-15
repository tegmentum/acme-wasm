//! acme-core — plain-Rust RFC 8555 ACME v2 primitives.
//!
//! This crate holds the domain types and pure logic for the ACME
//! protocol (RFC 8555), the TLS-ALPN-01 challenge (RFC 8737), and the
//! HTTP-01 / DNS-01 challenges from RFC 8555 §8.3 / §8.4. It does not
//! depend on wit-bindgen, wasi, or the Component Model — the wit-typed
//! wrapper `acme-protocol` layers on top and is a thin translation
//! between wit-bindgen structs and the plain types defined here.
//!
//! JWS-with-nonce signing (RFC 8555 §6.2, RFC 7515) delegates to
//! `oauth2-core`'s JWS primitives rather than reimplementing RS256 /
//! RS384 / ES256 / ES384. See `jws.rs` for the exact seam.
//!
//! Module layout follows RFC 8555 section numbering so the mapping
//! between spec text and code is one-to-one:
//!
//! - [`directory`] — §7.1.1 directory object.
//! - [`nonce`] — §6.5 replay-nonce handling.
//! - [`account`] — §7.3 account lifecycle.
//! - [`order`] — §7.4 order lifecycle (finalize lives here).
//! - [`authorization`] — §7.5 authorization polling.
//! - [`challenge`] — §7.5.1 challenge state machine (per-type solvers
//!   live in their own crates; this module only carries the shared
//!   record + key-authorization helper from §8.1).
//! - [`certificate`] — §7.4.2 certificate download and parsing.
//! - [`jws`] — RFC 7515 JWS-with-nonce assembly (delegates signing to
//!   oauth2-core).
//! - [`csr`] — PKCS#10 CSR generation for the finalize step.
//! - [`error`] — RFC 8555 §6.7 problem-document errors plus JOSE and
//!   transport failures.

pub mod account;
pub mod authorization;
pub mod certificate;
pub mod challenge;
pub mod csr;
pub mod directory;
pub mod error;
pub mod jws;
pub mod nonce;
pub mod order;

pub use error::AcmeError;
