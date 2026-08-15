#![allow(unused_imports, dead_code)]

//! ACME protocol component — wit-bindgen adapter over `acme-core`.
//!
//! Fill-in plan: once `acme-core` carries the real directory / nonce /
//! order / authorization / challenge / jws / csr primitives, this
//! crate becomes a thin per-interface delegating adapter of the same
//! shape as `oauth2-protocol`. The wit-bindgen `generate!` invocation
//! is deliberately absent in the v0 scaffold because the WIT
//! interfaces are still placeholders and populating `wit/deps/` (via
//! `wit-deps update`) is a separate one-time bootstrap step.
//!
//! When the adapter lands the top of the file will look like:
//!
//! ```ignore
//! wit_bindgen::generate!({
//!     world: "protocol",
//!     path: "../../wit",
//! });
//! ```
//!
//! Per-interface adapter modules (`directory`, `account`, `order`,
//! `authorization`, `challenge`, `jws`) slot in beside `lib.rs` and
//! delegate to the matching `acme_core::` module.

// Path dep — silences the "unused external crate" lint until the
// adapter modules actually use it.
use acme_core as _;
