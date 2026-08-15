#![allow(unused_imports, dead_code)]

//! ACME HTTP-client component — the wasi:http-composing sibling of
//! `acme-protocol`.
//!
//! Fill-in plan: once `acme-core` carries the real request builders
//! and response parsers, this crate targets the `http-client` world
//! in `wit/acme.wit`, exports the pure interfaces (delegating to
//! `acme-core` in the same shape as `acme-protocol`), and adds an
//! `acme-client` resource that drives an ACME order end-to-end over
//! `wasi:http/outgoing-handler`. See `oauth2-http-client` for the
//! reference shape.
//!
//! Splitting the batteries-included client into its own component
//! keeps `acme-protocol` free of any wasi:http dependency for
//! embedders (browser bundles, workers with a different transport)
//! that want the pure logic only.
//!
//! The wit-bindgen `generate!` call is deliberately absent in the
//! v0 scaffold — WIT worlds are placeholders and `wit/deps/` is
//! empty until `wit-deps update` runs.

// Path dep — silences the "unused external crate" lint until the
// client module actually uses it.
use acme_core as _;
