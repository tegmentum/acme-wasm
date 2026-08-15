#![allow(unused_imports, dead_code)]

//! Host-only integration-test helpers for `acme-wasm`.
//!
//! This crate is deliberately excluded from `workspace.default-members`
//! and marked `publish = false` — its dependencies (a Pebble process
//! spawner, an in-process HTTP-01 responder, a `MockDnsProvider`) are
//! host-only and would drag in `tokio` / `wasmtime` transitively for
//! any wasm32-wasip2 build.
//!
//! The v0 test harness will hold:
//!
//! - `pebble::spawn()` — brings up Pebble
//!   (https://github.com/letsencrypt/pebble) as a subprocess with a
//!   deterministic config, returns its directory URL and a `Drop`
//!   guard that tears it down. Assumes `pebble` is on `$PATH`; skips
//!   the test with a clear message if not.
//! - `http01::Responder` — a tiny hyper server bound to a random
//!   port that serves `/.well-known/acme-challenge/*` from an
//!   in-memory map; suitable for wiring under Pebble's HTTP-01
//!   validation (`pebble-challtestsrv` handles the DNS remap that
//!   points identifiers at 127.0.0.1).
//! - `dns::MockDnsProvider` — an implementation of
//!   `acme_challenge_dns_01::DnsProvider` that talks to
//!   `pebble-challtestsrv`'s admin API to seed TXT records.

// Silences the "unused external crate" lint until the harness
// modules land.
use acme_core as _;
