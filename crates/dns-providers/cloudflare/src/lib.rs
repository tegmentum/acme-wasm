#![allow(unused_imports, dead_code)]

//! Cloudflare DNS provider — first concrete implementation of the
//! [`DnsProvider`](acme_challenge_dns_01) trait for the DNS-01 solver.
//!
//! Uses the Cloudflare DNS Records REST API
//! (`https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records`).
//! Authentication is a scoped API token (Zone:DNS:Edit on the target
//! zones) supplied via the `Authorization: Bearer <token>` header —
//! Global API Key is deliberately not supported.
//!
//! This crate will hold:
//!
//! - `CloudflareProvider { token, zone_lookup }` — constructor takes
//!   a token and a strategy for mapping identifier → zone id (either
//!   a pre-populated `HashMap<String, String>` for static
//!   deployments or a `resolve_by_name` mode that calls
//!   `/zones?name={apex}` on demand and caches the result).
//! - `impl DnsProvider for CloudflareProvider` — `upsert_txt` POSTs
//!   to `/dns_records` with `{ type: "TXT", name, content, ttl: 60 }`
//!   and returns the created record id; `delete_txt` issues DELETE
//!   `/dns_records/{id}`.
//! - Error mapping: Cloudflare API errors (`success: false, errors:
//!   [...]`) into `DnsProviderError`.
//!
//! HTTP transport is left abstract via a trait so the same provider
//! can front a `reqwest::Client` on native, a `wasi:http` component
//! call in a Wasm build, or a mock in tests.
