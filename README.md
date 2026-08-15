# acme-wasm

RFC 8555 ACME client — Let's Encrypt and any other ACME-compliant CA —
packaged as WebAssembly components and as plain-Rust rlibs.

[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-APACHE)

## What this is

`acme-wasm` is a Cargo workspace covering RFC 8555 (ACME v2), RFC 8737
(TLS-ALPN-01 challenge), and the HTTP-01 and DNS-01 challenges defined
in RFC 8555 §8.3 / §8.4. The domain logic lives in a plain-Rust core
rlib with no wit-bindgen or wasi surface; a `cargo-component` adapter
re-exports the same operations over a WIT world, and a separate
`http-client` component wires the core to `wasi:http/outgoing-handler`
for real ACME round-trips.

## Architectural context

This repo is one layer of a small set of composable Wasm components for
SMART on FHIR — and, more broadly, for issuing and rotating the
certificates those servers terminate TLS with. Each sibling repo owns
one protocol layer, uses the same core-plus-adapter split, and can be
consumed either as a component or as an rlib:

- [`oauth2-wasm`](../oauth2-wasm) — OAuth 2.0 / RFC 7519 JWT
- [`oidc-wasm`](../oidc-wasm) — OpenID Connect 1.0 (uses `oauth2-core`)
- [`smart-wasm`](../smart-wasm) — SMART App Launch 1.0 / 2.0 (uses `oauth2-core`)
- [`fhir-wasm`](../fhir-wasm) — FHIR R4
- [`acme-wasm`](.) — RFC 8555 ACME client (this repo)
- [`smart-fhir-demo`](../smart-fhir-demo) — end-to-end composition demo

The JWS-with-nonce that ACME wraps every authenticated request in is
signature-compatible with the RFC 7515 JWS that `oauth2-core` already
implements for JWT; `acme-core::jws` delegates its RS256 / RS384 /
ES256 / ES384 signing to `oauth2-core`'s primitives rather than
reimplementing them.

## Crates in this workspace

- **`acme-core`** — pure-Rust ACME primitives: directory parsing,
  nonce handling, account / order / authorization / challenge state
  machines, JWS-with-nonce assembly, PKCS#10 CSR generation, and
  certificate download.
- **`acme-protocol`** — `tegmentum:acme-protocol` component; thin
  wit-bindgen adapter over `acme-core`.
- **`acme-http-client`** — `tegmentum:acme-http-client` component;
  `http-client` world that composes `acme-core` with
  `wasi:http/outgoing-handler` to drive an ACME order end-to-end.
- **`acme-challenge-tls-alpn-01`** — TLS-ALPN-01 solver (RFC 8737):
  builds the acme-tls/1 self-signed responder certificate the
  validation server presents on port 443.
- **`acme-challenge-http-01`** — HTTP-01 solver (RFC 8555 §8.3):
  computes the `/.well-known/acme-challenge/<token>` key-authorization
  response body.
- **`acme-challenge-dns-01`** — DNS-01 solver (RFC 8555 §8.4):
  computes the `_acme-challenge.<domain>` TXT record value and defines
  the `DnsProvider` trait that concrete provider crates implement.
- **`dns-providers/cloudflare`** — first concrete `DnsProvider`
  implementation, targeting the Cloudflare DNS API. Additional
  providers (Route 53, DigitalOcean, RFC 2136) can slot in behind the
  same trait without touching `acme-core` or the solver.

## v0 status

**Scaffolded** — the crates compile, the workspace resolves, the WIT
worlds parse. Real logic lands in follow-up phases:

1. `acme-core` — directory, nonce, JWS-with-nonce, account, order,
   authorization, challenge, finalize, certificate download.
2. `acme-protocol` and `acme-http-client` adapters.
3. Challenge solvers (TLS-ALPN-01, HTTP-01, DNS-01) in parallel.
4. `dns-providers/cloudflare`.
5. Pebble-driven integration tests under `crates/testing/`.

## Roadmap

- v0.1: RFC 8555 order flow against Pebble, all three challenge types,
  Cloudflare DNS provider.
- v0.2: additional DNS providers (Route 53, RFC 2136), ARI (RFC 9773)
  renewal-information hints, EAB (external account binding) for CAs
  that require it.
- v0.3: certificate revocation (RFC 8555 §7.6), account key rollover
  (§7.3.5), account deactivation (§7.3.6).

## Build

```
cargo test --workspace --lib
cargo component build --release --workspace
```

`cargo test` runs the rlib unit tests on the host. `cargo component
build` produces the wasip2 component artifacts under `target/`.

## End-to-end integration tests (Pebble)

`crates/testing/` ships a `PebbleHarness` that spins
[Pebble](https://github.com/letsencrypt/pebble) (the Let's Encrypt
team's official ACME-CA-for-testing) and
[`pebble-challtestsrv`](https://github.com/letsencrypt/pebble/tree/main/cmd/pebble-challtestsrv)
via `docker compose`, then drives the full RFC 8555 order flow through
each of the three challenge types against it.

All three tests are gated behind `#[ignore]` so a bare `cargo test`
does not need Docker. To run one:

```
cargo test -p acme-testing --test http_01     -- --ignored --nocapture
cargo test -p acme-testing --test tls_alpn_01 -- --ignored --nocapture
cargo test -p acme-testing --test dns_01      -- --ignored --nocapture
```

Or run all three (each in its own `--test` binary, sequentially, so
they don't race on ports 5001 / 5002 / 14000 / 15000 / 8055):

```
make test-e2e
```

The harness prefers `docker compose` (Docker CLI plugin) and falls
back to the standalone `docker-compose` binary; either is fine.
Container teardown happens in `PebbleHarness::Drop`; use `make
clean-pebble` if a panic leaves a stack behind.

## Status

v0.1 — pre-alpha. APIs, WIT worlds, and crate boundaries are all
expected to change without deprecation windows.

## License

MIT OR Apache-2.0.
