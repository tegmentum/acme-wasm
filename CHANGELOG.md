# Changelog

All notable changes to this project will be documented here.

Format: https://keepachangelog.com/en/1.1.0/
Versioning: https://semver.org/spec/v2.0.0.html

## [Unreleased]

### Added

- **`acme-core`** — plain-Rust RFC 8555 ACME v2 primitives.
  - `directory` — §7.1.1 directory object + fetcher.
  - `nonce` — §6.5 `Replay-Nonce` handling with a mutex-guarded ring
    buffer that primes from the CA's `newNonce` URL on first use and
    absorbs the header on every subsequent response.
  - `account` — §7.3 account lifecycle (create-with-jwk → store kid →
    subsequent requests via post-with-kid).
  - `order` / `authorization` / `challenge` — §7.4–§7.5.1 state
    machines including `poll_challenge` with configurable interval.
  - `certificate` — §7.4 finalize + §7.4.2 PEM chain download.
  - `jws` — RFC 7515 flattened JWS-with-nonce assembly for RS256 /
    ES256 / ES384 / EdDSA + RFC 7638 JWK thumbprint (referenced from
    the §8.1 key authorization).
  - `csr` — PKCS#10 CSR generation via rcgen; `CertificateKey`
    generators for P-256, P-384, Ed25519.
  - `transport` — `HttpClient` trait seam; optional
    `native-http`-feature `ReqwestTransport`.
  - Top-level `issue_certificate` orchestrator wraps the whole flow
    in one call.
  - Error taxonomy covering every RFC 8555 §6.7 problem-document
    error type plus Transport / Serialization / Jose / Timeout /
    MissingField / Http / Other.
  - 38 unit tests, all offline (RFC 7638 thumbprint reference vector,
    round-trip JWS sign+verify, directory parse against a captured
    Let's Encrypt staging fixture, CSR round-trip through x509-cert).

- **`acme-challenge-http-01`** — RFC 8555 §8.3 solver. `path(token)` +
  `response_body(token, key)` + `respond(...)`. I/O-free — caller
  plugs the `(path, body)` pair into their HTTP surface.

- **`acme-challenge-dns-01`** — RFC 8555 §8.4 solver + `DnsProvider`
  trait. `record_name(id)` (strips leading `*.` for wildcards),
  `record_value(token, key)` (base64url SHA-256 of key authorization).
  Ships `MockDnsProvider` and a `with_provisioned_record(...)` helper
  that guarantees cleanup on the caller's error.

- **`acme-challenge-tls-alpn-01`** — RFC 8737 solver.
  `responder_cert(id, token, key)` builds a self-signed P-256 leaf
  carrying a SAN dNSName + the critical `id-pe-acmeIdentifier`
  extension (OID `1.3.6.1.5.5.7.1.31`) whose extnValue is the DER
  OCTET STRING of SHA-256(key authorization). Ships
  `ACME_TLS_ALPN_PROTOCOL = b"acme-tls/1"` for the caller's ALPN
  wiring.

- **`acme-dns-provider-cloudflare`** — first concrete `DnsProvider`
  implementation. Scoped API token auth (Global API Key deliberately
  unsupported). Two zone-resolution modes:
  `ZoneLookup::Static(HashMap)` (Terraform/IaC flow, no `/zones` API
  call) and `ZoneLookup::ByName` (lazy `/zones?name=` lookup with an
  in-process cache). Delete is idempotent per the trait contract.

### Not yet implemented (queued)

- `acme-protocol` — wit-typed wasm adapter over `acme-core`.
- `acme-http-client` — `wasi:http/outgoing-handler`-backed transport
  for wasm callers.
- Pebble-backed end-to-end integration tests (all three challenge
  types).
