//! RFC 8555 §7.1.1 — the ACME directory object.
//!
//! Every ACME client bootstraps from a single URL: the CA's directory.
//! The response is a JSON object mapping resource names
//! (`newAccount`, `newOrder`, `newNonce`, `revokeCert`, `keyChange`,
//! optionally `renewalInfo` per RFC 9773 §4) to their absolute URLs,
//! plus a `meta` block carrying the terms-of-service URL, the CAA
//! identities list, and any external-account-binding requirement flag.
//!
//! This module will hold:
//!
//! - `Directory` — deserialized directory record.
//! - `Meta` — the `meta` sub-object.
//! - `parse(body)` — strict JSON deserializer that surfaces missing
//!   required fields (`newAccount`, `newOrder`, `newNonce`,
//!   `revokeCert`, `keyChange`) as `AcmeError::ParseError`.
//!
//! No I/O — the caller fetches the URL and hands the response body
//! in. The `acme-http-client` component wires that fetch to
//! `wasi:http/outgoing-handler`.
