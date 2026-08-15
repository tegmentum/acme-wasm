//! RFC 8555 §7.4 — order lifecycle.
//!
//! An order requests issuance for a specific set of identifiers
//! (typically DNS names, one per SAN entry on the resulting cert).
//! Its lifecycle is a state machine: `pending` → `ready` →
//! `processing` → `valid`, with `invalid` as a terminal failure
//! state.
//!
//! This module will hold:
//!
//! - `Identifier` — `{ type: "dns", value: "example.com" }`.
//! - `NewOrderRequest` — `identifiers`, `notBefore`, `notAfter`.
//! - `Order` — the returned record (`status`, `expires`,
//!   `identifiers`, `authorizations`, `finalize`, `certificate`).
//! - `OrderStatus` — the state enum above.
//! - Finalize helper (§7.4): POST a CSR (built by [`crate::csr`]) to
//!   the `finalize` URL when the order reaches `ready`, then poll the
//!   order URL until `valid`, then GET the `certificate` URL.
