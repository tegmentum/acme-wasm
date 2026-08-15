//! RFC 8555 §7.4.2 — certificate download.
//!
//! Once an order is `valid`, the client GETs (POST-as-GET, technically)
//! the `certificate` URL to fetch the issued chain. The default media
//! type is `application/pem-certificate-chain`; the `Link:
//! rel="alternate"` header advertises additional chains the CA can
//! serve (e.g. cross-signed roots for older trust stores).
//!
//! This module will hold:
//!
//! - `CertificateChain` — parsed PEM chain with the leaf separated
//!   from intermediates.
//! - `parse_pem_chain(body)` — strict PEM chain parser (rejects an
//!   empty chain and any non-CERTIFICATE label).
//! - `alternate_links(link_header)` — extracts alternate-chain URLs
//!   from the `Link` header for callers that want to pick a specific
//!   chain (Let's Encrypt's DST Root CA X3 vs. ISRG Root X1, etc.).
