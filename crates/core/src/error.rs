//! ACME error taxonomy.
//!
//! RFC 8555 §6.7 defines the ACME problem-document error type URIs
//! (`urn:ietf:params:acme:error:*`). Every error the CA returns is a
//! JSON problem document (RFC 7807) whose `type` field maps to one of
//! these codes. This module carries the enum and the URI-to-variant
//! parser, plus JOSE and transport failures the client raises
//! locally.
//!
//! This module will hold:
//!
//! - `AcmeError` — thiserror enum. Variants cover every §6.7 code
//!   (`badCSR`, `badNonce`, `badPublicKey`, `badRevocationReason`,
//!   `badSignatureAlgorithm`, `caa`, `compound`, `connection`, `dns`,
//!   `externalAccountRequired`, `incorrectResponse`, `invalidContact`,
//!   `malformed`, `orderNotReady`, `rateLimited`, `rejectedIdentifier`,
//!   `serverInternal`, `tls`, `unauthorized`, `unsupportedContact`,
//!   `unsupportedIdentifier`, `userActionRequired`) plus
//!   `ParseError`, `JwsError`, `Http { status, body }`, and
//!   `Other(String)`.
//! - `ProblemDocument` — RFC 7807 record for deserializing
//!   `application/problem+json` bodies.
//! - `parse_problem(body) -> AcmeError` — dispatches on the `type`
//!   URI, defaulting to `Other` for unknown codes.

use thiserror::Error;

/// Placeholder ACME error enum — the v0 scaffold carries only the
/// two variants every module hits before the §6.7 taxonomy lands.
/// Wiring the full variant set (all `urn:ietf:params:acme:error:*`
/// codes plus JOSE / transport failures) is the first commit into
/// this module in the follow-up phase.
#[derive(Debug, Error)]
pub enum AcmeError {
    /// JSON / PEM / header-parsing failure — malformed CA response.
    #[error("parse error: {0}")]
    ParseError(String),
    /// Catch-all for errors that do not yet have a dedicated variant.
    #[error("{0}")]
    Other(String),
}
