//! Shared type translation between `acme-core` plain Rust types and
//! the wit-bindgen-generated shapes.
//!
//! The wit-generated `acme-error` variant is defined once per interface
//! that names it (both `solver` and `orchestrator` re-use `types.acme-error`,
//! but wit-bindgen emits a distinct Rust `AcmeError` alias for every
//! `use types.{acme-error}` clause). Each conversion here is generic
//! over the target enum so a single body serves every interface's copy.

use crate::exports::tegmentum::acme::orchestrator::AcmeError as OrchestratorAcmeError;

/// Convert an `acme_core::AcmeError` into the orchestrator-facing wit
/// variant. Adding a second interface that names `acme-error` (e.g. a
/// future `authorization` interface) means adding a parallel function
/// here — the variant shapes are identical, but wit-bindgen aliases
/// them distinctly per interface.
///
/// Unused until the orchestrator is `wac plug`-composed against an
/// HTTP-providing component (see `orchestrator::issue_certificate`);
/// kept here so the composition step is a swap-in edit rather than a
/// new module.
#[allow(dead_code)]
pub fn to_orchestrator_error(e: acme_core::AcmeError) -> OrchestratorAcmeError {
    use acme_core::AcmeError as C;
    match e {
        C::BadCsr(s) => OrchestratorAcmeError::BadCsr(s),
        C::BadNonce(s) => OrchestratorAcmeError::BadNonce(s),
        C::BadPublicKey(s) => OrchestratorAcmeError::BadPublicKey(s),
        C::BadRevocationReason(s) => OrchestratorAcmeError::BadRevocationReason(s),
        C::BadSignatureAlgorithm(s) => OrchestratorAcmeError::BadSignatureAlgorithm(s),
        C::Caa(s) => OrchestratorAcmeError::Caa(s),
        C::Compound(s) => OrchestratorAcmeError::Compound(s),
        C::Connection(s) => OrchestratorAcmeError::Connection(s),
        C::Dns(s) => OrchestratorAcmeError::Dns(s),
        C::ExternalAccountRequired(s) => OrchestratorAcmeError::ExternalAccountRequired(s),
        C::IncorrectResponse(s) => OrchestratorAcmeError::IncorrectResponse(s),
        C::InvalidContact(s) => OrchestratorAcmeError::InvalidContact(s),
        C::Malformed(s) => OrchestratorAcmeError::Malformed(s),
        C::OrderNotReady(s) => OrchestratorAcmeError::OrderNotReady(s),
        C::RateLimited(s) => OrchestratorAcmeError::RateLimited(s),
        C::RejectedIdentifier(s) => OrchestratorAcmeError::RejectedIdentifier(s),
        C::ServerInternal(s) => OrchestratorAcmeError::ServerInternal(s),
        C::Tls(s) => OrchestratorAcmeError::Tls(s),
        C::Unauthorized(s) => OrchestratorAcmeError::Unauthorized(s),
        C::UnsupportedContact(s) => OrchestratorAcmeError::UnsupportedContact(s),
        C::UnsupportedIdentifier(s) => OrchestratorAcmeError::UnsupportedIdentifier(s),
        C::UserActionRequired(s) => OrchestratorAcmeError::UserActionRequired(s),
        C::AccountDoesNotExist(s) => OrchestratorAcmeError::AccountDoesNotExist(s),
        C::AlreadyRevoked(s) => OrchestratorAcmeError::AlreadyRevoked(s),
        C::BadRevoked(s) => OrchestratorAcmeError::BadRevoked(s),
        C::Transport(s) => OrchestratorAcmeError::Transport(s),
        C::Serialization(s) => OrchestratorAcmeError::Serialization(s),
        C::Jose(s) => OrchestratorAcmeError::Jose(s),
        C::Timeout(s) => OrchestratorAcmeError::Timeout(s),
        C::MissingField(s) => OrchestratorAcmeError::MissingField(s),
        C::Http { status, body } => OrchestratorAcmeError::Http((status, body)),
        C::Other(s) => OrchestratorAcmeError::Other(s),
    }
}

/// Translate the wit-bindgen `identifier` record into the plain
/// `acme_core::order::Identifier`. Every interface that names
/// `identifier` gets its own alias in the generated bindings; because
/// the shape is a two-field record the caller passes the wit type in
/// directly.
///
/// Unused until the orchestrator is composed with an HTTP provider —
/// see [`to_orchestrator_error`] for the same story.
#[allow(dead_code)]
pub fn identifier_from_wit(
    id: crate::exports::tegmentum::acme::orchestrator::Identifier,
) -> acme_core::order::Identifier {
    acme_core::order::Identifier {
        kind: id.kind,
        value: id.value,
    }
}

/// Same translation for the `solver` interface's alias — needed
/// because wit-bindgen emits a distinct nominal type per interface
/// even when the underlying record is identical.
pub fn identifier_from_solver_wit(
    id: crate::exports::tegmentum::acme::solver::Identifier,
) -> acme_core::order::Identifier {
    acme_core::order::Identifier {
        kind: id.kind,
        value: id.value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every acme-core AcmeError variant must translate — a regression
    /// here would silently drop error information at the WIT boundary.
    #[test]
    fn every_orchestrator_error_variant_translates() {
        let cases = [
            acme_core::AcmeError::BadCsr("x".into()),
            acme_core::AcmeError::BadNonce("x".into()),
            acme_core::AcmeError::BadPublicKey("x".into()),
            acme_core::AcmeError::BadRevocationReason("x".into()),
            acme_core::AcmeError::BadSignatureAlgorithm("x".into()),
            acme_core::AcmeError::Caa("x".into()),
            acme_core::AcmeError::Compound("x".into()),
            acme_core::AcmeError::Connection("x".into()),
            acme_core::AcmeError::Dns("x".into()),
            acme_core::AcmeError::ExternalAccountRequired("x".into()),
            acme_core::AcmeError::IncorrectResponse("x".into()),
            acme_core::AcmeError::InvalidContact("x".into()),
            acme_core::AcmeError::Malformed("x".into()),
            acme_core::AcmeError::OrderNotReady("x".into()),
            acme_core::AcmeError::RateLimited("x".into()),
            acme_core::AcmeError::RejectedIdentifier("x".into()),
            acme_core::AcmeError::ServerInternal("x".into()),
            acme_core::AcmeError::Tls("x".into()),
            acme_core::AcmeError::Unauthorized("x".into()),
            acme_core::AcmeError::UnsupportedContact("x".into()),
            acme_core::AcmeError::UnsupportedIdentifier("x".into()),
            acme_core::AcmeError::UserActionRequired("x".into()),
            acme_core::AcmeError::AccountDoesNotExist("x".into()),
            acme_core::AcmeError::AlreadyRevoked("x".into()),
            acme_core::AcmeError::BadRevoked("x".into()),
            acme_core::AcmeError::Transport("x".into()),
            acme_core::AcmeError::Serialization("x".into()),
            acme_core::AcmeError::Jose("x".into()),
            acme_core::AcmeError::Timeout("x".into()),
            acme_core::AcmeError::MissingField("x".into()),
            acme_core::AcmeError::Http {
                status: 502,
                body: "gateway".into(),
            },
            acme_core::AcmeError::Other("x".into()),
        ];
        for case in cases {
            // Just make sure the mapping does not panic; the shape
            // equivalence is enforced by the compile-time exhaustive
            // match above.
            let _ = to_orchestrator_error(case);
        }
    }
}
