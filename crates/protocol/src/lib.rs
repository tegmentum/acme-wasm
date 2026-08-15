//! ACME protocol component — wit-bindgen adapter over `acme-core`.
//!
//! Layout mirrors `oauth2-protocol`: `wit_bindgen::generate!` at the
//! top, a `Component` unit struct that implements the wit-generated
//! `Guest` trait for each exported interface, and a small adapter
//! module per interface that translates between the wit-bindgen structs
//! and the plain-Rust types in `acme-core`.
//!
//! Two interfaces are wired here:
//!
//! - `solver` — pure primitives that need no I/O. Today the only
//!   resource is `tls-alpn01-solver`; adding `http01-solver` /
//!   `dns01-solver` is a matter of expanding the WIT and calling into
//!   the matching `acme-challenge-*` crate.
//! - `orchestrator` — the end-to-end `issue-certificate` verb. The
//!   protocol crate is I/O-free by design, so this component alone
//!   cannot drive the RFC 8555 flow; the entry point returns an
//!   `acme-error::other(...)` explaining that a `wac plug` step is
//!   required to compose in an HTTP-providing component (typically
//!   `acme-http-client`).

wit_bindgen::generate!({
    world: "protocol",
    path: "../../wit",
});

mod orchestrator;
mod solver;
mod types;

use exports::tegmentum::acme::orchestrator::{
    AcmeError as OrchestratorAcmeError, Guest as OrchestratorGuest,
    Identifier as OrchestratorIdentifier, IssuedCertificate,
};
use exports::tegmentum::acme::solver::{Guest as SolverGuest, GuestTlsAlpn01Solver};

struct Component;

impl SolverGuest for Component {
    type TlsAlpn01Solver = solver::TlsAlpn01Solver;
}

impl OrchestratorGuest for Component {
    fn issue_certificate(
        directory_url: String,
        contact: Vec<String>,
        identifiers: Vec<OrchestratorIdentifier>,
        cert_key_pem: String,
        account_key_jwk: String,
    ) -> Result<IssuedCertificate, OrchestratorAcmeError> {
        orchestrator::issue_certificate(
            directory_url,
            contact,
            identifiers,
            cert_key_pem,
            account_key_jwk,
        )
    }
}

// Re-export so `solver::TlsAlpn01Solver` can `impl GuestTlsAlpn01Solver`
// without pulling the full path into its module every time.
pub(crate) use GuestTlsAlpn01Solver as SolverGuestTlsAlpn01Solver;

export!(Component);
