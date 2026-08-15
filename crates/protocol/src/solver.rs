//! wit-bindgen adapter for the `solver` interface.
//!
//! Today the only resource is `tls-alpn01-solver` — a stateless handle
//! wrapping [`acme_challenge_tls_alpn_01::responder_cert_from_key_authorization`].
//! The resource shape is used so future solver flavors (`http01-solver`,
//! `dns01-solver`) can be added without reshaping the interface.

use crate::exports::tegmentum::acme::solver::Identifier as SolverIdentifier;
use crate::types::identifier_from_solver_wit;

/// Concrete resource type the wit-bindgen `resource tls-alpn01-solver`
/// binding hangs its `GuestTlsAlpn01Solver` trait off. Stateless — the
/// unit struct exists purely so the resource has something to own.
pub struct TlsAlpn01Solver;

impl crate::SolverGuestTlsAlpn01Solver for TlsAlpn01Solver {
    fn new() -> Self {
        Self
    }

    fn responder_cert(
        &self,
        id: SolverIdentifier,
        key_authorization: String,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let identifier = identifier_from_solver_wit(id);
        acme_challenge_tls_alpn_01::responder_cert_from_key_authorization(
            &identifier.value,
            &key_authorization,
        )
        .map(|resp| (resp.cert_der, resp.key_der))
        .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SolverGuestTlsAlpn01Solver;

    /// Smoke test — wiring only. Exhaustive tests for the responder
    /// cert live in `acme_challenge_tls_alpn_01::tests`. A successful
    /// call returns two non-empty blobs (cert-der, key-pkcs8-der).
    #[test]
    fn responder_cert_smoke() {
        let solver = TlsAlpn01Solver::new();
        let id = SolverIdentifier {
            kind: "dns".to_string(),
            value: "example.com".to_string(),
        };
        // A key authorization is just an opaque string as far as the
        // TLS-ALPN-01 responder is concerned; the driver already
        // combined the token with the account thumbprint.
        let ka = "token.thumbprint".to_string();
        let (cert_der, key_der) = solver
            .responder_cert(id, ka)
            .expect("build responder cert");
        assert!(!cert_der.is_empty(), "cert-der should be populated");
        assert!(!key_der.is_empty(), "key-pkcs8-der should be populated");
    }
}
