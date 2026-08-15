//! PKCS#10 CSR generation for the finalize step (RFC 8555 §7.4).
//!
//! The `finalize` POST carries a base64url-encoded (RFC 4648 §5, no
//! padding) DER PKCS#10 CertificationRequest. The CSR's Subject
//! Alternative Name extension must exactly match the identifiers in
//! the order — a mismatch triggers `badCSR` (§6.7).
//!
//! Delegates the ASN.1 heavy lifting to `rcgen`. The certificate key
//! is generated separately from the account key — rotating the cert
//! key on every renewal reduces blast radius.

use crate::error::{AcmeError, Result};
use crate::order::Identifier;
use rcgen::{
    CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ED25519,
};

/// Private key material for the issued certificate.
///
/// Structurally parallel to [`crate::jws::AccountKey`] but stored as
/// `rcgen::KeyPair` because that is what the CSR builder wants. The
/// two enums stay separate because:
///
/// - Account keys need `alg` in the JOSE sense (RS256 / ES256 / …).
/// - Certificate keys need a `rcgen::SignatureAlgorithm` handle plus
///   `EncodePrivateKey`-compatible bytes for downstream storage.
pub struct CertificateKey {
    key_pair: KeyPair,
}

impl CertificateKey {
    /// Generate a fresh P-256 keypair. This is the sensible default —
    /// short signatures, universal CA support, no key-size decision.
    pub fn generate_p256() -> Result<Self> {
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| AcmeError::Jose(format!("keygen P-256: {e}")))?;
        Ok(Self { key_pair })
    }

    /// Generate a fresh P-384 keypair.
    pub fn generate_p384() -> Result<Self> {
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384)
            .map_err(|e| AcmeError::Jose(format!("keygen P-384: {e}")))?;
        Ok(Self { key_pair })
    }

    /// Generate a fresh Ed25519 keypair. Some CAs still reject EdDSA
    /// certs; use ECDSA / RSA if in doubt.
    pub fn generate_ed25519() -> Result<Self> {
        let key_pair = KeyPair::generate_for(&PKCS_ED25519)
            .map_err(|e| AcmeError::Jose(format!("keygen Ed25519: {e}")))?;
        Ok(Self { key_pair })
    }

    /// Serialize the private key as PKCS#8 PEM — for callers that
    /// need to persist it alongside the issued certificate.
    pub fn to_pkcs8_pem(&self) -> String {
        self.key_pair.serialize_pem()
    }

    /// Serialize the private key as PKCS#8 DER.
    pub fn to_pkcs8_der(&self) -> Vec<u8> {
        self.key_pair.serialize_der()
    }

    /// Access the underlying `rcgen::KeyPair`. Escape hatch for
    /// callers that want to reuse the key elsewhere (e.g. install it
    /// into a `rustls::sign::CertifiedKey`).
    pub fn key_pair(&self) -> &KeyPair {
        &self.key_pair
    }
}

/// Build a PKCS#10 CSR covering `identifiers` and signed by
/// `private_key`. Returns DER (raw bytes) — the finalize helper
/// base64url-encodes it before embedding in the JWS payload.
///
/// Only `dns`-type identifiers land in the SAN list; other identifier
/// types produce a `badCSR`-equivalent local error because rcgen has
/// no obvious mapping (RFC 8738 adds IP identifiers — plumb those
/// through when the crate grows IP support).
pub fn build_csr(private_key: &CertificateKey, identifiers: &[Identifier]) -> Result<Vec<u8>> {
    if identifiers.is_empty() {
        return Err(AcmeError::BadCsr("no identifiers".into()));
    }
    let dns_names: Vec<String> = identifiers
        .iter()
        .map(|id| {
            if id.kind == "dns" {
                Ok(id.value.clone())
            } else {
                Err(AcmeError::BadCsr(format!(
                    "unsupported identifier type: {}",
                    id.kind
                )))
            }
        })
        .collect::<Result<_>>()?;

    let params = CertificateParams::new(dns_names)
        .map_err(|e| AcmeError::BadCsr(format!("csr params: {e}")))?;
    let csr = params
        .serialize_request(&private_key.key_pair)
        .map_err(|e| AcmeError::BadCsr(format!("csr sign: {e}")))?;
    Ok(csr.der().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_cert::der::Decode;

    #[test]
    fn build_csr_produces_valid_der_for_dns_san() {
        let key = CertificateKey::generate_p256().unwrap();
        let der = build_csr(&key, &[Identifier::dns("example.com")]).unwrap();

        // The output must be a well-formed CertificationRequest.
        let parsed = x509_cert::request::CertReq::from_der(&der)
            .expect("valid PKCS#10 CertificationRequest DER");
        // Public key OID is ecPublicKey.
        assert_eq!(
            parsed
                .info
                .public_key
                .algorithm
                .oid
                .to_string(),
            "1.2.840.10045.2.1"
        );
    }

    #[test]
    fn build_csr_rejects_empty_identifiers() {
        let key = CertificateKey::generate_p256().unwrap();
        match build_csr(&key, &[]) {
            Err(AcmeError::BadCsr(_)) => {}
            other => panic!("expected BadCsr, got {other:?}"),
        }
    }

    #[test]
    fn build_csr_rejects_non_dns_identifiers() {
        let key = CertificateKey::generate_p256().unwrap();
        let id = Identifier {
            kind: "email".into(),
            value: "root@example.com".into(),
        };
        match build_csr(&key, &[id]) {
            Err(AcmeError::BadCsr(msg)) => assert!(msg.contains("email")),
            other => panic!("expected BadCsr, got {other:?}"),
        }
    }
}
