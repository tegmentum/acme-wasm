//! RFC 8737 — TLS Application-Layer Protocol Negotiation (ALPN)
//! Challenge for ACME (`tls-alpn-01`).
//!
//! The CA opens a TLS connection to port 443 of the identifier and
//! advertises the `acme-tls/1` ALPN protocol. The client must present
//! a self-signed certificate that:
//!
//! - Has a Subject Alternative Name (dNSName) matching the identifier.
//! - Carries the `acmeIdentifier` extension (OID 1.3.6.1.5.5.7.1.31),
//!   marked critical, whose extnValue is the DER-encoded OCTET STRING
//!   of the SHA-256 hash of the §8.1 key authorization.
//! - Is served on the connection that advertised ALPN `acme-tls/1`.
//!
//! This crate stays I/O-free — it builds the responder cert bytes and
//! matching keypair; the caller wires them into their own TLS acceptor
//! (rustls, native-tls, wasi:sockets-backed, whatever) scoped to the
//! `acme-tls/1` ALPN protocol.

use rcgen::{
    CertificateParams, CustomExtension, DistinguishedName, KeyPair, SanType, PKCS_ECDSA_P256_SHA256,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use acme_core::jws::AccountKey;

/// ALPN protocol identifier the CA advertises and the responder must
/// negotiate to (RFC 8737 §3).
pub const ACME_TLS_ALPN_PROTOCOL: &[u8] = b"acme-tls/1";

/// OID for the `id-pe-acmeIdentifier` extension (RFC 8737 §3), IANA
/// registered under the PKIX subtree.
///
/// `1.3.6.1.5.5.7.1.31`
pub const ACME_IDENTIFIER_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 31];

/// Errors from building the responder cert. Wraps rcgen's error type
/// so callers don't have to depend on rcgen directly.
#[derive(Debug, Error)]
pub enum TlsAlpn01Error {
    #[error("rcgen failed to build responder cert: {0}")]
    CertBuild(#[from] rcgen::Error),
}

/// The DER-encoded responder cert + matching PKCS#8 private key. Both
/// blobs are ready to hand to a TLS acceptor's cert-resolver keyed on
/// the `acme-tls/1` ALPN protocol.
#[derive(Debug, Clone)]
pub struct TlsAlpn01Responder {
    /// X.509 leaf cert, DER-encoded.
    pub cert_der: Vec<u8>,
    /// Private key, PKCS#8 DER-encoded (P-256).
    pub key_der: Vec<u8>,
}

/// Build the TLS-ALPN-01 responder cert for one identifier + challenge
/// pair.
///
/// The cert is self-signed, valid from now for one day (the CA
/// validates in seconds; we still pick a non-degenerate window so
/// stricter TLS stacks don't reject the leaf on parse).
pub fn responder_cert(
    identifier: &str,
    token: &str,
    account_key: &AccountKey,
) -> Result<TlsAlpn01Responder, TlsAlpn01Error> {
    // 1. Compute the raw SHA-256(key authorization). Note: acme-core's
    //    sha256_key_authorization returns the base64url-encoded form
    //    (used by DNS-01); TLS-ALPN-01 wants the raw 32 bytes to wrap
    //    in a DER OCTET STRING, so we compute here.
    let key_auth = acme_core::challenge::compute_key_authorization(token, account_key);
    let mut hasher = Sha256::new();
    hasher.update(key_auth.as_bytes());
    let hash: [u8; 32] = hasher.finalize().into();

    // 2. DER-encode as an OCTET STRING: tag 0x04, length 0x20 (32),
    //    then the 32 hash bytes. RFC 8737 §3 pins this shape exactly.
    let mut extn_value = Vec::with_capacity(34);
    extn_value.push(0x04);
    extn_value.push(0x20);
    extn_value.extend_from_slice(&hash);

    // 3. Build a P-256 self-signed cert with the SAN and the critical
    //    acmeIdentifier extension. Use ECDSA P-256 because it's the
    //    smallest widely-supported key type and rcgen has native
    //    support without extra features.
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut params = CertificateParams::new(vec![identifier.to_string()])?;
    params.distinguished_name = DistinguishedName::new();
    // Bracket the validity to a reasonable window; some strict TLS
    // stacks reject certs with equal not-before / not-after.
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(1);
    // Add the SAN as well as the CN — rcgen's `new(subject_alt_names)`
    // does the SAN, we don't need to redundantly push it.
    // Sanity-check the SAN encoded correctly:
    debug_assert!(params
        .subject_alt_names
        .iter()
        .any(|san| matches!(san, SanType::DnsName(_))));

    let mut ext = CustomExtension::from_oid_content(ACME_IDENTIFIER_OID, extn_value);
    ext.set_criticality(true);
    params.custom_extensions.push(ext);

    let cert = params.self_signed(&key_pair)?;
    let cert_der = cert.der().to_vec();
    let key_der = key_pair.serialize_der();
    Ok(TlsAlpn01Responder { cert_der, key_der })
}

#[cfg(test)]
mod tests {
    use super::*;
    use acme_core::jws::{AccountKey, EcdsaKey};
    use x509_cert::der::asn1::ObjectIdentifier;
    use x509_cert::der::Decode;
    use x509_cert::Certificate;

    const ACME_IDENTIFIER_OID_STR: &str = "1.3.6.1.5.5.7.1.31";
    const SUBJECT_ALT_NAME_OID_STR: &str = "2.5.29.17";

    fn test_account_key() -> AccountKey {
        let signing = p256::ecdsa::SigningKey::from_slice(&[0x11u8; 32]).expect("valid p256 seed");
        AccountKey::Ecdsa(EcdsaKey::P256(signing))
    }

    /// Locate our critical acmeIdentifier extension in the built cert
    /// and return its DER extnValue.
    fn extract_acme_identifier_ext(cert_der: &[u8]) -> (bool, Vec<u8>) {
        let cert = Certificate::from_der(cert_der).expect("parse leaf");
        let extensions = cert
            .tbs_certificate
            .extensions
            .as_ref()
            .expect("has extensions");
        let target: ObjectIdentifier = ACME_IDENTIFIER_OID_STR.parse().expect("valid OID");
        let ext = extensions
            .iter()
            .find(|e| e.extn_id == target)
            .expect("acmeIdentifier extension present");
        (ext.critical, ext.extn_value.as_bytes().to_vec())
    }

    #[test]
    fn responder_cert_is_marked_critical_and_carries_sha256_of_key_authorization() {
        let key = test_account_key();
        let token = "known-token-abc";
        let resp = responder_cert("example.com", token, &key).expect("build");

        // 1. Extension is critical.
        let (critical, extn_value) = extract_acme_identifier_ext(&resp.cert_der);
        assert!(critical, "acmeIdentifier extension MUST be critical");

        // 2. extnValue is OCTET STRING wrapping the raw SHA-256 hash.
        assert_eq!(extn_value.len(), 34, "OCTET STRING tag + length + 32 bytes");
        assert_eq!(extn_value[0], 0x04, "OCTET STRING tag");
        assert_eq!(extn_value[1], 0x20, "length = 32");

        // 3. The 32 hash bytes match SHA-256(key authorization).
        let key_auth = acme_core::challenge::compute_key_authorization(token, &key);
        let mut hasher = Sha256::new();
        hasher.update(key_auth.as_bytes());
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(&extn_value[2..], &expected);
    }

    #[test]
    fn responder_cert_has_san_matching_identifier() {
        let key = test_account_key();
        let resp = responder_cert("host.example.org", "tok", &key).expect("build");
        let cert = Certificate::from_der(&resp.cert_der).expect("parse leaf");
        let extensions = cert
            .tbs_certificate
            .extensions
            .as_ref()
            .expect("has extensions");
        // OID 2.5.29.17 = subjectAltName
        let san_oid: ObjectIdentifier = SUBJECT_ALT_NAME_OID_STR.parse().expect("valid OID");
        let san_ext = extensions
            .iter()
            .find(|e| e.extn_id == san_oid)
            .expect("SAN extension present");
        // Cheap smoke — DER-encoded GeneralNames sequence contains our
        // hostname bytes verbatim.
        let bytes = san_ext.extn_value.as_bytes();
        assert!(
            bytes
                .windows(b"host.example.org".len())
                .any(|w| w == b"host.example.org"),
            "SAN extnValue must contain the identifier bytes"
        );
    }

    #[test]
    fn key_der_is_pkcs8_p256() {
        let key = test_account_key();
        let resp = responder_cert("example.com", "tok", &key).expect("build");
        // p256 has a from_pkcs8_der on its SigningKey — if this parses
        // cleanly, the responder handed us a well-formed key.
        use p256::pkcs8::DecodePrivateKey;
        let _sk =
            p256::ecdsa::SigningKey::from_pkcs8_der(&resp.key_der).expect("parse PKCS#8 P-256 key");
    }
}
