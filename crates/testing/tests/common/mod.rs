//! Shared helpers for the three Pebble-driven integration tests.

use acme_core::certificate::split_pem_chain;
use acme_core::jws::{AccountKey, EcdsaKey};
use x509_cert::der::Decode;
use x509_cert::Certificate;

/// Fresh P-256 account key. Random per test invocation — Pebble's
/// account store is in-memory and resets between compose bring-ups
/// anyway, but re-using an account key across tests would just add
/// coupling for zero benefit.
pub fn fresh_account_key() -> AccountKey {
    use rand::rngs::OsRng;
    let sk = p256::ecdsa::SigningKey::random(&mut OsRng);
    AccountKey::Ecdsa(EcdsaKey::P256(sk))
}

/// Parse the returned PEM chain, pull out the leaf, and assert its
/// Subject Alternative Name extension contains the expected DNS name
/// as a substring — cheap check, no full ASN.1 walk of GeneralNames
/// but sufficient to prove the cert was issued for the identifier we
/// asked for.
pub fn assert_leaf_has_san(pem_chain: &[u8], expected_dns: &str) {
    let blocks = split_pem_chain(pem_chain);
    assert!(!blocks.is_empty(), "PEM chain contained no CERTIFICATE blocks");
    // rustls-pemfile: strip the `-----BEGIN/END-----` framing and
    // base64-decode.
    let mut cursor = &*blocks[0];
    let der = rustls_pemfile::certs(&mut cursor)
        .next()
        .expect("leaf DER present")
        .expect("leaf DER parses");
    let cert = Certificate::from_der(&der).expect("leaf certificate parses");

    let extensions = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .expect("leaf has extensions");
    let san_oid: x509_cert::der::asn1::ObjectIdentifier =
        "2.5.29.17".parse().expect("SAN OID literal");
    let san_ext = extensions
        .iter()
        .find(|e| e.extn_id == san_oid)
        .expect("leaf has SAN extension");
    let bytes = san_ext.extn_value.as_bytes();
    assert!(
        bytes
            .windows(expected_dns.len())
            .any(|w| w == expected_dns.as_bytes()),
        "SAN extension does not contain `{expected_dns}`: {:?}",
        String::from_utf8_lossy(bytes)
    );
}
