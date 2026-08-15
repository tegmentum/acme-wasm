//! RFC 7515 flattened JWS assembly for ACME (RFC 8555 §6.2).
//!
//! ACME wraps every authenticated request in a *flattened* JWS
//! (RFC 7515 §7.2.2). The protected header carries:
//!
//! - `alg` — one of RS256 / ES256 / ES384 / EdDSA.
//! - `nonce` — the most recent `Replay-Nonce` (§6.5).
//! - `url` — the exact URL the request is going to (bound into the
//!   signature to defeat cross-endpoint replay).
//! - Either `jwk` (first-time `newAccount`, or `revokeCert` when
//!   signing with the cert's key) OR `kid` (every other authenticated
//!   request; value is the account URL returned by `newAccount`).
//!
//! Payload is an arbitrary byte slice. ACME's POST-as-GET convention
//! (§6.3) uses an empty payload; the flattened form still needs the
//! empty-string encoding for `payload`.
//!
//! The RS256 / ES256 / ES384 signing paths are implemented directly on
//! top of `rsa` / `p256` / `p384` because `oauth2-core` currently
//! exposes only *verification* primitives (see
//! `oauth2_core::crypto_backend`). If oauth2-core grows a signing seam
//! upstream, migrate to it and remove the direct crypto here — the
//! module boundary is designed to make that swap mechanical.

use crate::error::{AcmeError, Result};
use base64::Engine;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

// ------------------------------------------------------------------
// Public account-key type — the union of every alg RFC 8555 §6.2 allows.
// ------------------------------------------------------------------

/// Private key material used to sign ACME requests.
///
/// The `alg` header emitted by the JWS layer is derived directly from
/// the variant, so callers cannot accidentally pair (say) an RSA key
/// with an ES256 header.
pub enum AccountKey {
    /// RSA — signed with RS256 (PKCS#1 v1.5 over SHA-256). Any modulus
    /// size the CA accepts (Let's Encrypt requires ≥ 2048 bits).
    Rsa(rsa::RsaPrivateKey),
    /// ECDSA on a NIST curve. RFC 8555 §6.2 permits P-256 and P-384.
    Ecdsa(EcdsaKey),
    /// Ed25519 — accepted by some CAs (RFC 8032 signatures, `alg=EdDSA`).
    Ed25519(ed25519_dalek::SigningKey),
}

/// ECDSA curve + key material. Split out from [`AccountKey`] because
/// the same enum is reused inside [`crate::csr::CertificateKey`].
pub enum EcdsaKey {
    /// NIST P-256 → `alg=ES256`.
    P256(p256::ecdsa::SigningKey),
    /// NIST P-384 → `alg=ES384`.
    P384(p384::ecdsa::SigningKey),
}

impl AccountKey {
    /// JOSE `alg` header value for this key.
    pub fn alg(&self) -> &'static str {
        match self {
            AccountKey::Rsa(_) => "RS256",
            AccountKey::Ecdsa(EcdsaKey::P256(_)) => "ES256",
            AccountKey::Ecdsa(EcdsaKey::P384(_)) => "ES384",
            AccountKey::Ed25519(_) => "EdDSA",
        }
    }

    /// Public JWK for this key (RFC 7517 §4 shape). Fields are emitted
    /// in the canonical order required by the RFC 7638 thumbprint
    /// (see [`jwk_thumbprint`]).
    pub fn public_jwk(&self) -> Value {
        match self {
            AccountKey::Rsa(sk) => {
                use rsa::traits::PublicKeyParts;
                let pk = sk.to_public_key();
                let n = b64url(&pk.n().to_bytes_be());
                let e = b64url(&pk.e().to_bytes_be());
                // RFC 7638 §3.2 canonical order for RSA: {"e","kty","n"}.
                json!({ "e": e, "kty": "RSA", "n": n })
            }
            AccountKey::Ecdsa(EcdsaKey::P256(sk)) => {
                let vk = sk.verifying_key();
                let point = vk.to_encoded_point(false);
                let x = b64url(point.x().expect("SEC1 x"));
                let y = b64url(point.y().expect("SEC1 y"));
                // RFC 7638 §3.2 canonical order for EC: {"crv","kty","x","y"}.
                json!({ "crv": "P-256", "kty": "EC", "x": x, "y": y })
            }
            AccountKey::Ecdsa(EcdsaKey::P384(sk)) => {
                let vk = sk.verifying_key();
                let point = vk.to_encoded_point(false);
                let x = b64url(point.x().expect("SEC1 x"));
                let y = b64url(point.y().expect("SEC1 y"));
                json!({ "crv": "P-384", "kty": "EC", "x": x, "y": y })
            }
            AccountKey::Ed25519(sk) => {
                let vk = sk.verifying_key();
                let x = b64url(vk.as_bytes());
                // RFC 8037 §2 canonical order for OKP: {"crv","kty","x"}.
                json!({ "crv": "Ed25519", "kty": "OKP", "x": x })
            }
        }
    }

    /// RFC 7638 JWK thumbprint (SHA-256, base64url without padding).
    /// Used to derive the challenge key authorization (RFC 8555 §8.1)
    /// and to identify accounts across CAs.
    pub fn jwk_thumbprint(&self) -> String {
        jwk_thumbprint(&self.public_jwk())
    }
}

/// Compute the RFC 7638 thumbprint of an already-canonicalised JWK.
///
/// The JWK MUST be laid out with keys in the order the RFC dictates
/// per key type — [`AccountKey::public_jwk`] produces one such layout.
/// Passing an arbitrary `Value` where keys are in a different order
/// will yield a different (invalid) thumbprint.
pub fn jwk_thumbprint(jwk: &Value) -> String {
    // `serde_json::to_string` on a `Value` built with `json!({..})`
    // preserves the insertion order of the macro's object literal, so
    // the callers above control the ordering.
    let bytes = serde_json::to_vec(jwk).expect("JWK is always serializable");
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    b64url(&hasher.finalize())
}

// ------------------------------------------------------------------
// Header + flattened JWS on-wire shapes.
// ------------------------------------------------------------------

#[derive(Serialize)]
struct ProtectedHeader<'a> {
    alg: &'a str,
    // Exactly one of `jwk` / `kid` per §6.2.
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
    nonce: &'a str,
    url: &'a str,
}

/// Flattened JWS (RFC 7515 §7.2.2).
#[derive(Serialize)]
struct Flattened<'a> {
    protected: &'a str,
    payload: &'a str,
    signature: &'a str,
}

// ------------------------------------------------------------------
// Public entry points.
// ------------------------------------------------------------------

/// Sign an ACME request using the `jwk` header form (RFC 8555 §6.2).
///
/// Used for `newAccount` (the CA does not yet know the account's URL,
/// so it identifies the key by embedding the JWK in the header) and
/// for `revokeCert` when signing with the certificate's own key.
pub fn sign_jws_with_jwk(
    payload: &[u8],
    url: &str,
    nonce: &str,
    key: &AccountKey,
) -> Result<Vec<u8>> {
    sign_jws_inner(payload, url, nonce, Some(key.public_jwk()), None, key)
}

/// Sign an ACME request using the `kid` header form (RFC 8555 §6.2).
///
/// Used for every authenticated request after the account has been
/// created. `kid` is the account URL (the `Location` header returned
/// by `newAccount`).
pub fn sign_jws_with_kid(
    payload: &[u8],
    url: &str,
    nonce: &str,
    kid: &str,
    key: &AccountKey,
) -> Result<Vec<u8>> {
    sign_jws_inner(payload, url, nonce, None, Some(kid), key)
}

fn sign_jws_inner(
    payload: &[u8],
    url: &str,
    nonce: &str,
    jwk: Option<Value>,
    kid: Option<&str>,
    key: &AccountKey,
) -> Result<Vec<u8>> {
    let header = ProtectedHeader {
        alg: key.alg(),
        jwk,
        kid,
        nonce,
        url,
    };
    let header_bytes =
        serde_json::to_vec(&header).map_err(|e| AcmeError::Jose(format!("header: {e}")))?;
    let protected_b64 = b64url(&header_bytes);
    // RFC 8555 §6.3 (POST-as-GET) sends an empty payload; the base64url
    // of an empty byte slice is the empty string, which is exactly what
    // the flattened form needs. No special-casing required.
    let payload_b64 = b64url(payload);
    let signing_input = format!("{protected_b64}.{payload_b64}");

    let signature = sign_bytes(signing_input.as_bytes(), key)?;
    let signature_b64 = b64url(&signature);

    let out = Flattened {
        protected: &protected_b64,
        payload: &payload_b64,
        signature: &signature_b64,
    };
    serde_json::to_vec(&out).map_err(|e| AcmeError::Jose(format!("serialize: {e}")))
}

fn sign_bytes(input: &[u8], key: &AccountKey) -> Result<Vec<u8>> {
    match key {
        AccountKey::Rsa(sk) => {
            use rsa::pkcs1v15::SigningKey as RsaSigning;
            use rsa::signature::{SignatureEncoding, Signer};
            let signer = RsaSigning::<sha2::Sha256>::new(sk.clone());
            let sig = signer.sign(input);
            Ok(sig.to_bytes().into_vec())
        }
        AccountKey::Ecdsa(EcdsaKey::P256(sk)) => {
            use p256::ecdsa::signature::Signer;
            use p256::ecdsa::Signature;
            let sig: Signature = sk.sign(input);
            // JWS ES256 = raw r || s, fixed 64 bytes (RFC 7518 §3.4).
            Ok(sig.to_bytes().to_vec())
        }
        AccountKey::Ecdsa(EcdsaKey::P384(sk)) => {
            use p384::ecdsa::signature::Signer;
            use p384::ecdsa::Signature;
            let sig: Signature = sk.sign(input);
            // JWS ES384 = raw r || s, fixed 96 bytes (RFC 7518 §3.4).
            Ok(sig.to_bytes().to_vec())
        }
        AccountKey::Ed25519(sk) => {
            use ed25519_dalek::Signer;
            let sig = sk.sign(input);
            Ok(sig.to_bytes().to_vec())
        }
    }
}

/// Base64url without padding (RFC 4648 §5 / RFC 7515 §2).
fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn decode_b64url(s: &str) -> Vec<u8> {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .expect("valid b64url")
    }

    // -- RFC 7638 §3.1 thumbprint reference vector -----------------------
    //
    // The RFC publishes exactly one worked example: an RSA public key
    // whose canonical JSON serialization SHA-256 to a specific 32-byte
    // digest, base64url-encoded as `NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs`.
    // This verifies our JWK canonical ordering and thumbprint helper.
    const RFC7638_RSA_JWK: &str = r#"{
        "kty":"RSA",
        "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e":"AQAB",
        "alg":"RS256",
        "kid":"2011-04-29"
    }"#;
    const RFC7638_EXPECTED_THUMBPRINT: &str = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

    #[test]
    fn rfc7638_thumbprint_reference_vector() {
        // Parse the RFC's example JWK and rebuild it in canonical form
        // (only {e, kty, n}, in that order) — exactly what our
        // `AccountKey::public_jwk` path emits.
        let v: Value = serde_json::from_str(RFC7638_RSA_JWK).unwrap();
        let canonical = json!({
            "e": v["e"],
            "kty": v["kty"],
            "n": v["n"],
        });
        assert_eq!(jwk_thumbprint(&canonical), RFC7638_EXPECTED_THUMBPRINT);
    }

    // -- RS256 round trip -----------------------------------------------

    /// Generate a fresh 2048-bit RSA key for the RS256 test. 2048 bits
    /// takes ~1s in debug mode — an embedded PKCS#8 fixture would be
    /// faster, but keygen-in-test keeps us bulletproof against
    /// encoding-format drift in the `rsa` crate.
    fn test_rsa_key() -> AccountKey {
        let sk = rsa::RsaPrivateKey::new(&mut OsRng, 2048).expect("RSA-2048 keygen");
        AccountKey::Rsa(sk)
    }

    #[test]
    fn rs256_jws_roundtrip_verifies_signature() {
        use rsa::pkcs1v15::{Signature, VerifyingKey};
        use rsa::signature::Verifier;

        let key = test_rsa_key();
        let payload = br#"{"termsOfServiceAgreed":true}"#;
        let jws = sign_jws_with_jwk(payload, "https://acme.example/newAccount", "abcdefgh", &key)
            .expect("sign");

        // Deserialize the flattened JWS and reconstruct the signing input.
        let v: Value = serde_json::from_slice(&jws).unwrap();
        let protected = v["protected"].as_str().unwrap();
        let payload_seg = v["payload"].as_str().unwrap();
        let signature_seg = v["signature"].as_str().unwrap();
        let signing_input = format!("{protected}.{payload_seg}");

        // Sanity: header carries the right nonce / url / alg and jwk.
        let header_bytes = decode_b64url(protected);
        let header: Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["nonce"], "abcdefgh");
        assert_eq!(header["url"], "https://acme.example/newAccount");
        assert_eq!(header["jwk"]["kty"], "RSA");
        assert!(header.get("kid").is_none());

        // Payload round-trips exactly.
        assert_eq!(decode_b64url(payload_seg), payload);

        // The signature verifies against the public key.
        let AccountKey::Rsa(sk) = key else {
            unreachable!()
        };
        let pk = sk.to_public_key();
        let verifier: VerifyingKey<sha2::Sha256> = VerifyingKey::new(pk);
        let sig_bytes = decode_b64url(signature_seg);
        let sig = Signature::try_from(sig_bytes.as_slice()).unwrap();
        verifier
            .verify(signing_input.as_bytes(), &sig)
            .expect("signature verifies");
    }

    #[test]
    fn es256_jws_roundtrip_verifies_signature() {
        use p256::ecdsa::signature::Verifier;
        use p256::ecdsa::{Signature, SigningKey};

        let sk = SigningKey::random(&mut OsRng);
        let vk = *sk.verifying_key();
        let key = AccountKey::Ecdsa(EcdsaKey::P256(sk));

        let payload = b"";
        let jws = sign_jws_with_kid(
            payload,
            "https://acme.example/order/1",
            "n1",
            "acct-42",
            &key,
        )
        .expect("sign");
        let v: Value = serde_json::from_slice(&jws).unwrap();
        let protected = v["protected"].as_str().unwrap();
        let payload_seg = v["payload"].as_str().unwrap();
        let signature_seg = v["signature"].as_str().unwrap();

        let header: Value = serde_json::from_slice(&decode_b64url(protected)).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "acct-42");
        assert!(header.get("jwk").is_none());
        // POST-as-GET: payload segment must be the empty string.
        assert_eq!(payload_seg, "");

        let signing_input = format!("{protected}.{payload_seg}");
        let sig = Signature::from_slice(&decode_b64url(signature_seg)).unwrap();
        vk.verify(signing_input.as_bytes(), &sig)
            .expect("ES256 verifies");
    }

    #[test]
    fn es384_jws_roundtrip_verifies_signature() {
        use p384::ecdsa::signature::Verifier;
        use p384::ecdsa::{Signature, SigningKey};

        let sk = SigningKey::random(&mut OsRng);
        let vk = *sk.verifying_key();
        let key = AccountKey::Ecdsa(EcdsaKey::P384(sk));

        let payload = br#"{"contact":["mailto:zw@example"]}"#;
        let jws = sign_jws_with_jwk(payload, "https://acme.example/newAccount", "nOnCe", &key)
            .expect("sign");
        let v: Value = serde_json::from_slice(&jws).unwrap();
        let protected = v["protected"].as_str().unwrap();
        let payload_seg = v["payload"].as_str().unwrap();
        let signature_seg = v["signature"].as_str().unwrap();

        let header: Value = serde_json::from_slice(&decode_b64url(protected)).unwrap();
        assert_eq!(header["alg"], "ES384");
        assert_eq!(header["jwk"]["crv"], "P-384");

        let signing_input = format!("{protected}.{payload_seg}");
        let sig = Signature::from_slice(&decode_b64url(signature_seg)).unwrap();
        vk.verify(signing_input.as_bytes(), &sig)
            .expect("ES384 verifies");
    }

    #[test]
    fn ed25519_jws_roundtrip_verifies_signature() {
        use ed25519_dalek::{Signature, SigningKey, Verifier};

        let mut seed = [0u8; 32];
        // Deterministic-enough for a unit test — real callers should use
        // `SigningKey::generate(&mut OsRng)`.
        for (i, b) in seed.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();
        let key = AccountKey::Ed25519(sk);

        let payload = br#"{}"#;
        let jws =
            sign_jws_with_kid(payload, "https://acme.example/kid", "n", "acct-1", &key).unwrap();
        let v: Value = serde_json::from_slice(&jws).unwrap();
        let protected = v["protected"].as_str().unwrap();
        let payload_seg = v["payload"].as_str().unwrap();
        let signature_seg = v["signature"].as_str().unwrap();

        let header: Value = serde_json::from_slice(&decode_b64url(protected)).unwrap();
        assert_eq!(header["alg"], "EdDSA");

        let signing_input = format!("{protected}.{payload_seg}");
        let sig_bytes = decode_b64url(signature_seg);
        let sig = Signature::from_slice(&sig_bytes).unwrap();
        vk.verify(signing_input.as_bytes(), &sig)
            .expect("Ed25519 verifies");
    }

    #[test]
    fn jwk_thumbprint_from_account_key_matches_manual_hash() {
        // AccountKey emits a canonical JWK, so this must equal the
        // hand-computed thumbprint of a JWK built the same way.
        let sk = p256::ecdsa::SigningKey::random(&mut OsRng);
        let key = AccountKey::Ecdsa(EcdsaKey::P256(sk));
        let via_helper = key.jwk_thumbprint();

        let jwk = key.public_jwk();
        let bytes = serde_json::to_vec(&jwk).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let via_manual = b64url(&hasher.finalize());

        assert_eq!(via_helper, via_manual);
    }
}
