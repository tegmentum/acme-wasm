//! RFC 8555 §7.3 — account lifecycle.
//!
//! An ACME account is identified by a public key. `newAccount` (§7.3)
//! either creates a fresh account (returning the account URL in the
//! `Location` header) or, with `onlyReturnExisting: true`, looks up an
//! existing account for a given key.
//!
//! The [`Account`] type here bundles the JSON fields RFC 8555 §7.1.2
//! defines with the runtime handles a caller needs to talk to the CA
//! after account creation: the private key, the account URL (`kid`),
//! and a shared nonce source.

use crate::directory::Directory;
use crate::error::{AcmeError, Result};
use crate::jws::{sign_jws_with_jwk, sign_jws_with_kid, AccountKey};
use crate::nonce::{NonceSource, ReplayNonceStore};
use crate::transport::{HttpClient, HttpResponse};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

/// Deserialized account object (RFC 8555 §7.1.2).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AccountRecord {
    /// One of `valid`, `deactivated`, `revoked`.
    #[serde(default)]
    pub status: String,
    /// Contact URLs (typically `mailto:` entries).
    #[serde(default)]
    pub contact: Vec<String>,
    /// True iff the account holder accepted the CA's terms of service.
    #[serde(rename = "termsOfServiceAgreed", default)]
    pub terms_of_service_agreed: Option<bool>,
    /// URL where the account's orders live (POST-as-GET returns the
    /// list). Not every CA populates this — Let's Encrypt omits it.
    #[serde(default)]
    pub orders: Option<String>,
    /// EAB payload the CA echoes back when the account was created
    /// with an external-account binding.
    #[serde(rename = "externalAccountBinding", default)]
    pub external_account_binding: Option<serde_json::Value>,
}

/// A live ACME account handle — the record plus everything a caller
/// needs to sign further requests: the private key, the account URL
/// (used as `kid` on every subsequent JWS), and a shared nonce store.
pub struct Account {
    /// Deserialized `newAccount` response body.
    pub record: AccountRecord,
    /// Account URL from the `Location` header. Every subsequent JWS
    /// carries this as its `kid` (§6.2).
    pub kid: String,
    /// Private key material. Never leaves the process.
    pub key: AccountKey,
    /// Shared nonce source. Every request in the flow consumes /
    /// refreshes this pool.
    pub nonce: Arc<dyn NonceSource>,
    /// The directory the account is bound to. Held so callers do not
    /// have to thread it separately through order-creation.
    pub directory: Directory,
}

impl Account {
    /// POST a signed request to `url` using the account's `kid` and
    /// key, absorbing any `Replay-Nonce` from the response.
    ///
    /// `payload` may be empty — that's the shape of POST-as-GET (§6.3).
    /// The response is returned as-is (including non-2xx) so callers
    /// can inspect headers before deciding to error out.
    pub fn post_kid(
        &self,
        url: &str,
        payload: &[u8],
        transport: &dyn HttpClient,
    ) -> Result<HttpResponse> {
        let nonce = self.nonce.get()?;
        let jws = sign_jws_with_kid(payload, url, &nonce, &self.kid, &self.key)?;
        let response = transport.post_jose(url, &jws)?;
        self.nonce.absorb(&response);
        Ok(response)
    }
}

impl std::fmt::Debug for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Account")
            .field("record", &self.record)
            .field("kid", &self.kid)
            .field("directory.new_order", &self.directory.new_order)
            .finish_non_exhaustive()
    }
}

/// POST `newAccount` and, on success, return an [`Account`] carrying
/// the deserialized record plus the runtime handles needed to sign
/// subsequent requests.
///
/// The JWS is signed with `jwk` (not `kid`) because the account URL
/// does not exist yet — the CA returns it in the `Location` header on
/// success.
pub fn create(
    directory: Directory,
    contact: &[String],
    terms_agreed: bool,
    key: AccountKey,
    transport: Arc<dyn HttpClient>,
) -> Result<Account> {
    create_with_options(
        directory,
        contact,
        terms_agreed,
        /* only_return_existing */ false,
        key,
        transport,
    )
}

/// Like [`create`] but exposes the `onlyReturnExisting` flag (§7.3.1)
/// so callers can look up an existing account without accidentally
/// spawning a duplicate on a fresh key.
pub fn create_with_options(
    directory: Directory,
    contact: &[String],
    terms_agreed: bool,
    only_return_existing: bool,
    key: AccountKey,
    transport: Arc<dyn HttpClient>,
) -> Result<Account> {
    let nonce_store = Arc::new(ReplayNonceStore::new(
        directory.new_nonce.clone(),
        transport.clone(),
    ));

    let payload = json!({
        "termsOfServiceAgreed": terms_agreed,
        "contact": contact,
        "onlyReturnExisting": only_return_existing,
    });
    let payload_bytes = serde_json::to_vec(&payload)?;
    let nonce = nonce_store.get()?;
    let jws =
        sign_jws_with_jwk(&payload_bytes, &directory.new_account, &nonce, &key)?;

    let response = transport.post_jose(&directory.new_account, &jws)?;
    nonce_store.absorb(&response);
    let response = response.ok()?;
    let kid = response
        .header("Location")
        .ok_or_else(|| AcmeError::MissingField("Location on newAccount response".into()))?
        .to_string();
    let record: AccountRecord = serde_json::from_slice(&response.body)?;
    Ok(Account {
        record,
        kid,
        key,
        nonce: nonce_store,
        directory,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jws::EcdsaKey;
    use crate::transport::HttpResponse;
    use p256::ecdsa::SigningKey;
    use rand::rngs::OsRng;
    use std::sync::Mutex;

    struct ScriptedCa {
        new_nonce_url: String,
        // Queue of (path-suffix, response) — head returns the first head-response,
        // post returns the first post-response.
        head_responses: Mutex<Vec<HttpResponse>>,
        post_responses: Mutex<Vec<HttpResponse>>,
        posts: Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl HttpClient for ScriptedCa {
        fn head(&self, url: &str) -> Result<HttpResponse> {
            assert_eq!(url, self.new_nonce_url);
            Ok(self.head_responses.lock().unwrap().remove(0))
        }
        fn get(&self, _url: &str) -> Result<HttpResponse> {
            unreachable!()
        }
        fn post_jose(&self, url: &str, body: &[u8]) -> Result<HttpResponse> {
            self.posts
                .lock()
                .unwrap()
                .push((url.to_string(), body.to_vec()));
            Ok(self.post_responses.lock().unwrap().remove(0))
        }
    }

    fn test_directory() -> Directory {
        Directory {
            new_nonce: "https://ca/new-nonce".into(),
            new_account: "https://ca/new-acct".into(),
            new_order: "https://ca/new-order".into(),
            new_authz: None,
            revoke_cert: "https://ca/revoke".into(),
            key_change: "https://ca/key-change".into(),
            renewal_info: None,
            meta: Default::default(),
        }
    }

    #[test]
    fn create_signs_with_jwk_and_captures_kid_from_location() {
        let sk = SigningKey::random(&mut OsRng);
        let account_key = AccountKey::Ecdsa(EcdsaKey::P256(sk));

        let transport = Arc::new(ScriptedCa {
            new_nonce_url: "https://ca/new-nonce".into(),
            head_responses: Mutex::new(vec![HttpResponse {
                status: 200,
                headers: vec![("Replay-Nonce".into(), "n0".into())],
                body: vec![],
            }]),
            post_responses: Mutex::new(vec![HttpResponse {
                status: 201,
                headers: vec![
                    ("Location".into(), "https://ca/acct/42".into()),
                    ("Replay-Nonce".into(), "n1".into()),
                ],
                body: br#"{"status":"valid","contact":["mailto:zw@example"]}"#.to_vec(),
            }]),
            posts: Mutex::new(vec![]),
        });

        let account = create(
            test_directory(),
            &["mailto:zw@example".into()],
            true,
            account_key,
            transport.clone(),
        )
        .expect("create");

        assert_eq!(account.kid, "https://ca/acct/42");
        assert_eq!(account.record.status, "valid");
        assert_eq!(
            account.record.contact.first().map(String::as_str),
            Some("mailto:zw@example")
        );

        // The follow-on nonce from the newAccount response is in the pool.
        let n = account.nonce.get().unwrap();
        assert_eq!(n, "n1");

        // Inspect the posted JWS: header carries jwk (not kid), the
        // correct url, and the primed nonce.
        let posts = transport.posts.lock().unwrap();
        let (url, body) = &posts[0];
        assert_eq!(url, "https://ca/new-acct");
        let v: serde_json::Value = serde_json::from_slice(body).unwrap();
        let protected = v["protected"].as_str().unwrap();
        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(protected)
            .unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["url"], "https://ca/new-acct");
        assert_eq!(header["nonce"], "n0");
        assert_eq!(header["alg"], "ES256");
        assert!(header.get("kid").is_none());
        assert_eq!(header["jwk"]["kty"], "EC");
    }

    #[test]
    fn create_missing_location_is_missing_field_error() {
        let sk = SigningKey::random(&mut OsRng);
        let account_key = AccountKey::Ecdsa(EcdsaKey::P256(sk));

        let transport = Arc::new(ScriptedCa {
            new_nonce_url: "https://ca/new-nonce".into(),
            head_responses: Mutex::new(vec![HttpResponse {
                status: 200,
                headers: vec![("Replay-Nonce".into(), "n0".into())],
                body: vec![],
            }]),
            post_responses: Mutex::new(vec![HttpResponse {
                status: 201,
                headers: vec![("Replay-Nonce".into(), "n1".into())],
                body: br#"{"status":"valid"}"#.to_vec(),
            }]),
            posts: Mutex::new(vec![]),
        });

        let err = create(
            test_directory(),
            &[],
            true,
            account_key,
            transport,
        )
        .unwrap_err();
        assert!(matches!(err, AcmeError::MissingField(_)), "got {err:?}");
    }

    use base64::Engine as _;
}
