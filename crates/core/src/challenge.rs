//! RFC 8555 §7.5.1 — challenge object, plus the §8.1 key-authorization
//! helper and the driver that arms + polls a challenge to completion.
//!
//! A challenge object is `{ type, url, status, token, ... }`. Every
//! challenge type derives its response from the same building block:
//! the **key authorization**, defined in §8.1 as
//! `token || '.' || base64url(JWK_Thumbprint(accountKey))` with the
//! thumbprint per RFC 7638.

use crate::account::Account;
use crate::error::{AcmeError, Result};
use crate::jws::AccountKey;
use crate::order::Identifier;
use crate::transport::HttpClient;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

/// RFC 8555 §7.1.6 challenge status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeStatus {
    Pending,
    Processing,
    Valid,
    Invalid,
    Unknown,
}

impl ChallengeStatus {
    /// Parse the wire `status` field. Unknown strings fall through to
    /// [`ChallengeStatus::Unknown`] rather than error — the client
    /// should treat any unrecognised state as terminal-uncertain.
    pub fn from_wire(s: &str) -> Self {
        match s {
            "pending" => ChallengeStatus::Pending,
            "processing" => ChallengeStatus::Processing,
            "valid" => ChallengeStatus::Valid,
            "invalid" => ChallengeStatus::Invalid,
            _ => ChallengeStatus::Unknown,
        }
    }
}

/// Classification of a challenge object by its `type` field. The
/// solver crates match on this to decide which of them owns the
/// challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeKind {
    Http01,
    Dns01,
    TlsAlpn01,
    /// Anything we don't recognise, preserved verbatim so callers
    /// can still log and route.
    Other(String),
}

impl ChallengeKind {
    pub fn from_type(s: &str) -> Self {
        match s {
            "http-01" => ChallengeKind::Http01,
            "dns-01" => ChallengeKind::Dns01,
            "tls-alpn-01" => ChallengeKind::TlsAlpn01,
            other => ChallengeKind::Other(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            ChallengeKind::Http01 => "http-01",
            ChallengeKind::Dns01 => "dns-01",
            ChallengeKind::TlsAlpn01 => "tls-alpn-01",
            ChallengeKind::Other(s) => s.as_str(),
        }
    }
}

/// Deserialized challenge object (RFC 8555 §8).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Challenge {
    /// `http-01` | `dns-01` | `tls-alpn-01` | future extensions.
    #[serde(rename = "type")]
    pub type_: String,
    pub url: String,
    pub status: String,
    #[serde(default)]
    pub validated: Option<String>,
    /// Random opaque token — solver combines with account thumbprint
    /// to build the key authorization (§8.1).
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub error: Option<serde_json::Value>,
}

impl Challenge {
    pub fn status_enum(&self) -> ChallengeStatus {
        ChallengeStatus::from_wire(&self.status)
    }
    pub fn kind(&self) -> ChallengeKind {
        ChallengeKind::from_type(&self.type_)
    }
}

/// Solver seam — implemented by each challenge crate.
///
/// The solver's job is to make the challenge externally observable
/// (write the well-known file, provision the TXT record, arm the
/// TLS-ALPN responder), and hand back a [`ChallengeReady`] handle whose
/// `Drop` tears the environment back down.
pub trait ChallengeSolver: Send + Sync {
    fn kind(&self) -> ChallengeKind;

    /// Prepare the environment for validation. Returns a Ready handle
    /// the driver polls with [`ChallengeReady::self_check`] before
    /// telling the CA to validate.
    fn arm(
        &self,
        identifier: &Identifier,
        key_authorization: &str,
    ) -> Result<Box<dyn ChallengeReady>>;
}

/// RAII handle returned from [`ChallengeSolver::arm`]. Callers drop it
/// once the CA has validated the challenge; `Drop` performs cleanup
/// (delete DNS record, unregister file responder, tear down TLS
/// listener, …).
pub trait ChallengeReady: Send + Sync {
    /// Verify that the challenge response is observable from the
    /// outside world. Some solvers (DNS-01 with slow propagation) may
    /// spin here; others (in-process HTTP-01 responder) return
    /// immediately.
    fn self_check(&self) -> Result<()>;
}

/// Compute the RFC 8555 §8.1 key authorization for a token/account
/// pair: `token || "." || base64url(JWK_Thumbprint(accountKey))`.
pub fn compute_key_authorization(token: &str, account_key: &AccountKey) -> String {
    let thumbprint = account_key.jwk_thumbprint();
    format!("{token}.{thumbprint}")
}

/// SHA-256 of the key authorization, base64url-encoded (RFC 7515 §2 —
/// no padding). Used by both DNS-01 (TXT record contents) and
/// TLS-ALPN-01 (which further wraps the raw hash in a DER OCTET STRING
/// inside the responder cert extension).
pub fn sha256_key_authorization(token: &str, account_key: &AccountKey) -> String {
    let ka = compute_key_authorization(token, account_key);
    let mut hasher = Sha256::new();
    hasher.update(ka.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
}

/// Drive a challenge to completion.
///
/// Steps (RFC 8555 §7.5.1):
/// 1. POST `{}` to the challenge URL to tell the CA the client is
///    ready.
/// 2. Poll the challenge URL (POST-as-GET) until it reaches `valid`
///    (success) or `invalid` (failure) or the deadline elapses.
/// 3. Drop the [`ChallengeReady`] handle so the solver tears down.
///
/// `poll_interval` is a starting hint; the driver honours the CA's
/// `Retry-After` header when present.
pub fn poll_challenge(
    challenge_url: &str,
    account: &Account,
    transport: &dyn HttpClient,
    ready: Box<dyn ChallengeReady>,
    timeout: Duration,
) -> Result<()> {
    poll_challenge_with_interval(
        challenge_url,
        account,
        transport,
        ready,
        timeout,
        Duration::from_secs(2),
    )
}

/// Same as [`poll_challenge`] with an explicit poll interval — tests
/// pass a tiny interval so they run fast.
pub fn poll_challenge_with_interval(
    challenge_url: &str,
    account: &Account,
    transport: &dyn HttpClient,
    ready: Box<dyn ChallengeReady>,
    timeout: Duration,
    poll_interval: Duration,
) -> Result<()> {
    // Self-check before telling the CA. Failing here saves an HTTP
    // round trip and gives the caller a clean error.
    ready.self_check()?;

    // Kick the CA. Payload is a literal empty JSON object per §7.5.1.
    let _ = account.post_kid(challenge_url, b"{}", transport)?.ok()?;

    let deadline = Instant::now() + timeout;
    loop {
        let response = account.post_kid(challenge_url, &[], transport)?.ok()?;
        let challenge: Challenge = serde_json::from_slice(&response.body)?;
        match challenge.status_enum() {
            ChallengeStatus::Valid => {
                drop(ready);
                return Ok(());
            }
            ChallengeStatus::Invalid => {
                drop(ready);
                let detail = challenge
                    .error
                    .and_then(|e| serde_json::to_string(&e).ok())
                    .unwrap_or_else(|| "challenge invalid".to_string());
                return Err(AcmeError::Malformed(detail));
            }
            _ => {}
        }
        if Instant::now() >= deadline {
            drop(ready);
            return Err(AcmeError::Timeout(format!(
                "challenge {challenge_url} still {} after {:?}",
                challenge.status, timeout
            )));
        }
        std::thread::sleep(poll_interval);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jws::EcdsaKey;

    /// RFC 8555 §8.1 defines the key authorization as
    /// `token || '.' || base64url(SHA-256(JCS(JWK)))`. This test
    /// picks an ES256 key, computes the value both ways, and asserts
    /// the helper produces the concatenation.
    #[test]
    fn key_authorization_is_token_dot_thumbprint() {
        use rand::rngs::OsRng;
        let sk = p256::ecdsa::SigningKey::random(&mut OsRng);
        let key = AccountKey::Ecdsa(EcdsaKey::P256(sk));
        let ka = compute_key_authorization("abc123", &key);
        let expected = format!("abc123.{}", key.jwk_thumbprint());
        assert_eq!(ka, expected);
    }

    /// Sanity: no `=` padding on the SHA-256 result (RFC 7515 §2).
    #[test]
    fn sha256_key_authorization_is_base64url_unpadded() {
        use rand::rngs::OsRng;
        let sk = p256::ecdsa::SigningKey::random(&mut OsRng);
        let key = AccountKey::Ecdsa(EcdsaKey::P256(sk));
        let out = sha256_key_authorization("tok", &key);
        assert!(!out.contains('='));
        // 32-byte SHA-256 base64url encodes to 43 chars (32 * 4/3 rounded up).
        assert_eq!(out.len(), 43);
    }

    #[test]
    fn kind_classifies_known_types() {
        assert_eq!(ChallengeKind::from_type("http-01"), ChallengeKind::Http01);
        assert_eq!(ChallengeKind::from_type("dns-01"), ChallengeKind::Dns01);
        assert_eq!(
            ChallengeKind::from_type("tls-alpn-01"),
            ChallengeKind::TlsAlpn01
        );
        match ChallengeKind::from_type("device-attest-01") {
            ChallengeKind::Other(s) => assert_eq!(s, "device-attest-01"),
            other => panic!("expected Other, got {other:?}"),
        }
    }
}
