//! RFC 8555 §7.5 — authorization objects.
//!
//! Each identifier in an order has a corresponding authorization
//! object listing the challenges the client can complete to prove
//! control of that identifier. The client picks one challenge,
//! provisions the response, POSTs the challenge URL to signal
//! readiness, and polls the authorization until it flips to `valid`
//! (or `invalid`).

use crate::account::Account;
use crate::challenge::Challenge;
use crate::error::Result;
use crate::order::Identifier;
use crate::transport::HttpClient;
use serde::{Deserialize, Serialize};

/// RFC 8555 §7.1.6 authorization status enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationStatus {
    Pending,
    Valid,
    Invalid,
    Deactivated,
    Expired,
    Revoked,
    Unknown,
}

impl AuthorizationStatus {
    /// Parse the wire `status` field. Unknown strings fall through to
    /// [`AuthorizationStatus::Unknown`] rather than error.
    pub fn from_wire(s: &str) -> Self {
        match s {
            "pending" => AuthorizationStatus::Pending,
            "valid" => AuthorizationStatus::Valid,
            "invalid" => AuthorizationStatus::Invalid,
            "deactivated" => AuthorizationStatus::Deactivated,
            "expired" => AuthorizationStatus::Expired,
            "revoked" => AuthorizationStatus::Revoked,
            _ => AuthorizationStatus::Unknown,
        }
    }
}

/// Deserialized authorization record (RFC 8555 §7.1.4).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Authorization {
    pub identifier: Identifier,
    pub status: String,
    #[serde(default)]
    pub expires: Option<String>,
    pub challenges: Vec<Challenge>,
    /// True iff the authorization is for a wildcard identifier.
    #[serde(default)]
    pub wildcard: bool,
}

impl Authorization {
    pub fn status_enum(&self) -> AuthorizationStatus {
        AuthorizationStatus::from_wire(&self.status)
    }
}

/// POST-as-GET the authorization URL and deserialize the response.
pub fn fetch(url: &str, account: &Account, transport: &dyn HttpClient) -> Result<Authorization> {
    let response = account.post_kid(url, &[], transport)?.ok()?;
    let authz: Authorization = serde_json::from_slice(&response.body)?;
    Ok(authz)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_enum_parses_known_states() {
        assert_eq!(
            AuthorizationStatus::from_wire("pending"),
            AuthorizationStatus::Pending
        );
        assert_eq!(
            AuthorizationStatus::from_wire("valid"),
            AuthorizationStatus::Valid
        );
        assert_eq!(
            AuthorizationStatus::from_wire("invalid"),
            AuthorizationStatus::Invalid
        );
        assert_eq!(
            AuthorizationStatus::from_wire("deactivated"),
            AuthorizationStatus::Deactivated
        );
        assert_eq!(
            AuthorizationStatus::from_wire("weird"),
            AuthorizationStatus::Unknown
        );
    }

    #[test]
    fn parses_rfc_shape() {
        let body = br#"{
            "identifier": {"type": "dns", "value": "example.com"},
            "status": "pending",
            "expires": "2025-01-01T00:00:00Z",
            "challenges": [
                {
                    "type": "http-01",
                    "url": "https://ca/chall/1",
                    "status": "pending",
                    "token": "tok"
                }
            ],
            "wildcard": false
        }"#;
        let authz: Authorization = serde_json::from_slice(body).unwrap();
        assert_eq!(authz.status_enum(), AuthorizationStatus::Pending);
        assert_eq!(authz.identifier.value, "example.com");
        assert_eq!(authz.challenges.len(), 1);
        assert_eq!(authz.challenges[0].kind().as_str(), "http-01");
    }
}
