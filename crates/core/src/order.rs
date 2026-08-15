//! RFC 8555 §7.4 — order lifecycle.
//!
//! An order requests issuance for a specific set of identifiers
//! (typically DNS names, one per SAN entry on the resulting cert).
//! Its lifecycle is a state machine: `pending` → `ready` →
//! `processing` → `valid`, with `invalid` as a terminal failure state
//! (§7.1.6).

use crate::account::Account;
use crate::error::{AcmeError, Result};
use crate::transport::HttpClient;
use serde::{Deserialize, Serialize};
use serde_json::json;

/// One identifier the order asks the CA to issue for. RFC 8555
/// enumerates only the `dns` type; RFC 8738 adds `ip`. Unknown types
/// pass through unchanged so downstream extensions keep working.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Identifier {
    #[serde(rename = "type")]
    pub kind: String,
    pub value: String,
}

impl Identifier {
    /// Build a DNS identifier (the common case).
    pub fn dns(name: impl Into<String>) -> Self {
        Self {
            kind: "dns".into(),
            value: name.into(),
        }
    }
}

/// RFC 8555 §7.1.6 order status enum. The `Unknown` fallback keeps
/// forward-compatibility with any new status the RFC adds later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderStatus {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
    Unknown,
}

impl OrderStatus {
    /// Parse the wire `status` field. Unknown strings fall through to
    /// [`OrderStatus::Unknown`] rather than error.
    pub fn from_wire(s: &str) -> Self {
        match s {
            "pending" => OrderStatus::Pending,
            "ready" => OrderStatus::Ready,
            "processing" => OrderStatus::Processing,
            "valid" => OrderStatus::Valid,
            "invalid" => OrderStatus::Invalid,
            _ => OrderStatus::Unknown,
        }
    }
}

/// Deserialized order record (RFC 8555 §7.1.3).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Order {
    /// `pending` | `ready` | `processing` | `valid` | `invalid`.
    pub status: String,
    /// When the order expires (RFC 3339). CAs vary — Let's Encrypt
    /// gives a week.
    #[serde(default)]
    pub expires: Option<String>,
    pub identifiers: Vec<Identifier>,
    #[serde(rename = "notBefore", default)]
    pub not_before: Option<String>,
    #[serde(rename = "notAfter", default)]
    pub not_after: Option<String>,
    /// Set when `status = invalid`. Carries the problem document.
    #[serde(default)]
    pub error: Option<serde_json::Value>,
    /// URLs of each identifier's authorization object.
    pub authorizations: Vec<String>,
    /// URL to POST the CSR to.
    pub finalize: String,
    /// URL to GET (POST-as-GET) the issued PEM chain from once the
    /// order reaches `valid`.
    #[serde(default)]
    pub certificate: Option<String>,
    /// Order URL — populated from the `Location` header on creation.
    /// Not part of the JSON body; kept as a runtime handle so callers
    /// can poll and finalize without threading the URL separately.
    #[serde(skip)]
    pub url: String,
}

impl Order {
    pub fn status_enum(&self) -> OrderStatus {
        OrderStatus::from_wire(&self.status)
    }
}

/// POST `newOrder`, returning the created order.
///
/// The `identifiers` slice becomes the SAN list on the eventual
/// certificate — the CSR the client submits to `finalize` must cover
/// exactly this list (§7.4).
pub fn create(
    account: &Account,
    identifiers: &[Identifier],
    transport: &dyn HttpClient,
) -> Result<Order> {
    let payload = json!({ "identifiers": identifiers });
    let payload_bytes = serde_json::to_vec(&payload)?;
    let response = account.post_kid(&account.directory.new_order, &payload_bytes, transport)?;
    let url = response
        .header("Location")
        .ok_or_else(|| AcmeError::MissingField("Location on newOrder response".into()))?
        .to_string();
    let response = response.ok()?;
    let mut order: Order = serde_json::from_slice(&response.body)?;
    order.url = url;
    Ok(order)
}

/// POST-as-GET the order URL to fetch its current state. Used both by
/// [`crate::certificate::finalize`] and by callers that want to poll
/// manually.
pub fn refresh(
    account: &Account,
    order_url: &str,
    transport: &dyn HttpClient,
) -> Result<Order> {
    let response = account.post_kid(order_url, &[], transport)?.ok()?;
    let mut order: Order = serde_json::from_slice(&response.body)?;
    order.url = order_url.to_string();
    Ok(order)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_dns_helper() {
        assert_eq!(
            Identifier::dns("example.com"),
            Identifier {
                kind: "dns".into(),
                value: "example.com".into(),
            }
        );
    }

    #[test]
    fn status_enum_parses_known_states() {
        assert_eq!(OrderStatus::from_wire("pending"), OrderStatus::Pending);
        assert_eq!(OrderStatus::from_wire("ready"), OrderStatus::Ready);
        assert_eq!(OrderStatus::from_wire("processing"), OrderStatus::Processing);
        assert_eq!(OrderStatus::from_wire("valid"), OrderStatus::Valid);
        assert_eq!(OrderStatus::from_wire("invalid"), OrderStatus::Invalid);
        assert_eq!(OrderStatus::from_wire("weird"), OrderStatus::Unknown);
    }

    #[test]
    fn order_deserializes_from_rfc_shape() {
        let body = br#"{
            "status": "pending",
            "expires": "2025-01-01T00:00:00Z",
            "identifiers": [{"type": "dns", "value": "example.com"}],
            "authorizations": ["https://ca/authz/1"],
            "finalize": "https://ca/order/1/finalize"
        }"#;
        let order: Order = serde_json::from_slice(body).unwrap();
        assert_eq!(order.status_enum(), OrderStatus::Pending);
        assert_eq!(order.identifiers.len(), 1);
        assert_eq!(order.finalize, "https://ca/order/1/finalize");
        assert!(order.certificate.is_none());
    }
}
