//! Cloudflare DNS provider — first concrete implementation of the
//! [`DnsProvider`] trait for the DNS-01 solver.
//!
//! Talks to Cloudflare's DNS Records REST API
//! (`https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records`),
//! authenticating via a scoped API token
//! (`Authorization: Bearer <token>`). Global API Key is deliberately
//! not supported — scoped tokens are Cloudflare's recommended path and
//! avoid handing the ACME client the keys to the entire account.
//!
//! HTTP transport is abstracted behind [`HttpTransport`] so the same
//! provider composes with:
//!
//! - a `reqwest::Client` on native Rust (opt in via the `native-http`
//!   feature),
//! - a `wasi:http/outgoing-handler`-backed adapter in a Wasm build,
//! - a [`MockTransport`] in tests.
//!
//! Zone resolution: [`ZoneLookup::Static`] takes a precomputed map;
//! [`ZoneLookup::ByName`] calls `/zones?name={apex}` on demand and
//! caches the result in a `Mutex<HashMap>`.

use std::collections::HashMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use acme_challenge_dns_01::{DnsProvider, DnsProviderError, RecordHandle};

pub mod transport;

pub use transport::{HttpMethod, HttpResponse, HttpTransport, MockTransport, TransportError};

const CLOUDFLARE_API_BASE: &str = "https://api.cloudflare.com/client/v4";
const DEFAULT_TTL_SECONDS: u32 = 60;

/// Errors specific to the Cloudflare provider. The [`DnsProvider`]
/// impl flattens these into [`DnsProviderError`] variants — this type
/// is exposed so callers who want fine-grained retry logic can match
/// on it before flattening.
#[derive(Debug, Error)]
pub enum CloudflareError {
    #[error("cloudflare transport error: {0}")]
    Transport(#[from] TransportError),

    #[error("cloudflare API rejected request: {0}")]
    Api(String),

    #[error("no zone found for `{0}`; supply a static ZoneLookup or grant Zone:Read on the account token")]
    NoZone(String),

    #[error("malformed cloudflare response: {0}")]
    BadResponse(String),
}

impl From<CloudflareError> for DnsProviderError {
    fn from(e: CloudflareError) -> Self {
        match e {
            CloudflareError::Transport(t) => DnsProviderError::Transport(t.to_string()),
            CloudflareError::Api(m) => DnsProviderError::Rejected(m),
            CloudflareError::NoZone(z) => DnsProviderError::ZoneNotFound(z),
            CloudflareError::BadResponse(m) => DnsProviderError::Rejected(m),
        }
    }
}

/// Strategy for turning an identifier (`_acme-challenge.example.com`)
/// into the Cloudflare zone id it lives under.
///
/// `Static` skips any API round-trip — callers who already know their
/// zones from Terraform / infra IaC set this and cap the token to
/// `Zone:DNS:Edit` on just those zones (no `Zone:Read` on the account
/// required).
///
/// `ByName` looks the zone up on demand via `/zones?name={apex}` and
/// caches the result. Simpler operationally, needs a token with
/// `Zone:Read` on the parent account plus `Zone:DNS:Edit` on the
/// target zones.
pub enum ZoneLookup {
    Static(HashMap<String, String>),
    ByName {
        cache: Mutex<HashMap<String, String>>,
    },
}

impl ZoneLookup {
    /// Precomputed apex → zone id map. Take `("example.com".into(),
    /// "abcd1234...".into())` at construction time.
    pub fn static_map(m: HashMap<String, String>) -> Self {
        Self::Static(m)
    }

    /// Lazy lookup via `/zones?name=`. Results cache in-process until
    /// the provider is dropped.
    pub fn by_name() -> Self {
        Self::ByName {
            cache: Mutex::new(HashMap::new()),
        }
    }
}

/// Cloudflare DNS provider — construct with an API token and a
/// [`ZoneLookup`] strategy, plug the resulting `Box<dyn DnsProvider>`
/// into an [`acme_challenge_dns_01`] solver.
pub struct CloudflareProvider<T: HttpTransport> {
    token: String,
    lookup: ZoneLookup,
    transport: T,
    api_base: String,
}

impl<T: HttpTransport> CloudflareProvider<T> {
    pub fn new(token: impl Into<String>, lookup: ZoneLookup, transport: T) -> Self {
        Self {
            token: token.into(),
            lookup,
            transport,
            api_base: CLOUDFLARE_API_BASE.to_string(),
        }
    }

    /// Override the API base. Only useful for tests that point at a
    /// mock server; production deploys should leave the default.
    pub fn with_api_base(mut self, base: impl Into<String>) -> Self {
        self.api_base = base.into();
        self
    }

    fn auth_headers(&self) -> Vec<(String, String)> {
        vec![
            (
                "Authorization".to_string(),
                format!("Bearer {}", self.token),
            ),
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ]
    }

    /// The apex of a record name. `_acme-challenge.api.example.com` →
    /// `example.com`. Naive two-label rule works for every real TLD we
    /// care about; PSL-aware resolution is out of scope for v0.
    ///
    /// Callers with unusual TLDs (`.co.uk`, effective TLDs) should use
    /// [`ZoneLookup::Static`] and skip this heuristic.
    fn apex_from_record_name(name: &str) -> String {
        let labels: Vec<&str> = name.split('.').collect();
        if labels.len() <= 2 {
            name.to_string()
        } else {
            labels[labels.len() - 2..].join(".")
        }
    }

    fn resolve_zone_id(&self, record_name: &str) -> Result<String, CloudflareError> {
        let apex = Self::apex_from_record_name(record_name);
        match &self.lookup {
            ZoneLookup::Static(m) => m.get(&apex).cloned().ok_or(CloudflareError::NoZone(apex)),
            ZoneLookup::ByName { cache } => {
                if let Some(cached) = cache.lock().unwrap().get(&apex).cloned() {
                    return Ok(cached);
                }
                let url = format!("{}/zones?name={}", self.api_base, urlencoding_encode(&apex));
                let resp =
                    self.transport
                        .request(HttpMethod::Get, &url, &[], &self.auth_headers())?;
                let zones: CfListResponse<CfZone> = serde_json::from_slice(&resp.body)
                    .map_err(|e| CloudflareError::BadResponse(e.to_string()))?;
                if !zones.success {
                    return Err(cf_api_error(zones.errors));
                }
                let id = zones
                    .result
                    .into_iter()
                    .next()
                    .ok_or_else(|| CloudflareError::NoZone(apex.clone()))?
                    .id;
                cache.lock().unwrap().insert(apex, id.clone());
                Ok(id)
            }
        }
    }
}

impl<T: HttpTransport + Send + Sync> DnsProvider for CloudflareProvider<T> {
    fn upsert_txt(
        &self,
        name: &str,
        value: &str,
        ttl_seconds: u32,
    ) -> Result<RecordHandle, DnsProviderError> {
        let zone_id = self.resolve_zone_id(name).map_err(DnsProviderError::from)?;
        let url = format!("{}/zones/{}/dns_records", self.api_base, zone_id);
        let body = serde_json::to_vec(&CfCreateTxtRequest {
            record_type: "TXT",
            name,
            content: value,
            ttl: if ttl_seconds == 0 {
                DEFAULT_TTL_SECONDS
            } else {
                ttl_seconds
            },
        })
        .map_err(|e| DnsProviderError::Rejected(e.to_string()))?;
        let resp = self
            .transport
            .request(HttpMethod::Post, &url, &body, &self.auth_headers())
            .map_err(CloudflareError::from)
            .map_err(DnsProviderError::from)?;
        let created: CfSingleResponse<CfDnsRecord> = serde_json::from_slice(&resp.body)
            .map_err(|e| CloudflareError::BadResponse(e.to_string()))
            .map_err(DnsProviderError::from)?;
        if !created.success {
            return Err(DnsProviderError::from(cf_api_error(created.errors)));
        }
        let record = created.result.ok_or_else(|| {
            DnsProviderError::from(CloudflareError::BadResponse(
                "success: true but result missing".into(),
            ))
        })?;
        // Encode `zone_id/record_id` in the handle so delete can find
        // the record without a second name→zone lookup.
        Ok(RecordHandle::new(format!("{zone_id}/{}", record.id)))
    }

    fn delete_txt(&self, handle: &RecordHandle) -> Result<(), DnsProviderError> {
        let s = handle.as_str();
        let (zone_id, record_id) = s
            .split_once('/')
            .ok_or_else(|| DnsProviderError::Rejected(format!("malformed handle `{s}`")))?;
        let url = format!("{}/zones/{zone_id}/dns_records/{record_id}", self.api_base);
        let resp = self
            .transport
            .request(HttpMethod::Delete, &url, &[], &self.auth_headers())
            .map_err(CloudflareError::from)
            .map_err(DnsProviderError::from)?;
        // Cloudflare returns 200 with success: true on delete, and
        // 404-ish shapes on missing records. Treat 404 (or success:
        // false with a "not found" style error) as OK per the trait's
        // idempotency contract.
        if resp.status == 404 {
            return Ok(());
        }
        let deleted: CfSingleResponse<CfDnsRecord> = serde_json::from_slice(&resp.body)
            .map_err(|e| CloudflareError::BadResponse(e.to_string()))
            .map_err(DnsProviderError::from)?;
        if !deleted.success {
            let is_not_found = deleted
                .errors
                .iter()
                .any(|e| e.message.to_lowercase().contains("not found"));
            if is_not_found {
                return Ok(());
            }
            return Err(DnsProviderError::from(cf_api_error(deleted.errors)));
        }
        Ok(())
    }
}

fn cf_api_error(errors: Vec<CfError>) -> CloudflareError {
    if errors.is_empty() {
        CloudflareError::Api("unknown error (success: false with no error detail)".into())
    } else {
        CloudflareError::Api(
            errors
                .iter()
                .map(|e| format!("{}: {}", e.code, e.message))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }
}

/// Minimal URL-form encoding for zone lookup query strings. Cloudflare
/// zone names are DNS labels and `.` — nothing that actually needs
/// percent-encoding — but be defensive.
fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ---- Cloudflare wire types ---------------------------------------------

#[derive(Serialize)]
struct CfCreateTxtRequest<'a> {
    #[serde(rename = "type")]
    record_type: &'static str,
    name: &'a str,
    content: &'a str,
    ttl: u32,
}

#[derive(Deserialize)]
struct CfListResponse<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<CfError>,
    #[serde(default = "Vec::new")]
    result: Vec<T>,
}

#[derive(Deserialize)]
struct CfSingleResponse<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<CfError>,
    // Option<T> deserializes to None on a missing field without needing
    // T: Default — a plain `#[serde(default)]` here would demand it.
    result: Option<T>,
}

#[derive(Deserialize)]
struct CfZone {
    id: String,
    #[serde(default)]
    #[allow(dead_code)]
    name: String,
}

#[derive(Deserialize)]
struct CfDnsRecord {
    id: String,
}

#[derive(Deserialize, Debug)]
struct CfError {
    code: i64,
    message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider_with_mock(mock: MockTransport) -> CloudflareProvider<MockTransport> {
        let mut map = HashMap::new();
        map.insert("example.com".into(), "zone-abcd".into());
        CloudflareProvider::new("test-token", ZoneLookup::static_map(map), mock)
    }

    #[test]
    fn upsert_txt_posts_bearer_json_and_returns_zone_slash_id_handle() {
        let mock = MockTransport::new(vec![transport::MockCall {
            expected_method: HttpMethod::Post,
            expected_url_suffix: "/zones/zone-abcd/dns_records".into(),
            expected_headers: vec![
                ("Authorization".into(), "Bearer test-token".into()),
                ("Content-Type".into(), "application/json".into()),
            ],
            expected_body_contains: vec![
                "\"type\":\"TXT\"".into(),
                "\"name\":\"_acme-challenge.example.com\"".into(),
                "\"content\":\"deadbeef\"".into(),
                "\"ttl\":60".into(),
            ],
            reply: HttpResponse {
                status: 200,
                headers: vec![],
                body: br#"{"success":true,"errors":[],"result":{"id":"rec-xyz"}}"#.to_vec(),
            },
        }]);

        let provider = provider_with_mock(mock);
        let handle = provider
            .upsert_txt("_acme-challenge.example.com", "deadbeef", 60)
            .expect("upsert");
        assert_eq!(handle.as_str(), "zone-abcd/rec-xyz");
    }

    #[test]
    fn delete_txt_hits_correct_zone_and_record() {
        let mock = MockTransport::new(vec![transport::MockCall {
            expected_method: HttpMethod::Delete,
            expected_url_suffix: "/zones/zone-abcd/dns_records/rec-xyz".into(),
            expected_headers: vec![("Authorization".into(), "Bearer test-token".into())],
            expected_body_contains: vec![],
            reply: HttpResponse {
                status: 200,
                headers: vec![],
                body: br#"{"success":true,"errors":[],"result":{"id":"rec-xyz"}}"#.to_vec(),
            },
        }]);
        let provider = provider_with_mock(mock);
        provider
            .delete_txt(&RecordHandle::new("zone-abcd/rec-xyz"))
            .expect("delete");
    }

    #[test]
    fn delete_txt_is_idempotent_on_404() {
        let mock = MockTransport::new(vec![transport::MockCall {
            expected_method: HttpMethod::Delete,
            expected_url_suffix: "/zones/zone-abcd/dns_records/rec-gone".into(),
            expected_headers: vec![],
            expected_body_contains: vec![],
            reply: HttpResponse {
                status: 404,
                headers: vec![],
                body: b"{}".to_vec(),
            },
        }]);
        let provider = provider_with_mock(mock);
        provider
            .delete_txt(&RecordHandle::new("zone-abcd/rec-gone"))
            .expect("delete idempotent on 404");
    }

    #[test]
    fn apex_extraction_takes_last_two_labels() {
        assert_eq!(
            CloudflareProvider::<MockTransport>::apex_from_record_name(
                "_acme-challenge.api.example.com",
            ),
            "example.com"
        );
        assert_eq!(
            CloudflareProvider::<MockTransport>::apex_from_record_name("_acme-challenge.foo.io"),
            "foo.io"
        );
    }

    #[test]
    fn cf_api_error_flattens_multiple_errors() {
        let e = cf_api_error(vec![
            CfError {
                code: 1004,
                message: "DNS Validation Error".into(),
            },
            CfError {
                code: 9109,
                message: "Zone not editable".into(),
            },
        ]);
        let s = e.to_string();
        assert!(s.contains("1004: DNS Validation Error"));
        assert!(s.contains("9109: Zone not editable"));
    }
}
