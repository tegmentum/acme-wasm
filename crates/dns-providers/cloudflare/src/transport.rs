//! HTTP transport abstraction for the Cloudflare provider.
//!
//! Kept minimal (sync, one method, no streaming) so a `reqwest` on
//! native, a `wasi:http/outgoing-handler` adapter in a wasm build, and
//! a [`MockTransport`] in tests can all fit behind the same trait
//! object. Mirrors the shape of `acme-core::HttpClient` — same three
//! verbs, same `HttpResponse` shape — but is a separate trait because
//! Cloudflare needs additional headers on every request that ACME
//! doesn't (Bearer auth, JSON content-type).

use std::sync::Mutex;

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Delete,
}

impl HttpMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Delete => "DELETE",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("http transport failure: {0}")]
    Http(String),
    #[error("http transport misuse: {0}")]
    Misuse(String),
}

pub trait HttpTransport: Send + Sync {
    fn request(
        &self,
        method: HttpMethod,
        url: &str,
        body: &[u8],
        headers: &[(String, String)],
    ) -> Result<HttpResponse, TransportError>;
}

// ---- test transport ----

/// One expected call for the [`MockTransport`] script.
#[derive(Debug, Clone)]
pub struct MockCall {
    pub expected_method: HttpMethod,
    /// The URL is asserted by *suffix* to keep tests robust against
    /// `api_base` overrides.
    pub expected_url_suffix: String,
    /// Header assertions are subset — the mock passes if every
    /// expected header appears in the actual header list.
    pub expected_headers: Vec<(String, String)>,
    /// Body assertions are substring — the mock passes if every
    /// expected fragment appears in the actual body.
    pub expected_body_contains: Vec<String>,
    /// Response the mock returns when the assertion passes.
    pub reply: HttpResponse,
}

/// Sequential script for tests: the Nth `request()` call is asserted
/// against the Nth `MockCall`. Panics if the script is exhausted or if
/// an expectation fails — tests should assert on the returned
/// `Result` after the sequence.
pub struct MockTransport {
    script: Mutex<Vec<MockCall>>,
}

impl MockTransport {
    pub fn new(script: Vec<MockCall>) -> Self {
        Self {
            script: Mutex::new(script),
        }
    }
}

impl HttpTransport for MockTransport {
    fn request(
        &self,
        method: HttpMethod,
        url: &str,
        body: &[u8],
        headers: &[(String, String)],
    ) -> Result<HttpResponse, TransportError> {
        let mut script = self.script.lock().unwrap();
        let call = script.remove(0);

        assert_eq!(call.expected_method, method, "method mismatch for {url}");
        assert!(
            url.ends_with(&call.expected_url_suffix),
            "url `{url}` does not end with `{}`",
            call.expected_url_suffix
        );
        for (k, v) in &call.expected_headers {
            assert!(
                headers
                    .iter()
                    .any(|(hk, hv)| hk.eq_ignore_ascii_case(k) && hv == v),
                "header `{k}: {v}` not found in {headers:?}",
            );
        }
        let body_str = std::str::from_utf8(body).unwrap_or("");
        for fragment in &call.expected_body_contains {
            assert!(
                body_str.contains(fragment.as_str()),
                "body missing fragment `{fragment}`; body was {body_str}",
            );
        }
        Ok(call.reply)
    }
}
