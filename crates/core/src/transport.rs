//! HTTP transport abstraction — the seam ACME logic uses to talk to
//! the CA without depending on any particular I/O stack.
//!
//! ACME needs three verbs:
//!
//! - `HEAD` on `newNonce` to prime the nonce pool (§7.2).
//! - `GET` on the directory URL (§7.1.1). Every other read uses
//!   POST-as-GET (§6.3), which we express through `post_jose`.
//! - `POST` with `Content-Type: application/jose+json` for every
//!   authenticated request.
//!
//! Making the seam a trait keeps `acme-core` independent of any HTTP
//! client. The wit-typed component under `crates/http-client` drives
//! this trait from `wasi:http/outgoing-handler`; host callers who want
//! a batteries-included transport enable the `native-http` feature and
//! use [`ReqwestTransport`] below.

use crate::error::{problem_from_response, AcmeError, Result};

/// One raw HTTP response.
///
/// Headers are a flat `Vec<(name, value)>` — ACME cares about several
/// headers that can legally repeat (`Link`, `Replay-Nonce`) so a `Map`
/// would drop information.
#[derive(Debug, Clone, Default)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// First header whose name matches case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// All values for the named header, in order.
    pub fn headers_all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// Convert a non-2xx response into an [`AcmeError`], parsing the
    /// body as an RFC 7807 problem document when possible.
    pub fn into_error(self) -> AcmeError {
        problem_from_response(self.status, self.header("Content-Type"), &self.body)
    }

    /// Consume this response, checking that the status is 2xx. On
    /// failure, returns the same problem-document translation used
    /// throughout the crate.
    pub fn ok(self) -> Result<Self> {
        if (200..300).contains(&self.status) {
            Ok(self)
        } else {
            Err(self.into_error())
        }
    }
}

/// Send / receive raw HTTP.
///
/// Every method is `&self` — implementations that need interior
/// mutability must handle it themselves. Object-safe by construction
/// (no generic parameters, no `Self` in argument position beyond the
/// receiver) so `Box<dyn HttpClient>` works.
pub trait HttpClient: Send + Sync {
    /// HEAD — only used against the directory's `newNonce` URL (§7.2).
    fn head(&self, url: &str) -> Result<HttpResponse>;

    /// GET — only used against the directory itself (§7.1.1). Every
    /// authenticated read after that goes through `post_jose` as a
    /// POST-as-GET (§6.3).
    fn get(&self, url: &str) -> Result<HttpResponse>;

    /// POST with `Content-Type: application/jose+json`. Body is the
    /// serialized JWS flattened form.
    fn post_jose(&self, url: &str, body: &[u8]) -> Result<HttpResponse>;
}

impl<T: HttpClient + ?Sized> HttpClient for std::sync::Arc<T> {
    fn head(&self, url: &str) -> Result<HttpResponse> {
        (**self).head(url)
    }
    fn get(&self, url: &str) -> Result<HttpResponse> {
        (**self).get(url)
    }
    fn post_jose(&self, url: &str, body: &[u8]) -> Result<HttpResponse> {
        (**self).post_jose(url, body)
    }
}

impl<T: HttpClient + ?Sized> HttpClient for &T {
    fn head(&self, url: &str) -> Result<HttpResponse> {
        (**self).head(url)
    }
    fn get(&self, url: &str) -> Result<HttpResponse> {
        (**self).get(url)
    }
    fn post_jose(&self, url: &str, body: &[u8]) -> Result<HttpResponse> {
        (**self).post_jose(url, body)
    }
}

// --------------------------------------------------------------------
// Reqwest-backed implementation. Gated behind `native-http` so the
// default build stays wasm32-wasip2 friendly (reqwest pulls in a
// native TLS stack).
// --------------------------------------------------------------------

#[cfg(feature = "native-http")]
pub use self::reqwest_impl::ReqwestTransport;

#[cfg(feature = "native-http")]
mod reqwest_impl {
    use super::{HttpClient, HttpResponse};
    use crate::error::{AcmeError, Result};

    /// Blocking reqwest-based [`HttpClient`]. Convenient for tests and
    /// CLI callers on a native host. Wasm builds should not enable
    /// the `native-http` feature and should instead compose the
    /// `crates/http-client` component with a `wasi:http` provider.
    pub struct ReqwestTransport {
        client: reqwest::blocking::Client,
    }

    impl Default for ReqwestTransport {
        fn default() -> Self {
            Self::new()
        }
    }

    impl ReqwestTransport {
        pub fn new() -> Self {
            let client = reqwest::blocking::Client::builder()
                .user_agent(concat!("tegmentum-acme-core/", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("reqwest client");
            Self { client }
        }

        pub fn with_client(client: reqwest::blocking::Client) -> Self {
            Self { client }
        }

        fn send(&self, req: reqwest::blocking::RequestBuilder) -> Result<HttpResponse> {
            let resp = req
                .send()
                .map_err(|e| AcmeError::Transport(e.to_string()))?;
            let status = resp.status().as_u16();
            let headers = resp
                .headers()
                .iter()
                .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();
            let body = resp
                .bytes()
                .map_err(|e| AcmeError::Transport(e.to_string()))?
                .to_vec();
            Ok(HttpResponse {
                status,
                headers,
                body,
            })
        }
    }

    impl HttpClient for ReqwestTransport {
        fn head(&self, url: &str) -> Result<HttpResponse> {
            self.send(self.client.head(url))
        }
        fn get(&self, url: &str) -> Result<HttpResponse> {
            self.send(self.client.get(url))
        }
        fn post_jose(&self, url: &str, body: &[u8]) -> Result<HttpResponse> {
            self.send(
                self.client
                    .post(url)
                    .header("Content-Type", "application/jose+json")
                    .body(body.to_vec()),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_lookup_is_case_insensitive() {
        let r = HttpResponse {
            status: 200,
            headers: vec![("Replay-Nonce".into(), "abc".into())],
            body: vec![],
        };
        assert_eq!(r.header("replay-nonce"), Some("abc"));
        assert_eq!(r.header("REPLAY-NONCE"), Some("abc"));
    }

    #[test]
    fn headers_all_preserves_order_and_repeats() {
        let r = HttpResponse {
            status: 200,
            headers: vec![
                ("Link".into(), "<one>;rel=\"up\"".into()),
                ("Content-Type".into(), "text/plain".into()),
                ("Link".into(), "<two>;rel=\"alternate\"".into()),
            ],
            body: vec![],
        };
        let links = r.headers_all("link");
        assert_eq!(links, vec!["<one>;rel=\"up\"", "<two>;rel=\"alternate\""]);
    }

    #[test]
    fn ok_passes_2xx() {
        let r = HttpResponse {
            status: 201,
            headers: vec![],
            body: vec![],
        };
        assert!(r.ok().is_ok());
    }

    #[test]
    fn ok_rejects_4xx_with_problem_body() {
        let r = HttpResponse {
            status: 400,
            headers: vec![("Content-Type".into(), "application/problem+json".into())],
            body: br#"{"type":"urn:ietf:params:acme:error:badNonce","detail":"stale"}"#.to_vec(),
        };
        let err = r.ok().unwrap_err();
        assert!(matches!(err, AcmeError::BadNonce(_)), "got {err:?}");
    }
}
