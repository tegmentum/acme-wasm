//! ACME HTTP-client component — wasi:http-driven transport for
//! [`acme_core::transport::HttpClient`].
//!
//! `acme-core` factors out the HTTP seam so the pure protocol logic
//! (nonce handling, JWS-with-nonce assembly, order / authorization /
//! challenge state machines, CSR generation) never mentions a
//! particular network stack. This crate is the wit-typed adapter that
//! wires that seam to `wasi:http/outgoing-handler@0.2.3`, so an ACME
//! order can be driven end-to-end inside a wasm component.
//!
//! `WasiHttpClient` is a zero-sized handle — every request runs
//! against the ambient `wasi:http` capability the host grants the
//! component instance, so there is no client-side connection pool or
//! long-lived state to carry.
//!
//! Only the three verbs ACME actually uses are wired:
//!
//! - `HEAD` on `newNonce` (RFC 8555 §7.2).
//! - `GET` on the directory URL (RFC 8555 §7.1.1). Every authenticated
//!   read after that is a POST-as-GET (RFC 8555 §6.3) and rides
//!   `post_jose`.
//! - `POST` with `Content-Type: application/jose+json` (RFC 8555 §6.2)
//!   for every authenticated request.

// The wit-bindgen macro emits bindings for the `http-client` world
// declared in `wit/acme.wit`. `generate_all` pulls in the transitively
// referenced `wasi:*` packages (`wasi:io/poll`, `wasi:io/streams`,
// `wasi:clocks`, …) that `wasi:http` cross-references, saving us an
// explicit `with:` mapping per package.
wit_bindgen::generate!({
    world: "http-client",
    path: "../../wit",
    generate_all,
});

use acme_core::error::{AcmeError, Result};
use acme_core::transport::{HttpClient, HttpResponse};

use crate::wasi::http::outgoing_handler;
use crate::wasi::http::types::{
    Fields, IncomingResponse, Method, OutgoingBody, OutgoingRequest, Scheme,
};
use crate::wasi::io::streams::StreamError;

// The `http-client` world declares `export types`, but that interface
// currently defines only records and variants (no functions) — so
// wit-bindgen emits no `Guest` trait to implement, and there is
// intentionally no `export!(...)` here. When `types` grows a
// functional method (e.g. a helper the host wants to invoke), add a
// unit `Component` struct and `export!(Component);` alongside the
// per-interface `Guest` impl.

// ---------------------------------------------------------------------------
// Public API.
// ---------------------------------------------------------------------------

/// [`HttpClient`](acme_core::transport::HttpClient) implementation
/// backed by `wasi:http/outgoing-handler`.
///
/// Zero-sized — there is no per-instance state because `wasi:http`
/// draws its capability from the component's imports rather than from
/// a client-side connection pool. Constructing one is free; a single
/// instance can be shared (via `Arc`) across every module in
/// `acme-core` that needs to hit the CA.
#[derive(Debug, Default, Clone, Copy)]
pub struct WasiHttpClient;

impl WasiHttpClient {
    /// Create a fresh handle. Equivalent to `WasiHttpClient::default()`.
    pub const fn new() -> Self {
        Self
    }
}

impl HttpClient for WasiHttpClient {
    fn head(&self, url: &str) -> Result<HttpResponse> {
        round_trip(Method::Head, url, None)
    }

    fn get(&self, url: &str) -> Result<HttpResponse> {
        round_trip(Method::Get, url, None)
    }

    fn post_jose(&self, url: &str, body: &[u8]) -> Result<HttpResponse> {
        round_trip(
            Method::Post,
            url,
            Some(JoseBody {
                content_type: "application/jose+json",
                bytes: body,
            }),
        )
    }
}

// ---------------------------------------------------------------------------
// wasi:http round-trip.
// ---------------------------------------------------------------------------

/// A body plus its `Content-Type`, borrowed for the duration of the
/// request build. `None` means "no body" — used for HEAD / GET.
struct JoseBody<'a> {
    content_type: &'static str,
    bytes: &'a [u8],
}

fn round_trip(method: Method, url: &str, body: Option<JoseBody<'_>>) -> Result<HttpResponse> {
    let (scheme, authority, path_with_query) = parse_url(url)?;

    let headers = Fields::new();
    // Some hosts require an explicit Host header even though wasi:http
    // conveys the authority separately; set it defensively so the
    // proxy adapter's behaviour is predictable across providers.
    headers
        .append(&"host".to_string(), authority.as_bytes())
        .map_err(|e| AcmeError::Transport(format!("append host header: {e:?}")))?;
    if let Some(b) = &body {
        headers
            .append(&"content-type".to_string(), b.content_type.as_bytes())
            .map_err(|e| AcmeError::Transport(format!("append content-type: {e:?}")))?;
    }

    let request = OutgoingRequest::new(headers);
    request
        .set_method(&method)
        .map_err(|()| AcmeError::Transport("wasi:http set_method rejected value".into()))?;
    request
        .set_scheme(Some(&scheme))
        .map_err(|()| AcmeError::Transport("wasi:http set_scheme rejected value".into()))?;
    request
        .set_authority(Some(&authority))
        .map_err(|()| AcmeError::Transport("wasi:http set_authority rejected value".into()))?;
    request
        .set_path_with_query(Some(&path_with_query))
        .map_err(|()| {
            AcmeError::Transport("wasi:http set_path_with_query rejected value".into())
        })?;

    // Even for HEAD / GET we have to acquire the outgoing body and
    // `finish()` it — some hosts hang on `handle()` otherwise because
    // they buffer the request in full before dialling out.
    let outgoing_body = request
        .body()
        .map_err(|()| AcmeError::Transport("outgoing-request body already taken".into()))?;
    if let Some(b) = body {
        write_all(&outgoing_body, b.bytes)?;
    }
    OutgoingBody::finish(outgoing_body, None)
        .map_err(|e| AcmeError::Transport(format!("finish outgoing body: {e:?}")))?;

    dispatch_and_read(request)
}

fn write_all(outgoing_body: &OutgoingBody, mut data: &[u8]) -> Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    let stream = outgoing_body
        .write()
        .map_err(|()| AcmeError::Transport("outgoing body stream already taken".into()))?;
    let pollable = stream.subscribe();
    while !data.is_empty() {
        pollable.block();
        let permit = stream
            .check_write()
            .map_err(|e| AcmeError::Transport(format!("check_write: {e:?}")))?
            as usize;
        if permit == 0 {
            // Backpressure — loop and re-poll.
            continue;
        }
        let len = data.len().min(permit);
        let (chunk, rest) = data.split_at(len);
        stream
            .write(chunk)
            .map_err(|e| AcmeError::Transport(format!("write: {e:?}")))?;
        data = rest;
    }
    stream
        .flush()
        .map_err(|e| AcmeError::Transport(format!("flush: {e:?}")))?;
    // Block on the flush before dropping — some hosts lose tail bytes
    // if the output-stream handle drops mid-flight.
    pollable.block();
    drop(pollable);
    // Explicit drop clarifies the ordering: the write stream must be
    // gone before OutgoingBody::finish runs in the caller.
    drop(stream);
    Ok(())
}

fn dispatch_and_read(request: OutgoingRequest) -> Result<HttpResponse> {
    let future_response = outgoing_handler::handle(request, None)
        .map_err(|e| AcmeError::Transport(format!("outgoing_handler::handle: {e:?}")))?;

    let incoming = match future_response.get() {
        Some(r) => r,
        None => {
            let pollable = future_response.subscribe();
            pollable.block();
            future_response
                .get()
                .expect("future-incoming-response resolved after block")
        }
    }
    .map_err(|()| AcmeError::Transport("future-incoming-response already taken".into()))?
    .map_err(|e| AcmeError::Transport(format!("response error: {e:?}")))?;
    drop(future_response);

    read_response(incoming)
}

fn read_response(incoming: IncomingResponse) -> Result<HttpResponse> {
    let status = incoming.status();
    let headers_handle = incoming.headers();
    let raw_headers = headers_handle.entries();
    drop(headers_handle);

    // ACME cares about headers that legally repeat (`Link`,
    // `Replay-Nonce`) — the flat `Vec<(name, value)>` preserves order
    // and multiplicity. Values decode as UTF-8 with lossy fallback:
    // any non-UTF-8 header value from a well-behaved ACME CA is
    // already broken, and lossy conversion keeps us diagnosable
    // rather than dropping the response outright.
    let headers = raw_headers
        .into_iter()
        .map(|(name, value)| (name, String::from_utf8_lossy(&value).into_owned()))
        .collect::<Vec<(String, String)>>();

    let incoming_body = incoming
        .consume()
        .map_err(|()| AcmeError::Transport("incoming response body already consumed".into()))?;
    drop(incoming);

    let input_stream = incoming_body
        .stream()
        .map_err(|()| AcmeError::Transport("incoming body stream already taken".into()))?;
    let pollable = input_stream.subscribe();

    let mut body: Vec<u8> = Vec::new();
    loop {
        pollable.block();
        match input_stream.read(64 * 1024) {
            Ok(chunk) => {
                if !chunk.is_empty() {
                    body.extend_from_slice(&chunk);
                }
            }
            Err(StreamError::Closed) => break,
            Err(e) => {
                return Err(AcmeError::Transport(format!("body read: {e:?}")));
            }
        }
    }

    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

// ---------------------------------------------------------------------------
// URL splitting.
//
// ACME endpoints are always `http`/`https` with a fixed authority + path;
// we deliberately do not pull in the full `url` crate for this — the
// naive split matches what `oauth2-http-client` does and keeps the
// component slim.
// ---------------------------------------------------------------------------

fn parse_url(url: &str) -> Result<(Scheme, String, String)> {
    let (scheme, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (Scheme::Https, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (Scheme::Http, rest)
    } else {
        return Err(AcmeError::Transport(format!(
            "unsupported URL scheme: {url}"
        )));
    };
    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(AcmeError::Transport(format!("URL missing authority: {url}")));
    }
    Ok((scheme, authority.to_string(), path.to_string()))
}

// ---------------------------------------------------------------------------
// Host-side unit tests.
//
// A live wasi:http round trip needs a wasmtime harness and a real HTTP
// server on the other side, which is out of scope for this crate's
// unit tests — see `crates/testing` for the integration harness. Here
// we instead assert:
//
// * URL splitting mirrors the shape the round-trip helper feeds to
//   `wasi:http/types`, and
// * `WasiHttpClient` genuinely implements `acme_core::HttpClient` for
//   every verb, so a signature drift in the trait breaks the build.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use acme_core::transport::HttpClient;

    #[test]
    fn parse_url_https() {
        let (scheme, authority, path) =
            parse_url("https://acme-v02.api.letsencrypt.org/directory").unwrap();
        assert!(matches!(scheme, Scheme::Https));
        assert_eq!(authority, "acme-v02.api.letsencrypt.org");
        assert_eq!(path, "/directory");
    }

    #[test]
    fn parse_url_http_no_path() {
        let (scheme, authority, path) = parse_url("http://localhost:14000").unwrap();
        assert!(matches!(scheme, Scheme::Http));
        assert_eq!(authority, "localhost:14000");
        assert_eq!(path, "/");
    }

    #[test]
    fn parse_url_rejects_unknown_scheme() {
        assert!(parse_url("ftp://example.com").is_err());
    }

    #[test]
    fn parse_url_rejects_empty_authority() {
        assert!(parse_url("https:///directory").is_err());
    }

    /// `HttpClient` is object-safe by design; this ensures
    /// `WasiHttpClient` can be handed to any acme-core entry point
    /// that expects `Arc<dyn HttpClient>`. Compile-only.
    #[test]
    fn wasi_http_client_is_object_safe_http_client() {
        fn _boxable(_: Box<dyn HttpClient>) {}
        fn _arced(_: std::sync::Arc<dyn HttpClient>) {}
        let client = WasiHttpClient::new();
        _boxable(Box::new(client));
        _arced(std::sync::Arc::new(client));
    }

    /// Compile-only witness that the trait's three verbs are covered
    /// by our impl. Each method is invoked through a
    /// `WasiHttpClient` value in a never-run helper so the signatures
    /// have to line up at type-check time; the closure short-circuits
    /// out before any real `wasi:http` call is attempted at runtime.
    #[test]
    fn covers_every_http_client_method() {
        #[allow(dead_code, unreachable_code, unused_variables)]
        fn _touch_every_verb(c: &WasiHttpClient) {
            // The `return` keeps this test suite from actually driving
            // wasi:http on the host — we only need the compiler to
            // resolve each method against the trait impl.
            return;
            let _: Result<HttpResponse> = HttpClient::head(c, "https://example.com/nonce");
            let _: Result<HttpResponse> = HttpClient::get(c, "https://example.com/directory");
            let _: Result<HttpResponse> =
                HttpClient::post_jose(c, "https://example.com/orders", b"{}");
        }
    }
}
