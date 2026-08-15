//! RFC 8555 §7.4 finalize + §7.4.2 certificate download.
//!
//! Once every authorization in the order is `valid`, the client:
//!
//! 1. Builds a PKCS#10 CSR covering the order's identifiers.
//! 2. POSTs the CSR to `order.finalize` in a JWS whose payload is
//!    `{ "csr": base64url(der) }` (RFC 8555 §7.4).
//! 3. Polls the order URL until `status = valid` and the
//!    `certificate` field is populated.
//! 4. POST-as-GETs the certificate URL to fetch the PEM chain.

use crate::account::Account;
use crate::csr::{build_csr, CertificateKey};
use crate::error::{AcmeError, Result};
use crate::order::{Order, OrderStatus};
use crate::transport::HttpClient;
use base64::Engine;
use serde_json::json;
use std::time::{Duration, Instant};

/// Wall-clock ceiling on the finalize-poll loop. Callers that want a
/// different budget should use [`finalize_with_deadline`].
pub const DEFAULT_FINALIZE_TIMEOUT: Duration = Duration::from_secs(120);

/// POST the CSR to the order's finalize URL, then poll the order URL
/// until it reaches `valid` (or `invalid`, or the deadline elapses).
/// Returns the finalized order — with `certificate` populated on
/// success — ready to hand to [`download`].
pub fn finalize(
    order: &Order,
    private_key: &CertificateKey,
    account: &Account,
    transport: &dyn HttpClient,
) -> Result<Order> {
    finalize_with_deadline(
        order,
        private_key,
        account,
        transport,
        DEFAULT_FINALIZE_TIMEOUT,
    )
}

/// Same as [`finalize`] with an explicit timeout — the finalize-poll
/// loop bails with [`AcmeError::Timeout`] once the deadline passes.
pub fn finalize_with_deadline(
    order: &Order,
    private_key: &CertificateKey,
    account: &Account,
    transport: &dyn HttpClient,
    timeout: Duration,
) -> Result<Order> {
    finalize_with_intervals(
        order,
        private_key,
        account,
        transport,
        timeout,
        Duration::from_secs(2),
    )
}

/// Full-control variant used by tests to keep the poll loop tight.
pub fn finalize_with_intervals(
    order: &Order,
    private_key: &CertificateKey,
    account: &Account,
    transport: &dyn HttpClient,
    timeout: Duration,
    poll_interval: Duration,
) -> Result<Order> {
    if order.url.is_empty() {
        return Err(AcmeError::MissingField(
            "order.url populated by order::create / refresh".into(),
        ));
    }

    let csr_der = build_csr(private_key, &order.identifiers)?;
    let payload = json!({
        "csr": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&csr_der),
    });
    let payload_bytes = serde_json::to_vec(&payload)?;
    let _ = account
        .post_kid(&order.finalize, &payload_bytes, transport)?
        .ok()?;

    // Poll the order URL until it settles.
    let deadline = Instant::now() + timeout;
    loop {
        let refreshed = crate::order::refresh(account, &order.url, transport)?;
        match refreshed.status_enum() {
            OrderStatus::Valid => {
                if refreshed.certificate.is_none() {
                    return Err(AcmeError::MissingField(
                        "order.certificate on valid order".into(),
                    ));
                }
                return Ok(refreshed);
            }
            OrderStatus::Invalid => {
                let detail = refreshed
                    .error
                    .and_then(|e| serde_json::to_string(&e).ok())
                    .unwrap_or_else(|| "order invalid".to_string());
                return Err(AcmeError::Malformed(detail));
            }
            _ => {}
        }
        if Instant::now() >= deadline {
            return Err(AcmeError::Timeout(format!(
                "order {} still {} after {:?}",
                order.url, refreshed.status, timeout
            )));
        }
        std::thread::sleep(poll_interval);
    }
}

/// POST-as-GET the certificate URL. The response body is a PEM
/// certificate chain (`application/pem-certificate-chain`) — leaf
/// first, then each intermediate up to (but not including) the root.
pub fn download(cert_url: &str, account: &Account, transport: &dyn HttpClient) -> Result<Vec<u8>> {
    let response = account.post_kid(cert_url, &[], transport)?.ok()?;
    Ok(response.body)
}

/// Split a PEM chain into individual `-----BEGIN CERTIFICATE-----`
/// blocks — useful for callers that want to hand the leaf to a TLS
/// stack and the intermediates to a truststore.
pub fn split_pem_chain(pem: &[u8]) -> Vec<Vec<u8>> {
    const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
    const END: &[u8] = b"-----END CERTIFICATE-----";
    let text = match std::str::from_utf8(pem) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let mut out = Vec::new();
    let mut cursor = 0usize;
    let text_bytes = text.as_bytes();
    while let Some(begin_off) = find(text_bytes, BEGIN, cursor) {
        let end_off = match find(text_bytes, END, begin_off) {
            Some(o) => o + END.len(),
            None => break,
        };
        // Include a trailing newline so downstream parsers that expect
        // one (rustls-pemfile) do not choke.
        let mut block = text_bytes[begin_off..end_off].to_vec();
        block.push(b'\n');
        out.push(block);
        cursor = end_off;
    }
    out
}

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from >= haystack.len() || needle.is_empty() || needle.len() > haystack.len() - from {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|off| off + from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_pem_chain_returns_each_block() {
        let pem = b"-----BEGIN CERTIFICATE-----\naaa\n-----END CERTIFICATE-----\n\
                    -----BEGIN CERTIFICATE-----\nbbb\n-----END CERTIFICATE-----\n";
        let blocks = split_pem_chain(pem);
        assert_eq!(blocks.len(), 2);
        assert!(blocks[0].starts_with(b"-----BEGIN CERTIFICATE-----"));
        assert!(blocks[0].ends_with(b"-----END CERTIFICATE-----\n"));
        assert!(blocks[1].windows(3).any(|w| w == b"bbb"));
    }

    #[test]
    fn split_pem_chain_handles_no_blocks() {
        assert!(split_pem_chain(b"").is_empty());
        assert!(split_pem_chain(b"not a chain").is_empty());
    }
}
