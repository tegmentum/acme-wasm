//! End-to-end TLS-ALPN-01 issuance against Pebble.
//!
//! Gated behind `#[ignore]`. To run:
//!
//! ```text
//! cargo test -p acme-testing --test tls_alpn_01 -- --ignored --nocapture
//! ```
//!
//! Uses a rustls acceptor bound on port 5001 (Pebble's default
//! `tlsPort`) with a `SwappableResolver` that dispatches on ALPN — the
//! resolver only answers when the peer negotiates `acme-tls/1`, so a
//! plain-HTTPS probe would be rejected during the handshake.

use std::sync::Arc;
use std::time::Duration;

use acme_core::csr::CertificateKey;
use acme_core::order::Identifier;
use acme_core::transport::ReqwestTransport;
use acme_testing::{PebbleHarness, TlsAlpn01Server};
use acme_testing::tls_server::TlsAlpn01SolverAdapter;

mod common;
use common::{assert_leaf_has_san, fresh_account_key};

#[test]
#[ignore = "requires Docker; run with --ignored"]
fn tls_alpn_01_e2e_issuance() {
    // Install the ring crypto provider once — rustls 0.23 requires it.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let identifier = "alpn.example.internal";

    let harness = PebbleHarness::spawn().expect("spawn Pebble");
    eprintln!("pebble directory: {}", harness.directory_url);
    eprintln!("pebble host_ip:   {}", harness.host_ip);

    harness
        .add_a(identifier, &[&harness.host_ip])
        .expect("challtestsrv add_a");

    // Bind the TLS-ALPN-01 responder on Pebble's default tlsPort.
    let tls_server = Arc::new(TlsAlpn01Server::bind_default().expect(
        "bind 0.0.0.0:5001 for TLS-ALPN-01 — free the port or run with sudo if it's in use",
    ));
    let solver = Box::new(TlsAlpn01SolverAdapter::new(tls_server.clone()));

    let http = harness.reqwest_client().expect("build trusting client");
    let transport = Arc::new(ReqwestTransport::with_client(http));

    let account_key = fresh_account_key();
    let cert_key = CertificateKey::generate_p256().expect("cert key");

    let pem = acme_core::issue_certificate_with_timeouts(
        &harness.directory_url,
        &["mailto:tester@example.internal".into()],
        &[Identifier::dns(identifier.to_string())],
        vec![solver],
        &cert_key,
        account_key,
        transport,
        Duration::from_secs(30),
        Duration::from_secs(30),
    )
    .expect("issue_certificate");

    assert!(
        !pem.is_empty(),
        "issue_certificate returned an empty PEM chain"
    );
    assert_leaf_has_san(&pem, identifier);

    harness.clear_a(identifier).ok();
    drop(tls_server);
    drop(harness);
}
