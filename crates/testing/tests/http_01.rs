//! End-to-end HTTP-01 issuance against Pebble.
//!
//! Gated behind `#[ignore]` — a plain `cargo test` never runs this
//! (no Docker required). To run:
//!
//! ```text
//! cargo test -p acme-testing --test http_01 -- --ignored --nocapture
//! ```
//!
//! What the test does:
//!
//! 1. Spin up Pebble + pebble-challtestsrv via docker compose.
//! 2. Point `example.internal` at the host in challtestsrv's DNS so
//!    Pebble resolves the identifier to our test process.
//! 3. Bind our HTTP-01 responder on port 5002 (Pebble's default
//!    `httpPort`).
//! 4. Run the ACME order end-to-end using `acme_core::issue_certificate`.
//! 5. Verify the returned PEM chain parses and the leaf's SAN carries
//!    `example.internal`.

use std::sync::Arc;
use std::time::Duration;

use acme_core::csr::CertificateKey;
use acme_core::order::Identifier;
use acme_core::transport::ReqwestTransport;
use acme_testing::{Http01Server, PebbleHarness};
use acme_testing::http_server::Http01SolverAdapter;

mod common;
use common::{assert_leaf_has_san, fresh_account_key};

#[test]
#[ignore = "requires Docker; run with --ignored"]
fn http_01_e2e_issuance() {
    let identifier = "example.internal";

    let harness = PebbleHarness::spawn().expect("spawn Pebble");
    eprintln!("pebble directory: {}", harness.directory_url);
    eprintln!("pebble host_ip:   {}", harness.host_ip);

    // Steer example.internal at the host so Pebble reaches our
    // responder over the docker network.
    harness
        .add_a(identifier, &[&harness.host_ip])
        .expect("challtestsrv add_a");

    // Bind the HTTP-01 responder on port 5002 (Pebble's default httpPort).
    let http_server = Arc::new(Http01Server::bind_default().expect(
        "bind 0.0.0.0:5002 for HTTP-01 — free the port or run with sudo if it's in use",
    ));
    let solver = Box::new(Http01SolverAdapter::new(http_server.clone()));

    // reqwest client that trusts Pebble's minica.
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
        // Pebble validates in ~1s; keep the loop tight so a failure is
        // noisy rather than hanging out for the full default 120s.
        Duration::from_secs(30),
        Duration::from_secs(30),
    )
    .expect("issue_certificate");

    assert!(
        !pem.is_empty(),
        "issue_certificate returned an empty PEM chain"
    );
    assert_leaf_has_san(&pem, identifier);

    // Explicit teardown so the drop order is deterministic in test
    // output.
    harness.clear_a(identifier).ok();
    drop(http_server);
    drop(harness);
}
