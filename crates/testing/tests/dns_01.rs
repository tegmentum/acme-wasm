//! End-to-end DNS-01 issuance against Pebble.
//!
//! Gated behind `#[ignore]`. To run:
//!
//! ```text
//! cargo test -p acme-testing --test dns_01 -- --ignored --nocapture
//! ```
//!
//! Uses a small `ChallTestSrvProvider` that calls pebble-challtestsrv's
//! `/set-txt` / `/clear-txt` HTTP admin endpoints. Pebble's DNS lookups
//! for `_acme-challenge.dns.example.internal` are served straight out
//! of the mock server's in-memory record map — no propagation delay.

use std::sync::Arc;
use std::time::Duration;

use acme_core::csr::CertificateKey;
use acme_core::order::Identifier;
use acme_core::transport::ReqwestTransport;
use acme_testing::dns_provider::DnsSolverAdapter;
use acme_testing::{ChallTestSrvProvider, PebbleHarness};

mod common;
use common::{assert_leaf_has_san, fresh_account_key};

#[test]
#[ignore = "requires Docker; run with --ignored"]
fn dns_01_e2e_issuance() {
    let identifier = "dns.example.internal";

    let harness = PebbleHarness::spawn().expect("spawn Pebble");
    eprintln!("pebble directory: {}", harness.directory_url);
    eprintln!("challtestsrv:     {}", harness.challtestsrv_dns_url);

    // For DNS-01 the CA does not connect back to us at all — it only
    // resolves the TXT record. Still, the mock DNS server must return
    // *something* for A queries on the identifier or Pebble's HTTP
    // fallback would trip; give it a bogus IP.
    harness.add_a(identifier, &["127.0.0.1"]).ok();

    let provider = Arc::new(ChallTestSrvProvider::new(&harness.challtestsrv_dns_url));
    let solver = Box::new(DnsSolverAdapter::new(provider));

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
    drop(harness);
}
