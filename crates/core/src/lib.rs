//! acme-core — plain-Rust RFC 8555 ACME v2 primitives.
//!
//! This crate holds the domain types and pure logic for the ACME
//! protocol (RFC 8555), the TLS-ALPN-01 challenge (RFC 8737), and the
//! HTTP-01 / DNS-01 challenges from RFC 8555 §8.3 / §8.4. It does not
//! depend on wit-bindgen, wasi, or the Component Model — the wit-typed
//! wrapper `acme-protocol` layers on top and is a thin translation
//! between wit-bindgen structs and the plain types defined here.
//!
//! Module layout follows RFC 8555 section numbering so the mapping
//! between spec text and code is one-to-one:
//!
//! - [`directory`] — §7.1.1 directory object.
//! - [`nonce`] — §6.5 replay-nonce handling.
//! - [`account`] — §7.3 account lifecycle.
//! - [`order`] — §7.4 order lifecycle.
//! - [`authorization`] — §7.5 authorization polling.
//! - [`challenge`] — §7.5.1 challenge state machine and the §8.1
//!   key-authorization helper.
//! - [`certificate`] — §7.4 finalize + §7.4.2 certificate download.
//! - [`jws`] — RFC 7515 flattened JWS-with-nonce assembly (RS256 /
//!   ES256 / ES384 / EdDSA), plus RFC 7638 JWK thumbprint.
//! - [`csr`] — PKCS#10 CSR generation for the finalize step.
//! - [`transport`] — the `HttpClient` seam every request rides on.
//! - [`error`] — RFC 8555 §6.7 problem-document errors plus JOSE and
//!   transport failures.
//!
//! JWS-with-nonce signing (RFC 8555 §6.2, RFC 7515) is implemented
//! directly on top of the `rsa` / `p256` / `p384` / `ed25519-dalek`
//! crates. `oauth2-core` currently exposes only *verification*
//! primitives; when it grows a signing seam upstream the JWS module
//! will migrate to it (the boundary is designed to make the swap
//! mechanical).

pub mod account;
pub mod authorization;
pub mod certificate;
pub mod challenge;
pub mod csr;
pub mod directory;
pub mod error;
pub mod jws;
pub mod nonce;
pub mod order;
pub mod transport;

pub use error::{AcmeError, Result};

use crate::account::Account;
use crate::challenge::{ChallengeReady, ChallengeSolver};
use crate::csr::CertificateKey;
use crate::jws::AccountKey;
use crate::order::Identifier;
use crate::transport::HttpClient;
use std::sync::Arc;
use std::time::Duration;

/// Wall-clock ceiling on a single challenge's arm-and-poll loop. The
/// full [`issue_certificate`] budget is roughly `challenges * this
/// value` plus finalize; adjust with the `-with-timeouts` variant when
/// the defaults do not fit a caller's scenario.
pub const DEFAULT_CHALLENGE_TIMEOUT: Duration = Duration::from_secs(120);

/// End-to-end ACME issuance.
///
/// Runs the full RFC 8555 order flow:
///
/// 1. Fetch the directory.
/// 2. `newAccount` (creates or reuses the account for `account_key`).
/// 3. `newOrder` for `identifiers`.
/// 4. For each authorization: pick a [`ChallengeSolver`] whose `kind`
///    matches one of the challenges, arm it, and drive
///    [`challenge::poll_challenge`] to `valid`.
/// 5. Build a CSR with `cert_key`, POST to finalize, poll the order.
/// 6. POST-as-GET the certificate URL and return the PEM chain.
///
/// The returned bytes are the CA's `application/pem-certificate-chain`
/// body — leaf first, then intermediates. Use
/// [`certificate::split_pem_chain`] to split it into individual blocks.
pub fn issue_certificate(
    directory_url: &str,
    contact: &[String],
    identifiers: &[Identifier],
    solvers: Vec<Box<dyn ChallengeSolver>>,
    cert_key: &CertificateKey,
    account_key: AccountKey,
    transport: Arc<dyn HttpClient>,
) -> Result<Vec<u8>> {
    issue_certificate_with_timeouts(
        directory_url,
        contact,
        identifiers,
        solvers,
        cert_key,
        account_key,
        transport,
        DEFAULT_CHALLENGE_TIMEOUT,
        certificate::DEFAULT_FINALIZE_TIMEOUT,
    )
}

/// [`issue_certificate`] with the challenge-poll and finalize-poll
/// budgets exposed. Used by both the default entry point above and by
/// integration tests that need to keep the loops tight.
#[allow(clippy::too_many_arguments)]
pub fn issue_certificate_with_timeouts(
    directory_url: &str,
    contact: &[String],
    identifiers: &[Identifier],
    solvers: Vec<Box<dyn ChallengeSolver>>,
    cert_key: &CertificateKey,
    account_key: AccountKey,
    transport: Arc<dyn HttpClient>,
    challenge_timeout: Duration,
    finalize_timeout: Duration,
) -> Result<Vec<u8>> {
    let directory = directory::fetch(directory_url, transport.as_ref())?;
    let account = account::create(
        directory,
        contact,
        /* terms_agreed */ true,
        account_key,
        transport.clone(),
    )?;
    let order = order::create(&account, identifiers, transport.as_ref())?;

    for authz_url in &order.authorizations {
        run_one_authorization(
            authz_url,
            &account,
            transport.as_ref(),
            solvers.as_slice(),
            challenge_timeout,
        )?;
    }

    let final_order = certificate::finalize_with_deadline(
        &order,
        cert_key,
        &account,
        transport.as_ref(),
        finalize_timeout,
    )?;
    let cert_url = final_order.certificate.ok_or_else(|| {
        AcmeError::MissingField("certificate URL on valid order".into())
    })?;
    certificate::download(&cert_url, &account, transport.as_ref())
}

/// Handle one authorization: fetch it, pick a matching solver, arm the
/// challenge, and poll it to `valid`.
///
/// Kept private to the orchestrator so the public API stays a single
/// entry point. Callers that want per-authorization control should
/// build the flow out of the module-level helpers directly.
fn run_one_authorization(
    authz_url: &str,
    account: &Account,
    transport: &dyn HttpClient,
    solvers: &[Box<dyn ChallengeSolver>],
    timeout: Duration,
) -> Result<()> {
    let authz = authorization::fetch(authz_url, account, transport)?;
    if authz.status_enum() == authorization::AuthorizationStatus::Valid {
        // Already satisfied — skip. Reused authorizations do this.
        return Ok(());
    }

    let (solver, challenge) = pick_solver_and_challenge(&authz, solvers)?;
    let token = challenge
        .token
        .as_deref()
        .ok_or_else(|| AcmeError::MissingField("challenge.token".into()))?;
    let key_authorization = challenge::compute_key_authorization(token, &account.key);
    let ready: Box<dyn ChallengeReady> = solver.arm(&authz.identifier, &key_authorization)?;
    challenge::poll_challenge(&challenge.url, account, transport, ready, timeout)
}

fn pick_solver_and_challenge<'a>(
    authz: &'a authorization::Authorization,
    solvers: &'a [Box<dyn ChallengeSolver>],
) -> Result<(&'a dyn ChallengeSolver, &'a challenge::Challenge)> {
    for solver in solvers {
        let want = solver.kind();
        if let Some(ch) = authz.challenges.iter().find(|c| c.kind() == want) {
            return Ok((solver.as_ref(), ch));
        }
    }
    Err(AcmeError::UnsupportedIdentifier(format!(
        "no solver for identifier {}: challenges offered {:?}",
        authz.identifier.value,
        authz.challenges.iter().map(|c| &c.type_).collect::<Vec<_>>()
    )))
}
