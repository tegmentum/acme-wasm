//! Host-only integration-test helpers for `acme-wasm`.
//!
//! This crate is deliberately excluded from `workspace.default-members`
//! and marked `publish = false` — its dependencies (a Pebble docker
//! stack spawner, an in-process HTTP-01 responder, a TLS-ALPN-01
//! rustls acceptor, a challtestsrv-backed DnsProvider) are host-only
//! and would drag in `tokio` / `wasmtime` transitively for any
//! wasm32-wasip2 build.
//!
//! ## The Pebble harness
//!
//! [`PebbleHarness::spawn`] brings up
//! [Pebble](https://github.com/letsencrypt/pebble) — the Let's Encrypt
//! team's official ACME-CA-for-testing — plus
//! [pebble-challtestsrv](https://github.com/letsencrypt/pebble/tree/main/cmd/pebble-challtestsrv)
//! via `docker compose up -d`. The compose file is embedded (see
//! [`COMPOSE_YAML`]) and written to a tempdir on spawn; a `Drop`
//! implementation runs `docker compose down` to tear the stack back
//! down.
//!
//! Callers get:
//!
//! - [`PebbleHarness::directory_url`] — the ACME v2 directory URL
//!   (`https://localhost:14000/dir`).
//! - [`PebbleHarness::ca_pem`] — Pebble's self-signed CA cert, so a
//!   [`reqwest::blocking::Client`] can trust JWS POSTs.
//! - [`PebbleHarness::challtestsrv_dns_url`] — the challtestsrv HTTP
//!   admin API base (default `http://localhost:8055`), used by
//!   [`ChallTestSrvProvider`] to seed DNS-01 TXT records.
//! - [`PebbleHarness::host_ip`] — the IPv4 address Pebble containers
//!   use to reach the host (used to point A records at the test's own
//!   HTTP-01 / TLS-ALPN-01 responders).
//!
//! Assumes `docker` and `docker compose` are on `$PATH` and the daemon
//! is running. If not, `spawn()` returns an error and the caller — the
//! `#[ignore]`-gated integration tests — surfaces it as a test failure
//! with a clear message.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::TempDir;
use thiserror::Error;

pub mod http_server;
pub mod tls_server;
pub mod dns_provider;

pub use dns_provider::ChallTestSrvProvider;
pub use http_server::Http01Server;
pub use tls_server::TlsAlpn01Server;

/// Compose stack: Pebble + pebble-challtestsrv on a private bridge.
///
/// * Pebble listens on `0.0.0.0:14000` (ACME v2 directory) and
///   `0.0.0.0:15000` (management API), and uses challtestsrv as its
///   DNS resolver so unknown names can be steered at the host.
/// * challtestsrv exposes the HTTP admin API on `0.0.0.0:8055` and a
///   DNS server on `0.0.0.0:8053` (only used by Pebble inside the
///   docker network; tests never speak DNS directly).
/// * Both services get `host.docker.internal` mapped to the host
///   gateway via `extra_hosts` — Docker Desktop already ships this
///   mapping, and the explicit entry makes the Linux `host-gateway`
///   convention work too.
/// * `PEBBLE_VA_NOSLEEP=1` disables the deliberate anti-flake random
///   delays Pebble injects into validation. `PEBBLE_WFE_NONCEREJECT=0`
///   disables Pebble's random nonce-reject-to-catch-clients behaviour.
///
/// The compose project name is passed via `-p acme-testing-pebble` so
/// concurrent invocations don't collide with stale runs.
pub const COMPOSE_YAML: &str = r#"services:
  pebble:
    image: ghcr.io/letsencrypt/pebble:latest
    container_name: acme-testing-pebble
    command:
      - -config
      - test/config/pebble-config.json
      - -dnsserver
      - challtestsrv:8053
    environment:
      PEBBLE_VA_NOSLEEP: "1"
      PEBBLE_WFE_NONCEREJECT: "0"
    ports:
      - "14000:14000"
      - "15000:15000"
    depends_on:
      - challtestsrv
    extra_hosts:
      - "host.docker.internal:host-gateway"
    networks:
      - acmenet

  challtestsrv:
    image: ghcr.io/letsencrypt/pebble-challtestsrv:latest
    container_name: acme-testing-challtestsrv
    # `-dnsserver :8053` — the mock DNS server Pebble queries.
    # `-management :8055` — HTTP admin API the harness POSTs to.
    # Everything else (`-http01`, `-https01`, `-tlsalpn01`, `-doh`) is
    # disabled with an empty string so challtestsrv doesn't collide with
    # ports the test's own responders bind on the host.
    command:
      - -defaultIPv4
      - ""
      - -defaultIPv6
      - ""
      - -management
      - :8055
      - -dnsserver
      - :8053
      - -http01
      - ""
      - -https01
      - ""
      - -tlsalpn01
      - ""
      - -doh
      - ""
    ports:
      - "8055:8055"
    extra_hosts:
      - "host.docker.internal:host-gateway"
    networks:
      - acmenet

networks:
  acmenet:
    driver: bridge
"#;

/// Fixed compose project name — passed with `-p` so `docker compose
/// down` targets exactly the stack this harness brought up, and so a
/// forgotten container from a prior run is reused / reset predictably.
pub const COMPOSE_PROJECT: &str = "acme-testing-pebble";

/// Container name for the Pebble service — used by `docker cp` /
/// `docker exec` calls to pull the CA cert and resolve
/// `host.docker.internal` from inside the container.
pub const PEBBLE_CONTAINER: &str = "acme-testing-pebble";

/// Errors from harness spawn / teardown.
#[derive(Debug, Error)]
pub enum HarnessError {
    #[error("failed to spawn docker command `{cmd}`: {source}")]
    Spawn {
        cmd: String,
        source: std::io::Error,
    },
    #[error("docker command `{cmd}` exited {status}: {stderr}")]
    NonZeroExit {
        cmd: String,
        status: i32,
        stderr: String,
    },
    #[error("Pebble directory endpoint did not come up within {0:?}")]
    DirectoryTimeout(Duration),
    #[error("failed to write embedded compose yaml to tempdir: {0}")]
    WriteCompose(#[source] std::io::Error),
    #[error("failed to extract Pebble CA cert from container: {0}")]
    ExtractCa(String),
    #[error("could not resolve host.docker.internal from inside the pebble container")]
    NoHostIp,
    #[error("reqwest error: {0}")]
    Http(#[from] reqwest::Error),
}

/// A running Pebble + pebble-challtestsrv stack.
///
/// The stack is torn down in `Drop`. Callers should hold the harness
/// alive for the duration of the test — dropping mid-flow will kill
/// Pebble before the ACME order finalizes.
pub struct PebbleHarness {
    /// The ACME v2 directory URL — `https://localhost:14000/dir`.
    pub directory_url: String,
    /// The self-signed CA that signed Pebble's ACME endpoint TLS cert
    /// (`pebble.minica.pem`). PEM-encoded. Load into a reqwest client
    /// via [`reqwest_client_trusting`].
    pub ca_pem: Vec<u8>,
    /// The pebble-challtestsrv HTTP admin API base URL —
    /// `http://localhost:8055`. Used by [`ChallTestSrvProvider`] for
    /// DNS-01 TXT provisioning and by tests that need to seed A
    /// records (see [`Self::add_a`]).
    pub challtestsrv_dns_url: String,
    /// The IPv4 address Pebble containers use to reach the host —
    /// pulled from the container's `/etc/hosts` entry for
    /// `host.docker.internal`. Point A records at this so Pebble's
    /// validator connects back to the test's own responders.
    pub host_ip: String,
    /// Owns the compose file until the harness drops.
    _tempdir: TempDir,
    /// Path to the compose file inside the tempdir — used by the
    /// `Drop` teardown call.
    compose_path: PathBuf,
}

impl PebbleHarness {
    /// Bring the stack up and wait for the ACME directory endpoint to
    /// respond. Tears down any leftover stack from a previous run
    /// under the same project name before starting.
    pub fn spawn() -> Result<Self, HarnessError> {
        let tempdir = TempDir::new().map_err(HarnessError::WriteCompose)?;
        let compose_path = tempdir.path().join("docker-compose.yml");
        std::fs::write(&compose_path, COMPOSE_YAML).map_err(HarnessError::WriteCompose)?;

        // Best-effort: kill any leftover stack from a previous run so
        // ports 14000 / 15000 / 8055 are free.
        let _ = run_compose(&compose_path, &["down", "--remove-orphans", "--timeout", "3"]);

        // Bring the stack up.
        run_compose(&compose_path, &["up", "-d", "--wait"])
            .or_else(|_| run_compose(&compose_path, &["up", "-d"]))?;

        // Extract the CA cert. `docker cp` streams it to stdout; the
        // path is stable across pebble releases (baked into the
        // official image).
        let ca_pem = docker_cp_from_container(PEBBLE_CONTAINER, "/test/certs/pebble.minica.pem")?;
        if ca_pem.is_empty() {
            return Err(HarnessError::ExtractCa(
                "pebble.minica.pem was empty".into(),
            ));
        }

        // Read /etc/hosts inside the container to learn the IP
        // host.docker.internal resolves to — that's the address
        // Pebble's validator will dial the host on.
        let host_ip = read_host_docker_internal_ip()?;

        let harness = Self {
            directory_url: "https://localhost:14000/dir".into(),
            ca_pem,
            challtestsrv_dns_url: "http://localhost:8055".into(),
            host_ip,
            _tempdir: tempdir,
            compose_path,
        };

        // Poll the directory endpoint. Pebble usually comes up in
        // 2-3s; give it a comfortable ceiling.
        wait_for_directory(&harness.directory_url, &harness.ca_pem, Duration::from_secs(60))?;

        Ok(harness)
    }

    /// Build a `reqwest::blocking::Client` that trusts Pebble's CA.
    /// Wrap it in `acme_core::transport::ReqwestTransport` to hand to
    /// the ACME issuance flow.
    pub fn reqwest_client(&self) -> Result<reqwest::blocking::Client, HarnessError> {
        reqwest_client_trusting(&self.ca_pem)
    }

    // ------------------------------------------------------------------
    // pebble-challtestsrv admin API (documented at
    // https://github.com/letsencrypt/pebble/tree/main/cmd/pebble-challtestsrv#mock-dns).
    // Every endpoint takes a JSON body and returns 200 on success; on
    // failure they return the error as text.
    // ------------------------------------------------------------------

    /// Set the default IPv4 answer for A queries with no explicit
    /// record. Useful when many identifiers should point at the same
    /// host.
    pub fn set_default_ipv4(&self, ip: &str) -> Result<(), HarnessError> {
        self.post_admin(
            "/set-default-ipv4",
            &serde_json::json!({ "ip": ip }),
        )
    }

    /// Publish an explicit A record. Overrides the default IPv4 answer
    /// for exactly this host. FQDN with trailing dot per DNS.
    pub fn add_a(&self, host: &str, addresses: &[&str]) -> Result<(), HarnessError> {
        self.post_admin(
            "/add-a",
            &serde_json::json!({
                "host": fqdn(host),
                "addresses": addresses,
            }),
        )
    }

    /// Remove the A record set by [`Self::add_a`]. Idempotent.
    pub fn clear_a(&self, host: &str) -> Result<(), HarnessError> {
        self.post_admin(
            "/clear-a",
            &serde_json::json!({ "host": fqdn(host) }),
        )
    }

    /// Publish a TXT record — the DNS-01 provisioning primitive.
    ///
    /// `host` should already carry the `_acme-challenge.` prefix; use
    /// [`acme_challenge_dns_01::record_name`] to derive it.
    pub fn set_txt(&self, host: &str, value: &str) -> Result<(), HarnessError> {
        self.post_admin(
            "/set-txt",
            &serde_json::json!({
                "host": fqdn(host),
                "value": value,
            }),
        )
    }

    /// Remove the TXT record set by [`Self::set_txt`]. Idempotent.
    pub fn clear_txt(&self, host: &str) -> Result<(), HarnessError> {
        self.post_admin(
            "/clear-txt",
            &serde_json::json!({ "host": fqdn(host) }),
        )
    }

    fn post_admin(&self, path: &str, body: &serde_json::Value) -> Result<(), HarnessError> {
        let url = format!("{}{}", self.challtestsrv_dns_url, path);
        let resp = reqwest::blocking::Client::new()
            .post(&url)
            .json(body)
            .send()?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16() as i32;
            let stderr = resp.text().unwrap_or_default();
            return Err(HarnessError::NonZeroExit {
                cmd: format!("POST {url}"),
                status,
                stderr,
            });
        }
        Ok(())
    }
}

impl Drop for PebbleHarness {
    fn drop(&mut self) {
        // Best-effort teardown. Errors from a failing docker compose
        // down are visible in the test output via `eprintln!` but we
        // never panic in Drop.
        if let Err(e) = run_compose(&self.compose_path, &["down", "--timeout", "5"]) {
            eprintln!("PebbleHarness::drop: docker compose down failed: {e}");
        }
    }
}

// --------------------------------------------------------------------
// Helpers.
// --------------------------------------------------------------------

/// Ensure a hostname ends in `.` — the DNS-server admin API requires
/// FQDNs. Idempotent.
fn fqdn(host: &str) -> String {
    if host.ends_with('.') {
        host.to_string()
    } else {
        format!("{host}.")
    }
}

/// Build a blocking reqwest client that trusts a caller-provided PEM
/// bundle IN ADDITION to the platform's system roots. Test-only —
/// production `acme-core::transport::ReqwestTransport::new()` uses
/// only the system roots.
pub fn reqwest_client_trusting(pem: &[u8]) -> Result<reqwest::blocking::Client, HarnessError> {
    let mut builder = reqwest::blocking::Client::builder()
        .user_agent(concat!("acme-testing/", env!("CARGO_PKG_VERSION")));
    // Split into individual PEM blocks so reqwest sees each root cert
    // separately (some minica bundles carry multiple).
    for cert_pem in split_pem_certs(pem) {
        let cert = reqwest::Certificate::from_pem(&cert_pem)?;
        builder = builder.add_root_certificate(cert);
    }
    Ok(builder.build()?)
}

fn split_pem_certs(pem: &[u8]) -> Vec<Vec<u8>> {
    const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
    const END: &[u8] = b"-----END CERTIFICATE-----";
    let mut out = Vec::new();
    let mut cursor = 0;
    while let Some(begin) = pem[cursor..].windows(BEGIN.len()).position(|w| w == BEGIN) {
        let begin = begin + cursor;
        let Some(end) = pem[begin..].windows(END.len()).position(|w| w == END) else {
            break;
        };
        let end = begin + end + END.len();
        let mut block = pem[begin..end].to_vec();
        block.push(b'\n');
        out.push(block);
        cursor = end;
    }
    if out.is_empty() {
        vec![pem.to_vec()]
    } else {
        out
    }
}

/// `docker compose -p <project> -f <file> <args...>`, with a fallback
/// to the standalone `docker-compose` binary — some Docker installs
/// ship an old `docker compose` plugin whose HTTP client speaks an
/// older API version than the daemon accepts, and the standalone
/// binary is often newer.
fn run_compose(compose_path: &std::path::Path, args: &[&str]) -> Result<Vec<u8>, HarnessError> {
    match run_compose_binary("docker", &["compose"], compose_path, args) {
        Ok(out) => Ok(out),
        Err(HarnessError::NonZeroExit { stderr, .. })
            if stderr.contains("API version") || stderr.contains("too old") =>
        {
            // Retry with the standalone docker-compose binary.
            run_compose_binary("docker-compose", &[], compose_path, args)
        }
        Err(HarnessError::Spawn { .. }) => {
            // docker CLI itself is missing — try the standalone binary as a last resort.
            run_compose_binary("docker-compose", &[], compose_path, args)
        }
        Err(e) => Err(e),
    }
}

fn run_compose_binary(
    program: &str,
    prefix: &[&str],
    compose_path: &std::path::Path,
    args: &[&str],
) -> Result<Vec<u8>, HarnessError> {
    let mut cmd = Command::new(program);
    for p in prefix {
        cmd.arg(p);
    }
    cmd.arg("-p")
        .arg(COMPOSE_PROJECT)
        .arg("-f")
        .arg(compose_path)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let display = format!("{program} {} {}", prefix.join(" "), args.join(" "));
    let output = cmd.output().map_err(|source| HarnessError::Spawn {
        cmd: display.clone(),
        source,
    })?;

    if !output.status.success() {
        return Err(HarnessError::NonZeroExit {
            cmd: display,
            status: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(output.stdout)
}

/// `docker cp <container>:<path> -` streams the file to stdout as a
/// tar archive. We extract the single-file entry inline (POSIX ustar,
/// 512-byte header, filename in first 100 bytes, size at offset 124 as
/// octal ASCII).
fn docker_cp_from_container(container: &str, path: &str) -> Result<Vec<u8>, HarnessError> {
    let mut cmd = Command::new("docker");
    cmd.arg("cp")
        .arg(format!("{container}:{path}"))
        .arg("-")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = cmd.output().map_err(|source| HarnessError::Spawn {
        cmd: format!("docker cp {container}:{path} -"),
        source,
    })?;
    if !output.status.success() {
        return Err(HarnessError::NonZeroExit {
            cmd: format!("docker cp {container}:{path} -"),
            status: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    extract_first_tar_file(&output.stdout)
        .ok_or_else(|| HarnessError::ExtractCa("failed to parse tar stream".into()))
}

/// Minimal ustar parser — pulls out the first regular file's contents.
/// Sufficient for `docker cp <container>:<file> -`, which always emits
/// exactly one entry.
fn extract_first_tar_file(tar: &[u8]) -> Option<Vec<u8>> {
    // Header is 512 bytes. Size in octal at [124..136), NUL-terminated
    // or space-terminated.
    if tar.len() < 512 {
        return None;
    }
    let size_bytes = &tar[124..136];
    let size_str = std::str::from_utf8(size_bytes)
        .ok()?
        .trim_end_matches(|c: char| c == '\0' || c.is_whitespace());
    let size = usize::from_str_radix(size_str.trim(), 8).ok()?;
    if tar.len() < 512 + size {
        return None;
    }
    Some(tar[512..512 + size].to_vec())
}

/// `docker cp <pebble>:/etc/hosts -` — the `extra_hosts` mapping puts
/// `host.docker.internal` in the container's `/etc/hosts`, so we can
/// read the IP the host resolves to from inside the network without
/// needing a shell or `cat` inside the image (the Pebble image is a
/// scratch image with only the `pebble` binary).
fn read_host_docker_internal_ip() -> Result<String, HarnessError> {
    let hosts = docker_cp_from_container(PEBBLE_CONTAINER, "/etc/hosts")?;
    let text = String::from_utf8_lossy(&hosts);
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let ip = it.next().unwrap_or("");
        for name in it {
            if name == "host.docker.internal" {
                return Ok(ip.to_string());
            }
        }
    }
    Err(HarnessError::NoHostIp)
}

/// Poll the directory URL until it returns 200 or the deadline
/// elapses.
fn wait_for_directory(
    url: &str,
    ca_pem: &[u8],
    timeout: Duration,
) -> Result<(), HarnessError> {
    let client = reqwest_client_trusting(ca_pem)?;
    let deadline = Instant::now() + timeout;
    let mut last_err: Option<String> = None;
    while Instant::now() < deadline {
        match client
            .get(url)
            .timeout(Duration::from_secs(2))
            .send()
        {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            Ok(resp) => {
                last_err = Some(format!("HTTP {}", resp.status()));
            }
            Err(e) => {
                last_err = Some(e.to_string());
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    eprintln!(
        "pebble directory never came up (last error: {})",
        last_err.unwrap_or_else(|| "n/a".into())
    );
    Err(HarnessError::DirectoryTimeout(timeout))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fqdn_adds_trailing_dot_once() {
        assert_eq!(fqdn("example.com"), "example.com.");
        assert_eq!(fqdn("example.com."), "example.com.");
    }

    #[test]
    fn compose_yaml_names_both_services() {
        assert!(COMPOSE_YAML.contains("pebble:"));
        assert!(COMPOSE_YAML.contains("challtestsrv:"));
        assert!(COMPOSE_YAML.contains("ghcr.io/letsencrypt/pebble:latest"));
    }

    #[test]
    fn split_pem_certs_finds_multi_block_bundle() {
        let bundle = b"-----BEGIN CERTIFICATE-----\naaa\n-----END CERTIFICATE-----\n\
                       -----BEGIN CERTIFICATE-----\nbbb\n-----END CERTIFICATE-----\n";
        let blocks = split_pem_certs(bundle);
        assert_eq!(blocks.len(), 2);
        assert!(blocks[0].windows(3).any(|w| w == b"aaa"));
        assert!(blocks[1].windows(3).any(|w| w == b"bbb"));
    }

    #[test]
    fn extract_first_tar_file_reads_ustar_size_field() {
        // Hand-craft a minimal ustar with a 5-byte payload "hello".
        let mut header = vec![0u8; 512];
        // filename
        header[..5].copy_from_slice(b"hello");
        // size at 124..136, octal ASCII, NUL-padded. "5" = 0o5 = 5 bytes.
        let size_field = b"00000000005\0";
        header[124..124 + size_field.len()].copy_from_slice(size_field);
        let mut tar = header;
        tar.extend_from_slice(b"hello");
        // Pad to 512-byte boundary for realism (not required by parser).
        tar.resize(1024, 0);
        assert_eq!(extract_first_tar_file(&tar), Some(b"hello".to_vec()));
    }
}
