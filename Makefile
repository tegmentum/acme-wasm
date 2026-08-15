# Repository build / test helpers.
#
# Host-only integration tests under `crates/testing/` spin up Pebble
# and pebble-challtestsrv via `docker compose` — they are gated behind
# `#[ignore]` so plain `cargo test` doesn't drag in Docker. The
# `test-e2e` target below runs them explicitly.

.PHONY: build test test-unit test-e2e test-e2e-http-01 test-e2e-tls-alpn-01 test-e2e-dns-01 clean-pebble

# Default: whatever the workspace's default-members compile — this is
# what CI runs on every push.
build:
	cargo build --workspace

# Host-only unit tests. Does NOT require Docker.
test test-unit:
	cargo test --workspace --lib

# Pebble-backed end-to-end integration tests. Requires Docker + docker
# compose. Runs each `--test` in its own binary so ports 5001 / 5002 /
# 14000 / 15000 / 8055 are exclusively bound one at a time.
test-e2e: test-e2e-http-01 test-e2e-tls-alpn-01 test-e2e-dns-01

test-e2e-http-01:
	cargo test -p acme-testing --test http_01 -- --ignored --nocapture

test-e2e-tls-alpn-01:
	cargo test -p acme-testing --test tls_alpn_01 -- --ignored --nocapture

test-e2e-dns-01:
	cargo test -p acme-testing --test dns_01 -- --ignored --nocapture

# Best-effort cleanup for a leftover Pebble stack — useful when a
# previous e2e run panicked before its Drop guard ran.
clean-pebble:
	-docker compose -p acme-testing-pebble down --remove-orphans --timeout 3 2>/dev/null
	-docker-compose -p acme-testing-pebble down --remove-orphans --timeout 3 2>/dev/null
