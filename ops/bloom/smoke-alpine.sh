#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ALPINE_IMAGE='alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b'
ALPINE_PLATFORM=linux/amd64
BLOOM_BIN=${1:-"${SCRIPT_DIR}/artifacts/v0.1.3-x86_64-musl/bloom"}

[ -f "$BLOOM_BIN" ] || {
  printf 'error: Bloom artifact is missing: %s\n' "$BLOOM_BIN" >&2
  exit 1
}
BLOOM_BIN=$(CDPATH= cd -- "$(dirname -- "$BLOOM_BIN")" && pwd)/$(basename -- "$BLOOM_BIN")

# Network is deliberately disabled: version, watch-wallet initialization, and
# local VFS reads must work in the clean Alpine base without package installs.
docker run --rm \
  --platform "$ALPINE_PLATFORM" \
  --network none \
  --volume "${BLOOM_BIN}:/usr/local/bin/bloom:ro" \
  --volume "${SCRIPT_DIR}/guest-bootstrap.sh:/usr/local/sbin/bloom-guest-bootstrap:ro" \
  "$ALPINE_IMAGE" \
  sh -ec '
    bloom --version
    ldd /usr/local/bin/bloom 2>&1 || true
    mkdir -p /workspace /bloom
    bloom-guest-bootstrap init 0x1111111111111111111111111111111111111111
    wallet_list=$(BLOOM_HOME=/workspace/.bloom bloom --quiet wallet list)
    printf "%s\n" "$wallet_list" | grep -q "[[:space:]]watch$"
    test "$(BLOOM_HOME=/workspace/.bloom bloom --quiet wallet address workspace-login | tr "[:upper:]" "[:lower:]")" = 0x1111111111111111111111111111111111111111
    BLOOM_HOME=/workspace/.bloom bloom --quiet vfs ls /
    BLOOM_HOME=/workspace/.bloom bloom --quiet vfs cat /wallets/workspace-login/address
    test ! -e /workspace/.bloom/keystore/workspace-login/encrypted.key
    test ! -e /workspace/.bloom/keystore/workspace-login/passkey.json
    if PRIVATE_KEY=forbidden bloom-guest-bootstrap validate 0x1111111111111111111111111111111111111111 2>/tmp/signer-env.err; then
      printf "%s\n" "error: bootstrap unexpectedly accepted signer environment" >&2
      exit 1
    fi
    grep -q "PRIVATE_KEY is forbidden" /tmp/signer-env.err
    : > /workspace/.bloom/keystore/workspace-login/encrypted.key
    if bloom-guest-bootstrap init 0x1111111111111111111111111111111111111111 2>/tmp/signer-state.err; then
      printf "%s\n" "error: bootstrap unexpectedly accepted signer state" >&2
      exit 1
    fi
    grep -q "signer or unknown state is forbidden" /tmp/signer-state.err
    if BLOOM_EGRESS_MODE=air-gapped bloom-guest-bootstrap serve 0x1111111111111111111111111111111111111111 2>/tmp/serve.err; then
      printf "%s\n" "error: serve unexpectedly accepted air-gapped mode" >&2
      exit 1
    fi
    grep -q "controlled egress is unavailable" /tmp/serve.err
  '

printf 'Clean Alpine watch-wallet/VFS smoke passed for %s\n' "$BLOOM_BIN"
