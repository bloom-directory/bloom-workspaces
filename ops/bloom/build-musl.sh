#!/bin/sh
set -eu

# Reproducible x86_64-musl build of the exact Bloom v0.1.3 release source.
# The source archive, Alpine builder image, top-level build packages, Cargo.lock,
# git dependencies, enabled feature set, and Rust build flags are all pinned or
# captured in the emitted provenance.

BLOOM_VERSION=v0.1.3
BLOOM_COMMIT=c81e61036bf2939385124ed5bb713a478e16d511
BLOOM_SOURCE_SHA256=2abf7a306aed41c74ced343dabf75d728d6c3af926e49f6ac2fa2f4c85a223e9
BLOOM_CARGO_LOCK_SHA256=2bbfabcbe1b14032b0c1e54ce386e27883d545a55ad46c487a073a2e5c8da96e
BLOOM_SOURCE_DATE_EPOCH=1785419359
BLOOM_SOURCE_URL="https://github.com/bloom-directory/bloom/archive/${BLOOM_COMMIT}.tar.gz"

ALPINE_IMAGE='alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b'
ALPINE_PLATFORM=linux/amd64
BUILD_PACKAGES='build-base=0.5-r4 cargo=1.96.1-r0 rust=1.96.1-r0 git=2.54.0-r0 cmake=4.2.3-r0 perl=5.42.2-r0 pkgconf=2.5.1-r0 openssl-dev=3.5.7-r0 openssl-libs-static=3.5.7-r0'

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DEFAULT_OUTPUT_DIR="${SCRIPT_DIR}/artifacts/${BLOOM_VERSION}-x86_64-musl"
OUTPUT_DIR=${1:-$DEFAULT_OUTPUT_DIR}

command -v curl >/dev/null 2>&1 || {
  printf '%s\n' 'error: curl is required to download the pinned source archive' >&2
  exit 1
}
command -v docker >/dev/null 2>&1 || {
  printf '%s\n' 'error: Docker is required for the isolated Alpine builder' >&2
  exit 1
}
command -v sha256sum >/dev/null 2>&1 || {
  printf '%s\n' 'error: sha256sum is required to verify source and output' >&2
  exit 1
}

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR=$(CDPATH= cd -- "$OUTPUT_DIR" && pwd)
BUILD_DIR=$(mktemp -d "${TMPDIR:-/tmp}/bloom-musl.${BLOOM_VERSION}.XXXXXX")

cleanup() {
  case "$BUILD_DIR" in
    "${TMPDIR:-/tmp}"/bloom-musl."${BLOOM_VERSION}".*) rm -rf -- "$BUILD_DIR" ;;
    *) printf 'warning: refusing to remove unexpected build directory: %s\n' "$BUILD_DIR" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

SOURCE_ARCHIVE="${BUILD_DIR}/bloom-${BLOOM_COMMIT}.tar.gz"
SOURCE_DIR="${BUILD_DIR}/source"
mkdir -p "$SOURCE_DIR"

printf 'Downloading Bloom %s source at %s...\n' "$BLOOM_VERSION" "$BLOOM_COMMIT"
curl --fail --location --proto '=https' --tlsv1.2 --retry 3 \
  --output "$SOURCE_ARCHIVE" "$BLOOM_SOURCE_URL"
printf '%s  %s\n' "$BLOOM_SOURCE_SHA256" "$SOURCE_ARCHIVE" | sha256sum --check --status - || {
  printf '%s\n' 'error: Bloom source archive checksum mismatch' >&2
  exit 1
}

tar -xzf "$SOURCE_ARCHIVE" --strip-components=1 -C "$SOURCE_DIR"
printf '%s  %s\n' "$BLOOM_CARGO_LOCK_SHA256" "${SOURCE_DIR}/Cargo.lock" | sha256sum --check --status - || {
  printf '%s\n' 'error: tagged Cargo.lock checksum mismatch' >&2
  exit 1
}

printf 'Building Bloom %s in pinned Alpine 3.24 (this is a large release build)...\n' "$BLOOM_VERSION"
docker run --rm \
  --platform "$ALPINE_PLATFORM" \
  --network bridge \
  --env "BUILD_PACKAGES=$BUILD_PACKAGES" \
  --env "HOST_UID=$(id -u)" \
  --env "HOST_GID=$(id -g)" \
  --env "SOURCE_DATE_EPOCH=$BLOOM_SOURCE_DATE_EPOCH" \
  --volume "${SOURCE_DIR}:/src:ro" \
  --volume "${OUTPUT_DIR}:/out" \
  "$ALPINE_IMAGE" \
  sh -ec '
    apk add --no-cache $BUILD_PACKAGES
    export CARGO_HOME=/tmp/cargo-home
    export CARGO_INCREMENTAL=0
    export CARGO_NET_GIT_FETCH_WITH_CLI=true
    export CARGO_TARGET_DIR=/tmp/cargo-target
    export OPENSSL_STATIC=1
    export PKG_CONFIG_ALL_STATIC=1
    # Keep proc-macro crates dynamically loadable by the Alpine host compiler.
    # +crt-static is passed only to the final executable below.
    export RUSTFLAGS="-C strip=symbols --remap-path-prefix=/src=/usr/src/bloom"
    cd /src
    cargo rustc --release --locked --package bloom --no-default-features --features mount -- \
      -C target-feature=+crt-static -C panic=abort
    strip --strip-all /tmp/cargo-target/release/bloom
    install -m 0755 /tmp/cargo-target/release/bloom /out/bloom
    rustc --version > /out/build-environment.txt
    cargo --version >> /out/build-environment.txt
    apk --version | head -n 1 >> /out/build-environment.txt
    apk info -v | sort >> /out/build-environment.txt
    file /out/bloom > /out/bloom.file.txt
    ldd /out/bloom > /out/bloom.ldd.txt 2>&1 || true
    /out/bloom --version > /out/bloom.version.txt
    chown "$HOST_UID:$HOST_GID" /out/bloom /out/build-environment.txt /out/bloom.file.txt /out/bloom.ldd.txt /out/bloom.version.txt
  '

(CDPATH= cd -- "$OUTPUT_DIR" && sha256sum bloom > SHA256SUMS)
BINARY_BYTES=$(wc -c < "$OUTPUT_DIR/bloom" | tr -d '[:space:]')
BINARY_SHA256=$(cut -d ' ' -f 1 < "$OUTPUT_DIR/SHA256SUMS")

{
  printf '{\n'
  printf '  "schema": 1,\n'
  printf '  "artifact": "bloom",\n'
  printf '  "version": "%s",\n' "$BLOOM_VERSION"
  printf '  "source_repository": "https://github.com/bloom-directory/bloom",\n'
  printf '  "source_commit": "%s",\n' "$BLOOM_COMMIT"
  printf '  "source_archive_sha256": "%s",\n' "$BLOOM_SOURCE_SHA256"
  printf '  "cargo_lock_sha256": "%s",\n' "$BLOOM_CARGO_LOCK_SHA256"
  printf '  "source_date_epoch": %s,\n' "$BLOOM_SOURCE_DATE_EPOCH"
  printf '  "builder_image": "%s",\n' "$ALPINE_IMAGE"
  printf '  "builder_platform": "%s",\n' "$ALPINE_PLATFORM"
  printf '  "cargo_command": "cargo rustc --release --locked --package bloom --no-default-features --features mount -- -C target-feature=+crt-static -C panic=abort",\n'
  printf '  "unsafe_debug_signer": false,\n'
  printf '  "binary_sha256": "%s",\n' "$BINARY_SHA256"
  printf '  "binary_bytes": %s\n' "$BINARY_BYTES"
  printf '}\n'
} > "$OUTPUT_DIR/provenance.json"

printf 'Built %s (%s bytes) at %s\n' "$BLOOM_VERSION" "$BINARY_BYTES" "$OUTPUT_DIR/bloom"
printf 'SHA256 %s\n' "$BINARY_SHA256"
