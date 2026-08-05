#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
output_dir="${1:-$repo_root/artifacts/nfs-kernel}"
case "$output_dir" in "$repo_root"/*) ;; *) printf 'Output must remain below %s\n' "$repo_root" >&2; exit 64 ;; esac
mkdir -p "$output_dir"

builder_image='debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241'
relative_output="${output_dir#"$repo_root"/}"

docker run --rm \
  --volume "$repo_root:/work" \
  --workdir /work \
  --env "BUILD_UID=$(id -u)" \
  --env "BUILD_GID=$(id -g)" \
  --env "BLOOM_KERNEL_JOBS=${BLOOM_KERNEL_JOBS:-8}" \
  "$builder_image" \
  /bin/bash -lc '
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends \
      bc binutils bison build-essential ca-certificates cpio curl flex libelf-dev libssl-dev openssl perl python3 tar util-linux xz-utils
    chown "$BUILD_UID:$BUILD_GID" "/work/'"$relative_output"'"
    exec setpriv --reuid="$BUILD_UID" --regid="$BUILD_GID" --clear-groups \
      /work/ops/connections/build-nfs-kernel.sh "/work/'"$relative_output"'"
  '
