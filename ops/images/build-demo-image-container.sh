#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
builder_image='archlinux:base@sha256:345a872f6c95e082d4b8c050af637eebb57402c6e2177b411c3acf7df84eb33b'

docker run --rm \
  --volume "$repo_root:/work" \
  --workdir /work \
  --env "BUILD_UID=$(id -u)" \
  --env "BUILD_GID=$(id -g)" \
  "$builder_image" \
  /bin/bash -lc '
    set -euo pipefail
    pacman -Sy --noconfirm --needed e2fsprogs
    /work/ops/images/build-demo-image.sh
    chown "$BUILD_UID:$BUILD_GID" \
      /work/artifacts/bloom-alpine.ext4 \
      /work/artifacts/bloom-alpine.provenance.txt \
      /work/artifacts/vmlinux-6.1.155 \
      /work/artifacts/firecracker \
      /work/artifacts/jailer
  '
