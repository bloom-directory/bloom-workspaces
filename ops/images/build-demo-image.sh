#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_dir="${BLOOM_ARTIFACT_DIR:-$repo_root/artifacts}"
scratch="$(mktemp -d)"
trap 'rm -rf -- "$scratch"' EXIT

alpine_version="3.24.0"
alpine_archive="alpine-minirootfs-${alpine_version}-x86_64.tar.gz"
alpine_sha256="de9a11c0e0e7e9c94db3ed8af7b450eafc0b13687bd7e9199d55050f20aa0a89"
kernel_name="vmlinux-6.1.155"
kernel_sha256="e41c7048bd2475e7e788153823fcb9166a7e0b78c4c443bd6446d015fa735f53"
firecracker_version="v1.16.1"
firecracker_archive="firecracker-${firecracker_version}-x86_64.tgz"
firecracker_sha256="382a02a869e4d6d5cb14c40577f9545e8458021ea8b0b2d3fc10ec14d9c242e6"

mkdir -p "$artifact_dir" "$scratch/rootfs"
curl -fL "https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/$alpine_archive" -o "$scratch/$alpine_archive"
printf '%s  %s\n' "$alpine_sha256" "$scratch/$alpine_archive" | sha256sum --check --status
tar --numeric-owner -xzf "$scratch/$alpine_archive" -C "$scratch/rootfs"

install -D -m 0755 "$repo_root/ops/images/guest/bloom-init" "$scratch/rootfs/usr/local/sbin/bloom-init"
cc -static -O2 -Wall -Wextra -Werror "$repo_root/ops/images/guest/bloom-vsock-agent.c" -o "$scratch/rootfs/usr/local/sbin/bloom-vsock-agent" -lutil
install -D -m 0644 "$repo_root/ops/images/guest/profile" "$scratch/rootfs/etc/profile"
install -D -m 0644 "$repo_root/ops/images/guest/ashrc" "$scratch/rootfs/etc/ashrc"
mkdir -p "$scratch/rootfs/workspace" "$scratch/rootfs/proc" "$scratch/rootfs/sys" "$scratch/rootfs/dev" "$scratch/rootfs/run" "$scratch/rootfs/tmp"

truncate -s 1G "$artifact_dir/bloom-alpine.ext4"
mkfs.ext4 -F -q -d "$scratch/rootfs" "$artifact_dir/bloom-alpine.ext4"

curl -fL "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.14/x86_64/$kernel_name" -o "$artifact_dir/$kernel_name"
printf '%s  %s\n' "$kernel_sha256" "$artifact_dir/$kernel_name" | sha256sum --check --status

curl -fL "https://github.com/firecracker-microvm/firecracker/releases/download/$firecracker_version/$firecracker_archive" -o "$scratch/$firecracker_archive"
printf '%s  %s\n' "$firecracker_sha256" "$scratch/$firecracker_archive" | sha256sum --check --status
tar -xzf "$scratch/$firecracker_archive" -C "$scratch"
install -m 0755 "$scratch/release-${firecracker_version}-x86_64/firecracker-${firecracker_version}-x86_64" "$artifact_dir/firecracker"
install -m 0755 "$scratch/release-${firecracker_version}-x86_64/jailer-${firecracker_version}-x86_64" "$artifact_dir/jailer"

printf 'Built verified demo assets in %s\n' "$artifact_dir"
printf 'These images are a development baseline; patch and scan them before an Internet deployment.\n'
