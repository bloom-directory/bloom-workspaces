#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_dir="${BLOOM_ARTIFACT_DIR:-$repo_root/artifacts}"
bloom_artifact="${BLOOM_CLI_ARTIFACT:-$repo_root/ops/bloom/artifacts/v0.1.3-x86_64-musl/bloom}"
bloom_sums="$(dirname "$bloom_artifact")/SHA256SUMS"
scratch="$(mktemp -d)"
trap 'rm -rf -- "$scratch"' EXIT

alpine_version="3.24.0"
alpine_archive="alpine-minirootfs-${alpine_version}-x86_64.tar.gz"
alpine_sha256="de9a11c0e0e7e9c94db3ed8af7b450eafc0b13687bd7e9199d55050f20aa0a89"
apk_tools_version="3.0.7-r0"
apk_tools_archive="apk-tools-static-${apk_tools_version}.apk"
apk_tools_sha256="ed1c5e82177844249b7c4ecc2653b78eed096be20496b7fb860a9e165b2e5ce1"
kernel_name="vmlinux-6.1.155"
kernel_sha256="e41c7048bd2475e7e788153823fcb9166a7e0b78c4c443bd6446d015fa735f53"
firecracker_version="v1.16.1"
firecracker_archive="firecracker-${firecracker_version}-x86_64.tgz"
firecracker_sha256="382a02a869e4d6d5cb14c40577f9545e8458021ea8b0b2d3fc10ec14d9c242e6"
image_uuid="b1000000-0000-4000-8000-000000000001"

if [[ "$(id -u)" -ne 0 ]]; then
  printf 'The curated image build must run as root so apk can preserve ownership and execute signed package triggers.\n' >&2
  exit 1
fi
for command in curl sha256sum tar install chroot truncate mkfs.ext4; do
  command -v "$command" >/dev/null || { printf 'Missing build dependency: %s\n' "$command" >&2; exit 1; }
done
if [[ ! -x "$bloom_artifact" || ! -f "$bloom_sums" ]]; then
  printf 'Missing verified musl Bloom CLI. Run ops/bloom/build-musl.sh first or set BLOOM_CLI_ARTIFACT.\n' >&2
  exit 1
fi
(cd "$(dirname "$bloom_artifact")" && sha256sum --check --status SHA256SUMS)

mkdir -p "$artifact_dir" "$scratch/rootfs" "$scratch/apk-tools"
curl -fL "https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/$alpine_archive" -o "$scratch/$alpine_archive"
printf '%s  %s\n' "$alpine_sha256" "$scratch/$alpine_archive" | sha256sum --check --status
tar --numeric-owner -xzf "$scratch/$alpine_archive" -C "$scratch/rootfs"

curl -fL "https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/$apk_tools_archive" -o "$scratch/$apk_tools_archive"
printf '%s  %s\n' "$apk_tools_sha256" "$scratch/$apk_tools_archive" | sha256sum --check --status
tar -xzf "$scratch/$apk_tools_archive" -C "$scratch/apk-tools" sbin/apk.static

mapfile -t packages < <(sed -E '/^[[:space:]]*(#|$)/d' "$repo_root/ops/images/packages.lock")
"$scratch/apk-tools/sbin/apk.static" \
  --root "$scratch/rootfs" \
  --repositories-file "$repo_root/ops/images/repositories" \
  --no-cache \
  add "${packages[@]}"

install -D -m 0755 "$repo_root/ops/images/guest/bloom-init" "$scratch/rootfs/usr/local/sbin/bloom-init"
install -D -m 0755 "$repo_root/ops/images/guest/bloom-workspace-device" "$scratch/rootfs/usr/local/sbin/bloom-workspace-device"
install -D -m 0755 "$repo_root/ops/images/guest/bloom-workspace-identity" "$scratch/rootfs/usr/local/sbin/bloom-workspace-identity"
# Build the Rust guest-control binary (static musl for Alpine)
guest_control_bin="$repo_root/ops/guest-control/target/x86_64-unknown-linux-musl/release/bloom-guest-control"
if [[ ! -x "$guest_control_bin" ]]; then
  printf 'Building Rust guest-control binary (musl)...\n' >&2
  (cd "$repo_root/ops/guest-control" && cargo build --release --target x86_64-unknown-linux-musl)
fi
install -D -m 0755 "$guest_control_bin" "$scratch/rootfs/usr/local/libexec/bloom-guest-control"
install -D -m 0755 "$guest_control_bin" "$scratch/rootfs/usr/local/bin/bloom-workspace"
install -D -m 0755 "$repo_root/ops/bloom/guest-bootstrap.sh" "$scratch/rootfs/usr/local/sbin/bloom-guest-bootstrap"
install -D -m 0755 "$repo_root/ops/connections/workspace-ssh-session" "$scratch/rootfs/usr/local/libexec/bloom-workspace-shell"
install -D -m 0755 "$bloom_artifact" "$scratch/rootfs/usr/local/bin/bloom"
install -D -m 0444 "$repo_root/ops/images/guest/bloom-surface.md" "$scratch/rootfs/bloom/README.md"
install -D -m 0644 "$repo_root/ops/images/guest/bloom-vsock-agent.c" "$scratch/rootfs/tmp/bloom-vsock-agent.c"
chroot "$scratch/rootfs" /usr/bin/cc -static -O2 -Wall -Wextra -Werror /tmp/bloom-vsock-agent.c -o /usr/local/sbin/bloom-vsock-agent -lutil
rm -f -- "$scratch/rootfs/tmp/bloom-vsock-agent.c"
install -D -m 0644 "$repo_root/ops/images/guest/profile" "$scratch/rootfs/etc/profile"
install -D -m 0644 "$repo_root/ops/images/guest/ashrc" "$scratch/rootfs/etc/ashrc"
install -D -m 0600 "$repo_root/ops/images/guest/sshd_config" "$scratch/rootfs/etc/ssh/sshd_config"
mkdir -p "$scratch/rootfs/workspace" "$scratch/rootfs/bloom" "$scratch/rootfs/proc" "$scratch/rootfs/sys" "$scratch/rootfs/dev" "$scratch/rootfs/run" "$scratch/rootfs/tmp"

if ! grep -q '^workspace:' "$scratch/rootfs/etc/group"; then
  printf 'workspace:x:1000:\n' >>"$scratch/rootfs/etc/group"
  printf 'workspace:!::\n' >>"$scratch/rootfs/etc/gshadow"
fi
if ! grep -q '^workspace:' "$scratch/rootfs/etc/passwd"; then
  printf 'workspace:x:1000:1000:Bloom Workspace:/workspace:/bin/bash\n' >>"$scratch/rootfs/etc/passwd"
  printf 'workspace:!:20000:0:99999:7:::\n' >>"$scratch/rootfs/etc/shadow"
fi
chown 1000:1000 "$scratch/rootfs/workspace"
chmod 0700 "$scratch/rootfs/workspace"
chmod 0755 "$scratch/rootfs/bloom"
# apk's transaction identifier is intentionally random and has no runtime value.
# Excluding the build log keeps the otherwise pinned ext4 artifact byte-stable.
rm -f -- "$scratch/rootfs/var/log/apk.log"

provenance="$artifact_dir/bloom-alpine.provenance.txt"
{
  printf 'format=bloom-workspace-image-v1\n'
  printf 'architecture=x86_64\n'
  printf 'alpine_version=%s\n' "$alpine_version"
  printf 'alpine_archive_sha256=%s\n' "$alpine_sha256"
  printf 'apk_tools_version=%s\n' "$apk_tools_version"
  printf 'apk_tools_archive_sha256=%s\n' "$apk_tools_sha256"
  printf 'repositories_begin\n'
  sed -E '/^[[:space:]]*(#|$)/d' "$repo_root/ops/images/repositories"
  printf 'repositories_end\n'
  printf 'requested_packages_begin\n'
  printf '%s\n' "${packages[@]}"
  printf 'requested_packages_end\n'
  printf 'installed_packages_begin\n'
  "$scratch/apk-tools/sbin/apk.static" --root "$scratch/rootfs" info -vv | LC_ALL=C sort
  printf 'installed_packages_end\n'
  printf 'bloom_cli=installed-static-musl\n'
  printf 'bloom_cli_release=v0.1.3\n'
  printf 'bloom_cli_sha256=%s\n' "$(sha256sum "$bloom_artifact" | cut -d' ' -f1)"
  printf 'guest_control_sha256=%s\n' "$(sha256sum "$guest_control_bin" | cut -d' ' -f1)"
} >"$provenance"

truncate -s 4G "$artifact_dir/bloom-alpine.ext4"
SOURCE_DATE_EPOCH=1785376800 mkfs.ext4 -F -q \
  -U "$image_uuid" \
  -E "hash_seed=$image_uuid,lazy_itable_init=0,lazy_journal_init=0" \
  -d "$scratch/rootfs" \
  "$artifact_dir/bloom-alpine.ext4"

curl -fL "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.14/x86_64/$kernel_name" -o "$artifact_dir/$kernel_name"
printf '%s  %s\n' "$kernel_sha256" "$artifact_dir/$kernel_name" | sha256sum --check --status

curl -fL "https://github.com/firecracker-microvm/firecracker/releases/download/$firecracker_version/$firecracker_archive" -o "$scratch/$firecracker_archive"
printf '%s  %s\n' "$firecracker_sha256" "$scratch/$firecracker_archive" | sha256sum --check --status
tar -xzf "$scratch/$firecracker_archive" -C "$scratch"
install -m 0755 "$scratch/release-${firecracker_version}-x86_64/firecracker-${firecracker_version}-x86_64" "$artifact_dir/firecracker"
install -m 0755 "$scratch/release-${firecracker_version}-x86_64/jailer-${firecracker_version}-x86_64" "$artifact_dir/jailer"

{
  printf 'rootfs_sha256='
  sha256sum "$artifact_dir/bloom-alpine.ext4" | cut -d' ' -f1
  printf 'kernel_sha256=%s\n' "$kernel_sha256"
  printf 'firecracker_sha256='
  sha256sum "$artifact_dir/firecracker" | cut -d' ' -f1
  printf 'jailer_sha256='
  sha256sum "$artifact_dir/jailer" | cut -d' ' -f1
} >>"$provenance"

printf 'Built verified curated development assets in %s\n' "$artifact_dir"
printf 'Package and artifact provenance: %s\n' "$provenance"
