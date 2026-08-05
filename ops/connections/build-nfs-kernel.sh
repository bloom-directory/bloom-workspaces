#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C
export KBUILD_BUILD_USER=bloom
export KBUILD_BUILD_HOST=workspace-builder
export KBUILD_BUILD_TIMESTAMP='1970-01-01 00:00:00 UTC'
export KCONFIG_NOTIMESTAMP=1

linux_version=6.1.155
linux_sha256=c29387aeee085fbcbd91236224b9df805063bac43615e75cea2c6b29604a5c73
firecracker_version=1.16.1
base_config_sha256=adbc70ab5e89213ba00594b12d25e09bdf8bb1ed3c252d7449326bb14c22963b
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ "${1:-}" = "--print-inputs" ]; then
  printf 'linux_version=%s\nlinux_sha256=%s\nfirecracker_version=%s\nbase_config_sha256=%s\n' "$linux_version" "$linux_sha256" "$firecracker_version" "$base_config_sha256"
  exit 0
fi
output_dir=${1:-"$script_dir/../../artifacts/nfs-kernel"}
kernel_jobs=${BLOOM_KERNEL_JOBS:-2}
case "$kernel_jobs" in ''|*[!0-9]*) printf 'BLOOM_KERNEL_JOBS must be an integer\n' >&2; exit 64 ;; esac
if [ "$kernel_jobs" -lt 1 ] || [ "$kernel_jobs" -gt 128 ]; then
  printf 'BLOOM_KERNEL_JOBS must be between 1 and 128\n' >&2
  exit 64
fi
for required_tool in bc bison curl flex gcc make openssl perl readelf sha256sum tar xz; do
  command -v "$required_tool" >/dev/null || { printf 'Missing kernel build tool: %s\n' "$required_tool" >&2; exit 69; }
done
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT

mkdir -p -- "$output_dir"
curl -fL "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${linux_version}.tar.xz" -o "$scratch/linux.tar.xz"
printf '%s  %s\n' "$linux_sha256" "$scratch/linux.tar.xz" | sha256sum -c -
curl -fL "https://raw.githubusercontent.com/firecracker-microvm/firecracker/v${firecracker_version}/resources/guest_configs/microvm-kernel-ci-x86_64-6.1.config" -o "$scratch/base.config"
printf '%s  %s\n' "$base_config_sha256" "$scratch/base.config" | sha256sum -c -
tar -C "$scratch" -xf "$scratch/linux.tar.xz"
source_dir="$scratch/linux-${linux_version}"
cp "$scratch/base.config" "$source_dir/.config"

while IFS= read -r setting; do
  case "$setting" in
    CONFIG_*=y) option=${setting%%=*}; option=${option#CONFIG_}; "$source_dir/scripts/config" --file "$source_dir/.config" --enable "$option" ;;
    '# CONFIG_'*' is not set') option=${setting#\# CONFIG_}; option=${option% is not set}; "$source_dir/scripts/config" --file "$source_dir/.config" --disable "$option" ;;
    ''|'# '*) ;;
    *) printf 'Unsupported kernel fragment line: %s\n' "$setting" >&2; exit 1 ;;
  esac
done < "$script_dir/nfsd.config"

make -C "$source_dir" olddefconfig
make -C "$source_dir" -j"$kernel_jobs" vmlinux
for required in CONFIG_NFSD=y CONFIG_NFSD_V4=y '# CONFIG_NFSD_BLOCKLAYOUT is not set' '# CONFIG_NFSD_SCSILAYOUT is not set' '# CONFIG_NFSD_FLEXFILELAYOUT is not set'; do
  grep -Fxq "$required" "$source_dir/.config" || { printf 'Missing required kernel setting: %s\n' "$required" >&2; exit 1; }
done
if grep -Fxq 'CONFIG_NFSD_PNFS=y' "$source_dir/.config"; then
  printf 'pNFS server layouts must remain disabled\n' >&2
  exit 1
fi
if ! readelf -n "$source_dir/vmlinux" 2>/dev/null | grep -Eq 'Xen.*0x0*12'; then
  printf 'Built kernel is missing the QEMU PVH ELF note\n' >&2
  exit 1
fi
install -m 0755 -- "$source_dir/vmlinux" "$output_dir/vmlinux-${linux_version}-nfsd"
install -m 0644 -- "$source_dir/.config" "$output_dir/vmlinux-${linux_version}-nfsd.config"
{
  printf 'builder_image=debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241\n'
  gcc --version | head -n 1
  ld --version | head -n 1
} > "$output_dir/BUILD-ENVIRONMENT.txt"
(cd "$output_dir" && sha256sum "vmlinux-${linux_version}-nfsd" "vmlinux-${linux_version}-nfsd.config" BUILD-ENVIRONMENT.txt) > "$output_dir/SHA256SUMS"
printf 'Built pinned QEMU NFS kernel in %s\n' "$output_dir"
