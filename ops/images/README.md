# Curated workspace image

`build-demo-image.sh` produces the x86-64 Alpine development image used by the
QEMU and Firecracker pilots. Run it as root on a disposable build host so signed
APK install scripts can run in the staged root filesystem:

```sh
sudo ops/images/build-demo-image.sh
```

The base archive, APK bootstrap tool, kernel, and Firecracker release have pinned
SHA-256 digests. Direct package versions and repository branches are in
`packages.lock` and `repositories`; Alpine's packaged signing keys verify indexes
and APKs. The build emits `artifacts/bloom-alpine.provenance.txt` with the complete
resolved package set and output digests. Alpine point-release repositories retain
only their current signed package revision, so long-term rebuilds also require an
operator-controlled mirror of the resolved APK closure recorded by provenance.

The practical image includes Git, curl and CA roots, Bash, nano and Neovim, jq,
ripgrep, OpenSSH client/server, tmux, Python/pip, Node/npm, a C/C++ build toolchain,
NFS utilities, the bounded guest-control service, and the verified static Bloom
CLI. The interactive account is the locked-password, unprivileged `workspace`
user. sshd and NFSD remain stopped until the agent supplies a workspace scope,
the operator CA public key, and the required runtime/kernel capability.

At boot, `/workspace` stays on the disposable root filesystem unless the kernel
command line contains the exact token `bloom_workspace=/dev/vdb`. When it does,
init waits up to five seconds for that block device and mounts it as ext4 with
`nodev,nosuid`; a missing or unmountable advertised volume powers the guest off.
The runtime declares an exact `bloom_transport=qemu` or
`bloom_transport=vsock` kernel argument; the image never infers the transport
from device-node presence. Firecracker's vsock agent and QEMU's serial fallback
both use the same locked uid/gid 1000 account with cleared groups and
capabilities, never a root shell.

## Bloom CLI

The upstream Bloom v0.1.3 release binary is glibc-linked and cannot run safely
on this Alpine/musl image through `gcompat`. `ops/bloom/build-musl.sh` therefore
builds the pinned upstream commit as static PIE in a pinned container, checks the
source and Cargo inputs, and emits provenance and a checksum. The image build
refuses to proceed unless that artifact verifies, then installs it as
`/usr/local/bin/bloom` and initializes only the authenticated watch address.

## Egress integration hooks

The image includes tools that honor `HTTP_PROXY` and `HTTPS_PROXY`; init sets
them only when the node agent creates one private proxy
socket per workspace and the runtime must expose only that socket: QEMU through a
restricted user-net `guestfwd`, Firecracker through its per-port vsock Unix socket
and a guest TCP-to-vsock bridge. Guests must not receive a general TAP/NAT route.
CONNECT is TLS-only: the proxy buffers a bounded ClientHello and requires one
unencrypted SNI exactly matching the approved hostname before opening the pinned
upstream IP. Missing/mismatched SNI, ECH, non-TLS protocols, and malformed or
oversized ClientHello records fail closed. TLS remains end-to-end encrypted after
that hostname check.
