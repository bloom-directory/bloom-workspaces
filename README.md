# Bloom Workspaces

Bloom Workspaces is a public-signup prototype for short-lived, wallet-authenticated Linux development machines. A user signs an [ERC-4361 SIWE](https://eips.ethereum.org/EIPS/eip-4361) message and gets a real, unprivileged shell inside a dedicated KVM VM—without being placed on an operator-maintained allowlist.

This repository now includes a working vertical slice for:

- injected-wallet and WalletConnect/Reown mobile SIWE;
- QEMU and jailed Firecracker VM isolation with hard lease expiry;
- a curated Alpine image containing Git, compilers, Node, Python, editors, SSH, NFS tools, and a verified static Bloom CLI;
- policy-controlled HTTP/HTTPS package egress with hostname, DNS, SNI, address, byte, connection, and time limits;
- browser terminal, authenticated file upload/download, persistent wallet-owned volumes, and structured job APIs with streamed logs and cancellation;
- watch-only Bloom identity and VFS access, with no signer or transaction capability in the guest;
- short-lived, owner-scoped SSH certificates over a private WebSocket gateway;
- optional NFSv4 over an NFS-only SSH tunnel, backed by a verified NFSD-enabled QEMU kernel.

The original product prompt is [bloom-directory/pm#38](https://github.com/bloom-directory/pm/issues/38).

## What works on each client

| Client | Browser terminal/files/jobs | Wallet sign-in | Native SSH | Native NFS |
|---|---|---|---|---|
| Linux | Yes | Browser wallet or WalletConnect | Yes, OpenSSH + Node proxy helper | Yes, admin mount required |
| macOS | Yes | Browser wallet or WalletConnect | Yes, OpenSSH + Node proxy helper | Implemented; real-device validation remains a release gate |
| Windows | Yes | Browser wallet or WalletConnect | Conditional on optional OpenSSH + Node | Conditional on Client for NFS, admin, and compatibility probe |
| Android / iOS | Yes | WalletConnect deep-link/QR flow | Browser-terminal fallback | Browser-files fallback |

Browser access is the reliable zero-install product. Desktop SSH/NFS are power-user paths and never expose guest ports publicly.

## Build and run

Requirements: Linux, Node 22+, KVM, QEMU, Docker for the reproducible builders, and enough space for a 4 GiB sparse guest image.

```bash
npm ci
ops/bloom/build-musl.sh
sudo ops/images/build-demo-image.sh
npm run dev:vm
```

Open <http://127.0.0.1:8787>, use **Local demo sign-in**, and create a workspace. `npm run dev` is a non-isolated host-process UI development mode and is rejected in public mode.

For optional native NFS, build and select the pinned NFSD kernel:

```bash
ops/connections/build-nfs-kernel-container.sh
export BLOOM_VM_KERNEL="$PWD/artifacts/nfs-kernel/vmlinux-6.1.155-nfsd"
export BLOOM_NFS_KERNEL_CONFIG="$PWD/artifacts/nfs-kernel/vmlinux-6.1.155-nfsd.config"
export BLOOM_SSH_ENABLED=1
export BLOOM_SSH_CA_KEY=/absolute/private/path/workspace_ca
export BLOOM_NFS_ENABLED=1
```

Generate the SSH user CA outside the repository with `ssh-keygen -t ed25519 -f /absolute/private/path/workspace_ca`. The private key must be owned by the agent user and mode 0600; the sibling `.pub` file is the only CA material sent into guests.

Enable curated package access with `BLOOM_VM_EGRESS=controlled`. The default policy permits the public npm and PyPI hosts listed in `.env.example`; raw Internet mode is rejected in public deployments.

## Product and security boundaries

- The workspace shell can run arbitrary commands as UID/GID 1000 inside its own VM. It is not guest root and receives no host, wallet, or platform secret.
- Persistent storage is a separate quota-bounded ext4 volume keyed to the authenticated wallet. Stopping a VM retains it; the explicit destroy API removes it. Jailed Firecracker currently reports persistence unsupported; QEMU is the complete reference path.
- `/bloom` is watch-only. The guest can read its wallet-scoped Bloom VFS through `bloom vfs` and `bloom-workspace`, but cannot sign, approve, or submit transactions.
- Controlled egress is HTTP/HTTPS package access, not general networking. Private, loopback, link-local, metadata, multicast, reserved, and non-allowlisted destinations are blocked; TLS SNI must match the requested host.
- SSH grants accept only a user public key, last at most the remaining workspace lease, pin an ephemeral guest host key, and are revoked when the workspace stops. The user's private key never leaves their device.
- NFS listens only on guest loopback and is reachable solely through an NFS-mode certificate that cannot open a shell or PTY. All NFS identities are squashed to the workspace user.
- The operator remains trusted for compute confidentiality. Do not place seed phrases, funded private keys, production credentials, or Bloom signing/approval services in a workspace.

Public access is bounded with Turnstile, wallet/IP rolling limits, one active workspace per wallet, fixed VM resources, a bounded FIFO queue, and hard node-agent expiry. Wallet identity is not proof of personhood, so capacity and spend limits remain essential.

## Verification

```bash
npm run check
npm run build
npm run smoke:live
```

The image and kernel builders pin upstream inputs, verify SHA-256 digests, and emit provenance/checksum manifests. Read [Architecture](docs/architecture.md), [Threat model](docs/threat-model.md), [Private connections](ops/connections/README.md), and [Public launch](docs/public-launch.md) before exposing a deployment.

## Repository map

- `web/` — SIWE/WalletConnect UI, terminal, files, jobs, Bloom, and connection grants.
- `src/control/` — public auth, admission, lifecycle, APIs, and WebSocket relays.
- `src/agent/` — private node API, VM lifecycle, egress, volumes, guest control, and SSH leases.
- `src/jobs/`, `src/ssh/`, `src/nfs/` — bounded execution and private connection policies.
- `ops/images/`, `ops/bloom/`, `ops/guest-control/`, `ops/connections/` — reproducible guest/runtime artifacts.

MIT. Experimental software; no warranty.
