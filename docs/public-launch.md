# Public launch

The service is designed for public registration, not an allowlist. Public means automatically bounded, not unlimited.

## Startup requirements

Public mode refuses unsafe combinations. Configure:

- the exact HTTPS `BLOOM_ORIGIN`;
- `BLOOM_PUBLIC_MODE=1` and development auth off;
- QEMU or jailed Firecracker—never the host process runtime;
- independent, non-default session and agent secrets of at least 32 bytes;
- Turnstile site and secret keys;
- `BLOOM_VM_EGRESS=none` or `controlled`, never raw `internet`;
- reviewed capacity, lease, memory, CPU, and disk limits.

Generate secrets with `openssl rand -base64 48` and keep them in root-readable deployment files outside Git.

Optional SSH requires an absolute private CA key path and sibling `.pub` file. The private file must be owned by the agent user and mode 0600. Optional NFS additionally requires QEMU, persistent volumes, the verified custom kernel/config/checksum set, and the SSH gateway. Do not enable a capability merely because its UI exists; the agent's health response is the authority.

## Recommended pilot limits

```text
BLOOM_LEASE_MINUTES=20
BLOOM_MAX_LEASE_MINUTES=30
BLOOM_MAX_RUNNING=4
BLOOM_MAX_QUEUE=40
BLOOM_MAX_ACTIVE_PER_WALLET=1
BLOOM_MAX_ACTIVE_PER_IP=1
BLOOM_DAILY_PER_WALLET=2
BLOOM_DAILY_PER_IP=3
BLOOM_VM_MEMORY_MIB=512
BLOOM_VM_VCPUS=1
BLOOM_VM_EGRESS=controlled
```

Review the egress hostname list before selecting `controlled`. The policy is appropriate for public package registries; it is not a safe way to inject private registry credentials or broad cloud access.

## Host setup

1. Use a dedicated, patched Linux/KVM host with current CPU microcode. Do not colocate production wallets, signing services, secrets, or unrelated tenants.
2. Separate control and agent identities. Keep the control user out of `kvm`; give only the agent its VM artifacts, data directory, runtime socket directory, `/dev/kvm`, and optional SSH CA.
3. Build the static Bloom CLI, curated image, and optional NFS kernel from pinned inputs. Vulnerability-scan them and record their generated checksums/provenance.
4. Install the systemd services. Keep `KillMode=control-group`; verify an agent crash kills all child VMs. Use the root/jailer unit only for Firecracker and reserve its UID/GID range.
5. Terminate TLS with a maintained proxy in front of `127.0.0.1:8787`. Preserve WebSocket upgrades for terminal and `bloom-ssh-v1`. Never expose the agent socket, QEMU loopback forwards, port 22, or port 2049.
6. Default-deny inbound except TLS and operator management. Do not attach a Firecracker TAP device without separately reviewed host firewall/egress policy.
7. Enforce disk, memory, PID, CPU, and file-descriptor ceilings at systemd and infrastructure layers. Alert on queue saturation, VM failures, disk pressure, agent restarts, admission spikes, and spend.
8. Publish terms, retention/deletion behavior, an abuse contact, and an emergency admission-off switch before announcement.

## Go/no-go checks

- [ ] `npm ci`, `npm run check`, `npm run build`, shell syntax checks, and dependency audit pass from a clean clone.
- [ ] The selected VM image boots and guest-control readiness passes on the deployment host.
- [ ] Terminal, upload/download/delete, structured job/log/cancel, Bloom watch/VFS, and persistence-across-workspace-ID flows pass.
- [ ] Allowed package installs work and metadata/private/disallowed destinations fail.
- [ ] If SSH is enabled, real certificate issuance, pinned host-key connection, expiry, revocation, wrong-owner, wrong-mode, and connection-limit tests pass through public TLS.
- [ ] If NFS is enabled, the kernel checksum gate passes and Linux mount/write/remount/unmount works only through the SSH tunnel. Required macOS/Windows device gates are recorded separately.
- [ ] Stopped/expired VMs, tunnels, proxy sessions, and disposable disks disappear promptly; persistent volumes remain only when selected.
- [ ] The control identity cannot use KVM, read VM disks, or read the SSH CA. The VM contains no operator secret.
- [ ] Turnstile and trusted-proxy/IP behavior are verified on the production hostname.
- [ ] Backups exclude live tenant disks and session cookies unless a documented encrypted policy says otherwise.

The repository does not provision DNS, TLS, Cloudflare, cloud resources, monitoring, abuse staffing, or budgets. Those external systems remain operator-owned launch gates.
