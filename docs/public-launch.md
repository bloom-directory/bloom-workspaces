# Public launch

The service is designed for public registration, not an allowlist. Public access should begin as a deliberately small, air-gapped pilot.

## Required configuration

Public mode refuses to start unless all of these are true:

- `BLOOM_PUBLIC_MODE=1`;
- `BLOOM_ORIGIN` is the exact public HTTPS origin;
- development authentication is off;
- runtime is QEMU or Firecracker;
- Firecracker uses the jailer;
- session and agent secrets are at least 32 non-default bytes;
- Turnstile site and secret keys are configured;
- guest egress is `none`.

Generate independent secrets with `openssl rand -base64 48`. Store them in root-readable environment files, not Git.

## Initial limits

Recommended first-week settings on a dedicated host:

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
BLOOM_VM_EGRESS=none
```

These are cost ceilings, not product ideals. Raise them only from observed utilization and abuse data.

## Host setup

1. Use a dedicated, fully patched Linux/KVM host with current CPU microcode. Do not colocate wallets, signing services, databases with production secrets, or unrelated tenants.
2. Create `bloom-control`, `bloom-agent`, and `bloom-workspaces` identities. Keep the control user out of the `kvm` group. The QEMU agent runs unprivileged with supplemental `kvm` access. Firecracker uses the separate root/jailer unit; reserve numeric UIDs/GIDs 30000–49999 exclusively for its per-VM jails.
3. Build and vulnerability-scan the guest image. Pin the resulting kernel/rootfs digests in deployment inventory.
4. Copy `ops/control.env.example` and `ops/agent.env.example` to their respective root-owned environment files and replace every placeholder. Only the shared agent bearer belongs in both. Install the control unit and the QEMU agent unit. If selecting Firecracker, install `bloom-workspaces-agent-firecracker.service` under the name `bloom-workspaces-agent.service` instead. Confirm the control process cannot open `/dev/kvm`; confirm the node agent does not receive the session or Turnstile secrets.
5. Put Caddy or another maintained TLS proxy in front of `127.0.0.1:8787`. Do not expose the node-agent socket or port.
6. Configure firewall default-deny inbound except 80/443 and the operator management path. The initial guest has no egress interface.
7. Set disk, memory, PID, CPU, and file-descriptor ceilings at both systemd and infrastructure layers.
8. Configure alerts for queue saturation, VM start failures, unexpected VM exits, disk pressure, agent restarts, and admission spikes.

## Go/no-go checks

- [ ] `npm run check` and `npm run build` pass from a clean clone.
- [ ] QEMU or jailed Firecracker live smoke test passes on the deployment host.
- [ ] A stopped/expired VM process and disk disappear within five seconds.
- [ ] Killing the node agent kills every child VM; recovery marks workspaces failed.
- [ ] Direct requests cannot bypass the TLS proxy's client-IP chain.
- [ ] Turnstile tokens are required and verified for the production hostname.
- [ ] A guest cannot reach the host, RFC1918, link-local, cloud metadata, or Internet.
- [ ] The control user cannot read VM disks or use KVM.
- [ ] The VM contains no operator secret and receives none at runtime.
- [ ] Backups exclude live VM disks and session cookies; deletion behavior is documented.
- [ ] Terms, privacy/retention language, abuse contact, and emergency shutdown are published.
- [ ] Per-day infrastructure spend alert and hard provider budget are active.

## Rollout

Public does not mean unbounded. Announce an experimental capacity pool, show queue state honestly, and return a clear capacity response when full. Use a feature flag to close new admission while allowing active leases to expire. Never solve a capacity incident by disabling isolation or expiry.

The current repository provides deployment artifacts but does not provision a DNS name, cloud account, Turnstile account, or monitoring service. Those are operator-owned external resources and are the remaining deployment gate.
