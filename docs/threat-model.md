# Threat model

## Trust statement

The tenant does not trust workspace code on their laptop because none runs there. They do trust the Bloom operator and host for the confidentiality and integrity of remote compute. This is isolated hosted compute, not trustless compute.

The operator treats every wallet, browser session, terminal byte, guest filesystem, guest kernel, and guest network packet as hostile.

## Protected assets

- the host, KVM device, control-plane database, and node-agent socket;
- other tenants' VM memory, disks, terminal data, and quotas;
- service availability and the operator's compute budget;
- SIWE sessions and audit integrity;
- any future Bloom approval/signing service outside this repository.

## Enforced boundaries

| Threat | Control |
|---|---|
| Host command execution through the shell | One KVM VM per tenant; process runtime rejected in public mode |
| Cross-tenant files or memory | Separate VM process and cloned fixed-size ext4 image |
| Infinite compute spend | Global capacity, bounded queue, per-wallet/IP quotas, hard lease |
| Wallet/SIWE replay | Random single-use nonce, five-minute expiry, exact domain/URI/chain, network binding |
| CSRF or cross-origin WebSocket | SameSite=Strict HTTP-only cookie, per-session CSRF token, exact Origin checks |
| Session database theft | Only HMAC hashes of opaque session tokens are stored |
| Raw IP retention | HMAC-pseudonymous IPs; rotate the secret to sever historical linkage |
| Control-plane compromise reaching KVM | Separate Unix users and private authenticated agent socket |
| Agent crash leaving paid compute | systemd control-group kill plus startup reconciliation |
| Guest disables its watchdog | Host agent enforces the same deadline independently |
| Guest floods terminal output | 256 KiB history and WebSocket backpressure caps |
| Public Sybil signups | Turnstile, IP plus wallet budgets, queue bound, global hard cap |
| Guest reaches cloud metadata/private services | No guest egress in the initial public profile |
| Secret leakage in snapshots | No automatic snapshots; disks deleted on stop |

## Lines we do not cross

1. The local `embednfs` Bloom server is never exposed to the Internet; it does not implement RPCSEC_GSS.
2. An arbitrary shell never runs in the control-plane process, host namespace, or a production multi-tenant container.
3. A public Firecracker deployment never runs without the jailer.
4. A workspace never receives seed phrases, funded private keys, host Docker/KVM sockets, CA/KDC keys, cloud credentials, metadata access, or Bloom's trusted signing core.
5. SIWE never substitutes for transaction-specific approval.
6. Unauthenticated or retryable filesystem writes never cause financial side effects.
7. A wallet does not buy unlimited compute merely by being cheap to create.
8. We do not call the operator-trusted workspace “trustless.”

## Residual risks

- KVM, QEMU, Firecracker, the host kernel, and CPU are software/hardware attack surfaces. Patch cadence and microcode matter.
- IP controls affect shared networks and do not eliminate Sybil traffic. They are cost controls, not identity proof.
- The demo Alpine image is minimal, not a maintained developer distribution. Rebuild and scan it before launch.
- Root in the guest can deny its own service, destroy its own data, or hide activity from guest-level tooling.
- Browser wallet support currently verifies ordinary EOA signatures. Contract-wallet verification requires a chain RPC and an explicit ERC-1271 path.
- Operator access can observe host-side terminal and disk data. Confidential-computing claims require a different architecture.

## Required review before raising caps

Perform an external host/isolation review, adversarial guest escape exercise, dependency and image scan, incident runbook drill, deletion verification, load/queue test, and cost-abuse simulation. Start with no funds and no production credentials.
