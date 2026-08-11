# Bloom Workspaces finish plan

> **STATUS (2026-08-11): STALE.** This was the resume checkpoint from the
> pre-ceremony-rewrite era (paused 2026-08-05). Many "must rerun" items here
> predate the Sealed Approval ceremony, the custody-handoff work, and bloom-mcp.
> Treat as historical context only; the current state lives in the README,
> `docs/ceremony-relay.md`, `docs/mcp-plan.md`, and `docs/issues/`.

This is the durable resume checkpoint for the capability-expansion work paused
on 2026-08-05. Do not discard or reset the current worktree: the implementation
is intentionally uncommitted and includes all product slices described below.

## Outcome already implemented

- Controlled HTTP/HTTPS package egress with hostname policy, public-IP
  validation, connection/byte/time limits, pinned upstream addresses, and
  fail-closed TLS SNI inspection.
- A reproducible Alpine development image containing Git, Bash, curl, CA roots,
  Node/npm, Python/pip, C/C++ tools, Nano, Neovim, tmux, OpenSSH, NFS utilities,
  the bounded guest-control service, and a verified static-musl Bloom CLI.
- Authenticated file list/upload/download/delete APIs rooted under `/workspace`.
- Wallet-owned 128 MiB persistent ext4 volumes that survive workspace IDs and
  can be explicitly destroyed; disposable storage remains the default.
- Structured argv jobs with rooted working directories, environment allowlists,
  uid/gid 1000, cleared capabilities, resource/log/concurrency limits,
  cancellation, timeouts, retained status, and SSE progress.
- A watch-only `/bloom` surface and guest helper. No wallet signer, private key,
  WalletConnect session, or transaction authority enters the guest.
- Injected-wallet and optional WalletConnect/Reown SIWE authentication using the
  same challenge/session path, with a safe unconfigured fallback.
- Short-lived wallet/workspace/mode-scoped SSH certificates, a private QEMU
  host-forward, authenticated WebSocket relay, revocation, host-key pinning, and
  separate forced shell/NFS certificate policies.
- NFSv4 on guest loopback only, tunneled through the SSH grant, with `all_squash`
  to uid/gid 1000, v2/v3 disabled, pNFS layouts disabled, persistent-volume-only
  eligibility, and explicit platform capability/fallback responses.
- A responsive browser UI for storage, files, jobs/logs, Bloom state, SSH/NFS
  grants, capabilities, and mobile fallbacks.
- Operator, architecture, threat-model, testing, public-launch, image, Bloom,
  SSH, and NFS documentation.

## Last verified evidence

- `npm run check`: 22 test files and 140 tests passed before the final two QEMU
  boot fixes below.
- Unconfigured and WalletConnect-configured production web builds passed.
- `npm audit --audit-level=high`: zero vulnerabilities.
- All three systemd units passed `systemd-analyze verify`.
- Shell, Node, Python, TypeScript, guest-init, Bloom-musl, SSH, NFS, egress,
  filesystem, persistence, job, authentication, and UI contract checks passed.
- The pinned Debian bookworm/GCC 12 NFS kernel built successfully. Its manifest
  verifies, the config gate passes, and `readelf` shows the Xen PVH note type
  `0x12` required by QEMU direct kernel boot.
- A direct KVM/QEMU boot reached the unprivileged `workspace` shell with the
  custom kernel, rebuilt curated image, and watch-only Bloom bootstrap.

These checks must be rerun because the final QEMU transport fixes were made
after the last full suite.

## Exact pause point

Live QEMU testing found and fixed three integration assumptions:

1. The first NFS kernel was built with Arch/GCC 16 and lacked QEMU's Xen PVH
   note. The builder now uses pinned Debian bookworm/GCC 12, verifies note type
   `0x12`, and publishes checksums plus build-environment provenance. The rebuilt
   artifact passed this gate.
2. QEMU placed `control.sock` below the long workspace data path, which can
   exceed Unix socket path limits. `QemuRuntime` now uses
   `BLOOM_RUNTIME_SOCKET_DIR` for its control socket and removes that runtime
   directory during cleanup.
3. `/dev/vsock` exists when the kernel supports vsock even if QEMU has no vsock
   device. Runtime selection is now explicit: QEMU passes
   `bloom_transport=qemu`; Firecracker passes `bloom_transport=vsock`.

The direct boot after item 3 showed one remaining minimal-image issue: devtmpfs
creates `/dev/vport0p1`, but without udev it does not create
`/dev/virtio-ports/org.bloom.control`. `bloom-init` now resolves the exact port
name through `/sys/class/virtio-ports/<port>/name` and opens the corresponding
character device. `ops/images/test-guest-init.sh` passes with this change.

The image rebuild containing that final sysfs resolution was intentionally
interrupted when compute was closed. Treat the current image artifact as stale
or possibly partial until it is rebuilt and its provenance is verified.

## Resume in this order

1. Inspect, preserve, and orient:

   ```sh
   cd /home/user/code/bloom/bloom-workspaces
   git status --short
   bash ops/images/test-guest-init.sh
   ```

2. Rebuild the curated image from source; do not patch the ext4 artifact by
   hand:

   ```sh
   ops/images/build-demo-image-container.sh
   sha256sum artifacts/bloom-alpine.ext4
   sed -n '1,220p' artifacts/bloom-alpine.provenance.txt
   ```

   Confirm provenance contains the new image digest and use `debugfs` read-only
   inspection to confirm `/usr/local/sbin/bloom-init` contains both the explicit
   transport parsing and `org.bloom.control` sysfs lookup.

3. Reverify the custom NFS kernel:

   ```sh
   cd artifacts/nfs-kernel
   sha256sum -c SHA256SUMS
   readelf -n vmlinux-6.1.155-nfsd | rg 'Xen|0x00000012'
   cd ../..
   ```

4. Run the full static/automated gate before another VM:

   ```sh
   npm run check
   npm run build
   VITE_REOWN_PROJECT_ID=test-project npm run build
   npm audit --audit-level=high
   bash -n ops/images/build-demo-image.sh
   bash -n ops/images/build-demo-image-container.sh
   bash -n ops/connections/build-nfs-kernel.sh
   bash -n ops/connections/build-nfs-kernel-container.sh
   bash ops/images/test-guest-init.sh
   ```

   Also rerun the documented Python/Node syntax checks and
   `systemd-analyze verify` commands from `docs/testing.md`.

5. Start a fresh QEMU reference deployment using short paths under a new
   `mktemp -d` directory for the database, agent socket, runtime sockets, SSH CA,
   and cookie jar. Set:

   - `BLOOM_RUNTIME=qemu`
   - `BLOOM_VM_EGRESS=controlled`
   - `BLOOM_PERSISTENCE_ENABLED=1`
   - `BLOOM_SSH_ENABLED=1`
   - `BLOOM_NFS_ENABLED=1`
   - `BLOOM_VM_KERNEL=artifacts/nfs-kernel/vmlinux-6.1.155-nfsd`
   - `BLOOM_NFS_KERNEL_CONFIG=artifacts/nfs-kernel/vmlinux-6.1.155-nfsd.config`
   - `BLOOM_VM_ROOTFS=artifacts/bloom-alpine.ext4`

   Use development auth only on loopback. Never enable it in public mode.

6. Create a persistent workspace and require it to reach `running`. If it does
   not, capture the QEMU serial tail before cleanup and record the exact agent
   error. Then run `scripts/smoke-live.mjs` and independently verify:

   - authenticated file upload/list/download/delete;
   - a successful structured Node/Python job with streamed logs;
   - timeout and cancellation behavior;
   - `bloom` watch identity and VFS access with no signing material;
   - allowed HTTPS access to an approved package registry;
   - rejection of an unapproved host and cloud-metadata/private addresses;
   - a small package installation inside `/workspace`.

7. Prove durability, not merely attachment:

   - write a unique marker through the file API;
   - stop the workspace;
   - create a new persistent workspace for the same wallet;
   - download and compare the marker;
   - stop it, explicitly destroy the volume, and confirm later recreation does
     not contain the marker.

8. Exercise the SSH path end to end with a temporary Ed25519 client key:

   - issue a shell grant through the authenticated API;
   - connect through the WebSocket proxy and pinned guest host key;
   - verify the forced unprivileged shell lands in `/workspace`;
   - verify forwarding, root login, arbitrary remote commands, expired grants,
     revoked grants, wrong-wallet grants, and wrong-mode grants fail.

   For a loopback HTTP development origin, use a test-only local WebSocket
   bridge or local trusted TLS terminator. Do not weaken the shipped helper's
   production HTTPS/WSS requirement.

9. Exercise NFS on a Linux reference client:

   - issue an NFS-mode certificate;
   - establish only the authorized loopback port forward;
   - mount NFSv4 inside an ephemeral privileged test container if host mount
     privileges are unavailable;
   - create/read/delete a marker and confirm uid/gid squashing to 1000;
   - revoke the lease and confirm the tunnel closes;
   - unmount before stopping the workspace.

10. Reconcile docs and capability claims against the live evidence. Keep these
    platform qualifications explicit:

    - the browser/file/job UI is the universal desktop and mobile path;
    - WalletConnect requires an operator project ID and real-device validation;
    - SSH is first-class on Linux/macOS, conditional on Windows OpenSSH/client
      setup, and a browser fallback on Android/iOS;
    - native NFS is Linux-reference, device/admin-gated on macOS and Windows,
      and not promised on Android/iOS.

11. Run `git diff --check`, inspect every untracked file, update this checkpoint
    with final evidence, and only then mark runtime hardening and product finish
    complete. Commit or push only if separately requested.

## Boundaries that must not change

- Never provide unrestricted guest Internet in public mode.
- Never expose the host Docker socket, `/dev/kvm`, control-plane secrets, SSH CA
  private key, funded wallet keys, WalletConnect session, or cloud metadata to a
  guest.
- Never accept shell command strings for jobs; keep structured argv execution.
- Never let file/cwd/symlink resolution escape `/workspace`.
- Never expose NFS directly to the public network; tunnel it through a scoped,
  revocable grant.
- Never claim Firecracker parity for persistence, SSH, or NFS unless that path
  is implemented and live-tested; capability reporting must remain honest.
- Never make native mounting the only workflow. Browser transfer remains the
  safe cross-platform fallback.

## Compute shutdown state

At pause time there was no Bloom development server, QEMU guest, guest-control
process, or image-builder container running. The only active Docker containers
were unrelated pre-existing Matrix services and were intentionally left alone.
