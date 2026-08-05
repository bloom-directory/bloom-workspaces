# Testing

## Automated

`npm run check` covers:

- unsafe public configuration rejection;
- valid constrained public configuration;
- SIWE signature verification, network binding, and replay rejection;
- wallet concurrency, queue fairness, owner stop, and lease expiry;
- live PTY input/output and node-agent termination;
- rooted file transfers, persistent-volume lifecycle, structured jobs, and Bloom status;
- controlled-egress address/SNI/limit enforcement;
- SSH certificate mode separation, revocation, client argv, and NFS capability gates;
- server and browser TypeScript.

`npm run build` produces the static browser bundle and Node ESM server.

## Live VM smoke

Build the pinned image, run either VM backend, use local demo login, and create a workspace:

```bash
ops/bloom/build-musl.sh
sudo ops/images/build-demo-image.sh
npm run dev:vm             # QEMU/KVM
# or: npm run dev:firecracker
npm run smoke:live
```

The smoke command uses the current local session and requires the command response marker to differ from the typed input. This prevents terminal echo from producing a false pass. Run it a second time to exercise reconnect and retained PTY state.

## Adversarial host checks

Before a public deployment, automate these on the target image and kernel:

1. Fork bombs and memory/disk exhaustion remain within systemd/VM limits.
2. Guest reboot, panic, agent kill, and terminal flood do not affect another VM.
3. Expiry kills an idle, busy, and deliberately watchdog-tampered guest.
4. Control-plane kill, node-agent kill, and host reboot converge to honest failed/stopped state.
5. Direct Unix socket access fails for the control-plane and unrelated host users.
6. Origin, CSRF, stale session, replayed SIWE, reused Turnstile, and oversized WebSocket frames fail closed.
7. A guest cannot reach metadata, host, private, or non-allowlisted destinations; controlled mode reaches only reviewed public HTTP/HTTPS package hosts.
8. Queue floods never exceed the configured number of VM processes or provider budget.
9. SSH wrong-wallet, wrong-workspace, wrong-mode, expired/revoked token, host-key mismatch, text WebSocket, and connection-flood paths fail closed.
10. NFS is absent for disposable/Firecracker/unverified-kernel workspaces and is reachable only through the NFS-mode SSH tunnel.

## Client matrix

The browser path should cover current Safari, Chromium, Firefox, MetaMask, Rabby,
and WalletConnect mobile handoff. Linux is the native SSH/NFS reference client.
macOS still requires Intel/Apple Silicon device tests across supported patch
versions, sleep/wake and network changes. Windows requires optional-feature and
NFSv4 probes. Android/iOS intentionally exercise browser fallbacks only.
