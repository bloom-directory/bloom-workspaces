# Testing

## Automated

`npm run check` covers:

- unsafe public configuration rejection;
- valid constrained public configuration;
- SIWE signature verification, network binding, and replay rejection;
- wallet concurrency, queue fairness, owner stop, and lease expiry;
- live PTY input/output and node-agent termination;
- server and browser TypeScript.

`npm run build` produces the static browser bundle and Node ESM server.

## Live VM smoke

Build the pinned image, run either VM backend, use local demo login, and create a workspace:

```bash
ops/images/build-demo-image.sh
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
7. A guest cannot reach metadata, host, private networks, SMTP, or DNS when the air-gapped profile is selected.
8. Queue floods never exceed the configured number of VM processes or provider budget.

## Client matrix

The browser path should cover current Safari, Chromium, Firefox, MetaMask, Rabby, and mobile wallet handoff. Native NFS research separately requires real Intel/Apple Silicon macOS Tahoe patch versions, sleep/wake, Wi-Fi changes, hotel/corporate networks, and non-admin mount/unmount behavior.
