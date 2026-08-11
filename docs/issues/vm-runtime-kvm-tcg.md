# Issue: VM runtime — KVM requirement, flaky TCG fallback, host-path coupling

The real product (isolated VMs) is hard to run, develop, and test.

## Evidence
- The VM needs KVM. The dev machine has BIOS SVM disabled (no `/dev/kvm`); most
  cloud VMs need nested virt. There's no KVM locally, so the VM path is
  unvalidated here.
- The `BLOOM_VM_ACCEL=tcg` fallback I added (software emulation, no KVM) is
  **flaky**: the virtio-serial control-channel handshake succeeded ~2 of 6
  attempts. Kernel boots in ~2s; the guest-control handshake is the unreliable
  part. Not a dependable test path.
- bloom's IPC socket path is capped at SUN_LEN (108). The deep workspace path
  exceeds it, so RealBloom places the home under `/tmp/bloom-ws-<id>` with custom
  cleanup on stop — orphans on crash.
- `guest-control` hardcodes `/workspace/.bloom/run/bloom.sock` (`constants.rs`)
  — inflexible; made host-side debugging painful.

## Impact
Can't run or validate the VM product without KVM; the TCG fallback isn't
reliable enough to substitute; host-path limits force workarounds.

## Direction
1. Get a KVM host (BIOS toggle or nested-virt cloud box) to validate the VM path.
2. Either harden TCG (investigate the virtio-serial handshake flakiness) or scope it strictly to boot-smoke, not ceremony.
3. Make the bloom socket path configurable in `guest-control` (env override) instead of hardcoded.
4. Reconsider the `/tmp` bloom-home placement + crash-safe cleanup.
