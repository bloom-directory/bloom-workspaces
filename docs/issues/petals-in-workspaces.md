# Issue: Petals in a watch-only workspace — state and signing blockers

Petals (bloom wasm apps) are the natural "agent" unit, but their state and
signing model clash with the workspace's custody/isolation design.

## Evidence (bloom source)
- Petal state lives in the bloom home at `~/.bloom/petals/{store,data}`
  (`bloom-petals/src/store.rs:79-80`). In a **disposable** workspace it's lost on
  stop; in a **persistent** one it survives, scoped to the wallet.
- Petal signing requires a live `SealedApprovalGrant` minted by a ceremony and
  held in an in-memory `SignerCache` (`bloom-keystore/src/petal_host.rs:41-50`).
  Grants are `!Serialize` → **lost on every workspace/daemon restart**.
- `sign_hash` is policy-gated (`"component sign_hash denied by sign intent policy"`,
  `bloom-petals/src/vm.rs:1371`).
- A watch-only workspace can't mint a grant at all without reaching the user
  (the custody-relay/SSH problem).

## Impact
Long-running petal workflows that sign repeatedly are blocked: state evaporates
in disposable mode, and every restart forces a fresh ceremony. A petal that
expects to sign directly fails in a watch-only workspace.

## Direction
1. Trace one real petal's full lifecycle (install → persist state → sign → restart) in a workspace to convert these from inferred to concrete.
2. Decide the persistence default for petal workspaces (likely persistent).
3. Define the "refresh grant each session" UX, or push bloom for a longer-lived signing session.
4. Document which petal capabilities are/aren't available in a watch-only workspace.
