# Issue: ceremony signing is unvalidated end-to-end

The single most important product behavior — an agent stages a tx, the user
approves, bloom signs — has **never run once**, in a VM or against bloom's real
ceremony server.

## Evidence
- Slice 1 built a relay transport; its `ceremony.approve` op **mock-verifies**
  (accepts any assertion). `docs/ceremony-relay.md` says so.
- `scripts/smoke-live.mjs` asserts `walletSigning === false` and never exercises
  real signing.
- bloom's ceremony is WebAuthn-PRF: the relay must proxy bloom's 3 ceremony
  endpoints and carry the **PRF output** (which decrypts the wallet key), not
  verify itself. The current relay shape is wrong for real signing.
- `SealedApprovalGrant` is `!Serialize` + in-memory only (bloom side) → any
  workspace/daemon restart loses in-flight signing sessions.

## Impact
The product's defining feature is unproven. Any signing-related claim (in the
README, in demos) is currently aspirational.

## Direction
1. Validate the ceremony on a KVM host against bloom's real ceremony server.
2. Rework the relay to proxy bloom's `/ceremony/{token}/{plan.json,challenge,complete}` carrying the assertion + PRF output, instead of mock-verifying.
3. Add a real ceremony step to `smoke-live.mjs`.
4. Decide the grant-loss story for restarts (re-ceremony? session resume?).
