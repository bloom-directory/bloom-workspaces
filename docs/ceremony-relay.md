# Ceremony relay transport

The Sealed Approval ceremony has two transports from the user's browser to the
in-guest ceremony server. Both reach the *same* guest-side verifier; they differ
only in the channel and in what the operator can observe.

## Transports

- **SSH (device-local, default-trust-minimized).** The user forwards
  `18734:localhost:18734` over the workspace SSH grant and opens the ceremony
  URL in their local browser. The operator's relay carries only opaque TLS
  bytes; it cannot read the WebAuthn challenge or assertion.
- **Relay (browser-native).** The already-authenticated browser session fetches
  the ceremony challenge through the Bloom control plane, performs WebAuthn
  locally, and posts the assertion back through the control plane, which
  forwards it into the guest for verification. No SSH, no install, works on
  mobile.

## Security argument for the relay

The property both transports preserve: **the operator cannot forge the user's
approval of a specific transaction.**

1. The guest generates a single-use `challenge` per pending request, bound to
   that request id and the staged `plan.md`. It returns the challenge through
   `ceremony.pending`.
2. The browser displays `planMd` to the user, then calls
   `navigator.credentials.get({ publicKey: { challenge } })`. The WebAuthn
   assertion is signed by a credential private key that never leaves the user's
   device, over the challenge and the relying-party origin.
3. The browser posts the assertion to
   `POST /api/workspaces/:id/ceremony/:requestId/approve`. The control plane
   forwards it to the guest as `ceremony.approve`, bound to the authenticated
   wallet and workspace.
4. The guest verifies the assertion (signature, origin/relying party, the exact
   challenge it issued for that request, single-use) and finalizes or rejects.

Because the credential private key is device-bound, the operator cannot produce
a valid assertion even though the relay carries challenge and assertion in
plaintext. Because the challenge is single-use and bound to the request id and
plan, a captured assertion cannot be replayed against a different request or a
different plan.

## Trust shift vs. SSH

With SSH, the operator sees only encrypted bytes. With the relay, the operator's
control plane sees the challenge and assertion in transit. This does not let the
operator forge an approval, but it does mean the operator could observe or drop
ceremony traffic — which is already within the operator's trusted position: the
threat model states the tenant trusts the operator for the integrity of remote
compute, and the workspace is never a vault for funded keys. The relay therefore
does not lower the documented trust floor; it trades "operator cannot see
ceremony bytes" for "zero-install, mobile-reachable approval." Users who need the
stronger channel keep the SSH option.

## Request shapes

`GET /api/workspaces/:id/ceremony` returns requests extended with a relay
challenge:

```json
{ "requests": [{ "id": "tx_…", "chain": "…", "wallet": "…", "planMd": "…",
  "ceremonyUrl": "http://localhost:18734/ceremony/…", "challenge": "base64…" }] }
```

`POST /api/workspaces/:id/ceremony/:requestId/approve` body:

```json
{ "assertion": { "credentialId": "base64", "authenticatorData": "base64",
  "clientDataJSON": "base64", "signature": "base64" } }
```

Response: `{ "approved": true }` or a guest error.

## Slice status

- **Slice 1 (this change):** the relay transport end to end — protocol op,
  control-plane + agent endpoints, browser WebAuthn UI, and a mock ceremony on
  the process runtime so the whole loop is exercisable without KVM. The mock
  verifier accepts any well-formed assertion; it does not perform real WebAuthn
  cryptography.
- **Slice 2 (KVM, later):** wire the relay to the real in-guest ceremony server
  so the guest performs full WebAuthn verification against Bloom's approval
  core, and add the ceremony step to `scripts/smoke-live.mjs`.

The relay must never be offered for a capability the guest reports as
unavailable: if `ceremony.pending` returns no challenge for a request, the UI
falls back to the SSH ceremony link and the approve endpoint rejects.
