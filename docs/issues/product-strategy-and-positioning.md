# Issue: product strategy & positioning — workspace (VM) vs bloom-mcp

The product story has split, and the repo's identity needs a decision.

## Evidence
- `bloom-mcp` (this repo, `ops/bloom-mcp`) now covers the **trusted-agent** case
  (Claude Desktop / ChatGPT driving bloom locally) with zero friction — no
  browser, no server, no API key. Custody is natural (local passkey).
- bloom-workspaces (the VM product) is now justified **only** for *untrusted*
  code (community Petals, someone else's agent) where isolation earns its cost.
- The README still calls the workspace a "public-signup prototype." Whether this
  is a real product, a pilot, or a prototype is undecided.
- Two-credential UX risk: SIWE sign-in (MetaMask) + passkey signing is two
  different credentials — potentially confusing.
- Cross-repo doc coherence: ceremony is described in `docs/ceremony-relay.md`
  (workspaces), bloom's `Open-Internet Sealed Approval Ceremony.md`, and the
  threat model — drift risk. README signing claims already drifted once (fixed).

## Impact
Without a posture decision, effort is split and messaging is muddled. Half the
issues in this folder only matter if the workspace ships as a product.

## Direction
1. Decide: is bloom-workspaces a **prototype**, a **bounded pilot**, or a
   **product**? This sets which issues in `docs/issues/` actually matter.
2. Decide the primary surface for end users: **bloom-mcp (local, zero-friction)**
   as the mass path, with the **workspace (VM)** as the untrusted-code niche /
   Phase-3 hardened backend for MCP. (Current recommendation.)
3. Reconcile docs across repos (ceremony, custody, signing) to a single source
   of truth; add a README cross-reference to bloom-mcp.
4. Revisit the two-credential UX once signing is real (consider SIWE-via-passkey
   to unify).
