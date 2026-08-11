# Issue: operations & scaling are unbuilt (single-node pilot only)

The architecture is explicitly a capped single-node pilot. Everything needed for
a real deployment is missing.

## Evidence (from `docs/architecture.md`, `docs/public-launch.md`)
- Single-node only. Multi-node needs durable scheduling, node fencing/
  heartbeats, encrypted volume lifecycle, backup/deletion policy, failure-domain
  testing, metrics, abuse response, spend controls.
- Heavy, slow, uncached artifact builds: bloom-musl (~10 min), the Alpine image,
  the NFSD kernel. `docs/finish-plan.md` calls the image rebuild "mandatory."
- bloom binary is ~49 MB; cold-start is slow, especially on small/TCG VMs.
- bloom daemon polls chain RPCs per workspace → per-tenant egress and cost;
  scales poorly.
- The repo provisions no DNS, TLS, Cloudflare, monitoring, abuse staffing, or
  budgets — all operator-owned launch gates.

## Impact
Nowhere near production. Running it for real users is a large ops build, not a
config change.

## Direction
1. If pursuing hosted deployment: scope the multi-node + ops build as its own
   workstream (scheduling, volumes, abuse, spend, monitoring).
2. Cache the artifact builds (CI, registry) so image rebuilds aren't a wall.
3. For per-tenant RPC cost: shared/proxy RPC pooling, or move RPC reads off the
   workspace onto an operator-side cache.
