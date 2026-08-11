# bloom via MCP — plan

Let users drive bloom from AI clients they already have (Claude Desktop, ChatGPT,
Cursor, VS Code) with zero friction: no browser tab, no API key, no account, no
per-use payment. bloom and the signing key never leave the user's machine.

This plan supersedes the ceremony-relay/handoff path in bloom-workspaces for the
**trusted-agent** use case. bloom-workspaces remains the product for *untrusted*
code (community Petals, someone else's agent) where the VM's isolation is justified.

## The loop

```
Claude Desktop ─stdio─> bloom mcp serve ─> bloom-daemon (in-process or via IPC)
                                            │
                                keystore · chains · tx_engine · outbox
                                            │
                               Sealed Approval (local passkey ceremony)
                                            │
                                  user taps passkey → signed
```

The AI reads wallet state, stages transactions, and the user approves each one
with a passkey. Signing is gated by bloom's Sealed Approval — the AI can read
freely, stage freely, but **cannot sign** without the user.

## Settled decisions (investigated against the bloom source)

1. **MCP SDK: `rmcp`.** The official Rust SDK (modelcontextprotocol/rust-sdk),
   v3.1.2, with `server` + `transport-io` + `macros` + `schemars` features.
   Provides `#[tool]` declarations, stdio transport, and JSON-schema generation.

2. **In-process, with IPC fallback (mirror the CLI).** `bloom-daemon` is a clean
   library (`pub struct Daemon`). The MCP server constructs it in-process. If a
   `bloom serve` is already running on the same home (the `HomeWritePermit` file
   lock is held), fall back to `bloom-daemon::ipc::IpcClient` (also `pub`) —
   exactly the CLI's try-IPC-then-in-process pattern. No user-facing coexistence
   sharp edges.

3. **Tool granularity: high-level tools + a `vfs.read` escape hatch.** Semantic
   tools (`wallet.balance`, `tx.stage`, `tx.confirm`) make the AI behave better
   and are easy to audit. `vfs.read(path)` covers anything unanticipated. Writes
   stay high-level (stage/confirm) — no generic `vfs.write` that could bypass the
   staging/outbox model.

4. **Where it lives: new `bloom-mcp` crate + `bloom mcp serve` subcommand** in the
   bloom workspace. `bloom-mcp` is a library crate (depends on `bloom-daemon`,
   `bloom-tx`, `rmcp`); the bloom binary gains `Cmd::Mcp` that dispatches to it.

## In-process API surface (verified — thin wrappers, no orchestration rewrite)

`Daemon` is a data struct with public fields; every wallet operation is a direct
`pub` method call on those fields. The wallet VFS handler is a thin path-router
over the same methods — the MCP server bypasses it.

| Operation | Tool → call (all `pub`) |
|---|---|
| List wallets | `wallet.list` → `d.keystore.list()` |
| Balance / tokens | `wallet.balance` → `keystore.info_unverified(w)` → `chains.get(c)` → `client.balance(addr)` / `erc20_balance(...)` |
| Stage tx | `tx.stage` → `intent_parser::parse()` → `d.tx_engine.stage(...)` |
| List pending | `tx.pending` → `d.tx_engine.outbox.list(w, c, OutboxState::Pending)` (+ `outbox.read` per id) |
| Confirm / sign | `tx.confirm` → `d.tx_engine.confirm(...)`; on `ApprovalRequired`, run the passkey ceremony (below), retry |

**Ceremony (the one non-trivial bit):** the passkey `confirm` sub-case needs ~30
lines of glue copied from the CLI's `sign_outbox_sealed_approval_if_challenged`
(`main.rs:3051`). Its only non-trivial callee,
`bloom_daemon::sealed_ceremony::run_sealed_approval_ceremony`, is already `pub`.
It opens the user's browser to the localhost ceremony URL; the user taps their
passkey; bloom signs. Works in-process.

## Custody and safety (fall out for free)

- The signing key is in `bloom-daemon`, encrypted under a WebAuthn PRF output.
  The AI never sees it; the ceremony decrypts it transiently in daemon memory.
- The AI can stage any tx but cannot sign — Sealed Approval + `policy.toml`
  enforce the user-in-the-loop. The MCP server adds no new authority surface.
- Optional `--read-only` mode for users who want Claude to look but never propose.

## Distribution (zero-friction)

```
claude mcp add bloom -- bloom mcp serve
```

One line. Works in any MCP-stdio client. No login, API key, or billing. The user
creates a bloom wallet once (`bloom wallet new`, passkey ceremony) and funds it.

## Phase 1 — MVP loop (the proof)

The deliverable: in Claude Desktop, "what's my Base balance? propose sending
0.001 ETH to 0x1111…" → the AI reads, stages, calls confirm → the user's browser
opens the passkey ceremony → user taps → signed.

Task list:

1. **Scaffold `crates/bloom-mcp`** in the bloom workspace. `Cargo.toml` deps:
   `bloom-daemon` (no `mount` feature), `bloom-tx`, `bloom-keystore`, `bloom-evm`,
   `rmcp` (`server`, `transport-io`, `macros`, `schemars`), `tokio`, `serde`,
   `serde_json`, `anyhow`, `tracing`.
2. **Acquire the daemon.** `bloom_mcp::serve()` first tries `IpcClient` against
   the home socket; if absent, `HomeWritePermit::acquire(&home)` +
   `Daemon::from_home_with_permit`. Hold the handle for the server's lifetime.
   Call `d.spawn_background_tasks()` for the outbox-expiry sweeper.
3. **Define the tools** with `#[tool]` on a `BloomMcp` handler struct:
   - `wallet_list` → `Vec<WalletInfo>`
   - `wallet_balance(wallet, chain)` → balance + nonce
   - `wallet_tokens(wallet, chain)` → ERC-20 balances
   - `tx_stage(wallet, chain, intent_text)` → staged id (accepts the same TOML/JSON
     the CLI does via `intent_parser::parse`)
   - `tx_pending(wallet, chain)` → `Vec<{id, plan_md, intent_hash}>`
   - `tx_confirm(wallet, chain, id)` → runs confirm; on `ApprovalRequired`, runs
     the in-process ceremony helper, retries confirm → `{signed, tx_hash?}`
   - `vfs_read(path)` → read-only VFS read (escape hatch)
4. **Copy the ceremony helper** (~30 lines from `main.rs:3051`) into `bloom-mcp`
   as `pub(crate) async fn confirm_with_ceremony(&d, wallet, chain, id)`. It
   delegates to `bloom_daemon::sealed_ceremony::run_sealed_approval_ceremony`.
5. **Add `Cmd::Mcp`** to `crates/bloom/src/main.rs` (clap subcommand) dispatching
   to `bloom_mcp::serve().await`. Subcommand: `bloom mcp serve`.
6. **Serve over rmcp stdio**: `serve_server(BloomMcp::new(d), rmcp::transport::io::stdio()).await`.
7. **Tests.** Unit: tool → daemon-method mapping against a fake daemon.
   Integration: real in-process daemon (disposable home, anvil chain) + an rmcp
   client driving each tool end-to-end, including the ceremony path with a test
   credential.
8. **Distribution doc.** Add to bloom's README/QUICKSTART: the `claude mcp add`
   one-liner + the one-time `bloom wallet new` setup.

Definition of done: the eight tools work through a real MCP client; staging +
confirming a tx on anvil (local testnet) completes via the local passkey
ceremony; existing bloom tests still pass.

## Phase 2 — richness + safety

Tokens/positions/history reads; `policy.toml` surfaced to the AI (spending caps,
allowlists); `--read-only` toggle; ceremony UX polish from inside the chat; richer
error/review surfaces; `tx.cancel`, `tx.replace`, `wallet.portfolio`.

## Phase 3 — reach

ChatGPT connectors (remote/streamable-HTTP MCP), Cursor/VS Code, and an optional
**remote-workspace mode** — this is where bloom-workspaces finally plugs in, as an
opt-in hardened/isolated backend for users who want hosted bloom or to run
untrusted agents. The workspace is *not* in the default MCP path.

## bloom-workspaces' role (unchanged by this plan)

Out of the default MCP path. Remains the separate product for *untrusted* code
where the VM earns its cost. The custody-handoff work already landed in
bloom-workspaces stays valid for that niche and as the Phase-3 hardened backend.

## Open during implementation (non-blocking)

- `schemars::JsonSchema` derives on the bloom types used as tool args/results
  (or wrap them in MCP-specific types).
- Startup warmup (chain RPC probing) — pre-warm or accept ~1s first call.
- Empty-wallet UX (guide users to `bloom wallet new`).
- Build with `mount` feature off (the MCP server does not mount `/bloom`).
