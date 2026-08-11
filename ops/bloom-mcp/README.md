# bloom-mcp

An MCP (Model Context Protocol) server that exposes bloom wallet operations to
AI clients — Claude Desktop, ChatGPT, Cursor, VS Code, anything that speaks MCP.

The AI reads wallet state and stages transactions; the user signs each one via
bloom's local Sealed Approval passkey ceremony. The signing key never leaves the
user's machine — the AI can stage but cannot sign.

## How it works

`bloom-mcp` is a stdio server that drives the `bloom` CLI. It is a thin wrapper:
each tool spawns the corresponding `bloom` subcommand. It depends on nothing from
bloom except the `bloom` binary being on PATH (override with `BLOOM_BIN`).

## Build

```sh
cargo build --release                              # stdio (local) binary
cargo build --release --features http              # adds the streamable-HTTP server mode
```

## Modes

`bloom-mcp` has two transports:

- **stdio (default)** — Claude Desktop spawns it locally. `bloom-mcp`.
- **HTTP (`--features http`)** — run as a remote MCP server for server deployment:
  ```sh
  bloom-mcp --http --bind 0.0.0.0:8080     # serves MCP at http://host:8080/mcp
  ```

## Add to Claude Desktop (local)

Ensure `bloom` is installed and on PATH (and you've created a wallet with
`bloom wallet new`), then:

```sh
claude mcp add bloom -- /absolute/path/to/bloom-mcp
```

Restart Claude Desktop. Your AI can now read your wallet and stage transactions;
confirming one opens the passkey ceremony in your browser.

For other MCP clients (Cursor, VS Code) use the same binary as a stdio command.

## Server deployment (reads + staging; signing is limited)

You can run bloom-mcp on a server with `--http` and point Claude Desktop at it as
a remote MCP server. Reads (`wallet_balance`, `wallet_list`, `vfs_read`) and
staging (`tx_stage`, `tx_pending`) work against the server's bloom home.

**Signing (`tx_confirm`) does not work natively from a server**, because bloom's
Sealed Approval ceremony binds to `localhost:18734` and the WebAuthn RP ID
`"localhost"` — a user's browser can't reach the server's loopback ceremony, and
the key shouldn't live on the server anyway. Two options:

- **Today (power-user):** SSH-tunnel the ceremony to your machine and approve
  locally — `ssh -L 18734:localhost:18734 user@server`, then call `tx_confirm`;
  bloom opens the ceremony on your laptop at `http://localhost:18734/...`, your
  passkey works (same RP ID), and the server's bloom signs.
- **Later (clean):** bloom's documented open-internet relay
  (`docs/architecture/Open-Internet Sealed Approval Ceremony.md`, not yet
  implemented) would let the ceremony be re-hosted at a public URL so no tunnel
  is needed.

For custody-safe hosted bloom, this is the same problem bloom-workspaces solves
with its custody relay/handoff — the two converge here.

## Tools

| Tool | What it does |
|---|---|
| `wallet_list` | List wallets in the bloom home. |
| `wallet_balance` | Live native balance + nonce for a wallet/chain. |
| `tx_stage` | Stage a transaction (returns the staged id). Does NOT sign. |
| `tx_pending` | List pending staged transactions for a wallet/chain. |
| `tx_confirm` | Sign + broadcast a staged tx (opens the local passkey ceremony; user must approve). |
| `vfs_read` | Read-only escape hatch for any bloom VFS path. |

All state-changing operations go through bloom's normal model: staging writes an
intent to the outbox; signing is gated by Sealed Approval + `policy.toml`. The
MCP server adds no new authority surface.

## Environment

- `BLOOM_BIN` — bloom binary path (default: `bloom` on PATH).
- `BLOOM_HOME` — bloom home (default: the user's `~/.bloom`), inherited by the
  bloom subprocess.

## Status

MVP. Both transports work: stdio (local) and streamable-HTTP (`--features http`,
server-deployable). Reads, stage, and pending are live-verified over both
transports against a real bloom home. `tx_confirm` is wired; locally it triggers
bloom's interactive browser ceremony (full live verification needs a registered
passkey), and over a server it requires the SSH-tunnel workaround above until
bloom ships its open-internet relay.
