//! MCP server exposing bloom wallet operations to AI clients.
//!
//! A thin stdio server that drives the `bloom` CLI: an AI assistant (Claude
//! Desktop, ChatGPT, etc.) reads wallet state, stages transactions, and the
//! user signs each one via bloom's local Sealed Approval passkey ceremony.
//! The signing key never leaves the user's machine; the AI cannot sign.

use rmcp::{
    handler::server::wrapper::Parameters, schemars, tool, tool_router, ServiceExt,
    transport::stdio,
};
use serde::Deserialize;
use tokio::process::Command;

#[derive(Clone)]
struct BloomMcp;

/// Which bloom binary to invoke. Defaults to `bloom` on PATH; override with
/// BLOOM_BIN for testing.
fn bloom_bin() -> String {
    std::env::var("BLOOM_BIN").unwrap_or_else(|_| "bloom".to_string())
}

/// Run `bloom --quiet <args>`; return trimmed stdout on success, stderr (or a
/// status error) on failure. `--quiet` keeps daemon/RPC logs off stderr.
async fn run_bloom(args: &[&str]) -> Result<String, String> {
    let output = Command::new(bloom_bin())
        .arg("--quiet")
        .args(args)
        .output()
        .await
        .map_err(|e| format!("failed to spawn bloom: {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if output.status.success() {
        Ok(stdout)
    } else if stderr.is_empty() {
        Err(format!("bloom {} failed: exit {:?}", args.join(" "), output.status.code()))
    } else {
        Err(stderr)
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct WalletChainArgs {
    /// Wallet name (see wallet_list).
    wallet: String,
    /// Chain name: base, ethereum, arbitrum, optimism, polygon, ...
    chain: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct StageArgs {
    /// Wallet name.
    wallet: String,
    /// Chain name.
    chain: String,
    /// Transaction intent as JSON or TOML, e.g. {"to":"0x...","value":"1000000"} (value in wei).
    intent: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ConfirmArgs {
    /// Wallet name.
    wallet: String,
    /// Chain name.
    chain: String,
    /// Staged transaction id returned by tx_stage.
    id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct VfsReadArgs {
    /// bloom VFS path, e.g. /wallets/<wallet>/chains/<chain>/balance or /wallets/<wallet>/policy.toml.
    path: String,
}

#[tool_router(server_handler)]
impl BloomMcp {
    #[tool(description = "List bloom wallets in the user's bloom home.")]
    async fn wallet_list(&self) -> String {
        run_bloom(&["wallet", "list"]).await.unwrap_or_else(|e| format!("error: {e}"))
    }

    #[tool(description = "Read a wallet's native balance and nonce on a chain (live read against the chain RPC). Values in wei / units.")]
    async fn wallet_balance(&self, Parameters(args): Parameters<WalletChainArgs>) -> String {
        let base = format!("/wallets/{}/chains/{}/", args.wallet, args.chain);
        let balance = run_bloom(&["vfs", "cat", &format!("{base}balance")]).await;
        let nonce = run_bloom(&["vfs", "cat", &format!("{base}nonce")]).await;
        format!("balance: {}\nnonce: {}", balance.unwrap_or_else(|e| e), nonce.unwrap_or_else(|e| e))
    }

    #[tool(description = "Stage a transaction for later signing. Returns the staged tx id. Does NOT sign or broadcast. The user must run tx_confirm (which triggers their passkey ceremony) to sign.")]
    async fn tx_stage(&self, Parameters(args): Parameters<StageArgs>) -> String {
        match run_bloom(&["wallet", "stage", &args.wallet, &args.chain, "--intent", &args.intent]).await {
            Ok(id) => format!("staged: {id}"),
            Err(e) => format!("error: {e}"),
        }
    }

    #[tool(description = "List pending (staged, not yet signed) transactions for a wallet/chain. Returns tx ids and their plan.md.")]
    async fn tx_pending(&self, Parameters(args): Parameters<WalletChainArgs>) -> String {
        let path = format!("/wallets/{}/chains/{}/outbox/pending", args.wallet, args.chain);
        run_bloom(&["vfs", "ls", &path]).await.unwrap_or_else(|e| format!("error: {e}"))
    }

    #[tool(description = "Confirm (sign + broadcast) a staged transaction. For passkey wallets this opens the local Sealed Approval ceremony in the user's browser; the user must approve with their passkey. Blocks until the user approves or declines. Returns the result (incl. tx hash on success).")]
    async fn tx_confirm(&self, Parameters(args): Parameters<ConfirmArgs>) -> String {
        run_bloom(&["wallet", "confirm", &args.wallet, &args.chain, &args.id])
            .await
            .unwrap_or_else(|e| format!("error: {e}"))
    }

    #[tool(description = "Read-only access to any bloom VFS path (escape hatch for anything not covered above). e.g. /wallets/<w>/chains/<c>/balance.json, /wallets/<w>/policy.toml, /docs/README.md")]
    async fn vfs_read(&self, Parameters(args): Parameters<VfsReadArgs>) -> String {
        run_bloom(&["vfs", "cat", &args.path]).await.unwrap_or_else(|e| format!("error: {e}"))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--http") {
        #[cfg(feature = "http")]
        {
            return serve_http(args).await;
        }
        #[cfg(not(feature = "http"))]
        {
            anyhow::bail!("HTTP mode requires building with --features http");
        }
    }
    let service = BloomMcp.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

/// Streamable-HTTP server mode for remote/server deployment. Reads + staging
/// work against a server-side bloom home; signing still needs the user to reach
/// the ceremony (SSH tunnel today, bloom's open-internet relay later).
#[cfg(feature = "http")]
async fn serve_http(args: Vec<String>) -> anyhow::Result<()> {
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    };
    let bind = args
        .iter()
        .position(|a| a == "--bind")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "127.0.0.1:8000".to_string());
    let service = StreamableHttpService::new(
        || Ok(BloomMcp),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default(),
    );
    let router = axum::Router::new().nest_service("/mcp", service);
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    eprintln!("bloom-mcp streamable-http listening on {bind} at /mcp");
    axum::serve(listener, router).await?;
    Ok(())
}
