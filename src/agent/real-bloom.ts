import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { CeremonyRequestView } from "./mock-ceremony.js";

/**
 * Dev-only bridge that runs the REAL bloom CLI against a workspace-local bloom
 * home on the process runtime, so the ceremony relay surfaces bloom-generated
 * transaction plans without KVM. Mirrors what `bloom-guest-bootstrap` + the
 * in-guest ceremony scan do, minus isolation and minus real WebAuthn
 * verification (the approval assertion is still accepted as-is here; real
 * verification is Slice 2). Forbidden in public mode.
 *
 * `home` MUST be a short path: bloom binds its IPC socket at `<home>/run/bloom.sock`
 * and Unix socket paths are capped at SUN_LEN (108). The default deep workspace
 * path exceeds that, so the caller places the home under a short tmp dir.
 */
export type RealBloomOptions = {
  bloomBin: string;
  home: string;
  wallet: string;
};

const WALLET_NAME = "workspace-login";

export class RealBloom {
  readonly home: string;
  private readonly bloomBin: string;
  private readonly wallet: string;

  constructor(opts: RealBloomOptions) {
    this.bloomBin = opts.bloomBin;
    this.home = opts.home;
    this.wallet = opts.wallet;
  }

  async init(): Promise<void> {
    await mkdir(join(this.home, "keystore", WALLET_NAME), { recursive: true });
    await this.runBloom(["init"]);
    const walletDir = join(this.home, "keystore", WALLET_NAME);
    await writeFile(join(walletDir, "address"), `${this.wallet}\n`);
    await writeFile(join(walletDir, "kind"), "watch\n");
    await writeFile(join(walletDir, "pubkey"), "");
  }

  async stage(intent: Record<string, unknown>): Promise<void> {
    await this.runBloom(["wallet", "stage", WALLET_NAME, "base", "--intent", JSON.stringify(intent)]);
  }

  async pending(): Promise<{ requests: CeremonyRequestView[] }> {
    const walletOutbox = join(this.home, "outbox", WALLET_NAME);
    const requests: CeremonyRequestView[] = [];
    let chains: string[] = [];
    try { chains = await readdir(walletOutbox); } catch { return { requests }; }
    for (const chain of chains) {
      const pendingDir = join(walletOutbox, chain, "pending");
      let txIds: string[] = [];
      try { txIds = await readdir(pendingDir); } catch { continue; }
      for (const txId of txIds) {
        const planMd = await this.readPlan(pendingDir, txId);
        if (planMd === undefined) continue;
        requests.push({ id: txId, chain, wallet: this.wallet, planMd, ceremonyUrl: null, challenge: this.challengeFor(txId, planMd) });
      }
    }
    return { requests };
  }

  /** Resolves a pending request by removing its outbox directory. Returns false if not found. */
  async approve(txId: string): Promise<boolean> {
    const walletOutbox = join(this.home, "outbox", WALLET_NAME);
    let chains: string[] = [];
    try { chains = await readdir(walletOutbox); } catch { return false; }
    for (const chain of chains) {
      const dir = join(walletOutbox, chain, "pending", txId);
      try { await rm(dir, { recursive: true }); return true; } catch { /* not in this chain */ }
    }
    return false;
  }

  private async readPlan(pendingDir: string, txId: string): Promise<string | undefined> {
    try { return await readFile(join(pendingDir, txId, "plan.md"), "utf8"); } catch { return undefined; }
  }

  private challengeFor(txId: string, planMd: string): string {
    return createHash("sha256").update(`${txId}:${planMd}`).digest().subarray(0, 32).toString("base64");
  }

  private runBloom(args: string[]): Promise<void> {
    return new Promise((resolve, reject) => {
      const child = spawn(this.bloomBin, ["--home", this.home, "--quiet", ...args], { stdio: ["ignore", "ignore", "pipe"] });
      let stderr = "";
      child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
      const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error(`bloom ${args.join(" ")} timed out`)); }, 90_000);
      child.on("error", (error) => { clearTimeout(timer); reject(error); });
      child.on("exit", (code) => {
        clearTimeout(timer);
        if (code === 0) resolve();
        else reject(new Error(`bloom ${args.join(" ")} exited ${code}: ${stderr.slice(-800)}`));
      });
    });
  }
}
