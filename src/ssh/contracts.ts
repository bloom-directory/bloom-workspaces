import { createHash } from "node:crypto";

export const MAX_SSH_LEASE_MS = 2 * 60 * 60_000;
export const DEFAULT_SSH_LEASE_MS = 15 * 60_000;

const WORKSPACE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const WALLET = /^0x[0-9a-f]{40}$/i;

export type SshAccessMode = "shell" | "nfs";

export type PrivateSshEndpoint =
  | { kind: "unix"; path: string }
  | { kind: "tcp"; host: "127.0.0.1" | "::1"; port: number };

export function normalizeWorkspaceId(value: string) {
  if (!WORKSPACE_ID.test(value)) throw new Error("Invalid workspace id");
  return value.toLowerCase();
}

export function normalizeWallet(value: string) {
  if (!WALLET.test(value)) throw new Error("Invalid wallet address");
  return value.toLowerCase();
}

export function normalizeAccessMode(value: string): SshAccessMode {
  if (value !== "shell" && value !== "nfs") throw new Error("Invalid SSH access mode");
  return value;
}

/**
 * OpenSSH principals are deliberately opaque and deterministic. The wallet
 * digest prevents one wallet's certificate from authorizing another wallet's
 * workspace lease without publishing the wallet address in guest files.
 */
export function workspacePrincipal(workspaceId: string, wallet: string, mode: SshAccessMode) {
  const id = normalizeWorkspaceId(workspaceId);
  const owner = normalizeWallet(wallet);
  const accessMode = normalizeAccessMode(mode);
  const ownerDigest = createHash("sha256").update(owner).digest("hex").slice(0, 32);
  return `bloom-${accessMode}-${id}-w-${ownerDigest}`;
}

export function assertPort(value: number, label = "port") {
  if (!Number.isSafeInteger(value) || value < 1 || value > 65_535) throw new Error(`Invalid ${label}`);
  return value;
}
