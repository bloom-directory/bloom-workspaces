import type { Request, Response } from "express";
import { getAddress, verifyMessage, type Hex } from "viem";
import { generateSiweNonce, parseSiweMessage } from "viem/siwe";
import { z } from "zod";
import type { Config } from "../config.js";
import type { BloomDatabase } from "../db.js";
import { audit } from "../db.js";
import { createSession } from "./session.js";

const VerifyBody = z.object({ message: z.string().min(1).max(4096), signature: z.string().regex(/^0x[0-9a-fA-F]+$/).max(132) });

export function issueChallenge(db: BloomDatabase, config: Config, ipHash: string) {
  const nonce = generateSiweNonce();
  const issuedAt = new Date();
  const expirationTime = new Date(issuedAt.getTime() + config.challengeTtlMs);
  const url = new URL(config.origin);
  db.prepare("DELETE FROM auth_challenges WHERE expires_at < ? OR consumed_at IS NOT NULL").run(Date.now() - 60_000);
  db.prepare("INSERT INTO auth_challenges (nonce, domain, uri, chain_id, ip_hash, issued_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
    .run(nonce, url.host, url.origin, config.authChainId, ipHash, issuedAt.getTime(), expirationTime.getTime());
  return {
    nonce,
    domain: url.host,
    uri: url.origin,
    chainId: config.authChainId,
    statement: "Sign in to request a Bloom workspace. Workspace processes may request wallet signatures; you will approve each request in your wallet.",
    issuedAt: issuedAt.toISOString(),
    expirationTime: expirationTime.toISOString(),
  };
}

export async function verifyChallenge(request: Request, response: Response, db: BloomDatabase, config: Config, ipHash: string) {
  const { message, signature } = VerifyBody.parse(request.body);
  const parsed = parseSiweMessage(message);
  if (!parsed.nonce || !parsed.address || !parsed.domain || !parsed.uri || !parsed.chainId || parsed.version !== "1") throw new AuthError("Malformed SIWE message");
  const challenge = db.prepare("SELECT domain, uri, chain_id, ip_hash, issued_at, expires_at, consumed_at FROM auth_challenges WHERE nonce = ?")
    .get(parsed.nonce) as { domain: string; uri: string; chain_id: number; ip_hash: string; issued_at: number; expires_at: number; consumed_at: number | null } | undefined;
  if (!challenge || challenge.consumed_at || challenge.expires_at < Date.now()) throw new AuthError("Challenge expired or already used");
  if (challenge.ip_hash !== ipHash) throw new AuthError("Challenge was issued to a different client");
  if (parsed.domain !== challenge.domain || parsed.uri !== challenge.uri || Number(parsed.chainId) !== challenge.chain_id) throw new AuthError("SIWE audience mismatch");
  if (!parsed.issuedAt || Math.abs(new Date(parsed.issuedAt).getTime() - challenge.issued_at) > 30_000) throw new AuthError("SIWE issuance time mismatch");
  if (parsed.expirationTime && new Date(parsed.expirationTime).getTime() < Date.now()) throw new AuthError("SIWE message expired");
  if (parsed.expirationTime && new Date(parsed.expirationTime).getTime() > challenge.expires_at + 30_000) throw new AuthError("SIWE expiry exceeds challenge lifetime");
  if (parsed.notBefore && new Date(parsed.notBefore).getTime() > Date.now() + 30_000) throw new AuthError("SIWE message is not active yet");
  const address = getAddress(parsed.address);
  const valid = await verifyMessage({ address, message, signature: signature as Hex });
  if (!valid) throw new AuthError("Invalid wallet signature");
  const consumed = db.prepare("UPDATE auth_challenges SET consumed_at = ? WHERE nonce = ? AND consumed_at IS NULL").run(Date.now(), parsed.nonce);
  if (Number(consumed.changes) !== 1) throw new AuthError("Challenge was already used");
  const csrfToken = createSession(response, db, config, address, ipHash);
  audit(db, "auth.login", address, undefined, { method: "siwe" });
  return { wallet: address, csrfToken };
}

export class AuthError extends Error {}
