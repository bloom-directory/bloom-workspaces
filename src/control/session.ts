import type { Request, Response } from "express";
import type { Config } from "../config.js";
import type { BloomDatabase } from "../db.js";
import { opaqueToken, parseCookies, tokenHash } from "../security.js";

export type Session = { tokenHash: string; wallet: string; csrfToken: string; ipHash: string; expiresAt: number };

export function readSession(request: Request, db: BloomDatabase, config: Config): Session | undefined {
  const token = parseCookies(request.headers.cookie).get("bloom_session");
  if (!token) return undefined;
  const row = db.prepare("SELECT token_hash, wallet, csrf_token, ip_hash, expires_at FROM sessions WHERE token_hash = ? AND expires_at > ?")
    .get(tokenHash(token, config.sessionSecret), Date.now()) as { token_hash: string; wallet: string; csrf_token: string; ip_hash: string; expires_at: number } | undefined;
  return row ? { tokenHash: row.token_hash, wallet: row.wallet, csrfToken: row.csrf_token, ipHash: row.ip_hash, expiresAt: row.expires_at } : undefined;
}

export function createSession(response: Response, db: BloomDatabase, config: Config, wallet: string, ipHash: string) {
  const token = opaqueToken();
  const csrfToken = opaqueToken(24);
  const now = Date.now();
  db.prepare("INSERT INTO sessions (token_hash, wallet, csrf_token, ip_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)")
    .run(tokenHash(token, config.sessionSecret), wallet.toLowerCase(), csrfToken, ipHash, now, now + config.sessionTtlMs);
  response.cookie("bloom_session", token, {
    httpOnly: true,
    secure: config.origin.startsWith("https://"),
    sameSite: "strict",
    path: "/",
    maxAge: config.sessionTtlMs,
  });
  return csrfToken;
}

export function clearSession(request: Request, response: Response, db: BloomDatabase, config: Config) {
  const token = parseCookies(request.headers.cookie).get("bloom_session");
  if (token) db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(tokenHash(token, config.sessionSecret));
  response.clearCookie("bloom_session", { httpOnly: true, secure: config.origin.startsWith("https://"), sameSite: "strict", path: "/" });
}
