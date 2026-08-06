import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";
import type { IncomingMessage } from "node:http";

export function opaqueToken(bytes = 32) {
  return randomBytes(bytes).toString("base64url");
}

export function tokenHash(token: string, secret: string) {
  return createHmac("sha256", secret).update(token).digest("hex");
}

export function stableHash(value: string, secret: string) {
  return createHmac("sha256", secret).update(value).digest("hex");
}

export function safeEqual(left: string, right: string) {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

export function parseCookies(header: string | undefined) {
  const cookies = new Map<string, string>();
  for (const item of header?.split(";") ?? []) {
    const index = item.indexOf("=");
    if (index < 1) continue;
    try { cookies.set(item.slice(0, index).trim(), decodeURIComponent(item.slice(index + 1).trim())); }
    catch { /* Ignore malformed cookie values instead of failing the request. */ }
  }
  return cookies;
}

export function clientIp(request: IncomingMessage, trustedProxyHops: number) {
  const direct = normalizeIp(request.socket.remoteAddress ?? "");
  if (trustedProxyHops === 0) return direct;
  const forwarded = request.headers["x-forwarded-for"];
  if (typeof forwarded !== "string") throw new Error("Missing X-Forwarded-For from trusted proxy");
  const chain = forwarded.split(",").map((part) => normalizeIp(part.trim()));
  const index = chain.length - trustedProxyHops;
  if (index < 0 || !chain[index]) throw new Error("Invalid trusted proxy chain");
  return chain[index];
}

function normalizeIp(value: string) {
  const normalized = value.startsWith("::ffff:") ? value.slice(7) : value;
  if (!isIP(normalized)) throw new Error("Unable to determine client IP");
  return normalized;
}

export function requestFingerprint(ip: string, secret: string) {
  return stableHash(`ip:${ip}`, secret);
}

export function hashForLog(value: string) {
  return createHash("sha256").update(value).digest("hex").slice(0, 16);
}

export function validBrowserOrigin(header: string | undefined, expectedOrigin: string) {
  if (!header) return false;
  try { return new URL(header).origin === expectedOrigin; } catch { return false; }
}
