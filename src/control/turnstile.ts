import type { Config } from "../config.js";

export async function verifyTurnstile(config: Config, token: string | null | undefined, clientIp: string) {
  if (!config.turnstileSecret) return !config.publicMode;
  if (!token) return false;
  const body = new URLSearchParams({ secret: config.turnstileSecret, response: token, remoteip: clientIp });
  const response = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body, signal: AbortSignal.timeout(5_000) });
  if (!response.ok) return false;
  const result = await response.json() as { success?: boolean; hostname?: string };
  return result.success === true && result.hostname === new URL(config.origin).hostname;
}
