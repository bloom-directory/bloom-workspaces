import type { GuestRequest } from "../guest-protocol.js";

type Call = (request: GuestRequest, timeoutMs?: number) => Promise<unknown>;

export async function waitForGuestControl(call: Call, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown;
  while (Date.now() < deadline) {
    try {
      const result = await call({ version: 1, id: "readiness", operation: "hello" }, 1_000);
      if (isHello(result)) return result;
      lastError = new Error("Guest hello response did not match protocol v1");
    } catch (error) { lastError = error; }
    await new Promise<void>((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Guest control did not become ready: ${lastError instanceof Error ? lastError.message : "timeout"}`);
}

function isHello(value: unknown): value is { protocolVersion: 1; operations: string[] } {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as { protocolVersion?: unknown; operations?: unknown };
  const required = ["fs.list", "fs.read", "fs.write", "fs.delete", "job.start", "job.status", "job.cancel", "bloom.status", "connections.configure"];
  const operations = candidate.operations;
  if (candidate.protocolVersion !== 1 || !Array.isArray(operations)) return false;
  return required.every((operation) => operations.includes(operation));
}
