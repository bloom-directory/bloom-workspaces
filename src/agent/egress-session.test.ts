import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig } from "../config.js";
import { startFirecrackerWorkspaceEgress, startQemuWorkspaceEgress } from "./egress-session.js";

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

describe("workspace egress transport", () => {
  it("stays completely absent unless controlled mode is enabled", async () => {
    const config = loadConfig({ BLOOM_RUNTIME: "qemu", BLOOM_VM_EGRESS: "none" });
    await expect(startQemuWorkspaceEgress(config, "workspace-a")).resolves.toBeUndefined();
  });

  it("binds a private QEMU endpoint and emits only a restricted guest forward", async () => {
    const config = loadConfig({ BLOOM_RUNTIME: "qemu", BLOOM_VM_EGRESS: "controlled" });
    const session = await startQemuWorkspaceEgress(config, "workspace-a");
    if (!session) throw new Error("missing egress session");
    cleanups.push(session.close);
    expect(session.kernelArgument).toBe("bloom_egress=qemu");
    expect(session.qemuGuestForward).toMatch(/^guestfwd=tcp:10\.0\.2\.100:3128-tcp:127\.0\.0\.1:[0-9]+$/u);
    await session.close();
    await session.close();
  });

  it("uses only the Firecracker per-port vsock Unix socket", async () => {
    const directory = await mkdtemp(join(tmpdir(), "bloom-egress-session-"));
    cleanups.push(async () => { await rm(directory, { recursive: true, force: true }); });
    await mkdir(directory, { recursive: true });
    const base = join(directory, "v.sock");
    const config = loadConfig({ BLOOM_RUNTIME: "firecracker", BLOOM_VM_EGRESS: "controlled" });
    const session = await startFirecrackerWorkspaceEgress(config, "workspace-a", base);
    if (!session) throw new Error("missing egress session");
    cleanups.push(session.close);
    expect(session.kernelArgument).toBe("bloom_egress=vsock");
    expect(session.qemuGuestForward).toBeUndefined();
  });
});
