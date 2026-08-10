import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { RealBloom } from "./real-bloom.js";

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => { while (cleanups.length) await cleanups.pop()?.(); });

async function withOutbox(plan: Record<string, string>): Promise<{ rb: RealBloom }> {
  const dir = await mkdtemp(join(tmpdir(), "bloom-real-"));
  const rb = new RealBloom({ bloomBin: "bloom", home: dir, wallet: "0x000000000000000000000000000000000000dead" });
  for (const [path, content] of Object.entries(plan)) {
    const fullPath = join(rb.home, "outbox", path);
    await mkdir(fullPath, { recursive: true });
    await writeFile(join(fullPath, "plan.md"), content);
  }
  cleanups.push(async () => { await rm(dir, { recursive: true, force: true }); });
  return { rb };
}

describe("RealBloom outbox read/approve (no bloom subprocess)", () => {
  it("reads real plan.md entries across chains with a generated challenge", async () => {
    const { rb } = await withOutbox({
      "workspace-login/base/pending/0001-abc": "# Real plan\ntransfer 1 wei",
      "workspace-login/ethereum/pending/0002-def": "# Other plan",
    });
    const { requests } = await rb.pending();
    expect(requests.map((r) => r.id).sort()).toEqual(["0001-abc", "0002-def"]);
    const first = requests.find((r) => r.id === "0001-abc")!;
    expect(first.planMd).toContain("Real plan");
    expect(first.chain).toBe("base");
    expect(first.ceremonyUrl).toBeNull();
    expect(typeof first.challenge).toBe("string");
    expect(first.challenge.length).toBeGreaterThan(0);
  });

  it("approves by removing the pending entry", async () => {
    const { rb } = await withOutbox({
      "workspace-login/base/pending/0001-abc": "# plan",
      "workspace-login/base/pending/0002-def": "# plan",
    });
    expect(await rb.approve("0001-abc")).toBe(true);
    const { requests } = await rb.pending();
    expect(requests.map((r) => r.id)).toEqual(["0002-def"]);
  });

  it("approve returns false for an unknown tx", async () => {
    const { rb } = await withOutbox({ "workspace-login/base/pending/0001-abc": "# plan" });
    expect(await rb.approve("nope")).toBe(false);
  });

  it("pending is empty when the outbox does not exist", async () => {
    const dir = await mkdtemp(join(tmpdir(), "bloom-real-empty-"));
    cleanups.push(async () => { await rm(dir, { recursive: true, force: true }); });
  const rb = new RealBloom({ bloomBin: "bloom", home: dir, wallet: "0x000000000000000000000000000000000000dead" });
    expect((await rb.pending()).requests).toEqual([]);
  });
});
