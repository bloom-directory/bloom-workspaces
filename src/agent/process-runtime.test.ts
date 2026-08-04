import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { ProcessRuntime } from "./process-runtime.js";

describe("node-agent lease enforcement", () => {
  it("terminates a live terminal when its lease expires", async () => {
    const directory = await mkdtemp(join(tmpdir(), "bloom-runtime-"));
    const runtime = new ProcessRuntime(directory);
    const id = randomUUID();
    await runtime.create({ id, leaseExpiresAt: Date.now() + 30 });
    let output = "";
    runtime.attach(id, (message) => { if (message.type === "output") output += message.data; });
    runtime.write(id, "printf bloom-runtime-ok\\n");
    await eventually(() => output.includes("bloom-runtime-ok"));
    await new Promise((resolve) => setTimeout(resolve, 35));
    await runtime.sweep();
    expect(runtime.status(id)).toBe("stopped");
    await runtime.close();
    await rm(directory, { recursive: true, force: true });
  });
});

async function eventually(predicate: () => boolean) {
  for (let attempt = 0; attempt < 50; attempt++) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error("condition was not reached");
}
