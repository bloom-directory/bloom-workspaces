import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { destroyVolumeDirectory, ensureExt4Volume, volumeDirectory } from "./data-volume.js";
import { RuntimeDataError } from "./runtime.js";

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => { while (cleanups.length) await cleanups.pop()?.(); });

async function makeDataDir() {
  const dir = await mkdtemp(join(tmpdir(), "bloom-vol-test-"));
  cleanups.push(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

describe("data volume management", () => {
  describe("volumeDirectory", () => {
    it("rejects non-UUID volume IDs", () => {
      const dataDir = "/data";
      expect(() => volumeDirectory(dataDir, "not-a-uuid")).toThrow(RuntimeDataError);
      expect(() => volumeDirectory(dataDir, "")).toThrow(RuntimeDataError);
      expect(() => volumeDirectory(dataDir, "../../../etc")).toThrow(RuntimeDataError);
    });

    it("accepts valid UUID v4 and returns expected path", () => {
      const id = randomUUID();
      expect(volumeDirectory("/data", id)).toBe(join("/data", "volumes", id));
    });
  });

  describe("ensureExt4Volume", () => {
    it("rejects invalid quota values", async () => {
      const dir = await makeDataDir();
      const id = randomUUID();
      await expect(ensureExt4Volume(dir, id, 0)).rejects.toThrow(RuntimeDataError);
      await expect(ensureExt4Volume(dir, id, 15 * 1024 * 1024)).rejects.toThrow(RuntimeDataError);
      await expect(ensureExt4Volume(dir, id, 6 * 1024 * 1024 * 1024)).rejects.toThrow(RuntimeDataError);
      await expect(ensureExt4Volume(dir, id, Number.NaN)).rejects.toThrow(RuntimeDataError);
    });

    it("rejects when disk space is insufficient", async () => {
      const dir = await makeDataDir();
      const id = randomUUID();
      // Request more space than available — 5 GiB almost certainly exceeds test env
      await expect(ensureExt4Volume(dir, id, 5 * 1024 * 1024 * 1024)).rejects.toThrow(/Insufficient disk space/);
    });

    it("creates and validates a small ext4 volume", async () => {
      const dir = await makeDataDir();
      const id = randomUUID();
      const quota = 16 * 1024 * 1024; // 16 MiB minimum
      const image = await ensureExt4Volume(dir, id, quota);
      expect(image).toContain("workspace.ext4");

      // Second call with same ID returns existing image (idempotent)
      const image2 = await ensureExt4Volume(dir, id, quota);
      expect(image2).toBe(image);
    });
  });

  describe("destroyVolumeDirectory", () => {
    it("removes the volume directory", async () => {
      const dir = await makeDataDir();
      const id = randomUUID();
      await ensureExt4Volume(dir, id, 16 * 1024 * 1024);
      await destroyVolumeDirectory(dir, id);
      // Should be idempotent (no error on second call)
      await destroyVolumeDirectory(dir, id);
    });
  });
});
