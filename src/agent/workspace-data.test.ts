import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { access, lstat, mkdtemp, mkdir, open, readFile, readdir, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadConfig } from "../config.js";
import { FirecrackerRuntime } from "./firecracker-runtime.js";
import { destroyVolumeDirectory, ensureExt4Volume } from "./data-volume.js";
import { ProcessRuntime } from "./process-runtime.js";
import { QemuRuntime } from "./qemu-runtime.js";
import { RuntimeDataError, type RuntimeSpec } from "./runtime.js";

describe("process workspace data", () => {
  it("supports bounded rooted file operations and cleans disposable data", async () => {
    const directory = await mkdtemp(join(tmpdir(), "bloom-data-"));
    const runtime = new ProcessRuntime(directory);
    const spec = disposable(32);
    try {
      await runtime.create(spec);
      await runtime.writeFile(spec.id, "src/index.txt", Buffer.from("bloom"));
      await expect(runtime.listFiles(spec.id, "src")).resolves.toMatchObject([{ path: "src/index.txt", type: "file", size: 5 }]);
      await expect(runtime.readFile(spec.id, "src/index.txt")).resolves.toEqual(Buffer.from("bloom"));
      await expect(runtime.writeFile(spec.id, "too-large", Buffer.alloc(33))).rejects.toMatchObject({ status: 413 });
      await runtime.deleteFile(spec.id, "src/index.txt");
      await expect(runtime.readFile(spec.id, "src/index.txt")).rejects.toMatchObject({ status: 404 });

      await runtime.stop(spec.id, "test complete");
      await expect(access(join(directory, spec.id), constants.F_OK)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(runtime.listFiles(spec.id, "")).rejects.toMatchObject({ status: 409 });
    } finally {
      await runtime.close();
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("retains a wallet volume across workspace recreation and destroys it explicitly", async () => {
    const directory = await mkdtemp(join(tmpdir(), "bloom-data-"));
    const runtime = new ProcessRuntime(directory);
    const volumeId = randomUUID();
    const first = persistent(volumeId);
    const second = persistent(volumeId);
    try {
      await runtime.create(first);
      await runtime.writeFile(first.id, "survives.txt", Buffer.from("durable"));
      await runtime.stop(first.id, "recreate");
      expect(await readFile(join(directory, "volumes", volumeId, "workspace", "survives.txt"), "utf8")).toBe("durable");

      await runtime.create(second);
      await expect(runtime.readFile(second.id, "survives.txt")).resolves.toEqual(Buffer.from("durable"));
      await expect(runtime.destroyVolume(volumeId)).rejects.toMatchObject({ status: 409 });
      await runtime.stop(second.id, "destroy volume");
      await runtime.destroyVolume(volumeId);
      await expect(access(join(directory, "volumes", volumeId), constants.F_OK)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await runtime.close();
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("rejects traversal, symlink escape, and concurrent quota overrun", async () => {
    const directory = await mkdtemp(join(tmpdir(), "bloom-data-"));
    const runtime = new ProcessRuntime(directory);
    const spec = disposable(6);
    const outside = join(directory, "outside");
    try {
      await runtime.create(spec);
      await mkdir(outside);
      await writeFile(join(outside, "secret"), "host-secret");
      await symlink(outside, join(directory, spec.id, "workspace", "escape"));

      for (const path of ["../outside/secret", "/etc/passwd", "a/../b", "a\\b", "escape/secret"]) {
        await expect(runtime.readFile(spec.id, path)).rejects.toBeInstanceOf(RuntimeDataError);
        await expect(runtime.writeFile(spec.id, path, Buffer.from("x"))).rejects.toBeInstanceOf(RuntimeDataError);
      }
      expect(await readFile(join(outside, "secret"), "utf8")).toBe("host-secret");

      const writes = await Promise.allSettled([
        runtime.writeFile(spec.id, "one", Buffer.from("1234")),
        runtime.writeFile(spec.id, "two", Buffer.from("5678")),
      ]);
      expect(writes.filter((result) => result.status === "fulfilled")).toHaveLength(1);
      expect(writes.filter((result) => result.status === "rejected")).toHaveLength(1);
      const stored = (await Promise.all((await runtime.listFiles(spec.id, "")).filter((entry) => entry.type === "file").map((entry) => lstat(join(directory, spec.id, "workspace", entry.path))))).reduce((sum, stat) => sum + stat.size, 0);
      expect(stored).toBeLessThanOrEqual(6);

      await rm(join(directory, spec.id, "workspace"), { recursive: true });
      await symlink(outside, join(directory, spec.id, "workspace"));
      await expect(runtime.readFile(spec.id, "secret")).rejects.toMatchObject({ status: 409 });
      await expect(runtime.writeFile(spec.id, "secret", Buffer.from("changed"))).rejects.toMatchObject({ status: 409 });
      expect(await readFile(join(outside, "secret"), "utf8")).toBe("host-secret");
    } finally {
      await runtime.close();
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("reports VM persistence separately from the bounded guest file transport", async () => {
    const qemu = new QemuRuntime(loadConfig({ BLOOM_RUNTIME: "qemu" }));
    const firecracker = new FirecrackerRuntime(loadConfig({ BLOOM_RUNTIME: "firecracker" }));
    for (const runtime of [qemu, firecracker]) {
      expect(runtime.dataCapabilities("missing")).toMatchObject({ persistence: true, fileTransfer: true });
      await expect(runtime.listFiles("missing", ".")).rejects.toMatchObject({ status: 409 });
      await expect(runtime.readFile("missing", "file")).rejects.toMatchObject({ status: 409 });
    }

    const jailed = new FirecrackerRuntime(loadConfig({ BLOOM_RUNTIME: "firecracker", BLOOM_FIRECRACKER_JAILED: "1" }));
    expect(jailed.dataCapabilities("missing")).toMatchObject({
      persistence: false,
      persistenceReason: "Persistent data disks are unsupported with the Firecracker jailer",
      fileTransfer: true,
    });
    await expect(jailed.create(persistent(randomUUID()))).rejects.toMatchObject({ status: 501 });
  });

  it("creates and destroys a bounded ext4 backing disk without mounting it on the host", async () => {
    const directory = await mkdtemp(join(tmpdir(), "bloom-volume-"));
    const volumeId = randomUUID();
    try {
      const images = await Promise.all(Array.from({ length: 4 }, () => ensureExt4Volume(directory, volumeId, 16 * 1024 * 1024)));
      const image = images[0]!;
      expect(new Set(images)).toEqual(new Set([image]));
      expect((await stat(image)).size).toBe(16 * 1024 * 1024);
      const bytes = await readFile(image);
      expect(bytes.subarray(1080, 1082)).toEqual(Buffer.from([0x53, 0xef]));
      expect(await readdir(join(directory, "volumes", volumeId))).toEqual(["workspace.ext4"]);
      expect(await ensureExt4Volume(directory, volumeId, 16 * 1024 * 1024)).toBe(image);

      const incompleteVolumeId = randomUUID();
      const incompleteDirectory = join(directory, "volumes", incompleteVolumeId);
      const incompleteImage = join(incompleteDirectory, "workspace.ext4");
      await mkdir(incompleteDirectory, { recursive: true });
      const incomplete = await open(incompleteImage, "wx", 0o600);
      await incomplete.truncate(16 * 1024 * 1024);
      await incomplete.close();
      await expect(ensureExt4Volume(directory, incompleteVolumeId, 16 * 1024 * 1024)).rejects.toMatchObject({ status: 409 });

      await destroyVolumeDirectory(directory, volumeId);
      await expect(access(image, constants.F_OK)).rejects.toMatchObject({ code: "ENOENT" });
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
});

function disposable(quotaBytes: number): RuntimeSpec {
  return { id: randomUUID(), leaseExpiresAt: Date.now() + 60_000, storage: { mode: "disposable", quotaBytes } };
}

function persistent(volumeId: string): RuntimeSpec {
  return { id: randomUUID(), leaseExpiresAt: Date.now() + 60_000, storage: { mode: "persistent", volumeId, quotaBytes: 16 * 1024 * 1024 } };
}
