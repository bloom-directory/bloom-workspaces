import { constants } from "node:fs";
import { statfs } from "node:fs/promises";
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { link, mkdir, open, rm } from "node:fs/promises";
import { promisify } from "node:util";
import { join } from "node:path";
import { RuntimeDataError } from "./runtime.js";

const execFileAsync = promisify(execFile);
const VOLUME_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function volumeDirectory(dataDir: string, volumeId: string) {
  if (!VOLUME_ID.test(volumeId)) throw new RuntimeDataError("Invalid volume id", 400);
  return join(dataDir, "volumes", volumeId);
}

export async function ensureExt4Volume(dataDir: string, volumeId: string, quotaBytes: number) {
  if (!Number.isSafeInteger(quotaBytes) || quotaBytes < 16 * 1024 * 1024 || quotaBytes > 5 * 1024 * 1024 * 1024) {
    throw new RuntimeDataError("Invalid volume quota", 400);
  }
  // Pre-flight: refuse to start if the host cannot accommodate the volume.
  const { bavail, bsize } = await statfs(dataDir);
  const available = bavail * bsize;
  if (available < quotaBytes) {
    throw new RuntimeDataError(
      `Insufficient disk space: need ${quotaBytes} bytes, ${available} available`, 507,
    );
  }
  const directory = volumeDirectory(dataDir, volumeId);
  const image = join(directory, "workspace.ext4");
  await mkdir(directory, { recursive: true, mode: 0o700 });
  try {
    await validatePublishedImage(image, quotaBytes);
    return image;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }

  const temporary = join(directory, `.workspace-${randomUUID()}.tmp`);
  let handle;
  try {
    handle = await open(temporary, "wx", 0o600);
    await handle.truncate(quotaBytes);
    await handle.close();
    handle = undefined;
    await execFileAsync("mkfs.ext4", ["-q", "-F", temporary], { timeout: 60_000, maxBuffer: 64 * 1024 });
    // link(2) is an atomic no-replace publish. Concurrent creators can only
    // expose a fully formatted image at the stable path; losing temporary
    // images are discarded without replacing the published backing disk.
    try { await link(temporary, image); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
    await validatePublishedImage(image, quotaBytes);
    return image;
  } catch (error) {
    await handle?.close();
    throw error;
  } finally { await rm(temporary, { force: true }); }
}

export async function destroyVolumeDirectory(dataDir: string, volumeId: string) {
  await rm(volumeDirectory(dataDir, volumeId), { recursive: true, force: true });
}

async function validatePublishedImage(image: string, quotaBytes: number) {
  let handle;
  try {
    handle = await open(image, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size !== quotaBytes) throw new RuntimeDataError("Persistent volume image has an invalid size", 409);
    const magic = Buffer.alloc(2);
    const { bytesRead } = await handle.read(magic, 0, magic.byteLength, 1080);
    if (bytesRead !== 2 || magic[0] !== 0x53 || magic[1] !== 0xef) throw new RuntimeDataError("Persistent volume image is not a formatted ext4 filesystem", 409);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ELOOP") throw new RuntimeDataError("Persistent volume image cannot be a symbolic link", 409);
    throw error;
  } finally { await handle?.close(); }
}
