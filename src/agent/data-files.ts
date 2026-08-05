import { constants } from "node:fs";
import { lstat, mkdir, open, readdir, rm } from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";
import { RuntimeDataError, type WorkspaceFileEntry, type WorkspaceFileWrite } from "./runtime.js";

export const MAX_FILE_TRANSFER_BYTES = 8 * 1024 * 1024;
const MAX_LIST_ENTRIES = 1_000;
const MAX_QUOTA_SCAN_ENTRIES = 20_000;

type Root = { path: string; quotaBytes: number };

/**
 * Host-directory implementation used only by the explicitly development-only
 * process runtime. VM runtimes must use a guest protocol and never mount or
 * walk an untrusted guest filesystem on the host.
 */
export class WorkspaceDataFiles {
  private readonly locks = new Map<string, Promise<void>>();

  async list(root: Root, requestedPath: string): Promise<WorkspaceFileEntry[]> {
    await assertRoot(root.path);
    const target = await checkedExistingPath(root.path, requestedPath, true);
    const stat = await lstat(target);
    if (!stat.isDirectory()) throw new RuntimeDataError("File list path is not a directory", 400);
    const entries = await readdir(target, { withFileTypes: true });
    if (entries.length > MAX_LIST_ENTRIES) throw new RuntimeDataError("Directory contains too many entries", 413);
    return Promise.all(entries.sort((a, b) => a.name.localeCompare(b.name)).map(async (entry) => {
      const entryPath = join(target, entry.name);
      const entryStat = await lstat(entryPath);
      const type = entryStat.isSymbolicLink() ? "symlink" : entryStat.isDirectory() ? "directory" : "file";
      return {
        path: relative(root.path, entryPath).split(sep).join("/"),
        type,
        size: entryStat.isFile() ? entryStat.size : 0,
        modifiedAt: entryStat.mtimeMs,
      } satisfies WorkspaceFileEntry;
    }));
  }

  async read(root: Root, requestedPath: string): Promise<Buffer> {
    await assertRoot(root.path);
    const target = await checkedExistingPath(root.path, requestedPath, false);
    let handle;
    try {
      handle = await open(target, constants.O_RDONLY | constants.O_NOFOLLOW);
      const stat = await handle.stat();
      if (!stat.isFile()) throw new RuntimeDataError("Download path is not a regular file", 400);
      if (stat.size > MAX_FILE_TRANSFER_BYTES) throw new RuntimeDataError("File exceeds the download limit", 413);
      return await handle.readFile();
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ELOOP") throw new RuntimeDataError("Symbolic links are not allowed", 400);
      throw error;
    } finally { await handle?.close(); }
  }

  async write(root: Root, requestedPath: string, contents: Buffer): Promise<WorkspaceFileWrite> {
    if (contents.byteLength > MAX_FILE_TRANSFER_BYTES) throw new RuntimeDataError("Upload exceeds the file size limit", 413);
    return this.serialized(root.path, async () => {
      await assertRoot(root.path);
      const relativePath = validateRelativePath(requestedPath, false);
      const target = resolve(root.path, relativePath);
      await ensureSafeParents(root.path, dirname(target));
      const priorSize = await regularFileSizeOrZero(target);
      const usedBefore = await directoryBytes(root.path);
      const usedAfter = usedBefore - priorSize + contents.byteLength;
      if (usedAfter > root.quotaBytes) throw new RuntimeDataError("Workspace storage quota exceeded", 413);

      let handle;
      try {
        handle = await open(target, constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | constants.O_NOFOLLOW, 0o600);
        await handle.writeFile(contents);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ELOOP") throw new RuntimeDataError("Symbolic links are not allowed", 400);
        throw error;
      } finally { await handle?.close(); }
      return { size: contents.byteLength, usedBytes: usedAfter, quotaBytes: root.quotaBytes };
    });
  }

  async delete(root: Root, requestedPath: string) {
    return this.serialized(root.path, async () => {
      await assertRoot(root.path);
      const target = await checkedExistingPath(root.path, requestedPath, false);
      const stat = await lstat(target);
      if (stat.isSymbolicLink()) throw new RuntimeDataError("Symbolic links are not allowed", 400);
      if (!stat.isFile()) throw new RuntimeDataError("Delete path is not a regular file", 400);
      await rm(target);
      return { usedBytes: await directoryBytes(root.path), quotaBytes: root.quotaBytes };
    });
  }

  private async serialized<T>(root: string, operation: () => Promise<T>): Promise<T> {
    const previous = this.locks.get(root) ?? Promise.resolve();
    let release: () => void = () => undefined;
    const current = new Promise<void>((resolveLock) => { release = resolveLock; });
    const queued = previous.then(() => current);
    this.locks.set(root, queued);
    await previous;
    try { return await operation(); }
    finally {
      release();
      if (this.locks.get(root) === queued) this.locks.delete(root);
    }
  }
}

function validateRelativePath(value: string, allowEmpty: boolean) {
  if (Buffer.byteLength(value) > 4_096 || value.includes("\0") || value.includes("\\") || value.startsWith("/")) {
    throw new RuntimeDataError("Invalid workspace path", 400);
  }
  if ((!value || value === ".") && allowEmpty) return "";
  const parts = value.split("/");
  if (!value || parts.some((part) => !part || part === "." || part === "..")) throw new RuntimeDataError("Invalid workspace path", 400);
  return parts.join(sep);
}

async function checkedExistingPath(root: string, requestedPath: string, allowEmpty: boolean) {
  const relativePath = validateRelativePath(requestedPath, allowEmpty);
  const target = resolve(root, relativePath);
  if (target !== resolve(root) && !target.startsWith(`${resolve(root)}${sep}`)) throw new RuntimeDataError("Workspace path escapes /workspace", 400);
  const parts = relativePath ? relativePath.split(sep) : [];
  let cursor = resolve(root);
  for (const part of parts) {
    cursor = join(cursor, part);
    try {
      const stat = await lstat(cursor);
      if (stat.isSymbolicLink()) throw new RuntimeDataError("Symbolic links are not allowed", 400);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") throw new RuntimeDataError("Workspace path does not exist", 404);
      throw error;
    }
  }
  return target;
}

async function ensureSafeParents(root: string, targetParent: string) {
  const relativeParent = relative(resolve(root), targetParent);
  if (relativeParent.startsWith("..") || resolve(root, relativeParent) !== targetParent) throw new RuntimeDataError("Workspace path escapes /workspace", 400);
  let cursor = resolve(root);
  for (const part of relativeParent ? relativeParent.split(sep) : []) {
    cursor = join(cursor, part);
    try {
      const stat = await lstat(cursor);
      if (stat.isSymbolicLink() || !stat.isDirectory()) throw new RuntimeDataError("Workspace path contains an unsafe parent", 400);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      await mkdir(cursor, { mode: 0o700 });
      const stat = await lstat(cursor);
      if (stat.isSymbolicLink() || !stat.isDirectory()) throw new RuntimeDataError("Workspace path contains an unsafe parent", 400);
    }
  }
}

async function regularFileSizeOrZero(target: string) {
  try {
    const stat = await lstat(target);
    if (stat.isSymbolicLink() || !stat.isFile()) throw new RuntimeDataError("Upload target is not a regular file", 400);
    return stat.size;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return 0;
    throw error;
  }
}

async function directoryBytes(root: string) {
  await assertRoot(root);
  let count = 0;
  let bytes = 0;
  const pending = [root];
  while (pending.length) {
    const directory = pending.pop()!;
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (++count > MAX_QUOTA_SCAN_ENTRIES) throw new RuntimeDataError("Workspace contains too many files", 413);
      const path = join(directory, entry.name);
      const stat = await lstat(path);
      if (stat.isSymbolicLink()) continue;
      if (stat.isDirectory()) pending.push(path);
      else if (stat.isFile()) bytes += stat.size;
    }
  }
  return bytes;
}

async function assertRoot(root: string) {
  try {
    const stat = await lstat(root);
    if (stat.isSymbolicLink() || !stat.isDirectory()) throw new RuntimeDataError("Workspace data root is unsafe", 409);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") throw new RuntimeDataError("Workspace data root is unavailable", 409);
    throw error;
  }
}
