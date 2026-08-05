import { randomUUID } from "node:crypto";
import { z } from "zod";
import { GuestRequest, MAX_FILE_CHUNK_BYTES, type GuestRequest as GuestRequestValue } from "../guest-protocol.js";
import { GuestChannelError } from "./guest-channel.js";
import { RuntimeDataError, type WorkspaceFileEntry, type WorkspaceFileWrite } from "./runtime.js";

export type GuestCall = (request: GuestRequestValue, timeoutMs?: number) => Promise<unknown>;
type GuestOperation = GuestRequestValue extends infer Request
  ? Request extends GuestRequestValue ? Omit<Request, "version" | "id"> : never
  : never;

const FileEntry = z.object({
  path: z.string().min(1).max(1024),
  type: z.enum(["file", "directory", "symlink"]),
  size: z.number().int().nonnegative(),
  modifiedAt: z.number().int().nonnegative(),
}).strict();
const FileList = z.object({ files: z.array(FileEntry).max(1000) }).strict();
const ReadChunk = z.object({
  path: z.string(), offset: z.number().int().nonnegative(), nextOffset: z.number().int().nonnegative(),
  size: z.number().int().min(0).max(8 * 1024 * 1024), eof: z.boolean(), data: z.string(),
}).strict();
const WriteChunk = z.object({
  path: z.string(), size: z.number().int().nonnegative(), nextOffset: z.number().int().nonnegative(),
  usedBytes: z.number().int().nonnegative(), quotaBytes: z.number().int().positive(),
}).strict();
const DeleteResult = z.object({
  path: z.string(), deleted: z.literal(true), usedBytes: z.number().int().nonnegative(), quotaBytes: z.number().int().positive(),
}).strict();

/** Bounded chunk adapter between the node-agent file API and guest protocol v1. */
export class GuestWorkspace {
  constructor(private readonly call: GuestCall) {}

  async list(path: string): Promise<WorkspaceFileEntry[]> {
    const result = FileList.parse(await this.request({ operation: "fs.list", path }));
    return result.files;
  }

  async read(path: string): Promise<Buffer> {
    const chunks: Buffer[] = [];
    let offset = 0;
    let expectedSize: number | undefined;
    for (;;) {
      const result = ReadChunk.parse(await this.request({ operation: "fs.read", path, offset, maxBytes: MAX_FILE_CHUNK_BYTES }));
      if (result.path !== path || result.offset !== offset || (expectedSize !== undefined && result.size !== expectedSize)) {
        throw new RuntimeDataError("Guest returned an inconsistent file response", 501);
      }
      expectedSize = result.size;
      const chunk = canonicalBase64(result.data);
      if (chunk.byteLength > MAX_FILE_CHUNK_BYTES || result.nextOffset !== offset + chunk.byteLength) {
        throw new RuntimeDataError("Guest returned an invalid file chunk", 501);
      }
      chunks.push(chunk);
      offset = result.nextOffset;
      if (result.eof) {
        if (offset !== result.size) throw new RuntimeDataError("Guest ended the file response early", 501);
        return Buffer.concat(chunks, offset);
      }
      if (chunk.byteLength === 0) throw new RuntimeDataError("Guest file transfer made no progress", 501);
    }
  }

  async write(path: string, contents: Buffer): Promise<WorkspaceFileWrite> {
    let offset = 0;
    let final: z.infer<typeof WriteChunk> | undefined;
    do {
      const chunk = contents.subarray(offset, Math.min(contents.length, offset + MAX_FILE_CHUNK_BYTES));
      final = WriteChunk.parse(await this.request({
        operation: "fs.write", path, offset, data: chunk.toString("base64"), truncate: offset === 0,
      }));
      if (final.path !== path || final.nextOffset !== offset + chunk.byteLength) {
        throw new RuntimeDataError("Guest returned an inconsistent upload response", 501);
      }
      offset = final.nextOffset;
    } while (offset < contents.length);
    if (!final || final.size !== contents.length) throw new RuntimeDataError("Guest did not commit the complete upload", 501);
    return { size: final.size, usedBytes: final.usedBytes, quotaBytes: final.quotaBytes };
  }

  async delete(path: string) {
    const result = DeleteResult.parse(await this.request({ operation: "fs.delete", path, recursive: false }));
    if (result.path !== path) throw new RuntimeDataError("Guest returned an inconsistent delete response", 501);
    return { usedBytes: result.usedBytes, quotaBytes: result.quotaBytes };
  }

  private async request(operation: GuestOperation): Promise<unknown> {
    try {
      return await this.call(GuestRequest.parse({ version: 1, id: `fs_${randomUUID().replaceAll("-", "")}`, ...operation }));
    } catch (error) {
      if (error instanceof RuntimeDataError) throw error;
      if (error instanceof GuestChannelError) {
        const status = error.code === "not_found" ? 404
          : error.code === "conflict" ? 409
            : error.code === "limit_exceeded" ? 413
              : error.code === "unavailable" || error.code === "transport" ? 501 : 400;
        throw new RuntimeDataError(error.message, status);
      }
      throw new RuntimeDataError("Guest returned an invalid data response", 501);
    }
  }
}

function canonicalBase64(value: string) {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)) {
    throw new RuntimeDataError("Guest returned invalid base64", 501);
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value) throw new RuntimeDataError("Guest returned non-canonical base64", 501);
  return decoded;
}
