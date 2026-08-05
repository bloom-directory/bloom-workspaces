import { posix } from "node:path";
import { z } from "zod";

export const GUEST_PROTOCOL_VERSION = 1;
export const MAX_GUEST_FRAME_BYTES = 384 * 1024;
export const MAX_FILE_CHUNK_BYTES = 256 * 1024;
export const MAX_JOB_LOG_CHUNK_BYTES = 256 * 1024;

const RequestId = z.string().regex(/^[A-Za-z0-9_-]{1,64}$/);
const RelativePath = z.string().min(1).max(1024).refine(isSafeWorkspacePath, "unsafe workspace path");
const WorkspaceDirectory = z.union([z.literal("."), RelativePath]);
const Base64Chunk = z.string().max(Math.ceil(MAX_FILE_CHUNK_BYTES / 3) * 4 + 4)
  .refine((value) => isCanonicalBase64(value) && Buffer.byteLength(value, "base64") <= MAX_FILE_CHUNK_BYTES, "invalid or oversized base64 payload");
const JobId = z.string().uuid();
const Environment = z.record(
  z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,63}$/),
  z.string().max(8192),
).refine((value) => Object.keys(value).length <= 64, "too many environment variables");

const Envelope = z.object({ version: z.literal(GUEST_PROTOCOL_VERSION), id: RequestId });

export const GuestRequest = z.discriminatedUnion("operation", [
  Envelope.extend({ operation: z.literal("hello") }),
  Envelope.extend({ operation: z.literal("fs.list"), path: WorkspaceDirectory }),
  Envelope.extend({
    operation: z.literal("fs.read"),
    path: RelativePath,
    offset: z.number().int().min(0),
    maxBytes: z.number().int().min(1).max(MAX_FILE_CHUNK_BYTES),
  }),
  Envelope.extend({
    operation: z.literal("fs.write"),
    path: RelativePath,
    offset: z.number().int().min(0),
    data: Base64Chunk,
    truncate: z.boolean(),
  }),
  Envelope.extend({ operation: z.literal("fs.delete"), path: RelativePath, recursive: z.literal(false) }),
  Envelope.extend({
    operation: z.literal("job.start"),
    jobId: JobId,
    argv: z.array(z.string().min(1).max(4096)).min(1).max(64),
    cwd: WorkspaceDirectory,
    environment: Environment,
    timeoutMs: z.number().int().min(1_000).max(2 * 60 * 60_000),
  }),
  Envelope.extend({
    operation: z.literal("job.status"),
    jobId: JobId,
    logOffset: z.number().int().min(0),
    maxBytes: z.number().int().min(1).max(MAX_JOB_LOG_CHUNK_BYTES),
  }),
  Envelope.extend({ operation: z.literal("job.cancel"), jobId: JobId }),
  Envelope.extend({ operation: z.literal("bloom.status") }),
  Envelope.extend({
    operation: z.literal("connections.configure"),
    workspaceId: z.string().uuid(),
    wallet: z.string().regex(/^0x[0-9a-f]{40}$/),
    caPublicKey: z.string().min(32).max(1024).regex(/^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$/),
    nfs: z.boolean(),
  }),
  Envelope.extend({
    operation: z.literal("signing.request"),
    method: z.enum(["eth_sendTransaction", "personal_sign", "eth_signTypedData_v4"]),
    params: z.array(z.unknown()).min(1).max(8),
  }),
  Envelope.extend({ operation: z.literal("signing.status"), requestId: z.string().min(1).max(64) }),
  Envelope.extend({ operation: z.literal("signing.pending") }),
  Envelope.extend({
    operation: z.literal("signing.resolve"),
    requestId: z.string().min(1).max(64),
    result: z.unknown().optional(),
    error: z.string().min(1).max(1024).optional(),
  }).refine((v) => v.result !== undefined || v.error !== undefined, "either result or error is required"),
]);

export type GuestRequest = z.infer<typeof GuestRequest>;

export type GuestErrorCode =
  | "invalid_request"
  | "not_found"
  | "conflict"
  | "limit_exceeded"
  | "permission_denied"
  | "unavailable"
  | "internal";

const GuestErrorCodeSchema = z.enum([
  "invalid_request",
  "not_found",
  "conflict",
  "limit_exceeded",
  "permission_denied",
  "unavailable",
  "internal",
]);

export const GuestResponse = z.discriminatedUnion("ok", [
  z.object({ version: z.literal(GUEST_PROTOCOL_VERSION), id: RequestId, ok: z.literal(true), result: z.unknown() }),
  z.object({
    version: z.literal(GUEST_PROTOCOL_VERSION),
    id: RequestId,
    ok: z.literal(false),
    error: z.object({ code: GuestErrorCodeSchema, message: z.string().min(1).max(1024) }),
  }),
]);

export type GuestResponse = z.infer<typeof GuestResponse>;

export function encodeGuestFrame(value: GuestRequest | GuestResponse): Buffer {
  const body = Buffer.from(`${JSON.stringify(value)}\n`);
  if (body.byteLength > MAX_GUEST_FRAME_BYTES) throw new Error("Guest protocol frame exceeds the maximum size");
  return body;
}

/** Extract complete JSON-lines while retaining an incomplete tail for the next read. */
export function decodeGuestFrames(buffer: Buffer): { frames: unknown[]; remainder: Buffer } {
  if (buffer.byteLength > MAX_GUEST_FRAME_BYTES * 2) throw new Error("Guest protocol receive buffer exceeds the maximum size");
  const frames: unknown[] = [];
  let start = 0;
  for (;;) {
    const newline = buffer.indexOf(0x0a, start);
    if (newline < 0) break;
    const length = newline - start;
    if (length === 0) { start = newline + 1; continue; }
    if (length + 1 > MAX_GUEST_FRAME_BYTES) throw new Error("Guest protocol frame exceeds the maximum size");
    frames.push(JSON.parse(buffer.subarray(start, newline).toString("utf8")) as unknown);
    start = newline + 1;
  }
  const remainder = buffer.subarray(start);
  if (remainder.byteLength > MAX_GUEST_FRAME_BYTES) throw new Error("Guest protocol frame exceeds the maximum size");
  return { frames, remainder };
}

export function isSafeWorkspacePath(value: string) {
  if (value.includes("\0") || value.includes("\\") || value.startsWith("/") || value.endsWith("/")) return false;
  const normalized = posix.normalize(value);
  return normalized === value && normalized !== "." && !normalized.startsWith("../") && normalized !== "..";
}

function isCanonicalBase64(value: string) {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) return false;
  return Buffer.from(value, "base64").toString("base64") === value;
}
