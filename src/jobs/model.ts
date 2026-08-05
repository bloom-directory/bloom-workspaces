import { z } from "zod";

export const MAX_ACTIVE_JOBS = 2;
export const MAX_RETAINED_JOBS = 64;
export const MAX_JOB_LOG_BYTES = 1024 * 1024;
export const MAX_JOB_LOG_CHUNK_BYTES = 256 * 1024;
export const MAX_JOB_TIMEOUT_MS = 2 * 60 * 60_000;

export const jobStates = ["queued", "running", "succeeded", "failed", "cancelled", "timed_out"] as const;
export type JobState = (typeof jobStates)[number];

const userEnvironmentNames = new Set([
  "CI",
  "DEBUG",
  "FORCE_COLOR",
  "LANG",
  "LC_ALL",
  "LOG_LEVEL",
  "NODE_ENV",
  "NO_COLOR",
  "PYTHONUNBUFFERED",
  "RUST_BACKTRACE",
  "RUST_LOG",
  "TERM",
  "TZ",
]);
const userEnvironmentPrefixes = ["APP_", "JOB_", "TEST_"];

const JobEnvironment = z.record(
  z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,63}$/),
  z.string().max(8192).refine((value) => !value.includes("\0"), "environment values may not contain NUL"),
).superRefine((environment, context) => {
  if (Object.keys(environment).length > 64) context.addIssue({ code: "custom", message: "too many environment variables" });
  let bytes = 0;
  for (const [name, value] of Object.entries(environment)) {
    if (!userEnvironmentNames.has(name) && !userEnvironmentPrefixes.some((prefix) => name.startsWith(prefix))) {
      context.addIssue({ code: "custom", path: [name], message: "environment variable is not allowlisted" });
    }
    bytes += Buffer.byteLength(name) + Buffer.byteLength(value);
  }
  if (bytes > 32 * 1024) context.addIssue({ code: "custom", message: "environment exceeds the aggregate size limit" });
});

const RelativeJobPath = z.string().min(1).max(1024).refine((path) => {
  if (path === ".") return true;
  if (path.includes("\0") || path.includes("\\") || path.startsWith("/") || path.endsWith("/")) return false;
  const parts = path.split("/");
  return parts.every((part) => part !== "" && part !== "." && part !== "..");
}, "cwd must stay below /workspace");

export const StructuredJobSpec = z.object({
  argv: z.array(z.string().min(1).max(4096).refine((value) => !value.includes("\0"), "argv may not contain NUL")).min(1).max(64)
    .refine((argv) => argv.reduce((bytes, value) => bytes + Buffer.byteLength(value), 0) <= 32 * 1024, "argv exceeds the aggregate size limit"),
  cwd: RelativeJobPath,
  environment: JobEnvironment.default({}),
  timeoutMs: z.number().int().min(1000).max(MAX_JOB_TIMEOUT_MS),
}).strict();

export type StructuredJobSpec = z.infer<typeof StructuredJobSpec>;

export const JobLogChunk = z.object({
  offset: z.number().int().nonnegative(),
  nextOffset: z.number().int().nonnegative(),
  endOffset: z.number().int().nonnegative(),
  truncatedBefore: z.boolean(),
  eof: z.boolean(),
  encoding: z.literal("base64"),
  data: z.string(),
}).superRefine((value, context) => {
  if (!(value.offset <= value.nextOffset && value.nextOffset <= value.endOffset)) {
    context.addIssue({ code: "custom", message: "invalid log cursor ordering" });
  }
  const decoded = Buffer.from(value.data, "base64");
  if (decoded.toString("base64") !== value.data || decoded.byteLength > MAX_JOB_LOG_CHUNK_BYTES || decoded.byteLength !== value.nextOffset - value.offset) {
    context.addIssue({ code: "custom", path: ["data"], message: "invalid bounded log payload" });
  }
});

export const JobStatus = z.object({
  jobId: z.string().uuid(),
  state: z.enum(jobStates),
  createdAt: z.number().int().nonnegative(),
  startedAt: z.number().int().nonnegative().nullable(),
  finishedAt: z.number().int().nonnegative().nullable(),
  exitCode: z.number().int().nullable(),
  signal: z.number().int().positive().nullable(),
  timeoutMs: z.number().int().min(1000).max(MAX_JOB_TIMEOUT_MS),
  logs: JobLogChunk,
}).superRefine((job, context) => {
  const terminal = isTerminalJobState(job.state);
  if (terminal !== (job.finishedAt !== null)) context.addIssue({ code: "custom", path: ["finishedAt"], message: "terminal state and finish time disagree" });
  if ((job.state === "queued") !== (job.startedAt === null)) context.addIssue({ code: "custom", path: ["startedAt"], message: "start time and state disagree" });
  if (job.state === "succeeded" && job.exitCode !== 0) context.addIssue({ code: "custom", path: ["exitCode"], message: "successful job must exit zero" });
});

export type JobStatus = z.infer<typeof JobStatus>;

export function isTerminalJobState(state: JobState) {
  return state === "succeeded" || state === "failed" || state === "cancelled" || state === "timed_out";
}

export function decodeJobLog(chunk: z.infer<typeof JobLogChunk>) {
  return Buffer.from(JobLogChunk.parse(chunk).data, "base64");
}

const transitions: Record<JobState, ReadonlySet<JobState>> = {
  queued: new Set(["running", "failed", "cancelled"]),
  running: new Set(["succeeded", "failed", "cancelled", "timed_out"]),
  succeeded: new Set(),
  failed: new Set(),
  cancelled: new Set(),
  timed_out: new Set(),
};

export function isValidJobTransition(from: JobState, to: JobState) {
  return from === to || transitions[from].has(to);
}

export function isAllowlistedJobEnvironmentName(name: string) {
  return userEnvironmentNames.has(name) || userEnvironmentPrefixes.some((prefix) => name.startsWith(prefix));
}
