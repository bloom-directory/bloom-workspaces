export const MAX_UPLOAD_BYTES = 8 * 1024 * 1024;
export const MAX_JOB_TIMEOUT_MS = 2 * 60 * 60_000;

export const JOB_ENVIRONMENT_NAMES = [
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
] as const;

const JOB_ENVIRONMENT_PREFIXES = ["APP_", "JOB_", "TEST_"] as const;

export type EnvironmentRow = { name: string; value: string };

export function parseStructuredArgv(source: string): string[] {
  let value: unknown;
  try { value = JSON.parse(source); }
  catch { throw new Error('Arguments must be valid JSON, for example ["npm", "test"].'); }
  if (!Array.isArray(value) || value.length === 0 || value.length > 64 || value.some((item) => typeof item !== "string" || item.length === 0 || item.includes("\0"))) {
    throw new Error("Arguments must be a JSON array of 1–64 non-empty strings.");
  }
  if (value.some((item) => item.length > 4096) || value.reduce((sum, item) => sum + new TextEncoder().encode(item).byteLength, 0) > 32 * 1024) {
    throw new Error("Arguments exceed the job size limit.");
  }
  return value;
}

export function normalizeWorkspacePath(source: string, options: { allowRoot?: boolean } = {}): string {
  const path = source.trim();
  if (options.allowRoot && path === ".") return path;
  if (!path || path.length > 4096 || path.startsWith("/") || path.endsWith("/") || path.includes("\\") || path.includes("\0")) {
    throw new Error("Use a relative path below /workspace.");
  }
  if (path.split("/").some((part) => part === "" || part === "." || part === "..")) {
    throw new Error("The path cannot contain empty, . or .. segments.");
  }
  return path;
}

export function isAllowlistedEnvironmentName(name: string) {
  return /^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(name)
    && (JOB_ENVIRONMENT_NAMES.some((allowed) => allowed === name) || JOB_ENVIRONMENT_PREFIXES.some((prefix) => name.startsWith(prefix)));
}

export function buildJobEnvironment(rows: EnvironmentRow[]): Record<string, string> {
  const environment: Record<string, string> = {};
  let bytes = 0;
  for (const row of rows) {
    const name = row.name.trim();
    if (!name && !row.value) continue;
    if (!isAllowlistedEnvironmentName(name)) {
      throw new Error(`${name || "Environment name"} is not allowlisted. Use a listed name or APP_, JOB_, or TEST_ prefix.`);
    }
    if (Object.hasOwn(environment, name)) throw new Error(`${name} is duplicated.`);
    if (row.value.includes("\0") || row.value.length > 8192) throw new Error(`${name} has an invalid or oversized value.`);
    environment[name] = row.value;
    bytes += new TextEncoder().encode(name + row.value).byteLength;
  }
  if (Object.keys(environment).length > 64 || bytes > 32 * 1024) throw new Error("Environment exceeds the job limit.");
  return environment;
}

export function parseTimeoutSeconds(source: string): number {
  const seconds = Number(source);
  if (!Number.isInteger(seconds) || seconds < 1 || seconds > MAX_JOB_TIMEOUT_MS / 1000) {
    throw new Error("Timeout must be between 1 second and 2 hours.");
  }
  return seconds * 1000;
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "Unknown";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let value = bytes / 1024;
  let index = 0;
  while (value >= 1024 && index < units.length - 1) { value /= 1024; index += 1; }
  return `${value >= 10 ? value.toFixed(0) : value.toFixed(1)} ${units[index]}`;
}

export type ConnectionMethod = {
  kind: "ssh" | "nfs";
  status: "available" | "disabled" | "unsupported";
  reason: string;
  command?: string;
  instructions: string[];
};

/**
 * The connection API may evolve independently of the browser. Only explicitly
 * reviewed display fields are accepted; tokens, keys, and arbitrary object
 * properties are deliberately ignored.
 */
export function readConnectionMethods(value: unknown): ConnectionMethod[] {
  if (!isRecord(value)) return [];
  return (["ssh", "nfs"] as const).flatMap((kind) => {
    const candidate = value[kind];
    if (!isRecord(candidate)) return [];
    const rawStatus = candidate.status;
    const status = rawStatus === "available" || rawStatus === "disabled" || rawStatus === "unsupported" ? rawStatus : undefined;
    if (!status) return [];
    const reason = typeof candidate.reason === "string" ? candidate.reason.slice(0, 1000) : "No connection details were supplied.";
    const command = typeof candidate.command === "string" && candidate.command.length <= 4096 ? candidate.command : undefined;
    const instructions = Array.isArray(candidate.instructions)
      ? candidate.instructions.filter((item): item is string => typeof item === "string").slice(0, 12).map((item) => item.slice(0, 1000))
      : [];
    return [{ kind, status, reason, ...(command ? { command } : {}), instructions }];
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
