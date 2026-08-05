import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";

const REQUIRED = [
  "CONFIG_NETWORK_FILESYSTEMS=y",
  "CONFIG_EXPORTFS=y",
  "CONFIG_FHANDLE=y",
  "CONFIG_NFSD=y",
  "CONFIG_NFSD_V4=y",
  "# CONFIG_NFSD_BLOCKLAYOUT is not set",
  "# CONFIG_NFSD_SCSILAYOUT is not set",
  "# CONFIG_NFSD_FLEXFILELAYOUT is not set",
] as const;

/** Refuse to advertise NFS unless the selected kernel and config match the
 * checksums emitted by the pinned builder and the required NFSD settings. */
export async function verifyNfsKernelArtifacts(kernelPath: string, configPath: string) {
  const [kernel, config, manifest] = await Promise.all([
    readFile(kernelPath),
    readFile(configPath),
    readFile(join(dirname(configPath), "SHA256SUMS"), "utf8"),
  ]);
  const lines = new Set(config.toString("utf8").split(/\r?\n/));
  for (const setting of REQUIRED) if (!lines.has(setting)) throw new Error(`NFS kernel config is missing required setting: ${setting}`);
  if (lines.has("CONFIG_NFSD_PNFS=y")) throw new Error("NFS kernel config unexpectedly enables pNFS");
  const expected = parseManifest(manifest);
  for (const [path, contents] of [[kernelPath, kernel], [configPath, config]] as const) {
    const name = basename(path);
    const digest = createHash("sha256").update(contents).digest("hex");
    if (expected.get(name) !== digest) throw new Error(`NFS kernel artifact checksum failed: ${name}`);
  }
}

function parseManifest(source: string) {
  const result = new Map<string, string>();
  for (const line of source.split(/\r?\n/)) {
    if (!line) continue;
    const match = line.match(/^([0-9a-f]{64})  ([A-Za-z0-9._-]+)$/);
    if (!match?.[1] || !match[2] || result.has(match[2])) throw new Error("Invalid NFS kernel checksum manifest");
    result.set(match[2], match[1]);
  }
  return result;
}
