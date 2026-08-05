import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { parseSshPublicKey } from "../ssh-public-key.js";

const execute = promisify(execFile);
const WORKSPACE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export type SshCertificateSpec = {
  caKeyPath: string;
  publicKey: string;
  workspaceId: string;
  validAfter: number;
  validBefore: number;
  permitPortForwarding: boolean;
};

export async function signWorkspaceSshCertificate(spec: SshCertificateSpec) {
  if (!WORKSPACE_ID.test(spec.workspaceId)) throw new Error("Invalid workspace id");
  if (!Number.isSafeInteger(spec.validAfter) || !Number.isSafeInteger(spec.validBefore) || spec.validBefore <= spec.validAfter) throw new Error("Invalid SSH certificate validity");
  if (spec.validBefore - spec.validAfter > 2 * 60 * 60_000) throw new Error("SSH certificate validity exceeds the workspace maximum");
  const key = parseSshPublicKey(spec.publicKey);
  const directory = await mkdtemp(join(tmpdir(), "bloom-ssh-cert-"));
  const publicKeyPath = join(directory, "workspace.pub");
  try {
    await writeFile(publicKeyPath, `${key.normalized}\n`, { mode: 0o600 });
    const validAfterSeconds = Math.floor(spec.validAfter / 1000);
    const validBeforeSeconds = Math.floor(spec.validBefore / 1000);
    const extensions = ["-O", "clear", "-O", "permit-pty"];
    if (spec.permitPortForwarding) extensions.push("-O", "permit-port-forwarding");
    await execute("ssh-keygen", [
      "-q",
      "-s", spec.caKeyPath,
      "-I", `bloom-workspace:${spec.workspaceId}`,
      "-n", spec.workspaceId,
      "-V", `0x${validAfterSeconds.toString(16)}:0x${validBeforeSeconds.toString(16)}`,
      ...extensions,
      publicKeyPath,
    ], { timeout: 10_000, maxBuffer: 16 * 1024 });
    const certificate = (await readFile(join(directory, "workspace-cert.pub"), "utf8")).trim();
    if (!certificate.startsWith("ssh-ed25519-cert-v01@openssh.com ")) throw new Error("SSH signer returned an unexpected certificate");
    return { certificate, fingerprint: key.fingerprint, principal: spec.workspaceId, validAfter: spec.validAfter, validBefore: spec.validBefore };
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}
