import { randomBytes } from "node:crypto";
import { execFile } from "node:child_process";
import { lstat, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { tmpdir } from "node:os";
import { promisify } from "node:util";
import { parseSshPublicKey } from "../ssh-public-key.js";
import { MAX_SSH_LEASE_MS, normalizeAccessMode, normalizeWallet, normalizeWorkspaceId, type SshAccessMode, workspacePrincipal } from "./contracts.js";

const execute = promisify(execFile);

export type WorkspaceCertificateSpec = {
  caKeyPath: string;
  publicKey: string;
  workspaceId: string;
  wallet: string;
  mode: SshAccessMode;
  validAfter: number;
  validBefore: number;
};

export type SignedWorkspaceCertificate = {
  certificate: string;
  fingerprint: string;
  principal: string;
  serial: string;
  validAfter: number;
  validBefore: number;
  mode: SshAccessMode;
};

export type WorkspaceCertificateSigner = (spec: WorkspaceCertificateSpec) => Promise<SignedWorkspaceCertificate>;

/** Sign an Ed25519 user key. The caller never supplies or uploads a private key. */
export async function signWorkspaceCertificate(spec: WorkspaceCertificateSpec): Promise<SignedWorkspaceCertificate> {
  const workspaceId = normalizeWorkspaceId(spec.workspaceId);
  const wallet = normalizeWallet(spec.wallet);
  const mode = normalizeAccessMode(spec.mode);
  assertValidity(spec.validAfter, spec.validBefore);
  await validateSshCaKey(spec.caKeyPath);
  const key = parseSshPublicKey(spec.publicKey);
  const principal = workspacePrincipal(workspaceId, wallet, mode);
  const serial = randomCertificateSerial();
  const directory = await mkdtemp(join(tmpdir(), "bloom-workspace-cert-"));
  const publicKeyPath = join(directory, "user.pub");

  try {
    await writeFile(publicKeyPath, `${key.normalized}\n`, { mode: 0o600, flag: "wx" });
    const extensions = mode === "shell"
      ? ["-O", "force-command=/usr/local/libexec/bloom-workspace-shell", "-O", "permit-pty"]
      : ["-O", "force-command=/bin/false", "-O", "permit-port-forwarding"];
    await execute("ssh-keygen", [
      "-q",
      "-s", spec.caKeyPath,
      "-I", `bloom:${mode}:${workspaceId}:${wallet}`,
      "-z", serial,
      "-n", principal,
      "-V", `${epoch(spec.validAfter)}:${epoch(spec.validBefore)}`,
      "-O", "clear",
      ...extensions,
      publicKeyPath,
    ], { timeout: 10_000, maxBuffer: 32 * 1024 });

    const certificate = (await readFile(join(directory, "user-cert.pub"), "utf8")).trim();
    if (!certificate.startsWith("ssh-ed25519-cert-v01@openssh.com ") || certificate.includes("\n")) {
      throw new Error("SSH signer returned an unexpected certificate");
    }
    return { certificate, fingerprint: key.fingerprint, principal, serial, validAfter: spec.validAfter, validBefore: spec.validBefore, mode };
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

export async function validateSshCaKey(path: string) {
  if (!isAbsolute(path) || path.includes("\0") || path.includes("\n") || path.includes("\r")) throw new Error("SSH CA key path must be absolute");
  const stat = await lstat(path);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("SSH CA key must be a regular file");
  if ((stat.mode & 0o077) !== 0) throw new Error("SSH CA key must not be accessible by group or others");
  if (typeof process.getuid === "function" && stat.uid !== process.getuid()) throw new Error("SSH CA key must be owned by the agent user");
}

export async function validateSshCaPair(path: string, publicKey: string) {
  await validateSshCaKey(path);
  const expected = parseSshPublicKey(publicKey).normalized;
  const derived = parseSshPublicKey((await execute("ssh-keygen", ["-y", "-f", path], { timeout: 10_000, maxBuffer: 8 * 1024 })).stdout).normalized;
  if (derived !== expected) throw new Error("SSH CA public key does not match the configured private key");
  return expected;
}

function assertValidity(validAfter: number, validBefore: number) {
  if (!Number.isSafeInteger(validAfter) || !Number.isSafeInteger(validBefore) || validBefore <= validAfter) throw new Error("Invalid SSH certificate validity");
  // The signer backdates certificates by five seconds for ordinary clock skew;
  // the usable lease itself remains bounded by MAX_SSH_LEASE_MS.
  if (validBefore - validAfter > MAX_SSH_LEASE_MS + 5_000) throw new Error("SSH certificate validity exceeds the workspace maximum");
}

function epoch(milliseconds: number) {
  return `0x${Math.floor(milliseconds / 1000).toString(16)}`;
}

function randomCertificateSerial() {
  return (randomBytes(8).readBigUInt64BE() & 0x7fff_ffff_ffff_ffffn).toString(10);
}
