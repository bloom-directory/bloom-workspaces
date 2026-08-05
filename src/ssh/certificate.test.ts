import { execFile } from "node:child_process";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { signWorkspaceCertificate, validateSshCaPair } from "./certificate.js";

const execute = promisify(execFile);
const created: string[] = [];

afterEach(async () => {
  await Promise.all(created.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("workspace SSH certificate signing", () => {
  it("signs separate least-privilege shell and NFS certificates", async () => {
    const directory = await keys();
    const ca = join(directory, "ca");
    const publicKey = await readFile(join(directory, "user.pub"), "utf8");
    const common = {
      caKeyPath: ca,
      publicKey,
      workspaceId: "123e4567-e89b-42d3-a456-426614174000",
      wallet: "0x1111111111111111111111111111111111111111",
      validAfter: Date.now() - 1_000,
      validBefore: Date.now() + 60_000,
    } as const;
    const shell = await signWorkspaceCertificate({ ...common, mode: "shell" });
    const nfs = await signWorkspaceCertificate({ ...common, mode: "nfs" });
    const shellInfo = await inspect(directory, "shell", shell.certificate);
    const nfsInfo = await inspect(directory, "nfs", nfs.certificate);

    expect(shell.principal).not.toBe(nfs.principal);
    expect(shellInfo).toContain(`Key ID: \"bloom:shell:${common.workspaceId}:${common.wallet}\"`);
    expect(shellInfo).toContain(shell.principal);
    expect(shellInfo).toContain("force-command /usr/local/libexec/bloom-workspace-shell");
    expect(shellInfo).toContain("permit-pty");
    expect(shellInfo).not.toContain("permit-port-forwarding");
    expect(nfsInfo).toContain(`Key ID: \"bloom:nfs:${common.workspaceId}:${common.wallet}\"`);
    expect(nfsInfo).toContain(nfs.principal);
    expect(nfsInfo).toContain("force-command /bin/false");
    expect(nfsInfo).toContain("permit-port-forwarding");
    expect(nfsInfo).not.toContain("permit-pty");
    expect(nfsInfo).not.toContain("permit-agent-forwarding");
    expect(nfsInfo).not.toContain("permit-X11-forwarding");
  });

  it("rejects user private-key material and an exposed operator CA", async () => {
    const directory = await keys();
    const ca = join(directory, "ca");
    const common = {
      caKeyPath: ca,
      workspaceId: "123e4567-e89b-42d3-a456-426614174000",
      wallet: "0x1111111111111111111111111111111111111111",
      mode: "shell" as const,
      validAfter: Date.now() - 1_000,
      validBefore: Date.now() + 60_000,
    };
    const privateKey = await readFile(join(directory, "user"), "utf8");
    await expect(signWorkspaceCertificate({ ...common, publicKey: privateKey })).rejects.toThrow("Invalid SSH public key");
    await chmod(ca, 0o644);
    await expect(signWorkspaceCertificate({ ...common, publicKey: await readFile(join(directory, "user.pub"), "utf8") })).rejects.toThrow("must not be accessible");
  });

  it("rejects a CA public file that does not match the private signer", async () => {
    const first = await keys();
    const second = await keys();
    await expect(validateSshCaPair(join(first, "ca"), await readFile(join(first, "ca.pub"), "utf8"))).resolves.toMatch(/^ssh-ed25519 /);
    await expect(validateSshCaPair(join(first, "ca"), await readFile(join(second, "ca.pub"), "utf8"))).rejects.toThrow("does not match");
  });
});

async function keys() {
  const directory = await mkdtemp(join(tmpdir(), "bloom-ssh-signer-test-"));
  created.push(directory);
  await execute("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", join(directory, "ca")]);
  await execute("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", join(directory, "user")]);
  return directory;
}

async function inspect(directory: string, name: string, certificate: string) {
  const path = join(directory, `${name}-cert.pub`);
  await writeFile(path, `${certificate}\n`, { mode: 0o600 });
  return (await execute("ssh-keygen", ["-L", "-f", path])).stdout;
}
