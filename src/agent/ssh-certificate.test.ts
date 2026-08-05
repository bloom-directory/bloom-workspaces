import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { signWorkspaceSshCertificate } from "./ssh-certificate.js";

const execute = promisify(execFile);
const directories: string[] = [];
afterEach(async () => { await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true }))); });

describe("workspace SSH certificates", () => {
  it("signs only the workspace principal for a lease-bounded interval", async () => {
    const directory = await mkdtemp(join(tmpdir(), "bloom-ssh-ca-test-"));
    directories.push(directory);
    const ca = join(directory, "ca");
    const user = join(directory, "user");
    await execute("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", ca]);
    await execute("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", user]);
    const publicKey = await readFile(`${user}.pub`, "utf8");
    const now = Date.now() - 5_000;
    const workspaceId = "123e4567-e89b-42d3-a456-426614174000";
    const result = await signWorkspaceSshCertificate({
      caKeyPath: ca,
      publicKey,
      workspaceId,
      validAfter: now,
      validBefore: now + 60_000,
      permitPortForwarding: true,
    });
    const certificatePath = join(directory, "signed.pub");
    await import("node:fs/promises").then(({ writeFile }) => writeFile(certificatePath, `${result.certificate}\n`));
    const { stdout } = await execute("ssh-keygen", ["-L", "-f", certificatePath]);
    expect(stdout).toContain(`Key ID: \"bloom-workspace:${workspaceId}\"`);
    expect(stdout).toContain(workspaceId);
    expect(stdout).toContain("permit-port-forwarding");
    expect(stdout).toContain("permit-pty");
    expect(stdout).not.toContain("permit-agent-forwarding");
    expect(stdout).not.toContain("permit-X11-forwarding");
  });

  it("rejects validity beyond the maximum workspace lease", async () => {
    await expect(signWorkspaceSshCertificate({
      caKeyPath: "/unused",
      publicKey: "invalid",
      workspaceId: "123e4567-e89b-42d3-a456-426614174000",
      validAfter: 0,
      validBefore: 3 * 60 * 60_000,
      permitPortForwarding: false,
    })).rejects.toThrow(/validity exceeds/);
  });
});
