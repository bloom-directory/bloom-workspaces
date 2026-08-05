import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { verifyNfsKernelArtifacts } from "./kernel-gate.js";

const created: string[] = [];
afterEach(async () => { await Promise.all(created.splice(0).map((path) => rm(path, { recursive: true, force: true }))); });

describe("NFS kernel artifact gate", () => {
  it("requires matching checksums and every NFSD setting", async () => {
    const directory = await mkdtemp(join(tmpdir(), "bloom-nfs-kernel-"));
    created.push(directory);
    const kernel = join(directory, "vmlinux-test-nfsd");
    const config = `${kernel}.config`;
    const kernelBytes = Buffer.from("kernel");
    const configBytes = Buffer.from([
      "CONFIG_NETWORK_FILESYSTEMS=y", "CONFIG_EXPORTFS=y", "CONFIG_FHANDLE=y",
      "CONFIG_NFSD=y", "CONFIG_NFSD_V4=y", "# CONFIG_NFSD_BLOCKLAYOUT is not set",
      "# CONFIG_NFSD_SCSILAYOUT is not set", "# CONFIG_NFSD_FLEXFILELAYOUT is not set", "",
    ].join("\n"));
    await writeFile(kernel, kernelBytes);
    await writeFile(config, configBytes);
    await writeFile(join(directory, "SHA256SUMS"), `${digest(kernelBytes)}  ${basename(kernel)}\n${digest(configBytes)}  ${basename(config)}\n`);
    await expect(verifyNfsKernelArtifacts(kernel, config)).resolves.toBeUndefined();
    await writeFile(kernel, "tampered");
    await expect(verifyNfsKernelArtifacts(kernel, config)).rejects.toThrow("checksum failed");
    await writeFile(kernel, kernelBytes);
    await writeFile(config, configBytes.toString().replace("CONFIG_NFSD_V4=y", "# CONFIG_NFSD_V4 is not set"));
    await expect(verifyNfsKernelArtifacts(kernel, config)).rejects.toThrow("CONFIG_NFSD_V4=y");
  });
});

function digest(value: Buffer) { return createHash("sha256").update(value).digest("hex"); }
