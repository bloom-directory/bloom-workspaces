import { generateKeyPairSync } from "node:crypto";
import { PassThrough } from "node:stream";
import { describe, expect, it, vi } from "vitest";
import { guestSshdPlan } from "../ssh/guest-sshd.js";
import { SshLeaseManager } from "../ssh/lease-manager.js";
import { workspacePrincipal } from "../ssh/contracts.js";
import { createSshClientArgv, workspaceKnownHostsLine } from "../ssh/client-plan.js";
import { sshPlatformCapability } from "../ssh/platform.js";
import { createNfsExportPlan } from "../nfs/export-plan.js";
import { createNfsClientPlan, nfsPlatformCapability } from "../nfs/client-plan.js";
import { nativeNfsDecision } from "../nfs/capability.js";

const WORKSPACE_A = "123e4567-e89b-42d3-a456-426614174000";
const WORKSPACE_B = "223e4567-e89b-42d3-a456-426614174001";
const WALLET_A = "0x1111111111111111111111111111111111111111";
const WALLET_B = "0x2222222222222222222222222222222222222222";

describe("SSH gateway lease boundary", () => {
  it("issues wallet/workspace/mode scoped leases and keeps private keys client-side", async () => {
    let now = 1_800_000_000_000;
    const signer = vi.fn(async (spec) => ({
      certificate: "ssh-ed25519-cert-v01@openssh.com AAAA",
      fingerprint: "SHA256:test",
      principal: workspacePrincipal(spec.workspaceId, spec.wallet, spec.mode),
      serial: "1",
      validAfter: spec.validAfter,
      validBefore: spec.validBefore,
      mode: spec.mode,
    }));
    const streams: PassThrough[] = [];
    const manager = new SshLeaseManager({
      caKeyPath: "/run/secrets/user_ca",
      privateSocketRoot: "/run/bloom-workspaces/vm",
      maxLeaseMs: 60_000,
      clock: () => now,
      signer,
      connector: async () => {
        const stream = new PassThrough();
        streams.push(stream);
        return stream;
      },
    });
    const publicKey = ed25519PublicKey();
    const grant = await manager.issue({ workspaceId: WORKSPACE_A, wallet: WALLET_A, publicKey, mode: "nfs", workspaceLeaseExpiresAt: now + 20_000, endpoint: { kind: "unix", path: `/run/bloom-workspaces/vm/${WORKSPACE_A}/ssh.sock` } });
    expect(grant.validBefore).toBe(now + 20_000);
    expect(grant).not.toHaveProperty("privateKey");
    expect(signer).toHaveBeenCalledWith(expect.objectContaining({ publicKey, workspaceId: WORKSPACE_A, wallet: WALLET_A, mode: "nfs" }));
    expect(grant.principal).not.toBe(workspacePrincipal(WORKSPACE_A, WALLET_B, "nfs"));

    await expect(manager.openTunnel({ leaseId: grant.leaseId, workspaceId: WORKSPACE_B, wallet: WALLET_A, mode: "nfs", accessToken: grant.accessToken })).rejects.toThrow("scope mismatch");
    await expect(manager.openTunnel({ leaseId: grant.leaseId, workspaceId: WORKSPACE_A, wallet: WALLET_B, mode: "nfs", accessToken: grant.accessToken })).rejects.toThrow("scope mismatch");
    await expect(manager.openTunnel({ leaseId: grant.leaseId, workspaceId: WORKSPACE_A, wallet: WALLET_A, mode: "shell", accessToken: grant.accessToken })).rejects.toThrow("scope mismatch");
    const stream = await manager.openTunnel({ leaseId: grant.leaseId, workspaceId: WORKSPACE_A, wallet: WALLET_A, mode: "nfs", accessToken: grant.accessToken });
    now += 20_001;
    manager.sweepExpired();
    expect(stream.destroyed).toBe(true);
    await expect(manager.openTunnel({ leaseId: grant.leaseId, workspaceId: WORKSPACE_A, wallet: WALLET_A, mode: "nfs", accessToken: grant.accessToken })).rejects.toThrow("expired or revoked");
    manager.stop();
  });

  it("rejects public endpoints, path escape, injection, invalid tokens, and excess sessions", async () => {
    let finishConnection: ((stream: PassThrough) => void) | undefined;
    const signer = vi.fn(async (spec) => ({ certificate: "ssh-ed25519-cert-v01@openssh.com AAAA", fingerprint: "SHA256:test", principal: workspacePrincipal(spec.workspaceId, spec.wallet, spec.mode), serial: "2", validAfter: spec.validAfter, validBefore: spec.validBefore, mode: spec.mode }));
    const manager = new SshLeaseManager({
      caKeyPath: "/run/secrets/user_ca",
      privateSocketRoot: "/run/bloom-workspaces/vm",
      maxConnectionsPerLease: 1,
      signer,
      connector: async () => new Promise<PassThrough>((resolve) => { finishConnection = resolve; }),
    });
    const common = { workspaceId: WORKSPACE_A, wallet: WALLET_A, publicKey: ed25519PublicKey(), mode: "shell" as const, workspaceLeaseExpiresAt: Date.now() + 60_000 };
    await expect(manager.issue({ ...common, endpoint: { kind: "tcp", host: "127.0.0.1", port: 0 } })).rejects.toThrow("Invalid private SSH endpoint port");
    await expect(manager.issue({ ...common, endpoint: { kind: "tcp", host: "0.0.0.0", port: 22 } as never })).rejects.toThrow("host-private");
    await expect(manager.issue({ ...common, endpoint: { kind: "unix", path: "/run/bloom-workspaces/escape.sock" } })).rejects.toThrow("escapes");
    const grant = await manager.issue({ ...common, endpoint: { kind: "tcp", host: "127.0.0.1", port: 2201 } });
    await expect(manager.openTunnel({ leaseId: grant.leaseId, workspaceId: WORKSPACE_A, wallet: WALLET_A, mode: "shell", accessToken: "x".repeat(32) })).rejects.toThrow("Invalid SSH lease token");
    const first = manager.openTunnel({ leaseId: grant.leaseId, workspaceId: WORKSPACE_A, wallet: WALLET_A, mode: "shell", accessToken: grant.accessToken });
    await Promise.resolve();
    await expect(manager.openTunnel({ leaseId: grant.leaseId, workspaceId: WORKSPACE_A, wallet: WALLET_A, mode: "shell", accessToken: grant.accessToken })).rejects.toThrow("connection limit");
    finishConnection?.(new PassThrough());
    await first;
    manager.stop();
  });

  it("emits disjoint server restrictions for shell and NFS certificates", () => {
    const caPublicKey = ed25519PublicKey();
    const shell = guestSshdPlan({ workspaceId: WORKSPACE_A, wallet: WALLET_A, mode: "shell", caPublicKey });
    const nfs = guestSshdPlan({ workspaceId: WORKSPACE_A, wallet: WALLET_A, mode: "nfs", caPublicKey });
    const combined = guestSshdPlan({ workspaceId: WORKSPACE_A, wallet: WALLET_A, modes: ["shell", "nfs"], caPublicKey });
    expect(shell.argv).toContain("DisableForwarding=yes");
    expect(shell.argv).toContain("ForceCommand=/usr/local/libexec/bloom-workspace-shell");
    expect(shell.argv.join(" ")).not.toContain("2049");
    expect(nfs.argv).toContain("AllowTcpForwarding=local");
    expect(nfs.argv).toContain("PermitOpen=127.0.0.1:2049");
    expect(nfs.argv).toContain("PermitTTY=no");
    expect(nfs.argv).toContain("MaxSessions=0");
    expect(nfs.principal).not.toBe(shell.principal);
    expect(nfs.hostKeygen.args).toEqual(["-q", "-t", "ed25519", "-N", "", "-f", "/run/bloom/ssh/ssh_host_ed25519_key"]);
    expect(nfs.files).toContainEqual({ path: "/run/bloom/ssh/user_ca.pub", mode: 0o644, content: `${caPublicKey}\n` });
    expect(combined.principals).toEqual([shell.principal, nfs.principal]);
    expect(combined.argv).toContain("AllowTcpForwarding=local");
    expect(combined.argv).toContain("PermitOpen=127.0.0.1:2049");
    expect(combined.argv).toContain("PermitTTY=yes");
    expect(combined.argv).not.toContain("ForceCommand=/usr/local/libexec/bloom-workspace-shell");
    expect(combined.files.find((file) => file.path.endsWith("authorized_principals"))?.content).toBe(`${shell.principal}\n${nfs.principal}\n`);
  });

  it("keeps the bearer token out of SSH argv and strictly pins the guest host key", () => {
    const argv = createSshClientArgv(clientConnection("shell"));
    expect(argv.join(" ")).toContain("ProxyCommand=/opt/bloom/bin/bloom-ssh-proxy");
    expect(argv.join(" ")).toContain("--token-file /home/me/.bloom/ssh-token");
    expect(argv.join(" ")).not.toContain("secret-token");
    expect(argv).toContain("StrictHostKeyChecking=yes");
    expect(argv).toContain(`HostKeyAlias=bloom-${WORKSPACE_A}`);
    expect(workspaceKnownHostsLine(WORKSPACE_A, `${ed25519PublicKey()} disposable-comment`)).toMatchObject({ alias: `bloom-${WORKSPACE_A}`, line: expect.stringMatching(new RegExp(`^bloom-${WORKSPACE_A} ssh-ed25519 [A-Za-z0-9+/]+=*\\n$`)), fingerprint: expect.stringMatching(/^SHA256:/) });
    expect(() => createSshClientArgv({ ...clientConnection("shell"), gatewayOrigin: "https://ssh.example/;touch-pwn" })).toThrow("HTTPS origin");
    expect(() => createSshClientArgv({ ...clientConnection("shell"), proxyHelperPath: "/opt/bloom/proxy;touch" })).toThrow("not safe");
  });

  it("uses browser terminal fallback on mobile and gates Windows tooling", () => {
    expect(sshPlatformCapability("linux")).toMatchObject({ status: "supported" });
    expect(sshPlatformCapability("macos")).toMatchObject({ status: "supported" });
    expect(sshPlatformCapability("windows")).toMatchObject({ status: "conditional", fallback: "browser-terminal" });
    expect(sshPlatformCapability("android")).toMatchObject({ status: "fallback", fallback: "browser-terminal" });
    expect(sshPlatformCapability("ios")).toMatchObject({ status: "fallback", fallback: "browser-terminal" });
  });
});

describe("native NFS over SSH", () => {
  it("exports only /workspace to loopback with squashed identity and NFSv4", () => {
    const plan = createNfsExportPlan({ workspaceId: WORKSPACE_A, runtime: "qemu", nfsdBuiltIn: true, persistentWorkspace: true });
    expect(plan.listen).toEqual({ host: "127.0.0.1", port: 2049 });
    expect(plan.prepare.flatMap((command) => command.args).join(" ")).toContain("127.0.0.1:/workspace");
    expect(plan.prepare.flatMap((command) => command.args).join(" ")).toContain("all_squash");
    expect(plan.prepare).toContainEqual({ program: "/bin/hostname", args: [`bloom-${WORKSPACE_A}`] });
    expect(plan.activate.flatMap((command) => command.args)).toContain("127.0.0.1");
    expect(plan.activate.flatMap((command) => command.args)).toContain("--leasetime");
    expect(plan.activate.flatMap((command) => command.args)).not.toContain("--scope");
    expect(JSON.stringify(plan)).not.toContain("0.0.0.0");
    expect(() => createNfsExportPlan({ workspaceId: WORKSPACE_A, runtime: "firecracker", nfsdBuiltIn: false, persistentWorkspace: true })).toThrow("QEMU reference");
    expect(() => createNfsExportPlan({ workspaceId: WORKSPACE_A, runtime: "qemu", nfsdBuiltIn: false, persistentWorkspace: true })).toThrow("does not provide NFSD");
    expect(() => createNfsExportPlan({ workspaceId: WORKSPACE_A, runtime: "qemu", nfsdBuiltIn: true, persistentWorkspace: false })).toThrow("persistent");
  });

  it("builds injection-safe local-forward and mount argv without a public NFS address", () => {
    const plan = createNfsClientPlan({ ...clientConnection("nfs"), platform: "linux", localPort: 30490, mountPoint: "/mnt/workspace" });
    expect(plan.sshTunnelArgv).toContain("127.0.0.1:30490:127.0.0.1:2049");
    expect(plan.sshTunnelArgv).toContain("StrictHostKeyChecking=yes");
    expect(plan.mountArgv).toContain("127.0.0.1:/");
    expect(JSON.stringify(plan)).not.toContain("0.0.0.0");
    expect(() => createNfsClientPlan({ ...clientConnection("nfs"), platform: "linux", gatewayOrigin: "https://ssh.example/;pwn", localPort: 30490, mountPoint: "/mnt" })).toThrow("HTTPS origin");
    expect(() => createNfsClientPlan({ ...clientConnection("nfs"), platform: "linux", localPort: 2049, mountPoint: "/mnt\n--fake" })).toThrow("Invalid mount point");
  });

  it("degrades honestly by runtime and client platform", () => {
    expect(nfsPlatformCapability("android")).toMatchObject({ status: "fallback", fallback: "browser-files" });
    expect(nfsPlatformCapability("ios")).toMatchObject({ status: "fallback", fallback: "browser-files" });
    expect(nfsPlatformCapability("windows")).toMatchObject({ status: "conditional", requiresAdmin: true });
    expect(nativeNfsDecision({ runtime: "firecracker", persistentWorkspace: true, sshGateway: true, nfsdBuiltIn: false, platform: "linux" })).toMatchObject({ status: "fallback", runtime: "firecracker" });
    expect(nativeNfsDecision({ runtime: "qemu", persistentWorkspace: true, sshGateway: true, nfsdBuiltIn: true, platform: "macos" })).toMatchObject({ status: "supported", transport: "nfs4-over-ssh" });
  });
});

function ed25519PublicKey() {
  const { publicKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ type: "spki", format: "der" });
  const raw = spki.subarray(-32);
  const type = Buffer.from("ssh-ed25519");
  const blob = Buffer.concat([length(type), type, length(raw), raw]);
  return `ssh-ed25519 ${blob.toString("base64")}`;
}

function clientConnection(mode: "shell" | "nfs") {
  return {
    gatewayOrigin: "https://workspaces.example",
    workspaceId: WORKSPACE_A,
    leaseId: "323e4567-e89b-42d3-a456-426614174002",
    mode,
    proxyHelperPath: "/opt/bloom/bin/bloom-ssh-proxy",
    tokenFilePath: "/home/me/.bloom/ssh-token",
    privateKeyPath: "/home/me/.ssh/id_ed25519",
    certificatePath: "/tmp/workspace-cert.pub",
    knownHostsPath: "/home/me/.ssh/known_hosts",
  } as const;
}

function length(value: Buffer) {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32BE(value.byteLength);
  return buffer;
}
