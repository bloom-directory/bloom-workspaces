import { randomBytes } from "node:crypto";
import { resolve } from "node:path";
import { z } from "zod";

const booleanString = z.enum(["0", "1"]).default("0").transform((value) => value === "1");
const integer = (fallback: number) => z.coerce.number().int().positive().default(fallback);

const Env = z.object({
  BLOOM_ORIGIN: z.string().url().default("http://127.0.0.1:8787"),
  BLOOM_PORT: integer(8787),
  BLOOM_DATABASE: z.string().default("./data/control.sqlite"),
  BLOOM_AGENT_SOCKET: z.string().default("./data/agent.sock"),
  BLOOM_AGENT_TOKEN: z.string().default("local-agent-token-change-me"),
  BLOOM_SESSION_SECRET: z.string().default("local-session-secret-change-me"),
  BLOOM_RUNTIME: z.enum(["process", "qemu", "firecracker"]).default("process"),
  BLOOM_DEV_AUTH: booleanString,
  BLOOM_PUBLIC_MODE: booleanString,
  BLOOM_TRUSTED_PROXY_HOPS: z.coerce.number().int().min(0).max(5).default(0),
  BLOOM_TURNSTILE_SITE_KEY: z.string().optional(),
  BLOOM_TURNSTILE_SECRET: z.string().optional(),
  BLOOM_AUTH_CHAIN_ID: integer(1),
  BLOOM_LEASE_MINUTES: integer(30),
  BLOOM_MAX_LEASE_MINUTES: integer(120),
  BLOOM_MAX_RUNNING: integer(10),
  BLOOM_MAX_QUEUE: integer(100),
  BLOOM_MAX_ACTIVE_PER_WALLET: integer(1),
  BLOOM_MAX_ACTIVE_PER_IP: integer(2),
  BLOOM_DAILY_PER_WALLET: integer(3),
  BLOOM_DAILY_PER_IP: integer(5),
  BLOOM_DATA_DIR: z.string().default("./data/workspaces"),
  BLOOM_VM_KERNEL: z.string().default("./artifacts/vmlinux-6.1.155"),
  BLOOM_VM_ROOTFS: z.string().default("./artifacts/bloom-alpine.ext4"),
  BLOOM_FIRECRACKER_BIN: z.string().default("./artifacts/firecracker"),
  BLOOM_FIRECRACKER_JAILER_BIN: z.string().default("./artifacts/jailer"),
  BLOOM_FIRECRACKER_JAILED: booleanString,
  BLOOM_JAILER_CHROOT_BASE: z.string().default("/run/bloom-jailer"),
  BLOOM_RUNTIME_SOCKET_DIR: z.string().default("/tmp/bloom-workspaces-vm"),
  BLOOM_QEMU_BIN: z.string().default("qemu-system-x86_64"),
  BLOOM_VM_MEMORY_MIB: z.coerce.number().int().min(128).max(8192).default(512),
  BLOOM_VM_VCPUS: z.coerce.number().int().min(1).max(8).default(1),
  BLOOM_VM_EGRESS: z.enum(["none", "internet"]).default("none"),
});

export type Config = ReturnType<typeof loadConfig>;

export function loadConfig(source: NodeJS.ProcessEnv = process.env, role: "all" | "control" | "agent" = "all") {
  const env = Env.parse(source);
  const origin = new URL(env.BLOOM_ORIGIN);
  const config = {
    origin: origin.origin,
    port: env.BLOOM_PORT,
    databasePath: resolve(env.BLOOM_DATABASE),
    agentSocket: resolve(env.BLOOM_AGENT_SOCKET),
    agentToken: env.BLOOM_AGENT_TOKEN,
    sessionSecret: env.BLOOM_SESSION_SECRET,
    runtime: env.BLOOM_RUNTIME,
    devAuth: env.BLOOM_DEV_AUTH,
    publicMode: env.BLOOM_PUBLIC_MODE,
    trustedProxyHops: env.BLOOM_TRUSTED_PROXY_HOPS,
    turnstileSiteKey: env.BLOOM_TURNSTILE_SITE_KEY,
    turnstileSecret: env.BLOOM_TURNSTILE_SECRET,
    authChainId: env.BLOOM_AUTH_CHAIN_ID,
    leaseMs: env.BLOOM_LEASE_MINUTES * 60_000,
    maxLeaseMs: env.BLOOM_MAX_LEASE_MINUTES * 60_000,
    maxRunning: env.BLOOM_MAX_RUNNING,
    maxQueue: env.BLOOM_MAX_QUEUE,
    maxActivePerWallet: env.BLOOM_MAX_ACTIVE_PER_WALLET,
    maxActivePerIp: env.BLOOM_MAX_ACTIVE_PER_IP,
    dailyPerWallet: env.BLOOM_DAILY_PER_WALLET,
    dailyPerIp: env.BLOOM_DAILY_PER_IP,
    dataDir: resolve(env.BLOOM_DATA_DIR),
    vmKernel: resolve(env.BLOOM_VM_KERNEL),
    vmRootfs: resolve(env.BLOOM_VM_ROOTFS),
    firecrackerBin: resolve(env.BLOOM_FIRECRACKER_BIN),
    firecrackerJailerBin: resolve(env.BLOOM_FIRECRACKER_JAILER_BIN),
    firecrackerJailed: env.BLOOM_FIRECRACKER_JAILED,
    jailerChrootBase: resolve(env.BLOOM_JAILER_CHROOT_BASE),
    runtimeSocketDir: resolve(env.BLOOM_RUNTIME_SOCKET_DIR),
    qemuBin: env.BLOOM_QEMU_BIN.includes("/") ? resolve(env.BLOOM_QEMU_BIN) : env.BLOOM_QEMU_BIN,
    vmMemoryMib: env.BLOOM_VM_MEMORY_MIB,
    vmVcpus: env.BLOOM_VM_VCPUS,
    vmEgress: env.BLOOM_VM_EGRESS,
    sessionTtlMs: 12 * 60 * 60_000,
    challengeTtlMs: 5 * 60_000,
    agentRequestTimeoutMs: 15_000,
  } as const;

  assertSafeConfiguration(config, role);
  return config;
}

function assertSafeConfiguration(config: {
  origin: string;
  runtime: string;
  devAuth: boolean;
  publicMode: boolean;
  turnstileSiteKey: string | undefined;
  turnstileSecret: string | undefined;
  sessionSecret: string;
  agentToken: string;
  vmEgress: string;
  firecrackerJailed: boolean;
}, role: "all" | "control" | "agent") {
  if (!config.publicMode) return;
  const errors: string[] = [];
  if (role !== "agent" && !config.origin.startsWith("https://")) errors.push("BLOOM_ORIGIN must use HTTPS");
  if (role !== "agent" && config.devAuth) errors.push("BLOOM_DEV_AUTH must be disabled");
  if (config.runtime === "process") errors.push("the process runtime is forbidden");
  if (role !== "agent" && (!config.turnstileSiteKey || !config.turnstileSecret)) errors.push("Turnstile keys are required");
  if (role !== "agent" && (config.sessionSecret.includes("change-me") || Buffer.byteLength(config.sessionSecret) < 32)) errors.push("BLOOM_SESSION_SECRET must be at least 32 random bytes");
  if (config.agentToken.includes("change-me") || Buffer.byteLength(config.agentToken) < 32) errors.push("BLOOM_AGENT_TOKEN must be at least 32 random bytes");
  if (config.vmEgress === "internet") errors.push("unfiltered QEMU user-mode egress is forbidden; deploy an audited egress proxy first");
  if (config.runtime === "firecracker" && !config.firecrackerJailed) errors.push("Firecracker must run through the jailer");
  if (errors.length) throw new Error(`Unsafe public configuration: ${errors.join("; ")}`);
}

export function randomSecret() {
  return randomBytes(32).toString("base64url");
}
