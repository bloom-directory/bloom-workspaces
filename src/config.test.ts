import { describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";

describe("public configuration guardrails", () => {
  it("rejects the process runtime in public mode", () => {
    expect(() => loadConfig({
      BLOOM_PUBLIC_MODE: "1",
      BLOOM_ORIGIN: "https://workspaces.example.com",
      BLOOM_RUNTIME: "process",
      BLOOM_SESSION_SECRET: "s".repeat(32),
      BLOOM_AGENT_TOKEN: "a".repeat(32),
      BLOOM_TURNSTILE_SITE_KEY: "site",
      BLOOM_TURNSTILE_SECRET: "secret",
    })).toThrow(/process runtime/);
  });

  it("rejects public Firecracker without the jailer", () => {
    expect(() => loadConfig({
      BLOOM_PUBLIC_MODE: "1",
      BLOOM_ORIGIN: "https://workspaces.example.com",
      BLOOM_RUNTIME: "firecracker",
      BLOOM_SESSION_SECRET: "s".repeat(32),
      BLOOM_AGENT_TOKEN: "a".repeat(32),
      BLOOM_TURNSTILE_SITE_KEY: "site",
      BLOOM_TURNSTILE_SECRET: "secret",
    })).toThrow(/jailer/);
  });

  it("accepts a capacity-limited, air-gapped QEMU public pilot", () => {
    const config = loadConfig({
      BLOOM_PUBLIC_MODE: "1",
      BLOOM_ORIGIN: "https://workspaces.example.com",
      BLOOM_RUNTIME: "qemu",
      BLOOM_SESSION_SECRET: "s".repeat(32),
      BLOOM_AGENT_TOKEN: "a".repeat(32),
      BLOOM_TURNSTILE_SITE_KEY: "site",
      BLOOM_TURNSTILE_SECRET: "secret",
    });
    expect(config.publicMode).toBe(true);
  });

  it("does not require browser secrets in the public node-agent process", () => {
    const config = loadConfig({
      BLOOM_PUBLIC_MODE: "1",
      BLOOM_RUNTIME: "qemu",
      BLOOM_AGENT_TOKEN: "a".repeat(32),
    }, "agent");
    expect(config.runtime).toBe("qemu");
    expect(config.turnstileSecret).toBeUndefined();
  });

  it("accepts controlled public egress but continues to reject raw Internet access", () => {
    const base = {
      BLOOM_PUBLIC_MODE: "1",
      BLOOM_ORIGIN: "https://workspaces.example.com",
      BLOOM_RUNTIME: "qemu",
      BLOOM_SESSION_SECRET: "s".repeat(32),
      BLOOM_AGENT_TOKEN: "a".repeat(32),
      BLOOM_TURNSTILE_SITE_KEY: "site",
      BLOOM_TURNSTILE_SECRET: "secret",
    };
    expect(loadConfig({ ...base, BLOOM_VM_EGRESS: "controlled" }).vmEgress).toBe("controlled");
    expect(() => loadConfig({ ...base, BLOOM_VM_EGRESS: "internet" })).toThrow(/unfiltered/);
  });

  it("bounds and parses the controlled egress policy", () => {
    const config = loadConfig({
      BLOOM_EGRESS_ALLOWED_HOSTS: "registry.npmjs.org, *.npmjs.org",
      BLOOM_EGRESS_MAX_CONNECTIONS: "12",
      BLOOM_EGRESS_MAX_MIB_PER_CONNECTION: "64",
    });
    expect(config.egressAllowedHosts).toEqual(["registry.npmjs.org", "*.npmjs.org"]);
    expect(config.egressMaxConnections).toBe(12);
    expect(config.egressMaxBytesPerConnection).toBe(64 * 1024 * 1024);
  });

  it("allows the operator to fail closed persistent allocation", () => {
    expect(loadConfig({ BLOOM_PERSISTENCE_ENABLED: "0" }).persistenceEnabled).toBe(false);
    expect(loadConfig({}).persistenceEnabled).toBe(true);
  });

  it("defaults storage quota to 512 MiB and respects operator override", () => {
    expect(loadConfig({}).storageQuotaBytes).toBe(512 * 1024 * 1024);
    expect(loadConfig({ BLOOM_STORAGE_QUOTA_MIB: "2048" }).storageQuotaBytes).toBe(2 * 1024 * 1024 * 1024);
    expect(() => loadConfig({ BLOOM_STORAGE_QUOTA_MIB: "8" })).toThrow();
    expect(() => loadConfig({ BLOOM_STORAGE_QUOTA_MIB: "8192" })).toThrow();
  });

  it("defaults preinstalled petals to empty and respects operator override", () => {
    expect(loadConfig({}).preinstalledPetals).toEqual([]);
    expect(loadConfig({ BLOOM_PREINSTALLED_PETALS: "foo,bar" }).preinstalledPetals).toEqual(["foo", "bar"]);
    expect(loadConfig({ BLOOM_PREINSTALLED_PETALS: "single-petal" }).preinstalledPetals).toEqual(["single-petal"]);
    expect(loadConfig({ BLOOM_PREINSTALLED_PETALS: "  spaced  ,  trimmed  " }).preinstalledPetals).toEqual(["spaced", "trimmed"]);
    expect(loadConfig({ BLOOM_PREINSTALLED_PETALS: "" }).preinstalledPetals).toEqual([]);
  });

  it("rejects invalid petal names", () => {
    expect(() => loadConfig({ BLOOM_PREINSTALLED_PETALS: "foo;bar" })).toThrow();
    expect(() => loadConfig({ BLOOM_PREINSTALLED_PETALS: "foo/bar" })).toThrow();
    expect(() => loadConfig({ BLOOM_PREINSTALLED_PETALS: "foo bar" })).toThrow();
    expect(() => loadConfig({ BLOOM_PREINSTALLED_PETALS: "../etc" })).toThrow();
  });

  it("rejects more than 32 petals", () => {
    const too_many = Array.from({ length: 33 }, (_, i) => `p${i}`).join(",");
    expect(() => loadConfig({ BLOOM_PREINSTALLED_PETALS: too_many })).toThrow();
  });

  it("requires explicit SSH/NFS prerequisites in public mode", () => {
    const base = {
      BLOOM_PUBLIC_MODE: "1", BLOOM_ORIGIN: "https://workspaces.example.com", BLOOM_RUNTIME: "qemu",
      BLOOM_SESSION_SECRET: "s".repeat(32), BLOOM_AGENT_TOKEN: "a".repeat(32),
      BLOOM_TURNSTILE_SITE_KEY: "site", BLOOM_TURNSTILE_SECRET: "secret",
    };
    expect(() => loadConfig({ ...base, BLOOM_SSH_ENABLED: "1" })).toThrow(/SSH_CA_KEY/);
    expect(() => loadConfig({ ...base, BLOOM_NFS_ENABLED: "1" })).toThrow(/requires the SSH gateway/);
    expect(loadConfig({ ...base, BLOOM_SSH_ENABLED: "1", BLOOM_SSH_CA_KEY: "/run/bloom/ca" }).sshEnabled).toBe(true);
  });
});
