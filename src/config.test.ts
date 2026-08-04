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
});
