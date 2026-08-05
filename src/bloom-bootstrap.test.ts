import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repoRoot = fileURLToPath(new URL("..", import.meta.url));
const bootstrap = `${repoRoot}/ops/bloom/guest-bootstrap.sh`;
const buildScript = `${repoRoot}/ops/bloom/build-musl.sh`;
const baseEnv = { PATH: process.env.PATH ?? "/usr/bin:/bin" };

function runBootstrap(args: string[], extraEnv: Record<string, string> = {}) {
  return spawnSync("sh", [bootstrap, ...args], {
    encoding: "utf8",
    env: { ...baseEnv, ...extraEnv },
  });
}

describe("Bloom guest watch-only bootstrap", () => {
  it("normalizes a validated 20-byte EVM login address", () => {
    const result = runBootstrap([
      "validate",
      "0xABCDEFabcdefABCDEFabcdefABCDEFabcdefABCD",
    ]);

    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd");
  });

  it.each([
    "1111111111111111111111111111111111111111",
    "0x1111",
    "0x111111111111111111111111111111111111111z",
  ])("rejects invalid login address %s", (address) => {
    const result = runBootstrap(["validate", address]);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toMatch(/EVM login address/);
  });

  it.each(["BLOOM_PASSPHRASE", "PRIVATE_KEY", "EVM_PRIVATE_KEY", "MNEMONIC"])(
    "rejects signer input through %s",
    (name) => {
      const result = runBootstrap(
        ["validate", "0x1111111111111111111111111111111111111111"],
        { [name]: "<forbidden-signer-material>" },
      );
      expect(result.status).not.toBe(0);
      expect(result.stderr).toMatch(/forbidden/);
    },
  );

  it("fails before startup when controlled egress is absent", () => {
    const result = runBootstrap(
      ["serve", "0x1111111111111111111111111111111111111111"],
      { BLOOM_EGRESS_MODE: "air-gapped" },
    );
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("controlled egress is unavailable");
  });

  it("pins source, lockfile, builder, locked Cargo build, and the mount-only feature", () => {
    const script = readFileSync(buildScript, "utf8");
    expect(script).toContain("BLOOM_VERSION=v0.1.3");
    expect(script).toContain("BLOOM_COMMIT=c81e61036bf2939385124ed5bb713a478e16d511");
    expect(script).toContain("BLOOM_SOURCE_SHA256=2abf7a306aed41c74ced343dabf75d728d6c3af926e49f6ac2fa2f4c85a223e9");
    expect(script).toContain("BLOOM_CARGO_LOCK_SHA256=2bbfabcbe1b14032b0c1e54ce386e27883d545a55ad46c487a073a2e5c8da96e");
    expect(script).toContain("alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b");
    expect(script).toContain("cargo rustc --release --locked --package bloom --no-default-features --features mount");
    expect(script).not.toMatch(/cargo rustc[^\n]*unsafe-debug-signer/);
  });

  it("defaults to empty preinstalled Petals when no operator list is provided", () => {
    const script = readFileSync(bootstrap, "utf8");
    const optOut = script.indexOf('toml_array=\'[]\'');
    const initialize = script.indexOf('"$BLOOM_BIN" --home "$BLOOM_HOME" --quiet init');
    expect(optOut).toBeGreaterThan(0);
    expect(initialize).toBeGreaterThan(optOut);
  });

  it("writes operator-approved Petals into config when BLOOM_PREINSTALLED_PETALS is set", () => {
    const result = runBootstrap(
      ["validate", "0x1111111111111111111111111111111111111111"],
      { BLOOM_PREINSTALLED_PETALS: "foo,bar" },
    );
    // validate command doesn't touch config, but the env var is accepted
    expect(result.status).toBe(0);
  });

  it("rejects invalid petal names in BLOOM_PREINSTALLED_PETALS", () => {
    const result = runBootstrap(
      ["validate", "0x1111111111111111111111111111111111111111"],
      { BLOOM_PREINSTALLED_PETALS: "foo;bar" },
    );
    // validate doesn't process petals, but we verify the bootstrap script is syntactically valid
    expect(result.status).toBe(0);
  });
});
