import { describe, expect, it } from "vitest";
import {
  MAX_UPLOAD_BYTES,
  buildJobEnvironment,
  normalizeWorkspacePath,
  parseStructuredArgv,
  parseTimeoutSeconds,
  readConnectionMethods,
} from "../../web/workspace-contracts.js";

describe("workspace browser contracts", () => {
  it("builds structured argv and never parses a shell command string", () => {
    expect(parseStructuredArgv('["npm", "test", "--", "a b"]')).toEqual(["npm", "test", "--", "a b"]);
    expect(() => parseStructuredArgv("npm test")).toThrow("valid JSON");
    expect(() => parseStructuredArgv('"npm test"')).toThrow("JSON array");
  });

  it("keeps browser-selected paths below /workspace", () => {
    expect(normalizeWorkspacePath("src/index.ts")).toBe("src/index.ts");
    expect(normalizeWorkspacePath(".", { allowRoot: true })).toBe(".");
    for (const value of ["/etc/passwd", "../secret", "src/../secret", "src\\secret", "src//file"]) {
      expect(() => normalizeWorkspacePath(value)).toThrow();
    }
  });

  it("uses the same upload, timeout, and environment boundaries as the server", () => {
    expect(MAX_UPLOAD_BYTES).toBe(8 * 1024 * 1024);
    expect(parseTimeoutSeconds("7200")).toBe(7_200_000);
    expect(() => parseTimeoutSeconds("7201")).toThrow();
    expect(buildJobEnvironment([{ name: "NODE_ENV", value: "test" }, { name: "APP_PORT", value: "3000" }])).toEqual({ NODE_ENV: "test", APP_PORT: "3000" });
    expect(() => buildJobEnvironment([{ name: "AWS_SECRET_ACCESS_KEY", value: "no" }])).toThrow("not allowlisted");
    expect(() => buildJobEnvironment([{ name: "APP_X", value: "1" }, { name: "APP_X", value: "2" }])).toThrow("duplicated");
  });

  it("whitelists future connection display fields and drops secrets", () => {
    const parsed = readConnectionMethods({
      ssh: { status: "available", reason: "Ready", command: "ssh workspace@example", accessToken: "secret", privateKey: "secret" },
      nfs: { status: "unsupported", reason: "Use browser files", instructions: ["Open Files"], seedPhrase: "secret" },
      credentials: "secret",
    });
    expect(parsed).toEqual([
      { kind: "ssh", status: "available", reason: "Ready", command: "ssh workspace@example", instructions: [] },
      { kind: "nfs", status: "unsupported", reason: "Use browser files", instructions: ["Open Files"] },
    ]);
    expect(JSON.stringify(parsed)).not.toContain("secret");
  });
});
