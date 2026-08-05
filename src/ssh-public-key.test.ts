import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { parseSshPublicKey } from "./ssh-public-key.js";

describe("SSH public key validation", () => {
  it("normalizes a real OpenSSH Ed25519 key and drops its untrusted comment", () => {
    const { publicKey } = generateKeyPairSync("ed25519");
    const ssh = publicKey.export({ type: "spki", format: "der" });
    const raw = ssh.subarray(-32);
    const algorithm = Buffer.from("ssh-ed25519");
    const blob = Buffer.concat([length(algorithm), algorithm, length(raw), raw]);
    const parsed = parseSshPublicKey(`ssh-ed25519 ${blob.toString("base64")} someone@example\t`);
    expect(parsed.normalized).toBe(`ssh-ed25519 ${blob.toString("base64")}`);
    expect(parsed.fingerprint).toMatch(/^SHA256:[A-Za-z0-9+/]+$/);
  });

  it("rejects commands, multiline values, malformed blobs, and non-Ed25519 keys", () => {
    for (const value of [
      'command="touch /tmp/pwn" ssh-ed25519 AAAA',
      "ssh-ed25519 AAAA\nssh-ed25519 BBBB",
      "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ",
      "ssh-ed25519 !!!!",
      `ssh-ed25519 ${Buffer.alloc(64).toString("base64")}`,
    ]) expect(() => parseSshPublicKey(value), value).toThrow();
  });
});

function length(value: Buffer) {
  const result = Buffer.alloc(4);
  result.writeUInt32BE(value.byteLength);
  return result;
}
