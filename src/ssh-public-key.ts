import { createHash } from "node:crypto";

export type ParsedSshPublicKey = {
  algorithm: "ssh-ed25519";
  encoded: string;
  normalized: string;
  fingerprint: string;
};

/** Only compact Ed25519 keys are accepted for the public pilot. */
export function parseSshPublicKey(value: string): ParsedSshPublicKey {
  const input = value.trim();
  if (Buffer.byteLength(value) > 1024 || input.includes("\0") || input.includes("\n") || input.includes("\r")) {
    throw new Error("Invalid SSH public key");
  }
  const fields = input.split(/[ \t]+/);
  if (fields.length < 2 || fields[0] !== "ssh-ed25519" || !fields[1]) throw new Error("Only OpenSSH Ed25519 public keys are supported");
  const encoded = fields[1];
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) throw new Error("Invalid SSH public key encoding");
  const blob = Buffer.from(encoded, "base64");
  if (blob.toString("base64") !== encoded) throw new Error("Non-canonical SSH public key encoding");
  const decoded = decodeEd25519Blob(blob);
  if (decoded.algorithm !== "ssh-ed25519" || decoded.key.byteLength !== 32 || decoded.consumed !== blob.byteLength) throw new Error("Invalid SSH Ed25519 public key");
  const digest = createHash("sha256").update(blob).digest("base64").replace(/=+$/, "");
  return { algorithm: "ssh-ed25519", encoded, normalized: `ssh-ed25519 ${encoded}`, fingerprint: `SHA256:${digest}` };
}

function decodeEd25519Blob(blob: Buffer) {
  let offset = 0;
  const readString = () => {
    if (offset + 4 > blob.byteLength) throw new Error("Invalid SSH public key blob");
    const length = blob.readUInt32BE(offset);
    offset += 4;
    if (length > blob.byteLength - offset) throw new Error("Invalid SSH public key blob");
    const value = blob.subarray(offset, offset + length);
    offset += length;
    return value;
  };
  const algorithm = readString().toString("ascii");
  const key = readString();
  return { algorithm, key, consumed: offset };
}
