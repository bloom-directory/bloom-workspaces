import { z } from "zod";
import { parseSshPublicKey } from "../ssh-public-key.js";

const PublicKey = z.string().min(32).max(4096).transform((value, context) => {
  try { return parseSshPublicKey(value).normalized; }
  catch {
    context.addIssue({ code: "custom", message: "A valid OpenSSH Ed25519 public key is required" });
    return z.NEVER;
  }
});

export const SshLeaseBody = z.object({
  publicKey: PublicKey,
  mode: z.enum(["shell", "nfs"]),
  requestedTtlMs: z.number().int().min(5_000).optional(),
}).strict();

export type SshLeaseBody = z.infer<typeof SshLeaseBody>;

export const GuestConnectionStatus = z.object({
  workspaceId: z.string().uuid(),
  ssh: z.object({
    available: z.literal(true),
    hostKey: PublicKey,
    port: z.literal(22),
  }).strict(),
  nfs: z.object({
    available: z.boolean(),
    port: z.literal(2049).nullable(),
  }).strict(),
}).strict().superRefine((value, context) => {
  if (value.nfs.available !== (value.nfs.port === 2049)) {
    context.addIssue({ code: "custom", path: ["nfs", "port"], message: "NFS availability and port disagree" });
  }
});

export type GuestConnectionStatus = z.infer<typeof GuestConnectionStatus>;

export type AgentSshLeaseGrant = {
  leaseId: string;
  accessToken: string;
  certificate: string;
  fingerprint: string;
  principal: string;
  validAfter: number;
  validBefore: number;
  mode: "shell" | "nfs";
  hostKey: { alias: string; knownHostsLine: string; fingerprint: string };
};
