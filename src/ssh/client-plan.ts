import { normalizeAccessMode, normalizeWorkspaceId, type SshAccessMode } from "./contracts.js";
import { parseSshPublicKey } from "../ssh-public-key.js";

const LEASE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SAFE_POSIX_PROXY_PATH = /^\/[A-Za-z0-9._/-]+$/;
const SAFE_WINDOWS_PROXY_PATH = /^[A-Za-z]:\/[A-Za-z0-9._/-]+$/;

export type SshClientPlanInput = {
  gatewayOrigin: string;
  workspaceId: string;
  leaseId: string;
  mode: SshAccessMode;
  proxyHelperPath: string;
  tokenFilePath: string;
  privateKeyPath: string;
  certificatePath: string;
  knownHostsPath: string;
};

/**
 * OpenSSH invokes ProxyCommand through a shell, so every value in that one
 * option is limited to a shell-metacharacter-free alphabet. The bearer stays
 * in a 0600 file and never appears in argv or a URL.
 */
export function createSshClientArgv(input: SshClientPlanInput) {
  const workspaceId = normalizeWorkspaceId(input.workspaceId);
  const mode = normalizeAccessMode(input.mode);
  if (!LEASE_ID.test(input.leaseId)) throw new Error("Invalid SSH lease id");
  const origin = normalizeHttpsOrigin(input.gatewayOrigin);
  const helper = safeProxyPath(input.proxyHelperPath, "SSH proxy helper");
  const tokenFile = safeProxyPath(input.tokenFilePath, "SSH token file");
  const proxyCommand = `${helper} --origin ${origin} --workspace ${workspaceId} --lease ${input.leaseId.toLowerCase()} --mode ${mode} --token-file ${tokenFile}`;
  const key = localPath(input.privateKeyPath, "private key");
  const certificate = localPath(input.certificatePath, "certificate");
  const knownHosts = localPath(input.knownHostsPath, "known hosts");
  return [
    "ssh",
    "-o", `ProxyCommand=${proxyCommand}`,
    "-o", "BatchMode=yes",
    "-o", "IdentitiesOnly=yes",
    "-o", "StrictHostKeyChecking=yes",
    "-o", `UserKnownHostsFile=${knownHosts}`,
    "-o", `CertificateFile=${certificate}`,
    "-o", `HostKeyAlias=bloom-${workspaceId}`,
    "-o", "ServerAliveInterval=20",
    "-o", "ServerAliveCountMax=2",
    "-i", key,
    `workspace@bloom-${workspaceId}`,
  ];
}

export function workspaceKnownHostsLine(workspaceId: string, hostPublicKey: string) {
  const id = normalizeWorkspaceId(workspaceId);
  const key = parseSshPublicKey(hostPublicKey);
  return { alias: `bloom-${id}`, line: `bloom-${id} ${key.normalized}\n`, fingerprint: key.fingerprint };
}

function normalizeHttpsOrigin(value: string) {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("Invalid SSH gateway origin");
  }
  if (url.protocol !== "https:" || url.username || url.password || url.pathname !== "/" || url.search || url.hash) throw new Error("SSH gateway origin must be an HTTPS origin");
  const origin = url.origin.toLowerCase();
  if (!/^https:\/\/[a-z0-9.-]+(?::[0-9]{1,5})?$/.test(origin)) throw new Error("Invalid SSH gateway origin");
  return origin;
}

function safeProxyPath(value: string, label: string) {
  if ((!SAFE_POSIX_PROXY_PATH.test(value) && !SAFE_WINDOWS_PROXY_PATH.test(value)) || value.includes("..")) throw new Error(`${label} path is not safe for ProxyCommand`);
  return value;
}

function localPath(value: string, label: string) {
  if (!value || value.length > 4096 || value.includes("\0") || value.includes("\n") || value.includes("\r")) throw new Error(`Invalid ${label} path`);
  return value;
}
