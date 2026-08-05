import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { createConnection, type Socket } from "node:net";
import { isAbsolute, resolve, sep } from "node:path";
import type { Duplex } from "node:stream";
import { DEFAULT_SSH_LEASE_MS, MAX_SSH_LEASE_MS, assertPort, normalizeAccessMode, normalizeWallet, normalizeWorkspaceId, type PrivateSshEndpoint, type SshAccessMode, workspacePrincipal } from "./contracts.js";
import { signWorkspaceCertificate, type SignedWorkspaceCertificate, type WorkspaceCertificateSigner } from "./certificate.js";

export type SshLeaseRequest = {
  workspaceId: string;
  wallet: string;
  publicKey: string;
  mode: SshAccessMode;
  workspaceLeaseExpiresAt: number;
  requestedTtlMs?: number;
  endpoint: PrivateSshEndpoint;
};

export type SshLeaseGrant = Omit<SignedWorkspaceCertificate, "serial"> & {
  leaseId: string;
  accessToken: string;
};

export type SshTunnelRequest = {
  leaseId: string;
  workspaceId: string;
  wallet: string;
  mode: SshAccessMode;
  accessToken: string;
};

type LeaseRecord = SignedWorkspaceCertificate & {
  leaseId: string;
  workspaceId: string;
  wallet: string;
  endpoint: PrivateSshEndpoint;
  tokenHash: Buffer;
  active: Set<Duplex>;
  pending: number;
  expiryTimer: NodeJS.Timeout;
};

type SshLeaseManagerOptions = {
  caKeyPath: string;
  privateSocketRoot: string;
  maxLeaseMs?: number;
  maxConnectionsPerLease?: number;
  connectionTimeoutMs?: number;
  clock?: () => number;
  signer?: WorkspaceCertificateSigner;
  connector?: (endpoint: PrivateSshEndpoint, timeoutMs: number) => Promise<Duplex>;
};

/**
 * The gateway is deliberately transport-private: callers authenticate an HTTPS
 * or WebSocket request first, then this manager validates the wallet-scoped
 * bearer lease and opens the one registered loopback/Unix guest SSH endpoint.
 */
export class SshLeaseManager {
  private readonly leases = new Map<string, LeaseRecord>();
  private readonly caKeyPath: string;
  private readonly socketRoot: string;
  private readonly maxLeaseMs: number;
  private readonly maxConnections: number;
  private readonly connectionTimeoutMs: number;
  private readonly clock: () => number;
  private readonly signer: WorkspaceCertificateSigner;
  private readonly connector: (endpoint: PrivateSshEndpoint, timeoutMs: number) => Promise<Duplex>;

  constructor(options: SshLeaseManagerOptions) {
    if (!isAbsolute(options.privateSocketRoot)) throw new Error("Private SSH socket root must be absolute");
    this.caKeyPath = options.caKeyPath;
    this.socketRoot = resolve(options.privateSocketRoot);
    this.maxLeaseMs = options.maxLeaseMs ?? DEFAULT_SSH_LEASE_MS;
    if (!Number.isSafeInteger(this.maxLeaseMs) || this.maxLeaseMs < 5_000 || this.maxLeaseMs > MAX_SSH_LEASE_MS) throw new Error("Invalid maximum SSH lease");
    this.maxConnections = options.maxConnectionsPerLease ?? 2;
    if (!Number.isSafeInteger(this.maxConnections) || this.maxConnections < 1 || this.maxConnections > 8) throw new Error("Invalid SSH connection limit");
    this.connectionTimeoutMs = options.connectionTimeoutMs ?? 5_000;
    this.clock = options.clock ?? Date.now;
    this.signer = options.signer ?? signWorkspaceCertificate;
    this.connector = options.connector ?? connectPrivateEndpoint;
  }

  async issue(request: SshLeaseRequest): Promise<SshLeaseGrant> {
    const now = this.clock();
    const workspaceId = normalizeWorkspaceId(request.workspaceId);
    const wallet = normalizeWallet(request.wallet);
    const mode = normalizeAccessMode(request.mode);
    const endpoint = this.validateEndpoint(request.endpoint);
    if (!Number.isSafeInteger(request.workspaceLeaseExpiresAt) || request.workspaceLeaseExpiresAt <= now + 1_000) throw new Error("Workspace lease is expired");
    const requested = request.requestedTtlMs ?? this.maxLeaseMs;
    if (!Number.isSafeInteger(requested) || requested < 5_000 || requested > this.maxLeaseMs) throw new Error("Invalid requested SSH lease");
    const validBefore = Math.min(request.workspaceLeaseExpiresAt, now + requested);
    if (validBefore <= now + 1_000) throw new Error("SSH lease is too close to expiry");
    const validAfter = now - 5_000;
    const signed = await this.signer({
      caKeyPath: this.caKeyPath,
      publicKey: request.publicKey,
      workspaceId,
      wallet,
      mode,
      validAfter,
      validBefore,
    });
    if (signed.principal !== workspacePrincipal(workspaceId, wallet, mode) || signed.mode !== mode || signed.validAfter !== validAfter || signed.validBefore !== validBefore) throw new Error("SSH signer returned a certificate with the wrong scope");
    const leaseId = randomUUID();
    const accessToken = randomBytes(32).toString("base64url");
    const record = {
      ...signed,
      leaseId,
      workspaceId,
      wallet,
      endpoint,
      tokenHash: digestToken(accessToken),
      active: new Set<Duplex>(),
      pending: 0,
      expiryTimer: setTimeout(() => this.revokeTrusted(leaseId, "SSH lease expired"), Math.max(0, validBefore - this.clock())),
    } satisfies LeaseRecord;
    record.expiryTimer.unref();

    for (const existing of this.leases.values()) {
      if (existing.workspaceId === workspaceId && existing.mode === mode) this.revokeTrusted(existing.leaseId, "SSH lease replaced");
    }
    this.leases.set(leaseId, record);
    const { certificate, fingerprint, principal, validAfter: issuedAfter, validBefore: issuedBefore, mode: issuedMode } = signed;
    return { leaseId, accessToken, certificate, fingerprint, principal, validAfter: issuedAfter, validBefore: issuedBefore, mode: issuedMode };
  }

  async openTunnel(request: SshTunnelRequest): Promise<Duplex> {
    const lease = this.authorize(request);
    if (lease.active.size + lease.pending >= this.maxConnections) throw new Error("SSH lease connection limit reached");
    lease.pending += 1;
    let stream: Duplex;
    try {
      stream = await this.connector(lease.endpoint, this.connectionTimeoutMs);
    } finally {
      lease.pending -= 1;
    }
    if (this.clock() >= lease.validBefore || this.leases.get(lease.leaseId) !== lease) {
      stream.destroy();
      throw new Error("SSH lease expired");
    }
    lease.active.add(stream);
    const release = () => lease.active.delete(stream);
    stream.once("close", release);
    stream.once("end", release);
    stream.once("error", release);
    return stream;
  }

  revoke(request: Pick<SshTunnelRequest, "leaseId" | "workspaceId" | "wallet">) {
    const lease = this.leases.get(request.leaseId);
    if (!lease || lease.workspaceId !== normalizeWorkspaceId(request.workspaceId) || lease.wallet !== normalizeWallet(request.wallet)) throw new Error("SSH lease not found");
    this.revokeTrusted(lease.leaseId, "SSH lease revoked");
  }

  revokeWorkspace(workspaceId: string) {
    const id = normalizeWorkspaceId(workspaceId);
    for (const lease of this.leases.values()) if (lease.workspaceId === id) this.revokeTrusted(lease.leaseId, "Workspace stopped");
  }

  sweepExpired() {
    const now = this.clock();
    for (const lease of this.leases.values()) if (now >= lease.validBefore) this.revokeTrusted(lease.leaseId, "SSH lease expired");
  }

  stop() {
    for (const lease of [...this.leases.values()]) this.revokeTrusted(lease.leaseId, "SSH gateway stopped");
  }

  private authorize(request: SshTunnelRequest) {
    const lease = this.leases.get(request.leaseId);
    if (!lease || this.clock() >= lease.validBefore) {
      if (lease) this.revokeTrusted(lease.leaseId, "SSH lease expired");
      throw new Error("SSH lease expired or revoked");
    }
    if (lease.workspaceId !== normalizeWorkspaceId(request.workspaceId) || lease.wallet !== normalizeWallet(request.wallet) || lease.mode !== request.mode) throw new Error("SSH lease scope mismatch");
    const supplied = digestToken(request.accessToken);
    if (supplied.byteLength !== lease.tokenHash.byteLength || !timingSafeEqual(supplied, lease.tokenHash)) throw new Error("Invalid SSH lease token");
    return lease;
  }

  private revokeTrusted(leaseId: string, reason: string) {
    const lease = this.leases.get(leaseId);
    if (!lease) return;
    this.leases.delete(leaseId);
    clearTimeout(lease.expiryTimer);
    for (const stream of lease.active) stream.destroy(new Error(reason));
    lease.active.clear();
  }

  private validateEndpoint(endpoint: PrivateSshEndpoint): PrivateSshEndpoint {
    if (endpoint.kind === "tcp") {
      assertPort(endpoint.port, "private SSH endpoint port");
      if (endpoint.host !== "127.0.0.1" && endpoint.host !== "::1") throw new Error("SSH endpoint must be host-private");
      return { ...endpoint };
    }
    if (!isAbsolute(endpoint.path) || endpoint.path.includes("\0") || endpoint.path.includes("\n") || endpoint.path.includes("\r")) throw new Error("Invalid private SSH socket path");
    const path = resolve(endpoint.path);
    if (!path.startsWith(`${this.socketRoot}${sep}`)) throw new Error("SSH socket escapes the private runtime directory");
    return { kind: "unix", path };
  }
}

function digestToken(token: string) {
  if (typeof token !== "string" || token.length < 32 || token.length > 256 || !/^[A-Za-z0-9_-]+$/.test(token)) return Buffer.alloc(32);
  return createHash("sha256").update(token).digest();
}

function connectPrivateEndpoint(endpoint: PrivateSshEndpoint, timeoutMs: number): Promise<Socket> {
  return new Promise((resolveConnection, reject) => {
    const socket = endpoint.kind === "unix"
      ? createConnection({ path: endpoint.path })
      : createConnection({ host: endpoint.host, port: endpoint.port });
    const timeout = setTimeout(() => socket.destroy(new Error("Private SSH endpoint timed out")), timeoutMs);
    timeout.unref();
    socket.once("connect", () => {
      clearTimeout(timeout);
      resolveConnection(socket);
    });
    socket.once("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
  });
}
