import { request as httpRequest } from "node:http";
import { connect } from "node:net";
import WebSocket from "ws";
import type { Config } from "../config.js";
import type { CapabilitySet } from "../capabilities.js";
import type { BloomGuestStatus } from "../guest/results.js";
import type { JobStatus, StructuredJobSpec } from "../jobs/model.js";
import type { RuntimeSpec, RuntimeState, WorkspaceDataCapabilities, WorkspaceFileEntry, WorkspaceFileWrite } from "../agent/runtime.js";
import type { AgentSshLeaseGrant, SshLeaseBody } from "../ssh/api.js";

export class AgentClientError extends Error {
  constructor(message: string, readonly status: number) { super(message); }
}

export class AgentClient {
  constructor(private readonly config: Config) {}

  health() { return this.request<{ ok: boolean; runtime: string; dataCapabilities: WorkspaceDataCapabilities; capabilities: CapabilitySet }>("GET", "/v1/health"); }
  create(spec: RuntimeSpec) { return this.request<{ state: RuntimeState }>("POST", "/v1/workspaces", spec); }
  status(id: string) { return this.request<{ state: RuntimeState; dataCapabilities: WorkspaceDataCapabilities; capabilities: CapabilitySet }>("GET", `/v1/workspaces/${encodeURIComponent(id)}`); }
  stop(id: string) { return this.request<void>("DELETE", `/v1/workspaces/${encodeURIComponent(id)}`); }
  listFiles(id: string, path: string) { return this.request<{ files: WorkspaceFileEntry[] }>("GET", filePath(id, path)); }
  readFile(id: string, path: string) { return this.request<Buffer>("GET", filePath(id, path, true), undefined, true); }
  writeFile(id: string, path: string, contents: Buffer) { return this.request<WorkspaceFileWrite>("PUT", filePath(id, path), contents); }
  deleteFile(id: string, path: string) { return this.request<{ usedBytes: number; quotaBytes: number }>("DELETE", filePath(id, path)); }
  destroyVolume(id: string) { return this.request<void>("DELETE", `/v1/volumes/${encodeURIComponent(id)}`); }
  startJob(id: string, spec: StructuredJobSpec) { return this.request<JobStatus>("POST", `/v1/workspaces/${encodeURIComponent(id)}/jobs`, spec); }
  jobStatus(id: string, jobId: string, offset = 0, maxBytes = 256 * 1024) {
    return this.request<JobStatus>("GET", `/v1/workspaces/${encodeURIComponent(id)}/jobs/${encodeURIComponent(jobId)}?offset=${offset}&maxBytes=${maxBytes}`);
  }
  cancelJob(id: string, jobId: string) { return this.request<JobStatus>("DELETE", `/v1/workspaces/${encodeURIComponent(id)}/jobs/${encodeURIComponent(jobId)}`); }
  bloomStatus(id: string) { return this.request<BloomGuestStatus>("GET", `/v1/workspaces/${encodeURIComponent(id)}/bloom`); }
  ceremonyPending(id: string) { return this.request<{ requests: { id: string; chain: string; wallet: string; planMd: string; ceremonyUrl: string | null; challenge: string | null }[] }>("GET", `/v1/workspaces/${encodeURIComponent(id)}/ceremony`); }
  ceremonyApprove(id: string, txId: string, assertion: { credentialId: string; authenticatorData: string; clientDataJSON: string; signature: string }) {
    return this.request<{ approved: boolean }>("POST", `/v1/workspaces/${encodeURIComponent(id)}/ceremony/${encodeURIComponent(txId)}/approve`, { assertion });
  }
  connections(id: string) { return this.request<{ connections: Record<"ssh" | "nfs", { status: "available" | "disabled" | "unsupported"; reason: string; instructions: string[] }> }>("GET", `/v1/workspaces/${encodeURIComponent(id)}/connections`); }
  issueSsh(id: string, body: SshLeaseBody) { return this.request<AgentSshLeaseGrant>("POST", `/v1/workspaces/${encodeURIComponent(id)}/connections/ssh`, body); }
  revokeSsh(id: string, leaseId: string) { return this.request<void>("DELETE", `/v1/workspaces/${encodeURIComponent(id)}/connections/ssh/${encodeURIComponent(leaseId)}`); }

  terminal(id: string) {
    return new WebSocket(`ws://agent.local/v1/workspaces/${encodeURIComponent(id)}/terminal`, {
      headers: { authorization: `Bearer ${this.config.agentToken}` },
      createConnection: () => connect(this.config.agentSocket),
    });
  }

  sshTunnel(id: string, leaseId: string, mode: "shell" | "nfs", accessToken: string) {
    const query = `lease=${encodeURIComponent(leaseId)}&mode=${encodeURIComponent(mode)}`;
    return new WebSocket(`ws://agent.local/v1/workspaces/${encodeURIComponent(id)}/connections/ssh/tunnel?${query}`, "bloom-ssh-v1", {
      headers: { authorization: `Bearer ${this.config.agentToken}`, "x-bloom-ssh-token": accessToken },
      createConnection: () => connect(this.config.agentSocket),
      perMessageDeflate: false,
      maxPayload: 1024 * 1024,
    });
  }

  private request<T>(method: string, path: string, body?: unknown, binaryResponse = false) {
    const binaryBody = Buffer.isBuffer(body);
    const payload = body === undefined ? undefined : binaryBody ? body : Buffer.from(JSON.stringify(body));
    return new Promise<T>((resolve, reject) => {
      const request = httpRequest({
        socketPath: this.config.agentSocket,
        path,
        method,
        headers: {
          authorization: `Bearer ${this.config.agentToken}`,
          ...(payload ? { "content-type": binaryBody ? "application/octet-stream" : "application/json", "content-length": String(payload.length) } : {}),
        },
        timeout: this.config.agentRequestTimeoutMs,
      }, (response) => {
        const chunks: Buffer[] = [];
        let received = 0;
        const responseLimit = binaryResponse ? 8 * 1024 * 1024 : 1024 * 1024;
        response.on("data", (chunk) => {
          received += chunk.length;
          if (received > responseLimit) { response.destroy(new AgentClientError("Node agent response exceeded the size limit", 502)); return; }
          chunks.push(Buffer.from(chunk));
        });
        response.once("error", reject);
        response.on("end", () => {
          const text = Buffer.concat(chunks).toString();
          if ((response.statusCode ?? 500) >= 400) {
            let message = `Node agent returned ${response.statusCode}`;
            try { message = JSON.parse(text).error ?? message; } catch { /* use status */ }
            reject(new AgentClientError(message, response.statusCode ?? 500)); return;
          }
          if (binaryResponse) { resolve(Buffer.concat(chunks) as T); return; }
          if (!text) { resolve(undefined as T); return; }
          try { resolve(JSON.parse(text) as T); } catch (error) { reject(error); }
        });
      });
      request.once("timeout", () => request.destroy(new Error("Node agent request timed out")));
      request.once("error", reject);
      if (payload) request.write(payload);
      request.end();
    });
  }
}

function filePath(id: string, path: string, content = false) {
  return `/v1/workspaces/${encodeURIComponent(id)}/files${content ? "/content" : ""}?path=${encodeURIComponent(path)}`;
}
