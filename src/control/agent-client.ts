import { request as httpRequest } from "node:http";
import { connect } from "node:net";
import WebSocket from "ws";
import type { Config } from "../config.js";
import type { RuntimeSpec, RuntimeState } from "../agent/runtime.js";

export class AgentClient {
  constructor(private readonly config: Config) {}

  health() { return this.request<{ ok: boolean; runtime: string }>("GET", "/v1/health"); }
  create(spec: RuntimeSpec) { return this.request<{ state: RuntimeState }>("POST", "/v1/workspaces", spec); }
  status(id: string) { return this.request<{ state: RuntimeState }>("GET", `/v1/workspaces/${encodeURIComponent(id)}`); }
  stop(id: string) { return this.request<void>("DELETE", `/v1/workspaces/${encodeURIComponent(id)}`); }

  terminal(id: string) {
    return new WebSocket(`ws://agent.local/v1/workspaces/${encodeURIComponent(id)}/terminal`, {
      headers: { authorization: `Bearer ${this.config.agentToken}` },
      createConnection: () => connect(this.config.agentSocket),
    });
  }

  private request<T>(method: string, path: string, body?: unknown) {
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    return new Promise<T>((resolve, reject) => {
      const request = httpRequest({
        socketPath: this.config.agentSocket,
        path,
        method,
        headers: {
          authorization: `Bearer ${this.config.agentToken}`,
          ...(payload ? { "content-type": "application/json", "content-length": String(payload.length) } : {}),
        },
        timeout: this.config.agentRequestTimeoutMs,
      }, (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
        response.on("end", () => {
          const text = Buffer.concat(chunks).toString();
          if ((response.statusCode ?? 500) >= 400) {
            let message = `Node agent returned ${response.statusCode}`;
            try { message = JSON.parse(text).error ?? message; } catch { /* use status */ }
            reject(new Error(message)); return;
          }
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
