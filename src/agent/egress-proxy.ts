import http, { type IncomingHttpHeaders, type IncomingMessage, type RequestOptions } from "node:http";
import { connect as connectTcp, Socket } from "node:net";
import type { Duplex } from "node:stream";
import { EgressPolicy, EgressPolicyError, parseProxyAuthority, type ApprovedDestination } from "./egress-policy.js";
import { inspectTlsClientHello, TlsClientHelloError } from "./egress-tls.js";

export interface EgressAuditEvent {
  timestamp: string;
  action: "allow" | "deny" | "close";
  protocol: "http" | "connect" | "unknown";
  hostname?: string;
  port?: number;
  address?: string;
  reason: string;
  bytes?: number;
}

export interface EgressProxyOptions {
  policy: EgressPolicy;
  allowedMethods?: readonly string[];
  maxConcurrentConnections?: number;
  maxBytesPerConnection?: number;
  connectTimeoutMs?: number;
  idleTimeoutMs?: number;
  maxConnectionMs?: number;
  maxClientHelloBytes?: number;
  clientHelloTimeoutMs?: number;
  audit?: (event: EgressAuditEvent) => void;
}

export interface EgressProxy {
  server: http.Server;
  listen(pathOrPort: string | number, host?: string): Promise<void>;
  close(): Promise<void>;
}

const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

export function createEgressProxy(options: EgressProxyOptions): EgressProxy {
  const maxConcurrent = positiveInteger(options.maxConcurrentConnections ?? 32, "maxConcurrentConnections");
  const maxBytes = positiveInteger(options.maxBytesPerConnection ?? 128 * 1024 * 1024, "maxBytesPerConnection");
  const connectTimeoutMs = positiveInteger(options.connectTimeoutMs ?? 10_000, "connectTimeoutMs");
  const idleTimeoutMs = positiveInteger(options.idleTimeoutMs ?? 30_000, "idleTimeoutMs");
  const maxConnectionMs = positiveInteger(options.maxConnectionMs ?? 5 * 60_000, "maxConnectionMs");
  const maxClientHelloBytes = positiveInteger(options.maxClientHelloBytes ?? 64 * 1024, "maxClientHelloBytes");
  if (maxClientHelloBytes < 256) throw new Error("maxClientHelloBytes must be at least 256");
  const clientHelloTimeoutMs = positiveInteger(options.clientHelloTimeoutMs ?? 5_000, "clientHelloTimeoutMs");
  const allowedMethods = new Set((options.allowedMethods ?? ["GET", "HEAD", "POST"]).map((method) => {
    const normalized = method.toUpperCase();
    if (!/^[A-Z]+$/u.test(normalized)) throw new Error("allowedMethods contains an invalid method");
    return normalized;
  }));
  const audit = options.audit ?? ((event) => process.stdout.write(`${JSON.stringify(event)}\n`));
  let active = 0;

  const acquire = (): (() => void) | undefined => {
    if (active >= maxConcurrent) return undefined;
    active += 1;
    let released = false;
    return () => {
      if (!released) {
        released = true;
        active -= 1;
      }
    };
  };

  const server = http.createServer((request, response) => {
    const release = acquire();
    if (!release) {
      response.writeHead(503, { "content-type": "text/plain", connection: "close" });
      response.end("Proxy capacity reached\n");
      auditEvent(audit, { action: "deny", protocol: "http", reason: "concurrency-limit" });
      return;
    }
    void handleHttp(request, response, options.policy, { maxBytes, connectTimeoutMs, idleTimeoutMs, maxConnectionMs, audit, allowedMethods })
      .finally(release);
  });

  server.on("connect", (request, client, head) => {
    const release = acquire();
    if (!release) {
      writeSocketError(client, 503, "Proxy capacity reached");
      auditEvent(audit, { action: "deny", protocol: "connect", reason: "concurrency-limit" });
      return;
    }
    void handleConnect(request, client, head, options.policy, {
      maxBytes,
      connectTimeoutMs,
      idleTimeoutMs,
      maxConnectionMs,
      maxClientHelloBytes,
      clientHelloTimeoutMs,
      audit,
    })
      .finally(release);
  });
  server.on("clientError", (_error, socket) => writeSocketError(socket, 400, "Bad request"));
  server.requestTimeout = idleTimeoutMs;
  server.headersTimeout = Math.min(idleTimeoutMs, 30_000);
  server.keepAliveTimeout = Math.min(idleTimeoutMs, 5_000);

  return {
    server,
    async listen(pathOrPort, host) {
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        const done = () => { server.off("error", reject); resolve(); };
        if (typeof pathOrPort === "string") server.listen(pathOrPort, done);
        else server.listen(pathOrPort, host ?? "127.0.0.1", done);
      });
    },
    async close() {
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    },
  };
}

export function createHttpUpstreamOptions(destination: ApprovedDestination, request: IncomingMessage, url: URL): RequestOptions {
  return {
    protocol: "http:",
    host: destination.address,
    family: destination.family,
    port: destination.port,
    method: request.method,
    path: `${url.pathname}${url.search}`,
    headers: sanitizeHeaders(request.headers, destination),
    agent: false,
  };
}

export function createConnectOptions(destination: ApprovedDestination): { host: string; port: number; family: 4 | 6 } {
  return { host: destination.address, port: destination.port, family: destination.family };
}

interface Limits {
  maxBytes: number;
  connectTimeoutMs: number;
  idleTimeoutMs: number;
  maxConnectionMs: number;
  maxClientHelloBytes?: number;
  clientHelloTimeoutMs?: number;
  audit: (event: EgressAuditEvent) => void;
  allowedMethods?: ReadonlySet<string>;
}

async function handleHttp(
  request: IncomingMessage,
  response: http.ServerResponse,
  policy: EgressPolicy,
  limits: Limits,
): Promise<void> {
  let hostname: string | undefined;
  let port: number | undefined;
  let upstream: http.ClientRequest | undefined;
  let deadlineError: Error | undefined;
  const deadline = setTimeout(() => {
    deadlineError = new Error("connection-deadline");
    request.destroy();
    upstream?.destroy(deadlineError);
    response.destroy();
  }, limits.maxConnectionMs);
  deadline.unref();
  try {
    rejectProxyCredentials(request.headers);
    const method = request.method?.toUpperCase() ?? "";
    if (!limits.allowedMethods?.has(method)) throw new EgressPolicyError("invalid-authority", "HTTP method is not allowed");
    if (!request.url || !/^http:\/\//iu.test(request.url)) throw new EgressPolicyError("invalid-authority", "Absolute HTTP URL required");
    const url = new URL(request.url);
    if (url.protocol !== "http:" || url.username || url.password || url.hash) {
      throw new EgressPolicyError("credentials-forbidden", "Only credential-free HTTP proxy URLs are accepted");
    }
    ({ hostname, port } = parseProxyAuthority(url.host, 80));
    const destination = await policy.approve(hostname, port, "http");
    limits.audit({ timestamp: new Date().toISOString(), action: "allow", protocol: "http", hostname, port, address: destination.address, reason: "policy-approved" });

    const contentLength = parseContentLength(request.headers["content-length"]);
    if (contentLength !== undefined && contentLength > limits.maxBytes) throw new Error("request-byte-limit");
    if (deadlineError) throw deadlineError;
    const activeUpstream = http.request(createHttpUpstreamOptions(destination, request, url));
    upstream = activeUpstream;
    let bytes = 0;
    let transferError: Error | undefined;
    activeUpstream.setTimeout(limits.idleTimeoutMs, () => activeUpstream.destroy(new Error("upstream-idle-timeout")));
    const connectTimer = setTimeout(() => activeUpstream.destroy(new Error("upstream-connect-timeout")), limits.connectTimeoutMs);
    connectTimer.unref();
    activeUpstream.once("socket", (socket) => socket.once("connect", () => clearTimeout(connectTimer)));
    activeUpstream.once("response", (upstreamResponse) => {
      clearTimeout(connectTimer);
      let responseLength: number | undefined;
      try {
        responseLength = parseContentLength(upstreamResponse.headers["content-length"]);
      } catch (error) {
        transferError = error instanceof Error ? error : new Error("invalid-content-length");
        upstreamResponse.destroy();
        response.writeHead(502, { "content-type": "text/plain", connection: "close" });
        response.end("Egress request denied\n");
        return;
      }
      if (responseLength !== undefined && responseLength + bytes > limits.maxBytes) {
        transferError = new Error("response-byte-limit");
        upstreamResponse.destroy();
        response.writeHead(413, { "content-type": "text/plain", connection: "close" });
        response.end("Egress request denied\n");
        return;
      }
      response.writeHead(upstreamResponse.statusCode ?? 502, sanitizeResponseHeaders(upstreamResponse.headers));
      upstreamResponse.on("data", (chunk: Buffer) => {
        bytes += chunk.length;
        if (bytes > limits.maxBytes) {
          transferError = new Error("response-byte-limit");
          upstreamResponse.destroy(transferError);
          response.destroy(transferError);
        }
      });
      upstreamResponse.once("error", (error) => { transferError = error; response.destroy(error); });
      upstreamResponse.pipe(response);
    });
    request.on("data", (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > limits.maxBytes) activeUpstream.destroy(new Error("request-byte-limit"));
    });
    request.pipe(activeUpstream);
    await finishedHttp(activeUpstream, response);
    if (deadlineError) throw deadlineError;
    if (transferError) throw transferError;
    limits.audit({ timestamp: new Date().toISOString(), action: "close", protocol: "http", hostname, port, reason: "completed", bytes });
  } catch (error) {
    upstream?.destroy();
    if (!response.headersSent) {
      response.writeHead(statusFor(error), { "content-type": "text/plain", connection: "close" });
      response.end("Egress request denied\n");
    } else response.destroy();
    auditDenied(limits.audit, "http", error, hostname, port);
  } finally {
    clearTimeout(deadline);
  }
}

async function handleConnect(
  request: IncomingMessage,
  client: Duplex,
  head: Buffer,
  policy: EgressPolicy,
  limits: Limits,
): Promise<void> {
  let hostname: string | undefined;
  let port: number | undefined;
  let upstream: Socket | undefined;
  let tunnelAccepted = false;
  let deadlineError: Error | undefined;
  const deadline = setTimeout(() => {
    deadlineError = new Error("connection-deadline");
    upstream?.destroy();
    client.destroy();
  }, limits.maxConnectionMs);
  deadline.unref();
  try {
    rejectProxyCredentials(request.headers);
    ({ hostname, port } = parseProxyAuthority(request.url ?? ""));
    const destination = await policy.approve(hostname, port, "connect");
    if (deadlineError) throw deadlineError;
    if (client instanceof Socket) {
      client.setTimeout(limits.idleTimeoutMs, () => client.destroy(new Error("client-idle-timeout")));
    }
    client.write("HTTP/1.1 200 Connection Established\r\nProxy-Agent: bloom-egress\r\n\r\n");
    tunnelAccepted = true;
    const clientHello = await receiveTlsClientHello(
      client,
      head,
      hostname,
      Math.min(limits.maxClientHelloBytes ?? 64 * 1024, limits.maxBytes),
      limits.clientHelloTimeoutMs ?? 5_000,
    );
    limits.audit({ timestamp: new Date().toISOString(), action: "allow", protocol: "connect", hostname, port, address: destination.address, reason: "policy-and-sni-approved" });
    upstream = connectTcp(createConnectOptions(destination));
    upstream.setTimeout(limits.idleTimeoutMs, () => upstream?.destroy(new Error("upstream-idle-timeout")));
    await waitForConnect(upstream, limits.connectTimeoutMs);
    upstream.write(clientHello);
    let bytes = clientHello.length;
    const meter = (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > limits.maxBytes) {
        upstream?.destroy(new Error("tunnel-byte-limit"));
        client.destroy(new Error("tunnel-byte-limit"));
      }
    };
    client.on("data", meter);
    upstream.on("data", meter);
    upstream.pipe(client);
    client.pipe(upstream);
    client.resume();
    await waitForTunnelClose(client, upstream);
    if (deadlineError) throw deadlineError;
    client.destroy();
    upstream.destroy();
    limits.audit({ timestamp: new Date().toISOString(), action: "close", protocol: "connect", hostname, port, reason: "completed", bytes });
  } catch (error) {
    upstream?.destroy();
    if (!client.destroyed) {
      if (tunnelAccepted) client.destroy();
      else writeSocketError(client, statusFor(error), "Egress request denied");
    }
    auditDenied(limits.audit, "connect", error, hostname, port);
  } finally {
    clearTimeout(deadline);
  }
}

function rejectProxyCredentials(headers: IncomingHttpHeaders): void {
  if (headers["proxy-authorization"] !== undefined || headers.authorization !== undefined || headers.cookie !== undefined) {
    throw new EgressPolicyError("credentials-forbidden", "Credentials in the proxy request are forbidden");
  }
}

function sanitizeHeaders(headers: IncomingHttpHeaders, destination: ApprovedDestination): IncomingHttpHeaders {
  const sanitized: IncomingHttpHeaders = {};
  const connectionTokens = new Set((headers.connection ?? "").split(",").map((value) => value.trim().toLowerCase()));
  for (const [name, value] of Object.entries(headers)) {
    if (!HOP_BY_HOP.has(name.toLowerCase()) && !connectionTokens.has(name.toLowerCase()) && name.toLowerCase() !== "host") {
      sanitized[name] = value;
    }
  }
  sanitized.host = destination.port === 80 ? destination.hostname : `${destination.hostname}:${destination.port}`;
  sanitized.via = "1.1 bloom-egress";
  return sanitized;
}

function sanitizeResponseHeaders(headers: IncomingHttpHeaders): IncomingHttpHeaders {
  const sanitized: IncomingHttpHeaders = {};
  const connectionTokens = new Set((headers.connection ?? "").split(",").map((value) => value.trim().toLowerCase()));
  for (const [name, value] of Object.entries(headers)) {
    if (!HOP_BY_HOP.has(name.toLowerCase()) && !connectionTokens.has(name.toLowerCase())) sanitized[name] = value;
  }
  sanitized.via = "1.1 bloom-egress";
  return sanitized;
}

function parseContentLength(value: string | undefined): number | undefined {
  if (value === undefined) return undefined;
  if (!/^(?:0|[1-9][0-9]*)$/u.test(value)) throw new Error("invalid-content-length");
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw new Error("invalid-content-length");
  return parsed;
}

function statusFor(error: unknown): number {
  if (error instanceof EgressPolicyError) return error.code === "dns-failed" ? 502 : 403;
  if (error instanceof TlsClientHelloError) return 403;
  if (error instanceof Error && error.message.includes("byte-limit")) return 413;
  return 502;
}

function auditDenied(
  audit: (event: EgressAuditEvent) => void,
  protocol: "http" | "connect",
  error: unknown,
  hostname?: string,
  port?: number,
): void {
  const reason = error instanceof EgressPolicyError || error instanceof TlsClientHelloError
    ? error.code
    : error instanceof Error ? error.message : "proxy-error";
  auditEvent(audit, { action: "deny", protocol, reason, ...(hostname ? { hostname } : {}), ...(port ? { port } : {}) });
}

function auditEvent(audit: (event: EgressAuditEvent) => void, event: Omit<EgressAuditEvent, "timestamp">): void {
  audit({ timestamp: new Date().toISOString(), ...event });
}

function writeSocketError(socket: Duplex, status: number, message: string): void {
  if (socket.destroyed) return;
  socket.end(`HTTP/1.1 ${status} ${http.STATUS_CODES[status] ?? "Error"}\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: ${Buffer.byteLength(message) + 1}\r\n\r\n${message}\n`);
}

async function waitForConnect(socket: Socket, timeoutMs: number): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("upstream-connect-timeout")), timeoutMs);
    timer.unref();
    socket.once("connect", () => { clearTimeout(timer); resolve(); });
    socket.once("error", (error) => { clearTimeout(timer); reject(error); });
  });
}

async function receiveTlsClientHello(
  client: Duplex,
  initial: Buffer,
  expectedHostname: string,
  maxBytes: number,
  timeoutMs: number,
): Promise<Buffer> {
  client.pause();
  if (maxBytes < 256 || initial.length > maxBytes) {
    throw new TlsClientHelloError("client-hello-too-large", "TLS ClientHello exceeds the proxy limit");
  }
  let buffered = Buffer.from(initial);
  const initialInspection = inspectTlsClientHello(buffered, expectedHostname, maxBytes);
  if (initialInspection.state === "complete") return buffered;

  return await new Promise<Buffer>((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => fail(new Error("client-hello-timeout")), timeoutMs);
    timer.unref();
    const cleanup = () => {
      clearTimeout(timer);
      client.off("data", onData);
      client.off("end", onEnd);
      client.off("close", onClose);
      client.off("error", fail);
    };
    const complete = () => {
      if (settled) return;
      settled = true;
      client.pause();
      cleanup();
      resolve(buffered);
    };
    function fail(error: Error) {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    }
    const onData = (chunk: Buffer) => {
      try {
        if (chunk.length > maxBytes - buffered.length) {
          throw new TlsClientHelloError("client-hello-too-large", "TLS ClientHello exceeds the proxy limit");
        }
        buffered = Buffer.concat([buffered, chunk], buffered.length + chunk.length);
        if (inspectTlsClientHello(buffered, expectedHostname, maxBytes).state === "complete") complete();
      } catch (error) {
        fail(error instanceof Error ? error : new Error("invalid-client-hello"));
      }
    };
    const onEnd = () => fail(new Error("client-closed-before-client-hello"));
    const onClose = () => fail(new Error("client-closed-before-client-hello"));
    client.on("data", onData);
    client.once("end", onEnd);
    client.once("close", onClose);
    client.once("error", fail);
    client.resume();
  });
}

async function waitForTunnelClose(client: Duplex, upstream: Duplex): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const complete = () => { if (!settled) { settled = true; resolve(); } };
    const fail = (error: Error) => { if (!settled) { settled = true; reject(error); } };
    client.once("close", complete);
    upstream.once("close", complete);
    client.once("error", fail);
    upstream.once("error", fail);
  });
}

async function finishedHttp(upstream: http.ClientRequest, response: http.ServerResponse): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const complete = () => { if (!settled) { settled = true; resolve(); } };
    const fail = (error: Error) => { if (!settled) { settled = true; reject(error); } };
    response.once("finish", complete);
    response.once("close", complete);
    upstream.once("error", fail);
  });
}

function positiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error(`${name} must be a positive integer`);
  return value;
}
