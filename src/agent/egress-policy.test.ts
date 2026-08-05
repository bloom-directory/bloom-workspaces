import { EventEmitter } from "node:events";
import { createServer, request as httpRequest, type IncomingMessage, type Server } from "node:http";
import { connect as connectTcp, createServer as createTcpServer, type AddressInfo, type Server as TcpServer, type Socket } from "node:net";
import { describe, expect, it, vi } from "vitest";
import { createConnectOptions, createEgressProxy, createHttpUpstreamOptions } from "./egress-proxy.js";
import { inspectTlsClientHello, TlsClientHelloError } from "./egress-tls.js";
import {
  EgressPolicy,
  EgressPolicyError,
  isPublicAddress,
  parseProxyAuthority,
  type ResolvedAddress,
} from "./egress-policy.js";

const publicAnswer = [{ address: "104.16.24.34", family: 4 as const }];

describe("egress destination policy", () => {
  it("allows an allowlisted package host and returns the DNS-approved address", async () => {
    const lookup = vi.fn(async () => publicAnswer);
    const policy = new EgressPolicy({ allowedHosts: ["registry.npmjs.org"], lookup });

    await expect(policy.approve("registry.npmjs.org", 443, "connect")).resolves.toEqual({
      hostname: "registry.npmjs.org",
      port: 443,
      protocol: "connect",
      address: "104.16.24.34",
      family: 4,
    });
    expect(lookup).toHaveBeenCalledWith("registry.npmjs.org");
  });

  it("fails closed with an empty hostname allowlist", async () => {
    const lookup = vi.fn(async () => publicAnswer);
    const policy = new EgressPolicy({ lookup });
    await expect(policy.approve("registry.npmjs.org", 443, "connect")).rejects.toMatchObject({ code: "hostname-forbidden" });
    expect(lookup).not.toHaveBeenCalled();
  });

  it("allows only true subdomains for wildcard patterns", async () => {
    const policy = new EgressPolicy({ allowedHosts: ["*.npmjs.org"], lookup: async () => publicAnswer });
    await expect(policy.approve("cdn.npmjs.org", 443, "connect")).resolves.toMatchObject({ hostname: "cdn.npmjs.org" });
    await expect(policy.approve("npmjs.org", 443, "connect")).rejects.toMatchObject({ code: "hostname-forbidden" });
    await expect(policy.approve("evilnpmjs.org", 443, "connect")).rejects.toMatchObject({ code: "hostname-forbidden" });
  });

  it.each([
    "0.0.0.0",
    "10.0.0.1",
    "100.100.100.200",
    "100.64.0.1",
    "127.0.0.1",
    "168.63.129.16",
    "169.254.169.254",
    "172.16.0.1",
    "192.0.0.192",
    "192.0.2.1",
    "192.168.1.1",
    "198.18.0.1",
    "198.51.100.1",
    "203.0.113.1",
    "224.0.0.1",
    "255.255.255.255",
    "::",
    "::1",
    "::ffff:127.0.0.1",
    "64:ff9b::a9fe:a9fe",
    "fc00::1",
    "fe80::1",
    "ff02::1",
    "2001:db8::1",
    "2001:2::1",
    "2001:10::1",
    "2002::1",
  ])("classifies sensitive/non-global address %s as forbidden", (address) => {
    expect(isPublicAddress(address)).toBe(false);
  });

  it.each(["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])("classifies representative public address %s as public", (address) => {
    expect(isPublicAddress(address)).toBe(true);
  });

  it("rejects every DNS answer set containing a sensitive address", async () => {
    const answers: ResolvedAddress[] = [
      { address: "104.16.24.34", family: 4 },
      { address: "169.254.169.254", family: 4 },
    ];
    const policy = new EgressPolicy({ allowedHosts: ["registry.npmjs.org"], lookup: async () => answers });
    await expect(policy.approve("registry.npmjs.org", 443, "connect")).rejects.toMatchObject({ code: "address-forbidden" });
  });

  it("rejects DNS family mismatches instead of trusting resolver metadata", async () => {
    const answers = [{ address: "127.0.0.1", family: 6 as const }];
    const policy = new EgressPolicy({ allowedHosts: ["registry.npmjs.org"], lookup: async () => answers });
    await expect(policy.approve("registry.npmjs.org", 443, "connect")).rejects.toMatchObject({ code: "address-forbidden" });
  });

  it("bounds DNS resolution time", async () => {
    const policy = new EgressPolicy({
      allowedHosts: ["registry.npmjs.org"],
      dnsTimeoutMs: 1,
      lookup: async () => await new Promise<ResolvedAddress[]>(() => undefined),
    });
    await expect(policy.approve("registry.npmjs.org", 443, "connect")).rejects.toMatchObject({ code: "dns-failed" });
  });

  it.each([
    ["127.0.0.1:443", "ip-literal-forbidden"],
    ["[::1]:443", "ip-literal-forbidden"],
    ["user@registry.npmjs.org:443", "credentials-forbidden"],
    ["registry.npmjs.org:22", "port-forbidden"],
  ])("denies sensitive authority %s", async (authority, code) => {
    const policy = new EgressPolicy({ allowedHosts: ["registry.npmjs.org"], lookup: async () => publicAnswer });
    await expect(async () => {
      const parsed = parseProxyAuthority(authority);
      await policy.approve(parsed.hostname, parsed.port, "connect");
    }).rejects.toMatchObject({ code });
  });

  it("uses the approved IP—not the hostname—for both upstream connection modes", async () => {
    const policy = new EgressPolicy({ allowedHosts: ["registry.npmjs.org"], lookup: async () => publicAnswer });
    const destination = await policy.approve("registry.npmjs.org", 443, "connect");
    expect(createConnectOptions(destination)).toEqual({ host: "104.16.24.34", port: 443, family: 4 });

    const httpDestination = { ...destination, port: 80, protocol: "http" as const };
    const request = Object.assign(new EventEmitter(), { method: "GET", headers: {} }) as IncomingMessage;
    const upstream = createHttpUpstreamOptions(httpDestination, request, new URL("http://registry.npmjs.org/package?q=1"));
    expect(upstream.host).toBe("104.16.24.34");
    expect(upstream.headers).toMatchObject({ host: "registry.npmjs.org", via: "1.1 bloom-egress" });
  });

  it("uses distinct port sets for ordinary HTTP and CONNECT", async () => {
    const policy = new EgressPolicy({
      allowedHosts: ["registry.npmjs.org"],
      allowedHttpPorts: [80],
      allowedConnectPorts: [443],
      lookup: async () => publicAnswer,
    });
    await expect(policy.approve("registry.npmjs.org", 443, "http")).rejects.toBeInstanceOf(EgressPolicyError);
    await expect(policy.approve("registry.npmjs.org", 80, "connect")).rejects.toMatchObject({ code: "port-forbidden" });
  });
});

describe("egress proxy limits", () => {
  it.each(["proxy-authorization", "authorization", "cookie"])("rejects %s credentials generically before resolving a destination", async (header) => {
    const approve = vi.fn();
    const audit = vi.fn();
    const proxy = createEgressProxy({ policy: { approve } as unknown as EgressPolicy, audit });
    await proxy.listen(0);
    try {
      const address = proxy.server.address() as AddressInfo;
      const result = await proxyRequest(address.port, {
        path: "http://registry.npmjs.org/package",
        headers: { [header]: "redacted-secret" },
      });
      expect(result).toEqual({ status: 403, body: "Egress request denied\n" });
      expect(approve).not.toHaveBeenCalled();
      expect(audit).toHaveBeenCalledWith(expect.objectContaining({ action: "deny", reason: "credentials-forbidden" }));
    } finally {
      await proxy.close();
    }
  });

  it("rejects an upstream response whose declared size exceeds the total byte limit", async () => {
    const upstream = createServer((_request, response) => {
      response.writeHead(200, { "content-length": "2" });
      response.end("aa");
    });
    await listen(upstream);
    const upstreamAddress = upstream.address() as AddressInfo;
    const approve = vi.fn(async () => ({
      hostname: "registry.npmjs.org",
      port: upstreamAddress.port,
      protocol: "http" as const,
      address: "127.0.0.1",
      family: 4 as const,
    }));
    const proxy = createEgressProxy({
      policy: { approve } as unknown as EgressPolicy,
      maxBytesPerConnection: 1,
      audit: () => undefined,
    });
    await proxy.listen(0);
    try {
      const proxyAddress = proxy.server.address() as AddressInfo;
      const result = await proxyRequest(proxyAddress.port, { path: "http://registry.npmjs.org/package" });
      expect(result).toEqual({ status: 413, body: "Egress request denied\n" });
    } finally {
      await proxy.close();
      await close(upstream);
    }
  });

  it("rejects oversized requests before opening the approved upstream", async () => {
    const approve = vi.fn(async () => ({
      hostname: "registry.npmjs.org",
      port: 80,
      protocol: "http" as const,
      address: "104.16.24.34",
      family: 4 as const,
    }));
    const proxy = createEgressProxy({
      policy: { approve } as unknown as EgressPolicy,
      maxBytesPerConnection: 1,
      audit: () => undefined,
    });
    await proxy.listen(0);
    try {
      const address = proxy.server.address() as AddressInfo;
      const result = await proxyRequest(address.port, {
        method: "POST",
        path: "http://registry.npmjs.org/package",
        headers: { "content-length": "2" },
        body: "aa",
      });
      expect(result).toEqual({ status: 413, body: "Egress request denied\n" });
      expect(approve).toHaveBeenCalledOnce();
    } finally {
      await proxy.close();
    }
  });

  it("validates explicit resource limits", () => {
    const policy = new EgressPolicy();
    expect(() => createEgressProxy({ policy, maxConcurrentConnections: 0 })).toThrow("positive integer");
    expect(() => createEgressProxy({ policy, maxBytesPerConnection: Number.POSITIVE_INFINITY })).toThrow("positive integer");
    expect(() => createEgressProxy({ policy, maxConnectionMs: 0 })).toThrow("positive integer");
    expect(() => createEgressProxy({ policy, allowedMethods: ["bad method"] })).toThrow("invalid method");
  });
});

describe("CONNECT TLS ClientHello inspection", () => {
  const hostname = "registry.npmjs.org";

  it("accepts a standard ClientHello with one exactly matching SNI", () => {
    const hello = clientHello(hostname);
    expect(inspectTlsClientHello(hello, hostname)).toEqual({ state: "complete", bytesConsumed: hello.length });
  });

  it("rejects a valid ClientHello for another SNI", () => {
    expect(() => inspectTlsClientHello(clientHello("github.com"), hostname)).toThrowError(
      expect.objectContaining({ code: "sni-mismatch" }),
    );
  });

  it("rejects a ClientHello without SNI", () => {
    expect(() => inspectTlsClientHello(clientHello(), hostname)).toThrowError(
      expect.objectContaining({ code: "missing-sni" }),
    );
  });

  it("accepts arbitrary TCP fragmentation only after the full ClientHello arrives", () => {
    const hello = clientHello(hostname);
    for (const length of [1, 4, 5, 17, hello.length - 1]) {
      expect(inspectTlsClientHello(hello.subarray(0, length), hostname)).toEqual({ state: "incomplete" });
    }
    expect(inspectTlsClientHello(Buffer.concat([
      hello.subarray(0, 7),
      hello.subarray(7, 29),
      hello.subarray(29),
    ]), hostname).state).toBe("complete");
  });

  it("accepts a ClientHello fragmented across bounded TLS handshake records", () => {
    const handshake = clientHelloHandshake(hostname);
    const fragmented = Buffer.concat([tlsHandshakeRecord(handshake.subarray(0, 11)), tlsHandshakeRecord(handshake.subarray(11))]);
    expect(inspectTlsClientHello(fragmented.subarray(0, 16), hostname)).toEqual({ state: "incomplete" });
    expect(inspectTlsClientHello(fragmented, hostname)).toEqual({ state: "complete", bytesConsumed: fragmented.length });
  });

  it("rejects oversized and malformed ClientHello framing", () => {
    expect(() => inspectTlsClientHello(Buffer.alloc(257, 0x16), hostname, 256)).toThrowError(
      expect.objectContaining({ code: "client-hello-too-large" }),
    );
    const zeroLengthRecord = Buffer.from([0x16, 0x03, 0x03, 0x00, 0x00]);
    expect(() => inspectTlsClientHello(zeroLengthRecord, hostname)).toThrowError(
      expect.objectContaining({ code: "malformed-client-hello" }),
    );
    const malformed = clientHello(hostname);
    malformed.writeUInt16BE(0xffff, malformed.length - Buffer.byteLength(hostname) - 9);
    expect(() => inspectTlsClientHello(malformed, hostname)).toThrow(TlsClientHelloError);
  });

  it("rejects Encrypted ClientHello even when the outer ClientHello has matching SNI", () => {
    expect(() => inspectTlsClientHello(clientHello(hostname, true), hostname)).toThrowError(
      expect.objectContaining({ code: "encrypted-client-hello-forbidden" }),
    );
  });

  it("rejects non-TLS CONNECT prefaces", () => {
    expect(() => inspectTlsClientHello(Buffer.from("GET / HTTP/1.1\r\n"), hostname)).toThrowError(
      expect.objectContaining({ code: "not-tls" }),
    );
  });

  it("does not open the approved upstream when SNI mismatches", async () => {
    let connections = 0;
    const upstream = createTcpServer((socket) => { connections += 1; socket.destroy(); });
    await listenTcp(upstream);
    const upstreamAddress = upstream.address() as AddressInfo;
    const proxy = createEgressProxy({
      policy: localConnectPolicy(hostname, upstreamAddress.port),
      audit: () => undefined,
    });
    await proxy.listen(0);
    let client: Socket | undefined;
    try {
      const proxyAddress = proxy.server.address() as AddressInfo;
      client = await openConnectTunnel(proxyAddress.port, hostname, clientHello("github.com"));
      await waitForSocketClose(client);
      expect(connections).toBe(0);
    } finally {
      client?.destroy();
      await proxy.close();
      await closeTcp(upstream);
    }
  });

  it("forwards a matching fragmented ClientHello intact after inspection", async () => {
    const hello = clientHello(hostname);
    let receivedResolve: ((value: Buffer) => void) | undefined;
    const received = new Promise<Buffer>((resolve) => { receivedResolve = resolve; });
    const upstream = createTcpServer((socket) => {
      const chunks: Buffer[] = [];
      socket.on("data", (chunk: Buffer) => {
        chunks.push(chunk);
        const combined = Buffer.concat(chunks);
        if (combined.length >= hello.length) {
          receivedResolve?.(combined);
          socket.destroy();
        }
      });
    });
    await listenTcp(upstream);
    const upstreamAddress = upstream.address() as AddressInfo;
    const proxy = createEgressProxy({
      policy: localConnectPolicy(hostname, upstreamAddress.port),
      audit: () => undefined,
    });
    await proxy.listen(0);
    let client: Socket | undefined;
    try {
      const proxyAddress = proxy.server.address() as AddressInfo;
      client = await openConnectTunnel(proxyAddress.port, hostname, hello, [3, 11, hello.length - 14]);
      await expect(received).resolves.toEqual(hello);
    } finally {
      client?.destroy();
      await proxy.close();
      await closeTcp(upstream);
    }
  });
});

async function proxyRequest(
  port: number,
  options: { method?: string; path: string; headers?: Record<string, string>; body?: string },
): Promise<{ status: number | undefined; body: string }> {
  return await new Promise((resolve, reject) => {
    const request = httpRequest({
      host: "127.0.0.1",
      port,
      method: options.method ?? "GET",
      path: options.path,
      headers: options.headers,
    }, (response) => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", (chunk: string) => { body += chunk; });
      response.once("end", () => resolve({ status: response.statusCode, body }));
    });
    request.once("error", reject);
    request.end(options.body);
  });
}

async function listen(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => { server.off("error", reject); resolve(); });
  });
}

async function close(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

async function listenTcp(server: TcpServer): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => { server.off("error", reject); resolve(); });
  });
}

async function closeTcp(server: TcpServer): Promise<void> {
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

function localConnectPolicy(hostname: string, port: number): EgressPolicy {
  return {
    approve: vi.fn(async () => ({ hostname, port, protocol: "connect" as const, address: "127.0.0.1", family: 4 as const })),
  } as unknown as EgressPolicy;
}

async function openConnectTunnel(
  proxyPort: number,
  hostname: string,
  hello: Buffer,
  fragments = [hello.length],
): Promise<Socket> {
  const socket = connectTcp({ host: "127.0.0.1", port: proxyPort });
  await new Promise<void>((resolve, reject) => {
    socket.once("connect", resolve);
    socket.once("error", reject);
  });
  socket.write(`CONNECT ${hostname}:443 HTTP/1.1\r\nHost: ${hostname}:443\r\n\r\n`);
  let response = "";
  await new Promise<void>((resolve, reject) => {
    const onData = (chunk: Buffer) => {
      response += chunk.toString("ascii");
      if (response.includes("\r\n\r\n")) {
        socket.off("data", onData);
        resolve();
      }
    };
    socket.on("data", onData);
    socket.once("error", reject);
  });
  expect(response).toContain("200 Connection Established");
  let offset = 0;
  for (const length of fragments) {
    socket.write(hello.subarray(offset, offset + length));
    offset += length;
  }
  if (offset !== hello.length) throw new Error("ClientHello fragment lengths do not cover the input");
  return socket;
}

async function waitForSocketClose(socket: Socket): Promise<void> {
  if (socket.destroyed) return;
  await new Promise<void>((resolve) => {
    socket.once("close", () => resolve());
    socket.once("error", () => resolve());
  });
}

function clientHello(hostname?: string, encryptedClientHello = false): Buffer {
  return tlsHandshakeRecord(clientHelloHandshake(hostname, encryptedClientHello));
}

function clientHelloHandshake(hostname?: string, encryptedClientHello = false): Buffer {
  const extensions: Buffer[] = [];
  if (hostname) {
    const name = Buffer.from(hostname, "ascii");
    const entry = Buffer.concat([Buffer.from([0]), uint16(name.length), name]);
    extensions.push(tlsExtension(0, Buffer.concat([uint16(entry.length), entry])));
  }
  if (encryptedClientHello) extensions.push(tlsExtension(0xfe0d, Buffer.alloc(0)));
  const encodedExtensions = Buffer.concat(extensions);
  const body = Buffer.concat([
    Buffer.from([0x03, 0x03]),
    Buffer.alloc(32, 0x42),
    Buffer.from([0]),
    uint16(2), Buffer.from([0x13, 0x01]),
    Buffer.from([1, 0]),
    uint16(encodedExtensions.length), encodedExtensions,
  ]);
  const header = Buffer.alloc(4);
  header[0] = 1;
  header.writeUIntBE(body.length, 1, 3);
  return Buffer.concat([header, body]);
}

function tlsHandshakeRecord(payload: Buffer): Buffer {
  return Buffer.concat([Buffer.from([0x16, 0x03, 0x03]), uint16(payload.length), payload]);
}

function tlsExtension(type: number, payload: Buffer): Buffer {
  return Buffer.concat([uint16(type), uint16(payload.length), payload]);
}

function uint16(value: number): Buffer {
  const buffer = Buffer.alloc(2);
  buffer.writeUInt16BE(value);
  return buffer;
}
