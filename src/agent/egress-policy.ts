import { lookup as nodeLookup } from "node:dns/promises";
import { isIP } from "node:net";
import { domainToASCII } from "node:url";

export type EgressProtocol = "http" | "connect";

export interface ResolvedAddress {
  address: string;
  family: 4 | 6;
}

export interface ApprovedDestination extends ResolvedAddress {
  hostname: string;
  port: number;
  protocol: EgressProtocol;
}

export interface EgressPolicyOptions {
  /** Exact hostnames or subdomain patterns such as `*.npmjs.org`. Empty fails closed. */
  allowedHosts?: readonly string[];
  allowedHttpPorts?: readonly number[];
  allowedConnectPorts?: readonly number[];
  dnsTimeoutMs?: number;
  lookup?: (hostname: string) => Promise<readonly ResolvedAddress[]>;
}

export const DEFAULT_PACKAGE_HOSTS = Object.freeze([
  "dl-cdn.alpinelinux.org",
  "github.com",
  "*.githubusercontent.com",
  "objects.githubusercontent.com",
  "registry.npmjs.org",
  "*.npmjs.org",
  "pypi.org",
  "files.pythonhosted.org",
  "index.crates.io",
  "static.crates.io",
  "nodejs.org",
]);

export class EgressPolicyError extends Error {
  constructor(
    public readonly code:
      | "invalid-authority"
      | "credentials-forbidden"
      | "ip-literal-forbidden"
      | "hostname-forbidden"
      | "port-forbidden"
      | "dns-failed"
      | "dns-empty"
      | "address-forbidden",
    message: string,
  ) {
    super(message);
    this.name = "EgressPolicyError";
  }
}

export class EgressPolicy {
  readonly #hostPatterns: readonly HostPattern[];
  readonly #httpPorts: ReadonlySet<number>;
  readonly #connectPorts: ReadonlySet<number>;
  readonly #dnsTimeoutMs: number;
  readonly #lookup: (hostname: string) => Promise<readonly ResolvedAddress[]>;

  constructor(options: EgressPolicyOptions = {}) {
    this.#hostPatterns = (options.allowedHosts ?? []).map(parseHostPattern);
    this.#httpPorts = new Set(options.allowedHttpPorts ?? [80]);
    this.#connectPorts = new Set(options.allowedConnectPorts ?? [443]);
    for (const port of [...this.#httpPorts, ...this.#connectPorts]) validatePort(port);
    this.#dnsTimeoutMs = validatePositiveInteger(options.dnsTimeoutMs ?? 5_000, "dnsTimeoutMs");
    this.#lookup = options.lookup ?? defaultLookup;
  }

  async approve(host: string, port: number, protocol: EgressProtocol): Promise<ApprovedDestination> {
    const hostname = normalizeHostname(host);
    if (isIP(hostname) !== 0) {
      throw new EgressPolicyError("ip-literal-forbidden", "IP-literal destinations are forbidden");
    }
    if (!this.#hostPatterns.some((pattern) => hostMatches(hostname, pattern))) {
      throw new EgressPolicyError("hostname-forbidden", "Destination hostname is not allowlisted");
    }
    validatePort(port);
    const ports = protocol === "connect" ? this.#connectPorts : this.#httpPorts;
    if (!ports.has(port)) {
      throw new EgressPolicyError("port-forbidden", "Destination port is not allowed for this protocol");
    }

    let answers: readonly ResolvedAddress[];
    try {
      answers = await withTimeout(this.#lookup(hostname), this.#dnsTimeoutMs);
    } catch {
      throw new EgressPolicyError("dns-failed", "Destination DNS resolution failed");
    }
    if (answers.length === 0) throw new EgressPolicyError("dns-empty", "Destination DNS returned no addresses");

    // Reject the entire answer set if any record is unsafe. This avoids selecting a
    // public answer now and a private answer after a retry or family fallback.
    for (const answer of answers) {
      const detectedFamily = isIP(answer.address);
      if (detectedFamily !== answer.family || !isPublicAddress(answer.address)) {
        throw new EgressPolicyError("address-forbidden", "Destination DNS returned a non-public address");
      }
    }

    const approved = answers[0];
    if (!approved) throw new EgressPolicyError("dns-empty", "Destination DNS returned no addresses");
    return { hostname, port, protocol, address: approved.address, family: approved.family };
  }
}

export function parseProxyAuthority(authority: string, defaultPort?: number): { hostname: string; port: number } {
  if (
    authority.length === 0
    || authority.length > 512
    || /[\u0000-\u0020\u007f/\\?#]/u.test(authority)
  ) {
    throw new EgressPolicyError("invalid-authority", "Malformed proxy authority");
  }
  if (authority.includes("@")) {
    throw new EgressPolicyError("credentials-forbidden", "Credentials in proxy authority are forbidden");
  }
  if (authority.startsWith("[")) {
    throw new EgressPolicyError("ip-literal-forbidden", "IP-literal destinations are forbidden");
  }

  const separators = authority.match(/:/gu)?.length ?? 0;
  if (separators > 1) {
    throw new EgressPolicyError("invalid-authority", "Malformed proxy authority");
  }
  const separator = authority.lastIndexOf(":");
  const rawHostname = separator >= 0 ? authority.slice(0, separator) : authority;
  const rawPort = separator >= 0 ? authority.slice(separator + 1) : undefined;
  if (rawPort === "" || (rawPort !== undefined && !/^[0-9]{1,5}$/u.test(rawPort))) {
    throw new EgressPolicyError("invalid-authority", "Malformed proxy port");
  }
  if (rawPort === undefined && defaultPort === undefined) {
    throw new EgressPolicyError("invalid-authority", "Proxy authority must include a port");
  }
  const hostname = normalizeHostname(rawHostname);
  if (isIP(hostname) !== 0) {
    throw new EgressPolicyError("ip-literal-forbidden", "IP-literal destinations are forbidden");
  }
  const port = rawPort === undefined ? defaultPort : Number(rawPort);
  if (port === undefined) throw new EgressPolicyError("invalid-authority", "Proxy authority must include a port");
  validatePort(port);
  return { hostname, port };
}

export function normalizeHostname(input: string): string {
  const withoutFinalDot = input.endsWith(".") ? input.slice(0, -1) : input;
  const hostname = domainToASCII(withoutFinalDot).toLowerCase();
  if (
    hostname.length === 0
    || hostname.length > 253
    || hostname.includes("..")
    || !hostname.split(".").every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label))
  ) {
    throw new EgressPolicyError("invalid-authority", "Malformed destination hostname");
  }
  if (
    hostname === "localhost"
    || hostname.endsWith(".localhost")
    || hostname.endsWith(".local")
    || hostname.endsWith(".internal")
    || hostname === "home.arpa"
    || hostname.endsWith(".home.arpa")
  ) {
    throw new EgressPolicyError("hostname-forbidden", "Local destination names are forbidden");
  }
  return hostname;
}

export function isPublicAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return isPublicIpv4(address);
  if (family === 6) return isPublicIpv6(address);
  return false;
}

interface HostPattern {
  hostname: string;
  includeSubdomains: boolean;
}

function parseHostPattern(input: string): HostPattern {
  const includeSubdomains = input.startsWith("*.");
  const hostname = normalizeHostname(includeSubdomains ? input.slice(2) : input);
  return { hostname, includeSubdomains };
}

function hostMatches(hostname: string, pattern: HostPattern): boolean {
  return pattern.includeSubdomains
    ? hostname.length > pattern.hostname.length && hostname.endsWith(`.${pattern.hostname}`)
    : hostname === pattern.hostname;
}

function validatePort(port: number): void {
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new EgressPolicyError("invalid-authority", "Invalid destination port");
  }
}

function validatePositiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error(`${name} must be a positive integer`);
  return value;
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error("DNS resolution timed out")), timeoutMs);
        timer.unref();
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function defaultLookup(hostname: string): Promise<readonly ResolvedAddress[]> {
  const results = await nodeLookup(hostname, { all: true, verbatim: true });
  return results.map(({ address, family }) => {
    if (family !== 4 && family !== 6) throw new Error("Unsupported DNS address family");
    return { address, family };
  });
}

function isPublicIpv4(address: string): boolean {
  const value = ipv4ToNumber(address);
  if (value === undefined) return false;
  return ![
    ["0.0.0.0", 8],
    ["10.0.0.0", 8],
    ["100.64.0.0", 10],
    ["127.0.0.0", 8],
    ["168.63.129.16", 32], // Azure platform virtual IP / WireServer
    ["169.254.0.0", 16],
    ["172.16.0.0", 12],
    ["192.0.0.0", 24],
    ["192.0.2.0", 24],
    ["192.88.99.0", 24],
    ["192.168.0.0", 16],
    ["198.18.0.0", 15],
    ["198.51.100.0", 24],
    ["203.0.113.0", 24],
    ["224.0.0.0", 4],
    ["240.0.0.0", 4],
  ].some(([base, bits]) => ipv4CidrContains(value, base as string, bits as number));
}

function ipv4ToNumber(address: string): number | undefined {
  const octets = address.split(".");
  if (octets.length !== 4) return undefined;
  let value = 0;
  for (const octet of octets) {
    if (!/^(?:0|[1-9][0-9]{0,2})$/u.test(octet)) return undefined;
    const parsed = Number(octet);
    if (parsed > 255) return undefined;
    value = (value * 256) + parsed;
  }
  return value >>> 0;
}

function ipv4CidrContains(value: number, base: string, bits: number): boolean {
  const baseValue = ipv4ToNumber(base);
  if (baseValue === undefined) return false;
  const divisor = 2 ** (32 - bits);
  return Math.floor(value / divisor) === Math.floor(baseValue / divisor);
}

function isPublicIpv6(address: string): boolean {
  const value = ipv6ToBigInt(address);
  if (value === undefined) return false;
  // Public unicast allocations are inside 2000::/3. This intentionally denies
  // ULA, link-local, multicast, unspecified, loopback, IPv4-mapped and NAT64.
  if ((value >> 125n) !== 1n) return false;
  return ![
    ["2001::", 32], // Teredo
    ["2001:2::", 48], // benchmarking
    ["2001:10::", 28], // ORCHID
    ["2001:20::", 28], // ORCHIDv2
    ["2001:db8::", 32], // documentation
    ["2002::", 16], // deprecated 6to4
    ["3ffe::", 16], // deprecated 6bone
  ].some(([base, bits]) => ipv6CidrContains(value, base as string, bits as number));
}

function ipv6ToBigInt(address: string): bigint | undefined {
  if (address.includes("%")) return undefined;
  let working = address.toLowerCase();
  if (working.includes(".")) {
    const separator = working.lastIndexOf(":");
    if (separator < 0) return undefined;
    const ipv4 = ipv4ToNumber(working.slice(separator + 1));
    if (ipv4 === undefined) return undefined;
    working = `${working.slice(0, separator)}:${(ipv4 >>> 16).toString(16)}:${(ipv4 & 0xffff).toString(16)}`;
  }
  const halves = working.split("::");
  if (halves.length > 2) return undefined;
  const left = halves[0] === "" ? [] : halves[0]?.split(":") ?? [];
  const right = halves.length === 1 || halves[1] === "" ? [] : halves[1]?.split(":") ?? [];
  const omitted = 8 - left.length - right.length;
  if ((halves.length === 1 && omitted !== 0) || (halves.length === 2 && omitted < 1)) return undefined;
  const words = [...left, ...Array.from({ length: omitted }, () => "0"), ...right];
  if (words.length !== 8 || words.some((word) => !/^[0-9a-f]{1,4}$/u.test(word))) return undefined;
  return words.reduce((value, word) => (value << 16n) | BigInt(`0x${word}`), 0n);
}

function ipv6CidrContains(value: bigint, base: string, bits: number): boolean {
  const baseValue = ipv6ToBigInt(base);
  return baseValue !== undefined && (value >> BigInt(128 - bits)) === (baseValue >> BigInt(128 - bits));
}
