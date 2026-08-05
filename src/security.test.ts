import { createServer, type IncomingMessage } from "node:http";
import { describe, expect, it } from "vitest";
import {
  clientIp,
  hashForLog,
  opaqueToken,
  parseCookies,
  requestFingerprint,
  safeEqual,
  stableHash,
  tokenHash,
  validBrowserOrigin,
} from "./security.js";

describe("security utilities", () => {
  describe("safeEqual", () => {
    it("returns true for identical strings", () => {
      expect(safeEqual("abc123", "abc123")).toBe(true);
      expect(safeEqual("", "")).toBe(true);
    });

    it("returns false for different strings", () => {
      expect(safeEqual("abc123", "abc124")).toBe(false);
      expect(safeEqual("abc", "abcd")).toBe(false);
      expect(safeEqual("abcd", "abc")).toBe(false);
    });

    it("handles unicode safely", () => {
      expect(safeEqual("héllo", "héllo")).toBe(true);
      expect(safeEqual("héllo", "hello")).toBe(false);
    });
  });

  describe("parseCookies", () => {
    it("parses standard cookie headers", () => {
      const cookies = parseCookies("session=abc; csrf=xyz; theme=dark");
      expect(cookies.get("session")).toBe("abc");
      expect(cookies.get("csrf")).toBe("xyz");
      expect(cookies.get("theme")).toBe("dark");
    });

    it("decodes URL-encoded values", () => {
      const cookies = parseCookies("data=hello%20world");
      expect(cookies.get("data")).toBe("hello world");
    });

    it("returns empty map for undefined header", () => {
      expect(parseCookies(undefined).size).toBe(0);
    });

    it("returns empty map for empty string", () => {
      expect(parseCookies("").size).toBe(0);
    });

    it("skips entries without a value separator", () => {
      const cookies = parseCookies("valid=ok; invalid; also=good");
      expect(cookies.get("valid")).toBe("ok");
      expect(cookies.has("invalid")).toBe(false);
      expect(cookies.get("also")).toBe("good");
    });

    it("handles cookies with equals signs in values", () => {
      const cookies = parseCookies("token=a=b=c");
      expect(cookies.get("token")).toBe("a=b=c");
    });

    it("trims whitespace around keys and values", () => {
      const cookies = parseCookies("  spaced  =  value  ");
      expect(cookies.get("spaced")).toBe("value");
    });
  });

  describe("clientIp", () => {
    function mockRequest(remoteAddress: string, forwardedFor?: string): IncomingMessage {
      return {
        socket: { remoteAddress },
        headers: forwardedFor ? { "x-forwarded-for": forwardedFor } : {},
      } as unknown as IncomingMessage;
    }

    it("returns direct socket address when trustedProxyHops is 0", () => {
      expect(clientIp(mockRequest("1.2.3.4"), 0)).toBe("1.2.3.4");
    });

    it("extracts from X-Forwarded-For with 1 hop", () => {
      expect(clientIp(mockRequest("10.0.0.1", "203.0.113.5"), 1)).toBe("203.0.113.5");
    });

    it("extracts from the correct position in a multi-hop chain", () => {
      // XFF = client, proxy1; trust 2 hops → index 0 → client IP
      expect(clientIp(mockRequest("10.0.0.2", "203.0.113.5, 10.0.0.1"), 2)).toBe("203.0.113.5");
      // XFF = client, proxy1, proxy2; trust 3 hops → index 0 → client IP
      expect(clientIp(mockRequest("10.0.0.3", "203.0.113.5, 10.0.0.1, 10.0.0.2"), 3)).toBe("203.0.113.5");
    });

    it("normalizes IPv4-mapped IPv6 addresses", () => {
      expect(clientIp(mockRequest("::ffff:1.2.3.4"), 0)).toBe("1.2.3.4");
    });

    it("throws when forwarded header is missing with trusted hops > 0", () => {
      expect(() => clientIp(mockRequest("1.2.3.4"), 1)).toThrow("Missing X-Forwarded-For");
    });

    it("throws when forwarded chain is shorter than trusted hops", () => {
      expect(() => clientIp(mockRequest("1.2.3.4", "1.2.3.4"), 3)).toThrow("Invalid trusted proxy chain");
    });

    it("throws on invalid IP in chain", () => {
      expect(() => clientIp(mockRequest("1.2.3.4", "not-an-ip"), 1)).toThrow("Unable to determine client IP");
    });
  });

  describe("validBrowserOrigin", () => {
    it("accepts exact origin match", () => {
      expect(validBrowserOrigin("https://bloom.example.com", "https://bloom.example.com")).toBe(true);
    });

    it("rejects different origin", () => {
      expect(validBrowserOrigin("https://evil.example.com", "https://bloom.example.com")).toBe(false);
    });

    it("rejects undefined header", () => {
      expect(validBrowserOrigin(undefined, "https://bloom.example.com")).toBe(false);
    });

    it("rejects malformed URLs", () => {
      expect(validBrowserOrigin("not-a-url", "https://bloom.example.com")).toBe(false);
    });

    it("distinguishes http from https", () => {
      expect(validBrowserOrigin("http://bloom.example.com", "https://bloom.example.com")).toBe(false);
    });

    it("distinguishes different ports", () => {
      expect(validBrowserOrigin("https://bloom.example.com:8443", "https://bloom.example.com")).toBe(false);
    });
  });

  describe("token and hash utilities", () => {
    it("opaqueToken generates unique base64url tokens", () => {
      const a = opaqueToken();
      const b = opaqueToken();
      expect(a).not.toBe(b);
      expect(a).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(a.length).toBeGreaterThanOrEqual(32);
    });

    it("tokenHash is deterministic for same inputs", () => {
      const secret = "test-secret";
      expect(tokenHash("token-123", secret)).toBe(tokenHash("token-123", secret));
    });

    it("tokenHash differs for different tokens", () => {
      const secret = "test-secret";
      expect(tokenHash("token-a", secret)).not.toBe(tokenHash("token-b", secret));
    });

    it("tokenHash differs for different secrets", () => {
      expect(tokenHash("token-123", "secret-a")).not.toBe(tokenHash("token-123", "secret-b"));
    });

    it("stableHash is deterministic", () => {
      const secret = "test-secret";
      expect(stableHash("data", secret)).toBe(stableHash("data", secret));
    });

    it("requestFingerprint uses stableHash with ip: prefix", () => {
      const secret = "test-secret";
      const fingerprint = requestFingerprint("1.2.3.4", secret);
      expect(fingerprint).toBe(stableHash("ip:1.2.3.4", secret));
    });

    it("hashForLog returns first 16 hex chars of sha256", () => {
      const result = hashForLog("test-value");
      expect(result).toMatch(/^[0-9a-f]{16}$/);
      expect(result).toHaveLength(16);
    });

    it("hashForLog is deterministic", () => {
      expect(hashForLog("test-value")).toBe(hashForLog("test-value"));
    });
  });
});
