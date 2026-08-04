import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { createSiweMessage } from "viem/siwe";
import { describe, expect, it } from "vitest";
import type { Request, Response } from "express";
import { loadConfig } from "../config.js";
import { openDatabase } from "../db.js";
import { AuthError, issueChallenge, verifyChallenge } from "./auth.js";

const account = privateKeyToAccount(generatePrivateKey());

describe("SIWE authentication", () => {
  it("accepts one bound challenge and rejects replay", async () => {
    const config = loadConfig({ BLOOM_ORIGIN: "http://127.0.0.1:8787" });
    const db = openDatabase(":memory:");
    const challenge = issueChallenge(db, config, "ip-a");
    const message = createSiweMessage({
      address: account.address,
      chainId: challenge.chainId,
      domain: challenge.domain,
      uri: challenge.uri,
      nonce: challenge.nonce,
      statement: challenge.statement,
      issuedAt: new Date(challenge.issuedAt),
      expirationTime: new Date(challenge.expirationTime),
      version: "1",
    });
    const signature = await account.signMessage({ message });
    const request = { body: { message, signature } } as Request;
    const cookies: unknown[] = [];
    const response = { cookie: (...args: unknown[]) => cookies.push(args) } as unknown as Response;
    const result = await verifyChallenge(request, response, db, config, "ip-a");
    expect(result.wallet).toBe(account.address);
    expect(cookies).toHaveLength(1);
    await expect(verifyChallenge(request, response, db, config, "ip-a")).rejects.toBeInstanceOf(AuthError);
    db.close();
  });

  it("binds a challenge to the requesting network", async () => {
    const config = loadConfig();
    const db = openDatabase(":memory:");
    const challenge = issueChallenge(db, config, "ip-a");
    const message = createSiweMessage({
      address: account.address, chainId: challenge.chainId, domain: challenge.domain, uri: challenge.uri,
      nonce: challenge.nonce, statement: challenge.statement, issuedAt: new Date(challenge.issuedAt),
      expirationTime: new Date(challenge.expirationTime), version: "1",
    });
    const signature = await account.signMessage({ message });
    await expect(verifyChallenge({ body: { message, signature } } as Request, {} as Response, db, config, "ip-b"))
      .rejects.toThrow(/different client/);
    db.close();
  });
});
