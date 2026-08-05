import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it } from "vitest";
import { decodeGuestFrames, encodeGuestFrame, GuestRequest, type GuestResponse } from "../guest-protocol.js";
import { GuestChannelError, requestGuest } from "./guest-channel.js";

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => { await Promise.all(cleanups.splice(0).map((cleanup) => cleanup())); });

describe("guest channel", () => {
  it("exchanges one validated request over a Unix socket", async () => {
    const endpoint = await fakeGuest((request) => ({ version: 1, id: request.id, ok: true, result: { protocol: 1 } }));
    await expect(requestGuest({ kind: "unix", path: endpoint }, GuestRequest.parse({ version: 1, id: "hello_1", operation: "hello" })))
      .resolves.toEqual({ protocol: 1 });
  });

  it("performs the Firecracker CONNECT handshake before sending the frame", async () => {
    const endpoint = await fakeGuest(
      (request) => ({ version: 1, id: request.id, ok: true, result: "ready" }),
      { handshake: "CONNECT 5001\n", response: "OK 1073741824\n" },
    );
    await expect(requestGuest({ kind: "firecracker-vsock", path: endpoint, port: 5001 }, GuestRequest.parse({ version: 1, id: "hello_2", operation: "hello" })))
      .resolves.toBe("ready");
  });

  it("maps bounded guest failures and rejects a mismatched response", async () => {
    const failed = await fakeGuest((request) => ({ version: 1, id: request.id, ok: false, error: { code: "permission_denied", message: "no" } }));
    await expect(requestGuest({ kind: "unix", path: failed }, GuestRequest.parse({ version: 1, id: "failed_1", operation: "hello" })))
      .rejects.toMatchObject({ code: "permission_denied", message: "no" });

    const mismatched = await fakeGuest(() => ({ version: 1, id: "someone_else", ok: true, result: null }));
    await expect(requestGuest({ kind: "unix", path: mismatched }, GuestRequest.parse({ version: 1, id: "failed_2", operation: "hello" })))
      .rejects.toBeInstanceOf(GuestChannelError);
  });
});

async function fakeGuest(
  respond: (request: GuestRequest) => GuestResponse,
  handshake?: { handshake: string; response: string },
) {
  const directory = await mkdtemp(join(tmpdir(), "bloom-guest-channel-"));
  const path = join(directory, "guest.sock");
  const server = createServer((socket) => {
    let buffer = Buffer.alloc(0);
    let connected = !handshake;
    socket.on("data", (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (!connected && handshake) {
        if (buffer.byteLength < Buffer.byteLength(handshake.handshake)) return;
        expect(buffer.subarray(0, Buffer.byteLength(handshake.handshake)).toString()).toBe(handshake.handshake);
        buffer = buffer.subarray(Buffer.byteLength(handshake.handshake));
        connected = true;
        socket.write(handshake.response);
      }
      if (!connected) return;
      const decoded = decodeGuestFrames(buffer);
      buffer = Buffer.from(decoded.remainder);
      const raw = decoded.frames[0];
      if (!raw) return;
      const request = GuestRequest.parse(raw);
      socket.end(encodeGuestFrame(respond(request)));
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(path, () => { server.off("error", reject); resolve(); });
  });
  cleanups.push(async () => {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    await rm(directory, { recursive: true, force: true });
  });
  return path;
}
