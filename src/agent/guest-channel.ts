import { connect } from "node:net";
import {
  decodeGuestFrames,
  encodeGuestFrame,
  GuestRequest,
  GuestResponse,
  MAX_GUEST_FRAME_BYTES,
  type GuestErrorCode,
} from "../guest-protocol.js";

export type GuestEndpoint =
  | { kind: "unix"; path: string }
  | { kind: "firecracker-vsock"; path: string; port: number };

export class GuestChannelError extends Error {
  constructor(message: string, readonly code: GuestErrorCode | "transport") { super(message); }
}

/**
 * Execute one bounded request over a private runtime socket. One connection per
 * request keeps failures isolated and maps directly onto Firecracker's
 * host-initiated vsock handshake.
 */
export async function requestGuest(endpoint: GuestEndpoint, input: GuestRequest, timeoutMs = 10_000): Promise<unknown> {
  const request = GuestRequest.parse(input);
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 120_000) throw new Error("Invalid guest request timeout");
  if (endpoint.kind === "firecracker-vsock" && (!Number.isSafeInteger(endpoint.port) || endpoint.port < 1 || endpoint.port > 0xffff_ffff)) {
    throw new Error("Invalid guest vsock port");
  }

  return new Promise((resolve, reject) => {
    const socket = connect(endpoint.path);
    let settled = false;
    let handshake = endpoint.kind === "firecracker-vsock";
    let handshakeBuffer = Buffer.alloc(0);
    let frameBuffer = Buffer.alloc(0);

    const finish = (error?: Error, result?: unknown) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (error) reject(error);
      else resolve(result);
    };

    const sendRequest = () => {
      try { socket.write(encodeGuestFrame(request)); }
      catch (error) { finish(asTransportError(error)); }
    };

    const timer = setTimeout(() => finish(new GuestChannelError("Guest request timed out", "transport")), timeoutMs);
    timer.unref();

    socket.once("connect", () => {
      if (endpoint.kind === "firecracker-vsock") socket.write(`CONNECT ${endpoint.port}\n`);
      else sendRequest();
    });
    socket.on("data", (chunk: Buffer) => {
      try {
        if (handshake) {
          handshakeBuffer = Buffer.concat([handshakeBuffer, chunk]);
          if (handshakeBuffer.byteLength > 128) throw new GuestChannelError("Invalid Firecracker vsock handshake", "transport");
          const newline = handshakeBuffer.indexOf(0x0a);
          if (newline < 0) return;
          const response = handshakeBuffer.subarray(0, newline).toString("ascii");
          if (!/^OK [0-9]+$/.test(response)) throw new GuestChannelError("Firecracker rejected the guest channel", "transport");
          const remainder = handshakeBuffer.subarray(newline + 1);
          handshakeBuffer = Buffer.alloc(0);
          handshake = false;
          sendRequest();
          if (remainder.byteLength) consumeFrames(remainder);
          return;
        }
        consumeFrames(chunk);
      } catch (error) { finish(asTransportError(error)); }
    });
    socket.once("error", (error) => finish(new GuestChannelError(`Guest channel unavailable: ${error.message}`, "transport")));
    socket.once("close", () => {
      if (!settled) finish(new GuestChannelError("Guest channel closed before responding", "transport"));
    });

    function consumeFrames(chunk: Buffer) {
      frameBuffer = Buffer.concat([frameBuffer, chunk]);
      if (frameBuffer.byteLength > MAX_GUEST_FRAME_BYTES) throw new GuestChannelError("Guest response exceeded the maximum size", "transport");
      const decoded = decodeGuestFrames(frameBuffer);
      frameBuffer = Buffer.from(decoded.remainder);
      if (decoded.frames.length === 0) return;
      if (decoded.frames.length !== 1 || frameBuffer.byteLength !== 0) throw new GuestChannelError("Guest sent an unexpected response sequence", "transport");
      const response = GuestResponse.parse(decoded.frames[0]);
      if (response.id !== request.id) throw new GuestChannelError("Guest response id did not match the request", "transport");
      if (!response.ok) finish(new GuestChannelError(response.error.message, response.error.code));
      else finish(undefined, response.result);
    }
  });
}

function asTransportError(error: unknown) {
  if (error instanceof GuestChannelError) return error;
  return new GuestChannelError(error instanceof Error ? error.message : "Invalid guest response", "transport");
}
