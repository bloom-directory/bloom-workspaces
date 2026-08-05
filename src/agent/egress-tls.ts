import { normalizeHostname } from "./egress-policy.js";

export interface TlsClientHelloInspection {
  state: "incomplete" | "complete";
  /** Number of raw TLS bytes through the record containing the ClientHello. */
  bytesConsumed?: number;
}

export class TlsClientHelloError extends Error {
  constructor(
    public readonly code:
      | "not-tls"
      | "malformed-client-hello"
      | "client-hello-too-large"
      | "missing-sni"
      | "sni-mismatch"
      | "encrypted-client-hello-forbidden",
    message: string,
  ) {
    super(message);
    this.name = "TlsClientHelloError";
  }
}

const TLS_HANDSHAKE_RECORD = 22;
const CLIENT_HELLO = 1;
const SERVER_NAME_EXTENSION = 0;
const ENCRYPTED_CLIENT_HELLO_EXTENSION = 0xfe0d;
const MAX_TLS_RECORD_PAYLOAD = (16 * 1024) + 256;

/**
 * Inspects one bounded CONNECT preface. It accepts TCP and TLS-record
 * fragmentation, but never guesses at a hostname or accepts opaque ECH.
 */
export function inspectTlsClientHello(
  input: Buffer,
  expectedHostname: string,
  maxBytes = 64 * 1024,
): TlsClientHelloInspection {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 256) throw new Error("maxBytes must be an integer of at least 256");
  if (input.length > maxBytes) throw tlsError("client-hello-too-large", "TLS ClientHello exceeds the proxy limit");
  const expected = normalizeHostname(expectedHostname);
  let recordOffset = 0;
  const handshakeParts: Buffer[] = [];
  let handshakeBytes = 0;

  while (true) {
    if (input.length - recordOffset < 5) return { state: "incomplete" };
    if (input[recordOffset] !== TLS_HANDSHAKE_RECORD) throw tlsError("not-tls", "CONNECT accepts TLS ClientHello records only");
    const recordVersion = input.readUInt16BE(recordOffset + 1);
    if (recordVersion < 0x0301 || recordVersion > 0x0304) throw tlsError("not-tls", "Invalid TLS record version");
    const recordLength = input.readUInt16BE(recordOffset + 3);
    if (recordLength === 0 || recordLength > MAX_TLS_RECORD_PAYLOAD) {
      throw tlsError("malformed-client-hello", "Invalid TLS handshake record length");
    }
    const recordEnd = recordOffset + 5 + recordLength;
    if (recordEnd > maxBytes) throw tlsError("client-hello-too-large", "TLS ClientHello exceeds the proxy limit");
    if (input.length < recordEnd) return { state: "incomplete" };

    const payload = input.subarray(recordOffset + 5, recordEnd);
    handshakeParts.push(payload);
    handshakeBytes += payload.length;
    recordOffset = recordEnd;
    const handshake = handshakeParts.length === 1 ? handshakeParts[0] : Buffer.concat(handshakeParts, handshakeBytes);
    if (!handshake) return { state: "incomplete" };
    if (handshake.length < 4) continue;
    if (handshake[0] !== CLIENT_HELLO) throw tlsError("not-tls", "First TLS handshake message is not ClientHello");
    const helloLength = handshake.readUIntBE(1, 3);
    const framedLength = helloLength + 4;
    if (framedLength > maxBytes) throw tlsError("client-hello-too-large", "TLS ClientHello exceeds the proxy limit");
    if (handshake.length < framedLength) continue;
    if (handshake.length !== framedLength) {
      throw tlsError("malformed-client-hello", "Unexpected handshake bytes follow ClientHello");
    }

    validateClientHello(handshake.subarray(4), expected);
    return { state: "complete", bytesConsumed: recordOffset };
  }
}

function validateClientHello(hello: Buffer, expectedHostname: string): void {
  let offset = 0;
  requireBytes(hello, offset, 34);
  const legacyVersion = hello.readUInt16BE(offset);
  if (legacyVersion < 0x0301 || legacyVersion > 0x0303) throw tlsError("malformed-client-hello", "Invalid ClientHello legacy version");
  offset += 34; // legacy_version + random

  requireBytes(hello, offset, 1);
  const sessionIdLength = hello[offset] ?? 0;
  if (sessionIdLength > 32) throw tlsError("malformed-client-hello", "Invalid TLS session id length");
  offset += 1;
  requireBytes(hello, offset, sessionIdLength);
  offset += sessionIdLength;

  requireBytes(hello, offset, 2);
  const cipherSuitesLength = hello.readUInt16BE(offset);
  offset += 2;
  if (cipherSuitesLength < 2 || cipherSuitesLength % 2 !== 0) throw tlsError("malformed-client-hello", "Invalid cipher suite vector");
  requireBytes(hello, offset, cipherSuitesLength);
  offset += cipherSuitesLength;

  requireBytes(hello, offset, 1);
  const compressionLength = hello[offset] ?? 0;
  offset += 1;
  if (compressionLength < 1) throw tlsError("malformed-client-hello", "Invalid compression methods vector");
  requireBytes(hello, offset, compressionLength);
  offset += compressionLength;

  requireBytes(hello, offset, 2);
  const extensionsLength = hello.readUInt16BE(offset);
  offset += 2;
  if (extensionsLength !== hello.length - offset) throw tlsError("malformed-client-hello", "Invalid ClientHello extensions length");
  const extensionsEnd = offset + extensionsLength;
  let sni: string | undefined;

  while (offset < extensionsEnd) {
    requireBytes(hello, offset, 4);
    const extensionType = hello.readUInt16BE(offset);
    const extensionLength = hello.readUInt16BE(offset + 2);
    offset += 4;
    requireBytes(hello, offset, extensionLength);
    const extension = hello.subarray(offset, offset + extensionLength);
    offset += extensionLength;
    if (extensionType === ENCRYPTED_CLIENT_HELLO_EXTENSION) {
      throw tlsError("encrypted-client-hello-forbidden", "Encrypted ClientHello cannot be policy inspected");
    }
    if (extensionType === SERVER_NAME_EXTENSION) {
      if (sni !== undefined) throw tlsError("malformed-client-hello", "Duplicate server_name extension");
      sni = parseSingleServerName(extension);
    }
  }

  if (sni === undefined) throw tlsError("missing-sni", "TLS ClientHello does not contain SNI");
  if (sni !== expectedHostname) throw tlsError("sni-mismatch", "TLS SNI does not match CONNECT authority");
}

function parseSingleServerName(extension: Buffer): string {
  if (extension.length < 5) throw tlsError("malformed-client-hello", "Malformed server_name extension");
  const listLength = extension.readUInt16BE(0);
  if (listLength !== extension.length - 2) throw tlsError("malformed-client-hello", "Invalid server_name list length");
  if (extension[2] !== 0) throw tlsError("malformed-client-hello", "Only DNS host_name SNI is accepted");
  const nameLength = extension.readUInt16BE(3);
  if (nameLength < 1 || nameLength !== extension.length - 5 || nameLength > 253) {
    throw tlsError("malformed-client-hello", "Invalid SNI hostname length");
  }
  const nameBytes = extension.subarray(5);
  if (nameBytes.some((byte) => byte < 0x21 || byte > 0x7e)) throw tlsError("malformed-client-hello", "SNI must be ASCII");
  const name = nameBytes.toString("ascii");
  if (name.endsWith(".")) throw tlsError("malformed-client-hello", "SNI must not have a trailing dot");
  try {
    return normalizeHostname(name);
  } catch {
    throw tlsError("malformed-client-hello", "SNI is not a valid public hostname");
  }
}

function requireBytes(buffer: Buffer, offset: number, length: number): void {
  if (length < 0 || offset < 0 || offset + length > buffer.length) {
    throw tlsError("malformed-client-hello", "Truncated ClientHello field");
  }
}

function tlsError(code: TlsClientHelloError["code"], message: string): TlsClientHelloError {
  return new TlsClientHelloError(code, message);
}
