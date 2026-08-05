#!/usr/bin/env node
import { readFile, stat } from "node:fs/promises";
import process from "node:process";
import WebSocket from "ws";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

try {
  const options = parse(process.argv.slice(2));
  const token = await readToken(options.tokenFile);
  const url = new URL(`/api/workspaces/${options.workspace}/connections/ssh/tunnel`, options.origin);
  url.protocol = "wss:";
  url.searchParams.set("lease", options.lease);
  url.searchParams.set("mode", options.mode);
  const socket = new WebSocket(url, "bloom-ssh-v1", {
    followRedirects: false,
    perMessageDeflate: false,
    handshakeTimeout: 10_000,
    maxPayload: 1024 * 1024,
    headers: { authorization: `Bearer ${token}` },
  });
  socket.binaryType = "nodebuffer";
  process.stdin.pause();
  socket.once("open", () => process.stdin.resume());
  socket.on("message", (data, binary) => {
    if (!binary) return fail("SSH gateway returned a non-binary frame");
    if (!process.stdout.write(data)) socket.pause();
  });
  process.stdout.on("drain", () => socket.resume());
  process.stdin.on("data", (chunk) => {
    if (socket.readyState !== WebSocket.OPEN) return;
    socket.send(chunk, { binary: true }, (error) => {
      if (error) fail("SSH gateway write failed");
    });
    if (socket.bufferedAmount > 1024 * 1024) {
      process.stdin.pause();
      const resume = setInterval(() => {
        if (socket.bufferedAmount <= 256 * 1024 || socket.readyState !== WebSocket.OPEN) {
          clearInterval(resume);
          if (socket.readyState === WebSocket.OPEN) process.stdin.resume();
        }
      }, 10);
      resume.unref();
    }
  });
  process.stdin.once("end", () => socket.close(1000));
  socket.once("unexpected-response", () => fail("SSH gateway rejected the tunnel"));
  socket.once("error", () => fail("SSH gateway connection failed"));
  socket.once("close", (code) => process.exit(code === 1000 ? 0 : 1));
} catch (error) {
  fail(error instanceof Error ? error.message : "SSH proxy failed");
}

function parse(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!flag?.startsWith("--") || value === undefined || values[flag.slice(2)] !== undefined) throw new Error("Invalid SSH proxy arguments");
    values[flag.slice(2)] = value;
  }
  if (Object.keys(values).length !== 5 || !values.origin || !values.workspace || !values.lease || !values.mode || !values["token-file"]) throw new Error("Missing SSH proxy arguments");
  const origin = new URL(values.origin);
  if (origin.protocol !== "https:" || origin.origin !== values.origin || origin.username || origin.password) throw new Error("SSH proxy requires an HTTPS origin");
  if (!UUID.test(values.workspace) || !UUID.test(values.lease)) throw new Error("Invalid SSH proxy lease scope");
  if (values.mode !== "shell" && values.mode !== "nfs") throw new Error("Invalid SSH proxy mode");
  return { origin: origin.origin, workspace: values.workspace.toLowerCase(), lease: values.lease.toLowerCase(), mode: values.mode, tokenFile: values["token-file"] };
}

async function readToken(path) {
  const metadata = await stat(path);
  if (!metadata.isFile() || (process.platform !== "win32" && (metadata.mode & 0o077) !== 0)) throw new Error("SSH token file must be a private regular file");
  if (typeof process.getuid === "function" && metadata.uid !== process.getuid()) throw new Error("SSH token file has the wrong owner");
  const token = (await readFile(path, { encoding: "utf8" })).trim();
  if (!/^[A-Za-z0-9_-]{32,256}$/.test(token)) throw new Error("Invalid SSH lease token");
  return token;
}

function fail(message) {
  process.stderr.write(`bloom-ssh-proxy: ${message}\n`);
  process.exit(1);
}
