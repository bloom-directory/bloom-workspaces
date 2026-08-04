import { readFile } from "node:fs/promises";
import WebSocket from "ws";

const origin = process.env.BLOOM_ORIGIN ?? "http://127.0.0.1:8787";
const cookieFile = process.env.BLOOM_COOKIE_FILE ?? "/tmp/bloom-workspaces-cookies";
const cookieLines = (await readFile(cookieFile, "utf8")).split("\n").filter((line) => line && (!line.startsWith("#") || line.startsWith("#HttpOnly_")));
const cookies = cookieLines.map((line) => { const fields = line.split("\t"); return `${fields[5]}=${fields[6]}`; }).join("; ");
if (!cookies) throw new Error(`No cookies found in ${cookieFile}`);
const current = await fetch(`${origin}/api/workspaces/current`, { headers: { cookie: cookies } }).then(async (response) => {
  if (!response.ok) throw new Error(await response.text());
  return response.json();
});
if (current.workspace?.state !== "running") throw new Error("No running workspace");

const websocketOrigin = origin.replace(/^http/, "ws");
const socket = new WebSocket(`${websocketOrigin}/api/workspaces/${current.workspace.id}/terminal`, { headers: { cookie: cookies, origin } });
const timeout = setTimeout(() => { console.error(output.slice(-8_000)); socket.terminate(); throw new Error("Terminal smoke test timed out"); }, 15_000);
let output = "";
let passed = false;
socket.on("open", () => socket.send(JSON.stringify({ type: "input", data: "printf '\\142loom-executed-ok\\n'\n" })));
socket.on("message", (raw) => {
  const message = JSON.parse(raw.toString());
  if (message.type === "output") output += message.data;
  if (!passed && output.includes("bloom-executed-ok")) {
    passed = true;
    clearTimeout(timeout);
    console.log("Browser → control plane → node agent → shell terminal: OK");
    socket.close();
  }
});
socket.on("error", (error) => { clearTimeout(timeout); throw error; });
