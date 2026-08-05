import { readFile } from "node:fs/promises";
import WebSocket from "ws";

const origin = process.env.BLOOM_ORIGIN ?? "http://127.0.0.1:8787";
const cookieFile = process.env.BLOOM_COOKIE_FILE ?? "/tmp/bloom-workspaces-cookies";
const cookieLines = (await readFile(cookieFile, "utf8")).split("\n").filter((line) => line && (!line.startsWith("#") || line.startsWith("#HttpOnly_")));
const cookies = cookieLines.map((line) => { const fields = line.split("\t"); return `${fields[5]}=${fields[6]}`; }).join("; ");
if (!cookies) throw new Error(`No cookies found in ${cookieFile}`);
const session = await fetch(`${origin}/api/session`, { headers: { cookie: cookies } }).then(json);
if (!session.authenticated || !session.csrfToken) throw new Error("Cookie file does not contain an authenticated session");
const current = await fetch(`${origin}/api/workspaces/current`, { headers: { cookie: cookies } }).then(async (response) => {
  if (!response.ok) throw new Error(await response.text());
  return response.json();
});
if (current.workspace?.state !== "running") throw new Error("No running workspace");
const workspaceId = current.workspace.id;
const mutationHeaders = { cookie: cookies, origin, "x-csrf-token": session.csrfToken };

const smokePath = ".bloom-live-smoke.txt";
const smokeBytes = Buffer.from("file-api-executed-ok\n");
await fetch(`${origin}/api/workspaces/${workspaceId}/files?path=${encodeURIComponent(smokePath)}`, {
  method: "PUT", headers: { ...mutationHeaders, "content-type": "application/octet-stream" }, body: smokeBytes,
}).then(json);
const downloaded = Buffer.from(await fetch(`${origin}/api/workspaces/${workspaceId}/files/content?path=${encodeURIComponent(smokePath)}`, { headers: { cookie: cookies } }).then(async (response) => {
  if (!response.ok) throw new Error(await response.text());
  return response.arrayBuffer();
}));
if (!downloaded.equals(smokeBytes)) throw new Error("File API round-trip did not preserve bytes");
await fetch(`${origin}/api/workspaces/${workspaceId}/files?path=${encodeURIComponent(smokePath)}`, {
  method: "DELETE", headers: mutationHeaders,
}).then(json);

const started = await fetch(`${origin}/api/workspaces/${workspaceId}/jobs`, {
  method: "POST", headers: { ...mutationHeaders, "content-type": "application/json" },
  body: JSON.stringify({ argv: ["printf", "job-executed-ok\\n"], cwd: ".", environment: { CI: "1" }, timeoutMs: 10_000 }),
}).then(json);
let job;
for (let attempt = 0; attempt < 40; attempt += 1) {
  job = await fetch(`${origin}/api/workspaces/${workspaceId}/jobs/${started.jobId}`, { headers: { cookie: cookies } }).then(json);
  if (["succeeded", "failed", "cancelled", "timed_out"].includes(job.state)) break;
  await new Promise((resolve) => setTimeout(resolve, 100));
}
if (job?.state !== "succeeded" || !Buffer.from(job.logs.data, "base64").toString().includes("job-executed-ok")) throw new Error("Structured job did not complete with retained output");
const bloom = await fetch(`${origin}/api/workspaces/${workspaceId}/bloom`, { headers: { cookie: cookies } }).then(json);
if (!bloom.available || bloom.capabilities.walletSigning !== false || bloom.capabilities.transactions !== false) throw new Error("Bloom watch-only capability contract failed");

const websocketOrigin = origin.replace(/^http/, "ws");
const socket = new WebSocket(`${websocketOrigin}/api/workspaces/${workspaceId}/terminal`, { headers: { cookie: cookies, origin } });
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
    console.log("Terminal, files, structured jobs, and watch-only Bloom: OK");
    socket.close();
  }
});
socket.on("error", (error) => { clearTimeout(timeout); throw error; });

async function json(response) {
  if (!response.ok) throw new Error(await response.text());
  return response.json();
}
