import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { createWalletClient, custom, type EIP1193Provider } from "viem";
import { createSiweMessage } from "viem/siwe";
import "./style.css";

type Workspace = {
  id: string;
  state: "queued" | "provisioning" | "running" | "stopping" | "stopped" | "failed";
  createdAt: number;
  leaseExpiresAt: number;
  queuePosition?: number;
  failure?: string;
};

type Session = { authenticated: boolean; wallet?: string; csrfToken?: string; devAuth?: boolean; turnstileSiteKey?: string; workspace?: Workspace };

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
let session: Session = { authenticated: false };
let socket: WebSocket | undefined;
let terminal: Terminal | undefined;
let fit: FitAddon | undefined;
let pollTimer: number | undefined;
let turnstileToken: string | undefined;
let turnstileWidget: string | undefined;

declare global {
  interface Window {
    turnstile?: {
      render(target: string, options: { sitekey: string; callback(token: string): void; "expired-callback"(): void }): string;
      reset(widget?: string): void;
    };
  }
}

async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("content-type", "application/json");
  if (session.csrfToken && init.method && init.method !== "GET") headers.set("x-csrf-token", session.csrfToken);
  const response = await fetch(path, { ...init, headers, credentials: "same-origin" });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error ?? `Request failed (${response.status})`);
  return body as T;
}

function setMessage(value = "") { $("message").textContent = value; }
function shortAddress(address?: string) { return address ? `${address.slice(0, 6)}…${address.slice(-4)}` : "Connected"; }

async function loadSession() {
  session = await api<Session>("/api/session");
  $("status").textContent = session.authenticated ? shortAddress(session.wallet) : "Not connected";
  $("auth-actions").classList.toggle("hidden", session.authenticated);
  $("dashboard").classList.toggle("hidden", !session.authenticated);
  $("dev-login").classList.toggle("hidden", !session.devAuth || session.authenticated);
  if (session.authenticated && session.turnstileSiteKey) void setupTurnstile(session.turnstileSiteKey);
  renderWorkspace(session.workspace);
}

async function setupTurnstile(siteKey: string) {
  $("turnstile").classList.remove("hidden");
  if (!document.querySelector("script[data-turnstile]")) {
    const script = document.createElement("script");
    script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
    script.async = true; script.defer = true; script.dataset.turnstile = "true";
    document.head.append(script);
  }
  for (let attempt = 0; attempt < 100 && !window.turnstile; attempt++) await new Promise((resolve) => setTimeout(resolve, 50));
  if (!window.turnstile || turnstileWidget) return;
  turnstileWidget = window.turnstile.render("#turnstile", {
    sitekey: siteKey,
    callback: (token) => { turnstileToken = token; },
    "expired-callback": () => { turnstileToken = undefined; },
  });
}

async function connectWallet() {
  const ethereum = (window as Window & { ethereum?: EIP1193Provider }).ethereum;
  if (!ethereum) throw new Error("No injected wallet found. Install or open a wallet-enabled browser.");
  const wallet = createWalletClient({ transport: custom(ethereum) });
  const accounts = await wallet.requestAddresses();
  const address = accounts[0];
  if (!address) throw new Error("The wallet returned no account.");
  const challenge = await api<{ nonce: string; domain: string; uri: string; chainId: number; statement: string; issuedAt: string; expirationTime: string }>("/api/auth/challenge");
  const message = createSiweMessage({
    address,
    nonce: challenge.nonce,
    domain: challenge.domain,
    uri: challenge.uri,
    chainId: challenge.chainId,
    statement: challenge.statement,
    issuedAt: new Date(challenge.issuedAt),
    expirationTime: new Date(challenge.expirationTime),
    version: "1",
  });
  const signature = await wallet.signMessage({ account: address, message });
  await api("/api/auth/verify", { method: "POST", body: JSON.stringify({ message, signature }) });
  await loadSession();
}

async function devLogin() {
  await api("/api/auth/dev", { method: "POST", body: "{}" });
  await loadSession();
}

function renderWorkspace(workspace?: Workspace) {
  clearTimeout(pollTimer);
  const create = $("create");
  const stop = $("stop");
  const wrap = $("terminal-wrap");
  if (!workspace || ["stopped", "failed"].includes(workspace.state)) {
    $("workspace-title").textContent = workspace?.state === "failed" ? "Provisioning failed" : "Ready when you are";
    $("workspace-detail").textContent = workspace?.failure ?? "One workspace per wallet. Sessions expire automatically.";
    create.classList.remove("hidden"); stop.classList.add("hidden"); wrap.classList.add("hidden");
    $("turnstile").classList.toggle("hidden", !session.turnstileSiteKey);
    closeTerminal();
    return;
  }
  create.classList.add("hidden"); stop.classList.remove("hidden");
  $("turnstile").classList.add("hidden");
  if (workspace.state === "queued") {
    $("workspace-title").textContent = `Queued${workspace.queuePosition ? ` · #${workspace.queuePosition}` : ""}`;
    $("workspace-detail").textContent = "Capacity is protected; this page will connect as soon as a machine is free.";
  } else if (workspace.state === "provisioning") {
    $("workspace-title").textContent = "Starting an isolated machine…";
    $("workspace-detail").textContent = "Usually ready in a few seconds.";
  } else {
    $("workspace-title").textContent = "Workspace is running";
    $("workspace-detail").textContent = `Created ${new Date(workspace.createdAt).toLocaleTimeString()}`;
    wrap.classList.remove("hidden");
    if (!socket) openTerminal(workspace);
  }
  updateLease(workspace);
  pollTimer = window.setTimeout(refreshWorkspace, workspace.state === "running" ? 10_000 : 1_500);
}

async function refreshWorkspace() {
  try {
    const result = await api<{ workspace?: Workspace }>("/api/workspaces/current");
    session.workspace = result.workspace;
    renderWorkspace(result.workspace);
  } catch (error) { setMessage((error as Error).message); }
}

function updateLease(workspace: Workspace) {
  const remaining = Math.max(0, workspace.leaseExpiresAt - Date.now());
  const minutes = Math.floor(remaining / 60_000);
  const seconds = Math.floor((remaining % 60_000) / 1000);
  $("lease").textContent = `expires in ${minutes}:${seconds.toString().padStart(2, "0")}`;
  if (remaining > 0) window.setTimeout(() => updateLease(workspace), 1_000);
}

function openTerminal(workspace: Workspace) {
  terminal = new Terminal({ cursorBlink: true, convertEol: true, fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: 13, theme: { background: "#070a08", foreground: "#dce8df", cursor: "#a8f0b5" } });
  fit = new FitAddon(); terminal.loadAddon(fit); terminal.open($("terminal")); fit.fit(); terminal.focus();
  const protocol = location.protocol === "https:" ? "wss" : "ws";
  socket = new WebSocket(`${protocol}://${location.host}/api/workspaces/${workspace.id}/terminal`);
  socket.addEventListener("open", () => sendResize());
  socket.addEventListener("message", (event) => {
    const message = JSON.parse(String(event.data)) as { type: string; data?: string; reason?: string };
    if (message.type === "output" && message.data) terminal?.write(message.data);
    if (message.type === "closed") terminal?.writeln(`\r\n\x1b[33m[workspace closed: ${message.reason ?? "ended"}]\x1b[0m`);
  });
  socket.addEventListener("close", () => { socket = undefined; });
  terminal.onData((data) => socket?.readyState === WebSocket.OPEN && socket.send(JSON.stringify({ type: "input", data })));
  window.addEventListener("resize", resizeTerminal);
}

function resizeTerminal() { fit?.fit(); sendResize(); }
function sendResize() { if (terminal && socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: "resize", cols: terminal.cols, rows: terminal.rows })); }
function closeTerminal() { socket?.close(); socket = undefined; terminal?.dispose(); terminal = undefined; fit = undefined; window.removeEventListener("resize", resizeTerminal); }

$("connect").addEventListener("click", () => connectWallet().catch((error) => setMessage(error.message)));
$("dev-login").addEventListener("click", () => devLogin().catch((error) => setMessage(error.message)));
$("create").addEventListener("click", async () => {
  try {
    setMessage();
    const result = await api<{ workspace: Workspace }>("/api/workspaces", { method: "POST", body: JSON.stringify({ turnstileToken: turnstileToken ?? null }) });
    turnstileToken = undefined; window.turnstile?.reset(turnstileWidget);
    session.workspace = result.workspace; renderWorkspace(result.workspace);
  }
  catch (error) { setMessage((error as Error).message); }
});
$("stop").addEventListener("click", async () => {
  try { await api("/api/workspaces/current", { method: "DELETE", body: "{}" }); await refreshWorkspace(); }
  catch (error) { setMessage((error as Error).message); }
});

loadSession().catch((error) => setMessage(error.message));
