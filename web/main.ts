import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { createWalletClient, custom, getAddress, isAddress, type EIP1193Provider } from "viem";
import { createSiweMessage } from "viem/siwe";
import {
  MAX_UPLOAD_BYTES,
  buildJobEnvironment,
  formatBytes,
  normalizeWorkspacePath,
  parseStructuredArgv,
  parseTimeoutSeconds,
  readConnectionMethods,
  type EnvironmentRow,
} from "./workspace-contracts.js";
import "./style.css";

type WorkspaceState = "queued" | "provisioning" | "running" | "stopping" | "stopped" | "failed";
type StorageMode = "disposable" | "persistent";
type Workspace = {
  id: string;
  state: WorkspaceState;
  createdAt: number;
  leaseExpiresAt: number;
  storage?: { mode: StorageMode; quotaBytes: number; retainedAfterStop: boolean };
  queuePosition?: number;
  failure?: string;
};
type CapabilityStatus = "available" | "disabled" | "unsupported";
type Capability = { status: CapabilityStatus; reason: string; transport?: string };
type CapabilityName = "terminal" | "files" | "persistence" | "jobs" | "bloom" | "controlledEgress" | "ssh" | "nfs";
type CapabilitySet = Partial<Record<CapabilityName, Capability>>;
type Session = {
  authenticated: boolean;
  wallet?: string;
  csrfToken?: string;
  devAuth?: boolean;
  turnstileSiteKey?: string;
  workspace?: Workspace;
  capabilities?: CapabilitySet;
};
type AuthChallenge = { nonce: string; domain: string; uri: string; chainId: number; statement: string; issuedAt: string; expirationTime: string };
type FileEntry = { path: string; type: "file" | "directory"; size?: number };
type JobState = "queued" | "running" | "succeeded" | "failed" | "cancelled" | "timed_out";
type JobStatus = {
  jobId: string;
  state: JobState;
  createdAt: number;
  startedAt: number | null;
  finishedAt: number | null;
  exitCode: number | null;
  signal: number | null;
  timeoutMs: number;
  logs: { offset: number; nextOffset: number; endOffset: number; truncatedBefore: boolean; eof: boolean; encoding: "base64"; data: string };
};
type BloomStatus = {
  available: boolean;
  mount: { path: "/bloom"; mounted: boolean };
  identity: { kind: "watch"; address: string } | null;
  capabilities: { files: boolean; jobs: boolean; bloomRead: boolean; walletSigning: false; transactions: false };
  helper: { name: "bloom-workspace"; protocolVersion: 1 };
};
type ConnectionGrant = {
  leaseId: string;
  accessToken: string;
  certificate: string;
  fingerprint: string;
  principal: string;
  validAfter: number;
  validBefore: number;
  hostKey: { alias: string; knownHostsLine: string };
  tunnel: { transport: "websocket"; protocol: "bloom-ssh-v1"; path: string; proxyHelper: string };
  capability?: { status?: string; reason?: string; requiresAdmin?: boolean; fallback?: string };
  sshArgv?: string[];
  sshTunnelArgv?: string[];
  mountArgv?: string[];
  unmountArgv?: string[];
};
type WalletProvider = EIP1193Provider & {
  disconnect?: () => Promise<void>;
  on?: (event: "accountsChanged" | "chainChanged" | "disconnect", listener: (value: unknown) => void) => unknown;
  removeListener?: (event: "accountsChanged" | "chainChanged" | "disconnect", listener: (value: unknown) => void) => unknown;
  off?: (event: "accountsChanged" | "chainChanged" | "disconnect", listener: (value: unknown) => void) => unknown;
};
type WalletBinding = {
  provider: WalletProvider;
  kind: "injected" | "walletconnect";
  address: string;
  chainId: number;
  handlers: {
    accountsChanged(value: unknown): void;
    chainChanged(value: unknown): void;
    disconnect(value: unknown): void;
  };
};

class ApiError extends Error {
  constructor(message: string, readonly status: number) { super(message); }
}

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
let session: Session = { authenticated: false };
let socket: WebSocket | undefined;
let terminal: Terminal | undefined;
let fit: FitAddon | undefined;
let workspacePollTimer: number | undefined;
let leaseTimer: number | undefined;
let jobPollTimer: number | undefined;
let outboxPollTimer: number | undefined;
let jobEvents: EventSource | undefined;
let activeJob: JobStatus | undefined;
let activeConnection: ConnectionGrant | undefined;
let jobLogOffset = 0;
let jobLogDecoder = new TextDecoder();
let loadedWorkspaceId: string | undefined;
let turnstileToken: string | undefined;
let turnstileWidget: string | undefined;
let authBusy = false;
let walletBinding: WalletBinding | undefined;
const walletConnectProjectId = import.meta.env.VITE_REOWN_PROJECT_ID?.trim() || undefined;
const terminalStates = new Set<JobState>(["succeeded", "failed", "cancelled", "timed_out"]);
const capabilityLabels: Record<CapabilityName, string> = {
  terminal: "Terminal",
  files: "Browser files",
  persistence: "Durable volume",
  jobs: "Structured jobs",
  bloom: "Bloom surface",
  controlledEgress: "Package access",
  ssh: "SSH",
  nfs: "Native NFS",
};

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
  if (typeof init.body === "string" && !headers.has("content-type")) headers.set("content-type", "application/json");
  if (session.csrfToken && init.method && init.method !== "GET") headers.set("x-csrf-token", session.csrfToken);
  const response = await fetch(path, { ...init, headers, credentials: "same-origin" });
  const body = response.status === 204 ? undefined : await response.json().catch(() => undefined) as { error?: unknown } | undefined;
  if (!response.ok) {
    if (response.status === 401 && !path.startsWith("/api/auth/")) expireSession();
    throw new ApiError(typeof body?.error === "string" ? body.error : `Request failed (${response.status})`, response.status);
  }
  return body as T;
}

async function apiBinary(path: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers);
  if (session.csrfToken && init.method && init.method !== "GET") headers.set("x-csrf-token", session.csrfToken);
  const response = await fetch(path, { ...init, headers, credentials: "same-origin" });
  if (!response.ok) {
    const body = await response.json().catch(() => undefined) as { error?: unknown } | undefined;
    if (response.status === 401) expireSession();
    throw new ApiError(typeof body?.error === "string" ? body.error : `Request failed (${response.status})`, response.status);
  }
  return response;
}

function setMessage(value = "") { $("message").textContent = value; }
function setInlineMessage(id: string, value = "", error = false) {
  const element = $(id);
  element.textContent = value;
  element.classList.toggle("error", error);
}
function shortAddress(address?: string) { return address ? `${address.slice(0, 6)}…${address.slice(-4)}` : "Connected"; }
function capability(name: CapabilityName): Capability {
  return session.capabilities?.[name] ?? { status: "unsupported", reason: "This deployment did not report the capability." };
}
function isAvailable(name: CapabilityName) { return capability(name).status === "available"; }

function renderSession() {
  $("status").textContent = session.authenticated ? shortAddress(session.wallet) : "Not connected";
  $("auth-actions").classList.toggle("hidden", session.authenticated);
  $("dashboard").classList.toggle("hidden", !session.authenticated);
  $("dev-login").classList.toggle("hidden", !session.devAuth || session.authenticated);
  $("logout").classList.toggle("hidden", !session.authenticated);
  if (session.authenticated && session.turnstileSiteKey) void setupTurnstile(session.turnstileSiteKey);
  renderCapabilities();
  renderWorkspace(session.workspace);
}

async function loadSession() {
  const result = await api<unknown>("/api/session");
  if (typeof result !== "object" || result === null || typeof (result as { authenticated?: unknown }).authenticated !== "boolean") {
    throw new Error("The workspace service returned an invalid session response.");
  }
  session = result as Session;
  renderSession();
}

function expireSession() {
  removeWalletListeners();
  session = { authenticated: false, devAuth: session.devAuth, capabilities: session.capabilities };
  closeWorkspaceResources();
  renderSession();
  setMessage("Your session expired. Sign in again to continue.");
}

async function setupTurnstile(siteKey: string) {
  $("turnstile").classList.remove("hidden");
  if (!document.querySelector("script[data-turnstile]")) {
    const script = document.createElement("script");
    script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
    script.async = true;
    script.defer = true;
    script.dataset.turnstile = "true";
    document.head.append(script);
  }
  for (let attempt = 0; attempt < 100 && !window.turnstile; attempt += 1) await new Promise((resolve) => setTimeout(resolve, 50));
  if (!window.turnstile || turnstileWidget) return;
  turnstileWidget = window.turnstile.render("#turnstile", {
    sitekey: siteKey,
    callback: (token) => { turnstileToken = token; },
    "expired-callback": () => { turnstileToken = undefined; },
  });
}

async function challenge() { return api<AuthChallenge>("/api/auth/challenge"); }

async function authenticate(provider: WalletProvider, address: string, value: AuthChallenge, kind: WalletBinding["kind"]) {
  if (!isAddress(address)) throw new Error("The wallet returned an invalid Ethereum account.");
  const normalizedAddress = getAddress(address);
  const wallet = createWalletClient({ transport: custom(provider) });
  const message = createSiweMessage({
    address: normalizedAddress,
    nonce: value.nonce,
    domain: value.domain,
    uri: value.uri,
    chainId: value.chainId,
    statement: value.statement,
    issuedAt: new Date(value.issuedAt),
    expirationTime: new Date(value.expirationTime),
    version: "1",
  });
  setMessage("Approve the login message in your wallet.");
  const signature = await wallet.signMessage({ account: normalizedAddress, message });
  const verified = await api<{ wallet: string; csrfToken: string }>("/api/auth/verify", { method: "POST", body: JSON.stringify({ message, signature }) });
  session = { ...session, authenticated: true, wallet: verified.wallet, csrfToken: verified.csrfToken };
  bindAuthenticatedWallet(provider, kind, normalizedAddress, value.chainId);
  try {
    await loadSession();
    if (!session.authenticated || session.wallet?.toLowerCase() !== normalizedAddress.toLowerCase()) throw new Error("The authenticated wallet did not match the selected account.");
  } catch (error) {
    await invalidateWalletSession("Wallet login could not be confirmed. Sign in again to continue.");
    throw error;
  }
  setMessage("Signed in. Your wallet keys remain on your device.");
}

async function connectInjectedWallet() {
  const ethereum = (window as Window & { ethereum?: EIP1193Provider }).ethereum;
  if (!ethereum) throw new Error("No browser wallet found. Install an extension, open this page in a wallet browser, or use Mobile wallet / QR.");
  const wallet = createWalletClient({ transport: custom(ethereum) });
  const accounts = await wallet.requestAddresses();
  const address = accounts[0];
  if (!address) throw new Error("The wallet returned no account.");
  await authenticate(ethereum as WalletProvider, address, await challenge(), "injected");
}

async function connectMobileWallet() {
  if (!walletConnectProjectId) throw new Error("Mobile/QR login is not configured on this deployment.");
  const value = await challenge();
  setMessage("Opening WalletConnect… Scan the QR code on desktop or choose a wallet on your phone.");
  const { EthereumProvider } = await import("@walletconnect/ethereum-provider");
  const provider = await EthereumProvider.init({
    projectId: walletConnectProjectId,
    optionalChains: [value.chainId],
    methods: ["personal_sign", "eth_sendTransaction", "eth_signTypedData_v4"],
    events: ["accountsChanged", "chainChanged"],
    showQrModal: true,
    telemetryEnabled: false,
    metadata: {
      name: "Bloom Workspaces",
      description: "Sign in to an isolated Linux workspace. Sign messages and transactions are relayed for your approval.",
      url: location.origin,
      icons: [`${location.origin}/bloom-workspaces.svg`],
      redirect: { universal: `${location.origin}/` },
    },
    qrModalOptions: { themeMode: "dark", themeVariables: { "--wcm-accent-color": "#a8f0b5" } },
  });
  try {
    await provider.connect({ optionalChains: [value.chainId] });
    const address = provider.accounts[0];
    if (!address) throw new Error("The mobile wallet returned no Ethereum account.");
    await authenticate(provider as WalletProvider, address, value, "walletconnect");
  } catch (error) {
    if (walletBinding?.provider !== provider) await provider.disconnect().catch(() => undefined);
    throw error;
  }
}

function parseWalletChainId(value: unknown) {
  if (typeof value === "number") return Number.isSafeInteger(value) ? value : undefined;
  if (typeof value !== "string" || !value.trim()) return undefined;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : undefined;
}

function removeWalletListeners(binding = walletBinding) {
  if (!binding) return;
  const remove = binding.provider.removeListener?.bind(binding.provider) ?? binding.provider.off?.bind(binding.provider);
  remove?.("accountsChanged", binding.handlers.accountsChanged);
  remove?.("chainChanged", binding.handlers.chainChanged);
  remove?.("disconnect", binding.handlers.disconnect);
  if (walletBinding === binding) walletBinding = undefined;
}

function bindAuthenticatedWallet(provider: WalletProvider, kind: WalletBinding["kind"], address: string, chainId: number) {
  removeWalletListeners();
  const handlers = {
    accountsChanged(value: unknown) {
      const accounts = Array.isArray(value) ? value : [];
      const next = typeof accounts[0] === "string" && isAddress(accounts[0]) ? getAddress(accounts[0]) : undefined;
      if (!next || next.toLowerCase() !== address.toLowerCase()) void invalidateWalletSession("Your wallet account changed. Sign in again to continue.");
    },
    chainChanged(value: unknown) {
      if (parseWalletChainId(value) !== chainId) void invalidateWalletSession("Your wallet network changed. Sign in again to continue.");
    },
    disconnect(_value: unknown) { void invalidateWalletSession("Your wallet disconnected. Sign in again to continue."); },
  };
  walletBinding = { provider, kind, address, chainId, handlers };
  provider.on?.("accountsChanged", handlers.accountsChanged);
  provider.on?.("chainChanged", handlers.chainChanged);
  provider.on?.("disconnect", handlers.disconnect);
}

async function invalidateWalletSession(reason: string) {
  const binding = walletBinding;
  if (!binding) return;
  removeWalletListeners(binding);
  const shouldLogout = session.authenticated;
  try {
    if (shouldLogout) await api("/api/auth/logout", { method: "POST", body: "{}" });
  } catch {
    reason += " Server sign-out could not be confirmed; reload before signing in again.";
  } finally {
    session = { authenticated: false, devAuth: session.devAuth, capabilities: session.capabilities };
    closeWorkspaceResources();
    renderSession();
    setMessage(reason);
  }
}

async function logout() {
  const binding = walletBinding;
  await api("/api/auth/logout", { method: "POST", body: "{}" });
  removeWalletListeners(binding);
  if (binding?.kind === "walletconnect") await binding.provider.disconnect?.().catch(() => undefined);
  closeWorkspaceResources();
  await loadSession();
  setMessage("Signed out.");
}

function setAuthBusy(value: boolean) {
  authBusy = value;
  const injected = $<HTMLButtonElement>("connect");
  const mobile = $<HTMLButtonElement>("connect-mobile");
  injected.disabled = value;
  mobile.disabled = value || !walletConnectProjectId;
  $("auth-actions").setAttribute("aria-busy", String(value));
}

async function runAuth(action: () => Promise<void>) {
  if (authBusy) return;
  setAuthBusy(true);
  setMessage();
  try { await action(); }
  catch (error) { setMessage(friendlyWalletError(error)); }
  finally { setAuthBusy(false); }
}

function friendlyWalletError(error: unknown) {
  const value = error as { code?: number; message?: string };
  const message = value?.message ?? "";
  if (value?.code === 4001 || /user rejected|user denied|modal closed|request reset/i.test(message)) return "Wallet login was canceled. No permissions were granted.";
  if (/proposal expired|request expired|timeout/i.test(message)) return "The wallet request expired. Try again and approve the login message promptly.";
  if (/invalid project|project id|origin.*allowlist|not configured/i.test(message)) return "Mobile/QR login is unavailable on this deployment. The operator must configure its Reown project and allowed domain.";
  return message || "Wallet login failed. Please try again.";
}

async function devLogin() {
  await api("/api/auth/dev", { method: "POST", body: "{}" });
  await loadSession();
}

function renderCapabilities() {
  const grid = $("capability-grid");
  grid.replaceChildren();
  for (const name of Object.keys(capabilityLabels) as CapabilityName[]) {
    const value = capability(name);
    const article = document.createElement("article");
    article.className = `capability-card capability-${value.status}`;
    const heading = document.createElement("div");
    const title = document.createElement("h3");
    title.textContent = capabilityLabels[name];
    const badge = document.createElement("span");
    badge.className = "status-badge";
    badge.textContent = value.status;
    heading.append(title, badge);
    const reason = document.createElement("p");
    reason.textContent = value.reason;
    article.append(heading, reason);
    grid.append(article);
  }
  const persistence = capability("persistence");
  const persistentInput = $<HTMLInputElement>("persistent-storage");
  persistentInput.disabled = persistence.status !== "available";
  if (persistentInput.disabled && persistentInput.checked) $<HTMLInputElement>('input[name="storage"][value="disposable"]').checked = true;
  $("persistent-choice").classList.toggle("choice-disabled", persistentInput.disabled);
  $("persistent-choice").setAttribute("title", persistentInput.disabled ? persistence.reason : "128 MiB retained after the machine stops");
  syncCapabilityControls();
}

function renderWorkspace(workspace?: Workspace) {
  window.clearTimeout(workspacePollTimer);
  window.clearTimeout(leaseTimer);
  const create = $("create");
  const stop = $("stop");
  const removeVolume = $("delete-volume");
  const consoleElement = $("workspace-console");
  const storageChoice = $<HTMLFieldSetElement>("storage-choice");
  const inactive = !workspace || workspace.state === "stopped" || workspace.state === "failed";
  if (inactive) {
    $("workspace-title").textContent = workspace?.state === "failed" ? "Provisioning failed" : "Ready when you are";
    $("workspace-detail").textContent = workspace?.failure ?? "One active workspace per wallet. Running sessions expire automatically.";
    $("storage-summary").textContent = workspace?.storage?.mode === "persistent"
      ? `Your ${formatBytes(workspace.storage.quotaBytes)} persistent volume is retained after stop.`
      : "Disposable storage is deleted on stop. Persistent storage is wallet-owned and quota-bounded.";
    create.classList.remove("hidden");
    stop.classList.add("hidden");
    removeVolume.classList.toggle("hidden", workspace?.storage?.mode !== "persistent");
    consoleElement.classList.add("hidden");
    storageChoice.disabled = false;
    $("turnstile").classList.toggle("hidden", !session.turnstileSiteKey);
    closeWorkspaceResources();
    renderCapabilities();
    return;
  }

  create.classList.add("hidden");
  stop.classList.remove("hidden");
  removeVolume.classList.add("hidden");
  storageChoice.disabled = true;
  $("turnstile").classList.add("hidden");
  $("storage-summary").textContent = workspace.storage
    ? `${workspace.storage.mode === "persistent" ? "Persistent" : "Disposable"} /workspace · ${formatBytes(workspace.storage.quotaBytes)} quota${workspace.storage.retainedAfterStop ? " · retained after stop" : " · deleted on stop"}`
    : "Workspace storage is quota-bounded.";
  if (workspace.state === "queued") {
    $("workspace-title").textContent = `Queued${workspace.queuePosition ? ` · #${workspace.queuePosition}` : ""}`;
    $("workspace-detail").textContent = "Capacity is protected; this page will connect as soon as a machine is free.";
    consoleElement.classList.add("hidden");
  } else if (workspace.state === "provisioning") {
    $("workspace-title").textContent = "Starting an isolated machine…";
    $("workspace-detail").textContent = "Preparing the runtime and its bounded service channels.";
    consoleElement.classList.add("hidden");
  } else if (workspace.state === "stopping") {
    $("workspace-title").textContent = "Stopping workspace…";
    $("workspace-detail").textContent = "Connections are being revoked and runtime resources are being released.";
    consoleElement.classList.add("hidden");
  } else {
    $("workspace-title").textContent = "Workspace is running";
    $("workspace-detail").textContent = `Created ${new Date(workspace.createdAt).toLocaleString()}`;
    consoleElement.classList.remove("hidden");
    if (loadedWorkspaceId !== workspace.id) resetWorkspaceTools(workspace.id);
    if (isAvailable("terminal") && !socket) openTerminal(workspace);
    if (!outboxPollTimer) startOutboxPoll(workspace.id);
  }
  updateLease(workspace);
  workspacePollTimer = window.setTimeout(refreshWorkspace, workspace.state === "running" ? 10_000 : 1_500);
}

async function refreshWorkspace() {
  try {
    const result = await api<{ workspace?: Workspace }>("/api/workspaces/current");
    session.workspace = result.workspace;
    renderWorkspace(result.workspace);
  } catch (error) { setMessage(errorMessage(error)); }
}

function updateLease(workspace: Workspace) {
  window.clearTimeout(leaseTimer);
  const remaining = Math.max(0, workspace.leaseExpiresAt - Date.now());
  const minutes = Math.floor(remaining / 60_000);
  const seconds = Math.floor((remaining % 60_000) / 1000);
  $("lease").textContent = remaining > 0 ? `Expires in ${minutes}:${seconds.toString().padStart(2, "0")}` : "Lease expired";
  if (remaining > 0) leaseTimer = window.setTimeout(() => updateLease(workspace), 1_000);
}

function resetWorkspaceTools(id: string) {
  closeWorkspaceResources();
  loadedWorkspaceId = id;
  activeJob = undefined;
  jobLogOffset = 0;
  $("job-output").textContent = "";
  $("job-output-wrap").classList.add("hidden");
  $("file-list").replaceChildren();
  $("bloom-status").replaceChildren();
  $("connection-list").replaceChildren();
  clearConnectionGrant();
  setInlineMessage("files-message", "Open Files to load the workspace root.");
  setInlineMessage("jobs-message");
  setInlineMessage("bloom-message", "Open Bloom to load its guest status.");
  setInlineMessage("connections-message", "Open Connect to check this deployment.");
  selectTab("terminal");
  syncCapabilityControls();
}

function closeWorkspaceResources() {
  closeTerminal();
  closeJobStream();
  closeOutboxPoll();
  clearConnectionGrant();
  loadedWorkspaceId = undefined;
  activeJob = undefined;
  window.clearTimeout(workspacePollTimer);
  window.clearTimeout(leaseTimer);
}

function closeOutboxPoll() {
  window.clearInterval(outboxPollTimer);
  outboxPollTimer = undefined;
}

function startOutboxPoll(workspaceId: string) {
  closeOutboxPoll();
  const seen = new Set<string>();
  outboxPollTimer = window.setInterval(async () => {
    if (!walletBinding || !session.authenticated) return;
    try {
      const result = await api<{ requests: { id: string; chain: string; wallet: string; planMd: string }[] }>(`/api/workspaces/${encodeURIComponent(workspaceId)}/outbox/pending`);
      for (const request of result.requests) {
        if (seen.has(request.id)) continue;
        seen.add(request.id);
        void promptAndResolveOutboxRequest(workspaceId, request);
      }
      if (seen.size > 50) { const keep = new Set(result.requests.map((r) => r.id)); for (const id of seen) if (!keep.has(id)) seen.delete(id); }
    } catch { /* workspace may have stopped */ }
  }, 3_000);
}

async function promptAndResolveOutboxRequest(workspaceId: string, request: { id: string; chain: string; wallet: string; planMd: string }) {
  if (!walletBinding) return;
  const dialog = $("outbox-dialog") as HTMLDialogElement;
  const description = $("outbox-description");
  const detail = $("outbox-detail");
  description.textContent = `Your workspace has a pending transaction for review. Review the plan below, then approve or reject.`;
  detail.textContent = request.planMd;
  dialog.showModal();
  const choice = await new Promise<string>((resolve) => {
    const onClose = () => { dialog.removeEventListener("close", onClose); resolve(dialog.returnValue || "reject"); };
    dialog.addEventListener("close", onClose);
  });
  if (choice !== "approve") {
    await api(`/api/workspaces/${encodeURIComponent(workspaceId)}/outbox/cancel`, {
      method: "POST",
      body: JSON.stringify({ id: request.id, chain: request.chain, wallet: request.wallet }),
    }).catch(() => undefined);
    return;
  }
  await api(`/api/workspaces/${encodeURIComponent(workspaceId)}/outbox/confirm`, {
    method: "POST",
    body: JSON.stringify({ id: request.id, chain: request.chain, wallet: request.wallet, confirmText: "y" }),
  }).catch(() => undefined);
}

function openTerminal(workspace: Workspace) {
  terminal = new Terminal({
    cursorBlink: true,
    convertEol: true,
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
    fontSize: 13,
    theme: { background: "#070a08", foreground: "#dce8df", cursor: "#a8f0b5", selectionBackground: "#315642" },
  });
  fit = new FitAddon();
  terminal.loadAddon(fit);
  terminal.open($("terminal"));
  fit.fit();
  const protocol = location.protocol === "https:" ? "wss" : "ws";
  socket = new WebSocket(`${protocol}://${location.host}/api/workspaces/${workspace.id}/terminal`);
  socket.addEventListener("open", () => sendResize());
  socket.addEventListener("message", (event) => {
    try {
      const message = JSON.parse(String(event.data)) as { type: string; data?: string; reason?: string };
      if (message.type === "output" && message.data) terminal?.write(message.data);
      if (message.type === "closed") terminal?.writeln(`\r\n\x1b[33m[workspace closed: ${message.reason ?? "ended"}]\x1b[0m`);
    } catch { terminal?.writeln("\r\n\x1b[31m[invalid terminal response]\x1b[0m"); }
  });
  socket.addEventListener("close", () => { socket = undefined; });
  socket.addEventListener("error", () => terminal?.writeln("\r\n\x1b[31m[terminal connection failed]\x1b[0m"));
  terminal.onData((data) => socket?.readyState === WebSocket.OPEN && socket.send(JSON.stringify({ type: "input", data })));
  window.addEventListener("resize", resizeTerminal);
}

function resizeTerminal() { fit?.fit(); sendResize(); }
function sendResize() { if (terminal && socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: "resize", cols: terminal.cols, rows: terminal.rows })); }
function closeTerminal() {
  socket?.close();
  socket = undefined;
  terminal?.dispose();
  terminal = undefined;
  fit = undefined;
  window.removeEventListener("resize", resizeTerminal);
  $("terminal").replaceChildren();
}

function selectTab(name: string) {
  for (const tab of document.querySelectorAll<HTMLButtonElement>("[role=tab]")) {
    const selected = tab.dataset.panel === name;
    tab.setAttribute("aria-selected", String(selected));
    tab.tabIndex = selected ? 0 : -1;
    $(`panel-${tab.dataset.panel}`).classList.toggle("hidden", !selected);
  }
  if (name === "terminal") window.setTimeout(() => { fit?.fit(); terminal?.focus(); }, 0);
  if (name === "files") void loadFiles();
  if (name === "bloom") void loadBloomStatus();
  if (name === "connections") void loadConnections();
}

function syncCapabilityControls() {
  const mappings: Array<[string, CapabilityName]> = [
    ["refresh-files", "files"], ["upload-file", "files"], ["upload-path", "files"], ["upload-button", "files"],
    ["job-argv", "jobs"], ["job-cwd", "jobs"], ["job-timeout", "jobs"], ["add-environment", "jobs"], ["start-job", "jobs"],
    ["refresh-bloom", "bloom"],
  ];
  for (const [id, name] of mappings) {
    const element = $<HTMLInputElement | HTMLButtonElement | HTMLTextAreaElement>(id);
    element.disabled = !isAvailable(name);
    element.title = isAvailable(name) ? "" : capability(name).reason;
  }
  const connectionForm = $("connection-form");
  const sshAvailable = isAvailable("ssh");
  connectionForm.classList.toggle("hidden", !sshAvailable);
  const mode = $<HTMLSelectElement>("connection-mode");
  const nfsOption = mode.querySelector<HTMLOptionElement>('option[value="nfs"]');
  if (nfsOption) { nfsOption.disabled = !isAvailable("nfs"); nfsOption.title = capability("nfs").reason; }
  for (const id of ["connection-public-key", "connection-mode", "connection-ttl", "issue-connection"]) {
    $<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement | HTMLButtonElement>(id).disabled = !sshAvailable;
  }
}

async function loadFiles() {
  const workspace = runningWorkspace();
  if (!workspace) return;
  if (!isAvailable("files")) { setInlineMessage("files-message", capability("files").reason, true); return; }
  setInlineMessage("files-message", "Loading workspace files…");
  try {
    const result = await api<{ files: FileEntry[] }>(`/api/workspaces/${encodeURIComponent(workspace.id)}/files?path=${encodeURIComponent(".")}`);
    renderFiles(result.files);
    setInlineMessage("files-message", `${result.files.length} ${result.files.length === 1 ? "entry" : "entries"} in /workspace.`);
  } catch (error) { setInlineMessage("files-message", errorMessage(error), true); }
}

function renderFiles(files: FileEntry[]) {
  const body = $("file-list");
  body.replaceChildren();
  $("files-empty").classList.toggle("hidden", files.length !== 0);
  for (const file of [...files].sort((a, b) => Number(a.type === "file") - Number(b.type === "file") || a.path.localeCompare(b.path))) {
    const row = document.createElement("tr");
    const name = document.createElement("td");
    name.className = "file-name";
    name.textContent = file.path;
    const type = document.createElement("td");
    type.textContent = file.type;
    const size = document.createElement("td");
    size.textContent = file.type === "file" && typeof file.size === "number" ? formatBytes(file.size) : "—";
    const actions = document.createElement("td");
    actions.className = "row-actions";
    if (file.type === "file") {
      const download = document.createElement("button");
      download.type = "button";
      download.className = "quiet";
      download.textContent = "Download";
      download.addEventListener("click", () => void downloadFile(file.path));
      actions.append(download);
    }
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "quiet danger-text";
    remove.textContent = "Delete";
    remove.addEventListener("click", () => void deleteFile(file));
    actions.append(remove);
    row.append(name, type, size, actions);
    body.append(row);
  }
}

async function uploadFile(event: SubmitEvent) {
  event.preventDefault();
  const workspace = runningWorkspace();
  const input = $<HTMLInputElement>("upload-file");
  const file = input.files?.[0];
  if (!workspace || !file) return;
  if (file.size > MAX_UPLOAD_BYTES) { setInlineMessage("files-message", `Upload is ${formatBytes(file.size)}; the limit is ${formatBytes(MAX_UPLOAD_BYTES)}.`, true); return; }
  try {
    const path = normalizeWorkspacePath($<HTMLInputElement>("upload-path").value || file.name);
    setInlineMessage("files-message", `Uploading ${path}…`);
    const button = $<HTMLButtonElement>("upload-button");
    button.disabled = true;
    try {
      await apiBinary(`/api/workspaces/${encodeURIComponent(workspace.id)}/files?path=${encodeURIComponent(path)}`, {
        method: "PUT",
        headers: { "content-type": "application/octet-stream" },
        body: file,
      });
    } finally { button.disabled = !isAvailable("files"); }
    input.value = "";
    $<HTMLInputElement>("upload-path").value = "";
    setInlineMessage("files-message", `${path} uploaded.`);
    await loadFiles();
  } catch (error) { setInlineMessage("files-message", errorMessage(error), true); }
}

async function downloadFile(path: string) {
  const workspace = runningWorkspace();
  if (!workspace) return;
  setInlineMessage("files-message", `Downloading ${path}…`);
  try {
    const response = await apiBinary(`/api/workspaces/${encodeURIComponent(workspace.id)}/files/content?path=${encodeURIComponent(path)}`);
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = path.split("/").at(-1) || "download";
    anchor.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
    setInlineMessage("files-message", `${path} downloaded.`);
  } catch (error) { setInlineMessage("files-message", errorMessage(error), true); }
}

async function deleteFile(file: FileEntry) {
  const workspace = runningWorkspace();
  if (!workspace) return;
  const confirmed = await confirmAction(
    `Delete ${file.type}?`,
    `${file.path} will be removed from /workspace. This cannot be undone${session.workspace?.storage?.retainedAfterStop ? ", even though the volume is persistent" : ""}.`,
    "Delete",
  );
  if (!confirmed) return;
  try {
    await api(`/api/workspaces/${encodeURIComponent(workspace.id)}/files?path=${encodeURIComponent(file.path)}`, { method: "DELETE", body: "{}" });
    setInlineMessage("files-message", `${file.path} deleted.`);
    await loadFiles();
  } catch (error) { setInlineMessage("files-message", errorMessage(error), true); }
}

function addEnvironmentRow(initial: EnvironmentRow = { name: "", value: "" }) {
  const row = document.createElement("div");
  row.className = "environment-row";
  const nameLabel = document.createElement("label");
  nameLabel.className = "field";
  const nameText = document.createElement("span");
  nameText.textContent = "Name";
  const name = document.createElement("input");
  name.className = "env-name";
  name.value = initial.name;
  name.setAttribute("list", "environment-names");
  name.autocomplete = "off";
  name.maxLength = 64;
  const valueLabel = document.createElement("label");
  valueLabel.className = "field grow";
  const valueText = document.createElement("span");
  valueText.textContent = "Value";
  const value = document.createElement("input");
  value.className = "env-value";
  value.value = initial.value;
  value.autocomplete = "off";
  value.maxLength = 8192;
  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "quiet env-remove";
  remove.textContent = "Remove";
  remove.setAttribute("aria-label", "Remove environment variable");
  remove.addEventListener("click", () => row.remove());
  nameLabel.append(nameText, name);
  valueLabel.append(valueText, value);
  row.append(nameLabel, valueLabel, remove);
  $("environment-rows").append(row);
  name.focus();
}

function environmentRows(): EnvironmentRow[] {
  return [...document.querySelectorAll<HTMLElement>(".environment-row")].map((row) => ({
    name: row.querySelector<HTMLInputElement>(".env-name")?.value ?? "",
    value: row.querySelector<HTMLInputElement>(".env-value")?.value ?? "",
  }));
}

async function startJob(event: SubmitEvent) {
  event.preventDefault();
  const workspace = runningWorkspace();
  if (!workspace) return;
  try {
    const spec = {
      argv: parseStructuredArgv($<HTMLTextAreaElement>("job-argv").value),
      cwd: normalizeWorkspacePath($<HTMLInputElement>("job-cwd").value, { allowRoot: true }),
      environment: buildJobEnvironment(environmentRows()),
      timeoutMs: parseTimeoutSeconds($<HTMLInputElement>("job-timeout").value),
    };
    setInlineMessage("jobs-message", "Starting structured job…");
    const button = $<HTMLButtonElement>("start-job");
    button.disabled = true;
    try {
      activeJob = await api<JobStatus>(`/api/workspaces/${encodeURIComponent(workspace.id)}/jobs`, { method: "POST", body: JSON.stringify(spec) });
    } finally { button.disabled = !isAvailable("jobs"); }
    jobLogOffset = 0;
    jobLogDecoder = new TextDecoder();
    $("job-output").textContent = "";
    $("job-output-wrap").classList.remove("hidden");
    applyJobStatus(activeJob);
    setInlineMessage("jobs-message", `Job ${activeJob.jobId.slice(0, 8)} started without a shell.`);
    streamJob(workspace.id, activeJob.jobId);
  } catch (error) { setInlineMessage("jobs-message", errorMessage(error), true); }
}

function applyJobStatus(status: JobStatus) {
  activeJob = status;
  const badge = $("job-state");
  badge.textContent = status.state.replace("_", " ");
  badge.className = `status-badge job-${status.state}`;
  const cancel = $<HTMLButtonElement>("cancel-job");
  cancel.disabled = terminalStates.has(status.state);
  cancel.classList.toggle("hidden", terminalStates.has(status.state));
  if (status.logs.truncatedBefore && status.logs.offset > jobLogOffset) appendJobLog("\n[older logs were truncated]\n");
  if (status.logs.nextOffset > jobLogOffset && status.logs.data) {
    appendJobLog(decodeBase64(status.logs.data, status.logs.eof));
    jobLogOffset = status.logs.nextOffset;
  }
  if (terminalStates.has(status.state)) {
    closeJobStream();
    const detail = status.state === "succeeded" ? "exit 0" : status.exitCode !== null ? `exit ${status.exitCode}` : status.signal !== null ? `signal ${status.signal}` : status.state.replace("_", " ");
    setInlineMessage("jobs-message", `Job finished: ${detail}.`);
  }
}

function decodeBase64(value: string, eof: boolean) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return jobLogDecoder.decode(bytes, { stream: !eof });
}

function appendJobLog(value: string) {
  const output = $("job-output");
  output.textContent += value;
  output.scrollTop = output.scrollHeight;
}

function streamJob(workspaceId: string, jobId: string) {
  closeJobStream();
  jobEvents = new EventSource(`/api/workspaces/${encodeURIComponent(workspaceId)}/jobs/${encodeURIComponent(jobId)}/events?offset=${jobLogOffset}`);
  jobEvents.addEventListener("status", (event) => {
    try { applyJobStatus(JSON.parse((event as MessageEvent<string>).data) as JobStatus); }
    catch { setInlineMessage("jobs-message", "Received an invalid job update; switching to polling.", true); fallbackJobPolling(workspaceId, jobId); }
  });
  jobEvents.onerror = () => {
    if (!activeJob || terminalStates.has(activeJob.state)) { closeJobStream(); return; }
    fallbackJobPolling(workspaceId, jobId);
  };
}

function fallbackJobPolling(workspaceId: string, jobId: string) {
  jobEvents?.close();
  jobEvents = undefined;
  window.clearTimeout(jobPollTimer);
  const poll = async () => {
    try {
      const status = await api<JobStatus>(`/api/workspaces/${encodeURIComponent(workspaceId)}/jobs/${encodeURIComponent(jobId)}?offset=${jobLogOffset}&maxBytes=${256 * 1024}`);
      applyJobStatus(status);
      if (!terminalStates.has(status.state)) jobPollTimer = window.setTimeout(poll, 1_000);
    } catch (error) { setInlineMessage("jobs-message", errorMessage(error), true); }
  };
  void poll();
}

function closeJobStream() {
  jobEvents?.close();
  jobEvents = undefined;
  window.clearTimeout(jobPollTimer);
}

async function cancelJob() {
  const workspace = runningWorkspace();
  if (!workspace || !activeJob || terminalStates.has(activeJob.state)) return;
  try {
    setInlineMessage("jobs-message", "Requesting cancellation…");
    const status = await api<JobStatus>(`/api/workspaces/${encodeURIComponent(workspace.id)}/jobs/${encodeURIComponent(activeJob.jobId)}`, { method: "DELETE", body: "{}" });
    applyJobStatus(status);
  } catch (error) { setInlineMessage("jobs-message", errorMessage(error), true); }
}

async function loadBloomStatus() {
  const workspace = runningWorkspace();
  if (!workspace) return;
  if (!isAvailable("bloom")) { setInlineMessage("bloom-message", capability("bloom").reason, true); renderBloomStatus(); return; }
  setInlineMessage("bloom-message", "Loading watch-only Bloom status…");
  try {
    const status = await api<BloomStatus>(`/api/workspaces/${encodeURIComponent(workspace.id)}/bloom`);
    renderBloomStatus(status);
    setInlineMessage("bloom-message", status.available ? "Bloom watch-only services are ready." : "Bloom is present but not ready.", !status.available);
  } catch (error) { renderBloomStatus(); setInlineMessage("bloom-message", errorMessage(error), true); }
}

function renderBloomStatus(status?: BloomStatus) {
  const grid = $("bloom-status");
  grid.replaceChildren();
  const details: Array<[string, string]> = status ? [
    ["Mount", status.mount.mounted ? status.mount.path : "Not mounted"],
    ["Identity", status.identity ? `${status.identity.kind}-only · ${shortAddress(status.identity.address)}` : "Unavailable"],
    ["Helper", `${status.helper.name} · protocol v${status.helper.protocolVersion}`],
    ["Wallet signing", status.capabilities.walletSigning ? "Enabled" : "Not available"],
    ["Transactions", status.capabilities.transactions ? "Enabled" : "Not available"],
  ] : [["Status", capability("bloom").reason]];
  for (const [label, value] of details) {
    const item = document.createElement("div");
    const term = document.createElement("span");
    term.textContent = label;
    const description = document.createElement("strong");
    description.textContent = value;
    item.append(term, description);
    grid.append(item);
  }
}

async function loadConnections() {
  const workspace = runningWorkspace();
  if (!workspace) return;
  setInlineMessage("connections-message", "Checking private connection options…");
  try {
    const result = await api<unknown>(`/api/workspaces/${encodeURIComponent(workspace.id)}/connections`);
    const object = typeof result === "object" && result !== null ? result as Record<string, unknown> : {};
    const methods = readConnectionMethods(object.connections ?? object);
    if (methods.length === 0) throw new Error("The connection service returned no reviewed connection methods.");
    renderConnections(methods);
    setInlineMessage("connections-message", "Connection capabilities are scoped to this workspace and its lease.");
  } catch (error) {
    if (error instanceof ApiError && error.status !== 404 && error.status !== 501) setInlineMessage("connections-message", error.message, true);
    else setInlineMessage("connections-message", "This deployment does not expose a connection grant API. Use browser files and terminal.");
    renderConnectionFallback();
  }
}

function renderConnections(methods: ReturnType<typeof readConnectionMethods>) {
  const list = $("connection-list");
  list.replaceChildren();
  for (const method of methods) {
    const article = document.createElement("article");
    const header = document.createElement("div");
    const title = document.createElement("h4");
    title.textContent = method.kind === "ssh" ? "SSH" : "Native NFS";
    const badge = document.createElement("span");
    badge.className = "status-badge";
    badge.textContent = method.status;
    header.append(title, badge);
    const reason = document.createElement("p");
    reason.textContent = method.reason;
    article.append(header, reason);
    if (method.command) article.append(connectionCommand(method.command));
    if (method.instructions.length) {
      const steps = document.createElement("ol");
      for (const instruction of method.instructions) { const item = document.createElement("li"); item.textContent = instruction; steps.append(item); }
      article.append(steps);
    }
    list.append(article);
  }
}

function connectionCommand(command: string) {
  const block = document.createElement("div");
  block.className = "command-block";
  const code = document.createElement("code");
  code.textContent = command;
  const copy = document.createElement("button");
  copy.type = "button";
  copy.className = "quiet";
  copy.textContent = "Copy";
  copy.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(command); copy.textContent = "Copied"; }
    catch { setInlineMessage("connections-message", "Copy failed. Select the command manually.", true); }
  });
  block.append(code, copy);
  return block;
}

function renderConnectionFallback() {
  renderConnections((["ssh", "nfs"] as const).map((kind) => {
    const value = capability(kind);
    return { kind, status: value.status, reason: value.reason, instructions: [] };
  }));
  syncCapabilityControls();
}

async function issueConnection(event: SubmitEvent) {
  event.preventDefault();
  const workspace = runningWorkspace();
  if (!workspace) return;
  const publicKey = $<HTMLTextAreaElement>("connection-public-key").value.trim();
  const mode = $<HTMLSelectElement>("connection-mode").value === "nfs" ? "nfs" : "shell";
  const requestedTtlMs = Number($<HTMLSelectElement>("connection-ttl").value);
  if (/PRIVATE KEY|BEGIN [A-Z ]+PRIVATE/i.test(publicKey)) {
    setInlineMessage("connections-message", "That appears to be a private key. It was not sent. Paste only the ssh-ed25519 .pub line.", true);
    return;
  }
  if (!/^ssh-ed25519 [A-Za-z0-9+/]+={0,2}(?: [^\r\n]*)?$/.test(publicKey)) {
    setInlineMessage("connections-message", "Paste one OpenSSH Ed25519 public-key line beginning ssh-ed25519.", true);
    return;
  }
  if (mode === "nfs" && !isAvailable("nfs")) {
    setInlineMessage("connections-message", capability("nfs").reason, true);
    return;
  }
  const button = $<HTMLButtonElement>("issue-connection");
  button.disabled = true;
  setInlineMessage("connections-message", `Issuing a short-lived ${mode === "nfs" ? "NFS tunnel" : "SSH"} grant…`);
  try {
    activeConnection = await api<ConnectionGrant>(`/api/workspaces/${encodeURIComponent(workspace.id)}/connections/ssh`, {
      method: "POST",
      body: JSON.stringify({ publicKey, mode, requestedTtlMs }),
    });
    renderConnectionGrant(activeConnection);
    setInlineMessage("connections-message", "Grant issued. Save the one-time token and certificate now; this page will not retain them.");
    $<HTMLTextAreaElement>("connection-public-key").value = "";
  } catch (error) { setInlineMessage("connections-message", errorMessage(error), true); }
  finally { button.disabled = !isAvailable("ssh"); }
}

function renderConnectionGrant(grant: ConnectionGrant) {
  $("connection-grant").classList.remove("hidden");
  const expiry = epochDate(grant.validBefore);
  $("connection-expiry").textContent = `Expires ${expiry.toLocaleTimeString()}`;
  const details = $("connection-details");
  details.replaceChildren();
  for (const [label, value] of [
    ["Principal", grant.principal],
    ["Public-key fingerprint", grant.fingerprint],
    ["Host alias", grant.hostKey.alias],
    ["Transport", `${grant.tunnel.protocol} over ${grant.tunnel.transport}`],
    ["Valid until", expiry.toLocaleString()],
  ]) {
    const item = document.createElement("div");
    const term = document.createElement("span");
    term.textContent = label;
    const description = document.createElement("strong");
    description.textContent = value;
    item.append(term, description);
    details.append(item);
  }
  const commands = $("connection-commands");
  commands.replaceChildren();
  commands.append(connectionTextBlock("Known-hosts entry", grant.hostKey.knownHostsLine));
  commands.append(connectionTextBlock("SSH certificate", grant.certificate));
  commands.append(connectionTextBlock("Proxy helper", `${grant.tunnel.proxyHelper} · ${grant.tunnel.path}`));
  for (const [label, argv] of [
    ["Connect with SSH · argv", grant.sshArgv],
    ["Start private SSH tunnel · argv", grant.sshTunnelArgv],
    ["Mount NFS · argv", grant.mountArgv],
    ["Unmount NFS · argv", grant.unmountArgv],
  ] as Array<[string, string[] | undefined]>) {
    if (argv) commands.append(connectionTextBlock(label, JSON.stringify(argv)));
  }
  if (grant.capability?.reason) {
    const note = document.createElement("p");
    note.className = "inline-message";
    note.textContent = `${grant.capability.status ?? "NFS"}: ${grant.capability.reason}${grant.capability.requiresAdmin ? " Administrator access is required on the client." : ""}`;
    commands.append(note);
  }
}

function connectionTextBlock(label: string, value: string) {
  const wrapper = document.createElement("div");
  wrapper.className = "connection-text-block";
  const heading = document.createElement("span");
  heading.textContent = label;
  const block = document.createElement("pre");
  block.textContent = value;
  wrapper.append(heading, block);
  return wrapper;
}

function epochDate(value: number) { return new Date(value < 1_000_000_000_000 ? value * 1000 : value); }

function downloadConnectionGrant() {
  if (!activeConnection) return;
  const blob = new Blob([JSON.stringify(activeConnection, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `bloom-workspace-${activeConnection.leaseId}.grant.json`;
  anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
  setInlineMessage("connections-message", "Grant downloaded. Set its file mode to 600 and delete it after use.");
}

async function copyConnectionToken() {
  if (!activeConnection) return;
  try {
    await navigator.clipboard.writeText(activeConnection.accessToken);
    setInlineMessage("connections-message", "Access token copied. Clear clipboard history after connecting.");
  } catch { setInlineMessage("connections-message", "Copy failed. Download the grant JSON instead.", true); }
}

async function revokeConnection() {
  const workspace = runningWorkspace();
  if (!workspace || !activeConnection) return;
  try {
    await api(`/api/workspaces/${encodeURIComponent(workspace.id)}/connections/ssh/${encodeURIComponent(activeConnection.leaseId)}`, { method: "DELETE" });
    clearConnectionGrant();
    setInlineMessage("connections-message", "Connection grant revoked.");
  } catch (error) { setInlineMessage("connections-message", errorMessage(error), true); }
}

function clearConnectionGrant() {
  activeConnection = undefined;
  $("connection-grant").classList.add("hidden");
  $("connection-details").replaceChildren();
  $("connection-commands").replaceChildren();
}

function runningWorkspace() {
  return session.workspace?.state === "running" ? session.workspace : undefined;
}

function errorMessage(error: unknown) { return error instanceof Error ? error.message : "Something went wrong. Please try again."; }

async function confirmAction(title: string, description: string, action: string) {
  const dialog = $<HTMLDialogElement>("confirm-dialog");
  $("confirm-title").textContent = title;
  $("confirm-description").textContent = description;
  $("confirm-action").textContent = action;
  dialog.returnValue = "cancel";
  dialog.showModal();
  return new Promise<boolean>((resolve) => dialog.addEventListener("close", () => resolve(dialog.returnValue === "confirm"), { once: true }));
}

async function createWorkspace() {
  try {
    setMessage();
    const selected = document.querySelector<HTMLInputElement>('input[name="storage"]:checked')?.value;
    const storage: StorageMode = selected === "persistent" ? "persistent" : "disposable";
    const result = await api<{ workspace: Workspace }>("/api/workspaces", {
      method: "POST",
      body: JSON.stringify({ turnstileToken: turnstileToken ?? null, storage }),
    });
    turnstileToken = undefined;
    window.turnstile?.reset(turnstileWidget);
    session.workspace = result.workspace;
    renderWorkspace(result.workspace);
  } catch (error) { setMessage(errorMessage(error)); }
}

async function stopWorkspace() {
  const workspace = session.workspace;
  if (!workspace) return;
  const retained = workspace.storage?.retainedAfterStop;
  const confirmed = await confirmAction(
    "Stop this workspace?",
    retained ? "The machine and active jobs will stop. Files on the persistent volume will be retained." : "The machine, active jobs, and disposable files will be deleted.",
    "Stop workspace",
  );
  if (!confirmed) return;
  try { await api("/api/workspaces/current", { method: "DELETE", body: "{}" }); await refreshWorkspace(); }
  catch (error) { setMessage(errorMessage(error)); }
}

async function deletePersistentVolume() {
  const confirmed = await confirmAction("Delete saved volume?", "Every retained file in this wallet-owned workspace volume will be permanently deleted.", "Delete volume");
  if (!confirmed) return;
  try {
    await api("/api/workspace-volume", { method: "DELETE", body: "{}" });
    session.workspace = undefined;
    renderWorkspace();
    setMessage("Persistent workspace volume deleted.");
  } catch (error) { setMessage(errorMessage(error)); }
}

for (const tab of document.querySelectorAll<HTMLButtonElement>("[role=tab]")) {
  tab.addEventListener("click", () => selectTab(tab.dataset.panel ?? "terminal"));
  tab.addEventListener("keydown", (event) => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    const tabs = [...document.querySelectorAll<HTMLButtonElement>("[role=tab]")];
    const current = tabs.indexOf(tab);
    const next = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : (current + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
    event.preventDefault();
    const target = tabs[next];
    if (target) { selectTab(target.dataset.panel ?? "terminal"); target.focus(); }
  });
}

$("connect").addEventListener("click", () => void runAuth(connectInjectedWallet));
$("connect-mobile").addEventListener("click", () => void runAuth(connectMobileWallet));
$("dev-login").addEventListener("click", () => void devLogin().catch((error) => setMessage(errorMessage(error))));
$("logout").addEventListener("click", () => void logout().catch((error) => setMessage(errorMessage(error))));
$("create").addEventListener("click", () => void createWorkspace());
$("stop").addEventListener("click", () => void stopWorkspace());
$("delete-volume").addEventListener("click", () => void deletePersistentVolume());
$("refresh-files").addEventListener("click", () => void loadFiles());
$("upload-form").addEventListener("submit", (event) => void uploadFile(event as SubmitEvent));
$("upload-file").addEventListener("change", () => {
  const file = $<HTMLInputElement>("upload-file").files?.[0];
  const path = $<HTMLInputElement>("upload-path");
  if (file && !path.value) path.value = file.name;
});
$("add-environment").addEventListener("click", () => addEnvironmentRow());
$("job-form").addEventListener("submit", (event) => void startJob(event as SubmitEvent));
$("cancel-job").addEventListener("click", () => void cancelJob());
$("refresh-bloom").addEventListener("click", () => void loadBloomStatus());
$("refresh-connections").addEventListener("click", () => void loadConnections());
$("connection-form").addEventListener("submit", (event) => void issueConnection(event as SubmitEvent));
$("download-connection").addEventListener("click", downloadConnectionGrant);
$("copy-connection-token").addEventListener("click", () => void copyConnectionToken());
$("revoke-connection").addEventListener("click", () => void revokeConnection());
$("open-files-fallback").addEventListener("click", () => { selectTab("files"); $("tab-files").focus(); });

const mobileButton = $<HTMLButtonElement>("connect-mobile");
if (!walletConnectProjectId) {
  mobileButton.disabled = true;
  mobileButton.textContent = "Mobile / QR unavailable";
  $("auth-note").textContent = "Mobile/QR login is not configured on this deployment. Browser wallet login still works. Login asks only for a message signature—never a transaction, seed phrase, or private key.";
}

loadSession().catch((error) => setMessage(errorMessage(error)));
