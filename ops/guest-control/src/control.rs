//! Guest control dispatcher: routes operations, manages Bloom status and SSH/NFS connections.

use crate::constants::*;
use crate::error::ControlError;
use crate::files::WorkspaceFiles;
use crate::jobs::JobEngine;
use crate::validate::*;
use base64::Engine;
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

static SSH_CA_PUBLIC_KEY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$").unwrap());

struct ConnectionState {
    sshd: Option<u32>,                     // pid
    mountd: Option<u32>,                   // pid
    scope: Option<(String, String, bool)>, // (workspace_id, wallet, nfs_enabled)
}

pub struct GuestControl {
    files: Arc<WorkspaceFiles>,
    jobs: Arc<JobEngine>,
    conn: Mutex<ConnectionState>,
}

impl GuestControl {
    pub fn new(files: Arc<WorkspaceFiles>, jobs: Arc<JobEngine>) -> Self {
        Self {
            files,
            jobs,
            conn: Mutex::new(ConnectionState {
                sshd: None,
                mountd: None,
                scope: None,
            }),
        }
    }

    pub fn close(&self) {
        let mut conn = self.conn.lock().unwrap();
        if let Some(pid) = conn.sshd {
            if unsafe { libc::kill(pid as i32, 0) } == 0 {
                unsafe {
                    libc::kill(pid as i32, libc::SIGTERM);
                }
                // Wait briefly
                for _ in 0..20 {
                    if unsafe { libc::kill(pid as i32, 0) } != 0 {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                unsafe {
                    libc::kill(pid as i32, libc::SIGKILL);
                }
            }
        }
        conn.sshd = None;
        if let Some(scope) = &conn.scope {
            if scope.2 {
                let _ = self.stop_partial_nfs(&mut conn);
            }
        }
    }

    pub fn handle(&self, raw: &Value) -> Value {
        let request_id = raw
            .get("id")
            .and_then(|v| v.as_str())
            .filter(|s| REQUEST_ID.is_match(s))
            .unwrap_or("invalid")
            .to_string();

        let result = (|| -> Result<Value, ControlError> {
            validate_request(raw)?;
            let operation = raw["operation"].as_str().unwrap_or("");
            match operation {
                "hello" => Ok(json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "operations": [
                        "fs.list", "fs.read", "fs.write", "fs.delete",
                        "job.start", "job.status", "job.cancel",
                        "bloom.status", "connections.configure", "ceremony.pending"
                    ],
                    "limits": {
                        "fileChunkBytes": MAX_FILE_CHUNK_BYTES,
                        "fileBytes": MAX_FILE_BYTES,
                        "activeJobs": MAX_ACTIVE_JOBS,
                        "retainedJobs": MAX_RETAINED_JOBS,
                        "jobProcesses": MAX_JOB_PROCESSES,
                        "jobLogBytes": MAX_LOG_BYTES,
                        "jobTimeoutMs": MAX_JOB_TIMEOUT_MS,
                    }
                })),
                "fs.list" => self.files.list(&raw["path"]),
                "fs.read" => self
                    .files
                    .read(&raw["path"], &raw["offset"], &raw["maxBytes"]),
                "fs.write" => {
                    self.files
                        .write(&raw["path"], &raw["offset"], &raw["data"], &raw["truncate"])
                }
                "fs.delete" => self.files.delete(&raw["path"], &raw["recursive"]),
                "job.start" => {
                    // Clone the request to avoid lifetime issues
                    self.jobs.start(raw)
                }
                "job.status" => self.jobs.status(raw),
                "job.cancel" => self.jobs.cancel(raw),
                "bloom.status" => self.bloom_status(),
                "connections.configure" => self.configure_connections(raw),
                "ceremony.pending" => self.ceremony_pending(),
                _ => Err(ControlError::invalid_request("unknown guest operation")),
            }
        })();

        match result {
            Ok(val) => {
                json!({ "version": PROTOCOL_VERSION, "id": request_id, "ok": true, "result": val })
            }
            Err(e) => {
                json!({ "version": PROTOCOL_VERSION, "id": request_id, "ok": false, "error": { "code": e.code, "message": truncate_str(&e.message, 1024) } })
            }
        }
    }

    fn bloom_status(&self) -> Result<Value, ControlError> {
        let address = self.files.watch_identity();
        let has_addr = address.is_some();
        let executable = which("bloom").is_some();
        Ok(json!({
            "available": executable && has_addr,
            "mount": { "path": "/bloom", "mounted": is_mount("/bloom") },
            "identity": if has_addr {
                json!({ "kind": "watch", "address": address.unwrap() })
            } else {
                Value::Null
            },
            "capabilities": {
                "files": true,
                "jobs": true,
                "bloomRead": executable && has_addr,
                "walletSigning": false,
                "transactions": false,
            },
            "helper": { "name": "bloom-workspace", "protocolVersion": PROTOCOL_VERSION },
        }))
    }

    fn bloom_ipc(&self, method: &str, params: &Value) -> Result<Value, ControlError> {
        if !Path::new(BLOOM_SOCKET_PATH).exists() {
            return Err(ControlError::unavailable(
                "Bloom IPC socket is not available",
            ));
        }
        let request = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let frame = serde_json::to_string(&request).unwrap() + "\n";
        let mut client = UnixStream::connect(BLOOM_SOCKET_PATH)
            .map_err(|_| ControlError::unavailable("cannot connect to Bloom IPC"))?;
        client.set_read_timeout(Some(Duration::from_secs(10))).ok();
        client.set_write_timeout(Some(Duration::from_secs(10))).ok();
        client
            .write_all(frame.as_bytes())
            .map_err(|_| ControlError::internal("bloom IPC write failed"))?;
        let mut response = Vec::new();
        let mut buf = [0u8; 65536];
        loop {
            let n = client
                .read(&mut buf)
                .map_err(|_| ControlError::internal("bloom IPC read failed"))?;
            if n == 0 {
                break;
            }
            response.extend_from_slice(&buf[..n]);
            if response.contains(&b'\n') {
                break;
            }
            if response.len() > 1024 * 1024 {
                break;
            }
        }
        let decoded: Value = serde_json::from_slice(&response)
            .map_err(|_| ControlError::internal("bloom IPC returned invalid JSON"))?;
        if decoded.get("error").is_some() {
            return Err(ControlError::internal(format!(
                "bloom IPC error: {}",
                decoded["error"]
            )));
        }
        Ok(decoded.get("result").cloned().unwrap_or(Value::Null))
    }

    fn ceremony_pending(&self) -> Result<Value, ControlError> {
        let wallet_result = self.bloom_ipc("list", &json!({ "path": "/wallets" }))?;
        let wallets: Vec<String> = wallet_result
            .get("entries")
            .and_then(|e| e.as_array())
            .map(|arr| {
                arr.iter()
                    .filter(|e| e.get("type").and_then(|t| t.as_str()) == Some("dir"))
                    .filter_map(|e| {
                        e.get("name")
                            .and_then(|n| n.as_str())
                            .map(|s| s.to_string())
                    })
                    .collect()
            })
            .unwrap_or_default();

        let mut pending = Vec::new();
        for wallet in wallets.iter().take(MAX_OUTBOX_CHAINS) {
            let chain_result = self.bloom_ipc(
                "list",
                &json!({ "path": format!("/wallets/{}/chains", wallet) }),
            )?;
            let chains: Vec<String> = chain_result
                .get("entries")
                .and_then(|e| e.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter(|e| e.get("type").and_then(|t| t.as_str()) == Some("dir"))
                        .filter_map(|e| {
                            e.get("name")
                                .and_then(|n| n.as_str())
                                .map(|s| s.to_string())
                        })
                        .collect()
                })
                .unwrap_or_default();

            for chain in chains.iter().take(MAX_OUTBOX_CHAINS) {
                let pending_result = self.bloom_ipc("list", &json!({ "path": format!("/wallets/{}/chains/{}/outbox/pending", wallet, chain) }))?;
                let ids: Vec<String> = pending_result
                    .get("entries")
                    .and_then(|e| e.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter(|e| e.get("type").and_then(|t| t.as_str()) == Some("dir"))
                            .filter_map(|e| {
                                e.get("name")
                                    .and_then(|n| n.as_str())
                                    .map(|s| s.to_string())
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                for tx_id in ids.iter().take(MAX_OUTBOX_PENDING) {
                    let plan_result = self.bloom_ipc("read", &json!({ "path": format!("/wallets/{}/chains/{}/outbox/pending/{}/plan.md", wallet, chain, tx_id) }))?;
                    let plan_b64 = plan_result
                        .get("bytes_b64")
                        .and_then(|b| b.as_str())
                        .unwrap_or("");
                    let plan_md = base64::engine::general_purpose::STANDARD
                        .decode(plan_b64)
                        .ok()
                        .and_then(|bytes| String::from_utf8(bytes).ok())
                        .unwrap_or_default();
                    let plan_md = if plan_md.len() > MAX_OUTBOX_PLAN_BYTES {
                        plan_md[..MAX_OUTBOX_PLAN_BYTES].to_string()
                    } else {
                        plan_md
                    };

                    let ceremony_url = self.bloom_ipc("read", &json!({ "path": format!("/wallets/{}/chains/{}/outbox/pending/{}/approval_challenge.json", wallet, chain, tx_id) }))
                        .ok()
                        .and_then(|result| {
                            let b64 = result.get("bytes_b64").and_then(|b| b.as_str())?;
                            let bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
                            let json: Value = serde_json::from_slice(&bytes).ok()?;
                            json.get("ceremony_url").and_then(|u| u.as_str()).map(|s| s.to_string())
                        });

                    pending.push(json!({
                        "id": tx_id,
                        "chain": chain,
                        "wallet": wallet,
                        "planMd": plan_md,
                        "ceremonyUrl": ceremony_url,
                    }));
                }
            }
        }
        Ok(json!({ "requests": pending }))
    }

    fn configure_connections(&self, request: &Value) -> Result<Value, ControlError> {
        let mut conn = self.conn.lock().unwrap();
        self.configure_connections_locked(&mut conn, request)
    }

    fn configure_connections_locked(
        &self,
        conn: &mut ConnectionState,
        request: &Value,
    ) -> Result<Value, ControlError> {
        let workspace_id = request["workspaceId"]
            .as_str()
            .ok_or_else(|| ControlError::invalid_request("invalid workspace id"))?;
        if !WORKSPACE_ID.is_match(workspace_id) {
            return Err(ControlError::invalid_request("invalid workspace id"));
        }
        let wallet = request["wallet"]
            .as_str()
            .ok_or_else(|| ControlError::invalid_request("invalid workspace wallet"))?;
        if !EVM_ADDRESS.is_match(wallet) {
            return Err(ControlError::invalid_request("invalid workspace wallet"));
        }
        let ca_public_key = request["caPublicKey"]
            .as_str()
            .ok_or_else(|| ControlError::invalid_request("invalid SSH CA public key"))?;
        if !SSH_CA_PUBLIC_KEY_RE.is_match(ca_public_key) {
            return Err(ControlError::invalid_request("invalid SSH CA public key"));
        }
        let nfs_enabled = request["nfs"]
            .as_bool()
            .ok_or_else(|| ControlError::invalid_request("invalid NFS capability"))?;

        let scope = (workspace_id.to_string(), wallet.to_string(), nfs_enabled);
        if let Some(existing) = &conn.scope {
            if *existing == scope {
                return Ok(self.connection_status(conn, workspace_id, nfs_enabled));
            }
            return Err(ControlError::conflict(
                "workspace connection scope is already configured",
            ));
        }
        if unsafe { libc::geteuid() } != 0 {
            return Err(ControlError::unavailable(
                "workspace connections require the root guest controller",
            ));
        }
        if which("sshd").is_none() || which("ssh-keygen").is_none() {
            return Err(ControlError::unavailable(
                "OpenSSH server tooling is unavailable",
            ));
        }

        // Validate CA public key payload
        let parts: Vec<&str> = ca_public_key.splitn(2, ' ').collect();
        if parts.len() != 2 {
            return Err(ControlError::invalid_request("invalid SSH CA public key"));
        }
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(parts[1])
            .map_err(|_| ControlError::invalid_request("invalid SSH CA public key"))?;
        if decoded.len() < 32 || decoded.len() > 128 {
            return Err(ControlError::invalid_request(
                "invalid SSH CA public key payload",
            ));
        }

        let dir = "/run/bloom/ssh";
        std::fs::create_dir_all(dir)
            .map_err(|_| ControlError::internal("cannot create ssh dir"))?;
        set_mode(dir, 0o700);

        let ca_path = format!("{}/user_ca.pub", dir);
        let principals_path = format!("{}/authorized_principals", dir);
        let host_key_path = format!("{}/ssh_host_ed25519_key", dir);

        let owner_digest = sha256_hex(wallet.as_bytes());
        let owner_digest = &owner_digest[..32];
        let mut principals = vec![format!("bloom-shell-{}-w-{}", workspace_id, owner_digest)];
        if nfs_enabled {
            principals.push(format!("bloom-nfs-{}-w-{}", workspace_id, owner_digest));
        }

        write_private_file(&ca_path, &format!("{}\n", ca_public_key), 0o600);
        write_private_file(
            &principals_path,
            &format!("{}\n", principals.join("\n")),
            0o600,
        );

        if !Path::new(&host_key_path).exists() {
            let status = std::process::Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f", &host_key_path])
                .status();
            if !matches!(status, Ok(s) if s.success()) {
                return Err(ControlError::unavailable("ssh-keygen failed"));
            }
        }
        set_mode(&host_key_path, 0o600);
        set_mode(&format!("{}.pub", host_key_path), 0o644);

        let shell = "/usr/local/libexec/bloom-workspace-shell";
        if !Path::new(shell).is_file() || is_symlink(shell) {
            return Err(ControlError::unavailable(
                "workspace SSH shell helper is unavailable",
            ));
        }

        let host_key_opt = format!("HostKey={}", host_key_path);
        let ca_keys_opt = format!("TrustedUserCAKeys={}", ca_path);
        let principals_opt = format!("AuthorizedPrincipalsFile={}", principals_path);
        let sshd_argv: Vec<&str> = vec![
            "sshd",
            "-D",
            "-e",
            "-f",
            "/etc/ssh/sshd_config",
            "-o",
            &host_key_opt,
            "-o",
            &ca_keys_opt,
            "-o",
            &principals_opt,
            "-o",
            "AuthorizedKeysFile=none",
            "-o",
            "AuthenticationMethods=publickey",
            "-o",
            "PubkeyAuthentication=yes",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "PermitRootLogin=no",
            "-o",
            "AllowUsers=workspace",
            "-o",
            "AllowAgentForwarding=no",
            "-o",
            "AllowTcpForwarding=local",
            "-o",
            "PermitOpen=127.0.0.1:2049 127.0.0.1:18734",
            "-o",
            "AllowStreamLocalForwarding=no",
            "-o",
            "GatewayPorts=no",
            "-o",
            "X11Forwarding=no",
            "-o",
            "PermitTunnel=no",
            "-o",
            "PermitUserEnvironment=no",
            "-o",
            "PermitUserRC=no",
            "-o",
            "PermitTTY=yes",
            "-o",
            "MaxSessions=1",
            "-o",
            "UsePAM=no",
            "-o",
            "AddressFamily=inet",
            "-o",
            "ListenAddress=0.0.0.0",
            "-o",
            "Port=22",
        ];

        let sshd_child = std::process::Command::new("sshd")
            .args(&sshd_argv[1..])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|_| ControlError::unavailable("workspace sshd failed to start"))?;
        std::thread::sleep(Duration::from_millis(50));
        let sshd_pid = sshd_child.id();

        if nfs_enabled {
            if let Err(e) = self.start_nfs(workspace_id) {
                // Kill sshd
                unsafe {
                    libc::kill(sshd_pid as i32, libc::SIGTERM);
                }
                std::thread::sleep(Duration::from_secs(2));
                unsafe {
                    libc::kill(sshd_pid as i32, libc::SIGKILL);
                }
                return Err(e);
            }
            conn.mountd = Some(0); // placeholder, set in start_nfs
        }

        conn.sshd = Some(sshd_pid);
        conn.scope = Some(scope);
        Ok(self.connection_status(conn, workspace_id, nfs_enabled))
    }

    fn start_nfs(&self, workspace_id: &str) -> Result<(), ControlError> {
        for cmd in &["exportfs", "rpc.mountd", "rpc.nfsd"] {
            if which(cmd).is_none() {
                self.stop_partial_nfs(&mut self.conn.lock().unwrap());
                return Err(ControlError::unavailable(&format!(
                    "NFS server tool is unavailable: {}",
                    cmd
                )));
            }
        }
        std::fs::create_dir_all("/proc/fs/nfsd").ok();
        if !is_mount("/proc/fs/nfsd") {
            let r = std::process::Command::new("mount")
                .args(["-t", "nfsd", "nfsd", "/proc/fs/nfsd"])
                .status();
            if !matches!(r, Ok(s) if s.success()) {
                self.stop_partial_nfs(&mut self.conn.lock().unwrap());
                return Err(ControlError::unavailable("failed to mount nfsd filesystem"));
            }
        }
        let options = "rw,fsid=0,sync,no_subtree_check,root_squash,all_squash,anonuid=1000,anongid=1000,insecure";
        let r = std::process::Command::new("exportfs")
            .args(["-i", "-o", options, "127.0.0.1:/workspace"])
            .status();
        if !matches!(r, Ok(s) if s.success()) {
            self.stop_partial_nfs(&mut self.conn.lock().unwrap());
            return Err(ControlError::unavailable("exportfs failed"));
        }

        let mountd_child = std::process::Command::new("rpc.mountd")
            .args([
                "--foreground",
                "--no-udp",
                "--no-nfs-version",
                "2",
                "--no-nfs-version",
                "3",
                "--ttl",
                "10",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        match mountd_child {
            Ok(child) => {
                std::thread::sleep(Duration::from_millis(50));
                let mountd_pid = child.id();
                if unsafe { libc::kill(mountd_pid as i32, 0) } != 0 {
                    self.stop_partial_nfs(&mut self.conn.lock().unwrap());
                    return Err(ControlError::unavailable(
                        "NFS mount daemon failed to start",
                    ));
                }
                {
                    let mut conn = self.conn.lock().unwrap();
                    conn.mountd = Some(mountd_pid);
                }
            }
            Err(_) => {
                self.stop_partial_nfs(&mut self.conn.lock().unwrap());
                return Err(ControlError::unavailable("rpc.mountd failed to start"));
            }
        }

        let r = std::process::Command::new("rpc.nfsd")
            .args([
                "--host",
                "127.0.0.1",
                "--no-udp",
                "--no-nfs-version",
                "2",
                "--no-nfs-version",
                "3",
                "--nfs-version",
                "4",
                "--leasetime",
                "10",
                "--grace-time",
                "10",
                "--port",
                "2049",
                "1",
            ])
            .status();
        if !matches!(r, Ok(s) if s.success()) {
            self.stop_partial_nfs(&mut self.conn.lock().unwrap());
            return Err(ControlError::unavailable("rpc.nfsd failed to start"));
        }
        Ok(())
    }

    fn stop_partial_nfs(&self, conn: &mut ConnectionState) {
        if let Some(pid) = conn.mountd {
            if pid > 0 && unsafe { libc::kill(pid as i32, 0) } == 0 {
                unsafe {
                    libc::kill(pid as i32, libc::SIGTERM);
                }
                for _ in 0..20 {
                    if unsafe { libc::kill(pid as i32, 0) } != 0 {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                unsafe {
                    libc::kill(pid as i32, libc::SIGKILL);
                }
            }
        }
        conn.mountd = None;
        if which("rpc.nfsd").is_some() {
            let _ = std::process::Command::new("rpc.nfsd").arg("0").status();
        }
        if which("exportfs").is_some() {
            let _ = std::process::Command::new("exportfs")
                .args(["-u", "127.0.0.1:/workspace"])
                .status();
        }
    }

    fn connection_status(
        &self,
        conn: &ConnectionState,
        workspace_id: &str,
        nfs_enabled: bool,
    ) -> Value {
        let host_key = read_small_regular_file("/run/bloom/ssh/ssh_host_ed25519_key.pub", 1024);
        let host_key = host_key
            .filter(|h| h.starts_with("ssh-ed25519 "))
            .map(|h| h.split_whitespace().take(2).collect::<Vec<_>>().join(" "));
        let host_key = match host_key {
            Some(hk) => hk,
            None => {
                return json!({ "error": { "code": "unavailable", "message": "guest SSH host key is unavailable" } })
            }
        };
        let ssh_available = conn
            .sshd
            .map(|p| unsafe { libc::kill(p as i32, 0) } == 0)
            .unwrap_or(false);
        let nfs_available = nfs_enabled
            && conn
                .mountd
                .map(|p| p > 0 && unsafe { libc::kill(p as i32, 0) } == 0)
                .unwrap_or(false);
        json!({
            "ssh": { "available": ssh_available, "hostKey": host_key, "port": 22 },
            "nfs": { "available": nfs_available, "port": if nfs_enabled { Some(2049) } else { None } },
            "workspaceId": workspace_id,
        })
    }
}

// Helper functions

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        s[..max].to_string()
    }
}

fn is_mount(path: &str) -> bool {
    let c_path = std::ffi::CString::new(path).unwrap();
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let mut parent_st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(c_path.as_ptr(), &mut st) } != 0 {
        return false;
    }
    let parent = Path::new(path).parent().unwrap_or(Path::new("/"));
    let c_parent = std::ffi::CString::new(parent.to_string_lossy().as_bytes()).unwrap();
    if unsafe { libc::stat(c_parent.as_ptr(), &mut parent_st) } != 0 {
        return false;
    }
    st.st_dev != parent_st.st_dev
}

fn is_symlink(path: &str) -> bool {
    std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

fn set_mode(path: &str, mode: libc::mode_t) {
    let c_path = std::ffi::CString::new(path).unwrap();
    unsafe {
        libc::chmod(c_path.as_ptr(), mode);
    }
}

fn write_private_file(path: &str, content: &str, mode: libc::mode_t) {
    let c_path = std::ffi::CString::new(path).unwrap();
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_NOFOLLOW,
            mode,
        )
    };
    if fd < 0 {
        return;
    }
    unsafe {
        libc::fchmod(fd, mode);
        let bytes = content.as_bytes();
        let mut written: usize = 0;
        while written < bytes.len() {
            let n = libc::write(
                fd,
                bytes[written..].as_ptr() as *const _,
                bytes.len() - written,
            );
            if n <= 0 {
                break;
            }
            written += n as usize;
        }
        libc::fsync(fd);
        libc::close(fd);
    }
}

fn read_small_regular_file(path: &str, maximum: usize) -> Option<String> {
    let c_path = std::ffi::CString::new(path).ok()?;
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW) };
    if fd < 0 {
        return None;
    }
    let result = unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(fd, &mut st) != 0 {
            return None;
        }
        if (st.st_mode & libc::S_IFMT as libc::mode_t) != libc::S_IFREG as libc::mode_t {
            return None;
        }
        if st.st_size > maximum as i64 {
            return None;
        }
        let mut buf = vec![0u8; maximum];
        let n = libc::read(fd, buf.as_mut_ptr() as *mut _, maximum);
        libc::close(fd);
        if n < 0 {
            return None;
        }
        buf.truncate(n as usize);
        String::from_utf8(buf).ok()
    };
    result.map(|s| s.trim().to_string())
}

fn sha256_hex(data: &[u8]) -> String {
    // Minimal SHA-256 implementation
    let mut hash = [0u32; 8];
    hash[0] = 0x6a09e667;
    hash[1] = 0xbb67ae85;
    hash[2] = 0x3c6ef372;
    hash[3] = 0xa54ff53a;
    hash[4] = 0x510e527f;
    hash[5] = 0x9b05688c;
    hash[6] = 0x1f83d9ab;
    hash[7] = 0x5be0cd19;

    let k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    // Pad message
    let mut msg = data.to_vec();
    let bit_len = (msg.len() * 8) as u64;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut a = hash[0];
        let mut b = hash[1];
        let mut c = hash[2];
        let mut d = hash[3];
        let mut e = hash[4];
        let mut f = hash[5];
        let mut g = hash[6];
        let mut h = hash[7];
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        hash[0] = hash[0].wrapping_add(a);
        hash[1] = hash[1].wrapping_add(b);
        hash[2] = hash[2].wrapping_add(c);
        hash[3] = hash[3].wrapping_add(d);
        hash[4] = hash[4].wrapping_add(e);
        hash[5] = hash[5].wrapping_add(f);
        hash[6] = hash[6].wrapping_add(g);
        hash[7] = hash[7].wrapping_add(h);
    }

    let mut result = String::new();
    for h in &hash {
        result.push_str(&format!("{:08x}", h));
    }
    result
}

fn which(cmd: &str) -> Option<String> {
    std::process::Command::new("which")
        .arg(cmd)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
}
