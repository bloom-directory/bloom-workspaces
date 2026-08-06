//! Bounded guest-side file, job, and Bloom status service.
//!
//! Accepts the version-1 JSON-line protocol over AF_VSOCK, a guest-local Unix
//! socket, and/or stdio. Every job is exec'd via prlimit + setpriv as the
//! unprivileged workspace account with no capabilities and no-new-privileges.
//!
//! This binary is intentionally dependency-light. It speaks the same wire
//! protocol as the original Python implementation and is a drop-in replacement.

mod client;
mod constants;
mod control;
mod error;
mod files;
mod jobs;
mod logs;
mod protocol;
mod server;
mod validate;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;

/// Global shutdown flag set by SIGTERM/SIGINT signal handlers.
pub static SHOULD_EXIT: AtomicBool = AtomicBool::new(false);

fn main() -> ExitCode {
    // If the first argument is a known client subcommand, dispatch to the CLI client.
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match argv.first().map(|s| s.as_str()) {
        Some("status") | Some("hello") | Some("files") | Some("jobs") => {
            return ExitCode::from(client::run(&argv) as u8);
        }
        _ => {}
    }

    // SIGTERM/SIGINT → graceful shutdown via atomic flag
    unsafe {
        extern "C" fn handle_signal(_sig: libc::c_int) {
            SHOULD_EXIT.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handle_signal as *const () as usize;
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
    }

    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };

    server::run(args)
}

pub struct Args {
    pub workspace: PathBuf,
    pub workspace_quota_bytes: u64,
    pub job_uid: u32,
    pub job_gid: u32,
    pub stdio: bool,
    pub unix_socket: Option<PathBuf>,
    pub vsock_port: Option<u32>,
}

fn parse_args() -> Result<Args, String> {
    let mut workspace = PathBuf::from("/workspace");
    let mut workspace_quota_bytes: u64 = 512 * 1024 * 1024;
    let mut job_uid: u32 = 1000;
    let mut job_gid: u32 = 1000;
    let mut stdio = false;
    let mut unix_socket: Option<PathBuf> = None;
    let mut vsock_port: Option<u32> = None;

    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        let arg = arg.to_string_lossy().to_string();
        match arg.as_str() {
            "--stdio" => stdio = true,
            "--workspace" => {
                workspace = PathBuf::from(args.next().ok_or("--workspace requires a value")?);
            }
            "--workspace-quota-bytes" => {
                let v = args
                    .next()
                    .ok_or("--workspace-quota-bytes requires a value")?;
                workspace_quota_bytes = v
                    .to_string_lossy()
                    .parse()
                    .map_err(|_| "workspace-quota-bytes must be a number")?;
            }
            "--job-uid" => {
                let v = args.next().ok_or("--job-uid requires a value")?;
                job_uid = v
                    .to_string_lossy()
                    .parse()
                    .map_err(|_| "job-uid must be a number")?;
            }
            "--job-gid" => {
                let v = args.next().ok_or("--job-gid requires a value")?;
                job_gid = v
                    .to_string_lossy()
                    .parse()
                    .map_err(|_| "job-gid must be a number")?;
            }
            "--unix-socket" => {
                unix_socket = Some(PathBuf::from(
                    args.next().ok_or("--unix-socket requires a value")?,
                ));
            }
            "--vsock-port" => {
                let v = args.next().ok_or("--vsock-port requires a value")?;
                vsock_port = Some(
                    v.to_string_lossy()
                        .parse()
                        .map_err(|_| "vsock-port must be a number")?,
                );
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }

    if !stdio && unix_socket.is_none() && vsock_port.is_none() {
        return Err(
            "at least one transport is required (--stdio, --unix-socket, or --vsock-port)".into(),
        );
    }
    if !(1024 * 1024..=16 * 1024 * 1024 * 1024).contains(&workspace_quota_bytes) {
        return Err("workspace quota is outside the supported range".into());
    }
    if let Some(port) = vsock_port {
        if port == 0 || port == u32::MAX {
            return Err("vsock port is outside the supported range".into());
        }
    }

    Ok(Args {
        workspace,
        workspace_quota_bytes,
        job_uid,
        job_gid,
        stdio,
        unix_socket,
        vsock_port,
    })
}

// Re-export for binary-level checks
pub use constants::*;
