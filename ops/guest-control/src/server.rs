//! Transport server: stdio, Unix socket, and AF_VSOCK listeners.

use crate::constants::*;
use crate::control::GuestControl;
use crate::files::WorkspaceFiles;
use crate::jobs::JobEngine;
use crate::protocol::process_frame;
use crate::Args;
use crate::SHOULD_EXIT;
use std::io::{BufRead, Write};
use std::os::fd::RawFd;
use std::os::unix::fs::FileTypeExt;
use std::process::ExitCode;
use std::sync::atomic::Ordering;
use std::sync::Arc;

pub fn run(args: Args) -> ExitCode {
    let files = match WorkspaceFiles::new(
        &args.workspace,
        args.workspace_quota_bytes,
        args.job_uid,
        args.job_gid,
    ) {
        Ok(f) => Arc::new(f),
        Err(e) => {
            eprintln!("fatal: {e}");
            return ExitCode::from(1);
        }
    };

    // Verify prlimit and setpriv exist
    if which("prlimit").is_none() || which("setpriv").is_none() {
        eprintln!("required job isolation command is unavailable");
        return ExitCode::from(1);
    }

    if let Err(e) = files.prepare_job_tmp() {
        eprintln!("failed to prepare job tmp: {e}");
        return ExitCode::from(1);
    }

    let jobs = Arc::new(JobEngine::new(files.clone(), args.job_uid, args.job_gid));
    let control = Arc::new(GuestControl::new(files.clone(), jobs.clone()));

    let mut listeners: Vec<ListenFd> = Vec::new();

    // Unix socket listener
    if let Some(ref sock_path) = args.unix_socket {
        match create_unix_listener(sock_path, args.job_uid, args.job_gid) {
            Ok(fd) => listeners.push(ListenFd::Unix(fd)),
            Err(e) => {
                eprintln!("failed to create unix socket: {e}");
                control.close();
                jobs.close();
                files.close();
                return ExitCode::from(1);
            }
        }
    }

    // VSOCK listener
    if let Some(port) = args.vsock_port {
        match create_vsock_listener(port) {
            Ok(fd) => listeners.push(ListenFd::Vsock(fd)),
            Err(e) => {
                eprintln!("failed to create vsock listener: {e}");
                control.close();
                jobs.close();
                files.close();
                return ExitCode::from(1);
            }
        }
    }

    // Stdio transport
    if args.stdio {
        let control_clone = control.clone();
        std::thread::spawn(move || {
            serve_stdio(control_clone);
            // Signal main thread to exit when stdin closes
            SHOULD_EXIT.store(true, Ordering::SeqCst);
        });
    }

    // Socket transport
    if !listeners.is_empty() {
        serve_sockets(control.clone(), &listeners);
    } else {
        // Stdio-only mode: wait for shutdown signal
        while !SHOULD_EXIT.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    }

    // Cleanup
    control.close();
    jobs.close();
    files.close();

    if let Some(ref sock_path) = args.unix_socket {
        let _ = std::fs::remove_file(sock_path);
    }

    ExitCode::SUCCESS
}

enum ListenFd {
    Unix(RawFd),
    Vsock(RawFd),
}

impl ListenFd {
    fn raw(&self) -> RawFd {
        match self {
            Self::Unix(fd) | Self::Vsock(fd) => *fd,
        }
    }
}

fn serve_stdio(control: Arc<GuestControl>) {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();
    let mut buf = String::new();
    loop {
        buf.clear();
        match reader.read_line(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(_) => {
                if buf.len() > MAX_FRAME_BYTES + 2 {
                    let err = serde_json::json!({
                        "version": PROTOCOL_VERSION,
                        "id": "invalid",
                        "ok": false,
                        "error": { "code": "limit_exceeded", "message": "guest protocol frame is too large" }
                    });
                    let resp = crate::protocol::encode_response(&err);
                    let _ = writer.write_all(&resp);
                    let _ = writer.flush();
                    continue;
                }
                let response = process_frame(&control, buf.as_bytes());
                let _ = writer.write_all(&response);
                let _ = writer.flush();
            }
        }
    }
}

fn serve_sockets(control: Arc<GuestControl>, listeners: &[ListenFd]) {
    loop {
        if SHOULD_EXIT.load(Ordering::SeqCst) {
            return;
        }
        let mut fds: Vec<libc::pollfd> = listeners
            .iter()
            .map(|l| libc::pollfd {
                fd: l.raw(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();

        // 500ms timeout so we can check SHOULD_EXIT periodically
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 500) };
        if rc < 0 {
            if unsafe { *libc::__errno_location() } == libc::EINTR {
                continue;
            }
            return;
        }
        if rc == 0 {
            continue; // timeout — check SHOULD_EXIT at top of loop
        }

        for (i, fd) in fds.iter().enumerate() {
            if fd.revents & libc::POLLIN == 0 {
                continue;
            }
            let listen_fd = listeners[i].raw();
            let addr_storage = match &listeners[i] {
                ListenFd::Unix(_) => {
                    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
                    let mut len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
                    let conn =
                        unsafe { libc::accept(listen_fd, &mut addr as *mut _ as *mut _, &mut len) };
                    if conn < 0 {
                        continue;
                    }
                    Some(conn)
                }
                ListenFd::Vsock(_) => {
                    let mut addr: libc::sockaddr = unsafe { std::mem::zeroed() };
                    let mut len = std::mem::size_of::<libc::sockaddr>() as libc::socklen_t;
                    let conn = unsafe { libc::accept(listen_fd, &mut addr, &mut len) };
                    if conn < 0 {
                        continue;
                    }
                    Some(conn)
                }
            };

            if let Some(conn) = addr_storage {
                handle_socket_connection(&control, conn);
            }
        }
    }
}

fn handle_socket_connection(control: &GuestControl, fd: RawFd) {
    // Set 10s timeout
    let tv = libc::timeval {
        tv_sec: 10,
        tv_usec: 0,
    };
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const _,
            std::mem::size_of_val(&tv) as libc::socklen_t,
        );
    }

    let mut frame = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
        if n <= 0 {
            break;
        }
        frame.extend_from_slice(&buf[..n as usize]);
        if frame.len() > MAX_FRAME_BYTES {
            break;
        }
        if frame.contains(&b'\n') {
            break;
        }
    }

    let response = process_frame(control, &frame);
    unsafe {
        let mut written: usize = 0;
        while written < response.len() {
            let n = libc::write(
                fd,
                response[written..].as_ptr() as *const _,
                response.len() - written,
            );
            if n <= 0 {
                break;
            }
            written += n as usize;
        }
        libc::close(fd);
    }
}

fn create_unix_listener(path: &std::path::Path, uid: u32, gid: u32) -> Result<RawFd, String> {
    let parent = path.parent().ok_or("invalid socket path")?;
    std::fs::create_dir_all(parent).map_err(|e| format!("cannot create socket dir: {e}"))?;

    // Remove existing socket
    if path.exists() {
        let meta =
            std::fs::symlink_metadata(path).map_err(|e| format!("cannot stat socket: {e}"))?;
        if !meta.file_type().is_socket() && !meta.file_type().is_symlink() {
            return Err("guest control socket path is occupied".into());
        }
        std::fs::remove_file(path).ok();
    }

    let c_path = std::ffi::CString::new(path.to_string_lossy().as_bytes())
        .map_err(|_| "invalid path".to_string())?;
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err("socket() failed".into());
    }
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as _;
    let path_str = path.to_string_lossy().into_owned();
    let path_bytes = path_str.as_bytes();
    if path_bytes.len() >= addr.sun_path.len() {
        return Err("socket path too long".into());
    }
    for (i, &b) in path_bytes.iter().enumerate() {
        addr.sun_path[i] = b as _;
    }
    let addr_len = (2 + path_bytes.len()) as libc::socklen_t;
    if unsafe { libc::bind(fd, &addr as *const _ as *const _, addr_len) } < 0 {
        unsafe {
            libc::close(fd);
        }
        return Err("bind() failed".into());
    }
    unsafe {
        libc::chmod(c_path.as_ptr(), 0o600);
        if libc::geteuid() == 0 {
            libc::chown(c_path.as_ptr(), uid, gid);
        }
        libc::listen(fd, 16);
    }
    Ok(fd)
}

fn create_vsock_listener(port: u32) -> Result<RawFd, String> {
    // AF_VSOCK = 40 on Linux
    let fd = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err("vsock socket() failed — AF_VSOCK not supported".into());
    }
    let mut addr: libc::sockaddr = unsafe { std::mem::zeroed() };
    addr.sa_family = AF_VSOCK as _;
    // sockaddr_vm layout: family(2), reserved(2), cid(4), port(4) = 12 bytes
    let addr_ptr = &addr as *const _ as *const u8;
    // cid = VMADDR_CID_ANY at offset 4
    unsafe {
        let cid_ptr = addr_ptr.add(4) as *mut u32;
        *cid_ptr = VMADDR_CID_ANY;
        let port_ptr = addr_ptr.add(8) as *mut u32;
        *port_ptr = port;
    }
    let addr_len = 12; // sizeof(sockaddr_vm)
    if unsafe { libc::bind(fd, &addr, addr_len) } < 0 {
        unsafe {
            libc::close(fd);
        }
        return Err("vsock bind() failed".into());
    }
    if unsafe { libc::listen(fd, 16) } < 0 {
        unsafe {
            libc::close(fd);
        }
        return Err("vsock listen() failed".into());
    }
    Ok(fd)
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
