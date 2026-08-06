//! Job engine: spawn isolated processes with prlimit + setpriv.

use crate::constants::*;
use crate::error::ControlError;
use crate::files::WorkspaceFiles;
use crate::logs::LogRing;
use crate::validate::{
    validate_environment, validate_integer, validate_job_id, validate_workspace_directory,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::io::Read;
use std::os::unix::io::AsRawFd;
use std::process::Stdio;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const TERMINAL_STATES: &[&str] = &["succeeded", "failed", "cancelled", "timed_out"];

fn is_terminal(state: &str) -> bool {
    TERMINAL_STATES.contains(&state)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

struct Job {
    job_id: String,
    argv: Vec<String>,
    cwd: String,
    timeout_ms: u64,
    created_at: u64,
    state: String,
    started_at: Option<u64>,
    finished_at: Option<u64>,
    exit_code: Option<i32>,
    signal_number: Option<i32>,
    pid: Option<u32>,
    cancel_requested: bool,
    logs: Arc<LogRing>,
    finished: Arc<AtomicBool>,
}

impl Job {
    fn new(job_id: String, argv: Vec<String>, cwd: String, timeout_ms: u64) -> Self {
        Self {
            job_id,
            argv,
            cwd,
            timeout_ms,
            created_at: now_ms(),
            state: "queued".into(),
            started_at: None,
            finished_at: None,
            exit_code: None,
            signal_number: None,
            pid: None,
            cancel_requested: false,
            logs: Arc::new(LogRing::new()),
            finished: Arc::new(AtomicBool::new(false)),
        }
    }
}

pub struct JobEngine {
    files: Arc<WorkspaceFiles>,
    job_uid: u32,
    job_gid: u32,
    jobs: Arc<Mutex<HashMap<String, Arc<Mutex<Job>>>>>,
    order: Arc<Mutex<Vec<String>>>,
}

impl JobEngine {
    pub fn new(files: Arc<WorkspaceFiles>, job_uid: u32, job_gid: u32) -> Self {
        Self {
            files,
            job_uid,
            job_gid,
            jobs: Arc::new(Mutex::new(HashMap::new())),
            order: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn start(&self, request: &Value) -> Result<Value, ControlError> {
        let job_id = validate_job_id(&request["jobId"])?;
        let argv_val = &request["argv"];
        let argv_arr = argv_val
            .as_array()
            .ok_or_else(|| ControlError::invalid_request("argv must be an array"))?;
        if argv_arr.is_empty() || argv_arr.len() > 64 {
            return Err(ControlError::invalid_request(
                "argv must contain between 1 and 64 arguments",
            ));
        }
        let mut validated_argv = Vec::with_capacity(argv_arr.len());
        let mut total_argv = 0usize;
        for arg in argv_arr {
            let s = arg.as_str().ok_or_else(|| {
                ControlError::invalid_request("argv contains an invalid argument")
            })?;
            if s.is_empty() || s.contains('\0') {
                return Err(ControlError::invalid_request(
                    "argv contains an invalid argument",
                ));
            }
            let size = s.len();
            if size > 4096 {
                return Err(ControlError::limit_exceeded(
                    "argv contains an oversized argument",
                ));
            }
            total_argv += size;
            if total_argv > 32 * 1024 {
                return Err(ControlError::limit_exceeded(
                    "argv exceeds the aggregate size limit",
                ));
            }
            validated_argv.push(s.to_string());
        }
        let cwd_parts = validate_workspace_directory(&request["cwd"])?;
        let cwd = if cwd_parts.is_empty() {
            ".".to_string()
        } else {
            cwd_parts.join("/")
        };
        let timeout_ms = validate_integer(
            &request["timeoutMs"],
            1000,
            MAX_JOB_TIMEOUT_MS as i64,
            "job timeout",
        )? as u64;
        let user_env = validate_environment(&request["environment"])?;

        // Check limits before inserting
        {
            let jobs = self.jobs.lock().unwrap();
            if jobs.contains_key(&job_id) {
                return Err(ControlError::conflict("job id already exists"));
            }
            let active = jobs
                .values()
                .filter(|j| {
                    let job = j.lock().unwrap();
                    !is_terminal(&job.state)
                })
                .count();
            if active >= MAX_ACTIVE_JOBS {
                return Err(ControlError::limit_exceeded(
                    "workspace already has the maximum number of active jobs",
                ));
            }
        }

        // Prune terminal jobs
        self.prune_terminal_jobs();

        {
            let jobs = self.jobs.lock().unwrap();
            if jobs.len() >= MAX_RETAINED_JOBS {
                return Err(ControlError::limit_exceeded(
                    "workspace has too many retained jobs",
                ));
            }
        }

        let cwd_fd = self.files.open_job_cwd(&Value::String(cwd.clone()))?;
        let job = Arc::new(Mutex::new(Job::new(
            job_id.clone(),
            validated_argv.clone(),
            cwd.clone(),
            timeout_ms,
        )));
        let launcher = self.launcher_argv(&validated_argv);

        // Build environment
        let env = self.job_environment(&user_env);

        // Spawn process
        let cwd_path = format!("/proc/self/fd/{}", cwd_fd);

        let mut command = std::process::Command::new(&launcher[0]);
        command.args(&launcher[1..]);
        command.current_dir(&cwd_path);
        command.env_clear();
        for (k, v) in &env {
            command.env(k, v);
        }
        command.stdin(std::process::Stdio::null());
        command.stdout(std::process::Stdio::piped());
        command.stderr(std::process::Stdio::piped());

        // Keep cwd_fd alive across exec
        use std::os::unix::process::CommandExt;
        let cwd_fd_for_pre_exec = cwd_fd;
        unsafe {
            command.pre_exec(move || {
                // Clear CLOEXEC so cwd_fd survives exec
                let flags = libc::fcntl(cwd_fd_for_pre_exec, libc::F_GETFD);
                if flags >= 0 {
                    libc::fcntl(
                        cwd_fd_for_pre_exec,
                        libc::F_SETFD,
                        flags & !libc::FD_CLOEXEC,
                    );
                }
                // Create new session for process-group isolation
                libc::setsid();
                Ok(())
            });
        }

        let child = match command.spawn() {
            Ok(c) => c,
            Err(e) => {
                unsafe {
                    libc::close(cwd_fd);
                }
                {
                    let mut job_guard = job.lock().unwrap();
                    job_guard.state = "failed".into();
                    job_guard.finished_at = Some(now_ms());
                    let msg = format!("bloom job launch failed: {e}\n");
                    job_guard.logs.append(msg.as_bytes());
                    job_guard.finished.store(true, Ordering::SeqCst);
                }
                let status = self.status_of(&job, 0, MAX_LOG_CHUNK_BYTES);
                // Insert the failed job so status() can find it
                self.jobs
                    .lock()
                    .unwrap()
                    .insert(job_id.clone(), job.clone());
                self.order.lock().unwrap().push(job_id.clone());
                return Ok(status);
            }
        };

        let pid = child.id();
        let mut stdout = child.stdout;
        let mut stderr = child.stderr;

        {
            let mut job_guard = job.lock().unwrap();
            job_guard.started_at = Some(now_ms());
            job_guard.state = "running".into();
            job_guard.pid = Some(pid);
        }

        // Insert into table
        self.jobs
            .lock()
            .unwrap()
            .insert(job_id.clone(), job.clone());
        self.order.lock().unwrap().push(job_id.clone());

        // Spawn concurrent log-streaming + wait thread.
        // The stdout reader runs concurrently with the waitpid poller so that
        // logs appear in real-time (job.status callers can see output while the
        // job is still running).
        let logs_for_capture = job.lock().unwrap().logs.clone();
        let job_for_wait = job.clone();
        let timeout = timeout_ms;
        std::thread::spawn(move || {
            // Take ownership of stdout so we can read from it
            let mut stdout = stdout;

            // Set both pipes to non-blocking
            if let Some(ref s) = stdout {
                let fd = s.as_raw_fd();
                unsafe {
                    let flags = libc::fcntl(fd, libc::F_GETFL);
                    libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                }
            }
            if let Some(ref s) = stderr {
                let fd = s.as_raw_fd();
                unsafe {
                    let flags = libc::fcntl(fd, libc::F_GETFL);
                    libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                }
            }

            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout);
            let mut timed_out = false;
            let mut status: libc::c_int = 0;
            let mut reaped = false;

            // Helper to drain a non-blocking pipe into the log buffer
            fn drain_nonblocking<R: Read>(pipe: &mut Option<R>, logs: &LogRing) {
                if let Some(ref mut out) = pipe {
                    let mut buf = [0u8; 16 * 1024];
                    loop {
                        match out.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => logs.append(&buf[..n]),
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(_) => break,
                        }
                    }
                }
            }
            fn drain_blocking<R: Read>(pipe: &mut Option<R>, logs: &LogRing) {
                if let Some(ref mut out) = pipe {
                    let mut buf = [0u8; 16 * 1024];
                    loop {
                        match out.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => logs.append(&buf[..n]),
                        }
                    }
                }
            }

            loop {
                // Drain any available stdout and stderr (non-blocking)
                drain_nonblocking(&mut stdout, &logs_for_capture);
                drain_nonblocking(&mut stderr, &logs_for_capture);

                // Check if child exited
                if !reaped {
                    let rc = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
                    if rc == pid as i32 {
                        reaped = true;
                    } else if rc < 0 {
                        reaped = true;
                        status = 0;
                    }
                }

                if reaped {
                    // Final drain of stdout and stderr
                    drain_blocking(&mut stdout, &logs_for_capture);
                    drain_blocking(&mut stderr, &logs_for_capture);
                    break;
                }

                // Check timeout
                if std::time::Instant::now() >= deadline {
                    timed_out = true;
                    signal_group(pid, libc::SIGTERM);
                    // Wait briefly for graceful exit
                    for _ in 0..100 {
                        let rc = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
                        if rc == pid as i32 || rc < 0 {
                            reaped = true;
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    if !reaped {
                        // Force kill
                        signal_group(pid, libc::SIGKILL);
                        unsafe {
                            libc::waitpid(pid as i32, &mut status, 0);
                        }
                        reaped = true;
                    }
                    // Final drain after timeout kill
                    drain_blocking(&mut stdout, &logs_for_capture);
                    drain_blocking(&mut stderr, &logs_for_capture);
                    break;
                }

                std::thread::sleep(std::time::Duration::from_millis(10));
            }

            // Determine terminal state
            let cancel_requested = job_for_wait.lock().unwrap().cancel_requested;
            let (state, exit_code, signal) = if timed_out && !cancel_requested {
                ("timed_out".into(), None, None)
            } else if cancel_requested {
                ("cancelled".into(), None, None)
            } else if libc::WIFEXITED(status) {
                let code = libc::WEXITSTATUS(status);
                if code == 0 {
                    ("succeeded".into(), Some(code), None)
                } else {
                    ("failed".into(), Some(code), None)
                }
            } else if libc::WIFSIGNALED(status) {
                ("failed".into(), None, Some(libc::WTERMSIG(status)))
            } else {
                ("failed".into(), None, None)
            };

            let mut job_guard = job_for_wait.lock().unwrap();
            job_guard.finished_at = Some(now_ms());
            job_guard.state = state;
            if let Some(sig) = signal {
                job_guard.signal_number = Some(sig);
            } else {
                job_guard.exit_code = exit_code;
            }
            job_guard.finished.store(true, Ordering::SeqCst);
        });

        let status = self.status_of(&job, 0, MAX_LOG_CHUNK_BYTES);
        unsafe {
            libc::close(cwd_fd);
        }
        Ok(status)
    }

    pub fn status(&self, request: &Value) -> Result<Value, ControlError> {
        let job_id = validate_job_id(&request["jobId"])?;
        let log_offset =
            validate_integer(&request["logOffset"], 0, 2i64.pow(53) - 1, "log cursor")? as u64;
        let max_bytes = validate_integer(
            &request["maxBytes"],
            1,
            MAX_LOG_CHUNK_BYTES as i64,
            "log read size",
        )? as usize;
        let job = {
            let jobs = self.jobs.lock().unwrap();
            jobs.get(&job_id)
                .cloned()
                .ok_or_else(|| ControlError::not_found("job does not exist"))?
        };
        Ok(self.status_of(&job, log_offset, max_bytes))
    }

    pub fn cancel(&self, request: &Value) -> Result<Value, ControlError> {
        let job_id = validate_job_id(&request["jobId"])?;
        let job = {
            let jobs = self.jobs.lock().unwrap();
            jobs.get(&job_id)
                .cloned()
                .ok_or_else(|| ControlError::not_found("job does not exist"))?
        };
        let mut job_guard = job.lock().unwrap();
        if is_terminal(&job_guard.state) {
            return Ok(self.status_of_inner(&job_guard, job_guard.logs.end_offset(), 1));
        }
        let pid = match job_guard.pid {
            Some(p) => p,
            None => return Err(ControlError::conflict("job has not started")),
        };
        let first_request = !job_guard.cancel_requested;
        job_guard.cancel_requested = true;
        // SIGTERM the process group
        signal_group(pid, libc::SIGTERM);
        if first_request {
            let job_for_cancel = job.clone();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs_f64(JOB_KILL_GRACE_SECONDS));
                let guard = job_for_cancel.lock().unwrap();
                if let Some(pid) = guard.pid {
                    signal_group(pid, libc::SIGKILL);
                }
            });
        }
        Ok(self.status_of_inner(&job_guard, job_guard.logs.end_offset(), 1))
    }

    pub fn close(&self) {
        let jobs = self.jobs.lock().unwrap();
        for job_arc in jobs.values() {
            let job_guard = job_arc.lock().unwrap();
            if !is_terminal(&job_guard.state) {
                if let Some(pid) = job_guard.pid {
                    signal_group(pid, libc::SIGKILL);
                }
            }
        }
    }

    fn status_of(&self, job: &Arc<Mutex<Job>>, log_offset: u64, max_bytes: usize) -> Value {
        let job_guard = job.lock().unwrap();
        self.status_of_inner(&job_guard, log_offset, max_bytes)
    }

    fn status_of_inner(&self, job: &Job, log_offset: u64, max_bytes: usize) -> Value {
        let logs_val = job
            .logs
            .slice(log_offset, max_bytes, is_terminal(&job.state))
            .unwrap_or_else(|e| json!({"error": e.message}));
        json!({
            "jobId": job.job_id,
            "state": job.state,
            "createdAt": job.created_at,
            "startedAt": job.started_at,
            "finishedAt": job.finished_at,
            "exitCode": job.exit_code,
            "signal": job.signal_number,
            "timeoutMs": job.timeout_ms,
            "logs": logs_val,
        })
    }

    fn prune_terminal_jobs(&self) {
        let mut jobs = self.jobs.lock().unwrap();
        let mut order = self.order.lock().unwrap();
        while jobs.len() >= MAX_RETAINED_JOBS {
            let terminal_id = order
                .iter()
                .find(|id| {
                    if let Some(j) = jobs.get(*id) {
                        let g = j.lock().unwrap();
                        is_terminal(&g.state)
                    } else {
                        false
                    }
                })
                .cloned();
            match terminal_id {
                Some(id) => {
                    jobs.remove(&id);
                    order.retain(|x| *x != id);
                }
                None => break,
            }
        }
    }

    fn launcher_argv(&self, user_argv: &[String]) -> Vec<String> {
        let prlimit = which("prlimit").unwrap_or_else(|| "/usr/bin/prlimit".into());
        let setpriv = which("setpriv").unwrap_or_else(|| "/usr/bin/setpriv".into());
        let mut cmd = vec![
            prlimit,
            "--nofile=64:64".into(),
            format!("--fsize={}:{}", MAX_JOB_FILE_BYTES, MAX_JOB_FILE_BYTES),
            "--core=0:0".into(),
        ];
        if unsafe { libc::geteuid() } == 0 {
            cmd.push(format!(
                "--nproc={}:{}",
                MAX_JOB_PROCESSES, MAX_JOB_PROCESSES
            ));
        }
        cmd.push("--".into());
        cmd.push(setpriv);
        cmd.push("--no-new-privs".into());
        cmd.push("--pdeathsig=SIGKILL".into());
        if unsafe { libc::geteuid() } == 0 {
            cmd.extend([
                "--bounding-set=-all".into(),
                "--inh-caps=-all".into(),
                "--ambient-caps=-all".into(),
                format!("--reuid={}", self.job_uid),
                format!("--regid={}", self.job_gid),
                "--clear-groups".into(),
            ]);
        }
        cmd.push("--".into());
        cmd.extend(user_argv.iter().cloned());
        cmd
    }

    fn job_environment(&self, user_env: &BTreeMap<String, String>) -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();
        env.insert("HOME".into(), "/workspace".into());
        env.insert("USER".into(), "workspace".into());
        env.insert("LOGNAME".into(), "workspace".into());
        env.insert("SHELL".into(), "/bin/bash".into());
        // Inherit PATH from parent so test/toolchain binaries are discoverable.
        // In production, the guest image sets PATH appropriately.
        let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".into());
        env.insert("PATH".into(), path);
        env.insert("TMPDIR".into(), "/workspace/.tmp".into());
        env.insert("LANG".into(), "C.UTF-8".into());

        for name in SYSTEM_PROXY_ENV {
            if let Ok(value) = std::env::var(name) {
                if !value.is_empty()
                    && value.len() <= 2048
                    && !value.contains('@')
                    && !value.contains('\0')
                {
                    env.insert(name.to_string(), value);
                }
            }
        }
        for name in &["SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS"] {
            if let Ok(value) = std::env::var(name) {
                if value.starts_with('/') && !value.contains('\0') && value.len() <= 1024 {
                    env.insert(name.to_string(), value);
                }
            }
        }
        for (k, v) in user_env {
            env.insert(k.clone(), v.clone());
        }
        env
    }
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

fn signal_group(pid: u32, sig: libc::c_int) {
    // killpg expects a negative pid for process group
    unsafe {
        // The pid is already a session leader (we called setsid in pre_exec)
        // So killpg(pid) = kill(-pid, sig)
        libc::kill(-(pid as i32), sig);
    }
}
