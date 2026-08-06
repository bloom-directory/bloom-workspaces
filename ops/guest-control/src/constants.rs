//! Compile-time constants matching the Python implementation.

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_FRAME_BYTES: usize = 384 * 1024;
pub const MAX_FILE_CHUNK_BYTES: usize = 256 * 1024;
pub const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_LOG_CHUNK_BYTES: usize = 256 * 1024;
pub const MAX_LOG_BYTES: usize = 1024 * 1024;
pub const MAX_LIST_ENTRIES: usize = 1000;
pub const MAX_SCAN_ENTRIES: usize = 20_000;
pub const MAX_ACTIVE_JOBS: usize = 2;
pub const MAX_RETAINED_JOBS: usize = 64;
pub const MAX_JOB_PROCESSES: u64 = 64;
pub const MAX_JOB_FILE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_JOB_TIMEOUT_MS: u64 = 2 * 60 * 60 * 1000;
pub const JOB_KILL_GRACE_SECONDS: f64 = 1.0;
pub const BLOOM_SOCKET_PATH: &str = "/workspace/.bloom/run/bloom.sock";
pub const MAX_OUTBOX_PLAN_BYTES: usize = 64 * 1024;
pub const MAX_OUTBOX_CHAINS: usize = 16;
pub const MAX_OUTBOX_PENDING: usize = 32;

/// AF_VSOCK constant on Linux (40).
pub const AF_VSOCK: libc::c_int = 40;
/// VMADDR_CID_ANY
pub const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;

/// Environment variables passed through to jobs.
pub const USER_ENV_EXACT: &[&str] = &[
    "CI",
    "DEBUG",
    "FORCE_COLOR",
    "LANG",
    "LC_ALL",
    "LOG_LEVEL",
    "NODE_ENV",
    "NO_COLOR",
    "PYTHONUNBUFFERED",
    "RUST_BACKTRACE",
    "RUST_LOG",
    "TERM",
    "TZ",
];

pub const USER_ENV_PREFIXES: &[&str] = &["APP_", "JOB_", "TEST_"];

pub const SYSTEM_PROXY_ENV: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
];
