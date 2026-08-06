//! Error types matching the Python ControlError.

use std::fmt;

#[derive(Debug, Clone)]
pub struct ControlError {
    pub code: String,
    pub message: String,
}

impl ControlError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
        }
    }

    pub fn invalid_request(msg: impl Into<String>) -> Self {
        Self::new("invalid_request", msg)
    }
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new("not_found", msg)
    }
    pub fn permission_denied(msg: impl Into<String>) -> Self {
        Self::new("permission_denied", msg)
    }
    pub fn limit_exceeded(msg: impl Into<String>) -> Self {
        Self::new("limit_exceeded", msg)
    }
    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::new("conflict", msg)
    }
    pub fn unavailable(msg: impl Into<String>) -> Self {
        Self::new("unavailable", msg)
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new("internal", msg)
    }
}

impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ControlError {}

/// Check an errno and map to appropriate ControlError.
pub fn from_io_error(error: &std::io::Error) -> ControlError {
    let raw = error.raw_os_error().unwrap_or(0);
    let code = match raw {
        libc::ENOENT => "not_found",
        libc::EACCES | libc::EPERM | libc::ELOOP | libc::ENOTDIR => "permission_denied",
        _ => "internal",
    };
    ControlError::new(code, "workspace operation failed")
}
