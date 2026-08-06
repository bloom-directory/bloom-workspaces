//! Request validation — mirrors the Python validate_* functions exactly.

use crate::constants::*;
use crate::error::ControlError;
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;

pub static REQUEST_ID: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9_-]{1,64}$").unwrap());
pub static ENV_NAME: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$").unwrap());
pub static EVM_ADDRESS: Lazy<Regex> = Lazy::new(|| Regex::new(r"^0x[0-9a-f]{40}$").unwrap());
pub static SSH_CA_PUBLIC_KEY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$").unwrap());
pub static WORKSPACE_ID: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$").unwrap()
});

/// Operation → expected field set.
pub fn expected_fields(operation: &str) -> Option<Vec<&'static str>> {
    let base = vec!["version", "id", "operation"];
    let mut fields = match operation {
        "hello" => base,
        "fs.list" => {
            let mut v = base;
            v.push("path");
            v
        }
        "fs.read" => {
            let mut v = base;
            v.extend_from_slice(&["path", "offset", "maxBytes"]);
            v
        }
        "fs.write" => {
            let mut v = base;
            v.extend_from_slice(&["path", "offset", "data", "truncate"]);
            v
        }
        "fs.delete" => {
            let mut v = base;
            v.extend_from_slice(&["path", "recursive"]);
            v
        }
        "job.start" => {
            let mut v = base;
            v.extend_from_slice(&["jobId", "argv", "cwd", "environment", "timeoutMs"]);
            v
        }
        "job.status" => {
            let mut v = base;
            v.extend_from_slice(&["jobId", "logOffset", "maxBytes"]);
            v
        }
        "job.cancel" => {
            let mut v = base;
            v.push("jobId");
            v
        }
        "bloom.status" => base,
        "connections.configure" => {
            let mut v = base;
            v.extend_from_slice(&["workspaceId", "wallet", "caPublicKey", "nfs"]);
            v
        }
        "ceremony.pending" => base,
        _ => return None,
    };
    fields.sort();
    Some(fields)
}

pub fn validate_request(raw: &Value) -> Result<(), ControlError> {
    let obj = raw
        .as_object()
        .ok_or_else(|| ControlError::invalid_request("request must be an object"))?;
    let version = obj.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
    if version != PROTOCOL_VERSION as u64 {
        return Err(ControlError::invalid_request(
            "unsupported guest protocol version",
        ));
    }
    let id = obj.get("id").and_then(|v| v.as_str()).unwrap_or("");
    if !REQUEST_ID.is_match(id) {
        return Err(ControlError::invalid_request("invalid request id"));
    }
    let operation = obj.get("operation").and_then(|v| v.as_str()).unwrap_or("");
    if operation.is_empty() {
        return Err(ControlError::invalid_request("operation is required"));
    }
    let expected = expected_fields(operation)
        .ok_or_else(|| ControlError::invalid_request("unknown guest operation"))?;
    let mut actual: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
    actual.sort();
    if actual != expected {
        return Err(ControlError::invalid_request(
            "request fields do not match the operation contract",
        ));
    }
    Ok(())
}

/// Validate and split a relative workspace path. Returns the path components.
pub fn validate_relative_path(value: &Value) -> Result<Vec<String>, ControlError> {
    let s = value
        .as_str()
        .ok_or_else(|| ControlError::invalid_request("workspace path must be a string"))?;
    let byte_len = s.len();
    if byte_len == 0 || byte_len > 1024 {
        return Err(ControlError::invalid_request(
            "workspace path has an invalid length",
        ));
    }
    if s.contains('\0') || s.contains('\\') {
        return Err(ControlError::invalid_request(
            "workspace path contains forbidden characters",
        ));
    }
    if s.starts_with('/') || s.ends_with('/') {
        return Err(ControlError::invalid_request(
            "workspace path must be relative",
        ));
    }
    // Check normalized path equals original (no .. or . components)
    let parts: Vec<&str> = s.split('/').collect();
    for part in &parts {
        if *part == "" || *part == "." || *part == ".." {
            return Err(ControlError::invalid_request("invalid workspace path"));
        }
    }
    Ok(parts.iter().map(|s| s.to_string()).collect())
}

/// Like validate_relative_path but "." is allowed (means root).
pub fn validate_workspace_directory(value: &Value) -> Result<Vec<String>, ControlError> {
    if value.as_str() == Some(".") {
        return Ok(vec![]);
    }
    validate_relative_path(value)
}

pub fn validate_integer(
    value: &Value,
    min: i64,
    max: i64,
    label: &str,
) -> Result<i64, ControlError> {
    let n = value
        .as_i64()
        .ok_or_else(|| ControlError::invalid_request(format!("{label} must be an integer")))?;
    // Reject booleans (JSON true/false become null via as_i64, so this is implicitly handled)
    if n < min || n > max {
        return Err(ControlError::invalid_request(format!(
            "{label} is outside the allowed range"
        )));
    }
    Ok(n)
}

pub fn validate_job_id(value: &Value) -> Result<String, ControlError> {
    let s = value
        .as_str()
        .ok_or_else(|| ControlError::invalid_request("job id must be a UUID"))?;
    // Parse as UUID and check canonical form
    let parsed =
        parse_uuid(s).ok_or_else(|| ControlError::invalid_request("job id must be a UUID"))?;
    if parsed != s {
        return Err(ControlError::invalid_request(
            "job id must be a canonical lowercase UUID",
        ));
    }
    Ok(s.to_string())
}

fn parse_uuid(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    if bytes.len() != 36 {
        return None;
    }
    if bytes[8] != b'-' || bytes[13] != b'-' || bytes[18] != b'-' || bytes[23] != b'-' {
        return None;
    }
    for i in 0..36 {
        if i == 8 || i == 13 || i == 18 || i == 23 {
            continue;
        }
        if !bytes[i].is_ascii_hexdigit() {
            return None;
        }
    }
    // Check version nibble (position 14) is '4'
    if bytes[14] != b'4' {
        return None;
    }
    // Check variant nibble (position 19) is 8/9/a/b
    match bytes[19] {
        b'8' | b'9' | b'a' | b'b' => {}
        _ => return None,
    }
    Some(s.to_lowercase())
}

pub fn validate_environment(
    value: &Value,
) -> Result<std::collections::BTreeMap<String, String>, ControlError> {
    let obj = value
        .as_object()
        .ok_or_else(|| ControlError::invalid_request("job environment must be an object"))?;
    if obj.len() > 64 {
        return Err(ControlError::invalid_request(
            "job environment must contain at most 64 variables",
        ));
    }
    let mut result = std::collections::BTreeMap::new();
    let mut total = 0usize;
    for (name, item) in obj {
        if !ENV_NAME.is_match(name) {
            return Err(ControlError::invalid_request(
                "job environment contains an invalid name",
            ));
        }
        let allowed = USER_ENV_EXACT.contains(&name.as_str())
            || USER_ENV_PREFIXES.iter().any(|p| name.starts_with(p));
        if !allowed {
            return Err(ControlError::permission_denied(format!(
                "job environment variable is not allowlisted: {name}"
            )));
        }
        let val = item.as_str().ok_or_else(|| {
            ControlError::invalid_request(format!("job environment value is invalid: {name}"))
        })?;
        if val.contains('\0') {
            return Err(ControlError::invalid_request(format!(
                "job environment value is invalid: {name}"
            )));
        }
        let encoded_len = val.len();
        if encoded_len > 8192 {
            return Err(ControlError::limit_exceeded(format!(
                "job environment value is too large: {name}"
            )));
        }
        total += name.len() + encoded_len;
        if total > 32 * 1024 {
            return Err(ControlError::limit_exceeded(
                "job environment exceeds the aggregate size limit",
            ));
        }
        result.insert(name.clone(), val.to_string());
    }
    Ok(result)
}
