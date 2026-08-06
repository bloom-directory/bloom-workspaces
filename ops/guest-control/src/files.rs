//! Workspace file operations with path-traversal-safe directory walking.

use crate::constants::*;
use crate::error::{from_io_error, ControlError};
use crate::validate::{validate_relative_path, validate_workspace_directory};
use base64::Engine;
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::io::RawFd;
use std::path::Path;
use std::sync::Mutex;

static EVM_ADDRESS_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^0x[0-9a-f]{40}$").unwrap());

pub struct WorkspaceFiles {
    root: std::path::PathBuf,
    root_fd: RawFd,
    quota_bytes: u64,
    owner_uid: u32,
    owner_gid: u32,
    write_lock: Mutex<()>,
    _root_file: std::fs::File, // keeps root_fd alive
}

impl WorkspaceFiles {
    pub fn new(
        root: &Path,
        quota_bytes: u64,
        owner_uid: u32,
        owner_gid: u32,
    ) -> Result<Self, String> {
        let canonical = root
            .canonicalize()
            .map_err(|e| format!("workspace root does not exist: {e}"))?;
        let meta = std::fs::symlink_metadata(&canonical)
            .map_err(|e| format!("cannot stat workspace root: {e}"))?;
        let mode = meta.permissions().mode();
        if mode & libc::S_IFMT as u32 == libc::S_IFLNK as u32 {
            return Err("workspace root must not be a symlink".into());
        }
        if !canonical.is_dir() {
            return Err("workspace root must be a directory".into());
        }
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(&canonical)
            .map_err(|e| format!("unsafe or unavailable workspace root: {e}"))?;

        let root_fd = file.as_raw_fd();
        Ok(Self {
            root: canonical,
            root_fd,
            quota_bytes,
            owner_uid,
            owner_gid,
            write_lock: Mutex::new(()),
            _root_file: file,
        })
    }

    pub fn close(&self) {
        // root_fd is closed when _root_file is dropped
    }

    pub fn prepare_job_tmp(&self) -> Result<(), ControlError> {
        let fd = self.open_directory(&[".tmp".to_string()], true)?;
        unsafe {
            libc::fchmod(fd, 0o700);
            if unsafe { libc::geteuid() } == 0 {
                unsafe {
                    libc::fchown(fd, self.owner_uid, self.owner_gid);
                }
            }
            libc::close(fd);
        }
        Ok(())
    }

    fn open_directory(&self, parts: &[String], create: bool) -> Result<RawFd, ControlError> {
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW;
        // Use openat(".", root_fd) instead of dup(root_fd) so each call gets an
        // independent directory handle with its own read position. dup() shares
        // the open file description, so readdir in one consumer advances the
        // position for all copies.
        let c_dot = std::ffi::CString::new(".").unwrap();
        let mut current = unsafe { libc::openat(self.root_fd, c_dot.as_ptr(), flags) };
        if current < 0 {
            return Err(from_io_error(&std::io::Error::last_os_error()));
        }
        for part in parts {
            let c_part = std::ffi::CString::new(part.as_str()).unwrap();
            if create {
                unsafe {
                    if libc::mkdirat(current, c_part.as_ptr(), 0o700) == 0 {
                        if unsafe { libc::geteuid() } == 0 {
                            libc::fchownat(
                                current,
                                c_part.as_ptr(),
                                self.owner_uid,
                                self.owner_gid,
                                libc::AT_SYMLINK_NOFOLLOW,
                            );
                        }
                    }
                }
            }
            let next = unsafe { libc::openat(current, c_part.as_ptr(), flags) };
            if next < 0 {
                unsafe {
                    libc::close(current);
                }
                return Err(from_io_error(&std::io::Error::last_os_error()));
            }
            unsafe {
                libc::close(current);
            }
            current = next;
        }
        Ok(current)
    }

    fn open_file(
        &self,
        parts: &[String],
        flags: i32,
        mode: u32,
        create_parents: bool,
    ) -> Result<RawFd, ControlError> {
        if parts.len() < 2 {
            return Err(ControlError::invalid_request(
                "file path must include a parent directory",
            ));
        }
        let parent = self.open_directory(&parts[..parts.len() - 1], create_parents)?;
        let c_name = std::ffi::CString::new(parts[parts.len() - 1].as_str()).unwrap();
        let fd = unsafe {
            libc::openat(
                parent,
                c_name.as_ptr(),
                flags | libc::O_NOFOLLOW,
                mode as libc::c_uint,
            )
        };
        unsafe {
            libc::close(parent);
        }
        if fd < 0 {
            return Err(from_io_error(&std::io::Error::last_os_error()));
        }
        Ok(fd)
    }

    pub fn list(&self, path: &Value) -> Result<Value, ControlError> {
        let parts = validate_workspace_directory(path)?;
        let dir = self.open_directory(&parts, false)?;
        let c_dot = std::ffi::CString::new(".").unwrap();
        let result = (|| -> Result<Value, ControlError> {
            let mut entries = vec![];
            unsafe {
                let dirp = libc::fdopendir(libc::openat(
                    dir,
                    c_dot.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY,
                ));
                if dirp.is_null() {
                    return Err(ControlError::internal("fdopendir failed"));
                }
                loop {
                    let entry_ptr = libc::readdir(dirp);
                    if entry_ptr.is_null() {
                        break;
                    }
                    let name = std::ffi::CStr::from_ptr((*entry_ptr).d_name.as_ptr())
                        .to_string_lossy()
                        .to_string();
                    if name == "." || name == ".." {
                        continue;
                    }
                    entries.push(name);
                }
                libc::closedir(dirp);
            }
            entries.sort();
            if entries.len() > MAX_LIST_ENTRIES {
                return Err(ControlError::limit_exceeded(
                    "directory contains too many entries",
                ));
            }
            let mut result_entries = Vec::with_capacity(entries.len());
            for name in &entries {
                let c_name = std::ffi::CString::new(name.as_str()).unwrap();
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                let rc = unsafe {
                    libc::fstatat(dir, c_name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW)
                };
                if rc != 0 {
                    continue;
                }
                let kind = if (st.st_mode & libc::S_IFMT as libc::mode_t)
                    == libc::S_IFLNK as libc::mode_t
                {
                    "symlink"
                } else if (st.st_mode & libc::S_IFMT as libc::mode_t)
                    == libc::S_IFDIR as libc::mode_t
                {
                    "directory"
                } else {
                    "file"
                };
                let size = if (st.st_mode & libc::S_IFMT as libc::mode_t)
                    == libc::S_IFREG as libc::mode_t
                {
                    st.st_size as u64
                } else {
                    0
                };
                let mut path_str = parts.join("/");
                if !path_str.is_empty() {
                    path_str.push('/');
                }
                path_str.push_str(name);
                result_entries.push(json!({
                    "path": path_str,
                    "type": kind,
                    "size": size,
                    "modifiedAt": (st.st_mtime as u64) * 1000,
                }));
            }
            Ok(json!({ "files": result_entries }))
        })();
        unsafe {
            libc::close(dir);
        }
        result
    }

    pub fn read(
        &self,
        path: &Value,
        offset: &Value,
        max_bytes: &Value,
    ) -> Result<Value, ControlError> {
        let parts = validate_relative_path(path)?;
        let start =
            crate::validate::validate_integer(offset, 0, MAX_FILE_BYTES as i64, "file offset")?
                as i64;
        let limit = crate::validate::validate_integer(
            max_bytes,
            1,
            MAX_FILE_CHUNK_BYTES as i64,
            "file read size",
        )? as usize;
        let fd = self.open_file(&parts, libc::O_RDONLY, 0, false)?;
        let result = (|| -> Result<Value, ControlError> {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(fd, &mut st) } != 0 {
                return Err(ControlError::internal("fstat failed"));
            }
            if (st.st_mode & libc::S_IFMT as libc::mode_t) != libc::S_IFREG as libc::mode_t {
                return Err(ControlError::invalid_request(
                    "download path is not a regular file",
                ));
            }
            if st.st_size > MAX_FILE_BYTES as i64 {
                return Err(ControlError::limit_exceeded(
                    "file exceeds the download limit",
                ));
            }
            if start > st.st_size {
                return Err(ControlError::invalid_request(
                    "file offset exceeds the file size",
                ));
            }
            let mut buf = vec![0u8; limit];
            let n = unsafe { libc::pread(fd, buf.as_mut_ptr() as *mut _, limit, start as i64) };
            if n < 0 {
                return Err(ControlError::internal("pread failed"));
            }
            buf.truncate(n as usize);
            let b64 = base64::engine::general_purpose::STANDARD.encode(&buf);
            let next = start + n as i64;
            Ok(json!({
                "path": parts.join("/"),
                "offset": start,
                "nextOffset": next,
                "size": st.st_size,
                "eof": next >= st.st_size,
                "data": b64,
            }))
        })();
        unsafe {
            libc::close(fd);
        }
        result
    }

    pub fn write(
        &self,
        path: &Value,
        offset: &Value,
        encoded: &Value,
        truncate: &Value,
    ) -> Result<Value, ControlError> {
        let parts = validate_relative_path(path)?;
        let start =
            crate::validate::validate_integer(offset, 0, MAX_FILE_BYTES as i64, "file offset")?
                as i64;
        let encoded_str = encoded
            .as_str()
            .ok_or_else(|| ControlError::invalid_request("file payload must be base64"))?;
        let do_truncate = truncate
            .as_bool()
            .ok_or_else(|| ControlError::invalid_request("truncate must be boolean"))?;
        if do_truncate && start != 0 {
            return Err(ControlError::invalid_request(
                "a truncating write must begin at offset zero",
            ));
        }
        let chunk = base64::engine::general_purpose::STANDARD
            .decode(encoded_str)
            .map_err(|_| ControlError::invalid_request("file payload is not canonical base64"))?;
        // Verify canonical encoding
        let re_encoded = base64::engine::general_purpose::STANDARD.encode(&chunk);
        if re_encoded != encoded_str {
            return Err(ControlError::invalid_request(
                "file payload is not canonical base64",
            ));
        }
        if chunk.len() > MAX_FILE_CHUNK_BYTES {
            return Err(ControlError::limit_exceeded(
                "file write chunk is too large",
            ));
        }
        if start + chunk.len() as i64 > MAX_FILE_BYTES as i64 {
            return Err(ControlError::limit_exceeded(
                "file exceeds the upload limit",
            ));
        }
        let _guard = self.write_lock.lock().unwrap();
        let flags = libc::O_WRONLY | libc::O_CREAT;
        let fd = self.open_file(&parts, flags, 0o600, true)?;
        let result = (|| -> Result<Value, ControlError> {
            if unsafe { libc::geteuid() } == 0 {
                unsafe {
                    libc::fchown(fd, self.owner_uid, self.owner_gid);
                }
            }
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(fd, &mut st) } != 0 {
                return Err(ControlError::internal("fstat failed"));
            }
            if (st.st_mode & libc::S_IFMT as libc::mode_t) != libc::S_IFREG as libc::mode_t {
                return Err(ControlError::invalid_request(
                    "upload target is not a regular file",
                ));
            }
            let prior = st.st_size;
            let used = self.directory_bytes()?;
            let resulting_size = if do_truncate {
                (start + chunk.len() as i64).max(0)
            } else {
                (start + chunk.len() as i64).max(prior)
            };
            if used - prior + resulting_size > self.quota_bytes as i64 {
                return Err(ControlError::limit_exceeded(
                    "workspace storage quota exceeded",
                ));
            }
            if do_truncate {
                unsafe {
                    libc::ftruncate(fd, 0);
                }
            }
            let mut written: usize = 0;
            while written < chunk.len() {
                let n = unsafe {
                    libc::pwrite(
                        fd,
                        chunk[written as usize..].as_ptr() as *const _,
                        (chunk.len() - written),
                        (start + written as i64) as i64,
                    )
                };
                if n <= 0 {
                    return Err(ControlError::internal("file write made no progress"));
                }
                written += n as usize;
            }
            unsafe {
                libc::fsync(fd);
            }
            let mut st2: libc::stat = unsafe { std::mem::zeroed() };
            unsafe {
                libc::fstat(fd, &mut st2);
            }
            Ok(json!({
                "path": parts.join("/"),
                "size": st2.st_size,
                "nextOffset": start + chunk.len() as i64,
                "usedBytes": used - prior + resulting_size,
                "quotaBytes": self.quota_bytes,
            }))
        })();
        unsafe {
            libc::close(fd);
        }
        result
    }

    pub fn delete(&self, path: &Value, recursive: &Value) -> Result<Value, ControlError> {
        let parts = validate_relative_path(path)?;
        // recursive must be false (protocol only allows non-recursive single-file delete)
        let do_recursive = recursive.as_bool().unwrap_or(false);
        if do_recursive {
            return Err(ControlError::permission_denied(
                "recursive deletion is not supported",
            ));
        }
        let _guard = self.write_lock.lock().unwrap();
        let parent = self.open_directory(&parts[..parts.len() - 1], false)?;
        let result = (|| -> Result<Value, ControlError> {
            let c_name = std::ffi::CString::new(parts[parts.len() - 1].as_str()).unwrap();
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstatat(parent, c_name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) }
                != 0
            {
                return Err(from_io_error(&std::io::Error::last_os_error()));
            }
            if (st.st_mode & libc::S_IFMT as libc::mode_t) != libc::S_IFREG as libc::mode_t {
                return Err(ControlError::invalid_request(
                    "delete path is not a regular file",
                ));
            }
            if unsafe { libc::unlinkat(parent, c_name.as_ptr(), 0) } != 0 {
                return Err(from_io_error(&std::io::Error::last_os_error()));
            }
            let used_after = self.directory_bytes()?;
            Ok(json!({
                "path": parts.join("/"),
                "deleted": true,
                "usedBytes": used_after,
                "quotaBytes": self.quota_bytes,
            }))
        })();
        unsafe {
            libc::close(parent);
        }
        result
    }

    pub fn open_job_cwd(&self, path: &Value) -> Result<RawFd, ControlError> {
        let parts = validate_workspace_directory(path)?;
        self.open_directory(&parts, false)
    }

    pub fn read_small(&self, path: &str, maximum: usize) -> Option<String> {
        let path_val = serde_json::Value::String(path.to_string());
        let parts = validate_relative_path(&path_val).ok()?;
        let fd = self.open_file(&parts, libc::O_RDONLY, 0, false).ok()?;
        let result = (|| -> Option<String> {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(fd, &mut st) } != 0 {
                return None;
            }
            if (st.st_mode & libc::S_IFMT as libc::mode_t) != libc::S_IFREG as libc::mode_t {
                return None;
            }
            if st.st_size > maximum as i64 {
                return None;
            }
            let mut buf = vec![0u8; maximum];
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, maximum) };
            if n < 0 {
                return None;
            }
            buf.truncate(n as usize);
            String::from_utf8(buf).ok().map(|s| s.trim().to_string())
        })();
        unsafe {
            libc::close(fd);
        }
        result
    }

    pub fn watch_identity(&self) -> Option<String> {
        let keystore_fd = self
            .open_directory(&[".bloom".to_string(), "keystore".to_string()], false)
            .ok()?;
        let identity = (|| -> Option<String> {
            // Check keystore has exactly "workspace-login"
            let mut entries = list_dir_entries(keystore_fd)?;
            entries.sort();
            if entries != vec!["workspace-login".to_string()] {
                return None;
            }
            unsafe {
                libc::close(keystore_fd);
            }

            // Check wallet has exactly address, kind, pubkey
            let wallet_fd = self
                .open_directory(
                    &[
                        ".bloom".to_string(),
                        "keystore".to_string(),
                        "workspace-login".to_string(),
                    ],
                    false,
                )
                .ok()?;
            let mut wallet_entries = list_dir_entries(wallet_fd)?;
            wallet_entries.sort();
            if wallet_entries
                != vec![
                    "address".to_string(),
                    "kind".to_string(),
                    "pubkey".to_string(),
                ]
            {
                return None;
            }
            unsafe {
                libc::close(wallet_fd);
            }

            let kind = self.read_small(".bloom/keystore/workspace-login/kind", 256)?;
            let address = self.read_small(".bloom/keystore/workspace-login/address", 256)?;
            let public_key = self.read_small(".bloom/keystore/workspace-login/pubkey", 256)?;
            let normalized = address.to_lowercase();
            if kind != "watch" || public_key != "" || !EVM_ADDRESS_RE.is_match(&normalized) {
                return None;
            }
            Some(normalized)
        })();
        // keystore_fd may already be closed inside the closure
        identity
    }

    fn directory_bytes(&self) -> Result<i64, ControlError> {
        let mut count = 0i64;
        let mut total = 0i64;
        walk_dir_bytes(self.root_fd, &mut count, &mut total, 0)?;
        Ok(total)
    }
}

fn list_dir_entries(fd: RawFd) -> Option<Vec<String>> {
    let mut entries = vec![];
    let c_dot = std::ffi::CString::new(".").unwrap();
    unsafe {
        let dirp = libc::fdopendir(libc::openat(
            fd,
            c_dot.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY,
        ));
        if dirp.is_null() {
            return None;
        }
        loop {
            let entry_ptr = libc::readdir(dirp);
            if entry_ptr.is_null() {
                break;
            }
            let name = std::ffi::CStr::from_ptr((*entry_ptr).d_name.as_ptr())
                .to_string_lossy()
                .to_string();
            if name == "." || name == ".." {
                continue;
            }
            entries.push(name);
        }
        libc::closedir(dirp);
    }
    Some(entries)
}

fn walk_dir_bytes(
    fd: RawFd,
    count: &mut i64,
    total: &mut i64,
    depth: usize,
) -> Result<(), ControlError> {
    if depth > 32 {
        return Ok(());
    }
    let c_dot = std::ffi::CString::new(".").unwrap();
    unsafe {
        let dirp = libc::fdopendir(libc::openat(
            fd,
            c_dot.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY,
        ));
        if dirp.is_null() {
            return Err(ControlError::internal("fdopendir failed"));
        }
        loop {
            let entry_ptr = libc::readdir(dirp);
            if entry_ptr.is_null() {
                break;
            }
            let name = std::ffi::CStr::from_ptr((*entry_ptr).d_name.as_ptr())
                .to_string_lossy()
                .to_string();
            if name == "." || name == ".." {
                continue;
            }
            let c_name = std::ffi::CString::new(name.as_str()).unwrap();
            let mut st: libc::stat = std::mem::zeroed();
            if libc::fstatat(fd, c_name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) != 0 {
                continue;
            }
            let mode = st.st_mode & libc::S_IFMT as libc::mode_t;
            if mode == libc::S_IFREG as libc::mode_t {
                *count += 1;
                if *count > MAX_SCAN_ENTRIES as i64 {
                    libc::closedir(dirp);
                    return Err(ControlError::limit_exceeded(
                        "workspace contains too many files",
                    ));
                }
                *total += st.st_size;
            } else if mode == libc::S_IFDIR as libc::mode_t {
                let child = libc::openat(
                    fd,
                    c_name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                );
                if child >= 0 {
                    let _ = walk_dir_bytes(child, count, total, depth + 1);
                    libc::close(child);
                }
            }
        }
        libc::closedir(dirp);
    }
    Ok(())
}
