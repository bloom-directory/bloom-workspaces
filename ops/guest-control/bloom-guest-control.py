#!/usr/bin/env python3
"""Bounded guest-side file, job, and Bloom status service.

The service is intentionally dependency-free.  It accepts the version-1
JSON-line protocol over AF_VSOCK and/or a guest-local Unix socket.  The service
may run as root so jobs cannot signal or ptrace it, but every job is exec'd via
prlimit + setpriv as the unprivileged workspace account with no capabilities
and no-new-privileges.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import errno
import json
import os
import posixpath
import re
import select
import shutil
import signal
import socket
import stat
import subprocess
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, BinaryIO


PROTOCOL_VERSION = 1
MAX_FRAME_BYTES = 384 * 1024
MAX_FILE_CHUNK_BYTES = 256 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_LOG_CHUNK_BYTES = 256 * 1024
MAX_LOG_BYTES = 1024 * 1024
MAX_LIST_ENTRIES = 1000
MAX_SCAN_ENTRIES = 20_000
MAX_ACTIVE_JOBS = 2
MAX_RETAINED_JOBS = 64
MAX_JOB_PROCESSES = 64
MAX_JOB_FILE_BYTES = 64 * 1024 * 1024
MAX_JOB_TIMEOUT_MS = 2 * 60 * 60 * 1000
JOB_KILL_GRACE_SECONDS = 1.0
BLOOM_SOCKET_PATH = os.environ.get("BLOOM_IPC_SOCKET", "/workspace/.bloom/run/bloom.sock")
MAX_OUTBOX_PLAN_BYTES = 64 * 1024
MAX_OUTBOX_CHAINS = 16
MAX_OUTBOX_PENDING = 32

REQUEST_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
EVM_ADDRESS = re.compile(r"^0x[0-9a-f]{40}$")
SSH_CA_PUBLIC_KEY = re.compile(r"^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$")
WORKSPACE_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
USER_ENV_EXACT = frozenset(
    {
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
    }
)
USER_ENV_PREFIXES = ("APP_", "JOB_", "TEST_")
SYSTEM_PROXY_ENV = ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy")


class ControlError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def now_ms() -> int:
    return int(time.time() * 1000)


def require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise ControlError(code, message)


def require_exact_keys(value: dict[str, Any], expected: set[str]) -> None:
    require(set(value) == expected, "invalid_request", "request fields do not match the operation contract")


def validate_request(raw: Any) -> dict[str, Any]:
    require(isinstance(raw, dict), "invalid_request", "request must be an object")
    require(raw.get("version") == PROTOCOL_VERSION, "invalid_request", "unsupported guest protocol version")
    require(isinstance(raw.get("id"), str) and REQUEST_ID.fullmatch(raw["id"]), "invalid_request", "invalid request id")
    operation = raw.get("operation")
    require(isinstance(operation, str), "invalid_request", "operation is required")
    base = {"version", "id", "operation"}
    fields = {
        "hello": base,
        "fs.list": base | {"path"},
        "fs.read": base | {"path", "offset", "maxBytes"},
        "fs.write": base | {"path", "offset", "data", "truncate"},
        "fs.delete": base | {"path", "recursive"},
        "job.start": base | {"jobId", "argv", "cwd", "environment", "timeoutMs"},
        "job.status": base | {"jobId", "logOffset", "maxBytes"},
        "job.cancel": base | {"jobId"},
        "bloom.status": base,
        "connections.configure": base | {"workspaceId", "wallet", "caPublicKey", "nfs"},
        "outbox.pending": base,
        "outbox.confirm": base | {"txId", "chain", "wallet", "confirmText"},
        "outbox.cancel": base | {"txId", "chain", "wallet"},
    }
    require(operation in fields, "invalid_request", "unknown guest operation")
    require_exact_keys(raw, fields[operation])
    return raw


def validate_relative_path(value: Any) -> list[str]:
    require(isinstance(value, str), "invalid_request", "workspace path must be a string")
    require(0 < len(value.encode("utf-8")) <= 1024, "invalid_request", "workspace path has an invalid length")
    require("\x00" not in value and "\\" not in value, "invalid_request", "workspace path contains forbidden characters")
    require(not value.startswith("/") and not value.endswith("/"), "invalid_request", "workspace path must be relative")
    require(posixpath.normpath(value) == value and value not in (".", "..") and not value.startswith("../"), "invalid_request", "workspace path escapes /workspace")
    parts = value.split("/")
    require(all(part not in ("", ".", "..") for part in parts), "invalid_request", "invalid workspace path")
    return parts


def validate_workspace_directory(value: Any) -> list[str]:
    if value == ".":
        return []
    return validate_relative_path(value)


def validate_integer(value: Any, minimum: int, maximum: int, label: str) -> int:
    require(isinstance(value, int) and not isinstance(value, bool), "invalid_request", f"{label} must be an integer")
    require(minimum <= value <= maximum, "invalid_request", f"{label} is outside the allowed range")
    return value


def validate_job_id(value: Any) -> str:
    require(isinstance(value, str), "invalid_request", "job id must be a UUID")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        raise ControlError("invalid_request", "job id must be a UUID") from None
    require(str(parsed) == value, "invalid_request", "job id must be a canonical lowercase UUID")
    return value


def validate_environment(value: Any) -> dict[str, str]:
    require(isinstance(value, dict) and len(value) <= 64, "invalid_request", "job environment must contain at most 64 variables")
    result: dict[str, str] = {}
    total = 0
    for name, item in value.items():
        require(isinstance(name, str) and ENV_NAME.fullmatch(name), "invalid_request", "job environment contains an invalid name")
        require(name in USER_ENV_EXACT or name.startswith(USER_ENV_PREFIXES), "permission_denied", f"job environment variable is not allowlisted: {name}")
        require(isinstance(item, str) and "\x00" not in item, "invalid_request", f"job environment value is invalid: {name}")
        encoded = item.encode("utf-8")
        require(len(encoded) <= 8192, "limit_exceeded", f"job environment value is too large: {name}")
        total += len(name.encode("ascii")) + len(encoded)
        require(total <= 32 * 1024, "limit_exceeded", "job environment exceeds the aggregate size limit")
        result[name] = item
    return result


class WorkspaceFiles:
    def __init__(self, root: str, quota_bytes: int, owner_uid: int, owner_gid: int):
        self.root = os.path.abspath(root)
        root_metadata = os.lstat(self.root)
        if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
            raise RuntimeError("workspace root must be a non-symlink directory")
        root_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
        try:
            self.root_fd = os.open(self.root, root_flags)
        except OSError as error:
            raise RuntimeError(f"unsafe or unavailable workspace root: {error}") from error
        self.quota_bytes = quota_bytes
        self.owner_uid = owner_uid
        self.owner_gid = owner_gid
        self.write_lock = threading.Lock()

    def close(self) -> None:
        os.close(self.root_fd)

    def prepare_job_tmp(self) -> None:
        descriptor = self._open_directory([".tmp"], create=True)
        try:
            os.fchmod(descriptor, 0o700)
            if os.geteuid() == 0:
                os.fchown(descriptor, self.owner_uid, self.owner_gid)
        finally:
            os.close(descriptor)

    def _open_directory(self, parts: list[str], create: bool = False) -> int:
        current = os.dup(self.root_fd)
        flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
        try:
            for part in parts:
                if create:
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=current)
                        if os.geteuid() == 0:
                            os.chown(part, self.owner_uid, self.owner_gid, dir_fd=current, follow_symlinks=False)
                    except FileExistsError:
                        pass
                following = os.open(part, flags, dir_fd=current)
                os.close(current)
                current = following
            return current
        except Exception:
            os.close(current)
            raise

    def _open_file(self, parts: list[str], flags: int, mode: int = 0o600, create_parents: bool = False) -> int:
        parent = self._open_directory(parts[:-1], create=create_parents)
        try:
            return os.open(parts[-1], flags | getattr(os, "O_NOFOLLOW", 0), mode, dir_fd=parent)
        finally:
            os.close(parent)

    def list(self, path: Any) -> dict[str, Any]:
        parts = validate_workspace_directory(path)
        directory = self._open_directory(parts)
        try:
            names = sorted(os.listdir(directory))
            require(len(names) <= MAX_LIST_ENTRIES, "limit_exceeded", "directory contains too many entries")
            entries = []
            for name in names:
                metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
                kind = "symlink" if stat.S_ISLNK(metadata.st_mode) else "directory" if stat.S_ISDIR(metadata.st_mode) else "file"
                entries.append(
                    {
                        "path": "/".join(parts + [name]),
                        "type": kind,
                        "size": metadata.st_size if stat.S_ISREG(metadata.st_mode) else 0,
                        "modifiedAt": int(metadata.st_mtime * 1000),
                    }
                )
            return {"files": entries}
        finally:
            os.close(directory)

    def read(self, path: Any, offset: Any, max_bytes: Any) -> dict[str, Any]:
        parts = validate_relative_path(path)
        start = validate_integer(offset, 0, MAX_FILE_BYTES, "file offset")
        limit = validate_integer(max_bytes, 1, MAX_FILE_CHUNK_BYTES, "file read size")
        descriptor = self._open_file(parts, os.O_RDONLY)
        try:
            metadata = os.fstat(descriptor)
            require(stat.S_ISREG(metadata.st_mode), "invalid_request", "download path is not a regular file")
            require(metadata.st_size <= MAX_FILE_BYTES, "limit_exceeded", "file exceeds the download limit")
            require(start <= metadata.st_size, "invalid_request", "file offset exceeds the file size")
            chunk = os.pread(descriptor, limit, start)
            return {
                "path": "/".join(parts),
                "offset": start,
                "nextOffset": start + len(chunk),
                "size": metadata.st_size,
                "eof": start + len(chunk) >= metadata.st_size,
                "data": base64.b64encode(chunk).decode("ascii"),
            }
        finally:
            os.close(descriptor)

    def write(self, path: Any, offset: Any, encoded: Any, truncate: Any) -> dict[str, Any]:
        parts = validate_relative_path(path)
        start = validate_integer(offset, 0, MAX_FILE_BYTES, "file offset")
        require(isinstance(encoded, str), "invalid_request", "file payload must be base64")
        require(isinstance(truncate, bool), "invalid_request", "truncate must be boolean")
        require(not truncate or start == 0, "invalid_request", "a truncating write must begin at offset zero")
        try:
            chunk = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            raise ControlError("invalid_request", "file payload is not canonical base64") from None
        require(base64.b64encode(chunk).decode("ascii") == encoded, "invalid_request", "file payload is not canonical base64")
        require(len(chunk) <= MAX_FILE_CHUNK_BYTES, "limit_exceeded", "file write chunk is too large")
        require(start + len(chunk) <= MAX_FILE_BYTES, "limit_exceeded", "file exceeds the upload limit")
        with self.write_lock:
            flags = os.O_WRONLY | os.O_CREAT
            descriptor = self._open_file(parts, flags, create_parents=True)
            try:
                if os.geteuid() == 0:
                    os.fchown(descriptor, self.owner_uid, self.owner_gid)
                metadata = os.fstat(descriptor)
                require(stat.S_ISREG(metadata.st_mode), "invalid_request", "upload target is not a regular file")
                prior = metadata.st_size
                used = self._directory_bytes()
                resulting_size = max(0 if truncate else prior, start + len(chunk))
                require(used - prior + resulting_size <= self.quota_bytes, "limit_exceeded", "workspace storage quota exceeded")
                if truncate:
                    os.ftruncate(descriptor, 0)
                written = 0
                while written < len(chunk):
                    count = os.pwrite(descriptor, chunk[written:], start + written)
                    require(count > 0, "internal", "file write made no progress")
                    written += count
                os.fsync(descriptor)
                final_size = os.fstat(descriptor).st_size
            finally:
                os.close(descriptor)
            used_after = self._directory_bytes()
            return {
                "path": "/".join(parts),
                "size": final_size,
                "nextOffset": start + len(chunk),
                "usedBytes": used_after,
                "quotaBytes": self.quota_bytes,
            }

    def delete(self, path: Any, recursive: Any) -> dict[str, Any]:
        parts = validate_relative_path(path)
        require(recursive is False, "permission_denied", "recursive deletion is not supported")
        with self.write_lock:
            parent = self._open_directory(parts[:-1])
            try:
                metadata = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
                require(stat.S_ISREG(metadata.st_mode), "invalid_request", "delete path is not a regular file")
                os.unlink(parts[-1], dir_fd=parent)
            finally:
                os.close(parent)
            used_after = self._directory_bytes()
            return {
                "path": "/".join(parts),
                "deleted": True,
                "usedBytes": used_after,
                "quotaBytes": self.quota_bytes,
            }

    def open_job_cwd(self, path: Any) -> int:
        return self._open_directory(validate_workspace_directory(path))

    def read_small(self, path: str, maximum: int = 256) -> str | None:
        try:
            descriptor = self._open_file(validate_relative_path(path), os.O_RDONLY)
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
                    return None
                return os.read(descriptor, maximum).decode("utf-8").strip()
            finally:
                os.close(descriptor)
        except (OSError, ControlError, UnicodeDecodeError):
            return None

    def watch_identity(self) -> str | None:
        """Return a validated public watch address, rejecting any extra state."""
        try:
            keystore = self._open_directory([".bloom", "keystore"])
            try:
                if sorted(os.listdir(keystore)) != ["workspace-login"]:
                    return None
            finally:
                os.close(keystore)
            wallet = self._open_directory([".bloom", "keystore", "workspace-login"])
            try:
                if sorted(os.listdir(wallet)) != ["address", "kind", "pubkey"]:
                    return None
            finally:
                os.close(wallet)
            kind = self.read_small(".bloom/keystore/workspace-login/kind")
            address = self.read_small(".bloom/keystore/workspace-login/address")
            public_key = self.read_small(".bloom/keystore/workspace-login/pubkey")
            normalized = address.lower() if address else None
            if kind != "watch" or public_key != "" or not isinstance(normalized, str) or EVM_ADDRESS.fullmatch(normalized) is None:
                return None
            return normalized
        except (OSError, ControlError):
            return None

    def _directory_bytes(self) -> int:
        count = 0
        total = 0
        for _, directories, files, directory_fd in os.fwalk(self.root, topdown=True, follow_symlinks=False):
            directories[:] = [name for name in directories if not stat.S_ISLNK(os.stat(name, dir_fd=directory_fd, follow_symlinks=False).st_mode)]
            for name in files:
                count += 1
                require(count <= MAX_SCAN_ENTRIES, "limit_exceeded", "workspace contains too many files")
                metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISREG(metadata.st_mode):
                    total += metadata.st_size
        return total


class LogRing:
    def __init__(self) -> None:
        self.data = bytearray()
        self.start_offset = 0
        self.end_offset = 0
        self.lock = threading.Lock()

    def append(self, chunk: bytes) -> None:
        if not chunk:
            return
        with self.lock:
            self.data.extend(chunk)
            self.end_offset += len(chunk)
            overflow = len(self.data) - MAX_LOG_BYTES
            if overflow > 0:
                del self.data[:overflow]
                self.start_offset += overflow

    def slice(self, requested_offset: int, maximum: int, terminal: bool) -> dict[str, Any]:
        with self.lock:
            require(requested_offset <= self.end_offset, "invalid_request", "log cursor is beyond the current log end")
            offset = max(requested_offset, self.start_offset)
            relative = offset - self.start_offset
            chunk = bytes(self.data[relative : relative + maximum])
            next_offset = offset + len(chunk)
            return {
                "offset": offset,
                "nextOffset": next_offset,
                "endOffset": self.end_offset,
                "truncatedBefore": requested_offset < self.start_offset,
                "eof": terminal and next_offset == self.end_offset,
                "encoding": "base64",
                "data": base64.b64encode(chunk).decode("ascii"),
            }


TERMINAL_STATES = frozenset({"succeeded", "failed", "cancelled", "timed_out"})


@dataclass
class Job:
    job_id: str
    argv: list[str]
    cwd: str
    timeout_ms: int
    created_at: int
    state: str = "queued"
    started_at: int | None = None
    finished_at: int | None = None
    exit_code: int | None = None
    signal_number: int | None = None
    process: subprocess.Popen[bytes] | None = None
    cancel_requested: bool = False
    logs: LogRing = field(default_factory=LogRing)
    finished: threading.Event = field(default_factory=threading.Event)


class JobEngine:
    def __init__(self, files: WorkspaceFiles, job_uid: int, job_gid: int):
        self.files = files
        self.job_uid = job_uid
        self.job_gid = job_gid
        self.jobs: OrderedDict[str, Job] = OrderedDict()
        self.lock = threading.RLock()

    def start(self, request: dict[str, Any]) -> dict[str, Any]:
        job_id = validate_job_id(request["jobId"])
        argv = request["argv"]
        require(isinstance(argv, list) and 1 <= len(argv) <= 64, "invalid_request", "argv must contain between 1 and 64 arguments")
        validated_argv = []
        total_argv = 0
        for argument in argv:
            require(isinstance(argument, str) and argument and "\x00" not in argument, "invalid_request", "argv contains an invalid argument")
            size = len(argument.encode("utf-8"))
            require(size <= 4096, "limit_exceeded", "argv contains an oversized argument")
            total_argv += size
            require(total_argv <= 32 * 1024, "limit_exceeded", "argv exceeds the aggregate size limit")
            validated_argv.append(argument)
        cwd_parts = validate_workspace_directory(request["cwd"])
        cwd = "/".join(cwd_parts) if cwd_parts else "."
        timeout_ms = validate_integer(request["timeoutMs"], 1000, MAX_JOB_TIMEOUT_MS, "job timeout")
        user_environment = validate_environment(request["environment"])
        launcher = self._launcher_argv(validated_argv)

        with self.lock:
            require(job_id not in self.jobs, "conflict", "job id already exists")
            active = sum(job.state not in TERMINAL_STATES for job in self.jobs.values())
            require(active < MAX_ACTIVE_JOBS, "limit_exceeded", "workspace already has the maximum number of active jobs")
            self._prune_terminal_jobs()
            require(len(self.jobs) < MAX_RETAINED_JOBS, "limit_exceeded", "workspace has too many retained jobs")
            cwd_fd = self.files.open_job_cwd(cwd)
            job = Job(job_id=job_id, argv=validated_argv, cwd=cwd, timeout_ms=timeout_ms, created_at=now_ms())
            self.jobs[job_id] = job
            try:
                job.started_at = now_ms()
                process = subprocess.Popen(
                    launcher,
                    cwd=f"/proc/self/fd/{cwd_fd}",
                    env=self._job_environment(user_environment),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    bufsize=0,
                    close_fds=True,
                    pass_fds=(cwd_fd,),
                    start_new_session=True,
                )
            except (OSError, subprocess.SubprocessError) as error:
                job.state = "failed"
                job.finished_at = now_ms()
                job.logs.append(f"bloom job launch failed: {error}\n".encode("utf-8", "replace"))
                job.finished.set()
                return self._status(job, 0, MAX_LOG_CHUNK_BYTES)
            finally:
                os.close(cwd_fd)
            job.process = process
            job.state = "running"
            threading.Thread(target=self._capture_output, args=(job,), daemon=True, name=f"job-log-{job_id}").start()
            threading.Thread(target=self._wait_for_job, args=(job,), daemon=True, name=f"job-wait-{job_id}").start()
            return self._status(job, 0, MAX_LOG_CHUNK_BYTES)

    def status(self, request: dict[str, Any]) -> dict[str, Any]:
        job = self._get(validate_job_id(request["jobId"]))
        offset = validate_integer(request["logOffset"], 0, 2**53 - 1, "log cursor")
        maximum = validate_integer(request["maxBytes"], 1, MAX_LOG_CHUNK_BYTES, "log read size")
        with self.lock:
            return self._status(job, offset, maximum)

    def cancel(self, request: dict[str, Any]) -> dict[str, Any]:
        job = self._get(validate_job_id(request["jobId"]))
        with self.lock:
            if job.state in TERMINAL_STATES:
                return self._status(job, job.logs.end_offset, 1)
            process = job.process
            require(process is not None, "conflict", "job has not started")
            if process.poll() is None:
                first_request = not job.cancel_requested
                job.cancel_requested = True
                self._signal_group(process.pid, signal.SIGTERM)
                if first_request:
                    threading.Thread(target=self._force_cancel, args=(job,), daemon=True, name=f"job-cancel-{job.job_id}").start()
            return self._status(job, job.logs.end_offset, 1)

    def close(self) -> None:
        with self.lock:
            active = [job for job in self.jobs.values() if job.state not in TERMINAL_STATES and job.process]
            for job in active:
                job.cancel_requested = True
                self._signal_group(job.process.pid, signal.SIGKILL)
        for job in active:
            job.finished.wait(2)

    def _get(self, job_id: str) -> Job:
        with self.lock:
            job = self.jobs.get(job_id)
            require(job is not None, "not_found", "job does not exist")
            return job

    def _prune_terminal_jobs(self) -> None:
        while len(self.jobs) >= MAX_RETAINED_JOBS:
            terminal_id = next((job_id for job_id, job in self.jobs.items() if job.state in TERMINAL_STATES), None)
            if terminal_id is None:
                return
            del self.jobs[terminal_id]

    def _capture_output(self, job: Job) -> None:
        stream = job.process.stdout if job.process else None
        if stream is None:
            return
        try:
            while True:
                chunk = stream.read(16 * 1024)
                if not chunk:
                    return
                job.logs.append(chunk)
        finally:
            stream.close()

    def _wait_for_job(self, job: Job) -> None:
        process = job.process
        if process is None:
            return
        timed_out = False
        try:
            try:
                process.wait(timeout=job.timeout_ms / 1000)
            except subprocess.TimeoutExpired:
                timed_out = True
                self._signal_group(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=JOB_KILL_GRACE_SECONDS)
                except subprocess.TimeoutExpired:
                    self._signal_group(process.pid, signal.SIGKILL)
                    process.wait()
            if process.stdout:
                # Give the bounded reader a chance to drain the closed pipe.
                for _ in range(100):
                    if process.stdout.closed:
                        break
                    time.sleep(0.01)
            with self.lock:
                return_code = process.returncode
                job.finished_at = now_ms()
                if timed_out:
                    job.state = "timed_out"
                elif job.cancel_requested:
                    job.state = "cancelled"
                elif return_code == 0:
                    job.state = "succeeded"
                else:
                    job.state = "failed"
                if return_code is not None and return_code < 0:
                    job.signal_number = -return_code
                else:
                    job.exit_code = return_code
        finally:
            job.finished.set()

    def _force_cancel(self, job: Job) -> None:
        time.sleep(JOB_KILL_GRACE_SECONDS)
        process = job.process
        if process is not None and process.poll() is None:
            self._signal_group(process.pid, signal.SIGKILL)

    def _status(self, job: Job, log_offset: int, max_bytes: int) -> dict[str, Any]:
        result: dict[str, Any] = {
            "jobId": job.job_id,
            "state": job.state,
            "createdAt": job.created_at,
            "startedAt": job.started_at,
            "finishedAt": job.finished_at,
            "exitCode": job.exit_code,
            "signal": job.signal_number,
            "timeoutMs": job.timeout_ms,
            "logs": job.logs.slice(log_offset, max_bytes, job.state in TERMINAL_STATES),
        }
        return result

    def _launcher_argv(self, argv: list[str]) -> list[str]:
        prlimit = shutil.which("prlimit") or "/usr/bin/prlimit"
        setpriv = shutil.which("setpriv") or "/usr/bin/setpriv"
        command = [
            prlimit,
            "--nofile=64:64",
            f"--fsize={MAX_JOB_FILE_BYTES}:{MAX_JOB_FILE_BYTES}",
            "--core=0:0",
        ]
        if os.geteuid() == 0:
            command.append(f"--nproc={MAX_JOB_PROCESSES}:{MAX_JOB_PROCESSES}")
        command.extend([
            "--",
            setpriv,
            "--no-new-privs",
            "--pdeathsig=SIGKILL",
        ])
        if os.geteuid() == 0:
            command.extend([
                "--bounding-set=-all",
                "--inh-caps=-all",
                "--ambient-caps=-all",
                f"--reuid={self.job_uid}",
                f"--regid={self.job_gid}",
                "--clear-groups",
            ])
        else:
            require(os.geteuid() == self.job_uid and os.getegid() == self.job_gid, "unavailable", "guest control must run as root to change job identity")
        return command + ["--"] + argv

    def _job_environment(self, user_environment: dict[str, str]) -> dict[str, str]:
        environment = {
            "HOME": "/workspace",
            "USER": "workspace",
            "LOGNAME": "workspace",
            "SHELL": "/bin/bash",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "TMPDIR": "/workspace/.tmp",
            "LANG": "C.UTF-8",
        }
        for name in SYSTEM_PROXY_ENV:
            value = os.environ.get(name)
            if value and len(value) <= 2048 and "@" not in value and "\x00" not in value:
                environment[name] = value
        for name in ("SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS"):
            value = os.environ.get(name)
            if value and value.startswith("/") and "\x00" not in value and len(value) <= 1024:
                environment[name] = value
        environment.update(user_environment)
        return environment

    @staticmethod
    def _signal_group(pid: int, requested_signal: signal.Signals) -> None:
        try:
            os.killpg(pid, requested_signal)
        except ProcessLookupError:
            pass


def write_private_file(path: str, content: str, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        os.fchmod(descriptor, mode)
        encoded = content.encode("utf-8")
        written = 0
        while written < len(encoded):
            count = os.write(descriptor, encoded[written:])
            if count <= 0:
                raise OSError("connection configuration write made no progress")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def read_small_regular_file(path: str, maximum: int) -> str | None:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
                return None
            return os.read(descriptor, maximum).decode("utf-8").strip()
        finally:
            os.close(descriptor)
    except (OSError, UnicodeDecodeError):
        return None


class GuestControl:
    def __init__(self, files: WorkspaceFiles, jobs: JobEngine):
        self.files = files
        self.jobs = jobs
        self.sshd: subprocess.Popen[bytes] | None = None
        self.mountd: subprocess.Popen[bytes] | None = None
        self.connection_scope: tuple[str, str, bool] | None = None
        self.connection_lock = threading.Lock()

    def handle(self, raw: Any) -> dict[str, Any]:
        request_id = raw.get("id") if isinstance(raw, dict) and isinstance(raw.get("id"), str) and REQUEST_ID.fullmatch(raw["id"]) else "invalid"
        try:
            request = validate_request(raw)
            operation = request["operation"]
            if operation == "hello":
                result = {
                    "protocolVersion": PROTOCOL_VERSION,
                    "operations": ["fs.list", "fs.read", "fs.write", "fs.delete", "job.start", "job.status", "job.cancel", "bloom.status", "connections.configure", "outbox.pending", "outbox.confirm", "outbox.cancel"],
                    "limits": {
                        "fileChunkBytes": MAX_FILE_CHUNK_BYTES,
                        "fileBytes": MAX_FILE_BYTES,
                        "activeJobs": MAX_ACTIVE_JOBS,
                        "retainedJobs": MAX_RETAINED_JOBS,
                        "jobProcesses": MAX_JOB_PROCESSES,
                        "jobLogBytes": MAX_LOG_BYTES,
                        "jobTimeoutMs": MAX_JOB_TIMEOUT_MS,
                    },
                }
            elif operation == "fs.list":
                result = self.files.list(request["path"])
            elif operation == "fs.read":
                result = self.files.read(request["path"], request["offset"], request["maxBytes"])
            elif operation == "fs.write":
                result = self.files.write(request["path"], request["offset"], request["data"], request["truncate"])
            elif operation == "fs.delete":
                result = self.files.delete(request["path"], request["recursive"])
            elif operation == "job.start":
                result = self.jobs.start(request)
            elif operation == "job.status":
                result = self.jobs.status(request)
            elif operation == "job.cancel":
                result = self.jobs.cancel(request)
            elif operation == "bloom.status":
                result = self._bloom_status()
            elif operation == "connections.configure":
                result = self._configure_connections(request)
            elif operation == "outbox.pending":
                result = self._outbox_pending()
            elif operation == "outbox.confirm":
                result = self._outbox_confirm(request)
            elif operation == "outbox.cancel":
                result = self._outbox_cancel(request)
            else:
                raise ControlError("invalid_request", "unknown guest operation")
            return {"version": PROTOCOL_VERSION, "id": request_id, "ok": True, "result": result}
        except ControlError as error:
            return {"version": PROTOCOL_VERSION, "id": request_id, "ok": False, "error": {"code": error.code, "message": str(error)[:1024]}}
        except FileNotFoundError:
            return {"version": PROTOCOL_VERSION, "id": request_id, "ok": False, "error": {"code": "not_found", "message": "workspace path does not exist"}}
        except PermissionError:
            return {"version": PROTOCOL_VERSION, "id": request_id, "ok": False, "error": {"code": "permission_denied", "message": "workspace operation was denied"}}
        except OSError as error:
            code = "not_found" if error.errno == errno.ENOENT else "permission_denied" if error.errno in (errno.EACCES, errno.EPERM, errno.ELOOP, errno.ENOTDIR) else "internal"
            return {"version": PROTOCOL_VERSION, "id": request_id, "ok": False, "error": {"code": code, "message": "workspace operation failed"}}
        except Exception:
            return {"version": PROTOCOL_VERSION, "id": request_id, "ok": False, "error": {"code": "internal", "message": "guest control operation failed"}}

    def _bloom_status(self) -> dict[str, Any]:
        address = self.files.watch_identity()
        watch_identity = address is not None
        executable = shutil.which("bloom") is not None
        return {
            "available": executable and watch_identity,
            "mount": {"path": "/bloom", "mounted": os.path.ismount("/bloom")},
            "identity": {"kind": "watch", "address": address} if watch_identity else None,
            "capabilities": {
                "files": True,
                "jobs": True,
                "bloomRead": executable and watch_identity,
                "walletSigning": True,
                "transactions": True,
            },
            "helper": {"name": "bloom-workspace", "protocolVersion": PROTOCOL_VERSION},
        }

    def _bloom_ipc(self, method: str, params: dict[str, Any]) -> Any:
        """Call bloom serve's IPC socket."""
        require(os.path.exists(BLOOM_SOCKET_PATH), "unavailable", "Bloom IPC socket is not available")
        request = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        frame = json.dumps(request, separators=(",", ":")).encode() + b"\n"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(10.0)
            client.connect(BLOOM_SOCKET_PATH)
            client.sendall(frame)
            response = bytearray()
            while b"\n" not in response:
                chunk = client.recv(65536)
                if not chunk:
                    break
                response.extend(chunk)
                if len(response) > 1024 * 1024:
                    break
        decoded = json.loads(bytes(response).decode())
        if "error" in decoded:
            raise ControlError("internal", f"bloom IPC error: {decoded['error']}")
        return decoded.get("result")

    def _outbox_pending(self) -> dict[str, Any]:
        """List pending outbox transactions by scanning the bloom VFS via IPC."""
        wallet_result = self._bloom_ipc("list", {"path": "/wallets"})
        wallets = [e.get("name") for e in (wallet_result.get("entries") or []) if e.get("type") == "dir"]
        pending = []
        for wallet in wallets[:MAX_OUTBOX_CHAINS]:
            chain_result = self._bloom_ipc("list", {"path": f"/wallets/{wallet}/chains"})
            chains = [e.get("name") for e in (chain_result.get("entries") or []) if e.get("type") == "dir"]
            for chain in chains[:MAX_OUTBOX_CHAINS]:
                pending_result = self._bloom_ipc("list", {"path": f"/wallets/{wallet}/chains/{chain}/outbox/pending"})
                ids = [e.get("name") for e in (pending_result.get("entries") or []) if e.get("type") == "dir"]
                for tx_id in ids[:MAX_OUTBOX_PENDING]:
                    plan_result = self._bloom_ipc("read", {"path": f"/wallets/{wallet}/chains/{chain}/outbox/pending/{tx_id}/plan.md"})
                    plan_b64 = plan_result.get("bytes_b64", "")
                    plan_md = base64.b64decode(plan_b64).decode("utf-8", errors="replace")[:MAX_OUTBOX_PLAN_BYTES]
                    pending.append({"id": tx_id, "chain": chain, "wallet": wallet, "planMd": plan_md})
        return {"requests": pending}

    def _outbox_confirm(self, request: dict[str, Any]) -> dict[str, Any]:
        """Write confirm to bloom's outbox via IPC."""
        tx_id = request["txId"]
        chain = request["chain"]
        wallet = request["wallet"]
        confirm_text = request["confirmText"]
        require(isinstance(tx_id, str) and len(tx_id) <= 64, "invalid_request", "invalid tx id")
        require(isinstance(chain, str) and len(chain) <= 32, "invalid_request", "invalid chain")
        require(isinstance(wallet, str) and len(wallet) <= 64, "invalid_request", "invalid wallet name")
        require(isinstance(confirm_text, str) and len(confirm_text.strip()) > 0, "invalid_request", "confirm text is required")
        path = f"/wallets/{wallet}/chains/{chain}/outbox/pending/{tx_id}/confirm"
        body_b64 = base64.b64encode(confirm_text.encode()).decode()
        self._bloom_ipc("write", {"path": path, "bytes_b64": body_b64})
        return {}

    def _outbox_cancel(self, request: dict[str, Any]) -> dict[str, Any]:
        """Write cancel to bloom's outbox via IPC."""
        tx_id = request["txId"]
        chain = request["chain"]
        wallet = request["wallet"]
        require(isinstance(tx_id, str) and len(tx_id) <= 64, "invalid_request", "invalid tx id")
        require(isinstance(chain, str) and len(chain) <= 32, "invalid_request", "invalid chain")
        require(isinstance(wallet, str) and len(wallet) <= 64, "invalid_request", "invalid wallet name")
        path = f"/wallets/{wallet}/chains/{chain}/outbox/pending/{tx_id}/cancel"
        body_b64 = base64.b64encode(b"cancel").decode()
        self._bloom_ipc("write", {"path": path, "bytes_b64": body_b64})
        return {}

    def _configure_connections(self, request: dict[str, Any]) -> dict[str, Any]:
        with self.connection_lock:
            return self._configure_connections_locked(request)

    def _configure_connections_locked(self, request: dict[str, Any]) -> dict[str, Any]:
        workspace_id = request["workspaceId"]
        wallet = request["wallet"]
        ca_public_key = request["caPublicKey"]
        nfs_enabled = request["nfs"]
        require(isinstance(workspace_id, str) and WORKSPACE_ID.fullmatch(workspace_id), "invalid_request", "invalid workspace id")
        require(isinstance(wallet, str) and EVM_ADDRESS.fullmatch(wallet), "invalid_request", "invalid workspace wallet")
        require(isinstance(ca_public_key, str) and SSH_CA_PUBLIC_KEY.fullmatch(ca_public_key), "invalid_request", "invalid SSH CA public key")
        require(isinstance(nfs_enabled, bool), "invalid_request", "invalid NFS capability")
        scope = (workspace_id, wallet, nfs_enabled)
        if self.connection_scope is not None:
            require(self.connection_scope == scope, "conflict", "workspace connection scope is already configured")
            return self._connection_status(workspace_id, nfs_enabled)
        require(os.geteuid() == 0, "unavailable", "workspace connections require the root guest controller")
        require(shutil.which("sshd") is not None and shutil.which("ssh-keygen") is not None, "unavailable", "OpenSSH server tooling is unavailable")

        try:
            decoded = base64.b64decode(ca_public_key.split(" ", 1)[1], validate=True)
        except (binascii.Error, ValueError):
            raise ControlError("invalid_request", "invalid SSH CA public key") from None
        require(32 <= len(decoded) <= 128, "invalid_request", "invalid SSH CA public key payload")
        directory = "/run/bloom/ssh"
        os.makedirs(directory, mode=0o700, exist_ok=True)
        os.chmod(directory, 0o700)
        ca_path = f"{directory}/user_ca.pub"
        principals_path = f"{directory}/authorized_principals"
        host_key_path = f"{directory}/ssh_host_ed25519_key"
        owner_digest = hashlib.sha256(wallet.encode("ascii")).hexdigest()[:32]
        principals = [f"bloom-shell-{workspace_id}-w-{owner_digest}"]
        if nfs_enabled:
            principals.append(f"bloom-nfs-{workspace_id}-w-{owner_digest}")
        write_private_file(ca_path, f"{ca_public_key}\n", 0o600)
        write_private_file(principals_path, "\n".join(principals) + "\n", 0o600)
        if not os.path.exists(host_key_path):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", host_key_path], check=True, timeout=10)
        os.chmod(host_key_path, 0o600)
        os.chmod(f"{host_key_path}.pub", 0o644)
        shell = "/usr/local/libexec/bloom-workspace-shell"
        require(os.path.isfile(shell) and not os.path.islink(shell), "unavailable", "workspace SSH shell helper is unavailable")
        sshd_argv = [
            "sshd", "-D", "-e", "-f", "/etc/ssh/sshd_config",
            "-o", f"HostKey={host_key_path}", "-o", f"TrustedUserCAKeys={ca_path}",
            "-o", f"AuthorizedPrincipalsFile={principals_path}", "-o", "AuthorizedKeysFile=none",
            "-o", "AuthenticationMethods=publickey", "-o", "PubkeyAuthentication=yes",
            "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
            "-o", "PermitRootLogin=no", "-o", "AllowUsers=workspace",
            "-o", "AllowAgentForwarding=no", "-o", "AllowTcpForwarding=local",
            "-o", "PermitOpen=127.0.0.1:2049", "-o", "AllowStreamLocalForwarding=no",
            "-o", "GatewayPorts=no", "-o", "X11Forwarding=no", "-o", "PermitTunnel=no",
            "-o", "PermitUserEnvironment=no", "-o", "PermitUserRC=no", "-o", "PermitTTY=yes",
            "-o", "MaxSessions=1", "-o", "UsePAM=no",
            "-o", "AddressFamily=inet", "-o", "ListenAddress=0.0.0.0", "-o", "Port=22",
        ]
        self.sshd = subprocess.Popen(sshd_argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
        time.sleep(0.05)
        require(self.sshd.poll() is None, "unavailable", "workspace sshd failed to start")
        if nfs_enabled:
            try:
                self._start_nfs(workspace_id)
            except Exception:
                self.sshd.terminate()
                self.sshd.wait(timeout=2)
                self.sshd = None
                raise
        self.connection_scope = scope
        return self._connection_status(workspace_id, nfs_enabled)

    def _start_nfs(self, workspace_id: str) -> None:
        try:
            os.makedirs("/proc/fs/nfsd", mode=0o755, exist_ok=True)
            for command in ("exportfs", "rpc.mountd", "rpc.nfsd"):
                require(shutil.which(command) is not None, "unavailable", f"NFS server tool is unavailable: {command}")
            if not os.path.ismount("/proc/fs/nfsd"):
                subprocess.run(["mount", "-t", "nfsd", "nfsd", "/proc/fs/nfsd"], check=True, timeout=10)
            options = "rw,fsid=0,sync,no_subtree_check,root_squash,all_squash,anonuid=1000,anongid=1000,insecure"
            subprocess.run(["exportfs", "-i", "-o", options, "127.0.0.1:/workspace"], check=True, timeout=10)
            self.mountd = subprocess.Popen(["rpc.mountd", "--foreground", "--no-udp", "--no-nfs-version", "2", "--no-nfs-version", "3", "--ttl", "10"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
            time.sleep(0.05)
            require(self.mountd.poll() is None, "unavailable", "NFS mount daemon failed to start")
            subprocess.run(["rpc.nfsd", "--host", "127.0.0.1", "--no-udp", "--no-nfs-version", "2", "--no-nfs-version", "3", "--nfs-version", "4", "--leasetime", "10", "--grace-time", "10", "--port", "2049", "1"], check=True, timeout=10)
        except ControlError:
            self._stop_partial_nfs()
            raise
        except (OSError, subprocess.SubprocessError):
            self._stop_partial_nfs()
            raise ControlError("unavailable", "guest NFS service failed to start") from None

    def _stop_partial_nfs(self) -> None:
        if self.mountd is not None and self.mountd.poll() is None:
            self.mountd.terminate()
            try:
                self.mountd.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.mountd.kill()
        self.mountd = None
        if shutil.which("rpc.nfsd") is not None:
            subprocess.run(["rpc.nfsd", "0"], check=False, timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if shutil.which("exportfs") is not None:
            subprocess.run(["exportfs", "-u", "127.0.0.1:/workspace"], check=False, timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _connection_status(self, workspace_id: str, nfs_enabled: bool) -> dict[str, Any]:
        host_key = read_small_regular_file("/run/bloom/ssh/ssh_host_ed25519_key.pub", 1024)
        require(host_key is not None and host_key.startswith("ssh-ed25519 "), "unavailable", "guest SSH host key is unavailable")
        normalized_host_key = " ".join(host_key.split()[:2])
        return {"ssh": {"available": self.sshd is not None and self.sshd.poll() is None, "hostKey": normalized_host_key, "port": 22}, "nfs": {"available": nfs_enabled and self.mountd is not None and self.mountd.poll() is None, "port": 2049 if nfs_enabled else None}, "workspaceId": workspace_id}

    def close(self) -> None:
        if self.sshd is not None and self.sshd.poll() is None:
            self.sshd.terminate()
            try:
                self.sshd.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.sshd.kill()
        if self.connection_scope is not None and self.connection_scope[2]:
            try:
                self._stop_partial_nfs()
            except (OSError, subprocess.SubprocessError):
                pass


def decode_frame(frame: bytes) -> Any:
    require(len(frame) <= MAX_FRAME_BYTES, "limit_exceeded", "guest protocol frame is too large")
    require(frame.endswith(b"\n"), "invalid_request", "guest protocol frame must end with a newline")
    try:
        return json.loads(frame[:-1].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ControlError("invalid_request", "guest protocol frame is not valid UTF-8 JSON") from None


def encode_response(response: dict[str, Any]) -> bytes:
    frame = json.dumps(response, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
    if len(frame) > MAX_FRAME_BYTES:
        fallback = {"version": PROTOCOL_VERSION, "id": response.get("id", "invalid"), "ok": False, "error": {"code": "internal", "message": "guest response exceeded the frame limit"}}
        return json.dumps(fallback, separators=(",", ":")).encode("utf-8") + b"\n"
    return frame


def process_frame(control: GuestControl, frame: bytes) -> bytes:
    try:
        request = decode_frame(frame)
        return encode_response(control.handle(request))
    except ControlError as error:
        return encode_response({"version": PROTOCOL_VERSION, "id": "invalid", "ok": False, "error": {"code": error.code, "message": str(error)}})


def serve_stdio(control: GuestControl, reader: BinaryIO, writer: BinaryIO) -> None:
    while True:
        frame = reader.readline(MAX_FRAME_BYTES + 2)
        if not frame:
            return
        writer.write(process_frame(control, frame))
        writer.flush()


def create_unix_listener(path: str, uid: int, gid: int) -> socket.socket:
    parent = os.path.dirname(path)
    os.makedirs(parent, mode=0o755, exist_ok=True)
    try:
        metadata = os.lstat(path)
        require(stat.S_ISSOCK(metadata.st_mode), "unavailable", "guest control socket path is occupied")
        os.unlink(path)
    except FileNotFoundError:
        pass
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    os.chmod(path, 0o600)
    if os.geteuid() == 0:
        os.chown(path, uid, gid)
    listener.listen(16)
    return listener


def create_vsock_listener(port: int) -> socket.socket:
    require(hasattr(socket, "AF_VSOCK"), "unavailable", "Python does not support AF_VSOCK")
    listener = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    listener.bind((getattr(socket, "VMADDR_CID_ANY", 0xFFFFFFFF), port))
    listener.listen(16)
    return listener


def serve_sockets(control: GuestControl, listeners: list[socket.socket]) -> None:
    while True:
        readable, _, _ = select.select(listeners, [], [])
        for listener in readable:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(10)
                frame = bytearray()
                while len(frame) <= MAX_FRAME_BYTES:
                    chunk = connection.recv(min(64 * 1024, MAX_FRAME_BYTES + 1 - len(frame)))
                    if not chunk:
                        break
                    frame.extend(chunk)
                    if b"\n" in chunk:
                        break
                connection.sendall(process_frame(control, bytes(frame)))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Bloom workspace guest control service")
    parser.add_argument("--workspace", default="/workspace")
    parser.add_argument("--workspace-quota-bytes", type=int, default=512 * 1024 * 1024)
    parser.add_argument("--job-uid", type=int, default=1000)
    parser.add_argument("--job-gid", type=int, default=1000)
    parser.add_argument("--stdio", action="store_true")
    parser.add_argument("--unix-socket")
    parser.add_argument("--vsock-port", type=int)
    args = parser.parse_args()
    if not args.stdio and not args.unix_socket and args.vsock_port is None:
        parser.error("at least one transport is required")
    if not 1024 * 1024 <= args.workspace_quota_bytes <= 16 * 1024 * 1024 * 1024:
        parser.error("workspace quota is outside the supported range")
    if args.vsock_port is not None and not 1 <= args.vsock_port <= 0xFFFFFFFF:
        parser.error("vsock port is outside the supported range")
    return args


def handle_shutdown(_signum: int, _frame: Any) -> None:
    raise KeyboardInterrupt


def main() -> int:
    args = parse_args()
    signal.signal(signal.SIGTERM, handle_shutdown)
    for required_command in ("prlimit", "setpriv"):
        if shutil.which(required_command) is None:
            raise RuntimeError(f"required job isolation command is unavailable: {required_command}")
    files = WorkspaceFiles(args.workspace, args.workspace_quota_bytes, args.job_uid, args.job_gid)
    files.prepare_job_tmp()
    jobs = JobEngine(files, args.job_uid, args.job_gid)
    control = GuestControl(files, jobs)
    listeners: list[socket.socket] = []
    try:
        if args.unix_socket:
            listeners.append(create_unix_listener(args.unix_socket, args.job_uid, args.job_gid))
        if args.vsock_port is not None:
            listeners.append(create_vsock_listener(args.vsock_port))
        stdio_thread: threading.Thread | None = None
        if args.stdio:
            stdio_thread = threading.Thread(
                target=serve_stdio,
                args=(control, os.fdopen(os.dup(0), "rb", buffering=0), os.fdopen(os.dup(1), "wb", buffering=0)),
                daemon=True,
                name="guest-control-stdio",
            )
            stdio_thread.start()
        if listeners:
            serve_sockets(control, listeners)
        elif stdio_thread is not None:
            while stdio_thread.is_alive():
                stdio_thread.join(0.25)
    except KeyboardInterrupt:
        pass
    finally:
        control.close()
        jobs.close()
        for listener in listeners:
            listener.close()
        if args.unix_socket:
            try:
                os.unlink(args.unix_socket)
            except FileNotFoundError:
                pass
        files.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
