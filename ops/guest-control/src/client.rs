//! Guest-local CLI client for the bloom-guest-control service.
//!
//! Connects to the Unix socket and provides `status`, `hello`, `files`, and
//! `jobs` subcommands — a direct port of the original Python `bloom-workspace`.

use base64::Engine;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

const SOCKET_PATH: &str = "/run/bloom/guest-control.sock";
const MAX_FRAME_BYTES: usize = 384 * 1024;
const MAX_CHUNK_BYTES: usize = 256 * 1024;

fn get_socket_path() -> String {
    std::env::var("BLOOM_GUEST_CONTROL_SOCKET").unwrap_or_else(|_| SOCKET_PATH.to_string())
}

fn send_request(operation: &str, fields: Value) -> Result<Value, String> {
    let id = format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let mut msg = json!({ "version": 1, "id": id, "operation": operation });
    if let Value::Object(ref mut map) = msg {
        if let Value::Object(fields_map) = fields {
            for (k, v) in fields_map {
                map.insert(k, v);
            }
        }
    }
    let frame = serde_json::to_string(&msg).map_err(|e| format!("serialize error: {e}"))?;
    let frame = frame + "\n";
    let frame_bytes = frame.as_bytes();
    if frame_bytes.len() > MAX_FRAME_BYTES {
        return Err("request exceeds the guest-control frame limit".into());
    }

    let socket_path = get_socket_path();
    let mut client = UnixStream::connect(&socket_path)
        .map_err(|e| format!("cannot connect to guest control socket: {e}"))?;
    client
        .write_all(frame_bytes)
        .map_err(|e| format!("socket write failed: {e}"))?;

    let mut response = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = client
            .read(&mut buf)
            .map_err(|e| format!("socket read failed: {e}"))?;
        if n == 0 {
            break;
        }
        response.extend_from_slice(&buf[..n]);
        if response.len() > MAX_FRAME_BYTES {
            break;
        }
        if response.contains(&b'\n') {
            break;
        }
    }

    let decoded: Value = serde_json::from_slice(&response)
        .map_err(|e| format!("invalid guest-control response: {e}"))?;
    if !decoded.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
        let code = decoded
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(|c| c.as_str())
            .unwrap_or("error");
        let msg = decoded
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .unwrap_or("request failed");
        return Err(format!("{code}: {msg}"));
    }
    Ok(decoded.get("result").cloned().unwrap_or(Value::Null))
}

fn print_json(value: &Value) {
    let pretty = serde_json::to_string_pretty(value).unwrap_or_default();
    println!("{pretty}");
}

pub fn run(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln!("usage: bloom-workspace <status|hello|files|jobs> ...");
        return 1;
    }

    let command = &args[0];
    let rest = &args[1..];

    match command.as_str() {
        "status" => match send_request("bloom.status", json!({})) {
            Ok(result) => {
                print_json(&result);
                0
            }
            Err(e) => {
                eprintln!("{e}");
                1
            }
        },
        "hello" => match send_request("hello", json!({})) {
            Ok(result) => {
                print_json(&result);
                0
            }
            Err(e) => {
                eprintln!("{e}");
                1
            }
        },
        "files" => {
            if rest.is_empty() {
                eprintln!("usage: bloom-workspace files <list|get|put|delete> ...");
                return 1;
            }
            let sub = &rest[0];
            let sub_args = &rest[1..];
            match sub.as_str() {
                "list" => {
                    if sub_args.len() < 1 {
                        eprintln!("usage: bloom-workspace files list <path>");
                        return 1;
                    }
                    match send_request("fs.list", json!({ "path": sub_args[0] })) {
                        Ok(result) => {
                            print_json(&result);
                            0
                        }
                        Err(e) => {
                            eprintln!("{e}");
                            1
                        }
                    }
                }
                "get" => {
                    if sub_args.len() < 2 {
                        eprintln!("usage: bloom-workspace files get <path> <output>");
                        return 1;
                    }
                    let path = &sub_args[0];
                    let output = &sub_args[1];
                    match download_file(path, output) {
                        Ok(()) => 0,
                        Err(e) => {
                            eprintln!("{e}");
                            1
                        }
                    }
                }
                "put" => {
                    if sub_args.len() < 2 {
                        eprintln!("usage: bloom-workspace files put <input> <path>");
                        return 1;
                    }
                    let input = &sub_args[0];
                    let path = &sub_args[1];
                    match upload_file(input, path) {
                        Ok(()) => 0,
                        Err(e) => {
                            eprintln!("{e}");
                            1
                        }
                    }
                }
                "delete" => {
                    if sub_args.len() < 1 {
                        eprintln!("usage: bloom-workspace files delete <path>");
                        return 1;
                    }
                    match send_request(
                        "fs.delete",
                        json!({ "path": sub_args[0], "recursive": false }),
                    ) {
                        Ok(result) => {
                            print_json(&result);
                            0
                        }
                        Err(e) => {
                            eprintln!("{e}");
                            1
                        }
                    }
                }
                _ => {
                    eprintln!("unknown files subcommand: {sub}");
                    1
                }
            }
        }
        "jobs" => {
            if rest.is_empty() {
                eprintln!("usage: bloom-workspace jobs <start|status|cancel> ...");
                return 1;
            }
            let sub = &rest[0];
            let sub_args = &rest[1..];
            match sub.as_str() {
                "start" => {
                    // Parse flags: --cwd, --timeout-ms, --env, then -- argv
                    let mut cwd = ".".to_string();
                    let mut timeout_ms: u64 = 15 * 60 * 1000;
                    let mut env: HashMap<String, String> = HashMap::new();
                    let mut argv: Vec<String> = Vec::new();
                    let mut i = 0;
                    while i < sub_args.len() {
                        match sub_args[i].as_str() {
                            "--cwd" => {
                                i += 1;
                                if i < sub_args.len() {
                                    cwd = sub_args[i].clone();
                                }
                            }
                            "--timeout-ms" => {
                                i += 1;
                                if i < sub_args.len() {
                                    timeout_ms = sub_args[i].parse().unwrap_or(15 * 60 * 1000);
                                }
                            }
                            "--env" => {
                                i += 1;
                                if i < sub_args.len() {
                                    if let Some((k, v)) = sub_args[i].split_once('=') {
                                        env.insert(k.to_string(), v.to_string());
                                    }
                                }
                            }
                            "--" => {
                                i += 1;
                                while i < sub_args.len() {
                                    argv.push(sub_args[i].clone());
                                    i += 1;
                                }
                            }
                            _ => {
                                argv.push(sub_args[i].clone());
                            }
                        }
                        i += 1;
                    }
                    if argv.is_empty() {
                        eprintln!("jobs start requires an argv after --");
                        return 1;
                    }
                    let job_id = format!(
                        "{:x}",
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos()
                    );
                    let env_json: Value = env
                        .into_iter()
                        .collect::<HashMap<_, _>>()
                        .into_iter()
                        .map(|(k, v)| (k, json!(v)))
                        .collect();
                    match send_request(
                        "job.start",
                        json!({
                            "jobId": job_id,
                            "argv": argv,
                            "cwd": cwd,
                            "environment": env_json,
                            "timeoutMs": timeout_ms,
                        }),
                    ) {
                        Ok(result) => {
                            print_json(&result);
                            0
                        }
                        Err(e) => {
                            eprintln!("{e}");
                            1
                        }
                    }
                }
                "status" => {
                    if sub_args.len() < 1 {
                        eprintln!("usage: bloom-workspace jobs status <job_id> [--cursor N]");
                        return 1;
                    }
                    let job_id = &sub_args[0];
                    let mut cursor: u64 = 0;
                    let mut i = 1;
                    while i < sub_args.len() {
                        if sub_args[i] == "--cursor" {
                            i += 1;
                            if i < sub_args.len() {
                                cursor = sub_args[i].parse().unwrap_or(0);
                            }
                        }
                        i += 1;
                    }
                    match send_request(
                        "job.status",
                        json!({
                            "jobId": job_id,
                            "logOffset": cursor,
                            "maxBytes": MAX_CHUNK_BYTES,
                        }),
                    ) {
                        Ok(result) => {
                            print_json(&result);
                            0
                        }
                        Err(e) => {
                            eprintln!("{e}");
                            1
                        }
                    }
                }
                "cancel" => {
                    if sub_args.len() < 1 {
                        eprintln!("usage: bloom-workspace jobs cancel <job_id>");
                        return 1;
                    }
                    match send_request("job.cancel", json!({ "jobId": sub_args[0] })) {
                        Ok(result) => {
                            print_json(&result);
                            0
                        }
                        Err(e) => {
                            eprintln!("{e}");
                            1
                        }
                    }
                }
                _ => {
                    eprintln!("unknown jobs subcommand: {sub}");
                    1
                }
            }
        }
        _ => {
            eprintln!("unknown command: {command}");
            1
        }
    }
}

fn download_file(path: &str, output: &str) -> Result<(), String> {
    let mut offset: u64 = 0;
    let mut file =
        std::fs::File::create(output).map_err(|e| format!("cannot create output file: {e}"))?;
    loop {
        let result = send_request(
            "fs.read",
            json!({
                "path": path,
                "offset": offset,
                "maxBytes": MAX_CHUNK_BYTES,
            }),
        )?;
        let data_b64 = result.get("data").and_then(|d| d.as_str()).unwrap_or("");
        let data = base64::engine::general_purpose::STANDARD
            .decode(data_b64)
            .map_err(|e| format!("base64 decode error: {e}"))?;
        file.write_all(&data)
            .map_err(|e| format!("write error: {e}"))?;
        offset = result
            .get("nextOffset")
            .and_then(|o| o.as_u64())
            .unwrap_or(offset + data.len() as u64);
        if result.get("eof").and_then(|e| e.as_bool()).unwrap_or(true) {
            break;
        }
    }
    print_json(&json!({ "path": path, "output": output, "size": offset }));
    Ok(())
}

fn upload_file(input: &str, path: &str) -> Result<(), String> {
    let metadata = std::fs::metadata(input).map_err(|e| format!("cannot stat input: {e}"))?;
    let size = metadata.len();
    if size > 8 * 1024 * 1024 {
        return Err("input exceeds the 8 MiB file limit".into());
    }
    let data = std::fs::read(input).map_err(|e| format!("cannot read input: {e}"))?;
    let mut offset: u64 = 0;
    let chunk_size = MAX_CHUNK_BYTES;
    let mut first = true;
    while offset < data.len() as u64 || first {
        let end = ((offset as usize) + chunk_size).min(data.len());
        let chunk = &data[offset as usize..end];
        let encoded = base64::engine::general_purpose::STANDARD.encode(chunk);
        let result = send_request(
            "fs.write",
            json!({
                "path": path,
                "offset": offset,
                "data": encoded,
                "truncate": first,
            }),
        )?;
        offset = result
            .get("nextOffset")
            .and_then(|o| o.as_u64())
            .unwrap_or(end as u64);
        first = false;
        if chunk.is_empty() {
            break;
        }
    }
    print_json(&json!({ "path": path, "size": offset }));
    Ok(())
}
