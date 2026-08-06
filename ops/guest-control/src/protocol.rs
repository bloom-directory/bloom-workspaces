//! JSON-line protocol frame encoding and decoding.

use crate::constants::*;
use crate::error::ControlError;
use serde_json::Value;

pub fn decode_frame(frame: &[u8]) -> Result<Value, ControlError> {
    if frame.len() > MAX_FRAME_BYTES {
        return Err(ControlError::limit_exceeded(
            "guest protocol frame is too large",
        ));
    }
    if !frame.ends_with(b"\n") {
        return Err(ControlError::invalid_request(
            "guest protocol frame must end with a newline",
        ));
    }
    let trimmed = &frame[..frame.len().saturating_sub(1)];
    serde_json::from_slice(trimmed)
        .map_err(|_| ControlError::invalid_request("guest protocol frame is not valid UTF-8 JSON"))
}

pub fn encode_response(response: &Value) -> Vec<u8> {
    let mut frame = serde_json::to_vec(response).unwrap_or_default();
    frame.push(b'\n');
    if frame.len() > MAX_FRAME_BYTES {
        let fallback = serde_json::json!({
            "version": PROTOCOL_VERSION,
            "id": response.get("id").and_then(|v| v.as_str()).unwrap_or("invalid"),
            "ok": false,
            "error": { "code": "internal", "message": "guest response exceeded the frame limit" }
        });
        frame = serde_json::to_vec(&fallback).unwrap_or_default();
        frame.push(b'\n');
    }
    frame
}

pub fn process_frame(control: &crate::control::GuestControl, frame: &[u8]) -> Vec<u8> {
    let response = match decode_frame(frame) {
        Ok(request) => control.handle(&request),
        Err(e) => serde_json::json!({
            "version": PROTOCOL_VERSION,
            "id": "invalid",
            "ok": false,
            "error": { "code": e.code, "message": e.message }
        }),
    };
    encode_response(&response)
}
