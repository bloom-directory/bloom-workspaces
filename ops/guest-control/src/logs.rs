//! Bounded log ring buffer with absolute offset tracking.

use crate::constants::*;
use crate::error::ControlError;
use base64::Engine;
use serde_json::{json, Value};
use std::sync::Mutex;

pub struct LogRing {
    data: Mutex<LogInner>,
}

struct LogInner {
    buf: Vec<u8>,
    start_offset: u64,
    end_offset: u64,
}

impl LogRing {
    pub fn new() -> Self {
        Self {
            data: Mutex::new(LogInner {
                buf: Vec::new(),
                start_offset: 0,
                end_offset: 0,
            }),
        }
    }

    pub fn append(&self, chunk: &[u8]) {
        if chunk.is_empty() {
            return;
        }
        let mut inner = self.data.lock().unwrap();
        inner.buf.extend_from_slice(chunk);
        inner.end_offset += chunk.len() as u64;
        let overflow = inner.buf.len() as i64 - MAX_LOG_BYTES as i64;
        if overflow > 0 {
            inner.buf.drain(..overflow as usize);
            inner.start_offset += overflow as u64;
        }
    }

    pub fn slice(
        &self,
        requested_offset: u64,
        maximum: usize,
        terminal: bool,
    ) -> Result<Value, ControlError> {
        let inner = self.data.lock().unwrap();
        if requested_offset > inner.end_offset {
            return Err(ControlError::invalid_request(
                "log cursor is beyond the current log end",
            ));
        }
        let offset = requested_offset.max(inner.start_offset);
        let relative = (offset - inner.start_offset) as usize;
        let end = (relative + maximum).min(inner.buf.len());
        let chunk = &inner.buf[relative..end];
        let next_offset = offset + chunk.len() as u64;
        let b64 = base64::engine::general_purpose::STANDARD.encode(chunk);
        Ok(json!({
            "offset": offset,
            "nextOffset": next_offset,
            "endOffset": inner.end_offset,
            "truncatedBefore": requested_offset < inner.start_offset,
            "eof": terminal && next_offset == inner.end_offset,
            "encoding": "base64",
            "data": b64,
        }))
    }

    pub fn end_offset(&self) -> u64 {
        self.data.lock().unwrap().end_offset
    }
}
