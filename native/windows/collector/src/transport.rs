use std::collections::{BTreeMap, VecDeque};
use std::env;
use std::io::Write;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use access_contract::{
    ContractValidator, JsonValue, JsonlValidator, ProtocolError, ValidationResult,
};
use windows::Win32::Foundation::{ERROR_BROKEN_PIPE, HANDLE};
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows::Win32::System::Console::{GetStdHandle, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};

use crate::protocol_model::{json_i64, json_u32, SystemCollectorClock};

pub const STDOUT_MAX_BYTES: usize = 524_288;
pub const STDOUT_STALL_TIMEOUT_MS: i64 = 250;
pub const DEBUG_TRACE_MAX_LINE_BYTES: usize = 4_000;

static DEBUG_ENABLED: OnceLock<bool> = OnceLock::new();
static DEBUG_STATE: OnceLock<Mutex<DebugRateLimit>> = OnceLock::new();

#[derive(Default)]
struct DebugRateLimit {
    last_key: String,
    last_ms: i64,
}

/// Content-free development diagnostics written as JSONL to `stderr`.
/// Enabled when `COMPUTER_ACCESS_DEBUG=1` or `DSH_COMPUTER_ACCESS_DEBUG=1`.
pub struct DebugTrace;

impl DebugTrace {
    pub fn enabled() -> bool {
        *DEBUG_ENABLED.get_or_init(|| {
            env::var("DSH_COMPUTER_ACCESS_DEBUG").as_deref() == Ok("1")
                || env::var("COMPUTER_ACCESS_DEBUG").as_deref() == Ok("1")
        })
    }

    pub fn record(
        code: &str,
        numbers: &[(&str, i64)],
        flags: &[(&str, bool)],
        strings: &[(&str, &str)],
        file: &str,
        line: u32,
    ) {
        if !Self::enabled() {
            return;
        }
        let state_lock = DEBUG_STATE.get_or_init(|| Mutex::new(DebugRateLimit::default()));
        let Ok(mut state) = state_lock.try_lock() else {
            return;
        };

        let mono = SystemCollectorClock::monotonic_ms_now();
        let find_str = |k: &str| {
            strings
                .iter()
                .find(|(key, _)| *key == k)
                .map(|(_, v)| *v)
                .unwrap_or("")
        };
        let find_num = |k: &str| {
            numbers
                .iter()
                .find(|(key, _)| *key == k)
                .map(|(_, v)| v.to_string())
                .unwrap_or_default()
        };
        let key = format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}",
            code,
            find_str("stage"),
            find_str("reason"),
            find_str("status"),
            find_str("phase"),
            find_str("outcome"),
            find_num("requestId"),
            find_num("readId"),
            find_num("nodeIndex")
        );
        if state.last_key == key && mono.saturating_sub(state.last_ms) < 1_000 {
            return;
        }
        state.last_key = key;
        state.last_ms = mono;

        let mut root = BTreeMap::new();
        root.insert("version".to_string(), json_i64(1));
        root.insert("code".to_string(), JsonValue::String(code.to_string()));
        root.insert("pid".to_string(), json_u32(std::process::id()));
        root.insert(
            "timeMs".to_string(),
            json_i64(SystemCollectorClock::unix_ms_now()),
        );
        root.insert("monotonicMs".to_string(), json_i64(mono));
        let basename = file.rsplit(['/', '\\']).next().unwrap_or("unknown");
        root.insert("file".to_string(), JsonValue::String(basename.to_string()));
        root.insert("line".to_string(), json_u32(line));

        let mut num_map = BTreeMap::new();
        for &(k, v) in numbers {
            num_map.insert(k.to_string(), json_i64(v));
        }
        root.insert("numbers".to_string(), JsonValue::Object(num_map));

        let mut flag_map = BTreeMap::new();
        for &(k, v) in flags {
            flag_map.insert(k.to_string(), JsonValue::Bool(v));
        }
        root.insert("flags".to_string(), JsonValue::Object(flag_map));

        if !strings.is_empty() {
            let mut str_map = BTreeMap::new();
            for &(k, raw) in strings {
                if matches!(k, "text" | "value" | "url" | "title" | "description" | "secret") {
                    continue;
                }
                if k == "applicationId" {
                    if raw.encode_utf16().count() <= 256 && !raw.chars().any(|c| c.is_control()) {
                        str_map.insert(k.to_string(), JsonValue::String(raw.to_string()));
                    }
                } else {
                    let clean: String = raw
                        .chars()
                        .filter(|c| !c.is_control())
                        .take(128)
                        .collect();
                    str_map.insert(k.to_string(), JsonValue::String(clean));
                }
            }
            if !str_map.is_empty() {
                root.insert("strings".to_string(), JsonValue::Object(str_map));
            }
        }

        let Ok(mut bytes) = JsonValue::Object(root).canonical_bytes() else {
            return;
        };
        if bytes.len() + 1 > DEBUG_TRACE_MAX_LINE_BYTES {
            return;
        }
        bytes.push(b'\n');
        let mut stderr = std::io::stderr().lock();
        let _ = stderr.write_all(&bytes);
        let _ = stderr.flush();
    }
}

/// Classification of outbound frame enqueue failures on `BoundedOutput`.
///
/// Per-message framing/validation errors (`EncodeFailed`) MUST NOT poison the stdout transport or
/// trigger exit 74 (`stdout-backpressure`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueError {
    EncodeFailed(ProtocolError),
    StdoutBackpressure,
    BrokenPipe,
}

struct OutputItem {
    data: Vec<u8>,
    is_observation: bool,
}

struct OutputState {
    queue: VecDeque<OutputItem>,
    queued_bytes: usize,
    max_pending: usize,
    in_flight_since_ms: Option<i64>,
    failed: bool,
    closed: bool,
}

/// Bounded asynchronous stdout transport with frame/byte/stall limits.
/// Prevents a slow or hung Host reader from blocking collector shutdown or worker reaping.
pub struct BoundedOutput {
    validator: ContractValidator,
    shared: Arc<(Mutex<OutputState>, Condvar)>,
}

impl BoundedOutput {
    pub fn new(validator: ContractValidator) -> Self {
        let shared = Arc::new((
            Mutex::new(OutputState {
                queue: VecDeque::new(),
                queued_bytes: 0,
                max_pending: 8,
                in_flight_since_ms: None,
                failed: false,
                closed: false,
            }),
            Condvar::new(),
        ));

        let writer_shared = Arc::clone(&shared);
        thread::spawn(move || {
            let stdout_handle = match unsafe { GetStdHandle(STD_OUTPUT_HANDLE) } {
                Ok(h) if !h.is_invalid() && !h.0.is_null() => h,
                _ => {
                    let (lock, cv) = &*writer_shared;
                    if let Ok(mut st) = lock.lock() {
                        st.failed = true;
                        cv.notify_all();
                    }
                    return;
                }
            };
            let raw_h = stdout_handle.0 as usize;
            Self::run_writer_loop(writer_shared, move |bytes| {
                write_all_handle(HANDLE(raw_h as *mut core::ffi::c_void), bytes)
            });
        });

        Self { validator, shared }
    }

    /// Construct a `BoundedOutput` backed by a custom sink callback (used by unit tests to verify
    /// encoding vs backpressure vs broken-pipe behavior deterministically without touching stdout).
    pub fn new_with_writer<F>(validator: ContractValidator, writer: F) -> Self
    where
        F: FnMut(&[u8]) -> bool + Send + 'static,
    {
        let shared = Arc::new((
            Mutex::new(OutputState {
                queue: VecDeque::new(),
                queued_bytes: 0,
                max_pending: 8,
                in_flight_since_ms: None,
                failed: false,
                closed: false,
            }),
            Condvar::new(),
        ));

        let writer_shared = Arc::clone(&shared);
        thread::spawn(move || {
            Self::run_writer_loop(writer_shared, writer);
        });

        Self { validator, shared }
    }

    fn run_writer_loop<F>(writer_shared: Arc<(Mutex<OutputState>, Condvar)>, mut writer: F)
    where
        F: FnMut(&[u8]) -> bool,
    {
        let (lock, cv) = &*writer_shared;
        loop {
            let item = {
                let mut st = match lock.lock() {
                    Ok(g) => g,
                    Err(_) => return,
                };
                while st.queue.is_empty() && !st.failed && !st.closed {
                    st = match cv.wait(st) {
                        Ok(g) => g,
                        Err(_) => return,
                    };
                }
                if st.failed {
                    return;
                }
                match st.queue.pop_front() {
                    Some(item) => {
                        st.queued_bytes = st.queued_bytes.saturating_sub(item.data.len());
                        st.in_flight_since_ms = Some(SystemCollectorClock::monotonic_ms_now());
                        item
                    }
                    None => {
                        // closed and queue empty
                        cv.notify_all();
                        return;
                    }
                }
            };

            let write_ok = writer(&item.data);

            let mut st = match lock.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            st.in_flight_since_ms = None;
            if !write_ok {
                st.failed = true;
            }
            cv.notify_all();
            if st.failed {
                return;
            }
        }
    }

    pub fn set_max_pending(&self, max_pending: usize) {
        let (lock, _) = &*self.shared;
        if let Ok(mut st) = lock.lock() {
            st.max_pending = max_pending.clamp(1, 64);
        }
    }

    /// Validate, encode, and enqueue an outbound Wire v1 message.
    ///
    /// Returns `Err(EnqueueError::EncodeFailed(_))` WITHOUT marking `failed = true` when a single
    /// message exceeds 65,536 bytes or fails schema validation. Marks `failed = true` ONLY on real
    /// stdout queue backpressure, stall timeout, or broken-pipe write failure.
    pub fn try_enqueue(&self, message: &JsonValue) -> Result<(), EnqueueError> {
        let data = self
            .validator
            .encode_frame(message)
            .map_err(EnqueueError::EncodeFailed)?;

        let (lock, cv) = &*self.shared;
        let Ok(mut st) = lock.lock() else {
            return Err(EnqueueError::BrokenPipe);
        };
        if st.failed {
            return Err(EnqueueError::BrokenPipe);
        }
        Self::check_stall_locked(&mut st);
        if st.failed {
            return Err(EnqueueError::StdoutBackpressure);
        }
        let is_observation = message.get("type").and_then(JsonValue::as_str) == Some("observation");
        let obs_count = st.queue.iter().filter(|i| i.is_observation).count();
        if st.queue.len() >= st.max_pending + 8
            || (is_observation && obs_count >= st.max_pending)
            || st.queued_bytes + data.len() > STDOUT_MAX_BYTES
        {
            st.failed = true;
            cv.notify_all();
            return Err(EnqueueError::StdoutBackpressure);
        }
        st.queued_bytes += data.len();
        st.queue.push_back(OutputItem {
            data,
            is_observation,
        });
        cv.notify_all();
        Ok(())
    }

    pub fn enqueue(&self, message: &JsonValue) {
        let _ = self.try_enqueue(message);
    }

    pub fn discard_observations(&self) {
        let (lock, _) = &*self.shared;
        if let Ok(mut st) = lock.lock() {
            st.queue.retain(|item| !item.is_observation);
            st.queued_bytes = st.queue.iter().map(|i| i.data.len()).sum();
        }
    }

    pub fn poll_health(&self) -> bool {
        let (lock, _) = &*self.shared;
        let Ok(mut st) = lock.lock() else {
            return false;
        };
        Self::check_stall_locked(&mut st);
        !st.failed
    }

    pub fn is_failed(&self) -> bool {
        let (lock, _) = &*self.shared;
        lock.lock().map(|st| st.failed).unwrap_or(true)
    }

    pub fn is_empty(&self) -> bool {
        let (lock, _) = &*self.shared;
        lock.lock()
            .map(|st| st.queue.is_empty() && st.in_flight_since_ms.is_none())
            .unwrap_or(true)
    }

    /// Block until all currently queued frames are flushed to stdout or `timeout_ms` elapses.
    pub fn flush_sync(&self, timeout_ms: u64) -> bool {
        let (lock, cv) = &*self.shared;
        let deadline = SystemCollectorClock::monotonic_ms_now() + timeout_ms as i64;
        let Ok(mut st) = lock.lock() else {
            return false;
        };
        while !st.failed && (!st.queue.is_empty() || st.in_flight_since_ms.is_some()) {
            Self::check_stall_locked(&mut st);
            if st.failed {
                return false;
            }
            let now = SystemCollectorClock::monotonic_ms_now();
            if now >= deadline {
                return false;
            }
            let wait = Duration::from_millis((deadline - now).min(20) as u64);
            st = match cv.wait_timeout(st, wait) {
                Ok((g, _)) => g,
                Err(_) => return false,
            };
        }
        !st.failed
    }

    pub fn close_and_drain(&self, timeout_ms: u64) -> bool {
        let ok = self.flush_sync(timeout_ms);
        let (lock, cv) = &*self.shared;
        if let Ok(mut st) = lock.lock() {
            st.closed = true;
            cv.notify_all();
        }
        ok && !self.is_failed()
    }

    fn check_stall_locked(st: &mut OutputState) {
        if let Some(started) = st.in_flight_since_ms {
            if SystemCollectorClock::monotonic_ms_now().saturating_sub(started)
                >= STDOUT_STALL_TIMEOUT_MS
            {
                st.failed = true;
            }
        }
    }
}

fn write_all_handle(handle: HANDLE, bytes: &[u8]) -> bool {
    let mut offset = 0usize;
    while offset < bytes.len() {
        let mut written: u32 = 0;
        // SAFETY: Valid stdout HANDLE and valid remaining byte slice.
        let res = unsafe { WriteFile(handle, Some(&bytes[offset..]), Some(&mut written), None) };
        if res.is_err() || written == 0 {
            return false;
        }
        offset += written as usize;
    }
    true
}

struct InputQueue {
    frames: VecDeque<ValidationResult>,
    eof: bool,
}

/// Asynchronous stdin NDJSON reader using `access_contract::JsonlValidator`.
pub struct InputFrames {
    shared: Arc<Mutex<InputQueue>>,
}

impl InputFrames {
    pub fn spawn(validator: ContractValidator) -> Self {
        let shared = Arc::new(Mutex::new(InputQueue {
            frames: VecDeque::new(),
            eof: false,
        }));
        let reader_shared = Arc::clone(&shared);
        thread::spawn(move || {
            let stdin_handle = match unsafe { GetStdHandle(STD_INPUT_HANDLE) } {
                Ok(h) if !h.is_invalid() && !h.0.is_null() => h,
                _ => {
                    if let Ok(mut q) = reader_shared.lock() {
                        q.eof = true;
                    }
                    return;
                }
            };
            let raw_h = stdin_handle.0 as usize;
            let mut jsonl = JsonlValidator::new(validator);
            let mut chunk = [0u8; 4_096];

            loop {
                // Simple backpressure if queue grows very large before main loop drains.
                loop {
                    let len = reader_shared.lock().map(|q| q.frames.len()).unwrap_or(0);
                    if len < 256 {
                        break;
                    }
                    thread::sleep(Duration::from_millis(5));
                }

                let mut read_count: u32 = 0;
                // SAFETY: Valid stdin HANDLE and stack buffer.
                let res = unsafe {
                    ReadFile(
                        HANDLE(raw_h as *mut core::ffi::c_void),
                        Some(&mut chunk),
                        Some(&mut read_count),
                        None,
                    )
                };
                match res {
                    Ok(()) if read_count == 0 => {
                        let _ = jsonl.finish(|item| {
                            if let Ok(mut q) = reader_shared.lock() {
                                q.frames.push_back(item);
                            }
                            Ok::<(), ()>(())
                        });
                        if let Ok(mut q) = reader_shared.lock() {
                            q.eof = true;
                        }
                        return;
                    }
                    Ok(()) => {
                        let _ = jsonl.push(&chunk[..read_count as usize], |item| {
                            if let Ok(mut q) = reader_shared.lock() {
                                q.frames.push_back(item);
                            }
                            Ok::<(), ()>(())
                        });
                    }
                    Err(err) if err.code() == ERROR_BROKEN_PIPE.to_hresult() => {
                        let _ = jsonl.finish(|item| {
                            if let Ok(mut q) = reader_shared.lock() {
                                q.frames.push_back(item);
                            }
                            Ok::<(), ()>(())
                        });
                        if let Ok(mut q) = reader_shared.lock() {
                            q.eof = true;
                        }
                        return;
                    }
                    Err(_) => {
                        if let Ok(mut q) = reader_shared.lock() {
                            q.eof = true;
                        }
                        return;
                    }
                }
            }
        });

        Self { shared }
    }

    /// Drains up to `max_frames` validated frames without blocking.
    /// Returns `false` once stdin reaches EOF and all buffered frames have been drained.
    pub fn drain<F>(&mut self, max_frames: usize, mut emit: F) -> bool
    where
        F: FnMut(ValidationResult),
    {
        let mut batch = Vec::new();
        let eof;
        {
            let Ok(mut q) = self.shared.lock() else {
                return false;
            };
            for _ in 0..max_frames {
                if let Some(item) = q.frames.pop_front() {
                    batch.push(item);
                } else {
                    break;
                }
            }
            eof = q.eof && q.frames.is_empty();
        }
        for item in batch {
            emit(item);
        }
        !eof
    }
}
