use std::collections::BTreeMap;
use std::env;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use access_contract::{utf16_len, JsonValue};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, DuplicateHandle, SetHandleInformation, DUPLICATE_HANDLE_OPTIONS,
    DUPLICATE_SAME_ACCESS, ERROR_BROKEN_PIPE, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::Memory::{
    CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, VirtualQuery, FILE_MAP_ALL_ACCESS,
    MEMORY_BASIC_INFORMATION, MEMORY_MAPPED_VIEW_ADDRESS, PAGE_READWRITE,
};
use windows::Win32::System::Pipes::{CreatePipe, PeekNamedPipe};
use windows::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess, GetExitCodeProcess,
    InitializeProcThreadAttributeList, ResumeThread, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW,
};

use crate::fixture;
use crate::input_activity_win32::VerifiedNormalBrowserWindow;
use crate::menu_action_core::MenuActionRecord;
use crate::ownership::{CliOptions, ParentProcessHandle};
use crate::protocol_model::{
    generate_uuid_v4, json_i64, AxEnablementResult, CapturePolicy, CollectorClock, GapDiagnostic,
    GapDiagnosticCode, SelectionReadResult, SourceHint, SurfaceReadFailure, SurfaceReadResult,
    SystemCollectorClock, TextRead, WorkerSurfaceIdentity, MAX_SAFE_INTEGER,
};
use crate::transport::DebugTrace;
use crate::uia_worker::{execute_live_one_shot, LiveUiaSession};

pub const SESSION_READ_DEADLINE_EXIT: i32 = 76;
pub const WORKER_PROGRESS_ENV: &str = "DSH_COLLECTOR_PROGRESS_HANDLE";
pub const WORKER_TOKEN_ENV: &str = "DSH_COLLECTOR_WORKER_TOKEN";
pub const WORKER_PARENT_HANDLE_ENV: &str = "DSH_COLLECTOR_PARENT_HANDLE";
pub const WORKER_MAX_FRAME_BYTES: usize = 65_536;
pub const WORKER_MAX_PIPE_BUFFER_BYTES: usize = 256 * 1024;

const PROGRESS_PAGE_BYTES: usize = 4_096;
const ESSENTIAL_WINDOWS_ENV_KEYS: &[&str] = &[
    "SystemRoot",
    "WINDIR",
    "SystemDrive",
    "ComSpec",
    "PATH",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "LOCALAPPDATA",
    "APPDATA",
    "PATHEXT",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadTicket {
    pub token: String,
    pub policy_revision: i64,
    pub capture_epoch: i64,
    pub policy: CapturePolicy,
    pub hint: Option<SourceHint>,
    pub deadline_monotonic_ms: i64,
    pub device_id: String,
    pub os_session_id: String,
    pub desktop_id: String,
    pub foreground_generation: Option<i64>,
    pub focus_generation: Option<i64>,
    pub debug_request_id: Option<i64>,
    pub read_only_ax_enablement: Option<bool>,
    pub focused_fast_only: Option<bool>,
}

impl ReadTicket {
    pub fn from_json(value: &JsonValue) -> Option<Self> {
        let obj = value.as_obj()?;
        let token = obj.get("token")?.as_str()?.to_string();
        let policy_revision = obj.get("policyRevision")?.as_i64()?;
        let capture_epoch = obj.get("captureEpoch")?.as_i64()?;
        let policy = CapturePolicy::from_json(obj.get("policy")?)?;
        let hint = match obj.get("hint") {
            None | Some(JsonValue::Null) => None,
            Some(v) => Some(SourceHint::from_json(v)?),
        };
        let deadline_monotonic_ms = obj.get("deadlineMonotonicMs")?.as_i64()?;
        let device_id = obj.get("deviceId")?.as_str()?.to_string();
        let os_session_id = obj.get("osSessionId")?.as_str()?.to_string();
        let desktop_id = obj.get("desktopId")?.as_str()?.to_string();
        let opt_i64 = |k: &str| -> Result<Option<i64>, ()> {
            match obj.get(k) {
                None | Some(JsonValue::Null) => Ok(None),
                Some(v) => v.as_i64().map(Some).ok_or(()),
            }
        };
        let opt_bool = |k: &str| -> Result<Option<bool>, ()> {
            match obj.get(k) {
                None | Some(JsonValue::Null) => Ok(None),
                Some(v) => v.as_bool().map(Some).ok_or(()),
            }
        };
        Some(Self {
            token,
            policy_revision,
            capture_epoch,
            policy,
            hint,
            deadline_monotonic_ms,
            device_id,
            os_session_id,
            desktop_id,
            foreground_generation: opt_i64("foregroundGeneration").ok()?,
            focus_generation: opt_i64("focusGeneration").ok()?,
            debug_request_id: opt_i64("debugRequestId").ok()?,
            read_only_ax_enablement: opt_bool("readOnlyAXEnablement").ok()?,
            focused_fast_only: opt_bool("focusedFastOnly").ok()?,
        })
    }

    pub fn to_json(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("token".to_string(), JsonValue::String(self.token.clone()));
        map.insert("policyRevision".to_string(), json_i64(self.policy_revision));
        map.insert("captureEpoch".to_string(), json_i64(self.capture_epoch));
        map.insert("policy".to_string(), self.policy.to_json());
        if let Some(ref hint) = self.hint {
            map.insert("hint".to_string(), hint.to_json());
        }
        map.insert(
            "deadlineMonotonicMs".to_string(),
            json_i64(self.deadline_monotonic_ms),
        );
        map.insert(
            "deviceId".to_string(),
            JsonValue::String(self.device_id.clone()),
        );
        map.insert(
            "osSessionId".to_string(),
            JsonValue::String(self.os_session_id.clone()),
        );
        map.insert(
            "desktopId".to_string(),
            JsonValue::String(self.desktop_id.clone()),
        );
        if let Some(v) = self.foreground_generation {
            map.insert("foregroundGeneration".to_string(), json_i64(v));
        }
        if let Some(v) = self.focus_generation {
            map.insert("focusGeneration".to_string(), json_i64(v));
        }
        if let Some(v) = self.debug_request_id {
            map.insert("debugRequestId".to_string(), json_i64(v));
        }
        if let Some(v) = self.read_only_ax_enablement {
            map.insert("readOnlyAXEnablement".to_string(), JsonValue::Bool(v));
        }
        if let Some(v) = self.focused_fast_only {
            map.insert("focusedFastOnly".to_string(), JsonValue::Bool(v));
        }
        JsonValue::Object(map)
    }

    pub fn valid_debug_request_id(&self) -> Option<i64> {
        self.debug_request_id
            .filter(|&v| (1..=MAX_SAFE_INTEGER).contains(&v))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReadResult {
    pub token: String,
    pub application: Option<crate::protocol_model::ApplicationIdentity>,
    pub diagnostic_application: Option<crate::protocol_model::ApplicationIdentity>,
    /// Internal worker->parent IPC secondary `.exe` basename for dual-ID defense-in-depth
    /// (NEVER emitted on the external collector wire protocol).
    pub exe_name: Option<String>,
    pub text: Option<TextRead>,
    pub reason: Option<String>,
    pub diagnostic: Option<GapDiagnostic>,
    pub enablement: Option<AxEnablementResult>,
    pub session_identity: Option<WorkerSurfaceIdentity>,
    pub surface: Option<SurfaceReadResult>,
    pub selection: Option<SelectionReadResult>,
    pub private_state: Option<String>,
    pub observer_status: Option<String>,
    pub focus_absent: Option<bool>,
    pub surface_failure: Option<SurfaceReadFailure>,
    /// Internal worker->parent IPC verified non-private browser window token for zero-COM
    /// `input.activity` gating (NEVER emitted on the external collector wire protocol).
    pub verified_normal_browser: Option<VerifiedNormalBrowserWindow>,
    pub capture_start_ms: i64,
    pub capture_end_ms: i64,
}

impl ReadResult {
    pub fn failure(
        token: impl Into<String>,
        reason: impl Into<String>,
        diagnostic: Option<GapDiagnostic>,
        capture_start_ms: i64,
        capture_end_ms: i64,
    ) -> Self {
        Self {
            token: token.into(),
            application: None,
            diagnostic_application: None,
            exe_name: None,
            text: None,
            reason: Some(reason.into()),
            diagnostic,
            enablement: None,
            session_identity: None,
            surface: None,
            selection: None,
            private_state: None,
            observer_status: None,
            focus_absent: None,
            surface_failure: None,
            verified_normal_browser: None,
            capture_start_ms,
            capture_end_ms: capture_end_ms.max(capture_start_ms),
        }
    }

    pub fn valid_surface(&self, policy: &CapturePolicy) -> bool {
        let (Some(identity), Some(surface)) = (&self.session_identity, &self.surface) else {
            return false;
        };
        if policy.capture_scope.as_deref() != Some(surface.scope.as_str())
            || surface.surface_id != identity.surface_id
            || surface.nodes.len() > policy.max_tree_nodes.unwrap_or(64)
            || surface.nodes.len() > 96
        {
            return false;
        }
        let mut remaining = policy.max_text_code_units.min(8_192);
        for node in &surface.nodes {
            if node.observed_at_ms < self.capture_start_ms
                || node.observed_at_ms > self.capture_end_ms
            {
                return false;
            }
            let units = node.text.as_deref().map(utf16_len).unwrap_or(0);
            if units > remaining {
                return false;
            }
            remaining -= units;
        }
        true
    }

    pub fn valid_window_only_channels(&self, policy: &CapturePolicy) -> bool {
        if self.focus_absent != Some(true) {
            return true;
        }
        if policy.capture_scope.as_deref() != Some("window")
            || self.reason.is_some()
            || self.surface_failure.is_some()
            || self.diagnostic.map(|d| d.code) != Some(GapDiagnosticCode::FocusedFieldUnavailable)
            || self.text.is_some()
            || self.selection.is_some()
            || !self.valid_surface(policy)
        {
            return false;
        }
        let Some(ref surface) = self.surface else {
            return false;
        };
        surface.scope == "window"
            && !surface.nodes.is_empty()
            && surface.nodes.iter().all(|n| n.focused != Some(true))
    }

    pub fn from_json(value: &JsonValue) -> Option<Self> {
        let obj = value.as_obj()?;
        let token = obj.get("token")?.as_str()?.to_string();
        let application = match obj.get("application") {
            None | Some(JsonValue::Null) => None,
            Some(v) => Some(crate::protocol_model::ApplicationIdentity::from_json(v)?),
        };
        let diagnostic_application = match obj.get("diagnosticApplication") {
            None | Some(JsonValue::Null) => None,
            Some(v) => Some(crate::protocol_model::ApplicationIdentity::from_json(v)?),
        };
        let exe_name = match obj.get("exeName") {
            None | Some(JsonValue::Null) => None,
            Some(v) => Some(v.as_str()?.to_string()),
        };
        let text = match obj.get("text") {
            None | Some(JsonValue::Null) => None,
            Some(v) => Some(TextRead::from_json(v)?),
        };
        let reason = match obj.get("reason") {
            None | Some(JsonValue::Null) => None,
            Some(v) => Some(v.as_str()?.to_string()),
        };
        let diagnostic = match obj.get("diagnostic") {
            None | Some(JsonValue::Null) => None,
            Some(v) => Some(GapDiagnostic::from_json(v)?),
        };
        let enablement = match obj.get("enablement") {
            None | Some(JsonValue::Null) => None,
            Some(v) => Some(AxEnablementResult::from_json(v)?),
        };
        let session_identity = match obj.get("sessionIdentity") {
            None | Some(JsonValue::Null) => None,
            Some(v) => Some(WorkerSurfaceIdentity::from_json(v)?),
        };
        let surface = match obj.get("surface") {
            None | Some(JsonValue::Null) => None,
            Some(v) => Some(SurfaceReadResult::from_json(v)?),
        };
        let selection = match obj.get("selection") {
            None | Some(JsonValue::Null) => None,
            Some(v) => Some(SelectionReadResult::from_json(v)?),
        };
        let private_state = match obj.get("privateState") {
            None | Some(JsonValue::Null) => None,
            Some(v) => Some(v.as_str()?.to_string()),
        };
        let observer_status = match obj.get("observerStatus") {
            None | Some(JsonValue::Null) => None,
            Some(v) => Some(v.as_str()?.to_string()),
        };
        let focus_absent = match obj.get("focusAbsent") {
            None | Some(JsonValue::Null) => None,
            Some(v) => Some(v.as_bool()?),
        };
        let surface_failure = match obj.get("surfaceFailure") {
            None | Some(JsonValue::Null) => None,
            Some(v) => Some(SurfaceReadFailure::parse(v.as_str()?)?),
        };
        let verified_normal_browser = match obj.get("verifiedNormalBrowser") {
            None | Some(JsonValue::Null) => None,
            Some(v) => {
                let bobj = v.as_obj()?;
                let hwnd_raw = isize::try_from(bobj.get("hwndRaw")?.as_i64()?).ok()?;
                let effective_pid = u32::try_from(bobj.get("effectivePid")?.as_i64()?).ok()?;
                let process_start_time = bobj.get("processStartTime")?.as_str()?.to_string();
                let title_sha256 = bobj.get("titleSha256")?.as_str()?.to_string();
                let title_utf16_len = u32::try_from(bobj.get("titleUtf16Len")?.as_i64()?).ok()?;
                let tok = VerifiedNormalBrowserWindow {
                    hwnd_raw,
                    effective_pid,
                    process_start_time,
                    title_sha256,
                    title_utf16_len,
                };
                tok.is_valid().then_some(tok)
            }
        };
        let capture_start_ms = obj.get("captureStartMs")?.as_i64()?;
        let capture_end_ms = obj.get("captureEndMs")?.as_i64()?;
        Some(Self {
            token,
            application,
            diagnostic_application,
            exe_name,
            text,
            reason,
            diagnostic,
            enablement,
            session_identity,
            surface,
            selection,
            private_state,
            observer_status,
            focus_absent,
            surface_failure,
            verified_normal_browser,
            capture_start_ms,
            capture_end_ms,
        })
    }

    pub fn to_json(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("token".to_string(), JsonValue::String(self.token.clone()));
        if let Some(ref app) = self.application {
            map.insert("application".to_string(), app.to_json());
        }
        if let Some(ref dapp) = self.diagnostic_application {
            map.insert("diagnosticApplication".to_string(), dapp.to_json());
        }
        if let Some(ref exe) = self.exe_name {
            map.insert("exeName".to_string(), JsonValue::String(exe.clone()));
        }
        if let Some(ref text) = self.text {
            map.insert("text".to_string(), text.to_json());
        }
        if let Some(ref reason) = self.reason {
            map.insert("reason".to_string(), JsonValue::String(reason.clone()));
        }
        if let Some(diag) = self.diagnostic {
            map.insert("diagnostic".to_string(), diag.to_json());
        }
        if let Some(ref en) = self.enablement {
            map.insert("enablement".to_string(), en.to_json());
        }
        if let Some(ref id) = self.session_identity {
            map.insert("sessionIdentity".to_string(), id.to_json());
        }
        if let Some(ref surface) = self.surface {
            map.insert("surface".to_string(), surface.to_json());
        }
        if let Some(ref selection) = self.selection {
            map.insert("selection".to_string(), selection.to_json());
        }
        if let Some(ref ps) = self.private_state {
            map.insert("privateState".to_string(), JsonValue::String(ps.clone()));
        }
        if let Some(ref os) = self.observer_status {
            map.insert("observerStatus".to_string(), JsonValue::String(os.clone()));
        }
        if let Some(fa) = self.focus_absent {
            map.insert("focusAbsent".to_string(), JsonValue::Bool(fa));
        }
        if let Some(sf) = self.surface_failure {
            map.insert(
                "surfaceFailure".to_string(),
                JsonValue::String(sf.as_str().to_string()),
            );
        }
        if let Some(ref vnb) = self.verified_normal_browser {
            if vnb.is_valid() {
                let mut bmap = BTreeMap::new();
                bmap.insert("hwndRaw".to_string(), json_i64(vnb.hwnd_raw as i64));
                bmap.insert(
                    "effectivePid".to_string(),
                    json_i64(i64::from(vnb.effective_pid)),
                );
                bmap.insert(
                    "processStartTime".to_string(),
                    JsonValue::String(vnb.process_start_time.clone()),
                );
                bmap.insert(
                    "titleSha256".to_string(),
                    JsonValue::String(vnb.title_sha256.clone()),
                );
                bmap.insert(
                    "titleUtf16Len".to_string(),
                    json_i64(i64::from(vnb.title_utf16_len)),
                );
                map.insert("verifiedNormalBrowser".to_string(), JsonValue::Object(bmap));
            }
        }
        map.insert("captureStartMs".to_string(), json_i64(self.capture_start_ms));
        map.insert("captureEndMs".to_string(), json_i64(self.capture_end_ms));
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadTimeoutCleanup {
    AwaitingExit,
    Reaped,
    Unconfirmed,
    Ineligible,
}

#[derive(Debug, Clone, PartialEq)]
pub enum WorkerEvent {
    Completed(Box<ReadResult>),
    Dirty,
    SubmitDirty,
    MenuTracking(bool),
    MenuAction(Box<MenuActionRecord>),
    InputDisabled(String),
    SecureInput,
    ReadDeadlineReached(Box<ReadTicket>),
    WorkerExitUnconfirmed,
    SessionWorkerExitedUnexpectedly,
}

/// Outcome of classifying a single stdout frame from a retiring session worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetiringFrameOutcome {
    Acknowledged,
    AckFailed,
    InputDisabled(String),
    IgnoreInFlight,
}

/// Pure classifier for stdout frames received while a session worker is actively retiring.
///
/// Malformed JSON (`JsonValue::parse` error), invalid `menuAction` payloads, mismatched/unhealthy
/// `retired` acks, or trailing frames/bytes after `retired` MUST fail closed with `AckFailed`
/// (emitting `WorkerEvent::InputDisabled("worker-retirement-ack-failed")`).
pub fn classify_retiring_session_frame(
    frame: &[u8],
    session_token: &str,
    retire_token: &str,
    is_last_frame_with_empty_tail: bool,
) -> RetiringFrameOutcome {
    let Ok(parsed) = JsonValue::parse(frame) else {
        return RetiringFrameOutcome::AckFailed;
    };
    if let Some(reason) = parsed.get("inputDisabled").and_then(JsonValue::as_str) {
        return RetiringFrameOutcome::InputDisabled(reason.to_string());
    }
    if let Some(obj) = parsed.as_obj() {
        if obj.len() == 1 {
            if let Some(menu_val) = obj.get("menuAction") {
                return if MenuActionRecord::from_json(menu_val).is_some() {
                    RetiringFrameOutcome::IgnoreInFlight
                } else {
                    RetiringFrameOutcome::AckFailed
                };
            }
        }
    }
    if let Some(retired_val) = parsed.get("retired") {
        let Some(retired_tok) = retired_val.as_str() else {
            return RetiringFrameOutcome::AckFailed;
        };
        let obj_ok = parsed.as_obj().map(|o| o.len() == 3).unwrap_or(false)
            && parsed.get("sessionToken").and_then(JsonValue::as_str) == Some(session_token)
            && retired_tok == retire_token
            && parsed.get("inputHealthy").and_then(JsonValue::as_bool) == Some(true)
            && is_last_frame_with_empty_tail;
        return if obj_ok {
            RetiringFrameOutcome::Acknowledged
        } else {
            RetiringFrameOutcome::AckFailed
        };
    }
    RetiringFrameOutcome::IgnoreInFlight
}

/// Encode a `ReadResult` for worker->parent pipe transport (`< 65_500` bytes + `\n`).
///
/// If the initial canonical JSON reaches or exceeds `65_500` bytes while carrying an internal
/// `verified_normal_browser` token, clears `result.verified_normal_browser = None` and retries
/// encoding once BEFORE failing closed (`None` -> exit 70).
pub fn encode_read_result_pipe_frame(result: &mut ReadResult) -> Option<Vec<u8>> {
    let mut encoded = result.to_json().canonical_bytes().ok()?;
    if encoded.len() >= 65_500 && result.verified_normal_browser.is_some() {
        result.verified_normal_browser = None;
        encoded = result.to_json().canonical_bytes().ok()?;
    }
    if encoded.len() >= 65_500 {
        return None;
    }
    encoded.push(b'\n');
    Some(encoded)
}

/// Classify what `WorkerEvent` (if any) to emit after an unexpected `eof` or `pipe_err` on a
/// worker pipe (once child cancellation has been confirmed).
///
/// An idle session worker (`is_session && active_ticket.is_none() && !retiring && !input_text`)
/// terminating unexpectedly MUST emit `WorkerEvent::SessionWorkerExitedUnexpectedly` so
/// `CollectorEngine` clears `menu_tracking_until_ms`, `verified_normal_browser`, buffered
/// `input.activity`, and the active epoch anchor instead of cancelling silently.
pub fn classify_worker_pipe_termination(
    is_session: bool,
    active_ticket: Option<&ReadTicket>,
    input_text_enabled: bool,
    retiring: bool,
) -> Option<WorkerEvent> {
    if input_text_enabled || retiring {
        Some(WorkerEvent::InputDisabled(
            "input-monitoring-unavailable".to_string(),
        ))
    } else if let Some(t) = active_ticket {
        let now = SystemCollectorClock::unix_ms_now();
        Some(WorkerEvent::Completed(Box::new(ReadResult::failure(
            t.token.clone(),
            "read-error",
            None,
            now,
            now,
        ))))
    } else if is_session {
        Some(WorkerEvent::SessionWorkerExitedUnexpectedly)
    } else {
        None
    }
}

/// Pipe-batch precedence classification for session workers (`inputDisabled` > `secureInput` >
/// content frames), matching macOS `Worker.swift`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionBatchPrecedence {
    InputDisabled(String),
    SecureInput,
    Normal,
}

/// Classify a complete batch of `\n`-delimited session-worker frames BEFORE dispatching any
/// content reply so a boundary notice (`inputDisabled` or `secureInput`) always outranks every
/// content frame (`ReadResult`, `menuAction`, `menuTracking`, `submitDirty`, `dirty`) in the
/// same pipe read batch, even when the content frame appeared earlier in the byte stream.
pub fn classify_session_pipe_batch(frames: &[&[u8]]) -> SessionBatchPrecedence {
    for frame in frames {
        if let Ok(parsed) = JsonValue::parse(frame) {
            if let Some(reason) = parsed.get("inputDisabled").and_then(JsonValue::as_str) {
                return SessionBatchPrecedence::InputDisabled(reason.to_string());
            }
        }
    }
    if frames.iter().any(|f| *f == b"{\"secureInput\":true}") {
        return SessionBatchPrecedence::SecureInput;
    }
    SessionBatchPrecedence::Normal
}

/// Encode a single-key `{"menuAction": ...}\n` pipe frame (carrying internal-only `exeName` for
/// parent dual-ID defense-in-depth), rejecting frames >= 65,500 bytes.
pub fn encode_menu_action_pipe_frame(record: &MenuActionRecord) -> Option<Vec<u8>> {
    if !record.is_valid() {
        return None;
    }
    let mut map = BTreeMap::new();
    map.insert("menuAction".to_string(), record.to_json());
    let mut encoded = JsonValue::Object(map).canonical_bytes().ok()?;
    if encoded.len() >= 65_500 {
        return None;
    }
    encoded.push(b'\n');
    Some(encoded)
}

/// Priority selector for unsolicited session-worker pipe frames, matching macOS
/// `SessionTransport.swift`:
/// `menuAction` > `menuTracking` > `submitDirty` > debounced `dirty`.
#[allow(clippy::too_many_arguments)]
pub fn next_session_unsolicited_frame<S>(
    source: &mut S,
    take_menu_action: impl FnOnce(&mut S) -> Option<MenuActionRecord>,
    take_menu_tracking: impl FnOnce(&mut S) -> Option<bool>,
    take_submit_dirty: impl FnOnce(&mut S) -> bool,
    take_dirty: impl FnOnce(&mut S) -> bool,
    now_ms: i64,
    next_dirty_ms: &mut i64,
    debounce_ms: i64,
) -> Option<Vec<u8>> {
    if let Some(record) = take_menu_action(source) {
        if let Some(encoded) = encode_menu_action_pipe_frame(&record) {
            return Some(encoded);
        }
    }
    if let Some(tracking) = take_menu_tracking(source) {
        return Some(if tracking {
            b"{\"menuTracking\":true}\n".to_vec()
        } else {
            b"{\"menuTracking\":false}\n".to_vec()
        });
    }
    if take_submit_dirty(source) {
        return Some(b"{\"submitDirty\":true}\n".to_vec());
    }
    if now_ms >= *next_dirty_ms && take_dirty(source) {
        *next_dirty_ms = now_ms.saturating_add(debounce_ms.max(50));
        return Some(b"{\"dirty\":true}\n".to_vec());
    }
    None
}

/// Lock-free anonymous shared-memory progress page layout shared between parent and worker.
#[repr(C)]
pub struct ProgressPageLayout {
    pub seq: AtomicU64,
    pub request_id: AtomicI64,
    pub read_id: AtomicI64,
    pub deadline_ms: AtomicI64,
    pub operation: AtomicI64,
    pub api: AtomicI64,
    pub attribute: AtomicI64,
    pub phase: AtomicI64,
    pub status: AtomicI64,
    pub index: AtomicI64,
    pub started_ms: AtomicI64,
    pub updated_ms: AtomicI64,
    pub focus_deadline_ms: AtomicI64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ProgressSnapshot {
    pub request_id: i64,
    pub read_id: i64,
    pub deadline_ms: i64,
    pub operation: i64,
    pub api: i64,
    pub attribute: i64,
    pub phase: i64,
    pub status: i64,
    pub index: i64,
    pub started_ms: i64,
    pub updated_ms: i64,
    pub focus_deadline_ms: i64,
}

/// Parent-side owner of an anonymous inheritable Windows shared-memory progress mapping.
pub struct WorkerProgressPage {
    mapping_handle: Option<HANDLE>,
    view: MEMORY_MAPPED_VIEW_ADDRESS,
}

// SAFETY: Mapping view is owned exclusively by this struct and only read atomically.
unsafe impl Send for WorkerProgressPage {}

impl WorkerProgressPage {
    pub fn create_inheritable() -> Option<Self> {
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: core::ptr::null_mut(),
            bInheritHandle: true.into(),
        };
        // SAFETY: Anonymous page-file-backed 4096-byte shared mapping with inheritable handle.
        unsafe {
            let handle = CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                Some(&sa),
                PAGE_READWRITE,
                0,
                PROGRESS_PAGE_BYTES as u32,
                PCWSTR::null(),
            )
            .ok()?;
            if handle.is_invalid() || handle.0.is_null() {
                return None;
            }
            let view = MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, PROGRESS_PAGE_BYTES);
            if view.Value.is_null() {
                let _ = CloseHandle(handle);
                return None;
            }
            core::ptr::write_bytes(view.Value, 0, PROGRESS_PAGE_BYTES);
            Some(Self {
                mapping_handle: Some(handle),
                view,
            })
        }
    }

    pub fn raw_handle(&self) -> Option<HANDLE> {
        self.mapping_handle
    }

    /// Close the inheritable section handle in the parent after child creation; view stays valid.
    pub fn close_section_handle(&mut self) {
        if let Some(h) = self.mapping_handle.take() {
            // SAFETY: Owned handle closed once after child spawn.
            unsafe {
                let _ = CloseHandle(h);
            }
        }
    }

    fn layout(&self) -> &ProgressPageLayout {
        // SAFETY: View is 4096-byte page-aligned allocation larger than ProgressPageLayout.
        unsafe { &*(self.view.Value as *const ProgressPageLayout) }
    }

    pub fn ended_inside_initial_focus(&self, deadline_ms: i64) -> bool {
        deadline_ms > 0 && self.layout().focus_deadline_ms.load(Ordering::Acquire) == deadline_ms
    }

    pub fn read_snapshot(&self) -> Option<ProgressSnapshot> {
        let layout = self.layout();
        for _ in 0..4 {
            let s1 = layout.seq.load(Ordering::Acquire);
            if !s1.is_multiple_of(2) {
                continue;
            }
            let snap = ProgressSnapshot {
                request_id: layout.request_id.load(Ordering::Relaxed),
                read_id: layout.read_id.load(Ordering::Relaxed),
                deadline_ms: layout.deadline_ms.load(Ordering::Relaxed),
                operation: layout.operation.load(Ordering::Relaxed),
                api: layout.api.load(Ordering::Relaxed),
                attribute: layout.attribute.load(Ordering::Relaxed),
                phase: layout.phase.load(Ordering::Relaxed),
                status: layout.status.load(Ordering::Relaxed),
                index: layout.index.load(Ordering::Relaxed),
                started_ms: layout.started_ms.load(Ordering::Relaxed),
                updated_ms: layout.updated_ms.load(Ordering::Relaxed),
                focus_deadline_ms: layout.focus_deadline_ms.load(Ordering::Relaxed),
            };
            // ARM64 seqlock invariant: Acquire fence ensures all Relaxed payload loads above
            // complete before the trailing seq load below (prevents load-load reordering).
            std::sync::atomic::fence(Ordering::Acquire);
            let s2 = layout.seq.load(Ordering::Relaxed);
            if s1 == s2 {
                return Some(snap);
            }
        }
        None
    }
}

impl Drop for WorkerProgressPage {
    fn drop(&mut self) {
        self.close_section_handle();
        if !self.view.Value.is_null() {
            // SAFETY: View mapped via MapViewOfFile.
            unsafe {
                let _ = UnmapViewOfFile(self.view);
            }
            self.view = MEMORY_MAPPED_VIEW_ADDRESS::default();
        }
    }
}

/// Worker-side client for lock-free progress writes into the inherited shared-memory page.
pub struct WorkerProgressClient {
    view: MEMORY_MAPPED_VIEW_ADDRESS,
}

// SAFETY: Atomic writes to page-aligned view owned exclusively by worker client.
unsafe impl Send for WorkerProgressClient {}
unsafe impl Sync for WorkerProgressClient {}

impl WorkerProgressClient {
    pub fn attach_from_env() -> Option<Self> {
        let raw = env::var(WORKER_PROGRESS_ENV).ok()?;
        let raw_val: usize = raw.parse().ok()?;
        if raw_val == 0 {
            return None;
        }
        let handle = HANDLE(raw_val as *mut core::ffi::c_void);
        // SAFETY: Map inherited section handle and close the handle immediately so no child inherits it.
        unsafe {
            let view = MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, PROGRESS_PAGE_BYTES);
            let _ = CloseHandle(handle);
            if view.Value.is_null() {
                return None;
            }
            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let queried = VirtualQuery(
                Some(view.Value),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );
            if queried == 0 || mbi.RegionSize < PROGRESS_PAGE_BYTES {
                let _ = UnmapViewOfFile(view);
                return None;
            }
            DebugTrace::record(
                "session-progress-ready",
                &[("phase", 1)],
                &[],
                &[],
                file!(),
                line!(),
            );
            Some(Self { view })
        }
    }

    fn layout(&self) -> &ProgressPageLayout {
        // SAFETY: Verified RegionSize >= 4096.
        unsafe { &*(self.view.Value as *const ProgressPageLayout) }
    }

    pub fn set_focus_deadline(&self, deadline_ms: i64) {
        self.layout()
            .focus_deadline_ms
            .store(deadline_ms, Ordering::Release);
    }

    pub fn begin_request(&self, request_id: Option<i64>, deadline_ms: i64) {
        let now = SystemCollectorClock::monotonic_ms_now();
        let layout = self.layout();
        layout.focus_deadline_ms.store(0, Ordering::Release);
        let s = layout.seq.fetch_add(1, Ordering::AcqRel);
        // ARM64 seqlock invariant: order odd seq increment strictly before Relaxed payload stores.
        std::sync::atomic::fence(Ordering::Release);
        layout
            .request_id
            .store(request_id.unwrap_or(0), Ordering::Relaxed);
        layout.read_id.store(0, Ordering::Relaxed);
        layout.deadline_ms.store(deadline_ms, Ordering::Relaxed);
        layout.operation.store(16, Ordering::Relaxed);
        layout.api.store(0, Ordering::Relaxed);
        layout.attribute.store(0, Ordering::Relaxed);
        layout.phase.store(1, Ordering::Relaxed);
        layout.status.store(-1, Ordering::Relaxed);
        layout.index.store(-1, Ordering::Relaxed);
        layout.started_ms.store(now, Ordering::Relaxed);
        layout.updated_ms.store(now, Ordering::Relaxed);
        layout.seq.store(s.wrapping_add(2), Ordering::Release);
    }

    pub fn stage(&self, operation: i64, index: i64) {
        let now = SystemCollectorClock::monotonic_ms_now();
        let layout = self.layout();
        let s = layout.seq.fetch_add(1, Ordering::AcqRel);
        // ARM64 seqlock invariant: order odd seq increment strictly before Relaxed payload stores.
        std::sync::atomic::fence(Ordering::Release);
        layout.operation.store(operation, Ordering::Relaxed);
        layout.index.store(index, Ordering::Relaxed);
        layout.phase.store(1, Ordering::Relaxed);
        layout.updated_ms.store(now, Ordering::Relaxed);
        layout.seq.store(s.wrapping_add(2), Ordering::Release);
    }

    pub fn finish_request(&self) {
        let now = SystemCollectorClock::monotonic_ms_now();
        let layout = self.layout();
        layout.focus_deadline_ms.store(0, Ordering::Release);
        let s = layout.seq.fetch_add(1, Ordering::AcqRel);
        // ARM64 seqlock invariant: order odd seq increment strictly before Relaxed payload stores.
        std::sync::atomic::fence(Ordering::Release);
        layout.request_id.store(0, Ordering::Relaxed);
        layout.operation.store(0, Ordering::Relaxed);
        layout.index.store(-1, Ordering::Relaxed);
        layout.started_ms.store(now, Ordering::Relaxed);
        layout.updated_ms.store(now, Ordering::Relaxed);
        layout.seq.store(s.wrapping_add(2), Ordering::Release);
    }
}

impl Drop for WorkerProgressClient {
    fn drop(&mut self) {
        if !self.view.Value.is_null() {
            // SAFETY: View mapped in `attach_from_env`.
            unsafe {
                let _ = UnmapViewOfFile(self.view);
            }
            self.view = MEMORY_MAPPED_VIEW_ADDRESS::default();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerPipeFrameError {
    FrameTooLarge,
}

/// Split complete `\n`-delimited lines from a worker pipe buffer while enforcing `max_frame_bytes`
/// PER individual line (including the trailing `\n`) and rejecting any incomplete line without `\n`
/// that has already reached or exceeded `max_frame_bytes`.
pub fn split_worker_pipe_frames(
    buffer: &mut Vec<u8>,
    max_frame_bytes: usize,
) -> Result<Vec<Vec<u8>>, WorkerPipeFrameError> {
    if max_frame_bytes == 0 {
        return Err(WorkerPipeFrameError::FrameTooLarge);
    }
    let mut frames = Vec::new();
    while let Some(pos) = buffer.iter().position(|&b| b == b'\n') {
        if pos + 1 > max_frame_bytes {
            return Err(WorkerPipeFrameError::FrameTooLarge);
        }
        let line = buffer[..pos].to_vec();
        buffer.drain(..=pos);
        frames.push(line);
    }
    if buffer.len() >= max_frame_bytes {
        return Err(WorkerPipeFrameError::FrameTooLarge);
    }
    Ok(frames)
}

fn is_process_handle_alive(handle: HANDLE) -> bool {
    if handle.is_invalid() || handle.0.is_null() {
        return false;
    }
    // SAFETY: Non-blocking liveness probe on owned child process handle.
    unsafe { WaitForSingleObject(handle, 0) == WAIT_TIMEOUT }
}

/// RAII wrapper around Win32 `PROC_THREAD_ATTRIBUTE_LIST` ensuring `DeleteProcThreadAttributeList`
/// ALWAYS runs whenever `InitializeProcThreadAttributeList` succeeded (including if
/// `UpdateProcThreadAttribute` fails).
struct ProcThreadAttrList {
    _buf: Vec<usize>,
    ptr: LPPROC_THREAD_ATTRIBUTE_LIST,
    initialized: bool,
}

impl ProcThreadAttrList {
    fn new_with_handle_list(handles: &[HANDLE]) -> Option<Self> {
        if handles.is_empty() {
            return None;
        }
        let mut attr_size: usize = 0;
        // SAFETY: Sizing query; expected to fail with ERROR_INSUFFICIENT_BUFFER and populate attr_size.
        unsafe {
            let _ = InitializeProcThreadAttributeList(None, 1, Some(0), &mut attr_size);
        }
        if attr_size == 0 {
            return None;
        }
        let word_count = attr_size.div_ceil(std::mem::size_of::<usize>()).max(8);
        let mut buf = vec![0usize; word_count];
        let ptr = LPPROC_THREAD_ATTRIBUTE_LIST(buf.as_mut_ptr() as *mut _);
        // SAFETY: Aligned buffer sized >= attr_size for 1 attribute.
        if unsafe { InitializeProcThreadAttributeList(Some(ptr), 1, Some(0), &mut attr_size) }
            .is_err()
        {
            return None;
        }
        let list = Self {
            _buf: buf,
            ptr,
            initialized: true,
        };
        // SAFETY: `list` owns the initialized attribute list and deletes it on Drop; `handles`
        // remains alive until CreateProcessW returns.
        if unsafe {
            UpdateProcThreadAttribute(
                list.ptr,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                Some(handles.as_ptr() as *const core::ffi::c_void),
                std::mem::size_of_val(handles),
                None,
                None,
            )
        }
        .is_err()
        {
            return None;
        }
        Some(list)
    }

    fn as_raw(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.ptr
    }
}

impl Drop for ProcThreadAttrList {
    fn drop(&mut self) {
        if self.initialized {
            // SAFETY: Balanced with successful InitializeProcThreadAttributeList.
            unsafe {
                DeleteProcThreadAttributeList(self.ptr);
            }
            self.initialized = false;
        }
    }
}

struct ReadTraceState {
    request_id: i64,
    deadline_ms: i64,
    started_ms: i64,
    last_poll_ms: i64,
    poll_gap_ms: i64,
}

struct ActiveRetire {
    retire_token: String,
    session_token: String,
    deadline_ms: i64,
    reap_deadline_ms: Option<i64>,
    acknowledged: bool,
}

struct ActiveChild {
    pid: u32,
    job: HANDLE,
    process: HANDLE,
    stdin_write: Option<HANDLE>,
    stdout_read: HANDLE,
    progress: Option<WorkerProgressPage>,
    session: bool,
    session_policy: CapturePolicy,
    session_epoch: i64,
    launch_token: String,
    idle_until_ms: i64,
    ticket: Option<ReadTicket>,
    read_trace: Option<ReadTraceState>,
    bytes: Vec<u8>,
    retire: Option<ActiveRetire>,
}

/// Real Windows Job Object out-of-process worker supervisor.
///
/// Spawns `computer-access-collector.exe --ax-worker ...` inside a Windows Job Object with
/// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, sanitized minimal environment, and selective handle inheritance.
/// Any timeout, pause, stop, or parent crash terminates and reaps the entire worker job tree.
pub struct JobWorkerSupervisor {
    executable: PathBuf,
    fixture: bool,
    scenario: String,
    child: Option<ActiveChild>,
    timeout_cleanup: ReadTimeoutCleanup,
}

// SAFETY: Owned exclusively by control loop thread.
unsafe impl Send for JobWorkerSupervisor {}

impl JobWorkerSupervisor {
    pub fn new(executable: PathBuf, fixture: bool, scenario: impl Into<String>) -> Self {
        Self {
            executable,
            fixture,
            scenario: scenario.into(),
            child: None,
            timeout_cleanup: ReadTimeoutCleanup::Ineligible,
        }
    }

    pub fn ready_for_read(&self) -> bool {
        let retiring = self
            .child
            .as_ref()
            .map(|c| c.retire.is_some())
            .unwrap_or(false);
        !retiring && self.timeout_cleanup != ReadTimeoutCleanup::Unconfirmed
    }

    pub fn active_child_pid(&self) -> Option<u32> {
        self.child.as_ref().map(|c| c.pid)
    }

    pub fn launch(&mut self, ticket: ReadTicket) -> Option<WorkerEvent> {
        if !self.ready_for_read() {
            if self.timeout_cleanup == ReadTimeoutCleanup::Unconfirmed {
                return Some(WorkerEvent::WorkerExitUnconfirmed);
            }
            return Some(Self::failure_event(
                &ticket,
                "stale",
                Some(GapDiagnosticCode::WorkerRetirementPending),
            ));
        }

        // Reuse an idle live session worker when policy, epoch, idle budget, and child liveness match.
        let now_reuse = SystemCollectorClock::monotonic_ms_now();
        let can_reuse = self.child.as_ref().is_some_and(|c| {
            c.session
                && c.ticket.is_none()
                && c.retire.is_none()
                && c.session_policy == ticket.policy
                && c.session_epoch == ticket.capture_epoch
                && c.stdin_write.is_some()
                && (c.idle_until_ms == 0 || now_reuse.saturating_add(1_000) < c.idle_until_ms)
                && is_process_handle_alive(c.process)
        });
        if can_reuse {
            if let Some(ref mut c) = self.child {
                let Ok(mut encoded) = ticket.to_json().canonical_bytes() else {
                    return Some(Self::failure_event(&ticket, "read-error", None));
                };
                if encoded.len() >= 65_535 {
                    return Some(Self::failure_event(&ticket, "read-error", None));
                }
                encoded.push(b'\n');
                let now = SystemCollectorClock::monotonic_ms_now();
                let trace = ticket.valid_debug_request_id().map(|req_id| ReadTraceState {
                    request_id: req_id,
                    deadline_ms: ticket.deadline_monotonic_ms,
                    started_ms: now,
                    last_poll_ms: now,
                    poll_gap_ms: 0,
                });
                let stdin_h = c.stdin_write.unwrap();
                if !write_all_pipe(stdin_h, &encoded) {
                    if self.cancel() == ReadTimeoutCleanup::Unconfirmed {
                        return Some(WorkerEvent::WorkerExitUnconfirmed);
                    }
                    return Some(Self::failure_event(&ticket, "read-error", None));
                }
                if let Some(ref tr) = trace {
                    let written_at = SystemCollectorClock::monotonic_ms_now();
                    DebugTrace::record(
                        "worker-request-written",
                        &[
                            ("childPid", c.pid as i64),
                            ("requestId", tr.request_id),
                            ("readRemainingMs", tr.deadline_ms - written_at),
                            ("elapsedMs", written_at - tr.started_ms),
                            ("requestWrittenMs", written_at),
                        ],
                        &[],
                        &[],
                        file!(),
                        line!(),
                    );
                }
                c.ticket = Some(ticket);
                c.read_trace = trace;
                c.idle_until_ms = 0;
                return None;
            }
        }

        if self.cancel() == ReadTimeoutCleanup::Unconfirmed {
            return Some(WorkerEvent::WorkerExitUnconfirmed);
        }
        self.timeout_cleanup = ReadTimeoutCleanup::Ineligible;

        let Ok(mut encoded) = ticket.to_json().canonical_bytes() else {
            return Some(Self::failure_event(&ticket, "read-error", None));
        };
        if encoded.len() >= 65_535 {
            return Some(Self::failure_event(&ticket, "read-error", None));
        }
        encoded.push(b'\n');

        let session = ticket.policy.uses_session_worker() && !self.fixture;
        let mut child = match self.spawn_child(&ticket, session) {
            Some(c) => c,
            None => return Some(Self::failure_event(&ticket, "read-error", None)),
        };

        let now = SystemCollectorClock::monotonic_ms_now();
        let trace = ticket.valid_debug_request_id().map(|req_id| ReadTraceState {
            request_id: req_id,
            deadline_ms: ticket.deadline_monotonic_ms,
            started_ms: now,
            last_poll_ms: now,
            poll_gap_ms: 0,
        });

        let stdin_h = child.stdin_write.unwrap();
        let wrote = write_all_pipe(stdin_h, &encoded);
        if !session {
            // Close child stdin EOF immediately for one-shot workers after delivering ticket.
            if let Some(h) = child.stdin_write.take() {
                unsafe {
                    let _ = CloseHandle(h);
                }
            }
        }
        if !wrote {
            if !terminate_and_close_child(child) {
                self.timeout_cleanup = ReadTimeoutCleanup::Unconfirmed;
                return Some(WorkerEvent::WorkerExitUnconfirmed);
            }
            return Some(Self::failure_event(&ticket, "read-error", None));
        }

        if let Some(ref tr) = trace {
            let written_at = SystemCollectorClock::monotonic_ms_now();
            DebugTrace::record(
                "worker-request-written",
                &[
                    ("childPid", child.pid as i64),
                    ("requestId", tr.request_id),
                    ("readRemainingMs", tr.deadline_ms - written_at),
                    ("elapsedMs", written_at - tr.started_ms),
                    ("requestWrittenMs", written_at),
                ],
                &[],
                &[],
                file!(),
                line!(),
            );
        }

        child.ticket = Some(ticket);
        child.read_trace = trace;
        self.child = Some(child);
        None
    }

    fn spawn_child(&self, ticket: &ReadTicket, session: bool) -> Option<ActiveChild> {
        // Create Job Object with KILL_ON_JOB_CLOSE.
        let job = unsafe { CreateJobObjectW(None, PCWSTR::null()).ok()? };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let set_ok = unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &limits as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
            .is_ok()
        };
        if !set_ok {
            unsafe {
                let _ = CloseHandle(job);
            }
            return None;
        }

        // Create anonymous stdin & stdout pipes with 64 KiB buffer.
        let inheritable_sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: core::ptr::null_mut(),
            bInheritHandle: true.into(),
        };
        let mut stdin_r = HANDLE::default();
        let mut stdin_w = HANDLE::default();
        if unsafe { CreatePipe(&mut stdin_r, &mut stdin_w, Some(&inheritable_sa), 65_536).is_err() }
        {
            unsafe {
                let _ = CloseHandle(job);
            }
            return None;
        }
        let _ = unsafe { SetHandleInformation(stdin_w, HANDLE_FLAG_INHERIT.0, Default::default()) };

        let mut stdout_r = HANDLE::default();
        let mut stdout_w = HANDLE::default();
        if unsafe {
            CreatePipe(&mut stdout_r, &mut stdout_w, Some(&inheritable_sa), 65_536).is_err()
        } {
            unsafe {
                let _ = CloseHandle(stdin_r);
                let _ = CloseHandle(stdin_w);
                let _ = CloseHandle(job);
            }
            return None;
        }
        let _ =
            unsafe { SetHandleInformation(stdout_r, HANDLE_FLAG_INHERIT.0, Default::default()) };

        // Prepare stderr handle for child (inherit parent stderr when debug trace enabled, else NUL).
        let (stderr_child, stderr_owned) = prepare_child_stderr(DebugTrace::enabled());
        let Some(stderr_h) = stderr_child else {
            unsafe {
                let _ = CloseHandle(stdin_r);
                let _ = CloseHandle(stdin_w);
                let _ = CloseHandle(stdout_r);
                let _ = CloseHandle(stdout_w);
                let _ = CloseHandle(job);
            }
            return None;
        };

        // Optional anonymous shared-memory progress page.
        let mut progress = if session || DebugTrace::enabled() {
            WorkerProgressPage::create_inheritable()
        } else {
            None
        };

        // Duplicate parent's own process handle with minimal wait+query rights so worker can
        // monitor parent liveness without PID-reuse races (P1-12).
        let mut parent_dup = HANDLE::default();
        let parent_handle_opt = unsafe {
            let cur = GetCurrentProcess();
            if DuplicateHandle(
                cur,
                cur,
                cur,
                &mut parent_dup,
                (PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION).0,
                true,
                DUPLICATE_HANDLE_OPTIONS(0),
            )
            .is_ok()
                && !parent_dup.is_invalid()
                && !parent_dup.0.is_null()
            {
                Some(parent_dup)
            } else {
                None
            }
        };

        // Assemble exact command line.
        let mut argv = vec![
            self.executable.to_string_lossy().into_owned(),
            "--ax-worker".to_string(),
            "--parent-pid".to_string(),
            std::process::id().to_string(),
            "--worker-token".to_string(),
            ticket.token.clone(),
        ];
        if self.fixture {
            argv.push("--synthetic".to_string());
            argv.push("yes".to_string());
            argv.push("--fixture-scenario".to_string());
            argv.push(self.scenario.clone());
        }
        if session {
            argv.push("--session-worker".to_string());
            argv.push("yes".to_string());
        }
        let mut cmdline_wide = build_windows_cmdline(&argv);
        let exe_wide = to_wide_null_str(&self.executable.to_string_lossy());

        // Assemble minimal sanitized Windows environment block.
        let mut extra_env: Vec<(String, String)> =
            vec![(WORKER_TOKEN_ENV.to_string(), ticket.token.clone())];
        if DebugTrace::enabled() {
            extra_env.push(("DSH_COMPUTER_ACCESS_DEBUG".to_string(), "1".to_string()));
            extra_env.push(("COMPUTER_ACCESS_DEBUG".to_string(), "1".to_string()));
        }
        if let Some(ref p) = progress {
            if let Some(h) = p.raw_handle() {
                extra_env.push((WORKER_PROGRESS_ENV.to_string(), (h.0 as usize).to_string()));
            }
        }
        if let Some(ph) = parent_handle_opt {
            extra_env.push((
                WORKER_PARENT_HANDLE_ENV.to_string(),
                (ph.0 as usize).to_string(),
            ));
        }
        let env_block = build_minimal_env_block(&extra_env);

        // Build selective handle inheritance list (deduplicated).
        let mut inherit_handles: Vec<HANDLE> = vec![stdin_r, stdout_w];
        if !inherit_handles.contains(&stderr_h) {
            inherit_handles.push(stderr_h);
        }
        if let Some(ref p) = progress {
            if let Some(h) = p.raw_handle() {
                if !inherit_handles.contains(&h) {
                    inherit_handles.push(h);
                }
            }
        }
        if let Some(ph) = parent_handle_opt {
            if !inherit_handles.contains(&ph) {
                inherit_handles.push(ph);
            }
        }

        // Fail CLOSED if PROC_THREAD_ATTRIBUTE_HANDLE_LIST cannot be constructed — NEVER fall
        // back to `bInheritHandles = true` without an explicit handle list!
        let Some(attr_list) = ProcThreadAttrList::new_with_handle_list(&inherit_handles) else {
            unsafe {
                let _ = CloseHandle(stdin_r);
                let _ = CloseHandle(stdin_w);
                let _ = CloseHandle(stdout_r);
                let _ = CloseHandle(stdout_w);
                if stderr_owned {
                    let _ = CloseHandle(stderr_h);
                }
                if let Some(ph) = parent_handle_opt {
                    let _ = CloseHandle(ph);
                }
                let _ = CloseHandle(job);
            }
            drop(progress);
            return None;
        };

        let si = STARTUPINFOEXW {
            StartupInfo: STARTUPINFOW {
                cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
                dwFlags: STARTF_USESTDHANDLES,
                hStdInput: stdin_r,
                hStdOutput: stdout_w,
                hStdError: stderr_h,
                ..Default::default()
            },
            lpAttributeList: attr_list.as_raw(),
        };
        let mut pi = PROCESS_INFORMATION::default();
        let flags = CREATE_SUSPENDED
            | CREATE_NO_WINDOW
            | CREATE_UNICODE_ENVIRONMENT
            | EXTENDED_STARTUPINFO_PRESENT;

        let created = unsafe {
            CreateProcessW(
                PCWSTR(exe_wide.as_ptr()),
                Some(PWSTR(cmdline_wide.as_mut_ptr())),
                None,
                None,
                true,
                flags,
                Some(env_block.as_ptr() as *const core::ffi::c_void),
                PCWSTR::null(),
                &si.StartupInfo,
                &mut pi,
            )
            .is_ok()
        };

        // Explicitly drop attribute list right after CreateProcessW (calls DeleteProcThreadAttributeList).
        drop(attr_list);
        // Close parent copies of child-end handles immediately.
        unsafe {
            let _ = CloseHandle(stdin_r);
            let _ = CloseHandle(stdout_w);
            if stderr_owned {
                let _ = CloseHandle(stderr_h);
            }
            if let Some(ph) = parent_handle_opt {
                let _ = CloseHandle(ph);
            }
        }
        if let Some(ref mut p) = progress {
            p.close_section_handle();
        }

        if !created {
            unsafe {
                let _ = CloseHandle(stdin_w);
                let _ = CloseHandle(stdout_r);
                let _ = CloseHandle(job);
            }
            return None;
        }

        // Assign child to Job Object BEFORE resuming its primary thread.
        let assigned = unsafe { AssignProcessToJobObject(job, pi.hProcess).is_ok() };
        if !assigned {
            unsafe {
                // Process is NOT in `job` when assignment fails; terminate & reap it directly.
                let _ = TerminateProcess(pi.hProcess, 1);
                let _ = WaitForSingleObject(pi.hProcess, 1_000);
                let _ = CloseHandle(pi.hThread);
                let _ = CloseHandle(pi.hProcess);
                let _ = CloseHandle(stdin_w);
                let _ = CloseHandle(stdout_r);
                let _ = CloseHandle(job);
            }
            return None;
        }

        let resumed = unsafe { ResumeThread(pi.hThread) };
        unsafe {
            let _ = CloseHandle(pi.hThread);
        }
        if resumed == u32::MAX {
            unsafe {
                let _ = TerminateJobObject(job, 1);
                let _ = WaitForSingleObject(pi.hProcess, 1_000);
                let _ = CloseHandle(pi.hProcess);
                let _ = CloseHandle(stdin_w);
                let _ = CloseHandle(stdout_r);
                let _ = CloseHandle(job);
            }
            return None;
        }

        let now = SystemCollectorClock::monotonic_ms_now();
        DebugTrace::record(
            "worker-launch",
            &[
                ("childPid", pi.dwProcessId as i64),
                ("readRemainingMs", ticket.deadline_monotonic_ms - now),
            ],
            &[("session", session)],
            &[],
            file!(),
            line!(),
        );

        Some(ActiveChild {
            pid: pi.dwProcessId,
            job,
            process: pi.hProcess,
            stdin_write: Some(stdin_w),
            stdout_read: stdout_r,
            progress,
            session,
            session_policy: ticket.policy.clone(),
            session_epoch: ticket.capture_epoch,
            launch_token: ticket.token.clone(),
            idle_until_ms: 0,
            ticket: None,
            read_trace: None,
            bytes: Vec::new(),
            retire: None,
        })
    }

    pub fn retire(&mut self) -> Option<WorkerEvent> {
        let c = self.child.as_mut()?;
        if c.retire.is_some() {
            return None;
        }
        if !c.session || c.session_policy.input_text != Some(true) {
            if self.cancel() == ReadTimeoutCleanup::Unconfirmed {
                return Some(WorkerEvent::WorkerExitUnconfirmed);
            }
            return None;
        }
        let now = SystemCollectorClock::monotonic_ms_now();
        let retire_token = generate_uuid_v4();
        let deadline_ms = c
            .ticket
            .as_ref()
            .map(|t| t.deadline_monotonic_ms.max(now + 1_000))
            .unwrap_or(now + 1_000);
        let mut cmd_map = BTreeMap::new();
        cmd_map.insert("retire".to_string(), JsonValue::String(retire_token.clone()));
        cmd_map.insert(
            "sessionToken".to_string(),
            JsonValue::String(c.launch_token.clone()),
        );
        let Ok(mut encoded) = JsonValue::Object(cmd_map).canonical_bytes() else {
            if self.cancel() == ReadTimeoutCleanup::Unconfirmed {
                return Some(WorkerEvent::WorkerExitUnconfirmed);
            }
            return Some(WorkerEvent::InputDisabled(
                "worker-retirement-ack-failed".to_string(),
            ));
        };
        encoded.push(b'\n');

        let wrote = c
            .stdin_write
            .map(|h| write_all_pipe(h, &encoded))
            .unwrap_or(false);
        if !wrote {
            if self.cancel() == ReadTimeoutCleanup::Unconfirmed {
                return Some(WorkerEvent::WorkerExitUnconfirmed);
            }
            return Some(WorkerEvent::InputDisabled(
                "worker-retirement-ack-failed".to_string(),
            ));
        }

        c.ticket = None;
        c.read_trace = None;
        c.idle_until_ms = 0;
        c.retire = Some(ActiveRetire {
            retire_token,
            session_token: c.launch_token.clone(),
            deadline_ms,
            reap_deadline_ms: None,
            acknowledged: false,
        });
        DebugTrace::record(
            "worker-retire-begin",
            &[
                ("childPid", c.pid as i64),
                ("remainingMs", deadline_ms - now),
            ],
            &[],
            &[],
            file!(),
            line!(),
        );
        None
    }

    fn cancel_push_if_unconfirmed(&mut self, events: &mut Vec<WorkerEvent>) -> bool {
        if self.cancel() == ReadTimeoutCleanup::Unconfirmed {
            events.push(WorkerEvent::WorkerExitUnconfirmed);
            true
        } else {
            false
        }
    }

    pub fn poll(&mut self) -> Vec<WorkerEvent> {
        let mut events = Vec::new();
        let Some(ref mut c) = self.child else {
            return events;
        };
        let now = SystemCollectorClock::monotonic_ms_now();

        if let Some(ref tr) = c.read_trace {
            let gap = now.saturating_sub(tr.last_poll_ms);
            if let Some(ref mut tr_mut) = c.read_trace {
                tr_mut.poll_gap_ms = gap;
                tr_mut.last_poll_ms = now;
            }
        }

        // Check active retirement state.
        if let Some(ref ret) = c.retire {
            if ret.acknowledged {
                let reap_deadline = ret.reap_deadline_ms.unwrap_or(now);
                let waited = unsafe { WaitForSingleObject(c.process, 0) };
                if waited == WAIT_OBJECT_0 {
                    let mut exit_code: u32 = 1;
                    let ok = unsafe { GetExitCodeProcess(c.process, &mut exit_code).is_ok() };
                    let pid = c.pid;
                    if self.cancel_push_if_unconfirmed(&mut events) {
                        return events;
                    }
                    if ok && exit_code == 0 {
                        DebugTrace::record(
                            "worker-reaped",
                            &[("childPid", pid as i64), ("waitStatus", 0)],
                            &[("acknowledged", true), ("forced", false)],
                            &[],
                            file!(),
                            line!(),
                        );
                    } else {
                        events.push(WorkerEvent::InputDisabled(
                            "worker-retirement-exit-unconfirmed".to_string(),
                        ));
                    }
                } else if now >= reap_deadline
                    && !self.cancel_push_if_unconfirmed(&mut events)
                {
                    events.push(WorkerEvent::InputDisabled(
                        "worker-retirement-exit-unconfirmed".to_string(),
                    ));
                }
                return events;
            }
            if now >= ret.deadline_ms {
                if !self.cancel_push_if_unconfirmed(&mut events) {
                    events.push(WorkerEvent::InputDisabled(
                        "worker-retirement-ack-failed".to_string(),
                    ));
                }
                return events;
            }
        }

        // Check idle timeout on session workers.
        if c.ticket.is_none() && c.idle_until_ms > 0 && now >= c.idle_until_ms {
            let input_enabled = c.session_policy.input_text == Some(true);
            if !self.cancel_push_if_unconfirmed(&mut events) && input_enabled {
                events.push(WorkerEvent::InputDisabled(
                    "input-monitoring-unavailable".to_string(),
                ));
            }
            return events;
        }

        // Non-blocking drain of worker stdout via PeekNamedPipe.
        // Buffer unread bytes up to WORKER_MAX_PIPE_BUFFER_BYTES (256 KiB) and enforce
        // WORKER_MAX_FRAME_BYTES (65,536 B) PER individual `\n`-delimited frame so multi-frame
        // bursts (e.g. 15 B dirty notice + 65,490 B ReadResult) parse cleanly without false error.
        let mut eof = false;
        let mut pipe_err = false;
        let mut frames: Vec<(Vec<u8>, Option<i64>)> = Vec::new();
        for _ in 0..32 {
            let mut avail: u32 = 0;
            // SAFETY: Valid anonymous pipe read handle.
            let peek = unsafe {
                PeekNamedPipe(c.stdout_read, None, 0, None, Some(&mut avail), None)
            };
            match peek {
                Ok(()) if avail == 0 => break,
                Ok(()) => {
                    let remaining_cap = WORKER_MAX_PIPE_BUFFER_BYTES.saturating_sub(c.bytes.len());
                    if remaining_cap == 0 {
                        pipe_err = true;
                        break;
                    }
                    let to_read = (avail as usize).min(8_192).min(remaining_cap);
                    let mut buf = vec![0u8; to_read];
                    let mut got: u32 = 0;
                    let r = unsafe { ReadFile(c.stdout_read, Some(&mut buf), Some(&mut got), None) };
                    match r {
                        Ok(()) if got == 0 => {
                            eof = true;
                            break;
                        }
                        Ok(()) => {
                            c.bytes.extend_from_slice(&buf[..got as usize]);
                            match split_worker_pipe_frames(&mut c.bytes, WORKER_MAX_FRAME_BYTES) {
                                Ok(new_lines) => {
                                    for line in new_lines {
                                        let ready_ms = c
                                            .read_trace
                                            .as_ref()
                                            .map(|_| SystemCollectorClock::monotonic_ms_now());
                                        frames.push((line, ready_ms));
                                    }
                                }
                                Err(WorkerPipeFrameError::FrameTooLarge) => {
                                    pipe_err = true;
                                    break;
                                }
                            }
                        }
                        Err(err) if err.code() == ERROR_BROKEN_PIPE.to_hresult() => {
                            eof = true;
                            break;
                        }
                        Err(_) => {
                            pipe_err = true;
                            break;
                        }
                    }
                }
                Err(err) if err.code() == ERROR_BROKEN_PIPE.to_hresult() => {
                    eof = true;
                    break;
                }
                Err(_) => {
                    pipe_err = true;
                    break;
                }
            }
        }

        if pipe_err {
            let active_ticket = c.ticket.clone();
            let is_session = c.session;
            let input_text_enabled = c.session_policy.input_text == Some(true);
            let retiring = c.retire.is_some();
            if !self.cancel_push_if_unconfirmed(&mut events) {
                if let Some(ev) = classify_worker_pipe_termination(
                    is_session,
                    active_ticket.as_ref(),
                    input_text_enabled,
                    retiring,
                ) {
                    events.push(ev);
                }
            }
            return events;
        }

        // Process frames with strict batch precedence: `inputDisabled` > `secureInput` > content.
        let mut should_cancel = false;
        let mut should_retire = false;
        let child_pid = c.pid;
        let is_session = c.session;

        let mut saw_secure_input = false;
        if is_session && !frames.is_empty() {
            let slices: Vec<&[u8]> = frames.iter().map(|(f, _)| f.as_slice()).collect();
            match classify_session_pipe_batch(&slices) {
                SessionBatchPrecedence::InputDisabled(reason_str) => {
                    if !self.cancel_push_if_unconfirmed(&mut events) {
                        events.push(WorkerEvent::InputDisabled(reason_str));
                    }
                    return events;
                }
                SessionBatchPrecedence::SecureInput => {
                    saw_secure_input = true;
                    events.push(WorkerEvent::SecureInput);
                    // When not actively retiring, `secureInput` supersedes every content frame
                    // in this batch without emitting any ReadResult/MenuAction/Dirty events.
                    if c.retire.is_none() {
                        return events;
                    }
                }
                SessionBatchPrecedence::Normal => {}
            }
        }

        for (idx, (frame, ready_ms)) in frames.iter().enumerate() {
            if is_session {
                if frame == b"{\"secureInput\":true}" {
                    continue;
                }
                if frame == b"{\"dirty\":true}" {
                    if c.retire.is_none() && !saw_secure_input {
                        events.push(WorkerEvent::Dirty);
                    }
                    continue;
                }
                if frame == b"{\"submitDirty\":true}" {
                    if c.retire.is_none() && !saw_secure_input {
                        events.push(WorkerEvent::SubmitDirty);
                    }
                    continue;
                }
                if frame == b"{\"menuTracking\":true}" {
                    if c.retire.is_none() && !saw_secure_input {
                        events.push(WorkerEvent::MenuTracking(true));
                    }
                    continue;
                }
                if frame == b"{\"menuTracking\":false}" {
                    if c.retire.is_none() && !saw_secure_input {
                        events.push(WorkerEvent::MenuTracking(false));
                    }
                    continue;
                }
                if let Some(ref mut ret) = c.retire {
                    let is_last_clean = idx + 1 == frames.len() && c.bytes.is_empty();
                    let outcome = classify_retiring_session_frame(
                        frame,
                        &ret.session_token,
                        &ret.retire_token,
                        is_last_clean,
                    );
                    match outcome {
                        RetiringFrameOutcome::InputDisabled(reason_str) => {
                            if !self.cancel_push_if_unconfirmed(&mut events) {
                                events.push(WorkerEvent::InputDisabled(reason_str));
                            }
                            return events;
                        }
                        RetiringFrameOutcome::AckFailed => {
                            if !self.cancel_push_if_unconfirmed(&mut events) {
                                events.push(WorkerEvent::InputDisabled(
                                    "worker-retirement-ack-failed".to_string(),
                                ));
                            }
                            return events;
                        }
                        RetiringFrameOutcome::Acknowledged => {
                            let ack_at = SystemCollectorClock::monotonic_ms_now();
                            if ack_at < ret.deadline_ms {
                                ret.acknowledged = true;
                                ret.reap_deadline_ms = Some(ack_at + 1_000);
                                DebugTrace::record(
                                    "worker-retire-ack",
                                    &[
                                        ("childPid", child_pid as i64),
                                        ("remainingMs", ret.deadline_ms - ack_at),
                                    ],
                                    &[("healthy", true)],
                                    &[],
                                    file!(),
                                    line!(),
                                );
                                return events;
                            } else {
                                if !self.cancel_push_if_unconfirmed(&mut events) {
                                    events.push(WorkerEvent::InputDisabled(
                                        "worker-retirement-ack-failed".to_string(),
                                    ));
                                }
                                return events;
                            }
                        }
                        RetiringFrameOutcome::IgnoreInFlight => continue,
                    }
                }
                if let Ok(parsed) = JsonValue::parse(frame) {
                    if let Some(reason) = parsed.get("inputDisabled").and_then(JsonValue::as_str) {
                        let reason_str = reason.to_string();
                        if !self.cancel_push_if_unconfirmed(&mut events) {
                            events.push(WorkerEvent::InputDisabled(reason_str));
                        }
                        return events;
                    }
                    if let Some(obj) = parsed.as_obj() {
                        if obj.len() == 1 {
                            if let Some(menu_val) = obj.get("menuAction") {
                                match MenuActionRecord::from_json(menu_val) {
                                    Some(record) => {
                                        if !saw_secure_input {
                                            events.push(WorkerEvent::MenuAction(Box::new(record)));
                                        }
                                        continue;
                                    }
                                    None => {
                                        let active_ticket = c.ticket.clone();
                                        let input_text_enabled =
                                            c.session_policy.input_text == Some(true);
                                        let retiring = c.retire.is_some();
                                        if !self.cancel_push_if_unconfirmed(&mut events) {
                                            if let Some(ev) = classify_worker_pipe_termination(
                                                is_session,
                                                active_ticket.as_ref(),
                                                input_text_enabled,
                                                retiring,
                                            ) {
                                                events.push(ev);
                                            }
                                        }
                                        return events;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if saw_secure_input {
                continue;
            }

            let decode_started = c
                .read_trace
                .as_ref()
                .map(|_| SystemCollectorClock::monotonic_ms_now());
            let decoded = JsonValue::parse(frame)
                .ok()
                .and_then(|v| ReadResult::from_json(&v));
            let decoded_at = c
                .read_trace
                .as_ref()
                .map(|_| SystemCollectorClock::monotonic_ms_now());

            let Some(ref active_ticket) = c.ticket else {
                let input_text_enabled = c.session_policy.input_text == Some(true);
                let retiring = c.retire.is_some();
                if !self.cancel_push_if_unconfirmed(&mut events) {
                    if let Some(ev) = classify_worker_pipe_termination(
                        is_session,
                        None,
                        input_text_enabled,
                        retiring,
                    ) {
                        events.push(ev);
                    }
                }
                return events;
            };
            let Some(response) = decoded else {
                let t = active_ticket.clone();
                if !self.cancel_push_if_unconfirmed(&mut events) {
                    events.push(Self::failure_event(&t, "read-error", None));
                }
                return events;
            };
            if response.token != active_ticket.token {
                let t = active_ticket.clone();
                if !self.cancel_push_if_unconfirmed(&mut events) {
                    events.push(Self::failure_event(&t, "read-error", None));
                }
                return events;
            }

            let trace = c.read_trace.take();
            if is_session {
                c.ticket = None;
                c.idle_until_ms = SystemCollectorClock::monotonic_ms_now() + 60_000;
                if matches!(
                    response.reason.as_deref(),
                    Some("session-app-changed" | "application-excluded")
                ) {
                    if c.session_policy.input_text == Some(true) {
                        should_retire = true;
                    } else {
                        should_cancel = true;
                    }
                }
            } else {
                c.ticket = None;
                should_cancel = true;
            }

            let dispatch_started = trace
                .as_ref()
                .map(|_| SystemCollectorClock::monotonic_ms_now());

            if let (Some(tr), Some(frame_ready), Some(d_start), Some(d_end), Some(disp_start)) = (
                trace,
                *ready_ms,
                decode_started,
                decoded_at,
                dispatch_started,
            ) {
                let dispatched_at = SystemCollectorClock::monotonic_ms_now();
                DebugTrace::record(
                    "worker-response-received",
                    &[
                        ("childPid", child_pid as i64),
                        ("requestId", tr.request_id),
                        ("readRemainingMs", tr.deadline_ms - disp_start),
                        ("frameBytes", (frame.len() + 1) as i64),
                        ("frameReadyMs", frame_ready),
                        ("decodeMs", d_end - d_start),
                        ("pollGapMs", tr.poll_gap_ms),
                        ("dispatchStartedMs", disp_start),
                    ],
                    &[],
                    &[],
                    file!(),
                    line!(),
                );
                DebugTrace::record(
                    "worker-response-dispatched",
                    &[
                        ("childPid", child_pid as i64),
                        ("requestId", tr.request_id),
                        ("readRemainingMs", tr.deadline_ms - dispatched_at),
                        ("elapsedMs", dispatched_at - disp_start),
                    ],
                    &[],
                    &[],
                    file!(),
                    line!(),
                );
            }

            events.push(WorkerEvent::Completed(Box::new(response)));
        }

        if should_cancel {
            self.cancel_push_if_unconfirmed(&mut events);
            return events;
        }
        if should_retire {
            if let Some(ev) = self.retire() {
                events.push(ev);
            }
            return events;
        }

        if !eof
            && frames.is_empty()
            && self.child.as_ref().is_some_and(|c| {
                c.session
                    && c.ticket.is_none()
                    && c.retire.is_none()
                    && !is_process_handle_alive(c.process)
            })
        {
            eof = true;
        }

        if eof {
            let active = self.child.as_ref().and_then(|c| c.ticket.clone());
            let input_text_enabled = self
                .child
                .as_ref()
                .map(|c| c.session_policy.input_text == Some(true))
                .unwrap_or(false);
            let retiring = self
                .child
                .as_ref()
                .map(|c| c.retire.is_some())
                .unwrap_or(false);
            if let Some(ref t) = active {
                if is_session
                    && t.policy.input_text == Some(true)
                    && SystemCollectorClock::monotonic_ms_now() >= t.deadline_monotonic_ms
                {
                    events.push(WorkerEvent::ReadDeadlineReached(Box::new(t.clone())));
                    return events;
                }
            }
            if !self.cancel_push_if_unconfirmed(&mut events) {
                if let Some(ev) = classify_worker_pipe_termination(
                    is_session,
                    active.as_ref(),
                    input_text_enabled,
                    retiring,
                ) {
                    events.push(ev);
                }
            }
        }

        events
    }

    pub fn abort_timed_out_read(&mut self, ticket: &ReadTicket) -> ReadTimeoutCleanup {
        let now = SystemCollectorClock::monotonic_ms_now();
        let matches = self.child.as_ref().is_some_and(|c| {
            now >= ticket.deadline_monotonic_ms
                && c.ticket.as_ref() == Some(ticket)
                && c.session
                && c.retire.is_none()
                && ticket.policy.input_text == Some(true)
        });
        if !matches {
            return ReadTimeoutCleanup::Ineligible;
        }
        let child = self.child.take().unwrap();
        let eligible = child.bytes.is_empty();
        let focus_ok = child
            .progress
            .as_ref()
            .map(|p| p.ended_inside_initial_focus(ticket.deadline_monotonic_ms))
            .unwrap_or(false);
        let reaped = terminate_and_close_child(child);
        self.timeout_cleanup = if !reaped {
            ReadTimeoutCleanup::Unconfirmed
        } else if eligible && focus_ok {
            ReadTimeoutCleanup::Reaped
        } else {
            ReadTimeoutCleanup::Ineligible
        };
        self.timeout_cleanup
    }

    pub fn timed_out_read_cleanup(&self) -> ReadTimeoutCleanup {
        self.timeout_cleanup
    }

    /// Immediately terminate the entire Job Object and reap the child process.
    /// Returns `ReadTimeoutCleanup::Unconfirmed` if termination cannot be confirmed.
    pub fn cancel(&mut self) -> ReadTimeoutCleanup {
        let Some(child) = self.child.take() else {
            return self.timeout_cleanup;
        };
        if let Some(ref tr) = child.read_trace {
            let now = SystemCollectorClock::monotonic_ms_now();
            DebugTrace::record(
                "worker-read-cancelled",
                &[
                    ("childPid", child.pid as i64),
                    ("requestId", tr.request_id),
                    ("readRemainingMs", tr.deadline_ms - now),
                    ("bufferBytes", child.bytes.len() as i64),
                ],
                &[],
                &[],
                file!(),
                line!(),
            );
        }
        let reaped = terminate_and_close_child(child);
        if !reaped {
            self.timeout_cleanup = ReadTimeoutCleanup::Unconfirmed;
            ReadTimeoutCleanup::Unconfirmed
        } else {
            ReadTimeoutCleanup::Reaped
        }
    }

    fn failure_event(
        ticket: &ReadTicket,
        reason: &str,
        code: Option<GapDiagnosticCode>,
    ) -> WorkerEvent {
        let now = SystemCollectorClock::unix_ms_now();
        WorkerEvent::Completed(Box::new(ReadResult::failure(
            ticket.token.clone(),
            reason,
            code.map(|c| GapDiagnostic::new(c, None)),
            now,
            now,
        )))
    }
}

impl Drop for JobWorkerSupervisor {
    fn drop(&mut self) {
        self.cancel();
    }
}

fn terminate_and_close_child(mut child: ActiveChild) -> bool {
    if let Some(h) = child.stdin_write.take() {
        unsafe {
            let _ = CloseHandle(h);
        }
    }
    unsafe {
        let _ = CloseHandle(child.stdout_read);
    }

    let already_exited = unsafe { WaitForSingleObject(child.process, 0) == WAIT_OBJECT_0 };
    let forced = !already_exited;
    let reaped = if already_exited {
        true
    } else {
        unsafe {
            let _ = TerminateJobObject(child.job, 1);
            WaitForSingleObject(child.process, 2_000) == WAIT_OBJECT_0
        }
    };

    let mut exit_code: u32 = 0;
    if reaped {
        unsafe {
            let _ = GetExitCodeProcess(child.process, &mut exit_code);
        }
        DebugTrace::record(
            "worker-reaped",
            &[
                ("childPid", child.pid as i64),
                ("waitStatus", exit_code as i64),
            ],
            &[("forced", forced)],
            &[],
            file!(),
            line!(),
        );
    }

    drop(child.progress);
    unsafe {
        let _ = CloseHandle(child.process);
        let _ = CloseHandle(child.job);
    }
    reaped
}

fn prepare_child_stderr(inherit_debug: bool) -> (Option<HANDLE>, bool) {
    if inherit_debug {
        if let Ok(stderr_h) = unsafe { GetStdHandle(STD_ERROR_HANDLE) } {
            if !stderr_h.is_invalid() && !stderr_h.0.is_null() {
                let mut dup = HANDLE::default();
                let ok = unsafe {
                    let cur = GetCurrentProcess();
                    DuplicateHandle(
                        cur,
                        stderr_h,
                        cur,
                        &mut dup,
                        0,
                        true,
                        DUPLICATE_SAME_ACCESS,
                    )
                    .is_ok()
                };
                if ok {
                    return (Some(dup), true);
                }
            }
        }
    }

    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: core::ptr::null_mut(),
        bInheritHandle: true.into(),
    };
    let nul = to_wide_null_str("NUL");
    let h = unsafe {
        CreateFileW(
            PCWSTR(nul.as_ptr()),
            FILE_GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            Some(&sa),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .ok()
    };
    (h, true)
}

fn write_all_pipe(handle: HANDLE, data: &[u8]) -> bool {
    let mut offset = 0usize;
    while offset < data.len() {
        let mut written: u32 = 0;
        let res = unsafe { WriteFile(handle, Some(&data[offset..]), Some(&mut written), None) };
        if res.is_err() || written == 0 {
            return false;
        }
        offset += written as usize;
    }
    true
}

fn to_wide_null_str(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

fn build_windows_cmdline(argv: &[String]) -> Vec<u16> {
    let mut cmd = String::new();
    for (i, arg) in argv.iter().enumerate() {
        if i > 0 {
            cmd.push(' ');
        }
        let needs_quote = arg.is_empty() || arg.chars().any(|c| matches!(c, ' ' | '\t' | '"'));
        if !needs_quote {
            cmd.push_str(arg);
        } else {
            cmd.push('"');
            let mut backslashes = 0usize;
            for ch in arg.chars() {
                if ch == '\\' {
                    backslashes += 1;
                } else if ch == '"' {
                    for _ in 0..(backslashes * 2 + 1) {
                        cmd.push('\\');
                    }
                    cmd.push('"');
                    backslashes = 0;
                } else {
                    for _ in 0..backslashes {
                        cmd.push('\\');
                    }
                    backslashes = 0;
                    cmd.push(ch);
                }
            }
            for _ in 0..(backslashes * 2) {
                cmd.push('\\');
            }
            cmd.push('"');
        }
    }
    to_wide_null_str(&cmd)
}

fn build_minimal_env_block(extra: &[(String, String)]) -> Vec<u16> {
    let mut entries: BTreeMap<String, (String, String)> = BTreeMap::new();
    for &canonical in ESSENTIAL_WINDOWS_ENV_KEYS {
        if let Ok(val) = env::var(canonical) {
            entries.insert(
                canonical.to_ascii_uppercase(),
                (canonical.to_string(), val),
            );
        }
    }
    for (k, v) in extra {
        entries.insert(k.to_ascii_uppercase(), (k.clone(), v.clone()));
    }
    let mut wide = Vec::new();
    for (_, (k, v)) in entries {
        wide.extend(OsStr::new(&format!("{k}={v}")).encode_wide());
        wide.push(0);
    }
    wide.push(0);
    wide
}

/// Worker-side atomic watchdog state shared between the worker loop and watchdog thread.
struct WorkerWatchdogState {
    deadline_ms: AtomicI64,
    phase: AtomicI64,
    finished: AtomicBool,
}

fn spawn_worker_watchdog(
    parent: ParentProcessHandle,
    initial_deadline_ms: i64,
    is_session: bool,
) -> Arc<WorkerWatchdogState> {
    let state = Arc::new(WorkerWatchdogState {
        deadline_ms: AtomicI64::new(initial_deadline_ms),
        phase: AtomicI64::new(0),
        finished: AtomicBool::new(false),
    });
    let wd = Arc::clone(&state);
    thread::spawn(move || {
        while !wd.finished.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(20));
            if wd.finished.load(Ordering::Acquire) {
                return;
            }
            if !parent.is_alive() {
                DebugTrace::record("session-parent-lost", &[], &[], &[], file!(), line!());
                std::process::exit(70);
            }
            let now = SystemCollectorClock::monotonic_ms_now();
            let dl = wd.deadline_ms.load(Ordering::Acquire);
            if now >= dl {
                let phase = wd.phase.load(Ordering::Acquire);
                DebugTrace::record(
                    "session-watchdog",
                    &[("phase", phase), ("readRemainingMs", dl - now)],
                    &[],
                    &[],
                    file!(),
                    line!(),
                );
                if is_session && phase == 1 {
                    std::process::exit(SESSION_READ_DEADLINE_EXIT);
                }
                std::process::exit(70);
            }
        }
    });
    state
}

fn open_worker_parent_handle(expected_ppid: u32) -> Option<ParentProcessHandle> {
    if let Ok(raw_str) = env::var(WORKER_PARENT_HANDLE_ENV) {
        if let Ok(raw_val) = raw_str.parse::<isize>() {
            if let Some(inherited) = ParentProcessHandle::from_inherited_handle(raw_val) {
                if inherited.pid() == expected_ppid {
                    return Some(inherited);
                }
            }
        }
    }
    ParentProcessHandle::open(expected_ppid)
}

/// Isolated `--ax-worker` child process entrypoint (both one-shot and `--session-worker yes`).
pub fn run_worker_cli(options: &CliOptions) -> i32 {
    if options.session_worker {
        return run_session_worker_cli(options);
    }
    let Some(ppid) = options.worker_parent_pid else {
        return 64;
    };
    let Some(parent) = open_worker_parent_handle(ppid) else {
        return 70;
    };
    let clock = SystemCollectorClock;
    let watchdog = spawn_worker_watchdog(parent, clock.monotonic_ms() + 5_500, false);
    let progress = WorkerProgressClient::attach_from_env();

    let stdin_h = match unsafe { GetStdHandle(STD_INPUT_HANDLE) } {
        Ok(h) if !h.is_invalid() && !h.0.is_null() => h,
        _ => return 74,
    };
    let stdout_h = match unsafe { GetStdHandle(STD_OUTPUT_HANDLE) } {
        Ok(h) if !h.is_invalid() && !h.0.is_null() => h,
        _ => return 74,
    };

    // Read single LF-terminated ticket frame (<= 65536 bytes).
    let mut buf = Vec::with_capacity(1_024);
    let mut chunk = [0u8; 4_096];
    while !buf.contains(&b'\n') {
        let mut n: u32 = 0;
        let res = unsafe { ReadFile(stdin_h, Some(&mut chunk), Some(&mut n), None) };
        if res.is_err() || n == 0 || buf.len() + (n as usize) > 65_536 {
            watchdog.finished.store(true, Ordering::Release);
            return 64;
        }
        buf.extend_from_slice(&chunk[..n as usize]);
    }
    if buf.last() != Some(&b'\n') || buf[..buf.len() - 1].contains(&b'\n') {
        watchdog.finished.store(true, Ordering::Release);
        return 64;
    }

    let expected_token = env::var(WORKER_TOKEN_ENV).ok();
    let ticket = match JsonValue::parse(&buf[..buf.len() - 1])
        .ok()
        .and_then(|v| ReadTicket::from_json(&v))
    {
        Some(t) => t,
        None => {
            watchdog.finished.store(true, Ordering::Release);
            return 64;
        }
    };

    let now = clock.monotonic_ms();
    if expected_token.as_deref() != Some(ticket.token.as_str())
        || !ticket.policy.enabled
        || !ticket.policy.has_valid_text_settings()
        || ticket.deadline_monotonic_ms <= now
        || ticket.deadline_monotonic_ms - now > 5_000
    {
        watchdog.finished.store(true, Ordering::Release);
        return 64;
    }

    if options.fixture && options.scenario == "workerhang" {
        // Intentionally hang until terminated by parent's Job Object or watchdog.
        loop {
            thread::sleep(Duration::from_secs(60));
        }
    }

    if let Some(ref p) = progress {
        p.begin_request(ticket.valid_debug_request_id(), ticket.deadline_monotonic_ms);
    }

    let mut result = if options.fixture {
        fixture::execute_fixture_read(&options.scenario, &ticket, &clock)
    } else {
        execute_live_one_shot(&ticket, &clock, progress.as_ref())
    };

    if let Some(ref p) = progress {
        p.finish_request();
    }

    if clock.monotonic_ms() >= ticket.deadline_monotonic_ms {
        watchdog.finished.store(true, Ordering::Release);
        return 70;
    }

    let Some(encoded) = encode_read_result_pipe_frame(&mut result) else {
        watchdog.finished.store(true, Ordering::Release);
        return 70;
    };

    let ok = write_all_pipe(stdout_h, &encoded);
    watchdog.finished.store(true, Ordering::Release);
    if ok {
        0
    } else {
        74
    }
}

fn run_session_worker_cli(options: &CliOptions) -> i32 {
    if options.fixture {
        return 64;
    }
    let Some(ppid) = options.worker_parent_pid else {
        return 64;
    };
    let Some(parent) = open_worker_parent_handle(ppid) else {
        return 70;
    };
    let launch_token = env::var(WORKER_TOKEN_ENV).unwrap_or_default();
    if launch_token.len() != 36 {
        return 64;
    }

    let clock = SystemCollectorClock;
    let progress = WorkerProgressClient::attach_from_env();
    let watchdog = spawn_worker_watchdog(parent, clock.monotonic_ms() + 5_500, true);
    let mut session = LiveUiaSession::new(progress);

    let exit_code = match (
        unsafe { GetStdHandle(STD_INPUT_HANDLE) },
        unsafe { GetStdHandle(STD_OUTPUT_HANDLE) },
    ) {
        (Ok(stdin_h), Ok(stdout_h))
            if !stdin_h.is_invalid()
                && !stdin_h.0.is_null()
                && !stdout_h.is_invalid()
                && !stdout_h.0.is_null() =>
        {
            run_session_worker_loop(
                &mut session,
                &watchdog,
                stdin_h,
                stdout_h,
                &launch_token,
                &clock,
            )
        }
        _ => 74,
    };

    // Explicitly drop `session` (abandoning UIA handlers + stopping watcher/hook + releasing COM)
    // BEFORE disarming the watchdog on EVERY exit path so teardown stays watchdog-protected!
    if exit_code != 70 {
        watchdog
            .deadline_ms
            .store(clock.monotonic_ms() + 1_500, Ordering::Release);
        watchdog.phase.store(0, Ordering::Release);
    }
    drop(session);
    watchdog.finished.store(true, Ordering::Release);
    exit_code
}

fn run_session_worker_loop(
    session: &mut LiveUiaSession,
    watchdog: &WorkerWatchdogState,
    stdin_h: HANDLE,
    stdout_h: HANDLE,
    launch_token: &str,
    clock: &SystemCollectorClock,
) -> i32 {
    let mut bytes = Vec::new();
    let mut initial = true;
    let mut pinned_policy: Option<CapturePolicy> = None;
    let mut pinned_epoch: Option<i64> = None;
    let mut pinned_revision: Option<i64> = None;
    let mut idle_until = clock.monotonic_ms() + 5_000;
    let mut secure_sent = false;
    let mut next_dirty_ms: i64 = 0;

    while clock.monotonic_ms() < idle_until {
        watchdog
            .deadline_ms
            .store(clock.monotonic_ms() + 5_500, Ordering::Release);
        watchdog.phase.store(0, Ordering::Release);

        // Non-blocking bounded stdin drain loop via PeekNamedPipe (matching JobWorkerSupervisor)
        // so >8 KiB ReadTicket frames arrive completely without interleaving poll()/sleep().
        for _ in 0..32 {
            let mut avail: u32 = 0;
            let peek = unsafe { PeekNamedPipe(stdin_h, None, 0, None, Some(&mut avail), None) };
            match peek {
                Ok(()) if avail == 0 => break,
                Ok(()) => {
                    let remaining_cap = WORKER_MAX_PIPE_BUFFER_BYTES.saturating_sub(bytes.len());
                    if remaining_cap == 0 {
                        return 64;
                    }
                    let to_read = (avail as usize).min(8_192).min(remaining_cap);
                    let mut chunk = vec![0u8; to_read];
                    let mut got: u32 = 0;
                    let r = unsafe { ReadFile(stdin_h, Some(&mut chunk), Some(&mut got), None) };
                    match r {
                        Ok(()) if got == 0 => return 0,
                        Ok(()) => {
                            bytes.extend_from_slice(&chunk[..got as usize]);
                            if bytes.contains(&b'\n') {
                                break;
                            }
                        }
                        Err(err) if err.code() == ERROR_BROKEN_PIPE.to_hresult() => return 0,
                        Err(_) => return 74,
                    }
                }
                Err(err) if err.code() == ERROR_BROKEN_PIPE.to_hresult() => return 0,
                Err(_) => return 74,
            }
        }

        if let Some(pos) = bytes.iter().position(|&b| b == b'\n') {
            if pos + 1 > WORKER_MAX_FRAME_BYTES {
                return 64;
            }
            let frame = bytes[..pos].to_vec();
            bytes.drain(..=pos);

            let Ok(parsed) = JsonValue::parse(&frame) else {
                return 64;
            };

            // Inert session-worker retire handshake.
            if let Some(retire_token) = parsed.get("retire").and_then(JsonValue::as_str) {
                let sess_tok = parsed.get("sessionToken").and_then(JsonValue::as_str);
                if sess_tok != Some(launch_token) || retire_token.len() != 36 {
                    return 64;
                }
                DebugTrace::record("session-retire-received", &[], &[], &[], file!(), line!());
                let healthy = session.retire_healthy();
                DebugTrace::record(
                    "session-retire-input-ended",
                    &[],
                    &[("healthy", healthy)],
                    &[],
                    file!(),
                    line!(),
                );
                DebugTrace::record(
                    "session-retire-observer-detached",
                    &[],
                    &[("healthy", healthy)],
                    &[],
                    file!(),
                    line!(),
                );
                let mut ack = BTreeMap::new();
                ack.insert("inputHealthy".to_string(), JsonValue::Bool(healthy));
                ack.insert(
                    "retired".to_string(),
                    JsonValue::String(retire_token.to_string()),
                );
                ack.insert(
                    "sessionToken".to_string(),
                    JsonValue::String(launch_token.to_string()),
                );
                let Ok(mut encoded) = JsonValue::Object(ack).canonical_bytes() else {
                    return 70;
                };
                encoded.push(b'\n');
                let ok = write_all_pipe(stdout_h, &encoded);
                DebugTrace::record(
                    "session-retire-written",
                    &[("pendingBytes", 0)],
                    &[],
                    &[],
                    file!(),
                    line!(),
                );
                return if ok { 0 } else { 74 };
            }

            // Standard ReadTicket request.
            let Some(ticket) = ReadTicket::from_json(&parsed) else {
                return 64;
            };
            let now = clock.monotonic_ms();
            if (initial && ticket.token != launch_token)
                || !ticket.policy.enabled
                || !ticket.policy.has_valid_text_settings()
                || !ticket.policy.uses_session_worker()
                || ticket.deadline_monotonic_ms <= now
                || ticket.deadline_monotonic_ms - now > 5_000
                || pinned_policy.as_ref().is_some_and(|p| p != &ticket.policy)
                || pinned_epoch.is_some_and(|e| e != ticket.capture_epoch)
                || pinned_revision.is_some_and(|r| r != ticket.policy_revision)
            {
                return 64;
            }

            initial = false;
            pinned_policy = Some(ticket.policy.clone());
            pinned_epoch = Some(ticket.capture_epoch);
            pinned_revision = Some(ticket.policy_revision);

            watchdog
                .deadline_ms
                .store(ticket.deadline_monotonic_ms, Ordering::Release);
            watchdog.phase.store(1, Ordering::Release);

            let mut result = session.read(&ticket, clock);

            watchdog.phase.store(2, Ordering::Release);
            // Check ONLY in-memory secure-input / input-failure flags before writing ReadResult;
            // NEVER run COM-bearing `session.poll()` prior to writing ReadResult to stdout!
            if session.secure_input_detected() {
                let now_unix = clock.unix_ms();
                result = ReadResult::failure(
                    ticket.token.clone(),
                    "secure-input-active",
                    None,
                    now_unix,
                    now_unix,
                );
            } else if let Some(failure) = session.input_failure() {
                let now_unix = clock.unix_ms();
                result = ReadResult::failure(
                    ticket.token.clone(),
                    failure,
                    None,
                    now_unix,
                    now_unix,
                );
            }

            if clock.monotonic_ms() >= ticket.deadline_monotonic_ms {
                return 70;
            }

            let Some(encoded) = encode_read_result_pipe_frame(&mut result) else {
                return 70;
            };
            if !write_all_pipe(stdout_h, &encoded) {
                return 74;
            }
            idle_until = clock.monotonic_ms() + 60_000;
            continue;
        } else if bytes.len() >= WORKER_MAX_FRAME_BYTES {
            return 64;
        }

        session.poll(clock);
        if let Some(failure) = session.input_failure() {
            let mut msg = BTreeMap::new();
            msg.insert(
                "inputDisabled".to_string(),
                JsonValue::String(failure.to_string()),
            );
            let Ok(mut encoded) = JsonValue::Object(msg).canonical_bytes() else {
                return 70;
            };
            encoded.push(b'\n');
            let _ = write_all_pipe(stdout_h, &encoded);
            return 0;
        }
        if session.secure_input_detected() {
            if !secure_sent {
                secure_sent = true;
                if !write_all_pipe(stdout_h, b"{\"secureInput\":true}\n") {
                    return 74;
                }
            }
        } else if !initial {
            let debounce_ms = pinned_policy.as_ref().map(|p| p.debounce_ms).unwrap_or(50);
            if let Some(frame) = next_session_unsolicited_frame(
                session,
                LiveUiaSession::take_next_menu_action,
                LiveUiaSession::take_menu_tracking,
                LiveUiaSession::take_submit_dirty,
                LiveUiaSession::take_dirty,
                clock.monotonic_ms(),
                &mut next_dirty_ms,
                debounce_ms,
            ) {
                if !write_all_pipe(stdout_h, &frame) {
                    return 74;
                }
            }
            if session.has_pending_menu_frame() {
                continue;
            }
        }

        thread::sleep(Duration::from_millis(5));
    }

    0
}
