use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use access_contract::{is_valid_application_id, JsonValue};
use windows::core::BOOL;
use windows::Win32::Foundation::{ERROR_BROKEN_PIPE, HANDLE, HWND, LPARAM};
use windows::Win32::Storage::FileSystem::{GetFileType, ReadFile, WriteFile, FILE_TYPE_UNKNOWN};
use windows::Win32::System::Console::{GetStdHandle, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetForegroundWindow, GetWindowThreadProcessId, IsIconic, IsWindowVisible,
    SetForegroundWindow, ShowWindow, SW_RESTORE,
};

use crate::desktop::assess_windows_desktop;
use crate::ownership::{
    current_wts_session_id, is_console_handle, is_pid_alive, parent_pid,
    process_start_time_for_pid, ParentProcessHandle,
};
use crate::policy::{
    resolve_application_id_for_pid, resolve_effective_pid, ApplicationPolicy, BrowserGate,
};
use crate::protocol_model::{
    ApplicationIdentity, DesktopStatus, SystemCollectorClock, MAX_SAFE_INTEGER,
};

pub const NAVIGATION_MAX_INPUT_BYTES: usize = 2_048;
pub const NAVIGATION_MAX_OUTPUT_BYTES: usize = 1_024;
pub const NAVIGATION_INPUT_TIMEOUT_MS: i64 = 1_000;
pub const NAVIGATION_TOTAL_DEADLINE_MS: i64 = 4_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceNavigationReason {
    Activated,
    InvalidRequest,
    InputTooLarge,
    InputTimeout,
    InputUnavailable,
    ParentUnavailable,
    DeadlineExceeded,
    SessionUnavailable,
    SessionMismatch,
    DesktopUnavailable,
    ApplicationUnavailable,
    ApplicationMismatch,
    ApplicationBlocked,
    ActivationRejected,
    ActivationUnconfirmed,
    PostconditionChanged,
    InternalError,
}

impl SourceNavigationReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Activated => "activated",
            Self::InvalidRequest => "invalid-request",
            Self::InputTooLarge => "input-too-large",
            Self::InputTimeout => "input-timeout",
            Self::InputUnavailable => "input-unavailable",
            Self::ParentUnavailable => "parent-unavailable",
            Self::DeadlineExceeded => "deadline-exceeded",
            Self::SessionUnavailable => "session-unavailable",
            Self::SessionMismatch => "session-mismatch",
            Self::DesktopUnavailable => "desktop-unavailable",
            Self::ApplicationUnavailable => "application-unavailable",
            Self::ApplicationMismatch => "application-mismatch",
            Self::ApplicationBlocked => "application-blocked",
            Self::ActivationRejected => "activation-rejected",
            Self::ActivationUnconfirmed => "activation-unconfirmed",
            Self::PostconditionChanged => "postcondition-changed",
            Self::InternalError => "internal-error",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceNavigationOutcome {
    Activated,
    Refused,
    Uncertain,
}

impl SourceNavigationOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Activated => "activated",
            Self::Refused => "refused",
            Self::Uncertain => "uncertain",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceNavigationReceipt {
    pub outcome: SourceNavigationOutcome,
    pub reason: SourceNavigationReason,
}

impl SourceNavigationReceipt {
    pub fn new(reason: SourceNavigationReason, after_dispatch: bool) -> Self {
        let outcome = match reason {
            SourceNavigationReason::Activated => SourceNavigationOutcome::Activated,
            SourceNavigationReason::ActivationRejected
            | SourceNavigationReason::ActivationUnconfirmed
            | SourceNavigationReason::PostconditionChanged => SourceNavigationOutcome::Uncertain,
            SourceNavigationReason::ParentUnavailable
            | SourceNavigationReason::DeadlineExceeded => {
                if after_dispatch {
                    SourceNavigationOutcome::Uncertain
                } else {
                    SourceNavigationOutcome::Refused
                }
            }
            _ => SourceNavigationOutcome::Refused,
        };
        Self { outcome, reason }
    }

    pub fn encoded_line(&self) -> Vec<u8> {
        format!(
            "{{\"version\":1,\"outcome\":\"{}\",\"reason\":\"{}\",\"captured\":false,\"launched\":false}}\n",
            self.outcome.as_str(),
            self.reason.as_str()
        )
        .into_bytes()
    }

    pub fn exit_code(&self) -> i32 {
        match self.reason {
            SourceNavigationReason::InvalidRequest | SourceNavigationReason::InputTooLarge => 64,
            SourceNavigationReason::InternalError => 70,
            SourceNavigationReason::InputUnavailable => 74,
            SourceNavigationReason::InputTimeout
            | SourceNavigationReason::ParentUnavailable
            | SourceNavigationReason::DeadlineExceeded => 75,
            _ => 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceNavigationRequest {
    pub application_id: String,
    pub process_id: u32,
    pub process_start_time: String,
    pub os_session_id: String,
    pub desktop_id: String,
    pub wts_session_id: u32,
}

impl SourceNavigationRequest {
    pub fn application(&self) -> ApplicationIdentity {
        ApplicationIdentity {
            application_id: self.application_id.clone(),
            process_id: self.process_id,
            process_start_time: self.process_start_time.clone(),
        }
    }

    pub fn accepts_arguments(args: &[String]) -> bool {
        args.len() == 1 && args[0] == "--navigate-source"
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, SourceNavigationReason> {
        if bytes.len() > NAVIGATION_MAX_INPUT_BYTES {
            return Err(SourceNavigationReason::InputTooLarge);
        }
        if bytes.is_empty() || bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
            return Err(SourceNavigationReason::InvalidRequest);
        }
        // Reject duplicate keys strictly before JsonValue::parse (which uses last-key-wins).
        if !has_unique_top_level_object_keys(bytes, 6) {
            return Err(SourceNavigationReason::InvalidRequest);
        }
        let root =
            JsonValue::parse(bytes).map_err(|_| SourceNavigationReason::InvalidRequest)?;
        let obj = root
            .as_obj()
            .ok_or(SourceNavigationReason::InvalidRequest)?;
        if obj.len() != 6 {
            return Err(SourceNavigationReason::InvalidRequest);
        }
        let version = obj
            .get("version")
            .ok_or(SourceNavigationReason::InvalidRequest)?;
        if !matches!(version, JsonValue::Number(v) if *v == 1.0) {
            return Err(SourceNavigationReason::InvalidRequest);
        }

        let raw_pid = match obj.get("processId") {
            Some(JsonValue::Number(n))
                if n.is_finite() && n.trunc() == *n && *n >= 2.0 && *n <= (i32::MAX as f64) =>
            {
                *n as u32
            }
            _ => return Err(SourceNavigationReason::InvalidRequest),
        };

        let application_id = obj
            .get("applicationId")
            .and_then(JsonValue::as_str)
            .ok_or(SourceNavigationReason::InvalidRequest)?;
        if application_id.is_empty()
            || application_id.len() > 256
            || !is_valid_application_id(application_id)
        {
            return Err(SourceNavigationReason::InvalidRequest);
        }

        let process_start_time = obj
            .get("processStartTime")
            .and_then(JsonValue::as_str)
            .ok_or(SourceNavigationReason::InvalidRequest)?;
        if !valid_process_start_time(process_start_time) {
            return Err(SourceNavigationReason::InvalidRequest);
        }

        let os_session_id = obj
            .get("osSessionId")
            .and_then(JsonValue::as_str)
            .ok_or(SourceNavigationReason::InvalidRequest)?;
        let wts_session_id = parse_canonical_wts_session(os_session_id)
            .ok_or(SourceNavigationReason::InvalidRequest)?;

        let desktop_id = obj
            .get("desktopId")
            .and_then(JsonValue::as_str)
            .ok_or(SourceNavigationReason::InvalidRequest)?;
        if desktop_id != format!("winsta0-default-{os_session_id}") {
            return Err(SourceNavigationReason::InvalidRequest);
        }

        Ok(Self {
            application_id: application_id.to_string(),
            process_id: raw_pid,
            process_start_time: process_start_time.to_string(),
            os_session_id: os_session_id.to_string(),
            desktop_id: desktop_id.to_string(),
            wts_session_id,
        })
    }
}

fn parse_canonical_wts_session(value: &str) -> Option<u32> {
    let rest = value.strip_prefix("wts-")?;
    if rest.is_empty() || rest.len() > 10 || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if rest.len() > 1 && rest.starts_with('0') {
        return None;
    }
    let parsed: u32 = rest.parse().ok()?;
    if parsed == u32::MAX {
        return None;
    }
    Some(parsed)
}

fn valid_process_start_time(value: &str) -> bool {
    if value.len() > 40 {
        return false;
    }
    let Some(rest) = value.strip_prefix("unix-ms:") else {
        return false;
    };
    let Some((whole, frac)) = rest.split_once('.') else {
        return false;
    };
    if whole.is_empty()
        || whole.len() > 16
        || frac.len() != 3
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !frac.bytes().all(|b| b.is_ascii_digit())
    {
        return false;
    }
    if whole.len() > 1 && whole.starts_with('0') {
        return false;
    }
    let Ok(n) = rest.parse::<f64>() else {
        return false;
    };
    n.is_finite() && n > 0.0 && n <= (MAX_SAFE_INTEGER as f64)
}

/// Strict flat-JSON top-level key count check that rejects duplicate keys even when values contain commas.
fn has_unique_top_level_object_keys(bytes: &[u8], expected_keys: usize) -> bool {
    let mut i = 0;
    let skip_ws = |idx: &mut usize| {
        while *idx < bytes.len() && matches!(bytes[*idx], b' ' | b'\t' | b'\r' | b'\n') {
            *idx += 1;
        }
    };
    skip_ws(&mut i);
    if i >= bytes.len() || bytes[i] != b'{' {
        return false;
    }
    i += 1;
    let mut depth: usize = 1;
    let mut in_string = false;
    let mut escaped = false;
    let mut commas_at_depth_1: usize = 0;
    let mut colons_at_depth_1: usize = 0;

    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
        } else {
            match b {
                b'"' => in_string = true,
                b'{' | b'[' => depth += 1,
                b'}' | b']' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        break;
                    }
                }
                b',' if depth == 1 => commas_at_depth_1 += 1,
                b':' if depth == 1 => colons_at_depth_1 += 1,
                _ => {}
            }
        }
        i += 1;
    }

    depth == 0
        && !in_string
        && colons_at_depth_1 == expected_keys
        && commas_at_depth_1 == expected_keys.saturating_sub(1)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NavigationSessionEvidence {
    pub current_wts_session_id: Option<u32>,
    pub desktop: DesktopStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NavigationApplicationEvidence {
    pub identity: ApplicationIdentity,
    pub permitted_non_browser: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavigationDispatch {
    NotDispatched(SourceNavigationReason),
    Submitted { accepted: bool },
}

pub trait SourceNavigationProvider {
    fn session_evidence(&self) -> NavigationSessionEvidence;
    fn running_application(&self, process_id: u32) -> Option<NavigationApplicationEvidence>;
    fn activate(
        &self,
        request: &SourceNavigationRequest,
        mark_dispatched: &dyn Fn() -> Option<SourceNavigationReason>,
    ) -> NavigationDispatch;
    fn frontmost_application(&self) -> Option<NavigationApplicationEvidence>;
}

pub fn gate_session(
    request: &SourceNavigationRequest,
    evidence: &NavigationSessionEvidence,
) -> Option<SourceNavigationReason> {
    let sid = evidence.current_wts_session_id?;
    if sid != request.wts_session_id {
        return Some(SourceNavigationReason::SessionMismatch);
    }
    if evidence.desktop != DesktopStatus::Unlocked {
        return Some(SourceNavigationReason::DesktopUnavailable);
    }
    None
}

pub fn gate_session_strict(
    request: &SourceNavigationRequest,
    evidence: &NavigationSessionEvidence,
) -> Option<SourceNavigationReason> {
    if evidence.current_wts_session_id.is_none() {
        return Some(SourceNavigationReason::SessionUnavailable);
    }
    gate_session(request, evidence)
}

pub fn gate_application(
    request: &SourceNavigationRequest,
    evidence: Option<&NavigationApplicationEvidence>,
) -> Option<SourceNavigationReason> {
    let Some(ev) = evidence else {
        return Some(SourceNavigationReason::ApplicationUnavailable);
    };
    if ev.identity != request.application() {
        return Some(SourceNavigationReason::ApplicationMismatch);
    }
    if !ev.permitted_non_browser {
        return Some(SourceNavigationReason::ApplicationBlocked);
    }
    None
}

pub fn navigate_source(
    request: &SourceNavigationRequest,
    provider: &dyn SourceNavigationProvider,
    mark_dispatched: &dyn Fn() -> Option<SourceNavigationReason>,
) -> SourceNavigationReceipt {
    if let Some(reason) = gate_session_strict(request, &provider.session_evidence()) {
        return SourceNavigationReceipt::new(reason, false);
    }
    if let Some(reason) = gate_application(
        request,
        provider.running_application(request.process_id).as_ref(),
    ) {
        return SourceNavigationReceipt::new(reason, false);
    }

    match provider.activate(request, mark_dispatched) {
        NavigationDispatch::NotDispatched(reason) => {
            let allowed = matches!(
                reason,
                SourceNavigationReason::ParentUnavailable
                    | SourceNavigationReason::DeadlineExceeded
                    | SourceNavigationReason::SessionUnavailable
                    | SourceNavigationReason::SessionMismatch
                    | SourceNavigationReason::DesktopUnavailable
                    | SourceNavigationReason::ApplicationUnavailable
                    | SourceNavigationReason::ApplicationMismatch
                    | SourceNavigationReason::ApplicationBlocked
                    | SourceNavigationReason::InternalError
            );
            return SourceNavigationReceipt::new(
                if allowed {
                    reason
                } else {
                    SourceNavigationReason::InternalError
                },
                false,
            );
        }
        NavigationDispatch::Submitted { accepted: false } => {
            return SourceNavigationReceipt::new(SourceNavigationReason::ActivationRejected, true);
        }
        NavigationDispatch::Submitted { accepted: true } => {}
    }

    if gate_session_strict(request, &provider.session_evidence()).is_some()
        || gate_application(
            request,
            provider.running_application(request.process_id).as_ref(),
        )
        .is_some()
    {
        return SourceNavigationReceipt::new(SourceNavigationReason::PostconditionChanged, true);
    }
    if gate_application(request, provider.frontmost_application().as_ref()).is_some() {
        return SourceNavigationReceipt::new(SourceNavigationReason::ActivationUnconfirmed, true);
    }
    if gate_application(
        request,
        provider.running_application(request.process_id).as_ref(),
    )
    .is_some()
        || gate_session_strict(request, &provider.session_evidence()).is_some()
    {
        return SourceNavigationReceipt::new(SourceNavigationReason::PostconditionChanged, true);
    }
    SourceNavigationReceipt::new(SourceNavigationReason::Activated, true)
}

struct WindowSearch {
    target_pid: u32,
    found_hwnd: Option<isize>,
}

unsafe extern "system" fn enum_top_level_for_pid(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let state = &mut *(lparam.0 as *mut WindowSearch);
    if !IsWindowVisible(hwnd).as_bool() {
        return BOOL(1);
    }
    let mut win_pid: u32 = 0;
    GetWindowThreadProcessId(hwnd, Some(&mut win_pid));
    let effective = resolve_effective_pid(win_pid, Some(hwnd.0 as isize));
    if win_pid == state.target_pid || effective == state.target_pid {
        state.found_hwnd = Some(hwnd.0 as isize);
        return BOOL(0);
    }
    BOOL(1)
}

fn find_visible_window_for_pid(pid: u32) -> Option<isize> {
    let mut search = WindowSearch {
        target_pid: pid,
        found_hwnd: None,
    };
    // SAFETY: Stack-local search struct lives for synchronous EnumWindows call.
    unsafe {
        let _ = EnumWindows(
            Some(enum_top_level_for_pid),
            LPARAM(&mut search as *mut WindowSearch as isize),
        );
    }
    search.found_hwnd
}

struct WindowsNavigationProvider;

impl WindowsNavigationProvider {
    fn evidence_for_pid(pid: u32, hwnd: Option<isize>) -> Option<NavigationApplicationEvidence> {
        if !is_pid_alive(pid) {
            return None;
        }
        let app_id = resolve_application_id_for_pid(pid, hwnd)?;
        let start_time = process_start_time_for_pid(pid)?;
        let permitted = !ApplicationPolicy::is_mandatory_denied(&app_id)
            && !ApplicationPolicy::is_system_ui(&app_id)
            && !BrowserGate::is_known_browser(&app_id);
        Some(NavigationApplicationEvidence {
            identity: ApplicationIdentity {
                application_id: app_id,
                process_id: pid,
                process_start_time: start_time,
            },
            permitted_non_browser: permitted,
        })
    }
}

impl SourceNavigationProvider for WindowsNavigationProvider {
    fn session_evidence(&self) -> NavigationSessionEvidence {
        let assessment = assess_windows_desktop();
        NavigationSessionEvidence {
            current_wts_session_id: current_wts_session_id(),
            desktop: assessment.status,
        }
    }

    fn running_application(&self, process_id: u32) -> Option<NavigationApplicationEvidence> {
        let hwnd = find_visible_window_for_pid(process_id);
        Self::evidence_for_pid(process_id, hwnd)
    }

    fn activate(
        &self,
        request: &SourceNavigationRequest,
        mark_dispatched: &dyn Fn() -> Option<SourceNavigationReason>,
    ) -> NavigationDispatch {
        let Some(raw_hwnd) = find_visible_window_for_pid(request.process_id) else {
            return NavigationDispatch::NotDispatched(
                SourceNavigationReason::ApplicationUnavailable,
            );
        };
        if let Some(reason) = gate_session_strict(request, &self.session_evidence()) {
            return NavigationDispatch::NotDispatched(reason);
        }
        if let Some(reason) = gate_application(
            request,
            Self::evidence_for_pid(request.process_id, Some(raw_hwnd)).as_ref(),
        ) {
            return NavigationDispatch::NotDispatched(reason);
        }
        if let Some(reason) = mark_dispatched() {
            return NavigationDispatch::NotDispatched(reason);
        }
        let hwnd = HWND(raw_hwnd as *mut core::ffi::c_void);
        // SAFETY: Valid top-level HWND resolved immediately prior.
        let accepted = unsafe {
            if IsIconic(hwnd).as_bool() {
                let _ = ShowWindow(hwnd, SW_RESTORE);
            }
            SetForegroundWindow(hwnd).as_bool()
        };
        NavigationDispatch::Submitted { accepted }
    }

    fn frontmost_application(&self) -> Option<NavigationApplicationEvidence> {
        // SAFETY: Standard Win32 foreground window query.
        let hwnd = unsafe { GetForegroundWindow() };
        if hwnd.0.is_null() {
            return None;
        }
        let mut pid: u32 = 0;
        // SAFETY: Valid HWND.
        unsafe {
            GetWindowThreadProcessId(hwnd, Some(&mut pid));
        }
        let effective = resolve_effective_pid(pid, Some(hwnd.0 as isize));
        Self::evidence_for_pid(effective, Some(hwnd.0 as isize))
    }
}

fn write_receipt_bounded(receipt: SourceNavigationReceipt) -> i32 {
    let bytes = receipt.encoded_line();
    if bytes.len() > NAVIGATION_MAX_OUTPUT_BYTES {
        return 70;
    }
    let stdout_handle = match unsafe { GetStdHandle(STD_OUTPUT_HANDLE) } {
        Ok(h) if !h.is_invalid() && !h.0.is_null() => h,
        _ => return 74,
    };
    if unsafe { GetFileType(stdout_handle) } == FILE_TYPE_UNKNOWN {
        return 74;
    }

    let raw_handle = stdout_handle.0 as usize;
    let (tx, rx) = mpsc::channel::<bool>();
    thread::spawn(move || {
        let h = HANDLE(raw_handle as *mut core::ffi::c_void);
        let mut offset = 0usize;
        let mut ok = true;
        while offset < bytes.len() {
            let mut written: u32 = 0;
            // SAFETY: Valid stdout handle and remaining byte slice.
            let res = unsafe { WriteFile(h, Some(&bytes[offset..]), Some(&mut written), None) };
            if res.is_err() || written == 0 {
                ok = false;
                break;
            }
            offset += written as usize;
        }
        let _ = tx.send(ok);
    });

    match rx.recv_timeout(Duration::from_millis(500)) {
        Ok(true) => receipt.exit_code(),
        _ => 74,
    }
}

enum StdinReadOutcome {
    Data(Vec<u8>),
    TooLarge,
    Unavailable,
}

fn read_stdin_bounded(
    input_deadline_ms: i64,
    parent: &ParentProcessHandle,
) -> Result<StdinReadOutcome, SourceNavigationReason> {
    let stdin_handle = match unsafe { GetStdHandle(STD_INPUT_HANDLE) } {
        Ok(h) if !h.is_invalid() && !h.0.is_null() => h,
        _ => return Ok(StdinReadOutcome::Unavailable),
    };
    if unsafe { GetFileType(stdin_handle) } == FILE_TYPE_UNKNOWN {
        return Ok(StdinReadOutcome::Unavailable);
    }

    let raw_handle = stdin_handle.0 as usize;
    let (tx, rx) = mpsc::channel::<StdinReadOutcome>();
    thread::spawn(move || {
        let h = HANDLE(raw_handle as *mut core::ffi::c_void);
        let mut out = Vec::with_capacity(512);
        let mut chunk = [0u8; 512];
        loop {
            let mut n: u32 = 0;
            // SAFETY: Valid stdin handle and stack buffer.
            let res = unsafe { ReadFile(h, Some(&mut chunk), Some(&mut n), None) };
            match res {
                Ok(()) if n == 0 => {
                    let _ = tx.send(StdinReadOutcome::Data(out));
                    return;
                }
                Ok(()) => {
                    let count = n as usize;
                    if out.len() + count > NAVIGATION_MAX_INPUT_BYTES {
                        let _ = tx.send(StdinReadOutcome::TooLarge);
                        return;
                    }
                    out.extend_from_slice(&chunk[..count]);
                }
                Err(err) if err.code() == ERROR_BROKEN_PIPE.to_hresult() => {
                    let _ = tx.send(StdinReadOutcome::Data(out));
                    return;
                }
                Err(_) => {
                    let _ = tx.send(StdinReadOutcome::Unavailable);
                    return;
                }
            }
        }
    });

    loop {
        if !parent.is_alive() {
            return Err(SourceNavigationReason::ParentUnavailable);
        }
        let now = SystemCollectorClock::monotonic_ms_now();
        if now >= input_deadline_ms {
            return Err(SourceNavigationReason::InputTimeout);
        }
        let wait_ms = (input_deadline_ms - now).min(20) as u64;
        match rx.recv_timeout(Duration::from_millis(wait_ms)) {
            Ok(outcome) => return Ok(outcome),
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(StdinReadOutcome::Unavailable),
        }
    }
}

/// CLI entrypoint for `--navigate-source`.
/// Enforces 2048B stdin cap, 1s input timeout, 4s total deadline, 20ms parent watchdog,
/// strict duplicate-key/BOM rejection, and exact 5-key receipt with exit codes `0`/`64`/`70`/`74`/`75`.
pub fn run_navigate_source_cli() -> i32 {
    if is_console_handle(STD_OUTPUT_HANDLE) {
        return 74;
    }
    let Some(ppid) = parent_pid() else {
        return write_receipt_bounded(SourceNavigationReceipt::new(
            SourceNavigationReason::ParentUnavailable,
            false,
        ));
    };
    let Some(parent) = ParentProcessHandle::open(ppid) else {
        return write_receipt_bounded(SourceNavigationReceipt::new(
            SourceNavigationReason::ParentUnavailable,
            false,
        ));
    };

    let started = SystemCollectorClock::monotonic_ms_now();
    let total_deadline = started + NAVIGATION_TOTAL_DEADLINE_MS;
    let input_deadline = started + NAVIGATION_INPUT_TIMEOUT_MS;

    let parent = Arc::new(parent);
    let after_dispatch = Arc::new(AtomicBool::new(false));
    let finished = Arc::new(AtomicBool::new(false));

    // Independent 20ms parent & total-deadline watchdog thread.
    let wd_parent = Arc::clone(&parent);
    let wd_dispatched = Arc::clone(&after_dispatch);
    let wd_finished = Arc::clone(&finished);
    thread::spawn(move || {
        while !wd_finished.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(20));
            if wd_finished.load(Ordering::Acquire) {
                return;
            }
            let dispatched = wd_dispatched.load(Ordering::Acquire);
            if !wd_parent.is_alive() {
                let code = write_receipt_bounded(SourceNavigationReceipt::new(
                    SourceNavigationReason::ParentUnavailable,
                    dispatched,
                ));
                std::process::exit(code);
            }
            if SystemCollectorClock::monotonic_ms_now() >= total_deadline {
                let code = write_receipt_bounded(SourceNavigationReceipt::new(
                    SourceNavigationReason::DeadlineExceeded,
                    dispatched,
                ));
                std::process::exit(code);
            }
        }
    });

    let input_bytes = match read_stdin_bounded(input_deadline, &parent) {
        Ok(StdinReadOutcome::Data(data)) => data,
        Ok(StdinReadOutcome::TooLarge) => {
            finished.store(true, Ordering::Release);
            return write_receipt_bounded(SourceNavigationReceipt::new(
                SourceNavigationReason::InputTooLarge,
                false,
            ));
        }
        Ok(StdinReadOutcome::Unavailable) => {
            finished.store(true, Ordering::Release);
            return write_receipt_bounded(SourceNavigationReceipt::new(
                SourceNavigationReason::InputUnavailable,
                false,
            ));
        }
        Err(reason) => {
            finished.store(true, Ordering::Release);
            return write_receipt_bounded(SourceNavigationReceipt::new(reason, false));
        }
    };

    let request = match SourceNavigationRequest::parse(&input_bytes) {
        Ok(req) => req,
        Err(reason) => {
            finished.store(true, Ordering::Release);
            return write_receipt_bounded(SourceNavigationReceipt::new(reason, false));
        }
    };

    let mark_dispatched = || -> Option<SourceNavigationReason> {
        if !parent.is_alive() {
            return Some(SourceNavigationReason::ParentUnavailable);
        }
        if SystemCollectorClock::monotonic_ms_now() >= total_deadline {
            return Some(SourceNavigationReason::DeadlineExceeded);
        }
        after_dispatch.store(true, Ordering::Release);
        None
    };

    let provider = WindowsNavigationProvider;
    let receipt = navigate_source(&request, &provider, &mark_dispatched);
    finished.store(true, Ordering::Release);
    write_receipt_bounded(receipt)
}
