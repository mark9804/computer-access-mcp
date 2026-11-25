use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use access_contract::{is_valid_application_id, JsonValue};
use windows::core::BOOL;
use windows::Win32::Foundation::{ERROR_BROKEN_PIPE, HANDLE, HWND, LPARAM};
use windows::Win32::Storage::FileSystem::{GetFileType, ReadFile, WriteFile, FILE_TYPE_UNKNOWN};
use windows::Win32::System::Console::{GetStdHandle, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetForegroundWindow, GetWindowThreadProcessId, IsIconic, IsWindow,
    IsWindowVisible, SetForegroundWindow, ShowWindow, SW_RESTORE,
};

use crate::desktop::assess_windows_desktop;
use crate::ownership::{
    current_wts_session_id, is_console_handle, is_pid_alive, parent_pid,
    process_start_time_for_pid, ParentProcessHandle,
};
use crate::policy::{
    resolve_app_identity_for_pid, resolve_effective_pid_checked, ApplicationPolicy, BrowserGate,
    ResolvedAppIdentity,
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
    pub resolved_identity: Option<ResolvedAppIdentity>,
}

impl NavigationApplicationEvidence {
    pub fn new(identity: ApplicationIdentity, permitted_non_browser: bool) -> Self {
        Self {
            identity,
            permitted_non_browser,
            resolved_identity: None,
        }
    }

    pub fn with_resolved(
        identity: ApplicationIdentity,
        permitted_non_browser: bool,
        resolved_identity: ResolvedAppIdentity,
    ) -> Self {
        Self {
            identity,
            permitted_non_browser,
            resolved_identity: Some(resolved_identity),
        }
    }
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
    let Some(sid) = evidence.current_wts_session_id else {
        return Some(SourceNavigationReason::SessionUnavailable);
    };
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
    gate_session(request, evidence)
}

fn is_blocked_navigation_id(id: &str) -> bool {
    id.eq_ignore_ascii_case("applicationframehost.exe")
        || ApplicationPolicy::is_mandatory_denied(id)
        || ApplicationPolicy::is_system_ui(id)
        || BrowserGate::is_known_browser(id)
}

pub fn gate_application(
    request: &SourceNavigationRequest,
    evidence: Option<&NavigationApplicationEvidence>,
) -> Option<SourceNavigationReason> {
    let Some(ev) = evidence else {
        return Some(SourceNavigationReason::ApplicationUnavailable);
    };
    if ev.identity.process_id != request.process_id
        || ev.identity.process_start_time != request.process_start_time
    {
        return Some(SourceNavigationReason::ApplicationMismatch);
    }
    let app_id_matches = match ev.resolved_identity {
        Some(ref resolved) => resolved.matches_id(&request.application_id),
        None => ev.identity.application_id == request.application_id,
    };
    if !app_id_matches {
        return Some(SourceNavigationReason::ApplicationMismatch);
    }
    let resolved_blocked = ev.resolved_identity.as_ref().is_some_and(|resolved| {
        ApplicationPolicy::is_mandatory_denied_identity(resolved)
            || ApplicationPolicy::is_system_ui_identity(resolved)
            || ApplicationPolicy::is_browser_identity(resolved)
    });
    if !ev.permitted_non_browser
        || resolved_blocked
        || is_blocked_navigation_id(&request.application_id)
        || is_blocked_navigation_id(&ev.identity.application_id)
    {
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

/// Strictly matches a top-level window against `target_pid` using ONLY the unwrapped effective PID,
/// preventing `ApplicationFrameHost.exe` host PIDs from being spliced onto an inner UWP window.
pub fn window_matches_target_pid(effective_pid: Option<u32>, target_pid: u32) -> bool {
    target_pid > 1 && effective_pid == Some(target_pid)
}

unsafe extern "system" fn enum_top_level_for_pid(hwnd: HWND, lparam: LPARAM) -> BOOL {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if lparam.0 == 0 {
            return BOOL(0);
        }
        // SAFETY: `lparam` points to stack-local `WindowSearch` during synchronous `EnumWindows`.
        let state = unsafe { &mut *(lparam.0 as *mut WindowSearch) };
        // SAFETY: Standard read-only Win32 visibility query.
        if unsafe { !IsWindowVisible(hwnd).as_bool() } {
            return BOOL(1);
        }
        let mut win_pid: u32 = 0;
        // SAFETY: Standard read-only Win32 PID query.
        unsafe {
            GetWindowThreadProcessId(hwnd, Some(&mut win_pid));
        }
        let effective = resolve_effective_pid_checked(win_pid, Some(hwnd.0 as isize));
        if window_matches_target_pid(effective, state.target_pid) {
            state.found_hwnd = Some(hwnd.0 as isize);
            return BOOL(0);
        }
        BOOL(1)
    }))
    .unwrap_or(BOOL(0))
}

fn find_visible_window_for_pid(pid: u32) -> Option<isize> {
    if pid <= 1 {
        return None;
    }
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
        if pid <= 1 || !is_pid_alive(pid) {
            return None;
        }
        // Guard against AFH cross-PID splicing: `pid` must already be the unwrapped effective PID.
        let effective_pid = resolve_effective_pid_checked(pid, hwnd)?;
        if effective_pid != pid {
            return None;
        }
        let resolved = resolve_app_identity_for_pid(effective_pid, hwnd)?;
        let start_time = process_start_time_for_pid(effective_pid)?;
        let permitted = !ApplicationPolicy::is_mandatory_denied_identity(&resolved)
            && !ApplicationPolicy::is_system_ui_identity(&resolved)
            && !ApplicationPolicy::is_browser_identity(&resolved);
        Some(NavigationApplicationEvidence::with_resolved(
            ApplicationIdentity {
                application_id: resolved.application_id.clone(),
                process_id: pid,
                process_start_time: start_time,
            },
            permitted,
            resolved,
        ))
    }

    fn evidence_for_hwnd(
        raw_hwnd: isize,
        require_visible: bool,
    ) -> Option<NavigationApplicationEvidence> {
        if raw_hwnd == 0 {
            return None;
        }
        let hwnd = HWND(raw_hwnd as *mut core::ffi::c_void);
        // SAFETY: Standard Win32 window liveness/visibility and owning-PID queries.
        let win_pid = unsafe {
            if !IsWindow(Some(hwnd)).as_bool() {
                return None;
            }
            if require_visible && !IsWindowVisible(hwnd).as_bool() {
                return None;
            }
            let mut pid: u32 = 0;
            GetWindowThreadProcessId(hwnd, Some(&mut pid));
            pid
        };
        let effective = resolve_effective_pid_checked(win_pid, Some(raw_hwnd))?;
        Self::evidence_for_pid(effective, Some(raw_hwnd))
    }
}

impl SourceNavigationProvider for WindowsNavigationProvider {
    fn session_evidence(&self) -> NavigationSessionEvidence {
        let assessment = assess_windows_desktop();
        let sid = current_wts_session_id();
        let cleanly_unlocked = assessment.status == DesktopStatus::Unlocked
            && assessment.session_available
            && assessment.session_matches_process
            && assessment.session_stable
            && assessment.signals_valid
            && !assessment.lock_transition;
        NavigationSessionEvidence {
            current_wts_session_id: if assessment.session_available {
                sid
            } else {
                None
            },
            desktop: if cleanly_unlocked {
                DesktopStatus::Unlocked
            } else if assessment.status == DesktopStatus::Locked {
                DesktopStatus::Locked
            } else {
                DesktopStatus::Unknown
            },
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
        // Re-verify the HWND's live owning PID, AFH unwrap, process start time, and dual-ID
        // immediately AFTER `assess_windows_desktop()` so a recycled HWND cannot be activated.
        let live_hwnd_evidence = Self::evidence_for_hwnd(raw_hwnd, true);
        if let Some(reason) = gate_application(request, live_hwnd_evidence.as_ref()) {
            return NavigationDispatch::NotDispatched(reason);
        }
        if let Some(reason) = mark_dispatched() {
            return NavigationDispatch::NotDispatched(reason);
        }
        let hwnd = HWND(raw_hwnd as *mut core::ffi::c_void);
        // SAFETY: Valid top-level HWND whose owning PID, start time, and dual-ID were just re-verified.
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
        Self::evidence_for_hwnd(hwnd.0 as isize, false)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WatchdogPhase {
    Pending,
    Dispatched,
    Finished,
}

#[derive(Debug)]
struct WatchdogState {
    phase: WatchdogPhase,
    emitted: bool,
}

/// Single-mutex watchdog state coordinator mirroring macOS `SourceNavigationWatchdog`.
///
/// Serializes dispatch transition (`Pending -> Dispatched`), timeout/parent-death termination,
/// and single-shot receipt emission so the watchdog and main thread can NEVER interleave stdout
/// writes or dispatch activation after a refusal receipt has been claimed.
pub struct SourceNavigationWatchdog {
    state: Mutex<WatchdogState>,
    total_deadline_ms: i64,
}

impl SourceNavigationWatchdog {
    pub fn new(total_deadline_ms: i64) -> Self {
        Self {
            state: Mutex::new(WatchdogState {
                phase: WatchdogPhase::Pending,
                emitted: false,
            }),
            total_deadline_ms,
        }
    }

    pub fn is_finished(&self) -> bool {
        let guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        guard.phase == WatchdogPhase::Finished || guard.emitted
    }

    /// Atomically validate parent/deadline boundary and mark dispatch started under the mutex.
    /// Returns `None` iff dispatch is authorized; returns `Some(reason)` if already finished,
    /// parent died, or deadline expired — preventing any post-timeout activation.
    pub fn try_mark_dispatched(
        &self,
        parent_alive: bool,
        now_ms: i64,
    ) -> Option<SourceNavigationReason> {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if guard.emitted || guard.phase == WatchdogPhase::Finished {
            return Some(SourceNavigationReason::DeadlineExceeded);
        }
        if !parent_alive {
            return Some(SourceNavigationReason::ParentUnavailable);
        }
        if now_ms >= self.total_deadline_ms {
            return Some(SourceNavigationReason::DeadlineExceeded);
        }
        guard.phase = WatchdogPhase::Dispatched;
        None
    }

    /// Atomically claim single-shot receipt emission while holding the watchdog mutex.
    ///
    /// `build_receipt` receives `after_dispatch: bool` from the locked state, and `emit` executes
    /// while the mutex is held so no concurrent writer or post-timeout dispatch can race.
    /// Returns `None` if another caller already emitted a receipt.
    pub fn claim_and_emit<B, E, R>(&self, build_receipt: B, emit: E) -> Option<R>
    where
        B: FnOnce(bool) -> SourceNavigationReceipt,
        E: FnOnce(SourceNavigationReceipt) -> R,
    {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if guard.emitted || guard.phase == WatchdogPhase::Finished {
            return None;
        }
        let after_dispatch = guard.phase == WatchdogPhase::Dispatched;
        guard.phase = WatchdogPhase::Finished;
        guard.emitted = true;
        let receipt = build_receipt(after_dispatch);
        Some(emit(receipt))
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
    if is_console_handle(STD_INPUT_HANDLE) {
        return Ok(StdinReadOutcome::Unavailable);
    }
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
    let watchdog = Arc::new(SourceNavigationWatchdog::new(total_deadline));

    // Independent 20ms parent & total-deadline watchdog thread synchronized via single Mutex.
    let wd_parent = Arc::clone(&parent);
    let wd_dog = Arc::clone(&watchdog);
    thread::spawn(move || {
        while !wd_dog.is_finished() {
            thread::sleep(Duration::from_millis(20));
            if wd_dog.is_finished() {
                return;
            }
            let boundary_reason = if !wd_parent.is_alive() {
                Some(SourceNavigationReason::ParentUnavailable)
            } else if SystemCollectorClock::monotonic_ms_now() >= total_deadline {
                Some(SourceNavigationReason::DeadlineExceeded)
            } else {
                None
            };
            if let Some(reason) = boundary_reason {
                let _ = wd_dog.claim_and_emit(
                    |after_dispatch| SourceNavigationReceipt::new(reason, after_dispatch),
                    |receipt| {
                        // Emit and exit while still holding the watchdog mutex so the main thread
                        // cannot write stdout concurrently or enter dispatch after a refusal.
                        let code = write_receipt_bounded(receipt);
                        std::process::exit(code);
                    },
                );
                return;
            }
        }
    });

    let finish_reason = |reason: SourceNavigationReason| -> i32 {
        watchdog
            .claim_and_emit(
                |after_dispatch| SourceNavigationReceipt::new(reason, after_dispatch),
                write_receipt_bounded,
            )
            .unwrap_or(75)
    };

    let input_bytes = match read_stdin_bounded(input_deadline, &parent) {
        Ok(StdinReadOutcome::Data(data)) => data,
        Ok(StdinReadOutcome::TooLarge) => {
            return finish_reason(SourceNavigationReason::InputTooLarge);
        }
        Ok(StdinReadOutcome::Unavailable) => {
            return finish_reason(SourceNavigationReason::InputUnavailable);
        }
        Err(reason) => {
            return finish_reason(reason);
        }
    };

    let request = match SourceNavigationRequest::parse(&input_bytes) {
        Ok(req) => req,
        Err(reason) => {
            return finish_reason(reason);
        }
    };

    let mark_dispatched = || -> Option<SourceNavigationReason> {
        watchdog.try_mark_dispatched(parent.is_alive(), SystemCollectorClock::monotonic_ms_now())
    };

    let provider = WindowsNavigationProvider;
    let receipt = navigate_source(&request, &provider, &mark_dispatched);
    watchdog
        .claim_and_emit(
            |after_dispatch| {
                if !parent.is_alive() {
                    SourceNavigationReceipt::new(
                        SourceNavigationReason::ParentUnavailable,
                        after_dispatch,
                    )
                } else if SystemCollectorClock::monotonic_ms_now() >= total_deadline {
                    SourceNavigationReceipt::new(
                        SourceNavigationReason::DeadlineExceeded,
                        after_dispatch,
                    )
                } else {
                    receipt
                }
            },
            write_receipt_bounded,
        )
        .unwrap_or(75)
}

#[cfg(test)]
mod callback_guard_tests {
    use super::*;

    #[test]
    fn enum_top_level_for_pid_null_lparam_returns_false_without_ub() {
        // SAFETY: Passing null `lparam` exercises the explicit null guard inside `catch_unwind`.
        let cont = unsafe { enum_top_level_for_pid(HWND(core::ptr::null_mut()), LPARAM(0)) };
        assert_eq!(cont, BOOL(0));
    }
}
