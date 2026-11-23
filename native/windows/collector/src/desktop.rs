use std::collections::BTreeMap;
use std::io::Write;

use access_contract::JsonValue;
use windows::Win32::Foundation::ERROR_ACCESS_DENIED;
use windows::Win32::System::RemoteDesktop::{
    WTSActive, WTSFreeMemory, WTSGetActiveConsoleSessionId, WTSQuerySessionInformationW,
    WTSSessionInfoEx, WTSINFOEXW, WTS_CURRENT_SERVER_HANDLE, WTS_SESSIONSTATE_LOCK,
    WTS_SESSIONSTATE_UNLOCK,
};
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, GetUserObjectInformationW, OpenInputDesktop, DESKTOP_CONTROL_FLAGS,
    DESKTOP_READOBJECTS, UOI_NAME,
};

use crate::ownership::current_wts_session_id;
use crate::protocol_model::DesktopStatus;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WtsLockState {
    Locked,
    Unlocked,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputDesktopState {
    Default,
    LockedDesktop,
    AccessDenied,
    Other,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DesktopSample {
    pub pid_session: Option<u32>,
    pub active_console: u32,
    pub wts_lock: WtsLockState,
    pub wts_active: Option<bool>,
    pub input_desktop: InputDesktopState,
}

impl DesktopSample {
    pub fn is_locked(&self) -> bool {
        self.wts_lock == WtsLockState::Locked
            || self.input_desktop == InputDesktopState::LockedDesktop
    }
}

/// Windows desktop readiness & lock assessment strictly upholding `parsePermissionReport(..., 'win32')` invariants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopAssessment {
    pub status: DesktopStatus,
    pub reason: &'static str,
    pub session_available: bool,
    pub session_matches_process: bool,
    pub session_stable: bool,
    pub signals_valid: bool,
    pub lock_transition: bool,
    pub screen_locked: Option<bool>,
    pub lock_source: &'static str,
}

impl DesktopAssessment {
    /// Construct a `DesktopAssessment` from two consecutive Win32 desktop samples.
    ///
    /// Guarantees two-way locked/unlocked invariants required by `src/host/service/permissions.ts`:
    /// - `locked = (screen_locked == Some(true))` <=> `status == Locked && reason == "screen-locked"`
    /// - `ready = !locked && lock_source in ["wts-session","win32-desktop"] && session_available
    ///   && session_matches_process && session_stable && signals_valid && !lock_transition
    ///   && screen_locked == Some(false)` <=> `status == Unlocked && reason == "ready"`
    /// - `lock_source` is ALWAYS in `["wts-session", "win32-desktop", "unknown"]`.
    pub fn from_samples(s1: DesktopSample, s2: DesktopSample) -> Self {
        let valid_pid_session =
            |s: DesktopSample| s.pid_session.is_some_and(|sid| sid != 0 && sid != u32::MAX);
        let session_available = valid_pid_session(s1) && valid_pid_session(s2);
        let both_console = session_available
            && s1.active_console != u32::MAX
            && s2.active_console != u32::MAX
            && s1.pid_session == Some(s1.active_console)
            && s2.pid_session == Some(s2.active_console);
        let both_wts_active =
            session_available && s1.wts_active == Some(true) && s2.wts_active == Some(true);
        let console_involved = (s1.active_console != u32::MAX
            && s1.pid_session == Some(s1.active_console))
            || (s2.active_console != u32::MAX && s2.pid_session == Some(s2.active_console));
        let session_stable = s1.pid_session == s2.pid_session
            && s1.wts_active == s2.wts_active
            && (!console_involved || s1.active_console == s2.active_console);
        // Active interactive WTS session (console OR active RDP) matches this process when WTS
        // reports `WTSActive` for `pid_session`, or (on console fallback only) when `pid_session`
        // equals `WTSGetActiveConsoleSessionId()` and WTS state is not inactive.
        let session_matches_process = session_available
            && (both_wts_active
                || (both_console && s1.wts_active.is_none() && s2.wts_active.is_none()));
        let lock_transition = s1.wts_lock != s2.wts_lock || s1.input_desktop != s2.input_desktop;

        let locked = s1.is_locked() || s2.is_locked();
        if locked {
            let lock_source =
                if s1.wts_lock == WtsLockState::Locked || s2.wts_lock == WtsLockState::Locked {
                    "wts-session"
                } else {
                    "win32-desktop"
                };
            return Self {
                status: DesktopStatus::Locked,
                reason: "screen-locked",
                session_available,
                session_matches_process,
                session_stable,
                signals_valid: true,
                lock_transition,
                screen_locked: Some(true),
                lock_source,
            };
        }

        let wts_inactive = s1.wts_active == Some(false) || s2.wts_active == Some(false);
        let desktop_other = s1.input_desktop == InputDesktopState::Other
            || s2.input_desktop == InputDesktopState::Other;
        let wts_desktop_contradiction = (s1.wts_lock == WtsLockState::Unlocked
            && matches!(
                s1.input_desktop,
                InputDesktopState::AccessDenied | InputDesktopState::Other
            ))
            || (s2.wts_lock == WtsLockState::Unlocked
                && matches!(
                    s2.input_desktop,
                    InputDesktopState::AccessDenied | InputDesktopState::Other
                ));
        let signals_valid = !wts_inactive && !desktop_other && !wts_desktop_contradiction;

        let (lock_source, screen_locked) = if both_wts_active
            && s1.wts_lock == WtsLockState::Unlocked
            && s2.wts_lock == WtsLockState::Unlocked
            && s1.input_desktop == InputDesktopState::Default
            && s2.input_desktop == InputDesktopState::Default
        {
            ("wts-session", Some(false))
        } else if both_console
            && !wts_inactive
            && s1.wts_lock == WtsLockState::Unknown
            && s2.wts_lock == WtsLockState::Unknown
            && s1.input_desktop == InputDesktopState::Default
            && s2.input_desktop == InputDesktopState::Default
        {
            ("win32-desktop", Some(false))
        } else {
            ("unknown", None)
        };

        let ready = (lock_source == "wts-session" || lock_source == "win32-desktop")
            && session_available
            && session_matches_process
            && session_stable
            && signals_valid
            && !lock_transition
            && screen_locked == Some(false);

        if ready {
            Self {
                status: DesktopStatus::Unlocked,
                reason: "ready",
                session_available,
                session_matches_process,
                session_stable,
                signals_valid,
                lock_transition,
                screen_locked,
                lock_source,
            }
        } else {
            let reason = if !session_available {
                "session-unavailable"
            } else if !signals_valid {
                "desktop-signal-invalid"
            } else if !session_stable {
                "desktop-session-changed"
            } else if !session_matches_process {
                "desktop-session-mismatch"
            } else if lock_transition {
                "desktop-lock-transition"
            } else {
                "lock-state-unavailable"
            };
            Self {
                status: DesktopStatus::Unknown,
                reason,
                session_available,
                session_matches_process,
                session_stable,
                signals_valid,
                lock_transition,
                screen_locked,
                lock_source,
            }
        }
    }

    pub fn to_json(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert(
            "status".to_string(),
            JsonValue::String(self.status.as_str().to_string()),
        );
        map.insert(
            "reason".to_string(),
            JsonValue::String(self.reason.to_string()),
        );
        map.insert(
            "sessionAvailable".to_string(),
            JsonValue::Bool(self.session_available),
        );
        map.insert(
            "sessionMatchesProcess".to_string(),
            JsonValue::Bool(self.session_matches_process),
        );
        map.insert(
            "sessionStable".to_string(),
            JsonValue::Bool(self.session_stable),
        );
        map.insert(
            "signalsValid".to_string(),
            JsonValue::Bool(self.signals_valid),
        );
        map.insert(
            "lockTransition".to_string(),
            JsonValue::Bool(self.lock_transition),
        );
        if let Some(locked) = self.screen_locked {
            map.insert("screenLocked".to_string(), JsonValue::Bool(locked));
        }
        map.insert(
            "lockSource".to_string(),
            JsonValue::String(self.lock_source.to_string()),
        );
        JsonValue::Object(map)
    }
}

fn query_wts_session_state(session_id: u32) -> (WtsLockState, Option<bool>) {
    // SAFETY: WTSQuerySessionInformationW allocates a WTSINFOEXW buffer freed via WTSFreeMemory.
    unsafe {
        let mut ptr = windows::core::PWSTR::null();
        let mut bytes: u32 = 0;
        if WTSQuerySessionInformationW(
            Some(WTS_CURRENT_SERVER_HANDLE),
            session_id,
            WTSSessionInfoEx,
            &mut ptr,
            &mut bytes,
        )
        .is_err()
        {
            return (WtsLockState::Unknown, None);
        }
        if ptr.is_null() || (bytes as usize) < std::mem::size_of::<WTSINFOEXW>() {
            if !ptr.is_null() {
                WTSFreeMemory(ptr.0 as *mut core::ffi::c_void);
            }
            return (WtsLockState::Unknown, None);
        }
        let info = *(ptr.0 as *const WTSINFOEXW);
        WTSFreeMemory(ptr.0 as *mut core::ffi::c_void);
        if info.Level != 1 {
            return (WtsLockState::Unknown, None);
        }
        let level1 = info.Data.WTSInfoExLevel1;
        let is_active = level1.SessionState == WTSActive;
        let lock = match level1.SessionFlags as u32 {
            x if x == WTS_SESSIONSTATE_LOCK => WtsLockState::Locked,
            x if x == WTS_SESSIONSTATE_UNLOCK => WtsLockState::Unlocked,
            _ => WtsLockState::Unknown,
        };
        (lock, Some(is_active))
    }
}

fn query_input_desktop_state() -> InputDesktopState {
    // SAFETY: OpenInputDesktop handle closed via CloseDesktop before returning.
    unsafe {
        let hdesk = match OpenInputDesktop(
            DESKTOP_CONTROL_FLAGS(0),
            false,
            DESKTOP_READOBJECTS,
        ) {
            Ok(h) => h,
            Err(err) => {
                if err.code() == ERROR_ACCESS_DENIED.to_hresult() {
                    return InputDesktopState::AccessDenied;
                }
                return InputDesktopState::Unavailable;
            }
        };
        let mut buf = [0u16; 128];
        let mut needed: u32 = 0;
        let ok = GetUserObjectInformationW(
            windows::Win32::Foundation::HANDLE(hdesk.0),
            UOI_NAME,
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            (buf.len() * 2) as u32,
            Some(&mut needed),
        )
        .is_ok();
        let _ = CloseDesktop(hdesk);
        if !ok {
            return InputDesktopState::Unavailable;
        }
        let units = (needed as usize / 2).min(buf.len());
        let len = buf[..units].iter().position(|&c| c == 0).unwrap_or(units);
        let Ok(name) = String::from_utf16(&buf[..len]) else {
            return InputDesktopState::Other;
        };
        if name.eq_ignore_ascii_case("default") {
            InputDesktopState::Default
        } else if name.eq_ignore_ascii_case("winlogon")
            || name.eq_ignore_ascii_case("screen-saver")
        {
            InputDesktopState::LockedDesktop
        } else {
            InputDesktopState::Other
        }
    }
}

fn sample_desktop_once() -> DesktopSample {
    let pid_session = current_wts_session_id();
    // SAFETY: WTSGetActiveConsoleSessionId takes no arguments.
    let active_console = unsafe { WTSGetActiveConsoleSessionId() };
    let (wts_lock, wts_active) = match pid_session {
        Some(sid) => query_wts_session_state(sid),
        None => (WtsLockState::Unknown, None),
    };
    let input_desktop = query_input_desktop_state();
    DesktopSample {
        pid_session,
        active_console,
        wts_lock,
        wts_active,
        input_desktop,
    }
}

/// Live dual-sampled Windows desktop assessment.
pub fn assess_windows_desktop() -> DesktopAssessment {
    let s1 = sample_desktop_once();
    let s2 = sample_desktop_once();
    DesktopAssessment::from_samples(s1, s2)
}

/// Sticky lock/boundary latch that holds blocked state until explicit user `start`/`resume`.
#[derive(Debug, Default, Clone, Copy)]
pub struct DesktopBoundaryLatch {
    latched: bool,
}

impl DesktopBoundaryLatch {
    pub fn new() -> Self {
        Self { latched: false }
    }

    pub fn is_latched(&self) -> bool {
        self.latched
    }

    pub fn block(&mut self) {
        self.latched = true;
    }

    pub fn reset_for_user_action(&mut self) {
        self.latched = false;
    }

    pub fn observe(&mut self, value: &DesktopAssessment) -> DesktopStatus {
        if value.status == DesktopStatus::Locked
            || !value.session_available
            || value.lock_transition
        {
            self.latched = true;
        }
        if self.latched {
            if value.status == DesktopStatus::Locked {
                DesktopStatus::Locked
            } else {
                DesktopStatus::Unknown
            }
        } else {
            value.status
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionAction {
    Check,
    RequestAccessibility,
    OpenAccessibilitySettings,
    RequestInputMonitoring,
    OpenInputMonitoringSettings,
}

impl PermissionAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::RequestAccessibility => "request-accessibility",
            Self::OpenAccessibilitySettings => "open-accessibility-settings",
            Self::RequestInputMonitoring => "request-input-monitoring",
            Self::OpenInputMonitoringSettings => "open-input-monitoring-settings",
        }
    }

    pub fn parse_str(s: &str) -> Option<Self> {
        match s {
            "check" => Some(Self::Check),
            "request-accessibility" => Some(Self::RequestAccessibility),
            "open-accessibility-settings" => Some(Self::OpenAccessibilitySettings),
            "request-input-monitoring" => Some(Self::RequestInputMonitoring),
            "open-input-monitoring-settings" => Some(Self::OpenInputMonitoringSettings),
            _ => None,
        }
    }

    pub fn parse_args(args: &[String]) -> Option<Self> {
        if args.len() == 2 && args[0] == "--permissions" {
            Self::parse_str(&args[1])
        } else {
            None
        }
    }
}

/// Build the closed 9-key `PermissionResponse` JSON strictly valid for `platform === 'win32'`.
pub fn build_permission_response(
    action: PermissionAction,
    assessment: &DesktopAssessment,
) -> JsonValue {
    let mut input_mon = BTreeMap::new();
    input_mon.insert(
        "state".to_string(),
        JsonValue::String("not-applicable".to_string()),
    );
    input_mon.insert(
        "promptRequested".to_string(),
        JsonValue::Bool(action == PermissionAction::RequestInputMonitoring),
    );
    input_mon.insert("settingsOpened".to_string(), JsonValue::Bool(false));

    let mut map = BTreeMap::new();
    map.insert("version".to_string(), JsonValue::Number(1.0));
    map.insert(
        "action".to_string(),
        JsonValue::String(action.as_str().to_string()),
    );
    map.insert(
        "accessibility".to_string(),
        JsonValue::String("not-applicable".to_string()),
    );
    map.insert("desktop".to_string(), assessment.to_json());
    map.insert(
        "screenRecording".to_string(),
        JsonValue::String("not-required".to_string()),
    );
    map.insert(
        "promptRequested".to_string(),
        JsonValue::Bool(action == PermissionAction::RequestAccessibility),
    );
    map.insert("settingsOpened".to_string(), JsonValue::Bool(false));
    map.insert("captured".to_string(), JsonValue::Bool(false));
    map.insert("inputMonitoring".to_string(), JsonValue::Object(input_mon));
    JsonValue::Object(map)
}

/// CLI entrypoint for `--permissions <action>`.
/// Exit codes: `0` success, `64` invalid args, `70` encode/size/write failure.
pub fn run_permissions_cli(action_str: &str) -> i32 {
    let Some(action) = PermissionAction::parse_str(action_str) else {
        return 64;
    };
    let assessment = assess_windows_desktop();
    let response = build_permission_response(action, &assessment);
    let Ok(mut encoded) = response.canonical_bytes() else {
        return 70;
    };
    encoded.push(b'\n');
    if encoded.len() > 4_096 {
        return 70;
    }
    let mut stdout = std::io::stdout().lock();
    if stdout.write_all(&encoded).is_err() || stdout.flush().is_err() {
        return 70;
    }
    0
}
