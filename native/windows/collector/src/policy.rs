use access_contract::{is_valid_application_id, utf16_len};
use windows::core::{BOOL, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, HWND, LPARAM,
};
use windows::Win32::Storage::Packaging::Appx::GetPackageFamilyName;
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumChildWindows, GetClassNameW, GetWindowThreadProcessId, IsWindowVisible,
};

use crate::protocol_model::{CapturePolicy, SecureStatus};

/// Mandatory excluded application bundle/exe families enforced across Host and Collector.
/// Matches `MANDATORY_EXCLUDED_APPLICATION_IDS` in `src/shared/app-policy.ts`.
pub const MANDATORY_EXCLUDED_APPLICATION_IDS: &[&str] = &[
    "com.1password",
    "com.agilebits.onepassword",
    "com.agilebits.onepassword7",
    "com.agilebits.onepassword-osx",
    "com.apple.safari",
    "com.apple.passwords",
    "com.apple.keychainaccess",
    "com.bitwarden.desktop",
    "com.dashlane.dashlanephonefinal",
    "com.lastpass.lastpass",
    "com.nordsec.nordpass",
    "me.proton.pass",
    "1password.exe",
    "bitwarden.exe",
    "keepass.exe",
    "keepassxc.exe",
    "dashlane.exe",
    "lastpass.exe",
    "nordpass.exe",
    "protonpass.exe",
];

/// System UI and authentication overlays silently skipped without emitting gap records.
/// Matches `SYSTEM_UI_SKIP_APPLICATION_IDS` in `src/shared/app-policy.ts`.
pub const SYSTEM_UI_SKIP_APPLICATION_IDS: &[&str] = &[
    "com.apple.windowmanager",
    "com.apple.controlcenter",
    "com.apple.notificationcenterui",
    "com.apple.securityagent",
    "com.apple.localauthentication.uiagent",
    "com.apple.localauthenticationremoteservice",
    "com.apple.loginwindow",
    "com.apple.usernotificationcenter",
    "lockapp.exe",
    "logonui.exe",
    "credentialuibroker.exe",
    "consent.exe",
    "shellexperiencehost.exe",
    "startmenuexperiencehost.exe",
    "searchhost.exe",
    "searchapp.exe",
    "textinputhost.exe",
    "pickerhost.exe",
];

/// Known browser application families matching `BROWSER_APPLICATION_FAMILIES` in `src/shared/app-policy.ts`.
pub const BROWSER_APPLICATION_FAMILIES: &[&str] = &[
    "com.apple.safari",
    "com.google.chrome",
    "org.chromium",
    "org.chromium.chromium",
    "com.brave.browser",
    "com.microsoft.edgemac",
    "company.thebrowser.browser",
    "company.thebrowser.dia",
    "com.vivaldi.vivaldi",
    "com.operasoftware.opera",
    "org.mozilla.firefox",
    "org.mozilla.nightly",
    "app.zen-browser.zen",
    "app.floorp.floorp",
    "ai.perplexity.comet",
    "com.openai.atlas",
    "net.imput.helium",
    "com.kagi.kagimacos",
    "org.torproject.torbrowser",
    "net.waterfox",
    "org.mozilla.librewolf",
    "io.gitlab.librewolf-community.librewolf",
    "net.librewolf.librewolf",
    "chrome.exe",
    "chromium.exe",
    "msedge.exe",
    "brave.exe",
    "firefox.exe",
    "vivaldi.exe",
    "opera.exe",
    "arc.exe",
    "zen.exe",
    "floorp.exe",
    "waterfox.exe",
    "librewolf.exe",
    "tor.exe",
    "comet.exe",
    "dia.exe",
];

/// Exact 9 case-insensitive multilingual private-window title substrings.
pub const PRIVATE_WINDOW_INDICATORS: &[&str] = &[
    "(incognito)",
    "(private)",
    "inprivate",
    "private browsing",
    "(privat)",
    "(privato)",
    "无痕",
    "隐私浏览",
    "私人浏览",
];

/// Normalize a Windows executable path or filename into a valid canonical applicationId.
///
/// Rules:
/// 1. Strip directory path (`\` or `/`).
/// 2. Lowercase.
/// 3. Strip ASCII whitespace (e.g. `"Proton Pass.exe"` -> `"protonpass.exe"`) BEFORE policy checks.
/// 4. Sanitize any remaining disallowed chars outside `[A-Za-z0-9._-]` to `-`.
/// 5. Trim leading non-ASCII-alphanumeric characters so output satisfies `is_valid_application_id`.
pub fn normalize_windows_exe_name(raw: &str) -> Option<String> {
    let base = raw.rsplit(['\\', '/']).next().unwrap_or(raw);
    let mut sanitized = String::with_capacity(base.len());
    for ch in base.chars() {
        if ch.is_ascii_whitespace() {
            continue;
        }
        let lower = ch.to_ascii_lowercase();
        if lower.is_ascii_alphanumeric() || matches!(lower, '.' | '_' | '-') {
            sanitized.push(lower);
        } else {
            sanitized.push('-');
        }
    }
    let trimmed = sanitized.trim_start_matches(|c: char| !c.is_ascii_alphanumeric());
    if trimmed.is_empty() || trimmed.len() > 256 || !is_valid_application_id(trimmed) {
        return None;
    }
    Some(trimmed.to_string())
}

/// Normalize an MSIX/UWP package family name (e.g. `Microsoft.WindowsTerminal_8wekyb3d8bbwe`)
/// by stripping the `_<publisherId>` suffix and normalizing to a valid lowercase applicationId.
pub fn normalize_package_family_name(family_name: &str) -> Option<String> {
    let pkg = family_name
        .rsplit_once('_')
        .map(|(prefix, _)| prefix)
        .unwrap_or(family_name);
    normalize_windows_exe_name(pkg)
}

fn query_process_image_path(pid: u32) -> Option<String> {
    if pid <= 1 {
        return None;
    }
    // SAFETY: Standard Win32 limited process query handle closed before returning.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = vec![0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
        .is_ok();
        let _ = CloseHandle(handle);
        if !ok || len == 0 {
            return None;
        }
        String::from_utf16(&buf[..len as usize]).ok()
    }
}

fn query_package_family_name_for_pid(pid: u32) -> Option<String> {
    if pid <= 1 {
        return None;
    }
    // SAFETY: GetPackageFamilyName takes a valid process handle and returns length in UTF-16 code units.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut len: u32 = 0;
        let first = GetPackageFamilyName(handle, &mut len, None);
        let result = if first == ERROR_INSUFFICIENT_BUFFER && len > 1 && len <= 512 {
            let mut buf = vec![0u16; len as usize];
            let second = GetPackageFamilyName(handle, &mut len, Some(PWSTR(buf.as_mut_ptr())));
            if second == ERROR_SUCCESS && len > 0 {
                let slice_len = buf
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or((len as usize).saturating_sub(1));
                String::from_utf16(&buf[..slice_len]).ok()
            } else {
                None
            }
        } else {
            None
        };
        let _ = CloseHandle(handle);
        result
    }
}

struct FrameHostChildSearch {
    host_pid: u32,
    core_window_pid: Option<u32>,
    fallback_pid: Option<u32>,
}

unsafe extern "system" fn enum_frame_host_children(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let state = &mut *(lparam.0 as *mut FrameHostChildSearch);
    let mut child_pid: u32 = 0;
    GetWindowThreadProcessId(hwnd, Some(&mut child_pid));
    if child_pid > 1 && child_pid != state.host_pid {
        let mut class_buf = [0u16; 128];
        let class_len = GetClassNameW(hwnd, &mut class_buf);
        if class_len > 0 {
            if let Ok(class_name) = String::from_utf16(&class_buf[..class_len as usize]) {
                if class_name == "Windows.UI.Core.CoreWindow" {
                    state.core_window_pid = Some(child_pid);
                    return BOOL(0);
                }
            }
        }
        if state.fallback_pid.is_none() && IsWindowVisible(hwnd).as_bool() {
            state.fallback_pid = Some(child_pid);
        }
    }
    BOOL(1)
}

/// Resolve the real UWP/MSIX inner `CoreWindow` PID when a window is hosted by `ApplicationFrameHost.exe`.
pub fn resolve_effective_pid(pid: u32, hwnd: Option<isize>) -> u32 {
    if pid <= 1 {
        return pid;
    }
    let Some(raw_hwnd) = hwnd else {
        return pid;
    };
    if raw_hwnd == 0 {
        return pid;
    }
    if let Some(path) = query_process_image_path(pid) {
        if normalize_windows_exe_name(&path).as_deref() == Some("applicationframehost.exe") {
            let mut search = FrameHostChildSearch {
                host_pid: pid,
                core_window_pid: None,
                fallback_pid: None,
            };
            // SAFETY: Valid HWND and pointer to stack-local search struct during synchronous EnumChildWindows.
            unsafe {
                let _ = EnumChildWindows(
                    Some(HWND(raw_hwnd as *mut core::ffi::c_void)),
                    Some(enum_frame_host_children),
                    LPARAM(&mut search as *mut FrameHostChildSearch as isize),
                );
            }
            if let Some(real_pid) = search.core_window_pid.or(search.fallback_pid) {
                return real_pid;
            }
        }
    }
    pid
}

/// Resolve canonical applicationId for a live Windows process (and optional top-level HWND).
///
/// 1. Unwraps `ApplicationFrameHost.exe` to its inner `CoreWindow` child PID when `hwnd` is provided.
/// 2. Queries `GetPackageFamilyName` and strips `_<publisherId>` for MSIX/UWP apps.
/// 3. Falls back to `QueryFullProcessImageNameW` + `normalize_windows_exe_name`.
pub fn resolve_application_id_for_pid(pid: u32, hwnd: Option<isize>) -> Option<String> {
    let target_pid = resolve_effective_pid(pid, hwnd);
    if target_pid <= 1 {
        return None;
    }
    if let Some(family_name) = query_package_family_name_for_pid(target_pid) {
        if let Some(pkg_id) = normalize_package_family_name(&family_name) {
            return Some(pkg_id);
        }
    }
    let image_path = query_process_image_path(target_pid)?;
    normalize_windows_exe_name(&image_path)
}

pub struct ApplicationPolicy;

impl ApplicationPolicy {
    pub fn matches_family(id: &str, family: &str) -> bool {
        let value = id.to_ascii_lowercase();
        let prefix = family.to_ascii_lowercase();
        value == prefix
            || (value.len() > prefix.len()
                && value.starts_with(&prefix)
                && value.as_bytes()[prefix.len()] == b'.')
    }

    pub fn is_mandatory_denied(id: &str) -> bool {
        MANDATORY_EXCLUDED_APPLICATION_IDS
            .iter()
            .any(|family| Self::matches_family(id, family))
    }

    pub fn is_system_ui(id: &str) -> bool {
        SYSTEM_UI_SKIP_APPLICATION_IDS
            .iter()
            .any(|family| Self::matches_family(id, family))
    }

    pub fn allows(id: &str, policy: &CapturePolicy) -> bool {
        if !policy.enabled
            || !is_valid_application_id(id)
            || Self::is_mandatory_denied(id)
            || Self::is_system_ui(id)
        {
            return false;
        }
        if let Some(ref excluded) = policy.excluded_application_ids {
            if excluded.iter().any(|family| Self::matches_family(id, family)) {
                return false;
            }
        }
        if policy.application_scope.as_deref() == Some("denylist") {
            return true;
        }
        if !matches!(policy.application_scope.as_deref(), None | Some("allowlist")) {
            return false;
        }
        let lower = id.to_ascii_lowercase();
        policy
            .allowed_application_ids
            .iter()
            .any(|allowed| allowed.to_ascii_lowercase() == lower)
    }
}

pub struct BrowserGate;

impl BrowserGate {
    pub fn is_known_browser(id: &str) -> bool {
        BROWSER_APPLICATION_FAMILIES
            .iter()
            .any(|family| ApplicationPolicy::matches_family(id, family))
    }

    pub fn allows(id: &str, policy: &CapturePolicy, is_browser_candidate: bool) -> bool {
        if !ApplicationPolicy::allows(id, policy) {
            return false;
        }
        let is_browser = is_browser_candidate || Self::is_known_browser(id);
        !is_browser
            || (policy.application_scope.as_deref() == Some("denylist")
                && policy.allow_browser_content == Some(true))
    }

    pub fn is_private_window_title(title: &str) -> bool {
        let lower = title.to_lowercase();
        PRIVATE_WINDOW_INDICATORS
            .iter()
            .any(|indicator| lower.contains(indicator))
    }

    pub fn should_block_private_windows(application_id: &str, block_private_windows: bool) -> bool {
        block_private_windows || Self::is_known_browser(application_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubroleRead {
    Value(String),
    AttributeUnsupported,
    NoValue,
    Failure,
    Malformed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedContentRead {
    Value(bool),
    AttributeUnsupported,
    NoValue,
    Failure,
    Malformed,
}

pub struct TextSecurityGate;

impl TextSecurityGate {
    pub fn is_sensitive_subrole(value: &str) -> bool {
        let lower = value.to_ascii_lowercase();
        lower.contains("secure") || lower.contains("password") || lower.contains("protected")
    }

    pub fn is_readable_text_role(role: Option<&str>) -> bool {
        matches!(role, Some("AXTextField" | "AXTextArea" | "AXStaticText"))
    }

    /// Authorizes traversal only, never reading a container's value.
    pub fn may_traverse(subrole: &SubroleRead, protected_content: ProtectedContentRead) -> bool {
        match subrole {
            SubroleRead::Failure | SubroleRead::Malformed => return false,
            SubroleRead::Value(v) if Self::is_sensitive_subrole(v) => return false,
            SubroleRead::Value(_) | SubroleRead::AttributeUnsupported | SubroleRead::NoValue => {}
        }
        matches!(
            protected_content,
            ProtectedContentRead::Value(false)
                | ProtectedContentRead::AttributeUnsupported
                | ProtectedContentRead::NoValue
        )
    }

    /// Classifies field security under `strict` vs `denylist` without ever turning API failures into absence.
    pub fn classify_metadata<F>(
        role: Option<&str>,
        subrole: &SubroleRead,
        protected_content: ProtectedContentRead,
        policy: &CapturePolicy,
        strict_fallback: Option<F>,
    ) -> SecureStatus
    where
        F: FnOnce() -> SecureStatus,
    {
        if role == Some("AXSecureTextField") {
            return SecureStatus::Sensitive;
        }
        if let SubroleRead::Value(ref value) = subrole {
            if Self::is_sensitive_subrole(value) {
                return SecureStatus::Sensitive;
            }
        }
        if protected_content == ProtectedContentRead::Value(true) {
            return SecureStatus::Sensitive;
        }
        if matches!(
            protected_content,
            ProtectedContentRead::Failure | ProtectedContentRead::Malformed
        ) || !Self::is_readable_text_role(role)
        {
            return SecureStatus::Unknown;
        }
        if matches!(subrole, SubroleRead::Failure | SubroleRead::Malformed) {
            return SecureStatus::Unknown;
        }
        let mode = policy.field_security_mode();
        if mode == "denylist" {
            return SecureStatus::NotDeclaredSensitive;
        }
        if mode != "strict" {
            return SecureStatus::Unknown;
        }
        if let Some(fallback) = strict_fallback {
            return fallback();
        }
        if let SubroleRead::Value(ref value) = subrole {
            return Self::classify(role, Some(value.as_str()), false, false, false, false, false);
        }
        SecureStatus::Unknown
    }

    pub fn classify_empty_subrole(
        role: Option<&str>,
        editable: Option<bool>,
        bounded_range_advertised: bool,
        character_count_known: bool,
    ) -> SecureStatus {
        if matches!(role, Some("AXTextField" | "AXTextArea"))
            && editable == Some(true)
            && bounded_range_advertised
            && character_count_known
        {
            SecureStatus::Safe
        } else {
            SecureStatus::Unknown
        }
    }

    /// Strict proof helper including Windows explicit `is_password == false` + TextPattern/char count.
    pub fn classify_windows_strict(
        role: Option<&str>,
        subrole: &SubroleRead,
        is_password: ProtectedContentRead,
        editable: bool,
        supports_text_pattern: bool,
        character_count_known: bool,
    ) -> SecureStatus {
        if role == Some("AXSecureTextField") || is_password == ProtectedContentRead::Value(true) {
            return SecureStatus::Sensitive;
        }
        if let SubroleRead::Value(ref s) = subrole {
            if Self::is_sensitive_subrole(s) {
                return SecureStatus::Sensitive;
            }
            if Self::is_readable_text_role(role)
                && matches!(
                    s.as_str(),
                    "AXStandardTextField" | "AXTextArea" | "AXStaticText" | "AXSearchField"
                )
            {
                return SecureStatus::Safe;
            }
        }
        if matches!(role, Some("AXTextField" | "AXTextArea"))
            && editable
            && supports_text_pattern
            && (character_count_known || is_password == ProtectedContentRead::Value(false))
        {
            return SecureStatus::Safe;
        }
        if role == Some("AXStaticText") && is_password == ProtectedContentRead::Value(false) {
            return SecureStatus::Safe;
        }
        SecureStatus::Unknown
    }

    pub fn classify(
        role: Option<&str>,
        subrole: Option<&str>,
        subrole_unsupported: bool,
        attribute_list_known: bool,
        subrole_advertised: bool,
        bounded_range_advertised: bool,
        character_count_known: bool,
    ) -> SecureStatus {
        if role == Some("AXSecureTextField") {
            return SecureStatus::Sensitive;
        }
        if let Some(sub) = subrole {
            if Self::is_sensitive_subrole(sub) {
                return SecureStatus::Sensitive;
            }
            if !Self::is_readable_text_role(role) {
                return SecureStatus::Unknown;
            }
            return if matches!(
                sub,
                "AXStandardTextField" | "AXTextArea" | "AXStaticText" | "AXSearchField"
            ) {
                SecureStatus::Safe
            } else {
                SecureStatus::Unknown
            };
        }
        if Self::is_readable_text_role(role)
            && subrole_unsupported
            && attribute_list_known
            && !subrole_advertised
            && bounded_range_advertised
            && character_count_known
        {
            SecureStatus::Safe
        } else {
            SecureStatus::Unknown
        }
    }
}

/// Unified budget metering UIA/AX queries, text code units, and monotonic deadlines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadBudget {
    pub deadline_ms: i64,
    pub final_validation_reserve_ms: i64,
    pub max_calls: usize,
    pub validation_reserve_calls: usize,
    pub max_text_units: usize,
    calls: usize,
    text_units: usize,
    text_violated: bool,
    is_final_validation: bool,
}

impl Default for ReadBudget {
    fn default() -> Self {
        Self::new(
            i64::MAX,
            Self::DEFAULT_FINAL_VALIDATION_RESERVE_MS,
            Self::DEFAULT_MAX_CALLS,
            Self::DEFAULT_FINAL_VALIDATION_RESERVE_CALLS,
            Self::MAX_TEXT_UNITS,
        )
    }
}

impl ReadBudget {
    pub const DEFAULT_MAX_CALLS: usize = 768;
    pub const MAX_CALLS_CAP: usize = 2048;
    pub const DEFAULT_FINAL_VALIDATION_RESERVE_CALLS: usize = 32;
    pub const DEFAULT_FINAL_VALIDATION_RESERVE_MS: i64 = 150;
    pub const MINIMUM_EXPLORATION_WINDOW_MS: i64 = 25;
    pub const MAX_TEXT_UNITS: usize = 8192;
    pub const FINAL_WINDOW_RECT_MIN_CALLS: usize = 8;

    pub fn new(
        deadline_ms: i64,
        final_validation_reserve_ms: i64,
        max_calls: usize,
        validation_reserve_calls: usize,
        max_text_units: usize,
    ) -> Self {
        let clamped_calls = max_calls.clamp(1, Self::MAX_CALLS_CAP);
        let clamped_reserve = validation_reserve_calls.min(clamped_calls);
        Self {
            deadline_ms,
            final_validation_reserve_ms: final_validation_reserve_ms.max(0),
            max_calls: clamped_calls,
            validation_reserve_calls: clamped_reserve,
            max_text_units: max_text_units.min(Self::MAX_TEXT_UNITS),
            calls: 0,
            text_units: 0,
            text_violated: false,
            is_final_validation: false,
        }
    }

    pub fn calls(&self) -> usize {
        self.calls
    }

    pub fn text_units(&self) -> usize {
        self.text_units
    }

    pub fn text_violated(&self) -> bool {
        self.text_violated
    }

    pub fn is_final_validation(&self) -> bool {
        self.is_final_validation
    }

    pub fn exploration_deadline_ms(&self) -> i64 {
        if self.deadline_ms == i64::MAX {
            i64::MAX
        } else {
            self.deadline_ms.saturating_sub(self.final_validation_reserve_ms)
        }
    }

    pub fn active_deadline_ms(&self) -> i64 {
        if self.is_final_validation {
            self.deadline_ms
        } else {
            self.exploration_deadline_ms()
        }
    }

    pub fn active_call_limit(&self) -> usize {
        if self.is_final_validation {
            self.max_calls
        } else {
            self.max_calls.saturating_sub(self.validation_reserve_calls)
        }
    }

    pub fn remaining_calls(&self) -> usize {
        self.active_call_limit().saturating_sub(self.calls)
    }

    pub fn remaining_text_units(&self) -> usize {
        if self.text_violated {
            0
        } else {
            self.max_text_units.saturating_sub(self.text_units)
        }
    }

    pub fn has_exploration_headroom(&self, now_ms: i64) -> bool {
        if self.text_violated || self.remaining_calls() == 0 || now_ms < 0 {
            return false;
        }
        let exp = self.exploration_deadline_ms();
        if exp == i64::MAX {
            return true;
        }
        let minimum = if self.final_validation_reserve_ms > 0 {
            Self::MINIMUM_EXPLORATION_WINDOW_MS
        } else {
            1
        };
        exp.saturating_sub(now_ms) >= minimum
    }

    pub fn can_recheck_window_rect(&self) -> bool {
        !self.text_violated && self.remaining_calls() >= Self::FINAL_WINDOW_RECT_MIN_CALLS
    }

    pub fn consume_calls(&mut self, count: usize, now_ms: i64) -> bool {
        if count == 0
            || self.text_violated
            || now_ms >= self.active_deadline_ms()
            || self.calls > self.active_call_limit().saturating_sub(count)
        {
            return false;
        }
        self.calls += count;
        true
    }

    pub fn consume_text(&mut self, units: usize, requested: Option<usize>) -> bool {
        if self.text_violated {
            return false;
        }
        if let Some(req) = requested {
            if units > req {
                self.text_violated = true;
                self.text_units = self.max_text_units + 1;
                return false;
            }
        }
        if units > self.max_text_units.saturating_sub(self.text_units) {
            self.text_violated = true;
            self.text_units = self.max_text_units + 1;
            return false;
        }
        self.text_units += units;
        true
    }

    pub fn begin_final_validation(&mut self) {
        self.is_final_validation = true;
    }
}

/// Pure monotonic phase-budget scheduling for best-effort UIA/AX channels.
pub struct PhaseBudget;

impl PhaseBudget {
    pub const FINAL_VALIDATION_RESERVE_MS: i64 = 350;
    pub const MINIMUM_OPTIONAL_MS: i64 = 200;
    pub const SURFACE_VALIDATION_RESERVE_MS: i64 = 150;
    pub const SURFACE_MINIMUM_EXPLORATION_MS: i64 = 25;

    pub fn optional_deadline(now_ms: i64, hard_deadline_ms: i64) -> Option<i64> {
        if now_ms < 0 || hard_deadline_ms <= now_ms {
            return None;
        }
        let remaining = hard_deadline_ms - now_ms;
        let reserve = Self::FINAL_VALIDATION_RESERVE_MS.min(remaining / 2);
        if remaining - reserve < Self::MINIMUM_OPTIONAL_MS {
            return None;
        }
        Some(hard_deadline_ms - reserve)
    }

    pub fn surface_exploration_deadline(now_ms: i64, optional_deadline_ms: i64) -> Option<i64> {
        if now_ms < 0 || optional_deadline_ms <= now_ms {
            return None;
        }
        let remaining = optional_deadline_ms - now_ms;
        if remaining - Self::SURFACE_VALIDATION_RESERVE_MS < Self::SURFACE_MINIMUM_EXPLORATION_MS {
            return None;
        }
        Some(optional_deadline_ms - Self::SURFACE_VALIDATION_RESERVE_MS)
    }

    pub fn read_optional_geometry<T, Now, Verify, Read>(
        now_ms: Now,
        phase_deadline_ms: i64,
        verify_boundary: Verify,
        read: Read,
    ) -> Option<T>
    where
        Now: Fn() -> i64,
        Verify: FnOnce() -> bool,
        Read: FnOnce(i64) -> Option<T>,
    {
        let geometry_deadline = || -> Option<i64> {
            let now = now_ms();
            if now < 0 || phase_deadline_ms <= now || phase_deadline_ms - now <= 50 {
                return None;
            }
            Some((phase_deadline_ms - 50).min(now + 20))
        };
        geometry_deadline()?;
        if !verify_boundary() {
            return None;
        }
        let deadline = geometry_deadline()?;
        read(deadline)
    }

    pub fn observer_deadline(
        now_ms: i64,
        hard_deadline_ms: i64,
        phase_deadline_ms: i64,
    ) -> Option<i64> {
        let optional = Self::optional_deadline(now_ms, hard_deadline_ms)?;
        if phase_deadline_ms <= now_ms {
            return None;
        }
        let cap = now_ms + (hard_deadline_ms - now_ms).min(100);
        Some(optional.min(phase_deadline_ms).min(cap))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaticTextProbeFailure {
    Interrupted,
    OversizedResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticTextProbeResult {
    pub text: Option<String>,
    pub consumed_units: usize,
    pub attempts: usize,
    pub failure: Option<StaticTextProbeFailure>,
}

pub struct StaticTextRangeProbe;

impl StaticTextRangeProbe {
    pub const MAXIMUM_ATTEMPTS: usize = 9;
    pub const MAXIMUM_PREFIX_UNITS: usize = 256;
    pub const DEFAULT_INITIAL_PREFIX_UNITS: usize = 2;

    pub fn read<Cont, CanStart, ReadRange>(
        budget: usize,
        max_attempts: usize,
        initial_prefix_units: usize,
        stop_after_nonempty: bool,
        mut should_continue: Cont,
        mut can_start_attempt: CanStart,
        mut read_range: ReadRange,
    ) -> StaticTextProbeResult
    where
        Cont: FnMut() -> bool,
        CanStart: FnMut() -> bool,
        ReadRange: FnMut(usize, usize) -> Option<String>,
    {
        let attempt_limit = max_attempts.min(Self::MAXIMUM_ATTEMPTS);
        if budget == 0 || attempt_limit == 0 {
            return StaticTextProbeResult {
                text: None,
                consumed_units: 0,
                attempts: 0,
                failure: None,
            };
        }
        let mut consumed: usize = 0;
        let mut attempts: usize = 0;
        let mut best: Option<String> = None;
        let mut best_units: isize = -1;
        let max_target = budget.min(Self::MAXIMUM_PREFIX_UNITS);
        let mut requested = initial_prefix_units
            .clamp(1, Self::MAXIMUM_PREFIX_UNITS)
            .min(budget);
        let mut successful_request: usize = 0;
        let mut failed_request: Option<usize> = None;

        while attempts < attempt_limit {
            if !should_continue() {
                return StaticTextProbeResult {
                    text: None,
                    consumed_units: consumed,
                    attempts,
                    failure: Some(StaticTextProbeFailure::Interrupted),
                };
            }
            if !can_start_attempt() {
                break;
            }
            let remaining = budget.saturating_sub(consumed);
            if requested == 0 || requested > remaining || requested > Self::MAXIMUM_PREFIX_UNITS {
                break;
            }
            attempts += 1;
            let response = read_range(0, requested);
            let units = response.as_deref().map(utf16_len).unwrap_or(0);
            let (sum, overflow) = consumed.overflowing_add(units);
            consumed = if overflow { usize::MAX } else { sum };
            let may_continue = should_continue();
            if overflow || units > requested || units > remaining {
                return StaticTextProbeResult {
                    text: None,
                    consumed_units: consumed,
                    attempts,
                    failure: Some(StaticTextProbeFailure::OversizedResponse),
                };
            }
            if !may_continue {
                return StaticTextProbeResult {
                    text: None,
                    consumed_units: consumed,
                    attempts,
                    failure: Some(StaticTextProbeFailure::Interrupted),
                };
            }

            if let Some(resp) = response {
                if resp.is_empty() {
                    failed_request = Some(requested);
                } else {
                    successful_request = requested;
                }
                let uncertain_end = resp.ends_with('\u{FFFD}');
                if !uncertain_end && (units as isize) > best_units {
                    best = Some(resp.clone());
                    best_units = units as isize;
                }
                if stop_after_nonempty && !resp.is_empty() && !uncertain_end {
                    break;
                }
                if requested >= max_target && !resp.is_empty() && !uncertain_end {
                    break;
                }
            } else {
                failed_request = Some(requested);
            }

            let available = budget.saturating_sub(consumed);
            let next = if let Some(failed) = failed_request {
                let upper = failed.saturating_sub(1).min(available);
                if upper <= successful_request {
                    break;
                }
                successful_request + (upper - successful_request).div_ceil(2)
            } else {
                let doubled = requested
                    .saturating_mul(2)
                    .min(Self::MAXIMUM_PREFIX_UNITS)
                    .min(available);
                if doubled <= requested {
                    break;
                }
                doubled
            };
            requested = next;
        }

        StaticTextProbeResult {
            text: best,
            consumed_units: consumed,
            attempts,
            failure: None,
        }
    }
}

/// Returns `true` iff `text` contains at least one non-whitespace Unicode scalar and ALL
/// non-whitespace scalars fall in Unicode Private Use Areas (`E000..=F8FF`, `F0000..=FFFFD`, `100000..=10FFFD`).
pub fn is_private_use_only_text(text: &str) -> bool {
    let mut saw_non_whitespace = false;
    for ch in text.chars() {
        if ch.is_whitespace() {
            continue;
        }
        saw_non_whitespace = true;
        let cp = ch as u32;
        let in_pua = (0xE000..=0xF8FF).contains(&cp)
            || (0xF0000..=0xFFFFD).contains(&cp)
            || (0x100000..=0x10FFFD).contains(&cp);
        if !in_pua {
            return false;
        }
    }
    saw_non_whitespace
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappedRole {
    pub ax_role: Option<&'static str>,
    pub subrole: Option<&'static str>,
    pub category: &'static str,
}

/// Canonical `UIA ControlType -> AX*` role mapping table matching #52 Section 3.F.6.
///
/// Pre-rule (highest priority): `is_password == true` ALWAYS maps to `AXSecureTextField` (blocked).
#[allow(clippy::too_many_arguments)]
pub fn map_uia_control_type_to_ax(
    control_type: i32,
    is_password: bool,
    is_multiline_or_text_pattern: bool,
    is_read_only: bool,
    has_children: bool,
    is_web_surface: bool,
    is_heading: bool,
    supports_scroll: bool,
    is_terminal_app: bool,
) -> MappedRole {
    if is_password {
        return MappedRole {
            ax_role: Some("AXSecureTextField"),
            subrole: None,
            category: "other",
        };
    }

    match control_type {
        // UIA_ButtonControlTypeId
        50000 => MappedRole {
            ax_role: Some("AXButton"),
            subrole: None,
            category: "container",
        },
        // UIA_CheckBoxControlTypeId
        50002 => MappedRole {
            ax_role: Some("AXCheckBox"),
            subrole: None,
            category: "container",
        },
        // UIA_ComboBoxControlTypeId
        50003 => MappedRole {
            ax_role: Some("AXComboBox"),
            subrole: None,
            category: "container",
        },
        // UIA_EditControlTypeId
        50004 => MappedRole {
            ax_role: Some(if is_multiline_or_text_pattern {
                "AXTextArea"
            } else {
                "AXTextField"
            }),
            subrole: None,
            category: "editable",
        },
        // UIA_HyperlinkControlTypeId
        50005 => MappedRole {
            ax_role: Some("AXLink"),
            subrole: None,
            category: "container",
        },
        // UIA_ImageControlTypeId (pruned)
        50006 => MappedRole {
            ax_role: Some("AXImage"),
            subrole: None,
            category: "other",
        },
        // UIA_ListItemControlTypeId
        50007 => MappedRole {
            ax_role: Some("AXRow"),
            subrole: None,
            category: "container",
        },
        // UIA_ListControlTypeId
        50008 => MappedRole {
            ax_role: Some("AXList"),
            subrole: None,
            category: "container",
        },
        // UIA_MenuControlTypeId
        50009 => MappedRole {
            ax_role: Some("AXMenu"),
            subrole: None,
            category: "container",
        },
        // UIA_MenuBarControlTypeId
        50010 => MappedRole {
            ax_role: Some("AXMenuBar"),
            subrole: None,
            category: "container",
        },
        // UIA_MenuItemControlTypeId
        50011 => MappedRole {
            ax_role: Some("AXMenuItem"),
            subrole: None,
            category: "container",
        },
        // UIA_RadioButtonControlTypeId
        50013 => MappedRole {
            ax_role: Some("AXRadioButton"),
            subrole: None,
            category: "container",
        },
        // UIA_ScrollBarControlTypeId (ignored by adapters)
        50014 => MappedRole {
            ax_role: Some("AXScrollBar"),
            subrole: None,
            category: "other",
        },
        // UIA_StatusBarControlTypeId -> synthetic subrole enables VSCode status bar pruning
        50017 => MappedRole {
            ax_role: Some("AXGroup"),
            subrole: Some("AXApplicationStatus"),
            category: "container",
        },
        // UIA_TabControlTypeId
        50018 => MappedRole {
            ax_role: Some("AXTabGroup"),
            subrole: None,
            category: "container",
        },
        // UIA_TabItemControlTypeId
        50019 => MappedRole {
            ax_role: Some("AXTabButton"),
            subrole: None,
            category: "container",
        },
        // UIA_TextControlTypeId
        50020 => MappedRole {
            ax_role: Some(if is_heading {
                "AXHeading"
            } else {
                "AXStaticText"
            }),
            subrole: None,
            category: "text",
        },
        // UIA_ToolBarControlTypeId
        50021 => MappedRole {
            ax_role: Some("AXToolbar"),
            subrole: None,
            category: "container",
        },
        // UIA_TreeControlTypeId
        50023 => MappedRole {
            ax_role: Some("AXOutline"),
            subrole: None,
            category: "container",
        },
        // UIA_TreeItemControlTypeId
        50024 => MappedRole {
            ax_role: Some("AXRow"),
            subrole: None,
            category: "container",
        },
        // UIA_CustomControlTypeId | UIA_GroupControlTypeId | UIA_HeaderControlTypeId | UIA_TitleBarControlTypeId
        50025 | 50026 | 50034 | 50037 => MappedRole {
            ax_role: Some("AXGroup"),
            subrole: None,
            category: "container",
        },
        // UIA_DataGridControlTypeId | UIA_TableControlTypeId
        50028 | 50036 => MappedRole {
            ax_role: Some("AXTable"),
            subrole: None,
            category: "container",
        },
        // UIA_DataItemControlTypeId
        50029 => MappedRole {
            ax_role: Some("AXRow"),
            subrole: None,
            category: "container",
        },
        // UIA_DocumentControlTypeId
        50030 => {
            if is_web_surface || has_children {
                MappedRole {
                    ax_role: Some("AXWebArea"),
                    subrole: None,
                    category: "container",
                }
            } else if is_multiline_or_text_pattern && !is_read_only {
                MappedRole {
                    ax_role: Some("AXTextArea"),
                    subrole: None,
                    category: if is_terminal_app {
                        "terminal"
                    } else {
                        "editable"
                    },
                }
            } else {
                MappedRole {
                    ax_role: Some("AXDocument"),
                    subrole: None,
                    category: "container",
                }
            }
        }
        // UIA_SplitButtonControlTypeId
        50031 => MappedRole {
            ax_role: Some("AXPopUpButton"),
            subrole: None,
            category: "container",
        },
        // UIA_WindowControlTypeId
        50032 => MappedRole {
            ax_role: Some("AXWindow"),
            subrole: None,
            category: "container",
        },
        // UIA_PaneControlTypeId
        50033 => MappedRole {
            ax_role: Some(if supports_scroll {
                "AXScrollArea"
            } else {
                "AXGroup"
            }),
            subrole: None,
            category: "container",
        },
        // UIA_HeaderItemControlTypeId
        50035 => MappedRole {
            ax_role: Some("AXColumn"),
            subrole: None,
            category: "container",
        },
        // Unmapped controls (Calendar 50001, ProgressBar 50012, Slider 50015, Spinner 50016,
        // ToolTip 50022, Thumb 50027, Separator 50038, SemanticZoom 50039, AppBar 50040, unknown)
        _ => MappedRole {
            ax_role: None,
            subrole: None,
            category: "other",
        },
    }
}

/// Normalize any role to the closed 11-value `GapDiagnostic.role` enum in `wire.schema.json`.
pub fn normalize_gap_role(role: Option<&str>) -> &'static str {
    match role {
        None => "unavailable",
        Some("AXTextField") => "AXTextField",
        Some("AXTextArea") => "AXTextArea",
        Some("AXStaticText") => "AXStaticText",
        Some("AXSecureTextField") => "AXSecureTextField",
        Some("AXMenuItem") => "AXMenuItem",
        Some("AXMenu") => "AXMenu",
        Some("AXWebArea") => "AXWebArea",
        Some("AXGroup") => "AXGroup",
        Some("AXButton") => "AXButton",
        Some("unavailable") => "unavailable",
        Some(_) => "other",
    }
}
