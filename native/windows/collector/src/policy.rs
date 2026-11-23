use access_contract::{is_valid_application_id, utf16_len};
use windows::core::{BOOL, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, HANDLE, HWND, LPARAM,
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

/// Case-insensitive multilingual private-window title substrings.
pub const PRIVATE_WINDOW_INDICATORS: &[&str] = &[
    "(incognito)",
    "new incognito tab",
    "(private)",
    "inprivate",
    "private browsing",
    "(privat)",
    "(privato)",
    "无痕",
    "隐私浏览",
    "私人浏览",
    "無痕",
    "私密瀏覽",
    "隱私瀏覽",
    "シークレット",
    "プライベート",
    "시크릿",
    "프라이빗",
    "사생활 보호",
    "incógnito",
    "navigation privée",
    "privater modus",
    "navegación privada",
    "navegação privativa",
    "navegação anônima",
    "navigazione anonima",
    "приватный просмотр",
    "инкогнито",
    "inkognito",
];

/// Case-insensitive unambiguous multilingual private/incognito indicator phrases matched strictly
/// against native browser frame toolbar/chrome controls (NEVER web `Document` content).
pub const PRIVATE_CHROME_INDICATORS: &[&str] = &[
    "incognito",
    "inprivate",
    "private browsing",
    "private window",
    "private mode",
    "シークレット",
    "プライベート ブラウジング",
    "プライベートブラウジング",
    "プライベートウィンドウ",
    "无痕",
    "無痕",
    "隐私浏览",
    "私人浏览",
    "私密瀏覽",
    "隱私瀏覽",
    "시크릿",
    "프라이빗",
    "사생활 보호",
    "incógnito",
    "navigation privée",
    "privater modus",
    "navegación privada",
    "navegação privativa",
    "navegação anônima",
    "navigazione in incognito",
    "navigazione anonima",
    "приватный просмотр",
    "инкогнито",
    "inkognito",
];

/// Exact (trimmed, case-insensitive) toolbar badge labels that unambiguously indicate a private
/// browser window only when they constitute the entire badge label (or `<label> (...)` window count),
/// avoiding false positives on normal buttons such as `"Privacy settings"` or `"My Private Bookmarks"`.
pub const PRIVATE_CHROME_EXACT_LABELS: &[&str] = &[
    "private",
    "privé",
    "privat",
    "privato",
    "プライベート",
    "私密",
];

/// Returns `true` when a native browser toolbar/chrome control label indicates a private/incognito
/// browser window, without matching broad ambiguous substrings like `"Privacy settings"` or
/// `"My Private Bookmarks"`.
pub fn is_private_chrome_label(label: &str) -> bool {
    let trimmed = label.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_lowercase();
    if PRIVATE_CHROME_INDICATORS
        .iter()
        .any(|indicator| lower.contains(indicator))
    {
        return true;
    }
    PRIVATE_CHROME_EXACT_LABELS.iter().any(|exact| {
        lower == *exact
            || lower
                .strip_prefix(exact)
                .is_some_and(|rest| rest.trim_start().starts_with('('))
    })
}

fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn is_application_frame_host_exe(exe_name: Option<&str>) -> bool {
    exe_name.is_some_and(|name| name.eq_ignore_ascii_case("applicationframehost.exe"))
}

/// Normalize a Windows executable path or filename into a valid canonical applicationId.
///
/// Rules:
/// 1. Strip directory path (`\` or `/`).
/// 2. Lowercase.
/// 3. For pure non-ASCII stems (e.g. `"微信.exe"`, `"メモ帳.exe"`), emit a deterministic
///    collision-resistant ASCII hash stem (`app-<16hex>.exe`) instead of collapsing to `"exe"`.
/// 4. Strip ASCII whitespace (e.g. `"Proton Pass.exe"` -> `"protonpass.exe"`) BEFORE policy checks.
/// 5. Sanitize any remaining disallowed chars outside `[A-Za-z0-9._-]` to `-`.
/// 6. Trim leading non-ASCII-alphanumeric characters so output satisfies `is_valid_application_id`.
pub fn normalize_windows_exe_name(raw: &str) -> Option<String> {
    let base = raw.rsplit(['\\', '/']).next().unwrap_or(raw).trim();
    if base.is_empty() {
        return None;
    }
    let has_exe_ext = base.len() >= 4
        && base.as_bytes()[base.len() - 4..].eq_ignore_ascii_case(b".exe");
    let raw_stem = if has_exe_ext {
        &base[..base.len() - 4]
    } else {
        base
    };
    if !raw_stem.chars().any(|c| c.is_ascii_alphanumeric()) {
        let non_ws_stem: String = raw_stem.chars().filter(|c| !c.is_whitespace()).collect();
        if !non_ws_stem.is_ascii() {
            let canonical_stem = non_ws_stem.to_lowercase();
            let hash = fnv1a_64(canonical_stem.as_bytes());
            let hashed = if has_exe_ext {
                format!("app-{hash:016x}.exe")
            } else {
                format!("app-{hash:016x}")
            };
            return is_valid_application_id(&hashed).then_some(hashed);
        }
        return None;
    }

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

/// Dual-ID Windows process identity ensuring MSIX/AppX package names never shadow `.exe`
/// basenames across mandatory-exclusion, System UI, browser, policy, and adapter checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAppIdentity {
    /// Primary wire applicationId: MSIX/AppX package name if packaged, else normalized `.exe` basename.
    pub application_id: String,
    /// Normalized `.exe` basename from `QueryFullProcessImageNameW`, if resolvable.
    pub exe_name: Option<String>,
    /// Normalized MSIX/AppX package name from `GetPackageFamilyName`, if packaged.
    pub package_name: Option<String>,
}

impl ResolvedAppIdentity {
    pub fn from_parts(package_name: Option<String>, exe_name: Option<String>) -> Option<Self> {
        let package_name = package_name
            .filter(|id| !id.is_empty() && id.len() <= 256 && is_valid_application_id(id));
        let exe_name =
            exe_name.filter(|id| !id.is_empty() && id.len() <= 256 && is_valid_application_id(id));
        if is_application_frame_host_exe(exe_name.as_deref())
            || is_application_frame_host_exe(package_name.as_deref())
        {
            return None;
        }
        let application_id = package_name.clone().or_else(|| exe_name.clone())?;
        if !is_valid_application_id(&application_id) {
            return None;
        }
        Some(Self {
            application_id,
            exe_name,
            package_name,
        })
    }

    pub fn from_single(application_id: String) -> Option<Self> {
        if application_id.is_empty()
            || application_id.len() > 256
            || !is_valid_application_id(&application_id)
            || is_application_frame_host_exe(Some(application_id.as_str()))
        {
            return None;
        }
        let is_exe = application_id.to_ascii_lowercase().ends_with(".exe");
        Some(Self {
            exe_name: is_exe.then(|| application_id.clone()),
            package_name: (!is_exe).then(|| application_id.clone()),
            application_id,
        })
    }

    pub fn candidate_ids(&self) -> Vec<&str> {
        let mut out = Vec::with_capacity(3);
        if !self.application_id.is_empty() {
            out.push(self.application_id.as_str());
        }
        if let Some(ref exe) = self.exe_name {
            if !exe.is_empty()
                && !out
                    .iter()
                    .any(|existing| existing.eq_ignore_ascii_case(exe))
            {
                out.push(exe.as_str());
            }
        }
        if let Some(ref pkg) = self.package_name {
            if !pkg.is_empty()
                && !out
                    .iter()
                    .any(|existing| existing.eq_ignore_ascii_case(pkg))
            {
                out.push(pkg.as_str());
            }
        }
        out
    }

    pub fn matches_id(&self, id: &str) -> bool {
        !id.is_empty()
            && self
                .candidate_ids()
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(id))
    }
}

fn query_process_image_path_from_handle(handle: HANDLE) -> Option<String> {
    // SAFETY: Caller passes a valid process handle with PROCESS_QUERY_LIMITED_INFORMATION.
    unsafe {
        for cap in [1024usize, 4096usize] {
            let mut buf = vec![0u16; cap];
            let mut len = buf.len() as u32;
            match QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_WIN32,
                PWSTR(buf.as_mut_ptr()),
                &mut len,
            ) {
                Ok(()) if len > 0 => {
                    return String::from_utf16(&buf[..len as usize]).ok();
                }
                Err(err) if err.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult() => continue,
                _ => return None,
            }
        }
        None
    }
}

fn query_process_image_path(pid: u32) -> Option<String> {
    if pid <= 1 {
        return None;
    }
    // SAFETY: Standard Win32 limited process query handle closed before returning.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let result = query_process_image_path_from_handle(handle);
        let _ = CloseHandle(handle);
        result
    }
}

fn query_package_family_name_from_handle(handle: HANDLE) -> Option<String> {
    // SAFETY: Caller passes a valid process handle with PROCESS_QUERY_LIMITED_INFORMATION.
    unsafe {
        let mut len: u32 = 0;
        let first = GetPackageFamilyName(handle, &mut len, None);
        if first == ERROR_INSUFFICIENT_BUFFER && len > 1 && len <= 512 {
            let mut buf = vec![0u16; len as usize];
            let second = GetPackageFamilyName(handle, &mut len, Some(PWSTR(buf.as_mut_ptr())));
            if second == ERROR_SUCCESS && len > 0 {
                let slice_len = buf
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or((len as usize).saturating_sub(1));
                return String::from_utf16(&buf[..slice_len]).ok();
            }
        }
        None
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
///
/// Fails closed (`None`) whenever `pid <= 1`, when `ApplicationFrameHost.exe` has no valid `hwnd`,
/// when `EnumChildWindows` finds no distinct inner UWP PID, or when the child PID itself resolves to
/// `ApplicationFrameHost.exe`.
pub fn resolve_effective_pid_checked(pid: u32, hwnd: Option<isize>) -> Option<u32> {
    if pid <= 1 {
        return None;
    }
    let host_exe = query_process_image_path(pid)
        .as_deref()
        .and_then(normalize_windows_exe_name);
    if is_application_frame_host_exe(host_exe.as_deref()) {
        let raw_hwnd = hwnd.filter(|&h| h != 0)?;
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
        let real_pid = search.core_window_pid.or(search.fallback_pid)?;
        if real_pid <= 1 || real_pid == pid {
            return None;
        }
        let inner_exe = query_process_image_path(real_pid)
            .as_deref()
            .and_then(normalize_windows_exe_name)?;
        if is_application_frame_host_exe(Some(inner_exe.as_str())) {
            return None;
        }
        return Some(real_pid);
    }
    Some(pid)
}

/// Backward-compatible wrapper around `resolve_effective_pid_checked`, returning `0` (invalid PID)
/// when resolution fails closed.
pub fn resolve_effective_pid(pid: u32, hwnd: Option<isize>) -> u32 {
    resolve_effective_pid_checked(pid, hwnd).unwrap_or(0)
}

/// Resolve dual-ID (`package_name` + `exe_name`) identity for a live Windows process (and optional
/// top-level HWND) without allowing MSIX/AppX package names to shadow the executable basename.
///
/// 1. Unwraps `ApplicationFrameHost.exe` fail-closed via `resolve_effective_pid_checked`.
/// 2. Opens the effective PID once and queries BOTH `GetPackageFamilyName` and
///    `QueryFullProcessImageNameW` from the same kernel process handle.
/// 3. Fails closed (`None`) if the `.exe` basename cannot be resolved or equals
///    `ApplicationFrameHost.exe`.
pub fn resolve_app_identity_for_pid(
    pid: u32,
    hwnd: Option<isize>,
) -> Option<ResolvedAppIdentity> {
    let target_pid = resolve_effective_pid_checked(pid, hwnd)?;
    // SAFETY: Single OpenProcess handle closed before returning; both package name and image path
    // are read from the exact same process object.
    let (raw_family, raw_image) = unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, target_pid).ok()?;
        let family = query_package_family_name_from_handle(handle);
        let image = query_process_image_path_from_handle(handle);
        let _ = CloseHandle(handle);
        (family, image)
    };
    let exe_id = raw_image.as_deref().and_then(normalize_windows_exe_name)?;
    if is_application_frame_host_exe(Some(exe_id.as_str())) {
        return None;
    }
    let pkg_id = raw_family
        .as_deref()
        .and_then(normalize_package_family_name);
    ResolvedAppIdentity::from_parts(pkg_id, Some(exe_id))
}

/// Resolve canonical primary wire applicationId for a live Windows process (and optional top-level HWND).
pub fn resolve_application_id_for_pid(pid: u32, hwnd: Option<isize>) -> Option<String> {
    resolve_app_identity_for_pid(pid, hwnd).map(|id| id.application_id)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityPolicyOutcome {
    Allowed,
    MandatoryDenied,
    SystemUi,
    ExcludedByPolicy,
    NotInAllowlist,
    BrowserExcluded,
    PolicyDisabledOrInvalid,
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

    pub fn is_mandatory_denied_identity(id: &ResolvedAppIdentity) -> bool {
        id.candidate_ids()
            .iter()
            .any(|candidate| Self::is_mandatory_denied(candidate))
    }

    pub fn is_system_ui_identity(id: &ResolvedAppIdentity) -> bool {
        id.candidate_ids()
            .iter()
            .any(|candidate| Self::is_system_ui(candidate))
    }

    pub fn is_browser_identity(id: &ResolvedAppIdentity) -> bool {
        id.candidate_ids()
            .iter()
            .any(|candidate| BrowserGate::is_known_browser(candidate))
    }

    pub fn evaluate_identity(
        policy: &CapturePolicy,
        id: &ResolvedAppIdentity,
    ) -> IdentityPolicyOutcome {
        let candidates = id.candidate_ids();
        if !policy.enabled
            || !is_valid_application_id(&id.application_id)
            || candidates.is_empty()
            || candidates
                .iter()
                .any(|c| is_application_frame_host_exe(Some(c)))
        {
            return IdentityPolicyOutcome::PolicyDisabledOrInvalid;
        }
        if Self::is_mandatory_denied_identity(id) {
            return IdentityPolicyOutcome::MandatoryDenied;
        }
        if Self::is_system_ui_identity(id) {
            return IdentityPolicyOutcome::SystemUi;
        }
        if let Some(ref excluded) = policy.excluded_application_ids {
            if candidates
                .iter()
                .any(|c| excluded.iter().any(|family| Self::matches_family(c, family)))
            {
                return IdentityPolicyOutcome::ExcludedByPolicy;
            }
        }
        if policy.application_scope.as_deref() == Some("denylist") {
            if Self::is_browser_identity(id) && policy.allow_browser_content != Some(true) {
                return IdentityPolicyOutcome::BrowserExcluded;
            }
            return IdentityPolicyOutcome::Allowed;
        }
        if !matches!(policy.application_scope.as_deref(), None | Some("allowlist")) {
            return IdentityPolicyOutcome::PolicyDisabledOrInvalid;
        }
        let in_allowlist = candidates.iter().any(|c| {
            policy
                .allowed_application_ids
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(c))
        });
        if !in_allowlist {
            return IdentityPolicyOutcome::NotInAllowlist;
        }
        if Self::is_browser_identity(id) {
            return IdentityPolicyOutcome::BrowserExcluded;
        }
        IdentityPolicyOutcome::Allowed
    }

    pub fn allows_identity(policy: &CapturePolicy, id: &ResolvedAppIdentity) -> bool {
        Self::evaluate_identity(policy, id) == IdentityPolicyOutcome::Allowed
    }

    pub fn allows(id: &str, policy: &CapturePolicy) -> bool {
        if !policy.enabled
            || !is_valid_application_id(id)
            || is_application_frame_host_exe(Some(id))
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

    pub fn is_known_browser_identity(id: &ResolvedAppIdentity) -> bool {
        ApplicationPolicy::is_browser_identity(id)
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

    pub fn allows_identity(
        id: &ResolvedAppIdentity,
        policy: &CapturePolicy,
        is_browser_candidate: bool,
    ) -> bool {
        if !ApplicationPolicy::allows_identity(policy, id) {
            return false;
        }
        let is_browser = is_browser_candidate || Self::is_known_browser_identity(id);
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

    /// Match native browser chrome toolbar/indicator controls (e.g. Chrome `AvatarToolbarButton`,
    /// Edge `InPrivate`, Firefox Private Browsing) while excluding user bookmark/extension buttons.
    ///
    /// INVARIANT: Callers MUST NEVER invoke this on web `Document (50030)` descendants.
    pub fn is_private_chrome_indicator(class_name: Option<&str>, name: &str) -> bool {
        if name.trim().is_empty() {
            return false;
        }
        if let Some(cls) = class_name {
            if cls.eq_ignore_ascii_case("BookmarkButton")
                || cls.eq_ignore_ascii_case("ToolbarActionView")
                || cls.eq_ignore_ascii_case("Tab")
            {
                return false;
            }
        }
        is_private_chrome_label(name)
    }

    pub fn should_block_private_windows(application_id: &str, block_private_windows: bool) -> bool {
        block_private_windows || Self::is_known_browser(application_id)
    }

    pub fn should_block_private_windows_identity(
        id: &ResolvedAppIdentity,
        block_private_windows: bool,
    ) -> bool {
        block_private_windows || Self::is_known_browser_identity(id)
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
        }
        if matches!(
            is_password,
            ProtectedContentRead::Failure | ProtectedContentRead::Malformed
        ) || matches!(subrole, SubroleRead::Failure | SubroleRead::Malformed)
        {
            return SecureStatus::Unknown;
        }
        if let SubroleRead::Value(ref s) = subrole {
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

/// Returns `true` when `class_name` identifies a native Win32/WinUI RichEdit control whose
/// `ControlType::Document (50030)` is a genuine leaf text editor (such as Windows 11 Notepad
/// `RichEditD2DPT`) rather than an Electron/Chromium web DOM container.
pub fn is_native_richedit_class(class_name: Option<&str>) -> bool {
    class_name.is_some_and(|c| {
        c.eq_ignore_ascii_case("RichEditD2DPT")
            || c.eq_ignore_ascii_case("RICHEDIT50W")
            || c.eq_ignore_ascii_case("RichEdit20W")
            || c.eq_ignore_ascii_case("RichEdit50W")
            || c.eq_ignore_ascii_case("RichEdit20A")
            || c.eq_ignore_ascii_case("RichEdit")
    })
}

/// Determine whether a focused non-Edit UIA element (`Custom 50025`, `Group 50026`, or
/// `Document 50030`) represents an editable `contenteditable` text composer (e.g. Feishu/Slack
/// ProseMirror/Quill) whose focused text should be captured as `AXTextArea` without altering its
/// container role in surface traversal.
#[allow(clippy::too_many_arguments)]
pub fn is_focused_editable_content_control(
    control_type: i32,
    is_password: ProtectedContentRead,
    supports_text_pattern: bool,
    supports_value_pattern: bool,
    value_is_read_only: Option<bool>,
    is_keyboard_focusable: Option<bool>,
    has_keyboard_focus: Option<bool>,
    aria_role: Option<&str>,
    class_name: Option<&str>,
) -> bool {
    if !matches!(control_type, 50025 | 50026 | 50030) {
        return false;
    }
    if is_password != ProtectedContentRead::Value(false) {
        return false;
    }
    if !supports_text_pattern {
        return false;
    }
    if value_is_read_only == Some(true) {
        return false;
    }
    let focusable = is_keyboard_focusable == Some(true) || has_keyboard_focus == Some(true);
    if !focusable {
        return false;
    }
    let aria_lower = aria_role.map(|r| r.to_ascii_lowercase());
    if matches!(
        aria_lower.as_deref(),
        Some("textbox" | "combobox" | "searchbox")
    ) {
        return true;
    }
    // Without an explicit editable ARIA role, never treat a whole-page browser/Electron
    // web surface or read-only document container as a focused text field.
    let is_web_host = class_name.is_some_and(|c| {
        c.eq_ignore_ascii_case("Chrome_RenderWidgetHostHWND")
            || c.eq_ignore_ascii_case("MozillaCompositorWindowClass")
    });
    if is_web_host {
        return false;
    }
    if matches!(
        aria_lower.as_deref(),
        Some("document" | "webarea" | "rootwebarea" | "application" | "main")
    ) {
        return false;
    }
    value_is_read_only == Some(false) && supports_value_pattern
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
