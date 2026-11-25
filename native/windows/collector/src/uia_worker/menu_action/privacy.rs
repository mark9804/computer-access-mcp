//! Pre-read / post-read menu privacy gates, Win32 HWND ownership checks, shared metadata safety
//! guards, and top-level application `MenuBar` discovery.
//!
//! Layer 1b submodule — imports `state` only (NEVER imports `walker` or `mod`).

use windows::Win32::Foundation::HWND;
use windows::Win32::UI::Accessibility::IUIAutomationElement;
use windows::Win32::UI::WindowsAndMessaging::{
    GetAncestor, GetClassNameW, GetDesktopWindow, GetForegroundWindow, GetWindow,
    GetWindowThreadProcessId, GA_ROOT, GW_OWNER,
};

use super::state::is_document_or_renderer_host_fields;
use crate::adapters::AdapterRegistry;
use crate::desktop::assess_windows_desktop;
use crate::menu_action_core::{
    BrowserChromeVerdict, BrowserMenuWindowGate, BrowserWindowInspection, UIA_MENU_BAR_CONTROL_TYPE,
};
use crate::policy::{ApplicationPolicy, BrowserGate, ResolvedAppIdentity, TextSecurityGate};
use crate::protocol_model::{
    ApplicationIdentity, CapturePolicy, CollectorClock, DesktopStatus, Stamp,
};
use crate::uia_com::{PrivateChromeVerdict, UiaClient, UiaElementMetadata};
use crate::uia_worker::target_verify::{
    is_owned_popup_hwnd, read_window_title_ephemeral, resolve_application_identity_for_hwnd,
};

/// Maximum direct children scanned on the bound window when locating the top application `MenuBar`.
const MAX_WINDOW_MENU_BAR_PROBE_CHILDREN: usize = 16;

/// Verified bound foreground window identity handed from `LiveUiaSession` to `MenuActionSession`.
#[derive(Debug, Clone)]
pub(in crate::uia_worker) struct MenuBindingTarget {
    pub(in crate::uia_worker) hwnd: HWND,
    pub(in crate::uia_worker) raw_pid: u32,
    pub(in crate::uia_worker) app: ApplicationIdentity,
    pub(in crate::uia_worker) resolved: ResolvedAppIdentity,
    pub(in crate::uia_worker) dpi: u32,
    pub(in crate::uia_worker) private_state: &'static str,
}

/// Active bound window snapshot owned by `MenuActionSession`.
pub(super) struct BoundMenuWindow {
    pub(super) hwnd: HWND,
    pub(super) raw_pid: u32,
    pub(super) app: ApplicationIdentity,
    pub(super) resolved: ResolvedAppIdentity,
    pub(super) is_browser: bool,
    pub(super) dpi: u32,
    pub(super) private_state: &'static str,
    pub(super) policy: CapturePolicy,
    pub(super) stamp: Stamp,
    /// Optional cached direct non-`SystemMenuBar` `MenuBar (50010)` element of `hwnd`.
    pub(super) app_menu_bar: Option<IUIAutomationElement>,
}

impl BoundMenuWindow {
    pub(super) fn walk_ctx(&self) -> MenuWalkContext {
        MenuWalkContext {
            hwnd: self.hwnd,
            expected_pid: self.app.process_id,
            raw_pid: self.raw_pid,
            is_browser: self.is_browser,
            dpi: self.dpi,
        }
    }
}

/// Compact immutable context carried through UIA menu ancestor walks and `MenuBar` ownership checks.
#[derive(Debug, Clone, Copy)]
pub(super) struct MenuWalkContext {
    pub hwnd: HWND,
    pub expected_pid: u32,
    pub raw_pid: u32,
    pub is_browser: bool,
    pub dpi: u32,
}

impl MenuWalkContext {
    pub fn matches_pid(&self, pid: u32) -> bool {
        pid > 0 && (pid == self.expected_pid || (self.raw_pid > 0 && pid == self.raw_pid))
    }

    pub fn raw_host_pid(&self) -> Option<u32> {
        (self.raw_pid > 0 && self.raw_pid != self.expected_pid).then_some(self.raw_pid)
    }
}

/// Shared PID + sensitivity + `TextSecurityGate::may_traverse` check applied before inspecting or
/// traversing any UIA menu node belonging to the bound foreground window.
pub(super) fn meta_is_safe_for_bound(
    meta: &UiaElementMetadata,
    expected_pid: u32,
    raw_pid: u32,
) -> bool {
    let ctx = MenuWalkContext {
        hwnd: HWND(core::ptr::null_mut()),
        expected_pid,
        raw_pid,
        is_browser: false,
        dpi: 0,
    };
    ctx.matches_pid(meta.process_id)
        && !meta.is_sensitive()
        && TextSecurityGate::may_traverse(&meta.subrole_read, meta.is_password)
}

/// Returns `true` when `meta` is the standard Win32 title-bar `SystemMenuBar`.
pub(super) fn is_system_menu_bar(meta: &UiaElementMetadata) -> bool {
    meta.automation_id
        .as_deref()
        .is_some_and(|aid| aid.eq_ignore_ascii_case("SystemMenuBar"))
}

/// Returns `true` when `meta` represents a web document or browser content-renderer host node.
pub(super) fn is_document_or_renderer_host(meta: &UiaElementMetadata) -> bool {
    is_document_or_renderer_host_fields(
        meta.control_type,
        meta.mapped.ax_role,
        meta.class_name.as_deref(),
    )
}

pub(super) fn root_hwnd_for_raw(raw_hwnd: isize) -> HWND {
    let hwnd = HWND(raw_hwnd as *mut core::ffi::c_void);
    if hwnd.0.is_null() {
        return hwnd;
    }
    // SAFETY: Standard read-only Win32 root ancestor query.
    let root = unsafe { GetAncestor(hwnd, GA_ROOT) };
    if !root.0.is_null() {
        root
    } else {
        hwnd
    }
}

pub(super) fn window_class_name(hwnd: HWND) -> Option<String> {
    if hwnd.0.is_null() {
        return None;
    }
    let mut buf = [0u16; 128];
    // SAFETY: Standard read-only Win32 class name query.
    let len = unsafe { GetClassNameW(hwnd, &mut buf) };
    if len <= 0 {
        return None;
    }
    String::from_utf16(&buf[..len as usize]).ok()
}

pub(super) fn hwnd_matches_bound_pid(hwnd: HWND, expected_pid: u32, raw_pid: u32) -> bool {
    if hwnd.0.is_null() {
        return false;
    }
    let mut pid: u32 = 0;
    // SAFETY: Standard read-only Win32 PID query.
    unsafe {
        GetWindowThreadProcessId(hwnd, Some(&mut pid));
    }
    let ctx = MenuWalkContext {
        hwnd,
        expected_pid,
        raw_pid,
        is_browser: false,
        dpi: 0,
    };
    ctx.matches_pid(pid)
}

pub(super) fn popup_hwnd_belongs_to_bound(
    popup_hwnd: HWND,
    bound_hwnd: HWND,
    expected_pid: u32,
    raw_pid: u32,
) -> bool {
    if popup_hwnd.0.is_null()
        || bound_hwnd.0.is_null()
        || popup_hwnd == bound_hwnd
        // SAFETY: Standard read-only Win32 desktop window handle lookup.
        || popup_hwnd == unsafe { GetDesktopWindow() }
    {
        return false;
    }
    if !hwnd_matches_bound_pid(popup_hwnd, expected_pid, raw_pid) {
        return false;
    }
    if is_owned_popup_hwnd(popup_hwnd, bound_hwnd) {
        return true;
    }
    // Strictly permit unowned popups ONLY when their class is classic Win32 `#32768`; reject all
    // unowned sibling top-level windows (e.g. separate Incognito browser windows, Desktop/Taskbar)
    // and popups owned by any other window.
    // SAFETY: Standard read-only Win32 owner query.
    let owner = unsafe { GetWindow(popup_hwnd, GW_OWNER) }
        .ok()
        .filter(|h| !h.0.is_null());
    owner.is_none()
        && window_class_name(popup_hwnd)
            .as_deref()
            .is_some_and(|cls| cls.eq_ignore_ascii_case("#32768"))
}

/// Fast zero-COM pre-gate verifying policy, unlocked desktop, foreground HWND (either `bound.hwnd`
/// or an owned popup of `bound.hwnd`), exact dual-ID `(app, resolved)` identity, app/browser
/// policy, and non-private ephemeral browser window title. Returns the verified foreground `HWND`.
pub(super) fn passes_fast_menu_privacy_pre_gate(
    registry: &AdapterRegistry,
    bound: &BoundMenuWindow,
    deadline_ms: i64,
    clock: &dyn CollectorClock,
) -> Option<HWND> {
    if clock.monotonic_ms() >= deadline_ms
        || !bound.policy.enabled
        || bound.policy.menu_actions != Some(true)
    {
        return None;
    }
    if assess_windows_desktop().status != DesktopStatus::Unlocked {
        return None;
    }
    // SAFETY: Standard Win32 foreground window lookup.
    let fg = unsafe { GetForegroundWindow() };
    if fg.0.is_null() {
        return None;
    }
    if fg != bound.hwnd && !is_owned_popup_hwnd(fg, bound.hwnd) {
        return None;
    }
    let (_, current_app, current_resolved) = resolve_application_identity_for_hwnd(fg, None, None)?;
    if current_app != bound.app || current_resolved != bound.resolved {
        return None;
    }
    if !ApplicationPolicy::allows_identity(&bound.policy, &current_resolved)
        || !BrowserGate::allows_identity(&current_resolved, &bound.policy, false)
    {
        return None;
    }
    let spec = registry.adapter_for_identity(&current_resolved);
    let is_browser = BrowserGate::is_known_browser_identity(&current_resolved)
        || BrowserGate::should_block_private_windows_identity(
            &current_resolved,
            spec.block_private_windows,
        );
    if is_browser {
        if bound.policy.application_scope.as_deref() != Some("denylist")
            || bound.policy.allow_browser_content != Some(true)
        {
            return None;
        }
        let title = read_window_title_ephemeral(bound.hwnd)?;
        if BrowserGate::is_private_window_title(&title) {
            return None;
        }
    }
    Some(fg)
}

/// Full pre-read & post-read privacy gate executed BEFORE reading any menu element title and
/// re-verified AFTER path resolution (including fail-closed native browser chrome verification and
/// post-check foreground identity verification).
pub(super) fn passes_live_menu_privacy_gates(
    uia: &UiaClient,
    registry: &AdapterRegistry,
    bound: &BoundMenuWindow,
    deadline_ms: i64,
    clock: &dyn CollectorClock,
) -> bool {
    let Some(fg) = passes_fast_menu_privacy_pre_gate(registry, bound, deadline_ms, clock) else {
        return false;
    };

    let spec = registry.adapter_for_identity(&bound.resolved);
    let is_browser_candidate = BrowserGate::is_known_browser_identity(&bound.resolved);
    let chrome_ok = BrowserMenuWindowGate::allows_foreground_window(
        &bound.resolved,
        is_browser_candidate,
        spec,
        &bound.policy,
        || inspect_browser_window_for_menu_gate(uia, bound.hwnd, bound.dpi, deadline_ms, clock),
    );
    if !chrome_ok {
        return false;
    }

    // Confirm foreground window did not switch away from `bound.hwnd` (or a verified same-identity
    // owned popup) while browser chrome inspection ran.
    // SAFETY: Standard Win32 foreground window lookup.
    let final_fg = unsafe { GetForegroundWindow() };
    if final_fg == fg {
        return true;
    }
    if final_fg != bound.hwnd && !is_owned_popup_hwnd(final_fg, bound.hwnd) {
        return false;
    }
    resolve_application_identity_for_hwnd(final_fg, None, None)
        .is_some_and(|(_, app, resolved)| app == bound.app && resolved == bound.resolved)
}

fn inspect_browser_window_for_menu_gate(
    uia: &UiaClient,
    hwnd: HWND,
    dpi: u32,
    deadline_ms: i64,
    clock: &dyn CollectorClock,
) -> BrowserWindowInspection {
    let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
    if rem <= 0 {
        return BrowserWindowInspection::Failure;
    }
    let safe_title = read_window_title_ephemeral(hwnd);
    if let Some(ref title) = safe_title {
        if BrowserGate::is_private_window_title(title) {
            return BrowserWindowInspection::Inspected {
                role: Some("AXWindow".to_string()),
                has_sensitive_evidence: false,
                safe_title,
                chrome_verdict: BrowserChromeVerdict::Private,
            };
        }
    }

    uia.apply_timeouts(rem);
    let Ok(win_el) = uia.element_from_hwnd(hwnd) else {
        return BrowserWindowInspection::Failure;
    };
    let Ok(meta) = uia.read_cached_metadata(&win_el, dpi, false, false) else {
        return BrowserWindowInspection::Failure;
    };
    let has_sensitive =
        meta.is_sensitive() || !TextSecurityGate::may_traverse(&meta.subrole_read, meta.is_password);
    let role = meta.mapped.ax_role.map(str::to_string);
    if has_sensitive || role.as_deref() != Some("AXWindow") {
        return BrowserWindowInspection::Inspected {
            role,
            has_sensitive_evidence: has_sensitive,
            safe_title,
            chrome_verdict: BrowserChromeVerdict::Inconclusive,
        };
    }

    let chrome_deadline = clock.monotonic_ms().saturating_add(80).min(deadline_ms);
    let verdict = match uia.is_private_browser_window_chrome(hwnd, chrome_deadline, deadline_ms) {
        Ok(PrivateChromeVerdict::VerifiedNormal) => BrowserChromeVerdict::VerifiedNormal,
        Ok(PrivateChromeVerdict::Private) => BrowserChromeVerdict::Private,
        Ok(PrivateChromeVerdict::Inconclusive) | Err(_) => BrowserChromeVerdict::Inconclusive,
    };
    uia.apply_timeouts(deadline_ms.saturating_sub(clock.monotonic_ms()).max(25));

    BrowserWindowInspection::Inspected {
        role,
        has_sensitive_evidence: false,
        safe_title,
        chrome_verdict: verdict,
    }
}

/// Locate the foreground window's direct non-`SystemMenuBar` top-level `MenuBar (50010)` element
/// (bounded to <= 16 children and `deadline_ms`), strictly skipping `AutomationId == "SystemMenuBar"`.
pub fn find_app_menu_bar_for_window(
    uia: &UiaClient,
    hwnd: HWND,
    expected_pid: u32,
    raw_pid: u32,
    dpi: u32,
    deadline_ms: i64,
    clock: &dyn CollectorClock,
) -> Option<IUIAutomationElement> {
    let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
    if hwnd.0.is_null() || rem <= 0 {
        return None;
    }
    uia.apply_timeouts(rem);
    let win_el = uia.element_from_hwnd(hwnd).ok()?;
    let children = uia
        .direct_children_bounded(&win_el, MAX_WINDOW_MENU_BAR_PROBE_CHILDREN, || {
            clock.monotonic_ms() < deadline_ms
        })
        .ok()?;
    for child in children {
        if clock.monotonic_ms() >= deadline_ms {
            break;
        }
        let Ok(meta) = uia.read_cached_metadata(&child, dpi, false, false) else {
            continue;
        };
        if !meta_is_safe_for_bound(&meta, expected_pid, raw_pid) {
            continue;
        }
        if meta.control_type == UIA_MENU_BAR_CONTROL_TYPE && !is_system_menu_bar(&meta) {
            return Some(child);
        }
    }
    None
}
