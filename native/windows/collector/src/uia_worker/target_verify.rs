//! Target window identity resolution, desktop/privacy gate verification, element security
//! classification, and post-read boundary revalidation.
//!
//! Layer 0 leaf module — imports no sibling `uia_worker` modules.

use windows::Win32::Foundation::HWND;
use windows::Win32::UI::Accessibility::IUIAutomationElement;
use windows::Win32::UI::WindowsAndMessaging::{
    GetAncestor, GetForegroundWindow, GetWindow, GA_ROOT, GA_ROOTOWNER, GW_OWNER,
};

use crate::adapters::{AdapterRegistry, AppAdapterSpec};
use crate::desktop::assess_windows_desktop;
use crate::input_activity_win32::VerifiedNormalBrowserWindow;
use crate::policy::{
    compute_window_title_digest, ApplicationPolicy, BrowserGate, IdentityPolicyOutcome,
    ResolvedAppIdentity, TextSecurityGate,
};
pub use crate::policy::{
    read_window_title_ephemeral, resolve_application_for_hwnd,
    resolve_application_identity_for_hwnd, resolve_foreground_application,
};
use crate::protocol_model::{
    ApplicationIdentity, CapturePolicy, CollectorClock, DesktopStatus, GapDiagnostic,
    GapDiagnosticCode, SecureStatus, SurfaceAbsoluteRect, SurfaceReadFailure,
};
use crate::uia_com::{
    window_rect_logical, PrivateChromeVerdict, UiaCallError, UiaClient, UiaElementMetadata,
};
use crate::uia_traversal::RuntimeIdKey;
use crate::worker_ipc::{ReadResult, ReadTicket};

/// Target window specification: either live foreground (`LiveForeground`) or a synthetic test HWND.
#[derive(Clone, Copy)]
pub(super) enum ReadTarget<'a> {
    LiveForeground,
    ExplicitWindow {
        window_hwnd: HWND,
        focused_hwnd: Option<HWND>,
        app_id_override: Option<&'a str>,
        resolved_override: Option<&'a ResolvedAppIdentity>,
        desktop_override: Option<DesktopStatus>,
    },
}

pub(super) fn check_desktop_status(target: ReadTarget<'_>) -> DesktopStatus {
    match target {
        ReadTarget::LiveForeground => assess_windows_desktop().status,
        ReadTarget::ExplicitWindow {
            desktop_override: Some(status),
            ..
        } => status,
        ReadTarget::ExplicitWindow {
            desktop_override: None,
            ..
        } => assess_windows_desktop().status,
    }
}

/// Maximum age (ms) of a cached `PrivateChromeVerdict::VerifiedNormal` browser chrome proof
/// before `verify_target_pre_read` forces a fresh full 128-node UIA toolbar scan.
pub(super) const VERIFIED_CHROME_PROOF_TTL_MS: i64 = 1_500;

/// Grace window (ms) for reusing an already-verified browser chrome proof at pre/post read
/// boundaries inside the exact same `execute_read_core` call so a read starting just before the
/// 1,500 ms TTL boundary does not trigger a surprise mid-read UIA toolbar walk.
pub(super) const VERIFIED_CHROME_PROOF_GRACE_TTL_MS: i64 = 2_000;

/// Short-lived proof that a specific live top-level browser `HWND` passed the full UIA
/// `is_private_browser_window_chrome` scan (`PrivateChromeVerdict::VerifiedNormal`) under an
/// exact `(hwnd, effective_pid, process_start_time, focus_epoch)` tuple.
///
/// Windows browsers never morph a normal top-level `HWND` into an Incognito/InPrivate window
/// in-place (private windows are always a distinct `HWND` that shifts foreground + `focus_epoch`),
/// and callers STILL run ephemeral window-title checks (`!BrowserGate::is_private_window_title`)
/// unconditionally on every read and keystroke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VerifiedChromeWindowProof {
    pub(super) hwnd_raw: isize,
    pub(super) effective_pid: u32,
    pub(super) process_start_time: String,
    pub(super) focus_epoch: u64,
    pub(super) verified_at_mono_ms: i64,
}

impl VerifiedChromeWindowProof {
    pub(super) fn matches(
        &self,
        hwnd: HWND,
        app: &ApplicationIdentity,
        current_focus_epoch: Option<u64>,
        now_mono_ms: i64,
    ) -> bool {
        let Some(epoch) = current_focus_epoch else {
            return false;
        };
        !hwnd.0.is_null()
            && self.hwnd_raw == (hwnd.0 as isize)
            && self.effective_pid != 0
            && self.effective_pid == app.process_id
            && !self.process_start_time.is_empty()
            && self.process_start_time == app.process_start_time
            && self.focus_epoch == epoch
            && now_mono_ms >= self.verified_at_mono_ms
            && now_mono_ms.saturating_sub(self.verified_at_mono_ms) < VERIFIED_CHROME_PROOF_TTL_MS
    }
}

/// Pure predicate deciding whether `reverify_window_boundary` may reuse the current read's
/// `VerifiedNormal` chrome proof instead of running a 2nd/3rd redundant UIA toolbar walk.
#[inline]
pub(super) const fn should_reuse_chrome_proof_at_boundary(
    is_live_foreground: bool,
    chrome_verified_normal: bool,
    has_non_private_title: bool,
    verified_focus_epoch: Option<u64>,
    current_focus_epoch: Option<u64>,
    verified_at_mono_ms: i64,
    now_mono_ms: i64,
) -> bool {
    if !is_live_foreground || !chrome_verified_normal || !has_non_private_title {
        return false;
    }
    let (Some(ver_epoch), Some(cur_epoch)) = (verified_focus_epoch, current_focus_epoch) else {
        return false;
    };
    if ver_epoch != cur_epoch || now_mono_ms < verified_at_mono_ms {
        return false;
    }
    now_mono_ms.saturating_sub(verified_at_mono_ms) < VERIFIED_CHROME_PROOF_GRACE_TTL_MS
}

pub(super) struct BoundaryReverifyOutcome {
    pub(super) verified_normal_browser: Option<VerifiedNormalBrowserWindow>,
    pub(super) chrome_verified_normal: bool,
    pub(super) chrome_verified_at_mono_ms: i64,
}

pub(super) struct VerifiedTarget {
    pub(super) hwnd: HWND,
    pub(super) raw_pid: u32,
    pub(super) app: ApplicationIdentity,
    pub(super) resolved: ResolvedAppIdentity,
    pub(super) spec: &'static AppAdapterSpec,
    pub(super) initial_logical_rect: Option<SurfaceAbsoluteRect>,
    pub(super) dpi: u32,
    pub(super) private_state: &'static str,
    pub(super) verified_normal_browser: Option<VerifiedNormalBrowserWindow>,
    pub(super) chrome_verified_normal: bool,
    pub(super) chrome_verified_at_mono_ms: i64,
    pub(super) chrome_verified_focus_epoch: Option<u64>,
}

pub(super) fn is_allowed_process_id(process_id: u32, verified: &VerifiedTarget) -> bool {
    process_id == 0 || process_id == verified.app.process_id || process_id == verified.raw_pid
}

/// Returns `true` when `hwnd` is a non-null window directly or transitively owned by `bound_hwnd`
/// (`GW_OWNER` / `GA_ROOTOWNER`) or rooted inside `bound_hwnd` (`GA_ROOT`), such as a WinUI 3
/// `Xaml_WindowedPopupClass` menu flyout popup. Strictly returns `false` for unowned sibling
/// windows (e.g. a separate Incognito browser window) or foreign apps.
pub(super) fn is_owned_popup_hwnd(hwnd: HWND, bound_hwnd: HWND) -> bool {
    if hwnd.0.is_null() || bound_hwnd.0.is_null() || hwnd == bound_hwnd {
        return false;
    }
    // SAFETY: Standard read-only Win32 window hierarchy/owner queries.
    unsafe {
        if GetAncestor(hwnd, GA_ROOT) == bound_hwnd {
            return true;
        }
        if GetWindow(hwnd, GW_OWNER)
            .ok()
            .filter(|h| !h.0.is_null())
            == Some(bound_hwnd)
        {
            return true;
        }
        GetAncestor(hwnd, GA_ROOTOWNER) == bound_hwnd
    }
}

pub(super) fn classify_element_security(
    meta: &UiaElementMetadata,
    policy: &CapturePolicy,
) -> SecureStatus {
    classify_element_security_with_role(meta, meta.mapped.ax_role, policy)
}

pub(super) fn classify_element_security_with_role(
    meta: &UiaElementMetadata,
    role: Option<&str>,
    policy: &CapturePolicy,
) -> SecureStatus {
    if meta.is_sensitive() {
        return SecureStatus::Sensitive;
    }
    TextSecurityGate::classify_metadata(
        role,
        &meta.subrole_read,
        meta.is_password,
        policy,
        Some(|| {
            // Strict Windows proof: explicit IsPassword == false AND readable text control with
            // either TextPattern or standard editable Win32 Edit/ValuePattern support.
            let has_bounded_text_support = meta.supports_text_pattern
                || meta.supports_text_pattern2
                || (meta.control_type == 50004 && meta.supports_value_pattern);
            TextSecurityGate::classify_windows_strict(
                role,
                &meta.subrole_read,
                meta.is_password,
                !meta.is_read_only,
                has_bounded_text_support,
                false,
            )
        }),
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn verify_target_pre_read(
    uia: &UiaClient,
    target: ReadTarget<'_>,
    ticket: &ReadTicket,
    registry: &AdapterRegistry,
    clock: &dyn CollectorClock,
    start_ms: i64,
    surface_requested: bool,
    cached_chrome_proof: Option<&VerifiedChromeWindowProof>,
    current_focus_epoch: Option<u64>,
) -> Result<VerifiedTarget, Box<ReadResult>> {
    let fail = |reason: &str,
                code: GapDiagnosticCode,
                surface_failure: Option<SurfaceReadFailure>| {
        let mut r = ReadResult::failure(
            ticket.token.clone(),
            reason,
            Some(GapDiagnostic::new(code, None)),
            start_ms,
            clock.unix_ms(),
        );
        r.surface_failure = surface_failure;
        Box::new(r)
    };

    if !ticket.policy.enabled {
        return Err(fail("stale", GapDiagnosticCode::InvalidSamplingPolicy, None));
    }
    if clock.monotonic_ms() >= ticket.deadline_monotonic_ms {
        return Err(fail("stale", GapDiagnosticCode::ReadDeadline, None));
    }
    if !ticket.policy.has_valid_text_settings() {
        return Err(fail(
            "policy-boundary",
            GapDiagnosticCode::InvalidSamplingPolicy,
            None,
        ));
    }
    if check_desktop_status(target) != DesktopStatus::Unlocked {
        return Err(fail(
            "desktop-unavailable",
            GapDiagnosticCode::DesktopUnavailable,
            None,
        ));
    }

    let (hwnd, app_override, resolved_override) = match target {
        ReadTarget::LiveForeground => {
            // SAFETY: Standard Win32 foreground window lookup.
            let fg = unsafe { GetForegroundWindow() };
            (fg, None, None)
        }
        ReadTarget::ExplicitWindow {
            window_hwnd,
            app_id_override,
            resolved_override,
            ..
        } => (window_hwnd, app_id_override, resolved_override),
    };

    let Some((raw_pid, app, resolved)) =
        resolve_application_identity_for_hwnd(hwnd, app_override, resolved_override)
    else {
        return Err(fail(
            "policy-boundary",
            GapDiagnosticCode::ApplicationUnavailable,
            None,
        ));
    };

    match ApplicationPolicy::evaluate_identity(&ticket.policy, &resolved) {
        IdentityPolicyOutcome::Allowed => {}
        IdentityPolicyOutcome::BrowserExcluded => {
            return Err(fail(
                "policy-boundary",
                GapDiagnosticCode::BrowserExcluded,
                None,
            ));
        }
        IdentityPolicyOutcome::MandatoryDenied | IdentityPolicyOutcome::SystemUi => {
            return Err(fail(
                "application-excluded",
                GapDiagnosticCode::ApplicationNotAllowed,
                None,
            ));
        }
        IdentityPolicyOutcome::ExcludedByPolicy
        | IdentityPolicyOutcome::NotInAllowlist
        | IdentityPolicyOutcome::PolicyDisabledOrInvalid => {
            let silent = ticket.policy.application_scope.as_deref() == Some("denylist")
                || ApplicationPolicy::is_mandatory_denied_identity(&resolved)
                || ApplicationPolicy::is_system_ui_identity(&resolved);
            return Err(fail(
                if silent {
                    "application-excluded"
                } else {
                    "policy-boundary"
                },
                GapDiagnosticCode::ApplicationNotAllowed,
                None,
            ));
        }
    }

    if !ApplicationPolicy::allows_identity(&ticket.policy, &resolved)
        || !BrowserGate::allows_identity(&resolved, &ticket.policy, false)
    {
        return Err(fail(
            "policy-boundary",
            GapDiagnosticCode::BrowserExcluded,
            None,
        ));
    }

    let spec = registry.adapter_for_identity(&resolved);
    let is_known_browser = BrowserGate::is_known_browser_identity(&resolved);
    let mut verified_normal_browser = None;
    let mut chrome_verified_normal = false;
    let mut chrome_verified_at_mono_ms = 0i64;
    let mut chrome_verified_focus_epoch = None;
    if BrowserGate::should_block_private_windows_identity(&resolved, spec.block_private_windows) {
        let ephemeral_title = read_window_title_ephemeral(hwnd);
        if let Some(ref title) = ephemeral_title {
            if BrowserGate::is_private_window_title(title) {
                return Err(fail(
                    "policy-boundary",
                    GapDiagnosticCode::BrowserExcluded,
                    surface_requested.then_some(SurfaceReadFailure::SecurityExcluded),
                ));
            }
        }
        let reused_proof_mono_ms = if matches!(target, ReadTarget::LiveForeground)
            && ephemeral_title.is_some()
        {
            cached_chrome_proof
                .filter(|p| p.matches(hwnd, &app, current_focus_epoch, clock.monotonic_ms()))
                .map(|p| p.verified_at_mono_ms)
        } else {
            None
        };
        if let Some(verified_at) = reused_proof_mono_ms {
            chrome_verified_normal = true;
            chrome_verified_at_mono_ms = verified_at;
            chrome_verified_focus_epoch = current_focus_epoch;
        } else {
            let chrome_deadline = clock
                .monotonic_ms()
                .saturating_add(400)
                .min(ticket.deadline_monotonic_ms);
            let verdict = uia.is_private_browser_window_chrome(
                hwnd,
                chrome_deadline,
                ticket.deadline_monotonic_ms,
            );
            uia.apply_timeouts(
                ticket
                    .deadline_monotonic_ms
                    .saturating_sub(clock.monotonic_ms()),
            );
            match verdict {
                Ok(PrivateChromeVerdict::VerifiedNormal) => {
                    chrome_verified_normal = true;
                    chrome_verified_at_mono_ms = clock.monotonic_ms();
                    chrome_verified_focus_epoch = current_focus_epoch;
                }
                Ok(PrivateChromeVerdict::Private | PrivateChromeVerdict::Inconclusive) | Err(_) => {
                    return Err(fail(
                        "policy-boundary",
                        GapDiagnosticCode::BrowserExcluded,
                        surface_requested.then_some(SurfaceReadFailure::SecurityExcluded),
                    ));
                }
            }
        }
        if ticket.policy.input_activity == Some(true) && is_known_browser {
            if let Some(title) = ephemeral_title {
                if !BrowserGate::is_private_window_title(&title) {
                    let digest = compute_window_title_digest(&title);
                    drop(title);
                    if let Some((title_sha256, title_utf16_len)) = digest {
                        let candidate = VerifiedNormalBrowserWindow {
                            hwnd_raw: hwnd.0 as isize,
                            effective_pid: app.process_id,
                            process_start_time: app.process_start_time.clone(),
                            title_sha256,
                            title_utf16_len,
                        };
                        if candidate.is_valid() {
                            verified_normal_browser = Some(candidate);
                        }
                    }
                }
            }
        }
    }

    if let Some(ref hint) = ticket.hint {
        if hint.application != app {
            return Err(fail("stale", GapDiagnosticCode::FocusChanged, None));
        }
    }

    let (initial_logical_rect, dpi) = match window_rect_logical(hwnd) {
        Some((_, logical, dpi)) => (Some(logical), dpi),
        None => (None, 96),
    };
    let private_state = if is_known_browser {
        "user-authorized"
    } else {
        "normal"
    };

    Ok(VerifiedTarget {
        hwnd,
        raw_pid,
        app,
        resolved,
        spec,
        initial_logical_rect,
        dpi,
        private_state,
        verified_normal_browser,
        chrome_verified_normal,
        chrome_verified_at_mono_ms,
        chrome_verified_focus_epoch,
    })
}

pub(super) fn reverify_window_boundary(
    uia: &UiaClient,
    target: ReadTarget<'_>,
    verified: &VerifiedTarget,
    ticket: &ReadTicket,
    clock: &dyn CollectorClock,
    current_focus_epoch: Option<u64>,
) -> Result<BoundaryReverifyOutcome, (GapDiagnosticCode, Option<SurfaceReadFailure>)> {
    if clock.monotonic_ms() >= ticket.deadline_monotonic_ms {
        return Err((
            GapDiagnosticCode::ReadDeadline,
            Some(SurfaceReadFailure::BoundaryIncomplete),
        ));
    }
    if check_desktop_status(target) != DesktopStatus::Unlocked {
        return Err((
            GapDiagnosticCode::DesktopUnavailable,
            Some(SurfaceReadFailure::BoundaryUnverified),
        ));
    }
    let (app_override, resolved_override) = match target {
        ReadTarget::LiveForeground => {
            // SAFETY: Live foreground window check.
            let fg = unsafe { GetForegroundWindow() };
            if fg != verified.hwnd {
                return Err((
                    GapDiagnosticCode::FocusChanged,
                    Some(SurfaceReadFailure::BoundaryMismatch),
                ));
            }
            (None, None)
        }
        ReadTarget::ExplicitWindow {
            app_id_override,
            resolved_override,
            ..
        } => (app_id_override, resolved_override),
    };

    let Some((_, current_app, current_resolved)) =
        resolve_application_identity_for_hwnd(verified.hwnd, app_override, resolved_override)
    else {
        return Err((
            GapDiagnosticCode::FocusChanged,
            Some(SurfaceReadFailure::BoundaryUnverified),
        ));
    };
    if current_app != verified.app || current_resolved != verified.resolved {
        return Err((
            GapDiagnosticCode::FocusChanged,
            Some(SurfaceReadFailure::BoundaryMismatch),
        ));
    }

    match ApplicationPolicy::evaluate_identity(&ticket.policy, &current_resolved) {
        IdentityPolicyOutcome::Allowed => {}
        IdentityPolicyOutcome::BrowserExcluded => {
            return Err((
                GapDiagnosticCode::BrowserExcluded,
                Some(SurfaceReadFailure::SecurityExcluded),
            ));
        }
        IdentityPolicyOutcome::MandatoryDenied
        | IdentityPolicyOutcome::SystemUi
        | IdentityPolicyOutcome::ExcludedByPolicy
        | IdentityPolicyOutcome::NotInAllowlist
        | IdentityPolicyOutcome::PolicyDisabledOrInvalid => {
            return Err((
                GapDiagnosticCode::ApplicationNotAllowed,
                Some(SurfaceReadFailure::SecurityExcluded),
            ));
        }
    }
    if !BrowserGate::allows_identity(&current_resolved, &ticket.policy, false) {
        return Err((
            GapDiagnosticCode::BrowserExcluded,
            Some(SurfaceReadFailure::SecurityExcluded),
        ));
    }

    let mut post_verified_browser = None;
    let mut chrome_verified_normal = false;
    let mut chrome_verified_at_mono_ms = 0i64;
    if BrowserGate::should_block_private_windows_identity(
        &current_resolved,
        verified.spec.block_private_windows,
    ) {
        let ephemeral_title = read_window_title_ephemeral(verified.hwnd);
        if let Some(ref title) = ephemeral_title {
            if BrowserGate::is_private_window_title(title) {
                return Err((
                    GapDiagnosticCode::BrowserExcluded,
                    Some(SurfaceReadFailure::SecurityExcluded),
                ));
            }
        }
        let reuse_proof = should_reuse_chrome_proof_at_boundary(
            matches!(target, ReadTarget::LiveForeground),
            verified.chrome_verified_normal,
            ephemeral_title.is_some(),
            verified.chrome_verified_focus_epoch,
            current_focus_epoch,
            verified.chrome_verified_at_mono_ms,
            clock.monotonic_ms(),
        );
        if reuse_proof {
            chrome_verified_normal = true;
            chrome_verified_at_mono_ms = verified.chrome_verified_at_mono_ms;
        } else {
            let chrome_deadline = clock
                .monotonic_ms()
                .saturating_add(300)
                .min(ticket.deadline_monotonic_ms);
            let verdict = uia.is_private_browser_window_chrome(
                verified.hwnd,
                chrome_deadline,
                ticket.deadline_monotonic_ms,
            );
            uia.apply_timeouts(
                ticket
                    .deadline_monotonic_ms
                    .saturating_sub(clock.monotonic_ms()),
            );
            if !matches!(verdict, Ok(PrivateChromeVerdict::VerifiedNormal)) {
                return Err((
                    GapDiagnosticCode::BrowserExcluded,
                    Some(SurfaceReadFailure::SecurityExcluded),
                ));
            }
            chrome_verified_normal = true;
            chrome_verified_at_mono_ms = clock.monotonic_ms();
        }
        if ticket.policy.input_activity == Some(true)
            && BrowserGate::is_known_browser_identity(&current_resolved)
        {
            if let Some(title) = ephemeral_title {
                if !BrowserGate::is_private_window_title(&title) {
                    let digest = compute_window_title_digest(&title);
                    drop(title);
                    if let Some((title_sha256, title_utf16_len)) = digest {
                        let candidate = VerifiedNormalBrowserWindow {
                            hwnd_raw: verified.hwnd.0 as isize,
                            effective_pid: current_app.process_id,
                            process_start_time: current_app.process_start_time,
                            title_sha256,
                            title_utf16_len,
                        };
                        if candidate.is_valid() {
                            post_verified_browser = Some(candidate);
                        }
                    }
                }
            }
        }
    }

    Ok(BoundaryReverifyOutcome {
        verified_normal_browser: post_verified_browser,
        chrome_verified_normal,
        chrome_verified_at_mono_ms,
    })
}

pub(super) fn reverify_focused_element(
    uia: &UiaClient,
    focused_elem: &IUIAutomationElement,
    expected_runtime_id: &RuntimeIdKey,
    expected_role: Option<&str>,
    expect_contenteditable: bool,
    verified: &VerifiedTarget,
    is_terminal: bool,
) -> Result<UiaElementMetadata, (GapDiagnosticCode, Option<SurfaceReadFailure>)> {
    let refreshed = uia.refresh_metadata(focused_elem).map_err(|_| {
        (
            GapDiagnosticCode::FocusChanged,
            Some(SurfaceReadFailure::BoundaryAxFailed),
        )
    })?;
    let meta = uia
        .read_cached_metadata(&refreshed, verified.dpi, false, is_terminal)
        .map_err(|_| {
            (
                GapDiagnosticCode::FocusChanged,
                Some(SurfaceReadFailure::BoundaryAxFailed),
            )
        })?;
    if meta.is_sensitive() {
        return Err((
            GapDiagnosticCode::SecureField,
            Some(SurfaceReadFailure::SecurityExcluded),
        ));
    }
    if !expected_runtime_id.is_empty() && meta.runtime_id != *expected_runtime_id {
        return Err((
            GapDiagnosticCode::FocusChanged,
            Some(SurfaceReadFailure::BoundaryMismatch),
        ));
    }
    if meta.mapped.ax_role != expected_role {
        return Err((
            GapDiagnosticCode::FocusChanged,
            Some(SurfaceReadFailure::BoundaryMismatch),
        ));
    }
    if expect_contenteditable && !meta.is_focused_editable_content() {
        return Err((
            GapDiagnosticCode::FocusChanged,
            Some(SurfaceReadFailure::BoundaryMismatch),
        ));
    }
    Ok(meta)
}

pub(super) fn element_belongs_to_window(
    uia: &UiaClient,
    elem: &IUIAutomationElement,
    meta: &UiaElementMetadata,
    verified: &VerifiedTarget,
) -> bool {
    if meta.process_id != 0
        && meta.process_id != verified.app.process_id
        && meta.process_id != verified.raw_pid
    {
        return false;
    }
    if let Some(native) = meta.native_hwnd {
        if native == verified.hwnd {
            return true;
        }
        // SAFETY: Standard Win32 root ancestor check.
        let root = unsafe { GetAncestor(native, GA_ROOT) };
        if root == verified.hwnd {
            return true;
        }
    }
    // Walk up to 24 ControlView parents looking for the target window HWND.
    let mut cur = elem.clone();
    for _ in 0..24 {
        let parent = match uia.parent_element(&cur) {
            Ok(Some(p)) => p,
            Ok(None) | Err(UiaCallError::Unavailable) => break,
            Err(UiaCallError::AccessDenied) => return false,
        };
        match uia.read_cached_metadata(&parent, verified.dpi, false, false) {
            Ok(pmeta) => {
                if pmeta.native_hwnd == Some(verified.hwnd) {
                    return true;
                }
                if pmeta.process_id != 0
                    && pmeta.process_id != verified.app.process_id
                    && pmeta.process_id != verified.raw_pid
                {
                    return false;
                }
            }
            Err(UiaCallError::AccessDenied) => return false,
            Err(UiaCallError::Unavailable) => {}
        }
        cur = parent;
    }
    // Fallback: if process matches and we couldn't traverse further (e.g., virtual UIA fragment),
    // accept only when process_id explicitly matches.
    meta.process_id == verified.app.process_id || meta.process_id == verified.raw_pid
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chrome_app(pid: u32, start: &str) -> ApplicationIdentity {
        ApplicationIdentity {
            application_id: "chrome.exe".to_string(),
            process_id: pid,
            process_start_time: start.to_string(),
        }
    }

    #[test]
    fn verified_chrome_window_proof_matches_strictly_within_ttl_and_rejects_mismatches() {
        let hwnd = HWND(0x2000usize as *mut core::ffi::c_void);
        let app = chrome_app(7777, "unix-ms:1700000000000.000");
        let proof = VerifiedChromeWindowProof {
            hwnd_raw: hwnd.0 as isize,
            effective_pid: 7777,
            process_start_time: app.process_start_time.clone(),
            focus_epoch: 12,
            verified_at_mono_ms: 10_000,
        };

        // Exact match at 0 ms and TTL - 1 ms.
        assert!(proof.matches(hwnd, &app, Some(12), 10_000));
        assert!(proof.matches(hwnd, &app, Some(12), 10_000 + VERIFIED_CHROME_PROOF_TTL_MS - 1));

        // Expired at exact TTL boundary or clock rollback -> fail closed.
        assert!(!proof.matches(hwnd, &app, Some(12), 10_000 + VERIFIED_CHROME_PROOF_TTL_MS));
        assert!(!proof.matches(hwnd, &app, Some(12), 9_999));

        // Missing or mismatched focus_epoch -> fail closed.
        assert!(!proof.matches(hwnd, &app, None, 10_100));
        assert!(!proof.matches(hwnd, &app, Some(13), 10_100));

        // Null or different HWND (e.g. switching to separate Incognito HWND) -> fail closed.
        assert!(!proof.matches(HWND::default(), &app, Some(12), 10_100));
        assert!(!proof.matches(
            HWND(0x3000usize as *mut core::ffi::c_void),
            &app,
            Some(12),
            10_100,
        ));

        // PID or process_start_time mismatch (PID reuse defense) -> fail closed.
        assert!(!proof.matches(hwnd, &chrome_app(8888, &app.process_start_time), Some(12), 10_100));
        assert!(!proof.matches(
            hwnd,
            &chrome_app(7777, "unix-ms:1700000009999.000"),
            Some(12),
            10_100,
        ));
        assert!(!proof.matches(hwnd, &chrome_app(7777, ""), Some(12), 10_100));
    }

    #[test]
    fn boundary_chrome_proof_reuse_enforces_live_title_epoch_and_grace_ttl() {
        // Valid LiveForeground reuse within 2,000 ms grace window.
        assert!(should_reuse_chrome_proof_at_boundary(
            true,
            true,
            true,
            Some(5),
            Some(5),
            20_000,
            20_000 + VERIFIED_CHROME_PROOF_GRACE_TTL_MS - 1,
        ));
        // ExplicitWindow tests NEVER skip full chrome verification.
        assert!(!should_reuse_chrome_proof_at_boundary(
            false,
            true,
            true,
            Some(5),
            Some(5),
            20_000,
            20_050,
        ));
        // Unverified chrome or missing/empty title -> fail closed.
        assert!(!should_reuse_chrome_proof_at_boundary(
            true,
            false,
            true,
            Some(5),
            Some(5),
            20_000,
            20_050,
        ));
        assert!(!should_reuse_chrome_proof_at_boundary(
            true,
            true,
            false,
            Some(5),
            Some(5),
            20_000,
            20_050,
        ));
        // Missing or changed focus_epoch -> fail closed.
        assert!(!should_reuse_chrome_proof_at_boundary(
            true,
            true,
            true,
            None,
            None,
            20_000,
            20_050,
        ));
        assert!(!should_reuse_chrome_proof_at_boundary(
            true,
            true,
            true,
            Some(5),
            Some(6),
            20_000,
            20_050,
        ));
        // Expired grace TTL or clock rollback -> fail closed.
        assert!(!should_reuse_chrome_proof_at_boundary(
            true,
            true,
            true,
            Some(5),
            Some(5),
            20_000,
            20_000 + VERIFIED_CHROME_PROOF_GRACE_TTL_MS,
        ));
        assert!(!should_reuse_chrome_proof_at_boundary(
            true,
            true,
            true,
            Some(5),
            Some(5),
            20_000,
            19_999,
        ));
    }
}
