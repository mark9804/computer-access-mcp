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
            Ok(PrivateChromeVerdict::Private | PrivateChromeVerdict::Inconclusive) | Err(_) => {
                return Err(fail(
                    "policy-boundary",
                    GapDiagnosticCode::BrowserExcluded,
                    surface_requested.then_some(SurfaceReadFailure::SecurityExcluded),
                ));
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
    })
}

pub(super) fn reverify_window_boundary(
    uia: &UiaClient,
    target: ReadTarget<'_>,
    verified: &VerifiedTarget,
    ticket: &ReadTicket,
    clock: &dyn CollectorClock,
) -> Result<Option<VerifiedNormalBrowserWindow>, (GapDiagnosticCode, Option<SurfaceReadFailure>)> {
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

    Ok(post_verified_browser)
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
