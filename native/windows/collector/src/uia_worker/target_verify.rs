//! Target window identity resolution, desktop/privacy gate verification, element security
//! classification, and post-read boundary revalidation.
//!
//! Layer 0 leaf module — imports no sibling `uia_worker` modules.

use windows::Win32::Foundation::HWND;
use windows::Win32::UI::Accessibility::IUIAutomationElement;
use windows::Win32::UI::WindowsAndMessaging::{
    GetAncestor, GetForegroundWindow, GetWindowTextLengthW, GetWindowTextW,
    GetWindowThreadProcessId, GA_ROOT,
};

use crate::adapters::{AdapterRegistry, AppAdapterSpec};
use crate::desktop::assess_windows_desktop;
use crate::ownership::process_start_time_for_pid;
use crate::policy::{
    resolve_app_identity_for_pid, resolve_effective_pid_checked, ApplicationPolicy, BrowserGate,
    IdentityPolicyOutcome, ResolvedAppIdentity, TextSecurityGate,
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

pub(super) fn read_window_title_ephemeral(hwnd: HWND) -> Option<String> {
    if hwnd.0.is_null() {
        return None;
    }
    // SAFETY: Standard Win32 window title query on live HWND; used in-memory ONLY for private
    // browser title detection and NEVER emitted, returned, or logged.
    unsafe {
        let len = GetWindowTextLengthW(hwnd);
        if len <= 0 {
            return None;
        }
        let mut buf = vec![0u16; (len as usize).min(512) + 1];
        let copied = GetWindowTextW(hwnd, &mut buf);
        if copied <= 0 {
            return None;
        }
        String::from_utf16(&buf[..copied as usize]).ok()
    }
}

/// Resolve raw window PID, effective UWP/Win32 PID, canonical `ApplicationIdentity`, and dual-ID
/// `ResolvedAppIdentity` for an HWND. Fails closed (`None`) whenever `resolve_effective_pid_checked`
/// or `resolve_app_identity_for_pid` fails or resolves to `ApplicationFrameHost.exe`.
pub fn resolve_application_identity_for_hwnd(
    hwnd: HWND,
    app_id_override: Option<&str>,
    resolved_override: Option<&ResolvedAppIdentity>,
) -> Option<(u32, ApplicationIdentity, ResolvedAppIdentity)> {
    if hwnd.0.is_null() {
        return None;
    }
    let mut raw_pid: u32 = 0;
    // SAFETY: Standard Win32 HWND -> PID query.
    unsafe {
        GetWindowThreadProcessId(hwnd, Some(&mut raw_pid));
    }
    let effective_pid = resolve_effective_pid_checked(raw_pid, Some(hwnd.0 as isize))?;
    let resolved = if let Some(res_ov) = resolved_override {
        if res_ov.package_name.is_some() || res_ov.exe_name.is_some() {
            ResolvedAppIdentity::from_parts(res_ov.package_name.clone(), res_ov.exe_name.clone())?
        } else {
            ResolvedAppIdentity::from_single(res_ov.application_id.clone())?
        }
    } else if let Some(over) = app_id_override {
        ResolvedAppIdentity::from_single(over.to_string())?
    } else {
        resolve_app_identity_for_pid(effective_pid, Some(hwnd.0 as isize))?
    };
    let process_start_time = process_start_time_for_pid(effective_pid)?;
    Some((
        raw_pid,
        ApplicationIdentity {
            application_id: resolved.application_id.clone(),
            process_id: effective_pid,
            process_start_time,
        },
        resolved,
    ))
}

/// Resolve raw window PID, effective UWP/Win32 PID, and canonical `ApplicationIdentity` for an HWND.
pub fn resolve_application_for_hwnd(
    hwnd: HWND,
    app_id_override: Option<&str>,
) -> Option<(u32, ApplicationIdentity)> {
    resolve_application_identity_for_hwnd(hwnd, app_id_override, None)
        .map(|(raw_pid, app, _)| (raw_pid, app))
}

/// Resolve the live foreground HWND, effective PID, and `ApplicationIdentity`.
pub fn resolve_foreground_application() -> Option<(HWND, ApplicationIdentity)> {
    // SAFETY: Standard Win32 foreground window lookup.
    let hwnd = unsafe { GetForegroundWindow() };
    let (_, app) = resolve_application_for_hwnd(hwnd, None)?;
    Some((hwnd, app))
}

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
}

pub(super) fn is_allowed_process_id(process_id: u32, verified: &VerifiedTarget) -> bool {
    process_id == 0 || process_id == verified.app.process_id || process_id == verified.raw_pid
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
    if BrowserGate::should_block_private_windows_identity(&resolved, spec.block_private_windows) {
        if let Some(title) = read_window_title_ephemeral(hwnd) {
            if BrowserGate::is_private_window_title(&title) {
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
            Ok(PrivateChromeVerdict::VerifiedNormal) => {}
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
    let private_state = if BrowserGate::is_known_browser_identity(&resolved) {
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
    })
}

pub(super) fn reverify_window_boundary(
    uia: &UiaClient,
    target: ReadTarget<'_>,
    verified: &VerifiedTarget,
    ticket: &ReadTicket,
    clock: &dyn CollectorClock,
) -> Result<(), (GapDiagnosticCode, Option<SurfaceReadFailure>)> {
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

    if BrowserGate::should_block_private_windows_identity(
        &current_resolved,
        verified.spec.block_private_windows,
    ) {
        if let Some(title) = read_window_title_ephemeral(verified.hwnd) {
            if BrowserGate::is_private_window_title(&title) {
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
    }

    Ok(())
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
