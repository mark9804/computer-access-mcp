//! Phase 3 Windows UI Automation Core Capture Engine.
//!
//! Runs exclusively inside the isolated out-of-process `--ax-worker` child process (one-shot or
//! `--session-worker yes`). Enforces all Non-Negotiable Invariant #2 privacy gates before and
//! after every UIA read, normalizes DPI via Per-Monitor V2, reads focused text (`uia.text` /
//! `uia.value`) + selection (`uia.text`) + bounded weighted surface trees (`uia.tree`) with
//! `SurfaceNodeMap` + `SurfaceBaseline` full/diff snapshots, and listens for WinEvent dirty
//! notifications on a clean background message-pump thread.

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};

use access_contract::utf16_len;
use windows::Win32::Foundation::HWND;
use windows::Win32::UI::Accessibility::IUIAutomationElement;
use windows::Win32::UI::WindowsAndMessaging::{
    GetAncestor, GetForegroundWindow, GetWindowTextLengthW, GetWindowTextW,
    GetWindowThreadProcessId, GA_ROOT,
};

use crate::adapters::{AdapterRegistry, AppAdapterSpec, SafeDisplayText, StaticTextPolicy};
use crate::adapters_custom::{
    matches_wechat_id, validate_custom_result, BackendAllowedNode, BackendCallBudget,
    BackendChildrenPage, BackendInspection, BackendTailChildrenRead, BackendTextRead,
    KernelSurfaceContext, SurfaceBackend, SurfaceHandle,
};
use crate::desktop::assess_windows_desktop;
use crate::ownership::process_start_time_for_pid;
use crate::policy::{
    is_effectively_empty_text, is_native_richedit_class, is_private_use_only_text,
    normalize_gap_role, resolve_app_identity_for_pid, resolve_effective_pid_checked,
    ApplicationPolicy, BrowserGate, IdentityPolicyOutcome, PhaseBudget, ReadBudget,
    ResolvedAppIdentity, SubroleRead, TextSecurityGate,
};
use crate::protocol_model::{
    bounded_utf16_slice, generate_uuid_v4, ApplicationIdentity, AxEnablementResult, CapturePolicy,
    CollectorClock, DesktopStatus, GapDiagnostic, GapDiagnosticCode, SecureStatus,
    SelectionReadResult, SurfaceAbsoluteRect, SurfaceBaseline, SurfaceBounds, SurfaceGeometry,
    SurfaceNode, SurfaceReadFailure, SurfaceReadResult, TextRead, WorkerSurfaceIdentity,
};
use crate::uia_com::{
    ensure_per_monitor_dpi_aware, warmup_window_uia, window_rect_logical, ComGuard,
    PrivateChromeVerdict, UiaCallError, UiaClient, UiaElementMetadata, WarmedHwndCache,
    WinEventWatcher,
};
use crate::uia_traversal::{
    PendingSurfaceCapture, RuntimeIdKey, SurfaceFocusAnchors, SurfaceNodeMap,
    WeightedSurfaceChildrenRead, WeightedSurfaceInspection, WeightedSurfaceMetadata,
    WeightedSurfaceTextRead, WeightedSurfaceTraversal, WeightedSurfaceTraversalLimits,
    WeightedSurfaceTraversalReason,
};
use crate::worker_ipc::{ReadResult, ReadTicket, WorkerProgressClient};

const MAX_CHILDREN_PER_CONTAINER: usize = 128;
const MAX_HEAD_CHILDREN_PER_CONTAINER: usize = 64;
const MAX_TAIL_CHILDREN_PER_CONTAINER: usize = 64;
const MAX_SURFACE_INTERNED_ELEMENTS: usize = 576;

fn read_window_title_ephemeral(hwnd: HWND) -> Option<String> {
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
enum ReadTarget<'a> {
    LiveForeground,
    ExplicitWindow {
        window_hwnd: HWND,
        focused_hwnd: Option<HWND>,
        app_id_override: Option<&'a str>,
        resolved_override: Option<&'a ResolvedAppIdentity>,
        desktop_override: Option<DesktopStatus>,
    },
}

fn check_desktop_status(target: ReadTarget<'_>) -> DesktopStatus {
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

struct VerifiedTarget {
    hwnd: HWND,
    raw_pid: u32,
    app: ApplicationIdentity,
    resolved: ResolvedAppIdentity,
    spec: &'static AppAdapterSpec,
    initial_logical_rect: Option<SurfaceAbsoluteRect>,
    dpi: u32,
    private_state: &'static str,
}

fn is_allowed_process_id(process_id: u32, verified: &VerifiedTarget) -> bool {
    process_id == 0 || process_id == verified.app.process_id || process_id == verified.raw_pid
}

fn classify_element_security(
    meta: &UiaElementMetadata,
    policy: &CapturePolicy,
) -> SecureStatus {
    classify_element_security_with_role(meta, meta.mapped.ax_role, policy)
}

fn classify_element_security_with_role(
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
fn verify_target_pre_read(
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

fn reverify_window_boundary(
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

fn reverify_focused_element(
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

fn element_belongs_to_window(
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

fn read_focused_text(
    uia: &UiaClient,
    focused_elem: &IUIAutomationElement,
    focused_meta: &UiaElementMetadata,
    ticket: &ReadTicket,
    clock: &dyn CollectorClock,
) -> Result<TextRead, GapDiagnosticCode> {
    let budget = ticket.policy.max_text_code_units.clamp(1, 8_192);
    let visible = ticket.policy.text_range.as_deref() == Some("visible");
    let deadline = ticket.deadline_monotonic_ms;
    let mut before_ipc = || -> Option<i64> {
        let rem = deadline.saturating_sub(clock.monotonic_ms());
        (rem > 0).then_some(rem)
    };

    if visible {
        let pat = uia
            .get_text_pattern_budgeted(focused_elem, true, true, &mut before_ipc)
            .map_err(|_| GapDiagnosticCode::VisibleRangeUnavailable)?
            .ok_or(GapDiagnosticCode::VisibleRangeUnavailable)?;
        let vis = uia
            .read_text_pattern_visible_budgeted(
                &pat,
                budget,
                || clock.monotonic_ms() + 30 < deadline,
                &mut before_ipc,
            )
            .ok_or(GapDiagnosticCode::VisibleRangeUnavailable)?;
        return Ok(TextRead {
            text: vis.text,
            source: "uia.text".to_string(),
            total_length: Some(vis.total_length),
            selection: vis.selection,
            range_start: vis.range_start,
            range_basis: "visible".to_string(),
            complete: false,
            truncated: vis.truncated,
            missing_reasons: vis.missing_reasons,
            read_units: None,
        });
    }

    // Primary: IUIAutomationTextPattern / TextPattern2 (prefix mode).
    match uia.get_text_pattern_budgeted(focused_elem, true, true, &mut before_ipc) {
        Ok(Some(pat)) => {
            if let Some(pref) = uia.read_text_pattern_prefix_budgeted(
                &pat,
                budget,
                || clock.monotonic_ms() + 30 < deadline,
                &mut before_ipc,
            ) {
                return Ok(TextRead {
                    text: pref.text,
                    source: "uia.text".to_string(),
                    total_length: pref.total_length,
                    selection: pref.selection,
                    range_start: 0,
                    range_basis: "prefix".to_string(),
                    complete: pref.complete,
                    truncated: pref.truncated,
                    missing_reasons: pref.missing_reasons,
                    read_units: None,
                });
            }
        }
        Err(UiaCallError::AccessDenied) => return Err(GapDiagnosticCode::TextReadUnavailable),
        Ok(None) | Err(UiaCallError::Unavailable) => {}
    }

    if clock.monotonic_ms() >= deadline {
        return Err(GapDiagnosticCode::ReadDeadline);
    }

    // Fallback: IUIAutomationValuePattern (prefix mode ONLY).
    match uia.get_value_pattern_budgeted(focused_elem, &mut before_ipc) {
        Ok(Some(val_pat)) => {
            if let Some(pref) =
                uia.read_value_pattern_prefix_budgeted(&val_pat, budget, &mut before_ipc)
            {
                return Ok(TextRead {
                    text: pref.text,
                    source: "uia.value".to_string(),
                    total_length: pref.total_length,
                    selection: None,
                    range_start: 0,
                    range_basis: "prefix".to_string(),
                    complete: pref.complete,
                    truncated: pref.truncated,
                    missing_reasons: pref.missing_reasons,
                    read_units: None,
                });
            }
        }
        Err(UiaCallError::AccessDenied) => return Err(GapDiagnosticCode::TextReadUnavailable),
        Ok(None) | Err(UiaCallError::Unavailable) => {}
    }

    // Static text fallback: Win32 STATIC / UIA Text controls expose label text via cached Name.
    if focused_meta.mapped.ax_role == Some("AXStaticText") {
        if let Some(ref name) = focused_meta.name {
            let total = utf16_len(name);
            let (text, complete, truncated, missing_reasons) = if total <= budget {
                (name.clone(), true, false, Vec::new())
            } else {
                let sliced = bounded_utf16_slice(name, 0, budget)
                    .ok_or(GapDiagnosticCode::TextResultInvalid)?;
                (sliced, false, true, vec!["text-budget".to_string()])
            };
            return Ok(TextRead {
                text,
                source: "uia.value".to_string(),
                total_length: Some(total),
                selection: None,
                range_start: 0,
                range_basis: "prefix".to_string(),
                complete,
                truncated,
                missing_reasons,
                read_units: None,
            });
        }
    }

    Err(GapDiagnosticCode::TextReadUnavailable)
}

struct InternedElement {
    element: IUIAutomationElement,
    runtime_id: RuntimeIdKey,
    meta: UiaElementMetadata,
    children_probed: bool,
    children_loaded: bool,
    children: Vec<usize>,
    last_probed_child: Option<IUIAutomationElement>,
    children_truncated: bool,
    /// Post-security-gate cached URL for `AXWebArea` / `AXLink` (`None` = not fetched yet).
    cached_url: Option<Option<String>>,
}

struct SurfaceCaptureStore {
    items: Vec<InternedElement>,
    by_runtime_id: HashMap<RuntimeIdKey, usize>,
}

impl SurfaceCaptureStore {
    fn new() -> Self {
        Self {
            items: Vec::with_capacity(64),
            by_runtime_id: HashMap::with_capacity(64),
        }
    }

    fn intern(
        &mut self,
        element: IUIAutomationElement,
        mut meta: UiaElementMetadata,
    ) -> Option<usize> {
        if meta.runtime_id.is_empty() {
            // Synthesize deterministic local key only if provider omitted RuntimeId.
            let synthetic = vec![-1, self.items.len() as i32];
            meta.runtime_id = RuntimeIdKey(synthetic);
        }
        if let Some(&idx) = self.by_runtime_id.get(&meta.runtime_id) {
            return Some(idx);
        }
        if self.items.len() >= MAX_SURFACE_INTERNED_ELEMENTS {
            return None;
        }
        let idx = self.items.len();
        let rid = meta.runtime_id.clone();
        self.items.push(InternedElement {
            element,
            runtime_id: rid.clone(),
            meta,
            children_probed: false,
            children_loaded: false,
            children: Vec::new(),
            last_probed_child: None,
            children_truncated: false,
            cached_url: None,
        });
        self.by_runtime_id.insert(rid, idx);
        Some(idx)
    }
}

/// Strictly validate and sanitize a candidate display URL (`http://` or `https://` ONLY):
/// - Rejects empty / whitespace / invisible-only strings (including `U+200B`, `U+FEFF`, etc.)
///   and any control characters (`\r`, `\n`, `\0`, `\t`, etc.).
/// - Requires an explicit `http://` or `https://` scheme (case-insensitive), rejecting
///   `javascript:`, `data:`, `file://`, `blob:`, `about:`, and arbitrary non-URL text.
/// - Strips any `userinfo` (`user:pass@` or `user@`) strictly from the authority component
///   (between `scheme://` and the first `/`, `?`, `#`, or `\`) using the last `@` in the
///   authority so `@` in path/query/fragment (e.g. `?email=a@b`) is preserved.
/// - Rejects empty or malformed hosts after stripping `userinfo`.
pub fn sanitize_display_url(raw: &str) -> Option<String> {
    if is_effectively_empty_text(raw) || raw.chars().any(char::is_control) {
        return None;
    }
    let trimmed = SafeDisplayText::clean(Some(raw))?;
    let scheme_len =
        if trimmed.len() >= 8 && trimmed.as_bytes()[..8].eq_ignore_ascii_case(b"https://") {
            8
        } else if trimmed.len() >= 7 && trimmed.as_bytes()[..7].eq_ignore_ascii_case(b"http://") {
            7
        } else {
            return None;
        };
    let scheme = &trimmed[..scheme_len];
    let rest = &trimmed[scheme_len..];
    let auth_end = rest.find(['/', '?', '#', '\\']).unwrap_or(rest.len());
    let authority = &rest[..auth_end];
    let suffix = &rest[auth_end..];
    let host_port = match authority.rfind('@') {
        Some(at_idx) => &authority[at_idx + 1..],
        None => authority,
    };
    if host_port.is_empty()
        || is_effectively_empty_text(host_port)
        || is_private_use_only_text(host_port)
        || host_port.chars().any(|c| {
            c.is_whitespace()
                || matches!(
                    c,
                    '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' | '\u{00AD}'
                )
        })
    {
        return None;
    }
    if host_port.starts_with('[') {
        let close = host_port.find(']')?;
        if close <= 1 {
            return None;
        }
        let after = &host_port[close + 1..];
        if !after.is_empty() {
            let port = after.strip_prefix(':')?;
            if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
        }
    } else if let Some((host, port)) = host_port.split_once(':') {
        if host.is_empty() || port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
    }
    Some(format!("{scheme}{host_port}{suffix}"))
}

/// Post-security-gate bounded `ValuePattern` URL reader strictly restricted to non-sensitive
/// `AXWebArea` and `AXLink` elements (e.g. Figma `/design/...`, `/slides/...` and Slack URLs).
///
/// Runs all security, `may_traverse`, and role gates BEFORE inspecting `cached_url`, meters and
/// timeout-refreshes every COM IPC individually, sanitizes the URL (`http://`/`https://` only,
/// `userinfo` stripped), and propagates `UiaCallError::AccessDenied` without swallowing.
fn read_safe_display_url_post_gate(
    uia: &UiaClient,
    store: &mut SurfaceCaptureStore,
    idx: usize,
    spec: &AppAdapterSpec,
    active_deadline_ms: i64,
    clock: &dyn CollectorClock,
    mut consume_call: impl FnMut() -> bool,
) -> Result<Option<String>, UiaCallError> {
    let Some(item) = store.items.get(idx) else {
        return Ok(None);
    };
    let ax_role = item.meta.mapped.ax_role;
    if !matches!(ax_role, Some("AXWebArea" | "AXLink"))
        || !item.meta.supports_value_pattern
        || item.meta.is_sensitive()
        || !TextSecurityGate::may_traverse(&item.meta.subrole_read, item.meta.is_password)
    {
        store.items[idx].cached_url = Some(None);
        return Ok(None);
    }
    if let Some(ref cached) = item.cached_url {
        return Ok(cached.clone());
    }

    let elem = store.items[idx].element.clone();
    let cap = spec.max_node_text_units.clamp(1, 512);
    let raw_read_cap = cap.clamp(1024, 8_192);
    let mut ipc_aborted = false;
    let mut before_ipc = || -> Option<i64> {
        let rem = active_deadline_ms.saturating_sub(clock.monotonic_ms());
        if rem <= 0 || !consume_call() {
            ipc_aborted = true;
            return None;
        }
        Some(rem)
    };

    let Some(vpat) = uia.get_value_pattern_budgeted(&elem, &mut before_ipc)? else {
        if !ipc_aborted {
            store.items[idx].cached_url = Some(None);
        }
        return Ok(None);
    };
    let pref_opt = match uia.read_value_pattern_prefix_budgeted_checked(
        &vpat,
        raw_read_cap,
        &mut before_ipc,
    ) {
        Ok(opt) => opt,
        Err(UiaCallError::AccessDenied) => return Err(UiaCallError::AccessDenied),
        Err(UiaCallError::Unavailable) => return Ok(None),
    };
    let Some(pref) = pref_opt else {
        if !ipc_aborted {
            store.items[idx].cached_url = Some(None);
        }
        return Ok(None);
    };
    let url = sanitize_display_url(&pref.text).and_then(|clean| {
        if utf16_len(&clean) <= cap {
            Some(clean)
        } else {
            bounded_utf16_slice(&clean, 0, cap).filter(|s| !s.is_empty())
        }
    });
    store.items[idx].cached_url = Some(url.clone());
    Ok(url)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum UiaNodeTextOutcome {
    Text {
        value: String,
        truncated: bool,
        reasons: Vec<String>,
        /// True when text is unfocused pure-PUA static text kept solely so `WeightedSurfaceTraversal`
        /// drops the leaf cleanly without charging `ProviderRefused` or text budget.
        is_unfocused_pua_static: bool,
    },
    Unavailable,
}

fn effective_static_text_cap(node_cap: usize, static_text_probe: StaticTextPolicy) -> usize {
    match static_text_probe {
        StaticTextPolicy::Standard => node_cap,
        StaticTextPolicy::BoundedRangeProbe { max_units } => node_cap.min(max_units),
    }
}

fn slice_node_text_bounded(raw: &str, cap: usize) -> UiaNodeTextOutcome {
    let units = utf16_len(raw);
    let (sliced, trunc) = if units <= cap {
        (raw.to_string(), false)
    } else if let Some(s) = bounded_utf16_slice(raw, 0, cap) {
        (s, true)
    } else {
        return UiaNodeTextOutcome::Unavailable;
    };
    UiaNodeTextOutcome::Text {
        value: sliced,
        truncated: trunc,
        reasons: if trunc {
            vec!["text-budget".to_string()]
        } else {
            Vec::new()
        },
        is_unfocused_pua_static: false,
    }
}

/// 0-IPC fast path for `AXStaticText` reading pre-cached `meta.name` / `meta.safe_description()`,
/// strictly clamping to `effective_static_text_cap(node_cap, static_text_probe)` so
/// `StaticTextPolicy::BoundedRangeProbe { max_units }` is honored even without pattern IPCs.
/// Returns `None` only when cached fields are absent/empty and pattern fallback may proceed.
fn read_cached_static_text_bounded(
    meta: &UiaElementMetadata,
    node_cap: usize,
    static_text_probe: StaticTextPolicy,
    is_focused: bool,
) -> Option<UiaNodeTextOutcome> {
    let effective_cap = effective_static_text_cap(node_cap, static_text_probe);
    if effective_cap == 0 || meta.is_sensitive() {
        return Some(UiaNodeTextOutcome::Unavailable);
    }

    if let Some(ref name) = meta.name {
        if !is_effectively_empty_text(name) {
            if !is_focused && is_private_use_only_text(name) {
                if let Some(desc) = meta.safe_description() {
                    if !is_effectively_empty_text(desc) && !is_private_use_only_text(desc) {
                        return Some(slice_node_text_bounded(desc, effective_cap));
                    }
                }
                return Some(UiaNodeTextOutcome::Text {
                    value: name.clone(),
                    truncated: false,
                    reasons: Vec::new(),
                    is_unfocused_pua_static: true,
                });
            }
            return Some(slice_node_text_bounded(name, effective_cap));
        }
    }

    if let Some(desc) = meta.safe_description() {
        if !is_effectively_empty_text(desc) && (is_focused || !is_private_use_only_text(desc)) {
            return Some(slice_node_text_bounded(desc, effective_cap));
        }
    }

    None
}

/// Shared post-security-gate bounded node text reader used by BOTH `LiveUiaSurfaceBackend` and
/// `WeightedSurfaceTraversal`:
/// - For `AXStaticText`, reads pre-cached `meta.name` FIRST (0 extra COM IPCs, skipping unfocused
///   PUA-only text), falling back to `meta.safe_description()`, and ONLY querying `TextPattern` /
///   `ValuePattern` when `name` is empty AND cached pattern availability flags are true (honoring
///   `StaticTextPolicy::BoundedRangeProbe { max_units }` on BOTH the 0-IPC fast path and pattern
///   fallbacks).
/// - For `AXTextField` / `AXTextArea`, gates `TextPattern` / `ValuePattern` on cached availability.
/// - Every COM IPC is individually budgeted and timeout-refreshed via `*_budgeted`.
#[allow(clippy::too_many_arguments)]
fn read_uia_node_text_bounded(
    uia: &UiaClient,
    elem: &IUIAutomationElement,
    meta: &UiaElementMetadata,
    expected_role: &str,
    node_cap: usize,
    static_text_probe: StaticTextPolicy,
    is_focused: bool,
    already_read_focus_text: Option<&str>,
    active_deadline_ms: i64,
    clock: &dyn CollectorClock,
    mut consume_call: impl FnMut() -> bool,
) -> UiaNodeTextOutcome {
    let effective_cap = if expected_role == "AXStaticText" {
        effective_static_text_cap(node_cap, static_text_probe)
    } else {
        node_cap
    };
    if effective_cap == 0 || meta.is_sensitive() {
        return UiaNodeTextOutcome::Unavailable;
    }

    if is_focused {
        if let Some(ft) = already_read_focus_text {
            return slice_node_text_bounded(ft, effective_cap);
        }
    }

    let mut before_ipc = || -> Option<i64> {
        let rem = active_deadline_ms.saturating_sub(clock.monotonic_ms());
        if rem <= 0 || !consume_call() {
            return None;
        }
        Some(rem)
    };

    if expected_role == "AXStaticText" {
        if let Some(outcome) =
            read_cached_static_text_bounded(meta, node_cap, static_text_probe, is_focused)
        {
            return outcome;
        }

        if meta.supports_text_pattern || meta.supports_text_pattern2 {
            match uia.get_text_pattern_budgeted(
                elem,
                meta.supports_text_pattern,
                meta.supports_text_pattern2,
                &mut before_ipc,
            ) {
                Ok(Some(pat)) => {
                    if let Some(pref) = uia.read_text_pattern_prefix_budgeted(
                        &pat,
                        effective_cap,
                        || false,
                        &mut before_ipc,
                    ) {
                        return UiaNodeTextOutcome::Text {
                            value: pref.text,
                            truncated: pref.truncated,
                            reasons: pref.missing_reasons,
                            is_unfocused_pua_static: false,
                        };
                    }
                }
                Err(UiaCallError::AccessDenied) => return UiaNodeTextOutcome::Unavailable,
                Ok(None) | Err(UiaCallError::Unavailable) => {}
            }
        }

        if meta.supports_value_pattern {
            if let Ok(Some(vpat)) = uia.get_value_pattern_budgeted(elem, &mut before_ipc) {
                if let Some(pref) =
                    uia.read_value_pattern_prefix_budgeted(&vpat, effective_cap, &mut before_ipc)
                {
                    return UiaNodeTextOutcome::Text {
                        value: pref.text,
                        truncated: pref.truncated,
                        reasons: pref.missing_reasons,
                        is_unfocused_pua_static: false,
                    };
                }
            }
        }

        return UiaNodeTextOutcome::Unavailable;
    }

    // Editable controls (`AXTextField` / `AXTextArea`).
    let try_text = meta.supports_text_pattern || meta.supports_text_pattern2;
    let try_value = meta.supports_value_pattern || (!try_text && meta.control_type == 50004);

    if try_text {
        match uia.get_text_pattern_budgeted(
            elem,
            meta.supports_text_pattern,
            meta.supports_text_pattern2,
            &mut before_ipc,
        ) {
            Ok(Some(pat)) => {
                if let Some(pref) = uia.read_text_pattern_prefix_budgeted(
                    &pat,
                    effective_cap,
                    || false,
                    &mut before_ipc,
                ) {
                    return UiaNodeTextOutcome::Text {
                        value: pref.text,
                        truncated: pref.truncated,
                        reasons: pref.missing_reasons,
                        is_unfocused_pua_static: false,
                    };
                }
            }
            Err(UiaCallError::AccessDenied) => return UiaNodeTextOutcome::Unavailable,
            Ok(None) | Err(UiaCallError::Unavailable) => {}
        }
    }

    if try_value {
        if let Ok(Some(vpat)) = uia.get_value_pattern_budgeted(elem, &mut before_ipc) {
            if let Some(pref) =
                uia.read_value_pattern_prefix_budgeted(&vpat, effective_cap, &mut before_ipc)
            {
                return UiaNodeTextOutcome::Text {
                    value: pref.text,
                    truncated: pref.truncated,
                    reasons: pref.missing_reasons,
                    is_unfocused_pua_static: false,
                };
            }
        }
    }

    UiaNodeTextOutcome::Unavailable
}

struct LiveUiaSurfaceBackend<'a> {
    uia: &'a UiaClient,
    target: ReadTarget<'a>,
    verified: &'a VerifiedTarget,
    policy: &'a CapturePolicy,
    clock: &'a dyn CollectorClock,
    capture_start_ms: i64,
    exploration_deadline_ms: i64,
    is_terminal: bool,
    focus_handle: Option<usize>,
    focused_runtime_id: Option<&'a RuntimeIdKey>,
    already_read_focus_text: Option<&'a str>,
    store: &'a mut SurfaceCaptureStore,
    saw_provider_refused: bool,
    saw_children_truncated: bool,
}

impl<'a> LiveUiaSurfaceBackend<'a> {
    fn build_allowed_node(
        &mut self,
        index: usize,
        is_root: bool,
        calls: &mut BackendCallBudget,
    ) -> BackendInspection {
        if index >= self.store.items.len() {
            return BackendInspection::Pruned(WeightedSurfaceTraversalReason::ProviderRefused);
        }
        let (meta, runtime_id, children_probed, parent_elem) = {
            let item = &self.store.items[index];
            (
                item.meta.clone(),
                item.runtime_id.clone(),
                item.children_probed,
                item.element.clone(),
            )
        };
        let is_focused = Some(index) == self.focus_handle
            || self
                .focused_runtime_id
                .is_some_and(|rid| !rid.is_empty() && runtime_id == *rid);
        let has_sensitive_focus = is_focused || meta.has_keyboard_focus == Some(true);

        if meta.is_sensitive() {
            if is_root || has_sensitive_focus {
                return BackendInspection::Fatal(SurfaceReadFailure::SecurityExcluded);
            }
            return BackendInspection::Pruned(WeightedSurfaceTraversalReason::SecurityPruned);
        }
        if !TextSecurityGate::may_traverse(&meta.subrole_read, meta.is_password) {
            if is_root {
                return BackendInspection::Fatal(SurfaceReadFailure::BoundaryUnverified);
            }
            return BackendInspection::Pruned(WeightedSurfaceTraversalReason::SecurityPruned);
        }
        if !is_allowed_process_id(meta.process_id, self.verified) {
            return BackendInspection::Pruned(WeightedSurfaceTraversalReason::ProviderRefused);
        }

        let subrole_str = match &meta.subrole_read {
            SubroleRead::Value(s) => Some(s.as_str()),
            _ => None,
        };
        if !is_root
            && !is_focused
            && (meta
                .mapped
                .ax_role
                .is_some_and(|r| self.verified.spec.ignores_role(r))
                || subrole_str.is_some_and(|s| self.verified.spec.ignores_subrole(s)))
        {
            return BackendInspection::Pruned(WeightedSurfaceTraversalReason::UnsupportedRole);
        }

        let reads_text = meta
            .mapped
            .ax_role
            .and_then(WeightedSurfaceTraversal::role_policy)
            .is_some_and(|p| p.reads_text());
        let needs_document_child_probe = meta.control_type == 50030
            && meta.mapped.ax_role != Some("AXWebArea")
            && !is_native_richedit_class(meta.class_name.as_deref());
        let is_wechat_title_wrapper =
            matches_wechat_id(meta.automation_id.as_deref(), "big_title_line_h_view");

        if (!reads_text || needs_document_child_probe || is_wechat_title_wrapper)
            && !children_probed
        {
            let mut child_handles = Vec::new();
            let mut last_probed: Option<IUIAutomationElement> = None;
            let mut loaded_all = false;
            let mut truncated_children = false;
            let mut has_any_child = false;

            let rem = self
                .exploration_deadline_ms
                .saturating_sub(self.clock.monotonic_ms());
            if rem > 0 && calls.try_consume(1) {
                self.uia.apply_timeouts(rem);
                match self.uia.first_child_element(&parent_elem) {
                    Ok(Some(first_el)) => {
                        has_any_child = true;
                        match self.uia.read_cached_metadata(
                            &first_el,
                            self.verified.dpi,
                            false,
                            self.is_terminal,
                        ) {
                            Ok(cmeta) => {
                                if is_allowed_process_id(cmeta.process_id, self.verified) {
                                    if let Some(ch_idx) = self.store.intern(first_el.clone(), cmeta)
                                    {
                                        child_handles.push(ch_idx);
                                    } else {
                                        truncated_children = true;
                                    }
                                }
                            }
                            Err(UiaCallError::AccessDenied) => {
                                if is_root || is_focused {
                                    return BackendInspection::Fatal(
                                        SurfaceReadFailure::ProviderUnavailable,
                                    );
                                }
                                self.saw_provider_refused = true;
                                truncated_children = true;
                            }
                            Err(UiaCallError::Unavailable) => {
                                self.saw_provider_refused = true;
                                truncated_children = true;
                            }
                        }
                        let rem2 = self
                            .exploration_deadline_ms
                            .saturating_sub(self.clock.monotonic_ms());
                        if rem2 > 0 && calls.try_consume(1) {
                            self.uia.apply_timeouts(rem2);
                            match self.uia.next_sibling_element(&first_el) {
                                Ok(Some(second_el)) => {
                                    match self.uia.read_cached_metadata(
                                        &second_el,
                                        self.verified.dpi,
                                        false,
                                        self.is_terminal,
                                    ) {
                                        Ok(cmeta) => {
                                            if is_allowed_process_id(
                                                cmeta.process_id,
                                                self.verified,
                                            ) {
                                                if let Some(ch_idx) =
                                                    self.store.intern(second_el.clone(), cmeta)
                                                {
                                                    if !child_handles.contains(&ch_idx) {
                                                        child_handles.push(ch_idx);
                                                    }
                                                } else {
                                                    truncated_children = true;
                                                }
                                            }
                                        }
                                        Err(UiaCallError::AccessDenied) => {
                                            if is_root || is_focused {
                                                return BackendInspection::Fatal(
                                                    SurfaceReadFailure::ProviderUnavailable,
                                                );
                                            }
                                            self.saw_provider_refused = true;
                                            truncated_children = true;
                                        }
                                        Err(UiaCallError::Unavailable) => {
                                            self.saw_provider_refused = true;
                                            truncated_children = true;
                                        }
                                    }
                                    last_probed = Some(second_el);
                                }
                                Ok(None) => {
                                    loaded_all = !truncated_children;
                                }
                                Err(UiaCallError::AccessDenied) => {
                                    if is_root || is_focused {
                                        return BackendInspection::Fatal(
                                            SurfaceReadFailure::ProviderUnavailable,
                                        );
                                    }
                                    self.saw_provider_refused = true;
                                    last_probed = Some(first_el);
                                    truncated_children = true;
                                }
                                Err(UiaCallError::Unavailable) => {
                                    self.saw_provider_refused = true;
                                    last_probed = Some(first_el);
                                    truncated_children = true;
                                }
                            }
                        } else {
                            last_probed = Some(first_el);
                            truncated_children = true;
                        }
                    }
                    Ok(None) => {
                        loaded_all = true;
                    }
                    Err(UiaCallError::AccessDenied) => {
                        if is_root || is_focused {
                            return BackendInspection::Fatal(
                                SurfaceReadFailure::ProviderUnavailable,
                            );
                        }
                        self.saw_provider_refused = true;
                        truncated_children = true;
                    }
                    Err(UiaCallError::Unavailable) => {
                        self.saw_provider_refused = true;
                        truncated_children = true;
                    }
                }
            } else {
                truncated_children = true;
            }

            if has_any_child
                && self.store.items[index].meta.control_type == 50030
                && !is_native_richedit_class(self.store.items[index].meta.class_name.as_deref())
            {
                let m = &self.store.items[index].meta;
                let updated = crate::policy::map_uia_control_type_to_ax(
                    50030,
                    false,
                    m.supports_text_pattern || m.supports_text_pattern2,
                    m.is_read_only,
                    true,
                    true,
                    false,
                    m.supports_scroll_pattern,
                    self.is_terminal,
                );
                self.store.items[index].meta.mapped = updated;
                self.store.items[index].cached_url = None;
            }
            if truncated_children {
                self.saw_children_truncated = true;
            }
            self.store.items[index].children = child_handles;
            self.store.items[index].last_probed_child = last_probed;
            self.store.items[index].children_probed = true;
            self.store.items[index].children_loaded = loaded_all && !truncated_children;
            self.store.items[index].children_truncated |= truncated_children;
        }

        let effective_meta = self.store.items[index].meta.clone();
        let Some(ax_role) = effective_meta.mapped.ax_role else {
            return BackendInspection::Pruned(WeightedSurfaceTraversalReason::UnsupportedRole);
        };

        let effective_reads_text = WeightedSurfaceTraversal::role_policy(ax_role)
            .is_some_and(|p| p.reads_text());
        let child_count = if effective_reads_text && !is_wechat_title_wrapper {
            0
        } else {
            self.store.items[index].children.len()
        };

        let url = match read_safe_display_url_post_gate(
            self.uia,
            self.store,
            index,
            self.verified.spec,
            self.exploration_deadline_ms,
            self.clock,
            || self.clock.monotonic_ms() < self.exploration_deadline_ms && calls.try_consume(1),
        ) {
            Ok(u) => u,
            Err(UiaCallError::AccessDenied) => {
                if is_root {
                    return BackendInspection::Fatal(SurfaceReadFailure::ProviderUnavailable);
                }
                self.saw_provider_refused = true;
                return BackendInspection::Pruned(WeightedSurfaceTraversalReason::ProviderRefused);
            }
            Err(UiaCallError::Unavailable) => None,
        };

        let display_text = SafeDisplayText::compose(
            ax_role,
            effective_meta.name.as_deref(),
            effective_meta.safe_description(),
            url.as_deref(),
            self.verified.spec.max_node_text_units,
        );
        let label = effective_meta
            .name
            .clone()
            .or_else(|| effective_meta.safe_description().map(str::to_string));

        let obs_ms = self.clock.unix_ms().max(self.capture_start_ms);
        let strict_security = Some(classify_element_security(&effective_meta, self.policy));

        BackendInspection::Allowed(Box::new(BackendAllowedNode {
            role: ax_role.to_string(),
            category: effective_meta.mapped.category,
            subrole: effective_meta.subrole_read.clone(),
            protected_content: effective_meta.is_password,
            child_count,
            is_focused,
            observed_at_ms: obs_ms,
            is_enabled: effective_meta.is_enabled,
            display_text,
            window_title: is_root
                .then(|| read_window_title_ephemeral(self.verified.hwnd))
                .flatten(),
            absolute_rect: effective_meta.logical_rect,
            identifier: effective_meta.automation_id.clone(),
            class_name: effective_meta.class_name.clone(),
            label,
            is_offscreen: effective_meta.is_offscreen == Some(true),
            strict_security,
        }))
    }
}

impl SurfaceBackend for LiveUiaSurfaceBackend<'_> {
    fn verify_desktop_and_application(&mut self) -> Option<SurfaceReadFailure> {
        if check_desktop_status(self.target) != DesktopStatus::Unlocked {
            return Some(SurfaceReadFailure::SecurityExcluded);
        }
        if !self.policy.enabled
            || !ApplicationPolicy::allows_identity(self.policy, &self.verified.resolved)
            || !BrowserGate::allows_identity(&self.verified.resolved, self.policy, false)
        {
            return Some(SurfaceReadFailure::SecurityExcluded);
        }
        None
    }

    fn inspect_backend_node(
        &mut self,
        index: usize,
        is_root: bool,
        calls: &mut BackendCallBudget,
    ) -> BackendInspection {
        self.build_allowed_node(index, is_root, calls)
    }

    fn refresh_backend_node(
        &mut self,
        index: usize,
        is_root: bool,
        calls: &mut BackendCallBudget,
    ) -> BackendInspection {
        let Some(item) = self.store.items.get(index) else {
            return BackendInspection::Pruned(WeightedSurfaceTraversalReason::ProviderRefused);
        };
        let elem = item.element.clone();
        let has_children_hint = !item.children.is_empty();
        let was_focused = Some(index) == self.focus_handle
            || self
                .focused_runtime_id
                .is_some_and(|rid| !rid.is_empty() && item.runtime_id == *rid);
        let rem = self
            .exploration_deadline_ms
            .saturating_sub(self.clock.monotonic_ms());
        if rem <= 0 {
            return BackendInspection::Pruned(WeightedSurfaceTraversalReason::TimeBudget);
        }
        if !calls.try_consume(1) {
            return BackendInspection::Pruned(WeightedSurfaceTraversalReason::WorkBudget);
        }
        self.uia.apply_timeouts(rem);
        let refreshed = match self.uia.refresh_metadata(&elem) {
            Ok(el) => el,
            Err(_) => {
                if is_root || was_focused {
                    return BackendInspection::Fatal(SurfaceReadFailure::BoundaryAxFailed);
                }
                self.saw_provider_refused = true;
                return BackendInspection::Pruned(WeightedSurfaceTraversalReason::ProviderRefused);
            }
        };
        let fresh_meta = match self.uia.read_cached_metadata(
            &refreshed,
            self.verified.dpi,
            has_children_hint,
            self.is_terminal,
        ) {
            Ok(m) => m,
            Err(_) => {
                if is_root || was_focused {
                    return BackendInspection::Fatal(SurfaceReadFailure::BoundaryAxFailed);
                }
                self.saw_provider_refused = true;
                return BackendInspection::Pruned(WeightedSurfaceTraversalReason::ProviderRefused);
            }
        };
        self.store.items[index].meta = fresh_meta;
        self.store.items[index].cached_url = None;
        self.build_allowed_node(index, is_root, calls)
    }

    fn parent_backend_node(
        &mut self,
        index: usize,
        calls: &mut BackendCallBudget,
    ) -> Option<usize> {
        let elem = self.store.items.get(index)?.element.clone();
        let rem = self
            .exploration_deadline_ms
            .saturating_sub(self.clock.monotonic_ms());
        if rem <= 0 || !calls.try_consume(1) {
            return None;
        }
        self.uia.apply_timeouts(rem);
        let parent = match self.uia.parent_element(&elem) {
            Ok(Some(p)) => p,
            Ok(None) | Err(UiaCallError::Unavailable) => return None,
            Err(UiaCallError::AccessDenied) => {
                self.saw_provider_refused = true;
                return None;
            }
        };
        let pmeta = match self
            .uia
            .read_cached_metadata(&parent, self.verified.dpi, true, self.is_terminal)
        {
            Ok(m) => m,
            Err(UiaCallError::Unavailable) => return None,
            Err(UiaCallError::AccessDenied) => {
                self.saw_provider_refused = true;
                return None;
            }
        };
        if pmeta.is_sensitive()
            || !TextSecurityGate::may_traverse(&pmeta.subrole_read, pmeta.is_password)
            || !is_allowed_process_id(pmeta.process_id, self.verified)
        {
            return None;
        }
        self.store.intern(parent, pmeta)
    }

    fn children_backend_page(
        &mut self,
        index: usize,
        expected_role: &str,
        offset: usize,
        limit: usize,
        calls: &mut BackendCallBudget,
    ) -> BackendChildrenPage {
        let Some(item) = self.store.items.get(index) else {
            return BackendChildrenPage::Unavailable(
                WeightedSurfaceTraversalReason::ProviderRefused,
            );
        };
        if item.meta.is_sensitive() || item.meta.mapped.ax_role != Some(expected_role) {
            return BackendChildrenPage::Unavailable(
                WeightedSurfaceTraversalReason::SecurityPruned,
            );
        }
        let target_len = offset.saturating_add(limit).min(MAX_CHILDREN_PER_CONTAINER);
        // Load one extra sibling when below MAX_CHILDREN_PER_CONTAINER so callers learn
        // whether additional siblings remain beyond this page even after a 2-child probe.
        let load_target = target_len
            .saturating_add(1)
            .min(MAX_CHILDREN_PER_CONTAINER);
        let needs_more = !item.children_loaded && item.children.len() < load_target;
        if needs_more {
            let (parent_elem, mut child_handles, last_probed) = {
                let it = &mut self.store.items[index];
                (
                    it.element.clone(),
                    std::mem::take(&mut it.children),
                    it.last_probed_child.take(),
                )
            };
            let mut seen_children: HashSet<usize> = child_handles.iter().copied().collect();
            let mut cur_prev = last_probed;
            let mut loaded_all = false;
            let mut truncated_children = false;
            let mut access_denied = false;

            let max_steps = load_target
                .saturating_sub(child_handles.len())
                .saturating_mul(2)
                .clamp(16, MAX_CHILDREN_PER_CONTAINER);
            let mut steps = 0usize;

            if cur_prev.is_none() && child_handles.is_empty() {
                let rem = self
                    .exploration_deadline_ms
                    .saturating_sub(self.clock.monotonic_ms());
                if rem > 0 && calls.try_consume(1) {
                    self.uia.apply_timeouts(rem);
                    steps += 1;
                    match self.uia.first_child_element(&parent_elem) {
                        Ok(Some(first_el)) => {
                            match self.uia.read_cached_metadata(
                                &first_el,
                                self.verified.dpi,
                                false,
                                self.is_terminal,
                            ) {
                                Ok(cmeta) => {
                                    if is_allowed_process_id(cmeta.process_id, self.verified) {
                                        if let Some(ch_idx) =
                                            self.store.intern(first_el.clone(), cmeta)
                                        {
                                            if seen_children.insert(ch_idx) {
                                                child_handles.push(ch_idx);
                                            }
                                            cur_prev = Some(first_el);
                                        } else {
                                            truncated_children = true;
                                        }
                                    } else {
                                        cur_prev = Some(first_el);
                                    }
                                }
                                Err(UiaCallError::AccessDenied) => {
                                    access_denied = true;
                                    self.saw_provider_refused = true;
                                    truncated_children = true;
                                }
                                Err(UiaCallError::Unavailable) => {
                                    self.saw_provider_refused = true;
                                    truncated_children = true;
                                }
                            }
                        }
                        Ok(None) => {
                            loaded_all = true;
                        }
                        Err(UiaCallError::AccessDenied) => {
                            access_denied = true;
                            self.saw_provider_refused = true;
                            truncated_children = true;
                        }
                        Err(UiaCallError::Unavailable) => {
                            self.saw_provider_refused = true;
                            truncated_children = true;
                        }
                    }
                } else {
                    truncated_children = true;
                }
            }

            while !access_denied && !truncated_children {
                let Some(prev_el) = cur_prev.take() else {
                    break;
                };
                if child_handles.len() >= load_target {
                    cur_prev = Some(prev_el);
                    break;
                }
                if steps >= max_steps {
                    cur_prev = Some(prev_el);
                    truncated_children = true;
                    break;
                }
                let rem = self
                    .exploration_deadline_ms
                    .saturating_sub(self.clock.monotonic_ms());
                if rem <= 0 || !calls.try_consume(1) {
                    cur_prev = Some(prev_el);
                    truncated_children = true;
                    break;
                }
                steps += 1;
                self.uia.apply_timeouts(rem);
                match self.uia.next_sibling_element(&prev_el) {
                    Ok(Some(next_el)) => {
                        match self.uia.read_cached_metadata(
                            &next_el,
                            self.verified.dpi,
                            false,
                            self.is_terminal,
                        ) {
                            Ok(cmeta) => {
                                if is_allowed_process_id(cmeta.process_id, self.verified) {
                                    if let Some(ch_idx) =
                                        self.store.intern(next_el.clone(), cmeta)
                                    {
                                        if seen_children.insert(ch_idx) {
                                            child_handles.push(ch_idx);
                                        } else {
                                            loaded_all = true;
                                            break;
                                        }
                                    } else {
                                        cur_prev = Some(prev_el);
                                        truncated_children = true;
                                        break;
                                    }
                                }
                                cur_prev = Some(next_el);
                            }
                            Err(UiaCallError::AccessDenied) => {
                                access_denied = true;
                                self.saw_provider_refused = true;
                                truncated_children = true;
                                break;
                            }
                            Err(UiaCallError::Unavailable) => {
                                self.saw_provider_refused = true;
                                cur_prev = Some(prev_el);
                                truncated_children = true;
                                break;
                            }
                        }
                    }
                    Ok(None) => {
                        loaded_all = true;
                        break;
                    }
                    Err(UiaCallError::AccessDenied) => {
                        access_denied = true;
                        self.saw_provider_refused = true;
                        truncated_children = true;
                        break;
                    }
                    Err(UiaCallError::Unavailable) => {
                        self.saw_provider_refused = true;
                        cur_prev = Some(prev_el);
                        truncated_children = true;
                        break;
                    }
                }
            }

            if truncated_children {
                self.saw_children_truncated = true;
            }
            let it = &mut self.store.items[index];
            it.children = child_handles;
            it.last_probed_child = cur_prev;
            it.children_probed = true;
            if loaded_all && !access_denied && !truncated_children {
                it.children_loaded = true;
            }
            it.children_truncated |= truncated_children;

            if access_denied {
                return BackendChildrenPage::AccessDenied;
            }
        }

        let it = &self.store.items[index];
        let total = it.children.len();
        if offset >= total {
            return BackendChildrenPage::Values {
                handles: Vec::new(),
                truncated: !it.children_loaded || it.children_truncated,
            };
        }
        let end = offset.saturating_add(limit).min(total);
        let truncated = end < total || !it.children_loaded || it.children_truncated;
        BackendChildrenPage::Values {
            handles: it.children[offset..end].to_vec(),
            truncated,
        }
    }

    fn tail_children_backend(
        &mut self,
        index: usize,
        expected_role: &str,
        limit: usize,
        calls: &mut BackendCallBudget,
    ) -> BackendTailChildrenRead {
        let Some(item) = self.store.items.get(index) else {
            return BackendTailChildrenRead::Unavailable(
                WeightedSurfaceTraversalReason::ProviderRefused,
            );
        };
        if item.meta.is_sensitive() || item.meta.mapped.ax_role != Some(expected_role) {
            return BackendTailChildrenRead::Unavailable(
                WeightedSurfaceTraversalReason::SecurityPruned,
            );
        }
        let capped_limit = limit.min(MAX_TAIL_CHILDREN_PER_CONTAINER);
        if capped_limit == 0 {
            return BackendTailChildrenRead::Values {
                handles: Vec::new(),
                truncated: false,
            };
        }
        let parent_elem = item.element.clone();
        let rem = self
            .exploration_deadline_ms
            .saturating_sub(self.clock.monotonic_ms());
        if rem <= 0 {
            return BackendTailChildrenRead::Unavailable(
                WeightedSurfaceTraversalReason::TimeBudget,
            );
        }
        if !calls.try_consume(1) {
            return BackendTailChildrenRead::Unavailable(
                WeightedSurfaceTraversalReason::WorkBudget,
            );
        }
        self.uia.apply_timeouts(rem);

        let mut tail_handles: Vec<usize> = Vec::with_capacity(capped_limit);
        let mut tail_seen: HashSet<usize> = HashSet::with_capacity(capped_limit);
        let mut truncated = false;

        let mut cur = match self.uia.last_child_element(&parent_elem) {
            Ok(opt) => opt,
            Err(UiaCallError::AccessDenied) => {
                self.saw_provider_refused = true;
                self.saw_children_truncated = true;
                return BackendTailChildrenRead::AccessDenied;
            }
            Err(UiaCallError::Unavailable) => {
                self.saw_provider_refused = true;
                self.saw_children_truncated = true;
                return BackendTailChildrenRead::Unavailable(
                    WeightedSurfaceTraversalReason::ProviderRefused,
                );
            }
        };
        if cur.is_none() {
            // Provider did not expose LastChild; fall back to any head children if present.
            let it = &self.store.items[index];
            let fallback_children = it.children.clone();
            let start = fallback_children.len().saturating_sub(capped_limit);
            return BackendTailChildrenRead::Values {
                handles: fallback_children[start..].to_vec(),
                truncated: start > 0 || !it.children_loaded || it.children_truncated,
            };
        }

        let max_steps = capped_limit
            .saturating_mul(2)
            .clamp(16, MAX_CHILDREN_PER_CONTAINER);
        let mut steps = 0usize;

        while let Some(tail_el) = cur {
            if steps >= max_steps {
                truncated = true;
                self.saw_children_truncated = true;
                break;
            }
            steps += 1;

            match self.uia.read_cached_metadata(
                &tail_el,
                self.verified.dpi,
                false,
                self.is_terminal,
            ) {
                Ok(cmeta) => {
                    if is_allowed_process_id(cmeta.process_id, self.verified) {
                        if let Some(ch_idx) = self.store.intern(tail_el.clone(), cmeta) {
                            if !tail_seen.insert(ch_idx) {
                                break;
                            }
                            tail_handles.push(ch_idx);
                        } else {
                            truncated = true;
                            self.saw_children_truncated = true;
                            break;
                        }
                    }
                }
                Err(UiaCallError::AccessDenied) => {
                    self.saw_provider_refused = true;
                    self.saw_children_truncated = true;
                    return BackendTailChildrenRead::AccessDenied;
                }
                Err(UiaCallError::Unavailable) => {
                    self.saw_provider_refused = true;
                    self.saw_children_truncated = true;
                    truncated = true;
                    break;
                }
            }

            let rem_step = self
                .exploration_deadline_ms
                .saturating_sub(self.clock.monotonic_ms());
            if rem_step <= 0 || !calls.try_consume(1) {
                truncated = true;
                self.saw_children_truncated = true;
                break;
            }
            self.uia.apply_timeouts(rem_step);
            let prev = match self.uia.previous_sibling_element(&tail_el) {
                Ok(opt) => opt,
                Err(UiaCallError::AccessDenied) => {
                    self.saw_provider_refused = true;
                    self.saw_children_truncated = true;
                    return BackendTailChildrenRead::AccessDenied;
                }
                Err(UiaCallError::Unavailable) => {
                    self.saw_provider_refused = true;
                    self.saw_children_truncated = true;
                    truncated = true;
                    break;
                }
            };
            if tail_handles.len() >= capped_limit {
                if prev.is_some() {
                    truncated = true;
                }
                break;
            }
            cur = prev;
        }

        tail_handles.reverse();
        BackendTailChildrenRead::Values {
            handles: tail_handles,
            truncated,
        }
    }

    fn read_backend_node_text(
        &mut self,
        index: usize,
        expected_role: &str,
        max_units: usize,
        static_text_probe: StaticTextPolicy,
        calls: &mut BackendCallBudget,
    ) -> BackendTextRead {
        let Some(item) = self.store.items.get(index) else {
            return BackendTextRead::Unavailable {
                reasons: vec!["node-text-unavailable".to_string()],
            };
        };
        let meta = item.meta.clone();
        let elem = item.element.clone();
        let runtime_id = item.runtime_id.clone();
        let is_focused = Some(index) == self.focus_handle
            || self
                .focused_runtime_id
                .is_some_and(|rid| !rid.is_empty() && runtime_id == *rid);

        match read_uia_node_text_bounded(
            self.uia,
            &elem,
            &meta,
            expected_role,
            max_units,
            static_text_probe,
            is_focused,
            self.already_read_focus_text,
            self.exploration_deadline_ms,
            self.clock,
            || self.clock.monotonic_ms() < self.exploration_deadline_ms && calls.try_consume(1),
        ) {
            UiaNodeTextOutcome::Text {
                is_unfocused_pua_static: true,
                ..
            } => BackendTextRead::Unavailable {
                reasons: Vec::new(),
            },
            UiaNodeTextOutcome::Text {
                value,
                truncated,
                reasons,
                is_unfocused_pua_static: false,
            } => BackendTextRead::Text {
                value,
                complete: !truncated,
                reasons,
            },
            UiaNodeTextOutcome::Unavailable => BackendTextRead::Unavailable {
                reasons: vec!["node-text-unavailable".to_string()],
            },
        }
    }

    fn read_backend_node_bounds(
        &mut self,
        index: usize,
        window_rect: SurfaceAbsoluteRect,
    ) -> Option<(SurfaceBounds, i64)> {
        let rect = self.store.items.get(index)?.meta.logical_rect?;
        let rel = rect.relative_to(window_rect)?;
        let obs_ms = self.clock.unix_ms().max(self.capture_start_ms);
        Some((rel, obs_ms))
    }

    fn read_backend_window_rect(&mut self) -> Option<SurfaceAbsoluteRect> {
        window_rect_logical(self.verified.hwnd).map(|(_, logical, _)| logical)
    }

    fn verify_final_surface_boundary(&mut self) -> Option<SurfaceReadFailure> {
        self.verify_desktop_and_application()
    }
}

#[allow(clippy::too_many_arguments)]
fn capture_surface_tree(
    uia: &UiaClient,
    registry: &AdapterRegistry,
    target: ReadTarget<'_>,
    verified: &VerifiedTarget,
    ticket: &ReadTicket,
    clock: &dyn CollectorClock,
    scope: &str,
    focused_elem: Option<&IUIAutomationElement>,
    focused_runtime_id: Option<&RuntimeIdKey>,
    already_read_focus_text: Option<&str>,
    max_nodes: usize,
    max_text_units: usize,
    optional_deadline_ms: i64,
    capture_start_ms: i64,
    is_terminal: bool,
) -> Result<(PendingSurfaceCapture, usize), SurfaceReadFailure> {
    let now = clock.monotonic_ms();
    let Some(exploration_deadline) =
        PhaseBudget::surface_exploration_deadline(now, optional_deadline_ms)
    else {
        return Err(SurfaceReadFailure::NotStartedBudget);
    };

    let mut budget = ReadBudget::new(
        optional_deadline_ms,
        ReadBudget::DEFAULT_FINAL_VALIDATION_RESERVE_MS,
        ReadBudget::DEFAULT_MAX_CALLS,
        ReadBudget::DEFAULT_FINAL_VALIDATION_RESERVE_CALLS,
        max_text_units.min(ticket.policy.max_text_code_units),
    );
    if !budget.has_exploration_headroom(now) {
        return Err(SurfaceReadFailure::NotStartedBudget);
    }

    uia.apply_timeouts(exploration_deadline.saturating_sub(now));

    let window_elem = uia.element_from_hwnd(verified.hwnd).map_err(|e| match e {
        UiaCallError::AccessDenied => SurfaceReadFailure::ProviderUnavailable,
        UiaCallError::Unavailable => SurfaceReadFailure::ProviderUnavailable,
    })?;
    if !budget.consume_calls(1, clock.monotonic_ms()) {
        return Err(SurfaceReadFailure::CallBudget);
    }
    let window_meta = uia
        .read_cached_metadata(&window_elem, verified.dpi, true, is_terminal)
        .map_err(|_| SurfaceReadFailure::ProviderUnavailable)?;
    if window_meta.is_sensitive() {
        return Err(SurfaceReadFailure::SecurityExcluded);
    }
    if !TextSecurityGate::may_traverse(&window_meta.subrole_read, window_meta.is_password) {
        return Err(SurfaceReadFailure::SecurityExcluded);
    }

    // Determine traversal root (region prefers enclosing container around focused field).
    let (root_elem, root_meta) = if scope == "region" {
        let mut chosen = (window_elem.clone(), window_meta.clone());
        if let Some(fe) = focused_elem {
            let rem = exploration_deadline.saturating_sub(clock.monotonic_ms());
            if rem > 0 && budget.consume_calls(1, clock.monotonic_ms()) {
                uia.apply_timeouts(rem);
                match uia.parent_element(fe) {
                    Ok(Some(parent)) => {
                        match uia.read_cached_metadata(&parent, verified.dpi, true, is_terminal) {
                            Ok(pmeta) => {
                                if pmeta.is_sensitive() {
                                    return Err(SurfaceReadFailure::SecurityExcluded);
                                }
                                if TextSecurityGate::may_traverse(
                                    &pmeta.subrole_read,
                                    pmeta.is_password,
                                ) && is_allowed_process_id(pmeta.process_id, verified)
                                    && matches!(
                                        pmeta.mapped.ax_role,
                                        Some(
                                            "AXGroup"
                                                | "AXScrollArea"
                                                | "AXSplitGroup"
                                                | "AXList"
                                                | "AXTable"
                                                | "AXOutline"
                                                | "AXRow"
                                                | "AXCell"
                                        )
                                    )
                                {
                                    chosen = (parent, pmeta);
                                }
                            }
                            Err(UiaCallError::AccessDenied) => {
                                return Err(SurfaceReadFailure::ProviderUnavailable);
                            }
                            Err(UiaCallError::Unavailable) => {}
                        }
                    }
                    Ok(None) | Err(UiaCallError::Unavailable) => {}
                    Err(UiaCallError::AccessDenied) => {
                        return Err(SurfaceReadFailure::ProviderUnavailable);
                    }
                }
            }
        }
        chosen
    } else {
        (window_elem, window_meta)
    };

    let mut store = SurfaceCaptureStore::new();
    let root_handle = store
        .intern(root_elem, root_meta)
        .ok_or(SurfaceReadFailure::ProviderUnavailable)?;

    let mut focus_handle: Option<usize> = None;
    if let Some(fe) = focused_elem {
        if let Ok(fmeta) = uia.read_cached_metadata(fe, verified.dpi, false, is_terminal) {
            if fmeta.is_sensitive() {
                return Err(SurfaceReadFailure::SecurityExcluded);
            }
            focus_handle = store.intern(fe.clone(), fmeta);
        }
    }

    let initial_rect = verified.initial_logical_rect;
    let spec = verified.spec;
    let clamped_max_nodes = max_nodes.clamp(1, 96);
    let mut custom_fallback_reasons: Vec<String> = Vec::new();
    let mut custom_fallback_children_truncated = false;

    // Phase 4: Dispatch custom `AppAdapter::extract_surface` (e.g. WeChat, Figma) through the
    // unbypassable `KernelSurfaceContext<LiveUiaSurfaceBackend>` for `scope == "window"`.
    if scope == "window" {
        if let Some(custom_adapter) = registry.custom_adapter_for(spec.id) {
            let prior_text_units = budget.text_units();
            let mut live_backend = LiveUiaSurfaceBackend {
                uia,
                target,
                verified,
                policy: &ticket.policy,
                clock,
                capture_start_ms,
                exploration_deadline_ms: exploration_deadline,
                is_terminal,
                focus_handle,
                focused_runtime_id,
                already_read_focus_text,
                store: &mut store,
                saw_provider_refused: false,
                saw_children_truncated: false,
            };
            let mut ctx = KernelSurfaceContext::new(
                verified.resolved.clone(),
                &ticket.policy,
                spec,
                scope,
                clamped_max_nodes,
                SurfaceHandle(root_handle),
                focus_handle.map(SurfaceHandle),
                budget,
                clock,
                &mut live_backend,
            );
            ctx.set_initial_window_rect(initial_rect);
            let custom_opt = custom_adapter.extract_surface(&mut ctx);

            // CRITICAL: Aborted custom extraction MUST fail closed — NEVER fall back to weighted!
            if let Some(err) = ctx.abort_failure() {
                return Err(err);
            }
            if let Some(custom_res) = custom_opt {
                if ctx.budget().text_violated()
                    || !validate_custom_result(&custom_res, &ctx, clamped_max_nodes)
                {
                    return Err(SurfaceReadFailure::BoundaryUnverified);
                }
                let mut missing_reasons: Vec<String> = Vec::new();
                for r in custom_res.missing_reasons {
                    if !missing_reasons.contains(&r) {
                        missing_reasons.push(r);
                    }
                }
                for r in ctx.extra_reasons() {
                    if !missing_reasons.contains(r) {
                        missing_reasons.push(r.clone());
                    }
                }
                if ctx.budget().remaining_calls() == 0
                    && !missing_reasons.iter().any(|r| r == "tree-call-budget")
                {
                    missing_reasons.push("tree-call-budget".to_string());
                }
                if clock.monotonic_ms() >= ctx.budget().exploration_deadline_ms()
                    && !missing_reasons.iter().any(|r| r == "tree-time-budget")
                {
                    missing_reasons.push("tree-time-budget".to_string());
                }
                let mut final_budget = ctx.into_budget();
                let (backend_provider_refused, backend_children_truncated) = (
                    live_backend.saw_provider_refused,
                    live_backend.saw_children_truncated,
                );
                if backend_provider_refused
                    && !missing_reasons.iter().any(|r| r == "tree-provider-refused")
                {
                    missing_reasons.push("tree-provider-refused".to_string());
                }
                if backend_children_truncated
                    && !missing_reasons.iter().any(|r| r == "tree-child-limit")
                {
                    missing_reasons.push("tree-child-limit".to_string());
                }

                let mut total_surface_units = 0usize;
                let surface_text_cap = max_text_units
                    .min(ticket.policy.max_text_code_units)
                    .min(8_192);
                let mut nodes: Vec<SurfaceNode> = Vec::with_capacity(custom_res.nodes.len());
                let mut references: Vec<(String, RuntimeIdKey)> =
                    Vec::with_capacity(custom_res.nodes.len());
                let mut any_truncated = backend_children_truncated;
                let mut saw_focused = false;

                for item in &custom_res.nodes {
                    let local_id = format!("n{}", item.handle.0);
                    let parent_id = item.parent.map(|p| format!("n{}", p.0));
                    let rid = store.items[item.handle.0].runtime_id.clone();

                    let mut text = item.text.clone();
                    if !item.is_focused {
                        if let Some(ref t) = text {
                            if is_private_use_only_text(t) {
                                text = None;
                            }
                        }
                    }
                    if let Some(ref t) = text {
                        let units = utf16_len(t);
                        let avail = surface_text_cap.saturating_sub(total_surface_units);
                        if units > avail {
                            if avail > 0 {
                                text = bounded_utf16_slice(t, 0, avail);
                                total_surface_units += text.as_deref().map(utf16_len).unwrap_or(0);
                            } else {
                                text = None;
                            }
                            any_truncated = true;
                            if !missing_reasons.iter().any(|r| r == "text-budget") {
                                missing_reasons.push("text-budget".to_string());
                            }
                        } else {
                            total_surface_units += units;
                        }
                    }

                    let focused = if item.is_focused && !saw_focused && focused_elem.is_some() {
                        saw_focused = true;
                        Some(true)
                    } else {
                        None
                    };

                    nodes.push(SurfaceNode {
                        id: local_id.clone(),
                        parent_id,
                        role: item.role.to_string(),
                        text,
                        observed_at_ms: item.observed_at_ms,
                        bounds: item.bounds,
                        bounds_observed_at_ms: item.bounds_observed_at_ms,
                        ax_role: item.ax_role.clone(),
                        focused,
                    });
                    references.push((local_id, rid));
                }

                final_budget.begin_final_validation();
                let mut geometry: Option<SurfaceGeometry> = None;
                if let Some(init) = initial_rect {
                    if final_budget.can_recheck_window_rect() {
                        let final_logical_rect =
                            window_rect_logical(verified.hwnd).map(|(_, l, _)| l);
                        let geom_obs_ms = clock.unix_ms().max(capture_start_ms);
                        geometry = init.geometry_if_unchanged(final_logical_rect, geom_obs_ms);
                        SurfaceBaseline::invalidate_geometry_if_moved(
                            &mut nodes,
                            &mut geometry,
                            &mut missing_reasons,
                            initial_rect,
                            final_logical_rect,
                        );
                    } else if !missing_reasons.iter().any(|r| r == "geometry-unavailable") {
                        missing_reasons.push("geometry-unavailable".to_string());
                    }
                }
                if geometry.is_none() {
                    for node in &mut nodes {
                        node.bounds = None;
                        node.bounds_observed_at_ms = None;
                    }
                }
                let complete =
                    custom_res.complete && !any_truncated && missing_reasons.is_empty();
                let truncated = any_truncated || !complete;
                if !complete {
                    let mut ordered = vec!["bounded-ax-tree".to_string()];
                    missing_reasons.sort();
                    missing_reasons.dedup();
                    for r in missing_reasons
                        .into_iter()
                        .filter(|r| r != "bounded-ax-tree")
                        .take(15)
                    {
                        ordered.push(r);
                    }
                    missing_reasons = ordered;
                }
                return Ok((
                    PendingSurfaceCapture {
                        nodes,
                        truncated,
                        reasons: missing_reasons,
                        complete,
                        geometry,
                        adapter_id: verified.spec.id.to_string(),
                        references,
                    },
                    total_surface_units,
                ));
            }
            if ctx.budget().text_violated() {
                return Err(SurfaceReadFailure::BoundaryUnverified);
            }
            custom_fallback_reasons = ctx.take_extra_reasons();
            budget = ctx.into_budget();
            budget.restore_text_units(prior_text_units);
            if live_backend.saw_provider_refused
                && !custom_fallback_reasons
                    .iter()
                    .any(|r| r == "tree-provider-refused")
            {
                custom_fallback_reasons.push("tree-provider-refused".to_string());
            }
            if live_backend.saw_children_truncated {
                custom_fallback_children_truncated = true;
            }
        }
    }

    let store_cell = RefCell::new(store);
    let budget_cell = RefCell::new(budget);
    let security_excluded_hit = Cell::new(false);
    let provider_unavailable_hit = Cell::new(false);
    let any_weighted_children_truncated = Cell::new(custom_fallback_children_truncated);
    let weighted_children_expanded: RefCell<HashSet<usize>> = RefCell::new(HashSet::new());
    let extra_reasons_cell: RefCell<Vec<String>> = RefCell::new(custom_fallback_reasons);
    let push_extra_reason = |reason: &str| {
        let mut reasons = extra_reasons_cell.borrow_mut();
        if !reasons.iter().any(|r| r == reason) {
            reasons.push(reason.to_string());
        }
    };

    // Helper closure to inspect an interned node with O(1) child-existence probing (at most 2
    // calls: first child + second sibling) instead of eagerly walking up to 128 siblings.
    // Full sibling enumeration is deferred strictly to `read_children` when traversal expands a
    // container. Also probes non-RichEdit `Document (50030)` via `first_child_element` BEFORE
    // finalizing `AXWebArea` vs `AXTextArea` so Electron/Chromium DOM subtrees are never pruned.
    let inspect_node = |handle: &usize| -> WeightedSurfaceInspection {
        let idx = *handle;
        let now_mono = clock.monotonic_ms();
        if now_mono >= budget_cell.borrow().active_deadline_ms() {
            return WeightedSurfaceInspection::Pruned(WeightedSurfaceTraversalReason::TimeBudget);
        }
        let (meta, runtime_id, children_probed, parent_elem) = {
            let s = store_cell.borrow();
            (
                s.items[idx].meta.clone(),
                s.items[idx].runtime_id.clone(),
                s.items[idx].children_probed,
                s.items[idx].element.clone(),
            )
        };
        let is_focused = Some(idx) == focus_handle
            || focused_runtime_id.is_some_and(|rid| !rid.is_empty() && runtime_id == *rid);
        let has_sensitive_focus = is_focused || meta.has_keyboard_focus == Some(true);

        if meta.is_sensitive() {
            if idx == root_handle || has_sensitive_focus {
                security_excluded_hit.set(true);
            }
            return WeightedSurfaceInspection::Pruned(
                WeightedSurfaceTraversalReason::SecurityPruned,
            );
        }
        if !TextSecurityGate::may_traverse(&meta.subrole_read, meta.is_password) {
            return WeightedSurfaceInspection::Pruned(
                WeightedSurfaceTraversalReason::SecurityPruned,
            );
        }
        if !is_allowed_process_id(meta.process_id, verified) {
            return WeightedSurfaceInspection::Pruned(
                WeightedSurfaceTraversalReason::ProviderRefused,
            );
        }

        let role_str = meta.mapped.ax_role;
        let subrole_pre = match &meta.subrole_read {
            SubroleRead::Value(s) => Some(s.as_str()),
            _ => None,
        };
        // Prune adapter-ignored roles/subroles BEFORE probing children (0 wasted COM IPCs!).
        if idx != root_handle
            && !is_focused
            && (role_str.is_some_and(|r| spec.ignores_role(r))
                || subrole_pre.is_some_and(|s| spec.ignores_subrole(s)))
        {
            return WeightedSurfaceInspection::Pruned(
                WeightedSurfaceTraversalReason::UnsupportedRole,
            );
        }

        let policy_opt = role_str.and_then(WeightedSurfaceTraversal::role_policy);
        let reads_text = policy_opt.is_some_and(|p| p.reads_text());
        let needs_document_child_probe = meta.control_type == 50030
            && meta.mapped.ax_role != Some("AXWebArea")
            && !is_native_richedit_class(meta.class_name.as_deref());

        // Probe at most 2 children (`0`, `1`, or `>= 2` hint) without walking all 128 siblings!
        if (!reads_text || needs_document_child_probe) && !children_probed {
            let mut child_handles = Vec::new();
            let mut last_probed: Option<IUIAutomationElement> = None;
            let mut loaded_all = false;
            let mut truncated_children = false;
            let mut has_any_child = false;

            if budget_cell.borrow_mut().consume_calls(1, clock.monotonic_ms()) {
                let active_dl = budget_cell.borrow().active_deadline_ms();
                uia.apply_timeouts(active_dl.saturating_sub(clock.monotonic_ms()));
                match uia.first_child_element(&parent_elem) {
                    Ok(Some(first_el)) => {
                        has_any_child = true;
                        match uia.read_cached_metadata(&first_el, verified.dpi, false, is_terminal)
                        {
                            Ok(cmeta) => {
                                if is_allowed_process_id(cmeta.process_id, verified) {
                                    if let Some(ch_idx) =
                                        store_cell.borrow_mut().intern(first_el.clone(), cmeta)
                                    {
                                        child_handles.push(ch_idx);
                                    } else {
                                        truncated_children = true;
                                    }
                                }
                            }
                            Err(UiaCallError::AccessDenied) => {
                                if idx == root_handle {
                                    provider_unavailable_hit.set(true);
                                    return WeightedSurfaceInspection::Pruned(
                                        WeightedSurfaceTraversalReason::ProviderRefused,
                                    );
                                }
                                push_extra_reason("tree-provider-refused");
                                truncated_children = true;
                            }
                            Err(UiaCallError::Unavailable) => {
                                push_extra_reason("tree-provider-refused");
                                truncated_children = true;
                            }
                        }
                        // Probe 2nd sibling (1 call) to distinguish 1-child wrappers from multi-child
                        // split/pane containers (required for PaneHeaderBand and wrapper priority).
                        if budget_cell.borrow_mut().consume_calls(1, clock.monotonic_ms()) {
                            let active_dl = budget_cell.borrow().active_deadline_ms();
                            uia.apply_timeouts(active_dl.saturating_sub(clock.monotonic_ms()));
                            match uia.next_sibling_element(&first_el) {
                                Ok(Some(second_el)) => {
                                    match uia.read_cached_metadata(
                                        &second_el,
                                        verified.dpi,
                                        false,
                                        is_terminal,
                                    ) {
                                        Ok(cmeta) => {
                                            if is_allowed_process_id(cmeta.process_id, verified) {
                                                if let Some(ch_idx) = store_cell
                                                    .borrow_mut()
                                                    .intern(second_el.clone(), cmeta)
                                                {
                                                    if !child_handles.contains(&ch_idx) {
                                                        child_handles.push(ch_idx);
                                                    }
                                                } else {
                                                    truncated_children = true;
                                                }
                                            }
                                        }
                                        Err(UiaCallError::AccessDenied) => {
                                            if idx == root_handle {
                                                provider_unavailable_hit.set(true);
                                                return WeightedSurfaceInspection::Pruned(
                                                    WeightedSurfaceTraversalReason::ProviderRefused,
                                                );
                                            }
                                            push_extra_reason("tree-provider-refused");
                                            truncated_children = true;
                                        }
                                        Err(UiaCallError::Unavailable) => {
                                            push_extra_reason("tree-provider-refused");
                                            truncated_children = true;
                                        }
                                    }
                                    last_probed = Some(second_el);
                                }
                                Ok(None) => {
                                    loaded_all = !truncated_children;
                                }
                                Err(UiaCallError::AccessDenied) => {
                                    if idx == root_handle {
                                        provider_unavailable_hit.set(true);
                                        return WeightedSurfaceInspection::Pruned(
                                            WeightedSurfaceTraversalReason::ProviderRefused,
                                        );
                                    }
                                    push_extra_reason("tree-provider-refused");
                                    last_probed = Some(first_el);
                                    truncated_children = true;
                                }
                                Err(UiaCallError::Unavailable) => {
                                    push_extra_reason("tree-provider-refused");
                                    last_probed = Some(first_el);
                                    truncated_children = true;
                                }
                            }
                        } else {
                            last_probed = Some(first_el);
                            truncated_children = true;
                        }
                    }
                    Ok(None) => {
                        loaded_all = true;
                    }
                    Err(UiaCallError::AccessDenied) => {
                        if idx == root_handle {
                            provider_unavailable_hit.set(true);
                            return WeightedSurfaceInspection::Pruned(
                                WeightedSurfaceTraversalReason::ProviderRefused,
                            );
                        }
                        push_extra_reason("tree-provider-refused");
                        truncated_children = true;
                    }
                    Err(UiaCallError::Unavailable) => {
                        push_extra_reason("tree-provider-refused");
                        truncated_children = true;
                    }
                }
            } else {
                truncated_children = true;
            }

            if truncated_children {
                any_weighted_children_truncated.set(true);
            }
            let mut s = store_cell.borrow_mut();
            if has_any_child
                && s.items[idx].meta.control_type == 50030
                && !is_native_richedit_class(s.items[idx].meta.class_name.as_deref())
            {
                let m = &s.items[idx].meta;
                let updated = crate::policy::map_uia_control_type_to_ax(
                    50030,
                    false,
                    m.supports_text_pattern || m.supports_text_pattern2,
                    m.is_read_only,
                    true,
                    true,
                    false,
                    m.supports_scroll_pattern,
                    is_terminal,
                );
                s.items[idx].meta.mapped = updated;
                s.items[idx].cached_url = None;
            }
            s.items[idx].children = child_handles;
            s.items[idx].last_probed_child = last_probed;
            s.items[idx].children_probed = true;
            s.items[idx].children_loaded = loaded_all && !truncated_children;
            s.items[idx].children_truncated |= truncated_children;
        }

        let (effective_meta, child_count) = {
            let s = store_cell.borrow();
            let effective_reads_text = s.items[idx]
                .meta
                .mapped
                .ax_role
                .and_then(WeightedSurfaceTraversal::role_policy)
                .is_some_and(|p| p.reads_text());
            let count = if effective_reads_text {
                0
            } else {
                s.items[idx].children.len()
            };
            (s.items[idx].meta.clone(), count)
        };

        let obs_ms = clock.unix_ms().max(capture_start_ms);
        let bounds = initial_rect.and_then(|win| {
            effective_meta
                .logical_rect
                .and_then(|r| r.relative_to(win))
        });
        let bounds_observed_at_ms = bounds.map(|_| obs_ms);

        let url_res = {
            let active_dl = budget_cell.borrow().active_deadline_ms();
            let mut s = store_cell.borrow_mut();
            read_safe_display_url_post_gate(
                uia,
                &mut s,
                idx,
                spec,
                active_dl,
                clock,
                || budget_cell.borrow_mut().consume_calls(1, clock.monotonic_ms()),
            )
        };
        let url = match url_res {
            Ok(u) => u,
            Err(UiaCallError::AccessDenied) => {
                if idx == root_handle {
                    provider_unavailable_hit.set(true);
                }
                return WeightedSurfaceInspection::Pruned(
                    WeightedSurfaceTraversalReason::ProviderRefused,
                );
            }
            Err(UiaCallError::Unavailable) => None,
        };

        let display_text = effective_meta.mapped.ax_role.and_then(|ax| {
            SafeDisplayText::compose(
                ax,
                effective_meta.name.as_deref(),
                effective_meta.safe_description(),
                url.as_deref(),
                spec.max_node_text_units,
            )
        });

        let subrole = match &effective_meta.subrole_read {
            crate::policy::SubroleRead::Value(s) => Some(s.clone()),
            _ => None,
        };

        WeightedSurfaceInspection::Allowed(WeightedSurfaceMetadata {
            ax_role: effective_meta.mapped.ax_role.map(str::to_string),
            category: effective_meta.mapped.category,
            subrole,
            child_count,
            is_focused,
            observed_at_ms: obs_ms,
            is_enabled: effective_meta.is_enabled,
            display_text,
            bounds,
            bounds_observed_at_ms,
        })
    };

    // Focus-anchor path collection (max 48 hops, bounded prep time & calls).
    let mut focus_plan = None;
    let mut prep_work = 0usize;
    let mut prep_probes = 0usize;
    if let Some(fh) = focus_handle {
        let prep_now = clock.monotonic_ms();
        let prep_budget_ms = exploration_deadline
            .saturating_sub(prep_now)
            .checked_div(3)
            .unwrap_or(0)
            .min(160);
        let prep_deadline = prep_now + prep_budget_ms;
        let prep_calls = (budget_cell.borrow().remaining_calls() / 4).min(192);
        let prep_start_calls = budget_cell.borrow().calls();

        if prep_budget_ms >= 5 && prep_calls >= 4 {
            let anchor_res = SurfaceFocusAnchors::collect(
                root_handle,
                fh,
                SurfaceFocusAnchors::MAXIMUM_HOPS,
                SurfaceFocusAnchors::MAXIMUM_WORK,
                SurfaceFocusAnchors::MAXIMUM_PROBES,
                |h| inspect_node(h),
                |h| {
                    let rem = prep_deadline.saturating_sub(clock.monotonic_ms());
                    if rem <= 0 || !budget_cell.borrow_mut().consume_calls(1, clock.monotonic_ms()) {
                        return None;
                    }
                    uia.apply_timeouts(rem);
                    let elem = store_cell.borrow().items[*h].element.clone();
                    let parent = match uia.parent_element(&elem) {
                        Ok(Some(p)) => p,
                        Ok(None) | Err(UiaCallError::Unavailable) => return None,
                        Err(UiaCallError::AccessDenied) => {
                            push_extra_reason("tree-provider-refused");
                            return None;
                        }
                    };
                    let pmeta = match uia.read_cached_metadata(
                        &parent,
                        verified.dpi,
                        true,
                        is_terminal,
                    ) {
                        Ok(m) => m,
                        Err(UiaCallError::AccessDenied) => {
                            push_extra_reason("tree-provider-refused");
                            return None;
                        }
                        Err(UiaCallError::Unavailable) => return None,
                    };
                    if pmeta.is_sensitive() {
                        security_excluded_hit.set(true);
                        return None;
                    }
                    if !TextSecurityGate::may_traverse(&pmeta.subrole_read, pmeta.is_password) {
                        return None;
                    }
                    if !is_allowed_process_id(pmeta.process_id, verified) {
                        return None;
                    }
                    store_cell.borrow_mut().intern(parent, pmeta)
                },
                || {
                    let b = budget_cell.borrow();
                    !security_excluded_hit.get()
                        && !provider_unavailable_hit.get()
                        && !b.text_violated()
                        && clock.monotonic_ms() < prep_deadline
                        && b.calls().saturating_sub(prep_start_calls) < prep_calls
                },
            );
            if security_excluded_hit.get() {
                return Err(SurfaceReadFailure::SecurityExcluded);
            }
            if provider_unavailable_hit.get() {
                return Err(SurfaceReadFailure::ProviderUnavailable);
            }
            prep_work = anchor_res.work;
            prep_probes = anchor_res.probes;
            focus_plan = anchor_res.plan;
        }
    }

    let limits = WeightedSurfaceTraversalLimits::new(
        max_nodes.clamp(1, 96),
        None,
        None,
        192,
        64,
        spec.page_size,
        4,
    );
    let preferred: HashSet<&str> = spec.preferred_roles.iter().copied().collect();
    let ignored: HashSet<&str> = spec.ignored_roles.iter().copied().collect();
    let ignored_sub: HashSet<&str> = spec.ignored_subroles.iter().copied().collect();

    let traversal = WeightedSurfaceTraversal::run(
        root_handle,
        limits,
        &preferred,
        &ignored,
        &ignored_sub,
        spec.collapse_empty_containers,
        prep_work,
        prep_probes,
        focus_plan.as_ref(),
        |h| inspect_node(h),
        |h, offset, count| {
            let idx = *h;
            let needs_lazy_load = {
                let s = store_cell.borrow();
                !s.items[idx].children_loaded
                    && !weighted_children_expanded.borrow().contains(&idx)
            };
            if needs_lazy_load {
                let (parent_elem, mut child_handles, last_probed, hint_count) = {
                    let mut s = store_cell.borrow_mut();
                    let item = &mut s.items[idx];
                    let hint_count = item.children.len();
                    (
                        item.element.clone(),
                        std::mem::take(&mut item.children),
                        item.last_probed_child.take(),
                        hint_count,
                    )
                };
                let mut seen_children: HashSet<usize> = child_handles.iter().copied().collect();
                let mut loaded_all = false;
                let mut truncated_children = false;
                let mut provider_refused = false;
                let mut more_after_head: Option<IUIAutomationElement> = None;

                // 1. Continue walking head siblings up to MAX_HEAD_CHILDREN_PER_CONTAINER (64).
                let mut cur_prev = last_probed;
                if cur_prev.is_none() && child_handles.is_empty() {
                    if budget_cell.borrow_mut().consume_calls(1, clock.monotonic_ms()) {
                        let active_dl = budget_cell.borrow().active_deadline_ms();
                        uia.apply_timeouts(active_dl.saturating_sub(clock.monotonic_ms()));
                        match uia.first_child_element(&parent_elem) {
                            Ok(Some(first_el)) => {
                                match uia.read_cached_metadata(
                                    &first_el,
                                    verified.dpi,
                                    false,
                                    is_terminal,
                                ) {
                                    Ok(cmeta) => {
                                        if is_allowed_process_id(cmeta.process_id, verified) {
                                            if let Some(ch_idx) = store_cell
                                                .borrow_mut()
                                                .intern(first_el.clone(), cmeta)
                                            {
                                                if seen_children.insert(ch_idx) {
                                                    child_handles.push(ch_idx);
                                                }
                                            } else {
                                                truncated_children = true;
                                            }
                                        }
                                    }
                                    Err(_) => {
                                        truncated_children = true;
                                        provider_refused = true;
                                    }
                                }
                                cur_prev = Some(first_el);
                            }
                            Ok(None) => {
                                loaded_all = true;
                            }
                            Err(UiaCallError::AccessDenied | UiaCallError::Unavailable) => {
                                truncated_children = true;
                                provider_refused = true;
                            }
                        }
                    } else {
                        truncated_children = true;
                    }
                }

                let mut head_steps = 0usize;
                let max_head_steps = MAX_CHILDREN_PER_CONTAINER;
                while let Some(prev_el) = cur_prev.take() {
                    if truncated_children || head_steps >= max_head_steps {
                        cur_prev = Some(prev_el);
                        truncated_children = true;
                        break;
                    }
                    head_steps += 1;
                    if !budget_cell.borrow_mut().consume_calls(1, clock.monotonic_ms()) {
                        cur_prev = Some(prev_el);
                        truncated_children = true;
                        break;
                    }
                    let active_dl = budget_cell.borrow().active_deadline_ms();
                    uia.apply_timeouts(active_dl.saturating_sub(clock.monotonic_ms()));
                    let next_el = match uia.next_sibling_element(&prev_el) {
                        Ok(Some(el)) => el,
                        Ok(None) => {
                            loaded_all = !truncated_children;
                            break;
                        }
                        Err(UiaCallError::AccessDenied | UiaCallError::Unavailable) => {
                            cur_prev = Some(prev_el);
                            truncated_children = true;
                            provider_refused = true;
                            break;
                        }
                    };
                    if child_handles.len() >= MAX_HEAD_CHILDREN_PER_CONTAINER {
                        more_after_head = Some(next_el);
                        break;
                    }
                    match uia.read_cached_metadata(&next_el, verified.dpi, false, is_terminal) {
                        Ok(cmeta) => {
                            if is_allowed_process_id(cmeta.process_id, verified) {
                                if let Some(ch_idx) =
                                    store_cell.borrow_mut().intern(next_el.clone(), cmeta)
                                {
                                    if seen_children.insert(ch_idx) {
                                        child_handles.push(ch_idx);
                                    } else {
                                        loaded_all = !truncated_children;
                                        break;
                                    }
                                } else {
                                    cur_prev = Some(prev_el);
                                    truncated_children = true;
                                    break;
                                }
                            }
                        }
                        Err(_) => {
                            cur_prev = Some(prev_el);
                            truncated_children = true;
                            provider_refused = true;
                            break;
                        }
                    }
                    cur_prev = Some(next_el);
                }

                // 2. If container has > 64 children, also walk tail siblings backward (up to 64)
                // so bottom-aligned chat lists (Feishu/Slack) expose the newest messages for
                // SurfaceChildFrontier's tail-first paging!
                if let Some(extra_head_el) = more_after_head {
                    let mut tail_handles: Vec<usize> = Vec::new();
                    let mut tail_seen: HashSet<usize> = HashSet::new();
                    let mut met_head = false;
                    let mut last_child_absent = false;
                    let tail_cap = MAX_CHILDREN_PER_CONTAINER
                        .saturating_sub(child_handles.len())
                        .min(MAX_TAIL_CHILDREN_PER_CONTAINER);
                    if tail_cap > 0 && budget_cell.borrow_mut().consume_calls(1, clock.monotonic_ms())
                    {
                        let active_dl = budget_cell.borrow().active_deadline_ms();
                        uia.apply_timeouts(active_dl.saturating_sub(clock.monotonic_ms()));
                        let mut tail_cur = match uia.last_child_element(&parent_elem) {
                            Ok(Some(el)) => Some(el),
                            Ok(None) => {
                                last_child_absent = true;
                                None
                            }
                            Err(UiaCallError::AccessDenied | UiaCallError::Unavailable) => {
                                truncated_children = true;
                                provider_refused = true;
                                None
                            }
                        };
                        let mut tail_steps = 0usize;
                        let max_tail_steps = MAX_CHILDREN_PER_CONTAINER;
                        while let Some(tail_el) = tail_cur {
                            if tail_steps >= max_tail_steps {
                                truncated_children = true;
                                break;
                            }
                            tail_steps += 1;
                            match uia.read_cached_metadata(&tail_el, verified.dpi, false, is_terminal)
                            {
                                Ok(cmeta) => {
                                    if is_allowed_process_id(cmeta.process_id, verified) {
                                        if let Some(ch_idx) =
                                            store_cell.borrow_mut().intern(tail_el.clone(), cmeta)
                                        {
                                            if seen_children.contains(&ch_idx) {
                                                met_head = true;
                                                break;
                                            }
                                            if !tail_seen.insert(ch_idx) {
                                                break;
                                            }
                                            tail_handles.push(ch_idx);
                                        } else {
                                            truncated_children = true;
                                            break;
                                        }
                                    }
                                }
                                Err(_) => {
                                    truncated_children = true;
                                    provider_refused = true;
                                    break;
                                }
                            }
                            if tail_handles.len() >= tail_cap {
                                truncated_children = true;
                                break;
                            }
                            if !budget_cell.borrow_mut().consume_calls(1, clock.monotonic_ms()) {
                                truncated_children = true;
                                break;
                            }
                            let active_dl = budget_cell.borrow().active_deadline_ms();
                            uia.apply_timeouts(active_dl.saturating_sub(clock.monotonic_ms()));
                            tail_cur = match uia.previous_sibling_element(&tail_el) {
                                Ok(opt) => opt,
                                Err(_) => {
                                    truncated_children = true;
                                    provider_refused = true;
                                    break;
                                }
                            };
                        }
                    } else {
                        truncated_children = true;
                    }
                    if tail_handles.is_empty() && !met_head {
                        // Only fall back to the peeked 65th head child when provider legitimately
                        // reported no LastChild (`Ok(None)`), never on `Unavailable`/`AccessDenied`.
                        if last_child_absent {
                            if let Ok(cmeta) = uia.read_cached_metadata(
                                &extra_head_el,
                                verified.dpi,
                                false,
                                is_terminal,
                            ) {
                                if is_allowed_process_id(cmeta.process_id, verified) {
                                    if let Some(ch_idx) =
                                        store_cell.borrow_mut().intern(extra_head_el, cmeta)
                                    {
                                        if seen_children.insert(ch_idx) {
                                            child_handles.push(ch_idx);
                                        }
                                    }
                                }
                            }
                        }
                        truncated_children = true;
                    } else {
                        tail_handles.reverse();
                        child_handles.extend(tail_handles);
                        if met_head && !truncated_children {
                            loaded_all = true;
                        } else {
                            truncated_children = true;
                        }
                    }
                }

                let total = child_handles.len();
                if truncated_children {
                    any_weighted_children_truncated.set(true);
                }
                {
                    let mut s = store_cell.borrow_mut();
                    s.items[idx].children = child_handles;
                    s.items[idx].last_probed_child = cur_prev;
                    if loaded_all && !truncated_children {
                        s.items[idx].children_loaded = true;
                    }
                    s.items[idx].children_truncated |= truncated_children;
                }
                weighted_children_expanded.borrow_mut().insert(idx);
                if provider_refused {
                    push_extra_reason("tree-provider-refused");
                    if total == 0 && hint_count > 0 {
                        return WeightedSurfaceChildrenRead::Unavailable(
                            WeightedSurfaceTraversalReason::ProviderRefused,
                        );
                    }
                }
                if total != hint_count {
                    return WeightedSurfaceChildrenRead::ResolvedCount(total);
                }
            }

            let s = store_cell.borrow();
            let total = s.items[idx].children.len();
            if offset >= total {
                return WeightedSurfaceChildrenRead::Values(Vec::new());
            }
            let end = (offset + count).min(total);
            WeightedSurfaceChildrenRead::Values(s.items[idx].children[offset..end].to_vec())
        },
        |h| {
            let idx = *h;
            let (meta, elem, runtime_id) = {
                let s = store_cell.borrow();
                (
                    s.items[idx].meta.clone(),
                    s.items[idx].element.clone(),
                    s.items[idx].runtime_id.clone(),
                )
            };
            if meta.is_sensitive() {
                security_excluded_hit.set(true);
                return None;
            }
            let sec = classify_element_security(&meta, &ticket.policy);
            if sec == SecureStatus::Sensitive {
                security_excluded_hit.set(true);
                return None;
            }
            if !ticket.policy.allows_secure(sec) {
                return None;
            }
            let remaining = budget_cell.borrow().remaining_text_units();
            if remaining == 0 {
                return None;
            }
            let node_cap = spec.max_node_text_units.min(remaining);
            if node_cap == 0 {
                return None;
            }

            let is_focused = Some(idx) == focus_handle
                || focused_runtime_id.is_some_and(|rid| !rid.is_empty() && runtime_id == *rid);
            let expected_role = meta.mapped.ax_role?;
            let active_dl = budget_cell.borrow().active_deadline_ms();

            match read_uia_node_text_bounded(
                uia,
                &elem,
                &meta,
                expected_role,
                node_cap,
                spec.static_text_probe,
                is_focused,
                already_read_focus_text,
                active_dl,
                clock,
                || budget_cell.borrow_mut().consume_calls(1, clock.monotonic_ms()),
            ) {
                UiaNodeTextOutcome::Text {
                    value,
                    truncated,
                    is_unfocused_pua_static,
                    ..
                } => {
                    if !is_unfocused_pua_static {
                        let units = utf16_len(&value);
                        if !budget_cell.borrow_mut().consume_text(units, Some(node_cap)) {
                            return None;
                        }
                    }
                    Some(WeightedSurfaceTextRead {
                        text: Some(value),
                        truncated,
                    })
                }
                UiaNodeTextOutcome::Unavailable => None,
            }
        },
        || {
            let b = budget_cell.borrow();
            !security_excluded_hit.get()
                && !provider_unavailable_hit.get()
                && !b.text_violated()
                && b.remaining_calls() > 0
                && clock.monotonic_ms() < exploration_deadline
        },
        || {
            !security_excluded_hit.get()
                && !provider_unavailable_hit.get()
                && !budget_cell.borrow().text_violated()
                && clock.monotonic_ms() < optional_deadline_ms
        },
    );

    if security_excluded_hit.get() {
        return Err(SurfaceReadFailure::SecurityExcluded);
    }
    if provider_unavailable_hit.get() {
        return Err(SurfaceReadFailure::ProviderUnavailable);
    }
    let mut budget = budget_cell.into_inner();
    let store = store_cell.into_inner();
    let mut extra_reasons = extra_reasons_cell.into_inner();
    if budget.text_violated() {
        return Err(SurfaceReadFailure::CallBudget);
    }

    // Build final SurfaceNodes ensuring total UTF-16 text sum <= max_text_units.min(8192).
    let mut total_surface_units = 0usize;
    let surface_text_cap = max_text_units.min(ticket.policy.max_text_code_units).min(8_192);
    let mut nodes: Vec<SurfaceNode> = Vec::with_capacity(traversal.nodes.len());
    let mut references: Vec<(String, RuntimeIdKey)> = Vec::with_capacity(traversal.nodes.len());
    let mut any_truncated = any_weighted_children_truncated.get();
    let mut saw_focused = false;

    if any_weighted_children_truncated.get()
        && !extra_reasons.iter().any(|r| r == "tree-child-limit")
    {
        extra_reasons.push("tree-child-limit".to_string());
    }
    if budget.remaining_calls() == 0 {
        any_truncated = true;
        if !extra_reasons.iter().any(|r| r == "tree-call-budget") {
            extra_reasons.push("tree-call-budget".to_string());
        }
    }

    for sample in &traversal.nodes {
        let local_id = format!("n{}", sample.handle);
        let parent_id = sample.parent.map(|p| format!("n{p}"));
        let rid = store.items[sample.handle].runtime_id.clone();

        if store.items[sample.handle].children_truncated {
            any_truncated = true;
            if !extra_reasons.iter().any(|r| r == "tree-child-limit") {
                extra_reasons.push("tree-child-limit".to_string());
            }
        }

        let mut text = if let Some(ref tr) = sample.text_read {
            if tr.truncated {
                any_truncated = true;
            }
            tr.text.clone()
        } else {
            sample.metadata.display_text.clone()
        };

        // Enforce PUA exclusion on non-focused display/static text and hard UTF-16 sum cap.
        if !sample.metadata.is_focused {
            if let Some(ref t) = text {
                if is_private_use_only_text(t) {
                    text = None;
                }
            }
        }
        if let Some(ref t) = text {
            let units = utf16_len(t);
            let avail = surface_text_cap.saturating_sub(total_surface_units);
            if units > avail {
                if avail > 0 {
                    text = bounded_utf16_slice(t, 0, avail);
                    total_surface_units += text.as_deref().map(utf16_len).unwrap_or(0);
                } else {
                    text = None;
                }
                any_truncated = true;
                if !extra_reasons.iter().any(|r| r == "text-budget") {
                    extra_reasons.push("text-budget".to_string());
                }
            } else {
                total_surface_units += units;
            }
        }

        let focused = if sample.metadata.is_focused && !saw_focused && focused_elem.is_some() {
            saw_focused = true;
            Some(true)
        } else {
            None
        };

        nodes.push(SurfaceNode {
            id: local_id.clone(),
            parent_id,
            role: sample.metadata.category.to_string(),
            text,
            observed_at_ms: sample.metadata.observed_at_ms,
            bounds: sample.metadata.bounds,
            bounds_observed_at_ms: sample.metadata.bounds_observed_at_ms,
            ax_role: sample.metadata.ax_role.clone(),
            focused,
        });
        references.push((local_id, rid));
    }

    let mut missing_reasons: Vec<String> = traversal
        .reasons
        .iter()
        .map(|r| r.as_str().to_string())
        .collect();
    for r in extra_reasons {
        if !missing_reasons.contains(&r) {
            missing_reasons.push(r);
        }
    }

    // Final validation phase: recheck window rect and invalidate geometry if window moved!
    budget.begin_final_validation();
    let mut geometry: Option<SurfaceGeometry> = None;
    if let Some(init) = initial_rect {
        if budget.can_recheck_window_rect() {
            let final_logical_rect = window_rect_logical(verified.hwnd).map(|(_, l, _)| l);
            let geom_obs_ms = clock.unix_ms().max(capture_start_ms);
            geometry = init.geometry_if_unchanged(final_logical_rect, geom_obs_ms);
            SurfaceBaseline::invalidate_geometry_if_moved(
                &mut nodes,
                &mut geometry,
                &mut missing_reasons,
                initial_rect,
                final_logical_rect,
            );
        } else if !missing_reasons.iter().any(|r| r == "geometry-unavailable") {
            missing_reasons.push("geometry-unavailable".to_string());
        }
    }

    // Schema invariant: node bounds are only valid when SurfaceGeometry is present.
    if geometry.is_none() {
        for node in &mut nodes {
            node.bounds = None;
            node.bounds_observed_at_ms = None;
        }
    }

    let complete = traversal.complete && !any_truncated && missing_reasons.is_empty();
    let truncated = any_truncated
        || traversal.reasons.iter().any(|r| {
            matches!(
                r,
                WeightedSurfaceTraversalReason::WorkBudget
                    | WeightedSurfaceTraversalReason::ProbeBudget
                    | WeightedSurfaceTraversalReason::PendingBudget
                    | WeightedSurfaceTraversalReason::OutputBudget
                    | WeightedSurfaceTraversalReason::DepthBudget
                    | WeightedSurfaceTraversalReason::TimeBudget
            )
        });

    Ok((
        PendingSurfaceCapture {
            nodes,
            truncated,
            reasons: missing_reasons,
            complete,
            geometry,
            adapter_id: verified.spec.id.to_string(),
            references,
        },
        total_surface_units,
    ))
}

/// Live one-shot worker entrypoint invoked by `worker_ipc::run_worker_cli` in `--serve` mode.
pub fn execute_live_one_shot(
    ticket: &ReadTicket,
    clock: &dyn CollectorClock,
    progress: Option<&WorkerProgressClient>,
) -> ReadResult {
    ensure_per_monitor_dpi_aware();
    let start_ms = clock.unix_ms();
    if let Some(p) = progress {
        p.stage(1, -1);
    }

    let Ok(_com) = ComGuard::init_mta() else {
        return ReadResult::failure(
            ticket.token.clone(),
            "read-error",
            Some(GapDiagnostic::new(
                GapDiagnosticCode::TextReadUnavailable,
                None,
            )),
            start_ms,
            clock.unix_ms(),
        );
    };
    let Ok(uia) = UiaClient::new() else {
        return ReadResult::failure(
            ticket.token.clone(),
            "read-error",
            Some(GapDiagnostic::new(
                GapDiagnosticCode::TextReadUnavailable,
                None,
            )),
            start_ms,
            clock.unix_ms(),
        );
    };

    let registry = AdapterRegistry::new();
    let mut node_map = SurfaceNodeMap::new();
    let mut baseline = SurfaceBaseline::new();
    let mut state = SessionIdentityState::new();
    execute_read_core(
        &uia,
        &registry,
        ReadTarget::LiveForeground,
        ticket,
        clock,
        progress,
        "unavailable",
        &mut state,
        &mut node_map,
        &mut baseline,
        None,
    )
}

/// Deterministic integration-test entrypoint that runs the FULL live UIA pipeline (pre-read
/// privacy gates, private browser title/chrome checks, MTA COM, DPI normalization,
/// `TextSecurityGate`, `uia.text`/`uia.value`, `uia.tree`, `SurfaceNodeMap`, `SurfaceBaseline`,
/// and post-read revalidation) targeting an explicit synthetic Win32 window `HWND`.
pub fn read_window_for_test(
    window_hwnd: HWND,
    focused_hwnd: Option<HWND>,
    app_id_override: Option<&str>,
    desktop_override: Option<DesktopStatus>,
    ticket: &ReadTicket,
    clock: &dyn CollectorClock,
) -> ReadResult {
    read_window_internal_for_test(
        window_hwnd,
        focused_hwnd,
        app_id_override,
        None,
        desktop_override,
        ticket,
        clock,
    )
}

/// Deterministic integration-test entrypoint accepting an explicit dual-ID `ResolvedAppIdentity`
/// (e.g., MSIX package name + `.exe` basename) to verify dual-ID policy/browser/adapter enforcement.
pub fn read_window_with_identity_for_test(
    window_hwnd: HWND,
    focused_hwnd: Option<HWND>,
    resolved_identity: &ResolvedAppIdentity,
    desktop_override: Option<DesktopStatus>,
    ticket: &ReadTicket,
    clock: &dyn CollectorClock,
) -> ReadResult {
    read_window_internal_for_test(
        window_hwnd,
        focused_hwnd,
        None,
        Some(resolved_identity),
        desktop_override,
        ticket,
        clock,
    )
}

fn read_window_internal_for_test(
    window_hwnd: HWND,
    focused_hwnd: Option<HWND>,
    app_id_override: Option<&str>,
    resolved_override: Option<&ResolvedAppIdentity>,
    desktop_override: Option<DesktopStatus>,
    ticket: &ReadTicket,
    clock: &dyn CollectorClock,
) -> ReadResult {
    ensure_per_monitor_dpi_aware();
    let start_ms = clock.unix_ms();
    let Ok(_com) = ComGuard::init_mta() else {
        return ReadResult::failure(
            ticket.token.clone(),
            "read-error",
            Some(GapDiagnostic::new(
                GapDiagnosticCode::TextReadUnavailable,
                None,
            )),
            start_ms,
            clock.unix_ms(),
        );
    };
    let Ok(uia) = UiaClient::new() else {
        return ReadResult::failure(
            ticket.token.clone(),
            "read-error",
            Some(GapDiagnostic::new(
                GapDiagnosticCode::TextReadUnavailable,
                None,
            )),
            start_ms,
            clock.unix_ms(),
        );
    };
    let registry = AdapterRegistry::new();
    let mut node_map = SurfaceNodeMap::new();
    let mut baseline = SurfaceBaseline::new();
    let mut state = SessionIdentityState::new();
    execute_read_core(
        &uia,
        &registry,
        ReadTarget::ExplicitWindow {
            window_hwnd,
            focused_hwnd,
            app_id_override,
            resolved_override,
            desktop_override,
        },
        ticket,
        clock,
        None,
        "unavailable",
        &mut state,
        &mut node_map,
        &mut baseline,
        None,
    )
}

struct SessionIdentityState {
    session_id: String,
    bound_application: Option<ApplicationIdentity>,
    bound_raw_pid: u32,
    identity: Option<WorkerSurfaceIdentity>,
    previous_window: Option<isize>,
    previous_focus_runtime_id: Option<RuntimeIdKey>,
    invalidated_focus: bool,
    serial: i64,
}

impl SessionIdentityState {
    fn new() -> Self {
        Self {
            session_id: generate_uuid_v4(),
            bound_application: None,
            bound_raw_pid: 0,
            identity: None,
            previous_window: None,
            previous_focus_runtime_id: None,
            invalidated_focus: false,
            serial: 0,
        }
    }

    fn invalidate(&mut self) {
        self.invalidated_focus = true;
        self.identity = None;
        self.previous_window = None;
        self.previous_focus_runtime_id = None;
    }
}

#[allow(clippy::too_many_arguments)]
fn execute_read_core(
    uia: &UiaClient,
    registry: &AdapterRegistry,
    target: ReadTarget<'_>,
    ticket: &ReadTicket,
    clock: &dyn CollectorClock,
    progress: Option<&WorkerProgressClient>,
    observer_status: &str,
    state: &mut SessionIdentityState,
    node_map: &mut SurfaceNodeMap,
    baseline: &mut SurfaceBaseline,
    mut warmed_hwnds: Option<&mut WarmedHwndCache>,
) -> ReadResult {
    let start_ms = clock.unix_ms();
    let fast_only = ticket.focused_fast_only == Some(true);
    let surface_requested = !fast_only
        && matches!(
            ticket.policy.capture_scope.as_deref(),
            Some("region" | "window")
        );

    let verified = match verify_target_pre_read(
        uia,
        target,
        ticket,
        registry,
        clock,
        start_ms,
        surface_requested,
    ) {
        Ok(v) => v,
        Err(res) => {
            if matches!(
                res.diagnostic.map(|d| d.code),
                Some(
                    GapDiagnosticCode::ApplicationUnavailable
                        | GapDiagnosticCode::BrowserExcluded
                )
            ) {
                state.invalidate();
                node_map.reset();
                baseline.reset();
            }
            return *res;
        }
    };

    // Session app binding check: if bound to a different app, signal session-app-changed so the
    // engine resets boundaries cleanly.
    if let Some(ref bound) = state.bound_application {
        if *bound != verified.app {
            state.invalidate();
            node_map.reset();
            baseline.reset();
            if let Some(cache) = warmed_hwnds.as_deref_mut() {
                cache.clear();
            }
            return ReadResult::failure(
                ticket.token.clone(),
                "session-app-changed",
                Some(GapDiagnostic::new(GapDiagnosticCode::FocusChanged, None)),
                start_ms,
                clock.unix_ms(),
            );
        }
    } else {
        state.bound_application = Some(verified.app.clone());
    }
    state.bound_raw_pid = verified.raw_pid;

    let is_terminal = registry.is_terminal_identity(&verified.resolved);

    // Optional bounded Chromium/Electron ElementFromHandle warmup (cached once per HWND per session).
    let enablement: AxEnablementResult = warmup_window_uia(
        uia,
        verified.hwnd,
        verified.spec,
        &ticket.policy,
        ticket.read_only_ax_enablement == Some(true),
        ticket.deadline_monotonic_ms,
        clock,
        warmed_hwnds,
    );

    if clock.monotonic_ms() >= ticket.deadline_monotonic_ms {
        let mut r = ReadResult::failure(
            ticket.token.clone(),
            "stale",
            Some(GapDiagnostic::new(GapDiagnosticCode::ReadDeadline, None)),
            start_ms,
            clock.unix_ms(),
        );
        r.enablement = Some(enablement);
        r.diagnostic_application = Some(verified.app);
        r.exe_name = verified.resolved.exe_name.clone();
        return r;
    }

    uia.apply_timeouts(
        ticket
            .deadline_monotonic_ms
            .saturating_sub(clock.monotonic_ms()),
    );

    // Resolve focused UIA element wrapped in progress.set_focus_deadline.
    if let Some(p) = progress {
        p.set_focus_deadline(ticket.deadline_monotonic_ms);
    }
    let focus_lookup: Result<Option<IUIAutomationElement>, UiaCallError> = match target {
        ReadTarget::LiveForeground => match uia.focused_element() {
            Ok(el) => Ok(Some(el)),
            Err(UiaCallError::AccessDenied) => Err(UiaCallError::AccessDenied),
            Err(UiaCallError::Unavailable) => Ok(None),
        },
        ReadTarget::ExplicitWindow {
            focused_hwnd: Some(fh),
            ..
        } => match uia.element_from_hwnd(fh) {
            Ok(el) => Ok(Some(el)),
            Err(UiaCallError::AccessDenied) => Err(UiaCallError::AccessDenied),
            Err(UiaCallError::Unavailable) => Ok(None),
        },
        ReadTarget::ExplicitWindow {
            focused_hwnd: None, ..
        } => Ok(None),
    };
    if let Some(p) = progress {
        p.set_focus_deadline(0);
    }

    let focused_opt: Option<(IUIAutomationElement, UiaElementMetadata)> = match focus_lookup {
        Err(UiaCallError::AccessDenied) => {
            let mut r = ReadResult::failure(
                ticket.token.clone(),
                "read-error",
                Some(GapDiagnostic::new(
                    GapDiagnosticCode::TextReadUnavailable,
                    None,
                )),
                start_ms,
                clock.unix_ms(),
            );
            r.enablement = Some(enablement);
            r.observer_status = Some(observer_status.to_string());
            r.diagnostic_application = Some(verified.app);
            r.exe_name = verified.resolved.exe_name.clone();
            if surface_requested {
                r.surface_failure = Some(SurfaceReadFailure::ProviderUnavailable);
            }
            return r;
        }
        Ok(Some(el)) => match uia.read_cached_metadata(&el, verified.dpi, false, is_terminal) {
            Err(UiaCallError::AccessDenied) => {
                let mut r = ReadResult::failure(
                    ticket.token.clone(),
                    "read-error",
                    Some(GapDiagnostic::new(
                        GapDiagnosticCode::TextReadUnavailable,
                        None,
                    )),
                    start_ms,
                    clock.unix_ms(),
                );
                r.enablement = Some(enablement);
                r.observer_status = Some(observer_status.to_string());
                r.diagnostic_application = Some(verified.app);
                r.exe_name = verified.resolved.exe_name.clone();
                if surface_requested {
                    r.surface_failure = Some(SurfaceReadFailure::ProviderUnavailable);
                }
                return r;
            }
            Err(UiaCallError::Unavailable) => None,
            Ok(meta) => {
                // IMMEDIATE PRE-READ SECURITY GATE: password field aborts ALL reads immediately!
                if meta.is_sensitive() {
                    state.invalidate();
                    node_map.reset();
                    baseline.reset();
                    let mut r = ReadResult::failure(
                        ticket.token.clone(),
                        "policy-boundary",
                        Some(GapDiagnostic::new(
                            GapDiagnosticCode::SecureField,
                            Some("AXSecureTextField"),
                        )),
                        start_ms,
                        clock.unix_ms(),
                    );
                    r.enablement = Some(enablement);
                    r.observer_status = Some(observer_status.to_string());
                    if surface_requested {
                        r.surface_failure = Some(SurfaceReadFailure::SecurityExcluded);
                    }
                    return r;
                }
                if element_belongs_to_window(uia, &el, &meta, &verified) {
                    Some((el, meta))
                } else {
                    None
                }
            }
        },
        Ok(None) | Err(UiaCallError::Unavailable) => None,
    };

    // Unfocused-window fallback when captureScope == "window" and adapter allows it.
    if focused_opt.is_none() {
        if !fast_only
            && ticket.policy.capture_scope.as_deref() == Some("window")
            && verified.spec.window_anchor.allows_unfocused_window()
        {
            return execute_unfocused_window_read(
                uia,
                registry,
                target,
                &verified,
                ticket,
                clock,
                start_ms,
                enablement,
                observer_status,
                state,
                node_map,
                baseline,
                is_terminal,
            );
        }

        state.invalidate();
        node_map.reset();
        baseline.reset();
        let mut r = ReadResult::failure(
            ticket.token.clone(),
            "focus-unavailable",
            Some(GapDiagnostic::new(
                GapDiagnosticCode::FocusedFieldUnavailable,
                None,
            )),
            start_ms,
            clock.unix_ms(),
        );
        r.enablement = Some(enablement);
        r.observer_status = Some(observer_status.to_string());
        r.diagnostic_application = Some(verified.app);
        r.exe_name = verified.resolved.exe_name.clone();
        if surface_requested {
            r.surface_failure = Some(SurfaceReadFailure::AnchorUnavailable);
        }
        return r;
    }

    let (focused_elem, focused_meta) = focused_opt.unwrap();
    let focus_role = focused_meta.mapped.ax_role;
    let is_contenteditable_text = focused_meta.is_focused_editable_content();
    let effective_focus_text_role = if is_contenteditable_text {
        Some("AXTextArea")
    } else {
        focus_role
    };
    let diag_role = Some(normalize_gap_role(effective_focus_text_role));
    let is_text_role = TextSecurityGate::is_readable_text_role(effective_focus_text_role);
    let focus_security = classify_element_security_with_role(
        &focused_meta,
        effective_focus_text_role,
        &ticket.policy,
    );

    if focus_security == SecureStatus::Sensitive {
        state.invalidate();
        node_map.reset();
        baseline.reset();
        let mut r = ReadResult::failure(
            ticket.token.clone(),
            "policy-boundary",
            Some(GapDiagnostic::new(
                GapDiagnosticCode::SecureField,
                Some("AXSecureTextField"),
            )),
            start_ms,
            clock.unix_ms(),
        );
        r.enablement = Some(enablement);
        r.observer_status = Some(observer_status.to_string());
        if surface_requested {
            r.surface_failure = Some(SurfaceReadFailure::SecurityExcluded);
        }
        return r;
    }

    // If focused element is NOT a readable text field AND no surface was requested, fail cleanly.
    if !is_text_role && !surface_requested {
        let mut r = ReadResult::failure(
            ticket.token.clone(),
            "policy-boundary",
            Some(GapDiagnostic::new(
                GapDiagnosticCode::FocusedRoleNotText,
                diag_role,
            )),
            start_ms,
            clock.unix_ms(),
        );
        r.enablement = Some(enablement);
        r.observer_status = Some(observer_status.to_string());
        r.diagnostic_application = Some(verified.app);
        r.exe_name = verified.resolved.exe_name.clone();
        return r;
    }

    // If focused element IS a text role but failed strict/denylist security gate, abort.
    if is_text_role && !ticket.policy.allows_secure(focus_security) {
        let mut r = ReadResult::failure(
            ticket.token.clone(),
            "policy-boundary",
            Some(GapDiagnostic::new(
                GapDiagnosticCode::FieldSecurityUnknown,
                diag_role,
            )),
            start_ms,
            clock.unix_ms(),
        );
        r.enablement = Some(enablement);
        r.observer_status = Some(observer_status.to_string());
        r.diagnostic_application = Some(verified.app);
        r.exe_name = verified.resolved.exe_name.clone();
        return r;
    }

    // Pre-read boundary verification right before text extraction.
    if let Err((code, sf)) = reverify_window_boundary(uia, target, &verified, ticket, clock) {
        let mut r = ReadResult::failure(
            ticket.token.clone(),
            if matches!(
                code,
                GapDiagnosticCode::BrowserExcluded | GapDiagnosticCode::ApplicationNotAllowed
            ) {
                "policy-boundary"
            } else {
                "stale"
            },
            Some(GapDiagnostic::new(code, diag_role)),
            start_ms,
            clock.unix_ms(),
        );
        r.enablement = Some(enablement);
        r.observer_status = Some(observer_status.to_string());
        if surface_requested {
            r.surface_failure = sf;
        }
        return r;
    }

    let mut text_read: Option<TextRead> = None;
    let mut text_failure_code: Option<GapDiagnosticCode> = None;
    let mut charged_units = 0usize;

    if is_text_role {
        match read_focused_text(uia, &focused_elem, &focused_meta, ticket, clock) {
            Ok(tr) => {
                charged_units = charged_units.saturating_add(tr.charged_units());
                text_read = Some(tr);
            }
            Err(code) => {
                text_failure_code = Some(code);
            }
        }
    }

    // If no surface was requested and text failed, return failure immediately.
    if !surface_requested && text_read.is_none() {
        let code = text_failure_code.unwrap_or(GapDiagnosticCode::TextReadUnavailable);
        let reason = if code == GapDiagnosticCode::ReadDeadline {
            "stale"
        } else {
            "read-error"
        };
        let mut r = ReadResult::failure(
            ticket.token.clone(),
            reason,
            Some(GapDiagnostic::new(code, diag_role)),
            start_ms,
            clock.unix_ms(),
        );
        r.enablement = Some(enablement);
        r.observer_status = Some(observer_status.to_string());
        r.diagnostic_application = Some(verified.app);
        r.exe_name = verified.resolved.exe_name.clone();
        return r;
    }

    // Maintain stable session identity across reads on the same window + focused RuntimeId.
    let raw_hwnd = verified.hwnd.0 as isize;
    let focus_rid = focused_meta.runtime_id.clone();
    let changed = state.invalidated_focus
        || state.identity.is_none()
        || state.previous_window != Some(raw_hwnd)
        || state.previous_focus_runtime_id.as_ref() != Some(&focus_rid);
    if changed {
        state.serial += 1;
        baseline.reset();
        node_map.reset();
        let node_id = node_map
            .identifier(&focus_rid)
            .unwrap_or_else(generate_uuid_v4);
        state.identity = Some(WorkerSurfaceIdentity {
            session_id: state.session_id.clone(),
            window_id: generate_uuid_v4(),
            node_id,
            surface_id: generate_uuid_v4(),
            window_generation: state.serial,
            focus_generation: state.serial,
        });
    }
    state.invalidated_focus = false;
    state.previous_window = Some(raw_hwnd);
    state.previous_focus_runtime_id = Some(focus_rid.clone());

    let identity = state.identity.clone().unwrap();
    let mut selection_read: Option<SelectionReadResult> = None;
    let mut pending_surface: Option<PendingSurfaceCapture> = None;
    let mut surface_failure: Option<SurfaceReadFailure> = None;

    // Optional channels (selection + bounded surface tree) run inside optional phase budget.
    if !fast_only {
        let remaining_total = 8_192usize.saturating_sub(charged_units);
        if let Some(optional_deadline) =
            PhaseBudget::optional_deadline(clock.monotonic_ms(), ticket.deadline_monotonic_ms)
        {
            if ticket.policy.selection_capture == Some(true)
                && is_text_role
                && remaining_total > 0
                && clock.monotonic_ms() < optional_deadline
            {
                let mut sel_before_ipc = || -> Option<i64> {
                    let rem = optional_deadline.saturating_sub(clock.monotonic_ms());
                    (rem > 0).then_some(rem)
                };
                if let Ok(Some(pat)) =
                    uia.get_text_pattern_budgeted(&focused_elem, true, true, &mut sel_before_ipc)
                {
                    let sel_cap = remaining_total.min(ticket.policy.max_text_code_units);
                    if let Some(sel) = uia.read_text_pattern_selection_budgeted(
                        &pat,
                        sel_cap,
                        &mut sel_before_ipc,
                    ) {
                        charged_units = charged_units.saturating_add(utf16_len(&sel.text));
                        selection_read = Some(sel);
                    }
                }
            }

            if surface_requested {
                let scope = ticket.policy.capture_scope.as_deref().unwrap_or("window");
                let remaining_for_surface = 8_192usize.saturating_sub(charged_units);
                if clock.monotonic_ms() < optional_deadline && remaining_for_surface > 0 {
                    match capture_surface_tree(
                        uia,
                        registry,
                        target,
                        &verified,
                        ticket,
                        clock,
                        scope,
                        Some(&focused_elem),
                        Some(&focus_rid),
                        text_read.as_ref().map(|t| t.text.as_str()),
                        ticket.policy.max_tree_nodes.unwrap_or(64),
                        remaining_for_surface.min(ticket.policy.max_text_code_units),
                        optional_deadline,
                        start_ms,
                        is_terminal,
                    ) {
                        Ok((capture, units)) => {
                            charged_units = charged_units.saturating_add(units);
                            pending_surface = Some(capture);
                        }
                        Err(sf) => {
                            surface_failure = Some(sf);
                        }
                    }
                } else {
                    surface_failure = Some(SurfaceReadFailure::NotStartedBudget);
                }
            }
        } else if surface_requested {
            surface_failure = Some(SurfaceReadFailure::NotStartedBudget);
        }
    }

    // Fail closed immediately if surface traversal discovered a security exclusion (e.g.
    // root/focus became sensitive, private browser window, or policy changed), even if an
    // earlier focused text or selection read succeeded.
    if surface_failure == Some(SurfaceReadFailure::SecurityExcluded) {
        state.invalidate();
        node_map.reset();
        baseline.reset();
        let code = text_failure_code.unwrap_or(GapDiagnosticCode::SecureField);
        let mut r = ReadResult::failure(
            ticket.token.clone(),
            "policy-boundary",
            Some(GapDiagnostic::new(code, diag_role)),
            start_ms,
            clock.unix_ms(),
        );
        r.enablement = Some(enablement);
        r.observer_status = Some(observer_status.to_string());
        r.surface_failure = surface_failure;
        return r;
    }

    // If neither text nor surface nor selection succeeded, fail cleanly and roll back identity state.
    if text_read.is_none() && pending_surface.is_none() && selection_read.is_none() {
        state.invalidate();
        node_map.reset();
        baseline.reset();
        let code = text_failure_code.unwrap_or(GapDiagnosticCode::TextReadUnavailable);
        let mut r = ReadResult::failure(
            ticket.token.clone(),
            "read-error",
            Some(GapDiagnostic::new(code, diag_role)),
            start_ms,
            clock.unix_ms(),
        );
        r.enablement = Some(enablement);
        r.observer_status = Some(observer_status.to_string());
        r.surface_failure = surface_failure;
        r.diagnostic_application = Some(verified.app);
        r.exe_name = verified.resolved.exe_name.clone();
        return r;
    }

    // FINAL POST-READ REVALIDATION: desktop unlocked, HWND/PID/startTime/dual-ID, private chrome,
    // and focused RuntimeId + IsPassword == false! Roll back `SessionIdentityState` on EVERY abort.
    if let Err((code, sf)) = reverify_window_boundary(uia, target, &verified, ticket, clock) {
        state.invalidate();
        node_map.reset();
        baseline.reset();
        let mut r = ReadResult::failure(
            ticket.token.clone(),
            if matches!(
                code,
                GapDiagnosticCode::BrowserExcluded | GapDiagnosticCode::ApplicationNotAllowed
            ) {
                "policy-boundary"
            } else {
                "stale"
            },
            Some(GapDiagnostic::new(code, diag_role)),
            start_ms,
            clock.unix_ms(),
        );
        r.enablement = Some(enablement);
        r.observer_status = Some(observer_status.to_string());
        if surface_requested {
            r.surface_failure = sf;
        }
        return r;
    }

    if let Err((code, sf)) = reverify_focused_element(
        uia,
        &focused_elem,
        &focus_rid,
        focus_role,
        is_contenteditable_text,
        &verified,
        is_terminal,
    ) {
        state.invalidate();
        node_map.reset();
        baseline.reset();
        let mut r = ReadResult::failure(
            ticket.token.clone(),
            if code == GapDiagnosticCode::SecureField {
                "policy-boundary"
            } else {
                "stale"
            },
            Some(GapDiagnostic::new(code, diag_role)),
            start_ms,
            clock.unix_ms(),
        );
        r.enablement = Some(enablement);
        r.observer_status = Some(observer_status.to_string());
        if surface_requested {
            r.surface_failure = sf;
        }
        return r;
    }

    if charged_units > 8_192 {
        state.invalidate();
        node_map.reset();
        baseline.reset();
        let mut r = ReadResult::failure(
            ticket.token.clone(),
            "read-error",
            Some(GapDiagnostic::new(
                GapDiagnosticCode::TextResultInvalid,
                diag_role,
            )),
            start_ms,
            clock.unix_ms(),
        );
        r.enablement = Some(enablement);
        r.observer_status = Some(observer_status.to_string());
        r.diagnostic_application = Some(verified.app);
        r.exe_name = verified.resolved.exe_name.clone();
        return r;
    }

    if clock.monotonic_ms() >= ticket.deadline_monotonic_ms {
        state.invalidate();
        node_map.reset();
        baseline.reset();
        let mut r = ReadResult::failure(
            ticket.token.clone(),
            "stale",
            Some(GapDiagnostic::new(GapDiagnosticCode::ReadDeadline, diag_role)),
            start_ms,
            clock.unix_ms(),
        );
        r.enablement = Some(enablement);
        r.observer_status = Some(observer_status.to_string());
        if surface_requested {
            r.surface_failure = Some(SurfaceReadFailure::BoundaryIncomplete);
        }
        return r;
    }

    // Commit pending surface into SurfaceNodeMap + SurfaceBaseline only after ALL validations pass.
    let mut committed_surface: Option<SurfaceReadResult> = None;
    if let Some(capture) = pending_surface {
        let scope = ticket.policy.capture_scope.as_deref().unwrap_or("window");
        let mut proposed_map = node_map.clone();
        let reset_needed = proposed_map.prepare_commit(
            &capture.adapter_id,
            &capture.selected_handles(),
            Some((&focus_rid, &identity.node_id)),
        );
        if let Some(nodes) = capture.materialize_nodes(|k| proposed_map.identifier(k)) {
            if clock.monotonic_ms() < ticket.deadline_monotonic_ms {
                if reset_needed {
                    baseline.reset();
                }
                *node_map = proposed_map;
                committed_surface = Some(baseline.snapshot(
                    &identity.surface_id,
                    scope,
                    nodes,
                    capture.complete,
                    true,
                    capture.truncated,
                    capture.reasons,
                    capture.geometry,
                ));
            } else {
                surface_failure = Some(SurfaceReadFailure::BoundaryIncomplete);
            }
        } else {
            surface_failure = Some(SurfaceReadFailure::ProviderUnavailable);
        }
    }

    if text_read.is_none() && committed_surface.is_none() && selection_read.is_none() {
        state.invalidate();
        node_map.reset();
        baseline.reset();
        let mut r = ReadResult::failure(
            ticket.token.clone(),
            if surface_failure == Some(SurfaceReadFailure::BoundaryIncomplete) {
                "stale"
            } else {
                "read-error"
            },
            Some(GapDiagnostic::new(
                if surface_failure == Some(SurfaceReadFailure::BoundaryIncomplete) {
                    GapDiagnosticCode::ReadDeadline
                } else {
                    GapDiagnosticCode::TextReadUnavailable
                },
                diag_role,
            )),
            start_ms,
            clock.unix_ms(),
        );
        r.enablement = Some(enablement);
        r.observer_status = Some(observer_status.to_string());
        r.surface_failure = surface_failure;
        r.diagnostic_application = Some(verified.app);
        r.exe_name = verified.resolved.exe_name.clone();
        return r;
    }

    let mut end_ms = clock.unix_ms().max(start_ms);
    if let Some(ref surf) = committed_surface {
        for n in &surf.nodes {
            end_ms = end_ms.max(n.observed_at_ms);
            if let Some(bt) = n.bounds_observed_at_ms {
                end_ms = end_ms.max(bt);
            }
        }
        if let Some(ref g) = surf.geometry {
            end_ms = end_ms.max(g.observed_at_ms);
        }
    }
    ReadResult {
        token: ticket.token.clone(),
        application: Some(verified.app.clone()),
        diagnostic_application: Some(verified.app),
        exe_name: verified.resolved.exe_name.clone(),
        text: text_read,
        reason: None,
        diagnostic: None,
        enablement: Some(enablement),
        session_identity: Some(identity),
        surface: committed_surface,
        selection: selection_read,
        private_state: Some(verified.private_state.to_string()),
        observer_status: Some(observer_status.to_string()),
        focus_absent: None,
        surface_failure,
        capture_start_ms: start_ms,
        capture_end_ms: end_ms,
    }
}

#[allow(clippy::too_many_arguments)]
fn execute_unfocused_window_read(
    uia: &UiaClient,
    registry: &AdapterRegistry,
    target: ReadTarget<'_>,
    verified: &VerifiedTarget,
    ticket: &ReadTicket,
    clock: &dyn CollectorClock,
    start_ms: i64,
    enablement: AxEnablementResult,
    observer_status: &str,
    state: &mut SessionIdentityState,
    node_map: &mut SurfaceNodeMap,
    baseline: &mut SurfaceBaseline,
    is_terminal: bool,
) -> ReadResult {
    let fail = |reason: &str,
                code: GapDiagnosticCode,
                sf: Option<SurfaceReadFailure>,
                diag_app: Option<ApplicationIdentity>| {
        let mut r = ReadResult::failure(
            ticket.token.clone(),
            reason,
            Some(GapDiagnostic::new(code, None)),
            start_ms,
            clock.unix_ms(),
        );
        r.enablement = Some(enablement.clone());
        r.observer_status = Some(observer_status.to_string());
        r.surface_failure = sf;
        if diag_app.is_some() {
            r.exe_name = verified.resolved.exe_name.clone();
        }
        r.diagnostic_application = diag_app;
        r
    };

    let Some(optional_deadline) =
        PhaseBudget::optional_deadline(clock.monotonic_ms(), ticket.deadline_monotonic_ms)
    else {
        return fail(
            "stale",
            GapDiagnosticCode::ReadDeadline,
            Some(SurfaceReadFailure::NotStartedBudget),
            Some(verified.app.clone()),
        );
    };

    let raw_hwnd = verified.hwnd.0 as isize;
    let changed = state.invalidated_focus
        || state.identity.is_none()
        || state.previous_focus_runtime_id.is_some()
        || state.previous_window != Some(raw_hwnd);
    if changed {
        state.serial += 1;
        baseline.reset();
        node_map.reset();
        state.identity = Some(WorkerSurfaceIdentity {
            session_id: state.session_id.clone(),
            window_id: generate_uuid_v4(),
            node_id: generate_uuid_v4(),
            surface_id: generate_uuid_v4(),
            window_generation: state.serial,
            focus_generation: state.serial,
        });
    }
    let identity = state.identity.clone().unwrap();

    let capture = match capture_surface_tree(
        uia,
        registry,
        target,
        verified,
        ticket,
        clock,
        "window",
        None,
        None,
        None,
        ticket.policy.max_tree_nodes.unwrap_or(64),
        ticket.policy.max_text_code_units.min(8_192),
        optional_deadline,
        start_ms,
        is_terminal,
    ) {
        Ok((cap, _)) if !cap.nodes.is_empty() => cap,
        Ok(_) => {
            state.invalidate();
            node_map.reset();
            baseline.reset();
            return fail(
                "read-error",
                GapDiagnosticCode::TextReadUnavailable,
                Some(SurfaceReadFailure::ProviderUnavailable),
                Some(verified.app.clone()),
            );
        }
        Err(sf) => {
            state.invalidate();
            node_map.reset();
            baseline.reset();
            let code = if sf == SurfaceReadFailure::SecurityExcluded {
                GapDiagnosticCode::SecureField
            } else {
                GapDiagnosticCode::TextReadUnavailable
            };
            let diag_app = (sf != SurfaceReadFailure::SecurityExcluded)
                .then(|| verified.app.clone());
            return fail(sf.gap_reason(), code, Some(sf), diag_app);
        }
    };

    if let Err((code, sf)) = reverify_window_boundary(uia, target, verified, ticket, clock) {
        state.invalidate();
        node_map.reset();
        baseline.reset();
        let diag_app =
            (sf != Some(SurfaceReadFailure::SecurityExcluded)).then(|| verified.app.clone());
        return fail(
            if matches!(
                code,
                GapDiagnosticCode::BrowserExcluded | GapDiagnosticCode::ApplicationNotAllowed
            ) {
                "policy-boundary"
            } else {
                "stale"
            },
            code,
            sf,
            diag_app,
        );
    }

    let mut proposed_map = node_map.clone();
    let reset_needed =
        proposed_map.prepare_commit(&capture.adapter_id, &capture.selected_handles(), None);
    let Some(nodes) = capture.materialize_nodes(|k| proposed_map.identifier(k)) else {
        state.invalidate();
        node_map.reset();
        baseline.reset();
        return fail(
            "read-error",
            GapDiagnosticCode::TextResultInvalid,
            Some(SurfaceReadFailure::ProviderUnavailable),
            Some(verified.app.clone()),
        );
    };
    if clock.monotonic_ms() >= ticket.deadline_monotonic_ms {
        state.invalidate();
        node_map.reset();
        baseline.reset();
        return fail(
            "stale",
            GapDiagnosticCode::ReadDeadline,
            Some(SurfaceReadFailure::BoundaryIncomplete),
            Some(verified.app.clone()),
        );
    }

    if reset_needed {
        baseline.reset();
    }
    *node_map = proposed_map;
    let committed = baseline.snapshot(
        &identity.surface_id,
        "window",
        nodes,
        capture.complete,
        true,
        capture.truncated,
        capture.reasons,
        capture.geometry,
    );

    state.invalidated_focus = false;
    state.previous_window = Some(raw_hwnd);
    state.previous_focus_runtime_id = None;

    let mut end_ms = clock.unix_ms().max(start_ms);
    for n in &committed.nodes {
        end_ms = end_ms.max(n.observed_at_ms);
        if let Some(bt) = n.bounds_observed_at_ms {
            end_ms = end_ms.max(bt);
        }
    }
    if let Some(ref g) = committed.geometry {
        end_ms = end_ms.max(g.observed_at_ms);
    }
    ReadResult {
        token: ticket.token.clone(),
        application: Some(verified.app.clone()),
        diagnostic_application: Some(verified.app.clone()),
        exe_name: verified.resolved.exe_name.clone(),
        text: None,
        reason: None,
        diagnostic: Some(GapDiagnostic::new(
            GapDiagnosticCode::FocusedFieldUnavailable,
            None,
        )),
        enablement: Some(enablement),
        session_identity: Some(identity),
        surface: Some(committed),
        selection: None,
        private_state: Some(verified.private_state.to_string()),
        observer_status: Some(observer_status.to_string()),
        focus_absent: Some(true),
        surface_failure: None,
        capture_start_ms: start_ms,
        capture_end_ms: end_ms,
    }
}

/// Stateful live session worker invoked by `worker_ipc::run_session_worker_cli` (`--session-worker yes`).
///
/// Holds the MTA COM `IUIAutomation` instance, `SurfaceNodeMap`, `SurfaceBaseline`, and a
/// lightweight background `SetWinEventHook` message-pump thread for event-driven dirty wakeups.
///
/// Field drop order invariant: `uia` is declared BEFORE `_com` so COM pointers release prior to
/// `CoUninitialize()`.
pub struct LiveUiaSession {
    progress: Option<WorkerProgressClient>,
    registry: AdapterRegistry,
    watcher: Option<WinEventWatcher>,
    uia: Option<UiaClient>,
    _com: Option<ComGuard>,
    state: SessionIdentityState,
    node_map: SurfaceNodeMap,
    baseline: SurfaceBaseline,
    warmed_hwnds: WarmedHwndCache,
    dirty: bool,
    submit_dirty: bool,
    menu_tracking: Option<bool>,
    input_failure: Option<String>,
    secure_input_detected: bool,
}

impl LiveUiaSession {
    pub fn new(progress: Option<WorkerProgressClient>) -> Self {
        ensure_per_monitor_dpi_aware();
        let com = ComGuard::init_mta().ok();
        let uia = com.as_ref().and_then(|_| UiaClient::new().ok());
        let initial_pid = resolve_foreground_application()
            .map(|(_, app)| app.process_id)
            .unwrap_or(0);
        let watcher = Some(WinEventWatcher::start_for_pid(initial_pid));
        Self {
            progress,
            registry: AdapterRegistry::new(),
            watcher,
            uia,
            _com: com,
            state: SessionIdentityState::new(),
            node_map: SurfaceNodeMap::new(),
            baseline: SurfaceBaseline::new(),
            warmed_hwnds: WarmedHwndCache::new(),
            dirty: false,
            submit_dirty: false,
            menu_tracking: None,
            input_failure: None,
            secure_input_detected: false,
        }
    }

    pub fn is_com_ready(&self) -> bool {
        self.uia.is_some()
    }

    pub fn is_watcher_active(&self) -> bool {
        self.watcher
            .as_ref()
            .is_some_and(WinEventWatcher::is_active)
    }

    pub fn read(&mut self, ticket: &ReadTicket, clock: &dyn CollectorClock) -> ReadResult {
        if let Some(ref p) = self.progress {
            p.begin_request(ticket.valid_debug_request_id(), ticket.deadline_monotonic_ms);
        }
        let result = self.read_internal(ReadTarget::LiveForeground, ticket, clock);
        if let Some(ref p) = self.progress {
            p.finish_request();
        }
        result
    }

    /// Stateful test entrypoint preserving `SurfaceNodeMap`, `SurfaceBaseline`, and `WarmedHwndCache`
    /// across repeated reads on an explicit synthetic Win32 window (for testing `full` -> `diff`
    /// snapshots and single-warmup HWND caching).
    pub fn read_window_for_test(
        &mut self,
        window_hwnd: HWND,
        focused_hwnd: Option<HWND>,
        app_id_override: Option<&str>,
        desktop_override: Option<DesktopStatus>,
        ticket: &ReadTicket,
        clock: &dyn CollectorClock,
    ) -> ReadResult {
        self.read_internal(
            ReadTarget::ExplicitWindow {
                window_hwnd,
                focused_hwnd,
                app_id_override,
                resolved_override: None,
                desktop_override,
            },
            ticket,
            clock,
        )
    }

    fn read_internal(
        &mut self,
        target: ReadTarget<'_>,
        ticket: &ReadTicket,
        clock: &dyn CollectorClock,
    ) -> ReadResult {
        let start_ms = clock.unix_ms();
        let Some(ref uia) = self.uia else {
            return ReadResult::failure(
                ticket.token.clone(),
                "read-error",
                Some(GapDiagnostic::new(
                    GapDiagnosticCode::TextReadUnavailable,
                    None,
                )),
                start_ms,
                clock.unix_ms(),
            );
        };
        let observer_status = if self.is_watcher_active() {
            "best-effort"
        } else {
            "unavailable"
        };
        let result = execute_read_core(
            uia,
            &self.registry,
            target,
            ticket,
            clock,
            self.progress.as_ref(),
            observer_status,
            &mut self.state,
            &mut self.node_map,
            &mut self.baseline,
            Some(&mut self.warmed_hwnds),
        );
        if let Some(ref app) = result.application {
            if let Some(ref watcher) = self.watcher {
                watcher.set_target_pids(app.process_id, self.state.bound_raw_pid);
            }
        }
        result
    }

    pub fn poll(&mut self, _clock: &dyn CollectorClock) {
        if let Some(ref watcher) = self.watcher {
            if watcher.take_dirty() {
                self.dirty = true;
            }
            if watcher.take_focus_invalidated() {
                self.state.invalidate();
            }
        }
    }

    pub fn take_dirty(&mut self) -> bool {
        std::mem::take(&mut self.dirty)
    }

    pub fn take_submit_dirty(&mut self) -> bool {
        std::mem::take(&mut self.submit_dirty)
    }

    pub fn take_menu_tracking(&mut self) -> Option<bool> {
        self.menu_tracking.take()
    }

    pub fn input_failure(&self) -> Option<&str> {
        self.input_failure.as_deref()
    }

    pub fn secure_input_detected(&self) -> bool {
        self.secure_input_detected
    }

    /// Cleanly detach WinEvent hooks, stop background pump thread, and release COM interfaces
    /// for the inert retire handshake.
    pub fn retire_healthy(&mut self) -> bool {
        if let Some(ref p) = self.progress {
            p.finish_request();
        }
        if let Some(mut watcher) = self.watcher.take() {
            watcher.stop();
        }
        // Release all UIA COM interfaces before CoUninitialize runs on Drop.
        self.uia = None;
        self.baseline.reset();
        self.node_map.reset();
        self.warmed_hwnds.clear();
        self.state.invalidate();
        self.dirty = false;
        self.submit_dirty = false;
        self.menu_tracking = None;
        true
    }
}

impl Drop for LiveUiaSession {
    fn drop(&mut self) {
        if let Some(mut watcher) = self.watcher.take() {
            watcher.stop();
        }
        self.uia = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{MappedRole, ProtectedContentRead};

    fn sample_static_text_meta(
        name: Option<&str>,
        help_text: Option<&str>,
        is_password: ProtectedContentRead,
    ) -> UiaElementMetadata {
        UiaElementMetadata {
            runtime_id: RuntimeIdKey(vec![42, 7]),
            process_id: 1234,
            control_type: 50020,
            is_password,
            is_enabled: Some(true),
            is_control_element: Some(true),
            is_content_element: Some(true),
            is_offscreen: Some(false),
            is_keyboard_focusable: Some(false),
            has_keyboard_focus: Some(false),
            native_hwnd: None,
            name: name.map(str::to_string),
            localized_control_type: Some("text".to_string()),
            automation_id: None,
            class_name: None,
            aria_role: None,
            aria_properties: None,
            landmark_type: None,
            help_text: help_text.map(str::to_string),
            full_description: None,
            heading_level: 0,
            supports_text_pattern: false,
            supports_text_pattern2: false,
            supports_value_pattern: false,
            supports_scroll_pattern: false,
            value_is_read_only: None,
            is_read_only: true,
            logical_rect: None,
            subrole_read: SubroleRead::Value("AXStaticText".to_string()),
            mapped: MappedRole {
                ax_role: Some("AXStaticText"),
                subrole: None,
                category: "text",
            },
        }
    }

    #[test]
    fn sanitize_display_url_allows_http_https_strips_userinfo_and_rejects_unsafe_inputs() {
        assert_eq!(
            sanitize_display_url("https://www.figma.com/design/abc?node-id=1").as_deref(),
            Some("https://www.figma.com/design/abc?node-id=1")
        );
        assert_eq!(
            sanitize_display_url("HTTP://user:secret@example.com:8080/path?q=a@b").as_deref(),
            Some("HTTP://example.com:8080/path?q=a@b")
        );
        assert_eq!(
            sanitize_display_url("https://token@example.com/a").as_deref(),
            Some("https://example.com/a")
        );
        assert_eq!(
            sanitize_display_url("https://example.com/user?email=a@b#sec@1").as_deref(),
            Some("https://example.com/user?email=a@b#sec@1")
        );
        assert_eq!(
            sanitize_display_url("https://user:p@ss@example.com/user?email=a@b").as_deref(),
            Some("https://example.com/user?email=a@b")
        );
        assert_eq!(
            sanitize_display_url("  \u{200B}https://[::1]:3000/test\u{FEFF}  ").as_deref(),
            Some("https://[::1]:3000/test")
        );

        for rejected in [
            "",
            "   ",
            "\u{200B}",
            "\u{FEFF}  \u{200D}",
            "javascript:alert(1)",
            "JAVASCRIPT:alert(1)",
            "data:text/html,<h1>x</h1>",
            "file:///C:/secret.txt",
            "blob:https://example.com/123",
            "about:blank",
            "Just some document text",
            "https://",
            "https:///path",
            "https://user:pass@/path",
            "https://user:pass@:8080/path",
            "https://user:pass@\\evil.com",
            "https://example.com/a\nb",
            "https://example.com/a\r\nb",
            "https://example.com/\0",
            "https://example.com/\t",
            "https://foo bar/path",
            "https://\u{200B}/path",
            "https://example.com:notaport/path",
        ] {
            assert_eq!(
                sanitize_display_url(rejected),
                None,
                "expected URL to be rejected: {rejected:?}"
            );
        }
    }

    #[test]
    fn ax_static_text_bounded_range_probe_clamps_zero_ipc_fast_path() {
        let meta = sample_static_text_meta(
            Some("Hello 可见🙂 world 1234567890"),
            Some("Fallback description text"),
            ProtectedContentRead::Value(false),
        );

        // Standard policy uses full `node_cap`.
        assert_eq!(
            read_cached_static_text_bounded(&meta, 256, StaticTextPolicy::Standard, false),
            Some(UiaNodeTextOutcome::Text {
                value: "Hello 可见🙂 world 1234567890".to_string(),
                truncated: false,
                reasons: Vec::new(),
                is_unfocused_pua_static: false,
            })
        );

        // BoundedRangeProbe { max_units: 9 } MUST clamp the 0-IPC `meta.name` fast path to
        // `node_cap.min(9)` without bisecting the UTF-16 surrogate pair "🙂" at indices 8..10.
        assert_eq!(
            read_cached_static_text_bounded(
                &meta,
                256,
                StaticTextPolicy::BoundedRangeProbe { max_units: 9 },
                false,
            ),
            Some(UiaNodeTextOutcome::Text {
                value: "Hello 可见".to_string(),
                truncated: true,
                reasons: vec!["text-budget".to_string()],
                is_unfocused_pua_static: false,
            })
        );

        // Also clamps the 0-IPC `safe_description()` path when `name` is absent or unfocused PUA.
        let desc_only = sample_static_text_meta(
            None,
            Some("Fallback description text"),
            ProtectedContentRead::Value(false),
        );
        assert_eq!(
            read_cached_static_text_bounded(
                &desc_only,
                256,
                StaticTextPolicy::BoundedRangeProbe { max_units: 8 },
                false,
            ),
            Some(UiaNodeTextOutcome::Text {
                value: "Fallback".to_string(),
                truncated: true,
                reasons: vec!["text-budget".to_string()],
                is_unfocused_pua_static: false,
            })
        );

        let pua_with_desc = sample_static_text_meta(
            Some("\u{E000}\u{E001}"),
            Some("Fallback description text"),
            ProtectedContentRead::Value(false),
        );
        assert_eq!(
            read_cached_static_text_bounded(
                &pua_with_desc,
                256,
                StaticTextPolicy::BoundedRangeProbe { max_units: 8 },
                false,
            ),
            Some(UiaNodeTextOutcome::Text {
                value: "Fallback".to_string(),
                truncated: true,
                reasons: vec!["text-budget".to_string()],
                is_unfocused_pua_static: false,
            })
        );

        // Zero probe budget fails closed with Unavailable.
        assert_eq!(
            read_cached_static_text_bounded(
                &meta,
                256,
                StaticTextPolicy::BoundedRangeProbe { max_units: 0 },
                false,
            ),
            Some(UiaNodeTextOutcome::Unavailable)
        );

        // Sensitive metadata always fails closed on the 0-IPC fast path.
        let secret = sample_static_text_meta(
            Some("ShouldNeverRead"),
            None,
            ProtectedContentRead::Value(true),
        );
        assert_eq!(
            read_cached_static_text_bounded(&secret, 256, StaticTextPolicy::Standard, false),
            Some(UiaNodeTextOutcome::Unavailable)
        );
    }
}
