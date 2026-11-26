//! Core focused and unfocused-window UIA read execution pipelines and per-session identity state.
//!
//! Layer 2 module — imports only Layer 0 (`target_verify`, `text_read`) and Layer 1
//! (`surface_backend`, `input_text`).

use std::hint::black_box;

use history_contract::utf16_len;
use windows::Win32::Foundation::HWND;
use windows::Win32::UI::Accessibility::IUIAutomationElement;

use super::input_hook::qpc_ns_now;
use super::input_text::{
    is_sensitive_or_es_password_meta, BoundInputField, InputTextSession,
};
use super::surface_backend::capture_surface_tree;
use super::target_verify::{
    classify_element_security_with_role, element_belongs_to_window, is_owned_popup_hwnd,
    read_window_title_ephemeral, resolve_application_identity_for_hwnd, reverify_focused_element,
    reverify_window_boundary, verify_target_pre_read, ReadTarget, VerifiedChromeWindowProof,
    VerifiedTarget,
};
use super::text_read::read_focused_text;
use crate::adapters::AdapterRegistry;
use crate::desktop::assess_windows_desktop;
use crate::input_text_core::{
    InputTextContext, InputTextFieldRole, InputTextGapReason, InputTextGapRecord, InputTextLimits,
    InputTextPrivateState, InputTextRecord,
};
use crate::policy::{
    normalize_gap_role, BrowserGate, PhaseBudget, ResolvedAppIdentity, TextSecurityGate,
};
use crate::protocol_model::{
    generate_uuid_v4, ApplicationIdentity, AxEnablementResult, CollectorClock, DesktopStatus,
    GapDiagnostic, GapDiagnosticCode, SecureStatus, SelectionReadResult, SurfaceBaseline,
    SurfaceReadFailure, SurfaceReadResult, TargetIdentity, TextRead, WorkerSurfaceIdentity,
};
use crate::uia_com::{
    warmup_window_uia, UiaCallError, UiaClient, UiaElementMetadata, WarmedHwndCache,
};
use crate::uia_traversal::{PendingSurfaceCapture, RuntimeIdKey, SurfaceNodeMap};
use crate::worker_ipc::{ReadResult, ReadTicket, WorkerProgressClient};

fn invalidate_input_session(
    input_session: &mut Option<&mut InputTextSession>,
    uia: Option<&UiaClient>,
    deadline_ms: i64,
    clock: &dyn CollectorClock,
) {
    if let Some(inp) = input_session.as_deref_mut() {
        inp.invalidate(uia, Some(deadline_ms), clock);
    }
    if let Some(u) = uia {
        u.apply_timeouts(deadline_ms.saturating_sub(clock.monotonic_ms()));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BarrierDrainVerdict {
    Proceed,
    AbortPolicyBoundary,
    AbortStaleFocus,
    SkipSyncSecureInput,
}

fn evaluate_barrier_drain_verdict(
    was_armed_before_drain: bool,
    is_armed_after_drain: bool,
    drained_gaps: &[InputTextGapRecord],
    reverify_focus_epoch: u64,
    current_focus_epoch: u64,
    secure_input_detected: bool,
) -> BarrierDrainVerdict {
    if drained_gaps.iter().any(|g| {
        matches!(
            g.reason,
            InputTextGapReason::PolicyBoundary | InputTextGapReason::FieldSecurityUnknown
        )
    }) {
        return BarrierDrainVerdict::AbortPolicyBoundary;
    }
    if secure_input_detected {
        return BarrierDrainVerdict::SkipSyncSecureInput;
    }
    let has_boundary_gap = drained_gaps.iter().any(|g| {
        matches!(
            g.reason,
            InputTextGapReason::TargetMismatch
                | InputTextGapReason::RoleNotEditable
                | InputTextGapReason::Stale
        )
    });
    let disarmed_during_drain = was_armed_before_drain && !is_armed_after_drain;
    if has_boundary_gap
        || current_focus_epoch != reverify_focus_epoch
        || disarmed_during_drain
    {
        return BarrierDrainVerdict::AbortStaleFocus;
    }
    BarrierDrainVerdict::Proceed
}

fn zeroize_input_records(records: Vec<InputTextRecord>) {
    for rec in records {
        let mut bytes = rec.text.into_bytes();
        bytes.fill(0);
        black_box(&bytes);
    }
}

pub(super) struct SessionIdentityState {
    session_id: String,
    pub(super) bound_application: Option<ApplicationIdentity>,
    pub(super) bound_resolved: Option<ResolvedAppIdentity>,
    pub(super) bound_hwnd: Option<HWND>,
    pub(super) bound_dpi: u32,
    pub(super) bound_private_state: &'static str,
    pub(super) bound_raw_pid: u32,
    verified_chrome_proof: Option<VerifiedChromeWindowProof>,
    identity: Option<WorkerSurfaceIdentity>,
    previous_window: Option<isize>,
    previous_focus_runtime_id: Option<RuntimeIdKey>,
    invalidated_focus: bool,
    serial: i64,
}

impl SessionIdentityState {
    pub(super) fn new() -> Self {
        Self {
            session_id: generate_uuid_v4(),
            bound_application: None,
            bound_resolved: None,
            bound_hwnd: None,
            bound_dpi: 96,
            bound_private_state: "normal",
            bound_raw_pid: 0,
            verified_chrome_proof: None,
            identity: None,
            previous_window: None,
            previous_focus_runtime_id: None,
            invalidated_focus: false,
            serial: 0,
        }
    }

    pub(super) fn invalidate(&mut self) {
        self.invalidated_focus = true;
        self.verified_chrome_proof = None;
        self.identity = None;
        self.previous_window = None;
        self.previous_focus_runtime_id = None;
    }

    pub(super) fn clear_menu_binding(&mut self) {
        self.bound_hwnd = None;
        self.bound_resolved = None;
        self.bound_dpi = 96;
        self.bound_private_state = "normal";
        self.verified_chrome_proof = None;
    }
}

fn should_preserve_menu_binding_on_reverify_failure(
    target: ReadTarget<'_>,
    verified: &VerifiedTarget,
    code: GapDiagnosticCode,
) -> bool {
    if code != GapDiagnosticCode::FocusChanged {
        return false;
    }
    match target {
        ReadTarget::LiveForeground => {
            if assess_windows_desktop().status != DesktopStatus::Unlocked {
                return false;
            }
            // SAFETY: Standard read-only foreground window lookup.
            let fg = unsafe { windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow() };
            if fg.0.is_null() || (fg != verified.hwnd && !is_owned_popup_hwnd(fg, verified.hwnd)) {
                return false;
            }
            let identity_ok = resolve_application_identity_for_hwnd(fg, None, None)
                .is_some_and(|(_, app, res)| app == verified.app && res == verified.resolved);
            if !identity_ok {
                return false;
            }
            let Some(title) = read_window_title_ephemeral(verified.hwnd) else {
                return false;
            };
            !BrowserGate::is_private_window_title(&title)
        }
        ReadTarget::ExplicitWindow { .. } => true,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn execute_read_core(
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
    mut input_session: Option<&mut InputTextSession>,
    ensure_input_hook: Option<&mut dyn FnMut(&mut InputTextSession) -> bool>,
    hook_is_healthy: bool,
    focus_epoch_hooks_active: bool,
) -> ReadResult {
    let start_ms = clock.unix_ms();
    let fast_only = ticket.focused_fast_only == Some(true);
    let surface_requested = !fast_only
        && matches!(
            ticket.policy.capture_scope.as_deref(),
            Some("region" | "window")
        );

    if ticket.policy.input_text == Some(true) {
        if let Some(inp) = input_session.as_deref_mut() {
            if let Some(failure) = inp.input_failure() {
                let failure_str = failure.to_string();
                state.invalidate();
                state.clear_menu_binding();
                node_map.reset();
                baseline.reset();
                return ReadResult::failure(
                    ticket.token.clone(),
                    failure_str,
                    None,
                    start_ms,
                    clock.unix_ms(),
                );
            }
            if inp.was_hook_attempted() && !hook_is_healthy {
                inp.mark_input_failure("input-monitoring-disabled");
                inp.invalidate(Some(uia), Some(ticket.deadline_monotonic_ms), clock);
                state.invalidate();
                state.clear_menu_binding();
                node_map.reset();
                baseline.reset();
                return ReadResult::failure(
                    ticket.token.clone(),
                    "input-monitoring-disabled",
                    None,
                    start_ms,
                    clock.unix_ms(),
                );
            }
        }
    } else {
        invalidate_input_session(
            &mut input_session,
            Some(uia),
            ticket.deadline_monotonic_ms,
            clock,
        );
    }

    let pre_read_focus_epoch = focus_epoch_hooks_active
        .then(|| input_session.as_deref().map(InputTextSession::current_focus_epoch))
        .flatten();
    let mut verified = match verify_target_pre_read(
        uia,
        target,
        ticket,
        registry,
        clock,
        start_ms,
        surface_requested,
        state.verified_chrome_proof.as_ref(),
        pre_read_focus_epoch,
    ) {
        Ok(v) => v,
        Err(res) => {
            invalidate_input_session(
                &mut input_session,
                Some(uia),
                ticket.deadline_monotonic_ms,
                clock,
            );
            state.clear_menu_binding();
            if res.reason.as_deref() == Some("policy-boundary")
                || matches!(
                    res.diagnostic.map(|d| d.code),
                    Some(
                        GapDiagnosticCode::ApplicationNotAllowed
                            | GapDiagnosticCode::ApplicationUnavailable
                            | GapDiagnosticCode::BrowserExcluded
                            | GapDiagnosticCode::DesktopUnavailable
                            | GapDiagnosticCode::InvalidSamplingPolicy
                    )
                )
            {
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
            invalidate_input_session(
                &mut input_session,
                Some(uia),
                ticket.deadline_monotonic_ms,
                clock,
            );
            state.invalidate();
            state.clear_menu_binding();
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
    state.bound_hwnd = Some(verified.hwnd);
    state.bound_resolved = Some(verified.resolved.clone());
    state.bound_dpi = verified.dpi;
    state.bound_private_state = verified.private_state;
    let post_verify_focus_epoch = focus_epoch_hooks_active
        .then(|| input_session.as_deref().map(InputTextSession::current_focus_epoch))
        .flatten();
    if let (true, true, Some(epoch)) = (
        matches!(target, ReadTarget::LiveForeground),
        verified.chrome_verified_normal,
        verified.chrome_verified_focus_epoch,
    ) {
        if post_verify_focus_epoch == Some(epoch) {
            state.verified_chrome_proof = Some(VerifiedChromeWindowProof {
                hwnd_raw: verified.hwnd.0 as isize,
                effective_pid: verified.app.process_id,
                process_start_time: verified.app.process_start_time.clone(),
                focus_epoch: epoch,
                verified_at_mono_ms: verified.chrome_verified_at_mono_ms,
            });
        } else {
            state.verified_chrome_proof = None;
        }
    } else {
        state.verified_chrome_proof = None;
    }

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
        invalidate_input_session(
            &mut input_session,
            Some(uia),
            ticket.deadline_monotonic_ms,
            clock,
        );
        state.clear_menu_binding();
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

    // Snapshot focus epoch strictly BEFORE resolving focused UIA element so any intra-window
    // focus switch (e.g. Tab into a password box) during text/surface extraction is caught at
    // post-read revalidation.
    let pre_focus_epoch = focus_epoch_hooks_active
        .then(|| input_session.as_deref().map(InputTextSession::current_focus_epoch))
        .flatten();

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
            invalidate_input_session(
                &mut input_session,
                Some(uia),
                ticket.deadline_monotonic_ms,
                clock,
            );
            state.invalidate();
            state.clear_menu_binding();
            node_map.reset();
            baseline.reset();
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
                invalidate_input_session(
                    &mut input_session,
                    Some(uia),
                    ticket.deadline_monotonic_ms,
                    clock,
                );
                state.invalidate();
                state.clear_menu_binding();
                node_map.reset();
                baseline.reset();
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
                if is_sensitive_or_es_password_meta(&meta) {
                    invalidate_input_session(
                        &mut input_session,
                        Some(uia),
                        ticket.deadline_monotonic_ms,
                        clock,
                    );
                    state.invalidate();
                    state.clear_menu_binding();
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
        invalidate_input_session(
            &mut input_session,
            Some(uia),
            ticket.deadline_monotonic_ms,
            clock,
        );
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
        invalidate_input_session(
            &mut input_session,
            Some(uia),
            ticket.deadline_monotonic_ms,
            clock,
        );
        state.invalidate();
        state.clear_menu_binding();
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
    // Note: keep `state.bound_*` intact so `MenuActionSession` stays bound on non-text controls,
    // while invalidating `state` identity/focus tracking so worker & engine generations stay synced.
    if !is_text_role && !surface_requested {
        invalidate_input_session(
            &mut input_session,
            Some(uia),
            ticket.deadline_monotonic_ms,
            clock,
        );
        state.invalidate();
        node_map.reset();
        baseline.reset();
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
        r.verified_normal_browser = verified.verified_normal_browser;
        return r;
    }

    // If focused element IS a text role but failed strict/denylist security gate, abort.
    if is_text_role && !ticket.policy.allows_secure(focus_security) {
        invalidate_input_session(
            &mut input_session,
            Some(uia),
            ticket.deadline_monotonic_ms,
            clock,
        );
        state.invalidate();
        state.clear_menu_binding();
        node_map.reset();
        baseline.reset();
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
    let pre_extract_focus_epoch = focus_epoch_hooks_active
        .then(|| input_session.as_deref().map(InputTextSession::current_focus_epoch))
        .flatten();
    match reverify_window_boundary(
        uia,
        target,
        &verified,
        ticket,
        clock,
        pre_extract_focus_epoch,
    ) {
        Ok(outcome) => {
            if outcome.chrome_verified_normal
                && outcome.chrome_verified_at_mono_ms >= verified.chrome_verified_at_mono_ms
            {
                let post_pre_extract_epoch = focus_epoch_hooks_active
                    .then(|| input_session.as_deref().map(InputTextSession::current_focus_epoch))
                    .flatten();
                verified.chrome_verified_normal = true;
                verified.chrome_verified_at_mono_ms = outcome.chrome_verified_at_mono_ms;
                verified.chrome_verified_focus_epoch = if post_pre_extract_epoch
                    == pre_extract_focus_epoch
                {
                    pre_extract_focus_epoch
                } else {
                    None
                };
            }
        }
        Err((code, sf)) => {
            invalidate_input_session(
                &mut input_session,
                Some(uia),
                ticket.deadline_monotonic_ms,
                clock,
            );
            state.invalidate();
            node_map.reset();
            baseline.reset();
            if sf == Some(SurfaceReadFailure::BoundaryUnverified)
                || !should_preserve_menu_binding_on_reverify_failure(target, &verified, code)
            {
                state.clear_menu_binding();
            }
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
    }

    // P1-2: Record the causal barrier QPC cutoff strictly BEFORE reading text/selection/surface so
    // keystrokes typed concurrently during snapshot extraction are deferred to the next cycle
    // instead of appearing before an older snapshot that does not yet contain them.
    let barrier_qpc_ns = qpc_ns_now();

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
        invalidate_input_session(
            &mut input_session,
            Some(uia),
            ticket.deadline_monotonic_ms,
            clock,
        );
        let code = text_failure_code.unwrap_or(GapDiagnosticCode::TextReadUnavailable);
        if code == GapDiagnosticCode::ReadDeadline {
            state.clear_menu_binding();
        }
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
        invalidate_input_session(
            &mut input_session,
            Some(uia),
            ticket.deadline_monotonic_ms,
            clock,
        );
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

    // Optional channels (selection + bounded surface tree) run inside optional phase budget,
    // reserving 2,048 UTF-16 code units ahead of selection & surface when `input.text` is enabled.
    if !fast_only {
        let input_reserve = if ticket.policy.input_text == Some(true) {
            InputTextLimits::MAX_CODE_UNITS
        } else {
            0
        };
        let remaining_total = 8_192usize
            .saturating_sub(charged_units)
            .saturating_sub(input_reserve);
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
                let remaining_for_surface = 8_192usize
                    .saturating_sub(charged_units)
                    .saturating_sub(input_reserve);
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
        invalidate_input_session(
            &mut input_session,
            Some(uia),
            ticket.deadline_monotonic_ms,
            clock,
        );
        state.invalidate();
        state.clear_menu_binding();
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
        invalidate_input_session(
            &mut input_session,
            Some(uia),
            ticket.deadline_monotonic_ms,
            clock,
        );
        state.invalidate();
        let code = text_failure_code.unwrap_or(GapDiagnosticCode::TextReadUnavailable);
        if code == GapDiagnosticCode::ReadDeadline
            || matches!(
                surface_failure,
                Some(
                    SurfaceReadFailure::SecurityExcluded
                        | SurfaceReadFailure::BoundaryUnverified
                        | SurfaceReadFailure::BoundaryMismatch
                        | SurfaceReadFailure::BoundaryAxFailed
                        | SurfaceReadFailure::BoundaryIncomplete
                )
            )
        {
            state.clear_menu_binding();
        }
        node_map.reset();
        baseline.reset();
        let reason = if code == GapDiagnosticCode::ReadDeadline
            || matches!(
                surface_failure,
                Some(
                    SurfaceReadFailure::BoundaryIncomplete | SurfaceReadFailure::BoundaryMismatch
                )
            ) {
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
        r.surface_failure = surface_failure;
        r.diagnostic_application = Some(verified.app);
        r.exe_name = verified.resolved.exe_name.clone();
        return r;
    }

    // Snapshot monotonic focus epoch right BEFORE final post-read boundary & focus revalidation
    // and compare against `pre_focus_epoch` (P1-1: catch intra-window Tab into a password box
    // during text/surface extraction!).
    let reverify_focus_epoch_opt = focus_epoch_hooks_active
        .then(|| input_session.as_deref().map(InputTextSession::current_focus_epoch))
        .flatten();
    if pre_focus_epoch.is_some() && reverify_focus_epoch_opt != pre_focus_epoch {
        invalidate_input_session(
            &mut input_session,
            Some(uia),
            ticket.deadline_monotonic_ms,
            clock,
        );
        state.invalidate();
        if !should_preserve_menu_binding_on_reverify_failure(
            target,
            &verified,
            GapDiagnosticCode::FocusChanged,
        ) {
            state.clear_menu_binding();
        }
        node_map.reset();
        baseline.reset();
        let mut r = ReadResult::failure(
            ticket.token.clone(),
            "stale",
            Some(GapDiagnostic::new(
                GapDiagnosticCode::FocusChanged,
                diag_role,
            )),
            start_ms,
            clock.unix_ms(),
        );
        r.enablement = Some(enablement);
        r.observer_status = Some(observer_status.to_string());
        if surface_requested {
            r.surface_failure = Some(SurfaceReadFailure::BoundaryMismatch);
        }
        return r;
    }
    let reverify_focus_epoch = reverify_focus_epoch_opt.unwrap_or(0);

    // FINAL POST-READ REVALIDATION: desktop unlocked, HWND/PID/startTime/dual-ID, private chrome,
    // and focused RuntimeId + IsPassword == false + strict security! Roll back on EVERY abort.
    let post_outcome = match reverify_window_boundary(
        uia,
        target,
        &verified,
        ticket,
        clock,
        reverify_focus_epoch_opt,
    ) {
        Ok(outcome) => outcome,
        Err((code, sf)) => {
            invalidate_input_session(
                &mut input_session,
                Some(uia),
                ticket.deadline_monotonic_ms,
                clock,
            );
            state.invalidate();
            if sf == Some(SurfaceReadFailure::BoundaryUnverified)
                || !should_preserve_menu_binding_on_reverify_failure(target, &verified, code)
            {
                state.clear_menu_binding();
            }
            node_map.reset();
            baseline.reset();
            let mut r = ReadResult::failure(
                ticket.token.clone(),
                if matches!(
                    code,
                    GapDiagnosticCode::BrowserExcluded
                        | GapDiagnosticCode::ApplicationNotAllowed
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
    };
    let post_verified_browser = post_outcome.verified_normal_browser;
    let effective_chrome_verified_normal = post_outcome.chrome_verified_normal;
    let effective_chrome_verified_at_mono_ms = post_outcome.chrome_verified_at_mono_ms;
    if matches!(target, ReadTarget::LiveForeground)
        && effective_chrome_verified_normal
        && reverify_focus_epoch_opt.is_some()
        && input_session
            .as_deref()
            .map(InputTextSession::current_focus_epoch)
            == reverify_focus_epoch_opt
    {
        state.verified_chrome_proof = Some(VerifiedChromeWindowProof {
            hwnd_raw: verified.hwnd.0 as isize,
            effective_pid: verified.app.process_id,
            process_start_time: verified.app.process_start_time.clone(),
            focus_epoch: reverify_focus_epoch,
            verified_at_mono_ms: effective_chrome_verified_at_mono_ms,
        });
    } else {
        state.verified_chrome_proof = None;
    }

    let refreshed_focus_meta = match reverify_focused_element(
        uia,
        target,
        &focused_elem,
        &focus_rid,
        focus_role,
        is_contenteditable_text,
        &verified,
        is_terminal,
    ) {
        Ok(m) => m,
        Err((code, sf)) => {
            invalidate_input_session(
                &mut input_session,
                Some(uia),
                ticket.deadline_monotonic_ms,
                clock,
            );
            state.invalidate();
            if code == GapDiagnosticCode::SecureField
                || sf == Some(SurfaceReadFailure::BoundaryAxFailed)
                || !should_preserve_menu_binding_on_reverify_failure(target, &verified, code)
            {
                state.clear_menu_binding();
            }
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
    };

    // P1-1: Re-run full `classify_element_security_with_role` on refreshed post-read metadata so a
    // `ProtectedContentRead::Failure` on refresh fails closed in strict mode instead of reusing
    // the pre-read `Safe` status!
    let final_focus_security = classify_element_security_with_role(
        &refreshed_focus_meta,
        effective_focus_text_role,
        &ticket.policy,
    );
    if is_sensitive_or_es_password_meta(&refreshed_focus_meta)
        || final_focus_security == SecureStatus::Sensitive
    {
        invalidate_input_session(
            &mut input_session,
            Some(uia),
            ticket.deadline_monotonic_ms,
            clock,
        );
        state.invalidate();
        state.clear_menu_binding();
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
    if is_text_role && !ticket.policy.allows_secure(final_focus_security) {
        invalidate_input_session(
            &mut input_session,
            Some(uia),
            ticket.deadline_monotonic_ms,
            clock,
        );
        state.invalidate();
        state.clear_menu_binding();
        node_map.reset();
        baseline.reset();
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
        if surface_requested {
            r.surface_failure = Some(SurfaceReadFailure::SecurityExcluded);
        }
        return r;
    }

    if charged_units > 8_192 {
        invalidate_input_session(
            &mut input_session,
            Some(uia),
            ticket.deadline_monotonic_ms,
            clock,
        );
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
        invalidate_input_session(
            &mut input_session,
            Some(uia),
            ticket.deadline_monotonic_ms,
            clock,
        );
        state.invalidate();
        state.clear_menu_binding();
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

    // Causal `input.text` read-barrier drain & editable-field binding sync (runs AFTER final
    // post-read boundary & focus revalidation and BEFORE committing `pending_surface`).
    let mut input_records: Vec<InputTextRecord> = Vec::new();
    let mut input_gaps: Vec<InputTextGapRecord> = Vec::new();

    let editable_role = if !refreshed_focus_meta.is_read_only
        && ticket.policy.allows_secure(final_focus_security)
        && !focus_rid.is_empty()
    {
        match effective_focus_text_role {
            Some("AXTextField") => Some(InputTextFieldRole::TextField),
            Some("AXTextArea") => Some(InputTextFieldRole::TextArea),
            _ => None,
        }
    } else {
        None
    };

    if ticket.policy.input_text == Some(true) {
        if let Some(inp) = input_session.as_deref_mut() {
            if !focus_epoch_hooks_active {
                // P1-4: Fail closed — never arm `InputTextSession` when foreground/focus WinEvent
                // hooks are inactive (frozen `focus_epoch` cannot fence intra-window focus switches).
                inp.invalidate(Some(uia), Some(ticket.deadline_monotonic_ms), clock);
            } else if let Some(role) = editable_role {
                let hook_ok = match ensure_input_hook {
                    Some(starter) => starter(inp),
                    None => hook_is_healthy,
                };
                if !hook_ok || inp.input_failure().is_some() {
                    let failure_reason = inp
                        .input_failure()
                        .unwrap_or("input-monitoring-unavailable")
                        .to_string();
                    inp.mark_input_failure(&failure_reason);
                    inp.invalidate(Some(uia), Some(ticket.deadline_monotonic_ms), clock);
                    state.invalidate();
                    state.clear_menu_binding();
                    node_map.reset();
                    baseline.reset();
                    return ReadResult::failure(
                        ticket.token.clone(),
                        failure_reason,
                        None,
                        start_ms,
                        clock.unix_ms(),
                    );
                }

                let private_state_enum = if verified.private_state == "user-authorized" {
                    InputTextPrivateState::UserAuthorized
                } else {
                    InputTextPrivateState::Normal
                };
                let input_context = InputTextContext {
                    target: TargetIdentity {
                        device_id: ticket.device_id.clone(),
                        os_session_id: ticket.os_session_id.clone(),
                        desktop_id: ticket.desktop_id.clone(),
                        process_id: verified.app.process_id,
                        process_start_time: verified.app.process_start_time.clone(),
                        application_id: verified.app.application_id.clone(),
                        window_id: identity.window_id.clone(),
                        window_generation: identity.window_generation,
                    },
                    surface_id: identity.surface_id.clone(),
                    capture_epoch: ticket.capture_epoch,
                    foreground_generation: ticket.foreground_generation.unwrap_or(0)
                        + i64::from(changed),
                    focus_generation: ticket.focus_generation.unwrap_or(0) + i64::from(changed),
                    policy_revision: ticket.policy_revision,
                    field_security_mode: ticket.policy.field_security_mode().to_string(),
                    secure_status: final_focus_security,
                    private_state: private_state_enum,
                    exe_name: verified.resolved.exe_name.clone(),
                };

                if !changed {
                    if effective_chrome_verified_normal {
                        inp.refresh_verified_chrome_proof(
                            verified.hwnd,
                            &verified.app,
                            &verified.resolved,
                            reverify_focus_epoch,
                            effective_chrome_verified_at_mono_ms,
                        );
                    }
                    let was_armed_before_drain = inp.is_context_armed();
                    let remaining_for_input = 8_192usize.saturating_sub(charged_units);
                    let (drained_records, drained_gaps) = inp.drain_at_barrier(
                        uia,
                        registry,
                        &ticket.policy,
                        remaining_for_input,
                        barrier_qpc_ns,
                        ticket.deadline_monotonic_ms,
                        clock,
                    );
                    uia.apply_timeouts(
                        ticket
                            .deadline_monotonic_ms
                            .saturating_sub(clock.monotonic_ms()),
                    );
                    match evaluate_barrier_drain_verdict(
                        was_armed_before_drain,
                        inp.is_context_armed(),
                        &drained_gaps,
                        reverify_focus_epoch,
                        inp.current_focus_epoch(),
                        inp.secure_input_detected(),
                    ) {
                        BarrierDrainVerdict::AbortPolicyBoundary => {
                            zeroize_input_records(drained_records);
                            inp.invalidate(Some(uia), Some(ticket.deadline_monotonic_ms), clock);
                            state.invalidate();
                            state.clear_menu_binding();
                            node_map.reset();
                            baseline.reset();
                            let code = if drained_gaps
                                .iter()
                                .any(|g| g.reason == InputTextGapReason::FieldSecurityUnknown)
                                && !drained_gaps
                                    .iter()
                                    .any(|g| g.reason == InputTextGapReason::PolicyBoundary)
                            {
                                GapDiagnosticCode::FieldSecurityUnknown
                            } else {
                                GapDiagnosticCode::SecureField
                            };
                            let mut r = ReadResult::failure(
                                ticket.token.clone(),
                                "policy-boundary",
                                Some(GapDiagnostic::new(code, diag_role)),
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
                        BarrierDrainVerdict::AbortStaleFocus => {
                            zeroize_input_records(drained_records);
                            inp.invalidate(Some(uia), Some(ticket.deadline_monotonic_ms), clock);
                            state.invalidate();
                            if !should_preserve_menu_binding_on_reverify_failure(
                                target,
                                &verified,
                                GapDiagnosticCode::FocusChanged,
                            ) {
                                state.clear_menu_binding();
                            }
                            node_map.reset();
                            baseline.reset();
                            let mut r = ReadResult::failure(
                                ticket.token.clone(),
                                "stale",
                                Some(GapDiagnostic::new(
                                    GapDiagnosticCode::FocusChanged,
                                    diag_role,
                                )),
                                start_ms,
                                clock.unix_ms(),
                            );
                            r.enablement = Some(enablement);
                            r.observer_status = Some(observer_status.to_string());
                            if surface_requested {
                                r.surface_failure = Some(SurfaceReadFailure::BoundaryMismatch);
                            }
                            return r;
                        }
                        BarrierDrainVerdict::SkipSyncSecureInput => {
                            zeroize_input_records(drained_records);
                            inp.invalidate(Some(uia), Some(ticket.deadline_monotonic_ms), clock);
                            state.invalidate();
                            state.clear_menu_binding();
                            node_map.reset();
                            baseline.reset();
                            let mut r = ReadResult::failure(
                                ticket.token.clone(),
                                "secure-input-active",
                                None,
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
                        BarrierDrainVerdict::Proceed => {
                            for rec in &drained_records {
                                charged_units = charged_units.saturating_add(rec.utf16_len());
                            }
                            input_records = drained_records;
                            input_gaps = drained_gaps;
                        }
                    }
                } else if inp.current_focus_epoch() != reverify_focus_epoch {
                    inp.invalidate(Some(uia), Some(ticket.deadline_monotonic_ms), clock);
                    state.invalidate();
                    if !should_preserve_menu_binding_on_reverify_failure(
                        target,
                        &verified,
                        GapDiagnosticCode::FocusChanged,
                    ) {
                        state.clear_menu_binding();
                    }
                    node_map.reset();
                    baseline.reset();
                    let mut r = ReadResult::failure(
                        ticket.token.clone(),
                        "stale",
                        Some(GapDiagnostic::new(
                            GapDiagnosticCode::FocusChanged,
                            diag_role,
                        )),
                        start_ms,
                        clock.unix_ms(),
                    );
                    r.enablement = Some(enablement);
                    r.observer_status = Some(observer_status.to_string());
                    if surface_requested {
                        r.surface_failure = Some(SurfaceReadFailure::BoundaryMismatch);
                    }
                    return r;
                }

                if !inp.secure_input_detected() {
                    let is_browser = BrowserGate::is_known_browser_identity(&verified.resolved)
                        || BrowserGate::should_block_private_windows_identity(
                            &verified.resolved,
                            verified.spec.block_private_windows,
                        );
                    inp.sync_binding(
                        uia,
                        BoundInputField {
                            hwnd: verified.hwnd,
                            raw_pid: verified.raw_pid,
                            app: verified.app.clone(),
                            resolved: verified.resolved.clone(),
                            is_browser,
                            dpi: verified.dpi,
                            is_terminal,
                            focus_runtime_id: focus_rid.clone(),
                            focus_role: role,
                            context: input_context,
                            policy: ticket.policy.clone(),
                            expected_focus_epoch: reverify_focus_epoch,
                            supports_text_edit_pattern: refreshed_focus_meta
                                .supports_text_edit_pattern,
                            chrome_verified_normal: effective_chrome_verified_normal,
                            chrome_verified_at_mono_ms: effective_chrome_verified_at_mono_ms,
                        },
                        changed,
                        ticket.deadline_monotonic_ms,
                        clock,
                    );
                }
            } else {
                inp.invalidate(Some(uia), Some(ticket.deadline_monotonic_ms), clock);
            }
        }
    } else {
        invalidate_input_session(
            &mut input_session,
            Some(uia),
            ticket.deadline_monotonic_ms,
            clock,
        );
    }

    if charged_units > 8_192 {
        zeroize_input_records(input_records);
        invalidate_input_session(
            &mut input_session,
            Some(uia),
            ticket.deadline_monotonic_ms,
            clock,
        );
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
        zeroize_input_records(input_records);
        invalidate_input_session(
            &mut input_session,
            Some(uia),
            ticket.deadline_monotonic_ms,
            clock,
        );
        state.invalidate();
        state.clear_menu_binding();
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

    if text_read.is_none()
        && committed_surface.is_none()
        && selection_read.is_none()
        && input_records.is_empty()
    {
        invalidate_input_session(
            &mut input_session,
            Some(uia),
            ticket.deadline_monotonic_ms,
            clock,
        );
        state.invalidate();
        if surface_failure == Some(SurfaceReadFailure::BoundaryIncomplete) {
            state.clear_menu_binding();
        }
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
        input_records,
        input_gaps,
        private_state: Some(verified.private_state.to_string()),
        observer_status: Some(observer_status.to_string()),
        focus_absent: None,
        surface_failure,
        verified_normal_browser: post_verified_browser
            .filter(|_| verified.verified_normal_browser.is_some()),
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
        state.clear_menu_binding();
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
            if matches!(
                sf,
                SurfaceReadFailure::SecurityExcluded
                    | SurfaceReadFailure::BoundaryIncomplete
                    | SurfaceReadFailure::BoundaryUnverified
                    | SurfaceReadFailure::BoundaryMismatch
                    | SurfaceReadFailure::BoundaryAxFailed
            ) {
                state.clear_menu_binding();
            }
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

    let post_verified_browser =
        match reverify_window_boundary(uia, target, verified, ticket, clock, None) {
            Ok(outcome) => outcome.verified_normal_browser,
            Err((code, sf)) => {
                state.invalidate();
                if sf == Some(SurfaceReadFailure::BoundaryUnverified)
                    || !should_preserve_menu_binding_on_reverify_failure(target, verified, code)
                {
                    state.clear_menu_binding();
                }
                node_map.reset();
                baseline.reset();
                let diag_app =
                    (sf != Some(SurfaceReadFailure::SecurityExcluded)).then(|| verified.app.clone());
                return fail(
                    if matches!(
                        code,
                        GapDiagnosticCode::BrowserExcluded
                            | GapDiagnosticCode::ApplicationNotAllowed
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
        };

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
        state.clear_menu_binding();
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
        input_records: Vec::new(),
        input_gaps: Vec::new(),
        private_state: Some(verified.private_state.to_string()),
        observer_status: Some(observer_status.to_string()),
        focus_absent: Some(true),
        surface_failure: None,
        verified_normal_browser: post_verified_browser
            .filter(|_| verified.verified_normal_browser.is_some()),
        capture_start_ms: start_ms,
        capture_end_ms: end_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn barrier_drain_verdict_blocks_rearm_on_policy_boundary_target_mismatch_epoch_or_disarm() {
        // 1. Healthy armed drain with unchanged epoch proceeds to sync_binding.
        assert_eq!(
            evaluate_barrier_drain_verdict(true, true, &[], 5, 5, false),
            BarrierDrainVerdict::Proceed
        );
        // 2. Unarmed before drain (e.g. `input_text` just toggled on) with no gaps & matching epoch proceeds.
        assert_eq!(
            evaluate_barrier_drain_verdict(false, false, &[], 5, 5, false),
            BarrierDrainVerdict::Proceed
        );
        // 3. PolicyBoundary & FieldSecurityUnknown in drained_gaps ALWAYS abort fail-closed.
        assert_eq!(
            evaluate_barrier_drain_verdict(
                true,
                false,
                &[InputTextGapRecord::new(InputTextGapReason::PolicyBoundary)],
                5,
                6,
                false,
            ),
            BarrierDrainVerdict::AbortPolicyBoundary
        );
        assert_eq!(
            evaluate_barrier_drain_verdict(
                true,
                true,
                &[InputTextGapRecord::new(InputTextGapReason::FieldSecurityUnknown)],
                5,
                5,
                false,
            ),
            BarrierDrainVerdict::AbortPolicyBoundary
        );
        // 4. TargetMismatch, RoleNotEditable, and Stale abort stale focus without re-arming.
        for reason in [
            InputTextGapReason::TargetMismatch,
            InputTextGapReason::RoleNotEditable,
            InputTextGapReason::Stale,
        ] {
            assert_eq!(
                evaluate_barrier_drain_verdict(
                    true,
                    true,
                    &[InputTextGapRecord::new(reason)],
                    5,
                    5,
                    false,
                ),
                BarrierDrainVerdict::AbortStaleFocus,
                "reason={reason:?} must abort stale focus"
            );
        }
        // 5. Focus epoch drift during drain aborts stale focus.
        assert_eq!(
            evaluate_barrier_drain_verdict(true, true, &[], 5, 6, false),
            BarrierDrainVerdict::AbortStaleFocus
        );
        // 6. Disarming during drain without gaps (e.g. BoundaryMismatch with empty buffer) aborts stale focus.
        assert_eq!(
            evaluate_barrier_drain_verdict(true, false, &[], 5, 5, false),
            BarrierDrainVerdict::AbortStaleFocus
        );
        // 7. Secure Input latched skips sync_binding.
        assert_eq!(
            evaluate_barrier_drain_verdict(true, false, &[], 5, 5, true),
            BarrierDrainVerdict::SkipSyncSecureInput
        );
    }

    #[test]
    fn session_identity_invalidate_clears_focus_identity_while_preserving_menu_bound_fields() {
        let mut st = SessionIdentityState::new();
        st.bound_hwnd = Some(HWND(0x1234usize as *mut core::ffi::c_void));
        st.bound_dpi = 144;
        st.bound_private_state = "user-authorized";
        st.identity = Some(WorkerSurfaceIdentity {
            session_id: st.session_id.clone(),
            window_id: "w1".to_string(),
            node_id: "n1".to_string(),
            surface_id: "s1".to_string(),
            window_generation: 1,
            focus_generation: 1,
        });
        st.previous_window = Some(0x1234);
        st.previous_focus_runtime_id = Some(RuntimeIdKey(vec![42, 1]));
        st.verified_chrome_proof = Some(VerifiedChromeWindowProof {
            hwnd_raw: 0x1234,
            effective_pid: 4242,
            process_start_time: "unix-ms:1700000000000.000".to_string(),
            focus_epoch: 3,
            verified_at_mono_ms: 1_000,
        });

        st.invalidate();
        assert!(st.invalidated_focus);
        assert!(st.verified_chrome_proof.is_none());
        assert!(st.identity.is_none());
        assert!(st.previous_window.is_none());
        assert!(st.previous_focus_runtime_id.is_none());
        // Bound menu fields remain intact for `MenuActionSession` on `FocusedRoleNotText`.
        assert_eq!(st.bound_hwnd, Some(HWND(0x1234usize as *mut core::ffi::c_void)));
        assert_eq!(st.bound_dpi, 144);
        assert_eq!(st.bound_private_state, "user-authorized");

        // `clear_menu_binding` also clears `verified_chrome_proof`.
        st.verified_chrome_proof = Some(VerifiedChromeWindowProof {
            hwnd_raw: 0x1234,
            effective_pid: 4242,
            process_start_time: "unix-ms:1700000000000.000".to_string(),
            focus_epoch: 3,
            verified_at_mono_ms: 1_000,
        });
        st.clear_menu_binding();
        assert!(st.verified_chrome_proof.is_none());
    }
}
