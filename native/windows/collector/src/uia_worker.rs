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

use crate::adapters::{AdapterRegistry, AppAdapterSpec, SafeDisplayText};
use crate::desktop::assess_windows_desktop;
use crate::ownership::process_start_time_for_pid;
use crate::policy::{
    is_private_use_only_text, normalize_gap_role, resolve_application_id_for_pid,
    resolve_effective_pid, ApplicationPolicy, BrowserGate, PhaseBudget, ReadBudget,
    TextSecurityGate,
};
use crate::protocol_model::{
    bounded_utf16_slice, generate_uuid_v4, ApplicationIdentity, AxEnablementResult, CapturePolicy,
    CollectorClock, DesktopStatus, GapDiagnostic, GapDiagnosticCode, SecureStatus,
    SelectionReadResult, SurfaceAbsoluteRect, SurfaceBaseline, SurfaceGeometry, SurfaceNode,
    SurfaceReadFailure, SurfaceReadResult, TextRead, WorkerSurfaceIdentity,
};
use crate::uia_com::{
    ensure_per_monitor_dpi_aware, read_text_pattern_prefix, read_text_pattern_selection,
    read_text_pattern_visible, read_value_pattern_prefix, warmup_window_uia, window_rect_logical,
    ComGuard, UiaCallError, UiaClient, UiaElementMetadata, WinEventWatcher,
};
use crate::uia_traversal::{
    PendingSurfaceCapture, RuntimeIdKey, SurfaceFocusAnchors, SurfaceNodeMap,
    WeightedSurfaceChildrenRead, WeightedSurfaceInspection, WeightedSurfaceMetadata,
    WeightedSurfaceTextRead, WeightedSurfaceTraversal, WeightedSurfaceTraversalLimits,
    WeightedSurfaceTraversalReason,
};
use crate::worker_ipc::{ReadResult, ReadTicket, WorkerProgressClient};

const MAX_CHILDREN_PER_CONTAINER: usize = 128;
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

/// Resolve raw window PID, effective UWP/Win32 PID, and canonical `ApplicationIdentity` for an HWND.
pub fn resolve_application_for_hwnd(
    hwnd: HWND,
    app_id_override: Option<&str>,
) -> Option<(u32, ApplicationIdentity)> {
    if hwnd.0.is_null() {
        return None;
    }
    let mut raw_pid: u32 = 0;
    // SAFETY: Standard Win32 HWND -> PID query.
    unsafe {
        GetWindowThreadProcessId(hwnd, Some(&mut raw_pid));
    }
    let effective_pid = resolve_effective_pid(raw_pid, Some(hwnd.0 as isize));
    if effective_pid <= 1 {
        return None;
    }
    let application_id = match app_id_override {
        Some(over) => over.to_string(),
        None => resolve_application_id_for_pid(effective_pid, Some(hwnd.0 as isize))?,
    };
    let process_start_time = process_start_time_for_pid(effective_pid)?;
    Some((
        raw_pid,
        ApplicationIdentity {
            application_id,
            process_id: effective_pid,
            process_start_time,
        },
    ))
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
    spec: &'static AppAdapterSpec,
    initial_logical_rect: Option<SurfaceAbsoluteRect>,
    dpi: u32,
    private_state: &'static str,
}

fn classify_element_security(
    meta: &UiaElementMetadata,
    policy: &CapturePolicy,
) -> SecureStatus {
    if meta.is_sensitive() {
        return SecureStatus::Sensitive;
    }
    let role = meta.mapped.ax_role;
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

fn verify_target_pre_read(
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

    let (hwnd, app_override) = match target {
        ReadTarget::LiveForeground => {
            // SAFETY: Standard Win32 foreground window lookup.
            let fg = unsafe { GetForegroundWindow() };
            (fg, None)
        }
        ReadTarget::ExplicitWindow {
            window_hwnd,
            app_id_override,
            ..
        } => (window_hwnd, app_id_override),
    };

    let Some((raw_pid, app)) = resolve_application_for_hwnd(hwnd, app_override) else {
        return Err(fail(
            "policy-boundary",
            GapDiagnosticCode::ApplicationUnavailable,
            None,
        ));
    };

    if !ApplicationPolicy::allows(&app.application_id, &ticket.policy) {
        let silent = ticket.policy.application_scope.as_deref() == Some("denylist")
            || ApplicationPolicy::is_mandatory_denied(&app.application_id)
            || ApplicationPolicy::is_system_ui(&app.application_id);
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

    if !BrowserGate::allows(&app.application_id, &ticket.policy, false) {
        return Err(fail(
            "policy-boundary",
            GapDiagnosticCode::BrowserExcluded,
            None,
        ));
    }

    let spec = registry.adapter_for(&app.application_id);
    if BrowserGate::should_block_private_windows(&app.application_id, spec.block_private_windows) {
        if let Some(title) = read_window_title_ephemeral(hwnd) {
            if BrowserGate::is_private_window_title(&title) {
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
    let private_state = if BrowserGate::is_known_browser(&app.application_id) {
        "user-authorized"
    } else {
        "normal"
    };

    Ok(VerifiedTarget {
        hwnd,
        raw_pid,
        app,
        spec,
        initial_logical_rect,
        dpi,
        private_state,
    })
}

fn reverify_window_boundary(
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
    let app_override = match target {
        ReadTarget::LiveForeground => {
            // SAFETY: Live foreground window check.
            let fg = unsafe { GetForegroundWindow() };
            if fg != verified.hwnd {
                return Err((
                    GapDiagnosticCode::FocusChanged,
                    Some(SurfaceReadFailure::BoundaryMismatch),
                ));
            }
            None
        }
        ReadTarget::ExplicitWindow {
            app_id_override, ..
        } => app_id_override,
    };

    let Some((_, current_app)) = resolve_application_for_hwnd(verified.hwnd, app_override) else {
        return Err((
            GapDiagnosticCode::FocusChanged,
            Some(SurfaceReadFailure::BoundaryUnverified),
        ));
    };
    if current_app != verified.app {
        return Err((
            GapDiagnosticCode::FocusChanged,
            Some(SurfaceReadFailure::BoundaryMismatch),
        ));
    }

    if BrowserGate::should_block_private_windows(
        &verified.app.application_id,
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
    }

    Ok(())
}

fn reverify_focused_element(
    uia: &UiaClient,
    focused_elem: &IUIAutomationElement,
    expected_runtime_id: &RuntimeIdKey,
    expected_role: Option<&str>,
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
        let Ok(Some(parent)) = uia.parent_element(&cur) else {
            break;
        };
        if let Ok(pmeta) = uia.read_cached_metadata(&parent, verified.dpi, false, false) {
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
    uia.apply_timeouts(deadline.saturating_sub(clock.monotonic_ms()));

    if visible {
        let pat = uia
            .get_text_pattern(focused_elem)
            .map_err(|_| GapDiagnosticCode::VisibleRangeUnavailable)?
            .ok_or(GapDiagnosticCode::VisibleRangeUnavailable)?;
        let vis = read_text_pattern_visible(&pat, budget, || {
            clock.monotonic_ms() + 30 < deadline
        })
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
    if let Ok(Some(pat)) = uia.get_text_pattern(focused_elem) {
        if let Some(pref) = read_text_pattern_prefix(&pat, budget, || {
            clock.monotonic_ms() + 30 < deadline
        }) {
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

    if clock.monotonic_ms() >= deadline {
        return Err(GapDiagnosticCode::ReadDeadline);
    }

    // Fallback: IUIAutomationValuePattern (prefix mode ONLY).
    if let Ok(Some(val_pat)) = uia.get_value_pattern(focused_elem) {
        if let Some(pref) = read_value_pattern_prefix(&val_pat, budget) {
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
    children_loaded: bool,
    children: Vec<usize>,
    children_truncated: bool,
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
            children_loaded: false,
            children: Vec::new(),
            children_truncated: false,
        });
        self.by_runtime_id.insert(rid, idx);
        Some(idx)
    }
}

#[allow(clippy::too_many_arguments)]
fn capture_surface_tree(
    uia: &UiaClient,
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
            if budget.consume_calls(1, clock.monotonic_ms()) {
                if let Ok(Some(parent)) = uia.parent_element(fe) {
                    if let Ok(pmeta) =
                        uia.read_cached_metadata(&parent, verified.dpi, true, is_terminal)
                    {
                        if pmeta.is_sensitive() {
                            return Err(SurfaceReadFailure::SecurityExcluded);
                        }
                        if matches!(
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
                        ) {
                            chosen = (parent, pmeta);
                        }
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
    let store_cell = RefCell::new(store);
    let budget_cell = RefCell::new(budget);
    let security_excluded_hit = Cell::new(false);
    let mut extra_reasons: Vec<String> = Vec::new();

    // Helper closure to inspect an interned node, lazily enumerating direct ControlView children
    // for container nodes so SurfaceChildFrontier can page tail/head without extra IPC.
    let inspect_node = |handle: &usize| -> WeightedSurfaceInspection {
        let idx = *handle;
        let now_mono = clock.monotonic_ms();
        if now_mono >= budget_cell.borrow().active_deadline_ms() {
            return WeightedSurfaceInspection::Pruned(WeightedSurfaceTraversalReason::TimeBudget);
        }
        let (meta, runtime_id, children_loaded, parent_elem) = {
            let s = store_cell.borrow();
            (
                s.items[idx].meta.clone(),
                s.items[idx].runtime_id.clone(),
                s.items[idx].children_loaded,
                s.items[idx].element.clone(),
            )
        };
        if meta.is_sensitive() {
            if idx == root_handle || Some(idx) == focus_handle {
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
        if meta.process_id != 0
            && meta.process_id != verified.app.process_id
            && meta.process_id != verified.raw_pid
        {
            return WeightedSurfaceInspection::Pruned(
                WeightedSurfaceTraversalReason::ProviderRefused,
            );
        }

        let is_focused = Some(idx) == focus_handle
            || focused_runtime_id.is_some_and(|rid| !rid.is_empty() && runtime_id == *rid);

        let role_str = meta.mapped.ax_role;
        let policy_opt = role_str.and_then(WeightedSurfaceTraversal::role_policy);
        let reads_text = policy_opt.is_some_and(|p| p.reads_text());

        // Lazily load direct ControlView children for non-text containers.
        if !reads_text && !children_loaded {
            let mut child_handles = Vec::new();
            let mut truncated_children = false;
            if budget_cell.borrow_mut().consume_calls(1, clock.monotonic_ms()) {
                let active_dl = budget_cell.borrow().active_deadline_ms();
                uia.apply_timeouts(active_dl.saturating_sub(clock.monotonic_ms()));
                let mut cur = uia.first_child_element(&parent_elem).unwrap_or_default();
                while let Some(child_el) = cur {
                    if child_handles.len() >= MAX_CHILDREN_PER_CONTAINER {
                        truncated_children = true;
                        break;
                    }
                    if let Ok(cmeta) =
                        uia.read_cached_metadata(&child_el, verified.dpi, false, is_terminal)
                    {
                        if let Some(ch_idx) = store_cell.borrow_mut().intern(child_el.clone(), cmeta)
                        {
                            child_handles.push(ch_idx);
                        }
                    }
                    if !budget_cell.borrow_mut().consume_calls(1, clock.monotonic_ms()) {
                        truncated_children = true;
                        break;
                    }
                    cur = uia.next_sibling_element(&child_el).unwrap_or_default();
                }
            }
            let mut s = store_cell.borrow_mut();
            s.items[idx].children = child_handles;
            s.items[idx].children_loaded = true;
            s.items[idx].children_truncated = truncated_children;
        }

        // Update Document control type classification if we now know whether it has children.
        let (effective_meta, child_count) = {
            let mut s = store_cell.borrow_mut();
            let count = s.items[idx].children.len();
            if s.items[idx].meta.control_type == 50030 && count > 0 {
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
            }
            (s.items[idx].meta.clone(), count)
        };

        let obs_ms = clock.unix_ms().max(capture_start_ms);
        let bounds = initial_rect.and_then(|win| {
            effective_meta
                .logical_rect
                .and_then(|r| r.relative_to(win))
        });
        let bounds_observed_at_ms = bounds.map(|_| obs_ms);

        let display_text = effective_meta.mapped.ax_role.and_then(|ax| {
            SafeDisplayText::compose(
                ax,
                effective_meta.name.as_deref(),
                None,
                None,
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
                    if !budget_cell.borrow_mut().consume_calls(1, clock.monotonic_ms()) {
                        return None;
                    }
                    let elem = store_cell.borrow().items[*h].element.clone();
                    let parent = uia.parent_element(&elem).ok()??;
                    let pmeta = uia
                        .read_cached_metadata(&parent, verified.dpi, true, is_terminal)
                        .ok()?;
                    if pmeta.is_sensitive() {
                        security_excluded_hit.set(true);
                        return None;
                    }
                    store_cell.borrow_mut().intern(parent, pmeta)
                },
                || {
                    let b = budget_cell.borrow();
                    !security_excluded_hit.get()
                        && !b.text_violated()
                        && clock.monotonic_ms() < prep_deadline
                        && b.calls().saturating_sub(prep_start_calls) < prep_calls
                },
            );
            if security_excluded_hit.get() {
                return Err(SurfaceReadFailure::SecurityExcluded);
            }
            if let Some(plan) = anchor_res.plan {
                prep_work = plan.work;
                prep_probes = plan.probes;
                focus_plan = Some(plan);
            }
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
            let s = store_cell.borrow();
            if !s.items[idx].children_loaded {
                return WeightedSurfaceChildrenRead::Unavailable(
                    WeightedSurfaceTraversalReason::InconsistentChildren,
                );
            }
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

            // Reuse already-read focused text when available to avoid redundant IPC.
            let is_focused = Some(idx) == focus_handle
                || focused_runtime_id.is_some_and(|rid| !rid.is_empty() && runtime_id == *rid);
            if is_focused {
                if let Some(ft) = already_read_focus_text {
                    let units = utf16_len(ft);
                    let (sliced, trunc) = if units <= node_cap {
                        (ft.to_string(), false)
                    } else {
                        (bounded_utf16_slice(ft, 0, node_cap)?, true)
                    };
                    let actual = utf16_len(&sliced);
                    if !budget_cell.borrow_mut().consume_text(actual, Some(node_cap)) {
                        return None;
                    }
                    return Some(WeightedSurfaceTextRead {
                        text: Some(sliced),
                        truncated: trunc,
                    });
                }
            }

            if !budget_cell.borrow_mut().consume_calls(1, clock.monotonic_ms()) {
                return None;
            }
            let active_dl = budget_cell.borrow().active_deadline_ms();
            uia.apply_timeouts(active_dl.saturating_sub(clock.monotonic_ms()));

            // Primary: TextPattern bounded prefix.
            if let Ok(Some(pat)) = uia.get_text_pattern(&elem) {
                if let Some(pref) = read_text_pattern_prefix(&pat, node_cap, || false) {
                    let units = utf16_len(&pref.text);
                    if !budget_cell.borrow_mut().consume_text(units, Some(node_cap)) {
                        return None;
                    }
                    return Some(WeightedSurfaceTextRead {
                        text: Some(pref.text),
                        truncated: pref.truncated,
                    });
                }
            }

            // Fallback: ValuePattern bounded prefix.
            if let Ok(Some(vpat)) = uia.get_value_pattern(&elem) {
                if let Some(pref) = read_value_pattern_prefix(&vpat, node_cap) {
                    let units = utf16_len(&pref.text);
                    if !budget_cell.borrow_mut().consume_text(units, Some(node_cap)) {
                        return None;
                    }
                    return Some(WeightedSurfaceTextRead {
                        text: Some(pref.text),
                        truncated: pref.truncated,
                    });
                }
            }

            // Static text leaf: safe cached Name (excluding pure-PUA icon text).
            if meta.mapped.ax_role == Some("AXStaticText") {
                if let Some(ref name) = meta.name {
                    let units = utf16_len(name);
                    let (sliced, trunc) = if units <= node_cap {
                        (name.clone(), false)
                    } else {
                        (bounded_utf16_slice(name, 0, node_cap)?, true)
                    };
                    let actual = utf16_len(&sliced);
                    if !budget_cell.borrow_mut().consume_text(actual, Some(node_cap)) {
                        return None;
                    }
                    return Some(WeightedSurfaceTextRead {
                        text: Some(sliced),
                        truncated: trunc,
                    });
                }
            }

            None
        },
        || {
            let b = budget_cell.borrow();
            !security_excluded_hit.get()
                && !b.text_violated()
                && b.remaining_calls() > 0
                && clock.monotonic_ms() < exploration_deadline
        },
        || {
            !security_excluded_hit.get()
                && !budget_cell.borrow().text_violated()
                && clock.monotonic_ms() < optional_deadline_ms
        },
    );

    if security_excluded_hit.get() {
        return Err(SurfaceReadFailure::SecurityExcluded);
    }
    let mut budget = budget_cell.into_inner();
    let store = store_cell.into_inner();
    if budget.text_violated() {
        return Err(SurfaceReadFailure::CallBudget);
    }

    // Build final SurfaceNodes ensuring total UTF-16 text sum <= max_text_units.min(8192).
    let mut total_surface_units = 0usize;
    let surface_text_cap = max_text_units.min(ticket.policy.max_text_code_units).min(8_192);
    let mut nodes: Vec<SurfaceNode> = Vec::with_capacity(traversal.nodes.len());
    let mut references: Vec<(String, RuntimeIdKey)> = Vec::with_capacity(traversal.nodes.len());
    let mut any_truncated = false;
    let mut saw_focused = false;

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
    let final_logical_rect = if budget.can_recheck_window_rect() {
        window_rect_logical(verified.hwnd).map(|(_, l, _)| l)
    } else {
        None
    };
    let geom_obs_ms = clock.unix_ms().max(capture_start_ms);
    let mut geometry: Option<SurfaceGeometry> = initial_rect.and_then(|init| {
        init.geometry_if_unchanged(final_logical_rect, geom_obs_ms)
    });

    SurfaceBaseline::invalidate_geometry_if_moved(
        &mut nodes,
        &mut geometry,
        &mut missing_reasons,
        initial_rect,
        final_logical_rect,
    );

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
    )
}

/// Deterministic integration-test entrypoint that runs the FULL live UIA pipeline (pre-read
/// privacy gates, private browser title check, MTA COM, DPI normalization, `TextSecurityGate`,
/// `uia.text`/`uia.value`, `uia.tree`, `SurfaceNodeMap`, `SurfaceBaseline`, and post-read
/// revalidation) targeting an explicit synthetic Win32 window `HWND`.
pub fn read_window_for_test(
    window_hwnd: HWND,
    focused_hwnd: Option<HWND>,
    app_id_override: Option<&str>,
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
            desktop_override,
        },
        ticket,
        clock,
        None,
        "unavailable",
        &mut state,
        &mut node_map,
        &mut baseline,
    )
}

struct SessionIdentityState {
    session_id: String,
    bound_application: Option<ApplicationIdentity>,
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
            identity: None,
            previous_window: None,
            previous_focus_runtime_id: None,
            invalidated_focus: false,
            serial: 0,
        }
    }

    fn invalidate(&mut self) {
        self.invalidated_focus = true;
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
) -> ReadResult {
    let start_ms = clock.unix_ms();
    let fast_only = ticket.focused_fast_only == Some(true);
    let surface_requested = !fast_only
        && matches!(
            ticket.policy.capture_scope.as_deref(),
            Some("region" | "window")
        );

    let verified = match verify_target_pre_read(
        target,
        ticket,
        registry,
        clock,
        start_ms,
        surface_requested,
    ) {
        Ok(v) => v,
        Err(res) => {
            if res.diagnostic.map(|d| d.code) == Some(GapDiagnosticCode::ApplicationUnavailable) {
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

    let is_terminal = registry.is_terminal_app(&verified.app.application_id);

    // Optional bounded Chromium/Electron WM_GETOBJECT warmup.
    let enablement: AxEnablementResult = warmup_window_uia(
        verified.hwnd,
        verified.spec,
        &ticket.policy,
        ticket.read_only_ax_enablement == Some(true),
        ticket.deadline_monotonic_ms,
        clock,
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
        if surface_requested {
            r.surface_failure = Some(SurfaceReadFailure::AnchorUnavailable);
        }
        return r;
    }

    let (focused_elem, focused_meta) = focused_opt.unwrap();
    let focus_role = focused_meta.mapped.ax_role;
    let diag_role = Some(normalize_gap_role(focus_role));
    let is_text_role = TextSecurityGate::is_readable_text_role(focus_role);
    let focus_security = classify_element_security(&focused_meta, &ticket.policy);

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
        return r;
    }

    // Pre-read boundary verification right before text extraction.
    if let Err((code, sf)) = reverify_window_boundary(target, &verified, ticket, clock) {
        let mut r = ReadResult::failure(
            ticket.token.clone(),
            if code == GapDiagnosticCode::BrowserExcluded {
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
                uia.apply_timeouts(optional_deadline.saturating_sub(clock.monotonic_ms()));
                if let Ok(Some(pat)) = uia.get_text_pattern(&focused_elem) {
                    let sel_cap = remaining_total.min(ticket.policy.max_text_code_units);
                    if let Some(sel) = read_text_pattern_selection(&pat, sel_cap) {
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

    // If neither text nor surface nor selection succeeded, fail cleanly.
    if text_read.is_none() && pending_surface.is_none() && selection_read.is_none() {
        let code = text_failure_code.unwrap_or(GapDiagnosticCode::TextReadUnavailable);
        let mut r = ReadResult::failure(
            ticket.token.clone(),
            if surface_failure == Some(SurfaceReadFailure::SecurityExcluded) {
                "policy-boundary"
            } else {
                "read-error"
            },
            Some(GapDiagnostic::new(code, diag_role)),
            start_ms,
            clock.unix_ms(),
        );
        r.enablement = Some(enablement);
        r.observer_status = Some(observer_status.to_string());
        r.surface_failure = surface_failure;
        if surface_failure != Some(SurfaceReadFailure::SecurityExcluded) {
            r.diagnostic_application = Some(verified.app);
        }
        return r;
    }

    // FINAL POST-READ REVALIDATION: desktop unlocked, HWND/PID/startTime, focused RuntimeId + IsPassword == false!
    if let Err((code, sf)) = reverify_window_boundary(target, &verified, ticket, clock) {
        let mut r = ReadResult::failure(
            ticket.token.clone(),
            if code == GapDiagnosticCode::BrowserExcluded {
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
        &verified,
        is_terminal,
    ) {
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
        return r;
    }

    if clock.monotonic_ms() >= ticket.deadline_monotonic_ms {
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

    if let Err((code, sf)) = reverify_window_boundary(target, verified, ticket, clock) {
        state.invalidate();
        node_map.reset();
        baseline.reset();
        let diag_app =
            (sf != Some(SurfaceReadFailure::SecurityExcluded)).then(|| verified.app.clone());
        return fail(
            if code == GapDiagnosticCode::BrowserExcluded {
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
        let watcher = Some(WinEventWatcher::start());
        Self {
            progress,
            registry: AdapterRegistry::new(),
            watcher,
            uia,
            _com: com,
            state: SessionIdentityState::new(),
            node_map: SurfaceNodeMap::new(),
            baseline: SurfaceBaseline::new(),
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

    /// Stateful test entrypoint preserving `SurfaceNodeMap` and `SurfaceBaseline` across repeated
    /// reads on an explicit synthetic Win32 window (for testing `full` -> `diff` snapshots).
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
        );
        if let Some(ref app) = result.application {
            if let Some(ref watcher) = self.watcher {
                watcher.set_target_pid(app.process_id);
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
