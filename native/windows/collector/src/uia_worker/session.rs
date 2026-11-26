//! One-shot and stateful session worker entrypoints (`execute_live_one_shot`, `LiveUiaSession`,
//! and deterministic synthetic-window test helpers).
//!
//! Layer 3 module — imports only Layer 0 (`target_verify`, `input_hook`), Layer 1 (`menu_action`,
//! `input_text`), and Layer 2 (`read_pipeline`).

use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Arc;

use windows::Win32::Foundation::HWND;

use super::input_hook::MenuCommitHook;
use super::input_text::InputTextSession;
use super::menu_action::{MenuActionSession, MenuBindingTarget};
use super::read_pipeline::{execute_read_core, SessionIdentityState};
use super::target_verify::{resolve_foreground_application, ReadTarget};
use crate::adapters::AdapterRegistry;
use crate::menu_action_core::MenuActionRecord;
use crate::policy::ResolvedAppIdentity;
use crate::protocol_model::{
    CollectorClock, DesktopStatus, GapDiagnostic, GapDiagnosticCode, Stamp, SurfaceBaseline,
};
use crate::uia_com::{
    ensure_per_monitor_dpi_aware, ComGuard, UiaClient, WarmedHwndCache, WinEventWatcher,
};
use crate::uia_traversal::SurfaceNodeMap;
use crate::worker_ipc::{ReadResult, ReadTicket, WorkerProgressClient};

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
        None,
        None,
        false,
        false,
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
        None,
        None,
        false,
        false,
    )
}

/// Stateful live session worker invoked by `worker_ipc::run_session_worker_cli` (`--session-worker yes`).
///
/// Holds the MTA COM `IUIAutomation` instance, `SurfaceNodeMap`, `SurfaceBaseline`,
/// `MenuActionSession`, `InputTextSession`, a single shared `"input-hook"` thread
/// (`MenuCommitHook`), and a lightweight background `SetWinEventHook` message-pump thread for
/// event-driven dirty wakeups, focus epoch fencing, and menu lifecycle notifications.
///
/// Field drop order invariant: `shared_hook` stops before `menu_session` / `input_session`, and
/// `menu_session`, `input_session`, and `uia` are declared BEFORE `_com` so every COM pointer
/// releases strictly prior to `CoUninitialize()`.
pub struct LiveUiaSession {
    progress: Option<WorkerProgressClient>,
    registry: AdapterRegistry,
    watcher: Option<WinEventWatcher>,
    shared_hook: Option<MenuCommitHook>,
    shared_menu_open: Arc<AtomicBool>,
    shared_hook_attempted: bool,
    /// Capabilities active on `shared_hook`: `(mouse_enabled, keyboard_enabled)`.
    shared_hook_caps: (bool, bool),
    /// Exact `focus_epoch` that `InputTextSession` was verified and bound against on the most
    /// recent `read_internal` call (P1-3: prevents trailing `focus_invalidated` in `poll()` from
    /// tearing down a freshly-verified binding of the same epoch).
    last_bound_focus_epoch: Option<u64>,
    menu_session: MenuActionSession,
    input_session: InputTextSession,
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
        let focus_epoch = watcher
            .as_ref()
            .map(|w| Arc::clone(w.focus_epoch()))
            .unwrap_or_else(|| Arc::new(AtomicU64::new(1)));
        let shared_menu_open = Arc::new(AtomicBool::new(false));
        let mut menu_session = MenuActionSession::new();
        menu_session.set_shared_commit_hook_flag(Arc::clone(&shared_menu_open));
        let input_session = InputTextSession::new(focus_epoch);
        Self {
            progress,
            registry: AdapterRegistry::new(),
            watcher,
            shared_hook: None,
            shared_menu_open,
            shared_hook_attempted: false,
            shared_hook_caps: (false, false),
            last_bound_focus_epoch: None,
            menu_session,
            input_session,
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

    pub fn reset_surface_baseline(&mut self) {
        self.baseline.reset();
        self.node_map.reset();
    }

    /// Reset surface baseline, session identity state, bound focus epoch, and `InputTextSession`
    /// when a `ReadResult` degrades to a stage-4 `"budget"` failure during IPC framing so worker
    /// and parent `CollectorEngine` never drift out of sync on `fg_gen`/`focus_gen`.
    pub fn invalidate_after_budget_degradation(&mut self, clock: &dyn CollectorClock) {
        self.reset_surface_baseline();
        self.state.invalidate();
        self.last_bound_focus_epoch = None;
        let deadline = clock.monotonic_ms().saturating_add(40);
        self.input_session
            .invalidate(self.uia.as_ref(), Some(deadline), clock);
    }

    pub fn is_input_session_armed(&self) -> bool {
        self.input_session.is_context_armed()
    }

    pub fn input_session_expected_focus_epoch(&self) -> u64 {
        self.input_session.expected_focus_epoch()
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
        let result = self.read_internal(ReadTarget::LiveForeground, ticket, clock, true);
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
            false,
        )
    }

    /// Stateful test entrypoint that ALSO wires the live `InputTextSession` + shared keyboard hook
    /// through `execute_read_core` on a synthetic Win32 window so tests can exercise the real
    /// `LiveUiaSession` -> `execute_read_core` -> `InputTextSession` arm / barrier / disarm path
    /// deterministically without stealing live desktop focus.
    pub fn read_window_with_input_session_for_test(
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
            true,
        )
    }

    fn read_internal(
        &mut self,
        target: ReadTarget<'_>,
        ticket: &ReadTicket,
        clock: &dyn CollectorClock,
        enable_input_session: bool,
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
        let is_live = matches!(target, ReadTarget::LiveForeground);
        let use_input_session = is_live || enable_input_session;
        let focus_epoch_hooks_active = self
            .watcher
            .as_ref()
            .is_some_and(WinEventWatcher::focus_epoch_hooks_active);
        if use_input_session {
            // P1-3: Drain any pre-read `focus_invalidated` BEFORE `execute_read_core` so a stale
            // transition flag from before this read cannot tear down the freshly-established
            // binding & TSF subscription in the immediately following `poll()`!
            if self
                .watcher
                .as_ref()
                .is_some_and(WinEventWatcher::take_focus_invalidated)
            {
                self.state.invalidate();
                self.last_bound_focus_epoch = None;
                self.input_session.on_focus_invalidated(Some(uia), clock);
            }
        }
        let need_mouse = ticket.policy.menu_actions == Some(true);
        let hook_is_healthy_initial = self
            .shared_hook
            .as_ref()
            .is_some_and(MenuCommitHook::is_healthy);

        let result = if use_input_session {
            let shared_hook = &mut self.shared_hook;
            let shared_hook_caps = &mut self.shared_hook_caps;
            let shared_hook_attempted = &mut self.shared_hook_attempted;
            let shared_menu_open = &self.shared_menu_open;
            let mut ensure_input_hook = |inp: &mut InputTextSession| -> bool {
                inp.mark_hook_attempted();
                let want_mouse = need_mouse || shared_hook_caps.0;
                if let Some(ref hook) = *shared_hook {
                    if shared_hook_caps.1 && (!want_mouse || shared_hook_caps.0) {
                        return hook.is_healthy();
                    }
                    // Upgrade existing hook cleanly when adding keyboard or mouse capability.
                    if let Some(mut old) = shared_hook.take() {
                        old.stop();
                    }
                    *shared_hook_caps = (false, false);
                    *shared_hook_attempted = false;
                }
                if *shared_hook_attempted {
                    return false;
                }
                *shared_hook_attempted = true;
                let slot = inp.create_keyboard_slot();
                *shared_hook = MenuCommitHook::try_start_with_options(
                    Arc::clone(shared_menu_open),
                    want_mouse,
                    Some(slot),
                );
                let ok = shared_hook
                    .as_ref()
                    .is_some_and(MenuCommitHook::is_healthy);
                if ok {
                    *shared_hook_caps = (want_mouse, true);
                }
                ok
            };
            execute_read_core(
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
                Some(&mut self.input_session),
                Some(&mut ensure_input_hook),
                hook_is_healthy_initial,
                focus_epoch_hooks_active,
            )
        } else {
            execute_read_core(
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
                None,
                None,
                false,
                false,
            )
        };
        if let Some(ref app) = result.application {
            if let Some(ref watcher) = self.watcher {
                watcher.set_target_pids(app.process_id, self.state.bound_raw_pid);
            }
        }
        if use_input_session {
            if self.input_session.is_context_armed() && focus_epoch_hooks_active {
                let bound_ep = self.input_session.expected_focus_epoch();
                self.last_bound_focus_epoch = (bound_ep != 0).then_some(bound_ep);
            } else {
                self.last_bound_focus_epoch = None;
            }
            if result
                .reason
                .as_deref()
                .is_some_and(|r| r.starts_with("secure-input-"))
            {
                self.secure_input_detected = true;
                self.input_session.suppress_secure_input(
                    Some(uia),
                    ticket.deadline_monotonic_ms,
                    clock,
                );
            }
        }
        if is_live {
            if ticket.policy.menu_actions == Some(true) {
                if let Some(ref watcher) = self.watcher {
                    watcher.set_menu_events_enabled(true);
                }
                let has_bound_window = self.state.bound_hwnd.is_some()
                    && self.state.bound_application.is_some()
                    && self.state.bound_resolved.is_some();
                match decide_menu_session_sync_action(
                    result.reason.as_deref(),
                    result.diagnostic.map(|d| d.code),
                    has_bound_window,
                ) {
                    MenuSessionSyncAction::ResetBoundary => {
                        self.menu_session.reset_for_boundary(
                            Some(uia),
                            true,
                            ticket.deadline_monotonic_ms,
                            clock,
                        );
                    }
                    MenuSessionSyncAction::SuppressSecureInput => {
                        self.secure_input_detected = true;
                        self.input_session.suppress_secure_input(
                            Some(uia),
                            ticket.deadline_monotonic_ms,
                            clock,
                        );
                        self.menu_session.suppress_secure_input(
                            Some(uia),
                            ticket.deadline_monotonic_ms,
                            clock,
                        );
                    }
                    MenuSessionSyncAction::SyncBinding => {
                        if let (Some(hwnd), Some(app), Some(resolved)) = (
                            self.state.bound_hwnd,
                            self.state.bound_application.clone(),
                            self.state.bound_resolved.clone(),
                        ) {
                            if let Some(ref watcher) = self.watcher {
                                watcher.set_target_pids(app.process_id, self.state.bound_raw_pid);
                            }
                            let need_kb = ticket.policy.input_text == Some(true);
                            let needs_upgrade = self.shared_hook.is_some()
                                && (!self.shared_hook_caps.0
                                    || (need_kb && !self.shared_hook_caps.1));
                            if needs_upgrade {
                                if let Some(mut old) = self.shared_hook.take() {
                                    old.stop();
                                }
                                self.shared_hook_caps = (false, false);
                                self.shared_hook_attempted = false;
                            }
                            if self.shared_hook.is_none() && !self.shared_hook_attempted {
                                self.shared_hook_attempted = true;
                                let kb_slot = if need_kb {
                                    self.input_session.mark_hook_attempted();
                                    Some(self.input_session.create_keyboard_slot())
                                } else {
                                    None
                                };
                                self.shared_hook = MenuCommitHook::try_start_with_options(
                                    Arc::clone(&self.shared_menu_open),
                                    true,
                                    kb_slot,
                                );
                                if self
                                    .shared_hook
                                    .as_ref()
                                    .is_some_and(MenuCommitHook::is_healthy)
                                {
                                    self.shared_hook_caps = (true, need_kb);
                                } else if need_kb {
                                    self.input_session
                                        .mark_input_failure("input-monitoring-unavailable");
                                }
                            }
                            let stamp = Stamp {
                                capture_epoch: ticket.capture_epoch,
                                foreground_generation: ticket.foreground_generation.unwrap_or(0),
                                focus_generation: ticket.focus_generation.unwrap_or(0),
                                policy_revision: ticket.policy_revision,
                            };
                            self.menu_session.sync_binding(
                                uia,
                                &self.registry,
                                MenuBindingTarget {
                                    hwnd,
                                    raw_pid: self.state.bound_raw_pid,
                                    app,
                                    resolved,
                                    dpi: self.state.bound_dpi,
                                    private_state: self.state.bound_private_state,
                                },
                                &ticket.policy,
                                stamp,
                                ticket.deadline_monotonic_ms,
                                clock,
                            );
                        } else {
                            self.menu_session.reset_for_boundary(
                                Some(uia),
                                true,
                                ticket.deadline_monotonic_ms,
                                clock,
                            );
                        }
                    }
                }
            } else {
                if let Some(ref watcher) = self.watcher {
                    watcher.set_menu_events_enabled(false);
                }
                self.menu_session.disable(
                    Some(uia),
                    false,
                    ticket.deadline_monotonic_ms,
                    clock,
                );
            }
        }
        if use_input_session {
            if self.input_session.secure_input_detected() {
                self.secure_input_detected = true;
            }
            if let Some(failure) = self.input_session.input_failure() {
                if self.input_failure.is_none() {
                    self.input_failure = Some(failure.to_string());
                }
            }
        }
        result
    }

    pub fn poll(&mut self, clock: &dyn CollectorClock) {
        let (win_menu_events, win_menu_events_dropped, focus_invalidated) =
            if let Some(ref watcher) = self.watcher {
                if watcher.take_dirty() {
                    self.dirty = true;
                }
                let focus_inv = watcher.take_focus_invalidated();
                let current_epoch = watcher.current_focus_epoch();
                // P1-3: Do NOT tear down a freshly-verified binding when `focus_epoch` still
                // equals `last_bound_focus_epoch` (e.g. a trailing flag for the exact same epoch).
                let effective_focus_inv = focus_inv
                    && self
                        .last_bound_focus_epoch
                        .is_none_or(|bound_ep| current_epoch != bound_ep);
                if effective_focus_inv {
                    self.state.invalidate();
                    self.last_bound_focus_epoch = None;
                }
                let events = watcher.drain_menu_events();
                let dropped = watcher.take_menu_events_dropped();
                (events, dropped, effective_focus_inv)
            } else {
                (Vec::new(), false, false)
            };

        let (commit_signals, commit_dropped, hook_healthy) = match self.shared_hook {
            Some(ref hook) => (
                hook.drain_signals(),
                hook.take_dropped_menu_signals(),
                hook.is_healthy(),
            ),
            None => (Vec::new(), 0, false),
        };

        if let Some(ref uia) = self.uia {
            if focus_invalidated {
                self.input_session.on_focus_invalidated(Some(uia), clock);
            }
            self.menu_session.poll_with_external_signals(
                uia,
                &self.registry,
                win_menu_events,
                win_menu_events_dropped,
                commit_signals,
                commit_dropped,
                clock,
            );
            self.input_session
                .poll(uia, &self.registry, hook_healthy, clock);
        }
        if let Some(tracking) = self.menu_session.take_menu_tracking() {
            self.menu_tracking = Some(tracking);
        }
        if self.input_session.take_dirty() {
            self.dirty = true;
        }
        if self.input_session.take_submit_dirty() {
            self.submit_dirty = true;
        }
        if self.input_session.secure_input_detected() {
            self.secure_input_detected = true;
        }
        if let Some(failure) = self.input_session.input_failure() {
            if self.input_failure.is_none() {
                self.input_failure = Some(failure.to_string());
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

    pub fn take_next_menu_action(&mut self) -> Option<MenuActionRecord> {
        self.menu_session.take_next_record()
    }

    pub fn has_pending_menu_frame(&self) -> bool {
        self.menu_session.has_pending_frame() || self.menu_tracking.is_some()
    }

    pub fn input_failure(&self) -> Option<&str> {
        self.input_failure.as_deref()
    }

    pub fn secure_input_detected(&self) -> bool {
        self.secure_input_detected
    }

    /// Cleanly abandon UIA event subscriptions, stop the single shared passive hook & WinEvent
    /// pump threads, and release COM interfaces for the inert retire handshake.
    pub fn retire_healthy(&mut self) -> bool {
        if let Some(ref p) = self.progress {
            p.finish_request();
        }
        let hook_was_healthy = !self.input_session.was_hook_attempted()
            || (self.input_failure.is_none()
                && self.input_session.input_failure().is_none()
                && self
                    .shared_hook
                    .as_ref()
                    .is_some_and(MenuCommitHook::is_healthy));
        self.menu_session.retire_for_process_exit();
        self.input_session.retire_for_process_exit();
        if let Some(mut hook) = self.shared_hook.take() {
            hook.stop();
        }
        self.shared_hook_caps = (false, false);
        self.last_bound_focus_epoch = None;
        if let Some(mut watcher) = self.watcher.take() {
            watcher.stop();
        }
        // Release all UIA COM interfaces before CoUninitialize runs on Drop.
        self.uia = None;
        self.baseline.reset();
        self.node_map.reset();
        self.warmed_hwnds.clear();
        self.state.invalidate();
        self.state.clear_menu_binding();
        self.dirty = false;
        self.submit_dirty = false;
        self.menu_tracking = None;
        hook_was_healthy
    }
}

impl Drop for LiveUiaSession {
    fn drop(&mut self) {
        // Process-exit safe teardown: abandon remote UIA handlers without synchronous remote
        // RemoveAutomationEventHandler COM RPCs that could stall on hung target UI threads.
        self.menu_session.retire_for_process_exit();
        self.input_session.retire_for_process_exit();
        if let Some(mut hook) = self.shared_hook.take() {
            hook.stop();
        }
        self.shared_hook_caps = (false, false);
        self.last_bound_focus_epoch = None;
        if let Some(mut watcher) = self.watcher.take() {
            watcher.stop();
        }
        self.uia = None;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MenuSessionSyncAction {
    ResetBoundary,
    SuppressSecureInput,
    SyncBinding,
}

/// Decides whether `MenuActionSession` should reset, suppress on Secure Input, or preserve/sync
/// its current binding after `execute_read_core` finishes.
///
/// - Preserves `MenuActionSession` on intra-window `"stale"` reads STRICTLY for `FocusChanged`
///   when `has_bound_window` was re-verified (never `ReadDeadline` or `DesktopUnavailable`).
/// - Preserves `MenuActionSession` on `"policy-boundary"` STRICTLY for `FocusedRoleNotText` when
///   `has_bound_window` is valid (e.g. clicking a non-text control or menu bar in an allowed app).
/// - Resets immediately on all true privacy/boundary/timeout failures.
fn decide_menu_session_sync_action(
    reason: Option<&str>,
    diagnostic_code: Option<GapDiagnosticCode>,
    has_bound_window: bool,
) -> MenuSessionSyncAction {
    if reason.is_some_and(|r| r.starts_with("secure-input-")) {
        return MenuSessionSyncAction::SuppressSecureInput;
    }
    if reason.is_some_and(|r| r.starts_with("input-monitoring-")) {
        return MenuSessionSyncAction::ResetBoundary;
    }
    if diagnostic_code == Some(GapDiagnosticCode::ReadDeadline) {
        return MenuSessionSyncAction::ResetBoundary;
    }
    if reason == Some("policy-boundary")
        && diagnostic_code == Some(GapDiagnosticCode::FocusedRoleNotText)
        && has_bound_window
    {
        return MenuSessionSyncAction::SyncBinding;
    }
    if matches!(
        reason,
        Some(
            "session-app-changed"
                | "application-excluded"
                | "desktop-unavailable"
                | "policy-boundary"
                | "timeout"
        )
    ) {
        return MenuSessionSyncAction::ResetBoundary;
    }
    if reason == Some("stale") {
        if has_bound_window && diagnostic_code == Some(GapDiagnosticCode::FocusChanged) {
            return MenuSessionSyncAction::SyncBinding;
        }
        return MenuSessionSyncAction::ResetBoundary;
    }
    if has_bound_window {
        MenuSessionSyncAction::SyncBinding
    } else {
        MenuSessionSyncAction::ResetBoundary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn menu_session_sync_preserves_same_window_stale_and_resets_hard_boundaries() {
        // Intra-window `"stale"` with FocusChanged keeps binding; ReadDeadline MUST reset!
        assert_eq!(
            decide_menu_session_sync_action(
                Some("stale"),
                Some(GapDiagnosticCode::FocusChanged),
                true,
            ),
            MenuSessionSyncAction::SyncBinding
        );
        assert_eq!(
            decide_menu_session_sync_action(
                Some("stale"),
                Some(GapDiagnosticCode::ReadDeadline),
                true,
            ),
            MenuSessionSyncAction::ResetBoundary
        );
        assert_eq!(
            decide_menu_session_sync_action(
                Some("read-error"),
                Some(GapDiagnosticCode::ReadDeadline),
                true,
            ),
            MenuSessionSyncAction::ResetBoundary
        );
        // `"policy-boundary"` with FocusedRoleNotText preserves binding when bound window is valid!
        assert_eq!(
            decide_menu_session_sync_action(
                Some("policy-boundary"),
                Some(GapDiagnosticCode::FocusedRoleNotText),
                true,
            ),
            MenuSessionSyncAction::SyncBinding
        );
        assert_eq!(
            decide_menu_session_sync_action(
                Some("policy-boundary"),
                Some(GapDiagnosticCode::FocusedRoleNotText),
                false,
            ),
            MenuSessionSyncAction::ResetBoundary
        );
        // True privacy `"policy-boundary"` codes MUST always reset!
        for privacy_code in [
            GapDiagnosticCode::SecureField,
            GapDiagnosticCode::BrowserExcluded,
            GapDiagnosticCode::FieldSecurityUnknown,
            GapDiagnosticCode::ApplicationNotAllowed,
            GapDiagnosticCode::ApplicationUnavailable,
        ] {
            assert_eq!(
                decide_menu_session_sync_action(
                    Some("policy-boundary"),
                    Some(privacy_code),
                    true,
                ),
                MenuSessionSyncAction::ResetBoundary
            );
        }
        // `"stale"` with cleared bound window or `DesktopUnavailable` MUST reset!
        assert_eq!(
            decide_menu_session_sync_action(
                Some("stale"),
                Some(GapDiagnosticCode::FocusChanged),
                false,
            ),
            MenuSessionSyncAction::ResetBoundary
        );
        assert_eq!(
            decide_menu_session_sync_action(
                Some("stale"),
                Some(GapDiagnosticCode::DesktopUnavailable),
                true,
            ),
            MenuSessionSyncAction::ResetBoundary
        );
        // Hard privacy/boundary reasons ALWAYS reset even if bound_hwnd was set.
        for hard_reason in [
            "session-app-changed",
            "application-excluded",
            "desktop-unavailable",
            "policy-boundary",
            "timeout",
            "input-monitoring-unavailable",
            "input-monitoring-disabled",
        ] {
            assert_eq!(
                decide_menu_session_sync_action(Some(hard_reason), None, true),
                MenuSessionSyncAction::ResetBoundary,
                "reason={hard_reason} must reset MenuActionSession"
            );
        }
        assert_eq!(
            decide_menu_session_sync_action(Some("secure-input-active"), None, true),
            MenuSessionSyncAction::SuppressSecureInput
        );
        // Normal successful read syncs binding when bound window is present, resets when absent.
        assert_eq!(
            decide_menu_session_sync_action(None, None, true),
            MenuSessionSyncAction::SyncBinding
        );
        assert_eq!(
            decide_menu_session_sync_action(None, None, false),
            MenuSessionSyncAction::ResetBoundary
        );
    }
}
