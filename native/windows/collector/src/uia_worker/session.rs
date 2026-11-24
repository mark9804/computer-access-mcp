//! One-shot and stateful session worker entrypoints (`execute_live_one_shot`, `LiveUiaSession`,
//! and deterministic synthetic-window test helpers).
//!
//! Layer 3 module — imports only Layer 0 (`target_verify`), Layer 1 (`menu_action_session`), and
//! Layer 2 (`read_pipeline`).

use windows::Win32::Foundation::HWND;

use super::menu_action_session::{MenuActionSession, MenuBindingTarget};
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

/// Stateful live session worker invoked by `worker_ipc::run_session_worker_cli` (`--session-worker yes`).
///
/// Holds the MTA COM `IUIAutomation` instance, `SurfaceNodeMap`, `SurfaceBaseline`,
/// `MenuActionSession`, and a lightweight background `SetWinEventHook` message-pump thread for
/// event-driven dirty wakeups and menu lifecycle notifications.
///
/// Field drop order invariant: `menu_session` and `uia` are declared BEFORE `_com` so COM pointers
/// release prior to `CoUninitialize()`.
pub struct LiveUiaSession {
    progress: Option<WorkerProgressClient>,
    registry: AdapterRegistry,
    watcher: Option<WinEventWatcher>,
    menu_session: MenuActionSession,
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
            menu_session: MenuActionSession::new(),
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
        let is_live = matches!(target, ReadTarget::LiveForeground);
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
        if is_live {
            if ticket.policy.menu_actions == Some(true) {
                if let Some(ref watcher) = self.watcher {
                    watcher.set_menu_events_enabled(true);
                }
                if matches!(
                    result.reason.as_deref(),
                    Some(
                        "session-app-changed"
                            | "application-excluded"
                            | "desktop-unavailable"
                            | "policy-boundary"
                            | "stale"
                            | "timeout"
                    )
                ) {
                    self.menu_session.reset_for_boundary(false);
                } else if result
                    .reason
                    .as_deref()
                    .is_some_and(|r| r.starts_with("secure-input-"))
                {
                    self.secure_input_detected = true;
                    self.menu_session.suppress_secure_input();
                } else if let (Some(hwnd), Some(app), Some(resolved)) = (
                    self.state.bound_hwnd,
                    self.state.bound_application.clone(),
                    self.state.bound_resolved.clone(),
                ) {
                    let stamp = Stamp {
                        capture_epoch: ticket.capture_epoch,
                        foreground_generation: ticket.foreground_generation.unwrap_or(0),
                        focus_generation: ticket.focus_generation.unwrap_or(0),
                        policy_revision: ticket.policy_revision,
                    };
                    self.menu_session.sync_binding(
                        uia,
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
                        clock,
                    );
                } else {
                    self.menu_session.reset_for_boundary(false);
                }
            } else {
                if let Some(ref watcher) = self.watcher {
                    watcher.set_menu_events_enabled(false);
                }
                self.menu_session.disable(false);
            }
        }
        result
    }

    pub fn poll(&mut self, clock: &dyn CollectorClock) {
        let win_menu_events = if let Some(ref watcher) = self.watcher {
            if watcher.take_dirty() {
                self.dirty = true;
            }
            if watcher.take_focus_invalidated() {
                self.state.invalidate();
            }
            watcher.drain_menu_events()
        } else {
            Vec::new()
        };
        if let Some(ref uia) = self.uia {
            self.menu_session
                .poll(uia, &self.registry, win_menu_events, clock);
        }
        if let Some(tracking) = self.menu_session.take_menu_tracking() {
            self.menu_tracking = Some(tracking);
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

    /// Cleanly abandon UIA event subscriptions, stop passive hook & WinEvent pump threads, and
    /// release COM interfaces for the inert retire handshake.
    pub fn retire_healthy(&mut self) -> bool {
        if let Some(ref p) = self.progress {
            p.finish_request();
        }
        self.menu_session.retire_for_process_exit();
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
        true
    }
}

impl Drop for LiveUiaSession {
    fn drop(&mut self) {
        self.menu_session.shutdown();
        if let Some(mut watcher) = self.watcher.take() {
            watcher.stop();
        }
        self.uia = None;
    }
}
