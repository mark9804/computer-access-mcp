//! Foreground top-menu-bar action capture (`menu.action` / `uia.menu`) running inside the isolated
//! `--ax-worker --session-worker yes` process.
//!
//! Layer 1 module — strictly acyclic 4-submodule DAG:
//! - Layer 1a (`state`): pure state machine, 3-way poll merge planner, wrapper/renderer classifiers
//! - Layer 1b (`privacy`): pre/post-read privacy gates, Win32 HWND checks, metadata safety guards
//! - Layer 1c (`walker`): bounded UIA ancestor walking, leaf child classifier, `MenuBar` ownership
//! - Layer 1d (`mod`): [`MenuActionSession`] lifecycle and event-stream orchestration
//!
//! Imports ONLY Layer 0 `uia_worker` leaves (`target_verify`, `uia_events`, `input_hook`) and core
//! modules (`adapters`, `desktop`, `menu_action_core`, `policy`, `protocol_model`, `uia_com`,
//! `uia_traversal`). ZERO imports of `read_pipeline` or `session`.

mod privacy;
pub mod state;
mod walker;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};

use windows::Win32::Foundation::HWND;
use windows::Win32::UI::Accessibility::IUIAutomationElement;

pub use privacy::find_app_menu_bar_for_window;
pub(in crate::uia_worker) use privacy::MenuBindingTarget;
pub use walker::{has_menu_child_for_test, resolve_uia_menu_leaf_for_test};

use privacy::{
    hwnd_matches_bound_pid, is_system_menu_bar, meta_is_safe_for_bound,
    passes_fast_menu_privacy_pre_gate, passes_live_menu_privacy_gates, popup_hwnd_belongs_to_bound,
    root_hwnd_for_raw, BoundMenuWindow,
};
use state::{
    plan_merged_poll_events, MenuHandleKey, MergedPollEvent, Win32MenuBarState, MAX_OPEN_MENUS,
};
use walker::{
    detect_verified_menu_bar_item, has_menu_child, inspect_walk_handle,
    is_structural_menu_focus_candidate, menu_bar_belongs_to_window, parent_walk_handle,
    preferred_meta_title, resolve_uia_menu_leaf_handle, verify_walk_menu_bar_owner,
    walk_handles_same, WalkHandle,
};

use super::input_hook::{qpc_ns_now, MenuCommitHook, MenuCommitSignal};
use super::target_verify::is_owned_popup_hwnd;
use super::uia_events::{
    create_menu_event_channel, RawUiaMenuEvent, UiaMenuEventKind, UiaMenuEventSubscription,
};
use crate::adapters::AdapterRegistry;
use crate::menu_action_core::{
    MenuActionDeduplicator, MenuActionPendingQueue, MenuActionRecord, MenuPathLimits,
    MenuPathResolver, MenuTrackingStateMachine, OpenedMenuKind, ResolvedMenuPath, Win32MenuBarLink,
    UIA_BUTTON_CONTROL_TYPE, UIA_CUSTOM_CONTROL_TYPE, UIA_GROUP_CONTROL_TYPE,
    UIA_MENU_BAR_CONTROL_TYPE, UIA_MENU_CONTROL_TYPE, UIA_MENU_ITEM_CONTROL_TYPE,
    UIA_PANE_CONTROL_TYPE, UIA_WINDOW_CONTROL_TYPE,
};
use crate::policy::BrowserGate;
use crate::protocol_model::{CapturePolicy, CollectorClock, Stamp};
use crate::uia_com::{UiaClient, UiaElementMetadata, WinMenuEvent, WinMenuEventKind};
use crate::uia_traversal::RuntimeIdKey;

/// Hard per-event UIA inspection & ancestor-walk time budget (ms).
const MENU_EVENT_BUDGET_MS: i64 = 120;
/// Maximum accepted hook signal age (200ms) in monotonic QPC nanoseconds.
const MAX_COMMIT_SIGNAL_AGE_NS: u64 = 200_000_000;

struct OpenUiaMenu {
    key: MenuHandleKey,
    elem: IUIAutomationElement,
    runtime_id: RuntimeIdKey,
}

fn detach_subscription_with_budget(
    sub: UiaMenuEventSubscription,
    retiring: bool,
    uia: Option<&UiaClient>,
    budget: Option<(i64, &dyn CollectorClock)>,
) {
    if retiring {
        sub.abandon_for_process_exit();
        return;
    }
    if let Some((deadline_ms, clock)) = budget {
        let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
        if rem <= 15 {
            sub.abandon_for_process_exit();
            return;
        }
        let per_call_ms = (rem / 3).clamp(1, 40) as u32;
        if let Some(u) = uia {
            u.apply_timeouts(per_call_ms as i64);
        }
        sub.detach_with_timeout(per_call_ms);
    } else {
        if let Some(u) = uia {
            u.apply_timeouts(40);
        }
        sub.detach();
    }
}

/// Stateful foreground top-menu-bar monitor combining MTA UIA event subscriptions, `WinEventWatcher`
/// menu lifecycle notifications, optional passive `MenuCommitHook` fallback, fail-closed browser
/// chrome privacy gates, bounded ancestor path resolution, and 250ms deduplication.
///
/// Field drop order note: COM fields (`open_uia_menus`, `popup_uia_sub`, `uia_sub`, `bound`) are
/// released explicitly on `retire_for_process_exit()` before `UiaClient` and `ComGuard` drop.
pub struct MenuActionSession {
    enabled: bool,
    retiring: bool,
    secure_input_suppressed: bool,
    open_uia_menus: Vec<OpenUiaMenu>,
    bound: Option<BoundMenuWindow>,
    popup_uia_sub: Option<(isize, UiaMenuEventSubscription)>,
    uia_sub: Option<UiaMenuEventSubscription>,
    uia_tx: Option<mpsc::SyncSender<RawUiaMenuEvent>>,
    uia_rx: Option<mpsc::Receiver<RawUiaMenuEvent>>,
    menu_open_flag: Arc<AtomicBool>,
    commit_hook: Option<MenuCommitHook>,
    hook_attempted: bool,
    accept_after_qpc_ns: u64,
    tracking: MenuTrackingStateMachine<MenuHandleKey, ResolvedMenuPath>,
    tracking_started_mono_ms: Option<i64>,
    dedup: MenuActionDeduplicator,
    pending_records: MenuActionPendingQueue,
    pending_tracking: Option<bool>,
    last_reported_tracking: bool,
    // Verified top-menu-bar tracking state (classic `#32768` + WinUI 3 / Electron popups).
    win32: Win32MenuBarState,
}

impl Default for MenuActionSession {
    fn default() -> Self {
        Self::new()
    }
}

impl MenuActionSession {
    pub fn new() -> Self {
        Self {
            enabled: false,
            retiring: false,
            secure_input_suppressed: false,
            open_uia_menus: Vec::new(),
            bound: None,
            popup_uia_sub: None,
            uia_sub: None,
            uia_tx: None,
            uia_rx: None,
            menu_open_flag: Arc::new(AtomicBool::new(false)),
            commit_hook: None,
            hook_attempted: false,
            accept_after_qpc_ns: qpc_ns_now(),
            tracking: MenuTrackingStateMachine::new(),
            tracking_started_mono_ms: None,
            dedup: MenuActionDeduplicator::new(),
            pending_records: MenuActionPendingQueue::new(),
            pending_tracking: None,
            last_reported_tracking: false,
            win32: Win32MenuBarState::default(),
        }
    }

    pub fn take_next_record(&mut self) -> Option<MenuActionRecord> {
        self.pending_records.pop_next()
    }

    pub fn take_menu_tracking(&mut self) -> Option<bool> {
        self.pending_tracking.take()
    }

    pub fn has_pending_frame(&self) -> bool {
        !self.pending_records.is_empty() || self.pending_tracking.is_some()
    }

    /// Bind or refresh menu monitoring for the verified foreground window.
    ///
    /// Cleanly rebinds (detaching previous UIA handlers and clearing tracking/highlight state)
    /// whenever the bound HWND, application identity, `captureEpoch`, or `policyRevision` changes.
    /// Skips COM probes (`find_app_menu_bar_for_window`, `attach_uia_subscription`) when
    /// `deadline_ms` budget is exhausted.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::uia_worker) fn sync_binding(
        &mut self,
        uia: &UiaClient,
        registry: &AdapterRegistry,
        target: MenuBindingTarget,
        policy: &CapturePolicy,
        stamp: Stamp,
        deadline_ms: i64,
        clock: &dyn CollectorClock,
    ) {
        if self.retiring
            || self.secure_input_suppressed
            || !policy.enabled
            || policy.menu_actions != Some(true)
        {
            self.disable(Some(uia), false, deadline_ms, clock);
            return;
        }
        if target.hwnd.0.is_null() {
            self.disable(Some(uia), false, deadline_ms, clock);
            return;
        }

        self.enabled = true;
        self.ensure_commit_hook();

        let same_binding = self.bound.as_ref().is_some_and(|b| {
            b.hwnd == target.hwnd
                && b.app == target.app
                && b.resolved == target.resolved
                && b.stamp.capture_epoch == stamp.capture_epoch
                && b.stamp.policy_revision == stamp.policy_revision
        });

        if same_binding {
            if let Some(ref mut b) = self.bound {
                b.policy = policy.clone();
                b.stamp = stamp;
                b.dpi = target.dpi;
                b.private_state = target.private_state;
            }
            if self.uia_sub.is_none()
                && deadline_ms.saturating_sub(clock.monotonic_ms()) > 15
            {
                self.attach_uia_subscription(uia, target.hwnd, deadline_ms, clock);
            }
            return;
        }

        // Rebind to the new foreground window / epoch cleanly.
        self.detach_uia_subscription(Some(uia), Some((deadline_ms, clock)));
        self.clear_tracking_state(Some(uia), false, Some((deadline_ms, clock)));
        self.pending_records.clear();
        self.dedup.reset();
        self.accept_after_qpc_ns = qpc_ns_now();

        let spec = registry.adapter_for_identity(&target.resolved);
        let is_browser = BrowserGate::is_known_browser_identity(&target.resolved)
            || BrowserGate::should_block_private_windows_identity(
                &target.resolved,
                spec.block_private_windows,
            );

        let bar_deadline = clock.monotonic_ms().saturating_add(40).min(deadline_ms);
        let app_menu_bar = if bar_deadline.saturating_sub(clock.monotonic_ms()) > 15 {
            find_app_menu_bar_for_window(
                uia,
                target.hwnd,
                target.app.process_id,
                target.raw_pid,
                target.dpi,
                bar_deadline,
                clock,
            )
        } else {
            None
        };

        self.bound = Some(BoundMenuWindow {
            hwnd: target.hwnd,
            raw_pid: target.raw_pid,
            app: target.app,
            resolved: target.resolved,
            is_browser,
            dpi: target.dpi,
            private_state: target.private_state,
            policy: policy.clone(),
            stamp,
            app_menu_bar,
        });

        if deadline_ms.saturating_sub(clock.monotonic_ms()) > 15 {
            self.attach_uia_subscription(uia, target.hwnd, deadline_ms, clock);
        }
    }

    /// Disable menu monitoring and tear down active subscriptions cleanly, abandoning remote COM
    /// detach locally if `deadline_ms` has already expired.
    pub fn disable(
        &mut self,
        uia: Option<&UiaClient>,
        emit_stop_tracking: bool,
        deadline_ms: i64,
        clock: &dyn CollectorClock,
    ) {
        self.enabled = false;
        self.detach_uia_subscription(uia, Some((deadline_ms, clock)));
        self.stop_commit_hook();
        self.bound = None;
        self.pending_records.clear();
        self.dedup.reset();
        self.accept_after_qpc_ns = qpc_ns_now();
        self.clear_tracking_state(uia, emit_stop_tracking, Some((deadline_ms, clock)));
    }

    /// Clear transient tracking/binding state on app change or excluded foreground application
    /// without permanently stopping the optional hook thread when `menu_actions` stays enabled,
    /// abandoning remote COM detach locally if `deadline_ms` has already expired.
    pub fn reset_for_boundary(
        &mut self,
        uia: Option<&UiaClient>,
        emit_stop_tracking: bool,
        deadline_ms: i64,
        clock: &dyn CollectorClock,
    ) {
        self.detach_uia_subscription(uia, Some((deadline_ms, clock)));
        self.bound = None;
        self.pending_records.clear();
        self.dedup.reset();
        self.accept_after_qpc_ns = qpc_ns_now();
        self.clear_tracking_state(uia, emit_stop_tracking, Some((deadline_ms, clock)));
    }

    /// Immediately suppress menu capture on Secure Input without flushing pending records,
    /// abandoning remote COM detach locally if `deadline_ms` has already expired.
    pub fn suppress_secure_input(
        &mut self,
        uia: Option<&UiaClient>,
        deadline_ms: i64,
        clock: &dyn CollectorClock,
    ) {
        self.secure_input_suppressed = true;
        self.disable(uia, false, deadline_ms, clock);
    }

    /// Process-exit retirement (`LiveUiaSession::retire_healthy()` and `Drop`): abandons remote
    /// UIA COM handlers without blocking on hung target UI threads and joins the local hook thread
    /// cleanly.
    pub fn retire_for_process_exit(&mut self) {
        self.retiring = true;
        self.enabled = false;
        self.menu_open_flag.store(false, Ordering::Release);
        self.pending_records.clear();
        self.pending_tracking = None;
        self.last_reported_tracking = false;
        self.clear_win32_menu_state();
        self.open_uia_menus.clear();
        let _ = self.tracking.reset();
        self.tracking_started_mono_ms = None;
        self.dedup.reset();
        if let Some((_, sub)) = self.popup_uia_sub.take() {
            sub.abandon_for_process_exit();
        }
        if let Some(sub) = self.uia_sub.take() {
            sub.abandon_for_process_exit();
        }
        self.uia_tx = None;
        self.uia_rx = None;
        self.stop_commit_hook();
        self.bound = None;
    }

    fn ensure_commit_hook(&mut self) {
        if self.commit_hook.is_some() || self.hook_attempted {
            return;
        }
        self.hook_attempted = true;
        // Gracefully degrades to `None` if low-level hook installation is unavailable: native
        // `UIA_Invoke_InvokedEventId` still functions without any input hook.
        self.commit_hook = MenuCommitHook::try_start(Arc::clone(&self.menu_open_flag));
    }

    fn stop_commit_hook(&mut self) {
        self.menu_open_flag.store(false, Ordering::Release);
        if let Some(mut hook) = self.commit_hook.take() {
            hook.stop();
        }
        self.hook_attempted = false;
    }

    fn attach_uia_subscription(
        &mut self,
        uia: &UiaClient,
        hwnd: HWND,
        deadline_ms: i64,
        clock: &dyn CollectorClock,
    ) {
        self.detach_uia_subscription(Some(uia), Some((deadline_ms, clock)));
        let deadline = clock.monotonic_ms().saturating_add(80).min(deadline_ms);
        let rem = deadline.saturating_sub(clock.monotonic_ms());
        if rem <= 15 {
            return;
        }
        uia.apply_timeouts(rem);
        let Ok(root) = uia.element_from_hwnd(hwnd) else {
            return;
        };
        let rem_attach = deadline.saturating_sub(clock.monotonic_ms());
        if rem_attach <= 15 {
            return;
        }
        let (tx, rx) = create_menu_event_channel();
        uia.apply_timeouts(rem_attach);
        if let Ok(sub) = UiaMenuEventSubscription::attach(uia.automation(), &root, tx.clone()) {
            self.uia_sub = Some(sub);
            self.uia_tx = Some(tx);
            self.uia_rx = Some(rx);
        }
    }

    fn detach_popup_uia_subscription(
        &mut self,
        uia: Option<&UiaClient>,
        budget: Option<(i64, &dyn CollectorClock)>,
    ) {
        if let Some((_, sub)) = self.popup_uia_sub.take() {
            detach_subscription_with_budget(sub, self.retiring, uia, budget);
        }
    }

    /// Attach a secondary bounded UIA subscription strictly to a verified same-PID detached popup
    /// HWND (such as WinUI 3 `Xaml_WindowedPopupClass` or `#32768`) while top-menu-bar tracking is
    /// active, sharing `self.uia_tx` so `UIA_Invoke_InvokedEventId` and `UIA_MenuClosedEventId`
    /// arrive in FIFO order.
    fn maybe_attach_popup_uia_subscription(
        &mut self,
        uia: &UiaClient,
        candidate_hwnd_raw: isize,
        deadline_ms: i64,
        clock: &dyn CollectorClock,
    ) {
        if candidate_hwnd_raw == 0 || self.retiring {
            return;
        }
        let (bound_hwnd, expected_pid, raw_pid) = match self.bound {
            Some(ref b) => (b.hwnd, b.app.process_id, b.raw_pid),
            None => return,
        };
        let Some(tx) = self.uia_tx.clone() else {
            return;
        };
        let popup_hwnd = root_hwnd_for_raw(candidate_hwnd_raw);
        let popup_raw = popup_hwnd.0 as isize;
        if popup_hwnd == bound_hwnd || popup_raw == 0 {
            return;
        }
        if self
            .popup_uia_sub
            .as_ref()
            .is_some_and(|(existing, _)| *existing == popup_raw)
        {
            return;
        }
        if !popup_hwnd_belongs_to_bound(popup_hwnd, bound_hwnd, expected_pid, raw_pid) {
            return;
        }
        let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
        if rem <= 15 {
            return;
        }
        uia.apply_timeouts(rem.min(50));
        let Ok(popup_root) = uia.element_from_hwnd(popup_hwnd) else {
            return;
        };
        if uia.is_root_desktop_element(&popup_root) {
            return;
        }
        self.detach_popup_uia_subscription(Some(uia), Some((deadline_ms, clock)));
        let rem_attach = deadline_ms.saturating_sub(clock.monotonic_ms());
        if rem_attach <= 15 {
            return;
        }
        uia.apply_timeouts(rem_attach);
        if let Ok(sub) = UiaMenuEventSubscription::attach(uia.automation(), &popup_root, tx) {
            self.popup_uia_sub = Some((popup_raw, sub));
        }
    }

    fn maybe_attach_popup_for_focus(
        &mut self,
        uia: &UiaClient,
        event_hwnd_raw: isize,
        native_hwnd: Option<HWND>,
        bound_hwnd: HWND,
        deadline_ms: i64,
        clock: &dyn CollectorClock,
    ) {
        let bound_hwnd_raw = bound_hwnd.0 as isize;
        if event_hwnd_raw != 0 && event_hwnd_raw != bound_hwnd_raw {
            self.maybe_attach_popup_uia_subscription(uia, event_hwnd_raw, deadline_ms, clock);
        } else if let Some(native) = native_hwnd {
            if native != bound_hwnd {
                self.maybe_attach_popup_uia_subscription(
                    uia,
                    native.0 as isize,
                    deadline_ms,
                    clock,
                );
            }
        }
    }

    fn detach_uia_subscription(
        &mut self,
        uia: Option<&UiaClient>,
        budget: Option<(i64, &dyn CollectorClock)>,
    ) {
        self.detach_popup_uia_subscription(uia, budget);
        if let Some(sub) = self.uia_sub.take() {
            detach_subscription_with_budget(sub, self.retiring, uia, budget);
        }
        self.uia_tx = None;
        self.uia_rx = None;
    }

    fn clear_win32_menu_state(&mut self) {
        self.win32.clear();
    }

    fn arm_verified_menu_bar_item(&mut self, title: String, bound_hwnd_raw: isize, now_mono: i64) {
        self.open_uia_menus.clear();
        self.win32.on_verified_menu_bar_item(title, now_mono);
        let transition = self
            .tracking
            .menu_opened(MenuHandleKey::Win32MenuBar(bound_hwnd_raw), true);
        self.sync_open_uia_menus();
        self.tracking.cancel();
        self.apply_tracking_change(transition.tracking_changed, now_mono);
    }

    fn record_open_uia_menu(
        &mut self,
        key: MenuHandleKey,
        elem: IUIAutomationElement,
        runtime_id: RuntimeIdKey,
        is_top_level: bool,
    ) {
        if is_top_level {
            self.open_uia_menus.clear();
        }
        self.sync_open_uia_menus();
        self.open_uia_menus.retain(|entry| entry.key != key);
        while self.open_uia_menus.len() >= MAX_OPEN_MENUS {
            self.open_uia_menus.remove(0);
        }
        self.open_uia_menus.push(OpenUiaMenu {
            key,
            elem,
            runtime_id,
        });
    }

    fn sync_open_uia_menus(&mut self) {
        let open = self.tracking.open_menus();
        self.open_uia_menus
            .retain(|entry| open.contains(&entry.key));
    }

    fn clear_tracking_state(
        &mut self,
        uia: Option<&UiaClient>,
        emit_stop_tracking: bool,
        budget: Option<(i64, &dyn CollectorClock)>,
    ) {
        self.detach_popup_uia_subscription(uia, budget);
        self.clear_win32_menu_state();
        self.open_uia_menus.clear();
        let transition = self.tracking.reset();
        self.tracking_started_mono_ms = None;
        self.menu_open_flag.store(false, Ordering::Release);
        if emit_stop_tracking {
            if let Some(active) = transition.tracking_changed {
                self.note_menu_tracking(active);
            }
        } else {
            self.pending_tracking = None;
            self.last_reported_tracking = false;
        }
    }

    fn note_menu_tracking(&mut self, active: bool) {
        if active == self.last_reported_tracking {
            return;
        }
        self.last_reported_tracking = active;
        self.pending_tracking = Some(active);
    }

    fn apply_tracking_change(&mut self, tracking_changed: Option<bool>, now_mono_ms: i64) {
        let is_open = self.tracking.is_tracking();
        self.menu_open_flag.store(is_open, Ordering::Release);
        if is_open {
            if self.tracking_started_mono_ms.is_none() {
                self.tracking_started_mono_ms = Some(now_mono_ms);
            }
        } else {
            self.tracking_started_mono_ms = None;
        }
        if let Some(active) = tracking_changed {
            self.note_menu_tracking(active);
        }
    }

    fn current_win32_link(&self, now_mono_ms: i64) -> Option<Win32MenuBarLink> {
        self.win32.current_link(now_mono_ms)
    }

    /// Poll all menu event sources (`WinEventWatcher`, MTA `UiaMenuEventSubscription`, and
    /// optional `MenuCommitHook`), enforcing pre-read & post-read privacy gates before reading any
    /// menu title and queuing verified `MenuActionRecord`s.
    pub fn poll(
        &mut self,
        uia: &UiaClient,
        registry: &AdapterRegistry,
        win_events: Vec<WinMenuEvent>,
        win_events_dropped: bool,
        clock: &dyn CollectorClock,
    ) {
        if !self.enabled || self.retiring || self.secure_input_suppressed {
            return;
        }

        let now_mono = clock.monotonic_ms();
        // ONE hard aggregate deadline across the ENTIRE `poll()` invocation (never per-event).
        let poll_deadline = now_mono.saturating_add(MENU_EVENT_BUDGET_MS);

        // Fail closed on bounded-channel overflow in any event source so a dropped `MenuClosed`,
        // `MenuEnd`, `PopupEnd`, `Escape`, or `Cancel` signal can never leave stale menu tracking
        // or highlights armed.
        let mut dropped_any = win_events_dropped;
        if let Some(ref sub) = self.uia_sub {
            if sub.take_dropped_count() > 0 {
                dropped_any = true;
            }
        }
        if let Some((_, ref sub)) = self.popup_uia_sub {
            if sub.take_dropped_count() > 0 {
                dropped_any = true;
            }
        }
        if let Some(ref hook) = self.commit_hook {
            if hook.take_dropped_menu_signals() > 0 {
                dropped_any = true;
            }
        }
        if dropped_any {
            if let Some(ref rx) = self.uia_rx {
                while rx.try_recv().is_ok() {}
            }
            if let Some(ref hook) = self.commit_hook {
                let _ = hook.drain_signals();
            }
            self.accept_after_qpc_ns = qpc_ns_now();
            self.clear_tracking_state(Some(uia), true, Some((poll_deadline, clock)));
            return;
        }

        // Fail-safe ceiling: never leave menu tracking, ActiveMenuBarLink, or the passive hook
        // latched past 10s if an app crashed or dropped its MenuEnd/MenuClosed notification.
        let tracking_expired = self.tracking_started_mono_ms.is_some_and(|started| {
            now_mono.saturating_sub(started) >= MenuPathLimits::MAX_MENU_TRACKING_MS
        });
        let link_expired = self.win32.expire_if_stale(now_mono);
        if tracking_expired || link_expired {
            self.clear_tracking_state(Some(uia), true, Some((poll_deadline, clock)));
        }

        // Drain MTA UIA menu events and optional passive hook signals once per poll cycle and
        // merge all 3 streams in strict monotonic QPC nanosecond order.
        let mut uia_events: Vec<Option<RawUiaMenuEvent>> = Vec::new();
        if let Some(ref rx) = self.uia_rx {
            while let Ok(ev) = rx.try_recv() {
                uia_events.push(Some(ev));
            }
        }
        let uia_meta: Vec<(Option<UiaMenuEventKind>, u64)> = uia_events
            .iter()
            .map(|slot| {
                slot.as_ref()
                    .map(|ev| (ev.kind(), ev.observed_qpc_ns))
                    .unwrap_or((None, 0))
            })
            .collect();
        let commit_signals = self
            .commit_hook
            .as_ref()
            .map(MenuCommitHook::drain_signals)
            .unwrap_or_default();
        let now_qpc = (!commit_signals.is_empty()).then(qpc_ns_now);

        for step in plan_merged_poll_events(&win_events, &uia_meta, &commit_signals) {
            match step {
                MergedPollEvent::WinEvent(idx) => {
                    let ev = win_events[idx];
                    match ev.kind {
                        WinMenuEventKind::MenuBarStart
                        | WinMenuEventKind::PopupStart
                        | WinMenuEventKind::FocusChanged => {
                            if clock.monotonic_ms() < poll_deadline {
                                self.handle_win_open_or_focus(
                                    uia,
                                    registry,
                                    ev,
                                    poll_deadline,
                                    clock,
                                );
                            }
                        }
                        WinMenuEventKind::DisarmNonMenuBar
                        | WinMenuEventKind::PopupEnd
                        | WinMenuEventKind::MenuEnd
                        | WinMenuEventKind::ForegroundChanged => {
                            self.handle_win_close_or_switch(uia, ev, poll_deadline, clock);
                        }
                    }
                }
                MergedPollEvent::UiaEvent(idx) => {
                    if let Some(ev) = uia_events.get_mut(idx).and_then(Option::take) {
                        self.handle_uia_menu_event(uia, registry, ev, poll_deadline, clock);
                    }
                }
                MergedPollEvent::CommitSignal(idx) => {
                    if let Some(qpc) = now_qpc {
                        self.handle_commit_signal(
                            uia,
                            registry,
                            commit_signals[idx],
                            qpc,
                            poll_deadline,
                            clock,
                        );
                    }
                }
            }
        }

        self.menu_open_flag
            .store(self.tracking.is_tracking(), Ordering::Release);
    }

    /// Applies the pure state transition for a verified `PopupStart` event, clearing stale UIA
    /// `RuntimeId` entries when transitioning to a new top-level popup so a suppressed `MenuClosed`
    /// after `PopupEnd` can never misclassify the next top-level menu as a submenu.
    fn apply_verified_popup_start(
        &mut self,
        popup_raw: isize,
        popup_title: Option<String>,
        now_mono: i64,
    ) {
        let is_top_level_popup =
            self.win32.is_popup_stack_empty() || !self.win32.has_bar_item_owner_popup();
        if is_top_level_popup {
            self.open_uia_menus.clear();
        }
        self.win32.on_popup_start(popup_raw, popup_title, now_mono);
        let transition = self
            .tracking
            .menu_opened(MenuHandleKey::Hwnd(popup_raw), is_top_level_popup);
        self.sync_open_uia_menus();
        self.apply_tracking_change(transition.tracking_changed, now_mono);
    }

    fn handle_win_open_or_focus(
        &mut self,
        uia: &UiaClient,
        registry: &AdapterRegistry,
        ev: WinMenuEvent,
        poll_deadline: i64,
        clock: &dyn CollectorClock,
    ) {
        let now_mono = clock.monotonic_ms();
        if now_mono >= poll_deadline {
            return;
        }
        match ev.kind {
            WinMenuEventKind::MenuBarStart => {
                // Strictly require `OBJID_MENU (-3)` for classic Win32 `#32768` menu-bar linkage.
                if !ev.from_objid_menu {
                    self.clear_tracking_state(Some(uia), true, Some((poll_deadline, clock)));
                    return;
                }
                if !self.passes_bound_privacy_gates(uia, registry, poll_deadline, clock) {
                    self.clear_tracking_state(Some(uia), true, Some((poll_deadline, clock)));
                    return;
                }
                self.open_uia_menus.clear();
                self.win32.on_menu_bar_start(now_mono);
                let transition = self
                    .tracking
                    .menu_opened(MenuHandleKey::Win32MenuBar(ev.hwnd_raw), true);
                self.sync_open_uia_menus();
                self.apply_tracking_change(transition.tracking_changed, now_mono);
            }
            WinMenuEventKind::PopupStart => {
                if !self.win32.is_active(now_mono) || ev.hwnd_raw == 0 {
                    return;
                }
                if !self.passes_bound_privacy_gates(uia, registry, poll_deadline, clock) {
                    self.clear_tracking_state(Some(uia), true, Some((poll_deadline, clock)));
                    return;
                }
                let popup_hwnd = root_hwnd_for_raw(ev.hwnd_raw);
                let Some((bound_hwnd, expected_pid, raw_pid, dpi)) = self
                    .bound
                    .as_ref()
                    .map(|b| (b.hwnd, b.app.process_id, b.raw_pid, b.dpi))
                else {
                    return;
                };
                if !popup_hwnd_belongs_to_bound(popup_hwnd, bound_hwnd, expected_pid, raw_pid) {
                    return;
                }
                let rem = poll_deadline.saturating_sub(clock.monotonic_ms());
                if rem <= 0 {
                    return;
                }
                uia.apply_timeouts(rem.min(50));
                let Ok(popup_el) = uia.element_from_hwnd(popup_hwnd) else {
                    return;
                };
                if uia.is_root_desktop_element(&popup_el) {
                    return;
                }
                let Ok(meta) = uia.read_cached_metadata(&popup_el, dpi, false, false) else {
                    return;
                };
                let safe = meta_is_safe_for_bound(&meta, expected_pid, raw_pid);
                let is_classic_menu = meta.control_type == UIA_MENU_CONTROL_TYPE
                    || meta
                        .class_name
                        .as_deref()
                        .is_some_and(|c| c.eq_ignore_ascii_case("#32768"));
                let is_xaml_popup = meta
                    .class_name
                    .as_deref()
                    .is_some_and(|c| c.eq_ignore_ascii_case("Xaml_WindowedPopupClass"))
                    || (is_owned_popup_hwnd(popup_hwnd, bound_hwnd)
                        && matches!(
                            meta.control_type,
                            UIA_WINDOW_CONTROL_TYPE
                                | UIA_PANE_CONTROL_TYPE
                                | UIA_GROUP_CONTROL_TYPE
                                | UIA_CUSTOM_CONTROL_TYPE
                        ));
                if !safe || (!is_classic_menu && !is_xaml_popup) {
                    return;
                }
                let popup_title = if is_classic_menu && self.win32.is_from_objid_menu() {
                    preferred_meta_title(&meta)
                } else {
                    None
                };
                let popup_raw = popup_hwnd.0 as isize;
                self.maybe_attach_popup_uia_subscription(uia, popup_raw, poll_deadline, clock);
                self.apply_verified_popup_start(popup_raw, popup_title, clock.monotonic_ms());
            }
            WinMenuEventKind::FocusChanged => {
                // Fast non-COM pre-gate first, then structural-only ControlType probe (zero
                // Name/Title/Value reads) so non-menu focus changes in Chrome/Edge never trigger
                // the heavy `is_private_browser_window_chrome` scan. Only menu candidates proceed
                // to full `passes_bound_privacy_gates` + `read_cached_metadata`.
                self.handle_focus_changed(uia, registry, ev.hwnd_raw, poll_deadline, clock);
            }
            _ => {}
        }
    }

    fn handle_focus_changed(
        &mut self,
        uia: &UiaClient,
        registry: &AdapterRegistry,
        event_hwnd_raw: isize,
        deadline_ms: i64,
        clock: &dyn CollectorClock,
    ) {
        let Some(ctx) = self.bound.as_ref().and_then(|bound| {
            passes_fast_menu_privacy_pre_gate(registry, bound, deadline_ms, clock)?;
            Some(bound.walk_ctx())
        }) else {
            self.clear_tracking_state(Some(uia), true, Some((deadline_ms, clock)));
            return;
        };

        let now_mono = clock.monotonic_ms();
        let rem = deadline_ms.saturating_sub(now_mono);
        if rem <= 0 {
            return;
        }
        // Structural-only focus ControlType probe: ZERO `Name`/`Title`/`Value`/`metadata_cache`!
        let probe_timeout_ms = if self.tracking.is_tracking() { 40 } else { 25 };
        uia.apply_timeouts(rem.min(probe_timeout_ms));
        let Ok(raw_focused) = uia.focused_element_raw() else {
            if self.tracking.is_tracking() || self.win32.is_armed() {
                self.clear_tracking_state(Some(uia), true, Some((deadline_ms, clock)));
            }
            return;
        };
        let Ok(ct) = uia.current_control_type(&raw_focused) else {
            if self.tracking.is_tracking() || self.win32.is_armed() {
                self.clear_tracking_state(Some(uia), true, Some((deadline_ms, clock)));
            }
            return;
        };
        if !is_structural_menu_focus_candidate(
            uia,
            &raw_focused,
            ct,
            ctx.is_browser,
            deadline_ms,
            clock,
        ) {
            // Non-menu element (e.g. `AXTextArea`, `Document`, `Edit`, regular button, tab):
            // immediately disarm `ActiveMenuBarLink` & tracking with ZERO browser chrome probe
            // and ZERO `metadata_cache` text reads.
            if self.tracking.is_tracking() || self.win32.is_armed() {
                self.clear_tracking_state(Some(uia), true, Some((deadline_ms, clock)));
            }
            return;
        }

        // Full pre-read privacy gate (including fail-closed `is_private_browser_window_chrome`
        // for browsers) BEFORE reading any `Name`/`Title` via `metadata_cache`.
        if !self.passes_bound_privacy_gates(uia, registry, deadline_ms, clock) {
            self.clear_tracking_state(Some(uia), true, Some((deadline_ms, clock)));
            return;
        }

        let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
        if rem <= 0 {
            return;
        }
        uia.apply_timeouts(rem.min(60));
        let Ok(focused) = uia.refresh_metadata(&raw_focused) else {
            if self.tracking.is_tracking() || self.win32.is_armed() {
                self.clear_tracking_state(Some(uia), true, Some((deadline_ms, clock)));
            }
            return;
        };
        let Ok(meta) = uia.read_cached_metadata(&focused, ctx.dpi, false, false) else {
            if self.tracking.is_tracking() || self.win32.is_armed() {
                self.clear_tracking_state(Some(uia), true, Some((deadline_ms, clock)));
            }
            return;
        };
        if !meta_is_safe_for_bound(&meta, ctx.expected_pid, ctx.raw_pid) {
            self.clear_tracking_state(Some(uia), true, Some((deadline_ms, clock)));
            return;
        }

        let now_mono = clock.monotonic_ms();
        let bound_hwnd_raw = ctx.hwnd.0 as isize;

        // 1. Check whether focused element is a verified top-level item inside a non-`SystemMenuBar`
        // `MenuBar (50010)` belonging to `bound_hwnd` (WinUI 3 Notepad, Electron, classic Win32).
        if let Some(title) = self.bound.as_ref().and_then(|bound| {
            detect_verified_menu_bar_item(uia, &focused, &meta, bound, deadline_ms, clock)
        }) {
            self.arm_verified_menu_bar_item(title, bound_hwnd_raw, now_mono);
            return;
        }

        // 2. Focus landed on a `MenuBar` container itself: preserve active tracking only if it is
        // the verified app `MenuBar`; clear on `SystemMenuBar` or foreign/document bar.
        if meta.control_type == UIA_MENU_BAR_CONTROL_TYPE {
            let valid_bar = !is_system_menu_bar(&meta)
                && menu_bar_belongs_to_window(uia, &focused, &meta, &ctx, deadline_ms, clock);
            if valid_bar {
                self.tracking.cancel();
            } else {
                self.clear_tracking_state(Some(uia), true, Some((deadline_ms, clock)));
            }
            return;
        }

        // 3. Focus landed directly on a `Menu (50009)` container (e.g., WinUI 3 `MenuFlyoutPresenter`
        // or Electron `<ul role="menu">` right on open): verify via `classify_uia_opened_menu`
        // and replace any `Win32MenuBar` / `Hwnd` placeholder cleanly so `MenuClosed` matches exact handle.
        if meta.control_type == UIA_MENU_CONTROL_TYPE {
            if let Some((key, opened_kind, menu_el, menu_rid)) =
                self.classify_uia_opened_menu(uia, focused, deadline_ms, clock)
            {
                self.maybe_attach_popup_for_focus(
                    uia,
                    event_hwnd_raw,
                    meta.native_hwnd,
                    ctx.hwnd,
                    deadline_ms,
                    clock,
                );
                let is_top = opened_kind == OpenedMenuKind::TopLevel;
                let already_tracked = self.open_uia_menus.iter().any(|e| e.key == key);
                let replacing_placeholder = is_top
                    && self.open_uia_menus.is_empty()
                    && self
                        .tracking
                        .open_menus()
                        .iter()
                        .all(|k| !matches!(k, MenuHandleKey::RuntimeId(_)));
                if !self.tracking.is_tracking()
                    || replacing_placeholder
                    || opened_kind == OpenedMenuKind::Submenu
                {
                    let transition = self.tracking.menu_opened(key.clone(), is_top);
                    self.record_open_uia_menu(key, menu_el, menu_rid, is_top);
                    if !already_tracked {
                        self.win32.on_uia_menu_opened(!is_top, now_mono);
                    }
                    self.apply_tracking_change(transition.tracking_changed, now_mono);
                }
                self.tracking.cancel();
            } else {
                self.clear_tracking_state(Some(uia), true, Some((deadline_ms, clock)));
            }
            return;
        }

        // 4. Focus is on a `MenuItem` inside an opened menu.
        if meta.control_type == UIA_MENU_ITEM_CONTROL_TYPE {
            if self.win32.is_active(now_mono) || self.tracking.is_tracking() {
                self.maybe_attach_popup_for_focus(
                    uia,
                    event_hwnd_raw,
                    meta.native_hwnd,
                    ctx.hwnd,
                    deadline_ms,
                    clock,
                );
            }

            // Refresh UIA timeouts immediately before `is_submenu_opener` and `has_menu_child`.
            let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
            if rem <= 0 {
                self.tracking.cancel();
                return;
            }
            uia.apply_timeouts(rem);
            let opener_pattern = uia.is_submenu_opener(&focused);
            let menu_child = has_menu_child(uia, &focused, ctx.dpi, deadline_ms, clock);
            let is_opener = matches!(opener_pattern, Ok(true)) || matches!(menu_child, Ok(true));
            if is_opener || meta.is_enabled == Some(false) {
                if self.tracking.is_tracking() && is_opener && meta.is_enabled != Some(false) {
                    self.win32
                        .on_submenu_opener_focused(preferred_meta_title(&meta), now_mono);
                }
                self.tracking.cancel();
                return;
            }
            if opener_pattern.is_err() || menu_child.is_err() {
                self.tracking.cancel();
                return;
            }

            // Pass precomputed `(Some(0), Some(false))` leaf checks so `inspect_walk_handle`
            // does NOT repeat `has_menu_child` and `is_submenu_opener` COM IPCs!
            let Some(resolved) = self.resolve_leaf_menu_item_cached(
                uia,
                focused,
                meta,
                Some((Some(0), Some(false))),
                deadline_ms,
                clock,
            ) else {
                self.tracking.cancel();
                return;
            };

            if !self.tracking.is_tracking() {
                // Direct `MenuBar`-anchored leaf (e.g. Electron `Alt+F` skipping bar-item focus):
                // `resolve_leaf_menu_item_cached` proved direct `MenuBar` ownership without needing
                // any `win32_link`, so arm tracking for `MenuCommitHook` fallback.
                let transition = self
                    .tracking
                    .menu_opened(MenuHandleKey::Win32MenuBar(bound_hwnd_raw), true);
                self.sync_open_uia_menus();
                self.apply_tracking_change(transition.tracking_changed, now_mono);
            }
            let active_key = self
                .win32
                .last_popup_hwnd()
                .map(MenuHandleKey::Hwnd)
                .filter(|k| self.tracking.open_menus().contains(k))
                .or_else(|| self.tracking.open_menus().last().cloned());
            if let Some(menu_key) = active_key {
                self.tracking
                    .update_selection(Some(resolved), menu_key, clock.monotonic_ms());
            }
            return;
        }

        // 5. Fallback for non-menu candidates (e.g., `Button` whose parent wasn't a valid MenuBar).
        if self.tracking.is_tracking() || self.win32.is_armed() {
            self.clear_tracking_state(Some(uia), true, Some((deadline_ms, clock)));
        }
    }

    fn apply_uia_menu_closed(
        &mut self,
        uia: Option<&UiaClient>,
        key_opt: Option<MenuHandleKey>,
        now_mono_ms: i64,
        budget: Option<(i64, &dyn CollectorClock)>,
    ) {
        let transition = if let Some(key) = key_opt {
            let tr = self.tracking.menu_closed(&key);
            if tr.removed.is_empty() {
                // Fail closed if the closed menu key was not tracked in `open_menus` (e.g. when a
                // `Win32MenuBar` placeholder was active): never leave `ActiveMenuBarLink` latched.
                self.tracking.reset()
            } else {
                tr
            }
        } else {
            // Windows UIA routinely delivers `UIA_MenuClosedEventId` with NULL sender.
            self.tracking.reset()
        };
        if !self.tracking.is_tracking() {
            self.detach_popup_uia_subscription(uia, budget);
            self.clear_win32_menu_state();
            self.open_uia_menus.clear();
        } else {
            self.sync_open_uia_menus();
            self.win32
                .on_uia_menu_closed(self.tracking.open_menus().len());
        }
        self.apply_tracking_change(transition.tracking_changed, now_mono_ms);
    }

    fn handle_uia_menu_event(
        &mut self,
        uia: &UiaClient,
        registry: &AdapterRegistry,
        ev: RawUiaMenuEvent,
        poll_deadline: i64,
        clock: &dyn CollectorClock,
    ) {
        let Some(kind) = ev.kind() else {
            return;
        };

        match kind {
            UiaMenuEventKind::MenuOpened => {
                if clock.monotonic_ms() >= poll_deadline {
                    return;
                }
                let Some(mta_sender) = ev.sender else {
                    return;
                };
                if !self.passes_bound_privacy_gates(uia, registry, poll_deadline, clock) {
                    self.clear_tracking_state(Some(uia), true, Some((poll_deadline, clock)));
                    return;
                }
                let sender_el = mta_sender.into_inner();
                let Some((key, opened_kind, menu_el, menu_rid)) =
                    self.classify_uia_opened_menu(uia, sender_el, poll_deadline, clock)
                else {
                    return;
                };
                let is_top = opened_kind == OpenedMenuKind::TopLevel;
                let already_tracked = self.open_uia_menus.iter().any(|e| e.key == key);
                let transition = self.tracking.menu_opened(key.clone(), is_top);
                self.record_open_uia_menu(key, menu_el, menu_rid, is_top);
                let now_mono = clock.monotonic_ms();
                if !already_tracked {
                    self.win32.on_uia_menu_opened(!is_top, now_mono);
                }
                self.apply_tracking_change(transition.tracking_changed, now_mono);
            }
            UiaMenuEventKind::MenuClosed => {
                if !self.tracking.is_tracking() {
                    return;
                }
                let has_runtime_id_keys = self
                    .tracking
                    .open_menus()
                    .iter()
                    .any(|k| matches!(k, MenuHandleKey::RuntimeId(_)));
                let key_opt = if !has_runtime_id_keys {
                    // No RuntimeId keys open: skip COM entirely and reset cleanly!
                    None
                } else if let Some(mta_sender) = ev.sender {
                    let rem = poll_deadline.saturating_sub(clock.monotonic_ms());
                    if rem <= 0 {
                        None
                    } else {
                        let sender_el = mta_sender.into_inner();
                        uia.apply_timeouts(rem.min(40));
                        // Integer SAFEARRAY only — zero 27-property `refresh_metadata`!
                        uia.live_runtime_id(&sender_el)
                            .map(MenuHandleKey::RuntimeId)
                    }
                } else {
                    None
                };
                self.apply_uia_menu_closed(
                    Some(uia),
                    key_opt,
                    clock.monotonic_ms(),
                    Some((poll_deadline, clock)),
                );
            }
            UiaMenuEventKind::Invoked => {
                if clock.monotonic_ms() >= poll_deadline {
                    return;
                }
                let Some(mta_sender) = ev.sender else {
                    return;
                };
                // Cheap zero-COM pre-gate FIRST.
                let Some((dpi, is_browser)) = self.bound.as_ref().and_then(|bound| {
                    passes_fast_menu_privacy_pre_gate(registry, bound, poll_deadline, clock)?;
                    Some((bound.dpi, bound.is_browser))
                }) else {
                    self.clear_tracking_state(Some(uia), true, Some((poll_deadline, clock)));
                    return;
                };

                // Cheap structural ControlType pre-filter (ZERO text reads!) BEFORE running the
                // 80ms browser chrome scan or 27-property `refresh_metadata`!
                // Reuse `is_structural_menu_focus_candidate` for `Button (50000)` so WinUI 3
                // (`Button -> MenuItem -> MenuBar`) and Electron custom titlebar wrappers
                // (`Button -> Custom/Group/Pane (<=2 hops) -> MenuBar`) match `FocusChanged` and
                // `detect_verified_menu_bar_item`, while browser `<button>` stays capped at 0 hops.
                let sender_el = mta_sender.into_inner();
                let rem = poll_deadline.saturating_sub(clock.monotonic_ms());
                if rem <= 0 {
                    return;
                }
                uia.apply_timeouts(rem.min(25));
                let Ok(ct) = uia.current_control_type(&sender_el) else {
                    return;
                };
                if ct != UIA_MENU_ITEM_CONTROL_TYPE
                    && (ct != UIA_BUTTON_CONTROL_TYPE
                        || !is_structural_menu_focus_candidate(
                            uia,
                            &sender_el,
                            ct,
                            is_browser,
                            poll_deadline,
                            clock,
                        ))
                {
                    return;
                }

                // Full pre-read privacy gate (incl. browser chrome) BEFORE reading any Name/Title.
                if !self.passes_bound_privacy_gates(uia, registry, poll_deadline, clock) {
                    self.clear_tracking_state(Some(uia), true, Some((poll_deadline, clock)));
                    return;
                }
                let rem = poll_deadline.saturating_sub(clock.monotonic_ms());
                if rem <= 0 {
                    return;
                }
                uia.apply_timeouts(rem);
                let Ok(refreshed_sender) = uia.refresh_metadata(&sender_el) else {
                    return;
                };
                let Ok(sender_meta) =
                    uia.read_cached_metadata(&refreshed_sender, dpi, false, false)
                else {
                    return;
                };

                // Before rejecting a non-leaf invoked element, check if it is a top-level item
                // inside a verified non-`SystemMenuBar` `MenuBar (50010)` belonging to `bound_hwnd`
                // (e.g., WinUI 3 Notepad / Electron clicking `"File"`).
                if let Some(bar_title) = self.bound.as_ref().and_then(|bound| {
                    detect_verified_menu_bar_item(
                        uia,
                        &refreshed_sender,
                        &sender_meta,
                        bound,
                        poll_deadline,
                        clock,
                    )
                }) {
                    if !self.passes_bound_privacy_gates(uia, registry, poll_deadline, clock) {
                        self.clear_tracking_state(Some(uia), true, Some((poll_deadline, clock)));
                        return;
                    }
                    if let Some(bound_hwnd_raw) = self.bound.as_ref().map(|b| b.hwnd.0 as isize) {
                        let mono = clock.monotonic_ms();
                        self.arm_verified_menu_bar_item(bar_title, bound_hwnd_raw, mono);
                    }
                    return;
                }

                let Some(resolved) = self.resolve_leaf_menu_item_cached(
                    uia,
                    refreshed_sender,
                    sender_meta,
                    None,
                    poll_deadline,
                    clock,
                ) else {
                    return;
                };
                // Post-read privacy gate AFTER ancestor resolution.
                if !self.passes_bound_privacy_gates(uia, registry, poll_deadline, clock) {
                    self.clear_tracking_state(Some(uia), true, Some((poll_deadline, clock)));
                    return;
                }
                // Consume any volatile highlight so fallback hook cannot double-emit, enqueue, and
                // disarm active menu tracking immediately after a committed leaf invocation.
                let commit_mono = clock.monotonic_ms();
                let _ = self.tracking.commit(commit_mono);
                self.enqueue_resolved_action(resolved, ev.observed_unix_ms, commit_mono);
                self.clear_tracking_state(Some(uia), true, Some((poll_deadline, clock)));
            }
        }
    }

    fn handle_commit_signal(
        &mut self,
        uia: &UiaClient,
        registry: &AdapterRegistry,
        sig: MenuCommitSignal,
        now_qpc_ns: u64,
        poll_deadline: i64,
        clock: &dyn CollectorClock,
    ) {
        let sig_qpc = sig.qpc_ns();
        if sig_qpc <= self.accept_after_qpc_ns {
            return;
        }
        match sig {
            MenuCommitSignal::Escape { .. } | MenuCommitSignal::Cancel { .. } => {
                // Disarm ActiveMenuBarLink + tracking unconditionally whenever `sig_qpc >
                // accept_after_qpc_ns` — NEVER reject Esc or right-click (`WM_RBUTTONDOWN`) via
                // the 200ms commit freshness cap or `sig_qpc > now_qpc_ns`, so a >200ms read can
                // never drop disarming and leak a stale top-menu-bar link into a context menu.
                self.clear_tracking_state(Some(uia), true, Some((poll_deadline, clock)));
            }
            MenuCommitSignal::LeftButtonUp { unix_ms, .. }
            | MenuCommitSignal::Return { unix_ms, .. } => {
                if sig_qpc > now_qpc_ns || now_qpc_ns - sig_qpc > MAX_COMMIT_SIGNAL_AGE_NS {
                    return;
                }
                let now_mono = clock.monotonic_ms();
                let Some(resolved) = self.tracking.commit(now_mono) else {
                    return;
                };
                if now_mono >= poll_deadline
                    || !self.passes_bound_privacy_gates(uia, registry, poll_deadline, clock)
                {
                    self.clear_tracking_state(Some(uia), true, Some((poll_deadline, clock)));
                    return;
                }
                self.enqueue_resolved_action(resolved, unix_ms, now_mono);
                self.clear_tracking_state(Some(uia), true, Some((poll_deadline, clock)));
            }
        }
    }

    fn handle_win_close_or_switch(
        &mut self,
        uia: &UiaClient,
        ev: WinMenuEvent,
        poll_deadline: i64,
        clock: &dyn CollectorClock,
    ) {
        let now_mono = clock.monotonic_ms();
        let budget = Some((poll_deadline, clock));
        match ev.kind {
            WinMenuEventKind::DisarmNonMenuBar => {
                // Any non-`OBJID_MENU` `EVENT_SYSTEM_MENUSTART` (including `OBJID_SYSMENU (-1)`
                // and right-click context menus `idObject == 0`) immediately disarms tracking!
                self.clear_tracking_state(Some(uia), true, budget);
            }
            WinMenuEventKind::PopupEnd => {
                if ev.hwnd_raw != 0 {
                    let root_raw = root_hwnd_for_raw(ev.hwnd_raw).0 as isize;
                    if self
                        .popup_uia_sub
                        .as_ref()
                        .is_some_and(|(h, _)| *h == root_raw || *h == ev.hwnd_raw)
                    {
                        self.detach_popup_uia_subscription(Some(uia), budget);
                    }
                    let should_disarm = self.win32.on_popup_end(root_raw);
                    if should_disarm {
                        self.clear_tracking_state(Some(uia), true, budget);
                    } else if self.win32.is_popup_stack_empty() {
                        // Classic Win32 slide-over (`File -> Edit`) or WinUI 3/Electron superseded
                        // popup close: `PopupEnd` detached the popup UIA subscription so
                        // `MenuClosed` for `R1` may never arrive. Clear `open_uia_menus` and stale
                        // `RuntimeId`/`Hwnd` entries from `tracking` so the next top-level menu
                        // (`Edit`) classifies cleanly as `TopLevel`. While a classic `OBJID_MENU`
                        // menu-bar session remains active (`!should_disarm`), restore the
                        // `Win32MenuBar` placeholder so `tracking.is_tracking()` and
                        // `menu_open_flag` stay continuous without emitting a spurious
                        // `menuTracking: false -> true` flicker before `PopupStart` or `MenuEnd`.
                        self.open_uia_menus.clear();
                        let transition = if self.win32.is_from_objid_menu() {
                            let bar_hwnd = self.bound.as_ref().map_or(0, |b| b.hwnd.0 as isize);
                            self.tracking
                                .menu_opened(MenuHandleKey::Win32MenuBar(bar_hwnd), true)
                        } else {
                            self.tracking.retain_open_menus(|k| {
                                !matches!(k, MenuHandleKey::RuntimeId(_))
                                    && *k != MenuHandleKey::Hwnd(root_raw)
                            })
                        };
                        self.sync_open_uia_menus();
                        self.apply_tracking_change(transition.tracking_changed, now_mono);
                    } else {
                        let transition = self
                            .tracking
                            .menu_closed(&MenuHandleKey::Hwnd(root_raw));
                        self.sync_open_uia_menus();
                        self.apply_tracking_change(transition.tracking_changed, now_mono);
                    }
                } else {
                    self.clear_tracking_state(Some(uia), true, budget);
                }
            }
            WinMenuEventKind::MenuEnd => {
                self.clear_tracking_state(Some(uia), true, budget);
            }
            WinMenuEventKind::ForegroundChanged => {
                // Keep active top-menu-bar tracking alive ONLY if foreground moved to a same-PID
                // owned popup of `bound.hwnd` (e.g., WinUI 3 `Xaml_WindowedPopupClass`); any
                // foreign window or unowned sibling window clears tracking immediately.
                let is_owned_popup_fg = ev.hwnd_raw != 0
                    && (self.win32.is_active(now_mono) || self.tracking.is_tracking())
                    && self.bound.as_ref().is_some_and(|b| {
                        let ev_hwnd = HWND(ev.hwnd_raw as *mut core::ffi::c_void);
                        is_owned_popup_hwnd(ev_hwnd, b.hwnd)
                            && hwnd_matches_bound_pid(ev_hwnd, b.app.process_id, b.raw_pid)
                    });
                if !is_owned_popup_fg {
                    self.clear_tracking_state(Some(uia), true, budget);
                }
            }
            _ => {}
        }
    }

    fn enqueue_resolved_action(
        &mut self,
        resolved: ResolvedMenuPath,
        observed_at_ms: i64,
        now_mono_ms: i64,
    ) {
        let Some(ref bound) = self.bound else {
            return;
        };
        if !self.dedup.should_emit(&resolved.path, now_mono_ms) {
            return;
        }
        let record = MenuActionRecord {
            application: bound.app.clone(),
            exe_name: bound.resolved.exe_name.clone(),
            path: resolved.path,
            truncated: resolved.truncated,
            observed_at_ms,
            private_state: bound.private_state.to_string(),
            stamp: bound.stamp,
            field_security: bound.policy.field_security_mode().to_string(),
        };
        let _ = self.pending_records.push(record);
    }

    fn passes_bound_privacy_gates(
        &self,
        uia: &UiaClient,
        registry: &AdapterRegistry,
        deadline_ms: i64,
        clock: &dyn CollectorClock,
    ) -> bool {
        let Some(ref bound) = self.bound else {
            return false;
        };
        passes_live_menu_privacy_gates(uia, registry, bound, deadline_ms, clock)
    }

    fn classify_uia_opened_menu(
        &self,
        uia: &UiaClient,
        menu_elem: IUIAutomationElement,
        deadline_ms: i64,
        clock: &dyn CollectorClock,
    ) -> Option<(MenuHandleKey, OpenedMenuKind, IUIAutomationElement, RuntimeIdKey)> {
        let bound = self.bound.as_ref()?;
        let ctx = bound.walk_ctx();
        let win32_link = self.current_win32_link(clock.monotonic_ms());

        let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
        if rem <= 0 {
            return None;
        }
        uia.apply_timeouts(rem);
        let refreshed = uia.refresh_metadata(&menu_elem).ok()?;
        let meta = uia
            .read_cached_metadata(&refreshed, ctx.dpi, false, false)
            .ok()?;
        let rid = meta.runtime_id.clone();
        let key = if !rid.is_empty() {
            MenuHandleKey::RuntimeId(rid.clone())
        } else {
            let hwnd = meta.native_hwnd?;
            MenuHandleKey::Hwnd(hwnd.0 as isize)
        };

        let app_menu_bar_handle = bound
            .app_menu_bar
            .as_ref()
            .map(|el| WalkHandle::from_uncached(el.clone()));
        let menu_elem_out = refreshed.clone();
        let menu_handle = WalkHandle::from_cached(refreshed, meta);
        let mut open_handles = Vec::with_capacity(self.open_uia_menus.len());
        for entry in &self.open_uia_menus {
            if entry.key == key {
                continue;
            }
            if !rid.is_empty() && !entry.runtime_id.is_empty() {
                // Unequal non-empty runtime_ids already prove distinct elements — skip COM IPC.
                if entry.runtime_id == rid {
                    continue;
                }
            } else {
                let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
                if rem <= 0 {
                    return None;
                }
                uia.apply_timeouts(rem);
                if uia.compare_elements(&entry.elem, &menu_handle.elem) {
                    continue;
                }
            }
            open_handles.push(WalkHandle::from_open_menu(
                entry.elem.clone(),
                entry.runtime_id.clone(),
            ));
        }

        let kind = MenuPathResolver::classify_opened_menu_with_bar_verifier(
            menu_handle,
            ctx.expected_pid,
            ctx.raw_host_pid(),
            app_menu_bar_handle.as_ref(),
            None,
            win32_link.as_ref(),
            &open_handles,
            !ctx.is_browser,
            |a, b| walk_handles_same(uia, a, b, deadline_ms, clock),
            |handle| inspect_walk_handle(uia, handle, false, ctx.dpi, deadline_ms, clock),
            |handle| parent_walk_handle(uia, handle, ctx.dpi, deadline_ms, clock),
            |bar_handle| verify_walk_menu_bar_owner(uia, bar_handle, &ctx, deadline_ms, clock),
            || clock.monotonic_ms() < deadline_ms,
        )?;
        Some((key, kind, menu_elem_out, rid))
    }

    fn resolve_leaf_menu_item_cached(
        &self,
        uia: &UiaClient,
        leaf_elem: IUIAutomationElement,
        leaf_meta: UiaElementMetadata,
        precomputed_leaf_checks: Option<(Option<usize>, Option<bool>)>,
        deadline_ms: i64,
        clock: &dyn CollectorClock,
    ) -> Option<ResolvedMenuPath> {
        let bound = self.bound.as_ref()?;
        let ctx = bound.walk_ctx();
        let win32_link = self.current_win32_link(clock.monotonic_ms());

        let mut leaf_handle = WalkHandle::from_cached(leaf_elem, leaf_meta);
        if let Some((child_count, is_opener)) = precomputed_leaf_checks {
            leaf_handle = leaf_handle.with_leaf_checks(child_count, is_opener);
        }

        resolve_uia_menu_leaf_handle(
            uia,
            leaf_handle,
            &ctx,
            bound.app_menu_bar.as_ref(),
            win32_link.as_ref(),
            deadline_ms,
            clock,
        )
    }

    // -------------------------------------------------------------------------
    // Integration-test helpers (`tests/menu_action_session.rs`)
    // -------------------------------------------------------------------------

    #[doc(hidden)]
    pub fn set_enabled_for_test(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    #[doc(hidden)]
    pub fn is_enabled_for_test(&self) -> bool {
        self.enabled
    }

    #[doc(hidden)]
    pub fn ensure_commit_hook_for_test(&mut self) -> bool {
        self.ensure_commit_hook();
        self.commit_hook.is_some()
    }

    #[doc(hidden)]
    pub fn inject_dropped_commit_signals_for_test(&self, count: u64) {
        if let Some(ref hook) = self.commit_hook {
            hook.inject_dropped_menu_signals_for_test(count);
        }
    }

    #[doc(hidden)]
    pub fn arm_menu_bar_item_for_test(&mut self, title: &str, hwnd_raw: isize, now_mono_ms: i64) {
        self.win32
            .on_verified_menu_bar_item(title.to_string(), now_mono_ms);
        let open_tr = self
            .tracking
            .menu_opened(MenuHandleKey::Win32MenuBar(hwnd_raw), true);
        self.apply_tracking_change(open_tr.tracking_changed, now_mono_ms);
    }

    #[doc(hidden)]
    pub fn start_win32_menu_bar_for_test(&mut self, hwnd_raw: Option<isize>, now_mono_ms: i64) {
        self.win32.on_menu_bar_start(now_mono_ms);
        if let Some(hwnd) = hwnd_raw {
            let open_tr = self
                .tracking
                .menu_opened(MenuHandleKey::Win32MenuBar(hwnd), true);
            self.apply_tracking_change(open_tr.tracking_changed, now_mono_ms);
        }
    }

    #[doc(hidden)]
    pub fn win32_on_popup_start_for_test(
        &mut self,
        popup_hwnd: isize,
        popup_title: Option<String>,
        now_mono_ms: i64,
    ) {
        self.win32
            .on_popup_start(popup_hwnd, popup_title, now_mono_ms);
    }

    #[doc(hidden)]
    pub fn win32_on_verified_menu_bar_item_for_test(&mut self, title: &str, now_mono_ms: i64) {
        self.win32
            .on_verified_menu_bar_item(title.to_string(), now_mono_ms);
    }

    #[doc(hidden)]
    pub fn win32_is_active_for_test(&self, now_mono_ms: i64) -> bool {
        self.win32.is_active(now_mono_ms)
    }

    #[doc(hidden)]
    pub fn apply_verified_popup_start_for_test(
        &mut self,
        popup_raw: isize,
        popup_title: Option<String>,
        now_mono_ms: i64,
    ) {
        self.apply_verified_popup_start(popup_raw, popup_title, now_mono_ms);
    }

    #[doc(hidden)]
    pub fn open_uia_menu_for_test(
        &mut self,
        elem: IUIAutomationElement,
        runtime_id: RuntimeIdKey,
        is_top_level: bool,
        now_mono_ms: Option<i64>,
    ) {
        let key = MenuHandleKey::RuntimeId(runtime_id.clone());
        let tr = self.tracking.menu_opened(key.clone(), is_top_level);
        self.record_open_uia_menu(key, elem, runtime_id, is_top_level);
        if let Some(mono) = now_mono_ms {
            self.apply_tracking_change(tr.tracking_changed, mono);
        }
    }

    #[doc(hidden)]
    pub fn update_selection_for_test(
        &mut self,
        resolved: Option<ResolvedMenuPath>,
        menu_key: MenuHandleKey,
        now_mono_ms: i64,
    ) {
        self.tracking
            .update_selection(resolved, menu_key, now_mono_ms);
    }

    #[doc(hidden)]
    pub fn apply_uia_menu_closed_for_test(
        &mut self,
        key_opt: Option<MenuHandleKey>,
        now_mono_ms: i64,
    ) {
        self.apply_uia_menu_closed(None, key_opt, now_mono_ms, None);
    }

    #[doc(hidden)]
    pub fn clear_tracking_state_for_test(&mut self, emit_stop_tracking: bool) {
        self.clear_tracking_state(None, emit_stop_tracking, None);
    }

    #[doc(hidden)]
    pub fn set_accept_after_qpc_ns_for_test(&mut self, qpc_ns: u64) {
        self.accept_after_qpc_ns = qpc_ns;
    }

    #[doc(hidden)]
    pub fn accept_after_qpc_ns_for_test(&self) -> u64 {
        self.accept_after_qpc_ns
    }

    #[doc(hidden)]
    pub fn handle_commit_signal_for_test(
        &mut self,
        uia: &UiaClient,
        registry: &AdapterRegistry,
        sig: MenuCommitSignal,
        now_qpc_ns: u64,
        poll_deadline: i64,
        clock: &dyn CollectorClock,
    ) {
        self.handle_commit_signal(uia, registry, sig, now_qpc_ns, poll_deadline, clock);
    }

    #[doc(hidden)]
    pub fn handle_win_close_or_switch_for_test(
        &mut self,
        uia: &UiaClient,
        ev: WinMenuEvent,
        poll_deadline: i64,
        clock: &dyn CollectorClock,
    ) {
        self.handle_win_close_or_switch(uia, ev, poll_deadline, clock);
    }

    #[doc(hidden)]
    pub fn is_tracking_for_test(&self) -> bool {
        self.tracking.is_tracking()
    }

    #[doc(hidden)]
    pub fn has_selection_for_test(&self) -> bool {
        self.tracking.has_selection()
    }

    #[doc(hidden)]
    pub fn is_menu_open_flag_set_for_test(&self) -> bool {
        self.menu_open_flag.load(Ordering::Acquire)
    }

    #[doc(hidden)]
    pub fn current_win32_link_for_test(&self, now_mono_ms: i64) -> Option<Win32MenuBarLink> {
        self.current_win32_link(now_mono_ms)
    }

    #[doc(hidden)]
    pub fn open_menu_keys_for_test(&self) -> &[MenuHandleKey] {
        self.tracking.open_menus()
    }

    #[doc(hidden)]
    pub fn open_uia_menu_keys_for_test(&self) -> Vec<MenuHandleKey> {
        self.open_uia_menus
            .iter()
            .map(|entry| entry.key.clone())
            .collect()
    }

    #[doc(hidden)]
    pub fn has_uia_subscription_for_test(&self) -> bool {
        self.uia_sub.is_some()
    }

    #[doc(hidden)]
    pub fn has_popup_uia_subscription_for_test(&self) -> bool {
        self.popup_uia_sub.is_some()
    }
}
