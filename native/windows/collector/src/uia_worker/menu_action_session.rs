//! Foreground top-menu-bar action capture (`menu.action` / `uia.menu`) running inside the isolated
//! `--ax-worker --session-worker yes` process.
//!
//! Layer 1 module — imports ONLY Layer 0 `uia_worker` leaves (`target_verify`, `uia_events`,
//! `input_hook`) and core modules (`adapters`, `desktop`, `menu_action_core`, `policy`,
//! `protocol_model`, `uia_com`, `uia_traversal`). ZERO imports of `read_pipeline` or `session`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};

use windows::Win32::Foundation::HWND;
use windows::Win32::UI::Accessibility::IUIAutomationElement;
use windows::Win32::UI::WindowsAndMessaging::{GetAncestor, GetForegroundWindow, GA_ROOT};

use super::input_hook::{qpc_ns_now, MenuCommitHook, MenuCommitSignal};
use super::target_verify::{read_window_title_ephemeral, resolve_application_identity_for_hwnd};
use super::uia_events::{
    create_menu_event_channel, RawUiaMenuEvent, UiaMenuEventKind, UiaMenuEventSubscription,
};
use crate::adapters::AdapterRegistry;
use crate::desktop::assess_windows_desktop;
use crate::menu_action_core::{
    BrowserChromeVerdict, BrowserMenuWindowGate, BrowserWindowInspection, MenuActionDeduplicator,
    MenuActionPendingQueue, MenuActionRecord, MenuNodeSnapshot, MenuPathLimits, MenuPathResolver,
    MenuTrackingStateMachine, OpenedMenuKind, ResolvedMenuPath, Win32MenuBarLink,
    UIA_MENU_BAR_CONTROL_TYPE, UIA_MENU_CONTROL_TYPE, UIA_MENU_ITEM_CONTROL_TYPE,
};
use crate::policy::{ApplicationPolicy, BrowserGate, ResolvedAppIdentity, TextSecurityGate};
use crate::protocol_model::{
    ApplicationIdentity, CapturePolicy, CollectorClock, DesktopStatus, Stamp,
};
use crate::uia_com::{
    PrivateChromeVerdict, UiaCallError, UiaClient, UiaElementMetadata, WinMenuEvent,
    WinMenuEventKind,
};
use crate::uia_traversal::RuntimeIdKey;

/// Hard per-event UIA inspection & ancestor-walk time budget (ms).
const MENU_EVENT_BUDGET_MS: i64 = 120;
/// Maximum accepted hook signal age (200ms) in monotonic QPC nanoseconds.
const MAX_COMMIT_SIGNAL_AGE_NS: u64 = 200_000_000;
/// Maximum direct children scanned on the bound window when locating the top application `MenuBar`.
const MAX_WINDOW_MENU_BAR_PROBE_CHILDREN: usize = 16;

/// Verified bound foreground window identity handed from `LiveUiaSession` to `MenuActionSession`.
#[derive(Debug, Clone)]
pub(super) struct MenuBindingTarget {
    pub(super) hwnd: HWND,
    pub(super) raw_pid: u32,
    pub(super) app: ApplicationIdentity,
    pub(super) resolved: ResolvedAppIdentity,
    pub(super) dpi: u32,
    pub(super) private_state: &'static str,
}

struct BoundMenuWindow {
    hwnd: HWND,
    raw_pid: u32,
    app: ApplicationIdentity,
    resolved: ResolvedAppIdentity,
    dpi: u32,
    private_state: &'static str,
    policy: CapturePolicy,
    stamp: Stamp,
    /// Optional cached direct non-`SystemMenuBar` `MenuBar (50010)` element of `hwnd`.
    app_menu_bar: Option<IUIAutomationElement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MenuHandleKey {
    RuntimeId(RuntimeIdKey),
    Hwnd(isize),
    Win32MenuBar(isize),
}

/// Element handle carried during `MenuPathResolver` ancestor walks so cached metadata and
/// `RuntimeIdKey` comparisons avoid redundant COM IPCs.
struct WalkHandle {
    elem: IUIAutomationElement,
    runtime_id: RuntimeIdKey,
    cached_meta: Option<UiaElementMetadata>,
}

impl WalkHandle {
    fn from_cached(elem: IUIAutomationElement, meta: UiaElementMetadata) -> Self {
        let runtime_id = meta.runtime_id.clone();
        Self {
            elem,
            runtime_id,
            cached_meta: Some(meta),
        }
    }

    fn from_uncached(elem: IUIAutomationElement) -> Self {
        Self {
            elem,
            runtime_id: RuntimeIdKey(Vec::new()),
            cached_meta: None,
        }
    }
}

/// Classic Win32 `#32768` top-menu-bar popup stack and bar-item linkage state.
///
/// Tracks the exact stack of open `#32768` popup HWNDs so gliding across top-level menu bar items
/// (`File -> Edit`) in any WinEvent ordering (`[PopupEnd, FocusChanged, PopupStart]`,
/// `[PopupEnd, PopupStart]`, `[FocusChanged, PopupEnd, PopupStart]`, or
/// `[FocusChanged, PopupStart, PopupEnd]`) updates `bar_item_title` cleanly without leaking the
/// prior top-level title or misclassifying `Edit` as a nested submenu under `File`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Win32MenuBarState {
    active: bool,
    bar_item_title: Option<String>,
    bar_item_owner_popup: Option<isize>,
    popup_stack: Vec<isize>,
    submenu_titles: Vec<String>,
    pending_submenu_candidate: Option<String>,
}

impl Win32MenuBarState {
    fn clear(&mut self) {
        self.active = false;
        self.bar_item_title = None;
        self.bar_item_owner_popup = None;
        self.popup_stack.clear();
        self.submenu_titles.clear();
        self.pending_submenu_candidate = None;
    }

    fn on_menu_bar_start(&mut self) {
        self.clear();
        self.active = true;
    }

    fn on_bar_item_focused(&mut self, title: String) {
        self.bar_item_title = Some(title);
        self.bar_item_owner_popup = None;
        self.submenu_titles.clear();
        self.pending_submenu_candidate = None;
    }

    fn on_submenu_opener_focused(&mut self, title: Option<String>) {
        if self.active {
            self.pending_submenu_candidate = title;
        }
    }

    fn on_popup_start(&mut self, popup_hwnd: isize, popup_title: Option<String>) {
        if !self.active || popup_hwnd == 0 {
            return;
        }
        if let Some(pos) = self.popup_stack.iter().position(|&h| h == popup_hwnd) {
            self.popup_stack.truncate(pos + 1);
            return;
        }
        if self.popup_stack.is_empty() || self.bar_item_owner_popup.is_none() {
            // Top-level dropdown directly under the MenuBar (depth 1), never a nested submenu.
            self.popup_stack.clear();
            self.submenu_titles.clear();
            self.pending_submenu_candidate = None;
            if self.bar_item_title.is_none() {
                self.bar_item_title = popup_title;
            }
            self.bar_item_owner_popup = Some(popup_hwnd);
        } else if self.submenu_titles.len() < MenuPathLimits::MAX_SEGMENTS {
            let sub_title = self.pending_submenu_candidate.take().or(popup_title);
            if let Some(title) = sub_title {
                self.submenu_titles.push(title);
            }
        }
        self.popup_stack.push(popup_hwnd);
    }

    fn on_popup_end(&mut self, popup_hwnd: isize) {
        if popup_hwnd == 0 {
            self.clear();
            return;
        }
        if let Some(pos) = self.popup_stack.iter().rposition(|&h| h == popup_hwnd) {
            self.popup_stack.remove(pos);
        }
        self.pending_submenu_candidate = None;
        if self.popup_stack.is_empty() {
            self.submenu_titles.clear();
            if self.bar_item_owner_popup == Some(popup_hwnd) {
                self.bar_item_title = None;
                self.bar_item_owner_popup = None;
            }
        } else {
            let target_sub_len = self.popup_stack.len().saturating_sub(1);
            self.submenu_titles.truncate(target_sub_len);
        }
    }

    fn last_popup_hwnd(&self) -> Option<isize> {
        self.popup_stack.last().copied()
    }

    fn current_link(&self) -> Option<Win32MenuBarLink> {
        if !self.active {
            return None;
        }
        let bar_title = self.bar_item_title.as_ref()?.clone();
        Some(Win32MenuBarLink {
            menu_bar_item_title: bar_title,
            submenu_titles: self.submenu_titles.clone(),
            from_menu_bar_start: true,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PollBatchStep {
    /// Flush pending `UIA_Invoke_InvokedEventId` events and `MenuCommitHook` signals while the
    /// volatile highlight and Win32 bar-item title are still intact (before `PopupEnd`).
    FlushInvokesAndCommitSignals,
    /// Flush all remaining UIA menu events (`MenuOpened`/`Invoked`/`MenuClosed` in arrival order)
    /// and `MenuCommitHook` signals before a full menu close (`MenuEnd` / `ForegroundChanged`).
    FlushAllUiaAndCommitSignals,
    /// Process `win_events[idx]` in true chronological FIFO order.
    WinEvent(usize),
}

fn plan_poll_win_events(win_events: &[WinMenuEvent]) -> Vec<PollBatchStep> {
    let mut steps = Vec::with_capacity(win_events.len().saturating_mul(2));
    for (idx, ev) in win_events.iter().enumerate() {
        match ev.kind {
            WinMenuEventKind::PopupEnd => {
                steps.push(PollBatchStep::FlushInvokesAndCommitSignals);
            }
            WinMenuEventKind::MenuEnd | WinMenuEventKind::ForegroundChanged => {
                steps.push(PollBatchStep::FlushAllUiaAndCommitSignals);
            }
            WinMenuEventKind::MenuBarStart
            | WinMenuEventKind::PopupStart
            | WinMenuEventKind::FocusChanged => {}
        }
        steps.push(PollBatchStep::WinEvent(idx));
    }
    steps
}

/// Stateful foreground top-menu-bar monitor combining MTA UIA event subscriptions, `WinEventWatcher`
/// menu lifecycle notifications, optional passive `MenuCommitHook` fallback, fail-closed browser
/// chrome privacy gates, bounded ancestor path resolution, and 250ms deduplication.
///
/// Field drop order note: COM fields (`uia_sub`, `bound`) are released explicitly on
/// `retire_for_process_exit()` / `shutdown()` before `UiaClient` and `ComGuard` drop.
pub(super) struct MenuActionSession {
    enabled: bool,
    retiring: bool,
    secure_input_suppressed: bool,
    bound: Option<BoundMenuWindow>,
    uia_sub: Option<UiaMenuEventSubscription>,
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
    // Classic Win32 `#32768` top-menu-bar tracking state.
    win32: Win32MenuBarState,
}

impl MenuActionSession {
    pub(super) fn new() -> Self {
        Self {
            enabled: false,
            retiring: false,
            secure_input_suppressed: false,
            bound: None,
            uia_sub: None,
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

    pub(super) fn take_next_record(&mut self) -> Option<MenuActionRecord> {
        self.pending_records.pop_next()
    }

    pub(super) fn take_menu_tracking(&mut self) -> Option<bool> {
        self.pending_tracking.take()
    }

    pub(super) fn has_pending_frame(&self) -> bool {
        !self.pending_records.is_empty() || self.pending_tracking.is_some()
    }

    /// Bind or refresh menu monitoring for the verified foreground window.
    ///
    /// Cleanly rebinds (detaching previous UIA handlers and clearing tracking/highlight state)
    /// whenever the bound HWND, application identity, `captureEpoch`, or `policyRevision` changes.
    pub(super) fn sync_binding(
        &mut self,
        uia: &UiaClient,
        target: MenuBindingTarget,
        policy: &CapturePolicy,
        stamp: Stamp,
        clock: &dyn CollectorClock,
    ) {
        if self.retiring
            || self.secure_input_suppressed
            || !policy.enabled
            || policy.menu_actions != Some(true)
        {
            self.disable(false);
            return;
        }
        if target.hwnd.0.is_null() {
            self.disable(false);
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
            if self.uia_sub.is_none() {
                self.attach_uia_subscription(uia, target.hwnd, clock);
            }
            return;
        }

        // Rebind to the new foreground window / epoch cleanly.
        self.detach_uia_subscription();
        self.clear_tracking_state(false);
        self.pending_records.clear();
        self.dedup.reset();
        self.accept_after_qpc_ns = qpc_ns_now();

        let app_menu_bar = find_app_menu_bar_for_window(
            uia,
            target.hwnd,
            target.app.process_id,
            target.raw_pid,
            target.dpi,
            clock.monotonic_ms().saturating_add(40),
            clock,
        );

        self.bound = Some(BoundMenuWindow {
            hwnd: target.hwnd,
            raw_pid: target.raw_pid,
            app: target.app,
            resolved: target.resolved,
            dpi: target.dpi,
            private_state: target.private_state,
            policy: policy.clone(),
            stamp,
            app_menu_bar,
        });

        self.attach_uia_subscription(uia, target.hwnd, clock);
    }

    /// Disable menu monitoring and tear down active subscriptions cleanly.
    pub(super) fn disable(&mut self, emit_stop_tracking: bool) {
        self.enabled = false;
        self.detach_uia_subscription();
        self.stop_commit_hook();
        self.bound = None;
        self.pending_records.clear();
        self.dedup.reset();
        self.accept_after_qpc_ns = qpc_ns_now();
        self.clear_tracking_state(emit_stop_tracking);
    }

    /// Clear transient tracking/binding state on app change or excluded foreground application
    /// without permanently stopping the optional hook thread when `menu_actions` stays enabled.
    pub(super) fn reset_for_boundary(&mut self, emit_stop_tracking: bool) {
        self.detach_uia_subscription();
        self.bound = None;
        self.pending_records.clear();
        self.dedup.reset();
        self.accept_after_qpc_ns = qpc_ns_now();
        self.clear_tracking_state(emit_stop_tracking);
    }

    /// Immediately suppress menu capture on Secure Input without flushing pending records.
    pub(super) fn suppress_secure_input(&mut self) {
        self.secure_input_suppressed = true;
        self.disable(false);
    }

    /// Process-exit retirement (`LiveUiaSession::retire_healthy()`): abandons remote UIA COM
    /// handlers without blocking on hung target UI threads and joins the local hook thread cleanly.
    pub(super) fn retire_for_process_exit(&mut self) {
        self.retiring = true;
        self.enabled = false;
        self.menu_open_flag.store(false, Ordering::Release);
        self.pending_records.clear();
        self.pending_tracking = None;
        self.last_reported_tracking = false;
        self.clear_win32_menu_state();
        let _ = self.tracking.reset();
        self.tracking_started_mono_ms = None;
        self.dedup.reset();
        if let Some(sub) = self.uia_sub.take() {
            sub.abandon_for_process_exit();
        }
        self.uia_rx = None;
        self.stop_commit_hook();
        self.bound = None;
    }

    /// Safe drop/shutdown path releasing all COM interfaces prior to `UiaClient` / `ComGuard` drop.
    pub(super) fn shutdown(&mut self) {
        if self.retiring {
            self.retire_for_process_exit();
        } else {
            self.disable(false);
        }
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
        clock: &dyn CollectorClock,
    ) {
        self.detach_uia_subscription();
        let deadline = clock.monotonic_ms().saturating_add(80);
        uia.apply_timeouts(deadline.saturating_sub(clock.monotonic_ms()));
        let Ok(root) = uia.element_from_hwnd(hwnd) else {
            return;
        };
        let (tx, rx) = create_menu_event_channel();
        uia.apply_timeouts(deadline.saturating_sub(clock.monotonic_ms()).max(25));
        if let Ok(sub) = UiaMenuEventSubscription::attach(uia.automation(), &root, tx) {
            self.uia_sub = Some(sub);
            self.uia_rx = Some(rx);
        }
    }

    fn detach_uia_subscription(&mut self) {
        if let Some(sub) = self.uia_sub.take() {
            if self.retiring {
                sub.abandon_for_process_exit();
            } else {
                sub.detach();
            }
        }
        self.uia_rx = None;
    }

    fn clear_win32_menu_state(&mut self) {
        self.win32.clear();
    }

    fn clear_tracking_state(&mut self, emit_stop_tracking: bool) {
        self.clear_win32_menu_state();
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

    fn current_win32_link(&self) -> Option<Win32MenuBarLink> {
        self.win32.current_link()
    }

    /// Poll all menu event sources (`WinEventWatcher`, MTA `UiaMenuEventSubscription`, and
    /// optional `MenuCommitHook`), enforcing pre-read & post-read privacy gates before reading any
    /// menu title and queuing verified `MenuActionRecord`s.
    pub(super) fn poll(
        &mut self,
        uia: &UiaClient,
        registry: &AdapterRegistry,
        win_events: Vec<WinMenuEvent>,
        clock: &dyn CollectorClock,
    ) {
        if !self.enabled || self.retiring || self.secure_input_suppressed {
            return;
        }

        let now_mono = clock.monotonic_ms();

        // Fail-safe ceiling: never leave menu tracking or the passive hook latched past 10s if
        // an app crashed or dropped its MenuEnd notification.
        if let Some(started) = self.tracking_started_mono_ms {
            if now_mono.saturating_sub(started) >= MenuPathLimits::MAX_MENU_TRACKING_MS {
                self.clear_tracking_state(true);
            }
        }

        // Drain MTA UIA menu events and optional passive hook signals once per poll cycle so
        // they can be interleaved cleanly right before any close/switch WinEvent without ever
        // dropping trailing WinEvents (e.g. `PopupEnd(File) -> FocusChanged(Edit) -> PopupStart(Edit)`).
        let mut uia_events: Vec<Option<RawUiaMenuEvent>> = Vec::new();
        if let Some(ref rx) = self.uia_rx {
            while let Ok(ev) = rx.try_recv() {
                uia_events.push(Some(ev));
            }
        }
        let mut commit_signals = self
            .commit_hook
            .as_ref()
            .map(MenuCommitHook::drain_signals)
            .unwrap_or_default();
        let now_qpc = (!commit_signals.is_empty()).then(qpc_ns_now);

        for step in plan_poll_win_events(&win_events) {
            match step {
                PollBatchStep::FlushInvokesAndCommitSignals => {
                    for slot in &mut uia_events {
                        if slot
                            .as_ref()
                            .is_some_and(|ev| ev.kind() == Some(UiaMenuEventKind::Invoked))
                        {
                            if let Some(ev) = slot.take() {
                                self.handle_uia_menu_event(uia, registry, ev, clock);
                            }
                        }
                    }
                    if let Some(qpc) = now_qpc {
                        for sig in commit_signals.drain(..) {
                            self.handle_commit_signal(uia, registry, sig, qpc, clock);
                        }
                    }
                }
                PollBatchStep::FlushAllUiaAndCommitSignals => {
                    for slot in &mut uia_events {
                        if let Some(ev) = slot.take() {
                            if ev.kind() == Some(UiaMenuEventKind::MenuClosed) {
                                if let Some(qpc) = now_qpc {
                                    for sig in commit_signals.drain(..) {
                                        self.handle_commit_signal(uia, registry, sig, qpc, clock);
                                    }
                                }
                            }
                            self.handle_uia_menu_event(uia, registry, ev, clock);
                        }
                    }
                    if let Some(qpc) = now_qpc {
                        for sig in commit_signals.drain(..) {
                            self.handle_commit_signal(uia, registry, sig, qpc, clock);
                        }
                    }
                }
                PollBatchStep::WinEvent(idx) => {
                    let ev = win_events[idx];
                    match ev.kind {
                        WinMenuEventKind::MenuBarStart
                        | WinMenuEventKind::PopupStart
                        | WinMenuEventKind::FocusChanged => {
                            self.handle_win_open_or_focus(uia, registry, ev, clock);
                        }
                        WinMenuEventKind::PopupEnd
                        | WinMenuEventKind::MenuEnd
                        | WinMenuEventKind::ForegroundChanged => {
                            self.handle_win_close_or_switch(ev, clock);
                        }
                    }
                }
            }
        }

        // Process any remaining MTA UIA events in exact arrival order (flushing passive commit
        // signals before `MenuClosed`), followed by any remaining passive hook commit signals.
        for slot in &mut uia_events {
            if let Some(ev) = slot.take() {
                if ev.kind() == Some(UiaMenuEventKind::MenuClosed) {
                    if let Some(qpc) = now_qpc {
                        for sig in commit_signals.drain(..) {
                            self.handle_commit_signal(uia, registry, sig, qpc, clock);
                        }
                    }
                }
                self.handle_uia_menu_event(uia, registry, ev, clock);
            }
        }
        if let Some(qpc) = now_qpc {
            for sig in commit_signals.drain(..) {
                self.handle_commit_signal(uia, registry, sig, qpc, clock);
            }
        }

        self.menu_open_flag
            .store(self.tracking.is_tracking(), Ordering::Release);
    }

    fn handle_win_open_or_focus(
        &mut self,
        uia: &UiaClient,
        registry: &AdapterRegistry,
        ev: WinMenuEvent,
        clock: &dyn CollectorClock,
    ) {
        let deadline = clock.monotonic_ms().saturating_add(MENU_EVENT_BUDGET_MS);
        match ev.kind {
            WinMenuEventKind::MenuBarStart => {
                // Strictly require `OBJID_MENU (-3)` for classic Win32 `#32768` menu-bar linkage.
                if !ev.from_objid_menu {
                    return;
                }
                if !self.passes_bound_privacy_gates(uia, registry, deadline, clock) {
                    self.clear_tracking_state(true);
                    return;
                }
                self.win32.on_menu_bar_start();
                let transition = self
                    .tracking
                    .menu_opened(MenuHandleKey::Win32MenuBar(ev.hwnd_raw), true);
                self.apply_tracking_change(transition.tracking_changed, clock.monotonic_ms());
            }
            WinMenuEventKind::PopupStart => {
                if !self.win32.active || ev.hwnd_raw == 0 {
                    return;
                }
                if !self.passes_bound_privacy_gates(uia, registry, deadline, clock) {
                    self.clear_tracking_state(true);
                    return;
                }
                let popup_hwnd = HWND(ev.hwnd_raw as *mut core::ffi::c_void);
                let Some((expected_pid, raw_pid, dpi)) = self
                    .bound
                    .as_ref()
                    .map(|b| (b.app.process_id, b.raw_pid, b.dpi))
                else {
                    return;
                };
                uia.apply_timeouts(deadline.saturating_sub(clock.monotonic_ms()).max(25));
                let mut popup_title: Option<String> = None;
                if let Ok(popup_el) = uia.element_from_hwnd(popup_hwnd) {
                    if let Ok(meta) = uia.read_cached_metadata(&popup_el, dpi, false, false) {
                        let pid_ok = meta.process_id > 0
                            && (meta.process_id == expected_pid
                                || (raw_pid > 0 && meta.process_id == raw_pid));
                        let safe = pid_ok
                            && !meta.is_sensitive()
                            && TextSecurityGate::may_traverse(&meta.subrole_read, meta.is_password);
                        let is_menu = meta.control_type == UIA_MENU_CONTROL_TYPE
                            || meta
                                .class_name
                                .as_deref()
                                .is_some_and(|c| c.eq_ignore_ascii_case("#32768"));
                        if !safe || !is_menu {
                            return;
                        }
                        popup_title = meta
                            .name
                            .as_deref()
                            .and_then(MenuPathLimits::sanitize_segment);
                    }
                }
                self.win32.on_popup_start(ev.hwnd_raw, popup_title);
                let transition = self
                    .tracking
                    .menu_opened(MenuHandleKey::Hwnd(ev.hwnd_raw), false);
                self.apply_tracking_change(transition.tracking_changed, clock.monotonic_ms());
            }
            WinMenuEventKind::FocusChanged => {
                if !self.tracking.is_tracking() {
                    return;
                }
                if !self.passes_bound_privacy_gates(uia, registry, deadline, clock) {
                    self.clear_tracking_state(true);
                    return;
                }
                self.inspect_focused_menu_item(uia, deadline, clock);
            }
            _ => {}
        }
    }

    fn inspect_focused_menu_item(
        &mut self,
        uia: &UiaClient,
        deadline_ms: i64,
        clock: &dyn CollectorClock,
    ) {
        let Some((expected_pid, raw_pid, dpi)) = self
            .bound
            .as_ref()
            .map(|b| (b.app.process_id, b.raw_pid, b.dpi))
        else {
            return;
        };
        let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
        if rem <= 0 {
            return;
        }
        uia.apply_timeouts(rem.min(60));
        let Ok(focused) = uia.focused_element() else {
            self.tracking.cancel();
            return;
        };
        let Ok(meta) = uia.read_cached_metadata(&focused, dpi, false, false) else {
            self.tracking.cancel();
            return;
        };
        let pid_ok = meta.process_id > 0
            && (meta.process_id == expected_pid || (raw_pid > 0 && meta.process_id == raw_pid));
        if !pid_ok
            || meta.is_sensitive()
            || !TextSecurityGate::may_traverse(&meta.subrole_read, meta.is_password)
            || meta.control_type != UIA_MENU_ITEM_CONTROL_TYPE
        {
            self.tracking.cancel();
            return;
        }

        // Check whether focused MenuItem is a top-level MenuBar item (parent is non-SystemMenuBar
        // MenuBar owned by this process and safe to traverse) -> update `win32` bar-item title
        // and cancel leaf selection.
        if let Ok(Some(parent)) = uia.parent_element(&focused) {
            if let Ok(pmeta) = uia.read_cached_metadata(&parent, dpi, false, false) {
                if pmeta.control_type == UIA_MENU_BAR_CONTROL_TYPE {
                    let parent_pid_ok = pmeta.process_id > 0
                        && (pmeta.process_id == expected_pid
                            || (raw_pid > 0 && pmeta.process_id == raw_pid));
                    let is_sys = pmeta
                        .automation_id
                        .as_deref()
                        .is_some_and(|a| a.eq_ignore_ascii_case("SystemMenuBar"));
                    if parent_pid_ok
                        && !is_sys
                        && !pmeta.is_sensitive()
                        && TextSecurityGate::may_traverse(&pmeta.subrole_read, pmeta.is_password)
                    {
                        if let Some(title) = meta
                            .name
                            .as_deref()
                            .and_then(MenuPathLimits::sanitize_segment)
                        {
                            self.win32.on_bar_item_focused(title);
                        }
                    }
                    self.tracking.cancel();
                    return;
                }
            }
        }

        // Check whether this MenuItem is a submenu opener inside a classic Win32 popup: record
        // candidate title for the next `PopupStart`, and cancel volatile leaf highlight.
        let is_opener = uia.is_submenu_opener(&focused).unwrap_or(false)
            || matches!(uia.first_child_element(&focused), Ok(Some(_)));
        if is_opener || meta.is_enabled == Some(false) {
            if is_opener && meta.is_enabled != Some(false) {
                self.win32.on_submenu_opener_focused(
                    meta.name
                        .as_deref()
                        .and_then(MenuPathLimits::sanitize_segment),
                );
            }
            self.tracking.cancel();
            return;
        }

        let Some(resolved) = self.resolve_leaf_menu_item(uia, focused, deadline_ms, clock) else {
            self.tracking.cancel();
            return;
        };

        let active_key = self
            .win32
            .last_popup_hwnd()
            .map(MenuHandleKey::Hwnd)
            .or_else(|| self.tracking.open_menus().last().cloned());
        if let Some(menu_key) = active_key {
            self.tracking
                .update_selection(Some(resolved), menu_key, clock.monotonic_ms());
        }
    }

    fn handle_uia_menu_event(
        &mut self,
        uia: &UiaClient,
        registry: &AdapterRegistry,
        ev: RawUiaMenuEvent,
        clock: &dyn CollectorClock,
    ) {
        let Some(kind) = ev.kind() else {
            return;
        };
        let deadline = clock.monotonic_ms().saturating_add(MENU_EVENT_BUDGET_MS);

        match kind {
            UiaMenuEventKind::MenuOpened => {
                let Some(mta_sender) = ev.sender else {
                    return;
                };
                if !self.passes_bound_privacy_gates(uia, registry, deadline, clock) {
                    self.clear_tracking_state(true);
                    return;
                }
                let sender_el = mta_sender.into_inner();
                let Some((key, opened_kind)) =
                    self.classify_uia_opened_menu(uia, sender_el, deadline, clock)
                else {
                    return;
                };
                let transition = self
                    .tracking
                    .menu_opened(key, opened_kind == OpenedMenuKind::TopLevel);
                self.apply_tracking_change(transition.tracking_changed, clock.monotonic_ms());
            }
            UiaMenuEventKind::MenuClosed => {
                let transition = if let Some(mta_sender) = ev.sender {
                    let sender_el = mta_sender.into_inner();
                    let rem = deadline.saturating_sub(clock.monotonic_ms()).max(25);
                    uia.apply_timeouts(rem);
                    let key_opt = uia
                        .refresh_metadata(&sender_el)
                        .ok()
                        .and_then(|cached| uia.runtime_id(&cached))
                        .map(MenuHandleKey::RuntimeId);
                    if let Some(key) = key_opt {
                        self.tracking.menu_closed(&key)
                    } else {
                        self.tracking.reset()
                    }
                } else {
                    // Windows UIA routinely delivers `UIA_MenuClosedEventId` with NULL sender.
                    self.tracking.reset()
                };
                if !self.tracking.is_tracking() {
                    self.clear_win32_menu_state();
                }
                self.apply_tracking_change(transition.tracking_changed, clock.monotonic_ms());
            }
            UiaMenuEventKind::Invoked => {
                let Some(mta_sender) = ev.sender else {
                    return;
                };
                // Pre-read privacy gate BEFORE reading any menu element name/title.
                if !self.passes_bound_privacy_gates(uia, registry, deadline, clock) {
                    return;
                }
                let sender_el = mta_sender.into_inner();
                let Some(resolved) =
                    self.resolve_leaf_menu_item(uia, sender_el, deadline, clock)
                else {
                    return;
                };
                // Post-read privacy gate AFTER ancestor resolution.
                if !self.passes_bound_privacy_gates(uia, registry, deadline, clock) {
                    return;
                }
                // Consume any volatile highlight so fallback hook cannot double-emit.
                let _ = self.tracking.commit(clock.monotonic_ms());
                self.enqueue_resolved_action(resolved, ev.observed_unix_ms, clock.monotonic_ms());
            }
        }
    }

    fn handle_commit_signal(
        &mut self,
        uia: &UiaClient,
        registry: &AdapterRegistry,
        sig: MenuCommitSignal,
        now_qpc_ns: u64,
        clock: &dyn CollectorClock,
    ) {
        let sig_qpc = sig.qpc_ns();
        if sig_qpc <= self.accept_after_qpc_ns
            || sig_qpc > now_qpc_ns
            || now_qpc_ns - sig_qpc > MAX_COMMIT_SIGNAL_AGE_NS
        {
            return;
        }
        match sig {
            MenuCommitSignal::Escape { .. } => {
                self.tracking.cancel();
            }
            MenuCommitSignal::LeftButtonUp { unix_ms, .. }
            | MenuCommitSignal::Return { unix_ms, .. } => {
                let now_mono = clock.monotonic_ms();
                let Some(resolved) = self.tracking.commit(now_mono) else {
                    return;
                };
                let deadline = now_mono.saturating_add(MENU_EVENT_BUDGET_MS);
                if !self.passes_bound_privacy_gates(uia, registry, deadline, clock) {
                    return;
                }
                self.enqueue_resolved_action(resolved, unix_ms, now_mono);
            }
        }
    }

    fn handle_win_close_or_switch(&mut self, ev: WinMenuEvent, clock: &dyn CollectorClock) {
        match ev.kind {
            WinMenuEventKind::PopupEnd => {
                if ev.hwnd_raw != 0 {
                    let transition = self
                        .tracking
                        .menu_closed(&MenuHandleKey::Hwnd(ev.hwnd_raw));
                    self.win32.on_popup_end(ev.hwnd_raw);
                    self.apply_tracking_change(transition.tracking_changed, clock.monotonic_ms());
                } else {
                    self.clear_tracking_state(true);
                }
            }
            WinMenuEventKind::MenuEnd | WinMenuEventKind::ForegroundChanged => {
                self.clear_tracking_state(true);
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
    ) -> Option<(MenuHandleKey, OpenedMenuKind)> {
        let bound = self.bound.as_ref()?;
        let win32_link = self.current_win32_link();
        let raw_host_pid = (bound.raw_pid > 0 && bound.raw_pid != bound.app.process_id)
            .then_some(bound.raw_pid);

        let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
        if rem <= 0 {
            return None;
        }
        uia.apply_timeouts(rem);
        let refreshed = uia.refresh_metadata(&menu_elem).ok()?;
        let meta = uia
            .read_cached_metadata(&refreshed, bound.dpi, false, false)
            .ok()?;
        let rid = meta.runtime_id.clone();
        let key = if !rid.is_empty() {
            MenuHandleKey::RuntimeId(rid)
        } else {
            let hwnd = meta.native_hwnd?;
            MenuHandleKey::Hwnd(hwnd.0 as isize)
        };

        let app_menu_bar_handle = bound
            .app_menu_bar
            .as_ref()
            .map(|el| WalkHandle::from_uncached(el.clone()));
        let menu_handle = WalkHandle::from_cached(refreshed, meta);
        let open_handles: Vec<WalkHandle> = Vec::new();

        let kind = MenuPathResolver::classify_opened_menu(
            menu_handle,
            bound.app.process_id,
            raw_host_pid,
            app_menu_bar_handle.as_ref(),
            None,
            win32_link.as_ref(),
            &open_handles,
            |a, b| walk_handles_same(uia, a, b),
            |handle| inspect_walk_handle(uia, handle, false, bound.dpi, bound.hwnd, deadline_ms, clock),
            |handle| parent_walk_handle(uia, handle, bound.dpi, deadline_ms, clock),
            || clock.monotonic_ms() < deadline_ms,
        )?;
        Some((key, kind))
    }

    fn resolve_leaf_menu_item(
        &self,
        uia: &UiaClient,
        leaf_elem: IUIAutomationElement,
        deadline_ms: i64,
        clock: &dyn CollectorClock,
    ) -> Option<ResolvedMenuPath> {
        let bound = self.bound.as_ref()?;
        let win32_link = self.current_win32_link();
        let raw_host_pid = (bound.raw_pid > 0 && bound.raw_pid != bound.app.process_id)
            .then_some(bound.raw_pid);

        resolve_uia_menu_leaf_internal(
            uia,
            leaf_elem,
            bound.hwnd,
            bound.app.process_id,
            raw_host_pid,
            bound.dpi,
            bound.app_menu_bar.as_ref(),
            win32_link.as_ref(),
            deadline_ms,
            clock,
        )
    }
}

/// Full pre-read & post-read privacy gate executed BEFORE reading any menu element title and
/// re-verified AFTER path resolution.
fn passes_live_menu_privacy_gates(
    uia: &UiaClient,
    registry: &AdapterRegistry,
    bound: &BoundMenuWindow,
    deadline_ms: i64,
    clock: &dyn CollectorClock,
) -> bool {
    if clock.monotonic_ms() >= deadline_ms
        || !bound.policy.enabled
        || bound.policy.menu_actions != Some(true)
    {
        return false;
    }
    if assess_windows_desktop().status != DesktopStatus::Unlocked {
        return false;
    }
    // SAFETY: Standard Win32 foreground window lookup.
    let fg = unsafe { GetForegroundWindow() };
    if fg != bound.hwnd || fg.0.is_null() {
        return false;
    }
    let Some((_, current_app, current_resolved)) =
        resolve_application_identity_for_hwnd(fg, None, None)
    else {
        return false;
    };
    if current_app != bound.app || current_resolved != bound.resolved {
        return false;
    }
    if !ApplicationPolicy::allows_identity(&bound.policy, &current_resolved)
        || !BrowserGate::allows_identity(&current_resolved, &bound.policy, false)
    {
        return false;
    }

    let spec = registry.adapter_for_identity(&current_resolved);
    let is_browser_candidate = BrowserGate::is_known_browser_identity(&current_resolved);
    let chrome_ok = BrowserMenuWindowGate::allows_foreground_window(
        &current_resolved,
        is_browser_candidate,
        spec,
        &bound.policy,
        || inspect_browser_window_for_menu_gate(uia, bound.hwnd, bound.dpi, deadline_ms, clock),
    );
    if !chrome_ok {
        return false;
    }

    // Confirm foreground window did not switch while browser chrome inspection ran.
    // SAFETY: Standard Win32 foreground window lookup.
    unsafe { GetForegroundWindow() == bound.hwnd }
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
        let pid_ok = meta.process_id > 0
            && (meta.process_id == expected_pid || (raw_pid > 0 && meta.process_id == raw_pid));
        if !pid_ok
            || meta.is_sensitive()
            || !TextSecurityGate::may_traverse(&meta.subrole_read, meta.is_password)
        {
            continue;
        }
        if meta.control_type == UIA_MENU_BAR_CONTROL_TYPE {
            let is_sys = meta
                .automation_id
                .as_deref()
                .is_some_and(|aid| aid.eq_ignore_ascii_case("SystemMenuBar"));
            if !is_sys {
                return Some(child);
            }
        }
    }
    None
}

fn walk_handles_same(uia: &UiaClient, a: &WalkHandle, b: &WalkHandle) -> bool {
    if !a.runtime_id.is_empty() && !b.runtime_id.is_empty() {
        return a.runtime_id == b.runtime_id;
    }
    uia.compare_elements(&a.elem, &b.elem)
}

fn menu_bar_belongs_to_window(
    uia: &UiaClient,
    bar_elem: &IUIAutomationElement,
    bar_meta: &UiaElementMetadata,
    bound_hwnd: HWND,
    dpi: u32,
    deadline_ms: i64,
    clock: &dyn CollectorClock,
) -> bool {
    if bound_hwnd.0.is_null() {
        return false;
    }
    if let Some(native) = bar_meta.native_hwnd {
        if native == bound_hwnd {
            return true;
        }
        // SAFETY: Standard Win32 root ancestor check.
        if unsafe { GetAncestor(native, GA_ROOT) } == bound_hwnd {
            return true;
        }
    }
    // Walk up to 6 ancestors to verify this MenuBar lives inside `bound_hwnd`.
    let mut cur = bar_elem.clone();
    for _ in 0..6 {
        if clock.monotonic_ms() >= deadline_ms {
            return false;
        }
        let Ok(Some(parent)) = uia.parent_element(&cur) else {
            return false;
        };
        if uia.is_root_desktop_element(&parent) {
            return false;
        }
        let Ok(pmeta) = uia.read_cached_metadata(&parent, dpi, false, false) else {
            return false;
        };
        if let Some(native) = pmeta.native_hwnd {
            if native == bound_hwnd {
                return true;
            }
            // SAFETY: Standard Win32 root ancestor check.
            if unsafe { GetAncestor(native, GA_ROOT) } == bound_hwnd {
                return true;
            }
        }
        cur = parent;
    }
    false
}

fn inspect_walk_handle(
    uia: &UiaClient,
    handle: &WalkHandle,
    is_leaf: bool,
    dpi: u32,
    bound_hwnd: HWND,
    deadline_ms: i64,
    clock: &dyn CollectorClock,
) -> Option<MenuNodeSnapshot> {
    let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
    if rem <= 0 {
        return None;
    }
    uia.apply_timeouts(rem);

    let meta = match handle.cached_meta {
        Some(ref cached) => cached.clone(),
        None => {
            let refreshed = uia.refresh_metadata(&handle.elem).ok()?;
            uia.read_cached_metadata(&refreshed, dpi, false, false)
                .ok()?
        }
    };

    if meta.is_sensitive() || !TextSecurityGate::may_traverse(&meta.subrole_read, meta.is_password)
    {
        return None;
    }

    // If this ancestor is a `MenuBar (50010)`, verify it is not `SystemMenuBar` and belongs to
    // `bound_hwnd` so secondary/foreign menu bars can never pass.
    if !is_leaf && meta.control_type == UIA_MENU_BAR_CONTROL_TYPE {
        let is_sys = meta
            .automation_id
            .as_deref()
            .is_some_and(|aid| aid.eq_ignore_ascii_case("SystemMenuBar"));
        if is_sys
            || !menu_bar_belongs_to_window(
                uia,
                &handle.elem,
                &meta,
                bound_hwnd,
                dpi,
                deadline_ms,
                clock,
            )
        {
            return None;
        }
    }

    let (child_count, is_submenu_opener) = if is_leaf {
        if clock.monotonic_ms() >= deadline_ms {
            return None;
        }
        let child_count = match uia.first_child_element(&handle.elem) {
            Ok(None) => Some(0),
            Ok(Some(_)) => Some(1),
            Err(UiaCallError::AccessDenied | UiaCallError::Unavailable) => None,
        };
        if clock.monotonic_ms() >= deadline_ms {
            return None;
        }
        let opener = match uia.is_submenu_opener(&handle.elem) {
            Ok(v) => Some(v),
            Err(_) => Some(true), // fail closed if ExpandCollapse status cannot be verified
        };
        (child_count, opener)
    } else {
        (None, None)
    };

    Some(MenuNodeSnapshot {
        pid: meta.process_id,
        control_type: Some(meta.control_type),
        role: meta.mapped.ax_role.map(str::to_string),
        subrole: meta.subrole_read.clone(),
        protected_content: meta.is_password,
        enabled: meta.is_enabled,
        title: meta.name.clone(),
        description: meta.safe_description().map(str::to_string),
        automation_id: meta.automation_id.clone(),
        class_name: meta.class_name.clone(),
        child_count,
        is_submenu_opener,
    })
}

fn parent_walk_handle(
    uia: &UiaClient,
    handle: &WalkHandle,
    dpi: u32,
    deadline_ms: i64,
    clock: &dyn CollectorClock,
) -> Option<WalkHandle> {
    let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
    if rem <= 0 {
        return None;
    }
    uia.apply_timeouts(rem);
    let parent = uia.parent_element(&handle.elem).ok()??;
    // Treat the Windows UIA Desktop root (`#32769` / `GetRootElement()`) as the top of the tree
    // (`None`) so Win32 `#32768` popups parented to Desktop can still match `Win32MenuBarLink`
    // while foreign application windows remain rejected by PID checks.
    if uia.is_root_desktop_element(&parent) {
        return None;
    }
    let meta = uia.read_cached_metadata(&parent, dpi, false, false).ok()?;
    Some(WalkHandle::from_cached(parent, meta))
}

#[allow(clippy::too_many_arguments)]
fn resolve_uia_menu_leaf_internal(
    uia: &UiaClient,
    leaf_elem: IUIAutomationElement,
    bound_hwnd: HWND,
    expected_pid: u32,
    raw_host_pid: Option<u32>,
    dpi: u32,
    app_menu_bar: Option<&IUIAutomationElement>,
    win32_link: Option<&Win32MenuBarLink>,
    deadline_ms: i64,
    clock: &dyn CollectorClock,
) -> Option<ResolvedMenuPath> {
    let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
    if rem <= 0 {
        return None;
    }
    uia.apply_timeouts(rem);
    let refreshed_leaf = uia.refresh_metadata(&leaf_elem).ok()?;
    let leaf_meta = uia
        .read_cached_metadata(&refreshed_leaf, dpi, false, false)
        .ok()?;
    let leaf_handle = WalkHandle::from_cached(refreshed_leaf, leaf_meta);

    let bar_handle = app_menu_bar.map(|bar| {
        uia.refresh_metadata(bar)
            .ok()
            .and_then(|c| {
                uia.read_cached_metadata(&c, dpi, false, false)
                    .ok()
                    .map(|m| WalkHandle::from_cached(c, m))
            })
            .unwrap_or_else(|| WalkHandle::from_uncached(bar.clone()))
    });

    MenuPathResolver::resolve(
        leaf_handle,
        expected_pid,
        raw_host_pid,
        bar_handle.as_ref(),
        None,
        win32_link,
        |a, b| walk_handles_same(uia, a, b),
        |handle, is_leaf| {
            inspect_walk_handle(uia, handle, is_leaf, dpi, bound_hwnd, deadline_ms, clock)
        },
        |handle| parent_walk_handle(uia, handle, dpi, deadline_ms, clock),
        || clock.monotonic_ms() < deadline_ms,
    )
}

/// Deterministic integration-test helper exercising the real MTA `UiaClient` ancestor walker and
/// `MenuPathResolver` against a live Win32 `IUIAutomationElement` leaf and target `HWND`.
#[allow(clippy::too_many_arguments)]
pub fn resolve_uia_menu_leaf_for_test(
    uia: &UiaClient,
    leaf_elem: &IUIAutomationElement,
    bound_hwnd: HWND,
    expected_pid: u32,
    dpi: u32,
    app_menu_bar: Option<&IUIAutomationElement>,
    win32_link: Option<&Win32MenuBarLink>,
    clock: &dyn CollectorClock,
) -> Option<ResolvedMenuPath> {
    let deadline_ms = clock.monotonic_ms().saturating_add(500);
    resolve_uia_menu_leaf_internal(
        uia,
        leaf_elem.clone(),
        bound_hwnd,
        expected_pid,
        None,
        dpi,
        app_menu_bar,
        win32_link,
        deadline_ms,
        clock,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_win_ev(kind: WinMenuEventKind, hwnd_raw: isize) -> WinMenuEvent {
        WinMenuEvent {
            kind,
            hwnd_raw,
            id_object: if matches!(kind, WinMenuEventKind::MenuBarStart) {
                -3
            } else {
                0
            },
            id_child: 0,
            from_objid_menu: matches!(kind, WinMenuEventKind::MenuBarStart),
            observed_mono_ms: 1_000,
            observed_unix_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn poll_planner_preserves_trailing_events_after_popup_end_and_flushes_before_close() {
        // Horizontal glide `File -> Edit` in a single 5ms batch:
        // `[PopupEnd(File), FocusChanged(Edit), PopupStart(Edit)]`.
        let glide = [
            mk_win_ev(WinMenuEventKind::PopupEnd, 0x10),
            mk_win_ev(WinMenuEventKind::FocusChanged, 0x11),
            mk_win_ev(WinMenuEventKind::PopupStart, 0x20),
        ];
        assert_eq!(
            plan_poll_win_events(&glide),
            vec![
                PollBatchStep::FlushInvokesAndCommitSignals,
                PollBatchStep::WinEvent(0),
                PollBatchStep::WinEvent(1),
                PollBatchStep::WinEvent(2),
            ],
            "PopupEnd must NEVER drop trailing FocusChanged or PopupStart events"
        );

        // Click commit + close + fast reopen in one batch:
        // `[FocusChanged(Save), PopupEnd(File), MenuEnd, MenuBarStart, PopupStart(Edit)]`.
        let close_and_reopen = [
            mk_win_ev(WinMenuEventKind::FocusChanged, 0x10),
            mk_win_ev(WinMenuEventKind::PopupEnd, 0x10),
            mk_win_ev(WinMenuEventKind::MenuEnd, 0x1),
            mk_win_ev(WinMenuEventKind::MenuBarStart, 0x1),
            mk_win_ev(WinMenuEventKind::PopupStart, 0x20),
        ];
        assert_eq!(
            plan_poll_win_events(&close_and_reopen),
            vec![
                PollBatchStep::WinEvent(0),
                PollBatchStep::FlushInvokesAndCommitSignals,
                PollBatchStep::WinEvent(1),
                PollBatchStep::FlushAllUiaAndCommitSignals,
                PollBatchStep::WinEvent(2),
                PollBatchStep::WinEvent(3),
                PollBatchStep::WinEvent(4),
            ]
        );
    }

    #[test]
    fn win32_menu_bar_state_handles_all_glide_orderings_and_nested_submenus() {
        // Order 1: `[PopupEnd(file), FocusChanged(Edit), PopupStart(edit)]`.
        let mut s = Win32MenuBarState::default();
        s.on_menu_bar_start();
        s.on_bar_item_focused("File".to_string());
        s.on_popup_start(0x10, Some("File".to_string()));
        assert_eq!(s.current_link().unwrap().menu_bar_item_title, "File");
        assert!(s.current_link().unwrap().submenu_titles.is_empty());

        s.on_popup_end(0x10);
        s.on_bar_item_focused("Edit".to_string());
        s.on_popup_start(0x20, Some("Edit".to_string()));
        let link1 = s.current_link().expect("Edit link");
        assert_eq!(link1.menu_bar_item_title, "Edit");
        assert!(link1.submenu_titles.is_empty());
        assert_eq!(s.last_popup_hwnd(), Some(0x20));

        // Order 2: `[PopupEnd(edit), PopupStart(view)]` (no intermediate FocusChanged).
        s.on_popup_end(0x20);
        s.on_popup_start(0x30, Some("View".to_string()));
        let link2 = s.current_link().expect("View link");
        assert_eq!(link2.menu_bar_item_title, "View");
        assert!(link2.submenu_titles.is_empty());

        // Order 3: `[FocusChanged(Help), PopupEnd(view), PopupStart(help)]`.
        s.on_bar_item_focused("Help".to_string());
        s.on_popup_end(0x30);
        s.on_popup_start(0x40, None);
        let link3 = s.current_link().expect("Help link");
        assert_eq!(link3.menu_bar_item_title, "Help");
        assert!(link3.submenu_titles.is_empty());

        // Order 4: `[FocusChanged(File), PopupStart(file2), PopupEnd(help)]`.
        s.on_bar_item_focused("File".to_string());
        s.on_popup_start(0x50, Some("File".to_string()));
        s.on_popup_end(0x40);
        let link4 = s.current_link().expect("File link");
        assert_eq!(link4.menu_bar_item_title, "File");
        assert!(link4.submenu_titles.is_empty());
        assert_eq!(s.last_popup_hwnd(), Some(0x50));

        // Nested submenu: `File -> Export -> PDF`, then closing `Export` returns to `File`.
        s.on_submenu_opener_focused(Some("Export".to_string()));
        s.on_popup_start(0x51, None);
        let sub = s.current_link().expect("File -> Export link");
        assert_eq!(sub.menu_bar_item_title, "File");
        assert_eq!(sub.submenu_titles, vec!["Export".to_string()]);
        assert_eq!(s.last_popup_hwnd(), Some(0x51));

        s.on_popup_end(0x51);
        let back = s.current_link().expect("back to File");
        assert_eq!(back.menu_bar_item_title, "File");
        assert!(back.submenu_titles.is_empty());
        assert_eq!(s.last_popup_hwnd(), Some(0x50));
    }
}
