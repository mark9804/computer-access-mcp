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
use windows::Win32::UI::WindowsAndMessaging::{
    GetAncestor, GetClassNameW, GetDesktopWindow, GetForegroundWindow, GetWindow,
    GetWindowThreadProcessId, GA_ROOT, GW_OWNER,
};

use super::input_hook::{qpc_ns_now, MenuCommitHook, MenuCommitSignal};
use super::target_verify::{
    is_owned_popup_hwnd, read_window_title_ephemeral, resolve_application_identity_for_hwnd,
};
use super::uia_events::{
    create_menu_event_channel, RawUiaMenuEvent, UiaMenuEventKind, UiaMenuEventSubscription,
};
use crate::adapters::AdapterRegistry;
use crate::desktop::assess_windows_desktop;
use crate::menu_action_core::{
    is_menu_structure_control_type, BrowserChromeVerdict, BrowserMenuWindowGate,
    BrowserWindowInspection, MenuActionDeduplicator, MenuActionPendingQueue, MenuActionRecord,
    MenuNodeSnapshot, MenuPathLimits, MenuPathResolver, MenuTrackingStateMachine, OpenedMenuKind,
    ResolvedMenuPath, Win32MenuBarLink, UIA_BUTTON_CONTROL_TYPE, UIA_CUSTOM_CONTROL_TYPE,
    UIA_GROUP_CONTROL_TYPE, UIA_MENU_BAR_CONTROL_TYPE, UIA_MENU_CONTROL_TYPE,
    UIA_MENU_ITEM_CONTROL_TYPE, UIA_PANE_CONTROL_TYPE, UIA_WINDOW_CONTROL_TYPE,
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
/// Maximum direct children scanned on a leaf `MenuItem` to distinguish visual children
/// (`Text`/`Image`/`Group`) from nested menu structure (`Menu`/`MenuItem`).
const MAX_LEAF_MENU_CHILD_SCAN: usize = 8;
/// Maximum ancestor hops walked when verifying a nested Electron/WinUI 3 `MenuBar` belongs to `bound_hwnd`.
const MAX_MENU_BAR_WINDOW_HOPS: usize = 18;

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

/// Verified top-menu-bar popup stack and bar-item linkage state for classic Win32 `#32768` menus
/// AND WinUI 3 / Electron detached popup menus opened from a verified non-`SystemMenuBar`
/// `MenuBar (50010)` item belonging to the bound foreground window.
///
/// Enforces a hard 10s monotonic TTL (`MenuPathLimits::MAX_MENU_TRACKING_MS`), and tracks the
/// exact stack of open popup HWNDs so gliding across top-level menu bar items (`File -> Edit`) in
/// any WinEvent ordering updates `bar_item_title` cleanly without leaking prior titles or
/// permitting right-click context menus.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Win32MenuBarState {
    active: bool,
    /// True ONLY when opened via classic Win32 `EVENT_SYSTEM_MENUSTART(OBJID_MENU)`; false when
    /// armed via WinUI 3 / Electron `MenuBar` item focus or invoke (where Win32 `MenuEnd` does not
    /// fire and `#32768` `"Context"` titles must never be adopted).
    from_objid_menu: bool,
    armed_mono_ms: Option<i64>,
    bar_item_title: Option<String>,
    bar_item_owner_popup: Option<isize>,
    popup_stack: Vec<isize>,
    submenu_titles: Vec<String>,
    pending_submenu_candidate: Option<String>,
}

impl Win32MenuBarState {
    fn clear(&mut self) {
        self.active = false;
        self.from_objid_menu = false;
        self.armed_mono_ms = None;
        self.bar_item_title = None;
        self.bar_item_owner_popup = None;
        self.popup_stack.clear();
        self.submenu_titles.clear();
        self.pending_submenu_candidate = None;
    }

    fn is_active(&self, now_mono_ms: i64) -> bool {
        self.active
            && self.armed_mono_ms.is_some_and(|armed| {
                now_mono_ms >= armed
                    && now_mono_ms.saturating_sub(armed) < MenuPathLimits::MAX_MENU_TRACKING_MS
            })
    }

    fn expire_if_stale(&mut self, now_mono_ms: i64) -> bool {
        if self.active && !self.is_active(now_mono_ms) {
            self.clear();
            true
        } else {
            false
        }
    }

    fn on_menu_bar_start(&mut self, now_mono_ms: i64) {
        self.clear();
        self.active = true;
        self.from_objid_menu = true;
        self.armed_mono_ms = Some(now_mono_ms);
    }

    /// Arms or updates the verified top-menu-bar link when focus or `Invoke_Invoked` hits a
    /// verified top-level item inside a non-`SystemMenuBar` `MenuBar (50010)` belonging to
    /// `bound_hwnd`. Preserves `from_objid_menu` only if already inside an active `OBJID_MENU`
    /// session.
    fn on_verified_menu_bar_item(&mut self, title: String, now_mono_ms: i64) {
        let keep_objid = self.from_objid_menu && self.is_active(now_mono_ms);
        self.active = true;
        self.from_objid_menu = keep_objid;
        self.armed_mono_ms = Some(now_mono_ms);
        self.bar_item_title = Some(title);
        self.bar_item_owner_popup = None;
        self.submenu_titles.clear();
        self.pending_submenu_candidate = None;
    }

    fn on_submenu_opener_focused(&mut self, title: Option<String>, now_mono_ms: i64) {
        if self.is_active(now_mono_ms) {
            self.pending_submenu_candidate = title;
        }
    }

    fn on_uia_menu_opened(&mut self, is_submenu: bool, now_mono_ms: i64) {
        if !self.is_active(now_mono_ms) || !is_submenu || !self.popup_stack.is_empty() {
            return;
        }
        if self.submenu_titles.len() < MenuPathLimits::MAX_SEGMENTS {
            if let Some(title) = self.pending_submenu_candidate.take() {
                self.submenu_titles.push(title);
            }
        }
    }

    fn on_uia_menu_closed(&mut self, remaining_open_menus: usize) {
        if self.popup_stack.is_empty() {
            self.submenu_titles
                .truncate(remaining_open_menus.saturating_sub(1));
            self.pending_submenu_candidate = None;
        }
    }

    fn on_popup_start(&mut self, popup_hwnd: isize, popup_title: Option<String>, now_mono_ms: i64) {
        if !self.is_active(now_mono_ms) || popup_hwnd == 0 {
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
            // Only classic `OBJID_MENU` sessions may fall back to the popup's window title;
            // WinUI 3 / Electron sessions require a verified `MenuBar` item title so a stray
            // `#32768` `"Context"` popup can never be adopted.
            if self.bar_item_title.is_none() && self.from_objid_menu {
                self.bar_item_title = popup_title;
            }
            self.bar_item_owner_popup = Some(popup_hwnd);
        } else if self.submenu_titles.len() < MenuPathLimits::MAX_SEGMENTS {
            let sub_title = if self.from_objid_menu {
                self.pending_submenu_candidate.take().or(popup_title)
            } else {
                self.pending_submenu_candidate.take()
            };
            if let Some(title) = sub_title {
                self.submenu_titles.push(title);
            }
        }
        self.popup_stack.push(popup_hwnd);
    }

    /// Processes `EVENT_SYSTEM_MENUPOPUPEND`. Returns `true` when the active menu-bar link should
    /// be fully disarmed (null HWND, or a non-`OBJID_MENU` WinUI 3 / Electron session whose popup
    /// stack is now empty).
    fn on_popup_end(&mut self, popup_hwnd: isize) -> bool {
        if popup_hwnd == 0 {
            self.clear();
            return true;
        }
        if let Some(pos) = self.popup_stack.iter().rposition(|&h| h == popup_hwnd) {
            self.popup_stack.remove(pos);
        }
        self.pending_submenu_candidate = None;
        if self.popup_stack.is_empty() {
            self.submenu_titles.clear();
            if !self.from_objid_menu {
                self.clear();
                return true;
            }
            if self.bar_item_owner_popup == Some(popup_hwnd) {
                self.bar_item_title = None;
                self.bar_item_owner_popup = None;
            }
        } else {
            let target_sub_len = self.popup_stack.len().saturating_sub(1);
            self.submenu_titles.truncate(target_sub_len);
        }
        false
    }

    fn last_popup_hwnd(&self) -> Option<isize> {
        self.popup_stack.last().copied()
    }

    fn current_link(&self, now_mono_ms: i64) -> Option<Win32MenuBarLink> {
        if !self.is_active(now_mono_ms) {
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
            WinMenuEventKind::FocusChanged => {
                // Coalesce uninterrupted consecutive `FocusChanged` bursts so only the latest
                // focus event in each run triggers a UIA focus probe.
                if win_events
                    .get(idx + 1)
                    .is_some_and(|next| next.kind == WinMenuEventKind::FocusChanged)
                {
                    continue;
                }
            }
            WinMenuEventKind::MenuBarStart | WinMenuEventKind::PopupStart => {}
        }
        steps.push(PollBatchStep::WinEvent(idx));
    }
    steps
}

/// Stateful foreground top-menu-bar monitor combining MTA UIA event subscriptions, `WinEventWatcher`
/// menu lifecycle notifications, optional passive `MenuCommitHook` fallback, fail-closed browser
/// chrome privacy gates, bounded ancestor path resolution, and 250ms deduplication.
///
/// Field drop order note: COM fields (`popup_uia_sub`, `uia_sub`, `bound`) are released explicitly
/// on `retire_for_process_exit()` / `shutdown()` before `UiaClient` and `ComGuard` drop.
pub(super) struct MenuActionSession {
    enabled: bool,
    retiring: bool,
    secure_input_suppressed: bool,
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

impl MenuActionSession {
    pub(super) fn new() -> Self {
        Self {
            enabled: false,
            retiring: false,
            secure_input_suppressed: false,
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
        if let Ok(sub) = UiaMenuEventSubscription::attach(uia.automation(), &root, tx.clone()) {
            self.uia_sub = Some(sub);
            self.uia_tx = Some(tx);
            self.uia_rx = Some(rx);
        }
    }

    fn detach_popup_uia_subscription(&mut self) {
        if let Some((_, sub)) = self.popup_uia_sub.take() {
            if self.retiring {
                sub.abandon_for_process_exit();
            } else {
                sub.detach();
            }
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
        let raw_hwnd = HWND(candidate_hwnd_raw as *mut core::ffi::c_void);
        // SAFETY: Standard read-only Win32 root ancestor query.
        let popup_hwnd = unsafe {
            let root = GetAncestor(raw_hwnd, GA_ROOT);
            if !root.0.is_null() {
                root
            } else {
                raw_hwnd
            }
        };
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
        self.detach_popup_uia_subscription();
        uia.apply_timeouts(deadline_ms.saturating_sub(clock.monotonic_ms()).max(25));
        if let Ok(sub) = UiaMenuEventSubscription::attach(uia.automation(), &popup_root, tx) {
            self.popup_uia_sub = Some((popup_raw, sub));
        }
    }

    fn detach_uia_subscription(&mut self) {
        self.detach_popup_uia_subscription();
        if let Some(sub) = self.uia_sub.take() {
            if self.retiring {
                sub.abandon_for_process_exit();
            } else {
                sub.detach();
            }
        }
        self.uia_tx = None;
        self.uia_rx = None;
    }

    fn clear_win32_menu_state(&mut self) {
        self.win32.clear();
    }

    fn clear_tracking_state(&mut self, emit_stop_tracking: bool) {
        self.detach_popup_uia_subscription();
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

    fn current_win32_link(&self, now_mono_ms: i64) -> Option<Win32MenuBarLink> {
        self.win32.current_link(now_mono_ms)
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

        // Fail-safe ceiling: never leave menu tracking, ActiveMenuBarLink, or the passive hook
        // latched past 10s if an app crashed or dropped its MenuEnd/MenuClosed notification.
        let tracking_expired = self
            .tracking_started_mono_ms
            .is_some_and(|started| now_mono.saturating_sub(started) >= MenuPathLimits::MAX_MENU_TRACKING_MS);
        let link_expired = self.win32.expire_if_stale(now_mono);
        if tracking_expired || link_expired {
            self.clear_tracking_state(true);
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
        let now_mono = clock.monotonic_ms();
        let deadline = now_mono.saturating_add(MENU_EVENT_BUDGET_MS);
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
                self.win32.on_menu_bar_start(now_mono);
                let transition = self
                    .tracking
                    .menu_opened(MenuHandleKey::Win32MenuBar(ev.hwnd_raw), true);
                self.apply_tracking_change(transition.tracking_changed, now_mono);
            }
            WinMenuEventKind::PopupStart => {
                if !self.win32.is_active(now_mono) || ev.hwnd_raw == 0 {
                    return;
                }
                if !self.passes_bound_privacy_gates(uia, registry, deadline, clock) {
                    self.clear_tracking_state(true);
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
                uia.apply_timeouts(deadline.saturating_sub(clock.monotonic_ms()).max(25));
                let Ok(popup_el) = uia.element_from_hwnd(popup_hwnd) else {
                    return;
                };
                if uia.is_root_desktop_element(&popup_el) {
                    return;
                }
                let Ok(meta) = uia.read_cached_metadata(&popup_el, dpi, false, false) else {
                    return;
                };
                let pid_ok = meta.process_id > 0
                    && (meta.process_id == expected_pid
                        || (raw_pid > 0 && meta.process_id == raw_pid));
                let safe = pid_ok
                    && !meta.is_sensitive()
                    && TextSecurityGate::may_traverse(&meta.subrole_read, meta.is_password);
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
                let popup_title = if is_classic_menu && self.win32.from_objid_menu {
                    meta.name
                        .as_deref()
                        .and_then(MenuPathLimits::sanitize_segment)
                } else {
                    None
                };
                let popup_raw = popup_hwnd.0 as isize;
                self.maybe_attach_popup_uia_subscription(uia, popup_raw, deadline, clock);
                self.win32.on_popup_start(popup_raw, popup_title, now_mono);
                let transition = self
                    .tracking
                    .menu_opened(MenuHandleKey::Hwnd(popup_raw), false);
                self.apply_tracking_change(transition.tracking_changed, clock.monotonic_ms());
            }
            WinMenuEventKind::FocusChanged => {
                // Fast non-COM pre-gate first, then structural-only ControlType probe (zero
                // Name/Title/Value reads) so non-menu focus changes in Chrome/Edge never trigger
                // the heavy `is_private_browser_window_chrome` scan. Only menu candidates proceed
                // to full `passes_bound_privacy_gates` + `read_cached_metadata`.
                self.handle_focus_changed(uia, registry, ev.hwnd_raw, deadline, clock);
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
        let Some((is_browser, bound_hwnd, expected_pid, raw_pid, dpi)) =
            self.bound.as_ref().and_then(|bound| {
                passes_fast_menu_privacy_pre_gate(registry, bound, deadline_ms, clock)?;
                let spec = registry.adapter_for_identity(&bound.resolved);
                let is_browser = BrowserGate::is_known_browser_identity(&bound.resolved)
                    || BrowserGate::should_block_private_windows_identity(
                        &bound.resolved,
                        spec.block_private_windows,
                    );
                Some((is_browser, bound.hwnd, bound.app.process_id, bound.raw_pid, bound.dpi))
            })
        else {
            self.clear_tracking_state(true);
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
            if self.tracking.is_tracking() || self.win32.active {
                self.clear_tracking_state(true);
            }
            return;
        };
        let Ok(ct) = uia.current_control_type(&raw_focused) else {
            if self.tracking.is_tracking() || self.win32.active {
                self.clear_tracking_state(true);
            }
            return;
        };
        if !is_structural_menu_focus_candidate(uia, &raw_focused, ct, is_browser, deadline_ms, clock)
        {
            // Non-menu element (e.g. `AXTextArea`, `Document`, `Edit`, regular button, tab):
            // immediately disarm `ActiveMenuBarLink` & tracking with ZERO browser chrome probe
            // and ZERO `metadata_cache` text reads.
            if self.tracking.is_tracking() || self.win32.active {
                self.clear_tracking_state(true);
            }
            return;
        }

        // Full pre-read privacy gate (including fail-closed `is_private_browser_window_chrome`
        // for browsers) BEFORE reading any `Name`/`Title` via `metadata_cache`.
        if !self.passes_bound_privacy_gates(uia, registry, deadline_ms, clock) {
            self.clear_tracking_state(true);
            return;
        }

        let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
        if rem <= 0 {
            return;
        }
        uia.apply_timeouts(rem.min(60));
        let Ok(focused) = uia.refresh_metadata(&raw_focused) else {
            if self.tracking.is_tracking() || self.win32.active {
                self.clear_tracking_state(true);
            }
            return;
        };
        let Ok(meta) = uia.read_cached_metadata(&focused, dpi, false, false) else {
            if self.tracking.is_tracking() || self.win32.active {
                self.clear_tracking_state(true);
            }
            return;
        };
        let pid_ok = meta.process_id > 0
            && (meta.process_id == expected_pid || (raw_pid > 0 && meta.process_id == raw_pid));
        if !pid_ok
            || meta.is_sensitive()
            || !TextSecurityGate::may_traverse(&meta.subrole_read, meta.is_password)
        {
            self.clear_tracking_state(true);
            return;
        }

        let now_mono = clock.monotonic_ms();

        // 1. Check whether focused element is a verified top-level item inside a non-`SystemMenuBar`
        // `MenuBar (50010)` belonging to `bound_hwnd` (WinUI 3 Notepad, Electron, classic Win32).
        if let Some(title) = self.bound.as_ref().and_then(|bound| {
            detect_verified_menu_bar_item(uia, &focused, &meta, bound, deadline_ms, clock)
        }) {
            let bound_hwnd_raw = bound_hwnd.0 as isize;
            self.win32.on_verified_menu_bar_item(title, now_mono);
            let transition = self
                .tracking
                .menu_opened(MenuHandleKey::Win32MenuBar(bound_hwnd_raw), true);
            self.tracking.cancel();
            self.apply_tracking_change(transition.tracking_changed, now_mono);
            return;
        }

        let bound_hwnd_raw = bound_hwnd.0 as isize;

        // 2. Focus landed on a `MenuBar` container itself: preserve active tracking only if it is
        // the verified app `MenuBar`; clear on `SystemMenuBar` or foreign bar.
        if meta.control_type == UIA_MENU_BAR_CONTROL_TYPE {
            let is_sys = meta
                .automation_id
                .as_deref()
                .is_some_and(|aid| aid.eq_ignore_ascii_case("SystemMenuBar"));
            let valid_bar = !is_sys
                && menu_bar_belongs_to_window(
                    uia,
                    &focused,
                    &meta,
                    bound_hwnd,
                    dpi,
                    deadline_ms,
                    clock,
                );
            if valid_bar {
                self.tracking.cancel();
            } else {
                self.clear_tracking_state(true);
            }
            return;
        }

        // 3. Focus landed directly on a `Menu (50009)` container (e.g., WinUI 3 `MenuFlyoutPresenter`
        // or Electron `<ul role="menu">` right on open): verify via `classify_uia_opened_menu`
        // and replace any `Win32MenuBar` placeholder cleanly so `MenuClosed` matches exact handle.
        if meta.control_type == UIA_MENU_CONTROL_TYPE {
            if let Some((key, opened_kind)) =
                self.classify_uia_opened_menu(uia, focused, deadline_ms, clock)
            {
                if event_hwnd_raw != 0 && event_hwnd_raw != bound_hwnd_raw {
                    self.maybe_attach_popup_uia_subscription(
                        uia,
                        event_hwnd_raw,
                        deadline_ms,
                        clock,
                    );
                } else if let Some(native) = meta.native_hwnd {
                    if native != bound_hwnd {
                        self.maybe_attach_popup_uia_subscription(
                            uia,
                            native.0 as isize,
                            deadline_ms,
                            clock,
                        );
                    }
                }
                let replacing_placeholder = opened_kind == OpenedMenuKind::TopLevel
                    && self.tracking.open_menus().len() == 1
                    && matches!(
                        self.tracking.open_menus().first(),
                        Some(MenuHandleKey::Win32MenuBar(_))
                    );
                if !self.tracking.is_tracking()
                    || replacing_placeholder
                    || opened_kind == OpenedMenuKind::Submenu
                {
                    let transition = self
                        .tracking
                        .menu_opened(key, opened_kind == OpenedMenuKind::TopLevel);
                    self.win32
                        .on_uia_menu_opened(opened_kind == OpenedMenuKind::Submenu, now_mono);
                    self.apply_tracking_change(transition.tracking_changed, now_mono);
                }
                self.tracking.cancel();
            } else {
                self.clear_tracking_state(true);
            }
            return;
        }

        // 4. Focus is on a `MenuItem` inside an opened menu.
        if meta.control_type == UIA_MENU_ITEM_CONTROL_TYPE {
            if self.win32.is_active(now_mono) || self.tracking.is_tracking() {
                if event_hwnd_raw != 0 && event_hwnd_raw != bound_hwnd_raw {
                    self.maybe_attach_popup_uia_subscription(
                        uia,
                        event_hwnd_raw,
                        deadline_ms,
                        clock,
                    );
                } else if let Some(native) = meta.native_hwnd {
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

            // Refresh UIA timeouts immediately before `is_submenu_opener` and `has_menu_child`.
            let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
            if rem <= 0 {
                self.tracking.cancel();
                return;
            }
            uia.apply_timeouts(rem);
            let opener_pattern = uia.is_submenu_opener(&focused);
            let menu_child = has_menu_child(uia, &focused, dpi, deadline_ms, clock);
            let is_opener = matches!(opener_pattern, Ok(true)) || matches!(menu_child, Ok(true));
            if is_opener || meta.is_enabled == Some(false) {
                if self.tracking.is_tracking() && is_opener && meta.is_enabled != Some(false) {
                    self.win32.on_submenu_opener_focused(
                        meta.name
                            .as_deref()
                            .and_then(MenuPathLimits::sanitize_segment),
                        now_mono,
                    );
                }
                self.tracking.cancel();
                return;
            }
            if opener_pattern.is_err() || menu_child.is_err() {
                self.tracking.cancel();
                return;
            }

            let Some(resolved) =
                self.resolve_leaf_menu_item_cached(uia, focused, meta, deadline_ms, clock)
            else {
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
        if self.tracking.is_tracking() || self.win32.active {
            self.clear_tracking_state(true);
        }
    }

    fn apply_uia_menu_closed(&mut self, key_opt: Option<MenuHandleKey>, now_mono_ms: i64) {
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
            self.detach_popup_uia_subscription();
            self.clear_win32_menu_state();
        } else {
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
        clock: &dyn CollectorClock,
    ) {
        let Some(kind) = ev.kind() else {
            return;
        };
        let now_mono = clock.monotonic_ms();
        let deadline = now_mono.saturating_add(MENU_EVENT_BUDGET_MS);

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
                let is_top = opened_kind == OpenedMenuKind::TopLevel;
                let transition = self.tracking.menu_opened(key, is_top);
                self.win32
                    .on_uia_menu_opened(!is_top, clock.monotonic_ms());
                self.apply_tracking_change(transition.tracking_changed, clock.monotonic_ms());
            }
            UiaMenuEventKind::MenuClosed => {
                let key_opt = if let Some(mta_sender) = ev.sender {
                    let sender_el = mta_sender.into_inner();
                    let rem = deadline.saturating_sub(clock.monotonic_ms()).max(25);
                    uia.apply_timeouts(rem);
                    uia.refresh_metadata(&sender_el)
                        .ok()
                        .and_then(|cached| uia.runtime_id(&cached))
                        .map(MenuHandleKey::RuntimeId)
                } else {
                    None
                };
                self.apply_uia_menu_closed(key_opt, clock.monotonic_ms());
            }
            UiaMenuEventKind::Invoked => {
                let Some(mta_sender) = ev.sender else {
                    return;
                };
                // Pre-read privacy gate BEFORE reading any menu element name/title.
                if !self.passes_bound_privacy_gates(uia, registry, deadline, clock) {
                    self.clear_tracking_state(true);
                    return;
                }
                let sender_el = mta_sender.into_inner();
                let rem = deadline.saturating_sub(clock.monotonic_ms());
                if rem <= 0 {
                    return;
                }
                uia.apply_timeouts(rem);
                let Ok(refreshed_sender) = uia.refresh_metadata(&sender_el) else {
                    return;
                };
                let Some(dpi) = self.bound.as_ref().map(|b| b.dpi) else {
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
                        deadline,
                        clock,
                    )
                }) {
                    if !self.passes_bound_privacy_gates(uia, registry, deadline, clock) {
                        self.clear_tracking_state(true);
                        return;
                    }
                    if let Some(bound_hwnd_raw) = self.bound.as_ref().map(|b| b.hwnd.0 as isize) {
                        let mono = clock.monotonic_ms();
                        self.win32.on_verified_menu_bar_item(bar_title, mono);
                        let transition = self
                            .tracking
                            .menu_opened(MenuHandleKey::Win32MenuBar(bound_hwnd_raw), true);
                        self.tracking.cancel();
                        self.apply_tracking_change(transition.tracking_changed, mono);
                    }
                    return;
                }

                let Some(resolved) = self.resolve_leaf_menu_item_cached(
                    uia,
                    refreshed_sender,
                    sender_meta,
                    deadline,
                    clock,
                ) else {
                    return;
                };
                // Post-read privacy gate AFTER ancestor resolution.
                if !self.passes_bound_privacy_gates(uia, registry, deadline, clock) {
                    self.clear_tracking_state(true);
                    return;
                }
                // Consume any volatile highlight so fallback hook cannot double-emit, enqueue, and
                // disarm active menu tracking immediately after a committed leaf invocation.
                let commit_mono = clock.monotonic_ms();
                let _ = self.tracking.commit(commit_mono);
                self.enqueue_resolved_action(resolved, ev.observed_unix_ms, commit_mono);
                self.clear_tracking_state(true);
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
                // Disarm ActiveMenuBarLink + tracking immediately so Esc -> right-click in editor
                // can never inherit a stale top-menu-bar link.
                self.clear_tracking_state(true);
            }
            MenuCommitSignal::LeftButtonUp { unix_ms, .. }
            | MenuCommitSignal::Return { unix_ms, .. } => {
                let now_mono = clock.monotonic_ms();
                let Some(resolved) = self.tracking.commit(now_mono) else {
                    return;
                };
                let deadline = now_mono.saturating_add(MENU_EVENT_BUDGET_MS);
                if !self.passes_bound_privacy_gates(uia, registry, deadline, clock) {
                    self.clear_tracking_state(true);
                    return;
                }
                self.enqueue_resolved_action(resolved, unix_ms, now_mono);
                self.clear_tracking_state(true);
            }
        }
    }

    fn handle_win_close_or_switch(&mut self, ev: WinMenuEvent, clock: &dyn CollectorClock) {
        let now_mono = clock.monotonic_ms();
        match ev.kind {
            WinMenuEventKind::PopupEnd => {
                if ev.hwnd_raw != 0 {
                    let root_raw = root_hwnd_for_raw(ev.hwnd_raw).0 as isize;
                    if self
                        .popup_uia_sub
                        .as_ref()
                        .is_some_and(|(h, _)| *h == root_raw || *h == ev.hwnd_raw)
                    {
                        self.detach_popup_uia_subscription();
                    }
                    let should_disarm = self.win32.on_popup_end(root_raw);
                    if should_disarm {
                        self.clear_tracking_state(true);
                    } else {
                        let transition = self
                            .tracking
                            .menu_closed(&MenuHandleKey::Hwnd(root_raw));
                        self.apply_tracking_change(transition.tracking_changed, now_mono);
                    }
                } else {
                    self.clear_tracking_state(true);
                }
            }
            WinMenuEventKind::MenuEnd => {
                self.clear_tracking_state(true);
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
                    self.clear_tracking_state(true);
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
    ) -> Option<(MenuHandleKey, OpenedMenuKind)> {
        let bound = self.bound.as_ref()?;
        let win32_link = self.current_win32_link(clock.monotonic_ms());
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

    fn resolve_leaf_menu_item_cached(
        &self,
        uia: &UiaClient,
        leaf_elem: IUIAutomationElement,
        leaf_meta: UiaElementMetadata,
        deadline_ms: i64,
        clock: &dyn CollectorClock,
    ) -> Option<ResolvedMenuPath> {
        let bound = self.bound.as_ref()?;
        let win32_link = self.current_win32_link(clock.monotonic_ms());
        let raw_host_pid = (bound.raw_pid > 0 && bound.raw_pid != bound.app.process_id)
            .then_some(bound.raw_pid);

        resolve_uia_menu_leaf_handle(
            uia,
            WalkHandle::from_cached(leaf_elem, leaf_meta),
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

fn root_hwnd_for_raw(raw_hwnd: isize) -> HWND {
    let hwnd = HWND(raw_hwnd as *mut core::ffi::c_void);
    if hwnd.0.is_null() {
        return hwnd;
    }
    // SAFETY: Standard read-only Win32 root ancestor query.
    let root = unsafe { GetAncestor(hwnd, GA_ROOT) };
    if !root.0.is_null() {
        root
    } else {
        hwnd
    }
}

fn window_class_name(hwnd: HWND) -> Option<String> {
    if hwnd.0.is_null() {
        return None;
    }
    let mut buf = [0u16; 128];
    // SAFETY: Standard read-only Win32 class name query.
    let len = unsafe { GetClassNameW(hwnd, &mut buf) };
    if len <= 0 {
        return None;
    }
    String::from_utf16(&buf[..len as usize]).ok()
}

fn hwnd_matches_bound_pid(hwnd: HWND, expected_pid: u32, raw_pid: u32) -> bool {
    if hwnd.0.is_null() {
        return false;
    }
    let mut pid: u32 = 0;
    // SAFETY: Standard read-only Win32 PID query.
    unsafe {
        GetWindowThreadProcessId(hwnd, Some(&mut pid));
    }
    pid > 0 && (pid == expected_pid || (raw_pid > 0 && pid == raw_pid))
}

fn popup_hwnd_belongs_to_bound(
    popup_hwnd: HWND,
    bound_hwnd: HWND,
    expected_pid: u32,
    raw_pid: u32,
) -> bool {
    if popup_hwnd.0.is_null()
        || bound_hwnd.0.is_null()
        || popup_hwnd == bound_hwnd
        // SAFETY: Standard read-only Win32 desktop window handle lookup.
        || popup_hwnd == unsafe { GetDesktopWindow() }
    {
        return false;
    }
    if !hwnd_matches_bound_pid(popup_hwnd, expected_pid, raw_pid) {
        return false;
    }
    if is_owned_popup_hwnd(popup_hwnd, bound_hwnd) {
        return true;
    }
    // Strictly permit unowned popups ONLY when their class is classic Win32 `#32768`; reject all
    // unowned sibling top-level windows (e.g. separate Incognito browser windows, Desktop/Taskbar)
    // and popups owned by any other window.
    // SAFETY: Standard read-only Win32 owner query.
    let owner = unsafe { GetWindow(popup_hwnd, GW_OWNER) }
        .ok()
        .filter(|h| !h.0.is_null());
    owner.is_none()
        && window_class_name(popup_hwnd)
            .as_deref()
            .is_some_and(|cls| cls.eq_ignore_ascii_case("#32768"))
}

/// Structural-only `ControlType` filter run on `FocusChanged` BEFORE heavy browser chrome
/// inspection or any `metadata_cache` (`Name`/`Title`/`Value`) read.
fn is_structural_menu_focus_candidate(
    uia: &UiaClient,
    focused: &IUIAutomationElement,
    control_type: i32,
    is_browser: bool,
    deadline_ms: i64,
    clock: &dyn CollectorClock,
) -> bool {
    if matches!(
        control_type,
        UIA_MENU_ITEM_CONTROL_TYPE | UIA_MENU_CONTROL_TYPE | UIA_MENU_BAR_CONTROL_TYPE
    ) {
        return true;
    }
    if control_type != UIA_BUTTON_CONTROL_TYPE {
        return false;
    }
    // For `Button (50000)`: in browsers check ONLY the immediate parent's ControlType (`MenuBar` /
    // `MenuItem`) so web-page `<button>` focus never triggers `is_private_browser_window_chrome`;
    // in non-browsers allow up to 2 structural wrapper hops (`Custom` / `Group` / `Pane`).
    let max_hops = if is_browser { 0 } else { 2 };
    let mut cur = focused.clone();
    for _ in 0..=max_hops {
        let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
        if rem <= 0 {
            return false;
        }
        uia.apply_timeouts(rem.min(25));
        let Ok(Some(parent)) = uia.parent_element_raw(&cur) else {
            return false;
        };
        let Ok(pct) = uia.current_control_type(&parent) else {
            return false;
        };
        if matches!(pct, UIA_MENU_BAR_CONTROL_TYPE | UIA_MENU_ITEM_CONTROL_TYPE) {
            return true;
        }
        if !matches!(
            pct,
            UIA_CUSTOM_CONTROL_TYPE | UIA_GROUP_CONTROL_TYPE | UIA_PANE_CONTROL_TYPE
        ) {
            return false;
        }
        cur = parent;
    }
    false
}

/// Checks whether `elem` (with cached `meta`) is a top-level item (`MenuItem`, `MenuBarItem`, or
/// `Button`) whose direct parent or ancestor within `<= 2` allowlisted safe transparent wrapper
/// hops (`Custom 50025` / `Group 50026` / `Pane 50033`) is a verified non-`SystemMenuBar`
/// `MenuBar (50010)` belonging to `bound.hwnd`.
fn detect_verified_menu_bar_item(
    uia: &UiaClient,
    elem: &IUIAutomationElement,
    meta: &UiaElementMetadata,
    bound: &BoundMenuWindow,
    deadline_ms: i64,
    clock: &dyn CollectorClock,
) -> Option<String> {
    let expected_pid = bound.app.process_id;
    let raw_pid = bound.raw_pid;
    let pid_ok = meta.process_id > 0
        && (meta.process_id == expected_pid || (raw_pid > 0 && meta.process_id == raw_pid));
    if !pid_ok
        || meta.is_sensitive()
        || !TextSecurityGate::may_traverse(&meta.subrole_read, meta.is_password)
        || meta.is_enabled == Some(false)
    {
        return None;
    }

    let is_bar_item_candidate = meta.control_type == UIA_MENU_ITEM_CONTROL_TYPE
        || meta.control_type == UIA_BUTTON_CONTROL_TYPE
        || meta.mapped.ax_role == Some("AXMenuBarItem");
    if !is_bar_item_candidate {
        return None;
    }

    let mut title = meta
        .name
        .as_deref()
        .and_then(MenuPathLimits::sanitize_segment)
        .or_else(|| {
            meta.safe_description()
                .and_then(MenuPathLimits::sanitize_segment)
        });

    let started_as_button = meta.control_type == UIA_BUTTON_CONTROL_TYPE;
    let mut cur = elem.clone();
    // Allow direct parent (hop 0) or up to 2 explicit allowlisted wrapper hops (`Custom 50025`,
    // `Group 50026`, `Pane 50033`, plus enclosing `MenuItem 50011` only on `started_as_button &&
    // hop == 0`) to reach `MenuBar (50010)`.
    for hop in 0..=2 {
        let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
        if rem <= 0 {
            return None;
        }
        uia.apply_timeouts(rem.min(40));
        let Ok(Some(parent)) = uia.parent_element(&cur) else {
            return None;
        };
        if uia.is_root_desktop_element(&parent) {
            return None;
        }
        let Ok(pmeta) = uia.read_cached_metadata(&parent, bound.dpi, false, false) else {
            return None;
        };
        let parent_pid_ok = pmeta.process_id > 0
            && (pmeta.process_id == expected_pid
                || (raw_pid > 0 && pmeta.process_id == raw_pid));
        if !parent_pid_ok
            || pmeta.is_sensitive()
            || !TextSecurityGate::may_traverse(&pmeta.subrole_read, pmeta.is_password)
        {
            return None;
        }
        if pmeta.control_type == UIA_MENU_BAR_CONTROL_TYPE {
            let is_sys = pmeta
                .automation_id
                .as_deref()
                .is_some_and(|aid| aid.eq_ignore_ascii_case("SystemMenuBar"));
            if is_sys {
                return None;
            }
            if let Some(ref expected_bar) = bound.app_menu_bar {
                if !uia.compare_elements(&parent, expected_bar) {
                    return None;
                }
            }
            if !menu_bar_belongs_to_window(
                uia,
                &parent,
                &pmeta,
                bound.hwnd,
                bound.dpi,
                deadline_ms,
                clock,
            ) {
                return None;
            }
            return title;
        }
        if pmeta.control_type == UIA_MENU_ITEM_CONTROL_TYPE {
            if started_as_button && hop == 0 && pmeta.is_enabled != Some(false) {
                if title.is_none() {
                    title = pmeta
                        .name
                        .as_deref()
                        .and_then(MenuPathLimits::sanitize_segment)
                        .or_else(|| {
                            pmeta
                                .safe_description()
                                .and_then(MenuPathLimits::sanitize_segment)
                        });
                }
                cur = parent;
                continue;
            }
            return None;
        }
        let is_allowed_wrapper = matches!(
            pmeta.control_type,
            UIA_CUSTOM_CONTROL_TYPE | UIA_GROUP_CONTROL_TYPE | UIA_PANE_CONTROL_TYPE
        ) && !matches!(
            pmeta.mapped.ax_role,
            Some(
                "AXWebArea"
                    | "AXDocument"
                    | "AXWindow"
                    | "AXSecureTextField"
                    | "AXTextArea"
                    | "AXTextField"
            )
        );
        if !is_allowed_wrapper {
            return None;
        }
        cur = parent;
    }
    None
}

/// Bounded scan (up to `MAX_LEAF_MENU_CHILD_SCAN = 8` direct children) returning `Ok(true)` ONLY
/// if any direct child has `control_type == UIA_MENU_CONTROL_TYPE (50009)` or
/// `UIA_MENU_ITEM_CONTROL_TYPE (50011)`, ignoring visual children (`Text`, `Image`, `Group`) and
/// failing closed (`Err`) on COM error, deadline expiry, unsafe child metadata, or `> 8` children.
fn has_menu_child(
    uia: &UiaClient,
    elem: &IUIAutomationElement,
    dpi: u32,
    deadline_ms: i64,
    clock: &dyn CollectorClock,
) -> Result<bool, UiaCallError> {
    let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
    if rem <= 0 {
        return Err(UiaCallError::Unavailable);
    }
    uia.apply_timeouts(rem);
    let mut cur = uia.first_child_element(elem)?;
    for _ in 0..MAX_LEAF_MENU_CHILD_SCAN {
        let Some(child) = cur else {
            return Ok(false);
        };
        let meta = uia.read_cached_metadata(&child, dpi, false, false)?;
        if meta.control_type == 0
            || meta.is_sensitive()
            || !TextSecurityGate::may_traverse(&meta.subrole_read, meta.is_password)
        {
            return Err(UiaCallError::Unavailable);
        }
        if is_menu_structure_control_type(meta.control_type) {
            return Ok(true);
        }
        let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
        if rem <= 0 {
            return Err(UiaCallError::Unavailable);
        }
        uia.apply_timeouts(rem);
        cur = uia.next_sibling_element(&child)?;
    }
    // Fail closed if the MenuItem has more than 8 direct children whose ControlTypes weren't scanned.
    if cur.is_some() {
        return Err(UiaCallError::Unavailable);
    }
    Ok(false)
}

/// Fast zero-COM pre-gate verifying policy, unlocked desktop, foreground HWND (either `bound.hwnd`
/// or an owned popup of `bound.hwnd`), exact dual-ID `(app, resolved)` identity, app/browser
/// policy, and non-private ephemeral browser window title. Returns the verified foreground `HWND`.
fn passes_fast_menu_privacy_pre_gate(
    registry: &AdapterRegistry,
    bound: &BoundMenuWindow,
    deadline_ms: i64,
    clock: &dyn CollectorClock,
) -> Option<HWND> {
    if clock.monotonic_ms() >= deadline_ms
        || !bound.policy.enabled
        || bound.policy.menu_actions != Some(true)
    {
        return None;
    }
    if assess_windows_desktop().status != DesktopStatus::Unlocked {
        return None;
    }
    // SAFETY: Standard Win32 foreground window lookup.
    let fg = unsafe { GetForegroundWindow() };
    if fg.0.is_null() {
        return None;
    }
    if fg != bound.hwnd && !is_owned_popup_hwnd(fg, bound.hwnd) {
        return None;
    }
    let (_, current_app, current_resolved) = resolve_application_identity_for_hwnd(fg, None, None)?;
    if current_app != bound.app || current_resolved != bound.resolved {
        return None;
    }
    if !ApplicationPolicy::allows_identity(&bound.policy, &current_resolved)
        || !BrowserGate::allows_identity(&current_resolved, &bound.policy, false)
    {
        return None;
    }
    let spec = registry.adapter_for_identity(&current_resolved);
    let is_browser = BrowserGate::is_known_browser_identity(&current_resolved)
        || BrowserGate::should_block_private_windows_identity(
            &current_resolved,
            spec.block_private_windows,
        );
    if is_browser {
        if bound.policy.application_scope.as_deref() != Some("denylist")
            || bound.policy.allow_browser_content != Some(true)
        {
            return None;
        }
        let title = read_window_title_ephemeral(bound.hwnd)?;
        if BrowserGate::is_private_window_title(&title) {
            return None;
        }
    }
    Some(fg)
}

/// Full pre-read & post-read privacy gate executed BEFORE reading any menu element title and
/// re-verified AFTER path resolution (including fail-closed native browser chrome verification and
/// post-check foreground identity verification).
fn passes_live_menu_privacy_gates(
    uia: &UiaClient,
    registry: &AdapterRegistry,
    bound: &BoundMenuWindow,
    deadline_ms: i64,
    clock: &dyn CollectorClock,
) -> bool {
    let Some(fg) = passes_fast_menu_privacy_pre_gate(registry, bound, deadline_ms, clock) else {
        return false;
    };

    let spec = registry.adapter_for_identity(&bound.resolved);
    let is_browser_candidate = BrowserGate::is_known_browser_identity(&bound.resolved);
    let chrome_ok = BrowserMenuWindowGate::allows_foreground_window(
        &bound.resolved,
        is_browser_candidate,
        spec,
        &bound.policy,
        || inspect_browser_window_for_menu_gate(uia, bound.hwnd, bound.dpi, deadline_ms, clock),
    );
    if !chrome_ok {
        return false;
    }

    // Confirm foreground window did not switch away from `bound.hwnd` (or a verified same-identity
    // owned popup) while browser chrome inspection ran.
    // SAFETY: Standard Win32 foreground window lookup.
    let final_fg = unsafe { GetForegroundWindow() };
    if final_fg == fg {
        return true;
    }
    if final_fg != bound.hwnd && !is_owned_popup_hwnd(final_fg, bound.hwnd) {
        return false;
    }
    resolve_application_identity_for_hwnd(final_fg, None, None)
        .is_some_and(|(_, app, resolved)| app == bound.app && resolved == bound.resolved)
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
    // Walk up to `MAX_MENU_BAR_WINDOW_HOPS` (18) ancestors to verify deep Electron / WinUI 3
    // `MenuBar` elements live inside `bound_hwnd`.
    let mut cur = bar_elem.clone();
    for _ in 0..MAX_MENU_BAR_WINDOW_HOPS {
        let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
        if rem <= 0 {
            return false;
        }
        uia.apply_timeouts(rem);
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
        let child_count = match has_menu_child(uia, &handle.elem, dpi, deadline_ms, clock) {
            Ok(false) => Some(0),
            Ok(true) => Some(1),
            Err(UiaCallError::AccessDenied | UiaCallError::Unavailable) => None,
        };
        let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
        if rem <= 0 {
            return None;
        }
        uia.apply_timeouts(rem);
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
fn resolve_uia_menu_leaf_handle(
    uia: &UiaClient,
    leaf_handle: WalkHandle,
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
    resolve_uia_menu_leaf_handle(
        uia,
        WalkHandle::from_cached(refreshed_leaf, leaf_meta),
        bound_hwnd,
        expected_pid,
        raw_host_pid,
        dpi,
        app_menu_bar,
        win32_link,
        deadline_ms,
        clock,
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

/// Deterministic integration-test helper exercising `has_menu_child` against a live Win32 UIA
/// element (distinguishing visual leaf children like `Text`/`Image`/`Group` from nested
/// `Menu`/`MenuItem` children).
pub fn has_menu_child_for_test(
    uia: &UiaClient,
    elem: &IUIAutomationElement,
    dpi: u32,
    clock: &dyn CollectorClock,
) -> Result<bool, UiaCallError> {
    let deadline_ms = clock.monotonic_ms().saturating_add(500);
    has_menu_child(uia, elem, dpi, deadline_ms, clock)
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

        // Consecutive uninterrupted `FocusChanged` bursts coalesce to the latest index while
        // preserving exact ordering around `PopupEnd` / `PopupStart`.
        let focus_burst = [
            mk_win_ev(WinMenuEventKind::FocusChanged, 0x10),
            mk_win_ev(WinMenuEventKind::FocusChanged, 0x11),
            mk_win_ev(WinMenuEventKind::FocusChanged, 0x12),
            mk_win_ev(WinMenuEventKind::PopupEnd, 0x12),
            mk_win_ev(WinMenuEventKind::FocusChanged, 0x20),
            mk_win_ev(WinMenuEventKind::FocusChanged, 0x21),
            mk_win_ev(WinMenuEventKind::PopupStart, 0x30),
        ];
        assert_eq!(
            plan_poll_win_events(&focus_burst),
            vec![
                PollBatchStep::WinEvent(2),
                PollBatchStep::FlushInvokesAndCommitSignals,
                PollBatchStep::WinEvent(3),
                PollBatchStep::WinEvent(5),
                PollBatchStep::WinEvent(6),
            ],
            "consecutive FocusChanged events must coalesce to the latest index per run"
        );
    }

    #[test]
    fn win32_menu_bar_state_handles_all_glide_orderings_and_nested_submenus() {
        // Order 1: `[PopupEnd(file), FocusChanged(Edit), PopupStart(edit)]`.
        let mut s = Win32MenuBarState::default();
        s.on_menu_bar_start(1_000);
        s.on_verified_menu_bar_item("File".to_string(), 1_000);
        s.on_popup_start(0x10, Some("File".to_string()), 1_010);
        assert_eq!(s.current_link(1_020).unwrap().menu_bar_item_title, "File");
        assert!(s.current_link(1_020).unwrap().submenu_titles.is_empty());

        s.on_popup_end(0x10);
        s.on_verified_menu_bar_item("Edit".to_string(), 1_030);
        s.on_popup_start(0x20, Some("Edit".to_string()), 1_040);
        let link1 = s.current_link(1_050).expect("Edit link");
        assert_eq!(link1.menu_bar_item_title, "Edit");
        assert!(link1.submenu_titles.is_empty());
        assert_eq!(s.last_popup_hwnd(), Some(0x20));

        // Order 2: `[PopupEnd(edit), PopupStart(view)]` (no intermediate FocusChanged).
        s.on_popup_end(0x20);
        s.on_popup_start(0x30, Some("View".to_string()), 1_060);
        let link2 = s.current_link(1_070).expect("View link");
        assert_eq!(link2.menu_bar_item_title, "View");
        assert!(link2.submenu_titles.is_empty());

        // Order 3: `[FocusChanged(Help), PopupEnd(view), PopupStart(help)]`.
        s.on_verified_menu_bar_item("Help".to_string(), 1_080);
        s.on_popup_end(0x30);
        s.on_popup_start(0x40, None, 1_090);
        let link3 = s.current_link(1_100).expect("Help link");
        assert_eq!(link3.menu_bar_item_title, "Help");
        assert!(link3.submenu_titles.is_empty());

        // Order 4: `[FocusChanged(File), PopupStart(file2), PopupEnd(help)]`.
        s.on_verified_menu_bar_item("File".to_string(), 1_110);
        s.on_popup_start(0x50, Some("File".to_string()), 1_120);
        s.on_popup_end(0x40);
        let link4 = s.current_link(1_130).expect("File link");
        assert_eq!(link4.menu_bar_item_title, "File");
        assert!(link4.submenu_titles.is_empty());
        assert_eq!(s.last_popup_hwnd(), Some(0x50));

        // Nested submenu: `File -> Export -> PDF`, then closing `Export` returns to `File`.
        s.on_submenu_opener_focused(Some("Export".to_string()), 1_140);
        s.on_popup_start(0x51, None, 1_150);
        let sub = s.current_link(1_160).expect("File -> Export link");
        assert_eq!(sub.menu_bar_item_title, "File");
        assert_eq!(sub.submenu_titles, vec!["Export".to_string()]);
        assert_eq!(s.last_popup_hwnd(), Some(0x51));

        s.on_popup_end(0x51);
        let back = s.current_link(1_170).expect("back to File");
        assert_eq!(back.menu_bar_item_title, "File");
        assert!(back.submenu_titles.is_empty());
        assert_eq!(s.last_popup_hwnd(), Some(0x50));
    }

    #[test]
    fn win32_menu_bar_state_arms_from_verified_bar_item_enforces_ttl_and_clears_on_non_menu() {
        // WinUI 3 Notepad path: no `MenuBarStart`, armed directly from verified `MenuBar` item.
        let mut s = Win32MenuBarState::default();
        assert_eq!(s.current_link(1_000), None);

        s.on_verified_menu_bar_item("File".to_string(), 1_000);
        let armed = s.current_link(1_000).expect("armed File link");
        assert_eq!(armed.menu_bar_item_title, "File");
        assert!(armed.from_menu_bar_start);
        assert!(armed.submenu_titles.is_empty());

        // UIA submenu tracking without Win32 `PopupStart`.
        s.on_submenu_opener_focused(Some("Zoom".to_string()), 1_100);
        s.on_uia_menu_opened(true, 1_110);
        let sub = s.current_link(1_120).expect("File -> Zoom link");
        assert_eq!(sub.submenu_titles, vec!["Zoom".to_string()]);
        s.on_uia_menu_closed(1);
        assert!(s.current_link(1_130).unwrap().submenu_titles.is_empty());

        // 10s TTL ceiling (`MAX_MENU_TRACKING_MS = 10_000`): 10_999ms valid, 11_000ms expired.
        assert!(s.current_link(10_999).is_some());
        assert_eq!(s.current_link(11_000), None);
        assert!(s.expire_if_stale(11_000));
        assert!(!s.active);

        // Clock rollback fails closed.
        s.on_verified_menu_bar_item("View".to_string(), 20_000);
        assert_eq!(s.current_link(19_999), None);
        assert!(s.current_link(20_000).is_some());

        // Clearing (as done on non-menu FocusChanged like AXTextArea) immediately disarms link
        // so any subsequent right-click context menu sees `None`.
        s.clear();
        assert_eq!(s.current_link(20_001), None);
    }

    #[test]
    fn winui3_popup_end_disarms_link_and_never_adopts_context_popup_title() {
        // WinUI 3 / Electron path (`!from_objid_menu`): PopupEnd emptying popup_stack MUST disarm
        // the link completely (since Win32 MenuEnd never fires), and a subsequent `#32768`
        // "Context" popup can NEVER adopt `"Context"` as `bar_item_title`!
        let mut s = Win32MenuBarState::default();
        s.on_verified_menu_bar_item("File".to_string(), 1_000);
        assert!(!s.from_objid_menu);
        s.on_popup_start(0x10, Some("Context".to_string()), 1_010);
        assert_eq!(s.current_link(1_020).unwrap().menu_bar_item_title, "File");

        // Closing the WinUI 3 popup disarms `active` completely and returns `true`.
        assert!(s.on_popup_end(0x10));
        assert!(!s.active);
        assert_eq!(s.current_link(1_030), None);

        // Even if `PopupEnd` arrives when `popup_stack` was already empty (e.g. no prior
        // `PopupStart`), `!from_objid_menu` disarms immediately.
        s.on_verified_menu_bar_item("Edit".to_string(), 1_100);
        assert!(s.on_popup_end(0x99));
        assert!(!s.active);
        assert_eq!(s.current_link(1_110), None);

        // Even if `bar_item_title` were cleared while `!from_objid_menu`, `on_popup_start` MUST
        // NOT adopt `"Context"` as `bar_item_title` or submenu title.
        s.on_verified_menu_bar_item("File".to_string(), 1_200);
        s.bar_item_title = None;
        s.on_popup_start(0x20, Some("Context".to_string()), 1_210);
        assert_eq!(
            s.current_link(1_220),
            None,
            "non-OBJID_MENU session must never adopt popup window title 'Context'"
        );
        // Nested popup without `pending_submenu_candidate` also must not adopt popup title.
        s.on_verified_menu_bar_item("File".to_string(), 1_300);
        s.on_popup_start(0x30, None, 1_310);
        s.on_popup_start(0x31, Some("Context".to_string()), 1_320);
        assert!(s.current_link(1_330).unwrap().submenu_titles.is_empty());
    }

    #[test]
    fn escape_and_unmatched_menu_closed_fallback_disarm_active_menu_bar_link() {
        use crate::protocol_model::SystemCollectorClock;
        use crate::uia_com::ComGuard;

        // 1. `MenuClosed` with a non-null `RuntimeId` that isn't in `open_menus` (because a
        // `Win32MenuBar` placeholder was active) MUST fail closed and disarm `win32` + tracking!
        let mut session = MenuActionSession::new();
        session.win32.on_verified_menu_bar_item("File".to_string(), 5_000);
        let open_tr = session
            .tracking
            .menu_opened(MenuHandleKey::Win32MenuBar(0x100), true);
        session.apply_tracking_change(open_tr.tracking_changed, 5_000);
        assert!(session.tracking.is_tracking());
        assert!(session.current_win32_link(5_010).is_some());

        session.apply_uia_menu_closed(Some(MenuHandleKey::RuntimeId(RuntimeIdKey(vec![42, 7]))), 5_020);
        assert!(!session.tracking.is_tracking());
        assert!(!session.menu_open_flag.load(Ordering::Acquire));
        assert_eq!(session.current_win32_link(5_030), None);

        // 2. `MenuCommitSignal::Escape` MUST fully disarm `ActiveMenuBarLink` + tracking (not just
        // clear volatile highlight) so `File -> Esc -> right-click` cannot leak `["File", ...]`.
        let _com = ComGuard::init_mta().expect("MTA COM init");
        let uia = UiaClient::new().expect("UiaClient::new");
        let registry = AdapterRegistry::new();
        let clock = SystemCollectorClock;
        let now_mono = clock.monotonic_ms();
        session.win32.on_verified_menu_bar_item("File".to_string(), now_mono);
        let open_tr = session
            .tracking
            .menu_opened(MenuHandleKey::Win32MenuBar(0x100), true);
        session.apply_tracking_change(open_tr.tracking_changed, now_mono);
        session.accept_after_qpc_ns = 100;
        let esc = MenuCommitSignal::Escape {
            qpc_ns: 200,
            unix_ms: clock.unix_ms(),
        };
        session.handle_commit_signal(&uia, &registry, esc, 250, &clock);
        assert!(!session.tracking.is_tracking());
        assert!(!session.menu_open_flag.load(Ordering::Acquire));
        assert_eq!(session.current_win32_link(now_mono + 10), None);
    }

    #[test]
    fn non_menu_focus_disarms_active_menu_bar_link_and_rejects_subsequent_context_menu() {
        use crate::policy::{ProtectedContentRead, SubroleRead};

        // 1. Arm `MenuActionSession` as if user focused `"File"` on a WinUI 3 `MenuBar`.
        let mut session = MenuActionSession::new();
        session.win32.on_verified_menu_bar_item("File".to_string(), 5_000);
        let open_tr = session
            .tracking
            .menu_opened(MenuHandleKey::Win32MenuBar(0x100), true);
        session.apply_tracking_change(open_tr.tracking_changed, 5_000);
        assert!(session.tracking.is_tracking());
        assert!(session.menu_open_flag.load(Ordering::Acquire));
        assert_eq!(session.take_menu_tracking(), Some(true));
        let armed_link = session.current_win32_link(5_050).expect("armed link");

        // Detached WinUI 3 flyout under Window resolves while armed.
        let nodes = [
            MenuNodeSnapshot {
                pid: 42,
                control_type: Some(UIA_MENU_ITEM_CONTROL_TYPE),
                role: Some("AXMenuItem".to_string()),
                subrole: SubroleRead::NoValue,
                protected_content: ProtectedContentRead::Value(false),
                enabled: Some(true),
                title: Some("Paste".to_string()),
                description: None,
                automation_id: None,
                class_name: None,
                child_count: Some(0),
                is_submenu_opener: Some(false),
            },
            MenuNodeSnapshot {
                pid: 42,
                control_type: Some(UIA_MENU_CONTROL_TYPE),
                role: Some("AXMenu".to_string()),
                subrole: SubroleRead::NoValue,
                protected_content: ProtectedContentRead::Value(false),
                enabled: Some(true),
                title: None,
                description: None,
                automation_id: None,
                class_name: Some("MenuFlyoutPresenter".to_string()),
                child_count: None,
                is_submenu_opener: None,
            },
            MenuNodeSnapshot {
                pid: 42,
                control_type: Some(UIA_GROUP_CONTROL_TYPE),
                role: Some("AXGroup".to_string()),
                subrole: SubroleRead::NoValue,
                protected_content: ProtectedContentRead::Value(false),
                enabled: Some(true),
                title: Some("Popup".to_string()),
                description: None,
                automation_id: None,
                class_name: None,
                child_count: None,
                is_submenu_opener: None,
            },
            MenuNodeSnapshot {
                pid: 42,
                control_type: Some(UIA_WINDOW_CONTROL_TYPE),
                role: Some("AXWindow".to_string()),
                subrole: SubroleRead::NoValue,
                protected_content: ProtectedContentRead::Value(false),
                enabled: Some(true),
                title: Some("Notepad".to_string()),
                description: None,
                automation_id: None,
                class_name: None,
                child_count: None,
                is_submenu_opener: None,
            },
        ];
        assert_eq!(
            MenuPathResolver::resolve(
                0usize,
                42,
                None,
                None,
                None,
                Some(&armed_link),
                |a, b| a == b,
                |&idx, _| Some(nodes[idx].clone()),
                |&idx| (idx + 1 < nodes.len()).then_some(idx + 1),
                || true,
            )
            .map(|r| r.path),
            Some(vec!["File".to_string(), "Paste".to_string()])
        );

        // 2. Focus moves to non-menu element (`AXTextArea`): `clear_tracking_state(true)` runs.
        session.clear_tracking_state(true);
        assert!(!session.tracking.is_tracking());
        assert!(!session.menu_open_flag.load(Ordering::Acquire));
        assert_eq!(session.take_menu_tracking(), Some(false));
        assert_eq!(session.current_win32_link(5_100), None);

        // 3. Subsequent right-click context menu in editor sees `None` link -> strictly rejected!
        let post_clear_link = session.current_win32_link(5_100);
        assert_eq!(
            MenuPathResolver::resolve(
                0usize,
                42,
                None,
                None,
                None,
                post_clear_link.as_ref(),
                |a, b| a == b,
                |&idx, _| Some(nodes[idx].clone()),
                |&idx| (idx + 1 < nodes.len()).then_some(idx + 1),
                || true,
            ),
            None,
            "right-click context menu after focusing AXTextArea MUST be strictly rejected"
        );
    }

    #[test]
    fn leaf_menu_child_classifier_ignores_visual_children_and_flags_nested_menus() {
        use crate::menu_action_core::{
            UIA_GROUP_CONTROL_TYPE, UIA_IMAGE_CONTROL_TYPE, UIA_TEXT_CONTROL_TYPE,
        };
        assert!(!is_menu_structure_control_type(UIA_TEXT_CONTROL_TYPE));
        assert!(!is_menu_structure_control_type(UIA_IMAGE_CONTROL_TYPE));
        assert!(!is_menu_structure_control_type(UIA_GROUP_CONTROL_TYPE));
        assert!(!is_menu_structure_control_type(UIA_BUTTON_CONTROL_TYPE));
        assert!(is_menu_structure_control_type(UIA_MENU_CONTROL_TYPE));
        assert!(is_menu_structure_control_type(UIA_MENU_ITEM_CONTROL_TYPE));
    }
}
