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
const MAX_MENU_BAR_WINDOW_HOPS: usize = MenuPathLimits::MAX_ABOVE_MENU_BAR_HOPS;
/// Maximum number of active non-placeholder UIA menu elements retained for submenu classification.
const MAX_OPEN_MENUS: usize = 8;

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
    is_browser: bool,
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

struct OpenUiaMenu {
    key: MenuHandleKey,
    elem: IUIAutomationElement,
    runtime_id: RuntimeIdKey,
}

/// Element handle carried during `MenuPathResolver` ancestor walks so cached metadata and
/// `RuntimeIdKey` comparisons avoid redundant COM IPCs.
struct WalkHandle {
    elem: IUIAutomationElement,
    runtime_id: RuntimeIdKey,
    cached_meta: Option<UiaElementMetadata>,
    /// Optional precomputed `(child_count, is_submenu_opener)` leaf checks so `handle_focus_changed`
    /// never repeats `has_menu_child` / `is_submenu_opener` COM IPCs inside `inspect_walk_handle`.
    precomputed_leaf_checks: Option<(Option<usize>, Option<bool>)>,
}

impl WalkHandle {
    fn from_cached(elem: IUIAutomationElement, meta: UiaElementMetadata) -> Self {
        let runtime_id = meta.runtime_id.clone();
        Self {
            elem,
            runtime_id,
            cached_meta: Some(meta),
            precomputed_leaf_checks: None,
        }
    }

    fn from_uncached(elem: IUIAutomationElement) -> Self {
        Self {
            elem,
            runtime_id: RuntimeIdKey(Vec::new()),
            cached_meta: None,
            precomputed_leaf_checks: None,
        }
    }

    fn from_open_menu(elem: IUIAutomationElement, runtime_id: RuntimeIdKey) -> Self {
        Self {
            elem,
            runtime_id,
            cached_meta: None,
            precomputed_leaf_checks: None,
        }
    }

    fn with_leaf_checks(
        mut self,
        child_count: Option<usize>,
        is_submenu_opener: Option<bool>,
    ) -> Self {
        self.precomputed_leaf_checks = Some((child_count, is_submenu_opener));
        self
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
    /// stack is now empty and was NOT closing a superseded prior popup during slide-over).
    fn on_popup_end(&mut self, popup_hwnd: isize) -> bool {
        if popup_hwnd == 0 {
            self.clear();
            return true;
        }
        // WinUI 3 / Electron slide-over order `[FocusChanged(Edit), PopupEnd(File), PopupStart(Edit)]`:
        // `on_verified_menu_bar_item("Edit")` cleared `bar_item_owner_popup` to `None` while
        // keeping File's closing popup HWND in `popup_stack`. Closing that superseded popup must
        // NOT wipe the newly armed `"Edit"` bar title!
        let was_superseded =
            self.bar_item_owner_popup.is_none() && self.popup_stack.contains(&popup_hwnd);
        if let Some(pos) = self.popup_stack.iter().rposition(|&h| h == popup_hwnd) {
            self.popup_stack.remove(pos);
        }
        self.pending_submenu_candidate = None;
        if self.popup_stack.is_empty() {
            self.submenu_titles.clear();
            if !self.from_objid_menu {
                if was_superseded {
                    return false;
                }
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
enum MergedPollEvent {
    WinEvent(usize),
    UiaEvent(usize),
    CommitSignal(usize),
}

/// Merge `WinEvent`, MTA UIA menu events, and low-level `MenuCommitHook` signals via a true 3-way
/// merge over the 3 already-ordered FIFO queues, comparing queue heads by `(qpc, rank, stream_id)`.
///
/// Intra-stream FIFO order is NEVER inverted on equal QPC timestamps (e.g., `[PopupEnd(File),
/// PopupStart(Edit)]` or `[MenuEnd, MenuBarStart]`), while `rank` still breaks cross-stream ties so
/// `Invoked` / `CommitSignal` events with `qpc_ns <= ev.observed_qpc_ns` flush ahead of `PopupEnd`
/// / `MenuEnd` / `MenuClosed` / `DisarmNonMenuBar`, and a strictly later `LeftButtonUp` after a
/// blank-area `WM_LBUTTONDOWN`-triggered `PopupEnd` runs AFTER `PopupEnd`. Consecutive
/// uninterrupted `FocusChanged` bursts coalesce to the latest event.
fn plan_merged_poll_events(
    win_events: &[WinMenuEvent],
    uia_events: &[(Option<UiaMenuEventKind>, u64)],
    commit_signals: &[MenuCommitSignal],
) -> Vec<MergedPollEvent> {
    let win_rank = |kind: WinMenuEventKind| -> u8 {
        match kind {
            WinMenuEventKind::MenuBarStart => 0,
            WinMenuEventKind::PopupStart => 1,
            WinMenuEventKind::FocusChanged => 3,
            WinMenuEventKind::DisarmNonMenuBar
            | WinMenuEventKind::PopupEnd
            | WinMenuEventKind::MenuEnd
            | WinMenuEventKind::ForegroundChanged => 7,
        }
    };
    let uia_rank = |kind: UiaMenuEventKind| -> u8 {
        match kind {
            UiaMenuEventKind::MenuOpened => 2,
            UiaMenuEventKind::Invoked => 4,
            UiaMenuEventKind::MenuClosed => 6,
        }
    };

    let mut merged =
        Vec::with_capacity(win_events.len() + uia_events.len() + commit_signals.len());
    let mut wi = 0usize;
    let mut ui = 0usize;
    let mut ci = 0usize;
    while ui < uia_events.len() && uia_events[ui].0.is_none() {
        ui += 1;
    }

    loop {
        let win_key = win_events
            .get(wi)
            .map(|ev| (ev.observed_qpc_ns, win_rank(ev.kind), 0u8));
        let uia_key = uia_events
            .get(ui)
            .and_then(|&(kind, qpc_ns)| kind.map(|k| (qpc_ns, uia_rank(k), 1u8)));
        let sig_key = commit_signals
            .get(ci)
            .map(|sig| (sig.qpc_ns(), 5u8, 2u8));

        let mut best: Option<((u64, u8, u8), u8)> = None;
        for (stream_id, key_opt) in [(0u8, win_key), (1u8, uia_key), (2u8, sig_key)] {
            if let Some(key) = key_opt {
                if best.is_none_or(|(best_key, _)| key < best_key) {
                    best = Some((key, stream_id));
                }
            }
        }
        match best {
            Some((_, 0)) => {
                merged.push(MergedPollEvent::WinEvent(wi));
                wi += 1;
            }
            Some((_, 1)) => {
                merged.push(MergedPollEvent::UiaEvent(ui));
                ui += 1;
                while ui < uia_events.len() && uia_events[ui].0.is_none() {
                    ui += 1;
                }
            }
            Some((_, 2)) => {
                merged.push(MergedPollEvent::CommitSignal(ci));
                ci += 1;
            }
            _ => break,
        }
    }

    let mut out = Vec::with_capacity(merged.len());
    for i in 0..merged.len() {
        let ev = merged[i];
        if let MergedPollEvent::WinEvent(widx) = ev {
            if win_events[widx].kind == WinMenuEventKind::FocusChanged {
                if let Some(&MergedPollEvent::WinEvent(next_widx)) = merged.get(i + 1) {
                    if win_events[next_widx].kind == WinMenuEventKind::FocusChanged {
                        continue;
                    }
                }
            }
        }
        out.push(ev);
    }
    out
}

/// Stateful foreground top-menu-bar monitor combining MTA UIA event subscriptions, `WinEventWatcher`
/// menu lifecycle notifications, optional passive `MenuCommitHook` fallback, fail-closed browser
/// chrome privacy gates, bounded ancestor path resolution, and 250ms deduplication.
///
/// Field drop order note: COM fields (`open_uia_menus`, `popup_uia_sub`, `uia_sub`, `bound`) are
/// released explicitly on `retire_for_process_exit()` before `UiaClient` and `ComGuard` drop.
pub(super) struct MenuActionSession {
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

impl MenuActionSession {
    pub(super) fn new() -> Self {
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
    /// Skips COM probes (`find_app_menu_bar_for_window`, `attach_uia_subscription`) when
    /// `deadline_ms` budget is exhausted.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn sync_binding(
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
    pub(super) fn disable(
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
    pub(super) fn reset_for_boundary(
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
    pub(super) fn suppress_secure_input(
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
    pub(super) fn retire_for_process_exit(&mut self) {
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
            if self.retiring {
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

    fn detach_uia_subscription(
        &mut self,
        uia: Option<&UiaClient>,
        budget: Option<(i64, &dyn CollectorClock)>,
    ) {
        self.detach_popup_uia_subscription(uia, budget);
        if let Some(sub) = self.uia_sub.take() {
            if self.retiring {
                sub.abandon_for_process_exit();
            } else if let Some((deadline_ms, clock)) = budget {
                let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
                if rem <= 15 {
                    sub.abandon_for_process_exit();
                } else {
                    let per_call_ms = (rem / 3).clamp(1, 40) as u32;
                    if let Some(u) = uia {
                        u.apply_timeouts(per_call_ms as i64);
                    }
                    sub.detach_with_timeout(per_call_ms);
                }
            } else {
                if let Some(u) = uia {
                    u.apply_timeouts(40);
                }
                sub.detach();
            }
        }
        self.uia_tx = None;
        self.uia_rx = None;
    }

    fn clear_win32_menu_state(&mut self) {
        self.win32.clear();
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
    pub(super) fn poll(
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
        let tracking_expired = self
            .tracking_started_mono_ms
            .is_some_and(|started| {
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
            self.win32.popup_stack.is_empty() || self.win32.bar_item_owner_popup.is_none();
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
        let Some((is_browser, bound_hwnd, expected_pid, raw_pid, dpi)) =
            self.bound.as_ref().and_then(|bound| {
                passes_fast_menu_privacy_pre_gate(registry, bound, deadline_ms, clock)?;
                Some((
                    bound.is_browser,
                    bound.hwnd,
                    bound.app.process_id,
                    bound.raw_pid,
                    bound.dpi,
                ))
            })
        else {
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
            if self.tracking.is_tracking() || self.win32.active {
                self.clear_tracking_state(Some(uia), true, Some((deadline_ms, clock)));
            }
            return;
        };
        let Ok(ct) = uia.current_control_type(&raw_focused) else {
            if self.tracking.is_tracking() || self.win32.active {
                self.clear_tracking_state(Some(uia), true, Some((deadline_ms, clock)));
            }
            return;
        };
        if !is_structural_menu_focus_candidate(uia, &raw_focused, ct, is_browser, deadline_ms, clock)
        {
            // Non-menu element (e.g. `AXTextArea`, `Document`, `Edit`, regular button, tab):
            // immediately disarm `ActiveMenuBarLink` & tracking with ZERO browser chrome probe
            // and ZERO `metadata_cache` text reads.
            if self.tracking.is_tracking() || self.win32.active {
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
            if self.tracking.is_tracking() || self.win32.active {
                self.clear_tracking_state(Some(uia), true, Some((deadline_ms, clock)));
            }
            return;
        };
        let Ok(meta) = uia.read_cached_metadata(&focused, dpi, false, false) else {
            if self.tracking.is_tracking() || self.win32.active {
                self.clear_tracking_state(Some(uia), true, Some((deadline_ms, clock)));
            }
            return;
        };
        let pid_ok = meta.process_id > 0
            && (meta.process_id == expected_pid || (raw_pid > 0 && meta.process_id == raw_pid));
        if !pid_ok
            || meta.is_sensitive()
            || !TextSecurityGate::may_traverse(&meta.subrole_read, meta.is_password)
        {
            self.clear_tracking_state(Some(uia), true, Some((deadline_ms, clock)));
            return;
        }

        let now_mono = clock.monotonic_ms();

        // 1. Check whether focused element is a verified top-level item inside a non-`SystemMenuBar`
        // `MenuBar (50010)` belonging to `bound_hwnd` (WinUI 3 Notepad, Electron, classic Win32).
        if let Some(title) = self.bound.as_ref().and_then(|bound| {
            detect_verified_menu_bar_item(uia, &focused, &meta, bound, deadline_ms, clock)
        }) {
            let bound_hwnd_raw = bound_hwnd.0 as isize;
            self.open_uia_menus.clear();
            self.win32.on_verified_menu_bar_item(title, now_mono);
            let transition = self
                .tracking
                .menu_opened(MenuHandleKey::Win32MenuBar(bound_hwnd_raw), true);
            self.sync_open_uia_menus();
            self.tracking.cancel();
            self.apply_tracking_change(transition.tracking_changed, now_mono);
            return;
        }

        let bound_hwnd_raw = bound_hwnd.0 as isize;

        // 2. Focus landed on a `MenuBar` container itself: preserve active tracking only if it is
        // the verified app `MenuBar`; clear on `SystemMenuBar` or foreign/document bar.
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
                    expected_pid,
                    raw_pid,
                    is_browser,
                    dpi,
                    deadline_ms,
                    clock,
                );
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
        if self.tracking.is_tracking() || self.win32.active {
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
                        self.open_uia_menus.clear();
                        self.win32.on_verified_menu_bar_item(bar_title, mono);
                        let transition = self
                            .tracking
                            .menu_opened(MenuHandleKey::Win32MenuBar(bound_hwnd_raw), true);
                        self.sync_open_uia_menus();
                        self.tracking.cancel();
                        self.apply_tracking_change(transition.tracking_changed, mono);
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
                    } else if self.win32.popup_stack.is_empty() {
                        // Classic Win32 slide-over (`File -> Edit`): `PopupEnd` detached the popup
                        // UIA subscription so `MenuClosed` for `R1` may never arrive. Clear
                        // `open_uia_menus` and stale `RuntimeId`-keyed open menus from `tracking`
                        // so the next top-level menu (`Edit`) classifies cleanly as `TopLevel`.
                        self.open_uia_menus.clear();
                        let transition = self.tracking.retain_open_menus(|k| {
                            !matches!(k, MenuHandleKey::RuntimeId(_))
                                && *k != MenuHandleKey::Hwnd(root_raw)
                        });
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
            bound.app.process_id,
            raw_host_pid,
            app_menu_bar_handle.as_ref(),
            None,
            win32_link.as_ref(),
            &open_handles,
            !bound.is_browser,
            |a, b| walk_handles_same(uia, a, b, deadline_ms, clock),
            |handle| inspect_walk_handle(uia, handle, false, bound.dpi, deadline_ms, clock),
            |handle| parent_walk_handle(uia, handle, bound.dpi, deadline_ms, clock),
            |bar_handle| {
                verify_walk_menu_bar_owner(
                    uia,
                    bar_handle,
                    bound.hwnd,
                    bound.app.process_id,
                    bound.raw_pid,
                    bound.is_browser,
                    bound.dpi,
                    deadline_ms,
                    clock,
                )
            },
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
        let win32_link = self.current_win32_link(clock.monotonic_ms());
        let raw_host_pid = (bound.raw_pid > 0 && bound.raw_pid != bound.app.process_id)
            .then_some(bound.raw_pid);

        let mut leaf_handle = WalkHandle::from_cached(leaf_elem, leaf_meta);
        if let Some((child_count, is_opener)) = precomputed_leaf_checks {
            leaf_handle = leaf_handle.with_leaf_checks(child_count, is_opener);
        }

        resolve_uia_menu_leaf_handle(
            uia,
            leaf_handle,
            bound.hwnd,
            bound.app.process_id,
            raw_host_pid,
            bound.is_browser,
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

fn preferred_meta_title(meta: &UiaElementMetadata) -> Option<String> {
    meta.name
        .as_deref()
        .and_then(MenuPathLimits::sanitize_segment)
        .or_else(|| {
            meta.safe_description()
                .and_then(MenuPathLimits::sanitize_segment)
        })
}

fn is_document_or_renderer_host(meta: &UiaElementMetadata) -> bool {
    meta.control_type == 50030
        || matches!(meta.mapped.ax_role, Some("AXWebArea" | "AXDocument"))
        || meta.class_name.as_deref().is_some_and(|c| {
            c.eq_ignore_ascii_case("Chrome_RenderWidgetHostHWND")
                || c.eq_ignore_ascii_case("MozillaCompositorWindowClass")
        })
}

/// Strict allowlist for transparent layout wrappers between a top-level menu bar item and its
/// `MenuBar (50010)` parent, matching `MenuNodeSnapshot::is_transparent_menu_wrapper`.
fn is_allowed_menu_bar_wrapper_fields(
    control_type: i32,
    ax_role: Option<&str>,
    class_name: Option<&str>,
) -> bool {
    let is_doc_or_renderer = control_type == 50030
        || matches!(ax_role, Some("AXWebArea" | "AXDocument"))
        || class_name.is_some_and(|c| {
            c.eq_ignore_ascii_case("Chrome_RenderWidgetHostHWND")
                || c.eq_ignore_ascii_case("MozillaCompositorWindowClass")
        });
    !is_doc_or_renderer
        && matches!(
            control_type,
            UIA_CUSTOM_CONTROL_TYPE | UIA_GROUP_CONTROL_TYPE | UIA_PANE_CONTROL_TYPE
        )
        && matches!(ax_role, None | Some("AXGroup" | "AXScrollArea"))
}

fn is_allowed_menu_bar_wrapper(meta: &UiaElementMetadata) -> bool {
    !is_document_or_renderer_host(meta)
        && is_allowed_menu_bar_wrapper_fields(
            meta.control_type,
            meta.mapped.ax_role,
            meta.class_name.as_deref(),
        )
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

    let mut title = preferred_meta_title(meta);

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
                let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
                if rem <= 0 {
                    return None;
                }
                uia.apply_timeouts(rem);
                if !uia.compare_elements(&parent, expected_bar) {
                    return None;
                }
            }
            if !menu_bar_belongs_to_window(
                uia,
                &parent,
                &pmeta,
                bound.hwnd,
                expected_pid,
                raw_pid,
                bound.is_browser,
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
                    title = preferred_meta_title(&pmeta);
                }
                cur = parent;
                continue;
            }
            return None;
        }
        if !is_allowed_menu_bar_wrapper(&pmeta) {
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

fn walk_handles_same(
    uia: &UiaClient,
    a: &WalkHandle,
    b: &WalkHandle,
    deadline_ms: i64,
    clock: &dyn CollectorClock,
) -> bool {
    if !a.runtime_id.is_empty() && !b.runtime_id.is_empty() {
        return a.runtime_id == b.runtime_id;
    }
    let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
    if rem <= 0 {
        return false;
    }
    uia.apply_timeouts(rem);
    uia.compare_elements(&a.elem, &b.elem)
}

#[allow(clippy::too_many_arguments)]
fn menu_bar_belongs_to_window(
    uia: &UiaClient,
    bar_elem: &IUIAutomationElement,
    bar_meta: &UiaElementMetadata,
    bound_hwnd: HWND,
    expected_pid: u32,
    raw_pid: u32,
    is_browser: bool,
    dpi: u32,
    deadline_ms: i64,
    clock: &dyn CollectorClock,
) -> bool {
    if bound_hwnd.0.is_null() {
        return false;
    }
    let pid_matches = |pid: u32| {
        pid > 0 && (pid == expected_pid || (raw_pid > 0 && pid == raw_pid))
    };
    let is_safe_node = |m: &UiaElementMetadata| {
        pid_matches(m.process_id)
            && !m.is_sensitive()
            && TextSecurityGate::may_traverse(&m.subrole_read, m.is_password)
            && !m
                .automation_id
                .as_deref()
                .is_some_and(|aid| aid.eq_ignore_ascii_case("SystemMenuBar"))
            && (!is_browser || !is_document_or_renderer_host(m))
    };
    if !is_safe_node(bar_meta) {
        return false;
    }
    let check_native_hwnd = |native: HWND| -> Result<bool, ()> {
        if is_browser
            && native != bound_hwnd
            && window_class_name(native).as_deref().is_some_and(|c| {
                c.eq_ignore_ascii_case("Chrome_RenderWidgetHostHWND")
                    || c.eq_ignore_ascii_case("MozillaCompositorWindowClass")
            })
        {
            return Err(());
        }
        if native == bound_hwnd {
            return Ok(true);
        }
        // SAFETY: Standard Win32 root ancestor check.
        Ok(unsafe { GetAncestor(native, GA_ROOT) } == bound_hwnd)
    };

    let mut matched_window = false;
    if let Some(native) = bar_meta.native_hwnd {
        match check_native_hwnd(native) {
            Ok(true) => {
                matched_window = true;
                if !is_browser && native == bound_hwnd {
                    return true;
                }
            }
            Ok(false) => {}
            Err(()) => return false,
        }
    }
    // Walk up to `MAX_MENU_BAR_WINDOW_HOPS` (20) ancestors verifying PID, sensitivity,
    // `may_traverse`, non-`SystemMenuBar`, and (for browsers) rejecting `Document (50030)` /
    // `AXWebArea` / `AXDocument` / renderer HWNDs at EVERY hop until reaching `Window
    // (bound_hwnd)` or Desktop root.
    let mut cur = bar_elem.clone();
    for _ in 0..MAX_MENU_BAR_WINDOW_HOPS {
        let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
        if rem <= 0 {
            return false;
        }
        uia.apply_timeouts(rem);
        let parent = match uia.parent_element(&cur) {
            Ok(Some(p)) => p,
            Ok(None) => return matched_window,
            Err(_) => return false,
        };
        if uia.is_root_desktop_element(&parent) {
            return matched_window;
        }
        let Ok(pmeta) = uia.read_cached_metadata(&parent, dpi, false, false) else {
            return false;
        };
        if !is_safe_node(&pmeta) {
            return false;
        }
        if let Some(native) = pmeta.native_hwnd {
            match check_native_hwnd(native) {
                Ok(true) => {
                    matched_window = true;
                    if !is_browser {
                        return true;
                    }
                    if pmeta.control_type == UIA_WINDOW_CONTROL_TYPE && native == bound_hwnd {
                        return true;
                    }
                }
                Ok(false) => {}
                Err(()) => return false,
            }
        }
        cur = parent;
    }
    false
}

/// Verifies ONCE that a reached `MenuBar (50010)` belongs to `bound_hwnd` (reused as the custom
/// `bar_verifier` for `MenuPathResolver::resolve_with_bar_verifier` and
/// `classify_opened_menu_with_bar_verifier` so the `MenuBar -> Window` COM walk never duplicates).
#[allow(clippy::too_many_arguments)]
fn verify_walk_menu_bar_owner(
    uia: &UiaClient,
    handle: &WalkHandle,
    bound_hwnd: HWND,
    expected_pid: u32,
    raw_pid: u32,
    is_browser: bool,
    dpi: u32,
    deadline_ms: i64,
    clock: &dyn CollectorClock,
) -> bool {
    let meta = match handle.cached_meta {
        Some(ref cached) => cached.clone(),
        None => {
            let rem = deadline_ms.saturating_sub(clock.monotonic_ms());
            if rem <= 0 {
                return false;
            }
            uia.apply_timeouts(rem);
            let Ok(refreshed) = uia.refresh_metadata(&handle.elem) else {
                return false;
            };
            let Ok(m) = uia.read_cached_metadata(&refreshed, dpi, false, false) else {
                return false;
            };
            m
        }
    };
    menu_bar_belongs_to_window(
        uia,
        &handle.elem,
        &meta,
        bound_hwnd,
        expected_pid,
        raw_pid,
        is_browser,
        dpi,
        deadline_ms,
        clock,
    )
}

fn inspect_walk_handle(
    uia: &UiaClient,
    handle: &WalkHandle,
    is_leaf: bool,
    dpi: u32,
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

    let (child_count, is_submenu_opener) = if is_leaf {
        if let Some(precomputed) = handle.precomputed_leaf_checks {
            precomputed
        } else {
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
        }
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
    is_browser: bool,
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

    let raw_pid = raw_host_pid.unwrap_or(0);
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

    MenuPathResolver::resolve_with_bar_verifier(
        leaf_handle,
        expected_pid,
        raw_host_pid,
        bar_handle.as_ref(),
        None,
        win32_link,
        !is_browser,
        |a, b| walk_handles_same(uia, a, b, deadline_ms, clock),
        |handle, is_leaf| inspect_walk_handle(uia, handle, is_leaf, dpi, deadline_ms, clock),
        |handle| parent_walk_handle(uia, handle, dpi, deadline_ms, clock),
        |bar_handle| {
            verify_walk_menu_bar_owner(
                uia,
                bar_handle,
                bound_hwnd,
                expected_pid,
                raw_pid,
                is_browser,
                dpi,
                deadline_ms,
                clock,
            )
        },
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
    is_browser: bool,
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
        is_browser,
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
        false,
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

    fn mk_win_ev_qpc(kind: WinMenuEventKind, hwnd_raw: isize, qpc_ns: u64) -> WinMenuEvent {
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
            observed_qpc_ns: qpc_ns,
            observed_mono_ms: 1_000,
            observed_unix_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn poll_planner_merges_by_qpc_prevents_blank_click_commit_and_coalesces_focus() {
        // 1. Blank-area click: PopupEnd (qpc=200) and MenuEnd (qpc=205) fired on WM_LBUTTONDOWN,
        // followed by LeftButtonUp (qpc=250). LeftButtonUp MUST run AFTER PopupEnd & MenuEnd!
        let blank_click_win = [
            mk_win_ev_qpc(WinMenuEventKind::FocusChanged, 0x10, 100),
            mk_win_ev_qpc(WinMenuEventKind::PopupEnd, 0x10, 200),
            mk_win_ev_qpc(WinMenuEventKind::MenuEnd, 0x1, 205),
        ];
        let blank_click_sigs = [MenuCommitSignal::LeftButtonUp {
            qpc_ns: 250,
            unix_ms: 1_700_000_000_250,
        }];
        assert_eq!(
            plan_merged_poll_events(&blank_click_win, &[], &blank_click_sigs),
            vec![
                MergedPollEvent::WinEvent(0),
                MergedPollEvent::WinEvent(1),
                MergedPollEvent::WinEvent(2),
                MergedPollEvent::CommitSignal(0),
            ],
            "LeftButtonUp with qpc_ns > PopupEnd.observed_qpc_ns MUST NEVER flush ahead of PopupEnd"
        );

        // 2. Real menu item click: LeftButtonUp / Invoked with qpc_ns <= PopupEnd.observed_qpc_ns
        // flushes strictly AHEAD of PopupEnd / MenuEnd!
        let item_click_win = [
            mk_win_ev_qpc(WinMenuEventKind::FocusChanged, 0x10, 100),
            mk_win_ev_qpc(WinMenuEventKind::PopupEnd, 0x10, 200),
            mk_win_ev_qpc(WinMenuEventKind::MenuEnd, 0x1, 205),
        ];
        let item_click_uia = [(Some(UiaMenuEventKind::Invoked), 200)];
        let item_click_sigs = [MenuCommitSignal::LeftButtonUp {
            qpc_ns: 200,
            unix_ms: 1_700_000_000_200,
        }];
        assert_eq!(
            plan_merged_poll_events(&item_click_win, &item_click_uia, &item_click_sigs),
            vec![
                MergedPollEvent::WinEvent(0),
                MergedPollEvent::UiaEvent(0),
                MergedPollEvent::CommitSignal(0),
                MergedPollEvent::WinEvent(1),
                MergedPollEvent::WinEvent(2),
            ],
            "Invoked and LeftButtonUp with qpc_ns <= PopupEnd MUST flush ahead of PopupEnd"
        );

        // 3. Horizontal glide `File -> Edit` in a single 5ms batch preserves trailing events.
        let glide = [
            mk_win_ev_qpc(WinMenuEventKind::PopupEnd, 0x10, 100),
            mk_win_ev_qpc(WinMenuEventKind::FocusChanged, 0x11, 110),
            mk_win_ev_qpc(WinMenuEventKind::PopupStart, 0x20, 120),
        ];
        assert_eq!(
            plan_merged_poll_events(&glide, &[], &[]),
            vec![
                MergedPollEvent::WinEvent(0),
                MergedPollEvent::WinEvent(1),
                MergedPollEvent::WinEvent(2),
            ],
            "PopupEnd must NEVER drop trailing FocusChanged or PopupStart events"
        );

        // 4. Consecutive uninterrupted `FocusChanged` bursts coalesce to the latest index while
        // preserving exact ordering around `PopupEnd` / `PopupStart`.
        let focus_burst = [
            mk_win_ev_qpc(WinMenuEventKind::FocusChanged, 0x10, 100),
            mk_win_ev_qpc(WinMenuEventKind::FocusChanged, 0x11, 101),
            mk_win_ev_qpc(WinMenuEventKind::FocusChanged, 0x12, 102),
            mk_win_ev_qpc(WinMenuEventKind::PopupEnd, 0x12, 105),
            mk_win_ev_qpc(WinMenuEventKind::FocusChanged, 0x20, 110),
            mk_win_ev_qpc(WinMenuEventKind::FocusChanged, 0x21, 111),
            mk_win_ev_qpc(WinMenuEventKind::PopupStart, 0x30, 115),
        ];
        assert_eq!(
            plan_merged_poll_events(&focus_burst, &[], &[]),
            vec![
                MergedPollEvent::WinEvent(2),
                MergedPollEvent::WinEvent(3),
                MergedPollEvent::WinEvent(5),
                MergedPollEvent::WinEvent(6),
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

        session.apply_uia_menu_closed(
            None,
            Some(MenuHandleKey::RuntimeId(RuntimeIdKey(vec![42, 7]))),
            5_020,
            None,
        );
        assert!(!session.tracking.is_tracking());
        assert!(!session.menu_open_flag.load(Ordering::Acquire));
        assert_eq!(session.current_win32_link(5_030), None);

        // 2. `MenuCommitSignal::Escape` MUST fully disarm `ActiveMenuBarLink` + tracking (not just
        // clear volatile highlight) so `File -> Esc -> right-click` cannot leak `["File", ...]`.
        let _uia_lock = crate::uia_com::acquire_test_mta_uia_lock();
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
        session.handle_commit_signal(&uia, &registry, esc, 250, now_mono + 120, &clock);
        assert!(!session.tracking.is_tracking());
        assert!(!session.menu_open_flag.load(Ordering::Acquire));
        assert_eq!(session.current_win32_link(now_mono + 10), None);

        // 3. `MenuCommitSignal::Cancel` (`WM_RBUTTONDOWN`) and `DisarmNonMenuBar` MUST also fully
        // disarm `ActiveMenuBarLink` + tracking!
        session.win32.on_verified_menu_bar_item("Edit".to_string(), now_mono);
        let open_tr = session
            .tracking
            .menu_opened(MenuHandleKey::Win32MenuBar(0x100), true);
        session.apply_tracking_change(open_tr.tracking_changed, now_mono);
        let cancel = MenuCommitSignal::Cancel {
            qpc_ns: 210,
            unix_ms: clock.unix_ms(),
        };
        session.handle_commit_signal(&uia, &registry, cancel, 250, now_mono + 120, &clock);
        assert!(!session.tracking.is_tracking());
        assert!(!session.menu_open_flag.load(Ordering::Acquire));
        assert_eq!(session.current_win32_link(now_mono + 10), None);

        session.win32.on_verified_menu_bar_item("View".to_string(), now_mono);
        let open_tr = session
            .tracking
            .menu_opened(MenuHandleKey::Win32MenuBar(0x100), true);
        session.apply_tracking_change(open_tr.tracking_changed, now_mono);
        session.handle_win_close_or_switch(
            &uia,
            mk_win_ev_qpc(WinMenuEventKind::DisarmNonMenuBar, 0x100, 300),
            now_mono + 120,
            &clock,
        );
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

        // 2. Focus moves to non-menu element (`AXTextArea`): `clear_tracking_state(None, true, None)` runs.
        session.clear_tracking_state(None, true, None);
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

    #[test]
    fn winui3_slide_over_focus_before_popup_end_preserves_new_bar_item() {
        // P2-9: WinUI 3 / Electron slide-over order `[FocusChanged(Edit), PopupEnd(File), PopupStart(Edit)]`
        // with `!from_objid_menu` MUST preserve `"Edit"` when File's superseded popup closes!
        let mut s = Win32MenuBarState::default();
        s.on_verified_menu_bar_item("File".to_string(), 1_000);
        assert!(!s.from_objid_menu);
        s.on_popup_start(0x10, None, 1_010);
        assert_eq!(s.current_link(1_020).unwrap().menu_bar_item_title, "File");

        // User glides horizontally onto `"Edit"` BEFORE File's popup (0x10) sends PopupEnd.
        s.on_verified_menu_bar_item("Edit".to_string(), 1_030);
        assert_eq!(s.current_link(1_035).unwrap().menu_bar_item_title, "Edit");

        // File's superseded popup closes -> MUST return false and NOT wipe `"Edit"`!
        assert!(
            !s.on_popup_end(0x10),
            "closing superseded File popup during WinUI 3 slide-over must NOT disarm Edit"
        );
        assert!(s.active);
        assert_eq!(s.current_link(1_040).unwrap().menu_bar_item_title, "Edit");

        // Edit's new popup (0x20) opens and owns `"Edit"`.
        s.on_popup_start(0x20, None, 1_050);
        assert_eq!(s.current_link(1_060).unwrap().menu_bar_item_title, "Edit");
        assert_eq!(s.last_popup_hwnd(), Some(0x20));

        // Closing Edit's active popup (0x20) MUST disarm cleanly and return true.
        assert!(s.on_popup_end(0x20));
        assert!(!s.active);
        assert_eq!(s.current_link(1_070), None);
    }

    #[test]
    fn dropped_commit_signals_fail_closed_and_clear_tracking_in_poll() {
        use crate::protocol_model::SystemCollectorClock;
        use crate::uia_com::ComGuard;

        // P2-6: Non-zero dropped signal count at start of `poll()` MUST fail closed, clear
        // tracking/link state, and emit `menuTracking: false`.
        let _uia_lock = crate::uia_com::acquire_test_mta_uia_lock();
        let _com = ComGuard::init_mta().expect("MTA COM init");
        let uia = UiaClient::new().expect("UiaClient::new");
        let registry = AdapterRegistry::new();
        let clock = SystemCollectorClock;
        let now_mono = clock.monotonic_ms();

        let mut session = MenuActionSession::new();
        session.enabled = true;
        session.ensure_commit_hook();
        assert!(
            session.commit_hook.is_some(),
            "MenuCommitHook must install in test"
        );

        session.win32.on_verified_menu_bar_item("File".to_string(), now_mono);
        let open_tr = session
            .tracking
            .menu_opened(MenuHandleKey::Win32MenuBar(0x200), true);
        session.apply_tracking_change(open_tr.tracking_changed, now_mono);
        assert_eq!(session.take_menu_tracking(), Some(true));
        assert!(session.tracking.is_tracking());

        session
            .commit_hook
            .as_ref()
            .unwrap()
            .inject_dropped_menu_signals_for_test(2);
        session.poll(&uia, &registry, Vec::new(), false, &clock);

        assert!(
            !session.tracking.is_tracking(),
            "dropped commit signal counter > 0 MUST clear menu tracking fail-closed"
        );
        assert!(!session.menu_open_flag.load(Ordering::Acquire));
        assert_eq!(session.current_win32_link(now_mono + 10), None);
        assert_eq!(session.take_menu_tracking(), Some(false));
        session.retire_for_process_exit();
    }

    #[test]
    fn active_open_handles_classify_detached_winui3_nested_submenu() {
        use crate::policy::{ProtectedContentRead, SubroleRead};

        // P1-7: Detached WinUI 3 nested submenu (`View -> Zoom -> Zoom In`) where both `View`
        // (id=10) and `Zoom` (id=20) flyout `Menu` nodes are parented to `Window` (id=99).
        let link = Win32MenuBarLink {
            menu_bar_item_title: "View".to_string(),
            submenu_titles: Vec::new(),
            from_menu_bar_start: true,
        };
        let mk_menu = || MenuNodeSnapshot {
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
        };
        let win_node = MenuNodeSnapshot {
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
        };
        let inspect = |id: &usize| match *id {
            10 | 20 => Some(mk_menu()),
            99 => Some(win_node.clone()),
            _ => None,
        };
        let parent = |id: &usize| match *id {
            10 | 20 => Some(99usize),
            _ => None,
        };

        // 1. With no open handles yet, `View` (10) classifies as TopLevel.
        assert_eq!(
            MenuPathResolver::classify_opened_menu_with_policy(
                10usize,
                42,
                None,
                None,
                None,
                Some(&link),
                &[],
                true,
                |a, b| a == b,
                inspect,
                parent,
                || true,
            ),
            Some(OpenedMenuKind::TopLevel)
        );

        // 2. With `View` (10) retained in active `open_handles`, detached `Zoom` (20) classifies
        // strictly as `OpenedMenuKind::Submenu` instead of `TopLevel`!
        let open_handles = [10usize];
        assert_eq!(
            MenuPathResolver::classify_opened_menu_with_policy(
                20usize,
                42,
                None,
                None,
                None,
                Some(&link),
                &open_handles,
                true,
                |a, b| a == b,
                inspect,
                parent,
                || true,
            ),
            Some(OpenedMenuKind::Submenu),
            "detached WinUI 3 nested submenu MUST classify as Submenu when open_handles is non-empty"
        );
    }

    #[test]
    fn p1_4_old_escape_and_cancel_still_disarm_while_old_commits_are_dropped() {
        use crate::protocol_model::SystemCollectorClock;
        use crate::uia_com::ComGuard;

        let _uia_lock = crate::uia_com::acquire_test_mta_uia_lock();
        let _com = ComGuard::init_mta().expect("MTA COM init");
        let uia = UiaClient::new().expect("UiaClient::new");
        let registry = AdapterRegistry::new();
        let clock = SystemCollectorClock;
        let now_mono = clock.monotonic_ms();

        let arm_with_highlight = |session: &mut MenuActionSession| {
            session.win32.on_verified_menu_bar_item("File".to_string(), now_mono);
            let tr = session
                .tracking
                .menu_opened(MenuHandleKey::Win32MenuBar(0x100), true);
            session.apply_tracking_change(tr.tracking_changed, now_mono);
            session.tracking.update_selection(
                Some(ResolvedMenuPath {
                    path: vec!["File".to_string(), "Save".to_string()],
                    truncated: false,
                }),
                MenuHandleKey::Win32MenuBar(0x100),
                now_mono,
            );
            session.accept_after_qpc_ns = 1_000_000_000;
        };

        let mut session = MenuActionSession::new();
        let now_qpc = 2_000_000_000u64;
        // 500ms old (> 200ms MAX_COMMIT_SIGNAL_AGE_NS), strictly after accept_after_qpc_ns.
        let old_qpc = now_qpc - 500_000_000;
        // Future relative to sampled `now_qpc`, strictly after accept_after_qpc_ns.
        let future_qpc = now_qpc + 10_000_000;

        // 1. >200ms old `Escape` MUST still disarm `Win32MenuBarState` + `tracking`.
        arm_with_highlight(&mut session);
        session.handle_commit_signal(
            &uia,
            &registry,
            MenuCommitSignal::Escape {
                qpc_ns: old_qpc,
                unix_ms: clock.unix_ms(),
            },
            now_qpc,
            now_mono + 120,
            &clock,
        );
        assert!(!session.tracking.is_tracking());
        assert_eq!(session.current_win32_link(now_mono + 10), None);

        // 2. >200ms old `Cancel` (`WM_RBUTTONDOWN`) MUST still disarm.
        arm_with_highlight(&mut session);
        session.handle_commit_signal(
            &uia,
            &registry,
            MenuCommitSignal::Cancel {
                qpc_ns: old_qpc,
                unix_ms: clock.unix_ms(),
            },
            now_qpc,
            now_mono + 120,
            &clock,
        );
        assert!(!session.tracking.is_tracking());
        assert_eq!(session.current_win32_link(now_mono + 10), None);

        // 3. `Escape` / `Cancel` with `sig_qpc > now_qpc_ns` MUST still disarm.
        for sig in [
            MenuCommitSignal::Escape {
                qpc_ns: future_qpc,
                unix_ms: clock.unix_ms(),
            },
            MenuCommitSignal::Cancel {
                qpc_ns: future_qpc,
                unix_ms: clock.unix_ms(),
            },
        ] {
            arm_with_highlight(&mut session);
            session.handle_commit_signal(&uia, &registry, sig, now_qpc, now_mono + 120, &clock);
            assert!(!session.tracking.is_tracking());
            assert_eq!(session.current_win32_link(now_mono + 10), None);
        }

        // 4. Stale `Escape` / `Cancel` BEFORE or AT `accept_after_qpc_ns` MUST be ignored.
        arm_with_highlight(&mut session);
        session.handle_commit_signal(
            &uia,
            &registry,
            MenuCommitSignal::Escape {
                qpc_ns: session.accept_after_qpc_ns,
                unix_ms: clock.unix_ms(),
            },
            now_qpc,
            now_mono + 120,
            &clock,
        );
        assert!(session.tracking.is_tracking());
        assert!(session.current_win32_link(now_mono + 10).is_some());

        // 5. >200ms old and future `LeftButtonUp` / `Return` MUST still be dropped (highlight
        //    preserved, nothing committed/enqueued).
        for sig in [
            MenuCommitSignal::LeftButtonUp {
                qpc_ns: old_qpc,
                unix_ms: clock.unix_ms(),
            },
            MenuCommitSignal::Return {
                qpc_ns: old_qpc,
                unix_ms: clock.unix_ms(),
            },
            MenuCommitSignal::LeftButtonUp {
                qpc_ns: future_qpc,
                unix_ms: clock.unix_ms(),
            },
            MenuCommitSignal::Return {
                qpc_ns: future_qpc,
                unix_ms: clock.unix_ms(),
            },
        ] {
            arm_with_highlight(&mut session);
            session.handle_commit_signal(&uia, &registry, sig, now_qpc, now_mono + 120, &clock);
            assert!(
                session.tracking.has_selection(),
                "stale/future commit signal {sig:?} MUST be dropped without consuming selection"
            );
            assert!(session.take_next_record().is_none());
        }
    }

    #[test]
    fn p1_5_open_uia_menus_eviction_sync_and_classic_win32_slide_over_keeps_edit_top_level() {
        use crate::policy::{ProtectedContentRead, SubroleRead};
        use crate::protocol_model::SystemCollectorClock;
        use crate::uia_com::ComGuard;

        let _uia_lock = crate::uia_com::acquire_test_mta_uia_lock();
        let _com = ComGuard::init_mta().expect("MTA COM init");
        let uia = UiaClient::new().expect("UiaClient::new");
        // SAFETY: Read-only MTA COM root element lookup for unit-test handle cloning.
        let root_el = unsafe { uia.automation().GetRootElement() }.expect("desktop root element");
        let clock = SystemCollectorClock;
        let now_mono = clock.monotonic_ms();

        // 1. Capacity-8 eviction sync: opening 9 nested menus MUST evict R0 from BOTH `tracking`
        //    and `open_uia_menus` and keep R8 in BOTH!
        let mut session = MenuActionSession::new();
        for i in 0..MAX_OPEN_MENUS {
            let rid = RuntimeIdKey(vec![100, i as i32]);
            let key = MenuHandleKey::RuntimeId(rid.clone());
            let _ = session.tracking.menu_opened(key.clone(), i == 0);
            session.record_open_uia_menu(key, root_el.clone(), rid, i == 0);
        }
        assert_eq!(session.tracking.open_menus().len(), MAX_OPEN_MENUS);
        assert_eq!(session.open_uia_menus.len(), MAX_OPEN_MENUS);

        let rid8 = RuntimeIdKey(vec![100, 8]);
        let key8 = MenuHandleKey::RuntimeId(rid8.clone());
        let _ = session.tracking.menu_opened(key8.clone(), false);
        session.record_open_uia_menu(key8.clone(), root_el.clone(), rid8, false);

        assert_eq!(session.tracking.open_menus().len(), MAX_OPEN_MENUS);
        assert_eq!(session.open_uia_menus.len(), MAX_OPEN_MENUS);
        assert!(
            !session
                .open_uia_menus
                .iter()
                .any(|e| e.key == MenuHandleKey::RuntimeId(RuntimeIdKey(vec![100, 0]))),
            "evicted R0 MUST be removed from open_uia_menus"
        );
        assert!(
            session.open_uia_menus.iter().any(|e| e.key == key8),
            "newly opened R8 MUST be present in open_uia_menus"
        );
        for entry in &session.open_uia_menus {
            assert!(session.tracking.open_menus().contains(&entry.key));
        }

        // Opening a nested PopupStart (`Hwnd`) at capacity 8 evicts R1 from `tracking` AND syncs
        // `open_uia_menus` so R1 is evicted from `open_uia_menus` too.
        session.win32.on_menu_bar_start(now_mono);
        session.win32.on_popup_start(0x10, Some("File".to_string()), now_mono);
        session.apply_verified_popup_start(0x11, Some("Sub".to_string()), now_mono + 5);
        assert!(
            !session
                .open_uia_menus
                .iter()
                .any(|e| e.key == MenuHandleKey::RuntimeId(RuntimeIdKey(vec![100, 1]))),
            "PopupStart eviction at capacity 8 MUST sync open_uia_menus"
        );
        for entry in &session.open_uia_menus {
            assert!(session.tracking.open_menus().contains(&entry.key));
        }

        // 2. Classic Win32 `"File" -> "Edit"` slide-over: `PopupEnd(P1)` empties `popup_stack`
        //    with `MenuClosed(R1)` suppressed after popup UIA detach. `open_uia_menus` and stale
        //    `RuntimeId(R1)` MUST be cleared so `"Edit"` (`R2`) classifies as `TopLevel`!
        let mut s = MenuActionSession::new();
        s.win32.on_menu_bar_start(now_mono);
        let tr = s
            .tracking
            .menu_opened(MenuHandleKey::Win32MenuBar(0x1000), true);
        s.apply_tracking_change(tr.tracking_changed, now_mono);
        s.apply_verified_popup_start(0x2001, Some("File".to_string()), now_mono + 10);
        let r1 = RuntimeIdKey(vec![42, 1]);
        let r1_key = MenuHandleKey::RuntimeId(r1.clone());
        let tr_r1 = s.tracking.menu_opened(r1_key.clone(), true);
        s.record_open_uia_menu(r1_key.clone(), root_el.clone(), r1, true);
        s.apply_tracking_change(tr_r1.tracking_changed, now_mono + 15);
        assert_eq!(s.open_uia_menus.len(), 1);

        // `PopupEnd(File)` fires and empties `win32.popup_stack` (suppressed `MenuClosed(R1)`).
        s.handle_win_close_or_switch(
            &uia,
            mk_win_ev_qpc(WinMenuEventKind::PopupEnd, 0x2001, 500),
            now_mono + 120,
            &clock,
        );
        assert!(
            s.open_uia_menus.is_empty(),
            "PopupEnd emptying popup_stack MUST clear open_uia_menus"
        );
        assert!(
            !s.tracking
                .open_menus()
                .iter()
                .any(|k| matches!(k, MenuHandleKey::RuntimeId(_))),
            "PopupEnd emptying popup_stack MUST clear stale RuntimeId open menus from tracking"
        );
        assert!(s.win32.is_active(now_mono + 20));

        // `PopupStart(Edit)` opens a new top-level popup.
        s.apply_verified_popup_start(0x2002, Some("Edit".to_string()), now_mono + 25);
        assert!(s.open_uia_menus.is_empty());
        assert_eq!(
            s.current_win32_link(now_mono + 30)
                .map(|l| l.menu_bar_item_title),
            Some("Edit".to_string())
        );

        // Classify `"Edit"` detached popup `Menu` against `s.open_uia_menus` (empty!) -> `TopLevel`!
        let edit_link = s.current_win32_link(now_mono + 30).expect("Edit link");
        let edit_menu_node = MenuNodeSnapshot {
            pid: 42,
            control_type: Some(UIA_MENU_CONTROL_TYPE),
            role: Some("AXMenu".to_string()),
            subrole: SubroleRead::NoValue,
            protected_content: ProtectedContentRead::Value(false),
            enabled: Some(true),
            title: Some("Edit".to_string()),
            description: None,
            automation_id: None,
            class_name: Some("#32768".to_string()),
            child_count: None,
            is_submenu_opener: None,
        };
        let open_ids: Vec<usize> = s.open_uia_menus.iter().enumerate().map(|(i, _)| i + 100).collect();
        let edit_kind = MenuPathResolver::classify_opened_menu_with_policy(
            2usize,
            42,
            None,
            None,
            None,
            Some(&edit_link),
            &open_ids,
            true,
            |a, b| a == b,
            |_| Some(edit_menu_node.clone()),
            |_| None,
            || true,
        );
        assert_eq!(
            edit_kind,
            Some(OpenedMenuKind::TopLevel),
            "classic Win32 'File' -> 'Edit' slide-over MUST keep 'Edit' classified as TopLevel"
        );

        // 3. Even if `PopupStart(Edit)` arrives on a top-level transition (`bar_item_owner_popup
        //    == None`) while stale `R1` is still in `open_uia_menus` / `tracking`, `PopupStart`
        //    clears `open_uia_menus` and stale `R1` so `"Edit"` stays `TopLevel`!
        let r_stale = RuntimeIdKey(vec![42, 99]);
        let r_stale_key = MenuHandleKey::RuntimeId(r_stale.clone());
        let _ = s.tracking.menu_opened(r_stale_key.clone(), true);
        s.record_open_uia_menu(r_stale_key, root_el, r_stale, true);
        s.win32.on_verified_menu_bar_item("View".to_string(), now_mono + 40);
        s.apply_verified_popup_start(0x2003, Some("View".to_string()), now_mono + 45);
        assert!(s.open_uia_menus.is_empty());
        assert!(!s
            .tracking
            .open_menus()
            .iter()
            .any(|k| matches!(k, MenuHandleKey::RuntimeId(_))));
    }

    #[test]
    fn p2_1_poll_planner_preserves_equal_qpc_intra_stream_fifo_and_cross_stream_rank() {
        // 1. Equal-QPC `[PopupEnd(File), PopupStart(Edit)]` MUST preserve intra-stream FIFO order!
        let slide = [
            mk_win_ev_qpc(WinMenuEventKind::PopupEnd, 0x10, 500),
            mk_win_ev_qpc(WinMenuEventKind::PopupStart, 0x20, 500),
        ];
        assert_eq!(
            plan_merged_poll_events(&slide, &[], &[]),
            vec![MergedPollEvent::WinEvent(0), MergedPollEvent::WinEvent(1)],
            "equal-QPC [PopupEnd, PopupStart] MUST NEVER invert intra-stream FIFO order"
        );

        // 2. Equal-QPC `[MenuEnd, MenuBarStart]` MUST preserve intra-stream FIFO order!
        let restart = [
            mk_win_ev_qpc(WinMenuEventKind::MenuEnd, 0x1, 700),
            mk_win_ev_qpc(WinMenuEventKind::MenuBarStart, 0x1, 700),
        ];
        assert_eq!(
            plan_merged_poll_events(&restart, &[], &[]),
            vec![MergedPollEvent::WinEvent(0), MergedPollEvent::WinEvent(1)],
            "equal-QPC [MenuEnd, MenuBarStart] MUST NEVER invert intra-stream FIFO order"
        );

        // 3. Equal-QPC `[MenuClosed, MenuOpened]` in UIA stream preserves intra-stream FIFO order.
        let uia_pair = [
            (Some(UiaMenuEventKind::MenuClosed), 800),
            (Some(UiaMenuEventKind::MenuOpened), 800),
        ];
        assert_eq!(
            plan_merged_poll_events(&[], &uia_pair, &[]),
            vec![MergedPollEvent::UiaEvent(0), MergedPollEvent::UiaEvent(1)]
        );

        // 4. Cross-stream equal-QPC ties STILL honor `rank` (Invoked rank 4 < LeftButtonUp rank 5
        //    < PopupEnd rank 7), while `PopupStart` queued behind `PopupEnd` stays AFTER `PopupEnd`!
        let cross_win = [
            mk_win_ev_qpc(WinMenuEventKind::PopupEnd, 0x10, 900),
            mk_win_ev_qpc(WinMenuEventKind::PopupStart, 0x20, 900),
        ];
        let cross_uia = [(Some(UiaMenuEventKind::Invoked), 900)];
        let cross_sig = [MenuCommitSignal::LeftButtonUp {
            qpc_ns: 900,
            unix_ms: 1_700_000_000_900,
        }];
        assert_eq!(
            plan_merged_poll_events(&cross_win, &cross_uia, &cross_sig),
            vec![
                MergedPollEvent::UiaEvent(0),
                MergedPollEvent::CommitSignal(0),
                MergedPollEvent::WinEvent(0),
                MergedPollEvent::WinEvent(1),
            ],
            "cross-stream equal-QPC ties must honor rank while preserving intra-stream FIFO"
        );
    }

    #[test]
    fn p2_5_dropped_win_events_fail_closed_and_wrapper_whitelist_matches_core() {
        use crate::protocol_model::SystemCollectorClock;
        use crate::uia_com::ComGuard;

        // 1. `win_events_dropped = true` triggers fail-closed reset in `poll()`.
        let _uia_lock = crate::uia_com::acquire_test_mta_uia_lock();
        let _com = ComGuard::init_mta().expect("MTA COM init");
        let uia = UiaClient::new().expect("UiaClient::new");
        let registry = AdapterRegistry::new();
        let clock = SystemCollectorClock;
        let now_mono = clock.monotonic_ms();

        let mut session = MenuActionSession::new();
        session.enabled = true;
        session.win32.on_verified_menu_bar_item("File".to_string(), now_mono);
        let open_tr = session
            .tracking
            .menu_opened(MenuHandleKey::Win32MenuBar(0x300), true);
        session.apply_tracking_change(open_tr.tracking_changed, now_mono);
        assert_eq!(session.take_menu_tracking(), Some(true));

        session.poll(
            &uia,
            &registry,
            vec![mk_win_ev_qpc(WinMenuEventKind::FocusChanged, 0x300, 100)],
            true,
            &clock,
        );
        assert!(!session.tracking.is_tracking());
        assert!(!session.menu_open_flag.load(Ordering::Acquire));
        assert_eq!(session.current_win32_link(now_mono + 10), None);
        assert_eq!(session.take_menu_tracking(), Some(false));

        // 2. `detect_verified_menu_bar_item` intermediate wrapper role whitelist: allows ONLY
        //    Custom/Group/Pane with `None | Some("AXGroup" | "AXScrollArea")` and non-renderer class.
        for ct in [
            UIA_CUSTOM_CONTROL_TYPE,
            UIA_GROUP_CONTROL_TYPE,
            UIA_PANE_CONTROL_TYPE,
        ] {
            assert!(is_allowed_menu_bar_wrapper_fields(ct, None, None));
            assert!(is_allowed_menu_bar_wrapper_fields(ct, Some("AXGroup"), None));
            assert!(is_allowed_menu_bar_wrapper_fields(
                ct,
                Some("AXScrollArea"),
                None
            ));
            for bad_role in [
                "AXHeading",
                "AXToolbar",
                "AXButton",
                "AXDialog",
                "AXWebArea",
                "AXDocument",
                "AXWindow",
                "AXTextField",
                "AXSecureTextField",
            ] {
                assert!(
                    !is_allowed_menu_bar_wrapper_fields(ct, Some(bad_role), None),
                    "ct={ct} role={bad_role} must be rejected"
                );
            }
            for bad_cls in ["Chrome_RenderWidgetHostHWND", "MozillaCompositorWindowClass"] {
                assert!(
                    !is_allowed_menu_bar_wrapper_fields(ct, Some("AXGroup"), Some(bad_cls)),
                    "renderer host {bad_cls} must be rejected"
                );
            }
        }
        assert!(!is_allowed_menu_bar_wrapper_fields(
            UIA_BUTTON_CONTROL_TYPE,
            Some("AXGroup"),
            None
        ));
    }

    #[test]
    fn p2_7_expired_deadline_abandons_subscriptions_locally_in_reset_and_disable() {
        use crate::protocol_model::SystemCollectorClock;
        use crate::uia_com::ComGuard;

        let _uia_lock = crate::uia_com::acquire_test_mta_uia_lock();
        let _com = ComGuard::init_mta().expect("MTA COM init");
        let uia = UiaClient::new().expect("UiaClient::new");
        let clock = SystemCollectorClock;
        let now_mono = clock.monotonic_ms();

        // Expired deadline (`now_mono - 1`): `reset_for_boundary` and `disable` abandon locally
        // instead of blocking on synchronous `RemoveAutomationEventHandler` COM RPCs.
        let mut session = MenuActionSession::new();
        session.enabled = true;
        session.win32.on_verified_menu_bar_item("File".to_string(), now_mono);
        let tr = session
            .tracking
            .menu_opened(MenuHandleKey::Win32MenuBar(0x400), true);
        session.apply_tracking_change(tr.tracking_changed, now_mono);

        session.reset_for_boundary(Some(&uia), true, now_mono - 1, &clock);
        assert!(session.uia_sub.is_none());
        assert!(session.popup_uia_sub.is_none());
        assert!(!session.tracking.is_tracking());
        assert_eq!(session.current_win32_link(now_mono + 1), None);

        session.disable(Some(&uia), false, now_mono - 1, &clock);
        assert!(!session.enabled);
        assert!(session.uia_sub.is_none());
        assert!(session.popup_uia_sub.is_none());

        // Near-deadline (`<= 15ms` remaining) ALSO abandons locally without risking COM RPC overrun.
        session.enabled = true;
        session.reset_for_boundary(Some(&uia), true, now_mono + 10, &clock);
        assert!(session.uia_sub.is_none());
        assert!(session.popup_uia_sub.is_none());
    }
}
