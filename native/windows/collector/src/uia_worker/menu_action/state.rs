//! Pure state types, poll-event merge planner, and wrapper/renderer classifiers for
//! foreground top-menu-bar action capture (`menu.action` / `uia.menu`).
//!
//! Layer 1a leaf submodule — **ZERO COM, ZERO Win32 API calls, ZERO `unsafe`**.

use crate::menu_action_core::{
    MenuPathLimits, Win32MenuBarLink, UIA_CUSTOM_CONTROL_TYPE, UIA_GROUP_CONTROL_TYPE,
    UIA_PANE_CONTROL_TYPE,
};
use crate::uia_com::{WinMenuEvent, WinMenuEventKind};
use crate::uia_traversal::RuntimeIdKey;
use crate::uia_worker::input_hook::MenuCommitSignal;
use crate::uia_worker::uia_events::UiaMenuEventKind;

/// Maximum number of active non-placeholder UIA menu elements retained for submenu classification.
pub const MAX_OPEN_MENUS: usize = 8;

/// Maximum transparent layout wrapper hops permitted between a top-level menu bar item and its
/// verified non-`SystemMenuBar` `MenuBar (50010)` ancestor.
pub const MAX_MENU_BAR_ITEM_WRAPPER_HOPS: usize = 2;

/// Unique key identifying an open menu handle tracked by `MenuTrackingStateMachine`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MenuHandleKey {
    RuntimeId(RuntimeIdKey),
    Hwnd(isize),
    Win32MenuBar(isize),
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
pub struct Win32MenuBarState {
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
    pub fn clear(&mut self) {
        self.active = false;
        self.from_objid_menu = false;
        self.armed_mono_ms = None;
        self.bar_item_title = None;
        self.bar_item_owner_popup = None;
        self.popup_stack.clear();
        self.submenu_titles.clear();
        self.pending_submenu_candidate = None;
    }

    pub fn is_armed(&self) -> bool {
        self.active
    }

    pub fn is_from_objid_menu(&self) -> bool {
        self.from_objid_menu
    }

    pub fn is_popup_stack_empty(&self) -> bool {
        self.popup_stack.is_empty()
    }

    pub fn has_bar_item_owner_popup(&self) -> bool {
        self.bar_item_owner_popup.is_some()
    }

    #[doc(hidden)]
    pub fn clear_bar_item_title_for_test(&mut self) {
        self.bar_item_title = None;
    }

    pub fn is_active(&self, now_mono_ms: i64) -> bool {
        self.active
            && self.armed_mono_ms.is_some_and(|armed| {
                now_mono_ms >= armed
                    && now_mono_ms.saturating_sub(armed) < MenuPathLimits::MAX_MENU_TRACKING_MS
            })
    }

    pub fn expire_if_stale(&mut self, now_mono_ms: i64) -> bool {
        if self.active && !self.is_active(now_mono_ms) {
            self.clear();
            true
        } else {
            false
        }
    }

    pub fn on_menu_bar_start(&mut self, now_mono_ms: i64) {
        self.clear();
        self.active = true;
        self.from_objid_menu = true;
        self.armed_mono_ms = Some(now_mono_ms);
    }

    /// Arms or updates the verified top-menu-bar link when focus or `Invoke_Invoked` hits a
    /// verified top-level item inside a non-`SystemMenuBar` `MenuBar (50010)` belonging to
    /// `bound_hwnd`. Preserves `from_objid_menu` only if already inside an active `OBJID_MENU`
    /// session.
    pub fn on_verified_menu_bar_item(&mut self, title: String, now_mono_ms: i64) {
        let keep_objid = self.from_objid_menu && self.is_active(now_mono_ms);
        self.active = true;
        self.from_objid_menu = keep_objid;
        self.armed_mono_ms = Some(now_mono_ms);
        self.bar_item_title = Some(title);
        self.bar_item_owner_popup = None;
        self.submenu_titles.clear();
        self.pending_submenu_candidate = None;
    }

    pub fn on_submenu_opener_focused(&mut self, title: Option<String>, now_mono_ms: i64) {
        if self.is_active(now_mono_ms) {
            self.pending_submenu_candidate = title;
        }
    }

    pub fn on_uia_menu_opened(&mut self, is_submenu: bool, now_mono_ms: i64) {
        if !self.is_active(now_mono_ms) || !is_submenu || !self.popup_stack.is_empty() {
            return;
        }
        if self.submenu_titles.len() < MenuPathLimits::MAX_SEGMENTS {
            if let Some(title) = self.pending_submenu_candidate.take() {
                self.submenu_titles.push(title);
            }
        }
    }

    pub fn on_uia_menu_closed(&mut self, remaining_open_menus: usize) {
        if self.popup_stack.is_empty() {
            self.submenu_titles
                .truncate(remaining_open_menus.saturating_sub(1));
            self.pending_submenu_candidate = None;
        }
    }

    pub fn on_popup_start(
        &mut self,
        popup_hwnd: isize,
        popup_title: Option<String>,
        now_mono_ms: i64,
    ) {
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
    pub fn on_popup_end(&mut self, popup_hwnd: isize) -> bool {
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

    pub fn last_popup_hwnd(&self) -> Option<isize> {
        self.popup_stack.last().copied()
    }

    pub fn current_link(&self, now_mono_ms: i64) -> Option<Win32MenuBarLink> {
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

/// Ordered dispatch step produced by [`plan_merged_poll_events`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergedPollEvent {
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
pub fn plan_merged_poll_events(
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

/// Single source of truth for browser content-renderer window classes whose subtrees must never
/// be mistaken for native browser chrome menus.
pub fn is_renderer_host_class(class_name: &str) -> bool {
    class_name.eq_ignore_ascii_case("Chrome_RenderWidgetHostHWND")
        || class_name.eq_ignore_ascii_case("MozillaCompositorWindowClass")
}

/// Returns `true` when raw UIA/AX metadata fields identify a web document or browser renderer
/// host node.
pub fn is_document_or_renderer_host_fields(
    control_type: i32,
    ax_role: Option<&str>,
    class_name: Option<&str>,
) -> bool {
    control_type == 50030
        || matches!(ax_role, Some("AXWebArea" | "AXDocument"))
        || class_name.is_some_and(is_renderer_host_class)
}

/// Strict allowlist for transparent layout wrappers between a top-level menu bar item and its
/// `MenuBar (50010)` parent, matching `MenuNodeSnapshot::is_transparent_menu_wrapper`.
pub fn is_allowed_menu_bar_wrapper_fields(
    control_type: i32,
    ax_role: Option<&str>,
    class_name: Option<&str>,
) -> bool {
    !is_document_or_renderer_host_fields(control_type, ax_role, class_name)
        && matches!(
            control_type,
            UIA_CUSTOM_CONTROL_TYPE | UIA_GROUP_CONTROL_TYPE | UIA_PANE_CONTROL_TYPE
        )
        && matches!(ax_role, None | Some("AXGroup" | "AXScrollArea"))
}
