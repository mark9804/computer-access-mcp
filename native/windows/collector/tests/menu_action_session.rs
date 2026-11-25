//! Integration & unit tests for `collector_core::uia_worker::menu_action` (`MenuActionSession`,
//! `Win32MenuBarState`, 3-way poll event merge planner, wrapper allowlist, and deadline-bounded
//! detach/fail-closed invariants).

use collector_core::adapters::AdapterRegistry;
use collector_core::menu_action_core::{
    is_menu_structure_control_type, MenuNodeSnapshot, MenuPathResolver, OpenedMenuKind,
    ResolvedMenuPath, Win32MenuBarLink, UIA_BUTTON_CONTROL_TYPE, UIA_CUSTOM_CONTROL_TYPE,
    UIA_GROUP_CONTROL_TYPE, UIA_IMAGE_CONTROL_TYPE, UIA_MENU_CONTROL_TYPE,
    UIA_MENU_ITEM_CONTROL_TYPE, UIA_PANE_CONTROL_TYPE, UIA_TEXT_CONTROL_TYPE,
    UIA_WINDOW_CONTROL_TYPE,
};
use collector_core::policy::{ProtectedContentRead, SubroleRead};
use collector_core::protocol_model::{CollectorClock, SystemCollectorClock};
use collector_core::uia_com::{ComGuard, UiaClient, WinMenuEvent, WinMenuEventKind};
use collector_core::uia_traversal::RuntimeIdKey;
use collector_core::uia_worker::input_hook::MenuCommitSignal;
use collector_core::uia_worker::menu_action::state::{
    is_allowed_menu_bar_wrapper_fields, plan_merged_poll_events, MenuHandleKey, MergedPollEvent,
    Win32MenuBarState, MAX_OPEN_MENUS,
};
use collector_core::uia_worker::menu_action::MenuActionSession;
use collector_core::uia_worker::uia_events::UiaMenuEventKind;

/// Keeps one process-wide MTA apartment + `IUIAutomation` instance alive and serializes concurrent
/// `UiaClient::new()` calls across parallel `#[test]` threads in this integration test binary.
fn acquire_test_mta_uia_lock() -> std::sync::MutexGuard<'static, ()> {
    static KEEPALIVE: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    static UIA_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let guard = UIA_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    KEEPALIVE.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::sync_channel::<()>(1);
        std::thread::spawn(move || {
            let _com = ComGuard::init_mta();
            let _uia = UiaClient::new();
            let _ = tx.send(());
            loop {
                std::thread::park();
            }
        });
        let _ = rx.recv();
    });
    guard
}

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
    assert!(!s.is_armed());

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
    assert!(!s.is_from_objid_menu());
    s.on_popup_start(0x10, Some("Context".to_string()), 1_010);
    assert_eq!(s.current_link(1_020).unwrap().menu_bar_item_title, "File");

    // Closing the WinUI 3 popup disarms `active` completely and returns `true`.
    assert!(s.on_popup_end(0x10));
    assert!(!s.is_armed());
    assert_eq!(s.current_link(1_030), None);

    // Even if `PopupEnd` arrives when `popup_stack` was already empty (e.g. no prior
    // `PopupStart`), `!from_objid_menu` disarms immediately.
    s.on_verified_menu_bar_item("Edit".to_string(), 1_100);
    assert!(s.on_popup_end(0x99));
    assert!(!s.is_armed());
    assert_eq!(s.current_link(1_110), None);

    // Even if `bar_item_title` were cleared while `!from_objid_menu`, `on_popup_start` MUST
    // NOT adopt `"Context"` as `bar_item_title` or submenu title.
    s.on_verified_menu_bar_item("File".to_string(), 1_200);
    s.clear_bar_item_title_for_test();
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
    // 1. `MenuClosed` with a non-null `RuntimeId` that isn't in `open_menus` (because a
    // `Win32MenuBar` placeholder was active) MUST fail closed and disarm `win32` + tracking!
    let mut session = MenuActionSession::new();
    session.arm_menu_bar_item_for_test("File", 0x100, 5_000);
    assert!(session.is_tracking_for_test());
    assert!(session.current_win32_link_for_test(5_010).is_some());

    session.apply_uia_menu_closed_for_test(
        Some(MenuHandleKey::RuntimeId(RuntimeIdKey(vec![42, 7]))),
        5_020,
    );
    assert!(!session.is_tracking_for_test());
    assert!(!session.is_menu_open_flag_set_for_test());
    assert_eq!(session.current_win32_link_for_test(5_030), None);

    // 2. `MenuCommitSignal::Escape` MUST fully disarm `ActiveMenuBarLink` + tracking (not just
    // clear volatile highlight) so `File -> Esc -> right-click` cannot leak `["File", ...]`.
    let _uia_lock = acquire_test_mta_uia_lock();
    let _com = ComGuard::init_mta().expect("MTA COM init");
    let uia = UiaClient::new().expect("UiaClient::new");
    let registry = AdapterRegistry::new();
    let clock = SystemCollectorClock;
    let now_mono = clock.monotonic_ms();
    session.arm_menu_bar_item_for_test("File", 0x100, now_mono);
    session.set_accept_after_qpc_ns_for_test(100);
    let esc = MenuCommitSignal::Escape {
        qpc_ns: 200,
        unix_ms: clock.unix_ms(),
    };
    session.handle_commit_signal_for_test(&uia, &registry, esc, 250, now_mono + 120, &clock);
    assert!(!session.is_tracking_for_test());
    assert!(!session.is_menu_open_flag_set_for_test());
    assert_eq!(session.current_win32_link_for_test(now_mono + 10), None);

    // 3. `MenuCommitSignal::Cancel` (`WM_RBUTTONDOWN`) and `DisarmNonMenuBar` MUST also fully
    // disarm `ActiveMenuBarLink` + tracking!
    session.arm_menu_bar_item_for_test("Edit", 0x100, now_mono);
    let cancel = MenuCommitSignal::Cancel {
        qpc_ns: 210,
        unix_ms: clock.unix_ms(),
    };
    session.handle_commit_signal_for_test(&uia, &registry, cancel, 250, now_mono + 120, &clock);
    assert!(!session.is_tracking_for_test());
    assert!(!session.is_menu_open_flag_set_for_test());
    assert_eq!(session.current_win32_link_for_test(now_mono + 10), None);

    session.arm_menu_bar_item_for_test("View", 0x100, now_mono);
    session.handle_win_close_or_switch_for_test(
        &uia,
        mk_win_ev_qpc(WinMenuEventKind::DisarmNonMenuBar, 0x100, 300),
        now_mono + 120,
        &clock,
    );
    assert!(!session.is_tracking_for_test());
    assert!(!session.is_menu_open_flag_set_for_test());
    assert_eq!(session.current_win32_link_for_test(now_mono + 10), None);
}

#[test]
fn non_menu_focus_disarms_active_menu_bar_link_and_rejects_subsequent_context_menu() {
    // 1. Arm `MenuActionSession` as if user focused `"File"` on a WinUI 3 `MenuBar`.
    let mut session = MenuActionSession::new();
    session.arm_menu_bar_item_for_test("File", 0x100, 5_000);
    assert!(session.is_tracking_for_test());
    assert!(session.is_menu_open_flag_set_for_test());
    assert_eq!(session.take_menu_tracking(), Some(true));
    let armed_link = session.current_win32_link_for_test(5_050).expect("armed link");

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
    session.clear_tracking_state_for_test(true);
    assert!(!session.is_tracking_for_test());
    assert!(!session.is_menu_open_flag_set_for_test());
    assert_eq!(session.take_menu_tracking(), Some(false));
    assert_eq!(session.current_win32_link_for_test(5_100), None);

    // 3. Subsequent right-click context menu in editor sees `None` link -> strictly rejected!
    let post_clear_link = session.current_win32_link_for_test(5_100);
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
    assert!(!s.is_from_objid_menu());
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
    assert!(s.is_armed());
    assert_eq!(s.current_link(1_040).unwrap().menu_bar_item_title, "Edit");

    // Edit's new popup (0x20) opens and owns `"Edit"`.
    s.on_popup_start(0x20, None, 1_050);
    assert_eq!(s.current_link(1_060).unwrap().menu_bar_item_title, "Edit");
    assert_eq!(s.last_popup_hwnd(), Some(0x20));

    // Closing Edit's active popup (0x20) MUST disarm cleanly and return true.
    assert!(s.on_popup_end(0x20));
    assert!(!s.is_armed());
    assert_eq!(s.current_link(1_070), None);
}

#[test]
fn dropped_commit_signals_fail_closed_and_clear_tracking_in_poll() {
    // P2-6: Non-zero dropped signal count at start of `poll()` MUST fail closed, clear
    // tracking/link state, and emit `menuTracking: false`.
    let _uia_lock = acquire_test_mta_uia_lock();
    let _com = ComGuard::init_mta().expect("MTA COM init");
    let uia = UiaClient::new().expect("UiaClient::new");
    let registry = AdapterRegistry::new();
    let clock = SystemCollectorClock;
    let now_mono = clock.monotonic_ms();

    let mut session = MenuActionSession::new();
    session.set_enabled_for_test(true);
    assert!(
        session.ensure_commit_hook_for_test(),
        "MenuCommitHook must install in test"
    );

    session.arm_menu_bar_item_for_test("File", 0x200, now_mono);
    assert_eq!(session.take_menu_tracking(), Some(true));
    assert!(session.is_tracking_for_test());

    session.inject_dropped_commit_signals_for_test(2);
    session.poll(&uia, &registry, Vec::new(), false, &clock);

    assert!(
        !session.is_tracking_for_test(),
        "dropped commit signal counter > 0 MUST clear menu tracking fail-closed"
    );
    assert!(!session.is_menu_open_flag_set_for_test());
    assert_eq!(session.current_win32_link_for_test(now_mono + 10), None);
    assert_eq!(session.take_menu_tracking(), Some(false));
    session.retire_for_process_exit();
}

#[test]
fn active_open_handles_classify_detached_winui3_nested_submenu() {
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
    let _uia_lock = acquire_test_mta_uia_lock();
    let _com = ComGuard::init_mta().expect("MTA COM init");
    let uia = UiaClient::new().expect("UiaClient::new");
    let registry = AdapterRegistry::new();
    let clock = SystemCollectorClock;
    let now_mono = clock.monotonic_ms();

    let arm_with_highlight = |session: &mut MenuActionSession| {
        session.arm_menu_bar_item_for_test("File", 0x100, now_mono);
        session.update_selection_for_test(
            Some(ResolvedMenuPath {
                path: vec!["File".to_string(), "Save".to_string()],
                truncated: false,
            }),
            MenuHandleKey::Win32MenuBar(0x100),
            now_mono,
        );
        session.set_accept_after_qpc_ns_for_test(1_000_000_000);
    };

    let mut session = MenuActionSession::new();
    let now_qpc = 2_000_000_000u64;
    // 500ms old (> 200ms MAX_COMMIT_SIGNAL_AGE_NS), strictly after accept_after_qpc_ns.
    let old_qpc = now_qpc - 500_000_000;
    // Future relative to sampled `now_qpc`, strictly after accept_after_qpc_ns.
    let future_qpc = now_qpc + 10_000_000;

    // 1. >200ms old `Escape` MUST still disarm `Win32MenuBarState` + `tracking`.
    arm_with_highlight(&mut session);
    session.handle_commit_signal_for_test(
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
    assert!(!session.is_tracking_for_test());
    assert_eq!(session.current_win32_link_for_test(now_mono + 10), None);

    // 2. >200ms old `Cancel` (`WM_RBUTTONDOWN`) MUST still disarm.
    arm_with_highlight(&mut session);
    session.handle_commit_signal_for_test(
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
    assert!(!session.is_tracking_for_test());
    assert_eq!(session.current_win32_link_for_test(now_mono + 10), None);

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
        session.handle_commit_signal_for_test(
            &uia,
            &registry,
            sig,
            now_qpc,
            now_mono + 120,
            &clock,
        );
        assert!(!session.is_tracking_for_test());
        assert_eq!(session.current_win32_link_for_test(now_mono + 10), None);
    }

    // 4. Stale `Escape` / `Cancel` BEFORE or AT `accept_after_qpc_ns` MUST be ignored.
    arm_with_highlight(&mut session);
    let cutoff_qpc = session.accept_after_qpc_ns_for_test();
    session.handle_commit_signal_for_test(
        &uia,
        &registry,
        MenuCommitSignal::Escape {
            qpc_ns: cutoff_qpc,
            unix_ms: clock.unix_ms(),
        },
        now_qpc,
        now_mono + 120,
        &clock,
    );
    assert!(session.is_tracking_for_test());
    assert!(session.current_win32_link_for_test(now_mono + 10).is_some());

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
        session.handle_commit_signal_for_test(
            &uia,
            &registry,
            sig,
            now_qpc,
            now_mono + 120,
            &clock,
        );
        assert!(
            session.has_selection_for_test(),
            "stale/future commit signal {sig:?} MUST be dropped without consuming selection"
        );
        assert!(session.take_next_record().is_none());
    }
}

#[test]
fn p1_5_open_uia_menus_eviction_sync_and_classic_win32_slide_over_keeps_edit_top_level() {
    let _uia_lock = acquire_test_mta_uia_lock();
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
        session.open_uia_menu_for_test(root_el.clone(), rid, i == 0, None);
    }
    assert_eq!(session.open_menu_keys_for_test().len(), MAX_OPEN_MENUS);
    assert_eq!(session.open_uia_menu_keys_for_test().len(), MAX_OPEN_MENUS);

    let rid8 = RuntimeIdKey(vec![100, 8]);
    let key8 = MenuHandleKey::RuntimeId(rid8.clone());
    session.open_uia_menu_for_test(root_el.clone(), rid8, false, None);

    assert_eq!(session.open_menu_keys_for_test().len(), MAX_OPEN_MENUS);
    let open_uia_keys = session.open_uia_menu_keys_for_test();
    assert_eq!(open_uia_keys.len(), MAX_OPEN_MENUS);
    assert!(
        !open_uia_keys.contains(&MenuHandleKey::RuntimeId(RuntimeIdKey(vec![100, 0]))),
        "evicted R0 MUST be removed from open_uia_menus"
    );
    assert!(
        open_uia_keys.contains(&key8),
        "newly opened R8 MUST be present in open_uia_menus"
    );
    for key in &open_uia_keys {
        assert!(session.open_menu_keys_for_test().contains(key));
    }

    // Opening a nested PopupStart (`Hwnd`) at capacity 8 evicts R1 from `tracking` AND syncs
    // `open_uia_menus` so R1 is evicted from `open_uia_menus` too.
    session.start_win32_menu_bar_for_test(None, now_mono);
    session.win32_on_popup_start_for_test(0x10, Some("File".to_string()), now_mono);
    session.apply_verified_popup_start_for_test(0x11, Some("Sub".to_string()), now_mono + 5);
    let open_uia_keys_after_popup = session.open_uia_menu_keys_for_test();
    assert!(
        !open_uia_keys_after_popup.contains(&MenuHandleKey::RuntimeId(RuntimeIdKey(vec![100, 1]))),
        "PopupStart eviction at capacity 8 MUST sync open_uia_menus"
    );
    for key in &open_uia_keys_after_popup {
        assert!(session.open_menu_keys_for_test().contains(key));
    }

    // 2. Classic Win32 `"File" -> "Edit"` slide-over: `PopupEnd(P1)` empties `popup_stack`
    //    with `MenuClosed(R1)` suppressed after popup UIA detach. `open_uia_menus` and stale
    //    `RuntimeId(R1)` MUST be cleared so `"Edit"` (`R2`) classifies as `TopLevel`!
    let mut s = MenuActionSession::new();
    s.start_win32_menu_bar_for_test(Some(0x1000), now_mono);
    s.apply_verified_popup_start_for_test(0x2001, Some("File".to_string()), now_mono + 10);
    let r1 = RuntimeIdKey(vec![42, 1]);
    s.open_uia_menu_for_test(root_el.clone(), r1, true, Some(now_mono + 15));
    assert_eq!(s.open_uia_menu_keys_for_test().len(), 1);

    // `PopupEnd(File)` fires and empties `win32.popup_stack` (suppressed `MenuClosed(R1)`).
    s.handle_win_close_or_switch_for_test(
        &uia,
        mk_win_ev_qpc(WinMenuEventKind::PopupEnd, 0x2001, 500),
        now_mono + 120,
        &clock,
    );
    assert!(
        s.open_uia_menu_keys_for_test().is_empty(),
        "PopupEnd emptying popup_stack MUST clear open_uia_menus"
    );
    assert!(
        !s.open_menu_keys_for_test()
            .iter()
            .any(|k| matches!(k, MenuHandleKey::RuntimeId(_))),
        "PopupEnd emptying popup_stack MUST clear stale RuntimeId open menus from tracking"
    );
    assert!(s.win32_is_active_for_test(now_mono + 20));

    // `PopupStart(Edit)` opens a new top-level popup.
    s.apply_verified_popup_start_for_test(0x2002, Some("Edit".to_string()), now_mono + 25);
    assert!(s.open_uia_menu_keys_for_test().is_empty());
    assert_eq!(
        s.current_win32_link_for_test(now_mono + 30)
            .map(|l| l.menu_bar_item_title),
        Some("Edit".to_string())
    );

    // Classify `"Edit"` detached popup `Menu` against `s.open_uia_menus` (empty!) -> `TopLevel`!
    let edit_link = s.current_win32_link_for_test(now_mono + 30).expect("Edit link");
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
    let open_ids: Vec<usize> = s
        .open_uia_menu_keys_for_test()
        .iter()
        .enumerate()
        .map(|(i, _)| i + 100)
        .collect();
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
    s.open_uia_menu_for_test(root_el, r_stale, true, None);
    s.win32_on_verified_menu_bar_item_for_test("View", now_mono + 40);
    s.apply_verified_popup_start_for_test(0x2003, Some("View".to_string()), now_mono + 45);
    assert!(s.open_uia_menu_keys_for_test().is_empty());
    assert!(!s
        .open_menu_keys_for_test()
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
    // 1. `win_events_dropped = true` triggers fail-closed reset in `poll()`.
    let _uia_lock = acquire_test_mta_uia_lock();
    let _com = ComGuard::init_mta().expect("MTA COM init");
    let uia = UiaClient::new().expect("UiaClient::new");
    let registry = AdapterRegistry::new();
    let clock = SystemCollectorClock;
    let now_mono = clock.monotonic_ms();

    let mut session = MenuActionSession::new();
    session.set_enabled_for_test(true);
    session.arm_menu_bar_item_for_test("File", 0x300, now_mono);
    assert_eq!(session.take_menu_tracking(), Some(true));

    session.poll(
        &uia,
        &registry,
        vec![mk_win_ev_qpc(WinMenuEventKind::FocusChanged, 0x300, 100)],
        true,
        &clock,
    );
    assert!(!session.is_tracking_for_test());
    assert!(!session.is_menu_open_flag_set_for_test());
    assert_eq!(session.current_win32_link_for_test(now_mono + 10), None);
    assert_eq!(session.take_menu_tracking(), Some(false));

    // 2. `detect_verified_menu_bar_item` intermediate wrapper role whitelist: allows ONLY
    //    Custom/Group/Pane with `None | Some("AXGroup" | "AXScrollArea")` and non-renderer class.
    for ct in [
        UIA_CUSTOM_CONTROL_TYPE,
        UIA_GROUP_CONTROL_TYPE,
        UIA_PANE_CONTROL_TYPE,
    ] {
        assert!(is_allowed_menu_bar_wrapper_fields(ct, None, None));
        assert!(is_allowed_menu_bar_wrapper_fields(
            ct,
            Some("AXGroup"),
            None
        ));
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
    let _uia_lock = acquire_test_mta_uia_lock();
    let _com = ComGuard::init_mta().expect("MTA COM init");
    let uia = UiaClient::new().expect("UiaClient::new");
    let clock = SystemCollectorClock;
    let now_mono = clock.monotonic_ms();

    // Expired deadline (`now_mono - 1`): `reset_for_boundary` and `disable` abandon locally
    // instead of blocking on synchronous `RemoveAutomationEventHandler` COM RPCs.
    let mut session = MenuActionSession::new();
    session.set_enabled_for_test(true);
    session.arm_menu_bar_item_for_test("File", 0x400, now_mono);

    session.reset_for_boundary(Some(&uia), true, now_mono - 1, &clock);
    assert!(!session.has_uia_subscription_for_test());
    assert!(!session.has_popup_uia_subscription_for_test());
    assert!(!session.is_tracking_for_test());
    assert_eq!(session.current_win32_link_for_test(now_mono + 1), None);

    session.disable(Some(&uia), false, now_mono - 1, &clock);
    assert!(!session.is_enabled_for_test());
    assert!(!session.has_uia_subscription_for_test());
    assert!(!session.has_popup_uia_subscription_for_test());

    // Near-deadline (`<= 15ms` remaining) ALSO abandons locally without risking COM RPC overrun.
    session.set_enabled_for_test(true);
    session.reset_for_boundary(Some(&uia), true, now_mono + 10, &clock);
    assert!(!session.has_uia_subscription_for_test());
    assert!(!session.has_popup_uia_subscription_for_test());
}
