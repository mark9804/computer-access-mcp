//! Live Win32 & MTA UIA integration tests for Phase 5A (`input.activity` + `menu.action`):
//! 1. `RawInputActivityMonitor` start/healthy/epoch-fence/stop + live `WM_WTSSESSION_CHANGE` latch.
//! 2. Live Win32 `CreateMenu`/`SetMenu` top menu bar (`File -> Export -> PDF`) skipping
//!    `SystemMenuBar`, rejecting right-click context menus, and validating with `ContractValidator`.
//! 3. Live MTA `UiaMenuEventSubscription` attach/detach/`abandon_for_process_exit` +
//!    `MenuCommitHook` start/toggle/stop with zero deadlock.
//! 4. Live isolated session worker (`--ax-worker --session-worker yes`) with `menu_actions: Some(true)`
//!    processing a live `ReadTicket` and exiting 0 cleanly on the `retire` ACK handshake.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::{BufRead, BufReader, Write};
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::sync::{mpsc, Arc, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use access_contract::{ContractValidator, JsonValue};
use collector_core::input_activity_win32::{
    monotonic_qpc_ns_now, RawInputActivityMonitor, RawInputNotice,
};
use collector_core::menu_action_core::{
    MenuActionRecord, MenuNodeSnapshot, MenuPathResolver, Win32MenuBarLink,
    UIA_MENU_BAR_CONTROL_TYPE, UIA_MENU_CONTROL_TYPE, UIA_MENU_ITEM_CONTROL_TYPE,
    UIA_WINDOW_CONTROL_TYPE,
};
use collector_core::ownership::current_wts_session_id;
use collector_core::policy::{ProtectedContentRead, SubroleRead};
use collector_core::protocol_model::{
    generate_uuid_v4, json_i64, ApplicationIdentity, ApplicationTargetIdentity, CapturePolicy,
    CollectorClock, Stamp, SystemCollectorClock,
};
use collector_core::uia_com::{ComGuard, UiaClient};
use collector_core::uia_worker::input_hook::MenuCommitHook;
use collector_core::uia_worker::uia_events::{
    create_menu_event_channel, UiaMenuEventSubscription,
};
use collector_core::uia_worker::{
    find_app_menu_bar_for_window, has_menu_child_for_test, resolve_uia_menu_leaf_for_test,
};
use collector_core::worker_ipc::{ReadResult, ReadTicket};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreateMenu, CreatePopupMenu, CreateWindowExW, DestroyWindow, DispatchMessageW,
    DrawMenuBar, GetMenu, GetMenuStringW, GetMessageW, GetSubMenu, PeekMessageW, PostMessageW,
    PostThreadMessageW, SetMenu, TranslateMessage, HMENU, MF_BYPOSITION, MF_POPUP, MF_STRING, MSG,
    PM_NOREMOVE, WINDOW_EX_STYLE, WINDOW_STYLE, WM_QUIT, WM_WTSSESSION_CHANGE, WS_CHILD,
    WS_EX_NOACTIVATE, WS_OVERLAPPEDWINDOW, WS_VISIBLE, WTS_SESSION_LOCK,
};

static TEST_MTA_KEEPALIVE: OnceLock<()> = OnceLock::new();

fn ensure_test_mta_apartment() {
    TEST_MTA_KEEPALIVE.get_or_init(|| {
        let (tx, rx) = mpsc::sync_channel::<()>(1);
        thread::spawn(move || {
            let _com = ComGuard::init_mta();
            let _uia = UiaClient::new();
            let _ = tx.send(());
            loop {
                thread::park();
            }
        });
        let _ = rx.recv();
    });
}

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

fn read_hmenu_item_string(menu: HMENU, position: u32) -> Option<String> {
    let mut buf = [0u16; 128];
    // SAFETY: Standard Win32 menu label lookup by zero-based position.
    let len = unsafe { GetMenuStringW(menu, position, Some(&mut buf), MF_BYPOSITION) };
    if len <= 0 {
        return None;
    }
    String::from_utf16(&buf[..len as usize]).ok()
}

struct SyntheticMenuWindow {
    hwnd: HWND,
    thread_id: u32,
    handle: Option<JoinHandle<()>>,
}

impl SyntheticMenuWindow {
    /// Spawn a real off-screen Win32 overlapped window with a live 3-level top menu bar
    /// (`File -> Export -> PDF`) without activating or stealing desktop focus.
    fn spawn_with_file_export_pdf_menu() -> Self {
        ensure_test_mta_apartment();
        let (tx, rx) = mpsc::sync_channel::<(isize, u32)>(1);
        let handle = thread::spawn(move || {
            let class_wide = to_wide("#32770");
            let title_wide = to_wide("Phase 5A Menu Test Window");
            let file_wide = to_wide("File");
            let export_wide = to_wide("Export");
            let pdf_wide = to_wide("PDF");

            // SAFETY: Self-contained Win32 window and HMENU created, pumped, and destroyed on
            // this dedicated UI thread; positioned off-screen with WS_EX_NOACTIVATE so live user
            // desktop focus is never disturbed.
            unsafe {
                let mut init_msg = MSG::default();
                let _ = PeekMessageW(&mut init_msg, None, 0, 0, PM_NOREMOVE);

                let hwnd = CreateWindowExW(
                    WINDOW_EX_STYLE(WS_EX_NOACTIVATE.0),
                    PCWSTR(class_wide.as_ptr()),
                    PCWSTR(title_wide.as_ptr()),
                    WINDOW_STYLE(WS_OVERLAPPEDWINDOW.0 | WS_VISIBLE.0),
                    -24_000,
                    -24_000,
                    640,
                    480,
                    None,
                    None,
                    None,
                    None,
                )
                .expect("CreateWindowExW synthetic menu window");

                let h_bar = CreateMenu().expect("CreateMenu");
                let h_file = CreatePopupMenu().expect("CreatePopupMenu File");
                let h_export = CreatePopupMenu().expect("CreatePopupMenu Export");
                AppendMenuW(h_export, MF_STRING, 1001, PCWSTR(pdf_wide.as_ptr()))
                    .expect("AppendMenuW PDF");
                AppendMenuW(
                    h_file,
                    MF_POPUP,
                    h_export.0 as usize,
                    PCWSTR(export_wide.as_ptr()),
                )
                .expect("AppendMenuW Export");
                AppendMenuW(
                    h_bar,
                    MF_POPUP,
                    h_file.0 as usize,
                    PCWSTR(file_wide.as_ptr()),
                )
                .expect("AppendMenuW File");
                SetMenu(hwnd, Some(h_bar)).expect("SetMenu");
                let _ = DrawMenuBar(hwnd);

                // Add a real visual child `STATIC` (`Text 50020`) inside a `BUTTON` container so
                // `has_menu_child_for_test` can be verified against live visual vs menu children.
                let group_class = to_wide("STATIC");
                let group_text = to_wide("Ctrl+S");
                let _ = CreateWindowExW(
                    WINDOW_EX_STYLE(0),
                    PCWSTR(group_class.as_ptr()),
                    PCWSTR(group_text.as_ptr()),
                    WINDOW_STYLE(WS_CHILD.0 | WS_VISIBLE.0),
                    10,
                    10,
                    120,
                    24,
                    Some(hwnd),
                    None,
                    None,
                    None,
                );

                let tid = GetCurrentThreadId();
                let _ = tx.send((hwnd.0 as isize, tid));

                let mut msg = MSG::default();
                while GetMessageW(&mut msg, None, 0, 0).0 > 0 {
                    let _ = TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
                let _ = DestroyWindow(hwnd);
            }
        });

        let (raw_hwnd, thread_id) = rx.recv().expect("synthetic menu window ready");
        Self {
            hwnd: HWND(raw_hwnd as *mut core::ffi::c_void),
            thread_id,
            handle: Some(handle),
        }
    }
}

impl Drop for SyntheticMenuWindow {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            if self.thread_id != 0 {
                // SAFETY: Posting WM_QUIT exits the synthetic UI thread's GetMessageW loop.
                unsafe {
                    let _ = PostThreadMessageW(self.thread_id, WM_QUIT, WPARAM(0), LPARAM(0));
                }
            }
            let _ = handle.join();
        }
    }
}

fn collector_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_computer-history-collector"))
}

#[test]
fn live_raw_input_activity_monitor_lifecycle_epoch_fence_and_wts_lock_latch() {
    let mut monitor = RawInputActivityMonitor::start().expect("RawInputActivityMonitor::start");
    assert!(monitor.is_healthy(), "monitor must be healthy after start");
    assert!(!monitor.is_desktop_latched());
    let hwnd_raw = monitor.message_window_raw_hwnd();
    assert_ne!(hwnd_raw, 0, "HWND_MESSAGE must be live");

    let policy = CapturePolicy {
        enabled: true,
        input_activity: Some(true),
        ..CapturePolicy::default()
    };
    let t0 = monotonic_qpc_ns_now();
    monitor.set_policy(Some(policy), t0);
    let fence1 = monitor.accept_after_qpc_ns();
    assert!(fence1 >= t0);

    let fence2 = monitor.reset_boundary(fence1.saturating_add(5_000));
    assert!(fence2 >= fence1.saturating_add(5_000));
    assert_eq!(monitor.accept_after_qpc_ns(), fence2);

    // Post a real live Win32 `WM_WTSSESSION_CHANGE(WTS_SESSION_LOCK)` message to the monitor's
    // `HWND_MESSAGE` window and verify <1ms sticky latching + `DesktopBoundaryLost` notice.
    let session_id = current_wts_session_id().unwrap_or(1);
    let hwnd = HWND(hwnd_raw as *mut core::ffi::c_void);
    // SAFETY: Posting WM_WTSSESSION_CHANGE to our own live message-only window.
    unsafe {
        PostMessageW(
            Some(hwnd),
            WM_WTSSESSION_CHANGE,
            WPARAM(WTS_SESSION_LOCK as usize),
            LPARAM(session_id as isize),
        )
        .expect("PostMessageW WM_WTSSESSION_CHANGE");
    }

    let deadline = Instant::now() + Duration::from_secs(2);
    while !monitor.is_desktop_latched() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        monitor.is_desktop_latched(),
        "WM_WTSSESSION_CHANGE(WTS_SESSION_LOCK) must latch desktop_latched immediately"
    );
    let notices = monitor.drain_events();
    assert!(
        notices
            .iter()
            .any(|n| matches!(n, RawInputNotice::DesktopBoundaryLost)),
        "expected RawInputNotice::DesktopBoundaryLost, got {notices:?}"
    );

    // Normal boundary reset MUST NOT clear the sticky lock latch.
    let _ = monitor.reset_boundary(0);
    assert!(
        monitor.is_desktop_latched(),
        "reset_boundary must keep sticky desktop latch armed"
    );

    // Explicit user start/resume reset clears the latch and advances the QPC fence.
    let fence3 = monitor.reset_desktop_latch_for_user_action(0);
    assert!(!monitor.is_desktop_latched());
    assert!(fence3 >= fence2);

    monitor.stop();
    assert!(!monitor.is_healthy());
    assert_eq!(monitor.message_window_raw_hwnd(), 0);
}

#[test]
fn live_win32_top_menu_bar_skips_system_menu_and_resolves_file_export_pdf() {
    let win = SyntheticMenuWindow::spawn_with_file_export_pdf_menu();
    let _com = ComGuard::init_mta().expect("MTA COM init");
    let uia = UiaClient::new().expect("UiaClient::new");
    let clock = SystemCollectorClock;
    let pid = std::process::id();

    // 1. Verify live Win32 window exposes BOTH SystemMenuBar and Application MenuBar, and that
    // `find_app_menu_bar_for_window` skips `SystemMenuBar` to return the application MenuBar!
    let win_el = uia
        .element_from_hwnd(win.hwnd)
        .expect("element_from_hwnd synthetic menu window");
    let children = uia
        .direct_children_bounded(&win_el, 16, || true)
        .expect("enumerate direct window children");

    let mut saw_system_menu_bar = false;
    let mut system_menu_item = None;
    for child in &children {
        if let Ok(meta) = uia.read_cached_metadata(child, 96, false, false) {
            if meta.control_type == UIA_MENU_BAR_CONTROL_TYPE
                && meta
                    .automation_id
                    .as_deref()
                    .is_some_and(|aid| aid.eq_ignore_ascii_case("SystemMenuBar"))
            {
                saw_system_menu_bar = true;
                system_menu_item = uia.first_child_element(child).ok().flatten();
            } else if meta.control_type == 50037 {
                // On Windows 10/11, `SystemMenuBar` lives directly inside `TitleBar (50037)`.
                if let Ok(tb_children) = uia.direct_children_bounded(child, 16, || true) {
                    for tb_child in &tb_children {
                        if let Ok(tbm) = uia.read_cached_metadata(tb_child, 96, false, false) {
                            if tbm.control_type == UIA_MENU_BAR_CONTROL_TYPE
                                && tbm
                                    .automation_id
                                    .as_deref()
                                    .is_some_and(|aid| aid.eq_ignore_ascii_case("SystemMenuBar"))
                            {
                                saw_system_menu_bar = true;
                                system_menu_item = uia.first_child_element(tb_child).ok().flatten();
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(
        saw_system_menu_bar,
        "WS_OVERLAPPEDWINDOW must expose SystemMenuBar so we verify exclusion"
    );

    let app_bar = find_app_menu_bar_for_window(
        &uia,
        win.hwnd,
        pid,
        pid,
        96,
        clock.monotonic_ms() + 1_000,
        &clock,
    )
    .expect("find_app_menu_bar_for_window must locate non-SystemMenuBar application MenuBar");
    let app_bar_meta = uia
        .read_cached_metadata(&app_bar, 96, false, false)
        .expect("app_bar metadata");
    assert_eq!(app_bar_meta.control_type, UIA_MENU_BAR_CONTROL_TYPE);
    assert!(
        !app_bar_meta
            .automation_id
            .as_deref()
            .is_some_and(|aid| aid.eq_ignore_ascii_case("SystemMenuBar")),
        "returned MenuBar must NOT be SystemMenuBar"
    );

    // 2. Live `SystemMenuBar` item MUST be rejected by `resolve_uia_menu_leaf_for_test`.
    if let Some(ref sys_item) = system_menu_item {
        assert_eq!(
            resolve_uia_menu_leaf_for_test(
                &uia,
                sys_item,
                win.hwnd,
                pid,
                96,
                Some(&app_bar),
                None,
                &clock,
            ),
            None,
            "SystemMenuBar item MUST always be rejected"
        );
    }

    // 3. Verify the real UIA top-level `"File"` MenuItem under Application MenuBar exists and
    // is rejected as a leaf (top-level submenu opener / < 2 segments).
    let file_item = uia
        .first_child_element(&app_bar)
        .expect("first child of app MenuBar")
        .expect("File MenuItem under app MenuBar");
    let file_meta = uia
        .read_cached_metadata(&file_item, 96, false, false)
        .expect("File MenuItem metadata");
    assert_eq!(file_meta.control_type, UIA_MENU_ITEM_CONTROL_TYPE);
    assert_eq!(file_meta.name.as_deref(), Some("File"));
    // Live `has_menu_child_for_test`: `app_bar` has a `MenuItem` child -> Ok(true), while `win_el`
    // (which has a real visual `Text (50020)` child `"Ctrl+S"`, plus `TitleBar` and `MenuBar`,
    // and NO direct `Menu`/`MenuItem` child) and `file_item` return Ok(false).
    assert_eq!(
        has_menu_child_for_test(&uia, &app_bar, 96, &clock),
        Ok(true),
        "MenuBar with MenuItem child must report has_menu_child == Ok(true)"
    );
    assert_eq!(
        has_menu_child_for_test(&uia, &win_el, 96, &clock),
        Ok(false),
        "element with visual Text child and no Menu/MenuItem child must report Ok(false)"
    );
    assert_eq!(
        has_menu_child_for_test(&uia, &file_item, 96, &clock),
        Ok(false),
        "closed File MenuItem without Menu/MenuItem children must report Ok(false)"
    );
    assert_eq!(
        resolve_uia_menu_leaf_for_test(
            &uia,
            &file_item,
            win.hwnd,
            pid,
            96,
            Some(&app_bar),
            None,
            &clock,
        ),
        None,
        "top-level submenu opener 'File' must not resolve as a leaf action"
    );

    // 4. Read exact live Win32 HMENU hierarchy (`File -> Export -> PDF`) attached to `win.hwnd`
    // and verify `MenuPathResolver::resolve` resolves `["File", "Export", "PDF"]` via both:
    // (a) direct UIA MenuBar chain (using the live `app_bar_meta` and `file_meta` snapshots), and
    // (b) Win32 `#32768` popup linked via `EVENT_SYSTEM_MENUSTART(OBJID_MENU)`, while strictly
    // rejecting a right-click context menu (`from_menu_bar_start: false`).
    // SAFETY: Read-only Win32 menu inspection on our live synthetic window.
    let (hmenu_file_title, hmenu_export_title, hmenu_pdf_title) = unsafe {
        let bar = GetMenu(win.hwnd);
        assert!(!bar.0.is_null(), "GetMenu must return attached top HMENU");
        let t_file = read_hmenu_item_string(bar, 0).expect("File menu label");
        let sub_file = GetSubMenu(bar, 0);
        assert!(!sub_file.0.is_null());
        let t_export = read_hmenu_item_string(sub_file, 0).expect("Export submenu label");
        let sub_export = GetSubMenu(sub_file, 0);
        assert!(!sub_export.0.is_null());
        let t_pdf = read_hmenu_item_string(sub_export, 0).expect("PDF leaf label");
        (t_file, t_export, t_pdf)
    };
    assert_eq!(hmenu_file_title, "File");
    assert_eq!(hmenu_export_title, "Export");
    assert_eq!(hmenu_pdf_title, "PDF");

    // (a) Direct UIA MenuBar chain anchored to live Win32 MenuBar + live "File" MenuItem metadata:
    let nodes = [
        // 0: leaf PDF
        MenuNodeSnapshot {
            pid,
            control_type: Some(UIA_MENU_ITEM_CONTROL_TYPE),
            role: Some("AXMenuItem".to_string()),
            subrole: SubroleRead::NoValue,
            protected_content: ProtectedContentRead::Value(false),
            enabled: Some(true),
            title: Some(hmenu_pdf_title.clone()),
            description: None,
            automation_id: None,
            class_name: None,
            child_count: Some(0),
            is_submenu_opener: Some(false),
        },
        // 1: Export submenu container
        MenuNodeSnapshot {
            pid,
            control_type: Some(UIA_MENU_CONTROL_TYPE),
            role: Some("AXMenu".to_string()),
            subrole: SubroleRead::NoValue,
            protected_content: ProtectedContentRead::Value(false),
            enabled: Some(true),
            title: None,
            description: None,
            automation_id: None,
            class_name: Some("#32768".to_string()),
            child_count: None,
            is_submenu_opener: None,
        },
        // 2: Export submenu item
        MenuNodeSnapshot {
            pid,
            control_type: Some(UIA_MENU_ITEM_CONTROL_TYPE),
            role: Some("AXMenuItem".to_string()),
            subrole: SubroleRead::NoValue,
            protected_content: ProtectedContentRead::Value(false),
            enabled: Some(true),
            title: Some(hmenu_export_title.clone()),
            description: None,
            automation_id: None,
            class_name: None,
            child_count: None,
            is_submenu_opener: None,
        },
        // 3: File dropdown container
        MenuNodeSnapshot {
            pid,
            control_type: Some(UIA_MENU_CONTROL_TYPE),
            role: Some("AXMenu".to_string()),
            subrole: SubroleRead::NoValue,
            protected_content: ProtectedContentRead::Value(false),
            enabled: Some(true),
            title: None,
            description: None,
            automation_id: None,
            class_name: Some("#32768".to_string()),
            child_count: None,
            is_submenu_opener: None,
        },
        // 4: Live File MenuBar item metadata
        MenuNodeSnapshot {
            pid: file_meta.process_id,
            control_type: Some(file_meta.control_type),
            role: file_meta.mapped.ax_role.map(str::to_string),
            subrole: file_meta.subrole_read.clone(),
            protected_content: file_meta.is_password,
            enabled: file_meta.is_enabled,
            title: file_meta.name.clone(),
            description: file_meta.safe_description().map(str::to_string),
            automation_id: file_meta.automation_id.clone(),
            class_name: file_meta.class_name.clone(),
            child_count: None,
            is_submenu_opener: None,
        },
        // 5: Live Application MenuBar metadata (NOT SystemMenuBar!)
        MenuNodeSnapshot {
            pid: app_bar_meta.process_id,
            control_type: Some(app_bar_meta.control_type),
            role: app_bar_meta.mapped.ax_role.map(str::to_string),
            subrole: app_bar_meta.subrole_read.clone(),
            protected_content: app_bar_meta.is_password,
            enabled: app_bar_meta.is_enabled,
            title: app_bar_meta.name.clone(),
            description: app_bar_meta.safe_description().map(str::to_string),
            automation_id: app_bar_meta.automation_id.clone(),
            class_name: app_bar_meta.class_name.clone(),
            child_count: None,
            is_submenu_opener: None,
        },
    ];
    let resolved_direct = MenuPathResolver::resolve(
        0usize,
        pid,
        None,
        Some(&5usize),
        None,
        None,
        |a, b| a == b,
        |idx, _| Some(nodes[*idx].clone()),
        |idx| (*idx + 1 < nodes.len()).then_some(*idx + 1),
        || true,
    )
    .expect("direct live MenuBar chain must resolve File -> Export -> PDF");
    assert_eq!(resolved_direct.path, vec!["File", "Export", "PDF"]);
    assert!(!resolved_direct.truncated);

    // (b) Win32 `#32768` popup parented to Window with `Win32MenuBarLink`:
    let win32_popup_nodes = [
        nodes[0].clone(),
        nodes[1].clone(),
        MenuNodeSnapshot {
            pid,
            control_type: Some(UIA_WINDOW_CONTROL_TYPE),
            role: Some("AXWindow".to_string()),
            subrole: SubroleRead::NoValue,
            protected_content: ProtectedContentRead::Value(false),
            enabled: Some(true),
            title: Some("Phase 5A Menu Test Window".to_string()),
            description: None,
            automation_id: None,
            class_name: Some("#32770".to_string()),
            child_count: None,
            is_submenu_opener: None,
        },
    ];
    let valid_link = Win32MenuBarLink {
        menu_bar_item_title: hmenu_file_title.clone(),
        submenu_titles: vec![hmenu_export_title.clone()],
        from_menu_bar_start: true,
    };
    let resolved_win32 = MenuPathResolver::resolve(
        0usize,
        pid,
        None,
        None,
        None,
        Some(&valid_link),
        |a, b| a == b,
        |idx, _| Some(win32_popup_nodes[*idx].clone()),
        |idx| (*idx + 1 < win32_popup_nodes.len()).then_some(*idx + 1),
        || true,
    )
    .expect("OBJID_MENU-linked Win32 #32768 popup must resolve File -> Export -> PDF");
    assert_eq!(resolved_win32.path, vec!["File", "Export", "PDF"]);

    // Right-click context menu (`from_menu_bar_start: false`) MUST be strictly rejected!
    let context_link = Win32MenuBarLink {
        menu_bar_item_title: hmenu_file_title,
        submenu_titles: vec![hmenu_export_title],
        from_menu_bar_start: false,
    };
    assert_eq!(
        MenuPathResolver::resolve(
            0usize,
            pid,
            None,
            None,
            None,
            Some(&context_link),
            |a, b| a == b,
            |idx, _| Some(win32_popup_nodes[*idx].clone()),
            |idx| (*idx + 1 < win32_popup_nodes.len()).then_some(*idx + 1),
            || true,
        ),
        None,
        "right-click #32768 context menu MUST be rejected"
    );

    // 5. Build canonical Wire v1 `menu.action` observation and validate with `ContractValidator`!
    let now_unix = clock.unix_ms();
    let stamp = Stamp {
        capture_epoch: 1,
        foreground_generation: 1,
        focus_generation: 1,
        policy_revision: 1,
    };
    let record = MenuActionRecord {
        application: ApplicationIdentity {
            application_id: "notepad.exe".to_string(),
            process_id: pid,
            process_start_time: "unix-ms:1700000000000.000".to_string(),
        },
        exe_name: Some("notepad.exe".to_string()),
        path: resolved_direct.path,
        truncated: resolved_direct.truncated,
        observed_at_ms: now_unix,
        private_state: "normal".to_string(),
        stamp,
        field_security: "strict".to_string(),
    };
    let target = ApplicationTargetIdentity {
        device_id: "dev-p5a-live".to_string(),
        os_session_id: "wts-1".to_string(),
        desktop_id: "winsta0-default-wts-1".to_string(),
        process_id: pid,
        process_start_time: record.application.process_start_time.clone(),
        application_id: record.application.application_id.clone(),
    };
    let mut envelope = BTreeMap::new();
    envelope.insert("protocolVersion".to_string(), json_i64(1));
    envelope.insert("type".to_string(), JsonValue::String("observation".to_string()));
    envelope.insert("eventId".to_string(), JsonValue::String("inst-live:1".to_string()));
    envelope.insert("instanceId".to_string(), JsonValue::String("inst-live".to_string()));
    envelope.insert("seq".to_string(), json_i64(1));
    envelope.insert("eventTimeMs".to_string(), json_i64(record.observed_at_ms));
    envelope.insert("monotonicMs".to_string(), json_i64(clock.monotonic_ms()));
    envelope.insert("target".to_string(), target.to_target_ref());
    envelope.insert("stamp".to_string(), stamp.to_json());
    envelope.insert("actor".to_string(), JsonValue::String("unknown".to_string()));
    envelope.insert("relatedActionIds".to_string(), JsonValue::Array(Vec::new()));
    envelope.insert("payload".to_string(), record.payload(false));

    let validator = ContractValidator::new().expect("ContractValidator::new");
    let frame = validator
        .encode_frame(&JsonValue::Object(envelope))
        .expect("live menu.action observation must pass ContractValidator");
    let text = std::str::from_utf8(&frame).unwrap();
    assert!(text.contains("\"source\":\"uia.menu\""));
    assert!(text.contains("\"path\":[\"File\",\"Export\",\"PDF\"]"));
    assert!(!text.contains("exeName"));
}

#[test]
fn live_mta_uia_menu_event_subscription_and_menu_commit_hook_zero_deadlock() {
    let win = SyntheticMenuWindow::spawn_with_file_export_pdf_menu();
    let _com = ComGuard::init_mta().expect("MTA COM init");
    let uia = UiaClient::new().expect("UiaClient::new");
    let root = uia
        .element_from_hwnd(win.hwnd)
        .expect("element_from_hwnd for subscription test");

    // 1. Live MTA `UiaMenuEventSubscription` attach -> detach cleanly.
    let (tx1, _rx1) = create_menu_event_channel();
    let sub1 = UiaMenuEventSubscription::attach(uia.automation(), &root, tx1)
        .expect("UiaMenuEventSubscription::attach (detach path)");
    assert!(sub1.is_active());
    assert_eq!(sub1.subscribed_event_count(), 3);
    sub1.detach();

    // 2. Live MTA `UiaMenuEventSubscription` attach -> `abandon_for_process_exit()` cleanly.
    let (tx2, _rx2) = create_menu_event_channel();
    let sub2 = UiaMenuEventSubscription::attach(uia.automation(), &root, tx2)
        .expect("UiaMenuEventSubscription::attach (abandon path)");
    assert!(sub2.is_active());
    assert_eq!(sub2.subscribed_event_count(), 3);
    sub2.abandon_for_process_exit();

    // 3. Live `MenuCommitHook` start -> toggle -> drain -> stop with zero deadlock.
    let menu_open = Arc::new(AtomicBool::new(false));
    let mut hook = MenuCommitHook::try_start(Arc::clone(&menu_open))
        .expect("MenuCommitHook::try_start on live desktop");
    assert!(hook.is_running());
    assert_ne!(hook.thread_id(), 0);
    assert!(!hook.is_menu_open());

    hook.set_menu_open(true);
    assert!(hook.is_menu_open());
    let _ = hook.drain_signals();
    hook.set_menu_open(false);
    assert!(!hook.is_menu_open());

    let stop_started = Instant::now();
    hook.stop();
    assert!(
        stop_started.elapsed() < Duration::from_secs(2),
        "MenuCommitHook::stop must join promptly without deadlock"
    );
    assert!(!hook.is_running());
    assert_eq!(hook.thread_id(), 0);
}

#[test]
fn live_session_worker_retire_ack_with_menu_actions_exits_cleanly() {
    let bin = collector_bin();
    let launch_token = generate_uuid_v4();
    let retire_token = generate_uuid_v4();
    let parent_pid = std::process::id().to_string();

    let mut child = Command::new(&bin)
        .args([
            "--ax-worker",
            "--parent-pid",
            &parent_pid,
            "--worker-token",
            &launch_token,
            "--session-worker",
            "yes",
        ])
        .env("DSH_COLLECTOR_WORKER_TOKEN", &launch_token)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn session worker");

    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);

    // 1. Deliver a live `ReadTicket` with `menu_actions: Some(true)` so `LiveUiaSession`
    // activates `MenuActionSession` (`WinEventWatcher` menu events + UIA subscriber + hook).
    let now_mono = SystemCollectorClock::monotonic_ms_now();
    let ticket = ReadTicket {
        token: launch_token.clone(),
        policy_revision: 1,
        capture_epoch: 1,
        policy: CapturePolicy {
            enabled: true,
            application_scope: Some("denylist".to_string()),
            menu_actions: Some(true),
            debounce_ms: 50,
            max_wait_ms: 100,
            read_timeout_ms: 2_000,
            ..CapturePolicy::default()
        },
        hint: None,
        deadline_monotonic_ms: now_mono + 2_500,
        device_id: "dev-live-retire".to_string(),
        os_session_id: "wts-live".to_string(),
        desktop_id: "winsta0-default-wts-live".to_string(),
        foreground_generation: Some(1),
        focus_generation: Some(1),
        debug_request_id: Some(1),
        read_only_ax_enablement: None,
        focused_fast_only: None,
    };
    let mut ticket_bytes = ticket.to_json().canonical_bytes().unwrap();
    ticket_bytes.push(b'\n');
    stdin.write_all(&ticket_bytes).unwrap();
    stdin.flush().unwrap();

    // Read until we receive the `ReadResult` matching `launch_token`.
    let mut saw_read_result = false;
    for _ in 0..8 {
        let mut line = String::new();
        let n = reader.read_line(&mut line).expect("read worker response");
        assert!(n > 0, "worker must not EOF before ReadResult");
        let parsed = JsonValue::parse_str(line.trim_end()).expect("valid JSON line");
        if let Some(res) = ReadResult::from_json(&parsed) {
            assert_eq!(res.token, launch_token);
            saw_read_result = true;
            break;
        }
    }
    assert!(saw_read_result, "session worker must reply with ReadResult");

    // 2. Send the `retire` handshake while keeping stdin open so exit 0 proves clean retire ACK
    // (including `UiaMenuEventSubscription::abandon_for_process_exit()` + `MenuCommitHook::stop()`).
    let retire_cmd =
        format!("{{\"retire\":\"{retire_token}\",\"sessionToken\":\"{launch_token}\"}}\n");
    stdin.write_all(retire_cmd.as_bytes()).unwrap();
    stdin.flush().unwrap();

    let mut ack_json = None;
    for _ in 0..16 {
        let mut line = String::new();
        let n = reader.read_line(&mut line).expect("read retire ACK");
        if n == 0 {
            break;
        }
        let parsed = JsonValue::parse_str(line.trim_end()).expect("valid JSON line");
        if parsed.get("retired").is_some() {
            ack_json = Some(parsed);
            break;
        }
    }
    let parsed = ack_json.expect("session worker must emit retired ACK");
    assert_eq!(
        parsed.get("inputHealthy").and_then(JsonValue::as_bool),
        Some(true)
    );
    assert_eq!(
        parsed.get("retired").and_then(JsonValue::as_str),
        Some(retire_token.as_str())
    );
    assert_eq!(
        parsed.get("sessionToken").and_then(JsonValue::as_str),
        Some(launch_token.as_str())
    );

    let status = child.wait().expect("wait session worker exit");
    assert_eq!(status.code(), Some(0));
    drop(stdin);
}
