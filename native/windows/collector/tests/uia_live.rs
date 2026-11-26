//! Comprehensive live Windows UI Automation (UIA), DPI normalization, surface baseline,
//! WinEvent watcher, and Non-Negotiable Invariant #2 privacy-gate integration tests.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::sync::{mpsc, Mutex, MutexGuard, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use history_contract::{utf16_len, ContractValidator, JsonValue};
use collector_core::engine::{
    CollectorEngine, CollectorEnvironment, EngineOutput, MonitoringCheck,
};
use collector_core::policy::ResolvedAppIdentity;
use collector_core::protocol_model::{
    generate_uuid_v4, json_i64, CapturePolicy, CollectorClock, DesktopStatus, GapDiagnosticCode,
    SurfaceBounds, SurfaceReadFailure, SystemCollectorClock,
};
use collector_core::uia_com::{ComGuard, PrivateChromeVerdict, UiaClient};
use collector_core::uia_traversal::{
    RuntimeIdKey, SurfaceChildFrontier, SurfaceFocusAnchors, SurfaceNodeMap,
    WeightedSurfaceChildrenRead, WeightedSurfaceInspection, WeightedSurfaceMetadata,
    WeightedSurfaceTextRead, WeightedSurfaceTraversal, WeightedSurfaceTraversalLimits,
};
use collector_core::uia_worker::{
    read_window_for_test, read_window_with_identity_for_test, sanitize_display_url, LiveUiaSession,
};
use collector_core::worker_ipc::{ReadTicket, ReadTimeoutCleanup, WorkerEvent};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DestroyWindow, DispatchMessageW, GetMessageW, PeekMessageW,
    PostThreadMessageW, SendMessageW, SetWindowTextW, TranslateMessage, ES_AUTOVSCROLL,
    ES_MULTILINE, ES_PASSWORD, MSG, PM_NOREMOVE, WINDOW_EX_STYLE, WINDOW_STYLE, WM_QUIT, WS_CHILD,
    WS_OVERLAPPEDWINDOW, WS_POPUP, WS_VISIBLE,
};

const EM_SETSEL: u32 = 0x00B1;

static TEST_MTA_KEEPALIVE: OnceLock<()> = OnceLock::new();
static LIVE_UIA_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Serialize live Win32/UIA tests within this test binary so parallel `cargo test` threads cannot
/// clobber `UIAutomationCore.dll`'s process-wide `SetConnectionTimeout` / `SetTransactionTimeout`
/// settings (e.g. `warmup_window_uia` decaying to 25 ms) or starve a 2-vCPU CI runner with a dozen
/// concurrent `CreateWindowExW` + `CUIAutomation8` tree walks.
fn lock_live_uia_test() -> MutexGuard<'static, ()> {
    LIVE_UIA_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Keep one process-wide MTA COM + `UiaClient` singleton initialized for the lifetime of the
/// `uia_live` test binary so parallel `#[test]` threads do not race `UIAutomationCore.dll`'s
/// cold-start `CUIAutomation8::ControlViewWalker()` initialization or repeatedly tear down its
/// internal client thread between sequential tests.
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

struct SyntheticWindowSpec {
    title: String,
    overlapped: bool,
    edit_text: String,
    password_text: Option<String>,
    static_label: Option<String>,
    pua_label: Option<String>,
    button_labels: Vec<String>,
}

struct SyntheticWin32Window {
    window_hwnd: HWND,
    edit_hwnd: HWND,
    password_hwnd: Option<HWND>,
    thread_id: u32,
    handle: Option<JoinHandle<()>>,
}

impl SyntheticWin32Window {
    fn spawn(spec: SyntheticWindowSpec) -> Self {
        ensure_test_mta_apartment();
        let (tx, rx) = mpsc::sync_channel::<(isize, isize, Option<isize>, u32)>(1);
        let handle = thread::spawn(move || {
            let class_wide = to_wide("#32770");
            let title_wide = to_wide(&spec.title);

            // SAFETY: Minimal pre-registered Win32 dialog/window class ("#32770") created & pumped
            // on a dedicated test UI thread so MTA UIA calls from the test thread never deadlock.
            unsafe {
                let mut init_msg = MSG::default();
                let _ = PeekMessageW(&mut init_msg, None, 0, 0, PM_NOREMOVE);

                let style = if spec.overlapped {
                    WS_OVERLAPPEDWINDOW | WS_VISIBLE
                } else {
                    WS_POPUP | WS_VISIBLE
                };
                // Place at deterministic visible coordinates (40, 40) size 420x320.
                let hwnd = CreateWindowExW(
                    WINDOW_EX_STYLE(0),
                    PCWSTR(class_wide.as_ptr()),
                    PCWSTR(title_wide.as_ptr()),
                    style,
                    40,
                    40,
                    420,
                    320,
                    None,
                    None,
                    None,
                    None,
                )
                .expect("CreateWindowExW top-level window");

                let static_class = to_wide("STATIC");
                let edit_class = to_wide("EDIT");
                let button_class = to_wide("BUTTON");

                for (i, label) in spec.button_labels.iter().enumerate() {
                    let w = to_wide(label);
                    let _ = CreateWindowExW(
                        WINDOW_EX_STYLE(0),
                        PCWSTR(button_class.as_ptr()),
                        PCWSTR(w.as_ptr()),
                        WS_CHILD | WS_VISIBLE,
                        12 + (i as i32) * 110,
                        230,
                        104,
                        28,
                        Some(hwnd),
                        None,
                        None,
                        None,
                    )
                    .expect("CreateWindowExW BUTTON");
                }

                if let Some(ref label) = spec.static_label {
                    let w = to_wide(label);
                    let _ = CreateWindowExW(
                        WINDOW_EX_STYLE(0),
                        PCWSTR(static_class.as_ptr()),
                        PCWSTR(w.as_ptr()),
                        WS_CHILD | WS_VISIBLE,
                        12,
                        12,
                        360,
                        28,
                        Some(hwnd),
                        None,
                        None,
                        None,
                    )
                    .expect("CreateWindowExW STATIC");
                }

                if let Some(ref pua) = spec.pua_label {
                    let w = to_wide(pua);
                    let _ = CreateWindowExW(
                        WINDOW_EX_STYLE(0),
                        PCWSTR(static_class.as_ptr()),
                        PCWSTR(w.as_ptr()),
                        WS_CHILD | WS_VISIBLE,
                        380,
                        12,
                        24,
                        24,
                        Some(hwnd),
                        None,
                        None,
                        None,
                    );
                }

                let edit_w = to_wide(&spec.edit_text);
                let edit_hwnd = CreateWindowExW(
                    WINDOW_EX_STYLE(0),
                    PCWSTR(edit_class.as_ptr()),
                    PCWSTR(edit_w.as_ptr()),
                    WS_CHILD
                        | WS_VISIBLE
                        | WINDOW_STYLE((ES_MULTILINE | ES_AUTOVSCROLL) as u32),
                    12,
                    52,
                    380,
                    120,
                    Some(hwnd),
                    None,
                    None,
                    None,
                )
                .expect("CreateWindowExW multiline EDIT");

                let password_hwnd = spec.password_text.as_ref().map(|secret| {
                    let w = to_wide(secret);
                    CreateWindowExW(
                        WINDOW_EX_STYLE(0),
                        PCWSTR(edit_class.as_ptr()),
                        PCWSTR(w.as_ptr()),
                        WS_CHILD | WS_VISIBLE | WINDOW_STYLE(ES_PASSWORD as u32),
                        12,
                        190,
                        380,
                        28,
                        Some(hwnd),
                        None,
                        None,
                        None,
                    )
                    .expect("CreateWindowExW ES_PASSWORD EDIT")
                });

                let tid = GetCurrentThreadId();
                tx.send((
                    hwnd.0 as isize,
                    edit_hwnd.0 as isize,
                    password_hwnd.map(|h| h.0 as isize),
                    tid,
                ))
                .unwrap();

                let mut msg = MSG::default();
                while GetMessageW(&mut msg, None, 0, 0).0 > 0 {
                    let _ = TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
                let _ = DestroyWindow(hwnd);
            }
        });

        let (win_raw, edit_raw, pw_raw, thread_id) = rx.recv().expect("window thread init");
        // Allow UIA tree initialization to settle briefly.
        thread::sleep(Duration::from_millis(30));
        Self {
            window_hwnd: HWND(win_raw as *mut core::ffi::c_void),
            edit_hwnd: HWND(edit_raw as *mut core::ffi::c_void),
            password_hwnd: pw_raw.map(|r| HWND(r as *mut core::ffi::c_void)),
            thread_id,
            handle: Some(handle),
        }
    }

    fn set_edit_text(&self, text: &str) {
        let w = to_wide(text);
        // SAFETY: Valid child EDIT HWND whose UI thread is actively pumping messages.
        unsafe {
            let _ = SetWindowTextW(self.edit_hwnd, PCWSTR(w.as_ptr()));
        }
    }

    fn set_edit_selection(&self, start_utf16: usize, end_utf16: usize) {
        // SAFETY: Standard EM_SETSEL message on live EDIT control.
        unsafe {
            let _ = SendMessageW(
                self.edit_hwnd,
                EM_SETSEL,
                Some(WPARAM(start_utf16)),
                Some(LPARAM(end_utf16 as isize)),
            );
        }
    }
}

impl Drop for SyntheticWin32Window {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            // SAFETY: Posting WM_QUIT exits the UI thread's GetMessageW loop so DestroyWindow runs.
            unsafe {
                let _ = PostThreadMessageW(self.thread_id, WM_QUIT, WPARAM(0), LPARAM(0));
            }
            let _ = handle.join();
        }
    }
}

struct MockEnv {
    launched: Vec<ReadTicket>,
}

impl MockEnv {
    fn new() -> Self {
        Self {
            launched: Vec::new(),
        }
    }
}

impl CollectorEnvironment for MockEnv {
    fn desktop_reason(&self) -> &str {
        "ready"
    }
    fn begin_monitoring(&mut self) -> MonitoringCheck {
        MonitoringCheck {
            desktop: DesktopStatus::Unlocked,
            accessibility: true,
        }
    }
    fn validate_before_accept(&mut self) -> MonitoringCheck {
        MonitoringCheck {
            desktop: DesktopStatus::Unlocked,
            accessibility: true,
        }
    }
    fn end_monitoring(&mut self) {}
    fn launch(&mut self, ticket: ReadTicket) -> Option<WorkerEvent> {
        self.launched.push(ticket);
        None
    }
    fn cancel_read(&mut self) -> ReadTimeoutCleanup {
        ReadTimeoutCleanup::Reaped
    }
}

fn configure_msg(rev: i64, policy: &CapturePolicy) -> JsonValue {
    let mut map = BTreeMap::new();
    map.insert("protocolVersion".to_string(), json_i64(1));
    map.insert("type".to_string(), JsonValue::String("configure".to_string()));
    map.insert("requestId".to_string(), JsonValue::String(format!("cfg-{rev}")));
    map.insert("ownerId".to_string(), JsonValue::String("owner-uia".to_string()));
    map.insert("instanceId".to_string(), JsonValue::String("inst-uia".to_string()));
    map.insert("policyRevision".to_string(), json_i64(rev));
    map.insert("policy".to_string(), policy.to_json());
    JsonValue::Object(map)
}

fn control_msg(rev: i64, cmd: &str) -> JsonValue {
    let mut map = BTreeMap::new();
    map.insert("protocolVersion".to_string(), json_i64(1));
    map.insert("type".to_string(), JsonValue::String("control".to_string()));
    map.insert("requestId".to_string(), JsonValue::String(format!("ctl-{cmd}-{rev}")));
    map.insert("ownerId".to_string(), JsonValue::String("owner-uia".to_string()));
    map.insert("instanceId".to_string(), JsonValue::String("inst-uia".to_string()));
    map.insert("policyRevision".to_string(), json_i64(rev));
    map.insert("command".to_string(), JsonValue::String(cmd.to_string()));
    map.insert("leaseDurationMs".to_string(), json_i64(10_000));
    JsonValue::Object(map)
}

fn make_ticket(policy: CapturePolicy, clock: &SystemCollectorClock) -> ReadTicket {
    ReadTicket {
        token: generate_uuid_v4(),
        policy_revision: 1,
        capture_epoch: 1,
        policy,
        hint: None,
        deadline_monotonic_ms: clock.monotonic_ms() + 3_000,
        device_id: "dev-uia-test".to_string(),
        os_session_id: "wts-1".to_string(),
        desktop_id: "winsta0-default-wts-1".to_string(),
        foreground_generation: Some(1),
        focus_generation: Some(1),
        debug_request_id: Some(1),
        read_only_ax_enablement: None,
        focused_fast_only: None,
    }
}

fn emitted_messages(outputs: Vec<EngineOutput>) -> Vec<JsonValue> {
    outputs
        .into_iter()
        .filter_map(|o| match o {
            EngineOutput::Emit(m) => Some(m),
            EngineOutput::DiscardQueuedObservations => None,
        })
        .collect()
}

#[test]
fn live_uia_plaintext_edit_utf16_cjk_emoji_and_wire_validation() {
    let _guard = lock_live_uia_test();
    let validator = ContractValidator::new().expect("schema loads");
    let clock = SystemCollectorClock;
    let sample_text = "Hello 可见🙂 world";
    let win = SyntheticWin32Window::spawn(SyntheticWindowSpec {
        title: "UIA Plaintext Test".to_string(),
        overlapped: false,
        edit_text: sample_text.to_string(),
        password_text: None,
        static_label: Some("Editor Label".to_string()),
        pua_label: None,
        button_labels: Vec::new(),
    });

    // Select "可见🙂" (UTF-16 indices 6..10: "Hello " = 6, "可" = 1, "见" = 1, "🙂" = 2).
    win.set_edit_selection(6, 10);

    let policy = CapturePolicy {
        enabled: true,
        allowed_application_ids: vec!["test-editor.exe".to_string()],
        field_security: Some("strict".to_string()),
        selection_capture: Some(true),
        max_text_code_units: 512,
        debounce_ms: 0,
        max_wait_ms: 1,
        read_timeout_ms: 3_000,
        ..CapturePolicy::default()
    };

    let mut engine = CollectorEngine::new(
        "owner-uia",
        "inst-uia",
        "dev-uia-test",
        "wts-1",
        "winsta0-default-wts-1",
        false,
        MockEnv::new(),
        clock,
        validator.clone(),
    );
    engine.receive(&configure_msg(1, &policy));
    engine.receive(&control_msg(1, "start"));
    let _ = engine.drain_outputs();
    thread::sleep(Duration::from_millis(5));
    engine.tick(true);
    let ticket = engine.environment.launched.pop().expect("ticket launched");

    // First confirm Locked desktop gate blocks pre-read with DesktopUnavailable & zero text.
    let locked_res = read_window_for_test(
        win.window_hwnd,
        Some(win.edit_hwnd),
        Some("test-editor.exe"),
        Some(DesktopStatus::Locked),
        &ticket,
        &clock,
    );
    assert_eq!(locked_res.reason.as_deref(), Some("desktop-unavailable"));
    assert_eq!(
        locked_res.diagnostic.map(|d| d.code),
        Some(GapDiagnosticCode::DesktopUnavailable)
    );
    assert!(locked_res.text.is_none());

    let res = read_window_for_test(
        win.window_hwnd,
        Some(win.edit_hwnd),
        Some("test-editor.exe"),
        Some(DesktopStatus::Unlocked),
        &ticket,
        &clock,
    );
    assert_eq!(res.reason, None, "unexpected failure: {:?}", res.diagnostic);
    let tr = res.text.as_ref().expect("text read present");
    assert_eq!(tr.text, sample_text);
    assert!(matches!(tr.source.as_str(), "uia.text" | "uia.value"));
    assert!(tr.complete);
    assert!(!tr.truncated);
    assert_eq!(tr.total_length, Some(utf16_len(sample_text)));

    // Selection capture on Win32 multiline EDIT must return exact UTF-16 slice "可见🙂".
    let sel = res.selection.as_ref().expect("selection read present");
    assert_eq!(sel.source, "uia.text");
    assert_eq!(sel.text, "可见🙂");
    assert_eq!(sel.range_start, 6);
    assert!(sel.missing_reasons.iter().any(|r| r == "selection-only"));

    // Feed through CollectorEngine and verify every emitted Wire v1 message passes schema validation.
    engine.complete(res);
    let msgs = emitted_messages(engine.drain_outputs());
    let text_msg = msgs
        .iter()
        .find(|m| {
            m.get("payload")
                .and_then(|p| p.get("kind"))
                .and_then(JsonValue::as_str)
                == Some("text.snapshot")
        })
        .expect("text.snapshot emitted");
    assert!(
        msgs.iter().any(|m| {
            m.get("payload")
                .and_then(|p| p.get("kind"))
                .and_then(JsonValue::as_str)
                == Some("selection.snapshot")
        }),
        "selection.snapshot emitted"
    );
    for msg in &msgs {
        validator
            .validate_message(msg)
            .expect("wire message must validate against wire.schema.json");
    }
    let payload = text_msg.get("payload").unwrap();
    assert_eq!(
        payload.get("text").and_then(JsonValue::as_str),
        Some(sample_text)
    );
    assert_eq!(
        payload
            .get("range")
            .and_then(|r| r.get("length"))
            .and_then(JsonValue::as_u64),
        Some(utf16_len(sample_text) as u64)
    );

    // Bounded UTF-16 truncation at limit=9 (inside the surrogate pair "🙂" at UTF-16 indices 8..10)
    // MUST NOT bisect the surrogate pair and MUST yield "Hello 可见" (8 UTF-16 units).
    let truncated_policy = CapturePolicy {
        max_text_code_units: 9,
        selection_capture: Some(false),
        ..policy.clone()
    };
    let trunc_ticket = make_ticket(truncated_policy, &clock);
    let trunc_res = read_window_for_test(
        win.window_hwnd,
        Some(win.edit_hwnd),
        Some("test-editor.exe"),
        Some(DesktopStatus::Unlocked),
        &trunc_ticket,
        &clock,
    );
    let trunc_text = trunc_res.text.expect("truncated text read");
    assert_eq!(trunc_text.text, "Hello 可见");
    assert!(trunc_text.truncated);
    assert!(!trunc_text.complete);
    assert!(trunc_text.missing_reasons.iter().any(|r| r == "text-budget"));

    // Visible range mode ("visible") on live multiline EDIT via uia.text.
    let vis_policy = CapturePolicy {
        text_range: Some("visible".to_string()),
        max_text_code_units: 512,
        selection_capture: Some(false),
        ..policy.clone()
    };
    let mut vis_engine = CollectorEngine::new(
        "owner-uia",
        "inst-uia",
        "dev-uia-test",
        "wts-1",
        "winsta0-default-wts-1",
        false,
        MockEnv::new(),
        clock,
        validator.clone(),
    );
    vis_engine.receive(&configure_msg(1, &vis_policy));
    vis_engine.receive(&control_msg(1, "start"));
    let _ = vis_engine.drain_outputs();
    thread::sleep(Duration::from_millis(5));
    vis_engine.tick(true);
    let vis_ticket = vis_engine.environment.launched.pop().expect("vis ticket");
    let vis_res = read_window_for_test(
        win.window_hwnd,
        Some(win.edit_hwnd),
        Some("test-editor.exe"),
        Some(DesktopStatus::Unlocked),
        &vis_ticket,
        &clock,
    );
    let vis_text = vis_res.text.as_ref().expect("visible range read present");
    assert_eq!(vis_text.source, "uia.text");
    assert_eq!(vis_text.range_basis, "visible");
    assert!(!vis_text.complete);
    assert_eq!(vis_text.total_length, Some(utf16_len(sample_text)));
    assert!(vis_text
        .missing_reasons
        .iter()
        .any(|r| r == "visible-range-only"));
    vis_engine.complete(vis_res);
    let vis_msgs = emitted_messages(vis_engine.drain_outputs());
    for msg in &vis_msgs {
        validator
            .validate_message(msg)
            .expect("visible range text.snapshot valid");
    }

    // Mandatory excluded password managers & Windows System UI silently skip BEFORE any UIA read.
    for blocked_app in ["1password.exe", "protonpass.exe", "lockapp.exe"] {
        let deny_policy = CapturePolicy {
            enabled: true,
            application_scope: Some("denylist".to_string()),
            allow_browser_content: Some(true),
            capture_scope: Some("window".to_string()),
            ..CapturePolicy::default()
        };
        let deny_ticket = make_ticket(deny_policy, &clock);
        let deny_res = read_window_for_test(
            win.window_hwnd,
            Some(win.edit_hwnd),
            Some(blocked_app),
            Some(DesktopStatus::Unlocked),
            &deny_ticket,
            &clock,
        );
        assert_eq!(
            deny_res.reason.as_deref(),
            Some("application-excluded"),
            "app={blocked_app}"
        );
        assert_eq!(
            deny_res.diagnostic.map(|d| d.code),
            Some(GapDiagnosticCode::ApplicationNotAllowed),
            "app={blocked_app}"
        );
        assert!(deny_res.text.is_none());
        assert!(deny_res.surface.is_none());
    }
}

#[test]
fn live_uia_password_edit_blocked_pre_read_zero_leakage() {
    let _guard = lock_live_uia_test();
    let clock = SystemCollectorClock;
    let secret_focused = "TopSecretPass!999";
    let secret_sibling = "SiblingSecret#42";

    let win = SyntheticWin32Window::spawn(SyntheticWindowSpec {
        title: "Login Form".to_string(),
        overlapped: false,
        edit_text: "alice@example.com".to_string(),
        password_text: Some(secret_focused.to_string()),
        static_label: Some("Username".to_string()),
        pua_label: None,
        button_labels: Vec::new(),
    });
    let pw_hwnd = win.password_hwnd.expect("password hwnd created");

    // 1. Focused ES_PASSWORD field MUST be blocked pre-read in BOTH strict AND denylist modes!
    for sec_mode in ["strict", "denylist"] {
        let policy = CapturePolicy {
            enabled: true,
            allowed_application_ids: vec!["login-app.exe".to_string()],
            field_security: Some(sec_mode.to_string()),
            capture_scope: Some("window".to_string()),
            max_tree_nodes: Some(32),
            max_text_code_units: 512,
            ..CapturePolicy::default()
        };
        let ticket = make_ticket(policy, &clock);
        let res = read_window_for_test(
            win.window_hwnd,
            Some(pw_hwnd),
            Some("login-app.exe"),
            Some(DesktopStatus::Unlocked),
            &ticket,
            &clock,
        );
        assert_eq!(res.reason.as_deref(), Some("policy-boundary"), "mode={sec_mode}");
        assert_eq!(
            res.diagnostic.map(|d| d.code),
            Some(GapDiagnosticCode::SecureField),
            "mode={sec_mode}"
        );
        assert_eq!(
            res.diagnostic.and_then(|d| d.role),
            Some("AXSecureTextField"),
            "mode={sec_mode}"
        );
        assert!(res.text.is_none(), "ZERO text allowed on password field");
        assert!(res.surface.is_none(), "ZERO surface allowed when password focused");
        assert_eq!(
            res.surface_failure,
            Some(SurfaceReadFailure::SecurityExcluded)
        );
        let serialized = String::from_utf8(res.to_json().canonical_bytes().unwrap()).unwrap();
        assert!(
            !serialized.contains(secret_focused),
            "password text MUST NEVER leak into ReadResult JSON"
        );
    }

    // 2. Sibling ES_PASSWORD control in a surface tree read MUST be pruned with ZERO leakage.
    let win2 = SyntheticWin32Window::spawn(SyntheticWindowSpec {
        title: "Login Form Sibling".to_string(),
        overlapped: false,
        edit_text: "visible-username".to_string(),
        password_text: Some(secret_sibling.to_string()),
        static_label: Some("Account".to_string()),
        pua_label: None,
        button_labels: Vec::new(),
    });
    let policy_surface = CapturePolicy {
        enabled: true,
        allowed_application_ids: vec!["login-app.exe".to_string()],
        field_security: Some("denylist".to_string()),
        capture_scope: Some("window".to_string()),
        max_tree_nodes: Some(32),
        max_text_code_units: 512,
        ..CapturePolicy::default()
    };
    let ticket2 = make_ticket(policy_surface, &clock);
    let res2 = read_window_for_test(
        win2.window_hwnd,
        Some(win2.edit_hwnd),
        Some("login-app.exe"),
        Some(DesktopStatus::Unlocked),
        &ticket2,
        &clock,
    );
    assert_eq!(res2.text.as_ref().map(|t| t.text.as_str()), Some("visible-username"));
    let surf = res2.surface.as_ref().expect("surface captured");
    assert!(
        surf.missing_reasons
            .iter()
            .any(|r| r == "tree-security-pruned"),
        "sibling password field must trigger tree-security-pruned: {:?}",
        surf.missing_reasons
    );
    let serialized2 = String::from_utf8(res2.to_json().canonical_bytes().unwrap()).unwrap();
    assert!(
        !serialized2.contains(secret_sibling),
        "sibling password MUST NEVER leak into surface snapshot JSON"
    );
    assert!(
        !serialized2.contains("AXSecureTextField"),
        "password node must be pruned from surface nodes"
    );
}

#[test]
fn live_uia_surface_tree_geometry_pua_filter_and_full_to_diff_baseline() {
    let _guard = lock_live_uia_test();
    let validator = ContractValidator::new().expect("schema loads");
    let clock = SystemCollectorClock;
    let win = SyntheticWin32Window::spawn(SyntheticWindowSpec {
        title: "Surface Baseline Test".to_string(),
        overlapped: false,
        edit_text: "First message 可见🙂".to_string(),
        password_text: None,
        static_label: Some("Chat Header Title".to_string()),
        pua_label: Some("\u{E000}\u{E001}".to_string()),
        button_labels: Vec::new(),
    });

    let policy = CapturePolicy {
        enabled: true,
        allowed_application_ids: vec!["surface-app.exe".to_string()],
        field_security: Some("strict".to_string()),
        capture_scope: Some("window".to_string()),
        max_tree_nodes: Some(32),
        max_text_code_units: 1_024,
        debounce_ms: 0,
        max_wait_ms: 1,
        read_timeout_ms: 3_000,
        ..CapturePolicy::default()
    };

    let mut engine = CollectorEngine::new(
        "owner-uia",
        "inst-uia",
        "dev-uia-test",
        "wts-1",
        "winsta0-default-wts-1",
        false,
        MockEnv::new(),
        clock,
        validator.clone(),
    );
    engine.receive(&configure_msg(1, &policy));
    engine.receive(&control_msg(1, "start"));
    let _ = engine.drain_outputs();

    let mut session = LiveUiaSession::new(None);
    assert!(session.is_com_ready(), "MTA COM + IUIAutomation must initialize");

    // --- Snapshot 1: full ---
    thread::sleep(Duration::from_millis(5));
    engine.tick(true);
    let ticket1 = engine.environment.launched.pop().expect("ticket1");

    let res1 = session.read_window_for_test(
        win.window_hwnd,
        Some(win.edit_hwnd),
        Some("surface-app.exe"),
        Some(DesktopStatus::Unlocked),
        &ticket1,
        &clock,
    );
    assert_eq!(res1.reason, None, "unexpected failure: {:?}", res1.diagnostic);
    let surf1 = res1.surface.as_ref().expect("surface1 present");
    assert_eq!(surf1.mode, "full");
    assert_eq!(surf1.revision, 1);
    assert!(surf1.complete, "clean WS_POPUP surface should be complete, missing={:?}", surf1.missing_reasons);

    let geom1 = surf1.geometry.as_ref().expect("DPI-normalized SurfaceGeometry present");
    assert_eq!(geom1.coordinate_space, "window-top-left-point");
    assert!(geom1.window_size.width > 0.0 && geom1.window_size.height > 0.0);

    let static_node = surf1
        .nodes
        .iter()
        .find(|n| n.text.as_deref() == Some("Chat Header Title"))
        .expect("STATIC label must be captured");
    assert_eq!(static_node.ax_role.as_deref(), Some("AXStaticText"));
    assert!(static_node.bounds.is_some());
    assert!(static_node.bounds_observed_at_ms.is_some());

    let edit_node1 = surf1
        .nodes
        .iter()
        .find(|n| n.text.as_deref() == Some("First message 可见🙂"))
        .expect("EDIT node must be captured");
    assert_eq!(edit_node1.focused, Some(true));
    assert!(matches!(
        edit_node1.ax_role.as_deref(),
        Some("AXTextArea" | "AXTextField")
    ));
    let stable_edit_id = edit_node1.id.clone();

    // Pure-PUA Codicon label "\u{E000}\u{E001}" MUST be filtered out!
    assert!(
        !surf1
            .nodes
            .iter()
            .any(|n| n.text.as_deref().is_some_and(|t| t.contains('\u{E000}'))),
        "pure-PUA icon leaf must be excluded from surface snapshot"
    );

    // Validate Wire v1 frame emitted by CollectorEngine.
    engine.complete(res1);
    let msgs1 = emitted_messages(engine.drain_outputs());
    let surf_msg1 = msgs1
        .iter()
        .find(|m| {
            m.get("payload")
                .and_then(|p| p.get("kind"))
                .and_then(JsonValue::as_str)
                == Some("surface.snapshot")
        })
        .expect("surface.snapshot #1 emitted");
    for msg in &msgs1 {
        validator.validate_message(msg).expect("snapshot #1 wire valid");
    }
    assert_eq!(
        surf_msg1
            .get("payload")
            .and_then(|p| p.get("source"))
            .and_then(JsonValue::as_str),
        Some("uia.tree")
    );
    assert_eq!(
        surf_msg1
            .get("payload")
            .and_then(|p| p.get("mode"))
            .and_then(JsonValue::as_str),
        Some("full")
    );

    // --- Snapshot 2: mutate EDIT text -> expect diff with same stable RuntimeId UUID ---
    win.set_edit_text("Second message updated!");
    thread::sleep(Duration::from_millis(20));

    // Trigger immediate debounced dirty read in engine.
    engine.worker_dirty();
    thread::sleep(Duration::from_millis(5));
    engine.tick(true);
    let ticket2 = engine.environment.launched.pop().expect("ticket2");

    let res2 = session.read_window_for_test(
        win.window_hwnd,
        Some(win.edit_hwnd),
        Some("surface-app.exe"),
        Some(DesktopStatus::Unlocked),
        &ticket2,
        &clock,
    );
    let surf2 = res2.surface.as_ref().expect("surface2 present");
    assert_eq!(surf2.mode, "diff");
    assert_eq!(surf2.revision, 2);
    assert_eq!(surf2.base_revision, Some(1));
    assert!(
        surf2.updated.contains(&stable_edit_id),
        "updated diff must reference the exact stable EDIT node UUID {stable_edit_id}: updated={:?}",
        surf2.updated
    );
    assert!(surf2.added.is_empty());
    assert!(surf2.removed.is_empty());

    engine.complete(res2);
    let msgs2 = emitted_messages(engine.drain_outputs());
    let surf_msg2 = msgs2
        .iter()
        .find(|m| {
            m.get("payload")
                .and_then(|p| p.get("kind"))
                .and_then(JsonValue::as_str)
                == Some("surface.snapshot")
        })
        .expect("surface.snapshot #2 emitted");
    for msg in &msgs2 {
        validator.validate_message(msg).expect("snapshot #2 diff wire valid");
    }
    assert_eq!(
        surf_msg2
            .get("payload")
            .and_then(|p| p.get("mode"))
            .and_then(JsonValue::as_str),
        Some("diff")
    );
    assert_eq!(
        surf_msg2
            .get("payload")
            .and_then(|p| p.get("baseRevision"))
            .and_then(JsonValue::as_i64),
        Some(1)
    );

    assert!(session.retire_healthy());
}

#[test]
fn live_uia_private_browser_window_title_gate_aborts_pre_read() {
    let _guard = lock_live_uia_test();
    let clock = SystemCollectorClock;
    let secret_body = "SensitiveBrowserText123";

    for (app_id, title) in [
        ("chrome.exe", "Secret - Google Chrome (Incognito)"),
        ("msedge.exe", "机密页面 - 隐私浏览"),
    ] {
        let win = SyntheticWin32Window::spawn(SyntheticWindowSpec {
            title: title.to_string(),
            overlapped: true,
            edit_text: secret_body.to_string(),
            password_text: None,
            static_label: Some("Address Bar".to_string()),
            pua_label: None,
            button_labels: Vec::new(),
        });

        let policy = CapturePolicy {
            enabled: true,
            application_scope: Some("denylist".to_string()),
            allow_browser_content: Some(true),
            capture_scope: Some("window".to_string()),
            max_tree_nodes: Some(32),
            max_text_code_units: 512,
            ..CapturePolicy::default()
        };
        let ticket = make_ticket(policy, &clock);
        let res = read_window_for_test(
            win.window_hwnd,
            Some(win.edit_hwnd),
            Some(app_id),
            Some(DesktopStatus::Unlocked),
            &ticket,
            &clock,
        );

        assert_eq!(res.reason.as_deref(), Some("policy-boundary"), "title={title}");
        assert_eq!(
            res.diagnostic.map(|d| d.code),
            Some(GapDiagnosticCode::BrowserExcluded),
            "title={title}"
        );
        assert_eq!(
            res.surface_failure,
            Some(SurfaceReadFailure::SecurityExcluded),
            "title={title}"
        );
        assert!(res.text.is_none());
        assert!(res.surface.is_none());
        assert!(res.diagnostic_application.is_none());

        let serialized = String::from_utf8(res.to_json().canonical_bytes().unwrap()).unwrap();
        assert!(
            !serialized.contains(secret_body),
            "browser body leaked for private title {title}"
        );
        assert!(
            !serialized.contains("Incognito") && !serialized.contains("隐私浏览"),
            "window title MUST NEVER leak into ReadResult JSON"
        );
    }
}

#[test]
fn live_uia_unfocused_window_fallback_and_engine_validation() {
    let _guard = lock_live_uia_test();
    let validator = ContractValidator::new().expect("schema loads");
    let clock = SystemCollectorClock;
    let win = SyntheticWin32Window::spawn(SyntheticWindowSpec {
        title: "Unfocused VSCode Window".to_string(),
        overlapped: false,
        edit_text: "fn main() {}".to_string(),
        password_text: None,
        static_label: Some("main.rs".to_string()),
        pua_label: None,
        button_labels: Vec::new(),
    });

    let policy = CapturePolicy {
        enabled: true,
        allowed_application_ids: vec!["code.exe".to_string()],
        capture_scope: Some("window".to_string()),
        ax_compatibility: Some(true),
        max_tree_nodes: Some(32),
        max_text_code_units: 512,
        debounce_ms: 0,
        max_wait_ms: 1,
        read_timeout_ms: 3_000,
        ..CapturePolicy::default()
    };

    let mut engine = CollectorEngine::new(
        "owner-uia",
        "inst-uia",
        "dev-uia-test",
        "wts-1",
        "winsta0-default-wts-1",
        false,
        MockEnv::new(),
        clock,
        validator.clone(),
    );
    engine.receive(&configure_msg(1, &policy));
    engine.receive(&control_msg(1, "start"));
    let _ = engine.drain_outputs();
    thread::sleep(Duration::from_millis(5));
    engine.tick(true);
    let ticket = engine.environment.launched.pop().expect("ticket");

    // Pass focused_hwnd = None to exercise AllowUnfocusedWindow fallback on vscode-family.
    let res = read_window_for_test(
        win.window_hwnd,
        None,
        Some("code.exe"),
        Some(DesktopStatus::Unlocked),
        &ticket,
        &clock,
    );
    assert_eq!(res.focus_absent, Some(true));
    assert!(res.text.is_none());
    assert_eq!(
        res.diagnostic.map(|d| d.code),
        Some(GapDiagnosticCode::FocusedFieldUnavailable)
    );
    assert!(res.valid_window_only_channels(&policy));
    let surf = res.surface.as_ref().expect("unfocused window surface present");
    assert!(surf.nodes.iter().all(|n| n.focused != Some(true)));
    assert!(surf
        .nodes
        .iter()
        .any(|n| n.text.as_deref() == Some("fn main() {}")));

    // axCompatibility warmup populated CaptureDiagnostics on ReadResult.
    let en = res.enablement.as_ref().expect("ax enablement reported");
    assert_eq!(en.attribute, "manual");
    assert_eq!(en.status, "enabled");

    engine.complete(res);
    let msgs = emitted_messages(engine.drain_outputs());
    assert!(msgs.iter().any(|m| {
        m.get("payload")
            .and_then(|p| p.get("kind"))
            .and_then(JsonValue::as_str)
            == Some("surface.snapshot")
    }));
    for msg in &msgs {
        validator
            .validate_message(msg)
            .expect("unfocused window surface.snapshot valid");
    }
}

#[test]
fn live_uia_session_mta_com_winevent_lifecycle_and_clean_teardown() {
    let _guard = lock_live_uia_test();
    ensure_test_mta_apartment();
    let clock = SystemCollectorClock;
    let started = Instant::now();

    let mut session1 = LiveUiaSession::new(None);
    assert!(session1.is_com_ready(), "MTA COM IUIAutomation initialized");
    assert!(
        session1.is_watcher_active(),
        "SetWinEventHook background watcher thread active"
    );
    session1.poll(&clock);
    assert!(session1.retire_healthy(), "retire_healthy returns true");
    assert!(
        !session1.is_com_ready(),
        "COM interfaces released on retire_healthy"
    );
    assert!(
        !session1.is_watcher_active(),
        "WinEvent watcher stopped on retire_healthy"
    );
    drop(session1);

    // Also verify Drop without explicit retire_healthy tears down promptly without hanging.
    {
        let mut session2 = LiveUiaSession::new(None);
        assert!(session2.is_com_ready());
        assert!(session2.is_watcher_active());
        session2.poll(&clock);
    }

    assert!(
        started.elapsed() < Duration::from_secs(10),
        "LiveUiaSession teardown must complete promptly without hanging"
    );
}

#[test]
fn weighted_surface_traversal_pane_header_band_and_node_map_overflow() {
    // 1. Alternating tail/head child paging.
    let mut frontier = SurfaceChildFrontier::new(10, false);
    assert_eq!(frontier.next(3), Some((7, 3, true))); // tail
    assert_eq!(frontier.next(3), Some((0, 3, false))); // head
    assert_eq!(frontier.next(3), Some((4, 3, true))); // tail
    assert_eq!(frontier.next(3), Some((3, 1, false))); // remaining head
    assert_eq!(frontier.next(3), None);

    // 2. PaneHeaderBand (headerHeight = 50pt in 24..=120pt above 400pt focused pane).
    // Tree: 0(AXWindow) -> [1(AXGroup header y=0..48) -> [2(AXStaticText "Room #general")],
    //                       3(AXScrollArea y=50..450) -> [4(AXTextArea focused)]]
    let mut parents: HashMap<usize, usize> = HashMap::new();
    parents.insert(1, 0);
    parents.insert(2, 1);
    parents.insert(3, 0);
    parents.insert(4, 3);

    let mut children: HashMap<usize, Vec<usize>> = HashMap::new();
    children.insert(0, vec![1, 3]);
    children.insert(1, vec![2]);
    children.insert(3, vec![4]);

    let make_meta = |id: usize| -> WeightedSurfaceMetadata {
        match id {
            0 => WeightedSurfaceMetadata {
                ax_role: Some("AXWindow".to_string()),
                category: "container",
                subrole: None,
                child_count: 2,
                is_focused: false,
                observed_at_ms: 100,
                is_enabled: Some(true),
                display_text: None,
                bounds: Some(SurfaceBounds::new(0.0, 0.0, 800.0, 460.0)),
                bounds_observed_at_ms: Some(100),
            },
            1 => WeightedSurfaceMetadata {
                ax_role: Some("AXGroup".to_string()),
                category: "container",
                subrole: None,
                child_count: 1,
                is_focused: false,
                observed_at_ms: 100,
                is_enabled: Some(true),
                display_text: None,
                bounds: Some(SurfaceBounds::new(0.0, 0.0, 800.0, 48.0)),
                bounds_observed_at_ms: Some(100),
            },
            2 => WeightedSurfaceMetadata {
                ax_role: Some("AXStaticText".to_string()),
                category: "text",
                subrole: None,
                child_count: 0,
                is_focused: false,
                observed_at_ms: 100,
                is_enabled: Some(true),
                display_text: None,
                bounds: Some(SurfaceBounds::new(12.0, 10.0, 200.0, 24.0)),
                bounds_observed_at_ms: Some(100),
            },
            3 => WeightedSurfaceMetadata {
                ax_role: Some("AXScrollArea".to_string()),
                category: "container",
                subrole: None,
                child_count: 1,
                is_focused: false,
                observed_at_ms: 100,
                is_enabled: Some(true),
                display_text: None,
                bounds: Some(SurfaceBounds::new(0.0, 50.0, 800.0, 400.0)),
                bounds_observed_at_ms: Some(100),
            },
            _ => WeightedSurfaceMetadata {
                ax_role: Some("AXTextArea".to_string()),
                category: "editable",
                subrole: None,
                child_count: 0,
                is_focused: true,
                observed_at_ms: 100,
                is_enabled: Some(true),
                display_text: None,
                bounds: Some(SurfaceBounds::new(10.0, 60.0, 780.0, 380.0)),
                bounds_observed_at_ms: Some(100),
            },
        }
    };

    let anchors = SurfaceFocusAnchors::collect(
        0usize,
        4usize,
        48,
        160,
        48,
        |&h| WeightedSurfaceInspection::Allowed(make_meta(h)),
        |&h| parents.get(&h).copied(),
        || true,
    );
    let plan = anchors.plan.expect("focus anchor chain collected");
    assert_eq!(plan.nodes.len(), 3); // 0 -> 3 -> 4

    let pref = HashSet::new();
    let ign = HashSet::new();
    let ign_sub = HashSet::new();
    let res = WeightedSurfaceTraversal::run(
        0usize,
        WeightedSurfaceTraversalLimits::default(),
        &pref,
        &ign,
        &ign_sub,
        false,
        plan.work,
        plan.probes,
        Some(&plan),
        |&h| WeightedSurfaceInspection::Allowed(make_meta(h)),
        |&h, off, cnt| {
            let list = children.get(&h).cloned().unwrap_or_default();
            let end = (off + cnt).min(list.len());
            WeightedSurfaceChildrenRead::Values(list[off.min(end)..end].to_vec())
        },
        |&h| match h {
            2 => Some(WeightedSurfaceTextRead {
                text: Some("Room #general".to_string()),
                truncated: false,
            }),
            4 => Some(WeightedSurfaceTextRead {
                text: Some("typing...".to_string()),
                truncated: false,
            }),
            _ => None,
        },
        || true,
        || true,
    );
    assert!(res.complete);
    assert!(res
        .nodes
        .iter()
        .any(|n| n.text_read.as_ref().and_then(|t| t.text.as_deref()) == Some("Room #general")));
    assert!(res
        .nodes
        .iter()
        .any(|n| n.metadata.is_focused && n.text_read.as_ref().and_then(|t| t.text.as_deref()) == Some("typing...")));

    // 3. SurfaceNodeMap capacity 192 overflow resets and pins focused node UUID.
    let mut map = SurfaceNodeMap::with_capacity(4);
    let focus_key = RuntimeIdKey(vec![42, 1]);
    let focus_id = map.identifier(&focus_key).unwrap();
    let batch1 = vec![
        focus_key.clone(),
        RuntimeIdKey(vec![42, 2]),
        RuntimeIdKey(vec![42, 3]),
    ];
    assert!(map.prepare_commit("generic", &batch1, Some((&focus_key, &focus_id))));
    for k in &batch1 {
        assert!(map.identifier(k).is_some());
    }
    // Same adapter & within capacity -> no reset.
    assert!(!map.prepare_commit("generic", &batch1, Some((&focus_key, &focus_id))));
    // Exceeding capacity triggers reset while preserving pinned focused UUID.
    let overflow_batch = vec![
        focus_key.clone(),
        RuntimeIdKey(vec![42, 4]),
        RuntimeIdKey(vec![42, 5]),
    ];
    assert!(map.prepare_commit("generic", &overflow_batch, Some((&focus_key, &focus_id))));
    assert_eq!(map.identifier(&focus_key).as_deref(), Some(focus_id.as_str()));
    // Adapter change triggers reset while preserving pinned focused UUID.
    assert!(map.prepare_commit("vscode-family", std::slice::from_ref(&focus_key), Some((&focus_key, &focus_id))));
    assert_eq!(map.identifier(&focus_key).as_deref(), Some(focus_id.as_str()));
}

#[test]
fn live_uia_private_browser_chrome_button_blocks_neutral_title_zero_leakage() {
    let _guard = lock_live_uia_test();
    let clock = SystemCollectorClock;
    let secret_body = "SecretChromeIncognitoBody777";
    let neutral_title = "Example - Google Chrome";

    // 1. Chrome Incognito on Windows omits "(Incognito)" from GetWindowTextW on navigated pages,
    // exposing a native frame toolbar button (e.g. "シークレット", "Incognito", "无痕模式").
    // Pre-read chrome gate MUST block with ZERO text, surface, or selection leakage.
    for indicator in ["シークレット", "Incognito", "无痕模式"] {
        let win = SyntheticWin32Window::spawn(SyntheticWindowSpec {
            title: neutral_title.to_string(),
            overlapped: true,
            edit_text: secret_body.to_string(),
            password_text: None,
            static_label: Some("Address Bar".to_string()),
            pua_label: None,
            button_labels: vec![indicator.to_string()],
        });

        let policy = CapturePolicy {
            enabled: true,
            application_scope: Some("denylist".to_string()),
            allow_browser_content: Some(true),
            capture_scope: Some("window".to_string()),
            selection_capture: Some(true),
            max_tree_nodes: Some(32),
            max_text_code_units: 512,
            ..CapturePolicy::default()
        };
        let ticket = make_ticket(policy, &clock);
        let res = read_window_for_test(
            win.window_hwnd,
            Some(win.edit_hwnd),
            Some("chrome.exe"),
            Some(DesktopStatus::Unlocked),
            &ticket,
            &clock,
        );

        assert_eq!(
            res.reason.as_deref(),
            Some("policy-boundary"),
            "indicator={indicator}"
        );
        assert_eq!(
            res.diagnostic.map(|d| d.code),
            Some(GapDiagnosticCode::BrowserExcluded),
            "indicator={indicator}"
        );
        assert_eq!(
            res.surface_failure,
            Some(SurfaceReadFailure::SecurityExcluded),
            "indicator={indicator}"
        );
        assert!(res.text.is_none(), "ZERO text leakage for {indicator}");
        assert!(res.surface.is_none(), "ZERO surface leakage for {indicator}");
        assert!(
            res.selection.is_none(),
            "ZERO selection leakage for {indicator}"
        );
        assert!(
            res.diagnostic_application.is_none(),
            "diagnostic_application must be omitted on BrowserExcluded"
        );

        let serialized = String::from_utf8(res.to_json().canonical_bytes().unwrap()).unwrap();
        assert!(
            !serialized.contains(secret_body),
            "incognito body leaked for indicator={indicator}"
        );
        assert!(
            !serialized.contains(indicator) && !serialized.contains(neutral_title),
            "browser chrome button or title leaked for indicator={indicator}"
        );
    }

    // 2. Normal chrome.exe window with neutral title and normal profile button "Chrome" MUST still be ALLOWED!
    let normal_body = "NormalAllowedBrowserBody888";
    let normal_win = SyntheticWin32Window::spawn(SyntheticWindowSpec {
        title: neutral_title.to_string(),
        overlapped: true,
        edit_text: normal_body.to_string(),
        password_text: None,
        static_label: Some("Address Bar".to_string()),
        pua_label: None,
        button_labels: vec!["Chrome".to_string()],
    });
    let normal_policy = CapturePolicy {
        enabled: true,
        application_scope: Some("denylist".to_string()),
        allow_browser_content: Some(true),
        capture_scope: Some("window".to_string()),
        max_tree_nodes: Some(32),
        max_text_code_units: 512,
        ..CapturePolicy::default()
    };
    let normal_ticket = make_ticket(normal_policy, &clock);
    let normal_res = read_window_for_test(
        normal_win.window_hwnd,
        Some(normal_win.edit_hwnd),
        Some("chrome.exe"),
        Some(DesktopStatus::Unlocked),
        &normal_ticket,
        &clock,
    );
    assert_eq!(
        normal_res.reason, None,
        "normal chrome.exe window must be allowed, got: {:?}",
        normal_res.diagnostic
    );
    assert_eq!(
        normal_res.text.as_ref().map(|t| t.text.as_str()),
        Some(normal_body)
    );
    assert!(normal_res.surface.is_some());
}

#[test]
fn weighted_surface_traversal_lazy_resolved_count_tail_first_paging() {
    // Root (0) -> List (1) with 20 children (100..120), where focus is child 119 (newest bottom item).
    // `inspect` returns ONLY a lazy hint `child_count = 2` for List (1) without enumerating all 20!
    // On first expansion, `children` returns `ResolvedCount(20)` so SurfaceChildFrontier pages
    // from the tail and captures child 119 / 118 immediately with zero InconsistentChildren.
    let list_children: Vec<usize> = (100..120).collect();
    let mut resolved = false;

    let make_meta = |id: usize| -> WeightedSurfaceMetadata {
        match id {
            0 => WeightedSurfaceMetadata {
                ax_role: Some("AXWindow".to_string()),
                category: "container",
                subrole: None,
                child_count: 1,
                is_focused: false,
                observed_at_ms: 100,
                is_enabled: Some(true),
                display_text: None,
                bounds: Some(SurfaceBounds::new(0.0, 0.0, 800.0, 600.0)),
                bounds_observed_at_ms: Some(100),
            },
            1 => WeightedSurfaceMetadata {
                ax_role: Some("AXList".to_string()),
                category: "container",
                subrole: None,
                // Lazy hint (2 = >=2 children) during inspect_node!
                child_count: 2,
                is_focused: false,
                observed_at_ms: 100,
                is_enabled: Some(true),
                display_text: None,
                bounds: Some(SurfaceBounds::new(0.0, 40.0, 800.0, 560.0)),
                bounds_observed_at_ms: Some(100),
            },
            n => WeightedSurfaceMetadata {
                ax_role: Some("AXStaticText".to_string()),
                category: "text",
                subrole: None,
                child_count: 0,
                is_focused: n == 119,
                observed_at_ms: 100,
                is_enabled: Some(true),
                display_text: None,
                bounds: None,
                bounds_observed_at_ms: None,
            },
        }
    };

    let anchors = SurfaceFocusAnchors::collect(
        0usize,
        119usize,
        48,
        160,
        48,
        |&h| WeightedSurfaceInspection::Allowed(make_meta(h)),
        |&h| match h {
            119 => Some(1),
            1 => Some(0),
            _ => None,
        },
        || true,
    );
    let plan = anchors.plan.expect("focus anchor chain collected");
    assert_eq!(plan.nodes.len(), 3); // 0 -> 1 -> 119

    let pref = HashSet::new();
    let ign = HashSet::new();
    let ign_sub = HashSet::new();
    let res = WeightedSurfaceTraversal::run(
        0usize,
        WeightedSurfaceTraversalLimits::new(8, None, None, 192, 64, 4, 4),
        &pref,
        &ign,
        &ign_sub,
        false,
        plan.work,
        plan.probes,
        Some(&plan),
        |&h| WeightedSurfaceInspection::Allowed(make_meta(h)),
        |&h, off, cnt| match h {
            0 => {
                let list = [1usize];
                let end = (off + cnt).min(list.len());
                WeightedSurfaceChildrenRead::Values(list[off.min(end)..end].to_vec())
            }
            1 => {
                if !resolved {
                    resolved = true;
                    return WeightedSurfaceChildrenRead::ResolvedCount(list_children.len());
                }
                let end = (off + cnt).min(list_children.len());
                WeightedSurfaceChildrenRead::Values(list_children[off.min(end)..end].to_vec())
            }
            _ => WeightedSurfaceChildrenRead::Values(Vec::new()),
        },
        |&h| {
            if h >= 100 {
                Some(WeightedSurfaceTextRead {
                    text: Some(format!("msg-{h}")),
                    truncated: false,
                })
            } else {
                None
            }
        },
        || true,
        || true,
    );

    assert!(resolved, "lazy ResolvedCount path must have executed");
    assert!(
        !res.reasons
            .iter()
            .any(|r| r.as_str() == "tree-children-inconsistent"),
        "lazy ResolvedCount must not emit tree-children-inconsistent: {:?}",
        res.reasons
    );
    assert!(
        res.nodes
            .iter()
            .any(|n| n.text_read.as_ref().and_then(|t| t.text.as_deref()) == Some("msg-119")),
        "newest focused tail message msg-119 must be captured"
    );
    assert!(
        res.nodes
            .iter()
            .any(|n| n.text_read.as_ref().and_then(|t| t.text.as_deref()) == Some("msg-118")),
        "adjacent newest tail message msg-118 must be captured by tail-first frontier"
    );
}

#[test]
fn live_uia_dual_id_msix_and_fail_closed_afh() {
    let _guard = lock_live_uia_test();
    let clock = SystemCollectorClock;
    let secret_body = "MsixVaultSecret999";
    let win = SyntheticWin32Window::spawn(SyntheticWindowSpec {
        title: "Vault Window".to_string(),
        overlapped: true,
        edit_text: secret_body.to_string(),
        password_text: None,
        static_label: Some("Header".to_string()),
        pua_label: None,
        button_labels: vec!["Private Browsing".to_string()],
    });

    let denylist_policy = CapturePolicy {
        enabled: true,
        application_scope: Some("denylist".to_string()),
        allow_browser_content: Some(true),
        capture_scope: Some("window".to_string()),
        max_tree_nodes: Some(32),
        max_text_code_units: 512,
        ..CapturePolicy::default()
    };

    // 1. MSIX packaged password manager: package_name does NOT shadow mandatory-excluded exe_name!
    let msix_1pass = ResolvedAppIdentity::from_parts(
        Some("91750d7e.1password".to_string()),
        Some("1password.exe".to_string()),
    )
    .expect("valid dual-ID");
    let ticket_1pass = make_ticket(denylist_policy.clone(), &clock);
    let res_1pass = read_window_with_identity_for_test(
        win.window_hwnd,
        Some(win.edit_hwnd),
        &msix_1pass,
        Some(DesktopStatus::Unlocked),
        &ticket_1pass,
        &clock,
    );
    assert_eq!(res_1pass.reason.as_deref(), Some("application-excluded"));
    assert_eq!(
        res_1pass.diagnostic.map(|d| d.code),
        Some(GapDiagnosticCode::ApplicationNotAllowed)
    );
    assert!(res_1pass.text.is_none());
    assert!(res_1pass.surface.is_none());

    // 2. MSIX packaged Firefox: dual-ID resolves browser-family adapter & blocks private chrome!
    let msix_firefox = ResolvedAppIdentity::from_parts(
        Some("mozilla.firefox".to_string()),
        Some("firefox.exe".to_string()),
    )
    .expect("valid dual-ID");
    let ticket_ff = make_ticket(denylist_policy.clone(), &clock);
    let res_ff = read_window_with_identity_for_test(
        win.window_hwnd,
        Some(win.edit_hwnd),
        &msix_firefox,
        Some(DesktopStatus::Unlocked),
        &ticket_ff,
        &clock,
    );
    assert_eq!(res_ff.reason.as_deref(), Some("policy-boundary"));
    assert_eq!(
        res_ff.diagnostic.map(|d| d.code),
        Some(GapDiagnosticCode::BrowserExcluded)
    );
    assert_eq!(
        res_ff.surface_failure,
        Some(SurfaceReadFailure::SecurityExcluded)
    );
    assert!(res_ff.text.is_none());
    assert!(res_ff.surface.is_none());

    // 3. ApplicationFrameHost.exe MUST fail closed as ApplicationUnavailable (never allowed).
    let ticket_afh = make_ticket(denylist_policy, &clock);
    let res_afh = read_window_for_test(
        win.window_hwnd,
        Some(win.edit_hwnd),
        Some("applicationframehost.exe"),
        Some(DesktopStatus::Unlocked),
        &ticket_afh,
        &clock,
    );
    assert_eq!(res_afh.reason.as_deref(), Some("policy-boundary"));
    assert_eq!(
        res_afh.diagnostic.map(|d| d.code),
        Some(GapDiagnosticCode::ApplicationUnavailable)
    );
    assert!(res_afh.text.is_none());
    assert!(res_afh.surface.is_none());
}

#[test]
fn live_uia_private_chrome_three_state_verdict_and_no_false_positives() {
    let _guard = lock_live_uia_test();
    ensure_test_mta_apartment();
    let clock = SystemCollectorClock;
    let _com = ComGuard::init_mta().expect("MTA COM init");
    let uia = UiaClient::new().expect("UiaClient init");

    // 1. Null HWND or expired deadline -> Inconclusive (fail closed!).
    let now = clock.monotonic_ms();
    assert_eq!(
        uia.is_private_browser_window_chrome(
            HWND(core::ptr::null_mut()),
            now + 40,
            now + 1_000
        ),
        Ok(PrivateChromeVerdict::Inconclusive)
    );

    // 2. Normal chrome with benign labels ("Privacy settings", "隐私设置", "My Private Bookmarks")
    // MUST return VerifiedNormal (no false positives!) and allow capture.
    let benign_body = "AllowedNormalBrowserText456";
    let benign_win = SyntheticWin32Window::spawn(SyntheticWindowSpec {
        title: "Docs - Google Chrome".to_string(),
        overlapped: true,
        edit_text: benign_body.to_string(),
        password_text: None,
        static_label: Some("Address Bar".to_string()),
        pua_label: None,
        button_labels: vec![
            "Privacy settings".to_string(),
            "隐私设置".to_string(),
            "My Private Bookmarks".to_string(),
        ],
    });
    let now2 = clock.monotonic_ms();
    assert_eq!(
        uia.is_private_browser_window_chrome(benign_win.window_hwnd, now2 + 2_000, now2 + 3_000),
        Ok(PrivateChromeVerdict::VerifiedNormal)
    );
    // Expired deadline on the same live window -> Inconclusive!
    assert_eq!(
        uia.is_private_browser_window_chrome(benign_win.window_hwnd, now2 - 1, now2 + 3_000),
        Ok(PrivateChromeVerdict::Inconclusive)
    );

    let browser_policy = CapturePolicy {
        enabled: true,
        application_scope: Some("denylist".to_string()),
        allow_browser_content: Some(true),
        capture_scope: Some("window".to_string()),
        max_tree_nodes: Some(32),
        max_text_code_units: 512,
        ..CapturePolicy::default()
    };
    let benign_ticket = make_ticket(browser_policy.clone(), &clock);
    let benign_res = read_window_for_test(
        benign_win.window_hwnd,
        Some(benign_win.edit_hwnd),
        Some("chrome.exe"),
        Some(DesktopStatus::Unlocked),
        &benign_ticket,
        &clock,
    );
    assert_eq!(
        benign_res.reason, None,
        "benign toolbar labels must not false-positive: {:?}",
        benign_res.diagnostic
    );
    assert_eq!(
        benign_res.text.as_ref().map(|t| t.text.as_str()),
        Some(benign_body)
    );

    // 3. Private chrome badge -> Private verdict.
    let priv_win = SyntheticWin32Window::spawn(SyntheticWindowSpec {
        title: "Example - Google Chrome".to_string(),
        overlapped: true,
        edit_text: "NeverReadThis".to_string(),
        password_text: None,
        static_label: Some("Address Bar".to_string()),
        pua_label: None,
        button_labels: vec!["InPrivate".to_string()],
    });
    let now3 = clock.monotonic_ms();
    assert_eq!(
        uia.is_private_browser_window_chrome(priv_win.window_hwnd, now3 + 2_000, now3 + 3_000),
        Ok(PrivateChromeVerdict::Private)
    );
}

#[test]
fn live_uia_session_caches_warmed_hwnd_once_per_session() {
    let _guard = lock_live_uia_test();
    let clock = SystemCollectorClock;
    let win = SyntheticWin32Window::spawn(SyntheticWindowSpec {
        title: "Warmup Cache Test".to_string(),
        overlapped: false,
        edit_text: "hello cache".to_string(),
        password_text: None,
        static_label: Some("Label".to_string()),
        pua_label: None,
        button_labels: Vec::new(),
    });

    let policy = CapturePolicy {
        enabled: true,
        allowed_application_ids: vec!["code.exe".to_string()],
        capture_scope: Some("window".to_string()),
        ax_compatibility: Some(true),
        max_tree_nodes: Some(32),
        max_text_code_units: 512,
        ..CapturePolicy::default()
    };

    let mut session = LiveUiaSession::new(None);
    assert!(session.is_com_ready());

    // First read warms HWND once via IUIAutomation::ElementFromHandle -> status == "enabled".
    let t1 = make_ticket(policy.clone(), &clock);
    let r1 = session.read_window_for_test(
        win.window_hwnd,
        Some(win.edit_hwnd),
        Some("code.exe"),
        Some(DesktopStatus::Unlocked),
        &t1,
        &clock,
    );
    assert_eq!(r1.reason, None);
    let en1 = r1.enablement.expect("first enablement present");
    assert_eq!(en1.status, "enabled");
    assert!(en1.changed);

    // Second read on the SAME HWND hits per-session WarmedHwndCache -> "already-enabled", changed=false!
    let t2 = make_ticket(policy, &clock);
    let r2 = session.read_window_for_test(
        win.window_hwnd,
        Some(win.edit_hwnd),
        Some("code.exe"),
        Some(DesktopStatus::Unlocked),
        &t2,
        &clock,
    );
    assert_eq!(r2.reason, None);
    let en2 = r2.enablement.expect("second enablement present");
    assert_eq!(en2.status, "already-enabled");
    assert!(!en2.changed);

    assert!(session.retire_healthy());
}

#[test]
fn live_uia_custom_adapters_fallback_and_password_fail_closed() {
    let _guard = lock_live_uia_test();
    let clock = SystemCollectorClock;
    let win = SyntheticWin32Window::spawn(SyntheticWindowSpec {
        title: "Custom Adapter Live Fallback".to_string(),
        overlapped: false,
        edit_text: "Live fallback message".to_string(),
        password_text: Some("SecretPass#99".to_string()),
        static_label: Some("Header Label".to_string()),
        pua_label: Some("\u{EBB1}".to_string()),
        button_labels: vec!["Action".to_string()],
    });
    let pw_hwnd = win.password_hwnd.expect("password hwnd");

    for app_id in ["wechat.exe", "figma.exe"] {
        let policy = CapturePolicy {
            enabled: true,
            allowed_application_ids: vec![app_id.to_string()],
            field_security: Some("denylist".to_string()),
            capture_scope: Some("window".to_string()),
            max_tree_nodes: Some(32),
            max_text_code_units: 1_024,
            ..CapturePolicy::default()
        };

        // 1. Live window without WeChat/Figma landmarks runs LiveUiaSurfaceBackend custom path,
        //    returns None cleanly, and falls back to WeightedSurfaceTraversal while pruning secrets.
        let t1 = make_ticket(policy.clone(), &clock);
        let r1 = read_window_for_test(
            win.window_hwnd,
            Some(win.edit_hwnd),
            Some(app_id),
            Some(DesktopStatus::Unlocked),
            &t1,
            &clock,
        );
        assert_eq!(r1.reason, None, "app={app_id} diag={:?}", r1.diagnostic);
        let surf = r1.surface.as_ref().expect("surface captured");
        assert!(
            surf.nodes
                .iter()
                .any(|n| n.text.as_deref() == Some("Header Label")),
            "app={app_id} must capture Header Label via live fallback"
        );
        assert!(
            surf.nodes
                .iter()
                .any(|n| n.text.as_deref() == Some("Live fallback message")),
            "app={app_id} must capture edit text via live fallback"
        );
        assert!(
            surf.missing_reasons
                .iter()
                .any(|r| r == "tree-security-pruned"),
            "app={app_id} fallback must preserve tree-security-pruned reason: {:?}",
            surf.missing_reasons
        );
        let json = String::from_utf8(r1.to_json().canonical_bytes().unwrap()).unwrap();
        assert!(!json.contains("SecretPass#99"), "app={app_id} leaked secret!");
        assert!(!json.contains('\u{EBB1}'), "app={app_id} leaked pure PUA!");

        // 2. Focused password field MUST fail closed with SecurityExcluded and ZERO fallback.
        let t2 = make_ticket(policy, &clock);
        let r2 = read_window_for_test(
            win.window_hwnd,
            Some(pw_hwnd),
            Some(app_id),
            Some(DesktopStatus::Unlocked),
            &t2,
            &clock,
        );
        assert_eq!(r2.surface_failure, Some(SurfaceReadFailure::SecurityExcluded));
        assert!(r2.surface.is_none());
        assert!(r2.text.is_none());
    }

    // 3. Public `sanitize_display_url` sanity check (strict http/https + userinfo stripping).
    assert_eq!(
        sanitize_display_url("HTTP://user:secret@example.com:8080/path?q=a@b").as_deref(),
        Some("HTTP://example.com:8080/path?q=a@b")
    );
    assert_eq!(sanitize_display_url("javascript:alert(1)"), None);
    assert_eq!(sanitize_display_url("https://user:pass@/path"), None);
}

#[test]
fn live_uia_weighted_lazy_expansion_exceeds_two_children_and_region_scope() {
    let _guard = lock_live_uia_test();
    ensure_test_mta_apartment();
    let clock = SystemCollectorClock;

    // Spawn a clean WS_POPUP Win32 window with 6 child controls (4 STATIC + 1 PUA STATIC + 1 EDIT)
    // to prove unified LiveUiaSurfaceBackend::children_backend_for_traversal expands past the
    // 2-child probe via ResolvedCount and captures ALL >2 siblings with complete == true.
    let (tx, rx) = mpsc::sync_channel::<(isize, isize, u32)>(1);
    let handle = thread::spawn(move || {
        let class_wide = to_wide("#32770");
        let title_wide = to_wide("Lazy Expansion Live Window");
        // SAFETY: Dedicated Win32 message-pumped UI thread for MTA UIA integration test.
        unsafe {
            let mut init_msg = MSG::default();
            let _ = PeekMessageW(&mut init_msg, None, 0, 0, PM_NOREMOVE);

            let hwnd = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                PCWSTR(class_wide.as_ptr()),
                PCWSTR(title_wide.as_ptr()),
                WS_POPUP | WS_VISIBLE,
                40,
                40,
                460,
                360,
                None,
                None,
                None,
                None,
            )
            .expect("CreateWindowExW top-level window");

            let static_class = to_wide("STATIC");
            let edit_class = to_wide("EDIT");

            for (idx, label) in [
                "Sibling Alpha",
                "Sibling Beta",
                "Sibling Gamma",
                "Sibling Delta",
            ]
            .iter()
            .enumerate()
            {
                let w = to_wide(label);
                let _ = CreateWindowExW(
                    WINDOW_EX_STYLE(0),
                    PCWSTR(static_class.as_ptr()),
                    PCWSTR(w.as_ptr()),
                    WS_CHILD | WS_VISIBLE,
                    12,
                    12 + (idx as i32) * 30,
                    360,
                    24,
                    Some(hwnd),
                    None,
                    None,
                    None,
                )
                .expect("CreateWindowExW STATIC");
            }

            let pua_w = to_wide("\u{E000}\u{E001}");
            let _ = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                PCWSTR(static_class.as_ptr()),
                PCWSTR(pua_w.as_ptr()),
                WS_CHILD | WS_VISIBLE,
                384,
                12,
                24,
                24,
                Some(hwnd),
                None,
                None,
                None,
            )
            .expect("CreateWindowExW PUA STATIC");

            let edit_w = to_wide("Focused Fifth Child");
            let edit_hwnd = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                PCWSTR(edit_class.as_ptr()),
                PCWSTR(edit_w.as_ptr()),
                WS_CHILD | WS_VISIBLE | WINDOW_STYLE((ES_MULTILINE | ES_AUTOVSCROLL) as u32),
                12,
                148,
                420,
                120,
                Some(hwnd),
                None,
                None,
                None,
            )
            .expect("CreateWindowExW multiline EDIT");

            let tid = GetCurrentThreadId();
            tx.send((hwnd.0 as isize, edit_hwnd.0 as isize, tid))
                .unwrap();

            let mut msg = MSG::default();
            while GetMessageW(&mut msg, None, 0, 0).0 > 0 {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            let _ = DestroyWindow(hwnd);
        }
    });

    let (win_raw, edit_raw, thread_id) = rx.recv().expect("window thread init");
    let win = SyntheticWin32Window {
        window_hwnd: HWND(win_raw as *mut core::ffi::c_void),
        edit_hwnd: HWND(edit_raw as *mut core::ffi::c_void),
        password_hwnd: None,
        thread_id,
        handle: Some(handle),
    };
    thread::sleep(Duration::from_millis(30));

    // 1. Weighted window scope captures ALL 4 STATIC labels + EDIT (>2 children!) with complete == true.
    let window_policy = CapturePolicy {
        enabled: true,
        allowed_application_ids: vec!["surface-app.exe".to_string()],
        field_security: Some("strict".to_string()),
        capture_scope: Some("window".to_string()),
        max_tree_nodes: Some(32),
        max_text_code_units: 1_024,
        ..CapturePolicy::default()
    };
    let t_win = make_ticket(window_policy, &clock);
    let r_win = read_window_for_test(
        win.window_hwnd,
        Some(win.edit_hwnd),
        Some("surface-app.exe"),
        Some(DesktopStatus::Unlocked),
        &t_win,
        &clock,
    );
    assert_eq!(r_win.reason, None, "unexpected failure: {:?}", r_win.diagnostic);
    let surf_win = r_win.surface.as_ref().expect("window surface present");
    assert!(
        surf_win.complete,
        "clean 6-child window surface must be complete, missing={:?}",
        surf_win.missing_reasons
    );
    for expected in [
        "Sibling Alpha",
        "Sibling Beta",
        "Sibling Gamma",
        "Sibling Delta",
        "Focused Fifth Child",
    ] {
        assert!(
            surf_win
                .nodes
                .iter()
                .any(|n| n.text.as_deref() == Some(expected)),
            "unified weighted traversal must lazily expand and capture `{expected}`; got {:?}",
            surf_win
                .nodes
                .iter()
                .filter_map(|n| n.text.as_deref())
                .collect::<Vec<_>>()
        );
    }
    assert!(
        !surf_win
            .nodes
            .iter()
            .any(|n| n.text.as_deref().is_some_and(|t| t.contains('\u{E000}'))),
        "unfocused pure-PUA STATIC must be dropped cleanly"
    );

    // 2. `capture_scope: Some("region")` on `wechat.exe` and `figma.exe` skips custom extraction
    //    and runs unified weighted capture cleanly with ALL >2 siblings and complete == true.
    for app_id in ["wechat.exe", "figma.exe"] {
        let region_policy = CapturePolicy {
            enabled: true,
            allowed_application_ids: vec![app_id.to_string()],
            field_security: Some("denylist".to_string()),
            capture_scope: Some("region".to_string()),
            max_tree_nodes: Some(32),
            max_text_code_units: 1_024,
            ..CapturePolicy::default()
        };
        let t_reg = make_ticket(region_policy, &clock);
        let r_reg = read_window_for_test(
            win.window_hwnd,
            Some(win.edit_hwnd),
            Some(app_id),
            Some(DesktopStatus::Unlocked),
            &t_reg,
            &clock,
        );
        assert_eq!(r_reg.reason, None, "app={app_id} diag={:?}", r_reg.diagnostic);
        let surf_reg = r_reg.surface.as_ref().expect("region surface present");
        assert_eq!(surf_reg.scope, "region");
        assert!(
            surf_reg.complete,
            "app={app_id} region surface must be complete, missing={:?}",
            surf_reg.missing_reasons
        );
        for expected in [
            "Sibling Alpha",
            "Sibling Beta",
            "Sibling Gamma",
            "Sibling Delta",
            "Focused Fifth Child",
        ] {
            assert!(
                surf_reg
                    .nodes
                    .iter()
                    .any(|n| n.text.as_deref() == Some(expected)),
                "app={app_id} region scope missing `{expected}`"
            );
        }
    }
}
