use access_contract::{is_valid_application_id, is_valid_ax_role, ContractValidator, JsonValue};
use collector_core::adapters::{AdapterRegistry, SafeDisplayText};
use collector_core::policy::{
    is_focused_editable_content_control, is_native_richedit_class, is_private_chrome_label,
    is_private_use_only_text, map_uia_control_type_to_ax, normalize_gap_role,
    normalize_package_family_name, normalize_windows_exe_name, resolve_effective_pid_checked,
    ApplicationPolicy, BrowserGate, IdentityPolicyOutcome, PhaseBudget, ProtectedContentRead,
    ReadBudget, ResolvedAppIdentity, StaticTextRangeProbe, SubroleRead, TextSecurityGate,
    PRIVATE_WINDOW_INDICATORS,
};
use collector_core::uia_com::classify_win_event;
use windows::Win32::UI::WindowsAndMessaging::{
    EVENT_OBJECT_FOCUS, EVENT_OBJECT_TEXTSELECTIONCHANGED, EVENT_OBJECT_VALUECHANGE,
    EVENT_SYSTEM_FOREGROUND,
};
use collector_core::protocol_model::{
    bounded_utf16_slice, hello_message, CapturePolicy, SecureStatus, SurfaceAbsoluteRect,
    SurfaceBaseline, SurfaceBounds, SurfaceGeometry, SurfaceNode, SurfaceWindowSize,
};

#[test]
fn normalize_windows_exe_name_handles_whitespace_paths_and_punctuation() {
    let proton = normalize_windows_exe_name(r"C:\Program Files\Proton Pass\Proton Pass.exe")
        .expect("proton pass normalizes");
    assert_eq!(proton, "protonpass.exe");
    assert!(is_valid_application_id(&proton));
    assert!(ApplicationPolicy::is_mandatory_denied(&proton));

    assert_eq!(
        normalize_windows_exe_name("Proton Pass.exe").as_deref(),
        Some("protonpass.exe")
    );
    assert_eq!(
        normalize_windows_exe_name("1Password.exe").as_deref(),
        Some("1password.exe")
    );
    assert!(ApplicationPolicy::is_mandatory_denied("1password.exe"));
    assert_eq!(
        normalize_windows_exe_name(r"C:\Windows\SystemApps\LockApp.exe").as_deref(),
        Some("lockapp.exe")
    );
    assert!(ApplicationPolicy::is_system_ui("lockapp.exe"));

    assert_eq!(
        normalize_windows_exe_name("My App (Beta)!.exe").as_deref(),
        Some("myapp-beta--.exe")
    );
    assert_eq!(
        normalize_windows_exe_name("___leading.exe").as_deref(),
        Some("leading.exe")
    );
    assert_eq!(normalize_windows_exe_name("   "), None);
    assert_eq!(normalize_windows_exe_name("..."), None);

    // MSIX/UWP package family name strips publisher suffix.
    let term = normalize_package_family_name("Microsoft.WindowsTerminal_8wekyb3d8bbwe")
        .expect("msix normalizes");
    assert_eq!(term, "microsoft.windowsterminal");
    assert!(is_valid_application_id(&term));
}

#[test]
fn application_policy_and_browser_gate_enforce_invariants() {
    let denylist_with_browsers = CapturePolicy {
        enabled: true,
        application_scope: Some("denylist".to_string()),
        allow_browser_content: Some(true),
        excluded_application_ids: Some(vec!["custom.excluded".to_string()]),
        ..CapturePolicy::default()
    };

    assert!(!ApplicationPolicy::allows("1password.exe", &denylist_with_browsers));
    assert!(!ApplicationPolicy::allows("protonpass.exe", &denylist_with_browsers));
    assert!(!ApplicationPolicy::allows("com.apple.Safari", &denylist_with_browsers));
    assert!(!ApplicationPolicy::allows("lockapp.exe", &denylist_with_browsers));
    assert!(!ApplicationPolicy::allows("credentialuibroker.exe", &denylist_with_browsers));
    assert!(!ApplicationPolicy::allows("custom.excluded", &denylist_with_browsers));
    assert!(!ApplicationPolicy::allows("custom.excluded.helper", &denylist_with_browsers));
    assert!(ApplicationPolicy::allows("custom.excludedx", &denylist_with_browsers));

    assert!(BrowserGate::is_known_browser("msedge.exe"));
    assert!(BrowserGate::is_known_browser("chrome.exe"));
    assert!(BrowserGate::is_known_browser("firefox.exe"));
    assert!(BrowserGate::allows("msedge.exe", &denylist_with_browsers, false));

    let allowlist = CapturePolicy {
        enabled: true,
        application_scope: Some("allowlist".to_string()),
        allowed_application_ids: vec!["msedge.exe".to_string(), "code.exe".to_string()],
        ..CapturePolicy::default()
    };
    assert!(BrowserGate::allows("code.exe", &allowlist, false));
    assert!(!BrowserGate::allows("msedge.exe", &allowlist, false));

    // Expanded 28 multilingual private window title indicators.
    assert_eq!(PRIVATE_WINDOW_INDICATORS.len(), 28);
    for title in [
        "GitHub - Google Chrome (Incognito)",
        "New Incognito Tab - Google Chrome",
        "Docs (Private)",
        "Banking - Microsoft Edge InPrivate",
        "Mozilla Firefox Private Browsing",
        "Fenster (Privat)",
        "Finestra (Privato)",
        "无痕浏览 - Edge",
        "隐私浏览模式",
        "私人浏览窗口",
        "無痕視窗 - Chrome",
        "私密瀏覽 - Firefox",
        "Mozilla Firefox 隱私瀏覽",
        "シークレット モード - Google Chrome",
        "プライベート ブラウジング",
        "시크릿 모드 - Chrome",
        "프라이빗 브라우징",
        "Mozilla Firefox 사생활 보호",
        "Nueva pestaña de incógnito",
        "Mozilla Firefox Navegación privada",
        "Navigation privée - Firefox",
        "Mozilla Firefox Privater Modus",
        "Navegação anônima - Chrome",
        "Mozilla Firefox Navegação privativa",
        "Mozilla Firefox Navigazione anonima",
        "Режим инкогнито - Chrome",
        "Mozilla Firefox Приватный просмотр",
        "Karta Inkognito - Chrome",
    ] {
        assert!(
            BrowserGate::is_private_window_title(title),
            "expected private indicator match for: {title}"
        );
    }
    assert!(!BrowserGate::is_private_window_title("Normal Window - Chrome"));
    assert!(!BrowserGate::is_private_window_title(
        "How Incognito Mode Works - Google Chrome"
    ));

    // Native browser chrome toolbar/profile indicators (non-Document frame controls).
    for (cls, name) in [
        (Some("AvatarToolbarButton"), "シークレット"),
        (Some("AvatarToolbarButton"), "Incognito"),
        (Some("AvatarToolbarButton"), "无痕模式"),
        (Some("AvatarToolbarButton"), "無痕"),
        (Some("AvatarToolbarButton"), "隱私瀏覽"),
        (Some("AvatarToolbarButton"), "InPrivate"),
        (Some("Button"), "Private Browsing"),
        (Some("Button"), "Private"),
        (Some("Button"), "Private (2)"),
        (Some("Button"), "Privé"),
        (Some("Button"), "Privat"),
        (Some("Button"), "Privato"),
        (Some("Button"), "プライベート"),
        (Some("Button"), "プライベート ブラウジング"),
        (Some("Button"), "Privater Modus"),
        (Some("Button"), "Navegación privada"),
        (Some("Button"), "Приватный просмотр"),
        (Some("Button"), "Navegação privativa"),
        (Some("Button"), "Navigazione anonima"),
        (Some("Button"), "사생활 보호"),
        (Some("Button"), "시크릿"),
        (Some("Button"), "프라이빗"),
        (Some("Custom"), "Navigation privée"),
        (Some("Text"), "Navegação anônima"),
        (Some("Text"), "Инкогнито"),
        (Some("Button"), "Inkognito"),
        (None, "Incógnito"),
    ] {
        assert!(
            is_private_chrome_label(name),
            "expected is_private_chrome_label match for name={name}"
        );
        assert!(
            BrowserGate::is_private_chrome_indicator(cls, name),
            "expected chrome indicator match for cls={cls:?} name={name}"
        );
    }
    // Tightened negative false-positive cases (even on non-excluded control classes!).
    for label in [
        "Privacy settings",
        "隐私设置",
        "My Private Bookmarks",
        "Private Repo - GitHub",
        "Privatkonto",
        "Private Docs",
        "Private Internet Access",
        "Chrome",
        "Guest",
        "Mark",
        "   ",
    ] {
        assert!(
            !is_private_chrome_label(label),
            "unexpected is_private_chrome_label false positive for label={label}"
        );
        assert!(
            !BrowserGate::is_private_chrome_indicator(Some("Button"), label),
            "unexpected chrome indicator false positive for label={label}"
        );
    }
    for (cls, name) in [
        (Some("BookmarkButton"), "Private Browsing"),
        (Some("ToolbarActionView"), "Incognito Helper"),
        (Some("Tab"), "InPrivate Tab"),
    ] {
        assert!(
            !BrowserGate::is_private_chrome_indicator(cls, name),
            "unexpected chrome indicator match for excluded class cls={cls:?} name={name}"
        );
    }
}

#[test]
fn text_security_gate_strict_vs_denylist() {
    let strict = CapturePolicy {
        field_security: Some("strict".to_string()),
        ..CapturePolicy::default()
    };
    let denylist = CapturePolicy {
        field_security: Some("denylist".to_string()),
        ..CapturePolicy::default()
    };

    // Password / secure / protected always Sensitive in both modes.
    for pol in [&strict, &denylist] {
        assert_eq!(
            TextSecurityGate::classify_metadata::<fn() -> SecureStatus>(
                Some("AXSecureTextField"),
                &SubroleRead::NoValue,
                ProtectedContentRead::Value(false),
                pol,
                None,
            ),
            SecureStatus::Sensitive
        );
        assert_eq!(
            TextSecurityGate::classify_metadata::<fn() -> SecureStatus>(
                Some("AXTextField"),
                &SubroleRead::Value("AXPasswordField".to_string()),
                ProtectedContentRead::Value(false),
                pol,
                None,
            ),
            SecureStatus::Sensitive
        );
        assert_eq!(
            TextSecurityGate::classify_metadata::<fn() -> SecureStatus>(
                Some("AXTextField"),
                &SubroleRead::NoValue,
                ProtectedContentRead::Value(true),
                pol,
                None,
            ),
            SecureStatus::Sensitive
        );
        // API failures never become NotDeclaredSensitive even in denylist mode!
        assert_eq!(
            TextSecurityGate::classify_metadata::<fn() -> SecureStatus>(
                Some("AXTextField"),
                &SubroleRead::Failure,
                ProtectedContentRead::Value(false),
                pol,
                None,
            ),
            SecureStatus::Unknown
        );
        assert_eq!(
            TextSecurityGate::classify_metadata::<fn() -> SecureStatus>(
                Some("AXTextField"),
                &SubroleRead::NoValue,
                ProtectedContentRead::Malformed,
                pol,
                None,
            ),
            SecureStatus::Unknown
        );
    }

    // Denylist permits ordinary readable text roles without sensitive evidence.
    assert_eq!(
        TextSecurityGate::classify_metadata::<fn() -> SecureStatus>(
            Some("AXTextField"),
            &SubroleRead::NoValue,
            ProtectedContentRead::Value(false),
            &denylist,
            None,
        ),
        SecureStatus::NotDeclaredSensitive
    );
    // Strict requires positive proof.
    assert_eq!(
        TextSecurityGate::classify_metadata::<fn() -> SecureStatus>(
            Some("AXTextField"),
            &SubroleRead::NoValue,
            ProtectedContentRead::Value(false),
            &strict,
            None,
        ),
        SecureStatus::Unknown
    );
    assert_eq!(
        TextSecurityGate::classify_metadata::<fn() -> SecureStatus>(
            Some("AXTextField"),
            &SubroleRead::Value("AXStandardTextField".to_string()),
            ProtectedContentRead::Value(false),
            &strict,
            None,
        ),
        SecureStatus::Safe
    );

    assert!(!TextSecurityGate::may_traverse(
        &SubroleRead::Value("AXSecureTextField".to_string()),
        ProtectedContentRead::Value(false)
    ));
    assert!(!TextSecurityGate::may_traverse(
        &SubroleRead::NoValue,
        ProtectedContentRead::Failure
    ));
    assert!(TextSecurityGate::may_traverse(
        &SubroleRead::AttributeUnsupported,
        ProtectedContentRead::NoValue
    ));
}

#[test]
fn read_budget_phase_budget_and_probe_invariants() {
    let mut budget = ReadBudget::new(1_000, 150, 768, 32, 100);
    assert_eq!(budget.exploration_deadline_ms(), 850);
    assert_eq!(budget.active_call_limit(), 736);
    assert!(budget.has_exploration_headroom(825));
    assert!(!budget.has_exploration_headroom(826));

    assert!(budget.consume_calls(730, 500));
    assert!(!budget.can_recheck_window_rect()); // 6 calls < 8
    assert!(!budget.consume_calls(10, 500));
    budget.begin_final_validation();
    assert_eq!(budget.active_call_limit(), 768);
    assert_eq!(budget.active_deadline_ms(), 1_000);
    assert!(budget.can_recheck_window_rect()); // 38 calls >= 8
    assert!(budget.consume_calls(10, 900));

    // Text budget overflow permanently latches text_violated.
    assert!(budget.consume_text(60, Some(60)));
    assert_eq!(budget.remaining_text_units(), 40);
    assert!(!budget.consume_text(50, Some(50)));
    assert!(budget.text_violated());
    assert_eq!(budget.remaining_text_units(), 0);
    assert!(!budget.consume_calls(1, 900));

    // PhaseBudget constants.
    assert_eq!(PhaseBudget::optional_deadline(0, 1_000), Some(650));
    assert_eq!(PhaseBudget::optional_deadline(0, 300), None);
    assert_eq!(PhaseBudget::surface_exploration_deadline(0, 650), Some(500));
    assert_eq!(PhaseBudget::surface_exploration_deadline(0, 170), None);

    // StaticTextRangeProbe bisection resolves exact odd length.
    let target = "abcdefghijk"; // 11 UTF-16 units
    let res = StaticTextRangeProbe::read(
        64,
        StaticTextRangeProbe::MAXIMUM_ATTEMPTS,
        StaticTextRangeProbe::DEFAULT_INITIAL_PREFIX_UNITS,
        false,
        || true,
        || true,
        |start, len| bounded_utf16_slice(target, start, len),
    );
    assert_eq!(res.failure, None);
    assert_eq!(res.text.as_deref(), Some(target));
}

#[test]
fn pua_filter_and_surface_baseline_and_window_move_invalidation() {
    assert!(is_private_use_only_text("\u{E000}\u{E001}"));
    assert!(is_private_use_only_text("  \u{F8FF} \u{F0000} \u{100000} "));
    assert!(!is_private_use_only_text(""));
    assert!(!is_private_use_only_text("   \t\n "));
    assert!(!is_private_use_only_text("\u{E000} Settings"));

    let mut baseline = SurfaceBaseline::new();
    let geom1 = SurfaceGeometry::new(SurfaceWindowSize::new(800.0, 600.0), 100);
    let node_a = SurfaceNode {
        id: "n1".to_string(),
        parent_id: None,
        role: "container".to_string(),
        text: None,
        observed_at_ms: 100,
        bounds: Some(SurfaceBounds::new(0.0, 0.0, 800.0, 600.0)),
        bounds_observed_at_ms: Some(100),
        ax_role: Some("AXWindow".to_string()),
        focused: None,
    };
    let node_b = SurfaceNode {
        id: "n2".to_string(),
        parent_id: Some("n1".to_string()),
        role: "editable".to_string(),
        text: Some("hello".to_string()),
        observed_at_ms: 100,
        bounds: Some(SurfaceBounds::new(10.0, 20.0, 200.0, 40.0)),
        bounds_observed_at_ms: Some(100),
        ax_role: Some("AXTextField".to_string()),
        focused: Some(true),
    };

    let s1 = baseline.snapshot(
        "surf-1",
        "window",
        vec![node_a.clone(), node_b.clone()],
        true,
        true,
        false,
        vec![],
        Some(geom1.clone()),
    );
    assert_eq!(s1.mode, "full");
    assert_eq!(s1.revision, 1);
    assert_eq!(s1.base_revision, None);

    // Second complete snapshot computes exact diff.
    let mut node_b2 = node_b.clone();
    node_b2.text = Some("hello world".to_string());
    let node_c = SurfaceNode {
        id: "n3".to_string(),
        parent_id: Some("n1".to_string()),
        role: "text".to_string(),
        text: Some("status".to_string()),
        observed_at_ms: 110,
        bounds: None,
        bounds_observed_at_ms: None,
        ax_role: Some("AXStaticText".to_string()),
        focused: None,
    };
    let s2 = baseline.snapshot(
        "surf-1",
        "window",
        vec![node_a.clone(), node_b2.clone(), node_c],
        true,
        true,
        false,
        vec![],
        Some(geom1),
    );
    assert_eq!(s2.mode, "diff");
    assert_eq!(s2.revision, 2);
    assert_eq!(s2.base_revision, Some(1));
    assert_eq!(s2.added, vec!["n3"]);
    assert_eq!(s2.updated, vec!["n2"]);
    assert!(s2.removed.is_empty());

    // Window move invalidation strips geometry & node bounds and records `geometry-window-moved`.
    let mut moved_nodes = vec![node_a, node_b2];
    let mut geom = Some(SurfaceGeometry::new(SurfaceWindowSize::new(800.0, 600.0), 120));
    let mut reasons = Vec::new();
    let initial = SurfaceAbsoluteRect::new(100.0, 100.0, 800.0, 600.0);
    let final_moved = SurfaceAbsoluteRect::new(120.0, 100.0, 800.0, 600.0);
    assert!(SurfaceBaseline::invalidate_geometry_if_moved(
        &mut moved_nodes,
        &mut geom,
        &mut reasons,
        initial,
        final_moved
    ));
    assert!(geom.is_none());
    assert!(moved_nodes.iter().all(|n| n.bounds.is_none() && n.bounds_observed_at_ms.is_none()));
    assert_eq!(reasons, vec!["geometry-window-moved"]);

    // Incomplete snapshot (from geometry-window-moved) forces full mode AND clears prior baseline.
    let s3 = baseline.snapshot(
        "surf-1",
        "window",
        moved_nodes.clone(),
        true,
        true,
        false,
        reasons,
        geom,
    );
    assert_eq!(s3.mode, "full");
    assert!(!s3.complete);

    let s4 = baseline.snapshot("surf-1", "window", moved_nodes, true, true, false, vec![], None);
    assert_eq!(s4.mode, "full");
    assert_eq!(s4.revision, 4);
}

#[test]
fn uia_control_type_mapping_table_and_gap_roles() {
    // Pre-rule: is_password overrides every control type to AXSecureTextField.
    for ct in [50004, 50020, 50030, 50026] {
        let m = map_uia_control_type_to_ax(ct, true, true, false, false, false, false, false, false);
        assert_eq!(m.ax_role, Some("AXSecureTextField"));
    }

    // Edit single vs multiline.
    assert_eq!(
        map_uia_control_type_to_ax(50004, false, false, false, false, false, false, false, false).ax_role,
        Some("AXTextField")
    );
    assert_eq!(
        map_uia_control_type_to_ax(50004, false, true, false, false, false, false, false, false).ax_role,
        Some("AXTextArea")
    );

    // Text heading vs static text.
    assert_eq!(
        map_uia_control_type_to_ax(50020, false, false, true, false, false, true, false, false).ax_role,
        Some("AXHeading")
    );
    assert_eq!(
        map_uia_control_type_to_ax(50020, false, false, true, false, false, false, false, false).ax_role,
        Some("AXStaticText")
    );

    // Document web vs editable leaf vs terminal vs read-only document.
    assert_eq!(
        map_uia_control_type_to_ax(50030, false, true, false, true, true, false, false, false).ax_role,
        Some("AXWebArea")
    );
    let doc_edit = map_uia_control_type_to_ax(50030, false, true, false, false, false, false, false, false);
    assert_eq!(doc_edit.ax_role, Some("AXTextArea"));
    assert_eq!(doc_edit.category, "editable");
    let doc_term = map_uia_control_type_to_ax(50030, false, true, false, false, false, false, false, true);
    assert_eq!(doc_term.ax_role, Some("AXTextArea"));
    assert_eq!(doc_term.category, "terminal");
    assert_eq!(
        map_uia_control_type_to_ax(50030, false, false, true, false, false, false, false, false).ax_role,
        Some("AXDocument")
    );

    // StatusBar carries synthetic AXApplicationStatus subrole.
    let status = map_uia_control_type_to_ax(50017, false, false, true, false, false, false, false, false);
    assert_eq!(status.ax_role, Some("AXGroup"));
    assert_eq!(status.subrole, Some("AXApplicationStatus"));

    // Pane with and without ScrollPattern.
    assert_eq!(
        map_uia_control_type_to_ax(50033, false, false, true, false, false, false, true, false).ax_role,
        Some("AXScrollArea")
    );
    assert_eq!(
        map_uia_control_type_to_ax(50033, false, false, true, false, false, false, false, false).ax_role,
        Some("AXGroup")
    );

    // Verify every mapped control type produces a valid AX role matching `^AX[A-Za-z0-9]{1,62}$`.
    for ct in 50000..=50040 {
        let m = map_uia_control_type_to_ax(ct, false, false, false, false, false, false, false, false);
        if let Some(ax) = m.ax_role {
            assert!(is_valid_ax_role(ax), "invalid axRole {ax} for ct {ct}");
        }
    }

    // Unmapped controls omit axRole and fall back to "other".
    for unmapped in [50001, 50012, 50015, 50016, 50022, 50027, 50038, 50039, 50040, 99999] {
        let m = map_uia_control_type_to_ax(unmapped, false, false, false, false, false, false, false, false);
        assert_eq!(m.ax_role, None);
        assert_eq!(m.category, "other");
    }

    // Gap role normalization.
    assert_eq!(normalize_gap_role(None), "unavailable");
    assert_eq!(normalize_gap_role(Some("AXTextField")), "AXTextField");
    assert_eq!(normalize_gap_role(Some("AXSecureTextField")), "AXSecureTextField");
    assert_eq!(normalize_gap_role(Some("AXTabButton")), "other");
}

#[test]
fn hello_capabilities_validate_and_match_serve_vs_fixture() {
    let validator = ContractValidator::new().expect("schema loads");

    let fixture_hello = hello_message("inst-1", true);
    validator
        .validate_message(&fixture_hello)
        .expect("fixture hello valid");
    let f_caps = fixture_hello.get("capabilities").and_then(JsonValue::as_array).unwrap();
    assert_eq!(f_caps.len(), 23);
    for name in [
        "text.snapshot",
        "text.visible-range",
        "input.activity",
        "ax.enablement",
        "text.marker",
        "surface.snapshot",
        "selection.snapshot",
        "input.text",
        "menu.action",
        "field.denylist",
    ] {
        let found = f_caps.iter().find(|c| {
            c.get("name").and_then(JsonValue::as_str) == Some(name)
                && c.get("direction").and_then(JsonValue::as_str) == Some("observe")
        });
        assert_eq!(
            found.and_then(|c| c.get("support")).and_then(JsonValue::as_str),
            Some("supported"),
            "fixture mode must support {name}"
        );
    }

    let serve_hello = hello_message("inst-2", false);
    validator
        .validate_message(&serve_hello)
        .expect("serve hello valid");
    let s_caps = serve_hello.get("capabilities").and_then(JsonValue::as_array).unwrap();
    let cap_support = |name: &str| {
        s_caps
            .iter()
            .find(|c| {
                c.get("name").and_then(JsonValue::as_str) == Some(name)
                    && c.get("direction").and_then(JsonValue::as_str) == Some("observe")
            })
            .and_then(|c| c.get("support"))
            .and_then(JsonValue::as_str)
    };
    for name in [
        "text.snapshot",
        "text.visible-range",
        "field.denylist",
        "ax.enablement",
        "surface.snapshot",
        "selection.snapshot",
    ] {
        assert_eq!(cap_support(name), Some("supported"), "serve mode must support {name}");
    }
    for name in ["text.marker", "input.text", "input.activity", "menu.action"] {
        assert_eq!(
            cap_support(name),
            Some("unsupported"),
            "serve mode phase2 must mark {name} unsupported"
        );
    }
}

#[test]
fn adapter_registry_and_safe_display_text() {
    let reg = AdapterRegistry::new();
    assert_eq!(reg.adapter_for("CODE.EXE").id, "vscode-family");
    assert_eq!(reg.adapter_for("antigravity.exe").id, "vscode-family");
    assert_eq!(reg.adapter_for("msedge.exe").id, "browser-family");
    assert_eq!(reg.adapter_for("microsoft.windowsterminal").id, "terminal-family");
    assert!(reg.is_terminal_app("wt.exe"));
    assert_eq!(reg.adapter_for("qq.exe").id, "qq");
    assert_eq!(reg.adapter_for("feishu.exe").id, "feishu");
    assert!(reg.adapter_for("feishu.exe").collapse_empty_containers);
    assert_eq!(reg.adapter_for("wechat.exe").id, "wechat");
    assert_eq!(reg.adapter_for("slack.exe").id, "slack");
    assert_eq!(reg.adapter_for("91750d7e.slack").id, "slack");
    assert_eq!(reg.adapter_for("91750D7E.SLACK").id, "slack");
    assert!(reg.adapter_for("91750d7e.slack").collapse_empty_containers);
    assert_eq!(reg.adapter_for("typora.exe").id, "typora");
    assert_eq!(reg.adapter_for("figma.exe").id, "figma");
    assert!(reg.adapter_for("figma.exe").collapse_empty_containers);
    assert!(reg.adapter_for("chrome.exe").collapse_empty_containers);
    assert!(reg.adapter_for("code.exe").collapse_empty_containers);
    assert_eq!(reg.adapter_for("notepad.exe").id, "generic");

    assert_eq!(
        SafeDisplayText::compose("AXButton", Some("\u{E000}"), None, None, 64),
        None
    );
    assert_eq!(
        SafeDisplayText::compose("AXWebArea", Some("Docs"), None, Some("https://example.com"), 64),
        Some("Docs (https://example.com)".to_string())
    );
}

#[test]
fn richedit_class_and_focused_contenteditable_classification() {
    for cls in ["RichEditD2DPT", "RICHEDIT50W", "RichEdit20W", "RichEdit50W", "richeditd2dpt"] {
        assert!(is_native_richedit_class(Some(cls)), "expected RichEdit class: {cls}");
    }
    for non_re in [None, Some(""), Some("Chrome_RenderWidgetHostHWND"), Some("Chrome_WidgetWin_1")] {
        assert!(!is_native_richedit_class(non_re), "unexpected RichEdit class: {non_re:?}");
    }

    // Feishu / Slack ProseMirror / Quill contenteditable composer (Group / Custom / Document with role=textbox).
    for ct in [50025, 50026, 50030] {
        for role in ["textbox", "combobox", "searchbox"] {
            assert!(
                is_focused_editable_content_control(
                    ct,
                    ProtectedContentRead::Value(false),
                    true,
                    false,
                    None,
                    Some(true),
                    Some(true),
                    Some(role),
                    None,
                ),
                "expected focused contenteditable match for ct={ct} role={role}"
            );
        }
    }

    // Explicit writable ValuePattern + TextPattern on Group/Custom without ARIA role.
    assert!(is_focused_editable_content_control(
        50026,
        ProtectedContentRead::Value(false),
        true,
        true,
        Some(false),
        Some(true),
        Some(false),
        None,
        None,
    ));

    // Read-only whole-page Chromium/Firefox Document MUST NOT emit bogus focused text.snapshot.
    assert!(!is_focused_editable_content_control(
        50030,
        ProtectedContentRead::Value(false),
        true,
        false,
        None,
        Some(true),
        Some(true),
        Some("rootwebarea"),
        Some("Chrome_RenderWidgetHostHWND"),
    ));
    assert!(!is_focused_editable_content_control(
        50030,
        ProtectedContentRead::Value(false),
        true,
        true,
        Some(false),
        Some(true),
        Some(true),
        Some("document"),
        None,
    ));
    assert!(!is_focused_editable_content_control(
        50030,
        ProtectedContentRead::Value(false),
        true,
        true,
        Some(false),
        Some(true),
        Some(true),
        None,
        Some("Chrome_RenderWidgetHostHWND"),
    ));

    // Read-only textbox, password field, missing TextPattern, or non-focusable control MUST reject.
    assert!(!is_focused_editable_content_control(
        50026,
        ProtectedContentRead::Value(false),
        true,
        true,
        Some(true),
        Some(true),
        Some(true),
        Some("textbox"),
        None,
    ));
    assert!(!is_focused_editable_content_control(
        50026,
        ProtectedContentRead::Value(true),
        true,
        true,
        Some(false),
        Some(true),
        Some(true),
        Some("textbox"),
        None,
    ));
    assert!(!is_focused_editable_content_control(
        50026,
        ProtectedContentRead::Value(false),
        false,
        true,
        Some(false),
        Some(true),
        Some(true),
        Some("textbox"),
        None,
    ));
    assert!(!is_focused_editable_content_control(
        50026,
        ProtectedContentRead::Value(false),
        true,
        true,
        Some(false),
        Some(false),
        Some(false),
        Some("textbox"),
        None,
    ));
}

#[test]
fn win_event_pid_filtering_prevents_background_focus_thrashing() {
    // Foreground switch ALWAYS wakes dirty + focus_invalidated from any PID.
    assert_eq!(classify_win_event(EVENT_SYSTEM_FOREGROUND, 2222, 1111, 1111), (true, true));
    assert_eq!(classify_win_event(EVENT_SYSTEM_FOREGROUND, 0, 1111, 1111), (true, true));

    // Background PID focus/value/selection MUST NOT wake or invalidate focus!
    assert_eq!(classify_win_event(EVENT_OBJECT_FOCUS, 2222, 1111, 1111), (false, false));
    assert_eq!(classify_win_event(EVENT_OBJECT_VALUECHANGE, 2222, 1111, 1111), (false, false));
    assert_eq!(
        classify_win_event(EVENT_OBJECT_TEXTSELECTIONCHANGED, 2222, 1111, 1111),
        (false, false)
    );
    assert_eq!(classify_win_event(EVENT_OBJECT_FOCUS, 0, 1111, 1111), (false, false));

    // Matching target PID (or raw ApplicationFrameHost PID) wakes appropriately.
    assert_eq!(classify_win_event(EVENT_OBJECT_FOCUS, 1111, 1111, 3333), (true, true));
    assert_eq!(classify_win_event(EVENT_OBJECT_FOCUS, 3333, 1111, 3333), (true, true));
    assert_eq!(classify_win_event(EVENT_OBJECT_VALUECHANGE, 1111, 1111, 3333), (true, false));
    assert_eq!(
        classify_win_event(EVENT_OBJECT_TEXTSELECTIONCHANGED, 3333, 1111, 3333),
        (true, false)
    );

    // Unbound target (0) accepts events until first read binds PID.
    assert_eq!(classify_win_event(EVENT_OBJECT_FOCUS, 2222, 0, 0), (true, true));
    assert_eq!(classify_win_event(EVENT_OBJECT_VALUECHANGE, 2222, 0, 0), (true, false));
}

#[test]
fn dual_id_resolution_prevents_msix_shadowing_and_afh_fallback() {
    let denylist_browsers_off = CapturePolicy {
        enabled: true,
        application_scope: Some("denylist".to_string()),
        allow_browser_content: Some(false),
        excluded_application_ids: Some(vec!["slack.exe".to_string()]),
        ..CapturePolicy::default()
    };
    let denylist_browsers_on = CapturePolicy {
        allow_browser_content: Some(true),
        ..denylist_browsers_off.clone()
    };
    let allowlist = CapturePolicy {
        enabled: true,
        application_scope: Some("allowlist".to_string()),
        allowed_application_ids: vec![
            "8bitsolutionsllc.bitwardendesktop".to_string(),
            "thebrowsercompany.arc".to_string(),
            "windowsterminal.exe".to_string(),
        ],
        ..CapturePolicy::default()
    };
    let registry = AdapterRegistry::new();

    // Store Bitwarden: MSIX package name must NEVER shadow `bitwarden.exe` mandatory deny!
    let store_bitwarden = ResolvedAppIdentity::from_parts(
        Some("8bitsolutionsllc.bitwardendesktop".to_string()),
        Some("bitwarden.exe".to_string()),
    )
    .expect("valid dual identity");
    assert_eq!(
        store_bitwarden.application_id,
        "8bitsolutionsllc.bitwardendesktop"
    );
    assert_eq!(
        store_bitwarden.candidate_ids(),
        vec!["8bitsolutionsllc.bitwardendesktop", "bitwarden.exe"]
    );
    assert!(store_bitwarden.matches_id("BITWARDEN.EXE"));
    assert!(store_bitwarden.matches_id("8bitSolutionsLLC.BitwardenDesktop"));
    assert!(ApplicationPolicy::is_mandatory_denied_identity(&store_bitwarden));
    assert!(!ApplicationPolicy::allows_identity(
        &denylist_browsers_on,
        &store_bitwarden
    ));
    assert!(!ApplicationPolicy::allows_identity(
        &allowlist,
        &store_bitwarden
    ));
    assert_eq!(
        ApplicationPolicy::evaluate_identity(&denylist_browsers_on, &store_bitwarden),
        IdentityPolicyOutcome::MandatoryDenied
    );

    // Windows AppX System UI apps must NEVER bypass System UI skip via package name!
    for (pkg, exe) in [
        ("microsoftwindows.client.cbs", "textinputhost.exe"),
        ("microsoft.lockapp", "lockapp.exe"),
        ("microsoft.windows.shellexperiencehost", "shellexperiencehost.exe"),
        (
            "microsoft.windows.startmenuexperiencehost",
            "startmenuexperiencehost.exe",
        ),
        ("microsoft.windows.search", "searchhost.exe"),
        ("microsoft.windows.search", "searchapp.exe"),
    ] {
        let sys_id = ResolvedAppIdentity::from_parts(Some(pkg.to_string()), Some(exe.to_string()))
            .expect("valid system ui identity");
        assert!(
            ApplicationPolicy::is_system_ui_identity(&sys_id),
            "expected System UI match for ({pkg}, {exe})"
        );
        assert!(
            !ApplicationPolicy::allows_identity(&denylist_browsers_on, &sys_id),
            "System UI ({pkg}, {exe}) must be denied"
        );
        assert_eq!(
            ApplicationPolicy::evaluate_identity(&denylist_browsers_on, &sys_id),
            IdentityPolicyOutcome::SystemUi
        );
    }

    // MSIX Arc & Store Firefox: browser gate + browser-family adapter (`block_private_windows: true`).
    for (pkg, exe) in [
        ("thebrowsercompany.arc", "arc.exe"),
        ("mozilla.firefox", "firefox.exe"),
    ] {
        let browser_id =
            ResolvedAppIdentity::from_parts(Some(pkg.to_string()), Some(exe.to_string()))
                .expect("valid browser identity");
        assert!(ApplicationPolicy::is_browser_identity(&browser_id));
        assert!(BrowserGate::is_known_browser_identity(&browser_id));
        assert!(!ApplicationPolicy::allows_identity(
            &denylist_browsers_off,
            &browser_id
        ));
        assert_eq!(
            ApplicationPolicy::evaluate_identity(&denylist_browsers_off, &browser_id),
            IdentityPolicyOutcome::BrowserExcluded
        );
        assert!(!ApplicationPolicy::allows_identity(&allowlist, &browser_id));
        assert!(ApplicationPolicy::allows_identity(
            &denylist_browsers_on,
            &browser_id
        ));
        assert!(BrowserGate::allows_identity(
            &browser_id,
            &denylist_browsers_on,
            false
        ));
        assert!(BrowserGate::should_block_private_windows_identity(
            &browser_id,
            false
        ));
        let spec = registry.adapter_for_identity(&browser_id);
        assert_eq!(spec.id, "browser-family");
        assert!(spec.block_private_windows);
    }

    // User denylist matches exe_name even when primary ID is an MSIX package name.
    let store_slack = ResolvedAppIdentity::from_parts(
        Some("91750d7e.slack".to_string()),
        Some("slack.exe".to_string()),
    )
    .expect("valid slack identity");
    assert_eq!(
        ApplicationPolicy::evaluate_identity(&denylist_browsers_on, &store_slack),
        IdentityPolicyOutcome::ExcludedByPolicy
    );
    assert!(!ApplicationPolicy::allows_identity(
        &denylist_browsers_on,
        &store_slack
    ));
    assert_eq!(registry.adapter_for_identity(&store_slack).id, "slack");

    // Allowlist matches STRICTLY against the canonical emitted primary wire ID (`application_id`),
    // so worker, engine, and Host `supervisor.ts` agree 100%, while mandatory exclusions,
    // System UI skips, user denylist exclusions, browser gating, and adapters still match dual-ID.
    let wt = ResolvedAppIdentity::from_parts(
        Some("microsoft.windowsterminal".to_string()),
        Some("windowsterminal.exe".to_string()),
    )
    .expect("valid terminal identity");
    assert_eq!(
        ApplicationPolicy::evaluate_identity(&allowlist, &wt),
        IdentityPolicyOutcome::NotInAllowlist
    );
    assert!(!ApplicationPolicy::allows_identity(&allowlist, &wt));
    assert!(registry.is_terminal_identity(&wt));

    let notepad_msix = ResolvedAppIdentity::from_parts(
        Some("microsoft.windowsnotepad".to_string()),
        Some("notepad.exe".to_string()),
    )
    .expect("valid msix notepad identity");
    let allowlist_by_exe = CapturePolicy {
        enabled: true,
        application_scope: Some("allowlist".to_string()),
        allowed_application_ids: vec!["notepad.exe".to_string()],
        ..CapturePolicy::default()
    };
    let allowlist_by_pkg = CapturePolicy {
        enabled: true,
        application_scope: Some("allowlist".to_string()),
        allowed_application_ids: vec!["microsoft.windowsnotepad".to_string()],
        ..CapturePolicy::default()
    };
    let denylist_excluding_notepad_exe = CapturePolicy {
        enabled: true,
        application_scope: Some("denylist".to_string()),
        allow_browser_content: Some(true),
        excluded_application_ids: Some(vec!["notepad.exe".to_string()]),
        ..CapturePolicy::default()
    };
    assert_eq!(
        ApplicationPolicy::evaluate_identity(&allowlist_by_exe, &notepad_msix),
        IdentityPolicyOutcome::NotInAllowlist
    );
    assert!(!ApplicationPolicy::allows_identity(
        &allowlist_by_exe,
        &notepad_msix
    ));
    assert_eq!(
        ApplicationPolicy::evaluate_identity(&allowlist_by_pkg, &notepad_msix),
        IdentityPolicyOutcome::Allowed
    );
    assert!(ApplicationPolicy::allows_identity(
        &allowlist_by_pkg,
        &notepad_msix
    ));
    assert_eq!(
        ApplicationPolicy::evaluate_identity(&denylist_excluding_notepad_exe, &notepad_msix),
        IdentityPolicyOutcome::ExcludedByPolicy
    );
    assert!(!ApplicationPolicy::allows_identity(
        &denylist_excluding_notepad_exe,
        &notepad_msix
    ));

    // `from_wire_and_exe` preserves primary ID, retains secondary exe_name, and fails closed on AFH/invalid.
    let wire_bw = ResolvedAppIdentity::from_wire_and_exe(
        "8bitsolutionsllc.bitwardendesktop".to_string(),
        Some("bitwarden.exe".to_string()),
    )
    .expect("valid wire+exe identity");
    assert_eq!(wire_bw.application_id, "8bitsolutionsllc.bitwardendesktop");
    assert_eq!(wire_bw.exe_name.as_deref(), Some("bitwarden.exe"));
    assert!(ApplicationPolicy::is_mandatory_denied_identity(&wire_bw));
    assert_eq!(
        ResolvedAppIdentity::from_wire_and_exe(
            "microsoft.someuwp".to_string(),
            Some("applicationframehost.exe".to_string()),
        ),
        None
    );
    assert_eq!(
        ResolvedAppIdentity::from_wire_and_exe(
            "microsoft.someuwp".to_string(),
            Some("bad id with spaces".to_string()),
        ),
        None
    );

    // Fail-closed ApplicationFrameHost.exe guards.
    assert_eq!(
        ResolvedAppIdentity::from_parts(None, Some("applicationframehost.exe".to_string())),
        None
    );
    assert_eq!(
        ResolvedAppIdentity::from_parts(
            Some("microsoft.someuwp".to_string()),
            Some("applicationframehost.exe".to_string())
        ),
        None
    );
    assert_eq!(
        ResolvedAppIdentity::from_single("applicationframehost.exe".to_string()),
        None
    );
    assert!(!ApplicationPolicy::allows(
        "applicationframehost.exe",
        &denylist_browsers_on
    ));
    let manual_afh = ResolvedAppIdentity {
        application_id: "applicationframehost.exe".to_string(),
        exe_name: Some("applicationframehost.exe".to_string()),
        package_name: None,
    };
    assert!(!ApplicationPolicy::allows_identity(
        &denylist_browsers_on,
        &manual_afh
    ));
    assert_eq!(resolve_effective_pid_checked(0, None), None);
    assert_eq!(resolve_effective_pid_checked(1, None), None);
}

#[test]
fn normalize_windows_exe_name_non_ascii_deterministic_and_no_exe_collapse() {
    let wechat_cn = normalize_windows_exe_name(r"C:\Apps\微信.exe")
        .expect("non-ASCII exe normalizes deterministically");
    let wechat_cn_upper_ext =
        normalize_windows_exe_name(r"D:\Other\微信.EXE").expect("case-insensitive .EXE");
    let notepad_jp = normalize_windows_exe_name(r"C:\Tools\メモ帳.exe")
        .expect("Japanese exe normalizes deterministically");

    assert_eq!(wechat_cn, wechat_cn_upper_ext);
    assert_ne!(wechat_cn, "exe");
    assert_ne!(notepad_jp, "exe");
    assert_ne!(wechat_cn, notepad_jp);
    assert!(wechat_cn.starts_with("app-"));
    assert!(wechat_cn.ends_with(".exe"));
    assert!(notepad_jp.starts_with("app-"));
    assert!(notepad_jp.ends_with(".exe"));
    assert!(is_valid_application_id(&wechat_cn));
    assert!(is_valid_application_id(&notepad_jp));

    // Empty / punctuation-only stems must NEVER collapse to "exe".
    assert_eq!(normalize_windows_exe_name(".exe"), None);
    assert_eq!(normalize_windows_exe_name("...exe"), None);
    assert_eq!(normalize_windows_exe_name("___.exe"), None);
    assert_eq!(normalize_windows_exe_name("   .exe"), None);

    // Normal ASCII executables remain 100% unchanged.
    assert_eq!(
        normalize_windows_exe_name("notepad.exe").as_deref(),
        Some("notepad.exe")
    );
    assert_eq!(
        normalize_windows_exe_name("Feishu.exe").as_deref(),
        Some("feishu.exe")
    );
    assert_eq!(
        normalize_windows_exe_name("Proton Pass.exe").as_deref(),
        Some("protonpass.exe")
    );
}

#[test]
fn classify_windows_strict_fails_closed_on_failure_and_malformed() {
    for bad_pw in [ProtectedContentRead::Failure, ProtectedContentRead::Malformed] {
        // Even with a safe subrole or character_count_known, Failure/Malformed MUST return Unknown.
        assert_eq!(
            TextSecurityGate::classify_windows_strict(
                Some("AXTextField"),
                &SubroleRead::Value("AXStandardTextField".to_string()),
                bad_pw,
                true,
                true,
                true,
            ),
            SecureStatus::Unknown
        );
        assert_eq!(
            TextSecurityGate::classify_windows_strict(
                Some("AXStaticText"),
                &SubroleRead::NoValue,
                bad_pw,
                false,
                false,
                true,
            ),
            SecureStatus::Unknown
        );
        // Explicit AXSecureTextField or sensitive subrole still classifies as Sensitive.
        assert_eq!(
            TextSecurityGate::classify_windows_strict(
                Some("AXSecureTextField"),
                &SubroleRead::NoValue,
                bad_pw,
                true,
                true,
                true,
            ),
            SecureStatus::Sensitive
        );
        assert_eq!(
            TextSecurityGate::classify_windows_strict(
                Some("AXTextField"),
                &SubroleRead::Value("AXPasswordField".to_string()),
                bad_pw,
                true,
                true,
                true,
            ),
            SecureStatus::Sensitive
        );
    }

    for bad_sub in [SubroleRead::Failure, SubroleRead::Malformed] {
        assert_eq!(
            TextSecurityGate::classify_windows_strict(
                Some("AXTextField"),
                &bad_sub,
                ProtectedContentRead::Value(false),
                true,
                true,
                true,
            ),
            SecureStatus::Unknown
        );
        assert_eq!(
            TextSecurityGate::classify_windows_strict(
                Some("AXTextField"),
                &bad_sub,
                ProtectedContentRead::Value(true),
                true,
                true,
                true,
            ),
            SecureStatus::Sensitive
        );
    }

    assert_eq!(
        TextSecurityGate::classify_windows_strict(
            Some("AXTextField"),
            &SubroleRead::NoValue,
            ProtectedContentRead::Value(false),
            true,
            true,
            false,
        ),
        SecureStatus::Safe
    );
    assert_eq!(
        TextSecurityGate::classify_windows_strict(
            Some("AXStaticText"),
            &SubroleRead::NoValue,
            ProtectedContentRead::Value(false),
            false,
            false,
            false,
        ),
        SecureStatus::Safe
    );
}
