use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use access_contract::{utf16_len, ContractValidator, JsonValue};
use collector_core::adapters::{BROWSER_FAMILY_SPEC, GENERIC_ADAPTER_SPEC};
use collector_core::input_text_core::{
    is_altgr_active, HeldKeyBitset, ImeCompositionState, InputTextAccumulator,
    InputTextApprovedContext, InputTextCaptureDecision, InputTextCaptureStep, InputTextContext,
    InputTextEventMetadata, InputTextFieldRole, InputTextGapReason, InputTextGapRecord,
    InputTextIngestOutcome, InputTextKind, InputTextLimits, InputTextModifier,
    InputTextPrivateState, InputTextReadGate, InputTextReadRejection, InputTextReadRejectionReason,
    InputTextReadRejectionStage, InputTextRecord, InputTextSafetyRequest, InputTextSample,
    InputTextSource, InputTextUnicodeRead, PendingSurrogate, SurrogateAssemblyOutcome,
    WindowsModifierState,
};
use collector_core::menu_action_core::{
    is_menu_structure_control_type, BrowserChromeVerdict, BrowserMenuWindowGate,
    BrowserWindowCountRead, BrowserWindowInspection, BrowserWindowReference,
    MenuActionDeduplicator, MenuActionPendingQueue, MenuActionRecord, MenuActionSource,
    MenuNodeSnapshot, MenuPathLimits, MenuPathResolver, MenuTrackingStateMachine, OpenedMenuKind,
    ResolvedMenuPath, Win32MenuBarLink, UIA_CUSTOM_CONTROL_TYPE, UIA_DOCUMENT_CONTROL_TYPE,
    UIA_EDIT_CONTROL_TYPE, UIA_GROUP_CONTROL_TYPE, UIA_IMAGE_CONTROL_TYPE,
    UIA_MENU_BAR_CONTROL_TYPE, UIA_MENU_CONTROL_TYPE, UIA_MENU_ITEM_CONTROL_TYPE,
    UIA_PANE_CONTROL_TYPE, UIA_TEXT_CONTROL_TYPE, UIA_WINDOW_CONTROL_TYPE,
};
use collector_core::policy::{ProtectedContentRead, ResolvedAppIdentity, SubroleRead};
use collector_core::protocol_model::{
    json_i64, ApplicationIdentity, ApplicationTargetIdentity, CapturePolicy, GapDiagnosticCode,
    InputActivityAccumulator, InputActivityCategory, InputActivitySample, SecureStatus, Stamp,
    TargetIdentity,
};

const BASE_NS: u64 = 1_000_000_000;

fn default_input_policy() -> CapturePolicy {
    CapturePolicy {
        enabled: true,
        input_activity: Some(false),
        application_scope: Some("denylist".to_string()),
        input_text: Some(true),
        max_text_code_units: 2_048,
        ..CapturePolicy::default()
    }
}

fn std_context() -> InputTextContext {
    InputTextContext {
        target: TargetIdentity {
            device_id: "win-device".to_string(),
            os_session_id: "win-session".to_string(),
            desktop_id: "win-desktop".to_string(),
            process_id: 42,
            process_start_time: "2026-11-24T15:00:00Z".to_string(),
            application_id: "notepad.exe".to_string(),
            window_id: "hwnd-1".to_string(),
            window_generation: 1,
        },
        surface_id: "field-1".to_string(),
        capture_epoch: 1,
        foreground_generation: 1,
        focus_generation: 1,
        policy_revision: 1,
        field_security_mode: "strict".to_string(),
        secure_status: SecureStatus::Safe,
        private_state: InputTextPrivateState::Normal,
        exe_name: Some("notepad.exe".to_string()),
    }
}

fn ctx_with_identity(app: &str, exe_name: Option<&str>) -> InputTextContext {
    let mut ctx = std_context();
    ctx.target.application_id = app.to_string();
    ctx.exe_name = exe_name.map(str::to_string);
    ctx
}

fn std_meta(pid: u32, ts_ns: u64, time_ms: i64) -> InputTextEventMetadata {
    InputTextEventMetadata {
        target_process_id: pid,
        timestamp_ns: ts_ns,
        callback_time_ms: time_ms,
    }
}

fn approved(
    ctx: InputTextContext,
    ts_ns: u64,
    role: InputTextFieldRole,
) -> InputTextApprovedContext {
    InputTextApprovedContext {
        context: ctx,
        metadata_monotonic_ns: ts_ns,
        role,
    }
}

fn sample(
    ctx: InputTextContext,
    kind: InputTextKind,
    text: &str,
    modifiers: Vec<InputTextModifier>,
    time_ms: i64,
) -> InputTextSample {
    InputTextSample::new(ctx, kind, text.to_string(), modifiers, time_ms)
}

fn seal_one(s: InputTextSample, source: InputTextSource) -> InputTextRecord {
    let ctx = s.context.clone();
    let end_ms = s.callback_time_ms;
    let mut acc = InputTextAccumulator::default();
    assert_eq!(acc.add(s, source), None);
    acc.take_due(end_ms + InputTextLimits::DEBOUNCE_MS, Some(&ctx))
        .expect("expected due record")
}

fn wrap_observation(
    event_time_ms: i64,
    monotonic_ms: i64,
    target: JsonValue,
    stamp: Stamp,
    payload: JsonValue,
) -> JsonValue {
    let mut map = BTreeMap::new();
    map.insert("protocolVersion".to_string(), json_i64(1));
    map.insert(
        "type".to_string(),
        JsonValue::String("observation".to_string()),
    );
    map.insert("eventId".to_string(), JsonValue::String("win:1".to_string()));
    map.insert(
        "instanceId".to_string(),
        JsonValue::String("collector-win".to_string()),
    );
    map.insert("seq".to_string(), json_i64(1));
    map.insert("eventTimeMs".to_string(), json_i64(event_time_ms));
    map.insert("monotonicMs".to_string(), json_i64(monotonic_ms));
    map.insert("target".to_string(), target);
    map.insert("stamp".to_string(), stamp.to_json());
    map.insert("actor".to_string(), JsonValue::String("unknown".to_string()));
    map.insert("relatedActionIds".to_string(), JsonValue::Array(Vec::new()));
    map.insert("payload".to_string(), payload);
    JsonValue::Object(map)
}

// =============================================================================
// 1. input.activity Core, AltGr, Autorepeat Bitset & Contract Validation
// =============================================================================

#[test]
fn input_activity_bucketing_256_cap_and_wire_contract() {
    let validator = ContractValidator::new().expect("validator");
    let app = ApplicationIdentity {
        application_id: "notepad.exe".to_string(),
        process_id: 42,
        process_start_time: "2026-11-24T15:00:00Z".to_string(),
    };
    let stamp = Stamp {
        capture_epoch: 1,
        foreground_generation: 2,
        focus_generation: 3,
        policy_revision: 1,
    };
    let categories = [
        InputActivityCategory::PointerRelease,
        InputActivityCategory::DragSample,
        InputActivityCategory::ScrollSample,
        InputActivityCategory::ShortcutPress,
    ];
    let mut acc = InputActivityAccumulator::default();
    for i in 0..300 {
        acc.add(
            InputActivitySample {
                application: app.clone(),
                exe_name: Some("notepad.exe".to_string()),
                category: categories[i % 4],
                callback_time_ms: 1_100 + (i as i64 % 500),
            },
            stamp,
        );
    }
    assert!(acc.take_completed(1_999).is_none());
    let bucket = acc.take_completed(2_000).expect("1s bucket completes");
    assert_eq!(bucket.interval_start_ms, 1_000);
    assert_eq!(bucket.interval_end_ms(), 2_000);
    assert_eq!(bucket.total(), 256);
    assert!(bucket.capped);
    assert_eq!(bucket.pointer_releases, 64);
    assert_eq!(bucket.drag_samples, 64);
    assert_eq!(bucket.scroll_samples, 64);
    assert_eq!(bucket.shortcut_presses, 64);
    assert!(acc.take_completed(2_001).is_none());

    let app_target = ApplicationTargetIdentity {
        device_id: "win-device".to_string(),
        os_session_id: "win-session".to_string(),
        desktop_id: "win-desktop".to_string(),
        process_id: app.process_id,
        process_start_time: app.process_start_time.clone(),
        application_id: app.application_id.clone(),
    };
    for fixture in [false, true] {
        let payload = bucket.payload(fixture);
        let expected_source = if fixture {
            "fixture"
        } else {
            "win32.listen-only"
        };
        assert_eq!(
            payload.get("source").and_then(JsonValue::as_str),
            Some(expected_source)
        );
        let reasons = payload
            .get("coverage")
            .and_then(|c| c.get("missingReasons"))
            .and_then(JsonValue::as_array)
            .expect("missingReasons");
        assert!(reasons
            .iter()
            .any(|v| v.as_str() == Some("input-events-capped")));
        let envelope = wrap_observation(
            bucket.interval_end_ms(),
            2_000,
            app_target.to_target_ref(),
            bucket.stamp,
            payload,
        );
        validator
            .encode_frame(&envelope)
            .expect("input.activity envelope must validate");
    }
}

#[test]
fn input_activity_discontinuities_and_stale_flush_drop() {
    let app = ApplicationIdentity {
        application_id: "notepad.exe".to_string(),
        process_id: 42,
        process_start_time: "birth-1".to_string(),
    };
    let stamp = Stamp {
        capture_epoch: 1,
        foreground_generation: 1,
        focus_generation: 1,
        policy_revision: 1,
    };
    let make = |app: ApplicationIdentity, ms: i64| InputActivitySample {
        application: app,
        exe_name: None,
        category: InputActivityCategory::PointerRelease,
        callback_time_ms: ms,
    };

    // Clock backstep before intervalStartMs clears bucket.
    let mut acc = InputActivityAccumulator::default();
    acc.add(make(app.clone(), 1_100), stamp);
    assert!(acc.take_completed(999).is_none());
    assert!(acc.take_completed(2_000).is_none());

    // Exact 1_000ms grace after intervalEndMs succeeds; 1_001ms stale flush drops.
    acc.add(make(app.clone(), 1_100), stamp);
    assert!(acc.take_completed(3_000).is_some());
    acc.add(make(app.clone(), 1_100), stamp);
    assert!(acc.take_completed(3_001).is_none());
    assert!(acc.take_completed(2_000).is_none());

    // Invalid timestamps or PID <= 1 clear pending.
    for bad_ms in [-1, 9_007_199_254_739_001] {
        acc.add(make(app.clone(), 1_100), stamp);
        acc.add(make(app.clone(), bad_ms), stamp);
        assert!(acc.take_completed(2_000).is_none());
    }
    acc.add(make(app.clone(), 1_100), stamp);
    acc.add(
        make(
            ApplicationIdentity {
                process_id: 1,
                ..app.clone()
            },
            1_200,
        ),
        stamp,
    );
    assert!(acc.take_completed(2_000).is_none());

    // App / epoch / policy / interval transitions discard previous bucket without merging.
    acc.add(make(app.clone(), 1_100), stamp);
    let mut stamp2 = stamp;
    stamp2.capture_epoch = 2;
    acc.add(make(app.clone(), 1_200), stamp2);
    let b = acc.take_completed(2_000).expect("new epoch bucket");
    assert_eq!(b.total(), 1);
    assert_eq!(b.stamp.capture_epoch, 2);
}

#[test]
fn altgr_normalization_autorepeat_bitset_and_timestamp_freshness() {
    // Pure AltGr (LCtrl + RAlt without RCtrl/LAlt/Win) is NOT a shortcut.
    let altgr = WindowsModifierState {
        left_ctrl: true,
        right_alt: true,
        ..WindowsModifierState::default()
    };
    assert!(is_altgr_active(altgr));
    let norm = altgr.normalize();
    assert!(norm.is_altgr);
    assert!(!norm.is_shortcut);
    assert!(norm.modifiers.is_empty());

    // AltGr + Shift preserves Shift only and remains non-shortcut text.
    let altgr_shift = WindowsModifierState {
        left_ctrl: true,
        right_alt: true,
        left_shift: true,
        ..WindowsModifierState::default()
    };
    let norm_shift = altgr_shift.normalize();
    assert!(norm_shift.is_altgr);
    assert!(!norm_shift.is_shortcut);
    assert_eq!(norm_shift.modifiers, vec![InputTextModifier::Shift]);

    // Adding RCtrl, LAlt, LWin, or RWin breaks AltGr and classifies as shortcut.
    for extra in [
        WindowsModifierState {
            right_ctrl: true,
            ..altgr
        },
        WindowsModifierState {
            left_alt: true,
            ..altgr
        },
        WindowsModifierState {
            left_win: true,
            ..altgr
        },
        WindowsModifierState {
            right_win: true,
            ..altgr
        },
    ] {
        assert!(!is_altgr_active(extra));
        let n = extra.normalize();
        assert!(!n.is_altgr);
        assert!(n.is_shortcut);
        assert!(n.modifiers.contains(&InputTextModifier::Control));
    }

    // Plain Ctrl+Shift+Alt+Win emits canonical order [Command, Control, Option, Shift].
    let all_mods = WindowsModifierState {
        right_ctrl: true,
        left_alt: true,
        right_shift: true,
        left_win: true,
        ..WindowsModifierState::default()
    }
    .normalize();
    assert!(all_mods.is_shortcut);
    assert_eq!(all_mods.modifiers, InputTextModifier::ALL.to_vec());

    // Alt-only without Ctrl/Win is NOT a shortcut.
    let alt_only = WindowsModifierState {
        left_alt: true,
        ..WindowsModifierState::default()
    }
    .normalize();
    assert!(!alt_only.is_altgr);
    assert!(!alt_only.is_shortcut);
    assert_eq!(alt_only.modifiers, vec![InputTextModifier::Option]);

    // HeldKeyBitset autorepeat suppression across all 4 u64 words.
    let mut held = HeldKeyBitset::new();
    for vk in [0u8, 1, 63, 64, 65, 127, 128, 191, 192, 254, 255] {
        assert!(!held.is_held(vk));
        assert!(held.press(vk), "first press of vk {vk} must return true");
        assert!(held.is_held(vk));
        assert!(!held.press(vk), "autorepeat of vk {vk} must return false");
        held.release(vk);
        assert!(!held.is_held(vk));
        assert!(held.press(vk), "re-press after release must return true");
    }
    held.clear();
    for vk in 0u8..=255 {
        assert!(!held.is_held(vk));
    }

    // Event timestamp freshness boundaries (200ms window + strictly after boundary).
    assert!(!InputTextLimits::is_timestamp_fresh(0, BASE_NS, 0));
    assert!(!InputTextLimits::is_timestamp_fresh(BASE_NS + 1, BASE_NS, 0));
    assert!(InputTextLimits::is_timestamp_fresh(800_000_000, BASE_NS, 0));
    assert!(!InputTextLimits::is_timestamp_fresh(
        799_999_999,
        BASE_NS,
        0
    ));
    assert!(!InputTextLimits::is_timestamp_fresh(
        950_000_000,
        BASE_NS,
        950_000_000
    ));
    assert!(InputTextLimits::is_timestamp_fresh(
        950_000_001,
        BASE_NS,
        950_000_000
    ));
}

// =============================================================================
// 2. input.text Core: Pre-Gate, Post-Gate, Shortcuts, Return, Surrogates, IME
// =============================================================================

#[test]
fn input_text_policy_default_off_and_pre_gate_never_invokes_unicode() {
    assert_eq!(CapturePolicy::default().input_text, None);
    for value in [None, Some(false)] {
        let mut policy = default_input_policy();
        policy.input_text = value;
        policy.input_activity = Some(true);
        let mut safety_calls = 0;
        let mut unicode_calls = 0;
        let mut rejections = Vec::new();
        let decision = InputTextReadGate::capture(
            std_meta(42, BASE_NS, 1_000),
            &[],
            &policy,
            0,
            || BASE_NS,
            |_| {
                safety_calls += 1;
                Err(InputTextGapReason::Stale)
            },
            || {
                unicode_calls += 1;
                InputTextUnicodeRead::Text("never".to_string())
            },
            |r| rejections.push(r),
        );
        assert_eq!(
            decision,
            InputTextCaptureDecision::Gap(InputTextGapReason::PolicyBoundary)
        );
        assert_eq!(safety_calls, 0);
        assert_eq!(unicode_calls, 0);
        assert_eq!(
            rejections,
            vec![InputTextReadRejection::new(
                InputTextReadRejectionStage::Receive,
                InputTextReadRejectionReason::PolicyDisabled,
            )]
        );
    }

    // Invalid / future / delayed / pre-boundary events fail before safety or unicode.
    let policy = default_input_policy();
    for bad_ts in [0u64, BASE_NS + 1, BASE_NS - 200_000_001, 900_000_000] {
        let mut safety_calls = 0;
        let mut unicode_calls = 0;
        let decision = InputTextReadGate::capture(
            std_meta(42, bad_ts, 1_000),
            &[],
            &policy,
            900_000_000,
            || BASE_NS,
            |_| {
                safety_calls += 1;
                Ok(approved(
                    std_context(),
                    BASE_NS,
                    InputTextFieldRole::TextArea,
                ))
            },
            || {
                unicode_calls += 1;
                InputTextUnicodeRead::Text("never".to_string())
            },
            |_| {},
        );
        assert_eq!(
            decision,
            InputTextCaptureDecision::Gap(InputTextGapReason::Stale)
        );
        assert_eq!(safety_calls, 0);
        assert_eq!(unicode_calls, 0);
    }

    // Mandatory-excluded apps, MSIX dual-ID Bitwarden/Arc, and unlisted browsers block BEFORE unicode.
    let blocked_identities: &[(&str, Option<&str>)] = &[
        ("1password.exe", Some("1password.exe")),
        ("bitwarden.exe", Some("bitwarden.exe")),
        ("protonpass.exe", Some("protonpass.exe")),
        ("com.apple.safari", None),
        ("8bitsolutions.bitwarden", Some("bitwarden.exe")),
        ("thebrowsercompany.arc", Some("arc.exe")),
        ("chrome.exe", Some("chrome.exe")),
        ("msedge.exe", Some("msedge.exe")),
        ("firefox.exe", Some("firefox.exe")),
        ("applicationframehost.exe", Some("applicationframehost.exe")),
        ("notepad.exe", Some("applicationframehost.exe")),
    ];
    for &(app_id, exe) in blocked_identities {
        let mut unicode_calls = 0;
        let ctx = ctx_with_identity(app_id, exe);
        let decision = InputTextReadGate::capture(
            std_meta(42, BASE_NS, 1_000),
            &[],
            &policy,
            0,
            || BASE_NS,
            |_| Ok(approved(ctx.clone(), BASE_NS, InputTextFieldRole::TextField)),
            || {
                unicode_calls += 1;
                InputTextUnicodeRead::Text("secret".to_string())
            },
            |_| {},
        );
        assert_eq!(
            decision,
            InputTextCaptureDecision::Gap(InputTextGapReason::Stale),
            "app_id={app_id} exe={exe:?} must be blocked before unicode"
        );
        assert_eq!(unicode_calls, 0);
    }

    // PID mismatch, invalid context fields, cached/future metadata, and verification timeout block BEFORE unicode.
    let mut bad_pid = std_context();
    bad_pid.target.process_id = 99;
    let mut empty_win = std_context();
    empty_win.target.window_id = String::new();
    let mut zero_rev = std_context();
    zero_rev.policy_revision = 0;
    let mut sensitive = std_context();
    sensitive.secure_status = SecureStatus::Sensitive;
    let mut not_strict = std_context();
    not_strict.secure_status = SecureStatus::NotDeclaredSensitive;

    let bad_contexts = [
        (bad_pid, InputTextGapReason::TargetMismatch),
        (empty_win, InputTextGapReason::Stale),
        (zero_rev, InputTextGapReason::Stale),
        (sensitive, InputTextGapReason::Stale),
        (not_strict, InputTextGapReason::Stale),
    ];
    for (bad_ctx, expected) in bad_contexts {
        let mut unicode_calls = 0;
        let decision = InputTextReadGate::capture(
            std_meta(42, BASE_NS, 1_000),
            &[],
            &policy,
            0,
            || BASE_NS,
            |_| {
                Ok(approved(
                    bad_ctx.clone(),
                    BASE_NS,
                    InputTextFieldRole::TextField,
                ))
            },
            || {
                unicode_calls += 1;
                InputTextUnicodeRead::Text("never".to_string())
            },
            |_| {},
        );
        assert_eq!(decision, InputTextCaptureDecision::Gap(expected));
        assert_eq!(unicode_calls, 0);
    }

    // Cached or future safety approval timestamp cannot approve read.
    for bad_meta_ts in [BASE_NS - 1, BASE_NS + 1] {
        let mut unicode_calls = 0;
        let decision = InputTextReadGate::capture(
            std_meta(42, BASE_NS, 1_000),
            &[],
            &policy,
            0,
            || BASE_NS,
            |_| {
                Ok(approved(
                    std_context(),
                    bad_meta_ts,
                    InputTextFieldRole::TextField,
                ))
            },
            || {
                unicode_calls += 1;
                InputTextUnicodeRead::Text("never".to_string())
            },
            |_| {},
        );
        assert_eq!(
            decision,
            InputTextCaptureDecision::Gap(InputTextGapReason::Stale)
        );
        assert_eq!(unicode_calls, 0);
    }

    // Safety read taking > 200ms returns VerificationTimeout BEFORE unicode.
    let clock = RefCell::new(BASE_NS);
    let mut unicode_calls = 0;
    let timed_out = InputTextReadGate::capture(
        std_meta(42, BASE_NS, 1_000),
        &[],
        &policy,
        0,
        || *clock.borrow(),
        |_| {
            *clock.borrow_mut() += 200_000_001;
            let now = *clock.borrow();
            Ok(approved(std_context(), now, InputTextFieldRole::TextField))
        },
        || {
            unicode_calls += 1;
            InputTextUnicodeRead::Text("never".to_string())
        },
        |_| {},
    );
    assert_eq!(
        timed_out,
        InputTextCaptureDecision::Gap(InputTextGapReason::VerificationTimeout)
    );
    assert_eq!(unicode_calls, 0);
}

#[test]
fn input_text_post_gate_mismatch_discards_and_purges_accumulator() {
    let policy = default_input_policy();
    let original = std_context();

    // Strict ordering: pre-gate -> unicode -> post-gate.
    let order = RefCell::new(Vec::new());
    let mut calls = 0;
    let ok = InputTextReadGate::capture(
        std_meta(42, BASE_NS, 1_000),
        &[InputTextModifier::Shift],
        &policy,
        0,
        || BASE_NS,
        |_| {
            calls += 1;
            order
                .borrow_mut()
                .push(if calls == 1 { "before" } else { "after" });
            Ok(approved(
                original.clone(),
                BASE_NS,
                InputTextFieldRole::TextArea,
            ))
        },
        || {
            order.borrow_mut().push("unicode");
            InputTextUnicodeRead::Text("合成\u{1F9EA}".to_string())
        },
        |_| {},
    );
    assert_eq!(*order.borrow(), vec!["before", "unicode", "after"]);
    match ok {
        InputTextCaptureDecision::Sample(s) => {
            assert_eq!(s.context, original);
            assert_eq!(s.text, "合成\u{1F9EA}");
            assert_eq!(s.modifiers, vec![InputTextModifier::Shift]);
        }
        other => panic!("expected sample, got {other:?}"),
    }

    // Post-read context divergence matrix (TargetMismatch vs Stale).
    let mut cases = Vec::new();
    let mut c = original.clone();
    c.surface_id = "other-field".to_string();
    cases.push((c, InputTextGapReason::TargetMismatch));

    let mut c = original.clone();
    c.target.window_id = "hwnd-2".to_string();
    cases.push((c, InputTextGapReason::TargetMismatch));

    let mut c = original.clone();
    c.target.process_start_time = "birth-2".to_string();
    cases.push((c, InputTextGapReason::TargetMismatch));

    let mut c = original.clone();
    c.focus_generation = 2;
    cases.push((c, InputTextGapReason::TargetMismatch));

    let mut c = original.clone();
    c.foreground_generation = 2;
    cases.push((c, InputTextGapReason::Stale));

    let mut c = original.clone();
    c.capture_epoch = 2;
    cases.push((c, InputTextGapReason::Stale));

    let mut c = original.clone();
    c.target.window_id = "hwnd-2".to_string();
    c.capture_epoch = 2;
    cases.push((c, InputTextGapReason::Stale));

    let mut c = original.clone();
    c.policy_revision = 2;
    cases.push((c, InputTextGapReason::Stale));

    let mut c = original.clone();
    c.private_state = InputTextPrivateState::UserAuthorized;
    cases.push((c, InputTextGapReason::Stale));

    for (changed, expected) in cases {
        let mut safety_calls = 0;
        let decision = InputTextReadGate::capture(
            std_meta(42, BASE_NS, 1_000),
            &[],
            &policy,
            0,
            || BASE_NS,
            |_| {
                safety_calls += 1;
                let ctx = if safety_calls == 1 {
                    original.clone()
                } else {
                    changed.clone()
                };
                Ok(approved(ctx, BASE_NS, InputTextFieldRole::TextField))
            },
            || InputTextUnicodeRead::Text("discard".to_string()),
            |_| {},
        );
        assert_eq!(decision, InputTextCaptureDecision::Gap(expected));
        assert_eq!(safety_calls, 2);
    }

    // Role change between pre and post rejects with Stale and purges pending + completed.
    let mut acc = InputTextAccumulator::default();
    let mut completed = vec![seal_one(
        sample(original.clone(), InputTextKind::Text, "prior", vec![], 900),
        InputTextSource::Win32Unicode,
    )];
    assert_eq!(
        acc.add(
            sample(original.clone(), InputTextKind::Text, "buf", vec![], 1_000),
            InputTextSource::Win32Unicode
        ),
        None
    );
    let mut safety_calls = 0;
    let step = InputTextReadGate::capture_with_accumulator(
        std_meta(42, BASE_NS, 1_100),
        &[],
        InputTextSource::Win32Unicode,
        &policy,
        0,
        &mut acc,
        &mut completed,
        || BASE_NS,
        |_| {
            safety_calls += 1;
            let role = if safety_calls == 1 {
                InputTextFieldRole::TextField
            } else {
                InputTextFieldRole::TextArea
            };
            Ok(approved(original.clone(), BASE_NS, role))
        },
        || InputTextUnicodeRead::Text("discard".to_string()),
        |_| {},
    );
    assert_eq!(step, InputTextCaptureStep::Gap(InputTextGapReason::Stale));
    assert!(acc.pending().is_none());
    assert!(completed.is_empty());

    // Post-read event expiry returns VerificationTimeout.
    let clock = RefCell::new(BASE_NS);
    let expired = InputTextReadGate::capture(
        std_meta(42, BASE_NS, 1_000),
        &[],
        &policy,
        0,
        || *clock.borrow(),
        |_| {
            let now = *clock.borrow();
            Ok(approved(original.clone(), now, InputTextFieldRole::TextArea))
        },
        || {
            *clock.borrow_mut() += 200_000_001;
            InputTextUnicodeRead::Text("late".to_string())
        },
        |_| {},
    );
    assert_eq!(
        expired,
        InputTextCaptureDecision::Gap(InputTextGapReason::VerificationTimeout)
    );
}

#[test]
fn input_text_shortcuts_skip_unicode_and_return_fast_seals_with_control_filtering() {
    let policy = default_input_policy();
    let ctx = std_context();

    // Shortcuts never invoke read_unicode and canonicalize/deduplicate modifiers.
    for mods in [
        vec![InputTextModifier::Command],
        vec![InputTextModifier::Control],
        vec![
            InputTextModifier::Shift,
            InputTextModifier::Command,
            InputTextModifier::Command,
            InputTextModifier::Option,
            InputTextModifier::Control,
        ],
    ] {
        let mut unicode_calls = 0;
        let decision = InputTextReadGate::capture(
            std_meta(42, BASE_NS, 1_000),
            &mods,
            &policy,
            0,
            || BASE_NS,
            |_| Ok(approved(ctx.clone(), BASE_NS, InputTextFieldRole::TextField)),
            || {
                unicode_calls += 1;
                InputTextUnicodeRead::Text("never".to_string())
            },
            |_| {},
        );
        assert_eq!(unicode_calls, 0);
        match decision {
            InputTextCaptureDecision::Sample(s) => {
                assert_eq!(s.event_kind, InputTextKind::Shortcut);
                assert_eq!(s.text, "");
                assert_eq!(s.modifiers, InputTextLimits::canonical_modifiers(&mods));
            }
            other => panic!("expected shortcut sample, got {other:?}"),
        }
    }

    // Option-only and AltGr remain Text (not shortcut).
    let altgr_norm = WindowsModifierState {
        left_ctrl: true,
        right_alt: true,
        ..WindowsModifierState::default()
    }
    .normalize();
    for (mods, text) in [
        (vec![InputTextModifier::Option], "é"),
        (altgr_norm.modifiers, "€"),
    ] {
        let decision = InputTextReadGate::capture(
            std_meta(42, BASE_NS, 1_000),
            &mods,
            &policy,
            0,
            || BASE_NS,
            |_| Ok(approved(ctx.clone(), BASE_NS, InputTextFieldRole::TextArea)),
            || InputTextUnicodeRead::Text(text.to_string()),
            |_| {},
        );
        match decision {
            InputTextCaptureDecision::Sample(s) => {
                assert_eq!(s.event_kind, InputTextKind::Text);
                assert_eq!(s.text, text);
            }
            other => panic!("expected text sample, got {other:?}"),
        }
    }

    // Return (\r, \n, \u{3}) produces empty Return sample and seals immediately via ingest_into_completed.
    for ret_text in ["\r", "\n", "\u{0003}"] {
        let mut acc = InputTextAccumulator::default();
        let mut completed = Vec::new();
        assert_eq!(
            acc.ingest_into_completed(
                &mut completed,
                sample(ctx.clone(), InputTextKind::Text, "hello", vec![], 1_000),
                InputTextSource::Win32Unicode
            ),
            Ok(InputTextIngestOutcome::Buffered)
        );
        let step = InputTextReadGate::capture_with_accumulator(
            std_meta(42, BASE_NS, 1_050),
            &[],
            InputTextSource::Win32Unicode,
            &policy,
            0,
            &mut acc,
            &mut completed,
            || BASE_NS,
            |_| Ok(approved(ctx.clone(), BASE_NS, InputTextFieldRole::TextField)),
            || InputTextUnicodeRead::Text(ret_text.to_string()),
            |_| {},
        );
        assert_eq!(step, InputTextCaptureStep::SealedReturn);
        assert!(acc.pending().is_none());
        assert_eq!(completed.len(), 2);
        assert_eq!(completed[0].event_kind, InputTextKind::Text);
        assert_eq!(completed[0].text, "hello");
        assert_eq!(completed[1].event_kind, InputTextKind::Return);
        assert_eq!(completed[1].text, "");
        assert_eq!(completed[1].event_count, 1);
    }

    // Empty & C0/C1 control characters are ignored without emitting gaps.
    for ctrl in [
        "",
        "\t",
        "\u{0000}",
        "\u{001B}",
        "\u{007F}",
        "\u{0080}",
        "\u{0085}",
        "\u{009F}",
        "a\nb",
    ] {
        let decision = InputTextReadGate::capture(
            std_meta(42, BASE_NS, 1_000),
            &[],
            &policy,
            0,
            || BASE_NS,
            |_| Ok(approved(ctx.clone(), BASE_NS, InputTextFieldRole::TextArea)),
            || InputTextUnicodeRead::Text(ctrl.to_string()),
            |_| {},
        );
        assert_eq!(
            decision,
            InputTextCaptureDecision::Ignored,
            "control/empty {ctrl:?} must be ignored"
        );
    }
}

#[test]
fn input_text_vk_packet_surrogate_pair_assembly_ttl_and_orphan_drop() {
    let units: Vec<u16> = "\u{1F9EA}".encode_utf16().collect();
    assert_eq!(units.len(), 2);
    let (hi, lo) = (units[0], units[1]);

    let mut assembler = PendingSurrogate::new();
    assert!(!assembler.has_pending());

    // Normal pair within 50ms TTL (exact 50ms boundary succeeds).
    assert_eq!(assembler.push(hi, 1_000), SurrogateAssemblyOutcome::PendingHigh);
    assert!(assembler.has_pending());
    assert_eq!(
        assembler.push(lo, 1_050),
        SurrogateAssemblyOutcome::Text("\u{1F9EA}".to_string())
    );
    assert!(!assembler.has_pending());

    // Expired at 51ms drops orphan high surrogate and lone low surrogate.
    assert_eq!(assembler.push(hi, 2_000), SurrogateAssemblyOutcome::PendingHigh);
    assert_eq!(assembler.push(lo, 2_051), SurrogateAssemblyOutcome::DroppedOrphan);
    assert!(!assembler.has_pending());

    // Clock rollback expires pending high surrogate.
    assert_eq!(assembler.push(hi, 3_000), SurrogateAssemblyOutcome::PendingHigh);
    assert_eq!(assembler.push(lo, 2_999), SurrogateAssemblyOutcome::DroppedOrphan);

    // Lone low surrogate is dropped.
    assert_eq!(assembler.push(lo, 4_000), SurrogateAssemblyOutcome::DroppedOrphan);

    // Consecutive high surrogates replace the orphaned first high.
    let note: Vec<u16> = "\u{1D11E}".encode_utf16().collect();
    assert_eq!(assembler.push(hi, 5_000), SurrogateAssemblyOutcome::PendingHigh);
    assert_eq!(
        assembler.push(note[0], 5_010),
        SurrogateAssemblyOutcome::PendingHigh
    );
    assert_eq!(
        assembler.push(note[1], 5_020),
        SurrogateAssemblyOutcome::Text("\u{1D11E}".to_string())
    );

    // High followed by BMP drops orphaned high and emits BMP.
    assert_eq!(assembler.push(hi, 6_000), SurrogateAssemblyOutcome::PendingHigh);
    assert_eq!(
        assembler.push('A' as u16, 6_010),
        SurrogateAssemblyOutcome::Text("A".to_string())
    );
    assert!(!assembler.has_pending());

    // Explicit clear on boundary drops pending high surrogate.
    assert_eq!(assembler.push(hi, 7_000), SurrogateAssemblyOutcome::PendingHigh);
    assembler.clear();
    assert!(!assembler.has_pending());
    assert_eq!(assembler.push(lo, 7_005), SurrogateAssemblyOutcome::DroppedOrphan);
}

#[test]
fn input_text_accumulator_limits_overflow_and_context_boundaries() {
    let ctx = std_context();

    // Debounce aggregates with original interval bounds.
    let mut acc = InputTextAccumulator::default();
    assert_eq!(
        acc.add(
            sample(ctx.clone(), InputTextKind::Text, "合成", vec![], 1_000),
            InputTextSource::Win32Unicode
        ),
        None
    );
    assert_eq!(
        acc.add(
            sample(ctx.clone(), InputTextKind::Text, "\u{1F9EA}", vec![], 1_300),
            InputTextSource::Win32Unicode
        ),
        None
    );
    assert!(acc.take_due(1_799, Some(&ctx)).is_none());
    let rec = acc.take_due(1_800, Some(&ctx)).expect("debounced flush");
    assert_eq!(rec.text, "合成\u{1F9EA}");
    assert_eq!(rec.event_count, 2);
    assert_eq!(rec.interval_start_ms, 1_000);
    assert_eq!(rec.interval_end_ms, 1_300);
    assert!(acc.pending().is_none());

    // Max wait 2000ms flushes despite continuous typing.
    for t in (1_000..=2_900).step_by(100) {
        assert_eq!(
            acc.add(
                sample(ctx.clone(), InputTextKind::Text, "x", vec![], t as i64),
                InputTextSource::Win32Unicode
            ),
            None
        );
    }
    assert!(!acc.is_due(2_999));
    assert!(acc.is_due(3_000));
    let waited = acc.take_due(3_000, Some(&ctx)).expect("maxWait flush");
    assert_eq!(waited.event_count, 20);
    assert_eq!(waited.interval_end_ms, 2_900);

    // UTF-16 2048 limit (1024 supplementary scalars) & 256 event count limit drop whole buffer with Budget.
    let full_utf16 = "\u{1F9EA}".repeat(1_024);
    assert_eq!(utf16_len(&full_utf16), 2_048);
    assert_eq!(
        acc.add(
            sample(ctx.clone(), InputTextKind::Text, &full_utf16, vec![], 1_000),
            InputTextSource::Win32Unicode
        ),
        None
    );
    assert_eq!(
        acc.add(
            sample(ctx.clone(), InputTextKind::Text, "x", vec![], 1_050),
            InputTextSource::Win32Unicode
        ),
        Some(InputTextGapReason::Budget)
    );
    assert!(acc.pending().is_none());

    for _ in 0..256 {
        assert_eq!(
            acc.add(
                sample(ctx.clone(), InputTextKind::Text, "a", vec![], 1_000),
                InputTextSource::Win32Unicode
            ),
            None
        );
    }
    assert_eq!(acc.pending().map(|p| p.event_count), Some(256));
    assert_eq!(
        acc.add(
            sample(ctx.clone(), InputTextKind::Text, "a", vec![], 1_000),
            InputTextSource::Win32Unicode
        ),
        Some(InputTextGapReason::Budget)
    );
    assert!(acc.pending().is_none());

    // Stricter policy max_text_code_units rejects without truncating.
    let mut small_policy = default_input_policy();
    small_policy.max_text_code_units = 3;
    let over = InputTextReadGate::capture(
        std_meta(42, BASE_NS, 1_000),
        &[],
        &small_policy,
        0,
        || BASE_NS,
        |_| Ok(approved(ctx.clone(), BASE_NS, InputTextFieldRole::TextArea)),
        || InputTextUnicodeRead::Text("abcd".to_string()),
        |_| {},
    );
    assert_eq!(
        over,
        InputTextCaptureDecision::Gap(InputTextGapReason::Budget)
    );
    let mut small_acc = InputTextAccumulator::from_policy(&small_policy);
    assert_eq!(small_acc.max_code_units(), 3);
    assert_eq!(
        small_acc.add(
            sample(ctx.clone(), InputTextKind::Text, "abc", vec![], 1_000),
            InputTextSource::Win32Unicode
        ),
        None
    );
    assert_eq!(
        small_acc.add(
            sample(ctx.clone(), InputTextKind::Text, "d", vec![], 1_010),
            InputTextSource::Win32Unicode
        ),
        Some(InputTextGapReason::Budget)
    );
    assert!(small_acc.pending().is_none());

    // Unicode saturated -> Budget, unavailable -> ReadError.
    let sat = InputTextReadGate::capture(
        std_meta(42, BASE_NS, 1_000),
        &[],
        &default_input_policy(),
        0,
        || BASE_NS,
        |_| Ok(approved(ctx.clone(), BASE_NS, InputTextFieldRole::TextArea)),
        || InputTextUnicodeRead::Saturated,
        |_| {},
    );
    assert_eq!(
        sat,
        InputTextCaptureDecision::Gap(InputTextGapReason::Budget)
    );
    let unavail = InputTextReadGate::capture(
        std_meta(42, BASE_NS, 1_000),
        &[],
        &default_input_policy(),
        0,
        || BASE_NS,
        |_| Ok(approved(ctx.clone(), BASE_NS, InputTextFieldRole::TextArea)),
        || InputTextUnicodeRead::Unavailable,
        |_| {},
    );
    assert_eq!(
        unavail,
        InputTextCaptureDecision::Gap(InputTextGapReason::ReadError)
    );

    // Every context boundary discards pending without flushing.
    let mut boundaries = Vec::new();
    let mut c = ctx.clone();
    c.target.application_id = "other.exe".to_string();
    boundaries.push(c);
    let mut c = ctx.clone();
    c.target.process_id = 99;
    boundaries.push(c);
    let mut c = ctx.clone();
    c.target.window_id = "hwnd-2".to_string();
    boundaries.push(c);
    let mut c = ctx.clone();
    c.target.window_generation = 2;
    boundaries.push(c);
    let mut c = ctx.clone();
    c.surface_id = "field-2".to_string();
    boundaries.push(c);
    let mut c = ctx.clone();
    c.capture_epoch = 2;
    boundaries.push(c);
    let mut c = ctx.clone();
    c.policy_revision = 2;
    boundaries.push(c);
    let mut c = ctx.clone();
    c.foreground_generation = 2;
    boundaries.push(c);
    let mut c = ctx.clone();
    c.focus_generation = 2;
    boundaries.push(c);

    for changed in boundaries {
        let mut b = InputTextAccumulator::default();
        assert_eq!(
            b.add(
                sample(ctx.clone(), InputTextKind::Text, "old", vec![], 1_000),
                InputTextSource::Win32Unicode
            ),
            None
        );
        assert_eq!(
            b.add(
                sample(changed.clone(), InputTextKind::Text, "new", vec![], 1_050),
                InputTextSource::Win32Unicode
            ),
            Some(InputTextGapReason::Stale)
        );
        assert!(b.pending().is_none());
        assert!(b.take_due(1_600, Some(&changed)).is_none());
    }

    // Clock rollback & overdue > 5000ms fail closed.
    let mut b = InputTextAccumulator::default();
    assert_eq!(
        b.add(
            sample(ctx.clone(), InputTextKind::Text, "a", vec![], 1_000),
            InputTextSource::Win32Unicode
        ),
        None
    );
    assert_eq!(
        b.add(
            sample(ctx.clone(), InputTextKind::Text, "b", vec![], 999),
            InputTextSource::Win32Unicode
        ),
        Some(InputTextGapReason::Stale)
    );
    assert!(b.pending().is_none());
    assert_eq!(
        b.add(
            sample(ctx.clone(), InputTextKind::Text, "a", vec![], 1_000),
            InputTextSource::Win32Unicode
        ),
        None
    );
    assert!(b.take_due(6_001, Some(&ctx)).is_none());
    assert!(b.pending().is_none());
}

#[test]
fn input_text_drain_at_barrier_dedup_backpressure_and_text_budget() {
    let policy = default_input_policy();
    let ctx = std_context();

    // 1. Sub-debounce pending + completed sharing one context revalidates ONCE and preserves order.
    let mut acc = InputTextAccumulator::default();
    assert_eq!(
        acc.add(
            sample(ctx.clone(), InputTextKind::Text, "nashi ", vec![], 1_000),
            InputTextSource::Win32Unicode
        ),
        None
    );
    let mut completed = vec![seal_one(
        sample(ctx.clone(), InputTextKind::Text, "prior", vec![], 900),
        InputTextSource::Win32Unicode,
    )];
    let mut safety_calls = 0;
    let drained = InputTextReadGate::drain_at_barrier(
        &mut completed,
        &mut acc,
        1_250,
        &policy,
        8_192,
        || BASE_NS,
        |req| {
            safety_calls += 1;
            match req {
                InputTextSafetyRequest::Flush(expected) if *expected == ctx => {
                    Ok(approved(ctx.clone(), BASE_NS, InputTextFieldRole::TextArea))
                }
                _ => Err(InputTextGapReason::Stale),
            }
        },
        |_| {},
    )
    .expect("barrier drain succeeds");
    assert_eq!(safety_calls, 1);
    assert_eq!(
        drained.iter().map(|r| r.text.as_str()).collect::<Vec<_>>(),
        vec!["prior", "nashi "]
    );
    assert!(completed.is_empty());
    assert!(acc.pending().is_none());

    // 2. Backpressure (> MAX_PENDING = 4) fails closed and purges both completed and pending.
    let mut acc_bp = InputTextAccumulator::default();
    assert_eq!(
        acc_bp.add(
            sample(ctx.clone(), InputTextKind::Text, "5th", vec![], 1_400),
            InputTextSource::Win32Unicode
        ),
        None
    );
    let mut completed_bp: Vec<InputTextRecord> = (0..InputTextLimits::MAX_PENDING)
        .map(|idx| {
            seal_one(
                sample(
                    ctx.clone(),
                    InputTextKind::Text,
                    &format!("s{idx}"),
                    vec![],
                    900 + (idx as i64) * 10,
                ),
                InputTextSource::Win32Unicode,
            )
        })
        .collect();
    let bp = InputTextReadGate::drain_at_barrier(
        &mut completed_bp,
        &mut acc_bp,
        1_450,
        &policy,
        8_192,
        || BASE_NS,
        |_| Ok(approved(ctx.clone(), BASE_NS, InputTextFieldRole::TextArea)),
        |_| {},
    );
    assert_eq!(bp, Err(InputTextGapReason::Backpressure));
    assert!(completed_bp.is_empty());
    assert!(acc_bp.pending().is_none());

    // 3. Remaining read text budget is strictly enforced without partial truncation.
    let mut acc_budget = InputTextAccumulator::default();
    assert_eq!(
        acc_budget.add(
            sample(ctx.clone(), InputTextKind::Text, "world", vec![], 1_000),
            InputTextSource::Win32Unicode
        ),
        None
    );
    let mut completed_budget = vec![seal_one(
        sample(ctx.clone(), InputTextKind::Text, "hello", vec![], 900),
        InputTextSource::Win32Unicode,
    )];
    // Total UTF-16 is 10 ("hello" + "world"); remaining budget 9 must fail with Budget and purge.
    let over_budget = InputTextReadGate::drain_at_barrier(
        &mut completed_budget,
        &mut acc_budget,
        1_050,
        &policy,
        9,
        || BASE_NS,
        |_| Ok(approved(ctx.clone(), BASE_NS, InputTextFieldRole::TextArea)),
        |_| {},
    );
    assert_eq!(over_budget, Err(InputTextGapReason::Budget));
    assert!(completed_budget.is_empty());
    assert!(acc_budget.pending().is_none());

    // 4. Safety failure and clock backstep clear both buffers.
    let mut acc_fail = InputTextAccumulator::default();
    assert_eq!(
        acc_fail.add(
            sample(ctx.clone(), InputTextKind::Text, "abc", vec![], 1_000),
            InputTextSource::Win32Unicode
        ),
        None
    );
    let mut completed_fail = Vec::new();
    let mut calls = 0;
    let backstep = InputTextReadGate::drain_at_barrier(
        &mut completed_fail,
        &mut acc_fail,
        999,
        &policy,
        8_192,
        || BASE_NS,
        |_| {
            calls += 1;
            Ok(approved(ctx.clone(), BASE_NS, InputTextFieldRole::TextArea))
        },
        |_| {},
    );
    assert_eq!(backstep, Err(InputTextGapReason::Stale));
    assert_eq!(calls, 0);
    assert!(acc_fail.pending().is_none());

    // 5. Revalidation distinguishes fresh VerificationTimeout from cached Stale evidence.
    let reval_clock = RefCell::new(BASE_NS);
    let timed_reval = InputTextReadGate::revalidate_buffered_context(
        &ctx,
        &policy,
        || *reval_clock.borrow(),
        |_| {
            *reval_clock.borrow_mut() += 200_000_001;
            let now = *reval_clock.borrow();
            Ok(approved(ctx.clone(), now, InputTextFieldRole::TextField))
        },
        |_| {},
    );
    assert_eq!(timed_reval, Err(InputTextGapReason::VerificationTimeout));

    *reval_clock.borrow_mut() = BASE_NS;
    let cached_reval = InputTextReadGate::revalidate_buffered_context(
        &ctx,
        &policy,
        || *reval_clock.borrow(),
        |_| {
            *reval_clock.borrow_mut() += 200_000_001;
            Ok(approved(
                ctx.clone(),
                BASE_NS - 1,
                InputTextFieldRole::TextField,
            ))
        },
        |_| {},
    );
    assert_eq!(cached_reval, Err(InputTextGapReason::Stale));
}

#[test]
fn input_text_ime_composition_purge_return_suppression_and_gated_commit() {
    let validator = ContractValidator::new().expect("validator");
    let policy = default_input_policy();
    let ctx = std_context();
    let mut ime = ImeCompositionState::new();
    let mut acc = InputTextAccumulator::default();

    // Raw Latin prefix buffered within 500ms is purged on composition start.
    assert_eq!(
        acc.add(
            sample(ctx.clone(), InputTextKind::Text, "nihao", vec![], 1_000),
            InputTextSource::Win32Unicode
        ),
        None
    );
    assert!(ime.on_composition_start(1_500, &mut acc));
    assert!(acc.pending().is_none());
    assert!(ime.should_suppress_raw_key(1_500));
    assert!(ime.should_suppress_return(1_500));

    // Composition decays after 5000ms safety bound if Finalized never arrives.
    assert!(ime.is_composing(6_500));
    assert!(!ime.should_suppress_return(6_501));
    assert!(!ime.is_composing(6_501));

    // Older text (> 500ms ago) is NOT purged as a raw Latin IME prefix.
    assert_eq!(
        acc.add(
            sample(ctx.clone(), InputTextKind::Text, "prior", vec![], 1_000),
            InputTextSource::Win32Unicode
        ),
        None
    );
    assert!(!ime.on_composition_start(1_501, &mut acc));
    assert_eq!(acc.pending().map(|p| p.text.as_str()), Some("prior"));
    acc.clear();

    // Already-finalized IME commit in pending is NOT purged when the next word starts composing.
    assert_eq!(
        acc.add(
            InputTextSample::ime_commit(ctx.clone(), "你好".to_string(), 2_000),
            InputTextSource::Win32Unicode
        ),
        None
    );
    assert!(!ime.on_composition_start(2_100, &mut acc));
    assert_eq!(acc.pending().map(|p| p.text.as_str()), Some("你好"));
    acc.clear();

    // Pre-gate failure on on_composition_finalized NEVER invokes read_committed.
    let mut read_calls = 0;
    let blocked = ime.on_composition_finalized(
        std_meta(42, BASE_NS, 2_200),
        &policy,
        0,
        || BASE_NS,
        |_| Err(InputTextGapReason::FieldSecurityUnknown),
        || {
            read_calls += 1;
            InputTextUnicodeRead::Text("秘密".to_string())
        },
        |_| {},
    );
    assert_eq!(
        blocked,
        InputTextCaptureDecision::Gap(InputTextGapReason::FieldSecurityUnknown)
    );
    assert_eq!(read_calls, 0);
    assert!(!ime.is_composing(2_200));

    // Valid gated composition commit emits IME-attributed sample passing ContractValidator.
    ime.on_composition_start(2_300, &mut acc);
    let committed = ime.on_composition_finalized(
        std_meta(42, BASE_NS, 2_400),
        &policy,
        0,
        || BASE_NS,
        |_| Ok(approved(ctx.clone(), BASE_NS, InputTextFieldRole::TextArea)),
        || InputTextUnicodeRead::Text("你好世界".to_string()),
        |_| {},
    );
    assert!(!ime.is_composing(2_400));
    let ime_sample = match committed {
        InputTextCaptureDecision::Sample(s) => *s,
        other => panic!("expected IME sample, got {other:?}"),
    };
    assert_eq!(ime_sample.text, "你好世界");
    assert_eq!(ime_sample.event_kind, InputTextKind::Text);
    assert!(ime_sample
        .extra_coverage_reasons
        .iter()
        .any(|r| r == "ime-composition-commit"));

    let record = seal_one(ime_sample, InputTextSource::Win32Unicode);
    let payload = record.payload().expect("valid IME input.text payload");
    let reasons = payload
        .get("coverage")
        .and_then(|c| c.get("missingReasons"))
        .and_then(JsonValue::as_array)
        .expect("missingReasons");
    assert!(reasons
        .iter()
        .any(|v| v.as_str() == Some("input-events-partial")));
    assert!(reasons
        .iter()
        .any(|v| v.as_str() == Some("ime-composition-commit")));
    assert!(reasons
        .iter()
        .any(|v| v.as_str() == Some("non-atomic-field-gate")));
    assert!(reasons
        .iter()
        .any(|v| v.as_str() == Some("effect-unverified")));
    let envelope = wrap_observation(
        record.interval_end_ms,
        2_500,
        record.context.target.to_target_ref(),
        record.context.stamp(),
        payload,
    );
    validator
        .encode_frame(&envelope)
        .expect("IME input.text envelope must validate");

    // IME post-gate mismatch discards committed text; over-budget emits Budget; C0/C1 ignored.
    let mut post_calls = 0;
    let mut changed_ctx = ctx.clone();
    changed_ctx.surface_id = "other-surface".to_string();
    let ime_mismatch = ime.on_composition_finalized(
        std_meta(42, BASE_NS, 2_500),
        &policy,
        0,
        || BASE_NS,
        |_| {
            post_calls += 1;
            let c = if post_calls == 1 {
                ctx.clone()
            } else {
                changed_ctx.clone()
            };
            Ok(approved(c, BASE_NS, InputTextFieldRole::TextArea))
        },
        || InputTextUnicodeRead::Text("丢弃".to_string()),
        |_| {},
    );
    assert_eq!(
        ime_mismatch,
        InputTextCaptureDecision::Gap(InputTextGapReason::TargetMismatch)
    );

    let mut tiny_policy = policy.clone();
    tiny_policy.max_text_code_units = 2;
    let ime_over = ime.on_composition_finalized(
        std_meta(42, BASE_NS, 2_600),
        &tiny_policy,
        0,
        || BASE_NS,
        |_| Ok(approved(ctx.clone(), BASE_NS, InputTextFieldRole::TextArea)),
        || InputTextUnicodeRead::Text("三个字".to_string()),
        |_| {},
    );
    assert_eq!(
        ime_over,
        InputTextCaptureDecision::Gap(InputTextGapReason::Budget)
    );

    let ime_ctrl = ime.on_composition_finalized(
        std_meta(42, BASE_NS, 2_700),
        &policy,
        0,
        || BASE_NS,
        |_| Ok(approved(ctx.clone(), BASE_NS, InputTextFieldRole::TextArea)),
        || InputTextUnicodeRead::Text("\r\n".to_string()),
        |_| {},
    );
    assert_eq!(ime_ctrl, InputTextCaptureDecision::Ignored);
}

#[test]
fn input_text_all_nine_gaps_ipc_roundtrip_and_contract_validation() {
    let validator = ContractValidator::new().expect("validator");
    let expected_gaps = [
        (
            InputTextGapReason::Stale,
            "stale",
            "stale",
            GapDiagnosticCode::InputContextUnverified,
        ),
        (
            InputTextGapReason::TargetMismatch,
            "input-target-mismatch",
            "stale",
            GapDiagnosticCode::InputTargetMismatch,
        ),
        (
            InputTextGapReason::RoleNotEditable,
            "input-role-not-editable",
            "stale",
            GapDiagnosticCode::InputRoleNotEditable,
        ),
        (
            InputTextGapReason::VerificationTimeout,
            "input-verification-timeout",
            "stale",
            GapDiagnosticCode::InputVerificationTimeout,
        ),
        (
            InputTextGapReason::FieldSecurityUnknown,
            "input-field-security-unknown",
            "stale",
            GapDiagnosticCode::InputFieldSecurityUnknown,
        ),
        (
            InputTextGapReason::Budget,
            "budget",
            "budget",
            GapDiagnosticCode::InputTextBudget,
        ),
        (
            InputTextGapReason::Backpressure,
            "backpressure",
            "backpressure",
            GapDiagnosticCode::InputTextBackpressure,
        ),
        (
            InputTextGapReason::ReadError,
            "read-error",
            "read-error",
            GapDiagnosticCode::InputTextReadUnavailable,
        ),
        (
            InputTextGapReason::PolicyBoundary,
            "policy-boundary",
            "policy-boundary",
            GapDiagnosticCode::InputPolicyBoundary,
        ),
    ];
    assert_eq!(expected_gaps.len(), InputTextGapReason::ALL.len());
    let ctx = std_context();
    for (reason, raw, broad, code) in expected_gaps {
        assert_eq!(reason.as_str(), raw);
        assert_eq!(InputTextGapReason::parse(raw), Some(reason));
        assert_eq!(reason.gap_reason(), broad);
        assert_eq!(reason.diagnostic_code(), code);
        assert_eq!(reason.diagnostic().role, None);

        let gap_rec = InputTextGapRecord::with_provider(reason, Some("notepad.exe".to_string()));
        assert!(gap_rec.is_valid());
        let rt = InputTextGapRecord::from_json(&gap_rec.to_json()).expect("gap IPC round-trip");
        assert_eq!(rt, gap_rec);

        let env = wrap_observation(
            1_000,
            1_000,
            ctx.target.to_target_ref(),
            ctx.stamp(),
            gap_rec.payload(),
        );
        validator
            .encode_frame(&env)
            .expect("input gap envelope must validate");
    }
    assert_eq!(InputTextGapReason::parse("PRIVATE_INPUT"), None);

    // IPC round-trip preserves internal exe_name, rejects unknown enums, and NEVER leaks exeName on wire.
    let rec = seal_one(
        sample(
            ctx.clone(),
            InputTextKind::Text,
            "合成\u{1F9EA}",
            vec![InputTextModifier::Shift],
            1_000,
        ),
        InputTextSource::Win32Unicode,
    );
    let ipc_json = rec.to_json();
    let decoded = InputTextRecord::from_json(&ipc_json).expect("IPC round-trip");
    assert_eq!(decoded, rec);
    assert_eq!(decoded.context.exe_name.as_deref(), Some("notepad.exe"));

    let mut corrupted = ipc_json.clone();
    if let JsonValue::Object(ref mut map) = corrupted {
        map.insert(
            "source".to_string(),
            JsonValue::String("unknown.source".to_string()),
        );
    }
    assert!(InputTextRecord::from_json(&corrupted).is_none());

    let wire_payload = rec.payload().expect("valid input.text payload");
    let wire_str = String::from_utf8(wire_payload.canonical_bytes().unwrap()).unwrap();
    assert!(!wire_str.contains("exeName"));
    assert!(!wire_str.contains("timestampNs"));
    assert!(!wire_str.contains("vkCode"));

    // Validate all combinations of source, eventKind, fieldSecurity, and privateState.
    let mut denylist_browser_ctx = ctx_with_identity("msedge.exe", Some("msedge.exe"));
    denylist_browser_ctx.target.window_id = "hwnd-2".to_string();
    denylist_browser_ctx.surface_id = "field-2".to_string();
    denylist_browser_ctx.field_security_mode = "denylist".to_string();
    denylist_browser_ctx.secure_status = SecureStatus::NotDeclaredSensitive;
    denylist_browser_ctx.private_state = InputTextPrivateState::UserAuthorized;
    for source in [InputTextSource::Win32Unicode, InputTextSource::Fixture] {
        for s in [
            sample(ctx.clone(), InputTextKind::Text, "hello\u{1F9EA}", vec![], 1_000),
            sample(ctx.clone(), InputTextKind::Return, "", vec![], 1_100),
            sample(
                ctx.clone(),
                InputTextKind::Shortcut,
                "",
                vec![
                    InputTextModifier::Command,
                    InputTextModifier::Control,
                    InputTextModifier::Option,
                    InputTextModifier::Shift,
                ],
                1_200,
            ),
            sample(
                denylist_browser_ctx.clone(),
                InputTextKind::Text,
                "browser-ok",
                vec![],
                1_300,
            ),
        ] {
            let record = seal_one(s, source);
            let env = wrap_observation(
                record.interval_end_ms,
                1_500,
                record.context.target.to_target_ref(),
                record.context.stamp(),
                record.payload().expect("valid input.text payload"),
            );
            validator
                .encode_frame(&env)
                .expect("input.text wire envelope must validate");
        }
    }
}

// =============================================================================
// 3. menu.action Core: Path Limits, Resolver, Tracking, Dedup & Browser Gate
// =============================================================================

#[test]
fn menu_path_sanitization_and_surrogate_safe_bound_path() {
    // Collapses CR/LF/TAB, strips C0/C1 (including U+0085), trims JS whitespace & U+FEFF.
    assert_eq!(
        MenuPathLimits::sanitize_segment(" \u{FEFF}File\t\r\n "),
        Some("File".to_string())
    );
    assert_eq!(
        MenuPathLimits::sanitize_segment("\u{0000}Save\r\n\tAs\u{007F}\u{0085}\u{009F}\u{FEFF}"),
        Some("Save As".to_string())
    );
    assert_eq!(
        MenuPathLimits::sanitize_segment(" \u{00A0}\u{3000}\u{FEFF}\t\r\n "),
        None
    );
    assert_eq!(MenuPathLimits::sanitize_segment("\u{0000}\u{001F}"), None);

    // Exact 128 UTF-16 per segment and 512 total (4 * 64 supplementary scalars): NOT truncated.
    let pair = "\u{1D11E}";
    let exact128 = pair.repeat(64);
    assert_eq!(utf16_len(&exact128), 128);
    let exact_path = MenuPathLimits::bound_path(&[
        exact128.clone(),
        exact128.clone(),
        exact128.clone(),
        exact128.clone(),
    ])
    .expect("exact 512 total must fit");
    assert!(!exact_path.truncated);
    assert_eq!(exact_path.path.len(), 4);

    // 129 UTF-16 ("a" + 64 supplementary pairs) truncates to 127 without bisecting surrogate.
    let boundary129 = format!("a{exact128}");
    let clipped = MenuPathLimits::bound_path(&["File".to_string(), boundary129])
        .expect("surrogate-safe truncation");
    assert!(clipped.truncated);
    assert_eq!(utf16_len(&clipped.path[1]), 127);
    assert!(MenuPathLimits::is_valid_path(&clipped.path));

    // Suffix reservation: 6 * 120 = 720 > 512 keeps every segment non-empty within 512 total.
    let seg120 = pair.repeat(60);
    let six = MenuPathLimits::bound_path(&vec![seg120; 6]).expect("6-segment suffix reserve");
    assert!(six.truncated);
    assert_eq!(six.path.len(), 6);
    assert!(six.path.iter().map(|s| utf16_len(s)).sum::<usize>() <= 512);
    assert!(MenuPathLimits::is_valid_path(&six.path));

    // 8 segments with a supplementary scalar at the very end reserves >= 2 UTF-16 units for segment 8.
    let mut eight_in = vec!["x".repeat(128); 7];
    eight_in.push(pair.repeat(4));
    let eight = MenuPathLimits::bound_path(&eight_in).expect("8-segment suffix reserve");
    assert!(eight.truncated);
    assert_eq!(eight.path.len(), 8);
    assert!(utf16_len(&eight.path[7]) >= 2);
    assert!(eight.path.iter().map(|s| utf16_len(s)).sum::<usize>() <= 512);
    assert!(MenuPathLimits::is_valid_path(&eight.path));

    // Segment count outside 2..=8 rejected.
    assert!(MenuPathLimits::bound_path(&["OnlyOne".to_string()]).is_none());
    assert!(MenuPathLimits::bound_path(&vec!["S".to_string(); 9]).is_none());
}

#[derive(Clone)]
struct SyntheticMenuNode {
    meta: MenuNodeSnapshot,
    parent: Option<usize>,
}

struct SyntheticMenuTree {
    nodes: Vec<SyntheticMenuNode>,
}

impl SyntheticMenuTree {
    fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    fn add(&mut self, meta: MenuNodeSnapshot, parent: Option<usize>) -> usize {
        let id = self.nodes.len();
        self.nodes.push(SyntheticMenuNode { meta, parent });
        id
    }

    fn set_parent(&mut self, id: usize, parent: Option<usize>) {
        self.nodes[id].parent = parent;
    }

    fn resolve(
        &self,
        leaf: usize,
        expected_pid: u32,
        raw_host_pid: Option<u32>,
        app_menu_bar: Option<usize>,
        excluded_bar_item: Option<usize>,
        win32_link: Option<&Win32MenuBarLink>,
    ) -> Option<ResolvedMenuPath> {
        MenuPathResolver::resolve(
            leaf,
            expected_pid,
            raw_host_pid,
            app_menu_bar.as_ref(),
            excluded_bar_item.as_ref(),
            win32_link,
            |a, b| a == b,
            |&id, is_leaf| {
                let mut m = self.nodes[id].meta.clone();
                if !is_leaf {
                    m.child_count = None;
                }
                Some(m)
            },
            |&id| self.nodes[id].parent,
            || true,
        )
    }
}

fn snap(
    pid: u32,
    control_type: Option<i32>,
    role: Option<&str>,
    title: Option<&str>,
) -> MenuNodeSnapshot {
    MenuNodeSnapshot {
        pid,
        control_type,
        role: role.map(str::to_string),
        subrole: SubroleRead::NoValue,
        protected_content: ProtectedContentRead::Value(false),
        enabled: Some(true),
        title: title.map(str::to_string),
        description: None,
        automation_id: None,
        class_name: None,
        child_count: Some(0),
        is_submenu_opener: Some(false),
    }
}

#[test]
fn menu_path_resolver_top_bar_win32_popup_and_security_rejections() {
    let mut tree = SyntheticMenuTree::new();
    let bar = tree.add(
        snap(42, Some(UIA_MENU_BAR_CONTROL_TYPE), Some("AXMenuBar"), None),
        None,
    );
    let file_item = tree.add(
        snap(
            42,
            Some(UIA_MENU_ITEM_CONTROL_TYPE),
            Some("AXMenuItem"),
            Some("File"),
        ),
        Some(bar),
    );
    let file_menu = tree.add(
        snap(42, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), None),
        Some(file_item),
    );
    let save = tree.add(
        snap(
            42,
            Some(UIA_MENU_ITEM_CONTROL_TYPE),
            Some("AXMenuItem"),
            Some("Save"),
        ),
        Some(file_menu),
    );

    // 2-level Windows UIA path (top-level MenuItem under MenuBar).
    assert_eq!(
        tree.resolve(save, 42, None, Some(bar), None, None),
        Some(ResolvedMenuPath {
            path: vec!["File".to_string(), "Save".to_string()],
            truncated: false,
        })
    );

    // 3-level submenu path.
    let mut export_meta = snap(
        42,
        Some(UIA_MENU_ITEM_CONTROL_TYPE),
        Some("AXMenuItem"),
        Some("Export"),
    );
    export_meta.child_count = Some(1);
    let export_item = tree.add(export_meta, Some(file_menu));
    let export_menu = tree.add(
        snap(42, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), None),
        Some(export_item),
    );
    let pdf = tree.add(
        snap(
            42,
            Some(UIA_MENU_ITEM_CONTROL_TYPE),
            Some("AXMenuItem"),
            Some("PDF..."),
        ),
        Some(export_menu),
    );
    assert_eq!(
        tree.resolve(pdf, 42, None, Some(bar), None, None),
        Some(ResolvedMenuPath {
            path: vec![
                "File".to_string(),
                "Export".to_string(),
                "PDF...".to_string()
            ],
            truncated: false,
        })
    );

    // Submenu openers (child_count > 0, child_count == None, or lazy is_submenu_opener == Some(true)) rejected.
    assert!(tree.resolve(export_item, 42, None, Some(bar), None, None).is_none());
    let mut lazy_meta = snap(
        42,
        Some(UIA_MENU_ITEM_CONTROL_TYPE),
        Some("AXMenuItem"),
        Some("Recent"),
    );
    lazy_meta.is_submenu_opener = Some(true);
    let lazy_opener = tree.add(lazy_meta, Some(file_menu));
    assert!(tree.resolve(lazy_opener, 42, None, Some(bar), None, None).is_none());

    // Disabled leaf rejected; absent enabled (None) allowed.
    let mut disabled_meta = snap(
        42,
        Some(UIA_MENU_ITEM_CONTROL_TYPE),
        Some("AXMenuItem"),
        Some("Disabled"),
    );
    disabled_meta.enabled = Some(false);
    let disabled_leaf = tree.add(disabled_meta, Some(file_menu));
    assert!(tree.resolve(disabled_leaf, 42, None, Some(bar), None, None).is_none());

    let mut nil_enabled = snap(
        42,
        Some(UIA_MENU_ITEM_CONTROL_TYPE),
        Some("AXMenuItem"),
        Some("NilEnabled"),
    );
    nil_enabled.enabled = None;
    let nil_enabled_leaf = tree.add(nil_enabled, Some(file_menu));
    assert_eq!(
        tree.resolve(nil_enabled_leaf, 42, None, Some(bar), None, None)
            .map(|r| r.path),
        Some(vec!["File".to_string(), "NilEnabled".to_string()])
    );

    // Leaf directly under MenuBar (1 segment, no bar-item ancestor) rejected.
    let direct_leaf = tree.add(
        snap(
            42,
            Some(UIA_MENU_ITEM_CONTROL_TYPE),
            Some("AXMenuItem"),
            Some("Direct"),
        ),
        Some(bar),
    );
    assert!(tree.resolve(direct_leaf, 42, None, Some(bar), None, None).is_none());

    // SystemMenuBar rejected even without app_menu_bar pointer.
    let mut sys_bar_meta = snap(42, Some(UIA_MENU_BAR_CONTROL_TYPE), Some("AXMenuBar"), Some("System"));
    sys_bar_meta.automation_id = Some("SystemMenuBar".to_string());
    let sys_bar = tree.add(sys_bar_meta, None);
    let sys_item = tree.add(
        snap(42, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("System")),
        Some(sys_bar),
    );
    let sys_menu = tree.add(
        snap(42, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), None),
        Some(sys_item),
    );
    let sys_close = tree.add(
        snap(42, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Close")),
        Some(sys_menu),
    );
    assert!(tree.resolve(sys_close, 42, None, None, None, None).is_none());

    // Exact 20-hop limit (`MAX_PARENT_HOPS`) accepted; 21 hops rejected.
    let mut wrappers = vec![file_menu];
    for _ in 0..19 {
        let next = tree.add(
            snap(42, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), None),
            Some(*wrappers.last().unwrap()),
        );
        wrappers.push(next);
    }
    let exact20 = tree.add(
        snap(42, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Exact20")),
        Some(wrappers[17]),
    );
    let over21 = tree.add(
        snap(42, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Over21")),
        Some(wrappers[18]),
    );
    assert_eq!(
        tree.resolve(exact20, 42, None, Some(bar), None, None)
            .map(|r| r.path),
        Some(vec!["File".to_string(), "Exact20".to_string()])
    );
    assert!(tree.resolve(over21, 42, None, Some(bar), None, None).is_none());

    // Classic Win32 #32768 popup under Window: accepted ONLY with from_menu_bar_start == true.
    let win = tree.add(
        snap(42, Some(UIA_WINDOW_CONTROL_TYPE), Some("AXWindow"), Some("Notepad")),
        None,
    );
    let mut popup_meta = snap(42, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), None);
    popup_meta.class_name = Some("#32768".to_string());
    let popup_menu = tree.add(popup_meta, Some(win));
    let popup_leaf = tree.add(
        snap(42, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("PDF")),
        Some(popup_menu),
    );
    // Right-click context menu (no link or from_menu_bar_start == false) MUST be rejected.
    assert!(tree.resolve(popup_leaf, 42, None, None, None, None).is_none());
    let ctx_link = Win32MenuBarLink {
        menu_bar_item_title: "File".to_string(),
        submenu_titles: vec![],
        from_menu_bar_start: false,
    };
    assert!(tree
        .resolve(popup_leaf, 42, None, None, None, Some(&ctx_link))
        .is_none());
    // Valid EVENT_SYSTEM_MENUSTART(OBJID_MENU) link resolves cleanly with sibling submenu titles.
    let valid_link = Win32MenuBarLink {
        menu_bar_item_title: " File ".to_string(),
        submenu_titles: vec!["Export".to_string()],
        from_menu_bar_start: true,
    };
    assert_eq!(
        tree.resolve(popup_leaf, 42, None, None, None, Some(&valid_link)),
        Some(ResolvedMenuPath {
            path: vec!["File".to_string(), "Export".to_string(), "PDF".to_string()],
            truncated: false,
        })
    );
    // Non-#32768 detached popup menu under Window (e.g. WinUI 3 MenuFlyoutPresenter): rejected
    // WITHOUT a verified top-menu-bar link (right-click context menu!), accepted WITH verified link.
    let non_win32_ctx = tree.add(
        snap(42, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), None),
        Some(win),
    );
    let non_win32_leaf = tree.add(
        snap(42, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Copy")),
        Some(non_win32_ctx),
    );
    assert!(tree.resolve(non_win32_leaf, 42, None, None, None, None).is_none());
    assert!(tree
        .resolve(non_win32_leaf, 42, None, None, None, Some(&ctx_link))
        .is_none());
    let top_file_link = Win32MenuBarLink {
        menu_bar_item_title: "File".to_string(),
        submenu_titles: vec![],
        from_menu_bar_start: true,
    };
    assert_eq!(
        tree.resolve(non_win32_leaf, 42, None, None, None, Some(&top_file_link)),
        Some(ResolvedMenuPath {
            path: vec!["File".to_string(), "Copy".to_string()],
            truncated: false,
        })
    );

    // Cross-PID hop rejected (unless explicit UWP raw_host_pid matches).
    let foreign_menu = tree.add(
        snap(99, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), None),
        Some(file_item),
    );
    let foreign_leaf = tree.add(
        snap(42, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Save")),
        Some(foreign_menu),
    );
    assert!(tree.resolve(foreign_leaf, 42, None, Some(bar), None, None).is_none());
    assert!(tree
        .resolve(foreign_leaf, 42, Some(99), Some(bar), None, None)
        .is_some());

    // Cycle rejected.
    let cyc_a = tree.add(snap(42, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), None), None);
    let cyc_b = tree.add(
        snap(42, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), None),
        Some(cyc_a),
    );
    tree.set_parent(cyc_a, Some(cyc_b));
    let cyc_leaf = tree.add(
        snap(42, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Loop")),
        Some(cyc_b),
    );
    assert!(tree.resolve(cyc_leaf, 42, None, Some(bar), None, None).is_none());

    // Sensitive / protected / failed-security leaf & ancestor nodes rejected.
    let mut prot_leaf = snap(42, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Key"));
    prot_leaf.protected_content = ProtectedContentRead::Value(true);
    let prot_id = tree.add(prot_leaf, Some(file_menu));
    assert!(tree.resolve(prot_id, 42, None, Some(bar), None, None).is_none());

    let mut fail_prot = snap(42, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Key"));
    fail_prot.protected_content = ProtectedContentRead::Failure;
    let fail_prot_id = tree.add(fail_prot, Some(file_menu));
    assert!(tree.resolve(fail_prot_id, 42, None, Some(bar), None, None).is_none());

    let mut sec_sub = snap(42, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Key"));
    sec_sub.subrole = SubroleRead::Value("AXPasswordItem".to_string());
    let sec_sub_id = tree.add(sec_sub, Some(file_menu));
    assert!(tree.resolve(sec_sub_id, 42, None, Some(bar), None, None).is_none());

    let mut prot_menu = snap(42, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), None);
    prot_menu.protected_content = ProtectedContentRead::Value(true);
    let prot_menu_id = tree.add(prot_menu, Some(file_item));
    let under_prot = tree.add(
        snap(42, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Open")),
        Some(prot_menu_id),
    );
    assert!(tree.resolve(under_prot, 42, None, Some(bar), None, None).is_none());

    // Blank title falls back to description; both blank rejected.
    let mut desc_meta = snap(
        42,
        Some(UIA_MENU_ITEM_CONTROL_TYPE),
        Some("AXMenuItem"),
        Some(" \u{00A0}\u{3000}\u{FEFF} "),
    );
    desc_meta.description = Some("Print...".to_string());
    let desc_leaf = tree.add(desc_meta, Some(file_menu));
    assert_eq!(
        tree.resolve(desc_leaf, 42, None, Some(bar), None, None)
            .map(|r| r.path),
        Some(vec!["File".to_string(), "Print...".to_string()])
    );

    // Opened menu classification distinguishes TopLevel, Submenu, Win32 popup, and rejects SystemMenuBar/context.
    let classify = |menu: usize, open: &[usize], link: Option<&Win32MenuBarLink>| {
        MenuPathResolver::classify_opened_menu(
            menu,
            42,
            None,
            Some(&bar),
            None,
            link,
            open,
            |a, b| a == b,
            |&id| Some(tree.nodes[id].meta.clone()),
            |&id| tree.nodes[id].parent,
            || true,
        )
    };
    assert_eq!(classify(file_menu, &[], None), Some(OpenedMenuKind::TopLevel));
    assert_eq!(
        classify(export_menu, &[file_menu], None),
        Some(OpenedMenuKind::Submenu)
    );
    assert_eq!(classify(export_menu, &[], None), Some(OpenedMenuKind::Submenu));
    assert_eq!(classify(sys_menu, &[], None), None);
    assert_eq!(classify(non_win32_ctx, &[], None), None);
    assert_eq!(classify(popup_menu, &[], None), None);
    assert_eq!(
        classify(popup_menu, &[], Some(&valid_link)),
        Some(OpenedMenuKind::TopLevel)
    );
    assert_eq!(
        classify(popup_menu, &[file_menu], Some(&valid_link)),
        Some(OpenedMenuKind::Submenu)
    );

    // Excluded bar item (e.g. Apple/System item) and submenus under it are rejected.
    let apple = tree.add(
        snap(42, None, Some("AXMenuBarItem"), Some("Apple")),
        Some(bar),
    );
    let apple_menu = tree.add(snap(42, None, Some("AXMenu"), None), Some(apple));
    let log_out = tree.add(
        snap(42, None, Some("AXMenuItem"), Some("Log Out")),
        Some(apple_menu),
    );
    assert!(tree
        .resolve(log_out, 42, None, Some(bar), Some(apple), None)
        .is_none());

    // 8-segment direct chain succeeds; 9 segments rejected.
    let mut chain = vec![file_item];
    for level in 2..=8 {
        let mut m = snap(
            42,
            Some(UIA_MENU_ITEM_CONTROL_TYPE),
            Some("AXMenuItem"),
            Some(&format!("L{level}")),
        );
        m.child_count = Some(if level == 8 { 0 } else { 1 });
        let id = tree.add(m, Some(*chain.last().unwrap()));
        chain.push(id);
    }
    assert_eq!(
        tree.resolve(*chain.last().unwrap(), 42, None, Some(bar), None, None)
            .map(|r| r.path),
        Some(vec![
            "File".to_string(),
            "L2".to_string(),
            "L3".to_string(),
            "L4".to_string(),
            "L5".to_string(),
            "L6".to_string(),
            "L7".to_string(),
            "L8".to_string(),
        ])
    );
    let seg9 = tree.add(
        snap(
            42,
            Some(UIA_MENU_ITEM_CONTROL_TYPE),
            Some("AXMenuItem"),
            Some("L9"),
        ),
        Some(*chain.last().unwrap()),
    );
    assert!(tree.resolve(seg9, 42, None, Some(bar), None, None).is_none());

    // Desktop-hosted Win32 #32768 popup (parent == None) succeeds ONLY with valid Win32MenuBarLink.
    let mut desktop_popup_meta = snap(42, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), None);
    desktop_popup_meta.class_name = Some("#32768".to_string());
    let desktop_popup = tree.add(desktop_popup_meta, None);
    let desktop_leaf = tree.add(
        snap(
            42,
            Some(UIA_MENU_ITEM_CONTROL_TYPE),
            Some("AXMenuItem"),
            Some("Exit"),
        ),
        Some(desktop_popup),
    );
    assert!(tree.resolve(desktop_leaf, 42, None, None, None, None).is_none());
    let top_only_link = Win32MenuBarLink {
        menu_bar_item_title: "File".to_string(),
        submenu_titles: vec![],
        from_menu_bar_start: true,
    };
    assert_eq!(
        tree.resolve(desktop_leaf, 42, None, None, None, Some(&top_only_link))
            .map(|r| r.path),
        Some(vec!["File".to_string(), "Exit".to_string()])
    );

    // Cancellation (should_continue returning false mid-walk) aborts immediately.
    let mut cont_calls = 0;
    let cancelled = MenuPathResolver::resolve(
        save,
        42,
        None,
        Some(&bar),
        None,
        None,
        |a, b| a == b,
        |&id, _| Some(tree.nodes[id].meta.clone()),
        |&id| tree.nodes[id].parent,
        || {
            cont_calls += 1;
            cont_calls <= 2
        },
    );
    assert!(cancelled.is_none());
}

#[test]
fn menu_path_resolver_winui3_notepad_and_electron_nested_dom_while_rejecting_context_menus() {
    let mut tree = SyntheticMenuTree::new();

    // 1. WinUI 3 Notepad detached popup `MenuFlyoutPresenter`:
    //    `MenuItem("Save") -> Menu(MenuFlyoutPresenter) -> Popup(Group) -> DesktopWindowXamlSource(Pane) -> Window`
    let notepad_win = tree.add(
        snap(77, Some(UIA_WINDOW_CONTROL_TYPE), Some("AXWindow"), Some("Untitled - Notepad")),
        None,
    );
    let xaml_source = tree.add(
        snap(77, Some(UIA_PANE_CONTROL_TYPE), Some("AXGroup"), Some("DesktopWindowXamlSource")),
        Some(notepad_win),
    );
    let popup_group = tree.add(
        snap(77, Some(UIA_GROUP_CONTROL_TYPE), Some("AXGroup"), Some("Popup")),
        Some(xaml_source),
    );
    let mut flyout_meta = snap(77, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), None);
    flyout_meta.class_name = Some("MenuFlyoutPresenter".to_string());
    let flyout_menu = tree.add(flyout_meta, Some(popup_group));
    let notepad_save = tree.add(
        snap(77, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Save")),
        Some(flyout_menu),
    );

    let verified_file_link = Win32MenuBarLink {
        menu_bar_item_title: "File".to_string(),
        submenu_titles: vec![],
        from_menu_bar_start: true,
    };
    let unverified_link = Win32MenuBarLink {
        menu_bar_item_title: "File".to_string(),
        submenu_titles: vec![],
        from_menu_bar_start: false,
    };

    // WITH verified MenuBar link -> resolves `["File", "Save"]`.
    assert_eq!(
        tree.resolve(notepad_save, 77, None, None, None, Some(&verified_file_link)),
        Some(ResolvedMenuPath {
            path: vec!["File".to_string(), "Save".to_string()],
            truncated: false,
        })
    );
    // WITHOUT verified MenuBar link (right-click context menu!) -> strictly returns `None`.
    assert_eq!(tree.resolve(notepad_save, 77, None, None, None, None), None);
    assert_eq!(
        tree.resolve(notepad_save, 77, None, None, None, Some(&unverified_link)),
        None
    );

    // WinUI 3 Notepad detached popup hosted under Desktop root (`Xaml_WindowedPopupClass` -> None):
    let mut desktop_flyout = snap(77, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), None);
    desktop_flyout.class_name = Some("MenuFlyoutPresenter".to_string());
    let desktop_popup_group = tree.add(
        snap(77, Some(UIA_GROUP_CONTROL_TYPE), Some("AXGroup"), Some("Popup")),
        None,
    );
    let desktop_flyout_menu = tree.add(desktop_flyout, Some(desktop_popup_group));
    let desktop_save = tree.add(
        snap(77, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Save As")),
        Some(desktop_flyout_menu),
    );
    assert_eq!(
        tree.resolve(desktop_save, 77, None, None, None, Some(&verified_file_link)),
        Some(ResolvedMenuPath {
            path: vec!["File".to_string(), "Save As".to_string()],
            truncated: false,
        })
    );
    assert_eq!(tree.resolve(desktop_save, 77, None, None, None, None), None);

    // WinUI 3 nested submenu inside popup (`View -> Zoom -> Zoom In`): deduplicates submenu segment
    // whether `submenu_titles` is empty OR already holds `"Zoom"`.
    let zoom_opener = tree.add(
        snap(77, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Zoom")),
        Some(flyout_menu),
    );
    let zoom_menu = tree.add(
        snap(77, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), None),
        Some(zoom_opener),
    );
    let zoom_in = tree.add(
        snap(77, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Zoom In")),
        Some(zoom_menu),
    );
    let view_link_empty_sub = Win32MenuBarLink {
        menu_bar_item_title: "View".to_string(),
        submenu_titles: vec![],
        from_menu_bar_start: true,
    };
    let view_link_with_sub = Win32MenuBarLink {
        menu_bar_item_title: "View".to_string(),
        submenu_titles: vec!["Zoom".to_string()],
        from_menu_bar_start: true,
    };
    assert_eq!(
        tree.resolve(zoom_in, 77, None, None, None, Some(&view_link_empty_sub))
            .map(|r| r.path),
        Some(vec!["View".to_string(), "Zoom".to_string(), "Zoom In".to_string()])
    );
    assert_eq!(
        tree.resolve(zoom_in, 77, None, None, None, Some(&view_link_with_sub))
            .map(|r| r.path),
        Some(vec!["View".to_string(), "Zoom".to_string(), "Zoom In".to_string()])
    );

    // Partial tail/head submenu overlap (`walked ["Format", "Export"]` + `link ["Export"]` ->
    // `["File", "Export", "Format", "PDF"]`, never duplicating `"Export"`).
    let export_item = tree.add(
        snap(77, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Export")),
        Some(flyout_menu),
    );
    let export_menu = tree.add(
        snap(77, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), None),
        Some(export_item),
    );
    let format_item = tree.add(
        snap(77, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Format")),
        Some(export_menu),
    );
    let format_menu = tree.add(
        snap(77, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), None),
        Some(format_item),
    );
    let format_pdf = tree.add(
        snap(77, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("PDF")),
        Some(format_menu),
    );
    let file_export_link = Win32MenuBarLink {
        menu_bar_item_title: "File".to_string(),
        submenu_titles: vec!["Export".to_string()],
        from_menu_bar_start: true,
    };
    assert_eq!(
        tree.resolve(format_pdf, 77, None, None, None, Some(&file_export_link))
            .map(|r| r.path),
        Some(vec![
            "File".to_string(),
            "Export".to_string(),
            "Format".to_string(),
            "PDF".to_string(),
        ])
    );

    // Classify opened WinUI 3 flyout: TopLevel ONLY with verified link; None without link.
    fn classify_tree(
        tree: &SyntheticMenuTree,
        menu: usize,
        open: &[usize],
        link: Option<&Win32MenuBarLink>,
    ) -> Option<OpenedMenuKind> {
        MenuPathResolver::classify_opened_menu(
            menu,
            77,
            None,
            None,
            None,
            link,
            open,
            |a, b| a == b,
            |&id| Some(tree.nodes[id].meta.clone()),
            |&id| tree.nodes[id].parent,
            || true,
        )
    }
    assert_eq!(
        classify_tree(&tree, flyout_menu, &[], Some(&verified_file_link)),
        Some(OpenedMenuKind::TopLevel)
    );
    assert_eq!(classify_tree(&tree, flyout_menu, &[], None), None);
    assert_eq!(
        classify_tree(&tree, flyout_menu, &[], Some(&unverified_link)),
        None
    );

    // 2. Electron / VS Code / Antigravity IDE nested DOM `MenuBar`:
    //    (a) `MenuItem("New Text File") -> Menu("File") -> Group -> Group -> MenuBar("Application")`
    let electron_win = tree.add(
        snap(77, Some(UIA_WINDOW_CONTROL_TYPE), Some("AXWindow"), Some("Antigravity")),
        None,
    );
    let electron_doc = tree.add(
        snap(77, Some(UIA_DOCUMENT_CONTROL_TYPE), Some("AXWebArea"), Some("Antigravity")),
        Some(electron_win),
    );
    let electron_bar = tree.add(
        snap(77, Some(UIA_MENU_BAR_CONTROL_TYPE), Some("AXMenuBar"), Some("Application")),
        Some(electron_doc),
    );
    let dom_group_outer = tree.add(
        snap(77, Some(UIA_GROUP_CONTROL_TYPE), Some("AXGroup"), None),
        Some(electron_bar),
    );
    let dom_group_inner = tree.add(
        snap(77, Some(UIA_GROUP_CONTROL_TYPE), Some("AXGroup"), None),
        Some(dom_group_outer),
    );
    let electron_file_menu = tree.add(
        snap(77, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), Some("File")),
        Some(dom_group_inner),
    );
    let new_text_file = tree.add(
        snap(77, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("New Text File")),
        Some(electron_file_menu),
    );
    assert_eq!(
        tree.resolve(new_text_file, 77, None, None, None, None),
        Some(ResolvedMenuPath {
            path: vec!["File".to_string(), "New Text File".to_string()],
            truncated: false,
        })
    );
    assert_eq!(
        classify_tree(&tree, electron_file_menu, &[], None),
        Some(OpenedMenuKind::TopLevel)
    );

    //    (b) Electron with intermediate `MenuItem("File")` between `Group` and `MenuBar`:
    let electron_file_btn = tree.add(
        snap(77, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("File")),
        Some(electron_bar),
    );
    let btn_grp1 = tree.add(
        snap(77, Some(UIA_GROUP_CONTROL_TYPE), Some("AXGroup"), None),
        Some(electron_file_btn),
    );
    let btn_grp2 = tree.add(
        snap(77, Some(UIA_GROUP_CONTROL_TYPE), Some("AXGroup"), None),
        Some(btn_grp1),
    );
    let btn_file_menu = tree.add(
        snap(77, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), Some("File")),
        Some(btn_grp2),
    );
    let section_group = tree.add(
        snap(77, Some(UIA_GROUP_CONTROL_TYPE), Some("AXGroup"), None),
        Some(btn_file_menu),
    );
    let open_folder = tree.add(
        snap(77, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Open Folder...")),
        Some(section_group),
    );
    assert_eq!(
        tree.resolve(open_folder, 77, None, None, None, None),
        Some(ResolvedMenuPath {
            path: vec!["File".to_string(), "Open Folder...".to_string()],
            truncated: false,
        })
    );

    //    (c) Electron right-click context menu (`MenuItem -> Menu -> Group -> Document -> Window`):
    //        STRICTLY returns `None` even if a verified `Win32MenuBarLink` were active!
    let ctx_group = tree.add(
        snap(77, Some(UIA_GROUP_CONTROL_TYPE), Some("AXGroup"), None),
        Some(electron_doc),
    );
    let ctx_menu = tree.add(
        snap(77, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), Some("Context")),
        Some(ctx_group),
    );
    let ctx_copy = tree.add(
        snap(77, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Copy")),
        Some(ctx_menu),
    );
    assert_eq!(tree.resolve(ctx_copy, 77, None, None, None, None), None);
    assert_eq!(
        tree.resolve(ctx_copy, 77, None, None, None, Some(&verified_file_link)),
        None,
        "Electron right-click context menu under Document/AXWebArea MUST NEVER resolve"
    );
    assert_eq!(
        classify_tree(&tree, ctx_menu, &[], Some(&verified_file_link)),
        None
    );

    //    (d) Context menu under `AXDocument` or `Edit` also strictly returns `None`.
    let ax_doc = tree.add(
        snap(77, Some(UIA_DOCUMENT_CONTROL_TYPE), Some("AXDocument"), Some("Editor")),
        Some(electron_win),
    );
    let doc_menu = tree.add(
        snap(77, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), None),
        Some(ax_doc),
    );
    let doc_paste = tree.add(
        snap(77, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Paste")),
        Some(doc_menu),
    );
    assert_eq!(
        tree.resolve(doc_paste, 77, None, None, None, Some(&verified_file_link)),
        None
    );
    let edit_node = tree.add(
        snap(77, Some(UIA_EDIT_CONTROL_TYPE), Some("AXTextArea"), Some("Input")),
        Some(electron_win),
    );
    let edit_menu = tree.add(
        snap(77, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), None),
        Some(edit_node),
    );
    let edit_cut = tree.add(
        snap(77, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Cut")),
        Some(edit_menu),
    );
    assert_eq!(
        tree.resolve(edit_cut, 77, None, None, None, Some(&verified_file_link)),
        None
    );

    //    (e) `SystemMenuBar` behind transparent `Group` wrappers is STILL strictly rejected.
    let mut sys_bar_meta = snap(77, Some(UIA_MENU_BAR_CONTROL_TYPE), Some("AXMenuBar"), Some("System"));
    sys_bar_meta.automation_id = Some("SystemMenuBar".to_string());
    let sys_bar = tree.add(sys_bar_meta, Some(notepad_win));
    let sys_wrap = tree.add(
        snap(77, Some(UIA_GROUP_CONTROL_TYPE), Some("AXGroup"), None),
        Some(sys_bar),
    );
    let sys_menu = tree.add(
        snap(77, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), Some("System")),
        Some(sys_wrap),
    );
    let sys_close = tree.add(
        snap(77, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Close")),
        Some(sys_menu),
    );
    assert_eq!(tree.resolve(sys_close, 77, None, None, None, None), None);
    assert_eq!(classify_tree(&tree, sys_menu, &[], None), None);

    //    (f) `classify_opened_menu` caps consecutive transparent wrappers at 6 hops.
    let mut wrap_parent = electron_bar;
    for _ in 0..7 {
        wrap_parent = tree.add(
            snap(77, Some(UIA_GROUP_CONTROL_TYPE), Some("AXGroup"), None),
            Some(wrap_parent),
        );
    }
    let too_deep_menu = tree.add(
        snap(77, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), Some("File")),
        Some(wrap_parent),
    );
    assert_eq!(classify_tree(&tree, too_deep_menu, &[], None), None);

    // 3. Leaf MenuItem child classifier ignores visual Text/Image/Group and flags Menu/MenuItem.
    assert!(!is_menu_structure_control_type(UIA_TEXT_CONTROL_TYPE));
    assert!(!is_menu_structure_control_type(UIA_IMAGE_CONTROL_TYPE));
    assert!(!is_menu_structure_control_type(UIA_GROUP_CONTROL_TYPE));
    assert!(is_menu_structure_control_type(UIA_MENU_CONTROL_TYPE));
    assert!(is_menu_structure_control_type(UIA_MENU_ITEM_CONTROL_TYPE));

    // Submenu opener with child Menu (`child_count = Some(1)`) or `ExpandCollapse != LeafNode`
    // (`is_submenu_opener = Some(true)`) is strictly rejected even on valid Electron/WinUI 3 trees.
    let mut sub_with_menu = snap(
        77,
        Some(UIA_MENU_ITEM_CONTROL_TYPE),
        Some("AXMenuItem"),
        Some("Recent"),
    );
    sub_with_menu.child_count = Some(1);
    let sub_with_menu_id = tree.add(sub_with_menu, Some(electron_file_menu));
    assert_eq!(tree.resolve(sub_with_menu_id, 77, None, None, None, None), None);

    let mut sub_lazy = snap(
        77,
        Some(UIA_MENU_ITEM_CONTROL_TYPE),
        Some("AXMenuItem"),
        Some("Preferences"),
    );
    sub_lazy.child_count = Some(0);
    sub_lazy.is_submenu_opener = Some(true);
    let sub_lazy_id = tree.add(sub_lazy, Some(electron_file_menu));
    assert_eq!(tree.resolve(sub_lazy_id, 77, None, None, None, None), None);

    // 4. Strict transparent wrapper allowlist: reject ToolBar (50021), TitleBar (50037),
    //    Tree (50023), List (50008), Tab (50018), Button (50000), StatusBar (50017), and
    //    ControlType(0) between Menu and MenuBar or Window.
    for &(bad_ct, bad_role) in &[
        (Some(50021), Some("AXToolbar")),
        (Some(50037), Some("AXGroup")),
        (Some(50023), Some("AXOutline")),
        (Some(50008), Some("AXList")),
        (Some(50018), Some("AXTabGroup")),
        (Some(50000), Some("AXButton")),
        (Some(50017), Some("AXGroup")),
        (Some(0), None),
        (None, Some("AXToolbar")),
    ] {
        let bad_wrap_bar = tree.add(snap(77, bad_ct, bad_role, None), Some(electron_bar));
        let bad_menu_bar = tree.add(
            snap(77, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), Some("File")),
            Some(bad_wrap_bar),
        );
        let bad_leaf_bar = tree.add(
            snap(77, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Save")),
            Some(bad_menu_bar),
        );
        assert_eq!(
            tree.resolve(bad_leaf_bar, 77, None, None, None, None),
            None,
            "disallowed wrapper ct={bad_ct:?} role={bad_role:?} under MenuBar must be rejected"
        );
        assert_eq!(
            classify_tree(&tree, bad_menu_bar, &[], None),
            None,
            "disallowed wrapper ct={bad_ct:?} role={bad_role:?} must be rejected by classify_opened_menu"
        );

        let bad_wrap_win = tree.add(snap(77, bad_ct, bad_role, None), Some(notepad_win));
        let bad_menu_win = tree.add(
            snap(77, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), None),
            Some(bad_wrap_win),
        );
        let bad_leaf_win = tree.add(
            snap(77, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Copy")),
            Some(bad_menu_win),
        );
        assert_eq!(
            tree.resolve(bad_leaf_win, 77, None, None, None, Some(&verified_file_link)),
            None,
            "disallowed wrapper ct={bad_ct:?} role={bad_role:?} under Window must be rejected"
        );
    }
}

#[test]
fn menu_tracking_state_machine_deduplicator_and_pending_queue() {
    let mut sm = MenuTrackingStateMachine::<String, ResolvedMenuPath>::new();
    assert!(!sm.is_tracking());
    assert!(sm.commit(1_000).is_none());

    let open_file = sm.menu_opened("file".to_string(), true);
    assert_eq!(open_file.tracking_changed, Some(true));
    assert!(open_file.removed.is_empty());
    assert!(sm.is_tracking());

    let save_path = ResolvedMenuPath {
        path: vec!["File".to_string(), "Save".to_string()],
        truncated: false,
    };
    sm.update_selection(Some(save_path.clone()), "file".to_string(), 1_000);
    assert!(sm.has_selection());

    // Duplicate top-level open is idempotent and keeps selection.
    let dup = sm.menu_opened("file".to_string(), true);
    assert_eq!(dup.tracking_changed, None);
    assert!(dup.removed.is_empty());
    assert!(sm.has_selection());

    // Single-shot commit consumes highlight once.
    assert_eq!(sm.commit(1_500), Some(save_path.clone()));
    assert!(!sm.has_selection());
    assert!(sm.commit(1_501).is_none());

    // Selection freshness: <= 10_000ms accepted, > 10_000ms or rollback rejected.
    sm.update_selection(Some(save_path.clone()), "file".to_string(), 2_000);
    assert_eq!(sm.commit(12_000), Some(save_path.clone()));
    sm.update_selection(Some(save_path.clone()), "file".to_string(), 2_000);
    assert!(sm.commit(12_001).is_none());
    sm.update_selection(Some(save_path.clone()), "file".to_string(), 2_000);
    assert!(sm.commit(1_999).is_none());

    // Submenu stack & nested close invalidation.
    let open_sub = sm.menu_opened("export".to_string(), false);
    assert_eq!(open_sub.tracking_changed, None);
    assert_eq!(sm.open_menus(), &["file".to_string(), "export".to_string()]);
    let pdf_path = ResolvedMenuPath {
        path: vec!["File".to_string(), "Export".to_string(), "PDF".to_string()],
        truncated: false,
    };
    sm.update_selection(Some(pdf_path), "export".to_string(), 3_000);
    let close_sub = sm.menu_closed(&"export".to_string());
    assert_eq!(close_sub.tracking_changed, None);
    assert_eq!(close_sub.removed, vec!["export".to_string()]);
    assert!(!sm.has_selection());

    // Cancel clears selection without leaving tracking.
    sm.update_selection(Some(save_path), "file".to_string(), 3_100);
    sm.cancel();
    assert!(!sm.has_selection());
    assert!(sm.is_tracking());

    // New top-level menu evicts stale stack; prune empties stack.
    sm.menu_opened("export".to_string(), false);
    let open_edit = sm.menu_opened("edit".to_string(), true);
    assert_eq!(open_edit.tracking_changed, None);
    assert_eq!(open_edit.removed, vec!["file".to_string(), "export".to_string()]);
    let pruned = sm.prune(&"edit".to_string());
    assert_eq!(pruned.tracking_changed, Some(false));
    assert!(!sm.is_tracking());

    // MAX_OPEN_MENUS = 8 evicts oldest when exceeded.
    for i in 1..=9 {
        sm.menu_opened(format!("m{i}"), i == 1);
    }
    assert_eq!(sm.open_menus().len(), MenuPathLimits::MAX_OPEN_MENUS);
    assert_eq!(sm.open_menus().first().map(String::as_str), Some("m2"));
    assert_eq!(sm.open_menus().last().map(String::as_str), Some("m9"));
    let reset = sm.reset();
    assert_eq!(reset.tracking_changed, Some(false));
    assert_eq!(reset.removed.len(), 8);
    assert_eq!(sm.reset().tracking_changed, None);

    // 250ms deduplicator prevents Invoke_Invoked + fallback double-fire.
    let mut dedup = MenuActionDeduplicator::new();
    let p_save = vec!["File".to_string(), "Save".to_string()];
    let p_open = vec!["File".to_string(), "Open".to_string()];
    assert!(dedup.should_emit(&p_save, 1_000));
    assert!(!dedup.should_emit(&p_save, 1_000));
    assert!(!dedup.should_emit(&p_save, 1_250));
    assert!(dedup.should_emit(&p_save, 1_251));
    assert!(dedup.should_emit(&p_open, 1_260));
    dedup.reset();
    assert!(dedup.should_emit(&p_open, 1_260));

    // Pending FIFO queue caps at MAX_PENDING_RECORDS = 8 and evicts oldest.
    let mut queue = MenuActionPendingQueue::new();
    let make_menu_rec = |label: &str, valid: bool| MenuActionRecord {
        application: ApplicationIdentity {
            application_id: "notepad.exe".to_string(),
            process_id: 42,
            process_start_time: "birth-1".to_string(),
        },
        exe_name: Some("notepad.exe".to_string()),
        path: if valid {
            vec!["File".to_string(), label.to_string()]
        } else {
            vec![label.to_string()]
        },
        truncated: false,
        observed_at_ms: 1_000,
        private_state: "normal".to_string(),
        stamp: Stamp {
            capture_epoch: 1,
            foreground_generation: 1,
            focus_generation: 1,
            policy_revision: 1,
        },
        field_security: "strict".to_string(),
    };
    assert!(!queue.push(make_menu_rec("Bad", false)));
    assert!(queue.is_empty());
    for i in 1..=9 {
        assert!(queue.push(make_menu_rec(&format!("Item{i}"), true)));
    }
    assert_eq!(queue.len(), MenuPathLimits::MAX_PENDING_RECORDS);
    assert_eq!(
        queue.pop_next().map(|r| r.path[1].clone()),
        Some("Item2".to_string())
    );
}

#[test]
fn browser_menu_window_gate_fail_closed_matrix() {
    let allow_browser = CapturePolicy {
        enabled: true,
        allowed_application_ids: vec![],
        application_scope: Some("denylist".to_string()),
        allow_browser_content: Some(true),
        menu_actions: Some(true),
        ..CapturePolicy::default()
    };
    let deny_browser = CapturePolicy {
        enabled: true,
        allowed_application_ids: vec!["custom.browser.exe".to_string()],
        application_scope: Some("allowlist".to_string()),
        allow_browser_content: Some(false),
        menu_actions: Some(true),
        ..CapturePolicy::default()
    };

    let notepad_id = ResolvedAppIdentity::from_single("notepad.exe".to_string()).unwrap();
    let edge_id = ResolvedAppIdentity::from_single("msedge.exe".to_string()).unwrap();
    let msix_arc = ResolvedAppIdentity::from_wire_and_exe(
        "thebrowsercompany.arc".to_string(),
        Some("arc.exe".to_string()),
    )
    .unwrap();
    let safari_id = ResolvedAppIdentity::from_single("com.apple.safari".to_string()).unwrap();
    let unlisted_id = ResolvedAppIdentity::from_single("custom.browser.exe".to_string()).unwrap();

    // Non-browser app performs ZERO window lookups and succeeds.
    let calls = Cell::new(0usize);
    assert!(BrowserMenuWindowGate::allows_menu_read(
        &notepad_id,
        false,
        &GENERIC_ADAPTER_SPEC,
        &deny_browser,
        |a: &&str, b: &&str| a == b,
        || {
            calls.set(calls.get() + 1);
            BrowserWindowReference::Failure
        },
        || {
            calls.set(calls.get() + 1);
            BrowserWindowReference::Failure
        },
        || {
            calls.set(calls.get() + 1);
            BrowserWindowCountRead::Failure
        },
        |_| {
            calls.set(calls.get() + 1);
            BrowserWindowInspection::Failure
        },
    ));
    assert_eq!(calls.get(), 0);

    // Known, MSIX dual-ID Arc, and unlisted candidate require denylist + allowBrowserContent == true.
    for (id, cand, spec) in [
        (&edge_id, false, &BROWSER_FAMILY_SPEC),
        (&msix_arc, false, &GENERIC_ADAPTER_SPEC),
        (&unlisted_id, true, &GENERIC_ADAPTER_SPEC),
    ] {
        assert!(!BrowserMenuWindowGate::allows_foreground_window(
            id,
            cand,
            spec,
            &deny_browser,
            || BrowserWindowInspection::Inspected {
                role: Some("AXWindow".to_string()),
                has_sensitive_evidence: false,
                safe_title: Some("Docs".to_string()),
                chrome_verdict: BrowserChromeVerdict::VerifiedNormal,
            }
        ));
    }

    // Mandatory-excluded Safari is blocked even with denylist + allowBrowserContent == true.
    assert!(!BrowserMenuWindowGate::allows_foreground_window(
        &safari_id,
        true,
        &BROWSER_FAMILY_SPEC,
        &allow_browser,
        || BrowserWindowInspection::Inspected {
            role: Some("AXWindow".to_string()),
            has_sensitive_evidence: false,
            safe_title: Some("Docs".to_string()),
            chrome_verdict: BrowserChromeVerdict::VerifiedNormal,
        }
    ));

    // Chrome verdict matrix: Private & Inconclusive fail closed; ONLY VerifiedNormal passes.
    for (verdict, expected) in [
        (BrowserChromeVerdict::Private, false),
        (BrowserChromeVerdict::Inconclusive, false),
        (BrowserChromeVerdict::VerifiedNormal, true),
    ] {
        assert_eq!(
            BrowserMenuWindowGate::allows_foreground_window(
                &edge_id,
                false,
                &BROWSER_FAMILY_SPEC,
                &allow_browser,
                || BrowserWindowInspection::Inspected {
                    role: Some("AXWindow".to_string()),
                    has_sensitive_evidence: false,
                    safe_title: Some("Docs - Microsoft Edge".to_string()),
                    chrome_verdict: verdict,
                }
            ),
            expected
        );
    }

    // Multilingual private window titles fail closed even if chrome verdict were VerifiedNormal.
    for private_title in [
        "Bank (Incognito)",
        "Sign in - InPrivate",
        "搜索 - 无痕",
        "シークレット",
    ] {
        assert!(!BrowserMenuWindowGate::allows_foreground_window(
            &edge_id,
            false,
            &BROWSER_FAMILY_SPEC,
            &allow_browser,
            || BrowserWindowInspection::Inspected {
                role: Some("AXWindow".to_string()),
                has_sensitive_evidence: false,
                safe_title: Some(private_title.to_string()),
                chrome_verdict: BrowserChromeVerdict::VerifiedNormal,
            }
        ));
    }

    // Identical focused & main window is inspected once.
    let mut inspect_calls = 0;
    assert!(BrowserMenuWindowGate::allows_menu_read(
        &edge_id,
        false,
        &BROWSER_FAMILY_SPEC,
        &allow_browser,
        |a: &&str, b: &&str| a == b,
        || BrowserWindowReference::Window("w1"),
        || BrowserWindowReference::Window("w1"),
        || BrowserWindowCountRead::Count(1),
        |_| {
            inspect_calls += 1;
            BrowserWindowInspection::Inspected {
                role: Some("AXWindow".to_string()),
                has_sensitive_evidence: false,
                safe_title: Some("Docs".to_string()),
                chrome_verdict: BrowserChromeVerdict::VerifiedNormal,
            }
        },
    ));
    assert_eq!(inspect_calls, 1);

    // Non-private dialog over Incognito main window, sheet role, sensitive evidence, None title, and lookup failure fail closed.
    assert!(!BrowserMenuWindowGate::allows_menu_read(
        &edge_id,
        false,
        &BROWSER_FAMILY_SPEC,
        &allow_browser,
        |a: &&str, b: &&str| a == b,
        || BrowserWindowReference::Window("dialog"),
        || BrowserWindowReference::Window("incognito-main"),
        || BrowserWindowCountRead::Count(2),
        |win| BrowserWindowInspection::Inspected {
            role: Some("AXWindow".to_string()),
            has_sensitive_evidence: false,
            safe_title: Some(if *win == "dialog" {
                "Print".to_string()
            } else {
                "Secret (Incognito)".to_string()
            }),
            chrome_verdict: BrowserChromeVerdict::VerifiedNormal,
        },
    ));
    assert!(!BrowserMenuWindowGate::allows_foreground_window(
        &edge_id,
        false,
        &BROWSER_FAMILY_SPEC,
        &allow_browser,
        || BrowserWindowInspection::Inspected {
            role: Some("AXSheet".to_string()),
            has_sensitive_evidence: false,
            safe_title: Some("Save".to_string()),
            chrome_verdict: BrowserChromeVerdict::VerifiedNormal,
        }
    ));
    assert!(!BrowserMenuWindowGate::allows_foreground_window(
        &edge_id,
        false,
        &BROWSER_FAMILY_SPEC,
        &allow_browser,
        || BrowserWindowInspection::Inspected {
            role: Some("AXWindow".to_string()),
            has_sensitive_evidence: true,
            safe_title: Some("Docs".to_string()),
            chrome_verdict: BrowserChromeVerdict::VerifiedNormal,
        }
    ));
    assert!(!BrowserMenuWindowGate::allows_foreground_window(
        &edge_id,
        false,
        &BROWSER_FAMILY_SPEC,
        &allow_browser,
        || BrowserWindowInspection::Inspected {
            role: Some("AXWindow".to_string()),
            has_sensitive_evidence: false,
            safe_title: None,
            chrome_verdict: BrowserChromeVerdict::VerifiedNormal,
        }
    ));

    // Absent focused & main windows require positive Count(0) proof.
    for (count_read, expected) in [
        (BrowserWindowCountRead::Count(0), true),
        (BrowserWindowCountRead::Count(1), false),
        (BrowserWindowCountRead::Failure, false),
    ] {
        assert_eq!(
            BrowserMenuWindowGate::allows_menu_read(
                &edge_id,
                false,
                &BROWSER_FAMILY_SPEC,
                &allow_browser,
                |a: &&str, b: &&str| a == b,
                || BrowserWindowReference::Absent,
                || BrowserWindowReference::Absent,
                || count_read,
                |_| BrowserWindowInspection::Failure,
            ),
            expected
        );
    }
}

#[test]
fn menu_action_record_ipc_roundtrip_and_contract_validation() {
    let validator = ContractValidator::new().expect("validator");
    let app = ApplicationIdentity {
        application_id: "notepad.exe".to_string(),
        process_id: 42,
        process_start_time: "2026-11-24T15:00:00Z".to_string(),
    };
    let app_target = ApplicationTargetIdentity {
        device_id: "win-device".to_string(),
        os_session_id: "win-session".to_string(),
        desktop_id: "win-desktop".to_string(),
        process_id: app.process_id,
        process_start_time: app.process_start_time.clone(),
        application_id: app.application_id.clone(),
    };
    let stamp = Stamp {
        capture_epoch: 1,
        foreground_generation: 2,
        focus_generation: 3,
        policy_revision: 1,
    };

    for (source, truncated, field_security, private_state) in [
        (MenuActionSource::UiaMenu, false, "strict", "normal"),
        (MenuActionSource::UiaMenu, true, "strict", "normal"),
        (MenuActionSource::Fixture, false, "denylist", "user-authorized"),
        (MenuActionSource::Fixture, true, "denylist", "user-authorized"),
    ] {
        let rec = MenuActionRecord {
            application: app.clone(),
            exe_name: Some("notepad.exe".to_string()),
            path: vec![
                "File".to_string(),
                "Export".to_string(),
                "PDF...".to_string(),
            ],
            truncated,
            observed_at_ms: 4_200,
            private_state: private_state.to_string(),
            stamp,
            field_security: field_security.to_string(),
        };
        assert!(rec.is_valid());
        let rt = MenuActionRecord::from_json(&rec.to_json()).expect("menu IPC round-trip");
        assert_eq!(rt, rec);
        assert_eq!(rt.exe_name.as_deref(), Some("notepad.exe"));

        let payload = rec.payload_with_source(source);
        let wire_str = String::from_utf8(payload.canonical_bytes().unwrap()).unwrap();
        assert!(!wire_str.contains("exeName"));
        let reasons = payload
            .get("coverage")
            .and_then(|c| c.get("missingReasons"))
            .and_then(JsonValue::as_array)
            .expect("missingReasons");
        assert!(reasons.iter().any(|v| v.as_str() == Some("menu-bar-only")));
        assert!(reasons
            .iter()
            .any(|v| v.as_str() == Some("effect-unverified")));
        assert_eq!(
            reasons
                .iter()
                .any(|v| v.as_str() == Some("menu-title-truncated")),
            truncated
        );

        let envelope = wrap_observation(
            rec.observed_at_ms,
            4_200,
            app_target.to_target_ref(),
            rec.stamp,
            payload,
        );
        validator
            .encode_frame(&envelope)
            .expect("menu.action envelope must validate");
    }

    // Invalid records fail validation and IPC decoding fail-closed.
    let mut bad = MenuActionRecord {
        application: app,
        exe_name: Some("applicationframehost.exe".to_string()),
        path: vec!["File".to_string(), "Save".to_string()],
        truncated: false,
        observed_at_ms: 1_000,
        private_state: "normal".to_string(),
        stamp,
        field_security: "strict".to_string(),
    };
    assert!(!bad.is_valid());
    assert!(MenuActionRecord::from_json(&bad.to_json()).is_none());

    bad.exe_name = Some("notepad.exe".to_string());
    bad.path = vec!["File".to_string(), "Bad\nItem".to_string()];
    assert!(!bad.is_valid());
    assert!(MenuActionRecord::from_json(&bad.to_json()).is_none());
}

// =============================================================================
// 4. PR #8 Review Hardening: P1-5, P1-13, P1-14, P2-8, P2-10, P2-11
// =============================================================================

#[test]
fn input_text_p1_13_post_return_cross_context_stale_pending_and_backwards_split_purge() {
    let ctx_a = std_context();
    let mut ctx_b = std_context();
    ctx_b.surface_id = "field-2".to_string();
    let mut ctx_epoch2 = std_context();
    ctx_epoch2.capture_epoch = 2;

    // 1. After Return seals pending into `completed` (leaving `acc.pending() == None`),
    //    a keystroke from a different field MUST purge and zeroize `completed`.
    let mut acc = InputTextAccumulator::default();
    let mut completed = Vec::new();
    assert_eq!(
        acc.ingest_into_completed(
            &mut completed,
            sample(ctx_a.clone(), InputTextKind::Text, "secret", vec![], 1_000),
            InputTextSource::Win32Unicode,
        ),
        Ok(InputTextIngestOutcome::Buffered)
    );
    assert_eq!(
        acc.ingest_into_completed(
            &mut completed,
            sample(ctx_a.clone(), InputTextKind::Return, "", vec![], 1_050),
            InputTextSource::Win32Unicode,
        ),
        Ok(InputTextIngestOutcome::SealedReturn)
    );
    assert!(acc.pending().is_none());
    assert_eq!(completed.len(), 2);

    assert_eq!(
        acc.ingest_into_completed(
            &mut completed,
            sample(ctx_b.clone(), InputTextKind::Text, "x", vec![], 1_100),
            InputTextSource::Win32Unicode,
        ),
        Err(InputTextGapReason::TargetMismatch)
    );
    assert!(acc.pending().is_none());
    assert!(completed.is_empty());

    // Epoch change after Return purges `completed` with `Stale`.
    assert_eq!(
        acc.ingest_into_completed(
            &mut completed,
            sample(ctx_a.clone(), InputTextKind::Return, "", vec![], 2_000),
            InputTextSource::Win32Unicode,
        ),
        Ok(InputTextIngestOutcome::SealedReturn)
    );
    assert_eq!(completed.len(), 1);
    assert_eq!(
        acc.ingest_into_completed(
            &mut completed,
            sample(ctx_epoch2, InputTextKind::Text, "y", vec![], 2_050),
            InputTextSource::Win32Unicode,
        ),
        Err(InputTextGapReason::Stale)
    );
    assert!(acc.pending().is_none());
    assert!(completed.is_empty());

    // 2. Post-Return backwards clock against `completed.last()` (`pending == None`) purges with `Stale`.
    assert_eq!(
        acc.ingest_into_completed(
            &mut completed,
            sample(ctx_a.clone(), InputTextKind::Return, "", vec![], 3_000),
            InputTextSource::Win32Unicode,
        ),
        Ok(InputTextIngestOutcome::SealedReturn)
    );
    assert_eq!(
        acc.ingest_into_completed(
            &mut completed,
            sample(ctx_a.clone(), InputTextKind::Text, "back", vec![], 2_999),
            InputTextSource::Win32Unicode,
        ),
        Err(InputTextGapReason::Stale)
    );
    assert!(acc.pending().is_none());
    assert!(completed.is_empty());

    // 3. Pending older than `MAX_INTERVAL_SPAN_MS` (5000ms) is purged with `Stale` BEFORE
    //    `take_segment` promotion (exact 5000ms allowed; 5001ms purged).
    assert_eq!(
        acc.ingest_into_completed(
            &mut completed,
            sample(ctx_a.clone(), InputTextKind::Text, "ok5s", vec![], 1_000),
            InputTextSource::Win32Unicode,
        ),
        Ok(InputTextIngestOutcome::Buffered)
    );
    assert_eq!(
        acc.ingest_into_completed(
            &mut completed,
            sample(ctx_a.clone(), InputTextKind::Text, "next", vec![], 6_000),
            InputTextSource::Win32Unicode,
        ),
        Ok(InputTextIngestOutcome::Buffered)
    );
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].text, "ok5s");
    assert_eq!(acc.pending().map(|p| p.text.as_str()), Some("next"));

    // Now advance 5001ms past `next`'s `interval_start_ms` (6_000 -> 11_001): MUST purge both!
    assert_eq!(
        acc.ingest_into_completed(
            &mut completed,
            sample(ctx_a.clone(), InputTextKind::Text, "late", vec![], 11_001),
            InputTextSource::Win32Unicode,
        ),
        Err(InputTextGapReason::Stale)
    );
    assert!(acc.pending().is_none());
    assert!(completed.is_empty());

    // Same >5s stale pending guard holds when the incoming sample is `Return`.
    assert_eq!(
        acc.ingest_into_completed(
            &mut completed,
            sample(ctx_a.clone(), InputTextKind::Text, "stale", vec![], 1_000),
            InputTextSource::Win32Unicode,
        ),
        Ok(InputTextIngestOutcome::Buffered)
    );
    assert_eq!(
        acc.ingest_into_completed(
            &mut completed,
            sample(ctx_a.clone(), InputTextKind::Return, "", vec![], 6_001),
            InputTextSource::Win32Unicode,
        ),
        Err(InputTextGapReason::Stale)
    );
    assert!(acc.pending().is_none());
    assert!(completed.is_empty());

    // 4. Segment split on `event_kind` change (`Text` -> `Return` or `Shortcut`) MUST NOT bypass
    //    backwards-clock rejection.
    for split_sample in [
        sample(ctx_a.clone(), InputTextKind::Return, "", vec![], 999),
        sample(
            ctx_a.clone(),
            InputTextKind::Shortcut,
            "",
            vec![InputTextModifier::Control],
            999,
        ),
    ] {
        assert_eq!(
            acc.ingest_into_completed(
                &mut completed,
                sample(ctx_a.clone(), InputTextKind::Text, "abc", vec![], 1_000),
                InputTextSource::Win32Unicode,
            ),
            Ok(InputTextIngestOutcome::Buffered)
        );
        assert_eq!(
            acc.ingest_into_completed(&mut completed, split_sample, InputTextSource::Win32Unicode),
            Err(InputTextGapReason::Stale)
        );
        assert!(acc.pending().is_none());
        assert!(completed.is_empty());
    }
}

#[test]
fn input_text_p1_14_ignored_key_in_new_context_purges_buffered_plaintext() {
    let policy = default_input_policy();
    let ctx_a = std_context();
    let mut ctx_b = std_context();
    ctx_b.surface_id = "field-b".to_string();
    let mut ctx_epoch2 = std_context();
    ctx_epoch2.capture_epoch = 2;

    // 1. Pressing non-text keys (`Tab`, `Escape`, `Backspace`/empty) in the SAME context preserves buffer.
    let mut acc = InputTextAccumulator::default();
    let mut completed = Vec::new();
    assert_eq!(
        acc.ingest_into_completed(
            &mut completed,
            sample(ctx_a.clone(), InputTextKind::Text, "keep", vec![], 1_000),
            InputTextSource::Win32Unicode,
        ),
        Ok(InputTextIngestOutcome::Buffered)
    );
    for key in ["\t", "", "\u{001B}", "\u{007F}"] {
        let step = InputTextReadGate::capture_with_accumulator(
            std_meta(42, BASE_NS, 1_010),
            &[],
            InputTextSource::Win32Unicode,
            &policy,
            0,
            &mut acc,
            &mut completed,
            || BASE_NS,
            |_| Ok(approved(ctx_a.clone(), BASE_NS, InputTextFieldRole::TextArea)),
            || InputTextUnicodeRead::Text(key.to_string()),
            |_| {},
        );
        assert_eq!(step, InputTextCaptureStep::Ignored);
        assert_eq!(acc.pending().map(|p| p.text.as_str()), Some("keep"));
    }

    // 2. Switching to field B and pressing Tab/Escape/empty purges BOTH `pending` and `completed`.
    for (new_ctx, key) in [
        (ctx_b.clone(), "\t"),
        (ctx_b.clone(), "\u{001B}"),
        (ctx_epoch2.clone(), ""),
    ] {
        acc.clear();
        completed.clear();
        completed.push(seal_one(
            sample(ctx_a.clone(), InputTextKind::Text, "prior", vec![], 900),
            InputTextSource::Win32Unicode,
        ));
        assert_eq!(
            acc.add(
                sample(ctx_a.clone(), InputTextKind::Text, "secret", vec![], 1_000),
                InputTextSource::Win32Unicode,
            ),
            None
        );
        let step = InputTextReadGate::capture_with_accumulator(
            std_meta(42, BASE_NS, 1_050),
            &[],
            InputTextSource::Win32Unicode,
            &policy,
            0,
            &mut acc,
            &mut completed,
            || BASE_NS,
            |_| Ok(approved(new_ctx.clone(), BASE_NS, InputTextFieldRole::TextField)),
            || InputTextUnicodeRead::Text(key.to_string()),
            |_| {},
        );
        assert_eq!(step, InputTextCaptureStep::Ignored);
        assert!(acc.pending().is_none());
        assert!(completed.is_empty());
    }

    // 3. Even when `pending == None` (post-Return), an Ignored key in context B purges `completed` from A.
    assert_eq!(
        acc.ingest_into_completed(
            &mut completed,
            sample(ctx_a.clone(), InputTextKind::Text, "submitted", vec![], 2_000),
            InputTextSource::Win32Unicode,
        ),
        Ok(InputTextIngestOutcome::Buffered)
    );
    assert_eq!(
        acc.ingest_into_completed(
            &mut completed,
            sample(ctx_a.clone(), InputTextKind::Return, "", vec![], 2_050),
            InputTextSource::Win32Unicode,
        ),
        Ok(InputTextIngestOutcome::SealedReturn)
    );
    assert!(acc.pending().is_none());
    assert_eq!(completed.len(), 2);

    let step = InputTextReadGate::capture_with_accumulator(
        std_meta(42, BASE_NS, 2_100),
        &[],
        InputTextSource::Win32Unicode,
        &policy,
        0,
        &mut acc,
        &mut completed,
        || BASE_NS,
        |_| Ok(approved(ctx_b.clone(), BASE_NS, InputTextFieldRole::TextField)),
        || InputTextUnicodeRead::Text("\t".to_string()),
        |_| {},
    );
    assert_eq!(step, InputTextCaptureStep::Ignored);
    assert!(acc.pending().is_none());
    assert!(completed.is_empty());
}

#[test]
fn menu_path_resolver_p1_5_browser_document_hosted_menubar_and_unsafe_ancestors_rejected() {
    let mut tree = SyntheticMenuTree::new();
    let win = tree.add(
        snap(88, Some(UIA_WINDOW_CONTROL_TYPE), Some("AXWindow"), Some("Chrome")),
        None,
    );

    let resolve_policy = |tree: &SyntheticMenuTree,
                          leaf: usize,
                          allow_doc: bool|
     -> Option<ResolvedMenuPath> {
        MenuPathResolver::resolve_with_policy(
            leaf,
            88,
            None,
            None,
            None,
            None,
            allow_doc,
            |a, b| a == b,
            |&id, is_leaf| {
                let mut m = tree.nodes[id].meta.clone();
                if !is_leaf {
                    m.child_count = None;
                }
                Some(m)
            },
            |&id| tree.nodes[id].parent,
            || true,
        )
    };
    let classify_policy = |tree: &SyntheticMenuTree,
                           menu: usize,
                           allow_doc: bool|
     -> Option<OpenedMenuKind> {
        MenuPathResolver::classify_opened_menu_with_policy(
            menu,
            88,
            None,
            None,
            None,
            None,
            &[],
            allow_doc,
            |a, b| a == b,
            |&id| Some(tree.nodes[id].meta.clone()),
            |&id| tree.nodes[id].parent,
            || true,
        )
    };

    // 1. All 5 document/renderer host ancestors above `MenuBar` are rejected when
    //    `allow_document_hosted_menu_bar = false` (browsers), and allowed when `true` (Electron).
    let doc_hosts = [
        snap(88, Some(UIA_DOCUMENT_CONTROL_TYPE), None, Some("Page")),
        snap(88, None, Some("AXWebArea"), Some("Page")),
        snap(88, None, Some("AXDocument"), Some("Page")),
        {
            let mut m = snap(88, Some(UIA_PANE_CONTROL_TYPE), Some("AXGroup"), None);
            m.class_name = Some("Chrome_RenderWidgetHostHWND".to_string());
            m
        },
        {
            let mut m = snap(88, Some(UIA_WINDOW_CONTROL_TYPE), Some("AXWindow"), None);
            m.class_name = Some("Chrome_RenderWidgetHostHWND".to_string());
            m
        },
        {
            let mut m = snap(88, Some(UIA_PANE_CONTROL_TYPE), Some("AXGroup"), None);
            m.class_name = Some("MozillaCompositorWindowClass".to_string());
            m
        },
        {
            let mut m = snap(88, Some(UIA_WINDOW_CONTROL_TYPE), Some("AXWindow"), None);
            m.class_name = Some("MozillaCompositorWindowClass".to_string());
            m
        },
    ];
    for host_meta in doc_hosts {
        let host = tree.add(host_meta, Some(win));
        let bar = tree.add(
            snap(88, Some(UIA_MENU_BAR_CONTROL_TYPE), Some("AXMenuBar"), Some("Web")),
            Some(host),
        );
        let item = tree.add(
            snap(88, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("File")),
            Some(bar),
        );
        let menu = tree.add(
            snap(88, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), None),
            Some(item),
        );
        let leaf = tree.add(
            snap(88, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Download")),
            Some(menu),
        );
        assert_eq!(
            resolve_policy(&tree, leaf, false),
            None,
            "browser policy must reject document-hosted <div role=menubar>"
        );
        assert_eq!(
            classify_policy(&tree, menu, false),
            None,
            "browser classify_opened_menu_with_policy must reject document-hosted MenuBar"
        );
        assert_eq!(
            resolve_policy(&tree, leaf, true).map(|r| r.path),
            Some(vec!["File".to_string(), "Download".to_string()])
        );
        assert_eq!(
            classify_policy(&tree, menu, true),
            Some(OpenedMenuKind::TopLevel)
        );
    }

    // 2. Native chrome `MenuBar` directly under safe `Pane -> Window` (or Desktop `None`) passes
    //    even with `allow_document_hosted_menu_bar = false`.
    let chrome_pane = tree.add(
        snap(88, Some(UIA_PANE_CONTROL_TYPE), Some("AXGroup"), Some("Chrome")),
        Some(win),
    );
    let native_bar = tree.add(
        snap(88, Some(UIA_MENU_BAR_CONTROL_TYPE), Some("AXMenuBar"), Some("App")),
        Some(chrome_pane),
    );
    let native_file = tree.add(
        snap(88, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("File")),
        Some(native_bar),
    );
    let native_menu = tree.add(
        snap(88, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), None),
        Some(native_file),
    );
    let native_new_tab = tree.add(
        snap(88, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("New Tab")),
        Some(native_menu),
    );
    assert_eq!(
        resolve_policy(&tree, native_new_tab, false).map(|r| r.path),
        Some(vec!["File".to_string(), "New Tab".to_string()])
    );
    assert_eq!(
        classify_policy(&tree, native_menu, false),
        Some(OpenedMenuKind::TopLevel)
    );

    let desktop_bar = tree.add(
        snap(88, Some(UIA_MENU_BAR_CONTROL_TYPE), Some("AXMenuBar"), Some("App")),
        None,
    );
    let desktop_file = tree.add(
        snap(88, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Edit")),
        Some(desktop_bar),
    );
    let desktop_menu = tree.add(
        snap(88, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), None),
        Some(desktop_file),
    );
    let desktop_copy = tree.add(
        snap(88, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Copy")),
        Some(desktop_menu),
    );
    assert_eq!(
        resolve_policy(&tree, desktop_copy, false).map(|r| r.path),
        Some(vec!["Edit".to_string(), "Copy".to_string()])
    );

    // 3. Unsafe ancestor ABOVE `MenuBar` (protected content, cross-PID, secure subrole,
    //    `AXSecureTextField`, `SystemMenuBar`, cycle, or hop exhaustion) rejected even when
    //    `allow_document_hosted_menu_bar = true`.
    let unsafe_ancestors = [
        {
            let mut m = snap(88, Some(UIA_PANE_CONTROL_TYPE), Some("AXGroup"), None);
            m.protected_content = ProtectedContentRead::Value(true);
            m
        },
        {
            let mut m = snap(88, Some(UIA_PANE_CONTROL_TYPE), Some("AXGroup"), None);
            m.protected_content = ProtectedContentRead::Failure;
            m
        },
        snap(99, Some(UIA_PANE_CONTROL_TYPE), Some("AXGroup"), None),
        {
            let mut m = snap(88, Some(UIA_PANE_CONTROL_TYPE), Some("AXGroup"), None);
            m.subrole = SubroleRead::Value("AXPasswordContainer".to_string());
            m
        },
        snap(88, None, Some("AXSecureTextField"), None),
        {
            let mut m = snap(88, Some(UIA_MENU_BAR_CONTROL_TYPE), Some("AXMenuBar"), None);
            m.automation_id = Some("SystemMenuBar".to_string());
            m
        },
    ];
    for bad_ancestor_meta in unsafe_ancestors {
        let bad_ancestor = tree.add(bad_ancestor_meta, Some(win));
        let bar = tree.add(
            snap(88, Some(UIA_MENU_BAR_CONTROL_TYPE), Some("AXMenuBar"), Some("App")),
            Some(bad_ancestor),
        );
        let item = tree.add(
            snap(88, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("File")),
            Some(bar),
        );
        let menu = tree.add(
            snap(88, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), None),
            Some(item),
        );
        let leaf = tree.add(
            snap(88, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Save")),
            Some(menu),
        );
        assert_eq!(resolve_policy(&tree, leaf, true), None);
        assert_eq!(classify_policy(&tree, menu, true), None);
    }

    // Cycle above `MenuBar` fails closed.
    let cyc_pane = tree.add(
        snap(88, Some(UIA_PANE_CONTROL_TYPE), Some("AXGroup"), None),
        None,
    );
    let cyc_bar = tree.add(
        snap(88, Some(UIA_MENU_BAR_CONTROL_TYPE), Some("AXMenuBar"), Some("App")),
        Some(cyc_pane),
    );
    tree.set_parent(cyc_pane, Some(cyc_bar));
    let cyc_file = tree.add(
        snap(88, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("File")),
        Some(cyc_bar),
    );
    let cyc_menu = tree.add(
        snap(88, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), None),
        Some(cyc_file),
    );
    let cyc_leaf = tree.add(
        snap(88, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Save")),
        Some(cyc_menu),
    );
    assert_eq!(resolve_policy(&tree, cyc_leaf, true), None);
    assert_eq!(classify_policy(&tree, cyc_menu, true), None);
}

#[test]
fn menu_path_p2_8_zwsp_and_pua_icon_fallback_and_p2_10_wrappers_and_disabled_menu() {
    // P2-8: ZWSP / zero-width invisible and pure PUA Segoe Fluent / Codicon glyphs return None.
    for empty_or_pua in [
        "\u{200B}",
        "\u{200C}\u{200D}\u{00AD}",
        " \u{200B}\u{FEFF}\t ",
        "\u{E74E}",
        " \u{EA60} \u{E710} ",
        "\u{F0001}",
        "\u{100000}",
    ] {
        assert_eq!(
            MenuPathLimits::sanitize_segment(empty_or_pua),
            None,
            "segment {empty_or_pua:?} must return None"
        );
        assert!(!MenuPathLimits::is_valid_segment(empty_or_pua));
    }
    // Mixed icon + real text is preserved.
    assert_eq!(
        MenuPathLimits::sanitize_segment("\u{E74E} Save"),
        Some("\u{E74E} Save".to_string())
    );

    let mut tree = SyntheticMenuTree::new();
    let win = tree.add(
        snap(42, Some(UIA_WINDOW_CONTROL_TYPE), Some("AXWindow"), Some("Editor")),
        None,
    );
    let bar = tree.add(
        snap(42, Some(UIA_MENU_BAR_CONTROL_TYPE), Some("AXMenuBar"), None),
        Some(win),
    );
    let file_item = tree.add(
        snap(42, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("File")),
        Some(bar),
    );
    let file_menu = tree.add(
        snap(42, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), None),
        Some(file_item),
    );

    // P2-8 fallback: PUA icon Name falls back to description (`safe_description()`).
    let mut pua_leaf_meta = snap(
        42,
        Some(UIA_MENU_ITEM_CONTROL_TYPE),
        Some("AXMenuItem"),
        Some("\u{E74E}"),
    );
    pua_leaf_meta.description = Some("Save File".to_string());
    let pua_leaf = tree.add(pua_leaf_meta, Some(file_menu));
    assert_eq!(
        tree.resolve(pua_leaf, 42, None, Some(bar), None, None)
            .map(|r| r.path),
        Some(vec!["File".to_string(), "Save File".to_string()])
    );

    // P2-8 fallback: ZWSP Name falls back to description.
    let mut zwsp_leaf_meta = snap(
        42,
        Some(UIA_MENU_ITEM_CONTROL_TYPE),
        Some("AXMenuItem"),
        Some("\u{200B}\u{200D}"),
    );
    zwsp_leaf_meta.description = Some("Open...".to_string());
    let zwsp_leaf = tree.add(zwsp_leaf_meta, Some(file_menu));
    assert_eq!(
        tree.resolve(zwsp_leaf, 42, None, Some(bar), None, None)
            .map(|r| r.path),
        Some(vec!["File".to_string(), "Open...".to_string()])
    );

    // P2-8: PUA-only Name + PUA-only description rejected.
    let mut both_pua_meta = snap(
        42,
        Some(UIA_MENU_ITEM_CONTROL_TYPE),
        Some("AXMenuItem"),
        Some("\u{E74E}"),
    );
    both_pua_meta.description = Some("\u{EA60}".to_string());
    let both_pua_leaf = tree.add(both_pua_meta, Some(file_menu));
    assert_eq!(tree.resolve(both_pua_leaf, 42, None, Some(bar), None, None), None);

    // P2-10: `MenuPathResolver::resolve` caps consecutive transparent wrappers at 6 hops.
    let mut wrap6 = bar;
    for _ in 0..6 {
        wrap6 = tree.add(
            snap(42, Some(UIA_GROUP_CONTROL_TYPE), Some("AXGroup"), None),
            Some(wrap6),
        );
    }
    let menu_after_6 = tree.add(
        snap(42, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), Some("File")),
        Some(wrap6),
    );
    let leaf_after_6 = tree.add(
        snap(42, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Save")),
        Some(menu_after_6),
    );
    assert_eq!(
        tree.resolve(leaf_after_6, 42, None, None, None, None)
            .map(|r| r.path),
        Some(vec!["File".to_string(), "Save".to_string()])
    );

    let wrap7 = tree.add(
        snap(42, Some(UIA_GROUP_CONTROL_TYPE), Some("AXGroup"), None),
        Some(wrap6),
    );
    let menu_after_7 = tree.add(
        snap(42, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), Some("File")),
        Some(wrap7),
    );
    let leaf_after_7 = tree.add(
        snap(42, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Save")),
        Some(menu_after_7),
    );
    assert_eq!(tree.resolve(leaf_after_7, 42, None, None, None, None), None);

    // P2-10: `AXHeading` (and other non-whitelisted roles) rejected on Custom/Group/Pane wrappers;
    //        `None`, `AXGroup`, and `AXScrollArea` allowed.
    for bad_role in ["AXHeading", "AXToolbar", "AXButton", "AXDialog"] {
        for ct in [
            UIA_CUSTOM_CONTROL_TYPE,
            UIA_GROUP_CONTROL_TYPE,
            UIA_PANE_CONTROL_TYPE,
        ] {
            let bad_wrap = tree.add(snap(42, Some(ct), Some(bad_role), None), Some(bar));
            let m = tree.add(
                snap(42, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), Some("File")),
                Some(bad_wrap),
            );
            let l = tree.add(
                snap(42, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Save")),
                Some(m),
            );
            assert_eq!(
                tree.resolve(l, 42, None, None, None, None),
                None,
                "wrapper ct={ct} role={bad_role} must be rejected"
            );
        }
    }
    for ok_role in [None, Some("AXGroup"), Some("AXScrollArea")] {
        let ok_wrap = tree.add(
            snap(42, Some(UIA_PANE_CONTROL_TYPE), ok_role, None),
            Some(bar),
        );
        let m = tree.add(
            snap(42, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), Some("File")),
            Some(ok_wrap),
        );
        let l = tree.add(
            snap(42, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Save")),
            Some(m),
        );
        assert_eq!(
            tree.resolve(l, 42, None, None, None, None).map(|r| r.path),
            Some(vec!["File".to_string(), "Save".to_string()])
        );
    }

    // P2-10: Disabled `Menu` (`enabled == Some(false)`) rejected by both `resolve` and `classify_opened_menu`.
    let mut disabled_menu_meta = snap(42, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), Some("File"));
    disabled_menu_meta.enabled = Some(false);
    let disabled_menu = tree.add(disabled_menu_meta, Some(file_item));
    let leaf_in_disabled = tree.add(
        snap(42, Some(UIA_MENU_ITEM_CONTROL_TYPE), Some("AXMenuItem"), Some("Save")),
        Some(disabled_menu),
    );
    assert_eq!(
        tree.resolve(leaf_in_disabled, 42, None, Some(bar), None, None),
        None
    );
    assert_eq!(
        MenuPathResolver::classify_opened_menu(
            disabled_menu,
            42,
            None,
            Some(&bar),
            None,
            None,
            &[],
            |a, b| a == b,
            |&id| Some(tree.nodes[id].meta.clone()),
            |&id| tree.nodes[id].parent,
            || true,
        ),
        None
    );

    // Intermediate disabled `Menu` ancestor also rejects nested submenu classification.
    let nested_under_disabled = tree.add(
        snap(42, Some(UIA_MENU_CONTROL_TYPE), Some("AXMenu"), None),
        Some(disabled_menu),
    );
    assert_eq!(
        MenuPathResolver::classify_opened_menu(
            nested_under_disabled,
            42,
            None,
            Some(&bar),
            None,
            None,
            &[],
            |a, b| a == b,
            |&id| Some(tree.nodes[id].meta.clone()),
            |&id| tree.nodes[id].parent,
            || true,
        ),
        None
    );
}

#[test]
fn p2_11_checked_sub_overflow_content_gate_fail_closed_ime_start_decay_and_pid_bounds() {
    let validator = ContractValidator::new().expect("validator");

    // 1. `process_mismatch` enforces `expected <= i32::MAX as u32` (never wraps negative).
    assert_eq!(
        InputTextGapReason::process_mismatch((i32::MAX as u32) + 1, 42),
        InputTextGapReason::Stale
    );
    assert_eq!(
        InputTextGapReason::process_mismatch(u32::MAX, 42),
        InputTextGapReason::Stale
    );
    assert_eq!(
        InputTextGapReason::process_mismatch(i32::MAX as u32, 42),
        InputTextGapReason::TargetMismatch
    );
    assert_eq!(
        InputTextGapReason::process_mismatch(42, i64::from(i32::MAX) + 1),
        InputTextGapReason::Stale
    );

    // 2. `InputTextContext::content_gate()` and `InputTextRecord::payload()` never map
    //    invalid/sensitive states to `"safe"`.
    let base_ctx = std_context();
    assert_eq!(
        base_ctx.content_gate().map(|g| g.secure),
        Some("safe".to_string())
    );
    let mut denylist_ctx = base_ctx.clone();
    denylist_ctx.field_security_mode = "denylist".to_string();
    denylist_ctx.secure_status = SecureStatus::NotDeclaredSensitive;
    assert_eq!(
        denylist_ctx.content_gate().map(|g| g.secure),
        Some("not-declared-sensitive".to_string())
    );
    for (mode, status, rev) in [
        ("strict", SecureStatus::Sensitive, 1),
        ("strict", SecureStatus::Unknown, 1),
        ("strict", SecureStatus::NotDeclaredSensitive, 1),
        ("denylist", SecureStatus::Sensitive, 1),
        ("denylist", SecureStatus::Unknown, 1),
        ("unknown-mode", SecureStatus::Safe, 1),
        ("strict", SecureStatus::Safe, 0),
    ] {
        let mut bad_ctx = base_ctx.clone();
        bad_ctx.field_security_mode = mode.to_string();
        bad_ctx.secure_status = status;
        bad_ctx.policy_revision = rev;
        assert_eq!(
            bad_ctx.content_gate(),
            None,
            "mode={mode} status={status:?} rev={rev} must NOT map to ContentGate"
        );
        assert!(!bad_ctx.is_valid());
        let bad_rec = InputTextRecord {
            context: bad_ctx,
            source: InputTextSource::Win32Unicode,
            event_kind: InputTextKind::Text,
            text: "secret".to_string(),
            modifiers: Vec::new(),
            interval_start_ms: 1_000,
            interval_end_ms: 1_000,
            event_count: 1,
            extra_coverage_reasons: Vec::new(),
        };
        assert!(bad_rec.payload().is_none());
    }

    // 3. `MenuActionRecord::content_gate()` never maps invalid/sensitive states to `"safe"`.
    let app = ApplicationIdentity {
        application_id: "notepad.exe".to_string(),
        process_id: 42,
        process_start_time: "2026-11-24T15:00:00Z".to_string(),
    };
    let app_target = ApplicationTargetIdentity {
        device_id: "win-device".to_string(),
        os_session_id: "win-session".to_string(),
        desktop_id: "win-desktop".to_string(),
        process_id: app.process_id,
        process_start_time: app.process_start_time.clone(),
        application_id: app.application_id.clone(),
    };
    let stamp = Stamp {
        capture_epoch: 1,
        foreground_generation: 1,
        focus_generation: 1,
        policy_revision: 1,
    };
    for bad_sec in ["sensitive", "unknown", "", "permissive"] {
        let bad_menu = MenuActionRecord {
            application: app.clone(),
            exe_name: Some("notepad.exe".to_string()),
            path: vec!["File".to_string(), "Save".to_string()],
            truncated: false,
            observed_at_ms: 1_000,
            private_state: "normal".to_string(),
            stamp,
            field_security: bad_sec.to_string(),
        };
        assert_eq!(bad_menu.content_gate(), None);
        assert!(!bad_menu.is_valid());
        assert!(bad_menu
            .try_payload_with_source(MenuActionSource::UiaMenu)
            .is_none());
        let fallback_payload = bad_menu.payload_with_source(MenuActionSource::UiaMenu);
        assert_eq!(
            fallback_payload
                .get("gate")
                .and_then(|g| g.get("secure"))
                .and_then(JsonValue::as_str),
            Some("unknown"),
            "invalid menu field_security={bad_sec:?} must NEVER emit gate.secure=\"safe\""
        );
        let env = wrap_observation(
            1_000,
            1_000,
            app_target.to_target_ref(),
            stamp,
            fallback_payload,
        );
        assert!(validator.encode_frame(&env).is_err());
    }

    // 4. Overflow-safe `checked_sub` across `PendingSurrogate`, `InputTextRecord`,
    //    `InputTextAccumulator`, `ImeCompositionState`, `MenuTrackingStateMachine`,
    //    and `MenuActionDeduplicator`.
    let units: Vec<u16> = "\u{1F9EA}".encode_utf16().collect();
    let mut surr = PendingSurrogate::new();
    assert_eq!(surr.push(units[0], i64::MIN), SurrogateAssemblyOutcome::PendingHigh);
    assert!(surr.expire_if_stale(i64::MAX));
    assert!(!surr.has_pending());
    assert_eq!(surr.push(units[0], i64::MAX), SurrogateAssemblyOutcome::PendingHigh);
    assert!(surr.expire_if_stale(i64::MIN));
    assert!(!surr.has_pending());

    let overflow_rec = InputTextRecord {
        context: base_ctx.clone(),
        source: InputTextSource::Win32Unicode,
        event_kind: InputTextKind::Text,
        text: "a".to_string(),
        modifiers: Vec::new(),
        interval_start_ms: i64::MIN,
        interval_end_ms: i64::MAX,
        event_count: 1,
        extra_coverage_reasons: Vec::new(),
    };
    assert!(!overflow_rec.is_valid());

    let mut acc = InputTextAccumulator::default();
    assert_eq!(
        acc.add(
            sample(base_ctx.clone(), InputTextKind::Text, "a", vec![], 1_000),
            InputTextSource::Win32Unicode,
        ),
        None
    );
    assert!(!acc.is_due(i64::MIN));
    assert!(acc.take_due(i64::MIN, Some(&base_ctx)).is_none());
    assert!(acc.pending().is_none());

    // 5. `ImeCompositionState` enforces `IME_COMPOSITION_MAX_MS` from `started_at_ms` as well as
    //    `last_update_ms`, resets cleanly after decay, and handles `i64::MIN`/`i64::MAX` safely.
    let mut ime = ImeCompositionState::new();
    ime.on_composition_start(1_000, &mut acc);
    // Repeated composition updates at t=4_000 cannot extend past t=1_000 + 5_000 = 6_000.
    ime.on_composition_start(4_000, &mut acc);
    assert!(ime.is_composing(6_000));
    assert!(!ime.is_composing(6_001));
    assert!(!ime.should_suppress_raw_key(6_001));
    // Fresh composition start after previous decay cleanly sets new `started_at_ms`.
    ime.on_composition_start(10_000, &mut acc);
    assert!(ime.is_composing(14_999));
    // Extreme timestamps fail closed without overflow panic.
    assert!(!ime.is_composing(i64::MAX));
    assert!(!ime.is_composing(i64::MIN));
    ime.reset();
    ime.on_composition_start(i64::MIN, &mut acc);
    assert!(!ime.is_composing(i64::MAX));

    // 6. `MenuTrackingStateMachine::commit` and `MenuActionDeduplicator::should_emit` overflow & rollback safety.
    let mut sm = MenuTrackingStateMachine::<String, ResolvedMenuPath>::new();
    let p = ResolvedMenuPath {
        path: vec!["File".to_string(), "Save".to_string()],
        truncated: false,
    };
    sm.menu_opened("m1".to_string(), true);
    sm.update_selection(Some(p.clone()), "m1".to_string(), i64::MIN);
    assert!(sm.commit(i64::MAX).is_none());
    sm.update_selection(Some(p), "m1".to_string(), i64::MAX);
    assert!(sm.commit(i64::MIN).is_none());

    let mut dedup = MenuActionDeduplicator::new();
    let path = vec!["File".to_string(), "Save".to_string()];
    assert!(dedup.should_emit(&path, 1_000));
    // Clock rollback fails closed (suppresses duplicate emission).
    assert!(!dedup.should_emit(&path, 999));
    // Overflow / underflow fails closed without panic.
    dedup.reset();
    assert!(dedup.should_emit(&path, i64::MIN));
    assert!(!dedup.should_emit(&path, i64::MAX));
    dedup.reset();
    assert!(dedup.should_emit(&path, i64::MAX));
    assert!(!dedup.should_emit(&path, i64::MIN));
}
