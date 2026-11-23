use access_contract::JsonValue;
use collector_core::desktop::{
    build_permission_response, DesktopAssessment, DesktopBoundaryLatch, DesktopSample,
    InputDesktopState, PermissionAction, WtsLockState,
};
use collector_core::navigation::{
    navigate_source, NavigationApplicationEvidence, NavigationDispatch, NavigationSessionEvidence,
    SourceNavigationOutcome, SourceNavigationProvider, SourceNavigationReason,
    SourceNavigationRequest,
};
use collector_core::protocol_model::{ApplicationIdentity, DesktopStatus};

/// Mirrors `parsePermissionReport(..., 'win32')` invariants from `src/host/service/permissions.ts`.
fn assert_win32_permission_invariants(json: &JsonValue, action: PermissionAction) {
    let obj = json.as_obj().expect("object");
    assert_eq!(obj.len(), 9);
    assert_eq!(obj.get("version").and_then(JsonValue::as_i64), Some(1));
    assert_eq!(
        obj.get("action").and_then(JsonValue::as_str),
        Some(action.as_str())
    );
    assert_eq!(
        obj.get("accessibility").and_then(JsonValue::as_str),
        Some("not-applicable")
    );
    assert_eq!(
        obj.get("screenRecording").and_then(JsonValue::as_str),
        Some("not-required")
    );
    assert_eq!(obj.get("captured").and_then(JsonValue::as_bool), Some(false));
    assert_eq!(
        obj.get("promptRequested").and_then(JsonValue::as_bool),
        Some(action == PermissionAction::RequestAccessibility)
    );
    let im = obj
        .get("inputMonitoring")
        .and_then(JsonValue::as_obj)
        .expect("inputMonitoring");
    assert_eq!(
        im.get("state").and_then(JsonValue::as_str),
        Some("not-applicable")
    );
    assert_eq!(
        im.get("promptRequested").and_then(JsonValue::as_bool),
        Some(action == PermissionAction::RequestInputMonitoring)
    );

    let desktop = obj
        .get("desktop")
        .and_then(JsonValue::as_obj)
        .expect("desktop");
    let status = desktop.get("status").and_then(JsonValue::as_str).unwrap();
    let reason = desktop.get("reason").and_then(JsonValue::as_str).unwrap();
    let lock_source = desktop.get("lockSource").and_then(JsonValue::as_str).unwrap();
    assert!(matches!(lock_source, "wts-session" | "win32-desktop" | "unknown"));
    assert_ne!(reason, "ready-console-compat");

    let screen_locked = desktop.get("screenLocked").and_then(JsonValue::as_bool);
    let locked = screen_locked == Some(true);
    let ready = !locked
        && matches!(lock_source, "wts-session" | "win32-desktop")
        && desktop.get("sessionAvailable").and_then(JsonValue::as_bool) == Some(true)
        && desktop.get("sessionMatchesProcess").and_then(JsonValue::as_bool) == Some(true)
        && desktop.get("sessionStable").and_then(JsonValue::as_bool) == Some(true)
        && desktop.get("signalsValid").and_then(JsonValue::as_bool) == Some(true)
        && desktop.get("lockTransition").and_then(JsonValue::as_bool) == Some(false)
        && screen_locked == Some(false);

    assert_eq!(status == "unlocked", ready);
    assert_eq!(reason == "ready", ready);
    assert_eq!(status == "locked", locked);
    assert_eq!(reason == "screen-locked", locked);
}

#[test]
fn desktop_assessment_upholds_all_win32_permission_invariants() {
    let unlocked_wts = DesktopSample {
        pid_session: Some(1),
        active_console: 1,
        wts_lock: WtsLockState::Unlocked,
        wts_active: Some(true),
        input_desktop: InputDesktopState::Default,
    };
    let unlocked_win32 = DesktopSample {
        pid_session: Some(1),
        active_console: 1,
        wts_lock: WtsLockState::Unknown,
        wts_active: Some(true),
        input_desktop: InputDesktopState::Default,
    };
    let locked_wts = DesktopSample {
        pid_session: Some(1),
        active_console: 1,
        wts_lock: WtsLockState::Locked,
        wts_active: Some(true),
        input_desktop: InputDesktopState::Default,
    };
    let locked_winlogon = DesktopSample {
        pid_session: Some(1),
        active_console: 1,
        wts_lock: WtsLockState::Unknown,
        wts_active: Some(true),
        input_desktop: InputDesktopState::LockedDesktop,
    };
    let active_rdp = DesktopSample {
        pid_session: Some(2),
        active_console: 1,
        wts_lock: WtsLockState::Unlocked,
        wts_active: Some(true),
        input_desktop: InputDesktopState::Default,
    };
    let active_rdp_no_console = DesktopSample {
        pid_session: Some(2),
        active_console: u32::MAX,
        wts_lock: WtsLockState::Unlocked,
        wts_active: Some(true),
        input_desktop: InputDesktopState::Default,
    };
    let rdp_unknown_wts_lock = DesktopSample {
        pid_session: Some(2),
        active_console: 1,
        wts_lock: WtsLockState::Unknown,
        wts_active: Some(true),
        input_desktop: InputDesktopState::Default,
    };
    let rdp_disconnected = DesktopSample {
        pid_session: Some(2),
        active_console: 1,
        wts_lock: WtsLockState::Unlocked,
        wts_active: Some(false),
        input_desktop: InputDesktopState::Default,
    };
    let session_zero = DesktopSample {
        pid_session: Some(0),
        active_console: 1,
        wts_lock: WtsLockState::Unlocked,
        wts_active: Some(true),
        input_desktop: InputDesktopState::Default,
    };
    let other_desktop = DesktopSample {
        pid_session: Some(1),
        active_console: 1,
        wts_lock: WtsLockState::Unlocked,
        wts_active: Some(true),
        input_desktop: InputDesktopState::Other,
    };
    let access_denied = DesktopSample {
        pid_session: Some(1),
        active_console: 1,
        wts_lock: WtsLockState::Unlocked,
        wts_active: Some(true),
        input_desktop: InputDesktopState::AccessDenied,
    };
    let no_session = DesktopSample {
        pid_session: None,
        active_console: u32::MAX,
        wts_lock: WtsLockState::Unknown,
        wts_active: None,
        input_desktop: InputDesktopState::Unavailable,
    };

    let cases = [
        (unlocked_wts, unlocked_wts, DesktopStatus::Unlocked, "ready", "wts-session"),
        (unlocked_win32, unlocked_win32, DesktopStatus::Unlocked, "ready", "win32-desktop"),
        // Active RDP session (WTSActive + UNLOCK + Default desktop, even when pid_session != active_console).
        (active_rdp, active_rdp, DesktopStatus::Unlocked, "ready", "wts-session"),
        (active_rdp_no_console, active_rdp_no_console, DesktopStatus::Unlocked, "ready", "wts-session"),
        // RDP without WTS unlock confirmation fails closed.
        (rdp_unknown_wts_lock, rdp_unknown_wts_lock, DesktopStatus::Unknown, "lock-state-unavailable", "unknown"),
        // Disconnected / inactive WTS session fails closed.
        (rdp_disconnected, rdp_disconnected, DesktopStatus::Unknown, "desktop-signal-invalid", "unknown"),
        // Session 0 (service session) fails closed.
        (session_zero, session_zero, DesktopStatus::Unknown, "session-unavailable", "unknown"),
        // Locked WTS or Winlogon/Screen-saver desktop -> Locked/screen-locked.
        (locked_wts, locked_wts, DesktopStatus::Locked, "screen-locked", "wts-session"),
        (locked_winlogon, locked_winlogon, DesktopStatus::Locked, "screen-locked", "win32-desktop"),
        // Transitions & invalid desktop signals fail closed.
        (unlocked_wts, unlocked_win32, DesktopStatus::Unknown, "desktop-lock-transition", "unknown"),
        (unlocked_wts, active_rdp, DesktopStatus::Unknown, "desktop-session-changed", "wts-session"),
        (other_desktop, other_desktop, DesktopStatus::Unknown, "desktop-signal-invalid", "unknown"),
        (access_denied, access_denied, DesktopStatus::Unknown, "desktop-signal-invalid", "unknown"),
        (no_session, no_session, DesktopStatus::Unknown, "session-unavailable", "unknown"),
    ];

    for (s1, s2, expected_status, expected_reason, expected_source) in cases {
        let assessment = DesktopAssessment::from_samples(s1, s2);
        assert_eq!(assessment.status, expected_status);
        assert_eq!(assessment.reason, expected_reason);
        assert_eq!(assessment.lock_source, expected_source);
        for action in [
            PermissionAction::Check,
            PermissionAction::RequestAccessibility,
            PermissionAction::OpenAccessibilitySettings,
            PermissionAction::RequestInputMonitoring,
            PermissionAction::OpenInputMonitoringSettings,
        ] {
            let resp = build_permission_response(action, &assessment);
            assert_win32_permission_invariants(&resp, action);
        }
    }
}

#[test]
fn desktop_boundary_latch_is_sticky_until_user_action() {
    let mut latch = DesktopBoundaryLatch::new();
    let ok_sample = DesktopSample {
        pid_session: Some(1),
        active_console: 1,
        wts_lock: WtsLockState::Unlocked,
        wts_active: Some(true),
        input_desktop: InputDesktopState::Default,
    };
    let locked_sample = DesktopSample {
        wts_lock: WtsLockState::Locked,
        ..ok_sample
    };
    let unlocked = DesktopAssessment::from_samples(ok_sample, ok_sample);
    let locked = DesktopAssessment::from_samples(locked_sample, locked_sample);

    assert_eq!(latch.observe(&unlocked), DesktopStatus::Unlocked);
    assert_eq!(latch.observe(&locked), DesktopStatus::Locked);
    assert!(latch.is_latched());
    // Remains blocked even after desktop unlocks until explicit user start/resume!
    assert_eq!(latch.observe(&unlocked), DesktopStatus::Unknown);
    latch.reset_for_user_action();
    assert!(!latch.is_latched());
    assert_eq!(latch.observe(&unlocked), DesktopStatus::Unlocked);
}

#[test]
fn source_navigation_request_parsing_strict_validation() {
    let valid = br#"{"version":1,"applicationId":"code.exe","processId":1234,"processStartTime":"unix-ms:1700000100000.000","osSessionId":"wts-1","desktopId":"winsta0-default-wts-1"}"#;
    let parsed = SourceNavigationRequest::parse(valid).expect("valid request");
    assert_eq!(parsed.application_id, "code.exe");
    assert_eq!(parsed.process_id, 1234);
    assert_eq!(parsed.wts_session_id, 1);

    // Oversized input.
    let big = vec![b' '; 2049];
    assert_eq!(
        SourceNavigationRequest::parse(&big),
        Err(SourceNavigationReason::InputTooLarge)
    );

    // Malformed, BOM, duplicate keys, wrong platform session, bad PID, mismatched desktop.
    let invalid_cases: &[&[u8]] = &[
        b"",
        b"\xef\xbb\xbf{\"version\":1,\"applicationId\":\"code.exe\",\"processId\":1234,\"processStartTime\":\"unix-ms:1700000100000.000\",\"osSessionId\":\"wts-1\",\"desktopId\":\"winsta0-default-wts-1\"}",
        br#"{"version":1,"version":1,"applicationId":"code.exe","processId":1234,"processStartTime":"unix-ms:1700000100000.000","osSessionId":"wts-1","desktopId":"winsta0-default-wts-1"}"#,
        br#"{"version":true,"applicationId":"code.exe","processId":1234,"processStartTime":"unix-ms:1700000100000.000","osSessionId":"wts-1","desktopId":"winsta0-default-wts-1"}"#,
        br#"{"version":1,"applicationId":"code.exe","processId":1,"processStartTime":"unix-ms:1700000100000.000","osSessionId":"wts-1","desktopId":"winsta0-default-wts-1"}"#,
        br#"{"version":1,"applicationId":"code.exe","processId":1234,"processStartTime":"unix-ms:01700000100000.000","osSessionId":"wts-1","desktopId":"winsta0-default-wts-1"}"#,
        br#"{"version":1,"applicationId":"code.exe","processId":1234,"processStartTime":"unix-ms:1700000100000.000","osSessionId":"audit-1","desktopId":"console-audit-1"}"#,
        br#"{"version":1,"applicationId":"code.exe","processId":1234,"processStartTime":"unix-ms:1700000100000.000","osSessionId":"wts-01","desktopId":"winsta0-default-wts-01"}"#,
        br#"{"version":1,"applicationId":"code.exe","processId":1234,"processStartTime":"unix-ms:1700000100000.000","osSessionId":"wts-1","desktopId":"winsta0-default-wts-2"}"#,
        br#"{"version":1,"applicationId":"code.exe","processId":1234,"processStartTime":"unix-ms:1700000100000.000","osSessionId":"wts-1","desktopId":"winsta0-default-wts-1"} trailing"#,
    ];
    for case in invalid_cases {
        assert_eq!(
            SourceNavigationRequest::parse(case),
            Err(SourceNavigationReason::InvalidRequest),
            "expected invalid-request for {:?}",
            String::from_utf8_lossy(case)
        );
    }
}

struct MockNavProvider {
    session: NavigationSessionEvidence,
    running: Option<NavigationApplicationEvidence>,
    frontmost: Option<NavigationApplicationEvidence>,
    dispatch: NavigationDispatch,
}

impl SourceNavigationProvider for MockNavProvider {
    fn session_evidence(&self) -> NavigationSessionEvidence {
        self.session.clone()
    }
    fn running_application(&self, _process_id: u32) -> Option<NavigationApplicationEvidence> {
        self.running.clone()
    }
    fn activate(
        &self,
        _request: &SourceNavigationRequest,
        mark_dispatched: &dyn Fn() -> Option<SourceNavigationReason>,
    ) -> NavigationDispatch {
        if let Some(reason) = mark_dispatched() {
            return NavigationDispatch::NotDispatched(reason);
        }
        self.dispatch
    }
    fn frontmost_application(&self) -> Option<NavigationApplicationEvidence> {
        self.frontmost.clone()
    }
}

#[test]
fn source_navigation_gating_and_receipt_outcomes() {
    let req = SourceNavigationRequest::parse(
        br#"{"version":1,"applicationId":"code.exe","processId":4242,"processStartTime":"unix-ms:1700000100000.000","osSessionId":"wts-1","desktopId":"winsta0-default-wts-1"}"#,
    )
    .unwrap();
    let good_app = NavigationApplicationEvidence {
        identity: ApplicationIdentity {
            application_id: "code.exe".to_string(),
            process_id: 4242,
            process_start_time: "unix-ms:1700000100000.000".to_string(),
        },
        permitted_non_browser: true,
    };

    // Happy path: activated -> exit 0.
    let ok_provider = MockNavProvider {
        session: NavigationSessionEvidence {
            current_wts_session_id: Some(1),
            desktop: DesktopStatus::Unlocked,
        },
        running: Some(good_app.clone()),
        frontmost: Some(good_app.clone()),
        dispatch: NavigationDispatch::Submitted { accepted: true },
    };
    let r = navigate_source(&req, &ok_provider, &|| None);
    assert_eq!(r.outcome, SourceNavigationOutcome::Activated);
    assert_eq!(r.reason, SourceNavigationReason::Activated);
    assert_eq!(r.exit_code(), 0);

    // Blocked app (browser / excluded) -> refused, exit 0.
    let blocked_provider = MockNavProvider {
        running: Some(NavigationApplicationEvidence {
            permitted_non_browser: false,
            ..good_app.clone()
        }),
        ..ok_provider
    };
    let r_blocked = navigate_source(&req, &blocked_provider, &|| None);
    assert_eq!(r_blocked.outcome, SourceNavigationOutcome::Refused);
    assert_eq!(r_blocked.reason, SourceNavigationReason::ApplicationBlocked);
    assert_eq!(r_blocked.exit_code(), 0);

    // Activation rejected -> uncertain, exit 0.
    let rejected_provider = MockNavProvider {
        session: NavigationSessionEvidence {
            current_wts_session_id: Some(1),
            desktop: DesktopStatus::Unlocked,
        },
        running: Some(good_app.clone()),
        frontmost: Some(good_app),
        dispatch: NavigationDispatch::Submitted { accepted: false },
    };
    let r_rej = navigate_source(&req, &rejected_provider, &|| None);
    assert_eq!(r_rej.outcome, SourceNavigationOutcome::Uncertain);
    assert_eq!(r_rej.reason, SourceNavigationReason::ActivationRejected);
    assert_eq!(r_rej.exit_code(), 0);
}
