use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use history_contract::JsonValue;
use collector_core::desktop::{
    build_permission_response, DesktopAssessment, DesktopBoundaryLatch, DesktopSample,
    InputDesktopState, PermissionAction, WtsLockState,
};
use collector_core::navigation::{
    gate_application, gate_session, navigate_source, window_matches_target_pid,
    NavigationApplicationEvidence, NavigationDispatch, NavigationSessionEvidence,
    SourceNavigationOutcome, SourceNavigationProvider, SourceNavigationReason,
    SourceNavigationReceipt, SourceNavigationRequest, SourceNavigationWatchdog,
};
use collector_core::ownership::{
    is_pid_alive, is_valid_parent_creation_time, is_wait_status_alive, parent_pid,
    ParentProcessHandle,
};
use collector_core::policy::ResolvedAppIdentity;
use collector_core::protocol_model::{ApplicationIdentity, DesktopStatus};
use windows::Win32::Foundation::{
    DuplicateHandle, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
};

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
    let good_app = NavigationApplicationEvidence::new(
        ApplicationIdentity {
            application_id: "code.exe".to_string(),
            process_id: 4242,
            process_start_time: "unix-ms:1700000100000.000".to_string(),
        },
        true,
    );

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

#[test]
fn desktop_boundary_latch_latches_on_access_denied_and_session_mismatch_after_unlocked() {
    let ok_sample = DesktopSample {
        pid_session: Some(1),
        active_console: 1,
        wts_lock: WtsLockState::Unlocked,
        wts_active: Some(true),
        input_desktop: InputDesktopState::Default,
    };
    let access_denied_sample = DesktopSample {
        pid_session: Some(1),
        active_console: 1,
        wts_lock: WtsLockState::Unknown,
        wts_active: Some(true),
        input_desktop: InputDesktopState::AccessDenied,
    };
    let rdp_disconnected_sample = DesktopSample {
        pid_session: Some(2),
        active_console: 1,
        wts_lock: WtsLockState::Unlocked,
        wts_active: Some(false),
        input_desktop: InputDesktopState::Default,
    };
    let startup_unknown_sample = DesktopSample {
        pid_session: Some(2),
        active_console: 1,
        wts_lock: WtsLockState::Unknown,
        wts_active: Some(true),
        input_desktop: InputDesktopState::Default,
    };

    let unlocked = DesktopAssessment::from_samples(ok_sample, ok_sample);
    let access_denied = DesktopAssessment::from_samples(access_denied_sample, access_denied_sample);
    assert_eq!(access_denied.status, DesktopStatus::Unknown);
    assert!(access_denied.session_available);
    assert!(!access_denied.lock_transition);

    let rdp_disconnected =
        DesktopAssessment::from_samples(rdp_disconnected_sample, rdp_disconnected_sample);
    assert_eq!(rdp_disconnected.status, DesktopStatus::Unknown);
    assert!(!rdp_disconnected.session_matches_process);

    let startup_unknown =
        DesktopAssessment::from_samples(startup_unknown_sample, startup_unknown_sample);
    assert_eq!(startup_unknown.status, DesktopStatus::Unknown);
    assert!(startup_unknown.session_available);
    assert!(!startup_unknown.lock_transition);

    // Case 1: Unlocked -> Unknown (ERROR_ACCESS_DENIED, session_available=true, lock_transition=false)
    // -> Unknown -> Unlocked MUST latch and stay latched until explicit reset!
    let mut latch = DesktopBoundaryLatch::new();
    assert_eq!(latch.observe(&unlocked), DesktopStatus::Unlocked);
    assert!(!latch.is_latched());
    assert_eq!(latch.observe(&access_denied), DesktopStatus::Unknown);
    assert!(latch.is_latched());
    assert_eq!(latch.observe(&access_denied), DesktopStatus::Unknown);
    assert_eq!(latch.observe(&unlocked), DesktopStatus::Unknown);
    assert!(latch.is_latched());
    latch.reset_for_user_action();
    assert!(!latch.is_latched());
    assert_eq!(latch.observe(&unlocked), DesktopStatus::Unlocked);

    // Case 2: Unlocked -> session_matches_process=false (RDP disconnect / fast-user-switch)
    // -> Unlocked MUST latch and stay latched until explicit reset!
    let mut latch2 = DesktopBoundaryLatch::new();
    assert_eq!(latch2.observe(&unlocked), DesktopStatus::Unlocked);
    assert_eq!(latch2.observe(&rdp_disconnected), DesktopStatus::Unknown);
    assert!(latch2.is_latched());
    assert_eq!(latch2.observe(&unlocked), DesktopStatus::Unknown);
    latch2.reset_for_user_action();
    assert!(!latch2.is_latched());
    assert_eq!(latch2.observe(&unlocked), DesktopStatus::Unlocked);

    // Case 3: Initial Unknown before ever observing Unlocked does not spuriously latch when
    // session_available, session_matches_process, and signals_valid all hold (lock-state-unavailable).
    let mut latch3 = DesktopBoundaryLatch::new();
    assert_eq!(latch3.observe(&startup_unknown), DesktopStatus::Unknown);
    assert!(!latch3.is_latched());
    assert_eq!(latch3.observe(&unlocked), DesktopStatus::Unlocked);
    assert!(!latch3.is_latched());
}

#[test]
fn desktop_boundary_latch_latches_immediately_on_initial_disconnected_or_invalid_signals() {
    let ok_sample = DesktopSample {
        pid_session: Some(1),
        active_console: 1,
        wts_lock: WtsLockState::Unlocked,
        wts_active: Some(true),
        input_desktop: InputDesktopState::Default,
    };
    let rdp_disconnected_sample = DesktopSample {
        pid_session: Some(2),
        active_console: 1,
        wts_lock: WtsLockState::Unlocked,
        wts_active: Some(false),
        input_desktop: InputDesktopState::Default,
    };
    let console_mismatch_sample = DesktopSample {
        pid_session: Some(2),
        active_console: 1,
        wts_lock: WtsLockState::Unknown,
        wts_active: None,
        input_desktop: InputDesktopState::Default,
    };
    let invalid_other_desktop_sample = DesktopSample {
        pid_session: Some(1),
        active_console: 1,
        wts_lock: WtsLockState::Unlocked,
        wts_active: Some(true),
        input_desktop: InputDesktopState::Other,
    };

    let unlocked = DesktopAssessment::from_samples(ok_sample, ok_sample);
    let rdp_disconnected =
        DesktopAssessment::from_samples(rdp_disconnected_sample, rdp_disconnected_sample);
    let console_mismatch =
        DesktopAssessment::from_samples(console_mismatch_sample, console_mismatch_sample);
    let invalid_other_desktop = DesktopAssessment::from_samples(
        invalid_other_desktop_sample,
        invalid_other_desktop_sample,
    );

    assert!(!rdp_disconnected.session_matches_process && !rdp_disconnected.signals_valid);
    assert!(!console_mismatch.session_matches_process && console_mismatch.signals_valid);
    assert!(invalid_other_desktop.session_matches_process && !invalid_other_desktop.signals_valid);

    for (label, initial) in [
        ("rdp-disconnected", &rdp_disconnected),
        ("console-session-mismatch", &console_mismatch),
        ("invalid-other-desktop", &invalid_other_desktop),
    ] {
        let mut latch = DesktopBoundaryLatch::new();
        assert_eq!(latch.observe(initial), DesktopStatus::Unknown, "{label}");
        assert!(
            latch.is_latched(),
            "initial {label} startup MUST latch immediately"
        );
        // Must stay latched even if desktop later reports Unlocked, until explicit user reset!
        assert_eq!(latch.observe(&unlocked), DesktopStatus::Unknown, "{label}");
        assert!(latch.is_latched(), "{label}");
        latch.reset_for_user_action();
        assert!(!latch.is_latched(), "{label}");
        assert_eq!(latch.observe(&unlocked), DesktopStatus::Unlocked, "{label}");
    }
}

#[test]
fn gate_session_fails_closed_and_navigation_enforces_dual_id_and_afh_non_splicing() {
    let req = SourceNavigationRequest::parse(
        br#"{"version":1,"applicationId":"code.exe","processId":4242,"processStartTime":"unix-ms:1700000100000.000","osSessionId":"wts-1","desktopId":"winsta0-default-wts-1"}"#,
    )
    .unwrap();

    // P2: gate_session MUST fail closed when current_wts_session_id is None!
    assert_eq!(
        gate_session(
            &req,
            &NavigationSessionEvidence {
                current_wts_session_id: None,
                desktop: DesktopStatus::Unlocked,
            }
        ),
        Some(SourceNavigationReason::SessionUnavailable)
    );
    assert_eq!(
        gate_session(
            &req,
            &NavigationSessionEvidence {
                current_wts_session_id: Some(2),
                desktop: DesktopStatus::Unlocked,
            }
        ),
        Some(SourceNavigationReason::SessionMismatch)
    );
    assert_eq!(
        gate_session(
            &req,
            &NavigationSessionEvidence {
                current_wts_session_id: Some(1),
                desktop: DesktopStatus::Locked,
            }
        ),
        Some(SourceNavigationReason::DesktopUnavailable)
    );
    assert_eq!(
        gate_session(
            &req,
            &NavigationSessionEvidence {
                current_wts_session_id: Some(1),
                desktop: DesktopStatus::Unlocked,
            }
        ),
        None
    );

    // P0-2: Dual-ID navigation blocks Store Bitwarden, MSIX Arc, and AppX System UI even when
    // request names the MSIX package ID.
    let bw_req = SourceNavigationRequest::parse(
        br#"{"version":1,"applicationId":"8bitsolutionsllc.bitwardendesktop","processId":500,"processStartTime":"unix-ms:1700000100000.000","osSessionId":"wts-1","desktopId":"winsta0-default-wts-1"}"#,
    )
    .unwrap();
    let bw_resolved = ResolvedAppIdentity::from_parts(
        Some("8bitsolutionsllc.bitwardendesktop".to_string()),
        Some("bitwarden.exe".to_string()),
    )
    .unwrap();
    let bw_ev = NavigationApplicationEvidence::with_resolved(
        ApplicationIdentity {
            application_id: bw_resolved.application_id.clone(),
            process_id: 500,
            process_start_time: "unix-ms:1700000100000.000".to_string(),
        },
        true, // Even if a caller mistakenly sets permitted_non_browser=true, dual-ID gate blocks!
        bw_resolved,
    );
    assert_eq!(
        gate_application(&bw_req, Some(&bw_ev)),
        Some(SourceNavigationReason::ApplicationBlocked)
    );

    let arc_req = SourceNavigationRequest::parse(
        br#"{"version":1,"applicationId":"thebrowsercompany.arc","processId":501,"processStartTime":"unix-ms:1700000100000.000","osSessionId":"wts-1","desktopId":"winsta0-default-wts-1"}"#,
    )
    .unwrap();
    let arc_resolved = ResolvedAppIdentity::from_parts(
        Some("thebrowsercompany.arc".to_string()),
        Some("arc.exe".to_string()),
    )
    .unwrap();
    let arc_ev = NavigationApplicationEvidence::with_resolved(
        ApplicationIdentity {
            application_id: arc_resolved.application_id.clone(),
            process_id: 501,
            process_start_time: "unix-ms:1700000100000.000".to_string(),
        },
        true,
        arc_resolved,
    );
    assert_eq!(
        gate_application(&arc_req, Some(&arc_ev)),
        Some(SourceNavigationReason::ApplicationBlocked)
    );

    // Permitted MSIX app matches cleanly by package name or exe name.
    let wt_req = SourceNavigationRequest::parse(
        br#"{"version":1,"applicationId":"microsoft.windowsterminal","processId":502,"processStartTime":"unix-ms:1700000100000.000","osSessionId":"wts-1","desktopId":"winsta0-default-wts-1"}"#,
    )
    .unwrap();
    let wt_resolved = ResolvedAppIdentity::from_parts(
        Some("microsoft.windowsterminal".to_string()),
        Some("windowsterminal.exe".to_string()),
    )
    .unwrap();
    let wt_ev = NavigationApplicationEvidence::with_resolved(
        ApplicationIdentity {
            application_id: wt_resolved.application_id.clone(),
            process_id: 502,
            process_start_time: "unix-ms:1700000100000.000".to_string(),
        },
        true,
        wt_resolved,
    );
    assert_eq!(gate_application(&wt_req, Some(&wt_ev)), None);

    // P0-3 / P1-9: AFH cross-PID non-splicing helper matches strictly on unwrapped effective PID.
    assert!(window_matches_target_pid(Some(1200), 1200));
    assert!(!window_matches_target_pid(Some(1200), 900));
    assert!(!window_matches_target_pid(None, 900));
    assert!(!window_matches_target_pid(None, 1200));
    assert!(!window_matches_target_pid(Some(1), 1));
    assert!(!window_matches_target_pid(Some(0), 0));
}

#[test]
fn source_navigation_watchdog_mutex_prevents_double_emit_and_post_timeout_dispatch() {
    // 1. Timeout wins BEFORE dispatch -> emits Refused; subsequent dispatch & emit are blocked.
    let dog1 = SourceNavigationWatchdog::new(1_000);
    let first = dog1.claim_and_emit(
        |after_dispatch| {
            assert!(!after_dispatch);
            SourceNavigationReceipt::new(SourceNavigationReason::DeadlineExceeded, after_dispatch)
        },
        |receipt| receipt,
    );
    assert_eq!(
        first,
        Some(SourceNavigationReceipt {
            outcome: SourceNavigationOutcome::Refused,
            reason: SourceNavigationReason::DeadlineExceeded,
        })
    );
    assert!(dog1.is_finished());
    // Dispatch after timeout refusal MUST be rejected!
    assert_eq!(
        dog1.try_mark_dispatched(true, 500),
        Some(SourceNavigationReason::DeadlineExceeded)
    );
    // Second emit MUST return None (no duplicate stdout line)!
    assert_eq!(
        dog1.claim_and_emit(
            |after_dispatch| SourceNavigationReceipt::new(
                SourceNavigationReason::Activated,
                after_dispatch
            ),
            |receipt| receipt
        ),
        None
    );

    // 2. Dispatch succeeds BEFORE timeout -> timeout emits Uncertain; main thread cannot double-emit.
    let dog2 = SourceNavigationWatchdog::new(1_000);
    assert_eq!(dog2.try_mark_dispatched(true, 500), None);
    let timed_out = dog2.claim_and_emit(
        |after_dispatch| {
            assert!(after_dispatch);
            SourceNavigationReceipt::new(SourceNavigationReason::DeadlineExceeded, after_dispatch)
        },
        |receipt| receipt,
    );
    assert_eq!(
        timed_out,
        Some(SourceNavigationReceipt {
            outcome: SourceNavigationOutcome::Uncertain,
            reason: SourceNavigationReason::DeadlineExceeded,
        })
    );
    assert_eq!(
        dog2.claim_and_emit(
            |after_dispatch| SourceNavigationReceipt::new(
                SourceNavigationReason::Activated,
                after_dispatch
            ),
            |receipt| receipt
        ),
        None
    );

    // 3. Concurrent contention across threads guarantees exactly one receipt and never dispatches
    // after a Refused receipt.
    for _ in 0..16 {
        let dog = Arc::new(SourceNavigationWatchdog::new(1_000));
        let emit_count = Arc::new(AtomicUsize::new(0));
        let refused_emitted = Arc::new(AtomicBool::new(false));
        let dispatch_after_refusal = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::new();

        for i in 0..8 {
            let d = Arc::clone(&dog);
            let count = Arc::clone(&emit_count);
            let refused = Arc::clone(&refused_emitted);
            let bad_dispatch = Arc::clone(&dispatch_after_refusal);
            handles.push(thread::spawn(move || {
                if i % 2 == 0 {
                    if d.try_mark_dispatched(true, 500).is_none()
                        && refused.load(Ordering::Acquire)
                    {
                        bad_dispatch.store(true, Ordering::Release);
                    }
                    let _ = d.claim_and_emit(
                        |after_dispatch| {
                            SourceNavigationReceipt::new(
                                SourceNavigationReason::Activated,
                                after_dispatch,
                            )
                        },
                        |receipt| {
                            count.fetch_add(1, Ordering::AcqRel);
                            if receipt.outcome == SourceNavigationOutcome::Refused {
                                refused.store(true, Ordering::Release);
                            }
                        },
                    );
                } else {
                    let _ = d.claim_and_emit(
                        |after_dispatch| {
                            SourceNavigationReceipt::new(
                                SourceNavigationReason::DeadlineExceeded,
                                after_dispatch,
                            )
                        },
                        |receipt| {
                            if receipt.outcome == SourceNavigationOutcome::Refused {
                                refused.store(true, Ordering::Release);
                            }
                            count.fetch_add(1, Ordering::AcqRel);
                        },
                    );
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(emit_count.load(Ordering::Acquire), 1);
        assert!(!dispatch_after_refusal.load(Ordering::Acquire));
    }
}

#[test]
fn parent_process_handle_verifies_creation_time_and_handles_wait_failed() {
    // Pure WAIT_EVENT and creation-time invariants.
    assert!(is_wait_status_alive(WAIT_TIMEOUT));
    assert!(!is_wait_status_alive(WAIT_OBJECT_0));
    assert!(!is_wait_status_alive(WAIT_FAILED));

    assert!(is_valid_parent_creation_time(100, 200));
    assert!(is_valid_parent_creation_time(100, 100));
    assert!(!is_valid_parent_creation_time(201, 200));
    assert!(!is_valid_parent_creation_time(0, 200));
    assert!(!is_valid_parent_creation_time(100, 0));

    // Invalid handles fail closed in from_inherited_handle.
    assert!(ParentProcessHandle::from_inherited_handle(0).is_none());
    assert!(ParentProcessHandle::from_inherited_handle(-1).is_none());
    assert!(ParentProcessHandle::from_inherited_handle(0x7FFF_1234).is_none());
    assert!(ParentProcessHandle::open(0).is_none());
    assert!(ParentProcessHandle::open(1).is_none());

    // Actual live parent process (cargo test harness) opens and verifies alive.
    if let Some(ppid) = parent_pid() {
        let parent = ParentProcessHandle::open(ppid).expect("live parent handle opens");
        assert_eq!(parent.pid(), ppid);
        assert!(parent.is_alive());
    }

    // Inherited duplicated handle for current process (creation_time == self_creation_time) succeeds.
    let mut dup_self = HANDLE::default();
    let dup_ok = unsafe {
        let cur = GetCurrentProcess();
        DuplicateHandle(
            cur,
            cur,
            cur,
            &mut dup_self,
            (PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION).0,
            false,
            Default::default(),
        )
        .is_ok()
    };
    assert!(dup_ok);
    let adopted = ParentProcessHandle::from_inherited_handle(dup_self.0 as isize)
        .expect("duplicated valid process handle adopted");
    assert_eq!(adopted.pid(), std::process::id());
    assert!(adopted.is_alive());
    drop(adopted);

    // PID-reuse protection: a freshly spawned child process has creation_time > self_creation_time,
    // so BOTH `ParentProcessHandle::open(child_pid)` and `from_inherited_handle(child_handle)` MUST
    // reject it and return None!
    thread::sleep(Duration::from_millis(25));
    let mut child = Command::new("findstr.exe")
        .arg("never-matches")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn helper child process");
    let child_pid = child.id();
    assert!(is_pid_alive(child_pid));
    assert!(
        ParentProcessHandle::open(child_pid).is_none(),
        "newer child process must be rejected as a recycled parent PID"
    );

    if let Ok(child_handle) = unsafe {
        OpenProcess(
            PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            false,
            child_pid,
        )
    } {
        assert!(
            ParentProcessHandle::from_inherited_handle(child_handle.0 as isize).is_none(),
            "newer child handle must be rejected by from_inherited_handle"
        );
    }

    let _ = child.kill();
    let _ = child.wait();
}
