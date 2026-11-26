use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI64, Ordering};
use std::thread;
use std::time::Duration;

use history_contract::{ContractValidator, JsonValue, ProtocolError};
use collector_core::engine::{
    CollectorEngine, CollectorEnvironment, EngineOutput, EnvironmentPollEvents, MonitoringCheck,
};
use collector_core::fixture::execute_fixture_read;
use collector_core::input_activity_win32::{RawInputNotice, VerifiedNormalBrowserWindow};
use collector_core::input_text_core::{
    InputTextContext, InputTextGapReason, InputTextGapRecord, InputTextKind, InputTextModifier,
    InputTextPrivateState, InputTextRecord, InputTextSource,
};
use collector_core::menu_action_core::MenuActionRecord;
use collector_core::ownership::is_pid_alive;
use collector_core::policy::ResolvedAppIdentity;
use collector_core::protocol_model::{
    generate_uuid_v4, hello_message, json_i64, ApplicationIdentity, CapturePolicy, CollectorClock,
    DesktopStatus, GapDiagnostic, GapDiagnosticCode, InputActivityCategory, InputActivitySample,
    SecureStatus, SelectionReadResult, SourceHint, Stamp, SurfaceBounds, SurfaceGeometry,
    SurfaceNode, SurfaceReadFailure, SurfaceReadResult, SurfaceWindowSize, SystemCollectorClock,
    TargetIdentity, TextRead, WorkerSurfaceIdentity,
};
use collector_core::transport::{BoundedOutput, EnqueueError};
use collector_core::worker_ipc::{
    classify_retiring_session_frame, classify_session_pipe_batch,
    classify_worker_pipe_termination, encode_menu_action_pipe_frame,
    encode_read_result_pipe_frame, next_session_unsolicited_frame, split_worker_pipe_frames,
    JobWorkerSupervisor, ReadResult, ReadTicket, ReadTimeoutCleanup, RetiringFrameOutcome,
    SessionBatchPrecedence, WorkerEvent, WORKER_MAX_FRAME_BYTES,
};

struct MockClock {
    mono: AtomicI64,
    unix: AtomicI64,
}

impl MockClock {
    fn new(mono: i64, unix: i64) -> Self {
        Self {
            mono: AtomicI64::new(mono),
            unix: AtomicI64::new(unix),
        }
    }

    fn advance(&self, delta_ms: i64) {
        self.mono.fetch_add(delta_ms, Ordering::SeqCst);
        self.unix.fetch_add(delta_ms, Ordering::SeqCst);
    }
}

impl CollectorClock for MockClock {
    fn monotonic_ms(&self) -> i64 {
        self.mono.load(Ordering::SeqCst)
    }

    fn unix_ms(&self) -> i64 {
        self.unix.load(Ordering::SeqCst)
    }
}

struct MockEnv {
    desktop: DesktopStatus,
    desktop_reason: String,
    accessibility_override: Option<bool>,
    secure_input_blocked: bool,
    input_monitoring_granted: bool,
    ready_override: Option<bool>,
    launched: Vec<ReadTicket>,
    aborted: Vec<ReadTicket>,
    cancelled: usize,
    begin_calls: usize,
    validation_calls: usize,
    cancel_cleanup: ReadTimeoutCleanup,
    abort_cleanup: Option<ReadTimeoutCleanup>,
    last_cleanup: ReadTimeoutCleanup,
    poll_events: Vec<WorkerEvent>,
    poll_notices: Vec<RawInputNotice>,
    poll_cleanup: Option<ReadTimeoutCleanup>,
    input_activity_started: bool,
    input_activity_healthy: bool,
    input_activity_begins: usize,
    input_activity_ends: usize,
    input_activity_clears: usize,
    validate_activity_ok: bool,
    verified_normal_browser: Option<VerifiedNormalBrowserWindow>,
}

impl MockEnv {
    fn unlocked() -> Self {
        Self {
            desktop: DesktopStatus::Unlocked,
            desktop_reason: "ready".to_string(),
            accessibility_override: None,
            secure_input_blocked: false,
            input_monitoring_granted: true,
            ready_override: None,
            launched: Vec::new(),
            aborted: Vec::new(),
            cancelled: 0,
            begin_calls: 0,
            validation_calls: 0,
            cancel_cleanup: ReadTimeoutCleanup::Reaped,
            abort_cleanup: None,
            last_cleanup: ReadTimeoutCleanup::Ineligible,
            poll_events: Vec::new(),
            poll_notices: Vec::new(),
            poll_cleanup: None,
            input_activity_started: false,
            input_activity_healthy: true,
            input_activity_begins: 0,
            input_activity_ends: 0,
            input_activity_clears: 0,
            validate_activity_ok: true,
            verified_normal_browser: None,
        }
    }
}

impl CollectorEnvironment for MockEnv {
    fn desktop_reason(&self) -> &str {
        &self.desktop_reason
    }
    fn secure_input_blocked(&self) -> bool {
        self.secure_input_blocked
    }
    fn begin_monitoring(&mut self) -> MonitoringCheck {
        self.begin_calls += 1;
        MonitoringCheck {
            desktop: self.desktop,
            accessibility: self
                .accessibility_override
                .unwrap_or(self.desktop == DesktopStatus::Unlocked),
        }
    }
    fn validate_before_accept(&mut self) -> MonitoringCheck {
        self.validation_calls += 1;
        MonitoringCheck {
            desktop: self.desktop,
            accessibility: self
                .accessibility_override
                .unwrap_or(self.desktop == DesktopStatus::Unlocked),
        }
    }
    fn end_monitoring(&mut self) {
        self.input_activity_started = false;
        self.verified_normal_browser = None;
    }
    fn input_monitoring_granted(&self) -> bool {
        self.input_monitoring_granted
    }
    fn input_activity_healthy(&self) -> bool {
        self.input_activity_healthy
    }
    fn begin_input_activity(&mut self, policy: &CapturePolicy) -> bool {
        self.input_activity_started = policy.input_activity == Some(true);
        if self.input_activity_started {
            self.input_activity_begins += 1;
        }
        self.input_activity_started
    }
    fn end_input_activity(&mut self) {
        if self.input_activity_started {
            self.input_activity_ends += 1;
        }
        self.input_activity_started = false;
        self.verified_normal_browser = None;
    }
    fn clear_input_activity(&mut self) {
        self.input_activity_clears += 1;
        self.verified_normal_browser = None;
    }
    fn set_verified_normal_browser(&mut self, verified: Option<VerifiedNormalBrowserWindow>) {
        self.verified_normal_browser = verified.filter(VerifiedNormalBrowserWindow::is_valid);
    }
    fn clear_verified_normal_browser(&mut self) {
        self.verified_normal_browser = None;
    }
    fn has_verified_normal_browser(&self, application: &ApplicationIdentity) -> Option<bool> {
        Some(
            self.verified_normal_browser
                .as_ref()
                .is_some_and(|tok| {
                    tok.matches_app(application.process_id, &application.process_start_time)
                }),
        )
    }
    fn validate_input_activity(&mut self, _application: &ApplicationIdentity) -> bool {
        self.validate_activity_ok && self.input_activity_started && self.input_activity_healthy
    }
    fn launch(&mut self, ticket: ReadTicket) -> Option<WorkerEvent> {
        self.launched.push(ticket);
        None
    }
    fn cancel_read(&mut self) -> ReadTimeoutCleanup {
        self.cancelled += 1;
        if self.cancel_cleanup == ReadTimeoutCleanup::Unconfirmed {
            self.last_cleanup = ReadTimeoutCleanup::Unconfirmed;
        }
        self.cancel_cleanup
    }
    fn abort_timed_out_read(&mut self, ticket: &ReadTicket) -> ReadTimeoutCleanup {
        self.aborted.push(ticket.clone());
        self.abort_cleanup.unwrap_or(self.last_cleanup)
    }
    fn timed_out_read_cleanup(&self) -> ReadTimeoutCleanup {
        self.last_cleanup
    }
    fn ready_for_read(&self) -> bool {
        self.ready_override
            .unwrap_or(self.last_cleanup != ReadTimeoutCleanup::Unconfirmed)
    }
    fn poll(&mut self) -> EnvironmentPollEvents {
        if let Some(cleanup) = self.poll_cleanup.take() {
            self.last_cleanup = cleanup;
        }
        EnvironmentPollEvents {
            worker_events: std::mem::take(&mut self.poll_events),
            desktop_change: None,
            input_samples: Vec::new(),
            input_notices: std::mem::take(&mut self.poll_notices),
            ..EnvironmentPollEvents::default()
        }
    }
}

fn configure_msg(owner: &str, inst: &str, rev: i64, policy: &CapturePolicy) -> JsonValue {
    let mut map = BTreeMap::new();
    map.insert("protocolVersion".to_string(), json_i64(1));
    map.insert("type".to_string(), JsonValue::String("configure".to_string()));
    map.insert("requestId".to_string(), JsonValue::String(format!("cfg-{rev}")));
    map.insert("ownerId".to_string(), JsonValue::String(owner.to_string()));
    map.insert("instanceId".to_string(), JsonValue::String(inst.to_string()));
    map.insert("policyRevision".to_string(), json_i64(rev));
    map.insert("policy".to_string(), policy.to_json());
    JsonValue::Object(map)
}

fn control_msg(owner: &str, inst: &str, rev: i64, cmd: &str, lease_ms: i64) -> JsonValue {
    let mut map = BTreeMap::new();
    map.insert("protocolVersion".to_string(), json_i64(1));
    map.insert("type".to_string(), JsonValue::String("control".to_string()));
    map.insert("requestId".to_string(), JsonValue::String(format!("ctl-{cmd}-{rev}")));
    map.insert("ownerId".to_string(), JsonValue::String(owner.to_string()));
    map.insert("instanceId".to_string(), JsonValue::String(inst.to_string()));
    map.insert("policyRevision".to_string(), json_i64(rev));
    map.insert("command".to_string(), JsonValue::String(cmd.to_string()));
    map.insert("leaseDurationMs".to_string(), json_i64(lease_ms));
    JsonValue::Object(map)
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
fn engine_lifecycle_epoch_fencing_dedup_and_blank_suppression() {
    let validator = ContractValidator::new().unwrap();
    let clock = MockClock::new(10_000, 1_700_000_000_000);
    let mut engine = CollectorEngine::new(
        "owner-1",
        "inst-1",
        "dev-1",
        "wts-1",
        "winsta0-default-wts-1",
        true,
        MockEnv::unlocked(),
        clock,
        validator.clone(),
    );

    let policy = CapturePolicy {
        enabled: true,
        allowed_application_ids: vec!["test.allowed".to_string()],
        max_text_code_units: 512,
        debounce_ms: 10,
        max_wait_ms: 50,
        read_timeout_ms: 200,
        ..CapturePolicy::default()
    };

    // Configure revision 1 -> ready.
    engine.receive(&configure_msg("owner-1", "inst-1", 1, &policy));
    let msgs = emitted_messages(engine.drain_outputs());
    assert_eq!(msgs[0].get("type").and_then(JsonValue::as_str), Some("configured"));
    assert_eq!(msgs[1].get("state").and_then(JsonValue::as_str), Some("ready"));
    for m in &msgs {
        validator.validate_message(m).expect("valid wire frame");
    }

    // Stale configure revision 1 rejected.
    engine.receive(&configure_msg("owner-1", "inst-1", 1, &policy));
    let stale_msgs = emitted_messages(engine.drain_outputs());
    assert_eq!(stale_msgs[0].get("code").and_then(JsonValue::as_str), Some("stale"));

    // Start -> running, schedules read.
    engine.receive(&control_msg("owner-1", "inst-1", 1, "start", 5_000));
    let _ = engine.drain_outputs();
    assert_eq!(engine.state(), "running");
    let epoch1 = engine.capture_epoch();

    // Advance past debounce/maxWait and tick -> launches read ticket.
    engine.clock.advance(60);
    engine.tick(true);
    let ticket1 = engine.environment.launched.pop().expect("ticket launched");

    // Complete with initial blank text -> context.changed ONLY, blank text.snapshot suppressed!
    let empty_res = execute_fixture_read("empty", &ticket1, &engine.clock);
    engine.complete(empty_res);
    let out_empty = emitted_messages(engine.drain_outputs());
    assert!(out_empty
        .iter()
        .any(|m| m.get("payload").and_then(|p| p.get("kind")).and_then(JsonValue::as_str)
            == Some("context.changed")));
    assert!(!out_empty
        .iter()
        .any(|m| m.get("payload").and_then(|p| p.get("kind")).and_then(JsonValue::as_str)
            == Some("text.snapshot")));

    // Pause -> repeated start MUST NOT clear user_paused; explicit resume increments epoch!
    engine.receive(&control_msg("owner-1", "inst-1", 1, "pause", 5_000));
    let _ = engine.drain_outputs();
    assert_eq!(engine.state(), "paused");

    engine.receive(&control_msg("owner-1", "inst-1", 1, "start", 5_000));
    let _ = engine.drain_outputs();
    assert_eq!(engine.state(), "paused");

    engine.receive(&control_msg("owner-1", "inst-1", 1, "resume", 5_000));
    let _ = engine.drain_outputs();
    assert_eq!(engine.state(), "running");
    assert!(engine.capture_epoch() > epoch1);

    // Lease expiration stops engine cleanly.
    engine.clock.advance(6_000);
    engine.tick(true);
    assert!(engine.should_exit());
    assert_eq!(engine.state(), "stopped");
}

#[test]
fn engine_promotes_surface_diff_to_full_when_base_revision_skipped() {
    let validator = ContractValidator::new().unwrap();
    let clock = MockClock::new(10_000, 1_700_000_000_000);
    let mut engine = CollectorEngine::new(
        "owner-1",
        "inst-1",
        "dev-1",
        "wts-1",
        "winsta0-default-wts-1",
        false,
        MockEnv::unlocked(),
        clock,
        validator.clone(),
    );

    let policy = CapturePolicy {
        enabled: true,
        allowed_application_ids: vec!["code.exe".to_string()],
        capture_scope: Some("window".to_string()),
        max_tree_nodes: Some(16),
        max_text_code_units: 512,
        debounce_ms: 10,
        max_wait_ms: 50,
        read_timeout_ms: 500,
        ..CapturePolicy::default()
    };

    engine.receive(&configure_msg("owner-1", "inst-1", 1, &policy));
    engine.receive(&control_msg("owner-1", "inst-1", 1, "start", 5_000));
    let _ = engine.drain_outputs();

    engine.clock.advance(60);
    engine.tick(true);
    let ticket = engine.environment.launched.pop().expect("ticket");

    let now_unix = engine.clock.unix_ms();
    let res = ReadResult {
        token: ticket.token.clone(),
        application: Some(ApplicationIdentity {
            application_id: "code.exe".to_string(),
            process_id: 2222,
            process_start_time: "unix-ms:1700000000000.000".to_string(),
        }),
        diagnostic_application: None,
        exe_name: Some("code.exe".to_string()),
        text: Some(TextRead {
            text: "abc".to_string(),
            source: "uia.text".to_string(),
            total_length: Some(3),
            selection: None,
            range_start: 0,
            range_basis: "prefix".to_string(),
            complete: true,
            truncated: false,
            missing_reasons: vec![],
            read_units: None,
        }),
        reason: None,
        diagnostic: None,
        enablement: None,
        session_identity: Some(WorkerSurfaceIdentity {
            session_id: "s1".to_string(),
            window_id: "w1".to_string(),
            node_id: "n1".to_string(),
            surface_id: "surf-1".to_string(),
            window_generation: 1,
            focus_generation: 1,
        }),
        surface: Some(SurfaceReadResult {
            surface_id: "surf-1".to_string(),
            revision: 3,
            scope: "window".to_string(),
            mode: "diff".to_string(),
            nodes: vec![SurfaceNode {
                id: "n1".to_string(),
                parent_id: None,
                role: "editable".to_string(),
                text: Some("abc".to_string()),
                observed_at_ms: now_unix,
                bounds: None,
                bounds_observed_at_ms: None,
                ax_role: Some("AXTextArea".to_string()),
                focused: Some(true),
            }],
            base_revision: Some(2),
            added: vec!["n1".to_string()],
            updated: vec![],
            removed: vec![],
            truncated: false,
            missing_reasons: vec![],
            complete: true,
            geometry: None,
        }),
        selection: None,
        input_records: Vec::new(),
        input_gaps: Vec::new(),
        private_state: Some("normal".to_string()),
        observer_status: Some("unavailable".to_string()),
        focus_absent: None,
        surface_failure: None,
        verified_normal_browser: None,
        capture_start_ms: now_unix,
        capture_end_ms: now_unix,
    };

    engine.complete(res);
    let msgs = emitted_messages(engine.drain_outputs());
    let surf_msg = msgs
        .iter()
        .find(|m| {
            m.get("payload")
                .and_then(|p| p.get("kind"))
                .and_then(JsonValue::as_str)
                == Some("surface.snapshot")
        })
        .expect("surface.snapshot emitted");
    validator
        .validate_message(surf_msg)
        .expect("promoted full surface valid");
    let payload = surf_msg.get("payload").unwrap();
    assert_eq!(payload.get("mode").and_then(JsonValue::as_str), Some("full"));
    assert_eq!(payload.get("source").and_then(JsonValue::as_str), Some("uia.tree"));
    assert!(payload.get("baseRevision").is_none());
    assert!(payload.get("changes").is_none());
}

#[test]
fn engine_recovers_and_reemits_context_changed_after_policy_boundary_and_focus_unavailable() {
    let validator = ContractValidator::new().unwrap();
    let clock = MockClock::new(20_000, 1_700_000_000_000);
    let mut engine = CollectorEngine::new(
        "owner-rec",
        "inst-rec",
        "dev-rec",
        "wts-1",
        "winsta0-default-wts-1",
        false,
        MockEnv::unlocked(),
        clock,
        validator.clone(),
    );

    let policy = CapturePolicy {
        enabled: true,
        allowed_application_ids: vec!["code.exe".to_string()],
        max_text_code_units: 512,
        debounce_ms: 10,
        max_wait_ms: 50,
        read_timeout_ms: 500,
        ..CapturePolicy::default()
    };

    engine.receive(&configure_msg("owner-rec", "inst-rec", 1, &policy));
    engine.receive(&control_msg("owner-rec", "inst-rec", 1, "start", 10_000));
    let _ = engine.drain_outputs();

    let stable_identity = WorkerSurfaceIdentity {
        session_id: "sess-rec".to_string(),
        window_id: "win-rec".to_string(),
        node_id: "node-rec".to_string(),
        surface_id: "surf-rec".to_string(),
        window_generation: 1,
        focus_generation: 1,
    };
    let make_valid_read = |token: String, text: &str, now_unix: i64| ReadResult {
        token,
        application: Some(ApplicationIdentity {
            application_id: "code.exe".to_string(),
            process_id: 3333,
            process_start_time: "unix-ms:1700000000000.000".to_string(),
        }),
        diagnostic_application: None,
        exe_name: Some("code.exe".to_string()),
        text: Some(TextRead {
            text: text.to_string(),
            source: "uia.text".to_string(),
            total_length: Some(text.encode_utf16().count()),
            selection: None,
            range_start: 0,
            range_basis: "prefix".to_string(),
            complete: true,
            truncated: false,
            missing_reasons: vec![],
            read_units: None,
        }),
        reason: None,
        diagnostic: None,
        enablement: None,
        session_identity: Some(stable_identity.clone()),
        surface: None,
        selection: None,
        input_records: Vec::new(),
        input_gaps: Vec::new(),
        private_state: Some("normal".to_string()),
        observer_status: Some("best-effort".to_string()),
        focus_absent: None,
        surface_failure: None,
        verified_normal_browser: None,
        capture_start_ms: now_unix,
        capture_end_ms: now_unix,
    };

    // 1. Initial valid read establishes resolved target and worker_identity.
    engine.clock.advance(60);
    engine.tick(true);
    let ticket1 = engine.environment.launched.pop().expect("ticket1");
    let now1 = engine.clock.unix_ms();
    engine.complete(make_valid_read(ticket1.token, "initial", now1));
    let msgs1 = emitted_messages(engine.drain_outputs());
    assert!(msgs1.iter().any(|m| {
        m.get("payload")
            .and_then(|p| p.get("kind"))
            .and_then(JsonValue::as_str)
            == Some("context.changed")
            && m.get("target")
                .and_then(|t| t.get("kind"))
                .and_then(JsonValue::as_str)
                == Some("resolved")
    }));
    for m in &msgs1 {
        validator.validate_message(m).expect("initial wire valid");
    }

    // 2. Transient focus-unavailable AND policy-boundary MUST clear worker_identity so the next
    // valid read with the EXACT SAME session_identity re-emits resolved context.changed before
    // text.snapshot (preventing silent CollectorAdmission drops).
    for (idx, (fail_reason, fail_code)) in [
        ("focus-unavailable", GapDiagnosticCode::FocusedFieldUnavailable),
        ("policy-boundary", GapDiagnosticCode::SecureField),
    ]
    .into_iter()
    .enumerate()
    {
        engine.clock.advance(1_200);
        engine.tick(true);
        let fail_ticket = engine.environment.launched.pop().expect("fail ticket");
        let now_fail = engine.clock.unix_ms();
        let fail_res = ReadResult::failure(
            fail_ticket.token,
            fail_reason,
            Some(GapDiagnostic::new(fail_code, None)),
            now_fail,
            now_fail,
        );
        engine.complete(fail_res);
        let fail_msgs = emitted_messages(engine.drain_outputs());
        assert!(
            fail_msgs.iter().any(|m| {
                m.get("payload")
                    .and_then(|p| p.get("kind"))
                    .and_then(JsonValue::as_str)
                    == Some("context.changed")
                    && m.get("target")
                        .and_then(|t| t.get("kind"))
                        .and_then(JsonValue::as_str)
                        == Some("unresolved")
            }),
            "expected unresolved context.changed on {fail_reason}"
        );
        for m in &fail_msgs {
            validator.validate_message(m).expect("failure wire valid");
        }

        // Next valid read reuses the EXACT SAME `stable_identity`.
        engine.clock.advance(1_200);
        engine.tick(true);
        let rec_ticket = engine.environment.launched.pop().expect("recovery ticket");
        let now_rec = engine.clock.unix_ms();
        let rec_text = format!("recovered-{idx}");
        engine.complete(make_valid_read(rec_ticket.token, &rec_text, now_rec));
        let rec_msgs = emitted_messages(engine.drain_outputs());

        let ctx_pos = rec_msgs
            .iter()
            .position(|m| {
                m.get("payload")
                    .and_then(|p| p.get("kind"))
                    .and_then(JsonValue::as_str)
                    == Some("context.changed")
                    && m.get("target")
                        .and_then(|t| t.get("kind"))
                        .and_then(JsonValue::as_str)
                        == Some("resolved")
            })
            .unwrap_or_else(|| {
                panic!("MUST re-emit resolved context.changed after {fail_reason} recovery")
            });
        let text_pos = rec_msgs
            .iter()
            .position(|m| {
                m.get("payload")
                    .and_then(|p| p.get("kind"))
                    .and_then(JsonValue::as_str)
                    == Some("text.snapshot")
            })
            .unwrap_or_else(|| panic!("MUST emit text.snapshot after {fail_reason} recovery"));
        assert!(
            ctx_pos < text_pos,
            "resolved context.changed MUST precede text.snapshot after {fail_reason}"
        );
        for m in &rec_msgs {
            validator.validate_message(m).expect("recovery wire valid");
        }
    }
}

#[test]
fn all_non_hanging_fixture_scenarios_behave_per_spec() {
    let clock = MockClock::new(10_000, 1_700_000_000_000);
    let make_ticket = |policy: CapturePolicy| ReadTicket {
        token: generate_uuid_v4(),
        policy_revision: 1,
        capture_epoch: 1,
        policy,
        hint: None,
        deadline_monotonic_ms: clock.monotonic_ms() + 1_000,
        device_id: "dev".to_string(),
        os_session_id: "fixture-1".to_string(),
        desktop_id: "fixture-desktop".to_string(),
        foreground_generation: Some(1),
        focus_generation: Some(1),
        debug_request_id: None,
        read_only_ax_enablement: None,
        focused_fast_only: None,
    };

    // allowed
    let r_allowed = execute_fixture_read("allowed", &make_ticket(CapturePolicy::default()), &clock);
    assert_eq!(
        r_allowed.text.as_ref().map(|t| t.text.as_str()),
        Some("Synthetic \u{1F9EA} text")
    );

    // value fallback
    let r_val = execute_fixture_read("value", &make_ticket(CapturePolicy::default()), &clock);
    assert_eq!(r_val.text.as_ref().map(|t| t.source.as_str()), Some("uia.value"));
    assert_eq!(
        r_val.text.as_ref().map(|t| t.text.as_str()),
        Some("Synthetic \u{1F9EA} text")
    );

    // partial visible
    let vis_pol = CapturePolicy {
        text_range: Some("visible".to_string()),
        max_text_code_units: 512,
        ..CapturePolicy::default()
    };
    let r_vis = execute_fixture_read("partial", &make_ticket(vis_pol), &clock);
    let t_vis = r_vis.text.expect("visible text");
    assert_eq!(t_vis.range_basis, "visible");
    assert_eq!(t_vis.range_start, 130);
    assert_eq!(t_vis.text.encode_utf16().count(), 260);
    assert_eq!(t_vis.total_length, Some(13_000));
    assert!(t_vis.missing_reasons.contains(&"visible-range-only".to_string()));

    // focus-loss
    let r_fl = execute_fixture_read("focus-loss", &make_ticket(CapturePolicy::default()), &clock);
    assert_eq!(r_fl.reason.as_deref(), Some("focus-unavailable"));
    assert_eq!(
        r_fl.diagnostic.map(|d| d.code),
        Some(GapDiagnosticCode::FocusedFieldUnavailable)
    );

    // sensitive
    let r_sens = execute_fixture_read("sensitive", &make_ticket(CapturePolicy::default()), &clock);
    assert_eq!(r_sens.reason.as_deref(), Some("policy-boundary"));
    assert_eq!(
        r_sens.diagnostic.map(|d| d.code),
        Some(GapDiagnosticCode::SecureField)
    );

    // browser
    let r_br = execute_fixture_read("browser", &make_ticket(CapturePolicy::default()), &clock);
    assert_eq!(r_br.reason.as_deref(), Some("policy-boundary"));
    assert_eq!(
        r_br.diagnostic.map(|d| d.code),
        Some(GapDiagnosticCode::ApplicationNotAllowed)
    );

    // readerror
    let r_err = execute_fixture_read("readerror", &make_ticket(CapturePolicy::default()), &clock);
    assert_eq!(r_err.reason.as_deref(), Some("read-error"));
    assert_eq!(
        r_err.diagnostic.map(|d| d.code),
        Some(GapDiagnosticCode::TextReadUnavailable)
    );
}

fn collector_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_computer-history-collector"))
}

#[test]
fn live_job_object_worker_hang_is_terminated_and_reaped() {
    let bin = collector_bin();
    let mut supervisor = JobWorkerSupervisor::new(bin, true, "workerhang");
    let now = SystemCollectorClock::monotonic_ms_now();
    let ticket = ReadTicket {
        token: generate_uuid_v4(),
        policy_revision: 1,
        capture_epoch: 1,
        policy: CapturePolicy::default(),
        hint: None,
        deadline_monotonic_ms: now + 3_000,
        device_id: "dev-job-test".to_string(),
        os_session_id: "fixture-job".to_string(),
        desktop_id: "fixture-desktop".to_string(),
        foreground_generation: Some(1),
        focus_generation: Some(1),
        debug_request_id: Some(1),
        read_only_ax_enablement: None,
        focused_fast_only: None,
    };

    assert!(supervisor.launch(ticket).is_none());
    let child_pid = supervisor.active_child_pid().expect("child spawned");
    assert!(is_pid_alive(child_pid), "hung worker should be running");

    // Cancel terminates the Windows Job Object and reaps the child promptly.
    supervisor.cancel();
    assert!(supervisor.active_child_pid().is_none());
    assert!(
        !is_pid_alive(child_pid),
        "Job Object termination must kill & reap hung worker PID {child_pid}"
    );
}

#[test]
fn live_session_worker_inert_retire_handshake() {
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
    let cmd = format!("{{\"retire\":\"{retire_token}\",\"sessionToken\":\"{launch_token}\"}}\n");
    stdin.write_all(cmd.as_bytes()).unwrap();
    stdin.flush().unwrap();

    // Keep stdin open to confirm worker exits strictly from retire handshake, not EOF.
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let parsed = JsonValue::parse_str(line.trim_end()).expect("valid JSON ack");
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

    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(0));
    drop(stdin);
}

#[test]
fn live_owner_lock_emits_hello_before_exit_73_on_contention() {
    let bin = collector_bin();
    let lock_id = format!("lock-test-{}", std::process::id());

    let mut first = Command::new(&bin)
        .args([
            "--fixture",
            "--owner-id",
            "owner-a",
            "--instance-id",
            "inst-a",
            "--device-id",
            "dev-a",
            "--fixture-lock-id",
            &lock_id,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn first");

    let mut first_reader = BufReader::new(first.stdout.take().unwrap());
    let mut hello1 = String::new();
    first_reader.read_line(&mut hello1).unwrap();
    assert!(hello1.contains("\"type\":\"hello\""));
    // Give first process a brief moment to acquire the lock after hello flush.
    thread::sleep(Duration::from_millis(50));

    let second = Command::new(&bin)
        .args([
            "--fixture",
            "--owner-id",
            "owner-b",
            "--instance-id",
            "inst-b",
            "--device-id",
            "dev-b",
            "--fixture-lock-id",
            &lock_id,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .expect("run second");

    assert_eq!(second.status.code(), Some(73));
    let second_stdout = String::from_utf8_lossy(&second.stdout);
    assert!(
        second_stdout.contains("\"type\":\"hello\""),
        "second process must emit hello BEFORE OwnerLock failure: {second_stdout}"
    );

    // Close first stdin so it exits cleanly with 0.
    drop(first.stdin.take());
    let first_status = first.wait().unwrap();
    assert_eq!(first_status.code(), Some(0));
}

#[test]
fn live_navigate_source_and_permissions_cli_exit_codes() {
    let bin = collector_bin();

    // Extra args on --navigate-source -> exit 64, empty stdout/stderr.
    let bad_args = Command::new(&bin)
        .args(["--navigate-source", "extra"])
        .output()
        .unwrap();
    assert_eq!(bad_args.status.code(), Some(64));
    assert!(bad_args.stdout.is_empty());
    assert!(bad_args.stderr.is_empty());

    // Oversized stdin -> exit 64, input-too-large receipt.
    let mut big_child = Command::new(&bin)
        .args(["--navigate-source"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    big_child
        .stdin
        .take()
        .unwrap()
        .write_all(&vec![b' '; 2049])
        .unwrap();
    let big_out = big_child.wait_with_output().unwrap();
    assert_eq!(big_out.status.code(), Some(64));
    assert!(String::from_utf8_lossy(&big_out.stdout).contains("\"reason\":\"input-too-large\""));

    // Duplicate key stdin -> exit 64, invalid-request receipt.
    let mut dup_child = Command::new(&bin)
        .args(["--navigate-source"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    dup_child
        .stdin
        .take()
        .unwrap()
        .write_all(br#"{"version":1,"version":1}"#)
        .unwrap();
    let dup_out = dup_child.wait_with_output().unwrap();
    assert_eq!(dup_out.status.code(), Some(64));
    assert!(String::from_utf8_lossy(&dup_out.stdout).contains("\"reason\":\"invalid-request\""));

    // Held stdin -> exit 75, input-timeout within 3s.
    let mut held = Command::new(&bin)
        .args(["--navigate-source"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut held_in = held.stdin.take().unwrap();
    held_in.write_all(b"{").unwrap();
    held_in.flush().unwrap();
    let held_out = held.wait_with_output().unwrap();
    drop(held_in);
    assert_eq!(held_out.status.code(), Some(75));
    assert!(String::from_utf8_lossy(&held_out.stdout).contains("\"reason\":\"input-timeout\""));

    // Permissions CLI check + invalid action.
    let perm_ok = Command::new(&bin)
        .args(["--permissions", "check"])
        .output()
        .unwrap();
    assert_eq!(perm_ok.status.code(), Some(0));
    let perm_json = JsonValue::parse(&perm_ok.stdout).expect("valid permissions JSON");
    assert_eq!(
        perm_json.get("accessibility").and_then(JsonValue::as_str),
        Some("not-applicable")
    );

    let perm_bad = Command::new(&bin)
        .args(["--permissions", "invalid"])
        .output()
        .unwrap();
    assert_eq!(perm_bad.status.code(), Some(64));
}

#[test]
fn engine_oversized_observation_emits_bounded_gap_and_keeps_bounded_output_healthy() {
    let validator = ContractValidator::new().unwrap();
    let clock = MockClock::new(30_000, 1_700_000_000_000);
    let mut engine = CollectorEngine::new(
        "owner-big",
        "inst-big",
        "dev-big",
        "wts-1",
        "winsta0-default-wts-1",
        false,
        MockEnv::unlocked(),
        clock,
        validator.clone(),
    );

    let policy = CapturePolicy {
        enabled: true,
        allowed_application_ids: vec!["code.exe".to_string()],
        capture_scope: Some("window".to_string()),
        max_tree_nodes: Some(96),
        max_text_code_units: 8_192,
        debounce_ms: 10,
        max_wait_ms: 50,
        read_timeout_ms: 500,
        ..CapturePolicy::default()
    };

    engine.receive(&configure_msg("owner-big", "inst-big", 1, &policy));
    engine.receive(&control_msg("owner-big", "inst-big", 1, "start", 10_000));
    let _ = engine.drain_outputs();

    engine.clock.advance(60);
    engine.tick(true);
    let ticket = engine.environment.launched.pop().expect("ticket");
    let now_unix = engine.clock.unix_ms();

    // Build a valid_surface() payload that stays within 96 nodes and <= 8,192 UTF-16 code units,
    // yet expands well past the 65,536-byte canonical UTF-8 JSON wire limit (due to 96 nodes with
    // metadata + JSON-escaped control chars \u0001 expanding 1 UTF-16 unit -> 6 UTF-8 JSON bytes).
    let mut nodes = Vec::with_capacity(96);
    for i in 0..96usize {
        let text = if i < 80 {
            Some("\u{0001}".repeat(100)) // 80 * 100 = 8,000 UTF-16 units -> 48,000 JSON bytes
        } else {
            None
        };
        nodes.push(SurfaceNode {
            id: format!("node-long-stable-identifier-segment-{i:04}-aaaaaaaaaaaaaaaaaaaa"),
            parent_id: (i > 0).then(|| "node-long-stable-identifier-segment-0000-aaaaaaaaaaaaaaaaaaaa".to_string()),
            role: "text".to_string(),
            text,
            observed_at_ms: now_unix,
            bounds: Some(SurfaceBounds::new(10.0, 20.0, 300.0, 40.0)),
            bounds_observed_at_ms: Some(now_unix),
            ax_role: Some("AXStaticText".to_string()),
            focused: None,
        });
    }

    let oversized_res = ReadResult {
        token: ticket.token,
        application: Some(ApplicationIdentity {
            application_id: "code.exe".to_string(),
            process_id: 4444,
            process_start_time: "unix-ms:1700000000000.000".to_string(),
        }),
        diagnostic_application: None,
        exe_name: Some("code.exe".to_string()),
        text: None,
        reason: None,
        diagnostic: None,
        enablement: None,
        session_identity: Some(WorkerSurfaceIdentity {
            session_id: "sess-big".to_string(),
            window_id: "win-big".to_string(),
            node_id: "node-big".to_string(),
            surface_id: "surf-big".to_string(),
            window_generation: 1,
            focus_generation: 1,
        }),
        surface: Some(SurfaceReadResult {
            surface_id: "surf-big".to_string(),
            revision: 1,
            scope: "window".to_string(),
            mode: "full".to_string(),
            nodes,
            base_revision: None,
            added: Vec::new(),
            updated: Vec::new(),
            removed: Vec::new(),
            truncated: false,
            missing_reasons: Vec::new(),
            complete: true,
            geometry: Some(SurfaceGeometry::new(
                SurfaceWindowSize {
                    width: 800.0,
                    height: 600.0,
                },
                now_unix,
            )),
        }),
        selection: None,
        input_records: Vec::new(),
        input_gaps: Vec::new(),
        private_state: Some("normal".to_string()),
        observer_status: Some("best-effort".to_string()),
        focus_absent: None,
        surface_failure: None,
        verified_normal_browser: None,
        capture_start_ms: now_unix,
        capture_end_ms: now_unix,
    };
    assert!(oversized_res.valid_surface(&policy));

    engine.complete(oversized_res);
    assert!(!engine.should_exit(), "oversized observation MUST NOT exit collector");
    assert_eq!(engine.state(), "running");

    let msgs = emitted_messages(engine.drain_outputs());
    assert!(
        !msgs.iter().any(|m| {
            m.get("payload")
                .and_then(|p| p.get("kind"))
                .and_then(JsonValue::as_str)
                == Some("surface.snapshot")
        }),
        "oversized surface.snapshot must be dropped rather than force-emitted"
    );
    let gap = msgs
        .iter()
        .find(|m| {
            m.get("payload")
                .and_then(|p| p.get("kind"))
                .and_then(JsonValue::as_str)
                == Some("gap")
        })
        .expect("bounded gap emitted for oversized surface.snapshot");
    let gap_payload = gap.get("payload").unwrap();
    assert_eq!(
        gap_payload.get("reason").and_then(JsonValue::as_str),
        Some("budget")
    );
    assert_eq!(
        gap_payload
            .get("diagnostic")
            .and_then(|d| d.get("code"))
            .and_then(JsonValue::as_str),
        Some("text-result-invalid")
    );
    for msg in &msgs {
        let encoded = validator
            .encode_frame(msg)
            .expect("every emitted message must validate and fit inside 65,536 B");
        assert!(encoded.len() <= 65_536);
    }

    // Verify BoundedOutput does NOT poison itself on EncodeFailed (FrameTooLarge / InvalidMessage).
    let output = BoundedOutput::new_with_writer(validator.clone(), |_| true);
    let mut huge_bad = BTreeMap::new();
    huge_bad.insert("type".to_string(), JsonValue::String("invalid".to_string()));
    huge_bad.insert(
        "blob".to_string(),
        JsonValue::String("x".repeat(70_000)),
    );
    let err = output
        .try_enqueue(&JsonValue::Object(huge_bad))
        .expect_err("unencodable frame must return EncodeFailed");
    assert!(matches!(
        err,
        EnqueueError::EncodeFailed(ProtocolError::InvalidMessage | ProtocolError::FrameTooLarge)
    ));
    assert!(
        !output.is_failed() && output.poll_health(),
        "EncodeFailed MUST NEVER mark BoundedOutput failed"
    );
    // Subsequent valid frame MUST enqueue and flush cleanly!
    output
        .try_enqueue(&hello_message("inst-big", false))
        .expect("valid hello enqueues after EncodeFailed");
    assert!(output.close_and_drain(500));
    assert!(!output.is_failed());
}

#[test]
fn worker_pipe_framing_parses_multi_frame_burst_and_rejects_oversized_line() {
    // 1. Combined multi-frame burst: 15 B dirty notice + ~65,528 B valid ReadResult (> 65,536 B total).
    let dirty_line = b"{\"dirty\":true}\n";
    assert_eq!(dirty_line.len(), 15);
    let mut large_result = Vec::with_capacity(65_536);
    large_result.extend_from_slice(br#"{"token":"t","pad":""#);
    large_result.extend(std::iter::repeat_n(b'a', 65_505));
    large_result.extend_from_slice(b"\"}\n");
    assert!(large_result.len() <= WORKER_MAX_FRAME_BYTES);
    assert!(dirty_line.len() + large_result.len() > WORKER_MAX_FRAME_BYTES);

    let mut burst = Vec::new();
    burst.extend_from_slice(dirty_line);
    burst.extend_from_slice(&large_result);

    let frames = split_worker_pipe_frames(&mut burst, WORKER_MAX_FRAME_BYTES)
        .expect("multi-frame burst under per-line 65,536 B limit must parse cleanly");
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0], b"{\"dirty\":true}");
    assert_eq!(frames[1].len(), large_result.len() - 1);
    assert!(burst.is_empty());

    // 2. Single line > 65,536 B (with '\n') MUST be rejected!
    let mut too_big_line = vec![b'x'; WORKER_MAX_FRAME_BYTES];
    too_big_line.push(b'\n'); // 65,537 bytes including '\n'
    assert!(split_worker_pipe_frames(&mut too_big_line, WORKER_MAX_FRAME_BYTES).is_err());

    // 3. Incomplete line without '\n' reaching 65,536 B MUST be rejected!
    let mut incomplete_too_big = vec![b'y'; WORKER_MAX_FRAME_BYTES];
    assert!(split_worker_pipe_frames(&mut incomplete_too_big, WORKER_MAX_FRAME_BYTES).is_err());

    // 4. Incomplete line of 65,535 B without '\n' waits, then succeeds once '\n' arrives (exact 65,536 B).
    let mut exact_max = vec![b'z'; WORKER_MAX_FRAME_BYTES - 1];
    assert_eq!(
        split_worker_pipe_frames(&mut exact_max, WORKER_MAX_FRAME_BYTES).unwrap().len(),
        0
    );
    exact_max.push(b'\n');
    let exact_frames = split_worker_pipe_frames(&mut exact_max, WORKER_MAX_FRAME_BYTES).unwrap();
    assert_eq!(exact_frames.len(), 1);
    assert_eq!(exact_frames[0].len(), WORKER_MAX_FRAME_BYTES - 1);
}

#[test]
fn engine_rejects_unsupported_serve_channels_and_pauses_on_unconfirmed_cancel() {
    let validator = ContractValidator::new().unwrap();
    let clock = MockClock::new(40_000, 1_700_000_000_000);
    let env = MockEnv::unlocked();

    let mut engine = CollectorEngine::new(
        "owner-ch",
        "inst-ch",
        "dev-ch",
        "wts-1",
        "winsta0-default-wts-1",
        false,
        env,
        clock,
        validator.clone(),
    );

    // 1. Non-fixture (--serve) configure MUST still reject unsupported macOS-only `text_markers`
    // while accepting Phase 5A + 5B channels (`input_activity`, `menu_actions`, `input_text`).
    let base = CapturePolicy {
        enabled: true,
        allowed_application_ids: vec!["code.exe".to_string()],
        ..CapturePolicy::default()
    };
    let unsupported_policy = CapturePolicy {
        text_markers: Some(true),
        ..base.clone()
    };
    engine.receive(&configure_msg("owner-ch", "inst-ch", 1, &unsupported_policy));
    let msgs = emitted_messages(engine.drain_outputs());
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].get("type").and_then(JsonValue::as_str), Some("error"));
    assert_eq!(
        msgs[0].get("code").and_then(JsonValue::as_str),
        Some("unsupported")
    );
    validator
        .validate_message(&msgs[0])
        .expect("unsupported error frame must be wire-valid");
    assert_eq!(engine.policy_revision(), 0, "rejected configure must not advance revision");
    assert_eq!(engine.state(), "unconfigured");

    // 1b. Live (--serve) configure accepts `input_text: true` cleanly!
    let supported_p5b = CapturePolicy {
        input_text: Some(true),
        input_activity: Some(true),
        menu_actions: Some(true),
        ..base.clone()
    };
    engine.receive(&configure_msg("owner-ch", "inst-ch", 1, &supported_p5b));
    let p5b_msgs = emitted_messages(engine.drain_outputs());
    assert_eq!(p5b_msgs[0].get("type").and_then(JsonValue::as_str), Some("configured"));
    assert_eq!(p5b_msgs[1].get("state").and_then(JsonValue::as_str), Some("ready"));
    assert_eq!(engine.policy_revision(), 1);
    for m in &p5b_msgs {
        validator.validate_message(m).expect("Phase 5B configured frames wire-valid");
    }

    // 2. Supported Phase 5A policy (`input_activity: true`, `menu_actions: true`) configures and
    // starts cleanly; read timeout with Unconfirmed cancel_read MUST transition engine to `paused`
    // with `worker-exit-unconfirmed` (fail closed!).
    let supported_p5a = CapturePolicy {
        input_activity: Some(true),
        menu_actions: Some(true),
        ..base
    };
    engine.receive(&configure_msg("owner-ch", "inst-ch", 2, &supported_p5a));
    engine.receive(&control_msg("owner-ch", "inst-ch", 2, "start", 10_000));
    let _ = engine.drain_outputs();
    assert_eq!(engine.state(), "running");
    assert_eq!(engine.policy_revision(), 2);

    engine.clock.advance(60);
    engine.tick(true);
    assert_eq!(engine.environment.launched.len(), 1);

    // Simulate worker kill failing to confirm exit when timeout fires.
    engine.environment.cancel_cleanup = ReadTimeoutCleanup::Unconfirmed;

    // Advance past read_timeout_ms (200ms) -> expire_read -> cancel_read returns Unconfirmed.
    engine.clock.advance(250);
    engine.tick(true);
    assert_eq!(engine.state(), "paused");
    let msgs = emitted_messages(engine.drain_outputs());
    let state_msg = msgs
        .iter()
        .find(|m| m.get("type").and_then(JsonValue::as_str) == Some("state"))
        .expect("paused state message emitted on Unconfirmed cancel_read");
    assert_eq!(
        state_msg.get("state").and_then(JsonValue::as_str),
        Some("paused")
    );
    assert_eq!(
        state_msg.get("reason").and_then(JsonValue::as_str),
        Some("worker-exit-unconfirmed")
    );
    for m in &msgs {
        validator
            .validate_message(m)
            .expect("timeout/unconfirmed messages wire-valid");
    }
}

#[test]
fn engine_parent_defense_in_depth_rejects_dual_id_excluded_and_browser_read_results() {
    let validator = ContractValidator::new().unwrap();

    // 1. Verify ReadResult JSON round-trips internal `exeName` cleanly.
    let now_unix = 1_700_000_000_100i64;
    let sample_res = ReadResult {
        token: "tok-roundtrip".to_string(),
        application: Some(ApplicationIdentity {
            application_id: "8bitsolutionsllc.bitwardendesktop".to_string(),
            process_id: 7001,
            process_start_time: "unix-ms:1700000000000.000".to_string(),
        }),
        diagnostic_application: Some(ApplicationIdentity {
            application_id: "8bitsolutionsllc.bitwardendesktop".to_string(),
            process_id: 7001,
            process_start_time: "unix-ms:1700000000000.000".to_string(),
        }),
        exe_name: Some("bitwarden.exe".to_string()),
        text: Some(TextRead {
            text: "vault-secret".to_string(),
            source: "uia.text".to_string(),
            total_length: Some(12),
            selection: None,
            range_start: 0,
            range_basis: "prefix".to_string(),
            complete: true,
            truncated: false,
            missing_reasons: vec![],
            read_units: None,
        }),
        reason: None,
        diagnostic: None,
        enablement: None,
        session_identity: Some(WorkerSurfaceIdentity {
            session_id: "s-rt".to_string(),
            window_id: "w-rt".to_string(),
            node_id: "n-rt".to_string(),
            surface_id: "surf-rt".to_string(),
            window_generation: 1,
            focus_generation: 1,
        }),
        surface: None,
        selection: None,
        input_records: Vec::new(),
        input_gaps: Vec::new(),
        private_state: Some("normal".to_string()),
        observer_status: Some("best-effort".to_string()),
        focus_absent: None,
        surface_failure: None,
        verified_normal_browser: None,
        capture_start_ms: now_unix,
        capture_end_ms: now_unix,
    };
    let json = sample_res.to_json();
    assert_eq!(
        json.get("exeName").and_then(JsonValue::as_str),
        Some("bitwarden.exe")
    );
    let roundtripped = ReadResult::from_json(&json).expect("ReadResult round-trips exeName");
    assert_eq!(roundtripped, sample_res);

    // 2. Parent-side defense-in-depth rejects mandatory-excluded Store Bitwarden
    // (`8bitsolutionsllc.bitwardendesktop` + `exe_name = Some("bitwarden.exe")`) even in denylist mode!
    let clock1 = MockClock::new(50_000, 1_700_000_000_000);
    let mut engine_bw = CollectorEngine::new(
        "owner-did",
        "inst-did",
        "dev-did",
        "wts-1",
        "winsta0-default-wts-1",
        false,
        MockEnv::unlocked(),
        clock1,
        validator.clone(),
    );
    let denylist_browsers_on = CapturePolicy {
        enabled: true,
        application_scope: Some("denylist".to_string()),
        allow_browser_content: Some(true),
        max_text_code_units: 512,
        debounce_ms: 10,
        max_wait_ms: 50,
        read_timeout_ms: 500,
        ..CapturePolicy::default()
    };
    engine_bw.receive(&configure_msg("owner-did", "inst-did", 1, &denylist_browsers_on));
    engine_bw.receive(&control_msg("owner-did", "inst-did", 1, "start", 10_000));
    let _ = engine_bw.drain_outputs();
    engine_bw.clock.advance(60);
    engine_bw.tick(true);
    let bw_ticket = engine_bw.environment.launched.pop().expect("bw ticket");
    let bw_unix = engine_bw.clock.unix_ms();
    let mut bw_res = sample_res.clone();
    bw_res.token = bw_ticket.token;
    bw_res.capture_start_ms = bw_unix;
    bw_res.capture_end_ms = bw_unix;
    engine_bw.complete(bw_res);

    let bw_msgs = emitted_messages(engine_bw.drain_outputs());
    assert!(
        !bw_msgs.iter().any(|m| {
            matches!(
                m.get("payload")
                    .and_then(|p| p.get("kind"))
                    .and_then(JsonValue::as_str),
                Some("text.snapshot" | "surface.snapshot" | "selection.snapshot")
            )
        }),
        "mandatory-excluded MSIX Bitwarden must NEVER emit any snapshot"
    );
    for msg in &bw_msgs {
        assert!(
            msg.get("payload")
                .and_then(|p| p.get("providerApplicationId"))
                .is_none(),
            "excluded MSIX Bitwarden must not leak providerApplicationId"
        );
        validator.validate_message(msg).expect("wire valid");
    }

    // 3. Parent-side defense-in-depth rejects MSIX Arc browser (`thebrowsercompany.arc` +
    // `exe_name = Some("arc.exe")`) when `allowBrowserContent: false`!
    let clock2 = MockClock::new(60_000, 1_700_000_000_000);
    let mut engine_arc = CollectorEngine::new(
        "owner-arc",
        "inst-arc",
        "dev-arc",
        "wts-1",
        "winsta0-default-wts-1",
        false,
        MockEnv::unlocked(),
        clock2,
        validator.clone(),
    );
    let denylist_browsers_off = CapturePolicy {
        enabled: true,
        application_scope: Some("denylist".to_string()),
        allow_browser_content: Some(false),
        max_text_code_units: 512,
        debounce_ms: 10,
        max_wait_ms: 50,
        read_timeout_ms: 500,
        ..CapturePolicy::default()
    };
    engine_arc.receive(&configure_msg("owner-arc", "inst-arc", 1, &denylist_browsers_off));
    engine_arc.receive(&control_msg("owner-arc", "inst-arc", 1, "start", 10_000));
    let _ = engine_arc.drain_outputs();
    engine_arc.clock.advance(60);
    engine_arc.tick(true);
    let arc_ticket = engine_arc.environment.launched.pop().expect("arc ticket");
    let arc_unix = engine_arc.clock.unix_ms();
    let arc_app = ApplicationIdentity {
        application_id: "thebrowsercompany.arc".to_string(),
        process_id: 7002,
        process_start_time: "unix-ms:1700000000000.000".to_string(),
    };
    let arc_res = ReadResult {
        token: arc_ticket.token,
        application: Some(arc_app.clone()),
        diagnostic_application: Some(arc_app),
        exe_name: Some("arc.exe".to_string()),
        capture_start_ms: arc_unix,
        capture_end_ms: arc_unix,
        ..sample_res
    };
    engine_arc.complete(arc_res);

    let arc_msgs = emitted_messages(engine_arc.drain_outputs());
    assert!(
        !arc_msgs.iter().any(|m| {
            matches!(
                m.get("payload")
                    .and_then(|p| p.get("kind"))
                    .and_then(JsonValue::as_str),
                Some("text.snapshot" | "surface.snapshot" | "selection.snapshot")
            )
        }),
        "MSIX Arc browser must be rejected when allowBrowserContent=false"
    );
    for msg in &arc_msgs {
        assert!(
            msg.get("payload")
                .and_then(|p| p.get("providerApplicationId"))
                .is_none(),
            "blocked MSIX Arc must not leak providerApplicationId"
        );
        validator.validate_message(msg).expect("wire valid");
    }
}

#[test]
fn engine_pauses_on_unconfirmed_cleanup_from_boundary_and_worker_poll() {
    let validator = ContractValidator::new().unwrap();
    let policy = CapturePolicy {
        enabled: true,
        allowed_application_ids: vec!["code.exe".to_string()],
        max_text_code_units: 512,
        debounce_ms: 10,
        max_wait_ms: 50,
        read_timeout_ms: 500,
        ..CapturePolicy::default()
    };

    // Case A: `boundary()` (triggered by `application_event`) observes `Unconfirmed` from
    // `cancel_read()` -> transitions immediately to `paused` with `worker-exit-unconfirmed`
    // and stops scheduling reads.
    let clock_a = MockClock::new(70_000, 1_700_000_000_000);
    let mut engine_a = CollectorEngine::new(
        "owner-b",
        "inst-b",
        "dev-b",
        "wts-1",
        "winsta0-default-wts-1",
        false,
        MockEnv::unlocked(),
        clock_a,
        validator.clone(),
    );
    engine_a.receive(&configure_msg("owner-b", "inst-b", 1, &policy));
    engine_a.receive(&control_msg("owner-b", "inst-b", 1, "start", 10_000));
    let _ = engine_a.drain_outputs();
    assert_eq!(engine_a.state(), "running");

    engine_a.environment.cancel_cleanup = ReadTimeoutCleanup::Unconfirmed;
    let ev_time = engine_a.clock.unix_ms();
    engine_a.application_event(SourceHint {
        application: ApplicationIdentity {
            application_id: "code.exe".to_string(),
            process_id: 8001,
            process_start_time: "unix-ms:1700000000000.000".to_string(),
        },
        event_time_ms: ev_time,
    });
    assert_eq!(engine_a.state(), "paused");
    let msgs_a = emitted_messages(engine_a.drain_outputs());
    let state_a = msgs_a
        .iter()
        .find(|m| m.get("type").and_then(JsonValue::as_str) == Some("state"))
        .expect("paused state emitted from boundary()");
    assert_eq!(state_a.get("state").and_then(JsonValue::as_str), Some("paused"));
    assert_eq!(
        state_a.get("reason").and_then(JsonValue::as_str),
        Some("worker-exit-unconfirmed")
    );
    assert!(
        !msgs_a.iter().any(|m| {
            m.get("payload")
                .and_then(|p| p.get("kind"))
                .and_then(JsonValue::as_str)
                == Some("context.changed")
        }),
        "boundary() unconfirmed must not emit context.changed"
    );
    for m in &msgs_a {
        validator.validate_message(m).expect("boundary state wire valid");
    }
    engine_a.clock.advance(500);
    engine_a.tick(true);
    assert!(engine_a.environment.launched.is_empty());

    // Case B: `poll_environment()` observes `WorkerEvent::WorkerExitUnconfirmed` from worker
    // supervisor polling -> transitions immediately to `paused` with `worker-exit-unconfirmed`.
    let clock_b = MockClock::new(80_000, 1_700_000_000_000);
    let mut engine_b = CollectorEngine::new(
        "owner-p1",
        "inst-p1",
        "dev-p1",
        "wts-1",
        "winsta0-default-wts-1",
        false,
        MockEnv::unlocked(),
        clock_b,
        validator.clone(),
    );
    engine_b.receive(&configure_msg("owner-p1", "inst-p1", 1, &policy));
    engine_b.receive(&control_msg("owner-p1", "inst-p1", 1, "start", 10_000));
    let _ = engine_b.drain_outputs();
    assert_eq!(engine_b.state(), "running");

    engine_b
        .environment
        .poll_events
        .push(WorkerEvent::WorkerExitUnconfirmed);
    engine_b.environment.poll_cleanup = Some(ReadTimeoutCleanup::Unconfirmed);
    engine_b.poll_environment();
    assert_eq!(engine_b.state(), "paused");
    let msgs_b = emitted_messages(engine_b.drain_outputs());
    let state_b = msgs_b
        .iter()
        .find(|m| m.get("type").and_then(JsonValue::as_str) == Some("state"))
        .expect("paused state emitted from poll_environment() WorkerExitUnconfirmed");
    assert_eq!(state_b.get("state").and_then(JsonValue::as_str), Some("paused"));
    assert_eq!(
        state_b.get("reason").and_then(JsonValue::as_str),
        Some("worker-exit-unconfirmed")
    );
    for m in &msgs_b {
        validator.validate_message(m).expect("poll state wire valid");
    }
    // Subsequent ticks must not spam duplicate state frames or launch reads.
    engine_b.clock.advance(500);
    engine_b.tick(true);
    assert!(engine_b.drain_outputs().is_empty());
    assert!(engine_b.environment.launched.is_empty());

    // Case C: Even if `timed_out_read_cleanup()` flips to `Unconfirmed` without a separate
    // WorkerEvent, `poll_environment()` / `tick()` still transitions `running` -> `paused`
    // (`worker-exit-unconfirmed`) instead of silently skipping `tick()` while remaining `running`.
    let clock_c = MockClock::new(90_000, 1_700_000_000_000);
    let mut engine_c = CollectorEngine::new(
        "owner-p2",
        "inst-p2",
        "dev-p2",
        "wts-1",
        "winsta0-default-wts-1",
        false,
        MockEnv::unlocked(),
        clock_c,
        validator.clone(),
    );
    engine_c.receive(&configure_msg("owner-p2", "inst-p2", 1, &policy));
    engine_c.receive(&control_msg("owner-p2", "inst-p2", 1, "start", 10_000));
    let _ = engine_c.drain_outputs();
    assert_eq!(engine_c.state(), "running");

    engine_c.environment.last_cleanup = ReadTimeoutCleanup::Unconfirmed;
    engine_c.tick(true);
    assert_eq!(engine_c.state(), "paused");
    let msgs_c = emitted_messages(engine_c.drain_outputs());
    let state_c = msgs_c
        .iter()
        .find(|m| m.get("type").and_then(JsonValue::as_str) == Some("state"))
        .expect("paused state emitted from tick() on Unconfirmed cleanup");
    assert_eq!(
        state_c.get("reason").and_then(JsonValue::as_str),
        Some("worker-exit-unconfirmed")
    );
    for m in &msgs_c {
        validator.validate_message(m).expect("tick state wire valid");
    }
}

#[test]
fn engine_dual_id_defense_in_depth_for_input_activity_and_menu_action() {
    let validator = ContractValidator::new().unwrap();
    let clock = MockClock::new(100_000, 1_700_000_000_100);
    let mut engine = CollectorEngine::new(
        "owner-p5a-dual",
        "inst-p5a-dual",
        "dev-p5a",
        "wts-1",
        "winsta0-default-wts-1",
        false,
        MockEnv::unlocked(),
        clock,
        validator.clone(),
    );

    // Denylist mode with allowBrowserContent = false -> blocks browsers (incl. MSIX Arc) AND
    // mandatory-excluded Store Bitwarden!
    let denylist_no_browser = CapturePolicy {
        enabled: true,
        application_scope: Some("denylist".to_string()),
        allow_browser_content: Some(false),
        input_activity: Some(true),
        menu_actions: Some(true),
        debounce_ms: 10,
        max_wait_ms: 50,
        read_timeout_ms: 2_000,
        ..CapturePolicy::default()
    };
    engine.receive(&configure_msg(
        "owner-p5a-dual",
        "inst-p5a-dual",
        1,
        &denylist_no_browser,
    ));
    engine.receive(&control_msg(
        "owner-p5a-dual",
        "inst-p5a-dual",
        1,
        "start",
        10_000,
    ));
    let _ = engine.drain_outputs();

    let bitwarden_app = ApplicationIdentity {
        application_id: "8bitsolutionsllc.bitwardendesktop".to_string(),
        process_id: 9001,
        process_start_time: "unix-ms:1700000000000.000".to_string(),
    };
    let arc_app = ApplicationIdentity {
        application_id: "thebrowsercompany.arc".to_string(),
        process_id: 9002,
        process_start_time: "unix-ms:1700000000000.000".to_string(),
    };
    let notepad_app = ApplicationIdentity {
        application_id: "notepad.exe".to_string(),
        process_id: 9003,
        process_start_time: "unix-ms:1700000000000.000".to_string(),
    };

    // 1. MSIX Bitwarden & MSIX Arc MUST be rejected on both input.activity and menu.action!
    let now_u = engine.clock.unix_ms();
    engine.input_activity(InputActivitySample {
        application: bitwarden_app.clone(),
        exe_name: Some("bitwarden.exe".to_string()),
        category: InputActivityCategory::ShortcutPress,
        callback_time_ms: now_u,
    });
    engine.input_activity(InputActivitySample {
        application: arc_app.clone(),
        exe_name: Some("arc.exe".to_string()),
        category: InputActivityCategory::PointerRelease,
        callback_time_ms: now_u,
    });
    engine.menu_action(MenuActionRecord {
        application: bitwarden_app.clone(),
        exe_name: Some("bitwarden.exe".to_string()),
        path: vec!["File".to_string(), "Unlock Vault".to_string()],
        truncated: false,
        observed_at_ms: now_u,
        private_state: "normal".to_string(),
        stamp: engine.stamp(),
        field_security: "strict".to_string(),
    });
    engine.menu_action(MenuActionRecord {
        application: arc_app.clone(),
        exe_name: Some("arc.exe".to_string()),
        path: vec!["File".to_string(), "New Tab".to_string()],
        truncated: false,
        observed_at_ms: now_u,
        private_state: "normal".to_string(),
        stamp: engine.stamp(),
        field_security: "strict".to_string(),
    });
    engine.clock.advance(1_000);
    engine.tick(true);
    let dropped_msgs = emitted_messages(engine.drain_outputs());
    assert!(
        !dropped_msgs.iter().any(|m| matches!(
            m.get("payload")
                .and_then(|p| p.get("kind"))
                .and_then(JsonValue::as_str),
            Some("input.activity" | "menu.action")
        )),
        "MSIX Bitwarden and blocked MSIX Arc MUST never emit input.activity or menu.action"
    );

    // 2. Allowed Notepad emits both wire-valid `input.activity` (`win32.listen-only`) and
    // `menu.action` (`uia.menu`) with ZERO internal `exeName` on external wire!
    let t_note = engine.clock.unix_ms();
    engine.input_activity(InputActivitySample {
        application: notepad_app.clone(),
        exe_name: Some("notepad.exe".to_string()),
        category: InputActivityCategory::PointerRelease,
        callback_time_ms: t_note,
    });
    engine.handle_worker_event(WorkerEvent::MenuAction(Box::new(MenuActionRecord {
        application: notepad_app.clone(),
        exe_name: Some("notepad.exe".to_string()),
        path: vec!["File".to_string(), "Export".to_string(), "PDF".to_string()],
        truncated: false,
        observed_at_ms: t_note,
        private_state: "normal".to_string(),
        stamp: engine.stamp(),
        field_security: "strict".to_string(),
    })));
    engine.clock.advance(1_000);
    engine.tick(true);

    let ok_msgs = emitted_messages(engine.drain_outputs());
    let activity = ok_msgs
        .iter()
        .find(|m| {
            m.get("payload")
                .and_then(|p| p.get("kind"))
                .and_then(JsonValue::as_str)
                == Some("input.activity")
        })
        .expect("input.activity emitted for allowed app");
    let menu = ok_msgs
        .iter()
        .find(|m| {
            m.get("payload")
                .and_then(|p| p.get("kind"))
                .and_then(JsonValue::as_str)
                == Some("menu.action")
        })
        .expect("menu.action emitted for allowed app");

    assert_eq!(
        activity
            .get("payload")
            .and_then(|p| p.get("source"))
            .and_then(JsonValue::as_str),
        Some("win32.listen-only")
    );
    assert_eq!(
        menu.get("payload")
            .and_then(|p| p.get("source"))
            .and_then(JsonValue::as_str),
        Some("uia.menu")
    );
    assert_eq!(
        menu.get("target")
            .and_then(|t| t.get("kind"))
            .and_then(JsonValue::as_str),
        Some("application")
    );
    assert_eq!(
        menu.get("eventTimeMs").and_then(JsonValue::as_i64),
        Some(t_note)
    );
    for msg in [activity, menu] {
        let bytes = validator.encode_frame(msg).expect("wire frame valid");
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(
            !text.contains("exeName"),
            "internal exeName MUST NEVER appear on external wire: {text}"
        );
    }

    // 3. With allowBrowserContent = true in denylist mode:
    // - MSIX Bitwarden is STILL rejected (mandatory denied!).
    // - MSIX Arc menu.action with private_state == "normal" is rejected (known browsers MUST carry "user-authorized"!).
    // - MSIX Arc menu.action with private_state == "user-authorized" is accepted!
    let denylist_with_browser = CapturePolicy {
        allow_browser_content: Some(true),
        ..denylist_no_browser
    };
    engine.receive(&configure_msg(
        "owner-p5a-dual",
        "inst-p5a-dual",
        2,
        &denylist_with_browser,
    ));
    engine.receive(&control_msg(
        "owner-p5a-dual",
        "inst-p5a-dual",
        2,
        "start",
        10_000,
    ));
    let _ = engine.drain_outputs();
    let t_br = engine.clock.unix_ms();

    engine.menu_action(MenuActionRecord {
        application: bitwarden_app,
        exe_name: Some("bitwarden.exe".to_string()),
        path: vec!["File".to_string(), "Quit".to_string()],
        truncated: false,
        observed_at_ms: t_br,
        private_state: "normal".to_string(),
        stamp: engine.stamp(),
        field_security: "strict".to_string(),
    });
    engine.menu_action(MenuActionRecord {
        application: arc_app.clone(),
        exe_name: Some("arc.exe".to_string()),
        path: vec!["File".to_string(), "New Tab".to_string()],
        truncated: false,
        observed_at_ms: t_br,
        private_state: "normal".to_string(),
        stamp: engine.stamp(),
        field_security: "strict".to_string(),
    });
    assert!(
        emitted_messages(engine.drain_outputs()).is_empty(),
        "Bitwarden and browser menu with privateState=normal must be rejected"
    );

    engine.menu_action(MenuActionRecord {
        application: arc_app,
        exe_name: Some("arc.exe".to_string()),
        path: vec!["File".to_string(), "New Tab".to_string()],
        truncated: false,
        observed_at_ms: t_br,
        private_state: "user-authorized".to_string(),
        stamp: engine.stamp(),
        field_security: "strict".to_string(),
    });
    let arc_msgs = emitted_messages(engine.drain_outputs());
    assert_eq!(arc_msgs.len(), 1);
    validator
        .encode_frame(&arc_msgs[0])
        .expect("authorized browser menu.action wire valid");
}

#[test]
fn engine_application_anchor_bumps_epoch_across_app_switch_and_excluded_app() {
    let validator = ContractValidator::new().unwrap();
    let clock = MockClock::new(120_000, 1_700_000_010_100);
    let mut engine = CollectorEngine::new(
        "owner-anc",
        "inst-anc",
        "dev-anc",
        "wts-1",
        "winsta0-default-wts-1",
        false,
        MockEnv::unlocked(),
        clock,
        validator.clone(),
    );

    let policy = CapturePolicy {
        enabled: true,
        application_scope: Some("denylist".to_string()),
        input_activity: Some(true),
        menu_actions: Some(true),
        debounce_ms: 10,
        max_wait_ms: 50,
        read_timeout_ms: 2_000,
        ..CapturePolicy::default()
    };
    engine.receive(&configure_msg("owner-anc", "inst-anc", 1, &policy));
    engine.receive(&control_msg("owner-anc", "inst-anc", 1, "start", 10_000));
    let _ = engine.drain_outputs();

    let app_a = ApplicationIdentity {
        application_id: "notepad.exe".to_string(),
        process_id: 1001,
        process_start_time: "unix-ms:1700000000000.000".to_string(),
    };
    let app_b = ApplicationIdentity {
        application_id: "code.exe".to_string(),
        process_id: 2002,
        process_start_time: "unix-ms:1700000000001.000".to_string(),
    };

    // 1. Anchor epoch E1 to App A via menu.action.
    let epoch1 = engine.capture_epoch();
    let t1 = engine.clock.unix_ms();
    engine.menu_action(MenuActionRecord {
        application: app_a.clone(),
        exe_name: Some("notepad.exe".to_string()),
        path: vec!["File".to_string(), "Save".to_string()],
        truncated: false,
        observed_at_ms: t1,
        private_state: "normal".to_string(),
        stamp: engine.stamp(),
        field_security: "strict".to_string(),
    });
    let m1 = emitted_messages(engine.drain_outputs());
    assert_eq!(m1.len(), 1);
    assert_eq!(
        m1[0]
            .get("stamp")
            .and_then(|s| s.get("captureEpoch"))
            .and_then(JsonValue::as_i64),
        Some(epoch1)
    );

    // 2. A menu.action for App B carrying epoch1 MUST be dropped (never 2 apps in 1 epoch!).
    engine.menu_action(MenuActionRecord {
        application: app_b.clone(),
        exe_name: Some("code.exe".to_string()),
        path: vec!["File".to_string(), "Open".to_string()],
        truncated: false,
        observed_at_ms: t1,
        private_state: "normal".to_string(),
        stamp: engine.stamp(),
        field_security: "strict".to_string(),
    });
    assert!(emitted_messages(engine.drain_outputs()).is_empty());

    // 3. Switch to excluded app via ReadResult ("application-excluded") MUST bump captureEpoch
    // so subsequent App B observation NEVER shares epoch1 with App A!
    engine.clock.advance(60);
    engine.tick(true);
    let excl_ticket = engine.environment.launched.pop().expect("ticket");
    let t_excl = engine.clock.unix_ms();
    engine.complete(ReadResult::failure(
        excl_ticket.token,
        "application-excluded",
        Some(GapDiagnostic::new(GapDiagnosticCode::ApplicationNotAllowed, None)),
        t_excl,
        t_excl,
    ));
    let epoch2 = engine.capture_epoch();
    assert!(
        epoch2 > epoch1,
        "application-excluded after anchored App A MUST bump captureEpoch"
    );
    let _ = engine.drain_outputs();

    // 4. Now App B emits cleanly in epoch2, and RawInputNotice::ExcludedApplication bumps to epoch3!
    let t2 = engine.clock.unix_ms();
    engine.menu_action(MenuActionRecord {
        application: app_b.clone(),
        exe_name: Some("code.exe".to_string()),
        path: vec!["File".to_string(), "Save All".to_string()],
        truncated: false,
        observed_at_ms: t2,
        private_state: "normal".to_string(),
        stamp: engine.stamp(),
        field_security: "strict".to_string(),
    });
    let m2 = emitted_messages(engine.drain_outputs());
    assert_eq!(m2.len(), 1);
    assert_eq!(
        m2[0]
            .get("stamp")
            .and_then(|s| s.get("captureEpoch"))
            .and_then(JsonValue::as_i64),
        Some(epoch2)
    );
    validator.encode_frame(&m2[0]).expect("epoch2 menu valid");

    engine.environment.poll_notices.push(RawInputNotice::Activity {
        sample: InputActivitySample {
            application: app_b,
            exe_name: Some("code.exe".to_string()),
            category: InputActivityCategory::PointerRelease,
            callback_time_ms: t2,
        },
        resolved: ResolvedAppIdentity::from_single("code.exe".to_string()).unwrap(),
    });
    engine
        .environment
        .poll_notices
        .push(RawInputNotice::ExcludedApplication);
    engine.poll_environment();
    assert!(
        engine.capture_epoch() > epoch2,
        "ExcludedApplication notice MUST discard buffered activity and bump captureEpoch"
    );
    engine.clock.advance(1_000);
    engine.tick(true);
    let after_excl = emitted_messages(engine.drain_outputs());
    assert!(
        !after_excl.iter().any(|m| {
            m.get("payload")
                .and_then(|p| p.get("kind"))
                .and_then(JsonValue::as_str)
                == Some("input.activity")
        }),
        "activity buffered before ExcludedApplication MUST NOT flush after switch"
    );
}

#[test]
fn engine_desktop_no_auto_resume_with_input_activity_vs_auto_resume_with_menu_actions_only() {
    let validator = ContractValidator::new().unwrap();

    // Case A: inputActivity = true -> desktop lock pauses AND desktop unlock MUST NEVER auto-resume!
    let clock_a = MockClock::new(140_000, 1_700_000_020_000);
    let mut engine_a = CollectorEngine::new(
        "owner-desk-a",
        "inst-desk-a",
        "dev-desk",
        "wts-1",
        "winsta0-default-wts-1",
        false,
        MockEnv::unlocked(),
        clock_a,
        validator.clone(),
    );
    let policy_input = CapturePolicy {
        enabled: true,
        input_activity: Some(true),
        menu_actions: Some(true),
        ..CapturePolicy::default()
    };
    engine_a.receive(&configure_msg("owner-desk-a", "inst-desk-a", 1, &policy_input));
    engine_a.receive(&control_msg("owner-desk-a", "inst-desk-a", 1, "start", 10_000));
    let _ = engine_a.drain_outputs();
    assert_eq!(engine_a.state(), "running");

    engine_a.environment.desktop = DesktopStatus::Locked;
    engine_a.environment.desktop_reason = "screen-locked".to_string();
    engine_a.desktop_changed(DesktopStatus::Locked, false);
    assert_eq!(engine_a.state(), "paused");
    let _ = engine_a.drain_outputs();

    // Desktop unlocks -> MUST stay paused, ZERO `{type:"state",requestId:"desktop",state:"running"}`!
    engine_a.environment.desktop = DesktopStatus::Unlocked;
    engine_a.environment.desktop_reason = "ready".to_string();
    engine_a.desktop_changed(DesktopStatus::Unlocked, true);
    assert_eq!(
        engine_a.state(),
        "paused",
        "inputActivity enabled MUST stay paused on desktop unlock (Host Invariant #3)"
    );
    let unlock_msgs_a = emitted_messages(engine_a.drain_outputs());
    assert!(
        !unlock_msgs_a.iter().any(|m| {
            m.get("type").and_then(JsonValue::as_str) == Some("state")
                && m.get("state").and_then(JsonValue::as_str) == Some("running")
        }),
        "MUST NEVER auto-emit running state on desktop unlock when inputActivity=true"
    );

    // Explicit owner `resume` restores running cleanly; then monitor failure pauses via input_activity_unavailable.
    engine_a.receive(&control_msg("owner-desk-a", "inst-desk-a", 1, "resume", 10_000));
    let _ = engine_a.drain_outputs();
    assert_eq!(engine_a.state(), "running");

    engine_a.environment.input_activity_healthy = false;
    engine_a.tick(true);
    assert_eq!(engine_a.state(), "paused");
    let fault_msgs = emitted_messages(engine_a.drain_outputs());
    assert_eq!(
        fault_msgs[0].get("reason").and_then(JsonValue::as_str),
        Some("input-monitoring-disabled")
    );
    validator.encode_frame(&fault_msgs[0]).expect("fault wire valid");

    // Case B: menuActions = true ONLY (inputActivity = false, inputText = false) -> desktop unlock
    // DOES auto-resume cleanly!
    let clock_b = MockClock::new(150_000, 1_700_000_030_000);
    let mut engine_b = CollectorEngine::new(
        "owner-desk-b",
        "inst-desk-b",
        "dev-desk",
        "wts-1",
        "winsta0-default-wts-1",
        false,
        MockEnv::unlocked(),
        clock_b,
        validator.clone(),
    );
    let policy_menu_only = CapturePolicy {
        enabled: true,
        input_activity: Some(false),
        input_text: Some(false),
        menu_actions: Some(true),
        ..CapturePolicy::default()
    };
    engine_b.receive(&configure_msg(
        "owner-desk-b",
        "inst-desk-b",
        1,
        &policy_menu_only,
    ));
    engine_b.receive(&control_msg("owner-desk-b", "inst-desk-b", 1, "start", 10_000));
    let _ = engine_b.drain_outputs();
    assert_eq!(engine_b.state(), "running");

    engine_b.environment.desktop = DesktopStatus::Locked;
    engine_b.environment.desktop_reason = "screen-locked".to_string();
    engine_b.desktop_changed(DesktopStatus::Locked, false);
    assert_eq!(engine_b.state(), "paused");
    let _ = engine_b.drain_outputs();

    engine_b.environment.desktop = DesktopStatus::Unlocked;
    engine_b.environment.desktop_reason = "ready".to_string();
    engine_b.desktop_changed(DesktopStatus::Unlocked, true);
    assert_eq!(
        engine_b.state(),
        "running",
        "menuActions-only MUST auto-resume on desktop unlock"
    );
    let unlock_msgs_b = emitted_messages(engine_b.drain_outputs());
    assert_eq!(unlock_msgs_b.len(), 1);
    assert_eq!(
        unlock_msgs_b[0].get("requestId").and_then(JsonValue::as_str),
        Some("desktop")
    );
    assert_eq!(
        unlock_msgs_b[0].get("state").and_then(JsonValue::as_str),
        Some("running")
    );
    assert_eq!(
        unlock_msgs_b[0].get("reason").and_then(JsonValue::as_str),
        Some("desktop-unlocked")
    );
    validator
        .encode_frame(&unlock_msgs_b[0])
        .expect("desktop unlock state wire valid");
}

#[test]
fn worker_ipc_pipe_batch_precedence_unsolicited_priority_and_read_only_enablement() {
    // 1. Pipe batch precedence: `inputDisabled` > `secureInput` > content frames.
    let content = br#"{"token":"t-1","captureStartMs":1,"captureEndMs":2}"#;
    let dirty = br#"{"dirty":true}"#;
    let secure = br#"{"secureInput":true}"#;
    let disabled = br#"{"inputDisabled":"input-monitoring-disabled"}"#;

    assert_eq!(
        classify_session_pipe_batch(&[content, dirty, secure, disabled]),
        SessionBatchPrecedence::InputDisabled("input-monitoring-disabled".to_string())
    );
    assert_eq!(
        classify_session_pipe_batch(&[content, dirty, secure]),
        SessionBatchPrecedence::SecureInput
    );
    assert_eq!(
        classify_session_pipe_batch(&[content, dirty]),
        SessionBatchPrecedence::Normal
    );

    // 2. Unsolicited frame priority: `menuAction` > `menuTracking` > `submitDirty` > debounced `dirty`.
    struct FakeSource {
        menu_action: Option<MenuActionRecord>,
        menu_tracking: Option<bool>,
        submit_dirty: bool,
        dirty: bool,
    }
    let rec = MenuActionRecord {
        application: ApplicationIdentity {
            application_id: "notepad.exe".to_string(),
            process_id: 5150,
            process_start_time: "unix-ms:1700000000000.000".to_string(),
        },
        exe_name: Some("notepad.exe".to_string()),
        path: vec!["File".to_string(), "Exit".to_string()],
        truncated: false,
        observed_at_ms: 1_700_000_000_500,
        private_state: "normal".to_string(),
        stamp: Stamp {
            capture_epoch: 1,
            foreground_generation: 0,
            focus_generation: 1,
            policy_revision: 1,
        },
        field_security: "strict".to_string(),
    };
    assert!(encode_menu_action_pipe_frame(&rec).is_some());

    let mut src = FakeSource {
        menu_action: Some(rec),
        menu_tracking: Some(false),
        submit_dirty: true,
        dirty: true,
    };
    let mut next_dirty_ms = 0i64;

    let f1 = next_session_unsolicited_frame(
        &mut src,
        |s| s.menu_action.take(),
        |s| s.menu_tracking.take(),
        |s| std::mem::take(&mut s.submit_dirty),
        |s| std::mem::take(&mut s.dirty),
        1_000,
        &mut next_dirty_ms,
        20,
    )
    .expect("1st frame must be menuAction");
    let p1 = JsonValue::parse(&f1[..f1.len() - 1]).unwrap();
    let decoded_rec = MenuActionRecord::from_json(p1.get("menuAction").unwrap()).unwrap();
    assert_eq!(decoded_rec.exe_name.as_deref(), Some("notepad.exe"));
    assert_eq!(decoded_rec.path, vec!["File", "Exit"]);

    let f2 = next_session_unsolicited_frame(
        &mut src,
        |s| s.menu_action.take(),
        |s| s.menu_tracking.take(),
        |s| std::mem::take(&mut s.submit_dirty),
        |s| std::mem::take(&mut s.dirty),
        1_000,
        &mut next_dirty_ms,
        20,
    )
    .expect("2nd frame must be menuTracking");
    assert_eq!(f2, b"{\"menuTracking\":false}\n");

    let f3 = next_session_unsolicited_frame(
        &mut src,
        |s| s.menu_action.take(),
        |s| s.menu_tracking.take(),
        |s| std::mem::take(&mut s.submit_dirty),
        |s| std::mem::take(&mut s.dirty),
        1_000,
        &mut next_dirty_ms,
        20,
    )
    .expect("3rd frame must be submitDirty");
    assert_eq!(f3, b"{\"submitDirty\":true}\n");

    let f4 = next_session_unsolicited_frame(
        &mut src,
        |s| s.menu_action.take(),
        |s| s.menu_tracking.take(),
        |s| std::mem::take(&mut s.submit_dirty),
        |s| std::mem::take(&mut s.dirty),
        1_000,
        &mut next_dirty_ms,
        20,
    )
    .expect("4th frame must be dirty");
    assert_eq!(f4, b"{\"dirty\":true}\n");
    assert_eq!(next_dirty_ms, 1_050, "dirty debounce floor is 50ms");

    // Dirty before cooldown expires is suppressed; after cooldown passes it emits.
    src.dirty = true;
    assert!(next_session_unsolicited_frame(
        &mut src,
        |s| s.menu_action.take(),
        |s| s.menu_tracking.take(),
        |s| std::mem::take(&mut s.submit_dirty),
        |s| std::mem::take(&mut s.dirty),
        1_049,
        &mut next_dirty_ms,
        20,
    )
    .is_none());
    assert!(src.dirty, "debounced dirty must remain pending until due");
    let f5 = next_session_unsolicited_frame(
        &mut src,
        |s| s.menu_action.take(),
        |s| s.menu_tracking.take(),
        |s| std::mem::take(&mut s.submit_dirty),
        |s| std::mem::take(&mut s.dirty),
        1_050,
        &mut next_dirty_ms,
        20,
    )
    .expect("dirty fires once debounce elapses");
    assert_eq!(f5, b"{\"dirty\":true}\n");

    // 3. Submit-dirty fast read sets `focused_fast_only: Some(true)` WITHOUT wrongly setting
    // `read_only_ax_enablement: Some(true)`.
    let validator = ContractValidator::new().unwrap();
    let clock = MockClock::new(160_000, 1_700_000_040_000);
    let mut engine = CollectorEngine::new(
        "owner-ro",
        "inst-ro",
        "dev-ro",
        "wts-1",
        "winsta0-default-wts-1",
        false,
        MockEnv::unlocked(),
        clock,
        validator,
    );
    let policy = CapturePolicy {
        enabled: true,
        menu_actions: Some(true),
        ..CapturePolicy::default()
    };
    engine.receive(&configure_msg("owner-ro", "inst-ro", 1, &policy));
    engine.receive(&control_msg("owner-ro", "inst-ro", 1, "start", 10_000));
    let _ = engine.drain_outputs();
    engine.worker_submit_dirty();
    engine.tick(true);
    let fast_ticket = engine.environment.launched.pop().expect("fast ticket launched");
    assert_eq!(fast_ticket.focused_fast_only, Some(true));
    assert_eq!(fast_ticket.read_only_ax_enablement, None);
}

#[test]
fn engine_repeated_excluded_application_notices_do_not_thrash_workers_or_bump_epoch() {
    let validator = ContractValidator::new().unwrap();
    let clock = MockClock::new(200_000, 1_700_000_050_000);
    let mut engine = CollectorEngine::new(
        "owner-excl",
        "inst-excl",
        "dev-excl",
        "wts-1",
        "winsta0-default-wts-1",
        false,
        MockEnv::unlocked(),
        clock,
        validator,
    );
    let policy = CapturePolicy {
        enabled: true,
        application_scope: Some("denylist".to_string()),
        input_activity: Some(true),
        menu_actions: Some(true),
        debounce_ms: 50,
        max_wait_ms: 250,
        read_timeout_ms: 500,
        ..CapturePolicy::default()
    };
    engine.receive(&configure_msg("owner-excl", "inst-excl", 1, &policy));
    engine.receive(&control_msg("owner-excl", "inst-excl", 1, "start", 10_000));
    let _ = engine.drain_outputs();

    // Advance past max_wait_ms (250ms) to launch the initial read.
    engine.clock.advance(250);
    engine.tick(true);
    assert_eq!(engine.environment.launched.len(), 1);
    let epoch_before = engine.capture_epoch();
    let cancels_before = engine.environment.cancelled;

    // 1. First transition onto an excluded app MUST bump epoch once, cancel the in-flight read,
    // and schedule the next read with reconciliation spacing (NOT immediate).
    engine.excluded_application_event();
    let epoch_after_first = engine.capture_epoch();
    assert_eq!(epoch_after_first, epoch_before + 1);
    assert_eq!(engine.environment.cancelled, cancels_before + 1);

    // Next immediate tick (10ms later) must NOT launch a new worker.
    engine.clock.advance(10);
    engine.tick(true);
    assert_eq!(
        engine.environment.launched.len(),
        1,
        "first excluded boundary must space next read by reconciliation_spacing"
    );

    // 2. Repeated ExcludedApplication notices arriving every 10ms while already excluded must
    // NOT bump capture_epoch, cancel workers, or spawn/kill workers in a loop.
    let cancels_after_first = engine.environment.cancelled;
    for _ in 0..10 {
        engine.environment.poll_notices.push(RawInputNotice::ExcludedApplication);
        engine.poll_environment();
        engine.tick(true);
        engine.clock.advance(10);
    }
    assert_eq!(
        engine.capture_epoch(),
        epoch_after_first,
        "repeated ExcludedApplication notices while already excluded must not bump captureEpoch"
    );
    assert_eq!(
        engine.environment.cancelled, cancels_after_first,
        "repeated ExcludedApplication notices while already excluded must not cancel idle workers"
    );
    assert_eq!(
        engine.environment.launched.len(),
        1,
        "repeated ExcludedApplication notices within 100ms must not spawn/thrash workers"
    );

    // 3. Reconciliation polling is still NOT starved once reconciliation_spacing elapses.
    engine.clock.advance(1_000);
    engine.tick(true);
    assert_eq!(
        engine.environment.launched.len(),
        2,
        "reconciliation poll should still fire once reconciliation_spacing elapses"
    );
}

#[test]
fn engine_p0_1_verified_normal_browser_token_lifecycle_and_clearing() {
    let validator = ContractValidator::new().unwrap();
    let clock = MockClock::new(210_000, 1_700_000_060_000);
    let mut engine = CollectorEngine::new(
        "owner-vnb",
        "inst-vnb",
        "dev-vnb",
        "wts-1",
        "winsta0-default-wts-1",
        false,
        MockEnv::unlocked(),
        clock,
        validator.clone(),
    );
    let policy = CapturePolicy {
        enabled: true,
        application_scope: Some("denylist".to_string()),
        allow_browser_content: Some(true),
        input_activity: Some(true),
        menu_actions: Some(true),
        debounce_ms: 10,
        max_wait_ms: 50,
        read_timeout_ms: 2_000,
        ..CapturePolicy::default()
    };
    engine.receive(&configure_msg("owner-vnb", "inst-vnb", 1, &policy));
    engine.receive(&control_msg("owner-vnb", "inst-vnb", 1, "start", 10_000));
    let _ = engine.drain_outputs();
    assert!(engine.environment.verified_normal_browser.is_none());

    // 1. ReadResult JSON round-trips internal `verifiedNormalBrowser` using SHA-256 digest +
    // UTF-16 length (constant ~150B, ZERO plaintext title in JSON or Debug output!) and drops invalid tokens.
    let chrome_app = ApplicationIdentity {
        application_id: "chrome.exe".to_string(),
        process_id: 6101,
        process_start_time: "unix-ms:1700000000000.000".to_string(),
    };
    let secret_long_title = format!("{} - Docs - Google Chrome", "T".repeat(4000));
    let good_tok = VerifiedNormalBrowserWindow::from_ephemeral_title(
        0x1234,
        6101,
        "unix-ms:1700000000000.000".to_string(),
        &secret_long_title,
    )
    .expect("valid digest token for 4000+ UTF-16 title");
    assert_eq!(good_tok.title_sha256.len(), 64);
    assert_eq!(good_tok.title_utf16_len as usize, secret_long_title.encode_utf16().count());
    assert!(
        !format!("{good_tok:?}").contains("Docs - Google Chrome"),
        "Debug output MUST NEVER leak raw window title"
    );
    let make_browser_res = |token: String, now_u: i64, vnb: Option<VerifiedNormalBrowserWindow>| {
        ReadResult {
            token,
            application: Some(chrome_app.clone()),
            diagnostic_application: Some(chrome_app.clone()),
            exe_name: Some("chrome.exe".to_string()),
            text: Some(TextRead {
                text: "hello browser".to_string(),
                source: "uia.text".to_string(),
                total_length: Some(13),
                selection: None,
                range_start: 0,
                range_basis: "prefix".to_string(),
                complete: true,
                truncated: false,
                missing_reasons: vec![],
                read_units: None,
            }),
            reason: None,
            diagnostic: None,
            enablement: None,
            session_identity: Some(WorkerSurfaceIdentity {
                session_id: "s-vnb".to_string(),
                window_id: "w-vnb".to_string(),
                node_id: "n-vnb".to_string(),
                surface_id: "surf-vnb".to_string(),
                window_generation: 1,
                focus_generation: 1,
            }),
            surface: None,
            selection: None,
            input_records: Vec::new(),
            input_gaps: Vec::new(),
            private_state: Some("user-authorized".to_string()),
            observer_status: Some("best-effort".to_string()),
            focus_absent: None,
            surface_failure: None,
            verified_normal_browser: vnb,
            capture_start_ms: now_u,
            capture_end_ms: now_u,
        }
    };

    let rt_sample = make_browser_res("tok-rt".to_string(), 1_700_000_060_000, Some(good_tok.clone()));
    let rt_json = rt_sample.to_json();
    let vnb_json = rt_json
        .get("verifiedNormalBrowser")
        .expect("verifiedNormalBrowser present");
    let vnb_bytes = vnb_json.canonical_bytes().unwrap();
    assert!(
        vnb_bytes.len() < 256,
        "verifiedNormalBrowser JSON must remain constant small size (<256 B), got {} B",
        vnb_bytes.len()
    );
    assert!(
        !std::str::from_utf8(&vnb_bytes)
            .unwrap()
            .contains("Docs - Google Chrome"),
        "verifiedNormalBrowser IPC JSON must contain ZERO plaintext title"
    );
    assert_eq!(
        ReadResult::from_json(&rt_json),
        Some(rt_sample),
        "internal ReadResult pipe JSON must round-trip valid verifiedNormalBrowser"
    );
    let invalid_tok = VerifiedNormalBrowserWindow {
        title_sha256: "INVALID_HEX".to_string(),
        ..good_tok.clone()
    };
    let invalid_res = make_browser_res("tok-bad".to_string(), 1_700_000_060_000, Some(invalid_tok));
    assert!(
        invalid_res.to_json().get("verifiedNormalBrowser").is_none(),
        "invalid verifiedNormalBrowser digest token MUST NEVER serialize"
    );

    // 2. Clean browser read with matching verified token populates environment token (and NEVER
    // leaks `verifiedNormalBrowser` on external stdout protocol frames!).
    engine.clock.advance(60);
    engine.tick(true);
    let t1 = engine.environment.launched.pop().expect("t1");
    let u1 = engine.clock.unix_ms();
    engine.complete(make_browser_res(t1.token, u1, Some(good_tok.clone())));
    assert_eq!(engine.environment.verified_normal_browser, Some(good_tok.clone()));
    for msg in emitted_messages(engine.drain_outputs()) {
        let bytes = validator.encode_frame(&msg).expect("wire valid");
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(
            !text.contains("verifiedNormalBrowser"),
            "verifiedNormalBrowser MUST NEVER appear on external stdout wire: {text}"
        );
    }

    // 3. BrowserExcluded read failure MUST clear `verified_normal_browser` immediately!
    engine.clock.advance(1_200);
    engine.tick(true);
    let t2 = engine.environment.launched.pop().expect("t2");
    let u2 = engine.clock.unix_ms();
    engine.complete(ReadResult::failure(
        t2.token,
        "policy-boundary",
        Some(GapDiagnostic::new(GapDiagnosticCode::BrowserExcluded, None)),
        u2,
        u2,
    ));
    assert_eq!(
        engine.environment.verified_normal_browser, None,
        "BrowserExcluded MUST clear verified_normal_browser immediately"
    );
    let _ = engine.drain_outputs();

    // 4. Re-verify browser, then confirm mismatched PID token clears it, and excluded_application_event clears it!
    engine.clock.advance(1_200);
    engine.tick(true);
    let t3 = engine.environment.launched.pop().expect("t3");
    let u3 = engine.clock.unix_ms();
    let bad_pid_tok = VerifiedNormalBrowserWindow {
        effective_pid: 9999,
        ..good_tok.clone()
    };
    engine.complete(make_browser_res(t3.token, u3, Some(bad_pid_tok)));
    assert_eq!(
        engine.environment.verified_normal_browser, None,
        "mismatched PID token MUST NOT be accepted"
    );
    let _ = engine.drain_outputs();

    engine.clock.advance(1_200);
    engine.tick(true);
    let t4 = engine.environment.launched.pop().expect("t4");
    let u4 = engine.clock.unix_ms();
    engine.complete(make_browser_res(t4.token, u4, Some(good_tok.clone())));
    assert_eq!(engine.environment.verified_normal_browser, Some(good_tok));
    let _ = engine.drain_outputs();

    engine.excluded_application_event();
    assert_eq!(
        engine.environment.verified_normal_browser, None,
        "excluded_application_event MUST clear verified_normal_browser"
    );
}

#[test]
fn engine_p1_11_policy_boundary_clears_menu_tracking_and_p1_12_return_from_excluded_schedules_fast() {
    let validator = ContractValidator::new().unwrap();
    let clock = MockClock::new(220_000, 1_700_000_070_000);
    let mut engine = CollectorEngine::new(
        "owner-p1112",
        "inst-p1112",
        "dev-p1112",
        "wts-1",
        "winsta0-default-wts-1",
        false,
        MockEnv::unlocked(),
        clock,
        validator.clone(),
    );
    let policy = CapturePolicy {
        enabled: true,
        application_scope: Some("denylist".to_string()),
        input_activity: Some(true),
        menu_actions: Some(true),
        debounce_ms: 10,
        max_wait_ms: 50,
        read_timeout_ms: 2_000,
        ..CapturePolicy::default()
    };
    engine.receive(&configure_msg("owner-p1112", "inst-p1112", 1, &policy));
    engine.receive(&control_msg("owner-p1112", "inst-p1112", 1, "start", 10_000));
    let _ = engine.drain_outputs();

    // P1-11: An in-flight read completing with `"policy-boundary"` while `menu_tracking_until_ms`
    // is active MUST clear `menu_tracking_until_ms` so reads are NOT suppressed for 10 seconds!
    engine.clock.advance(60);
    engine.tick(true);
    let t1 = engine.environment.launched.pop().expect("t1");
    engine.worker_menu_tracking(true);
    let u1 = engine.clock.unix_ms();
    engine.complete(ReadResult::failure(
        t1.token,
        "policy-boundary",
        Some(GapDiagnostic::new(GapDiagnosticCode::SecureField, None)),
        u1,
        u1,
    ));
    let _ = engine.drain_outputs();

    // Advance reconciliation spacing (1_000ms < 10_000ms menu tracking ceiling) and tick:
    // if `menu_tracking_until_ms` had NOT been cleared, tick() would return early for 10s!
    engine.clock.advance(1_100);
    engine.tick(true);
    let t2 = engine
        .environment
        .launched
        .pop()
        .expect("policy-boundary MUST clear menu_tracking_until_ms so next read is not blocked 10s");
    let u2 = engine.clock.unix_ms();
    let app_a = ApplicationIdentity {
        application_id: "notepad.exe".to_string(),
        process_id: 7101,
        process_start_time: "unix-ms:1700000000000.000".to_string(),
    };
    let app_b = ApplicationIdentity {
        application_id: "code.exe".to_string(),
        process_id: 7102,
        process_start_time: "unix-ms:1700000000001.000".to_string(),
    };
    engine.complete(ReadResult {
        token: t2.token,
        application: Some(app_a.clone()),
        diagnostic_application: Some(app_a),
        exe_name: Some("notepad.exe".to_string()),
        text: Some(TextRead {
            text: "hi".to_string(),
            source: "uia.text".to_string(),
            total_length: Some(2),
            selection: None,
            range_start: 0,
            range_basis: "prefix".to_string(),
            complete: true,
            truncated: false,
            missing_reasons: vec![],
            read_units: None,
        }),
        reason: None,
        diagnostic: None,
        enablement: None,
        session_identity: Some(WorkerSurfaceIdentity {
            session_id: "s-12".to_string(),
            window_id: "w-12".to_string(),
            node_id: "n-12".to_string(),
            surface_id: "surf-12".to_string(),
            window_generation: 1,
            focus_generation: 1,
        }),
        surface: None,
        selection: None,
        input_records: Vec::new(),
        input_gaps: Vec::new(),
        private_state: Some("normal".to_string()),
        observer_status: Some("best-effort".to_string()),
        focus_absent: None,
        surface_failure: None,
        verified_normal_browser: None,
        capture_start_ms: u2,
        capture_end_ms: u2,
    });
    let _ = engine.drain_outputs();

    // P1-12: Switch to excluded app -> bumps capture_epoch once, clears observed_application,
    // schedules reconciliation read at now + 1000ms.
    let epoch_before_excl = engine.capture_epoch();
    engine.excluded_application_event();
    let epoch_after_excl = engine.capture_epoch();
    assert_eq!(epoch_after_excl, epoch_before_excl + 1);
    let _ = engine.drain_outputs();

    // 20ms later, user returns to allowed App B and generates input_activity:
    // MUST emit `context.changed(reason: "application")` at `epoch_after_excl` (WITHOUT bumping
    // captureEpoch again) and schedule a prompt worker read (~50ms instead of waiting 1000ms)!
    engine.clock.advance(20);
    let t_ret = engine.clock.unix_ms();
    engine.input_activity(InputActivitySample {
        application: app_b,
        exe_name: Some("code.exe".to_string()),
        category: InputActivityCategory::PointerRelease,
        callback_time_ms: t_ret,
    });
    assert_eq!(
        engine.capture_epoch(),
        epoch_after_excl,
        "returning from excluded app must NOT bump captureEpoch a second time"
    );
    let ret_msgs = emitted_messages(engine.drain_outputs());
    let ctx_app = ret_msgs
        .iter()
        .find(|m| {
            m.get("payload")
                .and_then(|p| p.get("kind"))
                .and_then(JsonValue::as_str)
                == Some("context.changed")
                && m.get("payload")
                    .and_then(|p| p.get("reason"))
                    .and_then(JsonValue::as_str)
                    == Some("application")
        })
        .expect("returning from excluded app via input_activity MUST emit context.changed(application)");
    assert_eq!(
        ctx_app
            .get("stamp")
            .and_then(|s| s.get("captureEpoch"))
            .and_then(JsonValue::as_i64),
        Some(epoch_after_excl)
    );
    validator.encode_frame(ctx_app).expect("wire valid");

    // Advancing only 60ms (well under 1000ms reconciliation spacing) MUST launch the worker!
    engine.clock.advance(60);
    engine.tick(true);
    assert_eq!(
        engine.environment.launched.len(),
        1,
        "returning from excluded app MUST call schedule() to spin up worker promptly"
    );
}

#[test]
fn engine_p2_12_no_double_lock_boundary_worker_exit_advances_anchor_and_invalid_menu_no_mutate() {
    let validator = ContractValidator::new().unwrap();

    // 1. Desktop lock (`Locked` -> `Unknown` 250ms later) MUST NOT run a second `boundary()` or
    // emit a redundant `state: paused`!
    let clock1 = MockClock::new(230_000, 1_700_000_080_000);
    let mut engine1 = CollectorEngine::new(
        "owner-p212a",
        "inst-p212a",
        "dev-p212a",
        "wts-1",
        "winsta0-default-wts-1",
        false,
        MockEnv::unlocked(),
        clock1,
        validator.clone(),
    );
    let policy = CapturePolicy {
        enabled: true,
        application_scope: Some("denylist".to_string()),
        input_activity: Some(true),
        menu_actions: Some(true),
        debounce_ms: 10,
        max_wait_ms: 50,
        read_timeout_ms: 200,
        ..CapturePolicy::default()
    };
    engine1.receive(&configure_msg("owner-p212a", "inst-p212a", 1, &policy));
    engine1.receive(&control_msg("owner-p212a", "inst-p212a", 1, "start", 10_000));
    let _ = engine1.drain_outputs();

    engine1.environment.desktop = DesktopStatus::Locked;
    engine1.environment.desktop_reason = "screen-locked".to_string();
    engine1.desktop_changed(DesktopStatus::Locked, false);
    assert_eq!(engine1.state(), "paused");
    let epoch_after_lock = engine1.capture_epoch();
    let cancels_after_lock = engine1.environment.cancelled;
    let lock_msgs = emitted_messages(engine1.drain_outputs());
    assert_eq!(lock_msgs.len(), 1);
    assert_eq!(
        lock_msgs[0].get("state").and_then(JsonValue::as_str),
        Some("paused")
    );

    // 250ms later, `validate_before_accept()` returns `Unknown` (from latched boundary):
    // MUST NOT bump captureEpoch, cancel again, or emit a second `state: paused`!
    engine1.clock.advance(250);
    engine1.environment.desktop = DesktopStatus::Unknown;
    engine1.environment.desktop_reason = "desktop-lock-transition".to_string();
    engine1.desktop_changed(DesktopStatus::Unknown, false);
    assert_eq!(engine1.capture_epoch(), epoch_after_lock);
    assert_eq!(engine1.environment.cancelled, cancels_after_lock);
    assert!(
        emitted_messages(engine1.drain_outputs()).is_empty(),
        "Locked -> Unknown while already paused MUST NOT emit redundant state: paused"
    );

    // 2. Unexpected worker exit (`read-error` with `diagnostic: None`) AND read timeout
    // (`expire_read`) advance `capture_epoch` & clear `epoch_application_anchor` when anchored!
    let clock2 = MockClock::new(240_000, 1_700_000_090_000);
    let mut engine2 = CollectorEngine::new(
        "owner-p212b",
        "inst-p212b",
        "dev-p212b",
        "wts-1",
        "winsta0-default-wts-1",
        false,
        MockEnv::unlocked(),
        clock2,
        validator.clone(),
    );
    engine2.receive(&configure_msg("owner-p212b", "inst-p212b", 1, &policy));
    engine2.receive(&control_msg("owner-p212b", "inst-p212b", 1, "start", 10_000));
    let _ = engine2.drain_outputs();

    let app_a = ApplicationIdentity {
        application_id: "notepad.exe".to_string(),
        process_id: 8101,
        process_start_time: "unix-ms:1700000000000.000".to_string(),
    };
    let app_b = ApplicationIdentity {
        application_id: "code.exe".to_string(),
        process_id: 8102,
        process_start_time: "unix-ms:1700000000001.000".to_string(),
    };
    let t_a = engine2.clock.unix_ms();
    engine2.menu_action(MenuActionRecord {
        application: app_a.clone(),
        exe_name: Some("notepad.exe".to_string()),
        path: vec!["File".to_string(), "Save".to_string()],
        truncated: false,
        observed_at_ms: t_a,
        private_state: "normal".to_string(),
        stamp: engine2.stamp(),
        field_security: "strict".to_string(),
    });
    assert_eq!(emitted_messages(engine2.drain_outputs()).len(), 1);
    let epoch_a = engine2.capture_epoch();

    // Launch read and fail it with unexpected worker exit (`read-error`, `diagnostic: None`).
    engine2.clock.advance(60);
    engine2.tick(true);
    let crash_ticket = engine2.environment.launched.pop().expect("crash_ticket");
    let t_crash = engine2.clock.unix_ms();
    engine2.complete(ReadResult::failure(
        crash_ticket.token,
        "read-error",
        None,
        t_crash,
        t_crash,
    ));
    let epoch_after_crash = engine2.capture_epoch();
    assert!(
        epoch_after_crash > epoch_a,
        "unexpected worker exit with active anchor MUST advance captureEpoch"
    );
    let _ = engine2.drain_outputs();

    // Now App B can anchor cleanly in the new epoch; then read timeout advances boundary again!
    let t_b = engine2.clock.unix_ms();
    engine2.menu_action(MenuActionRecord {
        application: app_b.clone(),
        exe_name: Some("code.exe".to_string()),
        path: vec!["File".to_string(), "Open".to_string()],
        truncated: false,
        observed_at_ms: t_b,
        private_state: "normal".to_string(),
        stamp: engine2.stamp(),
        field_security: "strict".to_string(),
    });
    assert_eq!(emitted_messages(engine2.drain_outputs()).len(), 1);

    engine2.clock.advance(1_100);
    engine2.tick(true);
    let _timeout_ticket = engine2.environment.launched.pop().expect("timeout_ticket");
    engine2.clock.advance(250);
    engine2.tick(true);
    assert!(
        engine2.capture_epoch() > epoch_after_crash,
        "read timeout with active anchor MUST advance captureEpoch"
    );
    let _ = engine2.drain_outputs();

    // 3. Invalid `menu_action` failing `ContractValidator::validate_message` MUST NOT mutate
    // `observed_application` or `epoch_application_anchor`!
    let clock3 = MockClock::new(250_000, 1_700_000_100_000);
    let mut engine3 = CollectorEngine::new(
        "owner-p212c",
        "inst-p212c",
        "", // empty device_id causes target.deviceId schema validation to fail cleanly!
        "wts-1",
        "winsta0-default-wts-1",
        false,
        MockEnv::unlocked(),
        clock3,
        validator,
    );
    engine3.receive(&configure_msg("owner-p212c", "inst-p212c", 1, &policy));
    engine3.receive(&control_msg("owner-p212c", "inst-p212c", 1, "start", 10_000));
    let _ = engine3.drain_outputs();

    let t_bad = engine3.clock.unix_ms();
    engine3.menu_action(MenuActionRecord {
        application: app_a,
        exe_name: Some("notepad.exe".to_string()),
        path: vec!["File".to_string(), "Save".to_string()],
        truncated: false,
        observed_at_ms: t_bad,
        private_state: "normal".to_string(),
        stamp: engine3.stamp(),
        field_security: "strict".to_string(),
    });
    assert!(
        emitted_messages(engine3.drain_outputs()).is_empty(),
        "invalid wire message must be dropped"
    );
    // Restore valid `device_id` and submit App B at the SAME capture_epoch: if App A had mutated
    // `observed_application`/`epoch_application_anchor` before validation, App B would be dropped!
    engine3.device_id = "dev-valid".to_string();
    engine3.menu_action(MenuActionRecord {
        application: app_b,
        exe_name: Some("code.exe".to_string()),
        path: vec!["File".to_string(), "Save All".to_string()],
        truncated: false,
        observed_at_ms: t_bad,
        private_state: "normal".to_string(),
        stamp: engine3.stamp(),
        field_security: "strict".to_string(),
    });
    assert_eq!(
        emitted_messages(engine3.drain_outputs()).len(),
        1,
        "failed menu_action validation MUST NOT have polluted observed_application or epoch anchor"
    );
}

#[test]
fn worker_ipc_p2_14_malformed_json_during_retire_fails_ack_and_p2_13_large_ticket_drains() {
    // 1. P2-14: Malformed JSON while retiring MUST return `AckFailed` (so JobWorkerSupervisor
    // emits `WorkerEvent::InputDisabled("worker-retirement-ack-failed")` instead of silent cancel).
    let sess = "11111111-1111-4111-8111-111111111111";
    let ret = "22222222-2222-4222-8222-222222222222";
    assert_eq!(
        classify_retiring_session_frame(b"{malformed-json", sess, ret, true),
        RetiringFrameOutcome::AckFailed
    );
    assert_eq!(
        classify_retiring_session_frame(b"{\"menuAction\":{\"bad\":true}}", sess, ret, true),
        RetiringFrameOutcome::AckFailed
    );
    let valid_ack = format!("{{\"inputHealthy\":true,\"retired\":\"{ret}\",\"sessionToken\":\"{sess}\"}}");
    assert_eq!(
        classify_retiring_session_frame(valid_ack.as_bytes(), sess, ret, true),
        RetiringFrameOutcome::Acknowledged
    );
    assert_eq!(
        classify_retiring_session_frame(valid_ack.as_bytes(), sess, ret, false),
        RetiringFrameOutcome::AckFailed,
        "trailing bytes/frames after retired ack must fail closed"
    );
    assert_eq!(
        classify_retiring_session_frame(
            b"{\"token\":\"t1\",\"captureStartMs\":1,\"captureEndMs\":2}",
            sess,
            ret,
            false
        ),
        RetiringFrameOutcome::IgnoreInFlight,
        "valid in-flight ReadResult before retire ack is ignored cleanly"
    );
    assert_eq!(
        classify_retiring_session_frame(
            b"{\"inputDisabled\":\"input-monitoring-disabled\"}",
            sess,
            ret,
            true
        ),
        RetiringFrameOutcome::InputDisabled("input-monitoring-disabled".to_string())
    );

    // 2. P2-13: Live session worker drains >8 KiB ReadTicket frame in one bounded loop without
    // stalling, responds cleanly, and completes inert retire handshake with exit code 0!
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

    // Construct a >10 KiB ReadTicket (>8 KiB single chunk) using a long allowedApplicationIds list.
    let big_allowlist: Vec<String> = (0..400)
        .map(|i| format!("com.example.large.ticket.app.{i:04}.exe"))
        .collect();
    let now_mono = SystemCollectorClock::monotonic_ms_now();
    let big_ticket = ReadTicket {
        token: launch_token.clone(),
        policy_revision: 1,
        capture_epoch: 1,
        policy: CapturePolicy {
            enabled: true,
            allowed_application_ids: big_allowlist,
            capture_scope: Some("window".to_string()),
            menu_actions: Some(true),
            ..CapturePolicy::default()
        },
        hint: None,
        deadline_monotonic_ms: now_mono + 3_000,
        device_id: "dev-big-ticket".to_string(),
        os_session_id: "wts-1".to_string(),
        desktop_id: "winsta0-default-wts-1".to_string(),
        foreground_generation: Some(1),
        focus_generation: Some(1),
        debug_request_id: None,
        read_only_ax_enablement: None,
        focused_fast_only: None,
    };
    let mut ticket_bytes = big_ticket.to_json().canonical_bytes().unwrap();
    assert!(
        ticket_bytes.len() > 10_000,
        "test ReadTicket must exceed 8 KiB chunk size (got {} bytes)",
        ticket_bytes.len()
    );
    ticket_bytes.push(b'\n');
    stdin.write_all(&ticket_bytes).unwrap();
    stdin.flush().unwrap();

    let mut reader = BufReader::new(stdout);
    let mut resp_line = String::new();
    reader.read_line(&mut resp_line).unwrap();
    let resp_json = JsonValue::parse_str(resp_line.trim_end()).expect("valid ReadResult JSON");
    let resp = ReadResult::from_json(&resp_json).expect("decodes ReadResult");
    assert_eq!(resp.token, launch_token);

    let retire_cmd =
        format!("{{\"retire\":\"{retire_token}\",\"sessionToken\":\"{launch_token}\"}}\n");
    stdin.write_all(retire_cmd.as_bytes()).unwrap();
    stdin.flush().unwrap();

    let mut ack_line = String::new();
    reader.read_line(&mut ack_line).unwrap();
    let ack_json = JsonValue::parse_str(ack_line.trim_end()).expect("valid retire ack JSON");
    assert_eq!(
        ack_json.get("retired").and_then(JsonValue::as_str),
        Some(retire_token.as_str())
    );
    assert_eq!(
        ack_json.get("inputHealthy").and_then(JsonValue::as_bool),
        Some(true)
    );
    assert_eq!(child.wait().unwrap().code(), Some(0));
    drop(stdin);
}

#[test]
fn r2_p1_1_encode_read_result_pipe_frame_drops_verified_browser_before_oversize_fail() {
    let tok = VerifiedNormalBrowserWindow::from_ephemeral_title(
        0x1234,
        7777,
        "unix-ms:1700000000000.000".to_string(),
        "Docs - Google Chrome",
    )
    .expect("valid digest token");

    let mut base = ReadResult::failure("tok-size-test", "read-error", None, 1000, 1000);
    // Size a text payload so WITHOUT `verified_normal_browser` it is just below 65_500 bytes,
    // and WITH `verified_normal_browser` (~190 B) it crosses >= 65_500 bytes.
    let probe_without = ReadResult {
        reason: None,
        text: Some(TextRead {
            text: "a".repeat(100),
            source: "uia.text".to_string(),
            total_length: Some(100),
            selection: None,
            range_start: 0,
            range_basis: "prefix".to_string(),
            complete: true,
            truncated: false,
            missing_reasons: vec![],
            read_units: None,
        }),
        ..base.clone()
    };
    let overhead = probe_without.to_json().canonical_bytes().unwrap().len() - 100;
    let target_text_len = 65_440usize.saturating_sub(overhead);
    base.reason = None;
    base.text = Some(TextRead {
        text: "a".repeat(target_text_len),
        source: "uia.text".to_string(),
        total_length: Some(target_text_len),
        selection: None,
        range_start: 0,
        range_basis: "prefix".to_string(),
        complete: true,
        truncated: false,
        missing_reasons: vec![],
        read_units: None,
    });
    let len_without = base.to_json().canonical_bytes().unwrap().len();
    assert!(len_without < 65_500 && len_without > 65_400);

    base.verified_normal_browser = Some(tok);
    let len_with = base.to_json().canonical_bytes().unwrap().len();
    assert!(
        len_with >= 65_500,
        "frame with verified_normal_browser must exceed 65_500 B (got {len_with})"
    );

    let encoded = encode_read_result_pipe_frame(&mut base)
        .expect("must drop verified_normal_browser and succeed instead of triggering exit 70");
    assert_eq!(base.verified_normal_browser, None);
    assert!(encoded.ends_with(b"\n"));
    assert!(encoded.len() <= 65_500);
    let decoded = ReadResult::from_json(&JsonValue::parse(&encoded[..encoded.len() - 1]).unwrap())
        .expect("decodes retried frame");
    assert_eq!(decoded.verified_normal_browser, None);
    assert_eq!(decoded.text.as_ref().map(|t| t.text.len()), Some(target_text_len));

    // A frame that still exceeds 65_500 bytes even without verified_normal_browser fails closed.
    let mut still_too_big = base;
    still_too_big.text.as_mut().unwrap().text = "a".repeat(66_000);
    assert_eq!(encode_read_result_pipe_frame(&mut still_too_big), None);
}

#[test]
fn r2_p1_2_engine_browser_input_activity_gate_and_same_tick_cross_epoch_drop() {
    let validator = ContractValidator::new().unwrap();
    let clock = MockClock::new(260_000, 1_700_000_120_000);
    let mut engine = CollectorEngine::new(
        "owner-r2p12",
        "inst-r2p12",
        "dev-r2p12",
        "wts-1",
        "winsta0-default-wts-1",
        false,
        MockEnv::unlocked(),
        clock,
        validator.clone(),
    );
    let policy = CapturePolicy {
        enabled: true,
        application_scope: Some("denylist".to_string()),
        allow_browser_content: Some(true),
        input_activity: Some(true),
        menu_actions: Some(true),
        debounce_ms: 10,
        max_wait_ms: 50,
        read_timeout_ms: 2_000,
        ..CapturePolicy::default()
    };
    engine.receive(&configure_msg("owner-r2p12", "inst-r2p12", 1, &policy));
    engine.receive(&control_msg("owner-r2p12", "inst-r2p12", 1, "start", 10_000));
    let _ = engine.drain_outputs();

    let chrome_app = ApplicationIdentity {
        application_id: "chrome.exe".to_string(),
        process_id: 9101,
        process_start_time: "unix-ms:1700000000000.000".to_string(),
    };
    let chrome_res = ResolvedAppIdentity::from_single("chrome.exe".to_string()).unwrap();
    let notepad_app = ApplicationIdentity {
        application_id: "notepad.exe".to_string(),
        process_id: 9102,
        process_start_time: "unix-ms:1700000000001.000".to_string(),
    };
    let notepad_res = ResolvedAppIdentity::from_single("notepad.exe".to_string()).unwrap();
    let good_tok = VerifiedNormalBrowserWindow::from_ephemeral_title(
        0x5555,
        9101,
        "unix-ms:1700000000000.000".to_string(),
        "Docs - Google Chrome",
    )
    .expect("valid digest token");

    // 1. Unverified known browser sample in engine.input_activity() MUST fail closed:
    //    no context.changed, no observed_application mutation, no input.activity flush, no read launch!
    let t0 = engine.clock.unix_ms();
    engine.input_activity(InputActivitySample {
        application: chrome_app.clone(),
        exe_name: Some("chrome.exe".to_string()),
        category: InputActivityCategory::PointerRelease,
        callback_time_ms: t0,
    });
    assert!(
        emitted_messages(engine.drain_outputs()).is_empty(),
        "unverified browser input_activity MUST NOT emit context.changed"
    );
    // Launch first scheduled read (from `start`) to verify Chrome normally.
    engine.clock.advance(60);
    engine.tick(true);
    let t1 = engine.environment.launched.pop().expect("t1");
    assert!(
        t1.hint.is_none(),
        "unverified browser input_activity MUST NOT set pending_hint"
    );
    let u1 = engine.clock.unix_ms();
    engine.complete(ReadResult {
        token: t1.token,
        application: Some(chrome_app.clone()),
        diagnostic_application: Some(chrome_app.clone()),
        exe_name: Some("chrome.exe".to_string()),
        text: Some(TextRead {
            text: "browser ok".to_string(),
            source: "uia.text".to_string(),
            total_length: Some(10),
            selection: None,
            range_start: 0,
            range_basis: "prefix".to_string(),
            complete: true,
            truncated: false,
            missing_reasons: vec![],
            read_units: None,
        }),
        reason: None,
        diagnostic: None,
        enablement: None,
        session_identity: Some(WorkerSurfaceIdentity {
            session_id: "s-br".to_string(),
            window_id: "w-br".to_string(),
            node_id: "n-br".to_string(),
            surface_id: "surf-br".to_string(),
            window_generation: 1,
            focus_generation: 1,
        }),
        surface: None,
        selection: None,
        input_records: Vec::new(),
        input_gaps: Vec::new(),
        private_state: Some("user-authorized".to_string()),
        observer_status: Some("best-effort".to_string()),
        focus_absent: None,
        surface_failure: None,
        verified_normal_browser: Some(good_tok.clone()),
        capture_start_ms: u1,
        capture_end_ms: u1,
    });
    let _ = engine.drain_outputs();
    assert_eq!(engine.environment.verified_normal_browser, Some(good_tok.clone()));

    // 2. While verified, Chrome input_activity succeeds and flushes cleanly!
    let t_ok = engine.clock.unix_ms();
    engine.input_activity(InputActivitySample {
        application: chrome_app.clone(),
        exe_name: Some("chrome.exe".to_string()),
        category: InputActivityCategory::ScrollSample,
        callback_time_ms: t_ok,
    });
    engine.clock.advance(1_000);
    engine.tick(true);
    let ok_msgs = emitted_messages(engine.drain_outputs());
    assert!(
        ok_msgs.iter().any(|m| {
            m.get("payload")
                .and_then(|p| p.get("kind"))
                .and_then(JsonValue::as_str)
                == Some("input.activity")
        }),
        "verified browser input_activity must flush cleanly"
    );
    let t2 = engine.environment.launched.pop().expect("t2");

    // 3. Simulate background `raw-input` clearing its live shared token (e.g. foreground switch
    //    to Incognito) BEFORE engine clears its own copy -> engine.input_activity() MUST reject!
    engine.environment.verified_normal_browser = None;
    let t_revoked = engine.clock.unix_ms();
    engine.input_activity(InputActivitySample {
        application: chrome_app.clone(),
        exe_name: Some("chrome.exe".to_string()),
        category: InputActivityCategory::PointerRelease,
        callback_time_ms: t_revoked,
    });
    engine.clock.advance(1_000);
    engine.tick(true);
    let revoked_msgs = emitted_messages(engine.drain_outputs());
    assert!(
        !revoked_msgs.iter().any(|m| {
            m.get("payload")
                .and_then(|p| p.get("kind"))
                .and_then(JsonValue::as_str)
                == Some("input.activity")
        }),
        "browser sample MUST fail closed when live monitor token was cleared in background"
    );

    // 4. Same-tick `worker_events` vs drained `input_notices` cross-epoch race:
    //    Re-anchor to Notepad, then deliver BOTH a worker `BrowserExcluded` (or `application-excluded`)
    //    AND already-drained `RawInputNotice::Activity` + `RawInputNotice::ExcludedApplication` in one tick.
    let u2 = engine.clock.unix_ms();
    engine.complete(ReadResult {
        token: t2.token,
        application: Some(notepad_app.clone()),
        diagnostic_application: Some(notepad_app.clone()),
        exe_name: Some("notepad.exe".to_string()),
        text: Some(TextRead {
            text: "note".to_string(),
            source: "uia.text".to_string(),
            total_length: Some(4),
            selection: None,
            range_start: 0,
            range_basis: "prefix".to_string(),
            complete: true,
            truncated: false,
            missing_reasons: vec![],
            read_units: None,
        }),
        reason: None,
        diagnostic: None,
        enablement: None,
        session_identity: Some(WorkerSurfaceIdentity {
            session_id: "s-np".to_string(),
            window_id: "w-np".to_string(),
            node_id: "n-np".to_string(),
            surface_id: "surf-np".to_string(),
            window_generation: 1,
            focus_generation: 1,
        }),
        surface: None,
        selection: None,
        input_records: Vec::new(),
        input_gaps: Vec::new(),
        private_state: Some("normal".to_string()),
        observer_status: Some("best-effort".to_string()),
        focus_absent: None,
        surface_failure: None,
        verified_normal_browser: None,
        capture_start_ms: u2,
        capture_end_ms: u2,
    });
    let _ = engine.drain_outputs();
    engine.clock.advance(1_100);
    engine.tick(true);
    let t3 = engine.environment.launched.pop().expect("t3");

    let t_race = engine.clock.unix_ms();
    let epoch_before_race = engine.capture_epoch();
    engine
        .environment
        .poll_events
        .push(WorkerEvent::Completed(Box::new(ReadResult::failure(
            t3.token,
            "policy-boundary",
            Some(GapDiagnostic::new(GapDiagnosticCode::BrowserExcluded, None)),
            t_race,
            t_race,
        ))));
    // Already-drained Activity from the previous tick MUST be dropped, while ExcludedApplication
    // in the same batch MUST still run (bumping epoch)!
    engine.environment.poll_notices.push(RawInputNotice::Activity {
        sample: InputActivitySample {
            application: notepad_app,
            exe_name: Some("notepad.exe".to_string()),
            category: InputActivityCategory::ShortcutPress,
            callback_time_ms: t_race,
        },
        resolved: notepad_res,
    });
    engine.environment.poll_notices.push(RawInputNotice::Activity {
        sample: InputActivitySample {
            application: chrome_app,
            exe_name: Some("chrome.exe".to_string()),
            category: InputActivityCategory::PointerRelease,
            callback_time_ms: t_race,
        },
        resolved: chrome_res,
    });
    engine
        .environment
        .poll_notices
        .push(RawInputNotice::ExcludedApplication);
    engine.poll_environment();
    assert!(
        engine.capture_epoch() > epoch_before_race,
        "ExcludedApplication notice MUST still be handled even when same-tick Activity is dropped"
    );
    let _ = engine.drain_outputs();
    engine.clock.advance(1_000);
    engine.tick(true);
    let race_msgs = emitted_messages(engine.drain_outputs());
    assert!(
        !race_msgs.iter().any(|m| {
            m.get("payload")
                .and_then(|p| p.get("kind"))
                .and_then(JsonValue::as_str)
                == Some("input.activity")
        }),
        "same-tick drained Activity MUST be dropped after worker security boundary"
    );
    for m in &race_msgs {
        validator.validate_message(m).expect("wire valid");
    }
}

#[test]
fn r2_p1_3_and_p2_3_focused_role_not_text_preserves_menu_and_browser_token_while_exclusions_clear_activity() {
    let validator = ContractValidator::new().unwrap();
    let clock = MockClock::new(280_000, 1_700_000_140_000);
    let mut engine = CollectorEngine::new(
        "owner-r2p23",
        "inst-r2p23",
        "dev-r2p23",
        "wts-1",
        "winsta0-default-wts-1",
        false,
        MockEnv::unlocked(),
        clock,
        validator.clone(),
    );
    let policy = CapturePolicy {
        enabled: true,
        application_scope: Some("denylist".to_string()),
        allow_browser_content: Some(true),
        capture_scope: Some("focused".to_string()),
        input_activity: Some(true),
        menu_actions: Some(true),
        debounce_ms: 10,
        max_wait_ms: 50,
        read_timeout_ms: 2_000,
        ..CapturePolicy::default()
    };
    engine.receive(&configure_msg("owner-r2p23", "inst-r2p23", 1, &policy));
    engine.receive(&control_msg("owner-r2p23", "inst-r2p23", 1, "start", 30_000));
    let _ = engine.drain_outputs();

    let chrome_app = ApplicationIdentity {
        application_id: "chrome.exe".to_string(),
        process_id: 9201,
        process_start_time: "unix-ms:1700000000000.000".to_string(),
    };
    let good_tok = VerifiedNormalBrowserWindow::from_ephemeral_title(
        0x7777,
        9201,
        "unix-ms:1700000000000.000".to_string(),
        "Docs - Google Chrome",
    )
    .expect("valid digest token");

    // 1. P1-3 & P2-3: `FocusedRoleNotText` under `captureScope: "focused"` MUST:
    //    - adopt propagated `verified_normal_browser`
    //    - NOT clear `menu_tracking_until_ms`!
    engine.clock.advance(60);
    engine.tick(true);
    let t1 = engine.environment.launched.pop().expect("t1");
    engine.worker_menu_tracking(true);
    let u1 = engine.clock.unix_ms();
    let mut not_text_res = ReadResult::failure(
        t1.token,
        "policy-boundary",
        Some(GapDiagnostic::new(
            GapDiagnosticCode::FocusedRoleNotText,
            Some("AXButton"),
        )),
        u1,
        u1,
    );
    not_text_res.diagnostic_application = Some(chrome_app.clone());
    not_text_res.exe_name = Some("chrome.exe".to_string());
    not_text_res.verified_normal_browser = Some(good_tok.clone());
    engine.complete(not_text_res);
    let _ = engine.drain_outputs();

    assert_eq!(
        engine.environment.verified_normal_browser,
        Some(good_tok.clone()),
        "FocusedRoleNotText must preserve/adopt normal browser token"
    );
    // Advance 1,100ms (< 10,000ms menu tracking ceiling): tick() MUST NOT launch a read because
    // `menu_tracking_until_ms` was preserved on FocusedRoleNotText!
    engine.clock.advance(1_100);
    engine.tick(true);
    assert!(
        engine.environment.launched.is_empty(),
        "FocusedRoleNotText MUST NOT clear menu_tracking_until_ms"
    );

    // End menu tracking, verify browser input_activity works seamlessly with the adopted token!
    engine.worker_menu_tracking(false);
    let t_act = engine.clock.unix_ms();
    engine.input_activity(InputActivitySample {
        application: chrome_app.clone(),
        exe_name: Some("chrome.exe".to_string()),
        category: InputActivityCategory::PointerRelease,
        callback_time_ms: t_act,
    });
    let _ = engine.drain_outputs();

    // 2. P2-3: Security exclusions (`BrowserExcluded`, `SecureField`, `ApplicationNotAllowed`,
    //    `FieldSecurityUnknown`, `SurfaceReadFailure::SecurityExcluded`) MUST call
    //    `clear_input_activity()` so any buffered <1s bucket is dropped immediately!
    for (idx, (reason, diag, sf)) in [
        ("policy-boundary", Some(GapDiagnosticCode::BrowserExcluded), None),
        ("policy-boundary", Some(GapDiagnosticCode::SecureField), None),
        ("policy-boundary", Some(GapDiagnosticCode::ApplicationNotAllowed), None),
        ("policy-boundary", Some(GapDiagnosticCode::FieldSecurityUnknown), None),
        (
            "read-error",
            Some(GapDiagnosticCode::TextReadUnavailable),
            Some(SurfaceReadFailure::SecurityExcluded),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        // Keep lease alive across all iterations, re-seed verified browser token via
        // FocusedRoleNotText, and buffer a fresh <1s activity sample right before exclusion.
        engine.receive(&control_msg("owner-r2p23", "inst-r2p23", 1, "heartbeat", 30_000));
        let _ = engine.drain_outputs();
        engine.clock.advance(1_100);
        engine.tick(true);
        let seed_t = engine.environment.launched.pop().expect("seed ticket");
        let u_seed = engine.clock.unix_ms();
        let mut seed_res = ReadResult::failure(
            seed_t.token,
            "policy-boundary",
            Some(GapDiagnostic::new(
                GapDiagnosticCode::FocusedRoleNotText,
                Some("AXButton"),
            )),
            u_seed,
            u_seed,
        );
        seed_res.diagnostic_application = Some(chrome_app.clone());
        seed_res.exe_name = Some("chrome.exe".to_string());
        seed_res.verified_normal_browser = Some(good_tok.clone());
        engine.complete(seed_res);
        let _ = engine.drain_outputs();
        assert_eq!(engine.environment.verified_normal_browser, Some(good_tok.clone()));

        // Schedule a quick read via worker_dirty (20ms < 1s bucket) and buffer a <1s sample
        // right before completing the security exclusion!
        engine.worker_dirty();
        engine.clock.advance(20);
        engine.tick(true);
        let _ = engine.drain_outputs();
        let t_fresh = engine.clock.unix_ms();
        engine.input_activity(InputActivitySample {
            application: chrome_app.clone(),
            exe_name: Some("chrome.exe".to_string()),
            category: InputActivityCategory::ShortcutPress,
            callback_time_ms: t_fresh,
        });
        let fail_t = engine.environment.launched.pop().expect("fail ticket");
        let clears_before = engine.environment.input_activity_clears;
        let u_fail = engine.clock.unix_ms();
        let mut fail_res = ReadResult::failure(
            fail_t.token,
            reason,
            diag.map(|c| GapDiagnostic::new(c, None)),
            u_fail,
            u_fail,
        );
        fail_res.surface_failure = sf;
        engine.complete(fail_res);
        assert!(
            engine.environment.input_activity_clears > clears_before,
            "case {idx} ({reason}/{diag:?}/{sf:?}) MUST call clear_input_activity()"
        );
        assert_eq!(
            engine.environment.verified_normal_browser, None,
            "case {idx} MUST clear verified_normal_browser"
        );
        let _ = engine.drain_outputs();

        // Advancing 1s MUST NOT flush the discarded <1s bucket!
        engine.clock.advance(1_000);
        engine.tick(true);
        let after = emitted_messages(engine.drain_outputs());
        assert!(
            !after.iter().any(|m| {
                m.get("payload")
                    .and_then(|p| p.get("kind"))
                    .and_then(JsonValue::as_str)
                    == Some("input.activity")
            }),
            "case {idx}: buffered <1s activity MUST NOT flush after security exclusion"
        );
        // Drain any newly launched ticket cleanly before next iteration.
        if let Some(leftover) = engine.environment.launched.pop() {
            let ul = engine.clock.unix_ms();
            engine.complete(ReadResult::failure(leftover.token, "stale", None, ul, ul));
            let _ = engine.drain_outputs();
        }
    }

    // 3. P2-3: `DesktopUnavailable` and `ReadDeadline` MUST clear `verified_normal_browser`!
    for (reason, code) in [
        ("desktop-unavailable", GapDiagnosticCode::DesktopUnavailable),
        ("stale", GapDiagnosticCode::ReadDeadline),
    ] {
        engine.clock.advance(1_100);
        engine.tick(true);
        let seed_t = engine.environment.launched.pop().expect("seed ticket");
        let u_seed = engine.clock.unix_ms();
        let mut seed_res = ReadResult::failure(
            seed_t.token,
            "policy-boundary",
            Some(GapDiagnostic::new(
                GapDiagnosticCode::FocusedRoleNotText,
                Some("AXButton"),
            )),
            u_seed,
            u_seed,
        );
        seed_res.diagnostic_application = Some(chrome_app.clone());
        seed_res.exe_name = Some("chrome.exe".to_string());
        seed_res.verified_normal_browser = Some(good_tok.clone());
        engine.complete(seed_res);
        assert_eq!(engine.environment.verified_normal_browser, Some(good_tok.clone()));
        let _ = engine.drain_outputs();

        engine.clock.advance(1_100);
        engine.tick(true);
        let t_fail = engine.environment.launched.pop().expect("fail ticket");
        let u_fail = engine.clock.unix_ms();
        engine.complete(ReadResult::failure(
            t_fail.token,
            reason,
            Some(GapDiagnostic::new(code, None)),
            u_fail,
            u_fail,
        ));
        assert_eq!(
            engine.environment.verified_normal_browser, None,
            "{code:?} MUST clear verified_normal_browser"
        );
        let _ = engine.drain_outputs();
    }
    for m in emitted_messages(engine.drain_outputs()) {
        validator.validate_message(&m).expect("wire valid");
    }
}

#[test]
fn r2_p2_4_non_string_retired_fails_closed_and_idle_session_worker_exit_cleans_engine() {
    // 1. P2-4a: Any frame with `"retired"` whose value is NOT a JSON string MUST return AckFailed!
    let sess = "11111111-1111-4111-8111-111111111111";
    let ret = "22222222-2222-4222-8222-222222222222";
    for bad_retired in [
        format!("{{\"inputHealthy\":true,\"retired\":true,\"sessionToken\":\"{sess}\"}}"),
        format!("{{\"inputHealthy\":true,\"retired\":null,\"sessionToken\":\"{sess}\"}}"),
        format!("{{\"inputHealthy\":true,\"retired\":123,\"sessionToken\":\"{sess}\"}}"),
        format!("{{\"inputHealthy\":true,\"retired\":{{}},\"sessionToken\":\"{sess}\"}}"),
        format!("{{\"inputHealthy\":true,\"retired\":[],\"sessionToken\":\"{sess}\"}}"),
    ] {
        assert_eq!(
            classify_retiring_session_frame(bad_retired.as_bytes(), sess, ret, true),
            RetiringFrameOutcome::AckFailed,
            "non-string retired payload MUST fail closed with AckFailed: {bad_retired}"
        );
    }

    // 2. P2-4b: classify_worker_pipe_termination emits SessionWorkerExitedUnexpectedly for idle
    //    session worker termination instead of silently cancelling!
    assert_eq!(
        classify_worker_pipe_termination(true, None, false, false),
        Some(WorkerEvent::SessionWorkerExitedUnexpectedly)
    );
    assert_eq!(
        classify_worker_pipe_termination(false, None, false, false),
        None
    );
    assert_eq!(
        classify_worker_pipe_termination(true, None, true, false),
        Some(WorkerEvent::InputDisabled(
            "input-monitoring-unavailable".to_string()
        ))
    );
    assert_eq!(
        classify_worker_pipe_termination(true, None, false, true),
        Some(WorkerEvent::InputDisabled(
            "input-monitoring-unavailable".to_string()
        ))
    );

    // 3. P2-4c: CollectorEngine handling `WorkerEvent::SessionWorkerExitedUnexpectedly` MUST clear
    //    menu_tracking_until_ms, verified_normal_browser, buffered input.activity, AND invalidate
    //    the active application anchor (bumping capture_epoch) + drop same-tick drained Activity!
    let validator = ContractValidator::new().unwrap();
    let clock = MockClock::new(300_000, 1_700_000_160_000);
    let mut engine = CollectorEngine::new(
        "owner-r2p24",
        "inst-r2p24",
        "dev-r2p24",
        "wts-1",
        "winsta0-default-wts-1",
        false,
        MockEnv::unlocked(),
        clock,
        validator.clone(),
    );
    let policy = CapturePolicy {
        enabled: true,
        application_scope: Some("denylist".to_string()),
        allow_browser_content: Some(true),
        input_activity: Some(true),
        menu_actions: Some(true),
        debounce_ms: 10,
        max_wait_ms: 50,
        read_timeout_ms: 2_000,
        ..CapturePolicy::default()
    };
    engine.receive(&configure_msg("owner-r2p24", "inst-r2p24", 1, &policy));
    engine.receive(&control_msg("owner-r2p24", "inst-r2p24", 1, "start", 10_000));
    let _ = engine.drain_outputs();

    let chrome_app = ApplicationIdentity {
        application_id: "chrome.exe".to_string(),
        process_id: 9301,
        process_start_time: "unix-ms:1700000000000.000".to_string(),
    };
    let chrome_res = ResolvedAppIdentity::from_single("chrome.exe".to_string()).unwrap();
    let code_app = ApplicationIdentity {
        application_id: "code.exe".to_string(),
        process_id: 9302,
        process_start_time: "unix-ms:1700000000001.000".to_string(),
    };
    let good_tok = VerifiedNormalBrowserWindow::from_ephemeral_title(
        0x8888,
        9301,
        "unix-ms:1700000000000.000".to_string(),
        "Docs - Google Chrome",
    )
    .expect("valid token");

    // Anchor epoch to Chrome, set verified_normal_browser, activate menu tracking, and buffer <1s input.
    engine.clock.advance(60);
    engine.tick(true);
    let t1 = engine.environment.launched.pop().expect("t1");
    let u1 = engine.clock.unix_ms();
    engine.complete(ReadResult {
        token: t1.token,
        application: Some(chrome_app.clone()),
        diagnostic_application: Some(chrome_app.clone()),
        exe_name: Some("chrome.exe".to_string()),
        text: Some(TextRead {
            text: "chrome text".to_string(),
            source: "uia.text".to_string(),
            total_length: Some(11),
            selection: None,
            range_start: 0,
            range_basis: "prefix".to_string(),
            complete: true,
            truncated: false,
            missing_reasons: vec![],
            read_units: None,
        }),
        reason: None,
        diagnostic: None,
        enablement: None,
        session_identity: Some(WorkerSurfaceIdentity {
            session_id: "s-c".to_string(),
            window_id: "w-c".to_string(),
            node_id: "n-c".to_string(),
            surface_id: "surf-c".to_string(),
            window_generation: 1,
            focus_generation: 1,
        }),
        surface: None,
        selection: None,
        input_records: Vec::new(),
        input_gaps: Vec::new(),
        private_state: Some("user-authorized".to_string()),
        observer_status: Some("best-effort".to_string()),
        focus_absent: None,
        surface_failure: None,
        verified_normal_browser: Some(good_tok),
        capture_start_ms: u1,
        capture_end_ms: u1,
    });
    let _ = engine.drain_outputs();
    engine.worker_menu_tracking(true);
    engine.input_activity(InputActivitySample {
        application: chrome_app.clone(),
        exe_name: Some("chrome.exe".to_string()),
        category: InputActivityCategory::PointerRelease,
        callback_time_ms: u1,
    });
    let epoch_before = engine.capture_epoch();
    let clears_before = engine.environment.input_activity_clears;

    // Deliver SessionWorkerExitedUnexpectedly AND a same-tick drained Activity notice!
    engine
        .environment
        .poll_events
        .push(WorkerEvent::SessionWorkerExitedUnexpectedly);
    engine.environment.poll_notices.push(RawInputNotice::Activity {
        sample: InputActivitySample {
            application: chrome_app,
            exe_name: Some("chrome.exe".to_string()),
            category: InputActivityCategory::ScrollSample,
            callback_time_ms: u1,
        },
        resolved: chrome_res,
    });
    engine.poll_environment();

    assert!(
        engine.capture_epoch() > epoch_before,
        "unexpected idle session worker exit MUST invalidate anchor and bump captureEpoch"
    );
    assert_eq!(
        engine.environment.verified_normal_browser, None,
        "unexpected idle session worker exit MUST clear verified_normal_browser"
    );
    assert!(
        engine.environment.input_activity_clears > clears_before,
        "unexpected idle session worker exit MUST call clear_input_activity()"
    );
    let _ = engine.drain_outputs();

    // Verify menu_tracking_until_ms was cleared (read launches after 1_100ms, NOT stuck for 10s!)
    // AND buffered/same-tick input.activity does NOT flush!
    engine.clock.advance(1_100);
    engine.tick(true);
    assert_eq!(
        engine.environment.launched.len(),
        1,
        "unexpected idle session worker exit MUST clear menu_tracking_until_ms so reads resume promptly"
    );
    let after_exit_msgs = emitted_messages(engine.drain_outputs());
    assert!(
        !after_exit_msgs.iter().any(|m| {
            m.get("payload")
                .and_then(|p| p.get("kind"))
                .and_then(JsonValue::as_str)
                == Some("input.activity")
        }),
        "buffered and same-tick input.activity MUST NOT flush after unexpected worker exit"
    );

    // And a new app (code.exe) can now anchor cleanly in the new epoch via menu.action!
    let t_code = engine.clock.unix_ms();
    engine.menu_action(MenuActionRecord {
        application: code_app,
        exe_name: Some("code.exe".to_string()),
        path: vec!["File".to_string(), "Save".to_string()],
        truncated: false,
        observed_at_ms: t_code,
        private_state: "normal".to_string(),
        stamp: engine.stamp(),
        field_security: "strict".to_string(),
    });
    let code_msgs = emitted_messages(engine.drain_outputs());
    assert_eq!(
        code_msgs.len(),
        1,
        "new app must anchor cleanly after unexpected session worker exit cleared old anchor"
    );
    validator.encode_frame(&code_msgs[0]).expect("wire valid");
}

#[test]
fn r2_p1_3_all_hard_boundary_and_timeout_paths_clear_menu_tracking_and_unverified_focused_role() {
    let validator = ContractValidator::new().unwrap();
    let policy = CapturePolicy {
        enabled: true,
        application_scope: Some("denylist".to_string()),
        allow_browser_content: Some(true),
        capture_scope: Some("focused".to_string()),
        input_activity: Some(true),
        menu_actions: Some(true),
        debounce_ms: 10,
        max_wait_ms: 50,
        read_timeout_ms: 500,
        ..CapturePolicy::default()
    };

    let make_engine = |id: &str| {
        let clock = MockClock::new(400_000, 1_700_000_250_000);
        let mut engine = CollectorEngine::new(
            id,
            id,
            id,
            "wts-1",
            "winsta0-default-wts-1",
            false,
            MockEnv::unlocked(),
            clock,
            validator.clone(),
        );
        engine.receive(&configure_msg(id, id, 1, &policy));
        engine.receive(&control_msg(id, id, 1, "start", 10_000));
        let _ = engine.drain_outputs();
        engine
    };

    let chrome_app = ApplicationIdentity {
        application_id: "chrome.exe".to_string(),
        process_id: 9401,
        process_start_time: "unix-ms:1700000000000.000".to_string(),
    };
    let good_tok = VerifiedNormalBrowserWindow::from_ephemeral_title(
        0x7777,
        9401,
        "unix-ms:1700000000000.000".to_string(),
        "Normal Tab - Google Chrome",
    )
    .expect("valid token");

    let assert_menu_tracking_cleared = |engine: &mut CollectorEngine<MockEnv, MockClock>, label: &str| {
        engine.environment.launched.clear();
        engine.clock.advance(1_100);
        engine.tick(true);
        assert_eq!(
            engine.environment.launched.len(),
            1,
            "{label}: menu_tracking_until_ms must be cleared so tick() launches a read immediately instead of stalling 10s"
        );
    };

    // Case 1: desktop-unavailable clears menu_tracking_until_ms.
    {
        let mut engine = make_engine("r2p13-desktop");
        engine.clock.advance(60);
        engine.tick(true);
        let t = engine.environment.launched.pop().unwrap();
        let u = engine.clock.unix_ms();
        engine.worker_menu_tracking(true);
        engine.complete(ReadResult::failure(
            t.token,
            "desktop-unavailable",
            Some(GapDiagnostic::new(GapDiagnosticCode::DesktopUnavailable, None)),
            u,
            u,
        ));
        assert_menu_tracking_cleared(&mut engine, "desktop-unavailable");
    }

    // Case 2: stale + ReadDeadline clears menu_tracking_until_ms.
    {
        let mut engine = make_engine("r2p13-stale-deadline");
        engine.clock.advance(60);
        engine.tick(true);
        let t = engine.environment.launched.pop().unwrap();
        let u = engine.clock.unix_ms();
        engine.worker_menu_tracking(true);
        engine.complete(ReadResult::failure(
            t.token,
            "stale",
            Some(GapDiagnostic::new(GapDiagnosticCode::ReadDeadline, None)),
            u,
            u,
        ));
        assert_menu_tracking_cleared(&mut engine, "stale+ReadDeadline");
    }

    // Case 3: negative_application (policy-boundary + ApplicationUnavailable) clears menu_tracking_until_ms.
    {
        let mut engine = make_engine("r2p13-app-unavail");
        engine.clock.advance(60);
        engine.tick(true);
        let t = engine.environment.launched.pop().unwrap();
        let u = engine.clock.unix_ms();
        engine.worker_menu_tracking(true);
        engine.complete(ReadResult::failure(
            t.token,
            "policy-boundary",
            Some(GapDiagnostic::new(GapDiagnosticCode::ApplicationUnavailable, None)),
            u,
            u,
        ));
        assert_menu_tracking_cleared(&mut engine, "policy-boundary+ApplicationUnavailable");
    }

    // Case 4: unanchored application-excluded clears menu_tracking_until_ms.
    {
        let mut engine = make_engine("r2p13-app-excl");
        engine.clock.advance(60);
        engine.tick(true);
        let t = engine.environment.launched.pop().unwrap();
        let u = engine.clock.unix_ms();
        engine.worker_menu_tracking(true);
        engine.complete(ReadResult::failure(t.token, "application-excluded", None, u, u));
        assert_menu_tracking_cleared(&mut engine, "unanchored application-excluded");
    }

    // Case 5: unanchored expire_read (read deadline timeout) clears menu_tracking_until_ms.
    {
        let mut engine = make_engine("r2p13-expire");
        engine.clock.advance(60);
        engine.tick(true);
        let _t = engine.environment.launched.pop().unwrap();
        engine.worker_menu_tracking(true);
        engine.clock.advance(600);
        engine.tick(true);
        assert_menu_tracking_cleared(&mut engine, "unanchored expire_read");
    }

    // Case 6: FocusedRoleNotText with disallowed diagnostic_application (1password.exe) clears
    // BOTH menu_tracking_until_ms and verified_normal_browser.
    {
        let mut engine = make_engine("r2p13-disallowed-focus-role");
        engine.clock.advance(60);
        engine.tick(true);
        let t1 = engine.environment.launched.pop().unwrap();
        let u1 = engine.clock.unix_ms();
        let mut ok_res = ReadResult::failure(
            t1.token,
            "policy-boundary",
            Some(GapDiagnostic::new(GapDiagnosticCode::FocusedRoleNotText, Some("AXButton"))),
            u1,
            u1,
        );
        ok_res.diagnostic_application = Some(chrome_app.clone());
        ok_res.exe_name = Some("chrome.exe".to_string());
        ok_res.verified_normal_browser = Some(good_tok.clone());
        engine.complete(ok_res);
        assert_eq!(engine.environment.verified_normal_browser, Some(good_tok.clone()));

        engine.clock.advance(1_100);
        engine.tick(true);
        let t2 = engine.environment.launched.pop().unwrap();
        let u2 = engine.clock.unix_ms();
        engine.worker_menu_tracking(true);
        let mut denied_res = ReadResult::failure(
            t2.token,
            "policy-boundary",
            Some(GapDiagnostic::new(GapDiagnosticCode::FocusedRoleNotText, Some("AXButton"))),
            u2,
            u2,
        );
        denied_res.diagnostic_application = Some(ApplicationIdentity {
            application_id: "1password.exe".to_string(),
            process_id: 9999,
            process_start_time: "unix-ms:1700000000009.000".to_string(),
        });
        denied_res.exe_name = Some("1password.exe".to_string());
        engine.complete(denied_res);
        assert_eq!(engine.environment.verified_normal_browser, None);
        assert_menu_tracking_cleared(&mut engine, "disallowed FocusedRoleNotText");
    }

    // Case 7: FocusedRoleNotText with diagnostic_application == None fails closed (clears BOTH).
    {
        let mut engine = make_engine("r2p23-none-diag-app");
        engine.clock.advance(60);
        engine.tick(true);
        let t1 = engine.environment.launched.pop().unwrap();
        let u1 = engine.clock.unix_ms();
        let mut ok_res = ReadResult::failure(
            t1.token,
            "policy-boundary",
            Some(GapDiagnostic::new(GapDiagnosticCode::FocusedRoleNotText, Some("AXButton"))),
            u1,
            u1,
        );
        ok_res.diagnostic_application = Some(chrome_app.clone());
        ok_res.exe_name = Some("chrome.exe".to_string());
        ok_res.verified_normal_browser = Some(good_tok.clone());
        engine.complete(ok_res);
        assert_eq!(
            engine.environment.verified_normal_browser,
            Some(good_tok.clone())
        );

        engine.clock.advance(1_100);
        engine.tick(true);
        let t2 = engine.environment.launched.pop().unwrap();
        let u2 = engine.clock.unix_ms();
        engine.worker_menu_tracking(true);
        let none_res = ReadResult::failure(
            t2.token,
            "policy-boundary",
            Some(GapDiagnostic::new(GapDiagnosticCode::FocusedRoleNotText, Some("AXButton"))),
            u2,
            u2,
        );
        engine.complete(none_res);
        assert_eq!(
            engine.environment.verified_normal_browser, None,
            "FocusedRoleNotText with missing diagnostic_application must fail closed"
        );
        assert_menu_tracking_cleared(&mut engine, "FocusedRoleNotText missing diagnostic_application");
    }

    // Case 8: Same-PID browser FocusedRoleNotText with verified_normal_browser == None fails
    // closed on the browser token (matching normal reads) while preserving menu_tracking_until_ms.
    {
        let mut engine = make_engine("r3p2-focused-role-none-tok");
        engine.clock.advance(60);
        engine.tick(true);
        let t1 = engine.environment.launched.pop().unwrap();
        let u1 = engine.clock.unix_ms();
        let mut ok_res = ReadResult::failure(
            t1.token,
            "policy-boundary",
            Some(GapDiagnostic::new(GapDiagnosticCode::FocusedRoleNotText, Some("AXButton"))),
            u1,
            u1,
        );
        ok_res.diagnostic_application = Some(chrome_app.clone());
        ok_res.exe_name = Some("chrome.exe".to_string());
        ok_res.verified_normal_browser = Some(good_tok.clone());
        engine.complete(ok_res);
        assert_eq!(engine.environment.verified_normal_browser, Some(good_tok));

        engine.clock.advance(1_100);
        engine.tick(true);
        let t2 = engine.environment.launched.pop().unwrap();
        let u2 = engine.clock.unix_ms();
        engine.worker_menu_tracking(true);
        let mut unverified_res = ReadResult::failure(
            t2.token,
            "policy-boundary",
            Some(GapDiagnostic::new(GapDiagnosticCode::FocusedRoleNotText, Some("AXButton"))),
            u2,
            u2,
        );
        unverified_res.diagnostic_application = Some(chrome_app);
        unverified_res.exe_name = Some("chrome.exe".to_string());
        unverified_res.verified_normal_browser = None;
        engine.complete(unverified_res);
        assert_eq!(
            engine.environment.verified_normal_browser, None,
            "same-PID browser FocusedRoleNotText without verified token must fail closed"
        );
        engine.clock.advance(1_100);
        engine.tick(true);
        assert!(
            engine.environment.launched.is_empty(),
            "allowed same-PID FocusedRoleNotText must still preserve menu_tracking_until_ms"
        );
    }
}

fn make_test_input_context(
    app: &ApplicationIdentity,
    exe_name: Option<&str>,
    identity: &WorkerSurfaceIdentity,
    stamp: Stamp,
    field_security_mode: &str,
    secure_status: SecureStatus,
    private_state: InputTextPrivateState,
) -> InputTextContext {
    InputTextContext {
        target: TargetIdentity {
            device_id: "dev-p5b".to_string(),
            os_session_id: "wts-1".to_string(),
            desktop_id: "winsta0-default-wts-1".to_string(),
            process_id: app.process_id,
            process_start_time: app.process_start_time.clone(),
            application_id: app.application_id.clone(),
            window_id: identity.window_id.clone(),
            window_generation: identity.window_generation,
        },
        surface_id: identity.surface_id.clone(),
        capture_epoch: stamp.capture_epoch,
        foreground_generation: stamp.foreground_generation,
        focus_generation: stamp.focus_generation,
        policy_revision: stamp.policy_revision,
        field_security_mode: field_security_mode.to_string(),
        secure_status,
        private_state,
        exe_name: exe_name.map(str::to_string),
    }
}

#[test]
fn phase5b_read_result_input_text_and_gaps_json_roundtrip_and_window_only_rejection() {
    let app = ApplicationIdentity {
        application_id: "code.exe".to_string(),
        process_id: 5100,
        process_start_time: "unix-ms:1700000000000.000".to_string(),
    };
    let identity = WorkerSurfaceIdentity {
        session_id: "sess-p5b".to_string(),
        window_id: "win-p5b".to_string(),
        node_id: "node-p5b".to_string(),
        surface_id: "surf-p5b".to_string(),
        window_generation: 1,
        focus_generation: 1,
    };
    let stamp = Stamp {
        capture_epoch: 2,
        foreground_generation: 1,
        focus_generation: 1,
        policy_revision: 1,
    };
    let ctx = make_test_input_context(
        &app,
        Some("code.exe"),
        &identity,
        stamp,
        "strict",
        SecureStatus::Safe,
        InputTextPrivateState::Normal,
    );
    let rec_text = InputTextRecord {
        context: ctx.clone(),
        source: InputTextSource::Win32Unicode,
        event_kind: InputTextKind::Text,
        text: "hello 世界".to_string(),
        modifiers: vec![],
        interval_start_ms: 1_700_000_000_100,
        interval_end_ms: 1_700_000_000_250,
        event_count: 8,
        extra_coverage_reasons: vec!["non-atomic-field-gate".to_string()],
    };
    let rec_ret = InputTextRecord {
        context: ctx.clone(),
        source: InputTextSource::Win32Unicode,
        event_kind: InputTextKind::Return,
        text: String::new(),
        modifiers: vec![],
        interval_start_ms: 1_700_000_000_260,
        interval_end_ms: 1_700_000_000_260,
        event_count: 1,
        extra_coverage_reasons: vec![],
    };
    let rec_shortcut = InputTextRecord {
        context: ctx,
        source: InputTextSource::Win32Unicode,
        event_kind: InputTextKind::Shortcut,
        text: String::new(),
        modifiers: vec![InputTextModifier::Control, InputTextModifier::Shift],
        interval_start_ms: 1_700_000_000_300,
        interval_end_ms: 1_700_000_000_300,
        event_count: 1,
        extra_coverage_reasons: vec![],
    };
    let gaps = vec![
        InputTextGapRecord::new(InputTextGapReason::Budget),
        InputTextGapRecord::with_provider(
            InputTextGapReason::TargetMismatch,
            Some("code.exe".to_string()),
        ),
    ];

    let mut res = ReadResult::failure("tok-p5b-rt", "read-error", None, 1_700_000_000_100, 1_700_000_000_350);
    res.reason = None;
    res.application = Some(app.clone());
    res.session_identity = Some(identity.clone());
    res.input_records = vec![rec_text.clone(), rec_ret, rec_shortcut];
    res.input_gaps = gaps.clone();

    let json = res.to_json();
    assert!(json.get("inputRecords").is_some());
    assert!(json.get("inputGaps").is_some());
    let decoded = ReadResult::from_json(&json).expect("valid inputRecords and inputGaps round-trip");
    assert_eq!(decoded, res);

    // Empty input_records and input_gaps omit optional keys cleanly.
    let empty_res = ReadResult::failure("tok-empty", "read-error", None, 100, 100);
    let empty_json = empty_res.to_json();
    assert!(empty_json.get("inputRecords").is_none());
    assert!(empty_json.get("inputGaps").is_none());
    assert_eq!(ReadResult::from_json(&empty_json), Some(empty_res));

    // Fail-closed rejection for malformed inputRecords / inputGaps shapes and elements.
    let mut bad_non_arr_records = json.clone();
    bad_non_arr_records
        .as_obj_mut()
        .unwrap()
        .insert("inputRecords".to_string(), JsonValue::String("bad".to_string()));
    assert!(ReadResult::from_json(&bad_non_arr_records).is_none());

    let mut bad_non_arr_gaps = json.clone();
    bad_non_arr_gaps
        .as_obj_mut()
        .unwrap()
        .insert("inputGaps".to_string(), JsonValue::Bool(true));
    assert!(ReadResult::from_json(&bad_non_arr_gaps).is_none());

    let mut bad_record_elem = json.clone();
    bad_record_elem.as_obj_mut().unwrap().insert(
        "inputRecords".to_string(),
        JsonValue::Array(vec![JsonValue::Object(BTreeMap::new())]),
    );
    assert!(ReadResult::from_json(&bad_record_elem).is_none());

    let mut bad_gap_elem = json;
    let mut unknown_gap = BTreeMap::new();
    unknown_gap.insert(
        "reason".to_string(),
        JsonValue::String("not-a-valid-reason".to_string()),
    );
    unknown_gap.insert("count".to_string(), json_i64(1));
    bad_gap_elem.as_obj_mut().unwrap().insert(
        "inputGaps".to_string(),
        JsonValue::Array(vec![JsonValue::Object(unknown_gap)]),
    );
    assert!(ReadResult::from_json(&bad_gap_elem).is_none());

    // `valid_window_only_channels` MUST reject `focusAbsent: true` whenever `input_records` OR
    // `input_gaps` is non-empty, and accept when both are empty with a valid window surface.
    let window_policy = CapturePolicy {
        enabled: true,
        capture_scope: Some("window".to_string()),
        allowed_application_ids: vec!["code.exe".to_string()],
        ..CapturePolicy::default()
    };
    let now_u = 1_700_000_000_400i64;
    let mut win_only = ReadResult::failure(
        "tok-win-only",
        "focus-unavailable",
        Some(GapDiagnostic::new(
            GapDiagnosticCode::FocusedFieldUnavailable,
            None,
        )),
        now_u,
        now_u,
    );
    win_only.reason = None;
    win_only.application = Some(app);
    win_only.session_identity = Some(identity);
    win_only.focus_absent = Some(true);
    win_only.surface = Some(SurfaceReadResult {
        surface_id: "surf-p5b".to_string(),
        revision: 1,
        scope: "window".to_string(),
        mode: "full".to_string(),
        nodes: vec![SurfaceNode {
            id: "n1".to_string(),
            parent_id: None,
            role: "text".to_string(),
            text: Some("window text".to_string()),
            observed_at_ms: now_u,
            bounds: None,
            bounds_observed_at_ms: None,
            ax_role: Some("AXStaticText".to_string()),
            focused: None,
        }],
        base_revision: None,
        added: vec![],
        updated: vec![],
        removed: vec![],
        truncated: false,
        missing_reasons: vec![],
        complete: true,
        geometry: None,
    });
    assert!(
        win_only.valid_window_only_channels(&window_policy),
        "empty input_records and input_gaps must pass valid_window_only_channels"
    );

    let mut with_input_rec = win_only.clone();
    with_input_rec.input_records = vec![rec_text];
    assert!(
        !with_input_rec.valid_window_only_channels(&window_policy),
        "focusAbsent: true with non-empty input_records MUST be rejected"
    );

    let mut with_input_gap = win_only;
    with_input_gap.input_gaps = gaps;
    assert!(
        !with_input_gap.valid_window_only_channels(&window_policy),
        "focusAbsent: true with non-empty input_gaps MUST be rejected"
    );
}

#[test]
fn phase5b_engine_input_text_causal_ordering_and_input_gaps_after_snapshots() {
    let validator = ContractValidator::new().unwrap();

    // Test both live (`fixture = false`, source = "win32.unicode") and fixture (`fixture = true`,
    // source overridden to "fixture").
    for is_fixture in [false, true] {
        let clock = MockClock::new(100_000, 1_700_000_300_000);
        let mut engine = CollectorEngine::new(
            "owner-p5b",
            "inst-p5b",
            "dev-p5b",
            "wts-1",
            "winsta0-default-wts-1",
            is_fixture,
            MockEnv::unlocked(),
            clock,
            validator.clone(),
        );
        let policy = CapturePolicy {
            enabled: true,
            allowed_application_ids: vec!["code.exe".to_string()],
            capture_scope: Some("window".to_string()),
            selection_capture: Some(true),
            input_text: Some(true),
            max_tree_nodes: Some(16),
            max_text_code_units: 512,
            debounce_ms: 10,
            max_wait_ms: 50,
            read_timeout_ms: 500,
            ..CapturePolicy::default()
        };
        engine.receive(&configure_msg("owner-p5b", "inst-p5b", 1, &policy));
        engine.receive(&control_msg("owner-p5b", "inst-p5b", 1, "start", 10_000));
        let _ = engine.drain_outputs();

        engine.clock.advance(60);
        engine.tick(true);
        let ticket = engine.environment.launched.pop().expect("ticket");
        let now_u = engine.clock.unix_ms();

        let app = ApplicationIdentity {
            application_id: "code.exe".to_string(),
            process_id: 5201,
            process_start_time: "unix-ms:1700000000000.000".to_string(),
        };
        let identity = WorkerSurfaceIdentity {
            session_id: "sess-ord".to_string(),
            window_id: "win-ord".to_string(),
            node_id: "node-ord".to_string(),
            surface_id: "surf-ord".to_string(),
            window_generation: 1,
            focus_generation: 1,
        };
        // First read from a fresh identity bumps foreground_generation and focus_generation by +1.
        let mut expected_stamp = engine.stamp();
        expected_stamp.foreground_generation += 1;
        expected_stamp.focus_generation += 1;
        let ctx = make_test_input_context(
            &app,
            Some("code.exe"),
            &identity,
            expected_stamp,
            "strict",
            SecureStatus::Safe,
            InputTextPrivateState::Normal,
        );

        // Provide 5 records out of timestamp order -> MUST sort ascending by interval_end_ms and
        // cap at 4 records!
        let make_rec = |text: &str, kind: InputTextKind, end_ms: i64| InputTextRecord {
            context: ctx.clone(),
            source: InputTextSource::Win32Unicode,
            event_kind: kind,
            text: text.to_string(),
            modifiers: vec![],
            interval_start_ms: end_ms - 10,
            interval_end_ms: end_ms,
            event_count: 1,
            extra_coverage_reasons: vec!["non-atomic-field-gate".to_string()],
        };
        let input_records = vec![
            make_rec("third", InputTextKind::Text, now_u - 100),
            make_rec("first", InputTextKind::Text, now_u - 300),
            make_rec("", InputTextKind::Return, now_u - 50),
            make_rec("second", InputTextKind::Text, now_u - 200),
            make_rec("fifth-dropped", InputTextKind::Text, now_u - 10),
        ];
        // Provide 5 input gaps -> MUST cap at 4 and emit strictly AFTER snapshots!
        let input_gaps = vec![
            InputTextGapRecord::new(InputTextGapReason::Budget),
            InputTextGapRecord::new(InputTextGapReason::Backpressure),
            InputTextGapRecord::new(InputTextGapReason::TargetMismatch),
            InputTextGapRecord::new(InputTextGapReason::RoleNotEditable),
            InputTextGapRecord::new(InputTextGapReason::ReadError),
        ];

        let res = ReadResult {
            token: ticket.token,
            application: Some(app.clone()),
            diagnostic_application: Some(app.clone()),
            exe_name: Some("code.exe".to_string()),
            text: Some(TextRead {
                text: "first second third".to_string(),
                source: "uia.text".to_string(),
                total_length: Some(18),
                selection: None,
                range_start: 0,
                range_basis: "prefix".to_string(),
                complete: true,
                truncated: false,
                missing_reasons: vec![],
                read_units: None,
            }),
            reason: None,
            diagnostic: None,
            enablement: None,
            session_identity: Some(identity),
            surface: Some(SurfaceReadResult {
                surface_id: "surf-ord".to_string(),
                revision: 1,
                scope: "window".to_string(),
                mode: "full".to_string(),
                nodes: vec![SurfaceNode {
                    id: "node-ord".to_string(),
                    parent_id: None,
                    role: "editable".to_string(),
                    text: Some("first second third".to_string()),
                    observed_at_ms: now_u,
                    bounds: None,
                    bounds_observed_at_ms: None,
                    ax_role: Some("AXTextField".to_string()),
                    focused: Some(true),
                }],
                base_revision: None,
                added: vec![],
                updated: vec![],
                removed: vec![],
                truncated: false,
                missing_reasons: vec![],
                complete: true,
                geometry: None,
            }),
            selection: Some(SelectionReadResult {
                text: "third".to_string(),
                source: "uia.text".to_string(),
                range_start: 13,
                truncated: false,
                missing_reasons: vec!["selection-only".to_string()],
            }),
            input_records,
            input_gaps,
            private_state: Some("normal".to_string()),
            observer_status: Some("best-effort".to_string()),
            focus_absent: None,
            surface_failure: None,
            verified_normal_browser: None,
            capture_start_ms: now_u - 5,
            capture_end_ms: now_u,
        };
        engine.complete(res);
        let msgs = emitted_messages(engine.drain_outputs());
        for m in &msgs {
            let bytes = validator.encode_frame(m).expect("every frame must pass ContractValidator");
            let text = std::str::from_utf8(&bytes).unwrap();
            assert!(!text.contains("exeName"), "internal exeName must never leak on wire");
        }

        let kinds: Vec<&str> = msgs
            .iter()
            .filter_map(|m| {
                m.get("payload")
                    .and_then(|p| p.get("kind"))
                    .and_then(JsonValue::as_str)
            })
            .collect();
        assert_eq!(
            kinds,
            vec![
                "context.changed",
                "input.text",
                "input.text",
                "input.text",
                "input.text",
                "text.snapshot",
                "surface.snapshot",
                "selection.snapshot",
                "gap",
                "gap",
                "gap",
                "gap",
            ],
            "causal order must be context.changed -> <=4 input.text -> text/surface/selection -> <=4 gaps"
        );

        let input_msgs: Vec<&JsonValue> = msgs
            .iter()
            .filter(|m| {
                m.get("payload")
                    .and_then(|p| p.get("kind"))
                    .and_then(JsonValue::as_str)
                    == Some("input.text")
            })
            .collect();
        let expected_source = if is_fixture { "fixture" } else { "win32.unicode" };
        let expected_texts = ["first", "second", "third", ""];
        let expected_ends = [now_u - 300, now_u - 200, now_u - 100, now_u - 50];
        for (i, m) in input_msgs.iter().enumerate() {
            let payload = m.get("payload").unwrap();
            assert_eq!(payload.get("source").and_then(JsonValue::as_str), Some(expected_source));
            assert_eq!(payload.get("text").and_then(JsonValue::as_str), Some(expected_texts[i]));
            assert_eq!(m.get("eventTimeMs").and_then(JsonValue::as_i64), Some(expected_ends[i]));
            assert_eq!(
                payload.get("intervalEndMs").and_then(JsonValue::as_i64),
                Some(expected_ends[i])
            );
            assert_eq!(
                m.get("target")
                    .and_then(|t| t.get("kind"))
                    .and_then(JsonValue::as_str),
                Some("resolved")
            );
            assert_eq!(
                m.get("target")
                    .and_then(|t| t.get("identity"))
                    .and_then(|id| id.get("applicationId"))
                    .and_then(JsonValue::as_str),
                Some("code.exe")
            );
            assert_eq!(m.get("stamp"), Some(&expected_stamp.to_json()));
        }

        let gap_codes: Vec<&str> = msgs
            .iter()
            .filter(|m| {
                m.get("payload")
                    .and_then(|p| p.get("kind"))
                    .and_then(JsonValue::as_str)
                    == Some("gap")
            })
            .filter_map(|m| {
                m.get("payload")
                    .and_then(|p| p.get("diagnostic"))
                    .and_then(|d| d.get("code"))
                    .and_then(JsonValue::as_str)
            })
            .collect();
        assert_eq!(
            gap_codes,
            vec![
                "input-text-budget",
                "input-text-backpressure",
                "input-target-mismatch",
                "input-role-not-editable",
            ]
        );
    }
}

#[test]
fn phase5b_engine_input_text_defense_in_depth_rejects_mismatched_oversized_and_denied_records() {
    let validator = ContractValidator::new().unwrap();
    let clock = MockClock::new(150_000, 1_700_000_400_000);
    let mut engine = CollectorEngine::new(
        "owner-did5b",
        "inst-did5b",
        "dev-p5b",
        "wts-1",
        "winsta0-default-wts-1",
        false,
        MockEnv::unlocked(),
        clock,
        validator.clone(),
    );
    let policy = CapturePolicy {
        enabled: true,
        application_scope: Some("denylist".to_string()),
        allow_browser_content: Some(true),
        input_text: Some(true),
        field_security: Some("strict".to_string()),
        max_text_code_units: 8,
        debounce_ms: 10,
        max_wait_ms: 50,
        read_timeout_ms: 500,
        ..CapturePolicy::default()
    };
    engine.receive(&configure_msg("owner-did5b", "inst-did5b", 1, &policy));
    engine.receive(&control_msg("owner-did5b", "inst-did5b", 1, "start", 20_000));
    let _ = engine.drain_outputs();

    let app = ApplicationIdentity {
        application_id: "code.exe".to_string(),
        process_id: 5301,
        process_start_time: "unix-ms:1700000000000.000".to_string(),
    };
    let identity = WorkerSurfaceIdentity {
        session_id: "sess-did".to_string(),
        window_id: "win-did".to_string(),
        node_id: "node-did".to_string(),
        surface_id: "surf-did".to_string(),
        window_generation: 1,
        focus_generation: 1,
    };

    // Establish stable identity with an initial valid read.
    engine.clock.advance(60);
    engine.tick(true);
    let t0 = engine.environment.launched.pop().expect("t0");
    let u0 = engine.clock.unix_ms();
    let mut seed = ReadResult::failure(t0.token, "read-error", None, u0, u0);
    seed.reason = None;
    seed.application = Some(app.clone());
    seed.exe_name = Some("code.exe".to_string());
    seed.session_identity = Some(identity.clone());
    seed.private_state = Some("normal".to_string());
    engine.complete(seed);
    let _ = engine.drain_outputs();

    let good_stamp = engine.stamp();
    let good_ctx = make_test_input_context(
        &app,
        Some("code.exe"),
        &identity,
        good_stamp,
        "strict",
        SecureStatus::Safe,
        InputTextPrivateState::Normal,
    );

    let make_bad = |label: &'static str, mutate: fn(&mut InputTextRecord)| -> (&'static str, InputTextRecord) {
        let mut r = InputTextRecord {
            context: good_ctx.clone(),
            source: InputTextSource::Win32Unicode,
            event_kind: InputTextKind::Text,
            text: "secret".to_string(),
            modifiers: vec![],
            interval_start_ms: 1_700_000_400_100,
            interval_end_ms: 1_700_000_400_110,
            event_count: 1,
            extra_coverage_reasons: vec![],
        };
        mutate(&mut r);
        (label, r)
    };

    let bad_cases: Vec<(&str, InputTextRecord)> = vec![
        make_bad("mismatched captureEpoch", |r| r.context.capture_epoch += 1),
        make_bad("mismatched focusGeneration", |r| r.context.focus_generation += 1),
        make_bad("mismatched foregroundGeneration", |r| r.context.foreground_generation += 1),
        make_bad("mismatched policyRevision", |r| r.context.policy_revision += 1),
        make_bad("mismatched surfaceId", |r| r.context.surface_id = "other-surf".to_string()),
        make_bad("mismatched windowId", |r| r.context.target.window_id = "other-win".to_string()),
        make_bad("mismatched windowGeneration", |r| r.context.target.window_generation += 1),
        make_bad("mismatched privateState", |r| r.context.private_state = InputTextPrivateState::UserAuthorized),
        make_bad("mismatched fieldSecurityMode", |r| r.context.field_security_mode = "denylist".to_string()),
        make_bad("denied secondary exeName (MSIX Bitwarden)", |r| r.context.exe_name = Some("bitwarden.exe".to_string())),
        make_bad("oversized > maxTextCodeUnits (9 > 8)", |r| r.text = "123456789".to_string()),
        make_bad("sensitive secureStatus", |r| r.context.secure_status = SecureStatus::Sensitive),
    ];

    // Feed each bad record paired with one valid record so every case is tested without hitting .take(4).
    for (idx, (label, mut bad_rec)) in bad_cases.into_iter().enumerate() {
        engine.clock.advance(1_100);
        engine.tick(true);
        let t = engine.environment.launched.pop().expect("ticket");
        let now_u = engine.clock.unix_ms();
        bad_rec.interval_start_ms = now_u - 20;
        bad_rec.interval_end_ms = now_u - 10;
        let ok_text = format!("ok-{idx}");
        let ok_rec = InputTextRecord {
            context: good_ctx.clone(),
            source: InputTextSource::Win32Unicode,
            event_kind: InputTextKind::Text,
            text: ok_text.clone(),
            modifiers: vec![],
            interval_start_ms: now_u - 5,
            interval_end_ms: now_u,
            event_count: 1,
            extra_coverage_reasons: vec![],
        };
        let mut res = ReadResult::failure(t.token, "read-error", None, now_u, now_u);
        res.reason = None;
        res.application = Some(app.clone());
        res.exe_name = Some("code.exe".to_string());
        res.session_identity = Some(identity.clone());
        res.private_state = Some("normal".to_string());
        res.input_records = vec![bad_rec, ok_rec];
        engine.complete(res);
        let msgs = emitted_messages(engine.drain_outputs());
        let texts: Vec<&str> = msgs
            .iter()
            .filter(|m| {
                m.get("payload")
                    .and_then(|p| p.get("kind"))
                    .and_then(JsonValue::as_str)
                    == Some("input.text")
            })
            .filter_map(|m| {
                m.get("payload")
                    .and_then(|p| p.get("text"))
                    .and_then(JsonValue::as_str)
            })
            .collect();
        assert_eq!(
            texts,
            vec![ok_text.as_str()],
            "defense-in-depth case '{label}' MUST silently drop bad record while emitting valid one"
        );
        for m in &msgs {
            validator.encode_frame(m).expect("wire valid");
        }
    }
}

#[test]
fn phase5b_engine_read_recovery_full_lifecycle_exhaustion_stale_cleanup_and_interrupts() {
    let validator = ContractValidator::new().unwrap();

    let make_input_engine = |id: &str, input_activity: bool| {
        let clock = MockClock::new(500_000, 1_700_000_500_000);
        let mut env = MockEnv::unlocked();
        env.abort_cleanup = Some(ReadTimeoutCleanup::Reaped);
        env.last_cleanup = ReadTimeoutCleanup::Reaped;
        let mut engine = CollectorEngine::new(
            id,
            id,
            "dev-p5b",
            "wts-1",
            "winsta0-default-wts-1",
            false,
            env,
            clock,
            validator.clone(),
        );
        let policy = CapturePolicy {
            enabled: true,
            allowed_application_ids: vec!["code.exe".to_string()],
            input_text: Some(true),
            input_activity: Some(input_activity),
            sample_interval_ms: Some(1_000),
            debounce_ms: 10,
            max_wait_ms: 50,
            read_timeout_ms: 1_500,
            ..CapturePolicy::default()
        };
        engine.receive(&configure_msg(id, id, 1, &policy));
        engine.receive(&control_msg(id, id, 1, "start", 30_000));
        let _ = engine.drain_outputs();
        engine.clock.advance(60);
        engine.tick(true);
        engine
    };

    // 1. Happy path: AwaitingExit -> Reaped + cooldown -> EXACT SAME stamp on
    //    `read-timeout-recovered`, `readOnlyAXEnablement = true` on next ticket, timeout gap after
    //    `read-timeout-recovered`, and coarse input activity tap NOT torn down.
    {
        let mut engine = make_input_engine("rec-happy", true);
        let expired = engine.environment.launched.pop().expect("initial ticket");
        let begin_calls_before = engine.environment.begin_calls;
        let tap_ends_before = engine.environment.input_activity_ends;
        let tap_begins_before = engine.environment.input_activity_begins;
        let clears_before = engine.environment.input_activity_clears;

        // Early worker_read_deadline_reached MUST be ignored.
        engine.worker_read_deadline_reached(expired.clone());
        assert!(engine.environment.aborted.is_empty());
        assert_eq!(engine.state(), "running");

        engine.environment.abort_cleanup = Some(ReadTimeoutCleanup::AwaitingExit);
        engine.environment.last_cleanup = ReadTimeoutCleanup::AwaitingExit;
        engine
            .clock
            .advance(expired.deadline_monotonic_ms - engine.clock.monotonic_ms());
        // Wrong epoch MUST be ignored.
        let mut wrong_epoch = expired.clone();
        wrong_epoch.capture_epoch -= 1;
        engine.worker_read_deadline_reached(wrong_epoch);
        assert!(engine.environment.aborted.is_empty());

        // Exact deadline fires ReadRecovery.
        engine.worker_read_deadline_reached(expired.clone());
        assert_eq!(engine.environment.aborted, vec![expired.clone()]);
        assert_eq!(engine.state(), "paused");
        assert!(engine.capture_epoch() > expired.capture_epoch);
        assert_eq!(engine.environment.input_activity_ends, tap_ends_before);
        assert!(engine.environment.input_activity_clears > clears_before);

        let raw_recovering = engine.drain_outputs();
        assert!(
            raw_recovering
                .iter()
                .any(|o| matches!(o, EngineOutput::DiscardQueuedObservations)),
            "timeout boundary MUST discard queued observations"
        );
        let rec_msgs = emitted_messages(raw_recovering);
        let recovering_state = rec_msgs
            .iter()
            .find(|m| m.get("type").and_then(JsonValue::as_str) == Some("state"))
            .expect("read-timeout-recovering state");
        assert_eq!(
            recovering_state.get("requestId").and_then(JsonValue::as_str),
            Some("read-recovery")
        );
        assert_eq!(
            recovering_state.get("state").and_then(JsonValue::as_str),
            Some("paused")
        );
        assert_eq!(
            recovering_state.get("reason").and_then(JsonValue::as_str),
            Some("read-timeout-recovering")
        );
        let recovering_stamp = recovering_state.get("stamp").unwrap().clone();
        validator.encode_frame(recovering_state).expect("wire valid");

        // Heartbeat & `start` during recovery keep paused state without starting.
        engine.receive(&control_msg("rec-happy", "rec-happy", 1, "heartbeat", 30_000));
        engine.receive(&control_msg("rec-happy", "rec-happy", 1, "start", 30_000));
        let mid_msgs = emitted_messages(engine.drain_outputs());
        assert_eq!(engine.state(), "paused");
        assert_eq!(mid_msgs.len(), 2);
        for m in &mid_msgs {
            assert_eq!(m.get("state").and_then(JsonValue::as_str), Some("paused"));
            assert_eq!(
                m.get("reason").and_then(JsonValue::as_str),
                Some("read-timeout-recovering")
            );
            validator.encode_frame(m).expect("wire valid");
        }

        // At 999ms still AwaitingExit -> not resumed. Then Reaped at 999ms -> still waits for 1000ms due.
        engine.clock.advance(999);
        engine.tick(true);
        assert_eq!(engine.state(), "paused");
        assert!(engine.environment.launched.is_empty());

        engine.environment.last_cleanup = ReadTimeoutCleanup::Reaped;
        engine.tick(true);
        assert_eq!(engine.state(), "paused");
        assert!(engine.environment.launched.is_empty());

        // Advance final 1ms -> recovers cleanly with EXACT SAME STAMP, gap AFTER recovered state,
        // and immediate retry ticket carrying `read_only_ax_enablement == Some(true)`.
        let val_before = engine.environment.validation_calls;
        engine.clock.advance(1);
        engine.tick(true);
        assert_eq!(engine.state(), "running");
        assert!(engine.environment.validation_calls > val_before);
        assert_eq!(engine.environment.begin_calls, begin_calls_before);
        assert_eq!(engine.environment.input_activity_begins, tap_begins_before);

        let retry = engine
            .environment
            .launched
            .pop()
            .expect("retry ticket launched immediately on recovery tick");
        assert_eq!(retry.read_only_ax_enablement, Some(true));
        assert_eq!(retry.capture_epoch, engine.capture_epoch());
        assert_ne!(retry.token, expired.token);

        let recovered_msgs = emitted_messages(engine.drain_outputs());
        for m in &recovered_msgs {
            validator.encode_frame(m).expect("wire valid");
        }
        let rec_idx = recovered_msgs
            .iter()
            .position(|m| {
                m.get("type").and_then(JsonValue::as_str) == Some("state")
                    && m.get("state").and_then(JsonValue::as_str) == Some("running")
                    && m.get("requestId").and_then(JsonValue::as_str) == Some("read-recovery")
                    && m.get("reason").and_then(JsonValue::as_str) == Some("read-timeout-recovered")
            })
            .expect("read-timeout-recovered emitted");
        assert_eq!(
            recovered_msgs[rec_idx].get("stamp"),
            Some(&recovering_stamp),
            "read-timeout-recovered MUST keep the EXACT SAME stamp as read-timeout-recovering"
        );
        let gap_idx = recovered_msgs
            .iter()
            .position(|m| {
                m.get("payload")
                    .and_then(|p| p.get("kind"))
                    .and_then(JsonValue::as_str)
                    == Some("gap")
                    && m.get("payload")
                        .and_then(|p| p.get("reason"))
                        .and_then(JsonValue::as_str)
                        == Some("timeout")
                    && m.get("payload")
                        .and_then(|p| p.get("diagnostic"))
                        .and_then(|d| d.get("code"))
                        .and_then(JsonValue::as_str)
                        == Some("read-deadline")
            })
            .expect("timeout gap emitted");
        assert!(
            rec_idx < gap_idx,
            "Host MUST see running read-timeout-recovered before timeout gap"
        );
    }

    // 2. Sliding 60s window: 3 recoveries (1s, 2s, 4s) exhaust on 4th timeout -> `read-timeout-exhausted`.
    {
        let mut engine = make_input_engine("rec-exhaust", false);
        for (attempt, delay) in [(1usize, 1_000i64), (2, 2_000), (3, 4_000)] {
            let expired = engine.environment.launched.pop().expect("outstanding");
            engine
                .clock
                .advance(expired.deadline_monotonic_ms - engine.clock.monotonic_ms());
            engine.tick(true);
            let _ = engine.drain_outputs();
            assert_eq!(engine.state(), "paused", "attempt {attempt} enters recovery pause");

            engine.clock.advance(delay - 1);
            engine.tick(true);
            assert_eq!(engine.state(), "paused", "attempt {attempt} waits full backoff {delay}ms");

            engine.clock.advance(1);
            engine.tick(true);
            assert_eq!(engine.state(), "running", "attempt {attempt} recovers at {delay}ms");
            let _ = engine.drain_outputs();
        }
        // 4th timeout inside 60s window MUST pause with `read-timeout-exhausted`!
        let fourth = engine.environment.launched.pop().expect("4th ticket");
        let epoch_before = engine.capture_epoch();
        engine
            .clock
            .advance(fourth.deadline_monotonic_ms - engine.clock.monotonic_ms());
        engine.tick(true);
        assert_eq!(engine.state(), "paused");
        assert!(engine.capture_epoch() > epoch_before);
        let msgs = emitted_messages(engine.drain_outputs());
        let state = msgs.last().expect("exhausted state");
        assert_eq!(state.get("requestId").and_then(JsonValue::as_str), Some("read-recovery"));
        assert_eq!(state.get("reason").and_then(JsonValue::as_str), Some("read-timeout-exhausted"));
        validator.encode_frame(state).expect("wire valid");

        // Aging out >60s + unlock MUST NEVER auto-resume a latched exhausted pause!
        engine.receive(&control_msg("rec-exhaust", "rec-exhaust", 1, "heartbeat", 30_000));
        engine.clock.advance(25_000);
        engine.receive(&control_msg("rec-exhaust", "rec-exhaust", 1, "heartbeat", 30_000));
        engine.clock.advance(25_000);
        engine.receive(&control_msg("rec-exhaust", "rec-exhaust", 1, "heartbeat", 30_000));
        engine.clock.advance(25_000);
        engine.desktop_changed(DesktopStatus::Unlocked, true);
        engine.tick(true);
        assert_eq!(engine.state(), "paused");
        assert!(engine.environment.launched.is_empty());
    }

    // 3. Late completion (`"stale"`) -> `paused / read-timeout-unrecoverable` without calling abort.
    {
        let mut engine = make_input_engine("rec-late", false);
        let ticket = engine.environment.launched.pop().expect("ticket");
        engine
            .clock
            .advance(ticket.deadline_monotonic_ms - engine.clock.monotonic_ms());
        let now_u = engine.clock.unix_ms();
        engine.complete(ReadResult::failure(ticket.token, "read-error", None, now_u, now_u));
        assert_eq!(engine.state(), "paused");
        assert!(engine.environment.aborted.is_empty());
        let msgs = emitted_messages(engine.drain_outputs());
        let state = msgs.last().expect("late completion state");
        assert_eq!(state.get("requestId").and_then(JsonValue::as_str), Some("read-recovery"));
        assert_eq!(
            state.get("reason").and_then(JsonValue::as_str),
            Some("read-timeout-unrecoverable")
        );
        validator.encode_frame(state).expect("wire valid");
    }

    // 4. Ineligible and Unconfirmed cleanup paths -> latched manual-resume pause.
    for (label, abort_c, poll_c, expected_reason) in [
        (
            "ineligible-immediate",
            ReadTimeoutCleanup::Ineligible,
            ReadTimeoutCleanup::Reaped,
            "read-timeout-unrecoverable",
        ),
        (
            "unconfirmed-immediate",
            ReadTimeoutCleanup::Unconfirmed,
            ReadTimeoutCleanup::Reaped,
            "worker-exit-unconfirmed",
        ),
        (
            "awaiting-then-timeout",
            ReadTimeoutCleanup::AwaitingExit,
            ReadTimeoutCleanup::AwaitingExit,
            "worker-exit-unconfirmed",
        ),
        (
            "awaiting-then-ineligible",
            ReadTimeoutCleanup::AwaitingExit,
            ReadTimeoutCleanup::Ineligible,
            "read-timeout-unrecoverable",
        ),
    ] {
        let mut engine = make_input_engine(label, false);
        engine.environment.abort_cleanup = Some(abort_c);
        engine.environment.last_cleanup = poll_c;
        let ticket = engine.environment.launched.pop().expect("ticket");
        engine
            .clock
            .advance(ticket.deadline_monotonic_ms - engine.clock.monotonic_ms());
        engine.tick(true);
        engine.clock.advance(1_000);
        engine.tick(true);
        assert_eq!(engine.state(), "paused", "{label}");
        let msgs = emitted_messages(engine.drain_outputs());
        let state = msgs
            .iter()
            .rev()
            .find(|m| m.get("type").and_then(JsonValue::as_str) == Some("state"))
            .expect("paused state");
        assert_eq!(
            state.get("reason").and_then(JsonValue::as_str),
            Some(expected_reason),
            "{label}"
        );
        validator.encode_frame(state).expect("wire valid");
        engine.desktop_changed(DesktopStatus::Unlocked, true);
        engine.clock.advance(5_000);
        engine.tick(true);
        assert_eq!(engine.state(), "paused", "{label} must never auto-resume");
        assert!(engine.environment.launched.is_empty(), "{label}");
    }

    // 5. Interrupting active ReadRecovery on desktop lock, Secure Input, input fault, or `resume`.
    for mode in ["lock", "secure-input", "input-session-fault", "input-activity-fault"] {
        let mut engine = make_input_engine(mode, true);
        let ticket = engine.environment.launched.pop().expect("ticket");
        engine
            .clock
            .advance(ticket.deadline_monotonic_ms - engine.clock.monotonic_ms());
        engine.tick(true);
        let _ = engine.drain_outputs();
        assert_eq!(engine.state(), "paused");

        match mode {
            "lock" => {
                engine.environment.desktop = DesktopStatus::Locked;
                engine.environment.desktop_reason = "screen-locked".to_string();
                engine.desktop_changed(DesktopStatus::Locked, false);
            }
            "secure-input" => {
                engine.secure_input_detected("secure-input");
            }
            "input-session-fault" => {
                engine.input_session_unavailable("input-monitoring-disabled");
            }
            "input-activity-fault" => {
                engine.input_activity_unavailable("input-monitoring-disabled");
            }
            _ => unreachable!(),
        }
        let int_msgs = emitted_messages(engine.drain_outputs());
        assert!(!int_msgs.is_empty(), "{mode} emits interrupted state");
        for m in &int_msgs {
            validator.encode_frame(m).expect("wire valid");
        }
        // Restoring desktop + waiting past cooldown MUST NEVER auto-resume!
        engine.environment.desktop = DesktopStatus::Unlocked;
        engine.environment.desktop_reason = "ready".to_string();
        engine.desktop_changed(DesktopStatus::Unlocked, true);
        engine.clock.advance(5_000);
        engine.tick(true);
        assert_eq!(engine.state(), "paused", "{mode} MUST NOT auto-resume");
        assert!(engine.environment.launched.is_empty(), "{mode}");
    }

    // 6. `resume` while ReadRecovery is active cancels recovery and starts a fresh epoch cleanly
    //    (with `read_only_ax_enablement` reset to `None`).
    {
        let mut engine = make_input_engine("rec-resume", false);
        let ticket = engine.environment.launched.pop().expect("ticket");
        engine
            .clock
            .advance(ticket.deadline_monotonic_ms - engine.clock.monotonic_ms());
        engine.tick(true);
        let _ = engine.drain_outputs();
        assert_eq!(engine.state(), "paused");
        let rec_epoch = engine.capture_epoch();

        engine.receive(&control_msg("rec-resume", "rec-resume", 1, "resume", 30_000));
        let msgs = emitted_messages(engine.drain_outputs());
        assert_eq!(engine.state(), "running");
        assert!(engine.capture_epoch() > rec_epoch);
        let state = msgs.last().expect("started state");
        assert_eq!(state.get("reason").and_then(JsonValue::as_str), Some("started"));
        validator.encode_frame(state).expect("wire valid");

        engine.clock.advance(60);
        engine.tick(true);
        let fresh = engine.environment.launched.pop().expect("fresh ticket after resume");
        assert_eq!(fresh.read_only_ax_enablement, None);
    }
}
