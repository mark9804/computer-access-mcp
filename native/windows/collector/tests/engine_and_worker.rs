use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI64, Ordering};
use std::thread;
use std::time::Duration;

use access_contract::{ContractValidator, JsonValue};
use collector_core::engine::{
    CollectorEngine, CollectorEnvironment, EngineOutput, MonitoringCheck,
};
use collector_core::fixture::execute_fixture_read;
use collector_core::ownership::is_pid_alive;
use collector_core::protocol_model::{
    generate_uuid_v4, json_i64, ApplicationIdentity, CapturePolicy, CollectorClock, DesktopStatus,
    GapDiagnostic, GapDiagnosticCode, SurfaceNode, SurfaceReadResult, SystemCollectorClock,
    TextRead, WorkerSurfaceIdentity,
};
use collector_core::worker_ipc::{JobWorkerSupervisor, ReadResult, ReadTicket, WorkerEvent};

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
    launched: Vec<ReadTicket>,
    cancelled: usize,
}

impl MockEnv {
    fn unlocked() -> Self {
        Self {
            desktop: DesktopStatus::Unlocked,
            desktop_reason: "ready".to_string(),
            launched: Vec::new(),
            cancelled: 0,
        }
    }
}

impl CollectorEnvironment for MockEnv {
    fn desktop_reason(&self) -> &str {
        &self.desktop_reason
    }
    fn begin_monitoring(&mut self) -> MonitoringCheck {
        MonitoringCheck {
            desktop: self.desktop,
            accessibility: true,
        }
    }
    fn validate_before_accept(&mut self) -> MonitoringCheck {
        MonitoringCheck {
            desktop: self.desktop,
            accessibility: true,
        }
    }
    fn end_monitoring(&mut self) {}
    fn launch(&mut self, ticket: ReadTicket) -> Option<WorkerEvent> {
        self.launched.push(ticket);
        None
    }
    fn cancel_read(&mut self) {
        self.cancelled += 1;
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
        private_state: Some("normal".to_string()),
        observer_status: Some("unavailable".to_string()),
        focus_absent: None,
        surface_failure: None,
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
        private_state: Some("normal".to_string()),
        observer_status: Some("best-effort".to_string()),
        focus_absent: None,
        surface_failure: None,
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
    PathBuf::from(env!("CARGO_BIN_EXE_computer-access-collector"))
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
