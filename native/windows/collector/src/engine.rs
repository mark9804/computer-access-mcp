use std::collections::BTreeMap;
use std::path::PathBuf;

use access_contract::{
    is_valid_application_id, utf16_len, ContractValidator, JsonValue, ProtocolError,
};

use crate::desktop::{assess_windows_desktop, DesktopBoundaryLatch};
use crate::input_activity_win32::{
    monotonic_qpc_ns_now, validate_input_activity_application, RawInputActivityMonitor,
    RawInputNotice,
};
use crate::menu_action_core::{MenuActionRecord, MenuPathLimits};
use crate::policy::{ApplicationPolicy, BrowserGate, ResolvedAppIdentity};
use crate::protocol_model::{
    generate_uuid_v4, hello_message, json_i64, json_text_range, unresolved_target,
    ApplicationIdentity, ApplicationTargetIdentity, CapturePolicy, CollectorClock, ContentGate,
    Coverage, DesktopStatus, GapDiagnostic, GapDiagnosticCode, InputActivityAccumulator,
    InputActivityCategory, InputActivitySample, SourceHint, Stamp, SystemCollectorClock,
    TargetIdentity, TextRead, WorkerSurfaceIdentity, MAX_SAFE_INTEGER,
};
use crate::transport::DebugTrace;
use crate::worker_ipc::{JobWorkerSupervisor, ReadResult, ReadTicket, ReadTimeoutCleanup, WorkerEvent};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitoringCheck {
    pub desktop: DesktopStatus,
    pub accessibility: bool,
}

/// Platform environment abstraction so `CollectorEngine` is 100% unit-testable without live OS calls.
pub trait CollectorEnvironment {
    fn desktop_reason(&self) -> &str;
    fn secure_input_blocked(&self) -> bool {
        false
    }
    fn begin_monitoring(&mut self) -> MonitoringCheck;
    fn validate_before_accept(&mut self) -> MonitoringCheck;
    fn end_monitoring(&mut self);
    fn input_activity_reason(&self) -> &str {
        "input-monitoring-unavailable"
    }
    fn input_monitoring_granted(&self) -> bool {
        false
    }
    fn input_activity_healthy(&self) -> bool {
        true
    }
    fn begin_input_activity(&mut self, _policy: &CapturePolicy) -> bool {
        false
    }
    fn end_input_activity(&mut self) {}
    fn clear_input_activity(&mut self) {}
    fn validate_input_activity(&mut self, _application: &ApplicationIdentity) -> bool {
        false
    }
    fn validate_input_activity_identity(
        &mut self,
        application: &ApplicationIdentity,
        _resolved: &ResolvedAppIdentity,
    ) -> bool {
        self.validate_input_activity(application)
    }
    fn configure_policy(&mut self, _policy: &CapturePolicy) {}
    fn launch(&mut self, ticket: ReadTicket) -> Option<WorkerEvent>;
    fn cancel_read(&mut self) -> ReadTimeoutCleanup;
    fn retire_read(&mut self) -> Option<WorkerEvent> {
        let _ = self.cancel_read();
        None
    }
    fn abort_timed_out_read(&mut self, _ticket: &ReadTicket) -> ReadTimeoutCleanup {
        ReadTimeoutCleanup::Ineligible
    }
    fn timed_out_read_cleanup(&self) -> ReadTimeoutCleanup {
        ReadTimeoutCleanup::Ineligible
    }
    fn ready_for_read(&self) -> bool {
        true
    }
    fn poll(&mut self) -> EnvironmentPollEvents {
        EnvironmentPollEvents::default()
    }
}

#[derive(Debug, Default)]
pub struct EnvironmentPollEvents {
    pub worker_events: Vec<WorkerEvent>,
    pub desktop_change: Option<MonitoringCheck>,
    pub input_samples: Vec<InputActivitySample>,
    pub input_notices: Vec<RawInputNotice>,
    pub input_activity_unavailable: Option<String>,
}

/// Production Windows & fixture environment backed by `JobWorkerSupervisor`, live WTS/Win32
/// desktop gates, and the control-process `RawInputActivityMonitor`.
pub struct WindowsEnvironment {
    fixture: bool,
    scenario: String,
    worker: JobWorkerSupervisor,
    raw_input: Option<RawInputActivityMonitor>,
    active: bool,
    boundary: DesktopBoundaryLatch,
    desktop_reason: String,
    next_desktop_check_ms: i64,
    fixture_input: bool,
    next_fixture_input_ms: i64,
    capture_policy: Option<CapturePolicy>,
    input_policy: Option<CapturePolicy>,
    input_activity_reason: String,
}

impl WindowsEnvironment {
    pub fn new(executable: PathBuf, fixture: bool, scenario: impl Into<String>) -> Self {
        let scenario = scenario.into();
        let worker = JobWorkerSupervisor::new(executable, fixture, scenario.clone());
        Self {
            fixture,
            scenario,
            worker,
            raw_input: None,
            active: false,
            boundary: DesktopBoundaryLatch::new(),
            desktop_reason: "desktop-unavailable".to_string(),
            next_desktop_check_ms: 0,
            fixture_input: false,
            next_fixture_input_ms: 0,
            capture_policy: None,
            input_policy: None,
            input_activity_reason: "input-monitoring-unavailable".to_string(),
        }
    }

    fn fixture_desktop(&mut self) -> MonitoringCheck {
        match self.scenario.as_str() {
            "locked" => {
                self.desktop_reason = "screen-locked".to_string();
                MonitoringCheck {
                    desktop: DesktopStatus::Locked,
                    accessibility: true,
                }
            }
            "unknown" => {
                self.desktop_reason = "desktop-unavailable".to_string();
                MonitoringCheck {
                    desktop: DesktopStatus::Unknown,
                    accessibility: true,
                }
            }
            _ => {
                self.desktop_reason = "ready".to_string();
                MonitoringCheck {
                    desktop: DesktopStatus::Unlocked,
                    accessibility: true,
                }
            }
        }
    }
}

impl CollectorEnvironment for WindowsEnvironment {
    fn desktop_reason(&self) -> &str {
        &self.desktop_reason
    }

    fn begin_monitoring(&mut self) -> MonitoringCheck {
        self.active = true;
        if self.fixture {
            return self.fixture_desktop();
        }
        // Only explicit owner `start`/`resume` calls `begin_monitoring()`, so clear sticky latches here.
        self.boundary.reset_for_user_action();
        if let Some(ref mon) = self.raw_input {
            mon.reset_desktop_latch_for_user_action(monotonic_qpc_ns_now());
        }
        self.next_desktop_check_ms = SystemCollectorClock::monotonic_ms_now() + 250;
        self.validate_before_accept()
    }

    fn validate_before_accept(&mut self) -> MonitoringCheck {
        if !self.active {
            return MonitoringCheck {
                desktop: DesktopStatus::Unknown,
                accessibility: false,
            };
        }
        if self.fixture {
            return self.fixture_desktop();
        }
        if self
            .raw_input
            .as_ref()
            .is_some_and(RawInputActivityMonitor::is_desktop_latched)
        {
            self.boundary.block();
            self.desktop_reason = "desktop-lock-transition".to_string();
        }
        if self.boundary.is_latched() {
            return MonitoringCheck {
                desktop: DesktopStatus::Unknown,
                accessibility: false,
            };
        }
        let assessment = assess_windows_desktop();
        self.desktop_reason = assessment.reason.to_string();
        let status = self.boundary.observe(&assessment);
        // On Windows UIA requires no separate TCC grant; desktop unlocked suffices.
        MonitoringCheck {
            desktop: status,
            accessibility: status == DesktopStatus::Unlocked,
        }
    }

    fn end_monitoring(&mut self) {
        self.end_input_activity();
        self.active = false;
    }

    fn input_activity_reason(&self) -> &str {
        &self.input_activity_reason
    }

    fn input_monitoring_granted(&self) -> bool {
        true
    }

    fn input_activity_healthy(&self) -> bool {
        if self.fixture {
            self.fixture_input
        } else {
            self.raw_input
                .as_ref()
                .is_some_and(RawInputActivityMonitor::is_healthy)
        }
    }

    fn begin_input_activity(&mut self, policy: &CapturePolicy) -> bool {
        self.end_input_activity();
        self.input_activity_reason = "input-monitoring-unavailable".to_string();
        if !self.active || policy.input_activity != Some(true) {
            return false;
        }
        self.input_policy = Some(policy.clone());
        if self.fixture {
            self.fixture_input = self.scenario == "activity";
            self.next_fixture_input_ms = 0;
            return self.fixture_input;
        }
        match RawInputActivityMonitor::start() {
            Ok(monitor) => {
                let now_qpc = monotonic_qpc_ns_now();
                monitor.reset_desktop_latch_for_user_action(now_qpc);
                monitor.set_policy(Some(policy.clone()), now_qpc);
                if !monitor.is_healthy() {
                    let mut dead = monitor;
                    dead.stop();
                    self.input_policy = None;
                    return false;
                }
                self.raw_input = Some(monitor);
                true
            }
            Err(_) => {
                self.input_policy = None;
                false
            }
        }
    }

    fn end_input_activity(&mut self) {
        if let Some(mut monitor) = self.raw_input.take() {
            monitor.set_policy(None, monotonic_qpc_ns_now());
            monitor.stop();
        }
        self.fixture_input = false;
        self.next_fixture_input_ms = 0;
        self.input_policy = None;
    }

    fn clear_input_activity(&mut self) {
        // Epoch/boundary fence only — NEVER clears a sticky WTS desktop lock/disconnect latch.
        if let Some(ref monitor) = self.raw_input {
            monitor.reset_boundary(monotonic_qpc_ns_now());
        }
    }

    fn configure_policy(&mut self, policy: &CapturePolicy) {
        self.capture_policy = Some(policy.clone());
        if policy.input_activity != Some(true) {
            self.end_input_activity();
        } else if let Some(ref monitor) = self.raw_input {
            monitor.set_policy(Some(policy.clone()), monotonic_qpc_ns_now());
            self.input_policy = Some(policy.clone());
        }
    }

    fn validate_input_activity(&mut self, application: &ApplicationIdentity) -> bool {
        let Some(resolved) = ResolvedAppIdentity::from_single(application.application_id.clone())
        else {
            return false;
        };
        self.validate_input_activity_identity(application, &resolved)
    }

    fn validate_input_activity_identity(
        &mut self,
        application: &ApplicationIdentity,
        resolved: &ResolvedAppIdentity,
    ) -> bool {
        if self.fixture {
            return self.active
                && self.fixture_input
                && self.input_policy.as_ref().is_some_and(|p| {
                    p.input_activity == Some(true) && ApplicationPolicy::allows_identity(p, resolved)
                })
                && application.application_id == "test.allowed"
                && application.process_id == 4242
                && application.process_start_time == "fixture-birth-1";
        }
        if !self.active || self.boundary.is_latched() {
            return false;
        }
        let (Some(ref policy), Some(ref monitor)) = (&self.input_policy, &self.raw_input) else {
            return false;
        };
        if monitor.is_desktop_latched() || !monitor.is_healthy() {
            return false;
        }
        validate_input_activity_application(application, resolved, policy, monitor.is_healthy())
    }

    fn launch(&mut self, ticket: ReadTicket) -> Option<WorkerEvent> {
        self.worker.launch(ticket)
    }

    fn cancel_read(&mut self) -> ReadTimeoutCleanup {
        self.worker.cancel()
    }

    fn retire_read(&mut self) -> Option<WorkerEvent> {
        self.worker.retire()
    }

    fn abort_timed_out_read(&mut self, ticket: &ReadTicket) -> ReadTimeoutCleanup {
        self.worker.abort_timed_out_read(ticket)
    }

    fn timed_out_read_cleanup(&self) -> ReadTimeoutCleanup {
        self.worker.timed_out_read_cleanup()
    }

    fn ready_for_read(&self) -> bool {
        self.worker.ready_for_read()
    }

    fn poll(&mut self) -> EnvironmentPollEvents {
        let mut out = EnvironmentPollEvents {
            worker_events: self.worker.poll(),
            desktop_change: None,
            input_samples: Vec::new(),
            input_notices: Vec::new(),
            input_activity_unavailable: None,
        };

        if let Some(ref monitor) = self.raw_input {
            if !monitor.is_healthy() {
                out.input_activity_unavailable = Some("input-monitoring-disabled".to_string());
            }
            let notices = monitor.drain_events();
            let saw_boundary_loss = monitor.is_desktop_latched()
                || notices
                    .iter()
                    .any(|n| matches!(n, RawInputNotice::DesktopBoundaryLost));
            if saw_boundary_loss {
                self.boundary.block();
                self.desktop_reason = "desktop-lock-transition".to_string();
                out.desktop_change = Some(MonitoringCheck {
                    desktop: DesktopStatus::Unknown,
                    accessibility: false,
                });
            } else {
                out.input_notices = notices;
            }
        }

        if self.fixture_input && self.active {
            let now_unix = SystemCollectorClock::unix_ms_now();
            if now_unix >= self.next_fixture_input_ms {
                self.next_fixture_input_ms = (now_unix / 1_000 + 1) * 1_000;
                out.input_samples.push(InputActivitySample {
                    application: ApplicationIdentity {
                        application_id: "test.allowed".to_string(),
                        process_id: 4242,
                        process_start_time: "fixture-birth-1".to_string(),
                    },
                    exe_name: None,
                    category: InputActivityCategory::PointerRelease,
                    callback_time_ms: now_unix,
                });
            }
        }

        if self.active && !self.fixture && out.desktop_change.is_none() {
            let now = SystemCollectorClock::monotonic_ms_now();
            if now >= self.next_desktop_check_ms {
                self.next_desktop_check_ms = now + 250;
                out.desktop_change = Some(self.validate_before_accept());
            }
        }

        out
    }
}

/// Actions emitted by `CollectorEngine` for the host transport layer to execute.
#[derive(Debug, Clone)]
pub enum EngineOutput {
    Emit(JsonValue),
    DiscardQueuedObservations,
}

/// Serial, platform-free collector control state machine mirroring `CollectorEngine.swift`.
pub struct CollectorEngine<E: CollectorEnvironment, C: CollectorClock> {
    pub owner_id: String,
    pub instance_id: String,
    pub device_id: String,
    pub fixture: bool,
    os_session_id: String,
    desktop_id: String,
    pub environment: E,
    pub clock: C,
    validator: ContractValidator,

    state: &'static str,
    policy_revision: i64,
    capture_epoch: i64,
    foreground_generation: i64,
    focus_generation: i64,
    should_exit: bool,
    outstanding: Option<ReadTicket>,
    desktop: DesktopStatus,
    policy: Option<CapturePolicy>,
    user_paused: bool,
    primary_pause_reason: Option<String>,
    secure_input_suspended: bool,
    has_started: bool,
    lease_until: i64,
    seq: i64,
    snapshot_serial: i64,
    debug_request_serial: i64,
    target: JsonValue,
    next_read: Option<i64>,
    pending_hint: Option<SourceHint>,
    last_read: Option<i64>,
    input_accumulator: InputActivityAccumulator,
    input_listener_active: bool,
    observed_application: Option<ApplicationIdentity>,
    epoch_application_anchor: Option<(i64, ApplicationIdentity)>,
    worker_identity: Option<WorkerSurfaceIdentity>,
    dirty_since: Option<i64>,
    read_only_ax_enablement: bool,
    next_read_fast_only: bool,
    pending_submit_fast_read: bool,
    menu_tracking_until_ms: Option<i64>,
    capture_diagnostics: Option<JsonValue>,
    input_session_established: bool,

    // Volatile single-step snapshot deduplication & blank suppression.
    last_text_state: Option<JsonValue>,
    last_surface_state: Option<JsonValue>,
    last_selection_state: Option<JsonValue>,
    text_had_nonblank: bool,
    selection_had_nonblank: bool,
    last_surface_revision: Option<i64>,
    last_unavailable_state: Option<JsonValue>,

    pending_outputs: Vec<EngineOutput>,
}

impl<E: CollectorEnvironment, C: CollectorClock> CollectorEngine<E, C> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_id: impl Into<String>,
        instance_id: impl Into<String>,
        device_id: impl Into<String>,
        os_session_id: impl Into<String>,
        desktop_id: impl Into<String>,
        fixture: bool,
        environment: E,
        clock: C,
        validator: ContractValidator,
    ) -> Self {
        let lease_until = clock.monotonic_ms() + 30_000;
        Self {
            owner_id: owner_id.into(),
            instance_id: instance_id.into(),
            device_id: device_id.into(),
            fixture,
            os_session_id: os_session_id.into(),
            desktop_id: desktop_id.into(),
            environment,
            clock,
            validator,
            state: "unconfigured",
            policy_revision: 0,
            capture_epoch: 0,
            foreground_generation: 0,
            focus_generation: 0,
            should_exit: false,
            outstanding: None,
            desktop: DesktopStatus::Unknown,
            policy: None,
            user_paused: false,
            primary_pause_reason: None,
            secure_input_suspended: false,
            has_started: false,
            lease_until,
            seq: 0,
            snapshot_serial: 0,
            debug_request_serial: 0,
            target: unresolved_target("not-observed"),
            next_read: None,
            pending_hint: None,
            last_read: None,
            input_accumulator: InputActivityAccumulator::default(),
            input_listener_active: false,
            observed_application: None,
            epoch_application_anchor: None,
            worker_identity: None,
            dirty_since: None,
            read_only_ax_enablement: false,
            next_read_fast_only: false,
            pending_submit_fast_read: false,
            menu_tracking_until_ms: None,
            capture_diagnostics: None,
            input_session_established: false,
            last_text_state: None,
            last_surface_state: None,
            last_selection_state: None,
            text_had_nonblank: false,
            selection_had_nonblank: false,
            last_surface_revision: None,
            last_unavailable_state: None,
            pending_outputs: Vec::new(),
        }
    }

    pub fn state(&self) -> &'static str {
        self.state
    }

    pub fn should_exit(&self) -> bool {
        self.should_exit
    }

    pub fn policy_revision(&self) -> i64 {
        self.policy_revision
    }

    pub fn capture_epoch(&self) -> i64 {
        self.capture_epoch
    }

    pub fn outstanding(&self) -> Option<&ReadTicket> {
        self.outstanding.as_ref()
    }

    pub fn stamp(&self) -> Stamp {
        Stamp {
            capture_epoch: self.capture_epoch,
            foreground_generation: self.foreground_generation,
            focus_generation: self.focus_generation,
            policy_revision: self.policy_revision,
        }
    }

    pub fn drain_outputs(&mut self) -> Vec<EngineOutput> {
        std::mem::take(&mut self.pending_outputs)
    }

    fn emit(&mut self, msg: JsonValue) {
        self.pending_outputs.push(EngineOutput::Emit(msg));
    }

    pub fn hello(&mut self) {
        self.emit(hello_message(&self.instance_id, self.fixture));
    }

    pub fn failure(&mut self, code: &str, request_id: &str) {
        let mut map = BTreeMap::new();
        map.insert("protocolVersion".to_string(), json_i64(1));
        map.insert("type".to_string(), JsonValue::String("error".to_string()));
        map.insert(
            "requestId".to_string(),
            JsonValue::String(request_id.to_string()),
        );
        map.insert("code".to_string(), JsonValue::String(code.to_string()));
        map.insert("retryable".to_string(), JsonValue::Bool(false));
        self.emit(JsonValue::Object(map));
    }

    fn state_message(&mut self, request_id: &str, reason: &str) {
        let effective = if self.state == "paused" && self.secure_input_suspended {
            "secure-input-suppressed".to_string()
        } else if self.state == "paused" {
            let primary = self.primary_pause_reason.is_none();
            if primary {
                self.primary_pause_reason = Some(reason.to_string());
            }
            if request_id != "heartbeat" && reason != "heartbeat" {
                DebugTrace::record(
                    "collector-pause",
                    &[],
                    &[("primary", primary)],
                    &[("reason", reason)],
                    file!(),
                    line!(),
                );
            }
            self.primary_pause_reason
                .clone()
                .unwrap_or_else(|| reason.to_string())
        } else {
            self.primary_pause_reason = None;
            reason.to_string()
        };

        let mut map = BTreeMap::new();
        map.insert("protocolVersion".to_string(), json_i64(1));
        map.insert("type".to_string(), JsonValue::String("state".to_string()));
        map.insert(
            "requestId".to_string(),
            JsonValue::String(request_id.to_string()),
        );
        map.insert(
            "instanceId".to_string(),
            JsonValue::String(self.instance_id.clone()),
        );
        map.insert("state".to_string(), JsonValue::String(self.state.to_string()));
        map.insert("stamp".to_string(), self.stamp().to_json());
        map.insert("reason".to_string(), JsonValue::String(effective));
        if let Some(ref diag) = self.capture_diagnostics {
            map.insert("captureDiagnostics".to_string(), diag.clone());
        }
        self.emit(JsonValue::Object(map));
    }

    pub fn receive(&mut self, message: &JsonValue) {
        if self.should_exit {
            return;
        }
        if self.clock.monotonic_ms() >= self.lease_until {
            self.stop("lease-expired", "lease");
            return;
        }
        let request = message
            .get("requestId")
            .and_then(JsonValue::as_str)
            .unwrap_or("invalid")
            .to_string();
        let msg_type = message.get("type").and_then(JsonValue::as_str);
        if !matches!(msg_type, Some("configure" | "control")) {
            let code = if msg_type == Some("action.request") {
                "unsupported"
            } else {
                "invalid-message"
            };
            self.failure(code, &request);
            return;
        }

        let owner_ok =
            message.get("ownerId").and_then(JsonValue::as_str) == Some(self.owner_id.as_str());
        let inst_ok = message.get("instanceId").and_then(JsonValue::as_str)
            == Some(self.instance_id.as_str());
        if !owner_ok || !inst_ok {
            self.failure("permission-denied", &request);
            return;
        }
        let Some(revision) = message.get("policyRevision").and_then(JsonValue::as_i64) else {
            self.failure("invalid-message", &request);
            return;
        };

        if msg_type == Some("configure") {
            let parsed = message.get("policy").and_then(CapturePolicy::from_json);
            if revision <= self.policy_revision || parsed.is_none() {
                self.failure("stale", &request);
                return;
            }
            let parsed = parsed.unwrap();
            if !parsed.has_valid_text_settings() {
                self.failure("invalid-message", &request);
                return;
            }
            if !self.fixture
                && (parsed.input_text == Some(true) || parsed.text_markers == Some(true))
            {
                self.failure("unsupported", &request);
                return;
            }
            let _ = self.boundary("policy-boundary", true, false);
            self.environment.end_monitoring();
            self.desktop = DesktopStatus::Unknown;
            self.policy_revision = revision;
            self.environment.configure_policy(&parsed);
            let enabled = parsed.enabled;
            self.policy = Some(parsed);
            self.has_started = false;
            self.user_paused = false;
            self.state = "ready";

            let mut configured = BTreeMap::new();
            configured.insert("protocolVersion".to_string(), json_i64(1));
            configured.insert(
                "type".to_string(),
                JsonValue::String("configured".to_string()),
            );
            configured.insert("requestId".to_string(), JsonValue::String(request.clone()));
            configured.insert(
                "ownerId".to_string(),
                JsonValue::String(self.owner_id.clone()),
            );
            configured.insert(
                "instanceId".to_string(),
                JsonValue::String(self.instance_id.clone()),
            );
            configured.insert(
                "policyRevision".to_string(),
                json_i64(self.policy_revision),
            );
            self.emit(JsonValue::Object(configured));
            self.state_message(&request, if enabled { "configured" } else { "policy-disabled" });
            return;
        }

        if self.policy.is_none() || revision != self.policy_revision {
            self.failure("stale", &request);
            return;
        }
        let Some(command) = message.get("command").and_then(JsonValue::as_str) else {
            self.failure("invalid-message", &request);
            return;
        };
        let Some(duration) = message.get("leaseDurationMs").and_then(JsonValue::as_i64) else {
            self.failure("invalid-message", &request);
            return;
        };
        if !(1..=30_000).contains(&duration) {
            self.failure("invalid-message", &request);
            return;
        }
        self.lease_until = self.clock.monotonic_ms() + duration;

        match command {
            "start" | "resume" => {
                let policy = self.policy.clone().unwrap();
                if !policy.enabled {
                    self.failure("permission-denied", &request);
                    return;
                }
                if command == "start" && self.user_paused {
                    self.state_message(&request, "user-paused");
                    return;
                }
                if command == "resume" {
                    self.user_paused = false;
                }
                self.primary_pause_reason = None;
                self.secure_input_suspended = false;
                self.input_session_established = false;
                self.read_only_ax_enablement = false;
                self.has_started = true;
                let cleanup = self.boundary("not-observed", true, false);

                if !self.environment.ready_for_read()
                    || cleanup == ReadTimeoutCleanup::Unconfirmed
                {
                    self.user_paused = true;
                    self.state = "paused";
                    self.state_message(&request, "worker-exit-unconfirmed");
                    return;
                }

                let check = self.environment.begin_monitoring();
                self.desktop = check.desktop;
                if check.accessibility && self.environment.secure_input_blocked() {
                    self.state = "running";
                    self.secure_input_detected(&request);
                    return;
                }
                if self.desktop != DesktopStatus::Unlocked || !check.accessibility {
                    if policy.input_activity == Some(true) || policy.input_text == Some(true) {
                        self.user_paused = true;
                    }
                    let reason = if self.desktop != DesktopStatus::Unlocked {
                        self.environment.desktop_reason().to_string()
                    } else {
                        "permission-denied".to_string()
                    };
                    self.state = "paused";
                    self.state_message(&request, &reason);
                    return;
                }

                if policy.input_activity == Some(true) {
                    if !self.environment.begin_input_activity(&policy) {
                        let reason = self.environment.input_activity_reason().to_string();
                        if reason == "secure-input-active" {
                            self.state = "running";
                            self.secure_input_detected(&request);
                            return;
                        }
                        self.user_paused = true;
                        self.environment.end_input_activity();
                        self.state = "paused";
                        self.state_message(&request, &reason);
                        return;
                    }
                    self.input_listener_active = true;
                }

                self.state = "running";
                self.schedule();
                self.state_message(&request, "started");
            }
            "pause" => {
                self.secure_input_suspended = false;
                self.primary_pause_reason = None;
                self.user_paused = true;
                let cleanup = self.boundary("policy-boundary", true, false);
                self.state = "paused";
                let pause_reason = if cleanup == ReadTimeoutCleanup::Unconfirmed {
                    "worker-exit-unconfirmed"
                } else {
                    "user-paused"
                };
                self.state_message(&request, pause_reason);
            }
            "stop" => self.stop("stopped", &request),
            "heartbeat" => self.state_message(&request, "heartbeat"),
            _ => self.failure("invalid-message", &request),
        }
    }

    pub fn stop(&mut self, reason: &str, request_id: &str) {
        if self.should_exit {
            return;
        }
        self.secure_input_suspended = false;
        let _ = self.boundary("policy-boundary", true, false);
        self.environment.end_monitoring();
        self.desktop = DesktopStatus::Unknown;
        self.state = "stopped";
        self.should_exit = true;
        self.state_message(request_id, reason);
    }

    fn pause_worker_exit_unconfirmed(&mut self, request_id: &str) {
        if self.should_exit || (!self.has_started && self.state != "running") {
            return;
        }
        self.outstanding = None;
        self.next_read = None;
        self.next_read_fast_only = false;
        self.pending_submit_fast_read = false;
        self.dirty_since = None;
        self.clear_input_activity();
        self.input_listener_active = false;
        self.environment.end_input_activity();
        self.clear_snapshot_states();
        let was_secure = self.secure_input_suspended;
        self.secure_input_suspended = false;
        self.user_paused = true;
        if self.state == "running"
            || was_secure
            || self.primary_pause_reason.as_deref() != Some("worker-exit-unconfirmed")
        {
            self.primary_pause_reason = None;
            self.state = "paused";
            self.state_message(request_id, "worker-exit-unconfirmed");
        }
    }

    fn boundary(&mut self, unresolved: &str, end_input: bool, retire_input: bool) -> ReadTimeoutCleanup {
        self.last_unavailable_state = None;
        if end_input {
            self.input_listener_active = false;
            self.environment.end_input_activity();
        }
        self.clear_input_activity();
        self.observed_application = None;
        self.epoch_application_anchor = None;
        self.next_read = None;
        self.pending_hint = None;
        self.outstanding = None;
        self.worker_identity = None;
        self.dirty_since = None;
        self.capture_diagnostics = None;
        self.next_read_fast_only = false;
        self.pending_submit_fast_read = false;
        self.menu_tracking_until_ms = None;
        self.clear_snapshot_states();
        self.capture_epoch += 1;
        self.focus_generation += 1;
        self.target = unresolved_target(unresolved);
        self.pending_outputs
            .push(EngineOutput::DiscardQueuedObservations);
        let cleanup = if retire_input {
            if let Some(ev) = self.environment.retire_read() {
                self.handle_worker_event(ev);
            }
            self.environment.timed_out_read_cleanup()
        } else {
            self.environment.cancel_read()
        };
        if cleanup == ReadTimeoutCleanup::Unconfirmed
            || self.environment.timed_out_read_cleanup() == ReadTimeoutCleanup::Unconfirmed
        {
            ReadTimeoutCleanup::Unconfirmed
        } else {
            cleanup
        }
    }

    pub fn clear_input_activity(&mut self) {
        self.input_accumulator.clear();
        self.environment.clear_input_activity();
    }

    pub fn secure_input_detected(&mut self, request_id: &str) {
        if !self.has_started
            || self.policy.as_ref().map(|p| p.enabled) != Some(true)
            || self.should_exit
            || self.user_paused
            || (self.state != "running" && !self.secure_input_suspended)
            || self.secure_input_suspended
        {
            return;
        }
        self.secure_input_suspended = true;
        self.primary_pause_reason = None;
        self.state = "paused";
        let retire = self.input_session_established
            && self.policy.as_ref().and_then(|p| p.input_text) == Some(true);
        let cleanup = self.boundary("policy-boundary", false, retire);
        if cleanup == ReadTimeoutCleanup::Unconfirmed {
            self.pause_worker_exit_unconfirmed(request_id);
        } else {
            self.state_message(request_id, "secure-input-suppressed");
        }
    }

    pub fn desktop_changed(&mut self, new_status: DesktopStatus, accessibility: bool) {
        if !self.has_started
            || self.policy.as_ref().map(|p| p.enabled) != Some(true)
            || self.should_exit
        {
            return;
        }
        let changed = self.desktop != new_status;
        self.desktop = new_status;
        let has_input = self.policy.as_ref().is_some_and(|p| {
            p.input_activity == Some(true) || p.input_text == Some(true)
        });
        if new_status != DesktopStatus::Unlocked || !accessibility {
            let was_secure = self.secure_input_suspended;
            if was_secure {
                self.secure_input_suspended = false;
                self.primary_pause_reason = None;
            }
            if was_secure || has_input {
                self.user_paused = true;
            }
            if was_secure || changed || self.state == "running" {
                let reason = if new_status != DesktopStatus::Unlocked {
                    self.environment.desktop_reason().to_string()
                } else {
                    "permission-denied".to_string()
                };
                let cleanup = self.boundary("desktop-unavailable", true, false);
                self.state = "paused";
                if cleanup == ReadTimeoutCleanup::Unconfirmed {
                    self.user_paused = true;
                    self.state_message("desktop", "worker-exit-unconfirmed");
                } else {
                    self.state_message("desktop", &reason);
                }
            }
        } else if !self.secure_input_suspended
            && !self.user_paused
            && self.state == "paused"
            && !has_input
        {
            let cleanup = self.boundary("not-observed", true, false);
            if !self.environment.ready_for_read()
                || cleanup == ReadTimeoutCleanup::Unconfirmed
            {
                self.user_paused = true;
                self.state = "paused";
                self.state_message("desktop", "worker-exit-unconfirmed");
            } else {
                self.state = "running";
                self.schedule();
                self.state_message("desktop", "desktop-unlocked");
            }
        }
    }

    pub fn input_session_unavailable(&mut self, reason: &str) {
        if (self.state != "running" && !self.secure_input_suspended)
            || self.policy.as_ref().and_then(|p| p.input_text) != Some(true)
        {
            return;
        }
        let fixed = if matches!(
            reason,
            "input-monitoring-required"
                | "input-monitoring-disabled"
                | "input-monitoring-unavailable"
                | "input-session-boundary-requires-resume"
                | "worker-retirement-ack-failed"
                | "worker-retirement-exit-unconfirmed"
        ) {
            reason
        } else {
            "input-monitoring-unavailable"
        };
        if self.secure_input_suspended {
            self.primary_pause_reason = None;
            self.secure_input_suspended = false;
        }
        self.user_paused = true;
        let cleanup = self.boundary("policy-boundary", true, false);
        self.state = "paused";
        let final_reason = if cleanup == ReadTimeoutCleanup::Unconfirmed {
            "worker-exit-unconfirmed"
        } else {
            fixed
        };
        self.state_message("input", final_reason);
    }

    pub fn input_activity_unavailable(&mut self, reason: &str) {
        if !self.has_started
            || self.policy.as_ref().and_then(|p| p.input_activity) != Some(true)
            || self.should_exit
        {
            return;
        }
        let fixed = if matches!(
            reason,
            "input-monitoring-required"
                | "input-monitoring-unavailable"
                | "input-monitoring-disabled"
        ) {
            reason
        } else {
            "input-monitoring-unavailable"
        };
        if self.secure_input_suspended {
            self.primary_pause_reason = None;
            self.secure_input_suspended = false;
        }
        self.user_paused = true;
        let cleanup = self.boundary("policy-boundary", true, false);
        self.state = "paused";
        let final_reason = if cleanup == ReadTimeoutCleanup::Unconfirmed {
            "worker-exit-unconfirmed"
        } else {
            fixed
        };
        self.state_message("input", final_reason);
    }

    pub fn excluded_application_event(&mut self) {
        if self.state != "running" {
            return;
        }
        let has_epoch_anchor = self
            .epoch_application_anchor
            .as_ref()
            .is_some_and(|(ep, _)| *ep == self.capture_epoch);
        let needs_boundary = self.observed_application.is_some()
            || has_epoch_anchor
            || self.outstanding.is_some()
            || self.worker_identity.is_some()
            || self.menu_tracking_until_ms.is_some();
        let now = self.clock.monotonic_ms();
        let due = Some(now + self.reconciliation_spacing());
        if needs_boundary {
            let retire = self.input_session_established
                && self.policy.as_ref().and_then(|p| p.input_text) == Some(true);
            let cleanup = self.boundary("policy-boundary", false, retire);
            if cleanup == ReadTimeoutCleanup::Unconfirmed {
                self.pause_worker_exit_unconfirmed("boundary");
                return;
            }
            self.foreground_generation += 1;
            self.next_read = due;
            return;
        }
        // Already in the excluded/unresolved state: discard any buffered activity without
        // bumping `capture_epoch`, cancelling idle workers, or triggering immediate re-reads.
        self.next_read_fast_only = false;
        self.pending_submit_fast_read = false;
        if !self.input_accumulator.is_empty() {
            self.clear_input_activity();
        }
        self.clear_snapshot_states();
        self.target = unresolved_target("policy-boundary");
        self.next_read = match self.next_read {
            Some(existing) if existing > now => Some(existing),
            _ => due,
        };
    }

    fn epoch_anchor_mismatches(&self, app: &ApplicationIdentity) -> bool {
        self.observed_application
            .as_ref()
            .is_some_and(|known| known != app)
            || self
                .epoch_application_anchor
                .as_ref()
                .is_some_and(|(ep, anchored)| *ep == self.capture_epoch && anchored != app)
    }

    pub fn input_activity(&mut self, sample: InputActivitySample) {
        let now_unix = self.clock.unix_ms();
        let resolved = ResolvedAppIdentity::from_wire_and_exe(
            sample.application.application_id.clone(),
            sample.exe_name.clone(),
        );
        let allowed = self.state == "running"
            && self.desktop == DesktopStatus::Unlocked
            && !self.user_paused
            && self.input_listener_active
            && self.clock.monotonic_ms() < self.lease_until
            && resolved.as_ref().is_some_and(|res| {
                self.policy.as_ref().is_some_and(|p| {
                    p.enabled
                        && p.input_activity == Some(true)
                        && ApplicationPolicy::allows_identity(p, res)
                        && BrowserGate::allows_identity(res, p, false)
                })
            })
            && sample.callback_time_ms >= 0
            && sample.callback_time_ms <= now_unix
            && now_unix - sample.callback_time_ms <= 200;

        if !allowed {
            self.clear_input_activity();
            return;
        }
        self.last_unavailable_state = None;
        if self.epoch_anchor_mismatches(&sample.application) {
            self.application_event_with_exe(
                SourceHint {
                    application: sample.application,
                    event_time_ms: sample.callback_time_ms,
                },
                sample.exe_name,
            );
            return;
        }
        self.observed_application = Some(sample.application.clone());
        self.epoch_application_anchor = Some((self.capture_epoch, sample.application.clone()));
        if self.state == "running"
            && self.input_listener_active
            && !self.environment.input_activity_healthy()
        {
            self.input_activity_unavailable("input-monitoring-disabled");
            return;
        }

        self.flush_input_activity();
        let now_unix_after = self.clock.unix_ms();
        if self.state != "running"
            || !self.input_listener_active
            || self.user_paused
            || sample.callback_time_ms > now_unix_after
            || now_unix_after - sample.callback_time_ms > 200
        {
            self.clear_input_activity();
            return;
        }
        let stamp = self.stamp();
        self.input_accumulator.add(sample, stamp);
    }

    pub fn application_event(&mut self, hint: SourceHint) {
        self.application_event_with_exe(hint, None);
    }

    fn application_event_with_exe(&mut self, hint: SourceHint, exe_name: Option<String>) {
        if self.state != "running" || self.desktop != DesktopStatus::Unlocked {
            return;
        }
        let retire = self.input_session_established
            && self.policy.as_ref().and_then(|p| p.input_text) == Some(true);
        let cleanup = self.boundary("focus-unavailable", false, retire);
        if cleanup == ReadTimeoutCleanup::Unconfirmed {
            self.pause_worker_exit_unconfirmed("boundary");
            return;
        }
        self.foreground_generation += 1;
        let resolved = ResolvedAppIdentity::from_wire_and_exe(
            hint.application.application_id.clone(),
            exe_name,
        );
        let allowed = resolved.as_ref().is_some_and(|res| {
            self.policy.as_ref().is_some_and(|p| {
                ApplicationPolicy::allows_identity(p, res)
                    && BrowserGate::allows_identity(res, p, false)
            })
        });
        if !allowed {
            self.schedule();
            return;
        }
        self.observed_application = Some(hint.application.clone());
        self.epoch_application_anchor = Some((self.capture_epoch, hint.application.clone()));
        let event_time = hint.event_time_ms;
        self.pending_hint = Some(hint);
        let mut payload = BTreeMap::new();
        payload.insert(
            "kind".to_string(),
            JsonValue::String("context.changed".to_string()),
        );
        payload.insert(
            "reason".to_string(),
            JsonValue::String("application".to_string()),
        );
        self.emit_observation(JsonValue::Object(payload), Some(event_time), None, None, false);
        self.schedule();
    }

    fn flush_input_activity(&mut self) {
        let Some(bucket) = self.input_accumulator.take_completed(self.clock.unix_ms()) else {
            return;
        };
        let Some(resolved) = ResolvedAppIdentity::from_wire_and_exe(
            bucket.application.application_id.clone(),
            bucket.exe_name.clone(),
        ) else {
            return;
        };
        let valid = self.state == "running"
            && self.desktop == DesktopStatus::Unlocked
            && !self.user_paused
            && self.input_listener_active
            && self.clock.monotonic_ms() < self.lease_until
            && bucket.stamp.capture_epoch == self.capture_epoch
            && bucket.stamp.policy_revision == self.policy_revision
            && self.observed_application.as_ref() == Some(&bucket.application)
            && !self.epoch_anchor_mismatches(&bucket.application)
            && self.policy.as_ref().is_some_and(|p| {
                p.enabled
                    && p.input_activity == Some(true)
                    && ApplicationPolicy::allows_identity(p, &resolved)
                    && BrowserGate::allows_identity(&resolved, p, false)
            })
            && self
                .environment
                .validate_input_activity_identity(&bucket.application, &resolved);
        if !valid {
            return;
        }
        // A synchronous fresh validation can itself close the authority epoch or lease.
        if self.state != "running"
            || !self.input_listener_active
            || self.user_paused
            || bucket.stamp.capture_epoch != self.capture_epoch
            || bucket.stamp.policy_revision != self.policy_revision
            || self.clock.monotonic_ms() >= self.lease_until
        {
            return;
        }
        self.epoch_application_anchor =
            Some((bucket.stamp.capture_epoch, bucket.application.clone()));
        let target_id = ApplicationTargetIdentity {
            device_id: self.device_id.clone(),
            os_session_id: self.os_session_id.clone(),
            desktop_id: self.desktop_id.clone(),
            process_id: bucket.application.process_id,
            process_start_time: bucket.application.process_start_time.clone(),
            application_id: bucket.application.application_id.clone(),
        };
        let payload = bucket.payload(self.fixture);
        self.emit_observation(
            payload,
            Some(bucket.interval_end_ms()),
            Some(target_id.to_target_ref()),
            Some(bucket.stamp.to_json()),
            false,
        );
    }

    /// Validate and emit a committed foreground top-menu-bar action from the isolated session
    /// worker after epoch/policy/generation fencing, dual-ID policy & browser `privateState`
    /// verification, fresh desktop/Secure Input checks, and `ContractValidator` validation.
    pub fn menu_action(&mut self, record: MenuActionRecord) {
        if self.should_exit
            || self.state != "running"
            || self.user_paused
            || self.secure_input_suspended
            || self.desktop != DesktopStatus::Unlocked
            || self.clock.monotonic_ms() >= self.lease_until
        {
            return;
        }
        let Some(policy) = self.policy.clone() else {
            return;
        };
        if !policy.enabled || policy.menu_actions != Some(true) {
            return;
        }
        let now_unix = self.clock.unix_ms();
        if !record.is_valid()
            || record.stamp.capture_epoch != self.capture_epoch
            || record.stamp.policy_revision != self.policy_revision
            || record.stamp.foreground_generation > self.foreground_generation
            || record.stamp.focus_generation > self.focus_generation
            || record.field_security != policy.field_security_mode()
            || record.observed_at_ms > now_unix
            || now_unix - record.observed_at_ms > MenuPathLimits::MAX_SELECTION_AGE_MS
        {
            return;
        }
        if self.epoch_anchor_mismatches(&record.application) {
            return;
        }
        let Some(resolved) = record.resolved_app_identity() else {
            return;
        };
        if !ApplicationPolicy::allows_identity(&policy, &resolved)
            || !BrowserGate::allows_identity(&resolved, &policy, false)
        {
            return;
        }
        if BrowserGate::is_known_browser_identity(&resolved) {
            if record.private_state != "user-authorized"
                || policy.application_scope.as_deref() != Some("denylist")
                || policy.allow_browser_content != Some(true)
            {
                return;
            }
        } else if !(record.private_state == "normal"
            || (record.private_state == "user-authorized"
                && policy.application_scope.as_deref() == Some("denylist")
                && policy.allow_browser_content == Some(true)))
        {
            return;
        }

        let fresh = self.environment.validate_before_accept();
        if fresh.accessibility && self.environment.secure_input_blocked() {
            self.desktop = fresh.desktop;
            self.secure_input_detected("secure-input");
            return;
        }
        if fresh.desktop != DesktopStatus::Unlocked || !fresh.accessibility {
            self.desktop_changed(fresh.desktop, fresh.accessibility);
            return;
        }

        // Fresh validation can synchronously advance/close the authority epoch, policy, or lease.
        let still_ok = !self.should_exit
            && self.state == "running"
            && !self.user_paused
            && !self.secure_input_suspended
            && self.desktop == DesktopStatus::Unlocked
            && self.clock.monotonic_ms() < self.lease_until
            && record.stamp.capture_epoch == self.capture_epoch
            && record.stamp.policy_revision == self.policy_revision
            && record.stamp.foreground_generation <= self.foreground_generation
            && record.stamp.focus_generation <= self.focus_generation
            && !self.epoch_anchor_mismatches(&record.application)
            && self.policy.as_ref().is_some_and(|p| {
                p.enabled
                    && p.menu_actions == Some(true)
                    && p.field_security_mode() == record.field_security
            });
        if !still_ok {
            return;
        }

        if self.observed_application.is_none() {
            self.observed_application = Some(record.application.clone());
        }
        self.epoch_application_anchor =
            Some((record.stamp.capture_epoch, record.application.clone()));

        let target_id = ApplicationTargetIdentity {
            device_id: self.device_id.clone(),
            os_session_id: self.os_session_id.clone(),
            desktop_id: self.desktop_id.clone(),
            process_id: record.application.process_id,
            process_start_time: record.application.process_start_time.clone(),
            application_id: record.application.application_id.clone(),
        };
        let payload = record.payload(self.fixture);
        let target_ref = target_id.to_target_ref();
        let stamp_json = record.stamp.to_json();
        let candidate = self.observation_message(
            payload.clone(),
            Some(record.observed_at_ms),
            Some(target_ref.clone()),
            Some(stamp_json.clone()),
        );
        if self.validator.validate_message(&candidate).is_err() {
            return;
        }
        self.emit_observation(
            payload,
            Some(record.observed_at_ms),
            Some(target_ref),
            Some(stamp_json),
            false,
        );
    }

    fn spacing(&self) -> i64 {
        let debounce = self.policy.as_ref().map(|p| p.debounce_ms).unwrap_or(0);
        let max_wait = self.policy.as_ref().map(|p| p.max_wait_ms).unwrap_or(1);
        debounce.max(max_wait)
    }

    fn reconciliation_spacing(&self) -> i64 {
        let default_interval = if self.fixture { 150 } else { 1_000 };
        let sample_interval = self
            .policy
            .as_ref()
            .and_then(|p| p.sample_interval_ms)
            .unwrap_or(default_interval);
        self.spacing().max(sample_interval)
    }

    fn is_menu_tracking_active(&mut self) -> bool {
        if let Some(until) = self.menu_tracking_until_ms {
            if self.clock.monotonic_ms() >= until {
                self.menu_tracking_until_ms = None;
                return false;
            }
            return true;
        }
        false
    }

    fn schedule(&mut self) {
        let now = self.clock.monotonic_ms();
        let spacing = self.spacing();
        let base = (now + spacing).max(self.last_read.unwrap_or(now) + spacing);
        if let Some(until) = self.menu_tracking_until_ms {
            if until > now {
                self.next_read = Some(base.max(until));
                return;
            }
            self.menu_tracking_until_ms = None;
        }
        self.next_read = Some(base);
    }

    pub fn worker_dirty(&mut self) {
        if self.state != "running" || self.user_paused {
            return;
        }
        let Some(ref policy) = self.policy else {
            return;
        };
        if !policy.uses_session_worker() {
            return;
        }
        self.last_unavailable_state = None;
        let now = self.clock.monotonic_ms();
        let since = *self.dirty_since.get_or_insert(now);
        let due = (now + policy.debounce_ms).min(since + policy.max_wait_ms);
        self.next_read = Some(self.next_read.map(|n| n.min(due)).unwrap_or(due));
    }

    pub fn worker_submit_dirty(&mut self) {
        if self.state != "running" || self.user_paused {
            return;
        }
        if !self
            .policy
            .as_ref()
            .is_some_and(|p| p.uses_session_worker())
        {
            return;
        }
        self.last_unavailable_state = None;
        if self.outstanding.is_none() {
            self.next_read_fast_only = true;
            self.next_read = Some(self.clock.monotonic_ms());
        } else {
            self.pending_submit_fast_read = true;
        }
    }

    pub fn worker_menu_tracking(&mut self, active: bool) {
        if self.state != "running" || self.user_paused || self.secure_input_suspended {
            return;
        }
        if !self
            .policy
            .as_ref()
            .is_some_and(|p| p.enabled && p.menu_actions == Some(true) && p.uses_session_worker())
        {
            return;
        }
        if active {
            self.menu_tracking_until_ms = Some(self.clock.monotonic_ms() + 10_000);
        } else {
            self.menu_tracking_until_ms = None;
            self.worker_dirty();
        }
    }

    fn expire_read(&mut self, reason: &str) {
        self.last_unavailable_state = None;
        self.outstanding = None;
        self.next_read_fast_only = false;
        self.pending_submit_fast_read = false;
        let cleanup = self.environment.cancel_read();
        self.clear_snapshot_states();
        self.emit_gap(
            reason,
            Some(GapDiagnostic::new(GapDiagnosticCode::ReadDeadline, None)),
            None,
            false,
        );
        if cleanup == ReadTimeoutCleanup::Unconfirmed
            || self.environment.timed_out_read_cleanup() == ReadTimeoutCleanup::Unconfirmed
        {
            self.pause_worker_exit_unconfirmed("timeout");
            return;
        }
        self.next_read = Some(self.clock.monotonic_ms() + self.reconciliation_spacing());
    }

    pub fn poll_environment(&mut self) {
        if self.should_exit {
            return;
        }
        let events = self.environment.poll();

        // Safety-first ordering: a desktop lock/loss or input listener failure outranks any
        // buffered worker/input events polled in the same tick.
        let mut deferred_unlock = None;
        if let Some(check) = events.desktop_change {
            if check.desktop != DesktopStatus::Unlocked || !check.accessibility {
                self.desktop_changed(check.desktop, check.accessibility);
            } else {
                deferred_unlock = Some(check);
            }
        }
        if let Some(reason) = events.input_activity_unavailable {
            self.input_activity_unavailable(&reason);
        }
        for ev in events.worker_events {
            self.handle_worker_event(ev);
        }
        if self.state == "running"
            && self.environment.timed_out_read_cleanup() == ReadTimeoutCleanup::Unconfirmed
        {
            self.pause_worker_exit_unconfirmed("worker");
        }
        for notice in events.input_notices {
            match notice {
                RawInputNotice::DesktopBoundaryLost => {
                    self.desktop_changed(DesktopStatus::Unknown, false);
                }
                RawInputNotice::ExcludedApplication => {
                    self.excluded_application_event();
                }
                RawInputNotice::Activity {
                    mut sample,
                    resolved,
                } => {
                    if sample.exe_name.is_none() {
                        sample.exe_name = resolved.exe_name;
                    }
                    self.input_activity(sample);
                }
            }
        }
        for sample in events.input_samples {
            self.input_activity(sample);
        }
        if let Some(check) = deferred_unlock {
            self.desktop_changed(check.desktop, check.accessibility);
        }
    }

    pub fn handle_worker_event(&mut self, ev: WorkerEvent) {
        match ev {
            WorkerEvent::Completed(res) => self.complete(*res),
            WorkerEvent::Dirty => self.worker_dirty(),
            WorkerEvent::SubmitDirty => self.worker_submit_dirty(),
            WorkerEvent::MenuTracking(active) => self.worker_menu_tracking(active),
            WorkerEvent::MenuAction(record) => self.menu_action(*record),
            WorkerEvent::InputDisabled(reason) => self.input_session_unavailable(&reason),
            WorkerEvent::SecureInput => self.secure_input_detected("secure-input"),
            WorkerEvent::ReadDeadlineReached(ticket) => {
                if self.outstanding.as_ref() == Some(&*ticket)
                    && self.clock.monotonic_ms() >= ticket.deadline_monotonic_ms
                {
                    self.expire_read("timeout");
                }
            }
            WorkerEvent::WorkerExitUnconfirmed => {
                self.pause_worker_exit_unconfirmed("worker");
            }
        }
    }

    pub fn tick(&mut self, parent_alive: bool) {
        if self.should_exit {
            return;
        }
        if !parent_alive {
            self.stop("parent-death", "owner");
            return;
        }
        if self.clock.monotonic_ms() >= self.lease_until {
            self.stop("lease-expired", "lease");
            return;
        }

        if let Some(ref ticket) = self.outstanding {
            if self.clock.monotonic_ms() >= ticket.deadline_monotonic_ms {
                self.expire_read("timeout");
                if self.state != "running" {
                    return;
                }
            }
        }

        if self.state == "running"
            && self.environment.timed_out_read_cleanup() == ReadTimeoutCleanup::Unconfirmed
        {
            self.pause_worker_exit_unconfirmed("worker");
            return;
        }

        if self.state == "running"
            && self.input_listener_active
            && !self.environment.input_activity_healthy()
        {
            self.input_activity_unavailable("input-monitoring-disabled");
            return;
        }

        self.flush_input_activity();
        if self.is_menu_tracking_active() {
            return;
        }
        let now = self.clock.monotonic_ms();
        let Some(due) = self.next_read else {
            return;
        };
        if self.state != "running"
            || self.desktop != DesktopStatus::Unlocked
            || self.user_paused
            || self.outstanding.is_some()
            || now < due
            || !self.environment.ready_for_read()
        {
            return;
        }
        let Some(policy) = self.policy.clone() else {
            return;
        };
        if !policy.enabled {
            return;
        }

        let debug_request_id = if DebugTrace::enabled() && self.debug_request_serial < MAX_SAFE_INTEGER {
            self.debug_request_serial += 1;
            Some(self.debug_request_serial)
        } else {
            None
        };

        let fast_only = if self.next_read_fast_only {
            self.next_read_fast_only = false;
            Some(true)
        } else {
            None
        };

        let ticket = ReadTicket {
            token: generate_uuid_v4(),
            policy_revision: self.policy_revision,
            capture_epoch: self.capture_epoch,
            policy: policy.clone(),
            hint: self.pending_hint.take(),
            deadline_monotonic_ms: now + policy.read_timeout_ms,
            device_id: self.device_id.clone(),
            os_session_id: self.os_session_id.clone(),
            desktop_id: self.desktop_id.clone(),
            foreground_generation: Some(self.foreground_generation),
            focus_generation: Some(self.focus_generation),
            debug_request_id,
            read_only_ax_enablement: self.read_only_ax_enablement.then_some(true),
            focused_fast_only: fast_only,
        };

        self.outstanding = Some(ticket.clone());
        self.last_read = Some(now);
        self.next_read = None;
        self.dirty_since = None;
        if policy.input_text == Some(true) {
            self.input_session_established = true;
        }

        if let Some(ev) = self.environment.launch(ticket) {
            self.handle_worker_event(ev);
        }
    }

    fn valid_read(&self, read: &TextRead, policy: &CapturePolicy) -> bool {
        let count = utf16_len(&read.text);
        let expected_basis = policy.text_range.as_deref().unwrap_or("prefix");
        if read.range_basis != expected_basis
            || (read.range_start as u64) > (MAX_SAFE_INTEGER as u64)
            || count > policy.max_text_code_units
            || count > 8_192
            || !matches!(read.source.as_str(), "uia.text" | "uia.value")
        {
            return false;
        }
        if let Some(total) = read.total_length {
            if (total as u64) > (MAX_SAFE_INTEGER as u64)
                || read.range_start > total
                || count > total - read.range_start
            {
                return false;
            }
        }
        if read.range_basis == "visible" {
            if read.source != "uia.text"
                || read.total_length.is_none()
                || read.complete
                || (count == 0 && read.total_length != Some(0))
                || !read.missing_reasons.iter().any(|r| r == "visible-range-only")
            {
                return false;
            }
        } else if read.range_basis != "prefix" || read.range_start != 0 {
            return false;
        }
        if read.complete {
            if read.range_start != 0
                || read.total_length != Some(count)
                || read.truncated
                || !read.missing_reasons.is_empty()
            {
                return false;
            }
        } else if read.missing_reasons.is_empty() {
            return false;
        }
        if let Some(sel) = read.selection {
            if sel.start < read.range_start
                || sel.start - read.range_start > count
                || sel.length > count - (sel.start - read.range_start)
            {
                return false;
            }
        }
        true
    }

    fn still_authorized(&self, ticket: &ReadTicket) -> bool {
        self.state == "running"
            && self.desktop == DesktopStatus::Unlocked
            && !self.user_paused
            && ticket.capture_epoch == self.capture_epoch
            && ticket.policy_revision == self.policy_revision
            && self.clock.monotonic_ms() < self.lease_until
    }

    pub fn complete(&mut self, result: ReadResult) {
        let Some(ticket) = self.outstanding.clone() else {
            return;
        };
        if result.token != ticket.token {
            return;
        }
        self.outstanding = None;
        let is_fast_only = ticket.focused_fast_only == Some(true);

        if !self.still_authorized(&ticket) {
            self.next_read_fast_only = false;
            self.pending_submit_fast_read = false;
            self.clear_snapshot_states();
            self.emit_gap(
                "stale",
                Some(GapDiagnostic::new(
                    GapDiagnosticCode::CaptureAuthorityChanged,
                    None,
                )),
                None,
                false,
            );
            return;
        }

        if ticket.policy.input_text == Some(true) {
            if let Some(ref reason) = result.reason {
                if matches!(
                    reason.as_str(),
                    "input-monitoring-required"
                        | "input-monitoring-disabled"
                        | "input-monitoring-unavailable"
                        | "input-session-boundary-requires-resume"
                ) {
                    self.input_session_unavailable(reason);
                    return;
                }
            }
        }

        let provider_app_id = self.compute_provider_application_id(&ticket, &result);

        let negative_focus = result.reason.as_deref() == Some("focus-unavailable")
            && result.diagnostic.map(|d| d.code)
                == Some(GapDiagnosticCode::FocusedFieldUnavailable)
            && result.application.is_none()
            && result.session_identity.is_none()
            && result.text.is_none()
            && result.surface.is_none()
            && result.selection.is_none()
            && result.focus_absent != Some(true)
            && matches!(
                result.surface_failure,
                None | Some(crate::protocol_model::SurfaceReadFailure::AnchorUnavailable)
            )
            && result.capture_start_ms >= 0
            && result.capture_end_ms >= result.capture_start_ms
            && result.capture_end_ms <= self.clock.unix_ms();

        if negative_focus {
            if self.clock.monotonic_ms() >= ticket.deadline_monotonic_ms {
                self.expire_read("stale");
                return;
            }
            self.clear_snapshot_states();
            self.clear_input_activity();
            self.worker_identity = None;
            self.pending_hint = None;
            self.dirty_since = None;
            if self.pending_submit_fast_read {
                self.pending_submit_fast_read = false;
                self.next_read_fast_only = true;
                self.next_read = Some(self.clock.monotonic_ms());
            } else {
                let spacing = if is_fast_only {
                    self.reconciliation_spacing().min(200)
                } else {
                    self.reconciliation_spacing()
                };
                self.next_read = Some(self.clock.monotonic_ms() + spacing);
            }
            self.report_unavailable(
                &result,
                "focus-unavailable",
                "read-error",
                provider_app_id.as_deref(),
            );
            return;
        }

        let negative_application = result.reason.as_deref() == Some("policy-boundary")
            && result.diagnostic.map(|d| d.code)
                == Some(GapDiagnosticCode::ApplicationUnavailable)
            && result.application.is_none()
            && result.session_identity.is_none()
            && result.text.is_none()
            && result.surface.is_none()
            && result.selection.is_none()
            && result.focus_absent != Some(true)
            && result.surface_failure.is_none()
            && result.enablement.is_none()
            && result.private_state.is_none()
            && result.observer_status.is_none()
            && result.capture_start_ms >= 0
            && result.capture_end_ms >= result.capture_start_ms
            && result.capture_end_ms <= self.clock.unix_ms();

        if !negative_application {
            self.last_unavailable_state = None;
        }

        let fresh = self.environment.validate_before_accept();
        if fresh.accessibility && self.environment.secure_input_blocked() {
            if self.clock.monotonic_ms() >= ticket.deadline_monotonic_ms {
                self.expire_read("stale");
                return;
            }
            self.desktop = fresh.desktop;
            self.secure_input_detected("secure-input");
            return;
        }
        if fresh.desktop != DesktopStatus::Unlocked || !fresh.accessibility {
            self.desktop_changed(fresh.desktop, fresh.accessibility);
            return;
        }
        if !self.still_authorized(&ticket) {
            self.next_read_fast_only = false;
            self.pending_submit_fast_read = false;
            self.clear_snapshot_states();
            self.emit_gap(
                "stale",
                Some(GapDiagnostic::new(
                    GapDiagnosticCode::CaptureAuthorityChanged,
                    None,
                )),
                None,
                false,
            );
            return;
        }
        if self.clock.monotonic_ms() >= ticket.deadline_monotonic_ms {
            self.expire_read("stale");
            return;
        }

        if self.pending_submit_fast_read && self.state == "running" && !self.user_paused {
            self.pending_submit_fast_read = false;
            self.next_read_fast_only = true;
            self.next_read = Some(self.clock.monotonic_ms());
        } else if is_fast_only {
            self.next_read = Some(self.clock.monotonic_ms() + self.reconciliation_spacing().min(200));
        } else {
            self.next_read = Some(self.clock.monotonic_ms() + self.reconciliation_spacing());
        }

        if result.reason.as_deref() == Some("session-app-changed") {
            let retire = ticket.policy.input_text == Some(true);
            let cleanup = self.boundary("focus-unavailable", false, retire);
            if cleanup == ReadTimeoutCleanup::Unconfirmed {
                self.pause_worker_exit_unconfirmed("boundary");
            } else {
                self.schedule();
            }
            return;
        }
        if result.reason.as_deref() == Some("application-excluded") {
            let needs_anchor_bump = (ticket.policy.input_activity == Some(true)
                || ticket.policy.menu_actions == Some(true))
                && (self.observed_application.is_some()
                    || self
                        .epoch_application_anchor
                        .as_ref()
                        .is_some_and(|(ep, _)| *ep == self.capture_epoch));
            if needs_anchor_bump {
                let due = Some(self.clock.monotonic_ms() + self.reconciliation_spacing());
                let retire = self.input_session_established
                    && ticket.policy.input_text == Some(true);
                let cleanup = self.boundary("policy-boundary", false, retire);
                if cleanup == ReadTimeoutCleanup::Unconfirmed {
                    self.pause_worker_exit_unconfirmed("boundary");
                } else {
                    self.next_read = due;
                }
                return;
            }
            self.next_read_fast_only = false;
            self.pending_submit_fast_read = false;
            self.next_read = Some(self.clock.monotonic_ms() + self.reconciliation_spacing());
            self.worker_identity = None;
            self.observed_application = None;
            self.clear_input_activity();
            self.clear_snapshot_states();
            self.target = unresolved_target("policy-boundary");
            return;
        }
        if let Some(ref enablement) = result.enablement {
            let mut diag = BTreeMap::new();
            diag.insert(
                "axEnablement".to_string(),
                JsonValue::String(enablement.status.clone()),
            );
            diag.insert(
                "axAttribute".to_string(),
                JsonValue::String(enablement.attribute.clone()),
            );
            diag.insert(
                "observer".to_string(),
                JsonValue::String(
                    if result.observer_status.as_deref() == Some("best-effort") {
                        "best-effort".to_string()
                    } else {
                        "unavailable".to_string()
                    },
                ),
            );
            self.capture_diagnostics = Some(JsonValue::Object(diag));
        }
        if matches!(
            result.reason.as_deref(),
            Some("secure-input-active" | "secure-input-indicated")
        ) {
            self.secure_input_detected("secure-input");
            return;
        }
        if let Some(ref reason) = result.reason {
            if reason.starts_with("input-monitoring-") {
                self.user_paused = true;
                let cleanup = self.boundary("policy-boundary", true, false);
                self.state = "paused";
                let pause_reason = if cleanup == ReadTimeoutCleanup::Unconfirmed {
                    "worker-exit-unconfirmed"
                } else {
                    reason.as_str()
                };
                self.state_message("input", pause_reason);
                return;
            }
        }
        if negative_application {
            self.next_read_fast_only = false;
            self.pending_submit_fast_read = false;
            self.next_read = Some(self.clock.monotonic_ms() + self.reconciliation_spacing());
            self.clear_snapshot_states();
            self.clear_input_activity();
            self.worker_identity = None;
            self.pending_hint = None;
            self.dirty_since = None;
            self.report_unavailable(
                &result,
                "policy-boundary",
                "policy-boundary",
                provider_app_id.as_deref(),
            );
            return;
        }

        let surface_requested = !is_fast_only
            && matches!(
                ticket.policy.capture_scope.as_deref(),
                Some("region" | "window")
            );

        let resolved_app = result.application.as_ref().and_then(|app| {
            ResolvedAppIdentity::from_wire_and_exe(
                app.application_id.clone(),
                result.exe_name.clone(),
            )
        });
        let app_valid = match (&result.application, &resolved_app) {
            (Some(app), Some(resolved)) => {
                ApplicationPolicy::allows_identity(&ticket.policy, resolved)
                    && BrowserGate::allows_identity(resolved, &ticket.policy, false)
                    && result.capture_end_ms >= result.capture_start_ms
                    && result.valid_window_only_channels(&ticket.policy)
                    && result
                        .text
                        .as_ref()
                        .map(|t| self.valid_read(t, &ticket.policy))
                        != Some(false)
                    && (result.text.is_some()
                        || result.surface.is_some()
                        || result.selection.is_some()
                        || (ticket.policy.input_text == Some(true)
                            && result.session_identity.is_some()))
                    && ticket
                        .hint
                        .as_ref()
                        .map(|h| &h.application == app)
                        .unwrap_or(true)
            }
            _ => false,
        };

        if !app_valid {
            self.clear_snapshot_states();
            let reason = result.reason.as_deref().unwrap_or("read-error");
            if reason == "focus-unavailable" || reason == "policy-boundary" {
                self.worker_identity = None;
                self.focus_generation += 1;
                self.target = unresolved_target(if reason == "policy-boundary" {
                    "policy-boundary"
                } else {
                    "focus-unavailable"
                });
                let mut ctx = BTreeMap::new();
                ctx.insert(
                    "kind".to_string(),
                    JsonValue::String("context.changed".to_string()),
                );
                ctx.insert(
                    "reason".to_string(),
                    JsonValue::String("focus-unavailable".to_string()),
                );
                self.emit_observation(JsonValue::Object(ctx), None, None, None, false);
            }
            let gap_reason = if matches!(
                reason,
                "policy-boundary" | "stale" | "timeout" | "budget" | "desktop-unavailable"
            ) {
                reason
            } else {
                "read-error"
            };
            self.emit_gap(gap_reason, result.diagnostic, provider_app_id.as_deref(), false);
            if !(reason == "stale"
                && result.diagnostic.map(|d| d.code) == Some(GapDiagnosticCode::FocusChanged))
            {
                self.report_surface_failure(surface_requested, &result, provider_app_id.as_deref());
            }
            return;
        }

        let app = result.application.clone().unwrap();
        let app_changed_in_epoch = self.observed_application.as_ref().is_some_and(|k| k != &app)
            || ((ticket.policy.input_activity == Some(true)
                || ticket.policy.menu_actions == Some(true))
                && self
                    .epoch_application_anchor
                    .as_ref()
                    .is_some_and(|(ep, anchored)| *ep == self.capture_epoch && anchored != &app));
        if app_changed_in_epoch {
            let due = self.next_read;
            if ticket.policy.input_text == Some(true) {
                let cleanup = self.boundary("focus-unavailable", false, true);
                if cleanup == ReadTimeoutCleanup::Unconfirmed {
                    self.pause_worker_exit_unconfirmed("boundary");
                } else {
                    self.next_read = due;
                }
                return;
            }
            let cleanup = self.boundary("focus-unavailable", false, false);
            if cleanup == ReadTimeoutCleanup::Unconfirmed {
                self.pause_worker_exit_unconfirmed("boundary");
                return;
            }
            self.next_read = due;
        }
        self.observed_application = Some(app.clone());
        self.epoch_application_anchor = Some((self.capture_epoch, app.clone()));

        let changed =
            result.session_identity.is_none() || result.session_identity != self.worker_identity;
        if changed {
            self.clear_snapshot_states();
            self.foreground_generation += 1;
            self.focus_generation += 1;
        }
        self.worker_identity = result.session_identity.clone();
        self.snapshot_serial += 1;

        let window_id = result
            .session_identity
            .as_ref()
            .map(|id| id.window_id.clone())
            .unwrap_or_else(generate_uuid_v4);
        let node_id = result
            .session_identity
            .as_ref()
            .map(|id| id.node_id.clone())
            .unwrap_or_else(generate_uuid_v4);
        let window_gen = result
            .session_identity
            .as_ref()
            .map(|id| id.window_generation)
            .unwrap_or(self.foreground_generation);

        let target_identity = TargetIdentity {
            device_id: self.device_id.clone(),
            os_session_id: self.os_session_id.clone(),
            desktop_id: self.desktop_id.clone(),
            process_id: app.process_id,
            process_start_time: app.process_start_time.clone(),
            application_id: app.application_id.clone(),
            window_id,
            window_generation: window_gen,
        };
        self.target = target_identity.to_target_ref();

        if changed {
            let mut ctx = BTreeMap::new();
            ctx.insert(
                "kind".to_string(),
                JsonValue::String("context.changed".to_string()),
            );
            ctx.insert("reason".to_string(), JsonValue::String("focus".to_string()));
            self.emit_observation(
                JsonValue::Object(ctx),
                Some(result.capture_start_ms),
                None,
                None,
                false,
            );
        }

        let resolved_app = resolved_app.unwrap();
        let private_state = result.private_state.clone().unwrap_or_else(|| {
            if BrowserGate::is_known_browser_identity(&resolved_app) {
                "user-authorized".to_string()
            } else {
                "normal".to_string()
            }
        });
        if !matches!(private_state.as_str(), "normal" | "user-authorized")
            || (private_state == "user-authorized"
                && !(ticket.policy.application_scope.as_deref() == Some("denylist")
                    && ticket.policy.allow_browser_content == Some(true)))
        {
            self.clear_snapshot_states();
            return;
        }

        let gate = ContentGate {
            secure: ticket.policy.content_gate_secure().to_string(),
            private_state,
            policy_revision: self.policy_revision,
        }
        .to_json();

        // 1. Focused text snapshot
        if let Some(ref read) = result.text {
            let mut payload = BTreeMap::new();
            payload.insert(
                "kind".to_string(),
                JsonValue::String("text.snapshot".to_string()),
            );
            payload.insert(
                "snapshotId".to_string(),
                JsonValue::String(format!("s-{}-{}", self.snapshot_serial, generate_uuid_v4())),
            );
            payload.insert(
                "editSessionId".to_string(),
                JsonValue::String(generate_uuid_v4()),
            );
            payload.insert("nodeId".to_string(), JsonValue::String(node_id));
            payload.insert(
                "source".to_string(),
                JsonValue::String(if self.fixture {
                    "fixture".to_string()
                } else {
                    read.source.clone()
                }),
            );
            payload.insert(
                "scope".to_string(),
                JsonValue::String(if read.complete {
                    "field".to_string()
                } else {
                    "accessible-range".to_string()
                }),
            );
            payload.insert("valueState".to_string(), JsonValue::String("read".to_string()));
            payload.insert("text".to_string(), JsonValue::String(read.text.clone()));
            payload.insert(
                "range".to_string(),
                json_text_range(read.range_start, utf16_len(&read.text)),
            );
            payload.insert(
                "rangeBasis".to_string(),
                JsonValue::String(read.range_basis.clone()),
            );
            payload.insert(
                "composition".to_string(),
                JsonValue::String("unknown".to_string()),
            );
            payload.insert(
                "captureStartMs".to_string(),
                json_i64(result.capture_start_ms),
            );
            payload.insert("captureEndMs".to_string(), json_i64(result.capture_end_ms));
            payload.insert(
                "coverage".to_string(),
                Coverage {
                    status: if read.complete {
                        "complete".to_string()
                    } else {
                        "partial".to_string()
                    },
                    truncated: read.truncated,
                    missing_reasons: read.missing_reasons.clone(),
                }
                .to_json(),
            );
            payload.insert("gate".to_string(), gate.clone());
            if let Some(total) = read.total_length {
                payload.insert("totalLength".to_string(), json_i64(total as i64));
            }
            if let Some(sel) = read.selection {
                payload.insert(
                    "selection".to_string(),
                    json_text_range(sel.start, sel.length),
                );
            }

            match self.snapshot_state(&payload, result.capture_end_ms, false) {
                Ok(current) => {
                    let confirms_blank = read.complete
                        && read.range_basis == "prefix"
                        && read.range_start == 0
                        && read.total_length == Some(utf16_len(&read.text))
                        && !read.truncated
                        && read.missing_reasons.is_empty();
                    let emit_now = Self::should_emit_text_snapshot(
                        Some(current),
                        &read.text,
                        confirms_blank,
                        &mut self.last_text_state,
                        &mut self.text_had_nonblank,
                    );
                    if emit_now {
                        self.emit_observation(
                            JsonValue::Object(payload),
                            Some(result.capture_end_ms),
                            None,
                            None,
                            false,
                        );
                    }
                }
                Err(err) => {
                    self.last_text_state = None;
                    self.text_had_nonblank = false;
                    let gap_reason = if err == ProtocolError::FrameTooLarge {
                        "budget"
                    } else {
                        "read-error"
                    };
                    self.emit_gap(
                        gap_reason,
                        Some(GapDiagnostic::new(GapDiagnosticCode::TextResultInvalid, None)),
                        provider_app_id.as_deref(),
                        false,
                    );
                }
            }
        } else {
            self.last_text_state = None;
            self.text_had_nonblank = false;
        }

        // 2. Surface snapshot
        if let Some(ref surface) = result.surface {
            if result.valid_surface(&ticket.policy) {
                let mut payload = BTreeMap::new();
                payload.insert(
                    "kind".to_string(),
                    JsonValue::String("surface.snapshot".to_string()),
                );
                payload.insert(
                    "snapshotId".to_string(),
                    JsonValue::String(generate_uuid_v4()),
                );
                payload.insert(
                    "surfaceId".to_string(),
                    JsonValue::String(surface.surface_id.clone()),
                );
                payload.insert("revision".to_string(), json_i64(surface.revision));
                payload.insert(
                    "source".to_string(),
                    JsonValue::String(if self.fixture {
                        "fixture".to_string()
                    } else {
                        "uia.tree".to_string()
                    }),
                );
                payload.insert(
                    "scope".to_string(),
                    JsonValue::String(surface.scope.clone()),
                );
                payload.insert("mode".to_string(), JsonValue::String(surface.mode.clone()));
                payload.insert(
                    "nodes".to_string(),
                    JsonValue::Array(surface.nodes.iter().map(|n| n.to_json()).collect()),
                );
                payload.insert(
                    "captureStartMs".to_string(),
                    json_i64(result.capture_start_ms),
                );
                payload.insert("captureEndMs".to_string(), json_i64(result.capture_end_ms));
                payload.insert("gate".to_string(), gate.clone());
                payload.insert(
                    "consistency".to_string(),
                    JsonValue::String("non-atomic".to_string()),
                );
                payload.insert(
                    "coverage".to_string(),
                    Coverage {
                        status: if surface.complete {
                            "complete".to_string()
                        } else {
                            "partial".to_string()
                        },
                        truncated: surface.truncated,
                        missing_reasons: surface.missing_reasons.clone(),
                    }
                    .to_json(),
                );
                if let Some(ref geom) = surface.geometry {
                    payload.insert("geometry".to_string(), geom.to_json());
                }
                if surface.mode == "diff" {
                    if let Some(base) = surface.base_revision {
                        payload.insert("baseRevision".to_string(), json_i64(base));
                        let mut changes = BTreeMap::new();
                        changes.insert(
                            "added".to_string(),
                            JsonValue::Array(
                                surface
                                    .added
                                    .iter()
                                    .cloned()
                                    .map(JsonValue::String)
                                    .collect(),
                            ),
                        );
                        changes.insert(
                            "updated".to_string(),
                            JsonValue::Array(
                                surface
                                    .updated
                                    .iter()
                                    .cloned()
                                    .map(JsonValue::String)
                                    .collect(),
                            ),
                        );
                        changes.insert(
                            "removed".to_string(),
                            JsonValue::Array(
                                surface
                                    .removed
                                    .iter()
                                    .cloned()
                                    .map(JsonValue::String)
                                    .collect(),
                            ),
                        );
                        payload.insert("changes".to_string(), JsonValue::Object(changes));
                    }
                }

                if surface.mode == "diff" && surface.base_revision != self.last_surface_revision {
                    payload.insert("mode".to_string(), JsonValue::String("full".to_string()));
                    payload.remove("baseRevision");
                    payload.remove("changes");
                }
                match self.snapshot_state(
                    &payload,
                    result.capture_end_ms,
                    result.focus_absent == Some(true),
                ) {
                    Ok(current) => {
                        if self.last_surface_state.as_ref() != Some(&current) {
                            self.last_surface_revision = Some(surface.revision);
                            self.last_surface_state = Some(current);
                            self.emit_observation(
                                JsonValue::Object(payload),
                                Some(result.capture_end_ms),
                                None,
                                None,
                                false,
                            );
                        }
                    }
                    Err(err) => {
                        self.last_surface_state = None;
                        self.last_surface_revision = None;
                        let gap_reason = if err == ProtocolError::FrameTooLarge {
                            "budget"
                        } else {
                            "read-error"
                        };
                        self.emit_gap(
                            gap_reason,
                            Some(GapDiagnostic::new(GapDiagnosticCode::TextResultInvalid, None)),
                            provider_app_id.as_deref(),
                            false,
                        );
                    }
                }
            } else if !is_fast_only {
                self.last_surface_state = None;
                self.last_surface_revision = None;
            }
        } else if !is_fast_only {
            self.last_surface_state = None;
            self.last_surface_revision = None;
        }

        // 3. Selection snapshot
        if let (Some(ref selection), Some(ref identity)) =
            (&result.selection, &result.session_identity)
        {
            if ticket.policy.selection_capture == Some(true)
                && utf16_len(&selection.text) <= ticket.policy.max_text_code_units
            {
                let mut payload = BTreeMap::new();
                payload.insert(
                    "kind".to_string(),
                    JsonValue::String("selection.snapshot".to_string()),
                );
                payload.insert(
                    "snapshotId".to_string(),
                    JsonValue::String(generate_uuid_v4()),
                );
                payload.insert(
                    "surfaceId".to_string(),
                    JsonValue::String(identity.surface_id.clone()),
                );
                payload.insert(
                    "source".to_string(),
                    JsonValue::String(if self.fixture {
                        "fixture".to_string()
                    } else {
                        selection.source.clone()
                    }),
                );
                payload.insert(
                    "scope".to_string(),
                    JsonValue::String("selection".to_string()),
                );
                payload.insert("text".to_string(), JsonValue::String(selection.text.clone()));
                payload.insert(
                    "range".to_string(),
                    json_text_range(selection.range_start, utf16_len(&selection.text)),
                );
                payload.insert(
                    "captureStartMs".to_string(),
                    json_i64(result.capture_start_ms),
                );
                payload.insert("captureEndMs".to_string(), json_i64(result.capture_end_ms));
                payload.insert("gate".to_string(), gate);
                payload.insert(
                    "coverage".to_string(),
                    Coverage {
                        status: "partial".to_string(),
                        truncated: selection.truncated,
                        missing_reasons: selection.missing_reasons.clone(),
                    }
                    .to_json(),
                );

                match self.snapshot_state(&payload, result.capture_end_ms, false) {
                    Ok(current) => {
                        let confirms_blank = !selection.truncated
                            && selection
                                .missing_reasons
                                .iter()
                                .all(|r| r == "selection-only" || r == "non-atomic");
                        let emit_now = Self::should_emit_text_snapshot(
                            Some(current),
                            &selection.text,
                            confirms_blank,
                            &mut self.last_selection_state,
                            &mut self.selection_had_nonblank,
                        );
                        if emit_now {
                            self.emit_observation(
                                JsonValue::Object(payload),
                                Some(result.capture_end_ms),
                                None,
                                None,
                                false,
                            );
                        }
                    }
                    Err(err) => {
                        self.last_selection_state = None;
                        self.selection_had_nonblank = false;
                        let gap_reason = if err == ProtocolError::FrameTooLarge {
                            "budget"
                        } else {
                            "read-error"
                        };
                        self.emit_gap(
                            gap_reason,
                            Some(GapDiagnostic::new(GapDiagnosticCode::TextResultInvalid, None)),
                            provider_app_id.as_deref(),
                            false,
                        );
                    }
                }
            } else if !is_fast_only {
                self.last_selection_state = None;
                self.selection_had_nonblank = false;
            }
        } else if !is_fast_only {
            self.last_selection_state = None;
            self.selection_had_nonblank = false;
        }

        self.report_surface_failure(surface_requested, &result, provider_app_id.as_deref());
        if result.focus_absent == Some(true) && result.surface.is_none() {
            self.emit_gap(
                "read-error",
                Some(GapDiagnostic::new(
                    GapDiagnosticCode::FocusedFieldUnavailable,
                    None,
                )),
                provider_app_id.as_deref(),
                false,
            );
        }
    }

    fn report_surface_failure(
        &mut self,
        surface_requested: bool,
        result: &ReadResult,
        provider_app_id: Option<&str>,
    ) {
        if !surface_requested || result.surface.is_some() {
            return;
        }
        if let Some(failure) = result.surface_failure {
            self.emit_gap(
                failure.gap_reason(),
                Some(GapDiagnostic::new(failure.diagnostic_code(), None)),
                provider_app_id,
                false,
            );
        }
    }

    fn compute_provider_application_id(
        &self,
        ticket: &ReadTicket,
        result: &ReadResult,
    ) -> Option<String> {
        if !self.still_authorized(ticket)
            || self.clock.monotonic_ms() >= ticket.deadline_monotonic_ms
            || result.capture_start_ms < 0
            || result.capture_end_ms < result.capture_start_ms
            || result.capture_end_ms > self.clock.unix_ms()
            || result.reason.as_deref() == Some("application-excluded")
            || result
                .reason
                .as_deref()
                .is_some_and(|r| r.starts_with("secure-input-"))
            || matches!(
                result.diagnostic.map(|d| d.code),
                Some(
                    GapDiagnosticCode::SecureField
                        | GapDiagnosticCode::ApplicationNotAllowed
                        | GapDiagnosticCode::BrowserExcluded
                )
            )
            || result.surface_failure
                == Some(crate::protocol_model::SurfaceReadFailure::SecurityExcluded)
        {
            return None;
        }
        let app = result
            .diagnostic_application
            .as_ref()
            .or(result.application.as_ref())?;
        if result.application.as_ref().is_some_and(|a| a != app) {
            return None;
        }
        let resolved = ResolvedAppIdentity::from_wire_and_exe(
            app.application_id.clone(),
            result.exe_name.clone(),
        )?;
        if app.process_id == 0
            || app.process_start_time.is_empty()
            || utf16_len(&app.process_start_time) > 128
            || !is_valid_application_id(&app.application_id)
            || !ApplicationPolicy::allows_identity(&ticket.policy, &resolved)
            || !BrowserGate::allows_identity(&resolved, &ticket.policy, false)
            || ticket.hint.as_ref().is_some_and(|h| &h.application != app)
        {
            return None;
        }
        Some(app.application_id.clone())
    }

    fn clear_snapshot_states(&mut self) {
        self.last_text_state = None;
        self.last_surface_state = None;
        self.last_selection_state = None;
        self.last_surface_revision = None;
        self.text_had_nonblank = false;
        self.selection_had_nonblank = false;
    }

    fn should_emit_text_snapshot(
        current: Option<JsonValue>,
        text: &str,
        confirms_blank: bool,
        previous: &mut Option<JsonValue>,
        had_nonblank: &mut bool,
    ) -> bool {
        let Some(current) = current else {
            *previous = None;
            *had_nonblank = false;
            return false;
        };
        let nonblank = text.chars().any(|c| !c.is_whitespace());
        let changed = previous.as_ref() != Some(&current);
        *previous = Some(current);
        if !nonblank && confirms_blank {
            let clear = *had_nonblank;
            *had_nonblank = false;
            return clear;
        }
        if nonblank {
            *had_nonblank = true;
        }
        changed
    }

    fn snapshot_state(
        &self,
        payload: &BTreeMap<String, JsonValue>,
        event_time: i64,
        focus_absent: bool,
    ) -> Result<JsonValue, ProtocolError> {
        let obs = self.observation_message(
            JsonValue::Object(payload.clone()),
            Some(event_time),
            None,
            None,
        );
        self.validator.encode_frame(&obs)?;

        let mut stripped = payload.clone();
        for key in [
            "snapshotId",
            "editSessionId",
            "captureStartMs",
            "captureEndMs",
            "revision",
            "mode",
            "baseRevision",
            "changes",
        ] {
            stripped.remove(key);
        }
        if let Some(JsonValue::Array(nodes)) = stripped.get_mut("nodes") {
            for node in nodes.iter_mut() {
                if let Some(fields) = node.as_obj_mut() {
                    fields.remove("observedAtMs");
                    if fields.contains_key("boundsObservedAtMs") {
                        fields.insert("boundsObservedAtMs".to_string(), json_i64(0));
                    }
                }
            }
        }
        if let Some(JsonValue::Object(geom)) = stripped.get_mut("geometry") {
            if geom.contains_key("observedAtMs") {
                geom.insert("observedAtMs".to_string(), json_i64(0));
            }
        }
        let mut state = BTreeMap::new();
        state.insert("target".to_string(), self.target.clone());
        state.insert("stamp".to_string(), self.stamp().to_json());
        state.insert("focusAbsent".to_string(), JsonValue::Bool(focus_absent));
        state.insert("payload".to_string(), JsonValue::Object(stripped));
        Ok(JsonValue::Object(state))
    }

    fn unavailable_state(
        &self,
        result: &ReadResult,
        unresolved: &str,
        provider_app_id: Option<&str>,
    ) -> Option<JsonValue> {
        let provider = if let Some(ref app) = result.diagnostic_application {
            provider_app_id?;
            app.to_json()
        } else {
            JsonValue::Null
        };
        if let Some(ref ps) = result.private_state {
            if !matches!(ps.as_str(), "normal" | "user-authorized") {
                return None;
            }
        }
        if let Some(ref os) = result.observer_status {
            if !matches!(os.as_str(), "unavailable" | "best-effort") {
                return None;
            }
        }
        let mut map = BTreeMap::new();
        map.insert("target".to_string(), self.target.clone());
        map.insert("stamp".to_string(), self.stamp().to_json());
        map.insert(
            "unresolved".to_string(),
            JsonValue::String(unresolved.to_string()),
        );
        map.insert(
            "reason".to_string(),
            result
                .reason
                .as_ref()
                .map(|s| JsonValue::String(s.clone()))
                .unwrap_or(JsonValue::Null),
        );
        map.insert(
            "diagnostic".to_string(),
            result
                .diagnostic
                .map(GapDiagnostic::to_json)
                .unwrap_or(JsonValue::Null),
        );
        map.insert("provider".to_string(), provider);
        map.insert(
            "enablement".to_string(),
            result
                .enablement
                .as_ref()
                .map(|e| e.to_json())
                .unwrap_or(JsonValue::Null),
        );
        map.insert(
            "privateState".to_string(),
            result
                .private_state
                .as_ref()
                .map(|s| JsonValue::String(s.clone()))
                .unwrap_or(JsonValue::Null),
        );
        map.insert(
            "observerStatus".to_string(),
            result
                .observer_status
                .as_ref()
                .map(|s| JsonValue::String(s.clone()))
                .unwrap_or(JsonValue::Null),
        );
        map.insert(
            "focusAbsent".to_string(),
            result
                .focus_absent
                .map(JsonValue::Bool)
                .unwrap_or(JsonValue::Null),
        );
        map.insert(
            "surfaceFailure".to_string(),
            result
                .surface_failure
                .map(|f| JsonValue::String(f.as_str().to_string()))
                .unwrap_or(JsonValue::Null),
        );
        Some(JsonValue::Object(map))
    }

    fn report_unavailable(
        &mut self,
        result: &ReadResult,
        unresolved: &str,
        gap_reason: &str,
        provider_app_id: Option<&str>,
    ) {
        let current = self.unavailable_state(result, unresolved, provider_app_id);
        if current.is_some() && current == self.last_unavailable_state {
            return;
        }
        self.last_unavailable_state = None;
        let changed = self.target.get("kind").and_then(JsonValue::as_str) != Some("unresolved")
            || self.target.get("reason").and_then(JsonValue::as_str) != Some(unresolved);
        if changed {
            self.worker_identity = None;
            self.focus_generation += 1;
            self.target = unresolved_target(unresolved);
        }
        self.last_unavailable_state = self.unavailable_state(result, unresolved, provider_app_id);
        if changed {
            let mut ctx = BTreeMap::new();
            ctx.insert(
                "kind".to_string(),
                JsonValue::String("context.changed".to_string()),
            );
            ctx.insert(
                "reason".to_string(),
                JsonValue::String("focus-unavailable".to_string()),
            );
            self.emit_observation(JsonValue::Object(ctx), None, None, None, true);
        }
        self.emit_gap(gap_reason, result.diagnostic, provider_app_id, true);
    }

    fn emit_gap(
        &mut self,
        reason: &str,
        diagnostic: Option<GapDiagnostic>,
        provider_app_id: Option<&str>,
        preserving_unavailable: bool,
    ) {
        let mut payload = BTreeMap::new();
        payload.insert("kind".to_string(), JsonValue::String("gap".to_string()));
        payload.insert("reason".to_string(), JsonValue::String(reason.to_string()));
        payload.insert("count".to_string(), json_i64(1));
        if let Some(diag) = diagnostic {
            payload.insert("diagnostic".to_string(), diag.to_json());
        }
        if let Some(pid) = provider_app_id {
            payload.insert(
                "providerApplicationId".to_string(),
                JsonValue::String(pid.to_string()),
            );
        }
        self.emit_observation(
            JsonValue::Object(payload),
            None,
            None,
            None,
            preserving_unavailable,
        );
    }

    fn observation_message(
        &self,
        payload: JsonValue,
        event_time: Option<i64>,
        event_target: Option<JsonValue>,
        event_stamp: Option<JsonValue>,
    ) -> JsonValue {
        let next_seq = self.seq + 1;
        let mut map = BTreeMap::new();
        map.insert("protocolVersion".to_string(), json_i64(1));
        map.insert(
            "type".to_string(),
            JsonValue::String("observation".to_string()),
        );
        map.insert(
            "eventId".to_string(),
            JsonValue::String(format!("{}:{}", self.instance_id, next_seq)),
        );
        map.insert(
            "instanceId".to_string(),
            JsonValue::String(self.instance_id.clone()),
        );
        map.insert("seq".to_string(), json_i64(next_seq));
        map.insert(
            "eventTimeMs".to_string(),
            json_i64(event_time.unwrap_or_else(|| self.clock.unix_ms())),
        );
        map.insert("monotonicMs".to_string(), json_i64(self.clock.monotonic_ms()));
        map.insert(
            "target".to_string(),
            event_target.unwrap_or_else(|| self.target.clone()),
        );
        map.insert(
            "stamp".to_string(),
            event_stamp.unwrap_or_else(|| self.stamp().to_json()),
        );
        map.insert("actor".to_string(), JsonValue::String("unknown".to_string()));
        map.insert("relatedActionIds".to_string(), JsonValue::Array(Vec::new()));
        map.insert("payload".to_string(), payload);
        JsonValue::Object(map)
    }

    fn emit_observation(
        &mut self,
        payload: JsonValue,
        event_time: Option<i64>,
        event_target: Option<JsonValue>,
        event_stamp: Option<JsonValue>,
        preserving_unavailable: bool,
    ) {
        if !preserving_unavailable {
            self.last_unavailable_state = None;
        }
        let is_gap = payload.get("kind").and_then(JsonValue::as_str) == Some("gap");
        let message = self.observation_message(payload, event_time, event_target, event_stamp);
        match self.validator.encode_frame(&message) {
            Ok(_) => {
                self.seq += 1;
                self.emit(message);
            }
            Err(err) => {
                DebugTrace::record(
                    "observation-encode-failed",
                    &[],
                    &[("isGap", is_gap)],
                    &[("code", err.code())],
                    file!(),
                    line!(),
                );
                if !is_gap {
                    let gap_reason = if err == ProtocolError::FrameTooLarge {
                        "budget"
                    } else {
                        "read-error"
                    };
                    let mut fallback = BTreeMap::new();
                    fallback.insert("kind".to_string(), JsonValue::String("gap".to_string()));
                    fallback.insert(
                        "reason".to_string(),
                        JsonValue::String(gap_reason.to_string()),
                    );
                    fallback.insert("count".to_string(), json_i64(1));
                    fallback.insert(
                        "diagnostic".to_string(),
                        GapDiagnostic::new(GapDiagnosticCode::TextResultInvalid, None).to_json(),
                    );
                    let gap_msg =
                        self.observation_message(JsonValue::Object(fallback), None, None, None);
                    if self.validator.encode_frame(&gap_msg).is_ok() {
                        self.seq += 1;
                        self.emit(gap_msg);
                    }
                }
            }
        }
    }
}
