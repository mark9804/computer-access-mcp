use access_contract::utf16_len;

use crate::adapters::StaticTextPolicy;
use crate::policy::{ApplicationPolicy, BrowserGate, StaticTextRangeProbe};
use crate::protocol_model::{
    bounded_utf16_slice, ApplicationIdentity, CollectorClock, GapDiagnostic, GapDiagnosticCode,
    SecureStatus, TextRead, TextSelection, MAX_SAFE_INTEGER,
};
use crate::worker_ipc::{ReadResult, ReadTicket};

/// Focused-field provider trait implemented by both `SyntheticFieldProvider` and Stage 2 live UIA provider.
pub trait TextFieldProvider {
    fn application(&self) -> Option<ApplicationIdentity>;
    fn resolve_focused_field(&mut self) -> bool;
    fn role(&self) -> Option<String>;
    fn secure_status(&self) -> SecureStatus;
    fn number_of_characters(&self) -> Option<usize>;
    fn visible_range(&self) -> Option<TextSelection> {
        None
    }
    fn string_for_range(&self, start: usize, length: usize) -> Option<String>;
    fn bounded_known_length_value(&self) -> Option<String>;
    fn selected_range(&self) -> Option<TextSelection>;
    fn remains_same_focus_and_window(&self) -> bool;
}

/// Bounded focused-field text reader enforcing pre/post privacy gates, budgets, and range invariants.
pub struct BoundedTextReader;

impl BoundedTextReader {
    pub fn read(
        ticket: &ReadTicket,
        provider: &mut dyn TextFieldProvider,
        clock: &dyn CollectorClock,
        static_text_probe: StaticTextPolicy,
    ) -> ReadResult {
        let start = clock.unix_ms();
        let make_failure = |reason: &str, code: GapDiagnosticCode, role: Option<&str>| {
            ReadResult::failure(
                ticket.token.clone(),
                reason,
                Some(GapDiagnostic::new(code, role)),
                start,
                clock.unix_ms(),
            )
        };
        let security_failure = |status: SecureStatus| {
            if status == SecureStatus::Sensitive {
                GapDiagnosticCode::SecureField
            } else {
                GapDiagnosticCode::FieldSecurityUnknown
            }
        };

        if !ticket.policy.enabled {
            return make_failure("stale", GapDiagnosticCode::InvalidSamplingPolicy, None);
        }
        if clock.monotonic_ms() >= ticket.deadline_monotonic_ms {
            return make_failure("stale", GapDiagnosticCode::ReadDeadline, None);
        }
        if !ticket.policy.has_valid_text_settings() {
            return make_failure(
                "policy-boundary",
                GapDiagnosticCode::InvalidSamplingPolicy,
                None,
            );
        }

        let Some(app) = provider.application() else {
            return make_failure(
                "policy-boundary",
                GapDiagnosticCode::ApplicationUnavailable,
                None,
            );
        };
        if !ApplicationPolicy::allows(&app.application_id, &ticket.policy) {
            let reason = if ApplicationPolicy::is_system_ui(&app.application_id) {
                "application-excluded"
            } else {
                "policy-boundary"
            };
            return make_failure(reason, GapDiagnosticCode::ApplicationNotAllowed, None);
        }
        if !BrowserGate::allows(&app.application_id, &ticket.policy, false) {
            return make_failure("policy-boundary", GapDiagnosticCode::BrowserExcluded, None);
        }
        if let Some(ref hint) = ticket.hint {
            if hint.application != app {
                return make_failure("stale", GapDiagnosticCode::FocusChanged, None);
            }
        }
        if !provider.resolve_focused_field() {
            return make_failure(
                "focus-unavailable",
                GapDiagnosticCode::FocusedFieldUnavailable,
                None,
            );
        }

        let observed_role = provider.role();
        let diag_role = Some(crate::policy::normalize_gap_role(observed_role.as_deref()));
        let Some(role) = observed_role else {
            return make_failure(
                "policy-boundary",
                GapDiagnosticCode::FocusedRoleNotText,
                diag_role,
            );
        };
        if !matches!(role.as_str(), "AXTextField" | "AXTextArea" | "AXStaticText") {
            let code = if role == "AXSecureTextField" {
                GapDiagnosticCode::SecureField
            } else {
                GapDiagnosticCode::FocusedRoleNotText
            };
            return make_failure("policy-boundary", code, diag_role);
        }

        let security = provider.secure_status();
        if !ticket.policy.allows_secure(security) {
            return make_failure("policy-boundary", security_failure(security), diag_role);
        }

        let budget = ticket.policy.max_text_code_units.clamp(1, 8_192);
        let length = provider
            .number_of_characters()
            .filter(|&n| (n as u64) <= (MAX_SAFE_INTEGER as u64));
        let visible = ticket.policy.text_range.as_deref() == Some("visible");
        let basis = if visible { "visible" } else { "prefix" };

        let sampled = if visible {
            let (Some(total), Some(range)) = (length, provider.visible_range()) else {
                return make_failure(
                    "read-error",
                    GapDiagnosticCode::VisibleRangeUnavailable,
                    diag_role,
                );
            };
            if range.start > total
                || range.length > total.saturating_sub(range.start)
                || (range.length == 0 && total != 0)
            {
                return make_failure(
                    "read-error",
                    GapDiagnosticCode::VisibleRangeUnavailable,
                    diag_role,
                );
            }
            range
        } else {
            TextSelection::new(0, length.unwrap_or(budget))
        };

        let probe_max_units = match static_text_probe {
            StaticTextPolicy::BoundedRangeProbe { max_units } => {
                Some(max_units.clamp(1, StaticTextRangeProbe::MAXIMUM_PREFIX_UNITS))
            }
            StaticTextPolicy::Standard => None,
        };
        let probe_static_text = !visible
            && role == "AXStaticText"
            && (length.is_none() || length == Some(0))
            && probe_max_units.is_some();
        let requested = if probe_static_text {
            budget.min(probe_max_units.unwrap())
        } else {
            sampled.length.min(budget)
        };

        if !provider.remains_same_focus_and_window() {
            return make_failure("stale", GapDiagnosticCode::FocusChanged, diag_role);
        }
        let before_role = provider.role();
        if before_role.as_deref() != Some(role.as_str()) {
            return make_failure(
                "stale",
                GapDiagnosticCode::FocusChanged,
                Some(crate::policy::normalize_gap_role(before_role.as_deref())),
            );
        }
        let before_security = provider.secure_status();
        if !ticket.policy.allows_secure(before_security) {
            return make_failure("stale", security_failure(before_security), diag_role);
        }
        if clock.monotonic_ms() >= ticket.deadline_monotonic_ms {
            return make_failure("stale", GapDiagnosticCode::ReadDeadline, diag_role);
        }

        let mut text: Option<String>;
        let mut source = "uia.text";
        let mut static_probe_units: Option<usize> = None;

        if probe_static_text {
            let mut probe_failure: Option<ReadResult> = None;
            let probe = StaticTextRangeProbe::read(
                requested,
                StaticTextRangeProbe::MAXIMUM_ATTEMPTS,
                StaticTextRangeProbe::DEFAULT_INITIAL_PREFIX_UNITS,
                false,
                || {
                    if probe_failure.is_some() {
                        return false;
                    }
                    if clock.monotonic_ms() >= ticket.deadline_monotonic_ms {
                        probe_failure = Some(make_failure(
                            "stale",
                            GapDiagnosticCode::ReadDeadline,
                            diag_role,
                        ));
                        return false;
                    }
                    if !provider.remains_same_focus_and_window()
                        || provider.application().as_ref() != Some(&app)
                    {
                        probe_failure = Some(make_failure(
                            "stale",
                            GapDiagnosticCode::FocusChanged,
                            diag_role,
                        ));
                        return false;
                    }
                    let cur_role = provider.role();
                    if cur_role.as_deref() != Some(role.as_str()) {
                        probe_failure = Some(make_failure(
                            "stale",
                            GapDiagnosticCode::FocusChanged,
                            Some(crate::policy::normalize_gap_role(cur_role.as_deref())),
                        ));
                        return false;
                    }
                    let cur_sec = provider.secure_status();
                    if !ticket.policy.allows_secure(cur_sec) {
                        probe_failure =
                            Some(make_failure("stale", security_failure(cur_sec), diag_role));
                        return false;
                    }
                    if clock.monotonic_ms() >= ticket.deadline_monotonic_ms {
                        probe_failure = Some(make_failure(
                            "stale",
                            GapDiagnosticCode::ReadDeadline,
                            diag_role,
                        ));
                        return false;
                    }
                    true
                },
                || true,
                |s, l| provider.string_for_range(s, l),
            );
            if let Some(fail) = probe_failure {
                return fail;
            }
            if probe.failure.is_some() {
                return make_failure("read-error", GapDiagnosticCode::TextResultInvalid, diag_role);
            }
            let Some(probe_text) = probe.text else {
                return make_failure(
                    "read-error",
                    GapDiagnosticCode::TextReadUnavailable,
                    diag_role,
                );
            };
            static_probe_units = Some(probe.consumed_units);
            text = Some(probe_text);
        } else if length == Some(0) {
            text = Some(String::new());
        } else {
            text = provider.string_for_range(sampled.start, requested);
        }

        if !probe_static_text && !visible && text.is_none() {
            if let Some(total) = length {
                if total <= budget {
                    if provider.number_of_characters() != Some(total) {
                        return make_failure(
                            "read-error",
                            GapDiagnosticCode::TextResultInvalid,
                            diag_role,
                        );
                    }
                    if !provider.remains_same_focus_and_window() {
                        return make_failure(
                            "read-error",
                            GapDiagnosticCode::FocusChanged,
                            diag_role,
                        );
                    }
                    let fb_sec = provider.secure_status();
                    if !ticket.policy.allows_secure(fb_sec) {
                        return make_failure(
                            "read-error",
                            security_failure(fb_sec),
                            diag_role,
                        );
                    }
                    if clock.monotonic_ms() >= ticket.deadline_monotonic_ms {
                        return make_failure(
                            "read-error",
                            GapDiagnosticCode::ReadDeadline,
                            diag_role,
                        );
                    }
                    source = "uia.value";
                    text = provider.bounded_known_length_value();
                }
            }
        }

        let Some(text) = text else {
            return make_failure(
                "read-error",
                GapDiagnosticCode::TextReadUnavailable,
                diag_role,
            );
        };

        let actual_length = utf16_len(&text);
        if actual_length > requested
            || (!probe_static_text
                && length.is_some_and(|l| actual_length > l.saturating_sub(sampled.start)))
            || (visible && text.is_empty() && length != Some(0))
        {
            return make_failure("read-error", GapDiagnosticCode::TextResultInvalid, diag_role);
        }
        if clock.monotonic_ms() >= ticket.deadline_monotonic_ms {
            return make_failure("stale", GapDiagnosticCode::ReadDeadline, diag_role);
        }
        if !provider.remains_same_focus_and_window() {
            return make_failure("stale", GapDiagnosticCode::FocusChanged, diag_role);
        }
        let after_role = provider.role();
        if after_role.as_deref() != Some(role.as_str()) {
            return make_failure(
                "stale",
                GapDiagnosticCode::FocusChanged,
                Some(crate::policy::normalize_gap_role(after_role.as_deref())),
            );
        }
        let after_sec = provider.secure_status();
        if !ticket.policy.allows_secure(after_sec) {
            return make_failure("stale", security_failure(after_sec), diag_role);
        }

        let complete =
            !probe_static_text && !visible && sampled.start == 0 && length == Some(actual_length);
        let mut missing_reasons = Vec::new();
        let truncated = if probe_static_text {
            missing_reasons.push("static-text-length-unverified".to_string());
            true
        } else if visible {
            missing_reasons.push("visible-range-only".to_string());
            if sampled.length > budget {
                missing_reasons.push("text-budget".to_string());
            }
            if actual_length < requested {
                missing_reasons.push("range-short-read".to_string());
            }
            sampled.length > budget || actual_length < requested
        } else {
            match length {
                None => missing_reasons.push("length-unknown".to_string()),
                Some(l) if !complete => missing_reasons.push(if l > budget {
                    "text-budget".to_string()
                } else {
                    "range-short-read".to_string()
                }),
                _ => {}
            }
            !complete
        };

        let mut selection = provider.selected_range();
        if let Some(sel) = selection {
            if sel.start < sampled.start
                || sel.start - sampled.start > actual_length
                || sel.length > actual_length - (sel.start - sampled.start)
            {
                selection = None;
            }
        }

        if let Some(total) = length {
            if provider.number_of_characters() != Some(total) {
                return make_failure("stale", GapDiagnosticCode::TextResultInvalid, diag_role);
            }
        }
        if visible && provider.visible_range() != Some(sampled) {
            return make_failure(
                "stale",
                GapDiagnosticCode::VisibleRangeUnavailable,
                diag_role,
            );
        }
        if !provider.remains_same_focus_and_window()
            || (probe_static_text && provider.application().as_ref() != Some(&app))
        {
            return make_failure("stale", GapDiagnosticCode::FocusChanged, diag_role);
        }
        let final_role = provider.role();
        if final_role.as_deref() != Some(role.as_str()) {
            return make_failure(
                "stale",
                GapDiagnosticCode::FocusChanged,
                Some(crate::policy::normalize_gap_role(final_role.as_deref())),
            );
        }
        let final_sec = provider.secure_status();
        if !ticket.policy.allows_secure(final_sec) {
            return make_failure("stale", security_failure(final_sec), diag_role);
        }
        if clock.monotonic_ms() >= ticket.deadline_monotonic_ms {
            return make_failure("stale", GapDiagnosticCode::ReadDeadline, diag_role);
        }

        let end = clock.unix_ms().max(start);
        ReadResult {
            token: ticket.token.clone(),
            application: Some(app),
            diagnostic_application: None,
            exe_name: None,
            text: Some(TextRead {
                text,
                source: source.to_string(),
                total_length: if probe_static_text { None } else { length },
                selection,
                range_start: sampled.start,
                range_basis: basis.to_string(),
                complete,
                truncated,
                missing_reasons,
                read_units: static_probe_units,
            }),
            reason: None,
            diagnostic: None,
            enablement: None,
            session_identity: None,
            surface: None,
            selection: None,
            private_state: None,
            observer_status: None,
            focus_absent: None,
            surface_failure: None,
            verified_normal_browser: None,
            capture_start_ms: start,
            capture_end_ms: end,
        }
    }
}

/// Deterministic synthetic provider implementing all 12 `--fixture-scenario` cases.
pub struct SyntheticFieldProvider {
    scenario: String,
    content: String,
}

impl SyntheticFieldProvider {
    pub fn new(scenario: impl Into<String>) -> Self {
        let scenario = scenario.into();
        let content = match scenario.as_str() {
            "empty" => String::new(),
            "partial" => "Synthetic \u{1F9EA} ".repeat(1_000),
            _ => "Synthetic \u{1F9EA} text".to_string(),
        };
        Self { scenario, content }
    }
}

impl TextFieldProvider for SyntheticFieldProvider {
    fn application(&self) -> Option<ApplicationIdentity> {
        Some(ApplicationIdentity {
            application_id: if self.scenario == "browser" {
                "com.apple.Safari".to_string()
            } else {
                "test.allowed".to_string()
            },
            process_id: 4242,
            process_start_time: "fixture-birth-1".to_string(),
        })
    }

    fn resolve_focused_field(&mut self) -> bool {
        self.scenario != "focus-loss"
    }

    fn role(&self) -> Option<String> {
        Some("AXTextField".to_string())
    }

    fn secure_status(&self) -> SecureStatus {
        if self.scenario == "sensitive" {
            SecureStatus::Sensitive
        } else {
            SecureStatus::Safe
        }
    }

    fn number_of_characters(&self) -> Option<usize> {
        Some(utf16_len(&self.content))
    }

    fn visible_range(&self) -> Option<TextSelection> {
        if self.scenario == "partial" {
            return Some(TextSelection::new(130, 260));
        }
        let total = utf16_len(&self.content);
        let start = if self.content.is_empty() { 0 } else { 10 };
        Some(TextSelection::new(start, total.saturating_sub(start)))
    }

    fn string_for_range(&self, start: usize, length: usize) -> Option<String> {
        if matches!(self.scenario.as_str(), "value" | "readerror") {
            return None;
        }
        bounded_utf16_slice(&self.content, start, length)
    }

    fn bounded_known_length_value(&self) -> Option<String> {
        if self.scenario == "readerror" {
            None
        } else {
            Some(self.content.clone())
        }
    }

    fn selected_range(&self) -> Option<TextSelection> {
        Some(TextSelection::new(0, 0))
    }

    fn remains_same_focus_and_window(&self) -> bool {
        true
    }
}

/// Execute a fixture read inside the isolated `--ax-worker --synthetic yes` child process.
pub fn execute_fixture_read(
    scenario: &str,
    ticket: &ReadTicket,
    clock: &dyn CollectorClock,
) -> ReadResult {
    let mut provider = SyntheticFieldProvider::new(scenario);
    BoundedTextReader::read(
        ticket,
        &mut provider,
        clock,
        StaticTextPolicy::BoundedRangeProbe {
            max_units: StaticTextRangeProbe::MAXIMUM_PREFIX_UNITS,
        },
    )
}
