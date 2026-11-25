//! Pure, platform-free core logic for Phase 5 `input.text` capture and shared keyboard helpers.
//!
//! Zero Win32/COM dependencies. Enforces macOS-parity privacy gates, strict Pre-Gate -> Translate
//! -> Post-Gate ordering, bounded single-buffer accumulation, causal read-barrier draining,
//! Windows AltGr normalization, `VK_PACKET` surrogate-pair assembly, autorepeat tracking, and
//! IME composition prefix purging / gated commit admission.

use std::collections::BTreeMap;
use std::hint::black_box;

use history_contract::{is_valid_application_id, utf16_len, JsonValue};

use crate::policy::{BrowserGate, ResolvedAppIdentity};
use crate::protocol_model::{
    json_i64, json_usize, CapturePolicy, ContentGate, Coverage, GapDiagnostic, GapDiagnosticCode,
    SecureStatus, Stamp, TargetIdentity, MAX_SAFE_INTEGER,
};

const DEFAULT_KEYBOARD_COVERAGE_EXTRAS: &[&str] =
    &["event-unicode-not-ime-commit", "non-atomic-field-gate"];
const IME_COMMIT_COVERAGE_EXTRAS: &[&str] = &["ime-composition-commit", "non-atomic-field-gate"];

fn zeroize_string(text: String) {
    let mut bytes = text.into_bytes();
    bytes.fill(0);
    black_box(&bytes);
}

fn zeroize_unicode_read(read: InputTextUnicodeRead) {
    if let InputTextUnicodeRead::Text(text) = read {
        zeroize_string(text);
    }
}

/// Wire source literal for `input.text` observations on Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InputTextSource {
    Win32Unicode,
    Fixture,
}

impl InputTextSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Win32Unicode => "win32.unicode",
            Self::Fixture => "fixture",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "win32.unicode" => Some(Self::Win32Unicode),
            "fixture" => Some(Self::Fixture),
            _ => None,
        }
    }
}

/// Closed, normalized evidence kind for `input.text`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InputTextKind {
    Text,
    Return,
    Shortcut,
}

impl InputTextKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Return => "return",
            Self::Shortcut => "shortcut",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "text" => Some(Self::Text),
            "return" => Some(Self::Return),
            "shortcut" => Some(Self::Shortcut),
            _ => None,
        }
    }
}

/// Canonical modifier set matching wire v1 (`["command", "control", "option", "shift"]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InputTextModifier {
    Command,
    Control,
    Option,
    Shift,
}

impl InputTextModifier {
    pub const ALL: [Self; 4] = [Self::Command, Self::Control, Self::Option, Self::Shift];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Command => "command",
            Self::Control => "control",
            Self::Option => "option",
            Self::Shift => "shift",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "command" => Some(Self::Command),
            "control" => Some(Self::Control),
            "option" => Some(Self::Option),
            "shift" => Some(Self::Shift),
            _ => None,
        }
    }
}

/// Content-gate privacy state for `input.text` contexts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InputTextPrivateState {
    Normal,
    UserAuthorized,
}

impl InputTextPrivateState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::UserAuthorized => "user-authorized",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "normal" => Some(Self::Normal),
            "user-authorized" => Some(Self::UserAuthorized),
            _ => None,
        }
    }
}

/// Strictly editable focused-field roles permitted for `input.text` capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InputTextFieldRole {
    TextField,
    TextArea,
}

impl InputTextFieldRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TextField => "AXTextField",
            Self::TextArea => "AXTextArea",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "AXTextField" => Some(Self::TextField),
            "AXTextArea" => Some(Self::TextArea),
            _ => None,
        }
    }
}

/// Closed 9-value diagnostic gap reasons for `input.text` worker IPC and wire emission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InputTextGapReason {
    Stale,
    Budget,
    Backpressure,
    ReadError,
    PolicyBoundary,
    /// Private worker diagnostic; maps to broad public `Gap.reason = "stale"`.
    TargetMismatch,
    /// Private worker diagnostic; maps to broad public `Gap.reason = "stale"`.
    RoleNotEditable,
    /// Private worker diagnostic; maps to broad public `Gap.reason = "stale"`.
    VerificationTimeout,
    /// Private worker diagnostic; maps to broad public `Gap.reason = "stale"`.
    FieldSecurityUnknown,
}

impl InputTextGapReason {
    pub const ALL: [Self; 9] = [
        Self::Stale,
        Self::Budget,
        Self::Backpressure,
        Self::ReadError,
        Self::PolicyBoundary,
        Self::TargetMismatch,
        Self::RoleNotEditable,
        Self::VerificationTimeout,
        Self::FieldSecurityUnknown,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stale => "stale",
            Self::Budget => "budget",
            Self::Backpressure => "backpressure",
            Self::ReadError => "read-error",
            Self::PolicyBoundary => "policy-boundary",
            Self::TargetMismatch => "input-target-mismatch",
            Self::RoleNotEditable => "input-role-not-editable",
            Self::VerificationTimeout => "input-verification-timeout",
            Self::FieldSecurityUnknown => "input-field-security-unknown",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "stale" => Some(Self::Stale),
            "budget" => Some(Self::Budget),
            "backpressure" => Some(Self::Backpressure),
            "read-error" => Some(Self::ReadError),
            "policy-boundary" => Some(Self::PolicyBoundary),
            "input-target-mismatch" => Some(Self::TargetMismatch),
            "input-role-not-editable" => Some(Self::RoleNotEditable),
            "input-verification-timeout" => Some(Self::VerificationTimeout),
            "input-field-security-unknown" => Some(Self::FieldSecurityUnknown),
            _ => None,
        }
    }

    /// Public coarse `Gap.reason` wire literal.
    pub const fn gap_reason(self) -> &'static str {
        match self {
            Self::Stale
            | Self::TargetMismatch
            | Self::RoleNotEditable
            | Self::VerificationTimeout
            | Self::FieldSecurityUnknown => "stale",
            Self::Budget => "budget",
            Self::Backpressure => "backpressure",
            Self::ReadError => "read-error",
            Self::PolicyBoundary => "policy-boundary",
        }
    }

    /// Exact schema `GapDiagnosticCode` for this input gap reason.
    pub const fn diagnostic_code(self) -> GapDiagnosticCode {
        match self {
            Self::Stale => GapDiagnosticCode::InputContextUnverified,
            Self::Budget => GapDiagnosticCode::InputTextBudget,
            Self::Backpressure => GapDiagnosticCode::InputTextBackpressure,
            Self::ReadError => GapDiagnosticCode::InputTextReadUnavailable,
            Self::PolicyBoundary => GapDiagnosticCode::InputPolicyBoundary,
            Self::TargetMismatch => GapDiagnosticCode::InputTargetMismatch,
            Self::RoleNotEditable => GapDiagnosticCode::InputRoleNotEditable,
            Self::VerificationTimeout => GapDiagnosticCode::InputVerificationTimeout,
            Self::FieldSecurityUnknown => GapDiagnosticCode::InputFieldSecurityUnknown,
        }
    }

    /// Structured wire diagnostic carrying only the closed schema code (no role or user text).
    pub fn diagnostic(self) -> GapDiagnostic {
        GapDiagnostic::new(self.diagnostic_code(), None)
    }

    /// Valid and distinct PID facts distinguish positive target disagreement from absent/invalid targets.
    pub fn process_mismatch(expected: u32, observed: i64) -> Self {
        if expected > 1
            && expected <= i32::MAX as u32
            && observed > 1
            && observed <= i64::from(i32::MAX)
            && i64::from(expected) != observed
        {
            Self::TargetMismatch
        } else {
            Self::Stale
        }
    }

    /// Classifies disagreement between two caller-established contexts. Scope, policy, epoch,
    /// foreground-generation, and authority mismatches remain generic `Stale`; verified focus,
    /// window, or surface disagreement within the same authority reports `TargetMismatch`.
    pub fn context_mismatch(before: &InputTextContext, after: &InputTextContext) -> Self {
        if !before.is_valid()
            || !after.is_valid()
            || before.capture_epoch != after.capture_epoch
            || before.policy_revision != after.policy_revision
            || before.field_security_mode != after.field_security_mode
            || before.secure_status != after.secure_status
            || before.private_state != after.private_state
            || before.target.device_id != after.target.device_id
            || before.target.os_session_id != after.target.os_session_id
            || before.target.desktop_id != after.target.desktop_id
        {
            return Self::Stale;
        }
        if before.target != after.target
            || before.surface_id != after.surface_id
            || before.focus_generation != after.focus_generation
        {
            Self::TargetMismatch
        } else {
            Self::Stale
        }
    }
}

/// Immutable worker-to-engine diagnostic gap record for `input.text`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputTextGapRecord {
    pub reason: InputTextGapReason,
    pub count: i64,
    pub provider_application_id: Option<String>,
}

impl InputTextGapRecord {
    pub fn new(reason: InputTextGapReason) -> Self {
        Self {
            reason,
            count: 1,
            provider_application_id: None,
        }
    }

    pub fn with_provider(
        reason: InputTextGapReason,
        provider_application_id: Option<String>,
    ) -> Self {
        Self {
            reason,
            count: 1,
            provider_application_id,
        }
    }

    pub fn is_valid(&self) -> bool {
        (1..=MAX_SAFE_INTEGER).contains(&self.count)
            && self
                .provider_application_id
                .as_deref()
                .is_none_or(is_valid_application_id)
    }

    /// Builds a wire-v1 `gap` payload matching `wire.schema.json`.
    pub fn payload(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("kind".to_string(), JsonValue::String("gap".to_string()));
        map.insert(
            "reason".to_string(),
            JsonValue::String(self.reason.gap_reason().to_string()),
        );
        map.insert("count".to_string(), json_i64(self.count.max(1)));
        map.insert("diagnostic".to_string(), self.reason.diagnostic().to_json());
        if let Some(ref provider) = self.provider_application_id {
            if is_valid_application_id(provider) {
                map.insert(
                    "providerApplicationId".to_string(),
                    JsonValue::String(provider.clone()),
                );
            }
        }
        JsonValue::Object(map)
    }

    /// Serializes this gap record for internal worker->parent IPC.
    pub fn to_json(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert(
            "reason".to_string(),
            JsonValue::String(self.reason.as_str().to_string()),
        );
        map.insert("count".to_string(), json_i64(self.count));
        if let Some(ref provider) = self.provider_application_id {
            map.insert(
                "providerApplicationId".to_string(),
                JsonValue::String(provider.clone()),
            );
        }
        JsonValue::Object(map)
    }

    /// Deserializes a worker IPC gap record, rejecting unknown reason strings fail-closed.
    pub fn from_json(value: &JsonValue) -> Option<Self> {
        let obj = value.as_obj()?;
        let reason = InputTextGapReason::parse(obj.get("reason")?.as_str()?)?;
        let count = match obj.get("count") {
            None | Some(JsonValue::Null) => 1,
            Some(v) => v.as_i64()?,
        };
        let provider_application_id = match obj.get("providerApplicationId") {
            None | Some(JsonValue::Null) => None,
            Some(v) => Some(v.as_str()?.to_string()),
        };
        let record = Self {
            reason,
            count,
            provider_application_id,
        };
        record.is_valid().then_some(record)
    }
}

/// Frozen verified field context attached to every `input.text` sample and record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputTextContext {
    pub target: TargetIdentity,
    pub surface_id: String,
    pub capture_epoch: i64,
    pub foreground_generation: i64,
    pub focus_generation: i64,
    pub policy_revision: i64,
    pub field_security_mode: String,
    pub secure_status: SecureStatus,
    pub private_state: InputTextPrivateState,
    /// Internal-only normalized `.exe` basename for Windows dual-ID defense-in-depth
    /// (e.g. MSIX Bitwarden / Arc). NEVER emitted on the external wire protocol.
    pub exe_name: Option<String>,
}

impl InputTextContext {
    pub fn stamp(&self) -> Stamp {
        Stamp {
            capture_epoch: self.capture_epoch,
            foreground_generation: self.foreground_generation,
            focus_generation: self.focus_generation,
            policy_revision: self.policy_revision,
        }
    }

    pub fn resolved_app_identity(&self) -> Option<ResolvedAppIdentity> {
        ResolvedAppIdentity::from_wire_and_exe(
            self.target.application_id.clone(),
            self.exe_name.clone(),
        )
    }

    pub fn content_gate(&self) -> Option<ContentGate> {
        let secure = match (self.field_security_mode.as_str(), self.secure_status) {
            ("strict", SecureStatus::Safe) | ("denylist", SecureStatus::Safe) => {
                SecureStatus::Safe.as_str()
            }
            ("denylist", SecureStatus::NotDeclaredSensitive) => {
                SecureStatus::NotDeclaredSensitive.as_str()
            }
            _ => return None,
        };
        if !(1..=MAX_SAFE_INTEGER).contains(&self.policy_revision) {
            return None;
        }
        Some(ContentGate {
            secure: secure.to_string(),
            private_state: self.private_state.as_str().to_string(),
            policy_revision: self.policy_revision,
        })
    }

    pub fn is_valid(&self) -> bool {
        let pid_ok = self.target.process_id > 1 && self.target.process_id <= i32::MAX as u32;
        let ids_ok = is_valid_application_id(&self.target.application_id)
            && self.resolved_app_identity().is_some()
            && InputTextLimits::is_valid_identifier(&self.target.device_id, 128)
            && InputTextLimits::is_valid_identifier(&self.target.os_session_id, 128)
            && InputTextLimits::is_valid_identifier(&self.target.desktop_id, 128)
            && InputTextLimits::is_valid_identifier(&self.target.window_id, 128)
            && InputTextLimits::is_valid_identifier(&self.target.process_start_time, 128)
            && InputTextLimits::is_valid_identifier(&self.surface_id, 128);
        let nums_ok = InputTextLimits::is_safe_integer(self.target.window_generation)
            && InputTextLimits::is_safe_integer(self.capture_epoch)
            && InputTextLimits::is_safe_integer(self.foreground_generation)
            && InputTextLimits::is_safe_integer(self.focus_generation)
            && (1..=MAX_SAFE_INTEGER).contains(&self.policy_revision);
        let security_ok = self.content_gate().is_some();
        pid_ok && ids_ok && nums_ok && security_ok
    }

    /// Serializes this context for internal worker->parent IPC (never sent to external MCP/Host wire).
    pub fn to_json(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("target".to_string(), self.target.to_json());
        map.insert(
            "surfaceId".to_string(),
            JsonValue::String(self.surface_id.clone()),
        );
        map.insert("captureEpoch".to_string(), json_i64(self.capture_epoch));
        map.insert(
            "foregroundGeneration".to_string(),
            json_i64(self.foreground_generation),
        );
        map.insert(
            "focusGeneration".to_string(),
            json_i64(self.focus_generation),
        );
        map.insert("policyRevision".to_string(), json_i64(self.policy_revision));
        map.insert(
            "fieldSecurityMode".to_string(),
            JsonValue::String(self.field_security_mode.clone()),
        );
        map.insert(
            "secureStatus".to_string(),
            JsonValue::String(self.secure_status.as_str().to_string()),
        );
        map.insert(
            "privateState".to_string(),
            JsonValue::String(self.private_state.as_str().to_string()),
        );
        if let Some(ref exe) = self.exe_name {
            map.insert("exeName".to_string(), JsonValue::String(exe.clone()));
        }
        JsonValue::Object(map)
    }

    /// Deserializes an internal worker IPC context, failing closed on any unknown or invalid field.
    pub fn from_json(value: &JsonValue) -> Option<Self> {
        let obj = value.as_obj()?;
        let target_obj = obj.get("target")?.as_obj()?;
        let pid_u64 = target_obj.get("processId")?.as_u64()?;
        if pid_u64 <= 1 || pid_u64 > i32::MAX as u64 {
            return None;
        }
        let target = TargetIdentity {
            device_id: target_obj.get("deviceId")?.as_str()?.to_string(),
            os_session_id: target_obj.get("osSessionId")?.as_str()?.to_string(),
            desktop_id: target_obj.get("desktopId")?.as_str()?.to_string(),
            process_id: pid_u64 as u32,
            process_start_time: target_obj.get("processStartTime")?.as_str()?.to_string(),
            application_id: target_obj.get("applicationId")?.as_str()?.to_string(),
            window_id: target_obj.get("windowId")?.as_str()?.to_string(),
            window_generation: target_obj.get("windowGeneration")?.as_i64()?,
        };
        let surface_id = obj.get("surfaceId")?.as_str()?.to_string();
        let capture_epoch = obj.get("captureEpoch")?.as_i64()?;
        let foreground_generation = obj.get("foregroundGeneration")?.as_i64()?;
        let focus_generation = obj.get("focusGeneration")?.as_i64()?;
        let policy_revision = obj.get("policyRevision")?.as_i64()?;
        let field_security_mode = match obj.get("fieldSecurityMode") {
            None | Some(JsonValue::Null) => "strict".to_string(),
            Some(v) => v.as_str()?.to_string(),
        };
        let secure_status = match obj.get("secureStatus")?.as_str()? {
            "safe" => SecureStatus::Safe,
            "not-declared-sensitive" => SecureStatus::NotDeclaredSensitive,
            "sensitive" => SecureStatus::Sensitive,
            "unknown" => SecureStatus::Unknown,
            _ => return None,
        };
        let private_state = InputTextPrivateState::parse(obj.get("privateState")?.as_str()?)?;
        let exe_name = match obj.get("exeName") {
            None | Some(JsonValue::Null) => None,
            Some(v) => Some(v.as_str()?.to_string()),
        };
        let ctx = Self {
            target,
            surface_id,
            capture_epoch,
            foreground_generation,
            focus_generation,
            policy_revision,
            field_security_mode,
            secure_status,
            private_state,
            exe_name,
        };
        ctx.is_valid().then_some(ctx)
    }
}

/// Provider assertion constructed only after fresh UIA safe-role/security/desktop/identity checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputTextApprovedContext {
    pub context: InputTextContext,
    pub metadata_monotonic_ns: u64,
    pub role: InputTextFieldRole,
}

/// Minimal event timing/target metadata for synchronous Pre-Gate -> Translate -> Post-Gate checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputTextEventMetadata {
    pub target_process_id: u32,
    pub timestamp_ns: u64,
    pub callback_time_ms: i64,
}

/// Request passed to the synchronous safety provider for an individual event or buffered flush.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputTextSafetyRequest<'a> {
    Event(InputTextEventMetadata),
    Flush(&'a InputTextContext),
}

/// Outcome of the synchronous Unicode translation callback (`ToUnicodeEx(0x4)` / `VK_PACKET` / IME commit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputTextUnicodeRead {
    Text(String),
    Unavailable,
    Saturated,
}

/// Decision returned by `InputTextReadGate::capture` and `capture_ime_commit`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputTextCaptureDecision {
    Sample(Box<InputTextSample>),
    Ignored,
    Gap(InputTextGapReason),
}

/// Closed pipeline stage classification for debug telemetry (no user text or keycodes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InputTextReadRejectionStage {
    Receive,
    PreReadSafety,
    UnicodeRead,
    PostReadSafety,
}

impl InputTextReadRejectionStage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Receive => "receive",
            Self::PreReadSafety => "pre-read-safety",
            Self::UnicodeRead => "unicode-read",
            Self::PostReadSafety => "post-read-safety",
        }
    }
}

/// Closed rejection reason classification matching macOS `InputTextReadRejection.Reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InputTextReadRejectionReason {
    PolicyDisabled,
    TargetPidInvalid,
    EventTimeInvalid,
    EventBeforeBoundary,
    EventInFuture,
    EventAgeExceeded,
    SafetyUnavailable,
    ApprovalNotFresh,
    TargetPidMismatch,
    ContextChanged,
    RoleChanged,
    UnicodeUnavailable,
    UnicodeSaturated,
    UnicodeBudget,
}

impl InputTextReadRejectionReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PolicyDisabled => "policy-disabled",
            Self::TargetPidInvalid => "target-pid-invalid",
            Self::EventTimeInvalid => "event-time-invalid",
            Self::EventBeforeBoundary => "event-before-boundary",
            Self::EventInFuture => "event-in-future",
            Self::EventAgeExceeded => "event-age-exceeded",
            Self::SafetyUnavailable => "safety-unavailable",
            Self::ApprovalNotFresh => "approval-not-fresh",
            Self::TargetPidMismatch => "target-pid-mismatch",
            Self::ContextChanged => "context-changed",
            Self::RoleChanged => "role-changed",
            Self::UnicodeUnavailable => "unicode-unavailable",
            Self::UnicodeSaturated => "unicode-saturated",
            Self::UnicodeBudget => "unicode-budget",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InputTextReadRejection {
    pub stage: InputTextReadRejectionStage,
    pub reason: InputTextReadRejectionReason,
}

impl InputTextReadRejection {
    pub const fn new(
        stage: InputTextReadRejectionStage,
        reason: InputTextReadRejectionReason,
    ) -> Self {
        Self { stage, reason }
    }
}

/// Shared macOS-parity structural, freshness, and text-budget limits for `input.text`.
pub struct InputTextLimits;

impl InputTextLimits {
    pub const MAX_CODE_UNITS: usize = 2_048;
    pub const MAX_EVENTS: usize = 256;
    pub const DEBOUNCE_MS: i64 = 500;
    pub const MAX_WAIT_MS: i64 = 2_000;
    pub const MAX_PENDING: usize = 4;
    pub const MAX_EVENT_AGE_NS: u64 = 200_000_000;
    pub const MAX_INTERVAL_SPAN_MS: i64 = 5_000;
    pub const MAX_PENDING_SURROGATE_TTL_MS: i64 = 50;
    pub const IME_PREFIX_PURGE_WINDOW_MS: i64 = 500;
    pub const IME_COMPOSITION_MAX_MS: i64 = 5_000;

    pub const fn is_safe_integer(value: i64) -> bool {
        value >= 0 && value <= MAX_SAFE_INTEGER
    }

    pub fn code_unit_budget(policy: &CapturePolicy) -> usize {
        policy.max_text_code_units.min(Self::MAX_CODE_UNITS)
    }

    pub fn is_valid_identifier(value: &str, max_utf16: usize) -> bool {
        !value.is_empty() && utf16_len(value) <= max_utf16
    }

    /// C0 (`< 0x20`) and C1 (`0x7F..=0x9F`) control characters rejected for `input.text` text payloads.
    pub const fn is_control_scalar(c: char) -> bool {
        let code = c as u32;
        code < 0x20 || (code >= 0x7F && code <= 0x9F)
    }

    pub fn contains_control_scalar(text: &str) -> bool {
        text.chars().any(Self::is_control_scalar)
    }

    /// Filters a candidate keyboard-translated string: returns `Some(text)` only when non-empty
    /// and free of C0/C1 control scalars.
    pub fn filter_text_unit(text: &str) -> Option<&str> {
        if text.is_empty() || Self::contains_control_scalar(text) {
            None
        } else {
            Some(text)
        }
    }

    pub fn is_return_text(text: &str) -> bool {
        matches!(text, "\r" | "\n" | "\u{0003}")
    }

    /// Monotonic event freshness check shared by `input.text` and `input.activity`.
    pub fn is_timestamp_fresh(timestamp_ns: u64, now_ns: u64, after_ns: u64) -> bool {
        timestamp_ns > after_ns
            && timestamp_ns <= now_ns
            && now_ns - timestamp_ns <= Self::MAX_EVENT_AGE_NS
    }

    pub fn event_rejection(
        event: InputTextEventMetadata,
        now_ns: u64,
        after_ns: u64,
    ) -> Option<InputTextReadRejectionReason> {
        if event.target_process_id <= 1 || event.target_process_id > i32::MAX as u32 {
            return Some(InputTextReadRejectionReason::TargetPidInvalid);
        }
        if !Self::is_safe_integer(event.callback_time_ms) {
            return Some(InputTextReadRejectionReason::EventTimeInvalid);
        }
        if event.timestamp_ns <= after_ns {
            return Some(InputTextReadRejectionReason::EventBeforeBoundary);
        }
        if event.timestamp_ns > now_ns {
            return Some(InputTextReadRejectionReason::EventInFuture);
        }
        if now_ns - event.timestamp_ns > Self::MAX_EVENT_AGE_NS {
            return Some(InputTextReadRejectionReason::EventAgeExceeded);
        }
        None
    }

    pub fn event_is_fresh(event: InputTextEventMetadata, now_ns: u64, after_ns: u64) -> bool {
        Self::event_rejection(event, now_ns, after_ns).is_none()
    }

    pub fn approval_rejection(
        approval: &InputTextApprovedContext,
        since_ns: u64,
        now_ns: u64,
        policy: &CapturePolicy,
    ) -> Option<InputTextGapReason> {
        let Some(resolved) = approval.context.resolved_app_identity() else {
            return Some(InputTextGapReason::Stale);
        };
        let private_state_ok = approval.context.private_state == InputTextPrivateState::Normal
            || (policy.application_scope.as_deref() == Some("denylist")
                && policy.allow_browser_content == Some(true));
        if !policy.enabled
            || policy.input_text != Some(true)
            || !policy.has_valid_text_settings()
            || !approval.context.is_valid()
            || approval.context.field_security_mode != policy.field_security_mode()
            || !policy.allows_secure(approval.context.secure_status)
            || !private_state_ok
            || !BrowserGate::allows_identity(&resolved, policy, false)
            || now_ns < since_ns
            || approval.metadata_monotonic_ns < since_ns
            || approval.metadata_monotonic_ns > now_ns
        {
            return Some(InputTextGapReason::Stale);
        }
        // Bound the entire safety read (not merely the completion timestamp).
        if now_ns - since_ns > Self::MAX_EVENT_AGE_NS {
            return Some(InputTextGapReason::VerificationTimeout);
        }
        None
    }

    pub fn approval_is_fresh(
        approval: &InputTextApprovedContext,
        since_ns: u64,
        now_ns: u64,
        policy: &CapturePolicy,
    ) -> bool {
        Self::approval_rejection(approval, since_ns, now_ns, policy).is_none()
    }

    pub fn canonical_modifiers(values: &[InputTextModifier]) -> Vec<InputTextModifier> {
        InputTextModifier::ALL
            .iter()
            .copied()
            .filter(|m| values.contains(m))
            .collect()
    }
}

/// Platform-free Windows physical modifier key state for AltGr vs shortcut classification.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WindowsModifierState {
    pub left_ctrl: bool,
    pub right_ctrl: bool,
    pub left_alt: bool,
    pub right_alt: bool,
    pub left_shift: bool,
    pub right_shift: bool,
    pub left_win: bool,
    pub right_win: bool,
}

/// Result of normalizing Windows modifier keys into canonical wire modifiers + AltGr/shortcut flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedWindowsModifiers {
    pub is_altgr: bool,
    pub is_shortcut: bool,
    pub modifiers: Vec<InputTextModifier>,
}

impl WindowsModifierState {
    /// Returns `true` iff `LCtrl + RAlt` is active without `RCtrl`, `LAlt`, or either `Win` key
    /// (European keyboard AltGr character composition, e.g. `@`, `€`, `~`, `\`).
    pub const fn is_altgr(self) -> bool {
        self.left_ctrl
            && self.right_alt
            && !self.right_ctrl
            && !self.left_alt
            && !self.left_win
            && !self.right_win
    }

    /// Normalizes Windows physical modifiers into canonical wire modifiers:
    /// - When `AltGr` is active (`LCtrl + RAlt` without `RCtrl`/`LAlt`/`Win`), `is_shortcut` is
    ///   `false` and `Control`/`Option` are stripped from `modifiers` (preserving `Shift` if held)
    ///   so European characters remain valid `InputTextKind::Text`.
    /// - Otherwise `(Ctrl || Win)` sets `is_shortcut = true`, and modifiers are emitted in
    ///   canonical order `[Command, Control, Option, Shift]`.
    pub fn normalize(self) -> NormalizedWindowsModifiers {
        let is_altgr = self.is_altgr();
        let shift = self.left_shift || self.right_shift;
        if is_altgr {
            let mut modifiers = Vec::with_capacity(usize::from(shift));
            if shift {
                modifiers.push(InputTextModifier::Shift);
            }
            return NormalizedWindowsModifiers {
                is_altgr: true,
                is_shortcut: false,
                modifiers,
            };
        }
        let win = self.left_win || self.right_win;
        let ctrl = self.left_ctrl || self.right_ctrl;
        let alt = self.left_alt || self.right_alt;
        let mut modifiers = Vec::with_capacity(4);
        if win {
            modifiers.push(InputTextModifier::Command);
        }
        if ctrl {
            modifiers.push(InputTextModifier::Control);
        }
        if alt {
            modifiers.push(InputTextModifier::Option);
        }
        if shift {
            modifiers.push(InputTextModifier::Shift);
        }
        NormalizedWindowsModifiers {
            is_altgr: false,
            is_shortcut: win || ctrl,
            modifiers,
        }
    }
}

/// Convenience helper checking AltGr state (`LCtrl + RAlt` without `RCtrl`/`LAlt`/`Win`).
pub const fn is_altgr_active(state: WindowsModifierState) -> bool {
    state.is_altgr()
}

/// Ephemeral 256-bit virtual-key held-state bitset (`[u64; 4]`) for autorepeat suppression.
/// Never persisted or emitted; cleared on release and on every lifecycle/focus boundary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HeldKeyBitset([u64; 4]);

impl HeldKeyBitset {
    pub const fn new() -> Self {
        Self([0; 4])
    }

    /// Marks `vk` as held. Returns `true` if newly pressed (not already held), or `false` on autorepeat.
    pub fn press(&mut self, vk: u8) -> bool {
        let word = (vk >> 6) as usize;
        let mask = 1u64 << (vk & 63);
        let was_held = (self.0[word] & mask) != 0;
        self.0[word] |= mask;
        !was_held
    }

    pub fn release(&mut self, vk: u8) {
        let word = (vk >> 6) as usize;
        let mask = 1u64 << (vk & 63);
        self.0[word] &= !mask;
    }

    pub const fn is_held(&self, vk: u8) -> bool {
        let word = (vk >> 6) as usize;
        let mask = 1u64 << (vk & 63);
        (self.0[word] & mask) != 0
    }

    pub fn clear(&mut self) {
        self.0 = [0; 4];
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StoredHighSurrogate {
    unit: u16,
    received_at_ms: i64,
}

/// Result of feeding one UTF-16 code unit from Windows `VK_PACKET` into `PendingSurrogate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SurrogateAssemblyOutcome {
    /// Complete valid Unicode character (BMP scalar or assembled surrogate pair).
    Text(String),
    /// Stored leading high surrogate awaiting its trailing low surrogate within TTL.
    PendingHigh,
    /// Dropped an unpaired, expired, or orphaned surrogate (never emits U+FFFD).
    DroppedOrphan,
}

/// Single-slot UTF-16 surrogate-pair assembler for Windows `VK_PACKET` events with a 50ms TTL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingSurrogate {
    pending: Option<StoredHighSurrogate>,
    ttl_ms: i64,
}

impl Default for PendingSurrogate {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingSurrogate {
    pub const fn new() -> Self {
        Self {
            pending: None,
            ttl_ms: InputTextLimits::MAX_PENDING_SURROGATE_TTL_MS,
        }
    }

    pub fn with_ttl_ms(ttl_ms: i64) -> Self {
        Self {
            pending: None,
            ttl_ms: ttl_ms.max(1),
        }
    }

    pub fn clear(&mut self) {
        self.pending = None;
    }

    pub const fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Drops any stale or clock-rolled-back pending high surrogate. Returns `true` if dropped.
    pub fn expire_if_stale(&mut self, now_ms: i64) -> bool {
        if let Some(prev) = self.pending {
            if now_ms
                .checked_sub(prev.received_at_ms)
                .is_none_or(|elapsed| elapsed < 0 || elapsed > self.ttl_ms)
            {
                self.pending = None;
                return true;
            }
        }
        false
    }

    /// Feeds one `u16` code unit from `VK_PACKET` at `now_ms`.
    pub fn push(&mut self, unit: u16, now_ms: i64) -> SurrogateAssemblyOutcome {
        self.expire_if_stale(now_ms);
        if (0xD800..=0xDBFF).contains(&unit) {
            self.pending = Some(StoredHighSurrogate {
                unit,
                received_at_ms: now_ms,
            });
            return SurrogateAssemblyOutcome::PendingHigh;
        }
        if (0xDC00..=0xDFFF).contains(&unit) {
            let Some(high) = self.pending.take() else {
                return SurrogateAssemblyOutcome::DroppedOrphan;
            };
            return match char::decode_utf16([high.unit, unit]).next() {
                Some(Ok(ch)) => SurrogateAssemblyOutcome::Text(ch.to_string()),
                _ => SurrogateAssemblyOutcome::DroppedOrphan,
            };
        }
        // Any BMP scalar invalidates a stray preceding high surrogate.
        self.pending = None;
        match char::from_u32(u32::from(unit)) {
            Some(ch) => SurrogateAssemblyOutcome::Text(ch.to_string()),
            None => SurrogateAssemblyOutcome::DroppedOrphan,
        }
    }
}

/// Normalized, verified single keystroke or IME commit sample prior to interval aggregation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputTextSample {
    pub context: InputTextContext,
    pub event_kind: InputTextKind,
    pub text: String,
    pub modifiers: Vec<InputTextModifier>,
    pub callback_time_ms: i64,
    pub extra_coverage_reasons: Vec<String>,
}

fn sanitize_extra_coverage_reasons(reasons: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for reason in reasons {
        if reason == "input-events-partial" || reason == "effect-unverified" {
            continue;
        }
        if !out.contains(&reason) {
            out.push(reason);
        }
    }
    out
}

fn extra_coverage_reasons_valid(reasons: &[String]) -> bool {
    reasons.len() <= 14
        && reasons.iter().all(|r| {
            InputTextLimits::is_valid_identifier(r, 128)
                && !InputTextLimits::contains_control_scalar(r)
        })
}

fn is_valid_sample_parts(
    context: &InputTextContext,
    event_kind: InputTextKind,
    text: &str,
    modifiers: &[InputTextModifier],
    callback_time_ms: i64,
    extra_coverage_reasons: &[String],
) -> bool {
    let has_cmd_or_ctrl = modifiers.contains(&InputTextModifier::Command)
        || modifiers.contains(&InputTextModifier::Control);
    let text_ok = match event_kind {
        InputTextKind::Text => {
            !text.is_empty() && !has_cmd_or_ctrl && !InputTextLimits::contains_control_scalar(text)
        }
        InputTextKind::Return => text.is_empty(),
        InputTextKind::Shortcut => text.is_empty() && has_cmd_or_ctrl,
    };
    context.is_valid()
        && InputTextLimits::is_safe_integer(callback_time_ms)
        && utf16_len(text) <= InputTextLimits::MAX_CODE_UNITS
        && modifiers == InputTextLimits::canonical_modifiers(modifiers).as_slice()
        && extra_coverage_reasons_valid(extra_coverage_reasons)
        && text_ok
}

impl InputTextSample {
    pub fn new(
        context: InputTextContext,
        event_kind: InputTextKind,
        text: String,
        modifiers: Vec<InputTextModifier>,
        callback_time_ms: i64,
    ) -> Self {
        Self::with_extra_coverage(
            context,
            event_kind,
            text,
            modifiers,
            callback_time_ms,
            DEFAULT_KEYBOARD_COVERAGE_EXTRAS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        )
    }

    pub fn with_extra_coverage(
        context: InputTextContext,
        event_kind: InputTextKind,
        text: String,
        modifiers: Vec<InputTextModifier>,
        callback_time_ms: i64,
        extra_coverage_reasons: Vec<String>,
    ) -> Self {
        Self {
            context,
            event_kind,
            text,
            modifiers: InputTextLimits::canonical_modifiers(&modifiers),
            callback_time_ms,
            extra_coverage_reasons: sanitize_extra_coverage_reasons(extra_coverage_reasons),
        }
    }

    /// Constructs a gated IME composition-commit sample carrying `"ime-composition-commit"`
    /// and `"non-atomic-field-gate"` coverage reasons.
    pub fn ime_commit(context: InputTextContext, text: String, callback_time_ms: i64) -> Self {
        Self::with_extra_coverage(
            context,
            InputTextKind::Text,
            text,
            Vec::new(),
            callback_time_ms,
            IME_COMMIT_COVERAGE_EXTRAS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        )
    }

    pub fn is_valid(&self) -> bool {
        is_valid_sample_parts(
            &self.context,
            self.event_kind,
            &self.text,
            &self.modifiers,
            self.callback_time_ms,
            &self.extra_coverage_reasons,
        )
    }
}

/// Immutable, bounded, normalized worker IPC record and wire payload builder for `input.text`.
/// Raw hook/event metadata (keycodes, timestamps, HWNDs) is strictly absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputTextRecord {
    pub context: InputTextContext,
    pub source: InputTextSource,
    pub event_kind: InputTextKind,
    pub text: String,
    pub modifiers: Vec<InputTextModifier>,
    pub interval_start_ms: i64,
    pub interval_end_ms: i64,
    pub event_count: usize,
    pub extra_coverage_reasons: Vec<String>,
}

impl InputTextRecord {
    fn from_sample(
        sample: InputTextSample,
        source: InputTextSource,
        interval_start_ms: i64,
        event_count: usize,
    ) -> Self {
        Self {
            context: sample.context,
            source,
            event_kind: sample.event_kind,
            text: sample.text,
            modifiers: sample.modifiers,
            interval_start_ms,
            interval_end_ms: sample.callback_time_ms,
            event_count,
            extra_coverage_reasons: sample.extra_coverage_reasons,
        }
    }

    fn from_sample_with_text(
        sample: InputTextSample,
        source: InputTextSource,
        text: String,
        interval_start_ms: i64,
        event_count: usize,
    ) -> Self {
        zeroize_string(sample.text);
        Self {
            context: sample.context,
            source,
            event_kind: sample.event_kind,
            text,
            modifiers: sample.modifiers,
            interval_start_ms,
            interval_end_ms: sample.callback_time_ms,
            event_count,
            extra_coverage_reasons: sample.extra_coverage_reasons,
        }
    }

    pub fn utf16_len(&self) -> usize {
        utf16_len(&self.text)
    }

    pub fn is_valid(&self) -> bool {
        is_valid_sample_parts(
            &self.context,
            self.event_kind,
            &self.text,
            &self.modifiers,
            self.interval_end_ms,
            &self.extra_coverage_reasons,
        ) && InputTextLimits::is_safe_integer(self.interval_start_ms)
            && self
                .interval_end_ms
                .checked_sub(self.interval_start_ms)
                .is_some_and(|span| (0..=InputTextLimits::MAX_INTERVAL_SPAN_MS).contains(&span))
            && (1..=InputTextLimits::MAX_EVENTS).contains(&self.event_count)
    }

    /// Builds the exact 14-field wire-v1 `input.text` payload (`additionalProperties: false`).
    /// Returns `None` fail-closed if the record or its `content_gate()` is invalid/sensitive,
    /// so invalid or sensitive states never serialize as `"safe"` or leak plaintext to JSON.
    /// Never emits internal-only `exe_name` or raw event metadata.
    pub fn payload(&self) -> Option<JsonValue> {
        if !self.is_valid() {
            return None;
        }
        let gate = self.context.content_gate()?;
        let mut missing_reasons = Vec::with_capacity(2 + self.extra_coverage_reasons.len());
        missing_reasons.push("input-events-partial".to_string());
        for extra in &self.extra_coverage_reasons {
            if extra == "input-events-partial" || extra == "effect-unverified" {
                continue;
            }
            if InputTextLimits::is_valid_identifier(extra, 128)
                && !InputTextLimits::contains_control_scalar(extra)
                && !missing_reasons.contains(extra)
                && missing_reasons.len() < 15
            {
                missing_reasons.push(extra.clone());
            }
        }
        missing_reasons.push("effect-unverified".to_string());

        let coverage = Coverage {
            status: "partial".to_string(),
            truncated: false,
            missing_reasons,
        };

        let mut map = BTreeMap::new();
        map.insert(
            "kind".to_string(),
            JsonValue::String("input.text".to_string()),
        );
        map.insert(
            "source".to_string(),
            JsonValue::String(self.source.as_str().to_string()),
        );
        map.insert("scope".to_string(), JsonValue::String("field".to_string()));
        map.insert(
            "eventKind".to_string(),
            JsonValue::String(self.event_kind.as_str().to_string()),
        );
        map.insert("text".to_string(), JsonValue::String(self.text.clone()));
        map.insert(
            "modifiers".to_string(),
            JsonValue::Array(
                self.modifiers
                    .iter()
                    .map(|m| JsonValue::String(m.as_str().to_string()))
                    .collect(),
            ),
        );
        map.insert(
            "intervalStartMs".to_string(),
            json_i64(self.interval_start_ms),
        );
        map.insert("intervalEndMs".to_string(), json_i64(self.interval_end_ms));
        map.insert("eventCount".to_string(), json_usize(self.event_count));
        map.insert(
            "surfaceId".to_string(),
            JsonValue::String(self.context.surface_id.clone()),
        );
        map.insert("gate".to_string(), gate.to_json());
        map.insert(
            "secureInput".to_string(),
            JsonValue::String("inactive".to_string()),
        );
        map.insert("coverage".to_string(), coverage.to_json());
        map.insert(
            "effect".to_string(),
            JsonValue::String("unverified".to_string()),
        );
        Some(JsonValue::Object(map))
    }

    /// Serializes this record for internal worker->parent IPC.
    pub fn to_json(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("context".to_string(), self.context.to_json());
        map.insert(
            "source".to_string(),
            JsonValue::String(self.source.as_str().to_string()),
        );
        map.insert(
            "eventKind".to_string(),
            JsonValue::String(self.event_kind.as_str().to_string()),
        );
        map.insert("text".to_string(), JsonValue::String(self.text.clone()));
        map.insert(
            "modifiers".to_string(),
            JsonValue::Array(
                self.modifiers
                    .iter()
                    .map(|m| JsonValue::String(m.as_str().to_string()))
                    .collect(),
            ),
        );
        map.insert(
            "intervalStartMs".to_string(),
            json_i64(self.interval_start_ms),
        );
        map.insert("intervalEndMs".to_string(), json_i64(self.interval_end_ms));
        map.insert("eventCount".to_string(), json_usize(self.event_count));
        if !self.extra_coverage_reasons.is_empty() {
            map.insert(
                "extraCoverageReasons".to_string(),
                JsonValue::Array(
                    self.extra_coverage_reasons
                        .iter()
                        .cloned()
                        .map(JsonValue::String)
                        .collect(),
                ),
            );
        }
        JsonValue::Object(map)
    }

    /// Deserializes a worker IPC record, rejecting unknown enums or invalid fields fail-closed.
    pub fn from_json(value: &JsonValue) -> Option<Self> {
        let obj = value.as_obj()?;
        let context = InputTextContext::from_json(obj.get("context")?)?;
        let source = InputTextSource::parse(obj.get("source")?.as_str()?)?;
        let event_kind = InputTextKind::parse(obj.get("eventKind")?.as_str()?)?;
        let text = obj.get("text")?.as_str()?.to_string();
        let mods_arr = obj.get("modifiers")?.as_array()?;
        let mut modifiers = Vec::with_capacity(mods_arr.len());
        for item in mods_arr {
            modifiers.push(InputTextModifier::parse(item.as_str()?)?);
        }
        let interval_start_ms = obj.get("intervalStartMs")?.as_i64()?;
        let interval_end_ms = obj.get("intervalEndMs")?.as_i64()?;
        let event_count = usize::try_from(obj.get("eventCount")?.as_u64()?).ok()?;
        let extra_coverage_reasons = match obj.get("extraCoverageReasons") {
            None | Some(JsonValue::Null) => Vec::new(),
            Some(v) => {
                let arr = v.as_array()?;
                let mut extras = Vec::with_capacity(arr.len());
                for item in arr {
                    extras.push(item.as_str()?.to_string());
                }
                sanitize_extra_coverage_reasons(extras)
            }
        };
        let record = Self {
            context,
            source,
            event_kind,
            text,
            modifiers,
            interval_start_ms,
            interval_end_ms,
            event_count,
            extra_coverage_reasons,
        };
        if record.is_valid() {
            Some(record)
        } else {
            zeroize_string(record.text);
            None
        }
    }
}

/// Outcome of ingesting a verified sample into `InputTextAccumulator` + `completed` queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputTextIngestOutcome {
    /// Sample merged into or started the pending debounce buffer.
    Buffered,
    /// `Return` keystroke sealed immediately into `completed` (caller should wake fast focused read).
    SealedReturn,
}

/// Single bounded aggregation buffer. Context changes ALWAYS discard (never flush old text).
/// Capacity overflow discards the entire pending buffer and emits `InputTextGapReason::Budget`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputTextAccumulator {
    pending: Option<InputTextRecord>,
    max_code_units: usize,
}

impl Default for InputTextAccumulator {
    fn default() -> Self {
        Self::new(InputTextLimits::MAX_CODE_UNITS)
    }
}

impl InputTextAccumulator {
    pub fn new(max_code_units: usize) -> Self {
        Self {
            pending: None,
            max_code_units: max_code_units.min(InputTextLimits::MAX_CODE_UNITS),
        }
    }

    pub fn from_policy(policy: &CapturePolicy) -> Self {
        Self::new(InputTextLimits::code_unit_budget(policy))
    }

    pub const fn max_code_units(&self) -> usize {
        self.max_code_units
    }

    pub fn pending(&self) -> Option<&InputTextRecord> {
        self.pending.as_ref()
    }

    pub fn clear(&mut self) {
        if let Some(old) = self.pending.take() {
            zeroize_string(old.text);
        }
    }

    /// Merges `sample` into the single pending buffer, or discards the buffer and returns a gap reason.
    pub fn add(
        &mut self,
        sample: InputTextSample,
        source: InputTextSource,
    ) -> Option<InputTextGapReason> {
        if !sample.is_valid() {
            zeroize_string(sample.text);
            self.clear();
            return Some(InputTextGapReason::ReadError);
        }
        let sample_units = utf16_len(&sample.text);
        if sample_units > self.max_code_units {
            zeroize_string(sample.text);
            self.clear();
            return Some(InputTextGapReason::Budget);
        }
        if let Some(current) = self.pending.take() {
            if current.context != sample.context {
                zeroize_string(current.text);
                zeroize_string(sample.text);
                return Some(InputTextGapReason::Stale);
            }
            if sample
                .callback_time_ms
                .checked_sub(current.interval_end_ms)
                .is_none_or(|delta| delta < 0)
            {
                zeroize_string(current.text);
                zeroize_string(sample.text);
                return Some(InputTextGapReason::Stale);
            }
            let Some(wait_span) = sample.callback_time_ms.checked_sub(current.interval_start_ms)
            else {
                zeroize_string(current.text);
                zeroize_string(sample.text);
                return Some(InputTextGapReason::Stale);
            };
            if wait_span < 0 {
                zeroize_string(current.text);
                zeroize_string(sample.text);
                return Some(InputTextGapReason::Stale);
            }
            if wait_span > InputTextLimits::MAX_WAIT_MS
                || current.event_count >= InputTextLimits::MAX_EVENTS
                || utf16_len(&current.text).saturating_add(sample_units) > self.max_code_units
            {
                zeroize_string(current.text);
                zeroize_string(sample.text);
                return Some(InputTextGapReason::Budget);
            }
            if current.source != source
                || current.event_kind != sample.event_kind
                || current.modifiers != sample.modifiers
                || current.extra_coverage_reasons != sample.extra_coverage_reasons
            {
                zeroize_string(current.text);
                zeroize_string(sample.text);
                return Some(InputTextGapReason::Stale);
            }
            let mut merged = current.text;
            merged.push_str(&sample.text);
            let start = current.interval_start_ms;
            let count = current.event_count + 1;
            self.pending = Some(InputTextRecord::from_sample_with_text(
                sample, source, merged, start, count,
            ));
        } else {
            let start = sample.callback_time_ms;
            self.pending = Some(InputTextRecord::from_sample(sample, source, start, 1));
        }
        None
    }

    pub fn is_due(&self, now_ms: i64) -> bool {
        let Some(ref pending) = self.pending else {
            return false;
        };
        let Some(since_end) = now_ms.checked_sub(pending.interval_end_ms) else {
            return false;
        };
        let Some(since_start) = now_ms.checked_sub(pending.interval_start_ms) else {
            return false;
        };
        if since_end < 0 || since_start < 0 {
            return false;
        }
        since_end >= InputTextLimits::DEBOUNCE_MS || since_start >= InputTextLimits::MAX_WAIT_MS
    }

    /// Takes the pending buffer once due if and only if freshly approved for the exact same context.
    pub fn take_due(
        &mut self,
        now_ms: i64,
        approved_context: Option<&InputTextContext>,
    ) -> Option<InputTextRecord> {
        let current = self.pending.as_ref()?;
        if approved_context != Some(&current.context)
            || now_ms
                .checked_sub(current.interval_end_ms)
                .is_none_or(|delta| delta < 0)
            || now_ms
                .checked_sub(current.interval_start_ms)
                .is_none_or(|span| !(0..=InputTextLimits::MAX_INTERVAL_SPAN_MS).contains(&span))
        {
            self.clear();
            return None;
        }
        if !self.is_due(now_ms) {
            return None;
        }
        self.pending.take()
    }

    /// Causal barrier flush: seals pending immediately for a freshly approved exact context
    /// without waiting for the standalone 500ms debounce timer.
    pub fn take_at_barrier(
        &mut self,
        now_ms: i64,
        approved_context: Option<&InputTextContext>,
    ) -> Option<InputTextRecord> {
        let current = self.pending.as_ref()?;
        if approved_context != Some(&current.context)
            || now_ms
                .checked_sub(current.interval_end_ms)
                .is_none_or(|delta| delta < 0)
            || now_ms
                .checked_sub(current.interval_start_ms)
                .is_none_or(|span| !(0..=InputTextLimits::MAX_INTERVAL_SPAN_MS).contains(&span))
        {
            self.clear();
            return None;
        }
        self.pending.take()
    }

    /// Segments within the same verified safe context (e.g., `Text` followed by `Return`).
    pub fn take_segment(
        &mut self,
        approved_context: &InputTextContext,
    ) -> Option<InputTextRecord> {
        if self
            .pending
            .as_ref()
            .is_none_or(|p| p.context != *approved_context)
        {
            self.clear();
            return None;
        }
        self.pending.take()
    }

    /// Ingests a freshly gate-approved sample into `self` + `completed`:
    /// - Context change against pending or completed discards both and returns `context_mismatch`.
    /// - Monotonic timestamp regression or pending span `> MAX_INTERVAL_SPAN_MS` discards both with `Stale`.
    /// - Kind/modifier/source/coverage-origin change or due buffer seals the prior segment into `completed`.
    /// - `InputTextKind::Return` seals immediately into `completed` (returns `SealedReturn`).
    /// - Any overflow (`> MAX_PENDING`, budget, invalid) discards both pending & completed.
    pub fn ingest_into_completed(
        &mut self,
        completed: &mut Vec<InputTextRecord>,
        sample: InputTextSample,
        source: InputTextSource,
    ) -> Result<InputTextIngestOutcome, InputTextGapReason> {
        let purge = |acc: &mut Self, done: &mut Vec<InputTextRecord>, reason: InputTextGapReason| {
            acc.clear();
            for rec in done.drain(..) {
                zeroize_string(rec.text);
            }
            Err(reason)
        };

        if let Some(mismatched) = self
            .pending
            .iter()
            .chain(completed.iter().rev())
            .find(|rec| rec.context != sample.context)
        {
            let reason = InputTextGapReason::context_mismatch(&mismatched.context, &sample.context);
            zeroize_string(sample.text);
            return purge(self, completed, reason);
        }

        if let Some(latest) = self.pending.as_ref().or_else(|| completed.last()) {
            if sample
                .callback_time_ms
                .checked_sub(latest.interval_end_ms)
                .is_none_or(|delta| delta < 0)
            {
                zeroize_string(sample.text);
                return purge(self, completed, InputTextGapReason::Stale);
            }
        }

        if let Some(pending) = self.pending.as_ref() {
            if sample
                .callback_time_ms
                .checked_sub(pending.interval_start_ms)
                .is_none_or(|span| !(0..=InputTextLimits::MAX_INTERVAL_SPAN_MS).contains(&span))
            {
                zeroize_string(sample.text);
                return purge(self, completed, InputTextGapReason::Stale);
            }
            let needs_segment = self.is_due(sample.callback_time_ms)
                || pending.source != source
                || pending.event_kind != sample.event_kind
                || pending.modifiers != sample.modifiers
                || pending.extra_coverage_reasons != sample.extra_coverage_reasons;
            if needs_segment {
                if completed.len() >= InputTextLimits::MAX_PENDING {
                    zeroize_string(sample.text);
                    return purge(self, completed, InputTextGapReason::Backpressure);
                }
                if let Some(previous) = self.take_segment(&sample.context) {
                    if !previous.is_valid() {
                        zeroize_string(previous.text);
                        zeroize_string(sample.text);
                        return purge(self, completed, InputTextGapReason::ReadError);
                    }
                    completed.push(previous);
                }
            }
        }

        let is_return = sample.event_kind == InputTextKind::Return;
        let sample_ctx = sample.context.clone();
        if let Some(reason) = self.add(sample, source) {
            return purge(self, completed, reason);
        }

        if is_return {
            if completed.len() >= InputTextLimits::MAX_PENDING {
                return purge(self, completed, InputTextGapReason::Backpressure);
            }
            let Some(sealed) = self.take_segment(&sample_ctx) else {
                return purge(self, completed, InputTextGapReason::Stale);
            };
            if !sealed.is_valid() {
                zeroize_string(sealed.text);
                return purge(self, completed, InputTextGapReason::ReadError);
            }
            completed.push(sealed);
            return Ok(InputTextIngestOutcome::SealedReturn);
        }

        Ok(InputTextIngestOutcome::Buffered)
    }
}

/// Step outcome for `InputTextReadGate::capture_with_accumulator`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputTextCaptureStep {
    Buffered,
    SealedReturn,
    Ignored,
    Gap(InputTextGapReason),
}

enum InternalCaptureDecision {
    Sample(Box<InputTextSample>),
    Ignored { verified_context: Box<InputTextContext> },
    Gap(InputTextGapReason),
}

/// Pure synchronous Pre-Gate -> Translate -> Post-Gate state machine and causal barrier drain.
pub struct InputTextReadGate;

impl InputTextReadGate {
    #[allow(clippy::too_many_arguments)]
    fn capture_internal<Now, Safety, ReadUnicode, OnRejection>(
        metadata: InputTextEventMetadata,
        modifiers: &[InputTextModifier],
        policy: &CapturePolicy,
        after_ns: u64,
        now_ns: Now,
        mut typed_safety_provider: Safety,
        read_unicode: ReadUnicode,
        mut on_rejection: OnRejection,
    ) -> InternalCaptureDecision
    where
        Now: Fn() -> u64,
        Safety: FnMut(InputTextSafetyRequest<'_>) -> Result<InputTextApprovedContext, InputTextGapReason>,
        ReadUnicode: FnOnce() -> InputTextUnicodeRead,
        OnRejection: FnMut(InputTextReadRejection),
    {
        let mut reject = |stage: InputTextReadRejectionStage,
                          reason: InputTextReadRejectionReason,
                          gap: InputTextGapReason| {
            on_rejection(InputTextReadRejection::new(stage, reason));
            InternalCaptureDecision::Gap(gap)
        };

        if !policy.enabled || policy.input_text != Some(true) {
            return reject(
                InputTextReadRejectionStage::Receive,
                InputTextReadRejectionReason::PolicyDisabled,
                InputTextGapReason::PolicyBoundary,
            );
        }

        let before_start = now_ns();
        if let Some(reason) = InputTextLimits::event_rejection(metadata, before_start, after_ns) {
            return reject(
                InputTextReadRejectionStage::Receive,
                reason,
                InputTextGapReason::Stale,
            );
        }

        let before = match typed_safety_provider(InputTextSafetyRequest::Event(metadata)) {
            Ok(value) => value,
            Err(gap) => {
                return reject(
                    InputTextReadRejectionStage::PreReadSafety,
                    InputTextReadRejectionReason::SafetyUnavailable,
                    gap,
                );
            }
        };
        if let Some(gap) =
            InputTextLimits::approval_rejection(&before, before_start, now_ns(), policy)
        {
            return reject(
                InputTextReadRejectionStage::PreReadSafety,
                InputTextReadRejectionReason::ApprovalNotFresh,
                gap,
            );
        }
        if before.context.target.process_id != metadata.target_process_id {
            return reject(
                InputTextReadRejectionStage::PreReadSafety,
                InputTextReadRejectionReason::TargetPidMismatch,
                InputTextGapReason::process_mismatch(
                    metadata.target_process_id,
                    i64::from(before.context.target.process_id),
                ),
            );
        }
        if let Some(reason) = InputTextLimits::event_rejection(metadata, now_ns(), after_ns) {
            let gap = if reason == InputTextReadRejectionReason::EventAgeExceeded {
                InputTextGapReason::VerificationTimeout
            } else {
                InputTextGapReason::Stale
            };
            return reject(InputTextReadRejectionStage::PreReadSafety, reason, gap);
        }

        let canonical = InputTextLimits::canonical_modifiers(modifiers);
        let is_shortcut = canonical.contains(&InputTextModifier::Command)
            || canonical.contains(&InputTextModifier::Control);
        // Shortcut evidence never invokes Unicode translation and never touches clipboard.
        let read = if is_shortcut {
            InputTextUnicodeRead::Text(String::new())
        } else {
            read_unicode()
        };

        let after_start = now_ns();
        let after = match typed_safety_provider(InputTextSafetyRequest::Event(metadata)) {
            Ok(value) => value,
            Err(gap) => {
                zeroize_unicode_read(read);
                return reject(
                    InputTextReadRejectionStage::PostReadSafety,
                    InputTextReadRejectionReason::SafetyUnavailable,
                    gap,
                );
            }
        };
        if let Some(gap) =
            InputTextLimits::approval_rejection(&after, after_start, now_ns(), policy)
        {
            zeroize_unicode_read(read);
            return reject(
                InputTextReadRejectionStage::PostReadSafety,
                InputTextReadRejectionReason::ApprovalNotFresh,
                gap,
            );
        }
        if after.context != before.context {
            zeroize_unicode_read(read);
            return reject(
                InputTextReadRejectionStage::PostReadSafety,
                InputTextReadRejectionReason::ContextChanged,
                InputTextGapReason::context_mismatch(&before.context, &after.context),
            );
        }
        if after.role != before.role {
            zeroize_unicode_read(read);
            return reject(
                InputTextReadRejectionStage::PostReadSafety,
                InputTextReadRejectionReason::RoleChanged,
                InputTextGapReason::Stale,
            );
        }
        if let Some(reason) = InputTextLimits::event_rejection(metadata, now_ns(), after_ns) {
            zeroize_unicode_read(read);
            let gap = if reason == InputTextReadRejectionReason::EventAgeExceeded {
                InputTextGapReason::VerificationTimeout
            } else {
                InputTextGapReason::Stale
            };
            return reject(InputTextReadRejectionStage::PostReadSafety, reason, gap);
        }

        match read {
            InputTextUnicodeRead::Unavailable => reject(
                InputTextReadRejectionStage::UnicodeRead,
                InputTextReadRejectionReason::UnicodeUnavailable,
                InputTextGapReason::ReadError,
            ),
            InputTextUnicodeRead::Saturated => reject(
                InputTextReadRejectionStage::UnicodeRead,
                InputTextReadRejectionReason::UnicodeSaturated,
                InputTextGapReason::Budget,
            ),
            InputTextUnicodeRead::Text(text) => {
                if utf16_len(&text) > InputTextLimits::code_unit_budget(policy) {
                    zeroize_string(text);
                    return reject(
                        InputTextReadRejectionStage::UnicodeRead,
                        InputTextReadRejectionReason::UnicodeBudget,
                        InputTextGapReason::Budget,
                    );
                }
                let (kind, normalized) = if is_shortcut {
                    zeroize_string(text);
                    (InputTextKind::Shortcut, String::new())
                } else if InputTextLimits::is_return_text(&text) {
                    zeroize_string(text);
                    (InputTextKind::Return, String::new())
                } else if InputTextLimits::filter_text_unit(&text).is_none() {
                    zeroize_string(text);
                    return InternalCaptureDecision::Ignored {
                        verified_context: Box::new(before.context),
                    };
                } else {
                    (InputTextKind::Text, text)
                };
                InternalCaptureDecision::Sample(Box::new(InputTextSample::new(
                    before.context,
                    kind,
                    normalized,
                    canonical,
                    metadata.callback_time_ms,
                )))
            }
        }
    }

    /// Strict Pre-Gate -> Translate -> Post-Gate seam.
    /// - Pre-gate failure NEVER invokes `read_unicode`.
    /// - Shortcuts (`Command` / `Control`) NEVER invoke `read_unicode`.
    /// - Post-gate mismatch zeroizes and discards translated text.
    #[allow(clippy::too_many_arguments)]
    pub fn capture<Now, Safety, ReadUnicode, OnRejection>(
        metadata: InputTextEventMetadata,
        modifiers: &[InputTextModifier],
        policy: &CapturePolicy,
        after_ns: u64,
        now_ns: Now,
        typed_safety_provider: Safety,
        read_unicode: ReadUnicode,
        on_rejection: OnRejection,
    ) -> InputTextCaptureDecision
    where
        Now: Fn() -> u64,
        Safety: FnMut(InputTextSafetyRequest<'_>) -> Result<InputTextApprovedContext, InputTextGapReason>,
        ReadUnicode: FnOnce() -> InputTextUnicodeRead,
        OnRejection: FnMut(InputTextReadRejection),
    {
        match Self::capture_internal(
            metadata,
            modifiers,
            policy,
            after_ns,
            now_ns,
            typed_safety_provider,
            read_unicode,
            on_rejection,
        ) {
            InternalCaptureDecision::Sample(sample) => InputTextCaptureDecision::Sample(sample),
            InternalCaptureDecision::Ignored { .. } => InputTextCaptureDecision::Ignored,
            InternalCaptureDecision::Gap(reason) => InputTextCaptureDecision::Gap(reason),
        }
    }

    /// Runs `capture` and immediately purges both `accumulator` and `completed` on any gap,
    /// purges and zeroizes mismatched buffered plaintext on an `Ignored` key in a new verified
    /// context, or ingests the verified sample (sealing `Return` immediately) on success.
    #[allow(clippy::too_many_arguments)]
    pub fn capture_with_accumulator<Now, Safety, ReadUnicode, OnRejection>(
        metadata: InputTextEventMetadata,
        modifiers: &[InputTextModifier],
        source: InputTextSource,
        policy: &CapturePolicy,
        after_ns: u64,
        accumulator: &mut InputTextAccumulator,
        completed: &mut Vec<InputTextRecord>,
        now_ns: Now,
        typed_safety_provider: Safety,
        read_unicode: ReadUnicode,
        on_rejection: OnRejection,
    ) -> InputTextCaptureStep
    where
        Now: Fn() -> u64,
        Safety: FnMut(InputTextSafetyRequest<'_>) -> Result<InputTextApprovedContext, InputTextGapReason>,
        ReadUnicode: FnOnce() -> InputTextUnicodeRead,
        OnRejection: FnMut(InputTextReadRejection),
    {
        match Self::capture_internal(
            metadata,
            modifiers,
            policy,
            after_ns,
            now_ns,
            typed_safety_provider,
            read_unicode,
            on_rejection,
        ) {
            InternalCaptureDecision::Ignored { verified_context } => {
                let mismatched = accumulator
                    .pending()
                    .into_iter()
                    .chain(completed.iter().rev())
                    .any(|rec| rec.context != *verified_context);
                if mismatched {
                    accumulator.clear();
                    for rec in completed.drain(..) {
                        zeroize_string(rec.text);
                    }
                }
                InputTextCaptureStep::Ignored
            }
            InternalCaptureDecision::Gap(reason) => {
                accumulator.clear();
                for rec in completed.drain(..) {
                    zeroize_string(rec.text);
                }
                InputTextCaptureStep::Gap(reason)
            }
            InternalCaptureDecision::Sample(sample) => {
                match accumulator.ingest_into_completed(completed, *sample, source) {
                    Ok(InputTextIngestOutcome::Buffered) => InputTextCaptureStep::Buffered,
                    Ok(InputTextIngestOutcome::SealedReturn) => InputTextCaptureStep::SealedReturn,
                    Err(reason) => InputTextCaptureStep::Gap(reason),
                }
            }
        }
    }

    /// Strict Pre-Gate -> Read Committed Text -> Post-Gate seam for UIA/TSF IME composition commits.
    /// Pre-gate failure NEVER invokes `read_committed`; valid text emits an IME-attributed `Sample`.
    #[allow(clippy::too_many_arguments)]
    pub fn capture_ime_commit<Now, Safety, ReadCommitted, OnRejection>(
        metadata: InputTextEventMetadata,
        policy: &CapturePolicy,
        after_ns: u64,
        now_ns: Now,
        mut typed_safety_provider: Safety,
        read_committed: ReadCommitted,
        mut on_rejection: OnRejection,
    ) -> InputTextCaptureDecision
    where
        Now: Fn() -> u64,
        Safety: FnMut(InputTextSafetyRequest<'_>) -> Result<InputTextApprovedContext, InputTextGapReason>,
        ReadCommitted: FnOnce() -> InputTextUnicodeRead,
        OnRejection: FnMut(InputTextReadRejection),
    {
        let mut reject = |stage: InputTextReadRejectionStage,
                          reason: InputTextReadRejectionReason,
                          gap: InputTextGapReason| {
            on_rejection(InputTextReadRejection::new(stage, reason));
            InputTextCaptureDecision::Gap(gap)
        };

        if !policy.enabled || policy.input_text != Some(true) {
            return reject(
                InputTextReadRejectionStage::Receive,
                InputTextReadRejectionReason::PolicyDisabled,
                InputTextGapReason::PolicyBoundary,
            );
        }

        let before_start = now_ns();
        if let Some(reason) = InputTextLimits::event_rejection(metadata, before_start, after_ns) {
            return reject(
                InputTextReadRejectionStage::Receive,
                reason,
                InputTextGapReason::Stale,
            );
        }

        let before = match typed_safety_provider(InputTextSafetyRequest::Event(metadata)) {
            Ok(value) => value,
            Err(gap) => {
                return reject(
                    InputTextReadRejectionStage::PreReadSafety,
                    InputTextReadRejectionReason::SafetyUnavailable,
                    gap,
                );
            }
        };
        if let Some(gap) =
            InputTextLimits::approval_rejection(&before, before_start, now_ns(), policy)
        {
            return reject(
                InputTextReadRejectionStage::PreReadSafety,
                InputTextReadRejectionReason::ApprovalNotFresh,
                gap,
            );
        }
        if before.context.target.process_id != metadata.target_process_id {
            return reject(
                InputTextReadRejectionStage::PreReadSafety,
                InputTextReadRejectionReason::TargetPidMismatch,
                InputTextGapReason::process_mismatch(
                    metadata.target_process_id,
                    i64::from(before.context.target.process_id),
                ),
            );
        }
        if let Some(reason) = InputTextLimits::event_rejection(metadata, now_ns(), after_ns) {
            let gap = if reason == InputTextReadRejectionReason::EventAgeExceeded {
                InputTextGapReason::VerificationTimeout
            } else {
                InputTextGapReason::Stale
            };
            return reject(InputTextReadRejectionStage::PreReadSafety, reason, gap);
        }

        let read = read_committed();

        let after_start = now_ns();
        let after = match typed_safety_provider(InputTextSafetyRequest::Event(metadata)) {
            Ok(value) => value,
            Err(gap) => {
                zeroize_unicode_read(read);
                return reject(
                    InputTextReadRejectionStage::PostReadSafety,
                    InputTextReadRejectionReason::SafetyUnavailable,
                    gap,
                );
            }
        };
        if let Some(gap) =
            InputTextLimits::approval_rejection(&after, after_start, now_ns(), policy)
        {
            zeroize_unicode_read(read);
            return reject(
                InputTextReadRejectionStage::PostReadSafety,
                InputTextReadRejectionReason::ApprovalNotFresh,
                gap,
            );
        }
        if after.context != before.context {
            zeroize_unicode_read(read);
            return reject(
                InputTextReadRejectionStage::PostReadSafety,
                InputTextReadRejectionReason::ContextChanged,
                InputTextGapReason::context_mismatch(&before.context, &after.context),
            );
        }
        if after.role != before.role {
            zeroize_unicode_read(read);
            return reject(
                InputTextReadRejectionStage::PostReadSafety,
                InputTextReadRejectionReason::RoleChanged,
                InputTextGapReason::Stale,
            );
        }
        if let Some(reason) = InputTextLimits::event_rejection(metadata, now_ns(), after_ns) {
            zeroize_unicode_read(read);
            let gap = if reason == InputTextReadRejectionReason::EventAgeExceeded {
                InputTextGapReason::VerificationTimeout
            } else {
                InputTextGapReason::Stale
            };
            return reject(InputTextReadRejectionStage::PostReadSafety, reason, gap);
        }

        match read {
            InputTextUnicodeRead::Unavailable => reject(
                InputTextReadRejectionStage::UnicodeRead,
                InputTextReadRejectionReason::UnicodeUnavailable,
                InputTextGapReason::ReadError,
            ),
            InputTextUnicodeRead::Saturated => reject(
                InputTextReadRejectionStage::UnicodeRead,
                InputTextReadRejectionReason::UnicodeSaturated,
                InputTextGapReason::Budget,
            ),
            InputTextUnicodeRead::Text(text) => {
                if utf16_len(&text) > InputTextLimits::code_unit_budget(policy) {
                    zeroize_string(text);
                    return reject(
                        InputTextReadRejectionStage::UnicodeRead,
                        InputTextReadRejectionReason::UnicodeBudget,
                        InputTextGapReason::Budget,
                    );
                }
                if InputTextLimits::filter_text_unit(&text).is_none() {
                    zeroize_string(text);
                    return InputTextCaptureDecision::Ignored;
                }
                InputTextCaptureDecision::Sample(Box::new(InputTextSample::ime_commit(
                    before.context,
                    text,
                    metadata.callback_time_ms,
                )))
            }
        }
    }

    /// Revalidates one frozen context prior to flush or barrier drain.
    pub fn revalidate_buffered_context<Now, Safety, OnRejection>(
        expected: &InputTextContext,
        policy: &CapturePolicy,
        now_ns: Now,
        mut typed_safety_provider: Safety,
        mut on_rejection: OnRejection,
    ) -> Result<InputTextContext, InputTextGapReason>
    where
        Now: Fn() -> u64,
        Safety: FnMut(InputTextSafetyRequest<'_>) -> Result<InputTextApprovedContext, InputTextGapReason>,
        OnRejection: FnMut(InputTextReadRejectionReason),
    {
        let started = now_ns();
        let approval = match typed_safety_provider(InputTextSafetyRequest::Flush(expected)) {
            Ok(value) => value,
            Err(reason) => {
                on_rejection(InputTextReadRejectionReason::SafetyUnavailable);
                return Err(reason);
            }
        };
        if approval.context != *expected {
            // Exact match precedes freshness: do not infer target mismatch from an unvalidated approval.
            on_rejection(InputTextReadRejectionReason::ContextChanged);
            return Err(InputTextGapReason::Stale);
        }
        if let Some(reason) =
            InputTextLimits::approval_rejection(&approval, started, now_ns(), policy)
        {
            on_rejection(InputTextReadRejectionReason::ApprovalNotFresh);
            return Err(reason);
        }
        Ok(approval.context)
    }

    /// Causal read-barrier drain:
    /// - Revalidates each distinct context across `completed` and `accumulator.pending()` ONCE.
    /// - Seals pending ahead of the enclosing snapshot without waiting for debounce.
    /// - Enforces backpressure (`> MAX_PENDING` (4) -> `InputTextGapReason::Backpressure`).
    /// - Enforces `remaining_text_budget_units` across drained records (`> budget` -> `Budget`).
    /// - On any failure, purges both `accumulator` and `completed` without emitting partial text.
    #[allow(clippy::too_many_arguments)]
    pub fn drain_at_barrier<Now, Safety, OnRejection>(
        completed: &mut Vec<InputTextRecord>,
        accumulator: &mut InputTextAccumulator,
        now_ms: i64,
        policy: &CapturePolicy,
        remaining_text_budget_units: usize,
        now_ns: Now,
        mut typed_safety_provider: Safety,
        mut on_rejection: OnRejection,
    ) -> Result<Vec<InputTextRecord>, InputTextGapReason>
    where
        Now: Fn() -> u64,
        Safety: FnMut(InputTextSafetyRequest<'_>) -> Result<InputTextApprovedContext, InputTextGapReason>,
        OnRejection: FnMut(InputTextReadRejectionReason),
    {
        let fail = |acc: &mut InputTextAccumulator,
                    done: &mut Vec<InputTextRecord>,
                    reason: InputTextGapReason| {
            acc.clear();
            for rec in done.drain(..) {
                zeroize_string(rec.text);
            }
            Err(reason)
        };

        if completed.is_empty() && accumulator.pending().is_none() {
            return Ok(Vec::new());
        }
        if completed.len() > InputTextLimits::MAX_PENDING {
            return fail(accumulator, completed, InputTextGapReason::Backpressure);
        }
        if !completed.iter().all(InputTextRecord::is_valid) {
            return fail(accumulator, completed, InputTextGapReason::ReadError);
        }
        let per_record_cap = InputTextLimits::code_unit_budget(policy);
        if completed.iter().any(|r| r.utf16_len() > per_record_cap) {
            return fail(accumulator, completed, InputTextGapReason::Budget);
        }
        if let Some(pending) = accumulator.pending() {
            if now_ms
                .checked_sub(pending.interval_end_ms)
                .is_none_or(|delta| delta < 0)
                || now_ms
                    .checked_sub(pending.interval_start_ms)
                    .is_none_or(|span| !(0..=InputTextLimits::MAX_INTERVAL_SPAN_MS).contains(&span))
            {
                return fail(accumulator, completed, InputTextGapReason::Stale);
            }
            if pending.utf16_len() > per_record_cap {
                return fail(accumulator, completed, InputTextGapReason::Budget);
            }
        }

        let mut candidate_contexts: Vec<InputTextContext> =
            Vec::with_capacity(completed.len() + usize::from(accumulator.pending().is_some()));
        for rec in completed.iter() {
            if !candidate_contexts.contains(&rec.context) {
                candidate_contexts.push(rec.context.clone());
            }
        }
        if let Some(pending) = accumulator.pending() {
            if !candidate_contexts.contains(&pending.context) {
                candidate_contexts.push(pending.context.clone());
            }
        }

        let mut approved_contexts = Vec::with_capacity(candidate_contexts.len());
        for ctx in &candidate_contexts {
            match Self::revalidate_buffered_context(
                ctx,
                policy,
                &now_ns,
                &mut typed_safety_provider,
                &mut on_rejection,
            ) {
                Ok(approved) => approved_contexts.push(approved),
                Err(reason) => return fail(accumulator, completed, reason),
            }
        }

        if let Some(pending_ctx) = accumulator.pending().map(|p| p.context.clone()) {
            if completed.len() >= InputTextLimits::MAX_PENDING {
                return fail(accumulator, completed, InputTextGapReason::Backpressure);
            }
            if !approved_contexts.contains(&pending_ctx) {
                return fail(accumulator, completed, InputTextGapReason::Stale);
            }
            let Some(sealed) = accumulator.take_at_barrier(now_ms, Some(&pending_ctx)) else {
                return fail(accumulator, completed, InputTextGapReason::Stale);
            };
            if !sealed.is_valid() {
                zeroize_string(sealed.text);
                return fail(accumulator, completed, InputTextGapReason::Stale);
            }
            completed.push(sealed);
        }

        let total_units: usize = completed
            .iter()
            .try_fold(0usize, |acc, r| acc.checked_add(r.utf16_len()))
            .unwrap_or(usize::MAX);
        if total_units > remaining_text_budget_units {
            return fail(accumulator, completed, InputTextGapReason::Budget);
        }

        Ok(std::mem::take(completed))
    }
}

/// Platform-free CJK IME composition coordinator handling TSF/UIA `Composition` start/update
/// (purging recent raw Latin prefix buffered within 500ms & suppressing Return) and gated
/// `CompositionFinalized` commits.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ImeCompositionState {
    composing: bool,
    started_at_ms: Option<i64>,
    last_update_ms: Option<i64>,
}

impl ImeCompositionState {
    pub const fn new() -> Self {
        Self {
            composing: false,
            started_at_ms: None,
            last_update_ms: None,
        }
    }

    /// Clears composition state on focus, window, epoch, policy, or desktop-lock boundaries.
    pub fn reset(&mut self) {
        self.composing = false;
        self.started_at_ms = None;
        self.last_update_ms = None;
    }

    /// Returns `true` when actively composing and within the 5-second safety decay window from
    /// both composition start and last update.
    pub fn is_composing(&self, now_ms: i64) -> bool {
        if !self.composing {
            return false;
        }
        let (Some(started), Some(last)) = (self.started_at_ms, self.last_update_ms) else {
            return false;
        };
        let since_start_ok = now_ms
            .checked_sub(started)
            .is_some_and(|elapsed| (0..=InputTextLimits::IME_COMPOSITION_MAX_MS).contains(&elapsed));
        let since_last_ok = now_ms
            .checked_sub(last)
            .is_some_and(|elapsed| (0..=InputTextLimits::IME_COMPOSITION_MAX_MS).contains(&elapsed));
        since_start_ok && since_last_ok
    }

    /// Refreshes the 5-second safety decay timer and returns whether composition is still active.
    pub fn refresh_decay(&mut self, now_ms: i64) -> bool {
        if !self.is_composing(now_ms) {
            self.reset();
            return false;
        }
        true
    }

    /// Returns `true` when raw keyboard translation (`ToUnicodeEx`) should be suppressed.
    pub fn should_suppress_raw_key(&mut self, now_ms: i64) -> bool {
        self.refresh_decay(now_ms)
    }

    /// Returns `true` when `VK_RETURN` should be suppressed (selecting a CJK candidate must not
    /// fire a false submit / `Return` observation).
    pub fn should_suppress_return(&mut self, now_ms: i64) -> bool {
        self.refresh_decay(now_ms)
    }

    /// Handles UIA/TSF `TextEditChangeType_Composition`:
    /// - Marks composition active (bounded by 5-second safety decay from start and last update).
    /// - Purges any raw keyboard-translated Latin prefix buffered in `accumulator.pending()` within
    ///   the last 500ms (never purging already-finalized IME commits).
    ///
    /// Returns `true` if a buffered raw prefix was purged.
    pub fn on_composition_start(
        &mut self,
        now_ms: i64,
        accumulator: &mut InputTextAccumulator,
    ) -> bool {
        if !self.is_composing(now_ms) {
            self.reset();
        }
        self.composing = true;
        if self.started_at_ms.is_none() {
            self.started_at_ms = Some(now_ms);
        }
        self.last_update_ms = Some(now_ms);

        let should_purge = accumulator.pending().is_some_and(|pending| {
            let is_ime_commit = pending
                .extra_coverage_reasons
                .iter()
                .any(|r| r == "ime-composition-commit");
            let within_purge_window = match now_ms.checked_sub(pending.interval_end_ms) {
                Some(elapsed) => elapsed <= InputTextLimits::IME_PREFIX_PURGE_WINDOW_MS,
                None => now_ms < pending.interval_end_ms,
            };
            pending.event_kind == InputTextKind::Text && !is_ime_commit && within_purge_window
        });
        if should_purge {
            accumulator.clear();
            return true;
        }
        false
    }

    /// Handles UIA/TSF `TextEditChangeType_CompositionFinalized`:
    /// - Ends composition state immediately.
    /// - Runs full Pre-Gate -> Read Committed -> Post-Gate via `InputTextReadGate::capture_ime_commit`
    ///   so pre-gate failures never read committed BSTRs and post-gate mismatches discard text.
    #[allow(clippy::too_many_arguments)]
    pub fn on_composition_finalized<Now, Safety, ReadCommitted, OnRejection>(
        &mut self,
        metadata: InputTextEventMetadata,
        policy: &CapturePolicy,
        after_ns: u64,
        now_ns: Now,
        typed_safety_provider: Safety,
        read_committed: ReadCommitted,
        on_rejection: OnRejection,
    ) -> InputTextCaptureDecision
    where
        Now: Fn() -> u64,
        Safety: FnMut(InputTextSafetyRequest<'_>) -> Result<InputTextApprovedContext, InputTextGapReason>,
        ReadCommitted: FnOnce() -> InputTextUnicodeRead,
        OnRejection: FnMut(InputTextReadRejection),
    {
        self.reset();
        InputTextReadGate::capture_ime_commit(
            metadata,
            policy,
            after_ns,
            now_ns,
            typed_safety_provider,
            read_committed,
            on_rejection,
        )
    }
}
