use std::collections::{BTreeMap, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};

use history_contract::{utf16_len, ContractLimits, JsonValue};
use windows::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};
use windows::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};

pub const MAX_SAFE_INTEGER: i64 = ContractLimits::MAX_SAFE_INTEGER_I64;

/// System-wide monotonic and wall-clock time source shared across parent and worker processes.
pub trait CollectorClock: Send + Sync {
    fn monotonic_ms(&self) -> i64;
    fn unix_ms(&self) -> i64;
}

/// Real Windows clock using system-wide QPC (1ms precision, consistent across processes)
/// and `SystemTime` for Unix epoch milliseconds.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemCollectorClock;

impl SystemCollectorClock {
    pub fn monotonic_ms_now() -> i64 {
        let mut freq: i64 = 0;
        let mut counter: i64 = 0;
        // SAFETY: QueryPerformanceFrequency and QueryPerformanceCounter always succeed on Windows XP+.
        unsafe {
            let _ = QueryPerformanceFrequency(&mut freq);
            let _ = QueryPerformanceCounter(&mut counter);
        }
        if freq <= 0 || counter < 0 {
            return 0;
        }
        ((counter as u128 * 1_000) / (freq as u128)) as i64
    }

    pub fn unix_ms_now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }
}

impl CollectorClock for SystemCollectorClock {
    fn monotonic_ms(&self) -> i64 {
        Self::monotonic_ms_now()
    }

    fn unix_ms(&self) -> i64 {
        Self::unix_ms_now()
    }
}

/// Generate a cryptographically random RFC 4122 UUIDv4 (36 ASCII chars) using Win32 BCryptGenRandom.
pub fn generate_uuid_v4() -> String {
    let mut bytes = [0u8; 16];
    // SAFETY: Valid mutable buffer with system-preferred CSPRNG flag.
    let status = unsafe { BCryptGenRandom(None, &mut bytes, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    if status.is_err() {
        // Fallback entropy only if BCrypt fails unexpectedly (should never happen on Windows 10/11).
        let t = SystemCollectorClock::monotonic_ms_now() as u64;
        let u = SystemCollectorClock::unix_ms_now() as u64;
        let p = std::process::id() as u64;
        let a = t ^ (p << 32) ^ 0x9e37_79b9_7f4a_7c15;
        let b = u.wrapping_mul(0x517c_c1b7_2722_0a95) ^ a.rotate_left(17);
        bytes[..8].copy_from_slice(&a.to_le_bytes());
        bytes[8..].copy_from_slice(&b.to_le_bytes());
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

pub fn json_i64(v: i64) -> JsonValue {
    JsonValue::Number(v as f64)
}

pub fn json_usize(v: usize) -> JsonValue {
    JsonValue::Number(v as f64)
}

pub fn json_u32(v: u32) -> JsonValue {
    JsonValue::Number(v as f64)
}

pub fn json_text_range(start: usize, length: usize) -> JsonValue {
    let mut map = BTreeMap::new();
    map.insert("unit".to_string(), JsonValue::String("utf16".to_string()));
    map.insert("start".to_string(), json_usize(start));
    map.insert("length".to_string(), json_usize(length));
    JsonValue::Object(map)
}

/// Pure bounded UTF-16 slice that never bisects a surrogate pair.
pub fn bounded_utf16_slice(text: &str, start: usize, length: usize) -> Option<String> {
    let units: Vec<u16> = text.encode_utf16().collect();
    if start > units.len() || length > units.len().saturating_sub(start) {
        return None;
    }
    if start < units.len() && (0xDC00..=0xDFFF).contains(&units[start]) {
        return None;
    }
    let mut end = start + length;
    if end > start && (0xD800..=0xDBFF).contains(&units[end - 1]) {
        end -= 1;
    }
    String::from_utf16(&units[start..end]).ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopStatus {
    Unlocked,
    Locked,
    Unknown,
}

impl DesktopStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unlocked => "unlocked",
            Self::Locked => "locked",
            Self::Unknown => "unknown",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "unlocked" => Some(Self::Unlocked),
            "locked" => Some(Self::Locked),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureStatus {
    Safe,
    NotDeclaredSensitive,
    Sensitive,
    Unknown,
}

impl SecureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Safe => "safe",
            Self::NotDeclaredSensitive => "not-declared-sensitive",
            Self::Sensitive => "sensitive",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturePolicy {
    pub enabled: bool,
    pub input_activity: Option<bool>,
    pub text_range: Option<String>,
    pub sample_interval_ms: Option<i64>,
    pub allowed_application_ids: Vec<String>,
    pub application_scope: Option<String>,
    pub excluded_application_ids: Option<Vec<String>>,
    pub allow_browser_content: Option<bool>,
    pub ax_compatibility: Option<bool>,
    pub text_markers: Option<bool>,
    pub capture_scope: Option<String>,
    pub max_tree_nodes: Option<usize>,
    pub input_text: Option<bool>,
    pub selection_capture: Option<bool>,
    pub menu_actions: Option<bool>,
    pub field_security: Option<String>,
    pub max_text_code_units: usize,
    pub max_pending: usize,
    pub debounce_ms: i64,
    pub max_wait_ms: i64,
    pub read_timeout_ms: i64,
}

impl Default for CapturePolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            input_activity: Some(false),
            text_range: None,
            sample_interval_ms: None,
            allowed_application_ids: vec!["test.allowed".to_string()],
            application_scope: None,
            excluded_application_ids: None,
            allow_browser_content: None,
            ax_compatibility: None,
            text_markers: None,
            capture_scope: None,
            max_tree_nodes: None,
            input_text: None,
            selection_capture: None,
            menu_actions: None,
            field_security: None,
            max_text_code_units: 128,
            max_pending: 8,
            debounce_ms: 10,
            max_wait_ms: 50,
            read_timeout_ms: 200,
        }
    }
}

impl CapturePolicy {
    pub fn from_json(value: &JsonValue) -> Option<Self> {
        let obj = value.as_obj()?;
        let enabled = obj.get("enabled")?.as_bool()?;
        let allowed_raw = obj.get("allowedApplicationIds")?.as_array()?;
        let mut allowed_application_ids = Vec::with_capacity(allowed_raw.len());
        for item in allowed_raw {
            allowed_application_ids.push(item.as_str()?.to_string());
        }
        let excluded_application_ids = match obj.get("excludedApplicationIds") {
            None | Some(JsonValue::Null) => None,
            Some(v) => {
                let arr = v.as_array()?;
                let mut list = Vec::with_capacity(arr.len());
                for item in arr {
                    list.push(item.as_str()?.to_string());
                }
                Some(list)
            }
        };
        let opt_bool = |k: &str| -> Result<Option<bool>, ()> {
            match obj.get(k) {
                None | Some(JsonValue::Null) => Ok(None),
                Some(v) => v.as_bool().map(Some).ok_or(()),
            }
        };
        let opt_str = |k: &str| -> Result<Option<String>, ()> {
            match obj.get(k) {
                None | Some(JsonValue::Null) => Ok(None),
                Some(v) => v.as_str().map(|s| Some(s.to_string())).ok_or(()),
            }
        };
        let opt_i64 = |k: &str| -> Result<Option<i64>, ()> {
            match obj.get(k) {
                None | Some(JsonValue::Null) => Ok(None),
                Some(v) => v.as_i64().map(Some).ok_or(()),
            }
        };

        let max_text_code_units = usize::try_from(obj.get("maxTextCodeUnits")?.as_u64()?).ok()?;
        let max_pending = usize::try_from(obj.get("maxPending")?.as_u64()?).ok()?;
        let debounce_ms = obj.get("debounceMs")?.as_i64()?;
        let max_wait_ms = obj.get("maxWaitMs")?.as_i64()?;
        let read_timeout_ms = obj.get("readTimeoutMs")?.as_i64()?;

        let max_tree_nodes = match opt_i64("maxTreeNodes").ok()? {
            None => None,
            Some(n) if n >= 0 => Some(usize::try_from(n).ok()?),
            Some(_) => return None,
        };

        Some(Self {
            enabled,
            input_activity: opt_bool("inputActivity").ok()?,
            text_range: opt_str("textRange").ok()?,
            sample_interval_ms: opt_i64("sampleIntervalMs").ok()?,
            allowed_application_ids,
            application_scope: opt_str("applicationScope").ok()?,
            excluded_application_ids,
            allow_browser_content: opt_bool("allowBrowserContent").ok()?,
            ax_compatibility: opt_bool("axCompatibility").ok()?,
            text_markers: opt_bool("textMarkers").ok()?,
            capture_scope: opt_str("captureScope").ok()?,
            max_tree_nodes,
            input_text: opt_bool("inputText").ok()?,
            selection_capture: opt_bool("selectionCapture").ok()?,
            menu_actions: opt_bool("menuActions").ok()?,
            field_security: opt_str("fieldSecurity").ok()?,
            max_text_code_units,
            max_pending,
            debounce_ms,
            max_wait_ms,
            read_timeout_ms,
        })
    }

    pub fn to_json(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("enabled".to_string(), JsonValue::Bool(self.enabled));
        if let Some(v) = self.input_activity {
            map.insert("inputActivity".to_string(), JsonValue::Bool(v));
        }
        if let Some(ref v) = self.text_range {
            map.insert("textRange".to_string(), JsonValue::String(v.clone()));
        }
        if let Some(v) = self.sample_interval_ms {
            map.insert("sampleIntervalMs".to_string(), json_i64(v));
        }
        map.insert(
            "allowedApplicationIds".to_string(),
            JsonValue::Array(
                self.allowed_application_ids
                    .iter()
                    .cloned()
                    .map(JsonValue::String)
                    .collect(),
            ),
        );
        if let Some(ref v) = self.application_scope {
            map.insert("applicationScope".to_string(), JsonValue::String(v.clone()));
        }
        if let Some(ref list) = self.excluded_application_ids {
            map.insert(
                "excludedApplicationIds".to_string(),
                JsonValue::Array(list.iter().cloned().map(JsonValue::String).collect()),
            );
        }
        if let Some(v) = self.allow_browser_content {
            map.insert("allowBrowserContent".to_string(), JsonValue::Bool(v));
        }
        if let Some(v) = self.ax_compatibility {
            map.insert("axCompatibility".to_string(), JsonValue::Bool(v));
        }
        if let Some(v) = self.text_markers {
            map.insert("textMarkers".to_string(), JsonValue::Bool(v));
        }
        if let Some(ref v) = self.capture_scope {
            map.insert("captureScope".to_string(), JsonValue::String(v.clone()));
        }
        if let Some(v) = self.max_tree_nodes {
            map.insert("maxTreeNodes".to_string(), json_usize(v));
        }
        if let Some(v) = self.input_text {
            map.insert("inputText".to_string(), JsonValue::Bool(v));
        }
        if let Some(v) = self.selection_capture {
            map.insert("selectionCapture".to_string(), JsonValue::Bool(v));
        }
        if let Some(v) = self.menu_actions {
            map.insert("menuActions".to_string(), JsonValue::Bool(v));
        }
        if let Some(ref v) = self.field_security {
            map.insert("fieldSecurity".to_string(), JsonValue::String(v.clone()));
        }
        map.insert(
            "maxTextCodeUnits".to_string(),
            json_usize(self.max_text_code_units),
        );
        map.insert("maxPending".to_string(), json_usize(self.max_pending));
        map.insert("debounceMs".to_string(), json_i64(self.debounce_ms));
        map.insert("maxWaitMs".to_string(), json_i64(self.max_wait_ms));
        map.insert("readTimeoutMs".to_string(), json_i64(self.read_timeout_ms));
        JsonValue::Object(map)
    }

    pub fn has_valid_text_settings(&self) -> bool {
        let range_ok = matches!(self.text_range.as_deref(), None | Some("prefix") | Some("visible"));
        let interval_ok = self
            .sample_interval_ms
            .map(|v| (1_000..=30_000).contains(&v))
            .unwrap_or(true);
        let app_scope_ok = matches!(
            self.application_scope.as_deref(),
            None | Some("allowlist") | Some("denylist")
        );
        let cap_scope_ok = matches!(
            self.capture_scope.as_deref(),
            None | Some("focused") | Some("region") | Some("window")
        );
        let field_sec_ok = matches!(
            self.field_security.as_deref(),
            None | Some("strict") | Some("denylist")
        );
        let nodes_ok = self
            .max_tree_nodes
            .map(|v| (1..=96).contains(&v))
            .unwrap_or(true);
        let budget_ok = (1..=8_192).contains(&self.max_text_code_units)
            && (1..=64).contains(&self.max_pending)
            && (0..=2_000).contains(&self.debounce_ms)
            && (1..=5_000).contains(&self.max_wait_ms)
            && self.max_wait_ms >= self.debounce_ms
            && (1..=5_000).contains(&self.read_timeout_ms);
        range_ok
            && interval_ok
            && app_scope_ok
            && cap_scope_ok
            && field_sec_ok
            && nodes_ok
            && budget_ok
    }

    pub fn field_security_mode(&self) -> &str {
        self.field_security.as_deref().unwrap_or("strict")
    }

    pub fn allows_secure(&self, status: SecureStatus) -> bool {
        let mode = self.field_security_mode();
        if mode != "strict" && mode != "denylist" {
            return false;
        }
        status == SecureStatus::Safe
            || (mode == "denylist" && status == SecureStatus::NotDeclaredSensitive)
    }

    pub fn content_gate_secure(&self) -> &'static str {
        if self.field_security_mode() == "denylist" {
            SecureStatus::NotDeclaredSensitive.as_str()
        } else {
            SecureStatus::Safe.as_str()
        }
    }

    pub fn uses_session_worker(&self) -> bool {
        self.ax_compatibility == Some(true)
            || self.text_markers == Some(true)
            || self.input_text == Some(true)
            || self.selection_capture == Some(true)
            || self.menu_actions == Some(true)
            || matches!(self.capture_scope.as_deref(), Some("region") | Some("window"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stamp {
    pub capture_epoch: i64,
    pub foreground_generation: i64,
    pub focus_generation: i64,
    pub policy_revision: i64,
}

impl Stamp {
    pub fn to_json(self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("captureEpoch".to_string(), json_i64(self.capture_epoch));
        map.insert(
            "foregroundGeneration".to_string(),
            json_i64(self.foreground_generation),
        );
        map.insert("focusGeneration".to_string(), json_i64(self.focus_generation));
        map.insert("policyRevision".to_string(), json_i64(self.policy_revision));
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationIdentity {
    pub application_id: String,
    pub process_id: u32,
    pub process_start_time: String,
}

impl ApplicationIdentity {
    pub fn from_json(value: &JsonValue) -> Option<Self> {
        let obj = value.as_obj()?;
        let application_id = obj.get("applicationId")?.as_str()?.to_string();
        let pid = obj.get("processId")?.as_u64()?;
        if pid == 0 || pid > i32::MAX as u64 {
            return None;
        }
        let process_start_time = obj.get("processStartTime")?.as_str()?.to_string();
        Some(Self {
            application_id,
            process_id: pid as u32,
            process_start_time,
        })
    }

    pub fn to_json(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert(
            "applicationId".to_string(),
            JsonValue::String(self.application_id.clone()),
        );
        map.insert("processId".to_string(), json_u32(self.process_id));
        map.insert(
            "processStartTime".to_string(),
            JsonValue::String(self.process_start_time.clone()),
        );
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationTargetIdentity {
    pub device_id: String,
    pub os_session_id: String,
    pub desktop_id: String,
    pub process_id: u32,
    pub process_start_time: String,
    pub application_id: String,
}

impl ApplicationTargetIdentity {
    pub fn to_json(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("deviceId".to_string(), JsonValue::String(self.device_id.clone()));
        map.insert(
            "osSessionId".to_string(),
            JsonValue::String(self.os_session_id.clone()),
        );
        map.insert("desktopId".to_string(), JsonValue::String(self.desktop_id.clone()));
        map.insert("processId".to_string(), json_u32(self.process_id));
        map.insert(
            "processStartTime".to_string(),
            JsonValue::String(self.process_start_time.clone()),
        );
        map.insert(
            "applicationId".to_string(),
            JsonValue::String(self.application_id.clone()),
        );
        JsonValue::Object(map)
    }

    pub fn to_target_ref(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("kind".to_string(), JsonValue::String("application".to_string()));
        map.insert("identity".to_string(), self.to_json());
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetIdentity {
    pub device_id: String,
    pub os_session_id: String,
    pub desktop_id: String,
    pub process_id: u32,
    pub process_start_time: String,
    pub application_id: String,
    pub window_id: String,
    pub window_generation: i64,
}

impl TargetIdentity {
    pub fn to_json(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("deviceId".to_string(), JsonValue::String(self.device_id.clone()));
        map.insert(
            "osSessionId".to_string(),
            JsonValue::String(self.os_session_id.clone()),
        );
        map.insert("desktopId".to_string(), JsonValue::String(self.desktop_id.clone()));
        map.insert("processId".to_string(), json_u32(self.process_id));
        map.insert(
            "processStartTime".to_string(),
            JsonValue::String(self.process_start_time.clone()),
        );
        map.insert(
            "applicationId".to_string(),
            JsonValue::String(self.application_id.clone()),
        );
        map.insert("windowId".to_string(), JsonValue::String(self.window_id.clone()));
        map.insert(
            "windowGeneration".to_string(),
            json_i64(self.window_generation),
        );
        JsonValue::Object(map)
    }

    pub fn to_target_ref(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("kind".to_string(), JsonValue::String("resolved".to_string()));
        map.insert("identity".to_string(), self.to_json());
        JsonValue::Object(map)
    }
}

pub fn unresolved_target(reason: &str) -> JsonValue {
    let mut map = BTreeMap::new();
    map.insert("kind".to_string(), JsonValue::String("unresolved".to_string()));
    map.insert("reason".to_string(), JsonValue::String(reason.to_string()));
    JsonValue::Object(map)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceHint {
    pub application: ApplicationIdentity,
    pub event_time_ms: i64,
}

impl SourceHint {
    pub fn from_json(value: &JsonValue) -> Option<Self> {
        let obj = value.as_obj()?;
        let application = ApplicationIdentity::from_json(obj.get("application")?)?;
        let event_time_ms = obj.get("eventTimeMs")?.as_i64()?;
        Some(Self {
            application,
            event_time_ms,
        })
    }

    pub fn to_json(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("application".to_string(), self.application.to_json());
        map.insert("eventTimeMs".to_string(), json_i64(self.event_time_ms));
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextSelection {
    pub start: usize,
    pub length: usize,
}

impl TextSelection {
    pub fn new(start: usize, length: usize) -> Self {
        Self { start, length }
    }

    pub fn from_json(value: &JsonValue) -> Option<Self> {
        let obj = value.as_obj()?;
        let start = usize::try_from(obj.get("start")?.as_u64()?).ok()?;
        let length = usize::try_from(obj.get("length")?.as_u64()?).ok()?;
        Some(Self { start, length })
    }

    pub fn to_json(self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("start".to_string(), json_usize(self.start));
        map.insert("length".to_string(), json_usize(self.length));
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentGate {
    pub secure: String,
    pub private_state: String,
    pub policy_revision: i64,
}

impl ContentGate {
    pub fn to_json(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("secure".to_string(), JsonValue::String(self.secure.clone()));
        map.insert(
            "privateState".to_string(),
            JsonValue::String(self.private_state.clone()),
        );
        map.insert(
            "policyRevision".to_string(),
            json_i64(self.policy_revision),
        );
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coverage {
    pub status: String,
    pub truncated: bool,
    pub missing_reasons: Vec<String>,
}

impl Coverage {
    pub fn to_json(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("status".to_string(), JsonValue::String(self.status.clone()));
        map.insert("truncated".to_string(), JsonValue::Bool(self.truncated));
        map.insert(
            "missingReasons".to_string(),
            JsonValue::Array(
                self.missing_reasons
                    .iter()
                    .cloned()
                    .map(JsonValue::String)
                    .collect(),
            ),
        );
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GapDiagnosticCode {
    ApplicationNotAllowed,
    ApplicationUnavailable,
    BrowserExcluded,
    FocusedFieldUnavailable,
    FocusedRoleNotText,
    SecureField,
    FieldSecurityUnknown,
    VisibleRangeUnavailable,
    TextReadUnavailable,
    TextResultInvalid,
    FocusChanged,
    InvalidSamplingPolicy,
    ReadDeadline,
    AccessibilityDenied,
    DesktopUnavailable,
    InputContextUnverified,
    InputTargetMismatch,
    InputRoleNotEditable,
    InputVerificationTimeout,
    InputFieldSecurityUnknown,
    InputTextBudget,
    InputTextBackpressure,
    InputTextReadUnavailable,
    InputPolicyBoundary,
    CaptureAuthorityChanged,
    WorkerRetirementPending,
    SurfaceNotStartedBudget,
    SurfaceCallBudget,
    SurfaceTimeBudget,
    SurfaceAnchorUnavailable,
    SurfaceBoundaryUnverified,
    SurfaceBoundaryMismatch,
    SurfaceBoundaryAxFailed,
    SurfaceBoundaryIncomplete,
    SurfaceSecurityExcluded,
    SurfaceProviderUnavailable,
}

impl GapDiagnosticCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ApplicationNotAllowed => "application-not-allowed",
            Self::ApplicationUnavailable => "application-unavailable",
            Self::BrowserExcluded => "browser-excluded",
            Self::FocusedFieldUnavailable => "focused-field-unavailable",
            Self::FocusedRoleNotText => "focused-role-not-text",
            Self::SecureField => "secure-field",
            Self::FieldSecurityUnknown => "field-security-unknown",
            Self::VisibleRangeUnavailable => "visible-range-unavailable",
            Self::TextReadUnavailable => "text-read-unavailable",
            Self::TextResultInvalid => "text-result-invalid",
            Self::FocusChanged => "focus-changed",
            Self::InvalidSamplingPolicy => "invalid-sampling-policy",
            Self::ReadDeadline => "read-deadline",
            Self::AccessibilityDenied => "accessibility-denied",
            Self::DesktopUnavailable => "desktop-unavailable",
            Self::InputContextUnverified => "input-context-unverified",
            Self::InputTargetMismatch => "input-target-mismatch",
            Self::InputRoleNotEditable => "input-role-not-editable",
            Self::InputVerificationTimeout => "input-verification-timeout",
            Self::InputFieldSecurityUnknown => "input-field-security-unknown",
            Self::InputTextBudget => "input-text-budget",
            Self::InputTextBackpressure => "input-text-backpressure",
            Self::InputTextReadUnavailable => "input-text-read-unavailable",
            Self::InputPolicyBoundary => "input-policy-boundary",
            Self::CaptureAuthorityChanged => "capture-authority-changed",
            Self::WorkerRetirementPending => "worker-retirement-pending",
            Self::SurfaceNotStartedBudget => "surface-not-started-budget",
            Self::SurfaceCallBudget => "surface-call-budget",
            Self::SurfaceTimeBudget => "surface-time-budget",
            Self::SurfaceAnchorUnavailable => "surface-anchor-unavailable",
            Self::SurfaceBoundaryUnverified => "surface-boundary-unverified",
            Self::SurfaceBoundaryMismatch => "surface-boundary-mismatch",
            Self::SurfaceBoundaryAxFailed => "surface-boundary-ax-failed",
            Self::SurfaceBoundaryIncomplete => "surface-boundary-incomplete",
            Self::SurfaceSecurityExcluded => "surface-security-excluded",
            Self::SurfaceProviderUnavailable => "surface-provider-unavailable",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "application-not-allowed" => Some(Self::ApplicationNotAllowed),
            "application-unavailable" => Some(Self::ApplicationUnavailable),
            "browser-excluded" => Some(Self::BrowserExcluded),
            "focused-field-unavailable" => Some(Self::FocusedFieldUnavailable),
            "focused-role-not-text" => Some(Self::FocusedRoleNotText),
            "secure-field" => Some(Self::SecureField),
            "field-security-unknown" => Some(Self::FieldSecurityUnknown),
            "visible-range-unavailable" => Some(Self::VisibleRangeUnavailable),
            "text-read-unavailable" => Some(Self::TextReadUnavailable),
            "text-result-invalid" => Some(Self::TextResultInvalid),
            "focus-changed" => Some(Self::FocusChanged),
            "invalid-sampling-policy" => Some(Self::InvalidSamplingPolicy),
            "read-deadline" => Some(Self::ReadDeadline),
            "accessibility-denied" => Some(Self::AccessibilityDenied),
            "desktop-unavailable" => Some(Self::DesktopUnavailable),
            "input-context-unverified" => Some(Self::InputContextUnverified),
            "input-target-mismatch" => Some(Self::InputTargetMismatch),
            "input-role-not-editable" => Some(Self::InputRoleNotEditable),
            "input-verification-timeout" => Some(Self::InputVerificationTimeout),
            "input-field-security-unknown" => Some(Self::InputFieldSecurityUnknown),
            "input-text-budget" => Some(Self::InputTextBudget),
            "input-text-backpressure" => Some(Self::InputTextBackpressure),
            "input-text-read-unavailable" => Some(Self::InputTextReadUnavailable),
            "input-policy-boundary" => Some(Self::InputPolicyBoundary),
            "capture-authority-changed" => Some(Self::CaptureAuthorityChanged),
            "worker-retirement-pending" => Some(Self::WorkerRetirementPending),
            "surface-not-started-budget" => Some(Self::SurfaceNotStartedBudget),
            "surface-call-budget" => Some(Self::SurfaceCallBudget),
            "surface-time-budget" => Some(Self::SurfaceTimeBudget),
            "surface-anchor-unavailable" => Some(Self::SurfaceAnchorUnavailable),
            "surface-boundary-unverified" => Some(Self::SurfaceBoundaryUnverified),
            "surface-boundary-mismatch" => Some(Self::SurfaceBoundaryMismatch),
            "surface-boundary-ax-failed" => Some(Self::SurfaceBoundaryAxFailed),
            "surface-boundary-incomplete" => Some(Self::SurfaceBoundaryIncomplete),
            "surface-security-excluded" => Some(Self::SurfaceSecurityExcluded),
            "surface-provider-unavailable" => Some(Self::SurfaceProviderUnavailable),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GapDiagnostic {
    pub code: GapDiagnosticCode,
    pub role: Option<&'static str>,
}

impl GapDiagnostic {
    pub fn new(code: GapDiagnosticCode, role: Option<&str>) -> Self {
        Self {
            code,
            role: role.map(|r| crate::policy::normalize_gap_role(Some(r))),
        }
    }

    pub fn from_json(value: &JsonValue) -> Option<Self> {
        let obj = value.as_obj()?;
        let code = GapDiagnosticCode::parse(obj.get("code")?.as_str()?)?;
        let role = match obj.get("role") {
            None | Some(JsonValue::Null) => None,
            Some(v) => Some(crate::policy::normalize_gap_role(Some(v.as_str()?))),
        };
        Some(Self { code, role })
    }

    pub fn to_json(self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert(
            "code".to_string(),
            JsonValue::String(self.code.as_str().to_string()),
        );
        if let Some(role) = self.role {
            map.insert("role".to_string(), JsonValue::String(role.to_string()));
        }
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SurfaceBounds {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

impl SurfaceBounds {
    pub fn new(x: f64, y: f64, width: f64, height: f64) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.x.is_finite()
            && self.y.is_finite()
            && self.x.abs() <= 1_000_000.0
            && self.y.abs() <= 1_000_000.0
            && SurfaceWindowSize::new(self.width, self.height).is_valid()
    }

    pub fn from_json(value: &JsonValue) -> Option<Self> {
        let obj = value.as_obj()?;
        let b = Self {
            x: obj.get("x")?.as_f64()?,
            y: obj.get("y")?.as_f64()?,
            width: obj.get("width")?.as_f64()?,
            height: obj.get("height")?.as_f64()?,
        };
        b.is_valid().then_some(b)
    }

    pub fn to_json(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("x".to_string(), JsonValue::Number(self.x));
        map.insert("y".to_string(), JsonValue::Number(self.y));
        map.insert("width".to_string(), JsonValue::Number(self.width));
        map.insert("height".to_string(), JsonValue::Number(self.height));
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SurfaceWindowSize {
    pub width: f64,
    pub height: f64,
}

impl SurfaceWindowSize {
    pub fn new(width: f64, height: f64) -> Self {
        Self { width, height }
    }

    pub fn is_valid(&self) -> bool {
        self.width.is_finite()
            && self.height.is_finite()
            && self.width >= 0.0
            && self.height >= 0.0
            && self.width <= 1_000_000.0
            && self.height <= 1_000_000.0
    }

    pub fn from_json(value: &JsonValue) -> Option<Self> {
        let obj = value.as_obj()?;
        let s = Self {
            width: obj.get("width")?.as_f64()?,
            height: obj.get("height")?.as_f64()?,
        };
        s.is_valid().then_some(s)
    }

    pub fn to_json(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("width".to_string(), JsonValue::Number(self.width));
        map.insert("height".to_string(), JsonValue::Number(self.height));
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SurfaceGeometry {
    pub coordinate_space: String,
    pub window_size: SurfaceWindowSize,
    pub observed_at_ms: i64,
}

impl SurfaceGeometry {
    pub const COORDINATE_SPACE: &'static str = "window-top-left-point";

    pub fn new(window_size: SurfaceWindowSize, observed_at_ms: i64) -> Self {
        Self {
            coordinate_space: Self::COORDINATE_SPACE.to_string(),
            window_size,
            observed_at_ms,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.coordinate_space == Self::COORDINATE_SPACE
            && self.window_size.is_valid()
            && self.observed_at_ms >= 0
    }

    pub fn from_json(value: &JsonValue) -> Option<Self> {
        let obj = value.as_obj()?;
        let coordinate_space = obj.get("coordinateSpace")?.as_str()?.to_string();
        let window_size = SurfaceWindowSize::from_json(obj.get("windowSize")?)?;
        let observed_at_ms = obj.get("observedAtMs")?.as_i64()?;
        let g = Self {
            coordinate_space,
            window_size,
            observed_at_ms,
        };
        g.is_valid().then_some(g)
    }

    pub fn to_json(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert(
            "coordinateSpace".to_string(),
            JsonValue::String(self.coordinate_space.clone()),
        );
        map.insert("windowSize".to_string(), self.window_size.to_json());
        map.insert("observedAtMs".to_string(), json_i64(self.observed_at_ms));
        JsonValue::Object(map)
    }
}

/// Ephemeral absolute desktop rectangle (logical points). Never serialized over the wire.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SurfaceAbsoluteRect {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

impl SurfaceAbsoluteRect {
    pub fn new(x: f64, y: f64, width: f64, height: f64) -> Option<Self> {
        if !SurfaceBounds::new(x, y, width, height).is_valid() {
            return None;
        }
        Some(Self {
            x,
            y,
            width,
            height,
        })
    }

    /// Convert physical screen pixels (from Win32/UIA) to logical points using window DPI.
    pub fn from_physical_pixels(x: f64, y: f64, width: f64, height: f64, dpi: u32) -> Option<Self> {
        let scale = if dpi > 0 { 96.0 / (dpi as f64) } else { 1.0 };
        Self::new(x * scale, y * scale, width * scale, height * scale)
    }

    pub fn relative_to(&self, window: SurfaceAbsoluteRect) -> Option<SurfaceBounds> {
        let bounds = SurfaceBounds::new(
            self.x - window.x,
            self.y - window.y,
            self.width,
            self.height,
        );
        bounds.is_valid().then_some(bounds)
    }

    pub fn geometry_if_unchanged(
        &self,
        final_rect: Option<SurfaceAbsoluteRect>,
        observed_at_ms: i64,
    ) -> Option<SurfaceGeometry> {
        if final_rect == Some(*self) && observed_at_ms >= 0 {
            Some(SurfaceGeometry::new(
                SurfaceWindowSize::new(self.width, self.height),
                observed_at_ms,
            ))
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SurfaceNode {
    pub id: String,
    pub parent_id: Option<String>,
    pub role: String,
    pub text: Option<String>,
    pub observed_at_ms: i64,
    pub bounds: Option<SurfaceBounds>,
    pub bounds_observed_at_ms: Option<i64>,
    pub ax_role: Option<String>,
    pub focused: Option<bool>,
}

impl SurfaceNode {
    pub fn from_json(value: &JsonValue) -> Option<Self> {
        let obj = value.as_obj()?;
        let id = obj.get("id")?.as_str()?.to_string();
        let parent_id = match obj.get("parentId") {
            None | Some(JsonValue::Null) => None,
            Some(v) => Some(v.as_str()?.to_string()),
        };
        let role = obj.get("role")?.as_str()?.to_string();
        let text = match obj.get("text") {
            None | Some(JsonValue::Null) => None,
            Some(v) => Some(v.as_str()?.to_string()),
        };
        let observed_at_ms = obj.get("observedAtMs")?.as_i64()?;
        let bounds = match obj.get("bounds") {
            None | Some(JsonValue::Null) => None,
            Some(v) => Some(SurfaceBounds::from_json(v)?),
        };
        let bounds_observed_at_ms = match obj.get("boundsObservedAtMs") {
            None | Some(JsonValue::Null) => None,
            Some(v) => Some(v.as_i64()?),
        };
        let ax_role = match obj.get("axRole") {
            None | Some(JsonValue::Null) => None,
            Some(v) => Some(v.as_str()?.to_string()),
        };
        let focused = match obj.get("focused") {
            None | Some(JsonValue::Null) => None,
            Some(v) => Some(v.as_bool()?),
        };
        Some(Self {
            id,
            parent_id,
            role,
            text,
            observed_at_ms,
            bounds,
            bounds_observed_at_ms,
            ax_role,
            focused,
        })
    }

    pub fn to_json(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("id".to_string(), JsonValue::String(self.id.clone()));
        if let Some(ref parent_id) = self.parent_id {
            map.insert("parentId".to_string(), JsonValue::String(parent_id.clone()));
        }
        map.insert("role".to_string(), JsonValue::String(self.role.clone()));
        if let Some(ref text) = self.text {
            map.insert("text".to_string(), JsonValue::String(text.clone()));
        }
        map.insert("observedAtMs".to_string(), json_i64(self.observed_at_ms));
        if let Some(ref bounds) = self.bounds {
            map.insert("bounds".to_string(), bounds.to_json());
        }
        if let Some(t) = self.bounds_observed_at_ms {
            map.insert("boundsObservedAtMs".to_string(), json_i64(t));
        }
        if let Some(ref ax_role) = self.ax_role {
            map.insert("axRole".to_string(), JsonValue::String(ax_role.clone()));
        }
        if let Some(focused) = self.focused {
            map.insert("focused".to_string(), JsonValue::Bool(focused));
        }
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SurfaceReadResult {
    pub surface_id: String,
    pub revision: i64,
    pub scope: String,
    pub mode: String,
    pub nodes: Vec<SurfaceNode>,
    pub base_revision: Option<i64>,
    pub added: Vec<String>,
    pub updated: Vec<String>,
    pub removed: Vec<String>,
    pub truncated: bool,
    pub missing_reasons: Vec<String>,
    pub complete: bool,
    pub geometry: Option<SurfaceGeometry>,
}

impl SurfaceReadResult {
    pub fn from_json(value: &JsonValue) -> Option<Self> {
        let obj = value.as_obj()?;
        let surface_id = obj.get("surfaceId")?.as_str()?.to_string();
        let revision = obj.get("revision")?.as_i64()?;
        let scope = obj.get("scope")?.as_str()?.to_string();
        let mode = obj.get("mode")?.as_str()?.to_string();
        let mut nodes = Vec::new();
        for item in obj.get("nodes")?.as_array()? {
            nodes.push(SurfaceNode::from_json(item)?);
        }
        let base_revision = match obj.get("baseRevision") {
            None | Some(JsonValue::Null) => None,
            Some(v) => Some(v.as_i64()?),
        };
        let parse_str_vec = |key: &str| -> Option<Vec<String>> {
            match obj.get(key) {
                None | Some(JsonValue::Null) => Some(Vec::new()),
                Some(v) => {
                    let arr = v.as_array()?;
                    let mut out = Vec::with_capacity(arr.len());
                    for item in arr {
                        out.push(item.as_str()?.to_string());
                    }
                    Some(out)
                }
            }
        };
        let added = parse_str_vec("added")?;
        let updated = parse_str_vec("updated")?;
        let removed = parse_str_vec("removed")?;
        let truncated = obj.get("truncated")?.as_bool()?;
        let missing_reasons = parse_str_vec("missingReasons")?;
        let complete = obj.get("complete")?.as_bool()?;
        let geometry = match obj.get("geometry") {
            None | Some(JsonValue::Null) => None,
            Some(v) => Some(SurfaceGeometry::from_json(v)?),
        };
        Some(Self {
            surface_id,
            revision,
            scope,
            mode,
            nodes,
            base_revision,
            added,
            updated,
            removed,
            truncated,
            missing_reasons,
            complete,
            geometry,
        })
    }

    pub fn to_json(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert(
            "surfaceId".to_string(),
            JsonValue::String(self.surface_id.clone()),
        );
        map.insert("revision".to_string(), json_i64(self.revision));
        map.insert("scope".to_string(), JsonValue::String(self.scope.clone()));
        map.insert("mode".to_string(), JsonValue::String(self.mode.clone()));
        map.insert(
            "nodes".to_string(),
            JsonValue::Array(self.nodes.iter().map(SurfaceNode::to_json).collect()),
        );
        if let Some(base) = self.base_revision {
            map.insert("baseRevision".to_string(), json_i64(base));
        }
        map.insert(
            "added".to_string(),
            JsonValue::Array(self.added.iter().cloned().map(JsonValue::String).collect()),
        );
        map.insert(
            "updated".to_string(),
            JsonValue::Array(self.updated.iter().cloned().map(JsonValue::String).collect()),
        );
        map.insert(
            "removed".to_string(),
            JsonValue::Array(self.removed.iter().cloned().map(JsonValue::String).collect()),
        );
        map.insert("truncated".to_string(), JsonValue::Bool(self.truncated));
        map.insert(
            "missingReasons".to_string(),
            JsonValue::Array(
                self.missing_reasons
                    .iter()
                    .cloned()
                    .map(JsonValue::String)
                    .collect(),
            ),
        );
        map.insert("complete".to_string(), JsonValue::Bool(self.complete));
        if let Some(ref geometry) = self.geometry {
            map.insert("geometry".to_string(), geometry.to_json());
        }
        JsonValue::Object(map)
    }
}

/// Computes full vs diff surface snapshots against the immediately preceding complete baseline.
#[derive(Debug, Default)]
pub struct SurfaceBaseline {
    prior: Option<HashMap<String, SurfaceNode>>,
    surface_id: Option<String>,
    revision: i64,
    prior_geometry: Option<SurfaceGeometry>,
}

impl SurfaceBaseline {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset(&mut self) {
        self.prior = None;
        self.surface_id = None;
        self.revision = 0;
        self.prior_geometry = None;
    }

    /// Invalidates all geometry evidence if the final window rect differs from the initial rect,
    /// stripping node bounds and adding `"geometry-window-moved"` without discarding valid text.
    pub fn invalidate_geometry_if_moved(
        nodes: &mut [SurfaceNode],
        geometry: &mut Option<SurfaceGeometry>,
        missing_reasons: &mut Vec<String>,
        initial_rect: Option<SurfaceAbsoluteRect>,
        final_rect: Option<SurfaceAbsoluteRect>,
    ) -> bool {
        let moved = match (initial_rect, final_rect) {
            (Some(a), Some(b)) => a != b,
            (Some(_), None) => true,
            _ => false,
        };
        if moved {
            *geometry = None;
            for node in nodes.iter_mut() {
                node.bounds = None;
                node.bounds_observed_at_ms = None;
            }
            if !missing_reasons.iter().any(|r| r == "geometry-window-moved") {
                missing_reasons.push("geometry-window-moved".to_string());
            }
            true
        } else {
            false
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn snapshot(
        &mut self,
        surface_id: &str,
        scope: &str,
        nodes: Vec<SurfaceNode>,
        complete: bool,
        matching_known: bool,
        truncated: bool,
        missing_reasons: Vec<String>,
        geometry: Option<SurfaceGeometry>,
    ) -> SurfaceReadResult {
        if self.surface_id.as_deref() != Some(surface_id) {
            self.reset();
            self.surface_id = Some(surface_id.to_string());
        }
        let base = self.revision;
        self.revision += 1;

        let mut current: HashMap<String, SurfaceNode> = HashMap::with_capacity(nodes.len());
        for node in &nodes {
            current.insert(node.id.clone(), node.clone());
        }

        let effective_complete = complete && !truncated && missing_reasons.is_empty();
        let may_diff = effective_complete && matching_known && self.prior.is_some();

        let window_changed = self
            .prior_geometry
            .as_ref()
            .map(|g| (g.window_size, g.coordinate_space.as_str()))
            != geometry
                .as_ref()
                .map(|g| (g.window_size, g.coordinate_space.as_str()));

        let mut added = Vec::new();
        let mut updated = Vec::new();
        let mut removed = Vec::new();

        if may_diff {
            if let Some(ref prior) = self.prior {
                for node in &nodes {
                    match prior.get(&node.id) {
                        None => added.push(node.id.clone()),
                        Some(old) => {
                            if window_changed
                                || old.text != node.text
                                || old.role != node.role
                                || old.parent_id != node.parent_id
                                || old.bounds != node.bounds
                                || old.ax_role != node.ax_role
                                || old.focused != node.focused
                            {
                                updated.push(node.id.clone());
                            }
                        }
                    }
                }
                for key in prior.keys() {
                    if !current.contains_key(key) {
                        removed.push(key.clone());
                    }
                }
                removed.sort();
            }
        }

        if effective_complete && matching_known {
            self.prior = Some(current);
            self.prior_geometry = geometry.clone();
        } else {
            self.prior = None;
            self.prior_geometry = None;
        }

        SurfaceReadResult {
            surface_id: surface_id.to_string(),
            revision: self.revision,
            scope: scope.to_string(),
            mode: if may_diff {
                "diff".to_string()
            } else {
                "full".to_string()
            },
            nodes,
            base_revision: if may_diff { Some(base) } else { None },
            added,
            updated,
            removed,
            truncated,
            missing_reasons,
            complete: effective_complete,
            geometry,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerSurfaceIdentity {
    pub session_id: String,
    pub window_id: String,
    pub node_id: String,
    pub surface_id: String,
    pub window_generation: i64,
    pub focus_generation: i64,
}

impl WorkerSurfaceIdentity {
    pub fn from_json(value: &JsonValue) -> Option<Self> {
        let obj = value.as_obj()?;
        Some(Self {
            session_id: obj.get("sessionId")?.as_str()?.to_string(),
            window_id: obj.get("windowId")?.as_str()?.to_string(),
            node_id: obj.get("nodeId")?.as_str()?.to_string(),
            surface_id: obj.get("surfaceId")?.as_str()?.to_string(),
            window_generation: obj.get("windowGeneration")?.as_i64()?,
            focus_generation: obj.get("focusGeneration")?.as_i64()?,
        })
    }

    pub fn to_json(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert(
            "sessionId".to_string(),
            JsonValue::String(self.session_id.clone()),
        );
        map.insert(
            "windowId".to_string(),
            JsonValue::String(self.window_id.clone()),
        );
        map.insert("nodeId".to_string(), JsonValue::String(self.node_id.clone()));
        map.insert(
            "surfaceId".to_string(),
            JsonValue::String(self.surface_id.clone()),
        );
        map.insert(
            "windowGeneration".to_string(),
            json_i64(self.window_generation),
        );
        map.insert(
            "focusGeneration".to_string(),
            json_i64(self.focus_generation),
        );
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionReadResult {
    pub text: String,
    pub source: String,
    pub range_start: usize,
    pub truncated: bool,
    pub missing_reasons: Vec<String>,
}

impl SelectionReadResult {
    pub fn from_json(value: &JsonValue) -> Option<Self> {
        let obj = value.as_obj()?;
        let text = obj.get("text")?.as_str()?.to_string();
        let source = obj.get("source")?.as_str()?.to_string();
        let range_start = usize::try_from(obj.get("rangeStart")?.as_u64()?).ok()?;
        let truncated = obj.get("truncated")?.as_bool()?;
        let arr = obj.get("missingReasons")?.as_array()?;
        let mut missing_reasons = Vec::with_capacity(arr.len());
        for item in arr {
            missing_reasons.push(item.as_str()?.to_string());
        }
        Some(Self {
            text,
            source,
            range_start,
            truncated,
            missing_reasons,
        })
    }

    pub fn to_json(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("text".to_string(), JsonValue::String(self.text.clone()));
        map.insert("source".to_string(), JsonValue::String(self.source.clone()));
        map.insert("rangeStart".to_string(), json_usize(self.range_start));
        map.insert("truncated".to_string(), JsonValue::Bool(self.truncated));
        map.insert(
            "missingReasons".to_string(),
            JsonValue::Array(
                self.missing_reasons
                    .iter()
                    .cloned()
                    .map(JsonValue::String)
                    .collect(),
            ),
        );
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextRead {
    pub text: String,
    pub source: String,
    pub total_length: Option<usize>,
    pub selection: Option<TextSelection>,
    pub range_start: usize,
    pub range_basis: String,
    pub complete: bool,
    pub truncated: bool,
    pub missing_reasons: Vec<String>,
    pub read_units: Option<usize>,
}

impl TextRead {
    pub fn charged_units(&self) -> usize {
        utf16_len(&self.text).max(self.read_units.unwrap_or(0))
    }

    pub fn from_json(value: &JsonValue) -> Option<Self> {
        let obj = value.as_obj()?;
        let text = obj.get("text")?.as_str()?.to_string();
        let source = obj.get("source")?.as_str()?.to_string();
        let total_length = match obj.get("totalLength") {
            None | Some(JsonValue::Null) => None,
            Some(v) => Some(usize::try_from(v.as_u64()?).ok()?),
        };
        let selection = match obj.get("selection") {
            None | Some(JsonValue::Null) => None,
            Some(v) => Some(TextSelection::from_json(v)?),
        };
        let range_start = usize::try_from(obj.get("rangeStart")?.as_u64()?).ok()?;
        let range_basis = obj.get("rangeBasis")?.as_str()?.to_string();
        let complete = obj.get("complete")?.as_bool()?;
        let truncated = obj.get("truncated")?.as_bool()?;
        let arr = obj.get("missingReasons")?.as_array()?;
        let mut missing_reasons = Vec::with_capacity(arr.len());
        for item in arr {
            missing_reasons.push(item.as_str()?.to_string());
        }
        let read_units = match obj.get("readUnits") {
            None | Some(JsonValue::Null) => None,
            Some(v) => Some(usize::try_from(v.as_u64()?).ok()?),
        };
        Some(Self {
            text,
            source,
            total_length,
            selection,
            range_start,
            range_basis,
            complete,
            truncated,
            missing_reasons,
            read_units,
        })
    }

    pub fn to_json(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("text".to_string(), JsonValue::String(self.text.clone()));
        map.insert("source".to_string(), JsonValue::String(self.source.clone()));
        if let Some(total) = self.total_length {
            map.insert("totalLength".to_string(), json_usize(total));
        }
        if let Some(sel) = self.selection {
            map.insert("selection".to_string(), sel.to_json());
        }
        map.insert("rangeStart".to_string(), json_usize(self.range_start));
        map.insert(
            "rangeBasis".to_string(),
            JsonValue::String(self.range_basis.clone()),
        );
        map.insert("complete".to_string(), JsonValue::Bool(self.complete));
        map.insert("truncated".to_string(), JsonValue::Bool(self.truncated));
        map.insert(
            "missingReasons".to_string(),
            JsonValue::Array(
                self.missing_reasons
                    .iter()
                    .cloned()
                    .map(JsonValue::String)
                    .collect(),
            ),
        );
        if let Some(units) = self.read_units {
            map.insert("readUnits".to_string(), json_usize(units));
        }
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AxEnablementResult {
    pub status: String,
    pub attribute: String,
    pub changed: bool,
}

impl AxEnablementResult {
    pub fn from_json(value: &JsonValue) -> Option<Self> {
        let obj = value.as_obj()?;
        Some(Self {
            status: obj.get("status")?.as_str()?.to_string(),
            attribute: obj.get("attribute")?.as_str()?.to_string(),
            changed: obj.get("changed")?.as_bool()?,
        })
    }

    pub fn to_json(&self) -> JsonValue {
        let mut map = BTreeMap::new();
        map.insert("status".to_string(), JsonValue::String(self.status.clone()));
        map.insert(
            "attribute".to_string(),
            JsonValue::String(self.attribute.clone()),
        );
        map.insert("changed".to_string(), JsonValue::Bool(self.changed));
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceReadFailure {
    NotStartedBudget,
    CallBudget,
    TimeBudget,
    AnchorUnavailable,
    BoundaryUnverified,
    BoundaryMismatch,
    BoundaryAxFailed,
    BoundaryIncomplete,
    SecurityExcluded,
    ProviderUnavailable,
}

impl SurfaceReadFailure {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotStartedBudget => "surface-not-started-budget",
            Self::CallBudget => "surface-call-budget",
            Self::TimeBudget => "surface-time-budget",
            Self::AnchorUnavailable => "surface-anchor-unavailable",
            Self::BoundaryUnverified => "surface-boundary-unverified",
            Self::BoundaryMismatch => "surface-boundary-mismatch",
            Self::BoundaryAxFailed => "surface-boundary-ax-failed",
            Self::BoundaryIncomplete => "surface-boundary-incomplete",
            Self::SecurityExcluded => "surface-security-excluded",
            Self::ProviderUnavailable => "surface-provider-unavailable",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "surface-not-started-budget" => Some(Self::NotStartedBudget),
            "surface-call-budget" => Some(Self::CallBudget),
            "surface-time-budget" => Some(Self::TimeBudget),
            "surface-anchor-unavailable" => Some(Self::AnchorUnavailable),
            "surface-boundary-unverified" => Some(Self::BoundaryUnverified),
            "surface-boundary-mismatch" => Some(Self::BoundaryMismatch),
            "surface-boundary-ax-failed" => Some(Self::BoundaryAxFailed),
            "surface-boundary-incomplete" => Some(Self::BoundaryIncomplete),
            "surface-security-excluded" => Some(Self::SecurityExcluded),
            "surface-provider-unavailable" => Some(Self::ProviderUnavailable),
            _ => None,
        }
    }

    pub fn gap_reason(self) -> &'static str {
        match self {
            Self::NotStartedBudget | Self::CallBudget | Self::TimeBudget => "budget",
            Self::SecurityExcluded => "policy-boundary",
            Self::BoundaryMismatch | Self::BoundaryIncomplete => "stale",
            Self::AnchorUnavailable
            | Self::BoundaryUnverified
            | Self::BoundaryAxFailed
            | Self::ProviderUnavailable => "read-error",
        }
    }

    pub fn diagnostic_code(self) -> GapDiagnosticCode {
        match self {
            Self::NotStartedBudget => GapDiagnosticCode::SurfaceNotStartedBudget,
            Self::CallBudget => GapDiagnosticCode::SurfaceCallBudget,
            Self::TimeBudget => GapDiagnosticCode::SurfaceTimeBudget,
            Self::AnchorUnavailable => GapDiagnosticCode::SurfaceAnchorUnavailable,
            Self::BoundaryUnverified => GapDiagnosticCode::SurfaceBoundaryUnverified,
            Self::BoundaryMismatch => GapDiagnosticCode::SurfaceBoundaryMismatch,
            Self::BoundaryAxFailed => GapDiagnosticCode::SurfaceBoundaryAxFailed,
            Self::BoundaryIncomplete => GapDiagnosticCode::SurfaceBoundaryIncomplete,
            Self::SecurityExcluded => GapDiagnosticCode::SurfaceSecurityExcluded,
            Self::ProviderUnavailable => GapDiagnosticCode::SurfaceProviderUnavailable,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputActivityCategory {
    PointerRelease,
    DragSample,
    ScrollSample,
    ShortcutPress,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputActivitySample {
    pub application: ApplicationIdentity,
    /// Internal-only normalized `.exe` basename for dual-ID defense-in-depth (e.g., MSIX Bitwarden
    /// or Arc). NEVER emitted on the external wire protocol.
    pub exe_name: Option<String>,
    pub category: InputActivityCategory,
    pub callback_time_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputActivityBucket {
    pub application: ApplicationIdentity,
    /// Internal-only normalized `.exe` basename carried from `InputActivitySample` for flush-time
    /// dual-ID defense-in-depth. NEVER emitted in `payload()`.
    pub exe_name: Option<String>,
    pub stamp: Stamp,
    pub interval_start_ms: i64,
    pub pointer_releases: usize,
    pub drag_samples: usize,
    pub scroll_samples: usize,
    pub shortcut_presses: usize,
    pub capped: bool,
}

impl InputActivityBucket {
    pub fn interval_end_ms(&self) -> i64 {
        self.interval_start_ms + 1_000
    }

    pub fn total(&self) -> usize {
        self.pointer_releases + self.drag_samples + self.scroll_samples + self.shortcut_presses
    }

    fn add(&mut self, category: InputActivityCategory) {
        if self.total() >= 256 {
            self.capped = true;
            return;
        }
        match category {
            InputActivityCategory::PointerRelease => self.pointer_releases += 1,
            InputActivityCategory::DragSample => self.drag_samples += 1,
            InputActivityCategory::ScrollSample => self.scroll_samples += 1,
            InputActivityCategory::ShortcutPress => self.shortcut_presses += 1,
        }
    }

    pub fn payload(&self, fixture: bool) -> JsonValue {
        let mut reasons = vec![
            "input-events-partial".to_string(),
            "application-only".to_string(),
            "effect-unverified".to_string(),
        ];
        if self.capped {
            reasons.push("input-events-capped".to_string());
        }
        let mut counts = BTreeMap::new();
        counts.insert("pointerReleases".to_string(), json_usize(self.pointer_releases));
        counts.insert("dragSamples".to_string(), json_usize(self.drag_samples));
        counts.insert("scrollSamples".to_string(), json_usize(self.scroll_samples));
        counts.insert("shortcutPresses".to_string(), json_usize(self.shortcut_presses));

        let mut gate = BTreeMap::new();
        gate.insert(
            "policyRevision".to_string(),
            json_i64(self.stamp.policy_revision),
        );
        gate.insert("secureInput".to_string(), JsonValue::String("inactive".to_string()));
        gate.insert(
            "targetAttribution".to_string(),
            JsonValue::String("event-target-pid".to_string()),
        );
        gate.insert(
            "detail".to_string(),
            JsonValue::String("coarse-counts".to_string()),
        );

        let coverage = Coverage {
            status: "partial".to_string(),
            truncated: self.capped,
            missing_reasons: reasons,
        };

        let mut map = BTreeMap::new();
        map.insert("kind".to_string(), JsonValue::String("input.activity".to_string()));
        map.insert(
            "source".to_string(),
            JsonValue::String(if fixture {
                "fixture".to_string()
            } else {
                "win32.listen-only".to_string()
            }),
        );
        map.insert("scope".to_string(), JsonValue::String("application".to_string()));
        map.insert("intervalStartMs".to_string(), json_i64(self.interval_start_ms));
        map.insert("intervalEndMs".to_string(), json_i64(self.interval_end_ms()));
        map.insert("counts".to_string(), JsonValue::Object(counts));
        map.insert("gate".to_string(), JsonValue::Object(gate));
        map.insert("coverage".to_string(), coverage.to_json());
        JsonValue::Object(map)
    }
}

#[derive(Debug, Default)]
pub struct InputActivityAccumulator {
    pending: Option<InputActivityBucket>,
}

impl InputActivityAccumulator {
    pub fn clear(&mut self) {
        self.pending = None;
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_none()
    }

    pub fn add(&mut self, sample: InputActivitySample, stamp: Stamp) {
        if sample.callback_time_ms < 0
            || sample.callback_time_ms > 9_007_199_254_739_000
            || sample.application.process_id <= 1
            || sample.application.application_id.is_empty()
            || sample.application.process_start_time.is_empty()
        {
            self.clear();
            return;
        }
        let start = (sample.callback_time_ms / 1_000) * 1_000;
        if let Some(ref current) = self.pending {
            if current.application != sample.application
                || current.exe_name != sample.exe_name
                || current.stamp.capture_epoch != stamp.capture_epoch
                || current.stamp.policy_revision != stamp.policy_revision
                || current.interval_start_ms != start
            {
                self.clear();
            }
        }
        let bucket = self.pending.get_or_insert(InputActivityBucket {
            application: sample.application,
            exe_name: sample.exe_name,
            stamp,
            interval_start_ms: start,
            pointer_releases: 0,
            drag_samples: 0,
            scroll_samples: 0,
            shortcut_presses: 0,
            capped: false,
        });
        bucket.add(sample.category);
    }

    pub fn take_completed(&mut self, now_ms: i64) -> Option<InputActivityBucket> {
        let current = self.pending.as_ref()?;
        if now_ms < current.interval_start_ms {
            self.clear();
            return None;
        }
        if now_ms < current.interval_end_ms() {
            return None;
        }
        let taken = self.pending.take()?;
        if now_ms - taken.interval_end_ms() > 1_000 {
            return None;
        }
        Some(taken)
    }
}

fn capability(name: &str, direction: &str, support: &str, reason: &str) -> JsonValue {
    let mut map = BTreeMap::new();
    map.insert("name".to_string(), JsonValue::String(name.to_string()));
    map.insert(
        "direction".to_string(),
        JsonValue::String(direction.to_string()),
    );
    map.insert(
        "scope".to_string(),
        JsonValue::String("authorized-desktop".to_string()),
    );
    map.insert("support".to_string(), JsonValue::String(support.to_string()));
    map.insert("reason".to_string(), JsonValue::String(reason.to_string()));
    JsonValue::Object(map)
}

/// Build the canonical Wire v1 `hello` message with Windows/fixture capability declarations.
pub fn hello_message(instance_id: &str, fixture: bool) -> JsonValue {
    let mut caps = vec![
        capability(
            "text.snapshot",
            "observe",
            "supported",
            if fixture {
                "synthetic-fixture"
            } else {
                "focused-field"
            },
        ),
        capability("text.visible-range", "observe", "supported", "visible-range"),
        capability(
            "input.activity",
            "observe",
            "supported",
            "coarse-event-counts",
        ),
        capability(
            "ax.enablement",
            "observe",
            "supported",
            "accessibility-enablement",
        ),
        if fixture {
            capability("text.marker", "observe", "supported", "text-marker-range")
        } else {
            capability(
                "text.marker",
                "observe",
                "unsupported",
                "not-applicable-windows",
            )
        },
        capability(
            "surface.snapshot",
            "observe",
            "supported",
            "bounded-surface-tree",
        ),
        capability(
            "selection.snapshot",
            "observe",
            "supported",
            "text-selection",
        ),
        if fixture {
            capability("input.text", "observe", "supported", "typed-text-events")
        } else {
            capability(
                "input.text",
                "observe",
                "unsupported",
                "not-implemented-phase5b",
            )
        },
        capability(
            "menu.action",
            "observe",
            "supported",
            "foreground-menu-bar",
        ),
        capability(
            "field.denylist",
            "observe",
            "supported",
            "field-denylist-policy",
        ),
    ];

    for name in [
        "pointer.click",
        "scroll",
        "gesture.pinch",
        "gesture.rotate",
        "gesture.pan",
        "gesture.swipe",
        "contact.touch",
        "contact.pen",
        "view.zoom",
    ] {
        caps.push(capability(name, "observe", "unsupported", "not-implemented"));
    }

    for name in ["text.set", "pointer.click", "key.chord", "view.zoom"] {
        caps.push(capability(
            name,
            "act",
            "unsupported",
            "observe-only-collector",
        ));
    }

    let mut map = BTreeMap::new();
    map.insert("protocolVersion".to_string(), json_i64(1));
    map.insert("type".to_string(), JsonValue::String("hello".to_string()));
    map.insert(
        "instanceId".to_string(),
        JsonValue::String(instance_id.to_string()),
    );
    map.insert("capabilities".to_string(), JsonValue::Array(caps));
    map.insert(
        "maxFrameBytes".to_string(),
        json_usize(ContractLimits::MAX_FRAME_BYTES),
    );
    JsonValue::Object(map)
}
