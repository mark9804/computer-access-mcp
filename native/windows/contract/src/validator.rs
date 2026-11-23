use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::json::{utf16_len, JsonValue};
use crate::schema::SchemaValidator;

const EMBEDDED_WIRE_SCHEMA: &str = include_str!("../../../../src/shared/protocol/wire.schema.json");

/// Protocol-wide structural and framing limits shared with TypeScript and Swift.
pub struct ContractLimits;

impl ContractLimits {
    pub const PROTOCOL_VERSION: u32 = 1;
    pub const MAX_FRAME_BYTES: usize = 65_536;
    pub const MAX_TEXT_CODE_UNITS: usize = 8_192;
    pub const MAX_DEPTH: usize = 32;
    pub const MAX_COLLECTION_ITEMS: usize = 256;
    pub const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;
    pub const MAX_SAFE_INTEGER_U64: u64 = 9_007_199_254_740_991;
    pub const MAX_SAFE_INTEGER_I64: i64 = 9_007_199_254_740_991;
}

/// Wire protocol error codes. Deliberately carries only a static code, never
/// input fragments, file paths, or captured text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolError {
    InvalidMessage,
    UnsupportedVersion,
    FrameTooLarge,
}

impl ProtocolError {
    #[inline]
    pub const fn code(self) -> &'static str {
        match self {
            ProtocolError::InvalidMessage => "invalid-message",
            ProtocolError::UnsupportedVersion => "unsupported-version",
            ProtocolError::FrameTooLarge => "frame-too-large",
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for ProtocolError {}

/// Matches `^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$`.
pub fn is_valid_application_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    if bytes.is_empty() || bytes.len() > 256 {
        return false;
    }
    if !bytes[0].is_ascii_alphanumeric() {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Matches `^AX[A-Za-z0-9]{1,62}$`.
pub fn is_valid_ax_role(role: &str) -> bool {
    let bytes = role.as_bytes();
    if bytes.len() < 3 || bytes.len() > 64 {
        return false;
    }
    bytes.starts_with(b"AX") && bytes[2..].iter().all(|b| b.is_ascii_alphanumeric())
}

/// Wire-v1 structural and semantic validator. Pure `std`, zero desktop or I/O dependencies.
#[derive(Debug, Clone)]
pub struct ContractValidator {
    schema: SchemaValidator,
}

impl ContractValidator {
    /// Initializes a validator from the compile-time embedded `wire.schema.json`.
    pub fn new() -> Result<Self, ProtocolError> {
        Self::from_schema_bytes(EMBEDDED_WIRE_SCHEMA.as_bytes())
    }

    /// Initializes a validator from raw schema JSON bytes.
    pub fn from_schema_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let root = JsonValue::parse(bytes)?;
        let schema = SchemaValidator::new(root)?;
        Ok(Self { schema })
    }

    /// Validates a parsed `JsonValue` against wire v1 version, schema, and semantic rules.
    pub fn validate_message(&self, value: &JsonValue) -> Result<(), ProtocolError> {
        if let Some(version) = value.get("protocolVersion") {
            if *version != JsonValue::Number(1.0) {
                return Err(ProtocolError::UnsupportedVersion);
            }
        }
        self.schema.validate(value)?;
        validate_semantics(value)?;
        Ok(())
    }

    /// Decodes and validates a single bounded JSON frame (LF is not required here).
    pub fn decode_frame(&self, bytes: &[u8]) -> Result<JsonValue, ProtocolError> {
        if bytes.len() > ContractLimits::MAX_FRAME_BYTES {
            return Err(ProtocolError::FrameTooLarge);
        }
        let value = JsonValue::parse(bytes)?;
        self.validate_message(&value)?;
        Ok(value)
    }

    /// Validates `value` and encodes it as canonical JSON plus trailing LF (`0x0A`),
    /// enforcing the hard `65_536`-byte frame budget (including LF).
    pub fn encode_frame(&self, value: &JsonValue) -> Result<Vec<u8>, ProtocolError> {
        self.validate_message(value)?;
        let mut bytes = value.canonical_bytes()?;
        bytes.push(b'\n');
        if bytes.len() > ContractLimits::MAX_FRAME_BYTES {
            return Err(ProtocolError::FrameTooLarge);
        }
        Ok(bytes)
    }
}

fn validate_semantics(message: &JsonValue) -> Result<(), ProtocolError> {
    match message.get("type").and_then(JsonValue::as_str) {
        Some("configure") => {
            let policy = message.get("policy").ok_or(ProtocolError::InvalidMessage)?;
            validate_policy(policy)?;
        }
        Some("observation") => {
            validate_observation(message)?;
        }
        Some("action.receipt") => {
            validate_action_receipt(message)?;
        }
        _ => {}
    }
    Ok(())
}

fn validate_policy(policy: &JsonValue) -> Result<(), ProtocolError> {
    let max_wait = policy
        .get("maxWaitMs")
        .and_then(JsonValue::as_u64)
        .ok_or(ProtocolError::InvalidMessage)?;
    let debounce = policy
        .get("debounceMs")
        .and_then(JsonValue::as_u64)
        .ok_or(ProtocolError::InvalidMessage)?;
    if max_wait < debounce {
        return Err(ProtocolError::InvalidMessage);
    }

    let allowed = policy
        .get("allowedApplicationIds")
        .and_then(JsonValue::as_array)
        .ok_or(ProtocolError::InvalidMessage)?;
    validate_app_id_list(allowed)?;

    if let Some(excluded) = policy.get("excludedApplicationIds") {
        let excluded_arr = excluded.as_array().ok_or(ProtocolError::InvalidMessage)?;
        validate_app_id_list(excluded_arr)?;
    }

    Ok(())
}

fn validate_app_id_list(items: &[JsonValue]) -> Result<(), ProtocolError> {
    let mut seen = HashSet::with_capacity(items.len());
    for item in items {
        let id = item.as_str().ok_or(ProtocolError::InvalidMessage)?;
        if !is_valid_application_id(id) {
            return Err(ProtocolError::InvalidMessage);
        }
        if !seen.insert(id.to_ascii_lowercase()) {
            return Err(ProtocolError::InvalidMessage);
        }
    }
    Ok(())
}

fn validate_coverage(coverage: &JsonValue) -> Result<(), ProtocolError> {
    let status = coverage
        .get("status")
        .and_then(JsonValue::as_str)
        .ok_or(ProtocolError::InvalidMessage)?;
    let truncated = coverage
        .get("truncated")
        .and_then(JsonValue::as_bool)
        .ok_or(ProtocolError::InvalidMessage)?;
    let reasons = coverage
        .get("missingReasons")
        .and_then(JsonValue::as_array)
        .ok_or(ProtocolError::InvalidMessage)?;

    if status == "complete" {
        if truncated || !reasons.is_empty() {
            return Err(ProtocolError::InvalidMessage);
        }
    } else if reasons.is_empty() {
        return Err(ProtocolError::InvalidMessage);
    }
    Ok(())
}

fn validate_gate(gate: Option<&JsonValue>, revision: Option<&JsonValue>) -> Result<(), ProtocolError> {
    let gate = gate.ok_or(ProtocolError::InvalidMessage)?;
    let revision = revision.ok_or(ProtocolError::InvalidMessage)?;
    let secure = gate
        .get("secure")
        .and_then(JsonValue::as_str)
        .ok_or(ProtocolError::InvalidMessage)?;
    let private_state = gate
        .get("privateState")
        .and_then(JsonValue::as_str)
        .ok_or(ProtocolError::InvalidMessage)?;
    let gate_rev = gate
        .get("policyRevision")
        .ok_or(ProtocolError::InvalidMessage)?;

    if !matches!(secure, "safe" | "not-declared-sensitive")
        || gate_rev != revision
        || !matches!(private_state, "normal" | "user-authorized")
    {
        return Err(ProtocolError::InvalidMessage);
    }
    Ok(())
}

fn validate_range(range: &JsonValue) -> Result<(u64, u64), ProtocolError> {
    let start = range
        .get("start")
        .and_then(JsonValue::as_u64)
        .ok_or(ProtocolError::InvalidMessage)?;
    let length = range
        .get("length")
        .and_then(JsonValue::as_u64)
        .ok_or(ProtocolError::InvalidMessage)?;
    if length > ContractLimits::MAX_SAFE_INTEGER_U64 - start {
        return Err(ProtocolError::InvalidMessage);
    }
    Ok((start, length))
}

fn contains_str(items: &[JsonValue], needle: &str) -> bool {
    items.iter().any(|item| item.as_str() == Some(needle))
}

fn validate_observation(message: &JsonValue) -> Result<(), ProtocolError> {
    let payload = message.get("payload").ok_or(ProtocolError::InvalidMessage)?;
    let kind = payload
        .get("kind")
        .and_then(JsonValue::as_str)
        .ok_or(ProtocolError::InvalidMessage)?;
    let target_kind = message
        .get("target")
        .and_then(|t| t.get("kind"))
        .and_then(JsonValue::as_str)
        .ok_or(ProtocolError::InvalidMessage)?;
    let actor = message
        .get("actor")
        .and_then(JsonValue::as_str)
        .ok_or(ProtocolError::InvalidMessage)?;
    let related = message
        .get("relatedActionIds")
        .and_then(JsonValue::as_array)
        .ok_or(ProtocolError::InvalidMessage)?;
    let stamp_revision = message.get("stamp").and_then(|s| s.get("policyRevision"));

    if kind == "gap" {
        if let Some(provider_id) = payload
            .get("providerApplicationId")
            .and_then(JsonValue::as_str)
        {
            if !is_valid_application_id(provider_id) {
                return Err(ProtocolError::InvalidMessage);
            }
        }
    }

    let content_kind = matches!(
        kind,
        "text.snapshot"
            | "text.changed"
            | "surface.snapshot"
            | "selection.snapshot"
            | "input.text"
    );
    if let Some(relation) = message.get("relation") {
        if !content_kind {
            return Err(ProtocolError::InvalidMessage);
        }
        let ids = relation
            .get("evidenceIds")
            .and_then(JsonValue::as_array)
            .ok_or(ProtocolError::InvalidMessage)?;
        let event_id = message
            .get("eventId")
            .and_then(JsonValue::as_str)
            .ok_or(ProtocolError::InvalidMessage)?;
        let mut seen = HashSet::with_capacity(ids.len());
        for id in ids {
            let s = id.as_str().ok_or(ProtocolError::InvalidMessage)?;
            if s == event_id || !seen.insert(s) {
                return Err(ProtocolError::InvalidMessage);
            }
        }
    }

    if matches!(kind, "surface.snapshot" | "selection.snapshot" | "input.text") {
        if target_kind != "resolved" || actor != "unknown" || !related.is_empty() {
            return Err(ProtocolError::InvalidMessage);
        }
        validate_gate(payload.get("gate"), stamp_revision)?;
        match kind {
            "surface.snapshot" => validate_surface(payload)?,
            "selection.snapshot" => validate_selection(payload)?,
            "input.text" => validate_input_text(payload, message)?,
            _ => unreachable!(),
        }
    }

    // Application-only identities never stand in for a resolved text/window target.
    if target_kind == "application" && kind != "input.activity" && kind != "menu.action" {
        return Err(ProtocolError::InvalidMessage);
    }

    if kind == "input.activity" {
        validate_input_activity(payload, message, target_kind, actor, related, stamp_revision)?;
    }

    if kind == "menu.action" {
        validate_menu_action(payload, message, target_kind, actor, related, stamp_revision)?;
    }

    if kind == "text.snapshot" || kind == "text.changed" {
        if target_kind != "resolved" {
            return Err(ProtocolError::InvalidMessage);
        }
        let changed = kind == "text.changed";
        let snapshot = if changed {
            payload.get("after").ok_or(ProtocolError::InvalidMessage)?
        } else {
            payload
        };
        validate_text(snapshot)?;
        let source = snapshot
            .get("source")
            .and_then(JsonValue::as_str)
            .ok_or(ProtocolError::InvalidMessage)?;
        if source != "fixture" || snapshot.get("gate").is_some() {
            validate_gate(snapshot.get("gate"), stamp_revision)?;
        }
        if changed && payload.get("baseSnapshotId") == snapshot.get("snapshotId") {
            return Err(ProtocolError::InvalidMessage);
        }
    }

    if actor == "agent" && related.is_empty() {
        return Err(ProtocolError::InvalidMessage);
    }

    Ok(())
}

fn validate_surface(snapshot: &JsonValue) -> Result<(), ProtocolError> {
    let start = snapshot
        .get("captureStartMs")
        .and_then(JsonValue::as_u64)
        .ok_or(ProtocolError::InvalidMessage)?;
    let end = snapshot
        .get("captureEndMs")
        .and_then(JsonValue::as_u64)
        .ok_or(ProtocolError::InvalidMessage)?;
    if end < start {
        return Err(ProtocolError::InvalidMessage);
    }

    let coverage = snapshot
        .get("coverage")
        .ok_or(ProtocolError::InvalidMessage)?;
    validate_coverage(coverage)?;

    let geometry = snapshot.get("geometry");
    if let Some(geom) = geometry {
        let observed = geom
            .get("observedAtMs")
            .and_then(JsonValue::as_u64)
            .ok_or(ProtocolError::InvalidMessage)?;
        if observed < start || observed > end {
            return Err(ProtocolError::InvalidMessage);
        }
    }

    let nodes = snapshot
        .get("nodes")
        .and_then(JsonValue::as_array)
        .ok_or(ProtocolError::InvalidMessage)?;

    let mut by_id: HashMap<&str, &JsonValue> = HashMap::with_capacity(nodes.len());
    let mut focused_count = 0usize;
    let mut text_units = 0usize;

    for node in nodes {
        if node.get("focused").and_then(JsonValue::as_bool) == Some(true) {
            focused_count += 1;
            if focused_count > 1 {
                return Err(ProtocolError::InvalidMessage);
            }
        }
        let has_bounds = node.get("bounds").is_some();
        let bounds_observed = node.get("boundsObservedAtMs");
        if has_bounds != bounds_observed.is_some() {
            return Err(ProtocolError::InvalidMessage);
        }
        if has_bounds && geometry.is_none() {
            return Err(ProtocolError::InvalidMessage);
        }
        if let Some(obs_val) = bounds_observed {
            let obs = obs_val.as_u64().ok_or(ProtocolError::InvalidMessage)?;
            if obs < start || obs > end {
                return Err(ProtocolError::InvalidMessage);
            }
        }
        if let Some(ax_role) = node.get("axRole").and_then(JsonValue::as_str) {
            if !is_valid_ax_role(ax_role) {
                return Err(ProtocolError::InvalidMessage);
            }
        }
        let id = node
            .get("id")
            .and_then(JsonValue::as_str)
            .ok_or(ProtocolError::InvalidMessage)?;
        let observed = node
            .get("observedAtMs")
            .and_then(JsonValue::as_u64)
            .ok_or(ProtocolError::InvalidMessage)?;
        if observed < start || observed > end {
            return Err(ProtocolError::InvalidMessage);
        }
        if let Some(text) = node.get("text").and_then(JsonValue::as_str) {
            text_units = text_units
                .checked_add(utf16_len(text))
                .ok_or(ProtocolError::InvalidMessage)?;
            if text_units > ContractLimits::MAX_TEXT_CODE_UNITS {
                return Err(ProtocolError::InvalidMessage);
            }
        }
        if by_id.insert(id, node).is_some() {
            return Err(ProtocolError::InvalidMessage);
        }
    }

    // Iterative, bounded ancestry walk: every parentId must exist in `nodes` without cycles.
    for node in nodes {
        let id = node
            .get("id")
            .and_then(JsonValue::as_str)
            .ok_or(ProtocolError::InvalidMessage)?;
        let mut seen: HashSet<&str> = HashSet::new();
        seen.insert(id);
        let mut parent = node.get("parentId").and_then(JsonValue::as_str);
        while let Some(parent_id) = parent {
            if !seen.insert(parent_id) {
                return Err(ProtocolError::InvalidMessage);
            }
            let ancestor = by_id.get(parent_id).ok_or(ProtocolError::InvalidMessage)?;
            parent = ancestor.get("parentId").and_then(JsonValue::as_str);
        }
    }

    let mode = snapshot
        .get("mode")
        .and_then(JsonValue::as_str)
        .ok_or(ProtocolError::InvalidMessage)?;
    if mode == "full" {
        if snapshot.get("changes").is_some() || snapshot.get("baseRevision").is_some() {
            return Err(ProtocolError::InvalidMessage);
        }
    } else {
        let base_rev = snapshot
            .get("baseRevision")
            .and_then(JsonValue::as_u64)
            .ok_or(ProtocolError::InvalidMessage)?;
        let revision = snapshot
            .get("revision")
            .and_then(JsonValue::as_u64)
            .ok_or(ProtocolError::InvalidMessage)?;
        if base_rev >= revision {
            return Err(ProtocolError::InvalidMessage);
        }
        let changes = snapshot
            .get("changes")
            .ok_or(ProtocolError::InvalidMessage)?;
        let added = changes
            .get("added")
            .and_then(JsonValue::as_array)
            .ok_or(ProtocolError::InvalidMessage)?;
        let updated = changes
            .get("updated")
            .and_then(JsonValue::as_array)
            .ok_or(ProtocolError::InvalidMessage)?;
        let removed = changes
            .get("removed")
            .and_then(JsonValue::as_array)
            .ok_or(ProtocolError::InvalidMessage)?;

        let mut seen = HashSet::with_capacity(added.len() + updated.len() + removed.len());
        for id_val in added.iter().chain(updated.iter()) {
            let id = id_val.as_str().ok_or(ProtocolError::InvalidMessage)?;
            if !seen.insert(id) || !by_id.contains_key(id) {
                return Err(ProtocolError::InvalidMessage);
            }
        }
        for id_val in removed {
            let id = id_val.as_str().ok_or(ProtocolError::InvalidMessage)?;
            if !seen.insert(id) || by_id.contains_key(id) {
                return Err(ProtocolError::InvalidMessage);
            }
        }
        if coverage.get("status").and_then(JsonValue::as_str) != Some("complete")
            && !removed.is_empty()
        {
            return Err(ProtocolError::InvalidMessage);
        }
    }

    Ok(())
}

fn validate_selection(snapshot: &JsonValue) -> Result<(), ProtocolError> {
    let start = snapshot
        .get("captureStartMs")
        .and_then(JsonValue::as_u64)
        .ok_or(ProtocolError::InvalidMessage)?;
    let end = snapshot
        .get("captureEndMs")
        .and_then(JsonValue::as_u64)
        .ok_or(ProtocolError::InvalidMessage)?;
    if end < start {
        return Err(ProtocolError::InvalidMessage);
    }

    let text = snapshot
        .get("text")
        .and_then(JsonValue::as_str)
        .ok_or(ProtocolError::InvalidMessage)?;
    let range = snapshot.get("range").ok_or(ProtocolError::InvalidMessage)?;
    let (_, range_len) = validate_range(range)?;
    if range_len != utf16_len(text) as u64 {
        return Err(ProtocolError::InvalidMessage);
    }

    let coverage = snapshot
        .get("coverage")
        .ok_or(ProtocolError::InvalidMessage)?;
    let reasons = coverage
        .get("missingReasons")
        .and_then(JsonValue::as_array)
        .ok_or(ProtocolError::InvalidMessage)?;
    if coverage.get("status").and_then(JsonValue::as_str) != Some("partial")
        || !contains_str(reasons, "selection-only")
    {
        return Err(ProtocolError::InvalidMessage);
    }

    Ok(())
}

fn validate_input_text(payload: &JsonValue, message: &JsonValue) -> Result<(), ProtocolError> {
    let start = payload
        .get("intervalStartMs")
        .and_then(JsonValue::as_u64)
        .ok_or(ProtocolError::InvalidMessage)?;
    let end = payload
        .get("intervalEndMs")
        .and_then(JsonValue::as_u64)
        .ok_or(ProtocolError::InvalidMessage)?;
    let event_time = message
        .get("eventTimeMs")
        .and_then(JsonValue::as_u64)
        .ok_or(ProtocolError::InvalidMessage)?;
    if end < start || end - start > 5_000 || event_time != end {
        return Err(ProtocolError::InvalidMessage);
    }

    let modifiers = payload
        .get("modifiers")
        .and_then(JsonValue::as_array)
        .ok_or(ProtocolError::InvalidMessage)?;
    let mut seen = HashSet::with_capacity(modifiers.len());
    for item in modifiers {
        let m = item.as_str().ok_or(ProtocolError::InvalidMessage)?;
        if !seen.insert(m) {
            return Err(ProtocolError::InvalidMessage);
        }
    }

    let has_command = seen.contains("command") || seen.contains("control");
    let event_kind = payload
        .get("eventKind")
        .and_then(JsonValue::as_str)
        .ok_or(ProtocolError::InvalidMessage)?;
    let text = payload
        .get("text")
        .and_then(JsonValue::as_str)
        .ok_or(ProtocolError::InvalidMessage)?;

    if event_kind == "text" {
        if text.is_empty() || has_command {
            return Err(ProtocolError::InvalidMessage);
        }
    } else if !text.is_empty() || (event_kind == "shortcut" && !has_command) {
        return Err(ProtocolError::InvalidMessage);
    }

    let coverage = payload
        .get("coverage")
        .ok_or(ProtocolError::InvalidMessage)?;
    let reasons = coverage
        .get("missingReasons")
        .and_then(JsonValue::as_array)
        .ok_or(ProtocolError::InvalidMessage)?;
    if coverage.get("status").and_then(JsonValue::as_str) != Some("partial")
        || !contains_str(reasons, "input-events-partial")
        || !contains_str(reasons, "effect-unverified")
    {
        return Err(ProtocolError::InvalidMessage);
    }

    Ok(())
}

fn validate_input_activity(
    payload: &JsonValue,
    message: &JsonValue,
    target_kind: &str,
    actor: &str,
    related: &[JsonValue],
    stamp_revision: Option<&JsonValue>,
) -> Result<(), ProtocolError> {
    if target_kind != "application" || actor != "unknown" || !related.is_empty() {
        return Err(ProtocolError::InvalidMessage);
    }
    let gate_rev = payload
        .get("gate")
        .and_then(|g| g.get("policyRevision"))
        .ok_or(ProtocolError::InvalidMessage)?;
    if Some(gate_rev) != stamp_revision {
        return Err(ProtocolError::InvalidMessage);
    }

    let start = payload
        .get("intervalStartMs")
        .and_then(JsonValue::as_u64)
        .ok_or(ProtocolError::InvalidMessage)?;
    let end = payload
        .get("intervalEndMs")
        .and_then(JsonValue::as_u64)
        .ok_or(ProtocolError::InvalidMessage)?;
    let event_time = message
        .get("eventTimeMs")
        .and_then(JsonValue::as_u64)
        .ok_or(ProtocolError::InvalidMessage)?;
    if start % 1_000 != 0 || start.checked_add(1_000) != Some(end) || event_time != end {
        return Err(ProtocolError::InvalidMessage);
    }

    let counts = payload.get("counts").ok_or(ProtocolError::InvalidMessage)?;
    let pointer = counts
        .get("pointerReleases")
        .and_then(JsonValue::as_u64)
        .ok_or(ProtocolError::InvalidMessage)?;
    let drag = counts
        .get("dragSamples")
        .and_then(JsonValue::as_u64)
        .ok_or(ProtocolError::InvalidMessage)?;
    let scroll = counts
        .get("scrollSamples")
        .and_then(JsonValue::as_u64)
        .ok_or(ProtocolError::InvalidMessage)?;
    let shortcut = counts
        .get("shortcutPresses")
        .and_then(JsonValue::as_u64)
        .ok_or(ProtocolError::InvalidMessage)?;
    let total = pointer + drag + scroll + shortcut;
    if !(1..=256).contains(&total) {
        return Err(ProtocolError::InvalidMessage);
    }

    let coverage = payload
        .get("coverage")
        .ok_or(ProtocolError::InvalidMessage)?;
    let reasons = coverage
        .get("missingReasons")
        .and_then(JsonValue::as_array)
        .ok_or(ProtocolError::InvalidMessage)?;
    if coverage.get("status").and_then(JsonValue::as_str) != Some("partial") || reasons.is_empty() {
        return Err(ProtocolError::InvalidMessage);
    }

    Ok(())
}

fn validate_menu_action(
    payload: &JsonValue,
    message: &JsonValue,
    target_kind: &str,
    actor: &str,
    related: &[JsonValue],
    stamp_revision: Option<&JsonValue>,
) -> Result<(), ProtocolError> {
    if target_kind != "application" || actor != "unknown" || !related.is_empty() {
        return Err(ProtocolError::InvalidMessage);
    }
    let observed_at = payload
        .get("observedAtMs")
        .and_then(JsonValue::as_u64)
        .ok_or(ProtocolError::InvalidMessage)?;
    let event_time = message
        .get("eventTimeMs")
        .and_then(JsonValue::as_u64)
        .ok_or(ProtocolError::InvalidMessage)?;
    if event_time != observed_at {
        return Err(ProtocolError::InvalidMessage);
    }

    let path = payload
        .get("path")
        .and_then(JsonValue::as_array)
        .ok_or(ProtocolError::InvalidMessage)?;
    if !(2..=8).contains(&path.len()) {
        return Err(ProtocolError::InvalidMessage);
    }

    let mut total_units = 0usize;
    for item in path {
        let segment = item.as_str().ok_or(ProtocolError::InvalidMessage)?;
        let units = utf16_len(segment);
        if !(1..=128).contains(&units) {
            return Err(ProtocolError::InvalidMessage);
        }
        // Reject C0/C1 control characters and whitespace/BOM-only segments (matching JS trim()).
        if segment.chars().any(|c| {
            let code = c as u32;
            code < 0x20 || (0x7F..=0x9F).contains(&code)
        }) {
            return Err(ProtocolError::InvalidMessage);
        }
        if segment.chars().all(|c| c.is_whitespace() || c == '\u{FEFF}') {
            return Err(ProtocolError::InvalidMessage);
        }
        total_units += units;
        if total_units > 512 {
            return Err(ProtocolError::InvalidMessage);
        }
    }

    validate_gate(payload.get("gate"), stamp_revision)?;

    let coverage = payload
        .get("coverage")
        .ok_or(ProtocolError::InvalidMessage)?;
    let truncated = coverage
        .get("truncated")
        .and_then(JsonValue::as_bool)
        .ok_or(ProtocolError::InvalidMessage)?;
    let reasons = coverage
        .get("missingReasons")
        .and_then(JsonValue::as_array)
        .ok_or(ProtocolError::InvalidMessage)?;
    if coverage.get("status").and_then(JsonValue::as_str) != Some("partial")
        || !contains_str(reasons, "menu-bar-only")
        || !contains_str(reasons, "effect-unverified")
        || contains_str(reasons, "menu-title-truncated") != truncated
    {
        return Err(ProtocolError::InvalidMessage);
    }

    Ok(())
}

fn validate_text(snapshot: &JsonValue) -> Result<(), ProtocolError> {
    let capture_start = snapshot
        .get("captureStartMs")
        .and_then(JsonValue::as_u64)
        .ok_or(ProtocolError::InvalidMessage)?;
    let capture_end = snapshot
        .get("captureEndMs")
        .and_then(JsonValue::as_u64)
        .ok_or(ProtocolError::InvalidMessage)?;
    if capture_end < capture_start {
        return Err(ProtocolError::InvalidMessage);
    }

    let coverage = snapshot
        .get("coverage")
        .ok_or(ProtocolError::InvalidMessage)?;
    validate_coverage(coverage)?;
    let coverage_status = coverage
        .get("status")
        .and_then(JsonValue::as_str)
        .ok_or(ProtocolError::InvalidMessage)?;
    let missing_reasons = coverage
        .get("missingReasons")
        .and_then(JsonValue::as_array)
        .ok_or(ProtocolError::InvalidMessage)?;
    let complete = coverage_status == "complete";

    let range_vals = match snapshot.get("range") {
        Some(r) => Some(validate_range(r)?),
        None => None,
    };
    let selection_vals = match snapshot.get("selection") {
        Some(s) => Some(validate_range(s)?),
        None => None,
    };
    let total_length = match snapshot.get("totalLength") {
        Some(v) => Some(v.as_u64().ok_or(ProtocolError::InvalidMessage)?),
        None => None,
    };

    let value_state = snapshot
        .get("valueState")
        .and_then(JsonValue::as_str)
        .ok_or(ProtocolError::InvalidMessage)?;
    let scope = snapshot
        .get("scope")
        .and_then(JsonValue::as_str)
        .ok_or(ProtocolError::InvalidMessage)?;

    if value_state == "read" {
        let text = snapshot
            .get("text")
            .and_then(JsonValue::as_str)
            .ok_or(ProtocolError::InvalidMessage)?;
        let (start, length) = range_vals.ok_or(ProtocolError::InvalidMessage)?;
        if length != utf16_len(text) as u64 {
            return Err(ProtocolError::InvalidMessage);
        }
        if let Some(total) = total_length {
            if start > total || length > total - start {
                return Err(ProtocolError::InvalidMessage);
            }
        }
        if scope == "field" && complete && (start != 0 || total_length != Some(length)) {
            return Err(ProtocolError::InvalidMessage);
        }
    } else if snapshot.get("text").is_some()
        || range_vals.is_some()
        || selection_vals.is_some()
        || complete
    {
        return Err(ProtocolError::InvalidMessage);
    }

    if let (Some((sel_start, sel_len)), Some(total)) = (selection_vals, total_length) {
        if sel_start > total || sel_len > total - sel_start {
            return Err(ProtocolError::InvalidMessage);
        }
    }

    // Omitted rangeBasis preserves legacy wire-v1 accessible-range semantics.
    match snapshot.get("rangeBasis").and_then(JsonValue::as_str) {
        Some("prefix") => {
            if let Some((start, _)) = range_vals {
                if start != 0 {
                    return Err(ProtocolError::InvalidMessage);
                }
            }
        }
        Some("visible") => {
            let source = snapshot
                .get("source")
                .and_then(JsonValue::as_str)
                .ok_or(ProtocolError::InvalidMessage)?;
            if !matches!(source, "fixture" | "ax.range" | "ax.marker" | "uia.text")
                || scope != "accessible-range"
                || value_state != "read"
                || coverage_status != "partial"
                || !contains_str(missing_reasons, "visible-range-only")
            {
                return Err(ProtocolError::InvalidMessage);
            }
            let (start, length) = range_vals.ok_or(ProtocolError::InvalidMessage)?;
            let total = total_length.ok_or(ProtocolError::InvalidMessage)?;
            if start > total || length > total - start || (total > 0 && length == 0) {
                return Err(ProtocolError::InvalidMessage);
            }
            let end = start
                .checked_add(length)
                .ok_or(ProtocolError::InvalidMessage)?;
            if end > ContractLimits::MAX_SAFE_INTEGER_U64 {
                return Err(ProtocolError::InvalidMessage);
            }
            if let Some((sel_start, sel_len)) = selection_vals {
                if sel_start < start || sel_start > end || sel_len > end - sel_start {
                    return Err(ProtocolError::InvalidMessage);
                }
            }
        }
        _ => {}
    }

    Ok(())
}

fn validate_action_receipt(message: &JsonValue) -> Result<(), ProtocolError> {
    let start = message
        .get("startedMs")
        .and_then(JsonValue::as_u64)
        .ok_or(ProtocolError::InvalidMessage)?;
    let end = message
        .get("endedMs")
        .and_then(JsonValue::as_u64)
        .ok_or(ProtocolError::InvalidMessage)?;
    if end < start {
        return Err(ProtocolError::InvalidMessage);
    }

    let dispatch = message
        .get("dispatch")
        .and_then(JsonValue::as_str)
        .ok_or(ProtocolError::InvalidMessage)?;
    let effect = message
        .get("effect")
        .and_then(JsonValue::as_str)
        .ok_or(ProtocolError::InvalidMessage)?;
    let evidence_ids = message
        .get("evidenceIds")
        .and_then(JsonValue::as_array)
        .ok_or(ProtocolError::InvalidMessage)?;

    if effect == "confirmed"
        && (evidence_ids.is_empty() || dispatch == "not-dispatched" || dispatch == "unknown")
    {
        return Err(ProtocolError::InvalidMessage);
    }
    if effect == "refused" && dispatch != "not-dispatched" {
        return Err(ProtocolError::InvalidMessage);
    }
    if dispatch == "unknown" && effect != "uncertain" {
        return Err(ProtocolError::InvalidMessage);
    }
    Ok(())
}
