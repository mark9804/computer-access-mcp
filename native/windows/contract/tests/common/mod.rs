#![allow(dead_code)]

use history_contract::{utf16_len, ContractValidator, JsonValue, ProtocolError};

pub fn replacing(value: &JsonValue, path: &[&str], replacement: Option<JsonValue>) -> JsonValue {
    let Some((&head, tail)) = path.split_first() else {
        return replacement.unwrap_or_else(|| value.clone());
    };
    let Some(map) = value.as_obj() else {
        return replacement.unwrap_or_else(|| value.clone());
    };
    let mut copy = map.clone();
    if tail.is_empty() {
        match replacement {
            Some(v) => {
                copy.insert(head.to_owned(), v);
            }
            None => {
                copy.remove(head);
            }
        }
    } else if let Some(child) = copy.get(head).cloned() {
        copy.insert(head.to_owned(), replacing(&child, tail, replacement));
    }
    JsonValue::Object(copy)
}

pub fn assert_invalid(validator: &ContractValidator, value: &JsonValue) {
    assert_eq!(
        validator.validate_message(value),
        Err(ProtocolError::InvalidMessage),
        "expected InvalidMessage for {:?}",
        value
    );
}

pub fn hello() -> JsonValue {
    JsonValue::object([
        ("protocolVersion", JsonValue::from(1)),
        ("type", JsonValue::from("hello")),
        ("instanceId", JsonValue::from("fixture")),
        ("capabilities", JsonValue::array([])),
        ("maxFrameBytes", JsonValue::from(65_536)),
    ])
}

pub fn configure() -> JsonValue {
    JsonValue::object([
        ("protocolVersion", JsonValue::from(1)),
        ("type", JsonValue::from("configure")),
        ("requestId", JsonValue::from("request")),
        ("ownerId", JsonValue::from("owner")),
        ("instanceId", JsonValue::from("fixture")),
        ("policyRevision", JsonValue::from(1)),
        (
            "policy",
            JsonValue::object([
                ("enabled", JsonValue::from(false)),
                ("allowedApplicationIds", JsonValue::array([])),
                ("maxTextCodeUnits", JsonValue::from(8_192)),
                ("maxPending", JsonValue::from(8)),
                ("debounceMs", JsonValue::from(20)),
                ("maxWaitMs", JsonValue::from(100)),
                ("readTimeoutMs", JsonValue::from(1_000)),
            ]),
        ),
    ])
}

pub fn configured() -> JsonValue {
    JsonValue::object([
        ("protocolVersion", JsonValue::from(1)),
        ("type", JsonValue::from("configured")),
        ("requestId", JsonValue::from("request")),
        ("ownerId", JsonValue::from("owner")),
        ("instanceId", JsonValue::from("fixture")),
        ("policyRevision", JsonValue::from(1)),
    ])
}

pub fn control() -> JsonValue {
    let v = replacing(&configured(), &["type"], Some(JsonValue::from("control")));
    let v = replacing(&v, &["command"], Some(JsonValue::from("stop")));
    replacing(&v, &["leaseDurationMs"], Some(JsonValue::from(1_000)))
}

pub fn state() -> JsonValue {
    JsonValue::object([
        ("protocolVersion", JsonValue::from(1)),
        ("type", JsonValue::from("state")),
        ("requestId", JsonValue::from("request")),
        ("instanceId", JsonValue::from("fixture")),
        ("state", JsonValue::from("stopped")),
        ("stamp", stamp()),
        ("reason", JsonValue::from("")),
    ])
}

pub fn stamp() -> JsonValue {
    JsonValue::object([
        ("captureEpoch", JsonValue::from(1)),
        ("foregroundGeneration", JsonValue::from(2)),
        ("focusGeneration", JsonValue::from(3)),
        ("policyRevision", JsonValue::from(1)),
    ])
}

pub fn target_identity() -> JsonValue {
    JsonValue::object([
        ("deviceId", JsonValue::from("synthetic-device")),
        ("osSessionId", JsonValue::from("synthetic-os-session")),
        ("desktopId", JsonValue::from("synthetic-desktop")),
        ("processId", JsonValue::from(123)),
        ("processStartTime", JsonValue::from("synthetic-birth")),
        ("applicationId", JsonValue::from("fixture.app")),
        ("windowId", JsonValue::from("window")),
        ("windowGeneration", JsonValue::from(1)),
    ])
}

pub fn app_target_identity() -> JsonValue {
    let v = replacing(&target_identity(), &["windowId"], None);
    replacing(&v, &["windowGeneration"], None)
}

pub fn coverage(status: &str, truncated: bool, reasons: &[&str]) -> JsonValue {
    JsonValue::object([
        ("status", JsonValue::from(status)),
        ("truncated", JsonValue::from(truncated)),
        (
            "missingReasons",
            JsonValue::array(reasons.iter().map(|r| JsonValue::from(*r))),
        ),
    ])
}

pub fn complete_coverage() -> JsonValue {
    coverage("complete", false, &[])
}

pub fn text_range(start: f64, length: f64) -> JsonValue {
    JsonValue::object([
        ("unit", JsonValue::from("utf16")),
        ("start", JsonValue::from(start)),
        ("length", JsonValue::from(length)),
    ])
}

pub fn content_gate() -> JsonValue {
    JsonValue::object([
        ("secure", JsonValue::from("safe")),
        ("privateState", JsonValue::from("normal")),
        ("policyRevision", JsonValue::from(1)),
    ])
}

pub fn snapshot(text: &str) -> JsonValue {
    let len = utf16_len(text) as f64;
    JsonValue::object([
        ("kind", JsonValue::from("text.snapshot")),
        ("snapshotId", JsonValue::from("snapshot")),
        ("editSessionId", JsonValue::from("edit")),
        ("nodeId", JsonValue::from("node")),
        ("source", JsonValue::from("fixture")),
        ("scope", JsonValue::from("field")),
        ("valueState", JsonValue::from("read")),
        ("text", JsonValue::from(text)),
        ("range", text_range(0.0, len)),
        ("totalLength", JsonValue::from(len)),
        ("composition", JsonValue::from("unknown")),
        ("captureStartMs", JsonValue::from(10)),
        ("captureEndMs", JsonValue::from(11)),
        ("coverage", complete_coverage()),
    ])
}

pub fn observation(payload: JsonValue) -> JsonValue {
    JsonValue::object([
        ("protocolVersion", JsonValue::from(1)),
        ("type", JsonValue::from("observation")),
        ("eventId", JsonValue::from("event")),
        ("instanceId", JsonValue::from("fixture")),
        ("seq", JsonValue::from(1)),
        ("eventTimeMs", JsonValue::from(10)),
        ("monotonicMs", JsonValue::from(20)),
        (
            "target",
            JsonValue::object([
                ("kind", JsonValue::from("resolved")),
                ("identity", target_identity()),
            ]),
        ),
        ("stamp", stamp()),
        ("actor", JsonValue::from("unknown")),
        ("relatedActionIds", JsonValue::array([])),
        ("payload", payload),
    ])
}

pub fn action(value: JsonValue) -> JsonValue {
    JsonValue::object([
        ("protocolVersion", JsonValue::from(1)),
        ("type", JsonValue::from("action.request")),
        ("requestId", JsonValue::from("request")),
        ("actionId", JsonValue::from("action")),
        ("target", target_identity()),
        ("stamp", stamp()),
        ("snapshotId", JsonValue::from("snapshot")),
        ("backendId", JsonValue::from("fixture")),
        ("runtimeGeneration", JsonValue::from(1)),
        ("deadlineMs", JsonValue::from(1_000)),
        ("sessionId", JsonValue::from("session")),
        ("agentId", JsonValue::from("agent")),
        ("grantId", JsonValue::from("grant")),
        ("leaseId", JsonValue::from("lease")),
        ("mode", JsonValue::from("background")),
        ("expectedCondition", JsonValue::from("fixture-only")),
        ("action", value),
    ])
}

pub fn receipt(dispatch: &str, effect: &str) -> JsonValue {
    JsonValue::object([
        ("protocolVersion", JsonValue::from(1)),
        ("type", JsonValue::from("action.receipt")),
        ("requestId", JsonValue::from("request")),
        ("actionId", JsonValue::from("action")),
        ("dispatch", JsonValue::from(dispatch)),
        ("effect", JsonValue::from(effect)),
        ("startedMs", JsonValue::from(10)),
        ("endedMs", JsonValue::from(11)),
        ("route", JsonValue::from("fixture")),
        ("evidenceIds", JsonValue::array([JsonValue::from("evidence")])),
        ("reason", JsonValue::from("")),
    ])
}

pub fn protocol_failure() -> JsonValue {
    JsonValue::object([
        ("protocolVersion", JsonValue::from(1)),
        ("type", JsonValue::from("error")),
        ("requestId", JsonValue::from("request")),
        ("code", JsonValue::from("stale")),
        ("retryable", JsonValue::from(false)),
    ])
}
