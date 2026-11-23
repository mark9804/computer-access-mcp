mod common;

use access_contract::{ContractLimits, ContractValidator, JsonValue};
use common::*;

fn validator() -> ContractValidator {
    ContractValidator::new().expect("embedded wire.schema.json must load")
}

fn input_activity(source: &str) -> JsonValue {
    let payload = JsonValue::object([
        ("kind", JsonValue::from("input.activity")),
        ("source", JsonValue::from(source)),
        ("scope", JsonValue::from("application")),
        ("intervalStartMs", JsonValue::from(1_000)),
        ("intervalEndMs", JsonValue::from(2_000)),
        (
            "counts",
            JsonValue::object([
                ("pointerReleases", JsonValue::from(1)),
                ("dragSamples", JsonValue::from(0)),
                ("scrollSamples", JsonValue::from(0)),
                ("shortcutPresses", JsonValue::from(0)),
            ]),
        ),
        (
            "gate",
            JsonValue::object([
                ("policyRevision", JsonValue::from(1)),
                ("secureInput", JsonValue::from("inactive")),
                ("targetAttribution", JsonValue::from("event-target-pid")),
                ("detail", JsonValue::from("coarse-counts")),
            ]),
        ),
        (
            "coverage",
            coverage(
                "partial",
                false,
                &[
                    "input-events-partial",
                    "application-only",
                    "effect-unverified",
                ],
            ),
        ),
    ]);
    let msg = replacing(
        &observation(payload),
        &["target"],
        Some(JsonValue::object([
            ("kind", JsonValue::from("application")),
            ("identity", app_target_identity()),
        ])),
    );
    replacing(&msg, &["eventTimeMs"], Some(JsonValue::from(2_000)))
}

#[test]
fn additive_policy_leaves_legacy_absent_and_supports_opt_in() {
    let v = validator();
    let legacy = configure();
    assert_eq!(ContractLimits::PROTOCOL_VERSION, 1);
    assert_eq!(v.validate_message(&legacy), Ok(()));
    let rt = v.decode_frame(&v.encode_frame(&legacy).unwrap()).unwrap();
    assert!(rt.get("policy").unwrap().get("inputActivity").is_none());

    for enabled in [false, true] {
        let msg = replacing(
            &legacy,
            &["policy", "inputActivity"],
            Some(JsonValue::Bool(enabled)),
        );
        assert_eq!(v.decode_frame(&v.encode_frame(&msg).unwrap()), Ok(msg));
    }
    for bad in [JsonValue::Null, JsonValue::from(1), JsonValue::from("true")] {
        assert_invalid(&v, &replacing(&legacy, &["policy", "inputActivity"], Some(bad)));
    }
}

#[test]
fn application_activity_roundtrips_all_valid_sources() {
    let v = validator();
    for source in ["fixture", "cg.listen-only", "win32.listen-only"] {
        let msg = input_activity(source);
        assert_eq!(v.validate_message(&msg), Ok(()));
        assert_eq!(v.decode_frame(&v.encode_frame(&msg).unwrap()), Ok(msg.clone()));
        assert!(msg
            .get("target")
            .unwrap()
            .get("identity")
            .unwrap()
            .get("windowId")
            .is_none());
        assert_eq!(
            msg.get("target")
                .unwrap()
                .get("identity")
                .unwrap()
                .as_obj()
                .unwrap()
                .len(),
            6
        );
    }

    let mut cap = input_activity("win32.listen-only");
    cap = replacing(
        &cap,
        &["payload", "counts", "pointerReleases"],
        Some(JsonValue::from(256)),
    );
    cap = replacing(
        &cap,
        &["payload", "coverage", "truncated"],
        Some(JsonValue::Bool(true)),
    );
    assert_eq!(v.validate_message(&cap), Ok(()));
}

#[test]
fn gate_required_for_all_sources_without_fixture_bypass() {
    let v = validator();
    for source in ["fixture", "cg.listen-only", "win32.listen-only"] {
        let msg = input_activity(source);
        for path in [
            vec!["payload", "gate"],
            vec!["payload", "gate", "policyRevision"],
            vec!["payload", "gate", "secureInput"],
            vec!["payload", "gate", "targetAttribution"],
            vec!["payload", "gate", "detail"],
        ] {
            assert_invalid(&v, &replacing(&msg, &path, None));
        }
        assert_invalid(
            &v,
            &replacing(&msg, &["payload", "gate", "policyRevision"], Some(JsonValue::from(2))),
        );
        assert_invalid(
            &v,
            &replacing(&msg, &["payload", "gate", "secureInput"], Some(JsonValue::from("unknown"))),
        );
        assert_invalid(
            &v,
            &replacing(
                &msg,
                &["payload", "gate", "targetAttribution"],
                Some(JsonValue::from("foreground-pid")),
            ),
        );
        assert_invalid(
            &v,
            &replacing(&msg, &["payload", "gate", "detail"], Some(JsonValue::from("raw-events"))),
        );
    }
}

#[test]
fn time_count_coverage_and_actor_fail_closed() {
    let v = validator();
    let msg = input_activity("fixture");
    let mutations: [(&[&str], JsonValue); 15] = [
        (&["payload", "intervalStartMs"], JsonValue::from(1_001)),
        (&["payload", "intervalEndMs"], JsonValue::from(2_001)),
        (&["eventTimeMs"], JsonValue::from(1_000)),
        (&["payload", "counts", "pointerReleases"], JsonValue::from(0)),
        (&["payload", "counts", "pointerReleases"], JsonValue::from(257)),
        (&["payload", "counts", "pointerReleases"], JsonValue::from(1.5)),
        (&["payload", "counts", "pointerReleases"], JsonValue::Bool(true)),
        (&["payload", "counts", "scrollSamples"], JsonValue::from(256)),
        (&["payload", "coverage", "status"], JsonValue::from("complete")),
        (&["payload", "coverage", "status"], JsonValue::from("unknown")),
        (&["payload", "coverage", "missingReasons"], JsonValue::array([])),
        (&["actor"], JsonValue::from("user-estimated")),
        (&["actor"], JsonValue::from("agent")),
        (
            &["relatedActionIds"],
            JsonValue::array([JsonValue::from("synthetic-action")]),
        ),
        (&["payload", "source"], JsonValue::from("uia.text")),
    ];
    for (path, val) in mutations {
        assert_invalid(&v, &replacing(&msg, path, Some(val)));
    }
}

#[test]
fn application_identity_cannot_be_used_for_other_payloads() {
    let v = validator();
    let msg = input_activity("fixture");
    for payload in [
        snapshot("中文🙂"),
        JsonValue::object([
            ("kind", JsonValue::from("text.changed")),
            ("baseSnapshotId", JsonValue::from("before")),
            ("after", snapshot("中文🙂")),
        ]),
        JsonValue::object([
            ("kind", JsonValue::from("gap")),
            ("reason", JsonValue::from("stale")),
            ("count", JsonValue::from(1)),
        ]),
        JsonValue::object([
            ("kind", JsonValue::from("context.changed")),
            ("reason", JsonValue::from("application")),
        ]),
    ] {
        assert_invalid(&v, &replacing(&msg, &["payload"], Some(payload)));
    }
    assert_invalid(
        &v,
        &replacing(
            &msg,
            &["target"],
            observation(snapshot("中文🙂")).get("target").cloned(),
        ),
    );
    assert_invalid(
        &v,
        &replacing(
            &msg,
            &["target"],
            Some(JsonValue::object([
                ("kind", JsonValue::from("unresolved")),
                ("reason", JsonValue::from("not-observed")),
            ])),
        ),
    );
}
