mod common;

use history_contract::{ContractValidator, JsonValue};
use common::*;

fn validator() -> ContractValidator {
    ContractValidator::new().expect("embedded wire.schema.json must load")
}

fn menu_action(source: &str, path: &[&str], truncated: bool) -> JsonValue {
    let mut reasons = vec!["menu-bar-only", "effect-unverified"];
    if truncated {
        reasons.push("menu-title-truncated");
    }
    let payload = JsonValue::object([
        ("kind", JsonValue::from("menu.action")),
        ("source", JsonValue::from(source)),
        ("scope", JsonValue::from("menu-bar")),
        (
            "path",
            JsonValue::array(path.iter().map(|s| JsonValue::from(*s))),
        ),
        ("observedAtMs", JsonValue::from(2_500)),
        ("gate", content_gate()),
        ("secureInput", JsonValue::from("inactive")),
        ("coverage", coverage("partial", truncated, &reasons)),
        ("effect", JsonValue::from("unverified")),
    ]);
    let msg = replacing(
        &observation(payload),
        &["target"],
        Some(JsonValue::object([
            ("kind", JsonValue::from("application")),
            ("identity", app_target_identity()),
        ])),
    );
    replacing(&msg, &["eventTimeMs"], Some(JsonValue::from(2_500)))
}

#[test]
fn valid_menu_actions_roundtrip_and_respect_utf16_budget() {
    let v = validator();
    for source in ["fixture", "ax.menu", "uia.menu"] {
        let msg = menu_action(source, &["File", "Save"], false);
        assert_eq!(v.validate_message(&msg), Ok(()));
        assert_eq!(v.decode_frame(&v.encode_frame(&msg).unwrap()), Ok(msg));
    }

    let truncated = menu_action("uia.menu", &["File", "Export", "PDF..."], true);
    assert_eq!(
        v.decode_frame(&v.encode_frame(&truncated).unwrap()),
        Ok(truncated)
    );

    let depth8 = menu_action(
        "uia.menu",
        &["L1", "L2", "L3", "L4", "L5", "L6", "L7", "L8"],
        false,
    );
    assert_eq!(v.validate_message(&depth8), Ok(()));

    // Supplementary scalar U+1D11E occupies 2 UTF-16 code units; 4 * 128 = 512 UTF-16 code units.
    let seg = "\u{1D11E}".repeat(64);
    let exact_budget = menu_action("uia.menu", &[&seg, &seg, &seg, &seg], false);
    assert_eq!(v.validate_message(&exact_budget), Ok(()));
}

#[test]
fn path_constraints_reject_short_deep_blank_control_and_over_budget() {
    let v = validator();
    let base = menu_action("fixture", &["File", "Save"], false);
    let pair = "\u{1D11E}";
    let seg64 = pair.repeat(64);
    let seg65 = pair.repeat(65);
    let invalid_paths: Vec<Vec<String>> = vec![
        vec![],
        vec!["File".into()],
        vec!["L1", "L2", "L3", "L4", "L5", "L6", "L7", "L8", "L9"]
            .into_iter()
            .map(String::from)
            .collect(),
        vec!["File".into(), "".into()],
        vec!["File".into(), "   ".into()],
        vec!["File".into(), "\u{00A0}\u{3000}\u{FEFF}".into()],
        vec!["File".into(), "Save\nAs".into()],
        vec!["File".into(), "Save\rAs".into()],
        vec!["File".into(), "Save\tAs".into()],
        vec!["File".into(), "Save\u{0000}As".into()],
        vec!["File".into(), "Save\u{007F}As".into()],
        vec!["File".into(), "Save\u{0085}As".into()],
        vec!["File".into(), "Save\u{009F}As".into()],
        vec!["File".into(), seg65],
        vec![seg64.clone(), seg64.clone(), seg64.clone(), seg64, "a".into()],
    ];
    for path in invalid_paths {
        assert_invalid(
            &v,
            &replacing(
                &base,
                &["payload", "path"],
                Some(JsonValue::array(path.into_iter().map(JsonValue::from))),
            ),
        );
    }
}

#[test]
fn target_relation_time_coverage_gate_and_literals_fail_closed() {
    let v = validator();
    let base = menu_action("fixture", &["File", "Save"], false);
    assert_invalid(
        &v,
        &replacing(
            &base,
            &["target"],
            observation(snapshot("中文🙂")).get("target").cloned(),
        ),
    );
    assert_invalid(
        &v,
        &replacing(
            &base,
            &["target"],
            Some(JsonValue::object([
                ("kind", JsonValue::from("unresolved")),
                ("reason", JsonValue::from("focus-unavailable")),
            ])),
        ),
    );
    assert_invalid(
        &v,
        &replacing(
            &base,
            &["target", "identity", "windowId"],
            Some(JsonValue::from("window")),
        ),
    );
    assert_invalid(
        &v,
        &replacing(
            &base,
            &["relation"],
            Some(JsonValue::object([
                ("basis", JsonValue::from("temporal-same-surface")),
                ("evidenceIds", JsonValue::array([JsonValue::from("earlier:1")])),
                ("effect", JsonValue::from("unverified")),
            ])),
        ),
    );
    assert_invalid(
        &v,
        &replacing(&base, &["actor"], Some(JsonValue::from("user-estimated"))),
    );
    assert_invalid(
        &v,
        &replacing(
            &base,
            &["relatedActionIds"],
            Some(JsonValue::array([JsonValue::from("action-1")])),
        ),
    );
    assert_invalid(
        &v,
        &replacing(&base, &["eventTimeMs"], Some(JsonValue::from(2_501))),
    );

    assert_invalid(
        &v,
        &replacing(&base, &["payload", "coverage"], Some(complete_coverage())),
    );
    assert_invalid(
        &v,
        &replacing(
            &base,
            &["payload", "coverage", "missingReasons"],
            Some(JsonValue::array([JsonValue::from("effect-unverified")])),
        ),
    );
    assert_invalid(
        &v,
        &replacing(
            &base,
            &["payload", "coverage", "missingReasons"],
            Some(JsonValue::array([JsonValue::from("menu-bar-only")])),
        ),
    );
    assert_invalid(
        &v,
        &replacing(
            &base,
            &["payload", "coverage", "truncated"],
            Some(JsonValue::Bool(true)),
        ),
    );
    assert_invalid(
        &v,
        &replacing(
            &base,
            &["payload", "coverage", "missingReasons"],
            Some(JsonValue::array([
                JsonValue::from("menu-bar-only"),
                JsonValue::from("effect-unverified"),
                JsonValue::from("menu-title-truncated"),
            ])),
        ),
    );

    assert_invalid(&v, &replacing(&base, &["payload", "gate"], None));
    assert_invalid(
        &v,
        &replacing(&base, &["payload", "gate", "secure"], Some(JsonValue::from("sensitive"))),
    );
    assert_invalid(
        &v,
        &replacing(&base, &["payload", "gate", "privateState"], Some(JsonValue::from("private"))),
    );
    assert_invalid(
        &v,
        &replacing(&base, &["payload", "gate", "policyRevision"], Some(JsonValue::from(2))),
    );
    assert_invalid(
        &v,
        &replacing(&base, &["payload", "source"], Some(JsonValue::from("win32.listen-only"))),
    );
}
