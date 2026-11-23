mod common;

use access_contract::{
    utf16_len, ContractLimits, ContractValidator, JsonValue, ProtocolError, SchemaValidator,
    ValidationResult,
};
use common::*;

fn validator() -> ContractValidator {
    ContractValidator::new().expect("embedded wire.schema.json must load")
}

fn surface_snapshot(source: &str) -> JsonValue {
    let payload = JsonValue::object([
        ("kind", JsonValue::from("surface.snapshot")),
        ("snapshotId", JsonValue::from("surf-snap-1")),
        ("surfaceId", JsonValue::from("surface-1")),
        ("revision", JsonValue::from(1)),
        ("source", JsonValue::from(source)),
        ("scope", JsonValue::from("window")),
        ("mode", JsonValue::from("full")),
        (
            "nodes",
            JsonValue::array([
                JsonValue::object([
                    ("id", JsonValue::from("root")),
                    ("role", JsonValue::from("container")),
                    ("axRole", JsonValue::from("AXWindow")),
                    ("observedAtMs", JsonValue::from(10)),
                    (
                        "bounds",
                        JsonValue::object([
                            ("x", JsonValue::from(0)),
                            ("y", JsonValue::from(0)),
                            ("width", JsonValue::from(800)),
                            ("height", JsonValue::from(600)),
                        ]),
                    ),
                    ("boundsObservedAtMs", JsonValue::from(10)),
                ]),
                JsonValue::object([
                    ("id", JsonValue::from("editor")),
                    ("parentId", JsonValue::from("root")),
                    ("role", JsonValue::from("editable")),
                    ("axRole", JsonValue::from("AXTextArea")),
                    ("text", JsonValue::from("hello 🙂")),
                    ("focused", JsonValue::from(true)),
                    ("observedAtMs", JsonValue::from(11)),
                ]),
            ]),
        ),
        (
            "geometry",
            JsonValue::object([
                ("coordinateSpace", JsonValue::from("window-top-left-point")),
                (
                    "windowSize",
                    JsonValue::object([
                        ("width", JsonValue::from(800)),
                        ("height", JsonValue::from(600)),
                    ]),
                ),
                ("observedAtMs", JsonValue::from(10)),
            ]),
        ),
        ("captureStartMs", JsonValue::from(10)),
        ("captureEndMs", JsonValue::from(11)),
        ("coverage", complete_coverage()),
        ("gate", content_gate()),
        ("consistency", JsonValue::from("non-atomic")),
    ]);
    observation(payload)
}

fn selection_snapshot(source: &str, text: &str) -> JsonValue {
    let payload = JsonValue::object([
        ("kind", JsonValue::from("selection.snapshot")),
        ("snapshotId", JsonValue::from("sel-1")),
        ("surfaceId", JsonValue::from("surface-1")),
        ("source", JsonValue::from(source)),
        ("scope", JsonValue::from("selection")),
        ("text", JsonValue::from(text)),
        ("range", text_range(4.0, utf16_len(text) as f64)),
        ("captureStartMs", JsonValue::from(10)),
        ("captureEndMs", JsonValue::from(11)),
        (
            "coverage",
            coverage("partial", false, &["selection-only"]),
        ),
        ("gate", content_gate()),
    ]);
    observation(payload)
}

fn input_text(source: &str, event_kind: &str, text: &str, modifiers: &[&str]) -> JsonValue {
    let payload = JsonValue::object([
        ("kind", JsonValue::from("input.text")),
        ("source", JsonValue::from(source)),
        ("scope", JsonValue::from("field")),
        ("eventKind", JsonValue::from(event_kind)),
        ("text", JsonValue::from(text)),
        (
            "modifiers",
            JsonValue::array(modifiers.iter().map(|m| JsonValue::from(*m))),
        ),
        ("intervalStartMs", JsonValue::from(1_000)),
        ("intervalEndMs", JsonValue::from(1_500)),
        ("eventCount", JsonValue::from(2)),
        ("surfaceId", JsonValue::from("surface-1")),
        ("gate", content_gate()),
        ("secureInput", JsonValue::from("inactive")),
        (
            "coverage",
            coverage(
                "partial",
                false,
                &["input-events-partial", "effect-unverified"],
            ),
        ),
        ("effect", JsonValue::from("unverified")),
    ]);
    replacing(
        &observation(payload),
        &["eventTimeMs"],
        Some(JsonValue::from(1_500)),
    )
}

#[test]
fn all_top_level_branches_and_actions() {
    let v = validator();
    let fixtures = vec![
        hello(),
        configure(),
        configured(),
        control(),
        state(),
        observation(snapshot("中文🙂")),
        observation(JsonValue::object([
            ("kind", JsonValue::from("gap")),
            ("reason", JsonValue::from("timeout")),
            ("count", JsonValue::from(1)),
        ])),
        observation(JsonValue::object([
            ("kind", JsonValue::from("context.changed")),
            ("reason", JsonValue::from("focus")),
        ])),
        observation(JsonValue::object([
            ("kind", JsonValue::from("text.changed")),
            ("baseSnapshotId", JsonValue::from("before")),
            ("after", snapshot("中文🙂")),
        ])),
        surface_snapshot("uia.tree"),
        selection_snapshot("uia.text", "选中🙂"),
        input_text("win32.unicode", "text", "abc", &["shift"]),
        action(JsonValue::object([
            ("kind", JsonValue::from("text.set")),
            ("text", JsonValue::from("合成🙂")),
        ])),
        action(JsonValue::object([
            ("kind", JsonValue::from("pointer.click")),
            (
                "point",
                JsonValue::object([
                    ("x", JsonValue::from(-2.5)),
                    ("y", JsonValue::from(3.25)),
                    ("space", JsonValue::from("window-point")),
                    ("transformId", JsonValue::from("mapping")),
                ]),
            ),
            ("button", JsonValue::from("left")),
            ("count", JsonValue::from(2)),
        ])),
        action(JsonValue::object([
            ("kind", JsonValue::from("key.chord")),
            (
                "keys",
                JsonValue::array([JsonValue::from("Meta"), JsonValue::from("A")]),
            ),
        ])),
        action(JsonValue::object([
            ("kind", JsonValue::from("view.zoom")),
            ("subject", JsonValue::from("page")),
            ("scale", JsonValue::from(1.25)),
        ])),
        receipt("dispatched", "confirmed"),
        protocol_failure(),
    ];

    for fixture in fixtures {
        assert_eq!(v.validate_message(&fixture), Ok(()));
        let encoded = v.encode_frame(&fixture).expect("encode_frame");
        let decoded = v.decode_frame(&encoded).expect("decode_frame");
        assert_eq!(decoded, fixture);
    }
}

#[test]
fn closed_objects_and_required_fields_at_every_layer() {
    let v = validator();
    let base = observation(snapshot("中文🙂"));
    for path in [
        vec!["unknown"],
        vec!["stamp", "unknown"],
        vec!["target", "unknown"],
        vec!["target", "identity", "unknown"],
        vec!["payload", "unknown"],
        vec!["payload", "coverage", "unknown"],
        vec!["payload", "range", "unknown"],
    ] {
        assert_invalid(
            &v,
            &replacing(&base, &path, Some(JsonValue::from("synthetic-private-body"))),
        );
    }
    for path in [
        vec!["protocolVersion"],
        vec!["seq"],
        vec!["stamp", "captureEpoch"],
        vec!["target", "identity", "processId"],
        vec!["payload", "captureEndMs"],
    ] {
        assert_invalid(&v, &replacing(&base, &path, None));
    }
    assert_invalid(
        &v,
        &replacing(&hello(), &["capabilities"], Some(JsonValue::object::<[(&str, JsonValue); 0], &str>([]))),
    );
    assert_invalid(&v, &replacing(&base, &["target"], Some(JsonValue::Null)));
}

#[test]
fn boolean_is_not_number_or_integer_or_numeric_constant() {
    let v = validator();
    let obs = observation(snapshot("中文🙂"));
    assert_invalid(&v, &replacing(&obs, &["seq"], Some(JsonValue::Bool(true))));
    assert_invalid(
        &v,
        &replacing(
            &obs,
            &["payload", "coverage", "truncated"],
            Some(JsonValue::from(0)),
        ),
    );
    assert_invalid(
        &v,
        &replacing(&hello(), &["maxFrameBytes"], Some(JsonValue::Bool(true))),
    );
    assert_invalid(
        &v,
        &replacing(&protocol_failure(), &["retryable"], Some(JsonValue::from(0))),
    );
    assert_invalid(
        &v,
        &replacing(&configure(), &["policy", "enabled"], Some(JsonValue::from(1))),
    );
    let zoom = action(JsonValue::object([
        ("kind", JsonValue::from("view.zoom")),
        ("subject", JsonValue::from("page")),
        ("scale", JsonValue::Bool(true)),
    ]));
    assert_invalid(&v, &replacing(&zoom, &["runtimeGeneration"], Some(JsonValue::from(1))));
    assert_eq!(
        JsonValue::parse(b"[true,1,false,0]"),
        Ok(JsonValue::array([
            JsonValue::Bool(true),
            JsonValue::Number(1.0),
            JsonValue::Bool(false),
            JsonValue::Number(0.0),
        ]))
    );
}

#[test]
fn safe_integer_bounds_and_finite_numbers() {
    let v = validator();
    let obs = observation(snapshot("中文🙂"));
    assert_eq!(
        v.validate_message(&replacing(
            &obs,
            &["seq"],
            Some(JsonValue::Number(ContractLimits::MAX_SAFE_INTEGER))
        )),
        Ok(())
    );
    for num in [
        ContractLimits::MAX_SAFE_INTEGER + 1.0,
        0.0,
        -1.0,
        1.5,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
    ] {
        assert_invalid(&v, &replacing(&obs, &["seq"], Some(JsonValue::Number(num))));
    }
    for pid in [0.0, 2_147_483_648.0] {
        assert_invalid(
            &v,
            &replacing(
                &obs,
                &["target", "identity", "processId"],
                Some(JsonValue::Number(pid)),
            ),
        );
    }

    let hello_json = hello().canonical_string().unwrap();
    let overflow = hello_json.replace("65536", "1e400");
    assert_eq!(
        v.decode_frame(overflow.as_bytes()),
        Err(ProtocolError::InvalidMessage)
    );
    let scientific = hello_json.replace("65536", "6.5536e4");
    assert_eq!(v.decode_frame(scientific.as_bytes()), Ok(hello()));

    // Canonical formatting checks: -0.0 -> 0, '/' not escaped.
    let neg_zero = JsonValue::object([
        ("a", JsonValue::Number(-0.0)),
        ("b", JsonValue::from("path/with/slash")),
    ]);
    assert_eq!(
        neg_zero.canonical_string().unwrap(),
        r#"{"a":0,"b":"path/with/slash"}"#
    );
}

#[test]
fn version_errors_precedence_and_parse_errors_first() {
    let v = validator();
    for version in [
        JsonValue::from(2),
        JsonValue::from(0),
        JsonValue::from("1"),
        JsonValue::Bool(true),
        JsonValue::Null,
        JsonValue::array([]),
        JsonValue::object::<[(&str, JsonValue); 0], &str>([]),
    ] {
        let candidate = JsonValue::object([
            ("protocolVersion", version),
            ("body", JsonValue::from("never-echo-this-synthetic-body")),
        ]);
        assert_eq!(
            v.validate_message(&candidate),
            Err(ProtocolError::UnsupportedVersion)
        );
    }
    for root in [
        JsonValue::Null,
        JsonValue::array([]),
        JsonValue::from("synthetic"),
        JsonValue::from(1),
        JsonValue::Bool(true),
        JsonValue::object::<[(&str, JsonValue); 0], &str>([]),
    ] {
        assert_invalid(&v, &root);
    }

    // Parse-level errors (lone surrogate, depth 33) MUST fail BEFORE protocolVersion check!
    assert_eq!(
        v.decode_frame(br#"{"protocolVersion":2,"bad":"\ud800"}"#),
        Err(ProtocolError::InvalidMessage)
    );
    let deep_v2 = format!(
        r#"{{"protocolVersion":2,"bad":{}0{}}}"#,
        "[".repeat(33),
        "]".repeat(33)
    );
    assert_eq!(
        v.decode_frame(deep_v2.as_bytes()),
        Err(ProtocolError::InvalidMessage)
    );

    for err in [
        ProtocolError::InvalidMessage,
        ProtocolError::UnsupportedVersion,
        ProtocolError::FrameTooLarge,
    ] {
        assert_eq!(err.to_string(), err.code());
        assert_eq!(
            ValidationResult::Invalid(err).to_json_value(),
            JsonValue::object([
                ("code", JsonValue::from(err.code())),
                ("valid", JsonValue::Bool(false)),
            ])
        );
    }
}

#[test]
fn unicode_and_utf16_range_length_without_normalization() {
    let v = validator();
    for text in [
        "",
        "中文测试",
        "🙂",
        "👩🏽‍💻",
        "e\u{0301}",
        "é",
        "行一\n行二\t\u{0}",
        "ＡＢＣ",
    ] {
        let msg = observation(snapshot(text));
        let encoded = v.encode_frame(&msg).expect("encode");
        assert_eq!(v.decode_frame(&encoded), Ok(msg));
    }

    let emoji = snapshot("🙂");
    assert_invalid(
        &v,
        &observation(replacing(&emoji, &["range", "length"], Some(JsonValue::from(1)))),
    );
    let combining = snapshot("e\u{0301}");
    assert_invalid(
        &v,
        &observation(replacing(
            &combining,
            &["range", "length"],
            Some(JsonValue::from(1)),
        )),
    );
    assert_ne!(JsonValue::from("é"), JsonValue::from("e\u{0301}"));
    let changed = JsonValue::object([
        ("kind", JsonValue::from("text.changed")),
        ("baseSnapshotId", JsonValue::from("é")),
        (
            "after",
            replacing(&snapshot("中文🙂"), &["snapshotId"], Some(JsonValue::from("e\u{0301}"))),
        ),
    ]);
    assert_eq!(v.validate_message(&observation(changed)), Ok(()));
}

#[test]
fn utf16_text_and_identifier_budgets() {
    let v = validator();
    assert_eq!(
        v.validate_message(&observation(snapshot(&"🙂".repeat(4_096)))),
        Ok(())
    );
    assert_eq!(
        v.validate_message(&observation(snapshot(&"中".repeat(8_192)))),
        Ok(())
    );
    assert_invalid(&v, &observation(snapshot(&"🙂".repeat(4_097))));
    assert_eq!(
        v.validate_message(&replacing(
            &hello(),
            &["instanceId"],
            Some(JsonValue::from("🙂".repeat(64)))
        )),
        Ok(())
    );
    assert_invalid(
        &v,
        &replacing(
            &hello(),
            &["instanceId"],
            Some(JsonValue::from("🙂".repeat(65))),
        ),
    );
}

#[test]
fn strict_json_utf8_bom_surrogates_and_duplicate_keys() {
    let v = validator();
    let invalid = [
        "",
        " ",
        "{",
        "null null",
        r#"{"a":1,}"#,
        "[1,]",
        "+1",
        "01",
        "-.5",
        "1.",
        "1e",
        "NaN",
        "Infinity",
        "\"raw\nnewline\"",
        "\"raw\x00null\"",
        r#""\x20""#,
        r#""\uD800""#,
        r#""\uDC00""#,
        r#""\uD800x""#,
        r#""\uD800\u0041""#,
        r#""\uZZZZ""#,
    ];
    for input in invalid {
        assert_eq!(
            JsonValue::parse(input.as_bytes()),
            Err(ProtocolError::InvalidMessage),
            "expected parse error for {:?}",
            input
        );
    }
    for raw in [
        &[0xff][..],
        &[0xc0, 0xaf][..],
        &[0x22, 0xed, 0xa0, 0x80, 0x22][..],
    ] {
        assert_eq!(JsonValue::parse(raw), Err(ProtocolError::InvalidMessage));
    }
    assert_eq!(
        JsonValue::parse(br#""\uD83D\uDE42""#),
        Ok(JsonValue::from("🙂"))
    );
    assert_eq!(
        JsonValue::parse(br#"{"x":1,"x":2}"#),
        Ok(JsonValue::object([("x", JsonValue::from(2))]))
    );

    let mut bom = vec![0xef, 0xbb, 0xbf];
    bom.extend_from_slice(&hello().canonical_bytes().unwrap());
    assert_eq!(v.decode_frame(&bom), Err(ProtocolError::InvalidMessage));
}

#[test]
fn read_vs_unavailable_and_redacted_text_states() {
    let v = validator();
    assert_eq!(v.validate_message(&observation(snapshot(""))), Ok(()));
    for key in ["text", "range"] {
        assert_invalid(&v, &observation(replacing(&snapshot("中文🙂"), &[key], None)));
    }
    assert_invalid(
        &v,
        &observation(replacing(&snapshot("中文🙂"), &["text"], Some(JsonValue::Null))),
    );
    assert_invalid(
        &v,
        &observation(replacing(
            &snapshot("中文🙂"),
            &["range", "length"],
            Some(JsonValue::from(0)),
        )),
    );

    for state_name in ["unavailable", "redacted"] {
        let mut unavail = replacing(&snapshot("中文🙂"), &["valueState"], Some(JsonValue::from(state_name)));
        unavail = replacing(&unavail, &["text"], None);
        unavail = replacing(&unavail, &["range"], None);
        unavail = replacing(
            &unavail,
            &["coverage"],
            Some(coverage("partial", false, &["filtered"])),
        );
        assert_eq!(v.validate_message(&observation(unavail.clone())), Ok(()));
        for (key, val) in [
            ("text", JsonValue::from("")),
            ("range", text_range(0.0, 0.0)),
            ("selection", text_range(0.0, 0.0)),
        ] {
            assert_invalid(&v, &observation(replacing(&unavail, &[key], Some(val))));
        }
        assert_invalid(
            &v,
            &observation(replacing(&unavail, &["coverage"], Some(complete_coverage()))),
        );
    }
}

#[test]
fn coverage_capture_times_and_field_scope_bounds() {
    let v = validator();
    for bad_cov in [
        coverage("complete", true, &[]),
        coverage("complete", false, &["missing"]),
        coverage("partial", false, &[]),
        coverage("unknown", false, &[]),
    ] {
        assert_invalid(
            &v,
            &observation(replacing(&snapshot("中文🙂"), &["coverage"], Some(bad_cov))),
        );
    }
    for st in ["partial", "unknown"] {
        assert_eq!(
            v.validate_message(&observation(replacing(
                &snapshot("中文🙂"),
                &["coverage"],
                Some(coverage(st, false, &["synthetic-gap"])),
            ))),
            Ok(())
        );
    }
    assert_invalid(
        &v,
        &observation(replacing(
            &snapshot("中文🙂"),
            &["captureEndMs"],
            Some(JsonValue::from(9)),
        )),
    );
    assert_eq!(
        v.validate_message(&observation(replacing(
            &snapshot("中文🙂"),
            &["captureEndMs"],
            Some(JsonValue::from(10)),
        ))),
        Ok(())
    );

    assert_invalid(
        &v,
        &observation(replacing(&snapshot("中文🙂"), &["totalLength"], None)),
    );
    assert_invalid(
        &v,
        &observation(replacing(
            &snapshot("中文🙂"),
            &["range", "start"],
            Some(JsonValue::from(1)),
        )),
    );
    assert_invalid(
        &v,
        &observation(replacing(
            &snapshot("中文🙂"),
            &["totalLength"],
            Some(JsonValue::from(99)),
        )),
    );

    let mut ranged = replacing(
        &snapshot("中文🙂"),
        &["scope"],
        Some(JsonValue::from("accessible-range")),
    );
    ranged = replacing(&ranged, &["range", "start"], Some(JsonValue::from(20)));
    ranged = replacing(&ranged, &["totalLength"], Some(JsonValue::from(30)));
    assert_eq!(v.validate_message(&observation(ranged.clone())), Ok(()));
    assert_invalid(
        &v,
        &observation(replacing(&ranged, &["totalLength"], Some(JsonValue::from(21)))),
    );
    assert_eq!(
        v.validate_message(&observation(replacing(&ranged, &["totalLength"], None))),
        Ok(())
    );
    assert_eq!(
        v.validate_message(&observation(replacing(
            &ranged,
            &["selection"],
            Some(text_range(29.0, 1.0)),
        ))),
        Ok(())
    );
    assert_invalid(
        &v,
        &observation(replacing(
            &ranged,
            &["selection"],
            Some(text_range(30.0, 1.0)),
        )),
    );
}

#[test]
fn resolved_target_changed_base_gap_provider_relation_and_agent() {
    let v = validator();
    let unresolved = JsonValue::object([
        ("kind", JsonValue::from("unresolved")),
        ("reason", JsonValue::from("not-observed")),
    ]);
    assert_invalid(
        &v,
        &replacing(&observation(snapshot("中文🙂")), &["target"], Some(unresolved.clone())),
    );
    let same_changed = JsonValue::object([
        ("kind", JsonValue::from("text.changed")),
        ("baseSnapshotId", JsonValue::from("snapshot")),
        ("after", snapshot("中文🙂")),
    ]);
    assert_invalid(&v, &observation(same_changed));

    let gap = observation(JsonValue::object([
        ("kind", JsonValue::from("gap")),
        ("reason", JsonValue::from("stale")),
        ("count", JsonValue::from(1)),
    ]));
    assert_eq!(
        v.validate_message(&replacing(&gap, &["target"], Some(unresolved))),
        Ok(())
    );
    assert_eq!(
        v.validate_message(&replacing(
            &gap,
            &["payload", "providerApplicationId"],
            Some(JsonValue::from("code.exe")),
        )),
        Ok(())
    );
    assert_invalid(
        &v,
        &replacing(
            &gap,
            &["payload", "providerApplicationId"],
            Some(JsonValue::from("bad provider.exe")),
        ),
    );

    let agent = replacing(&gap, &["actor"], Some(JsonValue::from("agent")));
    assert_invalid(&v, &agent);
    assert_eq!(
        v.validate_message(&replacing(
            &agent,
            &["relatedActionIds"],
            Some(JsonValue::array([JsonValue::from("action")])),
        )),
        Ok(())
    );

    // Relation rules: allowed on content kinds, unique non-self evidenceIds, forbidden on gap.
    let valid_rel = JsonValue::object([
        ("basis", JsonValue::from("temporal-same-surface")),
        (
            "evidenceIds",
            JsonValue::array([JsonValue::from("prev-1"), JsonValue::from("prev-2")]),
        ),
        ("effect", JsonValue::from("unverified")),
    ]);
    assert_eq!(
        v.validate_message(&replacing(
            &observation(snapshot("中文🙂")),
            &["relation"],
            Some(valid_rel.clone()),
        )),
        Ok(())
    );
    assert_invalid(&v, &replacing(&gap, &["relation"], Some(valid_rel.clone())));
    assert_invalid(
        &v,
        &replacing(
            &observation(snapshot("中文🙂")),
            &["relation"],
            Some(replacing(
                &valid_rel,
                &["evidenceIds"],
                Some(JsonValue::array([
                    JsonValue::from("dup"),
                    JsonValue::from("dup"),
                ])),
            )),
        ),
    );
    assert_invalid(
        &v,
        &replacing(
            &observation(snapshot("中文🙂")),
            &["relation"],
            Some(replacing(
                &valid_rel,
                &["evidenceIds"],
                Some(JsonValue::array([JsonValue::from("event")])),
            )),
        ),
    );
}

#[test]
fn receipt_dispatch_effect_matrix_and_times() {
    let v = validator();
    for dispatch in ["not-dispatched", "dispatched", "partial", "unknown"] {
        for effect in ["confirmed", "unverifiable", "uncertain", "refused"] {
            let candidate = receipt(dispatch, effect);
            let valid = !(effect == "confirmed"
                && (dispatch == "not-dispatched" || dispatch == "unknown"))
                && !(effect == "refused" && dispatch != "not-dispatched")
                && !(dispatch == "unknown" && effect != "uncertain");
            if valid {
                assert_eq!(v.validate_message(&candidate), Ok(()));
            } else {
                assert_invalid(&v, &candidate);
            }
        }
    }
    assert_invalid(
        &v,
        &replacing(&receipt("dispatched", "confirmed"), &["evidenceIds"], Some(JsonValue::array([]))),
    );
    assert_invalid(
        &v,
        &replacing(&receipt("dispatched", "confirmed"), &["endedMs"], Some(JsonValue::from(9))),
    );
    assert_eq!(
        v.validate_message(&replacing(
            &receipt("dispatched", "confirmed"),
            &["endedMs"],
            Some(JsonValue::from(10)),
        )),
        Ok(())
    );
}

#[test]
fn policy_validation_and_collection_budgets() {
    let v = validator();
    assert_invalid(
        &v,
        &replacing(&configure(), &["policy", "maxWaitMs"], Some(JsonValue::from(19))),
    );
    assert_eq!(
        v.validate_message(&replacing(
            &configure(),
            &["policy", "maxWaitMs"],
            Some(JsonValue::from(20)),
        )),
        Ok(())
    );
    // Valid Windows & macOS IDs, overlap between allow/deny allowed, case-insensitive duplicate within list rejected.
    let mut cfg = replacing(
        &configure(),
        &["policy", "allowedApplicationIds"],
        Some(JsonValue::array([
            JsonValue::from("code.exe"),
            JsonValue::from("microsoft.windowsterminal"),
        ])),
    );
    cfg = replacing(
        &cfg,
        &["policy", "excludedApplicationIds"],
        Some(JsonValue::array([
            JsonValue::from("code.exe"),
            JsonValue::from("1password.exe"),
        ])),
    );
    assert_eq!(v.validate_message(&cfg), Ok(()));

    assert_invalid(
        &v,
        &replacing(
            &configure(),
            &["policy", "allowedApplicationIds"],
            Some(JsonValue::array([
                JsonValue::from("Code.exe"),
                JsonValue::from("code.exe"),
            ])),
        ),
    );
    assert_invalid(
        &v,
        &replacing(
            &configure(),
            &["policy", "excludedApplicationIds"],
            Some(JsonValue::array([JsonValue::from("-invalid.exe")])),
        ),
    );
    assert_invalid(
        &v,
        &replacing(
            &configure(),
            &["policy", "allowedApplicationIds"],
            Some(JsonValue::array(
                (0..65).map(|i| JsonValue::from(format!("app-{i}.exe"))),
            )),
        ),
    );
    assert_invalid(
        &v,
        &replacing(
            &observation(snapshot("中文🙂")),
            &["relatedActionIds"],
            Some(JsonValue::array((0..17).map(|_| JsonValue::from("action")))),
        ),
    );
    assert_invalid(
        &v,
        &action(JsonValue::object([
            ("kind", JsonValue::from("key.chord")),
            ("keys", JsonValue::array([])),
        ])),
    );
}

#[test]
fn surface_snapshot_ancestry_geometry_diff_and_ax_role_rules() {
    let v = validator();
    let full = surface_snapshot("uia.tree");
    assert_eq!(v.validate_message(&full), Ok(()));

    // Invalid axRole
    let bad_role = JsonValue::object([
        ("id", JsonValue::from("root")),
        ("role", JsonValue::from("container")),
        ("axRole", JsonValue::from("UIAEdit")),
        ("observedAtMs", JsonValue::from(10)),
    ]);
    assert_invalid(
        &v,
        &replacing(&full, &["payload", "nodes"], Some(JsonValue::array([bad_role]))),
    );

    // Cycle in parentId
    let cycle_nodes = JsonValue::array([
        JsonValue::object([
            ("id", JsonValue::from("a")),
            ("parentId", JsonValue::from("b")),
            ("role", JsonValue::from("container")),
            ("observedAtMs", JsonValue::from(10)),
        ]),
        JsonValue::object([
            ("id", JsonValue::from("b")),
            ("parentId", JsonValue::from("a")),
            ("role", JsonValue::from("container")),
            ("observedAtMs", JsonValue::from(10)),
        ]),
    ]);
    assert_invalid(&v, &replacing(&full, &["payload", "nodes"], Some(cycle_nodes)));

    // Missing parentId
    let orphan = JsonValue::array([JsonValue::object([
        ("id", JsonValue::from("a")),
        ("parentId", JsonValue::from("missing")),
        ("role", JsonValue::from("text")),
        ("observedAtMs", JsonValue::from(10)),
    ])]);
    assert_invalid(&v, &replacing(&full, &["payload", "nodes"], Some(orphan)));

    // Bounds without geometry
    assert_invalid(&v, &replacing(&full, &["payload", "geometry"], None));

    // Multiple focused nodes
    let two_focused = JsonValue::array([
        JsonValue::object([
            ("id", JsonValue::from("a")),
            ("role", JsonValue::from("editable")),
            ("focused", JsonValue::from(true)),
            ("observedAtMs", JsonValue::from(10)),
        ]),
        JsonValue::object([
            ("id", JsonValue::from("b")),
            ("role", JsonValue::from("editable")),
            ("focused", JsonValue::from(true)),
            ("observedAtMs", JsonValue::from(10)),
        ]),
    ]);
    assert_invalid(&v, &replacing(&full, &["payload", "nodes"], Some(two_focused)));

    // Valid diff snapshot
    let mut diff = replacing(&full, &["payload", "mode"], Some(JsonValue::from("diff")));
    diff = replacing(&diff, &["payload", "revision"], Some(JsonValue::from(2)));
    diff = replacing(&diff, &["payload", "baseRevision"], Some(JsonValue::from(1)));
    diff = replacing(
        &diff,
        &["payload", "changes"],
        Some(JsonValue::object([
            ("added", JsonValue::array([JsonValue::from("editor")])),
            ("updated", JsonValue::array([JsonValue::from("root")])),
            ("removed", JsonValue::array([JsonValue::from("old-node")])),
        ])),
    );
    assert_eq!(v.validate_message(&diff), Ok(()));

    // Diff with partial coverage MUST NOT have removed entries
    let partial_diff = replacing(
        &diff,
        &["payload", "coverage"],
        Some(coverage("partial", false, &["surface-call-budget"])),
    );
    assert_invalid(&v, &partial_diff);

    // Full mode MUST NOT have changes or baseRevision
    assert_invalid(
        &v,
        &replacing(&full, &["payload", "baseRevision"], Some(JsonValue::from(1))),
    );
}

#[test]
fn selection_and_input_text_semantics() {
    let v = validator();
    let sel = selection_snapshot("uia.text", "hello 🙂");
    assert_eq!(v.validate_message(&sel), Ok(()));
    assert_invalid(
        &v,
        &replacing(&sel, &["payload", "range", "length"], Some(JsonValue::from(7))),
    );
    assert_invalid(
        &v,
        &replacing(&sel, &["payload", "coverage"], Some(complete_coverage())),
    );

    assert_eq!(
        v.validate_message(&input_text("win32.unicode", "text", "hello", &[])),
        Ok(())
    );
    assert_eq!(
        v.validate_message(&input_text("win32.unicode", "return", "", &[])),
        Ok(())
    );
    assert_eq!(
        v.validate_message(&input_text("win32.unicode", "shortcut", "", &["control"])),
        Ok(())
    );
    // text eventKind cannot have command/control or empty text
    assert_invalid(&v, &input_text("win32.unicode", "text", "", &[]));
    assert_invalid(&v, &input_text("win32.unicode", "text", "c", &["control"]));
    // shortcut eventKind requires empty text and command/control
    assert_invalid(&v, &input_text("win32.unicode", "shortcut", "c", &["control"]));
    assert_invalid(&v, &input_text("win32.unicode", "shortcut", "", &["shift"]));
    // duplicate modifier
    assert_invalid(&v, &input_text("win32.unicode", "text", "a", &["shift", "shift"]));
    // interval > 5000ms
    assert_invalid(
        &v,
        &replacing(
            &replacing(
                &input_text("win32.unicode", "text", "a", &[]),
                &["payload", "intervalEndMs"],
                Some(JsonValue::from(6_001)),
            ),
            &["eventTimeMs"],
            Some(JsonValue::from(6_001)),
        ),
    );
}

#[test]
fn schema_depth_one_of_and_missing_references() {
    let empty_root = JsonValue::object([
        ("$defs", JsonValue::object::<[(&str, JsonValue); 0], &str>([])),
        ("type", JsonValue::from("boolean")),
    ]);
    let schema = SchemaValidator::new(empty_root.clone()).unwrap();
    assert_eq!(schema.validate_node(&JsonValue::Bool(true), &empty_root, 32), Ok(()));
    assert_eq!(
        schema.validate_node(&JsonValue::Bool(true), &empty_root, 33),
        Err(ProtocolError::InvalidMessage)
    );

    let ambiguous = JsonValue::object([
        ("$defs", JsonValue::object::<[(&str, JsonValue); 0], &str>([])),
        (
            "oneOf",
            JsonValue::array([
                JsonValue::object([("const", JsonValue::Bool(true))]),
                JsonValue::object([("type", JsonValue::from("boolean"))]),
            ]),
        ),
    ]);
    assert_eq!(
        SchemaValidator::new(ambiguous)
            .unwrap()
            .validate(&JsonValue::Bool(true)),
        Err(ProtocolError::InvalidMessage)
    );

    let absent = JsonValue::object([
        ("$defs", JsonValue::object::<[(&str, JsonValue); 0], &str>([])),
        ("$ref", JsonValue::from("#/$defs/Absent")),
    ]);
    assert_eq!(
        SchemaValidator::new(absent)
            .unwrap()
            .validate(&JsonValue::Bool(true)),
        Err(ProtocolError::InvalidMessage)
    );

    let deep = format!("{}0{}", "[".repeat(33), "]".repeat(33));
    assert_eq!(
        JsonValue::parse(deep.as_bytes()),
        Err(ProtocolError::InvalidMessage)
    );
}

#[test]
fn frame_bytes_and_canonical_original() {
    let v = validator();
    let msg = hello();
    let encoded = v.encode_frame(&msg).unwrap();
    assert_eq!(encoded.last(), Some(&b'\n'));
    assert!(!encoded.ends_with(b"\\n"));

    let mut exact = msg.canonical_bytes().unwrap();
    exact.resize(ContractLimits::MAX_FRAME_BYTES, b' ');
    assert_eq!(v.decode_frame(&exact), Ok(msg.clone()));
    exact.push(b' ');
    assert_eq!(v.decode_frame(&exact), Err(ProtocolError::FrameTooLarge));

    let wrapped = JsonValue::parse(&ValidationResult::Valid(msg.clone()).encoded_line().unwrap()).unwrap();
    assert_eq!(
        wrapped,
        JsonValue::object([
            ("message", msg),
            ("valid", JsonValue::Bool(true)),
        ])
    );

    let big_cap = JsonValue::object([
        ("name", JsonValue::from("text.snapshot")),
        ("direction", JsonValue::from("observe")),
        ("scope", JsonValue::from("app-local")),
        ("support", JsonValue::from("supported")),
        ("reason", JsonValue::from("\u{0}".repeat(256))),
    ]);
    let large = replacing(
        &hello(),
        &["capabilities"],
        Some(JsonValue::array((0..64).map(|_| big_cap.clone()))),
    );
    assert_eq!(v.validate_message(&large), Ok(()));
    assert_eq!(v.encode_frame(&large), Err(ProtocolError::FrameTooLarge));
}
