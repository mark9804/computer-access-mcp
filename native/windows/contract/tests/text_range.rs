mod common;

use access_contract::{utf16_len, ContractLimits, ContractValidator, JsonValue, ProtocolError};
use common::*;

fn validator() -> ContractValidator {
    ContractValidator::new().expect("embedded wire.schema.json must load")
}

fn visible(text: &str, start: f64, total: f64) -> JsonValue {
    let mut payload = snapshot(text);
    payload = replacing(&payload, &["rangeBasis"], Some(JsonValue::from("visible")));
    payload = replacing(
        &payload,
        &["scope"],
        Some(JsonValue::from("accessible-range")),
    );
    payload = replacing(
        &payload,
        &["range"],
        Some(text_range(start, utf16_len(text) as f64)),
    );
    payload = replacing(&payload, &["totalLength"], Some(JsonValue::from(total)));
    payload = replacing(
        &payload,
        &["coverage"],
        Some(coverage("partial", false, &["visible-range-only"])),
    );
    observation(payload)
}

fn native_visible(source: &str) -> JsonValue {
    let val = replacing(
        &visible("可见🙂", 10.0, 40.0),
        &["payload", "source"],
        Some(JsonValue::from(source)),
    );
    replacing(&val, &["payload", "gate"], Some(content_gate()))
}

#[test]
fn visible_fixture_ax_and_uia_text_roundtrip() {
    let v = validator();
    for text in ["可见🙂", "🙂", "👩🏽‍💻", "e\u{0301}", "中\n文", "\u{0}"] {
        let msg = visible(text, 10.0, 40.0);
        assert_eq!(v.decode_frame(&v.encode_frame(&msg).unwrap()), Ok(msg));
    }
    for source in ["ax.range", "ax.marker", "uia.text"] {
        let msg = native_visible(source);
        assert_eq!(v.validate_message(&msg), Ok(()));
        assert_eq!(v.decode_frame(&v.encode_frame(&msg).unwrap()), Ok(msg));
    }
    // Disallowed sources for visible range
    for source in ["ax.value", "uia.value"] {
        assert_invalid(&v, &native_visible(source));
    }
}

#[test]
fn omitted_basis_preserves_legacy_nonzero_accessible_range() {
    let v = validator();
    let mut val = replacing(&visible("可见🙂", 10.0, 40.0), &["payload", "rangeBasis"], None);
    val = replacing(&val, &["payload", "coverage"], Some(complete_coverage()));
    val = replacing(&val, &["payload", "selection"], Some(text_range(30.0, 1.0)));
    assert_eq!(v.validate_message(&val), Ok(()));
    assert_invalid(
        &v,
        &replacing(&val, &["payload", "rangeBasis"], Some(JsonValue::from("prefix"))),
    );

    let prefix = replacing(
        &observation(snapshot("中文🙂")),
        &["payload", "rangeBasis"],
        Some(JsonValue::from("prefix")),
    );
    assert_eq!(v.decode_frame(&v.encode_frame(&prefix).unwrap()), Ok(prefix));
}

#[test]
fn visible_empty_only_valid_when_total_is_zero() {
    let v = validator();
    let empty = visible("", 0.0, 0.0);
    assert_eq!(v.decode_frame(&v.encode_frame(&empty).unwrap()), Ok(empty.clone()));
    assert_eq!(
        v.validate_message(&replacing(
            &empty,
            &["payload", "selection"],
            Some(text_range(0.0, 0.0)),
        )),
        Ok(())
    );
    assert_invalid(&v, &visible("", 0.0, 1.0));
    assert_invalid(&v, &visible("", 40.0, 40.0));
    assert_invalid(&v, &visible("", 1.0, 0.0));
}

#[test]
fn visible_safe_int_bounds_and_selection_containment() {
    let v = validator();
    let largest = visible(
        "可见🙂",
        ContractLimits::MAX_SAFE_INTEGER - 4.0,
        ContractLimits::MAX_SAFE_INTEGER,
    );
    assert_eq!(v.validate_message(&largest), Ok(()));
    assert_invalid(
        &v,
        &replacing(
            &largest,
            &["payload", "range", "start"],
            Some(JsonValue::from(ContractLimits::MAX_SAFE_INTEGER - 3.0)),
        ),
    );

    for sel in [
        text_range(10.0, 0.0),
        text_range(10.0, 4.0),
        text_range(12.0, 2.0),
        text_range(14.0, 0.0),
    ] {
        assert_eq!(
            v.validate_message(&replacing(
                &visible("可见🙂", 10.0, 40.0),
                &["payload", "selection"],
                Some(sel),
            )),
            Ok(())
        );
    }
    for sel in [
        text_range(0.0, 0.0),
        text_range(9.0, 1.0),
        text_range(14.0, 1.0),
        text_range(15.0, 0.0),
        text_range(11.0, 4.0),
        text_range(ContractLimits::MAX_SAFE_INTEGER, 1.0),
    ] {
        assert_invalid(
            &v,
            &replacing(&visible("可见🙂", 10.0, 40.0), &["payload", "selection"], Some(sel)),
        );
    }

    // Lone surrogates in JSON payload rejected
    let token_json = visible("TOKEN", 10.0, 40.0).canonical_string().unwrap();
    for sur in [r"\ud800", r"\udc00"] {
        let bad = token_json.replace("TOKEN", sur);
        assert_eq!(
            v.decode_frame(bad.as_bytes()),
            Err(ProtocolError::InvalidMessage)
        );
    }

    // text.changed wraps identical visible validation
    let after = visible("可见🙂", 10.0, 40.0).get("payload").unwrap().clone();
    let changed = observation(JsonValue::object([
        ("kind", JsonValue::from("text.changed")),
        ("baseSnapshotId", JsonValue::from("before")),
        ("after", after),
    ]));
    assert_eq!(v.decode_frame(&v.encode_frame(&changed).unwrap()), Ok(changed.clone()));
    assert_invalid(
        &v,
        &replacing(&changed, &["payload", "after", "totalLength"], Some(JsonValue::from(13))),
    );
}
