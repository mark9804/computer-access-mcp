mod common;

use std::io::Write;
use std::process::{Command, Stdio};

use history_contract::{
    ContractLimits, ContractValidator, JsonValue, JsonlValidator, ProtocolError, ValidationResult,
};
use common::*;

fn validator() -> ContractValidator {
    ContractValidator::new().expect("embedded wire.schema.json must load")
}

#[test]
fn chunking_crlf_and_one_response_per_line() {
    let v = validator();
    let mut stream = JsonlValidator::new(v.clone());
    let expected = observation(snapshot("中文🙂e\u{0301}"));
    let mut bytes = expected.canonical_bytes().unwrap();
    bytes.extend_from_slice(b"\r\nnot-json\n\n");
    bytes.extend_from_slice(&v.encode_frame(&hello()).unwrap());

    let mut results = Vec::new();
    for byte in &bytes {
        stream
            .push(&[*byte], |res| {
                results.push(res);
                Ok::<(), ()>(())
            })
            .unwrap();
    }
    stream
        .finish(|res| {
            results.push(res);
            Ok::<(), ()>(())
        })
        .unwrap();

    assert_eq!(
        results,
        vec![
            ValidationResult::Valid(expected),
            ValidationResult::Invalid(ProtocolError::InvalidMessage),
            ValidationResult::Invalid(ProtocolError::InvalidMessage),
            ValidationResult::Valid(hello()),
        ]
    );
    assert_eq!(stream.buffered_byte_count(), 0);
}

#[test]
fn eof_is_safe_and_rejects_unterminated_frames() {
    let v = validator();
    let mut stream = JsonlValidator::new(v.clone());
    let mut results = Vec::new();

    stream
        .finish(|res| {
            results.push(res);
            Ok::<(), ()>(())
        })
        .unwrap();
    assert!(results.is_empty());

    stream
        .push(&hello().canonical_bytes().unwrap(), |res| {
            results.push(res);
            Ok::<(), ()>(())
        })
        .unwrap();
    assert!(results.is_empty());

    stream
        .finish(|res| {
            results.push(res);
            Ok::<(), ()>(())
        })
        .unwrap();
    assert_eq!(
        results,
        vec![ValidationResult::Invalid(ProtocolError::InvalidMessage)]
    );

    // Calling finish again emits nothing.
    stream
        .finish(|res| {
            results.push(res);
            Ok::<(), ()>(())
        })
        .unwrap();
    assert_eq!(results.len(), 1);

    stream
        .push(&v.encode_frame(&hello()).unwrap(), |res| {
            results.push(res);
            Ok::<(), ()>(())
        })
        .unwrap();
    stream
        .finish(|res| {
            results.push(res);
            Ok::<(), ()>(())
        })
        .unwrap();
    assert_eq!(results.last(), Some(&ValidationResult::Valid(hello())));
}

#[test]
fn lf_counts_toward_exact_frame_budget() {
    let v = validator();
    let payload = hello().canonical_bytes().unwrap();

    let mut exact = payload.clone();
    exact.resize(ContractLimits::MAX_FRAME_BYTES - 1, b' ');
    exact.push(b'\n');
    assert_eq!(exact.len(), ContractLimits::MAX_FRAME_BYTES);

    let mut too_long = payload;
    too_long.resize(ContractLimits::MAX_FRAME_BYTES, b' ');
    too_long.push(b'\n');

    let mut stream = JsonlValidator::new(v.clone());
    let mut results = Vec::new();
    let mut push = |data: &[u8]| {
        stream
            .push(data, |res| {
                results.push(res);
                Ok::<(), ()>(())
            })
            .unwrap();
    };
    push(&exact);
    push(&too_long);
    push(&v.encode_frame(&hello()).unwrap());
    stream
        .finish(|res| {
            results.push(res);
            Ok::<(), ()>(())
        })
        .unwrap();

    assert_eq!(
        results,
        vec![
            ValidationResult::Valid(hello()),
            ValidationResult::Invalid(ProtocolError::FrameTooLarge),
            ValidationResult::Valid(hello()),
        ]
    );
}

#[test]
fn oversize_line_has_bounded_memory_and_recovers_without_echo() {
    let v = validator();
    let mut stream = JsonlValidator::new(v.clone());
    let mut results = Vec::new();
    let chunk = vec![b'x'; 8_192];

    for _ in 0..100 {
        stream
            .push(&chunk, |res| {
                results.push(res);
                Ok::<(), ()>(())
            })
            .unwrap();
        assert!(stream.buffered_byte_count() <= ContractLimits::MAX_FRAME_BYTES);
    }
    assert!(results.is_empty());

    stream
        .push(b"discarded-private-body\n", |res| {
            results.push(res);
            Ok::<(), ()>(())
        })
        .unwrap();
    stream
        .push(&v.encode_frame(&hello()).unwrap(), |res| {
            results.push(res);
            Ok::<(), ()>(())
        })
        .unwrap();
    stream
        .finish(|res| {
            results.push(res);
            Ok::<(), ()>(())
        })
        .unwrap();

    assert_eq!(
        results,
        vec![
            ValidationResult::Invalid(ProtocolError::FrameTooLarge),
            ValidationResult::Valid(hello()),
        ]
    );
    assert_eq!(
        String::from_utf8(results[0].encoded_line().unwrap()).unwrap(),
        "{\"code\":\"frame-too-large\",\"valid\":false}\n"
    );

    // Oversized unterminated line at EOF emits frame-too-large.
    let huge = vec![b'x'; ContractLimits::MAX_FRAME_BYTES + 1];
    stream
        .push(&huge, |res| {
            results.push(res);
            Ok::<(), ()>(())
        })
        .unwrap();
    stream
        .finish(|res| {
            results.push(res);
            Ok::<(), ()>(())
        })
        .unwrap();
    assert_eq!(
        results.last(),
        Some(&ValidationResult::Invalid(ProtocolError::FrameTooLarge))
    );
}

#[test]
fn invalid_utf8_then_valid_line() {
    let v = validator();
    let mut stream = JsonlValidator::new(v.clone());
    let mut results = Vec::new();
    stream
        .push(&[0xff, b'\n'], |res| {
            results.push(res);
            Ok::<(), ()>(())
        })
        .unwrap();
    stream
        .push(&v.encode_frame(&hello()).unwrap(), |res| {
            results.push(res);
            Ok::<(), ()>(())
        })
        .unwrap();
    assert_eq!(
        results,
        vec![
            ValidationResult::Invalid(ProtocolError::InvalidMessage),
            ValidationResult::Valid(hello()),
        ]
    );
}

fn run_cli(args: &[&str], input: &[u8]) -> (i32, Vec<u8>, Vec<u8>) {
    let bin = env!("CARGO_BIN_EXE_contract-check");
    let mut child = Command::new(bin)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn contract-check");
    {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(input).unwrap();
    }
    let output = child.wait_with_output().expect("wait contract-check");
    (
        output.status.code().unwrap_or(-1),
        output.stdout,
        output.stderr,
    )
}

#[test]
fn cli_valid_and_invalid_lines_exit_zero_and_protocol_only() {
    let v = validator();
    let obs = observation(snapshot("中文🙂"));
    let mut input = v.encode_frame(&obs).unwrap();
    input.extend_from_slice(
        br#"{"protocolVersion":2,"body":"never-echo-synthetic-body"}
not-json
"#,
    );

    let (code, stdout, stderr) = run_cli(&["--validate-jsonl"], &input);
    assert_eq!(code, 0);
    assert!(stderr.is_empty());
    assert!(!stdout.contains(&b'\r'), "stdout must be LF-only");

    let text = String::from_utf8(stdout).unwrap();
    assert!(!text.contains("never-echo"));
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(
        JsonValue::parse_str(lines[0]).unwrap(),
        ValidationResult::Valid(obs).to_json_value()
    );
    assert_eq!(
        JsonValue::parse_str(lines[1]).unwrap(),
        ValidationResult::Invalid(ProtocolError::UnsupportedVersion).to_json_value()
    );
    assert_eq!(
        JsonValue::parse_str(lines[2]).unwrap(),
        ValidationResult::Invalid(ProtocolError::InvalidMessage).to_json_value()
    );
}

#[test]
fn cli_default_eof_and_bad_arguments() {
    let (code, stdout, stderr) = run_cli(&[], b"");
    assert_eq!(code, 0);
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());

    let partial = hello().canonical_bytes().unwrap();
    let (code, stdout, stderr) = run_cli(&[], &partial);
    assert_eq!(code, 0);
    assert!(stderr.is_empty());
    assert_eq!(
        JsonValue::parse(&stdout).unwrap(),
        ValidationResult::Invalid(ProtocolError::InvalidMessage).to_json_value()
    );

    for bad_args in [
        &["run"][..],
        &["--validate-jsonl", "extra"][..],
        &["--help"][..],
    ] {
        let (code, stdout, stderr) = run_cli(bad_args, b"");
        assert_eq!(code, 64);
        assert!(stdout.is_empty());
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            "usage: contract-check [--validate-jsonl]\n"
        );
    }
}
