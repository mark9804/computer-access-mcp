use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use computer_history_key_store::base64::decode_key_base64;
use computer_history_key_store::dpapi::DPAPI_KEY_FILENAME;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "chmcp-ks-test-{label}-{}-{id}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create temp dir");
        Self { path: dir }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_computer-history-key-store")
}

fn json_escape_path(path: &Path) -> String {
    let raw = path.to_str().expect("utf8 path");
    let mut out = String::with_capacity(raw.len() + 16);
    for ch in raw.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(ch),
        }
    }
    out
}

fn invoke(args: &[&str], stdin_bytes: &[u8]) -> (i32, String, String) {
    let mut child = Command::new(bin_path())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn key-store binary");

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(stdin_bytes);
    }

    let output = child.wait_with_output().expect("wait for key-store binary");
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    (code, stdout, stderr)
}

fn request_json(cmd: &str, data_root: &Path) -> Vec<u8> {
    format!(
        "{{\"version\":1,\"command\":\"{cmd}\",\"dataRoot\":\"{}\"}}\n",
        json_escape_path(data_root)
    )
    .into_bytes()
}

fn extract_json_string<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\":\"");
    let start = json.find(&needle)? + needle.len();
    let rest = &json[start..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

#[test]
fn invalid_args_exit_64_without_reading_stdin() {
    // Spawn with open stdin that is NEVER closed — binary must exit 64 immediately without waiting for stdin.
    let mut child = Command::new(bin_path())
        .args(["--command", "bogus"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");

    // Hold stdin handle open while waiting for process exit.
    let _held_stdin = child.stdin.take();
    let output = child.wait_with_output().expect("wait");
    assert_eq!(output.status.code(), Some(64));
    assert_eq!(output.stdout, b"{\"version\":1,\"status\":\"error\"}\n");
    assert!(output.stderr.is_empty());

    let (code, stdout, stderr) = invoke(&[], b"");
    assert_eq!(code, 64);
    assert_eq!(stdout, "{\"version\":1,\"status\":\"error\"}\n");
    assert!(stderr.is_empty());
}

#[test]
fn invalid_stdin_cases_exit_64() {
    let bad_inputs: &[&[u8]] = &[
        b"",
        b"not-json\n",
        b"\xEF\xBB\xBF{\"version\":1,\"command\":\"get\",\"dataRoot\":\"C:\\\\data\"}\n",
        br#"{"version":1,"command":"get","dataRoot":"C:\\data","extra":1}"#,
        br#"{"version":1,"command":"get","dataRoot":"C:\\data","dataRoot":"C:\\data"}"#,
        br#"{"version":1,"command":"get","dataRoot":"C:\\\uD800"}"#,
        br#"{"version":1,"command":"get","dataRoot":"C:\\"}"#,
        br#"{"version":1,"command":"create","dataRoot":"C:\\data"}"#,
        br#"{"version":1,"command":"get","dataRoot":"C:\\data"} trailing"#,
    ];

    for input in bad_inputs {
        let (code, stdout, stderr) = invoke(&["--command", "get"], input);
        assert_eq!(code, 64, "input={:?}", String::from_utf8_lossy(input));
        assert_eq!(stdout, "{\"version\":1,\"status\":\"error\"}\n");
        assert!(stderr.is_empty());
    }
}

#[test]
fn live_dpapi_full_lifecycle_and_non_plaintext_blob() {
    let temp = TempDir::new("lifecycle");
    let data_root = temp.path().join("nested").join("store");

    // 1. get on missing directory -> status: missing, phase: lookup, exit 0
    let (code, stdout, stderr) = invoke(&["--command", "get"], &request_json("get", &data_root));
    assert_eq!(code, 0);
    assert_eq!(stdout, "{\"version\":1,\"status\":\"missing\",\"phase\":\"lookup\"}\n");
    assert!(stderr.is_empty());

    // 2. create -> generates 32-byte key, writes raw DPAPI blob
    let (code, stdout, stderr) = invoke(&["--command", "create"], &request_json("create", &data_root));
    assert_eq!(code, 0);
    assert!(stderr.is_empty());
    assert!(stdout.ends_with('\n'));
    assert_eq!(extract_json_string(&stdout, "status"), Some("ok"));
    let created_b64 = extract_json_string(&stdout, "key")
        .expect("key field present")
        .to_string();
    assert_eq!(created_b64.len(), 44);
    let created_key = decode_key_base64(&created_b64).expect("strict 32-byte base64 key");

    // Verify raw DPAPI blob on disk is not plaintext and not base64 of plaintext
    let key_file = data_root.join(DPAPI_KEY_FILENAME);
    let raw_blob = fs::read(&key_file).expect("read master.key.dpapi");
    assert!(!raw_blob.is_empty() && raw_blob.len() <= 8192);
    assert!(
        !raw_blob
            .windows(32)
            .any(|w| w == created_key.as_bytes()),
        "DPAPI blob must not contain plaintext key bytes"
    );
    assert!(
        !raw_blob
            .windows(created_b64.len())
            .any(|w| w == created_b64.as_bytes()),
        "DPAPI blob must not contain base64 key"
    );

    // 3. get -> returns exact same key
    let (code, stdout, stderr) = invoke(&["--command", "get"], &request_json("get", &data_root));
    assert_eq!(code, 0);
    assert!(stderr.is_empty());
    assert_eq!(extract_json_string(&stdout, "status"), Some("ok"));
    assert_eq!(extract_json_string(&stdout, "key"), Some(created_b64.as_str()));

    // 4. idempotent create -> returns exact same key without replacing file
    let (code, stdout, stderr) = invoke(&["--command", "create"], &request_json("create", &data_root));
    assert_eq!(code, 0);
    assert!(stderr.is_empty());
    assert_eq!(extract_json_string(&stdout, "status"), Some("ok"));
    assert_eq!(extract_json_string(&stdout, "key"), Some(created_b64.as_str()));
    assert_eq!(fs::read(&key_file).expect("reread"), raw_blob);

    // 5. delete -> ok without key field, removes file
    let (code, stdout, stderr) = invoke(&["--command", "delete"], &request_json("delete", &data_root));
    assert_eq!(code, 0);
    assert!(stderr.is_empty());
    assert_eq!(stdout, "{\"version\":1,\"status\":\"ok\"}\n");
    assert!(!key_file.exists());

    // 6. idempotent delete -> still ok
    let (code, stdout, stderr) = invoke(&["--command", "delete"], &request_json("delete", &data_root));
    assert_eq!(code, 0);
    assert_eq!(stdout, "{\"version\":1,\"status\":\"ok\"}\n");
    assert!(stderr.is_empty());

    // 7. get after delete -> missing
    let (code, stdout, stderr) = invoke(&["--command", "get"], &request_json("get", &data_root));
    assert_eq!(code, 0);
    assert_eq!(stdout, "{\"version\":1,\"status\":\"missing\",\"phase\":\"lookup\"}\n");
    assert!(stderr.is_empty());
}

#[test]
fn concurrent_create_converges_on_single_winner_without_temp_leaks() {
    let temp = TempDir::new("race");
    let data_root = temp.path().join("raced");
    let req = request_json("create", &data_root);

    let mut children = Vec::new();
    for _ in 0..4 {
        let mut child = Command::new(bin_path())
            .args(["--command", "create"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn racer");
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(&req)
            .expect("write");
        drop(child.stdin.take());
        children.push(child);
    }

    let mut keys = Vec::new();
    for child in children {
        let out = child.wait_with_output().expect("wait racer");
        assert_eq!(out.status.code(), Some(0));
        assert!(out.stderr.is_empty());
        let stdout = String::from_utf8(out.stdout).expect("utf8");
        assert_eq!(
            extract_json_string(&stdout, "status"),
            Some("ok"),
            "unexpected racer response: {stdout}"
        );
        let key = extract_json_string(&stdout, "key").expect("key").to_string();
        assert_eq!(key.len(), 44);
        keys.push(key);
    }

    for k in &keys[1..] {
        assert_eq!(k, &keys[0], "all concurrent creators must observe the same winning key");
    }

    // No temp files should remain in data_root
    let entries: Vec<String> = fs::read_dir(&data_root)
        .expect("read_dir")
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(entries, vec![DPAPI_KEY_FILENAME.to_string()]);
}

#[test]
fn rejects_corrupt_oversized_empty_and_wrong_length_dpapi_blobs() {
    let temp = TempDir::new("corrupt");
    let data_root = temp.path().join("data");
    fs::create_dir_all(&data_root).expect("mkdir");
    let key_file = data_root.join(DPAPI_KEY_FILENAME);

    // Empty file -> error/lookup
    fs::write(&key_file, b"").expect("write empty");
    let (code, stdout, _) = invoke(&["--command", "get"], &request_json("get", &data_root));
    assert_eq!(code, 0);
    assert_eq!(extract_json_string(&stdout, "status"), Some("error"));
    assert_eq!(extract_json_string(&stdout, "phase"), Some("lookup"));

    // Oversized file (8193 bytes) -> error/lookup
    fs::write(&key_file, vec![0x55u8; 8193]).expect("write oversized");
    let (code, stdout, _) = invoke(&["--command", "get"], &request_json("get", &data_root));
    assert_eq!(code, 0);
    assert_eq!(extract_json_string(&stdout, "status"), Some("error"));
    assert_eq!(extract_json_string(&stdout, "phase"), Some("lookup"));

    // Corrupt non-DPAPI bytes -> error/dpapi-unprotect with osStatus
    fs::write(&key_file, b"not-a-valid-dpapi-blob").expect("write corrupt");
    let (code, stdout, _) = invoke(&["--command", "get"], &request_json("get", &data_root));
    assert_eq!(code, 0);
    assert_eq!(extract_json_string(&stdout, "status"), Some("error"));
    assert_eq!(extract_json_string(&stdout, "phase"), Some("dpapi-unprotect"));
    assert!(stdout.contains("\"osStatus\":"));

    // Valid DPAPI blob encrypting only 16 bytes (not 32) -> error/response-validation
    let short_plaintext = [0x11u8; 16];
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: short_plaintext.len() as u32,
        pbData: short_plaintext.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptProtectData(
            &in_blob,
            PCWSTR::null(),
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
        .expect("protect 16-byte test blob");
    }
    let short_dpapi = unsafe {
        let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(out_blob.pbData.cast())));
        slice
    };
    fs::write(&key_file, &short_dpapi).expect("write short dpapi");
    let (code, stdout, _) = invoke(&["--command", "get"], &request_json("get", &data_root));
    assert_eq!(code, 0);
    assert_eq!(extract_json_string(&stdout, "status"), Some("error"));
    assert_eq!(extract_json_string(&stdout, "phase"), Some("response-validation"));
}

#[test]
fn rejects_ntfs_junction_at_data_root_and_ancestor() {
    let temp = TempDir::new("junction");
    let real_target = temp.path().join("real-target");
    let junction = temp.path().join("junction-link");
    fs::create_dir_all(&real_target).expect("create target");

    // Create NTFS directory junction (works without admin rights on Windows).
    let mklink = Command::new("cmd")
        .args([
            "/C",
            "mklink",
            "/J",
            junction.to_str().unwrap(),
            real_target.to_str().unwrap(),
        ])
        .output()
        .expect("run mklink /J");
    assert!(
        mklink.status.success(),
        "mklink /J failed: {}",
        String::from_utf8_lossy(&mklink.stderr)
    );

    // Ensure cleanup removes junction before TempDir drop if needed.
    struct JunctionCleanup(PathBuf);
    impl Drop for JunctionCleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir(&self.0);
        }
    }
    let _cleanup = JunctionCleanup(junction.clone());

    // Direct junction as dataRoot must fail closed for get, create, and delete.
    for (cmd, expected_phase) in [("get", "lookup"), ("create", "add"), ("delete", "lookup")] {
        let (code, stdout, stderr) = invoke(&["--command", cmd], &request_json(cmd, &junction));
        assert_eq!(code, 0, "cmd={cmd}");
        assert!(stderr.is_empty());
        assert_eq!(extract_json_string(&stdout, "status"), Some("error"), "cmd={cmd}, stdout={stdout}");
        assert_eq!(extract_json_string(&stdout, "phase"), Some(expected_phase), "cmd={cmd}, stdout={stdout}");
    }
    assert!(!real_target.join(DPAPI_KEY_FILENAME).exists());

    // Ancestor junction (<junction>\nested\store) must also fail closed for get, create, and delete.
    let nested_under_junction = junction.join("nested").join("store");
    for (cmd, expected_phase) in [("get", "lookup"), ("create", "add"), ("delete", "lookup")] {
        let (code, stdout, stderr) = invoke(
            &["--command", cmd],
            &request_json(cmd, &nested_under_junction),
        );
        assert_eq!(code, 0, "ancestor cmd={cmd}");
        assert!(stderr.is_empty());
        assert_eq!(extract_json_string(&stdout, "status"), Some("error"), "ancestor cmd={cmd}, stdout={stdout}");
        assert_eq!(extract_json_string(&stdout, "phase"), Some(expected_phase), "ancestor cmd={cmd}, stdout={stdout}");
    }
    assert!(!real_target.join("nested").exists());
}
