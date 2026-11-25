use std::ffi::OsString;
use std::io::Read;
use std::path::{Component, Path, PathBuf, Prefix};

pub const MAX_REQUEST_BYTES: usize = 8192;
pub const MAX_DATA_ROOT_UTF16_UNITS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Get,
    Create,
    Delete,
}

impl Command {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "get" => Some(Self::Get),
            "create" => Some(Self::Create),
            "delete" => Some(Self::Delete),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Create => "create",
            Self::Delete => "delete",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyStoreRequest {
    pub command: Command,
    pub data_root: PathBuf,
    pub service: Option<String>,
    pub account: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestError {
    InvalidArguments,
    TooLarge,
    InvalidInput,
    Io,
}

/// Validates exact CLI args `[exe, "--command", "<get|create|delete>"]` BEFORE reading stdin.
pub fn parse_args(args: &[OsString]) -> Result<Command, RequestError> {
    if args.len() != 3 {
        return Err(RequestError::InvalidArguments);
    }
    let flag = args[1].to_str().ok_or(RequestError::InvalidArguments)?;
    let cmd_str = args[2].to_str().ok_or(RequestError::InvalidArguments)?;
    if flag != "--command" {
        return Err(RequestError::InvalidArguments);
    }
    Command::parse(cmd_str).ok_or(RequestError::InvalidArguments)
}

/// Validates CLI args first (without touching `reader`), then reads a bounded strict JSON
/// request from `reader`.
pub fn read_request(args: &[OsString], reader: &mut dyn Read) -> Result<KeyStoreRequest, RequestError> {
    let cli_command = parse_args(args)?;

    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let remaining = (MAX_REQUEST_BYTES + 1).saturating_sub(buf.len());
        if remaining == 0 {
            return Err(RequestError::TooLarge);
        }
        let to_read = remaining.min(chunk.len());
        match reader.read(&mut chunk[..to_read]) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > MAX_REQUEST_BYTES {
                    return Err(RequestError::TooLarge);
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(RequestError::Io),
        }
    }

    parse_request_bytes(&buf, cli_command)
}

pub fn parse_request_bytes(bytes: &[u8], expected_command: Command) -> Result<KeyStoreRequest, RequestError> {
    if bytes.is_empty() || bytes.len() > MAX_REQUEST_BYTES {
        return Err(if bytes.len() > MAX_REQUEST_BYTES {
            RequestError::TooLarge
        } else {
            RequestError::InvalidInput
        });
    }
    // Reject UTF-8 BOM explicitly.
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Err(RequestError::InvalidInput);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| RequestError::InvalidInput)?;

    let mut parser = JsonRequestParser::new(text);
    parser.parse(expected_command)
}

fn is_valid_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 128 {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Validates and normalizes a Windows `dataRoot` path.
/// Rejects empty, > 4096 UTF-16 code units, C0/DEL controls, relative paths,
/// bare drive roots (`C:\`), parent traversal (`..`), UNC/device namespaces,
/// and alternate data streams (`:` inside path segments).
pub fn validate_data_root(raw: &str) -> Result<PathBuf, RequestError> {
    if raw.is_empty() || raw.encode_utf16().count() > MAX_DATA_ROOT_UTF16_UNITS {
        return Err(RequestError::InvalidInput);
    }
    if raw.chars().any(|c| (c as u32) < 0x20 || (c as u32) == 0x7F) {
        return Err(RequestError::InvalidInput);
    }

    let path = Path::new(raw);
    let mut components = path.components();

    let prefix = match components.next() {
        Some(Component::Prefix(p)) => match p.kind() {
            Prefix::Disk(_) | Prefix::VerbatimDisk(_) => Component::Prefix(p),
            _ => return Err(RequestError::InvalidInput),
        },
        _ => return Err(RequestError::InvalidInput),
    };

    match components.next() {
        Some(Component::RootDir) => {}
        _ => return Err(RequestError::InvalidInput),
    }

    let mut normalized = PathBuf::new();
    normalized.push(prefix.as_os_str());
    normalized.push(Component::RootDir.as_os_str());

    let mut normal_count = 0usize;
    for comp in components {
        match comp {
            Component::Normal(seg) => {
                let seg_str = seg.to_str().ok_or(RequestError::InvalidInput)?;
                if seg_str.is_empty() || seg_str.contains(':') {
                    return Err(RequestError::InvalidInput);
                }
                normalized.push(seg);
                normal_count += 1;
            }
            Component::CurDir => {
                // Reject explicit '.' segments to keep path canonical and avoid ambiguity.
                return Err(RequestError::InvalidInput);
            }
            Component::ParentDir | Component::Prefix(_) | Component::RootDir => {
                return Err(RequestError::InvalidInput);
            }
        }
    }

    if normal_count == 0 {
        return Err(RequestError::InvalidInput);
    }

    Ok(normalized)
}

struct JsonRequestParser<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> JsonRequestParser<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            text,
            bytes: text.as_bytes(),
            pos: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn expect_byte(&mut self, expected: u8) -> Result<(), RequestError> {
        if self.peek() == Some(expected) {
            self.pos += 1;
            Ok(())
        } else {
            Err(RequestError::InvalidInput)
        }
    }

    fn parse(&mut self, expected_command: Command) -> Result<KeyStoreRequest, RequestError> {
        self.skip_ws();
        self.expect_byte(b'{')?;
        self.skip_ws();

        if self.peek() == Some(b'}') {
            return Err(RequestError::InvalidInput);
        }

        let mut version_seen = false;
        let mut command: Option<Command> = None;
        let mut data_root: Option<String> = None;
        let mut service: Option<String> = None;
        let mut account: Option<String> = None;

        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect_byte(b':')?;
            self.skip_ws();

            match key.as_str() {
                "version" => {
                    if version_seen {
                        return Err(RequestError::InvalidInput);
                    }
                    self.parse_version_one()?;
                    version_seen = true;
                }
                "command" => {
                    if command.is_some() {
                        return Err(RequestError::InvalidInput);
                    }
                    let raw = self.parse_string()?;
                    let parsed = Command::parse(&raw).ok_or(RequestError::InvalidInput)?;
                    command = Some(parsed);
                }
                "dataRoot" => {
                    if data_root.is_some() {
                        return Err(RequestError::InvalidInput);
                    }
                    data_root = Some(self.parse_string()?);
                }
                "service" => {
                    if service.is_some() {
                        return Err(RequestError::InvalidInput);
                    }
                    let val = self.parse_string()?;
                    if !is_valid_identifier(&val) {
                        return Err(RequestError::InvalidInput);
                    }
                    service = Some(val);
                }
                "account" => {
                    if account.is_some() {
                        return Err(RequestError::InvalidInput);
                    }
                    let val = self.parse_string()?;
                    if !is_valid_identifier(&val) {
                        return Err(RequestError::InvalidInput);
                    }
                    account = Some(val);
                }
                _ => return Err(RequestError::InvalidInput),
            }

            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                    self.skip_ws();
                    // Disallow trailing comma before '}'.
                    if self.peek() != Some(b'"') {
                        return Err(RequestError::InvalidInput);
                    }
                }
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(RequestError::InvalidInput),
            }
        }

        self.skip_ws();
        if self.pos != self.bytes.len() {
            return Err(RequestError::InvalidInput);
        }

        if !version_seen {
            return Err(RequestError::InvalidInput);
        }
        let command = command.ok_or(RequestError::InvalidInput)?;
        if command != expected_command {
            return Err(RequestError::InvalidInput);
        }
        let raw_root = data_root.ok_or(RequestError::InvalidInput)?;
        let validated_root = validate_data_root(&raw_root)?;

        Ok(KeyStoreRequest {
            command,
            data_root: validated_root,
            service,
            account,
        })
    }

    fn parse_version_one(&mut self) -> Result<(), RequestError> {
        if self.peek() != Some(b'1') {
            return Err(RequestError::InvalidInput);
        }
        self.pos += 1;
        match self.peek() {
            Some(b' ' | b'\t' | b'\n' | b'\r' | b',' | b'}') => Ok(()),
            _ => Err(RequestError::InvalidInput),
        }
    }

    fn parse_string(&mut self) -> Result<String, RequestError> {
        self.expect_byte(b'"')?;
        let mut out = String::new();

        while let Some(b) = self.peek() {
            if b == b'"' {
                self.pos += 1;
                return Ok(out);
            }
            if b < 0x20 {
                // RFC 8259 forbids unescaped control characters U+0000..=U+001F.
                return Err(RequestError::InvalidInput);
            }
            if b == b'\\' {
                self.pos += 1;
                let esc = self.peek().ok_or(RequestError::InvalidInput)?;
                self.pos += 1;
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\u{0008}'),
                    b'f' => out.push('\u{000C}'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        let code = self.parse_hex4()?;
                        if (0xD800..=0xDBFF).contains(&code) {
                            // High surrogate MUST be followed immediately by \uDC00..\uDFFF.
                            if self.peek() != Some(b'\\') {
                                return Err(RequestError::InvalidInput);
                            }
                            self.pos += 1;
                            if self.peek() != Some(b'u') {
                                return Err(RequestError::InvalidInput);
                            }
                            self.pos += 1;
                            let low = self.parse_hex4()?;
                            if !(0xDC00..=0xDFFF).contains(&low) {
                                return Err(RequestError::InvalidInput);
                            }
                            let scalar =
                                0x10000 + (((code as u32) - 0xD800) << 10) + ((low as u32) - 0xDC00);
                            let ch = char::from_u32(scalar).ok_or(RequestError::InvalidInput)?;
                            out.push(ch);
                        } else if (0xDC00..=0xDFFF).contains(&code) {
                            // Unpaired low surrogate.
                            return Err(RequestError::InvalidInput);
                        } else {
                            let ch = char::from_u32(code as u32).ok_or(RequestError::InvalidInput)?;
                            out.push(ch);
                        }
                    }
                    _ => return Err(RequestError::InvalidInput),
                }
            } else {
                let ch = self.text[self.pos..]
                    .chars()
                    .next()
                    .ok_or(RequestError::InvalidInput)?;
                out.push(ch);
                self.pos += ch.len_utf8();
            }
        }

        Err(RequestError::InvalidInput)
    }

    fn parse_hex4(&mut self) -> Result<u16, RequestError> {
        if self.pos + 4 > self.bytes.len() {
            return Err(RequestError::InvalidInput);
        }
        let mut value = 0u16;
        for i in 0..4 {
            let digit = match self.bytes[self.pos + i] {
                b'0'..=b'9' => (self.bytes[self.pos + i] - b'0') as u16,
                b'a'..=b'f' => (self.bytes[self.pos + i] - b'a' + 10) as u16,
                b'A'..=b'F' => (self.bytes[self.pos + i] - b'A' + 10) as u16,
                _ => return Err(RequestError::InvalidInput),
            };
            value = (value << 4) | digit;
        }
        self.pos += 4;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn args(parts: &[&str]) -> Vec<OsString> {
        parts.iter().map(OsString::from).collect()
    }

    #[test]
    fn accepts_valid_get_create_delete_requests() {
        for cmd in ["get", "create", "delete"] {
            let input = format!(
                "{{\"version\":1,\"command\":\"{cmd}\",\"dataRoot\":\"C:\\\\Users\\\\Alice\\\\computer-history-mcp\"}}\n"
            );
            let mut cursor = Cursor::new(input.as_bytes());
            let req = read_request(&args(&["key-store.exe", "--command", cmd]), &mut cursor)
                .expect("valid request");
            assert_eq!(req.command.as_str(), cmd);
            assert_eq!(req.data_root, PathBuf::from(r"C:\Users\Alice\computer-history-mcp"));
            assert_eq!(req.service, None);
            assert_eq!(req.account, None);
        }
    }

    #[test]
    fn accepts_optional_service_and_account_and_surrogate_pair_unicode() {
        let input = r#"{"version":1,"command":"get","dataRoot":"C:\\Users\\Alice\\\uD83D\uDE80-data","service":"com.computer-history.mcp","account":"history.dev-1"}"#;
        let mut cursor = Cursor::new(input.as_bytes());
        let req = read_request(&args(&["key-store.exe", "--command", "get"]), &mut cursor)
            .expect("valid request with surrogate pair");
        assert_eq!(req.data_root, PathBuf::from("C:\\Users\\Alice\\\u{1F680}-data"));
        assert_eq!(req.service.as_deref(), Some("com.computer-history.mcp"));
        assert_eq!(req.account.as_deref(), Some("history.dev-1"));
    }

    #[test]
    fn rejects_invalid_args_before_reading_stdin() {
        struct PanicReader;
        impl Read for PanicReader {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                panic!("stdin must not be read when CLI args are invalid");
            }
        }

        let bad_arg_sets: &[&[&str]] = &[
            &["key-store.exe"],
            &["key-store.exe", "--command"],
            &["key-store.exe", "--command", "unknown"],
            &["key-store.exe", "--other", "get"],
            &["key-store.exe", "--command", "get", "--extra"],
        ];
        for bad in bad_arg_sets {
            let mut reader = PanicReader;
            assert_eq!(
                read_request(&args(bad), &mut reader),
                Err(RequestError::InvalidArguments)
            );
        }
    }

    #[test]
    fn rejects_bom_lone_surrogates_duplicate_keys_extra_keys_trailing_tokens_and_bad_paths() {
        let valid_args = args(&["key-store.exe", "--command", "get"]);
        let cases: &[&[u8]] = &[
            b"",
            b"not-json",
            // UTF-8 BOM
            b"\xEF\xBB\xBF{\"version\":1,\"command\":\"get\",\"dataRoot\":\"C:\\\\data\"}",
            // Duplicate key
            br#"{"version":1,"version":1,"command":"get","dataRoot":"C:\\data"}"#,
            br#"{"version":1,"command":"get","dataRoot":"C:\\a","dataRoot":"C:\\b"}"#,
            // Extra key
            br#"{"version":1,"command":"get","dataRoot":"C:\\data","extra":true}"#,
            // Trailing token
            br#"{"version":1,"command":"get","dataRoot":"C:\\data"} {}"#,
            // Trailing comma
            br#"{"version":1,"command":"get","dataRoot":"C:\\data",}"#,
            // Lone high surrogate
            br#"{"version":1,"command":"get","dataRoot":"C:\\\uD800"}"#,
            // Lone low surrogate
            br#"{"version":1,"command":"get","dataRoot":"C:\\\uDC00"}"#,
            // High surrogate followed by non-low surrogate
            br#"{"version":1,"command":"get","dataRoot":"C:\\\uD800\u0041"}"#,
            // Unescaped control char
            b"{\"version\":1,\"command\":\"get\",\"dataRoot\":\"C:\\\\a\x01b\"}",
            // Escaped control char (DEL 0x7F or NUL) in dataRoot
            br#"{"version":1,"command":"get","dataRoot":"C:\\a\u0000b"}"#,
            br#"{"version":1,"command":"get","dataRoot":"C:\\a\u007Fb"}"#,
            // Command mismatch
            br#"{"version":1,"command":"create","dataRoot":"C:\\data"}"#,
            // Bad version
            br#"{"version":2,"command":"get","dataRoot":"C:\\data"}"#,
            br#"{"version":1.0,"command":"get","dataRoot":"C:\\data"}"#,
            br#"{"version":"1","command":"get","dataRoot":"C:\\data"}"#,
            // Bare drive root
            br#"{"version":1,"command":"get","dataRoot":"C:\\"}"#,
            br#"{"version":1,"command":"get","dataRoot":"C:/"}"#,
            // Relative path
            br#"{"version":1,"command":"get","dataRoot":"relative\\path"}"#,
            br#"{"version":1,"command":"get","dataRoot":"C:relative"}"#,
            // Parent traversal
            br#"{"version":1,"command":"get","dataRoot":"C:\\a\\..\\b"}"#,
            // Alternate data stream
            br#"{"version":1,"command":"get","dataRoot":"C:\\data:stream"}"#,
            // Invalid service/account
            br#"{"version":1,"command":"get","dataRoot":"C:\\data","service":"bad space"}"#,
            br#"{"version":1,"command":"get","dataRoot":"C:\\data","account":""}"#,
        ];

        for case in cases {
            let mut cursor = Cursor::new(*case);
            assert!(
                read_request(&valid_args, &mut cursor).is_err(),
                "expected rejection for case: {:?}",
                String::from_utf8_lossy(case)
            );
        }

        // Oversized input (> 8192 bytes)
        let big = vec![b' '; MAX_REQUEST_BYTES + 1];
        let mut cursor = Cursor::new(big);
        assert_eq!(read_request(&valid_args, &mut cursor), Err(RequestError::TooLarge));
    }
}
