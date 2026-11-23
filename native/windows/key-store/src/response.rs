use crate::base64::encode_key_base64;
use crate::zeroize::{ZeroizingKey, ZeroizingVec};

pub const MAX_RESPONSE_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    KeyOnNonOkStatus,
    ResponseTooLarge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseStatus {
    Ok,
    Missing,
    Denied,
    Error,
}

impl ResponseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Missing => "missing",
            Self::Denied => "denied",
            Self::Error => "error",
        }
    }
}

pub struct KeyStoreResponse {
    pub status: ResponseStatus,
    pub key: Option<ZeroizingKey>,
    pub phase: Option<&'static str>,
    pub os_status: Option<i32>,
}

impl KeyStoreResponse {
    pub fn ok_empty() -> Self {
        Self {
            status: ResponseStatus::Ok,
            key: None,
            phase: None,
            os_status: None,
        }
    }

    pub fn ok_key(key: ZeroizingKey) -> Self {
        Self {
            status: ResponseStatus::Ok,
            key: Some(key),
            phase: None,
            os_status: None,
        }
    }

    pub fn missing(phase: &'static str) -> Self {
        Self {
            status: ResponseStatus::Missing,
            key: None,
            phase: Some(phase),
            os_status: None,
        }
    }

    pub fn denied(phase: &'static str, os_status: Option<i32>) -> Self {
        Self {
            status: ResponseStatus::Denied,
            key: None,
            phase: Some(phase),
            os_status,
        }
    }

    pub fn error(phase: Option<&'static str>, os_status: Option<i32>) -> Self {
        Self {
            status: ResponseStatus::Error,
            key: None,
            phase,
            os_status,
        }
    }

    /// Serializes the response as a single LF-terminated JSON line bounded to `<= 1024` bytes.
    /// The returned `ZeroizingVec` clears any key material from memory on drop.
    pub fn encode_line(&self) -> Result<ZeroizingVec, EncodeError> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(b"{\"version\":1,\"status\":\"");
        out.extend_from_slice(self.status.as_str().as_bytes());
        out.push(b'"');

        if let Some(ref key) = self.key {
            if self.status != ResponseStatus::Ok {
                return Err(EncodeError::KeyOnNonOkStatus);
            }
            let encoded = encode_key_base64(key);
            out.extend_from_slice(b",\"key\":\"");
            out.extend_from_slice(encoded.as_bytes());
            out.push(b'"');
        }

        if let Some(phase) = self.phase {
            out.extend_from_slice(b",\"phase\":\"");
            push_json_escaped(&mut out, phase);
            out.push(b'"');
        }

        if let Some(os_status) = self.os_status {
            out.extend_from_slice(b",\"osStatus\":");
            out.extend_from_slice(os_status.to_string().as_bytes());
        }

        out.extend_from_slice(b"}\n");

        if out.len() > MAX_RESPONSE_BYTES {
            drop(ZeroizingVec::new(out));
            return Err(EncodeError::ResponseTooLarge);
        }

        Ok(ZeroizingVec::new(out))
    }
}

fn push_json_escaped(out: &mut Vec<u8>, s: &str) {
    for b in s.bytes() {
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x00..=0x1F => {
                let hex = format!("\\u{:04x}", b);
                out.extend_from_slice(hex.as_bytes());
            }
            _ => out.push(b),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_compact_lf_terminated_json_omitting_none_fields() {
        let err = KeyStoreResponse::error(None, None).encode_line().unwrap();
        assert_eq!(err.as_slice(), b"{\"version\":1,\"status\":\"error\"}\n");

        let miss = KeyStoreResponse::missing("lookup").encode_line().unwrap();
        assert_eq!(
            miss.as_slice(),
            b"{\"version\":1,\"status\":\"missing\",\"phase\":\"lookup\"}\n"
        );

        let denied = KeyStoreResponse::denied("dpapi-unprotect", Some(-2146893813))
            .encode_line()
            .unwrap();
        assert_eq!(
            denied.as_slice(),
            b"{\"version\":1,\"status\":\"denied\",\"phase\":\"dpapi-unprotect\",\"osStatus\":-2146893813}\n"
        );

        let ok_empty = KeyStoreResponse::ok_empty().encode_line().unwrap();
        assert_eq!(ok_empty.as_slice(), b"{\"version\":1,\"status\":\"ok\"}\n");

        let ok_key = KeyStoreResponse::ok_key(ZeroizingKey::zeroed())
            .encode_line()
            .unwrap();
        assert_eq!(
            ok_key.as_slice(),
            b"{\"version\":1,\"status\":\"ok\",\"key\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"}\n"
        );
    }
}
