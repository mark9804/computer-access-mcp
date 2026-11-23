use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::validator::{ContractLimits, ProtocolError};

/// Returns the number of UTF-16 code units required to encode `text`.
#[inline]
pub fn utf16_len(text: &str) -> usize {
    text.encode_utf16().count()
}

/// Strict RFC 8259 JSON value matching wire-v1 TypeScript and Swift semantics.
///
/// Primitives remain strictly distinct (`Bool(true)` is never `Number(1.0)`),
/// numbers use IEEE-754 `f64`, and strings compare by exact scalar/code-unit
/// sequence without Unicode normalization.
#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

impl JsonValue {
    /// Parses strict RFC 8259 UTF-8 JSON with bounded structural depth (`<= 32`),
    /// no BOM stripping, strict surrogate-pair handling, non-finite number
    /// rejection, and last-key-wins duplicate object keys (matching JS and Swift).
    pub fn parse(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let text = std::str::from_utf8(bytes).map_err(|_| ProtocolError::InvalidMessage)?;
        let mut parser = JsonParser {
            bytes: text.as_bytes(),
            offset: 0,
        };
        parser.parse()
    }

    /// Convenience wrapper around [`JsonValue::parse`] for UTF-8 `&str`.
    pub fn parse_str(text: &str) -> Result<Self, ProtocolError> {
        Self::parse(text.as_bytes())
    }

    /// Builds a `JsonValue::Object` from an iterator of `(key, value)` pairs.
    pub fn object<I, K>(entries: I) -> Self
    where
        I: IntoIterator<Item = (K, JsonValue)>,
        K: Into<String>,
    {
        let mut map = BTreeMap::new();
        for (k, v) in entries {
            map.insert(k.into(), v);
        }
        JsonValue::Object(map)
    }

    /// Builds a `JsonValue::Array` from an iterator of `JsonValue` items.
    pub fn array<I>(items: I) -> Self
    where
        I: IntoIterator<Item = JsonValue>,
    {
        JsonValue::Array(items.into_iter().collect())
    }

    /// Looks up a field on a `JsonValue::Object`.
    #[inline]
    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        match self {
            JsonValue::Object(map) => map.get(key),
            _ => None,
        }
    }

    /// Mutably looks up a field on a `JsonValue::Object`.
    #[inline]
    pub fn get_mut(&mut self, key: &str) -> Option<&mut JsonValue> {
        match self {
            JsonValue::Object(map) => map.get_mut(key),
            _ => None,
        }
    }

    #[inline]
    pub fn as_obj(&self) -> Option<&BTreeMap<String, JsonValue>> {
        match self {
            JsonValue::Object(map) => Some(map),
            _ => None,
        }
    }

    #[inline]
    pub fn as_obj_mut(&mut self) -> Option<&mut BTreeMap<String, JsonValue>> {
        match self {
            JsonValue::Object(map) => Some(map),
            _ => None,
        }
    }

    #[inline]
    pub fn as_array(&self) -> Option<&[JsonValue]> {
        match self {
            JsonValue::Array(items) => Some(items),
            _ => None,
        }
    }

    #[inline]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::String(text) => Some(text),
            _ => None,
        }
    }

    #[inline]
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            JsonValue::Number(n) => Some(*n),
            _ => None,
        }
    }

    /// Returns the numeric value as an exact safe `i64` if finite, integral, and
    /// within `[-MAX_SAFE_INTEGER, MAX_SAFE_INTEGER]`.
    #[inline]
    pub fn as_i64(&self) -> Option<i64> {
        let n = self.as_f64()?;
        if !n.is_finite() || n.trunc() != n || n.abs() > ContractLimits::MAX_SAFE_INTEGER {
            return None;
        }
        Some(n as i64)
    }

    /// Returns the numeric value as an exact safe `u64` if finite, integral, and
    /// within `[0, MAX_SAFE_INTEGER]`.
    #[inline]
    pub fn as_u64(&self) -> Option<u64> {
        let n = self.as_f64()?;
        if !n.is_finite() || n.trunc() != n || n < 0.0 || n > ContractLimits::MAX_SAFE_INTEGER {
            return None;
        }
        Some(n as u64)
    }

    #[inline]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            JsonValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    #[inline]
    pub fn is_null(&self) -> bool {
        matches!(self, JsonValue::Null)
    }

    /// Serializes this value into deterministic compact canonical JSON:
    /// sorted object keys, no whitespace, `/` unescaped, no Unicode
    /// normalization, `-0.0` formatted as `0`, and safe whole numbers without `.0`.
    pub fn canonical_string(&self) -> Result<String, ProtocolError> {
        let mut out = String::new();
        write_canonical(self, &mut out)?;
        Ok(out)
    }

    /// Serializes this value into canonical UTF-8 JSON bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        Ok(self.canonical_string()?.into_bytes())
    }
}

impl From<bool> for JsonValue {
    fn from(value: bool) -> Self {
        JsonValue::Bool(value)
    }
}

impl From<f64> for JsonValue {
    fn from(value: f64) -> Self {
        JsonValue::Number(value)
    }
}

impl From<i32> for JsonValue {
    fn from(value: i32) -> Self {
        JsonValue::Number(f64::from(value))
    }
}

impl From<u32> for JsonValue {
    fn from(value: u32) -> Self {
        JsonValue::Number(f64::from(value))
    }
}

impl From<i64> for JsonValue {
    fn from(value: i64) -> Self {
        JsonValue::Number(value as f64)
    }
}

impl From<u64> for JsonValue {
    fn from(value: u64) -> Self {
        JsonValue::Number(value as f64)
    }
}

impl From<usize> for JsonValue {
    fn from(value: usize) -> Self {
        JsonValue::Number(value as f64)
    }
}

impl From<String> for JsonValue {
    fn from(value: String) -> Self {
        JsonValue::String(value)
    }
}

impl From<&str> for JsonValue {
    fn from(value: &str) -> Self {
        JsonValue::String(value.to_owned())
    }
}

impl From<Vec<JsonValue>> for JsonValue {
    fn from(value: Vec<JsonValue>) -> Self {
        JsonValue::Array(value)
    }
}

impl From<BTreeMap<String, JsonValue>> for JsonValue {
    fn from(value: BTreeMap<String, JsonValue>) -> Self {
        JsonValue::Object(value)
    }
}

fn write_canonical(value: &JsonValue, out: &mut String) -> Result<(), ProtocolError> {
    match value {
        JsonValue::Null => out.push_str("null"),
        JsonValue::Bool(true) => out.push_str("true"),
        JsonValue::Bool(false) => out.push_str("false"),
        JsonValue::Number(n) => {
            if !n.is_finite() {
                return Err(ProtocolError::InvalidMessage);
            }
            if *n == 0.0 {
                // Normalize both +0.0 and -0.0 to "0".
                out.push('0');
            } else if n.fract() == 0.0 && n.abs() <= ContractLimits::MAX_SAFE_INTEGER {
                let _ = write!(out, "{}", *n as i64);
            } else {
                let abs = n.abs();
                if !(1e-6..1e21).contains(&abs) {
                    let _ = write!(out, "{:e}", n);
                } else {
                    let _ = write!(out, "{}", n);
                }
            }
        }
        JsonValue::String(s) => write_json_string(s, out),
        JsonValue::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical(item, out)?;
            }
            out.push(']');
        }
        JsonValue::Object(map) => {
            out.push('{');
            for (index, (key, val)) in map.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_json_string(key, out);
                out.push(':');
                write_canonical(val, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_json_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            // Note: '/' is intentionally NOT escaped and Unicode is NOT normalized.
            c => out.push(c),
        }
    }
    out.push('"');
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> JsonParser<'a> {
    fn parse(&mut self) -> Result<JsonValue, ProtocolError> {
        // UTF-8 BOM (EF BB BF) is NOT RFC 8259 whitespace and is never stripped.
        let value = self.parse_value(0)?;
        self.skip_whitespace();
        if self.offset != self.bytes.len() {
            return Err(ProtocolError::InvalidMessage);
        }
        Ok(value)
    }

    fn parse_value(&mut self, depth: usize) -> Result<JsonValue, ProtocolError> {
        if depth > ContractLimits::MAX_DEPTH {
            return Err(ProtocolError::InvalidMessage);
        }
        self.skip_whitespace();
        let &byte = self
            .bytes
            .get(self.offset)
            .ok_or(ProtocolError::InvalidMessage)?;
        match byte {
            b'{' => {
                self.offset += 1;
                let mut result = BTreeMap::new();
                self.skip_whitespace();
                if self.consume(b'}') {
                    return Ok(JsonValue::Object(result));
                }
                loop {
                    self.skip_whitespace();
                    let key = self.parse_string()?;
                    self.skip_whitespace();
                    if !self.consume(b':') {
                        return Err(ProtocolError::InvalidMessage);
                    }
                    let val = self.parse_value(depth + 1)?;
                    // Duplicate object keys use last-key-wins to match JS JSON.parse and Swift.
                    result.insert(key, val);
                    self.skip_whitespace();
                    if self.consume(b'}') {
                        return Ok(JsonValue::Object(result));
                    }
                    if !self.consume(b',') {
                        return Err(ProtocolError::InvalidMessage);
                    }
                }
            }
            b'[' => {
                self.offset += 1;
                let mut result = Vec::new();
                self.skip_whitespace();
                if self.consume(b']') {
                    return Ok(JsonValue::Array(result));
                }
                loop {
                    result.push(self.parse_value(depth + 1)?);
                    self.skip_whitespace();
                    if self.consume(b']') {
                        return Ok(JsonValue::Array(result));
                    }
                    if !self.consume(b',') {
                        return Err(ProtocolError::InvalidMessage);
                    }
                }
            }
            b'"' => Ok(JsonValue::String(self.parse_string()?)),
            b't' => {
                self.consume_literal(b"true")?;
                Ok(JsonValue::Bool(true))
            }
            b'f' => {
                self.consume_literal(b"false")?;
                Ok(JsonValue::Bool(false))
            }
            b'n' => {
                self.consume_literal(b"null")?;
                Ok(JsonValue::Null)
            }
            b'-' | b'0'..=b'9' => Ok(JsonValue::Number(self.parse_number()?)),
            _ => Err(ProtocolError::InvalidMessage),
        }
    }

    fn parse_string(&mut self) -> Result<String, ProtocolError> {
        if !self.consume(b'"') {
            return Err(ProtocolError::InvalidMessage);
        }
        let mut buf: Vec<u8> = Vec::new();
        while self.offset < self.bytes.len() {
            let byte = self.bytes[self.offset];
            self.offset += 1;
            if byte == b'"' {
                return String::from_utf8(buf).map_err(|_| ProtocolError::InvalidMessage);
            }
            if byte < 0x20 {
                return Err(ProtocolError::InvalidMessage);
            }
            if byte != b'\\' {
                buf.push(byte);
                continue;
            }
            let &escaped = self
                .bytes
                .get(self.offset)
                .ok_or(ProtocolError::InvalidMessage)?;
            self.offset += 1;
            match escaped {
                b'"' | b'\\' | b'/' => buf.push(escaped),
                b'b' => buf.push(0x08),
                b'f' => buf.push(0x0C),
                b'n' => buf.push(0x0A),
                b'r' => buf.push(0x0D),
                b't' => buf.push(0x09),
                b'u' => {
                    let first = self.parse_hex_unit()?;
                    let scalar = if (0xD800..=0xDBFF).contains(&first) {
                        if !self.consume(b'\\') || !self.consume(b'u') {
                            return Err(ProtocolError::InvalidMessage);
                        }
                        let second = self.parse_hex_unit()?;
                        if !(0xDC00..=0xDFFF).contains(&second) {
                            return Err(ProtocolError::InvalidMessage);
                        }
                        0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
                    } else if (0xDC00..=0xDFFF).contains(&first) {
                        return Err(ProtocolError::InvalidMessage);
                    } else {
                        first
                    };
                    let ch = char::from_u32(scalar).ok_or(ProtocolError::InvalidMessage)?;
                    let mut utf8 = [0u8; 4];
                    buf.extend_from_slice(ch.encode_utf8(&mut utf8).as_bytes());
                }
                _ => return Err(ProtocolError::InvalidMessage),
            }
        }
        Err(ProtocolError::InvalidMessage)
    }

    fn parse_hex_unit(&mut self) -> Result<u32, ProtocolError> {
        let mut value: u32 = 0;
        for _ in 0..4 {
            let &byte = self
                .bytes
                .get(self.offset)
                .ok_or(ProtocolError::InvalidMessage)?;
            self.offset += 1;
            let digit = match byte {
                b'0'..=b'9' => u32::from(byte - b'0'),
                b'A'..=b'F' => u32::from(byte - b'A' + 10),
                b'a'..=b'f' => u32::from(byte - b'a' + 10),
                _ => return Err(ProtocolError::InvalidMessage),
            };
            value = (value << 4) | digit;
        }
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<f64, ProtocolError> {
        let start = self.offset;
        let _ = self.consume(b'-');
        if !self.consume(b'0') {
            let &first = self
                .bytes
                .get(self.offset)
                .ok_or(ProtocolError::InvalidMessage)?;
            if !(b'1'..=b'9').contains(&first) {
                return Err(ProtocolError::InvalidMessage);
            }
            self.offset += 1;
            while self.offset < self.bytes.len() && self.bytes[self.offset].is_ascii_digit() {
                self.offset += 1;
            }
        }
        if self.consume(b'.') {
            self.consume_digits()?;
        }
        if self.consume(b'e') || self.consume(b'E') {
            if !self.consume(b'+') {
                let _ = self.consume(b'-');
            }
            self.consume_digits()?;
        }
        let slice = std::str::from_utf8(&self.bytes[start..self.offset])
            .map_err(|_| ProtocolError::InvalidMessage)?;
        let value: f64 = slice.parse().map_err(|_| ProtocolError::InvalidMessage)?;
        if !value.is_finite() {
            return Err(ProtocolError::InvalidMessage);
        }
        Ok(value)
    }

    fn consume_digits(&mut self) -> Result<(), ProtocolError> {
        let start = self.offset;
        while self.offset < self.bytes.len() && self.bytes[self.offset].is_ascii_digit() {
            self.offset += 1;
        }
        if self.offset == start {
            return Err(ProtocolError::InvalidMessage);
        }
        Ok(())
    }

    fn consume_literal(&mut self, literal: &[u8]) -> Result<(), ProtocolError> {
        if self.bytes[self.offset..].starts_with(literal) {
            self.offset += literal.len();
            Ok(())
        } else {
            Err(ProtocolError::InvalidMessage)
        }
    }

    #[inline]
    fn consume(&mut self, byte: u8) -> bool {
        if self.bytes.get(self.offset) == Some(&byte) {
            self.offset += 1;
            true
        } else {
            false
        }
    }

    #[inline]
    fn skip_whitespace(&mut self) {
        while let Some(&b) = self.bytes.get(self.offset) {
            if matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
                self.offset += 1;
            } else {
                break;
            }
        }
    }
}
