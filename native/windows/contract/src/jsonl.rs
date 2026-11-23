use crate::json::JsonValue;
use crate::validator::{ContractLimits, ContractValidator, ProtocolError};

/// Result of validating a single NDJSON line.
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationResult {
    Valid(JsonValue),
    Invalid(ProtocolError),
}

impl ValidationResult {
    /// Converts the result to the canonical response object.
    /// Invalid responses contain only `"code"` and `"valid": false` — never input fragments.
    pub fn to_json_value(&self) -> JsonValue {
        match self {
            ValidationResult::Valid(message) => JsonValue::object([
                ("message", message.clone()),
                ("valid", JsonValue::Bool(true)),
            ]),
            ValidationResult::Invalid(error) => JsonValue::object([
                ("code", JsonValue::String(error.code().to_owned())),
                ("valid", JsonValue::Bool(false)),
            ]),
        }
    }

    /// Encodes this result as canonical JSON plus trailing LF (`0x0A`).
    pub fn encoded_line(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut bytes = self.to_json_value().canonical_bytes()?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

/// Bounded, recovering streaming NDJSON validator.
///
/// Emits one `ValidationResult` per LF-delimited input line without echoing
/// invalid input and without allowing malformed or oversized lines to grow
/// buffered RAM past `ContractLimits::MAX_FRAME_BYTES` (65,536 bytes, including LF).
/// A nonempty unterminated line at EOF always fails with `invalid-message`
/// (or `frame-too-large` if already discarding an oversized line).
#[derive(Debug, Clone)]
pub struct JsonlValidator {
    validator: ContractValidator,
    pending: Vec<u8>,
    discarding_oversize: bool,
}

impl JsonlValidator {
    pub fn new(validator: ContractValidator) -> Self {
        Self {
            validator,
            pending: Vec::new(),
            discarding_oversize: false,
        }
    }

    /// Current buffered byte count, exposed so tests can verify the hard RAM bound.
    #[inline]
    pub fn buffered_byte_count(&self) -> usize {
        self.pending.len()
    }

    /// Feeds a chunk of raw bytes and invokes `emit` for each completed line.
    pub fn push<F, E>(&mut self, chunk: &[u8], mut emit: F) -> Result<(), E>
    where
        F: FnMut(ValidationResult) -> Result<(), E>,
    {
        for &byte in chunk {
            if byte == b'\n' {
                let result = if self.discarding_oversize
                    || self.pending.len() + 1 > ContractLimits::MAX_FRAME_BYTES
                {
                    ValidationResult::Invalid(ProtocolError::FrameTooLarge)
                } else {
                    match self.validator.decode_frame(&self.pending) {
                        Ok(value) => ValidationResult::Valid(value),
                        Err(err) => ValidationResult::Invalid(err),
                    }
                };
                self.pending.clear();
                self.discarding_oversize = false;
                emit(result)?;
            } else if !self.discarding_oversize {
                if self.pending.len() == ContractLimits::MAX_FRAME_BYTES {
                    self.pending.clear();
                    self.discarding_oversize = true;
                } else {
                    self.pending.push(byte);
                }
            }
        }
        Ok(())
    }

    /// Finalizes the stream at EOF, emitting an error if a partial or oversized
    /// unterminated line remained buffered.
    pub fn finish<F, E>(&mut self, mut emit: F) -> Result<(), E>
    where
        F: FnMut(ValidationResult) -> Result<(), E>,
    {
        let result = if self.discarding_oversize {
            Some(ValidationResult::Invalid(ProtocolError::FrameTooLarge))
        } else if !self.pending.is_empty() {
            Some(ValidationResult::Invalid(ProtocolError::InvalidMessage))
        } else {
            None
        };
        self.pending.clear();
        self.pending.shrink_to_fit();
        self.discarding_oversize = false;
        if let Some(res) = result {
            emit(res)?;
        }
        Ok(())
    }
}
