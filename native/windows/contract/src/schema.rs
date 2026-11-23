use std::collections::BTreeMap;

use crate::json::{utf16_len, JsonValue};
use crate::validator::{ContractLimits, ProtocolError};

/// Draft 2020-12 JSON Schema subset validator for `wire.schema.json`.
///
/// Mirrors `validate.ts` and `ContractValidator.swift`: depth starts at `0`
/// and increments by `1` for every `$ref`, `oneOf` branch, object property,
/// and array element, failing closed once `depth > ContractLimits::MAX_DEPTH`.
#[derive(Debug, Clone)]
pub struct SchemaValidator {
    root: JsonValue,
    definitions: BTreeMap<String, JsonValue>,
}

impl SchemaValidator {
    pub fn new(root: JsonValue) -> Result<Self, ProtocolError> {
        let definitions = root
            .get("$defs")
            .and_then(JsonValue::as_obj)
            .cloned()
            .ok_or(ProtocolError::InvalidMessage)?;
        Ok(Self { root, definitions })
    }

    pub fn validate(&self, value: &JsonValue) -> Result<(), ProtocolError> {
        self.validate_node(value, &self.root, 0)
    }

    pub fn validate_node(
        &self,
        value: &JsonValue,
        node: &JsonValue,
        depth: usize,
    ) -> Result<(), ProtocolError> {
        if depth > ContractLimits::MAX_DEPTH {
            return Err(ProtocolError::InvalidMessage);
        }
        let rule = node.as_obj().ok_or(ProtocolError::InvalidMessage)?;

        if let Some(ref_val) = rule.get("$ref") {
            let reference = ref_val.as_str().ok_or(ProtocolError::InvalidMessage)?;
            let name = reference
                .strip_prefix("#/$defs/")
                .filter(|s| !s.is_empty() && !s.contains('/'))
                .ok_or(ProtocolError::InvalidMessage)?;
            let target = self
                .definitions
                .get(name)
                .ok_or(ProtocolError::InvalidMessage)?;
            return self.validate_node(value, target, depth + 1);
        }

        if let Some(one_of_val) = rule.get("oneOf") {
            let branches = one_of_val.as_array().ok_or(ProtocolError::InvalidMessage)?;
            let mut matches = 0usize;
            for branch in branches {
                if self.validate_node(value, branch, depth + 1).is_ok() {
                    matches += 1;
                }
            }
            return if matches == 1 {
                Ok(())
            } else {
                Err(ProtocolError::InvalidMessage)
            };
        }

        if let Some(expected) = rule.get("const") {
            if value != expected {
                return Err(ProtocolError::InvalidMessage);
            }
        }

        if let Some(enum_values) = rule.get("enum") {
            let values = enum_values.as_array().ok_or(ProtocolError::InvalidMessage)?;
            if !values.iter().any(|candidate| candidate == value) {
                return Err(ProtocolError::InvalidMessage);
            }
        }

        match rule.get("type") {
            Some(JsonValue::String(kind)) => match kind.as_str() {
                "object" => {
                    let record = value.as_obj().ok_or(ProtocolError::InvalidMessage)?;
                    let empty = BTreeMap::new();
                    let properties = rule
                        .get("properties")
                        .and_then(JsonValue::as_obj)
                        .unwrap_or(&empty);
                    if let Some(required) = rule.get("required").and_then(JsonValue::as_array) {
                        for req in required {
                            let key = req.as_str().ok_or(ProtocolError::InvalidMessage)?;
                            if !record.contains_key(key) {
                                return Err(ProtocolError::InvalidMessage);
                            }
                        }
                    }
                    // Every generated object is closed; unknown keys always fail.
                    for (key, child) in record {
                        let child_rule = properties.get(key).ok_or(ProtocolError::InvalidMessage)?;
                        self.validate_node(child, child_rule, depth + 1)?;
                    }
                    Ok(())
                }
                "array" => {
                    let items = value.as_array().ok_or(ProtocolError::InvalidMessage)?;
                    let min_items = rule
                        .get("minItems")
                        .and_then(JsonValue::as_f64)
                        .unwrap_or(0.0);
                    let max_items = rule
                        .get("maxItems")
                        .and_then(JsonValue::as_f64)
                        .unwrap_or(ContractLimits::MAX_COLLECTION_ITEMS as f64);
                    let count = items.len() as f64;
                    if count < min_items || count > max_items {
                        return Err(ProtocolError::InvalidMessage);
                    }
                    let item_rule = rule.get("items").ok_or(ProtocolError::InvalidMessage)?;
                    for item in items {
                        self.validate_node(item, item_rule, depth + 1)?;
                    }
                    Ok(())
                }
                "string" => {
                    let text = value.as_str().ok_or(ProtocolError::InvalidMessage)?;
                    let min_len = rule
                        .get("minLength")
                        .and_then(JsonValue::as_f64)
                        .unwrap_or(0.0);
                    let max_len = rule
                        .get("maxLength")
                        .and_then(JsonValue::as_f64)
                        .unwrap_or(ContractLimits::MAX_TEXT_CODE_UNITS as f64);
                    // JSON Schema counts Unicode scalar values.
                    let scalar_count = text.chars().count() as f64;
                    if scalar_count < min_len || scalar_count > max_len {
                        return Err(ProtocolError::InvalidMessage);
                    }
                    // Wire v1 extension separately bounds UTF-16 code units.
                    if let Some(max_utf16) =
                        rule.get("x-maxUtf16CodeUnits").and_then(JsonValue::as_f64)
                    {
                        if (utf16_len(text) as f64) > max_utf16 {
                            return Err(ProtocolError::InvalidMessage);
                        }
                    }
                    Ok(())
                }
                "integer" | "number" => {
                    let number = value.as_f64().ok_or(ProtocolError::InvalidMessage)?;
                    if !number.is_finite() {
                        return Err(ProtocolError::InvalidMessage);
                    }
                    if kind == "integer"
                        && (number.trunc() != number
                            || number.abs() > ContractLimits::MAX_SAFE_INTEGER)
                    {
                        return Err(ProtocolError::InvalidMessage);
                    }
                    let min = rule
                        .get("minimum")
                        .and_then(JsonValue::as_f64)
                        .unwrap_or(f64::NEG_INFINITY);
                    let max = rule
                        .get("maximum")
                        .and_then(JsonValue::as_f64)
                        .unwrap_or(f64::INFINITY);
                    if number < min || number > max {
                        return Err(ProtocolError::InvalidMessage);
                    }
                    Ok(())
                }
                "boolean" => {
                    if value.as_bool().is_some() {
                        Ok(())
                    } else {
                        Err(ProtocolError::InvalidMessage)
                    }
                }
                _ => Err(ProtocolError::InvalidMessage),
            },
            None => {
                if rule.contains_key("const") || rule.contains_key("enum") {
                    Ok(())
                } else {
                    Err(ProtocolError::InvalidMessage)
                }
            }
            Some(_) => Err(ProtocolError::InvalidMessage),
        }
    }
}
