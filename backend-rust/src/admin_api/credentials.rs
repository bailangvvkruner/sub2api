use std::collections::BTreeMap;

use serde_json::{Map, Value};

pub const SENSITIVE_CREDENTIAL_KEYS: &[&str] = &[
    "access_token",
    "refresh_token",
    "id_token",
    "api_key",
    "session_key",
    "cookie",
    "aws_secret_access_key",
    "aws_session_token",
    "service_account_json",
    "service_account",
    "private_key",
];

#[must_use]
pub fn merge_credentials(existing: &Value, incoming: &Value) -> Value {
    let existing = existing.as_object();
    let Some(incoming) = incoming.as_object() else {
        return existing.map_or_else(
            || Value::Object(Map::new()),
            |value| Value::Object(value.clone()),
        );
    };
    let mut merged = incoming.clone();
    if let Some(existing) = existing {
        for key in SENSITIVE_CREDENTIAL_KEYS {
            if !incoming.contains_key(*key)
                && let Some(value) = existing.get(*key)
            {
                merged.insert((*key).to_owned(), value.clone());
            }
        }
    }
    Value::Object(merged)
}

#[must_use]
pub fn redact_credentials(credentials: &Value) -> (Value, BTreeMap<String, bool>) {
    let Some(credentials) = credentials.as_object() else {
        return (Value::Object(Map::new()), BTreeMap::new());
    };
    let mut redacted = credentials.clone();
    let mut status = BTreeMap::new();
    for key in SENSITIVE_CREDENTIAL_KEYS {
        if let Some(value) = redacted.remove(*key)
            && credential_present(&value)
        {
            status.insert(format!("has_{key}"), true);
        }
    }
    (Value::Object(redacted), status)
}

fn credential_present(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::String(value) => !value.is_empty(),
        _ => true,
    }
}
