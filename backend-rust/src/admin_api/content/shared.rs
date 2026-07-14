use axum::{
    Json,
    http::{HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use serde_json::Value;

use crate::admin_api::models::AdminError;

#[derive(Debug, Serialize)]
pub(super) struct Envelope<T> {
    code: u16,
    message: &'static str,
    data: T,
}

impl<T> Envelope<T> {
    pub(super) const fn success(data: T) -> Self {
        Self {
            code: 0,
            message: "success",
            data,
        }
    }
}

pub(super) fn success<T: Serialize>(data: T) -> Response {
    Json(Envelope::success(data)).into_response()
}

pub(super) fn created<T: Serialize>(data: T) -> Response {
    (StatusCode::CREATED, Json(Envelope::success(data))).into_response()
}

pub(super) fn json_text(raw: &str) -> serde_json::Value {
    serde_json::from_str(raw).unwrap_or(serde_json::Value::Null)
}

pub(super) fn trim_to(value: &str, max_chars: usize) -> String {
    value.trim().chars().take(max_chars).collect()
}

pub(super) fn normalize_provider(value: &str) -> Result<String, AdminError> {
    let value = value.trim().to_ascii_lowercase();
    if matches!(value.as_str(), "openai" | "anthropic" | "gemini") {
        Ok(value)
    } else {
        Err(AdminError::BadRequest(
            "provider must be openai, anthropic, or gemini".to_owned(),
        ))
    }
}

pub(super) fn normalize_api_mode(provider: &str, value: &str) -> Result<String, AdminError> {
    let value = if value.trim().is_empty() {
        "chat_completions"
    } else {
        value.trim()
    };
    if value == "chat_completions" || (provider == "openai" && value == "responses") {
        Ok(value.to_owned())
    } else {
        Err(AdminError::BadRequest(
            "api_mode must be chat_completions; responses is only supported for openai".to_owned(),
        ))
    }
}

pub(super) fn normalize_headers(
    headers: std::collections::BTreeMap<String, String>,
) -> Result<std::collections::BTreeMap<String, String>, AdminError> {
    let mut normalized = std::collections::BTreeMap::new();
    for (name, value) in headers {
        let name = name.trim();
        let lower = name.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "host" | "content-length" | "content-encoding" | "transfer-encoding" | "connection"
        ) {
            return Err(AdminError::BadRequest(format!(
                "header {name:?} cannot be overridden"
            )));
        }
        HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| AdminError::BadRequest(format!("header name {name:?} is invalid")))?;
        HeaderValue::from_str(&value)
            .map_err(|_| AdminError::BadRequest(format!("header value for {name:?} is invalid")))?;
        normalized.insert(name.to_owned(), value);
    }
    Ok(normalized)
}

pub(super) fn normalize_body_config(
    provider: &str,
    api_mode: &str,
    mode: &str,
    body: Option<Value>,
) -> Result<(String, Option<Value>), AdminError> {
    let mode = if mode.trim().is_empty() {
        "off"
    } else {
        mode.trim()
    };
    if !matches!(mode, "off" | "merge" | "replace") {
        return Err(AdminError::BadRequest(
            "body_override_mode must be off, merge, or replace".to_owned(),
        ));
    }
    let body = match body {
        Some(Value::Null) | None => None,
        Some(value) if value.is_object() => Some(value),
        Some(_) => {
            return Err(AdminError::BadRequest(
                "body_override must be a JSON object".to_owned(),
            ));
        }
    };
    if mode != "off"
        && body
            .as_ref()
            .and_then(Value::as_object)
            .is_none_or(serde_json::Map::is_empty)
    {
        return Err(AdminError::BadRequest(
            "body_override is required when body_override_mode is merge or replace".to_owned(),
        ));
    }
    if mode == "replace" && provider == "openai" {
        let object = body
            .as_ref()
            .and_then(Value::as_object)
            .ok_or_else(|| AdminError::BadRequest("replace-mode body is required".to_owned()))?;
        if api_mode == "responses" {
            let instructions = object
                .get("instructions")
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or_default();
            if instructions.is_empty() || object.get("input").is_none_or(value_is_empty) {
                return Err(AdminError::BadRequest(
                    "replace-mode responses body requires non-empty instructions and input"
                        .to_owned(),
                ));
            }
        } else if object.get("messages").is_none_or(value_is_empty) {
            return Err(AdminError::BadRequest(
                "replace-mode chat_completions body requires non-empty messages".to_owned(),
            ));
        }
    }
    Ok((mode.to_owned(), body))
}

fn value_is_empty(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(value) => value.trim().is_empty(),
        Value::Array(value) => value.is_empty(),
        Value::Object(value) => value.is_empty(),
        Value::Bool(_) | Value::Number(_) => false,
    }
}
