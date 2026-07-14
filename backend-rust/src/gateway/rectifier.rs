use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::Protocol;

const BUDGET_TOKENS: i64 = 32_000;
const MAX_TOKENS: i64 = 64_000;
const GEMINI_DUMMY_THOUGHT_SIGNATURE: &str = "skip_thought_signature_validator";

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
#[allow(clippy::struct_excessive_bools)]
pub(super) struct RectifierSettings {
    pub enabled: bool,
    pub thinking_signature_enabled: bool,
    pub thinking_budget_enabled: bool,
    pub apikey_signature_enabled: bool,
    pub apikey_signature_patterns: Vec<String>,
}

impl RectifierSettings {
    pub(super) fn rectify(
        &self,
        account_type: &str,
        protocol: Protocol,
        error_body: &[u8],
        request_body: &[u8],
    ) -> Option<RectifiedRequest> {
        if !self.enabled {
            return None;
        }
        let error = String::from_utf8_lossy(error_body).to_lowercase();
        if self.thinking_budget_enabled && is_thinking_budget_error(&error) {
            return rectify_thinking_budget(request_body).map(|body| RectifiedRequest {
                body,
                kind: RectificationKind::ThinkingBudget,
            });
        }
        if !self.signature_enabled_for(account_type, &error) {
            return None;
        }
        let body = match protocol {
            Protocol::Gemini => rectify_gemini_signatures(request_body),
            Protocol::Anthropic | Protocol::OpenAi => rectify_anthropic_signatures(request_body),
        }?;
        Some(RectifiedRequest {
            body,
            kind: RectificationKind::ThinkingSignature,
        })
    }

    fn signature_enabled_for(&self, account_type: &str, error: &str) -> bool {
        let is_api_key = account_type.trim().eq_ignore_ascii_case("apikey");
        if is_api_key {
            return self.apikey_signature_enabled
                && (is_signature_error(error)
                    || self.apikey_signature_patterns.iter().any(|pattern| {
                        let pattern = pattern.trim().to_lowercase();
                        !pattern.is_empty() && error.contains(&pattern)
                    }));
        }
        self.thinking_signature_enabled && is_signature_error(error)
    }
}

impl Default for RectifierSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            thinking_signature_enabled: true,
            thinking_budget_enabled: true,
            apikey_signature_enabled: false,
            apikey_signature_patterns: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RectificationKind {
    ThinkingSignature,
    ThinkingBudget,
}

impl RectificationKind {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::ThinkingSignature => "thinking_signature",
            Self::ThinkingBudget => "thinking_budget",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RectifiedRequest {
    pub body: Vec<u8>,
    pub kind: RectificationKind,
}

fn is_thinking_budget_error(error: &str) -> bool {
    let has_budget = error.contains("budget_tokens") || error.contains("budget tokens");
    let has_constraint = error.contains(">= 1024")
        || error.contains("greater than or equal to 1024")
        || (error.contains("1024") && error.contains("input should be"));
    has_budget && error.contains("thinking") && has_constraint
}

fn is_signature_error(error: &str) -> bool {
    error.contains("signature")
        || (error.contains("expected")
            && (error.contains("thinking") || error.contains("redacted_thinking")))
        || (error.contains("cannot be modified")
            && (error.contains("thinking") || error.contains("redacted_thinking")))
        || error.contains("non-empty content")
        || error.contains("empty content")
        || error.contains("content blocks must be non-empty")
        || error.contains("thinking block must contain")
}

fn rectify_thinking_budget(body: &[u8]) -> Option<Vec<u8>> {
    let mut value = serde_json::from_slice::<Value>(body).ok()?;
    let object = value.as_object_mut()?;
    if object
        .get("thinking")
        .and_then(Value::as_object)
        .and_then(|thinking| thinking.get("type"))
        .and_then(Value::as_str)
        .is_some_and(|kind| kind.eq_ignore_ascii_case("adaptive"))
    {
        return None;
    }
    let expected_thinking = json!({"type": "enabled", "budget_tokens": BUDGET_TOKENS});
    let changed = object.get("thinking") != Some(&expected_thinking)
        || object.get("max_tokens").and_then(Value::as_i64) != Some(MAX_TOKENS);
    if !changed {
        return None;
    }
    object.insert("thinking".to_owned(), expected_thinking);
    object.insert("max_tokens".to_owned(), Value::from(MAX_TOKENS));
    serde_json::to_vec(&value).ok()
}

fn rectify_anthropic_signatures(body: &[u8]) -> Option<Vec<u8>> {
    let mut value = serde_json::from_slice::<Value>(body).ok()?;
    let object = value.as_object_mut()?;
    let mut changed = object.remove("thinking").is_some();
    changed |= remove_thinking_context_strategies(object);

    if let Some(messages) = object.get_mut("messages").and_then(Value::as_array_mut) {
        for message in messages {
            let Some(message) = message.as_object_mut() else {
                continue;
            };
            let is_assistant = message.get("role").and_then(Value::as_str) == Some("assistant");
            let Some(content) = message.get_mut("content").and_then(Value::as_array_mut) else {
                continue;
            };
            let original = std::mem::take(content);
            let mut cleaned = Vec::with_capacity(original.len());
            for mut block in original {
                let Some(block_object) = block.as_object_mut() else {
                    cleaned.push(block);
                    continue;
                };
                match block_object.get("type").and_then(Value::as_str) {
                    Some("thinking") => {
                        changed = true;
                        if let Some(text) = block_object
                            .get("thinking")
                            .and_then(Value::as_str)
                            .filter(|text| !text.is_empty())
                        {
                            cleaned.push(json!({"type": "text", "text": text}));
                        }
                    }
                    Some("redacted_thinking") => changed = true,
                    Some("text")
                        if block_object
                            .get("text")
                            .and_then(Value::as_str)
                            .is_some_and(str::is_empty) =>
                    {
                        changed = true;
                    }
                    None if block_object.contains_key("thinking") => {
                        changed = true;
                        if let Some(text) = thinking_value_as_text(&block_object["thinking"])
                            .filter(|text| !text.is_empty())
                        {
                            cleaned.push(json!({"type": "text", "text": text}));
                        }
                    }
                    _ => cleaned.push(block),
                }
            }
            if cleaned.is_empty() {
                changed = true;
                let placeholder = if is_assistant {
                    "(assistant content removed)"
                } else {
                    "(content removed)"
                };
                cleaned.push(json!({"type": "text", "text": placeholder}));
            }
            *content = cleaned;
        }
    }
    if !changed {
        return None;
    }
    serde_json::to_vec(&value).ok()
}

fn remove_thinking_context_strategies(object: &mut Map<String, Value>) -> bool {
    let Some(edits) = object
        .get_mut("context_management")
        .and_then(Value::as_object_mut)
        .and_then(|context| context.get_mut("edits"))
        .and_then(Value::as_array_mut)
    else {
        return false;
    };
    let before = edits.len();
    edits
        .retain(|edit| edit.get("type").and_then(Value::as_str) != Some("clear_thinking_20251015"));
    edits.len() != before
}

fn thinking_value_as_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Null => None,
        value => serde_json::to_string(value).ok(),
    }
}

fn rectify_gemini_signatures(body: &[u8]) -> Option<Vec<u8>> {
    let mut value = serde_json::from_slice::<Value>(body).ok()?;
    if !replace_thought_signatures(&mut value) {
        return None;
    }
    serde_json::to_vec(&value).ok()
}

fn replace_thought_signatures(value: &mut Value) -> bool {
    match value {
        Value::Object(object) => {
            let mut changed = false;
            for (key, value) in object {
                if key == "thoughtSignature" {
                    if value.as_str() != Some(GEMINI_DUMMY_THOUGHT_SIGNATURE) {
                        *value = Value::String(GEMINI_DUMMY_THOUGHT_SIGNATURE.to_owned());
                        changed = true;
                    }
                } else {
                    changed |= replace_thought_signatures(value);
                }
            }
            changed
        }
        Value::Array(items) => {
            let mut changed = false;
            for item in items {
                changed |= replace_thought_signatures(item);
            }
            changed
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{
        GEMINI_DUMMY_THOUGHT_SIGNATURE, RectificationKind, RectifierSettings,
        is_thinking_budget_error,
    };
    use crate::gateway::Protocol;

    #[test]
    fn budget_detection_requires_all_constraint_markers_and_skips_adaptive() {
        assert!(is_thinking_budget_error(
            "thinking budget_tokens input should be >= 1024"
        ));
        assert!(!is_thinking_budget_error("budget_tokens must be >= 1024"));
        let settings = RectifierSettings::default();
        let adaptive = br#"{"thinking":{"type":"adaptive"},"max_tokens":1000}"#;
        assert!(
            settings
                .rectify(
                    "oauth",
                    Protocol::Anthropic,
                    b"thinking budget_tokens must be >= 1024",
                    adaptive,
                )
                .is_none()
        );
        let rectified = settings
            .rectify(
                "oauth",
                Protocol::Anthropic,
                b"thinking budget tokens must be greater than or equal to 1024",
                br#"{"max_tokens":1000}"#,
            )
            .unwrap();
        assert_eq!(rectified.kind, RectificationKind::ThinkingBudget);
        let value: Value = serde_json::from_slice(&rectified.body).unwrap();
        assert_eq!(value["thinking"]["budget_tokens"], 32_000);
        assert_eq!(value["max_tokens"], 64_000);
    }

    #[test]
    fn anthropic_signature_rectification_preserves_text_and_repairs_empty_messages() {
        let body = json!({
            "thinking": {"type": "enabled", "budget_tokens": 2048},
            "messages": [
                {"role":"assistant","content":[
                    {"type":"thinking","thinking":"private","signature":"stale"},
                    {"type":"redacted_thinking","data":"opaque"}
                ]},
                {"role":"user","content":[]}
            ]
        });
        let rectified = RectifierSettings::default()
            .rectify(
                "oauth",
                Protocol::Anthropic,
                b"invalid signature in thinking block",
                &serde_json::to_vec(&body).unwrap(),
            )
            .unwrap();
        let value: Value = serde_json::from_slice(&rectified.body).unwrap();
        assert!(value.get("thinking").is_none());
        assert_eq!(value["messages"][0]["content"][0]["type"], "text");
        assert_eq!(value["messages"][0]["content"][0]["text"], "private");
        assert_eq!(
            value["messages"][1]["content"][0]["text"],
            "(content removed)"
        );
    }

    #[test]
    fn api_key_custom_patterns_are_independent_and_case_insensitive() {
        let mut settings = RectifierSettings {
            apikey_signature_enabled: true,
            apikey_signature_patterns: vec!["Vendor Thought Token".to_owned()],
            ..RectifierSettings::default()
        };
        let body = br#"{"messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"x"}]}]}"#;
        assert!(
            settings
                .rectify(
                    "apikey",
                    Protocol::Anthropic,
                    b"invalid VENDOR THOUGHT TOKEN",
                    body,
                )
                .is_some()
        );
        settings.apikey_signature_enabled = false;
        assert!(
            settings
                .rectify("apikey", Protocol::Anthropic, b"invalid signature", body,)
                .is_none()
        );
    }

    #[test]
    fn gemini_signature_rectification_replaces_nested_values_once() {
        let body = br#"{"contents":[{"parts":[{"thoughtSignature":"stale"}]}],"signature":"keep"}"#;
        let rectified = RectifierSettings::default()
            .rectify(
                "oauth",
                Protocol::Gemini,
                b"Corrupted thought signature",
                body,
            )
            .unwrap();
        let value: Value = serde_json::from_slice(&rectified.body).unwrap();
        assert_eq!(
            value["contents"][0]["parts"][0]["thoughtSignature"],
            GEMINI_DUMMY_THOUGHT_SIGNATURE
        );
        assert_eq!(value["signature"], "keep");
        assert!(
            RectifierSettings::default()
                .rectify(
                    "oauth",
                    Protocol::Gemini,
                    b"Corrupted thought signature",
                    &rectified.body,
                )
                .is_none()
        );
    }
}
