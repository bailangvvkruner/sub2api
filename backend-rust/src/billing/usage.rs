use std::{error::Error, fmt};

use serde_json::{Map, Value};

const MAX_SSE_LINE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsageProvider {
    Anthropic,
    OpenAi,
    Gemini,
}

#[allow(clippy::struct_field_names)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_creation_input_tokens: u64,
    pub cache_read_input_tokens: u64,
}

impl TokenUsage {
    /// Returns the sum of all disjoint billing token categories.
    ///
    /// # Errors
    ///
    /// Returns an error when the total exceeds `u64`.
    pub fn checked_total(self) -> Result<u64, UsageError> {
        self.input_tokens
            .checked_add(self.output_tokens)
            .and_then(|value| value.checked_add(self.cache_creation_input_tokens))
            .and_then(|value| value.checked_add(self.cache_read_input_tokens))
            .ok_or_else(|| UsageError::Overflow("total_tokens".to_owned()))
    }
}

/// Parses either a buffered JSON response or an SSE response.
///
/// # Errors
///
/// Returns an error for malformed JSON/SSE usage, invalid token fields, or a
/// response that contains no recognized usage object.
pub fn parse_usage(provider: UsageProvider, body: &[u8]) -> Result<TokenUsage, UsageError> {
    let text =
        std::str::from_utf8(body).map_err(|error| UsageError::InvalidUtf8(error.to_string()))?;
    if text.lines().any(|line| line.starts_with("data:")) {
        parse_sse_usage(provider, body)
    } else {
        parse_json_usage(provider, body)
    }
}

/// Parses usage from a buffered JSON response.
///
/// # Errors
///
/// Returns an error for malformed JSON, invalid token fields, or a response
/// that contains no recognized usage object.
pub fn parse_json_usage(provider: UsageProvider, body: &[u8]) -> Result<TokenUsage, UsageError> {
    let value: Value =
        serde_json::from_slice(body).map_err(|error| UsageError::InvalidJson(error.to_string()))?;
    let parts = parse_event(provider, &value)?.ok_or(UsageError::MissingUsage)?;
    parts.finalize(provider)
}

/// Parses line-oriented SSE `data:` payloads. Usage events are cumulative:
/// each present field replaces its prior value while absent fields are kept.
///
/// # Errors
///
/// Returns an error for non-UTF-8 input, malformed `data:` JSON, invalid token
/// fields, or a stream that contains no recognized usage object.
pub fn parse_sse_usage(provider: UsageProvider, body: &[u8]) -> Result<TokenUsage, UsageError> {
    let mut accumulator = SseUsageAccumulator::new(provider);
    accumulator.push(body)?;
    accumulator.finish()
}

/// Incrementally extracts cumulative usage from arbitrarily split SSE chunks.
#[derive(Debug)]
pub struct SseUsageAccumulator {
    provider: UsageProvider,
    pending_line: Vec<u8>,
    merged: UsageParts,
    found: bool,
}

impl SseUsageAccumulator {
    #[must_use]
    pub const fn new(provider: UsageProvider) -> Self {
        Self {
            provider,
            pending_line: Vec::new(),
            merged: UsageParts {
                input: None,
                output: None,
                extra_output: None,
                cache_creation: None,
                cache_read: None,
            },
            found: false,
        }
    }

    /// Consumes another byte chunk from an SSE response.
    ///
    /// # Errors
    ///
    /// Returns an error for a line larger than 1 MiB, malformed `data:` JSON,
    /// or invalid token fields.
    pub fn push(&mut self, chunk: &[u8]) -> Result<(), UsageError> {
        self.pending_line
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| UsageError::Overflow("SSE line buffer".to_owned()))?;
        let mut buffered = std::mem::take(&mut self.pending_line);
        buffered.reserve(chunk.len());
        buffered.extend_from_slice(chunk);

        let mut start = 0;
        while let Some(relative_end) = buffered[start..].iter().position(|byte| *byte == b'\n') {
            let end = start + relative_end;
            if end - start > MAX_SSE_LINE_BYTES {
                return Err(line_too_long());
            }
            self.process_line(&buffered[start..end])?;
            start = end + 1;
        }
        self.pending_line.extend_from_slice(&buffered[start..]);
        if self.pending_line.len() > MAX_SSE_LINE_BYTES {
            return Err(line_too_long());
        }
        Ok(())
    }

    /// Finalizes the stream, including a last line without a newline.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed usage or when the stream contained no
    /// recognized usage fields.
    pub fn finish(mut self) -> Result<TokenUsage, UsageError> {
        if !self.pending_line.is_empty() {
            let line = std::mem::take(&mut self.pending_line);
            self.process_line(&line)?;
        }
        if !self.found {
            return Err(UsageError::MissingUsage);
        }
        self.merged.finalize(self.provider)
    }

    fn process_line(&mut self, line: &[u8]) -> Result<(), UsageError> {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(payload) = line.strip_prefix(b"data:") else {
            return Ok(());
        };
        let payload = payload.strip_prefix(b" ").unwrap_or(payload);
        let payload = trim_ascii(payload);
        if payload.is_empty() || payload == b"[DONE]" {
            return Ok(());
        }
        let value: Value = serde_json::from_slice(payload)
            .map_err(|error| UsageError::InvalidSseData(error.to_string()))?;
        if let Some(parts) = parse_event(self.provider, &value)? {
            self.merged.merge(parts);
            self.found = true;
        }
        Ok(())
    }
}

fn line_too_long() -> UsageError {
    UsageError::InvalidSseData("SSE data line exceeds 1 MiB".to_owned())
}

fn trim_ascii(mut input: &[u8]) -> &[u8] {
    while input.first().is_some_and(u8::is_ascii_whitespace) {
        input = &input[1..];
    }
    while input.last().is_some_and(u8::is_ascii_whitespace) {
        input = &input[..input.len() - 1];
    }
    input
}

#[derive(Clone, Copy, Debug, Default)]
struct UsageParts {
    input: Option<u64>,
    output: Option<u64>,
    extra_output: Option<u64>,
    cache_creation: Option<u64>,
    cache_read: Option<u64>,
}

impl UsageParts {
    fn has_fields(self) -> bool {
        self.input.is_some()
            || self.output.is_some()
            || self.extra_output.is_some()
            || self.cache_creation.is_some()
            || self.cache_read.is_some()
    }

    fn merge(&mut self, newer: Self) {
        merge_field(&mut self.input, newer.input);
        merge_field(&mut self.output, newer.output);
        merge_field(&mut self.extra_output, newer.extra_output);
        merge_field(&mut self.cache_creation, newer.cache_creation);
        merge_field(&mut self.cache_read, newer.cache_read);
    }

    fn finalize(self, provider: UsageProvider) -> Result<TokenUsage, UsageError> {
        let input = self.input.unwrap_or(0);
        let output = self.output.unwrap_or(0);
        let cache_creation = self.cache_creation.unwrap_or(0);
        let cache_read = self.cache_read.unwrap_or(0);

        match provider {
            UsageProvider::Anthropic => Ok(TokenUsage {
                input_tokens: input,
                output_tokens: output,
                cache_creation_input_tokens: cache_creation,
                cache_read_input_tokens: cache_read,
            }),
            UsageProvider::OpenAi => {
                let cached = cache_creation
                    .checked_add(cache_read)
                    .ok_or_else(|| UsageError::Overflow("cached input tokens".to_owned()))?;
                let input_tokens =
                    input
                        .checked_sub(cached)
                        .ok_or_else(|| UsageError::InvalidField {
                            field: "usage.input_tokens".to_owned(),
                            reason: "is smaller than the cache token categories".to_owned(),
                        })?;
                Ok(TokenUsage {
                    input_tokens,
                    output_tokens: output,
                    cache_creation_input_tokens: cache_creation,
                    cache_read_input_tokens: cache_read,
                })
            }
            UsageProvider::Gemini => {
                let output_tokens = output
                    .checked_add(self.extra_output.unwrap_or(0))
                    .ok_or_else(|| UsageError::Overflow("output_tokens".to_owned()))?;
                let input_tokens =
                    input
                        .checked_sub(cache_read)
                        .ok_or_else(|| UsageError::InvalidField {
                            field: "usageMetadata.promptTokenCount".to_owned(),
                            reason: "is smaller than cachedContentTokenCount".to_owned(),
                        })?;
                Ok(TokenUsage {
                    input_tokens,
                    output_tokens,
                    cache_creation_input_tokens: 0,
                    cache_read_input_tokens: cache_read,
                })
            }
        }
    }
}

fn merge_field(destination: &mut Option<u64>, newer: Option<u64>) {
    if newer.is_some() {
        *destination = newer;
    }
}

fn parse_event(provider: UsageProvider, value: &Value) -> Result<Option<UsageParts>, UsageError> {
    match provider {
        UsageProvider::Anthropic => parse_anthropic(value),
        UsageProvider::OpenAi => parse_openai(value),
        UsageProvider::Gemini => parse_gemini(value),
    }
}

fn parse_anthropic(value: &Value) -> Result<Option<UsageParts>, UsageError> {
    let Some(usage) = first_object(value, &[&["usage"], &["message", "usage"]])? else {
        return Ok(None);
    };
    let parts = UsageParts {
        input: token_field(usage, "input_tokens", "usage.input_tokens")?,
        output: token_field(usage, "output_tokens", "usage.output_tokens")?,
        extra_output: None,
        cache_creation: token_field(
            usage,
            "cache_creation_input_tokens",
            "usage.cache_creation_input_tokens",
        )?,
        cache_read: token_field(
            usage,
            "cache_read_input_tokens",
            "usage.cache_read_input_tokens",
        )?,
    };
    Ok(parts.has_fields().then_some(parts))
}

fn parse_openai(value: &Value) -> Result<Option<UsageParts>, UsageError> {
    let Some(usage) = first_object(value, &[&["usage"], &["response", "usage"]])? else {
        return Ok(None);
    };

    let input = first_token_field(
        usage,
        &[
            ("input_tokens", "usage.input_tokens"),
            ("prompt_tokens", "usage.prompt_tokens"),
        ],
    )?;
    let output = first_token_field(
        usage,
        &[
            ("output_tokens", "usage.output_tokens"),
            ("completion_tokens", "usage.completion_tokens"),
        ],
    )?;
    let cache_read = first_nested_token_field(
        usage,
        &[
            (
                &["input_tokens_details", "cached_tokens"],
                "usage.input_tokens_details.cached_tokens",
            ),
            (
                &["prompt_tokens_details", "cached_tokens"],
                "usage.prompt_tokens_details.cached_tokens",
            ),
            (
                &["cache_read_input_tokens"],
                "usage.cache_read_input_tokens",
            ),
            (&["cache_read_tokens"], "usage.cache_read_tokens"),
            (&["cached_tokens"], "usage.cached_tokens"),
        ],
    )?;
    let cache_creation = first_nested_token_field(
        usage,
        &[
            (
                &["input_tokens_details", "cache_write_tokens"],
                "usage.input_tokens_details.cache_write_tokens",
            ),
            (
                &["prompt_tokens_details", "cache_write_tokens"],
                "usage.prompt_tokens_details.cache_write_tokens",
            ),
            (
                &["input_tokens_details", "cache_creation_tokens"],
                "usage.input_tokens_details.cache_creation_tokens",
            ),
            (
                &["prompt_tokens_details", "cache_creation_tokens"],
                "usage.prompt_tokens_details.cache_creation_tokens",
            ),
            (&["cache_write_tokens"], "usage.cache_write_tokens"),
            (
                &["cache_creation_input_tokens"],
                "usage.cache_creation_input_tokens",
            ),
            (
                &["cache_write_input_tokens"],
                "usage.cache_write_input_tokens",
            ),
            (&["cache_creation_tokens"], "usage.cache_creation_tokens"),
        ],
    )?;
    let parts = UsageParts {
        input,
        output,
        extra_output: None,
        cache_creation,
        cache_read,
    };
    Ok(parts.has_fields().then_some(parts))
}

fn parse_gemini(value: &Value) -> Result<Option<UsageParts>, UsageError> {
    let Some(usage) = first_object(value, &[&["usageMetadata"], &["response", "usageMetadata"]])?
    else {
        return Ok(None);
    };
    let parts = UsageParts {
        input: token_field(usage, "promptTokenCount", "usageMetadata.promptTokenCount")?,
        output: token_field(
            usage,
            "candidatesTokenCount",
            "usageMetadata.candidatesTokenCount",
        )?,
        extra_output: token_field(
            usage,
            "thoughtsTokenCount",
            "usageMetadata.thoughtsTokenCount",
        )?,
        cache_creation: None,
        cache_read: token_field(
            usage,
            "cachedContentTokenCount",
            "usageMetadata.cachedContentTokenCount",
        )?,
    };
    Ok(parts.has_fields().then_some(parts))
}

fn first_object<'a>(
    root: &'a Value,
    paths: &[&[&str]],
) -> Result<Option<&'a Map<String, Value>>, UsageError> {
    for path in paths {
        let Some(value) = value_at(root, path) else {
            continue;
        };
        return value
            .as_object()
            .map(Some)
            .ok_or_else(|| UsageError::InvalidField {
                field: path.join("."),
                reason: "expected an object".to_owned(),
            });
    }
    Ok(None)
}

fn value_at<'a>(root: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter()
        .try_fold(root, |value, segment| value.get(*segment))
}

fn token_field(
    object: &Map<String, Value>,
    field: &str,
    display_path: &str,
) -> Result<Option<u64>, UsageError> {
    let Some(value) = object.get(field) else {
        return Ok(None);
    };
    value
        .as_u64()
        .map(Some)
        .ok_or_else(|| UsageError::InvalidField {
            field: display_path.to_owned(),
            reason: "expected a non-negative integer".to_owned(),
        })
}

fn first_token_field(
    object: &Map<String, Value>,
    fields: &[(&str, &str)],
) -> Result<Option<u64>, UsageError> {
    for (field, display_path) in fields {
        if object.contains_key(*field) {
            return token_field(object, field, display_path);
        }
    }
    Ok(None)
}

fn first_nested_token_field(
    object: &Map<String, Value>,
    fields: &[(&[&str], &str)],
) -> Result<Option<u64>, UsageError> {
    let root = Value::Object(object.clone());
    for (path, display_path) in fields {
        let Some(value) = value_at(&root, path) else {
            continue;
        };
        return value
            .as_u64()
            .map(Some)
            .ok_or_else(|| UsageError::InvalidField {
                field: (*display_path).to_owned(),
                reason: "expected a non-negative integer".to_owned(),
            });
    }
    Ok(None)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UsageError {
    InvalidUtf8(String),
    InvalidJson(String),
    InvalidSseData(String),
    MissingUsage,
    InvalidField { field: String, reason: String },
    Overflow(String),
}

impl fmt::Display for UsageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUtf8(message) => write!(formatter, "usage body is not UTF-8: {message}"),
            Self::InvalidJson(message) => write!(formatter, "invalid usage JSON: {message}"),
            Self::InvalidSseData(message) => write!(formatter, "invalid SSE data JSON: {message}"),
            Self::MissingUsage => formatter.write_str("response contains no recognized usage"),
            Self::InvalidField { field, reason } => {
                write!(formatter, "invalid usage field {field}: {reason}")
            }
            Self::Overflow(field) => write!(formatter, "usage field {field} overflowed"),
        }
    }
}

impl Error for UsageError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anthropic_supports_buffered_and_nested_usage() {
        let usage = parse_json_usage(
            UsageProvider::Anthropic,
            br#"{"message":{"usage":{"input_tokens":10,"output_tokens":2,"cache_creation_input_tokens":3,"cache_read_input_tokens":4}}}"#,
        )
        .unwrap();
        assert_eq!(
            usage,
            TokenUsage {
                input_tokens: 10,
                output_tokens: 2,
                cache_creation_input_tokens: 3,
                cache_read_input_tokens: 4,
            }
        );
    }

    #[test]
    fn sse_merges_latest_present_fields_instead_of_summing() {
        let body = br#"event: message_start
data: {"message":{"usage":{"input_tokens":10,"cache_read_input_tokens":4}}}

data: {"usage":{"output_tokens":2}}

data: {"usage":{"output_tokens":5,"cache_read_input_tokens":0}}

data: [DONE]
"#;
        let usage = parse_sse_usage(UsageProvider::Anthropic, body).unwrap();
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.output_tokens, 5);
        assert_eq!(usage.cache_read_input_tokens, 0);
    }

    #[test]
    fn openai_honors_nested_precedence_and_removes_cached_input() {
        let usage = parse_json_usage(
            UsageProvider::OpenAi,
            br#"{"usage":{"prompt_tokens":20,"completion_tokens":3,"cache_read_input_tokens":99,"prompt_tokens_details":{"cached_tokens":4,"cache_write_tokens":2}}}"#,
        )
        .unwrap();
        assert_eq!(usage.input_tokens, 14);
        assert_eq!(usage.output_tokens, 3);
        assert_eq!(usage.cache_creation_input_tokens, 2);
        assert_eq!(usage.cache_read_input_tokens, 4);
    }

    #[test]
    fn gemini_separates_cache_and_counts_thoughts_as_output() {
        let usage = parse_json_usage(
            UsageProvider::Gemini,
            br#"{"usageMetadata":{"promptTokenCount":100,"cachedContentTokenCount":40,"candidatesTokenCount":7,"thoughtsTokenCount":3}}"#,
        )
        .unwrap();
        assert_eq!(usage.input_tokens, 60);
        assert_eq!(usage.cache_read_input_tokens, 40);
        assert_eq!(usage.output_tokens, 10);
    }

    #[test]
    fn malformed_sse_data_fails_closed() {
        let error = parse_sse_usage(UsageProvider::OpenAi, b"data: {bad}\n").unwrap_err();
        assert!(matches!(error, UsageError::InvalidSseData(_)));
    }
}
