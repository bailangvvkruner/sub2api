//! Fail-closed JSON compatibility bridge for the common generation APIs.

#![allow(clippy::struct_field_names, clippy::too_many_lines)]

use std::{collections::HashMap, error::Error, fmt};

use axum::http::Method;
use serde_json::{Map, Value, json};

use super::{GatewayRoute, Protocol, RequestMetadata, ResponseMode, RouteKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransformStage {
    InvalidRequest,
    Unsupported,
    InvalidResponse,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TransformError {
    stage: TransformStage,
    message: String,
}

impl TransformError {
    fn invalid_request(message: impl Into<String>) -> Self {
        Self {
            stage: TransformStage::InvalidRequest,
            message: message.into(),
        }
    }

    fn unsupported(message: impl Into<String>) -> Self {
        Self {
            stage: TransformStage::Unsupported,
            message: message.into(),
        }
    }

    fn invalid_response(message: impl Into<String>) -> Self {
        Self {
            stage: TransformStage::InvalidResponse,
            message: message.into(),
        }
    }

    pub(crate) const fn stage(&self) -> TransformStage {
        self.stage
    }
}

impl fmt::Display for TransformError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for TransformError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProtocolBridge {
    client_protocol: Protocol,
    upstream_protocol: Protocol,
    client_kind: RouteKind,
    upstream_kind: RouteKind,
    normalize_same_protocol: bool,
}

impl ProtocolBridge {
    #[must_use]
    pub(crate) fn requires_conversion(self) -> bool {
        self.client_protocol != self.upstream_protocol
            || self.client_kind != self.upstream_kind
            || self.normalize_same_protocol
    }

    #[must_use]
    pub(crate) const fn normalize_wrapped_gemini(mut self) -> Self {
        self.normalize_same_protocol = true;
        self
    }

    pub(crate) fn transform_response(self, body: &[u8]) -> Result<Vec<u8>, TransformError> {
        if !self.requires_conversion() {
            return Ok(body.to_vec());
        }
        let value = serde_json::from_slice(body).map_err(|_| {
            TransformError::invalid_response(
                "upstream returned invalid JSON for protocol conversion",
            )
        })?;
        let response = parse_response(self.upstream_kind, &value)?;
        let converted = encode_response(self.client_kind, &response)?;
        serde_json::to_vec(&converted).map_err(|_| {
            TransformError::invalid_response("converted upstream response could not be encoded")
        })
    }

    #[must_use]
    pub(crate) fn stream_bridge(self) -> SseBridge {
        SseBridge::new(self)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SseBridge {
    bridge: ProtocolBridge,
    pending: Vec<u8>,
    source: StreamSourceState,
    encoder: StreamEncoder,
    finished: bool,
}

impl SseBridge {
    fn new(bridge: ProtocolBridge) -> Self {
        Self {
            bridge,
            pending: Vec::new(),
            source: StreamSourceState::default(),
            encoder: StreamEncoder::new(bridge.client_kind),
            finished: false,
        }
    }

    pub(crate) fn push(&mut self, chunk: &[u8]) -> Result<Vec<u8>, TransformError> {
        if !self.bridge.requires_conversion() {
            return Ok(chunk.to_vec());
        }
        if self.finished {
            return Err(TransformError::invalid_response(
                "upstream emitted data after the stream completed",
            ));
        }
        if self.pending.len().saturating_add(chunk.len()) > 2 * 1024 * 1024 {
            return Err(TransformError::invalid_response(
                "upstream SSE event exceeded 2 MiB",
            ));
        }
        self.pending.extend_from_slice(chunk);
        let mut output = Vec::new();
        while let Some((frame_end, delimiter_len)) = next_sse_frame(&self.pending) {
            let frame = self.pending[..frame_end].to_vec();
            self.pending.drain(..frame_end + delimiter_len);
            self.process_frame(&frame, &mut output)?;
        }
        Ok(output)
    }

    pub(crate) fn finish(&mut self) -> Result<Vec<u8>, TransformError> {
        if !self.bridge.requires_conversion() || self.finished {
            return Ok(Vec::new());
        }
        let mut output = Vec::new();
        if !self.pending.iter().all(u8::is_ascii_whitespace) {
            let frame = std::mem::take(&mut self.pending);
            self.process_frame(&frame, &mut output)?;
        }
        if !self.finished {
            self.encoder.encode(
                CanonicalStreamEvent::Stop {
                    reason: CanonicalStopReason::Unknown,
                    usage: self.source.usage,
                },
                &mut output,
            )?;
            self.finished = true;
        }
        Ok(output)
    }

    fn process_frame(&mut self, frame: &[u8], output: &mut Vec<u8>) -> Result<(), TransformError> {
        let parsed = parse_sse_frame(frame)?;
        if parsed.data.is_empty() {
            return Ok(());
        }
        if parsed.data == b"[DONE]" {
            if !self.finished {
                self.encoder.encode(
                    CanonicalStreamEvent::Stop {
                        reason: CanonicalStopReason::EndTurn,
                        usage: self.source.usage,
                    },
                    output,
                )?;
                self.finished = true;
            }
            return Ok(());
        }
        let value: Value = serde_json::from_slice(&parsed.data).map_err(|error| {
            TransformError::invalid_response(format!(
                "upstream SSE event contained invalid JSON: {error}"
            ))
        })?;
        let events = decode_stream_event(
            self.bridge.upstream_kind,
            parsed.event.as_deref(),
            &value,
            &mut self.source,
        )?;
        for event in events {
            self.encoder.encode(event, output)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
struct StreamSourceState {
    started: bool,
    stopped: bool,
    id: String,
    model: String,
    usage: Option<CanonicalUsage>,
    open_tools: HashMap<usize, String>,
}

#[derive(Clone, Debug)]
enum CanonicalStreamEvent {
    Start {
        id: String,
        model: String,
        usage: Option<CanonicalUsage>,
    },
    Text(String),
    Reasoning(String),
    ToolStart {
        index: usize,
        id: String,
        name: String,
    },
    ToolArguments {
        index: usize,
        delta: String,
    },
    ToolEnd {
        index: usize,
    },
    Stop {
        reason: CanonicalStopReason,
        usage: Option<CanonicalUsage>,
    },
}

#[derive(Clone, Debug)]
struct ParsedSseFrame {
    event: Option<String>,
    data: Vec<u8>,
}

fn next_sse_frame(buffer: &[u8]) -> Option<(usize, usize)> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| (index, 4))
        .or_else(|| {
            buffer
                .windows(2)
                .position(|window| window == b"\n\n")
                .map(|index| (index, 2))
        })
}

fn parse_sse_frame(frame: &[u8]) -> Result<ParsedSseFrame, TransformError> {
    let text = std::str::from_utf8(frame)
        .map_err(|_| TransformError::invalid_response("upstream SSE is not UTF-8"))?;
    let mut event = None;
    let mut data = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.starts_with(':') {
            continue;
        }
        if let Some(value) = line.strip_prefix("event:") {
            event = Some(value.trim().to_owned());
        } else if let Some(value) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push(b'\n');
            }
            data.extend_from_slice(value.strip_prefix(' ').unwrap_or(value).as_bytes());
        }
    }
    Ok(ParsedSseFrame { event, data })
}

fn decode_stream_event(
    kind: RouteKind,
    event_name: Option<&str>,
    value: &Value,
    state: &mut StreamSourceState,
) -> Result<Vec<CanonicalStreamEvent>, TransformError> {
    match kind {
        RouteKind::AnthropicMessages => decode_anthropic_stream(value, state),
        RouteKind::OpenAiResponses => decode_openai_responses_stream(event_name, value, state),
        RouteKind::OpenAiChatCompletions => decode_openai_chat_stream(value, state),
        RouteKind::GeminiGenerateContent | RouteKind::GeminiStreamGenerateContent => {
            decode_gemini_stream(value, state)
        }
        _ => Err(TransformError::invalid_response(
            "selected upstream operation has no SSE decoder",
        )),
    }
}

fn decode_anthropic_stream(
    value: &Value,
    state: &mut StreamSourceState,
) -> Result<Vec<CanonicalStreamEvent>, TransformError> {
    let object = response_object(value, "Anthropic SSE event")?;
    let event_type = required_response_string(object, "type")?;
    let mut events = Vec::new();
    match event_type.as_str() {
        "message_start" => {
            let message = response_object(
                object.get("message").ok_or_else(|| {
                    TransformError::invalid_response("Anthropic message_start has no message")
                })?,
                "Anthropic message_start message",
            )?;
            let id = required_response_string(message, "id")?;
            let model = required_response_string(message, "model")?;
            let usage = message
                .get("usage")
                .map(parse_anthropic_stream_usage)
                .transpose()?;
            state.started = true;
            state.id.clone_from(&id);
            state.model.clone_from(&model);
            merge_stream_usage(&mut state.usage, usage);
            events.push(CanonicalStreamEvent::Start { id, model, usage });
        }
        "content_block_start" => {
            ensure_source_start(state, &mut events);
            let index =
                usize::try_from(object.get("index").and_then(Value::as_u64).ok_or_else(|| {
                    TransformError::invalid_response("Anthropic content_block_start has no index")
                })?)
                .map_err(|_| {
                    TransformError::invalid_response("Anthropic block index is too large")
                })?;
            let block = response_object(
                object.get("content_block").ok_or_else(|| {
                    TransformError::invalid_response(
                        "Anthropic content_block_start has no content_block",
                    )
                })?,
                "Anthropic content block",
            )?;
            match required_response_string(block, "type")?.as_str() {
                "text" => {
                    if let Some(text) = block.get("text").and_then(Value::as_str)
                        && !text.is_empty()
                    {
                        events.push(CanonicalStreamEvent::Text(text.to_owned()));
                    }
                }
                "thinking" => {
                    if let Some(thinking) = block.get("thinking").and_then(Value::as_str)
                        && !thinking.is_empty()
                    {
                        events.push(CanonicalStreamEvent::Reasoning(thinking.to_owned()));
                    }
                }
                "tool_use" => {
                    let id = required_response_string(block, "id")?;
                    let name = required_response_string(block, "name")?;
                    state.open_tools.insert(index, id.clone());
                    events.push(CanonicalStreamEvent::ToolStart { index, id, name });
                }
                "redacted_thinking" => {}
                other => {
                    return Err(TransformError::invalid_response(format!(
                        "unsupported Anthropic streaming block {other:?}"
                    )));
                }
            }
        }
        "content_block_delta" => {
            ensure_source_start(state, &mut events);
            let index = usize::try_from(object.get("index").and_then(Value::as_u64).unwrap_or(0))
                .map_err(|_| {
                TransformError::invalid_response("Anthropic block index is too large")
            })?;
            let delta = response_object(
                object.get("delta").ok_or_else(|| {
                    TransformError::invalid_response("Anthropic content delta is missing")
                })?,
                "Anthropic content delta",
            )?;
            match required_response_string(delta, "type")?.as_str() {
                "text_delta" => events.push(CanonicalStreamEvent::Text(required_response_string(
                    delta, "text",
                )?)),
                "thinking_delta" => events.push(CanonicalStreamEvent::Reasoning(
                    required_response_string(delta, "thinking")?,
                )),
                "input_json_delta" => events.push(CanonicalStreamEvent::ToolArguments {
                    index,
                    delta: required_response_string(delta, "partial_json")?,
                }),
                "signature_delta" => {}
                other => {
                    return Err(TransformError::invalid_response(format!(
                        "unsupported Anthropic streaming delta {other:?}"
                    )));
                }
            }
        }
        "content_block_stop" => {
            let index = usize::try_from(object.get("index").and_then(Value::as_u64).unwrap_or(0))
                .map_err(|_| {
                TransformError::invalid_response("Anthropic block index is too large")
            })?;
            if state.open_tools.remove(&index).is_some() {
                events.push(CanonicalStreamEvent::ToolEnd { index });
            }
        }
        "message_delta" => {
            let usage = object
                .get("usage")
                .map(parse_anthropic_stream_usage)
                .transpose()?;
            merge_stream_usage(&mut state.usage, usage);
            let reason = object
                .get("delta")
                .and_then(Value::as_object)
                .and_then(|delta| delta.get("stop_reason"))
                .and_then(Value::as_str)
                .map_or(CanonicalStopReason::EndTurn, anthropic_stream_stop_reason);
            if !state.stopped {
                state.stopped = true;
                events.push(CanonicalStreamEvent::Stop {
                    reason,
                    usage: state.usage,
                });
            }
        }
        "message_stop" => {
            if !state.stopped {
                state.stopped = true;
                events.push(CanonicalStreamEvent::Stop {
                    reason: CanonicalStopReason::EndTurn,
                    usage: state.usage,
                });
            }
        }
        "ping" => {}
        "error" => {
            return Err(TransformError::invalid_response(
                "Anthropic upstream emitted an SSE error",
            ));
        }
        other => {
            return Err(TransformError::invalid_response(format!(
                "unsupported Anthropic SSE event {other:?}"
            )));
        }
    }
    Ok(events)
}

fn decode_openai_chat_stream(
    value: &Value,
    state: &mut StreamSourceState,
) -> Result<Vec<CanonicalStreamEvent>, TransformError> {
    let object = response_object(value, "OpenAI Chat SSE event")?;
    let mut events = Vec::new();
    if !state.started {
        let id = optional_response_string(object.get("id"), "id")?
            .unwrap_or_else(|| "chatcmpl_gateway".to_owned());
        let model = optional_response_string(object.get("model"), "model")?
            .unwrap_or_else(|| "unknown".to_owned());
        state.started = true;
        state.id.clone_from(&id);
        state.model.clone_from(&model);
        events.push(CanonicalStreamEvent::Start {
            id,
            model,
            usage: None,
        });
    }
    if let Some(usage) = object.get("usage") {
        let usage = parse_openai_usage(usage)?;
        merge_stream_usage(&mut state.usage, Some(usage));
    }
    let Some(choice) = object
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
    else {
        return Ok(events);
    };
    let choice = response_object(choice, "OpenAI Chat streaming choice")?;
    if let Some(delta) = choice.get("delta").and_then(Value::as_object) {
        if let Some(text) = delta.get("content").and_then(Value::as_str)
            && !text.is_empty()
        {
            events.push(CanonicalStreamEvent::Text(text.to_owned()));
        }
        if let Some(reasoning) = delta
            .get("reasoning_content")
            .or_else(|| delta.get("reasoning"))
            .and_then(Value::as_str)
            && !reasoning.is_empty()
        {
            events.push(CanonicalStreamEvent::Reasoning(reasoning.to_owned()));
        }
        if let Some(tool_calls) = delta.get("tool_calls").and_then(Value::as_array) {
            for tool_call in tool_calls {
                let tool_call = response_object(tool_call, "OpenAI streaming tool call")?;
                let index =
                    usize::try_from(tool_call.get("index").and_then(Value::as_u64).unwrap_or(0))
                        .map_err(|_| {
                            TransformError::invalid_response("OpenAI tool index is too large")
                        })?;
                let function = tool_call.get("function").and_then(Value::as_object);
                if let Some(name) = function
                    .and_then(|function| function.get("name"))
                    .and_then(Value::as_str)
                {
                    let id = tool_call
                        .get("id")
                        .and_then(Value::as_str)
                        .unwrap_or("call_gateway")
                        .to_owned();
                    state.open_tools.insert(index, id.clone());
                    events.push(CanonicalStreamEvent::ToolStart {
                        index,
                        id,
                        name: name.to_owned(),
                    });
                }
                if let Some(arguments) = function
                    .and_then(|function| function.get("arguments"))
                    .and_then(Value::as_str)
                    && !arguments.is_empty()
                {
                    events.push(CanonicalStreamEvent::ToolArguments {
                        index,
                        delta: arguments.to_owned(),
                    });
                }
            }
        }
    }
    if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str)
        && !state.stopped
    {
        for index in std::mem::take(&mut state.open_tools).into_keys() {
            events.push(CanonicalStreamEvent::ToolEnd { index });
        }
        state.stopped = true;
        events.push(CanonicalStreamEvent::Stop {
            reason: openai_stream_stop_reason(reason),
            usage: state.usage,
        });
    }
    Ok(events)
}

fn decode_openai_responses_stream(
    event_name: Option<&str>,
    value: &Value,
    state: &mut StreamSourceState,
) -> Result<Vec<CanonicalStreamEvent>, TransformError> {
    let object = response_object(value, "OpenAI Responses SSE event")?;
    let event_type = object
        .get("type")
        .and_then(Value::as_str)
        .or(event_name)
        .unwrap_or_default();
    let mut events = Vec::new();
    if event_type.starts_with("response.") && !state.started {
        let response = object.get("response").and_then(Value::as_object);
        let id = response
            .and_then(|response| response.get("id"))
            .or_else(|| object.get("response_id"))
            .and_then(Value::as_str)
            .unwrap_or("resp_gateway")
            .to_owned();
        let model = response
            .and_then(|response| response.get("model"))
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned();
        state.started = true;
        state.id.clone_from(&id);
        state.model.clone_from(&model);
        events.push(CanonicalStreamEvent::Start {
            id,
            model,
            usage: None,
        });
    }
    match event_type {
        "response.output_text.delta" => {
            events.push(CanonicalStreamEvent::Text(required_response_string(
                object, "delta",
            )?));
        }
        "response.reasoning_summary_text.delta" | "response.reasoning_text.delta" => {
            events.push(CanonicalStreamEvent::Reasoning(required_response_string(
                object, "delta",
            )?));
        }
        "response.output_item.added" => {
            if let Some(item) = object.get("item").and_then(Value::as_object)
                && item.get("type").and_then(Value::as_str) == Some("function_call")
            {
                let index = usize::try_from(
                    object
                        .get("output_index")
                        .and_then(Value::as_u64)
                        .unwrap_or(0),
                )
                .map_err(|_| {
                    TransformError::invalid_response("OpenAI output index is too large")
                })?;
                let id = item
                    .get("call_id")
                    .or_else(|| item.get("id"))
                    .and_then(Value::as_str)
                    .unwrap_or("call_gateway")
                    .to_owned();
                let name = item
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("tool")
                    .to_owned();
                state.open_tools.insert(index, id.clone());
                events.push(CanonicalStreamEvent::ToolStart { index, id, name });
            }
        }
        "response.function_call_arguments.delta" => {
            let index = usize::try_from(
                object
                    .get("output_index")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            )
            .map_err(|_| TransformError::invalid_response("OpenAI output index is too large"))?;
            events.push(CanonicalStreamEvent::ToolArguments {
                index,
                delta: required_response_string(object, "delta")?,
            });
        }
        "response.output_item.done" => {
            let index = usize::try_from(
                object
                    .get("output_index")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            )
            .map_err(|_| TransformError::invalid_response("OpenAI output index is too large"))?;
            if state.open_tools.remove(&index).is_some() {
                events.push(CanonicalStreamEvent::ToolEnd { index });
            }
        }
        "response.completed" | "response.incomplete" => {
            let response = object.get("response").and_then(Value::as_object);
            let usage = response
                .and_then(|response| response.get("usage"))
                .map(parse_openai_usage)
                .transpose()?;
            merge_stream_usage(&mut state.usage, usage);
            if !state.stopped {
                state.stopped = true;
                events.push(CanonicalStreamEvent::Stop {
                    reason: if event_type == "response.incomplete" {
                        CanonicalStopReason::MaxTokens
                    } else {
                        CanonicalStopReason::EndTurn
                    },
                    usage: state.usage,
                });
            }
        }
        "response.failed" | "error" => {
            return Err(TransformError::invalid_response(
                "OpenAI upstream emitted an SSE error",
            ));
        }
        _ => {}
    }
    Ok(events)
}

fn decode_gemini_stream(
    value: &Value,
    state: &mut StreamSourceState,
) -> Result<Vec<CanonicalStreamEvent>, TransformError> {
    let value = value.get("response").unwrap_or(value);
    let object = response_object(value, "Gemini SSE event")?;
    let mut events = Vec::new();
    if !state.started {
        let id = optional_response_string(object.get("responseId"), "responseId")?
            .unwrap_or_else(|| "gemini_gateway".to_owned());
        let model = optional_response_string(object.get("modelVersion"), "modelVersion")?
            .unwrap_or_else(|| "unknown".to_owned());
        state.started = true;
        state.id.clone_from(&id);
        state.model.clone_from(&model);
        events.push(CanonicalStreamEvent::Start {
            id,
            model,
            usage: None,
        });
    }
    if let Some(usage) = object.get("usageMetadata") {
        let usage = parse_gemini_stream_usage(usage)?;
        merge_stream_usage(&mut state.usage, Some(usage));
    }
    if let Some(candidate) = object
        .get("candidates")
        .and_then(Value::as_array)
        .and_then(|candidates| candidates.first())
        .and_then(Value::as_object)
    {
        if let Some(parts) = candidate
            .get("content")
            .and_then(Value::as_object)
            .and_then(|content| content.get("parts"))
            .and_then(Value::as_array)
        {
            for (index, part) in parts.iter().enumerate() {
                let part = response_object(part, "Gemini streaming part")?;
                if let Some(text) = part.get("text").and_then(Value::as_str) {
                    if part.get("thought").and_then(Value::as_bool) == Some(true) {
                        events.push(CanonicalStreamEvent::Reasoning(text.to_owned()));
                    } else {
                        events.push(CanonicalStreamEvent::Text(text.to_owned()));
                    }
                } else if let Some(call) = part.get("functionCall").and_then(Value::as_object) {
                    let id = call
                        .get("id")
                        .and_then(Value::as_str)
                        .map_or_else(|| format!("call_gemini_{index}"), ToOwned::to_owned);
                    let name = call
                        .get("name")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            TransformError::invalid_response(
                                "Gemini streaming function call has no name",
                            )
                        })?
                        .to_owned();
                    events.push(CanonicalStreamEvent::ToolStart { index, id, name });
                    let arguments = call
                        .get("args")
                        .cloned()
                        .unwrap_or_else(|| Value::Object(Map::new()));
                    events.push(CanonicalStreamEvent::ToolArguments {
                        index,
                        delta: serde_json::to_string(&arguments).map_err(|_| {
                            TransformError::invalid_response(
                                "Gemini streaming tool arguments could not be encoded",
                            )
                        })?,
                    });
                    events.push(CanonicalStreamEvent::ToolEnd { index });
                }
            }
        }
        if let Some(reason) = candidate.get("finishReason").and_then(Value::as_str)
            && !state.stopped
        {
            state.stopped = true;
            events.push(CanonicalStreamEvent::Stop {
                reason: gemini_stream_stop_reason(reason),
                usage: state.usage,
            });
        }
    }
    Ok(events)
}

fn ensure_source_start(state: &mut StreamSourceState, events: &mut Vec<CanonicalStreamEvent>) {
    if state.started {
        return;
    }
    state.started = true;
    "stream_gateway".clone_into(&mut state.id);
    "unknown".clone_into(&mut state.model);
    events.push(CanonicalStreamEvent::Start {
        id: state.id.clone(),
        model: state.model.clone(),
        usage: state.usage,
    });
}

fn parse_anthropic_stream_usage(value: &Value) -> Result<CanonicalUsage, TransformError> {
    let usage = response_object(value, "Anthropic streaming usage")?;
    let input_tokens = response_u64(usage.get("input_tokens"), "input_tokens")?;
    let output_tokens = response_u64(usage.get("output_tokens"), "output_tokens")?;
    let cached_input_tokens = response_u64(
        usage.get("cache_read_input_tokens"),
        "cache_read_input_tokens",
    )?;
    let cache_creation_input_tokens = response_u64(
        usage.get("cache_creation_input_tokens"),
        "cache_creation_input_tokens",
    )?;
    Ok(CanonicalUsage {
        input_tokens: input_tokens
            .saturating_add(cached_input_tokens)
            .saturating_add(cache_creation_input_tokens),
        output_tokens,
        total_tokens: input_tokens
            .saturating_add(output_tokens)
            .saturating_add(cached_input_tokens)
            .saturating_add(cache_creation_input_tokens),
        cached_input_tokens,
        cache_creation_input_tokens,
    })
}

fn parse_gemini_stream_usage(value: &Value) -> Result<CanonicalUsage, TransformError> {
    let usage = response_object(value, "Gemini streaming usage")?;
    let input_tokens = response_u64(usage.get("promptTokenCount"), "promptTokenCount")?;
    let output_tokens =
        response_u64(usage.get("candidatesTokenCount"), "candidatesTokenCount")?.saturating_add(
            response_u64(usage.get("thoughtsTokenCount"), "thoughtsTokenCount")?,
        );
    let total_tokens = response_u64(usage.get("totalTokenCount"), "totalTokenCount")?;
    let cached_input_tokens = response_u64(
        usage.get("cachedContentTokenCount"),
        "cachedContentTokenCount",
    )?;
    Ok(CanonicalUsage {
        input_tokens,
        output_tokens,
        total_tokens,
        cached_input_tokens,
        cache_creation_input_tokens: 0,
    })
}

fn merge_stream_usage(current: &mut Option<CanonicalUsage>, newer: Option<CanonicalUsage>) {
    let Some(newer) = newer else { return };
    let merged = current.map_or(newer, |current| CanonicalUsage {
        input_tokens: newer.input_tokens.max(current.input_tokens),
        output_tokens: newer.output_tokens.max(current.output_tokens),
        total_tokens: newer.total_tokens.max(current.total_tokens),
        cached_input_tokens: newer.cached_input_tokens.max(current.cached_input_tokens),
        cache_creation_input_tokens: newer
            .cache_creation_input_tokens
            .max(current.cache_creation_input_tokens),
    });
    *current = Some(merged);
}

fn anthropic_stream_stop_reason(reason: &str) -> CanonicalStopReason {
    match reason {
        "max_tokens" => CanonicalStopReason::MaxTokens,
        "tool_use" => CanonicalStopReason::ToolUse,
        "stop_sequence" => CanonicalStopReason::StopSequence,
        "refusal" => CanonicalStopReason::ContentFilter,
        "end_turn" => CanonicalStopReason::EndTurn,
        _ => CanonicalStopReason::Unknown,
    }
}

fn openai_stream_stop_reason(reason: &str) -> CanonicalStopReason {
    match reason {
        "length" => CanonicalStopReason::MaxTokens,
        "tool_calls" | "function_call" => CanonicalStopReason::ToolUse,
        "content_filter" => CanonicalStopReason::ContentFilter,
        "stop" => CanonicalStopReason::EndTurn,
        _ => CanonicalStopReason::Unknown,
    }
}

fn gemini_stream_stop_reason(reason: &str) -> CanonicalStopReason {
    match reason {
        "MAX_TOKENS" => CanonicalStopReason::MaxTokens,
        "SAFETY" | "BLOCKLIST" | "PROHIBITED_CONTENT" => CanonicalStopReason::ContentFilter,
        "STOP" => CanonicalStopReason::EndTurn,
        _ => CanonicalStopReason::Unknown,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActiveAnthropicBlock {
    Text(usize),
    Reasoning(usize),
    Tool { source: usize, output: usize },
}

#[derive(Clone, Debug, Default)]
struct StreamToolState {
    output_index: usize,
    id: String,
    name: String,
    arguments: String,
    done: bool,
}

#[derive(Clone, Debug)]
struct StreamEncoder {
    kind: RouteKind,
    id: String,
    model: String,
    started: bool,
    stopped: bool,
    usage: Option<CanonicalUsage>,
    next_output_index: usize,
    active_anthropic: Option<ActiveAnthropicBlock>,
    response_text_index: Option<usize>,
    response_reasoning_index: Option<usize>,
    response_text: String,
    response_reasoning: String,
    tools: HashMap<usize, StreamToolState>,
}

impl StreamEncoder {
    fn new(kind: RouteKind) -> Self {
        Self {
            kind,
            id: String::new(),
            model: String::new(),
            started: false,
            stopped: false,
            usage: None,
            next_output_index: 0,
            active_anthropic: None,
            response_text_index: None,
            response_reasoning_index: None,
            response_text: String::new(),
            response_reasoning: String::new(),
            tools: HashMap::new(),
        }
    }

    fn encode(
        &mut self,
        event: CanonicalStreamEvent,
        output: &mut Vec<u8>,
    ) -> Result<(), TransformError> {
        match event {
            CanonicalStreamEvent::Start { id, model, usage } => {
                merge_stream_usage(&mut self.usage, usage);
                self.start(&id, &model, output)
            }
            CanonicalStreamEvent::Text(text) => {
                self.ensure_started(output)?;
                self.text(&text, output)
            }
            CanonicalStreamEvent::Reasoning(text) => {
                self.ensure_started(output)?;
                self.reasoning(&text, output)
            }
            CanonicalStreamEvent::ToolStart { index, id, name } => {
                self.ensure_started(output)?;
                self.tool_start(index, &id, &name, output)
            }
            CanonicalStreamEvent::ToolArguments { index, delta } => {
                self.ensure_started(output)?;
                self.tool_arguments(index, &delta, output)
            }
            CanonicalStreamEvent::ToolEnd { index } => self.tool_end(index, output),
            CanonicalStreamEvent::Stop { reason, usage } => {
                merge_stream_usage(&mut self.usage, usage);
                self.ensure_started(output)?;
                self.stop(reason, output)
            }
        }
    }

    fn ensure_started(&mut self, output: &mut Vec<u8>) -> Result<(), TransformError> {
        if self.started {
            return Ok(());
        }
        self.start("stream_gateway", "unknown", output)
    }

    fn start(&mut self, id: &str, model: &str, output: &mut Vec<u8>) -> Result<(), TransformError> {
        if self.started {
            if self.id == id || id.is_empty() {
                return Ok(());
            }
            return Err(TransformError::invalid_response(
                "upstream stream changed response ID",
            ));
        }
        self.started = true;
        id.clone_into(&mut self.id);
        model.clone_into(&mut self.model);
        match self.kind {
            RouteKind::AnthropicMessages => {
                let usage = self.usage.unwrap_or_default();
                append_named_json(
                    output,
                    "message_start",
                    &json!({
                        "type": "message_start",
                        "message": {
                            "id": self.id,
                            "type": "message",
                            "role": "assistant",
                            "model": self.model,
                            "content": [],
                            "stop_reason": null,
                            "stop_sequence": null,
                            "usage": anthropic_usage_json(usage),
                        }
                    }),
                )?;
            }
            RouteKind::OpenAiChatCompletions => {
                append_data_json(
                    output,
                    &json!({
                        "id": self.id,
                        "object": "chat.completion.chunk",
                        "created": 0,
                        "model": self.model,
                        "choices": [{"index": 0, "delta": {"role": "assistant", "content": ""}, "finish_reason": null}],
                    }),
                )?;
            }
            RouteKind::OpenAiResponses => {
                append_named_json(
                    output,
                    "response.created",
                    &json!({
                        "type": "response.created",
                        "sequence_number": 0,
                        "response": response_stream_object(&self.id, &self.model, "in_progress", None),
                    }),
                )?;
            }
            RouteKind::GeminiGenerateContent | RouteKind::GeminiStreamGenerateContent => {}
            _ => {
                return Err(TransformError::invalid_response(
                    "client operation has no SSE encoder",
                ));
            }
        }
        Ok(())
    }

    fn text(&mut self, text: &str, output: &mut Vec<u8>) -> Result<(), TransformError> {
        if text.is_empty() {
            return Ok(());
        }
        match self.kind {
            RouteKind::AnthropicMessages => {
                let index = self.ensure_anthropic_block(AnthropicBlockKind::Text, output)?;
                append_named_json(
                    output,
                    "content_block_delta",
                    &json!({
                        "type": "content_block_delta",
                        "index": index,
                        "delta": {"type": "text_delta", "text": text},
                    }),
                )
            }
            RouteKind::OpenAiChatCompletions => append_data_json(
                output,
                &json!({
                    "id": self.id,
                    "object": "chat.completion.chunk",
                    "created": 0,
                    "model": self.model,
                    "choices": [{"index": 0, "delta": {"content": text}, "finish_reason": null}],
                }),
            ),
            RouteKind::OpenAiResponses => {
                let index = self.ensure_response_text(output)?;
                self.response_text.push_str(text);
                append_named_json(
                    output,
                    "response.output_text.delta",
                    &json!({
                        "type": "response.output_text.delta",
                        "sequence_number": 0,
                        "item_id": format!("msg_{}", response_id_suffix(&self.id)),
                        "output_index": index,
                        "content_index": 0,
                        "delta": text,
                    }),
                )
            }
            RouteKind::GeminiGenerateContent | RouteKind::GeminiStreamGenerateContent => {
                append_data_json(
                    output,
                    &json!({
                        "responseId": self.id,
                        "modelVersion": self.model,
                        "candidates": [{
                            "index": 0,
                            "content": {"role": "model", "parts": [{"text": text}]},
                        }],
                    }),
                )
            }
            _ => Err(TransformError::invalid_response(
                "client operation has no SSE text encoder",
            )),
        }
    }

    fn reasoning(&mut self, text: &str, output: &mut Vec<u8>) -> Result<(), TransformError> {
        if text.is_empty() {
            return Ok(());
        }
        match self.kind {
            RouteKind::AnthropicMessages => {
                let index = self.ensure_anthropic_block(AnthropicBlockKind::Reasoning, output)?;
                append_named_json(
                    output,
                    "content_block_delta",
                    &json!({
                        "type": "content_block_delta",
                        "index": index,
                        "delta": {"type": "thinking_delta", "thinking": text},
                    }),
                )
            }
            RouteKind::OpenAiChatCompletions => append_data_json(
                output,
                &json!({
                    "id": self.id,
                    "object": "chat.completion.chunk",
                    "created": 0,
                    "model": self.model,
                    "choices": [{"index": 0, "delta": {"reasoning_content": text}, "finish_reason": null}],
                }),
            ),
            RouteKind::OpenAiResponses => {
                let index = self.ensure_response_reasoning(output)?;
                self.response_reasoning.push_str(text);
                append_named_json(
                    output,
                    "response.reasoning_summary_text.delta",
                    &json!({
                        "type": "response.reasoning_summary_text.delta",
                        "sequence_number": 0,
                        "item_id": format!("rs_{}", response_id_suffix(&self.id)),
                        "output_index": index,
                        "summary_index": 0,
                        "delta": text,
                    }),
                )
            }
            RouteKind::GeminiGenerateContent | RouteKind::GeminiStreamGenerateContent => {
                append_data_json(
                    output,
                    &json!({
                        "responseId": self.id,
                        "modelVersion": self.model,
                        "candidates": [{
                            "index": 0,
                            "content": {"role": "model", "parts": [{"text": text, "thought": true}]},
                        }],
                    }),
                )
            }
            _ => Err(TransformError::invalid_response(
                "client operation has no SSE reasoning encoder",
            )),
        }
    }

    fn tool_start(
        &mut self,
        source_index: usize,
        id: &str,
        name: &str,
        output: &mut Vec<u8>,
    ) -> Result<(), TransformError> {
        if self.tools.contains_key(&source_index) {
            return Ok(());
        }
        match self.kind {
            RouteKind::AnthropicMessages => {
                self.close_anthropic_block(output)?;
                let output_index = self.allocate_output_index();
                self.active_anthropic = Some(ActiveAnthropicBlock::Tool {
                    source: source_index,
                    output: output_index,
                });
                append_named_json(
                    output,
                    "content_block_start",
                    &json!({
                        "type": "content_block_start",
                        "index": output_index,
                        "content_block": {"type": "tool_use", "id": id, "name": name, "input": {}},
                    }),
                )?;
                self.tools.insert(
                    source_index,
                    StreamToolState {
                        output_index,
                        id: id.to_owned(),
                        name: name.to_owned(),
                        ..StreamToolState::default()
                    },
                );
            }
            RouteKind::OpenAiChatCompletions => {
                let output_index = self.tools.len();
                append_data_json(
                    output,
                    &json!({
                        "id": self.id,
                        "object": "chat.completion.chunk",
                        "created": 0,
                        "model": self.model,
                        "choices": [{"index": 0, "delta": {"tool_calls": [{
                            "index": output_index,
                            "id": id,
                            "type": "function",
                            "function": {"name": name, "arguments": ""},
                        }]}, "finish_reason": null}],
                    }),
                )?;
                self.tools.insert(
                    source_index,
                    StreamToolState {
                        output_index,
                        id: id.to_owned(),
                        name: name.to_owned(),
                        ..StreamToolState::default()
                    },
                );
            }
            RouteKind::OpenAiResponses => {
                let output_index = self.allocate_output_index();
                append_named_json(
                    output,
                    "response.output_item.added",
                    &json!({
                        "type": "response.output_item.added",
                        "sequence_number": 0,
                        "output_index": output_index,
                        "item": {
                            "id": format!("fc_{}", response_id_suffix(id)),
                            "type": "function_call",
                            "status": "in_progress",
                            "call_id": id,
                            "name": name,
                            "arguments": "",
                        },
                    }),
                )?;
                self.tools.insert(
                    source_index,
                    StreamToolState {
                        output_index,
                        id: id.to_owned(),
                        name: name.to_owned(),
                        ..StreamToolState::default()
                    },
                );
            }
            RouteKind::GeminiGenerateContent | RouteKind::GeminiStreamGenerateContent => {
                self.tools.insert(
                    source_index,
                    StreamToolState {
                        output_index: source_index,
                        id: id.to_owned(),
                        name: name.to_owned(),
                        ..StreamToolState::default()
                    },
                );
            }
            _ => {
                return Err(TransformError::invalid_response(
                    "client operation has no SSE tool encoder",
                ));
            }
        }
        Ok(())
    }

    fn tool_arguments(
        &mut self,
        source_index: usize,
        delta: &str,
        output: &mut Vec<u8>,
    ) -> Result<(), TransformError> {
        let Some(tool) = self.tools.get_mut(&source_index) else {
            return Err(TransformError::invalid_response(
                "upstream emitted tool arguments before a tool start",
            ));
        };
        tool.arguments.push_str(delta);
        match self.kind {
            RouteKind::AnthropicMessages => append_named_json(
                output,
                "content_block_delta",
                &json!({
                    "type": "content_block_delta",
                    "index": tool.output_index,
                    "delta": {"type": "input_json_delta", "partial_json": delta},
                }),
            ),
            RouteKind::OpenAiChatCompletions => append_data_json(
                output,
                &json!({
                    "id": self.id,
                    "object": "chat.completion.chunk",
                    "created": 0,
                    "model": self.model,
                    "choices": [{"index": 0, "delta": {"tool_calls": [{
                        "index": tool.output_index,
                        "function": {"arguments": delta},
                    }]}, "finish_reason": null}],
                }),
            ),
            RouteKind::OpenAiResponses => append_named_json(
                output,
                "response.function_call_arguments.delta",
                &json!({
                    "type": "response.function_call_arguments.delta",
                    "sequence_number": 0,
                    "item_id": format!("fc_{}", response_id_suffix(&tool.id)),
                    "output_index": tool.output_index,
                    "delta": delta,
                }),
            ),
            RouteKind::GeminiGenerateContent | RouteKind::GeminiStreamGenerateContent => Ok(()),
            _ => Err(TransformError::invalid_response(
                "client operation has no SSE tool argument encoder",
            )),
        }
    }

    fn tool_end(
        &mut self,
        source_index: usize,
        output: &mut Vec<u8>,
    ) -> Result<(), TransformError> {
        let tool = {
            let Some(tool) = self.tools.get_mut(&source_index) else {
                return Ok(());
            };
            if tool.done {
                return Ok(());
            }
            tool.done = true;
            tool.clone()
        };
        match self.kind {
            RouteKind::AnthropicMessages => {
                if matches!(
                    self.active_anthropic,
                    Some(ActiveAnthropicBlock::Tool { source, .. }) if source == source_index
                ) {
                    self.close_anthropic_block(output)?;
                }
                Ok(())
            }
            RouteKind::OpenAiChatCompletions => Ok(()),
            RouteKind::OpenAiResponses => append_named_json(
                output,
                "response.output_item.done",
                &json!({
                    "type": "response.output_item.done",
                    "sequence_number": 0,
                    "output_index": tool.output_index,
                    "item": {
                        "id": format!("fc_{}", response_id_suffix(&tool.id)),
                        "type": "function_call",
                        "status": "completed",
                        "call_id": tool.id,
                        "name": tool.name,
                        "arguments": tool.arguments,
                    },
                }),
            ),
            RouteKind::GeminiGenerateContent | RouteKind::GeminiStreamGenerateContent => {
                let arguments: Value = serde_json::from_str(&tool.arguments).map_err(|_| {
                    TransformError::invalid_response(
                        "streamed tool arguments did not form a JSON value",
                    )
                })?;
                append_data_json(
                    output,
                    &json!({
                        "responseId": self.id,
                        "modelVersion": self.model,
                        "candidates": [{
                            "index": 0,
                            "content": {"role": "model", "parts": [{
                                "functionCall": {"id": tool.id, "name": tool.name, "args": arguments},
                            }]},
                        }],
                    }),
                )
            }
            _ => Err(TransformError::invalid_response(
                "client operation has no SSE tool completion encoder",
            )),
        }
    }

    fn stop(
        &mut self,
        reason: CanonicalStopReason,
        output: &mut Vec<u8>,
    ) -> Result<(), TransformError> {
        if self.stopped {
            return Ok(());
        }
        let open_tools = self
            .tools
            .iter()
            .filter_map(|(index, tool)| (!tool.done).then_some(*index))
            .collect::<Vec<_>>();
        for index in open_tools {
            self.tool_end(index, output)?;
        }
        self.stopped = true;
        let usage = self.usage.unwrap_or_default();
        match self.kind {
            RouteKind::AnthropicMessages => {
                self.close_anthropic_block(output)?;
                append_named_json(
                    output,
                    "message_delta",
                    &json!({
                        "type": "message_delta",
                        "delta": {"stop_reason": anthropic_stop_reason(reason), "stop_sequence": null},
                        "usage": {"output_tokens": usage.output_tokens},
                    }),
                )?;
                append_named_json(output, "message_stop", &json!({"type": "message_stop"}))
            }
            RouteKind::OpenAiChatCompletions => {
                append_data_json(
                    output,
                    &json!({
                        "id": self.id,
                        "object": "chat.completion.chunk",
                        "created": 0,
                        "model": self.model,
                        "choices": [{"index": 0, "delta": {}, "finish_reason": openai_finish_reason(reason)}],
                        "usage": openai_chat_usage_json(usage),
                    }),
                )?;
                output.extend_from_slice(b"data: [DONE]\n\n");
                Ok(())
            }
            RouteKind::OpenAiResponses => {
                self.finish_response_items(output)?;
                append_named_json(
                    output,
                    "response.completed",
                    &json!({
                        "type": "response.completed",
                        "sequence_number": 0,
                        "response": response_stream_object(&self.id, &self.model, "completed", Some(usage)),
                    }),
                )
            }
            RouteKind::GeminiGenerateContent | RouteKind::GeminiStreamGenerateContent => {
                append_data_json(
                    output,
                    &json!({
                        "responseId": self.id,
                        "modelVersion": self.model,
                        "candidates": [{"index": 0, "finishReason": gemini_finish_reason(reason)}],
                        "usageMetadata": gemini_usage_json(usage),
                    }),
                )
            }
            _ => Err(TransformError::invalid_response(
                "client operation has no SSE completion encoder",
            )),
        }
    }

    fn allocate_output_index(&mut self) -> usize {
        let index = self.next_output_index;
        self.next_output_index = self.next_output_index.saturating_add(1);
        index
    }

    fn ensure_anthropic_block(
        &mut self,
        kind: AnthropicBlockKind,
        output: &mut Vec<u8>,
    ) -> Result<usize, TransformError> {
        let existing = match (kind, self.active_anthropic) {
            (AnthropicBlockKind::Text, Some(ActiveAnthropicBlock::Text(index)))
            | (AnthropicBlockKind::Reasoning, Some(ActiveAnthropicBlock::Reasoning(index))) => {
                Some(index)
            }
            _ => None,
        };
        if let Some(index) = existing {
            return Ok(index);
        }
        self.close_anthropic_block(output)?;
        let index = self.allocate_output_index();
        let content_block = match kind {
            AnthropicBlockKind::Text => json!({"type": "text", "text": ""}),
            AnthropicBlockKind::Reasoning => {
                json!({"type": "thinking", "thinking": "", "signature": ""})
            }
        };
        self.active_anthropic = Some(match kind {
            AnthropicBlockKind::Text => ActiveAnthropicBlock::Text(index),
            AnthropicBlockKind::Reasoning => ActiveAnthropicBlock::Reasoning(index),
        });
        append_named_json(
            output,
            "content_block_start",
            &json!({
                "type": "content_block_start",
                "index": index,
                "content_block": content_block,
            }),
        )?;
        Ok(index)
    }

    fn close_anthropic_block(&mut self, output: &mut Vec<u8>) -> Result<(), TransformError> {
        let Some(block) = self.active_anthropic.take() else {
            return Ok(());
        };
        let index = match block {
            ActiveAnthropicBlock::Text(index) | ActiveAnthropicBlock::Reasoning(index) => index,
            ActiveAnthropicBlock::Tool { output, .. } => output,
        };
        append_named_json(
            output,
            "content_block_stop",
            &json!({"type": "content_block_stop", "index": index}),
        )
    }

    fn ensure_response_text(&mut self, output: &mut Vec<u8>) -> Result<usize, TransformError> {
        if let Some(index) = self.response_text_index {
            return Ok(index);
        }
        let index = self.allocate_output_index();
        self.response_text_index = Some(index);
        let item_id = format!("msg_{}", response_id_suffix(&self.id));
        append_named_json(
            output,
            "response.output_item.added",
            &json!({
                "type": "response.output_item.added",
                "sequence_number": 0,
                "output_index": index,
                "item": {"id": item_id, "type": "message", "status": "in_progress", "role": "assistant", "content": []},
            }),
        )?;
        append_named_json(
            output,
            "response.content_part.added",
            &json!({
                "type": "response.content_part.added",
                "sequence_number": 0,
                "item_id": item_id,
                "output_index": index,
                "content_index": 0,
                "part": {"type": "output_text", "text": "", "annotations": []},
            }),
        )?;
        Ok(index)
    }

    fn ensure_response_reasoning(&mut self, output: &mut Vec<u8>) -> Result<usize, TransformError> {
        if let Some(index) = self.response_reasoning_index {
            return Ok(index);
        }
        let index = self.allocate_output_index();
        self.response_reasoning_index = Some(index);
        append_named_json(
            output,
            "response.output_item.added",
            &json!({
                "type": "response.output_item.added",
                "sequence_number": 0,
                "output_index": index,
                "item": {"id": format!("rs_{}", response_id_suffix(&self.id)), "type": "reasoning", "status": "in_progress", "summary": []},
            }),
        )?;
        Ok(index)
    }

    fn finish_response_items(&mut self, output: &mut Vec<u8>) -> Result<(), TransformError> {
        if let Some(index) = self.response_text_index {
            let item_id = format!("msg_{}", response_id_suffix(&self.id));
            append_named_json(
                output,
                "response.output_text.done",
                &json!({
                    "type": "response.output_text.done",
                    "sequence_number": 0,
                    "item_id": item_id,
                    "output_index": index,
                    "content_index": 0,
                    "text": self.response_text,
                }),
            )?;
            append_named_json(
                output,
                "response.content_part.done",
                &json!({
                    "type": "response.content_part.done",
                    "sequence_number": 0,
                    "item_id": item_id,
                    "output_index": index,
                    "content_index": 0,
                    "part": {"type": "output_text", "text": self.response_text, "annotations": []},
                }),
            )?;
            append_named_json(
                output,
                "response.output_item.done",
                &json!({
                    "type": "response.output_item.done",
                    "sequence_number": 0,
                    "output_index": index,
                    "item": {"id": item_id, "type": "message", "status": "completed", "role": "assistant", "content": [{"type": "output_text", "text": self.response_text, "annotations": []}]},
                }),
            )?;
        }
        if let Some(index) = self.response_reasoning_index {
            append_named_json(
                output,
                "response.output_item.done",
                &json!({
                    "type": "response.output_item.done",
                    "sequence_number": 0,
                    "output_index": index,
                    "item": {"id": format!("rs_{}", response_id_suffix(&self.id)), "type": "reasoning", "status": "completed", "summary": [{"type": "summary_text", "text": self.response_reasoning}]},
                }),
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AnthropicBlockKind {
    Text,
    Reasoning,
}

fn append_named_json(
    output: &mut Vec<u8>,
    event: &str,
    value: &Value,
) -> Result<(), TransformError> {
    output.extend_from_slice(b"event: ");
    output.extend_from_slice(event.as_bytes());
    output.extend_from_slice(b"\ndata: ");
    append_json(output, value)?;
    output.extend_from_slice(b"\n\n");
    Ok(())
}

fn append_data_json(output: &mut Vec<u8>, value: &Value) -> Result<(), TransformError> {
    output.extend_from_slice(b"data: ");
    append_json(output, value)?;
    output.extend_from_slice(b"\n\n");
    Ok(())
}

fn append_json(output: &mut Vec<u8>, value: &Value) -> Result<(), TransformError> {
    serde_json::to_writer(&mut *output, value)
        .map_err(|_| TransformError::invalid_response("converted SSE event could not be encoded"))
}

fn anthropic_usage_json(usage: CanonicalUsage) -> Value {
    let uncached = usage.input_tokens.saturating_sub(
        usage
            .cached_input_tokens
            .saturating_add(usage.cache_creation_input_tokens),
    );
    json!({
        "input_tokens": uncached,
        "output_tokens": usage.output_tokens,
        "cache_read_input_tokens": usage.cached_input_tokens,
        "cache_creation_input_tokens": usage.cache_creation_input_tokens,
    })
}

fn openai_chat_usage_json(usage: CanonicalUsage) -> Value {
    json!({
        "prompt_tokens": usage.input_tokens,
        "completion_tokens": usage.output_tokens,
        "total_tokens": effective_total_tokens(usage),
        "prompt_tokens_details": {"cached_tokens": usage.cached_input_tokens},
    })
}

fn gemini_usage_json(usage: CanonicalUsage) -> Value {
    json!({
        "promptTokenCount": usage.input_tokens,
        "candidatesTokenCount": usage.output_tokens,
        "totalTokenCount": effective_total_tokens(usage),
        "cachedContentTokenCount": usage.cached_input_tokens,
    })
}

fn response_stream_object(
    id: &str,
    model: &str,
    status: &str,
    usage: Option<CanonicalUsage>,
) -> Value {
    let mut response = json!({
        "id": id,
        "object": "response",
        "created_at": 0,
        "status": status,
        "model": model,
        "output": [],
        "parallel_tool_calls": true,
    });
    if let Some(usage) = usage {
        response["usage"] = json!({
            "input_tokens": usage.input_tokens,
            "input_tokens_details": {"cached_tokens": usage.cached_input_tokens},
            "output_tokens": usage.output_tokens,
            "output_tokens_details": {"reasoning_tokens": 0},
            "total_tokens": effective_total_tokens(usage),
        });
    }
    response
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TransformedRequest {
    pub route: GatewayRoute,
    pub body: Vec<u8>,
    pub bridge: ProtocolBridge,
}

/// Validates that a platform/account-kind combination has a concrete adapter.
pub(crate) fn validate_upstream_adapter(
    platform: &str,
    account_type: &str,
) -> Result<(), TransformError> {
    let platform = platform.trim().to_ascii_lowercase();
    let account_type = account_type.trim().to_ascii_lowercase();
    match account_type.as_str() {
        "apikey" | "upstream" => Ok(()),
        "oauth"
            if matches!(
                platform.as_str(),
                "anthropic" | "openai" | "gemini" | "antigravity" | "grok"
            ) =>
        {
            Ok(())
        }
        "setup-token" | "bedrock" if platform == "anthropic" => Ok(()),
        "service_account" if matches!(platform.as_str(), "anthropic" | "gemini") => Ok(()),
        "oauth" | "setup-token" | "bedrock" | "service_account" => {
            Err(TransformError::unsupported(format!(
                "account type {account_type:?} is not supported for platform {platform:?}"
            )))
        }
        _ => Err(TransformError::unsupported(format!(
            "account type {account_type:?} is not supported by the generic upstream adapter"
        ))),
    }
}

#[cfg(test)]
pub(crate) fn prepare_protocol_request(
    route: &GatewayRoute,
    target_platform: &str,
    metadata: &RequestMetadata,
    body: &[u8],
) -> Result<TransformedRequest, TransformError> {
    prepare_protocol_request_for_account(route, target_platform, metadata, body, true, false)
}

pub(crate) fn prepare_protocol_request_for_account(
    route: &GatewayRoute,
    target_platform: &str,
    metadata: &RequestMetadata,
    body: &[u8],
    openai_use_responses: bool,
    force_openai_responses: bool,
) -> Result<TransformedRequest, TransformError> {
    let target_protocol = platform_protocol(target_platform)?;
    let normalize_same_protocol = target_platform.trim().eq_ignore_ascii_case("antigravity");
    let force_route_conversion = force_openai_responses
        && target_protocol == Protocol::OpenAi
        && route.kind == RouteKind::OpenAiChatCompletions;
    if route.protocol == target_protocol && !force_route_conversion {
        return Ok(TransformedRequest {
            route: route.clone(),
            body: body.to_vec(),
            bridge: ProtocolBridge {
                client_protocol: route.protocol,
                upstream_protocol: route.protocol,
                client_kind: route.kind,
                upstream_kind: route.kind,
                normalize_same_protocol,
            },
        });
    }
    ensure_convertible_client_route(route)?;
    let value = serde_json::from_slice(body)
        .map_err(|_| TransformError::invalid_request("request body must contain valid JSON"))?;
    let mut request = parse_request(route, &value)?;
    request.stream = route.response_mode(metadata.stream) == ResponseMode::ServerSentEvents;
    let upstream_route = conversion_route(
        target_protocol,
        &request.model,
        openai_use_responses,
        request.stream,
    )?;
    let upstream_body = encode_request(upstream_route.kind, &request)?;
    let body = serde_json::to_vec(&upstream_body)
        .map_err(|_| TransformError::invalid_request("converted request could not be encoded"))?;
    Ok(TransformedRequest {
        route: upstream_route.clone(),
        body,
        bridge: ProtocolBridge {
            client_protocol: route.protocol,
            upstream_protocol: target_protocol,
            client_kind: route.kind,
            upstream_kind: upstream_route.kind,
            normalize_same_protocol,
        },
    })
}

fn platform_protocol(platform: &str) -> Result<Protocol, TransformError> {
    match platform.trim().to_ascii_lowercase().as_str() {
        "anthropic" => Ok(Protocol::Anthropic),
        "openai" | "grok" => Ok(Protocol::OpenAi),
        "gemini" | "antigravity" => Ok(Protocol::Gemini),
        other => Err(TransformError::unsupported(format!(
            "gateway platform {other:?} is not supported"
        ))),
    }
}

fn ensure_convertible_client_route(route: &GatewayRoute) -> Result<(), TransformError> {
    let supported = matches!(
        route.kind,
        RouteKind::AnthropicMessages
            | RouteKind::OpenAiResponses
            | RouteKind::OpenAiChatCompletions
            | RouteKind::GeminiGenerateContent
            | RouteKind::GeminiStreamGenerateContent
    );
    let canonical = match route.kind {
        RouteKind::GeminiGenerateContent | RouteKind::GeminiStreamGenerateContent => {
            route.model_from_path.as_deref().is_some_and(|model| {
                let action = if route.kind == RouteKind::GeminiStreamGenerateContent {
                    "streamGenerateContent"
                } else {
                    "generateContent"
                };
                route.upstream_path == format!("/v1beta/models/{model}:{action}")
            })
        }
        _ => route.upstream_path == canonical_path(route.kind),
    };
    if !supported || !canonical {
        return Err(TransformError::unsupported(format!(
            "{} cannot be converted to the selected upstream protocol",
            route.upstream_path
        )));
    }
    Ok(())
}

const fn canonical_path(kind: RouteKind) -> &'static str {
    match kind {
        RouteKind::AnthropicMessages => "/v1/messages",
        RouteKind::OpenAiResponses => "/v1/responses",
        RouteKind::OpenAiChatCompletions => "/v1/chat/completions",
        RouteKind::GeminiGenerateContent => "__model_from_path__",
        _ => "__unsupported__",
    }
}

fn conversion_route(
    protocol: Protocol,
    model: &str,
    openai_use_responses: bool,
    stream: bool,
) -> Result<GatewayRoute, TransformError> {
    if model.trim().is_empty() {
        return Err(TransformError::invalid_request(
            "request model must not be empty",
        ));
    }
    if protocol == Protocol::Gemini && !valid_gemini_model_segment(model) {
        return Err(TransformError::invalid_request(
            "model cannot be represented in a Gemini request path",
        ));
    }
    let (kind, path, model_from_path) = match protocol {
        Protocol::Anthropic => (
            RouteKind::AnthropicMessages,
            "/v1/messages".to_owned(),
            None,
        ),
        Protocol::OpenAi if openai_use_responses => {
            (RouteKind::OpenAiResponses, "/v1/responses".to_owned(), None)
        }
        Protocol::OpenAi => (
            RouteKind::OpenAiChatCompletions,
            "/v1/chat/completions".to_owned(),
            None,
        ),
        Protocol::Gemini => {
            let (kind, action) = if stream {
                (
                    RouteKind::GeminiStreamGenerateContent,
                    "streamGenerateContent",
                )
            } else {
                (RouteKind::GeminiGenerateContent, "generateContent")
            };
            (
                kind,
                format!("/v1beta/models/{model}:{action}"),
                Some(model.to_owned()),
            )
        }
    };
    Ok(GatewayRoute {
        protocol,
        kind,
        method: Method::POST,
        upstream_path: path,
        model_from_path,
    })
}

fn valid_gemini_model_segment(model: &str) -> bool {
    !model.is_empty()
        && model
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CanonicalRequest {
    model: String,
    system: Vec<String>,
    messages: Vec<CanonicalMessage>,
    tools: Vec<CanonicalTool>,
    tool_choice: Option<CanonicalToolChoice>,
    max_output_tokens: Option<u64>,
    temperature: Option<Value>,
    top_p: Option<Value>,
    stream: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CanonicalMessage {
    role: CanonicalRole,
    blocks: Vec<CanonicalRequestBlock>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CanonicalRole {
    User,
    Assistant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CanonicalRequestBlock {
    Text(String),
    ToolCall {
        id: String,
        name: String,
        arguments: Value,
    },
    ToolResult {
        id: String,
        name: String,
        output: Value,
        is_error: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CanonicalTool {
    name: String,
    description: Option<String>,
    parameters: Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CanonicalToolChoice {
    Auto,
    Any,
    None,
    Tool(String),
}

fn parse_request(route: &GatewayRoute, value: &Value) -> Result<CanonicalRequest, TransformError> {
    match route.kind {
        RouteKind::AnthropicMessages => parse_anthropic_request(value),
        RouteKind::OpenAiResponses => parse_openai_responses_request(value),
        RouteKind::OpenAiChatCompletions => parse_openai_chat_request(value),
        RouteKind::GeminiGenerateContent | RouteKind::GeminiStreamGenerateContent => {
            parse_gemini_request(
                value,
                route.model_from_path.as_deref().ok_or_else(|| {
                    TransformError::invalid_request("Gemini request path does not identify a model")
                })?,
            )
        }
        _ => Err(TransformError::unsupported(
            "this request operation has no protocol conversion",
        )),
    }
}

fn parse_anthropic_request(value: &Value) -> Result<CanonicalRequest, TransformError> {
    let object = request_object(value, "Anthropic request")?;
    let model = required_request_string(object, "model")?;
    let system = object
        .get("system")
        .map(parse_anthropic_system)
        .transpose()?
        .unwrap_or_default();
    let message_values = required_request_array(object, "messages")?;
    let mut call_names = HashMap::new();
    let mut messages = Vec::with_capacity(message_values.len());
    for (message_index, message) in message_values.iter().enumerate() {
        let message = request_object(message, "Anthropic message")?;
        let role = match required_request_string(message, "role")?.as_str() {
            "user" => CanonicalRole::User,
            "assistant" => CanonicalRole::Assistant,
            other => {
                return Err(TransformError::invalid_request(format!(
                    "unsupported Anthropic message role {other:?} at index {message_index}"
                )));
            }
        };
        let content = message.get("content").ok_or_else(|| {
            TransformError::invalid_request("Anthropic message content is required")
        })?;
        let blocks = parse_anthropic_message_content(content, &mut call_names)?;
        push_message(&mut messages, role, blocks);
    }
    resolve_tool_result_names(&mut messages, &call_names)?;
    Ok(CanonicalRequest {
        model,
        system,
        messages,
        tools: parse_anthropic_tools(object.get("tools"))?,
        tool_choice: parse_anthropic_tool_choice(object.get("tool_choice"))?,
        max_output_tokens: optional_u64(object.get("max_tokens"), "max_tokens")?,
        temperature: optional_number(object.get("temperature"), "temperature")?,
        top_p: optional_number(object.get("top_p"), "top_p")?,
        stream: false,
    })
}

fn parse_anthropic_system(value: &Value) -> Result<Vec<String>, TransformError> {
    if let Some(text) = value.as_str() {
        return Ok(vec![text.to_owned()]);
    }
    let blocks = value.as_array().ok_or_else(|| {
        TransformError::invalid_request("Anthropic system must be text or an array of text blocks")
    })?;
    blocks
        .iter()
        .map(|block| {
            let block = request_object(block, "Anthropic system block")?;
            require_type(block, "text", "Anthropic system block")?;
            required_request_string(block, "text")
        })
        .collect()
}

fn parse_anthropic_message_content(
    value: &Value,
    call_names: &mut HashMap<String, String>,
) -> Result<Vec<CanonicalRequestBlock>, TransformError> {
    if let Some(text) = value.as_str() {
        return Ok(vec![CanonicalRequestBlock::Text(text.to_owned())]);
    }
    let blocks = value.as_array().ok_or_else(|| {
        TransformError::invalid_request("Anthropic message content must be text or an array")
    })?;
    blocks
        .iter()
        .map(|block| {
            let block = request_object(block, "Anthropic content block")?;
            match required_request_string(block, "type")?.as_str() {
                "text" => Ok(CanonicalRequestBlock::Text(required_request_string(
                    block, "text",
                )?)),
                "tool_use" => {
                    let id = required_request_string(block, "id")?;
                    let name = required_request_string(block, "name")?;
                    let arguments = block.get("input").cloned().ok_or_else(|| {
                        TransformError::invalid_request("Anthropic tool_use input is required")
                    })?;
                    if !arguments.is_object() {
                        return Err(TransformError::invalid_request(
                            "Anthropic tool_use input must be an object",
                        ));
                    }
                    call_names.insert(id.clone(), name.clone());
                    Ok(CanonicalRequestBlock::ToolCall {
                        id,
                        name,
                        arguments,
                    })
                }
                "tool_result" => Ok(CanonicalRequestBlock::ToolResult {
                    id: required_request_string(block, "tool_use_id")?,
                    name: String::new(),
                    output: block
                        .get("content")
                        .map(normalize_tool_output)
                        .transpose()?
                        .unwrap_or_else(|| Value::String(String::new())),
                    is_error: block
                        .get("is_error")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                }),
                other => Err(TransformError::invalid_request(format!(
                    "Anthropic content block type {other:?} is not supported for conversion"
                ))),
            }
        })
        .collect()
}

fn parse_anthropic_tools(value: Option<&Value>) -> Result<Vec<CanonicalTool>, TransformError> {
    optional_array(value, "Anthropic tools")?
        .unwrap_or_default()
        .iter()
        .map(|tool| {
            let tool = request_object(tool, "Anthropic tool")?;
            let parameters = tool.get("input_schema").cloned().ok_or_else(|| {
                TransformError::invalid_request("Anthropic tool input_schema is required")
            })?;
            require_object_schema(&parameters, "Anthropic tool input_schema")?;
            Ok(CanonicalTool {
                name: required_request_string(tool, "name")?,
                description: optional_string(tool.get("description"), "description")?,
                parameters,
            })
        })
        .collect()
}

fn parse_anthropic_tool_choice(
    value: Option<&Value>,
) -> Result<Option<CanonicalToolChoice>, TransformError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let object = request_object(value, "Anthropic tool_choice")?;
    match required_request_string(object, "type")?.as_str() {
        "auto" => Ok(Some(CanonicalToolChoice::Auto)),
        "any" => Ok(Some(CanonicalToolChoice::Any)),
        "none" => Ok(Some(CanonicalToolChoice::None)),
        "tool" => Ok(Some(CanonicalToolChoice::Tool(required_request_string(
            object, "name",
        )?))),
        other => Err(TransformError::invalid_request(format!(
            "Anthropic tool_choice type {other:?} is not supported"
        ))),
    }
}

fn parse_openai_chat_request(value: &Value) -> Result<CanonicalRequest, TransformError> {
    let object = request_object(value, "OpenAI Chat Completions request")?;
    let model = required_request_string(object, "model")?;
    let values = required_request_array(object, "messages")?;
    let mut system = Vec::new();
    let mut messages = Vec::with_capacity(values.len());
    let mut call_names = HashMap::new();
    for (index, message) in values.iter().enumerate() {
        let message = request_object(message, "OpenAI chat message")?;
        let role = required_request_string(message, "role")?;
        match role.as_str() {
            "system" | "developer" => {
                let content = message.get("content").ok_or_else(|| {
                    TransformError::invalid_request("OpenAI system message content is required")
                })?;
                system.extend(parse_openai_text_content(content, "OpenAI system message")?);
            }
            "user" => {
                let content = message.get("content").ok_or_else(|| {
                    TransformError::invalid_request("OpenAI user message content is required")
                })?;
                let blocks = parse_openai_message_content(content, "OpenAI user message")?;
                push_message(&mut messages, CanonicalRole::User, blocks);
            }
            "assistant" => {
                let mut blocks = match message.get("content") {
                    Some(Value::Null) | None => Vec::new(),
                    Some(content) => {
                        parse_openai_message_content(content, "OpenAI assistant message")?
                    }
                };
                if let Some(tool_calls) = optional_array(message.get("tool_calls"), "tool_calls")? {
                    for tool_call in tool_calls {
                        let tool_call = request_object(tool_call, "OpenAI tool call")?;
                        require_type(tool_call, "function", "OpenAI tool call")?;
                        let function = request_object(
                            tool_call.get("function").ok_or_else(|| {
                                TransformError::invalid_request(
                                    "OpenAI tool call function is required",
                                )
                            })?,
                            "OpenAI tool call function",
                        )?;
                        let id = required_request_string(tool_call, "id")?;
                        let name = required_request_string(function, "name")?;
                        let arguments = parse_json_arguments(
                            function.get("arguments"),
                            "OpenAI tool call arguments",
                        )?;
                        call_names.insert(id.clone(), name.clone());
                        blocks.push(CanonicalRequestBlock::ToolCall {
                            id,
                            name,
                            arguments,
                        });
                    }
                }
                if blocks.is_empty() {
                    return Err(TransformError::invalid_request(format!(
                        "OpenAI assistant message at index {index} has no content"
                    )));
                }
                push_message(&mut messages, CanonicalRole::Assistant, blocks);
            }
            "tool" => {
                let id = required_request_string(message, "tool_call_id")?;
                let output = message
                    .get("content")
                    .map(normalize_tool_output)
                    .transpose()?
                    .unwrap_or_else(|| Value::String(String::new()));
                push_message(
                    &mut messages,
                    CanonicalRole::User,
                    vec![CanonicalRequestBlock::ToolResult {
                        id,
                        name: String::new(),
                        output,
                        is_error: false,
                    }],
                );
            }
            other => {
                return Err(TransformError::invalid_request(format!(
                    "unsupported OpenAI message role {other:?} at index {index}"
                )));
            }
        }
    }
    resolve_tool_result_names(&mut messages, &call_names)?;
    Ok(CanonicalRequest {
        model,
        system,
        messages,
        tools: parse_openai_tools(object.get("tools"), OpenAiToolShape::Chat)?,
        tool_choice: parse_openai_tool_choice(object.get("tool_choice"))?,
        max_output_tokens: optional_u64(
            object
                .get("max_completion_tokens")
                .or_else(|| object.get("max_tokens")),
            "max_completion_tokens",
        )?,
        temperature: optional_number(object.get("temperature"), "temperature")?,
        top_p: optional_number(object.get("top_p"), "top_p")?,
        stream: false,
    })
}

fn parse_openai_responses_request(value: &Value) -> Result<CanonicalRequest, TransformError> {
    let object = request_object(value, "OpenAI Responses request")?;
    let model = required_request_string(object, "model")?;
    let mut system = object
        .get("instructions")
        .map(|instructions| parse_openai_text_content(instructions, "OpenAI instructions"))
        .transpose()?
        .unwrap_or_default();
    let input = object
        .get("input")
        .ok_or_else(|| TransformError::invalid_request("OpenAI Responses input is required"))?;
    let mut messages = Vec::new();
    let mut call_names = HashMap::new();
    if let Some(text) = input.as_str() {
        push_message(
            &mut messages,
            CanonicalRole::User,
            vec![CanonicalRequestBlock::Text(text.to_owned())],
        );
    } else {
        let items = input.as_array().ok_or_else(|| {
            TransformError::invalid_request("OpenAI Responses input must be text or an array")
        })?;
        for (index, item) in items.iter().enumerate() {
            let item = request_object(item, "OpenAI Responses input item")?;
            let item_type = item
                .get("type")
                .and_then(Value::as_str)
                .or_else(|| item.contains_key("role").then_some("message"))
                .ok_or_else(|| {
                    TransformError::invalid_request("OpenAI Responses input item type is required")
                })?;
            match item_type {
                "message" => {
                    let role = required_request_string(item, "role")?;
                    let content = item.get("content").ok_or_else(|| {
                        TransformError::invalid_request(
                            "OpenAI Responses message content is required",
                        )
                    })?;
                    if matches!(role.as_str(), "system" | "developer") {
                        system.extend(parse_openai_text_content(
                            content,
                            "OpenAI Responses system message",
                        )?);
                    } else {
                        let canonical_role = match role.as_str() {
                            "user" => CanonicalRole::User,
                            "assistant" => CanonicalRole::Assistant,
                            other => {
                                return Err(TransformError::invalid_request(format!(
                                    "unsupported OpenAI Responses role {other:?} at index {index}"
                                )));
                            }
                        };
                        push_message(
                            &mut messages,
                            canonical_role,
                            parse_openai_message_content(content, "OpenAI Responses message")?,
                        );
                    }
                }
                "function_call" => {
                    let id = required_request_string(item, "call_id")?;
                    let name = required_request_string(item, "name")?;
                    let arguments = parse_json_arguments(
                        item.get("arguments"),
                        "OpenAI Responses function arguments",
                    )?;
                    call_names.insert(id.clone(), name.clone());
                    push_message(
                        &mut messages,
                        CanonicalRole::Assistant,
                        vec![CanonicalRequestBlock::ToolCall {
                            id,
                            name,
                            arguments,
                        }],
                    );
                }
                "function_call_output" => {
                    push_message(
                        &mut messages,
                        CanonicalRole::User,
                        vec![CanonicalRequestBlock::ToolResult {
                            id: required_request_string(item, "call_id")?,
                            name: String::new(),
                            output: item
                                .get("output")
                                .map(normalize_tool_output)
                                .transpose()?
                                .unwrap_or_else(|| Value::String(String::new())),
                            is_error: false,
                        }],
                    );
                }
                other => {
                    return Err(TransformError::invalid_request(format!(
                        "OpenAI Responses input type {other:?} is not supported for conversion"
                    )));
                }
            }
        }
    }
    resolve_tool_result_names(&mut messages, &call_names)?;
    Ok(CanonicalRequest {
        model,
        system,
        messages,
        tools: parse_openai_tools(object.get("tools"), OpenAiToolShape::Responses)?,
        tool_choice: parse_openai_tool_choice(object.get("tool_choice"))?,
        max_output_tokens: optional_u64(object.get("max_output_tokens"), "max_output_tokens")?,
        temperature: optional_number(object.get("temperature"), "temperature")?,
        top_p: optional_number(object.get("top_p"), "top_p")?,
        stream: false,
    })
}

fn parse_openai_text_content(value: &Value, context: &str) -> Result<Vec<String>, TransformError> {
    if let Some(text) = value.as_str() {
        return Ok(vec![text.to_owned()]);
    }
    let array = value.as_array().ok_or_else(|| {
        TransformError::invalid_request(format!("{context} must be text or an array"))
    })?;
    array
        .iter()
        .map(|block| {
            let block = request_object(block, context)?;
            match required_request_string(block, "type")?.as_str() {
                "text" | "input_text" | "output_text" => required_request_string(block, "text"),
                other => Err(TransformError::invalid_request(format!(
                    "{context} block type {other:?} is not supported for conversion"
                ))),
            }
        })
        .collect()
}

fn parse_openai_message_content(
    value: &Value,
    context: &str,
) -> Result<Vec<CanonicalRequestBlock>, TransformError> {
    Ok(parse_openai_text_content(value, context)?
        .into_iter()
        .map(CanonicalRequestBlock::Text)
        .collect())
}

#[derive(Clone, Copy)]
enum OpenAiToolShape {
    Chat,
    Responses,
}

fn parse_openai_tools(
    value: Option<&Value>,
    shape: OpenAiToolShape,
) -> Result<Vec<CanonicalTool>, TransformError> {
    optional_array(value, "OpenAI tools")?
        .unwrap_or_default()
        .iter()
        .map(|tool| {
            let outer = request_object(tool, "OpenAI tool")?;
            require_type(outer, "function", "OpenAI tool")?;
            let function = match shape {
                OpenAiToolShape::Chat => request_object(
                    outer.get("function").ok_or_else(|| {
                        TransformError::invalid_request("OpenAI tool function is required")
                    })?,
                    "OpenAI tool function",
                )?,
                OpenAiToolShape::Responses => outer,
            };
            let parameters = function
                .get("parameters")
                .cloned()
                .unwrap_or_else(empty_object_schema);
            require_object_schema(&parameters, "OpenAI tool parameters")?;
            Ok(CanonicalTool {
                name: required_request_string(function, "name")?,
                description: optional_string(function.get("description"), "description")?,
                parameters,
            })
        })
        .collect()
}

fn parse_openai_tool_choice(
    value: Option<&Value>,
) -> Result<Option<CanonicalToolChoice>, TransformError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if let Some(choice) = value.as_str() {
        return match choice {
            "auto" => Ok(Some(CanonicalToolChoice::Auto)),
            "required" => Ok(Some(CanonicalToolChoice::Any)),
            "none" => Ok(Some(CanonicalToolChoice::None)),
            other => Err(TransformError::invalid_request(format!(
                "OpenAI tool_choice {other:?} is not supported"
            ))),
        };
    }
    let object = request_object(value, "OpenAI tool_choice")?;
    require_type(object, "function", "OpenAI tool_choice")?;
    let name = if let Some(function) = object.get("function") {
        required_request_string(
            request_object(function, "OpenAI tool_choice function")?,
            "name",
        )?
    } else {
        required_request_string(object, "name")?
    };
    Ok(Some(CanonicalToolChoice::Tool(name)))
}

fn parse_gemini_request(value: &Value, model: &str) -> Result<CanonicalRequest, TransformError> {
    let object = request_object(value, "Gemini request")?;
    let system = object
        .get("systemInstruction")
        .map(|instruction| {
            let instruction = request_object(instruction, "Gemini systemInstruction")?;
            parse_gemini_text_parts(
                required_request_array(instruction, "parts")?,
                "Gemini systemInstruction",
            )
        })
        .transpose()?
        .unwrap_or_default();
    let values = required_request_array(object, "contents")?;
    let mut messages = Vec::with_capacity(values.len());
    let mut call_names = HashMap::new();
    let mut generated_call_index = 0_u64;
    for (index, content) in values.iter().enumerate() {
        let content = request_object(content, "Gemini content")?;
        let role = match required_request_string(content, "role")?.as_str() {
            "user" => CanonicalRole::User,
            "model" => CanonicalRole::Assistant,
            other => {
                return Err(TransformError::invalid_request(format!(
                    "unsupported Gemini role {other:?} at index {index}"
                )));
            }
        };
        let parts = required_request_array(content, "parts")?;
        let mut blocks = Vec::with_capacity(parts.len());
        for part in parts {
            let part = request_object(part, "Gemini content part")?;
            if let Some(text) = part.get("text") {
                blocks.push(CanonicalRequestBlock::Text(
                    text.as_str()
                        .ok_or_else(|| {
                            TransformError::invalid_request("Gemini part text must be a string")
                        })?
                        .to_owned(),
                ));
            } else if let Some(call) = part.get("functionCall") {
                let call = request_object(call, "Gemini functionCall")?;
                generated_call_index = generated_call_index.saturating_add(1);
                let id = optional_string(call.get("id"), "Gemini functionCall id")?
                    .unwrap_or_else(|| format!("call_gemini_{generated_call_index}"));
                let name = required_request_string(call, "name")?;
                let arguments = call
                    .get("args")
                    .cloned()
                    .unwrap_or_else(|| Value::Object(Map::new()));
                if !arguments.is_object() {
                    return Err(TransformError::invalid_request(
                        "Gemini functionCall args must be an object",
                    ));
                }
                call_names.insert(id.clone(), name.clone());
                blocks.push(CanonicalRequestBlock::ToolCall {
                    id,
                    name,
                    arguments,
                });
            } else if let Some(response) = part.get("functionResponse") {
                let response = request_object(response, "Gemini functionResponse")?;
                generated_call_index = generated_call_index.saturating_add(1);
                let name = required_request_string(response, "name")?;
                let id = optional_string(response.get("id"), "Gemini functionResponse id")?
                    .or_else(|| {
                        call_names
                            .iter()
                            .find_map(|(id, call_name)| (call_name == &name).then(|| id.clone()))
                    })
                    .unwrap_or_else(|| format!("call_gemini_{generated_call_index}"));
                blocks.push(CanonicalRequestBlock::ToolResult {
                    id,
                    name,
                    output: response
                        .get("response")
                        .cloned()
                        .unwrap_or_else(|| Value::Object(Map::new())),
                    is_error: false,
                });
            } else {
                return Err(TransformError::invalid_request(
                    "Gemini content part is not supported for protocol conversion",
                ));
            }
        }
        push_message(&mut messages, role, blocks);
    }
    let generation = object
        .get("generationConfig")
        .map(|value| request_object(value, "Gemini generationConfig"))
        .transpose()?;
    Ok(CanonicalRequest {
        model: model.to_owned(),
        system,
        messages,
        tools: parse_gemini_tools(object.get("tools"))?,
        tool_choice: parse_gemini_tool_choice(object.get("toolConfig"))?,
        max_output_tokens: generation
            .and_then(|value| value.get("maxOutputTokens"))
            .map(|value| optional_u64(Some(value), "maxOutputTokens"))
            .transpose()?
            .flatten(),
        temperature: generation
            .and_then(|value| value.get("temperature"))
            .map(|value| optional_number(Some(value), "temperature"))
            .transpose()?
            .flatten(),
        top_p: generation
            .and_then(|value| value.get("topP"))
            .map(|value| optional_number(Some(value), "topP"))
            .transpose()?
            .flatten(),
        stream: false,
    })
}

fn parse_gemini_text_parts(parts: &[Value], context: &str) -> Result<Vec<String>, TransformError> {
    parts
        .iter()
        .map(|part| {
            let part = request_object(part, context)?;
            required_request_string(part, "text")
        })
        .collect()
}

fn parse_gemini_tools(value: Option<&Value>) -> Result<Vec<CanonicalTool>, TransformError> {
    let mut tools = Vec::new();
    for wrapper in optional_array(value, "Gemini tools")?.unwrap_or_default() {
        let wrapper = request_object(wrapper, "Gemini tool wrapper")?;
        let declarations = required_request_array(wrapper, "functionDeclarations")?;
        for declaration in declarations {
            let declaration = request_object(declaration, "Gemini function declaration")?;
            let parameters = declaration
                .get("parameters")
                .cloned()
                .unwrap_or_else(empty_object_schema);
            require_object_schema(&parameters, "Gemini function parameters")?;
            tools.push(CanonicalTool {
                name: required_request_string(declaration, "name")?,
                description: optional_string(declaration.get("description"), "description")?,
                parameters,
            });
        }
    }
    Ok(tools)
}

fn parse_gemini_tool_choice(
    value: Option<&Value>,
) -> Result<Option<CanonicalToolChoice>, TransformError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let config = request_object(value, "Gemini toolConfig")?
        .get("functionCallingConfig")
        .ok_or_else(|| {
            TransformError::invalid_request("Gemini functionCallingConfig is required")
        })?;
    let config = request_object(config, "Gemini functionCallingConfig")?;
    match required_request_string(config, "mode")?
        .to_ascii_uppercase()
        .as_str()
    {
        "AUTO" => Ok(Some(CanonicalToolChoice::Auto)),
        "NONE" => Ok(Some(CanonicalToolChoice::None)),
        "ANY" => {
            let names = optional_array(config.get("allowedFunctionNames"), "allowedFunctionNames")?;
            match names {
                Some([only]) => Ok(Some(CanonicalToolChoice::Tool(
                    only.as_str()
                        .ok_or_else(|| {
                            TransformError::invalid_request(
                                "allowedFunctionNames entries must be strings",
                            )
                        })?
                        .to_owned(),
                ))),
                Some([]) | None => Ok(Some(CanonicalToolChoice::Any)),
                Some(_) => Err(TransformError::unsupported(
                    "multiple allowed Gemini functions cannot be represented by every protocol",
                )),
            }
        }
        other => Err(TransformError::invalid_request(format!(
            "Gemini function calling mode {other:?} is not supported"
        ))),
    }
}

fn encode_request(kind: RouteKind, request: &CanonicalRequest) -> Result<Value, TransformError> {
    match kind {
        RouteKind::AnthropicMessages => encode_anthropic_request(request),
        RouteKind::OpenAiResponses => encode_openai_responses_request(request),
        RouteKind::OpenAiChatCompletions => encode_openai_chat_request(request),
        RouteKind::GeminiGenerateContent | RouteKind::GeminiStreamGenerateContent => {
            Ok(encode_gemini_request(request))
        }
        _ => Err(TransformError::unsupported(
            "selected upstream operation has no request encoder",
        )),
    }
}

fn encode_anthropic_request(request: &CanonicalRequest) -> Result<Value, TransformError> {
    let mut object = Map::new();
    object.insert("model".to_owned(), Value::String(request.model.clone()));
    object.insert(
        "max_tokens".to_owned(),
        json!(request.max_output_tokens.unwrap_or(4096)),
    );
    object.insert("stream".to_owned(), Value::Bool(request.stream));
    if !request.system.is_empty() {
        object.insert(
            "system".to_owned(),
            Value::String(request.system.join("\n\n")),
        );
    }
    let mut messages = Vec::with_capacity(request.messages.len());
    for message in &request.messages {
        let mut content = Vec::with_capacity(message.blocks.len());
        for block in &message.blocks {
            content.push(match block {
                CanonicalRequestBlock::Text(text) => json!({
                    "type": "text",
                    "text": text,
                }),
                CanonicalRequestBlock::ToolCall {
                    id,
                    name,
                    arguments,
                } => json!({
                    "type": "tool_use",
                    "id": id,
                    "name": name,
                    "input": arguments,
                }),
                CanonicalRequestBlock::ToolResult {
                    id,
                    output,
                    is_error,
                    ..
                } => json!({
                    "type": "tool_result",
                    "tool_use_id": id,
                    "content": tool_output_string(output)?,
                    "is_error": is_error,
                }),
            });
        }
        messages.push(json!({
            "role": match message.role {
                CanonicalRole::User => "user",
                CanonicalRole::Assistant => "assistant",
            },
            "content": content,
        }));
    }
    object.insert("messages".to_owned(), Value::Array(messages));
    let tools_disabled = matches!(
        request.tool_choice.as_ref(),
        Some(CanonicalToolChoice::None)
    );
    if !request.tools.is_empty() && !tools_disabled {
        object.insert(
            "tools".to_owned(),
            Value::Array(
                request
                    .tools
                    .iter()
                    .map(|tool| {
                        let mut value = json!({
                            "name": tool.name,
                            "input_schema": tool.parameters,
                        });
                        if let Some(description) = &tool.description {
                            value["description"] = Value::String(description.clone());
                        }
                        value
                    })
                    .collect(),
            ),
        );
    }
    if let Some(choice) = &request.tool_choice
        && !matches!(choice, CanonicalToolChoice::None)
    {
        object.insert(
            "tool_choice".to_owned(),
            match choice {
                CanonicalToolChoice::Auto => json!({"type": "auto"}),
                CanonicalToolChoice::Any => json!({"type": "any"}),
                CanonicalToolChoice::None => unreachable!("disabled tools omit Anthropic choice"),
                CanonicalToolChoice::Tool(name) => json!({"type": "tool", "name": name}),
            },
        );
    }
    insert_sampling_options(&mut object, request, "top_p");
    Ok(Value::Object(object))
}

fn encode_openai_chat_request(request: &CanonicalRequest) -> Result<Value, TransformError> {
    let mut object = Map::new();
    object.insert("model".to_owned(), Value::String(request.model.clone()));
    object.insert("stream".to_owned(), Value::Bool(request.stream));
    if request.stream {
        object.insert("stream_options".to_owned(), json!({"include_usage": true}));
    }
    let mut messages = Vec::new();
    if !request.system.is_empty() {
        messages.push(json!({
            "role": "system",
            "content": request.system.join("\n\n"),
        }));
    }
    for message in &request.messages {
        for block in &message.blocks {
            match block {
                CanonicalRequestBlock::Text(text) => messages.push(json!({
                    "role": match message.role {
                        CanonicalRole::User => "user",
                        CanonicalRole::Assistant => "assistant",
                    },
                    "content": text,
                })),
                CanonicalRequestBlock::ToolCall {
                    id,
                    name,
                    arguments,
                } => {
                    if message.role != CanonicalRole::Assistant {
                        return Err(TransformError::invalid_request(
                            "tool calls must belong to an assistant message",
                        ));
                    }
                    messages.push(json!({
                        "role": "assistant",
                        "content": null,
                        "tool_calls": [{
                            "id": id,
                            "type": "function",
                            "function": {
                                "name": name,
                                "arguments": serde_json::to_string(arguments).map_err(|_| {
                                    TransformError::invalid_request(
                                        "tool arguments could not be encoded",
                                    )
                                })?,
                            }
                        }],
                    }));
                }
                CanonicalRequestBlock::ToolResult { id, output, .. } => {
                    if message.role != CanonicalRole::User {
                        return Err(TransformError::invalid_request(
                            "tool results must belong to a user message",
                        ));
                    }
                    messages.push(json!({
                        "role": "tool",
                        "tool_call_id": id,
                        "content": tool_output_string(output)?,
                    }));
                }
            }
        }
    }
    object.insert("messages".to_owned(), Value::Array(messages));
    if let Some(max_output_tokens) = request.max_output_tokens {
        object.insert("max_completion_tokens".to_owned(), json!(max_output_tokens));
    }
    if !request.tools.is_empty() {
        object.insert(
            "tools".to_owned(),
            Value::Array(
                request
                    .tools
                    .iter()
                    .map(|tool| {
                        let mut function = json!({
                            "name": tool.name,
                            "parameters": tool.parameters,
                        });
                        if let Some(description) = &tool.description {
                            function["description"] = Value::String(description.clone());
                        }
                        json!({"type": "function", "function": function})
                    })
                    .collect(),
            ),
        );
    }
    if let Some(choice) = &request.tool_choice {
        object.insert(
            "tool_choice".to_owned(),
            match choice {
                CanonicalToolChoice::Auto => Value::String("auto".to_owned()),
                CanonicalToolChoice::Any => Value::String("required".to_owned()),
                CanonicalToolChoice::None => Value::String("none".to_owned()),
                CanonicalToolChoice::Tool(name) => {
                    json!({"type": "function", "function": {"name": name}})
                }
            },
        );
    }
    insert_sampling_options(&mut object, request, "top_p");
    Ok(Value::Object(object))
}

fn encode_openai_responses_request(request: &CanonicalRequest) -> Result<Value, TransformError> {
    let mut object = Map::new();
    object.insert("model".to_owned(), Value::String(request.model.clone()));
    object.insert("stream".to_owned(), Value::Bool(request.stream));
    if !request.system.is_empty() {
        object.insert(
            "instructions".to_owned(),
            Value::String(request.system.join("\n\n")),
        );
    }
    let mut input = Vec::new();
    for message in &request.messages {
        for block in &message.blocks {
            match block {
                CanonicalRequestBlock::Text(text) => input.push(json!({
                    "type": "message",
                    "role": match message.role {
                        CanonicalRole::User => "user",
                        CanonicalRole::Assistant => "assistant",
                    },
                    "content": [{
                        "type": match message.role {
                            CanonicalRole::User => "input_text",
                            CanonicalRole::Assistant => "output_text",
                        },
                        "text": text,
                    }],
                })),
                CanonicalRequestBlock::ToolCall {
                    id,
                    name,
                    arguments,
                } => input.push(json!({
                    "type": "function_call",
                    "call_id": id,
                    "name": name,
                    "arguments": serde_json::to_string(arguments).map_err(|_| {
                        TransformError::invalid_request("tool arguments could not be encoded")
                    })?,
                })),
                CanonicalRequestBlock::ToolResult { id, output, .. } => input.push(json!({
                    "type": "function_call_output",
                    "call_id": id,
                    "output": tool_output_string(output)?,
                })),
            }
        }
    }
    object.insert("input".to_owned(), Value::Array(input));
    if let Some(max_output_tokens) = request.max_output_tokens {
        object.insert("max_output_tokens".to_owned(), json!(max_output_tokens));
    }
    if !request.tools.is_empty() {
        object.insert(
            "tools".to_owned(),
            Value::Array(
                request
                    .tools
                    .iter()
                    .map(|tool| {
                        let mut value = json!({
                            "type": "function",
                            "name": tool.name,
                            "parameters": tool.parameters,
                        });
                        if let Some(description) = &tool.description {
                            value["description"] = Value::String(description.clone());
                        }
                        value
                    })
                    .collect(),
            ),
        );
    }
    if let Some(choice) = &request.tool_choice {
        object.insert(
            "tool_choice".to_owned(),
            match choice {
                CanonicalToolChoice::Auto => Value::String("auto".to_owned()),
                CanonicalToolChoice::Any => Value::String("required".to_owned()),
                CanonicalToolChoice::None => Value::String("none".to_owned()),
                CanonicalToolChoice::Tool(name) => {
                    json!({"type": "function", "name": name})
                }
            },
        );
    }
    insert_sampling_options(&mut object, request, "top_p");
    Ok(Value::Object(object))
}

fn encode_gemini_request(request: &CanonicalRequest) -> Value {
    let mut object = Map::new();
    if !request.system.is_empty() {
        object.insert(
            "systemInstruction".to_owned(),
            json!({
                "parts": request.system.iter().map(|text| json!({"text": text})).collect::<Vec<_>>(),
            }),
        );
    }
    let mut contents = Vec::with_capacity(request.messages.len());
    for message in &request.messages {
        let mut parts = Vec::with_capacity(message.blocks.len());
        for block in &message.blocks {
            parts.push(match block {
                CanonicalRequestBlock::Text(text) => json!({"text": text}),
                CanonicalRequestBlock::ToolCall {
                    id,
                    name,
                    arguments,
                } => json!({
                    "functionCall": {
                        "id": id,
                        "name": name,
                        "args": arguments,
                    }
                }),
                CanonicalRequestBlock::ToolResult {
                    id,
                    name,
                    output,
                    is_error,
                } => json!({
                    "functionResponse": {
                        "id": id,
                        "name": name,
                        "response": gemini_tool_response(output, *is_error),
                    }
                }),
            });
        }
        contents.push(json!({
            "role": match message.role {
                CanonicalRole::User => "user",
                CanonicalRole::Assistant => "model",
            },
            "parts": parts,
        }));
    }
    object.insert("contents".to_owned(), Value::Array(contents));
    if !request.tools.is_empty() {
        object.insert(
            "tools".to_owned(),
            json!([{
                "functionDeclarations": request.tools.iter().map(|tool| {
                    let mut declaration = json!({
                        "name": tool.name,
                        "parameters": tool.parameters,
                    });
                    if let Some(description) = &tool.description {
                        declaration["description"] = Value::String(description.clone());
                    }
                    declaration
                }).collect::<Vec<_>>(),
            }]),
        );
    }
    if let Some(choice) = &request.tool_choice {
        let function_calling = match choice {
            CanonicalToolChoice::Auto => json!({"mode": "AUTO"}),
            CanonicalToolChoice::Any => json!({"mode": "ANY"}),
            CanonicalToolChoice::None => json!({"mode": "NONE"}),
            CanonicalToolChoice::Tool(name) => {
                json!({"mode": "ANY", "allowedFunctionNames": [name]})
            }
        };
        object.insert(
            "toolConfig".to_owned(),
            json!({"functionCallingConfig": function_calling}),
        );
    }
    let mut generation = Map::new();
    if let Some(max_output_tokens) = request.max_output_tokens {
        generation.insert("maxOutputTokens".to_owned(), json!(max_output_tokens));
    }
    if let Some(temperature) = &request.temperature {
        generation.insert("temperature".to_owned(), temperature.clone());
    }
    if let Some(top_p) = &request.top_p {
        generation.insert("topP".to_owned(), top_p.clone());
    }
    if !generation.is_empty() {
        object.insert("generationConfig".to_owned(), Value::Object(generation));
    }
    Value::Object(object)
}

fn insert_sampling_options(
    object: &mut Map<String, Value>,
    request: &CanonicalRequest,
    top_p: &str,
) {
    if let Some(temperature) = &request.temperature {
        object.insert("temperature".to_owned(), temperature.clone());
    }
    if let Some(value) = &request.top_p {
        object.insert(top_p.to_owned(), value.clone());
    }
}

fn gemini_tool_response(output: &Value, is_error: bool) -> Value {
    let mut response = match output {
        Value::Object(object) => object.clone(),
        other => Map::from_iter([("result".to_owned(), other.clone())]),
    };
    if is_error {
        response.insert("is_error".to_owned(), Value::Bool(true));
    }
    Value::Object(response)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CanonicalResponse {
    id: String,
    model: String,
    blocks: Vec<CanonicalResponseBlock>,
    stop_reason: CanonicalStopReason,
    usage: Option<CanonicalUsage>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CanonicalResponseBlock {
    Text(String),
    ToolCall {
        id: String,
        name: String,
        arguments: Value,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CanonicalStopReason {
    EndTurn,
    MaxTokens,
    ToolUse,
    StopSequence,
    ContentFilter,
    Unknown,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CanonicalUsage {
    input_tokens: u64,
    output_tokens: u64,
    total_tokens: u64,
    cached_input_tokens: u64,
    cache_creation_input_tokens: u64,
}

fn parse_response(kind: RouteKind, value: &Value) -> Result<CanonicalResponse, TransformError> {
    match kind {
        RouteKind::AnthropicMessages => parse_anthropic_response(value),
        RouteKind::OpenAiResponses => parse_openai_responses_response(value),
        RouteKind::OpenAiChatCompletions => parse_openai_chat_response(value),
        RouteKind::GeminiGenerateContent => parse_gemini_response(value),
        _ => Err(TransformError::invalid_response(
            "selected upstream operation has no response decoder",
        )),
    }
}

fn parse_anthropic_response(value: &Value) -> Result<CanonicalResponse, TransformError> {
    let object = response_object(value, "Anthropic response")?;
    let content = required_response_array(object, "content")?;
    let mut blocks = Vec::with_capacity(content.len());
    for block in content {
        let block = response_object(block, "Anthropic response content block")?;
        match required_response_string(block, "type")?.as_str() {
            "text" => blocks.push(CanonicalResponseBlock::Text(required_response_string(
                block, "text",
            )?)),
            "tool_use" => {
                let arguments = block.get("input").cloned().ok_or_else(|| {
                    TransformError::invalid_response("Anthropic tool_use input is missing")
                })?;
                if !arguments.is_object() {
                    return Err(TransformError::invalid_response(
                        "Anthropic tool_use input is not an object",
                    ));
                }
                blocks.push(CanonicalResponseBlock::ToolCall {
                    id: required_response_string(block, "id")?,
                    name: required_response_string(block, "name")?,
                    arguments,
                });
            }
            other => {
                return Err(TransformError::invalid_response(format!(
                    "Anthropic response block type {other:?} cannot be converted"
                )));
            }
        }
    }
    let usage = object
        .get("usage")
        .map(|usage| {
            let usage = response_object(usage, "Anthropic usage")?;
            let input_tokens = response_u64(usage.get("input_tokens"), "input_tokens")?;
            let output_tokens = response_u64(usage.get("output_tokens"), "output_tokens")?;
            let cached_input_tokens = response_u64(
                usage.get("cache_read_input_tokens"),
                "cache_read_input_tokens",
            )?;
            let cache_creation_input_tokens = response_u64(
                usage.get("cache_creation_input_tokens"),
                "cache_creation_input_tokens",
            )?;
            Ok(CanonicalUsage {
                input_tokens: input_tokens
                    .saturating_add(cached_input_tokens)
                    .saturating_add(cache_creation_input_tokens),
                output_tokens,
                total_tokens: input_tokens
                    .saturating_add(output_tokens)
                    .saturating_add(cached_input_tokens)
                    .saturating_add(cache_creation_input_tokens),
                cached_input_tokens,
                cache_creation_input_tokens,
            })
        })
        .transpose()?;
    let stop_reason =
        match optional_response_string(object.get("stop_reason"), "stop_reason")?.as_deref() {
            Some("end_turn") | None => CanonicalStopReason::EndTurn,
            Some("max_tokens") => CanonicalStopReason::MaxTokens,
            Some("tool_use") => CanonicalStopReason::ToolUse,
            Some("stop_sequence") => CanonicalStopReason::StopSequence,
            Some("refusal") => CanonicalStopReason::ContentFilter,
            Some(_) => CanonicalStopReason::Unknown,
        };
    Ok(CanonicalResponse {
        id: required_response_string(object, "id")?,
        model: required_response_string(object, "model")?,
        blocks,
        stop_reason,
        usage,
    })
}

fn parse_openai_responses_response(value: &Value) -> Result<CanonicalResponse, TransformError> {
    let object = response_object(value, "OpenAI Responses response")?;
    let output = required_response_array(object, "output")?;
    let mut blocks = Vec::new();
    for item in output {
        let item = response_object(item, "OpenAI Responses output item")?;
        match required_response_string(item, "type")?.as_str() {
            "message" => {
                for content in required_response_array(item, "content")? {
                    let content = response_object(content, "OpenAI output content")?;
                    match required_response_string(content, "type")?.as_str() {
                        "output_text" | "text" => {
                            blocks.push(CanonicalResponseBlock::Text(required_response_string(
                                content, "text",
                            )?));
                        }
                        other => {
                            return Err(TransformError::invalid_response(format!(
                                "OpenAI output content type {other:?} cannot be converted"
                            )));
                        }
                    }
                }
            }
            "function_call" => blocks.push(CanonicalResponseBlock::ToolCall {
                id: required_response_string(item, "call_id")?,
                name: required_response_string(item, "name")?,
                arguments: parse_response_json_arguments(
                    item.get("arguments"),
                    "OpenAI function arguments",
                )?,
            }),
            "reasoning"
                if item
                    .get("summary")
                    .and_then(Value::as_array)
                    .is_none_or(Vec::is_empty)
                    && item.get("encrypted_content").is_none_or(Value::is_null) => {}
            other => {
                return Err(TransformError::invalid_response(format!(
                    "OpenAI output item type {other:?} cannot be converted"
                )));
            }
        }
    }
    let usage = object.get("usage").map(parse_openai_usage).transpose()?;
    let incomplete_reason = object
        .get("incomplete_details")
        .and_then(Value::as_object)
        .and_then(|details| details.get("reason"))
        .and_then(Value::as_str);
    let status = optional_response_string(object.get("status"), "status")?;
    let stop_reason = if blocks
        .iter()
        .any(|block| matches!(block, CanonicalResponseBlock::ToolCall { .. }))
    {
        CanonicalStopReason::ToolUse
    } else if matches!(incomplete_reason, Some("max_output_tokens")) {
        CanonicalStopReason::MaxTokens
    } else if matches!(incomplete_reason, Some("content_filter")) {
        CanonicalStopReason::ContentFilter
    } else if matches!(status.as_deref(), Some("completed") | None) {
        CanonicalStopReason::EndTurn
    } else {
        CanonicalStopReason::Unknown
    };
    Ok(CanonicalResponse {
        id: required_response_string(object, "id")?,
        model: required_response_string(object, "model")?,
        blocks,
        stop_reason,
        usage,
    })
}

fn parse_openai_chat_response(value: &Value) -> Result<CanonicalResponse, TransformError> {
    let object = response_object(value, "OpenAI Chat Completions response")?;
    let choices = required_response_array(object, "choices")?;
    let choice = choices.first().ok_or_else(|| {
        TransformError::invalid_response("OpenAI response did not contain a choice")
    })?;
    let choice = response_object(choice, "OpenAI response choice")?;
    let message = response_object(
        choice
            .get("message")
            .ok_or_else(|| TransformError::invalid_response("OpenAI choice has no message"))?,
        "OpenAI choice message",
    )?;
    let mut blocks = Vec::new();
    if let Some(content) = message.get("content")
        && !content.is_null()
    {
        for text in parse_response_text_content(content, "OpenAI response message")? {
            blocks.push(CanonicalResponseBlock::Text(text));
        }
    }
    if let Some(tool_calls) = optional_response_array(message.get("tool_calls"), "tool_calls")? {
        for tool_call in tool_calls {
            let tool_call = response_object(tool_call, "OpenAI response tool call")?;
            let function = response_object(
                tool_call.get("function").ok_or_else(|| {
                    TransformError::invalid_response("OpenAI tool call has no function")
                })?,
                "OpenAI response tool function",
            )?;
            blocks.push(CanonicalResponseBlock::ToolCall {
                id: required_response_string(tool_call, "id")?,
                name: required_response_string(function, "name")?,
                arguments: parse_response_json_arguments(
                    function.get("arguments"),
                    "OpenAI function arguments",
                )?,
            });
        }
    }
    let stop_reason =
        match optional_response_string(choice.get("finish_reason"), "finish_reason")?.as_deref() {
            Some("stop") | None => CanonicalStopReason::EndTurn,
            Some("length") => CanonicalStopReason::MaxTokens,
            Some("tool_calls" | "function_call") => CanonicalStopReason::ToolUse,
            Some("content_filter") => CanonicalStopReason::ContentFilter,
            Some(_) => CanonicalStopReason::Unknown,
        };
    Ok(CanonicalResponse {
        id: required_response_string(object, "id")?,
        model: required_response_string(object, "model")?,
        blocks,
        stop_reason,
        usage: object.get("usage").map(parse_openai_usage).transpose()?,
    })
}

fn parse_openai_usage(value: &Value) -> Result<CanonicalUsage, TransformError> {
    let usage = response_object(value, "OpenAI usage")?;
    let input_tokens = response_u64(
        usage
            .get("input_tokens")
            .or_else(|| usage.get("prompt_tokens")),
        "input tokens",
    )?;
    let output_tokens = response_u64(
        usage
            .get("output_tokens")
            .or_else(|| usage.get("completion_tokens")),
        "output tokens",
    )?;
    let total_tokens = response_u64(usage.get("total_tokens"), "total_tokens")?;
    let cached_input_tokens = usage
        .get("input_tokens_details")
        .or_else(|| usage.get("prompt_tokens_details"))
        .and_then(Value::as_object)
        .map_or(Ok(0), |details| {
            response_u64(details.get("cached_tokens"), "cached_tokens")
        })?;
    Ok(CanonicalUsage {
        input_tokens,
        output_tokens,
        total_tokens: if total_tokens == 0 {
            input_tokens.saturating_add(output_tokens)
        } else {
            total_tokens
        },
        cached_input_tokens,
        cache_creation_input_tokens: 0,
    })
}

fn parse_gemini_response(value: &Value) -> Result<CanonicalResponse, TransformError> {
    let value = value.get("response").unwrap_or(value);
    let object = response_object(value, "Gemini response")?;
    let candidates = required_response_array(object, "candidates")?;
    let candidate = candidates
        .first()
        .ok_or_else(|| TransformError::invalid_response("Gemini response has no candidate"))?;
    let candidate = response_object(candidate, "Gemini candidate")?;
    let content = response_object(
        candidate
            .get("content")
            .ok_or_else(|| TransformError::invalid_response("Gemini candidate has no content"))?,
        "Gemini candidate content",
    )?;
    let mut blocks = Vec::new();
    let mut generated_call_index = 0_u64;
    for part in required_response_array(content, "parts")? {
        let part = response_object(part, "Gemini response part")?;
        if let Some(text) = part.get("text") {
            blocks.push(CanonicalResponseBlock::Text(
                text.as_str()
                    .ok_or_else(|| {
                        TransformError::invalid_response("Gemini response text is not a string")
                    })?
                    .to_owned(),
            ));
        } else if let Some(call) = part.get("functionCall") {
            let call = response_object(call, "Gemini response functionCall")?;
            generated_call_index = generated_call_index.saturating_add(1);
            let id = optional_response_string(call.get("id"), "Gemini functionCall id")?
                .unwrap_or_else(|| format!("call_gemini_{generated_call_index}"));
            let arguments = call
                .get("args")
                .cloned()
                .unwrap_or_else(|| Value::Object(Map::new()));
            if !arguments.is_object() {
                return Err(TransformError::invalid_response(
                    "Gemini response function args are not an object",
                ));
            }
            blocks.push(CanonicalResponseBlock::ToolCall {
                id,
                name: required_response_string(call, "name")?,
                arguments,
            });
        } else {
            return Err(TransformError::invalid_response(
                "Gemini response part cannot be converted",
            ));
        }
    }
    let finish_reason = optional_response_string(candidate.get("finishReason"), "finishReason")?
        .unwrap_or_else(|| "STOP".to_owned())
        .to_ascii_uppercase();
    let stop_reason = if blocks
        .iter()
        .any(|block| matches!(block, CanonicalResponseBlock::ToolCall { .. }))
    {
        CanonicalStopReason::ToolUse
    } else {
        match finish_reason.as_str() {
            "STOP" => CanonicalStopReason::EndTurn,
            "MAX_TOKENS" => CanonicalStopReason::MaxTokens,
            "SAFETY" | "RECITATION" | "BLOCKLIST" | "PROHIBITED_CONTENT" => {
                CanonicalStopReason::ContentFilter
            }
            _ => CanonicalStopReason::Unknown,
        }
    };
    let usage = object
        .get("usageMetadata")
        .map(|usage| {
            let usage = response_object(usage, "Gemini usageMetadata")?;
            let input_tokens = response_u64(usage.get("promptTokenCount"), "promptTokenCount")?;
            let output_tokens =
                response_u64(usage.get("candidatesTokenCount"), "candidatesTokenCount")?;
            let total_tokens = response_u64(usage.get("totalTokenCount"), "totalTokenCount")?;
            Ok(CanonicalUsage {
                input_tokens,
                output_tokens,
                total_tokens: if total_tokens == 0 {
                    input_tokens.saturating_add(output_tokens)
                } else {
                    total_tokens
                },
                cached_input_tokens: response_u64(
                    usage.get("cachedContentTokenCount"),
                    "cachedContentTokenCount",
                )?,
                cache_creation_input_tokens: 0,
            })
        })
        .transpose()?;
    Ok(CanonicalResponse {
        id: optional_response_string(object.get("responseId"), "responseId")?
            .unwrap_or_else(|| "gemini_response".to_owned()),
        model: required_response_string(object, "modelVersion")?,
        blocks,
        stop_reason,
        usage,
    })
}

fn encode_response(kind: RouteKind, response: &CanonicalResponse) -> Result<Value, TransformError> {
    match kind {
        RouteKind::AnthropicMessages => encode_anthropic_response(response),
        RouteKind::OpenAiResponses => encode_openai_responses_response(response),
        RouteKind::OpenAiChatCompletions => encode_openai_chat_response(response),
        RouteKind::GeminiGenerateContent => encode_gemini_response(response),
        _ => Err(TransformError::invalid_response(
            "client operation has no response encoder",
        )),
    }
}

fn encode_anthropic_response(response: &CanonicalResponse) -> Result<Value, TransformError> {
    let content = response
        .blocks
        .iter()
        .map(|block| match block {
            CanonicalResponseBlock::Text(text) => Ok(json!({
                "type": "text",
                "text": text,
            })),
            CanonicalResponseBlock::ToolCall {
                id,
                name,
                arguments,
            } => {
                if !arguments.is_object() {
                    return Err(TransformError::invalid_response(
                        "converted tool arguments are not an object",
                    ));
                }
                Ok(json!({
                    "type": "tool_use",
                    "id": id,
                    "name": name,
                    "input": arguments,
                }))
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    let usage = response.usage.unwrap_or_default();
    let uncached_input_tokens = usage.input_tokens.saturating_sub(
        usage
            .cached_input_tokens
            .saturating_add(usage.cache_creation_input_tokens),
    );
    Ok(json!({
        "id": response.id,
        "type": "message",
        "role": "assistant",
        "model": response.model,
        "content": content,
        "stop_reason": anthropic_stop_reason(response.stop_reason),
        "stop_sequence": null,
        "usage": {
            "input_tokens": uncached_input_tokens,
            "output_tokens": usage.output_tokens,
            "cache_read_input_tokens": usage.cached_input_tokens,
            "cache_creation_input_tokens": usage.cache_creation_input_tokens,
        }
    }))
}

fn encode_openai_responses_response(response: &CanonicalResponse) -> Result<Value, TransformError> {
    let mut output = Vec::new();
    let mut text_content = Vec::new();
    for block in &response.blocks {
        match block {
            CanonicalResponseBlock::Text(text) => text_content.push(json!({
                "type": "output_text",
                "text": text,
                "annotations": [],
            })),
            CanonicalResponseBlock::ToolCall {
                id,
                name,
                arguments,
            } => output.push(json!({
                "id": format!("fc_{id}"),
                "type": "function_call",
                "status": "completed",
                "call_id": id,
                "name": name,
                "arguments": serde_json::to_string(arguments).map_err(|_| {
                    TransformError::invalid_response("converted tool arguments could not be encoded")
                })?,
            })),
        }
    }
    if !text_content.is_empty() {
        output.insert(
            0,
            json!({
                "id": format!("msg_{}", response_id_suffix(&response.id)),
                "type": "message",
                "status": "completed",
                "role": "assistant",
                "content": text_content,
            }),
        );
    }
    let usage = response.usage.unwrap_or_default();
    Ok(json!({
        "id": response.id,
        "object": "response",
        "created_at": 0,
        "status": if response.stop_reason == CanonicalStopReason::Unknown {
            "incomplete"
        } else {
            "completed"
        },
        "model": response.model,
        "output": output,
        "parallel_tool_calls": true,
        "usage": {
            "input_tokens": usage.input_tokens,
            "input_tokens_details": {
                "cached_tokens": usage.cached_input_tokens,
            },
            "output_tokens": usage.output_tokens,
            "output_tokens_details": {
                "reasoning_tokens": 0,
            },
            "total_tokens": effective_total_tokens(usage),
        }
    }))
}

fn encode_openai_chat_response(response: &CanonicalResponse) -> Result<Value, TransformError> {
    let mut text = Vec::new();
    let mut tool_calls = Vec::new();
    for block in &response.blocks {
        match block {
            CanonicalResponseBlock::Text(value) => text.push(value.as_str()),
            CanonicalResponseBlock::ToolCall {
                id,
                name,
                arguments,
            } => tool_calls.push(json!({
                "id": id,
                "type": "function",
                "function": {
                    "name": name,
                    "arguments": serde_json::to_string(arguments).map_err(|_| {
                        TransformError::invalid_response(
                            "converted tool arguments could not be encoded",
                        )
                    })?,
                }
            })),
        }
    }
    let mut message = json!({
        "role": "assistant",
        "content": if text.is_empty() {
            Value::Null
        } else {
            Value::String(text.join(""))
        },
    });
    if !tool_calls.is_empty() {
        message["tool_calls"] = Value::Array(tool_calls);
    }
    let usage = response.usage.unwrap_or_default();
    Ok(json!({
        "id": response.id,
        "object": "chat.completion",
        "created": 0,
        "model": response.model,
        "choices": [{
            "index": 0,
            "message": message,
            "finish_reason": openai_finish_reason(response.stop_reason),
        }],
        "usage": {
            "prompt_tokens": usage.input_tokens,
            "completion_tokens": usage.output_tokens,
            "total_tokens": effective_total_tokens(usage),
            "prompt_tokens_details": {
                "cached_tokens": usage.cached_input_tokens,
            }
        }
    }))
}

fn encode_gemini_response(response: &CanonicalResponse) -> Result<Value, TransformError> {
    let parts = response
        .blocks
        .iter()
        .map(|block| match block {
            CanonicalResponseBlock::Text(text) => Ok(json!({"text": text})),
            CanonicalResponseBlock::ToolCall {
                id,
                name,
                arguments,
            } => {
                if !arguments.is_object() {
                    return Err(TransformError::invalid_response(
                        "converted tool arguments are not an object",
                    ));
                }
                Ok(json!({
                    "functionCall": {
                        "id": id,
                        "name": name,
                        "args": arguments,
                    }
                }))
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    let usage = response.usage.unwrap_or_default();
    Ok(json!({
        "responseId": response.id,
        "modelVersion": response.model,
        "candidates": [{
            "index": 0,
            "content": {
                "role": "model",
                "parts": parts,
            },
            "finishReason": gemini_finish_reason(response.stop_reason),
        }],
        "usageMetadata": {
            "promptTokenCount": usage.input_tokens,
            "candidatesTokenCount": usage.output_tokens,
            "totalTokenCount": effective_total_tokens(usage),
            "cachedContentTokenCount": usage.cached_input_tokens,
        }
    }))
}

const fn anthropic_stop_reason(reason: CanonicalStopReason) -> &'static str {
    match reason {
        CanonicalStopReason::EndTurn
        | CanonicalStopReason::ContentFilter
        | CanonicalStopReason::Unknown => "end_turn",
        CanonicalStopReason::MaxTokens => "max_tokens",
        CanonicalStopReason::ToolUse => "tool_use",
        CanonicalStopReason::StopSequence => "stop_sequence",
    }
}

const fn openai_finish_reason(reason: CanonicalStopReason) -> &'static str {
    match reason {
        CanonicalStopReason::EndTurn
        | CanonicalStopReason::StopSequence
        | CanonicalStopReason::Unknown => "stop",
        CanonicalStopReason::MaxTokens => "length",
        CanonicalStopReason::ToolUse => "tool_calls",
        CanonicalStopReason::ContentFilter => "content_filter",
    }
}

const fn gemini_finish_reason(reason: CanonicalStopReason) -> &'static str {
    match reason {
        CanonicalStopReason::EndTurn
        | CanonicalStopReason::StopSequence
        | CanonicalStopReason::ToolUse => "STOP",
        CanonicalStopReason::MaxTokens => "MAX_TOKENS",
        CanonicalStopReason::ContentFilter => "SAFETY",
        CanonicalStopReason::Unknown => "OTHER",
    }
}

const fn effective_total_tokens(usage: CanonicalUsage) -> u64 {
    if usage.total_tokens == 0 {
        usage.input_tokens.saturating_add(usage.output_tokens)
    } else {
        usage.total_tokens
    }
}

fn response_id_suffix(id: &str) -> String {
    let suffix = id
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(48)
        .collect::<String>();
    if suffix.is_empty() {
        "gateway".to_owned()
    } else {
        suffix
    }
}

fn request_object<'a>(
    value: &'a Value,
    context: &str,
) -> Result<&'a Map<String, Value>, TransformError> {
    value
        .as_object()
        .ok_or_else(|| TransformError::invalid_request(format!("{context} must be a JSON object")))
}

fn response_object<'a>(
    value: &'a Value,
    context: &str,
) -> Result<&'a Map<String, Value>, TransformError> {
    value
        .as_object()
        .ok_or_else(|| TransformError::invalid_response(format!("{context} is not a JSON object")))
}

fn required_request_array<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a [Value], TransformError> {
    object
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| TransformError::invalid_request(format!("{field} must be a JSON array")))
}

fn required_response_array<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a [Value], TransformError> {
    object
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| {
            TransformError::invalid_response(format!("upstream {field} is not a JSON array"))
        })
}

fn optional_array<'a>(
    value: Option<&'a Value>,
    field: &str,
) -> Result<Option<&'a [Value]>, TransformError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(values)) => Ok(Some(values.as_slice())),
        Some(_) => Err(TransformError::invalid_request(format!(
            "{field} must be a JSON array"
        ))),
    }
}

fn optional_response_array<'a>(
    value: Option<&'a Value>,
    field: &str,
) -> Result<Option<&'a [Value]>, TransformError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(values)) => Ok(Some(values.as_slice())),
        Some(_) => Err(TransformError::invalid_response(format!(
            "upstream {field} is not a JSON array"
        ))),
    }
}

fn required_request_string(
    object: &Map<String, Value>,
    field: &str,
) -> Result<String, TransformError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| TransformError::invalid_request(format!("{field} must be a string")))
}

fn required_response_string(
    object: &Map<String, Value>,
    field: &str,
) -> Result<String, TransformError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            TransformError::invalid_response(format!("upstream {field} is not a string"))
        })
}

fn optional_string(value: Option<&Value>, field: &str) -> Result<Option<String>, TransformError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(TransformError::invalid_request(format!(
            "{field} must be a string"
        ))),
    }
}

fn optional_response_string(
    value: Option<&Value>,
    field: &str,
) -> Result<Option<String>, TransformError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(TransformError::invalid_response(format!(
            "upstream {field} is not a string"
        ))),
    }
}

fn optional_u64(value: Option<&Value>, field: &str) -> Result<Option<u64>, TransformError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_u64().map(Some).ok_or_else(|| {
            TransformError::invalid_request(format!("{field} must be a non-negative integer"))
        }),
    }
}

fn response_u64(value: Option<&Value>, field: &str) -> Result<u64, TransformError> {
    match value {
        None | Some(Value::Null) => Ok(0),
        Some(value) => value.as_u64().ok_or_else(|| {
            TransformError::invalid_response(format!(
                "upstream {field} is not a non-negative integer"
            ))
        }),
    }
}

fn optional_number(value: Option<&Value>, field: &str) -> Result<Option<Value>, TransformError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value @ Value::Number(_)) => Ok(Some(value.clone())),
        Some(_) => Err(TransformError::invalid_request(format!(
            "{field} must be a number"
        ))),
    }
}

fn require_type(
    object: &Map<String, Value>,
    expected: &str,
    context: &str,
) -> Result<(), TransformError> {
    let actual = required_request_string(object, "type")?;
    if actual == expected {
        Ok(())
    } else {
        Err(TransformError::invalid_request(format!(
            "{context} type must be {expected:?}, got {actual:?}"
        )))
    }
}

fn require_object_schema(value: &Value, context: &str) -> Result<(), TransformError> {
    if value.is_object() {
        Ok(())
    } else {
        Err(TransformError::invalid_request(format!(
            "{context} must be a JSON object"
        )))
    }
}

fn empty_object_schema() -> Value {
    json!({"type": "object", "properties": {}})
}

fn parse_json_arguments(value: Option<&Value>, context: &str) -> Result<Value, TransformError> {
    match value {
        Some(Value::Object(object)) => Ok(Value::Object(object.clone())),
        Some(Value::String(arguments)) => serde_json::from_str::<Value>(arguments)
            .map_err(|_| TransformError::invalid_request(format!("{context} is not valid JSON")))
            .and_then(|value| {
                if value.is_object() {
                    Ok(value)
                } else {
                    Err(TransformError::invalid_request(format!(
                        "{context} must encode a JSON object"
                    )))
                }
            }),
        _ => Err(TransformError::invalid_request(format!(
            "{context} is required"
        ))),
    }
}

fn parse_response_json_arguments(
    value: Option<&Value>,
    context: &str,
) -> Result<Value, TransformError> {
    match value {
        Some(Value::Object(object)) => Ok(Value::Object(object.clone())),
        Some(Value::String(arguments)) => serde_json::from_str::<Value>(arguments)
            .map_err(|_| TransformError::invalid_response(format!("{context} is not valid JSON")))
            .and_then(|value| {
                if value.is_object() {
                    Ok(value)
                } else {
                    Err(TransformError::invalid_response(format!(
                        "{context} does not encode a JSON object"
                    )))
                }
            }),
        _ => Err(TransformError::invalid_response(format!(
            "{context} is missing"
        ))),
    }
}

fn normalize_tool_output(value: &Value) -> Result<Value, TransformError> {
    let Value::Array(blocks) = value else {
        return Ok(value.clone());
    };
    let mut text = Vec::with_capacity(blocks.len());
    for block in blocks {
        let block = request_object(block, "tool result content block")?;
        require_type(block, "text", "tool result content block")?;
        text.push(required_request_string(block, "text")?);
    }
    Ok(Value::String(text.join("\n")))
}

fn tool_output_string(value: &Value) -> Result<String, TransformError> {
    if let Some(text) = value.as_str() {
        return Ok(text.to_owned());
    }
    serde_json::to_string(value)
        .map_err(|_| TransformError::invalid_request("tool output could not be encoded"))
}

fn push_message(
    messages: &mut Vec<CanonicalMessage>,
    role: CanonicalRole,
    mut blocks: Vec<CanonicalRequestBlock>,
) {
    if let Some(last) = messages.last_mut()
        && last.role == role
    {
        last.blocks.append(&mut blocks);
    } else {
        messages.push(CanonicalMessage { role, blocks });
    }
}

fn resolve_tool_result_names(
    messages: &mut [CanonicalMessage],
    call_names: &HashMap<String, String>,
) -> Result<(), TransformError> {
    for message in messages {
        for block in &mut message.blocks {
            if let CanonicalRequestBlock::ToolResult { id, name, .. } = block
                && name.is_empty()
            {
                *name = call_names.get(id).cloned().ok_or_else(|| {
                    TransformError::invalid_request(format!(
                        "tool result references unknown call {id:?}"
                    ))
                })?;
            }
        }
    }
    Ok(())
}

fn parse_response_text_content(
    value: &Value,
    context: &str,
) -> Result<Vec<String>, TransformError> {
    if let Some(text) = value.as_str() {
        return Ok(vec![text.to_owned()]);
    }
    let array = value.as_array().ok_or_else(|| {
        TransformError::invalid_response(format!("{context} is not text or an array"))
    })?;
    array
        .iter()
        .map(|block| {
            let block = response_object(block, context)?;
            match required_response_string(block, "type")?.as_str() {
                "text" | "output_text" => required_response_string(block, "text"),
                other => Err(TransformError::invalid_response(format!(
                    "{context} block type {other:?} cannot be converted"
                ))),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use axum::http::{Method, Uri};
    use serde_json::{Value, json};

    use super::{
        TransformStage, prepare_protocol_request, prepare_protocol_request_for_account,
        validate_upstream_adapter,
    };
    use crate::gateway::{Protocol, RequestMetadata, RouteKind, classify_route};

    fn metadata(model: &str, stream: bool) -> RequestMetadata {
        RequestMetadata {
            model: Some(model.to_owned()),
            stream,
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    fn route(method: Method, path: &str) -> crate::gateway::GatewayRoute {
        let uri: Uri = path.parse().expect("test URI should parse");
        classify_route(&method, &uri).expect("test route should classify")
    }

    fn body_json(body: &[u8]) -> Value {
        serde_json::from_slice(body).expect("converted body should be JSON")
    }

    #[test]
    fn same_protocol_is_a_byte_for_byte_passthrough() {
        let route = route(Method::POST, "/v1/messages");
        let body = br#"{ \"intentionally\": \"not parsed on identity path\" }"#;

        let transformed = prepare_protocol_request(
            &route,
            "anthropic",
            &metadata("claude-sonnet-4-6", false),
            body,
        )
        .expect("same protocol should pass through");

        assert_eq!(transformed.route, route);
        assert_eq!(transformed.body, body);
        assert!(!transformed.bridge.requires_conversion());
        assert_eq!(
            transformed
                .bridge
                .transform_response(body)
                .expect("identity response should pass through"),
            body
        );
    }

    #[test]
    fn anthropic_messages_bridge_to_openai_responses_with_tools_and_usage() {
        let route = route(Method::POST, "/v1/messages");
        let request = json!({
            "model": "claude-sonnet-4-6",
            "max_tokens": 512,
            "system": [{"type": "text", "text": "Be precise."}],
            "messages": [
                {"role": "user", "content": "weather?"},
                {"role": "assistant", "content": [{
                    "type": "tool_use", "id": "call_weather", "name": "weather",
                    "input": {"city": "Shanghai"}
                }]},
                {"role": "user", "content": [{
                    "type": "tool_result", "tool_use_id": "call_weather", "content": "sunny"
                }]}
            ],
            "tools": [{
                "name": "weather", "description": "Weather lookup",
                "input_schema": {"type": "object", "properties": {"city": {"type": "string"}}}
            }],
            "tool_choice": {"type": "tool", "name": "weather"}
        });
        let transformed = prepare_protocol_request(
            &route,
            "openai",
            &metadata("claude-sonnet-4-6", false),
            &serde_json::to_vec(&request).expect("request should encode"),
        )
        .expect("Anthropic request should convert");
        let converted = body_json(&transformed.body);

        assert_eq!(transformed.route.protocol, Protocol::OpenAi);
        assert_eq!(transformed.route.kind, RouteKind::OpenAiResponses);
        assert_eq!(converted["instructions"], "Be precise.");
        assert_eq!(converted["tools"][0]["name"], "weather");
        assert_eq!(converted["tool_choice"]["name"], "weather");
        assert!(converted["input"].as_array().is_some_and(|items| {
            items
                .iter()
                .any(|item| item["type"] == "function_call" && item["call_id"] == "call_weather")
                && items.iter().any(|item| {
                    item["type"] == "function_call_output" && item["call_id"] == "call_weather"
                })
        }));

        let upstream = json!({
            "id": "resp_123",
            "object": "response",
            "status": "completed",
            "model": "gpt-5.4",
            "output": [
                {"type": "message", "role": "assistant", "content": [
                    {"type": "output_text", "text": "Calling weather", "annotations": []}
                ]},
                {"type": "function_call", "call_id": "call_next", "name": "weather",
                 "arguments": "{\"city\":\"Beijing\"}"}
            ],
            "usage": {
                "input_tokens": 12, "output_tokens": 4, "total_tokens": 16,
                "input_tokens_details": {"cached_tokens": 3}
            }
        });
        let downstream = transformed
            .bridge
            .transform_response(&serde_json::to_vec(&upstream).expect("response should encode"))
            .expect("OpenAI response should convert");
        let downstream = body_json(&downstream);

        assert_eq!(downstream["type"], "message");
        assert_eq!(downstream["stop_reason"], "tool_use");
        assert_eq!(downstream["content"][0]["text"], "Calling weather");
        assert_eq!(downstream["content"][1]["type"], "tool_use");
        assert_eq!(downstream["content"][1]["input"]["city"], "Beijing");
        assert_eq!(downstream["usage"]["input_tokens"], 9);
        assert_eq!(downstream["usage"]["cache_read_input_tokens"], 3);
    }

    #[test]
    fn openai_chat_bridge_to_gemini_preserves_tool_exchange() {
        let route = route(Method::POST, "/v1/chat/completions");
        let request = json!({
            "model": "gemini-2.5-pro",
            "messages": [
                {"role": "developer", "content": "Use tools."},
                {"role": "user", "content": "lookup"},
                {"role": "assistant", "content": null, "tool_calls": [{
                    "id": "call_1", "type": "function",
                    "function": {"name": "lookup", "arguments": "{\"q\":\"rust\"}"}
                }]},
                {"role": "tool", "tool_call_id": "call_1", "content": "result"}
            ],
            "tools": [{"type": "function", "function": {
                "name": "lookup", "parameters": {"type": "object"}
            }}]
        });
        let transformed = prepare_protocol_request(
            &route,
            "gemini",
            &metadata("gemini-2.5-pro", false),
            &serde_json::to_vec(&request).expect("request should encode"),
        )
        .expect("OpenAI chat request should convert");
        let converted = body_json(&transformed.body);

        assert_eq!(transformed.route.protocol, Protocol::Gemini);
        assert_eq!(
            transformed.route.upstream_path,
            "/v1beta/models/gemini-2.5-pro:generateContent"
        );
        assert_eq!(
            converted["systemInstruction"]["parts"][0]["text"],
            "Use tools."
        );
        assert!(converted["contents"].as_array().is_some_and(|contents| {
            contents.iter().any(|content| {
                content["parts"].as_array().is_some_and(|parts| {
                    parts.iter().any(|part| part.get("functionCall").is_some())
                })
            }) && contents.iter().any(|content| {
                content["parts"].as_array().is_some_and(|parts| {
                    parts
                        .iter()
                        .any(|part| part.get("functionResponse").is_some())
                })
            })
        }));

        let upstream = json!({
            "responseId": "gemini_123",
            "modelVersion": "gemini-2.5-pro",
            "candidates": [{
                "content": {"role": "model", "parts": [
                    {"text": "done"},
                    {"functionCall": {"id": "call_2", "name": "lookup", "args": {"q": "rust"}}}
                ]},
                "finishReason": "STOP"
            }],
            "usageMetadata": {
                "promptTokenCount": 7, "candidatesTokenCount": 2, "totalTokenCount": 9
            }
        });
        let downstream = transformed
            .bridge
            .transform_response(&serde_json::to_vec(&upstream).expect("response should encode"))
            .expect("Gemini response should convert");
        let downstream = body_json(&downstream);

        assert_eq!(downstream["object"], "chat.completion");
        assert_eq!(downstream["choices"][0]["message"]["content"], "done");
        assert_eq!(
            downstream["choices"][0]["message"]["tool_calls"][0]["function"]["name"],
            "lookup"
        );
        assert_eq!(downstream["usage"]["total_tokens"], 9);
    }

    #[test]
    fn gemini_bridge_to_anthropic_preserves_system_tools_and_usage() {
        let route = route(
            Method::POST,
            "/v1beta/models/claude-sonnet-4-6:generateContent",
        );
        let request = json!({
            "systemInstruction": {"parts": [{"text": "Be concise."}]},
            "contents": [{"role": "user", "parts": [{"text": "hello"}]}],
            "tools": [{"functionDeclarations": [{
                "name": "search", "description": "Search",
                "parameters": {"type": "object", "properties": {}}
            }]}],
            "generationConfig": {"maxOutputTokens": 100}
        });
        let transformed = prepare_protocol_request(
            &route,
            "anthropic",
            &metadata("claude-sonnet-4-6", false),
            &serde_json::to_vec(&request).expect("request should encode"),
        )
        .expect("Gemini request should convert");
        let converted = body_json(&transformed.body);

        assert_eq!(transformed.route.kind, RouteKind::AnthropicMessages);
        assert_eq!(converted["system"], "Be concise.");
        assert_eq!(converted["tools"][0]["name"], "search");
        assert_eq!(converted["max_tokens"], 100);

        let upstream = json!({
            "id": "msg_123", "type": "message", "role": "assistant",
            "model": "claude-sonnet-4-6",
            "content": [{"type": "text", "text": "hello"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 5, "output_tokens": 1,
                      "cache_read_input_tokens": 2, "cache_creation_input_tokens": 3}
        });
        let downstream = transformed
            .bridge
            .transform_response(&serde_json::to_vec(&upstream).expect("response should encode"))
            .expect("Anthropic response should convert");
        let downstream = body_json(&downstream);

        assert_eq!(
            downstream["candidates"][0]["content"]["parts"][0]["text"],
            "hello"
        );
        assert_eq!(downstream["usageMetadata"]["promptTokenCount"], 10);
        assert_eq!(downstream["usageMetadata"]["cachedContentTokenCount"], 2);
    }

    #[test]
    fn unsupported_paths_fail_closed_and_special_accounts_use_concrete_adapters() {
        let messages = route(Method::POST, "/v1/messages");
        let embeddings = route(Method::POST, "/v1/embeddings");
        let unsupported = prepare_protocol_request(
            &embeddings,
            "anthropic",
            &metadata("text-embedding-3-small", false),
            br#"{"model":"text-embedding-3-small","input":"x"}"#,
        )
        .expect_err("embeddings must not be sent to Anthropic");
        assert_eq!(unsupported.stage(), TransformStage::Unsupported);

        let antigravity = prepare_protocol_request(
            &messages,
            "antigravity",
            &metadata("claude-sonnet-4-6", false),
            br#"{"model":"claude-sonnet-4-6","messages":[]}"#,
        )
        .expect("Antigravity should convert Anthropic messages to Gemini");
        assert_eq!(antigravity.route.protocol, Protocol::Gemini);
        assert_eq!(antigravity.route.kind, RouteKind::GeminiGenerateContent);

        for (platform, account_type) in [
            ("openai", "oauth"),
            ("anthropic", "setup-token"),
            ("anthropic", "bedrock"),
            ("gemini", "service_account"),
            ("antigravity", "apikey"),
        ] {
            assert!(
                validate_upstream_adapter(platform, account_type).is_ok(),
                "{platform}/{account_type} must have a concrete adapter"
            );
        }
        assert!(validate_upstream_adapter("openai", "bedrock").is_err());
        assert!(validate_upstream_adapter("gemini", "setup-token").is_err());
        assert!(validate_upstream_adapter("grok", "oauth").is_ok());
        assert!(validate_upstream_adapter("openai", "apikey").is_ok());
        assert!(validate_upstream_adapter("gemini", "upstream").is_ok());
    }

    #[test]
    fn openai_chat_sse_converts_incrementally_to_anthropic_events() {
        let messages = route(Method::POST, "/v1/messages");
        let transformed = prepare_protocol_request_for_account(
            &messages,
            "openai",
            &metadata("gpt-5.4", true),
            br#"{"model":"gpt-5.4","stream":true,"max_tokens":64,"messages":[{"role":"user","content":"hi"}]}"#,
            false,
            false,
        )
        .expect("streaming request should convert");
        assert_eq!(transformed.route.kind, RouteKind::OpenAiChatCompletions);
        assert_eq!(body_json(&transformed.body)["stream"], true);

        let mut bridge = transformed.bridge.stream_bridge();
        let first = bridge
            .push(
                br#"data: {"id":"chatcmpl_1","model":"gpt-5.4","choices":[{"index":0,"delta":{"role":"assistant","content":"hel"},"finish_reason":null}]}

"#,
            )
            .expect("first event should convert");
        let second = bridge
            .push(
                br#"data: {"id":"chatcmpl_1","model":"gpt-5.4","choices":[{"index":0,"delta":{"content":"lo"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}

data: [DONE]

"#,
            )
            .expect("terminal events should convert");
        let mut output = String::from_utf8(first).expect("converted SSE should be UTF-8");
        output.push_str(&String::from_utf8(second).expect("converted SSE should be UTF-8"));

        assert!(output.contains("event: message_start"));
        assert!(output.contains("event: content_block_delta"));
        assert!(output.contains(r#""text":"hel""#));
        assert!(output.contains(r#""text":"lo""#));
        assert!(output.contains("event: message_stop"));
    }

    #[test]
    fn openai_capability_can_select_chat_completions_for_cross_protocol_requests() {
        let route = route(Method::POST, "/v1/messages");
        let request = br#"{
            "model":"third-party-model",
            "max_tokens":128,
            "messages":[{"role":"user","content":"hello"}]
        }"#;

        let transformed = prepare_protocol_request_for_account(
            &route,
            "openai",
            &metadata("third-party-model", false),
            request,
            false,
            false,
        )
        .expect("explicitly unsupported Responses API should use Chat Completions");
        let converted = body_json(&transformed.body);

        assert_eq!(transformed.route.kind, RouteKind::OpenAiChatCompletions);
        assert_eq!(transformed.route.upstream_path, "/v1/chat/completions");
        assert_eq!(converted["messages"][0]["role"], "user");
        assert_eq!(converted["messages"][0]["content"], "hello");
    }
}
