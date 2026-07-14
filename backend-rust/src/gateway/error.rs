use std::fmt;

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::route::{Protocol, RouteKind};

/// Stable gateway error categories shared by all wire protocols.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayErrorKind {
    InvalidRequest,
    Authentication,
    Permission,
    NotFound,
    RateLimit,
    Upstream,
    Unavailable,
    Internal,
}

/// A sanitized error that can be rendered for any supported client protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayError {
    pub kind: GatewayErrorKind,
    pub message: String,
    pub upstream_status: Option<StatusCode>,
    pub request_id: Option<String>,
}

impl GatewayError {
    /// Creates a local gateway error without upstream response metadata.
    #[must_use]
    pub fn new(kind: GatewayErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            upstream_status: None,
            request_id: None,
        }
    }

    /// Converts an upstream HTTP error while only retaining a structured JSON
    /// message. HTML and arbitrary raw response bodies are not reflected.
    #[must_use]
    pub fn from_upstream(status: StatusCode, body: &[u8], request_id: Option<&str>) -> Self {
        let kind = kind_from_status(status);
        let message = extract_error_message(body)
            .unwrap_or_else(|| format!("Upstream returned HTTP {}", status.as_u16()));
        Self {
            kind,
            message,
            upstream_status: Some(status),
            request_id: request_id
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
        }
    }

    /// Returns the downstream HTTP status. Recognized client errors are
    /// preserved; upstream 5xx responses are normalized to `502`.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        if let Some(status) = self.upstream_status.filter(|status| {
            matches!(
                status.as_u16(),
                400 | 401 | 403 | 404 | 409 | 413 | 422 | 429
            )
        }) {
            return status;
        }
        match self.kind {
            GatewayErrorKind::InvalidRequest => StatusCode::BAD_REQUEST,
            GatewayErrorKind::Authentication => StatusCode::UNAUTHORIZED,
            GatewayErrorKind::Permission => StatusCode::FORBIDDEN,
            GatewayErrorKind::NotFound => StatusCode::NOT_FOUND,
            GatewayErrorKind::RateLimit => StatusCode::TOO_MANY_REQUESTS,
            GatewayErrorKind::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            GatewayErrorKind::Upstream => StatusCode::BAD_GATEWAY,
            GatewayErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Renders the non-streaming error envelope expected by a client protocol.
    #[must_use]
    pub fn json(&self, protocol: Protocol) -> Value {
        match protocol {
            Protocol::Anthropic => {
                let mut body = json!({
                    "type": "error",
                    "error": {
                        "type": self.anthropic_type(),
                        "message": self.message,
                    }
                });
                if let Some(request_id) = &self.request_id {
                    body["request_id"] = Value::String(request_id.clone());
                }
                body
            }
            Protocol::OpenAi => json!({
                "error": {
                    "message": self.message,
                    "type": self.openai_type(),
                    "param": null,
                    "code": self.openai_code(),
                }
            }),
            Protocol::Gemini => json!({
                "error": {
                    "code": self.status().as_u16(),
                    "message": self.message,
                    "status": self.google_status(),
                }
            }),
        }
    }

    /// Renders a terminal SSE error event for an already-started response.
    #[must_use]
    pub fn sse(&self, route: RouteKind) -> String {
        match route {
            RouteKind::OpenAiResponses | RouteKind::OpenAiResponsesCompact => {
                let event = json!({
                    "type": "response.failed",
                    "response": {
                        "id": self.response_id(),
                        "object": "response",
                        "status": "failed",
                        "output": [],
                        "error": {
                            "code": self.openai_code(),
                            "message": self.message,
                        }
                    }
                });
                format!("event: response.failed\ndata: {event}\n\n")
            }
            RouteKind::OpenAiChatCompletions => {
                format!("data: {}\n\ndata: [DONE]\n\n", self.json(Protocol::OpenAi))
            }
            RouteKind::OpenAiEmbeddings
            | RouteKind::OpenAiImageGenerations
            | RouteKind::OpenAiImageEdits
            | RouteKind::OpenAiVideoGenerations
            | RouteKind::OpenAiVideoStatus
            | RouteKind::OpenAiModels => {
                format!("data: {}\n\n", self.json(Protocol::OpenAi))
            }
            RouteKind::AnthropicMessages | RouteKind::AnthropicCountTokens => {
                format!("event: error\ndata: {}\n\n", self.json(Protocol::Anthropic))
            }
            RouteKind::GeminiGenerateContent
            | RouteKind::GeminiStreamGenerateContent
            | RouteKind::GeminiCountTokens
            | RouteKind::GeminiListModels
            | RouteKind::GeminiGetModel => {
                format!("data: {}\n\n", self.json(Protocol::Gemini))
            }
        }
    }

    fn anthropic_type(&self) -> &'static str {
        match self.kind {
            GatewayErrorKind::InvalidRequest => "invalid_request_error",
            GatewayErrorKind::Authentication => "authentication_error",
            GatewayErrorKind::Permission => "permission_error",
            GatewayErrorKind::NotFound => "not_found_error",
            GatewayErrorKind::RateLimit => "rate_limit_error",
            GatewayErrorKind::Upstream
            | GatewayErrorKind::Unavailable
            | GatewayErrorKind::Internal => "api_error",
        }
    }

    fn openai_type(&self) -> &'static str {
        match self.kind {
            GatewayErrorKind::InvalidRequest => "invalid_request_error",
            GatewayErrorKind::Authentication => "authentication_error",
            GatewayErrorKind::Permission => "permission_error",
            GatewayErrorKind::NotFound => "not_found_error",
            GatewayErrorKind::RateLimit => "rate_limit_error",
            GatewayErrorKind::Upstream | GatewayErrorKind::Unavailable => "upstream_error",
            GatewayErrorKind::Internal => "server_error",
        }
    }

    fn openai_code(&self) -> &'static str {
        match self.kind {
            GatewayErrorKind::InvalidRequest => "invalid_request",
            GatewayErrorKind::Authentication => "authentication_failed",
            GatewayErrorKind::Permission => "permission_denied",
            GatewayErrorKind::NotFound => "not_found",
            GatewayErrorKind::RateLimit => "rate_limit_exceeded",
            GatewayErrorKind::Upstream => "upstream_error",
            GatewayErrorKind::Unavailable => "service_unavailable",
            GatewayErrorKind::Internal => "server_error",
        }
    }

    fn google_status(&self) -> &'static str {
        match self.kind {
            GatewayErrorKind::InvalidRequest => "INVALID_ARGUMENT",
            GatewayErrorKind::Authentication => "UNAUTHENTICATED",
            GatewayErrorKind::Permission => "PERMISSION_DENIED",
            GatewayErrorKind::NotFound => "NOT_FOUND",
            GatewayErrorKind::RateLimit => "RESOURCE_EXHAUSTED",
            GatewayErrorKind::Unavailable => "UNAVAILABLE",
            GatewayErrorKind::Upstream | GatewayErrorKind::Internal => "INTERNAL",
        }
    }

    fn response_id(&self) -> String {
        let suffix = self
            .request_id
            .as_deref()
            .unwrap_or("gateway_error")
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect::<String>();
        format!("resp_{suffix}")
    }
}

impl fmt::Display for GatewayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.message)
    }
}

fn kind_from_status(status: StatusCode) -> GatewayErrorKind {
    match status {
        StatusCode::BAD_REQUEST
        | StatusCode::CONFLICT
        | StatusCode::PAYLOAD_TOO_LARGE
        | StatusCode::UNPROCESSABLE_ENTITY => GatewayErrorKind::InvalidRequest,
        StatusCode::UNAUTHORIZED => GatewayErrorKind::Authentication,
        StatusCode::FORBIDDEN => GatewayErrorKind::Permission,
        StatusCode::NOT_FOUND => GatewayErrorKind::NotFound,
        StatusCode::TOO_MANY_REQUESTS => GatewayErrorKind::RateLimit,
        StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT => {
            GatewayErrorKind::Unavailable
        }
        _ => GatewayErrorKind::Upstream,
    }
}

fn extract_error_message(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    [
        value.pointer("/error/message"),
        value.pointer("/response/error/message"),
        value.get("message"),
        value.get("detail"),
    ]
    .into_iter()
    .flatten()
    .find_map(Value::as_str)
    .map(str::trim)
    .filter(|message| !message.is_empty())
    .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;

    use super::{GatewayError, GatewayErrorKind};
    use crate::gateway::route::{Protocol, RouteKind};

    #[test]
    fn maps_rate_limit_to_each_protocol() {
        let error = GatewayError::from_upstream(
            StatusCode::TOO_MANY_REQUESTS,
            br#"{"error":{"message":"slow down"}}"#,
            Some("req-123"),
        );

        assert_eq!(error.kind, GatewayErrorKind::RateLimit);
        assert_eq!(error.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            error.json(Protocol::Anthropic)["error"]["type"],
            "rate_limit_error"
        );
        assert_eq!(
            error.json(Protocol::OpenAi)["error"]["code"],
            "rate_limit_exceeded"
        );
        assert_eq!(
            error.json(Protocol::Gemini)["error"]["status"],
            "RESOURCE_EXHAUSTED"
        );
    }

    #[test]
    fn does_not_reflect_non_json_upstream_bodies() {
        let error = GatewayError::from_upstream(
            StatusCode::BAD_GATEWAY,
            b"<html>private proxy diagnostics</html>",
            None,
        );

        assert_eq!(error.message, "Upstream returned HTTP 502");
        assert_eq!(error.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn responses_stream_ends_with_protocol_terminal_event() {
        let error = GatewayError::new(GatewayErrorKind::Unavailable, "try another account");
        let frame = error.sse(RouteKind::OpenAiResponses);

        assert!(frame.starts_with("event: response.failed\n"));
        assert!(frame.contains("\"type\":\"response.failed\""));
        assert!(frame.ends_with("\n\n"));
    }
}
