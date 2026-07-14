use axum::http::{Method, Uri};

use super::response::ResponseMode;

/// Public wire protocol used by an inbound gateway route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    Anthropic,
    OpenAi,
    Gemini,
}

/// Semantic operation represented by a supported route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteKind {
    AnthropicMessages,
    AnthropicCountTokens,
    OpenAiResponses,
    OpenAiResponsesCompact,
    OpenAiChatCompletions,
    OpenAiEmbeddings,
    OpenAiImageGenerations,
    OpenAiImageEdits,
    OpenAiVideoGenerations,
    OpenAiVideoStatus,
    OpenAiModels,
    GeminiGenerateContent,
    GeminiStreamGenerateContent,
    GeminiCountTokens,
    GeminiListModels,
    GeminiGetModel,
}

impl RouteKind {
    /// Returns whether a request body is required by this operation.
    #[must_use]
    pub const fn requires_body(self) -> bool {
        !matches!(
            self,
            Self::OpenAiModels
                | Self::OpenAiVideoStatus
                | Self::GeminiListModels
                | Self::GeminiGetModel
        )
    }

    /// Returns whether `stream: true` is meaningful for this operation.
    #[must_use]
    pub const fn allows_body_stream_flag(self) -> bool {
        matches!(
            self,
            Self::AnthropicMessages | Self::OpenAiResponses | Self::OpenAiChatCompletions
        )
    }
}

/// A normalized route ready for request inspection and upstream planning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayRoute {
    pub protocol: Protocol,
    pub kind: RouteKind,
    pub method: Method,
    pub upstream_path: String,
    pub model_from_path: Option<String>,
}

impl GatewayRoute {
    /// Resolves the expected response framing for this request.
    #[must_use]
    pub const fn response_mode(&self, body_requests_stream: bool) -> ResponseMode {
        if matches!(self.kind, RouteKind::GeminiStreamGenerateContent)
            || (body_requests_stream && self.kind.allows_body_stream_flag())
        {
            ResponseMode::ServerSentEvents
        } else {
            ResponseMode::Buffered
        }
    }
}

/// Classifies a supported Anthropic, `OpenAI`, or Gemini HTTP route.
///
/// Aliases are normalized to the public upstream paths. Unknown methods,
/// malformed Gemini actions, and unported routes return `None`.
#[must_use]
pub fn classify_route(method: &Method, uri: &Uri) -> Option<GatewayRoute> {
    let path = normalized_path(uri.path());
    if method == Method::POST {
        return classify_post(method, path);
    }
    if method == Method::GET {
        return classify_get(method, path);
    }
    None
}

fn classify_post(method: &Method, path: &str) -> Option<GatewayRoute> {
    if let Some((protocol, kind, upstream_path)) = classify_known_post(path) {
        return Some(route(protocol, kind, method, upstream_path, None));
    }

    if let Some(subpath) = response_subpath(path) {
        return Some(route(
            Protocol::OpenAi,
            RouteKind::OpenAiResponses,
            method,
            &format!("/v1/responses/{subpath}"),
            None,
        ));
    }

    let (model, action) = parse_gemini_model_action(path)?;
    let (kind, response_path) = match action {
        "generateContent" => (
            RouteKind::GeminiGenerateContent,
            format!("/v1beta/models/{model}:generateContent"),
        ),
        "streamGenerateContent" => (
            RouteKind::GeminiStreamGenerateContent,
            format!("/v1beta/models/{model}:streamGenerateContent"),
        ),
        "countTokens" => (
            RouteKind::GeminiCountTokens,
            format!("/v1beta/models/{model}:countTokens"),
        ),
        _ => return None,
    };
    Some(route(
        Protocol::Gemini,
        kind,
        method,
        &response_path,
        Some(model.to_owned()),
    ))
}

fn classify_known_post(path: &str) -> Option<(Protocol, RouteKind, &'static str)> {
    if matches_any(
        path,
        &[
            "/v1/messages",
            "/messages",
            "/anthropic/v1/messages",
            "/antigravity/v1/messages",
        ],
    ) {
        Some((
            Protocol::Anthropic,
            RouteKind::AnthropicMessages,
            "/v1/messages",
        ))
    } else if matches_any(
        path,
        &[
            "/v1/messages/count_tokens",
            "/messages/count_tokens",
            "/anthropic/v1/messages/count_tokens",
            "/antigravity/v1/messages/count_tokens",
        ],
    ) {
        Some((
            Protocol::Anthropic,
            RouteKind::AnthropicCountTokens,
            "/v1/messages/count_tokens",
        ))
    } else if matches_any(
        path,
        &[
            "/v1/responses/compact",
            "/responses/compact",
            "/openai/v1/responses/compact",
            "/backend-api/codex/responses/compact",
        ],
    ) {
        Some((
            Protocol::OpenAi,
            RouteKind::OpenAiResponsesCompact,
            "/v1/responses/compact",
        ))
    } else if matches_any(
        path,
        &[
            "/v1/responses",
            "/responses",
            "/openai/v1/responses",
            "/backend-api/codex/responses",
        ],
    ) {
        Some((
            Protocol::OpenAi,
            RouteKind::OpenAiResponses,
            "/v1/responses",
        ))
    } else if matches_any(
        path,
        &[
            "/v1/chat/completions",
            "/chat/completions",
            "/openai/v1/chat/completions",
        ],
    ) {
        Some((
            Protocol::OpenAi,
            RouteKind::OpenAiChatCompletions,
            "/v1/chat/completions",
        ))
    } else if matches_any(path, &["/v1/embeddings", "/embeddings"]) {
        Some((
            Protocol::OpenAi,
            RouteKind::OpenAiEmbeddings,
            "/v1/embeddings",
        ))
    } else if matches_any(path, &["/v1/images/generations", "/images/generations"]) {
        Some((
            Protocol::OpenAi,
            RouteKind::OpenAiImageGenerations,
            "/v1/images/generations",
        ))
    } else if matches_any(path, &["/v1/images/edits", "/images/edits"]) {
        Some((
            Protocol::OpenAi,
            RouteKind::OpenAiImageEdits,
            "/v1/images/edits",
        ))
    } else if matches_any(path, &["/v1/videos/generations", "/videos/generations"]) {
        Some((
            Protocol::OpenAi,
            RouteKind::OpenAiVideoGenerations,
            "/v1/videos/generations",
        ))
    } else {
        None
    }
}

fn classify_get(method: &Method, path: &str) -> Option<GatewayRoute> {
    if matches_any(
        path,
        &[
            "/v1/models",
            "/models",
            "/openai/v1/models",
            "/backend-api/codex/models",
            "/antigravity/models",
            "/antigravity/v1/models",
        ],
    ) {
        return Some(route(
            Protocol::OpenAi,
            RouteKind::OpenAiModels,
            method,
            "/v1/models",
            None,
        ));
    }
    if let Some(request_id) = video_request_id(path) {
        return Some(route(
            Protocol::OpenAi,
            RouteKind::OpenAiVideoStatus,
            method,
            &format!("/v1/videos/{request_id}"),
            None,
        ));
    }
    if matches_any(
        path,
        &[
            "/v1beta/models",
            "/gemini/v1beta/models",
            "/antigravity/v1beta/models",
        ],
    ) {
        return Some(route(
            Protocol::Gemini,
            RouteKind::GeminiListModels,
            method,
            "/v1beta/models",
            None,
        ));
    }
    let model = parse_gemini_get_model(path)?;
    Some(route(
        Protocol::Gemini,
        RouteKind::GeminiGetModel,
        method,
        &format!("/v1beta/models/{model}"),
        Some(model.to_owned()),
    ))
}

fn route(
    protocol: Protocol,
    kind: RouteKind,
    method: &Method,
    upstream_path: &str,
    model_from_path: Option<String>,
) -> GatewayRoute {
    GatewayRoute {
        protocol,
        kind,
        method: method.clone(),
        upstream_path: upstream_path.to_owned(),
        model_from_path,
    }
}

fn normalized_path(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() { "/" } else { trimmed }
}

fn matches_any(path: &str, candidates: &[&str]) -> bool {
    candidates.contains(&path)
}

fn parse_gemini_model_action(path: &str) -> Option<(&str, &str)> {
    let remainder = strip_gemini_models_prefix(path)?;
    let (model, action) = remainder.split_once(':')?;
    valid_model(model).then_some((model, action))
}

fn parse_gemini_get_model(path: &str) -> Option<&str> {
    let model = strip_gemini_models_prefix(path)?;
    (valid_model(model) && !model.contains(':')).then_some(model)
}

fn strip_gemini_models_prefix(path: &str) -> Option<&str> {
    [
        "/v1beta/models/",
        "/gemini/v1beta/models/",
        "/antigravity/v1beta/models/",
    ]
    .into_iter()
    .find_map(|prefix| path.strip_prefix(prefix))
}

fn response_subpath(path: &str) -> Option<&str> {
    [
        "/v1/responses/",
        "/responses/",
        "/backend-api/codex/responses/",
    ]
    .into_iter()
    .find_map(|prefix| path.strip_prefix(prefix))
    .filter(|subpath| valid_subpath(subpath))
}

fn video_request_id(path: &str) -> Option<&str> {
    ["/v1/videos/", "/videos/"]
        .into_iter()
        .find_map(|prefix| path.strip_prefix(prefix))
        .filter(|request_id| valid_path_segment(request_id))
}

fn valid_subpath(path: &str) -> bool {
    !path.is_empty()
        && path.split('/').all(valid_path_segment)
        && !path.split('/').any(|segment| matches!(segment, "." | ".."))
}

fn valid_path_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_model(model: &str) -> bool {
    !model.is_empty()
        && !model.contains('/')
        && model
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::{Protocol, RouteKind, classify_route};
    use axum::http::{Method, Uri};

    #[test]
    fn normalizes_openai_responses_aliases() {
        let uri: Uri = "/backend-api/codex/responses/compact"
            .parse()
            .expect("URI should parse");
        let route = classify_route(&Method::POST, &uri).expect("route should be supported");

        assert_eq!(route.protocol, Protocol::OpenAi);
        assert_eq!(route.kind, RouteKind::OpenAiResponsesCompact);
        assert_eq!(route.upstream_path, "/v1/responses/compact");
    }

    #[test]
    fn extracts_gemini_model_and_stream_action() {
        let uri: Uri = "/v1beta/models/gemini-2.5-pro:streamGenerateContent?alt=sse"
            .parse()
            .expect("URI should parse");
        let route = classify_route(&Method::POST, &uri).expect("route should be supported");

        assert_eq!(route.protocol, Protocol::Gemini);
        assert_eq!(route.kind, RouteKind::GeminiStreamGenerateContent);
        assert_eq!(route.model_from_path.as_deref(), Some("gemini-2.5-pro"));
    }

    #[test]
    fn rejects_unknown_methods_and_gemini_actions() {
        let messages: Uri = "/v1/messages".parse().expect("URI should parse");
        assert!(classify_route(&Method::GET, &messages).is_none());

        let unknown: Uri = "/v1beta/models/gemini-2.5-pro:delete"
            .parse()
            .expect("URI should parse");
        assert!(classify_route(&Method::POST, &unknown).is_none());
    }
}
