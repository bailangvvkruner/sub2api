use std::{error::Error, fmt};

use serde_json::Value;

use super::route::{GatewayRoute, RouteKind};

/// Model and response framing extracted from an inbound JSON request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestMetadata {
    pub model: Option<String>,
    pub stream: bool,
}

/// A request body that cannot be safely forwarded.
#[derive(Debug)]
pub enum RequestBodyError {
    Empty,
    InvalidJson(serde_json::Error),
    ExpectedObject,
    InvalidStreamFlag,
    MissingModel,
}

impl fmt::Display for RequestBodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("request body is empty"),
            Self::InvalidJson(_) => formatter.write_str("request body is not valid JSON"),
            Self::ExpectedObject => formatter.write_str("request body must be a JSON object"),
            Self::InvalidStreamFlag => formatter.write_str("stream must be a boolean"),
            Self::MissingModel => formatter.write_str("request does not identify a model"),
        }
    }
}

impl Error for RequestBodyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidJson(error) => Some(error),
            _ => None,
        }
    }
}

/// Inspects a request body without mutating or retaining the original bytes.
///
/// Gemini native routes take the model and streaming mode from the URL. Other
/// generation routes require a non-empty top-level `model` string.
///
/// # Errors
///
/// Returns an error for a missing required body, malformed JSON, a non-object
/// root, a non-boolean `stream` field, or a missing model.
pub fn inspect_request(
    route: &GatewayRoute,
    body: &[u8],
) -> Result<RequestMetadata, RequestBodyError> {
    if body.is_empty() {
        if route.kind.requires_body() {
            return Err(RequestBodyError::Empty);
        }
        return Ok(RequestMetadata {
            model: route.model_from_path.clone(),
            stream: false,
        });
    }

    // Image edits commonly use multipart/form-data. The model is optional and
    // parsing the multipart body is unnecessary for account selection.
    if route.kind == RouteKind::OpenAiImageEdits {
        return Ok(RequestMetadata {
            model: None,
            stream: false,
        });
    }

    let value: Value = serde_json::from_slice(body).map_err(RequestBodyError::InvalidJson)?;
    let object = value.as_object().ok_or(RequestBodyError::ExpectedObject)?;
    let body_model = object
        .get("model")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|model| !model.is_empty())
        .map(ToOwned::to_owned);
    let model = route.model_from_path.clone().or(body_model);

    let body_stream = match object.get("stream") {
        Some(Value::Bool(stream)) => *stream,
        Some(_) => return Err(RequestBodyError::InvalidStreamFlag),
        None => false,
    };
    let stream = match route.kind {
        RouteKind::GeminiStreamGenerateContent => true,
        RouteKind::OpenAiResponsesCompact
        | RouteKind::AnthropicCountTokens
        | RouteKind::GeminiCountTokens => false,
        kind if kind.allows_body_stream_flag() => body_stream,
        _ => false,
    };

    if route.kind.requires_body()
        && model.is_none()
        && !matches!(
            route.kind,
            RouteKind::OpenAiImageGenerations
                | RouteKind::OpenAiImageEdits
                | RouteKind::OpenAiVideoGenerations
        )
    {
        return Err(RequestBodyError::MissingModel);
    }

    Ok(RequestMetadata { model, stream })
}

#[cfg(test)]
mod tests {
    use axum::http::{Method, Uri};

    use super::{RequestBodyError, inspect_request};
    use crate::gateway::route::classify_route;

    #[test]
    fn reads_openai_model_and_stream_flag() {
        let uri: Uri = "/v1/responses".parse().expect("URI should parse");
        let route = classify_route(&Method::POST, &uri).expect("route should exist");
        let metadata = inspect_request(&route, br#"{"model":"gpt-5","stream":true}"#)
            .expect("request should be valid");

        assert_eq!(metadata.model.as_deref(), Some("gpt-5"));
        assert!(metadata.stream);
    }

    #[test]
    fn gemini_route_is_authoritative_for_model_and_streaming() {
        let uri: Uri = "/v1beta/models/gemini-2.5-pro:streamGenerateContent"
            .parse()
            .expect("URI should parse");
        let route = classify_route(&Method::POST, &uri).expect("route should exist");
        let metadata = inspect_request(&route, br#"{"model":"ignored","stream":false}"#)
            .expect("request should be valid");

        assert_eq!(metadata.model.as_deref(), Some("gemini-2.5-pro"));
        assert!(metadata.stream);
    }

    #[test]
    fn gemini_generate_action_ignores_body_stream_flag() {
        let uri: Uri = "/v1beta/models/gemini-2.5-pro:generateContent"
            .parse()
            .expect("URI should parse");
        let route = classify_route(&Method::POST, &uri).expect("route should exist");
        let metadata =
            inspect_request(&route, br#"{"stream":true}"#).expect("request should be valid");

        assert!(!metadata.stream);
    }

    #[test]
    fn refuses_ambiguous_stream_flags_and_missing_models() {
        let uri: Uri = "/v1/messages".parse().expect("URI should parse");
        let route = classify_route(&Method::POST, &uri).expect("route should exist");

        assert!(matches!(
            inspect_request(&route, br#"{"model":"claude","stream":"yes"}"#),
            Err(RequestBodyError::InvalidStreamFlag)
        ));
        assert!(matches!(
            inspect_request(&route, br#"{"messages":[]}"#),
            Err(RequestBodyError::MissingModel)
        ));
    }
}
