use std::{error::Error, fmt};

use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, header};
use url::Url;

use super::{
    request::RequestMetadata,
    response::ResponseMode,
    route::{GatewayRoute, Protocol},
};

/// Credential injected after all inbound authentication headers are discarded.
pub enum Credential {
    Bearer(String),
    ApiKey(String),
    None,
}

/// URL, headers, and framing required by an HTTP client adapter.
pub struct UpstreamRequestPlan {
    pub method: Method,
    pub url: Url,
    pub headers: HeaderMap,
    pub response_mode: ResponseMode,
}

/// A request plan that cannot be built safely.
#[derive(Debug)]
pub enum UpstreamBuildError {
    InvalidBaseUrl(url::ParseError),
    UnsupportedScheme,
    BaseUrlContainsCredentials,
    EmptyCredential,
    InvalidCredentialHeader,
}

impl fmt::Display for UpstreamBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBaseUrl(_) => formatter.write_str("upstream base URL is invalid"),
            Self::UnsupportedScheme => {
                formatter.write_str("upstream base URL must use HTTP or HTTPS")
            }
            Self::BaseUrlContainsCredentials => {
                formatter.write_str("upstream base URL must not contain credentials")
            }
            Self::EmptyCredential => formatter.write_str("upstream credential is empty"),
            Self::InvalidCredentialHeader => {
                formatter.write_str("upstream credential cannot be encoded as an HTTP header")
            }
        }
    }
}

impl Error for UpstreamBuildError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidBaseUrl(error) => Some(error),
            _ => None,
        }
    }
}

/// Builds a complete upstream request plan without retaining the request body.
///
/// # Errors
///
/// Returns an error when the base URL or credential cannot be represented
/// safely. Inbound authentication headers are never forwarded.
pub fn build_upstream_request(
    route: &GatewayRoute,
    metadata: &RequestMetadata,
    base_url: &str,
    credential: &Credential,
    inbound_headers: &HeaderMap,
) -> Result<UpstreamRequestPlan, UpstreamBuildError> {
    let response_mode = route.response_mode(metadata.stream);
    let url = build_upstream_url(base_url, route, response_mode)?;
    let headers = build_upstream_headers(
        route.protocol,
        &route.method,
        response_mode,
        credential,
        inbound_headers,
    )?;
    Ok(UpstreamRequestPlan {
        method: route.method.clone(),
        url,
        headers,
        response_mode,
    })
}

/// Joins a normalized route to a validated HTTP(S) base URL.
///
/// A base ending in `v1` or `v1beta` does not duplicate the matching route
/// prefix. Gemini streaming always uses `alt=sse`; arbitrary inbound query
/// parameters are intentionally not copied.
///
/// # Errors
///
/// Returns an error for malformed URLs, non-HTTP schemes, or URL credentials.
pub fn build_upstream_url(
    base_url: &str,
    route: &GatewayRoute,
    response_mode: ResponseMode,
) -> Result<Url, UpstreamBuildError> {
    let mut url = Url::parse(base_url).map_err(UpstreamBuildError::InvalidBaseUrl)?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(UpstreamBuildError::UnsupportedScheme);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(UpstreamBuildError::BaseUrlContainsCredentials);
    }

    let base_path = url.path().trim_matches('/');
    let route_path = route.upstream_path.trim_start_matches('/');
    let route_path = remove_duplicate_version(base_path, route_path);
    let path = if base_path.is_empty() {
        format!("/{route_path}")
    } else if route_path.is_empty() {
        format!("/{base_path}")
    } else {
        format!("/{base_path}/{route_path}")
    };
    url.set_path(&path);
    url.set_query(None);
    url.set_fragment(None);
    if route.protocol == Protocol::Gemini && response_mode == ResponseMode::ServerSentEvents {
        url.query_pairs_mut().append_pair("alt", "sse");
    }
    Ok(url)
}

/// Builds a minimal protocol-specific header set from a safe inbound allowlist.
///
/// # Errors
///
/// Returns an error when a configured credential is empty or is not a valid
/// HTTP header value.
pub fn build_upstream_headers(
    protocol: Protocol,
    method: &Method,
    response_mode: ResponseMode,
    credential: &Credential,
    inbound: &HeaderMap,
) -> Result<HeaderMap, UpstreamBuildError> {
    let mut headers = HeaderMap::new();
    copy_allowed_headers(protocol, inbound, &mut headers);

    headers.remove(header::AUTHORIZATION);
    headers.remove("x-api-key");
    headers.remove("x-goog-api-key");
    apply_credential(protocol, credential, &mut headers)?;

    if method != Method::GET && !headers.contains_key(header::CONTENT_TYPE) {
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
    }
    headers.insert(
        header::ACCEPT,
        HeaderValue::from_static(match response_mode {
            ResponseMode::Buffered => "application/json",
            ResponseMode::ServerSentEvents => "text/event-stream",
        }),
    );
    if protocol == Protocol::Anthropic && !headers.contains_key("anthropic-version") {
        headers.insert(
            HeaderName::from_static("anthropic-version"),
            HeaderValue::from_static("2023-06-01"),
        );
    }
    Ok(headers)
}

fn remove_duplicate_version<'a>(base_path: &str, route_path: &'a str) -> &'a str {
    let base_last = base_path.rsplit('/').next();
    let route_first = route_path.split('/').next();
    if base_last == route_first && matches!(base_last, Some("v1" | "v1beta")) {
        route_path.split_once('/').map_or("", |(_, rest)| rest)
    } else {
        route_path
    }
}

fn copy_allowed_headers(protocol: Protocol, inbound: &HeaderMap, output: &mut HeaderMap) {
    let names: &[&str] = match protocol {
        Protocol::Anthropic => &[
            "content-type",
            "anthropic-version",
            "anthropic-beta",
            "user-agent",
            "x-client-request-id",
        ],
        Protocol::OpenAi => &[
            "content-type",
            "idempotency-key",
            "openai-beta",
            "user-agent",
            "x-client-request-id",
            "x-codex-turn-state",
        ],
        Protocol::Gemini => &["content-type", "user-agent", "x-client-request-id"],
    };
    for name in names {
        for value in inbound.get_all(*name) {
            output.append(
                HeaderName::from_bytes(name.as_bytes()).expect("allowlisted header name is valid"),
                value.clone(),
            );
        }
    }
}

fn apply_credential(
    protocol: Protocol,
    credential: &Credential,
    headers: &mut HeaderMap,
) -> Result<(), UpstreamBuildError> {
    let (name, value) = match credential {
        Credential::None => return Ok(()),
        Credential::Bearer(token) => (header::AUTHORIZATION, credential_value("Bearer ", token)?),
        Credential::ApiKey(token) => {
            let name = match protocol {
                Protocol::Anthropic => HeaderName::from_static("x-api-key"),
                Protocol::OpenAi => header::AUTHORIZATION,
                Protocol::Gemini => HeaderName::from_static("x-goog-api-key"),
            };
            let prefix = if protocol == Protocol::OpenAi {
                "Bearer "
            } else {
                ""
            };
            (name, credential_value(prefix, token)?)
        }
    };
    headers.insert(name, value);
    Ok(())
}

fn credential_value(prefix: &str, secret: &str) -> Result<HeaderValue, UpstreamBuildError> {
    if secret.trim().is_empty() {
        return Err(UpstreamBuildError::EmptyCredential);
    }
    HeaderValue::from_str(&format!("{prefix}{secret}"))
        .map_err(|_| UpstreamBuildError::InvalidCredentialHeader)
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, Method, Uri, header};

    use super::{Credential, build_upstream_request, build_upstream_url};
    use crate::gateway::{RequestMetadata, ResponseMode, classify_route};

    #[test]
    fn avoids_duplicate_version_prefixes() {
        let uri: Uri = "/v1/responses".parse().expect("URI should parse");
        let route = classify_route(&Method::POST, &uri).expect("route should exist");
        let url = build_upstream_url(
            "https://proxy.example/openai/v1/",
            &route,
            ResponseMode::Buffered,
        )
        .expect("URL should build");

        assert_eq!(url.as_str(), "https://proxy.example/openai/v1/responses");
    }

    #[test]
    fn gemini_stream_adds_sse_query_and_replaces_inbound_auth() {
        let uri: Uri = "/v1beta/models/gemini-2.5-pro:streamGenerateContent"
            .parse()
            .expect("URI should parse");
        let route = classify_route(&Method::POST, &uri).expect("route should exist");
        let metadata = RequestMetadata {
            model: Some("gemini-2.5-pro".to_owned()),
            stream: true,
        };
        let mut inbound = HeaderMap::new();
        inbound.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer inbound"),
        );
        inbound.insert("x-goog-api-key", HeaderValue::from_static("inbound"));
        let plan = build_upstream_request(
            &route,
            &metadata,
            "https://generativelanguage.googleapis.com",
            &Credential::ApiKey("upstream-secret".to_owned()),
            &inbound,
        )
        .expect("request plan should build");

        assert_eq!(
            plan.url.as_str(),
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:streamGenerateContent?alt=sse"
        );
        assert_eq!(plan.headers["x-goog-api-key"], "upstream-secret");
        assert!(!plan.headers.contains_key(header::AUTHORIZATION));
        assert_eq!(plan.headers[header::ACCEPT], "text/event-stream");
    }

    #[test]
    fn anthropic_headers_have_version_and_do_not_copy_cookies() {
        let uri: Uri = "/v1/messages".parse().expect("URI should parse");
        let route = classify_route(&Method::POST, &uri).expect("route should exist");
        let metadata = RequestMetadata {
            model: Some("claude-sonnet-4-5".to_owned()),
            stream: false,
        };
        let mut inbound = HeaderMap::new();
        inbound.insert(header::COOKIE, HeaderValue::from_static("session=private"));
        inbound.insert(
            "anthropic-beta",
            HeaderValue::from_static("interleaved-thinking-2025-05-14"),
        );
        let plan = build_upstream_request(
            &route,
            &metadata,
            "https://api.anthropic.com",
            &Credential::ApiKey("sk-ant-test".to_owned()),
            &inbound,
        )
        .expect("request plan should build");

        assert_eq!(plan.headers["x-api-key"], "sk-ant-test");
        assert_eq!(plan.headers["anthropic-version"], "2023-06-01");
        assert!(!plan.headers.contains_key(header::COOKIE));
    }
}
