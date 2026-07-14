use std::{error::Error, fmt};

use axum::http::HeaderMap;

const AUTHORIZATION: &str = "authorization";
const X_API_KEY: &str = "x-api-key";
const X_GOOG_API_KEY: &str = "x-goog-api-key";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiKeySource {
    AuthorizationBearer,
    ApiKeyHeader,
    GoogleApiKeyHeader,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtractedApiKey {
    pub key: String,
    pub source: ApiKeySource,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialError {
    AuthorizationRequired,
    InvalidAuthorizationHeader,
    EmptyBearerToken,
    ApiKeyInQueryDeprecated,
    ApiKeyRequired,
    HeaderIsNotUtf8(&'static str),
}

impl fmt::Display for CredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthorizationRequired => formatter.write_str("Authorization header is required"),
            Self::InvalidAuthorizationHeader => {
                formatter.write_str("Authorization header must use the Bearer scheme")
            }
            Self::EmptyBearerToken => formatter.write_str("Bearer token cannot be empty"),
            Self::ApiKeyInQueryDeprecated => {
                formatter.write_str("API keys in query parameters are deprecated")
            }
            Self::ApiKeyRequired => formatter.write_str("API key is required"),
            Self::HeaderIsNotUtf8(name) => write!(formatter, "{name} header is not valid UTF-8"),
        }
    }
}

impl Error for CredentialError {}

/// Extracts a mandatory Bearer token for user JWT authentication.
/// Extracts a required JWT bearer token.
///
/// # Errors
///
/// Returns an error when the authorization header is missing, malformed,
/// empty, or not valid UTF-8.
pub fn extract_bearer_token(headers: &HeaderMap) -> Result<String, CredentialError> {
    let value = headers
        .get(AUTHORIZATION)
        .ok_or(CredentialError::AuthorizationRequired)?;
    let value = value
        .to_str()
        .map_err(|_| CredentialError::HeaderIsNotUtf8(AUTHORIZATION))?;
    let token = bearer_value(value).ok_or(CredentialError::InvalidAuthorizationHeader)?;
    if token.is_empty() {
        return Err(CredentialError::EmptyBearerToken);
    }
    Ok(token.to_owned())
}

/// Extracts a gateway API key with the same precedence as the Go middleware.
/// Non-empty `key` and `api_key` query parameters are rejected before headers.
/// Extracts an API key using the Go-compatible header precedence.
///
/// # Errors
///
/// Returns an error for malformed headers, missing credentials, or deprecated
/// query-string credentials.
pub fn extract_api_key(
    headers: &HeaderMap,
    raw_query: Option<&str>,
) -> Result<ExtractedApiKey, CredentialError> {
    if query_contains_api_key(raw_query) {
        return Err(CredentialError::ApiKeyInQueryDeprecated);
    }

    if let Some(value) = optional_header(headers, AUTHORIZATION)?
        && let Some(key) = bearer_value(value).filter(|key| !key.is_empty())
    {
        return Ok(ExtractedApiKey {
            key: key.to_owned(),
            source: ApiKeySource::AuthorizationBearer,
        });
    }
    if let Some(key) = non_empty_header(headers, X_API_KEY)? {
        return Ok(ExtractedApiKey {
            key,
            source: ApiKeySource::ApiKeyHeader,
        });
    }
    if let Some(key) = non_empty_header(headers, X_GOOG_API_KEY)? {
        return Ok(ExtractedApiKey {
            key,
            source: ApiKeySource::GoogleApiKeyHeader,
        });
    }
    Err(CredentialError::ApiKeyRequired)
}

fn optional_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<Option<&'a str>, CredentialError> {
    headers
        .get(name)
        .map(|value| {
            value
                .to_str()
                .map_err(|_| CredentialError::HeaderIsNotUtf8(name))
        })
        .transpose()
}

fn non_empty_header(
    headers: &HeaderMap,
    name: &'static str,
) -> Result<Option<String>, CredentialError> {
    Ok(optional_header(headers, name)?
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned))
}

fn bearer_value(value: &str) -> Option<&str> {
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    Some(token.trim())
}

fn query_contains_api_key(raw_query: Option<&str>) -> bool {
    raw_query.is_some_and(|query| {
        url::form_urlencoded::parse(query.as_bytes()).any(|(name, value)| {
            matches!(name.as_ref(), "key" | "api_key") && !value.trim().is_empty()
        })
    })
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn bearer_extraction_is_case_insensitive_and_trimmed() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("bEaReR   token-value"),
        );
        assert_eq!(
            extract_bearer_token(&headers).expect("Bearer token should parse"),
            "token-value"
        );
    }

    #[test]
    fn api_key_precedence_matches_gateway_contract() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer bearer-key"));
        headers.insert(X_API_KEY, HeaderValue::from_static("header-key"));
        headers.insert(X_GOOG_API_KEY, HeaderValue::from_static("google-key"));
        assert_eq!(
            extract_api_key(&headers, None).expect("API key should parse"),
            ExtractedApiKey {
                key: "bearer-key".to_owned(),
                source: ApiKeySource::AuthorizationBearer,
            }
        );
    }

    #[test]
    fn malformed_authorization_falls_back_to_api_key_header() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Basic credentials"));
        headers.insert(X_API_KEY, HeaderValue::from_static("header-key"));
        assert_eq!(
            extract_api_key(&headers, None)
                .expect("x-api-key fallback should work")
                .key,
            "header-key"
        );
    }

    #[test]
    fn non_empty_query_api_key_is_rejected_even_with_header() {
        let mut headers = HeaderMap::new();
        headers.insert(X_API_KEY, HeaderValue::from_static("header-key"));
        assert_eq!(
            extract_api_key(&headers, Some("api_key=query-key")),
            Err(CredentialError::ApiKeyInQueryDeprecated)
        );
        assert!(extract_api_key(&headers, Some("api_key=%20%20")).is_ok());
    }
}
