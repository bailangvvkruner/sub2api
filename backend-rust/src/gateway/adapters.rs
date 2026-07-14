use std::{
    env,
    error::Error,
    fmt::{self, Write as _},
};

use axum::http::{HeaderMap, HeaderName, HeaderValue, header};
use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, Datelike, Timelike, Utc};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

use crate::{repository::AccountRecord, rsa_crypto::sign_rsa_pkcs1_sha256};

use super::{
    GatewayRoute, Protocol, RequestMetadata, ResponseMode, RouteKind, UpstreamRequestPlan,
};

pub(crate) const ANTHROPIC_OAUTH_TOKEN_URL: &str = "https://platform.claude.com/v1/oauth/token";
pub(crate) const ANTHROPIC_OAUTH_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
pub(crate) const OPENAI_OAUTH_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
pub(crate) const OPENAI_OAUTH_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
pub(crate) const GROK_OAUTH_TOKEN_URL: &str = "https://auth.x.ai/oauth2/token";
pub(crate) const GROK_OAUTH_CLIENT_ID: &str = "b1a00492-073a-47ea-816f-4c329264a828";
pub(crate) const GOOGLE_OAUTH_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
pub(crate) const GEMINI_CLI_CLIENT_ID: &str =
    "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com";
pub(crate) const GEMINI_CLI_CLIENT_SECRET: &str = "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";
pub(crate) const ANTIGRAVITY_CLIENT_ID: &str =
    "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com";
pub(crate) const ANTIGRAVITY_CLIENT_SECRET: &str = "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";
pub(crate) const VERTEX_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

pub(crate) const OPENAI_CODEX_URL: &str = "https://chatgpt.com/backend-api/codex/responses";
const ANTIGRAVITY_DAILY_URL: &str = "https://daily-cloudcode-pa.sandbox.googleapis.com";
const GEMINI_CODE_ASSIST_URL: &str = "https://cloudcode-pa.googleapis.com";
const VERTEX_DEFAULT_LOCATION: &str = "us-central1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StreamWire {
    ServerSentEvents,
    BedrockEventStream,
}

#[derive(Default)]
pub(crate) struct BedrockEventStreamDecoder {
    pending: Vec<u8>,
}

impl BedrockEventStreamDecoder {
    pub(crate) fn push(&mut self, chunk: &[u8]) -> Result<Vec<u8>, AdapterError> {
        if self.pending.len().saturating_add(chunk.len()) > 16 * 1024 * 1024 {
            return Err(AdapterError::new(
                "Bedrock EventStream buffer exceeded 16 MiB",
            ));
        }
        self.pending.extend_from_slice(chunk);
        let mut output = Vec::new();
        loop {
            if self.pending.len() < 12 {
                break;
            }
            let total = usize::try_from(u32::from_be_bytes(
                self.pending[0..4]
                    .try_into()
                    .expect("the prelude length was checked"),
            ))
            .map_err(|_| AdapterError::new("invalid Bedrock EventStream length"))?;
            if !(16..=16 * 1024 * 1024).contains(&total) {
                return Err(AdapterError::new(
                    "invalid Bedrock EventStream frame length",
                ));
            }
            if self.pending.len() < total {
                break;
            }
            let frame = self.pending[..total].to_vec();
            self.pending.drain(..total);
            decode_bedrock_frame(&frame, &mut output)?;
        }
        Ok(output)
    }

    pub(crate) fn finish(&self) -> Result<(), AdapterError> {
        if self.pending.iter().all(u8::is_ascii_whitespace) {
            Ok(())
        } else {
            Err(AdapterError::new("truncated Bedrock EventStream frame"))
        }
    }
}

fn decode_bedrock_frame(frame: &[u8], output: &mut Vec<u8>) -> Result<(), AdapterError> {
    let headers_len = usize::try_from(u32::from_be_bytes(
        frame[4..8]
            .try_into()
            .expect("the EventStream prelude is complete"),
    ))
    .map_err(|_| AdapterError::new("invalid Bedrock EventStream header length"))?;
    if headers_len > frame.len().saturating_sub(16) {
        return Err(AdapterError::new(
            "invalid Bedrock EventStream header length",
        ));
    }
    let expected_prelude_crc = u32::from_be_bytes(
        frame[8..12]
            .try_into()
            .expect("the EventStream prelude is complete"),
    );
    if crc32fast::hash(&frame[..8]) != expected_prelude_crc {
        return Err(AdapterError::new(
            "Bedrock EventStream prelude CRC mismatch",
        ));
    }
    let expected_message_crc = u32::from_be_bytes(
        frame[frame.len() - 4..]
            .try_into()
            .expect("the EventStream message CRC is complete"),
    );
    if crc32fast::hash(&frame[..frame.len() - 4]) != expected_message_crc {
        return Err(AdapterError::new(
            "Bedrock EventStream message CRC mismatch",
        ));
    }
    let headers = &frame[12..12 + headers_len];
    let payload = &frame[12 + headers_len..frame.len() - 4];
    let event_type = eventstream_header(headers, ":event-type")?;
    let message_type = eventstream_header(headers, ":message-type")?;
    if event_type.as_deref() != Some("chunk") {
        if matches!(message_type.as_deref(), Some("exception" | "error"))
            || eventstream_header(headers, ":exception-type")?.is_some()
        {
            return Err(AdapterError::new(
                "Bedrock EventStream returned an exception",
            ));
        }
        return Ok(());
    }
    let envelope: Value = serde_json::from_slice(payload)
        .map_err(|_| AdapterError::new("Bedrock chunk envelope is invalid JSON"))?;
    let encoded = envelope
        .get("bytes")
        .and_then(Value::as_str)
        .ok_or_else(|| AdapterError::new("Bedrock chunk envelope has no bytes"))?;
    let decoded = general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| AdapterError::new("Bedrock chunk bytes are invalid base64"))?;
    let mut event: Value = serde_json::from_slice(&decoded)
        .map_err(|_| AdapterError::new("Bedrock chunk is invalid Anthropic JSON"))?;
    let object = event
        .as_object_mut()
        .ok_or_else(|| AdapterError::new("Bedrock chunk must contain a JSON object"))?;
    if object.get("usage").is_none()
        && let Some(metrics) = object
            .remove("amazon-bedrock-invocationMetrics")
            .and_then(|value| value.as_object().cloned())
    {
        object.insert(
            "usage".to_owned(),
            json!({
                "input_tokens": metrics.get("inputTokenCount").and_then(Value::as_u64).unwrap_or(0),
                "output_tokens": metrics.get("outputTokenCount").and_then(Value::as_u64).unwrap_or(0),
            }),
        );
    }
    let event_name = object
        .get("type")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let event = serde_json::to_vec(&event)
        .map_err(|_| AdapterError::new("Bedrock chunk could not be encoded"))?;
    if let Some(event_name) = event_name {
        output.extend_from_slice(b"event: ");
        output.extend_from_slice(event_name.as_bytes());
        output.push(b'\n');
    }
    output.extend_from_slice(b"data: ");
    output.extend_from_slice(&event);
    output.extend_from_slice(b"\n\n");
    Ok(())
}

fn eventstream_header(headers: &[u8], target: &str) -> Result<Option<String>, AdapterError> {
    let mut position = 0;
    while position < headers.len() {
        let name_len = usize::from(headers[position]);
        position += 1;
        let name_end = position.saturating_add(name_len);
        if name_end >= headers.len() {
            return Err(AdapterError::new("invalid Bedrock EventStream header"));
        }
        let name = std::str::from_utf8(&headers[position..name_end])
            .map_err(|_| AdapterError::new("invalid Bedrock EventStream header name"))?;
        position = name_end;
        let value_type = headers[position];
        position += 1;
        let (value, consumed) = match value_type {
            0 => (Some("true".to_owned()), 0),
            1 => (Some("false".to_owned()), 0),
            2 => (None, 1),
            3 => (None, 2),
            4 => (None, 4),
            5 | 8 => (None, 8),
            6 | 7 => {
                if position + 2 > headers.len() {
                    return Err(AdapterError::new("invalid Bedrock EventStream header"));
                }
                let length = usize::from(u16::from_be_bytes(
                    headers[position..position + 2]
                        .try_into()
                        .expect("the header length was checked"),
                ));
                position += 2;
                if position + length > headers.len() {
                    return Err(AdapterError::new("invalid Bedrock EventStream header"));
                }
                let value = (value_type == 7)
                    .then(|| std::str::from_utf8(&headers[position..position + length]))
                    .transpose()
                    .map_err(|_| AdapterError::new("invalid Bedrock EventStream header value"))?
                    .map(ToOwned::to_owned);
                (value, length)
            }
            9 => (None, 16),
            _ => {
                return Err(AdapterError::new(
                    "unsupported Bedrock EventStream header type",
                ));
            }
        };
        if position + consumed > headers.len() {
            return Err(AdapterError::new("invalid Bedrock EventStream header"));
        }
        position += consumed;
        if name == target {
            return Ok(value);
        }
    }
    Ok(None)
}

pub(crate) struct AdaptedRequest {
    pub plan: UpstreamRequestPlan,
    pub body: Vec<u8>,
    pub stream_wire: StreamWire,
    pub normalize_wrapped_gemini: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdapterError(String);

impl AdapterError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for AdapterError {}

pub(crate) fn adapt_request(
    account: &AccountRecord,
    route: &GatewayRoute,
    metadata: &RequestMetadata,
    plan: UpstreamRequestPlan,
    body: Vec<u8>,
) -> Result<AdaptedRequest, AdapterError> {
    let platform = account.platform.trim().to_ascii_lowercase();
    let account_type = account.account_type.trim().to_ascii_lowercase();
    let mut adapted = AdaptedRequest {
        plan,
        body,
        stream_wire: StreamWire::ServerSentEvents,
        normalize_wrapped_gemini: false,
    };

    if platform == "antigravity" {
        adapt_antigravity(account, route, metadata, &mut adapted)?;
    } else if account_type == "bedrock" {
        adapt_bedrock(account, metadata, &mut adapted)?;
    } else if account_type == "service_account" {
        adapt_vertex(account, route, metadata, &mut adapted)?;
    } else if account_type == "oauth" || account_type == "setup-token" {
        match platform.as_str() {
            "anthropic" => adapt_anthropic_oauth(&mut adapted)?,
            "openai" => adapt_openai_oauth(account, &mut adapted)?,
            "gemini" => adapt_gemini_oauth(account, route, metadata, &mut adapted)?,
            _ => {}
        }
    }
    Ok(adapted)
}

fn adapt_anthropic_oauth(adapted: &mut AdaptedRequest) -> Result<(), AdapterError> {
    adapted.plan.headers.remove("x-api-key");
    merge_header_token(
        &mut adapted.plan.headers,
        "anthropic-beta",
        "oauth-2025-04-20",
    )?;
    adapted.plan.headers.insert(
        header::USER_AGENT,
        HeaderValue::from_static("claude-cli/2.1.69 (external, cli)"),
    );
    adapted
        .plan
        .headers
        .insert("x-app", HeaderValue::from_static("cli"));
    Ok(())
}

fn adapt_openai_oauth(
    account: &AccountRecord,
    adapted: &mut AdaptedRequest,
) -> Result<(), AdapterError> {
    adapted.plan.url = configured_url(account, "base_url", OPENAI_CODEX_URL)?;
    adapted.plan.headers.remove("x-api-key");
    adapted.plan.headers.insert(
        "openai-beta",
        HeaderValue::from_static("responses=experimental"),
    );
    adapted
        .plan
        .headers
        .insert("originator", HeaderValue::from_static("codex_cli_rs"));
    adapted.plan.headers.insert(
        header::USER_AGENT,
        HeaderValue::from_static("codex_cli_rs/0.144.1 (Ubuntu 22.4.0; x86_64) xterm-256color"),
    );
    if let Some(account_id) = credential_string(&account.credentials, "chatgpt_account_id") {
        adapted.plan.headers.insert(
            "chatgpt-account-id",
            header_value(&account_id, "chatgpt_account_id")?,
        );
    }
    Ok(())
}

fn adapt_gemini_oauth(
    account: &AccountRecord,
    route: &GatewayRoute,
    metadata: &RequestMetadata,
    adapted: &mut AdaptedRequest,
) -> Result<(), AdapterError> {
    adapted.plan.headers.insert(
        header::USER_AGENT,
        HeaderValue::from_static("GeminiCLI/0.1.5 (Windows; AMD64)"),
    );
    let Some(project) = credential_string(&account.credentials, "project_id") else {
        return Ok(());
    };
    let model = required_model(metadata)?;
    let action = gemini_action(route.kind)?;
    let base = configured_base(account, GEMINI_CODE_ASSIST_URL)?;
    adapted.plan.url = endpoint_url(&base, &format!("/v1internal:{action}"), metadata.stream);
    let request = parse_object_body(&adapted.body, "Gemini OAuth request")?;
    adapted.body = encode_json(&json!({
        "model": model,
        "project": project,
        "request": request,
    }))?;
    adapted.normalize_wrapped_gemini = true;
    Ok(())
}

fn adapt_antigravity(
    account: &AccountRecord,
    route: &GatewayRoute,
    metadata: &RequestMetadata,
    adapted: &mut AdaptedRequest,
) -> Result<(), AdapterError> {
    let project = credential_string(&account.credentials, "project_id")
        .or_else(|| credential_string(&account.extra, "antigravity_project_id"))
        .ok_or_else(|| AdapterError::new("Antigravity account is missing project_id"))?;
    let model = required_model(metadata)?;
    let action = gemini_action(route.kind)?;
    let base = configured_base(account, ANTIGRAVITY_DAILY_URL)?;
    adapted.plan.url = endpoint_url(&base, &format!("/v1internal:{action}"), metadata.stream);
    let request = parse_object_body(&adapted.body, "Antigravity request")?;
    adapted.body = encode_json(&json!({
        "project": project,
        "requestId": format!("agent-{}", Uuid::new_v4()),
        "userAgent": "antigravity",
        "requestType": "agent",
        "model": model,
        "request": request,
    }))?;

    let authorization = adapted.plan.headers.get(header::AUTHORIZATION).cloned();
    adapted.plan.headers.clear();
    adapted.plan.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if let Some(authorization) = authorization {
        adapted
            .plan
            .headers
            .insert(header::AUTHORIZATION, authorization);
    }
    let version = env::var("ANTIGRAVITY_USER_AGENT_VERSION")
        .ok()
        .filter(|value| valid_version(value))
        .unwrap_or_else(|| "1.23.2".to_owned());
    adapted.plan.headers.insert(
        header::USER_AGENT,
        header_value(
            &format!("antigravity/{version} windows/amd64"),
            "Antigravity User-Agent",
        )?,
    );
    adapted.normalize_wrapped_gemini = true;
    Ok(())
}

fn adapt_vertex(
    account: &AccountRecord,
    route: &GatewayRoute,
    metadata: &RequestMetadata,
    adapted: &mut AdaptedRequest,
) -> Result<(), AdapterError> {
    let key = service_account_key(&account.credentials)?;
    let project = credential_string(&account.credentials, "project_id")
        .unwrap_or_else(|| key.project_id.clone());
    let model = required_model(metadata)?;
    let location = vertex_location(account, model);
    let host = if location == "global" {
        "aiplatform.googleapis.com".to_owned()
    } else {
        format!("{location}-aiplatform.googleapis.com")
    };
    let base = Url::parse(&format!("https://{host}"))
        .map_err(|_| AdapterError::new("invalid Vertex endpoint"))?;
    let stream = adapted.plan.response_mode == ResponseMode::ServerSentEvents;
    if route.protocol == Protocol::Anthropic {
        let model = normalize_vertex_anthropic_model(model);
        let action = if stream {
            "streamRawPredict"
        } else {
            "rawPredict"
        };
        adapted.plan.url =
            vertex_model_url(base, &project, location, "anthropic", &model, action, false)?;
        let mut body = parse_object_body(&adapted.body, "Vertex Anthropic request")?;
        body.remove("model");
        body.insert(
            "anthropic_version".to_owned(),
            Value::String("vertex-2023-10-16".to_owned()),
        );
        adapted.body = encode_json(&Value::Object(body))?;
        adapted.plan.headers.remove("anthropic-version");
        filter_vertex_beta(&mut adapted.plan.headers)?;
    } else {
        let action = gemini_action(route.kind)?;
        adapted.plan.url =
            vertex_model_url(base, &project, location, "google", model, action, stream)?;
    }
    adapted.plan.headers.remove("x-api-key");
    adapted.plan.headers.remove("x-goog-api-key");
    Ok(())
}

fn adapt_bedrock(
    account: &AccountRecord,
    metadata: &RequestMetadata,
    adapted: &mut AdaptedRequest,
) -> Result<(), AdapterError> {
    let model = required_model(metadata)?;
    let region = credential_string(&account.credentials, "aws_region")
        .unwrap_or_else(|| "us-east-1".to_owned());
    if !valid_aws_region(&region) {
        return Err(AdapterError::new("invalid AWS region"));
    }
    let mut url = Url::parse(&format!("https://bedrock-runtime.{region}.amazonaws.com"))
        .map_err(|_| AdapterError::new("invalid Bedrock endpoint"))?;
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|()| AdapterError::new("invalid Bedrock endpoint"))?;
        segments.push("model");
        segments.push(model);
        segments.push(
            if adapted.plan.response_mode == ResponseMode::ServerSentEvents {
                "invoke-with-response-stream"
            } else {
                "invoke"
            },
        );
    }
    adapted.plan.url = url;
    adapted.body = prepare_bedrock_body(&adapted.body, &adapted.plan.headers)?;
    adapted.plan.headers.clear();
    adapted.plan.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    adapted.plan.headers.insert(
        header::ACCEPT,
        HeaderValue::from_static(
            if adapted.plan.response_mode == ResponseMode::ServerSentEvents {
                "application/vnd.amazon.eventstream"
            } else {
                "application/json"
            },
        ),
    );
    sign_bedrock(
        &mut adapted.plan,
        &adapted.body,
        account,
        &region,
        Utc::now(),
    )?;
    if adapted.plan.response_mode == ResponseMode::ServerSentEvents {
        adapted.stream_wire = StreamWire::BedrockEventStream;
    }
    Ok(())
}

fn prepare_bedrock_body(body: &[u8], headers: &HeaderMap) -> Result<Vec<u8>, AdapterError> {
    let mut body = parse_object_body(body, "Bedrock request")?;
    body.insert(
        "anthropic_version".to_owned(),
        Value::String("bedrock-2023-05-31".to_owned()),
    );
    for field in ["model", "stream", "provider", "metadata", "output_config"] {
        body.remove(field);
    }
    if let Some(beta) = headers
        .get("anthropic-beta")
        .and_then(|value| value.to_str().ok())
    {
        let tokens = beta
            .split(',')
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .map(|token| Value::String(token.to_owned()))
            .collect::<Vec<_>>();
        if !tokens.is_empty() {
            body.insert("anthropic_beta".to_owned(), Value::Array(tokens));
        }
    }
    if let Some(tools) = body.get_mut("tools").and_then(Value::as_array_mut) {
        for tool in tools {
            if let Some(tool) = tool.as_object_mut() {
                tool.remove("custom");
            }
        }
    }
    for value in body.values_mut() {
        sanitize_cache_control(value);
    }
    encode_json(&Value::Object(body))
}

fn sanitize_cache_control(value: &mut Value) {
    match value {
        Value::Array(values) => values.iter_mut().for_each(sanitize_cache_control),
        Value::Object(object) => {
            if let Some(cache_control) = object
                .get_mut("cache_control")
                .and_then(Value::as_object_mut)
            {
                cache_control.remove("scope");
            }
            object.values_mut().for_each(sanitize_cache_control);
        }
        _ => {}
    }
}

fn sign_bedrock(
    plan: &mut UpstreamRequestPlan,
    body: &[u8],
    account: &AccountRecord,
    region: &str,
    now: DateTime<Utc>,
) -> Result<(), AdapterError> {
    let access_key = credential_string(&account.credentials, "aws_access_key_id")
        .ok_or_else(|| AdapterError::new("Bedrock account is missing aws_access_key_id"))?;
    let secret_key = credential_string(&account.credentials, "aws_secret_access_key")
        .ok_or_else(|| AdapterError::new("Bedrock account is missing aws_secret_access_key"))?;
    let session_token = credential_string(&account.credentials, "aws_session_token");
    let host = plan
        .url
        .host_str()
        .ok_or_else(|| AdapterError::new("Bedrock URL is missing host"))?;
    let payload_hash = hex::encode(Sha256::digest(body));
    let amz_date = format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        now.year(),
        now.month(),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );
    let date = format!("{:04}{:02}{:02}", now.year(), now.month(), now.day());
    plan.headers
        .insert("host", header_value(host, "Bedrock host")?);
    plan.headers.insert(
        "x-amz-date",
        header_value(&amz_date, "Bedrock signing date")?,
    );
    plan.headers.insert(
        "x-amz-content-sha256",
        header_value(&payload_hash, "Bedrock payload hash")?,
    );
    if let Some(token) = session_token.as_deref() {
        plan.headers.insert(
            "x-amz-security-token",
            header_value(token, "AWS session token")?,
        );
    }

    let mut signed = vec![
        ("content-type", "application/json".to_owned()),
        ("host", host.to_owned()),
        ("x-amz-content-sha256", payload_hash.clone()),
        ("x-amz-date", amz_date.clone()),
    ];
    if let Some(token) = session_token {
        signed.push(("x-amz-security-token", collapse_spaces(&token)));
    }
    signed.sort_unstable_by_key(|(name, _)| *name);
    let signed_headers = signed
        .iter()
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join(";");
    let mut canonical_headers = String::new();
    for (name, value) in &signed {
        writeln!(canonical_headers, "{name}:{}", collapse_spaces(value))
            .expect("writing to a String cannot fail");
    }
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        plan.method.as_str(),
        plan.url.path(),
        plan.url.query().unwrap_or(""),
        canonical_headers,
        signed_headers,
        payload_hash
    );
    let scope = format!("{date}/{region}/bedrock/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let date_key = hmac_sha256(format!("AWS4{secret_key}").as_bytes(), date.as_bytes())?;
    let region_key = hmac_sha256(&date_key, region.as_bytes())?;
    let service_key = hmac_sha256(&region_key, b"bedrock")?;
    let signing_key = hmac_sha256(&service_key, b"aws4_request")?;
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes())?);
    plan.headers.insert(
        header::AUTHORIZATION,
        header_value(
            &format!(
                "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
            ),
            "Bedrock authorization",
        )?,
    );
    Ok(())
}

fn hmac_sha256(key: &[u8], value: &[u8]) -> Result<Vec<u8>, AdapterError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| AdapterError::new("invalid AWS signing key"))?;
    mac.update(value);
    Ok(mac.finalize().into_bytes().to_vec())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct ServiceAccountKey {
    pub project_id: String,
    pub private_key_id: Option<String>,
    pub private_key: String,
    pub client_email: String,
}

pub(crate) fn service_account_key(credentials: &Value) -> Result<ServiceAccountKey, AdapterError> {
    for name in ["service_account_json", "service_account"] {
        let Some(raw) = credentials.get(name) else {
            continue;
        };
        let parsed = match raw {
            Value::String(raw) => serde_json::from_str(raw),
            value => serde_json::from_value(value.clone()),
        }
        .map_err(|_| AdapterError::new("invalid service account JSON"))?;
        let parsed: ServiceAccountKey = parsed;
        if parsed.project_id.trim().is_empty()
            || parsed.private_key.trim().is_empty()
            || parsed.client_email.trim().is_empty()
        {
            return Err(AdapterError::new(
                "service account JSON is missing required fields",
            ));
        }
        return Ok(parsed);
    }
    Err(AdapterError::new(
        "service account credentials are not configured",
    ))
}

pub(crate) fn service_account_assertion(
    key: &ServiceAccountKey,
    now_unix_seconds: i64,
) -> Result<String, AdapterError> {
    let header = json!({
        "alg": "RS256",
        "typ": "JWT",
        "kid": key.private_key_id,
    });
    let claims = json!({
        "iss": key.client_email,
        "scope": "https://www.googleapis.com/auth/cloud-platform",
        "aud": VERTEX_TOKEN_URL,
        "iat": now_unix_seconds,
        "exp": now_unix_seconds.saturating_add(3600),
    });
    let signing_input = format!(
        "{}.{}",
        general_purpose::URL_SAFE_NO_PAD.encode(encode_json(&header)?),
        general_purpose::URL_SAFE_NO_PAD.encode(encode_json(&claims)?),
    );
    let signature = sign_rsa_pkcs1_sha256(&key.private_key, signing_input.as_bytes())
        .map_err(|_| AdapterError::new("invalid service account private key"))?;
    Ok(format!(
        "{signing_input}.{}",
        general_purpose::URL_SAFE_NO_PAD.encode(signature)
    ))
}

fn vertex_model_url(
    mut base: Url,
    project: &str,
    location: &str,
    publisher: &str,
    model: &str,
    action: &str,
    stream: bool,
) -> Result<Url, AdapterError> {
    {
        let mut segments = base
            .path_segments_mut()
            .map_err(|()| AdapterError::new("invalid Vertex endpoint"))?;
        for segment in [
            "v1",
            "projects",
            project,
            "locations",
            location,
            "publishers",
            publisher,
            "models",
        ] {
            segments.push(segment);
        }
        segments.push(&format!("{model}:{action}"));
    }
    if stream {
        base.query_pairs_mut().append_pair("alt", "sse");
    }
    Ok(base)
}

fn vertex_location<'a>(account: &'a AccountRecord, model: &str) -> &'a str {
    account
        .credentials
        .get("vertex_model_locations")
        .and_then(Value::as_object)
        .and_then(|locations| locations.get(model))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|location| valid_location(location))
        .or_else(|| {
            ["location", "vertex_location"]
                .into_iter()
                .find_map(|name| {
                    account
                        .credentials
                        .get(name)
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|location| valid_location(location))
                })
        })
        .unwrap_or(VERTEX_DEFAULT_LOCATION)
}

fn normalize_vertex_anthropic_model(model: &str) -> String {
    let Some((prefix, date)) = model.rsplit_once('-') else {
        return model.to_owned();
    };
    if date.len() == 8 && date.bytes().all(|byte| byte.is_ascii_digit()) {
        format!("{prefix}@{date}")
    } else {
        model.to_owned()
    }
}

fn filter_vertex_beta(headers: &mut HeaderMap) -> Result<(), AdapterError> {
    let Some(raw) = headers
        .get("anthropic-beta")
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(());
    };
    let allowed = [
        "context-1m-2025-08-07",
        "context-management-2025-06-27",
        "fine-grained-tool-streaming-2025-05-14",
        "interleaved-thinking-2025-05-14",
    ];
    let value = raw
        .split(',')
        .map(str::trim)
        .filter(|token| allowed.contains(token))
        .collect::<Vec<_>>()
        .join(",");
    headers.remove("anthropic-beta");
    if !value.is_empty() {
        headers.insert(
            "anthropic-beta",
            header_value(&value, "Vertex anthropic-beta")?,
        );
    }
    Ok(())
}

fn gemini_action(kind: RouteKind) -> Result<&'static str, AdapterError> {
    match kind {
        RouteKind::GeminiGenerateContent => Ok("generateContent"),
        RouteKind::GeminiStreamGenerateContent => Ok("streamGenerateContent"),
        RouteKind::GeminiCountTokens => Ok("countTokens"),
        _ => Err(AdapterError::new(
            "selected account does not support this Gemini operation",
        )),
    }
}

fn required_model(metadata: &RequestMetadata) -> Result<&str, AdapterError> {
    metadata
        .model
        .as_deref()
        .map(str::trim)
        .filter(|model| !model.is_empty())
        .ok_or_else(|| AdapterError::new("upstream adapter requires a model"))
}

fn configured_base(account: &AccountRecord, fallback: &str) -> Result<Url, AdapterError> {
    let raw =
        credential_string(&account.credentials, "base_url").unwrap_or_else(|| fallback.to_owned());
    let mut base = Url::parse(&raw).map_err(|_| AdapterError::new("invalid adapter base URL"))?;
    if base.scheme() != "https" && base.scheme() != "http" {
        return Err(AdapterError::new("adapter base URL must use HTTP or HTTPS"));
    }
    base.set_query(None);
    base.set_fragment(None);
    Ok(base)
}

fn configured_url(account: &AccountRecord, key: &str, fallback: &str) -> Result<Url, AdapterError> {
    let raw = credential_string(&account.credentials, key).unwrap_or_else(|| fallback.to_owned());
    Url::parse(&raw).map_err(|_| AdapterError::new("invalid adapter URL"))
}

fn endpoint_url(base: &Url, path: &str, stream: bool) -> Url {
    let mut url = base.clone();
    let base_path = url.path().trim_end_matches('/');
    url.set_path(&format!("{base_path}{path}"));
    url.set_query(None);
    if stream {
        url.query_pairs_mut().append_pair("alt", "sse");
    }
    url
}

fn parse_object_body(body: &[u8], context: &str) -> Result<Map<String, Value>, AdapterError> {
    serde_json::from_slice::<Value>(body)
        .map_err(|_| AdapterError::new(format!("{context} is not valid JSON")))?
        .as_object()
        .cloned()
        .ok_or_else(|| AdapterError::new(format!("{context} must be a JSON object")))
}

fn encode_json(value: &Value) -> Result<Vec<u8>, AdapterError> {
    serde_json::to_vec(&value).map_err(|_| AdapterError::new("adapter JSON could not be encoded"))
}

pub(crate) fn credential_string(credentials: &Value, key: &str) -> Option<String> {
    credentials
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn header_value(value: &str, context: &str) -> Result<HeaderValue, AdapterError> {
    HeaderValue::from_str(value)
        .map_err(|_| AdapterError::new(format!("{context} is not a valid HTTP header")))
}

fn merge_header_token(
    headers: &mut HeaderMap,
    name: &'static str,
    token: &str,
) -> Result<(), AdapterError> {
    let current = headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if current
        .split(',')
        .map(str::trim)
        .any(|value| value == token)
    {
        return Ok(());
    }
    let value = if current.trim().is_empty() {
        token.to_owned()
    } else {
        format!("{current},{token}")
    };
    headers.insert(HeaderName::from_static(name), header_value(&value, name)?);
    Ok(())
}

fn collapse_spaces(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn valid_location(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_aws_region(value: &str) -> bool {
    valid_location(value)
}

fn valid_version(value: &str) -> bool {
    let mut parts = value.split('.');
    (0..3).all(|_| {
        parts
            .next()
            .is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    }) && parts.next().is_none()
}

#[cfg(test)]
mod tests {
    use axum::http::{Method, Uri};

    use super::*;
    use crate::{
        gateway::{Credential, build_upstream_request, classify_route},
        repository::STATUS_ACTIVE,
    };

    fn account(platform: &str, account_type: &str, credentials: Value) -> AccountRecord {
        AccountRecord {
            id: 7,
            name: "adapter".to_owned(),
            notes: None,
            platform: platform.to_owned(),
            account_type: account_type.to_owned(),
            credentials,
            extra: json!({}),
            proxy_id: None,
            proxy: None,
            proxy_fallback_origin_id: None,
            concurrency: 1,
            load_factor: None,
            priority: 1,
            rate_multiplier: "1".to_owned(),
            status: STATUS_ACTIVE.to_owned(),
            error_message: None,
            expires_at_unix_ms: None,
            auto_pause_on_expired: true,
            schedulable: true,
            rate_limit_reset_at_unix_ms: None,
            overload_until_unix_ms: None,
            temp_unschedulable_until_unix_ms: None,
            temp_unschedulable_reason: None,
            parent_account_id: None,
            quota_dimension: "global".to_owned(),
            group_ids: Vec::new(),
        }
    }

    fn plan(path: &str, metadata: &RequestMetadata) -> (GatewayRoute, UpstreamRequestPlan) {
        let uri: Uri = path.parse().expect("test URI should parse");
        let route = classify_route(&Method::POST, &uri).expect("route should classify");
        let plan = build_upstream_request(
            &route,
            metadata,
            "https://example.com",
            &Credential::Bearer("token".to_owned()),
            &HeaderMap::new(),
        )
        .expect("generic plan should build");
        (route, plan)
    }

    #[test]
    fn antigravity_wraps_gemini_wire_request() {
        let metadata = RequestMetadata {
            model: Some("gemini-2.5-pro".to_owned()),
            stream: true,
        };
        let (route, plan) = plan(
            "/v1beta/models/gemini-2.5-pro:streamGenerateContent",
            &metadata,
        );
        let account = account("antigravity", "oauth", json!({"project_id":"project-1"}));
        let adapted = adapt_request(
            &account,
            &route,
            &metadata,
            plan,
            br#"{"contents":[]}"#.to_vec(),
        )
        .expect("Antigravity request should adapt");
        let body: Value = serde_json::from_slice(&adapted.body).unwrap();
        assert_eq!(body["project"], "project-1");
        assert_eq!(body["model"], "gemini-2.5-pro");
        assert_eq!(body["request"]["contents"], json!([]));
        assert!(
            adapted
                .plan
                .url
                .as_str()
                .contains("v1internal:streamGenerateContent?alt=sse")
        );
        assert!(adapted.normalize_wrapped_gemini);
    }

    #[test]
    fn bedrock_body_and_signature_are_deterministic() {
        let metadata = RequestMetadata {
            model: Some("anthropic.claude-3-5-sonnet-20241022-v2:0".to_owned()),
            stream: false,
        };
        let (route, mut plan) = plan("/v1/messages", &metadata);
        plan.headers.insert(
            "anthropic-beta",
            HeaderValue::from_static("interleaved-thinking-2025-05-14"),
        );
        let account = account(
            "anthropic",
            "bedrock",
            json!({
                "aws_access_key_id":"AKIDEXAMPLE",
                "aws_secret_access_key":"secret",
                "aws_region":"us-east-1"
            }),
        );
        let mut adapted = AdaptedRequest {
            plan,
            body: br#"{"model":"ignored","stream":false,"messages":[],"tools":[{"name":"x","custom":{"defer_loading":true}}]}"#.to_vec(),
            stream_wire: StreamWire::ServerSentEvents,
            normalize_wrapped_gemini: false,
        };
        let _ = route;
        let model = metadata.model.as_deref().unwrap();
        let region = "us-east-1";
        let mut url = Url::parse("https://bedrock-runtime.us-east-1.amazonaws.com").unwrap();
        {
            let mut segments = url.path_segments_mut().unwrap();
            segments.push("model");
            segments.push(model);
            segments.push("invoke");
        }
        adapted.plan.url = url;
        adapted.body = prepare_bedrock_body(&adapted.body, &adapted.plan.headers).unwrap();
        adapted.plan.headers.clear();
        adapted.plan.headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        sign_bedrock(
            &mut adapted.plan,
            &adapted.body,
            &account,
            region,
            DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
                .unwrap()
                .with_timezone(&Utc),
        )
        .unwrap();
        let body: Value = serde_json::from_slice(&adapted.body).unwrap();
        assert_eq!(body["anthropic_version"], "bedrock-2023-05-31");
        assert!(body.get("model").is_none());
        assert!(body["tools"][0].get("custom").is_none());
        let authorization = adapted.plan.headers[header::AUTHORIZATION]
            .to_str()
            .unwrap();
        assert!(
            authorization
                .contains("Credential=AKIDEXAMPLE/20260102/us-east-1/bedrock/aws4_request")
        );
        assert!(
            authorization
                .contains("SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date")
        );
    }
}
