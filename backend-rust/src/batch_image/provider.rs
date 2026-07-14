use std::{fmt, time::Duration};

use reqwest::{StatusCode, Url, header};
use serde_json::{Value, json};

use super::{BatchError, sanitize_public_error};

const DEFAULT_BASE_URL: &str = "https://generativelanguage.googleapis.com";
const MAX_ERROR_BYTES: usize = 16 * 1024;

#[derive(Clone)]
pub(super) struct ProviderClient {
    client: reqwest::Client,
}

impl ProviderClient {
    pub(super) fn new() -> Result<Self, reqwest::Error> {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(15))
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_keepalive(Duration::from_secs(30))
            .build()
            .map(|client| Self { client })
    }

    pub(super) async fn submit(
        &self,
        base_url: &str,
        api_key: &str,
        display_name: &str,
        model: &str,
        jsonl: Vec<u8>,
    ) -> Result<ProviderBatch, ProviderError> {
        let boundary = format!("sub2api-{}", uuid::Uuid::new_v4().simple());
        let metadata = serde_json::to_vec(&json!({
            "file": {
                "displayName": display_name,
                "mimeType": "application/jsonl"
            }
        }))
        .map_err(|error| ProviderError::serialization(&error))?;
        let mut multipart = Vec::with_capacity(metadata.len() + jsonl.len() + 512);
        append_multipart_part(
            &mut multipart,
            &boundary,
            "metadata",
            None,
            "application/json; charset=utf-8",
            &metadata,
        );
        append_multipart_part(
            &mut multipart,
            &boundary,
            "file",
            Some("batch.jsonl"),
            "application/jsonl",
            &jsonl,
        );
        multipart.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

        let upload_url = endpoint(base_url, "/upload/v1beta/files?uploadType=multipart")?;
        let upload_response = self
            .client
            .post(upload_url)
            .header("x-goog-api-key", api_key)
            .header(
                header::CONTENT_TYPE,
                format!("multipart/related; boundary={boundary}"),
            )
            .body(multipart)
            .send()
            .await
            .map_err(|error| ProviderError::network(&error))?;
        let uploaded = read_json(upload_response).await?;
        let file = uploaded.get("file").unwrap_or(&uploaded);
        let input_ref = file
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                ProviderError::invalid_response(
                    "GEMINI_INVALID_RESPONSE",
                    "Gemini upload response is missing file name",
                )
            })?
            .to_owned();

        let model = encode_path_segment(model)?;
        let create_url = endpoint(
            base_url,
            &format!("/v1beta/models/{model}:batchGenerateContent"),
        )?;
        let create_response = self
            .client
            .post(create_url)
            .header("x-goog-api-key", api_key)
            .json(&json!({
                "batch": {
                    "displayName": display_name,
                    "inputConfig": { "fileName": input_ref }
                }
            }))
            .send()
            .await
            .map_err(|error| ProviderError::network(&error))?;
        let batch = read_json(create_response).await?;
        let name = batch
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                ProviderError::invalid_response(
                    "GEMINI_INVALID_RESPONSE",
                    "Gemini batch response is missing job name",
                )
            })?
            .to_owned();
        let state = batch
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        Ok(ProviderBatch {
            name,
            input_ref,
            state,
        })
    }

    pub(super) async fn get_batch(
        &self,
        base_url: &str,
        api_key: &str,
        batch_name: &str,
    ) -> Result<ProviderStatus, ProviderError> {
        let path = provider_resource_path(batch_name, false)?;
        let response = self
            .client
            .get(endpoint(base_url, &path)?)
            .header("x-goog-api-key", api_key)
            .send()
            .await
            .map_err(|error| ProviderError::network(&error))?;
        let value = read_json(response).await?;
        Ok(ProviderStatus::from_json(&value))
    }

    pub(super) async fn cancel(
        &self,
        base_url: &str,
        api_key: &str,
        batch_name: &str,
    ) -> Result<(), ProviderError> {
        let path = provider_resource_path(batch_name, true)?;
        let response = self
            .client
            .post(endpoint(base_url, &path)?)
            .header("x-goog-api-key", api_key)
            .send()
            .await
            .map_err(|error| ProviderError::network(&error))?;
        ensure_success(response).await
    }

    pub(super) async fn download_file(
        &self,
        base_url: &str,
        api_key: &str,
        file_name: &str,
        limit: usize,
    ) -> Result<Vec<u8>, ProviderError> {
        let path = file_resource_path(file_name)?;
        let metadata_response = self
            .client
            .get(endpoint(base_url, &path)?)
            .header("x-goog-api-key", api_key)
            .send()
            .await
            .map_err(|error| ProviderError::network(&error))?;
        let metadata = read_json(metadata_response).await?;
        let fallback_url = endpoint(base_url, &format!("{path}:download"))?;
        let download_url = metadata
            .get("downloadUri")
            .or_else(|| metadata.get("download_url"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(Url::parse)
            .transpose()
            .map_err(|error| {
                ProviderError::invalid_response(
                    "GEMINI_INVALID_RESPONSE",
                    format!("Gemini download URL is invalid: {error}"),
                )
            })?
            .unwrap_or(fallback_url);
        validate_download_url(&download_url, base_url)?;
        let response = self
            .client
            .get(download_url)
            .header("x-goog-api-key", api_key)
            .send()
            .await
            .map_err(|error| ProviderError::network(&error))?;
        if !response.status().is_success() {
            return Err(read_error(response).await);
        }
        if response
            .content_length()
            .is_some_and(|length| length > u64::try_from(limit).unwrap_or(u64::MAX))
        {
            return Err(ProviderError::invalid_response(
                "BATCH_IMAGE_DOWNLOAD_TOO_LARGE",
                "batch image provider output is too large",
            ));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|error| ProviderError::network(&error))?;
        if bytes.len() > limit {
            return Err(ProviderError::invalid_response(
                "BATCH_IMAGE_DOWNLOAD_TOO_LARGE",
                "batch image provider output is too large",
            ));
        }
        Ok(bytes.to_vec())
    }

    pub(super) async fn delete_file(
        &self,
        base_url: &str,
        api_key: &str,
        file_name: &str,
    ) -> Result<(), ProviderError> {
        let path = file_resource_path(file_name)?;
        let response = self
            .client
            .delete(endpoint(base_url, &path)?)
            .header("x-goog-api-key", api_key)
            .send()
            .await
            .map_err(|error| ProviderError::network(&error))?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(());
        }
        ensure_success(response).await
    }
}

pub(super) struct ProviderBatch {
    pub(super) name: String,
    pub(super) input_ref: String,
    pub(super) state: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProviderState {
    Queued,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

pub(super) struct ProviderStatus {
    pub(super) state: ProviderState,
    pub(super) output_ref: Option<String>,
    pub(super) error_code: Option<String>,
    pub(super) error_message: Option<String>,
}

impl ProviderStatus {
    fn from_json(value: &Value) -> Self {
        let raw_state = value
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_ascii_uppercase();
        let error = value.get("error");
        let error_code = error.and_then(|error| {
            error
                .get("status")
                .or_else(|| error.get("code"))
                .map(|value| match value {
                    Value::String(value) => value.clone(),
                    other => other.to_string(),
                })
        });
        let error_message = error
            .and_then(|error| error.get("message"))
            .and_then(Value::as_str)
            .map(sanitize_public_error);
        let state = match raw_state.as_str() {
            "JOB_STATE_PENDING" | "JOB_STATE_QUEUED" => ProviderState::Queued,
            "JOB_STATE_SUCCEEDED" => ProviderState::Succeeded,
            "JOB_STATE_FAILED" | "JOB_STATE_EXPIRED" => ProviderState::Failed,
            "JOB_STATE_CANCELLED" => ProviderState::Cancelled,
            _ if error.is_some() => ProviderState::Failed,
            _ => ProviderState::Running,
        };
        let output_ref = [
            value.pointer("/dest/fileName"),
            value.pointer("/dest/file_name"),
            value.pointer("/response/responsesFile"),
            value.pointer("/response/responses_file"),
        ]
        .into_iter()
        .flatten()
        .find_map(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
        Self {
            state,
            output_ref,
            error_code,
            error_message,
        }
    }
}

#[derive(Debug)]
pub(super) struct ProviderError {
    code: String,
    message: String,
    status: Option<StatusCode>,
}

impl ProviderError {
    fn new(
        code: impl Into<String>,
        message: impl Into<String>,
        status: Option<StatusCode>,
    ) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            status,
        }
    }

    fn network(error: &reqwest::Error) -> Self {
        tracing::warn!(error = %error, "Gemini batch request failed");
        Self::new(
            "GEMINI_INVALID_RESPONSE",
            "Gemini API request failed",
            error.status(),
        )
    }

    fn serialization(error: &serde_json::Error) -> Self {
        tracing::error!(error = %error, "serialize Gemini batch request");
        Self::new(
            "GEMINI_INVALID_RESPONSE",
            "Gemini batch request could not be serialized",
            None,
        )
    }

    fn invalid_response(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(code, message, None)
    }

    pub(super) fn code(&self) -> &str {
        &self.code
    }

    pub(super) fn message(&self) -> &str {
        &self.message
    }

    pub(super) fn public_submit_error(&self) -> BatchError {
        tracing::warn!(
            code = self.code,
            message = self.message,
            "Gemini batch submission failed"
        );
        BatchError::upstream(
            "BATCH_IMAGE_PROVIDER_SUBMIT_FAILED",
            "batch image provider submit failed",
        )
    }

    pub(super) fn public_poll_error(&self) -> BatchError {
        BatchError::upstream(&self.code, sanitize_public_error(&self.message))
    }

    pub(super) fn public_cancel_error(&self) -> BatchError {
        tracing::warn!(
            code = self.code,
            message = self.message,
            "Gemini batch cancellation failed"
        );
        BatchError::upstream(
            "BATCH_IMAGE_CANCEL_FAILED",
            "batch image cancellation failed",
        )
    }

    pub(super) fn public_download_error(&self) -> BatchError {
        let status = if self.code == "BATCH_IMAGE_DOWNLOAD_TOO_LARGE" {
            StatusCode::BAD_REQUEST
        } else if self.status == Some(StatusCode::GONE) {
            StatusCode::GONE
        } else {
            StatusCode::BAD_GATEWAY
        };
        BatchError::new(
            status,
            if self.code == "BATCH_IMAGE_DOWNLOAD_TOO_LARGE" {
                self.code.clone()
            } else {
                "BATCH_IMAGE_DOWNLOAD_FAILED".to_owned()
            },
            if self.code == "BATCH_IMAGE_DOWNLOAD_TOO_LARGE" {
                self.message.clone()
            } else {
                "batch image download failed".to_owned()
            },
        )
    }

    pub(super) fn public_cleanup_error(&self) -> BatchError {
        tracing::warn!(
            code = self.code,
            message = self.message,
            "Gemini batch cleanup failed"
        );
        BatchError::upstream(
            "BATCH_IMAGE_PROVIDER_CLEANUP_FAILED",
            "batch image provider cleanup failed",
        )
    }
}

impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ProviderError {}

async fn read_json(response: reqwest::Response) -> Result<Value, ProviderError> {
    if !response.status().is_success() {
        return Err(read_error(response).await);
    }
    response
        .json::<Value>()
        .await
        .map_err(|error| ProviderError::network(&error))
}

async fn ensure_success(response: reqwest::Response) -> Result<(), ProviderError> {
    if response.status().is_success() {
        Ok(())
    } else {
        Err(read_error(response).await)
    }
}

async fn read_error(response: reqwest::Response) -> ProviderError {
    let status = response.status();
    let bytes = response.bytes().await.unwrap_or_default();
    let bytes = &bytes[..bytes.len().min(MAX_ERROR_BYTES)];
    let parsed = serde_json::from_slice::<Value>(bytes).ok();
    let error = parsed.as_ref().and_then(|value| value.get("error"));
    let upstream_code = error.and_then(|error| {
        error
            .get("status")
            .or_else(|| error.get("code"))
            .map(|value| match value {
                Value::String(value) => value.clone(),
                other => other.to_string(),
            })
    });
    let upstream_message = error
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let (code, message) = match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => (
            "GEMINI_AUTH_FAILED",
            "Gemini authentication failed".to_owned(),
        ),
        StatusCode::TOO_MANY_REQUESTS => (
            "GEMINI_RATE_LIMITED",
            "Gemini rate limit exceeded".to_owned(),
        ),
        StatusCode::NOT_FOUND => (
            "GEMINI_BATCH_NOT_FOUND",
            "Gemini batch resource was not found".to_owned(),
        ),
        _ => (
            upstream_code
                .as_deref()
                .unwrap_or("GEMINI_INVALID_RESPONSE"),
            if upstream_message.is_empty() {
                "Gemini API request failed".to_owned()
            } else {
                sanitize_public_error(upstream_message)
            },
        ),
    };
    ProviderError::new(code, message, Some(status))
}

fn endpoint(base_url: &str, path: &str) -> Result<Url, ProviderError> {
    let mut base = Url::parse(if base_url.trim().is_empty() {
        DEFAULT_BASE_URL
    } else {
        base_url.trim()
    })
    .map_err(|error| {
        ProviderError::invalid_response(
            "BATCH_IMAGE_PROVIDER_UNSUPPORTED_ACCOUNT",
            format!("invalid Gemini base URL: {error}"),
        )
    })?;
    if !matches!(base.scheme(), "http" | "https") || base.host_str().is_none() {
        return Err(ProviderError::invalid_response(
            "BATCH_IMAGE_PROVIDER_UNSUPPORTED_ACCOUNT",
            "invalid Gemini base URL",
        ));
    }
    base.set_path("");
    base.set_query(None);
    base.set_fragment(None);
    base.join(path).map_err(|error| {
        ProviderError::invalid_response(
            "GEMINI_INVALID_RESPONSE",
            format!("invalid Gemini endpoint: {error}"),
        )
    })
}

fn provider_resource_path(name: &str, cancel: bool) -> Result<String, ProviderError> {
    let name = name.trim().trim_start_matches('/');
    if !valid_resource_name(name, "batches/") {
        return Err(ProviderError::invalid_response(
            "GEMINI_INVALID_RESPONSE",
            "invalid Gemini batch resource name",
        ));
    }
    Ok(if cancel {
        format!("/v1beta/{name}:cancel")
    } else {
        format!("/v1beta/{name}")
    })
}

fn file_resource_path(name: &str) -> Result<String, ProviderError> {
    let name = name.trim().trim_start_matches('/');
    if !valid_resource_name(name, "files/") {
        return Err(ProviderError::invalid_response(
            "GEMINI_INVALID_RESPONSE",
            "invalid Gemini file resource name",
        ));
    }
    Ok(format!("/v1beta/{name}"))
}

fn valid_resource_name(name: &str, prefix: &str) -> bool {
    name.starts_with(prefix)
        && name.len() > prefix.len()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
        && !name.contains("..")
}

fn encode_path_segment(value: &str) -> Result<String, ProviderError> {
    let value = value.trim();
    if value.is_empty()
        || value.contains('/')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ProviderError::invalid_response(
            "BATCH_IMAGE_INVALID_MODEL",
            "invalid Gemini model name",
        ));
    }
    Ok(value.to_owned())
}

fn validate_download_url(download: &Url, base_url: &str) -> Result<(), ProviderError> {
    let base = Url::parse(base_url).map_err(|_| {
        ProviderError::invalid_response("GEMINI_INVALID_RESPONSE", "Gemini base URL is invalid")
    })?;
    let host = download.host_str().unwrap_or_default().to_ascii_lowercase();
    let google_host = host == "googleapis.com" || host.ends_with(".googleapis.com");
    let same_origin = download.scheme() == base.scheme()
        && download.host_str() == base.host_str()
        && download.port_or_known_default() == base.port_or_known_default();
    if (download.scheme() == "https" && google_host) || same_origin {
        Ok(())
    } else {
        Err(ProviderError::invalid_response(
            "GEMINI_INVALID_RESPONSE",
            "Gemini download URL host is not allowed",
        ))
    }
}

fn append_multipart_part(
    output: &mut Vec<u8>,
    boundary: &str,
    name: &str,
    filename: Option<&str>,
    content_type: &str,
    body: &[u8],
) {
    output.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    output.extend_from_slice(format!("Content-Disposition: form-data; name=\"{name}\"").as_bytes());
    if let Some(filename) = filename {
        output.extend_from_slice(format!("; filename=\"{filename}\"").as_bytes());
    }
    output.extend_from_slice(format!("\r\nContent-Type: {content_type}\r\n\r\n").as_bytes());
    output.extend_from_slice(body);
    output.extend_from_slice(b"\r\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_state_maps_terminal_results() {
        let value = json!({
            "state": "JOB_STATE_SUCCEEDED",
            "dest": { "fileName": "files/result" }
        });
        let status = ProviderStatus::from_json(&value);
        assert_eq!(status.state, ProviderState::Succeeded);
        assert_eq!(status.output_ref.as_deref(), Some("files/result"));
    }

    #[test]
    fn provider_paths_reject_traversal() {
        assert!(provider_resource_path("batches/../secret", false).is_err());
        assert!(file_resource_path("files/../secret").is_err());
    }
}
