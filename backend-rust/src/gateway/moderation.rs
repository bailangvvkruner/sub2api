use std::{collections::BTreeMap, time::Duration};

use axum::http::StatusCode;
use reqwest::Client;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use super::{GatewayRoute, RequestMetadata, RouteKind};
use crate::auth::AuthContext;

const MAX_INPUT_CHARS: usize = 12_000;
const MAX_EXCERPT_CHARS: usize = 240;
const MAX_RESPONSE_BYTES: usize = 1 << 20;
const DEFAULT_BLOCK_MESSAGE: &str = "content was blocked by the configured risk-control policy";

const CATEGORIES: &[&str] = &[
    "harassment",
    "harassment/threatening",
    "hate",
    "hate/threatening",
    "illicit",
    "illicit/violent",
    "self-harm",
    "self-harm/intent",
    "self-harm/instructions",
    "sexual",
    "sexual/minors",
    "violence",
    "violence/graphic",
];

#[derive(Clone, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct ModerationConfig {
    enabled: bool,
    mode: ModerationMode,
    base_url: String,
    model: String,
    api_keys: Vec<String>,
    timeout: Duration,
    sample_rate: u8,
    all_groups: bool,
    group_ids: Vec<i64>,
    record_non_hits: bool,
    thresholds: BTreeMap<String, f64>,
    block_status: StatusCode,
    block_message: String,
    retry_count: usize,
    pre_hash_check_enabled: bool,
    blocked_keywords: Vec<String>,
    keyword_mode: KeywordMode,
    model_filter: ModelFilter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModerationMode {
    Off,
    Observe,
    PreBlock,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeywordMode {
    KeywordOnly,
    KeywordAndApi,
    ApiOnly,
}

#[derive(Clone, Debug)]
enum ModelFilter {
    All,
    Include(Vec<String>),
    Exclude(Vec<String>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ModerationOutcome {
    Allow,
    Block { status: StatusCode, message: String },
}

#[derive(Clone, Debug, Default)]
struct ModerationContent {
    text: String,
    images: Vec<String>,
}

#[derive(Clone, Debug)]
struct ModerationAuditContext {
    request_id: String,
    user_id: i64,
    user_email: String,
    api_key_id: i64,
    api_key_name: String,
    group_id: Option<i64>,
    group_name: String,
    endpoint: String,
    provider: String,
    model: String,
}

#[derive(Clone, Debug)]
struct ModerationResult {
    provider_flagged: bool,
    category_scores: BTreeMap<String, f64>,
    latency_ms: i32,
}

#[derive(Clone, Debug)]
struct LogRecord<'a> {
    action: &'a str,
    flagged: bool,
    highest_category: &'a str,
    highest_score: f64,
    scores: &'a BTreeMap<String, f64>,
    excerpt: &'a str,
    latency_ms: Option<i32>,
    error: &'a str,
    matched_keyword: &'a str,
}

impl ModerationConfig {
    pub(crate) async fn load(pool: &PgPool) -> Result<Self, String> {
        let (raw_config, raw_risk_control) = tokio::try_join!(
            sqlx::query_scalar::<_, String>(
                "SELECT value FROM settings WHERE key = 'content_moderation_config'",
            )
            .fetch_optional(pool),
            sqlx::query_scalar::<_, String>(
                "SELECT value FROM settings WHERE key = 'risk_control_enabled'",
            )
            .fetch_optional(pool),
        )
        .map_err(|error| format!("load content moderation settings: {error}"))?;
        let risk_control_enabled = raw_risk_control.as_deref().is_some_and(parse_setting_bool);
        Self::parse(raw_config.as_deref(), risk_control_enabled)
    }

    fn parse(raw: Option<&str>, risk_control_enabled: bool) -> Result<Self, String> {
        let value = match raw.map(str::trim).filter(|value| !value.is_empty()) {
            Some(raw) => serde_json::from_str::<Value>(raw)
                .map_err(|error| format!("content moderation config is invalid JSON: {error}"))?,
            None => Value::Object(Map::new()),
        };
        let object = value
            .as_object()
            .ok_or_else(|| "content moderation config must be an object".to_owned())?;
        let configured_enabled = optional_bool(object, "enabled", false)?;
        let mode = match optional_string(object, "mode", "pre_block")?.as_str() {
            "off" => ModerationMode::Off,
            "observe" => ModerationMode::Observe,
            "pre_block" => ModerationMode::PreBlock,
            _ => return Err("content moderation mode is invalid".to_owned()),
        };
        let base_url = optional_string(object, "base_url", "https://api.openai.com")?;
        validate_base_url(&base_url)?;
        let model = optional_string(object, "model", "omni-moderation-latest")?;
        if model.trim().is_empty() {
            return Err("content moderation model must not be empty".to_owned());
        }
        let mut api_keys = string_array(object.get("api_keys"), "api_keys", 100)?;
        if let Some(key) = object
            .get("api_key")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|key| !key.is_empty())
            && !api_keys.iter().any(|existing| existing == key)
        {
            api_keys.push(key.to_owned());
        }
        let timeout_ms = bounded_u64(object, "timeout_ms", 3_000, 100, 30_000)?;
        let sample_rate = u8::try_from(bounded_u64(object, "sample_rate", 100, 0, 100)?)
            .map_err(|_| "content moderation sample_rate is invalid".to_owned())?;
        let all_groups = optional_bool(object, "all_groups", true)?;
        let group_ids = integer_array(object.get("group_ids"), "group_ids", 10_000)?;
        let record_non_hits = optional_bool(object, "record_non_hits", false)?;
        let thresholds = parse_thresholds(object.get("thresholds"))?;
        let block_status_raw =
            u16::try_from(bounded_u64(object, "block_status", 403, 400, 599)?)
                .map_err(|_| "content moderation block_status is invalid".to_owned())?;
        let block_status = StatusCode::from_u16(block_status_raw)
            .map_err(|_| "content moderation block_status is invalid".to_owned())?;
        let block_message = optional_string(object, "block_message", DEFAULT_BLOCK_MESSAGE)?;
        let retry_count = usize::try_from(bounded_u64(object, "retry_count", 2, 0, 5)?)
            .map_err(|_| "content moderation retry_count is invalid".to_owned())?;
        let pre_hash_check_enabled = optional_bool(object, "pre_hash_check_enabled", false)?;
        let blocked_keywords =
            string_array(object.get("blocked_keywords"), "blocked_keywords", 10_000)?;
        let keyword_mode =
            match optional_string(object, "keyword_blocking_mode", "keyword_and_api")?.as_str() {
                "keyword_only" => KeywordMode::KeywordOnly,
                "keyword_and_api" => KeywordMode::KeywordAndApi,
                "api_only" => KeywordMode::ApiOnly,
                _ => return Err("content moderation keyword mode is invalid".to_owned()),
            };
        let model_filter = parse_model_filter(object.get("model_filter"))?;
        Ok(Self {
            enabled: configured_enabled && risk_control_enabled && mode != ModerationMode::Off,
            mode,
            base_url,
            model,
            api_keys,
            timeout: Duration::from_millis(timeout_ms),
            sample_rate,
            all_groups,
            group_ids,
            record_non_hits,
            thresholds,
            block_status,
            block_message,
            retry_count,
            pre_hash_check_enabled,
            blocked_keywords,
            keyword_mode,
            model_filter,
        })
    }

    pub(crate) const fn enabled(&self) -> bool {
        self.enabled
    }

    fn includes_group(&self, group_id: Option<i64>) -> bool {
        self.all_groups || group_id.is_some_and(|id| self.group_ids.contains(&id))
    }

    fn includes_model(&self, model: &str) -> bool {
        match &self.model_filter {
            ModelFilter::All => true,
            ModelFilter::Include(models) => models.iter().any(|candidate| candidate == model),
            ModelFilter::Exclude(models) => !models.iter().any(|candidate| candidate == model),
        }
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) async fn enforce(
    client: &Client,
    pool: &PgPool,
    config: ModerationConfig,
    auth: &AuthContext,
    route: &GatewayRoute,
    metadata: &RequestMetadata,
    body: &[u8],
) -> Result<ModerationOutcome, String> {
    if !config.enabled() {
        return Ok(ModerationOutcome::Allow);
    }
    let api_key = auth
        .api_key
        .as_ref()
        .ok_or_else(|| "authenticated moderation request has no API key".to_owned())?;
    let group_id = api_key.group_id;
    let model = metadata.model.as_deref().unwrap_or_default();
    if !config.includes_group(group_id) || !config.includes_model(model) {
        return Ok(ModerationOutcome::Allow);
    }
    let content = extract_content(route.kind, body)?;
    if content.text.is_empty() && content.images.is_empty() {
        return Ok(ModerationOutcome::Allow);
    }
    let input_hash = content_hash(&content);
    let audit = ModerationAuditContext {
        request_id: request_id_from_body(body),
        user_id: auth.user.id,
        user_email: auth.user.email.clone(),
        api_key_id: api_key.id,
        api_key_name: api_key.name.clone(),
        group_id,
        group_name: auth
            .group
            .as_ref()
            .map_or_else(String::new, |group| group.name.clone()),
        endpoint: route.upstream_path.clone(),
        provider: provider_name(route.kind).to_owned(),
        model: model.to_owned(),
    };

    if config.mode == ModerationMode::PreBlock
        && config.keyword_mode != KeywordMode::ApiOnly
        && let Some(keyword) = matching_keyword(&content.text, &config.blocked_keywords)
    {
        let scores = BTreeMap::from([("keyword".to_owned(), 1.0)]);
        persist_log_and_hash(
            pool,
            &audit,
            &config,
            &input_hash,
            true,
            LogRecord {
                action: "keyword_block",
                flagged: true,
                highest_category: "keyword",
                highest_score: 1.0,
                scores: &scores,
                excerpt: &content.text,
                latency_ms: None,
                error: "",
                matched_keyword: keyword,
            },
        )
        .await?;
        return Ok(block(&config));
    }
    if config.mode == ModerationMode::PreBlock && config.keyword_mode == KeywordMode::KeywordOnly {
        return Ok(ModerationOutcome::Allow);
    }

    if config.pre_hash_check_enabled {
        let already_flagged = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM content_moderation_flagged_hashes WHERE input_hash = $1)",
        )
        .bind(&input_hash)
        .fetch_one(pool)
        .await
        .map_err(|error| format!("check content moderation hash: {error}"))?;
        if already_flagged {
            let scores = BTreeMap::from([("hash".to_owned(), 1.0)]);
            persist_log_and_hash(
                pool,
                &audit,
                &config,
                &input_hash,
                false,
                LogRecord {
                    action: "hash_block",
                    flagged: true,
                    highest_category: "hash",
                    highest_score: 1.0,
                    scores: &scores,
                    excerpt: &content.text,
                    latency_ms: None,
                    error: "",
                    matched_keyword: "",
                },
            )
            .await?;
            return Ok(block(&config));
        }
    }
    if !sampled(&input_hash, config.sample_rate) {
        return Ok(ModerationOutcome::Allow);
    }
    if config.api_keys.is_empty() {
        if config.mode == ModerationMode::PreBlock {
            persist_fail_closed(
                pool,
                &audit,
                &config,
                &content,
                &input_hash,
                None,
                "no moderation API key is configured",
            )
            .await?;
            return Ok(block(&config));
        }
        return Ok(ModerationOutcome::Allow);
    }

    if config.mode == ModerationMode::Observe {
        let client = client.clone();
        let pool = pool.clone();
        tokio::spawn(async move {
            if let Err(error) =
                audit_and_persist(&client, &pool, &audit, &config, &content, &input_hash).await
            {
                tracing::warn!(error = %error, "observe content moderation failed");
            }
        });
        return Ok(ModerationOutcome::Allow);
    }

    match call_moderation(client, &config, &content).await {
        Ok(result) => {
            let (score_flagged, highest_category, highest_score) =
                evaluate_scores(&result.category_scores, &config.thresholds);
            let flagged = result.provider_flagged || score_flagged;
            if flagged || config.record_non_hits {
                persist_log_and_hash(
                    pool,
                    &audit,
                    &config,
                    &input_hash,
                    flagged,
                    LogRecord {
                        action: if flagged { "block" } else { "allow" },
                        flagged,
                        highest_category: &highest_category,
                        highest_score,
                        scores: &result.category_scores,
                        excerpt: &content.text,
                        latency_ms: Some(result.latency_ms),
                        error: "",
                        matched_keyword: "",
                    },
                )
                .await?;
            }
            Ok(if flagged {
                block(&config)
            } else {
                ModerationOutcome::Allow
            })
        }
        Err(error) => {
            persist_fail_closed(pool, &audit, &config, &content, &input_hash, None, &error).await?;
            Ok(block(&config))
        }
    }
}

async fn audit_and_persist(
    client: &Client,
    pool: &PgPool,
    audit: &ModerationAuditContext,
    config: &ModerationConfig,
    content: &ModerationContent,
    input_hash: &str,
) -> Result<(), String> {
    match call_moderation(client, config, content).await {
        Ok(result) => {
            let (score_flagged, highest_category, highest_score) =
                evaluate_scores(&result.category_scores, &config.thresholds);
            let flagged = result.provider_flagged || score_flagged;
            if flagged || config.record_non_hits {
                persist_log_and_hash(
                    pool,
                    audit,
                    config,
                    input_hash,
                    flagged,
                    LogRecord {
                        action: "allow",
                        flagged,
                        highest_category: &highest_category,
                        highest_score,
                        scores: &result.category_scores,
                        excerpt: &content.text,
                        latency_ms: Some(result.latency_ms),
                        error: "",
                        matched_keyword: "",
                    },
                )
                .await?;
            }
            Ok(())
        }
        Err(error) if config.record_non_hits => {
            let scores = BTreeMap::new();
            persist_log_and_hash(
                pool,
                audit,
                config,
                input_hash,
                false,
                LogRecord {
                    action: "error",
                    flagged: false,
                    highest_category: "",
                    highest_score: 0.0,
                    scores: &scores,
                    excerpt: &content.text,
                    latency_ms: None,
                    error: &error,
                    matched_keyword: "",
                },
            )
            .await
        }
        Err(error) => Err(error),
    }
}

async fn persist_fail_closed(
    pool: &PgPool,
    audit: &ModerationAuditContext,
    config: &ModerationConfig,
    content: &ModerationContent,
    input_hash: &str,
    latency_ms: Option<i32>,
    error: &str,
) -> Result<(), String> {
    let scores = BTreeMap::from([("moderation_error".to_owned(), 1.0)]);
    persist_log_and_hash(
        pool,
        audit,
        config,
        input_hash,
        true,
        LogRecord {
            action: "error",
            flagged: true,
            highest_category: "moderation_error",
            highest_score: 1.0,
            scores: &scores,
            excerpt: &content.text,
            latency_ms,
            error,
            matched_keyword: "",
        },
    )
    .await
}

async fn call_moderation(
    client: &Client,
    config: &ModerationConfig,
    content: &ModerationContent,
) -> Result<ModerationResult, String> {
    let endpoint = moderation_endpoint(&config.base_url)?;
    let input = if content.images.is_empty() {
        Value::String(content.text.clone())
    } else {
        let mut parts = Vec::with_capacity(2);
        if !content.text.is_empty() {
            parts.push(json!({"type": "text", "text": content.text.clone()}));
        }
        parts.push(json!({
            "type": "image_url",
            "image_url": {"url": content.images[0].clone()},
        }));
        Value::Array(parts)
    };
    let payload = json!({"model": config.model, "input": input});
    let attempts = config.retry_count.saturating_add(1);
    let mut last_error = "moderation API request failed".to_owned();
    for attempt in 0..attempts {
        let key = &config.api_keys[attempt % config.api_keys.len()];
        let started = std::time::Instant::now();
        let request = client
            .post(endpoint.clone())
            .bearer_auth(key)
            .json(&payload)
            .send();
        let response = match tokio::time::timeout(config.timeout, request).await {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                last_error = format!("moderation API request failed: {error}");
                continue;
            }
            Err(_) => {
                "moderation API request timed out".clone_into(&mut last_error);
                continue;
            }
        };
        let status = response.status();
        let body = read_response_limited(response).await?;
        if !status.is_success() {
            last_error = format!(
                "moderation API returned {status}: {}",
                String::from_utf8_lossy(&body).trim()
            );
            if status == StatusCode::BAD_REQUEST {
                break;
            }
            continue;
        }
        let value: Value = serde_json::from_slice(&body)
            .map_err(|error| format!("moderation API returned invalid JSON: {error}"))?;
        let result = value
            .get("results")
            .and_then(Value::as_array)
            .and_then(|results| results.first())
            .and_then(Value::as_object)
            .ok_or_else(|| "moderation API returned empty results".to_owned())?;
        let provider_flagged = result
            .get("flagged")
            .and_then(Value::as_bool)
            .ok_or_else(|| "moderation API result has no boolean flagged field".to_owned())?;
        let score_object = result
            .get("category_scores")
            .and_then(Value::as_object)
            .ok_or_else(|| "moderation API result has no category_scores object".to_owned())?;
        let mut category_scores = BTreeMap::new();
        for (category, score) in score_object {
            let score = score
                .as_f64()
                .filter(|score| score.is_finite() && (0.0..=1.0).contains(score))
                .ok_or_else(|| format!("moderation score for {category} is invalid"))?;
            category_scores.insert(category.clone(), score);
        }
        if category_scores.is_empty() {
            return Err("moderation API returned no category scores".to_owned());
        }
        return Ok(ModerationResult {
            provider_flagged,
            category_scores,
            latency_ms: i32::try_from(started.elapsed().as_millis()).unwrap_or(i32::MAX),
        });
    }
    Err(last_error)
}

async fn read_response_limited(response: reqwest::Response) -> Result<Vec<u8>, String> {
    use futures_util::StreamExt;

    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| format!("read moderation API response: {error}"))?;
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err("moderation API response exceeded 1 MiB".to_owned());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn persist_log_and_hash(
    pool: &PgPool,
    audit: &ModerationAuditContext,
    config: &ModerationConfig,
    input_hash: &str,
    record_hash: bool,
    record: LogRecord<'_>,
) -> Result<(), String> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|error| format!("begin content moderation audit: {error}"))?;
    if record_hash {
        sqlx::query(
            "INSERT INTO content_moderation_flagged_hashes (input_hash, created_at) VALUES ($1, NOW()) ON CONFLICT (input_hash) DO UPDATE SET created_at = EXCLUDED.created_at",
        )
        .bind(input_hash)
        .execute(&mut *transaction)
        .await
        .map_err(|error| format!("record content moderation hash: {error}"))?;
    }
    let scores = serde_json::to_string(record.scores)
        .map_err(|error| format!("encode moderation scores: {error}"))?;
    let thresholds = serde_json::to_string(&config.thresholds)
        .map_err(|error| format!("encode moderation thresholds: {error}"))?;
    sqlx::query(
        r"
INSERT INTO content_moderation_logs (
    request_id, user_id, user_email, api_key_id, api_key_name, group_id, group_name,
    endpoint, provider, model, mode, action, flagged, highest_category, highest_score,
    category_scores, threshold_snapshot, input_excerpt, upstream_latency_ms, error,
    violation_count, auto_banned, email_sent, queue_delay_ms, matched_keyword
) VALUES (
    $1, $2, $3, $4, $5, $6, $7,
    $8, $9, $10, $11, $12, $13, $14, $15,
    $16::jsonb, $17::jsonb, $18, $19, $20,
    0, FALSE, FALSE, NULL, $21
)
",
    )
    .bind(&audit.request_id)
    .bind(audit.user_id)
    .bind(&audit.user_email)
    .bind(audit.api_key_id)
    .bind(&audit.api_key_name)
    .bind(audit.group_id)
    .bind(&audit.group_name)
    .bind(&audit.endpoint)
    .bind(&audit.provider)
    .bind(&audit.model)
    .bind(match config.mode {
        ModerationMode::Off => "off",
        ModerationMode::Observe => "observe",
        ModerationMode::PreBlock => "pre_block",
    })
    .bind(record.action)
    .bind(record.flagged)
    .bind(record.highest_category)
    .bind(record.highest_score)
    .bind(scores)
    .bind(thresholds)
    .bind(truncate_chars(record.excerpt, MAX_EXCERPT_CHARS))
    .bind(record.latency_ms)
    .bind(truncate_chars(record.error, 2_000))
    .bind(truncate_chars(record.matched_keyword, 255))
    .execute(&mut *transaction)
    .await
    .map_err(|error| format!("record content moderation log: {error}"))?;
    transaction
        .commit()
        .await
        .map_err(|error| format!("commit content moderation audit: {error}"))?;
    Ok(())
}

fn extract_content(kind: RouteKind, body: &[u8]) -> Result<ModerationContent, String> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|error| format!("request body is invalid JSON for moderation: {error}"))?;
    let mut content = ModerationContent::default();
    match kind {
        RouteKind::AnthropicMessages | RouteKind::OpenAiChatCompletions => {
            let last = value
                .get("messages")
                .and_then(Value::as_array)
                .and_then(|messages| messages.last());
            if last
                .and_then(|message| message.get("role"))
                .and_then(Value::as_str)
                == Some("user")
            {
                collect_content(
                    last.and_then(|message| message.get("content")),
                    &mut content,
                );
            }
        }
        RouteKind::OpenAiResponses | RouteKind::OpenAiResponsesCompact => {
            let input = value.get("input");
            match input {
                Some(Value::String(text)) => push_text(&mut content, text),
                Some(Value::Array(items)) => {
                    if let Some(last) = items.last()
                        && last
                            .get("role")
                            .and_then(Value::as_str)
                            .is_none_or(|role| role == "user")
                    {
                        collect_content(last.get("content").or(Some(last)), &mut content);
                    }
                }
                Some(Value::Object(_)) => collect_content(input, &mut content),
                _ => {}
            }
        }
        RouteKind::GeminiGenerateContent | RouteKind::GeminiStreamGenerateContent => {
            if let Some(last) = value
                .get("contents")
                .and_then(Value::as_array)
                .and_then(|contents| contents.last())
                && last
                    .get("role")
                    .and_then(Value::as_str)
                    .is_none_or(|role| role == "user")
            {
                collect_content(last.get("parts"), &mut content);
            }
        }
        RouteKind::OpenAiImageGenerations
        | RouteKind::OpenAiImageEdits
        | RouteKind::OpenAiVideoGenerations => {
            if let Some(prompt) = value.get("prompt").and_then(Value::as_str) {
                push_text(&mut content, prompt);
            }
        }
        _ => {}
    }
    content.text = normalize_text(&content.text);
    content.text = truncate_chars(&content.text, MAX_INPUT_CHARS);
    content.images.sort();
    content.images.dedup();
    Ok(content)
}

fn collect_content(value: Option<&Value>, output: &mut ModerationContent) {
    let Some(value) = value else { return };
    match value {
        Value::String(text) => push_text(output, text),
        Value::Array(values) => {
            for value in values {
                collect_content(Some(value), output);
            }
        }
        Value::Object(object) => {
            if let Some(text) = object.get("text").and_then(Value::as_str) {
                push_text(output, text);
            }
            if let Some(content) = object.get("content") {
                collect_content(Some(content), output);
            }
            for image in [
                nested_string(object, &["image_url", "url"]),
                object.get("image_url").and_then(Value::as_str),
                object.get("url").and_then(Value::as_str),
                nested_string(object, &["fileData", "fileUri"]),
                nested_string(object, &["file_data", "file_uri"]),
            ]
            .into_iter()
            .flatten()
            {
                push_image(output, image);
            }
            for (mime, data) in [
                (
                    nested_string(object, &["source", "media_type"]),
                    nested_string(object, &["source", "data"]),
                ),
                (
                    nested_string(object, &["inlineData", "mimeType"]),
                    nested_string(object, &["inlineData", "data"]),
                ),
                (
                    nested_string(object, &["inline_data", "mime_type"]),
                    nested_string(object, &["inline_data", "data"]),
                ),
            ] {
                if let (Some(mime), Some(data)) = (mime, data) {
                    push_image(output, &format!("data:{mime};base64,{data}"));
                }
            }
        }
        _ => {}
    }
}

fn push_text(output: &mut ModerationContent, text: &str) {
    let text = text.trim();
    if text.is_empty() || text.contains("<system-reminder>") {
        return;
    }
    if !output.text.is_empty() {
        output.text.push('\n');
    }
    output.text.push_str(text);
}

fn nested_string<'a>(object: &'a Map<String, Value>, path: &[&str]) -> Option<&'a str> {
    let mut value = object.get(*path.first()?)?;
    for key in &path[1..] {
        value = value.get(*key)?;
    }
    value.as_str()
}

fn push_image(output: &mut ModerationContent, image: &str) {
    let image = image.trim();
    if image.starts_with("data:") || image.starts_with("http://") || image.starts_with("https://") {
        output.images.push(image.to_owned());
    }
}

fn content_hash(content: &ModerationContent) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"text:");
    hasher.update(content.text.as_bytes());
    for image in &content.images {
        let image_hash = Sha256::digest(image.as_bytes());
        hasher.update(b"\nimage:");
        hasher.update(hex::encode(image_hash).as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn sampled(hash: &str, rate: u8) -> bool {
    if rate >= 100 {
        return true;
    }
    if rate == 0 {
        return false;
    }
    hex::decode(hash)
        .ok()
        .filter(|bytes| bytes.len() >= 2)
        .is_none_or(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]) % 100 < u16::from(rate))
}

fn evaluate_scores(
    scores: &BTreeMap<String, f64>,
    thresholds: &BTreeMap<String, f64>,
) -> (bool, String, f64) {
    let mut flagged = false;
    let mut highest = String::new();
    let mut highest_score = 0.0;
    for (category, score) in scores {
        if highest.is_empty() || *score > highest_score {
            highest.clone_from(category);
            highest_score = *score;
        }
        if thresholds
            .get(category)
            .is_some_and(|threshold| score >= threshold)
        {
            flagged = true;
        }
    }
    (flagged, highest, highest_score)
}

fn block(config: &ModerationConfig) -> ModerationOutcome {
    ModerationOutcome::Block {
        status: config.block_status,
        message: if config.block_message.trim().is_empty() {
            DEFAULT_BLOCK_MESSAGE.to_owned()
        } else {
            config.block_message.clone()
        },
    }
}

fn matching_keyword<'a>(text: &str, keywords: &'a [String]) -> Option<&'a str> {
    let text = text.to_lowercase();
    keywords
        .iter()
        .find(|keyword| !keyword.is_empty() && text.contains(&keyword.to_lowercase()))
        .map(String::as_str)
}

fn provider_name(kind: RouteKind) -> &'static str {
    match kind {
        RouteKind::AnthropicMessages | RouteKind::AnthropicCountTokens => "anthropic",
        RouteKind::GeminiGenerateContent
        | RouteKind::GeminiStreamGenerateContent
        | RouteKind::GeminiCountTokens
        | RouteKind::GeminiListModels
        | RouteKind::GeminiGetModel => "gemini",
        _ => "openai",
    }
}

fn request_id_from_body(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    format!("mod_{}", hex::encode(&digest[..12]))
}

fn moderation_endpoint(base_url: &str) -> Result<url::Url, String> {
    let mut endpoint = url::Url::parse(base_url)
        .map_err(|error| format!("moderation base URL is invalid: {error}"))?;
    let base_path = endpoint.path().trim_end_matches('/').to_owned();
    endpoint.set_path(&format!("{base_path}/v1/moderations"));
    endpoint.set_query(None);
    endpoint.set_fragment(None);
    Ok(endpoint)
}

fn validate_base_url(base_url: &str) -> Result<(), String> {
    let parsed = url::Url::parse(base_url)
        .map_err(|error| format!("moderation base URL is invalid: {error}"))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err("moderation base URL must be HTTP(S)".to_owned());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("moderation base URL must not contain credentials".to_owned());
    }
    Ok(())
}

fn parse_thresholds(value: Option<&Value>) -> Result<BTreeMap<String, f64>, String> {
    let defaults = [
        ("harassment", 0.98),
        ("harassment/threatening", 0.90),
        ("hate", 0.65),
        ("hate/threatening", 0.65),
        ("illicit", 0.95),
        ("illicit/violent", 0.95),
        ("self-harm", 0.65),
        ("self-harm/intent", 0.85),
        ("self-harm/instructions", 0.65),
        ("sexual", 0.65),
        ("sexual/minors", 0.65),
        ("violence", 0.95),
        ("violence/graphic", 0.95),
    ];
    let mut thresholds = defaults
        .into_iter()
        .map(|(category, score)| (category.to_owned(), score))
        .collect::<BTreeMap<_, _>>();
    let Some(value) = value else {
        return Ok(thresholds);
    };
    let object = value
        .as_object()
        .ok_or_else(|| "content moderation thresholds must be an object".to_owned())?;
    for category in CATEGORIES {
        if let Some(score) = object.get(*category) {
            let score = score
                .as_f64()
                .filter(|score| score.is_finite() && (0.0..=1.0).contains(score))
                .ok_or_else(|| format!("content moderation threshold for {category} is invalid"))?;
            thresholds.insert((*category).to_owned(), score);
        }
    }
    Ok(thresholds)
}

fn parse_model_filter(value: Option<&Value>) -> Result<ModelFilter, String> {
    let Some(value) = value else {
        return Ok(ModelFilter::All);
    };
    let object = value
        .as_object()
        .ok_or_else(|| "content moderation model_filter must be an object".to_owned())?;
    let filter_type = optional_string(object, "type", "all")?;
    let models = string_array(object.get("models"), "model_filter.models", 1_000)?;
    match filter_type.as_str() {
        "all" => Ok(ModelFilter::All),
        "include" if !models.is_empty() => Ok(ModelFilter::Include(models)),
        "exclude" if !models.is_empty() => Ok(ModelFilter::Exclude(models)),
        "include" | "exclude" => Err("content moderation model filter is empty".to_owned()),
        _ => Err("content moderation model filter type is invalid".to_owned()),
    }
}

fn string_array(value: Option<&Value>, field: &str, limit: usize) -> Result<Vec<String>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| format!("content moderation {field} must be an array"))?;
    if values.len() > limit {
        return Err(format!("content moderation {field} is too large"));
    }
    let mut output = Vec::with_capacity(values.len());
    for value in values {
        let value = value
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("content moderation {field} contains an invalid value"))?;
        if !output.iter().any(|existing| existing == value) {
            output.push(value.to_owned());
        }
    }
    Ok(output)
}

fn integer_array(value: Option<&Value>, field: &str, limit: usize) -> Result<Vec<i64>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| format!("content moderation {field} must be an array"))?;
    if values.len() > limit {
        return Err(format!("content moderation {field} is too large"));
    }
    values
        .iter()
        .map(|value| {
            value
                .as_i64()
                .filter(|value| *value > 0)
                .ok_or_else(|| format!("content moderation {field} contains an invalid ID"))
        })
        .collect()
}

fn optional_string(
    object: &Map<String, Value>,
    field: &str,
    default: &str,
) -> Result<String, String> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(default.to_owned()),
        Some(Value::String(value)) => Ok(value.trim().to_owned()),
        Some(_) => Err(format!("content moderation {field} must be a string")),
    }
}

fn optional_bool(object: &Map<String, Value>, field: &str, default: bool) -> Result<bool, String> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(format!("content moderation {field} must be boolean")),
    }
}

fn bounded_u64(
    object: &Map<String, Value>,
    field: &str,
    default: u64,
    minimum: u64,
    maximum: u64,
) -> Result<u64, String> {
    let value = match object.get(field) {
        None | Some(Value::Null) => default,
        Some(value) => value
            .as_u64()
            .ok_or_else(|| format!("content moderation {field} must be an integer"))?,
    };
    if (minimum..=maximum).contains(&value) {
        Ok(value)
    } else {
        Err(format!(
            "content moderation {field} is outside its valid range"
        ))
    }
}

fn parse_setting_bool(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn normalize_text(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn truncate_chars(value: &str, limit: usize) -> String {
    value.chars().take(limit).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_latest_multimodal_user_turn() {
        let content = extract_content(
            RouteKind::OpenAiChatCompletions,
            br#"{"messages":[{"role":"user","content":"old"},{"role":"assistant","content":"answer"},{"role":"user","content":[{"type":"text","text":"new prompt"},{"type":"image_url","image_url":{"url":"https://example.test/image.png"}}]}]}"#,
        )
        .expect("content should parse");
        assert_eq!(content.text, "new prompt");
        assert_eq!(
            content.images,
            vec!["https://example.test/image.png".to_owned()]
        );
    }

    #[test]
    fn malformed_enabled_config_fails_closed_during_load() {
        let error = ModerationConfig::parse(Some(r#"{"enabled":"yes"}"#), true)
            .expect_err("invalid enabled type must fail");
        assert!(error.contains("enabled"));
    }

    #[test]
    fn deterministic_sampling_matches_hash_prefix() {
        assert!(sampled(&format!("0000{}", "0".repeat(60)), 1));
        assert!(!sampled(&format!("0063{}", "0".repeat(60)), 1));
    }
}
