#![allow(clippy::too_many_lines)]

use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderName, HeaderValue},
    response::Response,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::{StreamExt, future::join_all};
use rand::{RngCore, rngs::OsRng};
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgPool, Row, postgres::PgRow};
use url::Url;

use super::shared::{
    Envelope, created, json_text, normalize_api_mode, normalize_body_config, normalize_headers,
    normalize_provider, success, trim_to,
};
use crate::admin_api::{
    http::AdminApiState,
    models::{AdminError, AdminIdentity, Page, PageQuery, Patch, ValidatedProbeTarget},
    service::validate_public_probe_target,
};
use crate::security::secrets;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(45);
const PING_TIMEOUT: Duration = Duration::from_secs(8);
const DEGRADED_MILLIS: u128 = 6_000;
const RESPONSE_LIMIT: usize = 64 * 1024;

pub(super) fn router() -> Router<AdminApiState> {
    Router::new()
        .route("/api/v1/admin/channel-monitors", get(list).post(create))
        .route(
            "/api/v1/admin/channel-monitors/{id}",
            get(get_one).put(update).delete(delete_one),
        )
        .route("/api/v1/admin/channel-monitors/{id}/run", post(run))
        .route("/api/v1/admin/channel-monitors/{id}/history", get(history))
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    #[serde(default = "default_page")]
    page: i64,
    #[serde(default = "default_page_size")]
    page_size: i64,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    search: Option<String>,
}

const fn default_page() -> i64 {
    1
}

const fn default_page_size() -> i64 {
    20
}

#[derive(Debug, Deserialize)]
struct CreateRequest {
    name: String,
    provider: String,
    #[serde(default)]
    api_mode: String,
    endpoint: String,
    api_key: String,
    primary_model: String,
    #[serde(default)]
    extra_models: Vec<String>,
    #[serde(default)]
    group_name: String,
    #[serde(default = "default_true")]
    enabled: bool,
    interval_seconds: i32,
    #[serde(default)]
    jitter_seconds: i32,
    #[serde(default)]
    template_id: Option<i64>,
    #[serde(default)]
    extra_headers: BTreeMap<String, String>,
    #[serde(default)]
    body_override_mode: String,
    #[serde(default)]
    body_override: Option<Value>,
}

const fn default_true() -> bool {
    true
}

#[derive(Debug, Default, Deserialize)]
struct UpdateRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    api_mode: Option<String>,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    api_key: Option<String>,
    #[serde(default)]
    primary_model: Option<String>,
    #[serde(default)]
    extra_models: Option<Vec<String>>,
    #[serde(default)]
    group_name: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    interval_seconds: Option<i32>,
    #[serde(default)]
    jitter_seconds: Option<i32>,
    #[serde(default)]
    template_id: Option<i64>,
    #[serde(default)]
    clear_template: bool,
    #[serde(default)]
    extra_headers: Option<BTreeMap<String, String>>,
    #[serde(default)]
    body_override_mode: Option<String>,
    #[serde(default)]
    body_override: Patch<Value>,
}

#[derive(Clone, Debug, Serialize)]
struct ExtraModelStatus {
    model: String,
    status: String,
    latency_ms: Option<i32>,
}

#[derive(Clone, Debug, Serialize)]
struct MonitorView {
    id: i64,
    name: String,
    provider: String,
    api_mode: String,
    endpoint: String,
    api_key_masked: String,
    api_key_decrypt_failed: bool,
    primary_model: String,
    extra_models: Vec<String>,
    group_name: String,
    enabled: bool,
    interval_seconds: i32,
    jitter_seconds: i32,
    last_checked_at: Option<String>,
    created_by: i64,
    created_at: String,
    updated_at: String,
    primary_status: String,
    primary_latency_ms: Option<i32>,
    availability_7d: f64,
    extra_models_status: Vec<ExtraModelStatus>,
    template_id: Option<i64>,
    extra_headers: BTreeMap<String, String>,
    body_override_mode: String,
    body_override: Option<Value>,
}

#[derive(Clone, Debug)]
struct MonitorRecord {
    view: MonitorView,
    encrypted_api_key: String,
    plain_api_key: Option<String>,
}

#[derive(Clone, Debug)]
struct MonitorConfig {
    provider: String,
    api_mode: String,
    endpoint: String,
    api_key: String,
    extra_headers: BTreeMap<String, String>,
    body_override_mode: String,
    body_override: Option<Value>,
}

#[derive(Clone, Debug, Serialize)]
struct CheckResult {
    model: String,
    status: String,
    latency_ms: Option<i32>,
    ping_latency_ms: Option<i32>,
    message: String,
    checked_at: String,
}

const MONITOR_COLUMNS: &str = r"
m.id, m.name, m.provider, m.api_mode, m.endpoint, m.api_key_encrypted,
m.primary_model, m.extra_models::text AS extra_models_json, m.group_name,
m.enabled, m.interval_seconds, m.jitter_seconds, m.last_checked_at::text AS last_checked_at,
m.created_by, m.created_at::text AS created_at, m.updated_at::text AS updated_at,
m.template_id, m.extra_headers::text AS extra_headers_json,
m.body_override_mode, m.body_override::text AS body_override_json,
COALESCE((SELECT h.status FROM channel_monitor_histories h
          WHERE h.monitor_id = m.id AND h.model = m.primary_model
          ORDER BY h.checked_at DESC, h.id DESC LIMIT 1), '') AS primary_status,
(SELECT h.latency_ms FROM channel_monitor_histories h
 WHERE h.monitor_id = m.id AND h.model = m.primary_model
 ORDER BY h.checked_at DESC, h.id DESC LIMIT 1) AS primary_latency_ms,
COALESCE((SELECT 100.0 * COUNT(*) FILTER (WHERE h.status IN ('operational', 'degraded'))
                 / NULLIF(COUNT(*), 0)
          FROM channel_monitor_histories h
          WHERE h.monitor_id = m.id AND h.model = m.primary_model
            AND h.checked_at >= NOW() - INTERVAL '7 days'), 0)::double precision AS availability_7d";

async fn list(
    State(state): State<AdminApiState>,
    Query(mut query): Query<ListQuery>,
) -> Result<Json<Envelope<Page<MonitorView>>>, AdminError> {
    query.page = query.page.max(1);
    query.page_size = query.page_size.clamp(1, 100);
    let provider = query
        .provider
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let Some(provider) = provider {
        normalize_provider(provider)?;
    }
    let search = query
        .search
        .as_deref()
        .map(|value| trim_to(value, 200))
        .filter(|value| !value.is_empty())
        .map(|value| like_pattern(&value));
    let total = sqlx::query_scalar::<_, i64>(
        r"SELECT COUNT(*) FROM channel_monitors m
          WHERE ($1::text IS NULL OR m.provider = $1)
            AND ($2::boolean IS NULL OR m.enabled = $2)
            AND ($3::text IS NULL OR m.name ILIKE $3 OR m.endpoint ILIKE $3
                 OR m.primary_model ILIKE $3 OR m.group_name ILIKE $3)",
    )
    .bind(provider)
    .bind(query.enabled)
    .bind(search.as_deref())
    .fetch_one(state.service.pool())
    .await?;
    let ids = sqlx::query_scalar::<_, i64>(
        r"SELECT m.id FROM channel_monitors m
          WHERE ($1::text IS NULL OR m.provider = $1)
            AND ($2::boolean IS NULL OR m.enabled = $2)
            AND ($3::text IS NULL OR m.name ILIKE $3 OR m.endpoint ILIKE $3
                 OR m.primary_model ILIKE $3 OR m.group_name ILIKE $3)
          ORDER BY m.id DESC LIMIT $4 OFFSET $5",
    )
    .bind(provider)
    .bind(query.enabled)
    .bind(search.as_deref())
    .bind(query.page_size)
    .bind((query.page - 1) * query.page_size)
    .fetch_all(state.service.pool())
    .await?;
    let mut items = Vec::with_capacity(ids.len());
    for id in ids {
        items.push(fetch_monitor(state.service.pool(), id).await?.view);
    }
    let page_query = PageQuery {
        page: query.page,
        page_size: query.page_size,
        search: None,
        status: None,
        role: None,
        platform: None,
    };
    Ok(Json(Envelope::success(Page::new(
        items,
        total,
        &page_query,
    ))))
}

async fn get_one(
    State(state): State<AdminApiState>,
    Path(id): Path<i64>,
) -> Result<Json<Envelope<MonitorView>>, AdminError> {
    require_id(id)?;
    Ok(Json(Envelope::success(
        fetch_monitor(state.service.pool(), id).await?.view,
    )))
}

async fn create(
    State(state): State<AdminApiState>,
    Extension(identity): Extension<AdminIdentity>,
    Json(request): Json<CreateRequest>,
) -> Result<Response, AdminError> {
    let name = valid_name(&request.name)?;
    let provider = normalize_provider(&request.provider)?;
    let api_mode = normalize_api_mode(&provider, &request.api_mode)?;
    let (endpoint, _) = validate_endpoint(&request.endpoint).await?;
    let api_key = valid_api_key(&request.api_key)?;
    let primary_model = valid_model(&request.primary_model)?;
    let extra_models = normalize_models(&request.extra_models)?;
    let group_name = valid_group_name(&request.group_name)?;
    validate_interval(request.interval_seconds, request.jitter_seconds)?;
    validate_template_id(request.template_id)?;
    let headers = normalize_headers(request.extra_headers)?;
    let (body_mode, body) = normalize_body_config(
        &provider,
        &api_mode,
        &request.body_override_mode,
        request.body_override,
    )?;
    let encrypted_api_key = encrypt_api_key(&api_key)?;
    let extra_models_json = serde_json::to_string(&extra_models)
        .map_err(|error| AdminError::BadRequest(error.to_string()))?;
    let headers_json = serde_json::to_string(&headers)
        .map_err(|error| AdminError::BadRequest(error.to_string()))?;
    let body_json = body
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|error| AdminError::BadRequest(error.to_string()))?;
    let id = sqlx::query_scalar::<_, i64>(
        r"INSERT INTO channel_monitors
          (name, provider, api_mode, endpoint, api_key_encrypted, primary_model,
           extra_models, group_name, enabled, interval_seconds, jitter_seconds,
           created_by, template_id, extra_headers, body_override_mode, body_override)
          VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10, $11, $12,
                  $13, $14::jsonb, $15, $16::jsonb) RETURNING id",
    )
    .bind(name)
    .bind(provider)
    .bind(api_mode)
    .bind(endpoint)
    .bind(encrypted_api_key)
    .bind(primary_model)
    .bind(extra_models_json)
    .bind(group_name)
    .bind(request.enabled)
    .bind(request.interval_seconds)
    .bind(request.jitter_seconds)
    .bind(identity.user_id)
    .bind(request.template_id)
    .bind(headers_json)
    .bind(body_mode)
    .bind(body_json.as_deref())
    .fetch_one(state.service.pool())
    .await?;
    Ok(created(fetch_monitor(state.service.pool(), id).await?.view))
}

async fn update(
    State(state): State<AdminApiState>,
    Path(id): Path<i64>,
    Json(request): Json<UpdateRequest>,
) -> Result<Response, AdminError> {
    require_id(id)?;
    let normalized_endpoint = if let Some(endpoint) = request.endpoint.as_deref() {
        Some(validate_endpoint(endpoint).await?.0)
    } else {
        None
    };
    let mut transaction = state.service.pool().begin().await?;
    let sql =
        format!("SELECT {MONITOR_COLUMNS} FROM channel_monitors m WHERE m.id = $1 FOR UPDATE");
    let row = sqlx::query(&sql)
        .bind(id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(AdminError::NotFound("channel monitor"))?;
    let mut existing = monitor_from_row(&row, Vec::new())?;

    if let Some(name) = request.name.as_deref() {
        existing.view.name = valid_name(name)?;
    }
    let provider_changed = request.provider.is_some();
    if let Some(provider) = request.provider.as_deref() {
        existing.view.provider = normalize_provider(provider)?;
    }
    if let Some(api_mode) = request.api_mode.as_deref() {
        existing.view.api_mode = normalize_api_mode(&existing.view.provider, api_mode)?;
    } else if provider_changed && existing.view.provider != "openai" {
        "chat_completions".clone_into(&mut existing.view.api_mode);
    } else {
        existing.view.api_mode =
            normalize_api_mode(&existing.view.provider, &existing.view.api_mode)?;
    }
    if let Some(endpoint) = normalized_endpoint {
        existing.view.endpoint = endpoint;
    }
    if let Some(primary_model) = request.primary_model.as_deref() {
        existing.view.primary_model = valid_model(primary_model)?;
    }
    if let Some(extra_models) = request.extra_models.as_deref() {
        existing.view.extra_models = normalize_models(extra_models)?;
    }
    if let Some(group_name) = request.group_name.as_deref() {
        existing.view.group_name = valid_group_name(group_name)?;
    }
    if let Some(enabled) = request.enabled {
        existing.view.enabled = enabled;
    }
    if let Some(interval) = request.interval_seconds {
        existing.view.interval_seconds = interval;
    }
    if let Some(jitter) = request.jitter_seconds {
        existing.view.jitter_seconds = jitter;
    }
    validate_interval(existing.view.interval_seconds, existing.view.jitter_seconds)?;
    if request.clear_template {
        existing.view.template_id = None;
    } else if let Some(template_id) = request.template_id {
        validate_template_id(Some(template_id))?;
        existing.view.template_id = Some(template_id);
    }
    if let Some(headers) = request.extra_headers {
        existing.view.extra_headers = normalize_headers(headers)?;
    }
    let body = match request.body_override {
        Patch::Missing => existing.view.body_override,
        Patch::Null => None,
        Patch::Value(value) => Some(value),
    };
    let body_mode = request
        .body_override_mode
        .as_deref()
        .unwrap_or(&existing.view.body_override_mode);
    let (body_mode, body) = normalize_body_config(
        &existing.view.provider,
        &existing.view.api_mode,
        body_mode,
        body,
    )?;
    existing.view.body_override_mode = body_mode;
    existing.view.body_override = body;
    if let Some(api_key) = request.api_key.as_deref()
        && !api_key.trim().is_empty()
    {
        existing.encrypted_api_key = encrypt_api_key(&valid_api_key(api_key)?)?;
    }

    let extra_models_json = serde_json::to_string(&existing.view.extra_models)
        .map_err(|error| AdminError::BadRequest(error.to_string()))?;
    let headers_json = serde_json::to_string(&existing.view.extra_headers)
        .map_err(|error| AdminError::BadRequest(error.to_string()))?;
    let body_json = existing
        .view
        .body_override
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|error| AdminError::BadRequest(error.to_string()))?;
    sqlx::query(
        r"UPDATE channel_monitors SET
             name = $2, provider = $3, api_mode = $4, endpoint = $5,
             api_key_encrypted = $6, primary_model = $7, extra_models = $8::jsonb,
             group_name = $9, enabled = $10, interval_seconds = $11,
             jitter_seconds = $12, template_id = $13, extra_headers = $14::jsonb,
             body_override_mode = $15, body_override = $16::jsonb, updated_at = NOW()
           WHERE id = $1",
    )
    .bind(id)
    .bind(existing.view.name)
    .bind(existing.view.provider)
    .bind(existing.view.api_mode)
    .bind(existing.view.endpoint)
    .bind(existing.encrypted_api_key)
    .bind(existing.view.primary_model)
    .bind(extra_models_json)
    .bind(existing.view.group_name)
    .bind(existing.view.enabled)
    .bind(existing.view.interval_seconds)
    .bind(existing.view.jitter_seconds)
    .bind(existing.view.template_id)
    .bind(headers_json)
    .bind(existing.view.body_override_mode)
    .bind(body_json.as_deref())
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(success(fetch_monitor(state.service.pool(), id).await?.view))
}

async fn delete_one(
    State(state): State<AdminApiState>,
    Path(id): Path<i64>,
) -> Result<Response, AdminError> {
    require_id(id)?;
    let deleted =
        sqlx::query_scalar::<_, i64>("DELETE FROM channel_monitors WHERE id = $1 RETURNING id")
            .bind(id)
            .fetch_optional(state.service.pool())
            .await?;
    if deleted.is_none() {
        return Err(AdminError::NotFound("channel monitor"));
    }
    Ok(success(Value::Null))
}

async fn run(
    State(state): State<AdminApiState>,
    Path(id): Path<i64>,
) -> Result<Response, AdminError> {
    require_id(id)?;
    let monitor = fetch_monitor(state.service.pool(), id).await?;
    let api_key = monitor.plain_api_key.ok_or_else(|| {
        AdminError::Probe(
            "api key decryption failed; re-edit the monitor with a fresh key".to_owned(),
        )
    })?;
    let (_, target) = validate_endpoint(&monitor.view.endpoint).await?;
    let client = pinned_client(&monitor.view.endpoint, &target)?;
    let ping_latency_ms = ping_endpoint(&client, &monitor.view.endpoint).await;
    let config = MonitorConfig {
        provider: monitor.view.provider.clone(),
        api_mode: monitor.view.api_mode.clone(),
        endpoint: monitor.view.endpoint.clone(),
        api_key,
        extra_headers: monitor.view.extra_headers.clone(),
        body_override_mode: monitor.view.body_override_mode.clone(),
        body_override: monitor.view.body_override.clone(),
    };
    let mut models = vec![monitor.view.primary_model];
    models.extend(monitor.view.extra_models);
    let checks = models
        .into_iter()
        .map(|model| check_model(client.clone(), config.clone(), model, ping_latency_ms));
    let results = join_all(checks).await;
    persist_results(state.service.pool(), id, &results).await?;
    Ok(success(json!({"results": results})))
}

#[derive(Debug, Deserialize)]
struct HistoryQuery {
    #[serde(default)]
    model: Option<String>,
    #[serde(default = "default_history_limit")]
    limit: i64,
}

const fn default_history_limit() -> i64 {
    100
}

#[derive(Debug, Serialize)]
struct HistoryItem {
    id: i64,
    model: String,
    status: String,
    latency_ms: Option<i32>,
    ping_latency_ms: Option<i32>,
    message: String,
    checked_at: String,
}

async fn history(
    State(state): State<AdminApiState>,
    Path(id): Path<i64>,
    Query(query): Query<HistoryQuery>,
) -> Result<Response, AdminError> {
    require_id(id)?;
    let exists = sqlx::query_scalar::<_, i64>("SELECT id FROM channel_monitors WHERE id = $1")
        .bind(id)
        .fetch_optional(state.service.pool())
        .await?;
    if exists.is_none() {
        return Err(AdminError::NotFound("channel monitor"));
    }
    let model = query
        .model
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let limit = if query.limit <= 0 {
        default_history_limit()
    } else {
        query.limit.min(1_000)
    };
    let rows = sqlx::query(
        r"SELECT id, model, status, latency_ms, ping_latency_ms, message,
                  checked_at::text AS checked_at
           FROM channel_monitor_histories
           WHERE monitor_id = $1 AND ($2::text IS NULL OR model = $2)
           ORDER BY checked_at DESC, id DESC LIMIT $3",
    )
    .bind(id)
    .bind(model)
    .bind(limit)
    .fetch_all(state.service.pool())
    .await?;
    let items = rows
        .iter()
        .map(|row| {
            Ok(HistoryItem {
                id: row.try_get("id")?,
                model: row.try_get("model")?,
                status: row.try_get("status")?,
                latency_ms: row.try_get("latency_ms")?,
                ping_latency_ms: row.try_get("ping_latency_ms")?,
                message: row.try_get("message")?,
                checked_at: row.try_get("checked_at")?,
            })
        })
        .collect::<Result<Vec<_>, AdminError>>()?;
    Ok(success(json!({"items": items})))
}

async fn fetch_monitor(pool: &PgPool, id: i64) -> Result<MonitorRecord, AdminError> {
    let sql = format!("SELECT {MONITOR_COLUMNS} FROM channel_monitors m WHERE m.id = $1");
    let row = sqlx::query(&sql)
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(AdminError::NotFound("channel monitor"))?;
    let extra_models_json: String = row.try_get("extra_models_json")?;
    let extra_models: Vec<String> = serde_json::from_str(&extra_models_json).unwrap_or_default();
    let extra_status = load_extra_status(pool, id, &extra_models).await?;
    monitor_from_row(&row, extra_status)
}

async fn load_extra_status(
    pool: &PgPool,
    id: i64,
    models: &[String],
) -> Result<Vec<ExtraModelStatus>, AdminError> {
    if models.is_empty() {
        return Ok(Vec::new());
    }
    let rows = sqlx::query(
        r"SELECT DISTINCT ON (model) model, status, latency_ms
          FROM channel_monitor_histories
          WHERE monitor_id = $1 AND model = ANY($2)
          ORDER BY model, checked_at DESC, id DESC",
    )
    .bind(id)
    .bind(models)
    .fetch_all(pool)
    .await?;
    let mut latest = BTreeMap::new();
    for row in rows {
        latest.insert(
            row.try_get::<String, _>("model")?,
            (
                row.try_get::<String, _>("status")?,
                row.try_get::<Option<i32>, _>("latency_ms")?,
            ),
        );
    }
    Ok(models
        .iter()
        .map(|model| {
            let (status, latency_ms) = latest
                .get(model)
                .cloned()
                .unwrap_or_else(|| (String::new(), None));
            ExtraModelStatus {
                model: model.clone(),
                status,
                latency_ms,
            }
        })
        .collect())
}

fn monitor_from_row(
    row: &PgRow,
    extra_models_status: Vec<ExtraModelStatus>,
) -> Result<MonitorRecord, AdminError> {
    let encrypted_api_key: String = row.try_get("api_key_encrypted")?;
    let (plain_api_key, decrypt_failed) = match decrypt_api_key(&encrypted_api_key) {
        Ok(value) => (Some(value), false),
        Err(error) => {
            tracing::warn!(monitor_id = row.try_get::<i64, _>("id")?, %error, "channel monitor API key cannot be decrypted");
            (None, true)
        }
    };
    let extra_models_json: String = row.try_get("extra_models_json")?;
    let headers_json: String = row.try_get("extra_headers_json")?;
    let headers = serde_json::from_str::<BTreeMap<String, String>>(&headers_json)
        .map_err(|error| AdminError::Database(sqlx::Error::Decode(Box::new(error))))?;
    let body_json: Option<String> = row.try_get("body_override_json")?;
    Ok(MonitorRecord {
        view: MonitorView {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            provider: row.try_get("provider")?,
            api_mode: row.try_get("api_mode")?,
            endpoint: row.try_get("endpoint")?,
            api_key_masked: plain_api_key
                .as_deref()
                .map_or_else(|| "***".to_owned(), mask_api_key),
            api_key_decrypt_failed: decrypt_failed,
            primary_model: row.try_get("primary_model")?,
            extra_models: serde_json::from_str(&extra_models_json).unwrap_or_default(),
            group_name: row.try_get("group_name")?,
            enabled: row.try_get("enabled")?,
            interval_seconds: row.try_get("interval_seconds")?,
            jitter_seconds: row.try_get("jitter_seconds")?,
            last_checked_at: row.try_get("last_checked_at")?,
            created_by: row.try_get("created_by")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
            primary_status: row.try_get("primary_status")?,
            primary_latency_ms: row.try_get("primary_latency_ms")?,
            availability_7d: row.try_get("availability_7d")?,
            extra_models_status,
            template_id: row.try_get("template_id")?,
            extra_headers: headers,
            body_override_mode: row.try_get("body_override_mode")?,
            body_override: body_json.as_deref().map(json_text),
        },
        encrypted_api_key,
        plain_api_key,
    })
}

async fn validate_endpoint(raw: &str) -> Result<(String, ValidatedProbeTarget), AdminError> {
    let raw = raw.trim();
    if raw.len() > 500 {
        return Err(AdminError::BadRequest(
            "endpoint must not exceed 500 bytes".to_owned(),
        ));
    }
    let url = Url::parse(raw)
        .map_err(|_| AdminError::BadRequest("endpoint must be a valid HTTPS URL".to_owned()))?;
    if url.scheme() != "https" {
        return Err(AdminError::BadRequest("endpoint must use HTTPS".to_owned()));
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(AdminError::BadRequest(
            "endpoint must be a base origin without credentials, path, query, or fragment"
                .to_owned(),
        ));
    }
    let normalized = raw.trim_end_matches('/').to_owned();
    let target = validate_public_probe_target(&normalized).await?;
    Ok((normalized, target))
}

fn pinned_client(
    endpoint: &str,
    target: &ValidatedProbeTarget,
) -> Result<reqwest::Client, AdminError> {
    let url = Url::parse(endpoint)
        .map_err(|_| AdminError::BadRequest("monitor endpoint is invalid".to_owned()))?;
    let host = url
        .host_str()
        .ok_or_else(|| AdminError::BadRequest("monitor endpoint host is required".to_owned()))?;
    let mut builder = reqwest::Client::builder()
        .redirect(Policy::none())
        .no_proxy()
        .timeout(REQUEST_TIMEOUT);
    if url
        .host()
        .is_some_and(|host| matches!(host, url::Host::Domain(_)))
    {
        builder = builder.resolve_to_addrs(host, target.resolved_addresses());
    }
    builder
        .build()
        .map_err(|error| AdminError::Probe(format!("build monitor HTTP client: {error}")))
}

async fn ping_endpoint(client: &reqwest::Client, endpoint: &str) -> Option<i32> {
    let started = Instant::now();
    client
        .head(endpoint)
        .timeout(PING_TIMEOUT)
        .send()
        .await
        .ok()
        .map(|_| elapsed_millis(started))
}

async fn check_model(
    client: reqwest::Client,
    config: MonitorConfig,
    model: String,
    ping_latency_ms: Option<i32>,
) -> CheckResult {
    let checked_at = chrono::Utc::now().to_rfc3339();
    let (prompt, expected) = challenge();
    let started = Instant::now();
    let outcome = call_provider(&client, &config, &model, &prompt).await;
    let latency_ms = elapsed_millis(started);
    let (status, message) = match outcome {
        Err(message) => ("error".to_owned(), sanitize_message(&message, &config)),
        Ok((status_code, _text, raw)) if !(200..300).contains(&status_code) => (
            "error".to_owned(),
            sanitize_message(
                &format!("upstream HTTP {status_code}: {}", compact_body(&raw)),
                &config,
            ),
        ),
        Ok((_, text, _)) if config.body_override_mode == "replace" => {
            if text.trim().is_empty() {
                (
                    "failed".to_owned(),
                    "replace-mode: upstream returned 2xx with empty text".to_owned(),
                )
            } else {
                healthy_status(latency_ms)
            }
        }
        Ok((_, text, _)) if !challenge_matches(&text, &expected) => (
            "failed".to_owned(),
            truncate_message(&format!(
                "challenge mismatch (expected {expected}, got {text:?})"
            )),
        ),
        Ok(_) => healthy_status(latency_ms),
    };
    CheckResult {
        model,
        status,
        latency_ms: Some(latency_ms),
        ping_latency_ms,
        message,
        checked_at,
    }
}

fn healthy_status(latency_ms: i32) -> (String, String) {
    if u128::try_from(latency_ms).unwrap_or(u128::MAX) >= DEGRADED_MILLIS {
        (
            "degraded".to_owned(),
            format!("slow response: {latency_ms}ms"),
        )
    } else {
        ("operational".to_owned(), String::new())
    }
}

async fn call_provider(
    client: &reqwest::Client,
    config: &MonitorConfig,
    model: &str,
    prompt: &str,
) -> Result<(u16, String, String), String> {
    let (path, default_body, default_headers, text_kind) = provider_request(config, model, prompt)?;
    let body = request_body(config, default_body)?;
    let mut headers = default_headers;
    for (name, value) in &config.extra_headers {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|error| error.to_string())?;
        let value = HeaderValue::from_str(value).map_err(|error| error.to_string())?;
        headers.insert(name, value);
    }
    let mut url = Url::parse(&config.endpoint).map_err(|error| error.to_string())?;
    url.set_path(&path);
    let response = client
        .post(url)
        .headers(headers)
        .json(&body)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status().as_u16();
    let bytes = limited_response(response).await?;
    let raw = String::from_utf8_lossy(&bytes).into_owned();
    let value = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
    let text = extract_response_text(&value, text_kind);
    Ok((status, text, raw))
}

#[derive(Clone, Copy)]
enum TextKind {
    OpenAiChat,
    OpenAiResponses,
    Anthropic,
    Gemini,
}

fn provider_request(
    config: &MonitorConfig,
    model: &str,
    prompt: &str,
) -> Result<(String, Value, HeaderMap, TextKind), String> {
    let mut headers = HeaderMap::new();
    match (config.provider.as_str(), config.api_mode.as_str()) {
        ("openai", "responses") => {
            headers.insert(
                reqwest::header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {}", config.api_key))
                    .map_err(|error| error.to_string())?,
            );
            Ok((
                "/v1/responses".to_owned(),
                json!({
                    "model": model,
                    "instructions": "You are a channel health-check endpoint. Answer the arithmetic challenge exactly and briefly.",
                    "input": prompt,
                    "max_output_tokens": 50,
                    "stream": false
                }),
                headers,
                TextKind::OpenAiResponses,
            ))
        }
        ("openai", _) => {
            headers.insert(
                reqwest::header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {}", config.api_key))
                    .map_err(|error| error.to_string())?,
            );
            Ok((
                "/v1/chat/completions".to_owned(),
                json!({
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 50,
                    "stream": false
                }),
                headers,
                TextKind::OpenAiChat,
            ))
        }
        ("anthropic", _) => {
            headers.insert(
                HeaderName::from_static("x-api-key"),
                HeaderValue::from_str(&config.api_key).map_err(|error| error.to_string())?,
            );
            headers.insert(
                HeaderName::from_static("anthropic-version"),
                HeaderValue::from_static("2023-06-01"),
            );
            Ok((
                "/v1/messages".to_owned(),
                json!({
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 50
                }),
                headers,
                TextKind::Anthropic,
            ))
        }
        ("gemini", _) => {
            headers.insert(
                HeaderName::from_static("x-goog-api-key"),
                HeaderValue::from_str(&config.api_key).map_err(|error| error.to_string())?,
            );
            Ok((
                format!("/v1beta/models/{model}:generateContent"),
                json!({
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {"maxOutputTokens": 50}
                }),
                headers,
                TextKind::Gemini,
            ))
        }
        _ => Err("unsupported monitor provider or API mode".to_owned()),
    }
}

fn request_body(config: &MonitorConfig, default_body: Value) -> Result<Value, String> {
    match config.body_override_mode.as_str() {
        "off" => Ok(default_body),
        "replace" => config
            .body_override
            .clone()
            .ok_or_else(|| "replace-mode body_override is missing".to_owned()),
        "merge" => {
            let mut object = default_body
                .as_object()
                .cloned()
                .ok_or_else(|| "default monitor request body is not an object".to_owned())?;
            let overrides = config
                .body_override
                .as_ref()
                .and_then(Value::as_object)
                .ok_or_else(|| "merge-mode body_override is missing".to_owned())?;
            let denied = denied_body_keys(&config.provider, &config.api_mode);
            for (key, value) in overrides {
                if !denied.contains(key.as_str()) {
                    object.insert(key.clone(), value.clone());
                }
            }
            Ok(Value::Object(object))
        }
        _ => Err("invalid body_override_mode".to_owned()),
    }
}

fn denied_body_keys(provider: &str, api_mode: &str) -> BTreeSet<&'static str> {
    let keys: &[&str] = match (provider, api_mode) {
        ("openai", "responses") => &["model", "instructions", "input", "stream"],
        ("openai", _) => &["model", "messages", "stream"],
        ("anthropic", _) => &["model", "messages"],
        ("gemini", _) => &["contents"],
        _ => &[],
    };
    keys.iter().copied().collect()
}

async fn limited_response(response: reqwest::Response) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| error.to_string())?;
        let remaining = RESPONSE_LIMIT.saturating_sub(output.len());
        output.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        if output.len() >= RESPONSE_LIMIT {
            break;
        }
    }
    Ok(output)
}

fn extract_response_text(value: &Value, kind: TextKind) -> String {
    match kind {
        TextKind::OpenAiChat => value
            .pointer("/choices/0/message/content")
            .map(string_or_text_blocks)
            .unwrap_or_default(),
        TextKind::Anthropic => value
            .pointer("/content/0/text")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        TextKind::Gemini => value
            .pointer("/candidates/0/content/parts/0/text")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        TextKind::OpenAiResponses => extract_responses_text(value),
    }
}

fn string_or_text_blocks(value: &Value) -> String {
    if let Some(value) = value.as_str() {
        return value.to_owned();
    }
    value.as_array().map_or_else(String::new, |blocks| {
        blocks
            .iter()
            .filter_map(|block| block.get("text").and_then(Value::as_str))
            .collect::<String>()
    })
}

fn extract_responses_text(value: &Value) -> String {
    if let Some(text) = value.get("output_text").and_then(Value::as_str)
        && !text.trim().is_empty()
    {
        return text.to_owned();
    }
    let mut result = String::new();
    if let Some(outputs) = value.get("output").and_then(Value::as_array) {
        for output in outputs {
            if output
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind != "message")
            {
                continue;
            }
            if let Some(content) = output.get("content").and_then(Value::as_array) {
                for block in content {
                    if block
                        .get("type")
                        .and_then(Value::as_str)
                        .is_some_and(|kind| kind != "output_text")
                    {
                        continue;
                    }
                    if let Some(text) = block.get("text").and_then(Value::as_str) {
                        result.push_str(text);
                    }
                }
            }
        }
    }
    result
}

async fn persist_results(
    pool: &PgPool,
    monitor_id: i64,
    results: &[CheckResult],
) -> Result<(), AdminError> {
    let mut transaction = pool.begin().await?;
    for result in results {
        sqlx::query(
            r"INSERT INTO channel_monitor_histories
              (monitor_id, model, status, latency_ms, ping_latency_ms, message, checked_at)
              VALUES ($1, $2, $3, $4, $5, $6, $7::timestamptz)",
        )
        .bind(monitor_id)
        .bind(&result.model)
        .bind(&result.status)
        .bind(result.latency_ms)
        .bind(result.ping_latency_ms)
        .bind(&result.message)
        .bind(&result.checked_at)
        .execute(&mut *transaction)
        .await?;
    }
    sqlx::query("UPDATE channel_monitors SET last_checked_at = NOW() WHERE id = $1")
        .bind(monitor_id)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(())
}

fn challenge() -> (String, String) {
    let first = i32::try_from(OsRng.next_u32() % 50 + 1).unwrap_or(1);
    let second = i32::try_from(OsRng.next_u32() % 50 + 1).unwrap_or(1);
    let addition = OsRng.next_u32().is_multiple_of(2);
    let (left, operator, right, answer) = if addition {
        (first, "+", second, first + second)
    } else {
        let (high, low) = if first >= second {
            (first, second)
        } else {
            (second, first)
        };
        (high, "-", low, high - low)
    };
    (
        format!(
            "Calculate and respond with ONLY the number, nothing else.\n\nQ: 3 + 5 = ?\nA: 8\n\nQ: 12 - 7 = ?\nA: 5\n\nQ: {left} {operator} {right} = ?\nA:"
        ),
        answer.to_string(),
    )
}

fn challenge_matches(text: &str, expected: &str) -> bool {
    let mut current = String::new();
    let mut values = Vec::new();
    for character in text.chars() {
        if character.is_ascii_digit() || (character == '-' && current.is_empty()) {
            current.push(character);
        } else if !current.is_empty() {
            values.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        values.push(current);
    }
    values.iter().any(|value| value == expected)
}

fn monitor_key() -> Result<[u8; 32], AdminError> {
    secrets::config_encryption_key().map_err(|error| {
        AdminError::Probe(format!(
            "TOTP_ENCRYPTION_KEY is required for channel monitors: {error}"
        ))
    })
}

fn encrypt_api_key(plain: &str) -> Result<String, AdminError> {
    let key = monitor_key()?;
    encrypt_with_key(plain, &key)
}

fn encrypt_with_key(plain: &str, key: &[u8; 32]) -> Result<String, AdminError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| AdminError::Probe("initialize monitor encryption".to_owned()))?;
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let encrypted = cipher
        .encrypt(Nonce::from_slice(&nonce), plain.as_bytes())
        .map_err(|_| AdminError::Probe("encrypt monitor API key".to_owned()))?;
    let mut output = Vec::with_capacity(nonce.len() + encrypted.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&encrypted);
    Ok(STANDARD.encode(output))
}

fn decrypt_api_key(ciphertext: &str) -> Result<String, String> {
    let key = monitor_key().map_err(|error| error.to_string())?;
    decrypt_with_key(ciphertext, &key)
}

fn decrypt_with_key(ciphertext: &str, key: &[u8; 32]) -> Result<String, String> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| "initialize monitor encryption".to_owned())?;
    let decoded = STANDARD
        .decode(ciphertext)
        .map_err(|error| format!("decode monitor API key: {error}"))?;
    let (nonce, encrypted) = decoded
        .split_at_checked(12)
        .ok_or_else(|| "encrypted monitor API key is too short".to_owned())?;
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce), encrypted)
        .map_err(|_| "decrypt monitor API key".to_owned())?;
    String::from_utf8(plain).map_err(|error| format!("decode monitor API key text: {error}"))
}

fn mask_api_key(plain: &str) -> String {
    let prefix = plain.chars().take(4).collect::<String>();
    if plain.chars().count() <= 4 {
        "***".to_owned()
    } else {
        format!("{prefix}***")
    }
}

fn valid_name(value: &str) -> Result<String, AdminError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 100 {
        Err(AdminError::BadRequest(
            "monitor name is required and must not exceed 100 bytes".to_owned(),
        ))
    } else {
        Ok(value.to_owned())
    }
}

fn valid_api_key(value: &str) -> Result<String, AdminError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 2_000 {
        Err(AdminError::BadRequest(
            "api_key is required and must not exceed 2000 bytes".to_owned(),
        ))
    } else {
        Ok(value.to_owned())
    }
}

fn valid_model(value: &str) -> Result<String, AdminError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 200 {
        Err(AdminError::BadRequest(
            "primary_model is required and must not exceed 200 bytes".to_owned(),
        ))
    } else {
        Ok(value.to_owned())
    }
}

fn normalize_models(values: &[String]) -> Result<Vec<String>, AdminError> {
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for value in values {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if value.len() > 200 {
            return Err(AdminError::BadRequest(
                "extra model names must not exceed 200 bytes".to_owned(),
            ));
        }
        if seen.insert(value.to_owned()) {
            result.push(value.to_owned());
        }
    }
    Ok(result)
}

fn valid_group_name(value: &str) -> Result<String, AdminError> {
    let value = value.trim();
    if value.len() > 100 {
        Err(AdminError::BadRequest(
            "group_name must not exceed 100 bytes".to_owned(),
        ))
    } else {
        Ok(value.to_owned())
    }
}

fn validate_interval(interval: i32, jitter: i32) -> Result<(), AdminError> {
    if !(15..=3_600).contains(&interval) || jitter < 0 || interval - jitter < 15 {
        Err(AdminError::BadRequest(
            "interval_seconds must be in [15, 3600] and interval_seconds - jitter_seconds must be at least 15"
                .to_owned(),
        ))
    } else {
        Ok(())
    }
}

fn validate_template_id(id: Option<i64>) -> Result<(), AdminError> {
    if id.is_some_and(|id| id <= 0) {
        Err(AdminError::BadRequest(
            "template_id must be positive".to_owned(),
        ))
    } else {
        Ok(())
    }
}

fn require_id(id: i64) -> Result<(), AdminError> {
    if id > 0 {
        Ok(())
    } else {
        Err(AdminError::BadRequest("invalid monitor ID".to_owned()))
    }
}

fn elapsed_millis(started: Instant) -> i32 {
    i32::try_from(started.elapsed().as_millis()).unwrap_or(i32::MAX)
}

fn compact_body(raw: &str) -> String {
    let compact = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    truncate_chars(&compact, 300)
}

fn sanitize_message(message: &str, config: &MonitorConfig) -> String {
    let mut sanitized = message.replace(&config.api_key, "[REDACTED]");
    for value in config.extra_headers.values() {
        if value.chars().count() >= 4 {
            sanitized = sanitized.replace(value, "[REDACTED]");
        }
    }
    truncate_message(&sanitized)
}

fn truncate_message(message: &str) -> String {
    truncate_chars(message, 500)
}

fn truncate_chars(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_owned();
    }
    let suffix = "...(truncated)";
    let keep = max.saturating_sub(suffix.chars().count());
    format!("{}{suffix}", value.chars().take(keep).collect::<String>())
}

fn like_pattern(value: &str) -> String {
    format!(
        "%{}%",
        value
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_")
    )
}

#[cfg(test)]
mod tests {
    use super::{
        MonitorConfig, challenge_matches, decrypt_with_key, encrypt_with_key, mask_api_key,
        request_body,
    };
    use base64::Engine;
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn challenge_matching_requires_a_complete_integer() {
        assert!(challenge_matches("The answer is 17.", "17"));
        assert!(!challenge_matches("The answer is 117.", "17"));
    }

    #[test]
    fn api_key_mask_never_returns_the_secret() {
        assert_eq!(mask_api_key("abc"), "***");
        assert_eq!(mask_api_key("sk-secret"), "sk-s***");
    }

    #[test]
    fn api_key_cipher_uses_go_compatible_nonce_ciphertext_tag_layout() {
        let key = [0x42; 32];
        let ciphertext =
            encrypt_with_key("sk-monitor-secret", &key).expect("encryption should work");
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&ciphertext)
            .expect("ciphertext should be standard base64");
        assert_eq!(raw.len(), 12 + "sk-monitor-secret".len() + 16);
        assert_eq!(
            decrypt_with_key(&ciphertext, &key).expect("decryption should work"),
            "sk-monitor-secret"
        );
    }

    #[test]
    fn merge_mode_preserves_challenge_fields() {
        let config = MonitorConfig {
            provider: "openai".to_owned(),
            api_mode: "chat_completions".to_owned(),
            endpoint: "https://example.com".to_owned(),
            api_key: "secret".to_owned(),
            extra_headers: BTreeMap::new(),
            body_override_mode: "merge".to_owned(),
            body_override: Some(json!({"model": "attacker", "temperature": 0.1})),
        };
        let body = request_body(
            &config,
            json!({"model": "expected", "messages": [{"role": "user"}]}),
        )
        .expect("body should merge");
        assert_eq!(body["model"], "expected");
        assert_eq!(body["temperature"], 0.1);
    }
}
