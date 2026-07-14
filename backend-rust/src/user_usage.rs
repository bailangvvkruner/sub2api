use std::collections::HashMap;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::{get, post},
};
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgPool, Row, postgres::PgRow};

use crate::control_api::{ApiEnvelope, ApiError, ControlApiState, Paginated, Pagination};

#[derive(Clone)]
pub struct UserUsageApi {
    state: ControlApiState,
}

impl UserUsageApi {
    #[must_use]
    pub const fn new(state: ControlApiState) -> Self {
        Self { state }
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route("/api/v1/usage", get(list_usage))
            .route("/api/v1/usage/errors", get(list_errors))
            .route("/api/v1/usage/errors/{id}", get(get_error))
            .route("/api/v1/usage/stats", get(usage_stats))
            .route("/api/v1/usage/dashboard/stats", get(dashboard_stats))
            .route("/api/v1/usage/dashboard/trend", get(dashboard_trend))
            .route("/api/v1/usage/dashboard/models", get(dashboard_models))
            .route(
                "/api/v1/usage/dashboard/snapshot-v2",
                get(dashboard_snapshot),
            )
            .route(
                "/api/v1/usage/dashboard/api-keys-usage",
                post(api_keys_usage),
            )
            .route("/api/v1/usage/{id}", get(get_usage))
            .with_state(self.state.clone())
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
struct UsageQuery {
    page: Option<u32>,
    page_size: Option<u32>,
    api_key_id: Option<i64>,
    group_id: Option<i64>,
    model: Option<String>,
    start_date: Option<String>,
    end_date: Option<String>,
    period: Option<String>,
    granularity: Option<String>,
    request_type: Option<String>,
    stream: Option<bool>,
    billing_type: Option<i16>,
    billing_mode: Option<String>,
    status_code: Option<i32>,
    category: Option<String>,
    sort_by: Option<String>,
    sort_order: Option<String>,
    include_trend: Option<bool>,
    include_model_stats: Option<bool>,
    include_group_stats: Option<bool>,
}

impl UsageQuery {
    fn pagination(&self) -> Pagination {
        let page = self.page.unwrap_or(1).max(1);
        let page_size = self.page_size.unwrap_or(20).clamp(1, 1_000);
        Pagination {
            page,
            page_size,
            offset: i64::from(page.saturating_sub(1)) * i64::from(page_size),
        }
    }

    fn validate(&self) -> Result<(), ApiError> {
        for raw in [&self.start_date, &self.end_date].into_iter().flatten() {
            NaiveDate::parse_from_str(raw.trim(), "%Y-%m-%d")
                .map_err(|_| ApiError::bad_request("Invalid date; expected YYYY-MM-DD"))?;
        }
        if self.api_key_id.is_some_and(|id| id <= 0) || self.group_id.is_some_and(|id| id <= 0) {
            return Err(ApiError::bad_request("Resource IDs must be positive"));
        }
        parse_request_type(self.request_type.as_deref())?;
        if self
            .billing_mode
            .as_deref()
            .is_some_and(|mode| !matches!(mode, "token" | "image" | "video" | "per_request"))
        {
            return Err(ApiError::bad_request("Invalid billing_mode"));
        }
        Ok(())
    }

    fn date_range(&self) -> (Option<String>, Option<String>) {
        if self.start_date.is_some() || self.end_date.is_some() {
            return (self.start_date.clone(), self.end_date.clone());
        }
        let start = match self.period.as_deref().unwrap_or("week") {
            "today" => Some("0 days".to_owned()),
            "month" => Some("1 month".to_owned()),
            "year" => Some("1 year".to_owned()),
            _ => Some("7 days".to_owned()),
        };
        (start, None)
    }

    fn sort(&self) -> (&'static str, &'static str) {
        let column = match self.sort_by.as_deref() {
            Some("id") => "l.id",
            Some("total_cost") => "l.total_cost",
            Some("actual_cost") => "l.actual_cost",
            Some("duration_ms") => "l.duration_ms",
            _ => "l.created_at",
        };
        let direction = if self
            .sort_order
            .as_deref()
            .is_some_and(|order| order.eq_ignore_ascii_case("asc"))
        {
            "ASC"
        } else {
            "DESC"
        };
        (column, direction)
    }
}

#[derive(Debug, Serialize)]
struct UsageLogView {
    id: i64,
    user_id: i64,
    api_key_id: i64,
    account_id: i64,
    request_id: String,
    model: String,
    service_tier: Option<String>,
    reasoning_effort: Option<String>,
    inbound_endpoint: Option<String>,
    group_id: Option<i64>,
    subscription_id: Option<i64>,
    input_tokens: i32,
    output_tokens: i32,
    cache_creation_tokens: i32,
    cache_read_tokens: i32,
    cache_creation_5m_tokens: i32,
    cache_creation_1h_tokens: i32,
    input_cost: f64,
    output_cost: f64,
    cache_creation_cost: f64,
    cache_read_cost: f64,
    total_cost: f64,
    actual_cost: f64,
    rate_multiplier: f64,
    billing_type: i16,
    request_type: &'static str,
    stream: bool,
    openai_ws_mode: bool,
    duration_ms: Option<i32>,
    first_token_ms: Option<i32>,
    image_count: i32,
    image_size: Option<String>,
    image_input_size: Option<String>,
    image_output_size: Option<String>,
    image_size_source: Option<String>,
    image_size_breakdown: Option<Value>,
    image_output_tokens: i32,
    image_output_cost: f64,
    user_agent: Option<String>,
    ip_address: Option<String>,
    cache_ttl_overridden: bool,
    billing_mode: Option<String>,
    created_at: String,
}

const USAGE_SELECT: &str = r#"
SELECT
    l.id, l.user_id, l.api_key_id, l.account_id,
    COALESCE(l.request_id, '') AS request_id,
    COALESCE(NULLIF(l.requested_model, ''), l.model) AS model,
    l.service_tier, l.reasoning_effort, l.inbound_endpoint,
    l.group_id, l.subscription_id,
    l.input_tokens, l.output_tokens, l.cache_creation_tokens, l.cache_read_tokens,
    l.cache_creation_5m_tokens, l.cache_creation_1h_tokens,
    l.input_cost::text AS input_cost, l.output_cost::text AS output_cost,
    l.cache_creation_cost::text AS cache_creation_cost,
    l.cache_read_cost::text AS cache_read_cost,
    l.total_cost::text AS total_cost, l.actual_cost::text AS actual_cost,
    l.rate_multiplier::text AS rate_multiplier,
    l.billing_type, l.request_type, l.stream, l.openai_ws_mode,
    l.duration_ms, l.first_token_ms,
    COALESCE(l.image_count, 0) AS image_count, l.image_size,
    l.image_input_size, l.image_output_size, l.image_size_source,
    l.image_size_breakdown, l.image_output_tokens,
    l.image_output_cost::text AS image_output_cost,
    l.user_agent, l.ip_address, l.cache_ttl_overridden, l.billing_mode,
    to_char(l.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at
FROM usage_logs l
"#;

async fn list_usage(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    Query(query): Query<UsageQuery>,
) -> Result<Json<ApiEnvelope<Paginated<UsageLogView>>>, ApiError> {
    query.validate()?;
    let user_id = authenticated_user_id(&state, &headers).await?;
    let pagination = query.pagination();
    let request_type = parse_request_type(query.request_type.as_deref())?;
    let (sort, direction) = query.sort();
    let filter = usage_filter_sql();
    let count_sql = format!("SELECT COUNT(*)::bigint AS total FROM usage_logs l {filter}");
    let total_row = bind_usage_filters(sqlx::query(&count_sql), user_id, &query, request_type)
        .fetch_one(state.pool())
        .await
        .map_err(|error| ApiError::database(&error))?;
    let total = total_row
        .try_get("total")
        .map_err(|error| ApiError::database(&error))?;

    let list_sql =
        format!("{USAGE_SELECT} {filter} ORDER BY {sort} {direction} LIMIT $12 OFFSET $13");
    let rows = bind_usage_filters(sqlx::query(&list_sql), user_id, &query, request_type)
        .bind(i64::from(pagination.page_size))
        .bind(pagination.offset)
        .fetch_all(state.pool())
        .await
        .map_err(|error| ApiError::database(&error))?;
    let items = rows
        .iter()
        .map(usage_view)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| ApiError::database(&error))?;
    Ok(Json(ApiEnvelope::success(Paginated::new(
        items, total, pagination,
    ))))
}

async fn get_usage(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<ApiEnvelope<UsageLogView>>, ApiError> {
    if id <= 0 {
        return Err(ApiError::bad_request("Usage ID must be positive"));
    }
    let user_id = authenticated_user_id(&state, &headers).await?;
    let sql = format!("{USAGE_SELECT} WHERE l.id = $1 AND l.user_id = $2");
    let row = sqlx::query(&sql)
        .bind(id)
        .bind(user_id)
        .fetch_optional(state.pool())
        .await
        .map_err(|error| ApiError::database(&error))?
        .ok_or_else(|| ApiError::not_found("Usage record not found"))?;
    Ok(Json(ApiEnvelope::success(
        usage_view(&row).map_err(|error| ApiError::database(&error))?,
    )))
}

#[allow(clippy::too_many_lines)]
async fn list_errors(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    Query(query): Query<UsageQuery>,
) -> Result<Json<ApiEnvelope<Paginated<Value>>>, ApiError> {
    query.validate()?;
    let user_id = authenticated_user_id(&state, &headers).await?;
    ensure_error_view_enabled(state.pool()).await?;
    let pagination = query.pagination();
    let count = sqlx::query_scalar::<_, i64>(
        r"
SELECT COUNT(*)::bigint
FROM ops_error_logs e
WHERE (e.user_id = $1 OR e.deleted_key_owner_user_id = $1)
  AND ($2::bigint IS NULL OR e.api_key_id = $2)
  AND ($3::text IS NULL OR COALESCE(e.requested_model, e.model, '') = $3)
  AND ($4::integer IS NULL OR COALESCE(e.upstream_status_code, e.status_code, 0) = $4)
  AND ($5::text IS NULL OR (CASE
      WHEN e.error_phase = 'auth' THEN 'auth'
      WHEN e.error_phase = 'routing' THEN 'service_unavailable'
      WHEN e.error_phase IN ('upstream', 'network') THEN 'upstream'
      WHEN e.error_phase = 'internal' THEN 'internal'
      WHEN e.error_type = 'rate_limit_error' THEN 'rate_limit'
      WHEN e.error_type IN ('billing_error', 'subscription_error') THEN 'quota'
      WHEN e.error_type = 'invalid_request_error' THEN 'invalid_request'
      WHEN e.error_type = 'cyber_policy' THEN 'cyber'
      ELSE 'other' END) = $5)
  AND ($6::text IS NULL OR e.created_at >= $6::date)
  AND ($7::text IS NULL OR e.created_at < $7::date + INTERVAL '1 day')
",
    )
    .bind(user_id)
    .bind(query.api_key_id)
    .bind(normalized_text(query.model.as_deref()))
    .bind(query.status_code)
    .bind(normalized_error_category(query.category.as_deref())?)
    .bind(query.start_date.as_deref())
    .bind(query.end_date.as_deref())
    .fetch_one(state.pool())
    .await
    .map_err(|error| ApiError::database(&error))?;
    let rows = sqlx::query(
        r#"
SELECT e.id,
       to_char(e.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at,
       COALESCE(e.requested_model, e.model, '') AS model,
       COALESCE(e.inbound_endpoint, e.request_path, '') AS inbound_endpoint,
       COALESCE(e.upstream_status_code, e.status_code, 0) AS status_code,
       (CASE
          WHEN e.error_phase = 'auth' THEN 'auth'
          WHEN e.error_phase = 'routing' THEN 'service_unavailable'
          WHEN e.error_phase IN ('upstream', 'network') THEN 'upstream'
          WHEN e.error_phase = 'internal' THEN 'internal'
          WHEN e.error_type = 'rate_limit_error' THEN 'rate_limit'
          WHEN e.error_type IN ('billing_error', 'subscription_error') THEN 'quota'
          WHEN e.error_type = 'invalid_request_error' THEN 'invalid_request'
          WHEN e.error_type = 'cyber_policy' THEN 'cyber'
          ELSE 'other' END) AS category,
       COALESCE(e.platform, '') AS platform,
       COALESCE(e.error_message, '') AS message,
       COALESCE(k.name, e.deleted_key_name, '') AS key_name,
       (k.deleted_at IS NOT NULL OR (k.id IS NULL AND e.deleted_key_name IS NOT NULL)) AS key_deleted,
       CASE WHEN e.client_ip IS NULL THEN NULL ELSE host(e.client_ip) END AS client_ip,
       COALESCE(g.name, '') AS group_name,
       e.request_type, e.stream, COALESCE(e.user_agent, '') AS user_agent
FROM ops_error_logs e
LEFT JOIN api_keys k ON k.id = e.api_key_id
LEFT JOIN groups g ON g.id = e.group_id
WHERE (e.user_id = $1 OR e.deleted_key_owner_user_id = $1)
  AND ($2::bigint IS NULL OR e.api_key_id = $2)
  AND ($3::text IS NULL OR COALESCE(e.requested_model, e.model, '') = $3)
  AND ($4::integer IS NULL OR COALESCE(e.upstream_status_code, e.status_code, 0) = $4)
  AND ($5::text IS NULL OR (CASE
      WHEN e.error_phase = 'auth' THEN 'auth'
      WHEN e.error_phase = 'routing' THEN 'service_unavailable'
      WHEN e.error_phase IN ('upstream', 'network') THEN 'upstream'
      WHEN e.error_phase = 'internal' THEN 'internal'
      WHEN e.error_type = 'rate_limit_error' THEN 'rate_limit'
      WHEN e.error_type IN ('billing_error', 'subscription_error') THEN 'quota'
      WHEN e.error_type = 'invalid_request_error' THEN 'invalid_request'
      WHEN e.error_type = 'cyber_policy' THEN 'cyber'
      ELSE 'other' END) = $5)
  AND ($6::text IS NULL OR e.created_at >= $6::date)
  AND ($7::text IS NULL OR e.created_at < $7::date + INTERVAL '1 day')
ORDER BY e.created_at DESC
LIMIT $8 OFFSET $9
"#,
    )
    .bind(user_id)
    .bind(query.api_key_id)
    .bind(normalized_text(query.model.as_deref()))
    .bind(query.status_code)
    .bind(normalized_error_category(query.category.as_deref())?)
    .bind(query.start_date.as_deref())
    .bind(query.end_date.as_deref())
    .bind(i64::from(pagination.page_size))
    .bind(pagination.offset)
    .fetch_all(state.pool())
    .await
    .map_err(|error| ApiError::database(&error))?;
    let items = rows
        .iter()
        .map(error_value)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(ApiEnvelope::success(Paginated::new(
        items, count, pagination,
    ))))
}

async fn get_error(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<ApiEnvelope<Value>>, ApiError> {
    if id <= 0 {
        return Err(ApiError::bad_request("Error ID must be positive"));
    }
    let user_id = authenticated_user_id(&state, &headers).await?;
    ensure_error_view_enabled(state.pool()).await?;
    let row = sqlx::query(
        r#"
SELECT e.id,
       to_char(e.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at,
       COALESCE(e.requested_model, e.model, '') AS model,
       COALESCE(e.inbound_endpoint, e.request_path, '') AS inbound_endpoint,
       COALESCE(e.upstream_status_code, e.status_code, 0) AS status_code,
       (CASE
          WHEN e.error_phase = 'auth' THEN 'auth'
          WHEN e.error_phase = 'routing' THEN 'service_unavailable'
          WHEN e.error_phase IN ('upstream', 'network') THEN 'upstream'
          WHEN e.error_phase = 'internal' THEN 'internal'
          WHEN e.error_type = 'rate_limit_error' THEN 'rate_limit'
          WHEN e.error_type IN ('billing_error', 'subscription_error') THEN 'quota'
          WHEN e.error_type = 'invalid_request_error' THEN 'invalid_request'
          WHEN e.error_type = 'cyber_policy' THEN 'cyber'
          ELSE 'other' END) AS category,
       COALESCE(e.platform, '') AS platform,
       COALESCE(e.error_message, '') AS message,
       COALESCE(k.name, e.deleted_key_name, '') AS key_name,
       (k.deleted_at IS NOT NULL OR (k.id IS NULL AND e.deleted_key_name IS NOT NULL)) AS key_deleted,
       CASE WHEN e.client_ip IS NULL THEN NULL ELSE host(e.client_ip) END AS client_ip,
       COALESCE(g.name, '') AS group_name,
       e.request_type, e.stream, COALESCE(e.user_agent, '') AS user_agent,
       COALESCE(e.error_body, '') AS error_body, e.upstream_status_code
FROM ops_error_logs e
LEFT JOIN api_keys k ON k.id = e.api_key_id
LEFT JOIN groups g ON g.id = e.group_id
WHERE e.id = $1 AND (e.user_id = $2 OR e.deleted_key_owner_user_id = $2)
"#,
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(state.pool())
    .await
    .map_err(|error| ApiError::database(&error))?
    .ok_or_else(|| ApiError::not_found("Error request not found"))?;
    let mut value = error_value(&row)?;
    value["error_body"] = Value::String(
        row.try_get("error_body")
            .map_err(|error| ApiError::database(&error))?,
    );
    value["upstream_status_code"] = row
        .try_get::<Option<i32>, _>("upstream_status_code")
        .map_err(|error| ApiError::database(&error))?
        .map_or(Value::Null, Value::from);
    Ok(Json(ApiEnvelope::success(value)))
}

async fn usage_stats(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    Query(query): Query<UsageQuery>,
) -> Result<Json<ApiEnvelope<Value>>, ApiError> {
    query.validate()?;
    let user_id = authenticated_user_id(&state, &headers).await?;
    let row = aggregate_usage(state.pool(), user_id, &query).await?;
    Ok(Json(ApiEnvelope::success(stats_value(&row, &query)?)))
}

async fn dashboard_stats(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
) -> Result<Json<ApiEnvelope<Value>>, ApiError> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    let row = sqlx::query(
        r"
SELECT
    (SELECT COUNT(*) FROM api_keys WHERE user_id = $1 AND deleted_at IS NULL)::bigint AS total_api_keys,
    (SELECT COUNT(*) FROM api_keys WHERE user_id = $1 AND deleted_at IS NULL AND status = 'active')::bigint AS active_api_keys,
    COUNT(*)::bigint AS total_requests,
    COALESCE(SUM(input_tokens), 0)::bigint AS total_input_tokens,
    COALESCE(SUM(output_tokens), 0)::bigint AS total_output_tokens,
    COALESCE(SUM(cache_creation_tokens), 0)::bigint AS total_cache_creation_tokens,
    COALESCE(SUM(cache_read_tokens), 0)::bigint AS total_cache_read_tokens,
    COALESCE(SUM(total_cost), 0)::text AS total_cost,
    COALESCE(SUM(actual_cost), 0)::text AS total_actual_cost,
    COUNT(*) FILTER (WHERE created_at >= CURRENT_DATE)::bigint AS today_requests,
    COALESCE(SUM(input_tokens) FILTER (WHERE created_at >= CURRENT_DATE), 0)::bigint AS today_input_tokens,
    COALESCE(SUM(output_tokens) FILTER (WHERE created_at >= CURRENT_DATE), 0)::bigint AS today_output_tokens,
    COALESCE(SUM(cache_creation_tokens) FILTER (WHERE created_at >= CURRENT_DATE), 0)::bigint AS today_cache_creation_tokens,
    COALESCE(SUM(cache_read_tokens) FILTER (WHERE created_at >= CURRENT_DATE), 0)::bigint AS today_cache_read_tokens,
    COALESCE(SUM(total_cost) FILTER (WHERE created_at >= CURRENT_DATE), 0)::text AS today_cost,
    COALESCE(SUM(actual_cost) FILTER (WHERE created_at >= CURRENT_DATE), 0)::text AS today_actual_cost,
    COALESCE(AVG(duration_ms), 0)::double precision AS average_duration_ms,
    COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '60 minutes')::bigint AS recent_requests,
    COALESCE(SUM(input_tokens + output_tokens + cache_creation_tokens + cache_read_tokens)
        FILTER (WHERE created_at >= NOW() - INTERVAL '60 minutes'), 0)::bigint AS recent_tokens
FROM usage_logs
WHERE user_id = $1
",
    )
    .bind(user_id)
    .fetch_one(state.pool())
    .await
    .map_err(|error| ApiError::database(&error))?;
    Ok(Json(ApiEnvelope::success(dashboard_stats_value(&row)?)))
}

async fn dashboard_trend(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    Query(query): Query<UsageQuery>,
) -> Result<Json<ApiEnvelope<Value>>, ApiError> {
    query.validate()?;
    let user_id = authenticated_user_id(&state, &headers).await?;
    Ok(Json(ApiEnvelope::success(
        trend_value(state.pool(), user_id, &query).await?,
    )))
}

async fn dashboard_models(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    Query(query): Query<UsageQuery>,
) -> Result<Json<ApiEnvelope<Value>>, ApiError> {
    query.validate()?;
    let user_id = authenticated_user_id(&state, &headers).await?;
    Ok(Json(ApiEnvelope::success(
        models_value(state.pool(), user_id, &query).await?,
    )))
}

async fn dashboard_snapshot(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    Query(query): Query<UsageQuery>,
) -> Result<Json<ApiEnvelope<Value>>, ApiError> {
    query.validate()?;
    let user_id = authenticated_user_id(&state, &headers).await?;
    let include_trend = query.include_trend.unwrap_or(true);
    let include_models = query.include_model_stats.unwrap_or(true);
    let include_groups = query.include_group_stats.unwrap_or(true);
    let mut value = json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "start_date": query.start_date,
        "end_date": query.end_date,
        "granularity": normalized_granularity(query.granularity.as_deref())?,
    });
    if include_trend {
        value["trend"] = trend_value(state.pool(), user_id, &query).await?["trend"].clone();
    }
    if include_models {
        value["models"] = models_value(state.pool(), user_id, &query).await?["models"].clone();
    }
    if include_groups {
        value["groups"] = groups_value(state.pool(), user_id, &query).await?;
    }
    Ok(Json(ApiEnvelope::success(value)))
}

#[derive(Debug, Deserialize)]
struct ApiKeysUsageRequest {
    api_key_ids: Vec<i64>,
}

async fn api_keys_usage(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    Json(request): Json<ApiKeysUsageRequest>,
) -> Result<Json<ApiEnvelope<Value>>, ApiError> {
    let user_id = authenticated_user_id(&state, &headers).await?;
    if request.api_key_ids.len() > 200 || request.api_key_ids.iter().any(|id| *id <= 0) {
        return Err(ApiError::bad_request("Invalid API key ID list"));
    }
    let rows = sqlx::query(
        r"
SELECT k.id AS api_key_id,
       COALESCE(SUM(l.actual_cost) FILTER (WHERE l.created_at >= CURRENT_DATE), 0)::text AS today_actual_cost,
       COALESCE(SUM(l.actual_cost), 0)::text AS total_actual_cost
FROM api_keys k
LEFT JOIN usage_logs l ON l.api_key_id = k.id AND l.user_id = k.user_id
WHERE k.user_id = $1 AND k.id = ANY($2) AND k.deleted_at IS NULL
GROUP BY k.id
",
    )
    .bind(user_id)
    .bind(&request.api_key_ids)
    .fetch_all(state.pool())
    .await
    .map_err(|error| ApiError::database(&error))?;
    let mut usage_by_key = serde_json::Map::new();
    for row in rows {
        let id: i64 = row
            .try_get("api_key_id")
            .map_err(|error| ApiError::database(&error))?;
        usage_by_key.insert(
            id.to_string(),
            json!({
                "api_key_id": id,
                "today_actual_cost": numeric(&row, "today_actual_cost")?,
                "total_actual_cost": numeric(&row, "total_actual_cost")?,
            }),
        );
    }
    Ok(Json(ApiEnvelope::success(json!({ "stats": usage_by_key }))))
}

fn usage_filter_sql() -> &'static str {
    r"
WHERE l.user_id = $1
  AND ($2::bigint IS NULL OR l.api_key_id = $2)
  AND ($3::bigint IS NULL OR l.group_id = $3)
  AND ($4::text IS NULL OR COALESCE(NULLIF(l.requested_model, ''), l.model) = $4)
  AND ($5::text IS NULL OR l.created_at >= $5::date)
  AND ($6::text IS NULL OR l.created_at < $6::date + INTERVAL '1 day')
  AND ($7::smallint IS NULL OR (CASE WHEN l.request_type = 0 THEN
      CASE WHEN l.openai_ws_mode THEN 3 WHEN l.stream THEN 2 ELSE 1 END
      ELSE l.request_type END) = $7)
  AND ($8::boolean IS NULL OR l.stream = $8)
  AND ($9::smallint IS NULL OR l.billing_type = $9)
  AND ($10::text IS NULL OR l.billing_mode = $10)
  AND ($11::text IS NULL OR l.created_at >= NOW() - $11::interval)
"
}

fn bind_usage_filters<'q>(
    query: sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>,
    user_id: i64,
    filters: &'q UsageQuery,
    request_type: Option<i16>,
) -> sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments> {
    let (relative_start, _) = filters.date_range();
    let relative = if filters.start_date.is_none() {
        relative_start
    } else {
        None
    };
    query
        .bind(user_id)
        .bind(filters.api_key_id)
        .bind(filters.group_id)
        .bind(normalized_text(filters.model.as_deref()))
        .bind(filters.start_date.as_deref())
        .bind(filters.end_date.as_deref())
        .bind(request_type)
        .bind(if request_type.is_none() {
            filters.stream
        } else {
            None
        })
        .bind(filters.billing_type)
        .bind(normalized_text(filters.billing_mode.as_deref()))
        .bind(relative)
}

async fn aggregate_usage(
    pool: &PgPool,
    user_id: i64,
    filters: &UsageQuery,
) -> Result<PgRow, ApiError> {
    let sql = format!(
        r"
SELECT COUNT(*)::bigint AS total_requests,
       COALESCE(SUM(input_tokens), 0)::bigint AS total_input_tokens,
       COALESCE(SUM(output_tokens), 0)::bigint AS total_output_tokens,
       COALESCE(SUM(cache_creation_tokens), 0)::bigint AS total_cache_creation_tokens,
       COALESCE(SUM(cache_read_tokens), 0)::bigint AS total_cache_read_tokens,
       COALESCE(SUM(total_cost), 0)::text AS total_cost,
       COALESCE(SUM(actual_cost), 0)::text AS total_actual_cost,
       COALESCE(AVG(duration_ms), 0)::double precision AS average_duration_ms
FROM usage_logs l {}
",
        usage_filter_sql()
    );
    bind_usage_filters(
        sqlx::query(&sql),
        user_id,
        filters,
        parse_request_type(filters.request_type.as_deref())?,
    )
    .fetch_one(pool)
    .await
    .map_err(|error| ApiError::database(&error))
}

fn stats_value(row: &PgRow, query: &UsageQuery) -> Result<Value, ApiError> {
    let input = integer(row, "total_input_tokens")?;
    let output = integer(row, "total_output_tokens")?;
    let creation = integer(row, "total_cache_creation_tokens")?;
    let read = integer(row, "total_cache_read_tokens")?;
    Ok(json!({
        "period": query.period,
        "total_requests": integer(row, "total_requests")?,
        "total_input_tokens": input,
        "total_output_tokens": output,
        "total_cache_tokens": creation + read,
        "total_cache_read_tokens": read,
        "total_cache_creation_tokens": creation,
        "total_tokens": input + output + creation + read,
        "total_cost": numeric(row, "total_cost")?,
        "total_actual_cost": numeric(row, "total_actual_cost")?,
        "average_duration_ms": row.try_get::<f64, _>("average_duration_ms")
            .map_err(|error| ApiError::database(&error))?,
        "models": HashMap::<String, i64>::new(),
        "endpoints": [],
        "upstream_endpoints": [],
        "endpoint_paths": [],
    }))
}

fn dashboard_stats_value(row: &PgRow) -> Result<Value, ApiError> {
    let total_input = integer(row, "total_input_tokens")?;
    let total_output = integer(row, "total_output_tokens")?;
    let total_creation = integer(row, "total_cache_creation_tokens")?;
    let total_read = integer(row, "total_cache_read_tokens")?;
    let today_input = integer(row, "today_input_tokens")?;
    let today_output = integer(row, "today_output_tokens")?;
    let today_creation = integer(row, "today_cache_creation_tokens")?;
    let today_read = integer(row, "today_cache_read_tokens")?;
    Ok(json!({
        "total_api_keys": integer(row, "total_api_keys")?,
        "active_api_keys": integer(row, "active_api_keys")?,
        "total_requests": integer(row, "total_requests")?,
        "total_input_tokens": total_input,
        "total_output_tokens": total_output,
        "total_cache_creation_tokens": total_creation,
        "total_cache_read_tokens": total_read,
        "total_tokens": total_input + total_output + total_creation + total_read,
        "total_cost": numeric(row, "total_cost")?,
        "total_actual_cost": numeric(row, "total_actual_cost")?,
        "today_requests": integer(row, "today_requests")?,
        "today_input_tokens": today_input,
        "today_output_tokens": today_output,
        "today_cache_creation_tokens": today_creation,
        "today_cache_read_tokens": today_read,
        "today_tokens": today_input + today_output + today_creation + today_read,
        "today_cost": numeric(row, "today_cost")?,
        "today_actual_cost": numeric(row, "today_actual_cost")?,
        "average_duration_ms": row.try_get::<f64, _>("average_duration_ms")
            .map_err(|error| ApiError::database(&error))?,
        "rpm": integer(row, "recent_requests")? / 60,
        "tpm": integer(row, "recent_tokens")? / 60,
    }))
}

async fn trend_value(pool: &PgPool, user_id: i64, query: &UsageQuery) -> Result<Value, ApiError> {
    let granularity = normalized_granularity(query.granularity.as_deref())?;
    let format = if granularity == "hour" {
        "YYYY-MM-DD\"T\"HH24:00:00\"Z\""
    } else {
        "YYYY-MM-DD"
    };
    let sql = format!(
        r"
SELECT to_char(date_trunc('{granularity}', l.created_at AT TIME ZONE 'UTC'), '{format}') AS date,
       COUNT(*)::bigint AS requests,
       COALESCE(SUM(input_tokens), 0)::bigint AS input_tokens,
       COALESCE(SUM(output_tokens), 0)::bigint AS output_tokens,
       COALESCE(SUM(cache_creation_tokens), 0)::bigint AS cache_creation_tokens,
       COALESCE(SUM(cache_read_tokens), 0)::bigint AS cache_read_tokens,
       COALESCE(SUM(total_cost), 0)::text AS cost,
       COALESCE(SUM(actual_cost), 0)::text AS actual_cost
FROM usage_logs l {}
GROUP BY 1 ORDER BY 1
",
        usage_filter_sql()
    );
    let rows = bind_usage_filters(
        sqlx::query(&sql),
        user_id,
        query,
        parse_request_type(query.request_type.as_deref())?,
    )
    .fetch_all(pool)
    .await
    .map_err(|error| ApiError::database(&error))?;
    let trend = rows
        .iter()
        .map(trend_point)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(json!({
        "trend": trend,
        "start_date": query.start_date,
        "end_date": query.end_date,
        "granularity": granularity,
    }))
}

async fn models_value(pool: &PgPool, user_id: i64, query: &UsageQuery) -> Result<Value, ApiError> {
    let sql = format!(
        r"
SELECT COALESCE(NULLIF(l.requested_model, ''), l.model) AS model,
       COUNT(*)::bigint AS requests,
       COALESCE(SUM(input_tokens), 0)::bigint AS input_tokens,
       COALESCE(SUM(output_tokens), 0)::bigint AS output_tokens,
       COALESCE(SUM(cache_creation_tokens), 0)::bigint AS cache_creation_tokens,
       COALESCE(SUM(cache_read_tokens), 0)::bigint AS cache_read_tokens,
       COALESCE(SUM(total_cost), 0)::text AS cost,
       COALESCE(SUM(actual_cost), 0)::text AS actual_cost
FROM usage_logs l {}
GROUP BY 1 ORDER BY actual_cost DESC
",
        usage_filter_sql()
    );
    let rows = bind_usage_filters(
        sqlx::query(&sql),
        user_id,
        query,
        parse_request_type(query.request_type.as_deref())?,
    )
    .fetch_all(pool)
    .await
    .map_err(|error| ApiError::database(&error))?;
    let models = rows
        .iter()
        .map(model_value)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(json!({
        "models": models,
        "start_date": query.start_date,
        "end_date": query.end_date,
    }))
}

async fn groups_value(pool: &PgPool, user_id: i64, query: &UsageQuery) -> Result<Value, ApiError> {
    let sql = format!(
        r"
SELECT l.group_id, COALESCE(g.name, '') AS group_name,
       COUNT(*)::bigint AS requests,
       COALESCE(SUM(l.input_tokens + l.output_tokens + l.cache_creation_tokens + l.cache_read_tokens), 0)::bigint AS total_tokens,
       COALESCE(SUM(l.total_cost), 0)::text AS cost,
       COALESCE(SUM(l.actual_cost), 0)::text AS actual_cost
FROM usage_logs l LEFT JOIN groups g ON g.id = l.group_id {}
GROUP BY l.group_id, g.name ORDER BY actual_cost DESC
",
        usage_filter_sql()
    );
    let rows = bind_usage_filters(
        sqlx::query(&sql),
        user_id,
        query,
        parse_request_type(query.request_type.as_deref())?,
    )
    .fetch_all(pool)
    .await
    .map_err(|error| ApiError::database(&error))?;
    rows.iter()
        .map(|row| {
            Ok(json!({
                "group_id": row.try_get::<Option<i64>, _>("group_id")?.unwrap_or_default(),
                "group_name": row.try_get::<String, _>("group_name")?,
                "requests": row.try_get::<i64, _>("requests")?,
                "total_tokens": row.try_get::<i64, _>("total_tokens")?,
                "cost": numeric_sql(row, "cost")?,
                "actual_cost": numeric_sql(row, "actual_cost")?,
            }))
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map(Value::Array)
        .map_err(|error| ApiError::database(&error))
}

async fn authenticated_user_id(
    state: &ControlApiState,
    headers: &HeaderMap,
) -> Result<i64, ApiError> {
    Ok(state.authenticate(headers).await?.view.id)
}

fn usage_view(row: &PgRow) -> Result<UsageLogView, sqlx::Error> {
    let request_type: i16 = row.try_get("request_type")?;
    Ok(UsageLogView {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        api_key_id: row.try_get("api_key_id")?,
        account_id: row.try_get("account_id")?,
        request_id: row.try_get("request_id")?,
        model: row.try_get("model")?,
        service_tier: row.try_get("service_tier")?,
        reasoning_effort: row.try_get("reasoning_effort")?,
        inbound_endpoint: row.try_get("inbound_endpoint")?,
        group_id: row.try_get("group_id")?,
        subscription_id: row.try_get("subscription_id")?,
        input_tokens: row.try_get("input_tokens")?,
        output_tokens: row.try_get("output_tokens")?,
        cache_creation_tokens: row.try_get("cache_creation_tokens")?,
        cache_read_tokens: row.try_get("cache_read_tokens")?,
        cache_creation_5m_tokens: row.try_get("cache_creation_5m_tokens")?,
        cache_creation_1h_tokens: row.try_get("cache_creation_1h_tokens")?,
        input_cost: numeric_sql(row, "input_cost")?,
        output_cost: numeric_sql(row, "output_cost")?,
        cache_creation_cost: numeric_sql(row, "cache_creation_cost")?,
        cache_read_cost: numeric_sql(row, "cache_read_cost")?,
        total_cost: numeric_sql(row, "total_cost")?,
        actual_cost: numeric_sql(row, "actual_cost")?,
        rate_multiplier: numeric_sql(row, "rate_multiplier")?,
        billing_type: row.try_get("billing_type")?,
        request_type: request_type_name(
            request_type,
            row.try_get("stream")?,
            row.try_get("openai_ws_mode")?,
        ),
        stream: row.try_get("stream")?,
        openai_ws_mode: row.try_get("openai_ws_mode")?,
        duration_ms: row.try_get("duration_ms")?,
        first_token_ms: row.try_get("first_token_ms")?,
        image_count: row.try_get("image_count")?,
        image_size: row.try_get("image_size")?,
        image_input_size: row.try_get("image_input_size")?,
        image_output_size: row.try_get("image_output_size")?,
        image_size_source: row.try_get("image_size_source")?,
        image_size_breakdown: row.try_get("image_size_breakdown")?,
        image_output_tokens: row.try_get("image_output_tokens")?,
        image_output_cost: numeric_sql(row, "image_output_cost")?,
        user_agent: row.try_get("user_agent")?,
        ip_address: row.try_get("ip_address")?,
        cache_ttl_overridden: row.try_get("cache_ttl_overridden")?,
        billing_mode: row.try_get("billing_mode")?,
        created_at: row.try_get("created_at")?,
    })
}

fn trend_point(row: &PgRow) -> Result<Value, ApiError> {
    let input = integer(row, "input_tokens")?;
    let output = integer(row, "output_tokens")?;
    let creation = integer(row, "cache_creation_tokens")?;
    let read = integer(row, "cache_read_tokens")?;
    Ok(json!({
        "date": row.try_get::<String, _>("date").map_err(|error| ApiError::database(&error))?,
        "requests": integer(row, "requests")?,
        "input_tokens": input,
        "output_tokens": output,
        "cache_creation_tokens": creation,
        "cache_read_tokens": read,
        "total_tokens": input + output + creation + read,
        "cost": numeric(row, "cost")?,
        "actual_cost": numeric(row, "actual_cost")?,
    }))
}

fn model_value(row: &PgRow) -> Result<Value, ApiError> {
    let input = integer(row, "input_tokens")?;
    let output = integer(row, "output_tokens")?;
    let creation = integer(row, "cache_creation_tokens")?;
    let read = integer(row, "cache_read_tokens")?;
    Ok(json!({
        "model": row.try_get::<String, _>("model").map_err(|error| ApiError::database(&error))?,
        "requests": integer(row, "requests")?,
        "input_tokens": input,
        "output_tokens": output,
        "cache_creation_tokens": creation,
        "cache_read_tokens": read,
        "total_tokens": input + output + creation + read,
        "cost": numeric(row, "cost")?,
        "actual_cost": numeric(row, "actual_cost")?,
    }))
}

async fn ensure_error_view_enabled(pool: &PgPool) -> Result<(), ApiError> {
    let setting = sqlx::query_scalar::<_, String>(
        "SELECT value FROM settings WHERE key = 'allow_user_view_error_requests'",
    )
    .fetch_optional(pool)
    .await;
    match setting {
        Ok(Some(value)) if value.eq_ignore_ascii_case("true") => Ok(()),
        Ok(_) => Err(ApiError::forbidden(
            "Error requests view is disabled",
            "FEATURE_DISABLED",
        )),
        Err(error) => {
            tracing::warn!(error = %error, "read user error-view setting");
            Err(ApiError::forbidden(
                "Error requests view is disabled",
                "FEATURE_DISABLED",
            ))
        }
    }
}

fn normalized_error_category(value: Option<&str>) -> Result<Option<&str>, ApiError> {
    let value = normalized_text(value);
    if value.is_some_and(|category| {
        !matches!(
            category,
            "auth"
                | "service_unavailable"
                | "upstream"
                | "internal"
                | "rate_limit"
                | "quota"
                | "invalid_request"
                | "cyber"
                | "other"
        )
    }) {
        return Err(ApiError::bad_request("Invalid error category"));
    }
    Ok(value)
}

fn error_value(row: &PgRow) -> Result<Value, ApiError> {
    let request_type = row
        .try_get::<Option<i16>, _>("request_type")
        .map_err(|error| ApiError::database(&error))?;
    Ok(json!({
        "id": integer(row, "id")?,
        "created_at": row.try_get::<String, _>("created_at").map_err(|error| ApiError::database(&error))?,
        "model": row.try_get::<String, _>("model").map_err(|error| ApiError::database(&error))?,
        "inbound_endpoint": row.try_get::<String, _>("inbound_endpoint").map_err(|error| ApiError::database(&error))?,
        "status_code": row.try_get::<i32, _>("status_code").map_err(|error| ApiError::database(&error))?,
        "category": row.try_get::<String, _>("category").map_err(|error| ApiError::database(&error))?,
        "platform": row.try_get::<String, _>("platform").map_err(|error| ApiError::database(&error))?,
        "message": row.try_get::<String, _>("message").map_err(|error| ApiError::database(&error))?,
        "key_name": row.try_get::<String, _>("key_name").map_err(|error| ApiError::database(&error))?,
        "key_deleted": row.try_get::<bool, _>("key_deleted").map_err(|error| ApiError::database(&error))?,
        "client_ip": row.try_get::<Option<String>, _>("client_ip").map_err(|error| ApiError::database(&error))?,
        "group_name": row.try_get::<String, _>("group_name").map_err(|error| ApiError::database(&error))?,
        "request_type": request_type,
        "stream": row.try_get::<bool, _>("stream").map_err(|error| ApiError::database(&error))?,
        "user_agent": row.try_get::<String, _>("user_agent").map_err(|error| ApiError::database(&error))?,
    }))
}

fn parse_request_type(value: Option<&str>) -> Result<Option<i16>, ApiError> {
    value
        .map(|value| match value.trim() {
            "unknown" => Ok(0),
            "sync" => Ok(1),
            "stream" => Ok(2),
            "ws_v2" => Ok(3),
            "cyber" => Ok(4),
            _ => Err(ApiError::bad_request("Invalid request_type")),
        })
        .transpose()
}

const fn request_type_name(value: i16, stream: bool, websocket: bool) -> &'static str {
    match value {
        1 => "sync",
        2 => "stream",
        3 => "ws_v2",
        4 => "cyber",
        _ if websocket => "ws_v2",
        _ if stream => "stream",
        _ => "unknown",
    }
}

fn normalized_granularity(value: Option<&str>) -> Result<&'static str, ApiError> {
    match value.unwrap_or("day") {
        "day" => Ok("day"),
        "hour" => Ok("hour"),
        _ => Err(ApiError::bad_request("Invalid granularity")),
    }
}

fn normalized_text(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn integer(row: &PgRow, column: &str) -> Result<i64, ApiError> {
    row.try_get(column)
        .map_err(|error| ApiError::database(&error))
}

fn numeric(row: &PgRow, column: &str) -> Result<f64, ApiError> {
    numeric_sql(row, column).map_err(|error| ApiError::database(&error))
}

fn numeric_sql(row: &PgRow, column: &str) -> Result<f64, sqlx::Error> {
    let value = row.try_get::<String, _>(column)?;
    value
        .parse::<f64>()
        .map_err(|error| sqlx::Error::Protocol(format!("decode {column} numeric: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_type_and_sort_inputs_are_whitelisted() {
        assert_eq!(parse_request_type(Some("ws_v2")).unwrap(), Some(3));
        assert!(parse_request_type(Some("3 OR 1=1")).is_err());
        let query = UsageQuery {
            sort_by: Some("created_at; DROP TABLE users".to_owned()),
            sort_order: Some("sideways".to_owned()),
            ..UsageQuery::default()
        };
        assert_eq!(query.sort(), ("l.created_at", "DESC"));
    }

    #[test]
    fn validates_dates_and_ids() {
        let invalid = UsageQuery {
            start_date: Some("2026-99-99".to_owned()),
            ..UsageQuery::default()
        };
        assert!(invalid.validate().is_err());
        let invalid = UsageQuery {
            api_key_id: Some(0),
            ..UsageQuery::default()
        };
        assert!(invalid.validate().is_err());
    }
}
