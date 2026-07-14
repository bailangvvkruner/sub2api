//! Administrator usage queries and PostgreSQL-backed cleanup task control.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgPool, Row};

use super::{AdminError, AdminIdentity, AdminService, compat::required_path_id};

const MAX_PAGE_SIZE: i64 = 1_000;
const MAX_CLEANUP_RANGE_DAYS: i64 = 31;
const USAGE_HANDLERS: [&str; 8] = [
    "h.Admin.Usage.List",
    "h.Admin.Usage.Stats",
    "h.Admin.Usage.PendingStats",
    "h.Admin.Usage.SearchUsers",
    "h.Admin.Usage.SearchAPIKeys",
    "h.Admin.Usage.ListCleanupTasks",
    "h.Admin.Usage.CreateCleanupTask",
    "h.Admin.Usage.CancelCleanupTask",
];

const USAGE_WHERE: &str = r"
WHERE ($1::bigint IS NULL OR usage.user_id = $1)
  AND ($2::bigint IS NULL OR usage.api_key_id = $2)
  AND ($3::bigint IS NULL OR usage.account_id = $3)
  AND ($4::bigint IS NULL OR usage.group_id = $4)
  AND ($5::text IS NULL OR usage.model = $5)
  AND (
      $6::smallint IS NULL
      OR usage.request_type = $6
      OR ($6 = 1 AND usage.request_type = 0 AND NOT usage.stream AND NOT usage.openai_ws_mode)
      OR ($6 = 2 AND usage.request_type = 0 AND usage.stream AND NOT usage.openai_ws_mode)
      OR ($6 = 3 AND usage.request_type = 0 AND usage.openai_ws_mode)
  )
  AND ($7::boolean IS NULL OR usage.stream = $7)
  AND ($8::smallint IS NULL OR usage.billing_type = $8)
  AND (
      $9::text IS NULL
      OR ($9 = 'image' AND (
          usage.billing_mode = 'image'
          OR ((usage.billing_mode IS NULL OR usage.billing_mode = '') AND COALESCE(usage.image_count, 0) > 0)
      ))
      OR ($9 = 'token' AND (
          usage.billing_mode = 'token'
          OR ((usage.billing_mode IS NULL OR usage.billing_mode = '') AND COALESCE(usage.image_count, 0) <= 0)
      ))
      OR ($9 NOT IN ('image', 'token') AND usage.billing_mode = $9)
  )
  AND ($10::text IS NULL OR usage.created_at >= $10::text::timestamptz)
  AND ($11::text IS NULL OR usage.created_at < $11::text::timestamptz)
";

#[allow(clippy::too_many_arguments)]
pub(super) async fn dispatch(
    service: &AdminService,
    actor: &AdminIdentity,
    handler: &str,
    path: &str,
    query: &BTreeMap<String, String>,
    payload: Value,
) -> Option<Result<Value, AdminError>> {
    if !USAGE_HANDLERS.contains(&handler) {
        return None;
    }
    let pool = service.pool();
    let result = match handler {
        "h.Admin.Usage.List" => list_usage(pool, query).await,
        "h.Admin.Usage.Stats" => usage_stats(pool, query).await,
        "h.Admin.Usage.PendingStats" => Ok(pending_stats(service)),
        "h.Admin.Usage.SearchUsers" => search_users(pool, query).await,
        "h.Admin.Usage.SearchAPIKeys" => search_api_keys(pool, query).await,
        "h.Admin.Usage.ListCleanupTasks" => list_cleanup_tasks(pool, query).await,
        "h.Admin.Usage.CreateCleanupTask" => {
            create_cleanup_task(pool, actor.user_id, payload).await
        }
        "h.Admin.Usage.CancelCleanupTask" => {
            cancel_cleanup_task(
                pool,
                actor.user_id,
                required_path_id(path, "cleanup task").ok()?,
            )
            .await
        }
        _ => unreachable!("USAGE_HANDLERS and usage dispatch must stay aligned"),
    };
    Some(result)
}

#[derive(Clone, Debug, Default)]
struct UsageFilters {
    user_id: Option<i64>,
    api_key_id: Option<i64>,
    account_id: Option<i64>,
    group_id: Option<i64>,
    model: Option<String>,
    request_type: Option<i16>,
    stream: Option<bool>,
    billing_type: Option<i16>,
    billing_mode: Option<String>,
    start_time: Option<String>,
    end_time: Option<String>,
}

async fn list_usage(pool: &PgPool, query: &BTreeMap<String, String>) -> Result<Value, AdminError> {
    if let Some(raw) = trimmed_query(query, "exact_total") {
        raw.parse::<bool>().map_err(|_| {
            AdminError::BadRequest("Invalid exact_total value, use true or false".to_owned())
        })?;
    }
    let filters = parse_usage_filters(pool, query, false).await?;
    let (page, page_size) = pagination(query);
    let sort_column = match query.get("sort_by").map(String::as_str) {
        Some("id") => "usage.id",
        Some("duration_ms") => "usage.duration_ms",
        Some("total_cost") => "usage.total_cost",
        Some("actual_cost") => "usage.actual_cost",
        _ => "usage.created_at",
    };
    let direction = sort_direction(query);
    let sql = format!(
        r"
SELECT (to_jsonb(usage) - ARRAY['requested_model']::text[])
|| jsonb_build_object(
    'model', COALESCE(NULLIF(usage.requested_model, ''), usage.model),
    'request_type', CASE
        WHEN usage.request_type = 1 THEN 'sync'
        WHEN usage.request_type = 2 THEN 'stream'
        WHEN usage.request_type = 3 THEN 'ws_v2'
        WHEN usage.request_type = 4 THEN 'cyber'
        WHEN usage.openai_ws_mode THEN 'ws_v2'
        WHEN usage.stream THEN 'stream'
        ELSE 'sync'
    END,
    'stream', CASE WHEN usage.request_type = 1 THEN FALSE
                   WHEN usage.request_type IN (2, 3) THEN TRUE
                   ELSE usage.stream END,
    'openai_ws_mode', CASE WHEN usage.request_type = 3 THEN TRUE
                           WHEN usage.request_type IN (1, 2) THEN FALSE
                           ELSE usage.openai_ws_mode END
)
|| CASE WHEN relation_user.id IS NULL THEN '{{}}'::jsonb ELSE jsonb_build_object(
    'user', jsonb_build_object(
        'id', relation_user.id, 'email', relation_user.email,
        'username', relation_user.username, 'role', relation_user.role,
        'status', relation_user.status
    )
) END
|| CASE WHEN relation_key.id IS NULL THEN '{{}}'::jsonb ELSE jsonb_build_object(
    'api_key', jsonb_build_object(
        'id', relation_key.id, 'user_id', relation_key.user_id,
        'key', relation_key.key, 'name', relation_key.name,
        'group_id', relation_key.group_id, 'status', relation_key.status
    )
) END
|| CASE WHEN relation_group.id IS NULL THEN '{{}}'::jsonb ELSE jsonb_build_object(
    'group', jsonb_build_object(
        'id', relation_group.id, 'name', relation_group.name,
        'platform', relation_group.platform, 'status', relation_group.status
    )
) END
|| CASE WHEN relation_account.id IS NULL THEN '{{}}'::jsonb ELSE jsonb_build_object(
    'account', jsonb_build_object('id', relation_account.id, 'name', relation_account.name)
) END AS data
FROM usage_logs usage
LEFT JOIN users relation_user ON relation_user.id = usage.user_id
LEFT JOIN api_keys relation_key ON relation_key.id = usage.api_key_id
LEFT JOIN groups relation_group ON relation_group.id = usage.group_id
LEFT JOIN accounts relation_account ON relation_account.id = usage.account_id
{USAGE_WHERE}
ORDER BY {sort_column} {direction}, usage.id {direction}
LIMIT $12 OFFSET $13
"
    );
    let items = bind_usage_filters(sqlx::query_scalar::<_, Value>(&sql), &filters)
        .bind(page_size)
        .bind((page - 1) * page_size)
        .fetch_all(pool)
        .await?;
    let count_sql = format!("SELECT COUNT(*)::bigint FROM usage_logs usage {USAGE_WHERE}");
    let total = bind_usage_filters(sqlx::query_scalar::<_, i64>(&count_sql), &filters)
        .fetch_one(pool)
        .await?;
    Ok(paginated(&items, total, page, page_size))
}

async fn usage_stats(pool: &PgPool, query: &BTreeMap<String, String>) -> Result<Value, AdminError> {
    let filters = parse_usage_filters(pool, query, true).await?;
    let sql = format!(
        r"
SELECT COUNT(*)::bigint AS total_requests,
       COALESCE(SUM(input_tokens), 0)::bigint AS total_input_tokens,
       COALESCE(SUM(output_tokens), 0)::bigint AS total_output_tokens,
       COALESCE(SUM(cache_creation_tokens + cache_read_tokens), 0)::bigint AS total_cache_tokens,
       COALESCE(SUM(cache_creation_tokens), 0)::bigint AS total_cache_creation_tokens,
       COALESCE(SUM(cache_read_tokens), 0)::bigint AS total_cache_read_tokens,
       COALESCE(SUM(total_cost), 0)::double precision AS total_cost,
       COALESCE(SUM(actual_cost), 0)::double precision AS total_actual_cost,
       COALESCE(SUM(COALESCE(account_stats_cost, total_cost) * COALESCE(account_rate_multiplier, 1)), 0)::double precision AS total_account_cost,
       COALESCE(AVG(duration_ms), 0)::double precision AS average_duration_ms
FROM usage_logs usage
{USAGE_WHERE}
"
    );
    let row = bind_usage_query(sqlx::query(&sql), &filters)
        .fetch_one(pool)
        .await?;
    let input = row.try_get::<i64, _>("total_input_tokens")?;
    let output = row.try_get::<i64, _>("total_output_tokens")?;
    let cache = row.try_get::<i64, _>("total_cache_tokens")?;
    let endpoints = endpoint_stats(pool, &filters, "inbound_endpoint").await?;
    let upstream = endpoint_stats(pool, &filters, "upstream_endpoint").await?;
    let paths = endpoint_stats(pool, &filters, "path").await?;
    Ok(json!({
        "total_requests": row.try_get::<i64, _>("total_requests")?,
        "total_input_tokens": input,
        "total_output_tokens": output,
        "total_cache_tokens": cache,
        "total_cache_creation_tokens": row.try_get::<i64, _>("total_cache_creation_tokens")?,
        "total_cache_read_tokens": row.try_get::<i64, _>("total_cache_read_tokens")?,
        "total_tokens": input + output + cache,
        "total_cost": row.try_get::<f64, _>("total_cost")?,
        "total_actual_cost": row.try_get::<f64, _>("total_actual_cost")?,
        "total_account_cost": row.try_get::<f64, _>("total_account_cost")?,
        "average_duration_ms": row.try_get::<f64, _>("average_duration_ms")?,
        "endpoints": endpoints,
        "upstream_endpoints": upstream,
        "endpoint_paths": paths,
    }))
}

async fn endpoint_stats(
    pool: &PgPool,
    filters: &UsageFilters,
    dimension: &str,
) -> Result<Vec<Value>, AdminError> {
    let expression = match dimension {
        "inbound_endpoint" => "COALESCE(NULLIF(TRIM(usage.inbound_endpoint), ''), 'unknown')",
        "upstream_endpoint" => "COALESCE(NULLIF(TRIM(usage.upstream_endpoint), ''), 'unknown')",
        _ => {
            "CONCAT(COALESCE(NULLIF(TRIM(usage.inbound_endpoint), ''), 'unknown'), ' -> ', COALESCE(NULLIF(TRIM(usage.upstream_endpoint), ''), 'unknown'))"
        }
    };
    let sql = format!(
        r"
SELECT jsonb_build_object(
    'endpoint', {expression},
    'requests', COUNT(*)::bigint,
    'total_tokens', COALESCE(SUM(input_tokens + output_tokens + cache_creation_tokens + cache_read_tokens), 0)::bigint,
    'cost', COALESCE(SUM(total_cost), 0)::double precision,
    'actual_cost', COALESCE(SUM(actual_cost), 0)::double precision
)
FROM usage_logs usage
{USAGE_WHERE}
GROUP BY {expression}
ORDER BY COUNT(*) DESC
"
    );
    Ok(
        bind_usage_filters(sqlx::query_scalar::<_, Value>(&sql), filters)
            .fetch_all(pool)
            .await?,
    )
}

fn pending_stats(service: &AdminService) -> Value {
    let snapshot = service.runtime_stats().map_or_else(
        Default::default,
        super::service::AdminRuntimeStatsProvider::snapshot,
    );
    json!({
        "usage_log": snapshot.usage_log,
        "usage_billing": snapshot.usage_billing,
        "updated_at": Utc::now(),
    })
}

async fn search_users(
    pool: &PgPool,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let Some(keyword) = query.get("q").filter(|value| !value.is_empty()) else {
        return Ok(Value::Array(Vec::new()));
    };
    Ok(Value::Array(
        sqlx::query_scalar::<_, Value>(
            r"
SELECT jsonb_build_object('id', id, 'email', email, 'deleted', deleted_at IS NOT NULL)
FROM users
WHERE email ILIKE '%' || $1 || '%' OR username ILIKE '%' || $1 || '%'
ORDER BY email ASC, id ASC
LIMIT 30
",
        )
        .bind(keyword)
        .fetch_all(pool)
        .await?,
    ))
}

async fn search_api_keys(
    pool: &PgPool,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let user_id = parse_optional_id(query, "user_id")?;
    let keyword = query.get("q").map(String::as_str).unwrap_or_default();
    Ok(Value::Array(
        sqlx::query_scalar::<_, Value>(
            r"
SELECT jsonb_build_object('id', id, 'name', name, 'user_id', user_id)
FROM api_keys
WHERE deleted_at IS NULL
  AND ($1::bigint IS NULL OR user_id = $1)
  AND ($2 = '' OR name ILIKE '%' || $2 || '%')
ORDER BY id DESC
LIMIT 30
",
        )
        .bind(user_id)
        .bind(keyword)
        .fetch_all(pool)
        .await?,
    ))
}

async fn list_cleanup_tasks(
    pool: &PgPool,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let (page, page_size) = pagination(query);
    let items = sqlx::query_scalar::<_, Value>(&format!(
        "SELECT {} FROM usage_cleanup_tasks task ORDER BY task.created_at DESC, task.id DESC LIMIT $1 OFFSET $2",
        cleanup_task_json("task")
    ))
    .bind(page_size)
    .bind((page - 1) * page_size)
    .fetch_all(pool)
    .await?;
    let total = sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::bigint FROM usage_cleanup_tasks")
        .fetch_one(pool)
        .await?;
    Ok(paginated(&items, total, page, page_size))
}

#[derive(Debug, Deserialize)]
struct CreateCleanupRequest {
    start_date: String,
    end_date: String,
    user_id: Option<i64>,
    api_key_id: Option<i64>,
    account_id: Option<i64>,
    group_id: Option<i64>,
    model: Option<String>,
    request_type: Option<String>,
    stream: Option<bool>,
    billing_type: Option<i16>,
    #[serde(default)]
    timezone: String,
}

#[derive(Debug, Serialize)]
struct CleanupFilters {
    start_time: String,
    end_time: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    api_key_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    account_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    group_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_type: Option<i16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    billing_type: Option<i16>,
}

async fn create_cleanup_task(
    pool: &PgPool,
    actor_id: i64,
    payload: Value,
) -> Result<Value, AdminError> {
    let request: CreateCleanupRequest = serde_json::from_value(payload)
        .map_err(|error| AdminError::BadRequest(format!("Invalid request: {error}")))?;
    let start_date = request.start_date.trim();
    let end_date = request.end_date.trim();
    if start_date.is_empty() || end_date.is_empty() {
        return Err(AdminError::BadRequest(
            "start_date and end_date are required".to_owned(),
        ));
    }
    validate_positive_options([
        ("user_id", request.user_id),
        ("api_key_id", request.api_key_id),
        ("account_id", request.account_id),
        ("group_id", request.group_id),
    ])?;
    let start_time = parse_user_date(pool, start_date, &request.timezone, false).await?;
    let end_time = parse_user_date(pool, end_date, &request.timezone, true).await?;
    let parsed_start = DateTime::parse_from_rfc3339(&start_time)
        .map_err(|_| AdminError::BadRequest("Invalid start_date".to_owned()))?;
    let parsed_end = DateTime::parse_from_rfc3339(&end_time)
        .map_err(|_| AdminError::BadRequest("Invalid end_date".to_owned()))?;
    if parsed_end < parsed_start {
        return Err(AdminError::BadRequest(
            "end_date must be after start_date".to_owned(),
        ));
    }
    if parsed_end.signed_duration_since(parsed_start)
        > chrono::Duration::days(MAX_CLEANUP_RANGE_DAYS)
    {
        return Err(AdminError::BadRequest(format!(
            "date range exceeds {MAX_CLEANUP_RANGE_DAYS} days"
        )));
    }
    let request_type = request
        .request_type
        .as_deref()
        .map(parse_request_type)
        .transpose()?;
    let model = request
        .model
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    if model.as_ref().is_some_and(|value| value.len() > 100) {
        return Err(AdminError::BadRequest("model is too long".to_owned()));
    }
    // The worker uses an inclusive `created_at <= end_time` predicate, while
    // the API's end date is inclusive by calendar day. Keep midnight of the
    // following day outside the cleanup range at PostgreSQL's microsecond
    // timestamp precision.
    let end_time = (parsed_end - chrono::Duration::microseconds(1)).to_rfc3339();
    let filters = CleanupFilters {
        start_time,
        end_time,
        user_id: request.user_id,
        api_key_id: request.api_key_id,
        account_id: request.account_id,
        group_id: request.group_id,
        model,
        request_type,
        stream: request_type.is_none().then_some(request.stream).flatten(),
        billing_type: request.billing_type,
    };
    let filters =
        serde_json::to_value(filters).map_err(|error| AdminError::BadRequest(error.to_string()))?;
    let id = sqlx::query_scalar::<_, i64>(
        "INSERT INTO usage_cleanup_tasks (status, filters, created_by, deleted_rows) VALUES ('pending', $1, $2, 0) RETURNING id",
    )
    .bind(filters)
    .bind(actor_id)
    .fetch_one(pool)
    .await?;
    get_cleanup_task(pool, id).await
}

async fn cancel_cleanup_task(pool: &PgPool, actor_id: i64, id: i64) -> Result<Value, AdminError> {
    let mut transaction = pool.begin().await?;
    let status = sqlx::query_scalar::<_, String>(
        "SELECT status FROM usage_cleanup_tasks WHERE id = $1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(AdminError::NotFound("cleanup task"))?;
    if status == "canceled" {
        transaction.commit().await?;
        return Ok(json!({ "id": id, "status": "canceled" }));
    }
    if !matches!(status.as_str(), "pending" | "running") {
        return Err(AdminError::Conflict(
            "cleanup task cannot be canceled in current status".to_owned(),
        ));
    }
    sqlx::query(
        r"
UPDATE usage_cleanup_tasks
SET status = 'canceled', canceled_by = $2, canceled_at = NOW(),
    finished_at = NOW(), error_message = NULL, updated_at = NOW()
WHERE id = $1
",
    )
    .bind(id)
    .bind(actor_id)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(json!({ "id": id, "status": "canceled" }))
}

async fn get_cleanup_task(pool: &PgPool, id: i64) -> Result<Value, AdminError> {
    sqlx::query_scalar::<_, Value>(&format!(
        "SELECT {} FROM usage_cleanup_tasks task WHERE task.id = $1",
        cleanup_task_json("task")
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(AdminError::NotFound("cleanup task"))
}

fn cleanup_task_json(alias: &str) -> String {
    format!(
        r"
jsonb_strip_nulls(
    to_jsonb({alias})
    || jsonb_build_object(
        'filters', CASE WHEN {alias}.filters ? 'request_type' THEN
            jsonb_set(
                {alias}.filters,
                '{{request_type}}',
                to_jsonb(CASE ({alias}.filters->>'request_type')::smallint
                    WHEN 1 THEN 'sync' WHEN 2 THEN 'stream'
                    WHEN 3 THEN 'ws_v2' WHEN 4 THEN 'cyber' ELSE 'unknown' END)
            )
        ELSE {alias}.filters END
    )
)
"
    )
}

async fn parse_usage_filters(
    pool: &PgPool,
    query: &BTreeMap<String, String>,
    stats_defaults: bool,
) -> Result<UsageFilters, AdminError> {
    let request_type = trimmed_query(query, "request_type")
        .as_deref()
        .map(parse_request_type)
        .transpose()?;
    let stream = if request_type.is_some() {
        None
    } else {
        parse_optional_bool(query, "stream")?
    };
    let mut filters = UsageFilters {
        user_id: parse_optional_id(query, "user_id")?,
        api_key_id: parse_optional_id(query, "api_key_id")?,
        account_id: parse_optional_id(query, "account_id")?,
        group_id: parse_optional_id(query, "group_id")?,
        model: trimmed_query(query, "model"),
        request_type,
        stream,
        billing_type: parse_optional_i16(query, "billing_type")?,
        billing_mode: trimmed_query(query, "billing_mode"),
        start_time: None,
        end_time: None,
    };
    let timezone = query
        .get("timezone")
        .map(String::as_str)
        .unwrap_or_default();
    let start = trimmed_query(query, "start_date");
    let end = trimmed_query(query, "end_date");
    if stats_defaults && (start.is_none() || end.is_none()) {
        let period = query.get("period").map_or("today", String::as_str);
        let (start_time, end_time) = default_stats_range(pool, timezone, period).await?;
        filters.start_time = Some(start_time);
        filters.end_time = Some(end_time);
    } else {
        if let Some(start) = start {
            filters.start_time = Some(parse_user_date(pool, &start, timezone, false).await?);
        }
        if let Some(end) = end {
            filters.end_time = Some(parse_user_date(pool, &end, timezone, true).await?);
        }
    }
    Ok(filters)
}

async fn parse_user_date(
    pool: &PgPool,
    value: &str,
    timezone: &str,
    next_day: bool,
) -> Result<String, AdminError> {
    let expression = if next_day {
        "(($1::date + 1)::timestamp AT TIME ZONE COALESCE(NULLIF($2, ''), current_setting('TIMEZONE')))"
    } else {
        "($1::date::timestamp AT TIME ZONE COALESCE(NULLIF($2, ''), current_setting('TIMEZONE')))"
    };
    let timestamp = sqlx::query_scalar::<_, i64>(&format!(
        "SELECT EXTRACT(EPOCH FROM ({expression}))::bigint"
    ))
    .bind(value)
    .bind(timezone)
    .fetch_one(pool)
    .await
    .map_err(|_| AdminError::BadRequest("Invalid date or timezone".to_owned()))?;
    DateTime::<Utc>::from_timestamp(timestamp, 0)
        .map(|value| value.to_rfc3339())
        .ok_or_else(|| AdminError::BadRequest("Invalid date".to_owned()))
}

async fn default_stats_range(
    pool: &PgPool,
    timezone: &str,
    period: &str,
) -> Result<(String, String), AdminError> {
    let row = sqlx::query(
        r"
WITH zone AS (
    SELECT COALESCE(NULLIF($1, ''), current_setting('TIMEZONE')) AS name
)
SELECT EXTRACT(EPOCH FROM (CASE $2
         WHEN 'week' THEN NOW() - INTERVAL '7 days'
         WHEN 'month' THEN NOW() - INTERVAL '1 month'
         ELSE date_trunc('day', NOW() AT TIME ZONE zone.name) AT TIME ZONE zone.name
       END))::bigint AS start_time,
       EXTRACT(EPOCH FROM NOW())::bigint AS end_time
FROM zone
",
    )
    .bind(timezone)
    .bind(period)
    .fetch_one(pool)
    .await
    .map_err(|_| AdminError::BadRequest("Invalid timezone".to_owned()))?;
    let start = row.try_get::<i64, _>("start_time")?;
    let end = row.try_get::<i64, _>("end_time")?;
    let start = DateTime::<Utc>::from_timestamp(start, 0)
        .ok_or_else(|| AdminError::BadRequest("Invalid statistics range".to_owned()))?;
    let end = DateTime::<Utc>::from_timestamp(end, 0)
        .ok_or_else(|| AdminError::BadRequest("Invalid statistics range".to_owned()))?;
    Ok((start.to_rfc3339(), end.to_rfc3339()))
}

fn parse_request_type(value: &str) -> Result<i16, AdminError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "unknown" => Ok(0),
        "sync" => Ok(1),
        "stream" => Ok(2),
        "ws_v2" => Ok(3),
        "cyber" => Ok(4),
        _ => Err(AdminError::BadRequest(
            "invalid request_type, allowed values: unknown, sync, stream, ws_v2, cyber".to_owned(),
        )),
    }
}

fn bind_usage_filters<'q, O>(
    query: sqlx::query::QueryScalar<'q, sqlx::Postgres, O, sqlx::postgres::PgArguments>,
    filters: &'q UsageFilters,
) -> sqlx::query::QueryScalar<'q, sqlx::Postgres, O, sqlx::postgres::PgArguments>
where
    O: Send + Unpin,
{
    query
        .bind(filters.user_id)
        .bind(filters.api_key_id)
        .bind(filters.account_id)
        .bind(filters.group_id)
        .bind(filters.model.as_deref())
        .bind(filters.request_type)
        .bind(filters.stream)
        .bind(filters.billing_type)
        .bind(filters.billing_mode.as_deref())
        .bind(filters.start_time.as_deref())
        .bind(filters.end_time.as_deref())
}

fn bind_usage_query<'q>(
    query: sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>,
    filters: &'q UsageFilters,
) -> sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments> {
    query
        .bind(filters.user_id)
        .bind(filters.api_key_id)
        .bind(filters.account_id)
        .bind(filters.group_id)
        .bind(filters.model.as_deref())
        .bind(filters.request_type)
        .bind(filters.stream)
        .bind(filters.billing_type)
        .bind(filters.billing_mode.as_deref())
        .bind(filters.start_time.as_deref())
        .bind(filters.end_time.as_deref())
}

fn parse_optional_id(
    query: &BTreeMap<String, String>,
    key: &str,
) -> Result<Option<i64>, AdminError> {
    let Some(raw) = query.get(key).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let value = raw
        .parse::<i64>()
        .map_err(|_| AdminError::BadRequest(format!("Invalid {key}")))?;
    Ok((value > 0).then_some(value))
}

fn parse_optional_i16(
    query: &BTreeMap<String, String>,
    key: &str,
) -> Result<Option<i16>, AdminError> {
    query
        .get(key)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .parse::<i16>()
                .map_err(|_| AdminError::BadRequest(format!("Invalid {key}")))
        })
        .transpose()
}

fn parse_optional_bool(
    query: &BTreeMap<String, String>,
    key: &str,
) -> Result<Option<bool>, AdminError> {
    query
        .get(key)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value.parse::<bool>().map_err(|_| {
                AdminError::BadRequest(format!("Invalid {key} value, use true or false"))
            })
        })
        .transpose()
}

fn validate_positive_options<const N: usize>(
    values: [(&str, Option<i64>); N],
) -> Result<(), AdminError> {
    for (name, value) in values {
        if value.is_some_and(|value| value <= 0) {
            return Err(AdminError::BadRequest(format!(
                "{name} must be a positive integer"
            )));
        }
    }
    Ok(())
}

fn pagination(query: &BTreeMap<String, String>) -> (i64, i64) {
    let page = query_i64(query, "page", 1).max(1);
    let page_size = query_i64(query, "page_size", query_i64(query, "limit", 20));
    let page_size = if (1..=MAX_PAGE_SIZE).contains(&page_size) {
        page_size
    } else {
        20
    };
    (page, page_size)
}

fn query_i64(query: &BTreeMap<String, String>, key: &str, default: i64) -> i64 {
    query
        .get(key)
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn trimmed_query(query: &BTreeMap<String, String>, key: &str) -> Option<String> {
    query
        .get(key)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn sort_direction(query: &BTreeMap<String, String>) -> &'static str {
    if query
        .get("sort_order")
        .is_some_and(|value| value.eq_ignore_ascii_case("asc"))
    {
        "ASC"
    } else {
        "DESC"
    }
}

fn paginated(items: &[Value], total: i64, page: i64, page_size: i64) -> Value {
    json!({
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": ((total + page_size - 1) / page_size).max(1),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatcher_claims_all_eight_usage_routes() {
        assert_eq!(USAGE_HANDLERS.len(), 8);
        for handler in USAGE_HANDLERS {
            assert!(crate::route_contract::routes().any(|route| route.handler == handler));
        }
    }

    #[test]
    fn request_type_parser_matches_go_names() {
        assert_eq!(parse_request_type("sync").unwrap(), 1);
        assert_eq!(parse_request_type("STREAM").unwrap(), 2);
        assert_eq!(parse_request_type("ws_v2").unwrap(), 3);
        assert_eq!(parse_request_type("cyber").unwrap(), 4);
        assert!(parse_request_type("websocket").is_err());
    }

    #[test]
    fn cleanup_task_dto_converts_request_type_to_name() {
        let sql = cleanup_task_json("task");
        assert!(sql.contains("WHEN 3 THEN 'ws_v2'"));
        assert!(sql.contains("jsonb_strip_nulls"));
    }

    #[test]
    fn cleanup_end_excludes_the_next_day_midnight() {
        let exclusive = DateTime::parse_from_rfc3339("2026-07-15T00:00:00Z").unwrap();
        let inclusive = exclusive - chrono::Duration::microseconds(1);
        assert_eq!(inclusive.to_rfc3339(), "2026-07-14T23:59:59.999999+00:00");
    }
}
