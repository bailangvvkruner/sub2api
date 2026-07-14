use std::collections::HashMap;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::HeaderMap,
    routing::get,
};
use serde::Serialize;
use serde_json::Value;
use sqlx::Row;

use super::authenticated_user;
use crate::control_api::{ApiEnvelope, ApiError, ControlApiState};

const TIMELINE_LIMIT: i64 = 60;

pub(super) fn routes() -> Router<ControlApiState> {
    Router::new()
        .route("/api/v1/channel-monitors", get(list))
        .route("/api/v1/channel-monitors/{id}/status", get(status))
}

#[derive(Clone, Debug)]
struct Monitor {
    id: i64,
    name: String,
    provider: String,
    group_name: String,
    primary_model: String,
    extra_models: Vec<String>,
}

#[derive(Clone, Debug)]
struct Latest {
    status: String,
    latency_ms: Option<i32>,
    ping_latency_ms: Option<i32>,
}

#[derive(Debug, Serialize)]
struct MonitorListResponse {
    items: Vec<MonitorListItem>,
}

#[derive(Debug, Serialize)]
struct MonitorListItem {
    id: i64,
    name: String,
    provider: String,
    group_name: String,
    primary_model: String,
    primary_status: String,
    primary_latency_ms: Option<i32>,
    primary_ping_latency_ms: Option<i32>,
    availability_7d: f64,
    extra_models: Vec<ExtraModelStatus>,
    timeline: Vec<TimelinePoint>,
}

#[derive(Debug, Serialize)]
struct ExtraModelStatus {
    model: String,
    status: String,
    latency_ms: Option<i32>,
}

#[derive(Clone, Debug, Serialize)]
struct TimelinePoint {
    status: String,
    latency_ms: Option<i32>,
    ping_latency_ms: Option<i32>,
    checked_at: String,
}

#[derive(Debug, Serialize)]
struct MonitorDetail {
    id: i64,
    name: String,
    provider: String,
    group_name: String,
    models: Vec<ModelStat>,
}

#[derive(Debug, Serialize)]
struct ModelStat {
    model: String,
    latest_status: String,
    latest_latency_ms: Option<i32>,
    availability_7d: f64,
    availability_15d: f64,
    availability_30d: f64,
    avg_latency_7d_ms: Option<i32>,
}

#[derive(Clone, Debug, Default)]
struct Availability {
    pct_7d: f64,
    pct_15d: f64,
    pct_30d: f64,
    avg_latency_7d_ms: Option<i32>,
}

async fn list(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
) -> Result<Json<ApiEnvelope<MonitorListResponse>>, ApiError> {
    let _user = authenticated_user(&state, &headers).await?;
    if !feature_enabled(&state).await {
        return Ok(Json(ApiEnvelope::success(MonitorListResponse {
            items: Vec::new(),
        })));
    }
    let monitors = load_monitors(&state).await?;
    if monitors.is_empty() {
        return Ok(Json(ApiEnvelope::success(MonitorListResponse {
            items: Vec::new(),
        })));
    }
    let ids = monitors
        .iter()
        .map(|monitor| monitor.id)
        .collect::<Vec<_>>();
    let latest = load_latest(&state, &ids).await?;
    let availability = load_availability(&state, &ids).await?;
    let timelines = load_timelines(&state, &monitors).await?;
    let items = monitors
        .into_iter()
        .map(|monitor| {
            let primary_key = (monitor.id, monitor.primary_model.clone());
            let primary = latest.get(&primary_key);
            let extras = monitor
                .extra_models
                .iter()
                .map(|model| {
                    let item = latest.get(&(monitor.id, model.clone()));
                    ExtraModelStatus {
                        model: model.clone(),
                        status: item.map_or_else(String::new, |value| value.status.clone()),
                        latency_ms: item.and_then(|value| value.latency_ms),
                    }
                })
                .collect();
            MonitorListItem {
                id: monitor.id,
                name: monitor.name,
                provider: monitor.provider,
                group_name: monitor.group_name,
                primary_model: monitor.primary_model,
                primary_status: primary.map_or_else(String::new, |value| value.status.clone()),
                primary_latency_ms: primary.and_then(|value| value.latency_ms),
                primary_ping_latency_ms: primary.and_then(|value| value.ping_latency_ms),
                availability_7d: availability
                    .get(&primary_key)
                    .map_or(0.0, |value| value.pct_7d),
                extra_models: extras,
                timeline: timelines.get(&monitor.id).cloned().unwrap_or_default(),
            }
        })
        .collect();
    Ok(Json(ApiEnvelope::success(MonitorListResponse { items })))
}

async fn status(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<ApiEnvelope<MonitorDetail>>, ApiError> {
    let _user = authenticated_user(&state, &headers).await?;
    if id <= 0 {
        return Err(ApiError::bad_request("Invalid channel monitor ID"));
    }
    if !feature_enabled(&state).await {
        return Err(ApiError::not_found("Channel monitor not found"));
    }
    let monitor = load_monitor(&state, id)
        .await?
        .ok_or_else(|| ApiError::not_found("Channel monitor not found"))?;
    let latest = load_latest(&state, &[id]).await?;
    let availability = load_availability(&state, &[id]).await?;
    let models = std::iter::once(&monitor.primary_model)
        .chain(monitor.extra_models.iter())
        .map(|model| {
            let key = (id, model.clone());
            let latest = latest.get(&key);
            let availability = availability.get(&key).cloned().unwrap_or_default();
            ModelStat {
                model: model.clone(),
                latest_status: latest.map_or_else(String::new, |value| value.status.clone()),
                latest_latency_ms: latest.and_then(|value| value.latency_ms),
                availability_7d: availability.pct_7d,
                availability_15d: availability.pct_15d,
                availability_30d: availability.pct_30d,
                avg_latency_7d_ms: availability.avg_latency_7d_ms,
            }
        })
        .collect();
    Ok(Json(ApiEnvelope::success(MonitorDetail {
        id,
        name: monitor.name,
        provider: monitor.provider,
        group_name: monitor.group_name,
        models,
    })))
}

async fn feature_enabled(state: &ControlApiState) -> bool {
    match sqlx::query_scalar::<_, String>(
        "SELECT value FROM settings WHERE key = 'channel_monitor_enabled'",
    )
    .fetch_optional(state.pool())
    .await
    {
        Ok(value) => value.is_none_or(|raw| !raw.trim().eq_ignore_ascii_case("false")),
        Err(error) => {
            tracing::warn!(%error, "failed to read channel monitor feature flag; failing open");
            true
        }
    }
}

async fn load_monitors(state: &ControlApiState) -> Result<Vec<Monitor>, ApiError> {
    let rows = sqlx::query(
        r"
SELECT id, name, provider, group_name, primary_model, extra_models
FROM channel_monitors
WHERE enabled = TRUE
ORDER BY id
",
    )
    .fetch_all(state.pool())
    .await?;
    rows.iter().map(monitor_from_row).collect::<Result<_, _>>()
}

async fn load_monitor(state: &ControlApiState, id: i64) -> Result<Option<Monitor>, ApiError> {
    let row = sqlx::query(
        r"
SELECT id, name, provider, group_name, primary_model, extra_models
FROM channel_monitors
WHERE id = $1 AND enabled = TRUE
",
    )
    .bind(id)
    .fetch_optional(state.pool())
    .await?;
    row.as_ref().map(monitor_from_row).transpose()
}

fn monitor_from_row(row: &sqlx::postgres::PgRow) -> Result<Monitor, ApiError> {
    let raw: Value = row.try_get("extra_models")?;
    let extra_models = serde_json::from_value(raw)
        .map_err(|error| ApiError::internal("decode channel monitor models", error))?;
    Ok(Monitor {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        provider: row.try_get("provider")?,
        group_name: row.try_get("group_name")?,
        primary_model: row.try_get("primary_model")?,
        extra_models,
    })
}

async fn load_latest(
    state: &ControlApiState,
    ids: &[i64],
) -> Result<HashMap<(i64, String), Latest>, ApiError> {
    let rows = sqlx::query(
        r"
SELECT DISTINCT ON (monitor_id, model)
    monitor_id, model, status, latency_ms, ping_latency_ms
FROM channel_monitor_histories
WHERE monitor_id = ANY($1)
ORDER BY monitor_id, model, checked_at DESC
",
    )
    .bind(ids)
    .fetch_all(state.pool())
    .await?;
    rows.iter()
        .map(|row| {
            Ok((
                (row.try_get("monitor_id")?, row.try_get("model")?),
                Latest {
                    status: row.try_get("status")?,
                    latency_ms: row.try_get("latency_ms")?,
                    ping_latency_ms: row.try_get("ping_latency_ms")?,
                },
            ))
        })
        .collect::<Result<_, sqlx::Error>>()
        .map_err(Into::into)
}

async fn load_availability(
    state: &ControlApiState,
    ids: &[i64],
) -> Result<HashMap<(i64, String), Availability>, ApiError> {
    let rows = sqlx::query(
        r"
SELECT
    monitor_id, model,
    COUNT(*) FILTER (WHERE checked_at >= NOW() - INTERVAL '7 days')::bigint AS total_7d,
    COUNT(*) FILTER (WHERE checked_at >= NOW() - INTERVAL '7 days'
        AND status IN ('operational', 'degraded'))::bigint AS ok_7d,
    COUNT(*) FILTER (WHERE checked_at >= NOW() - INTERVAL '15 days')::bigint AS total_15d,
    COUNT(*) FILTER (WHERE checked_at >= NOW() - INTERVAL '15 days'
        AND status IN ('operational', 'degraded'))::bigint AS ok_15d,
    COUNT(*)::bigint AS total_30d,
    COUNT(*) FILTER (WHERE status IN ('operational', 'degraded'))::bigint AS ok_30d,
    AVG(latency_ms) FILTER (WHERE checked_at >= NOW() - INTERVAL '7 days')::integer
        AS avg_latency_7d
FROM channel_monitor_histories
WHERE monitor_id = ANY($1) AND checked_at >= NOW() - INTERVAL '30 days'
GROUP BY monitor_id, model
",
    )
    .bind(ids)
    .fetch_all(state.pool())
    .await?;
    rows.iter()
        .map(|row| {
            let total_7d: i64 = row.try_get("total_7d")?;
            let ok_7d: i64 = row.try_get("ok_7d")?;
            let total_15d: i64 = row.try_get("total_15d")?;
            let ok_15d: i64 = row.try_get("ok_15d")?;
            let total_30d: i64 = row.try_get("total_30d")?;
            let ok_30d: i64 = row.try_get("ok_30d")?;
            let avg: Option<i32> = row.try_get("avg_latency_7d")?;
            Ok((
                (row.try_get("monitor_id")?, row.try_get("model")?),
                Availability {
                    pct_7d: percentage(ok_7d, total_7d),
                    pct_15d: percentage(ok_15d, total_15d),
                    pct_30d: percentage(ok_30d, total_30d),
                    avg_latency_7d_ms: avg,
                },
            ))
        })
        .collect::<Result<_, sqlx::Error>>()
        .map_err(Into::into)
}

async fn load_timelines(
    state: &ControlApiState,
    monitors: &[Monitor],
) -> Result<HashMap<i64, Vec<TimelinePoint>>, ApiError> {
    let ids = monitors
        .iter()
        .map(|monitor| monitor.id)
        .collect::<Vec<_>>();
    let models = monitors
        .iter()
        .map(|monitor| monitor.primary_model.as_str())
        .collect::<Vec<_>>();
    let rows = sqlx::query(
        r#"
WITH targets AS (
    SELECT unnest($1::bigint[]) AS monitor_id, unnest($2::text[]) AS model
), ranked AS (
    SELECT h.monitor_id, h.status, h.latency_ms, h.ping_latency_ms,
           to_char(h.checked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS checked_at,
           ROW_NUMBER() OVER (PARTITION BY h.monitor_id ORDER BY h.checked_at DESC) AS row_number
    FROM channel_monitor_histories h
    JOIN targets t ON t.monitor_id = h.monitor_id AND t.model = h.model
)
SELECT monitor_id, status, latency_ms, ping_latency_ms, checked_at
FROM ranked
WHERE row_number <= $3
ORDER BY monitor_id, checked_at DESC
"#,
    )
    .bind(&ids)
    .bind(&models)
    .bind(TIMELINE_LIMIT)
    .fetch_all(state.pool())
    .await?;
    let mut timelines = HashMap::<i64, Vec<TimelinePoint>>::new();
    for row in rows {
        timelines
            .entry(row.try_get("monitor_id")?)
            .or_default()
            .push(TimelinePoint {
                status: row.try_get("status")?,
                latency_ms: row.try_get("latency_ms")?,
                ping_latency_ms: row.try_get("ping_latency_ms")?,
                checked_at: row.try_get("checked_at")?,
            });
    }
    Ok(timelines)
}

#[allow(clippy::cast_precision_loss)]
fn percentage(ok: i64, total: i64) -> f64 {
    if total == 0 {
        0.0
    } else {
        ok as f64 * 100.0 / total as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn availability_percentage_handles_empty_windows() {
        assert!(percentage(0, 0).abs() < f64::EPSILON);
        assert!((percentage(3, 4) - 75.0).abs() < f64::EPSILON);
    }
}
