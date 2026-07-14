use std::collections::HashMap;

use axum::{Json, Router, extract::State, http::HeaderMap, routing::get};
use serde::Serialize;
use sqlx::Row;

use super::{
    authenticated_user, decimal,
    groups::{GROUP_SELECT, GroupView, group_from_row},
};
use crate::control_api::{ApiEnvelope, ApiError, ControlApiState};

pub(super) fn routes() -> Router<ControlApiState> {
    Router::new()
        .route("/api/v1/subscriptions", get(list))
        .route("/api/v1/subscriptions/active", get(active))
        .route("/api/v1/subscriptions/progress", get(progress))
        .route("/api/v1/subscriptions/summary", get(summary))
}

#[derive(Clone, Debug, Serialize)]
struct SubscriptionView {
    id: i64,
    user_id: i64,
    group_id: i64,
    starts_at: String,
    expires_at: String,
    status: String,
    daily_window_start: Option<String>,
    weekly_window_start: Option<String>,
    monthly_window_start: Option<String>,
    daily_usage_usd: f64,
    weekly_usage_usd: f64,
    monthly_usage_usd: f64,
    created_at: String,
    updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    revoked_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<GroupView>,
}

#[derive(Clone, Debug)]
struct SubscriptionData {
    view: SubscriptionView,
    starts_at_epoch: i64,
    expires_at_epoch: i64,
    daily_window_epoch: Option<i64>,
    weekly_window_epoch: Option<i64>,
    monthly_window_epoch: Option<i64>,
}

#[derive(Debug, Serialize)]
struct ProgressInfo {
    subscription: SubscriptionView,
    progress: SubscriptionProgress,
}

#[derive(Debug, Serialize)]
struct SubscriptionProgress {
    id: i64,
    group_name: String,
    expires_at: String,
    expires_in_days: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    daily: Option<WindowProgress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    weekly: Option<WindowProgress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    monthly: Option<WindowProgress>,
}

#[derive(Debug, Serialize)]
struct WindowProgress {
    limit_usd: f64,
    used_usd: f64,
    remaining_usd: f64,
    percentage: f64,
    window_start: String,
    resets_at: String,
    resets_in_seconds: i64,
}

#[derive(Debug, Serialize)]
struct SubscriptionSummary {
    active_count: usize,
    total_used_usd: f64,
    subscriptions: Vec<SummaryItem>,
}

#[derive(Debug, Serialize)]
struct SummaryItem {
    id: i64,
    group_id: i64,
    group_name: String,
    status: String,
    #[serde(skip_serializing_if = "is_zero")]
    daily_used_usd: f64,
    #[serde(skip_serializing_if = "is_zero")]
    daily_limit_usd: f64,
    #[serde(skip_serializing_if = "is_zero")]
    weekly_used_usd: f64,
    #[serde(skip_serializing_if = "is_zero")]
    weekly_limit_usd: f64,
    #[serde(skip_serializing_if = "is_zero")]
    monthly_used_usd: f64,
    #[serde(skip_serializing_if = "is_zero")]
    monthly_limit_usd: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
}

async fn list(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
) -> Result<Json<ApiEnvelope<Vec<SubscriptionView>>>, ApiError> {
    let user = authenticated_user(&state, &headers).await?;
    let subscriptions = load_subscriptions(&state, user.id, false).await?;
    Ok(Json(ApiEnvelope::success(
        subscriptions.into_iter().map(|item| item.view).collect(),
    )))
}

async fn active(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
) -> Result<Json<ApiEnvelope<Vec<SubscriptionView>>>, ApiError> {
    let user = authenticated_user(&state, &headers).await?;
    let subscriptions = load_subscriptions(&state, user.id, true).await?;
    Ok(Json(ApiEnvelope::success(
        subscriptions.into_iter().map(|item| item.view).collect(),
    )))
}

async fn progress(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
) -> Result<Json<ApiEnvelope<Vec<ProgressInfo>>>, ApiError> {
    let user = authenticated_user(&state, &headers).await?;
    let subscriptions = load_subscriptions(&state, user.id, true).await?;
    let result = subscriptions
        .into_iter()
        .filter_map(|subscription| {
            let progress = calculate_progress(&subscription)?;
            Some(ProgressInfo {
                subscription: subscription.view,
                progress,
            })
        })
        .collect();
    Ok(Json(ApiEnvelope::success(result)))
}

async fn summary(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
) -> Result<Json<ApiEnvelope<SubscriptionSummary>>, ApiError> {
    let user = authenticated_user(&state, &headers).await?;
    let subscriptions = load_subscriptions(&state, user.id, true).await?;
    let total_used_usd = subscriptions
        .iter()
        .map(|item| item.view.monthly_usage_usd)
        .sum();
    let items = subscriptions
        .iter()
        .map(|item| {
            let group = item.view.group.as_ref();
            SummaryItem {
                id: item.view.id,
                group_id: item.view.group_id,
                group_name: group.map_or_else(String::new, |value| value.name.clone()),
                status: item.view.status.clone(),
                daily_used_usd: item.view.daily_usage_usd,
                daily_limit_usd: group.and_then(|value| value.daily_limit_usd).unwrap_or(0.0),
                weekly_used_usd: item.view.weekly_usage_usd,
                weekly_limit_usd: group
                    .and_then(|value| value.weekly_limit_usd)
                    .unwrap_or(0.0),
                monthly_used_usd: item.view.monthly_usage_usd,
                monthly_limit_usd: group
                    .and_then(|value| value.monthly_limit_usd)
                    .unwrap_or(0.0),
                expires_at: Some(item.view.expires_at.clone()),
            }
        })
        .collect();
    Ok(Json(ApiEnvelope::success(SubscriptionSummary {
        active_count: subscriptions.len(),
        total_used_usd,
        subscriptions: items,
    })))
}

async fn load_subscriptions(
    state: &ControlApiState,
    user_id: i64,
    active_only: bool,
) -> Result<Vec<SubscriptionData>, ApiError> {
    let active_filter = if active_only {
        "AND s.status = 'active' AND s.expires_at > NOW()"
    } else {
        ""
    };
    let sql = format!(
        r#"
SELECT
    s.id, s.user_id, s.group_id,
    to_char(s.starts_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS starts_at,
    to_char(s.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS expires_at,
    s.status,
    CASE WHEN s.daily_window_start IS NULL THEN NULL ELSE
        to_char(s.daily_window_start AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END AS daily_window_start,
    CASE WHEN s.weekly_window_start IS NULL THEN NULL ELSE
        to_char(s.weekly_window_start AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END AS weekly_window_start,
    CASE WHEN s.monthly_window_start IS NULL THEN NULL ELSE
        to_char(s.monthly_window_start AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END AS monthly_window_start,
    s.daily_usage_usd::text AS daily_usage_usd,
    s.weekly_usage_usd::text AS weekly_usage_usd,
    s.monthly_usage_usd::text AS monthly_usage_usd,
    to_char(s.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at,
    to_char(s.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS updated_at,
    EXTRACT(EPOCH FROM s.starts_at)::bigint AS starts_at_epoch,
    EXTRACT(EPOCH FROM s.expires_at)::bigint AS expires_at_epoch,
    EXTRACT(EPOCH FROM s.daily_window_start)::bigint AS daily_window_epoch,
    EXTRACT(EPOCH FROM s.weekly_window_start)::bigint AS weekly_window_epoch,
    EXTRACT(EPOCH FROM s.monthly_window_start)::bigint AS monthly_window_epoch
FROM user_subscriptions s
WHERE s.user_id = $1 AND s.deleted_at IS NULL {active_filter}
ORDER BY s.created_at DESC, s.id DESC
"#
    );
    let rows = sqlx::query(&sql)
        .bind(user_id)
        .fetch_all(state.pool())
        .await?;
    let group_ids = rows
        .iter()
        .map(|row| row.try_get::<i64, _>("group_id"))
        .collect::<Result<Vec<_>, _>>()?;
    let mut groups = load_groups(state, &group_ids).await?;
    rows.iter()
        .map(|row| {
            let group_id: i64 = row.try_get("group_id")?;
            Ok(SubscriptionData {
                view: SubscriptionView {
                    id: row.try_get("id")?,
                    user_id: row.try_get("user_id")?,
                    group_id,
                    starts_at: row.try_get("starts_at")?,
                    expires_at: row.try_get("expires_at")?,
                    status: row.try_get("status")?,
                    daily_window_start: row.try_get("daily_window_start")?,
                    weekly_window_start: row.try_get("weekly_window_start")?,
                    monthly_window_start: row.try_get("monthly_window_start")?,
                    daily_usage_usd: decimal(
                        row.try_get::<String, _>("daily_usage_usd")?.as_str(),
                    )?,
                    weekly_usage_usd: decimal(
                        row.try_get::<String, _>("weekly_usage_usd")?.as_str(),
                    )?,
                    monthly_usage_usd: decimal(
                        row.try_get::<String, _>("monthly_usage_usd")?.as_str(),
                    )?,
                    created_at: row.try_get("created_at")?,
                    updated_at: row.try_get("updated_at")?,
                    revoked_at: None,
                    group: groups.remove(&group_id),
                },
                starts_at_epoch: row.try_get("starts_at_epoch")?,
                expires_at_epoch: row.try_get("expires_at_epoch")?,
                daily_window_epoch: row.try_get("daily_window_epoch")?,
                weekly_window_epoch: row.try_get("weekly_window_epoch")?,
                monthly_window_epoch: row.try_get("monthly_window_epoch")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map_err(Into::into)
}

async fn load_groups(
    state: &ControlApiState,
    group_ids: &[i64],
) -> Result<HashMap<i64, GroupView>, ApiError> {
    if group_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let sql = format!("{GROUP_SELECT} WHERE g.id = ANY($1) AND g.deleted_at IS NULL");
    let rows = sqlx::query(&sql)
        .bind(group_ids)
        .fetch_all(state.pool())
        .await?;
    rows.iter()
        .map(|row| {
            let group = group_from_row(row)?;
            Ok((group.id, group))
        })
        .collect::<Result<HashMap<_, _>, sqlx::Error>>()
        .map_err(Into::into)
}

fn calculate_progress(subscription: &SubscriptionData) -> Option<SubscriptionProgress> {
    let group = subscription.view.group.as_ref()?;
    let now = chrono::Utc::now().timestamp();
    let expires_in_days = ((subscription.expires_at_epoch - now) / 86_400).max(0);
    let one_time_daily = subscription.expires_at_epoch <= subscription.starts_at_epoch + 86_400;
    Some(SubscriptionProgress {
        id: subscription.view.id,
        group_name: group.name.clone(),
        expires_at: subscription.view.expires_at.clone(),
        expires_in_days,
        daily: window_progress(
            group.daily_limit_usd,
            subscription.view.daily_usage_usd,
            subscription.daily_window_epoch,
            if one_time_daily {
                Some(subscription.expires_at_epoch)
            } else {
                subscription.daily_window_epoch.map(|start| start + 86_400)
            },
            subscription.view.daily_window_start.as_deref(),
            now,
        ),
        weekly: window_progress(
            group.weekly_limit_usd,
            subscription.view.weekly_usage_usd,
            subscription.weekly_window_epoch,
            subscription
                .weekly_window_epoch
                .map(|start| start + 7 * 86_400),
            subscription.view.weekly_window_start.as_deref(),
            now,
        ),
        monthly: window_progress(
            group.monthly_limit_usd,
            subscription.view.monthly_usage_usd,
            subscription.monthly_window_epoch,
            subscription
                .monthly_window_epoch
                .map(|start| start + 30 * 86_400),
            subscription.view.monthly_window_start.as_deref(),
            now,
        ),
    })
}

fn window_progress(
    limit: Option<f64>,
    used: f64,
    window_epoch: Option<i64>,
    reset_epoch: Option<i64>,
    window_start: Option<&str>,
    now: i64,
) -> Option<WindowProgress> {
    let limit = limit.filter(|value| *value > 0.0)?;
    window_epoch?;
    let reset_epoch = reset_epoch?;
    let window_start = window_start?.to_owned();
    Some(WindowProgress {
        limit_usd: limit,
        used_usd: used,
        remaining_usd: (limit - used).max(0.0),
        percentage: ((used / limit) * 100.0).min(100.0),
        window_start,
        resets_at: format_epoch(reset_epoch),
        resets_in_seconds: (reset_epoch - now).max(0),
    })
}

fn format_epoch(epoch: i64) -> String {
    chrono::DateTime::from_timestamp(epoch, 0).map_or_else(String::new, |time| {
        time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    })
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(value: &f64) -> bool {
    *value == 0.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_caps_usage_and_reset_countdown() {
        let progress = window_progress(
            Some(10.0),
            12.0,
            Some(1_000),
            Some(2_000),
            Some("1970-01-01T00:16:40Z"),
            3_000,
        )
        .expect("configured window should produce progress");
        assert!(progress.remaining_usd.abs() < f64::EPSILON);
        assert!((progress.percentage - 100.0).abs() < f64::EPSILON);
        assert_eq!(progress.resets_in_seconds, 0);
    }
}
