use std::collections::HashSet;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::Row;

use super::authenticated_user;
use crate::control_api::{ApiEnvelope, ApiError, ControlApiState, MessageResponse};

pub(super) fn routes() -> Router<ControlApiState> {
    Router::new()
        .route("/api/v1/announcements", get(list))
        .route("/api/v1/announcements/{id}/read", post(mark_read))
}

#[derive(Debug, Default, Deserialize)]
struct AnnouncementQuery {
    unread_only: Option<String>,
}

#[derive(Debug, Serialize)]
struct AnnouncementView {
    id: i64,
    title: String,
    content: String,
    notify_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    starts_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ends_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    read_at: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct Targeting {
    #[serde(default)]
    any_of: Vec<ConditionGroup>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct ConditionGroup {
    #[serde(default)]
    all_of: Vec<Condition>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct Condition {
    #[serde(rename = "type")]
    kind: String,
    operator: String,
    #[serde(default)]
    group_ids: Vec<i64>,
    #[serde(default)]
    value: f64,
}

async fn list(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    Query(query): Query<AnnouncementQuery>,
) -> Result<Json<ApiEnvelope<Vec<AnnouncementView>>>, ApiError> {
    let user = authenticated_user(&state, &headers).await?;
    let subscriptions = active_subscription_groups(state.pool(), user.id).await?;
    let rows = sqlx::query(
        r#"
SELECT
    a.id, a.title, a.content, a.notify_mode, a.targeting,
    CASE WHEN a.starts_at IS NULL THEN NULL ELSE
        to_char(a.starts_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END AS starts_at,
    CASE WHEN a.ends_at IS NULL THEN NULL ELSE
        to_char(a.ends_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END AS ends_at,
    CASE WHEN ar.read_at IS NULL THEN NULL ELSE
        to_char(ar.read_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END AS read_at,
    to_char(a.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at,
    to_char(a.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS updated_at
FROM announcements a
LEFT JOIN announcement_reads ar
  ON ar.announcement_id = a.id AND ar.user_id = $1
WHERE a.status = 'active'
  AND (a.starts_at IS NULL OR a.starts_at <= NOW())
  AND (a.ends_at IS NULL OR a.ends_at > NOW())
ORDER BY (ar.read_at IS NULL) DESC, a.id DESC
LIMIT 200
"#,
    )
    .bind(user.id)
    .fetch_all(state.pool())
    .await?;
    let unread_only = query.unread_only.as_deref().is_some_and(parse_bool);
    let mut announcements = Vec::with_capacity(rows.len());
    for row in rows {
        let targeting = decode_targeting(row.try_get("targeting")?)?;
        if !targeting.matches(user.balance, &subscriptions) {
            continue;
        }
        let read_at: Option<String> = row.try_get("read_at")?;
        if unread_only && read_at.is_some() {
            continue;
        }
        announcements.push(AnnouncementView {
            id: row.try_get("id")?,
            title: row.try_get("title")?,
            content: row.try_get("content")?,
            notify_mode: row.try_get("notify_mode")?,
            starts_at: row.try_get("starts_at")?,
            ends_at: row.try_get("ends_at")?,
            read_at,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        });
    }
    Ok(Json(ApiEnvelope::success(announcements)))
}

async fn mark_read(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<ApiEnvelope<MessageResponse>>, ApiError> {
    if id <= 0 {
        return Err(ApiError::bad_request("Invalid announcement ID"));
    }
    let user = authenticated_user(&state, &headers).await?;
    let mut transaction = state.pool().begin().await?;
    let targeting = sqlx::query_scalar::<_, Value>(
        r"
SELECT targeting
FROM announcements
WHERE id = $1 AND status = 'active'
  AND (starts_at IS NULL OR starts_at <= NOW())
  AND (ends_at IS NULL OR ends_at > NOW())
",
    )
    .bind(id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| ApiError::not_found("Announcement not found"))?;
    let subscriptions = sqlx::query_scalar::<_, i64>(
        r"
SELECT group_id
FROM user_subscriptions
WHERE user_id = $1 AND status = 'active' AND expires_at > NOW()
  AND deleted_at IS NULL
",
    )
    .bind(user.id)
    .fetch_all(&mut *transaction)
    .await?
    .into_iter()
    .collect::<HashSet<_>>();
    if !decode_targeting(targeting)?.matches(user.balance, &subscriptions) {
        return Err(ApiError::not_found("Announcement not found"));
    }
    sqlx::query(
        r"
INSERT INTO announcement_reads (announcement_id, user_id, read_at, created_at)
VALUES ($1, $2, NOW(), NOW())
ON CONFLICT (announcement_id, user_id) DO NOTHING
",
    )
    .bind(id)
    .bind(user.id)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Json(ApiEnvelope::success(MessageResponse {
        message: "ok",
    })))
}

async fn active_subscription_groups(
    pool: &sqlx::PgPool,
    user_id: i64,
) -> Result<HashSet<i64>, ApiError> {
    Ok(sqlx::query_scalar::<_, i64>(
        r"
SELECT group_id
FROM user_subscriptions
WHERE user_id = $1 AND status = 'active' AND expires_at > NOW()
  AND deleted_at IS NULL
",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?
    .into_iter()
    .collect())
}

fn decode_targeting(value: Value) -> Result<Targeting, ApiError> {
    serde_json::from_value(value)
        .map_err(|error| ApiError::internal("decode announcement targeting", error))
}

fn parse_bool(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "y" | "on"
    )
}

impl Targeting {
    fn matches(&self, balance: f64, subscriptions: &HashSet<i64>) -> bool {
        self.any_of.is_empty()
            || self.any_of.iter().any(|group| {
                !group.all_of.is_empty()
                    && group
                        .all_of
                        .iter()
                        .all(|condition| condition.matches(balance, subscriptions))
            })
    }
}

impl Condition {
    fn matches(&self, balance: f64, subscriptions: &HashSet<i64>) -> bool {
        match (self.kind.as_str(), self.operator.as_str()) {
            ("subscription", "in") => self
                .group_ids
                .iter()
                .any(|group_id| subscriptions.contains(group_id)),
            ("balance", "gt") => balance > self.value,
            ("balance", "gte") => balance >= self.value,
            ("balance", "lt") => balance < self.value,
            ("balance", "lte") => balance <= self.value,
            ("balance", "eq") => balance.total_cmp(&self.value).is_eq(),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targeting_preserves_or_of_and_groups() {
        let subscriptions = HashSet::from([7_i64]);
        let target = Targeting {
            any_of: vec![
                ConditionGroup {
                    all_of: vec![Condition {
                        kind: "balance".to_owned(),
                        operator: "gt".to_owned(),
                        value: 100.0,
                        ..Condition::default()
                    }],
                },
                ConditionGroup {
                    all_of: vec![Condition {
                        kind: "subscription".to_owned(),
                        operator: "in".to_owned(),
                        group_ids: vec![7],
                        ..Condition::default()
                    }],
                },
            ],
        };
        assert!(target.matches(0.0, &subscriptions));
        assert!(!target.matches(0.0, &HashSet::new()));
    }
}
