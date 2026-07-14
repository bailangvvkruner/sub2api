use std::collections::BTreeSet;

use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    response::Response,
    routing::get,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgPool, Row, postgres::PgRow};

use super::shared::{Envelope, json_text, success, trim_to};
use crate::admin_api::{
    http::AdminApiState,
    models::{AdminError, AdminIdentity, Page},
};

pub(super) fn router() -> Router<AdminApiState> {
    Router::new()
        .route("/api/v1/admin/announcements", get(list).post(create))
        .route(
            "/api/v1/admin/announcements/{id}",
            get(get_one).put(update).delete(delete_one),
        )
        .route(
            "/api/v1/admin/announcements/{id}/read-status",
            get(read_status),
        )
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    #[serde(default = "default_page")]
    page: i64,
    #[serde(default = "default_page_size")]
    page_size: i64,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    search: Option<String>,
    #[serde(default = "default_announcement_sort")]
    sort_by: String,
    #[serde(default = "default_desc")]
    sort_order: String,
}

impl ListQuery {
    fn normalize(mut self) -> Self {
        self.page = self.page.max(1);
        self.page_size = self.page_size.clamp(1, 1_000);
        self.status = self
            .status
            .take()
            .map(|value| trim_to(&value, 20))
            .filter(|value| !value.is_empty());
        self.search = self
            .search
            .take()
            .map(|value| trim_to(&value, 200))
            .filter(|value| !value.is_empty());
        self
    }

    const fn offset(&self) -> i64 {
        (self.page - 1) * self.page_size
    }
}

const fn default_page() -> i64 {
    1
}

const fn default_page_size() -> i64 {
    20
}

fn default_announcement_sort() -> String {
    "created_at".to_owned()
}

fn default_email_sort() -> String {
    "email".to_owned()
}

fn default_desc() -> String {
    "desc".to_owned()
}

fn default_asc() -> String {
    "asc".to_owned()
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct Targeting {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    any_of: Vec<ConditionGroup>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ConditionGroup {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    all_of: Vec<Condition>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Condition {
    #[serde(rename = "type")]
    kind: String,
    operator: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    group_ids: Vec<i64>,
    #[serde(default, skip_serializing_if = "is_zero")]
    value: f64,
}

#[allow(clippy::float_cmp, clippy::trivially_copy_pass_by_ref)]
const fn is_zero(value: &f64) -> bool {
    *value == 0.0
}

#[derive(Debug, Deserialize)]
struct CreateRequest {
    title: String,
    content: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    notify_mode: String,
    #[serde(default)]
    targeting: Value,
    #[serde(default)]
    starts_at: Option<i64>,
    #[serde(default)]
    ends_at: Option<i64>,
}

#[derive(Debug, Default, Deserialize)]
struct UpdateRequest {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    notify_mode: Option<String>,
    #[serde(default)]
    targeting: Option<Value>,
    #[serde(default)]
    starts_at: Option<i64>,
    #[serde(default)]
    ends_at: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
struct AnnouncementView {
    id: i64,
    title: String,
    content: String,
    status: String,
    notify_mode: String,
    targeting: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    starts_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ends_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_by: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    updated_by: Option<i64>,
    created_at: String,
    updated_at: String,
}

const ANNOUNCEMENT_COLUMNS: &str = r"
id, title, content, status, notify_mode, targeting::text AS targeting_json,
starts_at::text AS starts_at, ends_at::text AS ends_at, created_by, updated_by,
created_at::text AS created_at, updated_at::text AS updated_at";

async fn list(
    State(state): State<AdminApiState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Envelope<Page<AnnouncementView>>>, AdminError> {
    let query = query.normalize();
    let search = query.search.as_deref().map(like_pattern);
    let total = sqlx::query_scalar::<_, i64>(
        r"SELECT COUNT(*) FROM announcements
          WHERE ($1::text IS NULL OR status = $1)
            AND ($2::text IS NULL OR title ILIKE $2 OR content ILIKE $2)",
    )
    .bind(query.status.as_deref())
    .bind(search.as_deref())
    .fetch_one(state.service.pool())
    .await?;
    let sort = announcement_sort(&query.sort_by);
    let order = sort_order(&query.sort_order);
    let sql = format!(
        "SELECT {ANNOUNCEMENT_COLUMNS} FROM announcements
         WHERE ($1::text IS NULL OR status = $1)
           AND ($2::text IS NULL OR title ILIKE $2 OR content ILIKE $2)
         ORDER BY {sort} {order}, id {order} LIMIT $3 OFFSET $4"
    );
    let rows = sqlx::query(&sql)
        .bind(query.status.as_deref())
        .bind(search.as_deref())
        .bind(query.page_size)
        .bind(query.offset())
        .fetch_all(state.service.pool())
        .await?;
    let items = rows
        .iter()
        .map(announcement_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    let page_query = crate::admin_api::models::PageQuery {
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
) -> Result<Json<Envelope<AnnouncementView>>, AdminError> {
    positive_id(id, "announcement")?;
    Ok(Json(Envelope::success(
        fetch_announcement(state.service.pool(), id).await?,
    )))
}

async fn create(
    State(state): State<AdminApiState>,
    Extension(identity): Extension<AdminIdentity>,
    Json(request): Json<CreateRequest>,
) -> Result<Response, AdminError> {
    let title = valid_title(&request.title)?;
    let content = valid_content(&request.content)?;
    let status = valid_status(default_if_blank(&request.status, "draft"))?;
    let notify_mode = valid_notify_mode(default_if_blank(&request.notify_mode, "silent"))?;
    let targeting = normalize_targeting(request.targeting)?;
    let starts_at = request.starts_at.filter(|value| *value > 0);
    let ends_at = request.ends_at.filter(|value| *value > 0);
    validate_schedule(starts_at, ends_at)?;
    let targeting_json = serde_json::to_string(&targeting)
        .map_err(|error| AdminError::BadRequest(error.to_string()))?;
    let id = sqlx::query_scalar::<_, i64>(
        r"INSERT INTO announcements
          (title, content, status, notify_mode, targeting, starts_at, ends_at, created_by, updated_by)
          VALUES ($1, $2, $3, $4, $5::jsonb,
                  CASE WHEN $6::bigint IS NULL THEN NULL ELSE to_timestamp($6) END,
                  CASE WHEN $7::bigint IS NULL THEN NULL ELSE to_timestamp($7) END,
                  $8, $8)
          RETURNING id",
    )
    .bind(title)
    .bind(content)
    .bind(status)
    .bind(notify_mode)
    .bind(targeting_json)
    .bind(starts_at)
    .bind(ends_at)
    .bind(identity.user_id)
    .fetch_one(state.service.pool())
    .await?;
    Ok(success(fetch_announcement(state.service.pool(), id).await?))
}

async fn update(
    State(state): State<AdminApiState>,
    Extension(identity): Extension<AdminIdentity>,
    Path(id): Path<i64>,
    Json(request): Json<UpdateRequest>,
) -> Result<Response, AdminError> {
    positive_id(id, "announcement")?;
    let mut transaction = state.service.pool().begin().await?;
    let row = sqlx::query(
        r"SELECT title, content, status, notify_mode, targeting::text AS targeting_json,
                  EXTRACT(EPOCH FROM starts_at)::bigint AS starts_epoch,
                  EXTRACT(EPOCH FROM ends_at)::bigint AS ends_epoch
           FROM announcements WHERE id = $1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(AdminError::NotFound("announcement"))?;

    let title = request
        .title
        .as_deref()
        .map(valid_title)
        .transpose()?
        .unwrap_or(row.try_get("title")?);
    let content = request
        .content
        .as_deref()
        .map(valid_content)
        .transpose()?
        .unwrap_or(row.try_get("content")?);
    let status = request
        .status
        .as_deref()
        .map(valid_status)
        .transpose()?
        .unwrap_or(row.try_get("status")?);
    let notify_mode = request
        .notify_mode
        .as_deref()
        .map(valid_notify_mode)
        .transpose()?
        .unwrap_or(row.try_get("notify_mode")?);
    let targeting_json: String = row.try_get("targeting_json")?;
    let targeting = request
        .targeting
        .map_or_else(|| Ok(json_text(&targeting_json)), normalize_targeting)?;
    let starts_at = request
        .starts_at
        .map_or(row.try_get("starts_epoch")?, |value| {
            (value != 0).then_some(value)
        });
    let ends_at = request.ends_at.map_or(row.try_get("ends_epoch")?, |value| {
        (value != 0).then_some(value)
    });
    validate_schedule(starts_at, ends_at)?;
    sqlx::query(
        r"UPDATE announcements SET
             title = $2, content = $3, status = $4, notify_mode = $5,
             targeting = $6::jsonb,
             starts_at = CASE WHEN $7::bigint IS NULL THEN NULL ELSE to_timestamp($7) END,
             ends_at = CASE WHEN $8::bigint IS NULL THEN NULL ELSE to_timestamp($8) END,
             updated_by = $9, updated_at = NOW()
           WHERE id = $1",
    )
    .bind(id)
    .bind(title)
    .bind(content)
    .bind(status)
    .bind(notify_mode)
    .bind(serde_json::to_string(&targeting).map_err(|error| {
        AdminError::BadRequest(format!("invalid announcement targeting: {error}"))
    })?)
    .bind(starts_at)
    .bind(ends_at)
    .bind(identity.user_id)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(success(fetch_announcement(state.service.pool(), id).await?))
}

async fn delete_one(
    State(state): State<AdminApiState>,
    Path(id): Path<i64>,
) -> Result<Response, AdminError> {
    positive_id(id, "announcement")?;
    let deleted =
        sqlx::query_scalar::<_, i64>("DELETE FROM announcements WHERE id = $1 RETURNING id")
            .bind(id)
            .fetch_optional(state.service.pool())
            .await?;
    if deleted.is_none() {
        return Err(AdminError::NotFound("announcement"));
    }
    Ok(success(json!({
        "message": "Announcement deleted successfully"
    })))
}

#[derive(Debug, Deserialize)]
struct ReadStatusQuery {
    #[serde(default = "default_page")]
    page: i64,
    #[serde(default = "default_page_size")]
    page_size: i64,
    #[serde(default)]
    search: Option<String>,
    #[serde(default = "default_email_sort")]
    sort_by: String,
    #[serde(default = "default_asc")]
    sort_order: String,
}

#[derive(Debug, Serialize)]
struct UserReadStatus {
    user_id: i64,
    email: String,
    username: String,
    balance: f64,
    eligible: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    read_at: Option<String>,
}

async fn read_status(
    State(state): State<AdminApiState>,
    Path(id): Path<i64>,
    Query(mut query): Query<ReadStatusQuery>,
) -> Result<Json<Envelope<Page<UserReadStatus>>>, AdminError> {
    positive_id(id, "announcement")?;
    query.page = query.page.max(1);
    query.page_size = query.page_size.clamp(1, 1_000);
    let targeting_json =
        sqlx::query_scalar::<_, String>("SELECT targeting::text FROM announcements WHERE id = $1")
            .bind(id)
            .fetch_optional(state.service.pool())
            .await?
            .ok_or(AdminError::NotFound("announcement"))?;
    let targeting = json_text(&targeting_json);
    let search = query
        .search
        .as_deref()
        .map(|value| trim_to(value, 200))
        .filter(|value| !value.is_empty())
        .map(|value| like_pattern(&value));
    let total = sqlx::query_scalar::<_, i64>(
        r"SELECT COUNT(*) FROM users u
          WHERE u.deleted_at IS NULL
            AND ($1::text IS NULL OR u.email ILIKE $1 OR COALESCE(u.username, '') ILIKE $1)",
    )
    .bind(search.as_deref())
    .fetch_one(state.service.pool())
    .await?;
    let sort = user_sort(&query.sort_by);
    let order = sort_order(&query.sort_order);
    let sql = format!(
        r"SELECT u.id, u.email, COALESCE(u.username, '') AS username,
                  u.balance::double precision AS balance,
                  ARRAY(SELECT DISTINCT us.group_id FROM user_subscriptions us
                        WHERE us.user_id = u.id AND us.status = 'active'
                          AND us.starts_at <= NOW() AND us.expires_at > NOW()
                          AND us.deleted_at IS NULL) AS active_group_ids,
                  ar.read_at::text AS read_at
           FROM users u
           LEFT JOIN announcement_reads ar
             ON ar.user_id = u.id AND ar.announcement_id = $1
           WHERE u.deleted_at IS NULL
             AND ($2::text IS NULL OR u.email ILIKE $2 OR COALESCE(u.username, '') ILIKE $2)
           ORDER BY {sort} {order}, u.id {order} LIMIT $3 OFFSET $4"
    );
    let rows = sqlx::query(&sql)
        .bind(id)
        .bind(search.as_deref())
        .bind(query.page_size)
        .bind((query.page - 1) * query.page_size)
        .fetch_all(state.service.pool())
        .await?;
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let balance: f64 = row.try_get("balance")?;
        let group_ids: Vec<i64> = row.try_get("active_group_ids")?;
        items.push(UserReadStatus {
            user_id: row.try_get("id")?,
            email: row.try_get("email")?,
            username: row.try_get("username")?,
            balance,
            eligible: targeting_matches(&targeting, balance, &group_ids),
            read_at: row.try_get("read_at")?,
        });
    }
    let page_query = crate::admin_api::models::PageQuery {
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

async fn fetch_announcement(pool: &PgPool, id: i64) -> Result<AnnouncementView, AdminError> {
    let sql = format!("SELECT {ANNOUNCEMENT_COLUMNS} FROM announcements WHERE id = $1");
    let row = sqlx::query(&sql)
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(AdminError::NotFound("announcement"))?;
    announcement_from_row(&row)
}

fn announcement_from_row(row: &PgRow) -> Result<AnnouncementView, AdminError> {
    let targeting_json: String = row.try_get("targeting_json")?;
    Ok(AnnouncementView {
        id: row.try_get("id")?,
        title: row.try_get("title")?,
        content: row.try_get("content")?,
        status: row.try_get("status")?,
        notify_mode: row.try_get("notify_mode")?,
        targeting: json_text(&targeting_json),
        starts_at: row.try_get("starts_at")?,
        ends_at: row.try_get("ends_at")?,
        created_by: row.try_get("created_by")?,
        updated_by: row.try_get("updated_by")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn normalize_targeting(value: Value) -> Result<Value, AdminError> {
    if value.is_null() {
        return Ok(json!({}));
    }
    let mut targeting: Targeting = serde_json::from_value(value)
        .map_err(|_| AdminError::BadRequest("invalid announcement targeting rules".to_owned()))?;
    if targeting.any_of.len() > 50 {
        return Err(AdminError::BadRequest(
            "invalid announcement targeting rules".to_owned(),
        ));
    }
    for group in &mut targeting.any_of {
        if group.all_of.is_empty() || group.all_of.len() > 50 {
            return Err(AdminError::BadRequest(
                "invalid announcement targeting rules".to_owned(),
            ));
        }
        for condition in &mut group.all_of {
            condition.kind = condition.kind.trim().to_owned();
            condition.operator = condition.operator.trim().to_owned();
            if !condition.value.is_finite() || condition.group_ids.iter().any(|id| *id <= 0) {
                return Err(AdminError::BadRequest(
                    "invalid announcement targeting rules".to_owned(),
                ));
            }
            match condition.kind.as_str() {
                "subscription" if condition.operator == "in" && !condition.group_ids.is_empty() => {
                }
                "balance"
                    if matches!(
                        condition.operator.as_str(),
                        "gt" | "gte" | "lt" | "lte" | "eq"
                    ) => {}
                _ => {
                    return Err(AdminError::BadRequest(
                        "invalid announcement targeting rules".to_owned(),
                    ));
                }
            }
        }
    }
    serde_json::to_value(targeting)
        .map_err(|error| AdminError::BadRequest(format!("invalid targeting: {error}")))
}

#[allow(clippy::float_cmp)]
fn targeting_matches(value: &Value, balance: f64, active_group_ids: &[i64]) -> bool {
    let Ok(targeting) = serde_json::from_value::<Targeting>(value.clone()) else {
        return false;
    };
    if targeting.any_of.is_empty() {
        return true;
    }
    let groups = active_group_ids.iter().copied().collect::<BTreeSet<_>>();
    targeting.any_of.iter().any(|group| {
        !group.all_of.is_empty()
            && group
                .all_of
                .iter()
                .all(|condition| match condition.kind.as_str() {
                    "subscription" => {
                        condition.operator == "in"
                            && condition.group_ids.iter().any(|id| groups.contains(id))
                    }
                    "balance" => match condition.operator.as_str() {
                        "gt" => balance > condition.value,
                        "gte" => balance >= condition.value,
                        "lt" => balance < condition.value,
                        "lte" => balance <= condition.value,
                        "eq" => balance == condition.value,
                        _ => false,
                    },
                    _ => false,
                })
    })
}

fn valid_title(value: &str) -> Result<String, AdminError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 200 {
        return Err(AdminError::BadRequest(
            "announcement title is required and must not exceed 200 bytes".to_owned(),
        ));
    }
    Ok(value.to_owned())
}

fn valid_content(value: &str) -> Result<String, AdminError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(AdminError::BadRequest(
            "announcement content is required".to_owned(),
        ));
    }
    Ok(value.to_owned())
}

fn valid_status(value: &str) -> Result<String, AdminError> {
    let value = value.trim();
    if matches!(value, "draft" | "active" | "archived") {
        Ok(value.to_owned())
    } else {
        Err(AdminError::BadRequest(
            "announcement status must be draft, active, or archived".to_owned(),
        ))
    }
}

fn valid_notify_mode(value: &str) -> Result<String, AdminError> {
    let value = value.trim();
    if matches!(value, "silent" | "popup") {
        Ok(value.to_owned())
    } else {
        Err(AdminError::BadRequest(
            "announcement notify_mode must be silent or popup".to_owned(),
        ))
    }
}

fn validate_schedule(starts_at: Option<i64>, ends_at: Option<i64>) -> Result<(), AdminError> {
    if starts_at
        .zip(ends_at)
        .is_some_and(|(start, end)| start >= end)
    {
        return Err(AdminError::BadRequest(
            "announcement starts_at must be earlier than ends_at".to_owned(),
        ));
    }
    Ok(())
}

fn default_if_blank<'a>(value: &'a str, default: &'a str) -> &'a str {
    if value.trim().is_empty() {
        default
    } else {
        value
    }
}

fn positive_id(id: i64, resource: &str) -> Result<(), AdminError> {
    if id > 0 {
        Ok(())
    } else {
        Err(AdminError::BadRequest(format!("invalid {resource} ID")))
    }
}

fn announcement_sort(value: &str) -> &'static str {
    match value {
        "title" => "title",
        "status" => "status",
        "starts_at" => "starts_at",
        "ends_at" => "ends_at",
        "updated_at" => "updated_at",
        _ => "created_at",
    }
}

fn user_sort(value: &str) -> &'static str {
    match value {
        "username" => "username",
        "balance" => "balance",
        "created_at" => "u.created_at",
        "read_at" => "ar.read_at",
        _ => "u.email",
    }
}

fn sort_order(value: &str) -> &'static str {
    if value.eq_ignore_ascii_case("asc") {
        "ASC"
    } else {
        "DESC"
    }
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
    use serde_json::json;

    use super::{normalize_targeting, targeting_matches};

    #[test]
    fn targeting_validation_and_matching_follow_go_contract() {
        let value = normalize_targeting(json!({
            "any_of": [{"all_of": [
                {"type": "subscription", "operator": "in", "group_ids": [3]},
                {"type": "balance", "operator": "gte", "value": 10}
            ]}]
        }))
        .expect("targeting should validate");
        assert!(targeting_matches(&value, 10.0, &[3]));
        assert!(!targeting_matches(&value, 9.0, &[3]));
        assert!(!targeting_matches(&value, 10.0, &[4]));
    }
}
