use std::collections::{BTreeMap, BTreeSet};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    response::Response,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgPool, Row, postgres::PgRow};

use super::shared::{
    Envelope, created, json_text, normalize_api_mode, normalize_body_config, normalize_headers,
    normalize_provider, success,
};
use crate::admin_api::{
    http::AdminApiState,
    models::{AdminError, Patch},
};

pub(super) fn router() -> Router<AdminApiState> {
    Router::new()
        .route(
            "/api/v1/admin/channel-monitor-templates",
            get(list).post(create),
        )
        .route(
            "/api/v1/admin/channel-monitor-templates/{id}",
            get(get_one).put(update).delete(delete_one),
        )
        .route(
            "/api/v1/admin/channel-monitor-templates/{id}/monitors",
            get(associated_monitors),
        )
        .route(
            "/api/v1/admin/channel-monitor-templates/{id}/apply",
            post(apply),
        )
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    api_mode: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateRequest {
    name: String,
    provider: String,
    #[serde(default)]
    api_mode: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    extra_headers: BTreeMap<String, String>,
    #[serde(default)]
    body_override_mode: String,
    #[serde(default)]
    body_override: Option<Value>,
}

#[derive(Debug, Default, Deserialize)]
struct UpdateRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    api_mode: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    extra_headers: Option<BTreeMap<String, String>>,
    #[serde(default)]
    body_override_mode: Option<String>,
    #[serde(default)]
    body_override: Patch<Value>,
}

#[derive(Clone, Debug, Serialize)]
struct TemplateView {
    id: i64,
    name: String,
    provider: String,
    api_mode: String,
    description: String,
    extra_headers: Value,
    body_override_mode: String,
    body_override: Option<Value>,
    created_at: String,
    updated_at: String,
    associated_monitors: i64,
}

#[derive(Clone, Debug)]
struct TemplateRecord {
    view: TemplateView,
    headers: BTreeMap<String, String>,
}

const TEMPLATE_COLUMNS: &str = r"
t.id, t.name, t.provider, t.api_mode, t.description,
t.extra_headers::text AS extra_headers_json,
t.body_override_mode, t.body_override::text AS body_override_json,
t.created_at::text AS created_at, t.updated_at::text AS updated_at,
(SELECT COUNT(*) FROM channel_monitors m WHERE m.template_id = t.id) AS associated_monitors";

async fn list(
    State(state): State<AdminApiState>,
    Query(query): Query<ListQuery>,
) -> Result<Response, AdminError> {
    let provider = query
        .provider
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let Some(provider) = provider {
        normalize_provider(provider)?;
    }
    let api_mode = query
        .api_mode
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let Some(api_mode) = api_mode
        && !matches!(api_mode, "chat_completions" | "responses")
    {
        return Err(AdminError::BadRequest("invalid api_mode filter".to_owned()));
    }
    let sql = format!(
        "SELECT {TEMPLATE_COLUMNS} FROM channel_monitor_request_templates t
         WHERE ($1::text IS NULL OR t.provider = $1)
           AND ($2::text IS NULL OR t.api_mode = $2)
         ORDER BY t.provider, t.name, t.id"
    );
    let rows = sqlx::query(&sql)
        .bind(provider)
        .bind(api_mode)
        .fetch_all(state.service.pool())
        .await?;
    let items = rows
        .iter()
        .map(template_from_row)
        .map(|result| result.map(|record| record.view))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(success(json!({"items": items})))
}

async fn get_one(
    State(state): State<AdminApiState>,
    Path(id): Path<i64>,
) -> Result<Json<Envelope<TemplateView>>, AdminError> {
    require_id(id)?;
    Ok(Json(Envelope::success(
        fetch_template(state.service.pool(), id).await?.view,
    )))
}

async fn create(
    State(state): State<AdminApiState>,
    Json(request): Json<CreateRequest>,
) -> Result<Response, AdminError> {
    let name = valid_name(&request.name)?;
    let provider = normalize_provider(&request.provider)?;
    let api_mode = normalize_api_mode(&provider, &request.api_mode)?;
    let description = valid_description(&request.description)?;
    let headers = normalize_headers(request.extra_headers)?;
    let (body_mode, body) = normalize_body_config(
        &provider,
        &api_mode,
        &request.body_override_mode,
        request.body_override,
    )?;
    let headers_json = serde_json::to_string(&headers)
        .map_err(|error| AdminError::BadRequest(error.to_string()))?;
    let body_json = body
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|error| AdminError::BadRequest(error.to_string()))?;
    let id = sqlx::query_scalar::<_, i64>(
        r"INSERT INTO channel_monitor_request_templates
          (name, provider, api_mode, description, extra_headers, body_override_mode, body_override)
          VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7::jsonb) RETURNING id",
    )
    .bind(name)
    .bind(provider)
    .bind(api_mode)
    .bind(description)
    .bind(headers_json)
    .bind(body_mode)
    .bind(body_json.as_deref())
    .fetch_one(state.service.pool())
    .await?;
    Ok(created(
        fetch_template(state.service.pool(), id).await?.view,
    ))
}

async fn update(
    State(state): State<AdminApiState>,
    Path(id): Path<i64>,
    Json(request): Json<UpdateRequest>,
) -> Result<Response, AdminError> {
    require_id(id)?;
    let mut transaction = state.service.pool().begin().await?;
    let sql = format!(
        "SELECT {TEMPLATE_COLUMNS} FROM channel_monitor_request_templates t WHERE t.id = $1 FOR UPDATE"
    );
    let row = sqlx::query(&sql)
        .bind(id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(AdminError::NotFound("channel monitor template"))?;
    let existing = template_from_row(&row)?;
    let name = request
        .name
        .as_deref()
        .map(valid_name)
        .transpose()?
        .unwrap_or(existing.view.name);
    let description = request
        .description
        .as_deref()
        .map(valid_description)
        .transpose()?
        .unwrap_or(existing.view.description);
    let api_mode = request
        .api_mode
        .as_deref()
        .map(|value| normalize_api_mode(&existing.view.provider, value))
        .transpose()?
        .unwrap_or(existing.view.api_mode);
    let headers = request
        .extra_headers
        .map(normalize_headers)
        .transpose()?
        .unwrap_or(existing.headers);
    let body = match request.body_override {
        Patch::Missing => existing.view.body_override,
        Patch::Null => None,
        Patch::Value(value) => Some(value),
    };
    let body_mode = request
        .body_override_mode
        .as_deref()
        .unwrap_or(&existing.view.body_override_mode);
    let (body_mode, body) =
        normalize_body_config(&existing.view.provider, &api_mode, body_mode, body)?;
    let headers_json = serde_json::to_string(&headers)
        .map_err(|error| AdminError::BadRequest(error.to_string()))?;
    let body_json = body
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|error| AdminError::BadRequest(error.to_string()))?;
    sqlx::query(
        r"UPDATE channel_monitor_request_templates SET
             name = $2, api_mode = $3, description = $4, extra_headers = $5::jsonb,
             body_override_mode = $6, body_override = $7::jsonb, updated_at = NOW()
           WHERE id = $1",
    )
    .bind(id)
    .bind(name)
    .bind(api_mode)
    .bind(description)
    .bind(headers_json)
    .bind(body_mode)
    .bind(body_json.as_deref())
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(success(
        fetch_template(state.service.pool(), id).await?.view,
    ))
}

async fn delete_one(
    State(state): State<AdminApiState>,
    Path(id): Path<i64>,
) -> Result<Response, AdminError> {
    require_id(id)?;
    let deleted = sqlx::query_scalar::<_, i64>(
        "DELETE FROM channel_monitor_request_templates WHERE id = $1 RETURNING id",
    )
    .bind(id)
    .fetch_optional(state.service.pool())
    .await?;
    if deleted.is_none() {
        return Err(AdminError::NotFound("channel monitor template"));
    }
    Ok(success(Value::Null))
}

#[derive(Debug, Deserialize)]
struct ApplyRequest {
    monitor_ids: Vec<i64>,
}

async fn apply(
    State(state): State<AdminApiState>,
    Path(id): Path<i64>,
    Json(request): Json<ApplyRequest>,
) -> Result<Response, AdminError> {
    require_id(id)?;
    let monitor_ids = normalize_monitor_ids(&request.monitor_ids)?;
    let mut transaction = state.service.pool().begin().await?;
    let row = sqlx::query(
        r"SELECT extra_headers::text AS extra_headers_json, body_override_mode,
                  body_override::text AS body_override_json
           FROM channel_monitor_request_templates WHERE id = $1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(AdminError::NotFound("channel monitor template"))?;
    let headers_json: String = row.try_get("extra_headers_json")?;
    let body_mode: String = row.try_get("body_override_mode")?;
    let body_json: Option<String> = row.try_get("body_override_json")?;
    let affected = sqlx::query(
        r"UPDATE channel_monitors SET
             extra_headers = $3::jsonb, body_override_mode = $4,
             body_override = $5::jsonb, updated_at = NOW()
           WHERE template_id = $1 AND id = ANY($2)",
    )
    .bind(id)
    .bind(&monitor_ids)
    .bind(headers_json)
    .bind(body_mode)
    .bind(body_json.as_deref())
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    transaction.commit().await?;
    Ok(success(json!({"affected": affected})))
}

#[derive(Debug, Serialize)]
struct AssociatedMonitor {
    id: i64,
    name: String,
    provider: String,
    api_mode: String,
    enabled: bool,
}

async fn associated_monitors(
    State(state): State<AdminApiState>,
    Path(id): Path<i64>,
) -> Result<Response, AdminError> {
    require_id(id)?;
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT id FROM channel_monitor_request_templates WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(state.service.pool())
    .await?;
    if exists.is_none() {
        return Err(AdminError::NotFound("channel monitor template"));
    }
    let rows = sqlx::query(
        r"SELECT id, name, provider, api_mode, enabled FROM channel_monitors
          WHERE template_id = $1 ORDER BY name, id",
    )
    .bind(id)
    .fetch_all(state.service.pool())
    .await?;
    let items = rows
        .iter()
        .map(|row| {
            Ok(AssociatedMonitor {
                id: row.try_get("id")?,
                name: row.try_get("name")?,
                provider: row.try_get("provider")?,
                api_mode: row.try_get("api_mode")?,
                enabled: row.try_get("enabled")?,
            })
        })
        .collect::<Result<Vec<_>, AdminError>>()?;
    Ok(success(json!({"items": items})))
}

async fn fetch_template(pool: &PgPool, id: i64) -> Result<TemplateRecord, AdminError> {
    let sql = format!(
        "SELECT {TEMPLATE_COLUMNS} FROM channel_monitor_request_templates t WHERE t.id = $1"
    );
    let row = sqlx::query(&sql)
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(AdminError::NotFound("channel monitor template"))?;
    template_from_row(&row)
}

fn template_from_row(row: &PgRow) -> Result<TemplateRecord, AdminError> {
    let headers_json: String = row.try_get("extra_headers_json")?;
    let headers: BTreeMap<String, String> = serde_json::from_str(&headers_json)
        .map_err(|error| AdminError::Database(sqlx::Error::Decode(Box::new(error))))?;
    let body_json: Option<String> = row.try_get("body_override_json")?;
    Ok(TemplateRecord {
        view: TemplateView {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            provider: row.try_get("provider")?,
            api_mode: row.try_get("api_mode")?,
            description: row.try_get("description")?,
            extra_headers: json_text(&headers_json),
            body_override_mode: row.try_get("body_override_mode")?,
            body_override: body_json.as_deref().map(json_text),
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
            associated_monitors: row.try_get("associated_monitors")?,
        },
        headers,
    })
}

fn valid_name(value: &str) -> Result<String, AdminError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 100 {
        Err(AdminError::BadRequest(
            "template name is required and must not exceed 100 bytes".to_owned(),
        ))
    } else {
        Ok(value.to_owned())
    }
}

fn valid_description(value: &str) -> Result<String, AdminError> {
    let value = value.trim();
    if value.len() > 500 {
        Err(AdminError::BadRequest(
            "template description must not exceed 500 bytes".to_owned(),
        ))
    } else {
        Ok(value.to_owned())
    }
}

fn normalize_monitor_ids(ids: &[i64]) -> Result<Vec<i64>, AdminError> {
    if ids.is_empty() || ids.iter().any(|id| *id <= 0) {
        return Err(AdminError::BadRequest(
            "monitor_ids must be a non-empty array of positive IDs".to_owned(),
        ));
    }
    Ok(ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

fn require_id(id: i64) -> Result<(), AdminError> {
    if id > 0 {
        Ok(())
    } else {
        Err(AdminError::BadRequest("invalid template ID".to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::normalize_headers;

    #[test]
    fn computed_and_hop_by_hop_headers_are_rejected() {
        let mut headers = BTreeMap::new();
        headers.insert("Content-Length".to_owned(), "12".to_owned());
        assert!(normalize_headers(headers).is_err());
    }
}
