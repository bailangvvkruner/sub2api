use std::collections::{BTreeMap, BTreeSet};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    response::Response,
    routing::get,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, Row, Transaction, postgres::PgRow};

use super::shared::{Envelope, json_text, success, trim_to};
use crate::admin_api::{
    http::AdminApiState,
    models::{AdminError, Page, PageQuery},
};
use crate::billing::active_pricing_source;

pub(super) fn router() -> Router<AdminApiState> {
    Router::new()
        .route(
            "/api/v1/admin/channels/model-pricing",
            get(model_default_pricing),
        )
        .route(
            "/api/v1/admin/channels/pricing/sync-models",
            get(sync_pricing_models),
        )
        .route("/api/v1/admin/channels", get(list).post(create))
        .route(
            "/api/v1/admin/channels/{id}",
            get(get_one).put(update).delete(delete_one),
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
    #[serde(default = "default_sort")]
    sort_by: String,
    #[serde(default = "default_desc")]
    sort_order: String,
}

const fn default_page() -> i64 {
    1
}

const fn default_page_size() -> i64 {
    20
}

fn default_sort() -> String {
    "created_at".to_owned()
}

fn default_desc() -> String {
    "desc".to_owned()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PricingInterval {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id: Option<i64>,
    #[serde(default)]
    min_tokens: i32,
    #[serde(default)]
    max_tokens: Option<i32>,
    #[serde(default)]
    tier_label: String,
    #[serde(default)]
    input_price: Option<f64>,
    #[serde(default)]
    output_price: Option<f64>,
    #[serde(default)]
    cache_write_price: Option<f64>,
    #[serde(default)]
    cache_read_price: Option<f64>,
    #[serde(default)]
    per_request_price: Option<f64>,
    #[serde(default)]
    sort_order: i32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ModelPricing {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id: Option<i64>,
    #[serde(default)]
    platform: String,
    models: Vec<String>,
    #[serde(default)]
    billing_mode: String,
    #[serde(default)]
    input_price: Option<f64>,
    #[serde(default)]
    output_price: Option<f64>,
    #[serde(default)]
    cache_write_price: Option<f64>,
    #[serde(default)]
    cache_read_price: Option<f64>,
    #[serde(default)]
    image_output_price: Option<f64>,
    #[serde(default)]
    per_request_price: Option<f64>,
    #[serde(default)]
    intervals: Vec<PricingInterval>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AccountStatsPricingRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id: Option<i64>,
    #[serde(default)]
    name: String,
    #[serde(default)]
    group_ids: Vec<i64>,
    #[serde(default)]
    account_ids: Vec<i64>,
    #[serde(default)]
    pricing: Vec<ModelPricing>,
}

#[derive(Debug, Deserialize)]
struct CreateRequest {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    group_ids: Vec<i64>,
    #[serde(default)]
    model_pricing: Vec<ModelPricing>,
    #[serde(default)]
    model_mapping: BTreeMap<String, BTreeMap<String, String>>,
    #[serde(default)]
    billing_model_source: String,
    #[serde(default)]
    restrict_models: bool,
    #[serde(default)]
    features: String,
    #[serde(default)]
    features_config: Value,
    #[serde(default)]
    apply_pricing_to_account_stats: bool,
    #[serde(default)]
    account_stats_pricing_rules: Vec<AccountStatsPricingRule>,
}

#[derive(Debug, Default, Deserialize)]
struct UpdateRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    group_ids: Option<Vec<i64>>,
    #[serde(default)]
    model_pricing: Option<Vec<ModelPricing>>,
    #[serde(default)]
    model_mapping: Option<BTreeMap<String, BTreeMap<String, String>>>,
    #[serde(default)]
    billing_model_source: Option<String>,
    #[serde(default)]
    restrict_models: Option<bool>,
    #[serde(default)]
    features: Option<String>,
    #[serde(default)]
    features_config: Option<Value>,
    #[serde(default)]
    apply_pricing_to_account_stats: Option<bool>,
    #[serde(default)]
    account_stats_pricing_rules: Option<Vec<AccountStatsPricingRule>>,
}

#[derive(Clone, Debug, Serialize)]
struct ChannelView {
    id: i64,
    name: String,
    description: String,
    status: String,
    billing_model_source: String,
    restrict_models: bool,
    features: String,
    features_config: Value,
    group_ids: Vec<i64>,
    model_pricing: Vec<ModelPricing>,
    model_mapping: Value,
    apply_pricing_to_account_stats: bool,
    account_stats_pricing_rules: Vec<AccountStatsPricingRule>,
    created_at: String,
    updated_at: String,
}

async fn list(
    State(state): State<AdminApiState>,
    Query(mut query): Query<ListQuery>,
) -> Result<Json<Envelope<Page<ChannelView>>>, AdminError> {
    query.page = query.page.max(1);
    query.page_size = query.page_size.clamp(1, 1_000);
    let status = query
        .status
        .as_deref()
        .map(|value| trim_to(value, 20))
        .filter(|value| !value.is_empty());
    let search = query
        .search
        .as_deref()
        .map(|value| trim_to(value, 100))
        .filter(|value| !value.is_empty())
        .map(|value| like_pattern(&value));
    let total = sqlx::query_scalar::<_, i64>(
        r"SELECT COUNT(*) FROM channels
          WHERE ($1::text IS NULL OR status = $1)
            AND ($2::text IS NULL OR name ILIKE $2 OR description ILIKE $2)",
    )
    .bind(status.as_deref())
    .bind(search.as_deref())
    .fetch_one(state.service.pool())
    .await?;
    let sort = channel_sort(&query.sort_by);
    let order = sort_order(&query.sort_order);
    let sql = format!(
        "SELECT id FROM channels
         WHERE ($1::text IS NULL OR status = $1)
           AND ($2::text IS NULL OR name ILIKE $2 OR description ILIKE $2)
         ORDER BY {sort} {order}, id {order} LIMIT $3 OFFSET $4"
    );
    let ids = sqlx::query_scalar::<_, i64>(&sql)
        .bind(status.as_deref())
        .bind(search.as_deref())
        .bind(query.page_size)
        .bind((query.page - 1) * query.page_size)
        .fetch_all(state.service.pool())
        .await?;
    let mut items = Vec::with_capacity(ids.len());
    for id in ids {
        items.push(fetch_channel(state.service.pool(), id).await?);
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
) -> Result<Json<Envelope<ChannelView>>, AdminError> {
    require_id(id)?;
    Ok(Json(Envelope::success(
        fetch_channel(state.service.pool(), id).await?,
    )))
}

async fn create(
    State(state): State<AdminApiState>,
    Json(mut request): Json<CreateRequest>,
) -> Result<Response, AdminError> {
    request.name = valid_name(&request.name)?;
    request.description = request.description.trim().to_owned();
    request.billing_model_source = normalize_billing_source(&request.billing_model_source)?;
    request.group_ids = normalize_ids(&request.group_ids, "group")?;
    request.features_config = object_or_empty(request.features_config, "features_config")?;
    normalize_mapping(&mut request.model_mapping)?;
    normalize_pricing(&mut request.model_pricing, true)?;
    normalize_rules(&mut request.account_stats_pricing_rules)?;

    let mut transaction = state.service.pool().begin().await?;
    validate_channel_groups(&mut transaction, 0, &request.group_ids).await?;
    let model_mapping = serde_json::to_string(&request.model_mapping)
        .map_err(|error| AdminError::BadRequest(error.to_string()))?;
    let features_config = serde_json::to_string(&request.features_config)
        .map_err(|error| AdminError::BadRequest(error.to_string()))?;
    let id = sqlx::query_scalar::<_, i64>(
        r"INSERT INTO channels
          (name, description, status, model_mapping, billing_model_source,
           restrict_models, features, features_config, apply_pricing_to_account_stats)
          VALUES ($1, $2, 'active', $3::jsonb, $4, $5, $6, $7::jsonb, $8)
          RETURNING id",
    )
    .bind(request.name)
    .bind(request.description)
    .bind(model_mapping)
    .bind(request.billing_model_source)
    .bind(request.restrict_models)
    .bind(request.features)
    .bind(features_config)
    .bind(request.apply_pricing_to_account_stats)
    .fetch_one(&mut *transaction)
    .await?;
    replace_channel_groups(&mut transaction, id, &request.group_ids).await?;
    replace_model_pricing(&mut transaction, id, &request.model_pricing).await?;
    replace_account_rules(&mut transaction, id, &request.account_stats_pricing_rules).await?;
    transaction.commit().await?;
    Ok(success(fetch_channel(state.service.pool(), id).await?))
}

async fn update(
    State(state): State<AdminApiState>,
    Path(id): Path<i64>,
    Json(mut request): Json<UpdateRequest>,
) -> Result<Response, AdminError> {
    require_id(id)?;
    if let Some(name) = request.name.as_deref() {
        request.name = Some(valid_name(name)?);
    }
    if let Some(status) = request.status.as_deref() {
        request.status = Some(valid_channel_status(status)?);
    }
    if let Some(source) = request.billing_model_source.as_deref() {
        request.billing_model_source = Some(normalize_billing_source(source)?);
    }
    if let Some(group_ids) = request.group_ids.as_mut() {
        *group_ids = normalize_ids(group_ids, "group")?;
    }
    if let Some(mapping) = request.model_mapping.as_mut() {
        normalize_mapping(mapping)?;
    }
    if let Some(pricing) = request.model_pricing.as_mut() {
        normalize_pricing(pricing, true)?;
    }
    if let Some(rules) = request.account_stats_pricing_rules.as_mut() {
        normalize_rules(rules)?;
    }
    if let Some(config) = request.features_config.take() {
        request.features_config = Some(object_or_empty(config, "features_config")?);
    }

    let mut transaction = state.service.pool().begin().await?;
    let exists = sqlx::query_scalar::<_, i64>("SELECT id FROM channels WHERE id = $1 FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut *transaction)
        .await?;
    if exists.is_none() {
        return Err(AdminError::NotFound("channel"));
    }
    if let Some(group_ids) = request.group_ids.as_deref() {
        validate_channel_groups(&mut transaction, id, group_ids).await?;
    }
    let mapping_json = request
        .model_mapping
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|error| AdminError::BadRequest(error.to_string()))?;
    let features_json = request
        .features_config
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|error| AdminError::BadRequest(error.to_string()))?;
    sqlx::query(
        r"UPDATE channels SET
             name = COALESCE($2, name), description = COALESCE($3, description),
             status = COALESCE($4, status),
             model_mapping = COALESCE($5::jsonb, model_mapping),
             billing_model_source = COALESCE($6, billing_model_source),
             restrict_models = COALESCE($7, restrict_models),
             features = COALESCE($8, features),
             features_config = COALESCE($9::jsonb, features_config),
             apply_pricing_to_account_stats = COALESCE($10, apply_pricing_to_account_stats),
             updated_at = NOW()
           WHERE id = $1",
    )
    .bind(id)
    .bind(request.name.as_deref())
    .bind(request.description.as_deref())
    .bind(request.status.as_deref())
    .bind(mapping_json.as_deref())
    .bind(request.billing_model_source.as_deref())
    .bind(request.restrict_models)
    .bind(request.features.as_deref())
    .bind(features_json.as_deref())
    .bind(request.apply_pricing_to_account_stats)
    .execute(&mut *transaction)
    .await?;
    if let Some(group_ids) = request.group_ids.as_deref() {
        replace_channel_groups(&mut transaction, id, group_ids).await?;
    }
    if let Some(pricing) = request.model_pricing.as_deref() {
        replace_model_pricing(&mut transaction, id, pricing).await?;
    }
    if let Some(rules) = request.account_stats_pricing_rules.as_deref() {
        replace_account_rules(&mut transaction, id, rules).await?;
    }
    transaction.commit().await?;
    Ok(success(fetch_channel(state.service.pool(), id).await?))
}

async fn delete_one(
    State(state): State<AdminApiState>,
    Path(id): Path<i64>,
) -> Result<Response, AdminError> {
    require_id(id)?;
    let deleted = sqlx::query_scalar::<_, i64>("DELETE FROM channels WHERE id = $1 RETURNING id")
        .bind(id)
        .fetch_optional(state.service.pool())
        .await?;
    if deleted.is_none() {
        return Err(AdminError::NotFound("channel"));
    }
    Ok(success(json!({"message": "Channel deleted successfully"})))
}

#[derive(Debug, Deserialize)]
struct ModelQuery {
    model: Option<String>,
}

async fn model_default_pricing(Query(query): Query<ModelQuery>) -> Result<Response, AdminError> {
    let model = query.model.as_deref().map(str::trim).unwrap_or_default();
    if model.is_empty() {
        return Err(AdminError::BadRequest(
            "model parameter is required".to_owned(),
        ));
    }
    let source = active_pricing_source()
        .map_err(|error| AdminError::Probe(format!("load pricing catalog: {error}")))?;
    let catalog: BTreeMap<String, Value> = serde_json::from_str(&source)
        .map_err(|error| AdminError::Probe(format!("load pricing catalog: {error}")))?;
    let Some(entry) = find_catalog_entry(&catalog, model) else {
        return Ok(success(json!({"found": false})));
    };
    Ok(success(json!({
        "found": true,
        "input_price": entry.get("input_cost_per_token").and_then(Value::as_f64),
        "output_price": entry.get("output_cost_per_token").and_then(Value::as_f64),
        "cache_write_price": entry.get("cache_creation_input_token_cost").and_then(Value::as_f64),
        "cache_read_price": entry.get("cache_read_input_token_cost").and_then(Value::as_f64),
        "image_output_price": entry.get("output_cost_per_image_token")
            .or_else(|| entry.get("output_cost_per_image"))
            .and_then(Value::as_f64)
    })))
}

#[derive(Debug, Deserialize)]
struct PlatformQuery {
    platform: Option<String>,
}

async fn sync_pricing_models(Query(query): Query<PlatformQuery>) -> Result<Response, AdminError> {
    let platform = query
        .platform
        .as_deref()
        .map(str::trim)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let provider = match platform.as_str() {
        "anthropic" | "antigravity" => "anthropic",
        "openai" => "openai",
        "gemini" => "google",
        "grok" => "xai",
        "" => {
            return Err(AdminError::BadRequest(
                "platform parameter is required".to_owned(),
            ));
        }
        _ => {
            return Err(AdminError::BadRequest(format!(
                "unsupported platform: {platform}"
            )));
        }
    };
    let source = active_pricing_source()
        .map_err(|error| AdminError::Probe(format!("load pricing catalog: {error}")))?;
    let catalog: BTreeMap<String, Value> = serde_json::from_str(&source)
        .map_err(|error| AdminError::Probe(format!("load pricing catalog: {error}")))?;
    let mut models = catalog
        .into_iter()
        .filter_map(|(name, value)| {
            value
                .get("litellm_provider")
                .and_then(Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case(provider))
                .then_some(name)
        })
        .collect::<Vec<_>>();
    models.sort_unstable();
    Ok(success(json!({"models": models})))
}

async fn fetch_channel(pool: &PgPool, id: i64) -> Result<ChannelView, AdminError> {
    let row = sqlx::query(
        r"SELECT id, name, COALESCE(description, '') AS description, status,
                  COALESCE(billing_model_source, 'channel_mapped') AS billing_model_source,
                  COALESCE(restrict_models, FALSE) AS restrict_models,
                  COALESCE(features, '') AS features,
                  COALESCE(features_config, '{}'::jsonb)::text AS features_config_json,
                  COALESCE(model_mapping, '{}'::jsonb)::text AS model_mapping_json,
                  COALESCE(apply_pricing_to_account_stats, FALSE) AS apply_pricing_to_account_stats,
                  ARRAY(SELECT cg.group_id FROM channel_groups cg
                        WHERE cg.channel_id = channels.id ORDER BY cg.group_id) AS group_ids,
                  created_at::text AS created_at, updated_at::text AS updated_at
           FROM channels WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(AdminError::NotFound("channel"))?;
    let features_config_json: String = row.try_get("features_config_json")?;
    let model_mapping_json: String = row.try_get("model_mapping_json")?;
    Ok(ChannelView {
        id,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        status: row.try_get("status")?,
        billing_model_source: row.try_get("billing_model_source")?,
        restrict_models: row.try_get("restrict_models")?,
        features: row.try_get("features")?,
        features_config: json_text(&features_config_json),
        group_ids: row.try_get("group_ids")?,
        model_pricing: load_model_pricing(pool, "channel", id).await?,
        model_mapping: json_text(&model_mapping_json),
        apply_pricing_to_account_stats: row.try_get("apply_pricing_to_account_stats")?,
        account_stats_pricing_rules: load_account_rules(pool, id).await?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

async fn load_model_pricing(
    pool: &PgPool,
    owner_kind: &str,
    owner_id: i64,
) -> Result<Vec<ModelPricing>, AdminError> {
    let (table, owner_column, interval_table) = if owner_kind == "channel" {
        (
            "channel_model_pricing",
            "channel_id",
            "channel_pricing_intervals",
        )
    } else {
        (
            "channel_account_stats_model_pricing",
            "rule_id",
            "channel_account_stats_pricing_intervals",
        )
    };
    let sql = format!(
        r"SELECT id, platform, models::text AS models_json, billing_mode,
                  input_price::double precision AS input_price,
                  output_price::double precision AS output_price,
                  cache_write_price::double precision AS cache_write_price,
                  cache_read_price::double precision AS cache_read_price,
                  image_output_price::double precision AS image_output_price,
                  per_request_price::double precision AS per_request_price
           FROM {table} WHERE {owner_column} = $1 ORDER BY id"
    );
    let rows = sqlx::query(&sql).bind(owner_id).fetch_all(pool).await?;
    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        result.push(model_pricing_from_row(pool, interval_table, &row).await?);
    }
    Ok(result)
}

async fn model_pricing_from_row(
    pool: &PgPool,
    interval_table: &str,
    row: &PgRow,
) -> Result<ModelPricing, AdminError> {
    let id: i64 = row.try_get("id")?;
    let models_json: String = row.try_get("models_json")?;
    let sql = format!(
        r"SELECT id, min_tokens, max_tokens, COALESCE(tier_label, '') AS tier_label,
                  input_price::double precision AS input_price,
                  output_price::double precision AS output_price,
                  cache_write_price::double precision AS cache_write_price,
                  cache_read_price::double precision AS cache_read_price,
                  per_request_price::double precision AS per_request_price, sort_order
           FROM {interval_table} WHERE pricing_id = $1 ORDER BY sort_order, id"
    );
    let interval_rows = sqlx::query(&sql).bind(id).fetch_all(pool).await?;
    let intervals = interval_rows
        .iter()
        .map(interval_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ModelPricing {
        id: Some(id),
        platform: row.try_get("platform")?,
        models: serde_json::from_str(&models_json).unwrap_or_default(),
        billing_mode: row.try_get("billing_mode")?,
        input_price: row.try_get("input_price")?,
        output_price: row.try_get("output_price")?,
        cache_write_price: row.try_get("cache_write_price")?,
        cache_read_price: row.try_get("cache_read_price")?,
        image_output_price: row.try_get("image_output_price")?,
        per_request_price: row.try_get("per_request_price")?,
        intervals,
    })
}

fn interval_from_row(row: &PgRow) -> Result<PricingInterval, AdminError> {
    Ok(PricingInterval {
        id: Some(row.try_get("id")?),
        min_tokens: row.try_get("min_tokens")?,
        max_tokens: row.try_get("max_tokens")?,
        tier_label: row.try_get("tier_label")?,
        input_price: row.try_get("input_price")?,
        output_price: row.try_get("output_price")?,
        cache_write_price: row.try_get("cache_write_price")?,
        cache_read_price: row.try_get("cache_read_price")?,
        per_request_price: row.try_get("per_request_price")?,
        sort_order: row.try_get("sort_order")?,
    })
}

async fn load_account_rules(
    pool: &PgPool,
    channel_id: i64,
) -> Result<Vec<AccountStatsPricingRule>, AdminError> {
    let rows = sqlx::query(
        r"SELECT id, name, group_ids, account_ids
           FROM channel_account_stats_pricing_rules
           WHERE channel_id = $1 ORDER BY sort_order, id",
    )
    .bind(channel_id)
    .fetch_all(pool)
    .await?;
    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        let id: i64 = row.try_get("id")?;
        result.push(AccountStatsPricingRule {
            id: Some(id),
            name: row.try_get("name")?,
            group_ids: row.try_get("group_ids")?,
            account_ids: row.try_get("account_ids")?,
            pricing: load_model_pricing(pool, "rule", id).await?,
        });
    }
    Ok(result)
}

async fn validate_channel_groups(
    transaction: &mut Transaction<'_, Postgres>,
    channel_id: i64,
    group_ids: &[i64],
) -> Result<(), AdminError> {
    if group_ids.is_empty() {
        return Ok(());
    }
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM groups WHERE id = ANY($1) AND deleted_at IS NULL",
    )
    .bind(group_ids)
    .fetch_one(&mut **transaction)
    .await?;
    if usize::try_from(count).ok() != Some(group_ids.len()) {
        return Err(AdminError::BadRequest(
            "one or more groups do not exist".to_owned(),
        ));
    }
    let conflicts = sqlx::query_scalar::<_, i64>(
        r"SELECT group_id FROM channel_groups
          WHERE group_id = ANY($1) AND channel_id <> $2 LIMIT 1",
    )
    .bind(group_ids)
    .bind(channel_id)
    .fetch_optional(&mut **transaction)
    .await?;
    if conflicts.is_some() {
        return Err(AdminError::Conflict(
            "one or more groups already belong to another channel".to_owned(),
        ));
    }
    Ok(())
}

async fn replace_channel_groups(
    transaction: &mut Transaction<'_, Postgres>,
    channel_id: i64,
    group_ids: &[i64],
) -> Result<(), AdminError> {
    sqlx::query("DELETE FROM channel_groups WHERE channel_id = $1")
        .bind(channel_id)
        .execute(&mut **transaction)
        .await?;
    if !group_ids.is_empty() {
        sqlx::query(
            r"INSERT INTO channel_groups (channel_id, group_id)
              SELECT $1, unnest($2::bigint[])",
        )
        .bind(channel_id)
        .bind(group_ids)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

async fn replace_model_pricing(
    transaction: &mut Transaction<'_, Postgres>,
    channel_id: i64,
    pricing: &[ModelPricing],
) -> Result<(), AdminError> {
    sqlx::query("DELETE FROM channel_model_pricing WHERE channel_id = $1")
        .bind(channel_id)
        .execute(&mut **transaction)
        .await?;
    for item in pricing {
        insert_model_pricing(transaction, "channel", channel_id, item).await?;
    }
    Ok(())
}

async fn replace_account_rules(
    transaction: &mut Transaction<'_, Postgres>,
    channel_id: i64,
    rules: &[AccountStatsPricingRule],
) -> Result<(), AdminError> {
    sqlx::query("DELETE FROM channel_account_stats_pricing_rules WHERE channel_id = $1")
        .bind(channel_id)
        .execute(&mut **transaction)
        .await?;
    for (index, rule) in rules.iter().enumerate() {
        let rule_id = sqlx::query_scalar::<_, i64>(
            r"INSERT INTO channel_account_stats_pricing_rules
              (channel_id, name, group_ids, account_ids, sort_order)
              VALUES ($1, $2, $3, $4, $5) RETURNING id",
        )
        .bind(channel_id)
        .bind(&rule.name)
        .bind(&rule.group_ids)
        .bind(&rule.account_ids)
        .bind(i32::try_from(index).unwrap_or(i32::MAX))
        .fetch_one(&mut **transaction)
        .await?;
        for pricing in &rule.pricing {
            insert_model_pricing(transaction, "rule", rule_id, pricing).await?;
        }
    }
    Ok(())
}

async fn insert_model_pricing(
    transaction: &mut Transaction<'_, Postgres>,
    owner_kind: &str,
    owner_id: i64,
    pricing: &ModelPricing,
) -> Result<(), AdminError> {
    let models = serde_json::to_string(&pricing.models)
        .map_err(|error| AdminError::BadRequest(error.to_string()))?;
    let (table, owner_column, interval_table) = if owner_kind == "channel" {
        (
            "channel_model_pricing",
            "channel_id",
            "channel_pricing_intervals",
        )
    } else {
        (
            "channel_account_stats_model_pricing",
            "rule_id",
            "channel_account_stats_pricing_intervals",
        )
    };
    let sql = format!(
        r"INSERT INTO {table}
          ({owner_column}, platform, models, billing_mode, input_price, output_price,
           cache_write_price, cache_read_price, image_output_price, per_request_price)
          VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7, $8, $9, $10) RETURNING id"
    );
    let pricing_id = sqlx::query_scalar::<_, i64>(&sql)
        .bind(owner_id)
        .bind(&pricing.platform)
        .bind(models)
        .bind(&pricing.billing_mode)
        .bind(pricing.input_price)
        .bind(pricing.output_price)
        .bind(pricing.cache_write_price)
        .bind(pricing.cache_read_price)
        .bind(pricing.image_output_price)
        .bind(pricing.per_request_price)
        .fetch_one(&mut **transaction)
        .await?;
    for interval in &pricing.intervals {
        let sql = format!(
            r"INSERT INTO {interval_table}
              (pricing_id, min_tokens, max_tokens, tier_label, input_price, output_price,
               cache_write_price, cache_read_price, per_request_price, sort_order)
              VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"
        );
        sqlx::query(&sql)
            .bind(pricing_id)
            .bind(interval.min_tokens)
            .bind(interval.max_tokens)
            .bind(&interval.tier_label)
            .bind(interval.input_price)
            .bind(interval.output_price)
            .bind(interval.cache_write_price)
            .bind(interval.cache_read_price)
            .bind(interval.per_request_price)
            .bind(interval.sort_order)
            .execute(&mut **transaction)
            .await?;
    }
    Ok(())
}

fn normalize_rules(rules: &mut [AccountStatsPricingRule]) -> Result<(), AdminError> {
    for (index, rule) in rules.iter_mut().enumerate() {
        rule.name = trim_to(&rule.name, 100);
        rule.group_ids = normalize_ids(&rule.group_ids, "group")?;
        rule.account_ids = normalize_ids(&rule.account_ids, "account")?;
        if rule.group_ids.is_empty() && rule.account_ids.is_empty() {
            return Err(AdminError::BadRequest(format!(
                "pricing rule #{} must have at least one group or account",
                index + 1
            )));
        }
        if rule.pricing.is_empty() {
            return Err(AdminError::BadRequest(format!(
                "pricing rule #{} must have at least one pricing entry",
                index + 1
            )));
        }
        normalize_pricing(&mut rule.pricing, false)?;
    }
    Ok(())
}

fn normalize_pricing(
    pricing: &mut [ModelPricing],
    default_platform: bool,
) -> Result<(), AdminError> {
    for item in pricing.iter_mut() {
        item.id = None;
        item.platform = item.platform.trim().to_ascii_lowercase();
        if item.platform.is_empty() && default_platform {
            "anthropic".clone_into(&mut item.platform);
        }
        if item.platform.len() > 50 {
            return Err(AdminError::BadRequest(
                "pricing platform must not exceed 50 characters".to_owned(),
            ));
        }
        item.models = normalize_models(&item.models)?;
        item.billing_mode = if item.billing_mode.trim().is_empty() {
            "token".to_owned()
        } else {
            item.billing_mode.trim().to_owned()
        };
        if !matches!(
            item.billing_mode.as_str(),
            "token" | "per_request" | "image"
        ) {
            return Err(AdminError::BadRequest(
                "billing_mode must be token, per_request, or image".to_owned(),
            ));
        }
        validate_prices([
            item.input_price,
            item.output_price,
            item.cache_write_price,
            item.cache_read_price,
            item.image_output_price,
            item.per_request_price,
        ])?;
        normalize_intervals(&mut item.intervals, &item.billing_mode)?;
        if matches!(item.billing_mode.as_str(), "per_request" | "image")
            && item.per_request_price.is_none()
            && item.intervals.is_empty()
        {
            return Err(AdminError::BadRequest(
                "per-request price or intervals are required for per_request/image billing"
                    .to_owned(),
            ));
        }
    }
    validate_pattern_conflicts(pricing)
}

fn normalize_intervals(
    intervals: &mut [PricingInterval],
    billing_mode: &str,
) -> Result<(), AdminError> {
    for interval in intervals.iter_mut() {
        interval.id = None;
        interval.tier_label = trim_to(&interval.tier_label, 50);
        if interval.min_tokens < 0
            || interval
                .max_tokens
                .is_some_and(|max| max <= 0 || max <= interval.min_tokens)
        {
            return Err(AdminError::BadRequest(
                "pricing interval bounds are invalid".to_owned(),
            ));
        }
        validate_prices([
            interval.input_price,
            interval.output_price,
            interval.cache_write_price,
            interval.cache_read_price,
            interval.per_request_price,
        ])?;
        if interval.input_price.is_none()
            && interval.output_price.is_none()
            && interval.cache_write_price.is_none()
            && interval.cache_read_price.is_none()
            && interval.per_request_price.is_none()
        {
            return Err(AdminError::BadRequest(
                "every pricing interval must define at least one price".to_owned(),
            ));
        }
    }
    if billing_mode == "token" {
        let mut sorted = intervals.iter().collect::<Vec<_>>();
        sorted.sort_by_key(|interval| interval.min_tokens);
        for (index, interval) in sorted.iter().enumerate() {
            if interval.max_tokens.is_none() && index + 1 < sorted.len() {
                return Err(AdminError::BadRequest(
                    "an unbounded pricing interval must be last".to_owned(),
                ));
            }
            if index > 0 {
                let previous = sorted[index - 1];
                if previous
                    .max_tokens
                    .is_none_or(|max| max > interval.min_tokens)
                {
                    return Err(AdminError::BadRequest(
                        "pricing intervals must not overlap".to_owned(),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_prices<const N: usize>(prices: [Option<f64>; N]) -> Result<(), AdminError> {
    if prices
        .into_iter()
        .flatten()
        .any(|price| !price.is_finite() || price < 0.0)
    {
        Err(AdminError::BadRequest(
            "pricing values must be finite and non-negative".to_owned(),
        ))
    } else {
        Ok(())
    }
}

fn normalize_models(models: &[String]) -> Result<Vec<String>, AdminError> {
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for model in models {
        let model = model.trim();
        if model.is_empty() {
            continue;
        }
        let key = model.to_ascii_lowercase();
        if !seen.insert(key) {
            return Err(AdminError::BadRequest(format!(
                "duplicate model pattern {model:?} in a pricing entry"
            )));
        }
        result.push(model.to_owned());
    }
    if result.is_empty() || result.len() > 100 {
        return Err(AdminError::BadRequest(
            "each pricing entry must contain between 1 and 100 models".to_owned(),
        ));
    }
    Ok(result)
}

fn validate_pattern_conflicts(pricing: &[ModelPricing]) -> Result<(), AdminError> {
    let mut by_platform: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for item in pricing {
        for model in &item.models {
            by_platform
                .entry(item.platform.as_str())
                .or_default()
                .push(model.as_str());
        }
    }
    for (platform, patterns) in by_platform {
        for (index, left) in patterns.iter().enumerate() {
            for right in patterns.iter().skip(index + 1) {
                if patterns_conflict(left, right) {
                    return Err(AdminError::BadRequest(format!(
                        "model patterns '{left}' and '{right}' conflict in platform '{platform}'"
                    )));
                }
            }
        }
    }
    Ok(())
}

fn normalize_mapping(
    mapping: &mut BTreeMap<String, BTreeMap<String, String>>,
) -> Result<(), AdminError> {
    let original = std::mem::take(mapping);
    for (platform, entries) in original {
        let platform = platform.trim().to_ascii_lowercase();
        if platform.is_empty() || platform.len() > 50 {
            return Err(AdminError::BadRequest(
                "model mapping platform is invalid".to_owned(),
            ));
        }
        let mut normalized = BTreeMap::new();
        for (source, target) in entries {
            let source = source.trim().to_owned();
            let target = target.trim().to_owned();
            if source.is_empty() || target.is_empty() {
                return Err(AdminError::BadRequest(
                    "model mapping source and target are required".to_owned(),
                ));
            }
            if normalized.insert(source, target).is_some() {
                return Err(AdminError::BadRequest(
                    "duplicate model mapping source".to_owned(),
                ));
            }
        }
        let sources = normalized.keys().map(String::as_str).collect::<Vec<_>>();
        for (index, left) in sources.iter().enumerate() {
            if sources
                .iter()
                .skip(index + 1)
                .any(|right| patterns_conflict(left, right))
            {
                return Err(AdminError::BadRequest(format!(
                    "model mapping patterns conflict in platform '{platform}'"
                )));
            }
        }
        mapping.insert(platform, normalized);
    }
    Ok(())
}

fn patterns_conflict(left: &str, right: &str) -> bool {
    let left = left.to_ascii_lowercase();
    let right = right.to_ascii_lowercase();
    let (left_prefix, left_wildcard) = left
        .strip_suffix('*')
        .map_or((left.as_str(), false), |prefix| (prefix, true));
    let (right_prefix, right_wildcard) = right
        .strip_suffix('*')
        .map_or((right.as_str(), false), |prefix| (prefix, true));
    match (left_wildcard, right_wildcard) {
        (false, false) => left_prefix == right_prefix,
        (true, false) => right_prefix.starts_with(left_prefix),
        (false, true) => left_prefix.starts_with(right_prefix),
        (true, true) => {
            left_prefix.starts_with(right_prefix) || right_prefix.starts_with(left_prefix)
        }
    }
}

fn normalize_ids(ids: &[i64], label: &str) -> Result<Vec<i64>, AdminError> {
    if ids.iter().any(|id| *id <= 0) {
        return Err(AdminError::BadRequest(format!(
            "{label} IDs must be positive"
        )));
    }
    Ok(ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

fn valid_name(value: &str) -> Result<String, AdminError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 100 {
        Err(AdminError::BadRequest(
            "channel name is required and must not exceed 100 bytes".to_owned(),
        ))
    } else {
        Ok(value.to_owned())
    }
}

fn valid_channel_status(value: &str) -> Result<String, AdminError> {
    let value = value.trim();
    if matches!(value, "active" | "disabled") {
        Ok(value.to_owned())
    } else {
        Err(AdminError::BadRequest(
            "channel status must be active or disabled".to_owned(),
        ))
    }
}

fn normalize_billing_source(value: &str) -> Result<String, AdminError> {
    let value = value.trim();
    let value = if value.is_empty() {
        "channel_mapped"
    } else {
        value
    };
    if matches!(value, "requested" | "upstream" | "channel_mapped") {
        Ok(value.to_owned())
    } else {
        Err(AdminError::BadRequest(
            "billing_model_source must be requested, upstream, or channel_mapped".to_owned(),
        ))
    }
}

fn object_or_empty(value: Value, label: &str) -> Result<Value, AdminError> {
    if value.is_null() {
        Ok(json!({}))
    } else if value.is_object() {
        Ok(value)
    } else {
        Err(AdminError::BadRequest(format!(
            "{label} must be a JSON object"
        )))
    }
}

fn require_id(id: i64) -> Result<(), AdminError> {
    if id > 0 {
        Ok(())
    } else {
        Err(AdminError::BadRequest("invalid channel ID".to_owned()))
    }
}

fn channel_sort(value: &str) -> &'static str {
    match value {
        "name" => "name",
        "status" => "status",
        "updated_at" => "updated_at",
        _ => "created_at",
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

fn find_catalog_entry<'a>(catalog: &'a BTreeMap<String, Value>, model: &str) -> Option<&'a Value> {
    let lowered = model.trim().to_ascii_lowercase();
    let stripped = lowered.strip_prefix("models/").unwrap_or(&lowered);
    for candidate in [lowered.as_str(), stripped] {
        if let Some((_, value)) = catalog
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(candidate))
        {
            return Some(value);
        }
    }
    let normalized = stripped.replace("-4-5-", "-4.5-");
    catalog
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(&normalized))
        .map(|(_, value)| value)
}

#[cfg(test)]
mod tests {
    use super::{ModelPricing, PricingInterval, normalize_pricing, patterns_conflict};

    #[test]
    fn wildcard_conflicts_match_go_channel_rules() {
        assert!(patterns_conflict("claude-*", "claude-opus-4"));
        assert!(patterns_conflict("GPT-4", "gpt-4"));
        assert!(!patterns_conflict("claude-*", "gpt-*"));
    }

    #[test]
    fn overlapping_token_intervals_are_rejected() {
        let mut pricing = vec![ModelPricing {
            id: None,
            platform: "anthropic".to_owned(),
            models: vec!["claude-test".to_owned()],
            billing_mode: "token".to_owned(),
            input_price: None,
            output_price: None,
            cache_write_price: None,
            cache_read_price: None,
            image_output_price: None,
            per_request_price: None,
            intervals: vec![
                PricingInterval {
                    id: None,
                    min_tokens: 0,
                    max_tokens: Some(100),
                    tier_label: String::new(),
                    input_price: None,
                    output_price: None,
                    cache_write_price: None,
                    cache_read_price: None,
                    per_request_price: None,
                    sort_order: 0,
                },
                PricingInterval {
                    id: None,
                    min_tokens: 50,
                    max_tokens: None,
                    tier_label: String::new(),
                    input_price: None,
                    output_price: None,
                    cache_write_price: None,
                    cache_read_price: None,
                    per_request_price: None,
                    sort_order: 1,
                },
            ],
        }];
        assert!(normalize_pricing(&mut pricing, true).is_err());
    }
}
