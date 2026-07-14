//! `PostgreSQL` implementations for the ten administrator payment routes that
//! need payment-domain validation instead of generic table CRUD.

use std::collections::{BTreeMap, HashMap, HashSet};

use regex::Regex;
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, Row, Transaction};

use super::{AdminError, AdminIdentity, compat::required_path_id};

const INVALIDATION_CHANNEL: &str = "sub2api_auth_cache_invalidation";
const MAX_PAGE_SIZE: i64 = 1_000;
const PENDING_ORDER_STATUSES: [&str; 3] = ["PENDING", "PAID", "RECHARGING"];
const VALID_PROVIDER_KEYS: [&str; 5] = ["easypay", "alipay", "wxpay", "stripe", "airwallex"];

const PAYMENT_HANDLERS: [&str; 10] = [
    "adminPaymentHandler.ListOrders",
    "adminPaymentHandler.GetOrderDetail",
    "adminPaymentHandler.ListPlans",
    "adminPaymentHandler.CreatePlan",
    "adminPaymentHandler.UpdatePlan",
    "adminPaymentHandler.DeletePlan",
    "adminPaymentHandler.ListProviders",
    "adminPaymentHandler.CreateProvider",
    "adminPaymentHandler.UpdateProvider",
    "adminPaymentHandler.DeleteProvider",
];

pub(super) async fn dispatch(
    pool: &PgPool,
    actor: &AdminIdentity,
    handler: &str,
    path: &str,
    query: &BTreeMap<String, String>,
    payload: Value,
) -> Option<Result<Value, AdminError>> {
    if !PAYMENT_HANDLERS.contains(&handler) {
        return None;
    }
    let result = match handler {
        "adminPaymentHandler.ListOrders" => list_orders(pool, query).await,
        "adminPaymentHandler.GetOrderDetail" => {
            get_order_detail(pool, required_path_id(path, "payment order").ok()?).await
        }
        "adminPaymentHandler.ListPlans" => list_plans(pool).await,
        "adminPaymentHandler.CreatePlan" => create_plan(pool, actor, payload).await,
        "adminPaymentHandler.UpdatePlan" => {
            update_plan(
                pool,
                actor,
                required_path_id(path, "subscription plan").ok()?,
                payload,
            )
            .await
        }
        "adminPaymentHandler.DeletePlan" => {
            delete_plan(
                pool,
                actor,
                required_path_id(path, "subscription plan").ok()?,
            )
            .await
        }
        "adminPaymentHandler.ListProviders" => list_providers(pool).await,
        "adminPaymentHandler.CreateProvider" => create_provider(pool, actor, payload).await,
        "adminPaymentHandler.UpdateProvider" => {
            update_provider(
                pool,
                actor,
                required_path_id(path, "payment provider").ok()?,
                payload,
            )
            .await
        }
        "adminPaymentHandler.DeleteProvider" => {
            delete_provider(
                pool,
                actor,
                required_path_id(path, "payment provider").ok()?,
            )
            .await
        }
        _ => unreachable!("PAYMENT_HANDLERS and payment dispatch match must stay aligned"),
    };
    Some(result)
}

async fn list_orders(pool: &PgPool, query: &BTreeMap<String, String>) -> Result<Value, AdminError> {
    let page = query_positive_i64(query, "page").unwrap_or(1);
    let page_size = query_positive_i64(query, "page_size")
        .unwrap_or(20)
        .clamp(1, MAX_PAGE_SIZE);
    let user_id = query_positive_i64(query, "user_id");
    let status = trimmed_query(query, "status", 40);
    let order_type = trimmed_query(query, "order_type", 40);
    let payment_type = trimmed_query(query, "payment_type", 40);
    let keyword = trimmed_query(query, "keyword", 100);
    let rows = sqlx::query(
        r"
SELECT (to_jsonb(row) - 'provider_snapshot')
       || jsonb_build_object(
            'currency', COALESCE(NULLIF(row.provider_snapshot->>'currency', ''), 'CNY')
          ) AS data
FROM payment_orders row
WHERE ($1::bigint IS NULL OR row.user_id = $1)
  AND ($2::text IS NULL OR row.status = $2)
  AND ($3::text IS NULL OR row.order_type = $3)
  AND ($4::text IS NULL OR row.payment_type = $4)
  AND (
       $5::text IS NULL
       OR row.out_trade_no ILIKE '%' || $5 || '%'
       OR row.user_email ILIKE '%' || $5 || '%'
       OR row.user_name ILIKE '%' || $5 || '%'
  )
ORDER BY row.created_at DESC, row.id DESC
LIMIT $6 OFFSET $7
",
    )
    .bind(user_id)
    .bind(status.as_deref())
    .bind(order_type.as_deref())
    .bind(payment_type.as_deref())
    .bind(keyword.as_deref())
    .bind(page_size)
    .bind((page - 1) * page_size)
    .fetch_all(pool)
    .await?;
    let items = rows
        .into_iter()
        .map(|row| row.try_get::<Value, _>("data"))
        .collect::<Result<Vec<_>, _>>()?;
    let total = sqlx::query_scalar::<_, i64>(
        r"
SELECT COUNT(*)::bigint
FROM payment_orders row
WHERE ($1::bigint IS NULL OR row.user_id = $1)
  AND ($2::text IS NULL OR row.status = $2)
  AND ($3::text IS NULL OR row.order_type = $3)
  AND ($4::text IS NULL OR row.payment_type = $4)
  AND (
       $5::text IS NULL
       OR row.out_trade_no ILIKE '%' || $5 || '%'
       OR row.user_email ILIKE '%' || $5 || '%'
       OR row.user_name ILIKE '%' || $5 || '%'
  )
",
    )
    .bind(user_id)
    .bind(status.as_deref())
    .bind(order_type.as_deref())
    .bind(payment_type.as_deref())
    .bind(keyword.as_deref())
    .fetch_one(pool)
    .await?;
    Ok(paginated(&items, total, page, page_size))
}

async fn get_order_detail(pool: &PgPool, id: i64) -> Result<Value, AdminError> {
    let order = sqlx::query_scalar::<_, Value>(
        r"
SELECT (to_jsonb(row) - 'provider_snapshot')
       || jsonb_build_object(
            'currency', COALESCE(NULLIF(row.provider_snapshot->>'currency', ''), 'CNY')
          )
FROM payment_orders row
WHERE row.id = $1
",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(AdminError::NotFound("payment order"))?;
    let audit_logs = sqlx::query_scalar::<_, Value>(
        "SELECT to_jsonb(log) FROM payment_audit_logs log WHERE log.order_id = $1 ORDER BY log.created_at, log.id",
    )
    .bind(id.to_string())
    .fetch_all(pool)
    .await?;
    Ok(json!({ "order": order, "auditLogs": audit_logs }))
}

#[derive(Debug, Deserialize)]
struct CreatePlanRequest {
    #[serde(default)]
    group_id: i64,
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    price: f64,
    #[serde(default)]
    original_price: Option<f64>,
    #[serde(default)]
    validity_days: i32,
    #[serde(default)]
    validity_unit: String,
    #[serde(default)]
    features: String,
    #[serde(default)]
    product_name: String,
    #[serde(default)]
    for_sale: bool,
    #[serde(default)]
    sort_order: i32,
}

#[derive(Debug, Default, Deserialize)]
struct UpdatePlanRequest {
    group_id: Option<i64>,
    name: Option<String>,
    description: Option<String>,
    price: Option<f64>,
    original_price: Option<f64>,
    validity_days: Option<i32>,
    validity_unit: Option<String>,
    features: Option<String>,
    product_name: Option<String>,
    for_sale: Option<bool>,
    sort_order: Option<i32>,
}

#[derive(Debug)]
struct PlanState {
    group_id: i64,
    name: String,
    description: String,
    price: f64,
    original_price: Option<f64>,
    validity_days: i32,
    validity_unit: String,
    features: String,
    product_name: String,
    for_sale: bool,
    sort_order: i32,
}

async fn list_plans(pool: &PgPool) -> Result<Value, AdminError> {
    let plans = sqlx::query_scalar::<_, Value>(
        "SELECT to_jsonb(plan) FROM subscription_plans plan ORDER BY plan.sort_order, plan.id",
    )
    .fetch_all(pool)
    .await?;
    Ok(Value::Array(plans))
}

async fn create_plan(
    pool: &PgPool,
    actor: &AdminIdentity,
    payload: Value,
) -> Result<Value, AdminError> {
    let request: CreatePlanRequest = parse_payload(payload)?;
    let state = PlanState {
        group_id: request.group_id,
        name: request.name.trim().to_owned(),
        description: request.description,
        price: request.price,
        original_price: request.original_price,
        validity_days: request.validity_days,
        validity_unit: request.validity_unit.trim().to_owned(),
        features: request.features,
        product_name: request.product_name,
        for_sale: request.for_sale,
        sort_order: request.sort_order,
    };
    validate_plan(&state)?;
    let mut transaction = pool.begin().await?;
    ensure_live_group(&mut transaction, state.group_id).await?;
    let plan = sqlx::query_scalar::<_, Value>(
        r"
INSERT INTO subscription_plans (
    group_id, name, description, price, original_price, validity_days,
    validity_unit, features, product_name, for_sale, sort_order, created_at, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW(),NOW())
RETURNING to_jsonb(subscription_plans)
",
    )
    .bind(state.group_id)
    .bind(&state.name)
    .bind(&state.description)
    .bind(state.price)
    .bind(state.original_price)
    .bind(state.validity_days)
    .bind(&state.validity_unit)
    .bind(&state.features)
    .bind(&state.product_name)
    .bind(state.for_sale)
    .bind(state.sort_order)
    .fetch_one(&mut *transaction)
    .await?;
    notify_settings(&mut transaction).await?;
    transaction.commit().await?;
    audit_mutation(actor, "create", "subscription_plan", &plan);
    Ok(plan)
}

async fn update_plan(
    pool: &PgPool,
    actor: &AdminIdentity,
    id: i64,
    payload: Value,
) -> Result<Value, AdminError> {
    let request: UpdatePlanRequest = parse_payload(payload)?;
    let mut transaction = pool.begin().await?;
    let row = sqlx::query(
        r"
SELECT group_id, name, description, price::float8 AS price,
       original_price::float8 AS original_price, validity_days, validity_unit,
       features, product_name, for_sale, sort_order
FROM subscription_plans WHERE id = $1 FOR UPDATE
",
    )
    .bind(id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(AdminError::NotFound("subscription plan"))?;
    let mut state = PlanState {
        group_id: row.try_get("group_id")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        price: row.try_get("price")?,
        original_price: row.try_get("original_price")?,
        validity_days: row.try_get("validity_days")?,
        validity_unit: row.try_get("validity_unit")?,
        features: row.try_get("features")?,
        product_name: row.try_get("product_name")?,
        for_sale: row.try_get("for_sale")?,
        sort_order: row.try_get("sort_order")?,
    };
    if let Some(value) = request.group_id {
        state.group_id = value;
    }
    if let Some(value) = request.name {
        value.trim().clone_into(&mut state.name);
    }
    if let Some(value) = request.description {
        state.description = value;
    }
    if let Some(value) = request.price {
        state.price = value;
    }
    if let Some(value) = request.original_price {
        state.original_price = Some(value);
    }
    if let Some(value) = request.validity_days {
        state.validity_days = value;
    }
    if let Some(value) = request.validity_unit {
        value.trim().clone_into(&mut state.validity_unit);
    }
    if let Some(value) = request.features {
        state.features = value;
    }
    if let Some(value) = request.product_name {
        state.product_name = value;
    }
    if let Some(value) = request.for_sale {
        state.for_sale = value;
    }
    if let Some(value) = request.sort_order {
        state.sort_order = value;
    }
    validate_plan(&state)?;
    ensure_live_group(&mut transaction, state.group_id).await?;
    let plan = sqlx::query_scalar::<_, Value>(
        r"
UPDATE subscription_plans SET
    group_id=$2, name=$3, description=$4, price=$5, original_price=$6,
    validity_days=$7, validity_unit=$8, features=$9, product_name=$10,
    for_sale=$11, sort_order=$12, updated_at=NOW()
WHERE id=$1
RETURNING to_jsonb(subscription_plans)
",
    )
    .bind(id)
    .bind(state.group_id)
    .bind(&state.name)
    .bind(&state.description)
    .bind(state.price)
    .bind(state.original_price)
    .bind(state.validity_days)
    .bind(&state.validity_unit)
    .bind(&state.features)
    .bind(&state.product_name)
    .bind(state.for_sale)
    .bind(state.sort_order)
    .fetch_one(&mut *transaction)
    .await?;
    notify_settings(&mut transaction).await?;
    transaction.commit().await?;
    audit_mutation(actor, "update", "subscription_plan", &plan);
    Ok(plan)
}

async fn delete_plan(pool: &PgPool, actor: &AdminIdentity, id: i64) -> Result<Value, AdminError> {
    let mut transaction = pool.begin().await?;
    if sqlx::query_scalar::<_, i64>("SELECT id FROM subscription_plans WHERE id = $1 FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut *transaction)
        .await?
        .is_none()
    {
        return Err(AdminError::NotFound("subscription plan"));
    }
    let pending = pending_orders_for_plan(&mut transaction, id).await?;
    if pending > 0 {
        return Err(AdminError::Conflict(format!(
            "this plan has {pending} in-progress orders and cannot be deleted"
        )));
    }
    sqlx::query("DELETE FROM subscription_plans WHERE id = $1")
        .bind(id)
        .execute(&mut *transaction)
        .await?;
    notify_settings(&mut transaction).await?;
    transaction.commit().await?;
    tracing::info!(
        actor_id = actor.user_id,
        plan_id = id,
        "subscription plan deleted"
    );
    Ok(json!({ "message": "deleted" }))
}

fn validate_plan(plan: &PlanState) -> Result<(), AdminError> {
    if plan.name.is_empty() {
        return Err(AdminError::BadRequest("plan name is required".to_owned()));
    }
    if plan.name.chars().count() > 100 {
        return Err(AdminError::BadRequest(
            "plan name must not exceed 100 characters".to_owned(),
        ));
    }
    if plan.group_id <= 0 {
        return Err(AdminError::BadRequest("group is required".to_owned()));
    }
    if !plan.price.is_finite() || plan.price <= 0.0 {
        return Err(AdminError::BadRequest("price must be > 0".to_owned()));
    }
    if plan
        .original_price
        .is_some_and(|value| !value.is_finite() || value < 0.0)
    {
        return Err(AdminError::BadRequest(
            "original price must be >= 0".to_owned(),
        ));
    }
    if plan.validity_days <= 0 {
        return Err(AdminError::BadRequest(
            "validity days must be > 0".to_owned(),
        ));
    }
    if plan.validity_unit.is_empty() {
        return Err(AdminError::BadRequest(
            "validity unit is required".to_owned(),
        ));
    }
    if plan.validity_unit.chars().count() > 10 {
        return Err(AdminError::BadRequest(
            "validity unit must not exceed 10 characters".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct CreateProviderRequest {
    #[serde(default)]
    provider_key: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    config: HashMap<String, String>,
    #[serde(default)]
    supported_types: Vec<String>,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    payment_mode: String,
    #[serde(default)]
    sort_order: i32,
    #[serde(default)]
    limits: String,
    #[serde(default)]
    refund_enabled: bool,
    #[serde(default)]
    allow_user_refund: bool,
}

#[derive(Debug, Default, Deserialize)]
struct UpdateProviderRequest {
    name: Option<String>,
    config: Option<HashMap<String, String>>,
    supported_types: Option<Vec<String>>,
    enabled: Option<bool>,
    payment_mode: Option<String>,
    sort_order: Option<i32>,
    limits: Option<String>,
    refund_enabled: Option<bool>,
    allow_user_refund: Option<bool>,
}

#[derive(Clone, Debug)]
struct ProviderState {
    provider_key: String,
    name: String,
    config: HashMap<String, String>,
    supported_types: Vec<String>,
    enabled: bool,
    payment_mode: String,
    sort_order: i32,
    limits: String,
    refund_enabled: bool,
    allow_user_refund: bool,
}

async fn list_providers(pool: &PgPool) -> Result<Value, AdminError> {
    let rows = sqlx::query(
        "SELECT to_jsonb(provider) AS data, provider_key, config, supported_types FROM payment_provider_instances provider ORDER BY sort_order, id",
    )
    .fetch_all(pool)
    .await?;
    let providers = rows
        .into_iter()
        .map(|row| provider_view(&row))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Value::Array(providers))
}

async fn create_provider(
    pool: &PgPool,
    actor: &AdminIdentity,
    payload: Value,
) -> Result<Value, AdminError> {
    let request: CreateProviderRequest = parse_payload(payload)?;
    let mut state = ProviderState {
        provider_key: request.provider_key.trim().to_ascii_lowercase(),
        name: request.name.trim().to_owned(),
        config: request.config,
        supported_types: normalize_supported_types(request.supported_types)?,
        enabled: request.enabled,
        payment_mode: request.payment_mode.trim().to_ascii_lowercase(),
        sort_order: request.sort_order,
        limits: request.limits,
        refund_enabled: request.refund_enabled,
        allow_user_refund: request.allow_user_refund && request.refund_enabled,
    };
    normalize_provider(&mut state)?;
    validate_provider(&state)?;
    let mut transaction = pool.begin().await?;
    let config = serde_json::to_string(&state.config)
        .map_err(|error| AdminError::BadRequest(error.to_string()))?;
    let id = sqlx::query_scalar::<_, i64>(
        r"
INSERT INTO payment_provider_instances (
    provider_key, name, config, supported_types, enabled, payment_mode,
    sort_order, limits, refund_enabled, allow_user_refund, created_at, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW(),NOW())
RETURNING id
",
    )
    .bind(&state.provider_key)
    .bind(&state.name)
    .bind(config)
    .bind(state.supported_types.join(","))
    .bind(state.enabled)
    .bind(&state.payment_mode)
    .bind(state.sort_order)
    .bind(&state.limits)
    .bind(state.refund_enabled)
    .bind(state.allow_user_refund)
    .fetch_one(&mut *transaction)
    .await?;
    notify_settings(&mut transaction).await?;
    transaction.commit().await?;
    let provider = provider_by_id(pool, id).await?;
    audit_mutation(actor, "create", "payment_provider", &provider);
    Ok(provider)
}

async fn update_provider(
    pool: &PgPool,
    actor: &AdminIdentity,
    id: i64,
    payload: Value,
) -> Result<Value, AdminError> {
    let request: UpdateProviderRequest = parse_payload(payload)?;
    let mut transaction = pool.begin().await?;
    let mut state = load_provider_for_update(&mut transaction, id).await?;
    let previous = state.clone();
    if let Some(value) = request.name {
        value.trim().clone_into(&mut state.name);
    }
    if let Some(incoming) = request.config {
        merge_provider_config(&state.provider_key, &mut state.config, incoming);
    }
    if let Some(value) = request.supported_types {
        state.supported_types = normalize_supported_types(value)?;
    }
    if let Some(value) = request.enabled {
        state.enabled = value;
    }
    if let Some(value) = request.payment_mode {
        state.payment_mode = value.trim().to_ascii_lowercase();
    }
    if let Some(value) = request.sort_order {
        state.sort_order = value;
    }
    if let Some(value) = request.limits {
        state.limits = value;
    }
    if let Some(value) = request.refund_enabled {
        state.refund_enabled = value;
        if !value {
            state.allow_user_refund = false;
        }
    }
    if let Some(value) = request.allow_user_refund {
        state.allow_user_refund = value && state.refund_enabled;
    }
    normalize_provider(&mut state)?;
    validate_provider(&state)?;

    let pending = pending_orders_for_provider(&mut transaction, id).await?;
    if pending > 0 {
        validate_pending_provider_update(&previous, &state, pending)?;
    }
    let config = serde_json::to_string(&state.config)
        .map_err(|error| AdminError::BadRequest(error.to_string()))?;
    sqlx::query(
        r"
UPDATE payment_provider_instances SET
    name=$2, config=$3, supported_types=$4, enabled=$5, payment_mode=$6,
    sort_order=$7, limits=$8, refund_enabled=$9, allow_user_refund=$10,
    updated_at=NOW()
WHERE id=$1
",
    )
    .bind(id)
    .bind(&state.name)
    .bind(config)
    .bind(state.supported_types.join(","))
    .bind(state.enabled)
    .bind(&state.payment_mode)
    .bind(state.sort_order)
    .bind(&state.limits)
    .bind(state.refund_enabled)
    .bind(state.allow_user_refund)
    .execute(&mut *transaction)
    .await?;
    notify_settings(&mut transaction).await?;
    transaction.commit().await?;
    let provider = provider_by_id(pool, id).await?;
    audit_mutation(actor, "update", "payment_provider", &provider);
    Ok(provider)
}

async fn delete_provider(
    pool: &PgPool,
    actor: &AdminIdentity,
    id: i64,
) -> Result<Value, AdminError> {
    let mut transaction = pool.begin().await?;
    let _provider = load_provider_for_update(&mut transaction, id).await?;
    let pending = pending_orders_for_provider(&mut transaction, id).await?;
    if pending > 0 {
        return Err(AdminError::Conflict(format!(
            "this instance has {pending} in-progress orders and cannot be deleted"
        )));
    }
    sqlx::query("DELETE FROM payment_provider_instances WHERE id = $1")
        .bind(id)
        .execute(&mut *transaction)
        .await?;
    notify_settings(&mut transaction).await?;
    transaction.commit().await?;
    tracing::info!(
        actor_id = actor.user_id,
        provider_id = id,
        "payment provider deleted"
    );
    Ok(json!({ "message": "deleted" }))
}

async fn load_provider_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    id: i64,
) -> Result<ProviderState, AdminError> {
    let row = sqlx::query(
        r"
SELECT id, provider_key, name, config, supported_types, enabled, payment_mode,
       sort_order, limits, refund_enabled, allow_user_refund
FROM payment_provider_instances WHERE id = $1 FOR UPDATE
",
    )
    .bind(id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(AdminError::NotFound("payment provider"))?;
    let stored: String = row.try_get("config")?;
    Ok(ProviderState {
        provider_key: row.try_get("provider_key")?,
        name: row.try_get("name")?,
        config: parse_stored_config(&stored),
        supported_types: split_supported_types(&row.try_get::<String, _>("supported_types")?),
        enabled: row.try_get("enabled")?,
        payment_mode: row.try_get("payment_mode")?,
        sort_order: row.try_get("sort_order")?,
        limits: row.try_get("limits")?,
        refund_enabled: row.try_get("refund_enabled")?,
        allow_user_refund: row.try_get("allow_user_refund")?,
    })
}

async fn provider_by_id(pool: &PgPool, id: i64) -> Result<Value, AdminError> {
    let row = sqlx::query(
        "SELECT to_jsonb(provider) AS data, provider_key, config, supported_types FROM payment_provider_instances provider WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(AdminError::NotFound("payment provider"))?;
    provider_view(&row)
}

fn provider_view(row: &sqlx::postgres::PgRow) -> Result<Value, AdminError> {
    let mut data: Value = row.try_get("data")?;
    let provider_key: String = row.try_get("provider_key")?;
    let stored: String = row.try_get("config")?;
    let supported: String = row.try_get("supported_types")?;
    let object = data
        .as_object_mut()
        .ok_or_else(|| AdminError::Probe("payment provider row is not an object".to_owned()))?;
    object.insert(
        "config".to_owned(),
        serde_json::to_value(masked_provider_config(
            &provider_key,
            parse_stored_config(&stored),
        ))
        .map_err(|error| AdminError::Probe(error.to_string()))?,
    );
    object.insert(
        "supported_types".to_owned(),
        json!(split_supported_types(&supported)),
    );
    Ok(data)
}

fn normalize_provider(provider: &mut ProviderState) -> Result<(), AdminError> {
    provider.name = provider.name.trim().to_owned();
    provider.provider_key = provider.provider_key.trim().to_ascii_lowercase();
    provider.payment_mode = provider.payment_mode.trim().to_ascii_lowercase();
    provider.limits = provider.limits.trim().to_owned();
    if provider.name.is_empty() {
        return Err(AdminError::BadRequest(
            "provider name is required".to_owned(),
        ));
    }
    if provider.name.chars().count() > 100 {
        return Err(AdminError::BadRequest(
            "provider name must not exceed 100 characters".to_owned(),
        ));
    }
    if !VALID_PROVIDER_KEYS.contains(&provider.provider_key.as_str()) {
        return Err(AdminError::BadRequest(format!(
            "invalid provider key: {}",
            provider.provider_key
        )));
    }
    if !provider.limits.is_empty()
        && !serde_json::from_str::<Value>(&provider.limits).is_ok_and(|value| value.is_object())
    {
        return Err(AdminError::BadRequest(
            "provider limits must be a JSON object".to_owned(),
        ));
    }
    Ok(())
}

fn validate_provider(provider: &ProviderState) -> Result<(), AdminError> {
    validate_supported_types(
        &provider.provider_key,
        &provider.supported_types,
        &provider.config,
    )?;
    validate_payment_mode(&provider.provider_key, &provider.payment_mode)?;
    if provider.enabled {
        validate_provider_config(&provider.provider_key, &provider.config)?;
    }
    Ok(())
}

fn validate_supported_types(
    provider_key: &str,
    supported: &[String],
    config: &HashMap<String, String>,
) -> Result<(), AdminError> {
    let allowed = match provider_key {
        "alipay" => &["alipay", "alipay_direct"][..],
        "wxpay" => &["wxpay", "wxpay_direct", "wechat"][..],
        "stripe" => &["card", "link", "alipay", "wxpay", "stripe"][..],
        "airwallex" => &["airwallex"][..],
        "easypay" => return validate_easypay_methods(config, supported),
        _ => return Ok(()),
    };
    if let Some(invalid) = supported
        .iter()
        .find(|candidate| !allowed.contains(&candidate.as_str()))
    {
        return Err(AdminError::BadRequest(format!(
            "payment type {invalid} is not supported by {provider_key}"
        )));
    }
    Ok(())
}

fn validate_easypay_methods(
    config: &HashMap<String, String>,
    supported: &[String],
) -> Result<(), AdminError> {
    let raw = config
        .get("customMethods")
        .map_or("", String::as_str)
        .trim();
    let methods = if raw.is_empty() {
        Vec::new()
    } else {
        serde_json::from_str::<Vec<EasyPayMethod>>(raw)
            .map_err(|_| AdminError::BadRequest("customMethods must be a JSON array".to_owned()))?
    };
    let pattern = Regex::new(r"^[a-z0-9_-]+$").expect("fixed payment method regex");
    let mut custom = HashSet::new();
    for method in methods {
        let kind = method.kind.trim();
        let upstream = method.upstream_type.trim();
        if kind.is_empty() || upstream.is_empty() {
            return Err(AdminError::BadRequest(
                "customMethods upstreamType is required".to_owned(),
            ));
        }
        if !pattern.is_match(kind) || !pattern.is_match(upstream) {
            return Err(AdminError::BadRequest(
                "customMethods codes may only contain lowercase letters, digits, underscores, and hyphens"
                    .to_owned(),
            ));
        }
        if kind.starts_with("alipay") || kind.starts_with("wxpay") {
            return Err(AdminError::BadRequest(
                "customMethods type cannot start with alipay or wxpay".to_owned(),
            ));
        }
        if !custom.insert(kind.to_owned()) {
            return Err(AdminError::BadRequest(
                "duplicate customMethods type".to_owned(),
            ));
        }
    }
    for payment_type in supported {
        if matches!(payment_type.as_str(), "alipay" | "wxpay") {
            continue;
        }
        if !pattern.is_match(payment_type) || !custom.contains(payment_type) {
            return Err(AdminError::BadRequest(format!(
                "supported EasyPay custom type {payment_type} has no valid customMethods mapping"
            )));
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct EasyPayMethod {
    #[serde(rename = "type")]
    kind: String,
    #[serde(rename = "upstreamType")]
    upstream_type: String,
}

fn validate_payment_mode(provider_key: &str, mode: &str) -> Result<(), AdminError> {
    let valid = match provider_key {
        "easypay" => matches!(mode, "" | "qrcode" | "popup" | "redirect"),
        "alipay" => matches!(mode, "" | "qrcode" | "redirect"),
        _ => mode.is_empty(),
    };
    if valid {
        Ok(())
    } else {
        Err(AdminError::BadRequest(format!(
            "invalid payment mode {mode:?} for {provider_key}"
        )))
    }
}

fn validate_provider_config(
    provider_key: &str,
    config: &HashMap<String, String>,
) -> Result<(), AdminError> {
    let required: &[&str] = match provider_key {
        "easypay" => &["pid", "pkey", "apiBase"],
        "alipay" => &["appId", "privateKey"],
        "wxpay" => &[
            "appId",
            "mchId",
            "privateKey",
            "apiV3Key",
            "certSerial",
            "publicKey",
            "publicKeyId",
        ],
        "stripe" => &["secretKey"],
        "airwallex" => &["clientId", "apiKey", "apiBase"],
        _ => &[],
    };
    if let Some(missing) = required
        .iter()
        .find(|key| config_value(config, key).is_empty())
    {
        return Err(AdminError::BadRequest(format!(
            "{provider_key} config missing required key: {missing}"
        )));
    }
    if provider_key == "alipay"
        && config_value(config, "publicKey").is_empty()
        && config_value(config, "alipayPublicKey").is_empty()
    {
        return Err(AdminError::BadRequest(
            "alipay config missing required key: publicKey".to_owned(),
        ));
    }
    if matches!(provider_key, "stripe" | "airwallex") {
        let currency = config_value(config, "currency");
        if !currency.is_empty()
            && (currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_alphabetic()))
        {
            return Err(AdminError::BadRequest(
                "payment currency must be a three-letter code".to_owned(),
            ));
        }
    }
    if provider_key == "airwallex" {
        let base = config_value(config, "apiBase");
        let url = url::Url::parse(base)
            .map_err(|_| AdminError::BadRequest("airwallex apiBase is invalid".to_owned()))?;
        if url.scheme() != "https"
            || !matches!(
                url.host_str(),
                Some("api.airwallex.com" | "api-demo.airwallex.com")
            )
            || url.path().trim_end_matches('/') != "/api/v1"
        {
            return Err(AdminError::BadRequest(
                "airwallex apiBase must be an approved HTTPS API endpoint".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_pending_provider_update(
    previous: &ProviderState,
    next: &ProviderState,
    pending: i64,
) -> Result<(), AdminError> {
    if previous.enabled && !next.enabled {
        return Err(pending_provider_conflict(pending));
    }
    let next_types = next.supported_types.iter().collect::<HashSet<_>>();
    if previous
        .supported_types
        .iter()
        .any(|payment_type| !next_types.contains(payment_type))
    {
        return Err(AdminError::Conflict(format!(
            "cannot remove payment types while instance has {pending} pending orders"
        )));
    }
    for field in protected_config_fields(&previous.provider_key) {
        if config_value(&previous.config, field) != config_value(&next.config, field) {
            return Err(pending_provider_conflict(pending));
        }
    }
    Ok(())
}

fn pending_provider_conflict(count: i64) -> AdminError {
    AdminError::Conflict(format!("instance has {count} pending orders"))
}

fn merge_provider_config(
    provider_key: &str,
    existing: &mut HashMap<String, String>,
    incoming: HashMap<String, String>,
) {
    for (key, value) in incoming {
        if value.is_empty() && is_sensitive_config_field(provider_key, &key) {
            continue;
        }
        existing.insert(key, value);
    }
}

fn masked_provider_config(
    provider_key: &str,
    config: HashMap<String, String>,
) -> HashMap<String, String> {
    config
        .into_iter()
        .filter(|(key, _)| !is_sensitive_config_field(provider_key, key))
        .collect()
}

fn is_sensitive_config_field(provider_key: &str, field: &str) -> bool {
    let field = field.to_ascii_lowercase();
    sensitive_config_fields(provider_key).contains(&field.as_str())
}

fn sensitive_config_fields(provider_key: &str) -> &'static [&'static str] {
    match provider_key {
        "easypay" => &["pkey"],
        "alipay" => &["privatekey", "publickey", "alipaypublickey"],
        "wxpay" => &["privatekey", "apiv3key", "publickey"],
        "stripe" => &["secretkey", "webhooksecret"],
        "airwallex" => &["apikey", "webhooksecret"],
        _ => &[],
    }
}

fn protected_config_fields(provider_key: &str) -> &'static [&'static str] {
    match provider_key {
        "easypay" => &["pkey", "pid"],
        "alipay" => &["privatekey", "publickey", "alipaypublickey", "appid"],
        "wxpay" => &[
            "privatekey",
            "apiv3key",
            "publickey",
            "appid",
            "mpappid",
            "mchid",
            "publickeyid",
            "certserial",
        ],
        "stripe" => &["secretkey", "webhooksecret", "currency"],
        "airwallex" => &[
            "clientid",
            "apikey",
            "webhooksecret",
            "apibase",
            "accountid",
            "currency",
        ],
        _ => &[],
    }
}

fn config_value<'a>(config: &'a HashMap<String, String>, field: &str) -> &'a str {
    config
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(field))
        .map_or("", |(_, value)| value.trim())
}

fn parse_stored_config(stored: &str) -> HashMap<String, String> {
    serde_json::from_str(stored).unwrap_or_else(|_| {
        tracing::warn!(
            stored_len = stored.len(),
            "payment provider config is unreadable"
        );
        HashMap::new()
    })
}

fn normalize_supported_types(values: Vec<String>) -> Result<Vec<String>, AdminError> {
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();
    for value in values {
        let value = value.trim().to_ascii_lowercase();
        if value.is_empty() {
            continue;
        }
        if value.contains(',') || value.chars().count() > 64 {
            return Err(AdminError::BadRequest(
                "payment types contain an invalid value".to_owned(),
            ));
        }
        if seen.insert(value.clone()) {
            normalized.push(value);
        }
    }
    Ok(normalized)
}

fn split_supported_types(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

async fn pending_orders_for_plan(
    transaction: &mut Transaction<'_, Postgres>,
    id: i64,
) -> Result<i64, AdminError> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::bigint FROM payment_orders WHERE plan_id = $1 AND status = ANY($2)",
    )
    .bind(id)
    .bind(PENDING_ORDER_STATUSES.as_slice())
    .fetch_one(&mut **transaction)
    .await?)
}

async fn pending_orders_for_provider(
    transaction: &mut Transaction<'_, Postgres>,
    id: i64,
) -> Result<i64, AdminError> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::bigint FROM payment_orders WHERE provider_instance_id = $1 AND status = ANY($2)",
    )
    .bind(id.to_string())
    .bind(PENDING_ORDER_STATUSES.as_slice())
    .fetch_one(&mut **transaction)
    .await?)
}

async fn ensure_live_group(
    transaction: &mut Transaction<'_, Postgres>,
    id: i64,
) -> Result<(), AdminError> {
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM groups WHERE id = $1 AND deleted_at IS NULL)",
    )
    .bind(id)
    .fetch_one(&mut **transaction)
    .await?;
    if exists {
        Ok(())
    } else {
        Err(AdminError::NotFound("group"))
    }
}

async fn notify_settings(transaction: &mut Transaction<'_, Postgres>) -> Result<(), AdminError> {
    sqlx::query("SELECT pg_notify($1, $2)")
        .bind(INVALIDATION_CHANNEL)
        .bind(r#"{"version":1,"scope":"settings"}"#)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

fn audit_mutation(actor: &AdminIdentity, action: &str, resource: &str, value: &Value) {
    let resource_id = value.get("id").and_then(Value::as_i64);
    tracing::info!(
        actor_id = actor.user_id,
        actor_email = %actor.email,
        action,
        resource,
        resource_id,
        "administrator payment mutation"
    );
}

fn parse_payload<T: DeserializeOwned>(payload: Value) -> Result<T, AdminError> {
    if !payload.is_object() {
        return Err(AdminError::BadRequest(
            "request body must be a JSON object".to_owned(),
        ));
    }
    serde_json::from_value(payload)
        .map_err(|error| AdminError::BadRequest(format!("invalid request: {error}")))
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

fn query_positive_i64(query: &BTreeMap<String, String>, key: &str) -> Option<i64> {
    query
        .get(key)
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
}

fn trimmed_query(query: &BTreeMap<String, String>, key: &str, max_chars: usize) -> Option<String> {
    query
        .get(key)
        .map(|value| value.trim().chars().take(max_chars).collect::<String>())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use sqlx::postgres::PgPoolOptions;
    use uuid::Uuid;

    use super::*;

    #[test]
    fn payment_dispatcher_claims_exactly_the_ten_generic_routes() {
        assert_eq!(PAYMENT_HANDLERS.len(), 10);
        assert!(PAYMENT_HANDLERS.contains(&"adminPaymentHandler.ListOrders"));
        assert!(PAYMENT_HANDLERS.contains(&"adminPaymentHandler.DeleteProvider"));
        assert!(!PAYMENT_HANDLERS.contains(&"adminPaymentHandler.ProcessRefund"));
    }

    #[test]
    fn provider_secrets_are_redacted_and_blank_updates_preserve_them() {
        let mut config = HashMap::from([
            ("secretKey".to_owned(), "sk_live".to_owned()),
            ("publishableKey".to_owned(), "pk_live".to_owned()),
        ]);
        merge_provider_config(
            "stripe",
            &mut config,
            HashMap::from([
                ("secretKey".to_owned(), String::new()),
                ("currency".to_owned(), "USD".to_owned()),
            ]),
        );
        assert_eq!(config.get("secretKey").map(String::as_str), Some("sk_live"));
        let masked = masked_provider_config("stripe", config);
        assert!(!masked.contains_key("secretKey"));
        assert_eq!(
            masked.get("publishableKey").map(String::as_str),
            Some("pk_live")
        );
        assert_eq!(masked.get("currency").map(String::as_str), Some("USD"));
    }

    #[test]
    fn enabled_provider_requires_valid_config_and_visible_methods() {
        let provider = ProviderState {
            provider_key: "stripe".to_owned(),
            name: "Stripe".to_owned(),
            config: HashMap::new(),
            supported_types: vec!["bogus".to_owned()],
            enabled: true,
            payment_mode: String::new(),
            sort_order: 0,
            limits: String::new(),
            refund_enabled: false,
            allow_user_refund: false,
        };
        assert!(validate_provider(&provider).is_err());
        let mut valid = provider;
        valid.supported_types = vec!["card".to_owned()];
        valid
            .config
            .insert("secretKey".to_owned(), "secret".to_owned());
        assert!(validate_provider(&valid).is_ok());
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn postgres_provider_secret_round_trip_preserves_and_masks_credentials() {
        let database_url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL");
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .expect("connect PostgreSQL");
        let actor = AdminIdentity {
            user_id: 1,
            email: "admin@test.invalid".to_owned(),
        };
        let name = format!("rust-secret-test-{}", Uuid::new_v4());
        let created = create_provider(
            &pool,
            &actor,
            json!({
                "provider_key": "stripe",
                "name": name,
                "config": {"secretKey": "sk_test", "publishableKey": "pk_test"},
                "supported_types": ["card"],
                "enabled": false
            }),
        )
        .await
        .expect("create provider");
        let id = created["id"].as_i64().expect("provider id");
        assert!(created["config"].get("secretKey").is_none());
        update_provider(
            &pool,
            &actor,
            id,
            json!({"config": {"secretKey": "", "currency": "USD"}}),
        )
        .await
        .expect("update provider");
        let stored = sqlx::query_scalar::<_, String>(
            "SELECT config FROM payment_provider_instances WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("load provider config");
        let stored: HashMap<String, String> = serde_json::from_str(&stored).expect("config JSON");
        assert_eq!(stored.get("secretKey").map(String::as_str), Some("sk_test"));
        assert_eq!(stored.get("currency").map(String::as_str), Some("USD"));
        sqlx::query("DELETE FROM payment_provider_instances WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .expect("cleanup provider");
    }

    #[test]
    fn payload_must_be_an_object() {
        assert!(parse_payload::<UpdatePlanRequest>(Value::Array(Vec::new())).is_err());
    }
}
