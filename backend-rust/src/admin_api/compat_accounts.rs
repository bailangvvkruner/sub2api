//! PostgreSQL-backed compatibility handlers for account and proxy bulk operations.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use axum::http::Method;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{Client, Proxy, redirect::Policy};
use serde_json::{Map, Value, json};
use sqlx::{PgPool, Postgres, Row, Transaction};
use url::Url;

use super::{
    AdminError,
    compat::{payload_object, redacted_json, relation_list, required_path_id},
    compat_oauth,
    service::validate_public_probe_target,
};

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) async fn dispatch(
    pool: &PgPool,
    handler: &str,
    _category: &str,
    _method: &Method,
    path: &str,
    query: &BTreeMap<String, String>,
    payload: Value,
) -> Option<Result<Value, AdminError>> {
    let result = match handler {
        "h.Admin.Account.SyncUpstreamModels" => {
            sync_account_models(pool, required_path_id(path, "account").ok()?).await
        }
        "h.Admin.Account.SyncUpstreamModelsPreview" => sync_models_preview(pool, &payload).await,
        "h.Admin.Account.Refresh" => {
            compat_oauth::refresh_account_auto(pool, required_path_id(path, "account").ok()?).await
        }
        "h.Admin.Account.RefreshTier" => {
            refresh_account_tier(pool, required_path_id(path, "account").ok()?).await
        }
        "h.Admin.Account.RevertProxyFallback" => {
            revert_proxy_fallback(pool, required_path_id(path, "account").ok()?).await
        }
        "h.Admin.ScheduledTest.ListByAccount" => {
            relation_list(
                pool,
                "scheduled_test_plans",
                "account_id",
                required_path_id(path, "account").ok()?,
                query,
            )
            .await
        }
        "h.Admin.Account.GetAntigravityDefaultModelMapping" => {
            Ok(antigravity_default_model_mapping())
        }
        "h.Admin.Account.BatchCreate" => batch_create_accounts(pool, payload).await,
        "h.Admin.Account.BatchRefresh" => batch_refresh_accounts(pool, &payload).await,
        "h.Admin.Account.BatchRefreshTier" => batch_refresh_tiers(pool, &payload).await,
        "h.Admin.Account.BatchUpdateCredentials" => batch_update_credentials(pool, payload).await,
        "h.Admin.Account.BulkUpdate" => bulk_update_accounts(pool, payload).await,
        "h.Admin.Account.CheckMixedChannel" => check_mixed_channel(pool, &payload).await,
        "h.Admin.Account.ExportData" => export_account_data(pool, query).await,
        "h.Admin.Account.ImportData" => import_account_data(pool, &payload).await,
        "h.Admin.Account.ImportCodexSession" => import_codex_sessions(pool, &payload).await,
        "h.Admin.Account.SyncFromCRS" => sync_from_crs(pool, &payload, false).await,
        "h.Admin.Account.PreviewFromCRS" => sync_from_crs(pool, &payload, true).await,
        "h.Admin.Proxy.GetProxyAccounts" => {
            proxy_accounts(pool, required_path_id(path, "proxy").ok()?).await
        }
        "h.Admin.Proxy.GetStats" => proxy_stats(pool, required_path_id(path, "proxy").ok()?).await,
        "h.Admin.Proxy.BatchCreate" => batch_create_proxies(pool, &payload).await,
        "h.Admin.Proxy.BatchDelete" => batch_delete_proxies(pool, &payload).await,
        "h.Admin.Proxy.ExportData" => export_proxy_data(pool, query).await,
        "h.Admin.Proxy.ImportData" => import_proxy_data(pool, &payload).await,
        _ => return None,
    };
    Some(result)
}

async fn sync_account_models(pool: &PgPool, id: i64) -> Result<Value, AdminError> {
    let row = sqlx::query(
        "SELECT credentials, proxy_id FROM accounts WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(AdminError::NotFound("account"))?;
    let credentials: Value = row.try_get("credentials")?;
    let models = fetch_upstream_models(pool, &credentials, row.try_get("proxy_id")?).await?;
    let serialized = serde_json::to_string(&models)
        .map_err(|error| AdminError::BadRequest(error.to_string()))?;
    sqlx::query(
        "UPDATE accounts SET extra = jsonb_set(COALESCE(extra, '{}'::jsonb), '{upstream_models}', $2::jsonb, true), updated_at = NOW() WHERE id = $1",
    )
    .bind(id)
    .bind(serialized)
    .execute(pool)
    .await?;
    Ok(json!({ "models": models }))
}

async fn sync_models_preview(pool: &PgPool, payload: &Value) -> Result<Value, AdminError> {
    let api_key = required_string(payload, "api_key")?;
    let base_url = payload
        .get("base_url")
        .and_then(Value::as_str)
        .unwrap_or("https://api.openai.com");
    let credentials = json!({ "api_key": api_key, "base_url": base_url });
    let models =
        fetch_upstream_models(pool, &credentials, optional_i64(payload, "proxy_id")?).await?;
    Ok(json!({ "models": models }))
}

async fn fetch_upstream_models(
    pool: &PgPool,
    credentials: &Value,
    proxy_id: Option<i64>,
) -> Result<Vec<String>, AdminError> {
    let api_key = credentials
        .get("api_key")
        .or_else(|| credentials.get("access_token"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AdminError::BadRequest("account has no API credential".to_owned()))?;
    let base_url = credentials
        .get("base_url")
        .and_then(Value::as_str)
        .unwrap_or("https://api.openai.com");
    let endpoint = format!(
        "{}/v1/models",
        base_url.trim_end_matches('/').trim_end_matches("/v1")
    );
    let validated = validate_public_probe_target(&endpoint).await?;
    let mut builder = Client::builder()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(20));
    let url = Url::parse(validated.url())
        .map_err(|_| AdminError::BadRequest("upstream models URL is invalid".to_owned()))?;
    if let Some(host) = url.host_str() {
        for address in validated.resolved_addresses() {
            builder = builder.resolve(host, *address);
        }
    }
    if let Some(proxy_url) = load_proxy_url(pool, proxy_id).await? {
        builder = builder.proxy(Proxy::all(&proxy_url).map_err(|error| {
            AdminError::BadRequest(format!("invalid proxy configuration: {error}"))
        })?);
    }
    let response = builder
        .build()
        .map_err(|error| AdminError::Probe(format!("cannot create upstream client: {error}")))?
        .get(validated.url())
        .bearer_auth(api_key)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|error| AdminError::Probe(format!("upstream model request failed: {error}")))?;
    let status = response.status();
    let body = response
        .json::<Value>()
        .await
        .map_err(|error| AdminError::Probe(format!("invalid upstream model response: {error}")))?;
    if !status.is_success() {
        return Err(AdminError::Probe(format!(
            "upstream model request returned HTTP {}",
            status.as_u16()
        )));
    }
    let mut models = body
        .get("data")
        .and_then(Value::as_array)
        .or_else(|| body.get("models").and_then(Value::as_array))
        .into_iter()
        .flatten()
        .filter_map(|item| {
            item.as_str()
                .or_else(|| item.get("id").and_then(Value::as_str))
                .or_else(|| item.get("name").and_then(Value::as_str))
                .map(str::to_owned)
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    models.sort();
    Ok(models)
}

async fn refresh_account_tier(pool: &PgPool, id: i64) -> Result<Value, AdminError> {
    let row = sqlx::query(
        "SELECT platform, type, credentials, proxy_id FROM accounts WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(AdminError::NotFound("account"))?;
    let platform: String = row.try_get("platform")?;
    let account_type: String = row.try_get("type")?;
    let credentials: Value = row.try_get("credentials")?;
    if platform != "gemini"
        || account_type != "oauth"
        || credentials.get("oauth_type").and_then(Value::as_str) != Some("google_one")
    {
        return Err(AdminError::BadRequest(
            "only Gemini google_one OAuth accounts support tier refresh".to_owned(),
        ));
    }
    let access_token = credentials
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AdminError::BadRequest("account has no access_token".to_owned()))?;
    let (limit, usage) = drive_storage_quota(pool, access_token, row.try_get("proxy_id")?).await?;
    let tier_id = infer_google_one_tier(limit);
    let updated_at = chrono::Utc::now().to_rfc3339();
    let storage_info = json!({
        "drive_storage_limit": limit,
        "drive_storage_usage": usage,
        "drive_tier_updated_at": updated_at,
    });
    sqlx::query(
        "UPDATE accounts SET credentials=jsonb_set(credentials,'{tier_id}',to_jsonb($2::text),true), extra=extra || $3::jsonb, updated_at=NOW() WHERE id=$1",
    )
    .bind(id)
    .bind(tier_id)
    .bind(serde_json::to_string(&storage_info).map_err(json_error)?)
    .execute(pool)
    .await?;
    Ok(json!({
        "tier_id": tier_id,
        "storage_info": storage_info,
        "drive_storage_limit": limit,
        "drive_storage_usage": usage,
        "updated_at": updated_at,
    }))
}

async fn drive_storage_quota(
    pool: &PgPool,
    access_token: &str,
    proxy_id: Option<i64>,
) -> Result<(i64, i64), AdminError> {
    let mut builder = Client::builder()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(10));
    if let Some(proxy_url) = load_proxy_url(pool, proxy_id).await? {
        builder = builder.proxy(Proxy::all(&proxy_url).map_err(|error| {
            AdminError::BadRequest(format!("invalid proxy configuration: {error}"))
        })?);
    }
    let response = builder
        .build()
        .map_err(|error| AdminError::Probe(format!("cannot create Drive client: {error}")))?
        .get("https://www.googleapis.com/drive/v3/about?fields=storageQuota")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|error| AdminError::Probe(format!("Drive API request failed: {error}")))?;
    let status = response.status();
    let body = response
        .json::<Value>()
        .await
        .map_err(|error| AdminError::Probe(format!("Drive API returned invalid JSON: {error}")))?;
    if !status.is_success() {
        return Err(AdminError::Probe(format!(
            "Drive API returned HTTP {}",
            status.as_u16()
        )));
    }
    let quota = body
        .get("storageQuota")
        .ok_or_else(|| AdminError::Probe("Drive API response has no storageQuota".to_owned()))?;
    Ok((json_i64(quota.get("limit")), json_i64(quota.get("usage"))))
}

fn json_i64(value: Option<&Value>) -> i64 {
    value
        .and_then(|value| {
            value
                .as_i64()
                .or_else(|| value.as_str().and_then(|raw| raw.parse().ok()))
        })
        .unwrap_or(0)
}

fn infer_google_one_tier(storage_bytes: i64) -> &'static str {
    const GIB: i64 = 1_024 * 1_024 * 1_024;
    const TIB: i64 = 1_024 * GIB;
    if storage_bytes > 100 * TIB {
        "google_ai_ultra"
    } else if storage_bytes >= 2 * TIB {
        "google_ai_pro"
    } else if storage_bytes >= 15 * GIB {
        "google_one_free"
    } else {
        "google_one_unknown"
    }
}

async fn revert_proxy_fallback(pool: &PgPool, id: i64) -> Result<Value, AdminError> {
    let sql = format!(
        "UPDATE accounts row SET proxy_id = proxy_fallback_origin_id, proxy_fallback_origin_id = NULL, updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL AND proxy_fallback_origin_id IS NOT NULL RETURNING {}",
        redacted_json("row")
    );
    sqlx::query_scalar::<_, Value>(&sql)
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AdminError::BadRequest("account is not in proxy fallback state".to_owned()))
}

fn antigravity_default_model_mapping() -> Value {
    json!({
        "claude-fable-5": "claude-fable-5",
        "claude-opus-4-8": "claude-opus-4-8",
        "claude-opus-4-7": "claude-opus-4-7",
        "claude-opus-4-6": "claude-opus-4-6-thinking",
        "claude-opus-4-6-thinking": "claude-opus-4-6-thinking",
        "claude-sonnet-5": "claude-sonnet-5",
        "claude-sonnet-4-6": "claude-sonnet-4-6",
        "claude-sonnet-4-6-thinking": "claude-sonnet-4-6-thinking",
        "claude-sonnet-4-5": "claude-sonnet-4-5",
        "claude-haiku-4-5": "claude-sonnet-4-6",
        "claude-haiku-4-5-20251001": "claude-sonnet-4-6",
        "gemini-2.5-flash": "gemini-2.5-flash",
        "gemini-2.5-flash-image": "gemini-2.5-flash-image",
        "gemini-2.5-flash-image-preview": "gemini-2.5-flash-image",
        "gemini-2.5-flash-lite": "gemini-2.5-flash-lite",
        "gemini-2.5-flash-thinking": "gemini-2.5-flash-thinking",
        "gemini-2.5-pro": "gemini-2.5-pro",
        "gemini-3-flash": "gemini-3-flash",
        "gemini-3-flash-preview": "gemini-3-flash",
        "gemini-3-pro-high": "gemini-3-pro-high",
        "gemini-3-pro-low": "gemini-3-pro-low",
        "gemini-3-pro-preview": "gemini-3-pro-high",
        "gemini-3.1-pro": "gemini-3.1-pro-preview",
        "gemini-3.1-pro-high": "gemini-3.1-pro-preview",
        "gemini-3.1-pro-low": "gemini-3.1-pro-low",
        "gemini-3.1-pro-preview": "gemini-3.1-pro-preview",
        "gemini-3.1-flash-image": "gemini-3.1-flash-image",
        "gemini-3.1-flash-image-preview": "gemini-3.1-flash-image",
        "gemini-3-pro-image": "gemini-3.1-flash-image",
        "gemini-3-pro-image-preview": "gemini-3.1-flash-image",
        "gpt-oss-120b-medium": "gpt-oss-120b-medium",
        "tab_flash_lite_preview": "tab_flash_lite_preview"
    })
}

async fn batch_create_accounts(pool: &PgPool, payload: Value) -> Result<Value, AdminError> {
    let object = payload_object(payload)?;
    let accounts = object
        .get("accounts")
        .and_then(Value::as_array)
        .ok_or_else(|| AdminError::BadRequest("accounts must be a non-empty array".to_owned()))?;
    if accounts.is_empty() || accounts.len() > 1_000 {
        return Err(AdminError::BadRequest(
            "accounts must contain between 1 and 1000 items".to_owned(),
        ));
    }
    let mut success = 0_u64;
    let mut failed = 0_u64;
    let mut results = Vec::with_capacity(accounts.len());
    for item in accounts {
        let name = item.get("name").and_then(Value::as_str).unwrap_or_default();
        match create_account(pool, item).await {
            Ok(id) => {
                success += 1;
                results.push(json!({ "name": name, "id": id, "success": true }));
            }
            Err(error) => {
                failed += 1;
                results.push(json!({ "name": name, "success": false, "error": error.to_string() }));
            }
        }
    }
    Ok(json!({ "success": success, "failed": failed, "results": results }))
}

async fn create_account(pool: &PgPool, item: &Value) -> Result<i64, AdminError> {
    let name = required_string(item, "name")?;
    let platform = required_string(item, "platform")?;
    let account_type = required_string(item, "type")?;
    if !matches!(
        account_type.as_str(),
        "oauth" | "setup-token" | "apikey" | "upstream" | "bedrock" | "service_account"
    ) {
        return Err(AdminError::BadRequest("account type is invalid".to_owned()));
    }
    let credentials = item
        .get("credentials")
        .and_then(Value::as_object)
        .ok_or_else(|| AdminError::BadRequest("credentials must be an object".to_owned()))?;
    let extra = item
        .get("extra")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let concurrency = optional_i32(item, "concurrency")?.unwrap_or(3);
    let priority = optional_i32(item, "priority")?.unwrap_or(50);
    let rate_multiplier = item
        .get("rate_multiplier")
        .and_then(Value::as_f64)
        .unwrap_or(1.0);
    if !(0..=100_000).contains(&concurrency)
        || !(0..=100).contains(&priority)
        || !rate_multiplier.is_finite()
        || rate_multiplier < 0.0
    {
        return Err(AdminError::BadRequest(
            "account scheduling values are invalid".to_owned(),
        ));
    }
    let proxy_id = optional_i64(item, "proxy_id")?;
    let group_ids = positive_id_array(item.get("group_ids"), "group_ids")?;
    let status = item
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("active");
    if !matches!(status, "active" | "inactive" | "error") {
        return Err(AdminError::BadRequest(
            "account status is invalid".to_owned(),
        ));
    }
    let schedulable = item
        .get("schedulable")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let mut transaction = pool.begin().await?;
    validate_proxy(&mut transaction, proxy_id).await?;
    validate_groups(&mut transaction, &group_ids).await?;
    let id = sqlx::query_scalar::<_, i64>(
        "INSERT INTO accounts (name, notes, platform, type, credentials, extra, proxy_id, concurrency, priority, rate_multiplier, load_factor, status, schedulable, expires_at, auto_pause_on_expired) VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7,$8,$9,$10,$11,$12,$13,CASE WHEN $14::bigint IS NULL THEN NULL ELSE to_timestamp($14) END,$15) RETURNING id",
    )
    .bind(name.trim())
    .bind(item.get("notes").and_then(Value::as_str))
    .bind(platform.trim())
    .bind(account_type)
    .bind(serde_json::to_string(credentials).map_err(json_error)?)
    .bind(serde_json::to_string(&extra).map_err(json_error)?)
    .bind(proxy_id)
    .bind(concurrency)
    .bind(priority)
    .bind(rate_multiplier)
    .bind(optional_i32(item, "load_factor")?)
    .bind(status)
    .bind(schedulable)
    .bind(optional_i64(item, "expires_at")?)
    .bind(item.get("auto_pause_on_expired").and_then(Value::as_bool).unwrap_or(true))
    .fetch_one(&mut *transaction)
    .await?;
    replace_account_groups(&mut transaction, id, &group_ids, priority).await?;
    transaction.commit().await?;
    Ok(id)
}

async fn batch_refresh_accounts(pool: &PgPool, payload: &Value) -> Result<Value, AdminError> {
    let mut ids = positive_id_array(payload.get("account_ids"), "account_ids")?;
    if ids.is_empty() {
        ids = sqlx::query_scalar::<_, i64>(
            "SELECT id FROM accounts WHERE type = 'oauth' AND deleted_at IS NULL ORDER BY id",
        )
        .fetch_all(pool)
        .await?;
    }
    if ids.len() > 1_000 {
        return Err(AdminError::BadRequest(
            "at most 1000 accounts may be refreshed at once".to_owned(),
        ));
    }
    let mut success = 0_u64;
    let mut failed = 0_u64;
    let mut results = Vec::with_capacity(ids.len());
    for id in ids {
        match compat_oauth::refresh_account_auto(pool, id).await {
            Ok(account) => {
                success += 1;
                results.push(json!({ "account_id": id, "success": true, "account": account }));
            }
            Err(error) => {
                failed += 1;
                results.push(
                    json!({ "account_id": id, "success": false, "error": error.to_string() }),
                );
            }
        }
    }
    Ok(
        json!({ "total": success + failed, "success": success, "failed": failed, "results": results }),
    )
}

async fn batch_refresh_tiers(pool: &PgPool, payload: &Value) -> Result<Value, AdminError> {
    let mut ids = positive_id_array(payload.get("account_ids"), "account_ids")?;
    if ids.is_empty() {
        ids = sqlx::query_scalar::<_, i64>(
            "SELECT id FROM accounts WHERE platform = 'gemini' AND type = 'oauth' AND credentials->>'oauth_type' = 'google_one' AND deleted_at IS NULL ORDER BY id",
        )
        .fetch_all(pool)
        .await?;
    }
    if ids.len() > 1_000 {
        return Err(AdminError::BadRequest(
            "at most 1000 account tiers may be refreshed at once".to_owned(),
        ));
    }
    let mut success = 0_u64;
    let mut failed = 0_u64;
    let mut errors = Vec::new();
    for id in &ids {
        match refresh_account_tier(pool, *id).await {
            Ok(_) => success += 1,
            Err(error) => {
                failed += 1;
                errors.push(json!({ "account_id": id, "error": error.to_string() }));
            }
        }
    }
    Ok(json!({ "total": ids.len(), "success": success, "failed": failed, "errors": errors }))
}

async fn batch_update_credentials(pool: &PgPool, payload: Value) -> Result<Value, AdminError> {
    let object = payload_object(payload)?;
    let ids = positive_id_array(object.get("account_ids"), "account_ids")?;
    if ids.is_empty() || ids.len() > 1_000 {
        return Err(AdminError::BadRequest(
            "account_ids must contain between 1 and 1000 IDs".to_owned(),
        ));
    }
    let field = object
        .get("field")
        .and_then(Value::as_str)
        .ok_or_else(|| AdminError::BadRequest("field is required".to_owned()))?;
    if !matches!(
        field,
        "account_uuid" | "org_uuid" | "intercept_warmup_requests"
    ) {
        return Err(AdminError::BadRequest(
            "credential field is not batch-writable".to_owned(),
        ));
    }
    let value = object.get("value").cloned().unwrap_or(Value::Null);
    if field == "intercept_warmup_requests" && !value.is_boolean() {
        return Err(AdminError::BadRequest(
            "intercept_warmup_requests must be boolean".to_owned(),
        ));
    }
    if field != "intercept_warmup_requests" && !value.is_null() && !value.is_string() {
        return Err(AdminError::BadRequest(format!(
            "{field} must be string or null"
        )));
    }
    let mut transaction = pool.begin().await?;
    let existing = sqlx::query_scalar::<_, i64>(
        "SELECT id FROM accounts WHERE id = ANY($1) AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(&ids)
    .fetch_all(&mut *transaction)
    .await?;
    if existing.len() != ids.len() {
        return Err(AdminError::NotFound("account"));
    }
    let serialized = serde_json::to_string(&value).map_err(json_error)?;
    sqlx::query(
        "UPDATE accounts SET credentials = jsonb_set(COALESCE(credentials, '{}'::jsonb), ARRAY[$2], $3::jsonb, true), updated_at = NOW() WHERE id = ANY($1) AND deleted_at IS NULL",
    )
    .bind(&ids)
    .bind(field)
    .bind(serialized)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    let results = ids
        .iter()
        .map(|id| json!({ "account_id": id, "success": true }))
        .collect::<Vec<_>>();
    Ok(json!({
        "success": ids.len(), "failed": 0, "success_ids": ids,
        "failed_ids": [], "results": results
    }))
}

#[allow(clippy::too_many_lines)]
async fn bulk_update_accounts(pool: &PgPool, payload: Value) -> Result<Value, AdminError> {
    let object = payload_object(payload)?;
    let mut ids = positive_id_array(object.get("account_ids"), "account_ids")?;
    if ids.is_empty() {
        let filters = object
            .get("filters")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                AdminError::BadRequest("account_ids or filters is required".to_owned())
            })?;
        ids = filtered_account_ids(pool, filters).await?;
    }
    if ids.len() > 10_000 {
        return Err(AdminError::BadRequest(
            "bulk update is limited to 10000 accounts".to_owned(),
        ));
    }
    let has_updates = [
        "name",
        "proxy_id",
        "concurrency",
        "priority",
        "rate_multiplier",
        "load_factor",
        "status",
        "schedulable",
        "group_ids",
        "credentials",
        "extra",
    ]
    .iter()
    .any(|key| object.contains_key(*key));
    if !has_updates {
        return Err(AdminError::BadRequest("no updates provided".to_owned()));
    }
    let name = optional_nonempty_string(&object, "name")?;
    let proxy_set = object.contains_key("proxy_id");
    let proxy_id = optional_i64_from_map(&object, "proxy_id")?;
    let concurrency = optional_i32_from_map(&object, "concurrency")?;
    let priority = optional_i32_from_map(&object, "priority")?;
    let rate_multiplier = optional_f64_from_map(&object, "rate_multiplier")?;
    let load_factor = optional_i32_from_map(&object, "load_factor")?;
    let status = optional_nonempty_string(&object, "status")?;
    let schedulable = optional_bool_from_map(&object, "schedulable")?;
    if let Some(value) = concurrency
        && !(0..=100_000).contains(&value)
    {
        return Err(AdminError::BadRequest(
            "concurrency is out of range".to_owned(),
        ));
    }
    if let Some(value) = priority
        && !(0..=100).contains(&value)
    {
        return Err(AdminError::BadRequest(
            "priority is out of range".to_owned(),
        ));
    }
    if let Some(value) = rate_multiplier
        && (!value.is_finite() || value < 0.0)
    {
        return Err(AdminError::BadRequest(
            "rate_multiplier is invalid".to_owned(),
        ));
    }
    if let Some(value) = status.as_deref()
        && !matches!(value, "active" | "inactive" | "error")
    {
        return Err(AdminError::BadRequest("status is invalid".to_owned()));
    }
    let credentials = optional_object_json(&object, "credentials")?;
    let extra = optional_object_json(&object, "extra")?;
    let groups = object
        .contains_key("group_ids")
        .then(|| positive_id_array(object.get("group_ids"), "group_ids"))
        .transpose()?;
    let mut transaction = pool.begin().await?;
    validate_proxy(&mut transaction, proxy_id).await?;
    if let Some(group_ids) = &groups {
        validate_groups(&mut transaction, group_ids).await?;
    }
    let result = sqlx::query(
        "UPDATE accounts SET name = COALESCE($2,name), proxy_id = CASE WHEN $3 THEN $4 ELSE proxy_id END, concurrency = COALESCE($5,concurrency), priority = COALESCE($6,priority), rate_multiplier = COALESCE($7,rate_multiplier), load_factor = COALESCE($8,load_factor), status = COALESCE($9,status), schedulable = COALESCE($10,schedulable), credentials = CASE WHEN $11::jsonb IS NULL THEN credentials ELSE credentials || $11::jsonb END, extra = CASE WHEN $12::jsonb IS NULL THEN extra ELSE extra || $12::jsonb END, updated_at = NOW() WHERE id = ANY($1) AND deleted_at IS NULL",
    )
    .bind(&ids)
    .bind(name)
    .bind(proxy_set)
    .bind(proxy_id)
    .bind(concurrency)
    .bind(priority)
    .bind(rate_multiplier)
    .bind(load_factor)
    .bind(status)
    .bind(schedulable)
    .bind(credentials)
    .bind(extra)
    .execute(&mut *transaction)
    .await?;
    if let Some(group_ids) = groups {
        for id in &ids {
            replace_account_groups(&mut transaction, *id, &group_ids, priority.unwrap_or(50))
                .await?;
        }
    }
    transaction.commit().await?;
    Ok(json!({
        "matched": ids.len(),
        "updated": result.rows_affected(),
        "account_ids": ids,
    }))
}

async fn filtered_account_ids(
    pool: &PgPool,
    filters: &Map<String, Value>,
) -> Result<Vec<i64>, AdminError> {
    let platform = optional_nonempty_string(filters, "platform")?;
    let account_type = optional_nonempty_string(filters, "type")?;
    let status = optional_nonempty_string(filters, "status")?;
    let search = optional_nonempty_string(filters, "search")?.map(|value| format!("%{value}%"));
    let privacy = optional_nonempty_string(filters, "privacy_mode")?;
    let group = optional_nonempty_string(filters, "group")?;
    let group_id = group.as_deref().and_then(|value| value.parse::<i64>().ok());
    sqlx::query_scalar::<_, i64>(
        "SELECT a.id FROM accounts a WHERE a.deleted_at IS NULL AND ($1::text IS NULL OR a.platform=$1) AND ($2::text IS NULL OR a.type=$2) AND ($3::text IS NULL OR a.status=$3) AND ($4::text IS NULL OR a.name ILIKE $4 OR a.notes ILIKE $4) AND ($5::text IS NULL OR a.extra->>'privacy_mode'=$5) AND ($6::bigint IS NULL OR EXISTS (SELECT 1 FROM account_groups ag WHERE ag.account_id=a.id AND ag.group_id=$6)) AND ($7::boolean=FALSE OR NOT EXISTS (SELECT 1 FROM account_groups ag WHERE ag.account_id=a.id)) ORDER BY a.id LIMIT 10001",
    )
    .bind(platform)
    .bind(account_type)
    .bind(status)
    .bind(search)
    .bind(privacy)
    .bind(group_id)
    .bind(group.as_deref() == Some("ungrouped"))
    .fetch_all(pool)
    .await
    .map_err(AdminError::from)
}

async fn check_mixed_channel(pool: &PgPool, payload: &Value) -> Result<Value, AdminError> {
    let platform = required_string(payload, "platform")?;
    let groups = positive_id_array(payload.get("group_ids"), "group_ids")?;
    if groups.is_empty() {
        return Ok(json!({ "has_risk": false }));
    }
    let account_id = optional_i64(payload, "account_id")?.unwrap_or(0);
    let row = sqlx::query(
        "SELECT g.id, g.name, a.platform FROM groups g JOIN account_groups ag ON ag.group_id=g.id JOIN accounts a ON a.id=ag.account_id AND a.deleted_at IS NULL WHERE g.id=ANY($1) AND a.id<>$2 AND a.platform<>$3 ORDER BY g.id LIMIT 1",
    )
    .bind(&groups)
    .bind(account_id)
    .bind(&platform)
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(json!({ "has_risk": false }));
    };
    Ok(json!({
        "has_risk": true,
        "error": "mixed_channel_warning",
        "message": "the selected group already contains a different upstream platform",
        "details": {
            "group_id": row.try_get::<i64,_>("id")?,
            "group_name": row.try_get::<String,_>("name")?,
            "current_platform": row.try_get::<String,_>("platform")?,
            "other_platform": platform,
        }
    }))
}

#[allow(clippy::too_many_lines)]
async fn export_account_data(
    pool: &PgPool,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let ids = export_ids(query, "account")?;
    let selected_ids = (!ids.is_empty()).then_some(ids);
    let platform = query_text(query, "platform");
    let account_type = query_text(query, "type");
    let status = query_text(query, "status");
    let search =
        query_text(query, "search").map(|value| value.chars().take(100).collect::<String>());
    let privacy = query_text(query, "privacy_mode");
    let group = query_text(query, "group");
    let (group_id, ungrouped) = match group.as_deref() {
        None => (None, false),
        Some("ungrouped") => (None, true),
        Some(value) => {
            let id = value
                .parse::<i64>()
                .map_err(|_| AdminError::BadRequest("invalid group filter".to_owned()))?;
            if id <= 0 {
                return Err(AdminError::BadRequest("invalid group filter".to_owned()));
            }
            (Some(id), false)
        }
    };
    let sort_column = match query
        .get("sort_by")
        .map(|value| value.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("id") => "a.id",
        Some("status") => "a.status",
        Some("schedulable") => "a.schedulable",
        Some("priority") => "a.priority",
        Some("rate_multiplier") => "a.rate_multiplier",
        Some("last_used_at") => "a.last_used_at",
        Some("expires_at") => "a.expires_at",
        Some("created_at") => "a.created_at",
        _ => "a.name",
    };
    let sort_order = export_sort_order(query, "ASC");
    let sql = format!(
        r"
SELECT a.id, a.name, a.notes, a.platform, a.type, a.credentials,
       COALESCE(a.extra, '{{}}'::jsonb) AS extra, a.proxy_id, a.concurrency,
       a.priority, a.rate_multiplier::double precision AS rate_multiplier,
       EXTRACT(EPOCH FROM a.expires_at)::bigint AS expires_at,
       a.auto_pause_on_expired, a.parent_account_id
FROM accounts a
WHERE a.deleted_at IS NULL
  AND (
    ($1::bigint[] IS NOT NULL AND a.id = ANY($1))
    OR ($1::bigint[] IS NULL
      AND ($2::text IS NULL OR a.platform = $2)
      AND ($3::text IS NULL OR a.type = $3)
      AND (
        $4::text IS NULL
        OR ($4 = 'active' AND a.status = 'active' AND a.schedulable = TRUE
            AND (a.rate_limit_reset_at IS NULL OR a.rate_limit_reset_at <= NOW())
            AND (a.temp_unschedulable_until IS NULL OR a.temp_unschedulable_until <= NOW()))
        OR ($4 = 'rate_limited' AND a.status = 'active' AND a.rate_limit_reset_at > NOW()
            AND (a.temp_unschedulable_until IS NULL OR a.temp_unschedulable_until <= NOW()))
        OR ($4 = 'temp_unschedulable' AND a.status = 'active'
            AND a.temp_unschedulable_until > NOW())
        OR ($4 = 'unschedulable' AND a.status = 'active' AND a.schedulable = FALSE
            AND (a.rate_limit_reset_at IS NULL OR a.rate_limit_reset_at <= NOW())
            AND (a.temp_unschedulable_until IS NULL OR a.temp_unschedulable_until <= NOW()))
        OR ($4 NOT IN ('active','rate_limited','temp_unschedulable','unschedulable')
            AND a.status = $4)
      )
      AND ($5::text IS NULL OR a.name ILIKE '%' || $5 || '%')
      AND ($6::bigint IS NULL OR EXISTS (
        SELECT 1 FROM account_groups ag WHERE ag.account_id = a.id AND ag.group_id = $6
      ))
      AND ($7::boolean = FALSE OR NOT EXISTS (
        SELECT 1 FROM account_groups ag WHERE ag.account_id = a.id
      ))
      AND (
        $8::text IS NULL
        OR ($8 = '__unset__' AND COALESCE(a.extra->>'privacy_mode', '') = '')
        OR ($8 <> '__unset__' AND a.extra->>'privacy_mode' = $8)
      )
    )
  )
ORDER BY {sort_column} {sort_order}, a.id {sort_order}
"
    );
    let rows = sqlx::query(&sql)
        .bind(selected_ids.as_deref())
        .bind(platform.as_deref())
        .bind(account_type.as_deref())
        .bind(status.as_deref())
        .bind(search.as_deref())
        .bind(group_id)
        .bind(ungrouped)
        .bind(privacy.as_deref())
        .fetch_all(pool)
        .await?;

    let skipped_shadows = rows
        .iter()
        .filter(|row| {
            row.try_get::<Option<i64>, _>("parent_account_id")
                .ok()
                .flatten()
                .is_some()
        })
        .count();
    let rows = rows
        .into_iter()
        .filter(|row| {
            row.try_get::<Option<i64>, _>("parent_account_id")
                .ok()
                .flatten()
                .is_none()
        })
        .collect::<Vec<_>>();
    let include_proxies = parse_include_proxies(query)?;
    let proxy_ids = if include_proxies {
        rows.iter()
            .filter_map(|row| row.try_get::<Option<i64>, _>("proxy_id").ok().flatten())
            .collect::<BTreeSet<_>>()
    } else {
        BTreeSet::new()
    };
    let proxy_rows = load_export_proxies(pool, proxy_ids.into_iter().collect()).await?;
    let proxy_keys = proxy_rows
        .iter()
        .map(|row| Ok((row.try_get::<i64, _>("id")?, proxy_key_from_row(row)?)))
        .collect::<Result<BTreeMap<_, _>, AdminError>>()?;
    let proxies = export_proxy_values(&proxy_rows)?;
    let accounts = rows
        .iter()
        .map(|row| export_account_value(row, &proxy_keys))
        .collect::<Result<Vec<_>, _>>()?;

    let mut result = json!({
        "exported_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "proxies": proxies,
        "accounts": accounts,
    });
    if skipped_shadows > 0 {
        result["skipped_shadows"] = json!(skipped_shadows);
    }
    Ok(result)
}

async fn export_proxy_data(
    pool: &PgPool,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let ids = export_ids(query, "proxy")?;
    let selected_ids = (!ids.is_empty()).then_some(ids);
    let protocol = query_text(query, "protocol");
    let status = query_text(query, "status");
    let search =
        query_text(query, "search").map(|value| value.chars().take(100).collect::<String>());
    let sort_column = match query
        .get("sort_by")
        .map(|value| value.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("name") => "p.name",
        Some("protocol") => "p.protocol",
        Some("status") => "p.status",
        Some("created_at") => "p.created_at",
        Some("expiry") => "p.expires_at",
        Some("account_count") => {
            "(SELECT COUNT(*) FROM accounts a WHERE a.proxy_id=p.id AND a.deleted_at IS NULL)"
        }
        _ => "p.id",
    };
    let sort_order = export_sort_order(query, "DESC");
    let sql = format!(
        r"
SELECT p.id, p.name, p.protocol, p.host, p.port, p.username, p.password,
       p.status, EXTRACT(EPOCH FROM p.expires_at)::bigint AS expires_at,
       p.fallback_mode, p.backup_proxy_id, p.expiry_warn_days
FROM proxies p
WHERE p.deleted_at IS NULL
  AND (
    ($1::bigint[] IS NOT NULL AND p.id = ANY($1))
    OR ($1::bigint[] IS NULL
      AND ($2::text IS NULL OR p.protocol = $2)
      AND ($3::text IS NULL OR p.status = $3)
      AND ($4::text IS NULL OR p.name ILIKE '%' || $4 || '%')
    )
  )
ORDER BY {sort_column} {sort_order}, p.id {sort_order}
"
    );
    let rows = sqlx::query(&sql)
        .bind(selected_ids.as_deref())
        .bind(protocol.as_deref())
        .bind(status.as_deref())
        .bind(search.as_deref())
        .fetch_all(pool)
        .await?;
    Ok(json!({
        "exported_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "proxies": export_proxy_values(&rows)?,
        "accounts": [],
    }))
}

async fn load_export_proxies(
    pool: &PgPool,
    ids: Vec<i64>,
) -> Result<Vec<sqlx::postgres::PgRow>, AdminError> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query(
        r"
SELECT p.id, p.name, p.protocol, p.host, p.port, p.username, p.password,
       p.status, EXTRACT(EPOCH FROM p.expires_at)::bigint AS expires_at,
       p.fallback_mode, p.backup_proxy_id, p.expiry_warn_days
FROM proxies p WHERE p.id = ANY($1) AND p.deleted_at IS NULL ORDER BY p.id
",
    )
    .bind(ids)
    .fetch_all(pool)
    .await
    .map_err(AdminError::from)
}

fn export_account_value(
    row: &sqlx::postgres::PgRow,
    proxy_keys: &BTreeMap<i64, String>,
) -> Result<Value, AdminError> {
    let mut item = Map::new();
    item.insert("name".to_owned(), json!(row.try_get::<String, _>("name")?));
    if let Some(notes) = row.try_get::<Option<String>, _>("notes")? {
        item.insert("notes".to_owned(), json!(notes));
    }
    item.insert(
        "platform".to_owned(),
        json!(row.try_get::<String, _>("platform")?),
    );
    item.insert("type".to_owned(), json!(row.try_get::<String, _>("type")?));
    item.insert("credentials".to_owned(), row.try_get("credentials")?);
    let extra: Value = row.try_get("extra")?;
    if extra.as_object().is_some_and(|object| !object.is_empty()) {
        item.insert("extra".to_owned(), extra);
    }
    if let Some(proxy_id) = row.try_get::<Option<i64>, _>("proxy_id")?
        && let Some(proxy_key) = proxy_keys.get(&proxy_id)
    {
        item.insert("proxy_key".to_owned(), json!(proxy_key));
    }
    item.insert(
        "concurrency".to_owned(),
        json!(row.try_get::<i32, _>("concurrency")?),
    );
    item.insert(
        "priority".to_owned(),
        json!(row.try_get::<i32, _>("priority")?),
    );
    if let Some(multiplier) = row.try_get::<Option<f64>, _>("rate_multiplier")? {
        item.insert("rate_multiplier".to_owned(), json!(multiplier));
    }
    if let Some(expires_at) = row.try_get::<Option<i64>, _>("expires_at")? {
        item.insert("expires_at".to_owned(), json!(expires_at));
    }
    item.insert(
        "auto_pause_on_expired".to_owned(),
        json!(row.try_get::<bool, _>("auto_pause_on_expired")?),
    );
    Ok(Value::Object(item))
}

fn export_proxy_values(rows: &[sqlx::postgres::PgRow]) -> Result<Vec<Value>, AdminError> {
    let names = rows
        .iter()
        .map(|row| {
            Ok((
                row.try_get::<i64, _>("id")?,
                row.try_get::<String, _>("name")?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, AdminError>>()?;
    rows.iter()
        .map(|row| {
            let mut item = Map::new();
            item.insert("proxy_key".to_owned(), json!(proxy_key_from_row(row)?));
            item.insert("name".to_owned(), json!(row.try_get::<String, _>("name")?));
            item.insert(
                "protocol".to_owned(),
                json!(row.try_get::<String, _>("protocol")?),
            );
            item.insert("host".to_owned(), json!(row.try_get::<String, _>("host")?));
            item.insert("port".to_owned(), json!(row.try_get::<i32, _>("port")?));
            if let Some(username) = row
                .try_get::<Option<String>, _>("username")?
                .filter(|value| !value.is_empty())
            {
                item.insert("username".to_owned(), json!(username));
            }
            if let Some(password) = row
                .try_get::<Option<String>, _>("password")?
                .filter(|value| !value.is_empty())
            {
                item.insert("password".to_owned(), json!(password));
            }
            item.insert(
                "status".to_owned(),
                json!(row.try_get::<String, _>("status")?),
            );
            if let Some(expires_at) = row.try_get::<Option<i64>, _>("expires_at")? {
                item.insert("expires_at".to_owned(), json!(expires_at));
            }
            let fallback_mode: String = row.try_get("fallback_mode")?;
            if !fallback_mode.is_empty() {
                item.insert("fallback_mode".to_owned(), json!(fallback_mode));
            }
            if let Some(backup_id) = row.try_get::<Option<i64>, _>("backup_proxy_id")?
                && let Some(name) = names.get(&backup_id)
            {
                item.insert("backup_proxy_name".to_owned(), json!(name));
            }
            let warn_days: i32 = row.try_get("expiry_warn_days")?;
            if warn_days != 0 {
                item.insert("expiry_warn_days".to_owned(), json!(warn_days));
            }
            Ok(Value::Object(item))
        })
        .collect()
}

fn proxy_key_from_row(row: &sqlx::postgres::PgRow) -> Result<String, AdminError> {
    Ok(format!(
        "{}|{}|{}|{}|{}",
        row.try_get::<String, _>("protocol")?.trim(),
        row.try_get::<String, _>("host")?.trim(),
        row.try_get::<i32, _>("port")?,
        row.try_get::<Option<String>, _>("username")?
            .unwrap_or_default()
            .trim(),
        row.try_get::<Option<String>, _>("password")?
            .unwrap_or_default()
            .trim(),
    ))
}

fn export_ids(query: &BTreeMap<String, String>, resource: &str) -> Result<Vec<i64>, AdminError> {
    let Some(raw) = query.get("ids").filter(|value| !value.trim().is_empty()) else {
        return Ok(Vec::new());
    };
    raw.split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .parse::<i64>()
                .ok()
                .filter(|id| *id > 0)
                .ok_or_else(|| AdminError::BadRequest(format!("invalid {resource} id: {value}")))
        })
        .collect()
}

fn query_text(query: &BTreeMap<String, String>, key: &str) -> Option<String> {
    query
        .get(key)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn export_sort_order<'a>(query: &BTreeMap<String, String>, default: &'a str) -> &'a str {
    match query
        .get("sort_order")
        .map(|value| value.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("asc") => "ASC",
        Some("desc") => "DESC",
        _ => default,
    }
}

fn parse_include_proxies(query: &BTreeMap<String, String>) -> Result<bool, AdminError> {
    let Some(raw) = query.get("include_proxies") else {
        return Ok(true);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        value => Err(AdminError::BadRequest(format!(
            "invalid include_proxies value: {value}"
        ))),
    }
}

async fn import_account_data(pool: &PgPool, payload: &Value) -> Result<Value, AdminError> {
    let data = payload.get("data").unwrap_or(payload);
    validate_data_payload(data)?;
    let proxies = data
        .get("proxies")
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| AdminError::BadRequest("proxies is required".to_owned()))?;
    let accounts = data
        .get("accounts")
        .and_then(Value::as_array)
        .ok_or_else(|| AdminError::BadRequest("data.accounts must be an array".to_owned()))?;
    let proxy_result = import_proxy_items(pool, &proxies).await?;
    let skip_default_group_bind = payload
        .get("skip_default_group_bind")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let mut created = 0_u64;
    let mut failed = 0_u64;
    let mut errors = Vec::new();
    for account in accounts {
        let mut account = account.clone();
        if let Err(error) = validate_import_account(&account) {
            failed += 1;
            errors.push(json!({
                "kind": "account",
                "name": account.get("name"),
                "message": error.to_string(),
            }));
            continue;
        }
        if let Some(proxy_key) = account
            .get("proxy_key")
            .and_then(Value::as_str)
            .map(str::to_owned)
        {
            let Some(proxy_id) = proxy_result.ids_by_key.get(&proxy_key).copied() else {
                failed += 1;
                errors.push(json!({
                    "kind": "account",
                    "name": account.get("name"),
                    "proxy_key": proxy_key,
                    "message": "proxy_key not found",
                }));
                continue;
            };
            if let Some(object) = account.as_object_mut() {
                object.insert("proxy_id".to_owned(), json!(proxy_id));
            }
        }
        if !skip_default_group_bind
            && account
                .get("group_ids")
                .and_then(Value::as_array)
                .is_none_or(Vec::is_empty)
        {
            let platform = account
                .get("platform")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if let Some(group_id) = default_platform_group(pool, platform).await?
                && let Some(object) = account.as_object_mut()
            {
                object.insert("group_ids".to_owned(), json!([group_id]));
            }
        }
        match create_account(pool, &account).await {
            Ok(_) => created += 1,
            Err(error) => {
                failed += 1;
                errors.push(json!({
                    "kind": "account",
                    "name": account.get("name"),
                    "message": error.to_string(),
                }));
            }
        }
    }
    let mut all_errors = proxy_result.errors;
    all_errors.extend(errors);
    Ok(import_result_value(
        proxy_result.created,
        proxy_result.reused,
        proxy_result.failed,
        created,
        failed,
        all_errors,
    ))
}

async fn default_platform_group(pool: &PgPool, platform: &str) -> Result<Option<i64>, AdminError> {
    sqlx::query_scalar::<_, i64>(
        "SELECT id FROM groups WHERE platform=$1 AND name=$1 || '-default' AND status='active' AND deleted_at IS NULL ORDER BY id LIMIT 1",
    )
    .bind(platform)
    .fetch_optional(pool)
    .await
    .map_err(AdminError::from)
}

fn validate_data_payload(data: &Value) -> Result<(), AdminError> {
    let object = data
        .as_object()
        .ok_or_else(|| AdminError::BadRequest("data must be an object".to_owned()))?;
    if let Some(kind) = object.get("type").and_then(Value::as_str)
        && !kind.is_empty()
        && !matches!(kind, "sub2api-data" | "sub2api-bundle")
    {
        return Err(AdminError::BadRequest(format!(
            "unsupported data type: {kind}"
        )));
    }
    if let Some(version) = object.get("version").and_then(Value::as_i64)
        && !matches!(version, 0 | 1)
    {
        return Err(AdminError::BadRequest(format!(
            "unsupported data version: {version}"
        )));
    }
    if !object.get("proxies").is_some_and(Value::is_array) {
        return Err(AdminError::BadRequest("proxies is required".to_owned()));
    }
    if !object.get("accounts").is_some_and(Value::is_array) {
        return Err(AdminError::BadRequest("accounts is required".to_owned()));
    }
    Ok(())
}

fn validate_import_account(item: &Value) -> Result<(), AdminError> {
    required_string(item, "name")?;
    required_string(item, "platform")?;
    let account_type = required_string(item, "type")?;
    if !matches!(
        account_type.as_str(),
        "oauth" | "setup-token" | "apikey" | "upstream"
    ) {
        return Err(AdminError::BadRequest(format!(
            "account type is invalid: {account_type}"
        )));
    }
    let credentials = item
        .get("credentials")
        .and_then(Value::as_object)
        .filter(|credentials| !credentials.is_empty())
        .ok_or_else(|| AdminError::BadRequest("account credentials is required".to_owned()))?;
    let _ = credentials;
    if optional_i32(item, "concurrency")?.is_some_and(|value| value < 0) {
        return Err(AdminError::BadRequest(
            "concurrency must be >= 0".to_owned(),
        ));
    }
    if optional_i32(item, "priority")?.is_some_and(|value| value < 0) {
        return Err(AdminError::BadRequest("priority must be >= 0".to_owned()));
    }
    if item
        .get("rate_multiplier")
        .and_then(Value::as_f64)
        .is_some_and(|value| !value.is_finite() || value < 0.0)
    {
        return Err(AdminError::BadRequest(
            "rate_multiplier must be >= 0".to_owned(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn import_codex_sessions(pool: &PgPool, payload: &Value) -> Result<Value, AdminError> {
    let mut entries = payload
        .get("contents")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if let Some(content) = payload.get("content").and_then(Value::as_str)
        && !content.trim().is_empty()
    {
        entries.insert(0, content.to_owned());
    }
    if entries.is_empty() {
        return Err(AdminError::BadRequest(
            "content or contents must include a Codex session".to_owned(),
        ));
    }
    let mut expanded = Vec::new();
    for entry in entries {
        expanded.extend(expand_codex_input(&entry)?);
    }
    let entries = expanded;
    if entries.len() > 1_000 {
        return Err(AdminError::BadRequest(
            "at most 1000 Codex sessions may be imported".to_owned(),
        ));
    }
    let update_existing = payload
        .get("update_existing")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let mut created = 0_u64;
    let mut updated = 0_u64;
    let mut failed = 0_u64;
    let mut items = Vec::with_capacity(entries.len());
    for (index, raw) in entries.iter().enumerate() {
        let response_index = index + 1;
        let parsed = parse_codex_session(raw);
        let session = match parsed {
            Ok(value) => value,
            Err(error) => {
                failed += 1;
                items.push(
                    json!({ "index": response_index, "action": "failed", "message": error.to_string() }),
                );
                continue;
            }
        };
        let existing = find_codex_account(pool, &session).await?;
        if let Some(id) = existing
            && update_existing
        {
            let serialized = serde_json::to_string(&session.credentials).map_err(json_error)?;
            sqlx::query(
                "UPDATE accounts SET credentials=credentials || $2::jsonb, status='active', error_message=NULL, updated_at=NOW() WHERE id=$1",
            )
            .bind(id)
            .bind(serialized)
            .execute(pool)
            .await?;
            updated += 1;
            items.push(json!({ "index": response_index, "action": "updated", "account_id": id }));
            continue;
        }
        let mut item = payload.clone();
        let object = item
            .as_object_mut()
            .ok_or_else(|| AdminError::BadRequest("request body must be an object".to_owned()))?;
        object.insert("platform".to_owned(), json!("openai"));
        object.insert("type".to_owned(), json!("oauth"));
        object.insert("credentials".to_owned(), Value::Object(session.credentials));
        object.insert(
            "name".to_owned(),
            json!(codex_account_name(
                payload,
                &session.email,
                index,
                entries.len()
            )),
        );
        match create_account(pool, &item).await {
            Ok(id) => {
                created += 1;
                items.push(
                    json!({ "index": response_index, "action": "created", "account_id": id }),
                );
            }
            Err(error) => {
                failed += 1;
                items.push(
                    json!({ "index": response_index, "action": "failed", "message": error.to_string() }),
                );
            }
        }
    }
    Ok(json!({
        "total": entries.len(), "created": created, "updated": updated,
        "skipped": 0, "failed": failed, "items": items
    }))
}

fn expand_codex_input(raw: &str) -> Result<Vec<String>, AdminError> {
    fn flatten(value: Value, output: &mut Vec<String>) {
        match value {
            Value::Array(values) => {
                for value in values {
                    flatten(value, output);
                }
            }
            Value::String(value) => {
                if !value.trim().is_empty() {
                    output.push(value);
                }
            }
            value => output.push(value.to_string()),
        }
    }

    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    if raw.starts_with(['{', '[']) {
        let value = serde_json::from_str(raw)
            .map_err(|error| AdminError::BadRequest(format!("invalid Codex JSON: {error}")))?;
        let mut output = Vec::new();
        flatten(value, &mut output);
        return Ok(output);
    }
    let mut output = Vec::new();
    for line in raw.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if line.starts_with(['{', '[']) {
            let value = serde_json::from_str(line).map_err(|error| {
                AdminError::BadRequest(format!("invalid Codex JSON line: {error}"))
            })?;
            flatten(value, &mut output);
        } else {
            output.push(line.to_owned());
        }
    }
    Ok(output)
}

struct CodexSession {
    credentials: Map<String, Value>,
    email: String,
    account_id: String,
    user_id: String,
}

fn parse_codex_session(raw: &str) -> Result<CodexSession, AdminError> {
    let value = serde_json::from_str::<Value>(raw)
        .unwrap_or_else(|_| json!({ "access_token": raw.trim() }));
    let access_token = recursive_string(&value, &["access_token", "accessToken"])
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AdminError::BadRequest("Codex session has no access token".to_owned()))?;
    let refresh_token = recursive_string(&value, &["refresh_token", "refreshToken"]);
    let id_token = recursive_string(&value, &["id_token", "idToken"]);
    let claims = id_token
        .as_deref()
        .or(Some(access_token.as_str()))
        .and_then(jwt_claims)
        .unwrap_or(Value::Null);
    let auth = claims
        .get("https://api.openai.com/auth")
        .cloned()
        .unwrap_or(Value::Null);
    let email = claims
        .get("email")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| recursive_string(&value, &["email"]))
        .unwrap_or_default();
    let account_id = auth
        .get("chatgpt_account_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| recursive_string(&value, &["chatgpt_account_id", "account_id"]))
        .unwrap_or_default();
    let user_id = auth
        .get("chatgpt_user_id")
        .or_else(|| auth.get("user_id"))
        .and_then(Value::as_str)
        .or_else(|| claims.get("sub").and_then(Value::as_str))
        .unwrap_or_default()
        .to_owned();
    let mut credentials = Map::from_iter([
        ("access_token".to_owned(), json!(access_token)),
        ("auth_mode".to_owned(), json!("oauth")),
        ("oauth_mode".to_owned(), json!("oauth")),
    ]);
    if let Some(value) = refresh_token {
        credentials.insert("refresh_token".to_owned(), json!(value));
    }
    if let Some(value) = id_token {
        credentials.insert("id_token".to_owned(), json!(value));
    }
    if !email.is_empty() {
        credentials.insert("email".to_owned(), json!(email));
    }
    if !account_id.is_empty() {
        credentials.insert("chatgpt_account_id".to_owned(), json!(account_id));
    }
    if !user_id.is_empty() {
        credentials.insert("chatgpt_user_id".to_owned(), json!(user_id));
    }
    Ok(CodexSession {
        credentials,
        email,
        account_id,
        user_id,
    })
}

fn recursive_string(value: &Value, keys: &[&str]) -> Option<String> {
    match value {
        Value::Object(object) => {
            for key in keys {
                if let Some(value) = object.get(*key).and_then(Value::as_str) {
                    return Some(value.trim().to_owned());
                }
            }
            object
                .values()
                .find_map(|value| recursive_string(value, keys))
        }
        Value::Array(items) => items.iter().find_map(|value| recursive_string(value, keys)),
        _ => None,
    }
}

fn jwt_claims(token: &str) -> Option<Value> {
    let encoded = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    serde_json::from_slice(&bytes).ok()
}

async fn find_codex_account(
    pool: &PgPool,
    session: &CodexSession,
) -> Result<Option<i64>, AdminError> {
    if session.account_id.is_empty() && session.user_id.is_empty() && session.email.is_empty() {
        return Ok(None);
    }
    sqlx::query_scalar::<_, i64>(
        "SELECT id FROM accounts WHERE platform='openai' AND type='oauth' AND deleted_at IS NULL AND (($1<>'' AND credentials->>'chatgpt_account_id'=$1) OR ($2<>'' AND credentials->>'chatgpt_user_id'=$2) OR ($3<>'' AND lower(credentials->>'email')=lower($3))) ORDER BY id LIMIT 1",
    )
    .bind(&session.account_id)
    .bind(&session.user_id)
    .bind(&session.email)
    .fetch_optional(pool)
    .await
    .map_err(AdminError::from)
}

fn codex_account_name(payload: &Value, email: &str, index: usize, total: usize) -> String {
    let base = payload
        .get("name")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(if email.is_empty() {
            "Codex Account"
        } else {
            email
        });
    if total == 1 {
        base.to_owned()
    } else {
        format!("{base} {}", index + 1)
    }
}

#[allow(clippy::too_many_lines)]
async fn sync_from_crs(pool: &PgPool, payload: &Value, preview: bool) -> Result<Value, AdminError> {
    let base_url = required_string(payload, "base_url")?;
    let username = required_string(payload, "username")?;
    let password = required_string(payload, "password")?;
    let login_url = format!("{}/web/auth/login", base_url.trim_end_matches('/'));
    let login = post_public_json(
        &login_url,
        json!({ "username": username, "password": password }),
        None,
    )
    .await?;
    let token = login
        .get("success")
        .and_then(Value::as_bool)
        .filter(|success| *success)
        .and_then(|_| login.get("token"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AdminError::Probe("CRS login response has no token".to_owned()))?;
    let export_url = format!(
        "{}/admin/sync/export-accounts?include_secrets=true",
        base_url.trim_end_matches('/')
    );
    let exported = get_public_json(&export_url, Some(token)).await?;
    if exported.get("success").and_then(Value::as_bool) == Some(false) {
        return Err(AdminError::Probe(
            exported
                .get("message")
                .or_else(|| exported.get("error"))
                .and_then(Value::as_str)
                .unwrap_or("CRS export failed")
                .to_owned(),
        ));
    }
    let data = exported.get("data").unwrap_or(&exported);
    let collections = [
        ("claudeAccounts", "anthropic", "oauth"),
        ("claudeConsoleAccounts", "anthropic", "apikey"),
        ("openaiOAuthAccounts", "openai", "oauth"),
        ("openaiResponsesAccounts", "openai", "apikey"),
        ("geminiOAuthAccounts", "gemini", "oauth"),
        ("geminiApiKeyAccounts", "gemini", "apikey"),
    ];
    let selected = payload
        .get("selected_account_ids")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let mut items = Vec::new();
    let mut created = 0_u64;
    let mut updated = 0_u64;
    let mut skipped = 0_u64;
    let mut failed = 0_u64;
    for (key, platform, default_type) in collections {
        for source in data
            .get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let crs_id = source.get("id").and_then(Value::as_str).unwrap_or_default();
            let name = source.get("name").and_then(Value::as_str).unwrap_or(crs_id);
            if !selected.is_empty() && !selected.contains(crs_id) {
                skipped += 1;
                items.push(json!({ "crs_account_id": crs_id, "kind": key, "name": name, "action": "skipped" }));
                continue;
            }
            if preview {
                items.push(json!({
                    "crs_account_id": crs_id, "kind": key, "name": name,
                    "platform": platform, "type": default_type,
                    "action": "preview"
                }));
                continue;
            }
            let credentials = source
                .get("credentials")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            if credentials.is_empty() {
                failed += 1;
                items.push(json!({ "crs_account_id": crs_id, "kind": key, "name": name, "action": "failed", "error": "missing credentials" }));
                continue;
            }
            let proxy_id = if payload
                .get("sync_proxies")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                crs_proxy_id(pool, source.get("proxy"), name).await?
            } else {
                None
            };
            let existing = sqlx::query_scalar::<_, i64>(
                "SELECT id FROM accounts WHERE extra->>'crs_account_id'=$1 AND deleted_at IS NULL ORDER BY id LIMIT 1",
            )
            .bind(crs_id)
            .fetch_optional(pool)
            .await?;
            let extra = json!({
                "crs_account_id": crs_id,
                "crs_kind": key,
                "crs_synced_at": chrono::Utc::now().to_rfc3339(),
            });
            if let Some(id) = existing {
                let target_type = source
                    .get("authType")
                    .and_then(Value::as_str)
                    .unwrap_or(default_type);
                let has_shadows = sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS(SELECT 1 FROM accounts WHERE parent_account_id=$1 AND deleted_at IS NULL)",
                )
                .bind(id)
                .fetch_one(pool)
                .await?;
                if has_shadows && (platform != "openai" || target_type != "oauth") {
                    failed += 1;
                    items.push(json!({
                        "crs_account_id": crs_id, "kind": key, "name": name,
                        "action": "failed",
                        "error": "cannot change an OpenAI OAuth parent while credential shadows exist"
                    }));
                    continue;
                }
                sqlx::query(
                    "UPDATE accounts SET name=$2, platform=$3, type=$4, credentials=credentials || $5::jsonb, extra=extra || $6::jsonb, status=CASE WHEN $7 THEN 'active' ELSE 'inactive' END, schedulable=$8, priority=$9, proxy_id=COALESCE($10,proxy_id), updated_at=NOW() WHERE id=$1",
                )
                .bind(id)
                .bind(name)
                .bind(platform)
                .bind(target_type)
                .bind(serde_json::to_string(&credentials).map_err(json_error)?)
                .bind(serde_json::to_string(&extra).map_err(json_error)?)
                .bind(source.get("isActive").and_then(Value::as_bool).unwrap_or(true))
                .bind(source.get("schedulable").and_then(Value::as_bool).unwrap_or(true))
                .bind(clamp_priority(source.get("priority").and_then(Value::as_i64)))
                .bind(proxy_id)
                .execute(pool)
                .await?;
                updated += 1;
                items.push(json!({ "crs_account_id": crs_id, "kind": key, "name": name, "action": "updated" }));
            } else {
                let item = json!({
                    "name": if name.is_empty() { crs_id } else { name },
                    "platform": platform,
                    "type": source.get("authType").and_then(Value::as_str).unwrap_or(default_type),
                    "credentials": credentials,
                    "extra": extra,
                    "concurrency": source.get("maxConcurrentTasks").and_then(Value::as_i64).unwrap_or(3),
                    "priority": clamp_priority(source.get("priority").and_then(Value::as_i64)),
                    "proxy_id": proxy_id,
                    "status": if source.get("isActive").and_then(Value::as_bool).unwrap_or(true) { "active" } else { "inactive" },
                    "schedulable": source.get("schedulable").and_then(Value::as_bool).unwrap_or(true),
                });
                match create_account(pool, &item).await {
                    Ok(_) => {
                        created += 1;
                        items.push(json!({ "crs_account_id": crs_id, "kind": key, "name": name, "action": "created" }));
                    }
                    Err(error) => {
                        failed += 1;
                        items.push(json!({ "crs_account_id": crs_id, "kind": key, "name": name, "action": "failed", "error": error.to_string() }));
                    }
                }
            }
        }
    }
    if preview {
        Ok(json!({ "items": items, "total": items.len() }))
    } else {
        Ok(json!({
            "created": created, "updated": updated, "skipped": skipped,
            "failed": failed, "items": items
        }))
    }
}

async fn crs_proxy_id(
    pool: &PgPool,
    source: Option<&Value>,
    account_name: &str,
) -> Result<Option<i64>, AdminError> {
    let Some(source) = source.and_then(Value::as_object) else {
        return Ok(None);
    };
    let protocol = source
        .get("protocol")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_lowercase();
    let protocol = match protocol.as_str() {
        "socks" | "socks5h" => "socks5",
        "http" | "https" | "socks5" => protocol.as_str(),
        _ => return Ok(None),
    };
    let host = source
        .get("host")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    let port = source.get("port").and_then(Value::as_i64).unwrap_or(0);
    if host.is_empty() || !(1..=65_535).contains(&port) {
        return Ok(None);
    }
    let mut proxy = source.clone();
    proxy.insert("protocol".to_owned(), json!(protocol));
    proxy.insert("host".to_owned(), json!(host));
    proxy.insert("port".to_owned(), json!(port));
    proxy.insert("name".to_owned(), json!(format!("crs-{account_name}")));
    let (_, id) = create_or_reuse_proxy(pool, &Value::Object(proxy)).await?;
    Ok(Some(id))
}

async fn post_public_json(
    url: &str,
    payload: Value,
    bearer: Option<&str>,
) -> Result<Value, AdminError> {
    let client = public_client(url).await?;
    let mut request = client.post(url).json(&payload);
    if let Some(token) = bearer {
        request = request.bearer_auth(token);
    }
    checked_json_response(request.send().await, "remote POST").await
}

async fn get_public_json(url: &str, bearer: Option<&str>) -> Result<Value, AdminError> {
    let client = public_client(url).await?;
    let mut request = client.get(url);
    if let Some(token) = bearer {
        request = request.bearer_auth(token);
    }
    checked_json_response(request.send().await, "remote GET").await
}

async fn public_client(url: &str) -> Result<Client, AdminError> {
    let validated = validate_public_probe_target(url).await?;
    let parsed = Url::parse(validated.url())
        .map_err(|_| AdminError::BadRequest("remote URL is invalid".to_owned()))?;
    let mut builder = Client::builder()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(20));
    if let Some(host) = parsed.host_str() {
        for address in validated.resolved_addresses() {
            builder = builder.resolve(host, *address);
        }
    }
    builder
        .build()
        .map_err(|error| AdminError::Probe(format!("cannot create remote client: {error}")))
}

async fn checked_json_response(
    response: Result<reqwest::Response, reqwest::Error>,
    operation: &str,
) -> Result<Value, AdminError> {
    let response =
        response.map_err(|error| AdminError::Probe(format!("{operation} failed: {error}")))?;
    let status = response.status();
    let value = response.json::<Value>().await.map_err(|error| {
        AdminError::Probe(format!("{operation} returned invalid JSON: {error}"))
    })?;
    if !status.is_success() {
        return Err(AdminError::Probe(format!(
            "{operation} returned HTTP {}",
            status.as_u16()
        )));
    }
    Ok(value)
}

async fn proxy_accounts(pool: &PgPool, id: i64) -> Result<Value, AdminError> {
    ensure_proxy(pool, id).await?;
    let sql = format!(
        "SELECT COALESCE(jsonb_agg({} ORDER BY row.id), '[]'::jsonb) FROM accounts row WHERE row.proxy_id=$1 AND row.deleted_at IS NULL",
        redacted_json("row")
    );
    sqlx::query_scalar::<_, Value>(&sql)
        .bind(id)
        .fetch_one(pool)
        .await
        .map_err(AdminError::from)
}

async fn proxy_stats(pool: &PgPool, id: i64) -> Result<Value, AdminError> {
    ensure_proxy(pool, id).await?;
    let accounts = sqlx::query(
        "SELECT COUNT(*)::bigint AS total, COUNT(*) FILTER (WHERE status='active' AND schedulable)::bigint AS active FROM accounts WHERE proxy_id=$1 AND deleted_at IS NULL",
    )
    .bind(id)
    .fetch_one(pool)
    .await?;
    let usage = sqlx::query(
        "SELECT COUNT(*)::bigint AS requests, COALESCE(AVG(duration_ms),0)::double precision AS latency FROM usage_logs WHERE account_id IN (SELECT id FROM accounts WHERE proxy_id=$1 AND deleted_at IS NULL)",
    )
    .bind(id)
    .fetch_one(pool)
    .await?;
    let requests: i64 = usage.try_get("requests")?;
    let failures = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM ops_error_logs WHERE account_id IN (SELECT id FROM accounts WHERE proxy_id=$1 AND deleted_at IS NULL)",
    )
    .bind(id)
    .fetch_one(pool)
    .await?;
    let successes = requests.saturating_sub(failures);
    let success_rate = if requests == 0 {
        100.0
    } else {
        let successes = i32::try_from(successes).unwrap_or(i32::MAX);
        let requests = i32::try_from(requests).unwrap_or(i32::MAX);
        f64::from(successes) * 100.0 / f64::from(requests)
    };
    Ok(json!({
        "total_accounts": accounts.try_get::<i64,_>("total")?,
        "active_accounts": accounts.try_get::<i64,_>("active")?,
        "total_requests": requests,
        "success_rate": success_rate,
        "average_latency": usage.try_get::<f64,_>("latency")?,
    }))
}

async fn batch_create_proxies(pool: &PgPool, payload: &Value) -> Result<Value, AdminError> {
    let items = payload
        .get("proxies")
        .and_then(Value::as_array)
        .ok_or_else(|| AdminError::BadRequest("proxies must be a non-empty array".to_owned()))?;
    if items.is_empty() || items.len() > 1_000 {
        return Err(AdminError::BadRequest(
            "proxies must contain between 1 and 1000 items".to_owned(),
        ));
    }
    let result = import_proxy_items(pool, items).await?;
    Ok(
        json!({ "created": result.created, "skipped": result.reused, "failed": result.failed, "errors": result.errors }),
    )
}

async fn batch_delete_proxies(pool: &PgPool, payload: &Value) -> Result<Value, AdminError> {
    let ids = positive_id_array(payload.get("ids"), "ids")?;
    if ids.is_empty() || ids.len() > 1_000 {
        return Err(AdminError::BadRequest(
            "ids must contain between 1 and 1000 proxy IDs".to_owned(),
        ));
    }
    let mut transaction = pool.begin().await?;
    let mut deleted_ids = Vec::new();
    let mut skipped = Vec::new();
    for id in ids {
        let account_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM accounts WHERE proxy_id=$1 AND deleted_at IS NULL",
        )
        .bind(id)
        .fetch_one(&mut *transaction)
        .await?;
        if account_count > 0 {
            skipped
                .push(json!({ "id": id, "reason": "proxy is still used by one or more accounts" }));
            continue;
        }
        let update = sqlx::query(
            "UPDATE proxies SET deleted_at=NOW(), updated_at=NOW() WHERE id=$1 AND deleted_at IS NULL",
        )
        .bind(id)
        .execute(&mut *transaction)
        .await?;
        if update.rows_affected() == 1 {
            deleted_ids.push(id);
        } else {
            skipped.push(json!({ "id": id, "reason": "proxy not found" }));
        }
    }
    transaction.commit().await?;
    Ok(json!({ "deleted_ids": deleted_ids, "skipped": skipped }))
}

async fn import_proxy_data(pool: &PgPool, payload: &Value) -> Result<Value, AdminError> {
    let data = payload.get("data").unwrap_or(payload);
    validate_data_payload(data)?;
    let items = data
        .get("proxies")
        .and_then(Value::as_array)
        .ok_or_else(|| AdminError::BadRequest("data.proxies must be an array".to_owned()))?;
    let result = import_proxy_items(pool, items).await?;
    Ok(import_result_value(
        result.created,
        result.reused,
        result.failed,
        0,
        0,
        result.errors,
    ))
}

fn import_result_value(
    proxy_created: u64,
    proxy_reused: u64,
    proxy_failed: u64,
    account_created: u64,
    account_failed: u64,
    errors: Vec<Value>,
) -> Value {
    let mut result = json!({
        "proxy_created": proxy_created,
        "proxy_reused": proxy_reused,
        "proxy_failed": proxy_failed,
        "account_created": account_created,
        "account_failed": account_failed,
    });
    if !errors.is_empty() {
        result["errors"] = Value::Array(errors);
    }
    result
}

struct ProxyImportResult {
    created: u64,
    reused: u64,
    failed: u64,
    errors: Vec<Value>,
    ids_by_key: BTreeMap<String, i64>,
}

#[allow(clippy::too_many_lines)]
async fn import_proxy_items(
    pool: &PgPool,
    items: &[Value],
) -> Result<ProxyImportResult, AdminError> {
    let mut result = ProxyImportResult {
        created: 0,
        reused: 0,
        failed: 0,
        errors: Vec::new(),
        ids_by_key: BTreeMap::new(),
    };
    let existing = sqlx::query(
        "SELECT id,name,protocol,host,port,username,password,status FROM proxies WHERE deleted_at IS NULL ORDER BY id",
    )
    .fetch_all(pool)
    .await?;
    let mut names = BTreeMap::new();
    let mut statuses = BTreeMap::new();
    for row in &existing {
        let id: i64 = row.try_get("id")?;
        let key = format!(
            "{}|{}|{}|{}|{}",
            row.try_get::<String, _>("protocol")?.trim(),
            row.try_get::<String, _>("host")?.trim(),
            row.try_get::<i32, _>("port")?,
            row.try_get::<Option<String>, _>("username")?
                .unwrap_or_default()
                .trim(),
            row.try_get::<Option<String>, _>("password")?
                .unwrap_or_default()
                .trim(),
        );
        result.ids_by_key.insert(key, id);
        let name: String = row.try_get("name")?;
        if !name.is_empty() {
            names.insert(name, id);
        }
        statuses.insert(id, row.try_get::<String, _>("status")?);
    }
    for item in items {
        let key = match proxy_key(item) {
            Ok(key) => key,
            Err(error) => {
                result.failed += 1;
                result.errors.push(json!({
                    "kind": "proxy",
                    "name": item.get("name"),
                    "message": error.to_string(),
                }));
                continue;
            }
        };
        let normalized_status = match normalize_import_proxy_status(
            item.get("status")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ) {
            Ok(status) => status,
            Err(error) => {
                result.failed += 1;
                result.errors.push(json!({
                    "kind": "proxy", "name": item.get("name"),
                    "proxy_key": key, "message": error.to_string(),
                }));
                continue;
            }
        };
        if let Some(id) = result.ids_by_key.get(&key).copied() {
            result.reused += 1;
            if !normalized_status.is_empty()
                && statuses
                    .get(&id)
                    .is_some_and(|status| status != &normalized_status)
            {
                sqlx::query("UPDATE proxies SET status=$2,updated_at=NOW() WHERE id=$1")
                    .bind(id)
                    .bind(&normalized_status)
                    .execute(pool)
                    .await?;
                statuses.insert(id, normalized_status);
            }
            continue;
        }
        let mut normalized = item.clone();
        let Some(object) = normalized.as_object_mut() else {
            result.failed += 1;
            result.errors.push(json!({
                "kind": "proxy", "proxy_key": key,
                "message": "proxy must be an object",
            }));
            continue;
        };
        if object
            .get("name")
            .and_then(Value::as_str)
            .is_none_or(|name| name.trim().is_empty())
        {
            object.insert("name".to_owned(), json!("imported-proxy"));
        }
        object.insert(
            "status".to_owned(),
            json!(if normalized_status.is_empty() {
                "active"
            } else {
                normalized_status.as_str()
            }),
        );
        let backup_name = object
            .get("backup_proxy_name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_owned);
        if let Some(backup_name) = backup_name {
            if let Some(backup_id) = names.get(&backup_name).copied() {
                object.insert("backup_proxy_id".to_owned(), json!(backup_id));
            } else {
                object.insert("fallback_mode".to_owned(), json!("none"));
                result.errors.push(json!({
                    "kind": "proxy", "name": object.get("name"),
                    "proxy_key": key,
                    "message": format!("backup_proxy_name {backup_name:?} not found, fallback_mode downgraded to none"),
                }));
            }
        }
        match create_or_reuse_proxy(pool, &normalized).await {
            Ok((true, id)) => {
                result.created += 1;
                result.ids_by_key.insert(key, id);
                if let Some(name) = normalized
                    .get("name")
                    .and_then(Value::as_str)
                    .filter(|name| !name.is_empty())
                {
                    names.insert(name.to_owned(), id);
                }
            }
            Ok((false, id)) => {
                result.reused += 1;
                result.ids_by_key.insert(key, id);
            }
            Err(error) => {
                result.failed += 1;
                result.errors.push(json!({
                    "kind": "proxy",
                    "name": item.get("name"),
                    "proxy_key": key,
                    "message": error.to_string(),
                }));
            }
        }
    }
    Ok(result)
}

fn normalize_import_proxy_status(status: &str) -> Result<String, AdminError> {
    match status.trim().to_ascii_lowercase().as_str() {
        "" => Ok(String::new()),
        "active" => Ok("active".to_owned()),
        "inactive" | "disabled" | "expired" => Ok("inactive".to_owned()),
        value => Err(AdminError::BadRequest(format!(
            "proxy status is invalid: {value}"
        ))),
    }
}

async fn create_or_reuse_proxy(pool: &PgPool, item: &Value) -> Result<(bool, i64), AdminError> {
    let protocol = required_string(item, "protocol")?.to_lowercase();
    if !matches!(protocol.as_str(), "http" | "https" | "socks5" | "socks5h") {
        return Err(AdminError::BadRequest(
            "proxy protocol is invalid".to_owned(),
        ));
    }
    let host = required_string(item, "host")?;
    let port = optional_i32(item, "port")?
        .filter(|value| (1..=65_535).contains(value))
        .ok_or_else(|| AdminError::BadRequest("proxy port is invalid".to_owned()))?;
    let username = item
        .get("username")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    let password = item
        .get("password")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    let existing_id = sqlx::query_scalar::<_, i64>(
        "SELECT id FROM proxies WHERE deleted_at IS NULL AND protocol=$1 AND host=$2 AND port=$3 AND COALESCE(username,'')=$4 AND COALESCE(password,'')=$5 ORDER BY id LIMIT 1",
    )
    .bind(&protocol)
    .bind(host.trim())
    .bind(port)
    .bind(username)
    .bind(password)
    .fetch_optional(pool)
    .await?;
    if let Some(id) = existing_id {
        return Ok((false, id));
    }
    let fallback_mode = item
        .get("fallback_mode")
        .and_then(Value::as_str)
        .unwrap_or("none");
    if !matches!(fallback_mode, "none" | "direct" | "proxy") {
        return Err(AdminError::BadRequest(
            "proxy fallback mode is invalid".to_owned(),
        ));
    }
    let status = normalize_import_proxy_status(
        item.get("status")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    )?;
    let id = sqlx::query_scalar::<_, i64>(
        "INSERT INTO proxies (name,protocol,host,port,username,password,status,expires_at,fallback_mode,backup_proxy_id,expiry_warn_days) VALUES ($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),$7,CASE WHEN $8::bigint IS NULL THEN NULL ELSE to_timestamp($8) END,$9,$10,$11) RETURNING id",
    )
    .bind(item.get("name").and_then(Value::as_str).unwrap_or("imported-proxy"))
    .bind(protocol)
    .bind(host.trim())
    .bind(port)
    .bind(username)
    .bind(password)
    .bind(if status.is_empty() { "active" } else { &status })
    .bind(optional_i64(item, "expires_at")?)
    .bind(fallback_mode)
    .bind(optional_i64(item, "backup_proxy_id")?)
    .bind(optional_i32(item, "expiry_warn_days")?.unwrap_or(7))
    .fetch_one(pool)
    .await?;
    Ok((true, id))
}

fn proxy_key(item: &Value) -> Result<String, AdminError> {
    if let Some(key) = item
        .get("proxy_key")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        return Ok(key.to_owned());
    }
    let protocol = required_string(item, "protocol")?;
    let host = required_string(item, "host")?;
    let port = optional_i32(item, "port")?
        .ok_or_else(|| AdminError::BadRequest("proxy port is required".to_owned()))?;
    let username = item
        .get("username")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    let password = item
        .get("password")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    Ok(format!(
        "{}|{}|{port}|{username}|{password}",
        protocol.trim(),
        host.trim()
    ))
}

async fn ensure_proxy(pool: &PgPool, id: i64) -> Result<(), AdminError> {
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM proxies WHERE id=$1 AND deleted_at IS NULL)",
    )
    .bind(id)
    .fetch_one(pool)
    .await?;
    if exists {
        Ok(())
    } else {
        Err(AdminError::NotFound("proxy"))
    }
}

async fn validate_proxy(
    transaction: &mut Transaction<'_, Postgres>,
    id: Option<i64>,
) -> Result<(), AdminError> {
    let Some(id) = id else { return Ok(()) };
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM proxies WHERE id=$1 AND deleted_at IS NULL)",
    )
    .bind(id)
    .fetch_one(&mut **transaction)
    .await?;
    if exists {
        Ok(())
    } else {
        Err(AdminError::BadRequest("proxy_id does not exist".to_owned()))
    }
}

async fn validate_groups(
    transaction: &mut Transaction<'_, Postgres>,
    ids: &[i64],
) -> Result<(), AdminError> {
    if ids.is_empty() {
        return Ok(());
    }
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM groups WHERE id=ANY($1) AND deleted_at IS NULL",
    )
    .bind(ids)
    .fetch_one(&mut **transaction)
    .await?;
    if usize::try_from(count).ok() == Some(ids.len()) {
        Ok(())
    } else {
        Err(AdminError::BadRequest(
            "one or more group_ids do not exist".to_owned(),
        ))
    }
}

async fn replace_account_groups(
    transaction: &mut Transaction<'_, Postgres>,
    account_id: i64,
    groups: &[i64],
    priority: i32,
) -> Result<(), AdminError> {
    sqlx::query("DELETE FROM account_groups WHERE account_id=$1")
        .bind(account_id)
        .execute(&mut **transaction)
        .await?;
    if !groups.is_empty() {
        sqlx::query(
            "INSERT INTO account_groups (account_id,group_id,priority) SELECT $1,id,$3 FROM unnest($2::bigint[]) id",
        )
        .bind(account_id)
        .bind(groups)
        .bind(priority)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

async fn load_proxy_url(pool: &PgPool, id: Option<i64>) -> Result<Option<String>, AdminError> {
    let Some(id) = id else { return Ok(None) };
    let row = sqlx::query(
        "SELECT protocol,host,port,username,password FROM proxies WHERE id=$1 AND deleted_at IS NULL AND status='active'",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AdminError::BadRequest("account proxy is unavailable".to_owned()))?;
    let protocol: String = row.try_get("protocol")?;
    let host: String = row.try_get("host")?;
    let port: i32 = row.try_get("port")?;
    let mut url = Url::parse(&format!("{protocol}://{host}:{port}"))
        .map_err(|_| AdminError::BadRequest("proxy URL is invalid".to_owned()))?;
    if let Some(username) = row
        .try_get::<Option<String>, _>("username")?
        .filter(|v| !v.is_empty())
    {
        url.set_username(&username)
            .map_err(|()| AdminError::BadRequest("proxy username is invalid".to_owned()))?;
        if let Some(password) = row.try_get::<Option<String>, _>("password")? {
            url.set_password(Some(&password))
                .map_err(|()| AdminError::BadRequest("proxy password is invalid".to_owned()))?;
        }
    }
    Ok(Some(url.into()))
}

fn required_string(payload: &Value, key: &str) -> Result<String, AdminError> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| AdminError::BadRequest(format!("{key} is required")))
}

fn optional_i64(payload: &Value, key: &str) -> Result<Option<i64>, AdminError> {
    match payload.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_i64()
            .filter(|value| *value > 0)
            .map(Some)
            .ok_or_else(|| AdminError::BadRequest(format!("{key} must be a positive integer"))),
    }
}

fn optional_i32(payload: &Value, key: &str) -> Result<Option<i32>, AdminError> {
    match payload.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => i32::try_from(
            value
                .as_i64()
                .ok_or_else(|| AdminError::BadRequest(format!("{key} must be an integer")))?,
        )
        .map(Some)
        .map_err(|_| AdminError::BadRequest(format!("{key} is out of range"))),
    }
}

fn positive_id_array(value: Option<&Value>, key: &str) -> Result<Vec<i64>, AdminError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| AdminError::BadRequest(format!("{key} must be an array")))?;
    let mut ids = BTreeSet::new();
    for value in values {
        let id = value
            .as_i64()
            .filter(|id| *id > 0)
            .ok_or_else(|| AdminError::BadRequest(format!("{key} contains an invalid ID")))?;
        ids.insert(id);
    }
    Ok(ids.into_iter().collect())
}

fn optional_nonempty_string(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<String>, AdminError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => {
            Ok((!value.trim().is_empty()).then(|| value.trim().to_owned()))
        }
        Some(_) => Err(AdminError::BadRequest(format!("{key} must be a string"))),
    }
}

fn optional_i64_from_map(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<i64>, AdminError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_i64()
            .filter(|id| *id > 0)
            .map(Some)
            .ok_or_else(|| AdminError::BadRequest(format!("{key} must be a positive integer"))),
    }
}

fn optional_i32_from_map(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<i32>, AdminError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => i32::try_from(
            value
                .as_i64()
                .ok_or_else(|| AdminError::BadRequest(format!("{key} must be an integer")))?,
        )
        .map(Some)
        .map_err(|_| AdminError::BadRequest(format!("{key} is out of range"))),
    }
}

fn optional_f64_from_map(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<f64>, AdminError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_f64()
            .map(Some)
            .ok_or_else(|| AdminError::BadRequest(format!("{key} must be a number"))),
    }
}

fn optional_bool_from_map(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<bool>, AdminError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_bool()
            .map(Some)
            .ok_or_else(|| AdminError::BadRequest(format!("{key} must be boolean"))),
    }
}

fn optional_object_json(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<String>, AdminError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(value)) => serde_json::to_string(value).map(Some).map_err(json_error),
        Some(_) => Err(AdminError::BadRequest(format!("{key} must be an object"))),
    }
}

fn clamp_priority(value: Option<i64>) -> i32 {
    i32::try_from(value.unwrap_or(50).clamp(0, 100)).unwrap_or(50)
}

fn json_error(error: serde_json::Error) -> AdminError {
    let message = error.to_string();
    drop(error);
    AdminError::BadRequest(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    #[test]
    fn codex_session_parser_extracts_nested_tokens_and_claims() {
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "email": "admin@example.com",
                "https://api.openai.com/auth": {
                    "chatgpt_account_id": "acct-1",
                    "chatgpt_user_id": "user-1"
                }
            }))
            .unwrap(),
        );
        let token = format!("header.{claims}.signature");
        let session =
            parse_codex_session(&json!({ "tokens": { "access_token": token } }).to_string())
                .unwrap();
        assert_eq!(session.email, "admin@example.com");
        assert_eq!(session.account_id, "acct-1");
        assert_eq!(session.user_id, "user-1");
    }

    #[test]
    fn model_mapping_contains_current_aliases() {
        let mapping = antigravity_default_model_mapping();
        assert_eq!(
            mapping.get("gemini-3.1-flash-image-preview"),
            Some(&json!("gemini-3.1-flash-image"))
        );
        assert!(mapping.get("claude-opus-4-8").is_some());
    }

    #[test]
    fn positive_ids_are_deduplicated_and_sorted() {
        assert_eq!(
            positive_id_array(Some(&json!([3, 1, 3, 2])), "ids").unwrap(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn google_one_tier_matches_drive_storage_thresholds() {
        const GIB: i64 = 1_024 * 1_024 * 1_024;
        assert_eq!(infer_google_one_tier(15 * GIB), "google_one_free");
        assert_eq!(infer_google_one_tier(2 * 1_024 * GIB), "google_ai_pro");
        assert_eq!(infer_google_one_tier(101 * 1_024 * GIB), "google_ai_ultra");
        assert_eq!(infer_google_one_tier(0), "google_one_unknown");
    }

    #[test]
    fn codex_input_flattens_arrays_and_line_tokens() {
        assert_eq!(
            expand_codex_input(r#"["token-a",{"access_token":"token-b"}]"#).unwrap(),
            vec!["token-a", r#"{"access_token":"token-b"}"#]
        );
        assert_eq!(
            expand_codex_input("token-a\ntoken-b").unwrap(),
            vec!["token-a", "token-b"]
        );
    }

    #[test]
    fn migration_payload_keeps_secrets_and_has_no_export_cap() {
        let payload = json!({
            "type": "sub2api-data",
            "version": 1,
            "proxies": [{
                "protocol": "http", "host": "127.0.0.1", "port": 8080,
                "password": "proxy-secret"
            }],
            "accounts": [{
                "name": "oauth", "platform": "openai", "type": "oauth",
                "credentials": {"refresh_token": "account-secret"},
                "concurrency": 3, "priority": 50
            }]
        });
        validate_data_payload(&payload).unwrap();
        validate_import_account(&payload["accounts"][0]).unwrap();
        assert_eq!(payload["proxies"][0]["password"], "proxy-secret");
        assert_eq!(
            payload["accounts"][0]["credentials"]["refresh_token"],
            "account-secret"
        );

        let ids = (1..=1_501)
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            export_ids(&BTreeMap::from([("ids".to_owned(), ids)]), "account")
                .unwrap()
                .len(),
            1_501
        );
    }

    #[test]
    fn migration_import_validation_matches_go_contract() {
        assert!(validate_data_payload(&json!({ "proxies": [] })).is_err());
        assert!(
            validate_import_account(&json!({
                "name": "missing-secret", "platform": "openai", "type": "oauth",
                "credentials": {}
            }))
            .is_err()
        );
        assert_eq!(
            normalize_import_proxy_status("expired").unwrap(),
            "inactive"
        );
        let result = import_result_value(1, 2, 0, 3, 0, Vec::new());
        assert!(result.get("errors").is_none());
        assert_eq!(result["account_created"], 3);
    }

    #[test]
    fn migration_data_handlers_are_not_owned_by_generic_export() {
        let legacy = include_str!("compat_special.rs");
        for handler in [
            "h.Admin.Account.ExportData",
            "h.Admin.Account.ImportData",
            "h.Admin.Proxy.ExportData",
            "h.Admin.Proxy.ImportData",
        ] {
            assert!(
                !legacy.contains(handler),
                "legacy fallback still owns {handler}"
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL pointing at a migrated disposable *_test database"]
    async fn postgres_batch_updates_are_atomic_and_proxy_delete_skips_in_use_rows() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL must point at a disposable *_test database");
        let parsed = Url::parse(&database_url).expect("TEST_DATABASE_URL must be valid");
        assert!(
            parsed.path().trim_start_matches('/').ends_with("_test"),
            "refusing to mutate a database without an _test suffix"
        );
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await
            .expect("connect disposable PostgreSQL");
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let used_proxy = sqlx::query_scalar::<_, i64>(
            "INSERT INTO proxies (name,protocol,host,port,status) VALUES ($1,'http','127.0.0.1',18080,'active') RETURNING id",
        )
        .bind(format!("compat-used-{suffix}"))
        .fetch_one(&pool)
        .await
        .expect("insert used proxy");
        let free_proxy = sqlx::query_scalar::<_, i64>(
            "INSERT INTO proxies (name,protocol,host,port,status) VALUES ($1,'http','127.0.0.1',18081,'active') RETURNING id",
        )
        .bind(format!("compat-free-{suffix}"))
        .fetch_one(&pool)
        .await
        .expect("insert free proxy");
        let account_id = sqlx::query_scalar::<_, i64>(
            "INSERT INTO accounts (name,platform,type,credentials,extra,proxy_id,concurrency,priority,status,schedulable) VALUES ($1,'openai','apikey','{\"sentinel\":\"original\"}'::jsonb,'{}'::jsonb,$2,1,50,'active',TRUE) RETURNING id",
        )
        .bind(format!("compat-account-{suffix}"))
        .bind(used_proxy)
        .fetch_one(&pool)
        .await
        .expect("insert account fixture");

        let missing_id = i64::MAX - 17;
        let update = batch_update_credentials(
            &pool,
            json!({
                "account_ids": [account_id, missing_id],
                "field": "account_uuid",
                "value": "must-not-persist"
            }),
        )
        .await;
        assert!(matches!(update, Err(AdminError::NotFound("account"))));
        let credentials =
            sqlx::query_scalar::<_, Value>("SELECT credentials FROM accounts WHERE id=$1")
                .bind(account_id)
                .fetch_one(&pool)
                .await
                .expect("load credentials after rejected batch");
        assert_eq!(credentials.get("sentinel"), Some(&json!("original")));
        assert!(credentials.get("account_uuid").is_none());

        let deleted = batch_delete_proxies(&pool, &json!({ "ids": [used_proxy, free_proxy] }))
            .await
            .expect("batch delete proxies");
        assert_eq!(deleted["deleted_ids"], json!([free_proxy]));
        assert_eq!(deleted["skipped"][0]["id"], json!(used_proxy));
        let states = sqlx::query(
            "SELECT id, deleted_at IS NOT NULL AS deleted FROM proxies WHERE id=ANY($1) ORDER BY id",
        )
        .bind(vec![used_proxy, free_proxy])
        .fetch_all(&pool)
        .await
        .expect("load proxy states");
        assert_eq!(states.len(), 2);
        for row in states {
            let id: i64 = row.try_get("id").unwrap();
            let is_deleted: bool = row.try_get("deleted").unwrap();
            assert_eq!(is_deleted, id == free_proxy);
        }

        sqlx::query("DELETE FROM accounts WHERE id=$1")
            .bind(account_id)
            .execute(&pool)
            .await
            .expect("delete account fixture");
        sqlx::query("DELETE FROM proxies WHERE id=ANY($1)")
            .bind(vec![used_proxy, free_proxy])
            .execute(&pool)
            .await
            .expect("delete proxy fixtures");
    }
}
