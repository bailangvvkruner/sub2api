//! `PostgreSQL` implementations for administrator routes whose behavior cannot
//! be represented by the generic CRUD compatibility layer.

use std::{
    collections::BTreeMap,
    future::Future,
    time::{Duration, Instant},
};

use chrono::{DateTime, Datelike, TimeZone, Utc, Weekday};
use futures_util::{StreamExt, stream};
use regex::Regex;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};

use super::{AdminError, compat::required_path_id, service::validate_public_probe_target};

const AUTH_INVALIDATION_CHANNEL: &str = "sub2api_auth_cache_invalidation";
const MAX_BATCH_ITEMS: usize = 1_000;
const ALLOWED_PLATFORMS: [&str; 5] = ["anthropic", "openai", "gemini", "antigravity", "grok"];
const ATTRIBUTE_TYPES: [&str; 8] = [
    "text",
    "textarea",
    "number",
    "email",
    "url",
    "date",
    "select",
    "multiselect",
];

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) async fn dispatch(
    pool: &PgPool,
    handler: &str,
    path: &str,
    query: &BTreeMap<String, String>,
    payload: Value,
) -> Option<Result<Value, AdminError>> {
    let result = match handler {
        "h.Admin.Group.GetModelsListCandidates" => {
            with_path_id(path, "group", |id| group_model_candidates(pool, id, query)).await
        }
        "h.Admin.Group.BatchSetGroupRateMultipliers" => {
            with_path_id(path, "group", |id| sync_group_rates(pool, id, &payload)).await
        }
        "h.Admin.Group.ClearGroupRateMultipliers" => {
            with_path_id(path, "group", |id| clear_group_rates(pool, id)).await
        }
        "h.Admin.Group.BatchSetGroupRPMOverrides" => {
            with_path_id(path, "group", |id| sync_group_rpm(pool, id, &payload)).await
        }
        "h.Admin.Group.ClearGroupRPMOverrides" => {
            with_path_id(path, "group", |id| clear_group_rpm(pool, id)).await
        }
        "h.Admin.Group.UpdateSortOrder" => update_group_sort_order(pool, &payload).await,
        "h.Admin.User.BindAuthIdentity" => {
            with_path_id(path, "user", |id| bind_auth_identity(pool, id, &payload)).await
        }
        "h.Admin.User.GetUserPlatformQuotas" => {
            with_path_id(path, "user", |id| get_platform_quotas(pool, id)).await
        }
        "h.Admin.User.UpdateUserPlatformQuotas" => {
            with_path_id(path, "user", |id| {
                replace_platform_quotas(pool, id, &payload)
            })
            .await
        }
        "h.Admin.User.ResetUserPlatformQuotaWindow" => {
            with_path_id(path, "user", |id| reset_platform_quota(pool, id, &payload)).await
        }
        "h.Admin.UserAttribute.ListDefinitions" => list_attribute_definitions(pool, query).await,
        "h.Admin.UserAttribute.CreateDefinition" => {
            create_attribute_definition(pool, &payload).await
        }
        "h.Admin.UserAttribute.UpdateDefinition" => {
            with_path_id(path, "user attribute", |id| {
                update_attribute_definition(pool, id, &payload)
            })
            .await
        }
        "h.Admin.UserAttribute.DeleteDefinition" => {
            with_path_id(path, "user attribute", |id| {
                delete_attribute_definition(pool, id)
            })
            .await
        }
        "h.Admin.UserAttribute.ReorderDefinitions" => {
            reorder_attribute_definitions(pool, &payload).await
        }
        "h.Admin.UserAttribute.GetUserAttributes" => {
            with_path_id(path, "user", |id| get_user_attributes(pool, id)).await
        }
        "h.Admin.UserAttribute.UpdateUserAttributes" => {
            with_path_id(path, "user", |id| {
                update_user_attributes(pool, id, &payload)
            })
            .await
        }
        "h.Admin.UserAttribute.GetBatchUserAttributes" => {
            batch_user_attributes(pool, &payload).await
        }
        "h.Admin.ContentModeration.GetConfig" => moderation_config(pool).await,
        "h.Admin.ContentModeration.UpdateConfig" => update_moderation_config(pool, &payload).await,
        "h.Admin.ContentModeration.TestAPIKeys" => test_moderation_api_keys(&payload).await,
        "h.Admin.ContentModeration.DeleteFlaggedHash" => delete_flagged_hash(pool, &payload).await,
        "h.Admin.ContentModeration.ClearFlaggedHashes" => clear_flagged_hashes(pool).await,
        _ => return None,
    };
    Some(result)
}

async fn with_path_id<T, F, Fut>(
    path: &str,
    label: &'static str,
    operation: F,
) -> Result<T, AdminError>
where
    F: FnOnce(i64) -> Fut,
    Fut: Future<Output = Result<T, AdminError>>,
{
    operation(required_path_id(path, label)?).await
}

fn payload_object(payload: &Value) -> Result<&Map<String, Value>, AdminError> {
    payload
        .as_object()
        .ok_or_else(|| AdminError::BadRequest("request body must be a JSON object".to_owned()))
}

async fn ensure_live_row(
    transaction: &mut Transaction<'_, Postgres>,
    table: &'static str,
    id: i64,
    label: &'static str,
) -> Result<(), AdminError> {
    if id <= 0 {
        return Err(AdminError::BadRequest(format!(
            "{label} id must be positive"
        )));
    }
    let sql = format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE id = $1 AND deleted_at IS NULL)");
    if !sqlx::query_scalar::<_, bool>(&sql)
        .bind(id)
        .fetch_one(&mut **transaction)
        .await?
    {
        return Err(AdminError::NotFound(label));
    }
    Ok(())
}

async fn notify_auth(transaction: &mut Transaction<'_, Postgres>) -> Result<(), AdminError> {
    sqlx::query("SELECT pg_notify($1, $2)")
        .bind(AUTH_INVALIDATION_CHANNEL)
        .bind(r#"{"version":1,"scope":"auth"}"#)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn notify_settings(transaction: &mut Transaction<'_, Postgres>) -> Result<(), AdminError> {
    sqlx::query("SELECT pg_notify($1, $2)")
        .bind(AUTH_INVALIDATION_CHANNEL)
        .bind(r#"{"version":1,"scope":"settings"}"#)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn group_model_candidates(
    pool: &PgPool,
    group_id: i64,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    if group_id < 0 {
        return Err(AdminError::BadRequest(
            "group id must be non-negative".to_owned(),
        ));
    }
    let requested_platform = query
        .get("platform")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty());
    let platform = if group_id > 0 {
        let stored = sqlx::query_scalar::<_, String>(
            "SELECT platform FROM groups WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(group_id)
        .fetch_optional(pool)
        .await?
        .ok_or(AdminError::NotFound("group"))?;
        requested_platform.unwrap_or(&stored).to_owned()
    } else {
        requested_platform.unwrap_or("anthropic").to_owned()
    };
    if !ALLOWED_PLATFORMS.contains(&platform.as_str()) {
        return Err(AdminError::BadRequest("unsupported platform".to_owned()));
    }

    let mut models = default_model_candidates(&platform)
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if group_id > 0 {
        let mapped = sqlx::query_scalar::<_, String>(
            r"
SELECT DISTINCT mapping.model
FROM account_groups bindings
JOIN accounts account ON account.id = bindings.account_id
CROSS JOIN LATERAL jsonb_object_keys(
    CASE
        WHEN jsonb_typeof(account.credentials -> 'model_mapping') = 'object'
        THEN account.credentials -> 'model_mapping'
        ELSE '{}'::jsonb
    END
) AS mapping(model)
WHERE bindings.group_id = $1
  AND account.platform = $2
  AND account.deleted_at IS NULL
  AND account.status <> 'disabled'
  AND account.schedulable = TRUE
ORDER BY mapping.model
",
        )
        .bind(group_id)
        .bind(&platform)
        .fetch_all(pool)
        .await?;
        for model in mapped {
            let model = model.trim();
            if !model.is_empty() && !models.iter().any(|candidate| candidate == model) {
                models.push(model.to_owned());
            }
        }
    }
    Ok(json!({ "models": models }))
}

fn default_model_candidates(platform: &str) -> &'static [&'static str] {
    match platform {
        "openai" => &[
            "gpt-5.4",
            "gpt-5.3-codex",
            "gpt-5.2",
            "gpt-5.1-codex-max",
            "gpt-4.1",
        ],
        "gemini" => &[
            "gemini-3.1-pro-preview",
            "gemini-3-flash-preview",
            "gemini-2.5-pro",
            "gemini-2.5-flash",
        ],
        "antigravity" => &[
            "gemini-3.1-pro-high",
            "gemini-3-flash",
            "claude-opus-4-6-thinking",
            "claude-sonnet-4-6-thinking",
        ],
        "grok" => &["grok-4.1-fast", "grok-4", "grok-3", "grok-imagine-image"],
        _ => &[
            "claude-opus-4-6",
            "claude-sonnet-4-6",
            "claude-haiku-4-5-20251001",
        ],
    }
}

async fn sync_group_rates(
    pool: &PgPool,
    group_id: i64,
    payload: &Value,
) -> Result<Value, AdminError> {
    let entries = payload_object(payload)?
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| AdminError::BadRequest("entries must be an array".to_owned()))?;
    if entries.len() > MAX_BATCH_ITEMS {
        return Err(AdminError::BadRequest("too many rate entries".to_owned()));
    }
    let mut parsed = BTreeMap::<i64, f64>::new();
    for entry in entries {
        let object = payload_object(entry)?;
        let user_id = positive_id(object.get("user_id"), "user_id")?;
        let rate = object
            .get("rate_multiplier")
            .and_then(Value::as_f64)
            .filter(|rate| rate.is_finite() && *rate > 0.0)
            .ok_or_else(|| {
                AdminError::BadRequest(
                    "rate_multiplier must be finite and greater than zero".to_owned(),
                )
            })?;
        if parsed.insert(user_id, rate).is_some() {
            return Err(AdminError::BadRequest("duplicate user_id".to_owned()));
        }
    }

    let mut transaction = pool.begin().await?;
    ensure_live_row(&mut transaction, "groups", group_id, "group").await?;
    let keep = parsed.keys().copied().collect::<Vec<_>>();
    if keep.is_empty() {
        sqlx::query(
            "UPDATE user_group_rate_multipliers SET rate_multiplier = NULL, updated_at = NOW() WHERE group_id = $1",
        )
        .bind(group_id)
        .execute(&mut *transaction)
        .await?;
    } else {
        sqlx::query(
            "UPDATE user_group_rate_multipliers SET rate_multiplier = NULL, updated_at = NOW() WHERE group_id = $1 AND NOT (user_id = ANY($2))",
        )
        .bind(group_id)
        .bind(&keep)
        .execute(&mut *transaction)
        .await?;
    }
    delete_empty_group_overrides(&mut transaction, group_id).await?;
    for (user_id, rate) in parsed {
        sqlx::query(
            r"
INSERT INTO user_group_rate_multipliers
    (user_id, group_id, rate_multiplier, created_at, updated_at)
VALUES ($1, $2, $3::double precision, NOW(), NOW())
ON CONFLICT (user_id, group_id) DO UPDATE
SET rate_multiplier = EXCLUDED.rate_multiplier, updated_at = NOW()
",
        )
        .bind(user_id)
        .bind(group_id)
        .bind(rate)
        .execute(&mut *transaction)
        .await?;
    }
    notify_auth(&mut transaction).await?;
    transaction.commit().await?;
    Ok(json!({ "message": "Rate multipliers updated successfully" }))
}

async fn clear_group_rates(pool: &PgPool, group_id: i64) -> Result<Value, AdminError> {
    let mut transaction = pool.begin().await?;
    ensure_live_row(&mut transaction, "groups", group_id, "group").await?;
    sqlx::query("DELETE FROM user_group_rate_multipliers WHERE group_id = $1")
        .bind(group_id)
        .execute(&mut *transaction)
        .await?;
    notify_auth(&mut transaction).await?;
    transaction.commit().await?;
    Ok(json!({ "message": "Rate multipliers cleared successfully" }))
}

async fn sync_group_rpm(
    pool: &PgPool,
    group_id: i64,
    payload: &Value,
) -> Result<Value, AdminError> {
    let entries = payload_object(payload)?
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| AdminError::BadRequest("entries must be an array".to_owned()))?;
    if entries.len() > MAX_BATCH_ITEMS {
        return Err(AdminError::BadRequest("too many RPM entries".to_owned()));
    }
    let mut parsed = BTreeMap::<i64, Option<i32>>::new();
    for entry in entries {
        let object = payload_object(entry)?;
        let user_id = positive_id(object.get("user_id"), "user_id")?;
        let rpm =
            match object.get("rpm_override") {
                None | Some(Value::Null) => None,
                Some(value) => {
                    let value = value.as_i64().filter(|value| *value >= 0).ok_or_else(|| {
                        AdminError::BadRequest(
                            "rpm_override must be a non-negative integer or null".to_owned(),
                        )
                    })?;
                    Some(i32::try_from(value).map_err(|_| {
                        AdminError::BadRequest("rpm_override is too large".to_owned())
                    })?)
                }
            };
        if parsed.insert(user_id, rpm).is_some() {
            return Err(AdminError::BadRequest("duplicate user_id".to_owned()));
        }
    }

    let mut transaction = pool.begin().await?;
    ensure_live_row(&mut transaction, "groups", group_id, "group").await?;
    let keep = parsed.keys().copied().collect::<Vec<_>>();
    if keep.is_empty() {
        sqlx::query(
            "UPDATE user_group_rate_multipliers SET rpm_override = NULL, updated_at = NOW() WHERE group_id = $1",
        )
        .bind(group_id)
        .execute(&mut *transaction)
        .await?;
    } else {
        sqlx::query(
            "UPDATE user_group_rate_multipliers SET rpm_override = NULL, updated_at = NOW() WHERE group_id = $1 AND NOT (user_id = ANY($2))",
        )
        .bind(group_id)
        .bind(&keep)
        .execute(&mut *transaction)
        .await?;
    }
    for (user_id, rpm) in parsed {
        if let Some(rpm) = rpm {
            sqlx::query(
                r"
INSERT INTO user_group_rate_multipliers
    (user_id, group_id, rpm_override, created_at, updated_at)
VALUES ($1, $2, $3, NOW(), NOW())
ON CONFLICT (user_id, group_id) DO UPDATE
SET rpm_override = EXCLUDED.rpm_override, updated_at = NOW()
",
            )
            .bind(user_id)
            .bind(group_id)
            .bind(rpm)
            .execute(&mut *transaction)
            .await?;
        } else {
            sqlx::query(
                "UPDATE user_group_rate_multipliers SET rpm_override = NULL, updated_at = NOW() WHERE user_id = $1 AND group_id = $2",
            )
            .bind(user_id)
            .bind(group_id)
            .execute(&mut *transaction)
            .await?;
        }
    }
    delete_empty_group_overrides(&mut transaction, group_id).await?;
    notify_auth(&mut transaction).await?;
    transaction.commit().await?;
    Ok(json!({ "message": "RPM overrides updated successfully" }))
}

async fn clear_group_rpm(pool: &PgPool, group_id: i64) -> Result<Value, AdminError> {
    let mut transaction = pool.begin().await?;
    ensure_live_row(&mut transaction, "groups", group_id, "group").await?;
    sqlx::query(
        "UPDATE user_group_rate_multipliers SET rpm_override = NULL, updated_at = NOW() WHERE group_id = $1",
    )
    .bind(group_id)
    .execute(&mut *transaction)
    .await?;
    delete_empty_group_overrides(&mut transaction, group_id).await?;
    notify_auth(&mut transaction).await?;
    transaction.commit().await?;
    Ok(json!({ "message": "RPM overrides cleared successfully" }))
}

async fn delete_empty_group_overrides(
    transaction: &mut Transaction<'_, Postgres>,
    group_id: i64,
) -> Result<(), AdminError> {
    sqlx::query(
        "DELETE FROM user_group_rate_multipliers WHERE group_id = $1 AND rate_multiplier IS NULL AND rpm_override IS NULL",
    )
    .bind(group_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn update_group_sort_order(pool: &PgPool, payload: &Value) -> Result<Value, AdminError> {
    let updates = payload_object(payload)?
        .get("updates")
        .and_then(Value::as_array)
        .filter(|updates| !updates.is_empty())
        .ok_or_else(|| AdminError::BadRequest("updates must be a non-empty array".to_owned()))?;
    if updates.len() > MAX_BATCH_ITEMS {
        return Err(AdminError::BadRequest("too many group updates".to_owned()));
    }
    let mut parsed = BTreeMap::<i64, i32>::new();
    for update in updates {
        let object = payload_object(update)?;
        let id = positive_id(object.get("id"), "id")?;
        let order = object
            .get("sort_order")
            .and_then(Value::as_i64)
            .unwrap_or_default();
        let order = i32::try_from(order)
            .map_err(|_| AdminError::BadRequest("sort_order is out of range".to_owned()))?;
        if parsed.insert(id, order).is_some() {
            return Err(AdminError::BadRequest("duplicate group id".to_owned()));
        }
    }
    let mut transaction = pool.begin().await?;
    for (id, order) in parsed {
        let result = sqlx::query(
            "UPDATE groups SET sort_order = $2, updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(id)
        .bind(order)
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() == 0 {
            return Err(AdminError::NotFound("group"));
        }
    }
    transaction.commit().await?;
    Ok(json!({ "message": "Sort order updated successfully" }))
}

fn positive_id(value: Option<&Value>, name: &str) -> Result<i64, AdminError> {
    value
        .and_then(Value::as_i64)
        .filter(|value| *value > 0)
        .ok_or_else(|| AdminError::BadRequest(format!("{name} must be a positive integer")))
}

#[allow(clippy::too_many_lines)]
async fn bind_auth_identity(
    pool: &PgPool,
    user_id: i64,
    payload: &Value,
) -> Result<Value, AdminError> {
    let object = payload_object(payload)?;
    let provider_type = required_trimmed_string(object, "provider_type")?.to_lowercase();
    if !matches!(
        provider_type.as_str(),
        "email" | "linuxdo" | "oidc" | "wechat" | "dingtalk"
    ) {
        return Err(AdminError::BadRequest(
            "provider_type must be one of email, linuxdo, oidc, wechat, or dingtalk".to_owned(),
        ));
    }
    let requested_key = required_trimmed_string(object, "provider_key")?;
    let provider_subject = required_trimmed_string(object, "provider_subject")?;
    let canonical_key = canonical_provider_key(&provider_type, &requested_key);
    let compatible_keys = compatible_provider_keys(&provider_type, &requested_key);
    let issuer = optional_trimmed_string(object.get("issuer"))?;
    let metadata = optional_json_object(object.get("metadata"), "metadata")?;
    let channel = object
        .get("channel")
        .filter(|value| !value.is_null())
        .map(parse_identity_channel)
        .transpose()?;

    let mut transaction = pool.begin().await?;
    ensure_live_row(&mut transaction, "users", user_id, "user").await?;
    let identities = sqlx::query(
        r"
SELECT id, user_id, provider_key
FROM auth_identities
WHERE provider_type = $1
  AND provider_key = ANY($2)
  AND provider_subject = $3
FOR UPDATE
",
    )
    .bind(&provider_type)
    .bind(&compatible_keys)
    .bind(&provider_subject)
    .fetch_all(&mut *transaction)
    .await?;
    if identities.iter().any(|row| {
        row.try_get::<i64, _>("user_id")
            .is_ok_and(|owner| owner != user_id)
    }) {
        return Err(AdminError::Conflict(
            "auth identity already belongs to another user".to_owned(),
        ));
    }
    let identity_id = identities
        .iter()
        .filter(|row| row.try_get::<i64, _>("user_id").ok() == Some(user_id))
        .min_by_key(|row| {
            provider_key_rank(
                &provider_type,
                row.try_get::<String, _>("provider_key")
                    .as_deref()
                    .unwrap_or_default(),
            )
        })
        .map(|row| row.try_get::<i64, _>("id"))
        .transpose()?;
    let metadata_json = metadata.as_ref().map(Value::to_string);
    let identity_id = if let Some(identity_id) = identity_id {
        sqlx::query(
            r"
UPDATE auth_identities
SET provider_key = $2,
    verified_at = NOW(),
    issuer = CASE WHEN $3 THEN $4 ELSE issuer END,
    metadata = CASE WHEN $5 THEN $6::jsonb ELSE metadata END,
    updated_at = NOW()
WHERE id = $1
",
        )
        .bind(identity_id)
        .bind(&canonical_key)
        .bind(object.contains_key("issuer"))
        .bind(issuer.as_deref())
        .bind(metadata.is_some())
        .bind(metadata_json.as_deref())
        .execute(&mut *transaction)
        .await?;
        identity_id
    } else {
        sqlx::query_scalar::<_, i64>(
            r"
INSERT INTO auth_identities (
    user_id, provider_type, provider_key, provider_subject,
    verified_at, issuer, metadata, created_at, updated_at
)
VALUES ($1, $2, $3, $4, NOW(), $5, COALESCE($6::jsonb, '{}'::jsonb), NOW(), NOW())
RETURNING id
",
        )
        .bind(user_id)
        .bind(&provider_type)
        .bind(&canonical_key)
        .bind(&provider_subject)
        .bind(issuer.as_deref())
        .bind(metadata_json.as_deref())
        .fetch_one(&mut *transaction)
        .await?
    };

    let channel_id = if let Some(channel) = channel.as_ref() {
        let channels = sqlx::query(
            r"
SELECT channel_row.id, identity.user_id
FROM auth_identity_channels channel_row
JOIN auth_identities identity ON identity.id = channel_row.identity_id
WHERE channel_row.provider_type = $1
  AND channel_row.provider_key = ANY($2)
  AND channel_row.channel = $3
  AND channel_row.channel_app_id = $4
  AND channel_row.channel_subject = $5
FOR UPDATE OF channel_row
",
        )
        .bind(&provider_type)
        .bind(&compatible_keys)
        .bind(&channel.channel)
        .bind(&channel.app_id)
        .bind(&channel.subject)
        .fetch_all(&mut *transaction)
        .await?;
        if channels.iter().any(|row| {
            row.try_get::<i64, _>("user_id")
                .is_ok_and(|owner| owner != user_id)
        }) {
            return Err(AdminError::Conflict(
                "auth identity channel already belongs to another user".to_owned(),
            ));
        }
        let existing = channels
            .first()
            .map(|row| row.try_get::<i64, _>("id"))
            .transpose()?;
        let channel_metadata = channel.metadata.as_ref().map(Value::to_string);
        if let Some(channel_id) = existing {
            sqlx::query(
                r"
UPDATE auth_identity_channels
SET identity_id = $2,
    provider_key = $3,
    metadata = CASE WHEN $4 THEN $5::jsonb ELSE metadata END,
    updated_at = NOW()
WHERE id = $1
",
            )
            .bind(channel_id)
            .bind(identity_id)
            .bind(&canonical_key)
            .bind(channel.metadata.is_some())
            .bind(channel_metadata.as_deref())
            .execute(&mut *transaction)
            .await?;
            Some(channel_id)
        } else {
            Some(
                sqlx::query_scalar::<_, i64>(
                    r"
INSERT INTO auth_identity_channels (
    identity_id, provider_type, provider_key, channel,
    channel_app_id, channel_subject, metadata, created_at, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7::jsonb, '{}'::jsonb), NOW(), NOW())
RETURNING id
",
                )
                .bind(identity_id)
                .bind(&provider_type)
                .bind(&canonical_key)
                .bind(&channel.channel)
                .bind(&channel.app_id)
                .bind(&channel.subject)
                .bind(channel_metadata.as_deref())
                .fetch_one(&mut *transaction)
                .await?,
            )
        }
    } else {
        None
    };

    let mut result = sqlx::query_scalar::<_, Value>(
        r"
SELECT jsonb_build_object(
    'user_id', user_id,
    'provider_type', provider_type,
    'provider_key', provider_key,
    'provider_subject', provider_subject,
    'verified_at', verified_at,
    'issuer', issuer,
    'metadata', metadata,
    'created_at', created_at,
    'updated_at', updated_at
)
FROM auth_identities WHERE id = $1
",
    )
    .bind(identity_id)
    .fetch_one(&mut *transaction)
    .await?;
    if let Some(channel_id) = channel_id {
        let channel = sqlx::query_scalar::<_, Value>(
            r"
SELECT jsonb_build_object(
    'channel', channel,
    'channel_app_id', channel_app_id,
    'channel_subject', channel_subject,
    'metadata', metadata,
    'created_at', created_at,
    'updated_at', updated_at
)
FROM auth_identity_channels WHERE id = $1
",
        )
        .bind(channel_id)
        .fetch_one(&mut *transaction)
        .await?;
        result
            .as_object_mut()
            .expect("jsonb_build_object returns an object")
            .insert("channel".to_owned(), channel);
    }
    transaction.commit().await?;
    Ok(result)
}

struct IdentityChannelInput {
    channel: String,
    app_id: String,
    subject: String,
    metadata: Option<Value>,
}

fn parse_identity_channel(value: &Value) -> Result<IdentityChannelInput, AdminError> {
    let object = payload_object(value)?;
    Ok(IdentityChannelInput {
        channel: required_trimmed_string(object, "channel")?,
        app_id: required_trimmed_string(object, "channel_app_id")?,
        subject: required_trimmed_string(object, "channel_subject")?,
        metadata: optional_json_object(object.get("metadata"), "channel.metadata")?,
    })
}

fn required_trimmed_string(object: &Map<String, Value>, field: &str) -> Result<String, AdminError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| AdminError::BadRequest(format!("{field} is required")))
}

fn optional_trimmed_string(value: Option<&Value>) -> Result<Option<String>, AdminError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => {
            Ok(Some(value.trim().to_owned()).filter(|value| !value.is_empty()))
        }
        Some(_) => Err(AdminError::BadRequest(
            "issuer must be a string or null".to_owned(),
        )),
    }
}

fn optional_json_object(value: Option<&Value>, field: &str) -> Result<Option<Value>, AdminError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value @ Value::Object(_)) => Ok(Some(value.clone())),
        Some(_) => Err(AdminError::BadRequest(format!("{field} must be an object"))),
    }
}

fn compatible_provider_keys(provider_type: &str, requested: &str) -> Vec<String> {
    if provider_type != "wechat" {
        return vec![requested.to_owned()];
    }
    let mut keys = vec![requested.to_owned()];
    for key in ["wechat-main", "wechat"] {
        if !keys
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(key))
        {
            keys.push(key.to_owned());
        }
    }
    keys
}

fn canonical_provider_key(provider_type: &str, requested: &str) -> String {
    if provider_type == "wechat"
        && (requested.eq_ignore_ascii_case("wechat")
            || requested.eq_ignore_ascii_case("wechat-main"))
    {
        "wechat-main".to_owned()
    } else {
        requested.to_owned()
    }
}

fn provider_key_rank(provider_type: &str, key: &str) -> u8 {
    if provider_type != "wechat" {
        return 0;
    }
    if key.eq_ignore_ascii_case("wechat-main") {
        0
    } else if key.eq_ignore_ascii_case("wechat") {
        2
    } else {
        1
    }
}

#[derive(Clone, Copy)]
struct QuotaLimitInput {
    daily: Option<f64>,
    weekly: Option<f64>,
    monthly: Option<f64>,
}

async fn get_platform_quotas(pool: &PgPool, user_id: i64) -> Result<Value, AdminError> {
    if !sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND deleted_at IS NULL)",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?
    {
        return Err(AdminError::NotFound("user"));
    }
    let rows = sqlx::query(
        r"
SELECT platform,
       daily_limit_usd::double precision AS daily_limit,
       weekly_limit_usd::double precision AS weekly_limit,
       monthly_limit_usd::double precision AS monthly_limit,
       daily_usage_usd::double precision AS daily_usage,
       weekly_usage_usd::double precision AS weekly_usage,
       monthly_usage_usd::double precision AS monthly_usage,
       EXTRACT(EPOCH FROM daily_window_start)::bigint AS daily_start,
       EXTRACT(EPOCH FROM weekly_window_start)::bigint AS weekly_start,
       EXTRACT(EPOCH FROM monthly_window_start)::bigint AS monthly_start
FROM user_platform_quotas
WHERE user_id = $1 AND deleted_at IS NULL
ORDER BY platform
",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    let now = Utc::now();
    let quotas = rows
        .into_iter()
        .map(|row| quota_view(&row, now))
        .collect::<Result<Vec<_>, AdminError>>()?;
    Ok(json!({ "platform_quotas": quotas }))
}

fn quota_view(row: &sqlx::postgres::PgRow, now: DateTime<Utc>) -> Result<Value, AdminError> {
    let daily_start = epoch_time(row.try_get("daily_start")?);
    let weekly_start = epoch_time(row.try_get("weekly_start")?);
    let monthly_start = epoch_time(row.try_get("monthly_start")?);
    let day_start = Utc
        .with_ymd_and_hms(now.year(), now.month(), now.day(), 0, 0, 0)
        .single()
        .expect("UTC calendar date is valid");
    let days_from_monday = i64::from(match now.weekday() {
        Weekday::Mon => 0,
        Weekday::Tue => 1,
        Weekday::Wed => 2,
        Weekday::Thu => 3,
        Weekday::Fri => 4,
        Weekday::Sat => 5,
        Weekday::Sun => 6,
    });
    let week_start = day_start - chrono::Duration::days(days_from_monday);
    let daily_expired = daily_start.is_some_and(|start| start < day_start);
    let weekly_expired = weekly_start.is_some_and(|start| start < week_start);
    let monthly_expired = monthly_start
        .is_some_and(|start| now.signed_duration_since(start) >= chrono::Duration::days(30));
    let daily_usage = if daily_expired {
        0.0
    } else {
        row.try_get("daily_usage")?
    };
    let weekly_usage = if weekly_expired {
        0.0
    } else {
        row.try_get("weekly_usage")?
    };
    let monthly_usage = if monthly_expired {
        0.0
    } else {
        row.try_get("monthly_usage")?
    };
    Ok(json!({
        "platform": row.try_get::<String, _>("platform")?,
        "daily_usage_usd": daily_usage,
        "daily_limit_usd": row.try_get::<Option<f64>, _>("daily_limit")?,
        "daily_window_start": daily_start.map(|value| value.to_rfc3339()),
        "daily_window_resets_at": (!daily_expired).then(|| daily_start.map(|_| (day_start + chrono::Duration::days(1)).to_rfc3339())).flatten(),
        "weekly_usage_usd": weekly_usage,
        "weekly_limit_usd": row.try_get::<Option<f64>, _>("weekly_limit")?,
        "weekly_window_start": weekly_start.map(|value| value.to_rfc3339()),
        "weekly_window_resets_at": (!weekly_expired).then(|| weekly_start.map(|_| (week_start + chrono::Duration::days(7)).to_rfc3339())).flatten(),
        "monthly_usage_usd": monthly_usage,
        "monthly_limit_usd": row.try_get::<Option<f64>, _>("monthly_limit")?,
        "monthly_window_start": monthly_start.map(|value| value.to_rfc3339()),
        "monthly_window_resets_at": (!monthly_expired).then(|| monthly_start.map(|start| (start + chrono::Duration::days(30)).to_rfc3339())).flatten(),
    }))
}

fn epoch_time(epoch: Option<i64>) -> Option<DateTime<Utc>> {
    epoch.and_then(|epoch| DateTime::from_timestamp(epoch, 0))
}

async fn replace_platform_quotas(
    pool: &PgPool,
    user_id: i64,
    payload: &Value,
) -> Result<Value, AdminError> {
    let quotas = payload_object(payload)?
        .get("quotas")
        .and_then(Value::as_array)
        .ok_or_else(|| AdminError::BadRequest("quotas must be an array".to_owned()))?;
    if quotas.len() > ALLOWED_PLATFORMS.len() {
        return Err(AdminError::BadRequest(
            "too many platform quotas".to_owned(),
        ));
    }
    let mut parsed = BTreeMap::<String, QuotaLimitInput>::new();
    for quota in quotas {
        let object = payload_object(quota)?;
        let platform = required_trimmed_string(object, "platform")?.to_lowercase();
        if !ALLOWED_PLATFORMS.contains(&platform.as_str()) {
            return Err(AdminError::BadRequest(format!(
                "invalid platform: {platform}"
            )));
        }
        let limits = QuotaLimitInput {
            daily: quota_limit(object.get("daily_limit_usd"), "daily_limit_usd")?,
            weekly: quota_limit(object.get("weekly_limit_usd"), "weekly_limit_usd")?,
            monthly: quota_limit(object.get("monthly_limit_usd"), "monthly_limit_usd")?,
        };
        if parsed.insert(platform, limits).is_some() {
            return Err(AdminError::BadRequest("duplicate platform".to_owned()));
        }
    }

    let mut transaction = pool.begin().await?;
    ensure_live_row(&mut transaction, "users", user_id, "user").await?;
    let keep = parsed.keys().cloned().collect::<Vec<_>>();
    if keep.is_empty() {
        sqlx::query(
            "UPDATE user_platform_quotas SET deleted_at = NOW(), updated_at = NOW() WHERE user_id = $1 AND deleted_at IS NULL",
        )
        .bind(user_id)
        .execute(&mut *transaction)
        .await?;
    } else {
        sqlx::query(
            "UPDATE user_platform_quotas SET deleted_at = NOW(), updated_at = NOW() WHERE user_id = $1 AND deleted_at IS NULL AND NOT (platform = ANY($2))",
        )
        .bind(user_id)
        .bind(&keep)
        .execute(&mut *transaction)
        .await?;
    }
    for (platform, limits) in parsed {
        let updated = sqlx::query(
            r"
UPDATE user_platform_quotas
SET daily_limit_usd = $3::double precision,
    weekly_limit_usd = $4::double precision,
    monthly_limit_usd = $5::double precision,
    updated_at = NOW()
WHERE user_id = $1 AND platform = $2 AND deleted_at IS NULL
",
        )
        .bind(user_id)
        .bind(&platform)
        .bind(limits.daily)
        .bind(limits.weekly)
        .bind(limits.monthly)
        .execute(&mut *transaction)
        .await?;
        if updated.rows_affected() == 0 {
            sqlx::query(
                r"
INSERT INTO user_platform_quotas (
    user_id, platform, daily_limit_usd, weekly_limit_usd, monthly_limit_usd,
    daily_usage_usd, weekly_usage_usd, monthly_usage_usd, created_at, updated_at
)
VALUES ($1, $2, $3::double precision, $4::double precision, $5::double precision,
        0, 0, 0, NOW(), NOW())
ON CONFLICT (user_id, platform) WHERE deleted_at IS NULL DO UPDATE
SET daily_limit_usd = EXCLUDED.daily_limit_usd,
    weekly_limit_usd = EXCLUDED.weekly_limit_usd,
    monthly_limit_usd = EXCLUDED.monthly_limit_usd,
    updated_at = NOW()
",
            )
            .bind(user_id)
            .bind(&platform)
            .bind(limits.daily)
            .bind(limits.weekly)
            .bind(limits.monthly)
            .execute(&mut *transaction)
            .await?;
        }
    }
    notify_auth(&mut transaction).await?;
    transaction.commit().await?;
    get_platform_quotas(pool, user_id).await
}

fn quota_limit(value: Option<&Value>, field: &str) -> Result<Option<f64>, AdminError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_f64()
            .filter(|value| value.is_finite() && *value >= 0.0)
            .map(Some)
            .ok_or_else(|| {
                AdminError::BadRequest(format!("{field} must be a finite non-negative number"))
            }),
    }
}

async fn reset_platform_quota(
    pool: &PgPool,
    user_id: i64,
    payload: &Value,
) -> Result<Value, AdminError> {
    let object = payload_object(payload)?;
    let platform = required_trimmed_string(object, "platform")?.to_lowercase();
    if !ALLOWED_PLATFORMS.contains(&platform.as_str()) {
        return Err(AdminError::BadRequest(format!(
            "invalid platform: {platform}"
        )));
    }
    let window = required_trimmed_string(object, "window")?.to_lowercase();
    let sql = match window.as_str() {
        "daily" => {
            "UPDATE user_platform_quotas SET daily_usage_usd = 0, daily_window_start = NOW(), updated_at = NOW() WHERE user_id = $1 AND platform = $2 AND deleted_at IS NULL"
        }
        "weekly" => {
            "UPDATE user_platform_quotas SET weekly_usage_usd = 0, weekly_window_start = NOW(), updated_at = NOW() WHERE user_id = $1 AND platform = $2 AND deleted_at IS NULL"
        }
        "monthly" => {
            "UPDATE user_platform_quotas SET monthly_usage_usd = 0, monthly_window_start = NOW(), updated_at = NOW() WHERE user_id = $1 AND platform = $2 AND deleted_at IS NULL"
        }
        _ => return Err(AdminError::BadRequest("invalid window".to_owned())),
    };
    let mut transaction = pool.begin().await?;
    ensure_live_row(&mut transaction, "users", user_id, "user").await?;
    let result = sqlx::query(sql)
        .bind(user_id)
        .bind(&platform)
        .execute(&mut *transaction)
        .await?;
    if result.rows_affected() == 0 {
        return Err(AdminError::NotFound("user platform quota"));
    }
    notify_auth(&mut transaction).await?;
    transaction.commit().await?;
    get_platform_quotas(pool, user_id).await
}

async fn list_attribute_definitions(
    pool: &PgPool,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let enabled_only = query.get("enabled").is_some_and(|value| value == "true");
    let rows = sqlx::query_scalar::<_, Value>(
        r"
SELECT to_jsonb(definition) - 'deleted_at'
FROM user_attribute_definitions definition
WHERE deleted_at IS NULL AND (NOT $1 OR enabled = TRUE)
ORDER BY display_order, id
",
    )
    .bind(enabled_only)
    .fetch_all(pool)
    .await?;
    Ok(Value::Array(rows))
}

async fn create_attribute_definition(pool: &PgPool, payload: &Value) -> Result<Value, AdminError> {
    let object = payload_object(payload)?;
    let key = required_trimmed_string(object, "key")?;
    let name = required_trimmed_string(object, "name")?;
    if key.chars().count() > 100 || name.chars().count() > 255 {
        return Err(AdminError::BadRequest(
            "attribute key or name is too long".to_owned(),
        ));
    }
    let attribute_type = required_trimmed_string(object, "type")?.to_lowercase();
    validate_attribute_type(&attribute_type)?;
    let description = string_or_default(object.get("description"), "description")?;
    let options = json_array_or_default(object.get("options"), "options")?;
    let validation = json_object_or_default(object.get("validation"), "validation")?;
    validate_attribute_pattern(&name, &validation)?;
    let required = bool_or_default(object.get("required"), "required")?;
    let placeholder = string_or_default(object.get("placeholder"), "placeholder")?;
    if placeholder.chars().count() > 255 {
        return Err(AdminError::BadRequest("placeholder is too long".to_owned()));
    }
    let enabled = bool_or_default(object.get("enabled"), "enabled")?;
    let options_json = options.to_string();
    let validation_json = validation.to_string();
    sqlx::query_scalar::<_, Value>(
        r"
INSERT INTO user_attribute_definitions (
    key, name, description, type, options, required, validation,
    placeholder, display_order, enabled, created_at, updated_at
)
VALUES (
    $1, $2, $3, $4, $5::jsonb, $6, $7::jsonb, $8,
    COALESCE((SELECT MAX(display_order) + 1 FROM user_attribute_definitions WHERE deleted_at IS NULL), 0),
    $9, NOW(), NOW()
)
RETURNING to_jsonb(user_attribute_definitions) - 'deleted_at'
",
    )
    .bind(key)
    .bind(name)
    .bind(description)
    .bind(attribute_type)
    .bind(options_json)
    .bind(required)
    .bind(validation_json)
    .bind(placeholder)
    .bind(enabled)
    .fetch_one(pool)
    .await
    .map_err(Into::into)
}

async fn update_attribute_definition(
    pool: &PgPool,
    id: i64,
    payload: &Value,
) -> Result<Value, AdminError> {
    let object = payload_object(payload)?;
    let name = optional_string(object.get("name"), "name")?;
    if name
        .as_ref()
        .is_some_and(|name| name.trim().is_empty() || name.chars().count() > 255)
    {
        return Err(AdminError::BadRequest("name is invalid".to_owned()));
    }
    let description = optional_string(object.get("description"), "description")?;
    let attribute_type =
        optional_string(object.get("type"), "type")?.map(|value| value.trim().to_lowercase());
    if let Some(attribute_type) = attribute_type.as_deref() {
        validate_attribute_type(attribute_type)?;
    }
    let options = optional_json_array(object.get("options"), "options")?;
    let validation = optional_json_object(object.get("validation"), "validation")?;
    if let Some(validation) = validation.as_ref() {
        validate_attribute_pattern(name.as_deref().unwrap_or("attribute"), validation)?;
    }
    let required = optional_bool(object.get("required"), "required")?;
    let placeholder = optional_string(object.get("placeholder"), "placeholder")?;
    if placeholder
        .as_ref()
        .is_some_and(|placeholder| placeholder.chars().count() > 255)
    {
        return Err(AdminError::BadRequest("placeholder is too long".to_owned()));
    }
    let enabled = optional_bool(object.get("enabled"), "enabled")?;
    let options_json = options.as_ref().map(Value::to_string);
    let validation_json = validation.as_ref().map(Value::to_string);
    sqlx::query_scalar::<_, Value>(
        r"
UPDATE user_attribute_definitions
SET name = COALESCE($2, name),
    description = COALESCE($3, description),
    type = COALESCE($4, type),
    options = COALESCE($5::jsonb, options),
    required = COALESCE($6, required),
    validation = COALESCE($7::jsonb, validation),
    placeholder = COALESCE($8, placeholder),
    enabled = COALESCE($9, enabled),
    updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL
RETURNING to_jsonb(user_attribute_definitions) - 'deleted_at'
",
    )
    .bind(id)
    .bind(name.as_deref())
    .bind(description.as_deref())
    .bind(attribute_type.as_deref())
    .bind(options_json.as_deref())
    .bind(required)
    .bind(validation_json.as_deref())
    .bind(placeholder.as_deref())
    .bind(enabled)
    .fetch_optional(pool)
    .await?
    .ok_or(AdminError::NotFound("user attribute"))
}

async fn delete_attribute_definition(pool: &PgPool, id: i64) -> Result<Value, AdminError> {
    let mut transaction = pool.begin().await?;
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM user_attribute_definitions WHERE id = $1 AND deleted_at IS NULL)",
    )
    .bind(id)
    .fetch_one(&mut *transaction)
    .await?;
    if !exists {
        return Err(AdminError::NotFound("user attribute"));
    }
    sqlx::query("DELETE FROM user_attribute_values WHERE attribute_id = $1")
        .bind(id)
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "UPDATE user_attribute_definitions SET deleted_at = NOW(), updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .execute(&mut *transaction)
    .await?;
    notify_auth(&mut transaction).await?;
    transaction.commit().await?;
    Ok(json!({ "message": "Attribute definition deleted successfully" }))
}

async fn reorder_attribute_definitions(
    pool: &PgPool,
    payload: &Value,
) -> Result<Value, AdminError> {
    let ids = payload_object(payload)?
        .get("ids")
        .and_then(Value::as_array)
        .ok_or_else(|| AdminError::BadRequest("ids must be an array".to_owned()))?;
    if ids.len() > MAX_BATCH_ITEMS {
        return Err(AdminError::BadRequest("too many attribute ids".to_owned()));
    }
    let mut parsed = Vec::with_capacity(ids.len());
    for id in ids {
        let id = positive_id(Some(id), "attribute id")?;
        if parsed.contains(&id) {
            return Err(AdminError::BadRequest("duplicate attribute id".to_owned()));
        }
        parsed.push(id);
    }
    let mut transaction = pool.begin().await?;
    for (order, id) in parsed.into_iter().enumerate() {
        let order = i32::try_from(order)
            .map_err(|_| AdminError::BadRequest("too many attribute ids".to_owned()))?;
        let result = sqlx::query(
            "UPDATE user_attribute_definitions SET display_order = $2, updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(id)
        .bind(order)
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() == 0 {
            return Err(AdminError::NotFound("user attribute"));
        }
    }
    transaction.commit().await?;
    Ok(json!({ "message": "Reorder successful" }))
}

async fn get_user_attributes(pool: &PgPool, user_id: i64) -> Result<Value, AdminError> {
    let rows = sqlx::query_scalar::<_, Value>(
        r"
SELECT to_jsonb(attribute_value)
FROM user_attribute_values attribute_value
WHERE user_id = $1
ORDER BY attribute_id
",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(Value::Array(rows))
}

async fn update_user_attributes(
    pool: &PgPool,
    user_id: i64,
    payload: &Value,
) -> Result<Value, AdminError> {
    let values = payload_object(payload)?
        .get("values")
        .and_then(Value::as_object)
        .ok_or_else(|| AdminError::BadRequest("values must be an object".to_owned()))?;
    if values.len() > MAX_BATCH_ITEMS {
        return Err(AdminError::BadRequest(
            "too many attribute values".to_owned(),
        ));
    }
    let mut parsed = BTreeMap::<i64, String>::new();
    for (attribute_id, value) in values {
        let attribute_id = attribute_id
            .parse::<i64>()
            .ok()
            .filter(|id| *id > 0)
            .ok_or_else(|| {
                AdminError::BadRequest("attribute ids must be positive integers".to_owned())
            })?;
        let value = value
            .as_str()
            .ok_or_else(|| AdminError::BadRequest("attribute values must be strings".to_owned()))?;
        parsed.insert(attribute_id, value.to_owned());
    }
    let ids = parsed.keys().copied().collect::<Vec<_>>();
    let definitions = if ids.is_empty() {
        Vec::new()
    } else {
        sqlx::query(
            r"
SELECT id, name, type, options, required, validation
FROM user_attribute_definitions
WHERE id = ANY($1) AND enabled = TRUE AND deleted_at IS NULL
",
        )
        .bind(&ids)
        .fetch_all(pool)
        .await?
    };
    if definitions.len() != ids.len() {
        return Err(AdminError::NotFound("user attribute definition"));
    }
    for definition in &definitions {
        let id: i64 = definition.try_get("id")?;
        validate_attribute_value(
            definition,
            parsed.get(&id).expect("definition id was requested"),
        )?;
    }

    let mut transaction = pool.begin().await?;
    ensure_live_row(&mut transaction, "users", user_id, "user").await?;
    for (attribute_id, value) in parsed {
        sqlx::query(
            r"
INSERT INTO user_attribute_values
    (user_id, attribute_id, value, created_at, updated_at)
VALUES ($1, $2, $3, NOW(), NOW())
ON CONFLICT (user_id, attribute_id) DO UPDATE
SET value = EXCLUDED.value, updated_at = NOW()
",
        )
        .bind(user_id)
        .bind(attribute_id)
        .bind(value)
        .execute(&mut *transaction)
        .await?;
    }
    notify_auth(&mut transaction).await?;
    transaction.commit().await?;
    get_user_attributes(pool, user_id).await
}

fn validate_attribute_value(
    definition: &sqlx::postgres::PgRow,
    value: &str,
) -> Result<(), AdminError> {
    let name: String = definition.try_get("name")?;
    let attribute_type: String = definition.try_get("type")?;
    let required: bool = definition.try_get("required")?;
    let options: Value = definition.try_get("options")?;
    let validation: Value = definition.try_get("validation")?;
    if value.is_empty() {
        if required {
            return Err(AdminError::BadRequest(format!("{name} is required")));
        }
        return Ok(());
    }
    let rules = validation.as_object();
    if let Some(minimum) = rules
        .and_then(|rules| rules.get("min_length"))
        .and_then(Value::as_u64)
        && value.chars().count() < usize::try_from(minimum).unwrap_or(usize::MAX)
    {
        return Err(AdminError::BadRequest(format!("{name} is too short")));
    }
    if let Some(maximum) = rules
        .and_then(|rules| rules.get("max_length"))
        .and_then(Value::as_u64)
        && value.chars().count() > usize::try_from(maximum).unwrap_or(usize::MAX)
    {
        return Err(AdminError::BadRequest(format!("{name} is too long")));
    }
    if attribute_type == "number" {
        let number = value
            .parse::<i64>()
            .map_err(|_| AdminError::BadRequest(format!("{name} must be a number")))?;
        if rules
            .and_then(|rules| rules.get("min"))
            .and_then(Value::as_i64)
            .is_some_and(|minimum| number < minimum)
        {
            return Err(AdminError::BadRequest(format!(
                "{name} is below its minimum"
            )));
        }
        if rules
            .and_then(|rules| rules.get("max"))
            .and_then(Value::as_i64)
            .is_some_and(|maximum| number > maximum)
        {
            return Err(AdminError::BadRequest(format!(
                "{name} exceeds its maximum"
            )));
        }
    }
    if let Some(pattern) = rules
        .and_then(|rules| rules.get("pattern"))
        .and_then(Value::as_str)
        .filter(|pattern| !pattern.trim().is_empty())
    {
        let regex = Regex::new(pattern)
            .map_err(|_| AdminError::BadRequest(format!("{name} has an invalid pattern")))?;
        if !regex.is_match(value) {
            let message = rules
                .and_then(|rules| rules.get("message"))
                .and_then(Value::as_str)
                .filter(|message| !message.is_empty())
                .map_or_else(|| format!("{name} format is invalid"), ToOwned::to_owned);
            return Err(AdminError::BadRequest(message));
        }
    }
    if attribute_type == "select" {
        validate_selected_options(&name, &options, [value])?;
    } else if attribute_type == "multiselect" {
        let selected = serde_json::from_str::<Vec<String>>(value).unwrap_or_else(|_| {
            value
                .split(',')
                .map(|value| value.trim().to_owned())
                .collect()
        });
        validate_selected_options(&name, &options, selected.iter().map(String::as_str))?;
    }
    Ok(())
}

fn validate_selected_options<'a>(
    name: &str,
    options: &Value,
    selected: impl IntoIterator<Item = &'a str>,
) -> Result<(), AdminError> {
    let allowed = options
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|option| option.get("value").and_then(Value::as_str))
        .collect::<Vec<_>>();
    for selected in selected {
        if !allowed.contains(&selected.trim()) {
            return Err(AdminError::BadRequest(format!(
                "{name}: invalid option {selected}"
            )));
        }
    }
    Ok(())
}

async fn batch_user_attributes(pool: &PgPool, payload: &Value) -> Result<Value, AdminError> {
    let raw_ids = payload_object(payload)?
        .get("user_ids")
        .and_then(Value::as_array)
        .ok_or_else(|| AdminError::BadRequest("user_ids must be an array".to_owned()))?;
    let mut ids = Vec::new();
    for raw_id in raw_ids {
        if let Some(id) = raw_id.as_i64().filter(|id| *id > 0)
            && !ids.contains(&id)
        {
            ids.push(id);
        }
        if ids.len() > MAX_BATCH_ITEMS {
            return Err(AdminError::BadRequest("too many user ids".to_owned()));
        }
    }
    if ids.is_empty() {
        return Ok(json!({ "attributes": {} }));
    }
    let rows = sqlx::query(
        "SELECT user_id, attribute_id, value FROM user_attribute_values WHERE user_id = ANY($1) ORDER BY user_id, attribute_id",
    )
    .bind(&ids)
    .fetch_all(pool)
    .await?;
    let mut result = Map::new();
    for row in rows {
        let user_id = row.try_get::<i64, _>("user_id")?.to_string();
        let attribute_id = row.try_get::<i64, _>("attribute_id")?.to_string();
        let value: String = row.try_get("value")?;
        result
            .entry(user_id)
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .expect("batch attribute entry is an object")
            .insert(attribute_id, Value::String(value));
    }
    Ok(json!({ "attributes": result }))
}

fn validate_attribute_type(attribute_type: &str) -> Result<(), AdminError> {
    if ATTRIBUTE_TYPES.contains(&attribute_type) {
        Ok(())
    } else {
        Err(AdminError::BadRequest("invalid attribute type".to_owned()))
    }
}

fn validate_attribute_pattern(name: &str, validation: &Value) -> Result<(), AdminError> {
    if let Some(pattern) = validation
        .get("pattern")
        .and_then(Value::as_str)
        .filter(|pattern| !pattern.trim().is_empty())
    {
        Regex::new(pattern).map_err(|error| {
            AdminError::BadRequest(format!("invalid pattern for {name}: {error}"))
        })?;
    }
    Ok(())
}

fn optional_string(value: Option<&Value>, field: &str) -> Result<Option<String>, AdminError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(AdminError::BadRequest(format!("{field} must be a string"))),
    }
}

fn string_or_default(value: Option<&Value>, field: &str) -> Result<String, AdminError> {
    optional_string(value, field).map(Option::unwrap_or_default)
}

fn optional_bool(value: Option<&Value>, field: &str) -> Result<Option<bool>, AdminError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(AdminError::BadRequest(format!("{field} must be a boolean"))),
    }
}

fn bool_or_default(value: Option<&Value>, field: &str) -> Result<bool, AdminError> {
    optional_bool(value, field).map(Option::unwrap_or_default)
}

fn optional_json_array(value: Option<&Value>, field: &str) -> Result<Option<Value>, AdminError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value @ Value::Array(_)) => Ok(Some(value.clone())),
        Some(_) => Err(AdminError::BadRequest(format!("{field} must be an array"))),
    }
}

fn json_array_or_default(value: Option<&Value>, field: &str) -> Result<Value, AdminError> {
    optional_json_array(value, field).map(|value| value.unwrap_or_else(|| json!([])))
}

fn json_object_or_default(value: Option<&Value>, field: &str) -> Result<Value, AdminError> {
    optional_json_object(value, field).map(|value| value.unwrap_or_else(|| json!({})))
}

async fn moderation_config(pool: &PgPool) -> Result<Value, AdminError> {
    let config = load_moderation_config(pool).await?;
    Ok(moderation_config_view(&config))
}

#[allow(clippy::too_many_lines)]
async fn update_moderation_config(pool: &PgPool, payload: &Value) -> Result<Value, AdminError> {
    let patch = payload_object(payload)?;
    let mut config = load_moderation_config(pool).await?;
    {
        let object = config
            .as_object_mut()
            .expect("moderation defaults and stored config are objects");
        for field in [
            "enabled",
            "mode",
            "base_url",
            "model",
            "timeout_ms",
            "sample_rate",
            "all_groups",
            "group_ids",
            "record_non_hits",
            "thresholds",
            "worker_count",
            "queue_size",
            "block_status",
            "block_message",
            "email_on_hit",
            "auto_ban_enabled",
            "ban_threshold",
            "violation_window_hours",
            "cyber_policy_exclude_from_ban_count",
            "retry_count",
            "hit_retention_days",
            "non_hit_retention_days",
            "pre_hash_check_enabled",
            "blocked_keywords",
            "keyword_blocking_mode",
            "model_filter",
        ] {
            if let Some(value) = patch.get(field) {
                object.insert(field.to_owned(), value.clone());
            }
        }
    }

    let mut api_keys = moderation_api_keys(&config);
    if patch
        .get("clear_api_key")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        api_keys.clear();
    }
    if let Some(delete_hashes) = patch.get("delete_api_key_hashes") {
        let delete_hashes = delete_hashes.as_array().ok_or_else(|| {
            AdminError::BadRequest("delete_api_key_hashes must be an array".to_owned())
        })?;
        api_keys.retain(|key| {
            let hash = secret_hash(key);
            !delete_hashes
                .iter()
                .filter_map(Value::as_str)
                .any(|candidate| candidate.eq_ignore_ascii_case(&hash))
        });
    }
    let mut supplied = Vec::new();
    if let Some(value) = patch.get("api_key").filter(|value| !value.is_null()) {
        let key = value
            .as_str()
            .ok_or_else(|| AdminError::BadRequest("api_key must be a string".to_owned()))?;
        if !key.trim().is_empty() {
            supplied.push(key.trim().to_owned());
        }
    }
    if let Some(values) = patch.get("api_keys").filter(|value| !value.is_null()) {
        let values = values
            .as_array()
            .ok_or_else(|| AdminError::BadRequest("api_keys must be an array".to_owned()))?;
        for value in values {
            let key = value
                .as_str()
                .map(str::trim)
                .filter(|key| !key.is_empty())
                .ok_or_else(|| {
                    AdminError::BadRequest("api_keys must contain non-empty strings".to_owned())
                })?;
            supplied.push(key.to_owned());
        }
    }
    if !supplied.is_empty() {
        if patch.get("api_keys_mode").and_then(Value::as_str) == Some("replace") {
            api_keys.clear();
        }
        api_keys.extend(supplied);
    }
    normalize_string_list(&mut api_keys, 100);
    config
        .as_object_mut()
        .expect("moderation config is an object")
        .remove("api_key");
    config
        .as_object_mut()
        .expect("moderation config is an object")
        .insert("api_keys".to_owned(), json!(api_keys));
    validate_moderation_config(&config)?;

    let serialized = config.to_string();
    let mut transaction = pool.begin().await?;
    sqlx::query(
        r"
INSERT INTO settings (key, value, updated_at)
VALUES ('content_moderation_config', $1, NOW())
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
",
    )
    .bind(serialized)
    .execute(&mut *transaction)
    .await?;
    notify_settings(&mut transaction).await?;
    transaction.commit().await?;
    Ok(moderation_config_view(&config))
}

async fn load_moderation_config(pool: &PgPool) -> Result<Value, AdminError> {
    let mut config = default_moderation_config();
    if let Some(raw) = sqlx::query_scalar::<_, String>(
        "SELECT value FROM settings WHERE key = 'content_moderation_config'",
    )
    .fetch_optional(pool)
    .await?
    .filter(|raw| !raw.trim().is_empty())
    {
        let stored: Value = serde_json::from_str(&raw).map_err(|_| {
            AdminError::BadRequest("stored content moderation config is invalid JSON".to_owned())
        })?;
        let stored = stored.as_object().ok_or_else(|| {
            AdminError::BadRequest("stored content moderation config must be an object".to_owned())
        })?;
        config
            .as_object_mut()
            .expect("default moderation config is an object")
            .extend(stored.clone());
    }
    let keys = moderation_api_keys(&config);
    config
        .as_object_mut()
        .expect("moderation config is an object")
        .insert("api_keys".to_owned(), json!(keys));
    Ok(config)
}

fn default_moderation_config() -> Value {
    json!({
        "enabled": false,
        "mode": "pre_block",
        "base_url": "https://api.openai.com",
        "model": "omni-moderation-latest",
        "api_keys": [],
        "timeout_ms": 3000,
        "sample_rate": 100,
        "all_groups": true,
        "group_ids": [],
        "record_non_hits": false,
        "thresholds": {
            "harassment": 0.98,
            "harassment/threatening": 0.90,
            "hate": 0.65,
            "hate/threatening": 0.65,
            "illicit": 0.95,
            "illicit/violent": 0.95,
            "self-harm": 0.65,
            "self-harm/intent": 0.85,
            "self-harm/instructions": 0.65,
            "sexual": 0.65,
            "sexual/minors": 0.65,
            "violence": 0.95,
            "violence/graphic": 0.95
        },
        "worker_count": 4,
        "queue_size": 32768,
        "block_status": 403,
        "block_message": "content was blocked by the configured risk-control policy",
        "email_on_hit": true,
        "auto_ban_enabled": true,
        "ban_threshold": 10,
        "violation_window_hours": 720,
        "cyber_policy_exclude_from_ban_count": false,
        "retry_count": 2,
        "hit_retention_days": 180,
        "non_hit_retention_days": 3,
        "pre_hash_check_enabled": false,
        "blocked_keywords": [],
        "keyword_blocking_mode": "keyword_and_api",
        "model_filter": { "type": "all", "models": [] }
    })
}

fn moderation_api_keys(config: &Value) -> Vec<String> {
    let mut keys = config
        .get("api_keys")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if let Some(key) = config
        .get("api_key")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|key| !key.is_empty())
    {
        keys.push(key.to_owned());
    }
    normalize_string_list(&mut keys, 100);
    keys
}

fn normalize_string_list(values: &mut Vec<String>, limit: usize) {
    let mut normalized = Vec::with_capacity(values.len().min(limit));
    for value in values.drain(..) {
        let value = value.trim();
        if !value.is_empty() && !normalized.iter().any(|existing| existing == value) {
            normalized.push(value.to_owned());
        }
        if normalized.len() == limit {
            break;
        }
    }
    *values = normalized;
}

fn validate_moderation_config(config: &Value) -> Result<(), AdminError> {
    let object = config
        .as_object()
        .ok_or_else(|| AdminError::BadRequest("moderation config must be an object".to_owned()))?;
    let mode = object
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !matches!(mode, "off" | "observe" | "pre_block") {
        return Err(AdminError::BadRequest("invalid moderation mode".to_owned()));
    }
    let base_url = object
        .get("base_url")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let parsed = url::Url::parse(base_url)
        .map_err(|_| AdminError::BadRequest("invalid moderation base_url".to_owned()))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(AdminError::BadRequest(
            "moderation base_url must use HTTP or HTTPS".to_owned(),
        ));
    }
    bounded_config_integer(object, "timeout_ms", 100, 30_000)?;
    bounded_config_integer(object, "sample_rate", 0, 100)?;
    bounded_config_integer(object, "worker_count", 1, 32)?;
    bounded_config_integer(object, "queue_size", 1, 100_000)?;
    bounded_config_integer(object, "block_status", 400, 599)?;
    bounded_config_integer(object, "retry_count", 0, 5)?;
    bounded_config_integer(object, "hit_retention_days", 1, 3_650)?;
    bounded_config_integer(object, "non_hit_retention_days", 1, 3)?;
    if let Some(groups) = object.get("group_ids")
        && !groups.is_array()
    {
        return Err(AdminError::BadRequest(
            "group_ids must be an array".to_owned(),
        ));
    }
    if let Some(keywords) = object.get("blocked_keywords")
        && keywords
            .as_array()
            .is_none_or(|keywords| keywords.len() > 10_000)
    {
        return Err(AdminError::BadRequest(
            "blocked_keywords must be an array with at most 10000 items".to_owned(),
        ));
    }
    let keyword_mode = object
        .get("keyword_blocking_mode")
        .and_then(Value::as_str)
        .unwrap_or("keyword_and_api");
    if !matches!(
        keyword_mode,
        "keyword_only" | "keyword_and_api" | "api_only"
    ) {
        return Err(AdminError::BadRequest(
            "invalid keyword_blocking_mode".to_owned(),
        ));
    }
    if let Some(filter) = object.get("model_filter").and_then(Value::as_object) {
        let filter_type = filter.get("type").and_then(Value::as_str).unwrap_or("all");
        if !matches!(filter_type, "all" | "include" | "exclude") {
            return Err(AdminError::BadRequest(
                "invalid model_filter type".to_owned(),
            ));
        }
        if filter_type != "all"
            && filter
                .get("models")
                .and_then(Value::as_array)
                .is_none_or(Vec::is_empty)
        {
            return Err(AdminError::BadRequest(
                "model_filter models cannot be empty".to_owned(),
            ));
        }
    }
    Ok(())
}

fn bounded_config_integer(
    object: &Map<String, Value>,
    field: &str,
    minimum: i64,
    maximum: i64,
) -> Result<(), AdminError> {
    let value = object
        .get(field)
        .and_then(Value::as_i64)
        .ok_or_else(|| AdminError::BadRequest(format!("{field} must be an integer")))?;
    if (minimum..=maximum).contains(&value) {
        Ok(())
    } else {
        Err(AdminError::BadRequest(format!(
            "{field} must be between {minimum} and {maximum}"
        )))
    }
}

fn moderation_config_view(config: &Value) -> Value {
    let keys = moderation_api_keys(config);
    let masks = keys.iter().map(|key| mask_secret(key)).collect::<Vec<_>>();
    let statuses = keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            json!({
                "index": index,
                "key_hash": secret_hash(key),
                "masked": mask_secret(key),
                "status": "configured",
                "failure_count": 0,
                "success_count": 0,
                "last_error": "",
                "last_latency_ms": 0,
                "last_http_status": 0,
                "last_tested": false,
                "configured": true
            })
        })
        .collect::<Vec<_>>();
    let mut view = config.clone();
    let object = view
        .as_object_mut()
        .expect("moderation config view is an object");
    object.remove("api_key");
    object.remove("api_keys");
    object.insert("api_key_configured".to_owned(), json!(!keys.is_empty()));
    object.insert(
        "api_key_masked".to_owned(),
        json!(masks.first().cloned().unwrap_or_default()),
    );
    object.insert("api_key_count".to_owned(), json!(keys.len()));
    object.insert("api_key_masks".to_owned(), json!(masks));
    object.insert("api_key_statuses".to_owned(), json!(statuses));
    view
}

#[allow(clippy::too_many_lines)]
async fn test_moderation_api_keys(payload: &Value) -> Result<Value, AdminError> {
    let object = payload_object(payload)?;
    let keys = object
        .get("api_keys")
        .and_then(Value::as_array)
        .ok_or_else(|| AdminError::BadRequest("api_keys must be an array".to_owned()))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::trim)
                .filter(|key| !key.is_empty())
                .map(ToOwned::to_owned)
                .ok_or_else(|| {
                    AdminError::BadRequest("api_keys contains an invalid key".to_owned())
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if keys.is_empty() || keys.len() > 20 {
        return Err(AdminError::BadRequest(
            "api_keys must contain between 1 and 20 keys".to_owned(),
        ));
    }
    let base_url = object
        .get("base_url")
        .and_then(Value::as_str)
        .unwrap_or("https://api.openai.com");
    let endpoint = moderation_endpoint(base_url)?;
    let validated = validate_public_probe_target(endpoint.as_str()).await?;
    let host = endpoint
        .host_str()
        .ok_or_else(|| AdminError::BadRequest("moderation host is required".to_owned()))?;
    let timeout_ms = object
        .get("timeout_ms")
        .and_then(Value::as_u64)
        .unwrap_or(3_000)
        .clamp(100, 30_000);
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_millis(timeout_ms))
        .resolve_to_addrs(host, validated.resolved_addresses())
        .build()
        .map_err(|error| AdminError::Probe(format!("build moderation test client: {error}")))?;
    let model = object
        .get("model")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|model| !model.is_empty())
        .unwrap_or("omni-moderation-latest")
        .to_owned();
    let prompt = object
        .get("prompt")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|prompt| !prompt.is_empty())
        .unwrap_or("This is a content moderation connectivity test.")
        .chars()
        .take(12_000)
        .collect::<String>();
    let images = object
        .get("images")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .take(1)
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    let input = if images.is_empty() {
        Value::String(prompt)
    } else {
        let mut parts = vec![json!({ "type": "text", "text": prompt })];
        parts.extend(
            images
                .iter()
                .map(|image| json!({ "type": "image_url", "image_url": { "url": image } })),
        );
        Value::Array(parts)
    };
    let request_body = json!({ "model": model, "input": input });
    let endpoint = endpoint.to_string();
    let items = stream::iter(keys.into_iter().enumerate().map(|(index, key)| {
        let client = client.clone();
        let endpoint = endpoint.clone();
        let request_body = request_body.clone();
        async move {
            let started = Instant::now();
            let result = client
                .post(endpoint)
                .bearer_auth(&key)
                .json(&request_body)
                .send()
                .await;
            let latency = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
            match result {
                Ok(response) => {
                    let status = response.status();
                    json!({
                        "index": index,
                        "key_hash": secret_hash(&key),
                        "masked": mask_secret(&key),
                        "status": if status.is_success() { "active" } else { "failed" },
                        "failure_count": usize::from(!status.is_success()),
                        "success_count": usize::from(status.is_success()),
                        "last_error": if status.is_success() { String::new() } else { format!("HTTP {}", status.as_u16()) },
                        "last_checked_at": Utc::now().to_rfc3339(),
                        "last_latency_ms": latency,
                        "last_http_status": status.as_u16(),
                        "last_tested": true,
                        "configured": true
                    })
                }
                Err(error) => json!({
                    "index": index,
                    "key_hash": secret_hash(&key),
                    "masked": mask_secret(&key),
                    "status": "failed",
                    "failure_count": 1,
                    "success_count": 0,
                    "last_error": error.to_string(),
                    "last_checked_at": Utc::now().to_rfc3339(),
                    "last_latency_ms": latency,
                    "last_http_status": 0,
                    "last_tested": true,
                    "configured": true
                }),
            }
        }
    }))
    .buffer_unordered(4)
    .collect::<Vec<_>>()
    .await;
    Ok(json!({
        "items": items,
        "image_count": images.len()
    }))
}

fn moderation_endpoint(base_url: &str) -> Result<url::Url, AdminError> {
    let mut endpoint = url::Url::parse(base_url.trim())
        .map_err(|_| AdminError::BadRequest("invalid moderation base_url".to_owned()))?;
    if !matches!(endpoint.scheme(), "http" | "https") {
        return Err(AdminError::BadRequest(
            "moderation base_url must use HTTP or HTTPS".to_owned(),
        ));
    }
    if !endpoint
        .path()
        .trim_end_matches('/')
        .ends_with("/moderations")
    {
        let current = endpoint.path().trim_end_matches('/');
        let path = if current.ends_with("/v1") {
            format!("{current}/moderations")
        } else {
            format!("{current}/v1/moderations")
        };
        endpoint.set_path(&path);
    }
    endpoint.set_query(None);
    endpoint.set_fragment(None);
    Ok(endpoint)
}

fn secret_hash(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

fn mask_secret(secret: &str) -> String {
    let chars = secret.chars().collect::<Vec<_>>();
    if chars.len() <= 8 {
        return "****".to_owned();
    }
    format!(
        "{}****{}",
        chars.iter().take(4).collect::<String>(),
        chars.iter().skip(chars.len() - 4).collect::<String>()
    )
}

async fn delete_flagged_hash(pool: &PgPool, payload: &Value) -> Result<Value, AdminError> {
    let input_hash =
        required_trimmed_string(payload_object(payload)?, "input_hash")?.to_lowercase();
    validate_sha256_hex(&input_hash)?;
    let deleted =
        sqlx::query("DELETE FROM content_moderation_flagged_hashes WHERE input_hash = $1")
            .bind(&input_hash)
            .execute(pool)
            .await?
            .rows_affected()
            > 0;
    Ok(json!({ "input_hash": input_hash, "deleted": deleted }))
}

async fn clear_flagged_hashes(pool: &PgPool) -> Result<Value, AdminError> {
    let deleted = sqlx::query("DELETE FROM content_moderation_flagged_hashes")
        .execute(pool)
        .await?
        .rows_affected();
    Ok(json!({ "deleted": deleted }))
}

fn validate_sha256_hex(value: &str) -> Result<(), AdminError> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(AdminError::BadRequest(
            "input_hash must be a 64-character SHA-256 hex digest".to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    #[test]
    fn provider_key_normalization_preserves_wechat_compatibility() {
        assert_eq!(canonical_provider_key("wechat", "wechat"), "wechat-main");
        assert_eq!(
            canonical_provider_key("wechat", "mini-program"),
            "mini-program"
        );
        assert_eq!(
            compatible_provider_keys("wechat", "mini-program"),
            ["mini-program", "wechat-main", "wechat"]
        );
        assert_eq!(compatible_provider_keys("oidc", "issuer"), ["issuer"]);
    }

    #[test]
    fn moderation_view_never_returns_raw_api_keys() {
        let mut config = default_moderation_config();
        config
            .as_object_mut()
            .unwrap()
            .insert("api_keys".to_owned(), json!(["sk-test-secret-value"]));
        let view = moderation_config_view(&config);
        let encoded = view.to_string();
        assert!(!encoded.contains("sk-test-secret-value"));
        assert_eq!(view["api_key_configured"], true);
        assert_eq!(view["api_key_count"], 1);
        assert_eq!(view["api_key_masked"], "sk-t****alue");
    }

    #[test]
    fn moderation_config_rejects_unsafe_or_incoherent_values() {
        let mut config = default_moderation_config();
        assert!(validate_moderation_config(&config).is_ok());
        config["mode"] = json!("unknown");
        assert!(validate_moderation_config(&config).is_err());
        config = default_moderation_config();
        config["base_url"] = json!("file:///etc/passwd");
        assert!(validate_moderation_config(&config).is_err());
        config = default_moderation_config();
        config["block_status"] = json!(200);
        assert!(validate_moderation_config(&config).is_err());
        config = default_moderation_config();
        config["model_filter"] = json!({ "type": "include", "models": [] });
        assert!(validate_moderation_config(&config).is_err());
    }

    #[test]
    fn moderation_endpoint_keeps_origin_and_normalizes_path() {
        assert_eq!(
            moderation_endpoint("https://api.openai.com")
                .unwrap()
                .as_str(),
            "https://api.openai.com/v1/moderations"
        );
        assert_eq!(
            moderation_endpoint("https://example.com/custom/v1/")
                .unwrap()
                .as_str(),
            "https://example.com/custom/v1/moderations"
        );
        assert!(moderation_endpoint("file:///tmp/config").is_err());
    }

    #[test]
    fn destructive_hash_and_attribute_inputs_are_validated() {
        assert!(validate_sha256_hex(&"a".repeat(64)).is_ok());
        assert!(validate_sha256_hex(&"z".repeat(64)).is_err());
        assert!(validate_sha256_hex("abcd").is_err());
        assert!(validate_attribute_type("multiselect").is_ok());
        assert!(validate_attribute_type("script").is_err());
        assert!(
            validate_attribute_pattern("department", &json!({ "pattern": "^[a-z]+$" })).is_ok()
        );
        assert!(validate_attribute_pattern("department", &json!({ "pattern": "[" })).is_err());
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL pointing at a migrated disposable *_test database"]
    #[allow(clippy::too_many_lines)]
    async fn postgres_group_overrides_quotas_and_flagged_hashes_are_durable() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL must point at a disposable *_test database");
        let parsed = url::Url::parse(&database_url).expect("TEST_DATABASE_URL must be valid");
        assert!(
            parsed.path().trim_matches('/').ends_with("_test"),
            "refusing to mutate a database without an _test suffix"
        );
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .expect("connect disposable PostgreSQL");
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let group_id = sqlx::query_scalar::<_, i64>(
            "INSERT INTO groups (name, subscription_type) VALUES ($1, 'standard') RETURNING id",
        )
        .bind(format!("rust-admin-semantics-{suffix}"))
        .fetch_one(&pool)
        .await
        .expect("insert group fixture");
        let first_user = sqlx::query_scalar::<_, i64>(
            "INSERT INTO users (email, password_hash) VALUES ($1, 'unused') RETURNING id",
        )
        .bind(format!("rust-admin-a-{suffix}@example.com"))
        .fetch_one(&pool)
        .await
        .expect("insert first user fixture");
        let second_user = sqlx::query_scalar::<_, i64>(
            "INSERT INTO users (email, password_hash) VALUES ($1, 'unused') RETURNING id",
        )
        .bind(format!("rust-admin-b-{suffix}@example.com"))
        .fetch_one(&pool)
        .await
        .expect("insert second user fixture");

        sync_group_rpm(
            &pool,
            group_id,
            &json!({
                "entries": [
                    { "user_id": first_user, "rpm_override": 60 },
                    { "user_id": second_user, "rpm_override": 120 }
                ]
            }),
        )
        .await
        .expect("set RPM overrides");
        sync_group_rates(
            &pool,
            group_id,
            &json!({
                "entries": [{ "user_id": first_user, "rate_multiplier": 1.5 }]
            }),
        )
        .await
        .expect("set rate multiplier without destroying RPM overrides");
        let overrides = sqlx::query_as::<_, (i64, Option<f64>, Option<i32>)>(
            r"
SELECT user_id, rate_multiplier::double precision, rpm_override
FROM user_group_rate_multipliers
WHERE group_id = $1
ORDER BY user_id
",
        )
        .bind(group_id)
        .fetch_all(&pool)
        .await
        .expect("load combined group overrides");
        assert_eq!(
            overrides,
            vec![
                (first_user, Some(1.5), Some(60)),
                (second_user, None, Some(120)),
            ]
        );

        sync_group_rpm(
            &pool,
            group_id,
            &json!({
                "entries": [{ "user_id": second_user, "rpm_override": 240 }]
            }),
        )
        .await
        .expect("replace RPM overrides without destroying rate multipliers");
        let overrides = sqlx::query_as::<_, (i64, Option<f64>, Option<i32>)>(
            r"
SELECT user_id, rate_multiplier::double precision, rpm_override
FROM user_group_rate_multipliers
WHERE group_id = $1
ORDER BY user_id
",
        )
        .bind(group_id)
        .fetch_all(&pool)
        .await
        .expect("load replaced group overrides");
        assert_eq!(
            overrides,
            vec![
                (first_user, Some(1.5), None),
                (second_user, None, Some(240)),
            ]
        );
        clear_group_rpm(&pool, group_id)
            .await
            .expect("clear RPM overrides");
        let rate_only = sqlx::query_as::<_, (i64, Option<f64>, Option<i32>)>(
            "SELECT user_id, rate_multiplier::double precision, rpm_override FROM user_group_rate_multipliers WHERE group_id = $1",
        )
        .bind(group_id)
        .fetch_all(&pool)
        .await
        .expect("load rate-only override");
        assert_eq!(rate_only, vec![(first_user, Some(1.5), None)]);

        replace_platform_quotas(
            &pool,
            first_user,
            &json!({
                "quotas": [
                    {
                        "platform": "openai",
                        "daily_limit_usd": 3.0,
                        "weekly_limit_usd": 20.0,
                        "monthly_limit_usd": 70.0
                    },
                    { "platform": "gemini", "daily_limit_usd": 4.0 }
                ]
            }),
        )
        .await
        .expect("create platform quotas");
        sqlx::query(
            r"
UPDATE user_platform_quotas
SET daily_usage_usd = 9, weekly_usage_usd = 10, monthly_usage_usd = 11,
    daily_window_start = NOW(), weekly_window_start = NOW(), monthly_window_start = NOW()
WHERE user_id = $1 AND platform = 'openai' AND deleted_at IS NULL
",
        )
        .bind(first_user)
        .execute(&pool)
        .await
        .expect("seed quota usage");
        replace_platform_quotas(
            &pool,
            first_user,
            &json!({
                "quotas": [{
                    "platform": "openai",
                    "daily_limit_usd": 5.5,
                    "weekly_limit_usd": 25.0,
                    "monthly_limit_usd": null
                }]
            }),
        )
        .await
        .expect("replace platform quotas");
        let active_quotas = sqlx::query_as::<_, (String, Option<f64>, f64)>(
            r"
SELECT platform, daily_limit_usd::double precision, daily_usage_usd::double precision
FROM user_platform_quotas
WHERE user_id = $1 AND deleted_at IS NULL
ORDER BY platform
",
        )
        .bind(first_user)
        .fetch_all(&pool)
        .await
        .expect("load active quotas");
        assert_eq!(active_quotas, vec![("openai".to_owned(), Some(5.5), 9.0)]);
        let deleted_gemini = sqlx::query_scalar::<_, bool>(
            "SELECT deleted_at IS NOT NULL FROM user_platform_quotas WHERE user_id = $1 AND platform = 'gemini' ORDER BY id DESC LIMIT 1",
        )
        .bind(first_user)
        .fetch_one(&pool)
        .await
        .expect("load omitted quota state");
        assert!(deleted_gemini);
        reset_platform_quota(
            &pool,
            first_user,
            &json!({ "platform": "openai", "window": "daily" }),
        )
        .await
        .expect("reset daily platform quota window");
        let usage = sqlx::query_as::<_, (f64, f64, bool)>(
            r"
SELECT daily_usage_usd::double precision,
       weekly_usage_usd::double precision,
       daily_window_start IS NOT NULL
FROM user_platform_quotas
WHERE user_id = $1 AND platform = 'openai' AND deleted_at IS NULL
",
        )
        .bind(first_user)
        .fetch_one(&pool)
        .await
        .expect("load reset quota usage");
        assert_eq!(usage, (0.0, 10.0, true));

        clear_flagged_hashes(&pool)
            .await
            .expect("start with no flagged hashes");
        let first_hash = "a".repeat(64);
        let second_hash = "b".repeat(64);
        sqlx::query("INSERT INTO content_moderation_flagged_hashes (input_hash) VALUES ($1), ($2)")
            .bind(&first_hash)
            .bind(&second_hash)
            .execute(&pool)
            .await
            .expect("insert flagged hashes");
        let deleted = delete_flagged_hash(&pool, &json!({ "input_hash": first_hash }))
            .await
            .expect("delete one flagged hash");
        assert_eq!(deleted["deleted"], true);
        let cleared = clear_flagged_hashes(&pool)
            .await
            .expect("clear remaining flagged hashes");
        assert_eq!(cleared["deleted"], 1);

        clear_group_rates(&pool, group_id)
            .await
            .expect("clear group rate fixtures");
        sqlx::query("DELETE FROM groups WHERE id = $1")
            .bind(group_id)
            .execute(&pool)
            .await
            .expect("delete group fixture");
        sqlx::query("DELETE FROM users WHERE id = ANY($1)")
            .bind(vec![first_user, second_user])
            .execute(&pool)
            .await
            .expect("delete user fixtures");
        pool.close().await;
    }
}
