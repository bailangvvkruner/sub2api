use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use super::authenticated_user;
use crate::control_api::{ApiEnvelope, ApiError, ControlApiState};

const DEFAULT_AFFILIATE_RATE_PERCENT: f64 = 20.0;
const MAX_AFFILIATE_INVITEES: i64 = 100;

pub(super) fn routes() -> Router<ControlApiState> {
    Router::new()
        .route("/api/v1/user/aff", get(affiliate_detail))
        .route("/api/v1/user/aff/transfer", post(transfer_affiliate_quota))
        .route("/api/v1/user/platform-quotas", get(platform_quotas))
        .route(
            "/api/v1/user/api-keys/{id}/usage/daily",
            get(api_key_daily_usage),
        )
}

#[derive(Debug, Serialize)]
struct AffiliateDetail {
    user_id: i64,
    aff_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    inviter_id: Option<i64>,
    aff_count: i32,
    aff_quota: f64,
    aff_frozen_quota: f64,
    aff_history_quota: f64,
    effective_rebate_rate_percent: f64,
    invitees: Vec<AffiliateInvitee>,
}

#[derive(Debug, Serialize)]
struct AffiliateInvitee {
    user_id: i64,
    email: String,
    username: String,
    created_at: String,
    total_rebate: f64,
}

struct AffiliateRow {
    user_id: i64,
    aff_code: String,
    inviter_id: Option<i64>,
    aff_count: i32,
    aff_quota: f64,
    aff_frozen_quota: f64,
    aff_history_quota: f64,
    rate: Option<f64>,
}

async fn affiliate_detail(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
) -> Result<Json<ApiEnvelope<AffiliateDetail>>, ApiError> {
    let user = authenticated_user(&state, &headers).await?;
    let mut transaction = state.pool().begin().await?;
    ensure_affiliate(&mut transaction, user.id).await?;
    thaw_affiliate_quota(&mut transaction, user.id).await?;
    let affiliate = load_affiliate(&mut transaction, user.id).await?;
    transaction.commit().await?;

    let invitees = load_invitees(&state, user.id).await?;
    let global_rate = affiliate_global_rate(&state).await?;
    Ok(Json(ApiEnvelope::success(AffiliateDetail {
        user_id: affiliate.user_id,
        aff_code: affiliate.aff_code,
        inviter_id: affiliate.inviter_id,
        aff_count: affiliate.aff_count,
        aff_quota: affiliate.aff_quota,
        aff_frozen_quota: affiliate.aff_frozen_quota,
        aff_history_quota: affiliate.aff_history_quota,
        effective_rebate_rate_percent: affiliate.rate.unwrap_or(global_rate).clamp(0.0, 100.0),
        invitees,
    })))
}

async fn transfer_affiliate_quota(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
) -> Result<Json<ApiEnvelope<serde_json::Value>>, ApiError> {
    let user = authenticated_user(&state, &headers).await?;
    let mut transaction = state.pool().begin().await?;
    ensure_affiliate(&mut transaction, user.id).await?;
    thaw_affiliate_quota(&mut transaction, user.id).await?;

    let transferred = sqlx::query_scalar::<_, f64>(
        r"
WITH claimed AS (
    SELECT aff_quota::double precision AS amount
    FROM user_affiliates
    WHERE user_id = $1 AND aff_quota > 0
    FOR UPDATE
), cleared AS (
    UPDATE user_affiliates affiliate
    SET aff_quota = 0, updated_at = NOW()
    FROM claimed
    WHERE affiliate.user_id = $1
    RETURNING claimed.amount
)
SELECT amount FROM cleared
",
    )
    .bind(user.id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| ApiError::bad_request("No affiliate quota available to transfer"))?;

    let balance = sqlx::query_scalar::<_, f64>(
        r"
UPDATE users
SET balance = balance + $2::numeric,
    total_recharged = total_recharged + $2::numeric,
    updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL
RETURNING balance::double precision
",
    )
    .bind(user.id)
    .bind(transferred.to_string())
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| ApiError::not_found("User not found"))?;

    let snapshot = sqlx::query(
        r"
SELECT aff_quota::double precision AS aff_quota,
       aff_frozen_quota::double precision AS aff_frozen_quota,
       aff_history_quota::double precision AS aff_history_quota
FROM user_affiliates
WHERE user_id = $1
",
    )
    .bind(user.id)
    .fetch_one(&mut *transaction)
    .await?;
    sqlx::query(
        r"
INSERT INTO user_affiliate_ledger (
    user_id, action, amount, balance_after, aff_quota_after,
    aff_frozen_quota_after, aff_history_quota_after, created_at, updated_at
)
VALUES ($1, 'transfer', $2::numeric, $3::numeric, $4::numeric, $5::numeric,
        $6::numeric, NOW(), NOW())
",
    )
    .bind(user.id)
    .bind(transferred.to_string())
    .bind(balance.to_string())
    .bind(snapshot.try_get::<f64, _>("aff_quota")?.to_string())
    .bind(snapshot.try_get::<f64, _>("aff_frozen_quota")?.to_string())
    .bind(snapshot.try_get::<f64, _>("aff_history_quota")?.to_string())
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    state.invalidate_user_auth_cache().await;

    Ok(Json(ApiEnvelope::success(serde_json::json!({
        "transferred_quota": transferred,
        "balance": balance,
    }))))
}

async fn ensure_affiliate(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i64,
) -> Result<(), ApiError> {
    for _ in 0..3 {
        let code = Uuid::new_v4().simple().to_string()[..12].to_ascii_uppercase();
        let result = sqlx::query(
            r"
INSERT INTO user_affiliates (user_id, aff_code, created_at, updated_at)
VALUES ($1, $2, NOW(), NOW())
ON CONFLICT (user_id) DO NOTHING
",
        )
        .bind(user_id)
        .bind(code)
        .execute(&mut **transaction)
        .await;
        match result {
            Ok(_) => return Ok(()),
            Err(error)
                if error
                    .as_database_error()
                    .is_some_and(|db| db.code().as_deref() == Some("23505")) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(ApiError::internal(
        "create affiliate profile",
        "could not allocate a unique affiliate code",
    ))
}

async fn thaw_affiliate_quota(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i64,
) -> Result<(), ApiError> {
    let thawed = sqlx::query_scalar::<_, f64>(
        r"
WITH matured AS (
    UPDATE user_affiliate_ledger
    SET frozen_until = NULL, updated_at = NOW()
    WHERE user_id = $1 AND frozen_until IS NOT NULL AND frozen_until <= NOW()
    RETURNING amount
)
SELECT COALESCE(SUM(amount), 0)::double precision FROM matured
",
    )
    .bind(user_id)
    .fetch_one(&mut **transaction)
    .await?;
    if thawed > 0.0 {
        sqlx::query(
            r"
UPDATE user_affiliates
SET aff_quota = aff_quota + $2::numeric,
    aff_frozen_quota = GREATEST(aff_frozen_quota - $2::numeric, 0),
    updated_at = NOW()
WHERE user_id = $1
",
        )
        .bind(user_id)
        .bind(thawed.to_string())
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

async fn load_affiliate(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i64,
) -> Result<AffiliateRow, ApiError> {
    let row = sqlx::query(
        r"
SELECT user_id, aff_code, inviter_id, aff_count,
       aff_quota::double precision AS aff_quota,
       aff_frozen_quota::double precision AS aff_frozen_quota,
       aff_history_quota::double precision AS aff_history_quota,
       aff_rebate_rate_percent::double precision AS rate
FROM user_affiliates
WHERE user_id = $1
",
    )
    .bind(user_id)
    .fetch_one(&mut **transaction)
    .await?;
    Ok(AffiliateRow {
        user_id: row.try_get("user_id")?,
        aff_code: row.try_get("aff_code")?,
        inviter_id: row.try_get("inviter_id")?,
        aff_count: row.try_get("aff_count")?,
        aff_quota: row.try_get("aff_quota")?,
        aff_frozen_quota: row.try_get("aff_frozen_quota")?,
        aff_history_quota: row.try_get("aff_history_quota")?,
        rate: row.try_get("rate")?,
    })
}

async fn load_invitees(
    state: &ControlApiState,
    user_id: i64,
) -> Result<Vec<AffiliateInvitee>, ApiError> {
    let rows = sqlx::query(
        r#"
SELECT affiliate.user_id,
       COALESCE(invitee.email, '') AS email,
       COALESCE(invitee.username, '') AS username,
       to_char(affiliate.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
       COALESCE(SUM(ledger.amount), 0)::double precision AS total_rebate
FROM user_affiliates affiliate
LEFT JOIN users invitee ON invitee.id = affiliate.user_id
LEFT JOIN user_affiliate_ledger ledger
  ON ledger.user_id = $1 AND ledger.source_user_id = affiliate.user_id
 AND ledger.action = 'accrue'
WHERE affiliate.inviter_id = $1
GROUP BY affiliate.user_id, invitee.email, invitee.username, affiliate.created_at
ORDER BY affiliate.created_at DESC
LIMIT $2
"#,
    )
    .bind(user_id)
    .bind(MAX_AFFILIATE_INVITEES)
    .fetch_all(state.pool())
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(AffiliateInvitee {
                user_id: row.try_get("user_id")?,
                email: mask_email(&row.try_get::<String, _>("email")?),
                username: row.try_get("username")?,
                created_at: row.try_get("created_at")?,
                total_rebate: row.try_get("total_rebate")?,
            })
        })
        .collect()
}

async fn affiliate_global_rate(state: &ControlApiState) -> Result<f64, ApiError> {
    let raw = sqlx::query_scalar::<_, Option<String>>(
        "SELECT value FROM settings WHERE key = 'affiliate_rebate_rate'",
    )
    .fetch_optional(state.pool())
    .await?
    .flatten();
    Ok(raw
        .as_deref()
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite())
        .unwrap_or(DEFAULT_AFFILIATE_RATE_PERCENT))
}

fn mask_email(email: &str) -> String {
    let Some((local, domain)) = email.trim().split_once('@') else {
        return "***".to_owned();
    };
    let local = local
        .chars()
        .next()
        .map_or("***".to_owned(), |first| format!("{first}***"));
    let domain = domain.rsplit_once('.').map_or_else(
        || {
            domain
                .chars()
                .next()
                .map_or("***".to_owned(), |first| format!("{first}***"))
        },
        |(name, suffix)| {
            let name = name
                .chars()
                .next()
                .map_or("***".to_owned(), |first| format!("{first}***"));
            format!("{name}.{suffix}")
        },
    );
    format!("{local}@{domain}")
}

#[derive(Debug, Serialize)]
struct PlatformQuota {
    id: i64,
    user_id: i64,
    platform: String,
    daily_limit_usd: Option<f64>,
    weekly_limit_usd: Option<f64>,
    monthly_limit_usd: Option<f64>,
    daily_usage_usd: f64,
    weekly_usage_usd: f64,
    monthly_usage_usd: f64,
    daily_window_start: Option<String>,
    weekly_window_start: Option<String>,
    monthly_window_start: Option<String>,
}

async fn platform_quotas(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
) -> Result<Json<ApiEnvelope<serde_json::Value>>, ApiError> {
    let user = authenticated_user(&state, &headers).await?;
    let rows = sqlx::query(
        r#"
SELECT id, user_id, platform,
       daily_limit_usd::double precision AS daily_limit_usd,
       weekly_limit_usd::double precision AS weekly_limit_usd,
       monthly_limit_usd::double precision AS monthly_limit_usd,
       CASE WHEN daily_window_start IS NULL OR daily_window_start + INTERVAL '1 day' <= NOW()
            THEN 0 ELSE daily_usage_usd END::double precision AS daily_usage_usd,
       CASE WHEN weekly_window_start IS NULL OR weekly_window_start + INTERVAL '7 days' <= NOW()
            THEN 0 ELSE weekly_usage_usd END::double precision AS weekly_usage_usd,
       CASE WHEN monthly_window_start IS NULL OR monthly_window_start + INTERVAL '1 month' <= NOW()
            THEN 0 ELSE monthly_usage_usd END::double precision AS monthly_usage_usd,
       CASE WHEN daily_window_start IS NULL THEN NULL ELSE to_char(daily_window_start AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END AS daily_window_start,
       CASE WHEN weekly_window_start IS NULL THEN NULL ELSE to_char(weekly_window_start AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END AS weekly_window_start,
       CASE WHEN monthly_window_start IS NULL THEN NULL ELSE to_char(monthly_window_start AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END AS monthly_window_start
FROM user_platform_quotas
WHERE user_id = $1 AND deleted_at IS NULL
ORDER BY platform, id
"#,
    )
    .bind(user.id)
    .fetch_all(state.pool())
    .await?;
    let quotas = rows
        .into_iter()
        .map(|row| {
            Ok(PlatformQuota {
                id: row.try_get("id")?,
                user_id: row.try_get("user_id")?,
                platform: row.try_get("platform")?,
                daily_limit_usd: row.try_get("daily_limit_usd")?,
                weekly_limit_usd: row.try_get("weekly_limit_usd")?,
                monthly_limit_usd: row.try_get("monthly_limit_usd")?,
                daily_usage_usd: row.try_get("daily_usage_usd")?,
                weekly_usage_usd: row.try_get("weekly_usage_usd")?,
                monthly_usage_usd: row.try_get("monthly_usage_usd")?,
                daily_window_start: row.try_get("daily_window_start")?,
                weekly_window_start: row.try_get("weekly_window_start")?,
                monthly_window_start: row.try_get("monthly_window_start")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()?;
    Ok(Json(ApiEnvelope::success(serde_json::json!({
        "platform_quotas": quotas,
    }))))
}

#[derive(Debug, Default, Deserialize)]
struct DailyUsageQuery {
    days: Option<i32>,
    timezone: Option<String>,
}

#[derive(Debug, Serialize)]
struct DailyUsagePoint {
    date: String,
    requests: i64,
    input_tokens: i64,
    output_tokens: i64,
    cache_read_tokens: i64,
    cache_write_tokens: i64,
    total_tokens: i64,
    cost: f64,
    actual_cost: f64,
}

async fn api_key_daily_usage(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    Path(api_key_id): Path<i64>,
    Query(query): Query<DailyUsageQuery>,
) -> Result<Json<ApiEnvelope<serde_json::Value>>, ApiError> {
    let user = authenticated_user(&state, &headers).await?;
    let days = query.days.unwrap_or(30);
    if !(1..=90).contains(&days) {
        return Err(ApiError::bad_request("Invalid days, allowed range is 1-90"));
    }
    let owner = sqlx::query_scalar::<_, i64>(
        "SELECT user_id FROM api_keys WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(api_key_id)
    .fetch_optional(state.pool())
    .await?
    .ok_or_else(|| ApiError::not_found("API key not found"))?;
    if owner != user.id {
        return Err(ApiError::forbidden(
            "Not authorized to access this API key's usage",
            "API_KEY_OWNERSHIP_REQUIRED",
        ));
    }

    let timezone = validated_timezone(&state, query.timezone.as_deref()).await?;
    let rows = sqlx::query(
        r"
WITH bounds AS (
    SELECT date_trunc('day', NOW() AT TIME ZONE $4) - make_interval(days => $3 - 1) AS start_day,
           date_trunc('day', NOW() AT TIME ZONE $4) + INTERVAL '1 day' AS end_day
), days AS (
    SELECT generate_series(start_day, end_day - INTERVAL '1 day', INTERVAL '1 day') AS day
    FROM bounds
), aggregate AS (
    SELECT date_trunc('day', created_at AT TIME ZONE $4) AS day,
           COUNT(*)::bigint AS requests,
           COALESCE(SUM(input_tokens), 0)::bigint AS input_tokens,
           COALESCE(SUM(output_tokens), 0)::bigint AS output_tokens,
           COALESCE(SUM(cache_read_tokens), 0)::bigint AS cache_read_tokens,
           COALESCE(SUM(cache_creation_tokens), 0)::bigint AS cache_write_tokens,
           COALESCE(SUM(input_tokens + output_tokens + cache_read_tokens + cache_creation_tokens), 0)::bigint AS total_tokens,
           COALESCE(SUM(total_cost), 0)::double precision AS cost,
           COALESCE(SUM(actual_cost), 0)::double precision AS actual_cost
    FROM usage_logs, bounds
    WHERE user_id = $1 AND api_key_id = $2
      AND created_at >= start_day AT TIME ZONE $4
      AND created_at < end_day AT TIME ZONE $4
    GROUP BY 1
)
SELECT to_char(days.day, 'YYYY-MM-DD') AS date,
       COALESCE(aggregate.requests, 0)::bigint AS requests,
       COALESCE(aggregate.input_tokens, 0)::bigint AS input_tokens,
       COALESCE(aggregate.output_tokens, 0)::bigint AS output_tokens,
       COALESCE(aggregate.cache_read_tokens, 0)::bigint AS cache_read_tokens,
       COALESCE(aggregate.cache_write_tokens, 0)::bigint AS cache_write_tokens,
       COALESCE(aggregate.total_tokens, 0)::bigint AS total_tokens,
       COALESCE(aggregate.cost, 0)::double precision AS cost,
       COALESCE(aggregate.actual_cost, 0)::double precision AS actual_cost
FROM days
LEFT JOIN aggregate USING (day)
ORDER BY days.day
",
    )
    .bind(user.id)
    .bind(api_key_id)
    .bind(days)
    .bind(&timezone)
    .fetch_all(state.pool())
    .await?;
    let items = rows
        .into_iter()
        .map(|row| {
            Ok(DailyUsagePoint {
                date: row.try_get("date")?,
                requests: row.try_get("requests")?,
                input_tokens: row.try_get("input_tokens")?,
                output_tokens: row.try_get("output_tokens")?,
                cache_read_tokens: row.try_get("cache_read_tokens")?,
                cache_write_tokens: row.try_get("cache_write_tokens")?,
                total_tokens: row.try_get("total_tokens")?,
                cost: row.try_get("cost")?,
                actual_cost: row.try_get("actual_cost")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()?;
    let start_date = items
        .first()
        .map_or_else(String::new, |item| item.date.clone());
    let end_date = items
        .last()
        .map_or_else(String::new, |item| item.date.clone());
    Ok(Json(ApiEnvelope::success(serde_json::json!({
        "items": items,
        "days": days,
        "start_date": start_date,
        "end_date": end_date,
    }))))
}

async fn validated_timezone(
    state: &ControlApiState,
    requested: Option<&str>,
) -> Result<String, ApiError> {
    let requested = requested.unwrap_or("UTC").trim();
    if requested.is_empty() {
        return Ok("UTC".to_owned());
    }
    let valid = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM pg_timezone_names WHERE name = $1)",
    )
    .bind(requested)
    .fetch_one(state.pool())
    .await?;
    if valid {
        Ok(requested.to_owned())
    } else {
        Err(ApiError::bad_request("Invalid timezone"))
    }
}

#[cfg(test)]
mod tests {
    use super::mask_email;

    #[test]
    fn affiliate_invitee_email_is_masked() {
        assert_eq!(mask_email("alice@example.com"), "a***@e***.com");
        assert_eq!(mask_email("invalid"), "***");
    }
}
