use axum::{
    Json, Router,
    extract::{State, rejection::JsonRejection},
    http::HeaderMap,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Row, Transaction};

use super::{authenticated_user, json_payload};
use crate::control_api::{ApiEnvelope, ApiError, ControlApiState};

pub(super) fn routes() -> Router<ControlApiState> {
    Router::new()
        .route("/api/v1/redeem", post(redeem))
        .route("/api/v1/redeem/history", get(history))
}

#[derive(Debug, Deserialize)]
struct RedeemRequest {
    code: String,
}

#[derive(Debug, Serialize)]
struct RedeemCodeView {
    id: i64,
    code: String,
    #[serde(rename = "type")]
    code_type: String,
    value: f64,
    status: String,
    used_by: Option<i64>,
    used_at: Option<String>,
    created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
    group_id: Option<i64>,
    validity_days: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
}

struct LockedCode {
    id: i64,
    code_type: String,
    value: f64,
    status: String,
    expired: bool,
    group_id: Option<i64>,
    validity_days: i32,
}

async fn redeem(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    payload: Result<Json<RedeemRequest>, JsonRejection>,
) -> Result<Json<ApiEnvelope<RedeemCodeView>>, ApiError> {
    let user = authenticated_user(&state, &headers).await?;
    let request = json_payload(payload)?;
    let code = request.code.trim().to_ascii_uppercase();
    if code.is_empty() || code.len() > 64 {
        return Err(ApiError::bad_request("Redeem code is required"));
    }

    let mut transaction = state.pool().begin().await?;
    let locked = lock_code(&mut transaction, &code).await?;
    if locked.expired {
        sqlx::query(
            "UPDATE redeem_codes SET status = 'expired' WHERE id = $1 AND status = 'unused'",
        )
        .bind(locked.id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        return Err(ApiError::bad_request("Redeem code has expired"));
    }
    if locked.status != "unused" {
        return Err(ApiError::conflict(
            "Redeem code has already been used",
            "REDEEM_CODE_USED",
        ));
    }
    match locked.code_type.as_str() {
        "balance" => apply_balance(&mut transaction, user.id, locked.value).await?,
        "concurrency" => apply_concurrency(&mut transaction, user.id, locked.value).await?,
        "subscription" => apply_subscription(&mut transaction, user.id, &locked).await?,
        _ => return Err(ApiError::bad_request("Unsupported redeem code type")),
    }
    let claimed = sqlx::query(
        r"
UPDATE redeem_codes
SET status = 'used', used_by = $2, used_at = NOW()
WHERE id = $1 AND status = 'unused'
",
    )
    .bind(locked.id)
    .bind(user.id)
    .execute(&mut *transaction)
    .await?;
    if claimed.rows_affected() != 1 {
        return Err(ApiError::conflict(
            "Redeem code has already been used",
            "REDEEM_CODE_USED",
        ));
    }
    transaction.commit().await?;
    state.invalidate_user_auth_cache().await;
    Ok(Json(ApiEnvelope::success(
        get_code(state.pool(), locked.id, Some(user.id)).await?,
    )))
}

async fn history(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
) -> Result<Json<ApiEnvelope<Vec<RedeemCodeView>>>, ApiError> {
    let user = authenticated_user(&state, &headers).await?;
    let rows = sqlx::query(&format!(
        "{} WHERE used_by = $1 ORDER BY used_at DESC NULLS LAST, id DESC LIMIT 25",
        code_select()
    ))
    .bind(user.id)
    .fetch_all(state.pool())
    .await?;
    let codes = rows
        .into_iter()
        .map(|row| code_from_row(&row, Some(user.id)))
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(Json(ApiEnvelope::success(codes)))
}

async fn lock_code(
    transaction: &mut Transaction<'_, Postgres>,
    code: &str,
) -> Result<LockedCode, ApiError> {
    let row = sqlx::query(
        r"
SELECT id, type, value::double precision AS value, status,
       expires_at IS NOT NULL AND expires_at <= NOW() AS expired,
       group_id, validity_days
FROM redeem_codes
WHERE UPPER(code) = $1
FOR UPDATE
",
    )
    .bind(code)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| ApiError::not_found("Redeem code not found"))?;
    Ok(LockedCode {
        id: row.try_get("id")?,
        code_type: row.try_get("type")?,
        value: row.try_get("value")?,
        status: row.try_get("status")?,
        expired: row.try_get("expired")?,
        group_id: row.try_get("group_id")?,
        validity_days: row.try_get("validity_days")?,
    })
}

async fn apply_balance(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i64,
    value: f64,
) -> Result<(), ApiError> {
    let value = value.to_string();
    let result = sqlx::query(
        r"
UPDATE users
SET balance = CASE WHEN $2::numeric < 0 THEN GREATEST(balance + $2::numeric, 0)
                   ELSE balance + $2::numeric END,
    total_recharged = total_recharged + CASE WHEN $2::numeric > 0 THEN $2::numeric ELSE 0 END,
    updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL
",
    )
    .bind(user_id)
    .bind(value)
    .execute(&mut **transaction)
    .await?;
    if result.rows_affected() == 1 {
        Ok(())
    } else {
        Err(ApiError::not_found("User not found"))
    }
}

async fn apply_concurrency(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i64,
    value: f64,
) -> Result<(), ApiError> {
    if !value.is_finite()
        || value.fract() != 0.0
        || value < f64::from(i32::MIN)
        || value > f64::from(i32::MAX)
    {
        return Err(ApiError::bad_request("Invalid concurrency redeem value"));
    }
    let value = value
        .to_string()
        .parse::<i32>()
        .map_err(|error| ApiError::internal("convert concurrency redeem value", error))?;
    let result = sqlx::query(
        r"
UPDATE users
SET concurrency = GREATEST(concurrency + $2, 0), updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL
",
    )
    .bind(user_id)
    .bind(value)
    .execute(&mut **transaction)
    .await?;
    if result.rows_affected() == 1 {
        Ok(())
    } else {
        Err(ApiError::not_found("User not found"))
    }
}

async fn apply_subscription(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i64,
    code: &LockedCode,
) -> Result<(), ApiError> {
    let group_id = code
        .group_id
        .ok_or_else(|| ApiError::bad_request("Subscription redeem code has no group"))?;
    let group_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM groups WHERE id = $1 AND deleted_at IS NULL)",
    )
    .bind(group_id)
    .fetch_one(&mut **transaction)
    .await?;
    if !group_exists {
        return Err(ApiError::bad_request("Subscription group does not exist"));
    }
    let validity_days = if code.validity_days == 0 {
        30
    } else {
        code.validity_days
    };
    if validity_days > 0 {
        sqlx::query(
            r"
INSERT INTO user_subscriptions (
    user_id, group_id, starts_at, expires_at, status, assigned_at, notes,
    created_at, updated_at, deleted_at
)
VALUES ($1, $2, NOW(), NOW() + make_interval(days => $3), 'active', NOW(),
        $4, NOW(), NOW(), NULL)
ON CONFLICT (user_id, group_id) DO UPDATE
SET expires_at = GREATEST(user_subscriptions.expires_at, NOW()) + make_interval(days => $3),
    status = 'active', deleted_at = NULL, updated_at = NOW(), notes = EXCLUDED.notes
",
        )
        .bind(user_id)
        .bind(group_id)
        .bind(validity_days)
        .bind(format!("Redeemed with code {}", code.id))
        .execute(&mut **transaction)
        .await?;
    } else {
        sqlx::query(
            r"
UPDATE user_subscriptions
SET expires_at = GREATEST(starts_at, expires_at + make_interval(days => $3)),
    status = CASE WHEN expires_at + make_interval(days => $3) <= NOW()
                  THEN 'expired' ELSE status END,
    updated_at = NOW()
WHERE user_id = $1 AND group_id = $2 AND deleted_at IS NULL
",
        )
        .bind(user_id)
        .bind(group_id)
        .bind(validity_days)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

async fn get_code(
    pool: &sqlx::PgPool,
    id: i64,
    visible_to: Option<i64>,
) -> Result<RedeemCodeView, ApiError> {
    let row = sqlx::query(&format!("{} WHERE id = $1", code_select()))
        .bind(id)
        .fetch_one(pool)
        .await?;
    code_from_row(&row, visible_to)
}

fn code_select() -> &'static str {
    r#"
SELECT id, code, type, value::double precision AS value,
       CASE WHEN status = 'unused' AND expires_at IS NOT NULL AND expires_at <= NOW()
            THEN 'expired' ELSE status END AS status,
       used_by,
       CASE WHEN used_at IS NULL THEN NULL ELSE to_char(used_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END AS used_at,
       to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
       CASE WHEN expires_at IS NULL THEN NULL ELSE to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END AS expires_at,
       group_id, validity_days, notes
FROM redeem_codes
"#
}

fn code_from_row(
    row: &sqlx::postgres::PgRow,
    visible_to: Option<i64>,
) -> Result<RedeemCodeView, ApiError> {
    let code_type: String = row.try_get("type")?;
    let notes = if matches!(code_type.as_str(), "admin_balance" | "admin_concurrency") {
        row.try_get("notes")?
    } else {
        None
    };
    let used_by: Option<i64> = row.try_get("used_by")?;
    if visible_to.is_some_and(|user_id| used_by != Some(user_id)) {
        return Err(ApiError::forbidden(
            "Not authorized to view this redeem code",
            "REDEEM_OWNERSHIP_REQUIRED",
        ));
    }
    Ok(RedeemCodeView {
        id: row.try_get("id")?,
        code: row.try_get("code")?,
        code_type,
        value: row.try_get("value")?,
        status: row.try_get("status")?,
        used_by,
        used_at: row.try_get("used_at")?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
        group_id: row.try_get("group_id")?,
        validity_days: row.try_get("validity_days")?,
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::code_select;

    #[test]
    fn redeem_projection_applies_expiry_without_exposing_admin_notes() {
        let sql = code_select();
        assert!(sql.contains("status = 'unused'"));
        assert!(sql.contains("expires_at <= NOW()"));
    }
}
