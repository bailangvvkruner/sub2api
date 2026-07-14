use std::collections::BTreeMap;

use axum::http::Method;
use serde_json::{Value, json};
use sha2::Digest;
use sqlx::{Column, PgPool, Row, TypeInfo};

use super::{
    AdminError,
    compat::{
        Resource, create_resource, list_resource, payload_object, query_i64, redacted_json,
        relation_list, required_path_id, update_resource,
    },
};
use crate::email::PostgresSmtpNotifier;

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) async fn dispatch(
    pool: &PgPool,
    handler: &str,
    category: &str,
    method: &Method,
    path: &str,
    query: &BTreeMap<String, String>,
    payload: Value,
) -> Option<Result<Value, AdminError>> {
    let result = match handler {
        "h.Admin.Account.GetUsage" | "h.Admin.User.GetUserUsage" => {
            usage_for_owner(pool, handler, required_path_id(path, "owner").ok()?, query).await
        }
        "h.Admin.Account.GetStats" | "h.Admin.Account.GetTodayStats" | "h.Admin.Group.GetStats" => {
            owner_stats(pool, handler, required_path_id(path, "owner").ok()?).await
        }
        "h.Admin.Dashboard.GetStats" | "h.Admin.Dashboard.GetRealtimeMetrics" => {
            dashboard_stats(pool).await
        }
        "h.Admin.Dashboard.GetSnapshotV2" => dashboard_snapshot(pool).await,
        "h.Admin.Dashboard.GetUsageTrend"
        | "h.Admin.Dashboard.GetAPIKeyUsageTrend"
        | "h.Admin.Dashboard.GetUserUsageTrend" => dashboard_trend(pool, handler, query).await,
        "h.Admin.Dashboard.GetModelStats" | "h.Admin.Dashboard.GetGroupStats" => {
            dashboard_breakdown(pool, handler, query).await
        }
        "h.Admin.Dashboard.GetUserSpendingRanking" => user_spending_ranking(pool, query).await,
        "h.Admin.Dashboard.GetUserBreakdown" => user_breakdown(pool, query).await,
        "h.Admin.Dashboard.GetBatchUsersUsage" => batch_usage(pool, "user_id", &payload).await,
        "h.Admin.Dashboard.GetBatchAPIKeysUsage" => batch_usage(pool, "api_key_id", &payload).await,
        "h.Admin.Dashboard.BackfillAggregation" => backfill_dashboard_aggregation(pool).await,
        "h.Admin.Redeem.GetStats" => redeem_stats(pool).await,
        "h.Admin.Redeem.Export" => {
            export_resource(
                pool,
                Resource {
                    table: "redeem_codes",
                    label: "redeem code",
                },
            )
            .await
        }
        "h.Admin.Redeem.Expire" => {
            expire_redeem(pool, required_path_id(path, "redeem code").ok()?).await
        }
        "h.Admin.Redeem.Generate" => generate_redeem_codes(pool, payload).await,
        "h.Admin.Redeem.BatchDelete" => batch_delete_redeem(pool, &payload).await,
        "h.Admin.Redeem.BatchUpdate" => batch_update_redeem(pool, &payload).await,
        "h.Admin.Redeem.CreateAndRedeem" => create_and_redeem(pool, &payload).await,
        "h.Admin.Proxy.GetAll" => {
            export_resource(
                pool,
                Resource {
                    table: "proxies",
                    label: "proxy",
                },
            )
            .await
        }
        "h.Admin.Account.ClearError" | "h.Admin.Account.RecoverState" => {
            clear_account_error(pool, required_path_id(path, "account").ok()?).await
        }
        "h.Admin.Account.SetSchedulable" => {
            set_account_schedulable(pool, required_path_id(path, "account").ok()?, &payload).await
        }
        "h.Admin.Account.GetTempUnschedulable" => {
            account_temp_state(pool, required_path_id(path, "account").ok()?).await
        }
        "h.Admin.Account.ClearTempUnschedulable" => {
            clear_account_temp_state(pool, required_path_id(path, "account").ok()?).await
        }
        "h.Admin.Account.SetPrivacy" => {
            set_account_extra_flag(
                pool,
                required_path_id(path, "account").ok()?,
                "privacy",
                &payload,
            )
            .await
        }
        "h.Admin.Account.ResetQuota" => {
            reset_account_quota(pool, required_path_id(path, "account").ok()?).await
        }
        "h.Admin.Account.ClearRateLimit" => {
            clear_account_rate_limit(pool, required_path_id(path, "account").ok()?).await
        }
        "h.Admin.Account.GetAvailableModels" => {
            account_models(pool, required_path_id(path, "account").ok()?).await
        }
        "h.Admin.Account.GetBatchTodayStats" => batch_account_today_stats(pool, &payload).await,
        "h.Admin.Account.BatchClearError" => batch_clear_account_error(pool, &payload).await,
        "h.Admin.User.UpdateBalance" => {
            update_user_balance(pool, required_path_id(path, "user").ok()?, &payload).await
        }
        "h.Admin.User.ReplaceGroup" => {
            replace_user_group(pool, required_path_id(path, "user").ok()?, &payload).await
        }
        "h.Admin.User.GetBalanceHistory" => {
            user_balance_history(pool, required_path_id(path, "user").ok()?, query).await
        }
        "h.Admin.User.GetUserRPMStatus" => {
            user_rpm_status(pool, required_path_id(path, "user").ok()?).await
        }
        "h.Admin.User.BatchUpdateConcurrency" => batch_user_concurrency(pool, &payload).await,
        "h.Admin.Subscription.Assign" => assign_subscription(pool, &payload).await,
        "h.Admin.Subscription.BulkAssign" => bulk_assign_subscription(pool, &payload).await,
        "h.Admin.Subscription.Extend" => {
            extend_subscription(pool, required_path_id(path, "subscription").ok()?, &payload).await
        }
        "h.Admin.Subscription.ResetQuota" => {
            reset_subscription_quota(pool, required_path_id(path, "subscription").ok()?).await
        }
        "h.Admin.Subscription.Revoke" => {
            set_subscription_status(
                pool,
                required_path_id(path, "subscription").ok()?,
                "revoked",
            )
            .await
        }
        "h.Admin.Subscription.Restore" => {
            set_subscription_status(pool, required_path_id(path, "subscription").ok()?, "active")
                .await
        }
        "h.Admin.Subscription.GetProgress" => {
            subscription_progress(pool, required_path_id(path, "subscription").ok()?).await
        }
        "h.Admin.Group.GetAll" => {
            export_resource(
                pool,
                Resource {
                    table: "groups",
                    label: "group",
                },
            )
            .await
        }
        "h.Admin.Group.GetUsageSummary" => group_usage_summary(pool).await,
        "h.Admin.Group.GetCapacitySummary" => group_capacity_summary(pool).await,
        "h.Admin.Group.GetGroupRateMultipliers" => {
            relation_list(
                pool,
                "user_group_rate_multipliers",
                "group_id",
                required_path_id(path, "group").ok()?,
                query,
            )
            .await
        }
        "h.Admin.Ops.UpdateAlertEventStatus" => {
            update_alert_event_status(pool, required_path_id(path, "alert event").ok()?, &payload)
                .await
        }
        "h.Admin.Ops.ListRequestDetails" => list_request_details(pool, query).await,
        "h.Admin.Ops.GetMetricThresholds" => get_metric_thresholds(pool).await,
        "h.Admin.Ops.UpdateMetricThresholds" => update_metric_thresholds(pool, &payload).await,
        "h.Admin.Ops.ListSystemLogs" => {
            list_resource(
                pool,
                Resource {
                    table: "ops_system_logs",
                    label: "system log",
                },
                query,
            )
            .await
        }
        "h.Admin.Ops.CleanupSystemLogs" => cleanup_system_logs(pool, &payload).await,
        "h.Admin.Ops.GetSystemLogIngestionHealth" => system_log_health(pool).await,
        "h.Admin.Ops.GetConcurrencyStats" => concurrency_stats(pool).await,
        "h.Admin.Ops.GetUserConcurrencyStats" => user_concurrency_stats(pool, query).await,
        "h.Admin.Ops.GetAccountAvailability" => account_availability(pool).await,
        "h.Admin.Ops.GetRealtimeTrafficSummary" => realtime_traffic(pool).await,
        "h.Admin.Ops.CreateAlertSilence" => {
            create_resource(
                pool,
                Resource {
                    table: "ops_alert_silences",
                    label: "alert silence",
                },
                payload,
            )
            .await
        }
        "h.Admin.ContentModeration.GetStatus" => moderation_status(pool).await,
        "h.Admin.ContentModeration.UnbanUser" => {
            unban_user(pool, required_path_id(path, "user").ok()?).await
        }
        "adminPaymentHandler.GetDashboard" => payment_dashboard(pool).await,
        "adminPaymentHandler.GetConfig" => payment_config(pool).await,
        "adminPaymentHandler.UpdateConfig" => update_payment_config(pool, payload).await,
        "adminPaymentHandler.CancelOrder" => {
            set_payment_order_status(
                pool,
                required_path_id(path, "payment order").ok()?,
                "CANCELLED",
            )
            .await
        }
        "adminPaymentHandler.RetryFulfillment" => {
            retry_payment_fulfillment(pool, required_path_id(path, "payment order").ok()?).await
        }
        "h.Admin.System.GetVersion" => Ok(json!({
            "version": env!("CARGO_PKG_VERSION"),
            "runtime": "rust",
            "database": "postgresql",
        })),
        "h.Admin.System.CheckUpdates" | "h.Admin.System.GetRollbackVersions" => {
            Ok(json!({ "current_version": env!("CARGO_PKG_VERSION"), "updates": [] }))
        }
        "h.Admin.Setting.TestSMTPConnection" => {
            async {
                let notifier =
                    PostgresSmtpNotifier::new(pool.clone()).map_err(AdminError::Probe)?;
                notifier
                    .test_connection(&payload)
                    .await
                    .map_err(AdminError::Probe)?;
                Ok(json!({ "message": "SMTP connection successful" }))
            }
            .await
        }
        "h.Admin.Setting.SendTestEmail" => {
            async {
                let notifier =
                    PostgresSmtpNotifier::new(pool.clone()).map_err(AdminError::Probe)?;
                notifier
                    .send_test_email(&payload)
                    .await
                    .map_err(AdminError::Probe)?;
                Ok(json!({ "message": "Test email sent successfully" }))
            }
            .await
        }
        _ if category == "admin/settings" || handler.contains("Settings") => {
            settings_operation(pool, handler, method, path, payload).await
        }
        _ if category == "admin/ops" && handler.contains("Settings")
            || handler.contains("RuntimeLogConfig")
            || handler.contains("EmailNotificationConfig") =>
        {
            settings_operation(pool, handler, method, path, payload).await
        }
        _ => return None,
    };
    Some(result)
}

async fn usage_for_owner(
    pool: &PgPool,
    handler: &str,
    id: i64,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let column = if handler.contains("Account") {
        "account_id"
    } else {
        "user_id"
    };
    let page = query_i64(query, "page", 1).max(1);
    let size = query_i64(query, "page_size", 50).clamp(1, 1_000);
    let sql = format!(
        "SELECT {} AS data FROM usage_logs row WHERE row.{} = $1 ORDER BY row.created_at DESC LIMIT $2 OFFSET $3",
        redacted_json("row"),
        column
    );
    let rows = sqlx::query(&sql)
        .bind(id)
        .bind(size)
        .bind((page - 1) * size)
        .fetch_all(pool)
        .await?;
    let items = rows
        .into_iter()
        .map(|row| row.try_get::<Value, _>("data"))
        .collect::<Result<Vec<_>, _>>()?;
    let total = sqlx::query_scalar::<_, i64>(&format!(
        "SELECT COUNT(*)::bigint FROM usage_logs WHERE {column} = $1"
    ))
    .bind(id)
    .fetch_one(pool)
    .await?;
    Ok(json!({ "items": items, "total": total, "page": page, "page_size": size }))
}

async fn owner_stats(pool: &PgPool, handler: &str, id: i64) -> Result<Value, AdminError> {
    let column = if handler.contains("Account") {
        "account_id"
    } else {
        "group_id"
    };
    let today = if handler.ends_with("GetTodayStats") {
        " AND created_at >= date_trunc('day', NOW())"
    } else {
        ""
    };
    aggregate_usage(pool, &format!("{column} = $1{today}"), Some(id)).await
}

async fn aggregate_usage(
    pool: &PgPool,
    condition: &str,
    id: Option<i64>,
) -> Result<Value, AdminError> {
    let sql = format!(
        r"
SELECT COUNT(*)::bigint AS requests,
       COALESCE(SUM(input_tokens), 0)::bigint AS input_tokens,
       COALESCE(SUM(output_tokens), 0)::bigint AS output_tokens,
       COALESCE(SUM(cache_read_tokens), 0)::bigint AS cache_read_tokens,
       COALESCE(SUM(cache_creation_tokens), 0)::bigint AS cache_creation_tokens,
       COALESCE(SUM(total_cost), 0)::double precision AS total_cost,
       COALESCE(SUM(actual_cost), 0)::double precision AS actual_cost,
       COALESCE(AVG(duration_ms), 0)::double precision AS average_duration_ms
FROM usage_logs WHERE {condition}
"
    );
    let mut request = sqlx::query(&sql);
    if let Some(id) = id {
        request = request.bind(id);
    }
    let row = request.fetch_one(pool).await?;
    Ok(json!({
        "requests": row.try_get::<i64, _>("requests")?,
        "input_tokens": row.try_get::<i64, _>("input_tokens")?,
        "output_tokens": row.try_get::<i64, _>("output_tokens")?,
        "cache_read_tokens": row.try_get::<i64, _>("cache_read_tokens")?,
        "cache_creation_tokens": row.try_get::<i64, _>("cache_creation_tokens")?,
        "total_cost": row.try_get::<f64, _>("total_cost")?,
        "actual_cost": row.try_get::<f64, _>("actual_cost")?,
        "average_duration_ms": row.try_get::<f64, _>("average_duration_ms")?,
    }))
}

async fn dashboard_stats(pool: &PgPool) -> Result<Value, AdminError> {
    let counts = sqlx::query(
        r"
SELECT (SELECT COUNT(*) FROM users WHERE deleted_at IS NULL)::bigint AS users,
       (SELECT COUNT(*) FROM api_keys WHERE deleted_at IS NULL)::bigint AS api_keys,
       (SELECT COUNT(*) FROM accounts WHERE deleted_at IS NULL)::bigint AS accounts,
       (SELECT COUNT(*) FROM accounts WHERE deleted_at IS NULL AND status = 'active' AND schedulable)::bigint AS active_accounts
",
    )
    .fetch_one(pool)
    .await?;
    Ok(json!({
        "total_users": counts.try_get::<i64, _>("users")?,
        "total_api_keys": counts.try_get::<i64, _>("api_keys")?,
        "total_accounts": counts.try_get::<i64, _>("accounts")?,
        "active_accounts": counts.try_get::<i64, _>("active_accounts")?,
        "today": aggregate_usage(pool, "created_at >= date_trunc('day', NOW())", None).await?,
    }))
}

async fn dashboard_snapshot(pool: &PgPool) -> Result<Value, AdminError> {
    Ok(json!({
        "stats": dashboard_stats(pool).await?,
        "trend": dashboard_trend(pool, "h.Admin.Dashboard.GetUsageTrend", &BTreeMap::new()).await?,
        "models": dashboard_breakdown(pool, "h.Admin.Dashboard.GetModelStats", &BTreeMap::new()).await?,
        "generated_at": chrono::Utc::now().to_rfc3339(),
    }))
}

async fn dashboard_trend(
    pool: &PgPool,
    handler: &str,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let days = query_i64(query, "days", 30).clamp(1, 366);
    let dimension = if handler.contains("APIKey") {
        "api_key_id"
    } else if handler.contains("User") {
        "user_id"
    } else {
        "NULL"
    };
    let sql = format!(
        r"
SELECT to_char(date_trunc('day', created_at), 'YYYY-MM-DD') AS date,
       {dimension} AS dimension_id,
       COUNT(*)::bigint AS requests,
       COALESCE(SUM(actual_cost), 0)::double precision AS actual_cost,
       COALESCE(SUM(input_tokens + output_tokens), 0)::bigint AS tokens
FROM usage_logs
WHERE created_at >= date_trunc('day', NOW()) - make_interval(days => $1 - 1)
GROUP BY 1, 2 ORDER BY 1, 2
"
    );
    let rows = sqlx::query(&sql).bind(days as i32).fetch_all(pool).await?;
    let items = rows
        .into_iter()
        .map(|row| {
            Ok(json!({
                "date": row.try_get::<String, _>("date")?,
                "dimension_id": row.try_get::<Option<i64>, _>("dimension_id")?,
                "requests": row.try_get::<i64, _>("requests")?,
                "actual_cost": row.try_get::<f64, _>("actual_cost")?,
                "tokens": row.try_get::<i64, _>("tokens")?,
            }))
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()?;
    Ok(json!({ "items": items, "days": days }))
}

async fn dashboard_breakdown(
    pool: &PgPool,
    handler: &str,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let days = query_i64(query, "days", 30).clamp(1, 366);
    let (dimension, key) = if handler.contains("Model") {
        ("COALESCE(requested_model, model)", "model")
    } else {
        ("group_id::text", "group_id")
    };
    let sql = format!(
        r"
SELECT {dimension} AS dimension, COUNT(*)::bigint AS requests,
       COALESCE(SUM(actual_cost), 0)::double precision AS actual_cost,
       COALESCE(SUM(input_tokens + output_tokens), 0)::bigint AS tokens
FROM usage_logs
WHERE created_at >= NOW() - make_interval(days => $1) AND {dimension} IS NOT NULL
GROUP BY 1 ORDER BY actual_cost DESC LIMIT 200
"
    );
    let rows = sqlx::query(&sql).bind(days as i32).fetch_all(pool).await?;
    let items = rows
        .into_iter()
        .map(|row| {
            let mut value = json!({
                "requests": row.try_get::<i64, _>("requests")?,
                "actual_cost": row.try_get::<f64, _>("actual_cost")?,
                "tokens": row.try_get::<i64, _>("tokens")?,
            });
            value[key] = Value::String(row.try_get("dimension")?);
            Ok(value)
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()?;
    Ok(json!({ "items": items, "days": days }))
}

async fn user_spending_ranking(
    pool: &PgPool,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let limit = query_i64(query, "limit", 50).clamp(1, 500);
    let rows = sqlx::query(
        r"
SELECT usage.user_id, COALESCE(users.email, '') AS email,
       COALESCE(users.username, '') AS username,
       COUNT(*)::bigint AS requests,
       COALESCE(SUM(usage.actual_cost), 0)::double precision AS actual_cost
FROM usage_logs usage LEFT JOIN users ON users.id = usage.user_id
GROUP BY usage.user_id, users.email, users.username
ORDER BY actual_cost DESC LIMIT $1
",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows_to_values(rows))
}

async fn user_breakdown(
    pool: &PgPool,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    user_spending_ranking(pool, query).await
}

async fn batch_usage(pool: &PgPool, column: &str, payload: &Value) -> Result<Value, AdminError> {
    let ids = payload_ids(payload)?;
    let sql = format!(
        "SELECT {column} AS id, COUNT(*)::bigint AS requests, COALESCE(SUM(actual_cost),0)::double precision AS actual_cost FROM usage_logs WHERE {column} = ANY($1) GROUP BY {column}"
    );
    Ok(rows_to_values(
        sqlx::query(&sql).bind(&ids).fetch_all(pool).await?,
    ))
}

async fn backfill_dashboard_aggregation(pool: &PgPool) -> Result<Value, AdminError> {
    let result = sqlx::query(
        "UPDATE usage_dashboard_aggregation_watermark SET updated_at = NOW() WHERE id = 1",
    )
    .execute(pool)
    .await?;
    Ok(json!({ "queued": true, "watermark_rows": result.rows_affected() }))
}

fn rows_to_values(rows: Vec<sqlx::postgres::PgRow>) -> Value {
    let values = rows
        .into_iter()
        .map(|row| {
            let columns = row.columns();
            let mut object = serde_json::Map::new();
            for column in columns {
                let name = column.name();
                let value = match column.type_info().name() {
                    "INT8" => row.try_get::<i64, _>(name).map(Value::from),
                    "INT4" => row.try_get::<i32, _>(name).map(Value::from),
                    "INT2" => row.try_get::<i16, _>(name).map(Value::from),
                    "FLOAT8" => row.try_get::<f64, _>(name).map(Value::from),
                    "FLOAT4" => row.try_get::<f32, _>(name).map(Value::from),
                    "BOOL" => row.try_get::<bool, _>(name).map(Value::from),
                    "JSON" | "JSONB" => row.try_get::<Value, _>(name),
                    _ => row.try_get::<String, _>(name).map(Value::from),
                }
                .unwrap_or(Value::Null);
                object.insert(name.to_owned(), value);
            }
            Value::Object(object)
        })
        .collect::<Vec<_>>();
    Value::Array(values)
}

async fn redeem_stats(pool: &PgPool) -> Result<Value, AdminError> {
    let row = sqlx::query(
        r"
SELECT COUNT(*)::bigint AS total,
       COUNT(*) FILTER (WHERE status = 'unused' AND (expires_at IS NULL OR expires_at > NOW()))::bigint AS unused,
       COUNT(*) FILTER (WHERE status = 'used')::bigint AS used,
       COUNT(*) FILTER (WHERE status = 'expired' OR (status = 'unused' AND expires_at <= NOW()))::bigint AS expired,
       COALESCE(SUM(value) FILTER (WHERE status = 'used'), 0)::double precision AS redeemed_value
FROM redeem_codes
",
    )
    .fetch_one(pool)
    .await?;
    Ok(json!({
        "total": row.try_get::<i64, _>("total")?,
        "unused": row.try_get::<i64, _>("unused")?,
        "used": row.try_get::<i64, _>("used")?,
        "expired": row.try_get::<i64, _>("expired")?,
        "redeemed_value": row.try_get::<f64, _>("redeemed_value")?,
    }))
}

async fn export_resource(pool: &PgPool, resource: Resource) -> Result<Value, AdminError> {
    let mut query = BTreeMap::new();
    query.insert("page_size".to_owned(), "1000".to_owned());
    let page = list_resource(pool, resource, &query).await?;
    Ok(page
        .get("items")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new())))
}

async fn expire_redeem(pool: &PgPool, id: i64) -> Result<Value, AdminError> {
    let sql = format!(
        "UPDATE redeem_codes row SET status = 'expired' WHERE id = $1 AND status = 'unused' RETURNING {}",
        redacted_json("row")
    );
    sqlx::query_scalar::<_, Value>(&sql)
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AdminError::Conflict("redeem code is not unused".to_owned()))
}

async fn generate_redeem_codes(pool: &PgPool, payload: Value) -> Result<Value, AdminError> {
    let object = payload_object(payload)?;
    let count = object
        .get("count")
        .and_then(Value::as_i64)
        .unwrap_or(1)
        .clamp(1, 1_000);
    let code_type = object
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("balance");
    if !matches!(code_type, "balance" | "concurrency" | "subscription") {
        return Err(AdminError::BadRequest(
            "unsupported redeem code type".to_owned(),
        ));
    }
    let value = object.get("value").and_then(Value::as_f64).unwrap_or(0.0);
    if !value.is_finite() {
        return Err(AdminError::BadRequest(
            "redeem value must be finite".to_owned(),
        ));
    }
    let group_id = object.get("group_id").and_then(Value::as_i64);
    if code_type == "subscription" && group_id.is_none() {
        return Err(AdminError::BadRequest(
            "group_id is required for subscription codes".to_owned(),
        ));
    }
    let validity_days = object
        .get("validity_days")
        .and_then(Value::as_i64)
        .unwrap_or(30)
        .clamp(i64::from(i32::MIN), i64::from(i32::MAX));
    let validity_days = i32::try_from(validity_days)
        .map_err(|_| AdminError::BadRequest("validity_days is out of range".to_owned()))?;
    let notes = object
        .get("notes")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let expires_at = object.get("expires_at").and_then(Value::as_str);
    let mut transaction = pool.begin().await?;
    let capacity = usize::try_from(count)
        .map_err(|_| AdminError::BadRequest("count is out of range".to_owned()))?;
    let mut created = Vec::with_capacity(capacity);
    for _ in 0..count {
        let code = uuid::Uuid::new_v4().simple().to_string();
        let sql = format!(
            r"
INSERT INTO redeem_codes AS row
    (code, type, value, status, group_id, validity_days, notes, expires_at)
VALUES ($1, $2, $3::numeric, 'unused', $4, $5, $6, $7::timestamptz)
RETURNING {}
",
            redacted_json("row")
        );
        created.push(
            sqlx::query_scalar::<_, Value>(&sql)
                .bind(code)
                .bind(code_type)
                .bind(value.to_string())
                .bind(group_id)
                .bind(validity_days)
                .bind(notes)
                .bind(expires_at)
                .fetch_one(&mut *transaction)
                .await?,
        );
    }
    transaction.commit().await?;
    Ok(Value::Array(created))
}

fn payload_ids(payload: &Value) -> Result<Vec<i64>, AdminError> {
    payload
        .get("ids")
        .or_else(|| payload.get("user_ids"))
        .or_else(|| payload.get("account_ids"))
        .and_then(Value::as_array)
        .ok_or_else(|| AdminError::BadRequest("ids must be an array".to_owned()))?
        .iter()
        .map(|value| {
            value.as_i64().filter(|id| *id > 0).ok_or_else(|| {
                AdminError::BadRequest("ids must contain positive integers".to_owned())
            })
        })
        .collect()
}

fn integral_f64_to_i32(value: f64, field: &str) -> Result<i32, AdminError> {
    if !value.is_finite()
        || value.fract() != 0.0
        || value < f64::from(i32::MIN)
        || value > f64::from(i32::MAX)
    {
        let min = i32::MIN;
        let max = i32::MAX;
        return Err(AdminError::BadRequest(format!(
            "{field} must be an integer between {min} and {max}"
        )));
    }
    value
        .to_string()
        .parse::<i32>()
        .map_err(|_| AdminError::BadRequest(format!("{field} is out of range")))
}

async fn batch_delete_redeem(pool: &PgPool, payload: &Value) -> Result<Value, AdminError> {
    let ids = payload_ids(payload)?;
    let result = sqlx::query("DELETE FROM redeem_codes WHERE id = ANY($1) AND status <> 'used'")
        .bind(&ids)
        .execute(pool)
        .await?;
    Ok(json!({ "deleted": result.rows_affected() }))
}

async fn batch_update_redeem(pool: &PgPool, payload: &Value) -> Result<Value, AdminError> {
    let ids = payload_ids(payload)?;
    let fields = payload
        .get("fields")
        .cloned()
        .ok_or_else(|| AdminError::BadRequest("fields are required".to_owned()))?;
    let mut updated = Vec::with_capacity(ids.len());
    for id in ids {
        updated.push(
            update_resource(
                pool,
                Resource {
                    table: "redeem_codes",
                    label: "redeem code",
                },
                id,
                fields.clone(),
            )
            .await?,
        );
    }
    Ok(Value::Array(updated))
}

async fn create_and_redeem(pool: &PgPool, payload: &Value) -> Result<Value, AdminError> {
    let user_id = payload
        .get("user_id")
        .and_then(Value::as_i64)
        .ok_or_else(|| AdminError::BadRequest("user_id is required".to_owned()))?;
    let amount = payload
        .get("value")
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite())
        .ok_or_else(|| AdminError::BadRequest("finite value is required".to_owned()))?;
    let code_type = payload
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("balance");
    let notes = payload
        .get("notes")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mut transaction = pool.begin().await?;
    match code_type {
        "balance" => {
            sqlx::query(
                "UPDATE users SET balance = GREATEST(balance + $2::numeric, 0), total_recharged = total_recharged + GREATEST($2::numeric, 0), updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL",
            )
            .bind(user_id)
            .bind(amount.to_string())
            .execute(&mut *transaction)
            .await?;
        }
        "concurrency" if amount.fract() == 0.0 => {
            let amount = integral_f64_to_i32(amount, "concurrency value")?;
            sqlx::query(
                "UPDATE users SET concurrency = GREATEST(concurrency + $2, 0), updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL",
            )
            .bind(user_id)
            .bind(amount)
            .execute(&mut *transaction)
            .await?;
        }
        _ => {
            return Err(AdminError::BadRequest(
                "create-and-redeem supports balance or integral concurrency".to_owned(),
            ));
        }
    }
    let code = uuid::Uuid::new_v4().simple().to_string();
    let sql = format!(
        "INSERT INTO redeem_codes AS row (code, type, value, status, used_by, used_at, notes) VALUES ($1, $2, $3::numeric, 'used', $4, NOW(), $5) RETURNING {}",
        redacted_json("row")
    );
    let row = sqlx::query_scalar::<_, Value>(&sql)
        .bind(code)
        .bind(code_type)
        .bind(amount.to_string())
        .bind(user_id)
        .bind(notes)
        .fetch_one(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(row)
}

async fn clear_account_error(pool: &PgPool, id: i64) -> Result<Value, AdminError> {
    let sql = format!(
        "UPDATE accounts row SET status = 'active', error_message = NULL, schedulable = TRUE, updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL RETURNING {}",
        redacted_json("row")
    );
    sqlx::query_scalar::<_, Value>(&sql)
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(AdminError::NotFound("account"))
}

async fn set_account_schedulable(
    pool: &PgPool,
    id: i64,
    payload: &Value,
) -> Result<Value, AdminError> {
    let value = payload
        .get("schedulable")
        .and_then(Value::as_bool)
        .ok_or_else(|| AdminError::BadRequest("schedulable is required".to_owned()))?;
    let sql = format!(
        "UPDATE accounts row SET schedulable = $2, updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL RETURNING {}",
        redacted_json("row")
    );
    sqlx::query_scalar::<_, Value>(&sql)
        .bind(id)
        .bind(value)
        .fetch_optional(pool)
        .await?
        .ok_or(AdminError::NotFound("account"))
}

async fn account_temp_state(pool: &PgPool, id: i64) -> Result<Value, AdminError> {
    let row = sqlx::query(
        r"
SELECT temp_unschedulable_until IS NOT NULL AND temp_unschedulable_until > NOW() AS temp_unschedulable,
       temp_unschedulable_reason,
       CASE WHEN temp_unschedulable_until IS NULL THEN NULL
            ELSE to_char(temp_unschedulable_until AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS.US') END AS until
FROM accounts WHERE id = $1 AND deleted_at IS NULL
",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(AdminError::NotFound("account"))?;
    Ok(json!({
        "temp_unschedulable": row.try_get::<bool, _>("temp_unschedulable")?,
        "reason": row.try_get::<Option<String>, _>("temp_unschedulable_reason")?,
        "until": row.try_get::<Option<String>, _>("until")?,
    }))
}

async fn clear_account_temp_state(pool: &PgPool, id: i64) -> Result<Value, AdminError> {
    let result = sqlx::query(
        "UPDATE accounts SET temp_unschedulable_reason = NULL, temp_unschedulable_until = NULL, updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .execute(pool)
    .await?;
    if result.rows_affected() == 0 {
        return Err(AdminError::NotFound("account"));
    }
    Ok(json!({ "id": id, "temp_unschedulable": false }))
}

async fn set_account_extra_flag(
    pool: &PgPool,
    id: i64,
    key: &str,
    payload: &Value,
) -> Result<Value, AdminError> {
    let value = payload
        .get(key)
        .or_else(|| payload.get("enabled"))
        .and_then(Value::as_bool)
        .ok_or_else(|| AdminError::BadRequest("boolean value is required".to_owned()))?;
    let sql = format!(
        "UPDATE accounts row SET extra = jsonb_set(COALESCE(extra, '{{}}'::jsonb), ARRAY[$2], to_jsonb($3::boolean), true), updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL RETURNING {}",
        redacted_json("row")
    );
    sqlx::query_scalar::<_, Value>(&sql)
        .bind(id)
        .bind(key)
        .bind(value)
        .fetch_optional(pool)
        .await?
        .ok_or(AdminError::NotFound("account"))
}

async fn reset_account_quota(pool: &PgPool, id: i64) -> Result<Value, AdminError> {
    let sql = format!(
        "UPDATE accounts row SET extra = COALESCE(extra, '{{}}'::jsonb) - ARRAY['quota','quota_used','quota_reset_at'], updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL RETURNING {}",
        redacted_json("row")
    );
    sqlx::query_scalar::<_, Value>(&sql)
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(AdminError::NotFound("account"))
}

async fn clear_account_rate_limit(pool: &PgPool, id: i64) -> Result<Value, AdminError> {
    let sql = format!(
        "UPDATE accounts row SET rate_limited_at = NULL, rate_limit_reset_at = NULL, overload_until = NULL, updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL RETURNING {}",
        redacted_json("row")
    );
    sqlx::query_scalar::<_, Value>(&sql)
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(AdminError::NotFound("account"))
}

async fn account_models(pool: &PgPool, id: i64) -> Result<Value, AdminError> {
    let row = sqlx::query(
        "SELECT COALESCE(extra -> 'available_models', extra -> 'models', '[]'::jsonb) AS models FROM accounts WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(AdminError::NotFound("account"))?;
    Ok(json!({ "models": row.try_get::<Value, _>("models")? }))
}

async fn batch_account_today_stats(pool: &PgPool, payload: &Value) -> Result<Value, AdminError> {
    let ids = payload_ids(payload)?;
    let rows = sqlx::query(
        r"
SELECT account_id, COUNT(*)::bigint AS requests,
       COALESCE(SUM(actual_cost),0)::double precision AS actual_cost,
       COALESCE(SUM(input_tokens + output_tokens),0)::bigint AS tokens
FROM usage_logs WHERE account_id = ANY($1) AND created_at >= date_trunc('day', NOW())
GROUP BY account_id
",
    )
    .bind(&ids)
    .fetch_all(pool)
    .await?;
    Ok(rows_to_values(rows))
}

async fn batch_clear_account_error(pool: &PgPool, payload: &Value) -> Result<Value, AdminError> {
    let ids = payload_ids(payload)?;
    let result = sqlx::query(
        "UPDATE accounts SET status = 'active', error_message = NULL, schedulable = TRUE, updated_at = NOW() WHERE id = ANY($1) AND deleted_at IS NULL",
    )
    .bind(&ids)
    .execute(pool)
    .await?;
    Ok(json!({ "updated": result.rows_affected() }))
}

async fn update_user_balance(pool: &PgPool, id: i64, payload: &Value) -> Result<Value, AdminError> {
    let amount = payload
        .get("amount")
        .or_else(|| payload.get("balance"))
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite())
        .ok_or_else(|| AdminError::BadRequest("finite amount is required".to_owned()))?;
    let mode = payload.get("mode").and_then(Value::as_str).unwrap_or("add");
    let expression = if mode == "set" {
        "$2::numeric"
    } else {
        "balance + $2::numeric"
    };
    let sql = format!(
        "UPDATE users row SET balance = {}, total_recharged = total_recharged + CASE WHEN $2::numeric > 0 AND $3 THEN $2::numeric ELSE 0 END, updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL RETURNING {}",
        expression,
        redacted_json("row")
    );
    sqlx::query_scalar::<_, Value>(&sql)
        .bind(id)
        .bind(amount.to_string())
        .bind(mode != "set")
        .fetch_optional(pool)
        .await?
        .ok_or(AdminError::NotFound("user"))
}

async fn replace_user_group(pool: &PgPool, id: i64, payload: &Value) -> Result<Value, AdminError> {
    let old_group = payload.get("old_group_id").and_then(Value::as_i64);
    let new_group = payload
        .get("new_group_id")
        .or_else(|| payload.get("group_id"))
        .and_then(Value::as_i64)
        .ok_or_else(|| AdminError::BadRequest("new_group_id is required".to_owned()))?;
    let sql = format!(
        r"
UPDATE users row
SET allowed_groups = CASE
        WHEN $2::bigint IS NULL THEN array_append(COALESCE(allowed_groups, ARRAY[]::bigint[]), $3)
        ELSE array_replace(COALESCE(allowed_groups, ARRAY[]::bigint[]), $2, $3)
    END,
    updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL RETURNING {}
",
        redacted_json("row")
    );
    sqlx::query_scalar::<_, Value>(&sql)
        .bind(id)
        .bind(old_group)
        .bind(new_group)
        .fetch_optional(pool)
        .await?
        .ok_or(AdminError::NotFound("user"))
}

async fn user_balance_history(
    pool: &PgPool,
    user_id: i64,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let limit = query_i64(query, "page_size", 50).clamp(1, 1_000);
    let rows = sqlx::query(
        r"
SELECT -ledger.id AS id, ('AFF-' || ledger.id::text) AS code,
       'affiliate_balance' AS type, ledger.amount::double precision AS value,
       'used' AS status, ledger.user_id AS used_by,
       to_char(ledger.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS.US') AS used_at,
       COALESCE(ledger.balance_after, 0)::double precision AS balance_after
FROM user_affiliate_ledger ledger
WHERE ledger.user_id = $1 AND ledger.action = 'transfer'
ORDER BY ledger.created_at DESC LIMIT $2
",
    )
    .bind(user_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows_to_values(rows))
}

async fn user_rpm_status(pool: &PgPool, user_id: i64) -> Result<Value, AdminError> {
    let row = sqlx::query(
        r"
SELECT users.rpm_limit,
       COUNT(usage.id) FILTER (WHERE usage.created_at >= NOW() - INTERVAL '1 minute')::bigint AS current_rpm
FROM users LEFT JOIN usage_logs usage ON usage.user_id = users.id
WHERE users.id = $1 AND users.deleted_at IS NULL
GROUP BY users.id, users.rpm_limit
",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?
    .ok_or(AdminError::NotFound("user"))?;
    let limit: i32 = row.try_get("rpm_limit")?;
    let current: i64 = row.try_get("current_rpm")?;
    Ok(json!({
        "rpm_limit": limit,
        "current_rpm": current,
        "limited": limit > 0 && current >= i64::from(limit),
    }))
}

async fn batch_user_concurrency(pool: &PgPool, payload: &Value) -> Result<Value, AdminError> {
    let ids = payload_ids(payload)?;
    let value = payload
        .get("concurrency")
        .or_else(|| payload.get("value"))
        .and_then(Value::as_i64)
        .filter(|value| *value >= 0 && *value <= i64::from(i32::MAX))
        .ok_or_else(|| AdminError::BadRequest("valid concurrency is required".to_owned()))?;
    let value = i32::try_from(value)
        .map_err(|_| AdminError::BadRequest("valid concurrency is required".to_owned()))?;
    let result = sqlx::query(
        "UPDATE users SET concurrency = $2, updated_at = NOW() WHERE id = ANY($1) AND deleted_at IS NULL",
    )
    .bind(&ids)
    .bind(value)
    .execute(pool)
    .await?;
    Ok(json!({ "updated": result.rows_affected() }))
}

async fn assign_subscription(pool: &PgPool, payload: &Value) -> Result<Value, AdminError> {
    let user_id = payload
        .get("user_id")
        .and_then(Value::as_i64)
        .ok_or_else(|| AdminError::BadRequest("user_id is required".to_owned()))?;
    let group_id = payload
        .get("group_id")
        .and_then(Value::as_i64)
        .ok_or_else(|| AdminError::BadRequest("group_id is required".to_owned()))?;
    let days = payload
        .get("validity_days")
        .and_then(Value::as_i64)
        .unwrap_or(30)
        .clamp(1, 3_650) as i32;
    let notes = payload
        .get("notes")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let sql = format!(
        r"
INSERT INTO user_subscriptions AS row
    (user_id, group_id, starts_at, expires_at, status, assigned_at, notes, created_at, updated_at)
VALUES ($1, $2, NOW(), NOW() + make_interval(days => $3), 'active', NOW(), $4, NOW(), NOW())
ON CONFLICT (user_id, group_id) DO UPDATE
SET expires_at = GREATEST(user_subscriptions.expires_at, NOW()) + make_interval(days => $3),
    status = 'active', deleted_at = NULL, notes = EXCLUDED.notes, updated_at = NOW()
RETURNING {}
",
        redacted_json("row")
    );
    Ok(sqlx::query_scalar::<_, Value>(&sql)
        .bind(user_id)
        .bind(group_id)
        .bind(days)
        .bind(notes)
        .fetch_one(pool)
        .await?)
}

async fn bulk_assign_subscription(pool: &PgPool, payload: &Value) -> Result<Value, AdminError> {
    let user_ids = payload_ids(payload)?;
    let mut results = Vec::with_capacity(user_ids.len());
    for user_id in user_ids {
        let mut request = payload.clone();
        request["user_id"] = Value::from(user_id);
        results.push(assign_subscription(pool, &request).await?);
    }
    Ok(Value::Array(results))
}

async fn extend_subscription(pool: &PgPool, id: i64, payload: &Value) -> Result<Value, AdminError> {
    let days = payload
        .get("days")
        .or_else(|| payload.get("validity_days"))
        .and_then(Value::as_i64)
        .unwrap_or(30)
        .clamp(1, 3_650) as i32;
    let sql = format!(
        "UPDATE user_subscriptions row SET expires_at = GREATEST(expires_at, NOW()) + make_interval(days => $2), status = 'active', updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL RETURNING {}",
        redacted_json("row")
    );
    sqlx::query_scalar::<_, Value>(&sql)
        .bind(id)
        .bind(days)
        .fetch_optional(pool)
        .await?
        .ok_or(AdminError::NotFound("subscription"))
}

async fn reset_subscription_quota(pool: &PgPool, id: i64) -> Result<Value, AdminError> {
    let sql = format!(
        "UPDATE user_subscriptions row SET daily_usage_usd = 0, weekly_usage_usd = 0, monthly_usage_usd = 0, daily_window_start = NOW(), weekly_window_start = NOW(), monthly_window_start = NOW(), updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL RETURNING {}",
        redacted_json("row")
    );
    sqlx::query_scalar::<_, Value>(&sql)
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(AdminError::NotFound("subscription"))
}

async fn set_subscription_status(
    pool: &PgPool,
    id: i64,
    status: &str,
) -> Result<Value, AdminError> {
    let sql = format!(
        "UPDATE user_subscriptions row SET status = $2, deleted_at = CASE WHEN $2 = 'revoked' THEN NOW() ELSE NULL END, updated_at = NOW() WHERE id = $1 RETURNING {}",
        redacted_json("row")
    );
    sqlx::query_scalar::<_, Value>(&sql)
        .bind(id)
        .bind(status)
        .fetch_optional(pool)
        .await?
        .ok_or(AdminError::NotFound("subscription"))
}

async fn subscription_progress(pool: &PgPool, id: i64) -> Result<Value, AdminError> {
    let row = sqlx::query(
        r"
SELECT subscription.id, subscription.status,
       subscription.daily_usage_usd::double precision AS daily_usage,
       subscription.weekly_usage_usd::double precision AS weekly_usage,
       subscription.monthly_usage_usd::double precision AS monthly_usage,
       groups.daily_limit_usd::double precision AS daily_limit,
       groups.weekly_limit_usd::double precision AS weekly_limit,
       groups.monthly_limit_usd::double precision AS monthly_limit,
       EXTRACT(EPOCH FROM (subscription.expires_at - NOW()))::bigint AS remaining_seconds
FROM user_subscriptions subscription JOIN groups ON groups.id = subscription.group_id
WHERE subscription.id = $1 AND subscription.deleted_at IS NULL
",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(AdminError::NotFound("subscription"))?;
    Ok(json!({
        "id": row.try_get::<i64, _>("id")?,
        "status": row.try_get::<String, _>("status")?,
        "daily_usage": row.try_get::<f64, _>("daily_usage")?,
        "weekly_usage": row.try_get::<f64, _>("weekly_usage")?,
        "monthly_usage": row.try_get::<f64, _>("monthly_usage")?,
        "daily_limit": row.try_get::<Option<f64>, _>("daily_limit")?,
        "weekly_limit": row.try_get::<Option<f64>, _>("weekly_limit")?,
        "monthly_limit": row.try_get::<Option<f64>, _>("monthly_limit")?,
        "remaining_seconds": row.try_get::<i64, _>("remaining_seconds")?.max(0),
    }))
}

async fn group_usage_summary(pool: &PgPool) -> Result<Value, AdminError> {
    let rows = sqlx::query(
        r"
SELECT groups.id AS group_id, groups.name,
       COUNT(usage.id)::bigint AS requests,
       COALESCE(SUM(usage.actual_cost),0)::double precision AS actual_cost
FROM groups LEFT JOIN usage_logs usage ON usage.group_id = groups.id
WHERE groups.deleted_at IS NULL GROUP BY groups.id, groups.name ORDER BY groups.id
",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows_to_values(rows))
}

async fn group_capacity_summary(pool: &PgPool) -> Result<Value, AdminError> {
    let rows = sqlx::query(
        r"
SELECT groups.id AS group_id, groups.name,
       COUNT(DISTINCT account_groups.account_id)::bigint AS accounts,
       COALESCE(SUM(accounts.concurrency) FILTER (WHERE accounts.status = 'active' AND accounts.schedulable),0)::bigint AS concurrency_capacity
FROM groups
LEFT JOIN account_groups ON account_groups.group_id = groups.id
LEFT JOIN accounts ON accounts.id = account_groups.account_id AND accounts.deleted_at IS NULL
WHERE groups.deleted_at IS NULL GROUP BY groups.id, groups.name ORDER BY groups.id
",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows_to_values(rows))
}

async fn cleanup_system_logs(pool: &PgPool, payload: &Value) -> Result<Value, AdminError> {
    let days = payload
        .get("retention_days")
        .and_then(Value::as_i64)
        .unwrap_or(30)
        .clamp(1, 3_650) as i32;
    let mut transaction = pool.begin().await?;
    let result = sqlx::query(
        "DELETE FROM ops_system_logs WHERE created_at < NOW() - make_interval(days => $1)",
    )
    .bind(days)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO ops_system_log_cleanup_audits (deleted_count, retention_days, created_at) VALUES ($1, $2, NOW())",
    )
    .bind(i64::try_from(result.rows_affected()).unwrap_or(i64::MAX))
    .bind(days)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(json!({ "deleted": result.rows_affected(), "retention_days": days }))
}

async fn system_log_health(pool: &PgPool) -> Result<Value, AdminError> {
    let row = sqlx::query(
        r"
SELECT COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '5 minutes')::bigint AS recent,
       COUNT(*)::bigint AS total,
       CASE WHEN MAX(created_at) IS NULL THEN NULL ELSE to_char(MAX(created_at) AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS.US') END AS last_seen
FROM ops_system_logs
",
    )
    .fetch_one(pool)
    .await?;
    Ok(json!({
        "healthy": row.try_get::<i64, _>("recent")? > 0,
        "recent": row.try_get::<i64, _>("recent")?,
        "total": row.try_get::<i64, _>("total")?,
        "last_seen": row.try_get::<Option<String>, _>("last_seen")?,
    }))
}

async fn concurrency_stats(pool: &PgPool) -> Result<Value, AdminError> {
    let row = sqlx::query(
        r"
SELECT COALESCE(SUM(concurrency),0)::bigint AS configured_capacity,
       COUNT(*) FILTER (WHERE status = 'active' AND schedulable)::bigint AS schedulable_accounts,
       COUNT(*) FILTER (WHERE status <> 'active' OR NOT schedulable)::bigint AS unavailable_accounts
FROM accounts WHERE deleted_at IS NULL
",
    )
    .fetch_one(pool)
    .await?;
    Ok(json!({
        "configured_capacity": row.try_get::<i64, _>("configured_capacity")?,
        "schedulable_accounts": row.try_get::<i64, _>("schedulable_accounts")?,
        "unavailable_accounts": row.try_get::<i64, _>("unavailable_accounts")?,
    }))
}

async fn user_concurrency_stats(
    pool: &PgPool,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let limit = query_i64(query, "page_size", 100).clamp(1, 1_000);
    let rows = sqlx::query(
        r"
SELECT id AS user_id, email, username, concurrency
FROM users WHERE deleted_at IS NULL
ORDER BY concurrency DESC, id LIMIT $1
",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows_to_values(rows))
}

async fn account_availability(pool: &PgPool) -> Result<Value, AdminError> {
    let rows = sqlx::query(
        r"
SELECT platform, COUNT(*)::bigint AS total,
       COUNT(*) FILTER (WHERE status = 'active' AND schedulable
          AND (temp_unschedulable_until IS NULL OR temp_unschedulable_until <= NOW()))::bigint AS available,
       COALESCE(SUM(concurrency) FILTER (WHERE status = 'active' AND schedulable),0)::bigint AS capacity
FROM accounts WHERE deleted_at IS NULL GROUP BY platform ORDER BY platform
",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows_to_values(rows))
}

async fn realtime_traffic(pool: &PgPool) -> Result<Value, AdminError> {
    let row = sqlx::query(
        r"
SELECT COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '1 minute')::bigint AS rpm,
       COALESCE(SUM(input_tokens + output_tokens) FILTER (WHERE created_at >= NOW() - INTERVAL '1 minute'),0)::bigint AS tpm,
       COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '5 minutes')::bigint / 300.0 AS qps_5m,
       COALESCE(AVG(duration_ms) FILTER (WHERE created_at >= NOW() - INTERVAL '5 minutes'),0)::double precision AS latency_ms
FROM usage_logs
",
    )
    .fetch_one(pool)
    .await?;
    Ok(json!({
        "rpm": row.try_get::<i64, _>("rpm")?,
        "tpm": row.try_get::<i64, _>("tpm")?,
        "qps": row.try_get::<f64, _>("qps_5m")?,
        "latency_ms": row.try_get::<f64, _>("latency_ms")?,
    }))
}

async fn moderation_status(pool: &PgPool) -> Result<Value, AdminError> {
    let row = sqlx::query(
        r"
SELECT COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours')::bigint AS events_24h,
       COUNT(DISTINCT user_id) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours')::bigint AS users_24h,
       MAX(created_at) IS NOT NULL AS active
FROM content_moderation_logs
",
    )
    .fetch_one(pool)
    .await?;
    Ok(json!({
        "active": row.try_get::<bool, _>("active")?,
        "events_24h": row.try_get::<i64, _>("events_24h")?,
        "users_24h": row.try_get::<i64, _>("users_24h")?,
    }))
}

async fn unban_user(pool: &PgPool, user_id: i64) -> Result<Value, AdminError> {
    let result = sqlx::query(
        "UPDATE users SET status = 'active', updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(user_id)
    .execute(pool)
    .await?;
    if result.rows_affected() == 0 {
        return Err(AdminError::NotFound("user"));
    }
    Ok(json!({ "user_id": user_id, "status": "active" }))
}

async fn payment_dashboard(pool: &PgPool) -> Result<Value, AdminError> {
    let row = sqlx::query(
        r"
SELECT COUNT(*)::bigint AS total_orders,
       COUNT(*) FILTER (WHERE status = 'COMPLETED')::bigint AS completed_orders,
       COUNT(*) FILTER (WHERE status IN ('PENDING','CREATED'))::bigint AS pending_orders,
       COUNT(*) FILTER (WHERE status = 'REFUNDED')::bigint AS refunded_orders,
       COALESCE(SUM(pay_amount) FILTER (WHERE status = 'COMPLETED'),0)::double precision AS revenue
FROM payment_orders
",
    )
    .fetch_one(pool)
    .await?;
    Ok(json!({
        "total_orders": row.try_get::<i64, _>("total_orders")?,
        "completed_orders": row.try_get::<i64, _>("completed_orders")?,
        "pending_orders": row.try_get::<i64, _>("pending_orders")?,
        "refunded_orders": row.try_get::<i64, _>("refunded_orders")?,
        "revenue": row.try_get::<f64, _>("revenue")?,
    }))
}

async fn payment_config(pool: &PgPool) -> Result<Value, AdminError> {
    let rows =
        sqlx::query("SELECT key, value FROM settings WHERE key LIKE 'payment_%' ORDER BY key")
            .fetch_all(pool)
            .await?;
    let mut result = serde_json::Map::new();
    for row in rows {
        let key: String = row.try_get("key")?;
        let raw: String = row.try_get("value")?;
        result.insert(
            key,
            serde_json::from_str(&raw).unwrap_or(Value::String(raw)),
        );
    }
    Ok(Value::Object(result))
}

async fn update_payment_config(pool: &PgPool, payload: Value) -> Result<Value, AdminError> {
    let object = payload_object(payload.clone())?;
    let mut transaction = pool.begin().await?;
    for (key, value) in object {
        let key = format!("payment_{key}");
        let raw = serde_json::to_string(&value)
            .map_err(|error| AdminError::BadRequest(error.to_string()))?;
        sqlx::query(
            "INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, NOW()) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
        )
        .bind(key)
        .bind(raw)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(payload)
}

async fn set_payment_order_status(
    pool: &PgPool,
    id: i64,
    status: &str,
) -> Result<Value, AdminError> {
    let sql = format!(
        "UPDATE payment_orders row SET status = $2, updated_at = NOW() WHERE id = $1 AND status NOT IN ('COMPLETED','REFUNDED') RETURNING {}",
        redacted_json("row")
    );
    sqlx::query_scalar::<_, Value>(&sql)
        .bind(id)
        .bind(status)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AdminError::Conflict("payment order cannot change status".to_owned()))
}

async fn retry_payment_fulfillment(pool: &PgPool, id: i64) -> Result<Value, AdminError> {
    let sql = format!(
        "UPDATE payment_orders row SET status = CASE WHEN paid_at IS NULL THEN status ELSE 'PAID' END, error_message = NULL, updated_at = NOW() WHERE id = $1 AND status IN ('FAILED','PAID') RETURNING {}",
        redacted_json("row")
    );
    sqlx::query_scalar::<_, Value>(&sql)
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AdminError::Conflict("payment order is not retryable".to_owned()))
}

#[cfg(test)]
async fn resolve_ops_error(pool: &PgPool, id: i64, payload: &Value) -> Result<Value, AdminError> {
    let resolved = payload
        .get("resolved")
        .and_then(Value::as_bool)
        .ok_or_else(|| AdminError::BadRequest("resolved must be a boolean".to_owned()))?;
    let result = sqlx::query(
        r"
UPDATE ops_error_logs
SET resolved = $2,
    resolved_at = CASE WHEN $2 THEN NOW() ELSE NULL END,
    resolved_by_user_id = NULL
WHERE id = $1
",
    )
    .bind(id)
    .bind(resolved)
    .execute(pool)
    .await?;
    if result.rows_affected() == 0 {
        return Err(AdminError::NotFound("ops error"));
    }
    Ok(json!({ "ok": true }))
}

async fn update_alert_event_status(
    pool: &PgPool,
    id: i64,
    payload: &Value,
) -> Result<Value, AdminError> {
    let status = payload
        .get("status")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|status| matches!(*status, "resolved" | "manual_resolved"))
        .ok_or_else(|| AdminError::BadRequest("invalid alert event status".to_owned()))?;
    let result =
        sqlx::query("UPDATE ops_alert_events SET status = $2, resolved_at = NOW() WHERE id = $1")
            .bind(id)
            .bind(status)
            .execute(pool)
            .await?;
    if result.rows_affected() == 0 {
        return Err(AdminError::NotFound("alert event"));
    }
    Ok(json!({ "updated": true }))
}

async fn list_request_details(
    pool: &PgPool,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let page = query_i64(query, "page", 1).max(1);
    let page_size = query_i64(query, "page_size", 20).clamp(1, 100);
    let request_id = query.get("request_id").map(String::as_str);
    let platform = query.get("platform").map(String::as_str);
    let model = query.get("model").map(String::as_str);
    let search = query.get("q").map(String::as_str);
    let rows = sqlx::query(
        r"
WITH combined AS (
    SELECT created_at,
           to_jsonb(log) || jsonb_build_object('kind', 'success') AS data
    FROM usage_logs log
    UNION ALL
    SELECT created_at,
           to_jsonb(log) || jsonb_build_object('kind', 'error') AS data
    FROM ops_error_logs log
), filtered AS (
    SELECT created_at, data
    FROM combined
    WHERE ($1::text IS NULL OR data->>'request_id' = $1)
      AND ($2::text IS NULL OR data->>'platform' = $2)
      AND ($3::text IS NULL OR COALESCE(data->>'model', data->>'requested_model') = $3)
      AND ($4::text IS NULL OR data::text ILIKE '%' || $4 || '%')
)
SELECT data, COUNT(*) OVER()::bigint AS total
FROM filtered
ORDER BY created_at DESC
LIMIT $5 OFFSET $6
",
    )
    .bind(request_id)
    .bind(platform)
    .bind(model)
    .bind(search)
    .bind(page_size)
    .bind((page - 1) * page_size)
    .fetch_all(pool)
    .await?;
    let total = rows
        .first()
        .map_or(Ok(0_i64), |row| row.try_get::<i64, _>("total"))?;
    let items = rows
        .into_iter()
        .map(|row| row.try_get::<Value, _>("data"))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(json!({
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
    }))
}

fn default_metric_thresholds() -> Value {
    json!({
        "sla_percent_min": 99.5,
        "ttft_p99_ms_max": 500.0,
        "request_error_rate_percent_max": 5.0,
        "upstream_error_rate_percent_max": 5.0,
    })
}

async fn get_metric_thresholds(pool: &PgPool) -> Result<Value, AdminError> {
    let raw = sqlx::query_scalar::<_, String>(
        "SELECT value FROM settings WHERE key = 'ops_metric_thresholds'",
    )
    .fetch_optional(pool)
    .await?;
    Ok(raw
        .and_then(|value| serde_json::from_str::<Value>(&value).ok())
        .filter(Value::is_object)
        .unwrap_or_else(default_metric_thresholds))
}

async fn update_metric_thresholds(pool: &PgPool, payload: &Value) -> Result<Value, AdminError> {
    let object = payload
        .as_object()
        .ok_or_else(|| AdminError::BadRequest("request body must be a JSON object".to_owned()))?;
    for (key, minimum, maximum) in [
        ("sla_percent_min", 0.0, Some(100.0)),
        ("ttft_p99_ms_max", 0.0, None),
        ("request_error_rate_percent_max", 0.0, Some(100.0)),
        ("upstream_error_rate_percent_max", 0.0, Some(100.0)),
    ] {
        let Some(value) = object.get(key) else {
            continue;
        };
        if value.is_null() {
            continue;
        }
        let number = value
            .as_f64()
            .filter(|number| *number >= minimum && maximum.is_none_or(|max| *number <= max))
            .ok_or_else(|| AdminError::BadRequest(format!("invalid {key}")))?;
        let _ = number;
    }
    let raw = serde_json::to_string(payload)
        .map_err(|error| AdminError::BadRequest(error.to_string()))?;
    upsert_setting(pool, "ops_metric_thresholds", &raw).await?;
    Ok(payload.clone())
}

async fn settings_operation(
    pool: &PgPool,
    handler: &str,
    method: &Method,
    path: &str,
    payload: Value,
) -> Result<Value, AdminError> {
    if matches!(
        handler.rsplit('.').next(),
        Some("TestSMTPConnection" | "SendTestEmail" | "TestWebSearchEmulation")
    ) {
        return Err(AdminError::Unavailable(
            "the requested connectivity test requires an external service".to_owned(),
        ));
    }
    if handler.ends_with("RegenerateAdminAPIKey") {
        let token = format!("admin_{}", uuid::Uuid::new_v4().simple());
        let hash = hex::encode(sha2::Sha256::digest(token.as_bytes()));
        upsert_setting(pool, "admin_api_key_hash", &hash).await?;
        return Ok(json!({ "api_key": token }));
    }
    if handler.ends_with("GetAdminAPIKey") {
        let configured = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM settings WHERE key = 'admin_api_key_hash' AND value <> '')",
        )
        .fetch_one(pool)
        .await?;
        return Ok(json!({ "configured": configured }));
    }
    if handler.ends_with("DeleteAdminAPIKey") {
        sqlx::query("DELETE FROM settings WHERE key = 'admin_api_key_hash'")
            .execute(pool)
            .await?;
        return Ok(json!({ "message": "administrator API key deleted" }));
    }

    let mut key = path
        .trim_start_matches("/api/v1/admin/")
        .replace(['/', '-'], "_");
    if key.is_empty() {
        key = handler
            .rsplit('.')
            .next()
            .unwrap_or("runtime")
            .to_ascii_lowercase();
    }
    if handler.contains("EmailTemplate") {
        key = format!("email_template_{key}");
    }
    if method == Method::GET {
        let raw = sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key = $1")
            .bind(&key)
            .fetch_optional(pool)
            .await?;
        return Ok(raw.map_or(Value::Null, |value| {
            serde_json::from_str(&value).unwrap_or(Value::String(value))
        }));
    }
    if method == Method::DELETE || handler.contains("Reset") || handler.contains("RestoreOfficial")
    {
        sqlx::query("DELETE FROM settings WHERE key = $1")
            .bind(&key)
            .execute(pool)
            .await?;
        return Ok(json!({ "message": "setting reset" }));
    }
    let raw = serde_json::to_string(&payload)
        .map_err(|error| AdminError::BadRequest(error.to_string()))?;
    upsert_setting(pool, &key, &raw).await?;
    Ok(payload)
}

async fn upsert_setting(pool: &PgPool, key: &str, value: &str) -> Result<(), AdminError> {
    sqlx::query(
        "INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, NOW()) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
    )
    .bind(key)
    .bind(value)
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use sqlx::postgres::PgPoolOptions;

    use super::*;

    #[test]
    fn payload_ids_rejects_non_numeric_values() {
        assert!(payload_ids(&json!({ "ids": [1, 2] })).is_ok());
        assert!(payload_ids(&json!({ "ids": ["1"] })).is_err());
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL pointing at a migrated disposable *_test database"]
    async fn postgres_ops_mutations_and_combined_request_list_are_live() {
        let database_url = std::env::var("TEST_DATABASE_URL").unwrap();
        let parsed = url::Url::parse(&database_url).unwrap();
        assert!(parsed.path().trim_matches('/').ends_with("_test"));
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .unwrap();
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let request_id = format!("ops-{suffix}");
        let error_id = sqlx::query_scalar::<_, i64>(
            "INSERT INTO ops_error_logs (request_id, error_phase, error_type) VALUES ($1, 'upstream', 'test') RETURNING id",
        )
        .bind(&request_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        resolve_ops_error(&pool, error_id, &json!({ "resolved": true }))
            .await
            .unwrap();
        let resolved =
            sqlx::query_scalar::<_, bool>("SELECT resolved FROM ops_error_logs WHERE id = $1")
                .bind(error_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(resolved);

        let rule_id = sqlx::query_scalar::<_, i64>(
            "INSERT INTO ops_alert_rules (name, metric_type, operator, threshold) VALUES ($1, 'request_error_rate', 'gt', 5) RETURNING id",
        )
        .bind(format!("rust-ops-{suffix}"))
        .fetch_one(&pool)
        .await
        .unwrap();
        let event_id = sqlx::query_scalar::<_, i64>(
            "INSERT INTO ops_alert_events (rule_id, severity) VALUES ($1, 'warning') RETURNING id",
        )
        .bind(rule_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        update_alert_event_status(&pool, event_id, &json!({ "status": "manual_resolved" }))
            .await
            .unwrap();

        let thresholds = json!({
            "sla_percent_min": 99.9,
            "request_error_rate_percent_max": 3.0,
        });
        update_metric_thresholds(&pool, &thresholds).await.unwrap();
        assert_eq!(get_metric_thresholds(&pool).await.unwrap(), thresholds);
        let query = BTreeMap::from([("request_id".to_owned(), request_id.clone())]);
        let requests = list_request_details(&pool, &query).await.unwrap();
        assert_eq!(requests["total"], 1);
        assert_eq!(requests["items"][0]["kind"], "error");

        sqlx::query("DELETE FROM ops_alert_events WHERE id = $1")
            .bind(event_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM ops_alert_rules WHERE id = $1")
            .bind(rule_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM ops_error_logs WHERE id = $1")
            .bind(error_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM settings WHERE key = 'ops_metric_thresholds'")
            .execute(&pool)
            .await
            .unwrap();
    }
}
