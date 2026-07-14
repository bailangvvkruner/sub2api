//! PostgreSQL-backed semantics for the Go administrator operations API.

use std::collections::BTreeMap;

use axum::http::Method;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use sqlx::{PgPool, Row};

use super::{
    AdminError, AdminIdentity,
    compat::{redacted_json, required_path_id},
    compat_special,
};

const EMAIL_CONFIG_KEY: &str = "ops_email_notification_config";
const ALERT_RUNTIME_KEY: &str = "ops_alert_runtime_settings";
const ADVANCED_SETTINGS_KEY: &str = "ops_advanced_settings";
const RUNTIME_LOG_KEY: &str = "ops_runtime_log_config";
const METRIC_THRESHOLDS_KEY: &str = "ops_metric_thresholds";

#[allow(clippy::too_many_arguments)]
pub(super) async fn dispatch(
    pool: &PgPool,
    actor: &AdminIdentity,
    handler: &str,
    category: &str,
    method: &Method,
    path: &str,
    query: &BTreeMap<String, String>,
    payload: Value,
) -> Option<Result<Value, AdminError>> {
    if handler == "h.Admin.ContentModeration.ListLogs" {
        return Some(list_moderation_logs(pool, query).await);
    }
    if category != "admin/ops" || !owns_handler(handler) {
        return None;
    }

    let result = match handler {
        "h.Admin.Ops.ListAlertRules" => list_alert_rules(pool).await,
        "h.Admin.Ops.CreateAlertRule" => create_alert_rule(pool, &payload).await,
        "h.Admin.Ops.UpdateAlertRule" => {
            update_alert_rule(pool, required_path_id(path, "alert rule").ok()?, &payload).await
        }
        "h.Admin.Ops.DeleteAlertRule" => {
            delete_alert_rule(pool, required_path_id(path, "alert rule").ok()?).await
        }
        "h.Admin.Ops.ListAlertEvents" => list_alert_events(pool, query).await,
        "h.Admin.Ops.GetAlertEvent" => {
            get_alert_event(pool, required_path_id(path, "alert event").ok()?).await
        }
        "h.Admin.Ops.UpdateAlertEventStatus" => {
            update_alert_event(pool, required_path_id(path, "alert event").ok()?, &payload).await
        }
        "h.Admin.Ops.CreateAlertSilence" => create_alert_silence(pool, actor, &payload).await,
        "h.Admin.Ops.GetEmailNotificationConfig" => {
            read_json_setting(pool, EMAIL_CONFIG_KEY, default_email_config()).await
        }
        "h.Admin.Ops.UpdateEmailNotificationConfig" => update_email_config(pool, &payload).await,
        "h.Admin.Ops.GetAlertRuntimeSettings" => {
            read_json_setting(pool, ALERT_RUNTIME_KEY, default_alert_runtime()).await
        }
        "h.Admin.Ops.UpdateAlertRuntimeSettings" => update_alert_runtime(pool, &payload).await,
        "h.Admin.Ops.GetAdvancedSettings" => {
            read_json_setting(pool, ADVANCED_SETTINGS_KEY, default_advanced_settings()).await
        }
        "h.Admin.Ops.UpdateAdvancedSettings" => update_advanced_settings(pool, &payload).await,
        "h.Admin.Ops.GetRuntimeLogConfig" => {
            read_json_setting(pool, RUNTIME_LOG_KEY, default_runtime_log()).await
        }
        "h.Admin.Ops.UpdateRuntimeLogConfig" => update_runtime_log(pool, actor, &payload).await,
        "h.Admin.Ops.ResetRuntimeLogConfig" => reset_runtime_log(pool).await,
        "h.Admin.Ops.GetMetricThresholds" => {
            read_json_setting(pool, METRIC_THRESHOLDS_KEY, default_metric_thresholds()).await
        }
        "h.Admin.Ops.UpdateMetricThresholds" => update_metric_thresholds(pool, &payload).await,
        "h.Admin.Ops.ListSystemLogs" => list_system_logs(pool, query).await,
        "h.Admin.Ops.CleanupSystemLogs" => cleanup_system_logs(pool, actor, &payload).await,
        "h.Admin.Ops.GetSystemLogIngestionHealth" => system_log_health(pool).await,
        "h.Admin.Ops.GetDashboardOverview" => dashboard_overview(pool, query).await,
        "h.Admin.Ops.GetDashboardSnapshotV2" => dashboard_snapshot(pool, query).await,
        "h.Admin.Ops.GetDashboardThroughputTrend" => dashboard_throughput(pool, query).await,
        "h.Admin.Ops.GetDashboardErrorTrend" => dashboard_error_trend(pool, query).await,
        "h.Admin.Ops.GetDashboardLatencyHistogram" => {
            dashboard_latency_histogram(pool, query).await
        }
        "h.Admin.Ops.GetDashboardErrorDistribution" => {
            dashboard_error_distribution(pool, query).await
        }
        "h.Admin.Ops.GetDashboardOpenAITokenStats" => {
            dashboard_openai_token_stats(pool, query).await
        }
        "h.Admin.Ops.GetErrorLogs"
        | "h.Admin.Ops.ListRequestErrors"
        | "h.Admin.Ops.ListUpstreamErrors" => list_ops_errors(pool, handler, query, None).await,
        "h.Admin.Ops.GetErrorLogByID"
        | "h.Admin.Ops.GetRequestError"
        | "h.Admin.Ops.GetUpstreamError" => {
            get_ops_error(pool, required_path_id(path, "ops error").ok()?).await
        }
        "h.Admin.Ops.ListRequestErrorUpstreamErrors" => {
            list_request_error_upstream(pool, required_path_id(path, "ops error").ok()?, query)
                .await
        }
        "h.Admin.Ops.UpdateErrorResolution"
        | "h.Admin.Ops.ResolveRequestError"
        | "h.Admin.Ops.ResolveUpstreamError" => {
            resolve_error(
                pool,
                actor,
                required_path_id(path, "ops error").ok()?,
                &payload,
            )
            .await
        }
        _ => {
            return compat_special::dispatch(pool, handler, category, method, path, query, payload)
                .await;
        }
    };
    Some(result)
}

pub(super) fn owns_handler(handler: &str) -> bool {
    matches!(
        handler,
        "h.Admin.Ops.GetAccountAvailability"
            | "h.Admin.Ops.GetAdvancedSettings"
            | "h.Admin.Ops.UpdateAdvancedSettings"
            | "h.Admin.Ops.ListAlertEvents"
            | "h.Admin.Ops.GetAlertEvent"
            | "h.Admin.Ops.UpdateAlertEventStatus"
            | "h.Admin.Ops.ListAlertRules"
            | "h.Admin.Ops.CreateAlertRule"
            | "h.Admin.Ops.DeleteAlertRule"
            | "h.Admin.Ops.UpdateAlertRule"
            | "h.Admin.Ops.CreateAlertSilence"
            | "h.Admin.Ops.GetConcurrencyStats"
            | "h.Admin.Ops.GetDashboardErrorDistribution"
            | "h.Admin.Ops.GetDashboardErrorTrend"
            | "h.Admin.Ops.GetDashboardLatencyHistogram"
            | "h.Admin.Ops.GetDashboardOpenAITokenStats"
            | "h.Admin.Ops.GetDashboardOverview"
            | "h.Admin.Ops.GetDashboardSnapshotV2"
            | "h.Admin.Ops.GetDashboardThroughputTrend"
            | "h.Admin.Ops.GetEmailNotificationConfig"
            | "h.Admin.Ops.UpdateEmailNotificationConfig"
            | "h.Admin.Ops.GetErrorLogs"
            | "h.Admin.Ops.GetErrorLogByID"
            | "h.Admin.Ops.UpdateErrorResolution"
            | "h.Admin.Ops.GetRealtimeTrafficSummary"
            | "h.Admin.Ops.ListRequestErrors"
            | "h.Admin.Ops.GetRequestError"
            | "h.Admin.Ops.ResolveRequestError"
            | "h.Admin.Ops.ListRequestErrorUpstreamErrors"
            | "h.Admin.Ops.ListRequestDetails"
            | "h.Admin.Ops.GetAlertRuntimeSettings"
            | "h.Admin.Ops.UpdateAlertRuntimeSettings"
            | "h.Admin.Ops.GetRuntimeLogConfig"
            | "h.Admin.Ops.UpdateRuntimeLogConfig"
            | "h.Admin.Ops.ResetRuntimeLogConfig"
            | "h.Admin.Ops.GetMetricThresholds"
            | "h.Admin.Ops.UpdateMetricThresholds"
            | "h.Admin.Ops.ListSystemLogs"
            | "h.Admin.Ops.CleanupSystemLogs"
            | "h.Admin.Ops.GetSystemLogIngestionHealth"
            | "h.Admin.Ops.ListUpstreamErrors"
            | "h.Admin.Ops.GetUpstreamError"
            | "h.Admin.Ops.ResolveUpstreamError"
            | "h.Admin.Ops.GetUserConcurrencyStats"
    )
}

fn alert_rule_json(alias: &str) -> String {
    format!(
        "to_jsonb({alias}) || jsonb_build_object('description', COALESCE({alias}.description,''), 'severity', COALESCE({alias}.severity,''), 'notify_email', COALESCE({alias}.notify_email,TRUE))"
    )
}

async fn list_alert_rules(pool: &PgPool) -> Result<Value, AdminError> {
    let sql = format!(
        "SELECT {} AS data FROM ops_alert_rules rule ORDER BY rule.id DESC",
        alert_rule_json("rule")
    );
    json_rows(pool, &sql).await.map(Value::Array)
}

#[derive(Debug)]
struct AlertRuleInput<'a> {
    name: &'a str,
    description: &'a str,
    enabled: bool,
    severity: &'a str,
    metric_type: &'a str,
    operator: &'a str,
    threshold: f64,
    window_minutes: i32,
    sustained_minutes: i32,
    cooldown_minutes: i32,
    notify_email: bool,
    filters: Option<&'a Value>,
}

#[allow(
    clippy::too_many_lines,
    reason = "all alert-rule field validation stays together to preserve the compatibility contract"
)]
fn validate_alert_rule(payload: &Value) -> Result<AlertRuleInput<'_>, AdminError> {
    let object = object(payload)?;
    let name = required_text(object, "name")?;
    let metric_type = required_text(object, "metric_type")?;
    let valid_metric = matches!(
        metric_type,
        "success_rate"
            | "error_rate"
            | "upstream_error_rate"
            | "cpu_usage_percent"
            | "memory_usage_percent"
            | "concurrency_queue_depth"
            | "group_available_accounts"
            | "group_available_ratio"
            | "group_rate_limit_ratio"
            | "account_rate_limited_count"
            | "account_error_count"
            | "account_error_ratio"
            | "account_temp_unscheduled_count"
            | "overload_account_count"
            | "proxy_expired_count"
            | "proxy_expiring_soon_count"
    );
    if !valid_metric {
        return Err(AdminError::BadRequest("invalid metric_type".to_owned()));
    }
    let operator = required_text(object, "operator")?;
    if !matches!(operator, ">" | "<" | ">=" | "<=" | "==" | "!=") {
        return Err(AdminError::BadRequest("invalid operator".to_owned()));
    }
    let threshold = object
        .get("threshold")
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite() && *value >= 0.0)
        .ok_or_else(|| {
            AdminError::BadRequest("threshold must be a finite number >= 0".to_owned())
        })?;
    let percent_metric = matches!(
        metric_type,
        "success_rate"
            | "error_rate"
            | "upstream_error_rate"
            | "cpu_usage_percent"
            | "memory_usage_percent"
            | "group_available_ratio"
            | "group_rate_limit_ratio"
            | "account_error_ratio"
    );
    if percent_metric && threshold > 100.0 {
        return Err(AdminError::BadRequest(
            "threshold must be between 0 and 100".to_owned(),
        ));
    }
    let severity = object
        .get("severity")
        .and_then(Value::as_str)
        .unwrap_or("P2");
    if !matches!(severity, "P0" | "P1" | "P2" | "P3") {
        return Err(AdminError::BadRequest("invalid severity".to_owned()));
    }
    let window_minutes = optional_i32(object, "window_minutes", 1)?;
    if !matches!(window_minutes, 1 | 5 | 60) {
        return Err(AdminError::BadRequest(
            "window_minutes must be one of 1, 5, 60".to_owned(),
        ));
    }
    let sustained_minutes = optional_i32(object, "sustained_minutes", 1)?;
    let cooldown_minutes = optional_i32(object, "cooldown_minutes", 0)?;
    if !(1..=1_440).contains(&sustained_minutes) || !(0..=1_440).contains(&cooldown_minutes) {
        return Err(AdminError::BadRequest(
            "invalid sustained_minutes or cooldown_minutes".to_owned(),
        ));
    }
    let filters = object.get("filters").filter(|value| !value.is_null());
    if filters.is_some_and(|value| !value.is_object()) {
        return Err(AdminError::BadRequest(
            "filters must be an object".to_owned(),
        ));
    }
    Ok(AlertRuleInput {
        name,
        description: object
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        enabled: object
            .get("enabled")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        severity,
        metric_type,
        operator,
        threshold,
        window_minutes,
        sustained_minutes,
        cooldown_minutes,
        notify_email: object
            .get("notify_email")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        filters,
    })
}

async fn create_alert_rule(pool: &PgPool, payload: &Value) -> Result<Value, AdminError> {
    let rule = validate_alert_rule(payload)?;
    let sql = format!(
        "INSERT INTO ops_alert_rules (name,description,enabled,severity,metric_type,operator,threshold,window_minutes,sustained_minutes,cooldown_minutes,notify_email,filters,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW(),NOW()) RETURNING {}",
        alert_rule_json("ops_alert_rules")
    );
    sqlx::query_scalar::<_, Value>(&sql)
        .bind(rule.name)
        .bind(rule.description)
        .bind(rule.enabled)
        .bind(rule.severity)
        .bind(rule.metric_type)
        .bind(rule.operator)
        .bind(rule.threshold)
        .bind(rule.window_minutes)
        .bind(rule.sustained_minutes)
        .bind(rule.cooldown_minutes)
        .bind(rule.notify_email)
        .bind(rule.filters)
        .fetch_one(pool)
        .await
        .map_err(Into::into)
}

async fn update_alert_rule(pool: &PgPool, id: i64, payload: &Value) -> Result<Value, AdminError> {
    let rule = validate_alert_rule(payload)?;
    let sql = format!(
        "UPDATE ops_alert_rules SET name=$2,description=$3,enabled=$4,severity=$5,metric_type=$6,operator=$7,threshold=$8,window_minutes=$9,sustained_minutes=$10,cooldown_minutes=$11,notify_email=$12,filters=$13,updated_at=NOW() WHERE id=$1 RETURNING {}",
        alert_rule_json("ops_alert_rules")
    );
    sqlx::query_scalar::<_, Value>(&sql)
        .bind(id)
        .bind(rule.name)
        .bind(rule.description)
        .bind(rule.enabled)
        .bind(rule.severity)
        .bind(rule.metric_type)
        .bind(rule.operator)
        .bind(rule.threshold)
        .bind(rule.window_minutes)
        .bind(rule.sustained_minutes)
        .bind(rule.cooldown_minutes)
        .bind(rule.notify_email)
        .bind(rule.filters)
        .fetch_optional(pool)
        .await?
        .ok_or(AdminError::NotFound("alert rule"))
}

async fn delete_alert_rule(pool: &PgPool, id: i64) -> Result<Value, AdminError> {
    let result = sqlx::query("DELETE FROM ops_alert_rules WHERE id=$1")
        .bind(id)
        .execute(pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(AdminError::NotFound("alert rule"));
    }
    Ok(json!({ "deleted": true }))
}

async fn list_alert_events(
    pool: &PgPool,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let limit = query_positive_i64(query, "limit", 20)?.clamp(1, 500);
    let status = nonempty(query.get("status"));
    let severity = nonempty(query.get("severity"));
    let email_sent = query_bool(query, "email_sent")?;
    let before_id = query_optional_positive_i64(query, "before_id")?;
    let before_time = validated_timestamp_text(query.get("before_fired_at"), "before_fired_at")?;
    if before_id.is_some() != before_time.is_some() {
        return Err(AdminError::BadRequest(
            "before_fired_at and before_id must be provided together".to_owned(),
        ));
    }
    let rows = sqlx::query(
        r"
SELECT to_jsonb(event) AS data
FROM ops_alert_events event
WHERE ($1::text IS NULL OR event.status=$1)
  AND ($2::text IS NULL OR event.severity=$2)
  AND ($3::boolean IS NULL OR event.email_sent=$3)
  AND ($4::timestamptz IS NULL OR (event.fired_at,event.id) < ($4::timestamptz,$5))
ORDER BY event.fired_at DESC,event.id DESC LIMIT $6
",
    )
    .bind(status)
    .bind(severity)
    .bind(email_sent)
    .bind(before_time.as_deref())
    .bind(before_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(Value::Array(extract_json_rows(rows)?))
}

async fn get_alert_event(pool: &PgPool, id: i64) -> Result<Value, AdminError> {
    sqlx::query_scalar::<_, Value>(
        "SELECT to_jsonb(event) FROM ops_alert_events event WHERE event.id=$1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(AdminError::NotFound("alert event"))
}

async fn update_alert_event(pool: &PgPool, id: i64, payload: &Value) -> Result<Value, AdminError> {
    let status = payload
        .get("status")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| matches!(*value, "resolved" | "manual_resolved"))
        .ok_or_else(|| AdminError::BadRequest("invalid status".to_owned()))?;
    let result = sqlx::query("UPDATE ops_alert_events SET status=$2,resolved_at=NOW() WHERE id=$1")
        .bind(id)
        .bind(status)
        .execute(pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(AdminError::NotFound("alert event"));
    }
    Ok(json!({ "updated": true }))
}

async fn create_alert_silence(
    pool: &PgPool,
    actor: &AdminIdentity,
    payload: &Value,
) -> Result<Value, AdminError> {
    let object = object(payload)?;
    let rule_id = required_positive_i64(object, "rule_id")?;
    let platform = required_text(object, "platform")?;
    let until = validated_timestamp(object.get("until"), "until")?
        .ok_or_else(|| AdminError::BadRequest("until is required".to_owned()))?;
    let group_id = optional_positive_i64(object, "group_id")?;
    let region = object.get("region").and_then(Value::as_str).map(str::trim);
    let reason = object
        .get("reason")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    let sql = format!(
        "INSERT INTO ops_alert_silences (rule_id,platform,group_id,region,until,reason,created_by,created_at) VALUES ($1,$2,$3,$4,$5::timestamptz,$6,$7,NOW()) RETURNING {}",
        redacted_json("ops_alert_silences")
    );
    sqlx::query_scalar::<_, Value>(&sql)
        .bind(rule_id)
        .bind(platform)
        .bind(group_id)
        .bind(region)
        .bind(until)
        .bind(reason)
        .bind(actor.user_id)
        .fetch_one(pool)
        .await
        .map_err(Into::into)
}

async fn resolve_error(
    pool: &PgPool,
    actor: &AdminIdentity,
    id: i64,
    payload: &Value,
) -> Result<Value, AdminError> {
    let resolved = payload
        .get("resolved")
        .and_then(Value::as_bool)
        .ok_or_else(|| AdminError::BadRequest("resolved must be a boolean".to_owned()))?;
    let result = sqlx::query(
        "UPDATE ops_error_logs SET resolved=$2,resolved_at=CASE WHEN $2 THEN NOW() ELSE NULL END,resolved_by_user_id=CASE WHEN $2 THEN $3 ELSE NULL END WHERE id=$1",
    )
    .bind(id)
    .bind(resolved)
    .bind(actor.user_id)
    .execute(pool)
    .await?;
    if result.rows_affected() == 0 {
        return Err(AdminError::NotFound("ops error"));
    }
    Ok(json!({ "ok": true }))
}

fn default_email_config() -> Value {
    json!({
        "alert": { "enabled": true, "recipients": [], "min_severity": "", "rate_limit_per_hour": 0, "batching_window_seconds": 0, "include_resolved_alerts": false },
        "report": { "enabled": false, "recipients": [], "daily_summary_enabled": false, "daily_summary_schedule": "0 9 * * *", "weekly_summary_enabled": false, "weekly_summary_schedule": "0 9 * * 1", "error_digest_enabled": false, "error_digest_schedule": "0 9 * * *", "error_digest_min_count": 10, "account_health_enabled": false, "account_health_schedule": "0 9 * * *", "account_health_error_rate_threshold": 10.0 }
    })
}

fn default_alert_runtime() -> Value {
    json!({
        "evaluation_interval_seconds": 60,
        "distributed_lock": { "enabled": true, "key": "ops:alert:evaluator:leader", "ttl_seconds": 30 },
        "silencing": { "enabled": false, "global_until_rfc3339": "", "global_reason": "", "entries": [] },
        "thresholds": {}
    })
}

fn default_advanced_settings() -> Value {
    json!({
        "data_retention": { "cleanup_enabled": false, "cleanup_schedule": "0 3 * * *", "error_log_retention_days": 30, "minute_metrics_retention_days": 30, "hourly_metrics_retention_days": 30 },
        "aggregation": { "aggregation_enabled": false },
        "openai_account_quota_auto_pause": { "default_threshold_5h": 0.0, "default_threshold_7d": 0.0 },
        "ignore_count_tokens_errors": true,
        "ignore_context_canceled": true,
        "ignore_no_available_accounts": false,
        "ignore_invalid_api_key_errors": false,
        "ignore_insufficient_balance_errors": false,
        "display_openai_token_stats": false,
        "display_alert_events": true,
        "auto_refresh_enabled": false,
        "auto_refresh_interval_seconds": 30
    })
}

fn default_runtime_log() -> Value {
    json!({ "level": "info", "enable_sampling": false, "sampling_initial": 100, "sampling_thereafter": 100, "caller": false, "stacktrace_level": "error", "retention_days": 30, "source": "default" })
}

fn default_metric_thresholds() -> Value {
    json!({ "sla_percent_min": null, "ttft_p99_ms_max": null, "request_error_rate_percent_max": null, "upstream_error_rate_percent_max": null })
}

async fn update_email_config(pool: &PgPool, payload: &Value) -> Result<Value, AdminError> {
    object(payload)?;
    let mut config = read_json_setting(pool, EMAIL_CONFIG_KEY, default_email_config()).await?;
    merge_json(&mut config, payload.clone());
    let alert = config
        .get("alert")
        .and_then(Value::as_object)
        .ok_or_else(|| AdminError::BadRequest("alert config is required".to_owned()))?;
    validate_nonnegative(alert, "rate_limit_per_hour")?;
    validate_nonnegative(alert, "batching_window_seconds")?;
    if !matches!(
        alert
            .get("min_severity")
            .and_then(Value::as_str)
            .unwrap_or(""),
        "" | "critical" | "warning" | "info"
    ) {
        return Err(AdminError::BadRequest(
            "invalid alert.min_severity".to_owned(),
        ));
    }
    let report = config
        .get("report")
        .and_then(Value::as_object)
        .ok_or_else(|| AdminError::BadRequest("report config is required".to_owned()))?;
    validate_nonnegative(report, "error_digest_min_count")?;
    validate_range(report, "account_health_error_rate_threshold", 0.0, 100.0)?;
    write_json_setting(pool, EMAIL_CONFIG_KEY, &config).await?;
    Ok(config)
}

async fn update_alert_runtime(pool: &PgPool, payload: &Value) -> Result<Value, AdminError> {
    let mut config = default_alert_runtime();
    merge_json(&mut config, payload.clone());
    let object = object(&config)?;
    validate_i64_range(object, "evaluation_interval_seconds", 1, 86_400)?;
    let lock = object
        .get("distributed_lock")
        .and_then(Value::as_object)
        .ok_or_else(|| AdminError::BadRequest("distributed_lock is required".to_owned()))?;
    if lock
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        required_text(lock, "key")?;
        validate_i64_range(lock, "ttl_seconds", 1, 86_400)?;
    }
    validate_silencing(object.get("silencing"))?;
    write_json_setting(pool, ALERT_RUNTIME_KEY, &config).await?;
    Ok(config)
}

fn validate_silencing(value: Option<&Value>) -> Result<(), AdminError> {
    let Some(value) = value else { return Ok(()) };
    let settings = object(value)?;
    if !settings
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(());
    }
    validated_timestamp(settings.get("global_until_rfc3339"), "global_until_rfc3339")?;
    if let Some(entries) = settings.get("entries").and_then(Value::as_array) {
        for entry in entries {
            let entry = object(entry)?;
            validated_timestamp(entry.get("until_rfc3339"), "until_rfc3339")?
                .ok_or_else(|| AdminError::BadRequest("until_rfc3339 is required".to_owned()))?;
        }
    }
    Ok(())
}

async fn update_advanced_settings(pool: &PgPool, payload: &Value) -> Result<Value, AdminError> {
    let mut config = default_advanced_settings();
    merge_json(&mut config, payload.clone());
    let object = object(&config)?;
    let retention = object
        .get("data_retention")
        .and_then(Value::as_object)
        .ok_or_else(|| AdminError::BadRequest("data_retention is required".to_owned()))?;
    for key in [
        "error_log_retention_days",
        "minute_metrics_retention_days",
        "hourly_metrics_retention_days",
    ] {
        validate_i64_range(retention, key, 0, 365)?;
    }
    validate_i64_range(object, "auto_refresh_interval_seconds", 15, 300)?;
    let quota = object
        .get("openai_account_quota_auto_pause")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            AdminError::BadRequest("openai_account_quota_auto_pause is required".to_owned())
        })?;
    validate_range(quota, "default_threshold_5h", 0.0, 1.0)?;
    validate_range(quota, "default_threshold_7d", 0.0, 1.0)?;
    write_json_setting(pool, ADVANCED_SETTINGS_KEY, &config).await?;
    Ok(config)
}

async fn update_runtime_log(
    pool: &PgPool,
    actor: &AdminIdentity,
    payload: &Value,
) -> Result<Value, AdminError> {
    let mut config = default_runtime_log();
    merge_json(&mut config, payload.clone());
    let object = object(&config)?;
    if !matches!(
        object.get("level").and_then(Value::as_str),
        Some("debug" | "info" | "warn" | "error")
    ) {
        return Err(AdminError::BadRequest("invalid log level".to_owned()));
    }
    if !matches!(
        object.get("stacktrace_level").and_then(Value::as_str),
        Some("none" | "error" | "fatal")
    ) {
        return Err(AdminError::BadRequest(
            "invalid stacktrace_level".to_owned(),
        ));
    }
    validate_i64_range(object, "sampling_initial", 1, 1_000_000)?;
    validate_i64_range(object, "sampling_thereafter", 1, 1_000_000)?;
    validate_i64_range(object, "retention_days", 1, 3_650)?;
    config["source"] = Value::String("database".to_owned());
    config["updated_at"] = Value::String(Utc::now().to_rfc3339());
    config["updated_by_user_id"] = Value::from(actor.user_id);
    write_json_setting(pool, RUNTIME_LOG_KEY, &config).await?;
    Ok(config)
}

async fn reset_runtime_log(pool: &PgPool) -> Result<Value, AdminError> {
    sqlx::query("DELETE FROM settings WHERE key=$1")
        .bind(RUNTIME_LOG_KEY)
        .execute(pool)
        .await?;
    Ok(default_runtime_log())
}

async fn update_metric_thresholds(pool: &PgPool, payload: &Value) -> Result<Value, AdminError> {
    let object = object(payload)?;
    for key in [
        "sla_percent_min",
        "request_error_rate_percent_max",
        "upstream_error_rate_percent_max",
    ] {
        validate_nullable_range(object, key, 0.0, 100.0)?;
    }
    validate_nullable_range(object, "ttft_p99_ms_max", 0.0, f64::MAX)?;
    let mut config = default_metric_thresholds();
    merge_json(&mut config, payload.clone());
    write_json_setting(pool, METRIC_THRESHOLDS_KEY, &config).await?;
    Ok(config)
}

async fn read_json_setting(
    pool: &PgPool,
    key: &str,
    mut defaults: Value,
) -> Result<Value, AdminError> {
    let raw = sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key=$1")
        .bind(key)
        .fetch_optional(pool)
        .await?;
    if let Some(stored) = raw.and_then(|value| serde_json::from_str::<Value>(&value).ok())
        && stored.is_object()
    {
        merge_json(&mut defaults, stored);
    }
    Ok(defaults)
}

async fn write_json_setting(pool: &PgPool, key: &str, value: &Value) -> Result<(), AdminError> {
    let encoded =
        serde_json::to_string(value).map_err(|error| AdminError::BadRequest(error.to_string()))?;
    sqlx::query(
        "INSERT INTO settings (key,value,updated_at) VALUES ($1,$2,NOW()) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value,updated_at=NOW()",
    )
    .bind(key)
    .bind(encoded)
    .execute(pool)
    .await?;
    Ok(())
}

fn merge_json(target: &mut Value, patch: Value) {
    match (target, patch) {
        (Value::Object(target), Value::Object(patch)) => {
            for (key, value) in patch {
                if let Some(existing) = target.get_mut(&key) {
                    merge_json(existing, value);
                } else {
                    target.insert(key, value);
                }
            }
        }
        (target, value) => *target = value,
    }
}

async fn list_system_logs(
    pool: &PgPool,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let page = query_positive_i64(query, "page", 1)?;
    let page_size = query_positive_i64(query, "page_size", 20)?.clamp(1, 200);
    let range = TimeRange::from_query(query, "1h")?;
    let user_id = query_optional_positive_i64(query, "user_id")?;
    let api_key_id = query_optional_positive_i64(query, "api_key_id")?;
    let account_id = query_optional_positive_i64(query, "account_id")?;
    let rows = sqlx::query(
        r"
SELECT to_jsonb(log) AS data,COUNT(*) OVER()::bigint AS total
FROM ops_system_logs log
WHERE log.created_at >= $1::timestamptz AND log.created_at < $2::timestamptz
  AND ($3::text IS NULL OR log.level=$3)
  AND ($4::text IS NULL OR log.component=$4)
  AND ($5::text IS NULL OR log.request_id=$5)
  AND ($6::text IS NULL OR log.client_request_id=$6)
  AND ($7::bigint IS NULL OR log.user_id=$7)
  AND ($8::bigint IS NULL OR log.api_key_id=$8)
  AND ($9::bigint IS NULL OR log.account_id=$9)
  AND ($10::text IS NULL OR log.platform=$10)
  AND ($11::text IS NULL OR log.model=$11)
  AND ($12::text IS NULL OR log.message ILIKE '%'||$12||'%' OR log.extra::text ILIKE '%'||$12||'%')
ORDER BY log.created_at DESC,log.id DESC LIMIT $13 OFFSET $14
",
    )
    .bind(&range.start)
    .bind(&range.end)
    .bind(nonempty(query.get("level")))
    .bind(nonempty(query.get("component")))
    .bind(nonempty(query.get("request_id")))
    .bind(nonempty(query.get("client_request_id")))
    .bind(user_id)
    .bind(api_key_id)
    .bind(account_id)
    .bind(nonempty(query.get("platform")))
    .bind(nonempty(query.get("model")))
    .bind(nonempty(query.get("q")))
    .bind(page_size)
    .bind((page - 1) * page_size)
    .fetch_all(pool)
    .await?;
    paginated_rows(rows, page, page_size)
}

async fn cleanup_system_logs(
    pool: &PgPool,
    actor: &AdminIdentity,
    payload: &Value,
) -> Result<Value, AdminError> {
    let object = object(payload)?;
    let start = validated_timestamp(object.get("start_time"), "start_time")?;
    let end = validated_timestamp(object.get("end_time"), "end_time")?;
    let user_id = optional_positive_i64(object, "user_id")?;
    let api_key_id = optional_positive_i64(object, "api_key_id")?;
    let account_id = optional_positive_i64(object, "account_id")?;
    let mut transaction = pool.begin().await?;
    let result = sqlx::query(
        r"
DELETE FROM ops_system_logs log
WHERE ($1::timestamptz IS NULL OR log.created_at >= $1::timestamptz)
  AND ($2::timestamptz IS NULL OR log.created_at < $2::timestamptz)
  AND ($3::text IS NULL OR log.level=$3)
  AND ($4::text IS NULL OR log.component=$4)
  AND ($5::text IS NULL OR log.request_id=$5)
  AND ($6::text IS NULL OR log.client_request_id=$6)
  AND ($7::bigint IS NULL OR log.user_id=$7)
  AND ($8::bigint IS NULL OR log.api_key_id=$8)
  AND ($9::bigint IS NULL OR log.account_id=$9)
  AND ($10::text IS NULL OR log.platform=$10)
  AND ($11::text IS NULL OR log.model=$11)
  AND ($12::text IS NULL OR log.message ILIKE '%'||$12||'%' OR log.extra::text ILIKE '%'||$12||'%')
",
    )
    .bind(start.as_deref())
    .bind(end.as_deref())
    .bind(optional_text(object, "level")?)
    .bind(optional_text(object, "component")?)
    .bind(optional_text(object, "request_id")?)
    .bind(optional_text(object, "client_request_id")?)
    .bind(user_id)
    .bind(api_key_id)
    .bind(account_id)
    .bind(optional_text(object, "platform")?)
    .bind(optional_text(object, "model")?)
    .bind(optional_text(object, "q")?)
    .execute(&mut *transaction)
    .await?;
    let deleted = i64::try_from(result.rows_affected()).unwrap_or(i64::MAX);
    sqlx::query(
        "INSERT INTO ops_system_log_cleanup_audits (operator_id,conditions,deleted_rows,created_at) VALUES ($1,$2,$3,NOW())",
    )
    .bind(actor.user_id)
    .bind(payload)
    .bind(deleted)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(json!({ "deleted": deleted }))
}

async fn system_log_health(pool: &PgPool) -> Result<Value, AdminError> {
    let row = sqlx::query(
        "SELECT COUNT(*)::bigint AS written_count,COUNT(*) FILTER (WHERE created_at>=NOW()-INTERVAL '5 minutes')::bigint AS recent_count,MAX(created_at)::text AS last_written_at FROM ops_system_logs",
    )
    .fetch_one(pool)
    .await?;
    Ok(json!({
        "queue_depth": 0,
        "queue_capacity": 0,
        "dropped_count": 0,
        "write_failed_count": 0,
        "written_count": row.try_get::<i64, _>("written_count")?,
        "recent_count": row.try_get::<i64, _>("recent_count")?,
        "avg_write_delay_ms": 0,
        "last_error": null,
        "last_written_at": row.try_get::<Option<String>, _>("last_written_at")?,
    }))
}

struct DashboardFilter {
    range: TimeRange,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    platform: Option<String>,
    group_id: Option<i64>,
}

impl DashboardFilter {
    fn from_query(
        query: &BTreeMap<String, String>,
        default_range: &str,
    ) -> Result<Self, AdminError> {
        let range = TimeRange::from_query(query, default_range)?;
        let start = parse_timestamp(&range.start, "start_time")?;
        let end = parse_timestamp(&range.end, "end_time")?;
        Ok(Self {
            range,
            start,
            end,
            platform: nonempty(query.get("platform")).map(str::to_ascii_lowercase),
            group_id: query_optional_positive_i64(query, "group_id")?,
        })
    }

    fn bucket_seconds(&self) -> i64 {
        let seconds = self.end.signed_duration_since(self.start).num_seconds();
        if seconds <= 2 * 60 * 60 {
            60
        } else if seconds <= 24 * 60 * 60 {
            300
        } else {
            3_600
        }
    }

    fn bucket_label(&self) -> &'static str {
        match self.bucket_seconds() {
            300 => "5m",
            3_600 => "1h",
            _ => "1m",
        }
    }
}

async fn dashboard_overview(
    pool: &PgPool,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let filter = DashboardFilter::from_query(query, "1h")?;
    dashboard_overview_for(pool, &filter).await
}

#[allow(
    clippy::too_many_lines,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation
)]
async fn dashboard_overview_for(
    pool: &PgPool,
    filter: &DashboardFilter,
) -> Result<Value, AdminError> {
    let usage = sqlx::query(
        r"
SELECT COUNT(*)::bigint AS success_count,
       COALESCE(SUM(ul.input_tokens + ul.output_tokens + ul.cache_creation_tokens + ul.cache_read_tokens),0)::bigint AS token_consumed,
       ROUND(percentile_cont(0.50) WITHIN GROUP (ORDER BY ul.duration_ms) FILTER (WHERE ul.duration_ms IS NOT NULL))::bigint AS duration_p50,
       ROUND(percentile_cont(0.90) WITHIN GROUP (ORDER BY ul.duration_ms) FILTER (WHERE ul.duration_ms IS NOT NULL))::bigint AS duration_p90,
       ROUND(percentile_cont(0.95) WITHIN GROUP (ORDER BY ul.duration_ms) FILTER (WHERE ul.duration_ms IS NOT NULL))::bigint AS duration_p95,
       ROUND(percentile_cont(0.99) WITHIN GROUP (ORDER BY ul.duration_ms) FILTER (WHERE ul.duration_ms IS NOT NULL))::bigint AS duration_p99,
       ROUND(AVG(ul.duration_ms))::bigint AS duration_avg, MAX(ul.duration_ms)::bigint AS duration_max,
       ROUND(percentile_cont(0.50) WITHIN GROUP (ORDER BY ul.first_token_ms) FILTER (WHERE ul.first_token_ms IS NOT NULL))::bigint AS ttft_p50,
       ROUND(percentile_cont(0.90) WITHIN GROUP (ORDER BY ul.first_token_ms) FILTER (WHERE ul.first_token_ms IS NOT NULL))::bigint AS ttft_p90,
       ROUND(percentile_cont(0.95) WITHIN GROUP (ORDER BY ul.first_token_ms) FILTER (WHERE ul.first_token_ms IS NOT NULL))::bigint AS ttft_p95,
       ROUND(percentile_cont(0.99) WITHIN GROUP (ORDER BY ul.first_token_ms) FILTER (WHERE ul.first_token_ms IS NOT NULL))::bigint AS ttft_p99,
       ROUND(AVG(ul.first_token_ms))::bigint AS ttft_avg, MAX(ul.first_token_ms)::bigint AS ttft_max
FROM usage_logs ul
LEFT JOIN groups g ON g.id=ul.group_id
LEFT JOIN accounts a ON a.id=ul.account_id
WHERE ul.created_at >= $1::timestamptz AND ul.created_at < $2::timestamptz
  AND ($3::text IS NULL OR COALESCE(NULLIF(g.platform,''),a.platform)= $3)
  AND ($4::bigint IS NULL OR ul.group_id=$4)
",
    )
    .bind(&filter.range.start)
    .bind(&filter.range.end)
    .bind(filter.platform.as_deref())
    .bind(filter.group_id)
    .fetch_one(pool)
    .await?;
    let errors = sqlx::query(
        r"
SELECT COUNT(*) FILTER (WHERE COALESCE(status_code,0)>=400)::bigint AS error_total,
       COUNT(*) FILTER (WHERE COALESCE(status_code,0)>=400 AND is_business_limited)::bigint AS business_limited,
       COUNT(*) FILTER (WHERE COALESCE(status_code,0)>=400 AND NOT is_business_limited)::bigint AS error_sla,
       COUNT(*) FILTER (WHERE error_owner='provider' AND NOT is_business_limited AND COALESCE(upstream_status_code,status_code,0) NOT IN (429,529))::bigint AS upstream_excl,
       COUNT(*) FILTER (WHERE error_owner='provider' AND NOT is_business_limited AND COALESCE(upstream_status_code,status_code,0)=429)::bigint AS upstream_429,
       COUNT(*) FILTER (WHERE error_owner='provider' AND NOT is_business_limited AND COALESCE(upstream_status_code,status_code,0)=529)::bigint AS upstream_529
FROM ops_error_logs
WHERE created_at >= $1::timestamptz AND created_at < $2::timestamptz
  AND COALESCE(is_count_tokens,FALSE)=FALSE
  AND ($3::text IS NULL OR platform=$3)
  AND ($4::bigint IS NULL OR group_id=$4)
",
    )
    .bind(&filter.range.start)
    .bind(&filter.range.end)
    .bind(filter.platform.as_deref())
    .bind(filter.group_id)
    .fetch_one(pool)
    .await?;
    let success = usage.try_get::<i64, _>("success_count")?;
    let token_consumed = usage.try_get::<i64, _>("token_consumed")?;
    let error_total = errors.try_get::<i64, _>("error_total")?;
    let business_limited = errors.try_get::<i64, _>("business_limited")?;
    let error_sla = errors.try_get::<i64, _>("error_sla")?;
    let upstream_excl = errors.try_get::<i64, _>("upstream_excl")?;
    let request_total = success.saturating_add(error_total);
    let request_sla = success.saturating_add(error_sla);
    let window_seconds = filter
        .end
        .signed_duration_since(filter.start)
        .num_milliseconds()
        .max(1) as f64
        / 1_000.0;
    let rates = dashboard_rates(pool, filter).await?;
    let error_rate = ratio(error_sla, request_sla);
    let upstream_error_rate = ratio(upstream_excl, request_sla);
    let system_metrics = sqlx::query_scalar::<_, Value>(
        "SELECT to_jsonb(metric) FROM ops_system_metrics metric ORDER BY collected_at DESC,id DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;
    let job_heartbeats = sqlx::query_scalar::<_, Value>(
        "SELECT COALESCE(jsonb_agg(to_jsonb(job) ORDER BY job.job_name),'[]'::jsonb) FROM ops_job_heartbeats job",
    )
    .fetch_one(pool)
    .await?;
    let health_score = if request_total == 0 {
        100
    } else {
        (100.0 - error_rate.max(upstream_error_rate) * 1_000.0)
            .round()
            .clamp(0.0, 100.0) as i64
    };
    Ok(json!({
        "start_time": filter.range.start,
        "end_time": filter.range.end,
        "platform": filter.platform.clone().unwrap_or_default(),
        "group_id": filter.group_id,
        "health_score": health_score,
        "system_metrics": system_metrics,
        "job_heartbeats": job_heartbeats,
        "success_count": success,
        "error_count_total": error_total,
        "business_limited_count": business_limited,
        "error_count_sla": error_sla,
        "request_count_total": request_total,
        "request_count_sla": request_sla,
        "token_consumed": token_consumed,
        "sla": round4(ratio(success, request_sla)),
        "error_rate": round4(error_rate),
        "upstream_error_rate": round4(upstream_error_rate),
        "upstream_error_count_excl_429_529": upstream_excl,
        "upstream_429_count": errors.try_get::<i64,_>("upstream_429")?,
        "upstream_529_count": errors.try_get::<i64,_>("upstream_529")?,
        "qps": {
            "current": rates.0,
            "peak": rates.1,
            "avg": round1(request_total as f64 / window_seconds),
        },
        "tps": {
            "current": rates.2,
            "peak": rates.3,
            "avg": round1(token_consumed as f64 / window_seconds),
        },
        "duration": percentile_json(&usage, "duration")?,
        "ttft": percentile_json(&usage, "ttft")?,
    }))
}

async fn dashboard_rates(
    pool: &PgPool,
    filter: &DashboardFilter,
) -> Result<(f64, f64, f64, f64), AdminError> {
    let row = sqlx::query(
        r"
WITH usage_buckets AS (
 SELECT date_trunc('minute',ul.created_at) bucket,COUNT(*)::bigint requests,
        COALESCE(SUM(ul.input_tokens+ul.output_tokens+ul.cache_creation_tokens+ul.cache_read_tokens),0)::bigint tokens
 FROM usage_logs ul LEFT JOIN groups g ON g.id=ul.group_id LEFT JOIN accounts a ON a.id=ul.account_id
 WHERE ul.created_at >= $1::timestamptz AND ul.created_at < $2::timestamptz
   AND ($3::text IS NULL OR COALESCE(NULLIF(g.platform,''),a.platform)=$3)
   AND ($4::bigint IS NULL OR ul.group_id=$4) GROUP BY 1
), error_buckets AS (
 SELECT date_trunc('minute',created_at) bucket,COUNT(*)::bigint requests
 FROM ops_error_logs WHERE created_at >= $1::timestamptz AND created_at < $2::timestamptz
   AND COALESCE(is_count_tokens,FALSE)=FALSE AND COALESCE(status_code,0)>=400
   AND ($3::text IS NULL OR platform=$3) AND ($4::bigint IS NULL OR group_id=$4) GROUP BY 1
), combined AS (
 SELECT bucket,SUM(requests)::bigint requests,SUM(tokens)::bigint tokens FROM (
   SELECT bucket,requests,tokens FROM usage_buckets
   UNION ALL SELECT bucket,requests,0 FROM error_buckets
 ) source GROUP BY bucket
)
SELECT COALESCE(SUM(requests) FILTER (WHERE bucket >= date_trunc('minute',$2::timestamptz-INTERVAL '1 minute')),0)::double precision/60.0 current_qps,
       COALESCE(MAX(requests),0)::double precision/60.0 peak_qps,
       COALESCE(SUM(tokens) FILTER (WHERE bucket >= date_trunc('minute',$2::timestamptz-INTERVAL '1 minute')),0)::double precision/60.0 current_tps,
       COALESCE(MAX(tokens),0)::double precision/60.0 peak_tps FROM combined
",
    )
    .bind(&filter.range.start)
    .bind(&filter.range.end)
    .bind(filter.platform.as_deref())
    .bind(filter.group_id)
    .fetch_one(pool)
    .await?;
    Ok((
        round1(row.try_get("current_qps")?),
        round1(row.try_get("peak_qps")?),
        round1(row.try_get("current_tps")?),
        round1(row.try_get("peak_tps")?),
    ))
}

fn percentile_json(row: &sqlx::postgres::PgRow, prefix: &str) -> Result<Value, AdminError> {
    Ok(json!({
        "p50_ms": row.try_get::<Option<i64>,_>(format!("{prefix}_p50").as_str())?,
        "p90_ms": row.try_get::<Option<i64>,_>(format!("{prefix}_p90").as_str())?,
        "p95_ms": row.try_get::<Option<i64>,_>(format!("{prefix}_p95").as_str())?,
        "p99_ms": row.try_get::<Option<i64>,_>(format!("{prefix}_p99").as_str())?,
        "avg_ms": row.try_get::<Option<i64>,_>(format!("{prefix}_avg").as_str())?,
        "max_ms": row.try_get::<Option<i64>,_>(format!("{prefix}_max").as_str())?,
    }))
}

#[allow(clippy::cast_precision_loss)]
fn ratio(numerator: i64, denominator: i64) -> f64 {
    if denominator <= 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn round1(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}

fn round4(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}

async fn dashboard_snapshot(
    pool: &PgPool,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let filter = DashboardFilter::from_query(query, "1h")?;
    let overview = dashboard_overview_for(pool, &filter).await?;
    let throughput = dashboard_throughput_for(pool, &filter).await?;
    let error_trend = dashboard_error_trend_for(pool, &filter).await?;
    Ok(json!({
        "generated_at": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "overview": overview,
        "throughput_trend": throughput,
        "error_trend": error_trend,
    }))
}

async fn dashboard_throughput(
    pool: &PgPool,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let filter = DashboardFilter::from_query(query, "1h")?;
    dashboard_throughput_for(pool, &filter).await
}

async fn dashboard_throughput_for(
    pool: &PgPool,
    filter: &DashboardFilter,
) -> Result<Value, AdminError> {
    let bucket_seconds = filter.bucket_seconds();
    let points = sqlx::query_scalar::<_, Value>(
        r"
WITH series AS (
 SELECT generate_series(
   to_timestamp(floor(extract(epoch FROM $1::timestamptz)/$5::bigint)*$5::bigint),
   to_timestamp(floor(extract(epoch FROM ($2::timestamptz-INTERVAL '1 microsecond'))/$5::bigint)*$5::bigint),
   make_interval(secs=>$5::int)
 ) AS bucket
), usage_buckets AS (
 SELECT to_timestamp(floor(extract(epoch FROM ul.created_at)/$5::bigint)*$5::bigint) bucket,
        COUNT(*)::bigint requests,
        COALESCE(SUM(ul.input_tokens+ul.output_tokens+ul.cache_creation_tokens+ul.cache_read_tokens),0)::bigint tokens
 FROM usage_logs ul LEFT JOIN groups g ON g.id=ul.group_id LEFT JOIN accounts a ON a.id=ul.account_id
 WHERE ul.created_at >= $1::timestamptz AND ul.created_at < $2::timestamptz
   AND ($3::text IS NULL OR COALESCE(NULLIF(g.platform,''),a.platform)=$3)
   AND ($4::bigint IS NULL OR ul.group_id=$4) GROUP BY 1
), error_buckets AS (
 SELECT to_timestamp(floor(extract(epoch FROM e.created_at)/$5::bigint)*$5::bigint) bucket,
        COUNT(*)::bigint requests,
        COALESCE(SUM((SELECT COUNT(*) FROM jsonb_array_elements(COALESCE(e.upstream_errors,'[]'::jsonb)) ev
          WHERE split_part(ev->>'kind',':',1) IN ('failover','retry_exhausted_failover','failover_on_400'))),0)::bigint switches
 FROM ops_error_logs e
 WHERE e.created_at >= $1::timestamptz AND e.created_at < $2::timestamptz
   AND COALESCE(e.is_count_tokens,FALSE)=FALSE AND COALESCE(e.status_code,0)>=400
   AND ($3::text IS NULL OR e.platform=$3) AND ($4::bigint IS NULL OR e.group_id=$4)
 GROUP BY 1
)
SELECT jsonb_build_object(
 'bucket_start',s.bucket,
 'request_count',COALESCE(u.requests,0)+COALESCE(e.requests,0),
 'token_consumed',COALESCE(u.tokens,0),
 'switch_count',COALESCE(e.switches,0),
 'qps',ROUND(((COALESCE(u.requests,0)+COALESCE(e.requests,0))::numeric/$5::numeric),1)::double precision,
 'tps',ROUND((COALESCE(u.tokens,0)::numeric/$5::numeric),1)::double precision
)
FROM series s LEFT JOIN usage_buckets u USING(bucket) LEFT JOIN error_buckets e USING(bucket)
ORDER BY s.bucket
",
    )
    .bind(&filter.range.start)
    .bind(&filter.range.end)
    .bind(filter.platform.as_deref())
    .bind(filter.group_id)
    .bind(bucket_seconds)
    .fetch_all(pool)
    .await?;
    let mut result = json!({ "bucket": filter.bucket_label(), "points": points });
    if filter.platform.is_none() && filter.group_id.is_none() {
        result["by_platform"] = Value::Array(throughput_by_platform(pool, filter).await?);
    } else if filter.platform.is_some() && filter.group_id.is_none() {
        result["top_groups"] = Value::Array(throughput_top_groups(pool, filter).await?);
    }
    Ok(result)
}

async fn throughput_by_platform(
    pool: &PgPool,
    filter: &DashboardFilter,
) -> Result<Vec<Value>, AdminError> {
    sqlx::query_scalar::<_, Value>(
        r"
WITH usage AS (
 SELECT COALESCE(NULLIF(g.platform,''),a.platform,'') platform,COUNT(*)::bigint success,
        COALESCE(SUM(ul.input_tokens+ul.output_tokens+ul.cache_creation_tokens+ul.cache_read_tokens),0)::bigint tokens
 FROM usage_logs ul LEFT JOIN groups g ON g.id=ul.group_id LEFT JOIN accounts a ON a.id=ul.account_id
 WHERE ul.created_at >= $1::timestamptz AND ul.created_at < $2::timestamptz GROUP BY 1
), errors AS (
 SELECT COALESCE(platform,'') platform,COUNT(*)::bigint errors FROM ops_error_logs
 WHERE created_at >= $1::timestamptz AND created_at < $2::timestamptz
   AND COALESCE(is_count_tokens,FALSE)=FALSE AND COALESCE(status_code,0)>=400 GROUP BY 1
), combined AS (
 SELECT COALESCE(u.platform,e.platform) platform,COALESCE(u.success,0)+COALESCE(e.errors,0) requests,
        COALESCE(u.tokens,0) tokens FROM usage u FULL JOIN errors e USING(platform)
)
SELECT jsonb_build_object('platform',platform,'request_count',requests,'token_consumed',tokens)
FROM combined WHERE platform<>'' ORDER BY requests DESC,platform
",
    )
    .bind(&filter.range.start)
    .bind(&filter.range.end)
    .fetch_all(pool)
    .await
    .map_err(AdminError::from)
}

async fn throughput_top_groups(
    pool: &PgPool,
    filter: &DashboardFilter,
) -> Result<Vec<Value>, AdminError> {
    sqlx::query_scalar::<_, Value>(
        r"
WITH usage AS (
 SELECT ul.group_id,g.name,COUNT(*)::bigint success,
        COALESCE(SUM(ul.input_tokens+ul.output_tokens+ul.cache_creation_tokens+ul.cache_read_tokens),0)::bigint tokens
 FROM usage_logs ul JOIN groups g ON g.id=ul.group_id
 WHERE ul.created_at >= $1::timestamptz AND ul.created_at < $2::timestamptz AND g.platform=$3 GROUP BY 1,2
), errors AS (
 SELECT group_id,COUNT(*)::bigint errors FROM ops_error_logs
 WHERE created_at >= $1::timestamptz AND created_at < $2::timestamptz AND platform=$3
   AND group_id IS NOT NULL AND COALESCE(is_count_tokens,FALSE)=FALSE AND COALESCE(status_code,0)>=400 GROUP BY 1
), combined AS (
 SELECT COALESCE(u.group_id,e.group_id) group_id,COALESCE(u.name,g.name,'') name,
        COALESCE(u.success,0)+COALESCE(e.errors,0) requests,COALESCE(u.tokens,0) tokens
 FROM usage u FULL JOIN errors e USING(group_id) LEFT JOIN groups g ON g.id=COALESCE(u.group_id,e.group_id)
)
SELECT jsonb_build_object('group_id',group_id,'group_name',name,'request_count',requests,'token_consumed',tokens)
FROM combined ORDER BY requests DESC,group_id LIMIT 10
",
    )
    .bind(&filter.range.start)
    .bind(&filter.range.end)
    .bind(filter.platform.as_deref())
    .fetch_all(pool)
    .await
    .map_err(AdminError::from)
}

async fn dashboard_error_trend(
    pool: &PgPool,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let filter = DashboardFilter::from_query(query, "1h")?;
    dashboard_error_trend_for(pool, &filter).await
}

async fn dashboard_error_trend_for(
    pool: &PgPool,
    filter: &DashboardFilter,
) -> Result<Value, AdminError> {
    let bucket_seconds = filter.bucket_seconds();
    let points = sqlx::query_scalar::<_, Value>(
        r"
WITH series AS (
 SELECT generate_series(
  to_timestamp(floor(extract(epoch FROM $1::timestamptz)/$5::bigint)*$5::bigint),
  to_timestamp(floor(extract(epoch FROM ($2::timestamptz-INTERVAL '1 microsecond'))/$5::bigint)*$5::bigint),
  make_interval(secs=>$5::int)) bucket
), stats AS (
 SELECT to_timestamp(floor(extract(epoch FROM created_at)/$5::bigint)*$5::bigint) bucket,
  COUNT(*) FILTER (WHERE COALESCE(status_code,0)>=400)::bigint total,
  COUNT(*) FILTER (WHERE COALESCE(status_code,0)>=400 AND is_business_limited)::bigint business,
  COUNT(*) FILTER (WHERE COALESCE(status_code,0)>=400 AND NOT is_business_limited)::bigint sla,
  COUNT(*) FILTER (WHERE error_owner='provider' AND NOT is_business_limited AND COALESCE(upstream_status_code,status_code,0) NOT IN(429,529))::bigint upstream_excl,
  COUNT(*) FILTER (WHERE error_owner='provider' AND NOT is_business_limited AND COALESCE(upstream_status_code,status_code,0)=429)::bigint upstream_429,
  COUNT(*) FILTER (WHERE error_owner='provider' AND NOT is_business_limited AND COALESCE(upstream_status_code,status_code,0)=529)::bigint upstream_529
 FROM ops_error_logs WHERE created_at >= $1::timestamptz AND created_at < $2::timestamptz
  AND COALESCE(is_count_tokens,FALSE)=FALSE AND ($3::text IS NULL OR platform=$3)
  AND ($4::bigint IS NULL OR group_id=$4) GROUP BY 1
)
SELECT jsonb_build_object('bucket_start',series.bucket,'error_count_total',COALESCE(total,0),
 'business_limited_count',COALESCE(business,0),'error_count_sla',COALESCE(sla,0),
 'upstream_error_count_excl_429_529',COALESCE(upstream_excl,0),
 'upstream_429_count',COALESCE(upstream_429,0),'upstream_529_count',COALESCE(upstream_529,0))
FROM series LEFT JOIN stats USING(bucket) ORDER BY series.bucket
",
    )
    .bind(&filter.range.start)
    .bind(&filter.range.end)
    .bind(filter.platform.as_deref())
    .bind(filter.group_id)
    .bind(bucket_seconds)
    .fetch_all(pool)
    .await?;
    Ok(json!({ "bucket": filter.bucket_label(), "points": points }))
}

async fn dashboard_latency_histogram(
    pool: &PgPool,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let filter = DashboardFilter::from_query(query, "1h")?;
    let row = sqlx::query(
        r"
SELECT COUNT(*) FILTER (WHERE ul.duration_ms<100)::bigint b0,
 COUNT(*) FILTER (WHERE ul.duration_ms>=100 AND ul.duration_ms<200)::bigint b1,
 COUNT(*) FILTER (WHERE ul.duration_ms>=200 AND ul.duration_ms<500)::bigint b2,
 COUNT(*) FILTER (WHERE ul.duration_ms>=500 AND ul.duration_ms<1000)::bigint b3,
 COUNT(*) FILTER (WHERE ul.duration_ms>=1000 AND ul.duration_ms<2000)::bigint b4,
 COUNT(*) FILTER (WHERE ul.duration_ms>=2000)::bigint b5,
 COUNT(ul.duration_ms)::bigint total
FROM usage_logs ul LEFT JOIN groups g ON g.id=ul.group_id LEFT JOIN accounts a ON a.id=ul.account_id
WHERE ul.created_at >= $1::timestamptz AND ul.created_at < $2::timestamptz
 AND ($3::text IS NULL OR COALESCE(NULLIF(g.platform,''),a.platform)=$3)
 AND ($4::bigint IS NULL OR ul.group_id=$4)
",
    )
    .bind(&filter.range.start)
    .bind(&filter.range.end)
    .bind(filter.platform.as_deref())
    .bind(filter.group_id)
    .fetch_one(pool)
    .await?;
    let labels = [
        "0-100ms",
        "100-200ms",
        "200-500ms",
        "500-1000ms",
        "1000-2000ms",
        "2000ms+",
    ];
    let buckets = labels
        .iter()
        .enumerate()
        .map(|(index, label)| {
            row.try_get::<i64, _>(format!("b{index}").as_str())
                .map(|count| json!({ "range": label, "count": count }))
                .map_err(AdminError::from)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(json!({
        "start_time": filter.range.start, "end_time": filter.range.end,
        "platform": filter.platform.unwrap_or_default(), "group_id": filter.group_id,
        "total_requests": row.try_get::<i64,_>("total")?, "buckets": buckets,
    }))
}

async fn dashboard_error_distribution(
    pool: &PgPool,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let filter = DashboardFilter::from_query(query, "1h")?;
    let rows = sqlx::query(
        r"
SELECT COALESCE(upstream_status_code,status_code,0)::int status_code,COUNT(*)::bigint total,
 COUNT(*) FILTER (WHERE NOT is_business_limited)::bigint sla,
 COUNT(*) FILTER (WHERE is_business_limited)::bigint business_limited
FROM ops_error_logs WHERE created_at >= $1::timestamptz AND created_at < $2::timestamptz
 AND COALESCE(is_count_tokens,FALSE)=FALSE AND COALESCE(status_code,0)>=400
 AND ($3::text IS NULL OR platform=$3) AND ($4::bigint IS NULL OR group_id=$4)
GROUP BY 1 ORDER BY total DESC LIMIT 20
",
    )
    .bind(&filter.range.start)
    .bind(&filter.range.end)
    .bind(filter.platform.as_deref())
    .bind(filter.group_id)
    .fetch_all(pool)
    .await?;
    let mut total = 0_i64;
    let items = rows
        .iter()
        .map(|row| {
            let count = row.try_get::<i64, _>("total")?;
            total = total.saturating_add(count);
            Ok(json!({
                "status_code": row.try_get::<i32,_>("status_code")?, "total": count,
                "sla": row.try_get::<i64,_>("sla")?,
                "business_limited": row.try_get::<i64,_>("business_limited")?,
            }))
        })
        .collect::<Result<Vec<_>, AdminError>>()?;
    Ok(json!({ "total": total, "items": items }))
}

async fn dashboard_openai_token_stats(
    pool: &PgPool,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let time_range = query.get("time_range").map_or("30d", String::as_str);
    if !matches!(time_range, "30m" | "1h" | "1d" | "15d" | "30d") {
        return Err(AdminError::BadRequest("invalid time_range".to_owned()));
    }
    let filter = DashboardFilter::from_query(query, time_range)?;
    let top_n = query_optional_positive_i64(query, "top_n")?;
    if top_n.is_some_and(|value| value > 100) {
        return Err(AdminError::BadRequest("invalid top_n".to_owned()));
    }
    if top_n.is_some() && (query.contains_key("page") || query.contains_key("page_size")) {
        return Err(AdminError::BadRequest(
            "invalid query: top_n cannot be used with page/page_size".to_owned(),
        ));
    }
    let page = query_positive_i64(query, "page", 1)?;
    let page_size = query_positive_i64(query, "page_size", 20)?;
    if page_size > 100 {
        return Err(AdminError::BadRequest("invalid page_size".to_owned()));
    }
    let limit = top_n.unwrap_or(page_size);
    let offset = top_n.map_or((page - 1) * page_size, |_| 0);
    let rows = sqlx::query(
        r"
WITH stats AS (
 SELECT ul.model,COUNT(*)::bigint request_count,
  ROUND(AVG(CASE WHEN ul.duration_ms>0 AND ul.output_tokens>0 THEN ul.output_tokens*1000.0/ul.duration_ms END)::numeric,2)::double precision avg_tokens_per_sec,
  ROUND(AVG(ul.first_token_ms)::numeric,2)::double precision avg_first_token_ms,
  COALESCE(SUM(ul.output_tokens),0)::bigint total_output_tokens,
  COALESCE(ROUND(AVG(ul.duration_ms)::numeric),0)::bigint avg_duration_ms,
  COUNT(ul.first_token_ms)::bigint requests_with_first_token
 FROM usage_logs ul LEFT JOIN groups g ON g.id=ul.group_id LEFT JOIN accounts a ON a.id=ul.account_id
 WHERE ul.created_at >= $1::timestamptz AND ul.created_at < $2::timestamptz AND ul.model LIKE 'gpt%'
  AND ($3::text IS NULL OR COALESCE(NULLIF(g.platform,''),a.platform)=$3)
  AND ($4::bigint IS NULL OR ul.group_id=$4) GROUP BY ul.model
)
SELECT jsonb_build_object('model',model,'request_count',request_count,
 'avg_tokens_per_sec',avg_tokens_per_sec,'avg_first_token_ms',avg_first_token_ms,
 'total_output_tokens',total_output_tokens,'avg_duration_ms',avg_duration_ms,
 'requests_with_first_token',requests_with_first_token) data,
 COUNT(*) OVER()::bigint total FROM stats ORDER BY request_count DESC,model LIMIT $5 OFFSET $6
",
    )
    .bind(&filter.range.start)
    .bind(&filter.range.end)
    .bind(filter.platform.as_deref())
    .bind(filter.group_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    let total = rows
        .first()
        .map_or(Ok(0), |row| row.try_get::<i64, _>("total"))?;
    let items = rows
        .into_iter()
        .map(|row| row.try_get::<Value, _>("data").map_err(AdminError::from))
        .collect::<Result<Vec<_>, _>>()?;
    let mut result = json!({
        "time_range": time_range, "start_time": filter.range.start, "end_time": filter.range.end,
        "items": items, "total": total,
    });
    if let Some(platform) = filter.platform {
        result["platform"] = json!(platform);
    }
    if let Some(group_id) = filter.group_id {
        result["group_id"] = json!(group_id);
    }
    if let Some(top_n) = top_n {
        result["top_n"] = json!(top_n);
    } else {
        result["page"] = json!(page);
        result["page_size"] = json!(page_size);
    }
    Ok(result)
}

struct ErrorCorrelation {
    request_id: Option<String>,
    client_request_id: Option<String>,
    include_detail: bool,
}

async fn list_request_error_upstream(
    pool: &PgPool,
    parent_id: i64,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let parent = sqlx::query("SELECT request_id,client_request_id FROM ops_error_logs WHERE id=$1")
        .bind(parent_id)
        .fetch_optional(pool)
        .await?
        .ok_or(AdminError::NotFound("ops error"))?;
    let request_id = parent
        .try_get::<Option<String>, _>("request_id")?
        .filter(|value| !value.trim().is_empty());
    let client_request_id = parent
        .try_get::<Option<String>, _>("client_request_id")?
        .filter(|value| !value.trim().is_empty());
    if request_id.is_none() && client_request_id.is_none() {
        return Ok(json!({
            "items": [], "total": 0, "page": 1, "page_size": 10, "pages": 1,
        }));
    }
    let include_detail = query_bool(query, "include_detail")?.unwrap_or(false);
    list_ops_errors(
        pool,
        "h.Admin.Ops.ListRequestErrorUpstreamErrors",
        query,
        Some(ErrorCorrelation {
            request_id,
            client_request_id,
            include_detail,
        }),
    )
    .await
}

#[allow(clippy::too_many_lines)]
async fn list_ops_errors(
    pool: &PgPool,
    handler: &str,
    query: &BTreeMap<String, String>,
    correlation: Option<ErrorCorrelation>,
) -> Result<Value, AdminError> {
    let page = query_positive_i64(query, "page", 1)?;
    let page_size = query_positive_i64(query, "page_size", 20)?.min(500);
    let default_range = if correlation.is_some() { "30d" } else { "1h" };
    let range = TimeRange::from_query(query, default_range)?;
    let upstream = matches!(
        handler,
        "h.Admin.Ops.ListUpstreamErrors" | "h.Admin.Ops.ListRequestErrorUpstreamErrors"
    );
    let phase = if upstream {
        Some("upstream")
    } else {
        nonempty(query.get("phase"))
    };
    let owner = if upstream {
        Some("provider")
    } else {
        nonempty(query.get("error_owner"))
    };
    let resolved = query_bool(query, "resolved")?;
    let status_codes = parse_status_codes(query.get("status_codes"))?;
    let status_codes = (!status_codes.is_empty()).then_some(status_codes);
    let status_other = query_bool(query, "status_codes_other")?.unwrap_or(false);
    let correlation = correlation.unwrap_or(ErrorCorrelation {
        request_id: None,
        client_request_id: None,
        include_detail: false,
    });
    let request_id = correlation.request_id.as_deref();
    let client_request_id = if request_id.is_some() {
        None
    } else {
        correlation.client_request_id.as_deref()
    };
    let sort_column = match nonempty(query.get("sort_by"))
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("model") => "COALESCE(NULLIF(TRIM(e.requested_model),''),e.model)",
        Some("status_code") => "COALESCE(e.upstream_status_code,e.status_code,0)",
        _ => "e.created_at",
    };
    let sort_order = if nonempty(query.get("sort_order"))
        .is_some_and(|value| value.eq_ignore_ascii_case("asc"))
    {
        "ASC"
    } else {
        "DESC"
    };
    let json_expression = ops_error_json_expression(correlation.include_detail);
    let sql = format!(
        r"
SELECT {json_expression} AS data,COUNT(*) OVER()::bigint total
FROM ops_error_logs e
LEFT JOIN accounts a ON a.id=e.account_id
LEFT JOIN groups g ON g.id=e.group_id
LEFT JOIN users u ON u.id=e.user_id
LEFT JOIN users resolver ON resolver.id=e.resolved_by_user_id
LEFT JOIN users deleted_owner ON deleted_owner.id=e.deleted_key_owner_user_id
LEFT JOIN api_keys ak ON ak.id=e.api_key_id
WHERE e.created_at >= $1::timestamptz AND e.created_at < $2::timestamptz
 AND ($3::text IS NULL OR e.platform=$3)
 AND ($4::bigint IS NULL OR e.group_id=$4)
 AND ($5::bigint IS NULL OR e.account_id=$5)
 AND ($6::text IS NULL OR e.error_phase=$6)
 AND ($7::text IS NULL OR LOWER(COALESCE(e.error_owner,''))=LOWER($7))
 AND ($8::text IS NULL OR LOWER(COALESCE(e.error_source,''))=LOWER($8))
 AND ($9::boolean IS NULL OR COALESCE(e.resolved,FALSE)=$9)
 AND (CASE LOWER(COALESCE($10::text,'errors'))
       WHEN 'all' THEN TRUE
       WHEN 'excluded' THEN COALESCE(e.is_business_limited,FALSE)
       ELSE NOT COALESCE(e.is_business_limited,FALSE) END)
 AND ($11::text IS NULL OR e.request_id ILIKE '%'||$11||'%' OR e.client_request_id ILIKE '%'||$11||'%' OR e.error_message ILIKE '%'||$11||'%')
 AND ($12::text IS NULL OR u.email ILIKE '%'||$12||'%')
 AND ($13::text IS NULL OR COALESCE(e.requested_model,e.model,'')=$13)
 AND ($14::int[] IS NULL OR COALESCE(e.upstream_status_code,e.status_code,0)=ANY($14))
 AND (NOT $15::boolean OR NOT (COALESCE(e.upstream_status_code,e.status_code,0)=ANY(ARRAY[400,401,403,404,409,422,429,500,502,503,504,529])))
 AND ($16::text IS NULL OR COALESCE(e.request_id,'')=$16)
 AND ($17::text IS NULL OR COALESCE(e.client_request_id,'')=$17)
 AND ($18::boolean OR COALESCE(e.upstream_status_code,e.status_code,0)>=400 OR e.error_type='cyber_policy')
 AND ($19::bigint IS NULL OR e.user_id=$19)
 AND ($20::bigint IS NULL OR e.api_key_id=$20)
 AND (CASE COALESCE($21::text,'')
       WHEN '' THEN TRUE WHEN 'auth' THEN e.error_phase='auth'
       WHEN 'service_unavailable' THEN e.error_phase='routing'
       WHEN 'upstream' THEN e.error_phase=ANY(ARRAY['upstream','network'])
       WHEN 'internal' THEN e.error_phase='internal'
       WHEN 'rate_limit' THEN e.error_type='rate_limit_error'
       WHEN 'quota' THEN e.error_type=ANY(ARRAY['billing_error','subscription_error'])
       WHEN 'invalid_request' THEN e.error_type='invalid_request_error'
       WHEN 'cyber' THEN e.error_phase='request' AND e.error_type='cyber_policy'
       ELSE TRUE END)
ORDER BY {sort_column} {sort_order},e.id {sort_order}
LIMIT $22 OFFSET $23
"
    );
    let rows = sqlx::query(&sql)
        .bind(&range.start)
        .bind(&range.end)
        .bind(nonempty(query.get("platform")))
        .bind(query_optional_positive_i64(query, "group_id")?)
        .bind(query_optional_positive_i64(query, "account_id")?)
        .bind(phase)
        .bind(owner)
        .bind(nonempty(query.get("error_source")))
        .bind(resolved)
        .bind(nonempty(query.get("view")))
        .bind(nonempty(query.get("q")))
        .bind(nonempty(query.get("user_query")))
        .bind(nonempty(query.get("model")))
        .bind(status_codes.as_deref())
        .bind(status_other)
        .bind(request_id)
        .bind(client_request_id)
        .bind(upstream)
        .bind(query_optional_positive_i64(query, "user_id")?)
        .bind(query_optional_positive_i64(query, "api_key_id")?)
        .bind(nonempty(query.get("category")))
        .bind(page_size)
        .bind((page - 1) * page_size)
        .fetch_all(pool)
        .await?;
    let total = rows
        .first()
        .map_or(Ok(0), |row| row.try_get::<i64, _>("total"))?;
    let items = rows
        .into_iter()
        .map(|row| row.try_get::<Value, _>("data").map_err(AdminError::from))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(json!({
        "items": items, "total": total, "page": page, "page_size": page_size,
        "pages": ((total + page_size - 1) / page_size).max(1),
    }))
}

fn ops_error_json_expression(detail: bool) -> &'static str {
    if detail {
        r"(to_jsonb(e)-ARRAY['error_phase','error_type','error_message','upstream_errors']) || jsonb_build_object(
          'phase',e.error_phase,'type',e.error_type,'error_owner',COALESCE(e.error_owner,''),
          'error_source',COALESCE(e.error_source,''),'status_code',COALESCE(e.upstream_status_code,e.status_code,0),
          'platform',COALESCE(e.platform,''),'model',COALESCE(e.model,''),'message',COALESCE(e.error_message,''),
          'resolved',COALESCE(e.resolved,FALSE),'resolved_by_user_name',COALESCE(resolver.email,''),
          'user_email',COALESCE(u.email,''),'account_name',COALESCE(a.name,''),'group_name',COALESCE(g.name,''),
          'client_ip',CASE WHEN e.client_ip IS NULL THEN NULL ELSE host(e.client_ip) END,
          'api_key_name',COALESCE(NULLIF(ak.name,''),e.deleted_key_name,''),
          'api_key_deleted',(ak.deleted_at IS NOT NULL OR (ak.id IS NULL AND COALESCE(e.deleted_key_name,'')<>'')),
          'deleted_key_owner_email',COALESCE(deleted_owner.email,''),
          'upstream_errors',CASE WHEN e.upstream_errors IS NULL OR e.upstream_errors='null'::jsonb THEN '' ELSE e.upstream_errors::text END
        )"
    } else {
        r"(to_jsonb(e)-ARRAY['error_phase','error_type','error_message','error_body','upstream_error_message','upstream_error_detail','upstream_errors','auth_latency_ms','routing_latency_ms','upstream_latency_ms','response_latency_ms','time_to_first_token_ms','attempted_key_prefix','api_key_prefix','deleted_key_name']) || jsonb_build_object(
          'phase',e.error_phase,'type',e.error_type,'error_owner',COALESCE(e.error_owner,''),
          'error_source',COALESCE(e.error_source,''),'status_code',COALESCE(e.upstream_status_code,e.status_code,0),
          'platform',COALESCE(e.platform,''),'model',COALESCE(e.model,''),'message',COALESCE(e.error_message,''),
          'resolved',COALESCE(e.resolved,FALSE),'resolved_by_user_name',COALESCE(resolver.email,''),
          'user_email',COALESCE(u.email,''),'account_name',COALESCE(a.name,''),'group_name',COALESCE(g.name,''),
          'client_ip',CASE WHEN e.client_ip IS NULL THEN NULL ELSE host(e.client_ip) END,
          'api_key_name',COALESCE(NULLIF(ak.name,''),e.deleted_key_name,''),
          'api_key_deleted',(ak.deleted_at IS NOT NULL OR (ak.id IS NULL AND COALESCE(e.deleted_key_name,'')<>'')),
          'deleted_key_owner_email',COALESCE(deleted_owner.email,'')
        )"
    }
}

async fn get_ops_error(pool: &PgPool, id: i64) -> Result<Value, AdminError> {
    let sql = format!(
        r"
SELECT {} AS data FROM ops_error_logs e
LEFT JOIN accounts a ON a.id=e.account_id LEFT JOIN groups g ON g.id=e.group_id
LEFT JOIN users u ON u.id=e.user_id LEFT JOIN users resolver ON resolver.id=e.resolved_by_user_id
LEFT JOIN users deleted_owner ON deleted_owner.id=e.deleted_key_owner_user_id
LEFT JOIN api_keys ak ON ak.id=e.api_key_id WHERE e.id=$1
",
        ops_error_json_expression(true)
    );
    sqlx::query_scalar::<_, Value>(&sql)
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(AdminError::NotFound("ops error"))
}

fn parse_status_codes(raw: Option<&String>) -> Result<Vec<i32>, AdminError> {
    raw.map_or(Ok(Vec::new()), |raw| {
        raw.split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| {
                value
                    .parse::<i32>()
                    .ok()
                    .filter(|value| *value >= 0)
                    .ok_or_else(|| AdminError::BadRequest("Invalid status_codes".to_owned()))
            })
            .collect()
    })
}

async fn list_moderation_logs(
    pool: &PgPool,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let page = query_positive_i64(query, "page", 1)?;
    let page_size = query_positive_i64(query, "page_size", 20)?.min(100);
    let group_id = query_optional_positive_i64(query, "group_id")?;
    let from = moderation_date(nonempty(query.get("from")), false)?;
    let to = moderation_date(nonempty(query.get("to")), true)?;
    let rows = sqlx::query(
        r"
SELECT to_jsonb(log)||jsonb_build_object('user_status',COALESCE(users.status,'')) data,
       COUNT(*) OVER()::bigint total
FROM content_moderation_logs log LEFT JOIN users ON users.id=log.user_id
WHERE (CASE LOWER(COALESCE($1::text,''))
        WHEN 'hit' THEN log.flagged WHEN 'flagged' THEN log.flagged
        WHEN 'blocked' THEN log.action=ANY(ARRAY['block','keyword_block','hash_block'])
        WHEN 'block' THEN log.action=ANY(ARRAY['block','keyword_block','hash_block'])
        WHEN 'pass' THEN NOT log.flagged AND log.error=''
        WHEN 'allow' THEN NOT log.flagged AND log.error=''
        WHEN 'error' THEN log.error<>'' ELSE TRUE END)
 AND ($2::bigint IS NULL OR log.group_id=$2)
 AND ($3::text IS NULL OR log.endpoint=$3)
 AND ($4::text IS NULL OR log.request_id ILIKE '%'||$4||'%' OR log.user_email ILIKE '%'||$4||'%'
      OR log.api_key_name ILIKE '%'||$4||'%' OR log.model ILIKE '%'||$4||'%'
      OR log.input_excerpt ILIKE '%'||$4||'%')
 AND ($5::timestamptz IS NULL OR log.created_at >= $5::timestamptz)
 AND ($6::timestamptz IS NULL OR log.created_at <= $6::timestamptz)
ORDER BY log.created_at DESC,log.id DESC LIMIT $7 OFFSET $8
",
    )
    .bind(nonempty(query.get("result")))
    .bind(group_id)
    .bind(nonempty(query.get("endpoint")))
    .bind(nonempty(query.get("search")))
    .bind(from.as_deref())
    .bind(to.as_deref())
    .bind(page_size)
    .bind((page - 1) * page_size)
    .fetch_all(pool)
    .await?;
    let total = rows
        .first()
        .map_or(Ok(0), |row| row.try_get::<i64, _>("total"))?;
    let items = rows
        .into_iter()
        .map(|row| row.try_get::<Value, _>("data").map_err(AdminError::from))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(json!({
        "items": items,"total": total,"page": page,"page_size": page_size,
        "pages": ((total+page_size-1)/page_size).max(1),
    }))
}

fn moderation_date(value: Option<&str>, inclusive_end: bool) -> Result<Option<String>, AdminError> {
    let Some(value) = value else { return Ok(None) };
    if let Ok(timestamp) = DateTime::parse_from_rfc3339(value) {
        return Ok(Some(timestamp.with_timezone(&Utc).to_rfc3339()));
    }
    let date = chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .map_err(|_| AdminError::BadRequest("invalid moderation date".to_owned()))?;
    let mut timestamp = date
        .and_hms_opt(0, 0, 0)
        .ok_or_else(|| AdminError::BadRequest("invalid moderation date".to_owned()))?
        .and_utc();
    if inclusive_end {
        timestamp += chrono::Duration::days(1) - chrono::Duration::microseconds(1);
    }
    Ok(Some(timestamp.to_rfc3339()))
}

struct TimeRange {
    start: String,
    end: String,
}

impl TimeRange {
    fn from_query(
        query: &BTreeMap<String, String>,
        default_range: &str,
    ) -> Result<Self, AdminError> {
        let end = query
            .get("end_time")
            .map(|value| parse_timestamp(value, "end_time"))
            .transpose()?
            .unwrap_or_else(Utc::now);
        let duration = range_duration(
            query
                .get("time_range")
                .map_or(default_range, String::as_str),
        )
        .ok_or_else(|| AdminError::BadRequest("invalid time_range".to_owned()))?;
        let start = query
            .get("start_time")
            .map(|value| parse_timestamp(value, "start_time"))
            .transpose()?
            .unwrap_or_else(|| end - duration);
        if start >= end {
            return Err(AdminError::BadRequest(
                "start_time must be before end_time".to_owned(),
            ));
        }
        Ok(Self {
            start: start.to_rfc3339(),
            end: end.to_rfc3339(),
        })
    }
}

fn range_duration(value: &str) -> Option<chrono::Duration> {
    match value.trim() {
        "5m" => Some(chrono::Duration::minutes(5)),
        "30m" => Some(chrono::Duration::minutes(30)),
        "1h" => Some(chrono::Duration::hours(1)),
        "6h" => Some(chrono::Duration::hours(6)),
        "24h" | "1d" => Some(chrono::Duration::days(1)),
        "7d" => Some(chrono::Duration::days(7)),
        "15d" => Some(chrono::Duration::days(15)),
        "30d" => Some(chrono::Duration::days(30)),
        _ => None,
    }
}

fn validated_timestamp(value: Option<&Value>, name: &str) -> Result<Option<String>, AdminError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.trim().is_empty() => Ok(None),
        Some(Value::String(value)) => {
            parse_timestamp(value, name).map(|value| Some(value.to_rfc3339()))
        }
        Some(_) => Err(AdminError::BadRequest(format!("{name} must be RFC3339"))),
    }
}

fn validated_timestamp_text(
    value: Option<&String>,
    name: &str,
) -> Result<Option<String>, AdminError> {
    match value.map(String::as_str).map(str::trim) {
        None | Some("") => Ok(None),
        Some(value) => parse_timestamp(value, name).map(|value| Some(value.to_rfc3339())),
    }
}

fn parse_timestamp(value: &str, name: &str) -> Result<DateTime<Utc>, AdminError> {
    DateTime::parse_from_rfc3339(value.trim())
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| AdminError::BadRequest(format!("invalid {name}")))
}

fn object(value: &Value) -> Result<&Map<String, Value>, AdminError> {
    value
        .as_object()
        .ok_or_else(|| AdminError::BadRequest("request body must be a JSON object".to_owned()))
}

fn required_text<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, AdminError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AdminError::BadRequest(format!("{key} is required")))
}

fn optional_text<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, AdminError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok((!value.trim().is_empty()).then(|| value.trim())),
        Some(_) => Err(AdminError::BadRequest(format!("{key} must be a string"))),
    }
}

fn optional_i32(object: &Map<String, Value>, key: &str, default: i32) -> Result<i32, AdminError> {
    let value = match object.get(key) {
        None => i64::from(default),
        Some(value) => value
            .as_i64()
            .ok_or_else(|| AdminError::BadRequest(format!("{key} must be an integer")))?,
    };
    i32::try_from(value).map_err(|_| AdminError::BadRequest(format!("{key} is out of range")))
}

fn required_positive_i64(object: &Map<String, Value>, key: &str) -> Result<i64, AdminError> {
    optional_positive_i64(object, key)?
        .ok_or_else(|| AdminError::BadRequest(format!("valid {key} is required")))
}

fn optional_positive_i64(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<i64>, AdminError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_i64()
            .filter(|value| *value > 0)
            .map(Some)
            .ok_or_else(|| AdminError::BadRequest(format!("invalid {key}"))),
    }
}

fn query_positive_i64(
    query: &BTreeMap<String, String>,
    key: &str,
    default: i64,
) -> Result<i64, AdminError> {
    query.get(key).map_or(Ok(default), |value| {
        value
            .parse::<i64>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| AdminError::BadRequest(format!("invalid {key}")))
    })
}

fn query_optional_positive_i64(
    query: &BTreeMap<String, String>,
    key: &str,
) -> Result<Option<i64>, AdminError> {
    query
        .get(key)
        .map(|value| {
            value
                .parse::<i64>()
                .ok()
                .filter(|value| *value > 0)
                .ok_or_else(|| AdminError::BadRequest(format!("invalid {key}")))
        })
        .transpose()
}

fn query_bool(query: &BTreeMap<String, String>, key: &str) -> Result<Option<bool>, AdminError> {
    query
        .get(key)
        .filter(|value| !value.trim().is_empty())
        .map(|value| match value.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Ok(true),
            "false" | "0" | "no" => Ok(false),
            _ => Err(AdminError::BadRequest(format!("invalid {key}"))),
        })
        .transpose()
}

fn nonempty(value: Option<&String>) -> Option<&str> {
    value
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn validate_i64_range(
    object: &Map<String, Value>,
    key: &str,
    min: i64,
    max: i64,
) -> Result<(), AdminError> {
    object
        .get(key)
        .and_then(Value::as_i64)
        .filter(|value| (min..=max).contains(value))
        .map(|_| ())
        .ok_or_else(|| AdminError::BadRequest(format!("invalid {key}")))
}

fn validate_nonnegative(object: &Map<String, Value>, key: &str) -> Result<(), AdminError> {
    object
        .get(key)
        .and_then(Value::as_i64)
        .filter(|value| *value >= 0)
        .map(|_| ())
        .ok_or_else(|| AdminError::BadRequest(format!("invalid {key}")))
}

fn validate_range(
    object: &Map<String, Value>,
    key: &str,
    min: f64,
    max: f64,
) -> Result<(), AdminError> {
    object
        .get(key)
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite() && *value >= min && *value <= max)
        .map(|_| ())
        .ok_or_else(|| AdminError::BadRequest(format!("invalid {key}")))
}

fn validate_nullable_range(
    object: &Map<String, Value>,
    key: &str,
    min: f64,
    max: f64,
) -> Result<(), AdminError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(()),
        Some(_) => validate_range(object, key, min, max),
    }
}

async fn json_rows(pool: &PgPool, sql: &str) -> Result<Vec<Value>, AdminError> {
    extract_json_rows(sqlx::query(sql).fetch_all(pool).await?)
}

fn extract_json_rows(rows: Vec<sqlx::postgres::PgRow>) -> Result<Vec<Value>, AdminError> {
    rows.into_iter()
        .map(|row| row.try_get::<Value, _>("data").map_err(Into::into))
        .collect()
}

fn paginated_rows(
    rows: Vec<sqlx::postgres::PgRow>,
    page: i64,
    page_size: i64,
) -> Result<Value, AdminError> {
    let total = rows
        .first()
        .map_or(Ok(0_i64), |row| row.try_get::<i64, _>("total"))?;
    let items = extract_json_rows(rows)?;
    Ok(json!({ "items": items, "total": total, "page": page, "page_size": page_size }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route_contract;

    #[test]
    fn every_go_http_ops_route_has_dedicated_ownership() {
        let routes = route_contract::routes()
            .filter(|route| route.category == "admin/ops")
            .collect::<Vec<_>>();
        assert_eq!(routes.len(), 44);
        for route in routes {
            assert!(
                owns_handler(route.handler),
                "unowned ops route: {}",
                route.handler
            );
        }
    }

    #[test]
    fn websocket_route_remains_owned_by_typed_router() {
        let route = route_contract::routes()
            .find(|route| route.category == "admin/ops-websocket")
            .unwrap();
        assert_eq!(route.handler, "h.Admin.Ops.QPSWSHandler");
        assert!(!owns_handler(route.handler));
    }

    #[test]
    fn alert_rule_validation_applies_go_defaults_and_ranges() {
        let valid_payload = json!({
            "name": "errors",
            "metric_type": "error_rate",
            "operator": ">",
            "threshold": 5.0
        });
        let input = validate_alert_rule(&valid_payload).unwrap();
        assert!(input.enabled);
        assert!(input.notify_email);
        assert_eq!(input.severity, "P2");
        assert_eq!(input.window_minutes, 1);
        let invalid_payload = json!({
            "name": "bad",
            "metric_type": "error_rate",
            "operator": ">",
            "threshold": 101.0
        });
        assert!(validate_alert_rule(&invalid_payload).is_err());
    }

    #[test]
    fn dashboard_bucket_selection_matches_go_windows() {
        let minute = DashboardFilter::from_query(
            &BTreeMap::from([
                ("start_time".to_owned(), "2026-07-14T00:00:00Z".to_owned()),
                ("end_time".to_owned(), "2026-07-14T01:00:00Z".to_owned()),
            ]),
            "1h",
        )
        .unwrap();
        assert_eq!(minute.bucket_seconds(), 60);
        let hourly = DashboardFilter::from_query(
            &BTreeMap::from([
                ("start_time".to_owned(), "2026-07-01T00:00:00Z".to_owned()),
                ("end_time".to_owned(), "2026-07-14T00:00:00Z".to_owned()),
            ]),
            "1h",
        )
        .unwrap();
        assert_eq!(hourly.bucket_seconds(), 3_600);
    }

    #[test]
    fn correlation_and_risk_helpers_preserve_boundaries() {
        assert_eq!(
            parse_status_codes(Some(&"400, 529".to_owned())).unwrap(),
            vec![400, 529]
        );
        assert!(parse_status_codes(Some(&"bad".to_owned())).is_err());
        assert_eq!(
            moderation_date(Some("2026-07-14"), true).unwrap(),
            Some("2026-07-14T23:59:59.999999+00:00".to_owned())
        );
        assert!(ops_error_json_expression(false).contains("-ARRAY"));
        assert!(ops_error_json_expression(false).contains("'error_body'"));
        assert!(ops_error_json_expression(true).contains("'upstream_errors'"));
    }

    #[test]
    fn migrated_ops_handlers_do_not_fall_back_to_compat_special() {
        let legacy = include_str!("compat_special.rs");
        for handler in [
            "h.Admin.Ops.GetDashboardOverview",
            "h.Admin.Ops.GetDashboardSnapshotV2",
            "h.Admin.Ops.GetDashboardThroughputTrend",
            "h.Admin.Ops.GetDashboardErrorTrend",
            "h.Admin.Ops.GetDashboardLatencyHistogram",
            "h.Admin.Ops.GetDashboardErrorDistribution",
            "h.Admin.Ops.GetDashboardOpenAITokenStats",
            "h.Admin.Ops.ListRequestErrors",
            "h.Admin.Ops.GetRequestError",
            "h.Admin.Ops.ListRequestErrorUpstreamErrors",
            "h.Admin.Ops.ListUpstreamErrors",
            "h.Admin.Ops.GetUpstreamError",
            "h.Admin.ContentModeration.ListLogs",
        ] {
            assert!(
                !legacy.contains(handler),
                "legacy fallback still owns {handler}"
            );
        }
    }
}
