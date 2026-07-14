//! PostgreSQL-only background operations jobs.
//!
//! Every mutating job is elected with a `PostgreSQL` advisory lock. Derived
//! metrics remain idempotent, and alert/report progress is persisted so a
//! different replica can safely own the next cycle.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::too_many_lines
)]

use std::fmt::Write as _;
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt, fs,
    future::Future,
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Datelike, Days, NaiveDate, NaiveDateTime, Timelike, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Connection as _, PgConnection, PgPool, Postgres, Row, Transaction};
use tokio::{task::JoinHandle, time};
use tokio_util::sync::CancellationToken;

use crate::email::PostgresSmtpNotifier;

const METRICS_LOCK: i64 = 0x5355_4232_4f50_5301;
const DASHBOARD_LOCK: i64 = 0x5355_4232_4f50_5302;
const OPS_HOURLY_LOCK: i64 = 0x5355_4232_4f50_5303;
const OPS_DAILY_LOCK: i64 = 0x5355_4232_4f50_5304;
const ALERT_LOCK: i64 = 0x5355_4232_4f50_5305;
const REPORT_LOCK: i64 = 0x5355_4232_4f50_5306;
const CLEANUP_LOCK: i64 = 0x5355_4232_4f50_5307;
const MODERATION_CLEANUP_LOCK: i64 = 0x5355_4232_4f50_5308;
const CHANNEL_ROLLUP_LOCK: i64 = 0x5355_4232_4f50_5309;
const ALERT_EMAIL_LOCK: i64 = 0x5355_4232_4f50_530a;

const HEARTBEAT_METRICS: &str = "ops_metrics_collector";
const HEARTBEAT_DASHBOARD: &str = "usage_dashboard_aggregation";
const HEARTBEAT_OPS_HOURLY: &str = "ops_preaggregation_hourly";
const HEARTBEAT_OPS_DAILY: &str = "ops_preaggregation_daily";
const HEARTBEAT_ALERTS: &str = "ops_alert_evaluator";
const HEARTBEAT_REPORTS: &str = "ops_scheduled_reports";
const HEARTBEAT_CLEANUP: &str = "ops_cleanup";
const HEARTBEAT_MODERATION: &str = "content_moderation_cleanup";
const HEARTBEAT_CHANNELS: &str = "channel_monitor_rollup";
const ALERT_STATE_SETTING: &str = "ops_alert_evaluator_state";

const CLEANUP_BATCH_SIZE: i64 = 5_000;
const USAGE_CLEANUP_BATCH_SIZE: i64 = 10_000;
const ALERT_EMAIL_BATCH_SIZE: i64 = 100;
const CRON_CATCHUP_DAYS: u64 = 366 * 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpsRuntimeConfig {
    pub metrics_interval: Duration,
    pub dashboard_interval: Duration,
    pub ops_hourly_interval: Duration,
    pub ops_daily_interval: Duration,
    pub alert_interval: Duration,
    pub report_interval: Duration,
    pub cleanup_poll_interval: Duration,
    pub moderation_cleanup_interval: Duration,
    pub channel_rollup_interval: Duration,
    pub dashboard_lookback: Duration,
    pub usage_logs_retention_days: i64,
    pub billing_dedup_retention_days: i64,
    pub dashboard_hourly_retention_days: i64,
    pub dashboard_daily_retention_days: i64,
    pub channel_history_retention_days: i64,
    pub channel_rollup_retention_days: i64,
    pub timezone: String,
    pub shutdown_timeout: Duration,
}

impl Default for OpsRuntimeConfig {
    fn default() -> Self {
        Self {
            metrics_interval: Duration::from_mins(1),
            dashboard_interval: Duration::from_mins(1),
            ops_hourly_interval: Duration::from_mins(10),
            ops_daily_interval: Duration::from_hours(1),
            alert_interval: Duration::from_mins(1),
            report_interval: Duration::from_mins(1),
            cleanup_poll_interval: Duration::from_mins(1),
            moderation_cleanup_interval: Duration::from_hours(24),
            channel_rollup_interval: Duration::from_hours(1),
            dashboard_lookback: Duration::from_mins(2),
            usage_logs_retention_days: 90,
            billing_dedup_retention_days: 365,
            dashboard_hourly_retention_days: 180,
            dashboard_daily_retention_days: 730,
            channel_history_retention_days: 30,
            channel_rollup_retention_days: 30,
            timezone: std::env::var("TZ").unwrap_or_else(|_| "UTC".to_owned()),
            shutdown_timeout: Duration::from_secs(30),
        }
    }
}

impl OpsRuntimeConfig {
    /// Validates lifecycle and retention bounds.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero interval, an empty timezone, or a
    /// non-positive retention period.
    pub fn validate(&self) -> Result<(), OpsRuntimeConfigError> {
        for (name, value) in [
            ("metrics_interval", self.metrics_interval),
            ("dashboard_interval", self.dashboard_interval),
            ("ops_hourly_interval", self.ops_hourly_interval),
            ("ops_daily_interval", self.ops_daily_interval),
            ("alert_interval", self.alert_interval),
            ("report_interval", self.report_interval),
            ("cleanup_poll_interval", self.cleanup_poll_interval),
            (
                "moderation_cleanup_interval",
                self.moderation_cleanup_interval,
            ),
            ("channel_rollup_interval", self.channel_rollup_interval),
            ("shutdown_timeout", self.shutdown_timeout),
        ] {
            if value.is_zero() {
                return Err(OpsRuntimeConfigError(format!(
                    "{name} must be greater than zero"
                )));
            }
        }
        if self.timezone.trim().is_empty() {
            return Err(OpsRuntimeConfigError(
                "timezone must not be empty".to_owned(),
            ));
        }
        for (name, value) in [
            ("usage_logs_retention_days", self.usage_logs_retention_days),
            (
                "billing_dedup_retention_days",
                self.billing_dedup_retention_days,
            ),
            (
                "dashboard_hourly_retention_days",
                self.dashboard_hourly_retention_days,
            ),
            (
                "dashboard_daily_retention_days",
                self.dashboard_daily_retention_days,
            ),
            (
                "channel_history_retention_days",
                self.channel_history_retention_days,
            ),
            (
                "channel_rollup_retention_days",
                self.channel_rollup_retention_days,
            ),
        ] {
            if value <= 0 {
                return Err(OpsRuntimeConfigError(format!(
                    "{name} must be greater than zero"
                )));
            }
        }
        if self.billing_dedup_retention_days < self.usage_logs_retention_days {
            return Err(OpsRuntimeConfigError(
                "billing_dedup_retention_days must be >= usage_logs_retention_days".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpsRuntimeConfigError(String);

impl fmt::Display for OpsRuntimeConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for OpsRuntimeConfigError {}

pub struct OpsRuntime {
    cancellation: CancellationToken,
    tasks: Option<Vec<JoinHandle<()>>>,
    shutdown_timeout: Duration,
}

impl OpsRuntime {
    /// Starts all PostgreSQL-backed operations jobs.
    ///
    /// # Errors
    ///
    /// Returns an error when configuration is invalid or the SMTP TLS client
    /// cannot be initialized.
    #[allow(clippy::needless_pass_by_value)]
    pub fn spawn(pool: PgPool, config: OpsRuntimeConfig) -> Result<Self> {
        config.validate()?;
        let notifier = Arc::new(
            PostgresSmtpNotifier::new(pool.clone())
                .map_err(anyhow::Error::msg)
                .context("initialize ops SMTP notifier")?,
        );
        let cancellation = CancellationToken::new();
        let tasks = vec![
            tokio::spawn(metrics_loop(
                pool.clone(),
                config.metrics_interval,
                cancellation.child_token(),
            )),
            tokio::spawn(dashboard_loop(
                pool.clone(),
                config.clone(),
                cancellation.child_token(),
            )),
            tokio::spawn(ops_hourly_loop(
                pool.clone(),
                config.ops_hourly_interval,
                cancellation.child_token(),
            )),
            tokio::spawn(ops_daily_loop(
                pool.clone(),
                config.ops_daily_interval,
                cancellation.child_token(),
            )),
            tokio::spawn(alert_loop(
                pool.clone(),
                Arc::clone(&notifier),
                config.alert_interval,
                cancellation.child_token(),
            )),
            tokio::spawn(report_loop(
                pool.clone(),
                Arc::clone(&notifier),
                config.clone(),
                cancellation.child_token(),
            )),
            tokio::spawn(cleanup_loop(
                pool.clone(),
                config.clone(),
                cancellation.child_token(),
            )),
            tokio::spawn(moderation_cleanup_loop(
                pool.clone(),
                config.moderation_cleanup_interval,
                cancellation.child_token(),
            )),
            tokio::spawn(channel_rollup_loop(
                pool,
                config.clone(),
                cancellation.child_token(),
            )),
        ];
        Ok(Self {
            cancellation,
            tasks: Some(tasks),
            shutdown_timeout: config.shutdown_timeout,
        })
    }

    /// Cancels all jobs and waits for every active database operation.
    ///
    /// # Errors
    ///
    /// Returns an error if a task panics or the shared shutdown deadline is
    /// exceeded. Timed-out tasks are aborted and joined before returning.
    pub async fn shutdown(mut self) -> Result<()> {
        self.cancellation.cancel();
        let mut tasks = self.tasks.take().unwrap_or_default();
        let deadline = time::Instant::now() + self.shutdown_timeout;
        for index in 0..tasks.len() {
            let result = time::timeout_at(deadline, &mut tasks[index]).await;
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    abort_and_join(&mut tasks[index + 1..]).await;
                    return Err(anyhow!("ops runtime task failed: {error}"));
                }
                Err(_) => {
                    tasks[index].abort();
                    let _ = (&mut tasks[index]).await;
                    abort_and_join(&mut tasks[index + 1..]).await;
                    return Err(anyhow!(
                        "ops runtime did not stop within {:?}",
                        self.shutdown_timeout
                    ));
                }
            }
        }
        Ok(())
    }
}

impl Drop for OpsRuntime {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(tasks) = self.tasks.as_ref() {
            for task in tasks {
                task.abort();
            }
        }
    }
}

async fn abort_and_join(tasks: &mut [JoinHandle<()>]) {
    for task in tasks.iter() {
        task.abort();
    }
    for task in tasks {
        let _ = task.await;
    }
}

async fn wait_interval(ticker: &mut time::Interval, cancellation: &CancellationToken) -> bool {
    tokio::select! {
        () = cancellation.cancelled() => false,
        _ = ticker.tick() => true,
    }
}

fn interval(period: Duration) -> time::Interval {
    let mut ticker = time::interval(period);
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    ticker
}

async fn monitoring_enabled(pool: &PgPool) -> Result<bool> {
    let value = sqlx::query_scalar::<_, String>(
        "SELECT value FROM settings WHERE key = 'ops_monitoring_enabled'",
    )
    .fetch_optional(pool)
    .await
    .context("load ops monitoring switch")?;
    Ok(!value.is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "false" | "0" | "off" | "disabled"
        )
    }))
}

async fn try_xact_lock(transaction: &mut Transaction<'_, Postgres>, key: i64) -> Result<bool> {
    sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_xact_lock($1)")
        .bind(key)
        .fetch_one(&mut **transaction)
        .await
        .context("acquire PostgreSQL advisory transaction lock")
}

type LockedFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

async fn with_session_lock<T, F>(pool: &PgPool, key: i64, action: F) -> Result<Option<T>>
where
    T: Send,
    F: for<'a> FnOnce(&'a mut PgConnection) -> LockedFuture<'a, T>,
{
    let mut connection = pool
        .acquire()
        .await
        .context("acquire connection for ops advisory lock")?;
    // If this future is cancelled, close the session rather than returning a
    // possibly locked connection to the pool.
    connection.close_on_drop();
    let acquired = sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_lock($1)")
        .bind(key)
        .fetch_one(&mut *connection)
        .await
        .context("acquire PostgreSQL advisory session lock")?;
    if !acquired {
        return Ok(None);
    }
    let result = action(&mut connection).await;
    let unlock = sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1)")
        .bind(key)
        .fetch_one(&mut *connection)
        .await
        .context("release PostgreSQL advisory session lock")
        .and_then(|released| {
            if released {
                Ok(())
            } else {
                Err(anyhow!("PostgreSQL advisory session lock was not held"))
            }
        });
    match (result, unlock) {
        (Ok(value), Ok(())) => Ok(Some(value)),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(unlock_error)) => Err(error.context(format!(
            "also failed to release advisory lock: {unlock_error:#}"
        ))),
    }
}

async fn heartbeat_success(pool: &PgPool, job: &str, started: time::Instant, result: &str) {
    let duration_ms = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
    if let Err(error) = sqlx::query(
        r"
INSERT INTO ops_job_heartbeats (
    job_name,last_run_at,last_success_at,last_duration_ms,last_result,updated_at
)
VALUES ($1,NOW(),NOW(),$2,LEFT($3,2048),NOW())
ON CONFLICT (job_name) DO UPDATE SET
    last_run_at=EXCLUDED.last_run_at,
    last_success_at=EXCLUDED.last_success_at,
    last_duration_ms=EXCLUDED.last_duration_ms,
    last_result=EXCLUDED.last_result,
    last_error=NULL,
    updated_at=NOW()
",
    )
    .bind(job)
    .bind(duration_ms)
    .bind(result)
    .execute(pool)
    .await
    {
        tracing::warn!(job, error = %error, "failed to record ops job success");
    }
}

async fn heartbeat_error(pool: &PgPool, job: &str, started: time::Instant, error: &anyhow::Error) {
    let duration_ms = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
    if let Err(record_error) = sqlx::query(
        r"
INSERT INTO ops_job_heartbeats (
    job_name,last_run_at,last_error_at,last_error,last_duration_ms,updated_at
)
VALUES ($1,NOW(),NOW(),LEFT($2,2048),$3,NOW())
ON CONFLICT (job_name) DO UPDATE SET
    last_run_at=EXCLUDED.last_run_at,
    last_error_at=EXCLUDED.last_error_at,
    last_error=EXCLUDED.last_error,
    last_duration_ms=EXCLUDED.last_duration_ms,
    updated_at=NOW()
",
    )
    .bind(job)
    .bind(error.to_string())
    .bind(duration_ms)
    .execute(pool)
    .await
    {
        tracing::warn!(job, error = %record_error, "failed to record ops job error");
    }
}

#[derive(Default)]
struct SystemSampler {
    previous_cpu: Option<CpuSample>,
}

#[derive(Clone, Copy)]
struct CpuSample {
    used: u64,
    total: u64,
}

#[derive(Clone, Copy, Default)]
struct SystemStats {
    cpu_percent: Option<f64>,
    memory_used_mb: Option<i64>,
    memory_total_mb: Option<i64>,
    memory_percent: Option<f64>,
}

impl SystemSampler {
    fn sample(&mut self) -> SystemStats {
        let current_cpu = read_cpu_sample();
        let cpu_percent = self
            .previous_cpu
            .zip(current_cpu)
            .and_then(|(previous, current)| {
                let used = current.used.checked_sub(previous.used)?;
                let total = current.total.checked_sub(previous.total)?;
                (total > 0).then(|| round_one((used as f64 / total as f64) * 100.0))
            });
        self.previous_cpu = current_cpu;
        let (memory_used, memory_total) = read_memory_bytes();
        let memory_percent = memory_used.zip(memory_total).and_then(|(used, total)| {
            (total > 0).then(|| round_one((used as f64 / total as f64) * 100.0))
        });
        SystemStats {
            cpu_percent,
            memory_used_mb: memory_used.and_then(|value| i64::try_from(value / 1_048_576).ok()),
            memory_total_mb: memory_total.and_then(|value| i64::try_from(value / 1_048_576).ok()),
            memory_percent,
        }
    }
}

fn round_one(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}

fn read_cpu_sample() -> Option<CpuSample> {
    if let Some(used) = read_cgroup_cpu_usage()
        && let Some(cores) = read_cgroup_cpu_cores()
        && let Some(uptime_micros) = read_uptime_micros()
    {
        let total = (uptime_micros as f64 * cores).round();
        if total.is_finite() && total > 0.0 && total <= u64::MAX as f64 {
            return Some(CpuSample {
                used,
                total: total as u64,
            });
        }
    }
    let line = fs::read_to_string("/proc/stat")
        .ok()?
        .lines()
        .next()?
        .to_owned();
    let mut values = line
        .split_whitespace()
        .skip(1)
        .filter_map(|value| value.parse::<u64>().ok());
    let user = values.next()?;
    let nice = values.next()?;
    let system = values.next()?;
    let idle = values.next()?;
    let io_wait = values.next().unwrap_or(0);
    let irq = values.next().unwrap_or(0);
    let soft_irq = values.next().unwrap_or(0);
    let steal = values.next().unwrap_or(0);
    let busy_ticks = user
        .saturating_add(nice)
        .saturating_add(system)
        .saturating_add(irq)
        .saturating_add(soft_irq)
        .saturating_add(steal);
    Some(CpuSample {
        used: busy_ticks,
        total: busy_ticks.saturating_add(idle).saturating_add(io_wait),
    })
}

fn read_cgroup_cpu_usage() -> Option<u64> {
    if let Ok(raw) = fs::read_to_string("/sys/fs/cgroup/cpu.stat") {
        for line in raw.lines() {
            let mut fields = line.split_whitespace();
            if fields.next() == Some("usage_usec") {
                return fields.next()?.parse::<u64>().ok();
            }
        }
    }
    fs::read_to_string("/sys/fs/cgroup/cpuacct/cpuacct.usage")
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(|value| value / 1_000)
}

fn read_cgroup_cpu_cores() -> Option<f64> {
    let raw = fs::read_to_string("/sys/fs/cgroup/cpu.max").ok()?;
    let mut fields = raw.split_whitespace();
    let quota = fields.next()?;
    let period = fields.next()?.parse::<f64>().ok()?;
    if quota == "max" {
        return None;
    }
    let quota = quota.parse::<f64>().ok()?;
    (period > 0.0 && quota > 0.0).then_some(quota / period)
}

fn read_uptime_micros() -> Option<u64> {
    let seconds = fs::read_to_string("/proc/uptime")
        .ok()?
        .split_whitespace()
        .next()?
        .parse::<f64>()
        .ok()?;
    let micros = seconds * 1_000_000.0;
    (micros.is_finite() && micros >= 0.0 && micros <= u64::MAX as f64).then_some(micros as u64)
}

fn read_memory_bytes() -> (Option<u64>, Option<u64>) {
    if let Ok(current) = fs::read_to_string("/sys/fs/cgroup/memory.current")
        && let Ok(used) = current.trim().parse::<u64>()
    {
        let total = fs::read_to_string("/sys/fs/cgroup/memory.max")
            .ok()
            .and_then(|raw| raw.trim().parse::<u64>().ok());
        return (Some(used), total);
    }
    let Ok(raw) = fs::read_to_string("/proc/meminfo") else {
        return (None, None);
    };
    let mut total_kb = None;
    let mut available_kb = None;
    for line in raw.lines() {
        let mut fields = line.split_whitespace();
        match fields.next() {
            Some("MemTotal:") => total_kb = fields.next().and_then(|v| v.parse::<u64>().ok()),
            Some("MemAvailable:") => {
                available_kb = fields.next().and_then(|v| v.parse::<u64>().ok());
            }
            _ => {}
        }
    }
    let total = total_kb.map(|value| value.saturating_mul(1024));
    let used = total
        .zip(available_kb)
        .map(|(total, available)| total.saturating_sub(available.saturating_mul(1024)));
    (used, total)
}

async fn metrics_loop(pool: PgPool, period: Duration, cancellation: CancellationToken) {
    let mut ticker = interval(period);
    let mut sampler = SystemSampler::default();
    while wait_interval(&mut ticker, &cancellation).await {
        let started = time::Instant::now();
        if !monitoring_enabled(&pool).await.unwrap_or(true) {
            continue;
        }
        let stats = sampler.sample();
        match collect_metrics_once(&pool, stats).await {
            Ok(true) => {
                heartbeat_success(&pool, HEARTBEAT_METRICS, started, "window=1m").await;
            }
            Ok(false) => {}
            Err(error) => {
                tracing::error!(error = %error, "PostgreSQL ops metrics collection failed");
                heartbeat_error(&pool, HEARTBEAT_METRICS, started, &error).await;
            }
        }
    }
}

async fn collect_metrics_once(pool: &PgPool, stats: SystemStats) -> Result<bool> {
    let mut transaction = pool.begin().await.context("begin metrics collection")?;
    if !try_xact_lock(&mut transaction, METRICS_LOCK).await? {
        transaction.rollback().await?;
        return Ok(false);
    }
    let size = i32::try_from(pool.size()).unwrap_or(i32::MAX);
    let idle = i32::try_from(pool.num_idle()).unwrap_or(i32::MAX);
    let active = size.saturating_sub(idle);
    sqlx::query(METRICS_INSERT_SQL)
        .bind(stats.cpu_percent)
        .bind(stats.memory_used_mb)
        .bind(stats.memory_total_mb)
        .bind(stats.memory_percent)
        .bind(active)
        .bind(idle)
        .execute(&mut *transaction)
        .await
        .context("insert PostgreSQL ops system metrics")?;
    transaction.commit().await.context("commit metrics")?;
    Ok(true)
}

const METRICS_INSERT_SQL: &str = r"
WITH bounds AS (
    SELECT date_trunc('minute', NOW()) AS window_end,
           date_trunc('minute', NOW()) - INTERVAL '1 minute' AS window_start
), usage_stats AS (
    SELECT COUNT(*)::bigint AS success_count,
           COALESCE(SUM(input_tokens + output_tokens + cache_creation_tokens + cache_read_tokens),0)::bigint AS tokens,
           percentile_cont(0.50) WITHIN GROUP (ORDER BY duration_ms) FILTER (WHERE duration_ms IS NOT NULL)::int AS duration_p50,
           percentile_cont(0.90) WITHIN GROUP (ORDER BY duration_ms) FILTER (WHERE duration_ms IS NOT NULL)::int AS duration_p90,
           percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms) FILTER (WHERE duration_ms IS NOT NULL)::int AS duration_p95,
           percentile_cont(0.99) WITHIN GROUP (ORDER BY duration_ms) FILTER (WHERE duration_ms IS NOT NULL)::int AS duration_p99,
           AVG(duration_ms) FILTER (WHERE duration_ms IS NOT NULL)::double precision AS duration_avg,
           MAX(duration_ms)::int AS duration_max,
           percentile_cont(0.50) WITHIN GROUP (ORDER BY first_token_ms) FILTER (WHERE first_token_ms IS NOT NULL)::int AS ttft_p50,
           percentile_cont(0.90) WITHIN GROUP (ORDER BY first_token_ms) FILTER (WHERE first_token_ms IS NOT NULL)::int AS ttft_p90,
           percentile_cont(0.95) WITHIN GROUP (ORDER BY first_token_ms) FILTER (WHERE first_token_ms IS NOT NULL)::int AS ttft_p95,
           percentile_cont(0.99) WITHIN GROUP (ORDER BY first_token_ms) FILTER (WHERE first_token_ms IS NOT NULL)::int AS ttft_p99,
           AVG(first_token_ms) FILTER (WHERE first_token_ms IS NOT NULL)::double precision AS ttft_avg,
           MAX(first_token_ms)::int AS ttft_max
    FROM usage_logs, bounds
    WHERE created_at >= bounds.window_start AND created_at < bounds.window_end
), error_stats AS (
    SELECT COUNT(*) FILTER (WHERE COALESCE(status_code,0) >= 400)::bigint AS errors,
           COUNT(*) FILTER (WHERE COALESCE(status_code,0) >= 400 AND is_business_limited)::bigint AS limited,
           COUNT(*) FILTER (WHERE COALESCE(status_code,0) >= 400 AND NOT is_business_limited)::bigint AS sla_errors,
           COUNT(*) FILTER (WHERE error_owner='provider' AND NOT is_business_limited AND COALESCE(upstream_status_code,status_code,0) NOT IN (429,529))::bigint AS upstream_other,
           COUNT(*) FILTER (WHERE error_owner='provider' AND NOT is_business_limited AND COALESCE(upstream_status_code,status_code,0)=429)::bigint AS upstream_429,
           COUNT(*) FILTER (WHERE error_owner='provider' AND NOT is_business_limited AND COALESCE(upstream_status_code,status_code,0)=529)::bigint AS upstream_529
    FROM ops_error_logs, bounds
    WHERE created_at >= bounds.window_start AND created_at < bounds.window_end
      AND is_count_tokens=FALSE
), switch_stats AS (
    SELECT COALESCE(SUM(CASE WHEN split_part(event->>'kind',':',1) IN ('failover','retry_exhausted_failover','failover_on_400') THEN 1 ELSE 0 END),0)::bigint AS switches
    FROM ops_error_logs logs
    CROSS JOIN bounds
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE WHEN jsonb_typeof(logs.upstream_errors)='array' THEN logs.upstream_errors ELSE '[]'::jsonb END
    ) event
    WHERE logs.created_at >= bounds.window_start AND logs.created_at < bounds.window_end
      AND logs.is_count_tokens=FALSE
), removed AS (
    DELETE FROM ops_system_metrics
    USING bounds
    WHERE ops_system_metrics.created_at=bounds.window_end
      AND ops_system_metrics.window_minutes=1
      AND ops_system_metrics.platform IS NULL
      AND ops_system_metrics.group_id IS NULL
)
INSERT INTO ops_system_metrics (
    created_at,window_minutes,success_count,error_count_total,business_limited_count,error_count_sla,
    upstream_error_count_excl_429_529,upstream_429_count,upstream_529_count,
    token_consumed,account_switch_count,qps,tps,
    duration_p50_ms,duration_p90_ms,duration_p95_ms,duration_p99_ms,duration_avg_ms,duration_max_ms,
    ttft_p50_ms,ttft_p90_ms,ttft_p95_ms,ttft_p99_ms,ttft_avg_ms,ttft_max_ms,
    cpu_usage_percent,memory_used_mb,memory_total_mb,memory_usage_percent,
    db_ok,redis_ok,redis_conn_total,redis_conn_idle,db_conn_active,db_conn_idle,
    db_conn_waiting,goroutine_count,concurrency_queue_depth
)
SELECT bounds.window_end,1,usage_stats.success_count,error_stats.errors,error_stats.limited,error_stats.sla_errors,
       error_stats.upstream_other,error_stats.upstream_429,error_stats.upstream_529,
       usage_stats.tokens,switch_stats.switches,
       ROUND((usage_stats.success_count+error_stats.errors)::numeric/60,1)::double precision,
       ROUND(usage_stats.tokens::numeric/60,1)::double precision,
       usage_stats.duration_p50,usage_stats.duration_p90,usage_stats.duration_p95,usage_stats.duration_p99,
       usage_stats.duration_avg,usage_stats.duration_max,
       usage_stats.ttft_p50,usage_stats.ttft_p90,usage_stats.ttft_p95,usage_stats.ttft_p99,
       usage_stats.ttft_avg,usage_stats.ttft_max,
       $1,$2,$3,$4,TRUE,NULL,NULL,NULL,$5,$6,NULL,NULL,NULL
FROM bounds,usage_stats,error_stats,switch_stats
";

async fn dashboard_loop(pool: PgPool, config: OpsRuntimeConfig, cancellation: CancellationToken) {
    let mut ticker = interval(config.dashboard_interval);
    while wait_interval(&mut ticker, &cancellation).await {
        let started = time::Instant::now();
        match aggregate_dashboard_once(&pool, &config).await {
            Ok(true) => {
                heartbeat_success(
                    &pool,
                    HEARTBEAT_DASHBOARD,
                    started,
                    "hourly/daily aggregates and watermark updated",
                )
                .await;
            }
            Ok(false) => {}
            Err(error) => {
                tracing::error!(error = %error, "usage dashboard aggregation failed");
                heartbeat_error(&pool, HEARTBEAT_DASHBOARD, started, &error).await;
            }
        }
    }
}

async fn aggregate_dashboard_once(pool: &PgPool, config: &OpsRuntimeConfig) -> Result<bool> {
    let mut transaction = pool.begin().await.context("begin dashboard aggregation")?;
    if !try_xact_lock(&mut transaction, DASHBOARD_LOCK).await? {
        transaction.rollback().await?;
        return Ok(false);
    }
    let lookback_seconds = config.dashboard_lookback.as_secs() as f64;
    let initial_days = dashboard_initial_backfill_days(config);
    for suffix in [
        DASHBOARD_HOURLY_USERS_SQL,
        DASHBOARD_DAILY_USERS_SQL,
        DASHBOARD_HOURLY_SQL,
        DASHBOARD_DAILY_SQL,
    ] {
        let query = format!("{DASHBOARD_BOUNDS_SQL}{suffix}");
        sqlx::query(&query)
            .bind(initial_days)
            .bind(lookback_seconds)
            .execute(&mut *transaction)
            .await
            .context("upsert usage dashboard aggregates")?;
    }
    sqlx::query(
        r"
INSERT INTO usage_dashboard_aggregation_watermark (id,last_aggregated_at,updated_at)
VALUES (1,NOW(),NOW())
ON CONFLICT (id) DO UPDATE SET last_aggregated_at=EXCLUDED.last_aggregated_at,updated_at=NOW()
",
    )
    .execute(&mut *transaction)
    .await
    .context("update usage dashboard watermark")?;
    transaction
        .commit()
        .await
        .context("commit dashboard aggregation")?;
    Ok(true)
}

fn dashboard_initial_backfill_days(config: &OpsRuntimeConfig) -> i32 {
    i32::try_from(config.usage_logs_retention_days).unwrap_or(i32::MAX)
}

const DASHBOARD_BOUNDS_SQL: &str = r"
WITH bounds AS (
    SELECT date_trunc('hour',
               CASE WHEN watermark.last_aggregated_at <= TIMESTAMPTZ '1970-01-02 00:00:00+00'
                    THEN NOW() - make_interval(days => $1::int)
                    ELSE watermark.last_aggregated_at - make_interval(secs => $2::double precision)
               END
           ) AS hour_start,
           date_trunc('hour',NOW()) + INTERVAL '1 hour' AS hour_end,
           date_trunc('day',
               CASE WHEN watermark.last_aggregated_at <= TIMESTAMPTZ '1970-01-02 00:00:00+00'
                    THEN NOW() - make_interval(days => $1::int)
                    ELSE watermark.last_aggregated_at - make_interval(secs => $2::double precision)
               END
           ) AS day_start,
           date_trunc('day',NOW()) + INTERVAL '1 day' AS day_end
    FROM usage_dashboard_aggregation_watermark watermark
    WHERE watermark.id=1
)
";

const DASHBOARD_HOURLY_USERS_SQL: &str = r"
INSERT INTO usage_dashboard_hourly_users (bucket_start,user_id)
SELECT DISTINCT date_trunc('hour',logs.created_at),logs.user_id
FROM usage_logs logs,bounds
WHERE logs.created_at >= bounds.hour_start AND logs.created_at < bounds.hour_end
ON CONFLICT DO NOTHING
";

const DASHBOARD_DAILY_USERS_SQL: &str = r"
INSERT INTO usage_dashboard_daily_users (bucket_date,user_id)
SELECT DISTINCT (logs.created_at AT TIME ZONE 'UTC')::date,logs.user_id
FROM usage_logs logs,bounds
WHERE logs.created_at >= bounds.day_start AND logs.created_at < bounds.day_end
ON CONFLICT DO NOTHING
";

const DASHBOARD_HOURLY_SQL: &str = r"
, hourly AS (
    SELECT date_trunc('hour',logs.created_at) AS bucket_start,
           COUNT(*)::bigint AS total_requests,
           COALESCE(SUM(input_tokens),0)::bigint AS input_tokens,
           COALESCE(SUM(output_tokens),0)::bigint AS output_tokens,
           COALESCE(SUM(cache_creation_tokens),0)::bigint AS cache_creation_tokens,
           COALESCE(SUM(cache_read_tokens),0)::bigint AS cache_read_tokens,
           COALESCE(SUM(total_cost),0) AS total_cost,
           COALESCE(SUM(actual_cost),0) AS actual_cost,
           COALESCE(SUM(COALESCE(account_stats_cost,total_cost) * COALESCE(account_rate_multiplier,1)),0) AS account_cost,
           COALESCE(SUM(COALESCE(duration_ms,0)),0)::bigint AS total_duration_ms
    FROM usage_logs logs,bounds
    WHERE logs.created_at >= bounds.hour_start AND logs.created_at < bounds.hour_end
    GROUP BY 1
), users AS (
    SELECT bucket_start,COUNT(*)::bigint AS active_users
    FROM usage_dashboard_hourly_users,bounds
    WHERE bucket_start >= bounds.hour_start AND bucket_start < bounds.hour_end
    GROUP BY bucket_start
)
INSERT INTO usage_dashboard_hourly (
    bucket_start,total_requests,input_tokens,output_tokens,cache_creation_tokens,cache_read_tokens,
    total_cost,actual_cost,account_cost,total_duration_ms,active_users,computed_at
)
SELECT hourly.bucket_start,hourly.total_requests,hourly.input_tokens,hourly.output_tokens,
       hourly.cache_creation_tokens,hourly.cache_read_tokens,hourly.total_cost,hourly.actual_cost,
       hourly.account_cost,hourly.total_duration_ms,COALESCE(users.active_users,0),NOW()
FROM hourly LEFT JOIN users USING (bucket_start)
ON CONFLICT (bucket_start) DO UPDATE SET
    total_requests=EXCLUDED.total_requests,input_tokens=EXCLUDED.input_tokens,
    output_tokens=EXCLUDED.output_tokens,cache_creation_tokens=EXCLUDED.cache_creation_tokens,
    cache_read_tokens=EXCLUDED.cache_read_tokens,total_cost=EXCLUDED.total_cost,
    actual_cost=EXCLUDED.actual_cost,account_cost=EXCLUDED.account_cost,
    total_duration_ms=EXCLUDED.total_duration_ms,active_users=EXCLUDED.active_users,computed_at=NOW()
";

const DASHBOARD_DAILY_SQL: &str = r"
, daily AS (
    SELECT (hourly.bucket_start AT TIME ZONE 'UTC')::date AS bucket_date,
           COALESCE(SUM(total_requests),0)::bigint AS total_requests,
           COALESCE(SUM(input_tokens),0)::bigint AS input_tokens,
           COALESCE(SUM(output_tokens),0)::bigint AS output_tokens,
           COALESCE(SUM(cache_creation_tokens),0)::bigint AS cache_creation_tokens,
           COALESCE(SUM(cache_read_tokens),0)::bigint AS cache_read_tokens,
           COALESCE(SUM(total_cost),0) AS total_cost,
           COALESCE(SUM(actual_cost),0) AS actual_cost,
           COALESCE(SUM(account_cost),0) AS account_cost,
           COALESCE(SUM(total_duration_ms),0)::bigint AS total_duration_ms
    FROM usage_dashboard_hourly hourly,bounds
    WHERE hourly.bucket_start >= bounds.day_start AND hourly.bucket_start < bounds.day_end
    GROUP BY 1
), users AS (
    SELECT bucket_date,COUNT(*)::bigint AS active_users
    FROM usage_dashboard_daily_users,bounds
    WHERE bucket_date >= bounds.day_start::date AND bucket_date < bounds.day_end::date
    GROUP BY bucket_date
)
INSERT INTO usage_dashboard_daily (
    bucket_date,total_requests,input_tokens,output_tokens,cache_creation_tokens,cache_read_tokens,
    total_cost,actual_cost,account_cost,total_duration_ms,active_users,computed_at
)
SELECT daily.bucket_date,daily.total_requests,daily.input_tokens,daily.output_tokens,
       daily.cache_creation_tokens,daily.cache_read_tokens,daily.total_cost,daily.actual_cost,
       daily.account_cost,daily.total_duration_ms,COALESCE(users.active_users,0),NOW()
FROM daily LEFT JOIN users USING (bucket_date)
ON CONFLICT (bucket_date) DO UPDATE SET
    total_requests=EXCLUDED.total_requests,input_tokens=EXCLUDED.input_tokens,
    output_tokens=EXCLUDED.output_tokens,cache_creation_tokens=EXCLUDED.cache_creation_tokens,
    cache_read_tokens=EXCLUDED.cache_read_tokens,total_cost=EXCLUDED.total_cost,
    actual_cost=EXCLUDED.actual_cost,account_cost=EXCLUDED.account_cost,
    total_duration_ms=EXCLUDED.total_duration_ms,active_users=EXCLUDED.active_users,computed_at=NOW()
";

async fn ops_hourly_loop(pool: PgPool, period: Duration, cancellation: CancellationToken) {
    let mut ticker = interval(period);
    while wait_interval(&mut ticker, &cancellation).await {
        let started = time::Instant::now();
        if !monitoring_enabled(&pool).await.unwrap_or(true) {
            continue;
        }
        match aggregate_ops_hourly_once(&pool).await {
            Ok(Some((start, end))) => {
                heartbeat_success(
                    &pool,
                    HEARTBEAT_OPS_HOURLY,
                    started,
                    &format!("window_epoch={start}..{end}"),
                )
                .await;
            }
            Ok(None) => {}
            Err(error) => {
                tracing::error!(error = %error, "hourly ops aggregation failed");
                heartbeat_error(&pool, HEARTBEAT_OPS_HOURLY, started, &error).await;
            }
        }
    }
}

async fn aggregate_ops_hourly_once(pool: &PgPool) -> Result<Option<(i64, i64)>> {
    with_session_lock(pool, OPS_HOURLY_LOCK, |connection| {
        Box::pin(async move {
            let row = sqlx::query(
                r"
SELECT EXTRACT(EPOCH FROM date_trunc('hour',NOW()-INTERVAL '5 minutes'))::bigint AS end_epoch,
       EXTRACT(EPOCH FROM MAX(bucket_start))::bigint AS latest_epoch
FROM ops_metrics_hourly
",
            )
            .fetch_one(&mut *connection)
            .await?;
            let end: i64 = row.try_get("end_epoch")?;
            let latest: Option<i64> = row.try_get("latest_epoch")?;
            let mut start = end.saturating_sub(60 * 60);
            if let Some(latest) = latest {
                start = start.max(latest.saturating_sub(2 * 60 * 60));
            }
            start -= start.rem_euclid(60 * 60);
            if start >= end {
                return Ok((start, end));
            }
            sqlx::query(OPS_HOURLY_SQL)
                .bind(start as f64)
                .bind(end as f64)
                .execute(&mut *connection)
                .await
                .context("upsert hourly ops metrics")?;
            Ok((start, end))
        })
    })
    .await
}

async fn ops_daily_loop(pool: PgPool, period: Duration, cancellation: CancellationToken) {
    let mut ticker = interval(period);
    while wait_interval(&mut ticker, &cancellation).await {
        let started = time::Instant::now();
        if !monitoring_enabled(&pool).await.unwrap_or(true) {
            continue;
        }
        match aggregate_ops_daily_once(&pool).await {
            Ok(Some((start, end))) => {
                heartbeat_success(
                    &pool,
                    HEARTBEAT_OPS_DAILY,
                    started,
                    &format!("window_epoch={start}..{end}"),
                )
                .await;
            }
            Ok(None) => {}
            Err(error) => {
                tracing::error!(error = %error, "daily ops aggregation failed");
                heartbeat_error(&pool, HEARTBEAT_OPS_DAILY, started, &error).await;
            }
        }
    }
}

async fn aggregate_ops_daily_once(pool: &PgPool) -> Result<Option<(i64, i64)>> {
    with_session_lock(pool, OPS_DAILY_LOCK, |connection| {
        Box::pin(async move {
            let row = sqlx::query(
                r"
SELECT EXTRACT(EPOCH FROM date_trunc('day',NOW() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')::bigint AS end_epoch,
       EXTRACT(EPOCH FROM MAX(bucket_date::timestamp AT TIME ZONE 'UTC'))::bigint AS latest_epoch
FROM ops_metrics_daily
",
            )
            .fetch_one(&mut *connection)
            .await?;
            let end: i64 = row.try_get("end_epoch")?;
            let latest: Option<i64> = row.try_get("latest_epoch")?;
            let mut start = end.saturating_sub(24 * 60 * 60);
            if let Some(latest) = latest {
                start = start.max(latest.saturating_sub(48 * 60 * 60));
            }
            start -= start.rem_euclid(24 * 60 * 60);
            if start >= end {
                return Ok((start, end));
            }
            sqlx::query(OPS_DAILY_SQL)
                .bind(start as f64)
                .bind(end as f64)
                .execute(&mut *connection)
                .await
                .context("upsert daily ops metrics")?;
            Ok((start, end))
        })
    })
    .await
}

const OPS_HOURLY_SQL: &str = r"
WITH usage_base AS (
  SELECT date_trunc('hour',ul.created_at) AS bucket_start,
         groups.platform,ul.group_id,ul.duration_ms,ul.first_token_ms,
         (ul.input_tokens+ul.output_tokens+ul.cache_creation_tokens+ul.cache_read_tokens) AS tokens
  FROM usage_logs ul
  JOIN groups ON groups.id=ul.group_id
  WHERE ul.created_at >= to_timestamp($1) AND ul.created_at < to_timestamp($2)
), usage_agg AS (
  SELECT bucket_start,
         CASE WHEN GROUPING(platform)=1 THEN NULL ELSE platform END AS platform,
         CASE WHEN GROUPING(group_id)=1 THEN NULL ELSE group_id END AS group_id,
         COUNT(*)::bigint AS success_count,
         COUNT(*) FILTER (WHERE first_token_ms IS NOT NULL)::bigint AS ttft_sample_count,
         COALESCE(SUM(tokens),0)::bigint AS token_consumed,
         percentile_cont(0.50) WITHIN GROUP (ORDER BY duration_ms) FILTER (WHERE duration_ms IS NOT NULL) AS duration_p50_ms,
         percentile_cont(0.90) WITHIN GROUP (ORDER BY duration_ms) FILTER (WHERE duration_ms IS NOT NULL) AS duration_p90_ms,
         percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms) FILTER (WHERE duration_ms IS NOT NULL) AS duration_p95_ms,
         percentile_cont(0.99) WITHIN GROUP (ORDER BY duration_ms) FILTER (WHERE duration_ms IS NOT NULL) AS duration_p99_ms,
         AVG(duration_ms) FILTER (WHERE duration_ms IS NOT NULL)::double precision AS duration_avg_ms,
         MAX(duration_ms)::int AS duration_max_ms,
         percentile_cont(0.50) WITHIN GROUP (ORDER BY first_token_ms) FILTER (WHERE first_token_ms IS NOT NULL) AS ttft_p50_ms,
         percentile_cont(0.90) WITHIN GROUP (ORDER BY first_token_ms) FILTER (WHERE first_token_ms IS NOT NULL) AS ttft_p90_ms,
         percentile_cont(0.95) WITHIN GROUP (ORDER BY first_token_ms) FILTER (WHERE first_token_ms IS NOT NULL) AS ttft_p95_ms,
         percentile_cont(0.99) WITHIN GROUP (ORDER BY first_token_ms) FILTER (WHERE first_token_ms IS NOT NULL) AS ttft_p99_ms,
         AVG(first_token_ms) FILTER (WHERE first_token_ms IS NOT NULL)::double precision AS ttft_avg_ms,
         MAX(first_token_ms)::int AS ttft_max_ms
  FROM usage_base
  GROUP BY GROUPING SETS ((bucket_start),(bucket_start,platform),(bucket_start,platform,group_id))
), error_base AS (
  SELECT date_trunc('hour',created_at) AS bucket_start,
         COALESCE(platform,'unknown') AS platform,group_id,is_business_limited,error_owner,
         status_code AS client_status_code,COALESCE(upstream_status_code,status_code,0) AS effective_status_code
  FROM ops_error_logs
  WHERE created_at >= to_timestamp($1) AND created_at < to_timestamp($2) AND is_count_tokens=FALSE
), error_agg AS (
  SELECT bucket_start,
         CASE WHEN GROUPING(platform)=1 THEN NULL ELSE platform END AS platform,
         CASE WHEN GROUPING(group_id)=1 THEN NULL ELSE group_id END AS group_id,
         COUNT(*) FILTER (WHERE COALESCE(client_status_code,0)>=400)::bigint AS error_count_total,
         COUNT(*) FILTER (WHERE COALESCE(client_status_code,0)>=400 AND is_business_limited)::bigint AS business_limited_count,
         COUNT(*) FILTER (WHERE COALESCE(client_status_code,0)>=400 AND NOT is_business_limited)::bigint AS error_count_sla,
         COUNT(*) FILTER (WHERE error_owner='provider' AND NOT is_business_limited AND effective_status_code NOT IN (429,529))::bigint AS upstream_error_count_excl_429_529,
         COUNT(*) FILTER (WHERE error_owner='provider' AND NOT is_business_limited AND effective_status_code=429)::bigint AS upstream_429_count,
         COUNT(*) FILTER (WHERE error_owner='provider' AND NOT is_business_limited AND effective_status_code=529)::bigint AS upstream_529_count
  FROM error_base
  GROUP BY GROUPING SETS ((bucket_start),(bucket_start,platform),(bucket_start,platform,group_id))
  HAVING GROUPING(group_id)=1 OR group_id IS NOT NULL
), combined AS (
  SELECT COALESCE(u.bucket_start,e.bucket_start) AS bucket_start,
         COALESCE(u.platform,e.platform) AS platform,COALESCE(u.group_id,e.group_id) AS group_id,
         COALESCE(u.success_count,0) AS success_count,COALESCE(u.ttft_sample_count,0) AS ttft_sample_count,
         COALESCE(e.error_count_total,0) AS error_count_total,
         COALESCE(e.business_limited_count,0) AS business_limited_count,
         COALESCE(e.error_count_sla,0) AS error_count_sla,
         COALESCE(e.upstream_error_count_excl_429_529,0) AS upstream_error_count_excl_429_529,
         COALESCE(e.upstream_429_count,0) AS upstream_429_count,
         COALESCE(e.upstream_529_count,0) AS upstream_529_count,
         COALESCE(u.token_consumed,0) AS token_consumed,
         u.duration_p50_ms,u.duration_p90_ms,u.duration_p95_ms,u.duration_p99_ms,
         u.duration_avg_ms,u.duration_max_ms,u.ttft_p50_ms,u.ttft_p90_ms,u.ttft_p95_ms,
         u.ttft_p99_ms,u.ttft_avg_ms,u.ttft_max_ms
  FROM usage_agg u FULL OUTER JOIN error_agg e
    ON u.bucket_start=e.bucket_start
   AND COALESCE(u.platform,'')=COALESCE(e.platform,'')
   AND COALESCE(u.group_id,0)=COALESCE(e.group_id,0)
)
INSERT INTO ops_metrics_hourly (
  bucket_start,platform,group_id,success_count,ttft_sample_count,error_count_total,
  business_limited_count,error_count_sla,upstream_error_count_excl_429_529,
  upstream_429_count,upstream_529_count,token_consumed,
  duration_p50_ms,duration_p90_ms,duration_p95_ms,duration_p99_ms,duration_avg_ms,duration_max_ms,
  ttft_p50_ms,ttft_p90_ms,ttft_p95_ms,ttft_p99_ms,ttft_avg_ms,ttft_max_ms,computed_at
)
SELECT bucket_start,NULLIF(platform,''),group_id,success_count,ttft_sample_count,error_count_total,
       business_limited_count,error_count_sla,upstream_error_count_excl_429_529,
       upstream_429_count,upstream_529_count,token_consumed,
       duration_p50_ms::int,duration_p90_ms::int,duration_p95_ms::int,duration_p99_ms::int,
       duration_avg_ms,duration_max_ms,ttft_p50_ms::int,ttft_p90_ms::int,ttft_p95_ms::int,
       ttft_p99_ms::int,ttft_avg_ms,ttft_max_ms,NOW()
FROM combined WHERE bucket_start IS NOT NULL AND (platform IS NULL OR platform<>'')
ON CONFLICT (bucket_start,COALESCE(platform,''),COALESCE(group_id,0)) DO UPDATE SET
 success_count=EXCLUDED.success_count,ttft_sample_count=EXCLUDED.ttft_sample_count,
 error_count_total=EXCLUDED.error_count_total,business_limited_count=EXCLUDED.business_limited_count,
 error_count_sla=EXCLUDED.error_count_sla,
 upstream_error_count_excl_429_529=EXCLUDED.upstream_error_count_excl_429_529,
 upstream_429_count=EXCLUDED.upstream_429_count,upstream_529_count=EXCLUDED.upstream_529_count,
 token_consumed=EXCLUDED.token_consumed,duration_p50_ms=EXCLUDED.duration_p50_ms,
 duration_p90_ms=EXCLUDED.duration_p90_ms,duration_p95_ms=EXCLUDED.duration_p95_ms,
 duration_p99_ms=EXCLUDED.duration_p99_ms,duration_avg_ms=EXCLUDED.duration_avg_ms,
 duration_max_ms=EXCLUDED.duration_max_ms,ttft_p50_ms=EXCLUDED.ttft_p50_ms,
 ttft_p90_ms=EXCLUDED.ttft_p90_ms,ttft_p95_ms=EXCLUDED.ttft_p95_ms,
 ttft_p99_ms=EXCLUDED.ttft_p99_ms,ttft_avg_ms=EXCLUDED.ttft_avg_ms,
 ttft_max_ms=EXCLUDED.ttft_max_ms,computed_at=NOW()
";

const OPS_DAILY_SQL: &str = r"
INSERT INTO ops_metrics_daily (
 bucket_date,platform,group_id,success_count,ttft_sample_count,error_count_total,
 business_limited_count,error_count_sla,upstream_error_count_excl_429_529,
 upstream_429_count,upstream_529_count,token_consumed,
 duration_p50_ms,duration_p90_ms,duration_p95_ms,duration_p99_ms,duration_avg_ms,duration_max_ms,
 ttft_p50_ms,ttft_p90_ms,ttft_p95_ms,ttft_p99_ms,ttft_avg_ms,ttft_max_ms,computed_at
)
SELECT (bucket_start AT TIME ZONE 'UTC')::date,platform,group_id,
 COALESCE(SUM(success_count),0),COALESCE(SUM(ttft_sample_count),0),
 COALESCE(SUM(error_count_total),0),COALESCE(SUM(business_limited_count),0),
 COALESCE(SUM(error_count_sla),0),COALESCE(SUM(upstream_error_count_excl_429_529),0),
 COALESCE(SUM(upstream_429_count),0),COALESCE(SUM(upstream_529_count),0),
 COALESCE(SUM(token_consumed),0),
 ROUND(SUM(duration_p50_ms::double precision*success_count) FILTER (WHERE duration_p50_ms IS NOT NULL)
   / NULLIF(SUM(success_count) FILTER (WHERE duration_p50_ms IS NOT NULL),0))::int,
 ROUND(SUM(duration_p90_ms::double precision*success_count) FILTER (WHERE duration_p90_ms IS NOT NULL)
   / NULLIF(SUM(success_count) FILTER (WHERE duration_p90_ms IS NOT NULL),0))::int,
 MAX(duration_p95_ms),MAX(duration_p99_ms),
 SUM(duration_avg_ms*success_count) FILTER (WHERE duration_avg_ms IS NOT NULL)
   / NULLIF(SUM(success_count) FILTER (WHERE duration_avg_ms IS NOT NULL),0),
 MAX(duration_max_ms),
 ROUND(SUM(ttft_p50_ms::double precision*ttft_sample_count) FILTER (WHERE ttft_p50_ms IS NOT NULL)
   / NULLIF(SUM(ttft_sample_count) FILTER (WHERE ttft_p50_ms IS NOT NULL),0))::int,
 ROUND(SUM(ttft_p90_ms::double precision*ttft_sample_count) FILTER (WHERE ttft_p90_ms IS NOT NULL)
   / NULLIF(SUM(ttft_sample_count) FILTER (WHERE ttft_p90_ms IS NOT NULL),0))::int,
 MAX(ttft_p95_ms),MAX(ttft_p99_ms),
 SUM(ttft_avg_ms*ttft_sample_count) FILTER (WHERE ttft_avg_ms IS NOT NULL)
   / NULLIF(SUM(ttft_sample_count) FILTER (WHERE ttft_avg_ms IS NOT NULL),0),
 MAX(ttft_max_ms),NOW()
FROM ops_metrics_hourly
WHERE bucket_start >= to_timestamp($1) AND bucket_start < to_timestamp($2)
GROUP BY 1,2,3
ON CONFLICT (bucket_date,COALESCE(platform,''),COALESCE(group_id,0)) DO UPDATE SET
 success_count=EXCLUDED.success_count,ttft_sample_count=EXCLUDED.ttft_sample_count,
 error_count_total=EXCLUDED.error_count_total,business_limited_count=EXCLUDED.business_limited_count,
 error_count_sla=EXCLUDED.error_count_sla,
 upstream_error_count_excl_429_529=EXCLUDED.upstream_error_count_excl_429_529,
 upstream_429_count=EXCLUDED.upstream_429_count,upstream_529_count=EXCLUDED.upstream_529_count,
 token_consumed=EXCLUDED.token_consumed,duration_p50_ms=EXCLUDED.duration_p50_ms,
 duration_p90_ms=EXCLUDED.duration_p90_ms,duration_p95_ms=EXCLUDED.duration_p95_ms,
 duration_p99_ms=EXCLUDED.duration_p99_ms,duration_avg_ms=EXCLUDED.duration_avg_ms,
 duration_max_ms=EXCLUDED.duration_max_ms,ttft_p50_ms=EXCLUDED.ttft_p50_ms,
 ttft_p90_ms=EXCLUDED.ttft_p90_ms,ttft_p95_ms=EXCLUDED.ttft_p95_ms,
 ttft_p99_ms=EXCLUDED.ttft_p99_ms,ttft_avg_ms=EXCLUDED.ttft_avg_ms,
 ttft_max_ms=EXCLUDED.ttft_max_ms,computed_at=NOW()
";

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
struct AlertRuntimeSettings {
    evaluation_interval_seconds: u64,
    silencing: AlertSilencingSettings,
}

impl Default for AlertRuntimeSettings {
    fn default() -> Self {
        Self {
            evaluation_interval_seconds: 60,
            silencing: AlertSilencingSettings::default(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct AlertSilencingSettings {
    enabled: bool,
    global_until_rfc3339: String,
    entries: Vec<AlertSilenceEntry>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct AlertSilenceEntry {
    rule_id: Option<i64>,
    severities: Vec<String>,
    until_rfc3339: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct OpsEmailConfig {
    alert: OpsAlertEmailConfig,
    report: OpsReportEmailConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
struct OpsAlertEmailConfig {
    enabled: bool,
    recipients: Vec<String>,
    min_severity: String,
    rate_limit_per_hour: i64,
}

impl Default for OpsAlertEmailConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            recipients: Vec::new(),
            min_severity: String::new(),
            rate_limit_per_hour: 0,
        }
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
struct OpsReportEmailConfig {
    enabled: bool,
    recipients: Vec<String>,
    daily_summary_enabled: bool,
    daily_summary_schedule: String,
    weekly_summary_enabled: bool,
    weekly_summary_schedule: String,
    error_digest_enabled: bool,
    error_digest_schedule: String,
    error_digest_min_count: i64,
    account_health_enabled: bool,
    account_health_schedule: String,
    #[allow(dead_code)]
    account_health_error_rate_threshold: f64,
}

impl Default for OpsReportEmailConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            recipients: Vec::new(),
            daily_summary_enabled: false,
            daily_summary_schedule: "0 9 * * *".to_owned(),
            weekly_summary_enabled: false,
            weekly_summary_schedule: "0 9 * * 1".to_owned(),
            error_digest_enabled: false,
            error_digest_schedule: "0 9 * * *".to_owned(),
            error_digest_min_count: 10,
            account_health_enabled: false,
            account_health_schedule: "0 9 * * *".to_owned(),
            account_health_error_rate_threshold: 10.0,
        }
    }
}

#[derive(Clone, Debug)]
struct AlertRule {
    id: i64,
    name: String,
    severity: String,
    metric_type: String,
    operator: String,
    threshold: f64,
    window_minutes: i32,
    sustained_minutes: i32,
    cooldown_minutes: i32,
    notify_email: bool,
    filters: Value,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct AlertStateStore {
    rules: HashMap<String, AlertBreachState>,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
struct AlertBreachState {
    last_evaluated_epoch: i64,
    consecutive_breaches: u32,
}

#[derive(Clone, Debug)]
struct AlertNotification {
    event_id: i64,
    rule_id: i64,
    rule_name: String,
    severity: String,
    metric_type: String,
    operator: String,
    threshold: f64,
    metric_value: f64,
}

async fn alert_loop(
    pool: PgPool,
    notifier: Arc<PostgresSmtpNotifier>,
    fallback_period: Duration,
    cancellation: CancellationToken,
) {
    let mut delay = Duration::ZERO;
    loop {
        tokio::select! {
            () = cancellation.cancelled() => break,
            () = time::sleep(delay) => {}
        }
        let settings = load_alert_runtime(&pool).await.unwrap_or_default();
        delay = Duration::from_secs(settings.evaluation_interval_seconds.clamp(1, 24 * 60 * 60));
        if delay.is_zero() {
            delay = fallback_period;
        }
        if !monitoring_enabled(&pool).await.unwrap_or(true) {
            continue;
        }
        let started = time::Instant::now();
        match evaluate_alerts_once(&pool, &settings).await {
            Ok(Some((summary, notifications))) => {
                send_alert_notifications(&pool, &notifier, &settings, notifications).await;
                heartbeat_success(&pool, HEARTBEAT_ALERTS, started, &summary).await;
            }
            Ok(None) => {}
            Err(error) => {
                tracing::error!(error = %error, "ops alert evaluation failed");
                heartbeat_error(&pool, HEARTBEAT_ALERTS, started, &error).await;
            }
        }
    }
}

async fn load_alert_runtime(pool: &PgPool) -> Result<AlertRuntimeSettings> {
    load_json_setting(pool, "ops_alert_runtime_settings")
        .await
        .map(Option::unwrap_or_default)
}

async fn load_email_config(pool: &PgPool) -> Result<OpsEmailConfig> {
    load_json_setting(pool, "ops_email_notification_config")
        .await
        .map(Option::unwrap_or_default)
}

async fn load_json_setting<T>(pool: &PgPool, key: &str) -> Result<Option<T>>
where
    T: for<'de> Deserialize<'de>,
{
    let raw = sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key=$1")
        .bind(key)
        .fetch_optional(pool)
        .await
        .with_context(|| format!("load setting {key}"))?;
    raw.filter(|value| !value.trim().is_empty())
        .map(|value| serde_json::from_str(&value).with_context(|| format!("decode setting {key}")))
        .transpose()
}

async fn evaluate_alerts_once(
    pool: &PgPool,
    settings: &AlertRuntimeSettings,
) -> Result<Option<(String, Vec<AlertNotification>)>> {
    let mut transaction = pool.begin().await.context("begin alert evaluation")?;
    if !try_xact_lock(&mut transaction, ALERT_LOCK).await? {
        transaction.rollback().await?;
        return Ok(None);
    }
    let rules = load_alert_rules(&mut transaction).await?;
    let now_epoch = sqlx::query_scalar::<_, i64>("SELECT EXTRACT(EPOCH FROM NOW())::bigint")
        .fetch_one(&mut *transaction)
        .await?;
    let mut states = load_alert_states(&mut transaction).await?;
    let live_ids = rules
        .iter()
        .map(|rule| rule.id.to_string())
        .collect::<HashSet<_>>();
    states.rules.retain(|id, _| live_ids.contains(id));
    let evaluation_seconds =
        i64::try_from(settings.evaluation_interval_seconds).unwrap_or(i64::MAX);
    let mut evaluated = 0_u64;
    let mut created = 0_u64;
    let mut resolved = 0_u64;
    let mut notifications = Vec::new();

    for rule in &rules {
        let scope = AlertScope::from_filters(&rule.filters);
        let value = compute_alert_metric(&mut transaction, rule, &scope).await?;
        let Some(value) = value else {
            states.rules.remove(&rule.id.to_string());
            continue;
        };
        evaluated += 1;
        let breached = compare_metric(value, &rule.operator, rule.threshold);
        let required = required_breaches(rule.sustained_minutes, evaluation_seconds);
        let state = states.rules.entry(rule.id.to_string()).or_default();
        if state.last_evaluated_epoch > 0
            && now_epoch.saturating_sub(state.last_evaluated_epoch)
                > evaluation_seconds.saturating_mul(2)
        {
            state.consecutive_breaches = 0;
        }
        state.last_evaluated_epoch = now_epoch;
        if breached {
            state.consecutive_breaches = state.consecutive_breaches.saturating_add(1);
        } else {
            state.consecutive_breaches = 0;
        }

        let active_id = sqlx::query_scalar::<_, i64>(
            "SELECT id FROM ops_alert_events WHERE rule_id=$1 AND status='firing' ORDER BY fired_at DESC,id DESC LIMIT 1",
        )
        .bind(rule.id)
        .fetch_optional(&mut *transaction)
        .await?;

        if breached && state.consecutive_breaches >= required {
            if active_id.is_some()
                || database_alert_silenced(&mut transaction, rule.id, &scope).await?
                || alert_in_cooldown(&mut transaction, rule).await?
            {
                continue;
            }
            let dimensions = scope.dimensions();
            let description = format!(
                "{} {} {:.2} (current {:.2}) over last {}m ({})",
                rule.metric_type,
                rule.operator,
                rule.threshold,
                value,
                rule.window_minutes.max(1),
                scope.label()
            );
            let event_id = sqlx::query_scalar::<_, i64>(
                r"
INSERT INTO ops_alert_events (
 rule_id,severity,status,title,description,metric_value,threshold_value,dimensions,fired_at,created_at
)
VALUES ($1,$2,'firing',$3,$4,$5,$6,$7,NOW(),NOW()) RETURNING id
",
            )
            .bind(rule.id)
            .bind(&rule.severity)
            .bind(format!("{}: {}", rule.severity, rule.name))
            .bind(description)
            .bind(value)
            .bind(rule.threshold)
            .bind(dimensions)
            .fetch_one(&mut *transaction)
            .await?;
            sqlx::query("UPDATE ops_alert_rules SET last_triggered_at=NOW() WHERE id=$1")
                .bind(rule.id)
                .execute(&mut *transaction)
                .await?;
            created += 1;
            if rule.notify_email {
                notifications.push(AlertNotification {
                    event_id,
                    rule_id: rule.id,
                    rule_name: rule.name.clone(),
                    severity: rule.severity.clone(),
                    metric_type: rule.metric_type.clone(),
                    operator: rule.operator.clone(),
                    threshold: rule.threshold,
                    metric_value: value,
                });
            }
        } else if !breached && let Some(event_id) = active_id {
            sqlx::query(
                "UPDATE ops_alert_events SET status='resolved',resolved_at=NOW() WHERE id=$1 AND status='firing'",
            )
            .bind(event_id)
            .execute(&mut *transaction)
            .await?;
            resolved += 1;
        }
    }
    save_alert_states(&mut transaction, &states).await?;
    transaction
        .commit()
        .await
        .context("commit alert evaluation")?;
    Ok(Some((
        format!(
            "rules={} evaluated={evaluated} created={created} resolved={resolved}",
            rules.len()
        ),
        notifications,
    )))
}

async fn load_alert_rules(transaction: &mut Transaction<'_, Postgres>) -> Result<Vec<AlertRule>> {
    sqlx::query(
        r"
SELECT id,name,COALESCE(severity,'P2') AS severity,metric_type,operator,threshold,
       GREATEST(window_minutes,1) AS window_minutes,
       GREATEST(sustained_minutes,1) AS sustained_minutes,
       GREATEST(cooldown_minutes,0) AS cooldown_minutes,
       COALESCE(notify_email,TRUE) AS notify_email,COALESCE(filters,'{}'::jsonb) AS filters
FROM ops_alert_rules WHERE enabled=TRUE ORDER BY id
",
    )
    .fetch_all(&mut **transaction)
    .await?
    .into_iter()
    .map(|row| {
        Ok(AlertRule {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            severity: row.try_get("severity")?,
            metric_type: row.try_get("metric_type")?,
            operator: row.try_get("operator")?,
            threshold: row.try_get("threshold")?,
            window_minutes: row.try_get("window_minutes")?,
            sustained_minutes: row.try_get("sustained_minutes")?,
            cooldown_minutes: row.try_get("cooldown_minutes")?,
            notify_email: row.try_get("notify_email")?,
            filters: row.try_get("filters")?,
        })
    })
    .collect::<Result<Vec<_>, sqlx::Error>>()
    .context("decode alert rules")
}

async fn load_alert_states(transaction: &mut Transaction<'_, Postgres>) -> Result<AlertStateStore> {
    let raw = sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key=$1 FOR UPDATE")
        .bind(ALERT_STATE_SETTING)
        .fetch_optional(&mut **transaction)
        .await?;
    raw.map_or_else(
        || Ok(AlertStateStore::default()),
        |value| serde_json::from_str(&value).context("decode persisted alert evaluator state"),
    )
}

async fn save_alert_states(
    transaction: &mut Transaction<'_, Postgres>,
    states: &AlertStateStore,
) -> Result<()> {
    let encoded = serde_json::to_string(states).context("encode alert evaluator state")?;
    sqlx::query(
        r"
INSERT INTO settings (key,value,updated_at) VALUES ($1,$2,NOW())
ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value,updated_at=NOW()
",
    )
    .bind(ALERT_STATE_SETTING)
    .bind(encoded)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

#[derive(Clone, Debug, Default)]
struct AlertScope {
    platform: Option<String>,
    group_id: Option<i64>,
    region: Option<String>,
}

impl AlertScope {
    fn from_filters(filters: &Value) -> Self {
        let platform = filters
            .get("platform")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let group_id = filters.get("group_id").and_then(|value| {
            value.as_i64().or_else(|| {
                value
                    .as_str()
                    .and_then(|value| value.trim().parse::<i64>().ok())
            })
        });
        let region = filters
            .get("region")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        Self {
            platform,
            group_id: group_id.filter(|value| *value > 0),
            region,
        }
    }

    fn dimensions(&self) -> Value {
        let mut dimensions = serde_json::Map::new();
        if let Some(platform) = self.platform.as_ref() {
            dimensions.insert("platform".to_owned(), json!(platform));
        }
        if let Some(group_id) = self.group_id {
            dimensions.insert("group_id".to_owned(), json!(group_id));
        }
        Value::Object(dimensions)
    }

    fn label(&self) -> String {
        let mut values = Vec::new();
        if let Some(platform) = self.platform.as_ref() {
            values.push(format!("platform={platform}"));
        }
        if let Some(group_id) = self.group_id {
            values.push(format!("group_id={group_id}"));
        }
        if values.is_empty() {
            "overall".to_owned()
        } else {
            values.join(" ")
        }
    }
}

fn required_breaches(sustained_minutes: i32, interval_seconds: i64) -> u32 {
    let sustained_seconds = i64::from(sustained_minutes.max(1)).saturating_mul(60);
    let interval_seconds = interval_seconds.max(1);
    u32::try_from(
        sustained_seconds
            .saturating_add(interval_seconds - 1)
            .saturating_div(interval_seconds),
    )
    .unwrap_or(u32::MAX)
    .max(1)
}

fn compare_metric(value: f64, operator: &str, threshold: f64) -> bool {
    match operator.trim() {
        ">" => value > threshold,
        ">=" => value >= threshold,
        "<" => value < threshold,
        "<=" => value <= threshold,
        "==" => (value - threshold).abs() < f64::EPSILON,
        "!=" => (value - threshold).abs() >= f64::EPSILON,
        _ => false,
    }
}

async fn alert_in_cooldown(
    transaction: &mut Transaction<'_, Postgres>,
    rule: &AlertRule,
) -> Result<bool> {
    if rule.cooldown_minutes <= 0 {
        return Ok(false);
    }
    sqlx::query_scalar::<_, bool>(
        r"
SELECT EXISTS(
 SELECT 1 FROM ops_alert_events
 WHERE rule_id=$1 AND fired_at > NOW()-make_interval(mins => $2)
)
",
    )
    .bind(rule.id)
    .bind(rule.cooldown_minutes)
    .fetch_one(&mut **transaction)
    .await
    .context("check alert cooldown")
}

async fn database_alert_silenced(
    transaction: &mut Transaction<'_, Postgres>,
    rule_id: i64,
    scope: &AlertScope,
) -> Result<bool> {
    let Some(platform) = scope.platform.as_deref() else {
        return Ok(false);
    };
    sqlx::query_scalar::<_, bool>(
        r"
SELECT EXISTS(
 SELECT 1 FROM ops_alert_silences
 WHERE rule_id=$1 AND platform=$2
   AND group_id IS NOT DISTINCT FROM $3
   AND region IS NOT DISTINCT FROM $4
   AND until>NOW()
)
",
    )
    .bind(rule_id)
    .bind(platform)
    .bind(scope.group_id)
    .bind(scope.region.as_deref())
    .fetch_one(&mut **transaction)
    .await
    .context("check scoped alert silence")
}

async fn compute_alert_metric(
    transaction: &mut Transaction<'_, Postgres>,
    rule: &AlertRule,
    scope: &AlertScope,
) -> Result<Option<f64>> {
    match rule.metric_type.as_str() {
        "cpu_usage_percent" | "memory_usage_percent" | "concurrency_queue_depth" => {
            let column = match rule.metric_type.as_str() {
                "cpu_usage_percent" => "cpu_usage_percent",
                "memory_usage_percent" => "memory_usage_percent",
                _ => "concurrency_queue_depth::double precision",
            };
            let query = format!(
                "SELECT {column} AS value FROM ops_system_metrics WHERE window_minutes=1 ORDER BY created_at DESC,id DESC LIMIT 1"
            );
            return sqlx::query_scalar::<_, Option<f64>>(&query)
                .fetch_optional(&mut **transaction)
                .await
                .map(Option::flatten)
                .context("load latest system metric");
        }
        "proxy_expired_count" => {
            return sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*)::bigint FROM proxies WHERE status='expired' AND deleted_at IS NULL",
            )
            .fetch_one(&mut **transaction)
            .await
            .map(|value| Some(value as f64))
            .context("count expired proxies");
        }
        "proxy_expiring_soon_count" => {
            return sqlx::query_scalar::<_, i64>(
                r"
SELECT COUNT(*)::bigint FROM proxies
WHERE status='active' AND deleted_at IS NULL AND expires_at IS NOT NULL
  AND expires_at>NOW()
  AND expires_at<=NOW()+(GREATEST(COALESCE(expiry_warn_days,0),0)||' days')::interval
",
            )
            .fetch_one(&mut **transaction)
            .await
            .map(|value| Some(value as f64))
            .context("count proxies expiring soon");
        }
        _ => {}
    }

    if matches!(
        rule.metric_type.as_str(),
        "group_available_accounts"
            | "group_available_ratio"
            | "group_rate_limit_ratio"
            | "account_rate_limited_count"
            | "account_error_count"
            | "account_error_ratio"
            | "account_temp_unscheduled_count"
            | "overload_account_count"
    ) {
        return compute_account_metric(transaction, rule, scope).await;
    }

    if matches!(
        rule.metric_type.as_str(),
        "p95_latency_ms" | "p99_latency_ms"
    ) {
        let row = sqlx::query(ALERT_LATENCY_METRICS_SQL)
            .bind(rule.window_minutes.max(1))
            .bind(scope.platform.as_deref())
            .bind(scope.group_id)
            .fetch_one(&mut **transaction)
            .await
            .context("aggregate latency metric for alert")?;
        let column = if rule.metric_type == "p95_latency_ms" {
            "p95_latency_ms"
        } else {
            "p99_latency_ms"
        };
        return row
            .try_get::<Option<f64>, _>(column)
            .context("decode latency metric for alert");
    }

    if matches!(
        rule.metric_type.as_str(),
        "success_rate" | "error_rate" | "upstream_error_rate"
    ) {
        let row = sqlx::query(ALERT_REQUEST_METRICS_SQL)
            .bind(rule.window_minutes.max(1))
            .bind(scope.platform.as_deref())
            .bind(scope.group_id)
            .fetch_one(&mut **transaction)
            .await
            .context("aggregate request metric for alert")?;
        let success: i64 = row.try_get("success_count")?;
        let errors: i64 = row.try_get("error_count_sla")?;
        let upstream: i64 = row.try_get("upstream_errors")?;
        let denominator = success.saturating_add(errors);
        if denominator <= 0 {
            return Ok(None);
        }
        let value = match rule.metric_type.as_str() {
            "success_rate" => success as f64 / denominator as f64 * 100.0,
            "error_rate" => errors as f64 / denominator as f64 * 100.0,
            _ => upstream as f64 / denominator as f64 * 100.0,
        };
        return Ok(Some(value));
    }
    Ok(None)
}

const ALERT_LATENCY_METRICS_SQL: &str = r"
SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY logs.duration_ms)
           FILTER (WHERE logs.duration_ms IS NOT NULL) AS p95_latency_ms,
       percentile_cont(0.99) WITHIN GROUP (ORDER BY logs.duration_ms)
           FILTER (WHERE logs.duration_ms IS NOT NULL) AS p99_latency_ms
FROM usage_logs logs
LEFT JOIN groups ON groups.id=logs.group_id
LEFT JOIN accounts ON accounts.id=logs.account_id
WHERE logs.created_at>=NOW()-make_interval(mins => $1)
  AND ($2::text IS NULL OR
       LOWER(COALESCE(NULLIF(groups.platform,''),accounts.platform))=LOWER($2))
  AND ($3::bigint IS NULL OR logs.group_id=$3)
";

const ALERT_REQUEST_METRICS_SQL: &str = r"
WITH usage_stats AS (
 SELECT COUNT(*)::bigint AS success_count
 FROM usage_logs logs
 JOIN groups ON groups.id=logs.group_id
 WHERE logs.created_at>=NOW()-make_interval(mins => $1)
   AND ($2::text IS NULL OR groups.platform=$2)
   AND ($3::bigint IS NULL OR logs.group_id=$3)
), error_stats AS (
 SELECT COUNT(*) FILTER (WHERE COALESCE(status_code,0)>=400 AND NOT is_business_limited)::bigint AS error_count_sla,
        COUNT(*) FILTER (WHERE error_owner='provider' AND NOT is_business_limited
                          AND COALESCE(upstream_status_code,status_code,0) NOT IN (429,529))::bigint AS upstream_errors
 FROM ops_error_logs
 WHERE created_at>=NOW()-make_interval(mins => $1)
   AND is_count_tokens=FALSE
   AND ($2::text IS NULL OR platform=$2)
   AND ($3::bigint IS NULL OR group_id=$3)
)
SELECT usage_stats.success_count,error_stats.error_count_sla,error_stats.upstream_errors
FROM usage_stats,error_stats
";

async fn compute_account_metric(
    transaction: &mut Transaction<'_, Postgres>,
    rule: &AlertRule,
    scope: &AlertScope,
) -> Result<Option<f64>> {
    if rule.metric_type.starts_with("group_") && scope.group_id.is_none() {
        return Ok(None);
    }
    let row = sqlx::query(
        r"
WITH filtered AS (
 SELECT DISTINCT accounts.id,accounts.status,accounts.schedulable,
        accounts.rate_limit_reset_at,accounts.overload_until,accounts.temp_unschedulable_until
 FROM accounts
 LEFT JOIN account_groups ON account_groups.account_id=accounts.id
 WHERE accounts.deleted_at IS NULL
   AND ($1::text IS NULL OR accounts.platform=$1)
   AND ($2::bigint IS NULL OR account_groups.group_id=$2)
)
SELECT COUNT(*)::bigint AS total,
 COUNT(*) FILTER (WHERE status='active' AND schedulable
   AND (rate_limit_reset_at IS NULL OR rate_limit_reset_at<=NOW())
   AND (overload_until IS NULL OR overload_until<=NOW())
   AND (temp_unschedulable_until IS NULL OR temp_unschedulable_until<=NOW()))::bigint AS available,
 COUNT(*) FILTER (WHERE status<>'error' AND rate_limit_reset_at>NOW())::bigint AS rate_limited,
 COUNT(*) FILTER (WHERE status='error' AND temp_unschedulable_until IS NULL)::bigint AS errors,
 COUNT(*) FILTER (WHERE temp_unschedulable_until>NOW())::bigint AS temp_unscheduled,
 COUNT(*) FILTER (WHERE status<>'error' AND overload_until>NOW())::bigint AS overloaded
FROM filtered
",
    )
    .bind(scope.platform.as_deref())
    .bind(scope.group_id)
    .fetch_one(&mut **transaction)
    .await
    .context("aggregate account availability metric")?;
    let total: i64 = row.try_get("total")?;
    let available: i64 = row.try_get("available")?;
    let rate_limited: i64 = row.try_get("rate_limited")?;
    let errors: i64 = row.try_get("errors")?;
    let temp: i64 = row.try_get("temp_unscheduled")?;
    let overloaded: i64 = row.try_get("overloaded")?;
    let value = match rule.metric_type.as_str() {
        "group_available_accounts" => available as f64,
        "group_available_ratio" => ratio(available, total),
        "group_rate_limit_ratio" => ratio(rate_limited, total),
        "account_rate_limited_count" => rate_limited as f64,
        "account_error_count" => errors as f64,
        "account_error_ratio" => ratio(errors, total),
        "account_temp_unscheduled_count" => temp as f64,
        "overload_account_count" => overloaded as f64,
        _ => return Ok(None),
    };
    Ok(Some(value))
}

fn ratio(numerator: i64, denominator: i64) -> f64 {
    if denominator <= 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64 * 100.0
    }
}

fn runtime_email_silenced(
    settings: &AlertRuntimeSettings,
    notification: &AlertNotification,
) -> bool {
    if !settings.silencing.enabled {
        return false;
    }
    let now = Utc::now();
    if timestamp_in_future(&settings.silencing.global_until_rfc3339, now) {
        return true;
    }
    settings.silencing.entries.iter().any(|entry| {
        timestamp_in_future(&entry.until_rfc3339, now)
            && entry
                .rule_id
                .is_none_or(|rule_id| rule_id == notification.rule_id)
            && (entry.severities.is_empty()
                || entry
                    .severities
                    .iter()
                    .any(|value| value.eq_ignore_ascii_case(&notification.severity)))
    })
}

fn timestamp_in_future(raw: &str, now: DateTime<Utc>) -> bool {
    DateTime::parse_from_rfc3339(raw.trim()).is_ok_and(|value| value.with_timezone(&Utc) > now)
}

async fn send_alert_notifications(
    pool: &PgPool,
    notifier: &PostgresSmtpNotifier,
    settings: &AlertRuntimeSettings,
    _notifications: Vec<AlertNotification>,
) {
    let config = match load_email_config(pool).await {
        Ok(config) if config.alert.enabled => config.alert,
        Ok(_) => return,
        Err(error) => {
            tracing::warn!(error = %error, "failed to load alert email configuration");
            return;
        }
    };
    let recipients = normalize_recipients(&config.recipients);
    if recipients.is_empty() {
        return;
    }
    let notifier = notifier.clone();
    let settings = settings.clone();
    let result = with_session_lock(pool, ALERT_EMAIL_LOCK, move |connection| {
        Box::pin(async move {
            let notifications = load_pending_alert_notifications(connection).await?;
            let mut sent_last_hour = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*)::bigint FROM ops_alert_events WHERE email_sent=TRUE AND fired_at>=NOW()-INTERVAL '1 hour'",
            )
            .fetch_one(&mut *connection)
            .await
            .unwrap_or(0);
            for notification in notifications {
                if runtime_email_silenced(&settings, &notification)
                    || !severity_allowed(&config.min_severity, &notification.severity)
                    || (config.rate_limit_per_hour > 0
                        && sent_last_hour >= config.rate_limit_per_hour)
                {
                    continue;
                }
                let subject = format!(
                    "[Ops Alert][{}] {}",
                    notification.severity, notification.rule_name
                );
                let body = format!(
                    "<h2>{}</h2><p><b>Severity:</b> {}</p><p><b>Metric:</b> {} {} {:.2}</p><p><b>Current:</b> {:.2}</p>",
                    escape_html(&notification.rule_name),
                    escape_html(&notification.severity),
                    escape_html(&notification.metric_type),
                    escape_html(&notification.operator),
                    notification.threshold,
                    notification.metric_value
                );
                let mut all_sent = true;
                for recipient in &recipients {
                    if let Err(error) = notifier.send_html(recipient, &subject, &body).await {
                        all_sent = false;
                        tracing::warn!(event_id = notification.event_id, recipient, error = %error, "ops alert email failed");
                    }
                }
                if all_sent {
                    sqlx::query(
                        "UPDATE ops_alert_events SET email_sent=TRUE WHERE id=$1 AND email_sent=FALSE",
                    )
                    .bind(notification.event_id)
                    .execute(&mut *connection)
                    .await
                    .context("record ops alert email delivery")?;
                    sent_last_hour += 1;
                }
            }
            Ok(())
        })
    })
    .await;
    if let Err(error) = result {
        tracing::warn!(error = %error, "ops alert email retry cycle failed");
    }
}

async fn load_pending_alert_notifications(
    connection: &mut PgConnection,
) -> Result<Vec<AlertNotification>> {
    sqlx::query(PENDING_ALERT_NOTIFICATIONS_SQL)
        .bind(ALERT_EMAIL_BATCH_SIZE)
        .fetch_all(&mut *connection)
        .await?
        .into_iter()
        .map(|row| {
            Ok(AlertNotification {
                event_id: row.try_get("event_id")?,
                rule_id: row.try_get("rule_id")?,
                rule_name: row.try_get("rule_name")?,
                severity: row.try_get("severity")?,
                metric_type: row.try_get("metric_type")?,
                operator: row.try_get("operator")?,
                threshold: row.try_get("threshold")?,
                metric_value: row.try_get("metric_value")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .context("load pending ops alert email deliveries")
}

const PENDING_ALERT_NOTIFICATIONS_SQL: &str = r"
SELECT events.id AS event_id,events.rule_id,rules.name AS rule_name,
       events.severity,rules.metric_type,rules.operator,
       COALESCE(events.threshold_value,rules.threshold,0)::double precision AS threshold,
       COALESCE(events.metric_value,0)::double precision AS metric_value
FROM ops_alert_events events
JOIN ops_alert_rules rules ON rules.id=events.rule_id
WHERE events.status='firing' AND events.email_sent=FALSE
  AND rules.enabled=TRUE AND rules.notify_email=TRUE
ORDER BY events.fired_at,events.id
LIMIT $1
";

fn severity_allowed(minimum: &str, actual: &str) -> bool {
    fn rank(value: &str) -> i32 {
        match value.trim().to_ascii_lowercase().as_str() {
            "critical" | "p0" => 3,
            "warning" | "p1" | "p2" => 2,
            "info" | "p3" => 1,
            _ => 0,
        }
    }
    minimum.trim().is_empty() || rank(actual) >= rank(minimum)
}

fn normalize_recipients(values: &[String]) -> Vec<String> {
    let mut output = Vec::new();
    for value in values {
        let value = value.trim();
        if !value.is_empty()
            && value.contains('@')
            && !value.contains('\r')
            && !value.contains('\n')
            && !output.iter().any(|existing| existing == value)
        {
            output.push(value.to_owned());
        }
    }
    output
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[derive(Clone, Debug)]
struct ScheduledReport {
    kind: &'static str,
    title: &'static str,
    hours: i32,
    minimum_count: i64,
}

async fn report_loop(
    pool: PgPool,
    notifier: Arc<PostgresSmtpNotifier>,
    config: OpsRuntimeConfig,
    cancellation: CancellationToken,
) {
    let mut ticker = interval(config.report_interval);
    while wait_interval(&mut ticker, &cancellation).await {
        if !monitoring_enabled(&pool).await.unwrap_or(true) {
            continue;
        }
        let started = time::Instant::now();
        match claim_due_reports(&pool, &config.timezone).await {
            Ok(Some((email, reports))) => {
                let mut attempts = 0_u64;
                for report in &reports {
                    attempts = attempts.saturating_add(
                        run_scheduled_report(&pool, &notifier, &email, report).await,
                    );
                }
                heartbeat_success(
                    &pool,
                    HEARTBEAT_REPORTS,
                    started,
                    &format!("due={} send_attempts={attempts}", reports.len()),
                )
                .await;
            }
            Ok(None) => {}
            Err(error) => {
                tracing::error!(error = %error, "scheduled ops reports failed");
                heartbeat_error(&pool, HEARTBEAT_REPORTS, started, &error).await;
            }
        }
    }
}

async fn claim_due_reports(
    pool: &PgPool,
    timezone: &str,
) -> Result<Option<(OpsEmailConfig, Vec<ScheduledReport>)>> {
    let email = load_email_config(pool).await?;
    if !email.report.enabled {
        return Ok(Some((email, Vec::new())));
    }
    let definitions = [
        (
            email.report.daily_summary_enabled,
            "daily_summary",
            "Daily summary",
            24,
            &email.report.daily_summary_schedule,
            0,
        ),
        (
            email.report.weekly_summary_enabled,
            "weekly_summary",
            "Weekly summary",
            7 * 24,
            &email.report.weekly_summary_schedule,
            0,
        ),
        (
            email.report.error_digest_enabled,
            "error_digest",
            "Error digest",
            24,
            &email.report.error_digest_schedule,
            email.report.error_digest_min_count.max(0),
        ),
        (
            email.report.account_health_enabled,
            "account_health",
            "Account health",
            24,
            &email.report.account_health_schedule,
            0,
        ),
    ];
    let mut transaction = pool.begin().await.context("begin scheduled report claim")?;
    if !try_xact_lock(&mut transaction, REPORT_LOCK).await? {
        transaction.rollback().await?;
        return Ok(None);
    }
    let mut reports = Vec::new();
    for (enabled, kind, title, hours, schedule, minimum_count) in definitions {
        if !enabled {
            continue;
        }
        let schedule = match CronSchedule::parse(schedule) {
            Ok(schedule) => schedule,
            Err(error) => {
                tracing::warn!(kind, error = %error, "invalid scheduled report cron expression");
                continue;
            }
        };
        let job_name = format!("ops_report:{kind}");
        if !claim_report_if_due(&mut transaction, timezone, &job_name, &schedule).await? {
            continue;
        }
        reports.push(ScheduledReport {
            kind,
            title,
            hours,
            minimum_count,
        });
    }
    transaction.commit().await.context("commit report claims")?;
    Ok(Some((email, reports)))
}

async fn claim_report_if_due(
    transaction: &mut Transaction<'_, Postgres>,
    timezone: &str,
    job_name: &str,
    schedule: &CronSchedule,
) -> Result<bool> {
    let row = sqlx::query(
        r"
WITH moments AS (
 SELECT timezone($1,NOW()) AS local_now,
        (SELECT timezone($1,last_run_at)
         FROM ops_job_heartbeats WHERE job_name=$2) AS local_last
)
SELECT EXTRACT(YEAR FROM local_now)::int AS now_year,
       EXTRACT(MONTH FROM local_now)::int AS now_month,
       EXTRACT(DAY FROM local_now)::int AS now_day,
       EXTRACT(HOUR FROM local_now)::int AS now_hour,
       EXTRACT(MINUTE FROM local_now)::int AS now_minute,
       local_last IS NOT NULL AS has_last,
       COALESCE(EXTRACT(YEAR FROM local_last),0)::int AS last_year,
       COALESCE(EXTRACT(MONTH FROM local_last),0)::int AS last_month,
       COALESCE(EXTRACT(DAY FROM local_last),0)::int AS last_day,
       COALESCE(EXTRACT(HOUR FROM local_last),0)::int AS last_hour,
       COALESCE(EXTRACT(MINUTE FROM local_last),0)::int AS last_minute
FROM moments
",
    )
    .bind(timezone)
    .bind(job_name)
    .fetch_one(&mut **transaction)
    .await
    .with_context(|| format!("load scheduled report progress for {job_name}"))?;
    let now = decode_cron_minute(&row, "now")?;
    let last = if row.try_get::<bool, _>("has_last")? {
        Some(decode_cron_minute(&row, "last")?)
    } else {
        None
    };
    if !schedule.is_due(last, now) {
        return Ok(false);
    }
    sqlx::query(
        r"
INSERT INTO ops_job_heartbeats (job_name,last_run_at,updated_at)
VALUES ($1,NOW(),NOW())
ON CONFLICT (job_name) DO UPDATE SET last_run_at=NOW(),updated_at=NOW()
",
    )
    .bind(job_name)
    .execute(&mut **transaction)
    .await
    .with_context(|| format!("claim scheduled report {job_name}"))?;
    Ok(true)
}

fn decode_cron_minute(row: &sqlx::postgres::PgRow, prefix: &str) -> Result<NaiveDateTime> {
    let column = |suffix: &str| format!("{prefix}_{suffix}");
    let year = row.try_get::<i32, _>(column("year").as_str())?;
    let month = u32::try_from(row.try_get::<i32, _>(column("month").as_str())?)?;
    let day = u32::try_from(row.try_get::<i32, _>(column("day").as_str())?)?;
    let hour = u32::try_from(row.try_get::<i32, _>(column("hour").as_str())?)?;
    let minute = u32::try_from(row.try_get::<i32, _>(column("minute").as_str())?)?;
    NaiveDate::from_ymd_opt(year, month, day)
        .and_then(|date| date.and_hms_opt(hour, minute, 0))
        .ok_or_else(|| {
            anyhow!("invalid local cron minute {year:04}-{month:02}-{day:02} {hour:02}:{minute:02}")
        })
}

async fn run_scheduled_report(
    pool: &PgPool,
    notifier: &PostgresSmtpNotifier,
    email: &OpsEmailConfig,
    report: &ScheduledReport,
) -> u64 {
    let body = match build_report_html(pool, report).await {
        Ok(Some(body)) => body,
        Ok(None) => {
            heartbeat_success(
                pool,
                &format!("ops_report:{}", report.kind),
                time::Instant::now(),
                "suppressed by report threshold",
            )
            .await;
            return 0;
        }
        Err(error) => {
            heartbeat_error(
                pool,
                &format!("ops_report:{}", report.kind),
                time::Instant::now(),
                &error,
            )
            .await;
            return 0;
        }
    };
    let mut recipients = normalize_recipients(&email.report.recipients);
    if recipients.is_empty()
        && let Ok(Some(admin)) = sqlx::query_scalar::<_, String>(
            "SELECT email FROM users WHERE role='admin' AND deleted_at IS NULL ORDER BY id LIMIT 1",
        )
        .fetch_optional(pool)
        .await
    {
        recipients = normalize_recipients(&[admin]);
    }
    let subject = format!("[Ops Report] {}", report.title);
    let mut attempts = 0_u64;
    let mut failures = 0_u64;
    for recipient in recipients {
        attempts += 1;
        if let Err(error) = notifier.send_html(&recipient, &subject, &body).await {
            failures += 1;
            tracing::warn!(kind = report.kind, recipient, error = %error, "scheduled report delivery failed");
        }
    }
    let job = format!("ops_report:{}", report.kind);
    if failures == 0 {
        heartbeat_success(
            pool,
            &job,
            time::Instant::now(),
            &format!("send_attempts={attempts}"),
        )
        .await;
    } else {
        heartbeat_error(
            pool,
            &job,
            time::Instant::now(),
            &anyhow!("{failures} of {attempts} report deliveries failed"),
        )
        .await;
    }
    attempts
}

async fn build_report_html(pool: &PgPool, report: &ScheduledReport) -> Result<Option<String>> {
    match report.kind {
        "daily_summary" | "weekly_summary" => {
            let row = sqlx::query(
                r"
WITH usage_stats AS (
 SELECT COUNT(*)::bigint AS successes,
        COALESCE(SUM(input_tokens+output_tokens+cache_creation_tokens+cache_read_tokens),0)::bigint AS tokens,
        percentile_cont(0.50) WITHIN GROUP (ORDER BY duration_ms) FILTER (WHERE duration_ms IS NOT NULL)::int AS p50,
        percentile_cont(0.99) WITHIN GROUP (ORDER BY duration_ms) FILTER (WHERE duration_ms IS NOT NULL)::int AS p99
 FROM usage_logs WHERE created_at>=NOW()-make_interval(hours => $1)
), error_stats AS (
 SELECT COUNT(*) FILTER (WHERE COALESCE(status_code,0)>=400)::bigint AS errors,
        COUNT(*) FILTER (WHERE COALESCE(status_code,0)>=400 AND NOT is_business_limited)::bigint AS sla_errors,
        COUNT(*) FILTER (WHERE COALESCE(status_code,0)>=400 AND is_business_limited)::bigint AS limited
 FROM ops_error_logs WHERE created_at>=NOW()-make_interval(hours => $1) AND is_count_tokens=FALSE
)
SELECT usage_stats.successes,usage_stats.tokens,usage_stats.p50,usage_stats.p99,
       error_stats.errors,error_stats.sla_errors,error_stats.limited
FROM usage_stats,error_stats
",
            )
            .bind(report.hours)
            .fetch_one(pool)
            .await?;
            let successes: i64 = row.try_get("successes")?;
            let sla_errors: i64 = row.try_get("sla_errors")?;
            let denominator = successes.saturating_add(sla_errors);
            let sla = if denominator > 0 {
                successes as f64 / denominator as f64 * 100.0
            } else {
                0.0
            };
            Ok(Some(format!(
                "<h2>{}</h2><p><b>Window:</b> last {} hours</p><ul><li>Success: {}</li><li>Errors: {}</li><li>Business limited: {}</li><li>SLA: {:.2}%</li><li>Tokens: {}</li><li>Latency p50: {} ms</li><li>Latency p99: {} ms</li></ul>",
                escape_html(report.title),
                report.hours,
                successes,
                row.try_get::<i64, _>("errors")?,
                row.try_get::<i64, _>("limited")?,
                sla,
                row.try_get::<i64, _>("tokens")?,
                row.try_get::<Option<i32>, _>("p50")?
                    .map_or_else(|| "-".to_owned(), |value| value.to_string()),
                row.try_get::<Option<i32>, _>("p99")?
                    .map_or_else(|| "-".to_owned(), |value| value.to_string()),
            )))
        }
        "error_digest" => {
            let total = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*)::bigint FROM ops_error_logs WHERE created_at>=NOW()-make_interval(hours => $1) AND is_count_tokens=FALSE",
            )
            .bind(report.hours)
            .fetch_one(pool)
            .await?;
            if total < report.minimum_count {
                return Ok(None);
            }
            let rows = sqlx::query(
                r"
SELECT to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS') AS at,
       COALESCE(platform,'') AS platform,COALESCE(status_code,0) AS status_code,
       LEFT(COALESCE(error_message,''),180) AS message
FROM ops_error_logs
WHERE created_at>=NOW()-make_interval(hours => $1) AND is_count_tokens=FALSE
ORDER BY created_at DESC,id DESC LIMIT 10
",
            )
            .bind(report.hours)
            .fetch_all(pool)
            .await?;
            let mut items = String::new();
            for row in rows {
                write!(
                    &mut items,
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    escape_html(&row.try_get::<String, _>("at")?),
                    escape_html(&row.try_get::<String, _>("platform")?),
                    row.try_get::<i32, _>("status_code")?,
                    escape_html(&row.try_get::<String, _>("message")?),
                )
                .expect("writing an HTML row to a String cannot fail");
            }
            Ok(Some(format!(
                "<h2>Error digest</h2><p>Total errors: {total}</p><table><thead><tr><th>Time</th><th>Platform</th><th>Status</th><th>Message</th></tr></thead><tbody>{items}</tbody></table>"
            )))
        }
        "account_health" => {
            let row = sqlx::query(
                r"
SELECT COUNT(*)::bigint AS total,
 COUNT(*) FILTER (WHERE status='active' AND schedulable
   AND (rate_limit_reset_at IS NULL OR rate_limit_reset_at<=NOW())
   AND (overload_until IS NULL OR overload_until<=NOW())
   AND (temp_unschedulable_until IS NULL OR temp_unschedulable_until<=NOW()))::bigint AS available,
 COUNT(*) FILTER (WHERE rate_limit_reset_at>NOW())::bigint AS rate_limited,
 COUNT(*) FILTER (WHERE status='error')::bigint AS errors
FROM accounts WHERE deleted_at IS NULL
",
            )
            .fetch_one(pool)
            .await?;
            Ok(Some(format!(
                "<h2>Account health</h2><ul><li>Total: {}</li><li>Available: {}</li><li>Rate limited: {}</li><li>Error: {}</li></ul>",
                row.try_get::<i64, _>("total")?,
                row.try_get::<i64, _>("available")?,
                row.try_get::<i64, _>("rate_limited")?,
                row.try_get::<i64, _>("errors")?,
            )))
        }
        _ => Ok(None),
    }
}

#[derive(Clone, Copy, Debug)]
struct CronDate {
    minute: u32,
    hour: u32,
    day: u32,
    month: u32,
    weekday: u32,
}

impl CronDate {
    fn from_naive(value: NaiveDateTime) -> Self {
        Self {
            minute: value.minute(),
            hour: value.hour(),
            day: value.day(),
            month: value.month(),
            weekday: value.weekday().num_days_from_sunday(),
        }
    }
}

#[derive(Clone, Debug)]
struct CronSchedule {
    minutes: CronField,
    hours: CronField,
    days: CronField,
    months: CronField,
    weekdays: CronField,
}

impl CronSchedule {
    fn parse(expression: &str) -> Result<Self> {
        let fields = expression.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 5 {
            return Err(anyhow!("cron expression must contain five fields"));
        }
        Ok(Self {
            minutes: CronField::parse(fields[0], 0, 59, &[], false)?,
            hours: CronField::parse(fields[1], 0, 23, &[], false)?,
            days: CronField::parse(fields[2], 1, 31, &[], false)?,
            months: CronField::parse(
                fields[3],
                1,
                12,
                &[
                    ("JAN", 1),
                    ("FEB", 2),
                    ("MAR", 3),
                    ("APR", 4),
                    ("MAY", 5),
                    ("JUN", 6),
                    ("JUL", 7),
                    ("AUG", 8),
                    ("SEP", 9),
                    ("OCT", 10),
                    ("NOV", 11),
                    ("DEC", 12),
                ],
                false,
            )?,
            weekdays: CronField::parse(
                fields[4],
                0,
                7,
                &[
                    ("SUN", 0),
                    ("MON", 1),
                    ("TUE", 2),
                    ("WED", 3),
                    ("THU", 4),
                    ("FRI", 5),
                    ("SAT", 6),
                ],
                true,
            )?,
        })
    }

    fn matches(&self, date: CronDate) -> bool {
        if !self.minutes.contains(date.minute)
            || !self.hours.contains(date.hour)
            || !self.months.contains(date.month)
        {
            return false;
        }
        let day = self.days.contains(date.day);
        let weekday = self.weekdays.contains(date.weekday);
        if self.days.wildcard || self.weekdays.wildcard {
            day && weekday
        } else {
            day || weekday
        }
    }

    fn is_due(&self, last_run: Option<NaiveDateTime>, now: NaiveDateTime) -> bool {
        let Some(last_run) = last_run else {
            return self.matches(CronDate::from_naive(now));
        };
        if last_run >= now {
            return false;
        }
        let oldest_relevant = now
            .date()
            .checked_sub_days(Days::new(CRON_CATCHUP_DAYS))
            .unwrap_or(NaiveDate::MIN);
        let mut date = last_run.date().max(oldest_relevant);
        while date <= now.date() {
            for hour in 0..=23 {
                if !self.hours.contains(hour) {
                    continue;
                }
                for minute in 0..=59 {
                    if !self.minutes.contains(minute) {
                        continue;
                    }
                    let Some(candidate) = date.and_hms_opt(hour, minute, 0) else {
                        continue;
                    };
                    if candidate > last_run
                        && candidate <= now
                        && self.matches(CronDate::from_naive(candidate))
                    {
                        return true;
                    }
                }
            }
            let Some(next) = date.succ_opt() else {
                break;
            };
            date = next;
        }
        false
    }
}

#[derive(Clone, Debug)]
struct CronField {
    allowed: Vec<bool>,
    wildcard: bool,
}

impl CronField {
    fn parse(
        raw: &str,
        min: u32,
        max: u32,
        names: &[(&str, u32)],
        normalize_sunday: bool,
    ) -> Result<Self> {
        let raw = raw.trim().to_ascii_uppercase();
        if raw.is_empty() {
            return Err(anyhow!("cron field is empty"));
        }
        let wildcard = raw == "?" || raw.starts_with('*');
        let raw = if raw == "?" { "*" } else { raw.as_str() };
        let canonical_max = if normalize_sunday { 6 } else { max };
        let mut allowed = vec![false; usize::try_from(canonical_max + 1)?];
        for item in raw.split(',') {
            let (base, step) = item.split_once('/').map_or((item, 1), |(base, step)| {
                (base, step.parse::<u32>().unwrap_or(0))
            });
            if step == 0 {
                return Err(anyhow!("cron field step must be greater than zero"));
            }
            let (start, end) = if base == "*" {
                (min, max)
            } else if let Some((start, end)) = base.split_once('-') {
                (
                    parse_cron_value(start, min, max, names)?,
                    parse_cron_value(end, min, max, names)?,
                )
            } else {
                let start = parse_cron_value(base, min, max, names)?;
                (start, if item.contains('/') { max } else { start })
            };
            if start > end {
                return Err(anyhow!("cron field ranges must be ascending"));
            }
            for value in (start..=end).step_by(usize::try_from(step)?) {
                let canonical = if normalize_sunday && value == 7 {
                    0
                } else {
                    value
                };
                allowed[usize::try_from(canonical)?] = true;
            }
        }
        if !allowed.iter().any(|value| *value) {
            return Err(anyhow!("cron field selects no values"));
        }
        Ok(Self { allowed, wildcard })
    }

    fn contains(&self, value: u32) -> bool {
        self.allowed
            .get(usize::try_from(value).unwrap_or(usize::MAX))
            .copied()
            .unwrap_or(false)
    }
}

fn parse_cron_value(raw: &str, min: u32, max: u32, names: &[(&str, u32)]) -> Result<u32> {
    let value = names
        .iter()
        .find_map(|(name, value)| raw.eq_ignore_ascii_case(name).then_some(*value))
        .map_or_else(|| raw.parse::<u32>().map_err(anyhow::Error::from), Ok)?;
    if !(min..=max).contains(&value) {
        return Err(anyhow!("cron value {value} is outside [{min},{max}]"));
    }
    Ok(value)
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct OpsAdvancedSettings {
    data_retention: OpsDataRetention,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
struct OpsDataRetention {
    cleanup_enabled: bool,
    cleanup_schedule: String,
    error_log_retention_days: i64,
    minute_metrics_retention_days: i64,
    hourly_metrics_retention_days: i64,
}

impl Default for OpsDataRetention {
    fn default() -> Self {
        Self {
            cleanup_enabled: true,
            cleanup_schedule: "0 2 * * *".to_owned(),
            error_log_retention_days: 30,
            minute_metrics_retention_days: 30,
            hourly_metrics_retention_days: 30,
        }
    }
}

async fn cleanup_loop(pool: PgPool, config: OpsRuntimeConfig, cancellation: CancellationToken) {
    let mut ticker = interval(config.cleanup_poll_interval);
    while wait_interval(&mut ticker, &cancellation).await {
        let started = time::Instant::now();
        match cleanup_once(&pool, &config, &cancellation).await {
            Ok(Some(result)) => {
                heartbeat_success(&pool, HEARTBEAT_CLEANUP, started, &result).await;
            }
            Ok(None) => {}
            Err(error) => {
                tracing::error!(error = %error, "ops retention cleanup failed");
                heartbeat_error(&pool, HEARTBEAT_CLEANUP, started, &error).await;
            }
        }
    }
}

async fn cleanup_once(
    pool: &PgPool,
    config: &OpsRuntimeConfig,
    cancellation: &CancellationToken,
) -> Result<Option<String>> {
    let config = config.clone();
    let cancellation = cancellation.clone();
    with_session_lock(pool, CLEANUP_LOCK, move |connection| {
        Box::pin(async move {
            let settings = load_advanced_settings_connection(connection).await?;
            if !settings.data_retention.cleanup_enabled {
                return Ok(None);
            }
            let schedule = CronSchedule::parse(&settings.data_retention.cleanup_schedule)
                .context("parse ops cleanup schedule")?;
            let date = postgres_cron_date_connection(connection, &config.timezone).await?;
            if !schedule.matches(date) || !claim_job_minute(connection, HEARTBEAT_CLEANUP).await? {
                return Ok(None);
            }
            let retention = settings.data_retention;
            let mut counts = Vec::new();
            for target in [
                CleanupTarget::timestamp(
                    "ops_error_logs",
                    "created_at",
                    retention.error_log_retention_days,
                ),
                CleanupTarget::timestamp(
                    "ops_alert_events",
                    "created_at",
                    retention.error_log_retention_days,
                ),
                CleanupTarget::timestamp(
                    "ops_system_logs",
                    "created_at",
                    retention.error_log_retention_days,
                ),
                CleanupTarget::timestamp(
                    "ops_system_log_cleanup_audits",
                    "created_at",
                    retention.error_log_retention_days,
                ),
                CleanupTarget::timestamp(
                    "ops_system_metrics",
                    "created_at",
                    retention.minute_metrics_retention_days,
                ),
                CleanupTarget::timestamp(
                    "ops_metrics_hourly",
                    "bucket_start",
                    retention.hourly_metrics_retention_days,
                ),
                CleanupTarget::date(
                    "ops_metrics_daily",
                    "bucket_date",
                    retention.hourly_metrics_retention_days,
                ),
                CleanupTarget::timestamp(
                    "usage_dashboard_hourly",
                    "bucket_start",
                    config.dashboard_hourly_retention_days,
                ),
                CleanupTarget::timestamp(
                    "usage_dashboard_hourly_users",
                    "bucket_start",
                    config.dashboard_hourly_retention_days,
                ),
                CleanupTarget::date(
                    "usage_dashboard_daily",
                    "bucket_date",
                    config.dashboard_daily_retention_days,
                ),
                CleanupTarget::date(
                    "usage_dashboard_daily_users",
                    "bucket_date",
                    config.dashboard_daily_retention_days,
                ),
            ] {
                let deleted = cleanup_target(connection, &target, &cancellation).await?;
                counts.push(format!("{}={deleted}", target.table));
                if cancellation.is_cancelled() {
                    break;
                }
            }
            if !cancellation.is_cancelled() {
                let usage =
                    cleanup_usage_logs(connection, config.usage_logs_retention_days, &cancellation)
                        .await?;
                counts.push(format!("usage_logs={usage}"));
            }
            if !cancellation.is_cancelled() {
                let dedup = archive_billing_dedup(
                    connection,
                    config.billing_dedup_retention_days,
                    &cancellation,
                )
                .await?;
                counts.push(format!("usage_billing_dedup={dedup}"));
            }
            Ok(Some(counts.join(" ")))
        })
    })
    .await
    .map(Option::flatten)
}

async fn load_advanced_settings_connection(
    connection: &mut PgConnection,
) -> Result<OpsAdvancedSettings> {
    let raw = sqlx::query_scalar::<_, String>(
        "SELECT value FROM settings WHERE key='ops_advanced_settings'",
    )
    .fetch_optional(&mut *connection)
    .await?;
    raw.filter(|value| !value.trim().is_empty()).map_or_else(
        || Ok(OpsAdvancedSettings::default()),
        |value| serde_json::from_str(&value).context("decode ops advanced settings"),
    )
}

#[derive(Clone, Copy)]
struct CleanupTarget {
    table: &'static str,
    column: &'static str,
    days: i64,
    date_column: bool,
}

impl CleanupTarget {
    const fn timestamp(table: &'static str, column: &'static str, days: i64) -> Self {
        Self {
            table,
            column,
            days,
            date_column: false,
        }
    }

    const fn date(table: &'static str, column: &'static str, days: i64) -> Self {
        Self {
            table,
            column,
            days,
            date_column: true,
        }
    }
}

async fn cleanup_target(
    connection: &mut PgConnection,
    target: &CleanupTarget,
    cancellation: &CancellationToken,
) -> Result<u64> {
    if target.days < 0 {
        return Ok(0);
    }
    if target.days == 0 {
        let count_query = format!("SELECT COUNT(*)::bigint FROM {}", target.table);
        let count = sqlx::query_scalar::<_, i64>(&count_query)
            .fetch_one(&mut *connection)
            .await?;
        let truncate_query = format!("TRUNCATE TABLE {}", target.table);
        sqlx::query(&truncate_query)
            .execute(&mut *connection)
            .await?;
        return Ok(u64::try_from(count).unwrap_or(0));
    }
    let comparison = if target.date_column {
        format!(
            "{} < (CURRENT_DATE - make_interval(days => $1::int))::date",
            target.column
        )
    } else {
        format!("{} < NOW() - make_interval(days => $1::int)", target.column)
    };
    let query = format!(
        "WITH batch AS (SELECT ctid FROM {} WHERE {} LIMIT $2) DELETE FROM {} WHERE ctid IN (SELECT ctid FROM batch)",
        target.table, comparison, target.table
    );
    let mut total = 0_u64;
    loop {
        if cancellation.is_cancelled() {
            break;
        }
        let affected = sqlx::query(&query)
            .bind(i32::try_from(target.days).unwrap_or(i32::MAX))
            .bind(CLEANUP_BATCH_SIZE)
            .execute(&mut *connection)
            .await?
            .rows_affected();
        total = total.saturating_add(affected);
        if affected < u64::try_from(CLEANUP_BATCH_SIZE).unwrap_or(u64::MAX) {
            break;
        }
    }
    Ok(total)
}

async fn cleanup_usage_logs(
    connection: &mut PgConnection,
    days: i64,
    cancellation: &CancellationToken,
) -> Result<u64> {
    let partitioned = sqlx::query_scalar::<_, bool>(
        r"
SELECT EXISTS(
 SELECT 1 FROM pg_partitioned_table partitioned
 JOIN pg_class class ON class.oid=partitioned.partrelid
 WHERE class.relname='usage_logs'
)
",
    )
    .fetch_one(&mut *connection)
    .await?;
    if partitioned {
        // Dropping partitions needs a deployment-specific partition naming and
        // retention policy. Keep rows rather than issuing unsafe dynamic DDL.
        tracing::warn!(
            "usage_logs is partitioned; row cleanup is intentionally deferred to partition lifecycle management"
        );
        return Ok(0);
    }
    let mut total = 0_u64;
    loop {
        if cancellation.is_cancelled() {
            break;
        }
        let affected = sqlx::query(
            r"
WITH batch AS (
 SELECT ctid FROM usage_logs
 WHERE created_at<NOW()-make_interval(days => $1::int)
 LIMIT $2
)
DELETE FROM usage_logs WHERE ctid IN (SELECT ctid FROM batch)
",
        )
        .bind(i32::try_from(days).unwrap_or(i32::MAX))
        .bind(USAGE_CLEANUP_BATCH_SIZE)
        .execute(&mut *connection)
        .await?
        .rows_affected();
        total = total.saturating_add(affected);
        if affected < u64::try_from(USAGE_CLEANUP_BATCH_SIZE).unwrap_or(u64::MAX) {
            break;
        }
    }
    Ok(total)
}

async fn archive_billing_dedup(
    connection: &mut PgConnection,
    days: i64,
    cancellation: &CancellationToken,
) -> Result<u64> {
    let mut total = 0_u64;
    loop {
        if cancellation.is_cancelled() {
            break;
        }
        let affected = sqlx::query(
            r"
WITH batch AS (
 SELECT ctid,request_id,api_key_id,request_fingerprint,created_at
 FROM usage_billing_dedup
 WHERE created_at<NOW()-make_interval(days => $1::int)
 LIMIT $2
), archived AS (
 INSERT INTO usage_billing_dedup_archive (request_id,api_key_id,request_fingerprint,created_at)
 SELECT request_id,api_key_id,request_fingerprint,created_at FROM batch
 ON CONFLICT (request_id,api_key_id) DO NOTHING
)
DELETE FROM usage_billing_dedup WHERE ctid IN (SELECT ctid FROM batch)
",
        )
        .bind(i32::try_from(days).unwrap_or(i32::MAX))
        .bind(USAGE_CLEANUP_BATCH_SIZE)
        .execute(&mut *connection)
        .await?
        .rows_affected();
        total = total.saturating_add(affected);
        if affected < u64::try_from(USAGE_CLEANUP_BATCH_SIZE).unwrap_or(u64::MAX) {
            break;
        }
    }
    Ok(total)
}

async fn postgres_cron_date_connection(
    connection: &mut PgConnection,
    timezone: &str,
) -> Result<CronDate> {
    let row = sqlx::query(
        r"
SELECT EXTRACT(MINUTE FROM timezone($1,NOW()))::int AS minute,
       EXTRACT(HOUR FROM timezone($1,NOW()))::int AS hour,
       EXTRACT(DAY FROM timezone($1,NOW()))::int AS day,
       EXTRACT(MONTH FROM timezone($1,NOW()))::int AS month,
       EXTRACT(DOW FROM timezone($1,NOW()))::int AS weekday
",
    )
    .bind(timezone)
    .fetch_one(&mut *connection)
    .await?;
    Ok(CronDate {
        minute: u32::try_from(row.try_get::<i32, _>("minute")?)?,
        hour: u32::try_from(row.try_get::<i32, _>("hour")?)?,
        day: u32::try_from(row.try_get::<i32, _>("day")?)?,
        month: u32::try_from(row.try_get::<i32, _>("month")?)?,
        weekday: u32::try_from(row.try_get::<i32, _>("weekday")?)?,
    })
}

async fn claim_job_minute(connection: &mut PgConnection, job: &str) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, String>(
        r"
INSERT INTO ops_job_heartbeats (job_name,last_run_at,updated_at)
VALUES ($1,NOW(),NOW())
ON CONFLICT (job_name) DO UPDATE SET last_run_at=NOW(),updated_at=NOW()
WHERE ops_job_heartbeats.last_run_at IS NULL
   OR ops_job_heartbeats.last_run_at<date_trunc('minute',NOW())
RETURNING job_name
",
    )
    .bind(job)
    .fetch_optional(&mut *connection)
    .await?
    .is_some())
}

async fn moderation_cleanup_loop(pool: PgPool, period: Duration, cancellation: CancellationToken) {
    let mut ticker = interval(period);
    while wait_interval(&mut ticker, &cancellation).await {
        let started = time::Instant::now();
        match cleanup_moderation_once(&pool, &cancellation).await {
            Ok(Some((hits, non_hits))) => {
                heartbeat_success(
                    &pool,
                    HEARTBEAT_MODERATION,
                    started,
                    &format!("flagged={hits} non_flagged={non_hits}"),
                )
                .await;
            }
            Ok(None) => {}
            Err(error) => {
                tracing::error!(error = %error, "content moderation retention cleanup failed");
                heartbeat_error(&pool, HEARTBEAT_MODERATION, started, &error).await;
            }
        }
    }
}

async fn cleanup_moderation_once(
    pool: &PgPool,
    cancellation: &CancellationToken,
) -> Result<Option<(u64, u64)>> {
    let cancellation = cancellation.clone();
    with_session_lock(pool, MODERATION_CLEANUP_LOCK, move |connection| {
        Box::pin(async move {
            let config = sqlx::query_scalar::<_, String>(
                "SELECT value FROM settings WHERE key='content_moderation_config'",
            )
            .fetch_optional(&mut *connection)
            .await?
            .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
            .unwrap_or_else(|| json!({}));
            let hit_days = config
                .get("hit_retention_days")
                .and_then(Value::as_i64)
                .unwrap_or(180)
                .clamp(1, 3_650);
            let non_hit_days = config
                .get("non_hit_retention_days")
                .and_then(Value::as_i64)
                .unwrap_or(3)
                .clamp(1, 3);
            let hits = delete_moderation_batches(connection, true, hit_days, &cancellation).await?;
            let non_hits =
                delete_moderation_batches(connection, false, non_hit_days, &cancellation).await?;
            Ok((hits, non_hits))
        })
    })
    .await
}

async fn delete_moderation_batches(
    connection: &mut PgConnection,
    flagged: bool,
    days: i64,
    cancellation: &CancellationToken,
) -> Result<u64> {
    let mut total = 0_u64;
    loop {
        if cancellation.is_cancelled() {
            break;
        }
        let affected = sqlx::query(
            r"
WITH batch AS (
 SELECT id FROM content_moderation_logs
 WHERE flagged=$1 AND created_at<NOW()-make_interval(days => $2::int)
 ORDER BY id LIMIT $3
)
DELETE FROM content_moderation_logs WHERE id IN (SELECT id FROM batch)
",
        )
        .bind(flagged)
        .bind(i32::try_from(days).unwrap_or(i32::MAX))
        .bind(CLEANUP_BATCH_SIZE)
        .execute(&mut *connection)
        .await?
        .rows_affected();
        total = total.saturating_add(affected);
        if affected < u64::try_from(CLEANUP_BATCH_SIZE).unwrap_or(u64::MAX) {
            break;
        }
    }
    Ok(total)
}

async fn channel_rollup_loop(
    pool: PgPool,
    config: OpsRuntimeConfig,
    cancellation: CancellationToken,
) {
    let mut ticker = interval(config.channel_rollup_interval);
    while wait_interval(&mut ticker, &cancellation).await {
        let started = time::Instant::now();
        match channel_rollup_once(&pool, &config, &cancellation).await {
            Ok(Some((days, rows, histories_deleted, rollups_deleted))) => {
                heartbeat_success(
                    &pool,
                    HEARTBEAT_CHANNELS,
                    started,
                    &format!(
                        "days={days} rows={rows} histories_deleted={histories_deleted} rollups_deleted={rollups_deleted}"
                    ),
                )
                .await;
            }
            Ok(None) => {}
            Err(error) => {
                tracing::error!(error = %error, "channel monitor rollup failed");
                heartbeat_error(&pool, HEARTBEAT_CHANNELS, started, &error).await;
            }
        }
    }
}

async fn channel_rollup_once(
    pool: &PgPool,
    config: &OpsRuntimeConfig,
    cancellation: &CancellationToken,
) -> Result<Option<(u64, u64, u64, u64)>> {
    let config = config.clone();
    let cancellation = cancellation.clone();
    with_session_lock(pool, CHANNEL_ROLLUP_LOCK, move |connection| {
        Box::pin(async move {
            let dates = sqlx::query_scalar::<_, String>(
                r"
WITH start_date AS (
 SELECT COALESCE(
   (SELECT last_aggregated_date+1 FROM channel_monitor_aggregation_watermark WHERE id=1),
   CURRENT_DATE-make_interval(days => $1::int)
 )::date AS value
)
SELECT to_char(day::date,'YYYY-MM-DD')
FROM start_date,
     LATERAL generate_series(start_date.value,CURRENT_DATE-1,INTERVAL '1 day') day
ORDER BY day LIMIT 35
",
            )
            .bind(i32::try_from(config.channel_rollup_retention_days).unwrap_or(i32::MAX))
            .fetch_all(&mut *connection)
            .await
            .context("list channel rollup dates")?;
            let mut rows = 0_u64;
            let mut days = 0_u64;
            for date in dates {
                if cancellation.is_cancelled() {
                    break;
                }
                let mut transaction = connection
                    .begin()
                    .await
                    .context("begin daily channel rollup")?;
                let affected = sqlx::query(CHANNEL_ROLLUP_SQL)
                    .bind(&date)
                    .execute(&mut *transaction)
                    .await?
                    .rows_affected();
                sqlx::query(
                    r"
INSERT INTO channel_monitor_aggregation_watermark (id,last_aggregated_date,updated_at)
VALUES (1,$1::date,NOW())
ON CONFLICT (id) DO UPDATE SET last_aggregated_date=EXCLUDED.last_aggregated_date,updated_at=NOW()
",
                )
                .bind(&date)
                .execute(&mut *transaction)
                .await?;
                transaction
                    .commit()
                    .await
                    .context("commit daily channel rollup")?;
                rows = rows.saturating_add(affected);
                days += 1;
            }
            let histories_deleted = delete_channel_batches(
                connection,
                "channel_monitor_histories",
                "checked_at",
                false,
                config.channel_history_retention_days,
                &cancellation,
            )
            .await?;
            let rollups_deleted = delete_channel_batches(
                connection,
                "channel_monitor_daily_rollups",
                "bucket_date",
                true,
                config.channel_rollup_retention_days,
                &cancellation,
            )
            .await?;
            Ok((days, rows, histories_deleted, rollups_deleted))
        })
    })
    .await
}

const CHANNEL_ROLLUP_SQL: &str = r"
INSERT INTO channel_monitor_daily_rollups (
 monitor_id,model,bucket_date,total_checks,ok_count,operational_count,degraded_count,
 failed_count,error_count,sum_latency_ms,count_latency,sum_ping_latency_ms,count_ping_latency,computed_at
)
SELECT monitor_id,model,$1::date,COUNT(*)::int,
 COUNT(*) FILTER (WHERE status IN ('operational','degraded'))::int,
 COUNT(*) FILTER (WHERE status='operational')::int,
 COUNT(*) FILTER (WHERE status='degraded')::int,
 COUNT(*) FILTER (WHERE status='failed')::int,
 COUNT(*) FILTER (WHERE status='error')::int,
 COALESCE(SUM(latency_ms) FILTER (WHERE latency_ms IS NOT NULL),0)::bigint,
 COUNT(latency_ms)::int,
 COALESCE(SUM(ping_latency_ms) FILTER (WHERE ping_latency_ms IS NOT NULL),0)::bigint,
 COUNT(ping_latency_ms)::int,NOW()
FROM channel_monitor_histories
WHERE checked_at >= $1::date AND checked_at < $1::date+INTERVAL '1 day'
GROUP BY monitor_id,model
ON CONFLICT (monitor_id,model,bucket_date) DO UPDATE SET
 total_checks=EXCLUDED.total_checks,ok_count=EXCLUDED.ok_count,
 operational_count=EXCLUDED.operational_count,degraded_count=EXCLUDED.degraded_count,
 failed_count=EXCLUDED.failed_count,error_count=EXCLUDED.error_count,
 sum_latency_ms=EXCLUDED.sum_latency_ms,count_latency=EXCLUDED.count_latency,
 sum_ping_latency_ms=EXCLUDED.sum_ping_latency_ms,count_ping_latency=EXCLUDED.count_ping_latency,
 computed_at=NOW()
";

async fn delete_channel_batches(
    connection: &mut PgConnection,
    table: &str,
    column: &str,
    date_column: bool,
    days: i64,
    cancellation: &CancellationToken,
) -> Result<u64> {
    let cutoff = if date_column {
        format!("{column}<CURRENT_DATE-make_interval(days => $1::int)")
    } else {
        format!("{column}<NOW()-make_interval(days => $1::int)")
    };
    let query = format!(
        "WITH batch AS (SELECT id FROM {table} WHERE {cutoff} ORDER BY id LIMIT $2) DELETE FROM {table} WHERE id IN (SELECT id FROM batch)"
    );
    let mut total = 0_u64;
    loop {
        if cancellation.is_cancelled() {
            break;
        }
        let affected = sqlx::query(&query)
            .bind(i32::try_from(days).unwrap_or(i32::MAX))
            .bind(CLEANUP_BATCH_SIZE)
            .execute(&mut *connection)
            .await?
            .rows_affected();
        total = total.saturating_add(affected);
        if affected < u64::try_from(CLEANUP_BATCH_SIZE).unwrap_or(u64::MAX) {
            break;
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;
    use uuid::Uuid;

    #[test]
    fn defaults_are_postgres_only_and_lifecycle_is_bounded() {
        let config = OpsRuntimeConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.metrics_interval, Duration::from_mins(1));
        assert_eq!(config.usage_logs_retention_days, 90);
        assert_eq!(
            dashboard_initial_backfill_days(&config),
            i32::try_from(config.usage_logs_retention_days).unwrap()
        );
        assert!(METRICS_INSERT_SQL.contains("redis_ok,redis_conn_total,redis_conn_idle"));
        assert!(METRICS_INSERT_SQL.contains("TRUE,NULL,NULL,NULL"));
        assert!(OPS_HOURLY_SQL.contains("GROUPING SETS"));
        assert!(DASHBOARD_BOUNDS_SQL.contains("usage_dashboard_aggregation_watermark"));

        let mut invalid = config;
        invalid.report_interval = Duration::ZERO;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn cron_and_sustained_evaluation_match_go_semantics() {
        let cron = CronSchedule::parse("*/15 8-18 * JAN,MAR MON-FRI").unwrap();
        assert!(cron.matches(CronDate {
            minute: 45,
            hour: 12,
            day: 6,
            month: 3,
            weekday: 1,
        }));
        assert!(!cron.matches(CronDate {
            minute: 46,
            hour: 12,
            day: 6,
            month: 3,
            weekday: 1,
        }));
        assert_eq!(required_breaches(1, 60), 1);
        assert_eq!(required_breaches(5, 60), 5);
        assert_eq!(required_breaches(5, 90), 4);
        assert!(compare_metric(5.0, ">=", 5.0));
        assert!(!compare_metric(5.0, ">", 5.0));
    }

    #[test]
    fn scheduled_reports_catch_up_once_from_persisted_last_run() {
        let minute = |year, month, day, hour, minute| {
            NaiveDate::from_ymd_opt(year, month, day)
                .unwrap()
                .and_hms_opt(hour, minute, 0)
                .unwrap()
        };
        let daily = CronSchedule::parse("0 9 * * *").unwrap();
        assert!(daily.is_due(None, minute(2026, 7, 14, 9, 0)));
        assert!(!daily.is_due(None, minute(2026, 7, 14, 9, 1)));
        assert!(daily.is_due(Some(minute(2026, 7, 12, 9, 5)), minute(2026, 7, 14, 12, 0)));
        assert!(!daily.is_due(Some(minute(2026, 7, 14, 9, 0)), minute(2026, 7, 14, 12, 0)));

        let weekly = CronSchedule::parse("30 8 * * MON").unwrap();
        assert!(weekly.is_due(Some(minute(2026, 7, 6, 8, 31)), minute(2026, 7, 13, 8, 31)));
    }

    #[test]
    fn latency_alerts_and_email_retries_keep_scope_in_postgres() {
        assert!(ALERT_LATENCY_METRICS_SQL.contains("make_interval(mins => $1)"));
        assert!(ALERT_LATENCY_METRICS_SQL.contains("groups.platform"));
        assert!(ALERT_LATENCY_METRICS_SQL.contains("accounts.platform"));
        assert!(ALERT_LATENCY_METRICS_SQL.contains("logs.group_id=$3"));
        assert!(PENDING_ALERT_NOTIFICATIONS_SQL.contains("events.email_sent=FALSE"));
        assert!(PENDING_ALERT_NOTIFICATIONS_SQL.contains("events.status='firing'"));
        assert!(PENDING_ALERT_NOTIFICATIONS_SQL.contains("rules.notify_email=TRUE"));
        assert_eq!(ALERT_EMAIL_BATCH_SIZE, 100);
    }

    #[test]
    fn cleanup_queries_are_batched_and_billing_keys_are_archived() {
        assert!(CHANNEL_ROLLUP_SQL.contains("ON CONFLICT (monitor_id,model,bucket_date)"));
        assert!(CHANNEL_ROLLUP_SQL.contains("COUNT(*) FILTER"));
        assert!(OPS_DAILY_SQL.contains("ttft_sample_count"));
        assert!(OPS_DAILY_SQL.contains("ON CONFLICT"));
        assert_eq!(CLEANUP_BATCH_SIZE, 5_000);
        assert_eq!(USAGE_CLEANUP_BATCH_SIZE, 10_000);
    }

    async fn test_pool() -> PgPool {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL must be set for ignored PostgreSQL tests");
        let parsed = url::Url::parse(&database_url).expect("test database URL should parse");
        assert!(
            parsed.path().trim_matches('/').ends_with("_test"),
            "refusing to modify a database whose name does not end in _test"
        );
        PgPoolOptions::new()
            .max_connections(6)
            .connect(&database_url)
            .await
            .expect("connect migrated PostgreSQL test database")
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with the migrated PostgreSQL schema"]
    async fn postgres_ops_runtime_locks_aggregates_and_alerts_are_replica_safe() {
        let pool = test_pool().await;
        let mut owner = pool.begin().await.expect("begin competing lock owner");
        assert!(try_xact_lock(&mut owner, METRICS_LOCK).await.unwrap());
        assert!(
            !collect_metrics_once(
                &pool,
                SystemStats {
                    cpu_percent: Some(73.0),
                    ..SystemStats::default()
                },
            )
            .await
            .expect("competing metrics cycle should skip")
        );
        owner.rollback().await.unwrap();
        assert!(
            collect_metrics_once(
                &pool,
                SystemStats {
                    cpu_percent: Some(73.0),
                    memory_used_mb: Some(64),
                    memory_total_mb: Some(128),
                    memory_percent: Some(50.0),
                },
            )
            .await
            .expect("collect test metrics")
        );
        assert!(
            aggregate_dashboard_once(&pool, &OpsRuntimeConfig::default())
                .await
                .expect("aggregate dashboard")
        );
        aggregate_ops_hourly_once(&pool)
            .await
            .expect("aggregate hourly ops metrics");
        aggregate_ops_daily_once(&pool)
            .await
            .expect("aggregate daily ops metrics");

        let marker = Uuid::new_v4().simple().to_string();
        let rule_id = sqlx::query_scalar::<_, i64>(
            r"
INSERT INTO ops_alert_rules (
 name,enabled,severity,metric_type,operator,threshold,window_minutes,
 sustained_minutes,cooldown_minutes,notify_email,filters
)
VALUES ($1,TRUE,'P2','cpu_usage_percent','>=',70,1,1,10,FALSE,'{}'::jsonb)
RETURNING id
",
        )
        .bind(format!("rust-ops-{marker}"))
        .fetch_one(&pool)
        .await
        .expect("insert alert rule");
        let settings = AlertRuntimeSettings::default();
        let first = evaluate_alerts_once(&pool, &settings)
            .await
            .expect("evaluate alert")
            .expect("own alert lock");
        assert_eq!(first.1.len(), 0, "notify_email is disabled");
        evaluate_alerts_once(&pool, &settings)
            .await
            .expect("repeat alert evaluation");
        let events = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*)::bigint FROM ops_alert_events WHERE rule_id=$1 AND status='firing'",
        )
        .bind(rule_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(events, 1, "active event must be unique across cycles");

        sqlx::query("UPDATE ops_alert_rules SET notify_email=TRUE WHERE id=$1")
            .bind(rule_id)
            .execute(&pool)
            .await
            .unwrap();
        let mut connection = pool.acquire().await.unwrap();
        let pending = load_pending_alert_notifications(&mut connection)
            .await
            .expect("load durable pending alert emails");
        assert!(
            pending
                .iter()
                .any(|notification| notification.rule_id == rule_id),
            "an existing firing event must remain retryable"
        );
        drop(connection);

        sqlx::query("DELETE FROM ops_alert_events WHERE rule_id=$1")
            .bind(rule_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM ops_alert_rules WHERE id=$1")
            .bind(rule_id)
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with the migrated PostgreSQL schema"]
    async fn postgres_ops_runtime_rolls_up_channels_and_prunes_moderation_logs() {
        let pool = test_pool().await;
        let marker = Uuid::new_v4().simple().to_string();
        let previous_watermark = sqlx::query_scalar::<_, Option<String>>(
            "SELECT last_aggregated_date::text FROM channel_monitor_aggregation_watermark WHERE id=1",
        )
        .fetch_optional(&pool)
        .await
        .unwrap()
        .flatten();
        sqlx::query(
            r"
INSERT INTO channel_monitor_aggregation_watermark (id,last_aggregated_date,updated_at)
VALUES (1,CURRENT_DATE-2,NOW())
ON CONFLICT (id) DO UPDATE SET last_aggregated_date=CURRENT_DATE-2,updated_at=NOW()
",
        )
        .execute(&pool)
        .await
        .unwrap();
        let monitor_id = sqlx::query_scalar::<_, i64>(
            r"
INSERT INTO channel_monitors (
 name,provider,endpoint,api_key_encrypted,primary_model,enabled,interval_seconds,created_by
)
VALUES ($1,'openai','https://example.test','unused','gpt-test',TRUE,60,1) RETURNING id
",
        )
        .bind(format!("rust-ops-monitor-{marker}"))
        .fetch_one(&pool)
        .await
        .unwrap();
        sqlx::query(
            r"
INSERT INTO channel_monitor_histories (
 monitor_id,model,status,latency_ms,ping_latency_ms,checked_at
)
VALUES ($1,'gpt-test','operational',25,5,CURRENT_DATE-1+INTERVAL '1 hour')
",
        )
        .bind(monitor_id)
        .execute(&pool)
        .await
        .unwrap();
        let report = channel_rollup_once(
            &pool,
            &OpsRuntimeConfig::default(),
            &CancellationToken::new(),
        )
        .await
        .expect("run channel rollup")
        .expect("own channel lock");
        assert!(report.0 >= 1);
        let rollup = sqlx::query_scalar::<_, i64>(
            "SELECT total_checks::bigint FROM channel_monitor_daily_rollups WHERE monitor_id=$1 AND model='gpt-test' AND bucket_date=CURRENT_DATE-1",
        )
        .bind(monitor_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(rollup, 1);

        for (flagged, age) in [(true, 181), (false, 4)] {
            sqlx::query(
                r"
INSERT INTO content_moderation_logs (request_id,flagged,created_at)
VALUES ($1,$2,NOW()-make_interval(days => $3::int))
",
            )
            .bind(format!("rust-ops-moderation-{marker}-{flagged}"))
            .bind(flagged)
            .bind(age)
            .execute(&pool)
            .await
            .unwrap();
        }
        let deleted = cleanup_moderation_once(&pool, &CancellationToken::new())
            .await
            .expect("cleanup moderation logs")
            .expect("own moderation lock");
        assert!(deleted.0 >= 1 && deleted.1 >= 1);

        sqlx::query("DELETE FROM channel_monitors WHERE id=$1")
            .bind(monitor_id)
            .execute(&pool)
            .await
            .unwrap();
        match previous_watermark {
            Some(value) => {
                sqlx::query("UPDATE channel_monitor_aggregation_watermark SET last_aggregated_date=$1::date,updated_at=NOW() WHERE id=1")
                    .bind(value)
                    .execute(&pool)
                    .await
                    .unwrap();
            }
            None => {
                sqlx::query("UPDATE channel_monitor_aggregation_watermark SET last_aggregated_date=NULL,updated_at=NOW() WHERE id=1")
                    .execute(&pool)
                    .await
                    .unwrap();
            }
        }
        pool.close().await;
    }
}
