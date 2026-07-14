use std::{collections::HashMap, error::Error, fmt, time::Duration};

use anyhow::{Context, Result};
use chrono::DateTime;
use serde::Deserialize;
use serde_json::Value;
use sqlx::{Connection, PgConnection, PgPool, Postgres, QueryBuilder, Row, Transaction};
use tokio::{task::JoinHandle, time};
use tokio_util::sync::CancellationToken;

use crate::gateway::AuthCacheInvalidator;

const MAINTENANCE_LOCK_KEY: i64 = 0x5355_4232_4150_4901;
const USAGE_CLEANUP_LOCK_KEY: i64 = 0x5355_4232_4150_4902;
const USAGE_CLEANUP_BATCH_SIZE: i64 = 5_000;
const MAX_USAGE_CLEANUP_RANGE_DAYS: i64 = 31;
const FINAL_DRAIN_GRACE: Duration = Duration::from_secs(1);

const EXPIRE_PAYMENT_ORDERS_SQL: &str = r"
WITH expired AS (
    UPDATE payment_orders
    SET status = 'EXPIRED', updated_at = NOW()
    WHERE status = 'PENDING' AND expires_at <= NOW()
    RETURNING id
), audited AS (
    INSERT INTO payment_audit_logs (order_id, action, detail, operator, created_at)
    SELECT id::text,
           'ORDER_EXPIRED',
           jsonb_build_object('detail', 'order expired')::text,
           'system',
           NOW()
    FROM expired
    ON CONFLICT (order_id, action) DO NOTHING
    RETURNING 1
)
SELECT (SELECT COUNT(*)::bigint FROM expired) AS expired_count,
       (SELECT COUNT(*)::bigint FROM audited) AS audit_count
";

const CLAIM_USAGE_CLEANUP_TASK_SQL: &str = r"
WITH next AS (
    SELECT id
    FROM usage_cleanup_tasks
    WHERE status = 'pending'
       OR (
            status = 'running'
            AND updated_at <= NOW() - INTERVAL '30 minutes'
       )
    ORDER BY CASE WHEN status = 'pending' THEN 0 ELSE 1 END, created_at, id
    LIMIT 1
    FOR UPDATE SKIP LOCKED
)
UPDATE usage_cleanup_tasks AS tasks
SET status = 'running',
    started_at = NOW(),
    finished_at = NULL,
    error_message = NULL,
    updated_at = NOW()
FROM next
WHERE tasks.id = next.id
RETURNING tasks.id, tasks.filters, tasks.deleted_rows
";

const CLEANUP_PENDING_AUTH_SESSIONS_SQL: &str = r"
DELETE FROM pending_auth_sessions
WHERE expires_at <= NOW() OR consumed_at IS NOT NULL
";

const CLEANUP_OAUTH_STATES_SQL: &str = r"
DELETE FROM auth_oauth_states
WHERE expires_at <= NOW() OR consumed_at IS NOT NULL
";

const CLEANUP_WECHAT_RESUME_TOKENS_SQL: &str = r"
DELETE FROM auth_wechat_payment_resume_tokens
WHERE expires_at <= NOW() OR consumed_at IS NOT NULL
";

const CLEANUP_ADMIN_OAUTH_SESSIONS_SQL: &str = r"
DELETE FROM admin_oauth_sessions
WHERE expires_at <= NOW() OR consumed_at IS NOT NULL
";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceConfig {
    pub interval: Duration,
    pub shutdown_timeout: Duration,
}

impl Default for MaintenanceConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_mins(1),
            shutdown_timeout: Duration::from_secs(30),
        }
    }
}

impl MaintenanceConfig {
    /// # Errors
    ///
    /// Returns an error when either lifecycle duration is zero.
    pub fn validate(&self) -> Result<(), MaintenanceConfigError> {
        if self.interval.is_zero() {
            return Err(MaintenanceConfigError("interval must be greater than zero"));
        }
        if self.shutdown_timeout.is_zero() {
            return Err(MaintenanceConfigError(
                "shutdown_timeout must be greater than zero",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceConfigError(&'static str);

impl fmt::Display for MaintenanceConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for MaintenanceConfigError {}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MaintenanceReport {
    pub lock_acquired: bool,
    pub accounts_paused: u64,
    pub subscriptions_expired: u64,
    pub proxies_expired: u64,
    pub accounts_rerouted: u64,
    pub refresh_sessions_deleted: u64,
    pub security_tokens_deleted: u64,
    pub auth_rate_limit_windows_deleted: u64,
    pub idempotency_records_deleted: u64,
    pub payment_orders_expired: u64,
    pub payment_audit_logs_created: u64,
    pub pending_auth_sessions_deleted: u64,
    pub oauth_states_deleted: u64,
    pub wechat_resume_tokens_deleted: u64,
    pub admin_oauth_sessions_deleted: u64,
    pub usage_cleanup_tasks_claimed: u64,
    pub usage_cleanup_tasks_succeeded: u64,
    pub usage_cleanup_tasks_failed: u64,
    pub usage_cleanup_tasks_canceled: u64,
    pub usage_cleanup_tasks_requeued: u64,
    pub usage_cleanup_errors: u64,
    pub usage_logs_deleted: u64,
}

pub struct MaintenanceRuntime {
    cancellation: CancellationToken,
    task: JoinHandle<()>,
    shutdown_timeout: Duration,
}

impl MaintenanceRuntime {
    /// Starts the singleton `PostgreSQL` maintenance loop.
    ///
    /// # Errors
    ///
    /// Returns an error when the lifecycle configuration is invalid.
    pub fn spawn(pool: PgPool, config: MaintenanceConfig) -> Result<Self, MaintenanceConfigError> {
        Self::spawn_inner(pool, config, None)
    }

    /// Starts the maintenance loop and publishes cache invalidations for
    /// committed account, proxy, and subscription state changes.
    ///
    /// # Errors
    ///
    /// Returns an error when the lifecycle configuration is invalid.
    pub fn spawn_with_cache_invalidator(
        pool: PgPool,
        config: MaintenanceConfig,
        cache_invalidator: AuthCacheInvalidator,
    ) -> Result<Self, MaintenanceConfigError> {
        Self::spawn_inner(pool, config, Some(cache_invalidator))
    }

    fn spawn_inner(
        pool: PgPool,
        config: MaintenanceConfig,
        cache_invalidator: Option<AuthCacheInvalidator>,
    ) -> Result<Self, MaintenanceConfigError> {
        config.validate()?;
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let interval = config.interval;
        let final_drain_timeout = config.shutdown_timeout;
        let task = tokio::spawn(async move {
            maintenance_loop(
                pool,
                interval,
                final_drain_timeout,
                task_cancellation,
                cache_invalidator,
            )
            .await;
        });
        Ok(Self {
            cancellation,
            task,
            shutdown_timeout: config.shutdown_timeout.saturating_add(FINAL_DRAIN_GRACE),
        })
    }

    /// Stops the periodic loop and waits for an active database transaction.
    ///
    /// # Errors
    ///
    /// Returns an error when the task panics or does not stop before the
    /// configured deadline.
    pub async fn shutdown(self) -> Result<()> {
        self.cancellation.cancel();
        match time::timeout(self.shutdown_timeout, self.task).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(anyhow::anyhow!("maintenance task failed: {error}")),
            Err(_) => Err(anyhow::anyhow!(
                "maintenance task did not stop within {:?}",
                self.shutdown_timeout
            )),
        }
    }
}

async fn maintenance_loop(
    pool: PgPool,
    interval: Duration,
    final_drain_timeout: Duration,
    cancellation: CancellationToken,
    cache_invalidator: Option<AuthCacheInvalidator>,
) {
    let mut ticker = time::interval(interval);
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            () = cancellation.cancelled() => {
                run_final_maintenance_cycle(
                    &pool,
                    final_drain_timeout,
                    cache_invalidator.as_ref(),
                )
                .await;
                break;
            },
            _ = ticker.tick() => {
                match run_once_with_control(&pool, Some(&cancellation), None).await {
                    Ok(report) if report.lock_acquired => {
                        if let Some(invalidator) = cache_invalidator.as_ref() {
                            invalidate_maintenance_changes(invalidator, &report).await;
                        }
                        tracing::info!(?report, "PostgreSQL maintenance cycle completed");
                    }
                    Ok(_) => tracing::debug!("PostgreSQL maintenance cycle owned by another replica"),
                    Err(error) => tracing::error!(error = %error, "PostgreSQL maintenance cycle failed"),
                }
            }
        }
    }
}

async fn run_final_maintenance_cycle(
    pool: &PgPool,
    timeout: Duration,
    cache_invalidator: Option<&AuthCacheInvalidator>,
) {
    let deadline = time::Instant::now() + timeout;
    match time::timeout(timeout, run_once_with_control(pool, None, Some(deadline))).await {
        Ok(Ok(report)) if report.lock_acquired => {
            if let Some(invalidator) = cache_invalidator {
                invalidate_maintenance_changes(invalidator, &report).await;
            }
            tracing::info!(?report, "final PostgreSQL maintenance cycle completed");
        }
        Ok(Ok(_)) => {
            tracing::debug!("final PostgreSQL maintenance cycle owned by another replica");
        }
        Ok(Err(error)) => {
            tracing::error!(error = %error, "final PostgreSQL maintenance cycle failed");
        }
        Err(_) => {
            tracing::warn!(
                ?timeout,
                "final PostgreSQL maintenance cycle reached its deadline"
            );
        }
    }
}

async fn invalidate_maintenance_changes(
    invalidator: &AuthCacheInvalidator,
    report: &MaintenanceReport,
) {
    if report.subscriptions_expired > 0
        && let Err(error) = invalidator.invalidate_auth_cache().await
    {
        tracing::warn!(
            error = %error,
            "subscription maintenance committed but auth-cache notification failed"
        );
    }
    if (report.accounts_paused > 0 || report.proxies_expired > 0 || report.accounts_rerouted > 0)
        && let Err(error) = invalidator.invalidate_account_cache().await
    {
        tracing::warn!(
            error = %error,
            "account maintenance committed but scheduler-cache notification failed"
        );
    }
}

/// Runs one transactionally locked maintenance cycle.
///
/// # Errors
///
/// Returns an error when `PostgreSQL` cannot acquire a connection or a core
/// maintenance statement fails. Core state changes are rolled back together.
/// Usage-cleanup task failures are isolated and counted in the report so they
/// cannot suppress cache invalidation for already committed core changes.
pub async fn run_once(pool: &PgPool) -> Result<MaintenanceReport> {
    run_once_with_control(pool, None, None).await
}

async fn run_once_with_control(
    pool: &PgPool,
    cancellation: Option<&CancellationToken>,
    deadline: Option<time::Instant>,
) -> Result<MaintenanceReport> {
    let mut transaction = pool
        .begin()
        .await
        .context("begin maintenance transaction")?;
    let acquired = sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_xact_lock($1)")
        .bind(MAINTENANCE_LOCK_KEY)
        .fetch_one(&mut *transaction)
        .await
        .context("acquire maintenance advisory lock")?;
    if !acquired {
        transaction
            .rollback()
            .await
            .context("rollback skipped maintenance transaction")?;
        return Ok(MaintenanceReport::default());
    }

    let accounts_paused = pause_expired_accounts(&mut transaction).await?;
    let subscriptions_expired = expire_subscriptions(&mut transaction).await?;
    let (proxies_expired, accounts_rerouted) = sweep_expired_proxies(&mut transaction).await?;
    let refresh_sessions_deleted = cleanup_refresh_sessions(&mut transaction).await?;
    let security_tokens_deleted = cleanup_security_tokens(&mut transaction).await?;
    let auth_rate_limit_windows_deleted = cleanup_auth_rate_limit_windows(&mut transaction).await?;
    let idempotency_records_deleted = cleanup_idempotency(&mut transaction).await?;
    let (payment_orders_expired, payment_audit_logs_created) =
        expire_payment_orders(&mut transaction).await?;
    let pending_auth_sessions_deleted = cleanup_pending_auth_sessions(&mut transaction).await?;
    let oauth_states_deleted = cleanup_oauth_states(&mut transaction).await?;
    let wechat_resume_tokens_deleted = cleanup_wechat_resume_tokens(&mut transaction).await?;
    let admin_oauth_sessions_deleted = cleanup_admin_oauth_sessions(&mut transaction).await?;

    transaction
        .commit()
        .await
        .context("commit maintenance transaction")?;
    let mut report = MaintenanceReport {
        lock_acquired: true,
        accounts_paused,
        subscriptions_expired,
        proxies_expired,
        accounts_rerouted,
        refresh_sessions_deleted,
        security_tokens_deleted,
        auth_rate_limit_windows_deleted,
        idempotency_records_deleted,
        payment_orders_expired,
        payment_audit_logs_created,
        pending_auth_sessions_deleted,
        oauth_states_deleted,
        wechat_resume_tokens_deleted,
        admin_oauth_sessions_deleted,
        ..MaintenanceReport::default()
    };
    match process_next_usage_cleanup_task(pool, cancellation, deadline).await {
        Ok(usage) => usage.apply_to(&mut report),
        Err(error) => {
            report.usage_cleanup_errors = 1;
            tracing::error!(error = %error, "usage cleanup worker failed");
        }
    }
    Ok(report)
}

async fn pause_expired_accounts(transaction: &mut Transaction<'_, Postgres>) -> Result<u64> {
    let result = sqlx::query(
        r"
UPDATE accounts
SET schedulable = FALSE, updated_at = NOW()
WHERE deleted_at IS NULL
  AND schedulable = TRUE
  AND auto_pause_on_expired = TRUE
  AND expires_at IS NOT NULL
  AND expires_at <= NOW()
",
    )
    .execute(&mut **transaction)
    .await
    .context("pause expired accounts")?;
    if result.rows_affected() > 0 {
        enqueue_scheduler_rebuild(transaction).await?;
    }
    Ok(result.rows_affected())
}

async fn expire_subscriptions(transaction: &mut Transaction<'_, Postgres>) -> Result<u64> {
    Ok(sqlx::query(
        r"
UPDATE user_subscriptions
SET status = 'expired', updated_at = NOW()
WHERE status = 'active' AND expires_at <= NOW()
",
    )
    .execute(&mut **transaction)
    .await
    .context("expire user subscriptions")?
    .rows_affected())
}

#[derive(Clone, Debug)]
struct ProxySnapshot {
    id: i64,
    status: String,
    expired: bool,
    fallback_mode: String,
    backup_proxy_id: Option<i64>,
}

async fn sweep_expired_proxies(transaction: &mut Transaction<'_, Postgres>) -> Result<(u64, u64)> {
    let snapshots = load_proxy_snapshots(transaction).await?;
    let by_id = snapshots
        .iter()
        .cloned()
        .map(|proxy| (proxy.id, proxy))
        .collect::<HashMap<_, _>>();
    let expired = snapshots
        .iter()
        .filter(|proxy| proxy.status == "active" && proxy.expired)
        .collect::<Vec<_>>();
    let mut accounts_rerouted = 0_u64;

    for proxy in &expired {
        let target = resolve_proxy_target(proxy, &by_id);
        sqlx::query(
            "UPDATE proxies SET status = 'expired', updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(proxy.id)
        .execute(&mut **transaction)
        .await
        .with_context(|| format!("mark proxy {} expired", proxy.id))?;
        match target {
            ProxyTarget::Unchanged => {}
            ProxyTarget::Direct => {
                accounts_rerouted += reroute_accounts(transaction, proxy.id, None).await?;
            }
            ProxyTarget::Proxy(target_id) => {
                accounts_rerouted +=
                    reroute_accounts(transaction, proxy.id, Some(target_id)).await?;
            }
        }
    }
    if accounts_rerouted > 0 {
        enqueue_scheduler_rebuild(transaction).await?;
    }
    Ok((expired.len() as u64, accounts_rerouted))
}

async fn load_proxy_snapshots(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<Vec<ProxySnapshot>> {
    sqlx::query(
        r"
SELECT id, status,
       (expires_at IS NOT NULL AND expires_at <= NOW()) AS expired,
       fallback_mode, backup_proxy_id
FROM proxies
WHERE deleted_at IS NULL
",
    )
    .fetch_all(&mut **transaction)
    .await
    .context("load proxy fallback graph")?
    .into_iter()
    .map(|row| {
        Ok(ProxySnapshot {
            id: row.try_get("id")?,
            status: row.try_get("status")?,
            expired: row.try_get("expired")?,
            fallback_mode: row.try_get("fallback_mode")?,
            backup_proxy_id: row.try_get("backup_proxy_id")?,
        })
    })
    .collect::<Result<Vec<_>, sqlx::Error>>()
    .context("decode proxy fallback graph")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProxyTarget {
    Unchanged,
    Direct,
    Proxy(i64),
}

fn resolve_proxy_target(
    start: &ProxySnapshot,
    proxies: &HashMap<i64, ProxySnapshot>,
) -> ProxyTarget {
    match start.fallback_mode.as_str() {
        "direct" => ProxyTarget::Direct,
        "proxy" => resolve_proxy_chain(start, proxies),
        _ => ProxyTarget::Unchanged,
    }
}

fn resolve_proxy_chain(
    start: &ProxySnapshot,
    proxies: &HashMap<i64, ProxySnapshot>,
) -> ProxyTarget {
    let mut visited = std::collections::HashSet::from([start.id]);
    let mut current = start.backup_proxy_id;
    while let Some(id) = current {
        if !visited.insert(id) {
            return ProxyTarget::Unchanged;
        }
        let Some(proxy) = proxies.get(&id) else {
            return ProxyTarget::Unchanged;
        };
        if !proxy.expired && proxy.status != "expired" {
            return ProxyTarget::Proxy(proxy.id);
        }
        match proxy.fallback_mode.as_str() {
            "direct" => return ProxyTarget::Direct,
            "proxy" => current = proxy.backup_proxy_id,
            _ => return ProxyTarget::Unchanged,
        }
    }
    ProxyTarget::Unchanged
}

async fn reroute_accounts(
    transaction: &mut Transaction<'_, Postgres>,
    expired_proxy_id: i64,
    target_proxy_id: Option<i64>,
) -> Result<u64> {
    Ok(sqlx::query(
        r"
UPDATE accounts
SET proxy_id = $2, proxy_fallback_origin_id = $1, updated_at = NOW()
WHERE proxy_id = $1
  AND proxy_fallback_origin_id IS NULL
  AND deleted_at IS NULL
",
    )
    .bind(expired_proxy_id)
    .bind(target_proxy_id)
    .execute(&mut **transaction)
    .await
    .with_context(|| format!("reroute accounts from expired proxy {expired_proxy_id}"))?
    .rows_affected())
}

async fn enqueue_scheduler_rebuild(transaction: &mut Transaction<'_, Postgres>) -> Result<()> {
    sqlx::query(
        r"
INSERT INTO scheduler_outbox (event_type)
VALUES ('full_rebuild')
",
    )
    .execute(&mut **transaction)
    .await
    .context("enqueue scheduler full rebuild")?;
    Ok(())
}

async fn cleanup_refresh_sessions(transaction: &mut Transaction<'_, Postgres>) -> Result<u64> {
    Ok(sqlx::query(
        r"
DELETE FROM auth_refresh_sessions
WHERE expires_at < NOW() - INTERVAL '7 days'
",
    )
    .execute(&mut **transaction)
    .await
    .context("delete expired refresh sessions")?
    .rows_affected())
}

async fn cleanup_security_tokens(transaction: &mut Transaction<'_, Postgres>) -> Result<u64> {
    Ok(sqlx::query(
        r"
DELETE FROM auth_security_tokens
WHERE expires_at <= NOW()
   OR consumed_at <= NOW() - INTERVAL '1 day'
",
    )
    .execute(&mut **transaction)
    .await
    .context("delete expired authentication security tokens")?
    .rows_affected())
}

async fn cleanup_auth_rate_limit_windows(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<u64> {
    Ok(sqlx::query(
        r"
        WITH expired AS (
            SELECT ctid
            FROM auth_rate_limit_windows
            WHERE expires_at <= NOW()
            ORDER BY expires_at
            LIMIT 10000
        )
        DELETE FROM auth_rate_limit_windows
        WHERE ctid IN (SELECT ctid FROM expired)
        ",
    )
    .execute(&mut **transaction)
    .await
    .context("delete expired authentication rate-limit windows")?
    .rows_affected())
}

async fn cleanup_idempotency(transaction: &mut Transaction<'_, Postgres>) -> Result<u64> {
    Ok(
        sqlx::query("DELETE FROM idempotency_records WHERE expires_at <= NOW()")
            .execute(&mut **transaction)
            .await
            .context("delete expired idempotency records")?
            .rows_affected(),
    )
}

async fn expire_payment_orders(transaction: &mut Transaction<'_, Postgres>) -> Result<(u64, u64)> {
    let row = sqlx::query(EXPIRE_PAYMENT_ORDERS_SQL)
        .fetch_one(&mut **transaction)
        .await
        .context("expire pending payment orders and write audit logs")?;
    let expired = row.try_get::<i64, _>("expired_count")?;
    let audited = row.try_get::<i64, _>("audit_count")?;
    Ok((
        u64::try_from(expired).context("payment expiry count was negative")?,
        u64::try_from(audited).context("payment audit count was negative")?,
    ))
}

async fn cleanup_pending_auth_sessions(transaction: &mut Transaction<'_, Postgres>) -> Result<u64> {
    Ok(sqlx::query(CLEANUP_PENDING_AUTH_SESSIONS_SQL)
        .execute(&mut **transaction)
        .await
        .context("delete expired or consumed pending authentication sessions")?
        .rows_affected())
}

async fn cleanup_oauth_states(transaction: &mut Transaction<'_, Postgres>) -> Result<u64> {
    Ok(sqlx::query(CLEANUP_OAUTH_STATES_SQL)
        .execute(&mut **transaction)
        .await
        .context("delete expired or consumed OAuth states")?
        .rows_affected())
}

async fn cleanup_wechat_resume_tokens(transaction: &mut Transaction<'_, Postgres>) -> Result<u64> {
    Ok(sqlx::query(CLEANUP_WECHAT_RESUME_TOKENS_SQL)
        .execute(&mut **transaction)
        .await
        .context("delete expired or consumed WeChat payment resume tokens")?
        .rows_affected())
}

async fn cleanup_admin_oauth_sessions(transaction: &mut Transaction<'_, Postgres>) -> Result<u64> {
    Ok(sqlx::query(CLEANUP_ADMIN_OAUTH_SESSIONS_SQL)
        .execute(&mut **transaction)
        .await
        .context("delete expired or consumed administrator OAuth sessions")?
        .rows_affected())
}

#[derive(Debug, Deserialize)]
struct UsageCleanupFilters {
    start_time: String,
    end_time: String,
    user_id: Option<i64>,
    api_key_id: Option<i64>,
    account_id: Option<i64>,
    group_id: Option<i64>,
    model: Option<String>,
    request_type: Option<i16>,
    stream: Option<bool>,
    billing_type: Option<i16>,
}

impl UsageCleanupFilters {
    fn validate(mut self) -> Result<Self> {
        let start = DateTime::parse_from_rfc3339(self.start_time.trim())
            .context("usage cleanup start_time must be RFC3339")?;
        let end = DateTime::parse_from_rfc3339(self.end_time.trim())
            .context("usage cleanup end_time must be RFC3339")?;
        anyhow::ensure!(
            end >= start,
            "usage cleanup end_time must not precede start_time"
        );
        anyhow::ensure!(
            end.signed_duration_since(start)
                <= chrono::Duration::days(MAX_USAGE_CLEANUP_RANGE_DAYS),
            "usage cleanup range exceeds {MAX_USAGE_CLEANUP_RANGE_DAYS} days"
        );
        for (name, value) in [
            ("user_id", self.user_id),
            ("api_key_id", self.api_key_id),
            ("account_id", self.account_id),
            ("group_id", self.group_id),
        ] {
            if let Some(value) = value {
                anyhow::ensure!(value > 0, "usage cleanup {name} must be positive");
            }
        }
        if let Some(model) = self.model.as_mut() {
            *model = model.trim().to_owned();
            anyhow::ensure!(!model.is_empty(), "usage cleanup model cannot be empty");
            anyhow::ensure!(model.len() <= 100, "usage cleanup model is too long");
        }
        if let Some(request_type) = self.request_type {
            anyhow::ensure!(
                (0..=4).contains(&request_type),
                "usage cleanup request_type is invalid"
            );
        }
        if let Some(billing_type) = self.billing_type {
            anyhow::ensure!(
                billing_type >= 0,
                "usage cleanup billing_type cannot be negative"
            );
        }
        self.start_time = start.to_rfc3339();
        self.end_time = end.to_rfc3339();
        Ok(self)
    }
}

#[derive(Debug)]
struct UsageCleanupTask {
    id: i64,
    filters: Value,
    deleted_rows: i64,
}

#[derive(Clone, Copy, Debug, Default)]
struct UsageCleanupOutcome {
    claimed: u64,
    succeeded: u64,
    failed: u64,
    canceled: u64,
    requeued: u64,
    deleted: u64,
}

impl UsageCleanupOutcome {
    fn apply_to(self, report: &mut MaintenanceReport) {
        report.usage_cleanup_tasks_claimed = self.claimed;
        report.usage_cleanup_tasks_succeeded = self.succeeded;
        report.usage_cleanup_tasks_failed = self.failed;
        report.usage_cleanup_tasks_canceled = self.canceled;
        report.usage_cleanup_tasks_requeued = self.requeued;
        report.usage_logs_deleted = self.deleted;
    }
}

async fn process_next_usage_cleanup_task(
    pool: &PgPool,
    cancellation: Option<&CancellationToken>,
    deadline: Option<time::Instant>,
) -> Result<UsageCleanupOutcome> {
    if usage_cleanup_should_stop(cancellation, deadline) {
        return Ok(UsageCleanupOutcome::default());
    }

    let mut connection = pool
        .acquire()
        .await
        .context("acquire usage cleanup worker connection")?;
    // A canceled future must close the PostgreSQL session so its session-level
    // advisory lock cannot be returned to the pool still held.
    connection.close_on_drop();
    let acquired = sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_lock($1)")
        .bind(USAGE_CLEANUP_LOCK_KEY)
        .fetch_one(&mut *connection)
        .await
        .context("acquire usage cleanup worker advisory lock")?;
    if !acquired {
        return Ok(UsageCleanupOutcome::default());
    }

    let result =
        process_claimable_usage_cleanup_task(&mut connection, cancellation, deadline).await;
    let unlock_result = sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1)")
        .bind(USAGE_CLEANUP_LOCK_KEY)
        .fetch_one(&mut *connection)
        .await
        .context("release usage cleanup worker advisory lock");
    match (result, unlock_result) {
        (Ok(outcome), Ok(true)) => Ok(outcome),
        (Ok(_), Ok(false)) => anyhow::bail!("usage cleanup worker advisory lock was not held"),
        (Ok(_), Err(error)) | (Err(error), _) => Err(error),
    }
}

async fn process_claimable_usage_cleanup_task(
    connection: &mut PgConnection,
    cancellation: Option<&CancellationToken>,
    deadline: Option<time::Instant>,
) -> Result<UsageCleanupOutcome> {
    let Some(task) = claim_usage_cleanup_task(connection).await? else {
        return Ok(UsageCleanupOutcome::default());
    };
    let mut outcome = UsageCleanupOutcome {
        claimed: 1,
        ..UsageCleanupOutcome::default()
    };
    let filters = match serde_json::from_value::<UsageCleanupFilters>(task.filters)
        .context("decode usage cleanup filters")
        .and_then(UsageCleanupFilters::validate)
    {
        Ok(filters) => filters,
        Err(error) => {
            if mark_usage_cleanup_failed(connection, task.id, task.deleted_rows, &error).await? {
                outcome.failed = 1;
            } else {
                outcome.canceled = 1;
            }
            return Ok(outcome);
        }
    };

    loop {
        if usage_cleanup_should_stop(cancellation, deadline) {
            if requeue_usage_cleanup_task(connection, task.id).await? {
                outcome.requeued = 1;
            }
            return Ok(outcome);
        }
        match delete_usage_logs_batch(connection, task.id, &filters).await {
            Ok(UsageCleanupBatch::Deleted { rows, complete }) => {
                outcome.deleted = outcome.deleted.saturating_add(rows);
                if complete {
                    outcome.succeeded = 1;
                    return Ok(outcome);
                }
            }
            Ok(UsageCleanupBatch::Canceled) => {
                outcome.canceled = 1;
                return Ok(outcome);
            }
            Err(error) => {
                let deleted_rows = task
                    .deleted_rows
                    .saturating_add(i64::try_from(outcome.deleted).unwrap_or(i64::MAX));
                if mark_usage_cleanup_failed(connection, task.id, deleted_rows, &error).await? {
                    outcome.failed = 1;
                } else {
                    outcome.canceled = 1;
                }
                return Ok(outcome);
            }
        }
    }
}

fn usage_cleanup_should_stop(
    cancellation: Option<&CancellationToken>,
    deadline: Option<time::Instant>,
) -> bool {
    cancellation.is_some_and(CancellationToken::is_cancelled)
        || deadline.is_some_and(|deadline| time::Instant::now() >= deadline)
}

async fn claim_usage_cleanup_task(
    connection: &mut PgConnection,
) -> Result<Option<UsageCleanupTask>> {
    let mut transaction = connection
        .begin()
        .await
        .context("begin usage cleanup claim transaction")?;
    let row = sqlx::query(CLAIM_USAGE_CLEANUP_TASK_SQL)
        .fetch_optional(&mut *transaction)
        .await
        .context("claim pending or stale usage cleanup task")?;
    let task = row
        .map(|row| {
            Ok::<_, sqlx::Error>(UsageCleanupTask {
                id: row.try_get("id")?,
                filters: row.try_get("filters")?,
                deleted_rows: row.try_get("deleted_rows")?,
            })
        })
        .transpose()
        .context("decode claimed usage cleanup task")?;
    transaction
        .commit()
        .await
        .context("commit usage cleanup task claim")?;
    Ok(task)
}

enum UsageCleanupBatch {
    Deleted { rows: u64, complete: bool },
    Canceled,
}

async fn delete_usage_logs_batch(
    connection: &mut PgConnection,
    task_id: i64,
    filters: &UsageCleanupFilters,
) -> Result<UsageCleanupBatch> {
    let mut transaction = connection
        .begin()
        .await
        .context("begin usage cleanup batch transaction")?;
    let status = sqlx::query_scalar::<_, String>(
        "SELECT status FROM usage_cleanup_tasks WHERE id = $1 FOR UPDATE",
    )
    .bind(task_id)
    .fetch_optional(&mut *transaction)
    .await
    .context("lock usage cleanup task before deleting a batch")?;
    if status.as_deref() != Some("running") {
        transaction
            .rollback()
            .await
            .context("rollback canceled usage cleanup batch")?;
        return Ok(UsageCleanupBatch::Canceled);
    }

    let mut query = QueryBuilder::<Postgres>::new(
        "WITH target AS (SELECT id FROM usage_logs WHERE created_at >= ",
    );
    query
        .push_bind(&filters.start_time)
        .push("::timestamptz AND created_at <= ")
        .push_bind(&filters.end_time)
        .push("::timestamptz");
    push_optional_usage_filters(&mut query, filters);
    query
        .push(" ORDER BY created_at, id LIMIT ")
        .push_bind(USAGE_CLEANUP_BATCH_SIZE)
        .push(
            " FOR UPDATE SKIP LOCKED) \
             , deleted AS (DELETE FROM usage_logs AS logs USING target \
             WHERE logs.id = target.id RETURNING 1) \
             SELECT COUNT(*)::bigint FROM deleted",
        );
    let deleted = query
        .build_query_scalar::<i64>()
        .fetch_one(&mut *transaction)
        .await
        .context("delete one filtered usage-log batch")?;
    let complete = deleted < USAGE_CLEANUP_BATCH_SIZE;
    if complete {
        sqlx::query(
            r"
UPDATE usage_cleanup_tasks
SET status = 'succeeded',
    deleted_rows = deleted_rows + $1,
    error_message = NULL,
    finished_at = NOW(),
    updated_at = NOW()
WHERE id = $2 AND status = 'running'
",
        )
        .bind(deleted)
        .bind(task_id)
        .execute(&mut *transaction)
        .await
        .context("mark usage cleanup task succeeded")?;
    } else {
        sqlx::query(
            r"
UPDATE usage_cleanup_tasks
SET deleted_rows = deleted_rows + $1, updated_at = NOW()
WHERE id = $2 AND status = 'running'
",
        )
        .bind(deleted)
        .bind(task_id)
        .execute(&mut *transaction)
        .await
        .context("update usage cleanup task progress")?;
    }
    transaction
        .commit()
        .await
        .context("commit usage cleanup batch")?;
    Ok(UsageCleanupBatch::Deleted {
        rows: u64::try_from(deleted).context("usage cleanup deleted-row count was negative")?,
        complete,
    })
}

fn push_optional_usage_filters<'args>(
    query: &mut QueryBuilder<'args, Postgres>,
    filters: &'args UsageCleanupFilters,
) {
    if let Some(user_id) = filters.user_id {
        query.push(" AND user_id = ").push_bind(user_id);
    }
    if let Some(api_key_id) = filters.api_key_id {
        query.push(" AND api_key_id = ").push_bind(api_key_id);
    }
    if let Some(account_id) = filters.account_id {
        query.push(" AND account_id = ").push_bind(account_id);
    }
    if let Some(group_id) = filters.group_id {
        query.push(" AND group_id = ").push_bind(group_id);
    }
    if let Some(model) = filters.model.as_deref() {
        query.push(" AND model = ").push_bind(model);
    }
    if let Some(request_type) = filters.request_type {
        push_request_type_filter(query, request_type);
    } else if let Some(stream) = filters.stream {
        query.push(" AND stream = ").push_bind(stream);
    }
    if let Some(billing_type) = filters.billing_type {
        query.push(" AND billing_type = ").push_bind(billing_type);
    }
}

fn push_request_type_filter(query: &mut QueryBuilder<'_, Postgres>, request_type: i16) {
    match request_type {
        1 => {
            query
                .push(" AND (request_type = ")
                .push_bind(request_type)
                .push(" OR (request_type = 0 AND stream = FALSE AND openai_ws_mode = FALSE))");
        }
        2 => {
            query
                .push(" AND (request_type = ")
                .push_bind(request_type)
                .push(" OR (request_type = 0 AND stream = TRUE AND openai_ws_mode = FALSE))");
        }
        3 => {
            query
                .push(" AND (request_type = ")
                .push_bind(request_type)
                .push(" OR (request_type = 0 AND openai_ws_mode = TRUE))");
        }
        _ => {
            query.push(" AND request_type = ").push_bind(request_type);
        }
    }
}

async fn requeue_usage_cleanup_task(connection: &mut PgConnection, task_id: i64) -> Result<bool> {
    Ok(sqlx::query(
        r"
UPDATE usage_cleanup_tasks
SET status = 'pending', started_at = NULL, updated_at = NOW()
WHERE id = $1 AND status = 'running'
",
    )
    .bind(task_id)
    .execute(connection)
    .await
    .context("requeue interrupted usage cleanup task")?
    .rows_affected()
        > 0)
}

async fn mark_usage_cleanup_failed(
    connection: &mut PgConnection,
    task_id: i64,
    deleted_rows: i64,
    error: &anyhow::Error,
) -> Result<bool> {
    let message = error.to_string().chars().take(500).collect::<String>();
    Ok(sqlx::query(
        r"
UPDATE usage_cleanup_tasks
SET status = 'failed',
    deleted_rows = $2,
    error_message = $3,
    finished_at = NOW(),
    updated_at = NOW()
WHERE id = $1 AND status = 'running'
",
    )
    .bind(task_id)
    .bind(deleted_rows)
    .bind(message)
    .execute(connection)
    .await
    .context("mark usage cleanup task failed")?
    .rows_affected()
        > 0)
}

#[cfg(test)]
mod tests {
    use std::{
        env,
        sync::{
            Arc,
            atomic::{AtomicU32, Ordering},
        },
    };

    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use uuid::Uuid;

    use super::*;
    use crate::gateway::GatewayAuthState;

    #[derive(Default)]
    struct FakeCacheTarget {
        auth: AtomicU32,
        accounts: AtomicU32,
    }

    impl GatewayAuthState for FakeCacheTarget {
        fn invalidate_api_key(&self, _api_key_id: i64, _raw_key: Option<&str>) {}

        fn invalidate_auth_cache(&self) {
            self.auth.fetch_add(1, Ordering::Relaxed);
        }

        fn invalidate_account_cache(&self) {
            self.accounts.fetch_add(1, Ordering::Relaxed);
        }

        fn invalidate_runtime_settings(&self) {}

        fn api_key_current_concurrency(&self, _api_key_id: i64) -> u32 {
            0
        }
    }

    fn proxy(
        id: i64,
        status: &str,
        expired: bool,
        fallback_mode: &str,
        backup_proxy_id: Option<i64>,
    ) -> ProxySnapshot {
        ProxySnapshot {
            id,
            status: status.to_owned(),
            expired,
            fallback_mode: fallback_mode.to_owned(),
            backup_proxy_id,
        }
    }

    #[test]
    fn validates_lifecycle_durations() {
        let mut config = MaintenanceConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.shutdown_timeout, Duration::from_secs(30));
        config.interval = Duration::ZERO;
        assert!(config.validate().is_err());
    }

    #[test]
    fn destructive_maintenance_sql_preserves_atomicity_and_worker_leases() {
        assert!(EXPIRE_PAYMENT_ORDERS_SQL.contains("WHERE status = 'PENDING'"));
        assert!(EXPIRE_PAYMENT_ORDERS_SQL.contains("RETURNING id"));
        assert!(EXPIRE_PAYMENT_ORDERS_SQL.contains("'ORDER_EXPIRED'"));
        assert!(EXPIRE_PAYMENT_ORDERS_SQL.contains("ON CONFLICT (order_id, action) DO NOTHING"));

        assert!(CLAIM_USAGE_CLEANUP_TASK_SQL.contains("status = 'pending'"));
        assert!(CLAIM_USAGE_CLEANUP_TASK_SQL.contains("status = 'running'"));
        assert!(CLAIM_USAGE_CLEANUP_TASK_SQL.contains("INTERVAL '30 minutes'"));
        assert!(CLAIM_USAGE_CLEANUP_TASK_SQL.contains("FOR UPDATE SKIP LOCKED"));
        assert!(CLAIM_USAGE_CLEANUP_TASK_SQL.contains("SET status = 'running'"));

        for cleanup in [
            CLEANUP_PENDING_AUTH_SESSIONS_SQL,
            CLEANUP_OAUTH_STATES_SQL,
            CLEANUP_WECHAT_RESUME_TOKENS_SQL,
            CLEANUP_ADMIN_OAUTH_SESSIONS_SQL,
        ] {
            assert!(cleanup.contains("expires_at <= NOW()"));
            assert!(cleanup.contains("consumed_at IS NOT NULL"));
        }
    }

    #[test]
    fn usage_cleanup_filters_reject_ranges_that_could_broaden_deletion() {
        let valid = serde_json::from_value::<UsageCleanupFilters>(serde_json::json!({
            "start_time": "2026-01-01T00:00:00Z",
            "end_time": "2026-01-02T00:00:00Z",
            "user_id": 7,
            "model": "  gpt-5  ",
            "request_type": 2,
            "stream": false
        }))
        .unwrap()
        .validate()
        .unwrap();
        assert_eq!(valid.model.as_deref(), Some("gpt-5"));

        for filters in [
            serde_json::json!({
                "start_time": "2026-01-02T00:00:00Z",
                "end_time": "2026-01-01T00:00:00Z"
            }),
            serde_json::json!({
                "start_time": "2026-01-01T00:00:00Z",
                "end_time": "2026-02-02T00:00:00Z"
            }),
            serde_json::json!({
                "start_time": "2026-01-01T00:00:00Z",
                "end_time": "2026-01-02T00:00:00Z",
                "user_id": -1
            }),
            serde_json::json!({
                "start_time": "2026-01-01T00:00:00Z",
                "end_time": "2026-01-02T00:00:00Z",
                "model": "   "
            }),
            serde_json::json!({
                "start_time": "2026-01-01T00:00:00Z",
                "end_time": "2026-01-02T00:00:00Z",
                "request_type": 9
            }),
        ] {
            assert!(
                serde_json::from_value::<UsageCleanupFilters>(filters)
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
    }

    #[test]
    fn proxy_fallback_resolves_proxy_direct_and_cycles() {
        let start = proxy(1, "active", true, "proxy", Some(2));
        let active = proxy(2, "active", false, "none", None);
        let graph = HashMap::from([(1, start.clone()), (2, active)]);
        assert_eq!(resolve_proxy_target(&start, &graph), ProxyTarget::Proxy(2));

        let direct = proxy(2, "expired", true, "direct", None);
        let graph = HashMap::from([(1, start.clone()), (2, direct)]);
        assert_eq!(resolve_proxy_target(&start, &graph), ProxyTarget::Direct);

        let cycle = proxy(2, "expired", true, "proxy", Some(1));
        let graph = HashMap::from([(1, start.clone()), (2, cycle)]);
        assert_eq!(resolve_proxy_target(&start, &graph), ProxyTarget::Unchanged);
    }

    #[tokio::test]
    async fn committed_changes_invalidate_local_caches_before_publish() {
        let pool = PgPoolOptions::new().connect_lazy_with(PgConnectOptions::new());
        pool.close().await;
        let target = Arc::new(FakeCacheTarget::default());
        let gateway_target: Arc<dyn GatewayAuthState> = target.clone();
        let invalidator = AuthCacheInvalidator::new(pool, gateway_target);
        let report = MaintenanceReport {
            lock_acquired: true,
            accounts_paused: 1,
            subscriptions_expired: 1,
            ..MaintenanceReport::default()
        };

        invalidate_maintenance_changes(&invalidator, &report).await;
        assert_eq!(target.auth.load(Ordering::Relaxed), 1);
        assert_eq!(target.accounts.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL pointing at a migrated disposable *_test database"]
    #[allow(clippy::too_many_lines)]
    async fn postgres_cycle_expires_orders_cleans_auth_and_executes_usage_tasks() {
        let database_url = env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL must point at a disposable *_test database");
        let parsed = url::Url::parse(&database_url).expect("database URL should parse");
        assert!(
            parsed.path().trim_matches('/').ends_with("_test"),
            "refusing to modify a database whose name does not end in _test"
        );
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&database_url)
            .await
            .expect("connect to PostgreSQL maintenance test database");
        let marker = Uuid::new_v4().simple().to_string();
        let user_id = sqlx::query_scalar::<_, i64>(
            "INSERT INTO users (email, password_hash, role) VALUES ($1, 'unused', 'admin') RETURNING id",
        )
        .bind(format!("rust-maintenance-{marker}@example.com"))
        .fetch_one(&pool)
        .await
        .expect("insert maintenance test user");
        let account_id = sqlx::query_scalar::<_, i64>(
            "INSERT INTO accounts (name, platform, type) VALUES ($1, 'anthropic', 'apikey') RETURNING id",
        )
        .bind(format!("rust-maintenance-{marker}"))
        .fetch_one(&pool)
        .await
        .expect("insert maintenance test account");
        let api_key_id = sqlx::query_scalar::<_, i64>(
            "INSERT INTO api_keys (user_id, key, name) VALUES ($1, $2, $3) RETURNING id",
        )
        .bind(user_id)
        .bind(format!("sk-maintenance-{marker}"))
        .bind(format!("rust-maintenance-{marker}"))
        .fetch_one(&pool)
        .await
        .expect("insert maintenance test API key");

        let matching_request = format!("maintenance-match-{marker}");
        let retained_request = format!("maintenance-retain-{marker}");
        for (request_id, model) in [
            (matching_request.as_str(), "maintenance-match"),
            (retained_request.as_str(), "maintenance-retain"),
        ] {
            sqlx::query(
                r"
INSERT INTO usage_logs (
    user_id, api_key_id, account_id, request_id, model,
    request_type, stream, openai_ws_mode, created_at
)
VALUES ($1, $2, $3, $4, $5, 1, FALSE, FALSE, NOW() - INTERVAL '10 minutes')
",
            )
            .bind(user_id)
            .bind(api_key_id)
            .bind(account_id)
            .bind(request_id)
            .bind(model)
            .execute(&pool)
            .await
            .expect("insert maintenance usage-log fixture");
        }
        let cleanup_task_id = sqlx::query_scalar::<_, i64>(
            r"
INSERT INTO usage_cleanup_tasks (status, filters, created_by, created_at, updated_at)
VALUES (
    'pending',
    jsonb_build_object(
        'start_time', to_char(NOW() - INTERVAL '1 hour', 'YYYY-MM-DD') || 'T' ||
                      to_char(NOW() - INTERVAL '1 hour', 'HH24:MI:SS') || 'Z',
        'end_time', to_char(NOW() + INTERVAL '1 hour', 'YYYY-MM-DD') || 'T' ||
                    to_char(NOW() + INTERVAL '1 hour', 'HH24:MI:SS') || 'Z',
        'user_id', $1::bigint,
        'model', 'maintenance-match',
        'request_type', 1
    ),
    $1,
    NOW() - INTERVAL '100 years',
    NOW() - INTERVAL '100 years'
)
RETURNING id
",
        )
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .expect("insert pending usage cleanup task");

        let payment_order_id = sqlx::query_scalar::<_, i64>(
            r"
INSERT INTO payment_orders (
    user_id, user_email, amount, pay_amount, expires_at, out_trade_no, status
)
VALUES ($1, $2, 1, 1, NOW() - INTERVAL '1 minute', $3, 'PENDING')
RETURNING id
",
        )
        .bind(user_id)
        .bind(format!("rust-maintenance-{marker}@example.com"))
        .bind(format!("maintenance-{marker}"))
        .fetch_one(&pool)
        .await
        .expect("insert expired payment order");

        let pending_auth_id = sqlx::query_scalar::<_, i64>(
            r"
INSERT INTO pending_auth_sessions (
    session_token, intent, provider_type, provider_key, provider_subject,
    expires_at, created_at, updated_at
)
VALUES ($1, 'login', 'email', 'email', $2, NOW() - INTERVAL '1 hour',
        NOW() - INTERVAL '2 hours', NOW() - INTERVAL '2 hours')
RETURNING id
",
        )
        .bind(format!("maintenance-session-{marker}"))
        .bind(format!("maintenance-subject-{marker}"))
        .fetch_one(&pool)
        .await
        .expect("insert expired pending authentication session");

        let mut state_hash = Vec::from(Uuid::new_v4().as_bytes());
        state_hash.extend_from_slice(Uuid::new_v4().as_bytes());
        let oauth_state_id = Uuid::new_v4();
        sqlx::query(
            r"
INSERT INTO auth_oauth_states (
    id, state_hash, provider_type, expires_at, consumed_at, created_at
)
VALUES ($1::uuid, $2, 'github', NOW() + INTERVAL '1 hour', NOW(), NOW() - INTERVAL '1 hour')
",
        )
        .bind(oauth_state_id.to_string())
        .bind(&state_hash)
        .execute(&pool)
        .await
        .expect("insert consumed OAuth state");

        let mut resume_hash = Vec::from(Uuid::new_v4().as_bytes());
        resume_hash.extend_from_slice(Uuid::new_v4().as_bytes());
        let resume_id = Uuid::new_v4();
        sqlx::query(
            r"
INSERT INTO auth_wechat_payment_resume_tokens (
    id, token_hash, openid, payment_type, expires_at, created_at
)
VALUES ($1::uuid, $2, $3, 'wxpay', NOW() - INTERVAL '1 hour', NOW() - INTERVAL '2 hours')
",
        )
        .bind(resume_id.to_string())
        .bind(&resume_hash)
        .bind(format!("maintenance-openid-{marker}"))
        .execute(&pool)
        .await
        .expect("insert expired WeChat resume token");

        let mut admin_state_hash = Vec::from(Uuid::new_v4().as_bytes());
        admin_state_hash.extend_from_slice(Uuid::new_v4().as_bytes());
        let admin_oauth_id = Uuid::new_v4();
        sqlx::query(
            r"
INSERT INTO admin_oauth_sessions (
    id, provider, state_hash, verifier_ciphertext, expires_at, created_at
)
VALUES ($1::uuid, 'openai', $2, 'ciphertext', NOW() - INTERVAL '1 hour',
        NOW() - INTERVAL '2 hours')
",
        )
        .bind(admin_oauth_id.to_string())
        .bind(&admin_state_hash)
        .execute(&pool)
        .await
        .expect("insert expired administrator OAuth session");

        let report = run_once(&pool)
            .await
            .expect("run PostgreSQL maintenance cycle");
        assert!(report.lock_acquired);
        assert!(report.payment_orders_expired >= 1);
        assert!(report.payment_audit_logs_created >= 1);
        assert!(report.pending_auth_sessions_deleted >= 1);
        assert!(report.oauth_states_deleted >= 1);
        assert!(report.wechat_resume_tokens_deleted >= 1);
        assert!(report.admin_oauth_sessions_deleted >= 1);
        assert_eq!(report.usage_cleanup_tasks_claimed, 1);
        assert_eq!(report.usage_cleanup_tasks_succeeded, 1);
        assert_eq!(report.usage_logs_deleted, 1);

        let payment_status =
            sqlx::query_scalar::<_, String>("SELECT status FROM payment_orders WHERE id = $1")
                .bind(payment_order_id)
                .fetch_one(&pool)
                .await
                .expect("load expired payment order");
        assert_eq!(payment_status, "EXPIRED");
        let audit_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM payment_audit_logs WHERE order_id = $1 AND action = 'ORDER_EXPIRED'",
        )
        .bind(payment_order_id.to_string())
        .fetch_one(&pool)
        .await
        .expect("count payment expiry audit rows");
        assert_eq!(audit_count, 1);
        let task = sqlx::query_as::<_, (String, i64)>(
            "SELECT status, deleted_rows FROM usage_cleanup_tasks WHERE id = $1",
        )
        .bind(cleanup_task_id)
        .fetch_one(&pool)
        .await
        .expect("load completed usage cleanup task");
        assert_eq!(task, ("succeeded".to_owned(), 1));
        let retained =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM usage_logs WHERE request_id = $1")
                .bind(&retained_request)
                .fetch_one(&pool)
                .await
                .expect("count retained usage log");
        assert_eq!(retained, 1);
        for (table, id) in [
            ("pending_auth_sessions", pending_auth_id.to_string()),
            ("auth_oauth_states", oauth_state_id.to_string()),
            ("auth_wechat_payment_resume_tokens", resume_id.to_string()),
            ("admin_oauth_sessions", admin_oauth_id.to_string()),
        ] {
            let query = format!("SELECT COUNT(*) FROM {table} WHERE id::text = $1");
            let count = sqlx::query_scalar::<_, i64>(&query)
                .bind(id)
                .fetch_one(&pool)
                .await
                .expect("count cleaned authentication state");
            assert_eq!(count, 0, "{table} fixture should be deleted");
        }

        run_once(&pool)
            .await
            .expect("repeat maintenance cycle idempotently");
        let audit_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM payment_audit_logs WHERE order_id = $1 AND action = 'ORDER_EXPIRED'",
        )
        .bind(payment_order_id.to_string())
        .fetch_one(&pool)
        .await
        .expect("recount payment expiry audit rows");
        assert_eq!(audit_count, 1);

        sqlx::query("DELETE FROM payment_audit_logs WHERE order_id = $1")
            .bind(payment_order_id.to_string())
            .execute(&pool)
            .await
            .expect("delete payment audit fixture");
        sqlx::query("DELETE FROM payment_orders WHERE id = $1")
            .bind(payment_order_id)
            .execute(&pool)
            .await
            .expect("delete payment-order fixture");
        sqlx::query("DELETE FROM usage_cleanup_tasks WHERE id = $1")
            .bind(cleanup_task_id)
            .execute(&pool)
            .await
            .expect("delete usage cleanup task fixture");
        sqlx::query("DELETE FROM usage_logs WHERE request_id = $1")
            .bind(&retained_request)
            .execute(&pool)
            .await
            .expect("delete retained usage-log fixture");
        sqlx::query("DELETE FROM api_keys WHERE id = $1")
            .bind(api_key_id)
            .execute(&pool)
            .await
            .expect("delete API-key fixture");
        sqlx::query("DELETE FROM accounts WHERE id = $1")
            .bind(account_id)
            .execute(&pool)
            .await
            .expect("delete account fixture");
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("delete user fixture");
        pool.close().await;
    }
}
