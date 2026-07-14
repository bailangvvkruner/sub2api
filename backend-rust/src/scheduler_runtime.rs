//! PostgreSQL-backed runtime for scheduled account tests and channel monitors.
//!
//! Every job is claimed with a transaction-scoped advisory lock. The lock is
//! held through the upstream request and the durable result write, so a crash
//! rolls the whole attempt back and another replica can recover the same due
//! job without Redis or a separate lease table.

#![allow(
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::too_many_lines
)]

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    error::Error,
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::security::secrets;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Datelike, Local, Timelike, Utc};
use futures_util::StreamExt;
use rand::{RngCore, rngs::OsRng};
use reqwest::{Client, Proxy, redirect::Policy};
use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, Row, Transaction};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    task::{JoinHandle, JoinSet},
    time::{self, MissedTickBehavior},
};
use tokio_util::sync::CancellationToken;
use url::{Host, Url};

use crate::admin_api::validate_public_probe_target;

const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(45);
const DEFAULT_PING_TIMEOUT: Duration = Duration::from_secs(8);
const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_MAX_CONCURRENCY: usize = 10;
const DEFAULT_MAX_CANDIDATES: usize = 100;
const DEFAULT_RESPONSE_LIMIT: usize = 64 * 1024;
const DEGRADED_MILLIS: i32 = 6_000;
const MIN_MONITOR_INTERVAL_SECONDS: i64 = 15;
const MAX_CRON_SEARCH_MINUTES: i64 = 8 * 366 * 24 * 60;

/// Runtime tuning for both `PostgreSQL` control-plane schedulers.
#[derive(Clone, Debug)]
pub struct SchedulerRuntimeConfig {
    pub poll_interval: Duration,
    pub request_timeout: Duration,
    pub ping_timeout: Duration,
    pub shutdown_timeout: Duration,
    pub max_concurrency: usize,
    pub max_candidates_per_poll: usize,
    pub response_limit_bytes: usize,
}

impl Default for SchedulerRuntimeConfig {
    fn default() -> Self {
        Self {
            poll_interval: DEFAULT_POLL_INTERVAL,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            ping_timeout: DEFAULT_PING_TIMEOUT,
            shutdown_timeout: DEFAULT_SHUTDOWN_TIMEOUT,
            max_concurrency: DEFAULT_MAX_CONCURRENCY,
            max_candidates_per_poll: DEFAULT_MAX_CANDIDATES,
            response_limit_bytes: DEFAULT_RESPONSE_LIMIT,
        }
    }
}

impl SchedulerRuntimeConfig {
    fn validate(&self) -> std::result::Result<(), SchedulerRuntimeError> {
        if self.poll_interval.is_zero() {
            return Err(SchedulerRuntimeError::InvalidConfig(
                "poll_interval must be greater than zero",
            ));
        }
        if self.request_timeout.is_zero() || self.ping_timeout.is_zero() {
            return Err(SchedulerRuntimeError::InvalidConfig(
                "HTTP timeouts must be greater than zero",
            ));
        }
        if self.shutdown_timeout.is_zero() {
            return Err(SchedulerRuntimeError::InvalidConfig(
                "shutdown_timeout must be greater than zero",
            ));
        }
        if self.max_concurrency == 0 {
            return Err(SchedulerRuntimeError::InvalidConfig(
                "max_concurrency must be greater than zero",
            ));
        }
        if self.max_candidates_per_poll == 0 || i64::try_from(self.max_candidates_per_poll).is_err()
        {
            return Err(SchedulerRuntimeError::InvalidConfig(
                "max_candidates_per_poll is outside the supported range",
            ));
        }
        if self.response_limit_bytes == 0 {
            return Err(SchedulerRuntimeError::InvalidConfig(
                "response_limit_bytes must be greater than zero",
            ));
        }
        Ok(())
    }
}

/// Failure to start or cleanly stop the scheduler runtime.
#[derive(Debug)]
pub enum SchedulerRuntimeError {
    InvalidConfig(&'static str),
    Join(tokio::task::JoinError),
    ShutdownTimedOut(Duration),
}

impl fmt::Display for SchedulerRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => formatter.write_str(message),
            Self::Join(error) => write!(formatter, "scheduler runtime task failed: {error}"),
            Self::ShutdownTimedOut(timeout) => {
                write!(
                    formatter,
                    "scheduler runtime shutdown timed out after {timeout:?}"
                )
            }
        }
    }
}

impl Error for SchedulerRuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Join(error) => Some(error),
            Self::InvalidConfig(_) | Self::ShutdownTimedOut(_) => None,
        }
    }
}

/// Handle for the scheduled-test and channel-monitor background loops.
pub struct SchedulerRuntime {
    cancellation: CancellationToken,
    task: Option<JoinHandle<()>>,
    shutdown_timeout: Duration,
}

impl SchedulerRuntime {
    /// Starts both `PostgreSQL` schedulers. The first scan runs immediately.
    pub fn spawn(
        pool: PgPool,
        config: SchedulerRuntimeConfig,
    ) -> std::result::Result<Self, SchedulerRuntimeError> {
        config.validate()?;
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let shutdown_timeout = config.shutdown_timeout;
        let monitor_key = match monitor_key_from_env() {
            Ok(key) => key,
            Err(error) => {
                tracing::warn!(%error, "channel monitor encryption key is unavailable");
                None
            }
        };
        let task = tokio::spawn(scheduler_loop(
            pool,
            Arc::new(config),
            monitor_key,
            task_cancellation,
        ));
        tracing::info!("PostgreSQL scheduled-test and channel-monitor runtime started");
        Ok(Self {
            cancellation,
            task: Some(task),
            shutdown_timeout,
        })
    }

    /// Cancels pending HTTP work and waits for every worker to join.
    pub async fn shutdown(mut self) -> std::result::Result<(), SchedulerRuntimeError> {
        self.cancellation.cancel();
        let Some(mut task) = self.task.take() else {
            return Ok(());
        };
        if let Ok(result) = time::timeout(self.shutdown_timeout, &mut task).await {
            result.map_err(SchedulerRuntimeError::Join)
        } else {
            task.abort();
            let _ = task.await;
            Err(SchedulerRuntimeError::ShutdownTimedOut(
                self.shutdown_timeout,
            ))
        }
    }
}

impl Drop for SchedulerRuntime {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum WorkKey {
    ScheduledTest(i64),
    ChannelMonitor(i64),
}

async fn scheduler_loop(
    pool: PgPool,
    config: Arc<SchedulerRuntimeConfig>,
    monitor_key: Option<[u8; 32]>,
    cancellation: CancellationToken,
) {
    let permits = Arc::new(Semaphore::new(config.max_concurrency));
    let mut workers = JoinSet::new();
    let mut in_flight = HashSet::new();
    let mut ticker = time::interval(config.poll_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            () = cancellation.cancelled() => break,
            _ = ticker.tick() => {
                let work = load_due_work(&pool, &config).await;
                for key in work {
                    if in_flight.contains(&key) {
                        continue;
                    }
                    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                        break;
                    };
                    in_flight.insert(key);
                    let worker_pool = pool.clone();
                    let worker_config = Arc::clone(&config);
                    let worker_cancellation = cancellation.clone();
                    workers.spawn(async move {
                        let result = run_work(
                            &worker_pool,
                            &worker_config,
                            monitor_key.as_ref(),
                            &worker_cancellation,
                            key,
                            permit,
                        )
                        .await;
                        (key, result)
                    });
                }
            }
            joined = workers.join_next(), if !workers.is_empty() => {
                handle_worker_join(joined, &mut in_flight);
            }
        }
    }

    cancellation.cancel();
    while let Some(joined) = workers.join_next().await {
        handle_worker_join(Some(joined), &mut in_flight);
    }
    tracing::info!("PostgreSQL scheduled-test and channel-monitor workers stopped");
}

fn handle_worker_join(
    joined: Option<std::result::Result<(WorkKey, Result<()>), tokio::task::JoinError>>,
    in_flight: &mut HashSet<WorkKey>,
) {
    match joined {
        Some(Ok((key, Ok(())))) => {
            in_flight.remove(&key);
        }
        Some(Ok((key, Err(error)))) => {
            in_flight.remove(&key);
            tracing::warn!(?key, error = %error, "control-plane scheduled job failed");
        }
        Some(Err(error)) => {
            // A panic loses the returned key. Advisory locks still prevent a
            // duplicate durable execution, so allow all keys to be rediscovered.
            in_flight.clear();
            tracing::error!(%error, "control-plane scheduled worker panicked");
        }
        None => {}
    }
}

async fn load_due_work(pool: &PgPool, config: &SchedulerRuntimeConfig) -> Vec<WorkKey> {
    let limit = i64::try_from(config.max_candidates_per_poll).unwrap_or(i64::MAX);
    let scheduled = load_due_scheduled_tests(pool, limit);
    let monitors = load_due_channel_monitors(pool, limit);
    let (scheduled, monitors) = tokio::join!(scheduled, monitors);
    let scheduled = scheduled.unwrap_or_else(|error| {
        tracing::warn!(%error, "failed to scan due scheduled test plans");
        Vec::new()
    });
    let monitors = monitors.unwrap_or_else(|error| {
        tracing::warn!(%error, "failed to scan due channel monitors");
        Vec::new()
    });
    interleave_work(scheduled, monitors)
}

async fn load_due_scheduled_tests(pool: &PgPool, limit: i64) -> Result<Vec<i64>> {
    sqlx::query_scalar::<_, i64>(
        r"SELECT id
           FROM scheduled_test_plans
           WHERE enabled = TRUE
             AND (next_run_at IS NULL OR next_run_at <= NOW())
           ORDER BY next_run_at NULLS FIRST, id
           LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("query due scheduled test plans")
}

async fn load_due_channel_monitors(pool: &PgPool, limit: i64) -> Result<Vec<i64>> {
    if !channel_monitors_enabled(pool).await? {
        return Ok(Vec::new());
    }
    sqlx::query_scalar::<_, i64>(
        r"SELECT id
           FROM channel_monitors
           WHERE enabled = TRUE
             AND (
               last_checked_at IS NULL
               OR last_checked_at + make_interval(
                    secs => GREATEST(15, interval_seconds - GREATEST(jitter_seconds, 0))
                  ) <= NOW()
             )
           ORDER BY last_checked_at NULLS FIRST, id
           LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("query due channel monitors")
}

async fn channel_monitors_enabled(pool: &PgPool) -> Result<bool> {
    let value = sqlx::query_scalar::<_, Option<String>>(
        "SELECT (SELECT value FROM settings WHERE key = 'channel_monitor_enabled')",
    )
    .fetch_one(pool)
    .await
    .context("read channel monitor feature switch")?;
    Ok(value.as_deref().is_none_or(setting_is_true))
}

fn setting_is_true(raw: &str) -> bool {
    !matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "off" | "no" | "disabled"
    )
}

fn interleave_work(scheduled: Vec<i64>, monitors: Vec<i64>) -> Vec<WorkKey> {
    let mut result = Vec::with_capacity(scheduled.len() + monitors.len());
    let mut scheduled = scheduled.into_iter();
    let mut monitors = monitors.into_iter();
    loop {
        let left = scheduled.next();
        let right = monitors.next();
        if left.is_none() && right.is_none() {
            break;
        }
        if let Some(id) = left {
            result.push(WorkKey::ScheduledTest(id));
        }
        if let Some(id) = right {
            result.push(WorkKey::ChannelMonitor(id));
        }
    }
    result
}

async fn run_work(
    pool: &PgPool,
    config: &SchedulerRuntimeConfig,
    monitor_key: Option<&[u8; 32]>,
    cancellation: &CancellationToken,
    key: WorkKey,
    _permit: OwnedSemaphorePermit,
) -> Result<()> {
    match key {
        WorkKey::ScheduledTest(id) => process_scheduled_test(pool, config, cancellation, id).await,
        WorkKey::ChannelMonitor(id) => {
            process_channel_monitor(pool, config, monitor_key, cancellation, id).await
        }
    }
}

async fn try_advisory_lock(transaction: &mut Transaction<'_, Postgres>, key: &str) -> Result<bool> {
    sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(key)
        .fetch_one(&mut **transaction)
        .await
        .context("acquire scheduler advisory lock")
}

#[derive(Debug)]
struct ScheduledPlan {
    id: i64,
    account_id: i64,
    model: String,
    cron_expression: String,
    max_results: i32,
    auto_recover: bool,
    next_run_epoch: Option<i64>,
    account_deleted: bool,
    platform: String,
    account_type: String,
    credentials: Value,
    extra: Value,
    proxy_id: Option<i64>,
    proxy: Option<ProxySettings>,
}

#[derive(Clone, Debug)]
struct ProxySettings {
    protocol: String,
    host: String,
    port: i32,
    username: String,
    password: String,
}

async fn process_scheduled_test(
    pool: &PgPool,
    config: &SchedulerRuntimeConfig,
    cancellation: &CancellationToken,
    id: i64,
) -> Result<()> {
    let mut transaction = pool.begin().await.context("begin scheduled test claim")?;
    let lock_key = format!("sub2api:scheduled-test:{id}");
    if !try_advisory_lock(&mut transaction, &lock_key).await? {
        return Ok(());
    }
    let Some(plan) = load_scheduled_plan(&mut transaction, id).await? else {
        return Ok(());
    };
    if plan.account_deleted {
        sqlx::query(
            "UPDATE scheduled_test_plans SET enabled = FALSE, next_run_at = NULL, updated_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .execute(&mut *transaction)
        .await
        .context("disable scheduled test for deleted account")?;
        transaction.commit().await?;
        return Ok(());
    }

    let schedule = match CronSchedule::parse(&plan.cron_expression) {
        Ok(schedule) => schedule,
        Err(error) => {
            let now = Utc::now().timestamp();
            let outcome = ScheduledProbeOutcome::failed(
                now,
                now,
                &format!("invalid cron expression: {error}"),
            );
            persist_scheduled_outcome(&mut transaction, &plan, &outcome, None, true).await?;
            transaction.commit().await?;
            return Ok(());
        }
    };

    let now = Utc::now();
    if plan.next_run_epoch.is_none() {
        let next = match schedule.next_after(now) {
            Ok(next) => next.timestamp(),
            Err(error) => {
                let now = now.timestamp();
                let outcome = ScheduledProbeOutcome::failed(
                    now,
                    now,
                    &format!("cron expression cannot produce a next run: {error}"),
                );
                persist_scheduled_outcome(&mut transaction, &plan, &outcome, None, true).await?;
                transaction.commit().await?;
                return Ok(());
            }
        };
        sqlx::query(
            r"UPDATE scheduled_test_plans
               SET next_run_at = to_timestamp($2::double precision), updated_at = NOW()
               WHERE id = $1 AND enabled = TRUE AND next_run_at IS NULL",
        )
        .bind(id)
        .bind(next)
        .execute(&mut *transaction)
        .await
        .context("recover missing scheduled test next_run_at")?;
        transaction.commit().await?;
        return Ok(());
    }
    if plan
        .next_run_epoch
        .is_some_and(|next| next > now.timestamp())
    {
        return Ok(());
    }

    let outcome = run_scheduled_probe(&plan, config, cancellation).await?;
    let latest = load_latest_schedule_settings(&mut transaction, id).await?;
    let (next_run, disable) = if let Some(latest) = latest.as_ref() {
        match CronSchedule::parse(&latest.cron_expression)
            .and_then(|schedule| schedule.next_after(Utc::now()))
        {
            Ok(next) => (Some(next.timestamp()), false),
            Err(error) => {
                tracing::warn!(plan_id = id, %error, "scheduled test cron became invalid during execution");
                (None, true)
            }
        }
    } else {
        (None, false)
    };
    let mut current = plan;
    if let Some(latest) = latest {
        current.max_results = latest.max_results;
        current.auto_recover = latest.auto_recover;
    }
    persist_scheduled_outcome(&mut transaction, &current, &outcome, next_run, disable).await?;
    transaction
        .commit()
        .await
        .context("commit scheduled test result")?;
    Ok(())
}

async fn load_scheduled_plan(
    transaction: &mut Transaction<'_, Postgres>,
    id: i64,
) -> Result<Option<ScheduledPlan>> {
    let row = sqlx::query(
        r"SELECT p.id, p.account_id, p.model_id, p.cron_expression, p.max_results,
                  p.auto_recover,
                  EXTRACT(EPOCH FROM p.next_run_at)::bigint AS next_run_epoch,
                  (a.deleted_at IS NOT NULL) AS account_deleted,
                  a.platform, a.type AS account_type,
                  a.credentials::text AS credentials_json,
                  a.extra::text AS extra_json, a.proxy_id,
                  px.id AS active_proxy_id, px.protocol AS proxy_protocol,
                  px.host AS proxy_host, px.port AS proxy_port,
                  COALESCE(px.username, '') AS proxy_username,
                  COALESCE(px.password, '') AS proxy_password
           FROM scheduled_test_plans p
           JOIN accounts a ON a.id = p.account_id
           LEFT JOIN proxies px ON px.id = a.proxy_id
             AND px.deleted_at IS NULL AND px.status = 'active'
           WHERE p.id = $1 AND p.enabled = TRUE",
    )
    .bind(id)
    .fetch_optional(&mut **transaction)
    .await
    .context("load claimed scheduled test plan")?;
    row.map(|row| {
        let credentials_raw: String = row.try_get("credentials_json")?;
        let extra_raw: String = row.try_get("extra_json")?;
        let proxy_id: Option<i64> = row.try_get("proxy_id")?;
        let active_proxy_id: Option<i64> = row.try_get("active_proxy_id")?;
        let proxy = if active_proxy_id.is_some() {
            Some(ProxySettings {
                protocol: row.try_get("proxy_protocol")?,
                host: row.try_get("proxy_host")?,
                port: row.try_get("proxy_port")?,
                username: row.try_get("proxy_username")?,
                password: row.try_get("proxy_password")?,
            })
        } else {
            None
        };
        Ok(ScheduledPlan {
            id: row.try_get("id")?,
            account_id: row.try_get("account_id")?,
            model: row.try_get("model_id")?,
            cron_expression: row.try_get("cron_expression")?,
            max_results: row.try_get("max_results")?,
            auto_recover: row.try_get("auto_recover")?,
            next_run_epoch: row.try_get("next_run_epoch")?,
            account_deleted: row.try_get("account_deleted")?,
            platform: row.try_get("platform")?,
            account_type: row.try_get("account_type")?,
            credentials: parse_json(&credentials_raw, "account credentials")?,
            extra: parse_json(&extra_raw, "account extra")?,
            proxy_id,
            proxy,
        })
    })
    .transpose()
}

#[derive(Debug)]
struct LatestScheduleSettings {
    cron_expression: String,
    max_results: i32,
    auto_recover: bool,
}

async fn load_latest_schedule_settings(
    transaction: &mut Transaction<'_, Postgres>,
    id: i64,
) -> Result<Option<LatestScheduleSettings>> {
    sqlx::query(
        r"SELECT cron_expression, max_results, auto_recover
           FROM scheduled_test_plans WHERE id = $1 AND enabled = TRUE",
    )
    .bind(id)
    .fetch_optional(&mut **transaction)
    .await
    .context("reload scheduled test settings")?
    .map(|row| {
        Ok(LatestScheduleSettings {
            cron_expression: row.try_get("cron_expression")?,
            max_results: row.try_get("max_results")?,
            auto_recover: row.try_get("auto_recover")?,
        })
    })
    .transpose()
}

#[derive(Debug)]
struct ScheduledProbeOutcome {
    status: &'static str,
    response_text: String,
    error_message: String,
    latency_ms: i64,
    started_epoch: i64,
    finished_epoch: i64,
}

impl ScheduledProbeOutcome {
    fn failed(started_epoch: i64, finished_epoch: i64, error_message: &str) -> Self {
        Self {
            status: "failed",
            response_text: String::new(),
            error_message: truncate_chars(error_message, 4_000),
            latency_ms: finished_epoch
                .saturating_sub(started_epoch)
                .saturating_mul(1_000),
            started_epoch,
            finished_epoch,
        }
    }
}

async fn run_scheduled_probe(
    plan: &ScheduledPlan,
    config: &SchedulerRuntimeConfig,
    cancellation: &CancellationToken,
) -> Result<ScheduledProbeOutcome> {
    let started_epoch = Utc::now().timestamp();
    let started = Instant::now();
    let result = execute_account_probe(plan, config, cancellation).await;
    if cancellation.is_cancelled() {
        bail!("scheduled account test cancelled during shutdown");
    }
    let finished_epoch = Utc::now().timestamp();
    let latency_ms = millis_i64(started.elapsed());
    match result {
        Ok(response_text) => Ok(ScheduledProbeOutcome {
            status: "success",
            response_text: truncate_chars(&response_text, config.response_limit_bytes),
            error_message: String::new(),
            latency_ms,
            started_epoch,
            finished_epoch,
        }),
        Err(error) => Ok(ScheduledProbeOutcome {
            status: "failed",
            response_text: String::new(),
            error_message: truncate_chars(&sanitize_account_error(&error.to_string(), plan), 4_000),
            latency_ms,
            started_epoch,
            finished_epoch,
        }),
    }
}

async fn execute_account_probe(
    plan: &ScheduledPlan,
    config: &SchedulerRuntimeConfig,
    cancellation: &CancellationToken,
) -> Result<String> {
    let model = plan.model.trim();
    if model.is_empty() {
        bail!("scheduled test model is empty");
    }
    if plan.proxy_id.is_some() && plan.proxy.is_none() {
        bail!("configured account proxy is unavailable");
    }
    let base_url = account_base_url(plan)?;
    let credential = account_credential(plan)?;
    let client = pinned_client(&base_url, config.request_timeout, plan.proxy.as_ref()).await?;
    let auth_style = account_auth_style(&plan.platform, &plan.account_type);
    let api_mode = account_api_mode(plan);
    let extra_headers = account_request_headers(plan)?;
    let request = provider_request(ProviderRequest {
        provider: &plan.platform,
        api_mode,
        base_url: &base_url,
        credential: &credential,
        auth_style,
        model,
        prompt: "hi",
        extra_headers: &extra_headers,
        body_override_mode: "off",
        body_override: None,
    })?;
    let response =
        send_provider_request(&client, request, config.response_limit_bytes, cancellation).await?;
    if !(200..300).contains(&response.status) {
        bail!(
            "upstream HTTP {}: {}",
            response.status,
            compact_body(&response.raw)
        );
    }
    if response.text.trim().is_empty() {
        bail!("upstream returned a successful response without model output");
    }
    Ok(response.text)
}

fn account_base_url(plan: &ScheduledPlan) -> Result<String> {
    for value in [&plan.credentials, &plan.extra] {
        for key in ["base_url", "api_base_url", "endpoint", "custom_base_url"] {
            if let Some(url) = json_nonempty_string(value, key) {
                return Ok(url);
            }
        }
    }
    match plan.platform.trim().to_ascii_lowercase().as_str() {
        "openai" if !plan.account_type.eq_ignore_ascii_case("apikey") => {
            Ok("https://chatgpt.com/backend-api/codex".to_owned())
        }
        "openai" => Ok("https://api.openai.com".to_owned()),
        "grok" | "xai" => Ok("https://api.x.ai".to_owned()),
        "gemini" | "antigravity" => Ok("https://generativelanguage.googleapis.com".to_owned()),
        "anthropic" => Ok("https://api.anthropic.com".to_owned()),
        platform => bail!("unsupported scheduled test platform {platform:?}"),
    }
}

fn account_credential(plan: &ScheduledPlan) -> Result<String> {
    for value in [&plan.credentials, &plan.extra] {
        for key in ["api_key", "access_token", "token"] {
            if let Some(credential) = json_nonempty_string(value, key) {
                return Ok(credential);
            }
        }
    }
    bail!("account has no usable upstream credential")
}

fn json_nonempty_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn account_auth_style(platform: &str, account_type: &str) -> AuthStyle {
    if account_type.eq_ignore_ascii_case("apikey") {
        match platform.to_ascii_lowercase().as_str() {
            "anthropic" => AuthStyle::AnthropicApiKey,
            "gemini" | "antigravity" => AuthStyle::GeminiApiKey,
            _ => AuthStyle::Bearer,
        }
    } else {
        AuthStyle::Bearer
    }
}

fn account_api_mode(plan: &ScheduledPlan) -> &'static str {
    match plan.platform.trim().to_ascii_lowercase().as_str() {
        "grok" | "xai" => "responses",
        "openai" if !plan.account_type.eq_ignore_ascii_case("apikey") => "responses",
        "openai" => {
            match plan
                .extra
                .get("openai_responses_mode")
                .and_then(Value::as_str)
            {
                Some("force_chat_completions") => "chat_completions",
                Some("force_responses") => "responses",
                _ if plan
                    .extra
                    .get("openai_responses_supported")
                    .and_then(Value::as_bool)
                    == Some(false) =>
                {
                    "chat_completions"
                }
                _ => "responses",
            }
        }
        _ => "chat_completions",
    }
}

fn account_request_headers(plan: &ScheduledPlan) -> Result<BTreeMap<String, String>> {
    let mut headers = plan
        .credentials
        .get("header_overrides")
        .map(|value| {
            serde_json::from_value::<BTreeMap<String, String>>(value.clone())
                .context("parse account header_overrides")
        })
        .transpose()?
        .unwrap_or_default();
    if plan.platform.eq_ignore_ascii_case("openai")
        && !plan.account_type.eq_ignore_ascii_case("apikey")
    {
        headers
            .entry("accept".to_owned())
            .or_insert_with(|| "application/json".to_owned());
        headers
            .entry("openai-beta".to_owned())
            .or_insert_with(|| "responses=experimental".to_owned());
        headers
            .entry("originator".to_owned())
            .or_insert_with(|| "codex_cli_rs".to_owned());
        headers
            .entry("user-agent".to_owned())
            .or_insert_with(|| "codex_cli_rs/0.1".to_owned());
        if let Some(account_id) = json_nonempty_string(&plan.credentials, "chatgpt_account_id") {
            headers
                .entry("chatgpt-account-id".to_owned())
                .or_insert(account_id);
        }
    }
    Ok(headers)
}

async fn persist_scheduled_outcome(
    transaction: &mut Transaction<'_, Postgres>,
    plan: &ScheduledPlan,
    outcome: &ScheduledProbeOutcome,
    next_run_epoch: Option<i64>,
    disable: bool,
) -> Result<()> {
    sqlx::query(
        r"INSERT INTO scheduled_test_results
          (plan_id, status, response_text, error_message, latency_ms,
           started_at, finished_at, created_at)
          VALUES ($1, $2, $3, $4, $5,
                  to_timestamp($6::double precision),
                  to_timestamp($7::double precision), NOW())",
    )
    .bind(plan.id)
    .bind(outcome.status)
    .bind(&outcome.response_text)
    .bind(&outcome.error_message)
    .bind(outcome.latency_ms)
    .bind(outcome.started_epoch)
    .bind(outcome.finished_epoch)
    .execute(&mut **transaction)
    .await
    .context("insert scheduled test result")?;

    let keep = i64::from(plan.max_results.max(1));
    sqlx::query(
        r"DELETE FROM scheduled_test_results
           WHERE id IN (
             SELECT id FROM (
               SELECT id, ROW_NUMBER() OVER (ORDER BY created_at DESC, id DESC) AS position
               FROM scheduled_test_results WHERE plan_id = $1
             ) ranked WHERE position > $2
           )",
    )
    .bind(plan.id)
    .bind(keep)
    .execute(&mut **transaction)
    .await
    .context("prune scheduled test results")?;

    sqlx::query(
        r"UPDATE scheduled_test_plans
           SET last_run_at = to_timestamp($2::double precision),
               next_run_at = CASE WHEN $3::bigint IS NULL THEN NULL
                                  ELSE to_timestamp($3::double precision) END,
               enabled = CASE WHEN $4 THEN FALSE ELSE enabled END,
               updated_at = NOW()
           WHERE id = $1",
    )
    .bind(plan.id)
    .bind(outcome.finished_epoch)
    .bind(next_run_epoch)
    .bind(disable)
    .execute(&mut **transaction)
    .await
    .context("advance scheduled test plan")?;

    if outcome.status == "success" && plan.auto_recover {
        recover_account_runtime_state(transaction, plan.account_id).await?;
    }
    Ok(())
}

async fn recover_account_runtime_state(
    transaction: &mut Transaction<'_, Postgres>,
    account_id: i64,
) -> Result<()> {
    sqlx::query(
        r"UPDATE accounts
           SET status = CASE WHEN status = 'error' THEN 'active' ELSE status END,
               error_message = CASE WHEN status = 'error' THEN '' ELSE error_message END,
               rate_limited_at = NULL,
               rate_limit_reset_at = NULL,
               overload_until = NULL,
               temp_unschedulable_until = NULL,
               temp_unschedulable_reason = NULL,
               extra = (COALESCE(extra, '{}'::jsonb)
                        - 'model_rate_limits' - 'antigravity_quota_scopes'),
               updated_at = NOW()
           WHERE id = $1 AND deleted_at IS NULL
             AND (
               status = 'error' OR rate_limited_at IS NOT NULL
               OR rate_limit_reset_at IS NOT NULL OR overload_until IS NOT NULL
               OR temp_unschedulable_until IS NOT NULL
               OR COALESCE(extra, '{}'::jsonb) ? 'model_rate_limits'
               OR COALESCE(extra, '{}'::jsonb) ? 'antigravity_quota_scopes'
             )",
    )
    .bind(account_id)
    .execute(&mut **transaction)
    .await
    .context("recover account after successful scheduled test")?;
    Ok(())
}

#[derive(Debug)]
struct MonitorSnapshot {
    id: i64,
    provider: String,
    api_mode: String,
    endpoint: String,
    encrypted_api_key: String,
    primary_model: String,
    extra_models: Vec<String>,
    interval_seconds: i64,
    jitter_seconds: i64,
    last_checked_epoch: Option<i64>,
    extra_headers: BTreeMap<String, String>,
    body_override_mode: String,
    body_override: Option<Value>,
    config_error: Option<String>,
}

async fn process_channel_monitor(
    pool: &PgPool,
    config: &SchedulerRuntimeConfig,
    monitor_key: Option<&[u8; 32]>,
    cancellation: &CancellationToken,
    id: i64,
) -> Result<()> {
    let mut transaction = pool.begin().await.context("begin channel monitor claim")?;
    let lock_key = format!("sub2api:channel-monitor:{id}");
    if !try_advisory_lock(&mut transaction, &lock_key).await? {
        return Ok(());
    }
    if !channel_monitors_enabled_in_transaction(&mut transaction).await? {
        return Ok(());
    }
    let Some(monitor) = load_monitor_snapshot(&mut transaction, id).await? else {
        return Ok(());
    };
    let now = Utc::now().timestamp();
    if !monitor_is_due(&monitor, now) {
        return Ok(());
    }

    let results = run_monitor_checks(&monitor, config, monitor_key, cancellation).await?;
    let checked_epoch = results
        .iter()
        .map(|result| result.checked_epoch)
        .max()
        .unwrap_or(now);
    if !persist_monitor_results(&mut transaction, id, &results, checked_epoch).await? {
        return Ok(());
    }
    transaction
        .commit()
        .await
        .context("commit channel monitor results")?;
    Ok(())
}

async fn persist_monitor_results(
    transaction: &mut Transaction<'_, Postgres>,
    id: i64,
    results: &[MonitorCheckResult],
    checked_epoch: i64,
) -> Result<bool> {
    let claimed = sqlx::query_scalar::<_, i64>(
        r"UPDATE channel_monitors
           SET last_checked_at = to_timestamp($2::double precision)
           WHERE id = $1 AND enabled = TRUE
           RETURNING id",
    )
    .bind(id)
    .bind(checked_epoch)
    .fetch_optional(&mut **transaction)
    .await
    .context("advance channel monitor last_checked_at")?;
    if claimed.is_none() {
        return Ok(false);
    }
    for result in results {
        sqlx::query(
            r"INSERT INTO channel_monitor_histories
              (monitor_id, model, status, latency_ms, ping_latency_ms, message, checked_at)
              VALUES ($1, $2, $3, $4, $5, $6,
                      to_timestamp($7::double precision))",
        )
        .bind(id)
        .bind(&result.model)
        .bind(&result.status)
        .bind(result.latency_ms)
        .bind(result.ping_latency_ms)
        .bind(&result.message)
        .bind(result.checked_epoch)
        .execute(&mut **transaction)
        .await
        .context("insert channel monitor history")?;
    }
    Ok(true)
}

async fn channel_monitors_enabled_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<bool> {
    let value = sqlx::query_scalar::<_, Option<String>>(
        "SELECT (SELECT value FROM settings WHERE key = 'channel_monitor_enabled')",
    )
    .fetch_one(&mut **transaction)
    .await
    .context("read channel monitor feature switch while claiming")?;
    Ok(value.as_deref().is_none_or(setting_is_true))
}

async fn load_monitor_snapshot(
    transaction: &mut Transaction<'_, Postgres>,
    id: i64,
) -> Result<Option<MonitorSnapshot>> {
    let row = sqlx::query(
        r"SELECT id, provider, api_mode, endpoint, api_key_encrypted,
                  primary_model, extra_models::text AS extra_models_json,
                  interval_seconds::bigint, jitter_seconds::bigint,
                  EXTRACT(EPOCH FROM last_checked_at)::bigint AS last_checked_epoch,
                  extra_headers::text AS extra_headers_json,
                  body_override_mode, body_override::text AS body_override_json
           FROM channel_monitors WHERE id = $1 AND enabled = TRUE",
    )
    .bind(id)
    .fetch_optional(&mut **transaction)
    .await
    .context("load claimed channel monitor")?;
    row.map(|row| {
        let extra_models_raw: String = row.try_get("extra_models_json")?;
        let headers_raw: String = row.try_get("extra_headers_json")?;
        let body_raw: Option<String> = row.try_get("body_override_json")?;
        let mut errors = Vec::new();
        let extra_models =
            serde_json::from_str::<Vec<String>>(&extra_models_raw).unwrap_or_else(|error| {
                errors.push(format!("invalid extra_models JSON: {error}"));
                Vec::new()
            });
        let extra_headers = serde_json::from_str::<BTreeMap<String, String>>(&headers_raw)
            .unwrap_or_else(|error| {
                errors.push(format!("invalid extra_headers JSON: {error}"));
                BTreeMap::new()
            });
        let body_override = body_raw
            .as_deref()
            .map(serde_json::from_str::<Value>)
            .transpose()
            .unwrap_or_else(|error| {
                errors.push(format!("invalid body_override JSON: {error}"));
                None
            });
        Ok(MonitorSnapshot {
            id: row.try_get("id")?,
            provider: row.try_get("provider")?,
            api_mode: row.try_get("api_mode")?,
            endpoint: row.try_get("endpoint")?,
            encrypted_api_key: row.try_get("api_key_encrypted")?,
            primary_model: row.try_get("primary_model")?,
            extra_models,
            interval_seconds: row.try_get("interval_seconds")?,
            jitter_seconds: row.try_get("jitter_seconds")?,
            last_checked_epoch: row.try_get("last_checked_epoch")?,
            extra_headers,
            body_override_mode: row.try_get("body_override_mode")?,
            body_override,
            config_error: (!errors.is_empty()).then(|| errors.join("; ")),
        })
    })
    .transpose()
}

fn monitor_is_due(monitor: &MonitorSnapshot, now_epoch: i64) -> bool {
    let Some(last_checked) = monitor.last_checked_epoch else {
        return true;
    };
    let interval = monitor.interval_seconds.max(MIN_MONITOR_INTERVAL_SECONDS);
    let jitter = monitor.jitter_seconds.max(0);
    let delay = (interval + stable_jitter_seconds(monitor.id, last_checked, jitter))
        .max(MIN_MONITOR_INTERVAL_SECONDS);
    last_checked.saturating_add(delay) <= now_epoch
}

fn stable_jitter_seconds(monitor_id: i64, last_checked_epoch: i64, jitter: i64) -> i64 {
    if jitter <= 0 {
        return 0;
    }
    let mut digest = crc32fast::Hasher::new();
    digest.update(&monitor_id.to_be_bytes());
    digest.update(&last_checked_epoch.to_be_bytes());
    let width = jitter.saturating_mul(2).saturating_add(1);
    i64::from(digest.finalize()) % width - jitter
}

#[derive(Debug)]
struct MonitorCheckResult {
    model: String,
    status: String,
    latency_ms: Option<i32>,
    ping_latency_ms: Option<i32>,
    message: String,
    checked_epoch: i64,
}

async fn run_monitor_checks(
    monitor: &MonitorSnapshot,
    config: &SchedulerRuntimeConfig,
    monitor_key: Option<&[u8; 32]>,
    cancellation: &CancellationToken,
) -> Result<Vec<MonitorCheckResult>> {
    let models = monitor_models(monitor);
    let api_key = match (&monitor.config_error, monitor_key) {
        (Some(error), _) => return Ok(error_results(&models, error)),
        (None, None) => {
            return Ok(error_results(&models, "TOTP_ENCRYPTION_KEY is unavailable"));
        }
        (None, Some(key)) => match decrypt_monitor_api_key(&monitor.encrypted_api_key, key) {
            Ok(api_key) => api_key,
            Err(_) => {
                return Ok(error_results(
                    &models,
                    "channel monitor API key decryption failed",
                ));
            }
        },
    };
    let client = match pinned_client(&monitor.endpoint, config.request_timeout, None).await {
        Ok(client) => client,
        Err(error) => return Ok(error_results(&models, &error.to_string())),
    };
    let ping_latency_ms = ping_endpoint(
        &client,
        &monitor.endpoint,
        config.ping_timeout,
        cancellation,
    )
    .await?;
    let mut results = Vec::with_capacity(models.len());
    for model in models {
        if cancellation.is_cancelled() {
            bail!("channel monitor cancelled during shutdown");
        }
        results.push(
            check_monitor_model(
                &client,
                monitor,
                &api_key,
                model,
                ping_latency_ms,
                config,
                cancellation,
            )
            .await?,
        );
    }
    Ok(results)
}

fn monitor_models(monitor: &MonitorSnapshot) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut models = Vec::new();
    for model in std::iter::once(&monitor.primary_model).chain(&monitor.extra_models) {
        let model = model.trim();
        if !model.is_empty() && seen.insert(model.to_owned()) {
            models.push(model.to_owned());
        }
    }
    if models.is_empty() {
        models.push("unknown".to_owned());
    }
    models
}

fn error_results(models: &[String], error: &str) -> Vec<MonitorCheckResult> {
    let checked_epoch = Utc::now().timestamp();
    let message = truncate_chars(error, 500);
    models
        .iter()
        .map(|model| MonitorCheckResult {
            model: model.clone(),
            status: "error".to_owned(),
            latency_ms: None,
            ping_latency_ms: None,
            message: message.clone(),
            checked_epoch,
        })
        .collect()
}

async fn ping_endpoint(
    client: &Client,
    endpoint: &str,
    timeout: Duration,
    cancellation: &CancellationToken,
) -> Result<Option<i32>> {
    let started = Instant::now();
    let request = client.head(endpoint).timeout(timeout).send();
    let response = tokio::select! {
        () = cancellation.cancelled() => bail!("channel monitor ping cancelled"),
        response = request => response,
    };
    Ok(response.ok().map(|_| millis_i32(started.elapsed())))
}

#[allow(clippy::too_many_arguments)]
async fn check_monitor_model(
    client: &Client,
    monitor: &MonitorSnapshot,
    api_key: &str,
    model: String,
    ping_latency_ms: Option<i32>,
    config: &SchedulerRuntimeConfig,
    cancellation: &CancellationToken,
) -> Result<MonitorCheckResult> {
    let checked_epoch = Utc::now().timestamp();
    let (prompt, expected) = challenge();
    let started = Instant::now();
    let request = provider_request(ProviderRequest {
        provider: &monitor.provider,
        api_mode: &monitor.api_mode,
        base_url: &monitor.endpoint,
        credential: api_key,
        auth_style: monitor_auth_style(&monitor.provider),
        model: &model,
        prompt: &prompt,
        extra_headers: &monitor.extra_headers,
        body_override_mode: &monitor.body_override_mode,
        body_override: monitor.body_override.as_ref(),
    });
    let outcome = match request {
        Ok(request) => {
            send_provider_request(client, request, config.response_limit_bytes, cancellation).await
        }
        Err(error) => Err(error),
    };
    if cancellation.is_cancelled() {
        bail!("channel monitor request cancelled during shutdown");
    }
    let latency_ms = millis_i32(started.elapsed());
    let (status, message) = match outcome {
        Err(error) => (
            "error".to_owned(),
            sanitize_monitor_error(&error.to_string(), monitor, api_key),
        ),
        Ok(response) if !(200..300).contains(&response.status) => (
            "error".to_owned(),
            sanitize_monitor_error(
                &format!(
                    "upstream HTTP {}: {}",
                    response.status,
                    compact_body(&response.raw)
                ),
                monitor,
                api_key,
            ),
        ),
        Ok(response) if monitor.body_override_mode == "replace" => {
            if response.text.trim().is_empty() {
                (
                    "failed".to_owned(),
                    "replace-mode: upstream returned 2xx with empty text".to_owned(),
                )
            } else {
                healthy_monitor_status(latency_ms)
            }
        }
        Ok(response) if !challenge_matches(&response.text, &expected) => (
            "failed".to_owned(),
            truncate_chars(
                &format!(
                    "challenge mismatch (expected {expected}, got {:?})",
                    response.text
                ),
                500,
            ),
        ),
        Ok(_) => healthy_monitor_status(latency_ms),
    };
    Ok(MonitorCheckResult {
        model,
        status,
        latency_ms: Some(latency_ms),
        ping_latency_ms,
        message,
        checked_epoch,
    })
}

fn healthy_monitor_status(latency_ms: i32) -> (String, String) {
    if latency_ms >= DEGRADED_MILLIS {
        (
            "degraded".to_owned(),
            format!("slow response: {latency_ms}ms"),
        )
    } else {
        ("operational".to_owned(), String::new())
    }
}

fn monitor_auth_style(provider: &str) -> AuthStyle {
    match provider.to_ascii_lowercase().as_str() {
        "anthropic" => AuthStyle::AnthropicApiKey,
        "gemini" => AuthStyle::GeminiApiKey,
        _ => AuthStyle::Bearer,
    }
}

#[derive(Clone, Copy, Debug)]
enum AuthStyle {
    Bearer,
    AnthropicApiKey,
    GeminiApiKey,
}

#[derive(Clone, Copy, Debug)]
enum TextKind {
    OpenAiChat,
    OpenAiResponses,
    Anthropic,
    Gemini,
}

#[derive(Clone, Copy)]
struct ProviderRequest<'a> {
    provider: &'a str,
    api_mode: &'a str,
    base_url: &'a str,
    credential: &'a str,
    auth_style: AuthStyle,
    model: &'a str,
    prompt: &'a str,
    extra_headers: &'a BTreeMap<String, String>,
    body_override_mode: &'a str,
    body_override: Option<&'a Value>,
}

struct ProviderRequestSpec {
    url: Url,
    headers: reqwest::header::HeaderMap,
    body: Value,
    text_kind: TextKind,
}

fn provider_request(input: ProviderRequest<'_>) -> Result<ProviderRequestSpec> {
    use reqwest::header::{AUTHORIZATION, HeaderName, HeaderValue};

    let provider = input.provider.trim().to_ascii_lowercase();
    let mut headers = reqwest::header::HeaderMap::new();
    match input.auth_style {
        AuthStyle::Bearer => {
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {}", input.credential))
                    .context("encode bearer credential")?,
            );
        }
        AuthStyle::AnthropicApiKey => {
            headers.insert(
                HeaderName::from_static("x-api-key"),
                HeaderValue::from_str(input.credential).context("encode Anthropic API key")?,
            );
        }
        AuthStyle::GeminiApiKey => {
            headers.insert(
                HeaderName::from_static("x-goog-api-key"),
                HeaderValue::from_str(input.credential).context("encode Gemini API key")?,
            );
        }
    }

    let (path, default_body, text_kind) = match (provider.as_str(), input.api_mode) {
        ("openai" | "grok" | "xai", "responses") => (
            if provider == "openai" && is_chatgpt_codex_base(input.base_url) {
                "responses".to_owned()
            } else {
                "/v1/responses".to_owned()
            },
            json!({
                "model": input.model,
                "instructions": "You are a health-check endpoint. Answer exactly and briefly.",
                "input": input.prompt,
                "max_output_tokens": 50,
                "stream": false
            }),
            TextKind::OpenAiResponses,
        ),
        ("openai", "" | "chat_completions") | ("grok" | "xai", _) => (
            "/v1/chat/completions".to_owned(),
            json!({
                "model": input.model,
                "messages": [{"role": "user", "content": input.prompt}],
                "max_tokens": 50,
                "stream": false
            }),
            TextKind::OpenAiChat,
        ),
        ("anthropic", "" | "chat_completions") => {
            headers.insert(
                HeaderName::from_static("anthropic-version"),
                HeaderValue::from_static("2023-06-01"),
            );
            (
                "/v1/messages".to_owned(),
                json!({
                    "model": input.model,
                    "messages": [{"role": "user", "content": input.prompt}],
                    "max_tokens": 50
                }),
                TextKind::Anthropic,
            )
        }
        ("gemini" | "antigravity", "" | "chat_completions") => (
            format!("/v1beta/models/{}:generateContent", input.model),
            json!({
                "contents": [{"parts": [{"text": input.prompt}]}],
                "generationConfig": {"maxOutputTokens": 50}
            }),
            TextKind::Gemini,
        ),
        _ => bail!("unsupported provider or API mode"),
    };
    for (name, value) in input.extra_headers {
        headers.insert(
            HeaderName::from_bytes(name.as_bytes()).context("invalid monitor header name")?,
            HeaderValue::from_str(value).context("invalid monitor header value")?,
        );
    }
    let body = apply_body_override(
        &provider,
        input.api_mode,
        input.body_override_mode,
        input.body_override,
        default_body,
    )?;
    Ok(ProviderRequestSpec {
        url: joined_provider_url(input.base_url, &path)?,
        headers,
        body,
        text_kind,
    })
}

fn apply_body_override(
    provider: &str,
    api_mode: &str,
    mode: &str,
    override_body: Option<&Value>,
    default_body: Value,
) -> Result<Value> {
    match mode {
        "" | "off" => Ok(default_body),
        "replace" => override_body
            .cloned()
            .ok_or_else(|| anyhow!("replace-mode body_override is missing")),
        "merge" => {
            let mut body = default_body
                .as_object()
                .cloned()
                .ok_or_else(|| anyhow!("default request body is not an object"))?;
            let overrides = override_body
                .and_then(Value::as_object)
                .ok_or_else(|| anyhow!("merge-mode body_override is missing"))?;
            let denied = denied_body_keys(provider, api_mode);
            for (key, value) in overrides {
                if !denied.contains(key.as_str()) {
                    body.insert(key.clone(), value.clone());
                }
            }
            Ok(Value::Object(body))
        }
        _ => bail!("invalid body_override_mode"),
    }
}

fn denied_body_keys(provider: &str, api_mode: &str) -> BTreeSet<&'static str> {
    let values: &[&str] = match (provider, api_mode) {
        ("openai" | "grok" | "xai", "responses") => &["model", "instructions", "input", "stream"],
        ("openai" | "grok" | "xai", _) => &["model", "messages", "stream"],
        ("anthropic", _) => &["model", "messages"],
        ("gemini" | "antigravity", _) => &["contents"],
        _ => &[],
    };
    values.iter().copied().collect()
}

fn is_chatgpt_codex_base(base_url: &str) -> bool {
    Url::parse(base_url).is_ok_and(|url| {
        url.host_str()
            .is_some_and(|host| host.eq_ignore_ascii_case("chatgpt.com"))
            && url
                .path()
                .trim_end_matches('/')
                .ends_with("/backend-api/codex")
    })
}

fn joined_provider_url(base_url: &str, route: &str) -> Result<Url> {
    let mut url = Url::parse(base_url).context("parse upstream base URL")?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        bail!("upstream base URL must use HTTP or HTTPS");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("upstream base URL must not contain credentials");
    }
    let base_path = url.path().trim_matches('/');
    let mut route_path = route.trim_start_matches('/');
    if let Some(version) = base_path.rsplit('/').next()
        && matches!(version, "v1" | "v1beta")
        && route_path
            .strip_prefix(version)
            .is_some_and(|rest| rest.starts_with('/'))
    {
        route_path = route_path[version.len()..].trim_start_matches('/');
    }
    let path = match (base_path.is_empty(), route_path.is_empty()) {
        (true, _) => format!("/{route_path}"),
        (_, true) => format!("/{base_path}"),
        (false, false) => format!("/{base_path}/{route_path}"),
    };
    url.set_path(&path);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

struct ProviderResponse {
    status: u16,
    text: String,
    raw: String,
}

async fn send_provider_request(
    client: &Client,
    request: ProviderRequestSpec,
    response_limit: usize,
    cancellation: &CancellationToken,
) -> Result<ProviderResponse> {
    let response = tokio::select! {
        () = cancellation.cancelled() => bail!("upstream request cancelled"),
        response = client.post(request.url).headers(request.headers).json(&request.body).send() => {
            response.context("send upstream request")?
        }
    };
    let status = response.status().as_u16();
    let bytes = limited_response(response, response_limit, cancellation).await?;
    let raw = String::from_utf8_lossy(&bytes).into_owned();
    let value = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
    let text = extract_response_text(&value, request.text_kind);
    Ok(ProviderResponse { status, text, raw })
}

async fn limited_response(
    response: reqwest::Response,
    limit: usize,
    cancellation: &CancellationToken,
) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut stream = response.bytes_stream();
    loop {
        let chunk = tokio::select! {
            () = cancellation.cancelled() => bail!("upstream response read cancelled"),
            chunk = stream.next() => chunk,
        };
        let Some(chunk) = chunk else {
            break;
        };
        let chunk = chunk.context("read upstream response")?;
        let remaining = limit.saturating_sub(output.len());
        output.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        if output.len() >= limit {
            break;
        }
    }
    Ok(output)
}

fn extract_response_text(value: &Value, kind: TextKind) -> String {
    match kind {
        TextKind::OpenAiChat => value
            .pointer("/choices/0/message/content")
            .map(string_or_text_blocks)
            .unwrap_or_default(),
        TextKind::OpenAiResponses => extract_responses_text(value),
        TextKind::Anthropic => value
            .pointer("/content/0/text")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        TextKind::Gemini => value
            .pointer("/candidates/0/content/parts/0/text")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
    }
}

fn string_or_text_blocks(value: &Value) -> String {
    if let Some(value) = value.as_str() {
        return value.to_owned();
    }
    value.as_array().map_or_else(String::new, |blocks| {
        blocks
            .iter()
            .filter_map(|block| block.get("text").and_then(Value::as_str))
            .collect()
    })
}

fn extract_responses_text(value: &Value) -> String {
    if let Some(text) = value.get("output_text").and_then(Value::as_str)
        && !text.trim().is_empty()
    {
        return text.to_owned();
    }
    value
        .get("output")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|output| {
            output
                .get("type")
                .and_then(Value::as_str)
                .is_none_or(|kind| kind == "message")
        })
        .filter_map(|output| output.get("content").and_then(Value::as_array))
        .flatten()
        .filter(|block| {
            block
                .get("type")
                .and_then(Value::as_str)
                .is_none_or(|kind| kind == "output_text")
        })
        .filter_map(|block| block.get("text").and_then(Value::as_str))
        .collect()
}

async fn pinned_client(
    base_url: &str,
    timeout: Duration,
    proxy: Option<&ProxySettings>,
) -> Result<Client> {
    let target = validate_public_probe_target(base_url)
        .await
        .map_err(|error| anyhow!(error.to_string()))?;
    let url = Url::parse(target.url()).context("parse validated upstream URL")?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("upstream host is missing"))?;
    let mut builder = Client::builder()
        .redirect(Policy::none())
        .no_proxy()
        .timeout(timeout);
    if matches!(url.host(), Some(Host::Domain(_))) {
        builder = builder.resolve_to_addrs(host, target.resolved_addresses());
    }
    if let Some(proxy) = proxy {
        builder = builder.proxy(build_proxy(proxy)?);
    }
    builder.build().context("build upstream HTTP client")
}

fn build_proxy(settings: &ProxySettings) -> Result<Proxy> {
    if !(1..=65_535).contains(&settings.port) {
        bail!("configured proxy port is invalid");
    }
    let scheme = match settings.protocol.trim().to_ascii_lowercase().as_str() {
        "http" => "http",
        "https" => "https",
        "socks5" => "socks5",
        "socks5h" => "socks5h",
        _ => bail!("configured proxy protocol is unsupported"),
    };
    let mut url = Url::parse(&format!("{scheme}://proxy.invalid"))?;
    url.set_host(Some(settings.host.trim()))
        .map_err(|_| anyhow!("configured proxy host is invalid"))?;
    url.set_port(Some(u16::try_from(settings.port)?))
        .map_err(|()| anyhow!("configured proxy port is invalid"))?;
    if !settings.username.is_empty() {
        url.set_username(&settings.username)
            .map_err(|()| anyhow!("configured proxy username is invalid"))?;
        url.set_password(Some(&settings.password))
            .map_err(|()| anyhow!("configured proxy password is invalid"))?;
    }
    Proxy::all(url.as_str()).context("configure account proxy")
}

fn monitor_key_from_env() -> Result<Option<[u8; 32]>> {
    secrets::optional_config_encryption_key()
}

fn decrypt_monitor_api_key(ciphertext: &str, key: &[u8; 32]) -> Result<String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| anyhow!("initialize AES-256-GCM"))?;
    let decoded = STANDARD
        .decode(ciphertext)
        .context("decode encrypted monitor API key")?;
    let (nonce, encrypted) = decoded
        .split_at_checked(12)
        .ok_or_else(|| anyhow!("encrypted monitor API key is too short"))?;
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce), encrypted)
        .map_err(|_| anyhow!("decrypt monitor API key"))?;
    String::from_utf8(plain).context("decode monitor API key text")
}

fn sanitize_account_error(message: &str, plan: &ScheduledPlan) -> String {
    let mut result = message.to_owned();
    for value in [&plan.credentials, &plan.extra] {
        for key in ["api_key", "access_token", "token"] {
            if let Some(secret) = json_nonempty_string(value, key)
                && secret.len() >= 4
            {
                result = result.replace(&secret, "[REDACTED]");
            }
        }
    }
    truncate_chars(&result, 4_000)
}

fn sanitize_monitor_error(message: &str, monitor: &MonitorSnapshot, api_key: &str) -> String {
    let mut result = message.replace(api_key, "[REDACTED]");
    for value in monitor.extra_headers.values() {
        if value.len() >= 4 {
            result = result.replace(value, "[REDACTED]");
        }
    }
    truncate_chars(&result, 500)
}

fn compact_body(raw: &str) -> String {
    truncate_chars(&raw.split_whitespace().collect::<Vec<_>>().join(" "), 300)
}

fn truncate_chars(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_owned();
    }
    let suffix = "...(truncated)";
    let keep = max.saturating_sub(suffix.len());
    format!("{}{suffix}", value.chars().take(keep).collect::<String>())
}

fn millis_i32(duration: Duration) -> i32 {
    i32::try_from(duration.as_millis()).unwrap_or(i32::MAX)
}

fn millis_i64(duration: Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}

fn parse_json(raw: &str, label: &str) -> Result<Value> {
    serde_json::from_str(raw).with_context(|| format!("parse {label} JSON"))
}

fn challenge() -> (String, String) {
    let first = i32::try_from(OsRng.next_u32() % 50 + 1).unwrap_or(1);
    let second = i32::try_from(OsRng.next_u32() % 50 + 1).unwrap_or(1);
    let addition = OsRng.next_u32().is_multiple_of(2);
    let (left, operator, right, answer) = if addition {
        (first, "+", second, first + second)
    } else {
        let (high, low) = if first >= second {
            (first, second)
        } else {
            (second, first)
        };
        (high, "-", low, high - low)
    };
    (
        format!(
            "Calculate and respond with ONLY the number, nothing else.\n\nQ: 3 + 5 = ?\nA: 8\n\nQ: 12 - 7 = ?\nA: 5\n\nQ: {left} {operator} {right} = ?\nA:"
        ),
        answer.to_string(),
    )
}

fn challenge_matches(text: &str, expected: &str) -> bool {
    let mut current = String::new();
    let mut values = Vec::new();
    for character in text.chars() {
        if character.is_ascii_digit() || (character == '-' && current.is_empty()) {
            current.push(character);
        } else if !current.is_empty() {
            values.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        values.push(current);
    }
    values.iter().any(|value| value == expected)
}

#[derive(Clone, Debug)]
struct CronSchedule {
    minutes: CronField,
    hours: CronField,
    days_of_month: CronField,
    months: CronField,
    days_of_week: CronField,
}

impl CronSchedule {
    fn parse(expression: &str) -> Result<Self> {
        let fields = expression.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 5 {
            bail!("cron expression must contain five fields");
        }
        Ok(Self {
            minutes: CronField::parse(fields[0], 0, 59, &[], false)?,
            hours: CronField::parse(fields[1], 0, 23, &[], false)?,
            days_of_month: CronField::parse(fields[2], 1, 31, &[], false)?,
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
            days_of_week: CronField::parse(
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

    fn next_after(&self, after: DateTime<Utc>) -> Result<DateTime<Utc>> {
        let mut timestamp = after
            .timestamp()
            .div_euclid(60)
            .saturating_add(1)
            .saturating_mul(60);
        for _ in 0..MAX_CRON_SEARCH_MINUTES {
            let candidate = DateTime::<Utc>::from_timestamp(timestamp, 0)
                .ok_or_else(|| anyhow!("cron search exceeded the timestamp range"))?;
            if self.matches(candidate.with_timezone(&Local)) {
                return Ok(candidate);
            }
            timestamp = timestamp.saturating_add(60);
        }
        bail!("cron expression has no occurrence within eight years")
    }

    fn matches(&self, candidate: DateTime<Local>) -> bool {
        if !self.minutes.contains(candidate.minute())
            || !self.hours.contains(candidate.hour())
            || !self.months.contains(candidate.month())
        {
            return false;
        }
        let day_matches = self.days_of_month.contains(candidate.day());
        let weekday_matches = self
            .days_of_week
            .contains(candidate.weekday().num_days_from_sunday());
        if self.days_of_month.wildcard_syntax || self.days_of_week.wildcard_syntax {
            day_matches && weekday_matches
        } else {
            day_matches || weekday_matches
        }
    }
}

#[derive(Clone, Debug)]
struct CronField {
    allowed: Vec<bool>,
    wildcard_syntax: bool,
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
            bail!("cron field is empty");
        }
        let wildcard_syntax = raw == "?" || raw.starts_with('*');
        let raw = if raw == "?" { "*" } else { raw.as_str() };
        let canonical_max = if normalize_sunday { 6 } else { max };
        let mut allowed = vec![false; usize::try_from(canonical_max + 1)?];
        for item in raw.split(',') {
            let (base, step) = item.split_once('/').map_or((item, 1), |(base, step)| {
                (base, step.parse::<u32>().unwrap_or(0))
            });
            if step == 0 {
                bail!("cron field step must be greater than zero");
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
                bail!("cron field ranges must be ascending");
            }
            let mut value = start;
            while value <= end {
                let canonical = if normalize_sunday && value == 7 {
                    0
                } else {
                    value
                };
                if let Some(slot) = allowed.get_mut(usize::try_from(canonical)?) {
                    *slot = true;
                }
                let Some(next) = value.checked_add(step) else {
                    break;
                };
                value = next;
            }
        }
        if !allowed.iter().any(|value| *value) {
            bail!("cron field does not select any values");
        }
        Ok(Self {
            allowed,
            wildcard_syntax,
        })
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
        .map_or_else(|| raw.parse::<u32>().map_err(anyhow::Error::from), Ok)
        .with_context(|| format!("invalid cron value {raw:?}"))?;
    if !(min..=max).contains(&value) {
        bail!("cron value {value} is outside [{min}, {max}]");
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    #[test]
    fn cron_parser_supports_steps_ranges_lists_and_names() {
        let schedule = CronSchedule::parse("*/15 8-18 * JAN,MAR MON-FRI")
            .expect("cron expression should parse");
        assert!(schedule.minutes.contains(0));
        assert!(schedule.minutes.contains(45));
        assert!(!schedule.minutes.contains(46));
        assert!(schedule.hours.contains(12));
        assert!(!schedule.hours.contains(20));
        assert!(schedule.months.contains(1));
        assert!(schedule.months.contains(3));
        assert!(!schedule.months.contains(2));
        assert!(schedule.days_of_week.contains(1));
        assert!(!schedule.days_of_week.contains(0));
    }

    #[test]
    fn cron_next_run_is_strictly_after_input_and_minute_aligned() {
        let schedule = CronSchedule::parse("*/15 * * * *").expect("cron should parse");
        let now = Utc::now();
        let next = schedule.next_after(now).expect("next run should exist");
        assert!(next > now);
        assert_eq!(next.second(), 0);
        assert_eq!(next.nanosecond(), 0);
        assert!(next.signed_duration_since(now).num_minutes() <= 15);
    }

    #[test]
    fn invalid_cron_is_rejected_without_panicking() {
        assert!(CronSchedule::parse("* * *").is_err());
        assert!(CronSchedule::parse("*/0 * * * *").is_err());
        assert!(CronSchedule::parse("60 * * * *").is_err());
        assert!(CronSchedule::parse("* * 31 2 *").is_ok());
    }

    #[test]
    fn deterministic_jitter_is_stable_and_bounded() {
        let first = stable_jitter_seconds(42, 1_750_000_000, 20);
        let second = stable_jitter_seconds(42, 1_750_000_000, 20);
        assert_eq!(first, second);
        assert!((-20..=20).contains(&first));
        assert_eq!(stable_jitter_seconds(42, 1_750_000_000, 0), 0);
    }

    #[test]
    fn merge_body_cannot_replace_health_check_fields() {
        let body = apply_body_override(
            "openai",
            "chat_completions",
            "merge",
            Some(&json!({"model": "attacker", "temperature": 0.2})),
            json!({"model": "expected", "messages": [{"role": "user"}]}),
        )
        .expect("body should merge");
        assert_eq!(body["model"], "expected");
        assert_eq!(body["temperature"], 0.2);
    }

    #[test]
    fn provider_url_does_not_duplicate_version_prefix() {
        let url = joined_provider_url("https://api.example.test/v1", "/v1/chat/completions")
            .expect("URL should join");
        assert_eq!(url.as_str(), "https://api.example.test/v1/chat/completions");
    }

    #[test]
    fn challenge_match_requires_a_complete_integer() {
        assert!(challenge_matches("The answer is 17.", "17"));
        assert!(!challenge_matches("The answer is 117.", "17"));
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with the migrated PostgreSQL schema"]
    async fn postgres_scheduler_claim_recovery_and_result_writes_are_atomic() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL must be set for ignored PostgreSQL tests");
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&database_url)
            .await
            .expect("connect test PostgreSQL");
        let suffix = uuid::Uuid::new_v4();
        let account_id = sqlx::query_scalar::<_, i64>(
            r#"INSERT INTO accounts (name, platform, type, credentials, extra)
               VALUES ($1, 'openai', 'apikey',
                       '{"api_key":"not-used"}'::jsonb, '{}'::jsonb)
               RETURNING id"#,
        )
        .bind(format!("scheduler-test-{suffix}"))
        .fetch_one(&pool)
        .await
        .expect("insert test account");
        let plan_id = sqlx::query_scalar::<_, i64>(
            r"INSERT INTO scheduled_test_plans
              (account_id, model_id, cron_expression, enabled, next_run_at)
              VALUES ($1, 'gpt-test', '*/5 * * * *', TRUE, NULL)
              RETURNING id",
        )
        .bind(account_id)
        .fetch_one(&pool)
        .await
        .expect("insert test plan");

        let lock_key = format!("sub2api:scheduled-test:{plan_id}");
        let mut first_claim = pool.begin().await.expect("begin first claim");
        assert!(
            try_advisory_lock(&mut first_claim, &lock_key)
                .await
                .expect("acquire first claim")
        );
        let mut competing_claim = pool.begin().await.expect("begin competing claim");
        assert!(
            !try_advisory_lock(&mut competing_claim, &lock_key)
                .await
                .expect("test competing claim")
        );
        competing_claim
            .rollback()
            .await
            .expect("rollback competing claim");
        first_claim.rollback().await.expect("release first claim");

        process_scheduled_test(
            &pool,
            &SchedulerRuntimeConfig::default(),
            &CancellationToken::new(),
            plan_id,
        )
        .await
        .expect("recover missing next_run_at");
        let recovered = sqlx::query_scalar::<_, bool>(
            "SELECT next_run_at > NOW() FROM scheduled_test_plans WHERE id = $1",
        )
        .bind(plan_id)
        .fetch_one(&pool)
        .await
        .expect("read recovered plan");
        assert!(recovered);

        let now = Utc::now().timestamp();
        let plan = ScheduledPlan {
            id: plan_id,
            account_id,
            model: "gpt-test".to_owned(),
            cron_expression: "*/5 * * * *".to_owned(),
            max_results: 2,
            auto_recover: false,
            next_run_epoch: Some(now),
            account_deleted: false,
            platform: "openai".to_owned(),
            account_type: "apikey".to_owned(),
            credentials: json!({"api_key": "not-used"}),
            extra: json!({}),
            proxy_id: None,
            proxy: None,
        };
        let outcome = ScheduledProbeOutcome {
            status: "success",
            response_text: "ok".to_owned(),
            error_message: String::new(),
            latency_ms: 12,
            started_epoch: now,
            finished_epoch: now,
        };
        let mut result_transaction = pool.begin().await.expect("begin result write");
        persist_scheduled_outcome(
            &mut result_transaction,
            &plan,
            &outcome,
            Some(now + 300),
            false,
        )
        .await
        .expect("write scheduled result");
        result_transaction
            .commit()
            .await
            .expect("commit scheduled result");
        let scheduled_results = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM scheduled_test_results WHERE plan_id = $1 AND status = 'success'",
        )
        .bind(plan_id)
        .fetch_one(&pool)
        .await
        .expect("count scheduled results");
        assert_eq!(scheduled_results, 1);

        let monitor_id = sqlx::query_scalar::<_, i64>(
            r"INSERT INTO channel_monitors
              (name, provider, endpoint, api_key_encrypted, primary_model,
               enabled, interval_seconds, created_by)
              VALUES ($1, 'openai', 'https://api.example.test', 'not-used',
                      'gpt-test', TRUE, 60, 1)
              RETURNING id",
        )
        .bind(format!("scheduler-monitor-{suffix}"))
        .fetch_one(&pool)
        .await
        .expect("insert test monitor");
        let monitor_result = MonitorCheckResult {
            model: "gpt-test".to_owned(),
            status: "operational".to_owned(),
            latency_ms: Some(25),
            ping_latency_ms: Some(5),
            message: String::new(),
            checked_epoch: now,
        };
        let mut monitor_transaction = pool.begin().await.expect("begin monitor result write");
        assert!(
            persist_monitor_results(&mut monitor_transaction, monitor_id, &[monitor_result], now,)
                .await
                .expect("write monitor result")
        );
        monitor_transaction
            .commit()
            .await
            .expect("commit monitor result");
        let monitor_results = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM channel_monitor_histories WHERE monitor_id = $1 AND status = 'operational'",
        )
        .bind(monitor_id)
        .fetch_one(&pool)
        .await
        .expect("count monitor results");
        assert_eq!(monitor_results, 1);

        sqlx::query("DELETE FROM channel_monitors WHERE id = $1")
            .bind(monitor_id)
            .execute(&pool)
            .await
            .expect("delete test monitor");

        sqlx::query("DELETE FROM accounts WHERE id = $1")
            .bind(account_id)
            .execute(&pool)
            .await
            .expect("delete test account");
        pool.close().await;
    }
}
