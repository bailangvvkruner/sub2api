//! `PostgreSQL` backup execution, S3-compatible object storage, and scheduling.

use std::{
    env, fmt,
    future::Future,
    path::{Component, Path, PathBuf},
    process::Stdio,
    sync::{Arc, OnceLock},
    time::Duration,
};

use chrono::{DateTime, Datelike, Local, TimeZone, Timelike, Utc};
use flate2::read::GzDecoder;
use futures_util::StreamExt;
use hmac::{Hmac, Mac};
use reqwest::{
    Body, Client, Method, StatusCode,
    header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HOST, HeaderMap, HeaderValue},
    redirect::Policy,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool, Postgres, pool::PoolConnection};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
    sync::{Mutex, OwnedMutexGuard},
    task::JoinHandle,
    time,
};
use tokio_util::{io::ReaderStream, sync::CancellationToken};
use url::Url;
use uuid::Uuid;

use crate::security::secrets;

const BACKUP_S3_KEY: &str = "backup_s3_config";
const BACKUP_SCHEDULE_KEY: &str = "backup_schedule";
const BACKUP_SCHEDULE_CLAIM_KEY: &str = "backup_schedule_last_claim";
const BACKUP_RECORDS_KEY: &str = "backup_records";
const BACKUP_SCHEDULE_LOCK_KEY: i64 = 0x5355_4232_4150_4903;
const BACKUP_OPERATION_LOCK_KEY: i64 = 0x5355_4232_4150_4904;
const MAX_BACKUP_RECORDS: usize = 100;
const DEFAULT_MAX_LEGACY_SQL_BYTES: u64 = 64 * 1_024 * 1_024 * 1_024;
pub const ARTIFACT_FORMAT_PG_CUSTOM: &str = "postgres_custom_v1";
pub const ARTIFACT_FORMAT_LEGACY_GZIP_SQL: &str = "legacy_gzip_sql_v1";
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const S3_SERVICE: &str = "s3";
const S3_DOWNLOAD_TTL_SECONDS: u64 = 3_600;

static BACKUP_LOCK: OnceLock<Arc<Mutex<()>>> = OnceLock::new();
static BACKUP_TASKS: OnceLock<Arc<Mutex<Vec<JoinHandle<()>>>>> = OnceLock::new();

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct BackupS3Config {
    #[serde(default)]
    pub endpoint: String,
    #[serde(default = "default_s3_region")]
    pub region: String,
    #[serde(default)]
    pub bucket: String,
    #[serde(default)]
    pub access_key_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub secret_access_key: String,
    #[serde(default)]
    pub prefix: String,
    #[serde(default)]
    pub force_path_style: bool,
}

impl BackupS3Config {
    fn is_configured(&self) -> bool {
        !self.bucket.trim().is_empty()
            && !self.access_key_id.trim().is_empty()
            && !self.secret_access_key.trim().is_empty()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BackupSchedule {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub cron_expr: String,
    #[serde(default = "default_retain_days")]
    pub retain_days: i64,
    #[serde(default)]
    pub retain_count: i64,
}

impl Default for BackupSchedule {
    fn default() -> Self {
        Self {
            enabled: false,
            cron_expr: String::new(),
            retain_days: default_retain_days(),
            retain_count: 0,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BackupRecord {
    pub id: String,
    pub status: String,
    pub backup_type: String,
    pub file_name: String,
    pub s3_key: String,
    pub size_bytes: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub artifact_format: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sha256: String,
    pub triggered_by: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error_message: String,
    pub started_at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub finished_at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub expires_at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub progress: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub restore_status: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub restore_error: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub restored_at: String,
}

#[derive(Debug)]
pub enum BackupError {
    Invalid(String),
    Conflict(String),
    NotFound,
    Internal(String),
}

impl fmt::Display for BackupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) | Self::Conflict(message) | Self::Internal(message) => {
                formatter.write_str(message)
            }
            Self::NotFound => formatter.write_str("backup not found"),
        }
    }
}

impl std::error::Error for BackupError {}

impl From<sqlx::Error> for BackupError {
    fn from(error: sqlx::Error) -> Self {
        Self::Internal(format!(
            "PostgreSQL backup metadata operation failed: {error}"
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupDownload {
    pub url: String,
    pub storage: &'static str,
    pub expires_in: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupArtifactFormat {
    PostgresCustom,
    LegacyGzipSql,
}

impl BackupArtifactFormat {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PostgresCustom => ARTIFACT_FORMAT_PG_CUSTOM,
            Self::LegacyGzipSql => ARTIFACT_FORMAT_LEGACY_GZIP_SQL,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PreparedRestoreFile {
    pub path: PathBuf,
    pub format: BackupArtifactFormat,
    temporary_path: Option<PathBuf>,
}

impl PreparedRestoreFile {
    /// Removes the temporary file created for a legacy restore, when present.
    ///
    /// # Errors
    ///
    /// Returns an error when the temporary file cannot be removed.
    pub async fn cleanup(&self) -> Result<(), BackupError> {
        if let Some(path) = self.temporary_path.as_ref()
            && let Err(error) = tokio::fs::remove_file(path).await
            && error.kind() != std::io::ErrorKind::NotFound
        {
            return Err(BackupError::Internal(format!(
                "cannot remove temporary restore file: {error}"
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupRuntimeConfig {
    pub poll_interval: Duration,
    pub shutdown_timeout: Duration,
}

/// Process-local and `PostgreSQL`-session lock held for a complete backup operation.
///
/// The pooled connection is marked `close_on_drop`, so cancellation or panic closes
/// the `PostgreSQL` session and releases its advisory lock instead of leaking it back
/// into the pool.
pub struct BackupOperationGuard {
    _local: OwnedMutexGuard<()>,
    connection: PoolConnection<Postgres>,
}

impl BackupOperationGuard {
    #[must_use]
    pub fn connection_mut(&mut self) -> &mut PoolConnection<Postgres> {
        &mut self.connection
    }
}

#[derive(Clone, Debug)]
pub struct ApplicationWriteGate {
    database: String,
    role: String,
    database_setting: Option<String>,
    role_setting: Option<String>,
}

impl Default for BackupRuntimeConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(30),
            shutdown_timeout: Duration::from_secs(30),
        }
    }
}

pub struct BackupRuntime {
    cancellation: CancellationToken,
    task: JoinHandle<()>,
    shutdown_timeout: Duration,
}

impl BackupRuntime {
    /// Starts the PostgreSQL-coordinated backup scheduler.
    ///
    /// # Errors
    ///
    /// Returns an error when either scheduler duration is zero.
    pub fn spawn(pool: PgPool, config: BackupRuntimeConfig) -> Result<Self, BackupError> {
        if config.poll_interval.is_zero() || config.shutdown_timeout.is_zero() {
            return Err(BackupError::Invalid(
                "backup scheduler durations must be greater than zero".to_owned(),
            ));
        }
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            scheduler_loop(pool, config.poll_interval, task_cancellation).await;
        });
        Ok(Self {
            cancellation,
            task,
            shutdown_timeout: config.shutdown_timeout,
        })
    }

    /// Stops schedule polling and waits for the scheduler task to exit.
    ///
    /// # Errors
    ///
    /// Returns an error when the scheduler task fails or does not stop before
    /// the configured timeout.
    pub async fn shutdown(self) -> Result<(), BackupError> {
        self.cancellation.cancel();
        match time::timeout(self.shutdown_timeout, self.task).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                return Err(BackupError::Internal(format!(
                    "backup scheduler task failed: {error}"
                )));
            }
            Err(_) => {
                return Err(BackupError::Internal(format!(
                    "backup scheduler did not stop within {:?}",
                    self.shutdown_timeout
                )));
            }
        }
        drain_operation_tasks(self.shutdown_timeout).await
    }
}

#[must_use]
pub const fn default_retain_days() -> i64 {
    14
}

fn default_s3_region() -> String {
    "auto".to_owned()
}

/// Validates an S3-compatible backup configuration.
///
/// # Errors
///
/// Returns an error when required credentials are absent or the endpoint or
/// bucket is invalid.
pub fn validate_s3_config(
    config: &BackupS3Config,
    require_configured: bool,
) -> Result<(), BackupError> {
    let bucket_present = !config.bucket.trim().is_empty();
    let access_key_present = !config.access_key_id.trim().is_empty();
    let secret_present = !config.secret_access_key.trim().is_empty();
    if !bucket_present && !access_key_present && !secret_present && !require_configured {
        return Ok(());
    }
    if !bucket_present || !access_key_present || (require_configured && !secret_present) {
        return Err(BackupError::Invalid(
            "S3 bucket, access_key_id, and secret_access_key are required".to_owned(),
        ));
    }
    if config.bucket.contains('/') || config.bucket.chars().any(char::is_whitespace) {
        return Err(BackupError::Invalid(
            "S3 bucket must not contain slashes or whitespace".to_owned(),
        ));
    }
    if !config.endpoint.trim().is_empty() {
        let endpoint = Url::parse(config.endpoint.trim())
            .map_err(|_| BackupError::Invalid("S3 endpoint must be a valid URL".to_owned()))?;
        if !matches!(endpoint.scheme(), "http" | "https") || endpoint.host_str().is_none() {
            return Err(BackupError::Invalid(
                "S3 endpoint must use HTTP or HTTPS and include a host".to_owned(),
            ));
        }
        if !endpoint.username().is_empty() || endpoint.password().is_some() {
            return Err(BackupError::Invalid(
                "S3 endpoint must not contain user information".to_owned(),
            ));
        }
        if endpoint.query().is_some() || endpoint.fragment().is_some() {
            return Err(BackupError::Invalid(
                "S3 endpoint must not contain a query or fragment".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Validates a backup cron expression.
///
/// # Errors
///
/// Returns an error when the expression is empty or syntactically invalid.
pub fn validate_cron(expression: &str) -> Result<(), BackupError> {
    CronSchedule::parse(expression).map(|_| ())
}

/// Validates a backup schedule and its retention limits.
///
/// # Errors
///
/// Returns an error when the cron expression or a retention value is invalid.
pub fn validate_schedule(schedule: &BackupSchedule) -> Result<(), BackupError> {
    if schedule.enabled || !schedule.cron_expr.trim().is_empty() {
        validate_cron(&schedule.cron_expr)?;
    }
    if !(0..=3_650).contains(&schedule.retain_days) {
        return Err(BackupError::Invalid(
            "retain_days must be between 0 and 3650".to_owned(),
        ));
    }
    if !(0..=i64::try_from(MAX_BACKUP_RECORDS).unwrap_or(i64::MAX)).contains(&schedule.retain_count)
    {
        return Err(BackupError::Invalid(format!(
            "retain_count must be between 0 and {MAX_BACKUP_RECORDS}"
        )));
    }
    Ok(())
}

/// Checks that the configured S3-compatible bucket is reachable.
///
/// # Errors
///
/// Returns an error when the configuration is invalid or the bucket request fails.
pub async fn test_s3_connection(config: &BackupS3Config) -> Result<(), BackupError> {
    validate_s3_config(config, true)?;
    S3Client::new(config.clone())?.head_bucket().await
}

/// Acquires the process-local and database advisory locks for a backup operation.
///
/// # Errors
///
/// Returns an error when another operation holds either lock or the database
/// lock cannot be queried.
pub async fn try_operation_lock(pool: &PgPool) -> Result<BackupOperationGuard, BackupError> {
    let local = BACKUP_LOCK
        .get_or_init(|| Arc::new(Mutex::new(())))
        .clone()
        .try_lock_owned()
        .map_err(|_| BackupError::Conflict("a backup or restore is already running".to_owned()))?;
    let mut connection = pool.acquire().await?;
    connection.close_on_drop();
    let acquired = sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_lock($1)")
        .bind(BACKUP_OPERATION_LOCK_KEY)
        .fetch_one(&mut *connection)
        .await?;
    if !acquired {
        return Err(BackupError::Conflict(
            "a backup or restore is already running on another replica".to_owned(),
        ));
    }
    Ok(BackupOperationGuard {
        _local: local,
        connection,
    })
}

/// Makes every newly opened application session read-only and terminates existing
/// sessions before `pg_restore` starts. The operation-lock session remains alive
/// as the coordinator; `pg_restore` explicitly overrides the default for its own
/// single transaction.
///
/// # Errors
///
/// Returns an error when the database settings cannot be changed or conflicting
/// sessions cannot be terminated.
pub async fn quiesce_application_writes(
    lock: &mut BackupOperationGuard,
) -> Result<ApplicationWriteGate, BackupError> {
    let connection = &mut **lock.connection_mut();
    let (database, role) = sqlx::query_as::<_, (String, String)>(
        "SELECT current_database()::text, current_user::text",
    )
    .fetch_one(&mut *connection)
    .await?;
    let database_setting = read_only_setting(&mut *connection, false).await?;
    let role_setting = read_only_setting(&mut *connection, true).await?;
    let gate = ApplicationWriteGate {
        database,
        role,
        database_setting,
        role_setting,
    };

    alter_read_only_setting(&mut *connection, &gate, false, Some("on")).await?;
    if let Err(error) = alter_read_only_setting(&mut *connection, &gate, true, Some("on")).await {
        let _ = alter_read_only_setting(
            &mut *connection,
            &gate,
            false,
            gate.database_setting.as_deref(),
        )
        .await;
        return Err(error);
    }
    if let Err(error) = terminate_other_database_sessions(&mut *connection).await {
        let _ = resume_application_writes(lock, gate.clone()).await;
        return Err(error);
    }
    Ok(gate)
}

/// Restores the database/role defaults and reconnects application pools so no
/// session remains pinned to the temporary read-only default.
///
/// # Errors
///
/// Returns an error when a setting cannot be restored or existing sessions
/// cannot be terminated.
pub async fn resume_application_writes(
    lock: &mut BackupOperationGuard,
    gate: ApplicationWriteGate,
) -> Result<(), BackupError> {
    let connection = &mut **lock.connection_mut();
    let mut errors = Vec::new();
    if let Err(error) =
        alter_read_only_setting(&mut *connection, &gate, true, gate.role_setting.as_deref()).await
    {
        errors.push(error.to_string());
    }
    if let Err(error) = alter_read_only_setting(
        &mut *connection,
        &gate,
        false,
        gate.database_setting.as_deref(),
    )
    .await
    {
        errors.push(error.to_string());
    }
    if let Err(error) = terminate_other_database_sessions(&mut *connection).await {
        errors.push(error.to_string());
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(BackupError::Internal(format!(
            "cannot restore application write access: {}",
            errors.join("; ")
        )))
    }
}

async fn read_only_setting(
    connection: &mut PgConnection,
    role_specific: bool,
) -> Result<Option<String>, BackupError> {
    let role_predicate = if role_specific {
        "settings.setrole = (SELECT oid FROM pg_roles WHERE rolname = current_user)"
    } else {
        "settings.setrole = 0"
    };
    let sql = format!(
        "SELECT split_part(entry, '=', 2) \
         FROM pg_db_role_setting settings \
         CROSS JOIN LATERAL unnest(settings.setconfig) AS entry \
         WHERE settings.setdatabase = (SELECT oid FROM pg_database WHERE datname = current_database()) \
           AND {role_predicate} \
           AND split_part(entry, '=', 1) = 'default_transaction_read_only' \
         LIMIT 1"
    );
    sqlx::query_scalar(&sql)
        .fetch_optional(connection)
        .await
        .map_err(Into::into)
}

async fn alter_read_only_setting(
    connection: &mut PgConnection,
    gate: &ApplicationWriteGate,
    role_specific: bool,
    value: Option<&str>,
) -> Result<(), BackupError> {
    let target = if role_specific {
        format!(
            "ROLE {} IN DATABASE {}",
            quote_identifier(&gate.role),
            quote_identifier(&gate.database)
        )
    } else {
        format!("DATABASE {}", quote_identifier(&gate.database))
    };
    sqlx::query(&format!(
        "ALTER {target} RESET default_transaction_read_only"
    ))
    .execute(&mut *connection)
    .await?;
    if let Some(value) = value {
        let value = normalize_read_only_value(value)?;
        sqlx::query(&format!(
            "ALTER {target} SET default_transaction_read_only = {value}"
        ))
        .execute(connection)
        .await?;
    }
    Ok(())
}

async fn terminate_other_database_sessions(
    connection: &mut PgConnection,
) -> Result<(), BackupError> {
    let terminated = sqlx::query_scalar::<_, bool>(
        r"
SELECT COALESCE(bool_and(pg_terminate_backend(pid)), TRUE)
FROM pg_stat_activity
WHERE datname = current_database()
  AND pid <> pg_backend_pid()
  AND backend_type = 'client backend'
",
    )
    .fetch_one(connection)
    .await?;
    if terminated {
        Ok(())
    } else {
        Err(BackupError::Internal(
            "PostgreSQL refused to terminate one or more application sessions".to_owned(),
        ))
    }
}

fn normalize_read_only_value(value: &str) -> Result<&'static str, BackupError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "on" | "true" | "yes" | "1" => Ok("on"),
        "off" | "false" | "no" | "0" => Ok("off"),
        _ => Err(BackupError::Internal(
            "stored default_transaction_read_only value is invalid".to_owned(),
        )),
    }
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

/// Registers an accepted backup or restore task with the shutdown lifecycle.
pub async fn spawn_operation<F>(operation: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    let task = tokio::spawn(operation);
    let tasks = BACKUP_TASKS
        .get_or_init(|| Arc::new(Mutex::new(Vec::new())))
        .clone();
    let mut tasks = tasks.lock().await;
    tasks.retain(|task| !task.is_finished());
    tasks.push(task);
}

async fn drain_operation_tasks(timeout: Duration) -> Result<(), BackupError> {
    let tasks = BACKUP_TASKS
        .get_or_init(|| Arc::new(Mutex::new(Vec::new())))
        .clone();
    let pending = {
        let mut tasks = tasks.lock().await;
        std::mem::take(&mut *tasks)
    };
    let mut pending = pending;
    if let Ok(results) =
        time::timeout(timeout, futures_util::future::join_all(pending.iter_mut())).await
    {
        for result in results {
            result.map_err(|error| {
                BackupError::Internal(format!("backup operation task failed: {error}"))
            })?;
        }
        return Ok(());
    }
    for task in &pending {
        task.abort();
    }
    let _ = futures_util::future::join_all(pending).await;
    Err(BackupError::Internal(format!(
        "backup operation did not stop within {timeout:?}"
    )))
}

/// Starts a full database backup and records its asynchronous progress.
///
/// # Errors
///
/// Returns an error when the expiry is invalid, an operation is already active,
/// or backup metadata and configuration cannot be loaded.
pub async fn start_backup(
    pool: &PgPool,
    expire_days: i64,
    triggered_by: &str,
) -> Result<BackupRecord, BackupError> {
    start_backup_inner(pool, expire_days, triggered_by, None).await
}

#[allow(
    clippy::too_many_lines,
    reason = "backup setup and its spawned completion state machine form one lifecycle"
)]
async fn start_backup_inner(
    pool: &PgPool,
    expire_days: i64,
    triggered_by: &str,
    cleanup_schedule: Option<BackupSchedule>,
) -> Result<BackupRecord, BackupError> {
    if !(0..=3_650).contains(&expire_days) {
        return Err(BackupError::Invalid(
            "expire_days must be between 0 and 3650".to_owned(),
        ));
    }
    let lock = try_operation_lock(pool).await?;
    let s3_config = load_s3_config(pool).await?;
    if let Some(config) = s3_config.as_ref() {
        validate_s3_config(config, true)?;
    }

    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let file_name = format!("sub2api-{}-{}.dump", now.format("%Y%m%d-%H%M%S"), &id[..8]);
    let s3_key = s3_config.as_ref().map_or_else(
        || format!("local/{file_name}"),
        |config| build_s3_key(config, &file_name, now),
    );
    let record = BackupRecord {
        id: id.clone(),
        status: "running".to_owned(),
        backup_type: "postgres".to_owned(),
        file_name: file_name.clone(),
        s3_key,
        size_bytes: 0,
        artifact_format: ARTIFACT_FORMAT_PG_CUSTOM.to_owned(),
        sha256: String::new(),
        triggered_by: triggered_by.to_owned(),
        error_message: String::new(),
        started_at: now.to_rfc3339(),
        finished_at: String::new(),
        expires_at: if expire_days == 0 {
            String::new()
        } else {
            (now + chrono::Duration::days(expire_days)).to_rfc3339()
        },
        progress: "dumping".to_owned(),
        restore_status: String::new(),
        restore_error: String::new(),
        restored_at: String::new(),
    };
    insert_record(pool, record.clone()).await?;

    let task_pool = pool.clone();
    spawn_operation(async move {
        let _lock = lock;
        let path = match local_backup_path_for_file(&file_name) {
            Ok(path) => path,
            Err(error) => {
                finish_failed_backup(&task_pool, &id, error.to_string()).await;
                return;
            }
        };
        let result = async {
            let size = perform_pg_dump(&path).await?;
            let (sha256, hashed_size) = hash_file(&path).await?;
            if hashed_size != size {
                return Err(BackupError::Internal(
                    "backup file changed while its checksum was calculated".to_owned(),
                ));
            }
            if let Some(config) = s3_config {
                update_record(&task_pool, &id, |record| {
                    "uploading".clone_into(&mut record.progress);
                })
                .await?;
                let client = S3Client::new(config)?;
                client
                    .upload_file(
                        &record_key(&task_pool, &id).await?,
                        &path,
                        &sha256,
                        size,
                    )
                    .await?;
            }
            Ok::<(u64, String), BackupError>((size, sha256))
        }
        .await;

        let finished_at = Utc::now().to_rfc3339();
        match result {
            Ok((size, sha256)) => {
                let finalized = update_record(&task_pool, &id, |record| {
                    "completed".clone_into(&mut record.status);
                    record.size_bytes = i64::try_from(size).unwrap_or(i64::MAX);
                    record.sha256 = sha256;
                    record.progress.clear();
                    record.error_message.clear();
                    record.finished_at.clone_from(&finished_at);
                })
                .await;
                if let Err(error) = finalized {
                    tracing::error!(backup_id = %id, error = %error, "cannot finalize backup record");
                } else if let Some(schedule) = cleanup_schedule
                    && let Err(error) = cleanup_old_backups(&task_pool, &schedule).await
                {
                    tracing::error!(error = %error, "scheduled backup retention cleanup failed");
                }
            }
            Err(error) => finish_failed_backup(&task_pool, &id, error.to_string()).await,
        }
    })
    .await;
    Ok(record)
}

/// Deletes a completed backup and its local or remote artifact.
///
/// # Errors
///
/// Returns an error when the backup does not exist, is active, or its artifact
/// or metadata cannot be deleted.
pub async fn delete_backup(pool: &PgPool, id: &str) -> Result<(), BackupError> {
    let _lock = try_operation_lock(pool).await?;
    let record = find_record(pool, id).await?;
    if record.status == "running" || record.restore_status == "running" {
        return Err(BackupError::Conflict(
            "a running backup or restore cannot be deleted".to_owned(),
        ));
    }
    delete_artifacts(pool, &record).await?;
    remove_record(pool, id).await
}

/// Resolves a completed backup to a local route or a presigned object URL.
///
/// # Errors
///
/// Returns an error when the backup is unavailable, incomplete, or its download
/// location cannot be constructed.
pub async fn backup_download(pool: &PgPool, id: &str) -> Result<BackupDownload, BackupError> {
    let record = find_record(pool, id).await?;
    if record.status != "completed" {
        return Err(BackupError::Conflict(
            "only completed backups can be downloaded".to_owned(),
        ));
    }
    if !record.s3_key.starts_with("local/")
        && let Some(config) = load_s3_config(pool).await?
        && config.is_configured()
    {
        let url = S3Client::new(config)?.presign_get(&record.s3_key, S3_DOWNLOAD_TTL_SECONDS)?;
        return Ok(BackupDownload {
            url,
            storage: "s3",
            expires_in: S3_DOWNLOAD_TTL_SECONDS,
        });
    }
    let path = local_backup_path_for_file(&record.file_name)?;
    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|error| BackupError::Internal(format!("local backup is unavailable: {error}")))?;
    if !metadata.is_file() {
        return Err(BackupError::Internal(
            "local backup path is not a regular file".to_owned(),
        ));
    }
    Ok(BackupDownload {
        url: format!("/api/v1/admin/backups/{id}/download"),
        storage: "local",
        expires_in: 0,
    })
}

/// Resolves a completed Rust or legacy Go backup into a verified local restore file.
///
/// # Errors
///
/// Returns an error when the artifact is incomplete, invalid, unavailable, or
/// cannot be materialized locally.
pub async fn prepare_restore_file(
    pool: &PgPool,
    record: &BackupRecord,
) -> Result<PreparedRestoreFile, BackupError> {
    if record.status != "completed" {
        return Err(BackupError::Conflict(
            "only completed backups can be restored".to_owned(),
        ));
    }
    let format = backup_artifact_format(record)?;
    let expected_size = artifact_size(record)?;
    let path = local_backup_path_for_file(&record.file_name)?;
    match format {
        BackupArtifactFormat::PostgresCustom => {
            let expected_sha256 = artifact_sha256(record)?;
            materialize_artifact(
                pool,
                record,
                &path,
                expected_size,
                Some(&expected_sha256),
                true,
            )
            .await?;
            Ok(PreparedRestoreFile {
                path,
                format,
                temporary_path: None,
            })
        }
        BackupArtifactFormat::LegacyGzipSql => {
            materialize_artifact(pool, record, &path, expected_size, None, false).await?;
            let sql_path =
                backup_directory().join(format!(".legacy-restore-{}.sql", Uuid::new_v4().simple()));
            decompress_legacy_gzip(&path, &sql_path, max_legacy_sql_bytes()?).await?;
            Ok(PreparedRestoreFile {
                path: sql_path.clone(),
                format,
                temporary_path: Some(sql_path),
            })
        }
    }
}

/// Determines the format of a backup artifact, including legacy records.
///
/// # Errors
///
/// Returns an error when the record declares an unsupported artifact format.
pub fn backup_artifact_format(record: &BackupRecord) -> Result<BackupArtifactFormat, BackupError> {
    match record.artifact_format.trim() {
        ARTIFACT_FORMAT_PG_CUSTOM => return Ok(BackupArtifactFormat::PostgresCustom),
        ARTIFACT_FORMAT_LEGACY_GZIP_SQL => return Ok(BackupArtifactFormat::LegacyGzipSql),
        "" => {}
        value => {
            return Err(BackupError::Invalid(format!(
                "unsupported backup artifact format: {value}"
            )));
        }
    }
    let file_name = record.file_name.trim().to_ascii_lowercase();
    let s3_key = record.s3_key.trim().to_ascii_lowercase();
    if file_name.ends_with(".sql.gz") || s3_key.ends_with(".sql.gz") {
        return Ok(BackupArtifactFormat::LegacyGzipSql);
    }
    if Path::new(&file_name)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("dump"))
        || !record.sha256.trim().is_empty()
    {
        return Ok(BackupArtifactFormat::PostgresCustom);
    }
    Ok(BackupArtifactFormat::LegacyGzipSql)
}

async fn materialize_artifact(
    pool: &PgPool,
    record: &BackupRecord,
    path: &Path,
    expected_size: u64,
    expected_sha256: Option<&str>,
    reuse_verified_local: bool,
) -> Result<(), BackupError> {
    if reuse_verified_local
        && verify_artifact(path, expected_size, expected_sha256)
            .await
            .is_ok()
    {
        return Ok(());
    }
    let remote = !record.s3_key.is_empty() && !record.s3_key.starts_with("local/");
    if !remote {
        return verify_artifact(path, expected_size, expected_sha256).await;
    }

    let config = load_s3_config(pool)
        .await?
        .ok_or_else(|| BackupError::Internal("S3 configuration is unavailable".to_owned()))?;
    validate_s3_config(&config, true)?;
    let directory = path.parent().ok_or_else(|| {
        BackupError::Internal("backup destination has no parent directory".to_owned())
    })?;
    tokio::fs::create_dir_all(directory)
        .await
        .map_err(|error| {
            BackupError::Internal(format!("cannot create backup directory: {error}"))
        })?;
    let temporary = directory.join(format!(
        ".{}.{}.download",
        record.file_name,
        Uuid::new_v4().simple()
    ));
    let client = S3Client::new(config)?;
    let download = client
        .download_file(&record.s3_key, &temporary, expected_size, expected_sha256)
        .await;
    if let Err(error) = download {
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(error);
    }
    if let Err(error) = tokio::fs::remove_file(&path).await
        && error.kind() != std::io::ErrorKind::NotFound
    {
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(BackupError::Internal(format!(
            "cannot replace invalid local backup: {error}"
        )));
    }
    tokio::fs::rename(&temporary, &path)
        .await
        .map_err(|error| {
            BackupError::Internal(format!("cannot install downloaded backup: {error}"))
        })?;
    verify_artifact(path, expected_size, expected_sha256).await
}

#[must_use]
pub fn backup_directory() -> PathBuf {
    env::var_os("BACKUP_DIR").map_or_else(|| PathBuf::from("/app/data/backups"), PathBuf::from)
}

fn local_backup_path_for_file(file_name: &str) -> Result<PathBuf, BackupError> {
    let mut components = Path::new(file_name).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(BackupError::Invalid(
            "backup file name must contain exactly one safe path component".to_owned(),
        ));
    }
    Ok(backup_directory().join(file_name))
}

fn artifact_size(record: &BackupRecord) -> Result<u64, BackupError> {
    u64::try_from(record.size_bytes)
        .ok()
        .filter(|size| *size > 0)
        .ok_or_else(|| {
            BackupError::Invalid("backup record is missing a valid artifact size".to_owned())
        })
}

fn artifact_sha256(record: &BackupRecord) -> Result<String, BackupError> {
    let sha256 = record.sha256.trim().to_ascii_lowercase();
    if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(BackupError::Invalid(
            "backup record is missing a valid SHA-256 digest".to_owned(),
        ));
    }
    Ok(sha256)
}

async fn verify_artifact(
    path: &Path,
    expected_size: u64,
    expected_sha256: Option<&str>,
) -> Result<(), BackupError> {
    let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        BackupError::Internal(format!("backup artifact is unavailable: {error}"))
    })?;
    if !metadata.file_type().is_file() || metadata.len() != expected_size {
        return Err(BackupError::Internal(
            "backup artifact size does not match its record".to_owned(),
        ));
    }
    if let Some(expected_sha256) = expected_sha256 {
        let (actual_sha256, actual_size) = hash_file(path).await?;
        if actual_size != expected_size || !actual_sha256.eq_ignore_ascii_case(expected_sha256) {
            return Err(BackupError::Internal(
                "backup artifact SHA-256 digest does not match its record".to_owned(),
            ));
        }
    }
    Ok(())
}

fn max_legacy_sql_bytes() -> Result<u64, BackupError> {
    let Some(raw) = env::var_os("BACKUP_MAX_RESTORE_BYTES") else {
        return Ok(DEFAULT_MAX_LEGACY_SQL_BYTES);
    };
    let raw = raw.to_string_lossy();
    raw.trim()
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            BackupError::Invalid("BACKUP_MAX_RESTORE_BYTES must be a positive integer".to_owned())
        })
}

async fn decompress_legacy_gzip(
    compressed_path: &Path,
    sql_path: &Path,
    max_output_bytes: u64,
) -> Result<(), BackupError> {
    let compressed_path = compressed_path.to_path_buf();
    let worker_sql_path = sql_path.to_path_buf();
    let result = tokio::task::spawn_blocking(move || {
        use std::io::{Read as _, Write as _};

        let result = (|| {
            let input = std::fs::File::open(&compressed_path).map_err(|error| {
                BackupError::Internal(format!("cannot open legacy gzip backup: {error}"))
            })?;
            let mut decoder = GzDecoder::new(input);
            let mut output = std::fs::File::create(&worker_sql_path).map_err(|error| {
                BackupError::Internal(format!(
                    "cannot create temporary SQL restore file: {error}"
                ))
            })?;
            let mut buffer = vec![0_u8; 64 * 1_024];
            let mut written = 0_u64;
            loop {
                let read = decoder.read(&mut buffer).map_err(|error| {
                    BackupError::Invalid(format!(
                        "legacy gzip backup failed header, stream, or CRC validation: {error}"
                    ))
                })?;
                if read == 0 {
                    break;
                }
                written = written
                    .checked_add(u64::try_from(read).unwrap_or(u64::MAX))
                    .ok_or_else(|| {
                        BackupError::Invalid("legacy SQL backup is too large".to_owned())
                    })?;
                if written > max_output_bytes {
                    return Err(BackupError::Invalid(format!(
                        "legacy SQL backup exceeds the configured {max_output_bytes}-byte restore limit"
                    )));
                }
                output.write_all(&buffer[..read]).map_err(|error| {
                    BackupError::Internal(format!(
                        "cannot write temporary SQL restore file: {error}"
                    ))
                })?;
            }
            output.flush().map_err(|error| {
                BackupError::Internal(format!("cannot flush temporary SQL restore file: {error}"))
            })?;
            output.sync_all().map_err(|error| {
                BackupError::Internal(format!("cannot sync temporary SQL restore file: {error}"))
            })?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&worker_sql_path);
        }
        result
    })
    .await
    .map_err(|error| BackupError::Internal(format!("legacy gzip worker failed: {error}")))
    .and_then(|result| result);
    if result.is_err() {
        let _ = tokio::fs::remove_file(sql_path).await;
    }
    result
}

async fn scheduler_loop(pool: PgPool, interval: Duration, cancellation: CancellationToken) {
    let mut ticker = time::interval(interval);
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            () = cancellation.cancelled() => break,
            _ = ticker.tick() => {
                match claim_due_schedule(&pool, &Local::now()).await {
                    Ok(Some(schedule)) => {
                        match start_backup_inner(
                            &pool,
                            schedule.retain_days,
                            "scheduled",
                            Some(schedule),
                        )
                        .await
                        {
                            Ok(record) => {
                                tracing::info!(backup_id = %record.id, "scheduled PostgreSQL backup started");
                            }
                            Err(BackupError::Conflict(message)) => {
                                tracing::warn!(reason = %message, "scheduled PostgreSQL backup skipped");
                            }
                            Err(error) => tracing::error!(error = %error, "scheduled PostgreSQL backup failed to start"),
                        }
                    }
                    Ok(None) => {}
                    Err(error) => tracing::error!(error = %error, "backup schedule evaluation failed"),
                }
            }
        }
    }
}

async fn claim_due_schedule<Tz>(
    pool: &PgPool,
    now: &DateTime<Tz>,
) -> Result<Option<BackupSchedule>, BackupError>
where
    Tz: TimeZone,
    Tz::Offset: fmt::Display,
{
    let mut transaction = pool.begin().await?;
    let acquired = sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_xact_lock($1)")
        .bind(BACKUP_SCHEDULE_LOCK_KEY)
        .fetch_one(&mut *transaction)
        .await?;
    if !acquired {
        transaction.rollback().await?;
        return Ok(None);
    }
    let raw = sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key = $1")
        .bind(BACKUP_SCHEDULE_KEY)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(raw) = raw else {
        transaction.commit().await?;
        return Ok(None);
    };
    let schedule: BackupSchedule = serde_json::from_str(&raw)
        .map_err(|error| BackupError::Internal(format!("backup schedule is invalid: {error}")))?;
    let marker = minute_marker(now);
    let last_claim = sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key = $1")
        .bind(BACKUP_SCHEDULE_CLAIM_KEY)
        .fetch_optional(&mut *transaction)
        .await?
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .and_then(|value| {
            value
                .get("minute")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        });
    if !schedule_is_due(&schedule, last_claim.as_deref(), now)? {
        transaction.commit().await?;
        return Ok(None);
    }
    let claim = json!({ "minute": marker }).to_string();
    sqlx::query(
        "INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, NOW()) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
    )
    .bind(BACKUP_SCHEDULE_CLAIM_KEY)
    .bind(claim)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(Some(schedule))
}

fn schedule_is_due<Tz>(
    schedule: &BackupSchedule,
    last_claim: Option<&str>,
    now: &DateTime<Tz>,
) -> Result<bool, BackupError>
where
    Tz: TimeZone,
    Tz::Offset: fmt::Display,
{
    validate_schedule(schedule)?;
    if !schedule.enabled {
        return Ok(false);
    }
    let marker = minute_marker(now);
    if last_claim == Some(marker.as_str()) {
        return Ok(false);
    }
    Ok(CronSchedule::parse(&schedule.cron_expr)?.matches(now))
}

fn minute_marker<Tz>(now: &DateTime<Tz>) -> String
where
    Tz: TimeZone,
    Tz::Offset: fmt::Display,
{
    now.with_timezone(&Utc)
        .format("%Y-%m-%dT%H:%MZ")
        .to_string()
}

async fn cleanup_old_backups(pool: &PgPool, schedule: &BackupSchedule) -> Result<(), BackupError> {
    if schedule.retain_count == 0 && schedule.retain_days == 0 {
        return Ok(());
    }
    let mut records = load_records(pool).await?;
    records.sort_by(|left, right| right.started_at.cmp(&left.started_at));
    let now = Utc::now();
    let mut completed_index = 0_i64;
    let mut expired = Vec::new();
    for record in records {
        if record.status != "completed" || record.restore_status == "running" {
            continue;
        }
        let over_count = schedule.retain_count > 0 && completed_index >= schedule.retain_count;
        completed_index += 1;
        let over_age = schedule.retain_days > 0
            && DateTime::parse_from_rfc3339(&record.started_at)
                .ok()
                .is_some_and(|started| {
                    now.signed_duration_since(started.with_timezone(&Utc))
                        > chrono::Duration::days(schedule.retain_days)
                });
        if over_count || over_age {
            expired.push(record);
        }
    }
    for record in expired {
        match delete_artifacts(pool, &record).await {
            Ok(()) => remove_record(pool, &record.id).await?,
            Err(error) => {
                tracing::error!(backup_id = %record.id, error = %error, "retained backup whose artifacts could not be deleted");
            }
        }
    }
    Ok(())
}

async fn delete_artifacts(pool: &PgPool, record: &BackupRecord) -> Result<(), BackupError> {
    if !record.s3_key.is_empty() && !record.s3_key.starts_with("local/") {
        let config = load_s3_config(pool).await?.ok_or_else(|| {
            BackupError::Internal("S3 configuration is unavailable for remote deletion".to_owned())
        })?;
        validate_s3_config(&config, true)?;
        S3Client::new(config)?.delete_object(&record.s3_key).await?;
    }
    let path = local_backup_path_for_file(&record.file_name)?;
    if let Err(error) = tokio::fs::remove_file(path).await
        && error.kind() != std::io::ErrorKind::NotFound
    {
        return Err(BackupError::Internal(format!(
            "cannot delete local backup file: {error}"
        )));
    }
    Ok(())
}

async fn perform_pg_dump(path: &Path) -> Result<u64, BackupError> {
    let directory = path.parent().ok_or_else(|| {
        BackupError::Internal("backup destination has no parent directory".to_owned())
    })?;
    tokio::fs::create_dir_all(directory)
        .await
        .map_err(|error| {
            BackupError::Internal(format!("cannot create backup directory: {error}"))
        })?;
    let mut command = postgres_command("pg_dump");
    command.kill_on_drop(true);
    command
        .arg("--format=custom")
        .arg("--no-owner")
        .arg("--no-privileges")
        .arg("--file")
        .arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let output = command
        .output()
        .await
        .map_err(|error| BackupError::Internal(format!("cannot start pg_dump: {error}")))?;
    if !output.status.success() {
        let _ = tokio::fs::remove_file(path).await;
        return Err(BackupError::Internal(format!(
            "pg_dump failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(tokio::fs::metadata(path)
        .await
        .map_err(|error| BackupError::Internal(format!("cannot inspect backup file: {error}")))?
        .len())
}

fn postgres_command(program: &str) -> Command {
    let mut command = Command::new(program);
    if let Ok(database_url) = env::var("DATABASE_URL")
        && !database_url.trim().is_empty()
    {
        command.arg("--dbname").arg(database_url);
    } else {
        command
            .arg("--host")
            .arg(env::var("DATABASE_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned()))
            .arg("--port")
            .arg(env::var("DATABASE_PORT").unwrap_or_else(|_| "5432".to_owned()))
            .arg("--username")
            .arg(env::var("DATABASE_USER").unwrap_or_else(|_| "sub2api".to_owned()))
            .arg("--dbname")
            .arg(env::var("DATABASE_DBNAME").unwrap_or_else(|_| "sub2api".to_owned()));
        if let Ok(password) = env::var("DATABASE_PASSWORD") {
            command.env("PGPASSWORD", password);
        }
        if let Ok(ssl_mode) = env::var("DATABASE_SSLMODE") {
            command.env("PGSSLMODE", ssl_mode);
        }
    }
    command
}

async fn load_s3_config(pool: &PgPool) -> Result<Option<BackupS3Config>, BackupError> {
    let raw = sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key = $1")
        .bind(BACKUP_S3_KEY)
        .fetch_optional(pool)
        .await?;
    raw.map(|raw| {
        let mut config: BackupS3Config = serde_json::from_str(&raw).map_err(|error| {
            BackupError::Internal(format!("stored S3 configuration is invalid: {error}"))
        })?;
        config.secret_access_key = secrets::decrypt_config_secret(&config.secret_access_key)
            .map_err(|error| {
                BackupError::Internal(format!("cannot decrypt S3 configuration: {error}"))
            })?;
        if config.bucket.trim().is_empty() && config.access_key_id.trim().is_empty() {
            Ok(None)
        } else {
            Ok(Some(config))
        }
    })
    .transpose()
    .map(Option::flatten)
}

async fn load_records(pool: &PgPool) -> Result<Vec<BackupRecord>, BackupError> {
    let raw = sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key = $1")
        .bind(BACKUP_RECORDS_KEY)
        .fetch_optional(pool)
        .await?;
    raw.map(|raw| {
        serde_json::from_str(&raw).map_err(|error| {
            BackupError::Internal(format!("stored backup records are invalid: {error}"))
        })
    })
    .transpose()
    .map(Option::unwrap_or_default)
}

async fn find_record(pool: &PgPool, id: &str) -> Result<BackupRecord, BackupError> {
    load_records(pool)
        .await?
        .into_iter()
        .find(|record| record.id == id)
        .ok_or(BackupError::NotFound)
}

async fn record_key(pool: &PgPool, id: &str) -> Result<String, BackupError> {
    find_record(pool, id).await.map(|record| record.s3_key)
}

async fn insert_record(pool: &PgPool, record: BackupRecord) -> Result<(), BackupError> {
    mutate_records(pool, |records| {
        records.push(record);
        Ok(())
    })
    .await
}

async fn update_record(
    pool: &PgPool,
    id: &str,
    update: impl FnOnce(&mut BackupRecord),
) -> Result<BackupRecord, BackupError> {
    mutate_records(pool, |records| {
        let record = records
            .iter_mut()
            .find(|record| record.id == id)
            .ok_or(BackupError::NotFound)?;
        update(record);
        Ok(record.clone())
    })
    .await
}

async fn remove_record(pool: &PgPool, id: &str) -> Result<(), BackupError> {
    mutate_records(pool, |records| {
        let index = records
            .iter()
            .position(|record| record.id == id)
            .ok_or(BackupError::NotFound)?;
        if records[index].status == "running" || records[index].restore_status == "running" {
            return Err(BackupError::Conflict(
                "a running backup or restore cannot be deleted".to_owned(),
            ));
        }
        records.remove(index);
        Ok(())
    })
    .await
}

async fn mutate_records<T>(
    pool: &PgPool,
    mutation: impl FnOnce(&mut Vec<BackupRecord>) -> Result<T, BackupError>,
) -> Result<T, BackupError> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(BACKUP_RECORDS_KEY)
        .execute(&mut *transaction)
        .await?;
    let raw = sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key = $1")
        .bind(BACKUP_RECORDS_KEY)
        .fetch_optional(&mut *transaction)
        .await?;
    let mut records: Vec<BackupRecord> = raw
        .map(|raw| serde_json::from_str(&raw))
        .transpose()
        .map_err(|error| {
            BackupError::Internal(format!("stored backup records are invalid: {error}"))
        })?
        .unwrap_or_default();
    let output = mutation(&mut records)?;
    records.sort_by(|left, right| right.started_at.cmp(&left.started_at));
    records.truncate(MAX_BACKUP_RECORDS);
    let serialized = serde_json::to_string(&records).map_err(|error| {
        BackupError::Internal(format!("cannot serialize backup records: {error}"))
    })?;
    sqlx::query(
        "INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, NOW()) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
    )
    .bind(BACKUP_RECORDS_KEY)
    .bind(serialized)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(output)
}

async fn finish_failed_backup(pool: &PgPool, id: &str, message: String) {
    let finished_at = Utc::now().to_rfc3339();
    if let Err(error) = update_record(pool, id, |record| {
        "failed".clone_into(&mut record.status);
        record.error_message.clone_from(&message);
        record.progress.clear();
        record.finished_at.clone_from(&finished_at);
    })
    .await
    {
        tracing::error!(backup_id = %id, error = %error, "cannot persist failed backup record");
    }
}

fn build_s3_key(config: &BackupS3Config, file_name: &str, now: DateTime<Utc>) -> String {
    let prefix = config.prefix.trim_matches('/');
    let prefix = if prefix.is_empty() { "backups" } else { prefix };
    format!("{prefix}/{}/{file_name}", now.format("%Y/%m/%d"))
}

#[derive(Clone)]
struct S3Client {
    config: BackupS3Config,
    client: Client,
}

impl S3Client {
    fn new(config: BackupS3Config) -> Result<Self, BackupError> {
        validate_s3_config(&config, true)?;
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .redirect(Policy::none())
            .build()
            .map_err(|error| {
                BackupError::Internal(format!("cannot initialize S3 client: {error}"))
            })?;
        Ok(Self { config, client })
    }

    async fn head_bucket(&self) -> Result<(), BackupError> {
        let url = self.object_url(None)?;
        self.send_empty(Method::HEAD, url, false, Some(Duration::from_secs(30)))
            .await
    }

    async fn delete_object(&self, key: &str) -> Result<(), BackupError> {
        let url = self.object_url(Some(key))?;
        self.send_empty(Method::DELETE, url, true, Some(Duration::from_secs(30)))
            .await
    }

    async fn upload_file(
        &self,
        key: &str,
        path: &Path,
        payload_hash: &str,
        size: u64,
    ) -> Result<(), BackupError> {
        let url = self.object_url(Some(key))?;
        let signed = sign_headers(&self.config, &Method::PUT, &url, payload_hash, Utc::now())?;
        let file = tokio::fs::File::open(path).await.map_err(|error| {
            BackupError::Internal(format!("cannot open backup for upload: {error}"))
        })?;
        let body = Body::wrap_stream(ReaderStream::new(file));
        let response = self
            .client
            .put(url)
            .headers(signed)
            .header(CONTENT_LENGTH, size.to_string())
            .header(CONTENT_TYPE, "application/vnd.postgresql.custom")
            .body(body)
            .send()
            .await
            .map_err(|error| BackupError::Internal(format!("S3 upload request failed: {error}")))?;
        ensure_s3_success(response.status(), false, "upload")
    }

    async fn download_file(
        &self,
        key: &str,
        path: &Path,
        expected_size: u64,
        expected_sha256: Option<&str>,
    ) -> Result<(), BackupError> {
        let url = self.object_url(Some(key))?;
        let signed = sign_headers(&self.config, &Method::GET, &url, EMPTY_SHA256, Utc::now())?;
        let response = self
            .client
            .get(url)
            .headers(signed)
            .send()
            .await
            .map_err(|error| {
                BackupError::Internal(format!("S3 download request failed: {error}"))
            })?;
        ensure_s3_success(response.status(), false, "download")?;
        if let Some(content_length) = response.content_length()
            && content_length != expected_size
        {
            return Err(BackupError::Internal(format!(
                "S3 backup size mismatch: expected {expected_size} bytes, received {content_length}"
            )));
        }

        let mut output = tokio::fs::File::create(path).await.map_err(|error| {
            BackupError::Internal(format!("cannot create temporary backup file: {error}"))
        })?;
        let mut digest = Sha256::new();
        let mut received = 0_u64;
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| {
                BackupError::Internal(format!("cannot read S3 backup response: {error}"))
            })?;
            received = received
                .checked_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX))
                .ok_or_else(|| BackupError::Internal("S3 backup is too large".to_owned()))?;
            if received > expected_size {
                return Err(BackupError::Internal(format!(
                    "S3 backup exceeded its recorded size of {expected_size} bytes"
                )));
            }
            digest.update(&chunk);
            output.write_all(&chunk).await.map_err(|error| {
                BackupError::Internal(format!("cannot write downloaded backup: {error}"))
            })?;
        }
        output.flush().await.map_err(|error| {
            BackupError::Internal(format!("cannot flush downloaded backup: {error}"))
        })?;
        output.sync_all().await.map_err(|error| {
            BackupError::Internal(format!("cannot sync downloaded backup: {error}"))
        })?;
        drop(output);
        if received != expected_size {
            return Err(BackupError::Internal(format!(
                "S3 backup size mismatch: expected {expected_size} bytes, received {received}"
            )));
        }
        if let Some(expected_sha256) = expected_sha256 {
            let actual_sha256 = hex::encode(digest.finalize());
            if !actual_sha256.eq_ignore_ascii_case(expected_sha256) {
                return Err(BackupError::Internal(
                    "S3 backup SHA-256 digest mismatch".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn presign_get(&self, key: &str, expires_seconds: u64) -> Result<String, BackupError> {
        let url = self.object_url(Some(key))?;
        presign_url(&self.config, &Method::GET, url, expires_seconds, Utc::now()).map(String::from)
    }

    async fn send_empty(
        &self,
        method: Method,
        url: Url,
        allow_not_found: bool,
        timeout: Option<Duration>,
    ) -> Result<(), BackupError> {
        let signed = sign_headers(&self.config, &method, &url, EMPTY_SHA256, Utc::now())?;
        let mut request = self.client.request(method, url).headers(signed);
        if let Some(timeout) = timeout {
            request = request.timeout(timeout);
        }
        let response = request
            .send()
            .await
            .map_err(|error| BackupError::Internal(format!("S3 request failed: {error}")))?;
        ensure_s3_success(response.status(), allow_not_found, "request")
    }

    fn object_url(&self, key: Option<&str>) -> Result<Url, BackupError> {
        let region = effective_region(&self.config);
        let mut url = if self.config.endpoint.trim().is_empty() {
            Url::parse(&format!("https://s3.{region}.amazonaws.com")).map_err(|error| {
                BackupError::Internal(format!("cannot build AWS S3 endpoint: {error}"))
            })?
        } else {
            Url::parse(self.config.endpoint.trim())
                .map_err(|_| BackupError::Invalid("S3 endpoint must be a valid URL".to_owned()))?
        };
        if self.config.force_path_style {
            append_url_path(&mut url, Some(self.config.bucket.trim()), key)?;
        } else {
            let host = url
                .host_str()
                .ok_or_else(|| BackupError::Invalid("S3 endpoint has no host".to_owned()))?;
            let virtual_host = format!("{}.{}", self.config.bucket.trim(), host);
            url.set_host(Some(&virtual_host)).map_err(|_| {
                BackupError::Invalid(
                    "S3 bucket cannot be used with virtual-hosted addressing; enable force_path_style"
                        .to_owned(),
                )
            })?;
            append_url_path(&mut url, None, key)?;
        }
        Ok(url)
    }
}

fn append_url_path(
    url: &mut Url,
    bucket: Option<&str>,
    key: Option<&str>,
) -> Result<(), BackupError> {
    let mut segments = url.path_segments_mut().map_err(|()| {
        BackupError::Invalid("S3 endpoint cannot contain hierarchical paths".to_owned())
    })?;
    segments.pop_if_empty();
    if let Some(bucket) = bucket {
        segments.push(bucket);
    }
    if let Some(key) = key {
        for segment in key.split('/') {
            if !segment.is_empty() {
                segments.push(segment);
            }
        }
    }
    Ok(())
}

fn ensure_s3_success(
    status: StatusCode,
    allow_not_found: bool,
    operation: &str,
) -> Result<(), BackupError> {
    if status.is_success() || (allow_not_found && status == StatusCode::NOT_FOUND) {
        Ok(())
    } else {
        Err(BackupError::Internal(format!(
            "S3 {operation} returned HTTP {}",
            status.as_u16()
        )))
    }
}

async fn hash_file(path: &Path) -> Result<(String, u64), BackupError> {
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|error| BackupError::Internal(format!("cannot hash backup file: {error}")))?;
    let mut digest = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1_024];
    loop {
        let read = file
            .read(&mut buffer)
            .await
            .map_err(|error| BackupError::Internal(format!("cannot hash backup file: {error}")))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        size = size.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
    }
    Ok((hex::encode(digest.finalize()), size))
}

fn effective_region(config: &BackupS3Config) -> &str {
    let region = config.region.trim();
    if region.is_empty() || (region == "auto" && config.endpoint.trim().is_empty()) {
        "us-east-1"
    } else {
        region
    }
}

fn sign_headers(
    config: &BackupS3Config,
    method: &Method,
    url: &Url,
    payload_hash: &str,
    now: DateTime<Utc>,
) -> Result<HeaderMap, BackupError> {
    let host = canonical_host(url)?;
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();
    let canonical_headers =
        format!("host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n");
    let signed_header_names = "host;x-amz-content-sha256;x-amz-date";
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.as_str(),
        canonical_uri(url.path()),
        canonical_query(url),
        canonical_headers,
        signed_header_names,
        payload_hash
    );
    let region = effective_region(config);
    let scope = format!("{date}/{region}/{S3_SERVICE}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let signature = signing_signature(&config.secret_access_key, &date, region, &string_to_sign);
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_header_names}, Signature={signature}",
        config.access_key_id.trim()
    );
    let mut headers = HeaderMap::new();
    headers.insert(HOST, header_value(&host, "S3 host")?);
    headers.insert("x-amz-date", header_value(&amz_date, "S3 date")?);
    headers.insert(
        "x-amz-content-sha256",
        header_value(payload_hash, "S3 payload hash")?,
    );
    headers.insert(
        AUTHORIZATION,
        header_value(&authorization, "S3 authorization")?,
    );
    Ok(headers)
}

fn presign_url(
    config: &BackupS3Config,
    method: &Method,
    mut url: Url,
    expires_seconds: u64,
    now: DateTime<Utc>,
) -> Result<Url, BackupError> {
    if !(1..=604_800).contains(&expires_seconds) {
        return Err(BackupError::Invalid(
            "S3 signed URL expiry must be between 1 and 604800 seconds".to_owned(),
        ));
    }
    let host = canonical_host(&url)?;
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();
    let region = effective_region(config);
    let scope = format!("{date}/{region}/{S3_SERVICE}/aws4_request");
    let mut query = vec![
        ("X-Amz-Algorithm", "AWS4-HMAC-SHA256".to_owned()),
        (
            "X-Amz-Credential",
            format!("{}/{scope}", config.access_key_id.trim()),
        ),
        ("X-Amz-Date", amz_date.clone()),
        ("X-Amz-Expires", expires_seconds.to_string()),
        ("X-Amz-SignedHeaders", "host".to_owned()),
    ];
    let canonical_query = encoded_query(&query);
    let canonical_request = format!(
        "{}\n{}\n{}\nhost:{host}\n\nhost\nUNSIGNED-PAYLOAD",
        method.as_str(),
        canonical_uri(url.path()),
        canonical_query
    );
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let signature = signing_signature(&config.secret_access_key, &date, region, &string_to_sign);
    query.push(("X-Amz-Signature", signature));
    url.set_query(Some(&encoded_query(&query)));
    Ok(url)
}

fn header_value(value: &str, label: &str) -> Result<HeaderValue, BackupError> {
    HeaderValue::from_str(value)
        .map_err(|_| BackupError::Invalid(format!("{label} contains invalid bytes")))
}

fn canonical_host(url: &Url) -> Result<String, BackupError> {
    let host = url
        .host_str()
        .ok_or_else(|| BackupError::Invalid("S3 URL has no host".to_owned()))?
        .to_ascii_lowercase();
    Ok(url
        .port()
        .map_or(host.clone(), |port| format!("{host}:{port}")))
}

fn canonical_uri(encoded_path: &str) -> String {
    let decoded = percent_decode(encoded_path.as_bytes());
    let encoded = aws_percent_encode(&decoded, false);
    if encoded.is_empty() {
        "/".to_owned()
    } else {
        encoded
    }
}

fn canonical_query(url: &Url) -> String {
    let pairs = url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    encoded_query_owned(&pairs)
}

fn encoded_query(query: &[(&str, String)]) -> String {
    let owned = query
        .iter()
        .map(|(key, value)| ((*key).to_owned(), value.clone()))
        .collect::<Vec<_>>();
    encoded_query_owned(&owned)
}

fn encoded_query_owned(query: &[(String, String)]) -> String {
    let mut pairs = query
        .iter()
        .map(|(key, value)| {
            (
                aws_percent_encode(key.as_bytes(), true),
                aws_percent_encode(value.as_bytes(), true),
            )
        })
        .collect::<Vec<_>>();
    pairs.sort_unstable();
    pairs
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn aws_percent_encode(input: &[u8], encode_slash: bool) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(input.len());
    for &byte in input {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || (!encode_slash && byte == b'/')
        {
            output.push(char::from(byte));
        } else {
            output.push('%');
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    output
}

fn percent_decode(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if input[index] == b'%'
            && index + 2 < input.len()
            && let (Some(high), Some(low)) =
                (hex_value(input[index + 1]), hex_value(input[index + 2]))
        {
            output.push((high << 4) | low);
            index += 3;
        } else {
            output.push(input[index]);
            index += 1;
        }
    }
    output
}

const fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn sha256_hex(input: &[u8]) -> String {
    hex::encode(Sha256::digest(input))
}

fn signing_signature(secret: &str, date: &str, region: &str, string_to_sign: &str) -> String {
    let date_key = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let region_key = hmac_sha256(&date_key, region.as_bytes());
    let service_key = hmac_sha256(&region_key, S3_SERVICE.as_bytes());
    let signing_key = hmac_sha256(&service_key, b"aws4_request");
    hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()))
}

fn hmac_sha256(key: &[u8], input: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(input);
    let digest = mac.finalize().into_bytes();
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    output
}

#[derive(Clone, Debug)]
struct CronField {
    allowed: Vec<bool>,
    minimum: u32,
    maximum: u32,
    wildcard: bool,
    sunday_alias: bool,
}

impl CronField {
    fn parse(
        raw: &str,
        minimum: u32,
        maximum: u32,
        sunday_alias: bool,
    ) -> Result<Self, BackupError> {
        if raw.is_empty() {
            return Err(invalid_cron("empty field"));
        }
        let storage_max = if sunday_alias { 6 } else { maximum };
        let storage_len = usize::try_from(storage_max - minimum + 1)
            .map_err(|_| invalid_cron("field range is too large"))?;
        let mut field = Self {
            allowed: vec![false; storage_len],
            minimum,
            maximum,
            wildcard: raw.starts_with('*'),
            sunday_alias,
        };
        for item in raw.split(',') {
            field.add_item(item)?;
        }
        if field.allowed.iter().all(|allowed| !allowed) {
            return Err(invalid_cron("field selects no values"));
        }
        Ok(field)
    }

    fn add_item(&mut self, item: &str) -> Result<(), BackupError> {
        let mut step_parts = item.split('/');
        let base = step_parts.next().unwrap_or_default();
        let step = step_parts
            .next()
            .map(parse_cron_number)
            .transpose()?
            .unwrap_or(1);
        if step_parts.next().is_some() || step == 0 {
            return Err(invalid_cron("invalid step"));
        }
        let (start, end) = if base == "*" {
            (self.minimum, self.maximum)
        } else if let Some((start, end)) = base.split_once('-') {
            (parse_cron_number(start)?, parse_cron_number(end)?)
        } else {
            let value = parse_cron_number(base)?;
            (value, value)
        };
        if start < self.minimum || end > self.maximum || start > end {
            return Err(invalid_cron("value is outside its field range"));
        }
        let mut value = start;
        while value <= end {
            let normalized = if self.sunday_alias && value == 7 {
                0
            } else {
                value
            };
            let index = usize::try_from(normalized - self.minimum)
                .map_err(|_| invalid_cron("field index is invalid"))?;
            self.allowed[index] = true;
            let Some(next) = value.checked_add(step) else {
                break;
            };
            value = next;
        }
        Ok(())
    }

    fn contains(&self, value: u32) -> bool {
        let normalized = if self.sunday_alias && value == 7 {
            0
        } else {
            value
        };
        normalized
            .checked_sub(self.minimum)
            .and_then(|index| usize::try_from(index).ok())
            .and_then(|index| self.allowed.get(index))
            .copied()
            .unwrap_or(false)
    }
}

#[derive(Clone, Debug)]
struct CronSchedule {
    minute: CronField,
    hour: CronField,
    day_of_month: CronField,
    month: CronField,
    day_of_week: CronField,
}

impl CronSchedule {
    fn parse(expression: &str) -> Result<Self, BackupError> {
        let fields = expression.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 5 {
            return Err(invalid_cron("expected exactly five fields"));
        }
        Ok(Self {
            minute: CronField::parse(fields[0], 0, 59, false)?,
            hour: CronField::parse(fields[1], 0, 23, false)?,
            day_of_month: CronField::parse(fields[2], 1, 31, false)?,
            month: CronField::parse(fields[3], 1, 12, false)?,
            day_of_week: CronField::parse(fields[4], 0, 7, true)?,
        })
    }

    fn matches<Tz>(&self, now: &DateTime<Tz>) -> bool
    where
        Tz: TimeZone,
    {
        let day_of_month_matches = self.day_of_month.contains(now.day());
        let day_of_week_matches = self
            .day_of_week
            .contains(now.weekday().num_days_from_sunday());
        let day_matches = match (self.day_of_month.wildcard, self.day_of_week.wildcard) {
            (true, true) => true,
            (true, false) => day_of_week_matches,
            (false, true) => day_of_month_matches,
            (false, false) => day_of_month_matches || day_of_week_matches,
        };
        self.minute.contains(now.minute())
            && self.hour.contains(now.hour())
            && self.month.contains(now.month())
            && day_matches
    }
}

fn parse_cron_number(raw: &str) -> Result<u32, BackupError> {
    raw.parse::<u32>()
        .map_err(|_| invalid_cron("fields must use numeric values"))
}

fn invalid_cron(reason: &str) -> BackupError {
    BackupError::Invalid(format!(
        "cron_expr must be a valid five-field cron expression: {reason}"
    ))
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use flate2::{Compression, write::GzEncoder};
    use sqlx::{Connection, PgConnection, postgres::PgPoolOptions};
    use tokio::net::TcpListener;

    use super::*;

    fn test_config() -> BackupS3Config {
        BackupS3Config {
            endpoint: "https://s3.example.test/base".to_owned(),
            region: "us-east-1".to_owned(),
            bucket: "backup-bucket".to_owned(),
            access_key_id: "AKIDEXAMPLE".to_owned(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_owned(),
            prefix: "backups/".to_owned(),
            force_path_style: true,
        }
    }

    #[test]
    fn sigv4_header_signing_is_deterministic() {
        let config = test_config();
        let client = S3Client::new(config.clone()).unwrap();
        let url = client.object_url(Some("2026/07/db dump.dump")).unwrap();
        assert_eq!(
            url.as_str(),
            "https://s3.example.test/base/backup-bucket/2026/07/db%20dump.dump"
        );
        let now = Utc.with_ymd_and_hms(2026, 7, 14, 3, 4, 5).unwrap();
        let headers = sign_headers(&config, &Method::PUT, &url, EMPTY_SHA256, now).unwrap();
        assert_eq!(
            headers.get(AUTHORIZATION).unwrap().to_str().unwrap(),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260714/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=95f630f3cfb4b011663e983cd188d1737720853d2a02bb64e0b36c9a8e25dcd1"
        );
    }

    #[test]
    fn presigned_url_uses_virtual_or_path_style_endpoint() {
        let mut config = test_config();
        config.force_path_style = false;
        config.endpoint = "https://objects.example.test".to_owned();
        let client = S3Client::new(config.clone()).unwrap();
        let url = client.object_url(Some("backups/db.dump")).unwrap();
        assert_eq!(
            url.as_str(),
            "https://backup-bucket.objects.example.test/backups/db.dump"
        );
        let now = Utc.with_ymd_and_hms(2026, 7, 14, 3, 4, 5).unwrap();
        let signed = presign_url(&config, &Method::GET, url, 300, now).unwrap();
        assert!(signed.as_str().contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
        assert!(signed.as_str().contains("X-Amz-Expires=300"));
        assert!(signed.as_str().contains("X-Amz-Signature="));
        assert!(!signed.as_str().contains(&config.secret_access_key));
    }

    #[test]
    fn cron_supports_lists_ranges_steps_and_standard_day_or_semantics() {
        let cron = CronSchedule::parse("*/15 2,8-10 1 1-6 1-5").unwrap();
        assert!(cron.matches(&Utc.with_ymd_and_hms(2026, 2, 1, 8, 30, 0).unwrap()));
        assert!(cron.matches(&Utc.with_ymd_and_hms(2026, 2, 2, 8, 30, 0).unwrap()));
        assert!(!cron.matches(&Utc.with_ymd_and_hms(2026, 8, 2, 8, 30, 0).unwrap()));
        assert!(!cron.matches(&Utc.with_ymd_and_hms(2026, 2, 2, 8, 31, 0).unwrap()));
        assert!(
            CronSchedule::parse("0 0 * * 7")
                .unwrap()
                .matches(&Utc.with_ymd_and_hms(2026, 7, 19, 0, 0, 0).unwrap())
        );
    }

    #[test]
    fn schedule_runs_at_most_once_per_utc_minute() {
        let schedule = BackupSchedule {
            enabled: true,
            cron_expr: "4 3 * * *".to_owned(),
            retain_days: 14,
            retain_count: 10,
        };
        let now = Utc.with_ymd_and_hms(2026, 7, 14, 3, 4, 5).unwrap();
        assert!(schedule_is_due(&schedule, None, &now).unwrap());
        assert!(!schedule_is_due(&schedule, Some("2026-07-14T03:04Z"), &now).unwrap());
        assert!(
            !schedule_is_due(
                &schedule,
                None,
                &Utc.with_ymd_and_hms(2026, 7, 14, 3, 5, 0).unwrap()
            )
            .unwrap()
        );
    }

    #[test]
    fn invalid_cron_ranges_and_steps_are_rejected() {
        for expression in ["* * * *", "60 * * * *", "*/0 * * * *", "5-2 * * * *"] {
            assert!(validate_cron(expression).is_err(), "{expression}");
        }
    }

    #[tokio::test]
    async fn s3_restore_download_requires_exact_size_and_sha256() {
        let body = b"verified PostgreSQL custom backup".to_vec();
        let expected_sha256 = hex::encode(Sha256::digest(&body));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let response_body = body.clone();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1_024];
            loop {
                let read = socket.read(&mut chunk).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            assert!(String::from_utf8_lossy(&request).starts_with("GET /bucket/backup.dump"));
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response_body.len()
            );
            socket.write_all(headers.as_bytes()).await.unwrap();
            socket.write_all(&response_body).await.unwrap();
        });
        let config = BackupS3Config {
            endpoint: format!("http://{address}"),
            region: "us-east-1".to_owned(),
            bucket: "bucket".to_owned(),
            access_key_id: "test-key".to_owned(),
            secret_access_key: "test-secret".to_owned(),
            prefix: String::new(),
            force_path_style: true,
        };
        let directory = env::temp_dir().join(format!("sub2api-s3-restore-{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(&directory).await.unwrap();
        let path = directory.join("backup.dump");
        S3Client::new(config)
            .unwrap()
            .download_file(
                "backup.dump",
                &path,
                u64::try_from(body.len()).unwrap(),
                Some(&expected_sha256),
            )
            .await
            .unwrap();
        server.await.unwrap();
        assert_eq!(tokio::fs::read(&path).await.unwrap(), body);
        tokio::fs::remove_dir_all(directory).await.unwrap();
    }

    #[test]
    fn legacy_format_inference_survives_future_sha256_backfill() {
        let legacy: BackupRecord = serde_json::from_value(json!({
            "id": "legacy",
            "status": "completed",
            "backup_type": "postgres",
            "file_name": "sub2api_20260714_000000.sql.gz",
            "s3_key": "backups/2026/07/14/sub2api_20260714_000000.sql.gz",
            "size_bytes": 10,
            "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "triggered_by": "manual",
            "started_at": "2026-07-14T00:00:00Z"
        }))
        .unwrap();
        assert_eq!(
            backup_artifact_format(&legacy).unwrap(),
            BackupArtifactFormat::LegacyGzipSql
        );

        let mut custom = legacy.clone();
        custom.file_name = "sub2api.dump".to_owned();
        custom.s3_key = "backups/sub2api.dump".to_owned();
        custom.artifact_format = ARTIFACT_FORMAT_PG_CUSTOM.to_owned();
        assert_eq!(
            backup_artifact_format(&custom).unwrap(),
            BackupArtifactFormat::PostgresCustom
        );
    }

    #[tokio::test]
    async fn corrupt_legacy_gzip_crc_is_rejected_and_sql_is_removed() {
        let directory = env::temp_dir().join(format!("sub2api-legacy-gzip-{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(&directory).await.unwrap();
        let compressed_path = directory.join("legacy.sql.gz");
        let sql_path = directory.join("legacy.sql");
        let file = std::fs::File::create(&compressed_path).unwrap();
        let mut encoder = GzEncoder::new(file, Compression::default());
        std::io::Write::write_all(&mut encoder, b"CREATE TABLE integrity_test(id bigint);\n")
            .unwrap();
        encoder.finish().unwrap();
        let mut compressed = tokio::fs::read(&compressed_path).await.unwrap();
        let crc_index = compressed.len() - 8;
        compressed[crc_index] ^= 0xff;
        tokio::fs::write(&compressed_path, compressed)
            .await
            .unwrap();

        let error = decompress_legacy_gzip(&compressed_path, &sql_path, 1_024)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("CRC validation"));
        assert!(!sql_path.exists());
        tokio::fs::remove_dir_all(directory).await.unwrap();
    }

    #[tokio::test]
    async fn legacy_gzip_respects_output_limit_and_removes_sql() {
        let directory = env::temp_dir().join(format!("sub2api-legacy-limit-{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(&directory).await.unwrap();
        let compressed_path = directory.join("legacy.sql.gz");
        let sql_path = directory.join("legacy.sql");
        let file = std::fs::File::create(&compressed_path).unwrap();
        let mut encoder = GzEncoder::new(file, Compression::default());
        std::io::Write::write_all(&mut encoder, &vec![b'x'; 4_096]).unwrap();
        encoder.finish().unwrap();

        let error = decompress_legacy_gzip(&compressed_path, &sql_path, 1_024)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("configured 1024-byte restore limit")
        );
        assert!(!sql_path.exists());
        tokio::fs::remove_dir_all(directory).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL pointing at a disposable PostgreSQL *_test database"]
    async fn postgres_operation_lock_and_restore_write_gate_are_cross_instance() {
        let database_url = env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL is required");
        let parsed = Url::parse(&database_url).expect("TEST_DATABASE_URL must be a URL");
        assert!(
            parsed.path().trim_matches('/').ends_with("_test"),
            "refusing to alter database defaults outside a *_test database"
        );
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&database_url)
            .await
            .unwrap();
        let mut guard = try_operation_lock(&pool).await.unwrap();
        let mut competing = PgConnection::connect(&database_url).await.unwrap();
        let acquired = sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_lock($1)")
            .bind(BACKUP_OPERATION_LOCK_KEY)
            .fetch_one(&mut competing)
            .await
            .unwrap();
        assert!(!acquired);
        competing.close().await.unwrap();

        let gate = quiesce_application_writes(&mut guard).await.unwrap();
        let mut read_only = PgConnection::connect(&database_url).await.unwrap();
        let setting = sqlx::query_scalar::<_, String>(
            "SELECT current_setting('default_transaction_read_only')",
        )
        .fetch_one(&mut read_only)
        .await
        .unwrap();
        assert_eq!(setting, "on");
        read_only.close().await.unwrap();
        resume_application_writes(&mut guard, gate).await.unwrap();

        let mut writable = PgConnection::connect(&database_url).await.unwrap();
        let setting = sqlx::query_scalar::<_, String>(
            "SELECT current_setting('default_transaction_read_only')",
        )
        .fetch_one(&mut writable)
        .await
        .unwrap();
        assert_eq!(setting, "off");
        writable.close().await.unwrap();
        drop(guard);
        pool.close().await;
    }
}
