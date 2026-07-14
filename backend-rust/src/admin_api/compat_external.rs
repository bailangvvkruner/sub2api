//! Administrator operations that touch the local `PostgreSQL` runtime or fixed upstream services.

use std::{
    collections::{BTreeMap, HashSet},
    env,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};

use axum::http::Method;
use chrono::Utc;
use reqwest::{Client, Proxy, redirect::Policy};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sqlx::{PgPool, Postgres, Row, Transaction};
use tokio::process::Command;
use url::Url;
use uuid::Uuid;

use super::{AdminError, AdminIdentity};
use crate::{
    backup_runtime::{self, BackupError, BackupRecord, BackupS3Config, BackupSchedule},
    payment_api::{
        ProviderRuntime,
        refund::{
            ProviderRefundRequest, ProviderRefundResult, ProviderRefundStatus, RefundProvider,
        },
    },
    security::{password, secrets},
};

const BACKUP_S3_KEY: &str = "backup_s3_config";
const BACKUP_SCHEDULE_KEY: &str = "backup_schedule";
const BACKUP_RECORDS_KEY: &str = "backup_records";
const DATA_CONFIG_KEY: &str = "data_management_config";
const DATA_S3_PROFILES_KEY: &str = "data_management_s3_profiles";
const DATA_BACKUP_JOBS_KEY: &str = "data_management_backup_jobs";
const PG_RESTORE_SAFETY_ARGS: &[&str] = &[
    "--clean",
    "--if-exists",
    "--no-owner",
    "--no-privileges",
    "--single-transaction",
    "--exit-on-error",
];
const PSQL_RESTORE_SAFETY_ARGS: &[&str] = &[
    "--no-psqlrc",
    "--single-transaction",
    "--set",
    "ON_ERROR_STOP=on",
    "--file",
];
const GITHUB_RELEASES_URL: &str = "https://api.github.com/repos/Wei-Shaw/sub2api/releases";
const SYSTEM_DEPLOYMENT_REQUEST_KEY: &str = "system_deployment_request";
const SYSTEM_DEPLOYMENT_HISTORY_KEY: &str = "system_deployment_history";
const SYSTEM_DEPLOYMENT_LOCK_KEY: i64 = 0x5355_4232_4445_504c;
const MAX_SYSTEM_DEPLOYMENT_HISTORY: usize = 50;
const PROFILE_SECRET_FIELDS: &[&str] = &[
    "secret",
    "password",
    "token",
    "access_key",
    "secret_access_key",
];

#[derive(Clone, Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    published_at: String,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    assets: Vec<GitHubAsset>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
    size: i64,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn dispatch(
    pool: &PgPool,
    actor: &AdminIdentity,
    handler: &str,
    category: &str,
    method: &Method,
    path: &str,
    _query: &BTreeMap<String, String>,
    payload: Value,
) -> Option<Result<Value, AdminError>> {
    let result = match handler {
        "h.Admin.Backup.GetS3Config" => get_backup_s3_config(pool).await,
        "h.Admin.Backup.UpdateS3Config" => update_backup_s3_config(pool, payload).await,
        "h.Admin.Backup.TestS3Connection" => test_s3_config(pool, payload).await,
        "h.Admin.Backup.GetSchedule" => get_backup_schedule(pool).await,
        "h.Admin.Backup.UpdateSchedule" => update_backup_schedule(pool, payload).await,
        "h.Admin.Backup.CreateBackup" => start_backup(pool, &payload, "manual").await,
        "h.Admin.Backup.ListBackups" => list_backups(pool).await,
        "h.Admin.Backup.GetBackup" => get_backup(pool, backup_id(path)?).await,
        "h.Admin.Backup.DeleteBackup" => delete_backup(pool, backup_id(path)?).await,
        "h.Admin.Backup.GetDownloadURL" => backup_download_url(pool, backup_id(path)?).await,
        "h.Admin.Backup.RestoreBackup" => {
            restore_backup(pool, actor, backup_id(path)?, &payload).await
        }
        "h.Admin.DataManagement.GetAgentHealth" => Ok(json!({
            "healthy": true,
            "enabled": false,
            "mode": "embedded_postgresql",
            "message": "backup and profile management are handled by the Rust process",
        })),
        "h.Admin.DataManagement.GetConfig" => get_data_config(pool).await,
        "h.Admin.DataManagement.UpdateConfig" => update_data_config(pool, payload).await,
        "h.Admin.DataManagement.ListS3Profiles" => list_profiles(pool, DATA_S3_PROFILES_KEY).await,
        "h.Admin.DataManagement.CreateS3Profile" => {
            create_profile(pool, DATA_S3_PROFILES_KEY, payload).await
        }
        "h.Admin.DataManagement.UpdateS3Profile" => {
            update_profile(pool, DATA_S3_PROFILES_KEY, profile_id(path)?, payload).await
        }
        "h.Admin.DataManagement.DeleteS3Profile" => {
            delete_profile(pool, DATA_S3_PROFILES_KEY, profile_id(path)?).await
        }
        "h.Admin.DataManagement.SetActiveS3Profile" => {
            activate_profile(pool, DATA_S3_PROFILES_KEY, profile_id(path)?).await
        }
        "h.Admin.DataManagement.TestS3" => test_data_s3(pool, payload).await,
        "h.Admin.DataManagement.ListSourceProfiles" => match source_profiles_key(path) {
            Ok(key) => list_profiles(pool, &key).await,
            Err(error) => Err(error),
        },
        "h.Admin.DataManagement.CreateSourceProfile" => match source_profiles_key(path) {
            Ok(key) => create_profile(pool, &key, payload).await,
            Err(error) => Err(error),
        },
        "h.Admin.DataManagement.UpdateSourceProfile" => match source_profiles_key(path) {
            Ok(key) => update_profile(pool, &key, profile_id(path)?, payload).await,
            Err(error) => Err(error),
        },
        "h.Admin.DataManagement.DeleteSourceProfile" => match source_profiles_key(path) {
            Ok(key) => delete_profile(pool, &key, profile_id(path)?).await,
            Err(error) => Err(error),
        },
        "h.Admin.DataManagement.SetActiveSourceProfile" => match source_profiles_key(path) {
            Ok(key) => activate_profile(pool, &key, profile_id(path)?).await,
            Err(error) => Err(error),
        },
        "h.Admin.DataManagement.ListBackupJobs" => list_data_backup_jobs(pool).await,
        "h.Admin.DataManagement.GetBackupJob" => get_data_backup_job(pool, job_id(path)?).await,
        "h.Admin.DataManagement.CreateBackupJob" => create_data_backup_job(pool, payload).await,
        "h.Admin.System.CheckUpdates" => check_updates().await,
        "h.Admin.System.GetRollbackVersions" => rollback_versions().await,
        "h.Admin.System.PerformUpdate" => deployment_request(pool, "update", payload).await,
        "h.Admin.System.Rollback" => deployment_request(pool, "rollback", payload).await,
        "h.Admin.System.RestartService" => deployment_request(pool, "restart", payload).await,
        "h.Admin.Proxy.Test" => proxy_test(pool, proxy_id(path)?, false).await,
        "h.Admin.Proxy.CheckQuality" => proxy_test(pool, proxy_id(path)?, true).await,
        "adminPaymentHandler.ProcessRefund" => {
            process_provider_refund(pool, actor, payment_order_id(path)?, payload).await
        }
        "adminPaymentHandler.QueryAndFinalizeRefund" => {
            query_and_finalize_refund(pool, actor, payment_order_id(path)?).await
        }
        _ if category == "admin/data-management" => Err(AdminError::BadRequest(format!(
            "unsupported embedded data-management operation: {}",
            handler.rsplit('.').next().unwrap_or(handler)
        ))),
        _ if category == "admin/backups" => Err(AdminError::BadRequest(format!(
            "unsupported PostgreSQL backup operation: {}",
            handler.rsplit('.').next().unwrap_or(handler)
        ))),
        _ => return None,
    };
    let _ = method;
    Some(result)
}

const fn default_retain_days() -> i64 {
    backup_runtime::default_retain_days()
}

fn map_backup_error(error: BackupError) -> AdminError {
    match error {
        BackupError::Invalid(message) => AdminError::BadRequest(message),
        BackupError::Conflict(message) => AdminError::Conflict(message),
        BackupError::NotFound => AdminError::NotFound("backup"),
        BackupError::Internal(message) => AdminError::Probe(message),
    }
}

async fn setting_json(pool: &PgPool, key: &str) -> Result<Option<Value>, AdminError> {
    let raw = sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key = $1")
        .bind(key)
        .fetch_optional(pool)
        .await?;
    raw.map(|value| {
        serde_json::from_str(&value)
            .map_err(|error| AdminError::Probe(format!("setting {key} is invalid JSON: {error}")))
    })
    .transpose()
}

async fn get_data_config(pool: &PgPool) -> Result<Value, AdminError> {
    Ok(redact_profile_secrets(
        setting_json(pool, DATA_CONFIG_KEY)
            .await?
            .unwrap_or_else(|| {
                json!({
                    "enabled": false,
                    "mode": "embedded_postgresql",
                })
            }),
    ))
}

async fn update_data_config(pool: &PgPool, mut payload: Value) -> Result<Value, AdminError> {
    let previous = setting_json(pool, DATA_CONFIG_KEY).await?;
    encrypt_profile_secrets(&mut payload, previous.as_ref())?;
    put_setting_json(pool, DATA_CONFIG_KEY, &payload).await?;
    Ok(redact_profile_secrets(payload))
}

async fn put_setting_json(pool: &PgPool, key: &str, value: &Value) -> Result<(), AdminError> {
    let raw = serde_json::to_string(value)
        .map_err(|error| AdminError::BadRequest(format!("invalid JSON value: {error}")))?;
    sqlx::query(
        "INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, NOW()) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
    )
    .bind(key)
    .bind(raw)
    .execute(pool)
    .await?;
    Ok(())
}

async fn get_backup_s3_config(pool: &PgPool) -> Result<Value, AdminError> {
    let mut config = load_backup_s3_config(pool).await?;
    let configured = !config.bucket.trim().is_empty()
        && !config.access_key_id.trim().is_empty()
        && !config.secret_access_key.trim().is_empty();
    config.secret_access_key.clear();
    let mut value = serde_json::to_value(config).map_err(|error| {
        AdminError::Probe(format!("cannot serialize S3 configuration: {error}"))
    })?;
    value["secret_configured"] = json!(configured);
    value["storage_mode"] = json!(if configured { "s3_and_local" } else { "local" });
    Ok(value)
}

async fn update_backup_s3_config(pool: &PgPool, payload: Value) -> Result<Value, AdminError> {
    let mut incoming: BackupS3Config = serde_json::from_value(payload)
        .map_err(|error| AdminError::BadRequest(format!("invalid S3 configuration: {error}")))?;
    let previous = load_backup_s3_config(pool).await?;
    if incoming.secret_access_key.trim().is_empty()
        && (!incoming.bucket.trim().is_empty() || !incoming.access_key_id.trim().is_empty())
    {
        incoming.secret_access_key = previous.secret_access_key;
    }
    validate_s3_config(&incoming, false)?;
    let mut stored = incoming.clone();
    stored.secret_access_key = encrypt_secret(&stored.secret_access_key)?;
    put_setting_json(
        pool,
        BACKUP_S3_KEY,
        &serde_json::to_value(&stored).map_err(|error| {
            AdminError::Probe(format!("cannot store S3 configuration: {error}"))
        })?,
    )
    .await?;
    get_backup_s3_config(pool).await
}

async fn load_backup_s3_config(pool: &PgPool) -> Result<BackupS3Config, AdminError> {
    let mut config: BackupS3Config = setting_json(pool, BACKUP_S3_KEY)
        .await?
        .map(|value| {
            serde_json::from_value(value).map_err(|error| {
                AdminError::Probe(format!("stored S3 configuration is invalid: {error}"))
            })
        })
        .transpose()?
        .unwrap_or_default();
    config.secret_access_key = decrypt_secret(&config.secret_access_key)?;
    Ok(config)
}

fn validate_s3_config(config: &BackupS3Config, require_secret: bool) -> Result<(), AdminError> {
    backup_runtime::validate_s3_config(config, require_secret).map_err(map_backup_error)
}

async fn test_s3_config(pool: &PgPool, payload: Value) -> Result<Value, AdminError> {
    let mut config: BackupS3Config = serde_json::from_value(payload)
        .map_err(|error| AdminError::BadRequest(format!("invalid S3 configuration: {error}")))?;
    if config.secret_access_key.trim().is_empty() {
        config.secret_access_key = load_backup_s3_config(pool).await?.secret_access_key;
    }
    match validate_s3_config(&config, true) {
        Ok(()) => match backup_runtime::test_s3_connection(&config).await {
            Ok(()) => Ok(json!({
                "ok": true,
                "message": "S3 connection and credentials verified",
            })),
            Err(error) => Ok(json!({ "ok": false, "message": error.to_string() })),
        },
        Err(error) => Ok(json!({ "ok": false, "message": error.to_string() })),
    }
}

async fn get_backup_schedule(pool: &PgPool) -> Result<Value, AdminError> {
    Ok(setting_json(pool, BACKUP_SCHEDULE_KEY)
        .await?
        .unwrap_or_else(|| serde_json::to_value(BackupSchedule::default()).unwrap_or_default()))
}

async fn update_backup_schedule(pool: &PgPool, payload: Value) -> Result<Value, AdminError> {
    let schedule: BackupSchedule = serde_json::from_value(payload)
        .map_err(|error| AdminError::BadRequest(format!("invalid backup schedule: {error}")))?;
    backup_runtime::validate_schedule(&schedule).map_err(map_backup_error)?;
    let value = serde_json::to_value(schedule)
        .map_err(|error| AdminError::BadRequest(error.to_string()))?;
    put_setting_json(pool, BACKUP_SCHEDULE_KEY, &value).await?;
    Ok(value)
}

#[cfg(test)]
fn validate_cron(value: &str) -> Result<(), AdminError> {
    backup_runtime::validate_cron(value).map_err(map_backup_error)
}

async fn load_backup_records(pool: &PgPool) -> Result<Vec<BackupRecord>, AdminError> {
    setting_json(pool, BACKUP_RECORDS_KEY)
        .await?
        .map(|value| {
            serde_json::from_value(value)
                .map_err(|error| AdminError::Probe(format!("backup records are invalid: {error}")))
        })
        .transpose()
        .map(Option::unwrap_or_default)
}

async fn update_backup_record(
    pool: &PgPool,
    id: &str,
    update: impl FnOnce(&mut BackupRecord),
) -> Result<BackupRecord, AdminError> {
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
        .map(|value| serde_json::from_str(&value))
        .transpose()
        .map_err(|error| AdminError::Probe(format!("backup records are invalid: {error}")))?
        .unwrap_or_default();
    let record = records
        .iter_mut()
        .find(|record| record.id == id)
        .ok_or(AdminError::NotFound("backup"))?;
    update(record);
    let updated = record.clone();
    let serialized = serde_json::to_string(&records)
        .map_err(|error| AdminError::Probe(format!("cannot serialize backup records: {error}")))?;
    sqlx::query(
        "INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, NOW()) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
    )
    .bind(BACKUP_RECORDS_KEY)
    .bind(serialized)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(updated)
}

async fn start_backup(
    pool: &PgPool,
    payload: &Value,
    triggered_by: &str,
) -> Result<Value, AdminError> {
    let expire_days = payload
        .get("expire_days")
        .and_then(Value::as_i64)
        .unwrap_or(default_retain_days());
    let record = backup_runtime::start_backup(pool, expire_days, triggered_by)
        .await
        .map_err(map_backup_error)?;
    serde_json::to_value(record)
        .map_err(|error| AdminError::Probe(format!("cannot serialize backup record: {error}")))
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

fn backup_directory() -> PathBuf {
    backup_runtime::backup_directory()
}

async fn list_backups(pool: &PgPool) -> Result<Value, AdminError> {
    let records = load_backup_records(pool).await?;
    Ok(json!({ "items": records }))
}

async fn get_backup(pool: &PgPool, id: &str) -> Result<Value, AdminError> {
    let record = load_backup_records(pool)
        .await?
        .into_iter()
        .find(|record| record.id == id)
        .ok_or(AdminError::NotFound("backup"))?;
    serde_json::to_value(record)
        .map_err(|error| AdminError::Probe(format!("cannot serialize backup record: {error}")))
}

async fn delete_backup(pool: &PgPool, id: &str) -> Result<Value, AdminError> {
    backup_runtime::delete_backup(pool, id)
        .await
        .map_err(map_backup_error)?;
    Ok(json!({ "deleted": true }))
}

async fn backup_download_url(pool: &PgPool, id: &str) -> Result<Value, AdminError> {
    let download = backup_runtime::backup_download(pool, id)
        .await
        .map_err(map_backup_error)?;
    Ok(json!({
        "url": download.url,
        "expires_in": download.expires_in,
        "storage": download.storage,
    }))
}

async fn restore_backup(
    pool: &PgPool,
    actor: &AdminIdentity,
    id: &str,
    payload: &Value,
) -> Result<Value, AdminError> {
    let password_value = payload
        .get("password")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AdminError::BadRequest("password is required for restore".to_owned()))?;
    verify_actor_password(pool, actor.user_id, password_value).await?;
    let lock = backup_runtime::try_operation_lock(pool)
        .await
        .map_err(map_backup_error)?;
    let record = load_backup_records(pool)
        .await?
        .into_iter()
        .find(|record| record.id == id)
        .ok_or(AdminError::NotFound("backup"))?;
    if record.status != "completed" {
        return Err(AdminError::Conflict(
            "only completed backups can be restored".to_owned(),
        ));
    }
    let id = id.to_owned();
    let running = update_backup_record(pool, &id, |record| {
        "running".clone_into(&mut record.restore_status);
        record.restore_error.clear();
    })
    .await?;
    let task_pool = pool.clone();
    backup_runtime::spawn_operation(async move {
        let mut lock = lock;
        let result = async {
            let artifact = backup_runtime::prepare_restore_file(&task_pool, &record)
                .await
                .map_err(|error| error.to_string())?;
            let write_gate = backup_runtime::quiesce_application_writes(&mut lock)
                .await
                .map_err(|error| error.to_string())?;
            let restore_result = perform_database_restore(&artifact).await;
            let cleanup_result = artifact.cleanup().await.map_err(|error| error.to_string());
            let resume_result = backup_runtime::resume_application_writes(&mut lock, write_gate)
                .await
                .map_err(|error| error.to_string());
            let mut errors = Vec::new();
            if let Err(error) = restore_result {
                errors.push(error);
            }
            if let Err(error) = cleanup_result {
                errors.push(format!("temporary restore cleanup failed: {error}"));
            }
            if let Err(error) = resume_result {
                errors.push(format!("failed to resume writes: {error}"));
            }
            if errors.is_empty() {
                Ok(())
            } else {
                Err(errors.join("; "))
            }
        }
        .await;
        let restored_at = Utc::now().to_rfc3339();
        let record_snapshot = record.clone();
        let _ = update_backup_record(&task_pool, &id, |record| match &result {
            Ok(()) => {
                record.status.clone_from(&record_snapshot.status);
                record.backup_type.clone_from(&record_snapshot.backup_type);
                record.file_name.clone_from(&record_snapshot.file_name);
                record.s3_key.clone_from(&record_snapshot.s3_key);
                record.size_bytes = record_snapshot.size_bytes;
                record
                    .artifact_format
                    .clone_from(&record_snapshot.artifact_format);
                record.sha256.clone_from(&record_snapshot.sha256);
                record
                    .triggered_by
                    .clone_from(&record_snapshot.triggered_by);
                record.started_at.clone_from(&record_snapshot.started_at);
                record.finished_at.clone_from(&record_snapshot.finished_at);
                record.expires_at.clone_from(&record_snapshot.expires_at);
                record.progress.clear();
                record.error_message.clear();
                "completed".clone_into(&mut record.restore_status);
                record.restore_error.clear();
                record.restored_at.clone_from(&restored_at);
            }
            Err(message) => {
                "failed".clone_into(&mut record.restore_status);
                record.restore_error.clone_from(message);
            }
        })
        .await;
    })
    .await;
    serde_json::to_value(running)
        .map_err(|error| AdminError::Probe(format!("cannot serialize restore record: {error}")))
}

async fn perform_database_restore(
    artifact: &backup_runtime::PreparedRestoreFile,
) -> Result<(), String> {
    match artifact.format {
        backup_runtime::BackupArtifactFormat::PostgresCustom => {
            perform_pg_restore(&artifact.path).await
        }
        backup_runtime::BackupArtifactFormat::LegacyGzipSql => {
            perform_psql_restore(&artifact.path).await
        }
    }
}

async fn perform_pg_restore(path: &Path) -> Result<(), String> {
    let mut command = postgres_command("pg_restore");
    command.kill_on_drop(true);
    command.env("PGOPTIONS", "-c default_transaction_read_only=off");
    command
        .args(PG_RESTORE_SAFETY_ARGS)
        .arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let output = command
        .output()
        .await
        .map_err(|error| format!("cannot start pg_restore: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "pg_restore failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

async fn perform_psql_restore(path: &Path) -> Result<(), String> {
    let mut command = postgres_command("psql");
    command.kill_on_drop(true);
    command.env("PGOPTIONS", "-c default_transaction_read_only=off");
    command
        .args(PSQL_RESTORE_SAFETY_ARGS)
        .arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let output = command
        .output()
        .await
        .map_err(|error| format!("cannot start psql restore: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "psql restore failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

async fn verify_actor_password(
    pool: &PgPool,
    actor_id: i64,
    candidate: &str,
) -> Result<(), AdminError> {
    let hash = sqlx::query_scalar::<_, String>(
        "SELECT password_hash FROM users WHERE id = $1 AND role = 'admin' AND status = 'active' AND deleted_at IS NULL",
    )
    .bind(actor_id)
    .fetch_optional(pool)
    .await?
    .ok_or(AdminError::Unauthorized)?;
    let candidate = candidate.to_owned();
    let verified =
        tokio::task::spawn_blocking(move || password::verify_password(&candidate, &hash))
            .await
            .map_err(|error| AdminError::Probe(format!("password verification failed: {error}")))?
            .map_err(|error| AdminError::Probe(format!("password verification failed: {error}")))?;
    if !verified {
        return Err(AdminError::BadRequest(
            "incorrect administrator password".to_owned(),
        ));
    }
    Ok(())
}

async fn list_profiles(pool: &PgPool, key: &str) -> Result<Value, AdminError> {
    let mut profiles = profile_array(pool, key).await?;
    for profile in &mut profiles {
        normalize_profile_for_key(profile, key);
    }
    Ok(json!({ "items": redact_profile_secrets(Value::Array(profiles)) }))
}

async fn create_profile(pool: &PgPool, key: &str, payload: Value) -> Result<Value, AdminError> {
    let mut object = payload
        .as_object()
        .cloned()
        .ok_or_else(|| AdminError::BadRequest("profile must be a JSON object".to_owned()))?;
    let profile_id = object
        .get("profile_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let legacy_id = object
        .get("id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if profile_id.is_some() && legacy_id.is_some() && profile_id != legacy_id {
        return Err(AdminError::BadRequest(
            "profile_id and id must identify the same profile".to_owned(),
        ));
    }
    let id = profile_id
        .or(legacy_id)
        .map_or_else(|| Uuid::new_v4().to_string(), str::to_owned);
    let set_active = object
        .remove("set_active")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    object.insert("id".to_owned(), Value::String(id.clone()));
    object.insert("profile_id".to_owned(), Value::String(id.clone()));
    object.remove("active");
    object.remove("is_active");
    if key.ends_with("_postgres") {
        object.insert(
            "source_type".to_owned(),
            Value::String("postgres".to_owned()),
        );
    }
    object.insert(
        "created_at".to_owned(),
        Value::String(Utc::now().to_rfc3339()),
    );
    let mut value = Value::Object(object);
    set_profile_active(&mut value, set_active);
    encrypt_profile_secrets(&mut value, None)?;
    let mut transaction = pool.begin().await?;
    let mut profiles = locked_profile_array(&mut transaction, key).await?;
    if profiles
        .iter()
        .any(|profile| profile_matches_id(profile, &id))
    {
        return Err(AdminError::Conflict("profile already exists".to_owned()));
    }
    if set_active {
        for profile in &mut profiles {
            set_profile_active(profile, false);
        }
    }
    profiles.push(value.clone());
    save_profile_array(&mut transaction, key, &profiles).await?;
    transaction.commit().await?;
    Ok(redact_profile_secrets(value))
}

async fn update_profile(
    pool: &PgPool,
    key: &str,
    id: &str,
    payload: Value,
) -> Result<Value, AdminError> {
    let patch = payload
        .as_object()
        .ok_or_else(|| AdminError::BadRequest("profile must be a JSON object".to_owned()))?;
    let mut transaction = pool.begin().await?;
    let mut profiles = locked_profile_array(&mut transaction, key).await?;
    let profile = profiles
        .iter_mut()
        .find(|profile| profile_matches_id(profile, id))
        .ok_or(AdminError::NotFound("data-management profile"))?;
    normalize_profile_for_key(profile, key);
    let object = profile
        .as_object_mut()
        .ok_or_else(|| AdminError::Probe("stored profile is not an object".to_owned()))?;
    for (field, value) in patch {
        if !matches!(
            field.as_str(),
            "id" | "profile_id"
                | "created_at"
                | "active"
                | "is_active"
                | "set_active"
                | "source_type"
        ) {
            if PROFILE_SECRET_FIELDS.contains(&field.as_str()) && secret_is_omitted(value) {
                continue;
            }
            let mut value = value.clone();
            encrypt_profile_secrets(&mut value, object.get(field))?;
            object.insert(field.clone(), value);
        }
    }
    object.insert(
        "updated_at".to_owned(),
        Value::String(Utc::now().to_rfc3339()),
    );
    let updated = profile.clone();
    save_profile_array(&mut transaction, key, &profiles).await?;
    transaction.commit().await?;
    Ok(redact_profile_secrets(updated))
}

async fn delete_profile(pool: &PgPool, key: &str, id: &str) -> Result<Value, AdminError> {
    let mut transaction = pool.begin().await?;
    let mut profiles = locked_profile_array(&mut transaction, key).await?;
    let original = profiles.len();
    profiles.retain(|profile| !profile_matches_id(profile, id));
    if profiles.len() == original {
        return Err(AdminError::NotFound("data-management profile"));
    }
    save_profile_array(&mut transaction, key, &profiles).await?;
    transaction.commit().await?;
    Ok(json!({ "deleted": true }))
}

async fn activate_profile(pool: &PgPool, key: &str, id: &str) -> Result<Value, AdminError> {
    let mut transaction = pool.begin().await?;
    let mut profiles = locked_profile_array(&mut transaction, key).await?;
    let mut activated = activate_profile_values(&mut profiles, id)
        .ok_or(AdminError::NotFound("data-management profile"))?;
    for profile in &mut profiles {
        normalize_profile_for_key(profile, key);
    }
    normalize_profile_for_key(&mut activated, key);
    save_profile_array(&mut transaction, key, &profiles).await?;
    transaction.commit().await?;
    Ok(redact_profile_secrets(activated))
}

async fn profile_array(pool: &PgPool, key: &str) -> Result<Vec<Value>, AdminError> {
    match setting_json(pool, key).await? {
        None => Ok(Vec::new()),
        Some(Value::Array(profiles)) => Ok(profiles),
        Some(_) => Err(AdminError::Probe(format!(
            "stored profile collection {key} is invalid"
        ))),
    }
}

async fn locked_profile_array(
    transaction: &mut Transaction<'_, Postgres>,
    key: &str,
) -> Result<Vec<Value>, AdminError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(key)
        .execute(&mut **transaction)
        .await?;
    let raw = sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key = $1")
        .bind(key)
        .fetch_optional(&mut **transaction)
        .await?;
    match raw {
        None => Ok(Vec::new()),
        Some(raw) => match serde_json::from_str(&raw)
            .map_err(|error| AdminError::Probe(format!("setting {key} is invalid JSON: {error}")))?
        {
            Value::Array(profiles) => Ok(profiles),
            _ => Err(AdminError::Probe(format!(
                "stored profile collection {key} is invalid"
            ))),
        },
    }
}

async fn save_profile_array(
    transaction: &mut Transaction<'_, Postgres>,
    key: &str,
    profiles: &[Value],
) -> Result<(), AdminError> {
    let raw = serde_json::to_string(profiles).map_err(|error| {
        AdminError::Probe(format!(
            "cannot serialize profile collection {key}: {error}"
        ))
    })?;
    sqlx::query(
        "INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, NOW()) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
    )
    .bind(key)
    .bind(raw)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn profile_identifier(profile: &Value) -> Option<&str> {
    profile
        .get("profile_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            profile
                .get("id")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
}

fn profile_matches_id(profile: &Value, id: &str) -> bool {
    profile_identifier(profile) == Some(id) || profile.get("id").and_then(Value::as_str) == Some(id)
}

fn set_profile_active(profile: &mut Value, active: bool) {
    if let Some(object) = profile.as_object_mut() {
        object.insert("active".to_owned(), Value::Bool(active));
        object.insert("is_active".to_owned(), Value::Bool(active));
    }
}

fn normalize_profile_aliases(profile: &mut Value) {
    let id = profile_identifier(profile).map(str::to_owned);
    let active = profile
        .get("is_active")
        .and_then(Value::as_bool)
        .or_else(|| profile.get("active").and_then(Value::as_bool))
        .unwrap_or(false);
    if let Some(id) = id
        && let Some(object) = profile.as_object_mut()
    {
        object.insert("id".to_owned(), Value::String(id.clone()));
        object.insert("profile_id".to_owned(), Value::String(id));
    }
    set_profile_active(profile, active);
}

fn normalize_profile_for_key(profile: &mut Value, key: &str) {
    normalize_profile_aliases(profile);
    if key.ends_with("_postgres")
        && let Some(object) = profile.as_object_mut()
    {
        object.insert(
            "source_type".to_owned(),
            Value::String("postgres".to_owned()),
        );
    }
}

fn activate_profile_values(profiles: &mut [Value], id: &str) -> Option<Value> {
    let target = profiles
        .iter()
        .position(|profile| profile_matches_id(profile, id))?;
    for (index, profile) in profiles.iter_mut().enumerate() {
        normalize_profile_aliases(profile);
        set_profile_active(profile, index == target);
    }
    profiles.get(target).cloned()
}

fn redact_profile_secrets(mut value: Value) -> Value {
    match &mut value {
        Value::Array(items) => {
            for item in items {
                *item = redact_profile_secrets(item.take());
            }
        }
        Value::Object(object) => {
            for item in object.values_mut() {
                if item.is_array() || item.is_object() {
                    *item = redact_profile_secrets(item.take());
                }
            }
            for field in PROFILE_SECRET_FIELDS {
                if object.get(*field).is_some_and(|item| !item.is_null()) {
                    object.insert((*field).to_owned(), Value::String("********".to_owned()));
                }
            }
        }
        _ => {}
    }
    value
}

fn encrypt_profile_secrets(value: &mut Value, previous: Option<&Value>) -> Result<(), AdminError> {
    match value {
        Value::Array(items) => {
            for (index, item) in items.iter_mut().enumerate() {
                let previous = previous
                    .and_then(Value::as_array)
                    .and_then(|items| items.get(index));
                encrypt_profile_secrets(item, previous)?;
            }
        }
        Value::Object(object) => {
            for (field, item) in object {
                let previous = previous
                    .and_then(Value::as_object)
                    .and_then(|object| object.get(field));
                if PROFILE_SECRET_FIELDS.contains(&field.as_str()) {
                    if secret_is_omitted(item) {
                        if let Some(previous) = previous {
                            *item = previous.clone();
                        }
                        continue;
                    }
                    let raw = item.as_str().ok_or_else(|| {
                        AdminError::BadRequest(format!("{field} must be a string"))
                    })?;
                    *item = Value::String(encrypt_secret(raw)?);
                } else {
                    encrypt_profile_secrets(item, previous)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn decrypt_profile_secrets(value: &mut Value) -> Result<(), AdminError> {
    match value {
        Value::Array(items) => {
            for item in items {
                decrypt_profile_secrets(item)?;
            }
        }
        Value::Object(object) => {
            for (field, item) in object {
                if PROFILE_SECRET_FIELDS.contains(&field.as_str()) {
                    if let Some(raw) = item.as_str() {
                        *item = Value::String(decrypt_secret(raw)?);
                    }
                } else {
                    decrypt_profile_secrets(item)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn secret_is_omitted(value: &Value) -> bool {
    value.is_null()
        || value
            .as_str()
            .is_some_and(|value| value.trim().is_empty() || value == "********")
}

fn encrypt_secret(value: &str) -> Result<String, AdminError> {
    secrets::encrypt_config_secret(value)
        .map_err(|error| AdminError::Probe(format!("cannot encrypt configuration secret: {error}")))
}

fn decrypt_secret(value: &str) -> Result<String, AdminError> {
    secrets::decrypt_config_secret(value)
        .map_err(|error| AdminError::Probe(format!("cannot decrypt configuration secret: {error}")))
}

async fn test_data_s3(pool: &PgPool, payload: Value) -> Result<Value, AdminError> {
    let (mut candidate, profile_id) = if payload.as_object().is_some_and(Map::is_empty) {
        let profiles = profile_array(pool, DATA_S3_PROFILES_KEY).await?;
        let Some(profile) = profiles.into_iter().find(|profile| {
            profile.get("active").and_then(Value::as_bool) == Some(true)
                || profile.get("is_active").and_then(Value::as_bool) == Some(true)
        }) else {
            return Ok(json!({ "ok": false, "message": "no active S3 profile" }));
        };
        let profile_id = profile
            .get("profile_id")
            .or_else(|| profile.get("id"))
            .cloned();
        (profile, profile_id)
    } else {
        (payload, None)
    };
    decrypt_profile_secrets(&mut candidate)?;
    let config = data_management_s3_config(&candidate)?;
    let result = backup_runtime::test_s3_connection(&config).await;
    Ok(match result {
        Ok(()) => json!({
            "ok": true,
            "message": "S3 connection and credentials verified",
            "profile_id": profile_id,
        }),
        Err(error) => json!({
            "ok": false,
            "message": error.to_string(),
            "profile_id": profile_id,
        }),
    })
}

fn data_management_s3_config(value: &Value) -> Result<BackupS3Config, AdminError> {
    let source = value.get("s3").unwrap_or(value);
    let mut config: BackupS3Config = serde_json::from_value(source.clone()).map_err(|error| {
        AdminError::BadRequest(format!("invalid data-management S3 configuration: {error}"))
    })?;
    if !config.endpoint.trim().is_empty() && !config.endpoint.trim().contains("://") {
        let use_ssl = source
            .get("use_ssl")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        config.endpoint = format!(
            "{}://{}",
            if use_ssl { "https" } else { "http" },
            config.endpoint.trim()
        );
    }
    Ok(config)
}

async fn list_data_backup_jobs(pool: &PgPool) -> Result<Value, AdminError> {
    let records = load_backup_records(pool).await?;
    let jobs = profile_array(pool, DATA_BACKUP_JOBS_KEY)
        .await?
        .into_iter()
        .map(|job| refresh_data_backup_job(job, &records))
        .collect::<Vec<_>>();
    Ok(json!({ "items": jobs }))
}

async fn get_data_backup_job(pool: &PgPool, id: &str) -> Result<Value, AdminError> {
    let records = load_backup_records(pool).await?;
    if let Some(job) = profile_array(pool, DATA_BACKUP_JOBS_KEY)
        .await?
        .into_iter()
        .find(|job| data_backup_job_identifier(job) == Some(id))
    {
        return Ok(refresh_data_backup_job(job, &records));
    }
    records
        .iter()
        .find(|record| record.id == id && record.triggered_by == "data-management")
        .map(data_backup_job_from_record)
        .ok_or(AdminError::NotFound("data-management backup job"))
}

async fn create_data_backup_job(pool: &PgPool, payload: Value) -> Result<Value, AdminError> {
    if let Some(backup_type) = payload.get("backup_type").and_then(Value::as_str)
        && backup_type != "postgres"
    {
        return Err(AdminError::BadRequest(
            "only PostgreSQL backups are supported in this runtime".to_owned(),
        ));
    }
    let backup = start_backup(pool, &payload, "data-management").await?;
    let record: BackupRecord = serde_json::from_value(backup).map_err(|error| {
        AdminError::Probe(format!(
            "cannot decode newly created backup record: {error}"
        ))
    })?;
    let job = data_backup_job_from_record(&record);
    let mut transaction = pool.begin().await?;
    let mut jobs = locked_profile_array(&mut transaction, DATA_BACKUP_JOBS_KEY).await?;
    jobs.push(job.clone());
    save_profile_array(&mut transaction, DATA_BACKUP_JOBS_KEY, &jobs).await?;
    transaction.commit().await?;
    Ok(job)
}

fn data_backup_job_identifier(job: &Value) -> Option<&str> {
    ["job_id", "backup_id", "id"]
        .into_iter()
        .find_map(|field| job.get(field).and_then(Value::as_str))
}

fn refresh_data_backup_job(job: Value, records: &[BackupRecord]) -> Value {
    let Some(id) = data_backup_job_identifier(&job) else {
        return job;
    };
    records
        .iter()
        .find(|record| record.id == id)
        .map_or(job, data_backup_job_from_record)
}

fn data_backup_job_from_record(record: &BackupRecord) -> Value {
    let mut job = json!({
        "id": record.id,
        "job_id": record.id,
        "backup_id": record.id,
        "backup_type": record.backup_type,
        "status": record.status,
        "triggered_by": record.triggered_by,
        "created_at": record.started_at,
        "started_at": record.started_at,
        "mode": "embedded_postgresql",
    });
    if !record.finished_at.is_empty() {
        job["finished_at"] = Value::String(record.finished_at.clone());
    }
    if !record.error_message.is_empty() {
        job["error_message"] = Value::String(record.error_message.clone());
    }
    job
}

async fn check_updates() -> Result<Value, AdminError> {
    let release = github_client()
        .get(format!("{GITHUB_RELEASES_URL}/latest"))
        .send()
        .await
        .map_err(|error| AdminError::Probe(format!("GitHub release check failed: {error}")))?
        .error_for_status()
        .map_err(|error| AdminError::Probe(format!("GitHub release check failed: {error}")))?
        .json::<GitHubRelease>()
        .await
        .map_err(|error| AdminError::Probe(format!("invalid GitHub release response: {error}")))?;
    let current = env!("CARGO_PKG_VERSION");
    let latest = release.tag_name.trim_start_matches('v');
    Ok(json!({
        "current_version": current,
        "latest_version": latest,
        "has_update": compare_versions(current, latest).is_lt(),
        "cached": false,
        "build_type": "container",
        "release_info": {
            "name": release.name,
            "body": release.body,
            "published_at": release.published_at,
            "html_url": release.html_url,
            "assets": release.assets,
        }
    }))
}

async fn rollback_versions() -> Result<Value, AdminError> {
    let releases = github_client()
        .get(format!("{GITHUB_RELEASES_URL}?per_page=15"))
        .send()
        .await
        .map_err(|error| AdminError::Probe(format!("GitHub release check failed: {error}")))?
        .error_for_status()
        .map_err(|error| AdminError::Probe(format!("GitHub release check failed: {error}")))?
        .json::<Vec<GitHubRelease>>()
        .await
        .map_err(|error| AdminError::Probe(format!("invalid GitHub release response: {error}")))?;
    let current = env!("CARGO_PKG_VERSION");
    let mut seen = HashSet::new();
    let mut versions = releases
        .into_iter()
        .filter(|release| !release.draft && !release.prerelease)
        .filter_map(|release| {
            let version = release.tag_name.trim_start_matches('v').to_owned();
            (seen.insert(version.clone()) && compare_versions(&version, current).is_lt()).then(
                || {
                    json!({
                        "version": version,
                        "published_at": release.published_at,
                        "html_url": release.html_url,
                    })
                },
            )
        })
        .collect::<Vec<_>>();
    versions.sort_by(|left, right| {
        let left = left
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let right = right
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or_default();
        compare_versions(right, left)
    });
    versions.truncate(3);
    Ok(json!({ "versions": versions }))
}

fn github_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent(format!("sub2api-rust/{}", env!("CARGO_PKG_VERSION")))
        .redirect(Policy::limited(3))
        .build()
        .expect("fixed GitHub HTTP client configuration is valid")
}

fn compare_versions(left: &str, right: &str) -> std::cmp::Ordering {
    let parse = |value: &str| {
        value
            .trim_start_matches('v')
            .split(['.', '-', '+'])
            .map(|part| part.parse::<u64>().unwrap_or(0))
            .collect::<Vec<_>>()
    };
    let left = parse(left);
    let right = parse(right);
    for index in 0..left.len().max(right.len()) {
        let ordering = left
            .get(index)
            .copied()
            .unwrap_or(0)
            .cmp(&right.get(index).copied().unwrap_or(0));
        if !ordering.is_eq() {
            return ordering;
        }
    }
    std::cmp::Ordering::Equal
}

#[allow(
    clippy::too_many_lines,
    reason = "the deployment compatibility flow validates each operation in one transaction-shaped request"
)]
async fn deployment_request(
    pool: &PgPool,
    operation: &str,
    payload: Value,
) -> Result<Value, AdminError> {
    let (status, target_version, redeploy_command, message) = match operation {
        "restart" => (
            "pending_restart",
            None,
            None,
            "graceful service restart initiated",
        ),
        "update" => {
            let update = check_updates().await?;
            let current = update
                .get("current_version")
                .and_then(Value::as_str)
                .unwrap_or(env!("CARGO_PKG_VERSION"));
            let latest = update
                .get("latest_version")
                .and_then(Value::as_str)
                .and_then(normalize_release_version)
                .ok_or_else(|| {
                    AdminError::Probe("the latest release has an invalid version tag".to_owned())
                })?;
            if !update
                .get("has_update")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                return Ok(json!({
                    "accepted": false,
                    "already_up_to_date": true,
                    "current_version": current,
                    "latest_version": latest,
                    "need_restart": false,
                    "requires_redeploy": false,
                    "message": "already up to date",
                }));
            }
            let target = latest.to_owned();
            (
                "pending_redeploy",
                Some(target.clone()),
                Some(redeploy_command("update", &target)),
                "update deployment request recorded",
            )
        }
        "rollback" => {
            let target = payload
                .get("version")
                .and_then(Value::as_str)
                .and_then(normalize_release_version)
                .ok_or_else(|| {
                    AdminError::BadRequest(
                        "version is required because immutable containers have no local backup binary"
                            .to_owned(),
                    )
                })?
                .to_owned();
            let allowed = rollback_versions().await?;
            let is_allowed = allowed
                .get("versions")
                .and_then(Value::as_array)
                .is_some_and(|versions| {
                    versions.iter().any(|version| {
                        version.get("version").and_then(Value::as_str) == Some(target.as_str())
                    })
                });
            if !is_allowed {
                return Err(AdminError::BadRequest(
                    "version is not in the allowed rollback list".to_owned(),
                ));
            }
            (
                "pending_redeploy",
                Some(target.clone()),
                Some(redeploy_command("rollback", &target)),
                "rollback deployment request recorded",
            )
        }
        _ => {
            return Err(AdminError::BadRequest(
                "unsupported system deployment operation".to_owned(),
            ));
        }
    };
    let operation_id = format!("sysop-{}", Uuid::new_v4().simple());
    let request = json!({
        "operation_id": operation_id,
        "operation": operation,
        "payload": payload,
        "target_version": target_version,
        "status": status,
        "requested_at": Utc::now().to_rfc3339(),
    });
    persist_deployment_request(pool, &request).await?;
    Ok(json!({
        "operation_id": operation_id,
        "accepted": true,
        "need_restart": false,
        "requires_redeploy": operation != "restart",
        "target_version": target_version,
        "redeploy_command": redeploy_command,
        "message": message,
    }))
}

fn normalize_release_version(value: &str) -> Option<&str> {
    let value = value.trim();
    let value = value.strip_prefix('v').unwrap_or(value);
    let mut parts = value.split('.');
    let valid = value.len() <= 64
        && (2..=4).contains(&value.matches('.').count().saturating_add(1))
        && parts.all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()));
    valid.then_some(value)
}

fn redeploy_command(operation: &str, target_version: &str) -> String {
    if let Ok(template) = env::var("SUB2API_REDEPLOY_COMMAND")
        && !template.trim().is_empty()
    {
        return template
            .replace("{operation}", operation)
            .replace("{version}", target_version);
    }
    if operation == "rollback" {
        return format!(
            "git -C .source fetch --tags origin && git -C .source checkout --detach v{target_version} && docker compose up -d --build --remove-orphans"
        );
    }
    "git -C .source fetch origin main && git -C .source checkout -B main origin/main && docker compose up -d --build --remove-orphans"
        .to_owned()
}

async fn persist_deployment_request(pool: &PgPool, request: &Value) -> Result<(), AdminError> {
    let raw = serde_json::to_string(request).map_err(|error| {
        AdminError::Probe(format!("cannot serialize deployment request: {error}"))
    })?;
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(SYSTEM_DEPLOYMENT_LOCK_KEY)
        .execute(&mut *transaction)
        .await?;
    put_setting_raw(&mut transaction, SYSTEM_DEPLOYMENT_REQUEST_KEY, &raw).await?;

    let history_raw = sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key = $1")
        .bind(SYSTEM_DEPLOYMENT_HISTORY_KEY)
        .fetch_optional(&mut *transaction)
        .await?;
    let mut history = history_raw.map_or_else(
        || Ok(Vec::new()),
        |raw| {
            serde_json::from_str::<Vec<Value>>(&raw).map_err(|error| {
                AdminError::Probe(format!(
                    "system deployment history is invalid JSON: {error}"
                ))
            })
        },
    )?;
    if history.len() >= MAX_SYSTEM_DEPLOYMENT_HISTORY {
        let remove = history.len() + 1 - MAX_SYSTEM_DEPLOYMENT_HISTORY;
        history.drain(..remove);
    }
    history.push(request.clone());
    let history_raw = serde_json::to_string(&history).map_err(|error| {
        AdminError::Probe(format!("cannot serialize deployment history: {error}"))
    })?;
    put_setting_raw(
        &mut transaction,
        SYSTEM_DEPLOYMENT_HISTORY_KEY,
        &history_raw,
    )
    .await?;
    transaction.commit().await?;
    Ok(())
}

async fn put_setting_raw(
    transaction: &mut Transaction<'_, Postgres>,
    key: &str,
    value: &str,
) -> Result<(), AdminError> {
    sqlx::query(
        "INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, NOW()) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
    )
    .bind(key)
    .bind(value)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn proxy_test(pool: &PgPool, id: i64, quality: bool) -> Result<Value, AdminError> {
    let row = sqlx::query(
        "SELECT protocol, host, port, username, password FROM proxies WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(AdminError::NotFound("proxy"))?;
    let proxy_url = proxy_url_from_row(&row)?;
    let proxy = Proxy::all(&proxy_url)
        .map_err(|error| AdminError::BadRequest(format!("invalid proxy configuration: {error}")))?;
    let client = Client::builder()
        .proxy(proxy)
        .redirect(Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|error| AdminError::Probe(format!("cannot create proxy client: {error}")))?;
    if !quality {
        let started = Instant::now();
        let response = client
            .get("https://api.ipify.org?format=json")
            .send()
            .await
            .map_err(|error| AdminError::Probe(format!("proxy connection failed: {error}")))?;
        let status = response.status();
        let body = response.json::<Value>().await.unwrap_or(Value::Null);
        return Ok(json!({
            "success": status.is_success(),
            "status_code": status.as_u16(),
            "latency_ms": i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX),
            "ip": body.get("ip"),
        }));
    }
    let targets = [
        ("openai", "https://api.openai.com/v1/models"),
        ("anthropic", "https://api.anthropic.com/v1/models"),
        (
            "google",
            "https://generativelanguage.googleapis.com/v1beta/models",
        ),
    ];
    let mut results = Vec::with_capacity(targets.len());
    for (name, target) in targets {
        let started = Instant::now();
        let result = client.get(target).send().await;
        results.push(match result {
            Ok(response) => json!({
                "target": name,
                "reachable": true,
                "status_code": response.status().as_u16(),
                "latency_ms": i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX),
            }),
            Err(error) => json!({
                "target": name,
                "reachable": false,
                "error": error.to_string(),
            }),
        });
    }
    let reachable = results
        .iter()
        .filter(|result| result.get("reachable").and_then(Value::as_bool) == Some(true))
        .count();
    Ok(json!({
        "success": reachable == results.len(),
        "reachable_targets": reachable,
        "total_targets": results.len(),
        "results": results,
    }))
}

fn proxy_url_from_row(row: &sqlx::postgres::PgRow) -> Result<String, AdminError> {
    let protocol: String = row.try_get("protocol")?;
    let host: String = row.try_get("host")?;
    let port: i32 = row.try_get("port")?;
    let username: Option<String> = row.try_get("username")?;
    let password: Option<String> = row.try_get("password")?;
    let mut url = Url::parse(&format!("{protocol}://{host}:{port}"))
        .map_err(|_| AdminError::BadRequest("proxy URL is invalid".to_owned()))?;
    if let Some(username) = username.filter(|value| !value.is_empty()) {
        url.set_username(&username)
            .map_err(|()| AdminError::BadRequest("proxy username is invalid".to_owned()))?;
        if let Some(password) = password {
            url.set_password(Some(&password))
                .map_err(|()| AdminError::BadRequest("proxy password is invalid".to_owned()))?;
        }
    }
    Ok(url.into())
}

const REFUND_ORDER_SELECT: &str = r"
SELECT o.id, o.user_id, o.amount::text AS amount, o.pay_amount::text AS pay_amount,
       o.status, o.order_type, o.out_trade_no, o.payment_trade_no,
       COALESCE(o.provider_instance_id, '') AS provider_instance_id,
       COALESCE(o.provider_key, '') AS provider_key,
       COALESCE(o.provider_snapshot, '{}'::jsonb) AS provider_snapshot,
       o.refund_amount::text AS refund_amount, o.refund_reason,
       o.refund_request_reason,
       o.subscription_group_id, o.subscription_days,
       COALESCE(p.refund_enabled, FALSE) AS refund_enabled
FROM payment_orders o
LEFT JOIN payment_provider_instances p ON p.id::text = o.provider_instance_id
WHERE o.id = $1
";

#[derive(Clone, Debug)]
struct RefundOrder {
    id: i64,
    user_id: i64,
    amount: f64,
    pay_amount: f64,
    status: String,
    order_type: String,
    out_trade_no: String,
    payment_trade_no: String,
    provider_instance_id: String,
    provider_key: String,
    provider_snapshot: Value,
    refund_amount: f64,
    refund_reason: Option<String>,
    refund_request_reason: Option<String>,
    subscription_group_id: Option<i64>,
    subscription_days: Option<i32>,
    refund_enabled: bool,
}

struct PreparedRefund {
    order: RefundOrder,
    request: ProviderRefundRequest,
    refund_amount: f64,
    reason: String,
    force: bool,
    deduct_balance: bool,
}

#[derive(Default)]
struct FinalizedRefund {
    balance_deducted: f64,
    subscription_days_deducted: i32,
}

async fn process_provider_refund(
    pool: &PgPool,
    actor: &AdminIdentity,
    id: i64,
    payload: Value,
) -> Result<Value, AdminError> {
    let Some(prepared) = prepare_refund(pool, id, &payload).await? else {
        return Ok(refund_success_response(&FinalizedRefund::default(), false));
    };
    let operator = refund_operator(actor);
    if prepared.force {
        return match finalize_refund(pool, &prepared, &operator).await {
            Ok(finalized) => Ok(refund_success_response(&finalized, false)),
            Err(error) => {
                mark_refund_failed(pool, id, &operator, &error.to_string()).await?;
                Err(error)
            }
        };
    }

    let runtime = ProviderRuntime::new(pool.clone());
    let provider_id = refund_provider_instance_id(&prepared.order)?;
    let provider = match RefundProvider::load(&runtime, provider_id).await {
        Ok(provider) => provider,
        Err(error) => {
            return refund_provider_failure(pool, &prepared, &operator, error.to_string()).await;
        }
    };
    if let Err(error) = provider.validate_order_binding(
        &prepared.order.provider_instance_id,
        &prepared.order.provider_key,
        &prepared.order.provider_snapshot,
    ) {
        return refund_provider_failure(pool, &prepared, &operator, error.to_string()).await;
    }
    let result = match provider.refund(&runtime, &prepared.request).await {
        Ok(result) => result,
        Err(error) => {
            return refund_provider_failure(pool, &prepared, &operator, error.to_string()).await;
        }
    };
    match result.status {
        ProviderRefundStatus::Succeeded => {
            match finalize_refund(pool, &prepared, &operator).await {
                Ok(finalized) => Ok(refund_success_response(&finalized, false)),
                Err(error) => {
                    mark_refund_pending(
                        pool,
                        &prepared,
                        &operator,
                        &result,
                        provider.provider_key(),
                        provider.supports_query(),
                    )
                    .await?;
                    Ok(json!({
                        "success": false,
                        "warning": format!("provider confirmed the refund, but local finalization is pending: {error}"),
                        "provider_query_performed": false,
                    }))
                }
            }
        }
        ProviderRefundStatus::Pending => {
            mark_refund_pending(
                pool,
                &prepared,
                &operator,
                &result,
                provider.provider_key(),
                provider.supports_query(),
            )
            .await?;
            Ok(json!({
                "success": false,
                "warning": "gateway refund is pending confirmation",
                "provider_query_performed": false,
            }))
        }
        ProviderRefundStatus::Failed => {
            refund_provider_failure(
                pool,
                &prepared,
                &operator,
                "payment provider reported that the refund failed".to_owned(),
            )
            .await
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn query_and_finalize_refund(
    pool: &PgPool,
    actor: &AdminIdentity,
    id: i64,
) -> Result<Value, AdminError> {
    let order = load_refund_order(pool, id).await?;
    if matches!(order.status.as_str(), "REFUNDED" | "PARTIALLY_REFUNDED") {
        return Ok(refund_success_response(&FinalizedRefund::default(), false));
    }
    if order.status != "REFUND_PENDING" {
        return Err(AdminError::Conflict(
            "only pending refunds can be queried and finalized".to_owned(),
        ));
    }
    let detail = latest_refund_pending_detail(pool, id).await?;
    let refund_amount = if order.refund_amount > 0.0 {
        order.refund_amount
    } else {
        order.amount
    };
    let reason = order
        .refund_reason
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("refund order:{id}"));
    let request = provider_refund_request(
        &order,
        refund_amount,
        detail
            .get("refundID")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        &reason,
    );
    let prepared = PreparedRefund {
        order,
        request,
        refund_amount,
        reason,
        force: false,
        deduct_balance: detail
            .get("deductBalance")
            .and_then(Value::as_bool)
            .unwrap_or(true),
    };
    let runtime = ProviderRuntime::new(pool.clone());
    let provider_id = refund_provider_instance_id(&prepared.order)?;
    let provider = RefundProvider::load(&runtime, provider_id)
        .await
        .map_err(|error| AdminError::Unavailable(error.to_string()))?;
    provider
        .validate_order_binding(
            &prepared.order.provider_instance_id,
            &prepared.order.provider_key,
            &prepared.order.provider_snapshot,
        )
        .map_err(|error| AdminError::Conflict(error.to_string()))?;
    if !provider.supports_query() {
        return Err(AdminError::BadRequest(format!(
            "{} does not support refund status queries; verify the refund externally",
            provider.provider_key()
        )));
    }
    let operator = refund_operator(actor);
    let result = match provider.query_refund(&runtime, &prepared.request).await {
        Ok(result) => result,
        Err(error) => {
            write_refund_audit(
                pool,
                id,
                "REFUND_QUERY_FAILED",
                &operator,
                json!({"detail": error.to_string()}),
            )
            .await?;
            return Ok(json!({
                "success": false,
                "warning": format!("gateway refund remains pending; query failed: {error}"),
                "provider_query_performed": true,
            }));
        }
    };
    match result.status {
        ProviderRefundStatus::Succeeded => {
            match finalize_refund(pool, &prepared, &operator).await {
                Ok(finalized) => Ok(refund_success_response(&finalized, true)),
                Err(error) => {
                    mark_refund_pending(
                        pool,
                        &prepared,
                        &operator,
                        &result,
                        provider.provider_key(),
                        true,
                    )
                    .await?;
                    Ok(json!({
                        "success": false,
                        "warning": format!("provider confirmed the refund, but local finalization remains pending: {error}"),
                        "provider_query_performed": true,
                    }))
                }
            }
        }
        ProviderRefundStatus::Pending => {
            mark_refund_pending(
                pool,
                &prepared,
                &operator,
                &result,
                provider.provider_key(),
                true,
            )
            .await?;
            Ok(json!({
                "success": false,
                "warning": "gateway refund is still pending confirmation",
                "provider_query_performed": true,
            }))
        }
        ProviderRefundStatus::Failed => {
            mark_refund_failed(
                pool,
                id,
                &operator,
                "payment provider reported that the refund failed",
            )
            .await?;
            Ok(json!({
                "success": false,
                "warning": "gateway refund failed: payment provider reported failure",
                "provider_query_performed": true,
            }))
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn prepare_refund(
    pool: &PgPool,
    id: i64,
    payload: &Value,
) -> Result<Option<PreparedRefund>, AdminError> {
    let requested_amount = payload.get("amount").and_then(Value::as_f64).unwrap_or(0.0);
    if !requested_amount.is_finite() {
        return Err(AdminError::BadRequest(
            "refund amount must be finite".to_owned(),
        ));
    }
    let force = payload
        .get("force")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let deduct_balance = payload
        .get("deduct_balance")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut transaction = pool.begin().await?;
    let order = load_refund_order_for_update(&mut transaction, id).await?;
    if matches!(order.status.as_str(), "REFUNDED" | "PARTIALLY_REFUNDED") {
        transaction.commit().await?;
        return Ok(None);
    }
    if order.status == "REFUND_PENDING" {
        return Err(AdminError::Conflict(
            "refund is pending provider confirmation; query it instead of submitting again"
                .to_owned(),
        ));
    }
    if !matches!(
        order.status.as_str(),
        "COMPLETED" | "REFUND_REQUESTED" | "REFUND_FAILED"
    ) {
        return Err(AdminError::Conflict(format!(
            "order status {} does not allow a refund",
            order.status
        )));
    }
    let refund_amount = if requested_amount <= 0.0 {
        order.amount
    } else {
        requested_amount
    };
    let currency = refund_currency(&order);
    if refund_amount <= 0.0 || refund_amount - order.amount > refund_amount_tolerance(&currency) {
        return Err(AdminError::BadRequest(
            "refund amount is invalid or exceeds the credited order amount".to_owned(),
        ));
    }
    if !force {
        let _ = refund_provider_instance_id(&order)?;
        if !order.refund_enabled {
            return Err(AdminError::Forbidden(
                "refund is not enabled for the provider that created this order".to_owned(),
            ));
        }
    }
    if deduct_balance && order.order_type == "subscription" {
        validate_subscription_deduction(&mut transaction, &order).await?;
    }
    let reason = payload
        .get("reason")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            order
                .refund_request_reason
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| format!("refund order:{id}"));
    let affected = sqlx::query(
        r"
UPDATE payment_orders
SET status = 'REFUNDING', refund_amount = $2::numeric, refund_reason = $3,
    refund_at = NULL, force_refund = $4, failed_at = NULL, failed_reason = NULL,
    updated_at = NOW()
WHERE id = $1 AND status IN ('COMPLETED', 'REFUND_REQUESTED', 'REFUND_FAILED')
",
    )
    .bind(id)
    .bind(refund_amount.to_string())
    .bind(&reason)
    .bind(force)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if affected != 1 {
        return Err(AdminError::Conflict(
            "payment order changed while starting the refund".to_owned(),
        ));
    }
    transaction.commit().await?;
    let request = provider_refund_request(&order, refund_amount, "", &reason);
    Ok(Some(PreparedRefund {
        order,
        request,
        refund_amount,
        reason,
        force,
        deduct_balance,
    }))
}

async fn finalize_refund(
    pool: &PgPool,
    prepared: &PreparedRefund,
    operator: &str,
) -> Result<FinalizedRefund, AdminError> {
    let mut transaction = pool.begin().await?;
    let order = load_refund_order_for_update(&mut transaction, prepared.order.id).await?;
    let already_finalized = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM payment_audit_logs WHERE order_id = $1 AND action = 'REFUND_SUCCESS')",
    )
    .bind(order.id.to_string())
    .fetch_one(&mut *transaction)
    .await?;
    if already_finalized || matches!(order.status.as_str(), "REFUNDED" | "PARTIALLY_REFUNDED") {
        transaction.commit().await?;
        return Ok(FinalizedRefund::default());
    }
    if !matches!(order.status.as_str(), "REFUNDING" | "REFUND_PENDING") {
        return Err(AdminError::Conflict(format!(
            "order status {} cannot be finalized as refunded",
            order.status
        )));
    }
    let mut finalized = FinalizedRefund::default();
    if prepared.deduct_balance && order.order_type == "balance" {
        let balance = sqlx::query_scalar::<_, String>(
            "SELECT balance::text FROM users WHERE id = $1 FOR UPDATE",
        )
        .bind(order.user_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(AdminError::NotFound("payment order user"))?
        .parse::<f64>()
        .map_err(|error| AdminError::Probe(format!("invalid user balance: {error}")))?;
        finalized.balance_deducted = balance.max(0.0).min(prepared.refund_amount);
        if finalized.balance_deducted > 0.0 {
            sqlx::query(
                "UPDATE users SET balance = balance - $2::numeric, updated_at = NOW() WHERE id = $1",
            )
            .bind(order.user_id)
            .bind(finalized.balance_deducted.to_string())
            .execute(&mut *transaction)
            .await?;
        }
    } else if prepared.deduct_balance && order.order_type == "subscription" {
        finalized.subscription_days_deducted =
            deduct_subscription(&mut transaction, &order).await?;
    }
    let final_status = if prepared.refund_amount + refund_amount_tolerance(&refund_currency(&order))
        < order.amount
    {
        "PARTIALLY_REFUNDED"
    } else {
        "REFUNDED"
    };
    sqlx::query(
        r"
UPDATE payment_orders
SET status = $2, refund_amount = $3::numeric, refund_reason = $4,
    refund_at = NOW(), force_refund = $5, failed_at = NULL, failed_reason = NULL,
    updated_at = NOW()
WHERE id = $1
",
    )
    .bind(order.id)
    .bind(final_status)
    .bind(prepared.refund_amount.to_string())
    .bind(&prepared.reason)
    .bind(prepared.force)
    .execute(&mut *transaction)
    .await?;
    insert_refund_audit_tx(
        &mut transaction,
        order.id,
        "REFUND_SUCCESS",
        operator,
        json!({
            "refundAmount": prepared.refund_amount,
            "gatewayAmount": prepared.request.amount,
            "reason": prepared.reason,
            "balanceDeducted": finalized.balance_deducted,
            "subscriptionDaysDeducted": finalized.subscription_days_deducted,
            "force": prepared.force,
            "providerSkipped": prepared.force,
        }),
    )
    .await?;
    transaction.commit().await?;
    Ok(finalized)
}

async fn mark_refund_pending(
    pool: &PgPool,
    prepared: &PreparedRefund,
    operator: &str,
    result: &ProviderRefundResult,
    provider_key: &str,
    query_supported: bool,
) -> Result<(), AdminError> {
    let mut transaction = pool.begin().await?;
    sqlx::query(
        r"
UPDATE payment_orders
SET status = 'REFUND_PENDING', refund_amount = $2::numeric, refund_reason = $3,
    refund_at = NULL, force_refund = FALSE, failed_at = NULL, failed_reason = NULL,
    updated_at = NOW()
WHERE id = $1 AND status IN ('REFUNDING', 'REFUND_PENDING')
",
    )
    .bind(prepared.order.id)
    .bind(prepared.refund_amount.to_string())
    .bind(&prepared.reason)
    .execute(&mut *transaction)
    .await?;
    upsert_refund_audit_tx(
        &mut transaction,
        prepared.order.id,
        "REFUND_PENDING",
        operator,
        json!({
            "refundID": result.refund_id,
            "refundAmount": prepared.refund_amount,
            "gatewayAmount": prepared.request.amount,
            "reason": prepared.reason,
            "deductBalance": prepared.deduct_balance,
            "providerKey": provider_key,
            "providerQuerySupported": query_supported,
        }),
    )
    .await?;
    transaction.commit().await?;
    Ok(())
}

async fn refund_provider_failure(
    pool: &PgPool,
    prepared: &PreparedRefund,
    operator: &str,
    detail: String,
) -> Result<Value, AdminError> {
    mark_refund_failed(pool, prepared.order.id, operator, &detail).await?;
    Ok(json!({
        "success": false,
        "warning": format!("gateway refund failed: {detail}"),
        "provider_query_performed": false,
    }))
}

async fn mark_refund_failed(
    pool: &PgPool,
    order_id: i64,
    operator: &str,
    detail: &str,
) -> Result<(), AdminError> {
    let mut transaction = pool.begin().await?;
    sqlx::query(
        r"
UPDATE payment_orders
SET status = 'REFUND_FAILED', failed_at = NOW(), failed_reason = $2, updated_at = NOW()
WHERE id = $1 AND status IN ('REFUNDING', 'REFUND_PENDING', 'REFUND_FAILED')
",
    )
    .bind(order_id)
    .bind(detail)
    .execute(&mut *transaction)
    .await?;
    upsert_refund_audit_tx(
        &mut transaction,
        order_id,
        "REFUND_FAILED",
        operator,
        json!({"detail": detail}),
    )
    .await?;
    transaction.commit().await?;
    Ok(())
}

async fn load_refund_order(pool: &PgPool, id: i64) -> Result<RefundOrder, AdminError> {
    let row = sqlx::query(REFUND_ORDER_SELECT)
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(AdminError::NotFound("payment order"))?;
    refund_order_from_row(&row)
}

async fn load_refund_order_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    id: i64,
) -> Result<RefundOrder, AdminError> {
    let select_for_update = format!("{REFUND_ORDER_SELECT} FOR UPDATE OF o");
    let row = sqlx::query(&select_for_update)
        .bind(id)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(AdminError::NotFound("payment order"))?;
    refund_order_from_row(&row)
}

fn refund_order_from_row(row: &sqlx::postgres::PgRow) -> Result<RefundOrder, AdminError> {
    Ok(RefundOrder {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        amount: parse_refund_decimal(&row.try_get::<String, _>("amount")?, "order amount")?,
        pay_amount: parse_refund_decimal(
            &row.try_get::<String, _>("pay_amount")?,
            "provider amount",
        )?,
        status: row.try_get("status")?,
        order_type: row.try_get("order_type")?,
        out_trade_no: row.try_get("out_trade_no")?,
        payment_trade_no: row.try_get("payment_trade_no")?,
        provider_instance_id: row.try_get("provider_instance_id")?,
        provider_key: row.try_get("provider_key")?,
        provider_snapshot: row.try_get("provider_snapshot")?,
        refund_amount: parse_refund_decimal(
            &row.try_get::<String, _>("refund_amount")?,
            "refund amount",
        )?,
        refund_reason: row.try_get("refund_reason")?,
        refund_request_reason: row.try_get("refund_request_reason")?,
        subscription_group_id: row.try_get("subscription_group_id")?,
        subscription_days: row.try_get("subscription_days")?,
        refund_enabled: row.try_get("refund_enabled")?,
    })
}

fn provider_refund_request(
    order: &RefundOrder,
    refund_amount: f64,
    refund_id: &str,
    reason: &str,
) -> ProviderRefundRequest {
    let currency = refund_currency(order);
    ProviderRefundRequest {
        trade_no: order.payment_trade_no.clone(),
        order_id: order.out_trade_no.clone(),
        refund_id: refund_id.trim().to_owned(),
        amount: calculate_gateway_refund_amount(
            order.amount,
            order.pay_amount,
            refund_amount,
            &currency,
        ),
        total_amount: order.pay_amount,
        currency,
        reason: reason.to_owned(),
    }
}

fn refund_provider_instance_id(order: &RefundOrder) -> Result<i64, AdminError> {
    order.provider_instance_id.trim().parse().map_err(|_| {
        AdminError::Forbidden(
            "refund requires the exact provider instance that created the order".to_owned(),
        )
    })
}

fn refund_currency(order: &RefundOrder) -> String {
    order
        .provider_snapshot
        .get("currency")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_alphabetic()))
        .unwrap_or("CNY")
        .to_ascii_uppercase()
}

fn calculate_gateway_refund_amount(
    order_amount: f64,
    pay_amount: f64,
    refund_amount: f64,
    currency: &str,
) -> f64 {
    if order_amount <= 0.0 || pay_amount <= 0.0 || refund_amount <= 0.0 {
        return 0.0;
    }
    let raw = if (refund_amount - order_amount).abs() <= refund_amount_tolerance(currency) {
        pay_amount
    } else {
        pay_amount * refund_amount / order_amount
    };
    let multiplier = 10_f64.powi(i32::try_from(refund_currency_digits(currency)).unwrap_or(2));
    (raw * multiplier).round() / multiplier
}

fn refund_amount_tolerance(currency: &str) -> f64 {
    let digits = refund_currency_digits(currency);
    if digits <= 2 {
        0.01
    } else {
        10_f64.powi(-i32::try_from(digits).unwrap_or(2)) / 2.0
    }
}

fn refund_currency_digits(currency: &str) -> usize {
    match currency.to_ascii_uppercase().as_str() {
        "BIF" | "CLP" | "DJF" | "GNF" | "ISK" | "JPY" | "KMF" | "KRW" | "MGA" | "PYG" | "RWF"
        | "UGX" | "VND" | "VUV" | "XAF" | "XOF" | "XPF" => 0,
        "BHD" | "IQD" | "JOD" | "KWD" | "LYD" | "OMR" | "TND" => 3,
        _ => 2,
    }
}

async fn validate_subscription_deduction(
    transaction: &mut Transaction<'_, Postgres>,
    order: &RefundOrder,
) -> Result<(), AdminError> {
    let (Some(group_id), Some(days)) = (order.subscription_group_id, order.subscription_days)
    else {
        return Ok(());
    };
    if days <= 0 {
        return Ok(());
    }
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM user_subscriptions WHERE user_id = $1 AND group_id = $2)",
    )
    .bind(order.user_id)
    .bind(group_id)
    .fetch_one(&mut **transaction)
    .await?;
    if !exists {
        return Err(AdminError::Conflict(
            "cannot deduct the subscription granted by this order; disable deduct_balance"
                .to_owned(),
        ));
    }
    Ok(())
}

async fn deduct_subscription(
    transaction: &mut Transaction<'_, Postgres>,
    order: &RefundOrder,
) -> Result<i32, AdminError> {
    let (Some(group_id), Some(days)) = (order.subscription_group_id, order.subscription_days)
    else {
        return Ok(0);
    };
    if days <= 0 {
        return Ok(0);
    }
    let subscription_id = sqlx::query_scalar::<_, i64>(
        "SELECT id FROM user_subscriptions WHERE user_id = $1 AND group_id = $2 FOR UPDATE",
    )
    .bind(order.user_id)
    .bind(group_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| {
        AdminError::Conflict(
            "subscription disappeared before the provider refund was finalized".to_owned(),
        )
    })?;
    sqlx::query(
        r"
UPDATE user_subscriptions
SET expires_at = expires_at - make_interval(days => $2),
    status = CASE WHEN expires_at - make_interval(days => $2) <= NOW()
                  THEN 'expired' ELSE status END,
    updated_at = NOW()
WHERE id = $1
",
    )
    .bind(subscription_id)
    .bind(days)
    .execute(&mut **transaction)
    .await?;
    Ok(days)
}

async fn latest_refund_pending_detail(pool: &PgPool, id: i64) -> Result<Value, AdminError> {
    let detail = sqlx::query_scalar::<_, String>(
        "SELECT detail FROM payment_audit_logs WHERE order_id = $1 AND action = 'REFUND_PENDING' LIMIT 1",
    )
    .bind(id.to_string())
    .fetch_optional(pool)
    .await?
    .unwrap_or_else(|| "{}".to_owned());
    serde_json::from_str(&detail)
        .map_err(|error| AdminError::Probe(format!("stored refund audit is invalid: {error}")))
}

async fn write_refund_audit(
    pool: &PgPool,
    order_id: i64,
    action: &str,
    operator: &str,
    detail: Value,
) -> Result<(), AdminError> {
    let mut transaction = pool.begin().await?;
    upsert_refund_audit_tx(&mut transaction, order_id, action, operator, detail).await?;
    transaction.commit().await?;
    Ok(())
}

async fn insert_refund_audit_tx(
    transaction: &mut Transaction<'_, Postgres>,
    order_id: i64,
    action: &str,
    operator: &str,
    detail: Value,
) -> Result<(), AdminError> {
    sqlx::query(
        r"
INSERT INTO payment_audit_logs (order_id, action, detail, operator, created_at)
VALUES ($1, $2, $3, $4, NOW())
ON CONFLICT (order_id, action) DO NOTHING
",
    )
    .bind(order_id.to_string())
    .bind(action)
    .bind(detail.to_string())
    .bind(operator)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn upsert_refund_audit_tx(
    transaction: &mut Transaction<'_, Postgres>,
    order_id: i64,
    action: &str,
    operator: &str,
    detail: Value,
) -> Result<(), AdminError> {
    sqlx::query(
        r"
INSERT INTO payment_audit_logs (order_id, action, detail, operator, created_at)
VALUES ($1, $2, $3, $4, NOW())
ON CONFLICT (order_id, action) DO UPDATE
SET detail = EXCLUDED.detail, operator = EXCLUDED.operator, created_at = NOW()
",
    )
    .bind(order_id.to_string())
    .bind(action)
    .bind(detail.to_string())
    .bind(operator)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn refund_operator(actor: &AdminIdentity) -> String {
    format!("admin:{}", actor.user_id)
}

fn refund_success_response(finalized: &FinalizedRefund, provider_query_performed: bool) -> Value {
    json!({
        "success": true,
        "balance_deducted": finalized.balance_deducted,
        "subscription_days_deducted": finalized.subscription_days_deducted,
        "provider_query_performed": provider_query_performed,
    })
}

fn parse_refund_decimal(raw: &str, label: &str) -> Result<f64, AdminError> {
    raw.parse()
        .map_err(|error| AdminError::Probe(format!("invalid {label}: {error}")))
}

fn path_segment_after<'a>(path: &'a str, marker: &str) -> Option<&'a str> {
    path.split_once(marker)
        .map(|(_, tail)| {
            tail.trim_start_matches('/')
                .split('/')
                .next()
                .unwrap_or_default()
        })
        .filter(|value| !value.is_empty())
}

fn backup_id(path: &str) -> Option<&str> {
    path_segment_after(path, "/backups/")
        .filter(|value| *value != "s3-config" && *value != "schedule")
}

fn profile_id(path: &str) -> Option<&str> {
    path_segment_after(path, "/profiles/")
}

fn job_id(path: &str) -> Option<&str> {
    path_segment_after(path, "/data-management/backups/")
}

fn source_profiles_key(path: &str) -> Result<String, AdminError> {
    let source = path_segment_after(path, "/sources/")
        .ok_or_else(|| AdminError::BadRequest("source type is required".to_owned()))?;
    if source != "postgres" {
        return Err(AdminError::BadRequest(
            "only PostgreSQL source profiles are supported in this runtime".to_owned(),
        ));
    }
    Ok("data_management_source_profiles_postgres".to_owned())
}

fn proxy_id(path: &str) -> Option<i64> {
    path_segment_after(path, "/proxies/")?.parse().ok()
}

fn payment_order_id(path: &str) -> Option<i64> {
    path_segment_after(path, "/orders/")?.parse().ok()
}

pub(super) async fn local_backup_path(
    pool: &PgPool,
    id: &str,
) -> Result<(PathBuf, String), AdminError> {
    let record = load_backup_records(pool)
        .await?
        .into_iter()
        .find(|record| record.id == id)
        .ok_or(AdminError::NotFound("backup"))?;
    if record.status != "completed" {
        return Err(AdminError::Conflict(
            "only completed backups can be downloaded".to_owned(),
        ));
    }
    let path = backup_directory().join(&record.file_name);
    ensure_path_within(&path, &backup_directory())?;
    Ok((path, record.file_name))
}

fn ensure_path_within(path: &Path, root: &Path) -> Result<(), AdminError> {
    if path.parent() != Some(root) {
        return Err(AdminError::Forbidden(
            "backup path escaped the configured directory".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_profiles_are_postgresql_only() {
        assert_eq!(
            source_profiles_key("/api/v1/admin/data-management/sources/postgres/profiles").unwrap(),
            "data_management_source_profiles_postgres"
        );
        assert!(
            source_profiles_key("/api/v1/admin/data-management/sources/redis/profiles").is_err()
        );
    }

    #[test]
    fn profile_aliases_and_activation_are_compatible_and_unique() {
        let mut profiles = vec![
            json!({
                "id": "legacy",
                "active": true,
                "name": "Legacy profile",
            }),
            json!({
                "profile_id": "current",
                "is_active": false,
                "name": "Current profile",
            }),
        ];

        let activated = activate_profile_values(&mut profiles, "current").unwrap();
        assert_eq!(activated["id"], "current");
        assert_eq!(activated["profile_id"], "current");
        assert_eq!(activated["active"], true);
        assert_eq!(activated["is_active"], true);
        assert_eq!(
            profiles
                .iter()
                .filter(|profile| profile["active"] == Value::Bool(true))
                .count(),
            1
        );
        assert_eq!(profiles[0]["id"], "legacy");
        assert_eq!(profiles[0]["profile_id"], "legacy");
        assert_eq!(profiles[0]["active"], false);
        assert_eq!(profiles[0]["is_active"], false);
        assert!(activate_profile_values(&mut profiles, "missing").is_none());
    }

    #[test]
    fn data_management_backup_jobs_follow_runtime_terminal_status() {
        let mut record = BackupRecord {
            id: "backup-1".to_owned(),
            status: "completed".to_owned(),
            backup_type: "postgres".to_owned(),
            file_name: "backup.dump".to_owned(),
            s3_key: "local/backup.dump".to_owned(),
            size_bytes: 42,
            artifact_format: "postgres_custom_v1".to_owned(),
            sha256: "abc".to_owned(),
            triggered_by: "data-management".to_owned(),
            error_message: String::new(),
            started_at: "2026-07-14T00:00:00Z".to_owned(),
            finished_at: "2026-07-14T00:00:01Z".to_owned(),
            expires_at: String::new(),
            progress: String::new(),
            restore_status: String::new(),
            restore_error: String::new(),
            restored_at: String::new(),
        };
        let stale = json!({
            "id": "backup-1",
            "backup_id": "backup-1",
            "status": "running",
        });

        let completed = refresh_data_backup_job(stale.clone(), &[record.clone()]);
        assert_eq!(completed["job_id"], "backup-1");
        assert_eq!(completed["backup_id"], "backup-1");
        assert_eq!(completed["status"], "completed");
        assert_eq!(completed["finished_at"], "2026-07-14T00:00:01Z");

        record.status = "failed".to_owned();
        record.error_message = "pg_dump failed".to_owned();
        let failed = refresh_data_backup_job(stale, &[record]);
        assert_eq!(failed["status"], "failed");
        assert_eq!(failed["error_message"], "pg_dump failed");
    }

    #[test]
    fn version_comparison_is_numeric() {
        assert!(compare_versions("0.1.10", "0.1.9").is_gt());
        assert!(compare_versions("v1.0.0", "1.0.0").is_eq());
        assert!(compare_versions("1.0", "1.0.1").is_lt());
    }

    #[test]
    fn deployment_versions_are_shell_safe_and_commands_name_the_target() {
        assert_eq!(normalize_release_version("v0.1.146"), Some("0.1.146"));
        assert_eq!(normalize_release_version("1.2"), Some("1.2"));
        assert_eq!(normalize_release_version("1.2.3.4"), Some("1.2.3.4"));
        assert_eq!(normalize_release_version("1.2;rm"), None);
        assert_eq!(normalize_release_version("1.2-beta"), None);
        assert!(redeploy_command("rollback", "0.1.146").contains("v0.1.146"));
    }

    #[test]
    fn route_identifiers_do_not_confuse_configuration_paths() {
        assert_eq!(backup_id("/api/v1/admin/backups/abc/restore"), Some("abc"));
        assert_eq!(backup_id("/api/v1/admin/backups/s3-config"), None);
        assert_eq!(
            profile_id("/api/v1/admin/data-management/s3/profiles/p1"),
            Some("p1")
        );
    }

    #[test]
    fn cron_validation_rejects_shell_text() {
        assert!(validate_cron("0 2 * * *").is_ok());
        assert!(validate_cron("0 2 * * *; rm -rf /").is_err());
    }

    #[test]
    fn data_management_s3_accepts_nested_profiles_and_use_ssl() {
        let config = data_management_s3_config(&json!({
            "profile_id": "primary",
            "s3": {
                "endpoint": "minio.internal:9000",
                "region": "us-east-1",
                "bucket": "backups",
                "access_key_id": "access",
                "secret_access_key": "secret",
                "force_path_style": true,
                "use_ssl": false
            }
        }))
        .unwrap();
        assert_eq!(config.endpoint, "http://minio.internal:9000");
        assert_eq!(config.bucket, "backups");
        assert_eq!(config.secret_access_key, "secret");
        assert!(config.force_path_style);
    }

    #[test]
    fn provider_refund_amount_is_prorated_in_order_currency() {
        assert!(
            (calculate_gateway_refund_amount(100.0, 12.345, 50.0, "KWD") - 6.173).abs()
                < f64::EPSILON
        );
        assert!(
            (calculate_gateway_refund_amount(100.0, 12.345, 100.0, "KWD") - 12.345).abs()
                < f64::EPSILON
        );
        assert!(
            (calculate_gateway_refund_amount(100.0, 103.0, 50.0, "JPY") - 52.0).abs()
                < f64::EPSILON
        );
    }

    #[test]
    fn postgres_restore_is_atomic_and_stops_on_first_error() {
        assert!(PG_RESTORE_SAFETY_ARGS.contains(&"--single-transaction"));
        assert!(PG_RESTORE_SAFETY_ARGS.contains(&"--exit-on-error"));
        assert!(PG_RESTORE_SAFETY_ARGS.contains(&"--clean"));
        assert!(PSQL_RESTORE_SAFETY_ARGS.contains(&"--single-transaction"));
        assert!(PSQL_RESTORE_SAFETY_ARGS.contains(&"--no-psqlrc"));
        assert!(PSQL_RESTORE_SAFETY_ARGS.contains(&"ON_ERROR_STOP=on"));
        assert!(PSQL_RESTORE_SAFETY_ARGS.contains(&"--file"));
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL pointing at a migrated disposable *_test database"]
    #[allow(clippy::too_many_lines)]
    async fn postgres_forced_refund_is_atomic_and_idempotent() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL must point at a disposable *_test database");
        let parsed = Url::parse(&database_url).expect("TEST_DATABASE_URL must be valid");
        assert!(
            parsed.path().trim_matches('/').ends_with("_test"),
            "refusing to mutate a database without an _test suffix"
        );
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .expect("connect disposable PostgreSQL");
        let marker = Uuid::new_v4().simple().to_string();
        let user_id = sqlx::query_scalar::<_, i64>(
            "INSERT INTO users (email, password_hash, balance) VALUES ($1, 'unused', 20) RETURNING id",
        )
        .bind(format!("rust-refund-{marker}@example.com"))
        .fetch_one(&pool)
        .await
        .expect("insert refund user");
        let order_id = sqlx::query_scalar::<_, i64>(
            r"
INSERT INTO payment_orders (
    user_id, amount, pay_amount, order_type, status, out_trade_no, expires_at
)
VALUES ($1, 10, 10, 'balance', 'COMPLETED', $2, NOW() + INTERVAL '1 hour')
RETURNING id
",
        )
        .bind(user_id)
        .bind(format!("rust-refund-{marker}"))
        .fetch_one(&pool)
        .await
        .expect("insert refundable order");
        let actor = AdminIdentity {
            user_id,
            email: format!("rust-refund-{marker}@example.com"),
        };
        let payload = json!({
            "amount": 10,
            "reason": "atomic refund test",
            "deduct_balance": true,
            "force": true,
        });

        let first = process_provider_refund(&pool, &actor, order_id, payload.clone())
            .await
            .expect("force refund should complete");
        assert_eq!(first.get("success").and_then(Value::as_bool), Some(true));
        let second = process_provider_refund(&pool, &actor, order_id, payload)
            .await
            .expect("repeated force refund should be idempotent");
        assert_eq!(second.get("success").and_then(Value::as_bool), Some(true));

        let balance =
            sqlx::query_scalar::<_, String>("SELECT balance::text FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_one(&pool)
                .await
                .expect("load balance after refund");
        assert!((balance.parse::<f64>().unwrap() - 10.0).abs() < f64::EPSILON);
        let (status, audit_count) = sqlx::query_as::<_, (String, i64)>(
            r"
SELECT o.status,
       (SELECT COUNT(*) FROM payment_audit_logs
        WHERE order_id = o.id::text AND action = 'REFUND_SUCCESS')
FROM payment_orders o
WHERE o.id = $1
",
        )
        .bind(order_id)
        .fetch_one(&pool)
        .await
        .expect("load finalized refund state");
        assert_eq!(status, "REFUNDED");
        assert_eq!(audit_count, 1);

        sqlx::query("DELETE FROM payment_audit_logs WHERE order_id = $1")
            .bind(order_id.to_string())
            .execute(&pool)
            .await
            .expect("delete refund audit fixture");
        sqlx::query("DELETE FROM payment_orders WHERE id = $1")
            .bind(order_id)
            .execute(&pool)
            .await
            .expect("delete refund order fixture");
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("delete refund user fixture");
    }
}
