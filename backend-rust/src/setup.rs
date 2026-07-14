use std::{
    env,
    error::Error,
    fmt,
    sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{PgPool, postgres::PgPoolOptions};
use tokio::sync::Notify;
use url::Url;

use crate::{
    bootstrap::{AdminBootstrapConfig, AdminBootstrapOutcome, bootstrap_admin},
    config::{
        Config, MigrationConfig, MigrationMode, PersistedSetupConfig, PersistedSetupDatabase,
        PersistedSetupServer, persist_setup_config, setup_config_matches,
    },
    migrations,
    security::password,
};

static INSTALLING: AtomicBool = AtomicBool::new(false);
static SETUP_RESTART: OnceLock<Notify> = OnceLock::new();

#[derive(Clone, Debug, Serialize)]
pub struct SetupStatus {
    pub needs_setup: bool,
    pub step: &'static str,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SetupDatabaseConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    #[serde(default)]
    pub password: String,
    pub dbname: String,
    #[serde(default = "default_ssl_mode")]
    pub sslmode: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SetupAdminConfig {
    pub email: String,
    pub password: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub struct SetupServerConfig {
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub mode: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InstallRequest {
    pub database: SetupDatabaseConfig,
    pub admin: SetupAdminConfig,
    #[serde(default)]
    pub server: SetupServerConfig,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct InstallResponse {
    pub message: &'static str,
    pub restart: bool,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct SetupMessage {
    pub message: &'static str,
}

#[must_use]
pub fn setup_mode_enabled() -> bool {
    env::var("SETUP_MODE").is_ok_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes"
        )
    })
}

/// Returns the guarded setup state. Normal deployments do not query the
/// database and always report completed.
///
/// # Errors
///
/// Returns an error when setup mode is enabled but `PostgreSQL` cannot be read.
pub async fn status(pool: &PgPool) -> Result<SetupStatus, SetupError> {
    if !setup_mode_enabled() {
        return Ok(SetupStatus {
            needs_setup: false,
            step: "completed",
        });
    }
    let users_exist = sqlx::query_scalar::<_, bool>("SELECT EXISTS (SELECT 1 FROM users LIMIT 1)")
        .fetch_one(pool)
        .await
        .map_err(|error| SetupError::internal("check setup state", error))?;
    Ok(SetupStatus {
        needs_setup: !users_exist,
        step: if users_exist { "completed" } else { "welcome" },
    })
}

/// Tests a `PostgreSQL` connection, creating the requested database when the
/// configured role has permission and it does not exist yet.
///
/// # Errors
///
/// Returns a validation or connection error.
pub async fn test_database(
    current_pool: &PgPool,
    config: SetupDatabaseConfig,
) -> Result<SetupMessage, SetupError> {
    require_setup(current_pool).await?;
    let _guard = InstallGuard::acquire()?;
    validate_database(&config)?;
    ensure_candidate_database(&config).await?.close().await;
    Ok(SetupMessage {
        message: "Connection successful",
    })
}

/// Migrates the selected database, bootstraps its first administrator, and
/// persists the PostgreSQL/server selection for the next process start.
///
/// # Errors
///
/// Returns an error when setup is disabled/already complete, validation fails,
/// explicit environment overrides conflict with the requested switch, or
/// installation cannot be committed.
pub async fn install(
    pool: &PgPool,
    request: InstallRequest,
) -> Result<InstallResponse, SetupError> {
    let _guard = InstallGuard::acquire()?;
    install_inner(pool, request).await
}

async fn install_inner(
    pool: &PgPool,
    mut request: InstallRequest,
) -> Result<InstallResponse, SetupError> {
    require_setup(pool).await?;
    normalize_install_request(&mut request);
    validate_database(&request.database)?;
    validate_admin(&request.admin)?;
    validate_server(&request.server)?;

    let candidate = ensure_candidate_database(&request.database).await?;
    let current_identity = database_identity(pool).await?;
    let candidate_identity = database_identity(&candidate).await?;
    let database_changed = current_identity != candidate_identity;
    if database_changed && database_environment_pinned() {
        return Err(SetupError::bad_request(
            "Database environment variables pin the running PostgreSQL database",
        ));
    }
    let (server_changed, server_environment_conflict) = server_change(&request.server)?;
    if server_environment_conflict {
        return Err(SetupError::bad_request(
            "Server environment variables conflict with the requested listener",
        ));
    }

    migrations::run(
        &candidate,
        &MigrationConfig {
            mode: MigrationMode::Apply,
            timeout: setup_migration_timeout()?,
        },
    )
    .await
    .map_err(|error| SetupError::internal("migrate setup database", error))?;
    let persisted = PersistedSetupConfig {
        database: PersistedSetupDatabase {
            host: request.database.host.clone(),
            port: request.database.port,
            user: request.database.user.clone(),
            password: request.database.password.clone(),
            dbname: request.database.dbname.clone(),
            sslmode: request.database.sslmode.clone(),
        },
        server: PersistedSetupServer {
            host: request.server.host.clone(),
            port: request.server.port,
        },
    };
    let candidate_has_users = users_exist(&candidate).await?;
    if candidate_has_users {
        let recovery = setup_config_matches(&persisted)
            .await
            .map_err(|error| SetupError::internal("verify setup configuration", error))?
            && setup_admin_matches(&candidate, &request.admin).await?;
        if !recovery {
            return Err(SetupError::conflict(
                "Setup stopped because the database is no longer empty",
            ));
        }
    } else {
        persist_setup_config(&persisted)
            .await
            .map_err(|error| SetupError::internal("persist setup configuration", error))?;
        let outcome = bootstrap_admin(
            &candidate,
            &AdminBootstrapConfig::new(
                Some(request.admin.email.clone()),
                Some(request.admin.password.clone()),
            ),
        )
        .await
        .map_err(|error| SetupError::internal("bootstrap setup administrator", error))?;
        if !matches!(outcome, AdminBootstrapOutcome::Created { .. })
            && !setup_admin_matches(&candidate, &request.admin).await?
        {
            return Err(SetupError::conflict(
                "Setup stopped because the database is no longer empty",
            ));
        }
    }
    candidate.close().await;

    let restart = database_changed || server_changed;
    if restart {
        request_setup_restart();
    }
    Ok(InstallResponse {
        message: "Installation completed successfully",
        restart,
    })
}

pub fn setup_restart_requested() -> impl std::future::Future<Output = ()> {
    SETUP_RESTART.get_or_init(Notify::new).notified()
}

fn request_setup_restart() {
    SETUP_RESTART.get_or_init(Notify::new).notify_one();
}

/// Runs the one-time installation on an isolated current-thread runtime.
/// Migration execution pins a `SQLx` connection for a session advisory lock and
/// is intentionally not required to be `Send`; Axum handlers await only this
/// blocking-task join handle.
///
/// # Errors
///
/// Returns an error when installation is already running, configuration or
/// database setup fails, or the isolated runtime task cannot be joined.
pub async fn install_isolated(
    request: InstallRequest,
    current_database_url: Option<String>,
) -> Result<InstallResponse, SetupError> {
    let guard = InstallGuard::acquire()?;
    let current_database_url = match current_database_url {
        Some(url) => url,
        None => {
            Config::from_env()
                .map_err(|error| SetupError::internal("load setup configuration", error))?
                .database
                .url
        }
    };
    tokio::task::spawn_blocking(move || {
        let _guard = guard;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| SetupError::internal("create setup runtime", error))?;
        runtime.block_on(async move {
            let pool = PgPoolOptions::new()
                .min_connections(0)
                .max_connections(2)
                .acquire_timeout(Duration::from_secs(10))
                .connect(&current_database_url)
                .await
                .map_err(|error| SetupError::internal("connect running setup database", error))?;
            let result = install_inner(&pool, request).await;
            pool.close().await;
            result
        })
    })
    .await
    .map_err(|error| SetupError::internal("join setup runtime", error))?
}

struct InstallGuard;

impl InstallGuard {
    fn acquire() -> Result<Self, SetupError> {
        INSTALLING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| Self)
            .map_err(|_| SetupError::conflict("Another setup installation is already running"))
    }
}

impl Drop for InstallGuard {
    fn drop(&mut self) {
        INSTALLING.store(false, Ordering::Release);
    }
}

pub(crate) async fn require_setup(pool: &PgPool) -> Result<(), SetupError> {
    let state = status(pool).await?;
    if state.needs_setup {
        Ok(())
    } else {
        Err(SetupError::forbidden(
            "Setup is not allowed: system is already installed",
        ))
    }
}

async fn users_exist(pool: &PgPool) -> Result<bool, SetupError> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users LIMIT 1)")
        .fetch_one(pool)
        .await
        .map_err(|error| SetupError::internal("check setup users", error))
}

async fn setup_admin_matches(pool: &PgPool, admin: &SetupAdminConfig) -> Result<bool, SetupError> {
    let rows = sqlx::query_as::<_, (String, String)>(
        "SELECT email, password_hash FROM users WHERE role = 'admin' AND deleted_at IS NULL ORDER BY id LIMIT 2",
    )
    .fetch_all(pool)
    .await
    .map_err(|error| SetupError::internal("verify setup administrator", error))?;
    if rows.len() != 1 || !rows[0].0.eq_ignore_ascii_case(admin.email.trim()) {
        return Ok(false);
    }
    let password_value = admin.password.clone();
    let password_hash = rows[0].1.clone();
    tokio::task::spawn_blocking(move || password::verify_password(&password_value, &password_hash))
        .await
        .map_err(|error| SetupError::internal("join setup password verification", error))?
        .map_err(|error| SetupError::internal("verify setup password", error))
}

async fn ensure_candidate_database(config: &SetupDatabaseConfig) -> Result<PgPool, SetupError> {
    let maintenance = connect_database(config, "postgres").await?;
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)",
    )
    .bind(config.dbname.trim())
    .fetch_one(&maintenance)
    .await
    .map_err(|error| SetupError::internal("check setup database", error))?;
    if !exists {
        let name = config.dbname.trim();
        let statement = format!("CREATE DATABASE \"{name}\"");
        if let Err(error) = sqlx::query(&statement).execute(&maintenance).await
            && error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .is_none_or(|code| code != "42P04")
        {
            return Err(SetupError::internal("create setup database", error));
        }
    }
    maintenance.close().await;
    connect_database(config, config.dbname.trim()).await
}

async fn connect_database(
    config: &SetupDatabaseConfig,
    database_name: &str,
) -> Result<PgPool, SetupError> {
    let url = database_url(config, database_name)?;
    let connect = PgPoolOptions::new()
        .min_connections(0)
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect(url.as_str());
    match tokio::time::timeout(Duration::from_secs(6), connect).await {
        Ok(Ok(pool)) => Ok(pool),
        Ok(Err(error)) => {
            tracing::warn!(error = %error, "setup PostgreSQL connection test failed");
            Err(SetupError::bad_request("PostgreSQL connection failed"))
        }
        Err(_) => Err(SetupError::bad_request("PostgreSQL connection timed out")),
    }
}

fn database_url(config: &SetupDatabaseConfig, database_name: &str) -> Result<Url, SetupError> {
    let mut url = Url::parse("postgresql://localhost/postgres")
        .expect("hard-coded PostgreSQL setup URL should parse");
    url.set_host(Some(config.host.trim()))
        .map_err(|_| SetupError::bad_request("Invalid database hostname"))?;
    url.set_port(Some(config.port))
        .map_err(|()| SetupError::bad_request("Invalid database port"))?;
    url.set_username(config.user.trim())
        .map_err(|()| SetupError::bad_request("Invalid database username"))?;
    url.set_password(Some(&config.password))
        .map_err(|()| SetupError::bad_request("Invalid database password"))?;
    url.set_path(&format!("/{}", database_name.trim()));
    url.query_pairs_mut()
        .clear()
        .append_pair("sslmode", config.sslmode.trim());
    Ok(url)
}

#[derive(Eq, PartialEq)]
struct DatabaseIdentity {
    address: Option<String>,
    port: Option<i32>,
    user: String,
    database: String,
}

async fn database_identity(pool: &PgPool) -> Result<DatabaseIdentity, SetupError> {
    let (address, port, user, database) = sqlx::query_as::<
        _,
        (Option<String>, Option<i32>, String, String),
    >(
        "SELECT inet_server_addr()::text, inet_server_port(), current_user::text, current_database()",
    )
    .fetch_one(pool)
    .await
    .map_err(|error| SetupError::internal("identify setup database", error))?;
    Ok(DatabaseIdentity {
        address,
        port,
        user,
        database,
    })
}

fn database_environment_pinned() -> bool {
    if setup_config_overrides_environment() {
        return false;
    }
    [
        "DATABASE_URL",
        "DATABASE_HOST",
        "DATABASE_PORT",
        "DATABASE_USER",
        "DATABASE_PASSWORD",
        "DATABASE_DBNAME",
        "DATABASE_SSLMODE",
    ]
    .iter()
    .any(|name| env::var_os(name).is_some())
}

fn server_change(server: &SetupServerConfig) -> Result<(bool, bool), SetupError> {
    let current_host = env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_owned());
    let current_port = env::var("SERVER_PORT")
        .ok()
        .map(|value| value.parse::<u16>())
        .transpose()
        .map_err(|_| SetupError::bad_request("Invalid configured server port"))?
        .unwrap_or(8080);
    let host_changed = !server.host.is_empty() && server.host != current_host;
    let port_changed = server.port != 0 && server.port != current_port;
    let conflict = !setup_config_overrides_environment()
        && ((host_changed && env::var_os("SERVER_HOST").is_some())
            || (port_changed && env::var_os("SERVER_PORT").is_some()));
    Ok((host_changed || port_changed, conflict))
}

fn setup_config_overrides_environment() -> bool {
    env::var("SETUP_CONFIG_OVERRIDES_ENV").is_ok_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn setup_migration_timeout() -> Result<Duration, SetupError> {
    let seconds = env::var("SETUP_MIGRATION_TIMEOUT_SECONDS")
        .ok()
        .map(|value| value.parse::<u64>())
        .transpose()
        .map_err(|_| SetupError::bad_request("Invalid setup migration timeout"))?
        .unwrap_or(60);
    Ok(Duration::from_secs(if seconds == 0 { 60 } else { seconds }))
}

fn normalize_install_request(request: &mut InstallRequest) {
    request.database.host = request.database.host.trim().to_owned();
    request.database.user = request.database.user.trim().to_owned();
    request.database.dbname = request.database.dbname.trim().to_owned();
    request.database.sslmode = request.database.sslmode.trim().to_ascii_lowercase();
    request.admin.email = request.admin.email.trim().to_ascii_lowercase();
    request.server.host = request.server.host.trim().to_owned();
    request.server.mode = request.server.mode.trim().to_ascii_lowercase();
    if request.server.host.is_empty() {
        request.server.host = env::var("SERVER_HOST")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "0.0.0.0".to_owned());
    }
    if request.server.port == 0 {
        request.server.port = env::var("SERVER_PORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(8080);
    }
    if request.server.mode.is_empty() {
        request.server.mode.push_str("release");
    }
}

fn validate_database(config: &SetupDatabaseConfig) -> Result<(), SetupError> {
    let host = config.host.trim();
    if host.is_empty()
        || host.len() > 253
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':'))
    {
        return Err(SetupError::bad_request("Invalid database hostname"));
    }
    if config.port == 0 {
        return Err(SetupError::bad_request("Invalid database port"));
    }
    if !valid_identifier(config.user.trim(), false) {
        return Err(SetupError::bad_request("Invalid database username"));
    }
    if !valid_identifier(config.dbname.trim(), true) {
        return Err(SetupError::bad_request("Invalid database name"));
    }
    if !matches!(
        config.sslmode.trim(),
        "disable" | "require" | "verify-ca" | "verify-full"
    ) {
        return Err(SetupError::bad_request("Invalid database SSL mode"));
    }
    Ok(())
}

fn valid_identifier(value: &str, must_start_with_letter: bool) -> bool {
    if value.is_empty() || value.len() > 63 {
        return false;
    }
    if must_start_with_letter && !value.as_bytes()[0].is_ascii_alphabetic() {
        return false;
    }
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn validate_admin(admin: &SetupAdminConfig) -> Result<(), SetupError> {
    let email = admin.email.trim();
    let Some((local, domain)) = email.split_once('@') else {
        return Err(SetupError::bad_request("Invalid admin email"));
    };
    if email.len() > 254
        || local.is_empty()
        || domain.is_empty()
        || domain.starts_with('.')
        || domain.ends_with('.')
        || !domain.contains('.')
        || email.chars().any(char::is_whitespace)
    {
        return Err(SetupError::bad_request("Invalid admin email"));
    }
    if !(8..=128).contains(&admin.password.len()) {
        return Err(SetupError::bad_request(
            "Admin password must contain 8 to 128 bytes",
        ));
    }
    Ok(())
}

fn validate_server(server: &SetupServerConfig) -> Result<(), SetupError> {
    if server.host.is_empty()
        || server.host.len() > 253
        || !server
            .host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':'))
        || server.port == 0
    {
        return Err(SetupError::bad_request("Invalid server listener"));
    }
    if !server.mode.is_empty() && !matches!(server.mode.as_str(), "release" | "debug") {
        return Err(SetupError::bad_request("Invalid server mode"));
    }
    Ok(())
}

fn default_ssl_mode() -> String {
    "disable".to_owned()
}

#[derive(Debug)]
pub struct SetupError {
    status: StatusCode,
    message: &'static str,
    internal: Option<String>,
}

impl SetupError {
    const fn bad_request(message: &'static str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    const fn forbidden(message: &'static str) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }

    const fn conflict(message: &'static str) -> Self {
        Self::new(StatusCode::CONFLICT, message)
    }

    fn internal(context: &'static str, error: impl fmt::Display) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "Setup service is temporarily unavailable",
            internal: Some(format!("{context}: {error}")),
        }
    }

    const fn new(status: StatusCode, message: &'static str) -> Self {
        Self {
            status,
            message,
            internal: None,
        }
    }
}

impl fmt::Display for SetupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl Error for SetupError {}

impl IntoResponse for SetupError {
    fn into_response(self) -> Response {
        if let Some(internal) = self.internal {
            tracing::error!(error = %internal, "setup request failed");
        }
        (
            self.status,
            Json(json!({
                "code": self.status.as_u16(),
                "message": self.message,
            })),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn database() -> SetupDatabaseConfig {
        SetupDatabaseConfig {
            host: "localhost".to_owned(),
            port: 5432,
            user: "sub2api".to_owned(),
            password: "secret".to_owned(),
            dbname: "sub2api".to_owned(),
            sslmode: "disable".to_owned(),
        }
    }

    #[test]
    fn database_url_escapes_credentials_and_rejects_injection() {
        let mut config = database();
        config.password = "p@ss:/word".to_owned();
        let url = database_url(&config, &config.dbname).unwrap();
        assert!(url.as_str().contains("p%40ss%3A%2Fword"));

        config.host = "localhost?sslmode=disable".to_owned();
        assert!(validate_database(&config).is_err());
        config = database();
        config.dbname = "sub2api;DROP".to_owned();
        assert!(validate_database(&config).is_err());
    }

    #[test]
    fn postgres_only_install_contract_has_no_redis_field() {
        let request: InstallRequest = serde_json::from_value(json!({
            "database": {
                "host": "localhost",
                "port": 5432,
                "user": "sub2api",
                "password": "secret",
                "dbname": "sub2api",
                "sslmode": "disable"
            },
            "admin": {"email": "admin@example.com", "password": "long-enough"},
            "server": {"host": "0.0.0.0", "port": 8080, "mode": "release"}
        }))
        .unwrap();
        assert_eq!(request.database, database());
        assert!(validate_admin(&request.admin).is_ok());

        let legacy = serde_json::from_value::<InstallRequest>(json!({
            "database": {
                "host": "localhost", "port": 5432, "user": "sub2api",
                "password": "secret", "dbname": "sub2api", "sslmode": "disable"
            },
            "redis": {"host": "localhost", "port": 6379},
            "admin": {"email": "admin@example.com", "password": "long-enough"}
        }));
        assert!(legacy.is_err());
    }
}
