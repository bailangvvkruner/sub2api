use std::{
    collections::HashSet,
    env, fmt,
    future::Future,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::AsyncWriteExt;
use url::Url;

const SETUP_CONFIG_FILE: &str = "rust-setup.json";
const MAX_SETUP_CONFIG_BYTES: usize = 64 * 1024;
const LEGACY_CONFIG_FILE: &str = "config.yaml";
const MAX_LEGACY_CONFIG_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Config {
    pub server: ServerConfig,
    pub cors: CorsConfig,
    pub database: DatabaseConfig,
    pub migrations: MigrationConfig,
    pub auth: AuthConfig,
    pub gateway: GatewayConfig,
    pub bootstrap: BootstrapConfig,
    pub run_mode: String,
    pub timezone: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorsConfig {
    pub allowed_origins: Vec<String>,
    pub allow_credentials: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub trust_proxy_headers: bool,
    pub trusted_proxy_networks: Vec<IpNet>,
}

#[derive(Clone)]
pub struct BootstrapConfig {
    pub admin_email: Option<String>,
    pub admin_password: Option<String>,
    pub admin_concurrency: i32,
}

impl fmt::Debug for BootstrapConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BootstrapConfig")
            .field("admin_email", &self.admin_email)
            .field(
                "admin_password",
                &self.admin_password.as_ref().map(|_| "[REDACTED]"),
            )
            .field("admin_concurrency", &self.admin_concurrency)
            .finish()
    }
}

#[derive(Clone)]
pub struct AuthConfig {
    pub configured_jwt_secret: Option<String>,
    pub totp_encryption_key: Option<String>,
    pub access_token_lifetime: Duration,
    pub refresh_token_lifetime: Duration,
}

impl fmt::Debug for AuthConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthConfig")
            .field(
                "configured_jwt_secret",
                &self.configured_jwt_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "totp_encryption_key",
                &self.totp_encryption_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("access_token_lifetime", &self.access_token_lifetime)
            .field("refresh_token_lifetime", &self.refresh_token_lifetime)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayConfig {
    pub max_request_body_bytes: usize,
    pub max_buffered_response_bytes: usize,
    pub max_upstream_error_bytes: usize,
    pub connect_timeout: Duration,
    pub stream_data_interval_timeout: Duration,
    pub auth_cache_capacity: usize,
    pub auth_cache_ttl: Duration,
    pub account_cache_capacity: usize,
    pub account_cache_ttl: Duration,
}

#[derive(Clone)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout: Duration,
    pub max_lifetime: Duration,
    pub idle_timeout: Duration,
}

impl fmt::Debug for DatabaseConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseConfig")
            .field("url", &redact_database_url(&self.url))
            .field("max_connections", &self.max_connections)
            .field("min_connections", &self.min_connections)
            .field("acquire_timeout", &self.acquire_timeout)
            .field("max_lifetime", &self.max_lifetime)
            .field("idle_timeout", &self.idle_timeout)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationMode {
    Apply,
    Validate,
    Off,
}

impl FromStr for MigrationMode {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "apply" => Ok(Self::Apply),
            "validate" => Ok(Self::Validate),
            "off" => Ok(Self::Off),
            other => bail!("invalid MIGRATIONS_MODE {other:?}; expected apply, validate, or off"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationConfig {
    pub mode: MigrationMode,
    pub timeout: Duration,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PersistedSetupConfig {
    pub database: PersistedSetupDatabase,
    pub server: PersistedSetupServer,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PersistedSetupDatabase {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub dbname: String,
    pub sslmode: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PersistedSetupServer {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug)]
struct LegacyYamlConfig {
    path: PathBuf,
    value: serde_yaml::Value,
}

impl LegacyYamlConfig {
    fn at(&self, dotted_path: &str) -> Option<&serde_yaml::Value> {
        let mut current = &self.value;
        for segment in dotted_path.split('.') {
            let serde_yaml::Value::Mapping(mapping) = current else {
                return None;
            };
            let key = serde_yaml::Value::String(segment.to_owned());
            current = mapping.get(&key)?;
        }
        Some(current)
    }

    fn get<T>(&self, dotted_path: &str) -> Result<Option<T>>
    where
        T: DeserializeOwned,
    {
        let Some(current) = self.at(dotted_path) else {
            return Ok(None);
        };
        serde_yaml::from_value(current.clone())
            .with_context(|| {
                format!(
                    "parse {} from legacy configuration {}",
                    dotted_path,
                    self.path.display()
                )
            })
            .map(Some)
    }

    fn first<T>(&self, dotted_paths: &[&str]) -> Result<Option<T>>
    where
        T: DeserializeOwned,
    {
        for path in dotted_paths {
            if let Some(value) = self.get(path)? {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }
}

impl Config {
    /// Loads the Rust service configuration from the existing `Sub2API`
    /// environment variable contract. Redis variables are intentionally not
    /// read: `PostgreSQL` is the only external state service used by this binary.
    ///
    /// # Errors
    ///
    /// Returns an error when an environment variable is invalid, connection
    /// limits are inconsistent, or the database URL is not a `PostgreSQL` URL.
    pub fn from_env() -> Result<Self> {
        let legacy = load_legacy_yaml_config()?;
        if let Some(legacy) = legacy.as_ref() {
            tracing::info!(path = %legacy.path.display(), "loaded legacy config.yaml compatibility layer");
        }
        validate_legacy_behavioral_compatibility(legacy.as_ref())?;
        let persisted = load_persisted_setup_config()?;
        let setup_overrides_environment = parse_env("SETUP_CONFIG_OVERRIDES_ENV", false)?;
        let legacy_server_host: Option<String> = yaml_value(legacy.as_ref(), "server.host")?;
        let legacy_server_port: Option<u16> = yaml_value(legacy.as_ref(), "server.port")?;
        let trusted_proxy_networks = load_trusted_proxy_networks(legacy.as_ref())?;
        let trust_proxy_headers = optional_parsed_env("TRUST_PROXY_HEADERS")?
            .or(yaml_first(
                legacy.as_ref(),
                &["server.trust_proxy_headers"],
            )?)
            .unwrap_or(!trusted_proxy_networks.is_empty());
        let run_mode = env_or_yaml_string("RUN_MODE", legacy.as_ref(), &["run_mode"], "standard")?;
        let timezone = optional_env("TZ")
            .or_else(|| optional_env("TIMEZONE"))
            .or(yaml_first(legacy.as_ref(), &["timezone"])?)
            .unwrap_or_else(|| "Asia/Shanghai".to_owned());
        let admin_email =
            optional_env("ADMIN_EMAIL").or(yaml_first(legacy.as_ref(), &["default.admin_email"])?);
        let admin_password = optional_env("ADMIN_PASSWORD")
            .or(yaml_first(legacy.as_ref(), &["default.admin_password"])?);
        let admin_concurrency = if run_mode.eq_ignore_ascii_case("simple") {
            30
        } else {
            parse_env_or_yaml(
                "ADMIN_CONCURRENCY",
                legacy.as_ref(),
                &["default.user_concurrency"],
                5_i32,
            )?
        };
        let cors = load_cors_config(legacy.as_ref())?;
        Ok(Self {
            server: ServerConfig {
                host: env_or_persisted(
                    "SERVER_HOST",
                    persisted.as_ref().map(|config| config.server.host.as_str()),
                    legacy_server_host.as_deref(),
                    "0.0.0.0",
                    setup_overrides_environment,
                ),
                port: parse_env_or_persisted(
                    "SERVER_PORT",
                    persisted.as_ref().map(|config| config.server.port),
                    legacy_server_port,
                    8080_u16,
                    setup_overrides_environment,
                )?,
                trust_proxy_headers,
                trusted_proxy_networks,
            },
            cors,
            database: load_database_config(
                persisted.as_ref(),
                legacy.as_ref(),
                setup_overrides_environment,
            )?,
            migrations: load_migration_config(legacy.as_ref())?,
            auth: load_auth_config(legacy.as_ref())?,
            gateway: load_gateway_config(legacy.as_ref())?,
            bootstrap: BootstrapConfig {
                admin_email,
                admin_password,
                admin_concurrency,
            },
            run_mode,
            timezone,
        })
    }
}

fn validate_legacy_behavioral_compatibility(legacy: Option<&LegacyYamlConfig>) -> Result<()> {
    let Some(legacy) = legacy else {
        return Ok(());
    };
    validate_legacy_authentication_settings(legacy)?;
    validate_legacy_security_settings(legacy)?;
    validate_legacy_gateway_request_settings(legacy)?;
    validate_legacy_gateway_transport_settings(legacy)
}

fn validate_legacy_authentication_settings(legacy: &LegacyYamlConfig) -> Result<()> {
    for path in [
        "turnstile.required",
        "linuxdo_connect.enabled",
        "wechat_connect.enabled",
        "oidc_connect.enabled",
        "dingtalk_connect.enabled",
        "github_oauth.enabled",
        "google_oauth.enabled",
    ] {
        reject_legacy_nondefault(legacy, path, false)?;
    }
    reject_legacy_nondefault(legacy, "jwt.refresh_window_minutes", 2_i64)?;
    reject_legacy_nondefault(legacy, "default.api_key_prefix", "sk-".to_owned())
}

fn validate_legacy_security_settings(legacy: &LegacyYamlConfig) -> Result<()> {
    reject_legacy_nonempty_string(legacy, "server.frontend_url")?;
    reject_legacy_nondefault(legacy, "server.read_header_timeout", 30_i64)?;
    reject_legacy_nondefault(legacy, "server.idle_timeout", 120_i64)?;
    reject_legacy_nondefault(legacy, "server.h2c.enabled", false)?;

    reject_legacy_nondefault(legacy, "security.url_allowlist.enabled", false)?;
    reject_legacy_nondefault(legacy, "security.url_allowlist.allow_private_hosts", true)?;
    reject_legacy_nondefault(legacy, "security.url_allowlist.allow_insecure_http", true)?;
    reject_legacy_nondefault(legacy, "security.response_headers.enabled", true)?;
    reject_legacy_nondefault(
        legacy,
        "security.response_headers.additional_allowed",
        Vec::<String>::new(),
    )?;
    reject_legacy_nondefault(
        legacy,
        "security.response_headers.force_remove",
        Vec::<String>::new(),
    )?;
    reject_legacy_nondefault(legacy, "security.csp.enabled", true)?;
    reject_legacy_nondefault(
        legacy,
        "security.csp.policy",
        crate::frontend::DEFAULT_CSP_POLICY.to_owned(),
    )?;
    reject_legacy_nondefault(
        legacy,
        "security.proxy_fallback.allow_direct_on_error",
        false,
    )?;
    reject_legacy_nondefault(legacy, "security.proxy_probe.insecure_skip_verify", false)?;
    reject_legacy_nondefault(legacy, "security.trust_forwarded_ip_for_api_key_acl", false)
}

fn validate_legacy_gateway_request_settings(legacy: &LegacyYamlConfig) -> Result<()> {
    for (path, default) in [
        ("gateway.inject_beta_for_apikey", false),
        ("gateway.failover_on_400", false),
        ("gateway.force_codex_cli", false),
        ("gateway.codex_image_generation_bridge_enabled", false),
        ("gateway.openai_passthrough_allow_timeout_headers", false),
        ("gateway.openai_ws.mode_router_v2_enabled", false),
        ("gateway.openai_ws.enabled", true),
        ("gateway.openai_ws.oauth_enabled", true),
        ("gateway.openai_ws.apikey_enabled", true),
        ("gateway.openai_ws.force_http", false),
        ("gateway.openai_ws.allow_store_recovery", false),
        (
            "gateway.openai_ws.ingress_previous_response_recovery_enabled",
            true,
        ),
        ("gateway.openai_ws.store_disabled_force_new_conn", true),
        ("gateway.openai_ws.prewarm_generate_enabled", false),
        ("gateway.openai_ws.responses_websockets", false),
        ("gateway.openai_ws.responses_websockets_v2", true),
    ] {
        reject_legacy_nondefault(legacy, path, default)?;
    }
    reject_legacy_nondefault(legacy, "gateway.response_header_timeout", 600_i64)?;
    reject_legacy_nondefault(legacy, "gateway.openai_response_header_timeout", 0_i64)?;
    reject_legacy_nondefault(legacy, "gateway.max_account_switches", 10_i64)?;
    reject_legacy_nondefault(legacy, "gateway.max_account_switches_gemini", 3_i64)?;
    reject_legacy_nondefault(
        legacy,
        "gateway.antigravity_fallback_cooldown_minutes",
        1_i64,
    )?;
    reject_legacy_nondefault(legacy, "rate_limit.overload_cooldown_minutes", 10_i64)?;
    reject_legacy_nondefault(legacy, "rate_limit.oauth_401_cooldown_minutes", 10_i64)?;
    reject_legacy_nondefault(legacy, "gateway.openai_compact_model", "gpt-5.4".to_owned())?;
    reject_legacy_nonempty_string(legacy, "gateway.forced_codex_instructions_template_file")
}

fn validate_legacy_gateway_transport_settings(legacy: &LegacyYamlConfig) -> Result<()> {
    for (path, default) in [
        ("gateway.openai_http2.enabled", true),
        ("gateway.openai_http2.allow_proxy_fallback_to_http1", true),
        ("gateway.tls_fingerprint.enabled", true),
    ] {
        reject_legacy_nondefault(legacy, path, default)?;
    }
    for (path, default) in [
        ("gateway.stream_keepalive_interval", 10_i64),
        ("gateway.image_stream_data_interval_timeout", 900_i64),
        ("gateway.image_stream_keepalive_interval", 10_i64),
        ("gateway.openai_http2.fallback_error_threshold", 2_i64),
        ("gateway.openai_http2.fallback_window_seconds", 60_i64),
        ("gateway.openai_http2.fallback_ttl_seconds", 600_i64),
    ] {
        reject_legacy_nondefault(legacy, path, default)?;
    }
    reject_legacy_nondefault(
        legacy,
        "gateway.connection_pool_isolation",
        "account_proxy".to_owned(),
    )?;
    reject_legacy_nondefault(
        legacy,
        "gateway.openai_ws.ingress_mode_default",
        "ctx_pool".to_owned(),
    )?;
    reject_legacy_nondefault(
        legacy,
        "gateway.openai_ws.store_disabled_conn_mode",
        "strict".to_owned(),
    )?;
    reject_legacy_nonempty_mapping(legacy, "gateway.tls_fingerprint.profiles")
}

#[allow(clippy::needless_pass_by_value)]
fn reject_legacy_nondefault<T>(
    legacy: &LegacyYamlConfig,
    dotted_path: &str,
    supported_default: T,
) -> Result<()>
where
    T: DeserializeOwned + PartialEq + fmt::Debug,
{
    let Some(configured) = legacy.get::<T>(dotted_path)? else {
        return Ok(());
    };
    if configured == supported_default {
        return Ok(());
    }
    bail!(
        "legacy setting {dotted_path}={configured:?} changes authentication, security, proxy, or gateway behavior and is not imported by the Rust runtime; migrate it through supported Rust settings or reset it to {supported_default:?}"
    )
}

fn reject_legacy_nonempty_string(legacy: &LegacyYamlConfig, dotted_path: &str) -> Result<()> {
    let Some(configured) = legacy.get::<String>(dotted_path)? else {
        return Ok(());
    };
    if configured.trim().is_empty() {
        return Ok(());
    }
    bail!(
        "legacy setting {dotted_path} changes authentication, security, proxy, or gateway behavior and is not imported by the Rust runtime; migrate it through supported Rust settings or remove it"
    )
}

fn reject_legacy_nonempty_mapping(legacy: &LegacyYamlConfig, dotted_path: &str) -> Result<()> {
    let Some(configured) = legacy.at(dotted_path) else {
        return Ok(());
    };
    if matches!(configured, serde_yaml::Value::Null)
        || matches!(configured, serde_yaml::Value::Mapping(mapping) if mapping.is_empty())
    {
        return Ok(());
    }
    bail!(
        "legacy setting {dotted_path} is not imported by the Rust runtime; migrate these entries through the Rust administrator API or remove them"
    )
}

fn load_database_config(
    persisted: Option<&PersistedSetupConfig>,
    legacy: Option<&LegacyYamlConfig>,
    setup_overrides_environment: bool,
) -> Result<DatabaseConfig> {
    let persisted_database = persisted.map(|config| &config.database);
    let url = load_database_url(persisted_database, legacy, setup_overrides_environment)?;
    let max_connections = parse_nonzero_env_or_yaml(
        "DATABASE_MAX_OPEN_CONNS",
        legacy,
        &["database.max_open_conns"],
        50_u32,
    )?;
    let min_connections =
        parse_env_or_yaml("DATABASE_MIN_CONNS", legacy, &["database.min_conns"], 1_u32)?;
    if min_connections > max_connections {
        bail!(
            "DATABASE_MIN_CONNS ({min_connections}) cannot exceed DATABASE_MAX_OPEN_CONNS ({max_connections})"
        );
    }
    Ok(DatabaseConfig {
        url,
        max_connections,
        min_connections,
        acquire_timeout: Duration::from_secs(parse_nonzero_env_or_yaml(
            "DATABASE_ACQUIRE_TIMEOUT_SECONDS",
            legacy,
            &["database.acquire_timeout_seconds"],
            10_u64,
        )?),
        max_lifetime: minutes_duration(
            "DATABASE_CONN_MAX_LIFETIME_MINUTES",
            parse_env_or_yaml(
                "DATABASE_CONN_MAX_LIFETIME_MINUTES",
                legacy,
                &["database.conn_max_lifetime_minutes"],
                30_u64,
            )?,
            30,
        )?,
        idle_timeout: minutes_duration(
            "DATABASE_CONN_MAX_IDLE_TIME_MINUTES",
            parse_env_or_yaml(
                "DATABASE_CONN_MAX_IDLE_TIME_MINUTES",
                legacy,
                &["database.conn_max_idle_time_minutes"],
                5_u64,
            )?,
            5,
        )?,
    })
}

fn load_database_url(
    persisted_database: Option<&PersistedSetupDatabase>,
    legacy: Option<&LegacyYamlConfig>,
    setup_overrides_environment: bool,
) -> Result<String> {
    let configured_url = if setup_overrides_environment && persisted_database.is_some() {
        None
    } else {
        optional_env("DATABASE_URL").or(if persisted_database.is_none() {
            yaml_first(legacy, &["database.url"])?
        } else {
            None
        })
    };
    Ok(match configured_url {
        Some(url) => validate_database_url(&url)?,
        None => postgres_url_from_parts(&LegacyDatabaseParts {
            host: env_or_persisted(
                "DATABASE_HOST",
                persisted_database.map(|config| config.host.as_str()),
                yaml_first::<String>(legacy, &["database.host"])?.as_deref(),
                "127.0.0.1",
                setup_overrides_environment,
            ),
            port: parse_env_or_persisted(
                "DATABASE_PORT",
                persisted_database.map(|config| config.port),
                yaml_first(legacy, &["database.port"])?,
                5432_u16,
                setup_overrides_environment,
            )?,
            user: env_or_persisted(
                "DATABASE_USER",
                persisted_database.map(|config| config.user.as_str()),
                yaml_first::<String>(legacy, &["database.user"])?.as_deref(),
                "sub2api",
                setup_overrides_environment,
            ),
            password: env_or_persisted(
                "DATABASE_PASSWORD",
                persisted_database.map(|config| config.password.as_str()),
                yaml_first::<String>(legacy, &["database.password"])?.as_deref(),
                "",
                setup_overrides_environment,
            ),
            database: env_or_persisted(
                "DATABASE_DBNAME",
                persisted_database.map(|config| config.dbname.as_str()),
                yaml_first::<String>(legacy, &["database.dbname", "database.database"])?.as_deref(),
                "sub2api",
                setup_overrides_environment,
            ),
            ssl_mode: env_or_persisted(
                "DATABASE_SSLMODE",
                persisted_database.map(|config| config.sslmode.as_str()),
                yaml_first::<String>(legacy, &["database.sslmode"])?.as_deref(),
                "prefer",
                setup_overrides_environment,
            ),
        })?,
    })
}

pub(crate) fn setup_config_path() -> PathBuf {
    env::var_os("DATA_DIR")
        .map_or_else(|| PathBuf::from("./data"), PathBuf::from)
        .join(SETUP_CONFIG_FILE)
}

fn load_persisted_setup_config() -> Result<Option<PersistedSetupConfig>> {
    let path = setup_config_path();
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("read setup config {}", path.display()));
        }
    };
    if bytes.len() > MAX_SETUP_CONFIG_BYTES {
        bail!("setup config {} exceeds the size limit", path.display());
    }
    let config = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse setup config {}", path.display()))?;
    Ok(Some(config))
}

pub(crate) async fn persist_setup_config(config: &PersistedSetupConfig) -> Result<PathBuf> {
    let path = setup_config_path();
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create setup data directory {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(config).context("serialize setup config")?;
    if bytes.len() > MAX_SETUP_CONFIG_BYTES {
        bail!("serialized setup config exceeds the size limit");
    }
    if let Some(matches) = existing_setup_config_matches(&path, &bytes).await? {
        if !matches {
            bail!(
                "setup config {} already exists with different contents",
                path.display()
            );
        }
        restrict_file_permissions(&path).await?;
        sync_parent_directory(path.parent()).await?;
        return Ok(path);
    }
    let temporary = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4().simple()));
    let mut options = tokio::fs::OpenOptions::new();
    options.create_new(true).write(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options
        .open(&temporary)
        .await
        .with_context(|| format!("create temporary setup config {}", temporary.display()))?;
    if let Err(error) = file.write_all(&bytes).await {
        drop(file);
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(error).context("write temporary setup config");
    }
    if let Err(error) = file.sync_all().await {
        drop(file);
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(error).context("flush temporary setup config");
    }
    drop(file);
    if let Err(error) = restrict_file_permissions(&temporary).await {
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(error);
    }
    if let Err(error) = tokio::fs::hard_link(&temporary, &path).await {
        let matches = existing_setup_config_matches(&path, &bytes)
            .await
            .unwrap_or(None)
            .unwrap_or(false);
        let _ = tokio::fs::remove_file(&temporary).await;
        if matches {
            restrict_file_permissions(&path).await?;
            sync_parent_directory(path.parent()).await?;
            return Ok(path);
        }
        return Err(error).with_context(|| format!("install setup config {}", path.display()));
    }
    if let Err(error) = tokio::fs::remove_file(&temporary).await {
        tracing::warn!(
            path = %temporary.display(),
            %error,
            "setup config was installed but its temporary hard link could not be removed"
        );
    }
    sync_parent_directory(path.parent()).await?;
    Ok(path)
}

pub(crate) async fn setup_config_matches(config: &PersistedSetupConfig) -> Result<bool> {
    let bytes = serde_json::to_vec_pretty(config).context("serialize setup config")?;
    Ok(existing_setup_config_matches(&setup_config_path(), &bytes).await? == Some(true))
}

async fn existing_setup_config_matches(
    path: &std::path::Path,
    expected: &[u8],
) -> Result<Option<bool>> {
    match tokio::fs::read(path).await {
        Ok(existing) => Ok(Some(existing == expected)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read setup config {}", path.display())),
    }
}

#[cfg(unix)]
async fn sync_parent_directory(parent: Option<&std::path::Path>) -> Result<()> {
    let Some(parent) = parent.map(std::path::Path::to_owned) else {
        return Ok(());
    };
    let display = parent.display().to_string();
    tokio::task::spawn_blocking(move || std::fs::File::open(&parent)?.sync_all())
        .await
        .context("join setup directory sync")?
        .with_context(|| format!("sync setup data directory {display}"))
}

#[cfg(not(unix))]
fn sync_parent_directory(_parent: Option<&std::path::Path>) -> impl Future<Output = Result<()>> {
    std::future::ready(Ok(()))
}

#[cfg(unix)]
async fn restrict_file_permissions(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .await
        .with_context(|| format!("restrict setup config permissions {}", path.display()))
}

#[cfg(not(unix))]
fn restrict_file_permissions(_path: &std::path::Path) -> impl Future<Output = Result<()>> {
    std::future::ready(Ok(()))
}

fn load_migration_config(legacy: Option<&LegacyYamlConfig>) -> Result<MigrationConfig> {
    let mode = optional_env("MIGRATIONS_MODE")
        .as_deref()
        .unwrap_or("apply")
        .parse()?;
    let configured = parse_env_or_yaml(
        "SETUP_MIGRATION_TIMEOUT_SECONDS",
        legacy,
        &["database.migration_timeout_seconds"],
        0_u64,
    )?;
    Ok(MigrationConfig {
        mode,
        timeout: Duration::from_secs(if configured == 0 { 60 } else { configured }),
    })
}

fn load_auth_config(legacy: Option<&LegacyYamlConfig>) -> Result<AuthConfig> {
    let configured_minutes = optional_parsed_env("JWT_ACCESS_TOKEN_MINUTES")?
        .or(yaml_first(legacy, &["jwt.access_token_expire_minutes"])?)
        .filter(|minutes: &u64| *minutes != 0);
    let access_token_minutes = if let Some(minutes) = configured_minutes {
        minutes
    } else {
        parse_nonzero_env_or_yaml("JWT_EXPIRE_HOUR", legacy, &["jwt.expire_hour"], 24_u64)?
            .checked_mul(60)
            .context("JWT_EXPIRE_HOUR is too large")?
    };
    let totp_encryption_key = optional_env("TOTP_ENCRYPTION_KEY")
        .or(legacy_totp_encryption_key(legacy)?)
        .map(|value: String| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    if let Some(key) = totp_encryption_key.as_deref() {
        validate_totp_encryption_key(key)?;
    }
    Ok(AuthConfig {
        configured_jwt_secret: optional_env("JWT_SECRET").or(yaml_first(legacy, &["jwt.secret"])?),
        totp_encryption_key,
        access_token_lifetime: checked_duration(
            "JWT_ACCESS_TOKEN_MINUTES",
            access_token_minutes,
            60,
        )?,
        refresh_token_lifetime: checked_duration(
            "JWT_REFRESH_TOKEN_DAYS",
            parse_nonzero_env_or_yaml(
                "JWT_REFRESH_TOKEN_DAYS",
                legacy,
                &["jwt.refresh_token_expire_days"],
                30_u64,
            )?,
            24 * 60 * 60,
        )?,
    })
}

fn legacy_totp_encryption_key(legacy: Option<&LegacyYamlConfig>) -> Result<Option<String>> {
    Ok(yaml_first::<String>(legacy, &["totp.encryption_key"])?
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty()))
}

fn validate_totp_encryption_key(value: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("TOTP_ENCRYPTION_KEY must contain exactly 64 hexadecimal characters");
    }
    Ok(())
}

fn load_gateway_config(legacy: Option<&LegacyYamlConfig>) -> Result<GatewayConfig> {
    let stream_data_interval_timeout_seconds = parse_env_or_yaml(
        "GATEWAY_STREAM_DATA_INTERVAL_TIMEOUT_SECONDS",
        legacy,
        &["gateway.stream_data_interval_timeout"],
        180_u64,
    )?;
    if stream_data_interval_timeout_seconds != 0
        && !(30..=300).contains(&stream_data_interval_timeout_seconds)
    {
        bail!("GATEWAY_STREAM_DATA_INTERVAL_TIMEOUT_SECONDS must be 0 or between 30-300 seconds");
    }
    Ok(GatewayConfig {
        max_request_body_bytes: parse_nonzero_env_or_yaml(
            "GATEWAY_MAX_BODY_SIZE",
            legacy,
            &["gateway.max_body_size", "server.max_request_body_size"],
            256_usize * 1024 * 1024,
        )?,
        max_buffered_response_bytes: parse_nonzero_env_or_yaml(
            "GATEWAY_MAX_RESPONSE_SIZE",
            legacy,
            &["gateway.upstream_response_read_max_bytes"],
            64_usize * 1024 * 1024,
        )?,
        max_upstream_error_bytes: parse_nonzero_env_or_yaml(
            "GATEWAY_MAX_ERROR_SIZE",
            legacy,
            &["gateway.log_upstream_error_body_max_bytes"],
            1024_usize * 1024,
        )?,
        connect_timeout: Duration::from_secs(parse_nonzero_env_or_yaml(
            "GATEWAY_CONNECT_TIMEOUT_SECONDS",
            legacy,
            &["gateway.connect_timeout_seconds"],
            10_u64,
        )?),
        stream_data_interval_timeout: Duration::from_secs(stream_data_interval_timeout_seconds),
        auth_cache_capacity: parse_env_or_yaml(
            "L1_AUTH_CAPACITY",
            legacy,
            &["api_key_auth_cache.l1_size"],
            65_535_usize,
        )?,
        auth_cache_ttl: Duration::from_secs(parse_env_or_yaml(
            "L1_AUTH_TTL_SECONDS",
            legacy,
            &["api_key_auth_cache.l1_ttl_seconds"],
            15_u64,
        )?),
        account_cache_capacity: parse_env_or_yaml(
            "L1_ACCOUNT_CAPACITY",
            legacy,
            &["gateway.account_cache_capacity"],
            2_048_usize,
        )?,
        account_cache_ttl: Duration::from_secs(parse_env_or_yaml(
            "L1_ACCOUNT_TTL_SECONDS",
            legacy,
            &["gateway.account_cache_ttl_seconds"],
            2_u64,
        )?),
    })
}

struct LegacyDatabaseParts {
    host: String,
    port: u16,
    user: String,
    password: String,
    database: String,
    ssl_mode: String,
}

fn postgres_url_from_parts(parts: &LegacyDatabaseParts) -> Result<String> {
    if parts.host.trim().is_empty() {
        bail!("DATABASE_HOST cannot be empty");
    }
    if parts.user.is_empty() {
        bail!("DATABASE_USER cannot be empty");
    }
    if parts.database.is_empty() || parts.database.contains('/') {
        bail!("DATABASE_DBNAME must be a non-empty PostgreSQL database name");
    }

    let mut url = Url::parse("postgresql://localhost/postgres")
        .expect("the hard-coded PostgreSQL base URL must be valid");
    url.set_host(Some(parts.host.trim()))
        .context("invalid DATABASE_HOST")?;
    url.set_port(Some(parts.port))
        .map_err(|()| anyhow::anyhow!("invalid DATABASE_PORT"))?;
    url.set_username(&parts.user)
        .map_err(|()| anyhow::anyhow!("invalid DATABASE_USER"))?;
    url.set_password(Some(&parts.password))
        .map_err(|()| anyhow::anyhow!("invalid DATABASE_PASSWORD"))?;
    url.set_path(&format!("/{}", parts.database));
    url.query_pairs_mut()
        .clear()
        .append_pair("sslmode", parts.ssl_mode.trim());

    validate_database_url(url.as_str())
}

fn validate_database_url(value: &str) -> Result<String> {
    let url = Url::parse(value).context("DATABASE_URL is not a valid URL")?;
    match url.scheme() {
        "postgres" | "postgresql" => {}
        scheme => bail!("DATABASE_URL must use postgres:// or postgresql://; found {scheme:?}"),
    }
    if url.host_str().is_none() {
        bail!("DATABASE_URL must include a PostgreSQL host");
    }
    if url.path().trim_matches('/').is_empty() {
        bail!("DATABASE_URL must include a PostgreSQL database name");
    }
    Ok(value.to_owned())
}

fn redact_database_url(value: &str) -> String {
    let Ok(mut url) = Url::parse(value) else {
        return "<invalid database URL>".to_owned();
    };
    if url.password().is_some() {
        let _ = url.set_password(Some("[REDACTED]"));
    }
    url.to_string()
}

fn load_legacy_yaml_config() -> Result<Option<LegacyYamlConfig>> {
    let explicit = env::var_os("SUB2API_CONFIG_FILE").map(PathBuf::from);
    let paths = explicit
        .as_ref()
        .map_or_else(legacy_config_paths, |path| vec![path.clone()]);
    for path in paths {
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && explicit.is_none() => {
                continue;
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("read legacy configuration {}", path.display()));
            }
        };
        if bytes.len() > MAX_LEGACY_CONFIG_BYTES {
            bail!(
                "legacy configuration {} exceeds the {} byte size limit",
                path.display(),
                MAX_LEGACY_CONFIG_BYTES
            );
        }
        let value: serde_yaml::Value = serde_yaml::from_slice(&bytes)
            .with_context(|| format!("parse legacy configuration {}", path.display()))?;
        if !matches!(value, serde_yaml::Value::Mapping(_)) {
            bail!(
                "legacy configuration {} must contain a YAML mapping",
                path.display()
            );
        }
        return Ok(Some(LegacyYamlConfig { path, value }));
    }
    Ok(None)
}

fn legacy_config_paths() -> Vec<PathBuf> {
    let mut paths = Vec::with_capacity(5);
    if let Some(data_dir) = env::var_os("DATA_DIR") {
        paths.push(PathBuf::from(data_dir).join(LEGACY_CONFIG_FILE));
    }
    paths.extend([
        PathBuf::from("/app/data").join(LEGACY_CONFIG_FILE),
        PathBuf::from(LEGACY_CONFIG_FILE),
        PathBuf::from("./config").join(LEGACY_CONFIG_FILE),
        PathBuf::from("/etc/sub2api").join(LEGACY_CONFIG_FILE),
    ]);
    let mut seen = HashSet::new();
    paths.retain(|path| seen.insert(normalized_config_path(path)));
    paths
}

fn normalized_config_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir().map_or_else(|_| path.to_path_buf(), |directory| directory.join(path))
    }
}

fn yaml_value<T>(legacy: Option<&LegacyYamlConfig>, dotted_path: &str) -> Result<Option<T>>
where
    T: DeserializeOwned,
{
    legacy.map_or(Ok(None), |config| config.get(dotted_path))
}

fn yaml_first<T>(legacy: Option<&LegacyYamlConfig>, dotted_paths: &[&str]) -> Result<Option<T>>
where
    T: DeserializeOwned,
{
    legacy.map_or(Ok(None), |config| config.first(dotted_paths))
}

fn env_or_yaml_string(
    name: &str,
    legacy: Option<&LegacyYamlConfig>,
    dotted_paths: &[&str],
    default: &str,
) -> Result<String> {
    Ok(optional_env(name)
        .or(yaml_first(legacy, dotted_paths)?)
        .unwrap_or_else(|| default.to_owned()))
}

fn load_trusted_proxy_networks(legacy: Option<&LegacyYamlConfig>) -> Result<Vec<IpNet>> {
    let values = if let Some(raw) = optional_env("TRUSTED_PROXIES") {
        raw.split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect()
    } else {
        yaml_first::<Vec<String>>(legacy, &["server.trusted_proxies"])?.unwrap_or_default()
    };
    values
        .into_iter()
        .map(|value| {
            let value = value.trim();
            value
                .parse::<IpNet>()
                .or_else(|_| value.parse::<std::net::IpAddr>().map(IpNet::from))
                .with_context(|| format!("invalid trusted proxy network {value:?}"))
        })
        .collect()
}

fn load_cors_config(legacy: Option<&LegacyYamlConfig>) -> Result<CorsConfig> {
    let values = match env::var("CORS_ALLOWED_ORIGINS") {
        Ok(raw) => raw.split(',').map(ToOwned::to_owned).collect(),
        Err(env::VarError::NotPresent) => {
            yaml_first::<Vec<String>>(legacy, &["cors.allowed_origins"])?.unwrap_or_default()
        }
        Err(error) => return Err(error).context("read CORS_ALLOWED_ORIGINS"),
    };
    let mut seen = HashSet::new();
    let mut allowed_origins = Vec::new();
    for value in values {
        let origin = value.trim();
        if origin.is_empty() || !seen.insert(origin.to_owned()) {
            continue;
        }
        if origin != "*" && (origin.chars().any(char::is_control) || origin.chars().count() > 2_048)
        {
            bail!("invalid CORS origin {origin:?}");
        }
        allowed_origins.push(origin.to_owned());
    }
    let requested_credentials = match env::var("CORS_ALLOW_CREDENTIALS") {
        Ok(raw) => parse_loose_bool("CORS_ALLOW_CREDENTIALS", &raw)?,
        Err(env::VarError::NotPresent) => {
            yaml_first(legacy, &["cors.allow_credentials"])?.unwrap_or(true)
        }
        Err(error) => return Err(error).context("read CORS_ALLOW_CREDENTIALS"),
    };
    Ok(CorsConfig {
        allow_credentials: requested_credentials
            && !allowed_origins.iter().any(|origin| origin == "*"),
        allowed_origins,
    })
}

fn parse_loose_bool(name: &str, raw: &str) -> Result<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "on" | "yes" => Ok(true),
        "0" | "false" | "off" | "no" => Ok(false),
        _ => bail!("invalid {name} value {raw:?}"),
    }
}

fn optional_env(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.trim().is_empty())
}

fn env_or_persisted(
    name: &str,
    persisted: Option<&str>,
    legacy: Option<&str>,
    default: &str,
    persisted_first: bool,
) -> String {
    let environment = || optional_env(name);
    let persisted = || persisted.map(ToOwned::to_owned);
    let legacy = || legacy.map(ToOwned::to_owned);
    if persisted_first {
        persisted().or_else(environment).or_else(legacy)
    } else {
        environment().or_else(persisted).or_else(legacy)
    }
    .unwrap_or_else(|| default.to_owned())
}

fn parse_env<T>(name: &str, default: T) -> Result<T>
where
    T: FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    let Some(raw) = optional_env(name) else {
        return Ok(default);
    };
    raw.parse::<T>()
        .with_context(|| format!("invalid {name} value {raw:?}"))
}

fn parse_env_or_persisted<T>(
    name: &str,
    persisted: Option<T>,
    legacy: Option<T>,
    default: T,
    persisted_first: bool,
) -> Result<T>
where
    T: FromStr + Copy,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    if persisted_first && let Some(persisted) = persisted {
        return Ok(persisted);
    }
    optional_parsed_env(name)
        .map(|environment| environment.or(persisted).or(legacy).unwrap_or(default))
}

fn optional_parsed_env<T>(name: &str) -> Result<Option<T>>
where
    T: FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    optional_env(name)
        .map(|raw| {
            raw.parse::<T>()
                .with_context(|| format!("invalid {name} value {raw:?}"))
        })
        .transpose()
}

fn parse_env_or_yaml<T>(
    name: &str,
    legacy: Option<&LegacyYamlConfig>,
    dotted_paths: &[&str],
    default: T,
) -> Result<T>
where
    T: FromStr + Copy + DeserializeOwned,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    Ok(optional_parsed_env(name)?
        .or(yaml_first(legacy, dotted_paths)?)
        .unwrap_or(default))
}

fn parse_nonzero_env_or_yaml<T>(
    name: &str,
    legacy: Option<&LegacyYamlConfig>,
    dotted_paths: &[&str],
    default: T,
) -> Result<T>
where
    T: FromStr + Default + PartialEq + Copy + DeserializeOwned,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    let value = parse_env_or_yaml(name, legacy, dotted_paths, default)?;
    if value == T::default() {
        bail!("{name} must be greater than zero");
    }
    Ok(value)
}

fn checked_duration(name: &str, value: u64, unit_seconds: u64) -> Result<Duration> {
    let seconds = value
        .checked_mul(unit_seconds)
        .with_context(|| format!("{name} is too large"))?;
    Ok(Duration::from_secs(seconds))
}

fn minutes_duration(name: &str, minutes: u64, default_minutes: u64) -> Result<Duration> {
    const MAX_CONFIGURED_MINUTES: u64 = 24 * 60;
    let minutes = if minutes == 0 || minutes > MAX_CONFIGURED_MINUTES {
        tracing::warn!(
            key = name,
            before = minutes,
            after = default_minutes,
            "database connection pool duration clamped"
        );
        default_minutes
    } else {
        minutes
    };
    let seconds = minutes
        .checked_mul(60)
        .with_context(|| format!("{name} is too large"))?;
    Ok(Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy_yaml(source: &str) -> LegacyYamlConfig {
        LegacyYamlConfig {
            path: PathBuf::from("test-config.yaml"),
            value: serde_yaml::from_str(source).expect("test YAML should parse"),
        }
    }

    #[test]
    fn builds_legacy_postgres_url_with_escaped_credentials() {
        let url = postgres_url_from_parts(&LegacyDatabaseParts {
            host: "db.internal".to_owned(),
            port: 5544,
            user: "user@example.com".to_owned(),
            password: "p@ss:/word".to_owned(),
            database: "sub2api".to_owned(),
            ssl_mode: "require".to_owned(),
        })
        .expect("legacy settings should form a URL");

        let parsed = Url::parse(&url).expect("generated URL should parse");
        assert_eq!(parsed.scheme(), "postgresql");
        assert_eq!(parsed.host_str(), Some("db.internal"));
        assert_eq!(parsed.port(), Some(5544));
        assert_eq!(parsed.username(), "user%40example.com");
        assert_eq!(parsed.password(), Some("p%40ss%3A%2Fword"));
        assert_eq!(parsed.path(), "/sub2api");
        assert_eq!(parsed.query(), Some("sslmode=require"));
    }

    #[test]
    fn rejects_non_postgres_database_urls() {
        let error = validate_database_url("redis://localhost/0")
            .expect_err("Redis must never be accepted as the primary database");
        assert!(error.to_string().contains("postgres"));
    }

    #[test]
    fn debug_output_redacts_database_password() {
        let config = DatabaseConfig {
            url: "postgresql://sub2api:super-secret@localhost/sub2api".to_owned(),
            max_connections: 10,
            min_connections: 1,
            acquire_timeout: Duration::from_secs(3),
            max_lifetime: Duration::from_mins(30),
            idle_timeout: Duration::from_mins(5),
        };
        let debug = format!("{config:?}");
        assert!(!debug.contains("super-secret"));
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn database_pool_durations_match_go_clamping() {
        assert_eq!(
            minutes_duration("test", 0, 30).expect("zero should use fallback"),
            Duration::from_mins(30)
        );
        assert_eq!(
            minutes_duration("test", 24 * 60, 30).expect("24h should be allowed"),
            Duration::from_hours(24)
        );
        assert_eq!(
            minutes_duration("test", 24 * 60 + 1, 30).expect("over 24h should use fallback"),
            Duration::from_mins(30)
        );
    }

    #[test]
    fn legacy_yaml_reads_typed_nested_values_and_aliases() {
        let config = legacy_yaml(
            r"
server:
  host: 127.0.0.1
  port: 9090
database:
  dbname: migrated
gateway:
  max_body_size: 1048576
jwt:
  expire_hour: 12
redis:
  host: ignored.example
",
        );
        assert_eq!(
            config.get::<String>("server.host").unwrap().as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(config.get::<u16>("server.port").unwrap(), Some(9090));
        assert_eq!(
            config
                .first::<String>(&["database.database", "database.dbname"])
                .unwrap()
                .as_deref(),
            Some("migrated")
        );
        assert_eq!(
            config.get::<usize>("gateway.max_body_size").unwrap(),
            Some(1_048_576)
        );
        assert_eq!(config.get::<u64>("jwt.expire_hour").unwrap(), Some(12));
    }

    #[test]
    fn legacy_totp_key_is_mapped_and_validated() {
        let key = "ab".repeat(32);
        let config = legacy_yaml(&format!("totp:\n  encryption_key: {key}\n"));
        let mapped = legacy_totp_encryption_key(Some(&config))
            .expect("legacy TOTP key should parse")
            .expect("legacy TOTP key should be present");

        assert_eq!(mapped, key);
        validate_totp_encryption_key(&mapped).expect("legacy TOTP key should be valid");
        assert!(validate_totp_encryption_key("not-a-key").is_err());
    }

    #[test]
    fn legacy_default_behavioral_settings_remain_compatible() {
        let config = legacy_yaml(
            r"
turnstile:
  required: false
oidc_connect:
  enabled: false
security:
  response_headers:
    enabled: true
gateway:
  openai_ws:
    enabled: true
  tls_fingerprint:
    enabled: true
",
        );

        validate_legacy_behavioral_compatibility(Some(&config))
            .expect("legacy defaults must remain accepted");
    }

    #[test]
    fn legacy_security_and_authentication_features_fail_closed() {
        for (source, expected_path) in [
            ("oidc_connect:\n  enabled: true\n", "oidc_connect.enabled"),
            ("turnstile:\n  required: true\n", "turnstile.required"),
            (
                "security:\n  proxy_fallback:\n    allow_direct_on_error: true\n",
                "security.proxy_fallback.allow_direct_on_error",
            ),
        ] {
            let error = validate_legacy_behavioral_compatibility(Some(&legacy_yaml(source)))
                .expect_err("unsupported legacy behavior must fail closed");
            assert!(error.to_string().contains(expected_path), "{error:#}");
        }
    }

    #[test]
    fn legacy_gateway_overrides_fail_closed() {
        for (source, expected_path) in [
            (
                "gateway:\n  openai_ws:\n    enabled: false\n",
                "gateway.openai_ws.enabled",
            ),
            (
                "gateway:\n  tls_fingerprint:\n    profiles:\n      custom:\n        name: custom\n",
                "gateway.tls_fingerprint.profiles",
            ),
        ] {
            let error = validate_legacy_behavioral_compatibility(Some(&legacy_yaml(source)))
                .expect_err("unsupported legacy gateway behavior must fail closed");
            assert!(error.to_string().contains(expected_path), "{error:#}");
        }
    }

    #[test]
    fn auth_debug_redacts_totp_encryption_key() {
        let config = AuthConfig {
            configured_jwt_secret: Some("jwt-secret".to_owned()),
            totp_encryption_key: Some("totp-secret".to_owned()),
            access_token_lifetime: Duration::from_mins(1),
            refresh_token_lifetime: Duration::from_mins(2),
        };
        let debug = format!("{config:?}");
        assert!(!debug.contains("jwt-secret"));
        assert!(!debug.contains("totp-secret"));
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn bootstrap_debug_redacts_legacy_admin_password() {
        let config = BootstrapConfig {
            admin_email: Some("admin@example.com".to_owned()),
            admin_password: Some("do-not-log".to_owned()),
            admin_concurrency: 5,
        };
        let debug = format!("{config:?}");
        assert!(!debug.contains("do-not-log"));
        assert!(debug.contains("REDACTED"));
    }
}
