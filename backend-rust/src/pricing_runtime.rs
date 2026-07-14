//! Validated hot refresh for the shared model-pricing catalog.

use std::{collections::HashSet, path::PathBuf, time::Duration};

use anyhow::{Context, Result, bail};
use futures_util::StreamExt;
use reqwest::Client;
use sha2::{Digest, Sha256};
use tokio::{io::AsyncWriteExt, task::JoinHandle, time};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::billing::{PricingCatalog, replace_active_pricing_catalog};

const DEFAULT_REMOTE_URL: &str = "https://raw.githubusercontent.com/Wei-Shaw/model-price-repo/main/model_prices_and_context_window.json";
const DEFAULT_HASH_URL: &str = "https://raw.githubusercontent.com/Wei-Shaw/model-price-repo/main/model_prices_and_context_window.sha256";
const DEFAULT_MAX_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct PricingRefreshConfig {
    pub remote_url: Option<String>,
    pub hash_url: Option<String>,
    pub data_file: PathBuf,
    pub poll_interval: Duration,
    pub update_interval: Duration,
    pub request_timeout: Duration,
    pub shutdown_timeout: Duration,
    pub max_bytes: usize,
    pub allowed_hosts: HashSet<String>,
    pub allow_insecure_http: bool,
}

impl PricingRefreshConfig {
    /// Loads the Go-compatible pricing environment contract.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed numeric configuration.
    pub fn from_env() -> Result<Self> {
        let data_file = std::env::var_os("PRICING_DATA_FILE").map_or_else(
            || {
                std::env::var_os("DATA_DIR").map_or_else(
                    || PathBuf::from("./data/model_prices_and_context_window.json"),
                    |directory| {
                        PathBuf::from(directory).join("model_prices_and_context_window.json")
                    },
                )
            },
            PathBuf::from,
        );
        let allowed_hosts = std::env::var("PRICING_ALLOWED_HOSTS")
            .unwrap_or_else(|_| "raw.githubusercontent.com".to_owned())
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_ascii_lowercase)
            .collect();
        let config = Self {
            remote_url: optional_env("PRICING_REMOTE_URL", DEFAULT_REMOTE_URL),
            hash_url: optional_env("PRICING_HASH_URL", DEFAULT_HASH_URL),
            data_file,
            poll_interval: scaled_duration_env("PRICING_HASH_CHECK_INTERVAL_MINUTES", 10, 60)?,
            update_interval: scaled_duration_env("PRICING_UPDATE_INTERVAL_HOURS", 24, 60 * 60)?,
            request_timeout: Duration::from_secs(parse_positive_env(
                "PRICING_REQUEST_TIMEOUT_SECONDS",
                20,
            )?),
            shutdown_timeout: Duration::from_secs(30),
            max_bytes: usize::try_from(parse_positive_env(
                "PRICING_MAX_DOWNLOAD_BYTES",
                u64::try_from(DEFAULT_MAX_BYTES).unwrap_or(u64::MAX),
            )?)
            .context("PRICING_MAX_DOWNLOAD_BYTES does not fit usize")?,
            allowed_hosts,
            allow_insecure_http: boolean_env("PRICING_ALLOW_INSECURE_HTTP", false),
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.poll_interval.is_zero()
            || self.update_interval.is_zero()
            || self.request_timeout.is_zero()
            || self.shutdown_timeout.is_zero()
            || self.max_bytes == 0
        {
            bail!("pricing refresh durations and size limit must be positive");
        }
        if self.allowed_hosts.is_empty() && (self.remote_url.is_some() || self.hash_url.is_some()) {
            bail!("PRICING_ALLOWED_HOSTS cannot be empty when remote refresh is enabled");
        }
        for raw in [&self.remote_url, &self.hash_url].into_iter().flatten() {
            validate_remote_url(raw, self)?;
        }
        Ok(())
    }
}

pub struct PricingRefreshRuntime {
    cancellation: CancellationToken,
    task: JoinHandle<()>,
    shutdown_timeout: Duration,
}

impl PricingRefreshRuntime {
    /// Starts local-catalog recovery and periodic validated remote refresh.
    ///
    /// # Errors
    ///
    /// Returns an error when the HTTP client or configuration is invalid.
    pub fn spawn(config: PricingRefreshConfig) -> Result<Self> {
        config.validate()?;
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(config.request_timeout)
            .timeout(config.request_timeout)
            .build()
            .context("build pricing refresh HTTP client")?;
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let shutdown_timeout = config.shutdown_timeout;
        let task = tokio::spawn(refresh_loop(client, config, task_cancellation));
        Ok(Self {
            cancellation,
            task,
            shutdown_timeout,
        })
    }

    /// Cancels refresh work and joins the runtime.
    ///
    /// # Errors
    ///
    /// Returns an error if the task panics or misses its shutdown deadline.
    pub async fn shutdown(mut self) -> Result<()> {
        self.cancellation.cancel();
        if let Ok(result) = time::timeout(self.shutdown_timeout, &mut self.task).await {
            result.context("pricing refresh task failed")
        } else {
            self.task.abort();
            let _ = self.task.await;
            bail!(
                "pricing refresh task did not stop within {:?}",
                self.shutdown_timeout
            )
        }
    }
}

async fn refresh_loop(
    client: Client,
    config: PricingRefreshConfig,
    cancellation: CancellationToken,
) {
    let mut current_hash = match load_local_catalog(&config).await {
        Ok(hash) => hash,
        Err(error) => {
            tracing::warn!(%error, "local pricing catalog is unavailable; using bundled pricing");
            None
        }
    };
    let mut last_download = None;
    if let Err(error) = refresh_remote(&client, &config, &mut current_hash).await {
        tracing::warn!(%error, "initial model pricing refresh failed; keeping validated fallback");
    } else {
        last_download = Some(time::Instant::now());
    }

    let mut ticker = time::interval(config.poll_interval);
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    ticker.tick().await;
    loop {
        tokio::select! {
            () = cancellation.cancelled() => return,
            _ = ticker.tick() => {
                if config.hash_url.is_none()
                    && last_download.is_some_and(|last| last.elapsed() < config.update_interval)
                {
                    continue;
                }
                match refresh_remote(&client, &config, &mut current_hash).await {
                    Ok(()) => last_download = Some(time::Instant::now()),
                    Err(error) => tracing::warn!(%error, "model pricing refresh failed; keeping previous catalog"),
                }
            }
        }
    }
}

async fn load_local_catalog(config: &PricingRefreshConfig) -> Result<Option<String>> {
    recover_catalog_backup(config).await?;
    let metadata = match tokio::fs::metadata(&config.data_file).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect local pricing catalog"),
    };
    if metadata.len() > u64::try_from(config.max_bytes).unwrap_or(u64::MAX) {
        bail!("local pricing catalog exceeds configured size limit");
    }
    let bytes = tokio::fs::read(&config.data_file)
        .await
        .context("read local pricing catalog")?;
    let catalog = parse_catalog(&bytes)?;
    let models = catalog.len();
    replace_active_pricing_catalog(catalog).context("replace active pricing catalog")?;
    let hash = sha256_hex(&bytes);
    tracing::info!(path = %config.data_file.display(), models, "loaded validated local model pricing catalog");
    Ok(Some(hash))
}

async fn refresh_remote(
    client: &Client,
    config: &PricingRefreshConfig,
    current_hash: &mut Option<String>,
) -> Result<()> {
    let Some(remote_url) = config.remote_url.as_deref() else {
        return Ok(());
    };
    let expected_hash = if let Some(hash_url) = config.hash_url.as_deref() {
        match fetch_limited(client, hash_url, 4_096).await {
            Ok(bytes) => Some(parse_hash(&bytes)?),
            Err(error) if current_hash.is_some() => {
                tracing::warn!(%error, "pricing hash check failed; retaining current catalog");
                return Ok(());
            }
            Err(error) => return Err(error).context("fetch pricing hash"),
        }
    } else {
        None
    };
    if expected_hash.as_ref() == current_hash.as_ref() {
        return Ok(());
    }

    let bytes = fetch_limited(client, remote_url, config.max_bytes)
        .await
        .context("download model pricing catalog")?;
    let actual_hash = sha256_hex(&bytes);
    if let Some(expected_hash) = expected_hash.as_deref()
        && !actual_hash.eq_ignore_ascii_case(expected_hash)
    {
        bail!("downloaded pricing catalog SHA-256 does not match the published manifest");
    }
    let catalog = parse_catalog(&bytes)?;
    let model_count = catalog.len();
    persist_catalog(config, &bytes).await?;
    replace_active_pricing_catalog(catalog).context("replace active pricing catalog")?;
    *current_hash = Some(actual_hash);
    tracing::info!(
        models = model_count,
        "installed refreshed model pricing catalog"
    );
    Ok(())
}

fn parse_catalog(bytes: &[u8]) -> Result<PricingCatalog> {
    let source = std::str::from_utf8(bytes).context("pricing catalog is not UTF-8")?;
    let catalog = PricingCatalog::from_json(source).context("validate pricing catalog")?;
    if catalog.is_empty() {
        bail!("pricing catalog cannot be empty");
    }
    Ok(catalog)
}

async fn persist_catalog(config: &PricingRefreshConfig, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = config.data_file.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .context("create pricing data directory")?;
    }
    let temporary = config
        .data_file
        .with_extension(format!("tmp-{}", uuid::Uuid::new_v4().simple()));
    let mut file = tokio::fs::File::create(&temporary)
        .await
        .context("create temporary pricing catalog")?;
    file.write_all(bytes)
        .await
        .context("write temporary pricing catalog")?;
    file.sync_all()
        .await
        .context("flush temporary pricing catalog")?;
    drop(file);
    if let Err(error) = tokio::fs::rename(&temporary, &config.data_file).await {
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            let _ = tokio::fs::remove_file(&temporary).await;
            return Err(error).context("replace persisted pricing catalog");
        }
        let backup = catalog_backup_path(config);
        remove_file_if_present(&backup)
            .await
            .context("remove stale pricing catalog backup")?;
        let moved_previous = match tokio::fs::rename(&config.data_file, &backup).await {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => {
                let _ = tokio::fs::remove_file(&temporary).await;
                return Err(error).context("back up previous pricing catalog");
            }
        };
        if let Err(install_error) = tokio::fs::rename(&temporary, &config.data_file).await {
            let restore_error = if moved_previous {
                tokio::fs::rename(&backup, &config.data_file).await.err()
            } else {
                None
            };
            let _ = tokio::fs::remove_file(&temporary).await;
            if let Some(restore_error) = restore_error {
                bail!(
                    "replace persisted pricing catalog: {install_error}; restore previous catalog: {restore_error}"
                );
            }
            return Err(install_error).context("replace persisted pricing catalog");
        }
        if moved_previous {
            remove_file_if_present(&backup)
                .await
                .context("remove pricing catalog backup")?;
        }
    }
    Ok(())
}

async fn recover_catalog_backup(config: &PricingRefreshConfig) -> Result<()> {
    let backup = catalog_backup_path(config);
    match tokio::fs::metadata(&config.data_file).await {
        Ok(_) => {
            remove_file_if_present(&backup)
                .await
                .context("remove obsolete pricing catalog backup")?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match tokio::fs::rename(&backup, &config.data_file).await {
                Ok(()) => tracing::warn!(
                    path = %config.data_file.display(),
                    "recovered pricing catalog from interrupted replacement"
                ),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("recover pricing catalog backup"),
            }
        }
        Err(error) => return Err(error).context("inspect pricing catalog during recovery"),
    }
    Ok(())
}

fn catalog_backup_path(config: &PricingRefreshConfig) -> PathBuf {
    let mut path = config.data_file.as_os_str().to_os_string();
    path.push(".backup");
    PathBuf::from(path)
}

async fn remove_file_if_present(path: &std::path::Path) -> std::io::Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

async fn fetch_limited(client: &Client, raw_url: &str, limit: usize) -> Result<Vec<u8>> {
    let response = client
        .get(raw_url)
        .send()
        .await
        .with_context(|| format!("GET {raw_url}"))?
        .error_for_status()
        .with_context(|| format!("GET {raw_url} returned an error status"))?;
    if response
        .content_length()
        .is_some_and(|length| length > u64::try_from(limit).unwrap_or(u64::MAX))
    {
        bail!("pricing response exceeds configured size limit");
    }
    let mut stream = response.bytes_stream();
    let mut output = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("read pricing response body")?;
        if output.len().saturating_add(chunk.len()) > limit {
            bail!("pricing response exceeds configured size limit");
        }
        output.extend_from_slice(&chunk);
    }
    Ok(output)
}

fn validate_remote_url(raw: &str, config: &PricingRefreshConfig) -> Result<()> {
    let url = Url::parse(raw).with_context(|| format!("invalid pricing URL {raw:?}"))?;
    if url.scheme() != "https" && !(config.allow_insecure_http && url.scheme() == "http") {
        bail!("pricing URL must use HTTPS");
    }
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        bail!("pricing URL cannot contain credentials or a fragment");
    }
    let host = url
        .host_str()
        .context("pricing URL must contain a host")?
        .to_ascii_lowercase();
    if !config.allowed_hosts.contains(&host) {
        bail!("pricing host {host:?} is not in PRICING_ALLOWED_HOSTS");
    }
    Ok(())
}

fn parse_hash(bytes: &[u8]) -> Result<String> {
    let raw = std::str::from_utf8(bytes).context("pricing hash response is not UTF-8")?;
    let hash = raw
        .split_whitespace()
        .next()
        .context("pricing hash response is empty")?;
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("pricing hash response does not contain a SHA-256 digest");
    }
    Ok(hash.to_ascii_lowercase())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn optional_env(key: &str, default: &str) -> Option<String> {
    let value = std::env::var(key).unwrap_or_else(|_| default.to_owned());
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

fn parse_positive_env(key: &str, default: u64) -> Result<u64> {
    let value = std::env::var(key).unwrap_or_else(|_| default.to_string());
    let parsed = value
        .trim()
        .parse::<u64>()
        .with_context(|| format!("{key} must be a positive integer"))?;
    if parsed == 0 {
        bail!("{key} must be greater than zero");
    }
    Ok(parsed)
}

fn scaled_duration_env(key: &str, default: u64, scale: u64) -> Result<Duration> {
    let value = parse_positive_env(key, default)?;
    let seconds = value
        .checked_mul(scale)
        .with_context(|| format!("{key} is too large"))?;
    Ok(Duration::from_secs(seconds))
}

fn boolean_env(key: &str, default: bool) -> bool {
    std::env::var(key).map_or(default, |value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> PricingRefreshConfig {
        PricingRefreshConfig {
            remote_url: Some("https://raw.githubusercontent.com/pricing.json".to_owned()),
            hash_url: None,
            data_file: PathBuf::from("pricing.json"),
            poll_interval: Duration::from_mins(1),
            update_interval: Duration::from_hours(1),
            request_timeout: Duration::from_secs(5),
            shutdown_timeout: Duration::from_secs(5),
            max_bytes: 1024,
            allowed_hosts: HashSet::from(["raw.githubusercontent.com".to_owned()]),
            allow_insecure_http: false,
        }
    }

    #[test]
    fn remote_urls_are_https_and_allowlisted() {
        let config = config();
        assert!(validate_remote_url(config.remote_url.as_deref().unwrap(), &config).is_ok());
        assert!(validate_remote_url("http://raw.githubusercontent.com/a", &config).is_err());
        assert!(validate_remote_url("https://127.0.0.1/a", &config).is_err());
        assert!(validate_remote_url("https://user@example.com/a", &config).is_err());
    }

    #[test]
    fn hash_manifest_accepts_standard_sha256sum_format() {
        let hash = "a".repeat(64);
        assert_eq!(
            parse_hash(format!("{hash}  pricing.json\n").as_bytes()).unwrap(),
            hash
        );
        assert!(parse_hash(b"not-a-hash").is_err());
    }

    #[tokio::test]
    async fn interrupted_replacement_recovers_the_previous_catalog() {
        let directory = std::env::temp_dir().join(format!(
            "sub2api-pricing-recovery-{}",
            uuid::Uuid::new_v4().simple()
        ));
        tokio::fs::create_dir_all(&directory).await.unwrap();
        let mut config = config();
        config.data_file = directory.join("pricing.json");
        let backup = catalog_backup_path(&config);
        tokio::fs::write(&backup, b"previous").await.unwrap();

        recover_catalog_backup(&config).await.unwrap();

        assert_eq!(
            tokio::fs::read(&config.data_file).await.unwrap(),
            b"previous"
        );
        assert!(!tokio::fs::try_exists(&backup).await.unwrap());
        tokio::fs::remove_dir_all(directory).await.unwrap();
    }
}
