use std::{future::IntoFuture, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use sub2api_rust::{
    admin_api::{
        AdminApi, AdminService, Hs256AdminTokenVerifier, PasswordHasher, ReqwestAccountProbe,
    },
    backup_runtime::{BackupRuntime, BackupRuntimeConfig},
    batch_image::BatchImageService,
    bootstrap::{AdminBootstrapConfig, bootstrap_admin},
    config::{Config, MigrationMode},
    control_api::{ControlApiConfig, ControlApiState, router as control_router},
    database,
    email::PostgresSmtpNotifier,
    frontend::FrontendAssets,
    gateway::{
        AuthCacheInvalidationWorker, AuthCacheInvalidator, GatewayAuthState, GatewayRuntime,
        GatewayRuntimeConfig, GatewayWriteWorker,
    },
    http::{AppState, router_with_control},
    maintenance::{MaintenanceConfig, MaintenanceRuntime},
    migrations,
    ops_runtime::{OpsRuntime, OpsRuntimeConfig},
    payment_api::{PaymentApiState, router as payment_router},
    pricing_runtime::{PricingRefreshConfig, PricingRefreshRuntime},
    scheduler_runtime::{SchedulerRuntime, SchedulerRuntimeConfig},
    security::{
        password,
        secrets::{install_config_encryption_key, load_or_create_jwt_secret},
    },
    token_refresh::{TokenRefreshConfig, TokenRefreshRuntime},
    user_api::router as user_api_router,
    user_usage::UserUsageApi,
};
use tokio::{net::TcpListener, signal};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let config = Config::from_env().context("load configuration")?;
    if let Some(key) = config.auth.totp_encryption_key.as_deref() {
        install_config_encryption_key(key).context("install configuration encryption key")?;
    }
    run(config).await
}

#[allow(clippy::too_many_lines)]
async fn run(config: Config) -> Result<()> {
    tracing::info!(
        host = %config.server.host,
        port = config.server.port,
        max_connections = config.database.max_connections,
        migration_mode = ?config.migrations.mode,
        "starting PostgreSQL-only Rust service"
    );

    let (pool, jwt_secret_bytes) = initialize_database(&config).await?;
    let GatewayServices {
        gateway,
        gateway_writes,
        cache_invalidator,
        cache_invalidation_worker,
    } = start_gateway_services(&pool, &config).await?;
    let pricing_refresh = PricingRefreshRuntime::spawn(
        PricingRefreshConfig::from_env().context("load pricing refresh configuration")?,
    )
    .context("start model pricing refresh runtime")?;
    let batch_images = BatchImageService::new(pool.clone(), Some(gateway.clone()))
        .context("initialize PostgreSQL batch image service")?;
    let batch_image_worker = batch_images.spawn_worker();
    let control = initialize_control_api(
        &pool,
        &config,
        jwt_secret_bytes.clone(),
        cache_invalidator.clone(),
    )
    .await?;
    let payment_api_router = payment_router(PaymentApiState::new(
        pool.clone(),
        control.clone(),
        jwt_secret_bytes.clone(),
    ));
    let admin_router = build_admin_router(
        pool.clone(),
        jwt_secret_bytes,
        cache_invalidator.clone(),
        gateway.clone(),
    )?;
    let user_api_router = user_api_router(control.clone());
    let user_usage_router = UserUsageApi::new(control.clone()).router();
    let token_refresh = TokenRefreshRuntime::spawn(
        pool.clone(),
        cache_invalidator.clone(),
        TokenRefreshConfig::default(),
    )
    .context("start PostgreSQL OAuth token refresh runtime")?;
    let maintenance = MaintenanceRuntime::spawn_with_cache_invalidator(
        pool.clone(),
        MaintenanceConfig::default(),
        cache_invalidator,
    )
    .context("start PostgreSQL maintenance runtime")?;
    let backup_scheduler = BackupRuntime::spawn(pool.clone(), BackupRuntimeConfig::default())
        .context("start PostgreSQL backup scheduler")?;
    let scheduler = SchedulerRuntime::spawn(pool.clone(), SchedulerRuntimeConfig::default())
        .context("start PostgreSQL scheduled-test and channel-monitor runtime")?;
    let ops = OpsRuntime::spawn(pool.clone(), OpsRuntimeConfig::default())
        .context("start PostgreSQL operations runtime")?;

    let listener = TcpListener::bind((config.server.host.as_str(), config.server.port))
        .await
        .with_context(|| {
            format!(
                "bind HTTP listener on {}:{}",
                config.server.host, config.server.port
            )
        })?;
    let address = listener
        .local_addr()
        .context("read HTTP listener address")?;
    tracing::info!(%address, "Rust service is listening");

    let app = router_with_control(
        AppState::new(pool.clone())
            .with_gateway(gateway)
            .with_batch_images(batch_images)
            .with_setup_database_url(config.database.url.clone())
            .with_request_body_limit(config.gateway.max_request_body_bytes)
            .with_trusted_proxy_headers(config.server.trust_proxy_headers)
            .with_trusted_proxy_networks(config.server.trusted_proxy_networks.clone())
            .with_cors_policy(
                config.cors.allowed_origins.clone(),
                config.cors.allow_credentials,
            )
            .with_frontend(
                FrontendAssets::new(frontend_root()).with_public_settings(control.clone()),
            ),
        Some(
            control_router(control)
                .merge(user_api_router)
                .merge(user_usage_router)
                .merge(payment_api_router)
                .merge(admin_router),
        ),
    );
    let shutdown = CancellationToken::new();
    let signal_shutdown = shutdown.clone();
    let shutdown_pool = pool.clone();
    let signal_task = tokio::spawn(async move {
        shutdown_signal(shutdown_pool).await;
        signal_shutdown.cancel();
    });
    let serve_result = {
        let graceful_shutdown = shutdown.clone();
        let server = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move { graceful_shutdown.cancelled().await })
        .into_future();
        tokio::pin!(server);
        tokio::select! {
            result = &mut server => result.context("serve HTTP requests"),
            () = shutdown.cancelled() => {
                if let Ok(result) = tokio::time::timeout(Duration::from_secs(45), &mut server).await {
                    result.context("serve HTTP requests during graceful shutdown")
                } else {
                    tracing::warn!("HTTP graceful shutdown reached the 45 second deadline; closing active connections");
                    Err(anyhow::anyhow!(
                        "HTTP graceful shutdown exceeded the 45 second deadline"
                    ))
                }
            }
        }
    };
    if !signal_task.is_finished() {
        signal_task.abort();
    }
    let _ = signal_task.await;

    let (
        token_refresh_result,
        backup_scheduler_result,
        scheduler_result,
        pricing_refresh_result,
        ops_result,
        maintenance_result,
        batch_image_result,
    ) = tokio::join!(
        token_refresh.shutdown(),
        backup_scheduler.shutdown(),
        scheduler.shutdown(),
        pricing_refresh.shutdown(),
        ops.shutdown(),
        maintenance.shutdown(),
        batch_image_worker.shutdown(),
    );
    let cache_invalidation_result = async {
        if let Some(worker) = cache_invalidation_worker {
            worker.shutdown().await
        } else {
            Ok(())
        }
    }
    .await;
    let write_result = gateway_writes.shutdown().await;
    pool.close().await;

    serve_result?;
    token_refresh_result.context("stop PostgreSQL OAuth token refresh runtime")?;
    backup_scheduler_result.context("stop PostgreSQL backup scheduler")?;
    scheduler_result.context("stop PostgreSQL scheduled-test and channel-monitor runtime")?;
    pricing_refresh_result.context("stop model pricing refresh runtime")?;
    ops_result.context("stop PostgreSQL operations runtime")?;
    maintenance_result.context("stop PostgreSQL maintenance runtime")?;
    batch_image_result.context("stop batch image worker")?;
    cache_invalidation_result.context("stop PostgreSQL cache-invalidation listener")?;
    let write_report = write_result.context("drain gateway write-behind queue")?;
    if write_report.unflushed_mutations > 0 || write_report.last_error.is_some() {
        anyhow::bail!(
            "gateway shutdown left {} unflushed mutations: {}",
            write_report.unflushed_mutations,
            write_report
                .last_error
                .as_deref()
                .unwrap_or("unknown error")
        );
    }
    tracing::info!("Rust service stopped");
    Ok(())
}

struct GatewayServices {
    gateway: GatewayRuntime,
    gateway_writes: GatewayWriteWorker,
    cache_invalidator: AuthCacheInvalidator,
    cache_invalidation_worker: Option<AuthCacheInvalidationWorker>,
}

async fn initialize_database(config: &Config) -> Result<(sqlx::PgPool, Vec<u8>)> {
    let pool = database::connect(&config.database).await?;
    if config.migrations.mode != MigrationMode::Off {
        migrations::run(&pool, &config.migrations).await?;
    }

    let jwt_secret = load_or_create_jwt_secret(&pool, config.auth.configured_jwt_secret.as_deref())
        .await
        .context("initialize persistent JWT secret")?;
    if jwt_secret.created {
        tracing::warn!("JWT secret was generated and persisted in PostgreSQL");
    }
    if jwt_secret.configured_value_mismatched {
        tracing::warn!("configured JWT secret differs from PostgreSQL; using the persisted value");
    }

    if sub2api_rust::setup::setup_mode_enabled() {
        tracing::warn!("SETUP_MODE is enabled; waiting for PostgreSQL-only setup completion");
    } else {
        let admin_config = AdminBootstrapConfig::new(
            config.bootstrap.admin_email.clone(),
            config.bootstrap.admin_password.clone(),
        )
        .with_concurrency(config.bootstrap.admin_concurrency);
        let admin = bootstrap_admin(&pool, &admin_config)
            .await
            .context("bootstrap initial administrator")?;
        if let Some(line) = admin.password_log_line() {
            tracing::warn!("{line}");
        }
    }
    Ok((pool, jwt_secret.expose().as_bytes().to_vec()))
}

async fn start_gateway_services(pool: &sqlx::PgPool, config: &Config) -> Result<GatewayServices> {
    let gateway_config = GatewayRuntimeConfig {
        auth_cache_capacity: config.gateway.auth_cache_capacity,
        auth_cache_ttl: config.gateway.auth_cache_ttl,
        account_cache_capacity: config.gateway.account_cache_capacity,
        account_cache_ttl: config.gateway.account_cache_ttl,
        connect_timeout: config.gateway.connect_timeout,
        stream_idle_timeout: config.gateway.stream_data_interval_timeout,
        max_buffered_response_bytes: config.gateway.max_buffered_response_bytes,
        max_upstream_error_bytes: config.gateway.max_upstream_error_bytes,
        ..GatewayRuntimeConfig::default()
    };
    let (gateway, gateway_writes) = GatewayRuntime::spawn(pool.clone(), gateway_config)
        .context("start L1-first gateway runtime")?;
    let gateway_cache: Arc<dyn GatewayAuthState> = Arc::new(gateway.clone());
    let (cache_invalidator, cache_invalidation_worker) =
        match AuthCacheInvalidationWorker::spawn(pool, Arc::clone(&gateway_cache)).await {
            Ok((invalidator, worker)) => (invalidator, Some(worker)),
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    auth_cache_ttl_seconds = config.gateway.auth_cache_ttl.as_secs(),
                    account_cache_ttl_seconds = config.gateway.account_cache_ttl.as_secs(),
                    "PostgreSQL cache-invalidation listener unavailable; using bounded TTL fallback"
                );
                (AuthCacheInvalidator::new(pool.clone(), gateway_cache), None)
            }
        };
    Ok(GatewayServices {
        gateway,
        gateway_writes,
        cache_invalidator,
        cache_invalidation_worker,
    })
}

async fn initialize_control_api(
    pool: &sqlx::PgPool,
    config: &Config,
    jwt_secret: Vec<u8>,
    cache_invalidator: AuthCacheInvalidator,
) -> Result<ControlApiState> {
    let requested_timezone = &config.timezone;
    let (server_timezone, server_utc_offset) =
        resolve_server_timezone(pool, requested_timezone).await;
    let mut control_config = ControlApiConfig::new(jwt_secret)
        .with_access_token_lifetime(config.auth.access_token_lifetime)
        .with_refresh_token_lifetime(config.auth.refresh_token_lifetime)
        .with_run_mode(config.run_mode.clone())
        .with_server_timezone(server_timezone, server_utc_offset);
    if let Some(key) = config.auth.totp_encryption_key.as_deref() {
        control_config = control_config
            .with_totp_encryption_key(key)
            .map_err(anyhow::Error::msg)
            .context("configure TOTP encryption key")?;
    }
    let state = ControlApiState::new(pool.clone(), control_config)
        .context("initialize PostgreSQL control API")?;
    let notifier = PostgresSmtpNotifier::new(pool.clone())
        .map_err(anyhow::Error::msg)
        .context("initialize SMTP TLS client")?;
    Ok(state
        .with_auth_notifier(Arc::new(notifier))
        .with_auth_cache_invalidator(cache_invalidator))
}

struct BcryptPasswordHasher;

impl PasswordHasher for BcryptPasswordHasher {
    fn hash_password(&self, password: &str) -> std::result::Result<String, String> {
        password::hash_password(password).map_err(|error| error.to_string())
    }
}

fn build_admin_router(
    pool: sqlx::PgPool,
    jwt_secret: Vec<u8>,
    cache_invalidator: AuthCacheInvalidator,
    gateway: GatewayRuntime,
) -> Result<axum::Router> {
    let verifier = Hs256AdminTokenVerifier::new(jwt_secret)
        .context("initialize administrator JWT verifier")?;
    Ok(AdminApi::new(
        AdminService::new(pool, Arc::new(BcryptPasswordHasher))
            .with_account_probe(Arc::new(ReqwestAccountProbe::default()))
            .with_cache_invalidator(Arc::new(cache_invalidator))
            .with_runtime_stats(Arc::new(gateway)),
        Arc::new(verifier),
    )
    .router())
}

async fn resolve_server_timezone(pool: &sqlx::PgPool, configured: &str) -> (String, String) {
    let requested = configured.trim();
    let requested = if requested.is_empty() {
        "UTC"
    } else {
        requested
    };
    let offset_seconds = sqlx::query_scalar::<_, i64>(
        r"
SELECT EXTRACT(EPOCH FROM (
    (CURRENT_TIMESTAMP AT TIME ZONE $1)
    - (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')
))::bigint
",
    )
    .bind(requested)
    .fetch_one(pool)
    .await;
    match offset_seconds {
        Ok(offset_seconds) => resolved_timezone(requested, Some(offset_seconds)),
        Err(error) => {
            tracing::warn!(
                error = %error,
                timezone = requested,
                "invalid server timezone; falling back to UTC"
            );
            resolved_timezone(requested, None)
        }
    }
}

fn resolved_timezone(requested: &str, offset_seconds: Option<i64>) -> (String, String) {
    offset_seconds.map_or_else(
        || ("UTC".to_owned(), "+00:00".to_owned()),
        |offset_seconds| (requested.to_owned(), format_utc_offset(offset_seconds)),
    )
}

fn format_utc_offset(offset_seconds: i64) -> String {
    let sign = if offset_seconds < 0 { '-' } else { '+' };
    let total_minutes = offset_seconds.unsigned_abs() / 60;
    let hours = total_minutes / 60;
    let minutes = total_minutes % 60;
    format!("{sign}{hours:02}:{minutes:02}")
}

fn frontend_root() -> std::path::PathBuf {
    std::env::var_os("FRONTEND_DIR").map_or_else(
        || {
            let local = std::path::PathBuf::from("frontend-dist");
            if local.is_dir() {
                local
            } else {
                std::path::PathBuf::from("../frontend-dist")
            }
        },
        std::path::PathBuf::from,
    )
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("sub2api_rust=info,tower_http=info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}

async fn shutdown_signal(pool: sqlx::PgPool) {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C signal handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
        () = administrator_restart_request(&pool) => {},
        () = sub2api_rust::setup::setup_restart_requested() => {},
    }

    tracing::info!("shutdown signal received");
}

async fn administrator_restart_request(pool: &sqlx::PgPool) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let raw = match sqlx::query_scalar::<_, String>(
            "SELECT value FROM settings WHERE key = 'system_deployment_request'",
        )
        .fetch_optional(pool)
        .await
        {
            Ok(Some(raw)) => raw,
            Ok(None) => continue,
            Err(error) => {
                tracing::warn!(error = %error, "poll administrator restart request");
                continue;
            }
        };
        let Ok(mut request) = serde_json::from_str::<serde_json::Value>(&raw) else {
            continue;
        };
        if !is_pending_restart_request(&request) {
            continue;
        }
        request["status"] = serde_json::json!("shutting_down");
        request["handled_at"] = serde_json::json!(chrono::Utc::now().to_rfc3339());
        let Ok(updated) = serde_json::to_string(&request) else {
            continue;
        };
        match sqlx::query(
            "UPDATE settings SET value = $2, updated_at = NOW() WHERE key = 'system_deployment_request' AND value = $1",
        )
        .bind(&raw)
        .bind(updated)
        .execute(pool)
        .await
        {
            Ok(result) if result.rows_affected() == 1 => {
                tracing::warn!("administrator requested a graceful service restart");
                return;
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(error = %error, "claim administrator restart request"),
        }
    }
}

fn is_pending_restart_request(request: &serde_json::Value) -> bool {
    request.get("operation").and_then(serde_json::Value::as_str) == Some("restart")
        && request.get("status").and_then(serde_json::Value::as_str) == Some("pending_restart")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{format_utc_offset, is_pending_restart_request, resolved_timezone};

    #[test]
    fn formats_whole_hour_and_fractional_timezone_offsets() {
        assert_eq!(format_utc_offset(0), "+00:00");
        assert_eq!(format_utc_offset(19_800), "+05:30");
        assert_eq!(format_utc_offset(20_700), "+05:45");
        assert_eq!(format_utc_offset(-12_600), "-03:30");
    }

    #[test]
    fn invalid_timezone_query_falls_back_to_utc() {
        assert_eq!(
            resolved_timezone("Invalid/Zone", None),
            ("UTC".to_owned(), "+00:00".to_owned())
        );
    }

    #[test]
    fn only_new_unclaimed_restart_requests_stop_the_server() {
        assert!(is_pending_restart_request(&json!({
            "operation": "restart",
            "status": "pending_restart",
        })));
        assert!(!is_pending_restart_request(&json!({
            "operation": "update",
            "status": "pending_restart",
        })));
        assert!(!is_pending_restart_request(&json!({
            "operation": "restart",
            "status": "shutting_down",
        })));
    }
}
