use std::{error::Error, fmt, sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};
use sqlx::{
    PgPool,
    postgres::{PgListener, PgPoolOptions},
};
use tokio::task::{JoinError, JoinHandle};
use tokio_util::sync::CancellationToken;

use super::GatewayRuntime;

const AUTH_CACHE_INVALIDATION_CHANNEL: &str = "sub2api_auth_cache_invalidation";
const EVENT_VERSION: u8 = 1;
const LISTENER_RETRY_DELAY: Duration = Duration::from_secs(1);

pub trait GatewayAuthState: Send + Sync {
    fn invalidate_api_key(&self, api_key_id: i64, raw_key: Option<&str>);
    fn invalidate_auth_cache(&self);
    fn invalidate_account_cache(&self);
    fn invalidate_runtime_settings(&self);
    fn api_key_current_concurrency(&self, api_key_id: i64) -> u32;
}

impl GatewayAuthState for GatewayRuntime {
    fn invalidate_api_key(&self, api_key_id: i64, raw_key: Option<&str>) {
        self.invalidate_api_key_auth_cache(api_key_id, raw_key);
    }

    fn invalidate_auth_cache(&self) {
        self.invalidate_all_auth_cache();
    }

    fn invalidate_account_cache(&self) {
        self.invalidate_account_selection_cache();
    }

    fn invalidate_runtime_settings(&self) {
        self.invalidate_runtime_settings_cache();
    }

    fn api_key_current_concurrency(&self, api_key_id: i64) -> u32 {
        self.current_api_key_requests(api_key_id)
    }
}

impl crate::admin_api::AdminRuntimeStatsProvider for GatewayRuntime {
    fn snapshot(&self) -> crate::admin_api::AdminRuntimeStatsSnapshot {
        let snapshot = self.pending_billing_snapshot();
        let usage_log = snapshot.mutation_queue;
        let usage_billing = snapshot.billing_queue;

        crate::admin_api::AdminRuntimeStatsSnapshot {
            usage_log: crate::admin_api::AdminUsageLogPendingStats {
                pending_l1_entries: usage_log.pending_items,
                pending_l2_entries: 0,
                enqueued_total: usage_log.accepted,
                flushed_total: usage_log.flushed_items,
                flush_error_total: usage_log.failed_attempts,
                l2_mirror_error_total: 0,
                l2_trim_error_total: 0,
                dropped_after_stopped: usage_log
                    .rejected_full
                    .saturating_add(usage_log.rejected_closed)
                    .saturating_add(usage_log.abandoned_items),
            },
            usage_billing: crate::admin_api::AdminUsageBillingPendingStats {
                pending_l1_entries: u64::try_from(snapshot.pending_requests).unwrap_or(u64::MAX),
                pending_durable_entries: snapshot.pending_durable_entries,
                pending_balance_keys: u64::try_from(snapshot.pending_user_keys).unwrap_or(u64::MAX),
                pending_subscription_keys: u64::try_from(snapshot.pending_user_group_keys)
                    .unwrap_or(u64::MAX),
                pending_api_key_quota_keys: u64::try_from(snapshot.pending_api_key_keys)
                    .unwrap_or(u64::MAX),
                pending_api_key_rate_keys: u64::try_from(snapshot.pending_api_key_keys)
                    .unwrap_or(u64::MAX),
                pending_api_key_updater_keys: u64::try_from(snapshot.pending_api_key_keys)
                    .unwrap_or(u64::MAX),
                pending_account_quota_keys: u64::try_from(snapshot.pending_account_keys)
                    .unwrap_or(u64::MAX),
                pending_l2_entries: 0,
                dedup_entries: u64::try_from(snapshot.pending_requests).unwrap_or(u64::MAX),
                applied_total: usage_billing.flushed_items,
                dedup_skipped_total: 0,
                l2_mirror_error_total: 0,
                l2_trim_error_total: 0,
                flush_success_total: usage_billing.successful_flushes,
                flush_error_total: usage_billing.failed_attempts.saturating_add(
                    u64::try_from(snapshot.backpressure_failed_events).unwrap_or(u64::MAX),
                ),
                flush_balance_keys_total: usage_billing.flushed_items,
                flush_subscription_keys_total: 0,
                flush_api_key_quota_keys_total: usage_billing.flushed_items,
                flush_api_key_rate_keys_total: usage_billing.flushed_items,
                flush_account_quota_keys_total: usage_billing.flushed_items,
            },
        }
    }

    fn pending_api_key_cost(&self, api_key_id: i64) -> f64 {
        GatewayRuntime::pending_api_key_cost(self, api_key_id)
            .parse::<f64>()
            .unwrap_or_default()
    }

    fn pending_user_group_cost(&self, user_id: i64, group_id: i64) -> f64 {
        GatewayRuntime::pending_user_group_cost(self, user_id, group_id)
            .parse::<f64>()
            .unwrap_or_default()
    }

    fn api_key_current_concurrency(&self, api_key_id: i64) -> u64 {
        u64::from(self.current_api_key_requests(api_key_id))
    }
}

#[derive(Clone)]
pub struct AuthCacheInvalidator {
    pool: PgPool,
    target: Arc<dyn GatewayAuthState>,
}

impl AuthCacheInvalidator {
    #[must_use]
    pub fn new(pool: PgPool, target: Arc<dyn GatewayAuthState>) -> Self {
        Self { pool, target }
    }

    /// Removes an API key from this process immediately and broadcasts its ID
    /// to other Rust instances through `PostgreSQL`.
    ///
    /// # Errors
    ///
    /// Returns a database error if the cross-instance notification cannot be
    /// published. The local invalidation has already happened in that case.
    pub async fn invalidate_api_key(
        &self,
        api_key_id: i64,
        raw_key: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        self.publish(CacheInvalidation::ApiKey { api_key_id }, raw_key)
            .await
    }

    /// Invalidates every cached authentication snapshot. This is used for
    /// user and group mutations because those records are embedded in API-key
    /// authentication snapshots.
    ///
    /// # Errors
    ///
    /// Returns a database error if the cross-instance notification fails.
    /// Local invalidation has already completed when an error is returned.
    pub async fn invalidate_auth_cache(&self) -> Result<(), sqlx::Error> {
        self.publish(CacheInvalidation::Auth, None).await
    }

    /// Invalidates all cached account-selection partitions.
    ///
    /// # Errors
    ///
    /// Returns a database error if the cross-instance notification fails.
    /// Local invalidation has already completed when an error is returned.
    pub async fn invalidate_account_cache(&self) -> Result<(), sqlx::Error> {
        self.publish(CacheInvalidation::Accounts, None).await
    }

    /// Invalidates cached runtime-derived state after a settings mutation.
    ///
    /// # Errors
    ///
    /// Returns a database error if the cross-instance notification fails.
    /// Local invalidation has already completed when an error is returned.
    pub async fn invalidate_runtime_settings(&self) -> Result<(), sqlx::Error> {
        self.publish(CacheInvalidation::Settings, None).await
    }

    async fn publish(
        &self,
        invalidation: CacheInvalidation,
        raw_key: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        apply_invalidation(self.target.as_ref(), invalidation, raw_key);
        let payload = encode_event(invalidation);
        sqlx::query("SELECT pg_notify($1, $2)")
            .bind(AUTH_CACHE_INVALIDATION_CHANNEL)
            .bind(payload)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    #[must_use]
    pub fn api_key_current_concurrency(&self, api_key_id: i64) -> u32 {
        self.target.api_key_current_concurrency(api_key_id)
    }
}

#[async_trait::async_trait]
impl crate::admin_api::AdminCacheInvalidator for AuthCacheInvalidator {
    async fn invalidate_api_key(
        &self,
        api_key_id: i64,
        raw_key: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        Self::invalidate_api_key(self, api_key_id, raw_key).await
    }

    async fn invalidate_auth_cache(&self) -> Result<(), sqlx::Error> {
        Self::invalidate_auth_cache(self).await
    }

    async fn invalidate_account_cache(&self) -> Result<(), sqlx::Error> {
        Self::invalidate_account_cache(self).await
    }

    async fn invalidate_runtime_settings(&self) -> Result<(), sqlx::Error> {
        Self::invalidate_runtime_settings(self).await
    }
}

pub struct AuthCacheInvalidationWorker {
    cancellation: CancellationToken,
    task: JoinHandle<()>,
    listener_pool: PgPool,
}

impl AuthCacheInvalidationWorker {
    /// Starts a dedicated `PostgreSQL` listener connection. A separate one-slot
    /// pool prevents `LISTEN` from consuming an application query connection.
    ///
    /// # Errors
    ///
    /// Returns a database error if the dedicated connection or initial
    /// subscription cannot be established.
    pub async fn spawn(
        application_pool: &PgPool,
        target: Arc<dyn GatewayAuthState>,
    ) -> Result<(AuthCacheInvalidator, Self), sqlx::Error> {
        let connect_options = application_pool.connect_options().as_ref().clone();
        let listener_pool = PgPoolOptions::new()
            .min_connections(1)
            .max_connections(1)
            .max_lifetime(None)
            .idle_timeout(None)
            .connect_with(connect_options)
            .await?;
        let mut listener = PgListener::connect_with(&listener_pool).await?;
        listener.listen(AUTH_CACHE_INVALIDATION_CHANNEL).await?;

        let invalidator = AuthCacheInvalidator::new(application_pool.clone(), Arc::clone(&target));
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            listen_for_invalidations(&mut listener, target, task_cancellation).await;
        });
        Ok((
            invalidator,
            Self {
                cancellation,
                task,
                listener_pool,
            },
        ))
    }

    /// Stops the listener and closes its dedicated `PostgreSQL` pool.
    ///
    /// # Errors
    ///
    /// Returns an error if the listener task panicked or was aborted.
    pub async fn shutdown(self) -> Result<(), AuthCacheInvalidationShutdownError> {
        self.cancellation.cancel();
        let result = self.task.await;
        self.listener_pool.close().await;
        result.map_err(AuthCacheInvalidationShutdownError::Join)
    }
}

async fn listen_for_invalidations(
    listener: &mut PgListener,
    target: Arc<dyn GatewayAuthState>,
    cancellation: CancellationToken,
) {
    loop {
        tokio::select! {
            () = cancellation.cancelled() => break,
            notification = listener.recv() => match notification {
                Ok(notification) => match decode_event(notification.payload()) {
                    Ok(event) => apply_invalidation(target.as_ref(), event.invalidation, None),
                    Err(error) => {
                        tracing::warn!(
                            error = %error,
                            channel = notification.channel(),
                            "ignored invalid auth-cache notification"
                        );
                    }
                },
                Err(error) => {
                    tracing::warn!(error = %error, "auth-cache listener disconnected; retrying");
                    tokio::select! {
                        () = cancellation.cancelled() => break,
                        () = tokio::time::sleep(LISTENER_RETRY_DELAY) => {}
                    }
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct AuthCacheInvalidationEvent {
    version: u8,
    #[serde(flatten)]
    invalidation: CacheInvalidation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "scope", rename_all = "snake_case")]
enum CacheInvalidation {
    ApiKey { api_key_id: i64 },
    Auth,
    Accounts,
    Settings,
}

fn apply_invalidation(
    target: &dyn GatewayAuthState,
    invalidation: CacheInvalidation,
    raw_key: Option<&str>,
) {
    match invalidation {
        CacheInvalidation::ApiKey { api_key_id } => {
            target.invalidate_api_key(api_key_id, raw_key);
        }
        CacheInvalidation::Auth => target.invalidate_auth_cache(),
        CacheInvalidation::Accounts => target.invalidate_account_cache(),
        CacheInvalidation::Settings => target.invalidate_runtime_settings(),
    }
}

fn encode_event(invalidation: CacheInvalidation) -> String {
    serde_json::to_string(&AuthCacheInvalidationEvent {
        version: EVENT_VERSION,
        invalidation,
    })
    .expect("fixed auth-cache invalidation event must serialize")
}

fn decode_event(payload: &str) -> Result<AuthCacheInvalidationEvent, InvalidEventError> {
    let event: AuthCacheInvalidationEvent =
        serde_json::from_str(payload).map_err(InvalidEventError::Json)?;
    if event.version != EVENT_VERSION {
        return Err(InvalidEventError::UnsupportedVersion(event.version));
    }
    if matches!(
        event.invalidation,
        CacheInvalidation::ApiKey { api_key_id } if api_key_id <= 0
    ) {
        return Err(InvalidEventError::InvalidApiKeyId);
    }
    Ok(event)
}

#[derive(Debug)]
enum InvalidEventError {
    Json(serde_json::Error),
    UnsupportedVersion(u8),
    InvalidApiKeyId,
}

impl fmt::Display for InvalidEventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "invalid JSON: {error}"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported event version {version}")
            }
            Self::InvalidApiKeyId => formatter.write_str("API key ID must be positive"),
        }
    }
}

impl Error for InvalidEventError {}

#[derive(Debug)]
pub enum AuthCacheInvalidationShutdownError {
    Join(JoinError),
}

impl fmt::Display for AuthCacheInvalidationShutdownError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Join(error) => write!(formatter, "auth-cache listener task failed: {error}"),
        }
    }
}

impl Error for AuthCacheInvalidationShutdownError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Join(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};

    use sqlx::postgres::PgConnectOptions;

    use super::*;

    #[derive(Default)]
    struct FakeTarget {
        invalidated: AtomicI64,
        concurrency: AtomicU32,
        auth_invalidations: AtomicU32,
        account_invalidations: AtomicU32,
        settings_invalidations: AtomicU32,
    }

    impl GatewayAuthState for FakeTarget {
        fn invalidate_api_key(&self, api_key_id: i64, _raw_key: Option<&str>) {
            self.invalidated.store(api_key_id, Ordering::Relaxed);
        }

        fn invalidate_auth_cache(&self) {
            self.auth_invalidations.fetch_add(1, Ordering::Relaxed);
        }

        fn invalidate_account_cache(&self) {
            self.account_invalidations.fetch_add(1, Ordering::Relaxed);
        }

        fn invalidate_runtime_settings(&self) {
            self.settings_invalidations.fetch_add(1, Ordering::Relaxed);
        }

        fn api_key_current_concurrency(&self, _api_key_id: i64) -> u32 {
            self.concurrency.load(Ordering::Relaxed)
        }
    }

    #[test]
    fn event_round_trips_without_exposing_the_raw_key() {
        let invalidation = CacheInvalidation::ApiKey { api_key_id: 42 };
        let payload = encode_event(invalidation);
        assert_eq!(
            decode_event(&payload).expect("event should decode"),
            AuthCacheInvalidationEvent {
                version: EVENT_VERSION,
                invalidation,
            }
        );
        assert!(!payload.contains("sk-"));
        assert!(decode_event(r#"{"version":1,"scope":"api_key","api_key_id":0}"#).is_err());
    }

    #[test]
    fn all_cache_scopes_are_applied_locally() {
        let target = FakeTarget::default();
        apply_invalidation(&target, CacheInvalidation::Auth, None);
        apply_invalidation(&target, CacheInvalidation::Accounts, None);
        apply_invalidation(&target, CacheInvalidation::Settings, None);
        assert_eq!(target.auth_invalidations.load(Ordering::Relaxed), 1);
        assert_eq!(target.account_invalidations.load(Ordering::Relaxed), 1);
        assert_eq!(target.settings_invalidations.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn target_contract_exposes_local_concurrency() {
        let target = FakeTarget::default();
        target.concurrency.store(7, Ordering::Relaxed);
        target.invalidate_api_key(9, Some("sk-secret"));
        assert_eq!(target.invalidated.load(Ordering::Relaxed), 9);
        assert_eq!(target.api_key_current_concurrency(9), 7);
    }

    #[test]
    fn gateway_runtime_is_the_admin_stats_provider_and_main_wires_it() {
        fn assert_provider<T: crate::admin_api::AdminRuntimeStatsProvider>() {}
        assert_provider::<GatewayRuntime>();
        let main_source = include_str!("../main.rs");
        assert!(main_source.contains(".with_runtime_stats(Arc::new(gateway))"));
    }

    #[tokio::test]
    async fn local_invalidation_precedes_a_failed_database_publish() {
        let pool = PgPoolOptions::new().connect_lazy_with(PgConnectOptions::new());
        pool.close().await;
        let target = Arc::new(FakeTarget::default());
        let gateway_target: Arc<dyn GatewayAuthState> = target.clone();
        let invalidator = AuthCacheInvalidator::new(pool, gateway_target);

        assert!(
            invalidator
                .invalidate_api_key(27, Some("sk-secret"))
                .await
                .is_err()
        );
        assert_eq!(target.invalidated.load(Ordering::Relaxed), 27);
    }
}
