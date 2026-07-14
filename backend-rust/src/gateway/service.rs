use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
    future::Future,
    hash::{Hash, Hasher},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json,
    body::Body,
    http::{HeaderMap, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use serde_json::{Value, json};
use sqlx::{PgPool, Row};
use tokio::{sync::Notify, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::{
    auth::{
        AuthContext, AuthError, AuthSubject, CredentialError, extract_api_key,
        validate_api_key_snapshot,
    },
    billing::{
        BillingContext, BillingEvent, BillingInvalidation, BillingObserver, BillingPricingInterval,
        BillingPricingMode, BillingPricingOverride, Decimal, ModelPricing, PendingBilling,
        PendingBillingQueue, PostgresBillingSink, RequestType, SseBillingObserver, UsageProvider,
        request_fingerprint,
    },
    repository::{
        AccountProxyRecord, AccountRecord, ApiKeyAuthRecord, ApiKeyRecord,
        ChannelModelPricingRecord, ChannelPolicyRecord, ChannelPricingIntervalRecord,
        CoreRepository, GroupRecord, SubscriptionBillingRecord, UserPlatformQuotaRecord,
    },
    runtime::{
        BatchSink, BoxFlushFuture, L1Cache, SharedResult, ShutdownError, Singleflight, WriteBehind,
        WriteBehindConfig, WriteBehindConfigError, WriteBehindMetricsSnapshot, WriteBehindSender,
    },
};

use super::adapters::{
    ANTHROPIC_OAUTH_CLIENT_ID, ANTHROPIC_OAUTH_TOKEN_URL, ANTIGRAVITY_CLIENT_ID,
    ANTIGRAVITY_CLIENT_SECRET, AdaptedRequest, BedrockEventStreamDecoder, GEMINI_CLI_CLIENT_ID,
    GEMINI_CLI_CLIENT_SECRET, GOOGLE_OAUTH_TOKEN_URL, GROK_OAUTH_CLIENT_ID, GROK_OAUTH_TOKEN_URL,
    OPENAI_OAUTH_CLIENT_ID, OPENAI_OAUTH_TOKEN_URL, StreamWire, VERTEX_TOKEN_URL, adapt_request,
    credential_string as adapter_credential, service_account_assertion, service_account_key,
};
use super::moderation::{ModerationConfig, ModerationOutcome};
use super::runtime_authority::{
    AuthorityError, AuthorityErrorKind, AuthorityLease, BillingReservation, GatewayAuthority,
};
use super::runtime_policy::{ErrorPassthroughDecision, RuntimePolicies, StreamTimeoutSettings};
use super::tls_fingerprint::{AccountTlsFingerprint, TlsFingerprintProfile};
use super::transform::{
    SseBridge, TransformStage, prepare_protocol_request_for_account, validate_upstream_adapter,
};
use super::{
    Credential, GatewayError, GatewayErrorKind, GatewayRoute, PassthroughBody, Protocol,
    RequestMetadata, ResponseMode, RouteKind, UpstreamResponse, build_upstream_request,
    classify_route, inspect_request, prepare_passthrough, response_mode_from_headers,
};

mod websocket;

const DEFAULT_ANTHROPIC_BASE_URL: &str = "https://api.anthropic.com";
const DEFAULT_OPENAI_BASE_URL: &str = "https://api.openai.com";
const DEFAULT_GEMINI_BASE_URL: &str = "https://generativelanguage.googleapis.com";
const DEFAULT_GROK_BASE_URL: &str = "https://api.x.ai";
const CONTENT_MODERATION_SETTING_KEY: &str = "content_moderation_config";
const BILLING_FLUSH_INTERVAL: Duration = Duration::from_secs(30);
const AUTH_NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(30);
const RUNTIME_POLICY_CACHE_KEY: &str = "gateway-runtime-policies";
const RUNTIME_POLICY_CACHE_TTL: Duration = Duration::from_secs(5);
const SUBSCRIPTION_DAY_MILLIS: i64 = 24 * 60 * 60 * 1_000;
const SUBSCRIPTION_WEEK_MILLIS: i64 = 7 * SUBSCRIPTION_DAY_MILLIS;
const SUBSCRIPTION_MONTH_MILLIS: i64 = 30 * SUBSCRIPTION_DAY_MILLIS;
const API_KEY_5H_MILLIS: i64 = 5 * 60 * 60 * 1_000;
const API_KEY_1D_MILLIS: i64 = SUBSCRIPTION_DAY_MILLIS;
const API_KEY_7D_MILLIS: i64 = SUBSCRIPTION_WEEK_MILLIS;
const RPM_WINDOW_MILLIS: i64 = 60 * 1_000;

#[derive(Clone, Debug)]
pub struct GatewayRuntimeConfig {
    pub auth_cache_capacity: usize,
    pub auth_cache_ttl: Duration,
    pub account_cache_capacity: usize,
    pub account_cache_ttl: Duration,
    pub connect_timeout: Duration,
    pub stream_idle_timeout: Duration,
    pub max_buffered_response_bytes: usize,
    pub max_upstream_error_bytes: usize,
    pub write_behind: WriteBehindConfig,
    pub billing_enforced: bool,
}

impl Default for GatewayRuntimeConfig {
    fn default() -> Self {
        Self {
            auth_cache_capacity: 65_535,
            auth_cache_ttl: Duration::from_secs(15),
            account_cache_capacity: 2_048,
            account_cache_ttl: Duration::from_secs(2),
            connect_timeout: Duration::from_secs(10),
            stream_idle_timeout: Duration::from_mins(3),
            max_buffered_response_bytes: 64 * 1024 * 1024,
            max_upstream_error_bytes: 1024 * 1024,
            write_behind: WriteBehindConfig::default(),
            billing_enforced: !std::env::var("RUN_MODE")
                .ok()
                .is_some_and(|mode| mode.trim().eq_ignore_ascii_case("simple")),
        }
    }
}

#[derive(Clone)]
pub struct GatewayRuntime {
    inner: Arc<GatewayRuntimeInner>,
}

struct GatewayRuntimeInner {
    repository: CoreRepository,
    client: reqwest::Client,
    proxy_clients: Arc<L1Cache<ProxyClientKey, reqwest::Client>>,
    tls_fingerprint_clients: Arc<L1Cache<TlsClientKey, reqwest::Client>>,
    auth_cache: Arc<L1Cache<String, ApiKeyAuthRecord>>,
    auth_negative_cache: Arc<L1Cache<String, ()>>,
    auth_flights: Singleflight<String, ApiKeyAuthRecord, String>,
    auth_cache_epoch: Arc<AtomicU64>,
    account_cache: Arc<L1Cache<AccountPartition, Vec<AccountRecord>>>,
    account_flights: Singleflight<AccountPartition, Vec<AccountRecord>, String>,
    channel_cache: Arc<L1Cache<AccountPartition, Option<ChannelPolicyRecord>>>,
    channel_flights: Singleflight<AccountPartition, Option<ChannelPolicyRecord>, String>,
    account_cache_epoch: Arc<AtomicU64>,
    moderation_cache: Arc<L1Cache<String, ModerationConfig>>,
    moderation_flights: Singleflight<String, ModerationConfig, String>,
    moderation_cache_epoch: Arc<AtomicU64>,
    runtime_policy_cache: Arc<L1Cache<String, RuntimePolicies>>,
    runtime_policy_flights: Singleflight<String, RuntimePolicies, String>,
    runtime_policy_cache_epoch: Arc<AtomicU64>,
    in_flight: Arc<Mutex<HashMap<i64, u32>>>,
    api_key_in_flight: Arc<Mutex<HashMap<i64, u32>>>,
    user_in_flight: Arc<Mutex<HashMap<i64, u32>>>,
    rpm: Arc<Mutex<RpmState>>,
    access_tokens: Arc<L1Cache<i64, CachedAccessToken>>,
    access_token_flights: Singleflight<i64, CachedAccessToken, String>,
    writes: WriteBehindSender<GatewayMutation>,
    billing_observer: BillingObserver,
    pending_billing: PendingBilling,
    billing_writes: PendingBillingQueue,
    billing_backpressure: BillingBackpressure,
    authority: GatewayAuthority,
    config: GatewayRuntimeConfig,
}

pub struct GatewayWriteWorker {
    worker: WriteBehind<GatewayMutation>,
    billing_worker: WriteBehind<BillingEvent>,
    billing_backpressure: BillingBackpressure,
    authority_cancellation: CancellationToken,
    authority_task: JoinHandle<()>,
}

impl GatewayWriteWorker {
    /// Flushes all queued gateway mutations and stops the worker.
    ///
    /// # Errors
    ///
    /// Returns an error if the worker cannot drain before its configured
    /// shutdown deadline.
    pub async fn shutdown(self) -> Result<GatewayWriteShutdownReport, GatewayWriteShutdownError> {
        self.authority_cancellation.cancel();
        let (gateway, billing, backpressure, authority) = tokio::join!(
            self.worker.shutdown(),
            self.billing_worker.shutdown(),
            self.billing_backpressure.close_and_wait(),
            self.authority_task,
        );
        let gateway = gateway?;
        let billing = billing?;
        let authority_error = authority
            .err()
            .map(|error| format!("gateway authority worker: {error}"));
        let worker_error = match (gateway.last_error, billing.last_error) {
            (Some(gateway), Some(billing)) => {
                Some(format!("gateway mutations: {gateway}; billing: {billing}"))
            }
            (Some(error), None) | (None, Some(error)) => Some(error),
            (None, None) => None,
        };
        let worker_error = match (worker_error, authority_error) {
            (Some(worker), Some(authority)) => Some(format!("{worker}; {authority}")),
            (Some(error), None) | (None, Some(error)) => Some(error),
            (None, None) => None,
        };
        let last_error = match (worker_error, backpressure.last_error) {
            (Some(worker), Some(backpressure)) => {
                Some(format!("{worker}; billing backpressure: {backpressure}"))
            }
            (Some(error), None) | (None, Some(error)) => Some(error),
            (None, None) => None,
        };
        Ok(GatewayWriteShutdownReport {
            unflushed_mutations: gateway.unflushed.len()
                + billing.unflushed.len()
                + backpressure.failed_events,
            last_error,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayWriteShutdownReport {
    pub unflushed_mutations: usize,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct GatewayPendingBillingSnapshot {
    pub pending_requests: usize,
    pub pending_billed_cost: String,
    pub pending_account_cost: String,
    pub billing_queue: WriteBehindMetricsSnapshot,
    pub mutation_queue: WriteBehindMetricsSnapshot,
    pub backpressure_in_flight: usize,
    pub backpressure_failed_events: usize,
    pub pending_user_keys: usize,
    pub pending_api_key_keys: usize,
    pub pending_user_group_keys: usize,
    pub pending_user_platform_keys: usize,
    pub pending_account_keys: usize,
    pub pending_durable_entries: u64,
}

#[derive(Debug)]
pub enum GatewayWriteShutdownError {
    Runtime(ShutdownError),
}

impl fmt::Display for GatewayWriteShutdownError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(error) => error.fmt(formatter),
        }
    }
}

impl Error for GatewayWriteShutdownError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
        }
    }
}

impl From<ShutdownError> for GatewayWriteShutdownError {
    fn from(error: ShutdownError) -> Self {
        Self::Runtime(error)
    }
}

#[derive(Debug)]
pub enum GatewayRuntimeBuildError {
    Http(reqwest::Error),
    Pricing(crate::billing::PricingError),
    WriteBehind(WriteBehindConfigError),
}

impl fmt::Display for GatewayRuntimeBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(error) => write!(formatter, "build upstream HTTP client: {error}"),
            Self::Pricing(error) => write!(formatter, "load gateway billing prices: {error}"),
            Self::WriteBehind(error) => {
                write!(formatter, "configure gateway write-behind: {error}")
            }
        }
    }
}

impl Error for GatewayRuntimeBuildError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Http(error) => Some(error),
            Self::Pricing(error) => Some(error),
            Self::WriteBehind(error) => Some(error),
        }
    }
}

impl GatewayRuntime {
    /// Creates the L1-first gateway and its separately owned write worker.
    ///
    /// # Errors
    ///
    /// Returns an error when the HTTP client or write-behind configuration is
    /// invalid.
    #[allow(clippy::too_many_lines)]
    pub fn spawn(
        pool: PgPool,
        config: GatewayRuntimeConfig,
    ) -> Result<(Self, GatewayWriteWorker), GatewayRuntimeBuildError> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .connect_timeout(config.connect_timeout)
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_keepalive(Duration::from_secs(30))
            .build()
            .map_err(GatewayRuntimeBuildError::Http)?;
        let worker = WriteBehind::spawn(
            GatewayMutationSink { pool: pool.clone() },
            config.write_behind.clone(),
        )
        .map_err(GatewayRuntimeBuildError::WriteBehind)?;
        let writes = worker.sender();
        let billing_observer =
            BillingObserver::bundled().map_err(GatewayRuntimeBuildError::Pricing)?;
        let auth_cache = Arc::new(L1Cache::<String, ApiKeyAuthRecord>::new(
            config.auth_cache_capacity,
            config.auth_cache_ttl,
        ));
        let auth_negative_cache = Arc::new(L1Cache::<String, ()>::new(
            config.auth_cache_capacity,
            AUTH_NEGATIVE_CACHE_TTL,
        ));
        let auth_cache_epoch = Arc::new(AtomicU64::new(0));
        let account_cache = Arc::new(L1Cache::<AccountPartition, Vec<AccountRecord>>::new(
            config.account_cache_capacity,
            config.account_cache_ttl,
        ));
        let channel_cache = Arc::new(
            L1Cache::<AccountPartition, Option<ChannelPolicyRecord>>::new(
                config.account_cache_capacity,
                config.account_cache_ttl,
            ),
        );
        let account_cache_epoch = Arc::new(AtomicU64::new(0));
        let moderation_cache = Arc::new(L1Cache::<String, ModerationConfig>::new(
            1,
            config.account_cache_ttl,
        ));
        let moderation_cache_epoch = Arc::new(AtomicU64::new(0));
        let runtime_policy_cache = Arc::new(L1Cache::<String, RuntimePolicies>::new(
            1,
            RUNTIME_POLICY_CACHE_TTL,
        ));
        let runtime_policy_cache_epoch = Arc::new(AtomicU64::new(0));
        let pending_billing = PendingBilling::default();
        let invalidation_auth_cache = Arc::clone(&auth_cache);
        let invalidation_auth_epoch = Arc::clone(&auth_cache_epoch);
        let invalidation_account_cache = Arc::clone(&account_cache);
        let invalidation_account_epoch = Arc::clone(&account_cache_epoch);
        let billing_sink = pending_billing.sink_with_invalidator(
            PostgresBillingSink::new(pool.clone()),
            move |invalidation: &BillingInvalidation| {
                invalidate_local_billing_caches(
                    &invalidation_auth_cache,
                    &invalidation_auth_epoch,
                    &invalidation_account_cache,
                    &invalidation_account_epoch,
                    invalidation,
                );
            },
        );
        let mut billing_write_config = config.write_behind.clone();
        billing_write_config.flush_interval = BILLING_FLUSH_INTERVAL;
        let billing_worker = WriteBehind::spawn(billing_sink, billing_write_config)
            .map_err(GatewayRuntimeBuildError::WriteBehind)?;
        let billing_writes = pending_billing.queue(billing_worker.sender());
        let billing_backpressure = BillingBackpressure::default();
        let authority = GatewayAuthority::new(pool.clone());
        let authority_cancellation = CancellationToken::new();
        let authority_task = tokio::spawn(run_authority_worker(
            authority.clone(),
            billing_writes.clone(),
            authority_cancellation.clone(),
        ));
        let inner = GatewayRuntimeInner {
            repository: CoreRepository::new(pool),
            client,
            proxy_clients: Arc::new(L1Cache::new(
                config.account_cache_capacity,
                config.account_cache_ttl,
            )),
            tls_fingerprint_clients: Arc::new(L1Cache::new(
                config.account_cache_capacity,
                config.account_cache_ttl,
            )),
            auth_cache,
            auth_negative_cache,
            auth_flights: Singleflight::new(),
            auth_cache_epoch,
            account_cache,
            account_flights: Singleflight::new(),
            channel_cache,
            channel_flights: Singleflight::new(),
            account_cache_epoch,
            moderation_cache,
            moderation_flights: Singleflight::new(),
            moderation_cache_epoch,
            runtime_policy_cache,
            runtime_policy_flights: Singleflight::new(),
            runtime_policy_cache_epoch,
            in_flight: Arc::new(Mutex::new(HashMap::new())),
            api_key_in_flight: Arc::new(Mutex::new(HashMap::new())),
            user_in_flight: Arc::new(Mutex::new(HashMap::new())),
            rpm: Arc::new(Mutex::new(RpmState::default())),
            access_tokens: Arc::new(L1Cache::new(
                config.account_cache_capacity,
                Duration::from_hours(1),
            )),
            access_token_flights: Singleflight::new(),
            writes,
            billing_observer,
            pending_billing,
            billing_writes,
            billing_backpressure: billing_backpressure.clone(),
            authority,
            config,
        };
        Ok((
            Self {
                inner: Arc::new(inner),
            },
            GatewayWriteWorker {
                worker,
                billing_worker,
                billing_backpressure,
                authority_cancellation,
                authority_task,
            },
        ))
    }

    /// Invalidates a cached API-key authentication snapshot in this process.
    /// The epoch also prevents a database lookup started before invalidation
    /// from repopulating the cache after a committed mutation.
    pub fn invalidate_api_key_auth_cache(&self, api_key_id: i64, raw_key: Option<&str>) {
        self.inner.auth_cache_epoch.fetch_add(1, Ordering::AcqRel);
        if let Some(raw_key) = raw_key {
            let raw_key = raw_key.to_owned();
            self.inner.auth_cache.remove(&raw_key);
            self.inner.auth_negative_cache.remove(&raw_key);
        }
        self.inner
            .auth_cache
            .remove_where(|_, snapshot| snapshot.api_key.id == api_key_id);
    }

    /// Invalidates all authentication snapshots in this process.
    pub fn invalidate_all_auth_cache(&self) {
        self.inner.auth_cache_epoch.fetch_add(1, Ordering::AcqRel);
        self.inner.auth_cache.clear();
        self.inner.auth_negative_cache.clear();
    }

    /// Invalidates every cached scheduler partition. The account cache is
    /// deliberately small and short-lived, so a full clear keeps group,
    /// account, and proxy mutations correct without a secondary index.
    pub fn invalidate_account_selection_cache(&self) {
        self.inner
            .account_cache_epoch
            .fetch_add(1, Ordering::AcqRel);
        self.inner.account_cache.clear();
        self.inner.channel_cache.clear();
        self.inner.proxy_clients.clear();
        self.inner.tls_fingerprint_clients.clear();
    }

    /// Clears runtime-derived caches after settings changes. Public settings
    /// are read directly from `PostgreSQL`, while gateway snapshots use these
    /// bounded authentication, scheduler, and safety-setting caches.
    pub fn invalidate_runtime_settings_cache(&self) {
        self.invalidate_all_auth_cache();
        self.invalidate_account_selection_cache();
        self.inner
            .moderation_cache_epoch
            .fetch_add(1, Ordering::AcqRel);
        self.inner.moderation_cache.clear();
        self.inner
            .runtime_policy_cache_epoch
            .fetch_add(1, Ordering::AcqRel);
        self.inner.runtime_policy_cache.clear();
    }

    /// Returns the number of active gateway requests using an API key in this
    /// process.
    #[must_use]
    pub fn current_api_key_requests(&self, api_key_id: i64) -> u32 {
        lock(&self.inner.api_key_in_flight)
            .get(&api_key_id)
            .copied()
            .unwrap_or_default()
    }

    /// Returns the number of active gateway requests owned by a user in this
    /// process.
    #[must_use]
    pub fn current_user_requests(&self, user_id: i64) -> u32 {
        lock(&self.inner.user_in_flight)
            .get(&user_id)
            .copied()
            .unwrap_or_default()
    }

    #[must_use]
    pub fn pending_billing_snapshot(&self) -> GatewayPendingBillingSnapshot {
        let (backpressure_in_flight, backpressure_failed_events) =
            self.inner.billing_backpressure.snapshot();
        let key_counts = self.inner.pending_billing.key_counts();
        GatewayPendingBillingSnapshot {
            pending_requests: self.inner.pending_billing.len(),
            pending_billed_cost: self.inner.pending_billing.total_billed_cost().to_string(),
            pending_account_cost: self.inner.pending_billing.total_account_cost().to_string(),
            billing_queue: self.inner.billing_writes.metrics(),
            mutation_queue: self.inner.writes.metrics(),
            backpressure_in_flight,
            backpressure_failed_events,
            pending_user_keys: key_counts.users,
            pending_api_key_keys: key_counts.api_keys,
            pending_user_group_keys: key_counts.user_groups,
            pending_user_platform_keys: key_counts.user_platforms,
            pending_account_keys: key_counts.accounts,
            pending_durable_entries: self.inner.authority.ready_count(),
        }
    }

    /// Returns the process-local, not-yet-committed cost for one API key.
    #[must_use]
    pub fn pending_api_key_cost(&self, api_key_id: i64) -> String {
        self.inner
            .pending_billing
            .api_key_cost(api_key_id)
            .to_string()
    }

    /// Returns the process-local, not-yet-committed subscription cost for one
    /// user/group pair.
    #[must_use]
    pub fn pending_user_group_cost(&self, user_id: i64, group_id: i64) -> String {
        self.inner
            .pending_billing
            .user_group_cost(user_id, group_id)
            .to_string()
    }

    /// Handles a supported gateway route, returning `None` for control-plane
    /// and frontend paths that should be routed elsewhere.
    pub async fn try_handle(
        &self,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: Bytes,
        client_ip: Option<&str>,
    ) -> Option<Response> {
        if method == Method::GET && matches!(uri.path(), "/v1/usage" | "/antigravity/v1/usage") {
            return Some(self.handle_usage(&uri, &headers, client_ip).await);
        }
        let route = classify_route(&method, &uri)?;
        Some(
            self.handle_classified(route, &uri, headers, body, client_ip)
                .await,
        )
    }

    async fn handle_usage(
        &self,
        uri: &Uri,
        headers: &HeaderMap,
        client_ip: Option<&str>,
    ) -> Response {
        let auth = match self
            .authenticate(headers, uri.query(), client_ip, false)
            .await
        {
            Ok(auth) => auth,
            Err(error) => {
                let error = auth_gateway_error(&error);
                return (error.status(), Json(error.json(Protocol::Anthropic))).into_response();
            }
        };
        let Some(api_key) = auth.api_key.as_ref() else {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": {"message": "Invalid API key"}})),
            )
                .into_response();
        };
        let limits = match sqlx::query(
            r"
SELECT
    quota::text AS quota,
    quota_used::text AS quota_used,
    GREATEST(quota - quota_used, 0)::text AS quota_remaining,
    rate_limit_5h::text AS rate_limit_5h,
    rate_limit_1d::text AS rate_limit_1d,
    rate_limit_7d::text AS rate_limit_7d,
    usage_5h::text AS usage_5h,
    usage_1d::text AS usage_1d,
    usage_7d::text AS usage_7d,
    window_5h_start::text AS window_5h_start,
    window_1d_start::text AS window_1d_start,
    window_7d_start::text AS window_7d_start,
    expires_at::text AS expires_at
FROM api_keys
WHERE id = $1 AND deleted_at IS NULL
",
        )
        .bind(api_key.id)
        .fetch_optional(self.inner.repository.pool())
        .await
        {
            Ok(Some(row)) => row,
            Ok(None) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": {"message": "Invalid API key"}})),
                )
                    .into_response();
            }
            Err(error) => {
                tracing::error!(error = %error, "load API key usage limits");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": {"message": "Failed to get usage"}})),
                )
                    .into_response();
            }
        };
        let usage = load_usage_summary(self.inner.repository.pool(), api_key.id)
            .await
            .unwrap_or(Value::Null);
        Json(build_usage_payload(&auth, api_key, &limits, &usage)).into_response()
    }

    async fn runtime_policies(&self) -> Result<RuntimePolicies, GatewayError> {
        let repository = self.inner.repository.clone();
        let result = get_or_load_guarded(
            &self.inner.runtime_policy_cache,
            &self.inner.runtime_policy_flights,
            &self.inner.runtime_policy_cache_epoch,
            RUNTIME_POLICY_CACHE_KEY.to_owned(),
            || {
                let repository = repository.clone();
                async move {
                    RuntimePolicies::load(repository.pool())
                        .await
                        .map_err(|error| error.to_string())
                }
            },
        )
        .await;
        match result.as_ref() {
            Ok(policies) => Ok(policies.clone()),
            Err(error) => {
                tracing::error!(error = %error, "load gateway runtime policies");
                Err(GatewayError::new(
                    GatewayErrorKind::Unavailable,
                    "gateway policy service is temporarily unavailable",
                ))
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn handle_classified(
        &self,
        route: GatewayRoute,
        uri: &Uri,
        headers: HeaderMap,
        body: Bytes,
        client_ip: Option<&str>,
    ) -> Response {
        let auth = match self
            .authenticate(
                &headers,
                uri.query(),
                client_ip,
                self.inner.config.billing_enforced,
            )
            .await
        {
            Ok(auth) => auth,
            Err(error) => return gateway_error_response(&route, &auth_gateway_error(&error)),
        };
        if self.inner.config.billing_enforced
            && let Err(error) = self.validate_pending_billing(&auth)
        {
            return gateway_error_response(&route, &error);
        }
        let admission_id = uuid::Uuid::new_v4().to_string();
        let stable_billing_id = billing_request_id(&headers, &HeaderMap::new());
        let user_lease = match UserLease::try_acquire(
            auth.subject.user_id,
            auth.subject.concurrency,
            Arc::clone(&self.inner.user_in_flight),
        ) {
            Ok(lease) => lease,
            Err(error) => return gateway_error_response(&route, &error),
        };
        let global_user_lease = match self
            .inner
            .authority
            .acquire_user_lease(
                auth.subject.user_id,
                &admission_id,
                auth.subject.concurrency,
            )
            .await
        {
            Ok(Some(lease)) => lease,
            Ok(None) => {
                return gateway_error_response(
                    &route,
                    &GatewayError::new(GatewayErrorKind::RateLimit, "too many concurrent requests"),
                );
            }
            Err(error) => {
                return gateway_error_response(&route, &authority_gateway_error(&error));
            }
        };
        let metadata = match inspect_request(&route, &body) {
            Ok(metadata) => metadata,
            Err(error) => {
                return gateway_error_response(
                    &route,
                    &GatewayError::new(GatewayErrorKind::InvalidRequest, error.to_string()),
                );
            }
        };
        let policies = match self.runtime_policies().await {
            Ok(policies) => policies,
            Err(error) => return gateway_error_response(&route, &error),
        };
        if route_requires_content_moderation(route.kind) {
            match self
                .enforce_content_moderation_gate(&auth, &route, &metadata, &body)
                .await
            {
                Ok(ModerationOutcome::Allow) => {}
                Ok(ModerationOutcome::Block { status, message }) => {
                    return moderation_error_response(&route, status, &message);
                }
                Err(error) => return gateway_error_response(&route, &error),
            }
        }
        let platform = if uri.path().starts_with("/antigravity/") {
            "antigravity"
        } else {
            auth.group.as_ref().map_or_else(
                || protocol_platform(route.protocol),
                |group| group.platform.as_str(),
            )
        };
        if self.inner.config.billing_enforced
            && let Err(error) = validate_user_platform_quota(
                &auth,
                platform,
                &self.inner.pending_billing,
                now_unix_millis(),
            )
        {
            return gateway_error_response(&route, &error);
        }
        if self.inner.config.billing_enforced
            && let Err(error) = self.check_rpm(&auth, now_unix_millis())
        {
            return gateway_error_response(&route, &error);
        }
        if self.inner.config.billing_enforced
            && let Err(error) = self
                .inner
                .authority
                .acquire_rate_limits(&auth, &admission_id)
                .await
        {
            return gateway_error_response(&route, &authority_gateway_error(&error));
        }
        if let Some(message) = unsupported_platform_message(route.kind, platform) {
            return gateway_error_response(
                &route,
                &GatewayError::new(GatewayErrorKind::NotFound, message),
            );
        }
        let Some(api_key_id) = auth.api_key.as_ref().map(|api_key| api_key.id) else {
            return gateway_error_response(
                &route,
                &GatewayError::new(
                    GatewayErrorKind::Internal,
                    "authenticated request has no API key context",
                ),
            );
        };
        let api_key_lease =
            ApiKeyLease::acquire(api_key_id, Arc::clone(&self.inner.api_key_in_flight));
        let mut attempted_accounts = HashSet::new();
        let mut last_failure: Option<(GatewayRoute, GatewayError)> = None;
        let mut billing_reservation: Option<BillingReservation> = None;
        loop {
            let selection = match self
                .select_account(
                    &auth,
                    platform,
                    &metadata,
                    &attempted_accounts,
                    &admission_id,
                )
                .await
            {
                Ok(selection) => selection,
                Err(error) => {
                    return last_failure.map_or_else(
                        || gateway_error_response(&route, &error),
                        |(failed_route, failure)| gateway_error_response(&failed_route, &failure),
                    );
                }
            };
            attempted_accounts.insert(selection.account.id);
            match super::web_search::try_emulate(
                self.inner.repository.pool(),
                &route,
                &body,
                &selection.account,
                selection.channel_policy.as_ref(),
            )
            .await
            {
                Ok(Some(response)) => {
                    self.queue_touch(&auth, &selection.account);
                    return response;
                }
                Ok(None) => {}
                Err(error) => match error.kind() {
                    super::web_search::WebSearchFailureKind::InvalidRequest => {
                        tracing::debug!(
                            error = error.internal_message(),
                            "reject invalid web search emulation request"
                        );
                        return gateway_error_response(
                            &route,
                            &GatewayError::new(
                                GatewayErrorKind::InvalidRequest,
                                error.public_message(),
                            ),
                        );
                    }
                    super::web_search::WebSearchFailureKind::AccountProxy => {
                        tracing::warn!(
                            account_id = selection.account.id,
                            error = error.internal_message(),
                            "web search account proxy failed; trying another account"
                        );
                        self.record_account_transport_failure(
                            selection.account.id,
                            "account proxy is unavailable",
                        )
                        .await;
                        last_failure = Some((
                            route.clone(),
                            GatewayError::new(
                                GatewayErrorKind::Unavailable,
                                error.public_message(),
                            ),
                        ));
                        continue;
                    }
                    super::web_search::WebSearchFailureKind::Unavailable => {
                        tracing::error!(
                            account_id = selection.account.id,
                            error = error.internal_message(),
                            "web search emulation failed"
                        );
                        return gateway_error_response(
                            &route,
                            &GatewayError::new(
                                GatewayErrorKind::Unavailable,
                                error.public_message(),
                            ),
                        );
                    }
                },
            }
            let (client_route, mapped_body) =
                apply_model_mapping(route.clone(), &metadata, &body, &selection);
            let mapped_body = super::web_search::filter_history_blocks(
                &mapped_body,
                !selection.account.platform.eq_ignore_ascii_case("anthropic"),
            )
            .unwrap_or(mapped_body);
            if let Err(error) = validate_upstream_adapter(
                &selection.account.platform,
                &selection.account.account_type,
            ) {
                last_failure = Some((
                    client_route,
                    GatewayError::new(GatewayErrorKind::Unavailable, error.to_string()),
                ));
                continue;
            }
            let transformed = match prepare_protocol_request_for_account(
                &client_route,
                &selection.account.platform,
                &metadata,
                &mapped_body,
                should_use_openai_responses(&selection.account),
                selection.account.platform.eq_ignore_ascii_case("openai")
                    && selection.account.account_type.eq_ignore_ascii_case("oauth"),
            ) {
                Ok(transformed) => transformed,
                Err(error) => {
                    let kind = match error.stage() {
                        TransformStage::InvalidRequest => GatewayErrorKind::InvalidRequest,
                        TransformStage::Unsupported => GatewayErrorKind::Unavailable,
                        TransformStage::InvalidResponse => GatewayErrorKind::Internal,
                    };
                    let failure = GatewayError::new(kind, error.to_string());
                    if error.stage() == TransformStage::Unsupported {
                        last_failure = Some((client_route, failure));
                        continue;
                    }
                    return gateway_error_response(&client_route, &failure);
                }
            };
            let upstream_route = transformed.route;
            let mut outbound_body = transformed.body;
            let mut bridge = transformed.bridge;
            let upstream_metadata = match inspect_request(&upstream_route, &outbound_body) {
                Ok(metadata) => metadata,
                Err(error) => {
                    tracing::error!(error = %error, "inspect converted gateway request");
                    return gateway_error_response(
                        &client_route,
                        &GatewayError::new(
                            GatewayErrorKind::Internal,
                            "converted request is invalid",
                        ),
                    );
                }
            };
            let mut policy_headers = headers.clone();
            if upstream_route.protocol == Protocol::Anthropic
                && let Err(message) = policies.beta.apply(
                    &mut policy_headers,
                    &selection.account.account_type,
                    upstream_metadata.model.as_deref().unwrap_or_default(),
                )
            {
                return gateway_error_response(
                    &client_route,
                    &GatewayError::new(GatewayErrorKind::InvalidRequest, message),
                );
            }
            let prepared_billing = if self.inner.config.billing_enforced {
                match prepare_billing_context(
                    &self.inner.billing_observer,
                    &auth,
                    &selection,
                    &upstream_route,
                    &upstream_metadata,
                    &outbound_body,
                    &stable_billing_id,
                ) {
                    Ok(context) => context,
                    Err(error) => return gateway_error_response(&client_route, &error),
                }
            } else {
                None
            };
            if billing_reservation.is_none()
                && let Some(context) = prepared_billing.as_ref()
            {
                billing_reservation = match self
                    .inner
                    .authority
                    .begin_billing(
                        &auth,
                        selection.account.id,
                        &context.platform,
                        &context.request_id,
                        &context.request_fingerprint,
                    )
                    .await
                {
                    Ok(reservation) => Some(reservation),
                    Err(error) => {
                        return gateway_error_response(
                            &client_route,
                            &authority_gateway_error(&error),
                        );
                    }
                };
            }
            let (base_url, credential) = match self
                .resolve_upstream_credentials(&selection.account, upstream_route.protocol)
                .await
            {
                Ok(settings) => settings,
                Err(error) => {
                    last_failure = Some((
                        client_route,
                        GatewayError::new(GatewayErrorKind::Unavailable, error),
                    ));
                    continue;
                }
            };
            let plan = match build_upstream_request(
                &upstream_route,
                &upstream_metadata,
                &base_url,
                &credential,
                &policy_headers,
            ) {
                Ok(plan) => plan,
                Err(error) => {
                    last_failure = Some((
                        client_route,
                        GatewayError::new(GatewayErrorKind::Unavailable, error.to_string()),
                    ));
                    continue;
                }
            };
            let AdaptedRequest {
                plan,
                body: adapted_body,
                stream_wire,
                normalize_wrapped_gemini,
            } = match adapt_request(
                &selection.account,
                &upstream_route,
                &upstream_metadata,
                plan,
                outbound_body,
            ) {
                Ok(adapted) => adapted,
                Err(error) => {
                    last_failure = Some((
                        client_route,
                        GatewayError::new(GatewayErrorKind::Unavailable, error.to_string()),
                    ));
                    continue;
                }
            };
            outbound_body = adapted_body;
            if normalize_wrapped_gemini {
                bridge = bridge.normalize_wrapped_gemini();
            }

            let upstream_client = match self.upstream_client(&selection.account).await {
                Ok(client) => client,
                Err(error) => {
                    self.record_account_transport_failure(
                        selection.account.id,
                        "account upstream transport is unavailable",
                    )
                    .await;
                    last_failure = Some((client_route, error));
                    continue;
                }
            };
            let request_started = Instant::now();
            let upstream_method = plan.method.clone();
            let upstream_url = plan.url.clone();
            let upstream_request_headers = plan.headers.clone();
            let mut upstream = Some(
                match upstream_client
                    .request(upstream_method.clone(), upstream_url.clone())
                    .headers(upstream_request_headers.clone())
                    .body(outbound_body.clone())
                    .send()
                    .await
                {
                    Ok(response) => response,
                    Err(error) => {
                        tracing::warn!(
                            account_id = selection.account.id,
                            error = %error,
                            "gateway upstream request failed; trying another account"
                        );
                        self.record_account_transport_failure(
                            selection.account.id,
                            "upstream transport failed",
                        )
                        .await;
                        last_failure = Some((
                            client_route,
                            GatewayError::new(
                                GatewayErrorKind::Unavailable,
                                "upstream service is unavailable",
                            ),
                        ));
                        continue;
                    }
                },
            );

            self.queue_touch(&auth, &selection.account);
            let mut status = upstream
                .as_ref()
                .expect("the initial upstream response is present")
                .status();
            let mut upstream_headers = upstream
                .as_ref()
                .expect("the initial upstream response is present")
                .headers()
                .clone();
            let mut buffered_error_body = None;
            if status == StatusCode::BAD_REQUEST {
                let first_error_body = read_limited(
                    upstream
                        .take()
                        .expect("the initial bad request response is present"),
                    self.inner.config.max_upstream_error_bytes,
                )
                .await;
                if let Some(rectified) = policies.rectifier.rectify(
                    &selection.account.account_type,
                    upstream_route.protocol,
                    &first_error_body,
                    &outbound_body,
                ) {
                    tracing::warn!(
                        account_id = selection.account.id,
                        rectification = rectified.kind.as_str(),
                        "gateway upstream rejected request; retrying once with rectified body"
                    );
                    outbound_body = rectified.body;
                    let retry = match upstream_client
                        .request(upstream_method, upstream_url)
                        .headers(upstream_request_headers)
                        .body(outbound_body.clone())
                        .send()
                        .await
                    {
                        Ok(response) => response,
                        Err(error) => {
                            tracing::warn!(
                                account_id = selection.account.id,
                                rectification = rectified.kind.as_str(),
                                error = %error,
                                "gateway rectifier retry transport failed"
                            );
                            self.record_account_transport_failure(
                                selection.account.id,
                                "upstream rectifier retry transport failed",
                            )
                            .await;
                            last_failure = Some((
                                client_route,
                                GatewayError::new(
                                    GatewayErrorKind::Unavailable,
                                    "upstream service is unavailable",
                                ),
                            ));
                            continue;
                        }
                    };
                    status = retry.status();
                    upstream_headers = retry.headers().clone();
                    upstream = Some(retry);
                } else {
                    buffered_error_body = Some(first_error_body);
                }
            }
            if !status.is_success() {
                let request_id = upstream_headers
                    .get("x-request-id")
                    .or_else(|| upstream_headers.get("x-amzn-requestid"))
                    .and_then(|value| value.to_str().ok())
                    .map(ToOwned::to_owned);
                let error_body = match buffered_error_body {
                    Some(body) => body,
                    None => {
                        read_limited(
                            upstream
                                .take()
                                .expect("an unbuffered upstream error response is present"),
                            self.inner.config.max_upstream_error_bytes,
                        )
                        .await
                    }
                };
                let error = GatewayError::from_upstream(status, &error_body, request_id.as_deref());
                if let Some(decision) =
                    policies.match_error(&selection.account.platform, status, &error_body)
                {
                    if policies.ops_monitoring_enabled && !decision.skip_monitoring {
                        self.record_ops_upstream_error(
                            &auth,
                            &selection.account,
                            &admission_id,
                            uri.path(),
                            upstream_metadata.model.as_deref(),
                            metadata.stream,
                            status,
                            &error,
                            retry_after_seconds(&upstream_headers),
                            elapsed_millis(request_started),
                        )
                        .await;
                    }
                    return passthrough_error_response(&client_route, &error, decision);
                }
                if policies.ops_monitoring_enabled {
                    self.record_ops_upstream_error(
                        &auth,
                        &selection.account,
                        &admission_id,
                        uri.path(),
                        upstream_metadata.model.as_deref(),
                        metadata.stream,
                        status,
                        &error,
                        retry_after_seconds(&upstream_headers),
                        elapsed_millis(request_started),
                    )
                    .await;
                }
                self.record_account_http_failure(
                    selection.account.id,
                    status,
                    &upstream_headers,
                    &error.message,
                    &policies,
                )
                .await;
                tracing::warn!(
                    account_id = selection.account.id,
                    upstream_status = status.as_u16(),
                    "gateway upstream rejected request; trying another account"
                );
                last_failure = Some((client_route, error));
                continue;
            }
            let upstream = upstream.expect("a successful upstream response is present");

            let response_mode = response_mode_from_headers(plan.response_mode, &upstream_headers);
            let usage_provider = usage_provider(upstream_route.protocol);
            let billing_context = prepared_billing.map(|context| {
                (
                    context.finish(response_mode),
                    billing_reservation
                        .take()
                        .expect("token-billed requests reserve before upstream dispatch"),
                )
            });
            match response_mode {
                ResponseMode::ServerSentEvents => {
                    let (observer, reservation) =
                        billing_context.map_or((None, None), |(context, reservation)| {
                            (
                                Some(
                                    self.inner
                                        .billing_observer
                                        .start_sse(usage_provider, context),
                                ),
                                Some(reservation),
                            )
                        });
                    let timeout_context = StreamTimeoutContext {
                        runtime: self.clone(),
                        account_id: selection.account.id,
                        model: upstream_metadata.model.clone().unwrap_or_default(),
                        settings: policies.stream_timeout.clone(),
                    };
                    return stream_response(
                        status,
                        upstream_headers,
                        upstream,
                        bridge.requires_conversion().then(|| bridge.stream_bridge()),
                        stream_wire,
                        GatewayLeases {
                            _account: selection.lease,
                            _global_account: Some(selection.global_lease),
                            _api_key: api_key_lease,
                            _user: user_lease,
                            _global_user: Some(global_user_lease),
                        },
                        StreamBilling {
                            observer,
                            reservation,
                            writes: self.inner.billing_writes.clone(),
                            route: client_route.kind,
                            request_started,
                            backpressure: self.inner.billing_backpressure.clone(),
                            idle_timeout: self.inner.config.stream_idle_timeout,
                            timeout_context,
                        },
                    );
                }
                ResponseMode::Buffered => {
                    let bytes =
                        read_limited(upstream, self.inner.config.max_buffered_response_bytes).await;
                    if bytes.len() >= self.inner.config.max_buffered_response_bytes {
                        return gateway_error_response(
                            &client_route,
                            &GatewayError::new(
                                GatewayErrorKind::Upstream,
                                "upstream response exceeded the configured limit",
                            ),
                        );
                    }
                    let converted_bytes = if bridge.requires_conversion() {
                        match bridge.transform_response(&bytes) {
                            Ok(bytes) => Some(bytes),
                            Err(error) => {
                                tracing::warn!(error = %error, "convert gateway upstream response");
                                return gateway_error_response(
                                    &client_route,
                                    &GatewayError::new(
                                        GatewayErrorKind::Upstream,
                                        error.to_string(),
                                    ),
                                );
                            }
                        }
                    } else {
                        None
                    };
                    if let Some((context, mut reservation)) = billing_context {
                        match self.inner.billing_observer.observe_json(
                            usage_provider,
                            context,
                            &bytes,
                            Some(elapsed_millis(request_started)),
                        ) {
                            Ok(event) => {
                                if let Err(error) = reservation.stage(&event).await {
                                    tracing::error!(error = %error, "stage durable buffered billing");
                                    return gateway_error_response(
                                        &client_route,
                                        &GatewayError::new(
                                            GatewayErrorKind::Unavailable,
                                            "billing service is temporarily unavailable",
                                        ),
                                    );
                                }
                                if let Err(error) = self.inner.billing_writes.enqueue(event).await {
                                    tracing::error!(error = %error, "billing write-behind queue is closed");
                                    return gateway_error_response(
                                        &client_route,
                                        &GatewayError::new(
                                            GatewayErrorKind::Unavailable,
                                            "billing service is temporarily unavailable",
                                        ),
                                    );
                                }
                            }
                            Err(error) => {
                                tracing::error!(error = %error, "observe buffered gateway billing");
                                return gateway_error_response(
                                    &client_route,
                                    &GatewayError::new(
                                        GatewayErrorKind::Internal,
                                        "failed to process upstream usage",
                                    ),
                                );
                            }
                        }
                    }
                    let bytes = converted_bytes.unwrap_or(bytes);
                    if bridge.requires_conversion() {
                        normalize_converted_response_headers(&mut upstream_headers);
                    }
                    return buffered_response(status, upstream_headers, bytes);
                }
            }
        }
    }

    async fn authenticate(
        &self,
        headers: &HeaderMap,
        raw_query: Option<&str>,
        client_ip: Option<&str>,
        enforce_billing: bool,
    ) -> Result<AuthContext, AuthError> {
        let extracted = extract_api_key(headers, raw_query)?;
        let key = extracted.key;
        if self.inner.auth_negative_cache.get(&key).is_some() {
            return Err(AuthError::InvalidApiKey);
        }
        let observed_epoch = self.inner.auth_cache_epoch.load(Ordering::Acquire);
        let repository = self.inner.repository.clone();
        let shared = get_or_load_guarded(
            &self.inner.auth_cache,
            &self.inner.auth_flights,
            &self.inner.auth_cache_epoch,
            key.clone(),
            || {
                let repository = repository.clone();
                let lookup_key = key.clone();
                async move {
                    repository
                        .find_api_key_for_auth(&lookup_key)
                        .await
                        .map_err(|error| error.to_string())?
                        .ok_or_else(|| "api key was not found".to_owned())
                }
            },
        )
        .await;
        let snapshot = match shared.as_ref() {
            Ok(snapshot) => {
                self.inner.auth_negative_cache.remove(&key);
                snapshot.clone()
            }
            Err(message) if message == "api key was not found" => {
                self.inner.auth_negative_cache.insert(key.clone(), ());
                if self.inner.auth_cache_epoch.load(Ordering::Acquire) != observed_epoch {
                    self.inner.auth_negative_cache.remove(&key);
                }
                return Err(AuthError::InvalidApiKey);
            }
            Err(message) => {
                tracing::error!(error = %message, "API key L1 loader failed");
                return Err(AuthError::Repository(
                    crate::repository::RepositoryError::Database(sqlx::Error::Protocol(
                        message.clone(),
                    )),
                ));
            }
        };
        validate_api_key_snapshot(&snapshot, client_ip, now_unix_millis(), enforce_billing)?;
        let ApiKeyAuthRecord {
            api_key,
            user,
            group,
            subscription,
            platform_quotas,
        } = snapshot;
        let user = user.ok_or(AuthError::UserNotFound)?;
        Ok(AuthContext {
            subject: AuthSubject {
                user_id: user.id,
                concurrency: user.concurrency,
            },
            role: user.role.clone(),
            user,
            api_key: Some(api_key),
            group,
            subscription,
            platform_quotas,
            jwt_claims: None,
        })
    }

    async fn enforce_content_moderation_gate(
        &self,
        auth: &AuthContext,
        route: &GatewayRoute,
        metadata: &RequestMetadata,
        body: &[u8],
    ) -> Result<ModerationOutcome, GatewayError> {
        let key = CONTENT_MODERATION_SETTING_KEY.to_owned();
        let repository = self.inner.repository.clone();
        let shared = get_or_load_guarded(
            &self.inner.moderation_cache,
            &self.inner.moderation_flights,
            &self.inner.moderation_cache_epoch,
            key,
            || {
                let repository = repository.clone();
                async move { ModerationConfig::load(repository.pool()).await }
            },
        )
        .await;
        let config = match shared.as_ref() {
            Ok(config) => config.clone(),
            Err(error) => {
                tracing::error!(error = %error, "load content moderation gateway setting");
                return Err(GatewayError::new(
                    GatewayErrorKind::Unavailable,
                    "content moderation configuration is unavailable",
                ));
            }
        };
        super::moderation::enforce(
            &self.inner.client,
            self.inner.repository.pool(),
            config,
            auth,
            route,
            metadata,
            body,
        )
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "content moderation failed closed");
            GatewayError::new(
                GatewayErrorKind::Unavailable,
                "content moderation service is unavailable",
            )
        })
    }

    fn validate_pending_billing(&self, auth: &AuthContext) -> Result<(), GatewayError> {
        let api_key = auth.api_key.as_ref().ok_or_else(|| {
            GatewayError::new(
                GatewayErrorKind::Internal,
                "authenticated request has no API key context",
            )
        })?;
        let quota = parse_decimal_field(&api_key.quota, "API key quota")?;
        if quota > Decimal::ZERO {
            let durable_usage = parse_decimal_field(&api_key.quota_used, "API key quota usage")?;
            let effective_usage = self
                .inner
                .pending_billing
                .effective_api_key_usage(api_key.id, durable_usage)
                .map_err(|error| billing_arithmetic_error("API key quota", &error))?;
            if effective_usage >= quota {
                return Err(GatewayError::new(
                    GatewayErrorKind::RateLimit,
                    "API key quota exhausted",
                ));
            }
        }

        validate_api_key_rate_windows(api_key, &self.inner.pending_billing, now_unix_millis())?;

        if auth
            .group
            .as_ref()
            .is_some_and(GroupRecord::is_subscription_type)
        {
            validate_pending_subscription(auth, &self.inner.pending_billing, now_unix_millis())?;
        } else {
            let durable_balance = parse_decimal_field(&auth.user.balance, "user balance")?;
            let effective_balance = self
                .inner
                .pending_billing
                .effective_user_balance(auth.user.id, durable_balance)
                .map_err(|error| billing_arithmetic_error("user balance", &error))?;
            if effective_balance <= Decimal::ZERO {
                return Err(GatewayError::new(
                    GatewayErrorKind::Permission,
                    "insufficient balance",
                ));
            }
        }
        Ok(())
    }

    fn check_rpm(&self, auth: &AuthContext, now_unix_ms: i64) -> Result<(), GatewayError> {
        let api_key = auth.api_key.as_ref().ok_or_else(|| {
            GatewayError::new(
                GatewayErrorKind::Internal,
                "authenticated request has no API key context",
            )
        })?;
        let mut rpm = lock(&self.inner.rpm);
        rpm.rotate(now_unix_ms.div_euclid(RPM_WINDOW_MILLIS));

        if let Some(group) = auth.group.as_ref() {
            let limit = api_key.group_rpm_override.unwrap_or(group.rpm_limit);
            if limit > 0 {
                let count = increment_counter(&mut rpm.by_user_group, (auth.user.id, group.id));
                if count > u32::try_from(limit).unwrap_or(u32::MAX) {
                    return Err(GatewayError::new(
                        GatewayErrorKind::RateLimit,
                        "group requests-per-minute limit exceeded",
                    ));
                }
            }
        }

        if auth.user.rpm_limit > 0 {
            let count = increment_counter(&mut rpm.by_user, auth.user.id);
            if count > u32::try_from(auth.user.rpm_limit).unwrap_or(u32::MAX) {
                return Err(GatewayError::new(
                    GatewayErrorKind::RateLimit,
                    "user requests-per-minute limit exceeded",
                ));
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    async fn select_account(
        &self,
        auth: &AuthContext,
        platform: &str,
        metadata: &RequestMetadata,
        excluded: &HashSet<i64>,
        admission_id: &str,
    ) -> Result<AccountSelection, GatewayError> {
        let partition = AccountPartition {
            platform: platform.to_ascii_lowercase(),
            group_id: auth.api_key.as_ref().and_then(|key| key.group_id),
        };
        let channel_policy = if let Some(group_id) = partition.group_id {
            let repository = self.inner.repository.clone();
            let load_partition = partition.clone();
            let shared = get_or_load_guarded(
                &self.inner.channel_cache,
                &self.inner.channel_flights,
                &self.inner.account_cache_epoch,
                partition.clone(),
                || {
                    let repository = repository.clone();
                    let load_partition = load_partition.clone();
                    async move {
                        repository
                            .find_channel_policy(group_id, &load_partition.platform)
                            .await
                            .map_err(|error| error.to_string())
                    }
                },
            )
            .await;
            match shared.as_ref() {
                Ok(policy) => policy.clone(),
                Err(error) => {
                    tracing::error!(error = %error, "channel policy L1 loader failed");
                    return Err(GatewayError::new(
                        GatewayErrorKind::Unavailable,
                        "channel policy is temporarily unavailable",
                    ));
                }
            }
        } else {
            None
        };
        let requested_model = metadata.model.clone();
        let channel_mapped_model =
            apply_channel_model_mapping(channel_policy.as_ref(), requested_model.as_deref());
        if let Some(policy) = channel_policy.as_ref()
            && policy.restrict_models
            && !billing_source(policy).eq_ignore_ascii_case("upstream")
            && restriction_model(
                policy,
                requested_model.as_deref(),
                channel_mapped_model.as_deref(),
                None,
            )
            .is_some_and(|model| find_channel_pricing(policy, model).is_none())
        {
            return Err(channel_model_restricted_error());
        }
        let repository = self.inner.repository.clone();
        let load_partition = partition.clone();
        let shared = get_or_load_guarded(
            &self.inner.account_cache,
            &self.inner.account_flights,
            &self.inner.account_cache_epoch,
            partition,
            || {
                let repository = repository.clone();
                let load_partition = load_partition.clone();
                async move {
                    repository
                        .list_schedulable_accounts(
                            &load_partition.platform,
                            load_partition.group_id,
                            now_unix_millis(),
                        )
                        .await
                        .map_err(|error| error.to_string())
                }
            },
        )
        .await;
        let accounts = match shared.as_ref() {
            Ok(accounts) => accounts,
            Err(error) => {
                tracing::error!(error = %error, "account L1 loader failed");
                return Err(GatewayError::new(
                    GatewayErrorKind::Unavailable,
                    "account scheduler is temporarily unavailable",
                ));
            }
        };
        let mut upstream_restricted = false;
        let mut candidates = Vec::new();
        for account in accounts {
            if excluded.contains(&account.id) {
                continue;
            }
            match account_has_effective_quota(account, &self.inner.pending_billing) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(error) => {
                    tracing::warn!(account_id = account.id, error = %error, "skip account with invalid quota state");
                    continue;
                }
            }
            let mapped = match mapped_model(account, channel_mapped_model.as_deref()) {
                ModelMappingDecision::Allowed(mapped) => mapped,
                ModelMappingDecision::Unsupported => continue,
            };
            if let Some(policy) = channel_policy.as_ref()
                && policy.restrict_models
                && billing_source(policy).eq_ignore_ascii_case("upstream")
                && mapped
                    .as_deref()
                    .is_some_and(|model| find_channel_pricing(policy, model).is_none())
            {
                upstream_restricted = true;
                continue;
            }
            candidates.push((account.clone(), mapped));
        }
        if candidates.is_empty() && upstream_restricted {
            return Err(channel_model_restricted_error());
        }
        candidates.sort_by_key(|(account, _)| (account.priority, account.id));

        {
            let in_flight = lock(&self.inner.in_flight);
            candidates.sort_by_key(|(account, _)| {
                let current = in_flight.get(&account.id).copied().unwrap_or_default();
                (account.priority, current, account.id)
            });
        }
        for (account, mapped_model) in candidates {
            let lease = {
                let mut in_flight = lock(&self.inner.in_flight);
                let current = in_flight.get(&account.id).copied().unwrap_or_default();
                if account.concurrency > 0
                    && current >= u32::try_from(account.concurrency).unwrap_or(u32::MAX)
                {
                    None
                } else {
                    in_flight.insert(account.id, current.saturating_add(1));
                    Some(AccountLease {
                        account_id: account.id,
                        in_flight: Arc::clone(&self.inner.in_flight),
                    })
                }
            };
            let Some(lease) = lease else { continue };
            match self
                .inner
                .authority
                .acquire_account_lease(account.id, admission_id, account.concurrency)
                .await
            {
                Ok(Some(global_lease)) => {
                    return Ok(AccountSelection {
                        account,
                        requested_model,
                        channel_mapped_model,
                        mapped_model,
                        channel_policy,
                        lease,
                        global_lease,
                    });
                }
                Ok(None) => drop(lease),
                Err(error) => return Err(authority_gateway_error(&error)),
            }
        }
        Err(GatewayError::new(
            GatewayErrorKind::Unavailable,
            "no upstream account is currently available",
        ))
    }

    async fn record_account_transport_failure(&self, account_id: i64, reason: &str) {
        let reason = sanitized_failure_reason(reason);
        if let Err(error) = sqlx::query(
            r"
UPDATE accounts
SET temp_unschedulable_until = GREATEST(
        COALESCE(temp_unschedulable_until, NOW()),
        NOW() + make_interval(secs => 30)
    ),
    temp_unschedulable_reason = $2,
    error_message = $2,
    updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL
",
        )
        .bind(account_id)
        .bind(reason)
        .execute(self.inner.repository.pool())
        .await
        {
            tracing::error!(account_id, error = %error, "persist upstream transport failure");
        }
        self.invalidate_account_selection_cache();
    }

    async fn record_account_http_failure(
        &self,
        account_id: i64,
        status: StatusCode,
        headers: &HeaderMap,
        reason: &str,
        policies: &RuntimePolicies,
    ) {
        let reason = sanitized_failure_reason(reason);
        let retry_seconds = policies.failure_cooldown_seconds(status, retry_after_seconds(headers));
        let Some(retry_seconds) = retry_seconds else {
            tracing::info!(
                account_id,
                upstream_status = status.as_u16(),
                "dynamic cooldown policy left account schedulable"
            );
            return;
        };
        let result = if matches!(status.as_u16(), 401 | 403) {
            Some(
                sqlx::query(
                    r"
UPDATE accounts
SET status = 'error', schedulable = FALSE, error_message = $2,
    temp_unschedulable_until = NULL, temp_unschedulable_reason = NULL,
    updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL
",
                )
                .bind(account_id)
                .bind(reason)
                .execute(self.inner.repository.pool())
                .await,
            )
        } else if status == StatusCode::TOO_MANY_REQUESTS {
            Some(
                sqlx::query(
                    r"
UPDATE accounts
SET rate_limit_reset_at = GREATEST(
        COALESCE(rate_limit_reset_at, NOW()),
        NOW() + make_interval(secs => $2)
    ),
    temp_unschedulable_until = GREATEST(
        COALESCE(temp_unschedulable_until, NOW()),
        NOW() + make_interval(secs => $2)
    ),
    temp_unschedulable_reason = $3,
    error_message = $3,
    updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL
",
                )
                .bind(account_id)
                .bind(retry_seconds)
                .bind(reason)
                .execute(self.inner.repository.pool())
                .await,
            )
        } else if status.is_server_error() || status.as_u16() == 529 {
            Some(
                sqlx::query(
                    r"
UPDATE accounts
SET overload_until = GREATEST(
        COALESCE(overload_until, NOW()),
        NOW() + make_interval(secs => $2)
    ),
    temp_unschedulable_until = GREATEST(
        COALESCE(temp_unschedulable_until, NOW()),
        NOW() + make_interval(secs => $2)
    ),
    temp_unschedulable_reason = $3,
    error_message = $3,
    updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL
",
                )
                .bind(account_id)
                .bind(retry_seconds)
                .bind(reason)
                .execute(self.inner.repository.pool())
                .await,
            )
        } else {
            // A non-success response still leaves the current request free to
            // fail over, but deterministic client errors do not poison the
            // account for later requests.
            None
        };
        if let Some(Err(error)) = result {
            tracing::error!(
                account_id,
                upstream_status = status.as_u16(),
                error = %error,
                "persist upstream HTTP failure"
            );
        }
        self.invalidate_account_selection_cache();
    }

    #[allow(clippy::too_many_arguments)]
    async fn record_ops_upstream_error(
        &self,
        auth: &AuthContext,
        account: &AccountRecord,
        request_id: &str,
        request_path: &str,
        model: Option<&str>,
        stream: bool,
        status: StatusCode,
        error: &GatewayError,
        retry_after_seconds: Option<i32>,
        duration_ms: i32,
    ) {
        let result = sqlx::query(
            r"
INSERT INTO ops_error_logs (
    request_id, user_id, api_key_id, account_id, group_id,
    platform, model, request_path, stream,
    error_phase, error_type, severity, status_code,
    error_message, error_source, error_owner,
    upstream_status_code, upstream_error_message,
    retry_after_seconds, duration_ms, is_retryable
) VALUES (
    $1,$2,$3,$4,$5,$6,$7,$8,$9,
    'upstream','upstream_error','P2',$10,
    $11,'upstream','provider',$10,$11,$12,$13,$14
)
",
        )
        .bind(request_id)
        .bind(auth.user.id)
        .bind(auth.api_key.as_ref().map(|api_key| api_key.id))
        .bind(account.id)
        .bind(auth.api_key.as_ref().and_then(|api_key| api_key.group_id))
        .bind(&account.platform)
        .bind(model)
        .bind(request_path)
        .bind(stream)
        .bind(i32::from(status.as_u16()))
        .bind(sanitized_failure_reason(&error.message))
        .bind(retry_after_seconds)
        .bind(duration_ms)
        .bind(status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error())
        .execute(self.inner.repository.pool())
        .await;
        if let Err(error) = result {
            tracing::error!(account_id = account.id, error = %error, "record gateway upstream error");
        }
    }

    async fn record_stream_timeout(
        &self,
        account_id: i64,
        model: &str,
        settings: &StreamTimeoutSettings,
    ) {
        if !settings.tracks_account_health() {
            return;
        }
        match apply_stream_timeout_policy(self.inner.repository.pool(), account_id, model, settings)
            .await
        {
            Ok(triggered) => {
                if triggered {
                    self.invalidate_account_selection_cache();
                }
            }
            Err(error) => {
                tracing::error!(account_id, error = %error, "apply stream timeout policy");
            }
        }
    }

    async fn upstream_client(
        &self,
        account: &AccountRecord,
    ) -> Result<reqwest::Client, GatewayError> {
        let tls = AccountTlsFingerprint::from_account(account).map_err(|message| {
            tracing::warn!(account_id = account.id, error = %message, "account TLS fingerprint setting is invalid");
            GatewayError::new(
                GatewayErrorKind::Unavailable,
                "account TLS fingerprint configuration is invalid",
            )
        })?;
        let Some(tls) = tls else {
            return self.standard_upstream_client(account);
        };
        let proxy = self.usable_account_proxy(account)?;
        let key = TlsClientKey {
            profile_id: tls.profile_id,
            proxy: proxy.map(ProxyClientKey::from),
        };
        if let Some(client) = self.inner.tls_fingerprint_clients.get(&key) {
            return Ok(client);
        }
        let profile = TlsFingerprintProfile::load(self.inner.repository.pool(), tls.profile_id)
            .await
            .and_then(TlsFingerprintProfile::build)
            .map_err(|message| {
                tracing::warn!(
                    account_id = account.id,
                    tls_profile_id = tls.profile_id,
                    error = %message,
                    "account TLS fingerprint profile is unavailable"
                );
                GatewayError::new(
                    GatewayErrorKind::Unavailable,
                    "account TLS fingerprint profile is unavailable",
                )
            })?;
        for limitation in &profile.limitations {
            tracing::warn!(
                account_id = account.id,
                tls_profile_id = profile.profile_id,
                tls_profile_name = %profile.profile_name,
                limitation = %limitation,
                "TLS fingerprint capability limitation"
            );
        }
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .tls_backend_preconfigured(profile.config)
            .connect_timeout(self.inner.config.connect_timeout)
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_keepalive(Duration::from_secs(30));
        if let Some(proxy) = proxy {
            builder = builder.proxy(configured_proxy(account.id, proxy)?);
        }
        let client = builder.build().map_err(|error| {
            tracing::warn!(
                account_id = account.id,
                tls_profile_id = tls.profile_id,
                error = %error,
                "cannot build TLS fingerprint upstream client"
            );
            GatewayError::new(
                GatewayErrorKind::Unavailable,
                "account TLS fingerprint profile is unavailable",
            )
        })?;
        self.inner
            .tls_fingerprint_clients
            .insert(key, client.clone());
        Ok(client)
    }

    fn standard_upstream_client(
        &self,
        account: &AccountRecord,
    ) -> Result<reqwest::Client, GatewayError> {
        let Some(proxy_id) = account.proxy_id else {
            return Ok(self.inner.client.clone());
        };
        let proxy = self.usable_account_proxy(account)?.ok_or_else(|| {
            tracing::warn!(
                account_id = account.id,
                proxy_id,
                "account proxy is unavailable"
            );
            GatewayError::new(
                GatewayErrorKind::Unavailable,
                "account proxy is unavailable",
            )
        })?;
        let key = ProxyClientKey::from(proxy);
        if let Some(client) = self.inner.proxy_clients.get(&key) {
            return Ok(client);
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .proxy(configured_proxy(account.id, proxy)?)
            .connect_timeout(self.inner.config.connect_timeout)
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_keepalive(Duration::from_secs(30))
            .build()
            .map_err(|error| {
                tracing::warn!(account_id = account.id, proxy_id, error = %error, "cannot build account proxy client");
                GatewayError::new(
                    GatewayErrorKind::Unavailable,
                    "account proxy configuration is invalid",
                )
            })?;
        self.inner.proxy_clients.insert(key, client.clone());
        Ok(client)
    }

    #[allow(clippy::unused_self)]
    fn usable_account_proxy<'a>(
        &self,
        account: &'a AccountRecord,
    ) -> Result<Option<&'a AccountProxyRecord>, GatewayError> {
        let Some(proxy_id) = account.proxy_id else {
            return Ok(None);
        };
        let proxy = account.proxy.as_ref().ok_or_else(|| {
            tracing::warn!(
                account_id = account.id,
                proxy_id,
                "account proxy is unavailable"
            );
            GatewayError::new(
                GatewayErrorKind::Unavailable,
                "account proxy is unavailable",
            )
        })?;
        if !proxy.is_usable_at(now_unix_millis()) {
            return Err(GatewayError::new(
                GatewayErrorKind::Unavailable,
                "account proxy is unavailable",
            ));
        }
        Ok(Some(proxy))
    }

    async fn resolve_upstream_credentials(
        &self,
        account: &AccountRecord,
        protocol: Protocol,
    ) -> Result<(String, Credential), String> {
        let account_type = account.account_type.trim().to_ascii_lowercase();
        if account_type == "bedrock" {
            return Ok((DEFAULT_ANTHROPIC_BASE_URL.to_owned(), Credential::None));
        }
        if matches!(
            account_type.as_str(),
            "oauth" | "setup-token" | "service_account"
        ) {
            let token = self.access_token(account).await?;
            let base_url =
                adapter_credential(&account.credentials, "base_url").unwrap_or_else(|| {
                    match account.platform.as_str() {
                        "openai" => DEFAULT_OPENAI_BASE_URL,
                        "gemini" => DEFAULT_GEMINI_BASE_URL,
                        "grok" => DEFAULT_GROK_BASE_URL,
                        _ => DEFAULT_ANTHROPIC_BASE_URL,
                    }
                    .to_owned()
                });
            return Ok((base_url, Credential::Bearer(token)));
        }
        upstream_credentials(account, protocol)
    }

    async fn access_token(&self, account: &AccountRecord) -> Result<String, String> {
        let now = now_unix_millis();
        if let Some(cached) = self.inner.access_tokens.get(&account.id)
            && cached.is_fresh_at(now)
        {
            return Ok(cached.token);
        }

        let account_type = account.account_type.trim().to_ascii_lowercase();
        let existing = adapter_credential(&account.credentials, "access_token")
            .or_else(|| adapter_credential(&account.credentials, "token"));
        let expires_at = credential_expiry_unix_ms(&account.credentials).unwrap_or(i64::MAX);
        if let Some(token) = existing
            && (account_type == "setup-token" || expires_at > now.saturating_add(3 * 60 * 1_000))
        {
            self.inner.access_tokens.insert(
                account.id,
                CachedAccessToken {
                    token: token.clone(),
                    expires_at_unix_ms: expires_at,
                    refresh_token: None,
                },
            );
            return Ok(token);
        }

        let client = self
            .upstream_client(account)
            .await
            .map_err(|error| error.message)?;
        let account_id = account.id;
        let account = account.clone();
        let pool = self.inner.repository.pool().clone();
        let shared = self
            .inner
            .access_token_flights
            .run(account_id, || async move {
                refresh_account_token(&client, &pool, &account, now).await
            })
            .await;
        let token = shared.as_ref().as_ref().map_err(Clone::clone)?.clone();
        self.inner.access_tokens.insert(account_id, token.clone());
        self.invalidate_account_selection_cache();
        Ok(token.token)
    }

    fn queue_touch(&self, auth: &AuthContext, account: &AccountRecord) {
        let Some(api_key_id) = auth.api_key.as_ref().map(|key| key.id) else {
            return;
        };
        if let Err(error) = self.inner.writes.try_enqueue(GatewayMutation::Touch {
            api_key_id,
            account_id: account.id,
        }) {
            tracing::warn!(error = %error, "gateway write-behind queue rejected touch update");
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ProxyClientKey {
    protocol: String,
    host: String,
    port: i32,
    username: Option<String>,
    password: Option<String>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct TlsClientKey {
    profile_id: i64,
    proxy: Option<ProxyClientKey>,
}

impl From<&AccountProxyRecord> for ProxyClientKey {
    fn from(proxy: &AccountProxyRecord) -> Self {
        Self {
            protocol: proxy.protocol.to_ascii_lowercase(),
            host: proxy.host.clone(),
            port: proxy.port,
            username: proxy.username.clone(),
            password: proxy.password.clone(),
        }
    }
}

fn proxy_url(proxy: &AccountProxyRecord) -> Result<url::Url, &'static str> {
    let protocol = proxy.protocol.to_ascii_lowercase();
    if !matches!(protocol.as_str(), "http" | "https" | "socks5" | "socks5h") {
        return Err("unsupported proxy protocol");
    }
    let mut url = url::Url::parse(&format!("{protocol}://localhost"))
        .map_err(|_| "invalid proxy protocol")?;
    let raw_host = proxy.host.trim();
    if raw_host.is_empty() {
        return Err("invalid proxy host");
    }
    let host = raw_host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(raw_host);
    let host = if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    url.set_host(Some(&host))
        .map_err(|_| "invalid proxy host")?;
    let port = u16::try_from(proxy.port).map_err(|_| "invalid proxy port")?;
    if port == 0 {
        return Err("invalid proxy port");
    }
    url.set_port(Some(port))
        .map_err(|()| "invalid proxy port")?;
    if let Some(username) = proxy.username.as_deref()
        && !username.is_empty()
    {
        url.set_username(username)
            .map_err(|()| "invalid proxy username")?;
        if let Some(password) = proxy.password.as_deref() {
            url.set_password(Some(password))
                .map_err(|()| "invalid proxy password")?;
        }
    }
    Ok(url)
}

fn configured_proxy(
    account_id: i64,
    proxy: &AccountProxyRecord,
) -> Result<reqwest::Proxy, GatewayError> {
    let proxy_url = proxy_url(proxy).map_err(|message| {
        tracing::warn!(account_id, proxy_id = proxy.id, error = %message, "account proxy configuration is invalid");
        GatewayError::new(
            GatewayErrorKind::Unavailable,
            "account proxy configuration is invalid",
        )
    })?;
    reqwest::Proxy::all(proxy_url.as_str()).map_err(|error| {
        tracing::warn!(account_id, proxy_id = proxy.id, error = %error, "cannot configure account proxy");
        GatewayError::new(
            GatewayErrorKind::Unavailable,
            "account proxy configuration is invalid",
        )
    })
}

fn retry_after_seconds(headers: &HeaderMap) -> Option<i32> {
    if let Some(milliseconds) = headers
        .get("retry-after-ms")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
    {
        return i32::try_from(milliseconds.saturating_add(999) / 1_000).ok();
    }
    if let Some(seconds) = headers
        .get(header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
    {
        return i32::try_from(seconds).ok();
    }
    for name in ["x-ratelimit-reset", "x-rate-limit-reset"] {
        let Some(raw) = headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<i64>().ok())
        else {
            continue;
        };
        let reset_millis = if raw > 10_000_000_000 {
            raw
        } else {
            raw.saturating_mul(1_000)
        };
        let remaining = reset_millis.saturating_sub(now_unix_millis());
        return i32::try_from(remaining.saturating_add(999) / 1_000)
            .ok()
            .filter(|seconds| *seconds > 0);
    }
    None
}

fn sanitized_failure_reason(reason: &str) -> String {
    reason
        .chars()
        .filter(|character| !character.is_control())
        .take(500)
        .collect::<String>()
        .trim()
        .to_owned()
}

async fn apply_stream_timeout_policy(
    pool: &PgPool,
    account_id: i64,
    model: &str,
    settings: &StreamTimeoutSettings,
) -> Result<bool, sqlx::Error> {
    let model = model.chars().take(200).collect::<String>();
    let mut transaction = pool.begin().await?;
    let account_exists = sqlx::query_scalar::<_, i64>(
        "SELECT id FROM accounts WHERE id = $1 AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(account_id)
    .fetch_optional(&mut *transaction)
    .await?
    .is_some();
    if !account_exists {
        transaction.rollback().await?;
        return Ok(false);
    }
    sqlx::query(
        r"
DELETE FROM gateway_stream_timeout_events
WHERE account_id = $1
  AND occurred_at < NOW() - make_interval(mins => $2)
",
    )
    .bind(account_id)
    .bind(settings.threshold_window_minutes)
    .execute(&mut *transaction)
    .await?;
    sqlx::query("INSERT INTO gateway_stream_timeout_events (account_id, model) VALUES ($1, $2)")
        .bind(account_id)
        .bind(&model)
        .execute(&mut *transaction)
        .await?;
    let count = sqlx::query_scalar::<_, i64>(
        r"
SELECT COUNT(*)
FROM gateway_stream_timeout_events
WHERE account_id = $1
  AND occurred_at >= NOW() - make_interval(mins => $2)
",
    )
    .bind(account_id)
    .bind(settings.threshold_window_minutes)
    .fetch_one(&mut *transaction)
    .await?;
    let triggered = count >= i64::from(settings.threshold_count);
    if triggered {
        let reason = format!("stream idle timeout threshold reached for model {model}");
        match settings.action.as_str() {
            "temp_unsched" => {
                sqlx::query(
                    r"
UPDATE accounts
SET temp_unschedulable_until = GREATEST(
        COALESCE(temp_unschedulable_until, NOW()),
        NOW() + make_interval(mins => $2)
    ),
    temp_unschedulable_reason = $3,
    error_message = $3,
    updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL
",
                )
                .bind(account_id)
                .bind(settings.temp_unsched_minutes)
                .bind(&reason)
                .execute(&mut *transaction)
                .await?;
            }
            "error" => {
                sqlx::query(
                    r"
UPDATE accounts
SET status = 'error', schedulable = FALSE, error_message = $2,
    temp_unschedulable_until = NULL, temp_unschedulable_reason = NULL,
    updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL
",
                )
                .bind(account_id)
                .bind(&reason)
                .execute(&mut *transaction)
                .await?;
            }
            _ => {}
        }
        sqlx::query("DELETE FROM gateway_stream_timeout_events WHERE account_id = $1")
            .bind(account_id)
            .execute(&mut *transaction)
            .await?;
    }
    sqlx::query(
        "DELETE FROM gateway_stream_timeout_events WHERE occurred_at < NOW() - INTERVAL '24 hours'",
    )
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(triggered)
}

fn unsupported_platform_message(kind: RouteKind, platform: &str) -> Option<&'static str> {
    match kind {
        RouteKind::OpenAiEmbeddings if platform != "openai" => {
            Some("Embeddings API is not supported for this platform")
        }
        RouteKind::OpenAiImageGenerations | RouteKind::OpenAiImageEdits
            if !matches!(platform, "openai" | "grok") =>
        {
            Some("Images API is not supported for this platform")
        }
        RouteKind::OpenAiVideoGenerations | RouteKind::OpenAiVideoStatus if platform != "grok" => {
            Some("Videos API is not supported for this platform")
        }
        _ => None,
    }
}

const fn route_requires_content_moderation(kind: RouteKind) -> bool {
    matches!(
        kind,
        RouteKind::AnthropicMessages
            | RouteKind::OpenAiResponses
            | RouteKind::OpenAiResponsesCompact
            | RouteKind::OpenAiChatCompletions
            | RouteKind::OpenAiImageGenerations
            | RouteKind::OpenAiImageEdits
            | RouteKind::OpenAiVideoGenerations
            | RouteKind::GeminiGenerateContent
            | RouteKind::GeminiStreamGenerateContent
    )
}

fn invalidate_local_billing_caches(
    auth_cache: &L1Cache<String, ApiKeyAuthRecord>,
    auth_epoch: &AtomicU64,
    account_cache: &L1Cache<AccountPartition, Vec<AccountRecord>>,
    account_epoch: &AtomicU64,
    invalidation: &BillingInvalidation,
) {
    auth_epoch.fetch_add(1, Ordering::AcqRel);
    auth_cache.remove_where(|_, snapshot| {
        invalidation
            .user_ids()
            .binary_search(
                &snapshot
                    .user
                    .as_ref()
                    .map_or(snapshot.api_key.user_id, |user| user.id),
            )
            .is_ok()
            || invalidation
                .api_key_ids()
                .binary_search(&snapshot.api_key.id)
                .is_ok()
            || snapshot
                .api_key
                .group_id
                .is_some_and(|group_id| invalidation.group_ids().binary_search(&group_id).is_ok())
    });

    account_epoch.fetch_add(1, Ordering::AcqRel);
    account_cache.remove_where(|partition, accounts| {
        partition
            .group_id
            .is_some_and(|group_id| invalidation.group_ids().binary_search(&group_id).is_ok())
            || accounts.iter().any(|account| {
                invalidation
                    .account_ids()
                    .binary_search(&account.id)
                    .is_ok()
                    || account
                        .group_ids
                        .iter()
                        .any(|group_id| invalidation.group_ids().binary_search(group_id).is_ok())
            })
    });
}

async fn get_or_load_guarded<K, V, E, F, Fut>(
    cache: &L1Cache<K, V>,
    flights: &Singleflight<K, V, E>,
    epoch: &AtomicU64,
    key: K,
    load: F,
) -> SharedResult<V, E>
where
    K: Clone + Eq + Hash,
    V: Clone,
    F: Fn() -> Fut,
    Fut: Future<Output = Result<V, E>>,
{
    loop {
        let observed_epoch = epoch.load(Ordering::Acquire);
        let result = cache.get_or_load(flights, key.clone(), &load).await;
        if epoch.load(Ordering::Acquire) == observed_epoch {
            return result;
        }

        cache.remove(&key);
    }
}

fn build_usage_payload(
    auth: &AuthContext,
    api_key: &ApiKeyRecord,
    limits: &sqlx::postgres::PgRow,
    usage: &Value,
) -> Value {
    let quota = row_decimal(limits, "quota");
    let quota_used = row_decimal(limits, "quota_used");
    let has_quota = decimal_is_positive(&quota);
    let has_rates = ["rate_limit_5h", "rate_limit_1d", "rate_limit_7d"]
        .into_iter()
        .any(|column| decimal_is_positive(&row_decimal(limits, column)));
    let mut response = if has_quota || has_rates {
        let mut value = json!({
            "mode": "quota_limited",
            "isValid": matches!(api_key.status.as_str(), "active" | "quota_exhausted" | "expired"),
            "status": api_key.status,
            "unit": "USD",
            "usage": usage,
        });
        if has_quota {
            let remaining = row_decimal(limits, "quota_remaining");
            value["quota"] = json!({
                "limit": quota,
                "used": quota_used,
                "remaining": remaining,
                "unit": "USD"
            });
            value["remaining"] = remaining;
        }
        value
    } else {
        json!({
            "mode": "unrestricted",
            "isValid": true,
            "planName": auth.group.as_ref().map_or("wallet balance", |group| group.name.as_str()),
            "remaining": decimal_json(&auth.user.balance),
            "balance": decimal_json(&auth.user.balance),
            "unit": "USD",
            "usage": usage,
        })
    };
    let rate_limits = usage_rate_limits(limits);
    if !rate_limits.is_empty() {
        response["rate_limits"] = Value::Array(rate_limits);
    }
    if let Ok(Some(expires_at)) = limits.try_get::<Option<String>, _>("expires_at") {
        response["expires_at"] = Value::String(expires_at);
    }
    response
}

#[derive(Clone, Debug, Eq)]
struct AccountPartition {
    platform: String,
    group_id: Option<i64>,
}

impl PartialEq for AccountPartition {
    fn eq(&self, other: &Self) -> bool {
        self.platform == other.platform && self.group_id == other.group_id
    }
}

impl Hash for AccountPartition {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.platform.hash(state);
        self.group_id.hash(state);
    }
}

struct AccountSelection {
    account: AccountRecord,
    requested_model: Option<String>,
    channel_mapped_model: Option<String>,
    mapped_model: Option<String>,
    channel_policy: Option<ChannelPolicyRecord>,
    lease: AccountLease,
    global_lease: AuthorityLease,
}

#[derive(Clone, Debug)]
struct CachedAccessToken {
    token: String,
    expires_at_unix_ms: i64,
    refresh_token: Option<String>,
}

impl CachedAccessToken {
    fn is_fresh_at(&self, now_unix_ms: i64) -> bool {
        self.expires_at_unix_ms > now_unix_ms.saturating_add(3 * 60 * 1_000)
    }
}

#[derive(Default)]
struct RpmState {
    minute: i64,
    initialized: bool,
    by_user: HashMap<i64, u32>,
    by_user_group: HashMap<(i64, i64), u32>,
}

impl RpmState {
    fn rotate(&mut self, minute: i64) {
        if !self.initialized || self.minute != minute {
            self.minute = minute;
            self.initialized = true;
            self.by_user.clear();
            self.by_user_group.clear();
        }
    }
}

fn increment_counter<K>(counters: &mut HashMap<K, u32>, key: K) -> u32
where
    K: Eq + Hash,
{
    let count = counters.entry(key).or_default();
    *count = count.saturating_add(1);
    *count
}

struct AccountLease {
    account_id: i64,
    in_flight: Arc<Mutex<HashMap<i64, u32>>>,
}

struct ApiKeyLease {
    api_key_id: i64,
    in_flight: Arc<Mutex<HashMap<i64, u32>>>,
}

struct UserLease {
    user_id: i64,
    in_flight: Arc<Mutex<HashMap<i64, u32>>>,
}

struct GatewayLeases {
    _account: AccountLease,
    _global_account: Option<AuthorityLease>,
    _api_key: ApiKeyLease,
    _user: UserLease,
    _global_user: Option<AuthorityLease>,
}

impl UserLease {
    fn try_acquire(
        user_id: i64,
        concurrency: i32,
        in_flight: Arc<Mutex<HashMap<i64, u32>>>,
    ) -> Result<Self, GatewayError> {
        let mut current = lock(&in_flight);
        let active = current.get(&user_id).copied().unwrap_or_default();
        if concurrency > 0 && active >= u32::try_from(concurrency).unwrap_or(u32::MAX) {
            return Err(GatewayError::new(
                GatewayErrorKind::RateLimit,
                "too many concurrent requests",
            ));
        }
        current.insert(user_id, active.saturating_add(1));
        drop(current);
        Ok(Self { user_id, in_flight })
    }
}

impl ApiKeyLease {
    fn acquire(api_key_id: i64, in_flight: Arc<Mutex<HashMap<i64, u32>>>) -> Self {
        *lock(&in_flight).entry(api_key_id).or_default() += 1;
        Self {
            api_key_id,
            in_flight,
        }
    }
}

impl Drop for ApiKeyLease {
    fn drop(&mut self) {
        let mut in_flight = lock(&self.in_flight);
        if let Some(current) = in_flight.get_mut(&self.api_key_id) {
            *current = current.saturating_sub(1);
            if *current == 0 {
                in_flight.remove(&self.api_key_id);
            }
        }
    }
}

impl Drop for UserLease {
    fn drop(&mut self) {
        let mut in_flight = lock(&self.in_flight);
        if let Some(current) = in_flight.get_mut(&self.user_id) {
            *current = current.saturating_sub(1);
            if *current == 0 {
                in_flight.remove(&self.user_id);
            }
        }
    }
}

impl Drop for AccountLease {
    fn drop(&mut self) {
        let mut in_flight = lock(&self.in_flight);
        if let Some(current) = in_flight.get_mut(&self.account_id) {
            *current = current.saturating_sub(1);
            if *current == 0 {
                in_flight.remove(&self.account_id);
            }
        }
    }
}

struct StreamBilling {
    observer: Option<SseBillingObserver>,
    reservation: Option<BillingReservation>,
    writes: PendingBillingQueue,
    route: RouteKind,
    request_started: Instant,
    backpressure: BillingBackpressure,
    idle_timeout: Duration,
    timeout_context: StreamTimeoutContext,
}

#[derive(Clone, Default)]
struct BillingBackpressure {
    inner: Arc<BillingBackpressureInner>,
}

#[derive(Default)]
struct BillingBackpressureInner {
    state: Mutex<BillingBackpressureState>,
    changed: Notify,
}

#[derive(Default)]
struct BillingBackpressureState {
    accepting: bool,
    initialized: bool,
    in_flight: usize,
    failed_events: usize,
    last_error: Option<String>,
}

struct BillingBackpressureReport {
    failed_events: usize,
    last_error: Option<String>,
}

struct BillingBackpressureTaskGuard {
    tracker: BillingBackpressure,
    completed: bool,
}

impl BillingBackpressureTaskGuard {
    fn new(tracker: BillingBackpressure) -> Self {
        Self {
            tracker,
            completed: false,
        }
    }

    fn complete(mut self, error: Option<String>) {
        self.tracker.complete_task(error);
        self.completed = true;
    }
}

impl Drop for BillingBackpressureTaskGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.tracker.complete_task(Some(
                "streaming billing enqueue task was cancelled or panicked".to_owned(),
            ));
        }
    }
}

impl BillingBackpressure {
    fn snapshot(&self) -> (usize, usize) {
        let state = lock(&self.inner.state);
        (state.in_flight, state.failed_events)
    }

    #[cfg(test)]
    #[allow(clippy::result_large_err)]
    fn spawn(&self, queue: PendingBillingQueue, event: BillingEvent) -> Result<(), BillingEvent> {
        let backup = event.clone();
        let future = Box::pin(async move {
            queue
                .enqueue(event)
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
        });
        self.spawn_future(future).map_err(|()| backup)
    }

    fn spawn_future(&self, future: BillingFinalizeFuture) -> Result<(), ()> {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            self.record_failure("cannot enqueue streaming billing outside a Tokio runtime");
            return Err(());
        };
        {
            let mut state = lock(&self.inner.state);
            if state.initialized && !state.accepting {
                state.failed_events = state.failed_events.saturating_add(1);
                state.last_error = Some("billing shutdown already started".to_owned());
                return Err(());
            }
            state.initialized = true;
            state.accepting = true;
            state.in_flight = state.in_flight.saturating_add(1);
        }
        let guard = BillingBackpressureTaskGuard::new(self.clone());
        runtime.spawn(async move {
            let result = future.await;
            guard.complete(result.err());
        });
        Ok(())
    }

    fn complete_task(&self, error: Option<String>) {
        let mut state = lock(&self.inner.state);
        state.in_flight = state.in_flight.saturating_sub(1);
        if let Some(error) = error {
            state.failed_events = state.failed_events.saturating_add(1);
            state.last_error = Some(error);
        }
        drop(state);
        self.inner.changed.notify_waiters();
    }

    fn record_failure(&self, error: &str) {
        let mut state = lock(&self.inner.state);
        state.failed_events = state.failed_events.saturating_add(1);
        state.last_error = Some(error.to_owned());
    }

    async fn close_and_wait(&self) -> BillingBackpressureReport {
        loop {
            let notified = self.inner.changed.notified();
            {
                let mut state = lock(&self.inner.state);
                state.initialized = true;
                state.accepting = false;
                if state.in_flight == 0 {
                    return BillingBackpressureReport {
                        failed_events: state.failed_events,
                        last_error: state.last_error.clone(),
                    };
                }
            }
            notified.await;
        }
    }
}

type BillingFinalizeFuture = Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;

enum StreamTerminal {
    End(Vec<u8>),
    Error(reqwest::Error),
}

#[derive(Clone)]
struct StreamTimeoutContext {
    runtime: GatewayRuntime,
    account_id: i64,
    model: String,
    settings: StreamTimeoutSettings,
}

struct StreamIdleTimeout {
    duration: Duration,
    sleep: Pin<Box<tokio::time::Sleep>>,
}

impl StreamIdleTimeout {
    fn new(duration: Duration) -> Option<Self> {
        (!duration.is_zero()).then(|| Self {
            duration,
            sleep: Box::pin(tokio::time::sleep(duration)),
        })
    }

    fn reset(&mut self) {
        self.sleep
            .as_mut()
            .reset(tokio::time::Instant::now() + self.duration);
    }
}

struct LeasedStream {
    inner: Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>,
    bedrock: Option<BedrockEventStreamDecoder>,
    bridge: Option<SseBridge>,
    leases: Option<GatewayLeases>,
    billing: Option<SseBillingObserver>,
    billing_reservation: Option<BillingReservation>,
    billing_finalize: Option<BillingFinalizeFuture>,
    billing_finalize_started: bool,
    terminal: Option<StreamTerminal>,
    billing_writes: PendingBillingQueue,
    billing_route: RouteKind,
    request_started: Instant,
    billing_backpressure: BillingBackpressure,
    idle_timeout: Option<StreamIdleTimeout>,
    timeout_context: Option<StreamTimeoutContext>,
    finished: bool,
}

impl LeasedStream {
    fn start_billing_finalize(&mut self) {
        if self.billing_finalize_started {
            return;
        }
        self.billing_finalize_started = true;
        let Some(observer) = self.billing.take() else {
            self.billing_reservation.take();
            return;
        };
        let event = match observer.finish(Some(elapsed_millis(self.request_started))) {
            Ok(event) => event,
            Err(error) => {
                tracing::error!(error = %error, "observe streaming gateway billing");
                self.billing_reservation.take();
                self.billing_finalize = Some(Box::pin(async move { Err(error.to_string()) }));
                return;
            }
        };
        let Some(mut reservation) = self.billing_reservation.take() else {
            self.billing_finalize = Some(Box::pin(async {
                Err("streaming billing reservation is missing".to_owned())
            }));
            return;
        };
        let queue = self.billing_writes.clone();
        self.billing_finalize = Some(Box::pin(async move {
            reservation
                .stage(&event)
                .await
                .map_err(|error| error.to_string())?;
            queue
                .enqueue(event)
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
        }));
    }

    fn poll_terminal(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, reqwest::Error>>> {
        self.start_billing_finalize();
        if let Some(finalize) = self.billing_finalize.as_mut() {
            match finalize.as_mut().poll(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => {
                    tracing::error!(error = %error, "finalize durable streaming billing");
                    self.billing_finalize = None;
                    self.finished = true;
                    self.leases.take();
                    self.terminal.take();
                    return Poll::Ready(Some(Ok(billing_terminal_frame(self.billing_route))));
                }
            }
        }
        self.billing_finalize = None;
        self.finished = true;
        self.leases.take();
        match self.terminal.take() {
            Some(StreamTerminal::End(bytes)) if bytes.is_empty() => Poll::Ready(None),
            Some(StreamTerminal::End(bytes)) => Poll::Ready(Some(Ok(Bytes::from(bytes)))),
            Some(StreamTerminal::Error(error)) => Poll::Ready(Some(Err(error))),
            None => Poll::Ready(None),
        }
    }
}

impl Stream for LeasedStream {
    type Item = Result<Bytes, reqwest::Error>;

    #[allow(clippy::too_many_lines)]
    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.finished {
            return Poll::Ready(None);
        }
        loop {
            if this.terminal.is_some() {
                return this.poll_terminal(context);
            }
            if let Some(timeout) = this.idle_timeout.as_mut()
                && timeout.sleep.as_mut().poll(context).is_ready()
            {
                if let Some(timeout_context) = this.timeout_context.take()
                    && let Ok(runtime) = tokio::runtime::Handle::try_current()
                {
                    runtime.spawn(async move {
                        timeout_context
                            .runtime
                            .record_stream_timeout(
                                timeout_context.account_id,
                                &timeout_context.model,
                                &timeout_context.settings,
                            )
                            .await;
                    });
                }
                this.terminal = Some(StreamTerminal::End(
                    stream_timeout_terminal_frame(this.billing_route).to_vec(),
                ));
                continue;
            }
            match this.inner.as_mut().poll_next(context) {
                Poll::Ready(Some(Ok(bytes))) => {
                    if let Some(timeout) = this.idle_timeout.as_mut() {
                        timeout.reset();
                    }
                    let bytes = if let Some(decoder) = this.bedrock.as_mut() {
                        match decoder.push(&bytes) {
                            Ok(decoded) if decoded.is_empty() => continue,
                            Ok(decoded) => Bytes::from(decoded),
                            Err(error) => {
                                tracing::warn!(error = %error, "decode Bedrock EventStream");
                                this.billing = None;
                                this.finished = true;
                                this.leases.take();
                                return Poll::Ready(Some(Ok(stream_conversion_terminal_frame(
                                    this.billing_route,
                                ))));
                            }
                        }
                    } else {
                        bytes
                    };
                    if let Some(observer) = this.billing.as_mut()
                        && let Err(error) = observer.push(&bytes)
                    {
                        tracing::error!(error = %error, "observe streaming gateway billing chunk");
                        this.billing = None;
                        this.finished = true;
                        this.leases.take();
                        return Poll::Ready(Some(Ok(billing_terminal_frame(this.billing_route))));
                    }
                    if let Some(bridge) = this.bridge.as_mut() {
                        match bridge.push(&bytes) {
                            Ok(converted) if converted.is_empty() => continue,
                            Ok(converted) => return Poll::Ready(Some(Ok(Bytes::from(converted)))),
                            Err(error) => {
                                tracing::warn!(error = %error, "convert gateway upstream SSE");
                                this.billing = None;
                                this.finished = true;
                                this.leases.take();
                                return Poll::Ready(Some(Ok(stream_conversion_terminal_frame(
                                    this.billing_route,
                                ))));
                            }
                        }
                    }
                    return Poll::Ready(Some(Ok(bytes)));
                }
                Poll::Ready(Some(Err(error))) => {
                    this.terminal = Some(StreamTerminal::Error(error));
                }
                Poll::Ready(None) => {
                    let mut terminal = Vec::new();
                    if let Some(decoder) = this.bedrock.as_ref()
                        && let Err(error) = decoder.finish()
                    {
                        tracing::warn!(error = %error, "finish Bedrock EventStream decoding");
                        this.billing = None;
                        terminal.extend_from_slice(&stream_conversion_terminal_frame(
                            this.billing_route,
                        ));
                    }
                    if let Some(bridge) = this.bridge.as_mut() {
                        match bridge.finish() {
                            Ok(converted) => terminal.extend_from_slice(&converted),
                            Err(error) => {
                                tracing::warn!(error = %error, "finish gateway SSE conversion");
                                terminal.extend_from_slice(&stream_conversion_terminal_frame(
                                    this.billing_route,
                                ));
                            }
                        }
                    }
                    this.terminal = Some(StreamTerminal::End(terminal));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl Drop for LeasedStream {
    fn drop(&mut self) {
        self.start_billing_finalize();
        if let Some(finalize) = self.billing_finalize.take()
            && self.billing_backpressure.spawn_future(finalize).is_err()
        {
            tracing::error!("cannot track durable streaming billing finalization");
        }
    }
}

fn billing_terminal_frame(route: RouteKind) -> Bytes {
    Bytes::from(
        GatewayError::new(
            GatewayErrorKind::Internal,
            "failed to process streaming usage",
        )
        .sse(route),
    )
}

fn stream_conversion_terminal_frame(route: RouteKind) -> Bytes {
    Bytes::from(
        GatewayError::new(
            GatewayErrorKind::Upstream,
            "upstream stream could not be converted",
        )
        .sse(route),
    )
}

fn stream_timeout_terminal_frame(route: RouteKind) -> Bytes {
    Bytes::from(
        GatewayError::new(
            GatewayErrorKind::Upstream,
            "upstream stream was idle for too long",
        )
        .sse(route),
    )
}

async fn run_authority_worker(
    authority: GatewayAuthority,
    billing: PendingBillingQueue,
    cancellation: CancellationToken,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    let mut cleanup_tick = 0_u8;
    loop {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => break,
            _ = interval.tick() => {}
        }
        match authority.claim_ready_events(100).await {
            Ok(events) => {
                for event in events {
                    tokio::select! {
                        biased;
                        () = cancellation.cancelled() => return,
                        result = billing.enqueue(event) => {
                            if let Err(error) = result {
                                tracing::warn!(error = %error, "durable billing recovery enqueue failed");
                                break;
                            }
                        }
                    }
                }
            }
            Err(error) => {
                tracing::warn!(error = %error, "claim durable billing recovery batch");
            }
        }
        if let Err(error) = authority.refresh_ready_count().await {
            tracing::warn!(error = %error, "refresh durable billing ready count");
        }
        cleanup_tick = cleanup_tick.wrapping_add(1);
        if cleanup_tick >= 12 {
            cleanup_tick = 0;
            if let Err(error) = authority.cleanup_once().await {
                tracing::warn!(error = %error, "clean gateway authority runtime rows");
            }
        }
    }
}

#[derive(Clone, Debug)]
enum GatewayMutation {
    Touch { api_key_id: i64, account_id: i64 },
}

struct GatewayMutationSink {
    pool: PgPool,
}

impl BatchSink<GatewayMutation> for GatewayMutationSink {
    fn write_batch<'a>(&'a self, batch: &'a [GatewayMutation]) -> BoxFlushFuture<'a> {
        Box::pin(async move { flush_gateway_mutations(&self.pool, batch).await })
    }
}

async fn flush_gateway_mutations(pool: &PgPool, batch: &[GatewayMutation]) -> anyhow::Result<()> {
    let mut api_key_ids = HashSet::new();
    let mut account_ids = HashSet::new();
    for mutation in batch {
        let GatewayMutation::Touch {
            api_key_id,
            account_id,
        } = mutation;
        api_key_ids.insert(*api_key_id);
        account_ids.insert(*account_id);
    }
    let api_key_ids = api_key_ids.into_iter().collect::<Vec<_>>();
    let account_ids = account_ids.into_iter().collect::<Vec<_>>();
    let mut transaction = pool.begin().await?;
    if !api_key_ids.is_empty() {
        sqlx::query(
            "UPDATE api_keys SET last_used_at = NOW(), updated_at = NOW() WHERE id = ANY($1)",
        )
        .bind(&api_key_ids)
        .execute(&mut *transaction)
        .await?;
    }
    if !account_ids.is_empty() {
        sqlx::query(
            "UPDATE accounts SET last_used_at = NOW(), updated_at = NOW() WHERE id = ANY($1)",
        )
        .bind(&account_ids)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(())
}

fn protocol_platform(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Anthropic => "anthropic",
        Protocol::OpenAi => "openai",
        Protocol::Gemini => "gemini",
    }
}

const fn usage_provider(protocol: Protocol) -> UsageProvider {
    match protocol {
        Protocol::Anthropic => UsageProvider::Anthropic,
        Protocol::OpenAi => UsageProvider::OpenAi,
        Protocol::Gemini => UsageProvider::Gemini,
    }
}

fn parse_decimal_field(raw: &str, field: &str) -> Result<Decimal, GatewayError> {
    raw.parse::<Decimal>().map_err(|error| {
        tracing::error!(field, error = %error, "parse gateway billing decimal");
        GatewayError::new(GatewayErrorKind::Internal, "invalid billing state")
    })
}

fn billing_arithmetic_error(field: &str, error: &impl fmt::Display) -> GatewayError {
    tracing::error!(field, error = %error, "apply pending gateway billing");
    GatewayError::new(GatewayErrorKind::Internal, "invalid billing state")
}

fn validate_api_key_rate_windows(
    api_key: &ApiKeyRecord,
    pending: &PendingBilling,
    now_unix_ms: i64,
) -> Result<(), GatewayError> {
    for window in [
        ApiKeyRateWindow {
            name: "5-hour",
            limit: &api_key.rate_limit_5h,
            usage: &api_key.usage_5h,
            start_unix_ms: api_key.window_5h_start_unix_ms,
            duration_millis: API_KEY_5H_MILLIS,
        },
        ApiKeyRateWindow {
            name: "daily",
            limit: &api_key.rate_limit_1d,
            usage: &api_key.usage_1d,
            start_unix_ms: api_key.window_1d_start_unix_ms,
            duration_millis: API_KEY_1D_MILLIS,
        },
        ApiKeyRateWindow {
            name: "weekly",
            limit: &api_key.rate_limit_7d,
            usage: &api_key.usage_7d,
            start_unix_ms: api_key.window_7d_start_unix_ms,
            duration_millis: API_KEY_7D_MILLIS,
        },
    ] {
        validate_api_key_rate_window(api_key.id, pending, &window, now_unix_ms)?;
    }
    Ok(())
}

fn validate_user_platform_quota(
    auth: &AuthContext,
    platform: &str,
    pending: &PendingBilling,
    now_unix_ms: i64,
) -> Result<(), GatewayError> {
    if auth
        .group
        .as_ref()
        .is_some_and(GroupRecord::is_subscription_type)
    {
        return Ok(());
    }
    let Some(quota) = auth
        .platform_quotas
        .iter()
        .find(|quota| quota.platform.eq_ignore_ascii_case(platform))
    else {
        return Ok(());
    };
    let day_start = shanghai_day_start(now_unix_ms);
    let week_start = shanghai_week_start(now_unix_ms);
    for window in [
        PlatformQuotaWindow {
            name: "daily",
            limit: quota.daily_limit_usd.as_deref(),
            usage: &quota.daily_usage_usd,
            start_unix_ms: quota.daily_window_start_unix_ms,
            reset_boundary: day_start,
            rolling_millis: None,
        },
        PlatformQuotaWindow {
            name: "weekly",
            limit: quota.weekly_limit_usd.as_deref(),
            usage: &quota.weekly_usage_usd,
            start_unix_ms: quota.weekly_window_start_unix_ms,
            reset_boundary: week_start,
            rolling_millis: None,
        },
        PlatformQuotaWindow {
            name: "monthly",
            limit: quota.monthly_limit_usd.as_deref(),
            usage: &quota.monthly_usage_usd,
            start_unix_ms: quota.monthly_window_start_unix_ms,
            reset_boundary: now_unix_ms,
            rolling_millis: Some(SUBSCRIPTION_MONTH_MILLIS),
        },
    ] {
        validate_platform_quota_window(
            auth.user.id,
            platform,
            quota,
            pending,
            &window,
            now_unix_ms,
        )?;
    }
    Ok(())
}

struct PlatformQuotaWindow<'a> {
    name: &'static str,
    limit: Option<&'a str>,
    usage: &'a str,
    start_unix_ms: Option<i64>,
    reset_boundary: i64,
    rolling_millis: Option<i64>,
}

fn validate_platform_quota_window(
    user_id: i64,
    platform: &str,
    quota: &UserPlatformQuotaRecord,
    pending: &PendingBilling,
    window: &PlatformQuotaWindow<'_>,
    now_unix_ms: i64,
) -> Result<(), GatewayError> {
    let Some(raw_limit) = window.limit else {
        return Ok(());
    };
    let limit = parse_decimal_field(raw_limit, "user platform quota limit")?;
    if limit.is_negative() {
        return Err(GatewayError::new(
            GatewayErrorKind::Internal,
            "invalid user platform quota",
        ));
    }
    let usage = parse_decimal_field(window.usage, "user platform quota usage")?;
    if usage.is_negative() {
        return Err(GatewayError::new(
            GatewayErrorKind::Internal,
            "invalid user platform quota",
        ));
    }
    let expired = if let Some(duration) = window.rolling_millis {
        window
            .start_unix_ms
            .and_then(|start| start.checked_add(duration))
            .is_none_or(|deadline| deadline <= now_unix_ms)
    } else {
        window
            .start_unix_ms
            .is_none_or(|start| start < window.reset_boundary)
    };
    let pending_since = if let Some(duration) = window.rolling_millis {
        if expired {
            window
                .start_unix_ms
                .and_then(|start| start.checked_add(duration))
                .unwrap_or(0)
        } else {
            window.start_unix_ms.unwrap_or(0)
        }
    } else if expired {
        window.reset_boundary
    } else {
        window.start_unix_ms.unwrap_or(window.reset_boundary)
    };
    let pending_usage = pending.user_platform_cost_since(user_id, platform, pending_since);
    let effective = (if expired { Decimal::ZERO } else { usage })
        .checked_add(pending_usage)
        .map_err(|error| billing_arithmetic_error("user platform quota", &error))?;
    if effective >= limit {
        tracing::debug!(
            user_id,
            platform,
            window = window.name,
            configured_platform = quota.platform,
            "user platform quota exhausted"
        );
        return Err(GatewayError::new(
            GatewayErrorKind::RateLimit,
            format!("{} {platform} quota exhausted", window.name),
        ));
    }
    Ok(())
}

fn shanghai_day_start(now_unix_ms: i64) -> i64 {
    const OFFSET: i64 = 8 * 60 * 60 * 1_000;
    now_unix_ms
        .saturating_add(OFFSET)
        .div_euclid(SUBSCRIPTION_DAY_MILLIS)
        .saturating_mul(SUBSCRIPTION_DAY_MILLIS)
        .saturating_sub(OFFSET)
}

fn shanghai_week_start(now_unix_ms: i64) -> i64 {
    const OFFSET: i64 = 8 * 60 * 60 * 1_000;
    let local_day = now_unix_ms
        .saturating_add(OFFSET)
        .div_euclid(SUBSCRIPTION_DAY_MILLIS);
    let days_since_monday = local_day.saturating_add(3).rem_euclid(7);
    local_day
        .saturating_sub(days_since_monday)
        .saturating_mul(SUBSCRIPTION_DAY_MILLIS)
        .saturating_sub(OFFSET)
}

struct ApiKeyRateWindow<'a> {
    name: &'static str,
    limit: &'a str,
    usage: &'a str,
    start_unix_ms: Option<i64>,
    duration_millis: i64,
}

fn validate_api_key_rate_window(
    api_key_id: i64,
    pending: &PendingBilling,
    window: &ApiKeyRateWindow<'_>,
    now_unix_ms: i64,
) -> Result<(), GatewayError> {
    let limit = parse_decimal_field(window.limit, "API key rate limit")?;
    if limit <= Decimal::ZERO {
        return Ok(());
    }
    let durable_usage = parse_decimal_field(window.usage, "API key rate usage")?;
    if durable_usage.is_negative() {
        tracing::error!(
            window = window.name,
            "API key rate usage cannot be negative"
        );
        return Err(GatewayError::new(
            GatewayErrorKind::Internal,
            "invalid billing state",
        ));
    }

    let deadline = window
        .start_unix_ms
        .and_then(|start| start.checked_add(window.duration_millis));
    let expired = deadline.is_some_and(|deadline| deadline <= now_unix_ms);
    let durable_usage = if expired {
        Decimal::ZERO
    } else {
        durable_usage
    };
    let pending_usage = if expired {
        pending.api_key_cost_since(api_key_id, deadline.unwrap_or(now_unix_ms))
    } else if let Some(start) = window.start_unix_ms {
        pending.api_key_cost_since(api_key_id, start)
    } else {
        pending.api_key_cost(api_key_id)
    };
    let effective_usage = durable_usage
        .checked_add(pending_usage)
        .map_err(|error| billing_arithmetic_error("API key rate limit", &error))?;
    if effective_usage >= limit {
        return Err(GatewayError::new(
            GatewayErrorKind::RateLimit,
            format!("{} API key quota exhausted", window.name),
        ));
    }
    Ok(())
}

fn validate_pending_subscription(
    auth: &AuthContext,
    pending: &PendingBilling,
    now_unix_ms: i64,
) -> Result<(), GatewayError> {
    let (group_id, subscription) = active_subscription_context(auth, now_unix_ms)?;
    let one_time_daily = subscription.expires_at_unix_ms
        <= subscription
            .starts_at_unix_ms
            .checked_add(SUBSCRIPTION_DAY_MILLIS)
            .unwrap_or(i64::MAX);
    for window in subscription_quota_windows(subscription, one_time_daily) {
        validate_subscription_window(
            auth.user.id,
            group_id,
            subscription.id,
            pending,
            &window,
            now_unix_ms,
        )?;
    }
    Ok(())
}

fn active_subscription_context(
    auth: &AuthContext,
    now_unix_ms: i64,
) -> Result<(i64, &SubscriptionBillingRecord), GatewayError> {
    let api_key = auth.api_key.as_ref().ok_or_else(|| {
        GatewayError::new(
            GatewayErrorKind::Internal,
            "authenticated request has no API key context",
        )
    })?;
    let group_id = api_key.group_id.ok_or_else(|| {
        GatewayError::new(
            GatewayErrorKind::Internal,
            "subscription request has no group context",
        )
    })?;
    let subscription = auth.subscription.as_ref().ok_or_else(|| {
        GatewayError::new(GatewayErrorKind::Permission, "active subscription required")
    })?;
    if subscription.user_id != auth.user.id || subscription.group_id != group_id {
        tracing::error!(
            subscription_id = subscription.id,
            user_id = auth.user.id,
            group_id,
            "subscription billing snapshot does not match API key owner/group"
        );
        return Err(GatewayError::new(
            GatewayErrorKind::Internal,
            "invalid subscription billing state",
        ));
    }
    if subscription.starts_at_unix_ms > now_unix_ms
        || subscription.expires_at_unix_ms <= now_unix_ms
    {
        return Err(GatewayError::new(
            GatewayErrorKind::Permission,
            "active subscription required",
        ));
    }
    Ok((group_id, subscription))
}

fn subscription_quota_windows(
    subscription: &SubscriptionBillingRecord,
    one_time_daily: bool,
) -> [SubscriptionQuotaWindow<'_>; 3] {
    [
        SubscriptionQuotaWindow {
            name: "daily",
            limit: subscription.daily_limit_usd.as_deref(),
            usage: &subscription.daily_usage_usd,
            start_unix_ms: subscription.daily_window_start_unix_ms,
            duration_millis: SUBSCRIPTION_DAY_MILLIS,
            resets: !one_time_daily,
        },
        SubscriptionQuotaWindow {
            name: "weekly",
            limit: subscription.weekly_limit_usd.as_deref(),
            usage: &subscription.weekly_usage_usd,
            start_unix_ms: subscription.weekly_window_start_unix_ms,
            duration_millis: SUBSCRIPTION_WEEK_MILLIS,
            resets: true,
        },
        SubscriptionQuotaWindow {
            name: "monthly",
            limit: subscription.monthly_limit_usd.as_deref(),
            usage: &subscription.monthly_usage_usd,
            start_unix_ms: subscription.monthly_window_start_unix_ms,
            duration_millis: SUBSCRIPTION_MONTH_MILLIS,
            resets: true,
        },
    ]
}

fn validate_subscription_window(
    user_id: i64,
    group_id: i64,
    subscription_id: i64,
    pending: &PendingBilling,
    window: &SubscriptionQuotaWindow<'_>,
    now_unix_ms: i64,
) -> Result<(), GatewayError> {
    let Some(raw_limit) = window.limit else {
        return Ok(());
    };
    let limit = parse_decimal_field(raw_limit, "subscription quota limit")?;
    if limit <= Decimal::ZERO {
        return Ok(());
    }
    let mut durable_usage = parse_decimal_field(window.usage, "subscription quota usage")?;
    if durable_usage.is_negative() {
        tracing::error!(
            subscription_id,
            window = window.name,
            "subscription quota usage cannot be negative"
        );
        return Err(GatewayError::new(
            GatewayErrorKind::Internal,
            "invalid subscription billing state",
        ));
    }
    if window.resets
        && subscription_window_expired(window.start_unix_ms, window.duration_millis, now_unix_ms)?
    {
        durable_usage = Decimal::ZERO;
    }
    let effective_usage = pending
        .effective_user_group_usage(user_id, group_id, durable_usage)
        .map_err(|error| billing_arithmetic_error("subscription quota", &error))?;
    if effective_usage >= limit {
        return Err(GatewayError::new(
            GatewayErrorKind::RateLimit,
            format!("{} subscription quota exhausted", window.name),
        ));
    }
    Ok(())
}

struct SubscriptionQuotaWindow<'a> {
    name: &'static str,
    limit: Option<&'a str>,
    usage: &'a str,
    start_unix_ms: Option<i64>,
    duration_millis: i64,
    resets: bool,
}

fn subscription_window_expired(
    start_unix_ms: Option<i64>,
    duration_millis: i64,
    now_unix_ms: i64,
) -> Result<bool, GatewayError> {
    let Some(start_unix_ms) = start_unix_ms else {
        return Ok(false);
    };
    let deadline = start_unix_ms.checked_add(duration_millis).ok_or_else(|| {
        GatewayError::new(
            GatewayErrorKind::Internal,
            "invalid subscription billing state",
        )
    })?;
    Ok(now_unix_ms >= deadline)
}

fn account_has_effective_quota(
    account: &AccountRecord,
    pending: &PendingBilling,
) -> Result<bool, GatewayError> {
    if !account.account_type.eq_ignore_ascii_case("apikey")
        && !account.account_type.eq_ignore_ascii_case("bedrock")
    {
        return Ok(true);
    }

    let total_limit = account_extra_decimal(account, "quota_limit")?;
    if total_limit > Decimal::ZERO {
        let total_used = account_extra_decimal(account, "quota_used")?;
        if effective_account_usage(pending, account.id, total_used)? >= total_limit {
            return Ok(false);
        }
    }

    for window in [
        AccountQuotaWindow {
            limit_key: "quota_daily_limit",
            used_key: "quota_daily_used",
            mode_key: "quota_daily_reset_mode",
            start_key: "quota_daily_start",
            reset_key: "quota_daily_reset_at",
            duration_millis: 24 * 60 * 60 * 1_000,
        },
        AccountQuotaWindow {
            limit_key: "quota_weekly_limit",
            used_key: "quota_weekly_used",
            mode_key: "quota_weekly_reset_mode",
            start_key: "quota_weekly_start",
            reset_key: "quota_weekly_reset_at",
            duration_millis: 7 * 24 * 60 * 60 * 1_000,
        },
    ] {
        let limit = account_extra_decimal(account, window.limit_key)?;
        if limit <= Decimal::ZERO {
            continue;
        }
        let durable_usage = if account_quota_period_expired(account, window)? {
            Decimal::ZERO
        } else {
            account_extra_decimal(account, window.used_key)?
        };
        if effective_account_usage(pending, account.id, durable_usage)? >= limit {
            return Ok(false);
        }
    }
    Ok(true)
}

#[derive(Clone, Copy)]
struct AccountQuotaWindow {
    limit_key: &'static str,
    used_key: &'static str,
    mode_key: &'static str,
    start_key: &'static str,
    reset_key: &'static str,
    duration_millis: i64,
}

fn account_quota_period_expired(
    account: &AccountRecord,
    window: AccountQuotaWindow,
) -> Result<bool, GatewayError> {
    let fixed = account
        .extra
        .get(window.mode_key)
        .and_then(Value::as_str)
        .is_some_and(|mode| mode.eq_ignore_ascii_case("fixed"));
    let timestamp_key = if fixed {
        window.reset_key
    } else {
        window.start_key
    };
    let Some(raw_timestamp) = account.extra.get(timestamp_key).and_then(Value::as_str) else {
        return Ok(true);
    };
    let timestamp = chrono::DateTime::parse_from_rfc3339(raw_timestamp).map_err(|error| {
        tracing::error!(
            account_id = account.id,
            field = timestamp_key,
            error = %error,
            "parse account quota timestamp"
        );
        GatewayError::new(GatewayErrorKind::Internal, "invalid account quota state")
    })?;
    let deadline = if fixed {
        timestamp.timestamp_millis()
    } else {
        timestamp
            .timestamp_millis()
            .checked_add(window.duration_millis)
            .ok_or_else(|| {
                GatewayError::new(GatewayErrorKind::Internal, "invalid account quota state")
            })?
    };
    Ok(deadline <= now_unix_millis())
}

fn account_extra_decimal(account: &AccountRecord, key: &str) -> Result<Decimal, GatewayError> {
    let Some(value) = account.extra.get(key) else {
        return Ok(Decimal::ZERO);
    };
    let raw = match value {
        Value::Number(number) => number.to_string(),
        Value::String(value) => value.clone(),
        Value::Null => return Ok(Decimal::ZERO),
        _ => {
            tracing::error!(
                account_id = account.id,
                field = key,
                "invalid account quota value"
            );
            return Err(GatewayError::new(
                GatewayErrorKind::Internal,
                "invalid account quota state",
            ));
        }
    };
    parse_decimal_field(&raw, key)
}

fn effective_account_usage(
    pending: &PendingBilling,
    account_id: i64,
    durable_usage: Decimal,
) -> Result<Decimal, GatewayError> {
    pending
        .effective_account_usage(account_id, durable_usage)
        .map_err(|error| billing_arithmetic_error("account quota", &error))
}

struct PreparedBillingContext {
    request_id: String,
    user_id: i64,
    api_key_id: i64,
    account_id: i64,
    group_id: Option<i64>,
    channel_id: Option<i64>,
    platform: String,
    model: String,
    model_mapping_chain: Option<String>,
    pricing_override: Option<BillingPricingOverride>,
    group_multiplier: Decimal,
    account_multiplier: Decimal,
    request_fingerprint: String,
}

impl PreparedBillingContext {
    fn finish(self, response_mode: ResponseMode) -> BillingContext {
        let stream = response_mode == ResponseMode::ServerSentEvents;
        BillingContext {
            request_id: self.request_id,
            request_fingerprint: self.request_fingerprint,
            user_id: self.user_id,
            api_key_id: self.api_key_id,
            account_id: self.account_id,
            group_id: self.group_id,
            channel_id: self.channel_id,
            platform: self.platform,
            model: self.model,
            model_mapping_chain: self.model_mapping_chain,
            pricing_override: self.pricing_override,
            group_multiplier: self.group_multiplier,
            account_multiplier: self.account_multiplier,
            stream,
            request_type: if stream {
                RequestType::Stream
            } else {
                RequestType::Sync
            },
        }
    }
}

fn prepare_billing_context(
    observer: &BillingObserver,
    auth: &AuthContext,
    selection: &AccountSelection,
    route: &GatewayRoute,
    metadata: &RequestMetadata,
    request_body: &[u8],
    request_id: &str,
) -> Result<Option<PreparedBillingContext>, GatewayError> {
    if !route_is_token_billed(route.kind) {
        return Ok(None);
    }
    let api_key = auth.api_key.as_ref().ok_or_else(|| {
        GatewayError::new(
            GatewayErrorKind::Internal,
            "authenticated request has no API key billing context",
        )
    })?;
    let upstream_model = selection
        .mapped_model
        .as_deref()
        .or(route.model_from_path.as_deref())
        .or(metadata.model.as_deref())
        .ok_or_else(|| {
            GatewayError::new(
                GatewayErrorKind::InvalidRequest,
                "token-billed request does not identify a model",
            )
        })?;
    let model = selection
        .channel_policy
        .as_ref()
        .map_or(upstream_model, |policy| {
            restriction_model(
                policy,
                selection.requested_model.as_deref(),
                selection.channel_mapped_model.as_deref(),
                Some(upstream_model),
            )
            .unwrap_or(upstream_model)
        });
    let pricing_override = selection
        .channel_policy
        .as_ref()
        .map(|policy| channel_billing_override(policy, model))
        .transpose()?
        .flatten();
    let group_multiplier = auth.group.as_ref().map_or(Ok(Decimal::ONE), |group| {
        parse_decimal_field(&group.rate_multiplier, "group billing multiplier")
    })?;
    let account_multiplier = parse_decimal_field(
        &selection.account.rate_multiplier,
        "account billing multiplier",
    )?;
    if group_multiplier.is_negative() || account_multiplier.is_negative() {
        tracing::error!(
            group_id = api_key.group_id,
            account_id = selection.account.id,
            "gateway billing multiplier cannot be negative"
        );
        return Err(GatewayError::new(
            GatewayErrorKind::Internal,
            "invalid billing multiplier configuration",
        ));
    }
    observer
        .preflight_model_with_override(model, pricing_override.as_ref())
        .map_err(|error| {
            tracing::error!(model, error = %error, "preflight gateway model billing");
            GatewayError::new(
                GatewayErrorKind::Unavailable,
                "billing is unavailable for the selected model",
            )
        })?;

    Ok(Some(PreparedBillingContext {
        request_id: request_id.to_owned(),
        request_fingerprint: request_fingerprint(request_body),
        user_id: auth.user.id,
        api_key_id: api_key.id,
        account_id: selection.account.id,
        group_id: api_key.group_id,
        channel_id: selection.channel_policy.as_ref().map(|policy| policy.id),
        platform: selection.account.platform.to_ascii_lowercase(),
        model: model.to_owned(),
        model_mapping_chain: model_mapping_chain(selection),
        pricing_override,
        group_multiplier,
        account_multiplier,
    }))
}

const fn route_is_token_billed(kind: RouteKind) -> bool {
    matches!(
        kind,
        RouteKind::AnthropicMessages
            | RouteKind::OpenAiResponses
            | RouteKind::OpenAiResponsesCompact
            | RouteKind::OpenAiChatCompletions
            | RouteKind::OpenAiEmbeddings
            | RouteKind::GeminiGenerateContent
            | RouteKind::GeminiStreamGenerateContent
    )
}

fn billing_request_id(request_headers: &HeaderMap, response_headers: &HeaderMap) -> String {
    let candidate = response_headers
        .get("x-request-id")
        .or_else(|| request_headers.get("x-request-id"))
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let Some(candidate) = candidate else {
        return uuid::Uuid::new_v4().to_string();
    };
    if candidate.chars().count() <= 64 {
        candidate.to_owned()
    } else {
        request_fingerprint(candidate.as_bytes())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ModelMappingDecision {
    Allowed(Option<String>),
    Unsupported,
}

fn billing_source(policy: &ChannelPolicyRecord) -> &str {
    match policy.billing_model_source.trim() {
        "requested" => "requested",
        "upstream" => "upstream",
        _ => "channel_mapped",
    }
}

fn apply_channel_model_mapping(
    policy: Option<&ChannelPolicyRecord>,
    requested: Option<&str>,
) -> Option<String> {
    let requested = requested?;
    let Some(policy) = policy else {
        return Some(requested.to_owned());
    };
    let exact = policy
        .model_mapping
        .iter()
        .find(|(pattern, _)| pattern.eq_ignore_ascii_case(requested))
        .map(|(_, target)| target.as_str());
    if let Some(target) = exact {
        return Some(target.to_owned());
    }
    policy
        .model_mapping
        .iter()
        .filter_map(|(pattern, target)| {
            let prefix = pattern.strip_suffix('*')?;
            requested
                .get(..prefix.len())
                .filter(|candidate| candidate.eq_ignore_ascii_case(prefix))
                .map(|_| (prefix.len(), target.as_str()))
        })
        .max_by_key(|(length, _)| *length)
        .map_or_else(
            || Some(requested.to_owned()),
            |(_, target)| Some(target.to_owned()),
        )
}

fn find_channel_pricing<'a>(
    policy: &'a ChannelPolicyRecord,
    model: &str,
) -> Option<&'a ChannelModelPricingRecord> {
    if let Some(exact) = policy.model_pricing.iter().find(|pricing| {
        pricing
            .models
            .iter()
            .any(|pattern| pattern.eq_ignore_ascii_case(model))
    }) {
        return Some(exact);
    }
    policy
        .model_pricing
        .iter()
        .flat_map(|pricing| {
            pricing.models.iter().filter_map(move |pattern| {
                let prefix = pattern.strip_suffix('*')?;
                model
                    .get(..prefix.len())
                    .filter(|candidate| candidate.eq_ignore_ascii_case(prefix))
                    .map(|_| (prefix.len(), pricing))
            })
        })
        .max_by_key(|(length, _)| *length)
        .map(|(_, pricing)| pricing)
}

fn restriction_model<'a>(
    policy: &ChannelPolicyRecord,
    requested: Option<&'a str>,
    channel_mapped: Option<&'a str>,
    upstream: Option<&'a str>,
) -> Option<&'a str> {
    match billing_source(policy) {
        "requested" => requested,
        "upstream" => upstream,
        _ => channel_mapped,
    }
}

fn channel_model_restricted_error() -> GatewayError {
    GatewayError::new(
        GatewayErrorKind::Permission,
        "model is not available in the selected channel",
    )
}

fn channel_billing_override(
    policy: &ChannelPolicyRecord,
    model: &str,
) -> Result<Option<BillingPricingOverride>, GatewayError> {
    let Some(pricing) = find_channel_pricing(policy, model) else {
        return Ok(None);
    };
    let mode = match pricing.billing_mode.trim().to_ascii_lowercase().as_str() {
        "" | "token" => BillingPricingMode::Token,
        "per_request" => BillingPricingMode::PerRequest,
        "image" => BillingPricingMode::Image,
        mode => {
            tracing::error!(
                channel_id = policy.id,
                pricing_id = pricing.id,
                mode,
                "invalid channel billing mode"
            );
            return Err(GatewayError::new(
                GatewayErrorKind::Internal,
                "invalid channel pricing configuration",
            ));
        }
    };
    let pricing_override = ModelPricing {
        input_cost_per_token: parse_channel_price(pricing.input_price.as_deref(), "input")?,
        output_cost_per_token: parse_channel_price(pricing.output_price.as_deref(), "output")?,
        cache_creation_input_token_cost: parse_channel_price(
            pricing.cache_write_price.as_deref(),
            "cache write",
        )?,
        cache_read_input_token_cost: parse_channel_price(
            pricing.cache_read_price.as_deref(),
            "cache read",
        )?,
    };
    let intervals = pricing
        .intervals
        .iter()
        .filter(|interval| match mode {
            BillingPricingMode::Token => {
                interval.input_price.is_some()
                    || interval.output_price.is_some()
                    || interval.cache_write_price.is_some()
                    || interval.cache_read_price.is_some()
            }
            BillingPricingMode::PerRequest | BillingPricingMode::Image => {
                interval.per_request_price.is_some()
            }
        })
        .map(channel_billing_interval)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some(BillingPricingOverride {
        mode,
        pricing: pricing_override,
        per_request_price: parse_channel_price(
            pricing.per_request_price.as_deref(),
            "per request",
        )?,
        intervals,
    }))
}

fn channel_billing_interval(
    interval: &ChannelPricingIntervalRecord,
) -> Result<BillingPricingInterval, GatewayError> {
    let min_tokens = u64::try_from(interval.min_tokens)
        .map_err(|_| invalid_channel_pricing("negative interval minimum"))?;
    let max_tokens = interval
        .max_tokens
        .map(u64::try_from)
        .transpose()
        .map_err(|_| invalid_channel_pricing("negative interval maximum"))?;
    if max_tokens.is_some_and(|maximum| maximum <= min_tokens) {
        return Err(invalid_channel_pricing("invalid interval bounds"));
    }
    Ok(BillingPricingInterval {
        min_tokens,
        max_tokens,
        pricing: ModelPricing {
            input_cost_per_token: parse_channel_price(
                interval.input_price.as_deref(),
                "interval input",
            )?,
            output_cost_per_token: parse_channel_price(
                interval.output_price.as_deref(),
                "interval output",
            )?,
            cache_creation_input_token_cost: parse_channel_price(
                interval.cache_write_price.as_deref(),
                "interval cache write",
            )?,
            cache_read_input_token_cost: parse_channel_price(
                interval.cache_read_price.as_deref(),
                "interval cache read",
            )?,
        },
        per_request_price: parse_channel_price(
            interval.per_request_price.as_deref(),
            "interval per request",
        )?,
    })
}

fn parse_channel_price(raw: Option<&str>, field: &str) -> Result<Option<Decimal>, GatewayError> {
    let Some(raw) = raw else { return Ok(None) };
    let price = raw.parse::<Decimal>().map_err(|error| {
        tracing::error!(field, error = %error, "invalid channel price");
        invalid_channel_pricing("invalid decimal price")
    })?;
    if price.is_negative() {
        return Err(invalid_channel_pricing("negative price"));
    }
    Ok(Some(price))
}

fn invalid_channel_pricing(reason: &str) -> GatewayError {
    tracing::error!(reason, "invalid channel pricing configuration");
    GatewayError::new(
        GatewayErrorKind::Internal,
        "invalid channel pricing configuration",
    )
}

fn model_mapping_chain(selection: &AccountSelection) -> Option<String> {
    let requested = selection.requested_model.as_deref()?;
    let mut models = vec![requested];
    if let Some(channel_mapped) = selection.channel_mapped_model.as_deref()
        && !channel_mapped.eq_ignore_ascii_case(models.last().copied().unwrap_or_default())
    {
        models.push(channel_mapped);
    }
    if let Some(upstream) = selection.mapped_model.as_deref()
        && !upstream.eq_ignore_ascii_case(models.last().copied().unwrap_or_default())
    {
        models.push(upstream);
    }
    (models.len() > 1).then(|| models.join("->").chars().take(500).collect())
}

fn mapped_model(account: &AccountRecord, requested: Option<&str>) -> ModelMappingDecision {
    let Some(requested) = requested else {
        return ModelMappingDecision::Allowed(None);
    };
    let Some(mapping) = account
        .credentials
        .get("model_mapping")
        .and_then(Value::as_object)
    else {
        return ModelMappingDecision::Allowed(Some(requested.to_owned()));
    };
    if mapping.is_empty() {
        return ModelMappingDecision::Allowed(Some(requested.to_owned()));
    }
    let mut best: Option<(&str, &str)> = None;
    for (pattern, target) in mapping {
        let Some(target) = target
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let matches = pattern == requested
            || pattern
                .strip_suffix('*')
                .is_some_and(|prefix| requested.starts_with(prefix));
        if matches && best.is_none_or(|(current, _)| pattern.len() > current.len()) {
            best = Some((pattern, target));
        }
    }
    best.map_or(ModelMappingDecision::Unsupported, |(_, target)| {
        ModelMappingDecision::Allowed(Some(target.to_owned()))
    })
}

fn apply_model_mapping(
    mut route: GatewayRoute,
    metadata: &RequestMetadata,
    body: &[u8],
    selection: &AccountSelection,
) -> (GatewayRoute, Vec<u8>) {
    let Some(mapped) = selection.mapped_model.as_deref() else {
        return (route, body.to_vec());
    };
    if metadata.model.as_deref() == Some(mapped) {
        return (route, body.to_vec());
    }
    if let Some(original) = route.model_from_path.as_deref() {
        route.upstream_path = route.upstream_path.replacen(original, mapped, 1);
        route.model_from_path = Some(mapped.to_owned());
        return (route, body.to_vec());
    }
    let Ok(mut value) = serde_json::from_slice::<Value>(body) else {
        return (route, body.to_vec());
    };
    if let Some(object) = value.as_object_mut() {
        object.insert("model".to_owned(), Value::String(mapped.to_owned()));
    }
    let rewritten = serde_json::to_vec(&value).unwrap_or_else(|_| body.to_vec());
    (route, rewritten)
}

fn upstream_credentials(
    account: &AccountRecord,
    protocol: Protocol,
) -> Result<(String, Credential), String> {
    let base_url = credential_string(&account.credentials, "base_url").unwrap_or_else(|| {
        match account.platform.as_str() {
            "openai" => DEFAULT_OPENAI_BASE_URL,
            "gemini" => DEFAULT_GEMINI_BASE_URL,
            "grok" => DEFAULT_GROK_BASE_URL,
            _ => DEFAULT_ANTHROPIC_BASE_URL,
        }
        .to_owned()
    });
    let api_key = credential_string(&account.credentials, "api_key")
        .or_else(|| credential_string(&account.credentials, "access_token"))
        .or_else(|| credential_string(&account.credentials, "token"))
        .ok_or_else(|| format!("upstream account {} has no usable credential", account.id))?;
    let uses_api_key_header = matches!(
        account.account_type.to_ascii_lowercase().as_str(),
        "apikey" | "upstream"
    ) && protocol != Protocol::OpenAi;
    let credential = if uses_api_key_header {
        Credential::ApiKey(api_key)
    } else {
        Credential::Bearer(api_key)
    };
    Ok((base_url, credential))
}

async fn refresh_account_token(
    client: &reqwest::Client,
    pool: &PgPool,
    account: &AccountRecord,
    now_unix_ms: i64,
) -> Result<CachedAccessToken, String> {
    if account.account_type.eq_ignore_ascii_case("service_account") {
        let key = service_account_key(&account.credentials).map_err(|error| error.to_string())?;
        let assertion = service_account_assertion(&key, now_unix_ms.div_euclid(1_000))
            .map_err(|error| error.to_string())?;
        let response = client
            .post(VERTEX_TOKEN_URL)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", assertion.as_str()),
            ])
            .send()
            .await
            .map_err(|error| format!("service-account token request failed: {error}"))?;
        return parse_token_response(response, now_unix_ms).await;
    }

    if account.account_type.eq_ignore_ascii_case("setup-token") {
        let token = adapter_credential(&account.credentials, "access_token")
            .or_else(|| adapter_credential(&account.credentials, "token"))
            .ok_or_else(|| "setup-token account has no access_token".to_owned())?;
        return Ok(CachedAccessToken {
            token,
            expires_at_unix_ms: i64::MAX,
            refresh_token: None,
        });
    }

    let refresh_token = adapter_credential(&account.credentials, "refresh_token")
        .ok_or_else(|| format!("OAuth account {} has no refresh_token", account.id))?;
    let platform = account.platform.trim().to_ascii_lowercase();
    let response = match platform.as_str() {
        "anthropic" => {
            client
                .post(ANTHROPIC_OAUTH_TOKEN_URL)
                .header(header::ACCEPT, "application/json, text/plain, */*")
                .header(header::USER_AGENT, "axios/1.13.6")
                .json(&json!({
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": ANTHROPIC_OAUTH_CLIENT_ID,
                }))
                .send()
                .await
        }
        "openai" => {
            let client_id = adapter_credential(&account.credentials, "client_id")
                .unwrap_or_else(|| OPENAI_OAUTH_CLIENT_ID.to_owned());
            client
                .post(OPENAI_OAUTH_TOKEN_URL)
                .header(header::USER_AGENT, "codex-cli/0.91.0")
                .form(&[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", refresh_token.as_str()),
                    ("client_id", client_id.as_str()),
                    ("scope", "openid profile email"),
                ])
                .send()
                .await
        }
        "grok" => {
            grok_refresh_request(client, account, &refresh_token)
                .send()
                .await
        }
        "gemini" | "antigravity" => {
            let antigravity = platform == "antigravity";
            let default_client_id = if antigravity {
                ANTIGRAVITY_CLIENT_ID
            } else {
                GEMINI_CLI_CLIENT_ID
            };
            let default_secret = if antigravity {
                ANTIGRAVITY_CLIENT_SECRET
            } else {
                GEMINI_CLI_CLIENT_SECRET
            };
            let client_id = adapter_credential(&account.credentials, "client_id")
                .or_else(|| adapter_credential(&account.credentials, "oauth_client_id"))
                .unwrap_or_else(|| default_client_id.to_owned());
            let client_secret = adapter_credential(&account.credentials, "client_secret")
                .or_else(|| adapter_credential(&account.credentials, "oauth_client_secret"))
                .or_else(|| {
                    antigravity
                        .then(|| std::env::var("ANTIGRAVITY_OAUTH_CLIENT_SECRET").ok())
                        .flatten()
                })
                .or_else(|| {
                    (!antigravity)
                        .then(|| std::env::var("GEMINI_CLI_OAUTH_CLIENT_SECRET").ok())
                        .flatten()
                })
                .unwrap_or_else(|| default_secret.to_owned());
            client
                .post(GOOGLE_OAUTH_TOKEN_URL)
                .form(&[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", refresh_token.as_str()),
                    ("client_id", client_id.as_str()),
                    ("client_secret", client_secret.as_str()),
                ])
                .send()
                .await
        }
        _ => return Err(format!("OAuth platform {platform:?} is not supported")),
    }
    .map_err(|error| format!("OAuth token refresh failed: {error}"))?;

    let token = parse_token_response(response, now_unix_ms).await?;
    let mut credentials = account
        .credentials
        .as_object()
        .cloned()
        .ok_or_else(|| "account credentials must be a JSON object".to_owned())?;
    credentials.insert(
        "access_token".to_owned(),
        Value::String(token.token.clone()),
    );
    credentials.insert(
        "expires_at".to_owned(),
        Value::String(token.expires_at_unix_ms.div_euclid(1_000).to_string()),
    );
    if let Some(refresh_token) = token.refresh_token.as_ref() {
        credentials.insert(
            "refresh_token".to_owned(),
            Value::String(refresh_token.clone()),
        );
    }
    sqlx::query(
        "UPDATE accounts SET credentials = $2::jsonb, updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(account.id)
    .bind(Value::Object(credentials).to_string())
    .execute(pool)
    .await
    .map_err(|error| format!("persist refreshed account token: {error}"))?;
    Ok(token)
}

fn grok_refresh_request(
    client: &reqwest::Client,
    account: &AccountRecord,
    refresh_token: &str,
) -> reqwest::RequestBuilder {
    let client_id = adapter_credential(&account.credentials, "client_id")
        .or_else(|| adapter_credential(&account.credentials, "oauth_client_id"))
        .unwrap_or_else(|| GROK_OAUTH_CLIENT_ID.to_owned());
    client
        .post(GROK_OAUTH_TOKEN_URL)
        .header(header::USER_AGENT, "sub2api-grok-oauth/1.0")
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", client_id.as_str()),
        ])
}

async fn parse_token_response(
    response: reqwest::Response,
    now_unix_ms: i64,
) -> Result<CachedAccessToken, String> {
    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|error| format!("read token response: {error}"))?;
    if body.len() > 1024 * 1024 {
        return Err("token response exceeded 1 MiB".to_owned());
    }
    let value: Value = serde_json::from_slice(&body)
        .map_err(|_| format!("token endpoint returned invalid JSON ({status})"))?;
    if !status.is_success() {
        let message = value
            .get("error_description")
            .or_else(|| value.get("error"))
            .and_then(Value::as_str)
            .unwrap_or("token refresh was rejected");
        return Err(format!("token endpoint returned {status}: {message}"));
    }
    let token = value
        .get("access_token")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| "token response has no access_token".to_owned())?
        .to_owned();
    let expires_in = value
        .get("expires_in")
        .and_then(|value| {
            value
                .as_i64()
                .or_else(|| value.as_str()?.trim().parse().ok())
        })
        .filter(|seconds| *seconds > 0)
        .unwrap_or(3_600);
    Ok(CachedAccessToken {
        token,
        expires_at_unix_ms: now_unix_ms.saturating_add(expires_in.saturating_mul(1_000)),
        refresh_token: value
            .get("refresh_token")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .map(ToOwned::to_owned),
    })
}

fn credential_expiry_unix_ms(credentials: &Value) -> Option<i64> {
    let value = credentials.get("expires_at")?;
    if let Some(raw) = value.as_i64() {
        return Some(if raw > 10_000_000_000 {
            raw
        } else {
            raw.saturating_mul(1_000)
        });
    }
    let raw = value.as_str()?.trim();
    if let Ok(timestamp) = raw.parse::<i64>() {
        return Some(if timestamp > 10_000_000_000 {
            timestamp
        } else {
            timestamp.saturating_mul(1_000)
        });
    }
    chrono::DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|timestamp| timestamp.timestamp_millis())
}

fn should_use_openai_responses(account: &AccountRecord) -> bool {
    match account
        .extra
        .get("openai_responses_mode")
        .and_then(Value::as_str)
    {
        Some("force_responses") => return true,
        Some("force_chat_completions") => return false,
        _ => {}
    }
    account
        .extra
        .get("openai_responses_supported")
        .and_then(Value::as_bool)
        != Some(false)
}

fn credential_string(credentials: &Value, key: &str) -> Option<String> {
    credentials
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

async fn load_usage_summary(pool: &PgPool, api_key_id: i64) -> Result<Value, sqlx::Error> {
    let row = sqlx::query(
        r"
SELECT
    COUNT(*)::bigint AS total_requests,
    COALESCE(SUM(input_tokens), 0)::bigint AS total_input_tokens,
    COALESCE(SUM(output_tokens), 0)::bigint AS total_output_tokens,
    COALESCE(SUM(cache_creation_tokens), 0)::bigint AS total_cache_creation_tokens,
    COALESCE(SUM(cache_read_tokens), 0)::bigint AS total_cache_read_tokens,
    COALESCE(SUM(total_cost), 0)::text AS total_cost,
    COALESCE(SUM(actual_cost), 0)::text AS total_actual_cost,
    COUNT(*) FILTER (WHERE created_at >= CURRENT_DATE)::bigint AS today_requests,
    COALESCE(SUM(input_tokens) FILTER (WHERE created_at >= CURRENT_DATE), 0)::bigint AS today_input_tokens,
    COALESCE(SUM(output_tokens) FILTER (WHERE created_at >= CURRENT_DATE), 0)::bigint AS today_output_tokens,
    COALESCE(SUM(cache_creation_tokens) FILTER (WHERE created_at >= CURRENT_DATE), 0)::bigint AS today_cache_creation_tokens,
    COALESCE(SUM(cache_read_tokens) FILTER (WHERE created_at >= CURRENT_DATE), 0)::bigint AS today_cache_read_tokens,
    COALESCE(SUM(total_cost) FILTER (WHERE created_at >= CURRENT_DATE), 0)::text AS today_cost,
    COALESCE(SUM(actual_cost) FILTER (WHERE created_at >= CURRENT_DATE), 0)::text AS today_actual_cost,
    COALESCE(AVG(duration_ms), 0)::double precision AS average_duration_ms
FROM usage_logs
WHERE api_key_id = $1
",
    )
    .bind(api_key_id)
    .fetch_one(pool)
    .await?;
    let total_input: i64 = row.try_get("total_input_tokens")?;
    let total_output: i64 = row.try_get("total_output_tokens")?;
    let total_creation: i64 = row.try_get("total_cache_creation_tokens")?;
    let total_read: i64 = row.try_get("total_cache_read_tokens")?;
    let today_input: i64 = row.try_get("today_input_tokens")?;
    let today_output: i64 = row.try_get("today_output_tokens")?;
    let today_creation: i64 = row.try_get("today_cache_creation_tokens")?;
    let today_read: i64 = row.try_get("today_cache_read_tokens")?;
    Ok(json!({
        "today": {
            "requests": row.try_get::<i64, _>("today_requests")?,
            "input_tokens": today_input,
            "output_tokens": today_output,
            "cache_creation_tokens": today_creation,
            "cache_read_tokens": today_read,
            "total_tokens": today_input + today_output + today_creation + today_read,
            "cost": decimal_json(&row.try_get::<String, _>("today_cost")?),
            "actual_cost": decimal_json(&row.try_get::<String, _>("today_actual_cost")?),
        },
        "total": {
            "requests": row.try_get::<i64, _>("total_requests")?,
            "input_tokens": total_input,
            "output_tokens": total_output,
            "cache_creation_tokens": total_creation,
            "cache_read_tokens": total_read,
            "total_tokens": total_input + total_output + total_creation + total_read,
            "cost": decimal_json(&row.try_get::<String, _>("total_cost")?),
            "actual_cost": decimal_json(&row.try_get::<String, _>("total_actual_cost")?),
        },
        "average_duration_ms": row.try_get::<f64, _>("average_duration_ms")?,
        "rpm": 0,
        "tpm": 0,
    }))
}

fn usage_rate_limits(row: &sqlx::postgres::PgRow) -> Vec<Value> {
    [
        ("5h", "rate_limit_5h", "usage_5h", "window_5h_start"),
        ("1d", "rate_limit_1d", "usage_1d", "window_1d_start"),
        ("7d", "rate_limit_7d", "usage_7d", "window_7d_start"),
    ]
    .into_iter()
    .filter_map(|(window, limit_column, usage_column, start_column)| {
        let limit = row_decimal(row, limit_column);
        if !decimal_is_positive(&limit) {
            return None;
        }
        let used = row_decimal(row, usage_column);
        let mut value = json!({
            "window": window,
            "limit": limit,
            "used": used,
        });
        if let Ok(Some(start)) = row.try_get::<Option<String>, _>(start_column) {
            value["window_start"] = Value::String(start);
        }
        Some(value)
    })
    .collect()
}

fn row_decimal(row: &sqlx::postgres::PgRow, column: &str) -> Value {
    row.try_get::<String, _>(column)
        .map_or(Value::Null, |raw| decimal_json(&raw))
}

fn decimal_json(raw: &str) -> Value {
    serde_json::from_str(raw.trim()).unwrap_or(Value::Null)
}

fn decimal_is_positive(value: &Value) -> bool {
    value.as_number().is_some_and(|number| {
        let value = number.to_string();
        !value.starts_with('-')
            && value
                .bytes()
                .any(|byte| byte.is_ascii_digit() && byte != b'0')
    })
}

fn auth_gateway_error(error: &AuthError) -> GatewayError {
    let kind = match error.status_code() {
        StatusCode::UNAUTHORIZED => GatewayErrorKind::Authentication,
        StatusCode::FORBIDDEN => GatewayErrorKind::Permission,
        StatusCode::TOO_MANY_REQUESTS => GatewayErrorKind::RateLimit,
        StatusCode::BAD_REQUEST => GatewayErrorKind::InvalidRequest,
        _ => GatewayErrorKind::Internal,
    };
    let message = match error {
        AuthError::Credential(CredentialError::ApiKeyInQueryDeprecated) => error.to_string(),
        AuthError::Repository(_) => "authentication service is unavailable".to_owned(),
        _ => error.code().to_owned(),
    };
    GatewayError::new(kind, message)
}

fn authority_gateway_error(error: &AuthorityError) -> GatewayError {
    let kind = match error.kind() {
        AuthorityErrorKind::Limited => GatewayErrorKind::RateLimit,
        AuthorityErrorKind::Permission => GatewayErrorKind::Permission,
        AuthorityErrorKind::Unavailable => GatewayErrorKind::Unavailable,
        AuthorityErrorKind::InvalidState => GatewayErrorKind::Internal,
    };
    GatewayError::new(kind, error.to_string())
}

fn gateway_error_response(route: &GatewayRoute, error: &GatewayError) -> Response {
    (error.status(), Json(error.json(route.protocol))).into_response()
}

fn passthrough_error_response(
    route: &GatewayRoute,
    upstream_error: &GatewayError,
    decision: ErrorPassthroughDecision,
) -> Response {
    let mut error = upstream_error.clone();
    error.kind = GatewayErrorKind::Upstream;
    error.upstream_status = Some(decision.status);
    if let Some(message) = decision.message {
        error.message = message;
    }
    let mut body = error.json(route.protocol);
    if route.protocol == Protocol::Gemini {
        body["error"]["code"] = Value::from(decision.status.as_u16());
    }
    (decision.status, Json(body)).into_response()
}

fn moderation_error_response(route: &GatewayRoute, status: StatusCode, message: &str) -> Response {
    let error = GatewayError::new(GatewayErrorKind::Permission, message);
    (status, Json(error.json(route.protocol))).into_response()
}

fn buffered_response(status: StatusCode, headers: HeaderMap, body: Vec<u8>) -> Response {
    let plan = prepare_passthrough(UpstreamResponse::<()> {
        status,
        headers,
        body: PassthroughBody::Buffered(body),
    });
    let mut response = Response::new(match plan.body {
        PassthroughBody::Buffered(body) => Body::from(body),
        PassthroughBody::Stream(()) => Body::empty(),
    });
    *response.status_mut() = plan.status;
    *response.headers_mut() = plan.headers;
    response
}

fn normalize_converted_response_headers(headers: &mut HeaderMap) {
    headers.remove(header::CONTENT_LENGTH);
    headers.remove(header::CONTENT_ENCODING);
    headers.remove(header::ETAG);
    headers.remove("content-md5");
    headers.remove("digest");
    headers.insert(
        header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
}

fn stream_response(
    status: StatusCode,
    mut headers: HeaderMap,
    response: reqwest::Response,
    bridge: Option<SseBridge>,
    stream_wire: StreamWire,
    leases: GatewayLeases,
    billing: StreamBilling,
) -> Response {
    let stream = LeasedStream {
        inner: Box::pin(response.bytes_stream()),
        bedrock: (stream_wire == StreamWire::BedrockEventStream)
            .then(BedrockEventStreamDecoder::default),
        bridge,
        leases: Some(leases),
        billing: billing.observer,
        billing_reservation: billing.reservation,
        billing_finalize: None,
        billing_finalize_started: false,
        terminal: None,
        billing_writes: billing.writes,
        billing_route: billing.route,
        request_started: billing.request_started,
        billing_backpressure: billing.backpressure,
        idle_timeout: StreamIdleTimeout::new(billing.idle_timeout),
        timeout_context: Some(billing.timeout_context),
        finished: false,
    };
    if stream.bridge.is_some() {
        normalize_converted_stream_headers(&mut headers);
    }
    let plan = prepare_passthrough(UpstreamResponse {
        status,
        headers,
        body: PassthroughBody::Stream(stream),
    });
    let mut response = Response::new(match plan.body {
        PassthroughBody::Stream(stream) => Body::from_stream(stream),
        PassthroughBody::Buffered(body) => Body::from(body),
    });
    *response.status_mut() = plan.status;
    *response.headers_mut() = plan.headers;
    response
}

fn normalize_converted_stream_headers(headers: &mut HeaderMap) {
    headers.remove(header::CONTENT_LENGTH);
    headers.remove(header::CONTENT_ENCODING);
    headers.remove(header::ETAG);
    headers.remove("content-md5");
    headers.remove("digest");
    headers.insert(
        header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/event-stream"),
    );
}

fn elapsed_millis(started: Instant) -> i32 {
    i32::try_from(started.elapsed().as_millis()).unwrap_or(i32::MAX)
}

async fn read_limited(response: reqwest::Response, limit: usize) -> Vec<u8> {
    let mut stream = response.bytes_stream();
    let mut body = Vec::with_capacity(limit.min(16 * 1024));
    while let Some(chunk) = stream.next().await {
        let Ok(chunk) = chunk else {
            break;
        };
        let remaining = limit.saturating_sub(body.len());
        if remaining == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
    }
    body
}

fn now_unix_millis() -> i64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    i64::try_from(millis).unwrap_or(i64::MAX)
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use tokio::sync::Notify;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;
    use crate::{
        billing::{CostBreakdown, TokenUsage},
        repository::{
            GroupRecord, STATUS_ACTIVE, SubscriptionBillingRecord, UnixMillis, UserRecord,
        },
    };
    use serde_json::json;

    struct NoopBillingSink;

    impl BatchSink<BillingEvent> for NoopBillingSink {
        fn write_batch<'a>(&'a self, _batch: &'a [BillingEvent]) -> BoxFlushFuture<'a> {
            Box::pin(async { Ok(()) })
        }
    }

    struct NoopGatewayMutationSink;

    impl BatchSink<GatewayMutation> for NoopGatewayMutationSink {
        fn write_batch<'a>(&'a self, _batch: &'a [GatewayMutation]) -> BoxFlushFuture<'a> {
            Box::pin(async { Ok(()) })
        }
    }

    struct BlockedBillingSink {
        started: Arc<Notify>,
    }

    impl BatchSink<BillingEvent> for BlockedBillingSink {
        fn write_batch<'a>(&'a self, _batch: &'a [BillingEvent]) -> BoxFlushFuture<'a> {
            Box::pin(async move {
                self.started.notify_one();
                std::future::pending::<()>().await;
                Ok(())
            })
        }
    }

    struct GateBillingSink {
        first: AtomicBool,
        started: Arc<Notify>,
        release: Arc<Notify>,
    }

    impl BatchSink<BillingEvent> for GateBillingSink {
        fn write_batch<'a>(&'a self, _batch: &'a [BillingEvent]) -> BoxFlushFuture<'a> {
            Box::pin(async move {
                if !self.first.swap(true, Ordering::SeqCst) {
                    self.started.notify_one();
                    self.release.notified().await;
                }
                Ok(())
            })
        }
    }

    fn account(mapping: &Value) -> AccountRecord {
        AccountRecord {
            id: 7,
            name: "test".to_owned(),
            notes: None,
            platform: "openai".to_owned(),
            account_type: "apikey".to_owned(),
            credentials: json!({
                "api_key": "upstream",
                "model_mapping": mapping.clone(),
            }),
            extra: json!({}),
            proxy_id: None,
            proxy: None,
            proxy_fallback_origin_id: None,
            concurrency: 1,
            load_factor: None,
            priority: 50,
            rate_multiplier: "1".to_owned(),
            status: STATUS_ACTIVE.to_owned(),
            error_message: None,
            expires_at_unix_ms: None,
            auto_pause_on_expired: true,
            schedulable: true,
            rate_limit_reset_at_unix_ms: None,
            overload_until_unix_ms: None,
            temp_unschedulable_until_unix_ms: None,
            temp_unschedulable_reason: None,
            parent_account_id: None,
            quota_dimension: "global".to_owned(),
            group_ids: vec![1],
        }
    }

    fn user() -> UserRecord {
        UserRecord {
            id: 11,
            email: "user@example.com".to_owned(),
            username: "user".to_owned(),
            password_hash: "hash".to_owned(),
            auth_generation: 0,
            role: "user".to_owned(),
            balance: "10".to_owned(),
            concurrency: 5,
            status: STATUS_ACTIVE.to_owned(),
            rpm_limit: 0,
            allowed_group_ids: vec![7],
        }
    }

    fn subscription_group() -> GroupRecord {
        GroupRecord {
            id: 7,
            name: "subscription".to_owned(),
            platform: "openai".to_owned(),
            rate_multiplier: "1".to_owned(),
            is_exclusive: false,
            status: STATUS_ACTIVE.to_owned(),
            subscription_type: "subscription".to_owned(),
            rpm_limit: 0,
        }
    }

    fn subscription(starts_at_unix_ms: i64, expires_at_unix_ms: i64) -> SubscriptionBillingRecord {
        SubscriptionBillingRecord {
            id: 31,
            user_id: 11,
            group_id: 7,
            starts_at_unix_ms,
            expires_at_unix_ms,
            daily_limit_usd: None,
            weekly_limit_usd: None,
            monthly_limit_usd: None,
            daily_usage_usd: "0".to_owned(),
            weekly_usage_usd: "0".to_owned(),
            monthly_usage_usd: "0".to_owned(),
            daily_window_start_unix_ms: None,
            weekly_window_start_unix_ms: None,
            monthly_window_start_unix_ms: None,
        }
    }

    fn auth_context(subscription: Option<SubscriptionBillingRecord>) -> AuthContext {
        let user = user();
        AuthContext {
            subject: AuthSubject {
                user_id: user.id,
                concurrency: user.concurrency,
            },
            role: user.role.clone(),
            user,
            api_key: Some(ApiKeyRecord {
                id: 21,
                user_id: 11,
                key: "sk-test".to_owned(),
                name: "test".to_owned(),
                group_id: Some(7),
                status: STATUS_ACTIVE.to_owned(),
                ip_whitelist: Vec::new(),
                ip_blacklist: Vec::new(),
                quota: "0".to_owned(),
                quota_used: "0".to_owned(),
                expires_at_unix_ms: None,
                rate_limit_5h: "0".to_owned(),
                rate_limit_1d: "0".to_owned(),
                rate_limit_7d: "0".to_owned(),
                usage_5h: "0".to_owned(),
                usage_1d: "0".to_owned(),
                usage_7d: "0".to_owned(),
                window_5h_start_unix_ms: None,
                window_1d_start_unix_ms: None,
                window_7d_start_unix_ms: None,
                group_rpm_override: None,
            }),
            group: Some(subscription_group()),
            subscription,
            platform_quotas: Vec::new(),
            jwt_claims: None,
        }
    }

    fn billing_event(account_id: i64) -> BillingEvent {
        let cost = "0.25".parse::<Decimal>().expect("cost should parse");
        BillingEvent {
            request_id: "request-1".to_owned(),
            request_fingerprint: request_fingerprint(b"request"),
            user_id: 11,
            api_key_id: 21,
            account_id,
            group_id: Some(7),
            channel_id: None,
            platform: "openai".to_owned(),
            model: "test-model".to_owned(),
            model_mapping_chain: None,
            billing_mode: "token".to_owned(),
            usage: TokenUsage {
                input_tokens: 1,
                ..TokenUsage::default()
            },
            costs: CostBreakdown {
                input_cost: cost,
                total_cost: cost,
                actual_cost: cost,
                account_cost: cost,
                ..CostBreakdown::default()
            },
            group_multiplier: Decimal::ONE,
            account_multiplier: Decimal::ONE,
            stream: false,
            request_type: RequestType::Sync,
            duration_ms: None,
        }
    }

    #[test]
    fn longest_model_mapping_wildcard_wins() {
        let account = account(&json!({"gpt-*": "broad", "gpt-5*": "specific"}));
        assert_eq!(
            mapped_model(&account, Some("gpt-5.4")),
            ModelMappingDecision::Allowed(Some("specific".to_owned()))
        );
    }

    #[test]
    fn configured_mapping_is_a_model_allowlist() {
        let account = account(&json!({"gpt-5": "gpt-5.4"}));
        assert_eq!(
            mapped_model(&account, Some("claude")),
            ModelMappingDecision::Unsupported
        );
    }

    fn channel_policy(
        source: &str,
        pricing: Vec<ChannelModelPricingRecord>,
    ) -> ChannelPolicyRecord {
        ChannelPolicyRecord {
            id: 19,
            features: String::new(),
            features_config: json!({}),
            model_mapping: std::collections::BTreeMap::from([
                ("public-*".to_owned(), "gpt-broad".to_owned()),
                ("public-5*".to_owned(), "gpt-5".to_owned()),
                ("public-5.4".to_owned(), "gpt-5.4".to_owned()),
            ]),
            billing_model_source: source.to_owned(),
            restrict_models: true,
            allowed_models: pricing
                .iter()
                .flat_map(|entry| entry.models.iter().cloned())
                .collect(),
            model_pricing: pricing,
        }
    }

    fn channel_price(id: i64, models: &[&str]) -> ChannelModelPricingRecord {
        ChannelModelPricingRecord {
            id,
            models: models.iter().map(ToString::to_string).collect(),
            billing_mode: "token".to_owned(),
            input_price: Some("0.000001".to_owned()),
            output_price: Some("0.000002".to_owned()),
            cache_write_price: None,
            cache_read_price: None,
            per_request_price: None,
            intervals: Vec::new(),
        }
    }

    #[test]
    fn channel_mapping_prefers_exact_then_longest_wildcard() {
        let policy = channel_policy("channel_mapped", Vec::new());
        assert_eq!(
            apply_channel_model_mapping(Some(&policy), Some("PUBLIC-5.4")),
            Some("gpt-5.4".to_owned())
        );
        assert_eq!(
            apply_channel_model_mapping(Some(&policy), Some("public-5.3")),
            Some("gpt-5".to_owned())
        );
        assert_eq!(
            apply_channel_model_mapping(Some(&policy), Some("other")),
            Some("other".to_owned())
        );
    }

    #[test]
    fn channel_mapping_runs_before_account_mapping() {
        let policy = channel_policy("channel_mapped", Vec::new());
        let channel_mapped = apply_channel_model_mapping(Some(&policy), Some("public-5.3"));
        let account = account(&json!({"gpt-5": "upstream-gpt"}));
        assert_eq!(
            mapped_model(&account, channel_mapped.as_deref()),
            ModelMappingDecision::Allowed(Some("upstream-gpt".to_owned()))
        );
    }

    #[test]
    fn channel_pricing_prefers_exact_then_longest_wildcard() {
        let policy = channel_policy(
            "channel_mapped",
            vec![
                channel_price(1, &["gpt-*"]),
                channel_price(2, &["gpt-5*"]),
                channel_price(3, &["gpt-5.4"]),
            ],
        );
        assert_eq!(
            find_channel_pricing(&policy, "GPT-5.4").map(|item| item.id),
            Some(3)
        );
        assert_eq!(
            find_channel_pricing(&policy, "gpt-5.3").map(|item| item.id),
            Some(2)
        );
        assert_eq!(
            find_channel_pricing(&policy, "gpt-4").map(|item| item.id),
            Some(1)
        );
        assert!(find_channel_pricing(&policy, "claude").is_none());
    }

    #[test]
    fn restriction_uses_configured_billing_model_source() {
        let requested = channel_policy("requested", Vec::new());
        let channel_mapped = channel_policy("channel_mapped", Vec::new());
        let upstream = channel_policy("upstream", Vec::new());
        assert_eq!(
            restriction_model(&requested, Some("a"), Some("b"), Some("c")),
            Some("a")
        );
        assert_eq!(
            restriction_model(&channel_mapped, Some("a"), Some("b"), Some("c")),
            Some("b")
        );
        assert_eq!(
            restriction_model(&upstream, Some("a"), Some("b"), Some("c")),
            Some("c")
        );
    }

    #[test]
    fn openai_responses_capability_matches_go_fallback_contract() {
        let mut candidate = account(&json!({}));
        assert!(should_use_openai_responses(&candidate));

        candidate.extra = json!({"openai_responses_supported": false});
        assert!(!should_use_openai_responses(&candidate));

        candidate.extra = json!({
            "openai_responses_supported": false,
            "openai_responses_mode": "force_responses"
        });
        assert!(should_use_openai_responses(&candidate));

        candidate.extra = json!({
            "openai_responses_supported": true,
            "openai_responses_mode": "force_chat_completions"
        });
        assert!(!should_use_openai_responses(&candidate));
    }

    #[test]
    fn media_routes_enforce_the_go_platform_gates() {
        assert_eq!(
            unsupported_platform_message(RouteKind::OpenAiEmbeddings, "anthropic"),
            Some("Embeddings API is not supported for this platform")
        );
        assert!(unsupported_platform_message(RouteKind::OpenAiImageGenerations, "grok").is_none());
        assert_eq!(
            unsupported_platform_message(RouteKind::OpenAiVideoGenerations, "openai"),
            Some("Videos API is not supported for this platform")
        );
    }

    #[test]
    fn content_moderation_covers_all_generation_routes() {
        assert!(route_requires_content_moderation(
            RouteKind::AnthropicMessages
        ));
        assert!(route_requires_content_moderation(
            RouteKind::OpenAiResponses
        ));
        assert!(route_requires_content_moderation(
            RouteKind::GeminiGenerateContent
        ));
        assert!(!route_requires_content_moderation(RouteKind::OpenAiModels));
    }

    #[test]
    fn subscription_windows_reset_at_the_exact_duration_boundary() {
        let start = 1_000_000;
        for duration in [
            SUBSCRIPTION_DAY_MILLIS,
            SUBSCRIPTION_WEEK_MILLIS,
            SUBSCRIPTION_MONTH_MILLIS,
        ] {
            assert!(
                !subscription_window_expired(Some(start), duration, start + duration - 1)
                    .expect("window arithmetic should succeed")
            );
            assert!(
                subscription_window_expired(Some(start), duration, start + duration)
                    .expect("window arithmetic should succeed")
            );
        }
        assert!(
            !subscription_window_expired(None, SUBSCRIPTION_DAY_MILLIS, i64::MAX)
                .expect("an inactive window is not expired")
        );
    }

    #[test]
    fn pending_subscription_cost_closes_the_limit_at_equality() {
        let now = 100 * SUBSCRIPTION_DAY_MILLIS;
        let mut subscription = subscription(0, now + SUBSCRIPTION_MONTH_MILLIS);
        subscription.daily_limit_usd = Some("1".to_owned());
        subscription.daily_usage_usd = "0.75".to_owned();
        subscription.daily_window_start_unix_ms = Some(now);
        let auth = auth_context(Some(subscription));
        let pending = PendingBilling::default();
        let _reservation = pending
            .reserve(&billing_event(7))
            .expect("pending billing event should reserve");

        let error = validate_pending_subscription(&auth, &pending, now)
            .expect_err("pending cost reaching the limit must reject");
        assert_eq!(error.kind, GatewayErrorKind::RateLimit);
        assert!(error.message.contains("daily"));
    }

    #[test]
    fn expired_subscription_window_zeros_durable_usage_before_overlay() {
        let now = 100 * SUBSCRIPTION_DAY_MILLIS;
        let mut subscription = subscription(0, now + SUBSCRIPTION_MONTH_MILLIS);
        subscription.weekly_limit_usd = Some("1".to_owned());
        subscription.weekly_usage_usd = "1".to_owned();
        subscription.weekly_window_start_unix_ms = Some(now - SUBSCRIPTION_WEEK_MILLIS);
        let auth = auth_context(Some(subscription));

        validate_pending_subscription(&auth, &PendingBilling::default(), now)
            .expect("usage from an expired weekly window must reset to zero");
    }

    #[test]
    fn one_time_daily_and_unactivated_windows_preserve_durable_usage() {
        let now = 100 * SUBSCRIPTION_DAY_MILLIS;
        let starts_at = now - SUBSCRIPTION_DAY_MILLIS / 2;
        let mut one_time = subscription(starts_at, starts_at + SUBSCRIPTION_DAY_MILLIS);
        one_time.daily_limit_usd = Some("1".to_owned());
        one_time.daily_usage_usd = "1".to_owned();
        one_time.daily_window_start_unix_ms = Some(now - 2 * SUBSCRIPTION_DAY_MILLIS);
        let error = validate_pending_subscription(
            &auth_context(Some(one_time)),
            &PendingBilling::default(),
            now,
        )
        .expect_err("one-time daily quota must not reset after 24 hours");
        assert_eq!(error.kind, GatewayErrorKind::RateLimit);

        let mut unactivated = subscription(0, now + SUBSCRIPTION_MONTH_MILLIS);
        unactivated.monthly_limit_usd = Some("1".to_owned());
        unactivated.monthly_usage_usd = "1".to_owned();
        let error = validate_pending_subscription(
            &auth_context(Some(unactivated)),
            &PendingBilling::default(),
            now,
        )
        .expect_err("a NULL window start must not discard durable usage");
        assert_eq!(error.kind, GatewayErrorKind::RateLimit);
    }

    #[test]
    fn subscription_group_requires_an_active_matching_snapshot() {
        let now = 100 * SUBSCRIPTION_DAY_MILLIS;
        let missing =
            validate_pending_subscription(&auth_context(None), &PendingBilling::default(), now)
                .expect_err("subscription group without active subscription must reject");
        assert_eq!(missing.kind, GatewayErrorKind::Permission);

        let expired = subscription(0, now);
        let error = validate_pending_subscription(
            &auth_context(Some(expired)),
            &PendingBilling::default(),
            now,
        )
        .expect_err("cached subscription expiring at now must reject");
        assert_eq!(error.kind, GatewayErrorKind::Permission);
    }

    #[test]
    fn pending_account_cost_applies_to_total_and_active_window_quotas() {
        let pending = PendingBilling::default();
        let _reservation = pending
            .reserve(&billing_event(7))
            .expect("pending billing event should reserve");
        let mut candidate = account(&json!({}));
        candidate.extra = json!({"quota_limit": 1, "quota_used": 0.8});
        assert!(
            !account_has_effective_quota(&candidate, &pending).expect("total quota should parse")
        );

        let recent = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        candidate.extra = json!({
            "quota_daily_limit": 1,
            "quota_daily_used": 0.8,
            "quota_daily_start": recent,
        });
        assert!(
            !account_has_effective_quota(&candidate, &pending).expect("daily quota should parse")
        );

        let expired = (chrono::Utc::now() - chrono::Duration::hours(25)).to_rfc3339();
        candidate.extra["quota_daily_start"] = Value::String(expired);
        assert!(
            account_has_effective_quota(&candidate, &pending)
                .expect("expired daily usage should reset before pending overlay")
        );
    }

    #[test]
    fn user_platform_quota_counts_pending_cost_at_the_limit() {
        let now = now_unix_millis();
        let mut auth = auth_context(None);
        auth.group
            .as_mut()
            .expect("test group should exist")
            .subscription_type = "standard".to_owned();
        auth.platform_quotas = vec![UserPlatformQuotaRecord {
            platform: "openai".to_owned(),
            daily_limit_usd: Some("0.25".to_owned()),
            weekly_limit_usd: None,
            monthly_limit_usd: None,
            daily_usage_usd: "0".to_owned(),
            weekly_usage_usd: "0".to_owned(),
            monthly_usage_usd: "0".to_owned(),
            daily_window_start_unix_ms: Some(shanghai_day_start(now)),
            weekly_window_start_unix_ms: None,
            monthly_window_start_unix_ms: None,
        }];
        let pending = PendingBilling::default();
        let _reservation = pending
            .reserve(&billing_event(7))
            .expect("pending billing event should reserve");

        let error = validate_user_platform_quota(&auth, "openai", &pending, now)
            .expect_err("pending cost reaching the platform limit must reject");
        assert_eq!(error.kind, GatewayErrorKind::RateLimit);
        assert!(error.message.contains("daily openai"));
    }

    #[test]
    fn expired_user_platform_windows_reset_durable_usage_but_keep_new_pending_cost() {
        let now = now_unix_millis();
        let mut auth = auth_context(None);
        auth.group
            .as_mut()
            .expect("test group should exist")
            .subscription_type = "standard".to_owned();
        auth.platform_quotas = vec![UserPlatformQuotaRecord {
            platform: "openai".to_owned(),
            daily_limit_usd: Some("0.5".to_owned()),
            weekly_limit_usd: Some("0.5".to_owned()),
            monthly_limit_usd: Some("0.5".to_owned()),
            daily_usage_usd: "99".to_owned(),
            weekly_usage_usd: "99".to_owned(),
            monthly_usage_usd: "99".to_owned(),
            daily_window_start_unix_ms: Some(shanghai_day_start(now) - 1),
            weekly_window_start_unix_ms: Some(shanghai_week_start(now) - 1),
            monthly_window_start_unix_ms: Some(now - SUBSCRIPTION_MONTH_MILLIS),
        }];
        let pending = PendingBilling::default();
        let _reservation = pending
            .reserve(&billing_event(7))
            .expect("pending billing event should reserve");

        validate_user_platform_quota(&auth, "openai", &pending, now).expect(
            "expired durable usage should reset while new pending cost remains below limit",
        );
    }

    #[test]
    fn account_lease_releases_slot_on_drop() {
        let slots = Arc::new(Mutex::new(HashMap::from([(7, 1)])));
        {
            let _lease = AccountLease {
                account_id: 7,
                in_flight: Arc::clone(&slots),
            };
        }
        assert!(lock(&slots).is_empty());
    }

    #[test]
    fn api_key_lease_tracks_and_releases_active_requests() {
        let slots = Arc::new(Mutex::new(HashMap::new()));
        let first = ApiKeyLease::acquire(11, Arc::clone(&slots));
        let second = ApiKeyLease::acquire(11, Arc::clone(&slots));
        assert_eq!(lock(&slots).get(&11), Some(&2));

        drop(first);
        assert_eq!(lock(&slots).get(&11), Some(&1));
        drop(second);
        assert!(lock(&slots).is_empty());
    }

    #[tokio::test]
    async fn passthrough_rule_uses_rewritten_http_status_and_protocol_body() {
        let route = classify_route(
            &Method::POST,
            &Uri::from_static("/v1beta/models/gemini-2.5-pro:generateContent"),
        )
        .expect("route should be classified");
        let upstream = GatewayError::from_upstream(
            StatusCode::UNPROCESSABLE_ENTITY,
            br#"{"error":{"message":"invalid schema"}}"#,
            None,
        );
        let response = passthrough_error_response(
            &route,
            &upstream,
            ErrorPassthroughDecision {
                status: StatusCode::IM_A_TEAPOT,
                message: Some("custom policy message".to_owned()),
                skip_monitoring: true,
            },
        );
        assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .expect("response body should buffer");
        let body: Value = serde_json::from_slice(&body).expect("response should be JSON");
        assert_eq!(body["error"]["code"], 418);
        assert_eq!(body["error"]["message"], "custom policy message");
    }

    #[tokio::test]
    async fn idle_upstream_stream_emits_terminal_error() {
        let worker = WriteBehind::spawn(NoopBillingSink, WriteBehindConfig::default())
            .expect("test billing worker should start");
        let pending_billing = PendingBilling::default();
        let mut stream = LeasedStream {
            inner: Box::pin(futures_util::stream::pending::<Result<Bytes, reqwest::Error>>()),
            bedrock: None,
            bridge: None,
            leases: None,
            billing: None,
            billing_reservation: None,
            billing_finalize: None,
            billing_finalize_started: false,
            terminal: None,
            billing_writes: pending_billing.queue(worker.sender()),
            billing_route: RouteKind::AnthropicMessages,
            request_started: Instant::now(),
            billing_backpressure: BillingBackpressure::default(),
            idle_timeout: StreamIdleTimeout::new(Duration::from_millis(10)),
            timeout_context: None,
            finished: false,
        };
        let frame = tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .expect("idle timer should wake the stream")
            .expect("terminal frame should be emitted")
            .expect("terminal frame should not be a transport error");
        assert!(String::from_utf8_lossy(&frame).contains("idle for too long"));
        drop(stream);
        worker
            .shutdown()
            .await
            .expect("test billing worker should stop");
    }

    #[tokio::test]
    async fn streamed_response_drop_releases_both_leases() {
        let account_slots = Arc::new(Mutex::new(HashMap::from([(7, 1)])));
        let api_key_slots = Arc::new(Mutex::new(HashMap::new()));
        let user_slots = Arc::new(Mutex::new(HashMap::new()));
        let worker = WriteBehind::spawn(NoopBillingSink, WriteBehindConfig::default())
            .expect("test billing worker should start");
        let pending_billing = PendingBilling::default();
        let stream = LeasedStream {
            inner: Box::pin(futures_util::stream::pending::<Result<Bytes, reqwest::Error>>()),
            bedrock: None,
            bridge: None,
            leases: Some(GatewayLeases {
                _account: AccountLease {
                    account_id: 7,
                    in_flight: Arc::clone(&account_slots),
                },
                _global_account: None,
                _api_key: ApiKeyLease::acquire(11, Arc::clone(&api_key_slots)),
                _user: UserLease::try_acquire(10, 1, Arc::clone(&user_slots))
                    .expect("user slot should be available"),
                _global_user: None,
            }),
            billing: None,
            billing_reservation: None,
            billing_finalize: None,
            billing_finalize_started: false,
            terminal: None,
            billing_writes: pending_billing.queue(worker.sender()),
            billing_route: RouteKind::OpenAiResponses,
            request_started: Instant::now(),
            billing_backpressure: BillingBackpressure::default(),
            idle_timeout: None,
            timeout_context: None,
            finished: false,
        };
        assert_eq!(lock(&api_key_slots).get(&11), Some(&1));

        drop(stream);
        assert!(lock(&account_slots).is_empty());
        assert!(lock(&api_key_slots).is_empty());
        assert!(lock(&user_slots).is_empty());
        worker
            .shutdown()
            .await
            .expect("test billing worker should stop cleanly");
    }

    #[tokio::test]
    async fn billing_shutdown_waits_for_a_backpressured_enqueue() {
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let pending = PendingBilling::default();
        let config = WriteBehindConfig {
            queue_capacity: 1,
            batch_size: 1,
            flush_interval: Duration::from_secs(61),
            ..WriteBehindConfig::default()
        };
        let worker = WriteBehind::spawn(
            pending.sink(GateBillingSink {
                first: AtomicBool::new(false),
                started: Arc::clone(&started),
                release: Arc::clone(&release),
            }),
            config,
        )
        .expect("test billing worker should start");
        let queue = pending.queue(worker.sender());

        let mut first = billing_event(7);
        first.request_id = "backpressure-1".to_owned();
        first.request_fingerprint = request_fingerprint(first.request_id.as_bytes());
        queue
            .enqueue(first)
            .await
            .expect("first event should enqueue");
        started.notified().await;

        let mut second = billing_event(7);
        second.request_id = "backpressure-2".to_owned();
        second.request_fingerprint = request_fingerprint(second.request_id.as_bytes());
        queue
            .enqueue(second)
            .await
            .expect("second event should fill the queue");

        let mut third = billing_event(7);
        third.request_id = "backpressure-3".to_owned();
        third.request_fingerprint = request_fingerprint(third.request_id.as_bytes());
        let backpressure = BillingBackpressure::default();
        backpressure
            .spawn(queue, third)
            .expect("background enqueue should be tracked");
        assert_eq!(backpressure.snapshot(), (1, 0));

        let mut closing = tokio::spawn({
            let backpressure = backpressure.clone();
            async move { backpressure.close_and_wait().await }
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut closing)
                .await
                .is_err(),
            "shutdown must wait while the background enqueue has no capacity"
        );

        release.notify_one();
        let report = tokio::time::timeout(Duration::from_secs(1), closing)
            .await
            .expect("backpressure shutdown should finish after capacity is released")
            .expect("backpressure shutdown task should not panic");
        assert_eq!(report.failed_events, 0);
        assert!(report.last_error.is_none());
        assert_eq!(backpressure.snapshot(), (0, 0));

        let worker_report = worker
            .shutdown()
            .await
            .expect("test billing worker should stop cleanly");
        assert!(worker_report.is_clean());
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn dropped_backpressure_task_guard_cannot_stall_shutdown() {
        let backpressure = BillingBackpressure::default();
        {
            let mut state = lock(&backpressure.inner.state);
            state.initialized = true;
            state.accepting = true;
            state.in_flight = 1;
        }
        drop(BillingBackpressureTaskGuard::new(backpressure.clone()));

        let report = tokio::time::timeout(Duration::from_secs(1), backpressure.close_and_wait())
            .await
            .expect("RAII completion must wake shutdown");
        assert_eq!(report.failed_events, 1);
        assert!(
            report
                .last_error
                .as_deref()
                .is_some_and(|error| error.contains("cancelled or panicked"))
        );
    }

    #[tokio::test]
    async fn gateway_shutdown_is_bounded_when_billing_queue_and_sink_are_blocked() {
        let started = Arc::new(Notify::new());
        let pending = PendingBilling::default();
        let config = WriteBehindConfig {
            queue_capacity: 1,
            batch_size: 1,
            flush_interval: Duration::from_secs(61),
            max_retries: 0,
            attempt_timeout: Duration::from_millis(40),
            shutdown_timeout: Duration::from_secs(1),
            ..WriteBehindConfig::default()
        };
        let mutation_worker = WriteBehind::spawn(NoopGatewayMutationSink, config.clone())
            .expect("gateway mutation worker should start");
        let billing_worker = WriteBehind::spawn(
            pending.sink(BlockedBillingSink {
                started: Arc::clone(&started),
            }),
            config,
        )
        .expect("billing worker should start");
        let queue = pending.queue(billing_worker.sender());

        let mut first = billing_event(7);
        first.request_id = "blocked-shutdown-1".to_owned();
        first.request_fingerprint = request_fingerprint(first.request_id.as_bytes());
        queue
            .enqueue(first)
            .await
            .expect("first event should enqueue");
        started.notified().await;

        let mut second = billing_event(7);
        second.request_id = "blocked-shutdown-2".to_owned();
        second.request_fingerprint = request_fingerprint(second.request_id.as_bytes());
        queue
            .enqueue(second)
            .await
            .expect("second event should fill the queue");

        let mut third = billing_event(7);
        third.request_id = "blocked-shutdown-3".to_owned();
        third.request_fingerprint = request_fingerprint(third.request_id.as_bytes());
        let backpressure = BillingBackpressure::default();
        backpressure
            .spawn(queue, third)
            .expect("third event should wait behind the full queue");
        let writes = GatewayWriteWorker {
            worker: mutation_worker,
            billing_worker,
            billing_backpressure: backpressure,
            authority_cancellation: CancellationToken::new(),
            authority_task: tokio::spawn(async {}),
        };

        let report = tokio::time::timeout(Duration::from_secs(2), writes.shutdown())
            .await
            .expect("gateway shutdown must remain bounded")
            .expect("workers should return their unflushed report");
        assert_eq!(report.unflushed_mutations, 3);
        assert!(
            report
                .last_error
                .as_deref()
                .is_some_and(|error| error.contains("billing"))
        );
        assert_eq!(pending.len(), 2);
    }

    #[tokio::test]
    async fn invalidation_epoch_prevents_stale_loader_repopulation() {
        let cache = Arc::new(L1Cache::new(4, Duration::from_mins(1)));
        let flights = Arc::new(Singleflight::new());
        let epoch = Arc::new(AtomicU64::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());

        let task = tokio::spawn({
            let cache = Arc::clone(&cache);
            let flights = Arc::clone(&flights);
            let epoch = Arc::clone(&epoch);
            let calls = Arc::clone(&calls);
            let started = Arc::clone(&started);
            let release = Arc::clone(&release);
            async move {
                get_or_load_guarded(&cache, &flights, &epoch, "sk-test".to_owned(), || {
                    let call = calls.fetch_add(1, Ordering::SeqCst);
                    let started = Arc::clone(&started);
                    let release = Arc::clone(&release);
                    async move {
                        if call == 0 {
                            started.notify_one();
                            release.notified().await;
                            Ok::<_, ()>("stale".to_owned())
                        } else {
                            Ok("fresh".to_owned())
                        }
                    }
                })
                .await
            }
        });

        started.notified().await;
        epoch.fetch_add(1, Ordering::AcqRel);
        cache.remove(&"sk-test".to_owned());
        release.notify_one();

        let result = task.await.expect("guarded load task should finish");
        assert_eq!(result.as_ref(), &Ok("fresh".to_owned()));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(cache.get(&"sk-test".to_owned()).as_deref(), Some("fresh"));
    }

    #[tokio::test]
    async fn authentication_precedes_request_body_validation() {
        let pool = PgPoolOptions::new().connect_lazy_with(PgConnectOptions::new());
        let (gateway, worker) =
            GatewayRuntime::spawn(pool.clone(), GatewayRuntimeConfig::default())
                .expect("gateway should start without opening a lazy database pool");

        let response = gateway
            .try_handle(
                Method::POST,
                Uri::from_static("/v1/messages"),
                HeaderMap::new(),
                Bytes::from_static(b"{"),
                None,
            )
            .await
            .expect("messages route should be handled");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        worker
            .shutdown()
            .await
            .expect("empty gateway workers should stop cleanly");
        pool.close().await;
    }

    #[tokio::test]
    async fn configured_account_proxy_is_used_and_missing_proxy_fails_closed() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("proxy listener should bind");
        let proxy_address = listener.local_addr().expect("proxy address should resolve");
        let proxy_task = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("proxy should accept request");
            let mut bytes = vec![0_u8; 8 * 1024];
            let read = stream
                .read(&mut bytes)
                .await
                .expect("proxy should read request");
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await
                .expect("proxy should answer request");
            String::from_utf8(bytes[..read].to_vec()).expect("proxy request should be HTTP text")
        });

        let pool = PgPoolOptions::new().connect_lazy_with(PgConnectOptions::new());
        let (gateway, worker) =
            GatewayRuntime::spawn(pool.clone(), GatewayRuntimeConfig::default())
                .expect("gateway should start without opening a lazy database pool");
        let mut proxied = account(&json!({}));
        proxied.proxy_id = Some(9);
        proxied.proxy = Some(AccountProxyRecord {
            id: 9,
            protocol: "http".to_owned(),
            host: proxy_address.ip().to_string(),
            port: i32::from(proxy_address.port()),
            username: None,
            password: None,
            status: STATUS_ACTIVE.to_owned(),
            expires_at_unix_ms: None,
        });

        let response = gateway
            .upstream_client(&proxied)
            .await
            .expect("valid proxy should build a client")
            .get("http://upstream.invalid/v1/models")
            .send()
            .await
            .expect("request should be handled by the local proxy");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let request = proxy_task.await.expect("proxy task should finish");
        assert!(
            request.starts_with("GET http://upstream.invalid/v1/models HTTP/1.1"),
            "unexpected proxy request: {request:?}"
        );

        proxied.proxy = None;
        let error = gateway
            .upstream_client(&proxied)
            .await
            .expect_err("an account with an unresolved proxy must not use direct access");
        assert_eq!(error.kind, GatewayErrorKind::Unavailable);

        worker
            .shutdown()
            .await
            .expect("empty gateway workers should stop cleanly");
        pool.close().await;
    }

    #[test]
    fn proxy_url_encodes_credentials_and_rejects_unsupported_protocols() {
        let mut proxy = AccountProxyRecord {
            id: 9,
            protocol: "socks5".to_owned(),
            host: "2001:db8::1".to_owned(),
            port: 1080,
            username: Some("user@example.com".to_owned()),
            password: Some("p@ss/word".to_owned()),
            status: STATUS_ACTIVE.to_owned(),
            expires_at_unix_ms: None,
        };
        assert_eq!(
            proxy_url(&proxy).expect("proxy URL should build").as_str(),
            "socks5://user%40example.com:p%40ss%2Fword@[2001:db8::1]:1080"
        );

        proxy.protocol = "ftp".to_owned();
        assert!(proxy_url(&proxy).is_err());
        assert!(!proxy.is_usable_at(now_unix_millis()));
    }

    #[test]
    fn grok_oauth_refresh_uses_xai_endpoint_headers_and_form() {
        let mut account = account(&json!({}));
        account.platform = "grok".to_owned();
        account.account_type = "oauth".to_owned();
        account.credentials = json!({"client_id":"grok-client"});
        let request = grok_refresh_request(&reqwest::Client::new(), &account, "refresh-secret")
            .build()
            .expect("Grok refresh request should build");
        assert_eq!(request.url().as_str(), GROK_OAUTH_TOKEN_URL);
        assert_eq!(
            request
                .headers()
                .get(header::USER_AGENT)
                .and_then(|value| value.to_str().ok()),
            Some("sub2api-grok-oauth/1.0")
        );
        let form = request
            .body()
            .and_then(reqwest::Body::as_bytes)
            .map(|bytes| {
                url::form_urlencoded::parse(bytes)
                    .into_owned()
                    .collect::<HashMap<_, _>>()
            })
            .expect("Grok refresh form should be buffered");
        assert_eq!(
            form.get("grant_type").map(String::as_str),
            Some("refresh_token")
        );
        assert_eq!(
            form.get("refresh_token").map(String::as_str),
            Some("refresh-secret")
        );
        assert_eq!(
            form.get("client_id").map(String::as_str),
            Some("grok-client")
        );
    }

    #[test]
    fn default_flush_interval_is_exactly_thirty_seconds() {
        assert_eq!(
            GatewayRuntimeConfig::default().write_behind.flush_interval,
            Duration::from_secs(30)
        );
        assert_eq!(BILLING_FLUSH_INTERVAL, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn invalid_api_key_negative_cache_is_l1_first_and_invalidatable() {
        let pool = PgPoolOptions::new().connect_lazy_with(PgConnectOptions::new());
        let (gateway, worker) =
            GatewayRuntime::spawn(pool.clone(), GatewayRuntimeConfig::default())
                .expect("gateway should start without opening a lazy database pool");
        let key = "sk-known-missing".to_owned();
        gateway.inner.auth_negative_cache.insert(key.clone(), ());
        assert_eq!(
            gateway.inner.auth_negative_cache.default_ttl(),
            AUTH_NEGATIVE_CACHE_TTL
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-api-key",
            key.parse().expect("test API key should be a valid header"),
        );
        let error = gateway
            .authenticate(&headers, None, None, true)
            .await
            .expect_err("negative L1 hit must reject without PostgreSQL");
        assert!(matches!(error, AuthError::InvalidApiKey));

        gateway.invalidate_api_key_auth_cache(999, Some(&key));
        assert!(gateway.inner.auth_negative_cache.get(&key).is_none());

        worker
            .shutdown()
            .await
            .expect("empty gateway workers should stop cleanly");
        pool.close().await;
    }

    #[test]
    fn long_upstream_request_ids_are_stably_hashed_for_usage_logs() {
        let request_headers = HeaderMap::new();
        let mut response_headers = HeaderMap::new();
        response_headers.insert(
            "x-request-id",
            "a".repeat(80).parse().expect("header should parse"),
        );

        let request_id = billing_request_id(&request_headers, &response_headers);
        assert_eq!(request_id.len(), 64);
        assert_eq!(
            request_id,
            billing_request_id(&request_headers, &response_headers)
        );
    }

    #[test]
    fn timestamp_type_remains_signed_milliseconds() {
        let now: UnixMillis = now_unix_millis();
        assert!(now > 0);
    }

    #[test]
    fn decimal_positivity_is_exact_for_zero_scales() {
        assert!(!decimal_is_positive(&decimal_json("0.00000000")));
        assert!(!decimal_is_positive(&decimal_json("-1.0")));
        assert!(decimal_is_positive(&decimal_json("0.00000001")));
    }
}
