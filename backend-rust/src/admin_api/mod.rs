//! PostgreSQL-only administrator control-plane API.
//!
//! The module is intentionally self-contained so the application can mount its
//! router after providing a JWT verifier, password hasher, and optional account
//! probe. Mutations return cache-invalidation keys from the service layer.

mod affiliates;
mod auth;
mod compat;
mod compat_accounts;
mod compat_admin_semantics;
mod compat_external;
mod compat_oauth;
mod compat_ops;
mod compat_payment;
mod compat_relations;
mod compat_resources;
mod compat_settings;
mod compat_special;
mod compat_usage;
mod compliance;
mod content;
mod credentials;
mod http;
mod models;
mod ops_ws;
mod probe;
mod service;

pub use auth::{AdminTokenError, AdminTokenVerifier, Hs256AdminTokenVerifier};
pub use credentials::{SENSITIVE_CREDENTIAL_KEYS, merge_credentials, redact_credentials};
pub use http::{AdminApi, AdminApiState};
pub use models::{
    AccountProbe, AccountView, AdminClaims, AdminError, AdminIdentity, ApiKeyView,
    CreateAccountRequest, CreateApiKeyRequest, CreateGroupRequest, CreateProxyRequest,
    CreateUserRequest, GroupView, InvalidationKey, Mutation, Page, PageQuery, PasswordHasher,
    Patch, ProbeAccount, ProbeProxy, ProbeRequest, ProbeResult, ProxyView, SettingPatchRequest,
    UpdateAccountRequest, UpdateApiKeyRequest, UpdateGroupRequest, UpdateProxyRequest,
    UpdateUserRequest, UserView, ValidatedProbeTarget,
};
pub use probe::{ReqwestAccountProbe, ReqwestAccountProbeConfig};
pub use service::{
    ACCOUNT_SOFT_DELETE_SQL, API_KEY_SOFT_DELETE_SQL, AdminCacheInvalidator,
    AdminRuntimeStatsProvider, AdminRuntimeStatsSnapshot, AdminService,
    AdminUsageBillingPendingStats, AdminUsageLogPendingStats, GROUP_SOFT_DELETE_SQL,
    PROXY_SOFT_DELETE_SQL, USER_SOFT_DELETE_SQL, validate_public_probe_target,
};

pub(crate) async fn refresh_oauth_account(
    pool: &sqlx::PgPool,
    account_id: i64,
) -> Result<(), AdminError> {
    compat_oauth::refresh_account_auto(pool, account_id)
        .await
        .map(drop)
}
