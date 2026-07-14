#![allow(
    clippy::missing_errors_doc,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use rand::{RngCore, rngs::OsRng};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction, postgres::PgRow};
use tokio::{net::lookup_host, time::timeout};
use url::{Host, Url};

use super::{
    credentials::{merge_credentials, redact_credentials},
    models::{
        AccountProbe, AccountView, AdminClaims, AdminError, AdminIdentity, ApiKeyView,
        CreateAccountRequest, CreateApiKeyRequest, CreateGroupRequest, CreateProxyRequest,
        CreateUserRequest, GroupView, InvalidationKey, Mutation, Page, PageQuery, PasswordHasher,
        Patch, ProbeAccount, ProbeProxy, ProbeRequest, ProbeResult, ProxyView, SettingPatchRequest,
        UpdateAccountRequest, UpdateApiKeyRequest, UpdateGroupRequest, UpdateProxyRequest,
        UpdateUserRequest, UserView, ValidatedProbeTarget,
    },
};

pub const USER_SOFT_DELETE_SQL: &str = "UPDATE users SET status = 'disabled', deleted_at = NOW(), updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL";
pub const GROUP_SOFT_DELETE_SQL: &str = "UPDATE groups SET status = 'disabled', deleted_at = NOW(), updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL";
pub const ACCOUNT_SOFT_DELETE_SQL: &str = "UPDATE accounts SET status = 'disabled', schedulable = FALSE, deleted_at = NOW(), updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL";
pub const PROXY_SOFT_DELETE_SQL: &str = "UPDATE proxies SET status = 'disabled', deleted_at = NOW(), updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL";
pub const API_KEY_SOFT_DELETE_SQL: &str = "UPDATE api_keys SET status = 'disabled', deleted_at = NOW(), updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL";

const USER_COLUMNS: &str = r"
u.id, u.email, COALESCE(u.username, '') AS username,
COALESCE(u.notes, '') AS notes, u.role, u.balance::double precision AS balance,
u.concurrency, COALESCE(u.rpm_limit, 0) AS rpm_limit, u.status,
ARRAY(SELECT uag.group_id FROM user_allowed_groups uag WHERE uag.user_id = u.id ORDER BY uag.group_id) AS allowed_groups,
u.created_at::text AS created_at, u.updated_at::text AS updated_at";

const GROUP_COLUMNS: &str = r"
g.id, g.name, COALESCE(g.description, '') AS description, g.platform,
g.rate_multiplier::double precision AS rate_multiplier, g.is_exclusive, g.status,
g.subscription_type, COALESCE(g.rpm_limit, 0) AS rpm_limit,
g.created_at::text AS created_at, g.updated_at::text AS updated_at";

const ACCOUNT_COLUMNS: &str = r"
a.id, a.name, a.notes, a.platform, a.type AS account_type,
a.credentials::text AS credentials_json, a.extra::text AS extra_json, a.proxy_id,
a.concurrency, a.priority, a.rate_multiplier::double precision AS rate_multiplier,
a.load_factor, a.status, a.schedulable,
ARRAY(SELECT ag.group_id FROM account_groups ag WHERE ag.account_id = a.id ORDER BY ag.group_id) AS group_ids,
EXTRACT(EPOCH FROM a.expires_at)::bigint AS expires_at, a.auto_pause_on_expired,
a.created_at::text AS created_at, a.updated_at::text AS updated_at";

const PROXY_COLUMNS: &str = r"
p.id, p.name, p.protocol, p.host, p.port, p.username,
(COALESCE(p.password, '') <> '') AS has_password, p.status,
EXTRACT(EPOCH FROM p.expires_at)::bigint AS expires_at,
p.fallback_mode, p.backup_proxy_id, p.expiry_warn_days,
p.created_at::text AS created_at, p.updated_at::text AS updated_at";

const API_KEY_COLUMNS: &str = r"
k.id, k.user_id, k.key, k.name, k.group_id, k.status,
COALESCE(k.ip_whitelist::text, '[]') AS ip_whitelist_json,
COALESCE(k.ip_blacklist::text, '[]') AS ip_blacklist_json,
k.quota::double precision AS quota, k.quota_used::double precision AS quota_used,
EXTRACT(EPOCH FROM k.expires_at)::bigint AS expires_at,
k.rate_limit_5h::double precision AS rate_limit_5h,
k.rate_limit_1d::double precision AS rate_limit_1d,
k.rate_limit_7d::double precision AS rate_limit_7d,
k.created_at::text AS created_at, k.updated_at::text AS updated_at";

#[async_trait::async_trait]
pub trait AdminCacheInvalidator: Send + Sync {
    async fn invalidate_api_key(
        &self,
        api_key_id: i64,
        raw_key: Option<&str>,
    ) -> Result<(), sqlx::Error>;
    async fn invalidate_auth_cache(&self) -> Result<(), sqlx::Error>;
    async fn invalidate_account_cache(&self) -> Result<(), sqlx::Error>;
    async fn invalidate_runtime_settings(&self) -> Result<(), sqlx::Error>;
}

/// Process-local usage state exposed to administrator diagnostics and DTOs.
///
/// The gateway owns the concrete L1/write-behind implementation. Keeping this
/// as a small read-only interface lets the administrator API report the same
/// effective values without owning or mutating the hot path.
pub trait AdminRuntimeStatsProvider: Send + Sync {
    fn snapshot(&self) -> AdminRuntimeStatsSnapshot;

    fn pending_api_key_cost(&self, _api_key_id: i64) -> f64 {
        0.0
    }

    fn pending_user_group_cost(&self, _user_id: i64, _group_id: i64) -> f64 {
        0.0
    }

    fn api_key_current_concurrency(&self, _api_key_id: i64) -> u64 {
        0
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct AdminUsageLogPendingStats {
    pub pending_l1_entries: u64,
    pub pending_l2_entries: i64,
    pub enqueued_total: u64,
    pub flushed_total: u64,
    pub flush_error_total: u64,
    pub l2_mirror_error_total: u64,
    pub l2_trim_error_total: u64,
    pub dropped_after_stopped: u64,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct AdminUsageBillingPendingStats {
    pub pending_l1_entries: u64,
    pub pending_durable_entries: u64,
    pub pending_balance_keys: u64,
    pub pending_subscription_keys: u64,
    pub pending_api_key_quota_keys: u64,
    pub pending_api_key_rate_keys: u64,
    pub pending_api_key_updater_keys: u64,
    pub pending_account_quota_keys: u64,
    pub pending_l2_entries: i64,
    pub dedup_entries: u64,
    pub applied_total: u64,
    pub dedup_skipped_total: u64,
    pub l2_mirror_error_total: u64,
    pub l2_trim_error_total: u64,
    pub flush_success_total: u64,
    pub flush_error_total: u64,
    pub flush_balance_keys_total: u64,
    pub flush_subscription_keys_total: u64,
    pub flush_api_key_quota_keys_total: u64,
    pub flush_api_key_rate_keys_total: u64,
    pub flush_account_quota_keys_total: u64,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct AdminRuntimeStatsSnapshot {
    pub usage_log: AdminUsageLogPendingStats,
    pub usage_billing: AdminUsageBillingPendingStats,
}

#[derive(Clone, Copy)]
enum AdminCacheInvalidation<'a> {
    ApiKey { id: i64, raw_key: &'a str },
    Auth,
    Accounts,
    Settings,
}

#[derive(Clone)]
pub struct AdminService {
    pool: PgPool,
    password_hasher: Arc<dyn PasswordHasher>,
    account_probe: Option<Arc<dyn AccountProbe>>,
    cache_invalidator: Option<Arc<dyn AdminCacheInvalidator>>,
    runtime_stats: Option<Arc<dyn AdminRuntimeStatsProvider>>,
}

impl AdminService {
    #[must_use]
    pub fn new(pool: PgPool, password_hasher: Arc<dyn PasswordHasher>) -> Self {
        Self {
            pool,
            password_hasher,
            account_probe: None,
            cache_invalidator: None,
            runtime_stats: None,
        }
    }

    #[must_use]
    pub fn with_account_probe(mut self, probe: Arc<dyn AccountProbe>) -> Self {
        self.account_probe = Some(probe);
        self
    }

    #[must_use]
    pub fn with_cache_invalidator(mut self, invalidator: Arc<dyn AdminCacheInvalidator>) -> Self {
        self.cache_invalidator = Some(invalidator);
        self
    }

    #[must_use]
    pub fn with_runtime_stats(mut self, provider: Arc<dyn AdminRuntimeStatsProvider>) -> Self {
        self.runtime_stats = Some(provider);
        self
    }

    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    #[must_use]
    pub fn runtime_stats(&self) -> Option<&dyn AdminRuntimeStatsProvider> {
        self.runtime_stats.as_deref()
    }

    async fn publish_cache_invalidation(&self, invalidation: AdminCacheInvalidation<'_>) {
        let Some(publisher) = self.cache_invalidator.as_ref() else {
            return;
        };
        let (scope, resource_id, result) = match invalidation {
            AdminCacheInvalidation::ApiKey { id, raw_key } => (
                "api_key",
                Some(id),
                publisher.invalidate_api_key(id, Some(raw_key)).await,
            ),
            AdminCacheInvalidation::Auth => ("auth", None, publisher.invalidate_auth_cache().await),
            AdminCacheInvalidation::Accounts => {
                ("accounts", None, publisher.invalidate_account_cache().await)
            }
            AdminCacheInvalidation::Settings => (
                "settings",
                None,
                publisher.invalidate_runtime_settings().await,
            ),
        };
        if let Err(error) = result {
            tracing::warn!(
                error = %error,
                scope,
                resource_id,
                "admin mutation committed but cross-instance cache invalidation failed"
            );
        }
    }

    pub async fn authorize_admin(&self, claims: &AdminClaims) -> Result<AdminIdentity, AdminError> {
        if claims.role != "admin" {
            return Err(AdminError::Forbidden(
                "administrator role is required".to_owned(),
            ));
        }
        let row = sqlx::query(
            "SELECT email, password_hash, auth_generation, role, status FROM users WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(claims.user_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(AdminError::Unauthorized)?;
        let email: String = row.try_get("email")?;
        let password_hash: String = row.try_get("password_hash")?;
        let auth_generation: i64 = row.try_get("auth_generation")?;
        let role: String = row.try_get("role")?;
        let status: String = row.try_get("status")?;
        if role != "admin" || status != "active" {
            return Err(AdminError::Unauthorized);
        }
        if session_token_version(&email, &password_hash, auth_generation) != claims.token_version {
            return Err(AdminError::Unauthorized);
        }
        Ok(AdminIdentity {
            user_id: claims.user_id,
            email,
        })
    }

    pub async fn list_users(&self, query: PageQuery) -> Result<Page<UserView>, AdminError> {
        let query = query.normalized();
        let search = query.search.as_deref().map(like_pattern);
        let total = sqlx::query_scalar::<_, i64>(
            r"SELECT COUNT(*) FROM users u
              WHERE u.deleted_at IS NULL
                AND ($1::text IS NULL OR u.email ILIKE $1 OR u.username ILIKE $1)
                AND ($2::text IS NULL OR u.status = $2)
                AND ($3::text IS NULL OR u.role = $3)",
        )
        .bind(search.as_deref())
        .bind(query.status.as_deref())
        .bind(query.role.as_deref())
        .fetch_one(&self.pool)
        .await?;
        let sql = format!(
            "SELECT {USER_COLUMNS} FROM users u
             WHERE u.deleted_at IS NULL
               AND ($1::text IS NULL OR u.email ILIKE $1 OR u.username ILIKE $1)
               AND ($2::text IS NULL OR u.status = $2)
               AND ($3::text IS NULL OR u.role = $3)
             ORDER BY u.id DESC LIMIT $4 OFFSET $5"
        );
        let rows = sqlx::query(&sql)
            .bind(search.as_deref())
            .bind(query.status.as_deref())
            .bind(query.role.as_deref())
            .bind(query.page_size)
            .bind(query.offset())
            .fetch_all(&self.pool)
            .await?;
        let items = rows.iter().map(user_from_row).collect::<Result<_, _>>()?;
        Ok(Page::new(items, total, &query))
    }

    pub async fn get_user(&self, id: i64) -> Result<UserView, AdminError> {
        let sql =
            format!("SELECT {USER_COLUMNS} FROM users u WHERE u.id = $1 AND u.deleted_at IS NULL");
        sqlx::query(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .as_ref()
            .map(user_from_row)
            .transpose()?
            .ok_or(AdminError::NotFound("user"))
    }

    pub async fn create_user(
        &self,
        request: CreateUserRequest,
    ) -> Result<Mutation<UserView>, AdminError> {
        let email = normalize_email(&request.email)?;
        validate_password(&request.password)?;
        validate_user_role(&request.role)?;
        validate_nonnegative_i32("concurrency", request.concurrency)?;
        validate_nonnegative_i32("rpm_limit", request.rpm_limit)?;
        validate_finite("balance", request.balance)?;
        let password_hash = self
            .password_hasher
            .hash_password(&request.password)
            .map_err(AdminError::BadRequest)?;
        let mut transaction = self.pool.begin().await?;
        let group_ids = validate_group_ids(&mut transaction, &request.allowed_groups).await?;
        let id = sqlx::query_scalar::<_, i64>(
            r"INSERT INTO users
              (email, password_hash, username, notes, role, balance, concurrency, rpm_limit, status)
              VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active') RETURNING id",
        )
        .bind(email)
        .bind(password_hash)
        .bind(request.username.trim())
        .bind(request.notes.trim())
        .bind(request.role)
        .bind(request.balance)
        .bind(request.concurrency)
        .bind(request.rpm_limit)
        .fetch_one(&mut *transaction)
        .await?;
        sync_user_groups(&mut transaction, id, &group_ids).await?;
        transaction.commit().await?;
        self.publish_cache_invalidation(AdminCacheInvalidation::Auth)
            .await;
        Ok(Mutation {
            value: self.get_user(id).await?,
            invalidation_keys: user_invalidation(id),
        })
    }

    pub async fn update_user(
        &self,
        actor: &AdminIdentity,
        id: i64,
        request: UpdateUserRequest,
    ) -> Result<Mutation<UserView>, AdminError> {
        if id == actor.user_id
            && (request.role.as_deref().is_some_and(|role| role != "admin")
                || request
                    .status
                    .as_deref()
                    .is_some_and(|status| status != "active"))
        {
            return Err(AdminError::Forbidden(
                "an administrator cannot demote or disable their own account".to_owned(),
            ));
        }
        let email = request.email.as_deref().map(normalize_email).transpose()?;
        if let Some(role) = request.role.as_deref() {
            validate_user_role(role)?;
        }
        if let Some(status) = request.status.as_deref() {
            validate_status(status)?;
        }
        if let Some(value) = request.balance {
            validate_finite("balance", value)?;
        }
        if let Some(value) = request.concurrency {
            validate_nonnegative_i32("concurrency", value)?;
        }
        if let Some(value) = request.rpm_limit {
            validate_nonnegative_i32("rpm_limit", value)?;
        }
        let password_hash = request
            .password
            .as_deref()
            .filter(|password| !password.is_empty())
            .map(|password| {
                validate_password(password)?;
                self.password_hasher
                    .hash_password(password)
                    .map_err(AdminError::BadRequest)
            })
            .transpose()?;
        let mut transaction = self.pool.begin().await?;
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND deleted_at IS NULL FOR UPDATE)",
        )
        .bind(id)
        .fetch_one(&mut *transaction)
        .await?;
        if !exists {
            return Err(AdminError::NotFound("user"));
        }
        let result = sqlx::query(
            r"UPDATE users SET
              email = COALESCE($2, email), password_hash = COALESCE($3, password_hash),
              username = COALESCE($4, username), notes = COALESCE($5, notes),
              role = COALESCE($6, role), balance = COALESCE($7, balance),
              concurrency = COALESCE($8, concurrency), rpm_limit = COALESCE($9, rpm_limit),
              status = COALESCE($10, status), updated_at = NOW()
              WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(id)
        .bind(email)
        .bind(request.password.as_ref().and(password_hash))
        .bind(request.username.map(|value| value.trim().to_owned()))
        .bind(request.notes.map(|value| value.trim().to_owned()))
        .bind(request.role)
        .bind(request.balance)
        .bind(request.concurrency)
        .bind(request.rpm_limit)
        .bind(request.status)
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() == 0 {
            return Err(AdminError::NotFound("user"));
        }
        if let Some(group_ids) = request.allowed_groups {
            let group_ids = validate_group_ids(&mut transaction, &group_ids).await?;
            sync_user_groups(&mut transaction, id, &group_ids).await?;
        }
        transaction.commit().await?;
        self.publish_cache_invalidation(AdminCacheInvalidation::Auth)
            .await;
        Ok(Mutation {
            value: self.get_user(id).await?,
            invalidation_keys: user_invalidation(id),
        })
    }

    pub async fn delete_user(
        &self,
        actor: &AdminIdentity,
        id: i64,
    ) -> Result<Mutation<()>, AdminError> {
        if id == actor.user_id {
            return Err(AdminError::Forbidden(
                "an administrator cannot delete their own account".to_owned(),
            ));
        }
        let mut transaction = self.pool.begin().await?;
        let role = sqlx::query_scalar::<_, String>(
            "SELECT role FROM users WHERE id = $1 AND deleted_at IS NULL FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(AdminError::NotFound("user"))?;
        if role == "admin" {
            return Err(AdminError::Forbidden(
                "administrator accounts cannot be deleted through this endpoint".to_owned(),
            ));
        }
        let result = sqlx::query(USER_SOFT_DELETE_SQL)
            .bind(id)
            .execute(&mut *transaction)
            .await?;
        ensure_deleted(result.rows_affected(), "user")?;
        transaction.commit().await?;
        self.publish_cache_invalidation(AdminCacheInvalidation::Auth)
            .await;
        Ok(Mutation {
            value: (),
            invalidation_keys: user_invalidation(id),
        })
    }

    pub async fn list_groups(&self, query: PageQuery) -> Result<Page<GroupView>, AdminError> {
        let query = query.normalized();
        let search = query.search.as_deref().map(like_pattern);
        let total = sqlx::query_scalar::<_, i64>(
            r"SELECT COUNT(*) FROM groups g WHERE g.deleted_at IS NULL
              AND ($1::text IS NULL OR g.name ILIKE $1 OR g.description ILIKE $1)
              AND ($2::text IS NULL OR g.status = $2)
              AND ($3::text IS NULL OR g.platform = $3)",
        )
        .bind(search.as_deref())
        .bind(query.status.as_deref())
        .bind(query.platform.as_deref())
        .fetch_one(&self.pool)
        .await?;
        let sql = format!(
            "SELECT {GROUP_COLUMNS} FROM groups g WHERE g.deleted_at IS NULL
             AND ($1::text IS NULL OR g.name ILIKE $1 OR g.description ILIKE $1)
             AND ($2::text IS NULL OR g.status = $2)
             AND ($3::text IS NULL OR g.platform = $3)
             ORDER BY g.id DESC LIMIT $4 OFFSET $5"
        );
        let rows = sqlx::query(&sql)
            .bind(search.as_deref())
            .bind(query.status.as_deref())
            .bind(query.platform.as_deref())
            .bind(query.page_size)
            .bind(query.offset())
            .fetch_all(&self.pool)
            .await?;
        let items = rows.iter().map(group_from_row).collect::<Result<_, _>>()?;
        Ok(Page::new(items, total, &query))
    }

    pub async fn get_group(&self, id: i64) -> Result<GroupView, AdminError> {
        let sql = format!(
            "SELECT {GROUP_COLUMNS} FROM groups g WHERE g.id = $1 AND g.deleted_at IS NULL"
        );
        sqlx::query(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .as_ref()
            .map(group_from_row)
            .transpose()?
            .ok_or(AdminError::NotFound("group"))
    }

    pub async fn create_group(
        &self,
        request: CreateGroupRequest,
    ) -> Result<Mutation<GroupView>, AdminError> {
        let name = required_text("name", &request.name, 100)?;
        let platform = required_text("platform", &request.platform, 50)?;
        validate_positive_finite("rate_multiplier", request.rate_multiplier)?;
        validate_nonnegative_i32("rpm_limit", request.rpm_limit)?;
        let id = sqlx::query_scalar::<_, i64>(
            r"INSERT INTO groups
              (name, description, platform, rate_multiplier, is_exclusive, subscription_type, rpm_limit, status)
              VALUES ($1, $2, $3, $4, $5, $6, $7, 'active') RETURNING id",
        )
        .bind(name)
        .bind(request.description.trim())
        .bind(platform)
        .bind(request.rate_multiplier)
        .bind(request.is_exclusive)
        .bind(required_text(
            "subscription_type",
            &request.subscription_type,
            20,
        )?)
        .bind(request.rpm_limit)
        .fetch_one(&self.pool)
        .await?;
        self.publish_cache_invalidation(AdminCacheInvalidation::Auth)
            .await;
        self.publish_cache_invalidation(AdminCacheInvalidation::Accounts)
            .await;
        Ok(Mutation {
            value: self.get_group(id).await?,
            invalidation_keys: group_invalidation(id),
        })
    }

    pub async fn update_group(
        &self,
        id: i64,
        request: UpdateGroupRequest,
    ) -> Result<Mutation<GroupView>, AdminError> {
        let name = request
            .name
            .as_deref()
            .map(|value| required_text("name", value, 100))
            .transpose()?;
        let platform = request
            .platform
            .as_deref()
            .map(|value| required_text("platform", value, 50))
            .transpose()?;
        if let Some(value) = request.rate_multiplier {
            validate_positive_finite("rate_multiplier", value)?;
        }
        if let Some(value) = request.rpm_limit {
            validate_nonnegative_i32("rpm_limit", value)?;
        }
        if let Some(status) = request.status.as_deref() {
            validate_status(status)?;
        }
        let result = sqlx::query(
            r"UPDATE groups SET name = COALESCE($2, name),
              description = COALESCE($3, description), platform = COALESCE($4, platform),
              rate_multiplier = COALESCE($5, rate_multiplier),
              is_exclusive = COALESCE($6, is_exclusive), status = COALESCE($7, status),
              subscription_type = COALESCE($8, subscription_type),
              rpm_limit = COALESCE($9, rpm_limit), updated_at = NOW()
              WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(id)
        .bind(name)
        .bind(request.description.map(|value| value.trim().to_owned()))
        .bind(platform)
        .bind(request.rate_multiplier)
        .bind(request.is_exclusive)
        .bind(request.status)
        .bind(request.subscription_type)
        .bind(request.rpm_limit)
        .execute(&self.pool)
        .await?;
        ensure_deleted(result.rows_affected(), "group")?;
        self.publish_cache_invalidation(AdminCacheInvalidation::Auth)
            .await;
        self.publish_cache_invalidation(AdminCacheInvalidation::Accounts)
            .await;
        Ok(Mutation {
            value: self.get_group(id).await?,
            invalidation_keys: group_invalidation(id),
        })
    }

    pub async fn delete_group(&self, id: i64) -> Result<Mutation<()>, AdminError> {
        let result = sqlx::query(GROUP_SOFT_DELETE_SQL)
            .bind(id)
            .execute(&self.pool)
            .await?;
        ensure_deleted(result.rows_affected(), "group")?;
        self.publish_cache_invalidation(AdminCacheInvalidation::Auth)
            .await;
        self.publish_cache_invalidation(AdminCacheInvalidation::Accounts)
            .await;
        Ok(Mutation {
            value: (),
            invalidation_keys: group_invalidation(id),
        })
    }

    pub async fn list_accounts(&self, query: PageQuery) -> Result<Page<AccountView>, AdminError> {
        let query = query.normalized();
        let search = query.search.as_deref().map(like_pattern);
        let total = sqlx::query_scalar::<_, i64>(
            r"SELECT COUNT(*) FROM accounts a WHERE a.deleted_at IS NULL
              AND ($1::text IS NULL OR a.name ILIKE $1 OR a.notes ILIKE $1)
              AND ($2::text IS NULL OR a.status = $2)
              AND ($3::text IS NULL OR a.platform = $3)",
        )
        .bind(search.as_deref())
        .bind(query.status.as_deref())
        .bind(query.platform.as_deref())
        .fetch_one(&self.pool)
        .await?;
        let sql = format!(
            "SELECT {ACCOUNT_COLUMNS} FROM accounts a WHERE a.deleted_at IS NULL
             AND ($1::text IS NULL OR a.name ILIKE $1 OR a.notes ILIKE $1)
             AND ($2::text IS NULL OR a.status = $2)
             AND ($3::text IS NULL OR a.platform = $3)
             ORDER BY a.priority, a.id DESC LIMIT $4 OFFSET $5"
        );
        let rows = sqlx::query(&sql)
            .bind(search.as_deref())
            .bind(query.status.as_deref())
            .bind(query.platform.as_deref())
            .bind(query.page_size)
            .bind(query.offset())
            .fetch_all(&self.pool)
            .await?;
        let items = rows
            .iter()
            .map(account_from_row)
            .collect::<Result<_, _>>()?;
        Ok(Page::new(items, total, &query))
    }

    pub async fn get_account(&self, id: i64) -> Result<AccountView, AdminError> {
        let sql = format!(
            "SELECT {ACCOUNT_COLUMNS} FROM accounts a WHERE a.id = $1 AND a.deleted_at IS NULL"
        );
        sqlx::query(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .as_ref()
            .map(account_from_row)
            .transpose()?
            .ok_or(AdminError::NotFound("account"))
    }

    pub async fn create_account(
        &self,
        request: CreateAccountRequest,
    ) -> Result<Mutation<AccountView>, AdminError> {
        let name = required_text("name", &request.name, 100)?;
        let platform = required_text("platform", &request.platform, 50)?;
        let account_type = required_text("type", &request.account_type, 20)?;
        require_object("credentials", &request.credentials)?;
        require_object("extra", &request.extra)?;
        validate_account_numbers(
            request.concurrency,
            request.priority,
            request.rate_multiplier,
            request.load_factor,
        )?;
        let credentials_json = serde_json::to_string(&request.credentials)
            .map_err(|error| AdminError::BadRequest(error.to_string()))?;
        let extra_json = serde_json::to_string(&request.extra)
            .map_err(|error| AdminError::BadRequest(error.to_string()))?;
        let mut transaction = self.pool.begin().await?;
        let group_ids = validate_group_ids(&mut transaction, &request.group_ids).await?;
        validate_proxy_reference(&mut transaction, request.proxy_id).await?;
        let id = sqlx::query_scalar::<_, i64>(
            r"INSERT INTO accounts
              (name, notes, platform, type, credentials, extra, proxy_id, concurrency,
               priority, rate_multiplier, load_factor, status, schedulable, expires_at,
               auto_pause_on_expired)
              VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7, $8, $9, $10, $11,
                      'active', TRUE,
                      CASE WHEN $12::bigint IS NULL THEN NULL ELSE to_timestamp($12) END, $13)
              RETURNING id",
        )
        .bind(name)
        .bind(request.notes.as_deref().map(str::trim))
        .bind(platform)
        .bind(account_type)
        .bind(credentials_json)
        .bind(extra_json)
        .bind(request.proxy_id)
        .bind(request.concurrency)
        .bind(request.priority)
        .bind(request.rate_multiplier)
        .bind(request.load_factor)
        .bind(request.expires_at)
        .bind(request.auto_pause_on_expired)
        .fetch_one(&mut *transaction)
        .await?;
        sync_account_groups(&mut transaction, id, &group_ids, request.priority).await?;
        transaction.commit().await?;
        self.publish_cache_invalidation(AdminCacheInvalidation::Accounts)
            .await;
        Ok(Mutation {
            value: self.get_account(id).await?,
            invalidation_keys: account_invalidation(id),
        })
    }

    pub async fn update_account(
        &self,
        id: i64,
        request: UpdateAccountRequest,
    ) -> Result<Mutation<AccountView>, AdminError> {
        let mut transaction = self.pool.begin().await?;
        let current = sqlx::query(
            "SELECT credentials::text AS credentials_json, priority FROM accounts WHERE id = $1 AND deleted_at IS NULL FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(AdminError::NotFound("account"))?;
        let current_credentials: String = current.try_get("credentials_json")?;
        let current_priority: i32 = current.try_get("priority")?;
        if let Some(value) = request.concurrency {
            validate_nonnegative_i32("concurrency", value)?;
        }
        if let Some(value) = request.priority {
            validate_priority(value)?;
        }
        if let Some(value) = request.rate_multiplier {
            validate_positive_finite("rate_multiplier", value)?;
        }
        if let Patch::Value(value) = request.load_factor {
            validate_nonnegative_i32("load_factor", value)?;
        }
        if let Some(status) = request.status.as_deref() {
            validate_account_status(status)?;
        }
        let credentials_json = request
            .credentials
            .as_ref()
            .map(|incoming| {
                require_object("credentials", incoming)?;
                let current: Value = serde_json::from_str(&current_credentials)
                    .map_err(|error| AdminError::Database(sqlx::Error::Decode(Box::new(error))))?;
                serde_json::to_string(&merge_credentials(&current, incoming))
                    .map_err(|error| AdminError::BadRequest(error.to_string()))
            })
            .transpose()?;
        let extra_json = request
            .extra
            .as_ref()
            .map(|value| {
                require_object("extra", value)?;
                serde_json::to_string(value)
                    .map_err(|error| AdminError::BadRequest(error.to_string()))
            })
            .transpose()?;
        let (notes_set, notes) = patch_parts(&request.notes);
        let (proxy_set, proxy_id) = patch_parts(&request.proxy_id);
        let (load_set, load_factor) = patch_parts(&request.load_factor);
        let (expires_set, expires_at) = patch_parts(&request.expires_at);
        if proxy_set {
            validate_proxy_reference(&mut transaction, proxy_id).await?;
        }
        let result = sqlx::query(
            r"UPDATE accounts SET
              name = COALESCE($2, name),
              notes = CASE WHEN $3 THEN $4 ELSE notes END,
              type = COALESCE($5, type),
              credentials = COALESCE($6::jsonb, credentials), extra = COALESCE($7::jsonb, extra),
              proxy_id = CASE WHEN $8 THEN $9 ELSE proxy_id END,
              concurrency = COALESCE($10, concurrency), priority = COALESCE($11, priority),
              rate_multiplier = COALESCE($12, rate_multiplier),
              load_factor = CASE WHEN $13 THEN $14 ELSE load_factor END,
              status = COALESCE($15, status), schedulable = COALESCE($16, schedulable),
              expires_at = CASE WHEN $17 THEN
                CASE WHEN $18::bigint IS NULL THEN NULL ELSE to_timestamp($18) END
                ELSE expires_at END,
              auto_pause_on_expired = COALESCE($19, auto_pause_on_expired), updated_at = NOW()
              WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(id)
        .bind(request.name.map(|value| value.trim().to_owned()))
        .bind(notes_set)
        .bind(notes)
        .bind(request.account_type)
        .bind(credentials_json)
        .bind(extra_json)
        .bind(proxy_set)
        .bind(proxy_id)
        .bind(request.concurrency)
        .bind(request.priority)
        .bind(request.rate_multiplier)
        .bind(load_set)
        .bind(load_factor)
        .bind(request.status)
        .bind(request.schedulable)
        .bind(expires_set)
        .bind(expires_at)
        .bind(request.auto_pause_on_expired)
        .execute(&mut *transaction)
        .await?;
        ensure_deleted(result.rows_affected(), "account")?;
        if let Some(group_ids) = request.group_ids {
            let group_ids = validate_group_ids(&mut transaction, &group_ids).await?;
            let priority = request.priority.unwrap_or(current_priority);
            sync_account_groups(&mut transaction, id, &group_ids, priority).await?;
        }
        transaction.commit().await?;
        self.publish_cache_invalidation(AdminCacheInvalidation::Accounts)
            .await;
        Ok(Mutation {
            value: self.get_account(id).await?,
            invalidation_keys: account_invalidation(id),
        })
    }

    pub async fn delete_account(&self, id: i64) -> Result<Mutation<()>, AdminError> {
        let result = sqlx::query(ACCOUNT_SOFT_DELETE_SQL)
            .bind(id)
            .execute(&self.pool)
            .await?;
        ensure_deleted(result.rows_affected(), "account")?;
        self.publish_cache_invalidation(AdminCacheInvalidation::Accounts)
            .await;
        Ok(Mutation {
            value: (),
            invalidation_keys: account_invalidation(id),
        })
    }

    pub async fn test_account(&self, id: i64) -> Result<ProbeResult, AdminError> {
        let probe = self.account_probe.as_ref().ok_or_else(|| {
            AdminError::BadRequest("account connection testing is not configured".to_owned())
        })?;
        let row = sqlx::query(
            r"SELECT id, platform, type AS account_type, credentials::text AS credentials_json,
                     extra::text AS extra_json, proxy_id
              FROM accounts WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(AdminError::NotFound("account"))?;
        let credentials = json_from_row(&row, "credentials_json")?;
        let extra = json_from_row(&row, "extra_json")?;
        let platform: String = row.try_get("platform")?;
        let account_type: String = row.try_get("account_type")?;
        let mut urls = BTreeSet::new();
        collect_probe_urls(&credentials, &mut urls);
        collect_probe_urls(&extra, &mut urls);
        if urls.is_empty()
            && let Some(url) = default_account_probe_url(&platform)
        {
            urls.insert(url.to_owned());
        }
        let mut validated_targets = Vec::with_capacity(urls.len());
        for url in urls {
            validated_targets.push(validate_public_probe_target(&url).await?);
        }
        let proxy_id: Option<i64> = row.try_get("proxy_id")?;
        let proxy = if let Some(proxy_id) = proxy_id {
            let proxy = sqlx::query(
                r"SELECT protocol, host, port, username, password
                  FROM proxies
                  WHERE id = $1 AND deleted_at IS NULL AND status = 'active'
                    AND (expires_at IS NULL OR expires_at > NOW())",
            )
            .bind(proxy_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| AdminError::BadRequest("account proxy is unavailable".to_owned()))?;
            let host: String = proxy.try_get("host")?;
            let port: i32 = proxy.try_get("port")?;
            if !(1..=65_535).contains(&port) {
                return Err(AdminError::BadRequest("proxy port is invalid".to_owned()));
            }
            let protocol = proxy
                .try_get::<String, _>("protocol")?
                .trim()
                .to_ascii_lowercase();
            if !matches!(protocol.as_str(), "http" | "https" | "socks5" | "socks5h") {
                return Err(AdminError::BadRequest(
                    "proxy protocol is unsupported".to_owned(),
                ));
            }
            let validation_url = format!("http://{}:{port}", format_url_host(&host));
            let validated_target = validate_public_probe_target(&validation_url).await?;
            Some(ProbeProxy::new(
                protocol,
                host,
                u16::try_from(port)
                    .map_err(|_| AdminError::BadRequest("proxy port is invalid".to_owned()))?,
                proxy.try_get("username")?,
                proxy.try_get("password")?,
                validated_target,
            ))
        } else {
            None
        };
        probe
            .probe(ProbeRequest {
                account: ProbeAccount {
                    id,
                    platform,
                    account_type,
                    credentials,
                    extra,
                },
                validated_targets,
                proxy,
            })
            .await
            .map_err(AdminError::Probe)
    }

    pub async fn list_proxies(&self, query: PageQuery) -> Result<Page<ProxyView>, AdminError> {
        let query = query.normalized();
        let search = query.search.as_deref().map(like_pattern);
        let total = sqlx::query_scalar::<_, i64>(
            r"SELECT COUNT(*) FROM proxies p WHERE p.deleted_at IS NULL
              AND ($1::text IS NULL OR p.name ILIKE $1 OR p.host ILIKE $1)
              AND ($2::text IS NULL OR p.status = $2)",
        )
        .bind(search.as_deref())
        .bind(query.status.as_deref())
        .fetch_one(&self.pool)
        .await?;
        let sql = format!(
            "SELECT {PROXY_COLUMNS} FROM proxies p WHERE p.deleted_at IS NULL
             AND ($1::text IS NULL OR p.name ILIKE $1 OR p.host ILIKE $1)
             AND ($2::text IS NULL OR p.status = $2)
             ORDER BY p.id DESC LIMIT $3 OFFSET $4"
        );
        let rows = sqlx::query(&sql)
            .bind(search.as_deref())
            .bind(query.status.as_deref())
            .bind(query.page_size)
            .bind(query.offset())
            .fetch_all(&self.pool)
            .await?;
        let items = rows.iter().map(proxy_from_row).collect::<Result<_, _>>()?;
        Ok(Page::new(items, total, &query))
    }

    pub async fn get_proxy(&self, id: i64) -> Result<ProxyView, AdminError> {
        let sql = format!(
            "SELECT {PROXY_COLUMNS} FROM proxies p WHERE p.id = $1 AND p.deleted_at IS NULL"
        );
        sqlx::query(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .as_ref()
            .map(proxy_from_row)
            .transpose()?
            .ok_or(AdminError::NotFound("proxy"))
    }

    pub async fn create_proxy(
        &self,
        request: CreateProxyRequest,
    ) -> Result<Mutation<ProxyView>, AdminError> {
        validate_proxy_request(&request.protocol, &request.host, request.port)?;
        validate_fallback_mode(&request.fallback_mode)?;
        validate_nonnegative_i32("expiry_warn_days", request.expiry_warn_days)?;
        if request.backup_proxy_id.is_some() && request.fallback_mode != "proxy" {
            return Err(AdminError::BadRequest(
                "backup_proxy_id requires proxy fallback mode".to_owned(),
            ));
        }
        let id = sqlx::query_scalar::<_, i64>(
            r"INSERT INTO proxies
              (name, protocol, host, port, username, password, status, expires_at,
               fallback_mode, backup_proxy_id, expiry_warn_days)
              VALUES ($1, $2, $3, $4, $5, $6, 'active',
                      CASE WHEN $7::bigint IS NULL THEN NULL ELSE to_timestamp($7) END,
                      $8, $9, $10) RETURNING id",
        )
        .bind(required_text("name", &request.name, 100)?)
        .bind(request.protocol.trim().to_lowercase())
        .bind(request.host.trim())
        .bind(request.port)
        .bind(request.username.as_deref().map(str::trim))
        .bind(request.password.filter(|value| !value.is_empty()))
        .bind(request.expires_at)
        .bind(request.fallback_mode)
        .bind(request.backup_proxy_id)
        .bind(request.expiry_warn_days)
        .fetch_one(&self.pool)
        .await?;
        self.publish_cache_invalidation(AdminCacheInvalidation::Accounts)
            .await;
        Ok(Mutation {
            value: self.get_proxy(id).await?,
            invalidation_keys: proxy_invalidation(id),
        })
    }

    pub async fn update_proxy(
        &self,
        id: i64,
        request: UpdateProxyRequest,
    ) -> Result<Mutation<ProxyView>, AdminError> {
        if let Some(protocol) = request.protocol.as_deref() {
            validate_proxy_protocol(protocol)?;
        }
        if let Some(host) = request.host.as_deref() {
            required_text("host", host, 255)?;
        }
        if let Some(port) = request.port
            && !(1..=65_535).contains(&port)
        {
            return Err(AdminError::BadRequest("proxy port is invalid".to_owned()));
        }
        if let Some(status) = request.status.as_deref() {
            validate_status(status)?;
        }
        if let Some(mode) = request.fallback_mode.as_deref() {
            validate_fallback_mode(mode)?;
        }
        if let Some(days) = request.expiry_warn_days {
            validate_nonnegative_i32("expiry_warn_days", days)?;
        }
        let (username_set, username) = patch_parts(&request.username);
        let password = request.password.filter(|value| !value.is_empty());
        let (expires_set, expires_at) = patch_parts(&request.expires_at);
        let (backup_set, backup_proxy_id) = patch_parts(&request.backup_proxy_id);
        if backup_proxy_id == Some(id) {
            return Err(AdminError::BadRequest(
                "a proxy cannot use itself as its backup".to_owned(),
            ));
        }
        let result = sqlx::query(
            r"UPDATE proxies SET name = COALESCE($2, name), protocol = COALESCE($3, protocol),
              host = COALESCE($4, host), port = COALESCE($5, port),
              username = CASE WHEN $6 THEN $7 ELSE username END,
              password = COALESCE($8, password), status = COALESCE($9, status),
              expires_at = CASE WHEN $10 THEN
                CASE WHEN $11::bigint IS NULL THEN NULL ELSE to_timestamp($11) END
                ELSE expires_at END,
              fallback_mode = COALESCE($12, fallback_mode),
              backup_proxy_id = CASE WHEN $13 THEN $14 ELSE backup_proxy_id END,
              expiry_warn_days = COALESCE($15, expiry_warn_days), updated_at = NOW()
              WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(id)
        .bind(request.name.map(|value| value.trim().to_owned()))
        .bind(request.protocol.map(|value| value.trim().to_lowercase()))
        .bind(request.host.map(|value| value.trim().to_owned()))
        .bind(request.port)
        .bind(username_set)
        .bind(username)
        .bind(password)
        .bind(request.status)
        .bind(expires_set)
        .bind(expires_at)
        .bind(request.fallback_mode)
        .bind(backup_set)
        .bind(backup_proxy_id)
        .bind(request.expiry_warn_days)
        .execute(&self.pool)
        .await?;
        ensure_deleted(result.rows_affected(), "proxy")?;
        self.publish_cache_invalidation(AdminCacheInvalidation::Accounts)
            .await;
        Ok(Mutation {
            value: self.get_proxy(id).await?,
            invalidation_keys: proxy_invalidation(id),
        })
    }

    pub async fn delete_proxy(&self, id: i64) -> Result<Mutation<()>, AdminError> {
        let result = sqlx::query(PROXY_SOFT_DELETE_SQL)
            .bind(id)
            .execute(&self.pool)
            .await?;
        ensure_deleted(result.rows_affected(), "proxy")?;
        self.publish_cache_invalidation(AdminCacheInvalidation::Accounts)
            .await;
        Ok(Mutation {
            value: (),
            invalidation_keys: proxy_invalidation(id),
        })
    }

    pub async fn list_api_keys(&self, query: PageQuery) -> Result<Page<ApiKeyView>, AdminError> {
        let query = query.normalized();
        let search = query.search.as_deref().map(like_pattern);
        let total = sqlx::query_scalar::<_, i64>(
            r"SELECT COUNT(*) FROM api_keys k WHERE k.deleted_at IS NULL
              AND ($1::text IS NULL OR k.name ILIKE $1 OR k.key ILIKE $1)
              AND ($2::text IS NULL OR k.status = $2)",
        )
        .bind(search.as_deref())
        .bind(query.status.as_deref())
        .fetch_one(&self.pool)
        .await?;
        let sql = format!(
            "SELECT {API_KEY_COLUMNS} FROM api_keys k WHERE k.deleted_at IS NULL
             AND ($1::text IS NULL OR k.name ILIKE $1 OR k.key ILIKE $1)
             AND ($2::text IS NULL OR k.status = $2)
             ORDER BY k.id DESC LIMIT $3 OFFSET $4"
        );
        let rows = sqlx::query(&sql)
            .bind(search.as_deref())
            .bind(query.status.as_deref())
            .bind(query.page_size)
            .bind(query.offset())
            .fetch_all(&self.pool)
            .await?;
        let items = rows
            .iter()
            .map(api_key_from_row)
            .collect::<Result<_, _>>()?;
        Ok(Page::new(items, total, &query))
    }

    pub async fn get_api_key(&self, id: i64) -> Result<ApiKeyView, AdminError> {
        let sql = format!(
            "SELECT {API_KEY_COLUMNS} FROM api_keys k WHERE k.id = $1 AND k.deleted_at IS NULL"
        );
        sqlx::query(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .as_ref()
            .map(api_key_from_row)
            .transpose()?
            .ok_or(AdminError::NotFound("API key"))
    }

    pub async fn create_api_key(
        &self,
        request: CreateApiKeyRequest,
    ) -> Result<Mutation<ApiKeyView>, AdminError> {
        let key = request
            .custom_key
            .as_deref()
            .map(validate_api_key_secret)
            .transpose()?
            .unwrap_or_else(generate_api_key);
        validate_ip_rules(&request.ip_whitelist)?;
        validate_ip_rules(&request.ip_blacklist)?;
        validate_api_key_limits(
            request.quota,
            request.rate_limit_5h,
            request.rate_limit_1d,
            request.rate_limit_7d,
        )?;
        let whitelist = serde_json::to_string(&request.ip_whitelist)
            .map_err(|error| AdminError::BadRequest(error.to_string()))?;
        let blacklist = serde_json::to_string(&request.ip_blacklist)
            .map_err(|error| AdminError::BadRequest(error.to_string()))?;
        let id = sqlx::query_scalar::<_, i64>(
            r"INSERT INTO api_keys
              (user_id, key, name, group_id, status, ip_whitelist, ip_blacklist, quota,
               quota_used, expires_at, rate_limit_5h, rate_limit_1d, rate_limit_7d)
              SELECT $1, $2, $3, $4, 'active', $5::jsonb, $6::jsonb, $7, 0,
                     CASE WHEN $8::bigint IS NULL THEN NULL ELSE to_timestamp($8) END,
                     $9, $10, $11
              WHERE EXISTS (SELECT 1 FROM users WHERE id = $1 AND deleted_at IS NULL)
                AND ($4::bigint IS NULL OR EXISTS
                    (SELECT 1 FROM groups WHERE id = $4 AND deleted_at IS NULL))
              RETURNING id",
        )
        .bind(request.user_id)
        .bind(&key)
        .bind(required_text("name", &request.name, 100)?)
        .bind(request.group_id)
        .bind(whitelist)
        .bind(blacklist)
        .bind(request.quota)
        .bind(request.expires_at)
        .bind(request.rate_limit_5h)
        .bind(request.rate_limit_1d)
        .bind(request.rate_limit_7d)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AdminError::BadRequest("user or group does not exist".to_owned()))?;
        self.publish_cache_invalidation(AdminCacheInvalidation::ApiKey { id, raw_key: &key })
            .await;
        Ok(Mutation {
            value: self.get_api_key(id).await?,
            invalidation_keys: api_key_invalidation(id, &key),
        })
    }

    pub async fn update_api_key(
        &self,
        id: i64,
        request: UpdateApiKeyRequest,
    ) -> Result<Mutation<ApiKeyView>, AdminError> {
        if let Some(status) = request.status.as_deref() {
            validate_status(status)?;
        }
        if let Some(value) = request.ip_whitelist.as_ref() {
            validate_ip_rules(value)?;
        }
        if let Some(value) = request.ip_blacklist.as_ref() {
            validate_ip_rules(value)?;
        }
        for (name, value) in [
            ("quota", request.quota),
            ("rate_limit_5h", request.rate_limit_5h),
            ("rate_limit_1d", request.rate_limit_1d),
            ("rate_limit_7d", request.rate_limit_7d),
        ] {
            if let Some(value) = value {
                validate_nonnegative_finite(name, value)?;
            }
        }
        let old_key = sqlx::query_scalar::<_, String>(
            "SELECT key FROM api_keys WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(AdminError::NotFound("API key"))?;
        let (group_set, group_id) = patch_parts(&request.group_id);
        let (expires_set, expires_at) = patch_parts(&request.expires_at);
        let whitelist = request
            .ip_whitelist
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|error| AdminError::BadRequest(error.to_string()))?;
        let blacklist = request
            .ip_blacklist
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|error| AdminError::BadRequest(error.to_string()))?;
        let result = sqlx::query(
            r"UPDATE api_keys SET name = COALESCE($2, name),
              group_id = CASE WHEN $3 THEN $4 ELSE group_id END,
              status = COALESCE($5, status), ip_whitelist = COALESCE($6::jsonb, ip_whitelist),
              ip_blacklist = COALESCE($7::jsonb, ip_blacklist), quota = COALESCE($8, quota),
              quota_used = CASE WHEN $9 THEN 0 ELSE quota_used END,
              expires_at = CASE WHEN $10 THEN
                CASE WHEN $11::bigint IS NULL THEN NULL ELSE to_timestamp($11) END
                ELSE expires_at END,
              rate_limit_5h = COALESCE($12, rate_limit_5h),
              rate_limit_1d = COALESCE($13, rate_limit_1d),
              rate_limit_7d = COALESCE($14, rate_limit_7d), updated_at = NOW()
              WHERE id = $1 AND deleted_at IS NULL
                AND ($4::bigint IS NULL OR EXISTS
                    (SELECT 1 FROM groups WHERE id = $4 AND deleted_at IS NULL))",
        )
        .bind(id)
        .bind(request.name.map(|value| value.trim().to_owned()))
        .bind(group_set)
        .bind(group_id)
        .bind(request.status)
        .bind(whitelist)
        .bind(blacklist)
        .bind(request.quota)
        .bind(request.reset_quota)
        .bind(expires_set)
        .bind(expires_at)
        .bind(request.rate_limit_5h)
        .bind(request.rate_limit_1d)
        .bind(request.rate_limit_7d)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(AdminError::BadRequest(
                "API key or selected group does not exist".to_owned(),
            ));
        }
        self.publish_cache_invalidation(AdminCacheInvalidation::ApiKey {
            id,
            raw_key: &old_key,
        })
        .await;
        Ok(Mutation {
            value: self.get_api_key(id).await?,
            invalidation_keys: api_key_invalidation(id, &old_key),
        })
    }

    pub async fn delete_api_key(&self, id: i64) -> Result<Mutation<()>, AdminError> {
        let key = sqlx::query_scalar::<_, String>(
            "SELECT key FROM api_keys WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(AdminError::NotFound("API key"))?;
        let result = sqlx::query(API_KEY_SOFT_DELETE_SQL)
            .bind(id)
            .execute(&self.pool)
            .await?;
        ensure_deleted(result.rows_affected(), "API key")?;
        self.publish_cache_invalidation(AdminCacheInvalidation::ApiKey { id, raw_key: &key })
            .await;
        Ok(Mutation {
            value: (),
            invalidation_keys: api_key_invalidation(id, &key),
        })
    }

    pub async fn get_settings(&self) -> Result<BTreeMap<String, Value>, AdminError> {
        let rows = sqlx::query("SELECT key, value FROM settings ORDER BY key")
            .fetch_all(&self.pool)
            .await?;
        let mut values = BTreeMap::new();
        for row in rows {
            let key: String = row.try_get("key")?;
            let raw: String = row.try_get("value")?;
            let value = serde_json::from_str(&raw).unwrap_or(Value::String(raw));
            values.insert(key, value);
        }
        Ok(values)
    }

    pub async fn update_settings(
        &self,
        request: SettingPatchRequest,
    ) -> Result<Mutation<BTreeMap<String, Value>>, AdminError> {
        if request.values.is_empty() {
            return Err(AdminError::BadRequest(
                "at least one setting is required".to_owned(),
            ));
        }
        let mut transaction = self.pool.begin().await?;
        for (key, value) in &request.values {
            validate_setting_key(key)?;
            let raw = setting_to_storage(value)?;
            sqlx::query(
                r"INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, NOW())
                  ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
            )
            .bind(key)
            .bind(raw)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        self.publish_cache_invalidation(AdminCacheInvalidation::Settings)
            .await;
        let mut invalidation_keys = request
            .values
            .keys()
            .map(|key| InvalidationKey(format!("setting:{key}")))
            .collect::<Vec<_>>();
        invalidation_keys.extend([
            InvalidationKey("settings:public".to_owned()),
            InvalidationKey("gateway:runtime".to_owned()),
        ]);
        Ok(Mutation {
            value: self.get_settings().await?,
            invalidation_keys,
        })
    }
}

pub async fn validate_public_probe_target(
    raw_url: &str,
) -> Result<ValidatedProbeTarget, AdminError> {
    let url = Url::parse(raw_url)
        .map_err(|_| AdminError::BadRequest("probe target URL is invalid".to_owned()))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(AdminError::BadRequest(
            "probe target must use HTTP or HTTPS".to_owned(),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(AdminError::BadRequest(
            "probe target must not contain URL credentials".to_owned(),
        ));
    }
    let host = url
        .host()
        .ok_or_else(|| AdminError::BadRequest("probe target host is required".to_owned()))?;
    let port = url.port_or_known_default().ok_or_else(|| {
        AdminError::BadRequest("probe target port could not be determined".to_owned())
    })?;
    let resolved = match host {
        Host::Ipv4(address) => vec![SocketAddr::new(IpAddr::V4(address), port)],
        Host::Ipv6(address) => vec![SocketAddr::new(IpAddr::V6(address), port)],
        Host::Domain(domain) => {
            validate_public_hostname(domain)?;
            timeout(Duration::from_secs(3), lookup_host((domain, port)))
                .await
                .map_err(|_| {
                    AdminError::BadRequest("probe target DNS lookup timed out".to_owned())
                })?
                .map_err(|_| AdminError::BadRequest("probe target DNS lookup failed".to_owned()))?
                .collect::<Vec<_>>()
        }
    };
    if resolved.is_empty() || resolved.iter().any(|address| !is_public_ip(address.ip())) {
        return Err(AdminError::BadRequest(
            "probe target resolves to a non-public address".to_owned(),
        ));
    }
    let resolved = resolved
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    Ok(ValidatedProbeTarget::new(url.to_string(), resolved))
}

fn password_fingerprint_token_version(email: &str, password_hash: &str) -> i64 {
    let material = format!("{}\n{password_hash}", email.trim().to_lowercase());
    let digest = Sha256::digest(material.as_bytes());
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    i64::from_be_bytes(prefix) & i64::MAX
}

fn session_token_version(email: &str, password_hash: &str, auth_generation: i64) -> i64 {
    let fingerprint = password_fingerprint_token_version(email, password_hash);
    if auth_generation == 0 {
        return fingerprint;
    }
    let mut hasher = Sha256::new();
    hasher.update(b"sub2api/auth-generation/v1\0");
    hasher.update(fingerprint.to_be_bytes());
    hasher.update(auth_generation.to_be_bytes());
    let digest = hasher.finalize();
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    i64::from_be_bytes(prefix) & i64::MAX
}

fn user_from_row(row: &PgRow) -> Result<UserView, AdminError> {
    Ok(UserView {
        id: row.try_get("id")?,
        email: row.try_get("email")?,
        username: row.try_get("username")?,
        notes: row.try_get("notes")?,
        role: row.try_get("role")?,
        balance: row.try_get("balance")?,
        concurrency: row.try_get("concurrency")?,
        rpm_limit: row.try_get("rpm_limit")?,
        status: row.try_get("status")?,
        allowed_groups: row.try_get("allowed_groups")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn group_from_row(row: &PgRow) -> Result<GroupView, AdminError> {
    Ok(GroupView {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        platform: row.try_get("platform")?,
        rate_multiplier: row.try_get("rate_multiplier")?,
        is_exclusive: row.try_get("is_exclusive")?,
        status: row.try_get("status")?,
        subscription_type: row.try_get("subscription_type")?,
        rpm_limit: row.try_get("rpm_limit")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn account_from_row(row: &PgRow) -> Result<AccountView, AdminError> {
    let credentials = json_from_row(row, "credentials_json")?;
    let (credentials, credentials_status) = redact_credentials(&credentials);
    Ok(AccountView {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        notes: row.try_get("notes")?,
        platform: row.try_get("platform")?,
        account_type: row.try_get("account_type")?,
        credentials,
        credentials_status,
        extra: json_from_row(row, "extra_json")?,
        proxy_id: row.try_get("proxy_id")?,
        concurrency: row.try_get("concurrency")?,
        priority: row.try_get("priority")?,
        rate_multiplier: row.try_get("rate_multiplier")?,
        load_factor: row.try_get("load_factor")?,
        status: row.try_get("status")?,
        schedulable: row.try_get("schedulable")?,
        group_ids: row.try_get("group_ids")?,
        expires_at: row.try_get("expires_at")?,
        auto_pause_on_expired: row.try_get("auto_pause_on_expired")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn proxy_from_row(row: &PgRow) -> Result<ProxyView, AdminError> {
    Ok(ProxyView {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        protocol: row.try_get("protocol")?,
        host: row.try_get("host")?,
        port: row.try_get("port")?,
        username: row.try_get("username")?,
        has_password: row.try_get("has_password")?,
        status: row.try_get("status")?,
        expires_at: row.try_get("expires_at")?,
        fallback_mode: row.try_get("fallback_mode")?,
        backup_proxy_id: row.try_get("backup_proxy_id")?,
        expiry_warn_days: row.try_get("expiry_warn_days")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn api_key_from_row(row: &PgRow) -> Result<ApiKeyView, AdminError> {
    let whitelist: String = row.try_get("ip_whitelist_json")?;
    let blacklist: String = row.try_get("ip_blacklist_json")?;
    Ok(ApiKeyView {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        key: row.try_get("key")?,
        name: row.try_get("name")?,
        group_id: row.try_get("group_id")?,
        status: row.try_get("status")?,
        ip_whitelist: serde_json::from_str(&whitelist).unwrap_or_default(),
        ip_blacklist: serde_json::from_str(&blacklist).unwrap_or_default(),
        quota: row.try_get("quota")?,
        quota_used: row.try_get("quota_used")?,
        expires_at: row.try_get("expires_at")?,
        rate_limit_5h: row.try_get("rate_limit_5h")?,
        rate_limit_1d: row.try_get("rate_limit_1d")?,
        rate_limit_7d: row.try_get("rate_limit_7d")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn json_from_row(row: &PgRow, column: &str) -> Result<Value, AdminError> {
    let raw: String = row.try_get(column)?;
    serde_json::from_str(&raw)
        .map_err(|error| AdminError::Database(sqlx::Error::Decode(Box::new(error))))
}

async fn validate_group_ids(
    transaction: &mut Transaction<'_, Postgres>,
    ids: &[i64],
) -> Result<Vec<i64>, AdminError> {
    let ids = ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if ids.iter().any(|id| *id <= 0) {
        return Err(AdminError::BadRequest(
            "group IDs must be positive".to_owned(),
        ));
    }
    if ids.is_empty() {
        return Ok(ids);
    }
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM groups WHERE id = ANY($1) AND deleted_at IS NULL",
    )
    .bind(&ids)
    .fetch_one(&mut **transaction)
    .await?;
    if usize::try_from(count).ok() != Some(ids.len()) {
        return Err(AdminError::BadRequest(
            "one or more groups do not exist".to_owned(),
        ));
    }
    Ok(ids)
}

async fn sync_user_groups(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i64,
    group_ids: &[i64],
) -> Result<(), AdminError> {
    sqlx::query("DELETE FROM user_allowed_groups WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut **transaction)
        .await?;
    if !group_ids.is_empty() {
        sqlx::query(
            "INSERT INTO user_allowed_groups (user_id, group_id) SELECT $1, unnest($2::bigint[])",
        )
        .bind(user_id)
        .bind(group_ids)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

async fn sync_account_groups(
    transaction: &mut Transaction<'_, Postgres>,
    account_id: i64,
    group_ids: &[i64],
    priority: i32,
) -> Result<(), AdminError> {
    sqlx::query("DELETE FROM account_groups WHERE account_id = $1")
        .bind(account_id)
        .execute(&mut **transaction)
        .await?;
    if !group_ids.is_empty() {
        sqlx::query(
            r"INSERT INTO account_groups (account_id, group_id, priority)
              SELECT $1, unnest($2::bigint[]), $3",
        )
        .bind(account_id)
        .bind(group_ids)
        .bind(priority)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

async fn validate_proxy_reference(
    transaction: &mut Transaction<'_, Postgres>,
    proxy_id: Option<i64>,
) -> Result<(), AdminError> {
    let Some(proxy_id) = proxy_id else {
        return Ok(());
    };
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM proxies WHERE id = $1 AND deleted_at IS NULL)",
    )
    .bind(proxy_id)
    .fetch_one(&mut **transaction)
    .await?;
    if !exists {
        return Err(AdminError::BadRequest("proxy does not exist".to_owned()));
    }
    Ok(())
}

fn patch_parts<T: Clone>(patch: &Patch<T>) -> (bool, Option<T>) {
    match patch {
        Patch::Missing => (false, None),
        Patch::Null => (true, None),
        Patch::Value(value) => (true, Some(value.clone())),
    }
}

fn normalize_email(raw: &str) -> Result<String, AdminError> {
    let email = raw.trim().to_lowercase();
    let valid = email.len() <= 255
        && email
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'));
    if valid {
        Ok(email)
    } else {
        Err(AdminError::BadRequest(
            "email address is invalid".to_owned(),
        ))
    }
}

fn validate_password(password: &str) -> Result<(), AdminError> {
    if (8..=128).contains(&password.len()) {
        Ok(())
    } else {
        Err(AdminError::BadRequest(
            "password must contain between 8 and 128 bytes".to_owned(),
        ))
    }
}

fn required_text<'a>(name: &str, value: &'a str, max: usize) -> Result<&'a str, AdminError> {
    let value = value.trim();
    if value.is_empty() || value.len() > max {
        return Err(AdminError::BadRequest(format!(
            "{name} must contain between 1 and {max} bytes"
        )));
    }
    Ok(value)
}

fn validate_user_role(role: &str) -> Result<(), AdminError> {
    if matches!(role, "admin" | "user") {
        Ok(())
    } else {
        Err(AdminError::BadRequest("user role is invalid".to_owned()))
    }
}

fn validate_status(status: &str) -> Result<(), AdminError> {
    if matches!(status, "active" | "disabled") {
        Ok(())
    } else {
        Err(AdminError::BadRequest("status is invalid".to_owned()))
    }
}

fn validate_account_status(status: &str) -> Result<(), AdminError> {
    if matches!(status, "active" | "disabled" | "error") {
        Ok(())
    } else {
        Err(AdminError::BadRequest(
            "account status is invalid".to_owned(),
        ))
    }
}

fn validate_finite(name: &str, value: f64) -> Result<(), AdminError> {
    if value.is_finite() {
        Ok(())
    } else {
        Err(AdminError::BadRequest(format!("{name} must be finite")))
    }
}

fn validate_nonnegative_finite(name: &str, value: f64) -> Result<(), AdminError> {
    validate_finite(name, value)?;
    if value >= 0.0 {
        Ok(())
    } else {
        Err(AdminError::BadRequest(format!(
            "{name} must not be negative"
        )))
    }
}

fn validate_positive_finite(name: &str, value: f64) -> Result<(), AdminError> {
    validate_finite(name, value)?;
    if value >= 0.0 {
        Ok(())
    } else {
        Err(AdminError::BadRequest(format!(
            "{name} must not be negative"
        )))
    }
}

fn validate_nonnegative_i32(name: &str, value: i32) -> Result<(), AdminError> {
    if value >= 0 {
        Ok(())
    } else {
        Err(AdminError::BadRequest(format!(
            "{name} must not be negative"
        )))
    }
}

fn validate_priority(value: i32) -> Result<(), AdminError> {
    if (1..=100).contains(&value) {
        Ok(())
    } else {
        Err(AdminError::BadRequest(
            "priority must be between 1 and 100".to_owned(),
        ))
    }
}

fn validate_account_numbers(
    concurrency: i32,
    priority: i32,
    rate_multiplier: f64,
    load_factor: Option<i32>,
) -> Result<(), AdminError> {
    validate_nonnegative_i32("concurrency", concurrency)?;
    validate_priority(priority)?;
    validate_positive_finite("rate_multiplier", rate_multiplier)?;
    if let Some(value) = load_factor {
        validate_nonnegative_i32("load_factor", value)?;
    }
    Ok(())
}

fn require_object(name: &str, value: &Value) -> Result<(), AdminError> {
    if value.is_object() {
        Ok(())
    } else {
        Err(AdminError::BadRequest(format!(
            "{name} must be a JSON object"
        )))
    }
}

fn validate_proxy_request(protocol: &str, host: &str, port: i32) -> Result<(), AdminError> {
    validate_proxy_protocol(protocol)?;
    required_text("host", host, 255)?;
    if !(1..=65_535).contains(&port) {
        return Err(AdminError::BadRequest("proxy port is invalid".to_owned()));
    }
    Ok(())
}

fn validate_proxy_protocol(protocol: &str) -> Result<(), AdminError> {
    if matches!(
        protocol.trim().to_lowercase().as_str(),
        "http" | "https" | "socks5"
    ) {
        Ok(())
    } else {
        Err(AdminError::BadRequest(
            "proxy protocol is invalid".to_owned(),
        ))
    }
}

fn validate_fallback_mode(mode: &str) -> Result<(), AdminError> {
    if matches!(mode, "none" | "proxy" | "direct") {
        Ok(())
    } else {
        Err(AdminError::BadRequest(
            "proxy fallback mode is invalid".to_owned(),
        ))
    }
}

fn validate_api_key_secret(secret: &str) -> Result<String, AdminError> {
    let secret = secret.trim();
    if secret.starts_with("sk-")
        && (16..=128).contains(&secret.len())
        && secret.chars().all(|character| character.is_ascii_graphic())
    {
        Ok(secret.to_owned())
    } else {
        Err(AdminError::BadRequest(
            "custom API key must use the sk- prefix and contain 16 to 128 visible ASCII bytes"
                .to_owned(),
        ))
    }
}

fn generate_api_key() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    format!("sk-{}", hex::encode(bytes))
}

fn validate_ip_rules(rules: &[String]) -> Result<(), AdminError> {
    for rule in rules {
        let rule = rule.trim();
        if rule.parse::<IpAddr>().is_err() && rule.parse::<ipnet::IpNet>().is_err() {
            return Err(AdminError::BadRequest(format!(
                "IP restriction rule is invalid: {rule}"
            )));
        }
    }
    Ok(())
}

fn validate_api_key_limits(
    quota: f64,
    five_hours: f64,
    one_day: f64,
    seven_days: f64,
) -> Result<(), AdminError> {
    validate_nonnegative_finite("quota", quota)?;
    validate_nonnegative_finite("rate_limit_5h", five_hours)?;
    validate_nonnegative_finite("rate_limit_1d", one_day)?;
    validate_nonnegative_finite("rate_limit_7d", seven_days)
}

fn validate_setting_key(key: &str) -> Result<(), AdminError> {
    if key.is_empty()
        || key.len() > 100
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(AdminError::BadRequest(format!(
            "setting key is invalid: {key}"
        )));
    }
    Ok(())
}

fn setting_to_storage(value: &Value) -> Result<String, AdminError> {
    if let Value::String(value) = value {
        Ok(value.clone())
    } else {
        serde_json::to_string(value).map_err(|error| AdminError::BadRequest(error.to_string()))
    }
}

fn collect_probe_urls(value: &Value, urls: &mut BTreeSet<String>) {
    const URL_KEYS: &[&str] = &[
        "base_url",
        "api_base_url",
        "endpoint",
        "url",
        "custom_base_url",
    ];
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                let normalized_key = key.to_ascii_lowercase().replace('-', "_");
                if URL_KEYS.contains(&normalized_key.as_str())
                    && let Some(url) = value.as_str()
                    && !url.trim().is_empty()
                {
                    urls.insert(url.trim().to_owned());
                }
                collect_probe_urls(value, urls);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_probe_urls(item, urls);
            }
        }
        _ => {}
    }
}

fn default_account_probe_url(platform: &str) -> Option<&'static str> {
    match platform.trim().to_ascii_lowercase().as_str() {
        "anthropic" => Some("https://api.anthropic.com/v1/models"),
        "openai" => Some("https://api.openai.com/v1/models"),
        "gemini" => Some("https://generativelanguage.googleapis.com/v1beta/models"),
        "grok" => Some("https://api.x.ai/v1/models"),
        _ => None,
    }
}

fn validate_public_hostname(host: &str) -> Result<(), AdminError> {
    let host = host.trim_end_matches('.').to_lowercase();
    if host.is_empty()
        || host == "localhost"
        || host.ends_with(".localhost")
        || host
            .rsplit('.')
            .next()
            .is_some_and(|label| matches!(label, "local" | "internal" | "lan" | "home"))
    {
        return Err(AdminError::BadRequest(
            "probe target hostname is not public".to_owned(),
        ));
    }
    Ok(())
}

fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    !address.is_private()
        && !address.is_loopback()
        && !address.is_link_local()
        && !address.is_unspecified()
        && !address.is_multicast()
        && !address.is_broadcast()
        && !address.is_documentation()
        && octets[0] != 0
        && !(octets[0] == 100 && (64..=127).contains(&octets[1]))
        && !(octets[0] == 198 && matches!(octets[1], 18 | 19))
        && octets[0] < 240
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }
    !address.is_loopback()
        && !address.is_unspecified()
        && !address.is_multicast()
        && (segments[0] & 0xe000) == 0x2000
        && (segments[0] & 0xfe00) != 0xfc00
        && (segments[0] & 0xffc0) != 0xfe80
        && (segments[0] & 0xffc0) != 0xfec0
        && !(segments[0] == 0x2001 && segments[1] <= 0x01ff)
        && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
}

fn format_url_host(host: &str) -> String {
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

fn like_pattern(value: &str) -> String {
    format!("%{value}%")
}

fn ensure_deleted(rows_affected: u64, resource: &'static str) -> Result<(), AdminError> {
    if rows_affected == 0 {
        Err(AdminError::NotFound(resource))
    } else {
        Ok(())
    }
}

fn user_invalidation(id: i64) -> Vec<InvalidationKey> {
    vec![
        InvalidationKey(format!("user:{id}")),
        InvalidationKey(format!("auth:user:{id}")),
    ]
}

fn group_invalidation(id: i64) -> Vec<InvalidationKey> {
    vec![
        InvalidationKey(format!("group:{id}")),
        InvalidationKey("scheduler:groups".to_owned()),
    ]
}

fn account_invalidation(id: i64) -> Vec<InvalidationKey> {
    vec![
        InvalidationKey(format!("account:{id}")),
        InvalidationKey("scheduler:accounts".to_owned()),
    ]
}

fn proxy_invalidation(id: i64) -> Vec<InvalidationKey> {
    vec![InvalidationKey(format!("proxy:{id}"))]
}

fn api_key_invalidation(id: i64, key: &str) -> Vec<InvalidationKey> {
    vec![
        InvalidationKey(format!("api-key:{id}")),
        InvalidationKey(format!("api-key:secret:{key}")),
    ]
}
