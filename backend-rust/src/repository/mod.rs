mod models;

use std::{collections::BTreeMap, error::Error, fmt};

pub use models::{
    AccountProxyRecord, AccountRecord, ApiKeyAuthRecord, ApiKeyRecord, ChannelModelPricingRecord,
    ChannelPolicyRecord, ChannelPricingIntervalRecord, GroupRecord, STATUS_ACTIVE, STATUS_DELETED,
    SUBSCRIPTION_TYPE_SUBSCRIPTION, SubscriptionBillingRecord, UnixMillis, UserPlatformQuotaRecord,
    UserRecord,
};
use serde_json::Value;
use sqlx::{PgPool, Row, postgres::PgRow};

const USER_BY_ID_SQL: &str = r"
SELECT
    u.id,
    u.email,
    u.username,
    u.password_hash,
    u.auth_generation,
    u.role,
    u.balance::text AS balance,
    u.concurrency,
    u.status,
    u.rpm_limit,
    ARRAY(
        SELECT uag.group_id
        FROM user_allowed_groups uag
        JOIN groups allowed_group
          ON allowed_group.id = uag.group_id
         AND allowed_group.deleted_at IS NULL
        WHERE uag.user_id = u.id
        ORDER BY uag.group_id
    )::bigint[] AS allowed_group_ids
FROM users u
WHERE u.id = $1 AND u.deleted_at IS NULL
LIMIT 1
";

const GROUP_BY_ID_SQL: &str = r"
SELECT
    g.id,
    g.name,
    g.platform,
    g.rate_multiplier::text AS rate_multiplier,
    g.is_exclusive,
    g.status,
    g.subscription_type,
    g.rpm_limit
FROM groups g
WHERE g.id = $1 AND g.deleted_at IS NULL
LIMIT 1
";

const API_KEY_FOR_AUTH_SQL: &str = r"
SELECT
    k.id AS api_key_id,
    k.user_id AS api_key_user_id,
    k.key AS api_key_secret,
    k.name AS api_key_name,
    k.group_id AS api_key_group_id,
    k.status AS api_key_status,
    COALESCE(k.ip_whitelist, '[]'::jsonb)::text AS api_key_ip_whitelist,
    COALESCE(k.ip_blacklist, '[]'::jsonb)::text AS api_key_ip_blacklist,
    k.quota::text AS api_key_quota,
    k.quota_used::text AS api_key_quota_used,
    (EXTRACT(EPOCH FROM k.expires_at) * 1000)::bigint AS api_key_expires_at_unix_ms,
    k.rate_limit_5h::text AS api_key_rate_limit_5h,
    k.rate_limit_1d::text AS api_key_rate_limit_1d,
    k.rate_limit_7d::text AS api_key_rate_limit_7d,
    k.usage_5h::text AS api_key_usage_5h,
    k.usage_1d::text AS api_key_usage_1d,
    k.usage_7d::text AS api_key_usage_7d,
    (EXTRACT(EPOCH FROM k.window_5h_start) * 1000)::bigint
        AS api_key_window_5h_start_unix_ms,
    (EXTRACT(EPOCH FROM k.window_1d_start) * 1000)::bigint
        AS api_key_window_1d_start_unix_ms,
    (EXTRACT(EPOCH FROM k.window_7d_start) * 1000)::bigint
        AS api_key_window_7d_start_unix_ms,
    (
        SELECT ugr.rpm_override
        FROM user_group_rate_multipliers ugr
        WHERE ugr.user_id = k.user_id AND ugr.group_id = k.group_id
        LIMIT 1
    ) AS api_key_group_rpm_override,
    COALESCE((
        SELECT jsonb_agg(jsonb_build_object(
            'platform', quota.platform,
            'daily_limit_usd', quota.daily_limit_usd::text,
            'weekly_limit_usd', quota.weekly_limit_usd::text,
            'monthly_limit_usd', quota.monthly_limit_usd::text,
            'daily_usage_usd', quota.daily_usage_usd::text,
            'weekly_usage_usd', quota.weekly_usage_usd::text,
            'monthly_usage_usd', quota.monthly_usage_usd::text,
            'daily_window_start_unix_ms',
                (EXTRACT(EPOCH FROM quota.daily_window_start) * 1000)::bigint,
            'weekly_window_start_unix_ms',
                (EXTRACT(EPOCH FROM quota.weekly_window_start) * 1000)::bigint,
            'monthly_window_start_unix_ms',
                (EXTRACT(EPOCH FROM quota.monthly_window_start) * 1000)::bigint
        ) ORDER BY quota.platform)
        FROM user_platform_quotas quota
        WHERE quota.user_id = k.user_id AND quota.deleted_at IS NULL
    ), '[]'::jsonb)::text AS api_key_platform_quotas_json,
    u.id AS auth_user_id,
    u.email AS auth_user_email,
    u.username AS auth_user_username,
    u.password_hash AS auth_user_password_hash,
    u.auth_generation AS auth_user_auth_generation,
    u.role AS auth_user_role,
    u.balance::text AS auth_user_balance,
    u.concurrency AS auth_user_concurrency,
    u.status AS auth_user_status,
    u.rpm_limit AS auth_user_rpm_limit,
    ARRAY(
        SELECT uag.group_id
        FROM user_allowed_groups uag
        JOIN groups allowed_group
          ON allowed_group.id = uag.group_id
         AND allowed_group.deleted_at IS NULL
        WHERE uag.user_id = u.id
        ORDER BY uag.group_id
    )::bigint[] AS auth_user_allowed_group_ids,
    g.id AS auth_group_id,
    g.name AS auth_group_name,
    g.platform AS auth_group_platform,
    g.rate_multiplier::text AS auth_group_rate_multiplier,
    g.is_exclusive AS auth_group_is_exclusive,
    g.status AS auth_group_status,
    g.subscription_type AS auth_group_subscription_type,
    g.rpm_limit AS auth_group_rpm_limit,
    active_subscription.id AS auth_subscription_id,
    active_subscription.user_id AS auth_subscription_user_id,
    active_subscription.group_id AS auth_subscription_group_id,
    (EXTRACT(EPOCH FROM active_subscription.starts_at) * 1000)::bigint
        AS auth_subscription_starts_at_unix_ms,
    (EXTRACT(EPOCH FROM active_subscription.expires_at) * 1000)::bigint
        AS auth_subscription_expires_at_unix_ms,
    g.daily_limit_usd::text AS auth_subscription_daily_limit_usd,
    g.weekly_limit_usd::text AS auth_subscription_weekly_limit_usd,
    g.monthly_limit_usd::text AS auth_subscription_monthly_limit_usd,
    active_subscription.daily_usage_usd::text AS auth_subscription_daily_usage_usd,
    active_subscription.weekly_usage_usd::text AS auth_subscription_weekly_usage_usd,
    active_subscription.monthly_usage_usd::text AS auth_subscription_monthly_usage_usd,
    (EXTRACT(EPOCH FROM active_subscription.daily_window_start) * 1000)::bigint
        AS auth_subscription_daily_window_start_unix_ms,
    (EXTRACT(EPOCH FROM active_subscription.weekly_window_start) * 1000)::bigint
        AS auth_subscription_weekly_window_start_unix_ms,
    (EXTRACT(EPOCH FROM active_subscription.monthly_window_start) * 1000)::bigint
        AS auth_subscription_monthly_window_start_unix_ms
FROM api_keys k
LEFT JOIN users u
  ON u.id = k.user_id
 AND u.deleted_at IS NULL
LEFT JOIN groups g
  ON g.id = k.group_id
 AND g.deleted_at IS NULL
LEFT JOIN LATERAL (
    SELECT subscription.*
    FROM user_subscriptions subscription
    WHERE subscription.user_id = k.user_id
      AND subscription.group_id = k.group_id
      AND subscription.status = 'active'
      AND subscription.starts_at <= NOW()
      AND subscription.expires_at > NOW()
      AND subscription.deleted_at IS NULL
    ORDER BY subscription.id DESC
    LIMIT 1
) active_subscription ON TRUE
WHERE k.key = $1 AND k.deleted_at IS NULL
LIMIT 1
";

const ACCOUNT_BY_ID_SQL: &str = r"
SELECT
    a.id,
    a.name,
    a.notes,
    a.platform,
    a.type AS account_type,
    a.credentials::text AS credentials_json,
    a.extra::text AS extra_json,
    a.proxy_id,
    p.id AS account_proxy_id,
    p.protocol AS account_proxy_protocol,
    p.host AS account_proxy_host,
    p.port AS account_proxy_port,
    p.username AS account_proxy_username,
    p.password AS account_proxy_password,
    p.status AS account_proxy_status,
    (EXTRACT(EPOCH FROM p.expires_at) * 1000)::bigint AS account_proxy_expires_at_unix_ms,
    a.proxy_fallback_origin_id,
    a.concurrency,
    a.load_factor,
    a.priority,
    a.rate_multiplier::text AS rate_multiplier,
    a.status,
    a.error_message,
    (EXTRACT(EPOCH FROM a.expires_at) * 1000)::bigint AS expires_at_unix_ms,
    a.auto_pause_on_expired,
    a.schedulable,
    (EXTRACT(EPOCH FROM a.rate_limit_reset_at) * 1000)::bigint AS rate_limit_reset_at_unix_ms,
    (EXTRACT(EPOCH FROM a.overload_until) * 1000)::bigint AS overload_until_unix_ms,
    (EXTRACT(EPOCH FROM a.temp_unschedulable_until) * 1000)::bigint
        AS temp_unschedulable_until_unix_ms,
    a.temp_unschedulable_reason,
    a.parent_account_id,
    a.quota_dimension,
    ARRAY(
        SELECT ag.group_id
        FROM account_groups ag
        JOIN groups account_group
          ON account_group.id = ag.group_id
         AND account_group.deleted_at IS NULL
        WHERE ag.account_id = a.id
        ORDER BY ag.priority, ag.group_id
    )::bigint[] AS group_ids
FROM accounts a
LEFT JOIN proxies p
  ON p.id = a.proxy_id
 AND p.deleted_at IS NULL
WHERE a.id = $1 AND a.deleted_at IS NULL
LIMIT 1
";

const SCHEDULABLE_ACCOUNTS_SQL: &str = r"
SELECT
    a.id,
    a.name,
    a.notes,
    a.platform,
    a.type AS account_type,
    a.credentials::text AS credentials_json,
    a.extra::text AS extra_json,
    a.proxy_id,
    p.id AS account_proxy_id,
    p.protocol AS account_proxy_protocol,
    p.host AS account_proxy_host,
    p.port AS account_proxy_port,
    p.username AS account_proxy_username,
    p.password AS account_proxy_password,
    p.status AS account_proxy_status,
    (EXTRACT(EPOCH FROM p.expires_at) * 1000)::bigint AS account_proxy_expires_at_unix_ms,
    a.proxy_fallback_origin_id,
    a.concurrency,
    a.load_factor,
    a.priority,
    a.rate_multiplier::text AS rate_multiplier,
    a.status,
    a.error_message,
    (EXTRACT(EPOCH FROM a.expires_at) * 1000)::bigint AS expires_at_unix_ms,
    a.auto_pause_on_expired,
    a.schedulable,
    (EXTRACT(EPOCH FROM a.rate_limit_reset_at) * 1000)::bigint AS rate_limit_reset_at_unix_ms,
    (EXTRACT(EPOCH FROM a.overload_until) * 1000)::bigint AS overload_until_unix_ms,
    (EXTRACT(EPOCH FROM a.temp_unschedulable_until) * 1000)::bigint
        AS temp_unschedulable_until_unix_ms,
    a.temp_unschedulable_reason,
    a.parent_account_id,
    a.quota_dimension,
    ARRAY(
        SELECT ag.group_id
        FROM account_groups ag
        JOIN groups account_group
          ON account_group.id = ag.group_id
         AND account_group.deleted_at IS NULL
        WHERE ag.account_id = a.id
        ORDER BY ag.priority, ag.group_id
    )::bigint[] AS group_ids
FROM accounts a
LEFT JOIN proxies p
  ON p.id = a.proxy_id
 AND p.deleted_at IS NULL
WHERE a.deleted_at IS NULL
  AND a.status = 'active'
  AND a.schedulable = TRUE
  AND a.platform = $1
  AND (
      ($2::bigint IS NULL AND NOT EXISTS (
          SELECT 1 FROM account_groups ungrouped WHERE ungrouped.account_id = a.id
      ))
      OR
      ($2::bigint IS NOT NULL AND EXISTS (
          SELECT 1
          FROM account_groups grouped
          JOIN groups selected_group
            ON selected_group.id = grouped.group_id
           AND selected_group.deleted_at IS NULL
           AND selected_group.status = 'active'
          WHERE grouped.account_id = a.id AND grouped.group_id = $2
      ))
  )
ORDER BY
    COALESCE((
        SELECT grouped.priority
        FROM account_groups grouped
        WHERE grouped.account_id = a.id AND grouped.group_id = $2
        LIMIT 1
    ), a.priority),
    a.priority,
    a.last_used_at ASC NULLS FIRST,
    a.id
";

const CHANNEL_POLICY_SQL: &str = r"
SELECT
    c.id,
    COALESCE(c.features, '') AS features,
    COALESCE(c.features_config, '{}'::jsonb)::text AS features_config_json,
    COALESCE(c.model_mapping, '{}'::jsonb)::text AS model_mapping_json,
    COALESCE(NULLIF(c.billing_model_source, ''), 'channel_mapped') AS billing_model_source,
    COALESCE(c.restrict_models, FALSE) AS restrict_models
FROM channel_groups cg
JOIN channels c ON c.id = cg.channel_id
WHERE cg.group_id = $1 AND c.status = 'active'
ORDER BY c.id
LIMIT 1
";

const CHANNEL_MODEL_PRICING_SQL: &str = r"
SELECT
    id,
    models::text AS models_json,
    COALESCE(NULLIF(billing_mode, ''), 'token') AS billing_mode,
    input_price::text AS input_price,
    output_price::text AS output_price,
    cache_write_price::text AS cache_write_price,
    cache_read_price::text AS cache_read_price,
    per_request_price::text AS per_request_price
FROM channel_model_pricing
WHERE channel_id = $1 AND LOWER(platform) = LOWER($2)
ORDER BY id
";

const CHANNEL_PRICING_INTERVALS_SQL: &str = r"
SELECT
    min_tokens,
    max_tokens,
    input_price::text AS input_price,
    output_price::text AS output_price,
    cache_write_price::text AS cache_write_price,
    cache_read_price::text AS cache_read_price,
    per_request_price::text AS per_request_price
FROM channel_pricing_intervals
WHERE pricing_id = $1
ORDER BY sort_order, id
";

#[derive(Debug)]
pub enum RepositoryError {
    Database(sqlx::Error),
    InvalidJson {
        field: &'static str,
        source: serde_json::Error,
    },
    MissingJoinedField(&'static str),
}

impl fmt::Display for RepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(formatter, "PostgreSQL query failed: {error}"),
            Self::InvalidJson { field, source } => {
                write!(formatter, "invalid JSON in {field}: {source}")
            }
            Self::MissingJoinedField(field) => {
                write!(formatter, "joined PostgreSQL row is missing {field}")
            }
        }
    }
}

impl Error for RepositoryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            Self::InvalidJson { source, .. } => Some(source),
            Self::MissingJoinedField(_) => None,
        }
    }
}

impl From<sqlx::Error> for RepositoryError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

#[derive(Clone, Debug)]
pub struct CoreRepository {
    pool: PgPool,
}

impl CoreRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Loads the current, non-deleted user and its normalized allowed groups.
    ///
    /// # Errors
    ///
    /// Returns an error when `PostgreSQL` fails or a row cannot be decoded.
    pub async fn find_user_by_id(&self, id: i64) -> Result<Option<UserRecord>, RepositoryError> {
        let row = sqlx::query(USER_BY_ID_SQL)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(user_from_row).transpose()
    }

    /// Loads one current group.
    ///
    /// # Errors
    ///
    /// Returns an error when `PostgreSQL` fails or a row cannot be decoded.
    pub async fn find_group_by_id(&self, id: i64) -> Result<Option<GroupRecord>, RepositoryError> {
        let row = sqlx::query(GROUP_BY_ID_SQL)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(group_from_row).transpose()
    }

    /// Loads the same minimum API-key/user/group snapshot used by the Go auth hot path.
    ///
    /// # Errors
    ///
    /// Returns an error when `PostgreSQL` fails or JSON/row data is invalid.
    pub async fn find_api_key_for_auth(
        &self,
        key: &str,
    ) -> Result<Option<ApiKeyAuthRecord>, RepositoryError> {
        let row = sqlx::query(API_KEY_FOR_AUTH_SQL)
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(api_key_auth_from_row).transpose()
    }

    /// Loads one current upstream account and normalized group IDs.
    ///
    /// # Errors
    ///
    /// Returns an error when `PostgreSQL` fails or JSON/row data is invalid.
    pub async fn find_account_by_id(
        &self,
        id: i64,
    ) -> Result<Option<AccountRecord>, RepositoryError> {
        let row = sqlx::query(ACCOUNT_BY_ID_SQL)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(account_from_row).transpose()
    }

    /// Loads the `PostgreSQL` source-of-truth candidate set for one scheduling
    /// partition. Callers may keep this result in a short-lived L1 cache.
    ///
    /// # Errors
    ///
    /// Returns an error when `PostgreSQL` fails or any candidate row is invalid.
    pub async fn list_schedulable_accounts(
        &self,
        platform: &str,
        group_id: Option<i64>,
        now_unix_ms: UnixMillis,
    ) -> Result<Vec<AccountRecord>, RepositoryError> {
        let rows = sqlx::query(SCHEDULABLE_ACCOUNTS_SQL)
            .bind(platform)
            .bind(group_id)
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(account_from_row)
            .filter_map(|result| match result {
                Ok(account) if account.is_schedulable_at(now_unix_ms) => Some(Ok(account)),
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            })
            .collect()
    }

    /// Loads the active channel policy for a group and the pricing entries for
    /// the selected platform. The returned mapping is already narrowed from
    /// the persisted `platform -> mapping` object.
    ///
    /// # Errors
    ///
    /// Returns an error when `PostgreSQL` fails or persisted JSON is invalid.
    pub async fn find_channel_policy(
        &self,
        group_id: i64,
        platform: &str,
    ) -> Result<Option<ChannelPolicyRecord>, RepositoryError> {
        let Some(row) = sqlx::query(CHANNEL_POLICY_SQL)
            .bind(group_id)
            .fetch_optional(&self.pool)
            .await?
        else {
            return Ok(None);
        };
        let id: i64 = row.try_get("id")?;
        let features_config_json: String = row.try_get("features_config_json")?;
        let mapping_json: String = row.try_get("model_mapping_json")?;
        let pricing_rows = sqlx::query(CHANNEL_MODEL_PRICING_SQL)
            .bind(id)
            .bind(platform)
            .fetch_all(&self.pool)
            .await?;
        let mut allowed_models = Vec::new();
        let mut model_pricing = Vec::with_capacity(pricing_rows.len());
        for pricing_row in pricing_rows {
            let pricing_id: i64 = pricing_row.try_get("id")?;
            let models_json: String = pricing_row.try_get("models_json")?;
            let models = parse_string_list(&models_json, "channel_model_pricing.models")?;
            allowed_models.extend(models.iter().cloned());
            let interval_rows = sqlx::query(CHANNEL_PRICING_INTERVALS_SQL)
                .bind(pricing_id)
                .fetch_all(&self.pool)
                .await?;
            let intervals = interval_rows
                .iter()
                .map(channel_pricing_interval_from_row)
                .collect::<Result<Vec<_>, _>>()?;
            model_pricing.push(ChannelModelPricingRecord {
                id: pricing_id,
                models,
                billing_mode: pricing_row.try_get("billing_mode")?,
                input_price: pricing_row.try_get("input_price")?,
                output_price: pricing_row.try_get("output_price")?,
                cache_write_price: pricing_row.try_get("cache_write_price")?,
                cache_read_price: pricing_row.try_get("cache_read_price")?,
                per_request_price: pricing_row.try_get("per_request_price")?,
                intervals,
            });
        }
        Ok(Some(ChannelPolicyRecord {
            id,
            features: row.try_get("features")?,
            features_config: parse_json(&features_config_json, "channels.features_config")?,
            model_mapping: parse_channel_mapping(&mapping_json, platform)?,
            billing_model_source: row.try_get("billing_model_source")?,
            restrict_models: row.try_get("restrict_models")?,
            allowed_models,
            model_pricing,
        }))
    }
}

fn user_from_row(row: &PgRow) -> Result<UserRecord, RepositoryError> {
    Ok(UserRecord {
        id: row.try_get("id")?,
        email: row.try_get("email")?,
        username: row.try_get("username")?,
        password_hash: row.try_get("password_hash")?,
        auth_generation: row.try_get("auth_generation")?,
        role: row.try_get("role")?,
        balance: row.try_get("balance")?,
        concurrency: row.try_get("concurrency")?,
        status: row.try_get("status")?,
        rpm_limit: row.try_get("rpm_limit")?,
        allowed_group_ids: row.try_get("allowed_group_ids")?,
    })
}

fn group_from_row(row: &PgRow) -> Result<GroupRecord, RepositoryError> {
    Ok(GroupRecord {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        platform: row.try_get("platform")?,
        rate_multiplier: row.try_get("rate_multiplier")?,
        is_exclusive: row.try_get("is_exclusive")?,
        status: row.try_get("status")?,
        subscription_type: row.try_get("subscription_type")?,
        rpm_limit: row.try_get("rpm_limit")?,
    })
}

fn api_key_auth_from_row(row: &PgRow) -> Result<ApiKeyAuthRecord, RepositoryError> {
    let whitelist_json: String = row.try_get("api_key_ip_whitelist")?;
    let blacklist_json: String = row.try_get("api_key_ip_blacklist")?;
    let platform_quotas_json: String = row.try_get("api_key_platform_quotas_json")?;
    let api_key = ApiKeyRecord {
        id: row.try_get("api_key_id")?,
        user_id: row.try_get("api_key_user_id")?,
        key: row.try_get("api_key_secret")?,
        name: row.try_get("api_key_name")?,
        group_id: row.try_get("api_key_group_id")?,
        status: row.try_get("api_key_status")?,
        ip_whitelist: parse_string_list(&whitelist_json, "api_keys.ip_whitelist")?,
        ip_blacklist: parse_string_list(&blacklist_json, "api_keys.ip_blacklist")?,
        quota: row.try_get("api_key_quota")?,
        quota_used: row.try_get("api_key_quota_used")?,
        expires_at_unix_ms: row.try_get("api_key_expires_at_unix_ms")?,
        rate_limit_5h: row.try_get("api_key_rate_limit_5h")?,
        rate_limit_1d: row.try_get("api_key_rate_limit_1d")?,
        rate_limit_7d: row.try_get("api_key_rate_limit_7d")?,
        usage_5h: row.try_get("api_key_usage_5h")?,
        usage_1d: row.try_get("api_key_usage_1d")?,
        usage_7d: row.try_get("api_key_usage_7d")?,
        window_5h_start_unix_ms: row.try_get("api_key_window_5h_start_unix_ms")?,
        window_1d_start_unix_ms: row.try_get("api_key_window_1d_start_unix_ms")?,
        window_7d_start_unix_ms: row.try_get("api_key_window_7d_start_unix_ms")?,
        group_rpm_override: row.try_get("api_key_group_rpm_override")?,
    };

    Ok(ApiKeyAuthRecord {
        api_key,
        user: joined_user_from_row(row)?,
        group: joined_group_from_row(row)?,
        subscription: joined_subscription_from_row(row)?,
        platform_quotas: serde_json::from_str(&platform_quotas_json).map_err(|source| {
            RepositoryError::InvalidJson {
                field: "user_platform_quotas",
                source,
            }
        })?,
    })
}

fn joined_user_from_row(row: &PgRow) -> Result<Option<UserRecord>, RepositoryError> {
    let Some(id) = row.try_get::<Option<i64>, _>("auth_user_id")? else {
        return Ok(None);
    };
    Ok(Some(UserRecord {
        id,
        email: joined(row.try_get("auth_user_email")?, "users.email")?,
        username: joined(row.try_get("auth_user_username")?, "users.username")?,
        password_hash: joined(
            row.try_get("auth_user_password_hash")?,
            "users.password_hash",
        )?,
        auth_generation: joined(
            row.try_get("auth_user_auth_generation")?,
            "users.auth_generation",
        )?,
        role: joined(row.try_get("auth_user_role")?, "users.role")?,
        balance: joined(row.try_get("auth_user_balance")?, "users.balance")?,
        concurrency: joined(row.try_get("auth_user_concurrency")?, "users.concurrency")?,
        status: joined(row.try_get("auth_user_status")?, "users.status")?,
        rpm_limit: joined(row.try_get("auth_user_rpm_limit")?, "users.rpm_limit")?,
        allowed_group_ids: row.try_get("auth_user_allowed_group_ids")?,
    }))
}

fn joined_group_from_row(row: &PgRow) -> Result<Option<GroupRecord>, RepositoryError> {
    let Some(id) = row.try_get::<Option<i64>, _>("auth_group_id")? else {
        return Ok(None);
    };
    Ok(Some(GroupRecord {
        id,
        name: joined(row.try_get("auth_group_name")?, "groups.name")?,
        platform: joined(row.try_get("auth_group_platform")?, "groups.platform")?,
        rate_multiplier: joined(
            row.try_get("auth_group_rate_multiplier")?,
            "groups.rate_multiplier",
        )?,
        is_exclusive: joined(
            row.try_get("auth_group_is_exclusive")?,
            "groups.is_exclusive",
        )?,
        status: joined(row.try_get("auth_group_status")?, "groups.status")?,
        subscription_type: joined(
            row.try_get("auth_group_subscription_type")?,
            "groups.subscription_type",
        )?,
        rpm_limit: joined(row.try_get("auth_group_rpm_limit")?, "groups.rpm_limit")?,
    }))
}

fn joined_subscription_from_row(
    row: &PgRow,
) -> Result<Option<SubscriptionBillingRecord>, RepositoryError> {
    let Some(id) = row.try_get::<Option<i64>, _>("auth_subscription_id")? else {
        return Ok(None);
    };
    Ok(Some(SubscriptionBillingRecord {
        id,
        user_id: joined(
            row.try_get("auth_subscription_user_id")?,
            "user_subscriptions.user_id",
        )?,
        group_id: joined(
            row.try_get("auth_subscription_group_id")?,
            "user_subscriptions.group_id",
        )?,
        starts_at_unix_ms: joined(
            row.try_get("auth_subscription_starts_at_unix_ms")?,
            "user_subscriptions.starts_at",
        )?,
        expires_at_unix_ms: joined(
            row.try_get("auth_subscription_expires_at_unix_ms")?,
            "user_subscriptions.expires_at",
        )?,
        daily_limit_usd: row.try_get("auth_subscription_daily_limit_usd")?,
        weekly_limit_usd: row.try_get("auth_subscription_weekly_limit_usd")?,
        monthly_limit_usd: row.try_get("auth_subscription_monthly_limit_usd")?,
        daily_usage_usd: joined(
            row.try_get("auth_subscription_daily_usage_usd")?,
            "user_subscriptions.daily_usage_usd",
        )?,
        weekly_usage_usd: joined(
            row.try_get("auth_subscription_weekly_usage_usd")?,
            "user_subscriptions.weekly_usage_usd",
        )?,
        monthly_usage_usd: joined(
            row.try_get("auth_subscription_monthly_usage_usd")?,
            "user_subscriptions.monthly_usage_usd",
        )?,
        daily_window_start_unix_ms: row.try_get("auth_subscription_daily_window_start_unix_ms")?,
        weekly_window_start_unix_ms: row
            .try_get("auth_subscription_weekly_window_start_unix_ms")?,
        monthly_window_start_unix_ms: row
            .try_get("auth_subscription_monthly_window_start_unix_ms")?,
    }))
}

fn account_from_row(row: &PgRow) -> Result<AccountRecord, RepositoryError> {
    let credentials_json: String = row.try_get("credentials_json")?;
    let extra_json: String = row.try_get("extra_json")?;
    Ok(AccountRecord {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        notes: row.try_get("notes")?,
        platform: row.try_get("platform")?,
        account_type: row.try_get("account_type")?,
        credentials: parse_json(&credentials_json, "accounts.credentials")?,
        extra: parse_json(&extra_json, "accounts.extra")?,
        proxy_id: row.try_get("proxy_id")?,
        proxy: account_proxy_from_row(row)?,
        proxy_fallback_origin_id: row.try_get("proxy_fallback_origin_id")?,
        concurrency: row.try_get("concurrency")?,
        load_factor: row.try_get("load_factor")?,
        priority: row.try_get("priority")?,
        rate_multiplier: row.try_get("rate_multiplier")?,
        status: row.try_get("status")?,
        error_message: row.try_get("error_message")?,
        expires_at_unix_ms: row.try_get("expires_at_unix_ms")?,
        auto_pause_on_expired: row.try_get("auto_pause_on_expired")?,
        schedulable: row.try_get("schedulable")?,
        rate_limit_reset_at_unix_ms: row.try_get("rate_limit_reset_at_unix_ms")?,
        overload_until_unix_ms: row.try_get("overload_until_unix_ms")?,
        temp_unschedulable_until_unix_ms: row.try_get("temp_unschedulable_until_unix_ms")?,
        temp_unschedulable_reason: row.try_get("temp_unschedulable_reason")?,
        parent_account_id: row.try_get("parent_account_id")?,
        quota_dimension: row.try_get("quota_dimension")?,
        group_ids: row.try_get("group_ids")?,
    })
}

fn account_proxy_from_row(row: &PgRow) -> Result<Option<AccountProxyRecord>, RepositoryError> {
    let Some(id) = row.try_get::<Option<i64>, _>("account_proxy_id")? else {
        return Ok(None);
    };
    Ok(Some(AccountProxyRecord {
        id,
        protocol: joined(row.try_get("account_proxy_protocol")?, "proxies.protocol")?,
        host: joined(row.try_get("account_proxy_host")?, "proxies.host")?,
        port: joined(row.try_get("account_proxy_port")?, "proxies.port")?,
        username: row.try_get("account_proxy_username")?,
        password: row.try_get("account_proxy_password")?,
        status: joined(row.try_get("account_proxy_status")?, "proxies.status")?,
        expires_at_unix_ms: row.try_get("account_proxy_expires_at_unix_ms")?,
    }))
}

fn channel_pricing_interval_from_row(
    row: &PgRow,
) -> Result<ChannelPricingIntervalRecord, RepositoryError> {
    Ok(ChannelPricingIntervalRecord {
        min_tokens: row.try_get("min_tokens")?,
        max_tokens: row.try_get("max_tokens")?,
        input_price: row.try_get("input_price")?,
        output_price: row.try_get("output_price")?,
        cache_write_price: row.try_get("cache_write_price")?,
        cache_read_price: row.try_get("cache_read_price")?,
        per_request_price: row.try_get("per_request_price")?,
    })
}

fn joined<T>(value: Option<T>, field: &'static str) -> Result<T, RepositoryError> {
    value.ok_or(RepositoryError::MissingJoinedField(field))
}

fn parse_string_list(raw: &str, field: &'static str) -> Result<Vec<String>, RepositoryError> {
    serde_json::from_str(raw).map_err(|source| RepositoryError::InvalidJson { field, source })
}

fn parse_json(raw: &str, field: &'static str) -> Result<Value, RepositoryError> {
    serde_json::from_str(raw).map_err(|source| RepositoryError::InvalidJson { field, source })
}

fn parse_channel_mapping(
    raw: &str,
    platform: &str,
) -> Result<BTreeMap<String, String>, RepositoryError> {
    let value = parse_json(raw, "channels.model_mapping")?;
    let Some(root) = value.as_object() else {
        return Ok(BTreeMap::new());
    };
    let selected = root
        .iter()
        .find(|(key, value)| key.eq_ignore_ascii_case(platform) && value.is_object())
        .and_then(|(_, value)| value.as_object());
    let legacy = (platform.eq_ignore_ascii_case("anthropic")
        && root.values().all(Value::is_string))
    .then_some(root);
    let Some(mapping) = selected.or(legacy) else {
        return Ok(BTreeMap::new());
    };
    Ok(mapping
        .iter()
        .filter_map(|(pattern, target)| {
            let pattern = pattern.trim();
            let target = target.as_str()?.trim();
            (!pattern.is_empty() && !target.is_empty())
                .then(|| (pattern.to_owned(), target.to_owned()))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_api_key_ip_rules() {
        let parsed = parse_string_list(r#"["192.168.1.1","10.0.0.0/8"]"#, "api_keys.ip_whitelist")
            .expect("valid rule JSON should parse");
        assert_eq!(parsed, ["192.168.1.1", "10.0.0.0/8"]);
    }

    #[test]
    fn rejects_non_array_api_key_ip_rules() {
        let error = parse_string_list(r#"{"rule":"127.0.0.1"}"#, "api_keys.ip_whitelist")
            .expect_err("object must not decode as a rule list");
        assert!(error.to_string().contains("api_keys.ip_whitelist"));
    }

    #[test]
    fn auth_queries_exclude_soft_deleted_rows_and_use_join_table() {
        assert!(API_KEY_FOR_AUTH_SQL.contains("k.deleted_at IS NULL"));
        assert!(API_KEY_FOR_AUTH_SQL.contains("user_allowed_groups"));
        assert!(API_KEY_FOR_AUTH_SQL.contains("g.deleted_at IS NULL"));
        assert!(!API_KEY_FOR_AUTH_SQL.contains("u.allowed_groups"));
    }

    #[test]
    fn channel_policy_query_is_active_and_platform_scoped() {
        assert!(CHANNEL_POLICY_SQL.contains("c.status = 'active'"));
        assert!(CHANNEL_POLICY_SQL.contains("cg.group_id = $1"));
        assert!(CHANNEL_MODEL_PRICING_SQL.contains("LOWER(platform) = LOWER($2)"));
        assert!(CHANNEL_PRICING_INTERVALS_SQL.contains("ORDER BY sort_order, id"));
    }

    #[test]
    fn channel_mapping_selects_nested_platform_case_insensitively() {
        let mapping = parse_channel_mapping(
            r#"{"Anthropic":{"public-*":"claude-sonnet-4","exact":"claude-opus-4"},"openai":{"exact":"gpt-5"}}"#,
            "anthropic",
        )
        .expect("nested mapping should parse");
        assert_eq!(
            mapping.get("exact").map(String::as_str),
            Some("claude-opus-4")
        );
        assert_eq!(
            mapping.get("public-*").map(String::as_str),
            Some("claude-sonnet-4")
        );
        assert_eq!(mapping.len(), 2);
    }

    #[test]
    fn legacy_flat_channel_mapping_remains_readable() {
        let mapping = parse_channel_mapping(r#"{"alias":"upstream"}"#, "anthropic")
            .expect("legacy mapping should parse");
        assert_eq!(mapping.get("alias").map(String::as_str), Some("upstream"));
        let other_platform = parse_channel_mapping(r#"{"alias":"upstream"}"#, "openai")
            .expect("legacy mapping should parse");
        assert!(other_platform.is_empty());
    }

    #[test]
    fn account_scheduling_model_honors_runtime_windows() {
        let account = AccountRecord {
            id: 1,
            name: "account".to_owned(),
            notes: None,
            platform: "openai".to_owned(),
            account_type: "oauth".to_owned(),
            credentials: serde_json::json!({}),
            extra: serde_json::json!({}),
            proxy_id: None,
            proxy: None,
            proxy_fallback_origin_id: None,
            concurrency: 3,
            load_factor: None,
            priority: 50,
            rate_multiplier: "1.0000".to_owned(),
            status: STATUS_ACTIVE.to_owned(),
            error_message: None,
            expires_at_unix_ms: None,
            auto_pause_on_expired: true,
            schedulable: true,
            rate_limit_reset_at_unix_ms: Some(2_000),
            overload_until_unix_ms: None,
            temp_unschedulable_until_unix_ms: None,
            temp_unschedulable_reason: None,
            parent_account_id: None,
            quota_dimension: "global".to_owned(),
            group_ids: vec![7],
        };
        assert!(!account.is_schedulable_at(1_999));
        assert!(account.is_schedulable_at(2_000));
    }
}
