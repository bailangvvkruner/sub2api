use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

pub const STATUS_ACTIVE: &str = "active";
pub const STATUS_DELETED: &str = "deleted";
pub const SUBSCRIPTION_TYPE_SUBSCRIPTION: &str = "subscription";

/// Milliseconds since the Unix epoch. SQL queries project `timestamptz` values
/// into this representation so the repository does not depend on a time crate.
pub type UnixMillis = i64;

#[derive(Clone, Debug, PartialEq)]
pub struct UserRecord {
    pub id: i64,
    pub email: String,
    pub username: String,
    pub password_hash: String,
    pub auth_generation: i64,
    pub role: String,
    pub balance: String,
    pub concurrency: i32,
    pub status: String,
    pub rpm_limit: i32,
    pub allowed_group_ids: Vec<i64>,
}

impl UserRecord {
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == STATUS_ACTIVE
    }

    #[must_use]
    pub fn can_bind_group(&self, group_id: i64, is_exclusive: bool) -> bool {
        !is_exclusive || self.allowed_group_ids.contains(&group_id)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ApiKeyRecord {
    pub id: i64,
    pub user_id: i64,
    pub key: String,
    pub name: String,
    pub group_id: Option<i64>,
    pub status: String,
    pub ip_whitelist: Vec<String>,
    pub ip_blacklist: Vec<String>,
    pub quota: String,
    pub quota_used: String,
    pub expires_at_unix_ms: Option<UnixMillis>,
    pub rate_limit_5h: String,
    pub rate_limit_1d: String,
    pub rate_limit_7d: String,
    pub usage_5h: String,
    pub usage_1d: String,
    pub usage_7d: String,
    pub window_5h_start_unix_ms: Option<UnixMillis>,
    pub window_1d_start_unix_ms: Option<UnixMillis>,
    pub window_7d_start_unix_ms: Option<UnixMillis>,
    /// Per-user override for this API key's group. `None` inherits the group
    /// limit and `Some(0)` disables only the group-level RPM gate.
    pub group_rpm_override: Option<i32>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct GroupRecord {
    pub id: i64,
    pub name: String,
    pub platform: String,
    pub rate_multiplier: String,
    pub is_exclusive: bool,
    pub status: String,
    pub subscription_type: String,
    pub rpm_limit: i32,
}

impl GroupRecord {
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == STATUS_ACTIVE
    }

    #[must_use]
    pub fn is_deleted(&self) -> bool {
        self.status.eq_ignore_ascii_case(STATUS_DELETED)
    }

    #[must_use]
    pub fn is_subscription_type(&self) -> bool {
        self.subscription_type == SUBSCRIPTION_TYPE_SUBSCRIPTION
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ApiKeyAuthRecord {
    pub api_key: ApiKeyRecord,
    pub user: Option<UserRecord>,
    pub group: Option<GroupRecord>,
    pub subscription: Option<SubscriptionBillingRecord>,
    pub platform_quotas: Vec<UserPlatformQuotaRecord>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct UserPlatformQuotaRecord {
    pub platform: String,
    pub daily_limit_usd: Option<String>,
    pub weekly_limit_usd: Option<String>,
    pub monthly_limit_usd: Option<String>,
    pub daily_usage_usd: String,
    pub weekly_usage_usd: String,
    pub monthly_usage_usd: String,
    pub daily_window_start_unix_ms: Option<UnixMillis>,
    pub weekly_window_start_unix_ms: Option<UnixMillis>,
    pub monthly_window_start_unix_ms: Option<UnixMillis>,
}

/// Active subscription counters and group limits captured with API-key auth.
#[derive(Clone, Debug, PartialEq)]
pub struct SubscriptionBillingRecord {
    pub id: i64,
    pub user_id: i64,
    pub group_id: i64,
    pub starts_at_unix_ms: UnixMillis,
    pub expires_at_unix_ms: UnixMillis,
    pub daily_limit_usd: Option<String>,
    pub weekly_limit_usd: Option<String>,
    pub monthly_limit_usd: Option<String>,
    pub daily_usage_usd: String,
    pub weekly_usage_usd: String,
    pub monthly_usage_usd: String,
    pub daily_window_start_unix_ms: Option<UnixMillis>,
    pub weekly_window_start_unix_ms: Option<UnixMillis>,
    pub monthly_window_start_unix_ms: Option<UnixMillis>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountProxyRecord {
    pub id: i64,
    pub protocol: String,
    pub host: String,
    pub port: i32,
    pub username: Option<String>,
    pub password: Option<String>,
    pub status: String,
    pub expires_at_unix_ms: Option<UnixMillis>,
}

impl AccountProxyRecord {
    #[must_use]
    pub fn is_usable_at(&self, now_unix_ms: UnixMillis) -> bool {
        self.status == STATUS_ACTIVE
            && matches!(
                self.protocol.to_ascii_lowercase().as_str(),
                "http" | "https" | "socks5" | "socks5h"
            )
            && !self.host.trim().is_empty()
            && self.port > 0
            && self.port <= i32::from(u16::MAX)
            && self
                .expires_at_unix_ms
                .is_none_or(|expires_at| now_unix_ms < expires_at)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct AccountRecord {
    pub id: i64,
    pub name: String,
    pub notes: Option<String>,
    pub platform: String,
    pub account_type: String,
    pub credentials: Value,
    pub extra: Value,
    pub proxy_id: Option<i64>,
    pub proxy: Option<AccountProxyRecord>,
    pub proxy_fallback_origin_id: Option<i64>,
    pub concurrency: i32,
    pub load_factor: Option<i32>,
    pub priority: i32,
    pub rate_multiplier: String,
    pub status: String,
    pub error_message: Option<String>,
    pub expires_at_unix_ms: Option<UnixMillis>,
    pub auto_pause_on_expired: bool,
    pub schedulable: bool,
    pub rate_limit_reset_at_unix_ms: Option<UnixMillis>,
    pub overload_until_unix_ms: Option<UnixMillis>,
    pub temp_unschedulable_until_unix_ms: Option<UnixMillis>,
    pub temp_unschedulable_reason: Option<String>,
    pub parent_account_id: Option<i64>,
    pub quota_dimension: String,
    pub group_ids: Vec<i64>,
}

/// Channel data needed by the gateway model-routing hot path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelPolicyRecord {
    pub id: i64,
    pub features: String,
    pub features_config: Value,
    pub model_mapping: BTreeMap<String, String>,
    pub billing_model_source: String,
    pub restrict_models: bool,
    pub allowed_models: Vec<String>,
    pub model_pricing: Vec<ChannelModelPricingRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelModelPricingRecord {
    pub id: i64,
    pub models: Vec<String>,
    pub billing_mode: String,
    pub input_price: Option<String>,
    pub output_price: Option<String>,
    pub cache_write_price: Option<String>,
    pub cache_read_price: Option<String>,
    pub per_request_price: Option<String>,
    pub intervals: Vec<ChannelPricingIntervalRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelPricingIntervalRecord {
    pub min_tokens: i32,
    pub max_tokens: Option<i32>,
    pub input_price: Option<String>,
    pub output_price: Option<String>,
    pub cache_write_price: Option<String>,
    pub cache_read_price: Option<String>,
    pub per_request_price: Option<String>,
}

impl AccountRecord {
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == STATUS_ACTIVE
    }

    #[must_use]
    pub fn is_schedulable_at(&self, now_unix_ms: UnixMillis) -> bool {
        if !self.is_active() || !self.schedulable {
            return false;
        }
        if self.auto_pause_on_expired
            && self
                .expires_at_unix_ms
                .is_some_and(|expires_at| now_unix_ms >= expires_at)
        {
            return false;
        }
        if self.proxy_id.is_some()
            && self
                .proxy
                .as_ref()
                .is_none_or(|proxy| !proxy.is_usable_at(now_unix_ms))
        {
            return false;
        }
        [
            self.rate_limit_reset_at_unix_ms,
            self.overload_until_unix_ms,
            self.temp_unschedulable_until_unix_ms,
        ]
        .into_iter()
        .flatten()
        .all(|blocked_until| now_unix_ms >= blocked_until)
    }
}
