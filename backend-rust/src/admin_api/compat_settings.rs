//! Dedicated `PostgreSQL` semantics for administrator runtime settings.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::OnceLock,
    time::Duration,
};

use axum::http::Method;
use chrono::Utc;
use futures_util::StreamExt;
use rand::{RngCore, rngs::OsRng};
use regex::Regex;
use reqwest::{Client, Proxy, Response, redirect::Policy};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Map, Value, json};
use sqlx::{PgPool, Postgres, Row, Transaction};
use url::Url;

use super::AdminError;
use crate::security::secrets;

const AUTH_INVALIDATION_CHANNEL: &str = "sub2api_auth_cache_invalidation";
const SETTINGS_INVALIDATION_PAYLOAD: &str = r#"{"version":1,"scope":"settings"}"#;

const ADMIN_API_KEY: &str = "admin_api_key";
const OVERLOAD_COOLDOWN: &str = "overload_cooldown_settings";
const RATE_LIMIT_429_COOLDOWN: &str = "rate_limit_429_cooldown_settings";
const STREAM_TIMEOUT: &str = "stream_timeout_settings";
const RECTIFIER: &str = "rectifier_settings";
const BETA_POLICY: &str = "beta_policy_settings";
const WEB_SEARCH: &str = "web_search_emulation_config";
const WEB_SEARCH_USAGE_PREFIX: &str = "web_search_usage:";
const EMAIL_TEMPLATE_PREFIX: &str = "notification_email_template:";

const MAX_WEB_SEARCH_PROVIDERS: usize = 10;
const MAX_WEB_SEARCH_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_EMAIL_SUBJECT_CHARS: usize = 200;
const MAX_EMAIL_HTML_BYTES: usize = 30_000;

pub(super) async fn dispatch(
    pool: &PgPool,
    handler: &str,
    _method: &Method,
    path: &str,
    payload: Value,
) -> Option<Result<Value, AdminError>> {
    let operation = handler.strip_prefix("h.Admin.Setting.")?;
    Some(match operation {
        "GetAdminAPIKey" => get_admin_api_key(pool).await,
        "RegenerateAdminAPIKey" => regenerate_admin_api_key(pool).await,
        "DeleteAdminAPIKey" => delete_admin_api_key(pool).await,
        "GetOverloadCooldownSettings" => get_overload_cooldown(pool).await,
        "UpdateOverloadCooldownSettings" => update_overload_cooldown(pool, payload).await,
        "GetRateLimit429CooldownSettings" => get_rate_limit_429_cooldown(pool).await,
        "UpdateRateLimit429CooldownSettings" => update_rate_limit_429_cooldown(pool, payload).await,
        "GetStreamTimeoutSettings" => get_stream_timeout(pool).await,
        "UpdateStreamTimeoutSettings" => update_stream_timeout(pool, payload).await,
        "GetRectifierSettings" => get_rectifier(pool).await,
        "UpdateRectifierSettings" => update_rectifier(pool, payload).await,
        "GetBetaPolicySettings" => get_beta_policy(pool).await,
        "UpdateBetaPolicySettings" => update_beta_policy(pool, payload).await,
        "ListEmailTemplates" => list_email_templates(pool).await,
        "GetEmailTemplate" => get_email_template_route(pool, path).await,
        "UpdateEmailTemplate" => update_email_template_route(pool, path, payload).await,
        "RestoreOfficialEmailTemplate" => restore_email_template_route(pool, path).await,
        "PreviewEmailTemplate" => preview_email_template(pool, payload).await,
        "GetWebSearchEmulationConfig" => get_web_search(pool).await,
        "UpdateWebSearchEmulationConfig" => update_web_search(pool, payload).await,
        "ResetWebSearchUsage" => reset_web_search_usage(pool, payload).await,
        "TestWebSearchEmulation" => test_web_search(pool, payload).await,
        _ => return None,
    })
}

async fn get_admin_api_key(pool: &PgPool) -> Result<Value, AdminError> {
    let key = read_setting(pool, ADMIN_API_KEY).await?.unwrap_or_default();
    let exists = !key.is_empty();
    let masked_key = if key.len() > 14 {
        format!("{}...{}", &key[..10], &key[key.len() - 4..])
    } else {
        key
    };
    Ok(json!({ "exists": exists, "masked_key": masked_key }))
}

async fn regenerate_admin_api_key(pool: &PgPool) -> Result<Value, AdminError> {
    let mut random = [0_u8; 32];
    OsRng.fill_bytes(&mut random);
    let key = format!("admin-{}", hex::encode(random));
    write_setting(pool, ADMIN_API_KEY, &key).await?;
    Ok(json!({ "key": key }))
}

async fn delete_admin_api_key(pool: &PgPool) -> Result<Value, AdminError> {
    delete_setting(pool, ADMIN_API_KEY).await?;
    Ok(json!({ "message": "Admin API key deleted" }))
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(default)]
struct OverloadCooldownSettings {
    enabled: bool,
    cooldown_minutes: i32,
}

impl OverloadCooldownSettings {
    const fn production_default() -> Self {
        Self {
            enabled: true,
            cooldown_minutes: 10,
        }
    }

    fn normalize_read(mut self) -> Self {
        self.cooldown_minutes = self.cooldown_minutes.clamp(1, 120);
        self
    }

    fn validate_write(mut self) -> Result<Self, AdminError> {
        if !(1..=120).contains(&self.cooldown_minutes) {
            if self.enabled {
                return Err(AdminError::BadRequest(
                    "cooldown_minutes must be between 1-120".to_owned(),
                ));
            }
            self.cooldown_minutes = 10;
        }
        Ok(self)
    }
}

async fn get_overload_cooldown(pool: &PgPool) -> Result<Value, AdminError> {
    let settings = read_json_or(
        pool,
        OVERLOAD_COOLDOWN,
        OverloadCooldownSettings::production_default,
    )
    .await?
    .normalize_read();
    to_json_value(&settings)
}

async fn update_overload_cooldown(pool: &PgPool, payload: Value) -> Result<Value, AdminError> {
    let settings = from_payload::<OverloadCooldownSettings>(payload)?.validate_write()?;
    write_json_setting(pool, OVERLOAD_COOLDOWN, &settings).await?;
    to_json_value(&settings)
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(default)]
struct RateLimit429CooldownSettings {
    enabled: bool,
    cooldown_seconds: i32,
}

impl RateLimit429CooldownSettings {
    const fn production_default() -> Self {
        Self {
            enabled: true,
            cooldown_seconds: 5,
        }
    }

    fn normalize_read(mut self) -> Self {
        self.cooldown_seconds = self.cooldown_seconds.clamp(1, 7_200);
        self
    }

    fn validate_write(mut self) -> Result<Self, AdminError> {
        if !(1..=7_200).contains(&self.cooldown_seconds) {
            if self.enabled {
                return Err(AdminError::BadRequest(
                    "cooldown_seconds must be between 1-7200".to_owned(),
                ));
            }
            self.cooldown_seconds = 5;
        }
        Ok(self)
    }
}

async fn get_rate_limit_429_cooldown(pool: &PgPool) -> Result<Value, AdminError> {
    let settings = read_json_or(
        pool,
        RATE_LIMIT_429_COOLDOWN,
        RateLimit429CooldownSettings::production_default,
    )
    .await?
    .normalize_read();
    to_json_value(&settings)
}

async fn update_rate_limit_429_cooldown(
    pool: &PgPool,
    payload: Value,
) -> Result<Value, AdminError> {
    let settings = from_payload::<RateLimit429CooldownSettings>(payload)?.validate_write()?;
    write_json_setting(pool, RATE_LIMIT_429_COOLDOWN, &settings).await?;
    to_json_value(&settings)
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(default)]
struct StreamTimeoutSettings {
    enabled: bool,
    action: String,
    temp_unsched_minutes: i32,
    threshold_count: i32,
    threshold_window_minutes: i32,
}

impl StreamTimeoutSettings {
    fn production_default() -> Self {
        Self {
            enabled: false,
            action: "temp_unsched".to_owned(),
            temp_unsched_minutes: 5,
            threshold_count: 3,
            threshold_window_minutes: 10,
        }
    }

    fn normalize_read(mut self) -> Self {
        self.temp_unsched_minutes = self.temp_unsched_minutes.clamp(1, 60);
        self.threshold_count = self.threshold_count.clamp(1, 10);
        self.threshold_window_minutes = self.threshold_window_minutes.clamp(1, 60);
        if !matches!(self.action.as_str(), "temp_unsched" | "error" | "none") {
            "temp_unsched".clone_into(&mut self.action);
        }
        self
    }

    fn validate_write(self) -> Result<Self, AdminError> {
        if !(1..=60).contains(&self.temp_unsched_minutes) {
            return Err(AdminError::BadRequest(
                "temp_unsched_minutes must be between 1-60".to_owned(),
            ));
        }
        if !(1..=10).contains(&self.threshold_count) {
            return Err(AdminError::BadRequest(
                "threshold_count must be between 1-10".to_owned(),
            ));
        }
        if !(1..=60).contains(&self.threshold_window_minutes) {
            return Err(AdminError::BadRequest(
                "threshold_window_minutes must be between 1-60".to_owned(),
            ));
        }
        if !matches!(self.action.as_str(), "temp_unsched" | "error" | "none") {
            return Err(AdminError::BadRequest(format!(
                "invalid action: {}",
                self.action
            )));
        }
        Ok(self)
    }
}

async fn get_stream_timeout(pool: &PgPool) -> Result<Value, AdminError> {
    let settings = read_json_or(
        pool,
        STREAM_TIMEOUT,
        StreamTimeoutSettings::production_default,
    )
    .await?
    .normalize_read();
    to_json_value(&settings)
}

async fn update_stream_timeout(pool: &PgPool, payload: Value) -> Result<Value, AdminError> {
    let settings = from_payload::<StreamTimeoutSettings>(payload)?.validate_write()?;
    write_json_setting(pool, STREAM_TIMEOUT, &settings).await?;
    to_json_value(&settings)
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(default)]
#[allow(clippy::struct_excessive_bools)]
struct RectifierSettings {
    enabled: bool,
    thinking_signature_enabled: bool,
    thinking_budget_enabled: bool,
    apikey_signature_enabled: bool,
    apikey_signature_patterns: Vec<String>,
}

impl RectifierSettings {
    fn production_default() -> Self {
        Self {
            enabled: true,
            thinking_signature_enabled: true,
            thinking_budget_enabled: true,
            apikey_signature_enabled: false,
            apikey_signature_patterns: Vec::new(),
        }
    }

    fn validate_write(mut self) -> Result<Self, AdminError> {
        if self.apikey_signature_patterns.len() > 50 {
            return Err(AdminError::BadRequest(
                "Too many signature patterns (max 50)".to_owned(),
            ));
        }
        let mut cleaned = Vec::with_capacity(self.apikey_signature_patterns.len());
        for pattern in self.apikey_signature_patterns {
            let pattern = pattern.trim();
            if pattern.is_empty() {
                continue;
            }
            if pattern.chars().count() > 500 {
                return Err(AdminError::BadRequest(
                    "Signature pattern too long (max 500 characters)".to_owned(),
                ));
            }
            cleaned.push(pattern.to_owned());
        }
        self.apikey_signature_patterns = cleaned;
        Ok(self)
    }
}

async fn get_rectifier(pool: &PgPool) -> Result<Value, AdminError> {
    let settings = read_json_or(pool, RECTIFIER, RectifierSettings::production_default).await?;
    to_json_value(&settings)
}

async fn update_rectifier(pool: &PgPool, payload: Value) -> Result<Value, AdminError> {
    let settings = from_payload::<RectifierSettings>(payload)?.validate_write()?;
    write_json_setting(pool, RECTIFIER, &settings).await?;
    to_json_value(&settings)
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(default)]
struct BetaPolicySettings {
    rules: Vec<BetaPolicyRule>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(default)]
struct BetaPolicyRule {
    beta_token: String,
    action: String,
    scope: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    error_message: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    model_whitelist: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    fallback_action: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    fallback_error_message: String,
}

impl BetaPolicySettings {
    fn production_default() -> Self {
        Self {
            rules: vec![
                BetaPolicyRule {
                    beta_token: "fast-mode-2026-02-01".to_owned(),
                    action: "filter".to_owned(),
                    scope: "all".to_owned(),
                    ..BetaPolicyRule::default()
                },
                BetaPolicyRule {
                    beta_token: "context-1m-2025-08-07".to_owned(),
                    action: "pass".to_owned(),
                    scope: "all".to_owned(),
                    model_whitelist: [
                        "claude-sonnet-5",
                        "claude-sonnet-5-*",
                        "claude-sonnet-5@*",
                        "us.anthropic.claude-sonnet-5*",
                        "eu.anthropic.claude-sonnet-5*",
                        "apac.anthropic.claude-sonnet-5*",
                        "jp.anthropic.claude-sonnet-5*",
                        "au.anthropic.claude-sonnet-5*",
                        "us-gov.anthropic.claude-sonnet-5*",
                        "global.anthropic.claude-sonnet-5*",
                        "anthropic.claude-sonnet-5*",
                    ]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                    fallback_action: "filter".to_owned(),
                    ..BetaPolicyRule::default()
                },
            ],
        }
    }

    fn validate_write(mut self) -> Result<Self, AdminError> {
        for (index, rule) in self.rules.iter_mut().enumerate() {
            rule.beta_token = rule.beta_token.trim().to_owned();
            if rule.beta_token.is_empty() {
                return Err(AdminError::BadRequest(format!(
                    "rule[{index}]: beta_token cannot be empty"
                )));
            }
            if !matches!(rule.action.as_str(), "pass" | "filter" | "block") {
                return Err(AdminError::BadRequest(format!(
                    "rule[{index}]: invalid action {:?}",
                    rule.action
                )));
            }
            if !matches!(rule.scope.as_str(), "all" | "oauth" | "apikey" | "bedrock") {
                return Err(AdminError::BadRequest(format!(
                    "rule[{index}]: invalid scope {:?}",
                    rule.scope
                )));
            }
            for (pattern_index, pattern) in rule.model_whitelist.iter_mut().enumerate() {
                *pattern = pattern.trim().to_owned();
                if pattern.is_empty() {
                    return Err(AdminError::BadRequest(format!(
                        "rule[{index}]: model_whitelist[{pattern_index}] cannot be empty"
                    )));
                }
            }
            if !rule.fallback_action.is_empty()
                && !matches!(rule.fallback_action.as_str(), "pass" | "filter" | "block")
            {
                return Err(AdminError::BadRequest(format!(
                    "rule[{index}]: invalid fallback_action {:?}",
                    rule.fallback_action
                )));
            }
        }
        Ok(self)
    }
}

async fn get_beta_policy(pool: &PgPool) -> Result<Value, AdminError> {
    let settings = read_json_or(pool, BETA_POLICY, BetaPolicySettings::production_default).await?;
    to_json_value(&settings)
}

async fn update_beta_policy(pool: &PgPool, payload: Value) -> Result<Value, AdminError> {
    let settings = from_payload::<BetaPolicySettings>(payload)?.validate_write()?;
    write_json_setting(pool, BETA_POLICY, &settings).await?;
    to_json_value(&settings)
}

struct EmailEventDef {
    event: &'static str,
    label: &'static str,
    description: &'static str,
    category: &'static str,
    optional: bool,
    placeholders: &'static [&'static str],
    accent: &'static str,
    title_en: &'static str,
    title_zh: &'static str,
    subject_en: &'static str,
    subject_zh: &'static str,
    content_en: &'static str,
    content_zh: &'static str,
}

const EMAIL_EVENTS: &[EmailEventDef] = &[
    EmailEventDef {
        event: "auth.verify_code",
        label: "Email verification code",
        description: "Sent for registration, email binding, OAuth pending email, and TOTP verification flows.",
        category: "auth",
        optional: false,
        placeholders: &[
            "site_name",
            "recipient_name",
            "recipient_email",
            "verification_code",
            "expires_in_minutes",
        ],
        accent: "#4f46e5",
        title_en: "Email verification code",
        title_zh: "邮箱验证码",
        subject_en: "[{{site_name}}] Email verification code",
        subject_zh: "[{{site_name}}] 邮箱验证码",
        content_en: r#"<p>Hello {{recipient_name}},</p><p>Your verification code is:</p><p style="font-size:32px;font-weight:700;text-align:center">{{verification_code}}</p><p>This code expires in <strong>{{expires_in_minutes}}</strong> minutes.</p>"#,
        content_zh: r#"<p>{{recipient_name}}，您好：</p><p>您的验证码是：</p><p style="font-size:32px;font-weight:700;text-align:center">{{verification_code}}</p><p>验证码将在 <strong>{{expires_in_minutes}}</strong> 分钟后失效。</p>"#,
    },
    EmailEventDef {
        event: "auth.password_reset",
        label: "Password reset",
        description: "Sent when a user requests a password reset link.",
        category: "auth",
        optional: false,
        placeholders: &[
            "site_name",
            "recipient_name",
            "recipient_email",
            "reset_url",
            "expires_in_minutes",
        ],
        accent: "#7c3aed",
        title_en: "Password reset",
        title_zh: "密码重置",
        subject_en: "[{{site_name}}] Password reset request",
        subject_zh: "[{{site_name}}] 密码重置请求",
        content_en: r#"<p>Hello {{recipient_name}},</p><p>We received a request to reset your password.</p><p><a class="button" href="{{reset_url}}">Reset password</a></p><p>This link expires in <strong>{{expires_in_minutes}}</strong> minutes.</p>"#,
        content_zh: r#"<p>{{recipient_name}}，您好：</p><p>我们收到了您的密码重置请求。</p><p><a class="button" href="{{reset_url}}">重置密码</a></p><p>链接将在 <strong>{{expires_in_minutes}}</strong> 分钟后失效。</p>"#,
    },
    EmailEventDef {
        event: "notification_email.verify_code",
        label: "Notification email verification code",
        description: "Sent when a user verifies an extra notification email address.",
        category: "auth",
        optional: false,
        placeholders: &[
            "site_name",
            "recipient_name",
            "recipient_email",
            "verification_code",
            "expires_in_minutes",
        ],
        accent: "#0ea5e9",
        title_en: "Notification email verification",
        title_zh: "通知邮箱验证",
        subject_en: "[{{site_name}}] Notification email verification code",
        subject_zh: "[{{site_name}}] 通知邮箱验证码",
        content_en: r#"<p>Hello {{recipient_name}},</p><p>You are adding this address as an extra notification email.</p><p style="font-size:32px;font-weight:700;text-align:center">{{verification_code}}</p><p>This code expires in <strong>{{expires_in_minutes}}</strong> minutes.</p>"#,
        content_zh: r#"<p>{{recipient_name}}，您好：</p><p>您正在添加额外的通知邮箱。</p><p style="font-size:32px;font-weight:700;text-align:center">{{verification_code}}</p><p>验证码将在 <strong>{{expires_in_minutes}}</strong> 分钟后失效。</p>"#,
    },
    EmailEventDef {
        event: "subscription.purchase_success",
        label: "Subscription purchase success",
        description: "Sent after a subscription purchase is fulfilled.",
        category: "subscription",
        optional: false,
        placeholders: &[
            "site_name",
            "recipient_name",
            "recipient_email",
            "subscription_group",
            "subscription_days",
            "expiry_time",
            "order_id",
        ],
        accent: "#2563eb",
        title_en: "Subscription activated",
        title_zh: "订阅已开通",
        subject_en: "[{{site_name}}] Subscription purchase successful",
        subject_zh: "[{{site_name}}] 订阅购买成功",
        content_en: r"<p>Hello {{recipient_name}},</p><p>Your <strong>{{subscription_group}}</strong> subscription is active for <strong>{{subscription_days}}</strong> days.</p><p>Expiry: {{expiry_time}}</p><p>Order ID: {{order_id}}</p>",
        content_zh: r"<p>{{recipient_name}}，您好：</p><p>您的 <strong>{{subscription_group}}</strong> 订阅已开通，有效期 <strong>{{subscription_days}}</strong> 天。</p><p>到期时间：{{expiry_time}}</p><p>订单号：{{order_id}}</p>",
    },
    EmailEventDef {
        event: "subscription.expiry_reminder",
        label: "Subscription expiry reminder",
        description: "Optional reminder sent before an active subscription expires.",
        category: "subscription",
        optional: true,
        placeholders: &[
            "site_name",
            "recipient_name",
            "recipient_email",
            "subscription_group",
            "expiry_time",
            "days_remaining",
            "unsubscribe_url",
        ],
        accent: "#f97316",
        title_en: "Subscription expiry reminder",
        title_zh: "订阅到期提醒",
        subject_en: "[{{site_name}}] Subscription expires in {{days_remaining}} day(s)",
        subject_zh: "[{{site_name}}] 订阅将在 {{days_remaining}} 天后到期",
        content_en: r#"<p>Hello {{recipient_name}},</p><p>Your <strong>{{subscription_group}}</strong> subscription expires in <strong>{{days_remaining}}</strong> day(s).</p><p>Expiry: {{expiry_time}}</p><p><a href="{{unsubscribe_url}}">Unsubscribe</a></p>"#,
        content_zh: r#"<p>{{recipient_name}}，您好：</p><p>您的 <strong>{{subscription_group}}</strong> 订阅将在 <strong>{{days_remaining}}</strong> 天后到期。</p><p>到期时间：{{expiry_time}}</p><p><a href="{{unsubscribe_url}}">退订提醒</a></p>"#,
    },
    EmailEventDef {
        event: "balance.low",
        label: "Low balance alert",
        description: "Optional alert sent when balance crosses the configured low-balance threshold.",
        category: "billing",
        optional: true,
        placeholders: &[
            "site_name",
            "recipient_name",
            "recipient_email",
            "current_balance",
            "threshold",
            "recharge_url",
            "unsubscribe_url",
        ],
        accent: "#d97706",
        title_en: "Low balance alert",
        title_zh: "余额不足提醒",
        subject_en: "[{{site_name}}] Low balance alert",
        subject_zh: "[{{site_name}}] 余额不足提醒",
        content_en: r#"<p>Hello {{recipient_name}},</p><p>Your balance is <strong>${{current_balance}}</strong>, below <strong>${{threshold}}</strong>.</p><p><a class="button" href="{{recharge_url}}">Recharge now</a></p><p><a href="{{unsubscribe_url}}">Unsubscribe</a></p>"#,
        content_zh: r#"<p>{{recipient_name}}，您好：</p><p>当前余额为 <strong>${{current_balance}}</strong>，低于提醒阈值 <strong>${{threshold}}</strong>。</p><p><a class="button" href="{{recharge_url}}">立即充值</a></p><p><a href="{{unsubscribe_url}}">退订提醒</a></p>"#,
    },
    EmailEventDef {
        event: "balance.recharge_success",
        label: "Balance recharge success",
        description: "Sent after a balance recharge order is fulfilled.",
        category: "billing",
        optional: false,
        placeholders: &[
            "site_name",
            "recipient_name",
            "recipient_email",
            "recharge_amount",
            "current_balance",
            "order_id",
        ],
        accent: "#16a34a",
        title_en: "Recharge successful",
        title_zh: "余额充值成功",
        subject_en: "[{{site_name}}] Balance recharge successful",
        subject_zh: "[{{site_name}}] 余额充值成功",
        content_en: r"<p>Hello {{recipient_name}},</p><p>Your recharge of <strong>${{recharge_amount}}</strong> is complete.</p><p>Current balance: <strong>${{current_balance}}</strong></p><p>Order ID: {{order_id}}</p>",
        content_zh: r"<p>{{recipient_name}}，您好：</p><p>您的余额充值 <strong>${{recharge_amount}}</strong> 已完成。</p><p>当前余额：<strong>${{current_balance}}</strong></p><p>订单号：{{order_id}}</p>",
    },
    EmailEventDef {
        event: "account.quota_alert",
        label: "Account quota alert",
        description: "Sent to configured admin notification emails when an upstream account quota threshold is crossed.",
        category: "admin",
        optional: false,
        placeholders: &[
            "site_name",
            "recipient_name",
            "recipient_email",
            "account_id",
            "account_name",
            "platform",
            "quota_dimension",
            "quota_used",
            "quota_limit",
            "quota_remaining",
            "quota_threshold",
        ],
        accent: "#dc2626",
        title_en: "Account quota alert",
        title_zh: "账号限额告警",
        subject_en: "[{{site_name}}] Account quota alert - {{account_name}}",
        subject_zh: "[{{site_name}}] 账号限额告警 - {{account_name}}",
        content_en: r"<p>Account <strong>{{account_name}}</strong> crossed its quota threshold.</p><p>ID: {{account_id}}; Platform: {{platform}}; Dimension: {{quota_dimension}}</p><p>Used / Limit: {{quota_used}} / {{quota_limit}}; Remaining: {{quota_remaining}}; Threshold: {{quota_threshold}}</p>",
        content_zh: r"<p>账号 <strong>{{account_name}}</strong> 已触发限额告警。</p><p>ID：{{account_id}}；平台：{{platform}}；维度：{{quota_dimension}}</p><p>已用 / 限额：{{quota_used}} / {{quota_limit}}；剩余：{{quota_remaining}}；阈值：{{quota_threshold}}</p>",
    },
    EmailEventDef {
        event: "content_moderation.violation_notice",
        label: "Risk control violation notice",
        description: "Sent to users when a request triggers content moderation/risk control rules.",
        category: "risk_control",
        optional: false,
        placeholders: &[
            "site_name",
            "recipient_name",
            "recipient_email",
            "triggered_at",
            "group_name",
            "moderation_category",
            "moderation_score",
            "violation_count",
            "ban_threshold",
        ],
        accent: "#ef4444",
        title_en: "Risk control notice",
        title_zh: "账号风控提醒",
        subject_en: "[{{site_name}}] Risk control notice",
        subject_zh: "[{{site_name}}] 账号风控提醒",
        content_en: r"<p>Hello {{recipient_name}},</p><p>Your request triggered risk control at {{triggered_at}}.</p><p>Group: {{group_name}}; Category / Score: {{moderation_category}} / {{moderation_score}}; Count: {{violation_count}} / {{ban_threshold}}</p>",
        content_zh: r"<p>{{recipient_name}}，您好：</p><p>您的请求在 {{triggered_at}} 触发了风控策略。</p><p>分组：{{group_name}}；类别 / 分数：{{moderation_category}} / {{moderation_score}}；次数：{{violation_count}} / {{ban_threshold}}</p>",
    },
    EmailEventDef {
        event: "content_moderation.account_disabled",
        label: "Risk control account disabled",
        description: "Sent to users when content moderation automatically disables their account.",
        category: "risk_control",
        optional: false,
        placeholders: &[
            "site_name",
            "recipient_name",
            "recipient_email",
            "triggered_at",
            "group_name",
            "moderation_category",
            "moderation_score",
            "violation_count",
            "ban_threshold",
        ],
        accent: "#b91c1c",
        title_en: "Account disabled",
        title_zh: "账号已被禁用",
        subject_en: "[{{site_name}}] Account disabled by risk control",
        subject_zh: "[{{site_name}}] 账号已被禁用",
        content_en: r"<p>Hello {{recipient_name}},</p><p>Your account was disabled by risk control at {{triggered_at}}.</p><p>Group: {{group_name}}; Category / Score: {{moderation_category}} / {{moderation_score}}; Count: {{violation_count}} / {{ban_threshold}}</p>",
        content_zh: r"<p>{{recipient_name}}，您好：</p><p>您的账号在 {{triggered_at}} 被风控系统禁用。</p><p>分组：{{group_name}}；类别 / 分数：{{moderation_category}} / {{moderation_score}}；次数：{{violation_count}} / {{ban_threshold}}</p>",
    },
    EmailEventDef {
        event: "content_moderation.cyber_policy_notice",
        label: "Cyber policy notice",
        description: "Sent to users when an upstream request is blocked by cyber-security policy.",
        category: "risk_control",
        optional: false,
        placeholders: &[
            "site_name",
            "recipient_name",
            "recipient_email",
            "triggered_at",
            "model",
            "group_name",
            "upstream_message",
        ],
        accent: "#ef4444",
        title_en: "Cyber-security policy notice",
        title_zh: "网络安全策略拦截提醒",
        subject_en: "[{{site_name}}] Cyber-security policy notice",
        subject_zh: "[{{site_name}}] 网络安全策略拦截提醒",
        content_en: r"<p>Hello {{recipient_name}},</p><p>Your request was blocked at {{triggered_at}}.</p><p>Model: {{model}}; Group: {{group_name}}; Upstream message: {{upstream_message}}</p>",
        content_zh: r"<p>{{recipient_name}}，您好：</p><p>您的请求在 {{triggered_at}} 被上游安全策略拦截。</p><p>模型：{{model}}；分组：{{group_name}}；上游说明：{{upstream_message}}</p>",
    },
    EmailEventDef {
        event: "ops.alert",
        label: "Ops alert",
        description: "Sent to configured operations recipients when an ops alert rule fires.",
        category: "ops",
        optional: false,
        placeholders: &[
            "site_name",
            "recipient_name",
            "recipient_email",
            "rule_name",
            "severity",
            "alert_status",
            "metric_type",
            "operator",
            "metric_value",
            "threshold_value",
            "triggered_at",
            "alert_description",
        ],
        accent: "#ea580c",
        title_en: "Ops alert",
        title_zh: "运维告警",
        subject_en: "[Ops Alert][{{severity}}] {{rule_name}}",
        subject_zh: "[运维告警][{{severity}}] {{rule_name}}",
        content_en: r"<p><strong>Rule</strong>: {{rule_name}}</p><p><strong>Severity / Status</strong>: {{severity}} / {{alert_status}}</p><p><strong>Metric</strong>: {{metric_type}} {{operator}} {{metric_value}} ({{threshold_value}})</p><p><strong>Fired at</strong>: {{triggered_at}}</p><p>{{alert_description}}</p>",
        content_zh: r"<p><strong>规则</strong>：{{rule_name}}</p><p><strong>级别 / 状态</strong>：{{severity}} / {{alert_status}}</p><p><strong>指标</strong>：{{metric_type}} {{operator}} {{metric_value}}（{{threshold_value}}）</p><p><strong>触发时间</strong>：{{triggered_at}}</p><p>{{alert_description}}</p>",
    },
    EmailEventDef {
        event: "ops.scheduled_report",
        label: "Ops scheduled report",
        description: "Sent to configured operations recipients for scheduled reports.",
        category: "ops",
        optional: false,
        placeholders: &[
            "site_name",
            "recipient_name",
            "recipient_email",
            "report_name",
            "report_type",
            "report_start_time",
            "report_end_time",
            "report_html",
        ],
        accent: "#0891b2",
        title_en: "Ops report",
        title_zh: "运维报表",
        subject_en: "[Ops Report] {{report_name}}",
        subject_zh: "[运维报表] {{report_name}}",
        content_en: r"<p><strong>Report</strong>: {{report_name}}</p><p><strong>Type</strong>: {{report_type}}</p><p><strong>Range</strong>: {{report_start_time}} - {{report_end_time}}</p><div>{{report_html}}</div>",
        content_zh: r"<p><strong>报表</strong>：{{report_name}}</p><p><strong>类型</strong>：{{report_type}}</p><p><strong>时间范围</strong>：{{report_start_time}} - {{report_end_time}}</p><div>{{report_html}}</div>",
    },
];

#[derive(Clone, Debug)]
struct EmailTemplate {
    event: String,
    locale: String,
    subject: String,
    html: String,
    is_custom: bool,
    updated_at: Option<String>,
    placeholders: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct StoredEmailTemplate {
    subject: String,
    html: String,
    updated_at: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct UpdateEmailTemplateRequest {
    subject: String,
    html: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PreviewEmailTemplateRequest {
    event: String,
    locale: String,
    subject: String,
    html: String,
    variables: BTreeMap<String, String>,
}

async fn list_email_templates(pool: &PgPool) -> Result<Value, AdminError> {
    let rows = sqlx::query(
        "SELECT key, value FROM settings WHERE key LIKE 'notification_email_template:%'",
    )
    .fetch_all(pool)
    .await?;
    let overrides = rows
        .into_iter()
        .map(|row| {
            Ok((
                row.try_get::<String, _>("key")?,
                row.try_get::<String, _>("value")?,
            ))
        })
        .collect::<Result<HashMap<_, _>, sqlx::Error>>()?;

    let events = EMAIL_EVENTS
        .iter()
        .map(|event| {
            json!({
                "value": event.event,
                "label": event.label,
                "description": event.description,
                "category": event.category,
                "optional": event.optional,
            })
        })
        .collect::<Vec<_>>();
    let mut templates = Vec::with_capacity(EMAIL_EVENTS.len() * 2);
    for event in EMAIL_EVENTS {
        for locale in ["en", "zh"] {
            let key = email_template_key(event.event, locale);
            let template = email_template_from_raw(event, locale, overrides.get(&key))?;
            templates.push(email_template_summary(&template));
        }
    }
    let mut seen = HashSet::new();
    let placeholders = EMAIL_EVENTS
        .iter()
        .flat_map(|event| event.placeholders.iter().copied())
        .filter(|placeholder| seen.insert(*placeholder))
        .collect::<Vec<_>>();
    Ok(json!({
        "events": events,
        "locales": ["en", "zh"],
        "templates": templates,
        "placeholders": placeholders,
    }))
}

async fn get_email_template_route(pool: &PgPool, path: &str) -> Result<Value, AdminError> {
    let (event, locale) = email_template_path(path)?;
    let template = load_email_template(pool, event, locale).await?;
    Ok(email_template_detail(&template))
}

async fn update_email_template_route(
    pool: &PgPool,
    path: &str,
    payload: Value,
) -> Result<Value, AdminError> {
    let (event, locale) = email_template_path(path)?;
    let event = email_event(event)?;
    let locale = normalize_email_locale(locale);
    let request = from_payload::<UpdateEmailTemplateRequest>(payload)?;
    validate_email_template(event, &request.subject, &request.html)?;
    let stored = StoredEmailTemplate {
        subject: request.subject.trim().to_owned(),
        html: request.html,
        updated_at: Utc::now().to_rfc3339(),
    };
    write_json_setting(pool, &email_template_key(event.event, locale), &stored).await?;
    let template = load_email_template(pool, event.event, locale).await?;
    Ok(email_template_detail(&template))
}

async fn restore_email_template_route(pool: &PgPool, path: &str) -> Result<Value, AdminError> {
    let (event, locale) = email_template_path(path)?;
    let event = email_event(event)?;
    let locale = normalize_email_locale(locale);
    delete_setting(pool, &email_template_key(event.event, locale)).await?;
    Ok(email_template_detail(&official_email_template(
        event, locale,
    )))
}

async fn preview_email_template(pool: &PgPool, payload: Value) -> Result<Value, AdminError> {
    let request = from_payload::<PreviewEmailTemplateRequest>(payload)?;
    let event = email_event(&request.event)?;
    let locale = normalize_email_locale(&request.locale);
    let mut subject = request.subject;
    let mut html = request.html;
    if subject.trim().is_empty() || html.trim().is_empty() {
        let stored = load_email_template(pool, event.event, locale).await?;
        if subject.trim().is_empty() {
            subject = stored.subject;
        }
        if html.trim().is_empty() {
            html = stored.html;
        }
    }
    validate_email_template(event, &subject, &html)?;
    let mut variables = sample_email_variables(locale);
    if let Some(site_name) = read_setting(pool, "site_name").await?
        && !site_name.trim().is_empty()
    {
        variables.insert("site_name".to_owned(), site_name.trim().to_owned());
    }
    variables.extend(request.variables);
    let rendered_subject =
        render_email_string(event, &subject, &variables, false).replace(['\r', '\n'], "");
    let rendered_html = render_email_string(event, &html, &variables, true);
    Ok(json!({ "subject": rendered_subject, "html": rendered_html }))
}

async fn load_email_template(
    pool: &PgPool,
    event: &str,
    locale: &str,
) -> Result<EmailTemplate, AdminError> {
    let event = email_event(event)?;
    let locale = normalize_email_locale(locale);
    let raw = read_setting(pool, &email_template_key(event.event, locale)).await?;
    email_template_from_raw(event, locale, raw.as_ref())
}

fn email_template_from_raw(
    event: &EmailEventDef,
    locale: &str,
    raw: Option<&String>,
) -> Result<EmailTemplate, AdminError> {
    let mut template = official_email_template(event, locale);
    let Some(raw) = raw.filter(|raw| !raw.trim().is_empty()) else {
        return Ok(template);
    };
    let stored = serde_json::from_str::<StoredEmailTemplate>(raw).map_err(|error| {
        AdminError::Probe(format!(
            "decode email template override for {}/{}: {error}",
            event.event, locale
        ))
    })?;
    validate_email_template(event, &stored.subject, &stored.html).map_err(|error| {
        AdminError::Probe(format!(
            "stored email template for {}/{} is invalid: {error}",
            event.event, locale
        ))
    })?;
    template.subject = stored.subject;
    template.html = stored.html;
    template.is_custom = true;
    template.updated_at = Some(stored.updated_at);
    Ok(template)
}

fn official_email_template(event: &EmailEventDef, locale: &str) -> EmailTemplate {
    let chinese = locale == "zh";
    EmailTemplate {
        event: event.event.to_owned(),
        locale: locale.to_owned(),
        subject: if chinese {
            event.subject_zh
        } else {
            event.subject_en
        }
        .to_owned(),
        html: email_card(
            event.accent,
            if chinese {
                event.title_zh
            } else {
                event.title_en
            },
            if chinese {
                event.content_zh
            } else {
                event.content_en
            },
        ),
        is_custom: false,
        updated_at: None,
        placeholders: event.placeholders.iter().map(ToString::to_string).collect(),
    }
}

fn email_template_summary(template: &EmailTemplate) -> Value {
    let mut object = Map::from_iter([
        ("event".to_owned(), json!(template.event)),
        ("locale".to_owned(), json!(template.locale)),
        ("subject".to_owned(), json!(template.subject)),
    ]);
    if template.is_custom {
        object.insert("is_custom".to_owned(), Value::Bool(true));
    }
    if let Some(updated_at) = &template.updated_at {
        object.insert("updated_at".to_owned(), json!(updated_at));
    }
    Value::Object(object)
}

fn email_template_detail(template: &EmailTemplate) -> Value {
    let mut object = email_template_summary(template)
        .as_object()
        .cloned()
        .unwrap_or_default();
    object.insert("html".to_owned(), json!(template.html));
    object.insert("placeholders".to_owned(), json!(template.placeholders));
    Value::Object(object)
}

fn email_event(event: &str) -> Result<&'static EmailEventDef, AdminError> {
    let event = event.trim().to_ascii_lowercase();
    EMAIL_EVENTS
        .iter()
        .find(|definition| definition.event == event)
        .ok_or_else(|| AdminError::BadRequest(format!("unsupported email template event: {event}")))
}

fn email_template_path(path: &str) -> Result<(&str, &str), AdminError> {
    let segments = path.trim_matches('/').split('/').collect::<Vec<_>>();
    let index = segments
        .iter()
        .position(|segment| *segment == "email-templates")
        .ok_or_else(|| AdminError::BadRequest("email template path is invalid".to_owned()))?;
    match (segments.get(index + 1), segments.get(index + 2)) {
        (Some(event), Some(locale)) if !event.is_empty() && !locale.is_empty() => {
            Ok((event, locale))
        }
        _ => Err(AdminError::BadRequest(
            "email template event and locale are required".to_owned(),
        )),
    }
}

fn normalize_email_locale(raw: &str) -> &'static str {
    let raw = raw.trim().to_ascii_lowercase();
    for value in raw.split(',') {
        let tag = value.split(';').next().unwrap_or_default().trim();
        if tag.starts_with("zh") || tag == "cn" {
            return "zh";
        }
        if tag.starts_with("en") {
            return "en";
        }
    }
    "en"
}

fn email_template_key(event: &str, locale: &str) -> String {
    format!("{EMAIL_TEMPLATE_PREFIX}{event}:{locale}")
}

fn validate_email_template(
    event: &EmailEventDef,
    subject: &str,
    html: &str,
) -> Result<(), AdminError> {
    if subject.trim().is_empty() {
        return Err(AdminError::BadRequest(
            "email subject cannot be empty".to_owned(),
        ));
    }
    if subject.chars().count() > MAX_EMAIL_SUBJECT_CHARS {
        return Err(AdminError::BadRequest(format!(
            "email subject cannot exceed {MAX_EMAIL_SUBJECT_CHARS} characters"
        )));
    }
    if subject.chars().any(char::is_control) {
        return Err(AdminError::BadRequest(
            "email subject cannot contain control characters".to_owned(),
        ));
    }
    if html.trim().is_empty() {
        return Err(AdminError::BadRequest(
            "email html cannot be empty".to_owned(),
        ));
    }
    if html.len() > MAX_EMAIL_HTML_BYTES {
        return Err(AdminError::BadRequest(format!(
            "email html cannot exceed {MAX_EMAIL_HTML_BYTES} bytes"
        )));
    }
    if html.contains('\0') {
        return Err(AdminError::BadRequest(
            "email html cannot contain NUL characters".to_owned(),
        ));
    }
    let allowed = event.placeholders.iter().copied().collect::<HashSet<_>>();
    for captures in email_placeholder_pattern().captures_iter(&format!("{subject}\n{html}")) {
        let placeholder = captures.get(1).map_or("", |value| value.as_str());
        if !allowed.contains(placeholder) {
            return Err(AdminError::BadRequest(format!(
                "unsupported placeholder {{{{{placeholder}}}}} for event {}",
                event.event
            )));
        }
    }
    Ok(())
}

fn render_email_string(
    event: &EmailEventDef,
    input: &str,
    variables: &BTreeMap<String, String>,
    html: bool,
) -> String {
    email_placeholder_pattern()
        .replace_all(input, |captures: &regex::Captures<'_>| {
            let name = captures.get(1).map_or("", |value| value.as_str());
            let mut value = variables.get(name).cloned().unwrap_or_default();
            if name.ends_with("_url") && !safe_email_url(&value) {
                value.clear();
            }
            if html && !(event.event == "ops.scheduled_report" && name == "report_html") {
                escape_html(&value)
            } else {
                value.replace(['\r', '\n'], "")
            }
        })
        .into_owned()
}

fn safe_email_url(raw: &str) -> bool {
    let raw = raw.trim();
    if raw.is_empty() {
        return true;
    }
    if raw.starts_with('/') {
        return true;
    }
    Url::parse(raw).is_ok_and(|url| matches!(url.scheme(), "http" | "https" | "mailto"))
}

fn email_placeholder_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"\{\{\s*([a-zA-Z][a-zA-Z0-9_]*)\s*\}\}")
            .expect("email placeholder regex is valid")
    })
}

fn escape_html(raw: &str) -> String {
    let mut escaped = String::with_capacity(raw.len());
    for character in raw.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

fn sample_email_variables(locale: &str) -> BTreeMap<String, String> {
    let recipient = if locale == "zh" { "张三" } else { "Alex" };
    [
        ("site_name", "Sub2API"),
        ("recipient_name", recipient),
        ("recipient_email", "user@example.com"),
        ("verification_code", "123456"),
        ("expires_in_minutes", "15"),
        (
            "reset_url",
            "https://example.com/reset-password?token=preview",
        ),
        ("subscription_group", "Claude Pro"),
        ("subscription_days", "30"),
        ("expiry_time", "2026-06-18 12:00"),
        ("days_remaining", "3"),
        ("current_balance", "12.34"),
        ("threshold", "20.00"),
        ("recharge_url", "https://example.com/recharge"),
        ("recharge_amount", "50.00"),
        ("order_id", "1024"),
        ("unsubscribe_url", "https://example.com/unsubscribe"),
        ("account_id", "1001"),
        ("account_name", "openai-main"),
        ("platform", "openai"),
        ("quota_dimension", "Daily quota"),
        ("quota_used", "80.00"),
        ("quota_limit", "100.00"),
        ("quota_remaining", "20.00"),
        ("quota_threshold", "20%"),
        ("triggered_at", "2026-05-20 12:00:00"),
        ("group_name", "Default group"),
        ("moderation_category", "violence"),
        ("moderation_score", "0.982"),
        ("violation_count", "2"),
        ("ban_threshold", "3"),
        ("model", "claude-sonnet-4-20250514"),
        ("upstream_message", "Request blocked by cyber policy"),
        ("rule_name", "High error rate"),
        ("severity", "critical"),
        ("alert_status", "firing"),
        ("metric_type", "error_rate"),
        ("operator", ">="),
        ("metric_value", "12.50"),
        ("threshold_value", "10.00"),
        ("alert_description", "Error rate exceeded the threshold."),
        ("report_name", "Daily summary"),
        ("report_type", "daily_summary"),
        ("report_start_time", "2026-05-19 12:00"),
        ("report_end_time", "2026-05-20 12:00"),
        ("report_html", "<h2>Daily summary</h2><p>Requests: 1024</p>"),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value.to_owned()))
    .collect()
}

fn email_card(accent: &str, title: &str, content: &str) -> String {
    format!(
        r#"<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>body{{margin:0;padding:24px;background:#f4f4f5;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#18181b}}.container{{max-width:640px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden}}.header{{background:{accent};color:#fff;padding:28px 32px}}.header h1{{margin:0;font-size:24px}}.content{{padding:32px;font-size:15px;line-height:1.7}}.button{{display:inline-block;padding:11px 18px;border-radius:8px;background:{accent};color:#fff;text-decoration:none}}.footer{{padding:18px 32px;background:#fafafa;color:#71717a;font-size:12px}}</style></head><body><div class="container"><div class="header"><h1>{title}</h1></div><div class="content">{content}</div><div class="footer">This email was sent by {{{{site_name}}}}. Please do not reply directly.</div></div></body></html>"#
    )
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
struct WebSearchEmulationConfig {
    enabled: bool,
    providers: Vec<WebSearchProviderConfig>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
struct WebSearchProviderConfig {
    #[serde(rename = "type")]
    provider_type: String,
    api_key: String,
    api_key_configured: bool,
    quota_limit: Option<i64>,
    subscribed_at: Option<i64>,
    quota_used: i64,
    proxy_id: Option<i64>,
    expires_at: Option<i64>,
}

#[derive(Debug, Serialize)]
struct WebSearchResult {
    url: String,
    title: String,
    snippet: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    page_age: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct BraveResponse {
    web: BraveWeb,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct BraveWeb {
    results: Vec<BraveResult>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct BraveResult {
    url: String,
    title: String,
    description: String,
    age: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct TavilyResponse {
    results: Vec<TavilyResult>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct TavilyResult {
    url: String,
    title: String,
    content: String,
}

async fn get_web_search(pool: &PgPool) -> Result<Value, AdminError> {
    let config = load_web_search_config(pool).await?;
    web_search_public_value(pool, config).await
}

async fn update_web_search(pool: &PgPool, payload: Value) -> Result<Value, AdminError> {
    let mut incoming = from_payload::<WebSearchEmulationConfig>(payload)?;
    normalize_and_validate_web_search(&mut incoming)?;
    let existing = load_web_search_config(pool).await?;
    preserve_web_search_api_keys(&mut incoming, &existing);
    encrypt_web_search_api_keys(&mut incoming)?;
    if incoming.enabled {
        for provider in &incoming.providers {
            if provider.api_key.is_empty() {
                return Err(AdminError::BadRequest(format!(
                    "provider {} has no API key configured",
                    provider.provider_type
                )));
            }
        }
    }
    write_json_setting(pool, WEB_SEARCH, &incoming).await?;
    web_search_public_value(pool, incoming).await
}

async fn reset_web_search_usage(pool: &PgPool, payload: Value) -> Result<Value, AdminError> {
    let provider_type = payload
        .get("provider_type")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AdminError::BadRequest("provider_type is required".to_owned()))?;
    validate_web_search_provider_type(provider_type, 0)?;
    write_setting(
        pool,
        &format!("{WEB_SEARCH_USAGE_PREFIX}{provider_type}"),
        "0",
    )
    .await?;
    Ok(Value::Null)
}

async fn test_web_search(pool: &PgPool, payload: Value) -> Result<Value, AdminError> {
    let query = payload
        .get("query")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("major world events this year")
        .chars()
        .take(2_000)
        .collect::<String>();
    let config = load_web_search_config(pool).await?;
    if !config.enabled {
        return Err(AdminError::BadRequest(
            "web search emulation is disabled".to_owned(),
        ));
    }
    let usage = load_web_search_usage(pool, &config).await?;
    let now = Utc::now().timestamp();
    let provider = config
        .providers
        .iter()
        .find(|provider| {
            !provider.api_key.is_empty()
                && provider
                    .expires_at
                    .is_none_or(|expires_at| expires_at > now)
                && provider.quota_limit.is_none_or(|limit| {
                    usage
                        .get(&provider.provider_type)
                        .copied()
                        .unwrap_or_default()
                        < limit
                })
        })
        .ok_or_else(|| {
            AdminError::BadRequest("no available web search provider is configured".to_owned())
        })?;
    let api_key = secrets::decrypt_config_secret(&provider.api_key).map_err(|error| {
        AdminError::Probe(format!("decrypt web search provider API key: {error}"))
    })?;
    let client = web_search_client(pool, provider.proxy_id).await?;
    let results = match provider.provider_type.as_str() {
        "brave" => search_brave(&client, &api_key, &query).await?,
        "tavily" => search_tavily(&client, &api_key, &query).await?,
        _ => {
            return Err(AdminError::BadRequest(format!(
                "unsupported web search provider {}",
                provider.provider_type
            )));
        }
    };
    Ok(json!({
        "provider": provider.provider_type,
        "results": results,
        "query": query,
    }))
}

async fn load_web_search_config(pool: &PgPool) -> Result<WebSearchEmulationConfig, AdminError> {
    read_json_or(pool, WEB_SEARCH, WebSearchEmulationConfig::default).await
}

fn normalize_and_validate_web_search(
    config: &mut WebSearchEmulationConfig,
) -> Result<(), AdminError> {
    if config.providers.len() > MAX_WEB_SEARCH_PROVIDERS {
        return Err(AdminError::BadRequest(format!(
            "too many providers (max {MAX_WEB_SEARCH_PROVIDERS})"
        )));
    }
    let mut seen = HashSet::with_capacity(config.providers.len());
    for (index, provider) in config.providers.iter_mut().enumerate() {
        provider.provider_type = provider.provider_type.trim().to_ascii_lowercase();
        validate_web_search_provider_type(&provider.provider_type, index)?;
        if provider.quota_limit.is_some_and(|limit| limit < 0) {
            return Err(AdminError::BadRequest(format!(
                "provider[{index}]: quota_limit must be >= 0 or null"
            )));
        }
        if !seen.insert(provider.provider_type.clone()) {
            return Err(AdminError::BadRequest(format!(
                "provider[{index}]: duplicate type {:?}",
                provider.provider_type
            )));
        }
        provider.api_key = provider.api_key.trim().to_owned();
        provider.api_key_configured = false;
        provider.quota_used = 0;
        if provider.proxy_id.is_some_and(|id| id <= 0) {
            return Err(AdminError::BadRequest(format!(
                "provider[{index}]: proxy_id must be positive or null"
            )));
        }
    }
    Ok(())
}

fn validate_web_search_provider_type(provider_type: &str, index: usize) -> Result<(), AdminError> {
    if matches!(provider_type, "brave" | "tavily") {
        Ok(())
    } else {
        Err(AdminError::BadRequest(format!(
            "provider[{index}]: invalid type {provider_type:?}"
        )))
    }
}

fn preserve_web_search_api_keys(
    incoming: &mut WebSearchEmulationConfig,
    existing: &WebSearchEmulationConfig,
) {
    let existing = existing
        .providers
        .iter()
        .filter(|provider| !provider.api_key.is_empty())
        .map(|provider| (provider.provider_type.as_str(), provider.api_key.as_str()))
        .collect::<HashMap<_, _>>();
    for provider in &mut incoming.providers {
        if (provider.api_key.is_empty() || provider.api_key == "********")
            && let Some(api_key) = existing.get(provider.provider_type.as_str())
        {
            provider.api_key = (*api_key).to_owned();
        }
    }
}

fn encrypt_web_search_api_keys(config: &mut WebSearchEmulationConfig) -> Result<(), AdminError> {
    for provider in &mut config.providers {
        if provider.api_key.is_empty() {
            continue;
        }
        let plaintext = secrets::decrypt_config_secret(&provider.api_key).map_err(|error| {
            AdminError::Probe(format!("decrypt existing web search API key: {error}"))
        })?;
        provider.api_key = secrets::encrypt_config_secret(&plaintext)
            .map_err(|error| AdminError::Probe(format!("encrypt web search API key: {error}")))?;
    }
    Ok(())
}

async fn web_search_public_value(
    pool: &PgPool,
    mut config: WebSearchEmulationConfig,
) -> Result<Value, AdminError> {
    let usage = load_web_search_usage(pool, &config).await?;
    sanitize_web_search_config(&mut config, &usage);
    to_json_value(&config)
}

fn sanitize_web_search_config(config: &mut WebSearchEmulationConfig, usage: &HashMap<String, i64>) {
    for provider in &mut config.providers {
        provider.api_key_configured = !provider.api_key.is_empty();
        provider.api_key.clear();
        provider.quota_used = usage
            .get(&provider.provider_type)
            .copied()
            .unwrap_or_default();
    }
}

async fn load_web_search_usage(
    pool: &PgPool,
    config: &WebSearchEmulationConfig,
) -> Result<HashMap<String, i64>, AdminError> {
    let keys = config
        .providers
        .iter()
        .map(|provider| format!("{WEB_SEARCH_USAGE_PREFIX}{}", provider.provider_type))
        .collect::<Vec<_>>();
    if keys.is_empty() {
        return Ok(HashMap::new());
    }
    let rows = sqlx::query("SELECT key, value FROM settings WHERE key = ANY($1)")
        .bind(&keys)
        .fetch_all(pool)
        .await?;
    let mut usage = HashMap::with_capacity(rows.len());
    for row in rows {
        let key: String = row.try_get("key")?;
        let value: String = row.try_get("value")?;
        if let Some(provider_type) = key.strip_prefix(WEB_SEARCH_USAGE_PREFIX) {
            usage.insert(
                provider_type.to_owned(),
                value.parse::<i64>().unwrap_or_default().max(0),
            );
        }
    }
    Ok(usage)
}

async fn web_search_client(pool: &PgPool, proxy_id: Option<i64>) -> Result<Client, AdminError> {
    let mut builder = Client::builder()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(15));
    if let Some(proxy_id) = proxy_id {
        let proxy_url = load_web_search_proxy(pool, proxy_id).await?;
        builder = builder.proxy(Proxy::all(proxy_url).map_err(|error| {
            AdminError::BadRequest(format!("web search proxy is invalid: {error}"))
        })?);
    }
    builder
        .build()
        .map_err(|error| AdminError::Probe(format!("build web search client: {error}")))
}

async fn load_web_search_proxy(pool: &PgPool, proxy_id: i64) -> Result<String, AdminError> {
    let row = sqlx::query(
        "SELECT protocol, host, port, username, password FROM proxies WHERE id = $1 AND deleted_at IS NULL AND status = 'active'",
    )
    .bind(proxy_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AdminError::BadRequest("web search proxy is unavailable".to_owned()))?;
    let protocol: String = row.try_get("protocol")?;
    if !matches!(protocol.as_str(), "http" | "https" | "socks5" | "socks5h") {
        return Err(AdminError::BadRequest(
            "web search proxy protocol is invalid".to_owned(),
        ));
    }
    let host: String = row.try_get("host")?;
    let port: i32 = row.try_get("port")?;
    if !(1..=65_535).contains(&port) {
        return Err(AdminError::BadRequest(
            "web search proxy port is invalid".to_owned(),
        ));
    }
    let mut url = Url::parse(&format!("{protocol}://{host}:{port}"))
        .map_err(|_| AdminError::BadRequest("web search proxy URL is invalid".to_owned()))?;
    let username: Option<String> = row.try_get("username")?;
    let password: Option<String> = row.try_get("password")?;
    if let Some(username) = username.filter(|value| !value.is_empty()) {
        url.set_username(&username).map_err(|()| {
            AdminError::BadRequest("web search proxy username is invalid".to_owned())
        })?;
        url.set_password(password.as_deref()).map_err(|()| {
            AdminError::BadRequest("web search proxy password is invalid".to_owned())
        })?;
    }
    Ok(url.into())
}

async fn search_brave(
    client: &Client,
    api_key: &str,
    query: &str,
) -> Result<Vec<WebSearchResult>, AdminError> {
    let mut endpoint = Url::parse("https://api.search.brave.com/res/v1/web/search")
        .expect("Brave endpoint constant is valid");
    endpoint
        .query_pairs_mut()
        .append_pair("q", query)
        .append_pair("count", "5");
    let response = client
        .get(endpoint)
        .header("X-Subscription-Token", api_key)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|error| AdminError::Probe(format!("brave search request failed: {error}")))?;
    let body = bounded_web_search_response(response, "brave").await?;
    let response = serde_json::from_slice::<BraveResponse>(&body)
        .map_err(|error| AdminError::Probe(format!("decode brave response: {error}")))?;
    Ok(response
        .web
        .results
        .into_iter()
        .take(5)
        .map(|result| WebSearchResult {
            url: result.url,
            title: result.title,
            snippet: result.description,
            page_age: result.age,
        })
        .collect())
}

async fn search_tavily(
    client: &Client,
    api_key: &str,
    query: &str,
) -> Result<Vec<WebSearchResult>, AdminError> {
    let response = client
        .post("https://api.tavily.com/search")
        .json(&json!({
            "api_key": api_key,
            "query": query,
            "max_results": 5,
            "search_depth": "basic",
        }))
        .send()
        .await
        .map_err(|error| AdminError::Probe(format!("tavily search request failed: {error}")))?;
    let body = bounded_web_search_response(response, "tavily").await?;
    let response = serde_json::from_slice::<TavilyResponse>(&body)
        .map_err(|error| AdminError::Probe(format!("decode tavily response: {error}")))?;
    Ok(response
        .results
        .into_iter()
        .take(5)
        .map(|result| WebSearchResult {
            url: result.url,
            title: result.title,
            snippet: result.content,
            page_age: String::new(),
        })
        .collect())
}

async fn bounded_web_search_response(
    response: Response,
    provider: &str,
) -> Result<Vec<u8>, AdminError> {
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > MAX_WEB_SEARCH_RESPONSE_BYTES as u64)
    {
        return Err(AdminError::Probe(format!(
            "{provider} response exceeds {MAX_WEB_SEARCH_RESPONSE_BYTES} bytes"
        )));
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            AdminError::Probe(format!("read {provider} response failed: {error}"))
        })?;
        if body.len().saturating_add(chunk.len()) > MAX_WEB_SEARCH_RESPONSE_BYTES {
            return Err(AdminError::Probe(format!(
                "{provider} response exceeds {MAX_WEB_SEARCH_RESPONSE_BYTES} bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    if !status.is_success() {
        let detail = String::from_utf8_lossy(&body)
            .chars()
            .take(512)
            .collect::<String>();
        return Err(AdminError::Probe(format!(
            "{provider} returned HTTP {}: {detail}",
            status.as_u16()
        )));
    }
    Ok(body)
}

async fn read_setting(pool: &PgPool, key: &str) -> Result<Option<String>, AdminError> {
    sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key = $1")
        .bind(key)
        .fetch_optional(pool)
        .await
        .map_err(AdminError::from)
}

async fn read_json_or<T, F>(pool: &PgPool, key: &str, fallback: F) -> Result<T, AdminError>
where
    T: DeserializeOwned,
    F: FnOnce() -> T,
{
    let Some(raw) = read_setting(pool, key)
        .await?
        .filter(|raw| !raw.trim().is_empty())
    else {
        return Ok(fallback());
    };
    Ok(serde_json::from_str(&raw).unwrap_or_else(|_| fallback()))
}

async fn write_json_setting<T: Serialize + ?Sized>(
    pool: &PgPool,
    key: &str,
    value: &T,
) -> Result<(), AdminError> {
    let value = serde_json::to_string(value)
        .map_err(|error| AdminError::BadRequest(format!("serialize setting: {error}")))?;
    write_setting(pool, key, &value).await
}

async fn write_setting(pool: &PgPool, key: &str, value: &str) -> Result<(), AdminError> {
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, NOW()) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
    )
    .bind(key)
    .bind(value)
    .execute(&mut *transaction)
    .await?;
    notify_settings(&mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

async fn delete_setting(pool: &PgPool, key: &str) -> Result<(), AdminError> {
    let mut transaction = pool.begin().await?;
    sqlx::query("DELETE FROM settings WHERE key = $1")
        .bind(key)
        .execute(&mut *transaction)
        .await?;
    notify_settings(&mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

async fn notify_settings(transaction: &mut Transaction<'_, Postgres>) -> Result<(), AdminError> {
    sqlx::query("SELECT pg_notify($1, $2)")
        .bind(AUTH_INVALIDATION_CHANNEL)
        .bind(SETTINGS_INVALIDATION_PAYLOAD)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

fn from_payload<T: DeserializeOwned>(payload: Value) -> Result<T, AdminError> {
    if !payload.is_object() {
        return Err(AdminError::BadRequest(
            "request body must be a JSON object".to_owned(),
        ));
    }
    serde_json::from_value(payload)
        .map_err(|error| AdminError::BadRequest(format!("invalid request: {error}")))
}

fn to_json_value<T: Serialize + ?Sized>(value: &T) -> Result<Value, AdminError> {
    serde_json::to_value(value)
        .map_err(|error| AdminError::Probe(format!("serialize settings response: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_defaults_and_disabled_normalization_match_go_contract() {
        assert_eq!(
            OverloadCooldownSettings::production_default(),
            OverloadCooldownSettings {
                enabled: true,
                cooldown_minutes: 10,
            }
        );
        assert_eq!(
            OverloadCooldownSettings {
                enabled: false,
                cooldown_minutes: 0,
            }
            .validate_write()
            .unwrap()
            .cooldown_minutes,
            10
        );
        assert!(
            OverloadCooldownSettings {
                enabled: true,
                cooldown_minutes: 121,
            }
            .validate_write()
            .is_err()
        );
        assert_eq!(
            RateLimit429CooldownSettings {
                enabled: false,
                cooldown_seconds: 7_201,
            }
            .validate_write()
            .unwrap()
            .cooldown_seconds,
            5
        );

        let stream = StreamTimeoutSettings {
            action: "unknown".to_owned(),
            temp_unsched_minutes: -1,
            threshold_count: 99,
            threshold_window_minutes: 0,
            ..StreamTimeoutSettings::default()
        }
        .normalize_read();
        assert_eq!(stream.action, "temp_unsched");
        assert_eq!(stream.temp_unsched_minutes, 1);
        assert_eq!(stream.threshold_count, 10);
        assert_eq!(stream.threshold_window_minutes, 1);
    }

    #[test]
    fn beta_policy_validation_trims_models_and_rejects_invalid_values() {
        let settings = BetaPolicySettings {
            rules: vec![BetaPolicyRule {
                beta_token: " token ".to_owned(),
                action: "pass".to_owned(),
                scope: "oauth".to_owned(),
                model_whitelist: vec![" claude-* ".to_owned()],
                fallback_action: "filter".to_owned(),
                ..BetaPolicyRule::default()
            }],
        }
        .validate_write()
        .unwrap();
        assert_eq!(settings.rules[0].beta_token, "token");
        assert_eq!(settings.rules[0].model_whitelist, ["claude-*"]);

        let invalid = BetaPolicySettings {
            rules: vec![BetaPolicyRule {
                beta_token: "token".to_owned(),
                action: "drop".to_owned(),
                scope: "all".to_owned(),
                ..BetaPolicyRule::default()
            }],
        };
        assert!(invalid.validate_write().is_err());
        assert_eq!(BetaPolicySettings::production_default().rules.len(), 2);
    }

    #[test]
    fn email_templates_cover_every_event_locale_and_enforce_placeholders() {
        assert_eq!(EMAIL_EVENTS.len(), 13);
        for event in EMAIL_EVENTS {
            for locale in ["en", "zh"] {
                let template = official_email_template(event, locale);
                validate_email_template(event, &template.subject, &template.html).unwrap();
                assert_eq!(template.locale, locale);
                assert!(!template.placeholders.is_empty());
            }
        }

        let event = email_event("auth.verify_code").unwrap();
        let error = validate_email_template(event, "Verification", "<p>{{unsupported_value}}</p>")
            .unwrap_err();
        assert!(error.to_string().contains("unsupported placeholder"));
    }

    #[test]
    fn email_preview_escapes_values_except_scheduled_report_html() {
        let mut variables = sample_email_variables("en");
        variables.insert(
            "recipient_name".to_owned(),
            "<script>alert(1)</script>".to_owned(),
        );
        let verify = email_event("auth.verify_code").unwrap();
        assert_eq!(
            render_email_string(verify, "<p>{{recipient_name}}</p>", &variables, true),
            "<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>"
        );

        let report = email_event("ops.scheduled_report").unwrap();
        assert_eq!(
            render_email_string(report, "{{report_html}}", &variables, true),
            "<h2>Daily summary</h2><p>Requests: 1024</p>"
        );
    }

    #[test]
    fn web_search_preserves_existing_keys_and_never_returns_them() {
        let existing = WebSearchEmulationConfig {
            enabled: true,
            providers: vec![WebSearchProviderConfig {
                provider_type: "brave".to_owned(),
                api_key: "enc:v1:stored-ciphertext".to_owned(),
                ..WebSearchProviderConfig::default()
            }],
        };
        let mut incoming = WebSearchEmulationConfig {
            enabled: true,
            providers: vec![WebSearchProviderConfig {
                provider_type: "brave".to_owned(),
                api_key: "********".to_owned(),
                ..WebSearchProviderConfig::default()
            }],
        };
        preserve_web_search_api_keys(&mut incoming, &existing);
        assert_eq!(incoming.providers[0].api_key, "enc:v1:stored-ciphertext");

        let usage = HashMap::from([("brave".to_owned(), 17)]);
        sanitize_web_search_config(&mut incoming, &usage);
        assert!(incoming.providers[0].api_key.is_empty());
        assert!(incoming.providers[0].api_key_configured);
        assert_eq!(incoming.providers[0].quota_used, 17);
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL pointing to a disposable *_test PostgreSQL database"]
    async fn postgres_setting_writes_commit_before_cache_invalidation() {
        use sqlx::postgres::{PgListener, PgPoolOptions};
        use tokio::time::{Duration, timeout};

        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL must point to a disposable PostgreSQL database");
        let parsed = Url::parse(&database_url).expect("TEST_DATABASE_URL must be a URL");
        let database_name = parsed.path().trim_matches('/');
        assert!(
            database_name.ends_with("_test"),
            "refusing to mutate a database whose name does not end in _test"
        );

        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .unwrap();
        let mut listener = PgListener::connect(&database_url).await.unwrap();
        listener.listen(AUTH_INVALIDATION_CHANNEL).await.unwrap();
        let key = format!("compat_settings_test:{}", uuid::Uuid::new_v4());

        write_setting(&pool, &key, "committed").await.unwrap();
        let notification = timeout(Duration::from_secs(5), listener.recv())
            .await
            .expect("settings notification timed out")
            .unwrap();
        assert_eq!(notification.payload(), SETTINGS_INVALIDATION_PAYLOAD);
        assert_eq!(
            read_setting(&pool, &key).await.unwrap().as_deref(),
            Some("committed")
        );

        delete_setting(&pool, &key).await.unwrap();
        pool.close().await;
    }
}
