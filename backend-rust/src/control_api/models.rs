use std::{
    collections::{BTreeMap, HashMap, HashSet},
    hash::BuildHasher,
};

use async_trait::async_trait;
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Debug, Serialize)]
pub struct ApiEnvelope<T> {
    pub code: u16,
    pub message: &'static str,
    pub data: T,
}

impl<T> ApiEnvelope<T> {
    #[must_use]
    pub const fn success(data: T) -> Self {
        Self {
            code: 0,
            message: "success",
            data,
        }
    }
}

#[derive(Debug, Serialize)]
struct ErrorEnvelope<'a> {
    code: u16,
    message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: &'static str,
    reason: Option<&'static str>,
    internal: Option<String>,
}

impl ApiError {
    #[must_use]
    pub const fn bad_request(message: &'static str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message, None)
    }

    #[must_use]
    pub const fn unauthorized(message: &'static str) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message, None)
    }

    #[must_use]
    pub const fn forbidden(message: &'static str, reason: &'static str) -> Self {
        Self::new(StatusCode::FORBIDDEN, message, Some(reason))
    }

    #[must_use]
    pub const fn not_found(message: &'static str) -> Self {
        Self::new(StatusCode::NOT_FOUND, message, None)
    }

    #[must_use]
    pub const fn conflict(message: &'static str, reason: &'static str) -> Self {
        Self::new(StatusCode::CONFLICT, message, Some(reason))
    }

    #[must_use]
    pub const fn too_many_requests(message: &'static str) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, message, None)
    }

    #[must_use]
    pub fn database(error: &sqlx::Error) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "Service temporarily unavailable",
            reason: Some("DATABASE_ERROR"),
            internal: Some(error.to_string()),
        }
    }

    #[must_use]
    pub fn internal(context: &'static str, error: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "Internal server error",
            reason: Some("INTERNAL_ERROR"),
            internal: Some(format!("{context}: {error}")),
        }
    }

    const fn new(status: StatusCode, message: &'static str, reason: Option<&'static str>) -> Self {
        Self {
            status,
            message,
            reason,
            internal: None,
        }
    }

    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let Some(error) = &self.internal {
            tracing::error!(
                error,
                status = self.status.as_u16(),
                "control API request failed"
            );
        }
        let body = ErrorEnvelope {
            code: self.status.as_u16(),
            message: self.message,
            reason: self.reason,
        };
        (self.status, Json(body)).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        Self::database(&error)
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub turnstile_token: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub verify_code: String,
    #[serde(default)]
    pub turnstile_token: String,
    #[serde(default)]
    pub promo_code: String,
    #[serde(default)]
    pub invitation_code: String,
    #[serde(default)]
    pub aff_code: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ValidateCodeRequest {
    pub code: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct PromoCodeValidation {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bonus_amount: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<&'static str>,
}

impl PromoCodeValidation {
    #[must_use]
    pub const fn valid(bonus_amount: f64) -> Self {
        Self {
            valid: true,
            bonus_amount: Some(bonus_amount),
            error_code: None,
            message: None,
        }
    }

    #[must_use]
    pub const fn invalid(error_code: &'static str) -> Self {
        Self {
            valid: false,
            bonus_amount: None,
            error_code: Some(error_code),
            message: None,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct InvitationCodeValidation {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<&'static str>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct OAuthStartQuery {
    pub redirect: Option<String>,
    pub mode: Option<String>,
    pub promo_code: Option<String>,
    pub aff_code: Option<String>,
    pub aff: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct WechatPaymentOAuthStartQuery {
    pub payment_type: Option<String>,
    pub redirect: Option<String>,
    pub amount: Option<String>,
    pub order_type: Option<String>,
    pub plan_id: Option<i64>,
    pub scope: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CompleteWechatOAuthRequest {
    pub invitation_code: String,
    #[serde(default)]
    pub aff_code: String,
    pub adopt_display_name: Option<bool>,
    pub adopt_avatar: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct OAuthCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CompleteOAuthRegistrationRequest {
    pub password: String,
    #[serde(default)]
    pub invitation_code: String,
    #[serde(default)]
    pub aff_code: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PendingOAuthBindLoginRequest {
    pub email: String,
    pub password: String,
    pub adopt_display_name: Option<bool>,
    pub adopt_avatar: Option<bool>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PendingOAuthCreateAccountRequest {
    pub email: String,
    #[serde(default)]
    pub verify_code: String,
    pub password: String,
    #[serde(default)]
    pub invitation_code: String,
    #[serde(default)]
    pub aff_code: String,
    pub adopt_display_name: Option<bool>,
    pub adopt_avatar: Option<bool>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PendingOAuthSendVerifyCodeRequest {
    pub email: String,
    #[serde(default)]
    pub turnstile_token: String,
    #[serde(default)]
    pub pending_auth_token: String,
    #[serde(default)]
    pub pending_oauth_token: String,
}

#[derive(Clone, Debug)]
pub(crate) struct OAuthIdentityProfile {
    pub provider: String,
    pub provider_key: String,
    pub subject: String,
    pub issuer: Option<String>,
    pub email: String,
    pub username: String,
    pub display_name: String,
    pub avatar_url: String,
    pub metadata: Value,
}

#[derive(Clone, Debug)]
pub(crate) enum OAuthLoginOutcome {
    Auth(Box<AuthResponse>),
    RegistrationPending {
        session_token: String,
        browser_session_key: String,
        suggested_email: String,
    },
}

impl InvitationCodeValidation {
    #[must_use]
    pub const fn valid() -> Self {
        Self {
            valid: true,
            error_code: None,
        }
    }

    #[must_use]
    pub const fn invalid(error_code: &'static str) -> Self {
        Self {
            valid: false,
            error_code: Some(error_code),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct LogoutRequest {
    #[serde(default)]
    pub refresh_token: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ChangePasswordRequest {
    #[serde(alias = "current_password")]
    pub old_password: String,
    pub new_password: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
    #[serde(default)]
    pub turnstile_token: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ResetPasswordRequest {
    pub email: String,
    pub token: String,
    pub new_password: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SendVerificationCodeRequest {
    pub email: String,
    #[serde(default)]
    pub turnstile_token: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Login2faRequest {
    pub temp_token: String,
    pub totp_code: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TotpSetupRequest {
    #[serde(default)]
    pub email_code: String,
    #[serde(default)]
    pub password: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TotpEnableRequest {
    pub totp_code: String,
    pub setup_token: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TotpDisableRequest {
    #[serde(default)]
    pub email_code: String,
    #[serde(default)]
    pub password: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub token_type: &'static str,
    pub user: UserView,
}

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum LoginResponse {
    Auth(Box<AuthResponse>),
    Totp(TotpLoginChallenge),
}

#[derive(Clone, Debug, Serialize)]
pub struct TotpLoginChallenge {
    pub requires_2fa: bool,
    pub temp_token: String,
    pub user_email_masked: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct RefreshResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub token_type: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct MessageResponse {
    pub message: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct SendVerificationCodeResponse {
    pub message: &'static str,
    pub countdown: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct TotpStatus {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled_at: Option<String>,
    pub feature_enabled: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct TotpSetupResponse {
    pub secret: String,
    pub qr_code_url: String,
    pub setup_token: String,
    pub countdown: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct TotpVerificationMethod {
    pub method: &'static str,
    pub email_verify_enabled: bool,
}

#[async_trait]
pub trait AuthNotifier: Send + Sync {
    async fn send_verification_code(&self, email: &str, code: &str) -> Result<(), String>;
    async fn send_password_reset(&self, email: &str, token: &str) -> Result<(), String>;
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NotifyEmailEntry {
    pub email: String,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub verified: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct UserView {
    pub id: i64,
    pub email: String,
    pub username: String,
    pub role: String,
    pub balance: f64,
    pub frozen_balance: f64,
    pub concurrency: i32,
    pub status: String,
    pub allowed_groups: Vec<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_active_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub balance_notify_enabled: bool,
    pub balance_notify_threshold_type: String,
    pub balance_notify_threshold: Option<f64>,
    pub balance_notify_extra_emails: Vec<NotifyEmailEntry>,
    pub total_recharged: f64,
    pub rpm_limit: i32,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct IdentitySummary {
    pub provider: String,
    pub bound: bool,
    pub bound_count: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub display_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub subject_hint: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub provider_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub bind_start_path: String,
    pub can_bind: bool,
    pub can_unbind: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct IdentitySummarySet {
    pub email: IdentitySummary,
    pub linuxdo: IdentitySummary,
    pub oidc: IdentitySummary,
    pub wechat: IdentitySummary,
    pub dingtalk: IdentitySummary,
}

impl IdentitySummarySet {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            email: unbound_identity("email"),
            linuxdo: unbound_identity("linuxdo"),
            oidc: unbound_identity("oidc"),
            wechat: unbound_identity("wechat"),
            dingtalk: unbound_identity("dingtalk"),
        }
    }

    #[must_use]
    pub fn bindings(&self) -> BTreeMap<String, IdentitySummary> {
        [
            ("email", &self.email),
            ("linuxdo", &self.linuxdo),
            ("oidc", &self.oidc),
            ("wechat", &self.wechat),
            ("dingtalk", &self.dingtalk),
        ]
        .into_iter()
        .filter(|(_, summary)| summary.bound)
        .map(|(provider, summary)| (provider.to_owned(), summary.clone()))
        .collect()
    }
}

fn unbound_identity(provider: &str) -> IdentitySummary {
    IdentitySummary {
        provider: provider.to_owned(),
        can_bind: true,
        bind_start_path: format!("/api/v1/auth/{provider}/authorize"),
        ..IdentitySummary::default()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct UserProfile {
    #[serde(flatten)]
    pub user: UserView,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub avatar_url: String,
    pub identities: IdentitySummarySet,
    pub auth_bindings: BTreeMap<String, IdentitySummary>,
    pub identity_bindings: BTreeMap<String, IdentitySummary>,
    pub email_bound: bool,
    pub linuxdo_bound: bool,
    pub oidc_bound: bool,
    pub wechat_bound: bool,
    pub dingtalk_bound: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct CurrentUser {
    #[serde(flatten)]
    pub profile: UserProfile,
    pub run_mode: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct UpdateProfileRequest {
    pub username: Option<String>,
    pub avatar_url: Option<String>,
    pub balance_notify_enabled: Option<bool>,
    pub balance_notify_threshold: Option<f64>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ApiKeyListQuery {
    pub page: Option<u32>,
    pub page_size: Option<u32>,
    pub limit: Option<u32>,
    pub search: Option<String>,
    pub status: Option<String>,
    pub group_id: Option<i64>,
    pub sort_by: Option<String>,
    pub sort_order: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pagination {
    pub page: u32,
    pub page_size: u32,
    pub offset: i64,
}

impl ApiKeyListQuery {
    #[must_use]
    pub fn pagination(&self) -> Pagination {
        let page = self.page.unwrap_or(1).max(1);
        let page_size = self.page_size.or(self.limit).unwrap_or(20).clamp(1, 1_000);
        Pagination {
            page,
            page_size,
            offset: i64::from(page.saturating_sub(1)) * i64::from(page_size),
        }
    }

    #[must_use]
    pub fn order_by(&self) -> (&'static str, &'static str) {
        let field = match self.sort_by.as_deref() {
            Some("name") => "name",
            Some("status") => "status",
            Some("updated_at") => "updated_at",
            _ => "created_at",
        };
        let direction = if self
            .sort_order
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case("asc"))
        {
            "ASC"
        } else {
            "DESC"
        };
        (field, direction)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Paginated<T> {
    pub items: Vec<T>,
    pub total: i64,
    pub page: u32,
    pub page_size: u32,
    pub pages: u32,
}

impl<T> Paginated<T> {
    #[must_use]
    pub fn new(items: Vec<T>, total: i64, pagination: Pagination) -> Self {
        let total = total.max(0);
        let page_size = i64::from(pagination.page_size);
        let pages = ((total + page_size - 1) / page_size).max(1);
        Self {
            items,
            total,
            page: pagination.page,
            page_size: pagination.page_size,
            pages: u32::try_from(pages).unwrap_or(u32::MAX),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ApiKeyView {
    pub id: i64,
    pub user_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    pub name: String,
    pub group_id: Option<i64>,
    pub status: String,
    pub ip_whitelist: Vec<String>,
    pub ip_blacklist: Vec<String>,
    pub last_used_at: Option<String>,
    pub last_used_ip: Option<String>,
    pub quota: f64,
    pub quota_used: f64,
    pub expires_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub current_concurrency: i32,
    pub rate_limit_5h: f64,
    pub rate_limit_1d: f64,
    pub rate_limit_7d: f64,
    pub usage_5h: f64,
    pub usage_1d: f64,
    pub usage_7d: f64,
    pub window_5h_start: Option<String>,
    pub window_1d_start: Option<String>,
    pub window_7d_start: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reset_5h_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reset_1d_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reset_7d_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub group_id: Option<i64>,
    pub custom_key: Option<String>,
    #[serde(default)]
    pub ip_whitelist: Vec<String>,
    #[serde(default)]
    pub ip_blacklist: Vec<String>,
    pub quota: Option<f64>,
    pub expires_in_days: Option<i32>,
    pub rate_limit_5h: Option<f64>,
    pub rate_limit_1d: Option<f64>,
    pub rate_limit_7d: Option<f64>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct UpdateApiKeyRequest {
    pub id: Option<i64>,
    pub name: Option<String>,
    pub group_id: Option<i64>,
    pub status: Option<String>,
    pub ip_whitelist: Option<Vec<String>>,
    pub ip_blacklist: Option<Vec<String>>,
    pub quota: Option<f64>,
    pub expires_at: Option<String>,
    pub reset_quota: Option<bool>,
    pub rate_limit_5h: Option<f64>,
    pub rate_limit_1d: Option<f64>,
    pub rate_limit_7d: Option<f64>,
    pub reset_rate_limit_usage: Option<bool>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
pub struct ResourceIdQuery {
    pub id: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeleteMessage {
    pub message: &'static str,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LoginAgreementDocument {
    pub id: String,
    pub title: String,
    pub content_md: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CustomMenuItem {
    pub id: String,
    pub label: String,
    pub icon_svg: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub page_slug: String,
    pub visibility: String,
    pub sort_order: i32,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CustomEndpoint {
    pub name: String,
    pub endpoint: String,
    pub description: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct PublicSettings {
    pub registration_enabled: bool,
    pub email_verify_enabled: bool,
    pub force_email_on_third_party_signup: bool,
    pub registration_email_suffix_whitelist: Vec<String>,
    pub promo_code_enabled: bool,
    pub password_reset_enabled: bool,
    pub invitation_code_enabled: bool,
    pub totp_enabled: bool,
    pub login_agreement_enabled: bool,
    pub login_agreement_mode: String,
    pub login_agreement_updated_at: String,
    pub login_agreement_revision: String,
    pub login_agreement_documents: Vec<LoginAgreementDocument>,
    pub turnstile_enabled: bool,
    pub turnstile_site_key: String,
    pub site_name: String,
    pub site_logo: String,
    pub site_subtitle: String,
    pub api_base_url: String,
    pub contact_info: String,
    pub doc_url: String,
    pub home_content: String,
    pub hide_ccs_import_button: bool,
    pub purchase_subscription_enabled: bool,
    pub purchase_subscription_url: String,
    pub table_default_page_size: i32,
    pub table_page_size_options: Vec<i32>,
    pub custom_menu_items: Vec<CustomMenuItem>,
    pub custom_endpoints: Vec<CustomEndpoint>,
    pub dingtalk_oauth_enabled: bool,
    pub linuxdo_oauth_enabled: bool,
    pub wechat_oauth_enabled: bool,
    pub wechat_oauth_open_enabled: bool,
    pub wechat_oauth_mp_enabled: bool,
    pub wechat_oauth_mobile_enabled: bool,
    pub oidc_oauth_enabled: bool,
    pub oidc_oauth_provider_name: String,
    pub github_oauth_enabled: bool,
    pub google_oauth_enabled: bool,
    pub sora_client_enabled: bool,
    pub backend_mode_enabled: bool,
    pub payment_enabled: bool,
    pub version: String,
    pub server_timezone: String,
    pub server_utc_offset: String,
    pub balance_low_notify_enabled: bool,
    pub account_quota_notify_enabled: bool,
    pub balance_low_notify_threshold: f64,
    pub balance_low_notify_recharge_url: String,
    pub channel_monitor_enabled: bool,
    pub channel_monitor_default_interval_seconds: i32,
    pub available_channels_enabled: bool,
    pub affiliate_enabled: bool,
    pub risk_control_enabled: bool,
    pub allow_user_view_error_requests: bool,
}

#[derive(Clone, Debug)]
pub struct PublicRuntimeInfo {
    pub version: String,
    pub server_timezone: String,
    pub server_utc_offset: String,
}

pub const PUBLIC_SETTING_KEYS: &[&str] = &[
    "registration_enabled",
    "email_verify_enabled",
    "force_email_on_third_party_signup",
    "registration_email_suffix_whitelist",
    "promo_code_enabled",
    "password_reset_enabled",
    "invitation_code_enabled",
    "totp_enabled",
    "login_agreement_enabled",
    "login_agreement_mode",
    "login_agreement_updated_at",
    "login_agreement_documents",
    "turnstile_enabled",
    "turnstile_site_key",
    "site_name",
    "site_logo",
    "site_subtitle",
    "api_base_url",
    "contact_info",
    "doc_url",
    "home_content",
    "hide_ccs_import_button",
    "purchase_subscription_enabled",
    "purchase_subscription_url",
    "table_default_page_size",
    "table_page_size_options",
    "custom_menu_items",
    "custom_endpoints",
    "dingtalk_connect_enabled",
    "linuxdo_connect_enabled",
    "wechat_connect_enabled",
    "wechat_connect_open_enabled",
    "wechat_connect_mp_enabled",
    "wechat_connect_mobile_enabled",
    "oidc_connect_enabled",
    "oidc_connect_provider_name",
    "github_oauth_enabled",
    "google_oauth_enabled",
    "backend_mode_enabled",
    "payment_enabled",
    "balance_low_notify_enabled",
    "account_quota_notify_enabled",
    "balance_low_notify_threshold",
    "balance_low_notify_recharge_url",
    "channel_monitor_enabled",
    "channel_monitor_default_interval_seconds",
    "available_channels_enabled",
    "affiliate_enabled",
    "risk_control_enabled",
    "allow_user_view_error_requests",
];

#[must_use]
pub fn public_settings_from_values<S>(
    values: &HashMap<String, String, S>,
    runtime: &PublicRuntimeInfo,
) -> PublicSettings
where
    S: BuildHasher,
{
    let email_verify_enabled = setting_bool(values, "email_verify_enabled");
    let documents = parse_agreement_documents(value(values, "login_agreement_documents"));
    let updated_at = non_empty(values, "login_agreement_updated_at", "2026-03-31");
    let revision = agreement_revision(&updated_at, &documents);
    let table_default_page_size = value(values, "table_default_page_size")
        .trim()
        .parse::<i32>()
        .ok()
        .filter(|size| (5..=1_000).contains(size))
        .unwrap_or(20);
    let mut table_page_size_options =
        parse_json::<Vec<i32>>(value(values, "table_page_size_options"))
            .unwrap_or_else(|| vec![10, 20, 50]);
    table_page_size_options.retain(|size| (5..=1_000).contains(size));
    table_page_size_options.sort_unstable();
    table_page_size_options.dedup();
    if table_page_size_options.is_empty() {
        table_page_size_options = vec![10, 20, 50];
    }
    let custom_menu_items = parse_json::<Vec<CustomMenuItem>>(value(values, "custom_menu_items"))
        .unwrap_or_default()
        .into_iter()
        .filter(|item| item.visibility != "admin")
        .collect();
    let channel_interval = value(values, "channel_monitor_default_interval_seconds")
        .trim()
        .parse::<i32>()
        .unwrap_or(60)
        .clamp(15, 3_600);

    PublicSettings {
        registration_enabled: setting_bool(values, "registration_enabled"),
        email_verify_enabled,
        force_email_on_third_party_signup: setting_bool(
            values,
            "force_email_on_third_party_signup",
        ),
        registration_email_suffix_whitelist: parse_string_list(value(
            values,
            "registration_email_suffix_whitelist",
        )),
        promo_code_enabled: value(values, "promo_code_enabled") != "false",
        password_reset_enabled: email_verify_enabled
            && setting_bool(values, "password_reset_enabled"),
        invitation_code_enabled: setting_bool(values, "invitation_code_enabled"),
        totp_enabled: setting_bool(values, "totp_enabled"),
        login_agreement_enabled: setting_bool(values, "login_agreement_enabled"),
        login_agreement_mode: if value(values, "login_agreement_mode")
            .trim()
            .eq_ignore_ascii_case("checkbox")
        {
            "checkbox".to_owned()
        } else {
            "modal".to_owned()
        },
        login_agreement_updated_at: updated_at,
        login_agreement_revision: revision,
        login_agreement_documents: documents,
        turnstile_enabled: setting_bool(values, "turnstile_enabled"),
        turnstile_site_key: value(values, "turnstile_site_key").to_owned(),
        site_name: non_empty(values, "site_name", "Sub2API"),
        site_logo: value(values, "site_logo").to_owned(),
        site_subtitle: non_empty(
            values,
            "site_subtitle",
            "Subscription to API Conversion Platform",
        ),
        api_base_url: value(values, "api_base_url").to_owned(),
        contact_info: value(values, "contact_info").to_owned(),
        doc_url: value(values, "doc_url").to_owned(),
        home_content: value(values, "home_content").to_owned(),
        hide_ccs_import_button: setting_bool(values, "hide_ccs_import_button"),
        purchase_subscription_enabled: setting_bool(values, "purchase_subscription_enabled"),
        purchase_subscription_url: value(values, "purchase_subscription_url").trim().to_owned(),
        table_default_page_size,
        table_page_size_options,
        custom_menu_items,
        custom_endpoints: parse_json(value(values, "custom_endpoints")).unwrap_or_default(),
        dingtalk_oauth_enabled: setting_bool(values, "dingtalk_connect_enabled"),
        linuxdo_oauth_enabled: setting_bool(values, "linuxdo_connect_enabled"),
        wechat_oauth_enabled: setting_bool(values, "wechat_connect_enabled"),
        wechat_oauth_open_enabled: setting_bool(values, "wechat_connect_open_enabled"),
        wechat_oauth_mp_enabled: setting_bool(values, "wechat_connect_mp_enabled"),
        wechat_oauth_mobile_enabled: setting_bool(values, "wechat_connect_mobile_enabled"),
        oidc_oauth_enabled: setting_bool(values, "oidc_connect_enabled"),
        oidc_oauth_provider_name: non_empty(values, "oidc_connect_provider_name", "OIDC"),
        github_oauth_enabled: setting_bool(values, "github_oauth_enabled"),
        google_oauth_enabled: setting_bool(values, "google_oauth_enabled"),
        sora_client_enabled: false,
        backend_mode_enabled: setting_bool(values, "backend_mode_enabled"),
        payment_enabled: setting_bool(values, "payment_enabled"),
        version: runtime.version.clone(),
        server_timezone: runtime.server_timezone.clone(),
        server_utc_offset: runtime.server_utc_offset.clone(),
        balance_low_notify_enabled: setting_bool(values, "balance_low_notify_enabled"),
        account_quota_notify_enabled: setting_bool(values, "account_quota_notify_enabled"),
        balance_low_notify_threshold: value(values, "balance_low_notify_threshold")
            .trim()
            .parse::<f64>()
            .ok()
            .filter(|threshold| threshold.is_finite() && *threshold >= 0.0)
            .unwrap_or(0.0),
        balance_low_notify_recharge_url: value(values, "balance_low_notify_recharge_url")
            .to_owned(),
        channel_monitor_enabled: !setting_is_false(values, "channel_monitor_enabled"),
        channel_monitor_default_interval_seconds: channel_interval,
        available_channels_enabled: setting_bool(values, "available_channels_enabled"),
        affiliate_enabled: setting_bool(values, "affiliate_enabled"),
        risk_control_enabled: setting_bool(values, "risk_control_enabled"),
        allow_user_view_error_requests: setting_bool(values, "allow_user_view_error_requests"),
    }
}

fn value<'a, S>(values: &'a HashMap<String, String, S>, key: &str) -> &'a str
where
    S: BuildHasher,
{
    values.get(key).map_or("", String::as_str)
}

fn setting_bool<S>(values: &HashMap<String, String, S>, key: &str) -> bool
where
    S: BuildHasher,
{
    value(values, key).trim().eq_ignore_ascii_case("true")
}

fn setting_is_false<S>(values: &HashMap<String, String, S>, key: &str) -> bool
where
    S: BuildHasher,
{
    matches!(
        value(values, key).trim().to_ascii_lowercase().as_str(),
        "false" | "0" | "off" | "disabled"
    )
}

fn non_empty<S>(values: &HashMap<String, String, S>, key: &str, fallback: &str) -> String
where
    S: BuildHasher,
{
    let value = value(values, key).trim();
    if value.is_empty() {
        fallback.to_owned()
    } else {
        value.to_owned()
    }
}

fn parse_json<T>(raw: &str) -> Option<T>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_str(raw.trim()).ok()
}

fn parse_string_list(raw: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    parse_json::<Vec<Value>>(raw)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| value.as_str().map(str::trim).map(str::to_lowercase))
        .filter_map(|value| normalize_email_suffix(&value))
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

fn normalize_email_suffix(raw: &str) -> Option<String> {
    let raw = raw.trim().to_ascii_lowercase();
    if raw.is_empty() {
        return None;
    }
    if let Some(domain) = raw.strip_prefix("*.") {
        return valid_email_domain(domain).then(|| format!("*.{domain}"));
    }
    let domain = if raw.contains('@') {
        if raw.matches('@').count() != 1 {
            return None;
        }
        raw.strip_prefix('@')?
    } else {
        raw.as_str()
    };
    valid_email_domain(domain).then(|| format!("@{domain}"))
}

fn valid_email_domain(domain: &str) -> bool {
    let labels = domain.split('.').collect::<Vec<_>>();
    labels.len() >= 2
        && labels.iter().all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric())
                && label
                    .bytes()
                    .last()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric())
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn parse_agreement_documents(raw: &str) -> Vec<LoginAgreementDocument> {
    let documents = parse_json::<Vec<LoginAgreementDocument>>(raw)
        .map(normalize_agreement_documents)
        .unwrap_or_default();
    if documents.is_empty() {
        default_agreement_documents()
    } else {
        documents
    }
}

fn normalize_agreement_documents(
    documents: Vec<LoginAgreementDocument>,
) -> Vec<LoginAgreementDocument> {
    let mut seen = HashSet::new();
    documents
        .into_iter()
        .enumerate()
        .filter_map(|(index, document)| {
            let title = document.title.trim().to_owned();
            let content_md = document.content_md.trim().to_owned();
            if title.is_empty() && content_md.is_empty() {
                return None;
            }
            let mut id = normalize_agreement_id(&document.id);
            if id.is_empty() {
                let digest = Sha256::digest(format!("{index}:{title}:{content_md}").as_bytes());
                hex::encode(digest)[..12].clone_into(&mut id);
            }
            let base_id = id.clone();
            let mut suffix = 2;
            while !seen.insert(id.clone()) {
                id = format!("{base_id}-{suffix}");
                suffix += 1;
            }
            Some(LoginAgreementDocument {
                id,
                title,
                content_md,
            })
        })
        .collect()
}

fn normalize_agreement_id(raw: &str) -> String {
    let mut normalized = String::new();
    let mut last_was_separator = false;
    for character in raw.trim().to_ascii_lowercase().chars() {
        if character.is_ascii_lowercase() || character.is_ascii_digit() {
            normalized.push(character);
            last_was_separator = false;
        } else if matches!(character, '-' | '_' | ' ' | '.' | '/')
            && !last_was_separator
            && !normalized.is_empty()
        {
            normalized.push(if character == '_' { '_' } else { '-' });
            last_was_separator = true;
        }
    }
    normalized.trim_matches(['-', '_']).to_owned()
}

fn default_agreement_documents() -> Vec<LoginAgreementDocument> {
    [
        ("terms", "\u{670d}\u{52a1}\u{6761}\u{6b3e}"),
        ("usage-policy", "\u{4f7f}\u{7528}\u{653f}\u{7b56}"),
        (
            "supported-regions",
            "\u{652f}\u{6301}\u{7684}\u{56fd}\u{5bb6}\u{548c}\u{5730}\u{533a}",
        ),
        (
            "service-specific-terms",
            "\u{670d}\u{52a1}\u{7279}\u{5b9a}\u{6761}\u{6b3e}",
        ),
    ]
    .into_iter()
    .map(|(id, title)| LoginAgreementDocument {
        id: id.to_owned(),
        title: title.to_owned(),
        content_md: String::new(),
    })
    .collect()
}

fn agreement_revision(updated_at: &str, documents: &[LoginAgreementDocument]) -> String {
    #[derive(Serialize)]
    struct Revision<'a> {
        updated_at: &'a str,
        documents: &'a [LoginAgreementDocument],
    }

    let payload = serde_json::to_vec(&Revision {
        updated_at,
        documents,
    })
    .unwrap_or_else(|_| updated_at.as_bytes().to_vec());
    let digest = Sha256::digest(payload);
    hex::encode(digest)[..16].to_owned()
}
