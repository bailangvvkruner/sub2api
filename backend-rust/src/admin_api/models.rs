#![allow(clippy::missing_errors_doc)]

use std::{collections::BTreeMap, error::Error, fmt, net::SocketAddr};

use async_trait::async_trait;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct AdminClaims {
    pub user_id: i64,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub token_version: i64,
    #[serde(default)]
    pub exp: Option<i64>,
    #[serde(default)]
    pub nbf: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminIdentity {
    pub user_id: i64,
    pub email: String,
}

pub trait PasswordHasher: Send + Sync {
    fn hash_password(&self, password: &str) -> Result<String, String>;
}

#[derive(Clone, Debug, Default, PartialEq)]
pub enum Patch<T> {
    #[default]
    Missing,
    Null,
    Value(T),
}

impl<'de, T> Deserialize<'de> for Patch<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<T>::deserialize(deserializer).map(|value| match value {
            Some(value) => Self::Value(value),
            None => Self::Null,
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct PageQuery {
    #[serde(default = "default_page")]
    pub page: i64,
    #[serde(default = "default_page_size")]
    pub page_size: i64,
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub platform: Option<String>,
}

const fn default_page() -> i64 {
    1
}

const fn default_page_size() -> i64 {
    20
}

impl PageQuery {
    #[must_use]
    pub fn normalized(mut self) -> Self {
        self.page = self.page.max(1);
        self.page_size = self.page_size.clamp(1, 1_000);
        self.search = self
            .search
            .take()
            .map(|value| value.trim().chars().take(100).collect())
            .filter(|value: &String| !value.is_empty());
        self.status = trim_option(self.status);
        self.role = trim_option(self.role);
        self.platform = trim_option(self.platform);
        self
    }

    #[must_use]
    pub const fn offset(&self) -> i64 {
        (self.page - 1) * self.page_size
    }
}

fn trim_option(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug, Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
    pub pages: i64,
}

impl<T> Page<T> {
    #[must_use]
    pub fn new(items: Vec<T>, total: i64, query: &PageQuery) -> Self {
        let pages = ((total + query.page_size - 1) / query.page_size).max(1);
        Self {
            items,
            total,
            page: query.page,
            page_size: query.page_size,
            pages,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct InvalidationKey(pub String);

#[derive(Clone, Debug)]
pub struct Mutation<T> {
    pub value: T,
    pub invalidation_keys: Vec<InvalidationKey>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default = "default_user_role")]
    pub role: String,
    #[serde(default)]
    pub balance: f64,
    #[serde(default = "default_user_concurrency")]
    pub concurrency: i32,
    #[serde(default)]
    pub rpm_limit: i32,
    #[serde(default)]
    pub allowed_groups: Vec<i64>,
}

fn default_user_role() -> String {
    "user".to_owned()
}

const fn default_user_concurrency() -> i32 {
    5
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct UpdateUserRequest {
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub balance: Option<f64>,
    #[serde(default)]
    pub concurrency: Option<i32>,
    #[serde(default)]
    pub rpm_limit: Option<i32>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub allowed_groups: Option<Vec<i64>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct UserView {
    pub id: i64,
    pub email: String,
    pub username: String,
    pub notes: String,
    pub role: String,
    pub balance: f64,
    pub concurrency: i32,
    pub rpm_limit: i32,
    pub status: String,
    pub allowed_groups: Vec<i64>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_platform")]
    pub platform: String,
    #[serde(default = "default_rate")]
    pub rate_multiplier: f64,
    #[serde(default)]
    pub is_exclusive: bool,
    #[serde(default = "default_subscription_type")]
    pub subscription_type: String,
    #[serde(default)]
    pub rpm_limit: i32,
}

fn default_platform() -> String {
    "anthropic".to_owned()
}

const fn default_rate() -> f64 {
    1.0
}

fn default_subscription_type() -> String {
    "standard".to_owned()
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct UpdateGroupRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub platform: Option<String>,
    #[serde(default)]
    pub rate_multiplier: Option<f64>,
    #[serde(default)]
    pub is_exclusive: Option<bool>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub subscription_type: Option<String>,
    #[serde(default)]
    pub rpm_limit: Option<i32>,
}

#[derive(Clone, Debug, Serialize)]
pub struct GroupView {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub platform: String,
    pub rate_multiplier: f64,
    pub is_exclusive: bool,
    pub status: String,
    pub subscription_type: String,
    pub rpm_limit: i32,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CreateAccountRequest {
    pub name: String,
    #[serde(default)]
    pub notes: Option<String>,
    pub platform: String,
    #[serde(rename = "type")]
    pub account_type: String,
    pub credentials: Value,
    #[serde(default = "empty_object")]
    pub extra: Value,
    #[serde(default)]
    pub proxy_id: Option<i64>,
    #[serde(default = "default_account_concurrency")]
    pub concurrency: i32,
    #[serde(default = "default_priority")]
    pub priority: i32,
    #[serde(default = "default_rate")]
    pub rate_multiplier: f64,
    #[serde(default)]
    pub load_factor: Option<i32>,
    #[serde(default)]
    pub group_ids: Vec<i64>,
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(default = "default_true")]
    pub auto_pause_on_expired: bool,
}

fn empty_object() -> Value {
    Value::Object(serde_json::Map::new())
}

const fn default_account_concurrency() -> i32 {
    3
}

const fn default_priority() -> i32 {
    50
}

const fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct UpdateAccountRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub notes: Patch<String>,
    #[serde(default, rename = "type")]
    pub account_type: Option<String>,
    #[serde(default)]
    pub credentials: Option<Value>,
    #[serde(default)]
    pub extra: Option<Value>,
    #[serde(default)]
    pub proxy_id: Patch<i64>,
    #[serde(default)]
    pub concurrency: Option<i32>,
    #[serde(default)]
    pub priority: Option<i32>,
    #[serde(default)]
    pub rate_multiplier: Option<f64>,
    #[serde(default)]
    pub load_factor: Patch<i32>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub schedulable: Option<bool>,
    #[serde(default)]
    pub group_ids: Option<Vec<i64>>,
    #[serde(default)]
    pub expires_at: Patch<i64>,
    #[serde(default)]
    pub auto_pause_on_expired: Option<bool>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AccountView {
    pub id: i64,
    pub name: String,
    pub notes: Option<String>,
    pub platform: String,
    #[serde(rename = "type")]
    pub account_type: String,
    pub credentials: Value,
    pub credentials_status: BTreeMap<String, bool>,
    pub extra: Value,
    pub proxy_id: Option<i64>,
    pub concurrency: i32,
    pub priority: i32,
    pub rate_multiplier: f64,
    pub load_factor: Option<i32>,
    pub status: String,
    pub schedulable: bool,
    pub group_ids: Vec<i64>,
    pub expires_at: Option<i64>,
    pub auto_pause_on_expired: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CreateProxyRequest {
    pub name: String,
    pub protocol: String,
    pub host: String,
    pub port: i32,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(default = "default_fallback_mode")]
    pub fallback_mode: String,
    #[serde(default)]
    pub backup_proxy_id: Option<i64>,
    #[serde(default = "default_expiry_warning")]
    pub expiry_warn_days: i32,
}

fn default_fallback_mode() -> String {
    "none".to_owned()
}

const fn default_expiry_warning() -> i32 {
    7
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct UpdateProxyRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub port: Option<i32>,
    #[serde(default)]
    pub username: Patch<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub expires_at: Patch<i64>,
    #[serde(default)]
    pub fallback_mode: Option<String>,
    #[serde(default)]
    pub backup_proxy_id: Patch<i64>,
    #[serde(default)]
    pub expiry_warn_days: Option<i32>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProxyView {
    pub id: i64,
    pub name: String,
    pub protocol: String,
    pub host: String,
    pub port: i32,
    pub username: Option<String>,
    pub has_password: bool,
    pub status: String,
    pub expires_at: Option<i64>,
    pub fallback_mode: String,
    pub backup_proxy_id: Option<i64>,
    pub expiry_warn_days: i32,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    pub user_id: i64,
    pub name: String,
    #[serde(default)]
    pub group_id: Option<i64>,
    #[serde(default)]
    pub custom_key: Option<String>,
    #[serde(default)]
    pub ip_whitelist: Vec<String>,
    #[serde(default)]
    pub ip_blacklist: Vec<String>,
    #[serde(default)]
    pub quota: f64,
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub rate_limit_5h: f64,
    #[serde(default)]
    pub rate_limit_1d: f64,
    #[serde(default)]
    pub rate_limit_7d: f64,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct UpdateApiKeyRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub group_id: Patch<i64>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub ip_whitelist: Option<Vec<String>>,
    #[serde(default)]
    pub ip_blacklist: Option<Vec<String>>,
    #[serde(default)]
    pub quota: Option<f64>,
    #[serde(default)]
    pub reset_quota: bool,
    #[serde(default)]
    pub expires_at: Patch<i64>,
    #[serde(default)]
    pub rate_limit_5h: Option<f64>,
    #[serde(default)]
    pub rate_limit_1d: Option<f64>,
    #[serde(default)]
    pub rate_limit_7d: Option<f64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ApiKeyView {
    pub id: i64,
    pub user_id: i64,
    pub key: String,
    pub name: String,
    pub group_id: Option<i64>,
    pub status: String,
    pub ip_whitelist: Vec<String>,
    pub ip_blacklist: Vec<String>,
    pub quota: f64,
    pub quota_used: f64,
    pub expires_at: Option<i64>,
    pub rate_limit_5h: f64,
    pub rate_limit_1d: f64,
    pub rate_limit_7d: f64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct SettingPatchRequest {
    #[serde(default, flatten)]
    pub values: BTreeMap<String, Value>,
}

#[derive(Clone)]
pub struct ProbeAccount {
    pub id: i64,
    pub platform: String,
    pub account_type: String,
    pub credentials: Value,
    pub extra: Value,
}

impl fmt::Debug for ProbeAccount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProbeAccount")
            .field("id", &self.id)
            .field("platform", &self.platform)
            .field("account_type", &self.account_type)
            .field("credentials", &"[redacted]")
            .field("extra", &"[redacted]")
            .finish()
    }
}

#[derive(Clone)]
pub struct ValidatedProbeTarget {
    url: String,
    resolved: Vec<SocketAddr>,
}

impl ValidatedProbeTarget {
    pub(crate) fn new(url: String, resolved: Vec<SocketAddr>) -> Self {
        Self { url, resolved }
    }

    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    #[must_use]
    pub fn resolved_addresses(&self) -> &[SocketAddr] {
        &self.resolved
    }
}

impl fmt::Debug for ValidatedProbeTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedProbeTarget")
            .field("url", &"[redacted]")
            .field("resolved_address_count", &self.resolved.len())
            .finish()
    }
}

#[derive(Clone)]
pub struct ProbeProxy {
    protocol: String,
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    validated_target: ValidatedProbeTarget,
}

impl ProbeProxy {
    pub(crate) fn new(
        protocol: String,
        host: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
        validated_target: ValidatedProbeTarget,
    ) -> Self {
        Self {
            protocol,
            host,
            port,
            username,
            password,
            validated_target,
        }
    }

    #[must_use]
    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    #[must_use]
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    #[must_use]
    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    #[must_use]
    pub const fn validated_target(&self) -> &ValidatedProbeTarget {
        &self.validated_target
    }
}

impl fmt::Debug for ProbeProxy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProbeProxy")
            .field("protocol", &self.protocol)
            .field("host", &"[redacted]")
            .field("port", &self.port)
            .field("username", &self.username.as_ref().map(|_| "[redacted]"))
            .field("password", &self.password.as_ref().map(|_| "[redacted]"))
            .field("validated_target", &self.validated_target)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct ProbeRequest {
    pub account: ProbeAccount,
    pub validated_targets: Vec<ValidatedProbeTarget>,
    pub proxy: Option<ProbeProxy>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProbeResult {
    pub success: bool,
    pub message: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, Value>,
}

#[async_trait]
pub trait AccountProbe: Send + Sync {
    /// Implementations must connect only to `validated_targets` addresses and
    /// retain the original URL host for HTTP Host/TLS SNI verification. HTTP
    /// redirects must be disabled or passed through the same validation again.
    async fn probe(&self, request: ProbeRequest) -> Result<ProbeResult, String>;
}

#[derive(Debug)]
pub enum AdminError {
    BadRequest(String),
    Conflict(String),
    Database(sqlx::Error),
    Forbidden(String),
    NotFound(&'static str),
    Probe(String),
    Unavailable(String),
    Unauthorized,
}

impl AdminError {
    #[must_use]
    pub const fn status_code(&self) -> u16 {
        match self {
            Self::BadRequest(_) => 400,
            Self::Unauthorized => 401,
            Self::Forbidden(_) => 403,
            Self::NotFound(_) => 404,
            Self::Conflict(_) => 409,
            Self::Database(_) | Self::Probe(_) => 500,
            Self::Unavailable(_) => 503,
        }
    }
}

impl fmt::Display for AdminError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadRequest(message)
            | Self::Conflict(message)
            | Self::Forbidden(message)
            | Self::Probe(message)
            | Self::Unavailable(message) => formatter.write_str(message),
            Self::Database(_) => formatter.write_str("database operation failed"),
            Self::NotFound(resource) => write!(formatter, "{resource} not found"),
            Self::Unauthorized => formatter.write_str("administrator authentication required"),
        }
    }
}

impl Error for AdminError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            _ => None,
        }
    }
}

impl From<sqlx::Error> for AdminError {
    fn from(error: sqlx::Error) -> Self {
        if let sqlx::Error::Database(database) = &error {
            match database.code().as_deref() {
                Some("23505") => return Self::Conflict("resource already exists".to_owned()),
                Some("23503" | "23514") => {
                    return Self::BadRequest("referenced resource or value is invalid".to_owned());
                }
                _ => {}
            }
        }
        Self::Database(error)
    }
}
