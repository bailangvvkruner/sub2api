use std::{cmp::Ordering, error::Error, fmt};

use axum::http::{HeaderMap, StatusCode};

use crate::repository::{
    ApiKeyAuthRecord, ApiKeyRecord, CoreRepository, GroupRecord, RepositoryError,
    SubscriptionBillingRecord, UnixMillis, UserPlatformQuotaRecord, UserRecord,
};

use super::ip::IpRestrictionDecision;
use super::{
    CredentialError, JwtClaims, JwtError, JwtVerifier, MAX_JWT_LENGTH, check_ip_restriction,
    extract_api_key, extract_bearer_token, session_token_version,
};

pub const API_KEY_STATUS_EXPIRED: &str = "expired";
pub const API_KEY_STATUS_QUOTA_EXHAUSTED: &str = "quota_exhausted";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationMode {
    Jwt,
    ApiKey { enforce_billing: bool },
}

/// Input boundary intended for an Axum middleware adapter. The adapter can
/// place the returned [`AuthContext`] in request extensions.
#[derive(Clone, Copy, Debug)]
pub struct AuthenticationRequest<'a> {
    pub mode: AuthenticationMode,
    pub headers: &'a HeaderMap,
    pub raw_query: Option<&'a str>,
    pub client_ip: Option<&'a str>,
    pub now_unix_ms: UnixMillis,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthSubject {
    pub user_id: i64,
    pub concurrency: i32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AuthContext {
    pub subject: AuthSubject,
    pub role: String,
    pub user: UserRecord,
    pub api_key: Option<ApiKeyRecord>,
    pub group: Option<GroupRecord>,
    pub subscription: Option<SubscriptionBillingRecord>,
    pub platform_quotas: Vec<UserPlatformQuotaRecord>,
    pub jwt_claims: Option<JwtClaims>,
}

#[derive(Debug)]
pub enum AuthError {
    Credential(CredentialError),
    Jwt(JwtError),
    Repository(RepositoryError),
    InvalidApiKey,
    ApiKeyDisabled,
    ApiKeyExpired,
    ApiKeyQuotaExhausted,
    AccessDenied,
    UserNotFound,
    UserInactive,
    GroupDeleted,
    GroupDisabled,
    GroupNotAllowed,
    TokenRevoked,
}

impl AuthError {
    #[must_use]
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Credential(CredentialError::ApiKeyInQueryDeprecated) => StatusCode::BAD_REQUEST,
            Self::AccessDenied
            | Self::ApiKeyExpired
            | Self::GroupDeleted
            | Self::GroupDisabled
            | Self::GroupNotAllowed => StatusCode::FORBIDDEN,
            Self::ApiKeyQuotaExhausted => StatusCode::TOO_MANY_REQUESTS,
            Self::Repository(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Credential(_)
            | Self::Jwt(_)
            | Self::InvalidApiKey
            | Self::ApiKeyDisabled
            | Self::UserNotFound
            | Self::UserInactive
            | Self::TokenRevoked => StatusCode::UNAUTHORIZED,
        }
    }

    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Credential(error) => match error {
                CredentialError::AuthorizationRequired => "UNAUTHORIZED",
                CredentialError::InvalidAuthorizationHeader
                | CredentialError::HeaderIsNotUtf8(_) => "INVALID_AUTH_HEADER",
                CredentialError::EmptyBearerToken => "EMPTY_TOKEN",
                CredentialError::ApiKeyInQueryDeprecated => "api_key_in_query_deprecated",
                CredentialError::ApiKeyRequired => "API_KEY_REQUIRED",
            },
            Self::Jwt(JwtError::Expired) => "TOKEN_EXPIRED",
            Self::Jwt(_) => "INVALID_TOKEN",
            Self::Repository(_) => "INTERNAL_ERROR",
            Self::InvalidApiKey => "INVALID_API_KEY",
            Self::ApiKeyDisabled => "API_KEY_DISABLED",
            Self::ApiKeyExpired => "API_KEY_EXPIRED",
            Self::ApiKeyQuotaExhausted => "API_KEY_QUOTA_EXHAUSTED",
            Self::AccessDenied => "ACCESS_DENIED",
            Self::UserNotFound => "USER_NOT_FOUND",
            Self::UserInactive => "USER_INACTIVE",
            Self::GroupDeleted => "GROUP_DELETED",
            Self::GroupDisabled => "GROUP_DISABLED",
            Self::GroupNotAllowed => "GROUP_NOT_ALLOWED",
            Self::TokenRevoked => "TOKEN_REVOKED",
        }
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Credential(error) => error.fmt(formatter),
            Self::Jwt(error) => error.fmt(formatter),
            Self::Repository(error) => error.fmt(formatter),
            _ => formatter.write_str(self.code()),
        }
    }
}

impl Error for AuthError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Credential(error) => Some(error),
            Self::Jwt(error) => Some(error),
            Self::Repository(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CredentialError> for AuthError {
    fn from(error: CredentialError) -> Self {
        Self::Credential(error)
    }
}

impl From<JwtError> for AuthError {
    fn from(error: JwtError) -> Self {
        Self::Jwt(error)
    }
}

impl From<RepositoryError> for AuthError {
    fn from(error: RepositoryError) -> Self {
        Self::Repository(error)
    }
}

#[derive(Clone, Debug)]
pub struct Authenticator<V> {
    repository: CoreRepository,
    jwt_verifier: V,
}

impl<V> Authenticator<V>
where
    V: JwtVerifier,
{
    #[must_use]
    pub fn new(repository: CoreRepository, jwt_verifier: V) -> Self {
        Self {
            repository,
            jwt_verifier,
        }
    }

    /// Authenticates according to the requested credential mode.
    ///
    /// # Errors
    ///
    /// Returns a classified credential, authorization, or repository error.
    pub async fn authenticate(
        &self,
        request: AuthenticationRequest<'_>,
    ) -> Result<AuthContext, AuthError> {
        match request.mode {
            AuthenticationMode::Jwt => {
                self.authenticate_jwt(request.headers, request.now_unix_ms)
                    .await
            }
            AuthenticationMode::ApiKey { enforce_billing } => {
                self.authenticate_api_key(
                    request.headers,
                    request.raw_query,
                    request.client_ip,
                    request.now_unix_ms,
                    enforce_billing,
                )
                .await
            }
        }
    }

    /// Authenticates a user JWT and reloads the current user snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid/revoked tokens or unavailable/inactive
    /// users.
    pub async fn authenticate_jwt(
        &self,
        headers: &HeaderMap,
        now_unix_ms: UnixMillis,
    ) -> Result<AuthContext, AuthError> {
        let token = extract_bearer_token(headers)?;
        if token.len() > MAX_JWT_LENGTH {
            return Err(JwtError::TooLarge.into());
        }
        let now_unix_seconds = now_unix_ms.div_euclid(1_000);
        let claims = self.jwt_verifier.verify(&token, now_unix_seconds)?;
        claims.validate(now_unix_seconds)?;

        let user = self
            .repository
            .find_user_by_id(claims.user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;
        if !user.is_active() {
            return Err(AuthError::UserInactive);
        }
        let expected_version =
            session_token_version(&user.email, &user.password_hash, user.auth_generation);
        if claims.token_version != expected_version {
            return Err(AuthError::TokenRevoked);
        }
        Ok(AuthContext {
            subject: AuthSubject {
                user_id: user.id,
                concurrency: user.concurrency,
            },
            role: user.role.clone(),
            user,
            api_key: None,
            group: None,
            subscription: None,
            platform_quotas: Vec::new(),
            jwt_claims: Some(claims),
        })
    }

    /// Authenticates an API key and its user/group snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid credentials, IP/group restrictions,
    /// billing gates, or repository failures.
    pub async fn authenticate_api_key(
        &self,
        headers: &HeaderMap,
        raw_query: Option<&str>,
        client_ip: Option<&str>,
        now_unix_ms: UnixMillis,
        enforce_billing: bool,
    ) -> Result<AuthContext, AuthError> {
        let extracted = extract_api_key(headers, raw_query)?;
        let snapshot = self
            .repository
            .find_api_key_for_auth(&extracted.key)
            .await?
            .ok_or(AuthError::InvalidApiKey)?;
        validate_api_key_snapshot(&snapshot, client_ip, now_unix_ms, enforce_billing)?;

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
}

/// Applies status, IP, user, group, expiry, and optional quota gates.
///
/// # Errors
///
/// Returns the first classified authorization failure in Go-compatible order.
pub fn validate_api_key_snapshot(
    snapshot: &ApiKeyAuthRecord,
    client_ip: Option<&str>,
    now_unix_ms: UnixMillis,
    enforce_billing: bool,
) -> Result<(), AuthError> {
    let key = &snapshot.api_key;
    if key.status != crate::repository::STATUS_ACTIVE
        && key.status != API_KEY_STATUS_EXPIRED
        && key.status != API_KEY_STATUS_QUOTA_EXHAUSTED
    {
        return Err(AuthError::ApiKeyDisabled);
    }

    if (!key.ip_whitelist.is_empty() || !key.ip_blacklist.is_empty())
        && check_ip_restriction(
            client_ip.unwrap_or_default(),
            &key.ip_whitelist,
            &key.ip_blacklist,
        ) == IpRestrictionDecision::Deny
    {
        return Err(AuthError::AccessDenied);
    }

    let user = snapshot.user.as_ref().ok_or(AuthError::UserNotFound)?;
    if !user.is_active() {
        return Err(AuthError::UserInactive);
    }
    validate_group(key, user, snapshot.group.as_ref())?;

    if !enforce_billing {
        return Ok(());
    }
    if key.status == API_KEY_STATUS_QUOTA_EXHAUSTED {
        return Err(AuthError::ApiKeyQuotaExhausted);
    }
    if key.status == API_KEY_STATUS_EXPIRED
        || key
            .expires_at_unix_ms
            .is_some_and(|expires_at| now_unix_ms > expires_at)
    {
        return Err(AuthError::ApiKeyExpired);
    }
    if decimal_quota_exhausted(&key.quota, &key.quota_used) {
        return Err(AuthError::ApiKeyQuotaExhausted);
    }
    Ok(())
}

fn validate_group(
    key: &ApiKeyRecord,
    user: &UserRecord,
    group: Option<&GroupRecord>,
) -> Result<(), AuthError> {
    let Some(group_id) = key.group_id else {
        return Ok(());
    };
    let group = group.ok_or(AuthError::GroupDeleted)?;
    if group.is_deleted() {
        return Err(AuthError::GroupDeleted);
    }
    if !group.is_active() {
        return Err(AuthError::GroupDisabled);
    }
    if !group.is_subscription_type() && !user.can_bind_group(group_id, group.is_exclusive) {
        return Err(AuthError::GroupNotAllowed);
    }
    Ok(())
}

fn decimal_quota_exhausted(quota: &str, used: &str) -> bool {
    let Some(quota) = NonNegativeDecimal::parse(quota) else {
        return false;
    };
    if quota.is_zero() {
        return false;
    }
    NonNegativeDecimal::parse(used).is_some_and(|used| used.cmp(&quota) != Ordering::Less)
}

#[derive(Debug, Eq, PartialEq)]
struct NonNegativeDecimal<'a> {
    integer: &'a str,
    fractional: &'a str,
}

impl<'a> NonNegativeDecimal<'a> {
    fn parse(value: &'a str) -> Option<Self> {
        let value = value.trim().strip_prefix('+').unwrap_or(value.trim());
        if value.starts_with('-') {
            return None;
        }
        let mut parts = value.split('.');
        let integer = parts.next()?;
        let fractional = parts.next().unwrap_or_default();
        if parts.next().is_some()
            || integer.is_empty()
            || !integer.bytes().all(|byte| byte.is_ascii_digit())
            || !fractional.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        let integer = integer.trim_start_matches('0');
        let integer = if integer.is_empty() { "0" } else { integer };
        let fractional = fractional.trim_end_matches('0');
        Some(Self {
            integer,
            fractional,
        })
    }

    fn is_zero(&self) -> bool {
        self.integer == "0" && self.fractional.is_empty()
    }

    fn cmp(&self, other: &NonNegativeDecimal<'_>) -> Ordering {
        self.integer
            .len()
            .cmp(&other.integer.len())
            .then_with(|| self.integer.cmp(other.integer))
            .then_with(|| compare_fractional(self.fractional, other.fractional))
    }
}

fn compare_fractional(left: &str, right: &str) -> Ordering {
    let width = left.len().max(right.len());
    left.bytes()
        .chain(std::iter::repeat(b'0'))
        .zip(right.bytes().chain(std::iter::repeat(b'0')))
        .take(width)
        .find_map(|(left, right)| (left != right).then(|| left.cmp(&right)))
        .unwrap_or(Ordering::Equal)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user() -> UserRecord {
        UserRecord {
            id: 11,
            email: "user@example.com".to_owned(),
            username: "user".to_owned(),
            password_hash: "$2a$hash".to_owned(),
            auth_generation: 0,
            role: "user".to_owned(),
            balance: "10.00000000".to_owned(),
            concurrency: 5,
            status: crate::repository::STATUS_ACTIVE.to_owned(),
            rpm_limit: 0,
            allowed_group_ids: vec![7],
        }
    }

    fn group() -> GroupRecord {
        GroupRecord {
            id: 7,
            name: "exclusive".to_owned(),
            platform: "anthropic".to_owned(),
            rate_multiplier: "1.0000".to_owned(),
            is_exclusive: true,
            status: crate::repository::STATUS_ACTIVE.to_owned(),
            subscription_type: "standard".to_owned(),
            rpm_limit: 0,
        }
    }

    fn snapshot() -> ApiKeyAuthRecord {
        ApiKeyAuthRecord {
            api_key: ApiKeyRecord {
                id: 1,
                user_id: 11,
                key: "sk-test".to_owned(),
                name: "test".to_owned(),
                group_id: Some(7),
                status: crate::repository::STATUS_ACTIVE.to_owned(),
                ip_whitelist: vec!["10.0.0.0/8".to_owned()],
                ip_blacklist: Vec::new(),
                quota: "10.00000000".to_owned(),
                quota_used: "9.99999999".to_owned(),
                expires_at_unix_ms: Some(2_000),
                rate_limit_5h: "0.00000000".to_owned(),
                rate_limit_1d: "0.00000000".to_owned(),
                rate_limit_7d: "0.00000000".to_owned(),
                usage_5h: "0.00000000".to_owned(),
                usage_1d: "0.00000000".to_owned(),
                usage_7d: "0.00000000".to_owned(),
                window_5h_start_unix_ms: None,
                window_1d_start_unix_ms: None,
                window_7d_start_unix_ms: None,
                group_rpm_override: None,
            },
            user: Some(user()),
            group: Some(group()),
            subscription: None,
            platform_quotas: Vec::new(),
        }
    }

    #[test]
    fn valid_api_key_snapshot_passes_all_core_checks() {
        assert!(validate_api_key_snapshot(&snapshot(), Some("10.1.2.3"), 1_999, true).is_ok());
    }

    #[test]
    fn ip_and_group_restrictions_fail_closed() {
        assert_eq!(
            validate_api_key_snapshot(&snapshot(), Some("8.8.8.8"), 1_999, true)
                .expect_err("IP outside whitelist must fail")
                .code(),
            "ACCESS_DENIED"
        );
        let mut denied = snapshot();
        denied
            .user
            .as_mut()
            .expect("user exists")
            .allowed_group_ids
            .clear();
        assert_eq!(
            validate_api_key_snapshot(&denied, Some("10.1.2.3"), 1_999, true)
                .expect_err("exclusive group must require assignment")
                .code(),
            "GROUP_NOT_ALLOWED"
        );
    }

    #[test]
    fn billing_checks_can_be_skipped_for_usage_endpoint() {
        let mut expired = snapshot();
        expired.api_key.status = API_KEY_STATUS_EXPIRED.to_owned();
        assert!(validate_api_key_snapshot(&expired, Some("10.1.2.3"), 3_000, false).is_ok());
        assert_eq!(
            validate_api_key_snapshot(&expired, Some("10.1.2.3"), 3_000, true)
                .expect_err("billing path must reject expiry")
                .code(),
            "API_KEY_EXPIRED"
        );
    }

    #[test]
    fn decimal_quota_comparison_is_exact() {
        assert!(!decimal_quota_exhausted("0.00000000", "999999999999.0"));
        assert!(!decimal_quota_exhausted("10.00000000", "9.99999999"));
        assert!(decimal_quota_exhausted("10.00000000", "10.0"));
        assert!(decimal_quota_exhausted("10.00000000", "10.00000001"));
        assert!(decimal_quota_exhausted("0.01", "0000.0100"));
    }
}
