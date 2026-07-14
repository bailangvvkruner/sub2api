use std::{
    collections::HashMap,
    net::IpAddr,
    str::FromStr,
    sync::Arc,
    time::{Duration, SystemTime},
};

use axum::http::{HeaderMap, header::AUTHORIZATION};
use base64::{Engine, engine::general_purpose::STANDARD};
use ipnet::IpNet;
use rand::{RngCore, rngs::OsRng};
use reqwest::header::CONTENT_TYPE;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, QueryBuilder, Row, Transaction, postgres::PgRow};
use url::Url;
use uuid::Uuid;

use crate::{
    auth::session_token_version,
    gateway::AuthCacheInvalidator,
    security::{
        jwt::{JwtClaims, JwtCodec, JwtError},
        password,
    },
};

use super::{
    limiter::LoginRateLimiter,
    models::{
        ApiError, ApiKeyListQuery, ApiKeyView, AuthNotifier, AuthResponse, CreateApiKeyRequest,
        CurrentUser, ForgotPasswordRequest, IdentitySummary, IdentitySummarySet,
        InvitationCodeValidation, Login2faRequest, LoginResponse, MessageResponse,
        NotifyEmailEntry, OAuthIdentityProfile, OAuthLoginOutcome, PUBLIC_SETTING_KEYS, Paginated,
        PromoCodeValidation, PublicRuntimeInfo, PublicSettings, RefreshResponse, RegisterRequest,
        ResetPasswordRequest, SendVerificationCodeRequest, SendVerificationCodeResponse,
        TotpDisableRequest, TotpEnableRequest, TotpLoginChallenge, TotpSetupRequest,
        TotpSetupResponse, TotpStatus, TotpVerificationMethod, UpdateApiKeyRequest,
        UpdateProfileRequest, UserProfile, UserView, public_settings_from_values,
    },
    security_flow::{
        ActionRateLimiter, decode_security_key, decrypt_secret, derive_security_key,
        encrypt_secret, generate_totp_secret, random_token, token_hash, totp_uri, validate_totp,
        verification_code,
    },
};

pub const REFRESH_TOKEN_PREFIX: &str = "rt_";
const REFRESH_TOKEN_RANDOM_BYTES: usize = 32;
const MAX_AVATAR_DATA_URL_BYTES: usize = 4 * 1024 * 1024;
const TURNSTILE_VERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const EMAIL_VERIFY_TTL: Duration = Duration::from_mins(10);
const PASSWORD_RESET_TTL: Duration = Duration::from_mins(30);
const TOTP_SESSION_TTL: Duration = Duration::from_mins(5);
const SECURITY_MAX_ATTEMPTS: i32 = 5;

/// Exact schema contract consumed by the `PostgreSQL` migration runner.
/// Refresh tokens are stored only as 32-byte SHA-256 digests.
pub const REFRESH_TOKENS_DDL: &str =
    include_str!("../../migrations/174_postgres_refresh_sessions.sql");
pub const AUTH_SECURITY_DDL: &str = include_str!("../../migrations/175_auth_security_state.sql");
pub const AUTH_RATE_LIMIT_DDL: &str =
    include_str!("../../migrations/180_postgres_auth_rate_limits.sql");

#[derive(Clone)]
pub struct ControlApiConfig {
    jwt_secret: Vec<u8>,
    security_key: [u8; 32],
    pub access_token_lifetime: Duration,
    pub refresh_token_lifetime: Duration,
    pub run_mode: String,
    pub version: String,
    pub server_timezone: String,
    pub server_utc_offset: String,
    pub login_max_failures: u32,
    pub login_failure_window: Duration,
}

impl ControlApiConfig {
    #[must_use]
    pub fn new(jwt_secret: impl Into<Vec<u8>>) -> Self {
        let jwt_secret = jwt_secret.into();
        Self {
            security_key: derive_security_key(&jwt_secret),
            jwt_secret,
            access_token_lifetime: Duration::from_mins(15),
            refresh_token_lifetime: Duration::from_hours(30 * 24),
            run_mode: "standard".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            server_timezone: "UTC".to_owned(),
            server_utc_offset: "+00:00".to_owned(),
            login_max_failures: 10,
            login_failure_window: Duration::from_mins(15),
        }
    }

    /// Overrides the domain-separated JWT-derived key used to encrypt TOTP secrets.
    ///
    /// # Errors
    ///
    /// Returns an error unless the value is exactly 32 bytes encoded as hex.
    pub fn with_totp_encryption_key(mut self, raw: &str) -> Result<Self, String> {
        self.security_key = decode_security_key(raw).map_err(str::to_owned)?;
        Ok(self)
    }

    #[must_use]
    pub fn with_access_token_lifetime(mut self, lifetime: Duration) -> Self {
        self.access_token_lifetime = lifetime;
        self
    }

    #[must_use]
    pub fn with_refresh_token_lifetime(mut self, lifetime: Duration) -> Self {
        self.refresh_token_lifetime = lifetime;
        self
    }

    #[must_use]
    pub fn with_run_mode(mut self, run_mode: impl Into<String>) -> Self {
        self.run_mode = run_mode.into();
        self
    }

    #[must_use]
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    #[must_use]
    pub fn with_server_timezone(
        mut self,
        name: impl Into<String>,
        utc_offset: impl Into<String>,
    ) -> Self {
        self.server_timezone = name.into();
        self.server_utc_offset = utc_offset.into();
        self
    }
}

#[derive(Clone)]
pub struct ControlApiState {
    pool: PgPool,
    jwt: JwtCodec,
    config: ControlApiConfig,
    login_limiter: LoginRateLimiter,
    action_limiter: ActionRateLimiter,
    notifier: Option<Arc<dyn AuthNotifier>>,
    http_client: reqwest::Client,
    auth_cache_invalidator: Option<AuthCacheInvalidator>,
}

pub(crate) struct OAuthRegistrationCompletion<'a> {
    pub provider: &'a str,
    pub session_token: &'a str,
    pub browser_session_key: &'a str,
    pub password: String,
    pub invitation_code: &'a str,
    pub affiliate_code: &'a str,
    pub requested_email: Option<&'a str>,
    pub verify_code: &'a str,
}

impl ControlApiState {
    /// Builds the PostgreSQL-only control-plane state.
    ///
    /// # Errors
    ///
    /// Returns [`JwtError::WeakSecret`] when the configured JWT secret is too short.
    pub fn new(pool: PgPool, config: ControlApiConfig) -> Result<Self, JwtError> {
        let jwt = JwtCodec::new(config.jwt_secret.clone(), config.access_token_lifetime)?;
        let login_limiter =
            LoginRateLimiter::new(config.login_max_failures, config.login_failure_window);
        Ok(Self {
            pool,
            jwt,
            config,
            login_limiter,
            action_limiter: ActionRateLimiter::new(),
            notifier: None,
            http_client: reqwest::Client::new(),
            auth_cache_invalidator: None,
        })
    }

    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    #[must_use]
    pub fn with_auth_notifier(mut self, notifier: Arc<dyn AuthNotifier>) -> Self {
        self.notifier = Some(notifier);
        self
    }

    #[must_use]
    pub fn with_auth_cache_invalidator(mut self, invalidator: AuthCacheInvalidator) -> Self {
        self.auth_cache_invalidator = Some(invalidator);
        self
    }

    pub(crate) async fn login(
        &self,
        email: String,
        plain_password: String,
        turnstile_token: String,
    ) -> Result<LoginResponse, ApiError> {
        let email = normalize_email(&email)?;
        if plain_password.is_empty() || plain_password.len() > 4_096 {
            return Err(ApiError::bad_request("Invalid email or password"));
        }
        if self.login_limiter.is_limited(&email) || self.login_is_limited(&email).await? {
            return Err(ApiError::too_many_requests(
                "Too many failed login attempts, please try again later",
            ));
        }
        self.verify_turnstile(&turnstile_token).await?;

        let Some(user) = self.find_user_by_email(&email).await? else {
            self.login_limiter.record_failure(&email);
            self.record_login_failure(&email).await?;
            return Err(ApiError::unauthorized("Invalid email or password"));
        };
        if user.view.status != "active" {
            self.login_limiter.record_failure(&email);
            self.record_login_failure(&email).await?;
            return Err(ApiError::unauthorized("Invalid email or password"));
        }

        let password_hash = user.password_hash.clone();
        let password_matches = tokio::task::spawn_blocking(move || {
            password::verify_password(&plain_password, &password_hash)
        })
        .await
        .map_err(|error| ApiError::internal("join password verification task", error))?
        .map_err(|error| ApiError::internal("verify password", error))?;
        if !password_matches {
            self.login_limiter.record_failure(&email);
            self.record_login_failure(&email).await?;
            return Err(ApiError::unauthorized("Invalid email or password"));
        }
        if user.totp_enabled && self.setting_is_true("totp_enabled").await? {
            self.login_limiter.clear(&email);
            self.clear_login_failures(&email).await?;
            return Ok(LoginResponse::Totp(
                self.create_totp_login_challenge(&user).await?,
            ));
        }
        if user.view.role != "admin" && self.setting_is_true("backend_mode_enabled").await? {
            return Err(ApiError::forbidden(
                "Backend mode is active. Only admin login is allowed.",
                "BACKEND_MODE_ADMIN_ONLY",
            ));
        }

        let token_version = token_version(&user);
        let access_token = self
            .jwt
            .issue(
                user.view.id,
                user.view.email.clone(),
                user.view.role.clone(),
                token_version,
            )
            .map_err(|error| ApiError::internal("issue access token", error))?;
        let refresh_token = self
            .insert_refresh_token(&user, Uuid::new_v4(), token_version)
            .await?;
        if let Err(error) = sqlx::query("UPDATE users SET last_login_at = NOW() WHERE id = $1")
            .bind(user.view.id)
            .execute(&self.pool)
            .await
        {
            tracing::warn!(
                error = %error,
                user_id = user.view.id,
                "failed to record successful login"
            );
        }
        self.login_limiter.clear(&email);
        self.clear_login_failures(&email).await?;

        Ok(LoginResponse::Auth(Box::new(AuthResponse {
            access_token,
            refresh_token,
            expires_in: self.config.access_token_lifetime.as_secs(),
            token_type: "Bearer",
            user: user.view,
        })))
    }

    pub(crate) async fn register(
        &self,
        request: RegisterRequest,
    ) -> Result<AuthResponse, ApiError> {
        let email = normalize_email(&request.email)?;
        self.require_action_rate(&format!("register:{email}"), 5, Duration::from_mins(1))
            .await?;
        validate_new_password(&request.password)?;
        if !self.setting_is_true("registration_enabled").await? {
            return Err(ApiError::forbidden(
                "User registration is disabled",
                "REGISTRATION_DISABLED",
            ));
        }
        if self.setting_is_true("backend_mode_enabled").await? {
            return Err(ApiError::forbidden(
                "Backend mode is active. New user registration is disabled.",
                "BACKEND_MODE_ADMIN_ONLY",
            ));
        }
        self.verify_turnstile(&request.turnstile_token).await?;
        let password_hash = hash_password_async(request.password).await?;
        let email_verification_required = self.setting_is_true("email_verify_enabled").await?;
        if email_verification_required && request.verify_code.trim().is_empty() {
            return Err(ApiError::bad_request("Email verification code is required"));
        }

        let mut transaction = self.pool.begin().await?;
        if email_verification_required {
            self.consume_email_verification(&mut transaction, &email, request.verify_code.trim())
                .await?;
        }
        let invitation_id = consume_oauth_invitation_precheck(
            &mut transaction,
            self.setting_is_true("invitation_code_enabled").await?,
            &request.invitation_code,
        )
        .await?;
        let user_id = sqlx::query_scalar::<_, i64>(
            r"
INSERT INTO users (email, password_hash, role, status, concurrency, signup_source)
VALUES ($1, $2, 'user', 'active', 5, 'email')
RETURNING id
",
        )
        .bind(&email)
        .bind(password_hash)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| {
            if is_unique_violation(&error) {
                ApiError::conflict("Email is already registered", "EMAIL_ALREADY_EXISTS")
            } else {
                error.into()
            }
        })?;
        sqlx::query(
            r"
INSERT INTO auth_identities
    (user_id, provider_type, provider_key, provider_subject, verified_at)
VALUES ($1, 'email', 'email', $2,
        CASE WHEN $3 THEN NOW() ELSE NULL END)
ON CONFLICT (provider_type, provider_key, provider_subject) DO NOTHING
",
        )
        .bind(user_id)
        .bind(&email)
        .bind(email_verification_required)
        .execute(&mut *transaction)
        .await?;
        if let Some(invitation_id) = invitation_id {
            let updated = sqlx::query(
                "UPDATE redeem_codes SET status = 'used', used_by = $2, used_at = NOW() WHERE id = $1 AND status = 'unused'",
            )
            .bind(invitation_id)
            .bind(user_id)
            .execute(&mut *transaction)
            .await?;
            if updated.rows_affected() != 1 {
                return Err(ApiError::conflict(
                    "Invitation code has already been used",
                    "INVITATION_CODE_USED",
                ));
            }
        }
        if self.setting_is_true("promo_code_enabled").await? {
            apply_oauth_promo_code(&mut transaction, user_id, &request.promo_code).await?;
        }
        initialize_oauth_affiliate(&mut transaction, user_id, &request.aff_code).await?;
        transaction.commit().await?;
        let user = self
            .find_user_by_id(user_id)
            .await?
            .ok_or_else(|| ApiError::internal("load registered user", "user disappeared"))?;
        self.issue_auth_response(user).await
    }

    pub(crate) async fn oauth_login_or_begin_registration(
        &self,
        profile: OAuthIdentityProfile,
        redirect_to: &str,
        promo_code: &str,
        affiliate_code: &str,
    ) -> Result<OAuthLoginOutcome, ApiError> {
        let provider = normalize_oauth_provider(&profile.provider)?;
        let provider_key = profile.provider_key.trim();
        if provider_key.is_empty() || provider_key.len() > 2_048 {
            return Err(ApiError::bad_request("OAuth provider key is invalid"));
        }
        let email = normalize_email(&profile.email)?;
        let subject = profile.subject.trim();
        if subject.is_empty() || subject.len() > 255 {
            return Err(ApiError::bad_request("OAuth identity subject is invalid"));
        }
        let username = profile
            .username
            .trim()
            .chars()
            .take(100)
            .collect::<String>();
        let display_name = profile
            .display_name
            .trim()
            .chars()
            .take(255)
            .collect::<String>();
        let avatar_url = profile
            .avatar_url
            .trim()
            .chars()
            .take(2_048)
            .collect::<String>();
        let metadata = merge_oauth_metadata(
            profile.metadata,
            &email,
            &username,
            &display_name,
            &avatar_url,
            profile.issuer.as_deref(),
        );
        let mut transaction = self.pool.begin().await?;

        let identity_user = sqlx::query(
            r"
SELECT u.id, u.email, u.role, u.status
FROM auth_identities identity
JOIN users u ON u.id = identity.user_id
WHERE identity.provider_type = $1
  AND identity.provider_key = $2
  AND identity.provider_subject = $3
  AND u.deleted_at IS NULL
FOR UPDATE OF identity, u
",
        )
        .bind(provider)
        .bind(provider_key)
        .bind(subject)
        .fetch_optional(&mut *transaction)
        .await?;

        let user_id = if let Some(row) = identity_user {
            let identity_email: String = row.try_get("email")?;
            if !identity_email.eq_ignore_ascii_case(&email) {
                return Err(ApiError::conflict(
                    "OAuth identity belongs to a different email",
                    "AUTH_IDENTITY_EMAIL_MISMATCH",
                ));
            }
            ensure_oauth_user_can_login(
                &row.try_get::<String, _>("role")?,
                &row.try_get::<String, _>("status")?,
                self.setting_is_true("backend_mode_enabled").await?,
            )?;
            let user_id: i64 = row.try_get("id")?;
            sqlx::query(
                "UPDATE auth_identities SET metadata = $2, issuer = $3, verified_at = COALESCE(verified_at, NOW()), updated_at = NOW() WHERE user_id = $1 AND provider_type = $4 AND provider_key = $5 AND provider_subject = $6",
            )
            .bind(user_id)
            .bind(&metadata)
            .bind(profile.issuer.as_deref())
            .bind(provider)
            .bind(provider_key)
            .bind(subject)
            .execute(&mut *transaction)
            .await?;
            upsert_oauth_identity_channel(
                &mut transaction,
                user_id,
                provider,
                provider_key,
                subject,
                &metadata,
            )
            .await?;
            Some(user_id)
        } else {
            let email_user = sqlx::query(
                r"
SELECT id, role, status
FROM users
WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL
FOR UPDATE
",
            )
            .bind(&email)
            .fetch_optional(&mut *transaction)
            .await?;
            if let Some(row) = email_user {
                ensure_oauth_user_can_login(
                    &row.try_get::<String, _>("role")?,
                    &row.try_get::<String, _>("status")?,
                    self.setting_is_true("backend_mode_enabled").await?,
                )?;
                let user_id: i64 = row.try_get("id")?;
                sqlx::query(
                    r"
INSERT INTO auth_identities (
    user_id, provider_type, provider_key, provider_subject, verified_at, issuer, metadata
)
VALUES ($1, $2, $3, $4, NOW(), $5, $6)
ON CONFLICT (provider_type, provider_key, provider_subject) DO NOTHING
",
                )
                .bind(user_id)
                .bind(provider)
                .bind(provider_key)
                .bind(subject)
                .bind(profile.issuer.as_deref())
                .bind(&metadata)
                .execute(&mut *transaction)
                .await?;
                let actual_user = sqlx::query_scalar::<_, i64>(
                    "SELECT user_id FROM auth_identities WHERE provider_type = $1 AND provider_key = $2 AND provider_subject = $3",
                )
                .bind(provider)
                .bind(provider_key)
                .bind(subject)
                .fetch_one(&mut *transaction)
                .await?;
                if actual_user != user_id {
                    return Err(ApiError::conflict(
                        "OAuth identity is already bound",
                        "AUTH_IDENTITY_ALREADY_BOUND",
                    ));
                }
                upsert_oauth_identity_channel(
                    &mut transaction,
                    user_id,
                    provider,
                    provider_key,
                    subject,
                    &metadata,
                )
                .await?;
                Some(user_id)
            } else {
                None
            }
        };

        if let Some(user_id) = user_id {
            sqlx::query("UPDATE users SET last_login_at = NOW() WHERE id = $1")
                .bind(user_id)
                .execute(&mut *transaction)
                .await?;
            transaction.commit().await?;
            let user = self
                .find_user_by_id(user_id)
                .await?
                .ok_or_else(|| ApiError::internal("load OAuth user", "user disappeared"))?;
            return self
                .issue_auth_response(user)
                .await
                .map(Box::new)
                .map(OAuthLoginOutcome::Auth);
        }

        if self.setting_is_true("backend_mode_enabled").await? {
            return Err(ApiError::forbidden(
                "Backend mode is active. New user registration is disabled.",
                "BACKEND_MODE_ADMIN_ONLY",
            ));
        }
        if !self.setting_is_true("registration_enabled").await? {
            return Err(ApiError::forbidden(
                "User registration is disabled",
                "REGISTRATION_DISABLED",
            ));
        }

        let session_token = random_token("oauth_session_");
        let browser_session_key = random_token("oauth_browser_");
        let session_hash = hex::encode(Sha256::digest(session_token.as_bytes()));
        let browser_hash = hex::encode(Sha256::digest(browser_session_key.as_bytes()));
        let local_flow_state = serde_json::json!({
            "completion_response": {
                "step": "choice",
                "error": "registration_completion_required",
                "choice_reason": "registration_completion_required",
                "adoption_required": false,
                "create_account_allowed": true,
                "existing_account_bindable": false,
                "force_email_on_signup": true,
                "invitation_required": self.setting_is_true("invitation_code_enabled").await?,
                "email": email,
                "resolved_email": email,
                "provider": provider,
                "redirect": redirect_to
            },
            "promo_code": promo_code.trim(),
            "affiliate_code": affiliate_code.trim()
        });
        sqlx::query(
            r"
INSERT INTO pending_auth_sessions (
    session_token, intent, provider_type, provider_key, provider_subject,
    redirect_to, resolved_email, upstream_identity_claims, local_flow_state,
    browser_session_key, expires_at
)
VALUES ($1, 'login', $2, $3, $4, $5, $6, $7, $8, $9, NOW() + INTERVAL '10 minutes')
",
        )
        .bind(session_hash)
        .bind(provider)
        .bind(provider_key)
        .bind(subject)
        .bind(redirect_to)
        .bind(&email)
        .bind(&metadata)
        .bind(&local_flow_state)
        .bind(browser_hash)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(OAuthLoginOutcome::RegistrationPending {
            session_token,
            browser_session_key,
            suggested_email: email,
        })
    }

    pub(crate) async fn complete_oauth_registration(
        &self,
        input: OAuthRegistrationCompletion<'_>,
    ) -> Result<AuthResponse, ApiError> {
        let OAuthRegistrationCompletion {
            provider,
            session_token,
            browser_session_key,
            password,
            invitation_code,
            affiliate_code,
            requested_email,
            verify_code,
        } = input;
        let provider = normalize_oauth_provider(provider)?;
        validate_new_password(&password)?;
        let password_hash = hash_password_async(password).await?;
        let session_hash = hex::encode(Sha256::digest(session_token.as_bytes()));
        let browser_hash = hex::encode(Sha256::digest(browser_session_key.as_bytes()));
        let mut transaction = self.pool.begin().await?;
        let session = sqlx::query(
            r"
SELECT id, provider_key, provider_subject, resolved_email, upstream_identity_claims, local_flow_state
FROM pending_auth_sessions
WHERE session_token = $1
  AND browser_session_key = $2
  AND provider_type = $3
  AND intent = 'login'
  AND consumed_at IS NULL
  AND expires_at > NOW()
FOR UPDATE
",
        )
        .bind(session_hash)
        .bind(browser_hash)
        .bind(provider)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| ApiError::unauthorized("Pending OAuth session is invalid or expired"))?;
        let pending_id: i64 = session.try_get("id")?;
        let provider_key: String = session.try_get("provider_key")?;
        let subject: String = session.try_get("provider_subject")?;
        let resolved_email = normalize_email(&session.try_get::<String, _>("resolved_email")?)?;
        let email = requested_email
            .map(normalize_email)
            .transpose()?
            .unwrap_or_else(|| resolved_email.clone());
        if !email.eq_ignore_ascii_case(&resolved_email) {
            self.consume_email_verification(&mut transaction, &email, verify_code.trim())
                .await?;
        }
        let claims: serde_json::Value = session.try_get("upstream_identity_claims")?;
        let identity_issuer = claims
            .get("issuer")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let local_flow_state: serde_json::Value = session.try_get("local_flow_state")?;

        if self.setting_is_true("backend_mode_enabled").await? {
            return Err(ApiError::forbidden(
                "Backend mode is active. New user registration is disabled.",
                "BACKEND_MODE_ADMIN_ONLY",
            ));
        }
        if !self.setting_is_true("registration_enabled").await? {
            return Err(ApiError::forbidden(
                "User registration is disabled",
                "REGISTRATION_DISABLED",
            ));
        }
        let invitation_id = consume_oauth_invitation_precheck(
            &mut transaction,
            self.setting_is_true("invitation_code_enabled").await?,
            invitation_code,
        )
        .await?;
        let username = claims
            .get("username")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.chars().take(100).collect::<String>());
        let user_id = sqlx::query_scalar::<_, i64>(
            r"
INSERT INTO users (email, username, password_hash, role, status, concurrency, signup_source)
VALUES ($1, $2, $3, 'user', 'active', 5, $4)
RETURNING id
",
        )
        .bind(&email)
        .bind(username)
        .bind(password_hash)
        .bind(provider)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| {
            if is_unique_violation(&error) {
                ApiError::conflict("Email is already registered", "EMAIL_ALREADY_EXISTS")
            } else {
                error.into()
            }
        })?;
        sqlx::query(
            r"
INSERT INTO auth_identities (
    user_id, provider_type, provider_key, provider_subject, verified_at, issuer, metadata
)
VALUES ($1, $2, $3, $4, NOW(), $5, $6)
",
        )
        .bind(user_id)
        .bind(provider)
        .bind(&provider_key)
        .bind(&subject)
        .bind(identity_issuer)
        .bind(&claims)
        .execute(&mut *transaction)
        .await?;
        upsert_oauth_identity_channel(
            &mut transaction,
            user_id,
            provider,
            &provider_key,
            &subject,
            &claims,
        )
        .await?;
        if let Some(invitation_id) = invitation_id {
            let updated = sqlx::query(
                "UPDATE redeem_codes SET status = 'used', used_by = $2, used_at = NOW() WHERE id = $1 AND status = 'unused'",
            )
            .bind(invitation_id)
            .bind(user_id)
            .execute(&mut *transaction)
            .await?;
            if updated.rows_affected() != 1 {
                return Err(ApiError::conflict(
                    "Invitation code has already been used",
                    "INVITATION_CODE_USED",
                ));
            }
        }
        let promo_code = local_flow_state
            .get("promo_code")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        apply_oauth_promo_code(&mut transaction, user_id, promo_code).await?;
        let captured_affiliate_code = local_flow_state
            .get("affiliate_code")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let affiliate_code = if affiliate_code.trim().is_empty() {
            captured_affiliate_code
        } else {
            affiliate_code
        };
        initialize_oauth_affiliate(&mut transaction, user_id, affiliate_code).await?;
        sqlx::query(
            "UPDATE pending_auth_sessions SET consumed_at = NOW(), updated_at = NOW() WHERE id = $1 AND consumed_at IS NULL",
        )
        .bind(pending_id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        let user = self
            .find_user_by_id(user_id)
            .await?
            .ok_or_else(|| ApiError::internal("load OAuth user", "user disappeared"))?;
        self.issue_auth_response(user).await
    }

    pub(crate) async fn bind_pending_oauth_login(
        &self,
        expected_provider: Option<&str>,
        session_token: &str,
        browser_session_key: &str,
        email: &str,
        plain_password: String,
    ) -> Result<AuthResponse, ApiError> {
        let email = normalize_email(email)?;
        self.require_action_rate(
            &format!("oauth-bind-login:{email}"),
            10,
            Duration::from_mins(1),
        )
        .await?;
        let user = self
            .find_user_by_email(&email)
            .await?
            .ok_or_else(|| ApiError::unauthorized("Invalid email or password"))?;
        if user.view.status != "active" {
            return Err(ApiError::unauthorized("Invalid email or password"));
        }
        let password_hash = user.password_hash.clone();
        let password_matches = tokio::task::spawn_blocking(move || {
            password::verify_password(&plain_password, &password_hash)
        })
        .await
        .map_err(|error| ApiError::internal("join password verification task", error))?
        .map_err(|error| ApiError::internal("verify password", error))?;
        if !password_matches {
            return Err(ApiError::unauthorized("Invalid email or password"));
        }
        if user.totp_enabled && self.setting_is_true("totp_enabled").await? {
            return Err(ApiError::forbidden(
                "Complete two-factor authentication before binding OAuth",
                "TOTP_REQUIRED",
            ));
        }
        if user.view.role != "admin" && self.setting_is_true("backend_mode_enabled").await? {
            return Err(ApiError::forbidden(
                "Backend mode is active. Only admin login is allowed.",
                "BACKEND_MODE_ADMIN_ONLY",
            ));
        }
        let session_hash = hex::encode(Sha256::digest(session_token.as_bytes()));
        let browser_hash = hex::encode(Sha256::digest(browser_session_key.as_bytes()));
        let row = sqlx::query(
            r"
SELECT provider_type, provider_key, provider_subject, target_user_id,
       resolved_email, upstream_identity_claims
FROM pending_auth_sessions
WHERE session_token = $1
  AND browser_session_key = $2
  AND ($3::text IS NULL OR provider_type = $3)
  AND consumed_at IS NULL
  AND expires_at > NOW()
LIMIT 1
",
        )
        .bind(&session_hash)
        .bind(&browser_hash)
        .bind(expected_provider)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| ApiError::unauthorized("Pending OAuth session is invalid or expired"))?;
        let target_user_id: Option<i64> = row.try_get("target_user_id")?;
        if target_user_id.is_some_and(|target| target != user.view.id) {
            return Err(ApiError::conflict(
                "Pending OAuth session targets another user",
                "PENDING_AUTH_TARGET_USER_MISMATCH",
            ));
        }
        let claims: serde_json::Value = row.try_get("upstream_identity_claims")?;
        let profile = OAuthIdentityProfile {
            provider: row.try_get("provider_type")?,
            provider_key: row.try_get("provider_key")?,
            subject: row.try_get("provider_subject")?,
            issuer: claims
                .get("issuer")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            email: row.try_get("resolved_email")?,
            username: claims
                .get("username")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            display_name: claims
                .get("suggested_display_name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            avatar_url: claims
                .get("suggested_avatar_url")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            metadata: claims,
        };
        self.bind_oauth_identity(user.view.id, profile).await?;
        let consumed = sqlx::query(
            r"
UPDATE pending_auth_sessions
SET consumed_at = NOW(), updated_at = NOW()
WHERE session_token = $1 AND browser_session_key = $2 AND consumed_at IS NULL
",
        )
        .bind(session_hash)
        .bind(browser_hash)
        .execute(&self.pool)
        .await?;
        if consumed.rows_affected() != 1 {
            return Err(ApiError::unauthorized(
                "Pending OAuth session was already consumed",
            ));
        }
        self.issue_auth_response(user).await
    }

    pub(crate) async fn bind_oauth_identity(
        &self,
        user_id: i64,
        profile: OAuthIdentityProfile,
    ) -> Result<(), ApiError> {
        let provider = normalize_oauth_provider(&profile.provider)?;
        let provider_key = profile.provider_key.trim();
        let subject = profile.subject.trim();
        if user_id <= 0
            || provider_key.is_empty()
            || provider_key.len() > 2_048
            || subject.is_empty()
            || subject.len() > 255
        {
            return Err(ApiError::bad_request("OAuth identity is invalid"));
        }
        let email = normalize_email(&profile.email)?;
        let username = profile
            .username
            .trim()
            .chars()
            .take(100)
            .collect::<String>();
        let display_name = profile
            .display_name
            .trim()
            .chars()
            .take(255)
            .collect::<String>();
        let avatar_url = profile
            .avatar_url
            .trim()
            .chars()
            .take(2_048)
            .collect::<String>();
        let metadata = merge_oauth_metadata(
            profile.metadata,
            &email,
            &username,
            &display_name,
            &avatar_url,
            profile.issuer.as_deref(),
        );
        let mut transaction = self.pool.begin().await?;
        let user_status = sqlx::query_scalar::<_, String>(
            "SELECT status FROM users WHERE id = $1 AND deleted_at IS NULL FOR UPDATE",
        )
        .bind(user_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| ApiError::unauthorized("User is no longer available"))?;
        if user_status != "active" {
            return Err(ApiError::unauthorized("User account is not active"));
        }
        let existing_user = sqlx::query_scalar::<_, i64>(
            r"
SELECT user_id
FROM auth_identities
WHERE provider_type = $1 AND provider_key = $2 AND provider_subject = $3
FOR UPDATE
",
        )
        .bind(provider)
        .bind(provider_key)
        .bind(subject)
        .fetch_optional(&mut *transaction)
        .await?;
        if existing_user.is_some_and(|existing_user| existing_user != user_id) {
            return Err(ApiError::conflict(
                "OAuth identity is already bound to another user",
                "AUTH_IDENTITY_ALREADY_BOUND",
            ));
        }
        sqlx::query(
            r"
INSERT INTO auth_identities (
    user_id, provider_type, provider_key, provider_subject, verified_at, issuer, metadata
)
VALUES ($1, $2, $3, $4, NOW(), $5, $6)
ON CONFLICT (provider_type, provider_key, provider_subject)
DO UPDATE SET
    verified_at = COALESCE(auth_identities.verified_at, NOW()),
    issuer = EXCLUDED.issuer,
    metadata = EXCLUDED.metadata,
    updated_at = NOW()
WHERE auth_identities.user_id = EXCLUDED.user_id
",
        )
        .bind(user_id)
        .bind(provider)
        .bind(provider_key)
        .bind(subject)
        .bind(profile.issuer.as_deref())
        .bind(&metadata)
        .execute(&mut *transaction)
        .await?;
        upsert_oauth_identity_channel(
            &mut transaction,
            user_id,
            provider,
            provider_key,
            subject,
            &metadata,
        )
        .await?;
        transaction.commit().await?;
        self.invalidate_user_auth_cache().await;
        Ok(())
    }

    pub(crate) async fn send_verification_code(
        &self,
        request: SendVerificationCodeRequest,
    ) -> Result<SendVerificationCodeResponse, ApiError> {
        let email = normalize_email(&request.email)?;
        self.send_verification_code_for(&email, Some(&request.turnstile_token))
            .await
    }

    pub(crate) async fn send_totp_verification_code(
        &self,
        email: &str,
    ) -> Result<SendVerificationCodeResponse, ApiError> {
        let email = normalize_email(email)?;
        self.send_verification_code_for(&email, None).await
    }

    pub(crate) async fn send_email_binding_code(
        &self,
        user_id: i64,
        email: &str,
    ) -> Result<SendVerificationCodeResponse, ApiError> {
        self.send_authenticated_email_code(user_id, email, "email_bind")
            .await
    }

    pub(crate) async fn send_notification_email_code(
        &self,
        user_id: i64,
        email: &str,
    ) -> Result<SendVerificationCodeResponse, ApiError> {
        self.send_authenticated_email_code(user_id, email, "notify_email")
            .await
    }

    async fn send_authenticated_email_code(
        &self,
        user_id: i64,
        email: &str,
        purpose: &'static str,
    ) -> Result<SendVerificationCodeResponse, ApiError> {
        let email = normalize_email(email)?;
        self.require_action_rate(
            &format!("{purpose}:{user_id}:{email}"),
            5,
            Duration::from_mins(1),
        )
        .await?;
        let notifier = self.notifier.clone().ok_or_else(|| {
            ApiError::internal("send verification code", "email notifier is not configured")
        })?;
        let code = verification_code();
        let material = email_code_material(&email, &code);
        let hash = token_hash(&self.config.security_key, purpose, &material);
        let token_id = Uuid::new_v4().to_string();
        let mut transaction = self.pool.begin().await?;
        consume_active_security_tokens(&mut transaction, Some(user_id), &email, purpose).await?;
        insert_security_token(
            &mut transaction,
            SecurityTokenInsert {
                id: &token_id,
                purpose,
                hash: &hash,
                user_id: Some(user_id),
                subject: &email,
                secret_ciphertext: None,
                lifetime: EMAIL_VERIFY_TTL,
                max_attempts: SECURITY_MAX_ATTEMPTS,
            },
        )
        .await?;
        transaction.commit().await?;
        if let Err(error) = notifier.send_verification_code(&email, &code).await {
            let _ = consume_security_token_by_id(&self.pool, &token_id).await;
            return Err(ApiError::internal("deliver verification code", error));
        }
        Ok(SendVerificationCodeResponse {
            message: "Verification code sent successfully",
            countdown: 60,
        })
    }

    async fn send_verification_code_for(
        &self,
        email: &str,
        turnstile_token: Option<&str>,
    ) -> Result<SendVerificationCodeResponse, ApiError> {
        self.require_action_rate(&format!("email-code:{email}"), 5, Duration::from_mins(1))
            .await?;
        if let Some(token) = turnstile_token {
            self.verify_turnstile(token).await?;
        }
        let notifier = self.notifier.clone().ok_or_else(|| {
            ApiError::internal("send verification code", "email notifier is not configured")
        })?;
        let code = verification_code();
        let material = email_code_material(email, &code);
        let hash = token_hash(&self.config.security_key, "email_verify", &material);
        let token_id = Uuid::new_v4().to_string();
        let mut transaction = self.pool.begin().await?;
        consume_active_security_tokens(&mut transaction, None, email, "email_verify").await?;
        insert_security_token(
            &mut transaction,
            SecurityTokenInsert {
                id: &token_id,
                purpose: "email_verify",
                hash: &hash,
                user_id: None,
                subject: email,
                secret_ciphertext: None,
                lifetime: EMAIL_VERIFY_TTL,
                max_attempts: SECURITY_MAX_ATTEMPTS,
            },
        )
        .await?;
        transaction.commit().await?;
        if let Err(error) = notifier.send_verification_code(email, &code).await {
            let _ = consume_security_token_by_id(&self.pool, &token_id).await;
            return Err(ApiError::internal("deliver verification code", error));
        }
        Ok(SendVerificationCodeResponse {
            message: "Verification code sent successfully",
            countdown: 60,
        })
    }

    pub(crate) async fn login_2fa(
        &self,
        request: Login2faRequest,
    ) -> Result<AuthResponse, ApiError> {
        validate_prefixed_token(&request.temp_token, "totp_login_")?;
        let challenge_hash =
            token_hash(&self.config.security_key, "totp_login", &request.temp_token);
        self.require_action_rate(
            &format!("login-2fa:{}", hex::encode(challenge_hash)),
            20,
            Duration::from_mins(1),
        )
        .await?;
        let mut transaction = self.pool.begin().await?;
        let token_row = sqlx::query(
            r"
SELECT id::text AS id, user_id, attempts, max_attempts,
       expires_at > NOW() AS unexpired
FROM auth_security_tokens
WHERE purpose = 'totp_login' AND token_hash = $1 AND consumed_at IS NULL
FOR UPDATE
",
        )
        .bind(challenge_hash.as_slice())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| ApiError::bad_request("Invalid or expired 2FA session"))?;
        let token_id: String = token_row.try_get("id")?;
        let user_id: i64 = token_row.try_get("user_id")?;
        let attempts: i32 = token_row.try_get("attempts")?;
        let max_attempts: i32 = token_row.try_get("max_attempts")?;
        let unexpired: bool = token_row.try_get("unexpired")?;
        if !unexpired || attempts >= max_attempts {
            consume_security_token_tx(&mut transaction, &token_id).await?;
            transaction.commit().await?;
            return Err(ApiError::bad_request("Invalid or expired 2FA session"));
        }
        let user_row = sqlx::query(USER_BY_ID_SQL)
            .bind(user_id)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or_else(|| ApiError::unauthorized("User is no longer available"))?;
        let user = user_from_row(&user_row)?;
        let encrypted = user
            .totp_secret_encrypted
            .as_deref()
            .ok_or_else(|| ApiError::bad_request("TOTP is not configured"))?;
        let secret = decrypt_secret(&self.config.security_key, encrypted)
            .map_err(|error| ApiError::internal("decrypt TOTP secret", error))?;
        if !validate_totp(&secret, request.totp_code.trim(), now_unix_seconds()?) {
            let exhausted = record_security_failure(&mut transaction, &token_id).await?;
            transaction.commit().await?;
            return if exhausted {
                Err(ApiError::too_many_requests(
                    "Too many verification attempts, please try again later",
                ))
            } else {
                Err(ApiError::bad_request("Invalid TOTP code"))
            };
        }
        if user.view.status != "active" {
            return Err(ApiError::unauthorized("User is not active"));
        }
        if user.view.role != "admin"
            && setting_is_true_in_transaction(&mut transaction, "backend_mode_enabled").await?
        {
            return Err(ApiError::forbidden(
                "Backend mode is active. Only admin login is allowed.",
                "BACKEND_MODE_ADMIN_ONLY",
            ));
        }
        let version = token_version(&user);
        let access_token = self
            .jwt
            .issue(
                user.view.id,
                user.view.email.clone(),
                user.view.role.clone(),
                version,
            )
            .map_err(|error| ApiError::internal("issue access token", error))?;
        let refresh_token = insert_refresh_token_tx(
            &mut transaction,
            user.view.id,
            Uuid::new_v4(),
            version,
            self.config.refresh_token_lifetime,
        )
        .await?;
        consume_security_token_tx(&mut transaction, &token_id).await?;
        sqlx::query("UPDATE users SET last_login_at = NOW() WHERE id = $1")
            .bind(user.view.id)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(AuthResponse {
            access_token,
            refresh_token,
            expires_in: self.config.access_token_lifetime.as_secs(),
            token_type: "Bearer",
            user: user.view,
        })
    }

    pub(crate) async fn logout(&self, raw_refresh_token: &str) -> MessageResponse {
        if validate_refresh_token(raw_refresh_token).is_ok() {
            let hash = hash_refresh_token(raw_refresh_token);
            if let Err(error) = sqlx::query(
                "UPDATE auth_refresh_sessions SET revoked_at = COALESCE(revoked_at, NOW()) WHERE token_hash = $1",
            )
            .bind(hash.as_slice())
            .execute(&self.pool)
            .await
            {
                tracing::warn!(error = %error, "failed to revoke refresh token during logout");
            }
        }
        MessageResponse {
            message: "Logged out successfully",
        }
    }

    pub(crate) async fn revoke_all_sessions(
        &self,
        user_id: i64,
    ) -> Result<MessageResponse, ApiError> {
        let mut transaction = self.pool.begin().await?;
        let result = sqlx::query(
            "UPDATE users SET auth_generation = auth_generation + 1, updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(user_id)
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() != 1 {
            return Err(ApiError::not_found("User not found"));
        }
        revoke_user_security_state(&mut transaction, user_id).await?;
        transaction.commit().await?;
        self.invalidate_user_auth_cache().await;
        Ok(MessageResponse {
            message: "All sessions have been revoked. Please log in again.",
        })
    }

    pub(crate) async fn change_password(
        &self,
        user: UserRecord,
        old_password: String,
        new_password: String,
    ) -> Result<MessageResponse, ApiError> {
        validate_new_password(&new_password)?;
        if !verify_password_async(old_password, user.password_hash.clone()).await? {
            return Err(ApiError::bad_request("Current password is incorrect"));
        }
        let password_hash = hash_password_async(new_password).await?;
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            r"UPDATE users SET password_hash = $2, auth_generation = auth_generation + 1,
               updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(user.view.id)
        .bind(password_hash)
        .execute(&mut *transaction)
        .await?;
        revoke_user_security_state(&mut transaction, user.view.id).await?;
        transaction.commit().await?;
        self.invalidate_user_auth_cache().await;
        Ok(MessageResponse {
            message: "Password changed successfully. Please log in again.",
        })
    }

    pub(crate) async fn forgot_password(
        &self,
        request: ForgotPasswordRequest,
    ) -> Result<MessageResponse, ApiError> {
        let email = normalize_email(&request.email)?;
        self.require_action_rate(
            &format!("forgot-password:{email}"),
            5,
            Duration::from_mins(1),
        )
        .await?;
        self.verify_turnstile(&request.turnstile_token).await?;
        let response = MessageResponse {
            message: "If your email is registered, you will receive a password reset link shortly.",
        };
        let Some(notifier) = self.notifier.clone() else {
            tracing::warn!("password reset requested but no auth notifier is configured");
            return Ok(response);
        };
        let Some(user) = self.find_user_by_email(&email).await? else {
            return Ok(response);
        };
        if user.view.status != "active" {
            return Ok(response);
        }
        let raw_token = random_token("pr_");
        let hash = token_hash(&self.config.security_key, "password_reset", &raw_token);
        let token_id = Uuid::new_v4().to_string();
        let mut transaction = self.pool.begin().await?;
        consume_active_security_tokens(
            &mut transaction,
            Some(user.view.id),
            &email,
            "password_reset",
        )
        .await?;
        insert_security_token(
            &mut transaction,
            SecurityTokenInsert {
                id: &token_id,
                purpose: "password_reset",
                hash: &hash,
                user_id: Some(user.view.id),
                subject: &email,
                secret_ciphertext: None,
                lifetime: PASSWORD_RESET_TTL,
                max_attempts: SECURITY_MAX_ATTEMPTS,
            },
        )
        .await?;
        transaction.commit().await?;
        if let Err(error) = notifier.send_password_reset(&email, &raw_token).await {
            let _ = consume_security_token_by_id(&self.pool, &token_id).await;
            tracing::error!(error, "failed to deliver password reset token");
        }
        Ok(response)
    }

    pub(crate) async fn reset_password(
        &self,
        request: ResetPasswordRequest,
    ) -> Result<MessageResponse, ApiError> {
        let email = normalize_email(&request.email)?;
        validate_prefixed_token(&request.token, "pr_")?;
        validate_new_password(&request.new_password)?;
        self.require_action_rate(
            &format!("reset-password:{email}"),
            10,
            Duration::from_mins(1),
        )
        .await?;
        let hash = token_hash(&self.config.security_key, "password_reset", &request.token);
        let password_hash = hash_password_async(request.new_password).await?;
        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query(
            r"
SELECT id::text AS id, user_id
FROM auth_security_tokens
WHERE purpose = 'password_reset' AND token_hash = $1 AND subject = $2
  AND consumed_at IS NULL AND expires_at > NOW() AND attempts < max_attempts
FOR UPDATE
",
        )
        .bind(hash.as_slice())
        .bind(&email)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| ApiError::bad_request("Invalid or expired password reset token"))?;
        let token_id: String = row.try_get("id")?;
        let user_id: i64 = row.try_get("user_id")?;
        let updated = sqlx::query(
            r"UPDATE users SET password_hash = $2, auth_generation = auth_generation + 1,
               updated_at = NOW() WHERE id = $1 AND LOWER(email) = LOWER($3)
               AND status = 'active' AND deleted_at IS NULL",
        )
        .bind(user_id)
        .bind(password_hash)
        .bind(&email)
        .execute(&mut *transaction)
        .await?;
        if updated.rows_affected() != 1 {
            consume_security_token_tx(&mut transaction, &token_id).await?;
            transaction.commit().await?;
            return Err(ApiError::bad_request(
                "Invalid or expired password reset token",
            ));
        }
        revoke_user_security_state(&mut transaction, user_id).await?;
        transaction.commit().await?;
        self.invalidate_user_auth_cache().await;
        Ok(MessageResponse {
            message: "Your password has been reset successfully. You can now log in with your new password.",
        })
    }

    pub(crate) async fn totp_status(&self, user: &UserRecord) -> Result<TotpStatus, ApiError> {
        Ok(TotpStatus {
            enabled: user.totp_enabled,
            enabled_at: user.totp_enabled_at.clone(),
            feature_enabled: self.setting_is_true("totp_enabled").await?,
        })
    }

    pub(crate) async fn totp_verification_method(
        &self,
    ) -> Result<TotpVerificationMethod, ApiError> {
        let email_enabled =
            self.setting_is_true("email_verify_enabled").await? && self.notifier.is_some();
        Ok(TotpVerificationMethod {
            method: if email_enabled { "email" } else { "password" },
            email_verify_enabled: email_enabled,
        })
    }

    pub(crate) async fn initiate_totp_setup(
        &self,
        user: UserRecord,
        request: TotpSetupRequest,
    ) -> Result<TotpSetupResponse, ApiError> {
        if !self.setting_is_true("totp_enabled").await? {
            return Err(ApiError::bad_request("TOTP feature is not enabled"));
        }
        if user.totp_enabled {
            return Err(ApiError::bad_request(
                "TOTP is already enabled for this account",
            ));
        }
        self.require_action_rate(
            &format!("totp-setup:{}", user.view.id),
            5,
            Duration::from_mins(5),
        )
        .await?;
        let email_verification =
            self.setting_is_true("email_verify_enabled").await? && self.notifier.is_some();
        if !email_verification {
            if request.password.is_empty()
                || !verify_password_async(request.password, user.password_hash.clone()).await?
            {
                return Err(ApiError::bad_request("Password is incorrect"));
            }
        } else if request.email_code.trim().is_empty() {
            return Err(ApiError::bad_request("Email verification code is required"));
        }
        let secret = generate_totp_secret();
        let encrypted = encrypt_secret(&self.config.security_key, &secret)
            .map_err(|error| ApiError::internal("encrypt TOTP setup secret", error))?;
        let setup_token = random_token("totp_setup_");
        let setup_hash = token_hash(&self.config.security_key, "totp_setup", &setup_token);
        let mut transaction = self.pool.begin().await?;
        if email_verification {
            self.consume_email_verification(
                &mut transaction,
                &user.view.email,
                request.email_code.trim(),
            )
            .await?;
        }
        consume_active_security_tokens(
            &mut transaction,
            Some(user.view.id),
            &user.view.email,
            "totp_setup",
        )
        .await?;
        insert_security_token(
            &mut transaction,
            SecurityTokenInsert {
                id: &Uuid::new_v4().to_string(),
                purpose: "totp_setup",
                hash: &setup_hash,
                user_id: Some(user.view.id),
                subject: &user.view.email,
                secret_ciphertext: Some(&encrypted),
                lifetime: TOTP_SESSION_TTL,
                max_attempts: SECURITY_MAX_ATTEMPTS,
            },
        )
        .await?;
        transaction.commit().await?;
        Ok(TotpSetupResponse {
            qr_code_url: totp_uri(&user.view.email, &secret),
            secret,
            setup_token,
            countdown: TOTP_SESSION_TTL.as_secs(),
        })
    }

    pub(crate) async fn enable_totp(
        &self,
        user_id: i64,
        request: TotpEnableRequest,
    ) -> Result<MessageResponse, ApiError> {
        validate_prefixed_token(&request.setup_token, "totp_setup_")?;
        self.require_action_rate(
            &format!("totp-enable:{user_id}"),
            10,
            Duration::from_mins(5),
        )
        .await?;
        let hash = token_hash(
            &self.config.security_key,
            "totp_setup",
            &request.setup_token,
        );
        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query(
            r"
SELECT id::text AS id, secret_ciphertext, attempts, max_attempts,
       expires_at > NOW() AS unexpired
FROM auth_security_tokens
WHERE purpose = 'totp_setup' AND user_id = $1 AND token_hash = $2
  AND consumed_at IS NULL
FOR UPDATE
",
        )
        .bind(user_id)
        .bind(hash.as_slice())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| ApiError::bad_request("TOTP setup session has expired"))?;
        let token_id: String = row.try_get("id")?;
        let attempts: i32 = row.try_get("attempts")?;
        let max_attempts: i32 = row.try_get("max_attempts")?;
        let unexpired: bool = row.try_get("unexpired")?;
        if !unexpired || attempts >= max_attempts {
            consume_security_token_tx(&mut transaction, &token_id).await?;
            transaction.commit().await?;
            return Err(ApiError::bad_request("TOTP setup session has expired"));
        }
        let encrypted: String = row.try_get("secret_ciphertext")?;
        let secret = decrypt_secret(&self.config.security_key, &encrypted)
            .map_err(|error| ApiError::internal("decrypt TOTP setup secret", error))?;
        if !validate_totp(&secret, request.totp_code.trim(), now_unix_seconds()?) {
            let exhausted = record_security_failure(&mut transaction, &token_id).await?;
            transaction.commit().await?;
            return if exhausted {
                Err(ApiError::too_many_requests(
                    "Too many verification attempts, please try again later",
                ))
            } else {
                Err(ApiError::bad_request("Invalid TOTP code"))
            };
        }
        let updated = sqlx::query(
            r"UPDATE users SET totp_secret_encrypted = $2, totp_enabled = TRUE,
               totp_enabled_at = NOW(), updated_at = NOW()
               WHERE id = $1 AND deleted_at IS NULL AND totp_enabled = FALSE",
        )
        .bind(user_id)
        .bind(encrypted)
        .execute(&mut *transaction)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(ApiError::bad_request(
                "TOTP is already enabled or the user is unavailable",
            ));
        }
        consume_security_token_tx(&mut transaction, &token_id).await?;
        transaction.commit().await?;
        Ok(MessageResponse {
            message: "TOTP enabled successfully",
        })
    }

    pub(crate) async fn disable_totp(
        &self,
        user: UserRecord,
        request: TotpDisableRequest,
    ) -> Result<MessageResponse, ApiError> {
        if !user.totp_enabled {
            return Err(ApiError::bad_request("TOTP is not set up for this account"));
        }
        self.require_action_rate(
            &format!("totp-disable:{}", user.view.id),
            5,
            Duration::from_mins(5),
        )
        .await?;
        let email_verification =
            self.setting_is_true("email_verify_enabled").await? && self.notifier.is_some();
        if !email_verification {
            if request.password.is_empty()
                || !verify_password_async(request.password, user.password_hash.clone()).await?
            {
                return Err(ApiError::bad_request("Password is incorrect"));
            }
        } else if request.email_code.trim().is_empty() {
            return Err(ApiError::bad_request("Email verification code is required"));
        }
        let mut transaction = self.pool.begin().await?;
        if email_verification {
            self.consume_email_verification(
                &mut transaction,
                &user.view.email,
                request.email_code.trim(),
            )
            .await?;
        }
        sqlx::query(
            r"UPDATE users SET totp_secret_encrypted = NULL, totp_enabled = FALSE,
               totp_enabled_at = NULL, auth_generation = auth_generation + 1,
               updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(user.view.id)
        .execute(&mut *transaction)
        .await?;
        revoke_user_security_state(&mut transaction, user.view.id).await?;
        transaction.commit().await?;
        self.invalidate_user_auth_cache().await;
        Ok(MessageResponse {
            message: "TOTP disabled successfully. Please log in again.",
        })
    }

    async fn create_totp_login_challenge(
        &self,
        user: &UserRecord,
    ) -> Result<TotpLoginChallenge, ApiError> {
        let raw_token = random_token("totp_login_");
        let hash = token_hash(&self.config.security_key, "totp_login", &raw_token);
        let mut transaction = self.pool.begin().await?;
        consume_active_security_tokens(
            &mut transaction,
            Some(user.view.id),
            &user.view.email,
            "totp_login",
        )
        .await?;
        insert_security_token(
            &mut transaction,
            SecurityTokenInsert {
                id: &Uuid::new_v4().to_string(),
                purpose: "totp_login",
                hash: &hash,
                user_id: Some(user.view.id),
                subject: &user.view.email,
                secret_ciphertext: None,
                lifetime: TOTP_SESSION_TTL,
                max_attempts: SECURITY_MAX_ATTEMPTS,
            },
        )
        .await?;
        transaction.commit().await?;
        Ok(TotpLoginChallenge {
            requires_2fa: true,
            temp_token: raw_token,
            user_email_masked: mask_email(&user.view.email),
        })
    }

    pub(crate) async fn issue_auth_response(
        &self,
        user: UserRecord,
    ) -> Result<AuthResponse, ApiError> {
        let version = token_version(&user);
        let access_token = self
            .jwt
            .issue(
                user.view.id,
                user.view.email.clone(),
                user.view.role.clone(),
                version,
            )
            .map_err(|error| ApiError::internal("issue access token", error))?;
        let refresh_token = self
            .insert_refresh_token(&user, Uuid::new_v4(), version)
            .await?;
        Ok(AuthResponse {
            access_token,
            refresh_token,
            expires_in: self.config.access_token_lifetime.as_secs(),
            token_type: "Bearer",
            user: user.view,
        })
    }

    async fn consume_email_verification(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        email: &str,
        code: &str,
    ) -> Result<(), ApiError> {
        if code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ApiError::bad_request("Invalid email verification code"));
        }
        let material = email_code_material(email, code);
        let hash = token_hash(&self.config.security_key, "email_verify", &material);
        let row = sqlx::query(
            r"
SELECT id::text AS id
FROM auth_security_tokens
WHERE purpose = 'email_verify' AND subject = $1 AND token_hash = $2
  AND consumed_at IS NULL AND expires_at > NOW() AND attempts < max_attempts
FOR UPDATE
",
        )
        .bind(email)
        .bind(hash.as_slice())
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or_else(|| ApiError::bad_request("Invalid or expired email verification code"))?;
        let token_id: String = row.try_get("id")?;
        consume_security_token_tx(transaction, &token_id).await
    }

    pub(crate) async fn consume_email_binding_code(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        user_id: i64,
        email: &str,
        code: &str,
    ) -> Result<(), ApiError> {
        self.consume_authenticated_email_code(transaction, user_id, email, code, "email_bind")
            .await
    }

    pub(crate) async fn consume_notification_email_code(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        user_id: i64,
        email: &str,
        code: &str,
    ) -> Result<(), ApiError> {
        self.consume_authenticated_email_code(transaction, user_id, email, code, "notify_email")
            .await
    }

    async fn consume_authenticated_email_code(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        user_id: i64,
        email: &str,
        code: &str,
        purpose: &'static str,
    ) -> Result<(), ApiError> {
        if code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ApiError::bad_request("Invalid email verification code"));
        }
        let material = email_code_material(email, code);
        let hash = token_hash(&self.config.security_key, purpose, &material);
        let row = sqlx::query(
            r"
SELECT id::text AS id
FROM auth_security_tokens
WHERE purpose = $1 AND user_id = $2 AND subject = $3 AND token_hash = $4
  AND consumed_at IS NULL AND expires_at > NOW() AND attempts < max_attempts
FOR UPDATE
",
        )
        .bind(purpose)
        .bind(user_id)
        .bind(email)
        .bind(hash.as_slice())
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or_else(|| ApiError::bad_request("Invalid or expired email verification code"))?;
        let token_id: String = row.try_get("id")?;
        consume_security_token_tx(transaction, &token_id).await
    }

    async fn login_is_limited(&self, identity: &str) -> Result<bool, ApiError> {
        let subject_hash = rate_limit_subject_hash("login_failure", identity);
        Ok(sqlx::query_scalar::<_, bool>(
            r"
            SELECT EXISTS (
                SELECT 1
                FROM auth_rate_limit_windows
                WHERE scope='login_failure' AND subject_hash=$1
                  AND expires_at>NOW() AND attempts >= $2
            )
            ",
        )
        .bind(subject_hash.as_slice())
        .bind(i64::from(self.config.login_max_failures.max(1)))
        .fetch_one(&self.pool)
        .await?)
    }

    async fn record_login_failure(&self, identity: &str) -> Result<(), ApiError> {
        let subject_hash = rate_limit_subject_hash("login_failure", identity);
        let window_seconds = rate_limit_window_seconds(self.config.login_failure_window);
        sqlx::query(
            r"
            INSERT INTO auth_rate_limit_windows (
                scope,subject_hash,attempts,window_started_at,expires_at,updated_at
            ) VALUES (
                'login_failure',$1,1,NOW(),NOW()+make_interval(secs=>$2::double precision),NOW()
            )
            ON CONFLICT (scope,subject_hash) DO UPDATE SET
                attempts=CASE
                    WHEN auth_rate_limit_windows.expires_at<=NOW() THEN 1
                    ELSE auth_rate_limit_windows.attempts+1
                END,
                window_started_at=CASE
                    WHEN auth_rate_limit_windows.expires_at<=NOW() THEN NOW()
                    ELSE auth_rate_limit_windows.window_started_at
                END,
                expires_at=CASE
                    WHEN auth_rate_limit_windows.expires_at<=NOW()
                    THEN NOW()+make_interval(secs=>$2::double precision)
                    ELSE auth_rate_limit_windows.expires_at
                END,
                updated_at=NOW()
            ",
        )
        .bind(subject_hash.as_slice())
        .bind(window_seconds)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn clear_login_failures(&self, identity: &str) -> Result<(), ApiError> {
        let subject_hash = rate_limit_subject_hash("login_failure", identity);
        sqlx::query(
            "DELETE FROM auth_rate_limit_windows WHERE scope='login_failure' AND subject_hash=$1",
        )
        .bind(subject_hash.as_slice())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn require_action_rate(
        &self,
        key: &str,
        limit: u32,
        window: Duration,
    ) -> Result<(), ApiError> {
        if !self.action_limiter.allow(key, limit, window) {
            return Err(ApiError::too_many_requests(
                "Too many requests, please try again later",
            ));
        }
        let subject_hash = rate_limit_subject_hash("auth_action", key);
        let window_seconds = rate_limit_window_seconds(window);
        let accepted = sqlx::query_scalar::<_, i32>(
            r"
            INSERT INTO auth_rate_limit_windows (
                scope,subject_hash,attempts,window_started_at,expires_at,updated_at
            ) VALUES (
                'auth_action',$1,1,NOW(),NOW()+make_interval(secs=>$2::double precision),NOW()
            )
            ON CONFLICT (scope,subject_hash) DO UPDATE SET
                attempts=CASE
                    WHEN auth_rate_limit_windows.expires_at<=NOW() THEN 1
                    ELSE auth_rate_limit_windows.attempts+1
                END,
                window_started_at=CASE
                    WHEN auth_rate_limit_windows.expires_at<=NOW() THEN NOW()
                    ELSE auth_rate_limit_windows.window_started_at
                END,
                expires_at=CASE
                    WHEN auth_rate_limit_windows.expires_at<=NOW()
                    THEN NOW()+make_interval(secs=>$2::double precision)
                    ELSE auth_rate_limit_windows.expires_at
                END,
                updated_at=NOW()
            WHERE auth_rate_limit_windows.expires_at<=NOW()
               OR auth_rate_limit_windows.attempts < $3
            RETURNING attempts
            ",
        )
        .bind(subject_hash.as_slice())
        .bind(window_seconds)
        .bind(i64::from(limit.max(1)))
        .fetch_optional(&self.pool)
        .await?;
        if accepted.is_some() {
            Ok(())
        } else {
            Err(ApiError::too_many_requests(
                "Too many requests, please try again later",
            ))
        }
    }

    pub(crate) async fn refresh(&self, raw_token: &str) -> Result<RefreshResponse, ApiError> {
        validate_refresh_token(raw_token)?;
        let token_hash = hash_refresh_token(raw_token);
        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query(
            r"
SELECT
    id::text AS session_id,
    user_id,
    family_id::text AS family_id,
    token_version,
    expires_at > NOW() AS unexpired,
    consumed_at IS NOT NULL AS used,
    revoked_at IS NOT NULL AS revoked
FROM auth_refresh_sessions
WHERE token_hash = $1
FOR UPDATE
",
        )
        .bind(token_hash.as_slice())
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(row) = row else {
            return Err(ApiError::unauthorized("Invalid refresh token"));
        };
        let family_id: String = row.try_get("family_id")?;
        let consumed: bool = row.try_get("used")?;
        let revoked: bool = row.try_get("revoked")?;
        let unexpired: bool = row.try_get("unexpired")?;
        if consumed || revoked || !unexpired {
            revoke_family(&mut transaction, &family_id, consumed || revoked).await?;
            transaction.commit().await?;
            return Err(ApiError::unauthorized("Invalid or expired refresh token"));
        }

        let user_id: i64 = row.try_get("user_id")?;
        let stored_token_version: i64 = row.try_get("token_version")?;
        let Some(user_row) = sqlx::query(USER_BY_ID_SQL)
            .bind(user_id)
            .fetch_optional(&mut *transaction)
            .await?
        else {
            revoke_family(&mut transaction, &family_id, false).await?;
            transaction.commit().await?;
            return Err(ApiError::unauthorized("Invalid refresh token"));
        };
        let user = user_from_row(&user_row)?;
        let current_token_version = token_version(&user);
        if user.view.status != "active" || stored_token_version != current_token_version {
            revoke_family(&mut transaction, &family_id, false).await?;
            transaction.commit().await?;
            return Err(ApiError::unauthorized("Refresh token has been revoked"));
        }
        if user.view.role != "admin"
            && setting_is_true_in_transaction(&mut transaction, "backend_mode_enabled").await?
        {
            return Err(ApiError::forbidden(
                "Backend mode is active. Only admin login is allowed.",
                "BACKEND_MODE_ADMIN_ONLY",
            ));
        }

        let access_token = self
            .jwt
            .issue(
                user.view.id,
                user.view.email.clone(),
                user.view.role.clone(),
                current_token_version,
            )
            .map_err(|error| ApiError::internal("issue refreshed access token", error))?;
        let replacement = generate_refresh_token();
        let replacement_hash = hash_refresh_token(&replacement);
        let replacement_id = Uuid::new_v4().to_string();
        let lifetime_seconds = duration_seconds_i64(self.config.refresh_token_lifetime)?;
        sqlx::query(
            r"
INSERT INTO auth_refresh_sessions (
    id, token_hash, user_id, family_id, token_version, expires_at
)
VALUES (
    $1::uuid, $2, $3, $4::uuid, $5,
    NOW() + make_interval(secs => $6::double precision)
)
",
        )
        .bind(&replacement_id)
        .bind(replacement_hash.as_slice())
        .bind(user.view.id)
        .bind(&family_id)
        .bind(current_token_version)
        .bind(lifetime_seconds)
        .execute(&mut *transaction)
        .await?;
        let updated = sqlx::query(
            r"
UPDATE auth_refresh_sessions
SET consumed_at = NOW(), replaced_by = $2::uuid
WHERE token_hash = $1 AND consumed_at IS NULL AND revoked_at IS NULL
",
        )
        .bind(token_hash.as_slice())
        .bind(&replacement_id)
        .execute(&mut *transaction)
        .await?;
        if updated.rows_affected() != 1 {
            revoke_family(&mut transaction, &family_id, true).await?;
            transaction.commit().await?;
            return Err(ApiError::unauthorized("Invalid refresh token"));
        }
        transaction.commit().await?;

        Ok(RefreshResponse {
            access_token,
            refresh_token: replacement,
            expires_in: self.config.access_token_lifetime.as_secs(),
            token_type: "Bearer",
        })
    }

    pub(crate) async fn authenticate(&self, headers: &HeaderMap) -> Result<UserRecord, ApiError> {
        let token = bearer_token(headers)?;
        let claims = self
            .jwt
            .validate(token)
            .map_err(|_| ApiError::unauthorized("Invalid or expired access token"))?;
        let user = self.user_for_claims(&claims).await?;
        if user.view.role != "admin" {
            ensure_backend_mode_user_access(
                &user.view.role,
                self.setting_is_true("backend_mode_enabled").await?,
            )?;
        }
        Ok(user)
    }

    async fn user_for_claims(&self, claims: &JwtClaims) -> Result<UserRecord, ApiError> {
        let Some(user) = self.find_user_by_id(claims.user_id).await? else {
            return Err(ApiError::unauthorized("Invalid access token"));
        };
        if user.view.status != "active" || token_version(&user) != claims.token_version {
            return Err(ApiError::unauthorized("Access token has been revoked"));
        }
        Ok(user)
    }

    pub(crate) async fn profile_for_user(&self, user: UserRecord) -> Result<UserProfile, ApiError> {
        let mut identities = self.identity_summaries(user.view.id).await?;
        if !identities.email.bound && !user.view.email.is_empty() {
            identities.email.bound = true;
            identities.email.bound_count = 1;
            identities.email.can_bind = false;
            identities.email.provider_key.clone_from(&user.view.email);
        }
        set_identity_unbind_flags(&mut identities);
        let bindings = identities.bindings();
        Ok(UserProfile {
            email_bound: identities.email.bound,
            linuxdo_bound: identities.linuxdo.bound,
            oidc_bound: identities.oidc.bound,
            wechat_bound: identities.wechat.bound,
            dingtalk_bound: identities.dingtalk.bound,
            auth_bindings: bindings.clone(),
            identity_bindings: bindings,
            identities,
            avatar_url: user.avatar_url,
            user: user.view,
        })
    }

    pub(crate) async fn profile_by_id(&self, user_id: i64) -> Result<UserProfile, ApiError> {
        let user = self
            .find_user_by_id(user_id)
            .await?
            .ok_or_else(|| ApiError::not_found("User not found"))?;
        self.profile_for_user(user).await
    }

    pub(crate) async fn current_user(&self, user: UserRecord) -> Result<CurrentUser, ApiError> {
        Ok(CurrentUser {
            profile: self.profile_for_user(user).await?,
            run_mode: self.config.run_mode.clone(),
        })
    }

    pub(crate) async fn update_profile(
        &self,
        user_id: i64,
        request: UpdateProfileRequest,
    ) -> Result<UserProfile, ApiError> {
        validate_profile_update(&request)?;
        let mut transaction = self.pool.begin().await?;
        let threshold = request.balance_notify_threshold.map(decimal_string);
        let result = sqlx::query(
            r"
UPDATE users
SET
    username = COALESCE($2, username),
    balance_notify_enabled = COALESCE($3, balance_notify_enabled),
    balance_notify_threshold = CASE
        WHEN $4::text IS NULL THEN balance_notify_threshold
        WHEN $4::numeric <= 0 THEN NULL
        ELSE $4::numeric
    END,
    updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL
",
        )
        .bind(user_id)
        .bind(request.username.as_deref().map(str::trim))
        .bind(request.balance_notify_enabled)
        .bind(threshold)
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() != 1 {
            return Err(ApiError::not_found("User not found"));
        }
        if let Some(avatar_url) = request.avatar_url {
            update_avatar(&mut transaction, user_id, &avatar_url).await?;
        }
        transaction.commit().await?;
        let user = self
            .find_user_by_id(user_id)
            .await?
            .ok_or_else(|| ApiError::not_found("User not found"))?;
        self.profile_for_user(user).await
    }

    pub(crate) async fn public_settings(&self) -> Result<PublicSettings, ApiError> {
        let mut query =
            QueryBuilder::<Postgres>::new("SELECT key, value FROM settings WHERE key IN (");
        let mut separated = query.separated(", ");
        for key in PUBLIC_SETTING_KEYS {
            separated.push_bind(*key);
        }
        separated.push_unseparated(")");
        let rows = query.build().fetch_all(&self.pool).await?;
        let mut values = HashMap::with_capacity(rows.len());
        for row in rows {
            values.insert(row.try_get("key")?, row.try_get("value")?);
        }
        Ok(public_settings_from_values(
            &values,
            &PublicRuntimeInfo {
                version: self.config.version.clone(),
                server_timezone: self.config.server_timezone.clone(),
                server_utc_offset: self.config.server_utc_offset.clone(),
            },
        ))
    }

    pub(crate) async fn validate_promo_code(
        &self,
        raw_code: &str,
    ) -> Result<PromoCodeValidation, ApiError> {
        if !self.setting_is_true("promo_code_enabled").await? {
            return Ok(PromoCodeValidation::invalid("PROMO_CODE_DISABLED"));
        }
        let code = raw_code.trim();
        if code.is_empty() {
            return Ok(PromoCodeValidation::invalid("PROMO_CODE_INVALID"));
        }
        let row = sqlx::query(
            r"
SELECT
    bonus_amount::double precision AS bonus_amount,
    max_uses,
    used_count,
    status,
    expires_at IS NOT NULL AND expires_at < NOW() AS expired
FROM promo_codes
WHERE code = $1
LIMIT 1
",
        )
        .bind(code)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(PromoCodeValidation::invalid("PROMO_CODE_NOT_FOUND"));
        };
        if row.try_get::<bool, _>("expired")? {
            return Ok(PromoCodeValidation::invalid("PROMO_CODE_EXPIRED"));
        }
        if row.try_get::<String, _>("status")? != "active" {
            return Ok(PromoCodeValidation::invalid("PROMO_CODE_DISABLED"));
        }
        let max_uses = row.try_get::<i32, _>("max_uses")?;
        if max_uses > 0 && row.try_get::<i32, _>("used_count")? >= max_uses {
            return Ok(PromoCodeValidation::invalid("PROMO_CODE_MAX_USED"));
        }
        Ok(PromoCodeValidation::valid(row.try_get("bonus_amount")?))
    }

    pub(crate) async fn validate_invitation_code(
        &self,
        raw_code: &str,
    ) -> Result<InvitationCodeValidation, ApiError> {
        if !self.setting_is_true("invitation_code_enabled").await? {
            return Ok(InvitationCodeValidation::invalid(
                "INVITATION_CODE_DISABLED",
            ));
        }
        let code = raw_code.trim();
        if code.is_empty() {
            return Ok(InvitationCodeValidation::invalid(
                "INVITATION_CODE_NOT_FOUND",
            ));
        }
        let row = sqlx::query("SELECT type, status FROM redeem_codes WHERE code = $1 LIMIT 1")
            .bind(code)
            .fetch_optional(&self.pool)
            .await?;
        let Some(row) = row else {
            return Ok(InvitationCodeValidation::invalid(
                "INVITATION_CODE_NOT_FOUND",
            ));
        };
        if row.try_get::<String, _>("type")? != "invitation" {
            return Ok(InvitationCodeValidation::invalid("INVITATION_CODE_INVALID"));
        }
        if row.try_get::<String, _>("status")? != "unused" {
            return Ok(InvitationCodeValidation::invalid("INVITATION_CODE_USED"));
        }
        Ok(InvitationCodeValidation::valid())
    }

    async fn find_user_by_id(&self, user_id: i64) -> Result<Option<UserRecord>, ApiError> {
        sqlx::query(USER_BY_ID_SQL)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?
            .as_ref()
            .map(user_from_row)
            .transpose()
    }

    async fn find_user_by_email(&self, email: &str) -> Result<Option<UserRecord>, ApiError> {
        sqlx::query(USER_BY_EMAIL_SQL)
            .bind(email)
            .fetch_optional(&self.pool)
            .await?
            .as_ref()
            .map(user_from_row)
            .transpose()
    }

    async fn insert_refresh_token(
        &self,
        user: &UserRecord,
        family_id: Uuid,
        token_version: i64,
    ) -> Result<String, ApiError> {
        let lifetime_seconds = duration_seconds_i64(self.config.refresh_token_lifetime)?;
        for _ in 0..3 {
            let raw_token = generate_refresh_token();
            let token_hash = hash_refresh_token(&raw_token);
            let session_id = Uuid::new_v4().to_string();
            let result = sqlx::query(
                r"
INSERT INTO auth_refresh_sessions (
    id, token_hash, user_id, family_id, token_version, expires_at
)
VALUES (
    $1::uuid, $2, $3, $4::uuid, $5,
    NOW() + make_interval(secs => $6::double precision)
)
",
            )
            .bind(session_id)
            .bind(token_hash.as_slice())
            .bind(user.view.id)
            .bind(family_id.to_string())
            .bind(token_version)
            .bind(lifetime_seconds)
            .execute(&self.pool)
            .await;
            match result {
                Ok(_) => return Ok(raw_token),
                Err(error) if is_unique_violation(&error) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(ApiError::internal(
            "generate refresh token",
            "repeated hash collision",
        ))
    }

    async fn setting_is_true(&self, key: &str) -> Result<bool, ApiError> {
        let value = sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key = $1")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        Ok(value.is_some_and(|value| value.trim().eq_ignore_ascii_case("true")))
    }

    async fn verify_turnstile(&self, token: &str) -> Result<(), ApiError> {
        let rows = sqlx::query(
            "SELECT key, value FROM settings WHERE key IN ('turnstile_enabled', 'turnstile_secret_key')",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut enabled = false;
        let mut secret = String::new();
        for row in rows {
            let key: String = row.try_get("key")?;
            let value: String = row.try_get("value")?;
            match key.as_str() {
                "turnstile_enabled" => enabled = value.trim().eq_ignore_ascii_case("true"),
                "turnstile_secret_key" => secret = value,
                _ => {}
            }
        }
        if !enabled {
            return Ok(());
        }
        if token.trim().is_empty() {
            return Err(ApiError::bad_request("Turnstile verification is required"));
        }
        if secret.trim().is_empty() {
            return Err(ApiError::internal(
                "verify Turnstile",
                "Turnstile is enabled without a secret key",
            ));
        }
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("secret", secret.trim())
            .append_pair("response", token.trim())
            .finish();
        let response = self
            .http_client
            .post(TURNSTILE_VERIFY_URL)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(|error| ApiError::internal("call Turnstile verification", error))?;
        let result: TurnstileResult = response
            .json()
            .await
            .map_err(|error| ApiError::internal("decode Turnstile verification", error))?;
        if result.success {
            Ok(())
        } else {
            Err(ApiError::bad_request("Turnstile verification failed"))
        }
    }

    async fn identity_summaries(&self, user_id: i64) -> Result<IdentitySummarySet, ApiError> {
        let rows = sqlx::query(
            r#"
SELECT
    provider_type,
    COUNT(*)::bigint AS bound_count,
    COALESCE(MAX(provider_key), '') AS provider_key,
    COALESCE(MAX(metadata ->> 'display_name'), '') AS display_name,
    to_char(MAX(verified_at) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS verified_at
FROM auth_identities
WHERE user_id = $1
GROUP BY provider_type
"#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        let mut summaries = IdentitySummarySet::empty();
        for row in rows {
            let provider: String = row.try_get("provider_type")?;
            let summary = IdentitySummary {
                provider: provider.clone(),
                bound: true,
                bound_count: row.try_get("bound_count")?,
                display_name: row.try_get("display_name")?,
                subject_hint: String::new(),
                provider_key: row.try_get("provider_key")?,
                verified_at: row.try_get("verified_at")?,
                bind_start_path: String::new(),
                can_bind: false,
                can_unbind: false,
            };
            match provider.as_str() {
                "email" => summaries.email = summary,
                "linuxdo" => summaries.linuxdo = summary,
                "oidc" => summaries.oidc = summary,
                "wechat" => summaries.wechat = summary,
                "dingtalk" => summaries.dingtalk = summary,
                _ => {}
            }
        }
        Ok(summaries)
    }
}

impl ControlApiState {
    pub(crate) async fn list_api_keys(
        &self,
        user_id: i64,
        query: &ApiKeyListQuery,
    ) -> Result<Paginated<ApiKeyView>, ApiError> {
        let pagination = query.pagination();
        let status = normalize_status_filter(query.status.as_deref())?;
        let search = query
            .search
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.chars().take(100).collect::<String>());
        let total = sqlx::query_scalar::<_, i64>(
            r"
SELECT COUNT(*)::bigint
FROM api_keys k
WHERE k.user_id = $1
  AND k.deleted_at IS NULL
  AND ($2::text IS NULL OR k.status = $2)
  AND ($3::bigint IS NULL OR k.group_id = $3)
  AND (
      $4::text IS NULL
      OR k.name ILIKE '%' || $4 || '%'
      OR k.key ILIKE '%' || $4 || '%'
  )
",
        )
        .bind(user_id)
        .bind(status)
        .bind(query.group_id)
        .bind(search.as_deref())
        .fetch_one(&self.pool)
        .await?;

        let (order_field, order_direction) = query.order_by();
        let list_sql = format!(
            "SELECT {API_KEY_PROJECTION} \
             FROM api_keys k \
             WHERE k.user_id = $1 \
               AND k.deleted_at IS NULL \
               AND ($2::text IS NULL OR k.status = $2) \
               AND ($3::bigint IS NULL OR k.group_id = $3) \
               AND ($4::text IS NULL OR k.name ILIKE '%' || $4 || '%' OR k.key ILIKE '%' || $4 || '%') \
             ORDER BY k.{order_field} {order_direction}, k.id {order_direction} \
             LIMIT $5 OFFSET $6"
        );
        let rows = sqlx::query(&list_sql)
            .bind(user_id)
            .bind(status)
            .bind(query.group_id)
            .bind(search.as_deref())
            .bind(i64::from(pagination.page_size))
            .bind(pagination.offset)
            .fetch_all(&self.pool)
            .await?;
        let mut items = rows
            .iter()
            .map(|row| api_key_from_row(row, false))
            .collect::<Result<Vec<_>, _>>()?;
        self.enrich_api_key_concurrency(&mut items);
        Ok(Paginated::new(items, total, pagination))
    }

    pub(crate) async fn get_api_key(
        &self,
        user_id: i64,
        key_id: i64,
    ) -> Result<ApiKeyView, ApiError> {
        if key_id <= 0 {
            return Err(ApiError::bad_request("Invalid API key ID"));
        }
        self.find_api_key(user_id, key_id, false)
            .await?
            .ok_or_else(|| ApiError::not_found("API key not found"))
    }

    pub(crate) async fn create_api_key(
        &self,
        user_id: i64,
        request: CreateApiKeyRequest,
    ) -> Result<ApiKeyView, ApiError> {
        let name = request.name.trim();
        if name.is_empty() || name.len() > 100 {
            return Err(ApiError::bad_request(
                "API key name must contain 1 to 100 characters",
            ));
        }
        validate_ip_patterns(&request.ip_whitelist)?;
        validate_ip_patterns(&request.ip_blacklist)?;
        validate_non_negative(request.quota, "Quota")?;
        validate_non_negative(request.rate_limit_5h, "5-hour rate limit")?;
        validate_non_negative(request.rate_limit_1d, "Daily rate limit")?;
        validate_non_negative(request.rate_limit_7d, "Weekly rate limit")?;
        if request
            .expires_in_days
            .is_some_and(|days| !(0..=3_650).contains(&days))
        {
            return Err(ApiError::bad_request(
                "Expiration must be between 0 and 3650 days",
            ));
        }
        if let Some(group_id) = request.group_id {
            self.ensure_group_allowed(user_id, group_id).await?;
        }

        let custom_key = request
            .custom_key
            .as_deref()
            .map(str::trim)
            .filter(|key| !key.is_empty());
        if let Some(key) = custom_key {
            validate_custom_api_key(key)?;
        }
        let whitelist = serde_json::to_string(&request.ip_whitelist)
            .map_err(|error| ApiError::internal("encode IP whitelist", error))?;
        let blacklist = serde_json::to_string(&request.ip_blacklist)
            .map_err(|error| ApiError::internal("encode IP blacklist", error))?;
        let quota = decimal_string(request.quota.unwrap_or(0.0));
        let five_hour_limit = decimal_string(request.rate_limit_5h.unwrap_or(0.0));
        let daily_limit = decimal_string(request.rate_limit_1d.unwrap_or(0.0));
        let weekly_limit = decimal_string(request.rate_limit_7d.unwrap_or(0.0));

        for _ in 0..3 {
            let key = custom_key.map_or_else(generate_api_key, str::to_owned);
            let mut transaction = self.pool.begin().await?;
            let result = sqlx::query_scalar::<_, i64>(
                r"
INSERT INTO api_keys (
    user_id, key, name, group_id, status,
    ip_whitelist, ip_blacklist, quota, expires_at,
    rate_limit_5h, rate_limit_1d, rate_limit_7d
)
VALUES (
    $1, $2, $3, $4, 'active',
    $5::jsonb, $6::jsonb, $7::numeric,
    CASE WHEN $8::integer IS NULL OR $8 <= 0
         THEN NULL
         ELSE NOW() + make_interval(days => $8)
    END,
    $9::numeric, $10::numeric, $11::numeric
)
RETURNING id
",
            )
            .bind(user_id)
            .bind(&key)
            .bind(name)
            .bind(request.group_id)
            .bind(&whitelist)
            .bind(&blacklist)
            .bind(&quota)
            .bind(request.expires_in_days)
            .bind(&five_hour_limit)
            .bind(&daily_limit)
            .bind(&weekly_limit)
            .fetch_one(&mut *transaction)
            .await;
            match result {
                Ok(id) => {
                    let select_sql = format!(
                        "SELECT {API_KEY_PROJECTION} \
                         FROM api_keys k \
                         WHERE k.id = $1 AND k.user_id = $2 AND k.deleted_at IS NULL \
                         LIMIT 1"
                    );
                    let row = sqlx::query(&select_sql)
                        .bind(id)
                        .bind(user_id)
                        .fetch_one(&mut *transaction)
                        .await?;
                    let mut created = api_key_from_row(&row, true)?;
                    transaction.commit().await?;
                    self.invalidate_api_key_cache(id, Some(&key)).await;
                    self.enrich_api_key_concurrency(std::slice::from_mut(&mut created));
                    return Ok(created);
                }
                Err(error) if is_unique_violation(&error) && custom_key.is_some() => {
                    return Err(ApiError::conflict(
                        "API key already exists",
                        "API_KEY_EXISTS",
                    ));
                }
                Err(error) if is_unique_violation(&error) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(ApiError::internal(
            "generate API key",
            "repeated key collision",
        ))
    }

    pub(crate) async fn update_api_key(
        &self,
        user_id: i64,
        key_id: i64,
        request: UpdateApiKeyRequest,
    ) -> Result<ApiKeyView, ApiError> {
        if key_id <= 0 {
            return Err(ApiError::bad_request("Invalid API key ID"));
        }
        if request
            .name
            .as_deref()
            .is_some_and(|name| name.trim().len() > 100)
        {
            return Err(ApiError::bad_request(
                "API key name must not exceed 100 characters",
            ));
        }
        if let Some(status) = request.status.as_deref()
            && !matches!(status, "active" | "inactive")
        {
            return Err(ApiError::bad_request(
                "API key status must be active or inactive",
            ));
        }
        if let Some(patterns) = request.ip_whitelist.as_deref() {
            validate_ip_patterns(patterns)?;
        }
        if let Some(patterns) = request.ip_blacklist.as_deref() {
            validate_ip_patterns(patterns)?;
        }
        validate_non_negative(request.quota, "Quota")?;
        validate_non_negative(request.rate_limit_5h, "5-hour rate limit")?;
        validate_non_negative(request.rate_limit_1d, "Daily rate limit")?;
        validate_non_negative(request.rate_limit_7d, "Weekly rate limit")?;
        if let Some(expires_at) = request.expires_at.as_deref()
            && !expires_at.trim().is_empty()
            && chrono::DateTime::parse_from_rfc3339(expires_at.trim()).is_err()
        {
            return Err(ApiError::bad_request(
                "Expiration must be an RFC 3339 timestamp",
            ));
        }
        if let Some(group_id) = request.group_id {
            self.ensure_group_allowed(user_id, group_id).await?;
        }

        let mut transaction = self.pool.begin().await?;
        let raw_key = sqlx::query_scalar::<_, String>(
            "SELECT key FROM api_keys WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL FOR UPDATE",
        )
        .bind(key_id)
        .bind(user_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| ApiError::not_found("API key not found"))?;

        let mut update = QueryBuilder::<Postgres>::new("UPDATE api_keys SET updated_at = NOW()");
        if let Some(name) = request
            .name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            update.push(", name = ").push_bind(name);
        }
        if let Some(group_id) = request.group_id {
            update.push(", group_id = ").push_bind(group_id);
        }
        if let Some(status) = request.status.as_deref() {
            update.push(", status = ").push_bind(status);
        }
        if let Some(patterns) = request.ip_whitelist.as_ref() {
            let json = serde_json::to_string(patterns)
                .map_err(|error| ApiError::internal("encode IP whitelist", error))?;
            update
                .push(", ip_whitelist = ")
                .push_bind(json)
                .push("::jsonb");
        }
        if let Some(patterns) = request.ip_blacklist.as_ref() {
            let json = serde_json::to_string(patterns)
                .map_err(|error| ApiError::internal("encode IP blacklist", error))?;
            update
                .push(", ip_blacklist = ")
                .push_bind(json)
                .push("::jsonb");
        }
        if let Some(quota) = request.quota {
            update
                .push(", quota = ")
                .push_bind(decimal_string(quota))
                .push("::numeric");
        }
        if request.reset_quota.unwrap_or(false) {
            update.push(", quota_used = 0");
        }
        if let Some(expires_at) = request.expires_at.as_deref() {
            if expires_at.trim().is_empty() {
                update.push(", expires_at = NULL");
            } else {
                update
                    .push(", expires_at = ")
                    .push_bind(expires_at.trim())
                    .push("::timestamptz");
            }
        }
        if let Some(limit) = request.rate_limit_5h {
            update
                .push(", rate_limit_5h = ")
                .push_bind(decimal_string(limit))
                .push("::numeric");
        }
        if let Some(limit) = request.rate_limit_1d {
            update
                .push(", rate_limit_1d = ")
                .push_bind(decimal_string(limit))
                .push("::numeric");
        }
        if let Some(limit) = request.rate_limit_7d {
            update
                .push(", rate_limit_7d = ")
                .push_bind(decimal_string(limit))
                .push("::numeric");
        }
        if request.reset_rate_limit_usage.unwrap_or(false) {
            update.push(
                ", usage_5h = 0, usage_1d = 0, usage_7d = 0, \
                 window_5h_start = NULL, window_1d_start = NULL, window_7d_start = NULL",
            );
        }
        update
            .push(" WHERE id = ")
            .push_bind(key_id)
            .push(" AND user_id = ")
            .push_bind(user_id)
            .push(" AND deleted_at IS NULL");
        update.build().execute(&mut *transaction).await?;
        transaction.commit().await?;
        self.invalidate_api_key_cache(key_id, Some(&raw_key)).await;
        self.find_api_key(user_id, key_id, false)
            .await?
            .ok_or_else(|| ApiError::not_found("API key not found"))
    }

    pub(crate) async fn delete_api_key(&self, user_id: i64, key_id: i64) -> Result<(), ApiError> {
        if key_id <= 0 {
            return Err(ApiError::bad_request("Invalid API key ID"));
        }
        let raw_key = sqlx::query_scalar::<_, String>(
            r"
UPDATE api_keys
SET deleted_at = NOW(), updated_at = NOW()
WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL
RETURNING key
",
        )
        .bind(key_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        let raw_key = raw_key.ok_or_else(|| ApiError::not_found("API key not found"))?;
        self.invalidate_api_key_cache(key_id, Some(&raw_key)).await;
        Ok(())
    }

    async fn find_api_key(
        &self,
        user_id: i64,
        key_id: i64,
        expose_key: bool,
    ) -> Result<Option<ApiKeyView>, ApiError> {
        let sql = format!(
            "SELECT {API_KEY_PROJECTION} \
             FROM api_keys k \
             WHERE k.id = $1 AND k.user_id = $2 AND k.deleted_at IS NULL \
             LIMIT 1"
        );
        let mut view = sqlx::query(&sql)
            .bind(key_id)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?
            .as_ref()
            .map(|row| api_key_from_row(row, expose_key))
            .transpose()?;
        if let Some(view) = view.as_mut() {
            self.enrich_api_key_concurrency(std::slice::from_mut(view));
        }
        Ok(view)
    }

    async fn ensure_group_allowed(&self, user_id: i64, group_id: i64) -> Result<(), ApiError> {
        if group_id <= 0 {
            return Err(ApiError::bad_request("Invalid group ID"));
        }
        let allowed = sqlx::query_scalar::<_, bool>(
            r"
SELECT EXISTS (
    SELECT 1
    FROM groups g
    WHERE g.id = $2
      AND g.deleted_at IS NULL
      AND g.status = 'active'
      AND (
          (
              g.subscription_type = 'subscription'
              AND EXISTS (
                  SELECT 1
                  FROM user_subscriptions subscription
                  WHERE subscription.user_id = $1
                    AND subscription.group_id = g.id
                    AND subscription.status = 'active'
                    AND subscription.starts_at <= NOW()
                    AND subscription.expires_at > NOW()
              )
          )
          OR
          (
              g.subscription_type <> 'subscription'
              AND (
                  NOT g.is_exclusive
                  OR EXISTS (
                      SELECT 1
                      FROM user_allowed_groups allowed_group
                      WHERE allowed_group.user_id = $1
                        AND allowed_group.group_id = g.id
                  )
              )
          )
      )
)
",
        )
        .bind(user_id)
        .bind(group_id)
        .fetch_one(&self.pool)
        .await?;
        if allowed {
            Ok(())
        } else {
            Err(ApiError::forbidden(
                "User is not allowed to bind this group",
                "GROUP_NOT_ALLOWED",
            ))
        }
    }

    fn enrich_api_key_concurrency(&self, views: &mut [ApiKeyView]) {
        let Some(invalidator) = self.auth_cache_invalidator.as_ref() else {
            return;
        };
        for view in views {
            view.current_concurrency =
                i32::try_from(invalidator.api_key_current_concurrency(view.id)).unwrap_or(i32::MAX);
        }
    }

    async fn invalidate_api_key_cache(&self, api_key_id: i64, raw_key: Option<&str>) {
        let Some(invalidator) = self.auth_cache_invalidator.as_ref() else {
            return;
        };
        if let Err(error) = invalidator.invalidate_api_key(api_key_id, raw_key).await {
            tracing::warn!(
                error = %error,
                api_key_id,
                "API key was committed but cross-instance auth-cache invalidation failed"
            );
        }
    }

    pub(crate) async fn invalidate_user_auth_cache(&self) {
        let Some(invalidator) = self.auth_cache_invalidator.as_ref() else {
            return;
        };
        if let Err(error) = invalidator.invalidate_auth_cache().await {
            tracing::warn!(
                error = %error,
                "user security state was committed but auth-cache invalidation failed"
            );
        }
    }
}

fn normalize_oauth_provider(provider: &str) -> Result<&str, ApiError> {
    match provider.trim().to_ascii_lowercase().as_str() {
        "github" => Ok("github"),
        "google" => Ok("google"),
        "linuxdo" => Ok("linuxdo"),
        "oidc" => Ok("oidc"),
        "wechat" => Ok("wechat"),
        "dingtalk" => Ok("dingtalk"),
        _ => Err(ApiError::bad_request("OAuth provider is not supported")),
    }
}

fn merge_oauth_metadata(
    mut metadata: serde_json::Value,
    email: &str,
    username: &str,
    display_name: &str,
    avatar_url: &str,
    issuer: Option<&str>,
) -> serde_json::Value {
    if !metadata.is_object() {
        metadata = serde_json::json!({});
    }
    if let Some(object) = metadata.as_object_mut() {
        object.insert("email".to_owned(), serde_json::json!(email));
        object.insert("email_verified".to_owned(), serde_json::json!(true));
        object.insert("username".to_owned(), serde_json::json!(username));
        if !display_name.is_empty() {
            object.insert(
                "suggested_display_name".to_owned(),
                serde_json::json!(display_name),
            );
        }
        if !avatar_url.is_empty() {
            object.insert(
                "suggested_avatar_url".to_owned(),
                serde_json::json!(avatar_url),
            );
        }
        if let Some(issuer) = issuer.map(str::trim).filter(|value| !value.is_empty()) {
            object.insert("issuer".to_owned(), serde_json::json!(issuer));
        }
    }
    metadata
}

async fn upsert_oauth_identity_channel(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i64,
    provider: &str,
    provider_key: &str,
    provider_subject: &str,
    metadata: &serde_json::Value,
) -> Result<(), ApiError> {
    let channel = metadata
        .get("channel")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    let channel_app_id = metadata
        .get("channel_app_id")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    let channel_subject = metadata
        .get("channel_subject")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    if channel.is_empty() || channel_app_id.is_empty() || channel_subject.is_empty() {
        return Ok(());
    }
    if channel.len() > 20 || channel_app_id.len() > 255 || channel_subject.len() > 255 {
        return Err(ApiError::bad_request("OAuth channel identity is invalid"));
    }
    let identity_id = sqlx::query_scalar::<_, i64>(
        r"
SELECT id
FROM auth_identities
WHERE user_id = $1 AND provider_type = $2 AND provider_key = $3 AND provider_subject = $4
ORDER BY id
LIMIT 1
",
    )
    .bind(user_id)
    .bind(provider)
    .bind(provider_key)
    .bind(provider_subject)
    .fetch_one(&mut **transaction)
    .await?;
    sqlx::query(
        r"
INSERT INTO auth_identity_channels (
    identity_id, provider_type, provider_key, channel,
    channel_app_id, channel_subject, metadata
)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (provider_type, provider_key, channel, channel_app_id, channel_subject)
DO UPDATE SET
    identity_id = EXCLUDED.identity_id,
    metadata = EXCLUDED.metadata,
    updated_at = NOW()
",
    )
    .bind(identity_id)
    .bind(provider)
    .bind(provider_key)
    .bind(channel)
    .bind(channel_app_id)
    .bind(channel_subject)
    .bind(metadata)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn ensure_oauth_user_can_login(
    role: &str,
    status: &str,
    backend_mode_enabled: bool,
) -> Result<(), ApiError> {
    if status != "active" {
        return Err(ApiError::unauthorized("User account is not active"));
    }
    if backend_mode_enabled && role != "admin" {
        return Err(ApiError::forbidden(
            "Backend mode is active. Only admin login is allowed.",
            "BACKEND_MODE_ADMIN_ONLY",
        ));
    }
    Ok(())
}

fn ensure_backend_mode_user_access(role: &str, backend_mode_enabled: bool) -> Result<(), ApiError> {
    if backend_mode_enabled && role != "admin" {
        return Err(ApiError::forbidden(
            "Backend mode is active. User self-service is disabled.",
            "BACKEND_MODE_ADMIN_ONLY",
        ));
    }
    Ok(())
}

async fn consume_oauth_invitation_precheck(
    transaction: &mut Transaction<'_, Postgres>,
    invitation_required: bool,
    raw_code: &str,
) -> Result<Option<i64>, ApiError> {
    if !invitation_required {
        return Ok(None);
    }
    let code = raw_code.trim();
    if code.is_empty() {
        return Err(ApiError::bad_request("Invitation code is required"));
    }
    let invitation_id = sqlx::query_scalar::<_, i64>(
        r"
SELECT id
FROM redeem_codes
WHERE code = $1
  AND type = 'invitation'
  AND status = 'unused'
  AND (expires_at IS NULL OR expires_at > NOW())
FOR UPDATE
",
    )
    .bind(code)
    .fetch_optional(&mut **transaction)
    .await?;
    invitation_id
        .map(Some)
        .ok_or_else(|| ApiError::bad_request("Invitation code is invalid or already used"))
}

async fn apply_oauth_promo_code(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i64,
    raw_code: &str,
) -> Result<(), ApiError> {
    let code = raw_code.trim();
    if code.is_empty() {
        return Ok(());
    }
    let promo = sqlx::query(
        r"
SELECT id, bonus_amount::text AS bonus_amount
FROM promo_codes
WHERE code = $1
  AND status = 'active'
  AND (expires_at IS NULL OR expires_at > NOW())
  AND (max_uses = 0 OR used_count < max_uses)
FOR UPDATE
",
    )
    .bind(code)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(promo) = promo else {
        return Ok(());
    };
    let promo_id: i64 = promo.try_get("id")?;
    let bonus_amount: String = promo.try_get("bonus_amount")?;
    sqlx::query(
        r"
INSERT INTO promo_code_usages (promo_code_id, user_id, bonus_amount)
VALUES ($1, $2, $3::numeric)
ON CONFLICT (promo_code_id, user_id) DO NOTHING
",
    )
    .bind(promo_id)
    .bind(user_id)
    .bind(&bonus_amount)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE promo_codes SET used_count = used_count + 1, updated_at = NOW() WHERE id = $1",
    )
    .bind(promo_id)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE users SET balance = balance + $2::numeric, updated_at = NOW() WHERE id = $1",
    )
    .bind(user_id)
    .bind(bonus_amount)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn initialize_oauth_affiliate(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i64,
    raw_inviter_code: &str,
) -> Result<(), ApiError> {
    let enabled = sqlx::query_scalar::<_, String>(
        "SELECT value FROM settings WHERE key = 'affiliate_enabled'",
    )
    .fetch_optional(&mut **transaction)
    .await?
    .is_some_and(|value| value.trim().eq_ignore_ascii_case("true"));
    if !enabled {
        return Ok(());
    }
    sqlx::query(
        r"
INSERT INTO user_affiliates (user_id, aff_code)
VALUES (
    $1,
    UPPER(SUBSTRING(MD5($1::text || clock_timestamp()::text || random()::text), 1, 12))
)
ON CONFLICT (user_id) DO NOTHING
",
    )
    .bind(user_id)
    .execute(&mut **transaction)
    .await?;
    let inviter_code = raw_inviter_code.trim().to_ascii_uppercase();
    if inviter_code.is_empty()
        || inviter_code.len() > 32
        || !inviter_code.bytes().all(|byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
        })
    {
        return Ok(());
    }
    let inviter_id = sqlx::query_scalar::<_, i64>(
        "SELECT user_id FROM user_affiliates WHERE aff_code = $1 AND user_id <> $2 FOR UPDATE",
    )
    .bind(inviter_code)
    .bind(user_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(inviter_id) = inviter_id else {
        return Ok(());
    };
    let bound = sqlx::query(
        "UPDATE user_affiliates SET inviter_id = $2, updated_at = NOW() WHERE user_id = $1 AND inviter_id IS NULL",
    )
    .bind(user_id)
    .bind(inviter_id)
    .execute(&mut **transaction)
    .await?;
    if bound.rows_affected() == 1 {
        sqlx::query(
            "UPDATE user_affiliates SET aff_count = aff_count + 1, updated_at = NOW() WHERE user_id = $1",
        )
        .bind(inviter_id)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

const API_KEY_PROJECTION: &str = r#"
    k.id,
    k.user_id,
    k.key,
    k.name,
    k.group_id,
    k.status,
    COALESCE(k.ip_whitelist, '[]'::jsonb)::text AS ip_whitelist,
    COALESCE(k.ip_blacklist, '[]'::jsonb)::text AS ip_blacklist,
    to_char(k.last_used_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS last_used_at,
    NULL::text AS last_used_ip,
    k.quota::double precision AS quota,
    k.quota_used::double precision AS quota_used,
    to_char(k.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS expires_at,
    to_char(k.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at,
    to_char(k.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS updated_at,
    0::integer AS current_concurrency,
    k.rate_limit_5h::double precision AS rate_limit_5h,
    k.rate_limit_1d::double precision AS rate_limit_1d,
    k.rate_limit_7d::double precision AS rate_limit_7d,
    CASE WHEN k.window_5h_start IS NULL OR k.window_5h_start + INTERVAL '5 hours' <= NOW()
         THEN 0 ELSE k.usage_5h END::double precision AS usage_5h,
    CASE WHEN k.window_1d_start IS NULL OR k.window_1d_start + INTERVAL '1 day' <= NOW()
         THEN 0 ELSE k.usage_1d END::double precision AS usage_1d,
    CASE WHEN k.window_7d_start IS NULL OR k.window_7d_start + INTERVAL '7 days' <= NOW()
         THEN 0 ELSE k.usage_7d END::double precision AS usage_7d,
    CASE WHEN k.window_5h_start + INTERVAL '5 hours' > NOW()
         THEN to_char(k.window_5h_start AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END AS window_5h_start,
    CASE WHEN k.window_1d_start + INTERVAL '1 day' > NOW()
         THEN to_char(k.window_1d_start AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END AS window_1d_start,
    CASE WHEN k.window_7d_start + INTERVAL '7 days' > NOW()
         THEN to_char(k.window_7d_start AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END AS window_7d_start,
    CASE WHEN k.window_5h_start + INTERVAL '5 hours' > NOW()
         THEN to_char((k.window_5h_start + INTERVAL '5 hours') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END AS reset_5h_at,
    CASE WHEN k.window_1d_start + INTERVAL '1 day' > NOW()
         THEN to_char((k.window_1d_start + INTERVAL '1 day') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END AS reset_1d_at,
    CASE WHEN k.window_7d_start + INTERVAL '7 days' > NOW()
         THEN to_char((k.window_7d_start + INTERVAL '7 days') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END AS reset_7d_at
"#;

fn api_key_from_row(row: &PgRow, expose_key: bool) -> Result<ApiKeyView, ApiError> {
    let whitelist: String = row.try_get("ip_whitelist")?;
    let blacklist: String = row.try_get("ip_blacklist")?;
    Ok(ApiKeyView {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        key: expose_key.then(|| row.try_get("key")).transpose()?,
        name: row.try_get("name")?,
        group_id: row.try_get("group_id")?,
        status: row.try_get("status")?,
        ip_whitelist: serde_json::from_str(&whitelist).unwrap_or_default(),
        ip_blacklist: serde_json::from_str(&blacklist).unwrap_or_default(),
        last_used_at: row.try_get("last_used_at")?,
        last_used_ip: row.try_get("last_used_ip")?,
        quota: row.try_get("quota")?,
        quota_used: row.try_get("quota_used")?,
        expires_at: row.try_get("expires_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        current_concurrency: row.try_get("current_concurrency")?,
        rate_limit_5h: row.try_get("rate_limit_5h")?,
        rate_limit_1d: row.try_get("rate_limit_1d")?,
        rate_limit_7d: row.try_get("rate_limit_7d")?,
        usage_5h: row.try_get("usage_5h")?,
        usage_1d: row.try_get("usage_1d")?,
        usage_7d: row.try_get("usage_7d")?,
        window_5h_start: row.try_get("window_5h_start")?,
        window_1d_start: row.try_get("window_1d_start")?,
        window_7d_start: row.try_get("window_7d_start")?,
        reset_5h_at: row.try_get("reset_5h_at")?,
        reset_1d_at: row.try_get("reset_1d_at")?,
        reset_7d_at: row.try_get("reset_7d_at")?,
    })
}

fn normalize_status_filter(status: Option<&str>) -> Result<Option<&str>, ApiError> {
    match status.map(str::trim).filter(|status| !status.is_empty()) {
        None => Ok(None),
        Some(status @ ("active" | "inactive" | "expired" | "quota_exhausted")) => Ok(Some(status)),
        Some(_) => Err(ApiError::bad_request("Invalid API key status filter")),
    }
}

fn generate_api_key() -> String {
    let mut random = [0_u8; 32];
    OsRng.fill_bytes(&mut random);
    format!("sk-{}", hex::encode(random))
}

/// Validates the existing custom API-key contract.
///
/// # Errors
///
/// Returns a bad-request error when the key is too short, too long, or contains
/// characters outside ASCII letters, digits, `_`, and `-`.
pub fn validate_custom_api_key(key: &str) -> Result<(), ApiError> {
    if !(16..=128).contains(&key.len()) {
        return Err(ApiError::bad_request(
            "API key must contain between 16 and 128 characters",
        ));
    }
    if !key
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(ApiError::bad_request(
            "API key can only contain letters, numbers, underscores, and hyphens",
        ));
    }
    Ok(())
}

/// Validates IP addresses and CIDR networks used by an API key ACL.
///
/// # Errors
///
/// Returns a bad-request error when there are too many patterns or a pattern
/// is not a valid IP address/CIDR network.
pub fn validate_ip_patterns(patterns: &[String]) -> Result<(), ApiError> {
    if patterns.len() > 100 {
        return Err(ApiError::bad_request("Too many IP restriction patterns"));
    }
    for pattern in patterns {
        let pattern = pattern.trim();
        if pattern.is_empty()
            || (IpAddr::from_str(pattern).is_err() && IpNet::from_str(pattern).is_err())
        {
            return Err(ApiError::bad_request("Invalid IP restriction pattern"));
        }
    }
    Ok(())
}

fn validate_non_negative(value: Option<f64>, field: &'static str) -> Result<(), ApiError> {
    if value.is_some_and(|value| !value.is_finite() || value < 0.0) {
        tracing::debug!(field, "rejected invalid non-negative numeric field");
        return Err(ApiError::bad_request(
            "Quota and rate limits must be finite non-negative numbers",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_legacy_and_structured_notification_emails() {
        let legacy = parse_notify_email_entries(r#"[" first@example.com ", "second@example.com"]"#);
        assert_eq!(legacy.len(), 2);
        assert_eq!(legacy[0].email, "first@example.com");
        assert!(!legacy[0].verified);

        let structured = parse_notify_email_entries(
            r#"[{"email":"verified@example.com","disabled":true,"verified":true}]"#,
        );
        assert_eq!(structured.len(), 1);
        assert!(structured[0].disabled);
        assert!(structured[0].verified);
    }

    #[test]
    fn refresh_token_shape_is_strict() {
        assert!(validate_refresh_token(&format!("rt_{}", "ab".repeat(32))).is_ok());
        assert!(validate_refresh_token(&format!("sk_{}", "ab".repeat(32))).is_err());
        assert!(validate_refresh_token("rt_not-hex").is_err());
    }

    #[test]
    fn backend_mode_blocks_existing_users_but_keeps_admin_control_access() {
        let user_error = ensure_backend_mode_user_access("user", true)
            .expect_err("ordinary users must be blocked in backend mode");
        assert_eq!(user_error.status(), axum::http::StatusCode::FORBIDDEN);
        assert!(ensure_backend_mode_user_access("admin", true).is_ok());
        assert!(ensure_backend_mode_user_access("user", false).is_ok());
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL pointing at a migrated disposable *_test database"]
    async fn postgres_auth_rate_limits_are_cross_replica_and_hash_only() {
        let database_url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL is set");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&database_url)
            .await
            .expect("connect test PostgreSQL");
        let mut config = ControlApiConfig::new(b"0123456789abcdef0123456789abcdef".to_vec());
        config.login_max_failures = 2;
        config.login_failure_window = Duration::from_mins(1);
        let first = ControlApiState::new(pool.clone(), config.clone()).expect("build first state");
        let second = ControlApiState::new(pool.clone(), config).expect("build second state");
        let suffix = Uuid::new_v4();
        let action_key = format!("integration-action:{suffix}");

        first
            .require_action_rate(&action_key, 2, Duration::from_mins(1))
            .await
            .expect("first replica action should pass");
        second
            .require_action_rate(&action_key, 2, Duration::from_mins(1))
            .await
            .expect("second replica action should pass");
        let error = first
            .require_action_rate(&action_key, 2, Duration::from_mins(1))
            .await
            .expect_err("shared third action should be rejected");
        assert_eq!(error.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);

        let identity = format!("integration-{suffix}@example.invalid");
        first
            .record_login_failure(&identity)
            .await
            .expect("record first login failure");
        second
            .record_login_failure(&identity)
            .await
            .expect("record second login failure");
        assert!(
            first
                .login_is_limited(&identity)
                .await
                .expect("read shared login limit")
        );
        second
            .clear_login_failures(&identity)
            .await
            .expect("clear shared login limit");
        assert!(
            !first
                .login_is_limited(&identity)
                .await
                .expect("read cleared login limit")
        );

        sqlx::query(
            "DELETE FROM auth_rate_limit_windows WHERE scope='auth_action' AND subject_hash=$1",
        )
        .bind(rate_limit_subject_hash("auth_action", &action_key).as_slice())
        .execute(&pool)
        .await
        .expect("delete action-rate fixture");
    }
}

#[derive(Deserialize)]
struct TurnstileResult {
    success: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct UserRecord {
    pub view: UserView,
    password_hash: String,
    auth_generation: i64,
    totp_enabled: bool,
    totp_secret_encrypted: Option<String>,
    totp_enabled_at: Option<String>,
    avatar_url: String,
}

const USER_BY_ID_SQL: &str = r#"
SELECT
    u.id,
    u.email,
    u.username,
    u.password_hash,
    u.role,
    u.balance::double precision AS balance,
    u.frozen_balance::double precision AS frozen_balance,
    u.concurrency,
    u.status,
    COALESCE((
        SELECT ARRAY_AGG(uag.group_id ORDER BY uag.group_id)
        FROM user_allowed_groups uag
        WHERE uag.user_id = u.id
    ), ARRAY[]::bigint[]) AS allowed_groups,
    to_char(u.last_active_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS last_active_at,
    to_char(u.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at,
    to_char(u.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS updated_at,
    u.balance_notify_enabled,
    u.balance_notify_threshold_type,
    u.balance_notify_threshold::double precision AS balance_notify_threshold,
    u.balance_notify_extra_emails,
    u.total_recharged::double precision AS total_recharged,
    u.rpm_limit,
    u.auth_generation,
    u.totp_enabled,
    u.totp_secret_encrypted,
    to_char(u.totp_enabled_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS totp_enabled_at,
    COALESCE(avatar.url, '') AS avatar_url
FROM users u
LEFT JOIN user_avatars avatar ON avatar.user_id = u.id
WHERE u.id = $1 AND u.deleted_at IS NULL
LIMIT 1
"#;

const USER_BY_EMAIL_SQL: &str = r#"
SELECT
    u.id,
    u.email,
    u.username,
    u.password_hash,
    u.role,
    u.balance::double precision AS balance,
    u.frozen_balance::double precision AS frozen_balance,
    u.concurrency,
    u.status,
    COALESCE((
        SELECT ARRAY_AGG(uag.group_id ORDER BY uag.group_id)
        FROM user_allowed_groups uag
        WHERE uag.user_id = u.id
    ), ARRAY[]::bigint[]) AS allowed_groups,
    to_char(u.last_active_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS last_active_at,
    to_char(u.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at,
    to_char(u.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS updated_at,
    u.balance_notify_enabled,
    u.balance_notify_threshold_type,
    u.balance_notify_threshold::double precision AS balance_notify_threshold,
    u.balance_notify_extra_emails,
    u.total_recharged::double precision AS total_recharged,
    u.rpm_limit,
    u.auth_generation,
    u.totp_enabled,
    u.totp_secret_encrypted,
    to_char(u.totp_enabled_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS totp_enabled_at,
    COALESCE(avatar.url, '') AS avatar_url
FROM users u
LEFT JOIN user_avatars avatar ON avatar.user_id = u.id
WHERE LOWER(u.email) = LOWER($1) AND u.deleted_at IS NULL
LIMIT 1
"#;

fn user_from_row(row: &PgRow) -> Result<UserRecord, ApiError> {
    let extra_emails: String = row.try_get("balance_notify_extra_emails")?;
    Ok(UserRecord {
        view: UserView {
            id: row.try_get("id")?,
            email: row.try_get("email")?,
            username: row.try_get("username")?,
            role: row.try_get("role")?,
            balance: row.try_get("balance")?,
            frozen_balance: row.try_get("frozen_balance")?,
            concurrency: row.try_get("concurrency")?,
            status: row.try_get("status")?,
            allowed_groups: row.try_get("allowed_groups")?,
            last_active_at: row.try_get("last_active_at")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
            balance_notify_enabled: row.try_get("balance_notify_enabled")?,
            balance_notify_threshold_type: row.try_get("balance_notify_threshold_type")?,
            balance_notify_threshold: row.try_get("balance_notify_threshold")?,
            balance_notify_extra_emails: parse_notify_email_entries(&extra_emails),
            total_recharged: row.try_get("total_recharged")?,
            rpm_limit: row.try_get("rpm_limit")?,
        },
        password_hash: row.try_get("password_hash")?,
        auth_generation: row.try_get("auth_generation")?,
        totp_enabled: row.try_get("totp_enabled")?,
        totp_secret_encrypted: row.try_get("totp_secret_encrypted")?,
        totp_enabled_at: row.try_get("totp_enabled_at")?,
        avatar_url: row.try_get("avatar_url")?,
    })
}

fn token_version(user: &UserRecord) -> i64 {
    session_token_version(&user.view.email, &user.password_hash, user.auth_generation)
}

fn parse_notify_email_entries(raw: &str) -> Vec<NotifyEmailEntry> {
    let Ok(values) = serde_json::from_str::<Vec<serde_json::Value>>(raw.trim()) else {
        return Vec::new();
    };
    values
        .into_iter()
        .filter_map(|value| match value {
            serde_json::Value::String(email) => {
                let email = email.trim().to_owned();
                (!email.is_empty()).then_some(NotifyEmailEntry {
                    email,
                    disabled: false,
                    verified: false,
                })
            }
            value @ serde_json::Value::Object(_) => serde_json::from_value(value).ok(),
            _ => None,
        })
        .collect()
}

fn normalize_email(raw: &str) -> Result<String, ApiError> {
    let email = raw.trim().to_lowercase();
    let valid = email.len() <= 255
        && email
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'));
    if valid {
        Ok(email)
    } else {
        Err(ApiError::bad_request("Invalid email address"))
    }
}

fn bearer_token(headers: &HeaderMap) -> Result<&str, ApiError> {
    let value = headers
        .get(AUTHORIZATION)
        .ok_or_else(|| ApiError::unauthorized("Authorization header is required"))?
        .to_str()
        .map_err(|_| ApiError::unauthorized("Invalid Authorization header"))?;
    let (scheme, token) = value
        .split_once(' ')
        .ok_or_else(|| ApiError::unauthorized("Invalid Authorization header"))?;
    if !scheme.eq_ignore_ascii_case("Bearer") || token.trim().is_empty() {
        return Err(ApiError::unauthorized("Invalid Authorization header"));
    }
    Ok(token.trim())
}

fn duration_seconds_i64(duration: Duration) -> Result<i64, ApiError> {
    i64::try_from(duration.as_secs())
        .map_err(|error| ApiError::internal("convert token lifetime", error))
}

fn generate_refresh_token() -> String {
    let mut random = [0_u8; REFRESH_TOKEN_RANDOM_BYTES];
    OsRng.fill_bytes(&mut random);
    format!("{REFRESH_TOKEN_PREFIX}{}", hex::encode(random))
}

#[must_use]
pub fn hash_refresh_token(raw_token: &str) -> [u8; 32] {
    Sha256::digest(raw_token.as_bytes()).into()
}

fn validate_refresh_token(raw_token: &str) -> Result<(), ApiError> {
    let encoded = raw_token
        .strip_prefix(REFRESH_TOKEN_PREFIX)
        .ok_or_else(|| ApiError::unauthorized("Invalid refresh token"))?;
    if encoded.len() != REFRESH_TOKEN_RANDOM_BYTES * 2
        || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ApiError::unauthorized("Invalid refresh token"));
    }
    Ok(())
}

fn validate_prefixed_token(raw_token: &str, prefix: &str) -> Result<(), ApiError> {
    let encoded = raw_token
        .strip_prefix(prefix)
        .ok_or_else(|| ApiError::bad_request("Invalid security token"))?;
    if encoded.len() != 64 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ApiError::bad_request("Invalid security token"));
    }
    Ok(())
}

fn validate_new_password(password: &str) -> Result<(), ApiError> {
    if (6..=72).contains(&password.len()) {
        Ok(())
    } else {
        Err(ApiError::bad_request(
            "Password must contain between 6 and 72 bytes",
        ))
    }
}

async fn hash_password_async(password_value: String) -> Result<String, ApiError> {
    tokio::task::spawn_blocking(move || password::hash_password(&password_value))
        .await
        .map_err(|error| ApiError::internal("join password hashing task", error))?
        .map_err(|error| ApiError::internal("hash password", error))
}

async fn verify_password_async(
    password_value: String,
    password_hash: String,
) -> Result<bool, ApiError> {
    tokio::task::spawn_blocking(move || password::verify_password(&password_value, &password_hash))
        .await
        .map_err(|error| ApiError::internal("join password verification task", error))?
        .map_err(|error| ApiError::internal("verify password", error))
}

fn email_code_material(email: &str, code: &str) -> String {
    format!("{}\0{code}", email.trim().to_lowercase())
}

fn now_unix_seconds() -> Result<i64, ApiError> {
    let seconds = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|error| ApiError::internal("read system time", error))?
        .as_secs();
    i64::try_from(seconds).map_err(|error| ApiError::internal("convert system time", error))
}

fn mask_email(email: &str) -> String {
    let Some((local, domain)) = email.split_once('@') else {
        return "***".to_owned();
    };
    let visible = local.chars().next().unwrap_or('*');
    format!("{visible}***@{domain}")
}

struct SecurityTokenInsert<'a> {
    id: &'a str,
    purpose: &'a str,
    hash: &'a [u8; 32],
    user_id: Option<i64>,
    subject: &'a str,
    secret_ciphertext: Option<&'a str>,
    lifetime: Duration,
    max_attempts: i32,
}

async fn insert_security_token(
    transaction: &mut Transaction<'_, Postgres>,
    token: SecurityTokenInsert<'_>,
) -> Result<(), ApiError> {
    let lifetime = duration_seconds_i64(token.lifetime)?;
    sqlx::query(
        r"
INSERT INTO auth_security_tokens
    (id, purpose, token_hash, user_id, subject, secret_ciphertext,
     max_attempts, expires_at)
VALUES ($1::uuid, $2, $3, $4, $5, $6, $7,
        NOW() + make_interval(secs => $8::double precision))
",
    )
    .bind(token.id)
    .bind(token.purpose)
    .bind(token.hash.as_slice())
    .bind(token.user_id)
    .bind(token.subject)
    .bind(token.secret_ciphertext)
    .bind(token.max_attempts)
    .bind(lifetime)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn consume_active_security_tokens(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: Option<i64>,
    subject: &str,
    purpose: &str,
) -> Result<(), ApiError> {
    sqlx::query(
        r"
UPDATE auth_security_tokens
SET consumed_at = COALESCE(consumed_at, NOW())
WHERE purpose = $3 AND consumed_at IS NULL
  AND (($1::bigint IS NOT NULL AND user_id = $1)
       OR ($1::bigint IS NULL AND subject = $2))
",
    )
    .bind(user_id)
    .bind(subject)
    .bind(purpose)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn consume_security_token_tx(
    transaction: &mut Transaction<'_, Postgres>,
    id: &str,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE auth_security_tokens SET consumed_at = COALESCE(consumed_at, NOW()) WHERE id = $1::uuid",
    )
    .bind(id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn consume_security_token_by_id(pool: &PgPool, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE auth_security_tokens SET consumed_at = COALESCE(consumed_at, NOW()) WHERE id = $1::uuid",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

async fn record_security_failure(
    transaction: &mut Transaction<'_, Postgres>,
    id: &str,
) -> Result<bool, ApiError> {
    sqlx::query_scalar::<_, bool>(
        r"
UPDATE auth_security_tokens
SET attempts = LEAST(attempts + 1, max_attempts),
    consumed_at = CASE
        WHEN attempts + 1 >= max_attempts THEN COALESCE(consumed_at, NOW())
        ELSE consumed_at
    END
WHERE id = $1::uuid
RETURNING attempts >= max_attempts
",
    )
    .bind(id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(Into::into)
}

async fn revoke_user_security_state(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i64,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE auth_refresh_sessions SET revoked_at = COALESCE(revoked_at, NOW()) WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE auth_security_tokens SET consumed_at = COALESCE(consumed_at, NOW()) WHERE user_id = $1 AND consumed_at IS NULL",
    )
    .bind(user_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn insert_refresh_token_tx(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i64,
    family_id: Uuid,
    version: i64,
    lifetime: Duration,
) -> Result<String, ApiError> {
    let lifetime_seconds = duration_seconds_i64(lifetime)?;
    for _ in 0..3 {
        let raw_token = generate_refresh_token();
        let hash = hash_refresh_token(&raw_token);
        let result = sqlx::query(
            r"
INSERT INTO auth_refresh_sessions
    (id, token_hash, user_id, family_id, token_version, expires_at)
VALUES ($1::uuid, $2, $3, $4::uuid, $5,
        NOW() + make_interval(secs => $6::double precision))
",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(hash.as_slice())
        .bind(user_id)
        .bind(family_id.to_string())
        .bind(version)
        .bind(lifetime_seconds)
        .execute(&mut **transaction)
        .await;
        match result {
            Ok(_) => return Ok(raw_token),
            Err(error) if is_unique_violation(&error) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(ApiError::internal(
        "generate refresh token",
        "repeated hash collision",
    ))
}

async fn revoke_family(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    family_id: &str,
    reuse_detected: bool,
) -> Result<(), ApiError> {
    sqlx::query(
        r"
UPDATE auth_refresh_sessions
SET
    revoked_at = COALESCE(revoked_at, NOW()),
    reuse_detected_at = CASE
        WHEN $2 THEN COALESCE(reuse_detected_at, NOW())
        ELSE reuse_detected_at
    END
WHERE family_id = $1::uuid
",
    )
    .bind(family_id)
    .bind(reuse_detected)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn setting_is_true_in_transaction(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    key: &str,
) -> Result<bool, ApiError> {
    let value = sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key = $1")
        .bind(key)
        .fetch_optional(&mut **transaction)
        .await?;
    Ok(value.is_some_and(|value| value.trim().eq_ignore_ascii_case("true")))
}

fn set_identity_unbind_flags(identities: &mut IdentitySummarySet) {
    let bound_providers = [
        identities.email.bound,
        identities.linuxdo.bound,
        identities.oidc.bound,
        identities.wechat.bound,
        identities.dingtalk.bound,
    ]
    .into_iter()
    .filter(|bound| *bound)
    .count();
    let can_unbind = bound_providers > 1;
    for summary in [
        &mut identities.email,
        &mut identities.linuxdo,
        &mut identities.oidc,
        &mut identities.wechat,
        &mut identities.dingtalk,
    ] {
        summary.can_unbind = summary.bound && can_unbind;
    }
}

fn validate_profile_update(request: &UpdateProfileRequest) -> Result<(), ApiError> {
    if request
        .username
        .as_deref()
        .is_some_and(|username| username.trim().len() > 100)
    {
        return Err(ApiError::bad_request(
            "Username must not exceed 100 characters",
        ));
    }
    if request
        .balance_notify_threshold
        .is_some_and(|threshold| !threshold.is_finite())
    {
        return Err(ApiError::bad_request(
            "Balance notification threshold must be finite",
        ));
    }
    if let Some(avatar_url) = request.avatar_url.as_deref() {
        validate_avatar(avatar_url)?;
    }
    Ok(())
}

fn validate_avatar(raw: &str) -> Result<(), ApiError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(());
    }
    if raw.starts_with("data:") {
        if raw.len() > MAX_AVATAR_DATA_URL_BYTES {
            return Err(ApiError::bad_request("Avatar image is too large"));
        }
        let (metadata, encoded) = raw
            .split_once(',')
            .ok_or_else(|| ApiError::bad_request("Invalid avatar data URL"))?;
        if !metadata.to_ascii_lowercase().starts_with("data:image/")
            || !metadata.to_ascii_lowercase().ends_with(";base64")
            || STANDARD.decode(encoded.trim()).is_err()
        {
            return Err(ApiError::bad_request("Invalid avatar data URL"));
        }
        return Ok(());
    }
    let url = Url::parse(raw).map_err(|_| ApiError::bad_request("Invalid avatar URL"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(ApiError::bad_request("Invalid avatar URL"));
    }
    Ok(())
}

async fn update_avatar(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    user_id: i64,
    raw: &str,
) -> Result<(), ApiError> {
    let raw = raw.trim();
    if raw.is_empty() {
        sqlx::query("DELETE FROM user_avatars WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut **transaction)
            .await?;
        return Ok(());
    }
    let (provider, content_type, byte_size, sha256) = if raw.starts_with("data:") {
        let (metadata, encoded) = raw
            .split_once(',')
            .ok_or_else(|| ApiError::bad_request("Invalid avatar data URL"))?;
        let content_type = metadata
            .strip_prefix("data:")
            .and_then(|value| value.strip_suffix(";base64"))
            .unwrap_or_default()
            .to_owned();
        let bytes = STANDARD
            .decode(encoded.trim())
            .map_err(|_| ApiError::bad_request("Invalid avatar data URL"))?;
        (
            "inline",
            content_type,
            i32::try_from(bytes.len())
                .map_err(|error| ApiError::internal("convert avatar length", error))?,
            hex::encode(Sha256::digest(&bytes)),
        )
    } else {
        ("remote_url", String::new(), 0, String::new())
    };
    sqlx::query(
        r"
INSERT INTO user_avatars (
    user_id, storage_provider, storage_key, url, content_type, byte_size, sha256, updated_at
)
VALUES ($1, $2, '', $3, $4, $5, $6, NOW())
ON CONFLICT (user_id) DO UPDATE SET
    storage_provider = EXCLUDED.storage_provider,
    storage_key = EXCLUDED.storage_key,
    url = EXCLUDED.url,
    content_type = EXCLUDED.content_type,
    byte_size = EXCLUDED.byte_size,
    sha256 = EXCLUDED.sha256,
    updated_at = NOW()
",
    )
    .bind(user_id)
    .bind(provider)
    .bind(raw)
    .bind(content_type)
    .bind(byte_size)
    .bind(sha256)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn decimal_string(value: f64) -> String {
    format!("{value:.8}")
}

fn rate_limit_subject_hash(scope: &str, subject: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"sub2api/auth-rate-limit/v1\0");
    digest.update(scope.as_bytes());
    digest.update(b"\0");
    digest.update(subject.as_bytes());
    digest.finalize().into()
}

fn rate_limit_window_seconds(window: Duration) -> i64 {
    i64::try_from(window.as_secs().max(1)).unwrap_or(i64::MAX)
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
}
