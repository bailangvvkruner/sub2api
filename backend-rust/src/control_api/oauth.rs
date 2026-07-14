use std::{collections::HashMap, time::Duration};

use axum::{
    Json, Router,
    extract::{Query, State, rejection::QueryRejection},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{CACHE_CONTROL, COOKIE, LOCATION, PRAGMA, SET_COOKIE},
    },
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;
use subtle::ConstantTimeEq;
use url::Url;

use crate::rsa_crypto::{RsaCryptoError, RsaPublicKey};

use super::{
    ApiEnvelope, ApiError,
    models::{
        CompleteOAuthRegistrationRequest, CompleteWechatOAuthRequest, OAuthCallbackQuery,
        OAuthIdentityProfile, OAuthLoginOutcome, OAuthStartQuery, PendingOAuthBindLoginRequest,
        PendingOAuthCreateAccountRequest, PendingOAuthSendVerifyCodeRequest,
        SendVerificationCodeRequest, WechatPaymentOAuthStartQuery,
    },
    service::{ControlApiState, OAuthRegistrationCompletion},
};

const STATE_COOKIE: &str = "email_oauth_state";
const PENDING_SESSION_COOKIE: &str = "oauth_pending_session";
const PENDING_BROWSER_COOKIE: &str = "oauth_pending_browser_session";
const OAUTH_COOKIE_PATH: &str = "/api/v1/auth/oauth";
const OAUTH_TTL_SECONDS: i64 = 600;
const DEFAULT_REDIRECT: &str = "/dashboard";
const DEFAULT_FRONTEND_CALLBACK: &str = "/auth/oauth/callback";
const OIDC_VERIFIER_COOKIE: &str = "oidc_oauth_verifier";
const OIDC_NONCE_COOKIE: &str = "oidc_oauth_nonce";
const OAUTH_BIND_TOKEN_COOKIE: &str = "oauth_bind_access_token";

#[derive(Clone, Debug)]
struct ProviderConfig {
    provider: &'static str,
    client_id: String,
    client_secret: String,
    authorize_url: &'static str,
    token_url: &'static str,
    userinfo_url: &'static str,
    emails_url: Option<&'static str>,
    scopes: &'static str,
    redirect_url: String,
    frontend_callback: String,
}

#[derive(Clone, Debug)]
struct ConsumedState {
    redirect_to: String,
    promo_code: String,
    affiliate_code: String,
    verifier_hash: Option<Vec<u8>>,
    nonce_hash: Option<Vec<u8>>,
    intent: String,
    target_user_id: Option<i64>,
    provider_context: Value,
}

#[derive(Clone, Debug)]
struct OidcConfig {
    client_id: String,
    client_secret: String,
    issuer: String,
    authorize_url: String,
    token_url: String,
    userinfo_url: String,
    jwks_url: String,
    scopes: String,
    redirect_url: String,
    frontend_callback: String,
    token_auth_method: String,
    use_pkce: bool,
    validate_id_token: bool,
    require_email_verified: bool,
    allowed_signing_algs: Vec<String>,
    clock_skew_seconds: i64,
}

#[derive(Clone, Debug)]
struct WechatConfig {
    mode: String,
    app_id: String,
    app_secret: String,
    authorize_url: &'static str,
    scope: String,
    redirect_url: String,
    frontend_callback: String,
    requires_union_id: bool,
}

#[derive(Clone, Debug)]
struct WechatToken {
    access_token: String,
    openid: String,
    unionid: String,
    scope: String,
}

#[derive(Clone, Debug)]
struct DingTalkConfig {
    client_id: String,
    client_secret: String,
    redirect_url: String,
    frontend_callback: String,
    scopes: String,
    corp_restriction_policy: String,
    internal_corp_id: String,
}

pub(super) fn routes() -> Router<ControlApiState> {
    Router::new()
        .route("/api/v1/auth/oauth/bind-token", post(prepare_bind_token))
        .route("/api/v1/auth/oauth/github/start", get(github_start))
        .route("/api/v1/auth/oauth/github/callback", get(github_callback))
        .route(
            "/api/v1/auth/oauth/github/complete-registration",
            post(github_complete_registration),
        )
        .route("/api/v1/auth/oauth/google/start", get(google_start))
        .route("/api/v1/auth/oauth/google/callback", get(google_callback))
        .route(
            "/api/v1/auth/oauth/google/complete-registration",
            post(google_complete_registration),
        )
        .route("/api/v1/auth/oauth/linuxdo/start", get(linuxdo_start))
        .route(
            "/api/v1/auth/oauth/linuxdo/bind/start",
            get(linuxdo_bind_start),
        )
        .route("/api/v1/auth/oauth/linuxdo/callback", get(linuxdo_callback))
        .route(
            "/api/v1/auth/oauth/linuxdo/complete-registration",
            post(linuxdo_complete_registration),
        )
        .route(
            "/api/v1/auth/oauth/linuxdo/bind-login",
            post(linuxdo_bind_login),
        )
        .route(
            "/api/v1/auth/oauth/linuxdo/create-account",
            post(linuxdo_create_account),
        )
        .route("/api/v1/auth/oauth/oidc/start", get(oidc_start))
        .route("/api/v1/auth/oauth/oidc/bind/start", get(oidc_bind_start))
        .route("/api/v1/auth/oauth/oidc/callback", get(oidc_callback))
        .route(
            "/api/v1/auth/oauth/oidc/complete-registration",
            post(oidc_complete_registration),
        )
        .route("/api/v1/auth/oauth/oidc/bind-login", post(oidc_bind_login))
        .route(
            "/api/v1/auth/oauth/oidc/create-account",
            post(oidc_create_account),
        )
        .route("/api/v1/auth/oauth/wechat/start", get(wechat_start))
        .route(
            "/api/v1/auth/oauth/wechat/bind/start",
            get(wechat_bind_start),
        )
        .route("/api/v1/auth/oauth/wechat/callback", get(wechat_callback))
        .route(
            "/api/v1/auth/oauth/wechat/complete-registration",
            post(wechat_complete_registration),
        )
        .route(
            "/api/v1/auth/oauth/wechat/bind-login",
            post(wechat_bind_login),
        )
        .route(
            "/api/v1/auth/oauth/wechat/create-account",
            post(wechat_create_account),
        )
        .route(
            "/api/v1/auth/oauth/wechat/payment/start",
            get(wechat_payment_start),
        )
        .route(
            "/api/v1/auth/oauth/wechat/payment/callback",
            get(wechat_payment_callback),
        )
        .route("/api/v1/auth/oauth/dingtalk/start", get(dingtalk_start))
        .route(
            "/api/v1/auth/oauth/dingtalk/bind/start",
            get(dingtalk_bind_start),
        )
        .route(
            "/api/v1/auth/oauth/dingtalk/callback",
            get(dingtalk_callback),
        )
        .route(
            "/api/v1/auth/oauth/dingtalk/complete-registration",
            post(dingtalk_complete_registration),
        )
        .route(
            "/api/v1/auth/oauth/dingtalk/bind-login",
            post(dingtalk_bind_login),
        )
        .route(
            "/api/v1/auth/oauth/dingtalk/create-account",
            post(dingtalk_create_account),
        )
        .route(
            "/api/v1/auth/oauth/pending/exchange",
            post(exchange_pending_completion),
        )
        .route(
            "/api/v1/auth/oauth/pending/bind-login",
            post(pending_bind_login),
        )
        .route(
            "/api/v1/auth/oauth/pending/create-account",
            post(pending_create_account),
        )
        .route(
            "/api/v1/auth/oauth/pending/send-verify-code",
            post(pending_send_verify_code),
        )
}

async fn prepare_bind_token(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let _user = state.authenticate(&headers).await?;
    let token = bearer_token(&headers)
        .ok_or_else(|| ApiError::unauthorized("Authentication is required"))?;
    let secure = request_is_https(&headers);
    let mut response = StatusCode::NO_CONTENT.into_response();
    append_cookie(
        response.headers_mut(),
        &pending_cookie(OAUTH_BIND_TOKEN_COOKIE, token, secure),
    );
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

async fn github_start(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    query: Result<Query<OAuthStartQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    start_oauth(state, headers, query_payload(query)?, "github").await
}

async fn google_start(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    query: Result<Query<OAuthStartQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    start_oauth(state, headers, query_payload(query)?, "google").await
}

async fn linuxdo_start(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    query: Result<Query<OAuthStartQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    start_oauth(state, headers, query_payload(query)?, "linuxdo").await
}

async fn linuxdo_bind_start(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    query: Result<Query<OAuthStartQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let user_id = authenticate_bind_user(&state, &headers).await?;
    start_oauth_for_user(
        state,
        headers,
        query_payload(query)?,
        "linuxdo",
        Some(user_id),
    )
    .await
}

async fn oidc_start(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    query: Result<Query<OAuthStartQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    oidc_start_for_user(state, headers, query_payload(query)?, None).await
}

async fn oidc_bind_start(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    query: Result<Query<OAuthStartQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let user_id = authenticate_bind_user(&state, &headers).await?;
    oidc_start_for_user(state, headers, query_payload(query)?, Some(user_id)).await
}

async fn oidc_start_for_user(
    state: ControlApiState,
    headers: HeaderMap,
    query: OAuthStartQuery,
    target_user_id: Option<i64>,
) -> Result<Response, ApiError> {
    let config = load_oidc_config(&state).await?;
    let raw_state = random_bearer();
    let verifier = config.use_pkce.then(random_bearer);
    let nonce = config.validate_id_token.then(random_bearer);
    let redirect_to = sanitize_redirect(query.redirect.as_deref()).unwrap_or(DEFAULT_REDIRECT);
    let promo_code = query.promo_code.as_deref().unwrap_or_default().trim();
    let affiliate_code = query
        .aff_code
        .as_deref()
        .or(query.aff.as_deref())
        .unwrap_or_default()
        .trim();
    let state_hash = Sha256::digest(raw_state.as_bytes());
    let verifier_hash = verifier
        .as_deref()
        .map(|value| Sha256::digest(value.as_bytes()).to_vec());
    let nonce_hash = nonce
        .as_deref()
        .map(|value| Sha256::digest(value.as_bytes()).to_vec());
    sqlx::query(
        r"
INSERT INTO auth_oauth_states (
    id, state_hash, provider_type, redirect_to, promo_code, affiliate_code,
    verifier_hash, nonce_hash, intent, target_user_id, expires_at
)
VALUES (
    $1::uuid, $2, 'oidc', $3, $4, $5, $6, $7,
    CASE WHEN $8::bigint IS NULL THEN 'login' ELSE 'bind_current_user' END,
    $8, NOW() + INTERVAL '10 minutes'
)
",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(state_hash.as_slice())
    .bind(redirect_to)
    .bind(promo_code.chars().take(64).collect::<String>())
    .bind(affiliate_code.chars().take(64).collect::<String>())
    .bind(verifier_hash)
    .bind(nonce_hash)
    .bind(target_user_id)
    .execute(state.pool())
    .await?;

    let mut authorize_url = Url::parse(&config.authorize_url)
        .map_err(|error| ApiError::internal("parse OIDC authorize URL", error))?;
    {
        let mut pairs = authorize_url.query_pairs_mut();
        pairs
            .append_pair("response_type", "code")
            .append_pair("client_id", &config.client_id)
            .append_pair("redirect_uri", &config.redirect_url)
            .append_pair("scope", &config.scopes)
            .append_pair("state", &raw_state);
        if let Some(verifier) = verifier.as_deref() {
            let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
            pairs
                .append_pair("code_challenge", &challenge)
                .append_pair("code_challenge_method", "S256");
        }
        if let Some(nonce) = nonce.as_deref() {
            pairs.append_pair("nonce", nonce);
        }
    }
    let secure = request_is_https(&headers);
    let mut cookies = vec![state_cookie(&raw_state, secure)];
    if let Some(verifier) = verifier.as_deref() {
        cookies.push(pending_cookie(OIDC_VERIFIER_COOKIE, verifier, secure));
    }
    if let Some(nonce) = nonce.as_deref() {
        cookies.push(pending_cookie(OIDC_NONCE_COOKIE, nonce, secure));
    }
    if target_user_id.is_some() {
        cookies.push(clear_cookie(OAUTH_BIND_TOKEN_COOKIE, secure));
    }
    Ok(redirect_response(authorize_url.as_str(), &cookies))
}

async fn wechat_start(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    query: Result<Query<OAuthStartQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    wechat_start_for_user(state, headers, query_payload(query)?, None).await
}

async fn wechat_bind_start(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    query: Result<Query<OAuthStartQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let user_id = authenticate_bind_user(&state, &headers).await?;
    wechat_start_for_user(state, headers, query_payload(query)?, Some(user_id)).await
}

async fn wechat_start_for_user(
    state: ControlApiState,
    headers: HeaderMap,
    query: OAuthStartQuery,
    target_user_id: Option<i64>,
) -> Result<Response, ApiError> {
    let mode = resolve_wechat_mode(query.mode.as_deref(), &headers)?;
    let config = load_wechat_config(&state, mode).await?;
    let raw_state = random_bearer();
    let state_hash = Sha256::digest(raw_state.as_bytes());
    let redirect_to = sanitize_redirect(query.redirect.as_deref()).unwrap_or(DEFAULT_REDIRECT);
    let promo_code = query.promo_code.as_deref().unwrap_or_default().trim();
    let affiliate_code = query
        .aff_code
        .as_deref()
        .or(query.aff.as_deref())
        .unwrap_or_default()
        .trim();
    sqlx::query(
        r"
INSERT INTO auth_oauth_states (
    id, state_hash, provider_type, redirect_to, promo_code, affiliate_code,
    intent, target_user_id, provider_context, expires_at
)
VALUES (
    $1::uuid, $2, 'wechat', $3, $4, $5,
    CASE WHEN $6::bigint IS NULL THEN 'login' ELSE 'bind_current_user' END,
    $6, $7, NOW() + INTERVAL '10 minutes'
)
",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(state_hash.as_slice())
    .bind(redirect_to)
    .bind(promo_code.chars().take(64).collect::<String>())
    .bind(affiliate_code.chars().take(64).collect::<String>())
    .bind(target_user_id)
    .bind(json!({ "kind": "login", "mode": config.mode, "app_id": config.app_id }))
    .execute(state.pool())
    .await?;
    let authorize_url = build_wechat_authorize_url(&config, &raw_state)?;
    let secure = request_is_https(&headers);
    let mut cookies = vec![state_cookie(&raw_state, secure)];
    if target_user_id.is_some() {
        cookies.push(clear_cookie(OAUTH_BIND_TOKEN_COOKIE, secure));
    }
    Ok(redirect_response(&authorize_url, &cookies))
}

async fn wechat_payment_start(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    query: Result<Query<WechatPaymentOAuthStartQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let query = query_payload(query)?;
    let mut config = load_wechat_config(&state, "mp").await?;
    let payment_type = match query.payment_type.as_deref().map(str::trim) {
        Some("wxpay") => "wxpay",
        Some("wxpay_direct") => "wxpay_direct",
        _ => return Err(ApiError::bad_request("Invalid payment type")),
    };
    let redirect_to = normalize_wechat_payment_redirect(
        sanitize_redirect(query.redirect.as_deref()).unwrap_or("/purchase"),
    );
    let scope = match query.scope.as_deref().map(str::trim) {
        Some("snsapi_userinfo") => "snsapi_userinfo",
        _ => "snsapi_base",
    };
    config.scope = scope.to_owned();
    let raw_state = random_bearer();
    let state_hash = Sha256::digest(raw_state.as_bytes());
    sqlx::query(
        r"
INSERT INTO auth_oauth_states (
    id, state_hash, provider_type, redirect_to, provider_context, expires_at
)
VALUES ($1::uuid, $2, 'wechat', $3, $4, NOW() + INTERVAL '10 minutes')
",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(state_hash.as_slice())
    .bind(&redirect_to)
    .bind(json!({
        "kind": "payment",
        "mode": "mp",
        "payment_type": payment_type,
        "amount": query.amount.as_deref().unwrap_or_default().trim(),
        "order_type": query.order_type.as_deref().unwrap_or_default().trim(),
        "plan_id": query.plan_id,
        "scope": scope
    }))
    .execute(state.pool())
    .await?;
    let authorize_url = build_wechat_authorize_url(&config, &raw_state)?;
    Ok(redirect_response(
        &authorize_url,
        &[state_cookie(&raw_state, request_is_https(&headers))],
    ))
}

async fn dingtalk_start(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    query: Result<Query<OAuthStartQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    dingtalk_start_for_user(state, headers, query_payload(query)?, None).await
}

async fn dingtalk_bind_start(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    query: Result<Query<OAuthStartQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let user_id = authenticate_bind_user(&state, &headers).await?;
    dingtalk_start_for_user(state, headers, query_payload(query)?, Some(user_id)).await
}

async fn dingtalk_start_for_user(
    state: ControlApiState,
    headers: HeaderMap,
    query: OAuthStartQuery,
    target_user_id: Option<i64>,
) -> Result<Response, ApiError> {
    let config = load_dingtalk_config(&state).await?;
    let raw_state = random_bearer();
    let state_hash = Sha256::digest(raw_state.as_bytes());
    let redirect_to = sanitize_redirect(query.redirect.as_deref()).unwrap_or(DEFAULT_REDIRECT);
    let promo_code = query.promo_code.as_deref().unwrap_or_default().trim();
    let affiliate_code = query
        .aff_code
        .as_deref()
        .or(query.aff.as_deref())
        .unwrap_or_default()
        .trim();
    sqlx::query(
        r"
INSERT INTO auth_oauth_states (
    id, state_hash, provider_type, redirect_to, promo_code, affiliate_code,
    intent, target_user_id, provider_context, expires_at
)
VALUES (
    $1::uuid, $2, 'dingtalk', $3, $4, $5,
    CASE WHEN $6::bigint IS NULL THEN 'login' ELSE 'bind_current_user' END,
    $6, $7, NOW() + INTERVAL '10 minutes'
)
",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(state_hash.as_slice())
    .bind(redirect_to)
    .bind(promo_code.chars().take(64).collect::<String>())
    .bind(affiliate_code.chars().take(64).collect::<String>())
    .bind(target_user_id)
    .bind(json!({ "kind": "login" }))
    .execute(state.pool())
    .await?;
    let mut authorize_url = Url::parse("https://login.dingtalk.com/oauth2/auth")
        .map_err(|error| ApiError::internal("parse DingTalk authorize URL", error))?;
    authorize_url
        .query_pairs_mut()
        .append_pair("client_id", &config.client_id)
        .append_pair("redirect_uri", &config.redirect_url)
        .append_pair("response_type", "code")
        .append_pair("scope", &config.scopes)
        .append_pair("state", &raw_state)
        .append_pair("prompt", "consent");
    let secure = request_is_https(&headers);
    let mut cookies = vec![state_cookie(&raw_state, secure)];
    if target_user_id.is_some() {
        cookies.push(clear_cookie(OAUTH_BIND_TOKEN_COOKIE, secure));
    }
    Ok(redirect_response(authorize_url.as_str(), &cookies))
}

async fn start_oauth(
    state: ControlApiState,
    headers: HeaderMap,
    query: OAuthStartQuery,
    provider: &'static str,
) -> Result<Response, ApiError> {
    start_oauth_for_user(state, headers, query, provider, None).await
}

async fn start_oauth_for_user(
    state: ControlApiState,
    headers: HeaderMap,
    query: OAuthStartQuery,
    provider: &'static str,
    target_user_id: Option<i64>,
) -> Result<Response, ApiError> {
    let config = load_provider_config(&state, provider).await?;
    let raw_state = random_bearer();
    let state_hash = Sha256::digest(raw_state.as_bytes());
    let redirect_to = sanitize_redirect(query.redirect.as_deref()).unwrap_or(DEFAULT_REDIRECT);
    let promo_code = query.promo_code.as_deref().unwrap_or_default().trim();
    let affiliate_code = query
        .aff_code
        .as_deref()
        .or(query.aff.as_deref())
        .unwrap_or_default()
        .trim();
    sqlx::query(
        r"
INSERT INTO auth_oauth_states (
    id, state_hash, provider_type, redirect_to, promo_code, affiliate_code,
    intent, target_user_id, expires_at
)
VALUES (
    $1::uuid, $2, $3, $4, $5, $6,
    CASE WHEN $7::bigint IS NULL THEN 'login' ELSE 'bind_current_user' END,
    $7, NOW() + INTERVAL '10 minutes'
)
",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(state_hash.as_slice())
    .bind(provider)
    .bind(redirect_to)
    .bind(promo_code.chars().take(64).collect::<String>())
    .bind(affiliate_code.chars().take(64).collect::<String>())
    .bind(target_user_id)
    .execute(state.pool())
    .await?;

    let mut authorize_url = Url::parse(config.authorize_url)
        .map_err(|error| ApiError::internal("parse OAuth authorize URL", error))?;
    {
        let mut pairs = authorize_url.query_pairs_mut();
        pairs
            .append_pair("response_type", "code")
            .append_pair("client_id", &config.client_id)
            .append_pair("redirect_uri", &config.redirect_url)
            .append_pair("state", &raw_state)
            .append_pair("scope", config.scopes);
    }
    let secure = request_is_https(&headers);
    let mut cookies = vec![state_cookie(&raw_state, secure)];
    if target_user_id.is_some() {
        cookies.push(clear_cookie(OAUTH_BIND_TOKEN_COOKIE, secure));
    }
    Ok(redirect_response(authorize_url.as_str(), &cookies))
}

async fn github_callback(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    query: Result<Query<OAuthCallbackQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    oauth_callback(state, headers, query_payload(query)?, "github").await
}

async fn google_callback(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    query: Result<Query<OAuthCallbackQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    oauth_callback(state, headers, query_payload(query)?, "google").await
}

async fn linuxdo_callback(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    query: Result<Query<OAuthCallbackQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    oauth_callback(state, headers, query_payload(query)?, "linuxdo").await
}

async fn oidc_callback(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    query: Result<Query<OAuthCallbackQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let query = query_payload(query)?;
    let config = load_oidc_config(&state).await?;
    let secure = request_is_https(&headers);
    let clear_cookies = vec![
        clear_cookie(STATE_COOKIE, secure),
        clear_cookie(OIDC_VERIFIER_COOKIE, secure),
        clear_cookie(OIDC_NONCE_COOKIE, secure),
    ];
    if let Some(error) = query
        .error
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        return Ok(oauth_error_redirect(
            &config.frontend_callback,
            "provider_error",
            error,
            query.error_description.as_deref().unwrap_or_default(),
            &clear_cookies,
        ));
    }
    let code = query.code.as_deref().map(str::trim).unwrap_or_default();
    let raw_state = query.state.as_deref().map(str::trim).unwrap_or_default();
    let cookie_state = cookie_value(&headers, STATE_COOKIE).unwrap_or_default();
    if code.is_empty() || raw_state.is_empty() || !constant_time_equal(raw_state, cookie_state) {
        return Ok(oauth_error_redirect(
            &config.frontend_callback,
            "invalid_state",
            "invalid oauth state",
            "",
            &clear_cookies,
        ));
    }
    let Some(consumed) = consume_state(&state, "oidc", raw_state).await? else {
        return Ok(oauth_error_redirect(
            &config.frontend_callback,
            "invalid_state",
            "invalid or expired oauth state",
            "",
            &clear_cookies,
        ));
    };
    let verifier = cookie_value(&headers, OIDC_VERIFIER_COOKIE).unwrap_or_default();
    let nonce = cookie_value(&headers, OIDC_NONCE_COOKIE).unwrap_or_default();
    if !optional_bearer_hash_matches(consumed.verifier_hash.as_deref(), verifier)
        || !optional_bearer_hash_matches(consumed.nonce_hash.as_deref(), nonce)
    {
        return Ok(oauth_error_redirect(
            &config.frontend_callback,
            "invalid_state",
            "oauth verifier or nonce is invalid",
            "",
            &clear_cookies,
        ));
    }
    let profile = match exchange_oidc_profile(&config, code, verifier, nonce).await {
        Ok(profile) => profile,
        Err(error) => {
            tracing::warn!(error = %error, "OIDC exchange failed");
            return Ok(oauth_error_redirect(
                &config.frontend_callback,
                "token_exchange_failed",
                "failed to complete oidc login",
                "",
                &clear_cookies,
            ));
        }
    };
    if consumed.intent == "bind_current_user" {
        let target_user_id = consumed
            .target_user_id
            .ok_or_else(|| ApiError::unauthorized("OAuth bind state does not identify a user"))?;
        if let Err(error) = state.bind_oauth_identity(target_user_id, profile).await {
            tracing::warn!(status = %error.status(), "OIDC identity binding failed");
            return Ok(oauth_error_redirect(
                &config.frontend_callback,
                "bind_failed",
                "oidc identity could not be bound",
                "",
                &clear_cookies,
            ));
        }
        return Ok(fragment_redirect(
            &config.frontend_callback,
            &[("redirect", consumed.redirect_to.as_str())],
            &clear_cookies,
        ));
    }
    if consumed.intent != "login" {
        return Ok(oauth_error_redirect(
            &config.frontend_callback,
            "invalid_state",
            "invalid oauth intent",
            "",
            &clear_cookies,
        ));
    }
    let outcome = match state
        .oauth_login_or_begin_registration(
            profile,
            &consumed.redirect_to,
            &consumed.promo_code,
            &consumed.affiliate_code,
        )
        .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            tracing::warn!(status = %error.status(), "OIDC local login failed");
            return Ok(oauth_error_redirect(
                &config.frontend_callback,
                "login_failed",
                "oidc login could not be completed",
                "",
                &clear_cookies,
            ));
        }
    };
    Ok(match outcome {
        OAuthLoginOutcome::Auth(auth) => {
            let expires_in = auth.expires_in.to_string();
            fragment_redirect(
                &config.frontend_callback,
                &[
                    ("access_token", auth.access_token.as_str()),
                    ("refresh_token", auth.refresh_token.as_str()),
                    ("expires_in", expires_in.as_str()),
                    ("token_type", auth.token_type),
                    ("redirect", consumed.redirect_to.as_str()),
                ],
                &clear_cookies,
            )
        }
        OAuthLoginOutcome::RegistrationPending {
            session_token,
            browser_session_key,
            ..
        } => redirect_response(
            &config.frontend_callback,
            &[
                clear_cookies[0].clone(),
                clear_cookies[1].clone(),
                clear_cookies[2].clone(),
                pending_cookie(PENDING_SESSION_COOKIE, &session_token, secure),
                pending_cookie(PENDING_BROWSER_COOKIE, &browser_session_key, secure),
            ],
        ),
    })
}

async fn wechat_callback(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    query: Result<Query<OAuthCallbackQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let query = query_payload(query)?;
    let frontend_callback = load_wechat_frontend_callback(&state).await?;
    let secure = request_is_https(&headers);
    let clear_state = clear_cookie(STATE_COOKIE, secure);
    if let Some(error) = query
        .error
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Ok(oauth_error_redirect(
            &frontend_callback,
            "provider_error",
            error,
            query.error_description.as_deref().unwrap_or_default(),
            &[clear_state],
        ));
    }
    let code = query.code.as_deref().map(str::trim).unwrap_or_default();
    let raw_state = query.state.as_deref().map(str::trim).unwrap_or_default();
    let cookie_state = cookie_value(&headers, STATE_COOKIE).unwrap_or_default();
    if code.is_empty() || raw_state.is_empty() || !constant_time_equal(raw_state, cookie_state) {
        return Ok(oauth_error_redirect(
            &frontend_callback,
            "invalid_state",
            "invalid oauth state",
            "",
            &[clear_state],
        ));
    }
    let Some(consumed) = consume_state(&state, "wechat", raw_state).await? else {
        return Ok(oauth_error_redirect(
            &frontend_callback,
            "invalid_state",
            "invalid or expired oauth state",
            "",
            &[clear_state],
        ));
    };
    if consumed
        .provider_context
        .get("kind")
        .and_then(Value::as_str)
        != Some("login")
    {
        return Ok(oauth_error_redirect(
            &frontend_callback,
            "invalid_state",
            "invalid oauth context",
            "",
            &[clear_state],
        ));
    }
    let mode = consumed
        .provider_context
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let config = load_wechat_config(&state, mode).await?;
    let frontend_callback = config.frontend_callback.clone();
    let profile = match exchange_wechat_profile(&config, code).await {
        Ok(profile) => profile,
        Err(error) => {
            tracing::warn!(error = %error, "WeChat OAuth exchange failed");
            return Ok(oauth_error_redirect(
                &frontend_callback,
                "provider_error",
                "wechat_identity_fetch_failed",
                "",
                &[clear_state],
            ));
        }
    };
    if consumed.intent == "bind_current_user" {
        let target_user_id = consumed
            .target_user_id
            .ok_or_else(|| ApiError::unauthorized("OAuth bind state does not identify a user"))?;
        if let Err(error) = state.bind_oauth_identity(target_user_id, profile).await {
            tracing::warn!(status = %error.status(), "WeChat identity binding failed");
            return Ok(oauth_error_redirect(
                &frontend_callback,
                "bind_failed",
                "wechat identity could not be bound",
                "",
                &[clear_state],
            ));
        }
        return Ok(fragment_redirect(
            &frontend_callback,
            &[("redirect", consumed.redirect_to.as_str())],
            &[clear_state],
        ));
    }
    if consumed.intent != "login" {
        return Ok(oauth_error_redirect(
            &frontend_callback,
            "invalid_state",
            "invalid oauth intent",
            "",
            &[clear_state],
        ));
    }
    let outcome = match state
        .oauth_login_or_begin_registration(
            profile,
            &consumed.redirect_to,
            &consumed.promo_code,
            &consumed.affiliate_code,
        )
        .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            tracing::warn!(status = %error.status(), "WeChat local login failed");
            return Ok(oauth_error_redirect(
                &frontend_callback,
                "login_failed",
                "wechat login could not be completed",
                "",
                &[clear_state],
            ));
        }
    };
    Ok(match outcome {
        OAuthLoginOutcome::Auth(auth) => {
            let expires_in = auth.expires_in.to_string();
            fragment_redirect(
                &frontend_callback,
                &[
                    ("access_token", auth.access_token.as_str()),
                    ("refresh_token", auth.refresh_token.as_str()),
                    ("expires_in", expires_in.as_str()),
                    ("token_type", auth.token_type),
                    ("redirect", consumed.redirect_to.as_str()),
                ],
                &[clear_state],
            )
        }
        OAuthLoginOutcome::RegistrationPending {
            session_token,
            browser_session_key,
            ..
        } => redirect_response(
            &frontend_callback,
            &[
                clear_state,
                pending_cookie(PENDING_SESSION_COOKIE, &session_token, secure),
                pending_cookie(PENDING_BROWSER_COOKIE, &browser_session_key, secure),
            ],
        ),
    })
}

async fn wechat_payment_callback(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    query: Result<Query<OAuthCallbackQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let query = query_payload(query)?;
    let frontend_callback = "/auth/wechat/payment/callback";
    let secure = request_is_https(&headers);
    let clear_state = clear_cookie(STATE_COOKIE, secure);
    let code = query.code.as_deref().map(str::trim).unwrap_or_default();
    let raw_state = query.state.as_deref().map(str::trim).unwrap_or_default();
    let cookie_state = cookie_value(&headers, STATE_COOKIE).unwrap_or_default();
    if code.is_empty() || raw_state.is_empty() || !constant_time_equal(raw_state, cookie_state) {
        return Ok(oauth_error_redirect(
            frontend_callback,
            "invalid_state",
            "invalid oauth state",
            "",
            &[clear_state],
        ));
    }
    let Some(consumed) = consume_state(&state, "wechat", raw_state).await? else {
        return Ok(oauth_error_redirect(
            frontend_callback,
            "invalid_state",
            "invalid or expired oauth state",
            "",
            &[clear_state],
        ));
    };
    if consumed
        .provider_context
        .get("kind")
        .and_then(Value::as_str)
        != Some("payment")
    {
        return Ok(oauth_error_redirect(
            frontend_callback,
            "invalid_context",
            "invalid oauth context",
            "",
            &[clear_state],
        ));
    }
    let config = load_wechat_config(&state, "mp").await?;
    let token = match exchange_wechat_token(&config, code).await {
        Ok(token) => token,
        Err(error) => {
            tracing::warn!(error = %error, "WeChat payment OAuth exchange failed");
            return Ok(oauth_error_redirect(
                frontend_callback,
                "token_exchange_failed",
                "failed to exchange oauth code",
                "",
                &[clear_state],
            ));
        }
    };
    if token.openid.trim().is_empty() {
        return Ok(oauth_error_redirect(
            frontend_callback,
            "missing_openid",
            "missing openid",
            "",
            &[clear_state],
        ));
    }
    let resume_token = format!("wxresume_{}", random_bearer());
    let resume_hash = Sha256::digest(resume_token.as_bytes());
    let context = &consumed.provider_context;
    sqlx::query(
        r"
INSERT INTO auth_wechat_payment_resume_tokens (
    id, token_hash, openid, payment_type, amount, order_type, plan_id,
    redirect_to, scope, expires_at
)
VALUES (
    $1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, NOW() + INTERVAL '10 minutes'
)
",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(resume_hash.as_slice())
    .bind(&token.openid)
    .bind(
        context
            .get("payment_type")
            .and_then(Value::as_str)
            .unwrap_or("wxpay"),
    )
    .bind(
        context
            .get("amount")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    )
    .bind(
        context
            .get("order_type")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    )
    .bind(context.get("plan_id").and_then(Value::as_i64))
    .bind(&consumed.redirect_to)
    .bind(if token.scope.is_empty() {
        context
            .get("scope")
            .and_then(Value::as_str)
            .unwrap_or("snsapi_base")
    } else {
        token.scope.as_str()
    })
    .execute(state.pool())
    .await?;
    Ok(fragment_redirect(
        frontend_callback,
        &[
            ("wechat_resume_token", resume_token.as_str()),
            ("redirect", consumed.redirect_to.as_str()),
        ],
        &[clear_state],
    ))
}

async fn dingtalk_callback(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    query: Result<Query<OAuthCallbackQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let query = query_payload(query)?;
    let config = load_dingtalk_config(&state).await?;
    let secure = request_is_https(&headers);
    let clear_state = clear_cookie(STATE_COOKIE, secure);
    if let Some(error) = query
        .error
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Ok(oauth_error_redirect(
            &config.frontend_callback,
            "provider_error",
            error,
            query.error_description.as_deref().unwrap_or_default(),
            &[clear_state],
        ));
    }
    let code = query.code.as_deref().map(str::trim).unwrap_or_default();
    let raw_state = query.state.as_deref().map(str::trim).unwrap_or_default();
    let cookie_state = cookie_value(&headers, STATE_COOKIE).unwrap_or_default();
    if code.is_empty() || raw_state.is_empty() || !constant_time_equal(raw_state, cookie_state) {
        return Ok(oauth_error_redirect(
            &config.frontend_callback,
            "invalid_state",
            "invalid oauth state",
            "",
            &[clear_state],
        ));
    }
    let Some(consumed) = consume_state(&state, "dingtalk", raw_state).await? else {
        return Ok(oauth_error_redirect(
            &config.frontend_callback,
            "invalid_state",
            "invalid or expired oauth state",
            "",
            &[clear_state],
        ));
    };
    let profile = match exchange_dingtalk_profile(&config, code).await {
        Ok(profile) => profile,
        Err(error) => {
            tracing::warn!(error = %error, "DingTalk OAuth exchange failed");
            return Ok(oauth_error_redirect(
                &config.frontend_callback,
                "provider_error",
                "dingtalk_identity_fetch_failed",
                "",
                &[clear_state],
            ));
        }
    };
    if consumed.intent == "bind_current_user" {
        let target_user_id = consumed
            .target_user_id
            .ok_or_else(|| ApiError::unauthorized("OAuth bind state does not identify a user"))?;
        if let Err(error) = state.bind_oauth_identity(target_user_id, profile).await {
            tracing::warn!(status = %error.status(), "DingTalk identity binding failed");
            return Ok(oauth_error_redirect(
                &config.frontend_callback,
                "bind_failed",
                "dingtalk identity could not be bound",
                "",
                &[clear_state],
            ));
        }
        return Ok(fragment_redirect(
            &config.frontend_callback,
            &[("redirect", consumed.redirect_to.as_str())],
            &[clear_state],
        ));
    }
    if consumed.intent != "login" {
        return Ok(oauth_error_redirect(
            &config.frontend_callback,
            "invalid_state",
            "invalid oauth intent",
            "",
            &[clear_state],
        ));
    }
    let outcome = match state
        .oauth_login_or_begin_registration(
            profile,
            &consumed.redirect_to,
            &consumed.promo_code,
            &consumed.affiliate_code,
        )
        .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            tracing::warn!(status = %error.status(), "DingTalk local login failed");
            return Ok(oauth_error_redirect(
                &config.frontend_callback,
                "login_failed",
                "dingtalk login could not be completed",
                "",
                &[clear_state],
            ));
        }
    };
    Ok(match outcome {
        OAuthLoginOutcome::Auth(auth) => {
            let expires_in = auth.expires_in.to_string();
            fragment_redirect(
                &config.frontend_callback,
                &[
                    ("access_token", auth.access_token.as_str()),
                    ("refresh_token", auth.refresh_token.as_str()),
                    ("expires_in", expires_in.as_str()),
                    ("token_type", auth.token_type),
                    ("redirect", consumed.redirect_to.as_str()),
                ],
                &[clear_state],
            )
        }
        OAuthLoginOutcome::RegistrationPending {
            session_token,
            browser_session_key,
            ..
        } => redirect_response(
            &config.frontend_callback,
            &[
                clear_state,
                pending_cookie(PENDING_SESSION_COOKIE, &session_token, secure),
                pending_cookie(PENDING_BROWSER_COOKIE, &browser_session_key, secure),
            ],
        ),
    })
}

async fn oauth_callback(
    state: ControlApiState,
    headers: HeaderMap,
    query: OAuthCallbackQuery,
    provider: &'static str,
) -> Result<Response, ApiError> {
    let config = load_provider_config(&state, provider).await?;
    let secure = request_is_https(&headers);
    let clear_state = clear_cookie(STATE_COOKIE, secure);
    if let Some(provider_error) = query
        .error
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        return Ok(oauth_error_redirect(
            &config.frontend_callback,
            "provider_error",
            provider_error,
            query.error_description.as_deref().unwrap_or_default(),
            &[clear_state],
        ));
    }
    let code = query.code.as_deref().map(str::trim).unwrap_or_default();
    let raw_state = query.state.as_deref().map(str::trim).unwrap_or_default();
    if code.is_empty() || raw_state.is_empty() {
        return Ok(oauth_error_redirect(
            &config.frontend_callback,
            "missing_params",
            "missing code/state",
            "",
            &[clear_state],
        ));
    }
    let cookie_state = cookie_value(&headers, STATE_COOKIE).unwrap_or_default();
    if !constant_time_equal(raw_state, cookie_state) {
        return Ok(oauth_error_redirect(
            &config.frontend_callback,
            "invalid_state",
            "invalid oauth state",
            "",
            &[clear_state],
        ));
    }
    let Some(consumed) = consume_state(&state, provider, raw_state).await? else {
        return Ok(oauth_error_redirect(
            &config.frontend_callback,
            "invalid_state",
            "invalid or expired oauth state",
            "",
            &[clear_state],
        ));
    };
    let profile = match exchange_profile(&config, code).await {
        Ok(profile) => profile,
        Err(error) => {
            tracing::warn!(provider, error = %error, "OAuth provider exchange failed");
            return Ok(oauth_error_redirect(
                &config.frontend_callback,
                "token_exchange_failed",
                "failed to complete oauth login",
                "",
                &[clear_state],
            ));
        }
    };
    if consumed.intent == "bind_current_user" {
        let target_user_id = consumed
            .target_user_id
            .ok_or_else(|| ApiError::unauthorized("OAuth bind state does not identify a user"))?;
        if let Err(error) = state.bind_oauth_identity(target_user_id, profile).await {
            tracing::warn!(provider, status = %error.status(), "OAuth identity binding failed");
            return Ok(oauth_error_redirect(
                &config.frontend_callback,
                "bind_failed",
                "oauth identity could not be bound",
                "",
                &[clear_state],
            ));
        }
        return Ok(fragment_redirect(
            &config.frontend_callback,
            &[("redirect", consumed.redirect_to.as_str())],
            &[clear_state],
        ));
    }
    if consumed.intent != "login" {
        return Ok(oauth_error_redirect(
            &config.frontend_callback,
            "invalid_state",
            "invalid oauth intent",
            "",
            &[clear_state],
        ));
    }
    let outcome = match state
        .oauth_login_or_begin_registration(
            profile,
            &consumed.redirect_to,
            &consumed.promo_code,
            &consumed.affiliate_code,
        )
        .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            tracing::warn!(provider, status = %error.status(), "OAuth local login failed");
            return Ok(oauth_error_redirect(
                &config.frontend_callback,
                "login_failed",
                "oauth login could not be completed",
                "",
                &[clear_state],
            ));
        }
    };
    match outcome {
        OAuthLoginOutcome::Auth(auth) => {
            let fragment = [
                ("access_token", auth.access_token.as_str()),
                ("refresh_token", auth.refresh_token.as_str()),
                ("expires_in", &auth.expires_in.to_string()),
                ("token_type", auth.token_type),
                ("redirect", consumed.redirect_to.as_str()),
            ];
            Ok(fragment_redirect(
                &config.frontend_callback,
                &fragment,
                &[clear_state],
            ))
        }
        OAuthLoginOutcome::RegistrationPending {
            session_token,
            browser_session_key,
            suggested_email,
        } => {
            tracing::debug!(provider, email = %suggested_email, "OAuth registration requires completion");
            Ok(redirect_response(
                &config.frontend_callback,
                &[
                    clear_state,
                    pending_cookie(PENDING_SESSION_COOKIE, &session_token, secure),
                    pending_cookie(PENDING_BROWSER_COOKIE, &browser_session_key, secure),
                ],
            ))
        }
    }
}

async fn github_complete_registration(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    Json(request): Json<CompleteOAuthRegistrationRequest>,
) -> Result<Response, ApiError> {
    complete_registration(state, headers, request, "github").await
}

async fn google_complete_registration(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    Json(request): Json<CompleteOAuthRegistrationRequest>,
) -> Result<Response, ApiError> {
    complete_registration(state, headers, request, "google").await
}

async fn linuxdo_complete_registration(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    Json(request): Json<CompleteOAuthRegistrationRequest>,
) -> Result<Response, ApiError> {
    complete_registration(state, headers, request, "linuxdo").await
}

async fn oidc_complete_registration(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    Json(request): Json<CompleteOAuthRegistrationRequest>,
) -> Result<Response, ApiError> {
    complete_registration(state, headers, request, "oidc").await
}

async fn wechat_complete_registration(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    Json(request): Json<CompleteWechatOAuthRequest>,
) -> Result<Response, ApiError> {
    let session_token = cookie_value(&headers, PENDING_SESSION_COOKIE)
        .ok_or_else(|| ApiError::unauthorized("Pending OAuth session is missing"))?;
    let browser_session_key = cookie_value(&headers, PENDING_BROWSER_COOKIE)
        .ok_or_else(|| ApiError::unauthorized("Pending OAuth browser session is missing"))?;
    if request.adopt_display_name.is_some() || request.adopt_avatar.is_some() {
        tracing::debug!(
            adopt_display_name = ?request.adopt_display_name,
            adopt_avatar = ?request.adopt_avatar,
            "WeChat OAuth profile adoption preference received"
        );
    }
    let auth = state
        .complete_oauth_registration(OAuthRegistrationCompletion {
            provider: "wechat",
            session_token,
            browser_session_key,
            password: random_bearer(),
            invitation_code: &request.invitation_code,
            affiliate_code: &request.aff_code,
            requested_email: None,
            verify_code: "",
        })
        .await?;
    Ok(token_pair_response(&auth, &headers))
}

async fn dingtalk_complete_registration(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    Json(request): Json<CompleteWechatOAuthRequest>,
) -> Result<Response, ApiError> {
    let session_token = cookie_value(&headers, PENDING_SESSION_COOKIE)
        .ok_or_else(|| ApiError::unauthorized("Pending OAuth session is missing"))?;
    let browser_session_key = cookie_value(&headers, PENDING_BROWSER_COOKIE)
        .ok_or_else(|| ApiError::unauthorized("Pending OAuth browser session is missing"))?;
    if request.adopt_display_name.is_some() || request.adopt_avatar.is_some() {
        tracing::debug!(
            adopt_display_name = ?request.adopt_display_name,
            adopt_avatar = ?request.adopt_avatar,
            "DingTalk OAuth profile adoption preference received"
        );
    }
    let auth = state
        .complete_oauth_registration(OAuthRegistrationCompletion {
            provider: "dingtalk",
            session_token,
            browser_session_key,
            password: random_bearer(),
            invitation_code: &request.invitation_code,
            affiliate_code: &request.aff_code,
            requested_email: None,
            verify_code: "",
        })
        .await?;
    Ok(token_pair_response(&auth, &headers))
}

async fn complete_registration(
    state: ControlApiState,
    headers: HeaderMap,
    request: CompleteOAuthRegistrationRequest,
    provider: &'static str,
) -> Result<Response, ApiError> {
    let session_token = cookie_value(&headers, PENDING_SESSION_COOKIE)
        .ok_or_else(|| ApiError::unauthorized("Pending OAuth session is missing"))?;
    let browser_session_key = cookie_value(&headers, PENDING_BROWSER_COOKIE)
        .ok_or_else(|| ApiError::unauthorized("Pending OAuth browser session is missing"))?;
    let auth = state
        .complete_oauth_registration(OAuthRegistrationCompletion {
            provider,
            session_token,
            browser_session_key,
            password: request.password,
            invitation_code: &request.invitation_code,
            affiliate_code: &request.aff_code,
            requested_email: None,
            verify_code: "",
        })
        .await?;
    let secure = request_is_https(&headers);
    let mut response = Json(json!({
        "access_token": auth.access_token,
        "refresh_token": auth.refresh_token,
        "expires_in": auth.expires_in,
        "token_type": auth.token_type
    }))
    .into_response();
    append_cookie(
        response.headers_mut(),
        &clear_cookie(PENDING_SESSION_COOKIE, secure),
    );
    append_cookie(
        response.headers_mut(),
        &clear_cookie(PENDING_BROWSER_COOKIE, secure),
    );
    Ok(response)
}

async fn linuxdo_bind_login(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    Json(request): Json<PendingOAuthBindLoginRequest>,
) -> Result<Response, ApiError> {
    bind_pending_login(state, headers, request, Some("linuxdo")).await
}

async fn oidc_bind_login(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    Json(request): Json<PendingOAuthBindLoginRequest>,
) -> Result<Response, ApiError> {
    bind_pending_login(state, headers, request, Some("oidc")).await
}

async fn wechat_bind_login(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    Json(request): Json<PendingOAuthBindLoginRequest>,
) -> Result<Response, ApiError> {
    bind_pending_login(state, headers, request, Some("wechat")).await
}

async fn dingtalk_bind_login(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    Json(request): Json<PendingOAuthBindLoginRequest>,
) -> Result<Response, ApiError> {
    bind_pending_login(state, headers, request, Some("dingtalk")).await
}

async fn pending_bind_login(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    Json(request): Json<PendingOAuthBindLoginRequest>,
) -> Result<Response, ApiError> {
    bind_pending_login(state, headers, request, None).await
}

async fn bind_pending_login(
    state: ControlApiState,
    headers: HeaderMap,
    request: PendingOAuthBindLoginRequest,
    expected_provider: Option<&str>,
) -> Result<Response, ApiError> {
    let session_token = cookie_value(&headers, PENDING_SESSION_COOKIE)
        .ok_or_else(|| ApiError::unauthorized("Pending OAuth session is missing"))?;
    let browser_session_key = cookie_value(&headers, PENDING_BROWSER_COOKIE)
        .ok_or_else(|| ApiError::unauthorized("Pending OAuth browser session is missing"))?;
    if request.adopt_display_name.is_some() || request.adopt_avatar.is_some() {
        tracing::debug!(
            adopt_display_name = ?request.adopt_display_name,
            adopt_avatar = ?request.adopt_avatar,
            "pending OAuth profile adoption preference received"
        );
    }
    let auth = state
        .bind_pending_oauth_login(
            expected_provider,
            session_token,
            browser_session_key,
            &request.email,
            request.password,
        )
        .await?;
    Ok(token_pair_response(&auth, &headers))
}

async fn linuxdo_create_account(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    Json(request): Json<PendingOAuthCreateAccountRequest>,
) -> Result<Response, ApiError> {
    create_pending_account(state, headers, request, Some("linuxdo")).await
}

async fn oidc_create_account(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    Json(request): Json<PendingOAuthCreateAccountRequest>,
) -> Result<Response, ApiError> {
    create_pending_account(state, headers, request, Some("oidc")).await
}

async fn wechat_create_account(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    Json(request): Json<PendingOAuthCreateAccountRequest>,
) -> Result<Response, ApiError> {
    create_pending_account(state, headers, request, Some("wechat")).await
}

async fn dingtalk_create_account(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    Json(request): Json<PendingOAuthCreateAccountRequest>,
) -> Result<Response, ApiError> {
    create_pending_account(state, headers, request, Some("dingtalk")).await
}

async fn pending_create_account(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    Json(request): Json<PendingOAuthCreateAccountRequest>,
) -> Result<Response, ApiError> {
    create_pending_account(state, headers, request, None).await
}

async fn create_pending_account(
    state: ControlApiState,
    headers: HeaderMap,
    request: PendingOAuthCreateAccountRequest,
    expected_provider: Option<&str>,
) -> Result<Response, ApiError> {
    let session_token = cookie_value(&headers, PENDING_SESSION_COOKIE)
        .ok_or_else(|| ApiError::unauthorized("Pending OAuth session is missing"))?;
    let browser_session_key = cookie_value(&headers, PENDING_BROWSER_COOKIE)
        .ok_or_else(|| ApiError::unauthorized("Pending OAuth browser session is missing"))?;
    let provider = pending_provider(
        &state,
        session_token,
        browser_session_key,
        expected_provider,
    )
    .await?;
    if request.adopt_display_name.is_some() || request.adopt_avatar.is_some() {
        tracing::debug!(
            adopt_display_name = ?request.adopt_display_name,
            adopt_avatar = ?request.adopt_avatar,
            "pending OAuth account profile adoption preference received"
        );
    }
    let auth = state
        .complete_oauth_registration(OAuthRegistrationCompletion {
            provider: &provider,
            session_token,
            browser_session_key,
            password: request.password,
            invitation_code: &request.invitation_code,
            affiliate_code: &request.aff_code,
            requested_email: Some(&request.email),
            verify_code: &request.verify_code,
        })
        .await?;
    Ok(token_pair_response(&auth, &headers))
}

async fn pending_send_verify_code(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    Json(request): Json<PendingOAuthSendVerifyCodeRequest>,
) -> Result<Json<ApiEnvelope<super::models::SendVerificationCodeResponse>>, ApiError> {
    let session_token = cookie_value(&headers, PENDING_SESSION_COOKIE)
        .or_else(|| {
            (!request.pending_auth_token.trim().is_empty())
                .then_some(request.pending_auth_token.trim())
        })
        .or_else(|| {
            (!request.pending_oauth_token.trim().is_empty())
                .then_some(request.pending_oauth_token.trim())
        })
        .ok_or_else(|| ApiError::unauthorized("Pending OAuth session is missing"))?;
    let browser_session_key = cookie_value(&headers, PENDING_BROWSER_COOKIE)
        .ok_or_else(|| ApiError::unauthorized("Pending OAuth browser session is missing"))?;
    let _provider = pending_provider(&state, session_token, browser_session_key, None).await?;
    let response = state
        .send_verification_code(SendVerificationCodeRequest {
            email: request.email,
            turnstile_token: request.turnstile_token,
        })
        .await?;
    Ok(Json(ApiEnvelope::success(response)))
}

async fn pending_provider(
    state: &ControlApiState,
    session_token: &str,
    browser_session_key: &str,
    expected_provider: Option<&str>,
) -> Result<String, ApiError> {
    let session_hash = hex::encode(Sha256::digest(session_token.as_bytes()));
    let browser_hash = hex::encode(Sha256::digest(browser_session_key.as_bytes()));
    sqlx::query_scalar::<_, String>(
        r"
SELECT provider_type
FROM pending_auth_sessions
WHERE session_token = $1
  AND browser_session_key = $2
  AND ($3::text IS NULL OR provider_type = $3)
  AND consumed_at IS NULL
  AND expires_at > NOW()
LIMIT 1
",
    )
    .bind(session_hash)
    .bind(browser_hash)
    .bind(expected_provider)
    .fetch_optional(state.pool())
    .await?
    .ok_or_else(|| ApiError::unauthorized("Pending OAuth session is invalid or expired"))
}

fn token_pair_response(auth: &super::models::AuthResponse, headers: &HeaderMap) -> Response {
    let secure = request_is_https(headers);
    let mut response = Json(json!({
        "access_token": auth.access_token,
        "refresh_token": auth.refresh_token,
        "expires_in": auth.expires_in,
        "token_type": auth.token_type
    }))
    .into_response();
    append_cookie(
        response.headers_mut(),
        &clear_cookie(PENDING_SESSION_COOKIE, secure),
    );
    append_cookie(
        response.headers_mut(),
        &clear_cookie(PENDING_BROWSER_COOKIE, secure),
    );
    response
}

async fn exchange_pending_completion(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let session_token = cookie_value(&headers, PENDING_SESSION_COOKIE)
        .ok_or_else(|| ApiError::unauthorized("Pending OAuth session is missing"))?;
    let browser_session_key = cookie_value(&headers, PENDING_BROWSER_COOKIE)
        .ok_or_else(|| ApiError::unauthorized("Pending OAuth browser session is missing"))?;
    let session_hash = hex::encode(Sha256::digest(session_token.as_bytes()));
    let browser_hash = hex::encode(Sha256::digest(browser_session_key.as_bytes()));
    let row = sqlx::query(
        r"
SELECT local_flow_state, upstream_identity_claims, redirect_to, provider_type, resolved_email
FROM pending_auth_sessions
WHERE session_token = $1
  AND browser_session_key = $2
  AND consumed_at IS NULL
  AND expires_at > NOW()
LIMIT 1
",
    )
    .bind(session_hash)
    .bind(browser_hash)
    .fetch_optional(state.pool())
    .await?
    .ok_or_else(|| ApiError::unauthorized("Pending OAuth session is invalid or expired"))?;
    let local: Value = row.try_get("local_flow_state")?;
    let claims: Value = row.try_get("upstream_identity_claims")?;
    let mut payload = local
        .get("completion_response")
        .cloned()
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}));
    if let Some(object) = payload.as_object_mut() {
        object
            .entry("redirect")
            .or_insert(Value::String(row.try_get("redirect_to")?));
        object
            .entry("provider")
            .or_insert(Value::String(row.try_get("provider_type")?));
        object
            .entry("email")
            .or_insert(Value::String(row.try_get("resolved_email")?));
        for key in ["suggested_display_name", "suggested_avatar_url", "username"] {
            if let Some(value) = claims.get(key).cloned() {
                object.entry(key).or_insert(value);
            }
        }
    }
    Ok(Json(payload))
}

async fn consume_state(
    state: &ControlApiState,
    provider: &str,
    raw_state: &str,
) -> Result<Option<ConsumedState>, ApiError> {
    let digest = Sha256::digest(raw_state.as_bytes());
    let row = sqlx::query(
        r"
UPDATE auth_oauth_states
SET consumed_at = NOW()
WHERE state_hash = $1
  AND provider_type = $2
  AND consumed_at IS NULL
  AND expires_at > NOW()
RETURNING
    redirect_to, promo_code, affiliate_code, verifier_hash, nonce_hash,
    intent, target_user_id
    , provider_context
",
    )
    .bind(digest.as_slice())
    .bind(provider)
    .fetch_optional(state.pool())
    .await?;
    row.map(|row| {
        Ok(ConsumedState {
            redirect_to: row.try_get("redirect_to")?,
            promo_code: row.try_get("promo_code")?,
            affiliate_code: row.try_get("affiliate_code")?,
            verifier_hash: row.try_get("verifier_hash")?,
            nonce_hash: row.try_get("nonce_hash")?,
            intent: row.try_get("intent")?,
            target_user_id: row.try_get("target_user_id")?,
            provider_context: row.try_get("provider_context")?,
        })
    })
    .transpose()
}

async fn load_oidc_config(state: &ControlApiState) -> Result<OidcConfig, ApiError> {
    let rows = sqlx::query("SELECT key, value FROM settings WHERE key LIKE 'oidc_connect_%'")
        .fetch_all(state.pool())
        .await?;
    let settings = rows
        .into_iter()
        .map(|row| {
            Ok((
                row.try_get::<String, _>("key")?,
                row.try_get::<String, _>("value")?,
            ))
        })
        .collect::<Result<HashMap<_, _>, sqlx::Error>>()?;
    let get = |suffix: &str| {
        settings
            .get(&format!("oidc_connect_{suffix}"))
            .map(String::as_str)
            .unwrap_or_default()
            .trim()
    };
    if !get("enabled").eq_ignore_ascii_case("true") {
        return Err(ApiError::not_found("OAuth login is disabled"));
    }
    let client_id = get("client_id").to_owned();
    let client_secret = get("client_secret").to_owned();
    let redirect_url = get("redirect_url").to_owned();
    if client_id.is_empty() || redirect_url.is_empty() {
        return Err(ApiError::internal(
            "load OIDC configuration",
            "client ID and redirect URL are required",
        ));
    }
    validate_absolute_http_url(&redirect_url)?;
    let mut issuer = get("issuer_url").trim_end_matches('/').to_owned();
    let mut authorize_url = get("authorize_url").to_owned();
    let mut token_url = get("token_url").to_owned();
    let mut userinfo_url = get("userinfo_url").to_owned();
    let mut jwks_url = get("jwks_url").to_owned();
    let discovery_url = if get("discovery_url").is_empty() {
        (!issuer.is_empty()).then(|| format!("{issuer}/.well-known/openid-configuration"))
    } else {
        Some(get("discovery_url").to_owned())
    };
    if let Some(discovery_url) = discovery_url
        && (issuer.is_empty()
            || authorize_url.is_empty()
            || token_url.is_empty()
            || userinfo_url.is_empty()
            || jwks_url.is_empty())
    {
        validate_absolute_http_url(&discovery_url)?;
        let discovery: Value = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|error| ApiError::internal("build OIDC discovery client", error))?
            .get(discovery_url)
            .send()
            .await
            .map_err(|error| ApiError::internal("request OIDC discovery document", error))?
            .error_for_status()
            .map_err(|error| ApiError::internal("load OIDC discovery document", error))?
            .json()
            .await
            .map_err(|error| ApiError::internal("decode OIDC discovery document", error))?;
        fill_if_empty(&mut issuer, json_string(&discovery, "issuer"));
        fill_if_empty(
            &mut authorize_url,
            json_string(&discovery, "authorization_endpoint"),
        );
        fill_if_empty(&mut token_url, json_string(&discovery, "token_endpoint"));
        fill_if_empty(
            &mut userinfo_url,
            json_string(&discovery, "userinfo_endpoint"),
        );
        fill_if_empty(&mut jwks_url, json_string(&discovery, "jwks_uri"));
    }
    for value in [&issuer, &authorize_url, &token_url, &userinfo_url] {
        validate_absolute_http_url(value)?;
    }
    let validate_id_token = parse_bool_default(get("validate_id_token"), true);
    if validate_id_token {
        validate_absolute_http_url(&jwks_url)?;
    }
    let scopes = if get("scopes").is_empty() {
        "openid email profile".to_owned()
    } else {
        get("scopes").to_owned()
    };
    if !scopes.split_whitespace().any(|scope| scope == "openid") {
        return Err(ApiError::internal(
            "load OIDC configuration",
            "OIDC scopes must contain openid",
        ));
    }
    let token_auth_method = match get("token_auth_method") {
        "" | "client_secret_post" => "client_secret_post".to_owned(),
        "client_secret_basic" => "client_secret_basic".to_owned(),
        "none" => "none".to_owned(),
        _ => {
            return Err(ApiError::internal(
                "load OIDC configuration",
                "unsupported token authentication method",
            ));
        }
    };
    if token_auth_method != "none" && client_secret.is_empty() {
        return Err(ApiError::internal(
            "load OIDC configuration",
            "client secret is required for the configured token authentication method",
        ));
    }
    let allowed_signing_algs = match get("allowed_signing_algs") {
        "" => vec!["RS256".to_owned(), "ES256".to_owned(), "PS256".to_owned()],
        raw => raw
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect(),
    };
    if allowed_signing_algs.is_empty()
        || allowed_signing_algs.iter().any(|algorithm| {
            !matches!(
                algorithm.as_str(),
                "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" | "ES256"
            )
        })
    {
        return Err(ApiError::internal(
            "load OIDC configuration",
            "allowed signing algorithms contain an unsupported value",
        ));
    }
    let clock_skew_seconds = get("clock_skew_seconds")
        .parse::<i64>()
        .unwrap_or(120)
        .clamp(0, 600);
    let frontend_callback = match get("frontend_redirect_url") {
        "" => "/auth/oidc/callback".to_owned(),
        value => validate_frontend_callback(value)?,
    };
    Ok(OidcConfig {
        client_id,
        client_secret,
        issuer,
        authorize_url,
        token_url,
        userinfo_url,
        jwks_url,
        scopes,
        redirect_url,
        frontend_callback,
        token_auth_method,
        use_pkce: parse_bool_default(get("use_pkce"), true),
        validate_id_token,
        require_email_verified: parse_bool_default(get("require_email_verified"), false),
        allowed_signing_algs,
        clock_skew_seconds,
    })
}

async fn load_wechat_config(state: &ControlApiState, mode: &str) -> Result<WechatConfig, ApiError> {
    let rows = sqlx::query(
        "SELECT key, value FROM settings WHERE key LIKE 'wechat_connect_%' OR key = 'api_base_url'",
    )
    .fetch_all(state.pool())
    .await?;
    let settings = rows
        .into_iter()
        .map(|row| {
            Ok((
                row.try_get::<String, _>("key")?,
                row.try_get::<String, _>("value")?,
            ))
        })
        .collect::<Result<HashMap<_, _>, sqlx::Error>>()?;
    let get = |key: &str| {
        settings
            .get(key)
            .map(String::as_str)
            .unwrap_or_default()
            .trim()
    };
    if !get("wechat_connect_enabled").eq_ignore_ascii_case("true") {
        return Err(ApiError::not_found("WeChat OAuth login is disabled"));
    }
    let (enabled_key, app_id_key, app_secret_key, authorize_url, default_scope) = match mode {
        "open" => (
            "wechat_connect_open_enabled",
            "wechat_connect_open_app_id",
            "wechat_connect_open_app_secret",
            "https://open.weixin.qq.com/connect/qrconnect",
            "snsapi_login",
        ),
        "mp" => (
            "wechat_connect_mp_enabled",
            "wechat_connect_mp_app_id",
            "wechat_connect_mp_app_secret",
            "https://open.weixin.qq.com/connect/oauth2/authorize",
            "snsapi_userinfo",
        ),
        _ => {
            return Err(ApiError::bad_request(
                "WeChat OAuth mode must be open or mp",
            ));
        }
    };
    if !get(enabled_key).eq_ignore_ascii_case("true") {
        return Err(ApiError::not_found("WeChat OAuth mode is disabled"));
    }
    let app_id = if get(app_id_key).is_empty() {
        get("wechat_connect_app_id").to_owned()
    } else {
        get(app_id_key).to_owned()
    };
    let app_secret = if get(app_secret_key).is_empty() {
        get("wechat_connect_app_secret").to_owned()
    } else {
        get(app_secret_key).to_owned()
    };
    if app_id.is_empty() || app_secret.is_empty() {
        return Err(ApiError::internal(
            "load WeChat OAuth configuration",
            "app ID and app secret are required",
        ));
    }
    let redirect_url = if get("wechat_connect_redirect_url").is_empty() {
        let api_base = get("api_base_url").trim_end_matches('/');
        if api_base.is_empty() {
            return Err(ApiError::internal(
                "load WeChat OAuth configuration",
                "redirect URL or public API base URL is required",
            ));
        }
        format!("{api_base}/api/v1/auth/oauth/wechat/callback")
    } else {
        get("wechat_connect_redirect_url").to_owned()
    };
    validate_absolute_http_url(&redirect_url)?;
    let frontend_callback = match get("wechat_connect_frontend_redirect_url") {
        "" => "/auth/wechat/callback".to_owned(),
        value => validate_frontend_callback(value)?,
    };
    let scope = if mode == "mp" {
        match get("wechat_connect_scopes") {
            "snsapi_base" => "snsapi_base".to_owned(),
            _ => "snsapi_userinfo".to_owned(),
        }
    } else {
        default_scope.to_owned()
    };
    Ok(WechatConfig {
        mode: mode.to_owned(),
        app_id,
        app_secret,
        authorize_url,
        scope,
        redirect_url,
        frontend_callback,
        requires_union_id: get("wechat_connect_open_enabled").eq_ignore_ascii_case("true")
            && get("wechat_connect_mp_enabled").eq_ignore_ascii_case("true"),
    })
}

async fn load_dingtalk_config(state: &ControlApiState) -> Result<DingTalkConfig, ApiError> {
    let rows = sqlx::query("SELECT key, value FROM settings WHERE key LIKE 'dingtalk_connect_%'")
        .fetch_all(state.pool())
        .await?;
    let settings = rows
        .into_iter()
        .map(|row| {
            Ok((
                row.try_get::<String, _>("key")?,
                row.try_get::<String, _>("value")?,
            ))
        })
        .collect::<Result<HashMap<_, _>, sqlx::Error>>()?;
    let get = |suffix: &str| {
        settings
            .get(&format!("dingtalk_connect_{suffix}"))
            .map(String::as_str)
            .unwrap_or_default()
            .trim()
    };
    if !get("enabled").eq_ignore_ascii_case("true") {
        return Err(ApiError::not_found("DingTalk OAuth login is disabled"));
    }
    let client_id = get("client_id").to_owned();
    let client_secret = get("client_secret").to_owned();
    let redirect_url = get("redirect_url").to_owned();
    if client_id.is_empty() || client_secret.is_empty() || redirect_url.is_empty() {
        return Err(ApiError::internal(
            "load DingTalk OAuth configuration",
            "client ID, client secret, and redirect URL are required",
        ));
    }
    validate_absolute_http_url(&redirect_url)?;
    let frontend_callback = match get("frontend_redirect_url") {
        "" => "/auth/dingtalk/callback".to_owned(),
        value => validate_frontend_callback(value)?,
    };
    let corp_restriction_policy = match get("corp_restriction_policy") {
        "internal_only" => "internal_only".to_owned(),
        _ => "none".to_owned(),
    };
    let internal_corp_id = get("internal_corp_id").to_owned();
    if corp_restriction_policy == "internal_only" && internal_corp_id.is_empty() {
        return Err(ApiError::internal(
            "load DingTalk OAuth configuration",
            "internal corp ID is required by the restriction policy",
        ));
    }
    Ok(DingTalkConfig {
        client_id,
        client_secret,
        redirect_url,
        frontend_callback,
        scopes: if get("scopes").is_empty() {
            "openid".to_owned()
        } else {
            get("scopes").to_owned()
        },
        corp_restriction_policy,
        internal_corp_id,
    })
}

async fn exchange_dingtalk_profile(
    config: &DingTalkConfig,
    code: &str,
) -> Result<OAuthIdentityProfile, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|error| error.to_string())?;
    let token_response = client
        .post("https://api.dingtalk.com/v1.0/oauth2/userAccessToken")
        .json(&json!({
            "clientId": config.client_id,
            "clientSecret": config.client_secret,
            "code": code,
            "grantType": "authorization_code"
        }))
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !token_response.status().is_success() {
        return Err(format!(
            "DingTalk token endpoint returned {}",
            token_response.status()
        ));
    }
    let token: Value = token_response
        .json()
        .await
        .map_err(|error| error.to_string())?;
    let access_token = json_string(&token, "accessToken");
    if access_token.is_empty() {
        return Err("DingTalk token response omitted accessToken".to_owned());
    }
    let corp_id = json_string(&token, "corpId");
    if config.corp_restriction_policy == "internal_only" && corp_id != config.internal_corp_id {
        return Err("DingTalk account is outside the configured organization".to_owned());
    }
    let user_response = client
        .get("https://api.dingtalk.com/v1.0/contact/users/me")
        .header("x-acs-dingtalk-access-token", &access_token)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !user_response.status().is_success() {
        return Err(format!(
            "DingTalk userinfo endpoint returned {}",
            user_response.status()
        ));
    }
    let user: Value = user_response
        .json()
        .await
        .map_err(|error| error.to_string())?;
    let union_id = json_string(&user, "unionId");
    if union_id.is_empty() || union_id.len() > 255 {
        return Err("DingTalk userinfo omitted unionId".to_owned());
    }
    let nickname = first_nonempty([json_string(&user, "nick"), json_string(&user, "name")]);
    let username = if nickname.is_empty() {
        format!(
            "dingtalk_{}",
            &hex::encode(Sha256::digest(union_id.as_bytes()))[..12]
        )
    } else {
        nickname.clone()
    };
    Ok(OAuthIdentityProfile {
        provider: "dingtalk".to_owned(),
        provider_key: "dingtalk".to_owned(),
        subject: union_id.clone(),
        issuer: Some("https://login.dingtalk.com".to_owned()),
        email: format!(
            "dingtalk-{}@dingtalk-connect.invalid",
            union_id.to_ascii_lowercase()
        ),
        username,
        display_name: nickname,
        avatar_url: json_string(&user, "avatarUrl"),
        metadata: json!({
            "union_id": union_id,
            "corp_id": corp_id,
            "nickname": json_string(&user, "nick")
        }),
    })
}

async fn load_wechat_frontend_callback(state: &ControlApiState) -> Result<String, ApiError> {
    let value = sqlx::query_scalar::<_, String>(
        "SELECT value FROM settings WHERE key = 'wechat_connect_frontend_redirect_url'",
    )
    .fetch_optional(state.pool())
    .await?;
    match value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(value) => validate_frontend_callback(value),
        None => Ok("/auth/wechat/callback".to_owned()),
    }
}

fn resolve_wechat_mode<'a>(raw: Option<&'a str>, headers: &HeaderMap) -> Result<&'a str, ApiError> {
    match raw.map(str::trim).filter(|value| !value.is_empty()) {
        Some("open") => Ok("open"),
        Some("mp") => Ok("mp"),
        Some(_) => Err(ApiError::bad_request(
            "WeChat OAuth mode must be open or mp",
        )),
        None => {
            if headers
                .get("user-agent")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.to_ascii_lowercase().contains("micromessenger"))
            {
                Ok("mp")
            } else {
                Ok("open")
            }
        }
    }
}

fn build_wechat_authorize_url(config: &WechatConfig, state: &str) -> Result<String, ApiError> {
    let mut url = Url::parse(config.authorize_url)
        .map_err(|error| ApiError::internal("parse WeChat authorize URL", error))?;
    url.query_pairs_mut()
        .append_pair("appid", &config.app_id)
        .append_pair("redirect_uri", &config.redirect_url)
        .append_pair("response_type", "code")
        .append_pair("scope", &config.scope)
        .append_pair("state", state);
    url.set_fragment(Some("wechat_redirect"));
    Ok(url.to_string())
}

async fn exchange_wechat_token(config: &WechatConfig, code: &str) -> Result<WechatToken, String> {
    let mut endpoint = Url::parse("https://api.weixin.qq.com/sns/oauth2/access_token")
        .map_err(|error| error.to_string())?;
    endpoint
        .query_pairs_mut()
        .append_pair("appid", &config.app_id)
        .append_pair("secret", &config.app_secret)
        .append_pair("code", code)
        .append_pair("grant_type", "authorization_code");
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|error| error.to_string())?
        .get(endpoint)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err(format!(
            "WeChat token endpoint returned {}",
            response.status()
        ));
    }
    let body: Value = response.json().await.map_err(|error| error.to_string())?;
    if body
        .get("errcode")
        .and_then(Value::as_i64)
        .unwrap_or_default()
        != 0
    {
        return Err(format!(
            "WeChat token endpoint error {}",
            json_scalar_string(body.get("errcode")).unwrap_or_default()
        ));
    }
    let access_token = json_string(&body, "access_token");
    let openid = json_string(&body, "openid");
    if access_token.is_empty() || openid.is_empty() {
        return Err("WeChat token response omitted access_token or openid".to_owned());
    }
    Ok(WechatToken {
        access_token,
        openid,
        unionid: json_string(&body, "unionid"),
        scope: json_string(&body, "scope"),
    })
}

async fn exchange_wechat_profile(
    config: &WechatConfig,
    code: &str,
) -> Result<OAuthIdentityProfile, String> {
    let token = exchange_wechat_token(config, code).await?;
    let mut endpoint =
        Url::parse("https://api.weixin.qq.com/sns/userinfo").map_err(|error| error.to_string())?;
    endpoint
        .query_pairs_mut()
        .append_pair("access_token", &token.access_token)
        .append_pair("openid", &token.openid)
        .append_pair("lang", "zh_CN");
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|error| error.to_string())?
        .get(endpoint)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err(format!(
            "WeChat userinfo endpoint returned {}",
            response.status()
        ));
    }
    let user: Value = response.json().await.map_err(|error| error.to_string())?;
    if user
        .get("errcode")
        .and_then(Value::as_i64)
        .unwrap_or_default()
        != 0
    {
        return Err("WeChat userinfo endpoint returned an error".to_owned());
    }
    let unionid = first_nonempty([json_string(&user, "unionid"), token.unionid]);
    let openid = first_nonempty([json_string(&user, "openid"), token.openid]);
    let subject = if unionid.is_empty() {
        if config.requires_union_id {
            return Err("WeChat account did not return unionid".to_owned());
        }
        openid.clone()
    } else {
        unionid.clone()
    };
    if subject.is_empty() || subject.len() > 255 {
        return Err("WeChat account returned an invalid identity".to_owned());
    }
    let nickname = json_string(&user, "nickname");
    let username = if nickname.is_empty() {
        format!(
            "wechat_{}",
            &hex::encode(Sha256::digest(subject.as_bytes()))[..12]
        )
    } else {
        nickname.clone()
    };
    Ok(OAuthIdentityProfile {
        provider: "wechat".to_owned(),
        provider_key: "wechat-main".to_owned(),
        subject: subject.clone(),
        issuer: Some(config.app_id.clone()),
        email: format!("wechat-{subject}@wechat-connect.invalid"),
        username,
        display_name: nickname,
        avatar_url: json_string(&user, "headimgurl"),
        metadata: json!({
            "openid": openid,
            "unionid": unionid,
            "mode": config.mode,
            "channel": config.mode,
            "channel_app_id": config.app_id,
            "channel_subject": json_string(&user, "openid")
        }),
    })
}

fn normalize_wechat_payment_redirect(raw: &str) -> String {
    if raw == "/payment" {
        "/purchase".to_owned()
    } else if let Some(query) = raw.strip_prefix("/payment?") {
        format!("/purchase?{query}")
    } else {
        raw.to_owned()
    }
}

async fn exchange_oidc_profile(
    config: &OidcConfig,
    code: &str,
    verifier: &str,
    nonce: &str,
) -> Result<OAuthIdentityProfile, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent(concat!("sub2api-rust/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| error.to_string())?;
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("client_id", config.client_id.as_str()),
        ("code", code),
        ("redirect_uri", config.redirect_url.as_str()),
    ];
    if config.use_pkce {
        form.push(("code_verifier", verifier));
    }
    if config.token_auth_method == "client_secret_post" {
        form.push(("client_secret", config.client_secret.as_str()));
    }
    let token_body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(form)
        .finish();
    let mut request = client
        .post(&config.token_url)
        .header("accept", "application/json")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(token_body);
    if config.token_auth_method == "client_secret_basic" {
        request = request.basic_auth(&config.client_id, Some(&config.client_secret));
    }
    let response = request.send().await.map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err(format!(
            "OIDC token endpoint returned {}",
            response.status()
        ));
    }
    let token: Value = response.json().await.map_err(|error| error.to_string())?;
    let access_token = token
        .get("access_token")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "OIDC token response omitted access_token".to_owned())?;
    let id_claims = if config.validate_id_token {
        let id_token = token
            .get("id_token")
            .and_then(Value::as_str)
            .ok_or_else(|| "OIDC token response omitted id_token".to_owned())?;
        Some(validate_oidc_id_token(&client, config, id_token, nonce).await?)
    } else {
        None
    };
    let user_response = client
        .get(&config.userinfo_url)
        .bearer_auth(access_token)
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !user_response.status().is_success() {
        return Err(format!(
            "OIDC userinfo endpoint returned {}",
            user_response.status()
        ));
    }
    let userinfo: Value = user_response
        .json()
        .await
        .map_err(|error| error.to_string())?;
    let subject = id_claims
        .as_ref()
        .map(|claims| json_string(claims, "sub"))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| json_string(&userinfo, "sub"));
    if subject.is_empty() {
        return Err("OIDC identity omitted subject".to_owned());
    }
    let userinfo_subject = json_string(&userinfo, "sub");
    if !userinfo_subject.is_empty() && userinfo_subject != subject {
        return Err("OIDC userinfo subject does not match id_token".to_owned());
    }
    let email = first_nonempty([
        json_string(&userinfo, "email"),
        id_claims
            .as_ref()
            .map(|claims| json_string(claims, "email"))
            .unwrap_or_default(),
    ]);
    let email_verified = userinfo
        .get("email_verified")
        .and_then(Value::as_bool)
        .or_else(|| {
            id_claims
                .as_ref()
                .and_then(|claims| claims.get("email_verified"))
                .and_then(Value::as_bool)
        });
    if config.require_email_verified && email_verified != Some(true) {
        return Err("OIDC provider did not verify the email".to_owned());
    }
    let identity_key = format!("{}\u{1f}{subject}", config.issuer.to_ascii_lowercase());
    let email_hash = Sha256::digest(identity_key.as_bytes());
    let synthetic_email = format!(
        "oidc-{}@oidc-connect.invalid",
        hex::encode(&email_hash[..16])
    );
    let username = first_nonempty([
        json_string(&userinfo, "preferred_username"),
        json_string(&userinfo, "name"),
        id_claims
            .as_ref()
            .map(|claims| json_string(claims, "preferred_username"))
            .unwrap_or_default(),
    ]);
    let username = if username.is_empty() {
        format!(
            "oidc_{}",
            &hex::encode(Sha256::digest(subject.as_bytes()))[..12]
        )
    } else {
        username
    };
    Ok(OAuthIdentityProfile {
        provider: "oidc".to_owned(),
        provider_key: config.issuer.clone(),
        subject,
        issuer: Some(config.issuer.clone()),
        email: synthetic_email,
        username: username.clone(),
        display_name: first_nonempty([
            json_string(&userinfo, "name"),
            id_claims
                .as_ref()
                .map(|claims| json_string(claims, "name"))
                .unwrap_or_default(),
            username,
        ]),
        avatar_url: json_string(&userinfo, "picture"),
        metadata: json!({
            "compat_email": email,
            "email_verified": email_verified.unwrap_or(false),
            "issuer": config.issuer
        }),
    })
}

async fn validate_oidc_id_token(
    client: &reqwest::Client,
    config: &OidcConfig,
    token: &str,
    expected_nonce: &str,
) -> Result<Value, String> {
    let mut segments = token.split('.');
    let header_segment = segments
        .next()
        .ok_or_else(|| "invalid id_token".to_owned())?;
    let claims_segment = segments
        .next()
        .ok_or_else(|| "invalid id_token".to_owned())?;
    let signature_segment = segments
        .next()
        .ok_or_else(|| "invalid id_token".to_owned())?;
    if segments.next().is_some() {
        return Err("invalid id_token".to_owned());
    }
    let header: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(header_segment)
            .map_err(|_| "invalid id_token header".to_owned())?,
    )
    .map_err(|_| "invalid id_token header".to_owned())?;
    let claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(claims_segment)
            .map_err(|_| "invalid id_token claims".to_owned())?,
    )
    .map_err(|_| "invalid id_token claims".to_owned())?;
    let algorithm = json_string(&header, "alg");
    if !config
        .allowed_signing_algs
        .iter()
        .any(|allowed| allowed == &algorithm)
    {
        return Err("id_token signing algorithm is not allowed".to_owned());
    }
    let key_id = json_string(&header, "kid");
    let jwks: Value = client
        .get(&config.jwks_url)
        .send()
        .await
        .map_err(|error| error.to_string())?
        .error_for_status()
        .map_err(|error| error.to_string())?
        .json()
        .await
        .map_err(|error| error.to_string())?;
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| "OIDC JWKS omitted keys".to_owned())?;
    let jwk = select_oidc_signing_key(keys, &key_id, &algorithm)?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature_segment)
        .map_err(|_| "invalid id_token signature".to_owned())?;
    let signed = format!("{header_segment}.{claims_segment}");
    match algorithm.as_str() {
        "ES256" => verify_es256_signature(jwk, signed.as_bytes(), &signature)?,
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" => {
            let public_key = rsa_public_key_from_jwk(jwk)?;
            verify_rsa_signature(&algorithm, &public_key, signed.as_bytes(), &signature)?;
        }
        _ => return Err("unsupported OIDC signing algorithm".to_owned()),
    }
    validate_oidc_claims(&claims, config, expected_nonce)?;
    Ok(claims)
}

fn select_oidc_signing_key<'a>(
    keys: &'a [Value],
    key_id: &str,
    algorithm: &str,
) -> Result<&'a Value, String> {
    let mut matches = keys.iter().filter(|key| {
        (key_id.is_empty() || json_string(key, "kid") == key_id)
            && oidc_jwk_matches_algorithm(key, algorithm)
            && matches!(json_string(key, "use").as_str(), "" | "sig")
            && {
                let declared = json_string(key, "alg");
                declared.is_empty() || declared == algorithm
            }
    });
    let key = matches
        .next()
        .ok_or_else(|| "OIDC signing key was not found".to_owned())?;
    if matches.next().is_some() {
        return Err("OIDC signing key is ambiguous".to_owned());
    }
    Ok(key)
}

fn oidc_jwk_matches_algorithm(key: &Value, algorithm: &str) -> bool {
    match algorithm {
        "ES256" => json_string(key, "kty") == "EC" && json_string(key, "crv") == "P-256",
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" => {
            json_string(key, "kty") == "RSA"
        }
        _ => false,
    }
}

fn rsa_public_key_from_jwk(jwk: &Value) -> Result<RsaPublicKey, String> {
    let modulus = URL_SAFE_NO_PAD
        .decode(json_string(jwk, "n"))
        .map_err(|_| "invalid OIDC RSA modulus".to_owned())?;
    let exponent = URL_SAFE_NO_PAD
        .decode(json_string(jwk, "e"))
        .map_err(|_| "invalid OIDC RSA exponent".to_owned())?;
    if modulus.is_empty() || exponent.is_empty() {
        return Err("invalid OIDC RSA signing key".to_owned());
    }
    RsaPublicKey::from_components(modulus, exponent)
        .map_err(|_| "invalid OIDC RSA signing key".to_owned())
}

fn verify_es256_signature(jwk: &Value, signed: &[u8], signature: &[u8]) -> Result<(), String> {
    let x = URL_SAFE_NO_PAD
        .decode(json_string(jwk, "x"))
        .map_err(|_| "invalid OIDC P-256 x coordinate".to_owned())?;
    let y = URL_SAFE_NO_PAD
        .decode(json_string(jwk, "y"))
        .map_err(|_| "invalid OIDC P-256 y coordinate".to_owned())?;
    let x: [u8; 32] = x
        .try_into()
        .map_err(|_| "invalid OIDC P-256 x coordinate".to_owned())?;
    let y: [u8; 32] = y
        .try_into()
        .map_err(|_| "invalid OIDC P-256 y coordinate".to_owned())?;
    if signature.len() != 64 {
        return Err("invalid OIDC ES256 signature".to_owned());
    }
    let mut public_key = [0_u8; 65];
    public_key[0] = 0x04;
    public_key[1..33].copy_from_slice(&x);
    public_key[33..].copy_from_slice(&y);
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_key)
        .verify(signed, signature)
        .map_err(|_| "id_token signature verification failed".to_owned())
}

fn verify_rsa_signature(
    algorithm: &str,
    public_key: &RsaPublicKey,
    signed: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    public_key
        .verify(algorithm, signed, signature)
        .map_err(|error| match error {
            RsaCryptoError::InvalidKey => "invalid OIDC RSA signing key".to_owned(),
            RsaCryptoError::UnsupportedAlgorithm => "unsupported OIDC signing algorithm".to_owned(),
            RsaCryptoError::InvalidSignature | RsaCryptoError::SigningFailed => {
                "id_token signature verification failed".to_owned()
            }
        })
}

fn validate_oidc_claims(
    claims: &Value,
    config: &OidcConfig,
    expected_nonce: &str,
) -> Result<(), String> {
    if json_string(claims, "iss").trim_end_matches('/') != config.issuer.trim_end_matches('/') {
        return Err("id_token issuer mismatch".to_owned());
    }
    let audience = claims
        .get("aud")
        .ok_or_else(|| "id_token omitted audience".to_owned())?;
    let audience_matches = match audience {
        Value::String(value) => value == &config.client_id,
        Value::Array(values) => values
            .iter()
            .any(|value| value.as_str() == Some(&config.client_id)),
        _ => false,
    };
    if !audience_matches {
        return Err("id_token audience mismatch".to_owned());
    }
    let authorized_party = claims.get("azp").and_then(Value::as_str);
    if audience.as_array().is_some_and(|values| values.len() > 1) && authorized_party.is_none() {
        return Err("id_token omitted authorized party".to_owned());
    }
    if authorized_party.is_some_and(|value| value != config.client_id) {
        return Err("id_token authorized party mismatch".to_owned());
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system time is before unix epoch".to_owned())?
        .as_secs();
    let now = i64::try_from(now).map_err(|_| "system time exceeds i64".to_owned())?;
    let expires_at = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or_else(|| "id_token omitted expiration".to_owned())?;
    if expires_at.saturating_add(config.clock_skew_seconds) < now {
        return Err("id_token has expired".to_owned());
    }
    if claims
        .get("nbf")
        .and_then(Value::as_i64)
        .is_some_and(|not_before| not_before.saturating_sub(config.clock_skew_seconds) > now)
    {
        return Err("id_token is not active yet".to_owned());
    }
    let issued_at = claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or_else(|| "id_token omitted issued-at time".to_owned())?;
    if issued_at.saturating_sub(config.clock_skew_seconds) > now {
        return Err("id_token was issued in the future".to_owned());
    }
    if !constant_time_equal(&json_string(claims, "nonce"), expected_nonce) {
        return Err("id_token nonce mismatch".to_owned());
    }
    if json_string(claims, "sub").is_empty() {
        return Err("id_token omitted subject".to_owned());
    }
    Ok(())
}

fn optional_bearer_hash_matches(expected: Option<&[u8]>, raw: &str) -> bool {
    match expected {
        None => raw.is_empty(),
        Some(expected) if !raw.is_empty() => {
            let actual = Sha256::digest(raw.as_bytes());
            expected.len() == actual.len() && bool::from(expected.ct_eq(actual.as_slice()))
        }
        Some(_) => false,
    }
}

fn fill_if_empty(target: &mut String, value: String) {
    if target.is_empty() {
        *target = value;
    }
}

fn parse_bool_default(raw: &str, default: bool) -> bool {
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => true,
        "false" | "0" | "no" | "off" => false,
        _ => default,
    }
}

fn first_nonempty<const N: usize>(values: [String; N]) -> String {
    values
        .into_iter()
        .find(|value| !value.trim().is_empty())
        .unwrap_or_default()
}

async fn load_provider_config(
    state: &ControlApiState,
    provider: &'static str,
) -> Result<ProviderConfig, ApiError> {
    let setting_prefix = match provider {
        "linuxdo" => "linuxdo_connect_",
        _ => return load_email_provider_config(state, provider).await,
    };
    let rows = sqlx::query("SELECT key, value FROM settings WHERE key LIKE $1")
        .bind(format!("{setting_prefix}%"))
        .fetch_all(state.pool())
        .await?;
    let settings = rows
        .into_iter()
        .map(|row| {
            Ok((
                row.try_get::<String, _>("key")?,
                row.try_get::<String, _>("value")?,
            ))
        })
        .collect::<Result<HashMap<_, _>, sqlx::Error>>()?;
    let get = |suffix: &str| {
        settings
            .get(&format!("{setting_prefix}{suffix}"))
            .map(String::as_str)
            .unwrap_or_default()
            .trim()
    };
    if !get("enabled").eq_ignore_ascii_case("true") {
        return Err(ApiError::not_found("OAuth login is disabled"));
    }
    let client_id = get("client_id").to_owned();
    let client_secret = get("client_secret").to_owned();
    let redirect_url = get("redirect_url").to_owned();
    if client_id.is_empty() || client_secret.is_empty() || redirect_url.is_empty() {
        return Err(ApiError::internal(
            "load OAuth provider configuration",
            "client ID, client secret, and redirect URL are required",
        ));
    }
    validate_absolute_http_url(&redirect_url)?;
    let frontend_callback = match get("frontend_redirect_url") {
        "" => DEFAULT_FRONTEND_CALLBACK.to_owned(),
        value => validate_frontend_callback(value)?,
    };
    Ok(ProviderConfig {
        provider: "linuxdo",
        client_id,
        client_secret,
        authorize_url: "https://connect.linux.do/oauth2/authorize",
        token_url: "https://connect.linux.do/oauth2/token",
        userinfo_url: "https://connect.linux.do/api/user",
        emails_url: None,
        scopes: "user",
        redirect_url,
        frontend_callback: if frontend_callback == DEFAULT_FRONTEND_CALLBACK {
            "/auth/linuxdo/callback".to_owned()
        } else {
            frontend_callback
        },
    })
}

async fn load_email_provider_config(
    state: &ControlApiState,
    provider: &'static str,
) -> Result<ProviderConfig, ApiError> {
    let rows = sqlx::query("SELECT key, value FROM settings WHERE key LIKE $1")
        .bind(format!("{provider}_oauth_%"))
        .fetch_all(state.pool())
        .await?;
    let settings = rows
        .into_iter()
        .map(|row| {
            Ok((
                row.try_get::<String, _>("key")?,
                row.try_get::<String, _>("value")?,
            ))
        })
        .collect::<Result<HashMap<_, _>, sqlx::Error>>()?;
    let get = |suffix: &str| {
        settings
            .get(&format!("{provider}_oauth_{suffix}"))
            .map(String::as_str)
            .unwrap_or_default()
            .trim()
    };
    if !get("enabled").eq_ignore_ascii_case("true") {
        return Err(ApiError::not_found("OAuth login is disabled"));
    }
    let client_id = get("client_id").to_owned();
    let client_secret = get("client_secret").to_owned();
    let redirect_url = get("redirect_url").to_owned();
    if client_id.is_empty() || client_secret.is_empty() || redirect_url.is_empty() {
        return Err(ApiError::internal(
            "load OAuth provider configuration",
            "client ID, client secret, and redirect URL are required",
        ));
    }
    validate_absolute_http_url(&redirect_url)?;
    let frontend_callback = match get("frontend_redirect_url") {
        "" => DEFAULT_FRONTEND_CALLBACK.to_owned(),
        value => validate_frontend_callback(value)?,
    };
    Ok(match provider {
        "github" => ProviderConfig {
            provider,
            client_id,
            client_secret,
            authorize_url: "https://github.com/login/oauth/authorize",
            token_url: "https://github.com/login/oauth/access_token",
            userinfo_url: "https://api.github.com/user",
            emails_url: Some("https://api.github.com/user/emails"),
            scopes: "read:user user:email",
            redirect_url,
            frontend_callback,
        },
        "google" => ProviderConfig {
            provider,
            client_id,
            client_secret,
            authorize_url: "https://accounts.google.com/o/oauth2/v2/auth",
            token_url: "https://oauth2.googleapis.com/token",
            userinfo_url: "https://openidconnect.googleapis.com/v1/userinfo",
            emails_url: None,
            scopes: "openid email profile",
            redirect_url,
            frontend_callback,
        },
        _ => return Err(ApiError::bad_request("OAuth provider is not supported")),
    })
}

async fn exchange_profile(
    config: &ProviderConfig,
    code: &str,
) -> Result<OAuthIdentityProfile, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent(concat!("sub2api-rust/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| error.to_string())?;
    let token_body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("grant_type", "authorization_code"),
            ("client_id", config.client_id.as_str()),
            ("client_secret", config.client_secret.as_str()),
            ("code", code),
            ("redirect_uri", config.redirect_url.as_str()),
        ])
        .finish();
    let token_response = client
        .post(config.token_url)
        .header("accept", "application/json")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(token_body)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !token_response.status().is_success() {
        return Err(format!(
            "token endpoint returned {}",
            token_response.status()
        ));
    }
    let token: Value = token_response
        .json()
        .await
        .map_err(|error| error.to_string())?;
    let access_token = token
        .get("access_token")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "token endpoint omitted access_token".to_owned())?;
    let user_response = client
        .get(config.userinfo_url)
        .bearer_auth(access_token)
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !user_response.status().is_success() {
        return Err(format!(
            "userinfo endpoint returned {}",
            user_response.status()
        ));
    }
    let user: Value = user_response
        .json()
        .await
        .map_err(|error| error.to_string())?;
    match config.provider {
        "github" => github_profile(config, &client, access_token, user).await,
        "google" => google_profile(&user),
        "linuxdo" => linuxdo_profile(&user),
        _ => Err("unsupported OAuth provider".to_owned()),
    }
}

async fn github_profile(
    config: &ProviderConfig,
    client: &reqwest::Client,
    access_token: &str,
    user: Value,
) -> Result<OAuthIdentityProfile, String> {
    let subject = json_scalar_string(user.get("id"))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "GitHub profile omitted id".to_owned())?;
    let emails_url = config
        .emails_url
        .ok_or_else(|| "GitHub email endpoint is not configured".to_owned())?;
    let response = client
        .get(emails_url)
        .bearer_auth(access_token)
        .header("accept", "application/json")
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err(format!(
            "GitHub email endpoint returned {}",
            response.status()
        ));
    }
    let emails: Vec<Value> = response.json().await.map_err(|error| error.to_string())?;
    let email = emails
        .iter()
        .find(|entry| {
            entry.get("primary").and_then(Value::as_bool) == Some(true)
                && entry.get("verified").and_then(Value::as_bool) == Some(true)
        })
        .or_else(|| {
            emails
                .iter()
                .find(|entry| entry.get("verified").and_then(Value::as_bool) == Some(true))
        })
        .and_then(|entry| entry.get("email"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "GitHub account has no verified email".to_owned())?
        .to_owned();
    let login = json_string(&user, "login");
    let display_name = json_string(&user, "name");
    Ok(OAuthIdentityProfile {
        provider: "github".to_owned(),
        provider_key: "github".to_owned(),
        subject,
        issuer: Some("https://github.com".to_owned()),
        email,
        username: if login.is_empty() {
            format!(
                "github_{}",
                json_scalar_string(user.get("id")).unwrap_or_default()
            )
        } else {
            login.clone()
        },
        display_name,
        avatar_url: json_string(&user, "avatar_url"),
        metadata: json!({ "login": login }),
    })
}

fn google_profile(user: &Value) -> Result<OAuthIdentityProfile, String> {
    let subject = json_string(user, "sub");
    let email = json_string(user, "email");
    if subject.is_empty() || email.is_empty() {
        return Err("Google profile omitted subject or email".to_owned());
    }
    if user.get("email_verified").and_then(Value::as_bool) != Some(true) {
        return Err("Google email is not verified".to_owned());
    }
    let display_name = json_string(user, "name");
    let username = email
        .split('@')
        .next()
        .filter(|value| !value.is_empty())
        .unwrap_or("google_user")
        .to_owned();
    Ok(OAuthIdentityProfile {
        provider: "google".to_owned(),
        provider_key: "google".to_owned(),
        subject,
        issuer: Some("https://accounts.google.com".to_owned()),
        email,
        username,
        display_name,
        avatar_url: json_string(user, "picture"),
        metadata: json!({ "email_verified": true }),
    })
}

fn linuxdo_profile(user: &Value) -> Result<OAuthIdentityProfile, String> {
    let subject = first_json_path(user, &["sub", "id", "user_id", "uid", "user.id", "data.id"]);
    if subject.is_empty()
        || subject.len() > 56
        || !subject
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err("LinuxDo profile returned an invalid subject".to_owned());
    }
    let username = first_json_path(
        user,
        &[
            "username",
            "preferred_username",
            "name",
            "user.username",
            "user.name",
        ],
    );
    let username = if username.is_empty() {
        format!("linuxdo_{subject}")
    } else {
        username
    };
    let display_name = first_json_path(user, &["name", "nickname", "display_name", "user.name"]);
    let avatar_url = first_json_path(
        user,
        &[
            "avatar_url",
            "avatar",
            "picture",
            "profile_image_url",
            "user.avatar_url",
        ],
    );
    Ok(OAuthIdentityProfile {
        provider: "linuxdo".to_owned(),
        provider_key: "linuxdo".to_owned(),
        subject: subject.clone(),
        issuer: Some("https://connect.linux.do".to_owned()),
        email: format!("linuxdo-{subject}@linuxdo-connect.invalid"),
        username: username.clone(),
        display_name: if display_name.is_empty() {
            username
        } else {
            display_name
        },
        avatar_url,
        metadata: json!({
            "compat_email": first_json_path(user, &["email", "user.email", "data.email"])
        }),
    })
}

fn query_payload<T>(query: Result<Query<T>, QueryRejection>) -> Result<T, ApiError> {
    query
        .map(|Query(value)| value)
        .map_err(|_| ApiError::bad_request("Invalid query parameters"))
}

fn random_bearer() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn constant_time_equal(left: &str, right: &str) -> bool {
    left.len() == right.len() && bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get_all(COOKIE).iter().find_map(|header| {
        header.to_str().ok()?.split(';').find_map(|pair| {
            let (key, value) = pair.trim().split_once('=')?;
            (key == name).then_some(value)
        })
    })
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get("authorization")?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer")
        && !token.is_empty()
        && !token.chars().any(char::is_whitespace))
    .then_some(token)
}

async fn authenticate_bind_user(
    state: &ControlApiState,
    headers: &HeaderMap,
) -> Result<i64, ApiError> {
    let mut auth_headers = headers.clone();
    if bearer_token(&auth_headers).is_none() {
        let token = cookie_value(headers, OAUTH_BIND_TOKEN_COOKIE)
            .filter(|token| !token.is_empty() && !token.chars().any(char::is_whitespace))
            .ok_or_else(|| ApiError::unauthorized("Authentication is required"))?;
        let value = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|error| ApiError::internal("read OAuth bind token", error))?;
        auth_headers.insert("authorization", value);
    }
    Ok(state.authenticate(&auth_headers).await?.view.id)
}

fn sanitize_redirect(raw: Option<&str>) -> Option<&str> {
    let value = raw?.trim();
    (!value.is_empty()
        && value.len() <= 2_048
        && value.starts_with('/')
        && !value.starts_with("//")
        && !value.contains("://")
        && !value.contains(['\r', '\n']))
    .then_some(value)
}

fn validate_absolute_http_url(raw: &str) -> Result<(), ApiError> {
    let url = Url::parse(raw)
        .map_err(|error| ApiError::internal("validate OAuth redirect URL", error))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(ApiError::internal(
            "validate OAuth redirect URL",
            "URL must be absolute HTTP(S)",
        ));
    }
    Ok(())
}

fn validate_frontend_callback(raw: &str) -> Result<String, ApiError> {
    if raw.starts_with('/') && !raw.starts_with("//") && !raw.contains(['\r', '\n']) {
        return Ok(raw.to_owned());
    }
    validate_absolute_http_url(raw)?;
    Ok(raw.to_owned())
}

fn request_is_https(headers: &HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("https"))
}

fn state_cookie(value: &str, secure: bool) -> String {
    cookie(
        STATE_COOKIE,
        value,
        OAUTH_COOKIE_PATH,
        OAUTH_TTL_SECONDS,
        secure,
    )
}

fn pending_cookie(name: &str, value: &str, secure: bool) -> String {
    cookie(name, value, OAUTH_COOKIE_PATH, OAUTH_TTL_SECONDS, secure)
}

fn clear_cookie(name: &str, secure: bool) -> String {
    cookie(name, "", OAUTH_COOKIE_PATH, 0, secure)
}

fn cookie(name: &str, value: &str, path: &str, max_age: i64, secure: bool) -> String {
    format!(
        "{name}={value}; Path={path}; Max-Age={max_age}; HttpOnly; SameSite=Lax{}",
        if secure { "; Secure" } else { "" }
    )
}

fn redirect_response(location: &str, cookies: &[String]) -> Response {
    let mut response = StatusCode::FOUND.into_response();
    let location = HeaderValue::from_str(location)
        .unwrap_or_else(|_| HeaderValue::from_static(DEFAULT_REDIRECT));
    response.headers_mut().insert(LOCATION, location);
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(PRAGMA, HeaderValue::from_static("no-cache"));
    for cookie in cookies {
        append_cookie(response.headers_mut(), cookie);
    }
    response
}

fn append_cookie(headers: &mut HeaderMap, cookie: &str) {
    if let Ok(value) = HeaderValue::from_str(cookie) {
        headers.append(SET_COOKIE, value);
    }
}

fn fragment_redirect(
    frontend_callback: &str,
    values: &[(&str, &str)],
    cookies: &[String],
) -> Response {
    let fragment = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(values.iter().copied())
        .finish();
    let location = format!(
        "{}#{fragment}",
        frontend_callback.split('#').next().unwrap_or_default()
    );
    redirect_response(&location, cookies)
}

fn oauth_error_redirect(
    frontend_callback: &str,
    code: &str,
    message: &str,
    description: &str,
    cookies: &[String],
) -> Response {
    let mut values = vec![("error", code), ("error_message", message)];
    if !description.trim().is_empty() {
        values.push(("error_description", description));
    }
    fragment_redirect(frontend_callback, &values, cookies)
}

fn json_string(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default()
        .to_owned()
}

fn json_scalar_string(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(value) => Some(value.trim().to_owned()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn first_json_path(value: &Value, paths: &[&str]) -> String {
    paths
        .iter()
        .find_map(|path| {
            let mut current = value;
            for segment in path.split('.') {
                current = current.get(segment)?;
            }
            json_scalar_string(Some(current)).filter(|value| !value.is_empty())
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use ring::{
        rand::SystemRandom,
        signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
    };

    use super::*;

    #[test]
    fn redirect_sanitizer_rejects_external_and_header_injection_values() {
        assert_eq!(sanitize_redirect(Some("/dashboard")), Some("/dashboard"));
        assert_eq!(sanitize_redirect(Some("//example.com")), None);
        assert_eq!(sanitize_redirect(Some("https://example.com")), None);
        assert_eq!(sanitize_redirect(Some("/ok\r\nlocation: bad")), None);
    }

    #[test]
    fn oauth_state_comparison_is_exact() {
        assert!(constant_time_equal("abc", "abc"));
        assert!(!constant_time_equal("abc", "abcd"));
        assert!(!constant_time_equal("abc", "abd"));
    }

    #[test]
    fn cookie_parser_handles_multiple_cookie_headers_and_pairs() {
        let mut headers = HeaderMap::new();
        headers.append(COOKIE, HeaderValue::from_static("one=1; two=2"));
        headers.append(COOKIE, HeaderValue::from_static("target=value"));
        assert_eq!(cookie_value(&headers, "target"), Some("value"));
    }

    #[test]
    fn es256_jwk_verifies_fixed_width_jws_signatures() {
        let random = SystemRandom::new();
        let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &random)
            .expect("P-256 key generation should succeed");
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, document.as_ref(), &random)
                .expect("generated P-256 key should parse");
        let public_key = key.public_key().as_ref();
        assert_eq!(public_key.len(), 65);
        assert_eq!(public_key[0], 0x04);
        let jwk = json!({
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "use": "sig",
            "kid": "p256-key",
            "x": URL_SAFE_NO_PAD.encode(&public_key[1..33]),
            "y": URL_SAFE_NO_PAD.encode(&public_key[33..65])
        });
        let signed = b"header.claims";
        let signature = key
            .sign(&random, signed)
            .expect("P-256 signing should succeed");
        verify_es256_signature(&jwk, signed, signature.as_ref())
            .expect("valid ES256 signature should verify");

        let mut tampered = signature.as_ref().to_vec();
        tampered[0] ^= 1;
        assert!(verify_es256_signature(&jwk, signed, &tampered).is_err());
        assert!(verify_es256_signature(&jwk, signed, &tampered[..63]).is_err());
    }

    #[test]
    fn oidc_jwk_selection_enforces_key_type_curve_and_unambiguous_kid() {
        let keys = vec![
            json!({"kid":"ec-1","kty":"EC","crv":"P-256","alg":"ES256","use":"sig"}),
            json!({"kid":"ec-2","kty":"EC","crv":"P-256","alg":"ES256","use":"sig"}),
            json!({"kid":"rsa-1","kty":"RSA","alg":"RS256","use":"sig"}),
            json!({"kid":"wrong-curve","kty":"EC","crv":"P-384","alg":"ES256","use":"sig"}),
        ];
        let selected = select_oidc_signing_key(&keys, "ec-2", "ES256")
            .expect("matching ES256 key should be selected");
        assert_eq!(json_string(selected, "kid"), "ec-2");
        assert!(select_oidc_signing_key(&keys, "rsa-1", "ES256").is_err());
        assert!(select_oidc_signing_key(&keys, "wrong-curve", "ES256").is_err());
        assert!(select_oidc_signing_key(&keys, "", "ES256").is_err());
    }
}
