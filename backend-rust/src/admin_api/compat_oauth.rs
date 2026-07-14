//! Durable administrator OAuth flows for upstream model providers.

use std::{collections::BTreeMap, env, time::Duration};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use reqwest::{Client, Proxy, redirect::Policy};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use url::Url;
use uuid::Uuid;

use super::{AdminError, compat::redacted_json};
use crate::security::secrets;

const SESSION_TTL_MINUTES: i64 = 30;
const OPENAI_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const OPENAI_AUTHORIZE_URL: &str = "https://auth.openai.com/oauth/authorize";
const OPENAI_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
const OPENAI_REDIRECT_URI: &str = "http://localhost:1455/auth/callback";
const OPENAI_SCOPE: &str = "openid profile email offline_access";
const OPENAI_REFRESH_SCOPE: &str = "openid profile email";

const CLAUDE_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const CLAUDE_AUTHORIZE_URL: &str = "https://claude.ai/oauth/authorize";
const CLAUDE_TOKEN_URL: &str = "https://platform.claude.com/v1/oauth/token";
const CLAUDE_REDIRECT_URI: &str = "https://platform.claude.com/oauth/code/callback";
const CLAUDE_SCOPE_FULL: &str = "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload";
const CLAUDE_SCOPE_API: &str =
    "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload";
const CLAUDE_SCOPE_INFERENCE: &str = "user:inference";

const GOOGLE_AUTHORIZE_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const GEMINI_CLIENT_ID: &str =
    "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com";
const GEMINI_CLIENT_SECRET: &str = "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";
const GEMINI_CODE_ASSIST_REDIRECT_URI: &str = "https://codeassist.google.com/authcode";
const GEMINI_AI_STUDIO_REDIRECT_URI: &str = "http://localhost:1455/auth/callback";
const GEMINI_CODE_ASSIST_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile";
const GEMINI_AI_STUDIO_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/generative-language.retriever";

const ANTIGRAVITY_CLIENT_ID: &str =
    "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com";
const ANTIGRAVITY_CLIENT_SECRET: &str = "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";
const ANTIGRAVITY_REDIRECT_URI: &str = "http://localhost:8085/callback";
const ANTIGRAVITY_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/cclog https://www.googleapis.com/auth/experimentsandconfigs";

const GROK_CLIENT_ID: &str = "b1a00492-073a-47ea-816f-4c329264a828";
const GROK_AUTHORIZE_URL: &str = "https://auth.x.ai/oauth2/authorize";
const GROK_TOKEN_URL: &str = "https://auth.x.ai/oauth2/token";
const GROK_REDIRECT_URI: &str = "http://127.0.0.1:56121/callback";
const GROK_SCOPE: &str = "openid profile email offline_access grok-cli:access api:access";

#[derive(Debug, Deserialize, Serialize)]
struct SessionSecrets {
    state: String,
    verifier: String,
}

#[derive(Debug)]
struct OAuthSession {
    secrets: SessionSecrets,
    context: Value,
}

#[derive(Clone, Debug)]
struct TokenEndpoint {
    url: String,
    client_id: String,
    client_secret: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
    json_body: bool,
    user_agent: &'static str,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn dispatch(
    pool: &PgPool,
    handler: &str,
    _category: &str,
    _method: &axum::http::Method,
    path: &str,
    _query: &BTreeMap<String, String>,
    payload: Value,
) -> Option<Result<Value, AdminError>> {
    if !handles(handler) {
        return None;
    }
    let result = match handler {
        "h.Admin.OAuth.GenerateAuthURL" => {
            generate_claude_auth_url(pool, payload, CLAUDE_SCOPE_FULL).await
        }
        "h.Admin.OAuth.GenerateSetupTokenURL" => {
            generate_claude_auth_url(pool, payload, CLAUDE_SCOPE_INFERENCE).await
        }
        "h.Admin.OAuth.ExchangeCode" | "h.Admin.OAuth.ExchangeSetupTokenCode" => {
            exchange_code(pool, "anthropic", payload).await
        }
        "h.Admin.OAuth.CookieAuth" => claude_cookie_auth(pool, payload, false).await,
        "h.Admin.OAuth.SetupTokenCookieAuth" => claude_cookie_auth(pool, payload, true).await,
        "h.Admin.Account.ApplyOAuthCredentials" => {
            apply_oauth_credentials(pool, account_id(path)?, payload).await
        }
        "h.Admin.OpenAIOAuth.GenerateAuthURL" => generate_openai_auth_url(pool, payload).await,
        "h.Admin.OpenAIOAuth.ExchangeCode" => exchange_code(pool, "openai", payload).await,
        "h.Admin.OpenAIOAuth.RefreshToken" => refresh_token(pool, "openai", payload).await,
        "h.Admin.OpenAIOAuth.RefreshAccountToken" => {
            refresh_account(pool, account_id(path)?, "openai").await
        }
        "h.Admin.OpenAIOAuth.CreateAccountFromOAuth" => {
            create_account_from_oauth(pool, "openai", payload).await
        }
        "h.Admin.OpenAIOAuth.CreateAccountFromCodexPAT" => {
            create_openai_pat_account(pool, payload).await
        }
        "h.Admin.OpenAIOAuth.QueryQuota" => account_quota(pool, account_id(path)?, "openai").await,
        "h.Admin.OpenAIOAuth.ResetQuota" => {
            reset_account_quota(pool, account_id(path)?, "openai").await
        }
        "h.Admin.OpenAIOAuth.CreateShadow" => {
            create_openai_shadow(pool, account_id(path)?, payload).await
        }
        "h.Admin.GeminiOAuth.GetCapabilities" => Ok(gemini_capabilities()),
        "h.Admin.GeminiOAuth.GenerateAuthURL" => generate_gemini_auth_url(pool, payload).await,
        "h.Admin.GeminiOAuth.ExchangeCode" => exchange_code(pool, "gemini", payload).await,
        "h.Admin.AntigravityOAuth.GenerateAuthURL" => {
            generate_antigravity_auth_url(pool, payload).await
        }
        "h.Admin.AntigravityOAuth.ExchangeCode" => {
            exchange_code(pool, "antigravity", payload).await
        }
        "h.Admin.AntigravityOAuth.RefreshToken" => {
            refresh_token(pool, "antigravity", payload).await
        }
        "h.Admin.GrokOAuth.GenerateAuthURL" => generate_grok_auth_url(pool, payload).await,
        "h.Admin.GrokOAuth.ExchangeCode" => exchange_code(pool, "grok", payload).await,
        "h.Admin.GrokOAuth.RefreshToken" => refresh_token(pool, "grok", payload).await,
        "h.Admin.GrokOAuth.CreateAccountFromOAuth" => {
            create_account_from_oauth(pool, "grok", payload).await
        }
        "h.Admin.GrokOAuth.RefreshAccountToken" => {
            refresh_account(pool, account_id(path)?, "grok").await
        }
        "h.Admin.GrokOAuth.QueryQuota" => account_quota(pool, account_id(path)?, "grok").await,
        "h.Admin.GrokOAuth.ResetQuota" => {
            reset_account_quota(pool, account_id(path)?, "grok").await
        }
        "h.Admin.GrokOAuth.RuntimeSanity" => Ok(grok_runtime_sanity()),
        _ => unreachable!("handles() and OAuth dispatch must stay exhaustive"),
    };
    Some(result)
}

fn handles(handler: &str) -> bool {
    matches!(
        handler,
        "h.Admin.OAuth.GenerateAuthURL"
            | "h.Admin.OAuth.GenerateSetupTokenURL"
            | "h.Admin.OAuth.ExchangeCode"
            | "h.Admin.OAuth.ExchangeSetupTokenCode"
            | "h.Admin.OAuth.CookieAuth"
            | "h.Admin.OAuth.SetupTokenCookieAuth"
            | "h.Admin.Account.ApplyOAuthCredentials"
            | "h.Admin.OpenAIOAuth.GenerateAuthURL"
            | "h.Admin.OpenAIOAuth.ExchangeCode"
            | "h.Admin.OpenAIOAuth.RefreshToken"
            | "h.Admin.OpenAIOAuth.RefreshAccountToken"
            | "h.Admin.OpenAIOAuth.CreateAccountFromOAuth"
            | "h.Admin.OpenAIOAuth.CreateAccountFromCodexPAT"
            | "h.Admin.OpenAIOAuth.QueryQuota"
            | "h.Admin.OpenAIOAuth.ResetQuota"
            | "h.Admin.OpenAIOAuth.CreateShadow"
            | "h.Admin.GeminiOAuth.GetCapabilities"
            | "h.Admin.GeminiOAuth.GenerateAuthURL"
            | "h.Admin.GeminiOAuth.ExchangeCode"
            | "h.Admin.AntigravityOAuth.GenerateAuthURL"
            | "h.Admin.AntigravityOAuth.ExchangeCode"
            | "h.Admin.AntigravityOAuth.RefreshToken"
            | "h.Admin.GrokOAuth.GenerateAuthURL"
            | "h.Admin.GrokOAuth.ExchangeCode"
            | "h.Admin.GrokOAuth.RefreshToken"
            | "h.Admin.GrokOAuth.CreateAccountFromOAuth"
            | "h.Admin.GrokOAuth.RefreshAccountToken"
            | "h.Admin.GrokOAuth.QueryQuota"
            | "h.Admin.GrokOAuth.ResetQuota"
            | "h.Admin.GrokOAuth.RuntimeSanity"
    )
}

async fn generate_claude_auth_url(
    pool: &PgPool,
    payload: Value,
    scope: &str,
) -> Result<Value, AdminError> {
    let (session_id, state, challenge) = new_session(
        pool,
        "anthropic",
        json!({ "scope": scope, "proxy_id": optional_i64(&payload, "proxy_id")? }),
    )
    .await?;
    let auth_url = authorization_url(
        CLAUDE_AUTHORIZE_URL,
        &[
            ("code", "true"),
            ("client_id", CLAUDE_CLIENT_ID),
            ("response_type", "code"),
            ("redirect_uri", CLAUDE_REDIRECT_URI),
            ("scope", scope),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("state", &state),
        ],
    )?;
    Ok(json!({ "auth_url": auth_url, "session_id": session_id }))
}

async fn generate_openai_auth_url(pool: &PgPool, payload: Value) -> Result<Value, AdminError> {
    let redirect_uri = optional_string(&payload, "redirect_uri")?
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| OPENAI_REDIRECT_URI.to_owned());
    validate_loopback_redirect(&redirect_uri)?;
    let (session_id, state, challenge) = new_session(
        pool,
        "openai",
        json!({
            "client_id": OPENAI_CLIENT_ID,
            "redirect_uri": redirect_uri,
            "proxy_id": optional_i64(&payload, "proxy_id")?,
        }),
    )
    .await?;
    let auth_url = authorization_url(
        OPENAI_AUTHORIZE_URL,
        &[
            ("response_type", "code"),
            ("client_id", OPENAI_CLIENT_ID),
            ("redirect_uri", &redirect_uri),
            ("scope", OPENAI_SCOPE),
            ("state", &state),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("id_token_add_organizations", "true"),
            ("codex_cli_simplified_flow", "true"),
        ],
    )?;
    Ok(json!({ "auth_url": auth_url, "session_id": session_id, "state": state }))
}

async fn generate_gemini_auth_url(pool: &PgPool, payload: Value) -> Result<Value, AdminError> {
    let oauth_type = optional_string(&payload, "oauth_type")?
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "code_assist".to_owned());
    if !matches!(
        oauth_type.as_str(),
        "code_assist" | "google_one" | "ai_studio"
    ) {
        return Err(AdminError::BadRequest(
            "oauth_type must be code_assist, google_one, or ai_studio".to_owned(),
        ));
    }
    let config = gemini_client_config(&oauth_type)?;
    let redirect_uri = if config.2 {
        GEMINI_CODE_ASSIST_REDIRECT_URI
    } else {
        GEMINI_AI_STUDIO_REDIRECT_URI
    };
    let project_id = optional_string(&payload, "project_id")?.unwrap_or_default();
    let tier_id = optional_string(&payload, "tier_id")?.unwrap_or_default();
    validate_identifier("project_id", &project_id, 200)?;
    validate_identifier("tier_id", &tier_id, 64)?;
    let (session_id, state, challenge) = new_session(
        pool,
        "gemini",
        json!({
            "oauth_type": oauth_type,
            "redirect_uri": redirect_uri,
            "project_id": project_id,
            "tier_id": tier_id,
            "proxy_id": optional_i64(&payload, "proxy_id")?,
        }),
    )
    .await?;
    let mut parameters = vec![
        ("response_type", "code"),
        ("client_id", config.0.as_str()),
        ("redirect_uri", redirect_uri),
        ("scope", config.1.as_str()),
        ("state", state.as_str()),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("access_type", "offline"),
        ("prompt", "consent"),
        ("include_granted_scopes", "true"),
    ];
    if !project_id.is_empty() {
        parameters.push(("project_id", project_id.as_str()));
    }
    let auth_url = authorization_url(GOOGLE_AUTHORIZE_URL, &parameters)?;
    Ok(json!({ "auth_url": auth_url, "session_id": session_id, "state": state }))
}

async fn generate_antigravity_auth_url(pool: &PgPool, payload: Value) -> Result<Value, AdminError> {
    let (session_id, state, challenge) = new_session(
        pool,
        "antigravity",
        json!({ "proxy_id": optional_i64(&payload, "proxy_id")? }),
    )
    .await?;
    let auth_url = authorization_url(
        GOOGLE_AUTHORIZE_URL,
        &[
            ("client_id", ANTIGRAVITY_CLIENT_ID),
            ("redirect_uri", ANTIGRAVITY_REDIRECT_URI),
            ("response_type", "code"),
            ("scope", ANTIGRAVITY_SCOPE),
            ("state", &state),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("access_type", "offline"),
            ("prompt", "consent"),
            ("include_granted_scopes", "true"),
        ],
    )?;
    Ok(json!({ "auth_url": auth_url, "session_id": session_id, "state": state }))
}

async fn generate_grok_auth_url(pool: &PgPool, payload: Value) -> Result<Value, AdminError> {
    let redirect_uri = optional_string(&payload, "redirect_uri")?
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(grok_redirect_uri);
    validate_loopback_redirect(&redirect_uri)?;
    let nonce = random_url_token(16);
    let client_id = grok_client_id();
    let scope = grok_scope();
    let (session_id, state, challenge) = new_session(
        pool,
        "grok",
        json!({
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "proxy_id": optional_i64(&payload, "proxy_id")?,
        }),
    )
    .await?;
    let auth_url = authorization_url(
        &grok_authorize_url()?,
        &[
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", &redirect_uri),
            ("scope", &scope),
            ("state", &state),
            ("nonce", &nonce),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("plan", "generic"),
            ("referrer", "sub2api"),
        ],
    )?;
    Ok(json!({ "auth_url": auth_url, "session_id": session_id, "state": state }))
}

async fn new_session(
    pool: &PgPool,
    provider: &str,
    context: Value,
) -> Result<(String, String, String), AdminError> {
    let state = random_url_token(32);
    let verifier = random_url_token(if provider == "openai" { 64 } else { 32 });
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let id = Uuid::new_v4();
    let state_hash = Sha256::digest(state.as_bytes()).to_vec();
    let ciphertext = encrypt_session(&SessionSecrets {
        state: state.clone(),
        verifier,
    })?;
    let context = serde_json::to_string(&context)
        .map_err(|error| AdminError::BadRequest(format!("invalid OAuth context: {error}")))?;
    sqlx::query(
        "INSERT INTO admin_oauth_sessions (id, provider, state_hash, verifier_ciphertext, context, expires_at) VALUES ($1::uuid, $2, $3, $4, $5::jsonb, NOW() + make_interval(mins => $6))",
    )
    .bind(id.to_string())
    .bind(provider)
    .bind(state_hash)
    .bind(ciphertext)
    .bind(context)
    .bind(SESSION_TTL_MINUTES)
    .execute(pool)
    .await?;
    Ok((id.to_string(), state, challenge))
}

async fn consume_session(
    pool: &PgPool,
    provider: &str,
    payload: &Value,
) -> Result<OAuthSession, AdminError> {
    let session_id = required_string(payload, "session_id")?;
    let id = Uuid::parse_str(&session_id)
        .map_err(|_| AdminError::BadRequest("session_id is invalid".to_owned()))?;
    let mut transaction = pool.begin().await?;
    let row = sqlx::query(
        "SELECT state_hash, verifier_ciphertext, context::text AS context_json FROM admin_oauth_sessions WHERE id = $1::uuid AND provider = $2 AND consumed_at IS NULL AND expires_at > NOW() FOR UPDATE",
    )
    .bind(id.to_string())
    .bind(provider)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| AdminError::BadRequest("OAuth session was not found or has expired".to_owned()))?;
    let state_hash: Vec<u8> = row.try_get("state_hash")?;
    let ciphertext: String = row.try_get("verifier_ciphertext")?;
    let context_json: String = row.try_get("context_json")?;
    let secrets = decrypt_session(&ciphertext)?;
    let supplied_state = oauth_state_from_payload(payload);
    if provider != "anthropic" && supplied_state.is_none() {
        return Err(AdminError::BadRequest("OAuth state is required".to_owned()));
    }
    if let Some(state) = supplied_state {
        let supplied_hash = Sha256::digest(state.as_bytes());
        if state_hash.as_slice() != supplied_hash.as_slice() {
            return Err(AdminError::BadRequest("OAuth state is invalid".to_owned()));
        }
    }
    sqlx::query("UPDATE admin_oauth_sessions SET consumed_at = NOW() WHERE id = $1::uuid")
        .bind(id.to_string())
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    let context = serde_json::from_str(&context_json)
        .map_err(|error| AdminError::Probe(format!("stored OAuth context is invalid: {error}")))?;
    Ok(OAuthSession { secrets, context })
}

async fn exchange_code(pool: &PgPool, provider: &str, payload: Value) -> Result<Value, AdminError> {
    let session = consume_session(pool, provider, &payload).await?;
    let code = authorization_code(&required_string(&payload, "code")?)?;
    let proxy_id = optional_i64(&payload, "proxy_id")?
        .or_else(|| session.context.get("proxy_id").and_then(Value::as_i64));
    let client = oauth_client(pool, proxy_id).await?;
    let endpoint = token_endpoint(provider, &session.context)?;
    let mut fields = Map::from_iter([
        ("grant_type".to_owned(), json!("authorization_code")),
        ("client_id".to_owned(), json!(endpoint.client_id.clone())),
        ("code".to_owned(), json!(code)),
        ("code_verifier".to_owned(), json!(session.secrets.verifier)),
    ]);
    if let Some(secret) = endpoint.client_secret.as_deref() {
        fields.insert("client_secret".to_owned(), json!(secret));
    }
    if let Some(redirect_uri) = endpoint.redirect_uri.as_deref() {
        fields.insert("redirect_uri".to_owned(), json!(redirect_uri));
    }
    if provider == "anthropic" {
        fields.insert("state".to_owned(), json!(session.secrets.state));
    }
    let response = post_token(&client, endpoint, fields).await?;
    Ok(enrich_token(provider, response, &session.context, None))
}

async fn refresh_token(pool: &PgPool, provider: &str, payload: Value) -> Result<Value, AdminError> {
    let refresh = optional_string(&payload, "refresh_token")?
        .or(optional_string(&payload, "rt")?)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AdminError::BadRequest("refresh_token is required".to_owned()))?;
    let proxy_id = optional_i64(&payload, "proxy_id")?;
    let context = refresh_context(provider, &payload)?;
    let endpoint = token_endpoint(provider, &context)?;
    let client = oauth_client(pool, proxy_id).await?;
    let mut fields = Map::from_iter([
        ("grant_type".to_owned(), json!("refresh_token")),
        ("refresh_token".to_owned(), json!(refresh)),
        ("client_id".to_owned(), json!(endpoint.client_id.clone())),
    ]);
    if let Some(secret) = endpoint.client_secret.as_deref() {
        fields.insert("client_secret".to_owned(), json!(secret));
    }
    if let Some(scope) = endpoint.scope.as_deref() {
        fields.insert("scope".to_owned(), json!(scope));
    }
    let response = post_token(&client, endpoint, fields).await?;
    Ok(enrich_token(provider, response, &context, Some(&refresh)))
}

fn token_endpoint(provider: &str, context: &Value) -> Result<TokenEndpoint, AdminError> {
    match provider {
        "anthropic" => Ok(TokenEndpoint {
            url: CLAUDE_TOKEN_URL.to_owned(),
            client_id: CLAUDE_CLIENT_ID.to_owned(),
            client_secret: None,
            redirect_uri: Some(CLAUDE_REDIRECT_URI.to_owned()),
            scope: None,
            json_body: true,
            user_agent: "axios/1.13.6",
        }),
        "openai" => Ok(TokenEndpoint {
            url: OPENAI_TOKEN_URL.to_owned(),
            client_id: context
                .get("client_id")
                .and_then(Value::as_str)
                .unwrap_or(OPENAI_CLIENT_ID)
                .to_owned(),
            client_secret: None,
            redirect_uri: Some(
                context
                    .get("redirect_uri")
                    .and_then(Value::as_str)
                    .unwrap_or(OPENAI_REDIRECT_URI)
                    .to_owned(),
            ),
            scope: Some(OPENAI_REFRESH_SCOPE.to_owned()),
            json_body: false,
            user_agent: "codex-cli/0.91.0",
        }),
        "gemini" => {
            let oauth_type = context
                .get("oauth_type")
                .and_then(Value::as_str)
                .unwrap_or("code_assist");
            let config = gemini_client_config(oauth_type)?;
            Ok(TokenEndpoint {
                url: GOOGLE_TOKEN_URL.to_owned(),
                client_id: config.0,
                client_secret: Some(config.3),
                redirect_uri: Some(
                    context
                        .get("redirect_uri")
                        .and_then(Value::as_str)
                        .unwrap_or(if config.2 {
                            GEMINI_CODE_ASSIST_REDIRECT_URI
                        } else {
                            GEMINI_AI_STUDIO_REDIRECT_URI
                        })
                        .to_owned(),
                ),
                scope: None,
                json_body: false,
                user_agent: "GeminiCLI/0.1.5",
            })
        }
        "antigravity" => Ok(TokenEndpoint {
            url: GOOGLE_TOKEN_URL.to_owned(),
            client_id: ANTIGRAVITY_CLIENT_ID.to_owned(),
            client_secret: Some(antigravity_client_secret()),
            redirect_uri: Some(ANTIGRAVITY_REDIRECT_URI.to_owned()),
            scope: None,
            json_body: false,
            user_agent: "antigravity/1.23.2 windows/amd64",
        }),
        "grok" => Ok(TokenEndpoint {
            url: grok_token_url()?,
            client_id: context
                .get("client_id")
                .and_then(Value::as_str)
                .unwrap_or(GROK_CLIENT_ID)
                .to_owned(),
            client_secret: None,
            redirect_uri: context
                .get("redirect_uri")
                .and_then(Value::as_str)
                .map(str::to_owned),
            scope: None,
            json_body: false,
            user_agent: "sub2api-grok-oauth/1.0",
        }),
        _ => Err(AdminError::BadRequest(
            "unsupported OAuth provider".to_owned(),
        )),
    }
}

async fn post_token(
    client: &Client,
    endpoint: TokenEndpoint,
    fields: Map<String, Value>,
) -> Result<Value, AdminError> {
    let mut request = client
        .post(&endpoint.url)
        .header("Accept", "application/json")
        .header("User-Agent", endpoint.user_agent);
    request = if endpoint.json_body {
        request.json(&Value::Object(fields))
    } else {
        let form = fields
            .into_iter()
            .filter_map(|(key, value)| value.as_str().map(|value| (key, value.to_owned())))
            .collect::<Vec<_>>();
        request.form(&form)
    };
    let response = request
        .send()
        .await
        .map_err(|error| AdminError::Probe(format!("OAuth token request failed: {error}")))?;
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > 1_048_576)
    {
        return Err(AdminError::Probe(
            "OAuth provider returned an oversized response".to_owned(),
        ));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| AdminError::Probe(format!("OAuth response read failed: {error}")))?;
    if !status.is_success() {
        let message = String::from_utf8_lossy(&bytes)
            .chars()
            .take(2_048)
            .collect::<String>();
        return Err(AdminError::Probe(format!(
            "OAuth provider rejected the request ({status}): {message}"
        )));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| AdminError::Probe(format!("OAuth response is invalid JSON: {error}")))
}

fn enrich_token(
    provider: &str,
    mut response: Value,
    context: &Value,
    previous_refresh: Option<&str>,
) -> Value {
    let Some(object) = response.as_object_mut() else {
        return response;
    };
    let expires_in = object
        .get("expires_in")
        .and_then(Value::as_i64)
        .unwrap_or(if provider == "grok" { 21_600 } else { 3_600 });
    let safety_window = i64::from(matches!(provider, "gemini" | "antigravity")) * 300;
    let expires_at = (chrono::Utc::now().timestamp() + expires_in - safety_window)
        .max(chrono::Utc::now().timestamp() + 30);
    object.insert("expires_in".to_owned(), json!(expires_in));
    object.insert("expires_at".to_owned(), json!(expires_at));
    if object
        .get("refresh_token")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
        && let Some(refresh) = previous_refresh
    {
        object.insert("refresh_token".to_owned(), json!(refresh));
    }
    for field in ["client_id", "oauth_type", "project_id", "tier_id"] {
        if let Some(value) = context.get(field).filter(|value| !value.is_null()) {
            object.insert(field.to_owned(), value.clone());
        }
    }
    if let Some(token) = object.get("id_token").and_then(Value::as_str)
        && let Some(claims) = decode_jwt_payload(token)
    {
        copy_claim(&claims, object, "email", "email");
        let auth = claims.get("https://api.openai.com/auth");
        if let Some(auth) = auth {
            copy_claim(auth, object, "chatgpt_account_id", "chatgpt_account_id");
            copy_claim(auth, object, "chatgpt_user_id", "chatgpt_user_id");
            copy_claim(auth, object, "chatgpt_plan_type", "plan_type");
            copy_claim(auth, object, "poid", "organization_id");
        }
    }
    response
}

fn copy_claim(source: &Value, target: &mut Map<String, Value>, source_key: &str, target_key: &str) {
    if let Some(value) = source.get(source_key).filter(|value| !value.is_null()) {
        target.insert(target_key.to_owned(), value.clone());
    }
}

fn decode_jwt_payload(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice(&decoded).ok()
}

fn refresh_context(provider: &str, payload: &Value) -> Result<Value, AdminError> {
    Ok(match provider {
        "openai" => json!({
            "client_id": optional_string(payload, "client_id")?.filter(|value| !value.is_empty()).unwrap_or_else(|| OPENAI_CLIENT_ID.to_owned()),
            "redirect_uri": OPENAI_REDIRECT_URI,
        }),
        "gemini" => json!({
            "oauth_type": optional_string(payload, "oauth_type")?.filter(|value| !value.is_empty()).unwrap_or_else(|| "code_assist".to_owned()),
        }),
        "grok" => json!({
            "client_id": optional_string(payload, "client_id")?.filter(|value| !value.is_empty()).unwrap_or_else(grok_client_id),
            "redirect_uri": grok_redirect_uri(),
        }),
        _ => Value::Object(Map::new()),
    })
}

async fn oauth_client(pool: &PgPool, proxy_id: Option<i64>) -> Result<Client, AdminError> {
    let mut builder = Client::builder()
        .timeout(Duration::from_mins(2))
        .redirect(Policy::none());
    if let Some(proxy_id) = proxy_id {
        let row = sqlx::query(
            "SELECT protocol, host, port, username, password FROM proxies WHERE id = $1 AND status = 'active' AND deleted_at IS NULL",
        )
        .bind(proxy_id)
        .fetch_optional(pool)
        .await?
        .ok_or(AdminError::NotFound("proxy"))?;
        let protocol: String = row.try_get("protocol")?;
        let host: String = row.try_get("host")?;
        let port: i32 = row.try_get("port")?;
        if !(1..=65_535).contains(&port) {
            return Err(AdminError::BadRequest("proxy port is invalid".to_owned()));
        }
        let mut url = Url::parse(&format!("{protocol}://{host}:{port}"))
            .map_err(|_| AdminError::BadRequest("proxy URL is invalid".to_owned()))?;
        let username: Option<String> = row.try_get("username")?;
        let password: Option<String> = row.try_get("password")?;
        if let Some(username) = username.filter(|value| !value.is_empty()) {
            url.set_username(&username)
                .map_err(|()| AdminError::BadRequest("proxy username is invalid".to_owned()))?;
            url.set_password(password.as_deref())
                .map_err(|()| AdminError::BadRequest("proxy password is invalid".to_owned()))?;
        }
        builder = builder.proxy(Proxy::all(url.as_str()).map_err(|error| {
            AdminError::BadRequest(format!("proxy configuration is invalid: {error}"))
        })?);
    }
    builder
        .build()
        .map_err(|error| AdminError::Probe(format!("cannot build OAuth HTTP client: {error}")))
}

async fn claude_cookie_auth(
    pool: &PgPool,
    payload: Value,
    setup_token: bool,
) -> Result<Value, AdminError> {
    let session_key = required_string(&payload, "code")?;
    if session_key
        .bytes()
        .any(|byte| byte.is_ascii_control() || matches!(byte, b';' | b','))
    {
        return Err(AdminError::BadRequest(
            "Claude session key contains invalid cookie characters".to_owned(),
        ));
    }
    let client = oauth_client(pool, optional_i64(&payload, "proxy_id")?).await?;
    let cookie = format!("sessionKey={session_key}");
    let organizations = upstream_json(
        client
            .get("https://claude.ai/api/organizations")
            .header("Cookie", &cookie),
        "Claude organization lookup",
    )
    .await?;
    let organization_id = select_claude_organization(&organizations)?;
    let verifier = random_url_token(32);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let state = random_url_token(32);
    let scope = if setup_token {
        CLAUDE_SCOPE_INFERENCE
    } else {
        CLAUDE_SCOPE_API
    };
    let authorization = upstream_json(
        client
            .post(format!(
                "https://claude.ai/v1/oauth/{organization_id}/authorize"
            ))
            .header("Cookie", &cookie)
            .header("Origin", "https://claude.ai")
            .header("Referer", "https://claude.ai/new")
            .json(&json!({
                "response_type": "code",
                "client_id": CLAUDE_CLIENT_ID,
                "organization_uuid": organization_id,
                "redirect_uri": CLAUDE_REDIRECT_URI,
                "scope": scope,
                "state": state,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            })),
        "Claude authorization",
    )
    .await?;
    let redirect = authorization
        .get("redirect_uri")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AdminError::Probe("Claude authorization response is missing redirect_uri".to_owned())
        })?;
    let redirect = Url::parse(redirect)
        .map_err(|_| AdminError::Probe("Claude authorization redirect is invalid".to_owned()))?;
    let code = redirect
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.into_owned())
        .ok_or_else(|| AdminError::Probe("Claude authorization code is missing".to_owned()))?;
    let returned_state = redirect
        .query_pairs()
        .find(|(key, _)| key == "state")
        .map(|(_, value)| value.into_owned());
    if returned_state
        .as_deref()
        .is_some_and(|value| value != state)
    {
        return Err(AdminError::BadRequest(
            "Claude authorization state is invalid".to_owned(),
        ));
    }
    let endpoint = token_endpoint("anthropic", &Value::Null)?;
    let response = post_token(
        &client,
        endpoint,
        Map::from_iter([
            ("code".to_owned(), json!(code)),
            ("grant_type".to_owned(), json!("authorization_code")),
            ("client_id".to_owned(), json!(CLAUDE_CLIENT_ID)),
            ("redirect_uri".to_owned(), json!(CLAUDE_REDIRECT_URI)),
            ("code_verifier".to_owned(), json!(verifier)),
            ("state".to_owned(), json!(state)),
        ]),
    )
    .await?;
    let mut token = enrich_token("anthropic", response, &Value::Null, None);
    if let Some(object) = token.as_object_mut() {
        object.insert("org_uuid".to_owned(), json!(organization_id));
    }
    Ok(token)
}

fn select_claude_organization(organizations: &Value) -> Result<String, AdminError> {
    let organizations = organizations.as_array().ok_or_else(|| {
        AdminError::Probe("Claude organization response must be an array".to_owned())
    })?;
    let organization = organizations
        .iter()
        .find(|organization| organization.get("raven_type").and_then(Value::as_str) == Some("team"))
        .or_else(|| organizations.first())
        .ok_or_else(|| AdminError::BadRequest("no Claude organization is available".to_owned()))?;
    organization
        .get("uuid")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| AdminError::Probe("Claude organization UUID is missing".to_owned()))
}

async fn upstream_json(
    request: reqwest::RequestBuilder,
    operation: &str,
) -> Result<Value, AdminError> {
    let response = request
        .send()
        .await
        .map_err(|error| AdminError::Probe(format!("{operation} failed: {error}")))?;
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > 1_048_576)
    {
        return Err(AdminError::Probe(format!(
            "{operation} returned an oversized response"
        )));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| AdminError::Probe(format!("{operation} response failed: {error}")))?;
    if !status.is_success() {
        let message = String::from_utf8_lossy(&bytes)
            .chars()
            .take(2_048)
            .collect::<String>();
        return Err(AdminError::Probe(format!(
            "{operation} was rejected ({status}): {message}"
        )));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| AdminError::Probe(format!("{operation} returned invalid JSON: {error}")))
}

async fn apply_oauth_credentials(
    pool: &PgPool,
    id: i64,
    payload: Value,
) -> Result<Value, AdminError> {
    let account_type = required_string(&payload, "type")?;
    if !matches!(account_type.as_str(), "oauth" | "setup-token") {
        return Err(AdminError::BadRequest(
            "type must be oauth or setup-token".to_owned(),
        ));
    }
    let credentials = payload
        .get("credentials")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| AdminError::BadRequest("credentials must be an object".to_owned()))?;
    if credentials.is_empty() {
        return Err(AdminError::BadRequest(
            "credentials cannot be empty".to_owned(),
        ));
    }
    let extra = payload
        .get("extra")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let result = sqlx::query(
        "UPDATE accounts SET type = $2, credentials = $3::jsonb, extra = extra || $4::jsonb, status = 'active', error_message = NULL, updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL AND type IN ('oauth','setup-token')",
    )
    .bind(id)
    .bind(account_type)
    .bind(serde_json::to_string(&credentials).map_err(|error| AdminError::BadRequest(error.to_string()))?)
    .bind(serde_json::to_string(&extra).map_err(|error| AdminError::BadRequest(error.to_string()))?)
    .execute(pool)
    .await?;
    if result.rows_affected() == 0 {
        return Err(AdminError::BadRequest(
            "account was not found or is not OAuth-based".to_owned(),
        ));
    }
    account_public_json(pool, id).await
}

async fn refresh_account(
    pool: &PgPool,
    id: i64,
    expected_platform: &str,
) -> Result<Value, AdminError> {
    let row = sqlx::query(
        "SELECT platform, type, credentials::text AS credentials_json, proxy_id FROM accounts WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(AdminError::NotFound("account"))?;
    let platform: String = row.try_get("platform")?;
    let account_type: String = row.try_get("type")?;
    if platform != expected_platform || !matches!(account_type.as_str(), "oauth" | "setup-token") {
        return Err(AdminError::BadRequest(format!(
            "account is not a {expected_platform} OAuth account"
        )));
    }
    let credentials: Value = serde_json::from_str(&row.try_get::<String, _>("credentials_json")?)
        .map_err(|error| {
        AdminError::Probe(format!("stored credentials are invalid: {error}"))
    })?;
    let refresh = credentials
        .get("refresh_token")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AdminError::BadRequest("account has no refresh_token".to_owned()))?;
    let context = match expected_platform {
        "openai" => json!({
            "client_id": credentials.get("client_id").and_then(Value::as_str).unwrap_or(OPENAI_CLIENT_ID),
            "redirect_uri": OPENAI_REDIRECT_URI,
        }),
        "grok" => json!({
            "client_id": credentials.get("client_id").and_then(Value::as_str).unwrap_or(GROK_CLIENT_ID),
            "redirect_uri": credentials.get("redirect_uri").and_then(Value::as_str).unwrap_or(GROK_REDIRECT_URI),
        }),
        "gemini" => json!({
            "oauth_type": credentials.get("oauth_type").and_then(Value::as_str).unwrap_or("code_assist"),
        }),
        _ => Value::Object(Map::new()),
    };
    let client = oauth_client(pool, row.try_get("proxy_id")?).await?;
    let endpoint = token_endpoint(expected_platform, &context)?;
    let mut fields = Map::from_iter([
        ("grant_type".to_owned(), json!("refresh_token")),
        ("refresh_token".to_owned(), json!(refresh)),
        ("client_id".to_owned(), json!(endpoint.client_id.clone())),
    ]);
    if let Some(scope) = endpoint.scope.as_deref() {
        fields.insert("scope".to_owned(), json!(scope));
    }
    if let Some(secret) = endpoint.client_secret.as_deref() {
        fields.insert("client_secret".to_owned(), json!(secret));
    }
    let token = enrich_token(
        expected_platform,
        post_token(&client, endpoint, fields).await?,
        &context,
        Some(refresh),
    );
    let new_credentials = token_credentials(expected_platform, &token)?;
    let serialized = serde_json::to_string(&new_credentials)
        .map_err(|error| AdminError::BadRequest(error.to_string()))?;
    sqlx::query(
        "UPDATE accounts SET credentials = credentials || $2::jsonb, status = 'active', error_message = NULL, updated_at = NOW() WHERE id = $1",
    )
    .bind(id)
    .bind(serialized)
    .execute(pool)
    .await?;
    account_public_json(pool, id).await
}

pub(super) async fn refresh_account_auto(pool: &PgPool, id: i64) -> Result<Value, AdminError> {
    let platform = sqlx::query_scalar::<_, String>(
        "SELECT platform FROM accounts WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(AdminError::NotFound("account"))?;
    refresh_account(pool, id, &platform).await
}

async fn create_account_from_oauth(
    pool: &PgPool,
    provider: &str,
    payload: Value,
) -> Result<Value, AdminError> {
    let token = exchange_code(pool, provider, payload.clone()).await?;
    let credentials = token_credentials(provider, &token)?;
    let email = token
        .get("email")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let fallback = if provider == "openai" {
        "OpenAI OAuth Account"
    } else {
        "Grok OAuth Account"
    };
    create_account(
        pool,
        provider,
        "oauth",
        credentials,
        &payload,
        email,
        fallback,
    )
    .await
}

async fn create_openai_pat_account(pool: &PgPool, payload: Value) -> Result<Value, AdminError> {
    let access_token = required_string(&payload, "access_token")?;
    if !access_token.starts_with("at-") {
        return Err(AdminError::BadRequest(
            "Codex personal access token must start with at-".to_owned(),
        ));
    }
    let client = oauth_client(pool, optional_i64(&payload, "proxy_id")?).await?;
    let whoami = upstream_json(
        client
            .get("https://auth.openai.com/api/accounts/v1/user-auth-credential/whoami")
            .bearer_auth(&access_token)
            .header("Accept", "application/json")
            .header("Originator", "codex_cli_rs")
            .header("User-Agent", "codex-cli/0.91.0"),
        "Codex personal access token validation",
    )
    .await?;
    for field in [
        "email",
        "chatgpt_user_id",
        "chatgpt_account_id",
        "chatgpt_plan_type",
    ] {
        if whoami
            .get(field)
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(AdminError::Probe(format!(
                "Codex token validation response is missing {field}"
            )));
        }
    }
    let mut credentials = payload
        .get("credential_extras")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    credentials.insert("access_token".to_owned(), json!(access_token));
    credentials.insert("auth_mode".to_owned(), json!("personal_access_token"));
    credentials.insert("oauth_mode".to_owned(), json!("personal_access_token"));
    credentials.insert("token_type".to_owned(), json!("Bearer"));
    for field in [
        "email",
        "chatgpt_user_id",
        "chatgpt_account_id",
        "chatgpt_plan_type",
        "chatgpt_account_is_fedramp",
    ] {
        if let Some(value) = whoami.get(field) {
            let target = if field == "chatgpt_plan_type" {
                "plan_type"
            } else {
                field
            };
            credentials.insert(target.to_owned(), value.clone());
        }
    }
    let email = whoami
        .get("email")
        .and_then(Value::as_str)
        .unwrap_or_default();
    create_account(
        pool,
        "openai",
        "oauth",
        Value::Object(credentials),
        &payload,
        email,
        "Codex PAT Account",
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn create_account(
    pool: &PgPool,
    platform: &str,
    account_type: &str,
    credentials: Value,
    payload: &Value,
    suggested_name: &str,
    fallback_name: &str,
) -> Result<Value, AdminError> {
    let name = optional_string(payload, "name")?
        .filter(|value| !value.is_empty())
        .or_else(|| (!suggested_name.is_empty()).then(|| suggested_name.to_owned()))
        .unwrap_or_else(|| fallback_name.to_owned());
    if name.chars().count() > 100 {
        return Err(AdminError::BadRequest(
            "account name exceeds 100 characters".to_owned(),
        ));
    }
    let concurrency = payload
        .get("concurrency")
        .and_then(Value::as_i64)
        .unwrap_or(3);
    let concurrency = if concurrency <= 0 { 3 } else { concurrency };
    let priority = payload
        .get("priority")
        .and_then(Value::as_i64)
        .unwrap_or(50);
    let priority = if priority <= 0 { 50 } else { priority };
    if concurrency > 100_000 || !(1..=100).contains(&priority) {
        return Err(AdminError::BadRequest(
            "account concurrency or priority is out of range".to_owned(),
        ));
    }
    let proxy_id = optional_i64(payload, "proxy_id")?;
    let groups = group_ids(payload)?;
    let credentials = serde_json::to_string(&credentials)
        .map_err(|error| AdminError::BadRequest(error.to_string()))?;
    let extra = payload
        .get("extra")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let extra =
        serde_json::to_string(&extra).map_err(|error| AdminError::BadRequest(error.to_string()))?;
    let mut transaction = pool.begin().await?;
    validate_proxy(&mut transaction, proxy_id).await?;
    validate_groups(&mut transaction, &groups).await?;
    let id = sqlx::query_scalar::<_, i64>(
        "INSERT INTO accounts (name, platform, type, credentials, extra, proxy_id, concurrency, priority, status, schedulable) VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6, $7, $8, 'active', TRUE) RETURNING id",
    )
    .bind(name)
    .bind(platform)
    .bind(account_type)
    .bind(credentials)
    .bind(extra)
    .bind(proxy_id)
    .bind(i32::try_from(concurrency).map_err(|_| AdminError::BadRequest("concurrency is too large".to_owned()))?)
    .bind(i32::try_from(priority).map_err(|_| AdminError::BadRequest("priority is too large".to_owned()))?)
    .fetch_one(&mut *transaction)
    .await?;
    bind_groups(
        &mut transaction,
        id,
        &groups,
        i32::try_from(priority).unwrap_or(50),
    )
    .await?;
    transaction.commit().await?;
    account_public_json(pool, id).await
}

fn token_credentials(provider: &str, token: &Value) -> Result<Value, AdminError> {
    let token = token
        .as_object()
        .ok_or_else(|| AdminError::Probe("OAuth token response is not an object".to_owned()))?;
    let access_token = token
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AdminError::Probe("OAuth response has no access_token".to_owned()))?;
    let expires_at = token.get("expires_at").and_then(Value::as_i64).unwrap_or(0);
    let mut credentials = Map::from_iter([("access_token".to_owned(), json!(access_token))]);
    if expires_at > 0 {
        let expires = if matches!(provider, "gemini" | "antigravity") {
            expires_at.to_string()
        } else {
            chrono::DateTime::from_timestamp(expires_at, 0)
                .map_or_else(|| expires_at.to_string(), |value| value.to_rfc3339())
        };
        credentials.insert("expires_at".to_owned(), json!(expires));
    }
    for field in [
        "refresh_token",
        "id_token",
        "token_type",
        "scope",
        "client_id",
        "email",
        "chatgpt_account_id",
        "chatgpt_user_id",
        "organization_id",
        "plan_type",
        "project_id",
        "tier_id",
        "oauth_type",
        "subscription_tier",
        "entitlement_status",
    ] {
        if let Some(value) = token.get(field).filter(|value| !value.is_null()) {
            credentials.insert(field.to_owned(), value.clone());
        }
    }
    if provider == "grok" {
        credentials.insert("base_url".to_owned(), json!("https://api.x.ai/v1"));
    }
    Ok(Value::Object(credentials))
}

async fn account_public_json(pool: &PgPool, id: i64) -> Result<Value, AdminError> {
    let sql = format!(
        "SELECT {} FROM accounts row WHERE id = $1 AND deleted_at IS NULL",
        redacted_json("row")
    );
    sqlx::query_scalar::<_, Value>(&sql)
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(AdminError::NotFound("account"))
}

async fn account_quota(
    pool: &PgPool,
    id: i64,
    expected_platform: &str,
) -> Result<Value, AdminError> {
    let row = sqlx::query(
        "SELECT platform, status, schedulable, rate_limit_reset_at::text AS rate_limit_reset_at, overload_until::text AS overload_until, credentials - ARRAY['access_token','refresh_token','id_token']::text[] AS public_credentials FROM accounts WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(AdminError::NotFound("account"))?;
    let platform: String = row.try_get("platform")?;
    if platform != expected_platform {
        return Err(AdminError::BadRequest(format!(
            "account platform is {platform}, expected {expected_platform}"
        )));
    }
    let usage = sqlx::query(
        "SELECT COUNT(*)::bigint AS requests, COALESCE(SUM(input_tokens),0)::bigint AS input_tokens, COALESCE(SUM(output_tokens),0)::bigint AS output_tokens, COALESCE(SUM(actual_cost),0)::double precision AS cost FROM usage_logs WHERE account_id = $1 AND created_at >= date_trunc('day', NOW())",
    )
    .bind(id)
    .fetch_one(pool)
    .await?;
    Ok(json!({
        "account_id": id,
        "platform": platform,
        "status": row.try_get::<String, _>("status")?,
        "schedulable": row.try_get::<bool, _>("schedulable")?,
        "rate_limit_reset_at": row.try_get::<Option<String>, _>("rate_limit_reset_at")?,
        "overload_until": row.try_get::<Option<String>, _>("overload_until")?,
        "credentials": row.try_get::<Value, _>("public_credentials")?,
        "today": {
            "requests": usage.try_get::<i64, _>("requests")?,
            "input_tokens": usage.try_get::<i64, _>("input_tokens")?,
            "output_tokens": usage.try_get::<i64, _>("output_tokens")?,
            "cost": usage.try_get::<f64, _>("cost")?,
        },
        "source": "postgresql",
    }))
}

async fn reset_account_quota(
    pool: &PgPool,
    id: i64,
    expected_platform: &str,
) -> Result<Value, AdminError> {
    let result = sqlx::query(
        "UPDATE accounts SET rate_limited_at = NULL, rate_limit_reset_at = NULL, overload_until = NULL, temp_unschedulable_until = NULL, temp_unschedulable_reason = NULL, extra = extra - ARRAY['quota_exhausted','quota_reset_at','quota_usage','rate_limit']::text[], status = CASE WHEN status = 'error' THEN 'active' ELSE status END, error_message = NULL, updated_at = NOW() WHERE id = $1 AND platform = $2 AND deleted_at IS NULL",
    )
    .bind(id)
    .bind(expected_platform)
    .execute(pool)
    .await?;
    if result.rows_affected() == 0 {
        return Err(AdminError::NotFound("provider account"));
    }
    Ok(json!({ "success": true, "account_id": id, "reset": "local_quota_state" }))
}

async fn create_openai_shadow(
    pool: &PgPool,
    parent_id: i64,
    payload: Value,
) -> Result<Value, AdminError> {
    let mut transaction = pool.begin().await?;
    let parent = sqlx::query(
        "SELECT name, platform, type, parent_account_id, proxy_id, concurrency, priority FROM accounts WHERE id = $1 AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(parent_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(AdminError::NotFound("parent account"))?;
    if parent.try_get::<String, _>("platform")? != "openai"
        || parent.try_get::<String, _>("type")? != "oauth"
        || parent
            .try_get::<Option<i64>, _>("parent_account_id")?
            .is_some()
    {
        return Err(AdminError::BadRequest(
            "spark shadow requires a real OpenAI OAuth parent account".to_owned(),
        ));
    }
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM accounts WHERE parent_account_id = $1 AND quota_dimension = 'spark' AND deleted_at IS NULL)",
    )
    .bind(parent_id)
    .fetch_one(&mut *transaction)
    .await?;
    if exists {
        return Err(AdminError::Conflict(
            "parent account already has a spark shadow".to_owned(),
        ));
    }
    let parent_name: String = parent.try_get("name")?;
    let mut name = optional_string(&payload, "name")?
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("{parent_name} (Spark)"));
    name = name.chars().take(100).collect();
    let concurrency = payload
        .get("concurrency")
        .and_then(Value::as_i64)
        .filter(|value| *value > 0)
        .map_or_else(
            || parent.try_get::<i32, _>("concurrency").map(i64::from),
            Ok,
        )?;
    let priority = payload
        .get("priority")
        .and_then(Value::as_i64)
        .filter(|value| *value > 0)
        .map_or_else(|| parent.try_get::<i32, _>("priority").map(i64::from), Ok)?;
    let mut groups = group_ids(&payload)?;
    if groups.is_empty() {
        groups = sqlx::query_scalar::<_, i64>(
            "SELECT group_id FROM account_groups WHERE account_id = $1 ORDER BY group_id",
        )
        .bind(parent_id)
        .fetch_all(&mut *transaction)
        .await?;
    }
    validate_groups(&mut transaction, &groups).await?;
    let credentials = json!({
        "model_mapping": {
            "gpt-5.3-codex-spark": "gpt-5.3-codex-spark"
        }
    });
    let id = sqlx::query_scalar::<_, i64>(
        "INSERT INTO accounts (name, platform, type, credentials, extra, parent_account_id, quota_dimension, proxy_id, concurrency, priority, status, schedulable) VALUES ($1, 'openai', 'oauth', $2::jsonb, '{}'::jsonb, $3, 'spark', $4, $5, $6, 'active', TRUE) RETURNING id",
    )
    .bind(name)
    .bind(serde_json::to_string(&credentials).map_err(|error| AdminError::BadRequest(error.to_string()))?)
    .bind(parent_id)
    .bind(parent.try_get::<Option<i64>, _>("proxy_id")?)
    .bind(i32::try_from(concurrency).map_err(|_| AdminError::BadRequest("concurrency is too large".to_owned()))?)
    .bind(i32::try_from(priority).map_err(|_| AdminError::BadRequest("priority is too large".to_owned()))?)
    .fetch_one(&mut *transaction)
    .await?;
    bind_groups(
        &mut transaction,
        id,
        &groups,
        i32::try_from(priority).unwrap_or(50),
    )
    .await?;
    transaction.commit().await?;
    account_public_json(pool, id).await
}

fn group_ids(payload: &Value) -> Result<Vec<i64>, AdminError> {
    let Some(values) = payload.get("group_ids") else {
        return Ok(Vec::new());
    };
    let values = values
        .as_array()
        .ok_or_else(|| AdminError::BadRequest("group_ids must be an array".to_owned()))?;
    let mut groups = Vec::with_capacity(values.len());
    for value in values {
        let id = value.as_i64().filter(|id| *id > 0).ok_or_else(|| {
            AdminError::BadRequest("group_ids must contain positive integers".to_owned())
        })?;
        if !groups.contains(&id) {
            groups.push(id);
        }
    }
    Ok(groups)
}

async fn validate_groups(
    transaction: &mut Transaction<'_, Postgres>,
    groups: &[i64],
) -> Result<(), AdminError> {
    if groups.is_empty() {
        return Ok(());
    }
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::bigint FROM groups WHERE id = ANY($1) AND deleted_at IS NULL",
    )
    .bind(groups)
    .fetch_one(&mut **transaction)
    .await?;
    if usize::try_from(count).ok() != Some(groups.len()) {
        return Err(AdminError::BadRequest(
            "one or more group_ids do not exist".to_owned(),
        ));
    }
    Ok(())
}

async fn validate_proxy(
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
        return Err(AdminError::NotFound("proxy"));
    }
    Ok(())
}

async fn bind_groups(
    transaction: &mut Transaction<'_, Postgres>,
    account_id: i64,
    groups: &[i64],
    priority: i32,
) -> Result<(), AdminError> {
    for group_id in groups {
        sqlx::query(
            "INSERT INTO account_groups (account_id, group_id, priority) VALUES ($1, $2, $3) ON CONFLICT (account_id, group_id) DO UPDATE SET priority = EXCLUDED.priority",
        )
        .bind(account_id)
        .bind(group_id)
        .bind(priority)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

fn grok_runtime_sanity() -> Value {
    let authorize = grok_authorize_url();
    let token = grok_token_url();
    let redirect = grok_redirect_uri();
    json!({
        "base_url": {
            "value": env::var("XAI_BASE_URL").unwrap_or_else(|_| "https://api.x.ai/v1".to_owned()),
            "valid": true,
            "is_default": env::var("XAI_BASE_URL").is_err(),
        },
        "oauth_authorize_url": sanity_value(authorize, env::var("XAI_OAUTH_AUTHORIZE_URL").is_err()),
        "oauth_token_url": sanity_value(token, env::var("XAI_OAUTH_TOKEN_URL").is_err()),
        "oauth_redirect_uri": {
            "value": redirect,
            "valid": validate_loopback_redirect(&redirect).is_ok(),
            "is_default": env::var("XAI_OAUTH_REDIRECT_URI").is_err(),
        },
        "unsafe_url_overrides": false,
        "unsafe_high_concurrency": env_flag("XAI_GROK_UNSAFE_ALLOW_CONCURRENCY_GT_ONE"),
        "public_gateway_scope": "responses_only",
        "proxy_policy": "account_proxy_optional; OAuth endpoints are allowlisted",
    })
}

fn sanity_value(value: Result<String, AdminError>, is_default: bool) -> Value {
    match value {
        Ok(value) => json!({ "value": value, "valid": true, "is_default": is_default }),
        Err(error) => {
            json!({ "value": "", "valid": false, "error": error.to_string(), "is_default": is_default })
        }
    }
}

fn env_flag(name: &str) -> bool {
    env::var(name).is_ok_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn encrypt_session(secrets: &SessionSecrets) -> Result<String, AdminError> {
    let key = encryption_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| AdminError::Unavailable("OAuth encryption key is invalid".to_owned()))?;
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let plaintext = serde_json::to_vec(secrets)
        .map_err(|error| AdminError::Probe(format!("cannot serialize OAuth session: {error}")))?;
    let encrypted = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_slice())
        .map_err(|_| AdminError::Probe("OAuth session encryption failed".to_owned()))?;
    let mut combined = Vec::with_capacity(nonce.len() + encrypted.len());
    combined.extend_from_slice(&nonce);
    combined.extend_from_slice(&encrypted);
    Ok(base64::engine::general_purpose::STANDARD.encode(combined))
}

fn decrypt_session(ciphertext: &str) -> Result<SessionSecrets, AdminError> {
    let combined = base64::engine::general_purpose::STANDARD
        .decode(ciphertext)
        .map_err(|_| AdminError::Probe("stored OAuth session is invalid".to_owned()))?;
    if combined.len() <= 12 {
        return Err(AdminError::Probe(
            "stored OAuth session is truncated".to_owned(),
        ));
    }
    let key = encryption_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| AdminError::Unavailable("OAuth encryption key is invalid".to_owned()))?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&combined[..12]), &combined[12..])
        .map_err(|_| AdminError::Probe("stored OAuth session cannot be decrypted".to_owned()))?;
    serde_json::from_slice(&plaintext)
        .map_err(|error| AdminError::Probe(format!("stored OAuth session is invalid: {error}")))
}

fn encryption_key() -> Result<[u8; 32], AdminError> {
    secrets::config_encryption_key().map_err(|error| {
        AdminError::Unavailable(format!(
            "TOTP_ENCRYPTION_KEY is required for OAuth sessions: {error}"
        ))
    })
}

fn random_url_token(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    OsRng.fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

fn authorization_url(base: &str, parameters: &[(&str, &str)]) -> Result<String, AdminError> {
    let mut url = Url::parse(base)
        .map_err(|_| AdminError::BadRequest("OAuth authorize URL is invalid".to_owned()))?;
    {
        let mut query = url.query_pairs_mut();
        for (key, value) in parameters {
            query.append_pair(key, value);
        }
    }
    Ok(url.into())
}

fn oauth_state_from_payload(payload: &Value) -> Option<String> {
    optional_string(payload, "state")
        .ok()
        .flatten()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            payload
                .get("code")
                .and_then(Value::as_str)
                .and_then(|value| value.split_once('#').map(|(_, state)| state.to_owned()))
        })
        .or_else(|| {
            payload
                .get("code")
                .and_then(Value::as_str)
                .and_then(|value| Url::parse(value).ok())
                .and_then(|url| {
                    url.query_pairs()
                        .find(|(key, _)| key == "state")
                        .map(|(_, value)| value.into_owned())
                })
        })
}

fn authorization_code(raw: &str) -> Result<String, AdminError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AdminError::BadRequest(
            "authorization code is required".to_owned(),
        ));
    }
    if let Ok(url) = Url::parse(trimmed)
        && let Some((_, code)) = url.query_pairs().find(|(key, _)| key == "code")
    {
        return Ok(code.into_owned());
    }
    Ok(trimmed
        .split_once('#')
        .map_or(trimmed, |(code, _)| code)
        .to_owned())
}

fn required_string(payload: &Value, field: &str) -> Result<String, AdminError> {
    optional_string(payload, field)?
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AdminError::BadRequest(format!("{field} is required")))
}

fn optional_string(payload: &Value, field: &str) -> Result<Option<String>, AdminError> {
    match payload.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.trim().to_owned())),
        Some(_) => Err(AdminError::BadRequest(format!("{field} must be a string"))),
    }
}

fn optional_i64(payload: &Value, field: &str) -> Result<Option<i64>, AdminError> {
    match payload.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => value
            .as_i64()
            .filter(|value| *value > 0)
            .map(Some)
            .ok_or_else(|| AdminError::BadRequest(format!("{field} must be a positive integer"))),
        Some(_) => Err(AdminError::BadRequest(format!(
            "{field} must be a positive integer"
        ))),
    }
}

fn validate_loopback_redirect(value: &str) -> Result<(), AdminError> {
    let url = Url::parse(value)
        .map_err(|_| AdminError::BadRequest("redirect_uri is invalid".to_owned()))?;
    let host = url.host_str().unwrap_or_default();
    if url.scheme() != "http" || !matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1") {
        return Err(AdminError::BadRequest(
            "redirect_uri must use HTTP on a loopback host".to_owned(),
        ));
    }
    Ok(())
}

fn validate_identifier(field: &str, value: &str, max: usize) -> Result<(), AdminError> {
    if value.len() > max
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'/' | b'.'))
    {
        return Err(AdminError::BadRequest(format!("{field} is invalid")));
    }
    Ok(())
}

fn gemini_client_config(oauth_type: &str) -> Result<(String, String, bool, String), AdminError> {
    if oauth_type == "ai_studio" {
        let client_id = env::var("GEMINI_OAUTH_CLIENT_ID").unwrap_or_default();
        let secret = env::var("GEMINI_OAUTH_CLIENT_SECRET").unwrap_or_default();
        if client_id.trim().is_empty() || secret.trim().is_empty() {
            return Err(AdminError::BadRequest(
                "AI Studio OAuth requires GEMINI_OAUTH_CLIENT_ID and GEMINI_OAUTH_CLIENT_SECRET"
                    .to_owned(),
            ));
        }
        let scope =
            env::var("GEMINI_OAUTH_SCOPES").unwrap_or_else(|_| GEMINI_AI_STUDIO_SCOPE.to_owned());
        return Ok((client_id, scope, false, secret));
    }
    Ok((
        GEMINI_CLIENT_ID.to_owned(),
        GEMINI_CODE_ASSIST_SCOPE.to_owned(),
        true,
        env::var("GEMINI_CLI_OAUTH_CLIENT_SECRET")
            .unwrap_or_else(|_| GEMINI_CLIENT_SECRET.to_owned()),
    ))
}

fn gemini_capabilities() -> Value {
    let custom = env::var("GEMINI_OAUTH_CLIENT_ID").is_ok_and(|value| !value.trim().is_empty())
        && env::var("GEMINI_OAUTH_CLIENT_SECRET").is_ok_and(|value| !value.trim().is_empty());
    json!({
        "ai_studio_oauth_enabled": custom,
        "required_redirect_uris": [GEMINI_AI_STUDIO_REDIRECT_URI],
        "durable_sessions": true,
    })
}

fn antigravity_client_secret() -> String {
    env::var("ANTIGRAVITY_OAUTH_CLIENT_SECRET")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| ANTIGRAVITY_CLIENT_SECRET.to_owned())
}

fn grok_client_id() -> String {
    env::var("XAI_OAUTH_CLIENT_ID")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| GROK_CLIENT_ID.to_owned())
}

fn grok_scope() -> String {
    env::var("XAI_OAUTH_SCOPE")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| GROK_SCOPE.to_owned())
}

fn grok_redirect_uri() -> String {
    env::var("XAI_OAUTH_REDIRECT_URI")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| GROK_REDIRECT_URI.to_owned())
}

fn grok_authorize_url() -> Result<String, AdminError> {
    validated_grok_endpoint("XAI_OAUTH_AUTHORIZE_URL", GROK_AUTHORIZE_URL)
}

fn grok_token_url() -> Result<String, AdminError> {
    validated_grok_endpoint("XAI_OAUTH_TOKEN_URL", GROK_TOKEN_URL)
}

fn validated_grok_endpoint(name: &str, fallback: &str) -> Result<String, AdminError> {
    let value = env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| fallback.to_owned());
    let url =
        Url::parse(&value).map_err(|_| AdminError::BadRequest(format!("{name} is invalid")))?;
    let host = url.host_str().unwrap_or_default();
    if url.scheme() != "https" || !(host == "x.ai" || host.ends_with(".x.ai")) {
        return Err(AdminError::BadRequest(format!(
            "{name} must be an HTTPS x.ai endpoint"
        )));
    }
    Ok(value)
}

fn account_id(path: &str) -> Option<i64> {
    path.split_once("/accounts/")?
        .1
        .split('/')
        .next()?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_go_admin_provider_oauth_route_is_owned() {
        let routes = crate::route_contract::routes()
            .filter(|route| {
                matches!(
                    route.category,
                    "admin/openai" | "admin/gemini" | "admin/antigravity" | "admin/grok"
                ) || route.handler == "h.Admin.Account.ApplyOAuthCredentials"
                    || route.handler.starts_with("h.Admin.OAuth.")
                    || route.handler == "h.Admin.OpenAIOAuth.CreateShadow"
            })
            .collect::<Vec<_>>();
        assert_eq!(routes.len(), 30);
        let missing = routes
            .iter()
            .filter(|route| !handles(route.handler))
            .map(|route| route.handler)
            .collect::<Vec<_>>();
        assert!(missing.is_empty(), "unhandled OAuth routes: {missing:?}");
    }

    #[test]
    fn callback_parsing_accepts_url_fragment_and_bare_code() {
        assert_eq!(
            authorization_code("https://localhost/callback?code=abc&state=s").unwrap(),
            "abc"
        );
        assert_eq!(authorization_code("abc#state").unwrap(), "abc");
        assert_eq!(authorization_code("abc").unwrap(), "abc");
    }

    #[test]
    fn jwt_claims_are_extracted_without_trusting_them_for_authorization() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"email":"admin@example.com"}"#);
        let token = format!("header.{payload}.signature");
        assert_eq!(
            decode_jwt_payload(&token).unwrap()["email"],
            "admin@example.com"
        );
    }
}
