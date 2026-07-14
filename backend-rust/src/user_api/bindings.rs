use axum::{
    Json, Router,
    extract::{Path, State, rejection::JsonRejection},
    http::HeaderMap,
    routing::{delete, post, put},
};
use serde::{Deserialize, Serialize};
use sqlx::Row;

use super::json_payload;
use crate::{
    control_api::{ApiEnvelope, ApiError, ControlApiState},
    security::password,
};

const MAX_NOTIFICATION_EMAILS: usize = 3;

pub(super) fn routes() -> Router<ControlApiState> {
    Router::new()
        .route(
            "/api/v1/user/account-bindings/email/send-code",
            post(send_email_binding_code),
        )
        .route(
            "/api/v1/user/account-bindings/email",
            post(bind_email_identity),
        )
        .route(
            "/api/v1/user/account-bindings/{provider}",
            delete(unbind_identity),
        )
        .route(
            "/api/v1/user/auth-identities/bind/start",
            post(start_identity_binding),
        )
        .route(
            "/api/v1/user/notify-email/send-code",
            post(send_notification_email_code),
        )
        .route(
            "/api/v1/user/notify-email/verify",
            post(verify_notification_email),
        )
        .route(
            "/api/v1/user/notify-email/toggle",
            put(toggle_notification_email),
        )
        .route(
            "/api/v1/user/notify-email",
            delete(remove_notification_email),
        )
}

#[derive(Debug, Deserialize)]
struct EmailRequest {
    email: String,
}

#[derive(Debug, Deserialize)]
struct BindEmailRequest {
    email: String,
    verify_code: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct VerifyNotificationEmailRequest {
    email: String,
    code: String,
}

#[derive(Debug, Deserialize)]
struct ToggleNotificationEmailRequest {
    email: String,
    disabled: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct NotificationEmailEntry {
    email: String,
    #[serde(default)]
    disabled: bool,
    #[serde(default)]
    verified: bool,
}

#[derive(Debug, Deserialize)]
struct StartIdentityBindingRequest {
    provider: String,
    #[serde(default)]
    redirect_to: String,
}

#[derive(Debug, Serialize)]
struct StartIdentityBindingResponse {
    provider: String,
    authorize_url: String,
    method: &'static str,
    use_browser_redirect: bool,
}

async fn send_email_binding_code(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    payload: Result<Json<EmailRequest>, JsonRejection>,
) -> Result<Json<ApiEnvelope<serde_json::Value>>, ApiError> {
    let user = state.authenticate(&headers).await?;
    let request = json_payload(payload)?;
    let email = normalize_email(&request.email)?;
    reject_reserved_email(&email)?;
    let owned_by_other = sqlx::query_scalar::<_, bool>(
        r"
SELECT EXISTS (
    SELECT 1 FROM users
    WHERE LOWER(email) = LOWER($1) AND id <> $2 AND deleted_at IS NULL
    UNION ALL
    SELECT 1 FROM auth_identities
    WHERE provider_type = 'email' AND LOWER(provider_subject) = LOWER($1)
      AND user_id <> $2
)
",
    )
    .bind(&email)
    .bind(user.view.id)
    .fetch_one(state.pool())
    .await?;
    if owned_by_other {
        return Err(ApiError::conflict(
            "Email address is already in use",
            "EMAIL_ALREADY_EXISTS",
        ));
    }
    state.send_email_binding_code(user.view.id, &email).await?;
    Ok(Json(ApiEnvelope::success(serde_json::json!({
        "message": "Verification code sent successfully"
    }))))
}

#[allow(clippy::too_many_lines)]
async fn bind_email_identity(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    payload: Result<Json<BindEmailRequest>, JsonRejection>,
) -> Result<Json<ApiEnvelope<crate::control_api::UserProfile>>, ApiError> {
    let user = state.authenticate(&headers).await?;
    let request = json_payload(payload)?;
    let email = normalize_email(&request.email)?;
    reject_reserved_email(&email)?;
    if request.password.is_empty() || request.password.len() > 72 {
        return Err(ApiError::bad_request("Invalid password"));
    }

    let mut transaction = state.pool().begin().await?;
    let current = sqlx::query(
        r"
SELECT email, password_hash
FROM users
WHERE id = $1 AND status = 'active' AND deleted_at IS NULL
FOR UPDATE
",
    )
    .bind(user.view.id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| ApiError::not_found("User not found"))?;
    let old_email: String = current.try_get("email")?;
    let old_hash: String = current.try_get("password_hash")?;
    let first_real_email = is_reserved_email(&old_email) || old_email.trim().is_empty();
    if first_real_email && request.password.len() < 6 {
        return Err(ApiError::bad_request(
            "Password must contain between 6 and 72 bytes",
        ));
    }
    if !first_real_email {
        let candidate = request.password.clone();
        let password_matches =
            tokio::task::spawn_blocking(move || password::verify_password(&candidate, &old_hash))
                .await
                .map_err(|error| ApiError::internal("join password verification task", error))?
                .map_err(|error| ApiError::internal("verify password", error))?;
        if !password_matches {
            return Err(ApiError::bad_request("Password is incorrect"));
        }
    }
    let password_value = request.password;
    let password_hash =
        tokio::task::spawn_blocking(move || password::hash_password(&password_value))
            .await
            .map_err(|error| ApiError::internal("join password hashing task", error))?
            .map_err(|error| ApiError::internal("hash password", error))?;

    let owned_by_other = sqlx::query_scalar::<_, bool>(
        r"
SELECT EXISTS (
    SELECT 1 FROM users
    WHERE LOWER(email) = LOWER($1) AND id <> $2 AND deleted_at IS NULL
    UNION ALL
    SELECT 1 FROM auth_identities
    WHERE provider_type = 'email' AND LOWER(provider_subject) = LOWER($1)
      AND user_id <> $2
)
",
    )
    .bind(&email)
    .bind(user.view.id)
    .fetch_one(&mut *transaction)
    .await?;
    if owned_by_other {
        return Err(ApiError::conflict(
            "Email address is already in use",
            "EMAIL_ALREADY_EXISTS",
        ));
    }
    state
        .consume_email_binding_code(
            &mut transaction,
            user.view.id,
            &email,
            request.verify_code.trim(),
        )
        .await?;

    sqlx::query(
        r"
UPDATE users
SET email = $2, password_hash = $3, auth_generation = auth_generation + 1,
    updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL
",
    )
    .bind(user.view.id)
    .bind(&email)
    .bind(password_hash)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r"
INSERT INTO auth_identities (
    user_id, provider_type, provider_key, provider_subject,
    verified_at, metadata, created_at, updated_at
)
VALUES ($1, 'email', 'email', $2, NOW(), $3, NOW(), NOW())
ON CONFLICT (provider_type, provider_key, provider_subject) DO NOTHING
",
    )
    .bind(user.view.id)
    .bind(&email)
    .bind(serde_json::json!({"source": "rust_user_email_bind"}))
    .execute(&mut *transaction)
    .await?;
    let identity_owner = sqlx::query_scalar::<_, i64>(
        r"
SELECT user_id FROM auth_identities
WHERE provider_type = 'email' AND provider_key = 'email' AND provider_subject = $1
",
    )
    .bind(&email)
    .fetch_optional(&mut *transaction)
    .await?;
    if identity_owner != Some(user.view.id) {
        return Err(ApiError::conflict(
            "Email address is already in use",
            "EMAIL_ALREADY_EXISTS",
        ));
    }
    if !old_email.eq_ignore_ascii_case(&email) {
        sqlx::query(
            r"
DELETE FROM auth_identities
WHERE user_id = $1 AND provider_type = 'email' AND provider_key = 'email'
  AND LOWER(provider_subject) = LOWER($2)
",
        )
        .bind(user.view.id)
        .bind(old_email)
        .execute(&mut *transaction)
        .await?;
    }
    revoke_user_sessions(&mut transaction, user.view.id).await?;
    transaction.commit().await?;
    state.invalidate_user_auth_cache().await;
    Ok(Json(ApiEnvelope::success(
        state.profile_by_id(user.view.id).await?,
    )))
}

async fn unbind_identity(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    Path(provider): Path<String>,
) -> Result<Json<ApiEnvelope<crate::control_api::UserProfile>>, ApiError> {
    let user = state.authenticate(&headers).await?;
    let provider = normalize_unbind_provider(&provider)?;
    let mut transaction = state.pool().begin().await?;
    let email = sqlx::query_scalar::<_, String>(
        "SELECT email FROM users WHERE id = $1 AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(user.view.id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| ApiError::not_found("User not found"))?;
    let bound_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM auth_identities WHERE user_id = $1 AND provider_type = $2",
    )
    .bind(user.view.id)
    .bind(provider)
    .fetch_one(&mut *transaction)
    .await?;
    if bound_count > 0 {
        let remaining = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM auth_identities WHERE user_id = $1 AND provider_type <> $2",
        )
        .bind(user.view.id)
        .bind(provider)
        .fetch_one(&mut *transaction)
        .await?;
        if remaining == 0 && is_reserved_email(&email) {
            return Err(ApiError::bad_request(
                "Cannot remove the last available sign-in method",
            ));
        }
        sqlx::query("DELETE FROM auth_identities WHERE user_id = $1 AND provider_type = $2")
            .bind(user.view.id)
            .bind(provider)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            r"
UPDATE users SET auth_generation = auth_generation + 1, updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL
",
        )
        .bind(user.view.id)
        .execute(&mut *transaction)
        .await?;
        revoke_user_sessions(&mut transaction, user.view.id).await?;
    }
    transaction.commit().await?;
    if bound_count > 0 {
        state.invalidate_user_auth_cache().await;
    }
    Ok(Json(ApiEnvelope::success(
        state.profile_by_id(user.view.id).await?,
    )))
}

async fn start_identity_binding(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    payload: Result<Json<StartIdentityBindingRequest>, JsonRejection>,
) -> Result<Json<ApiEnvelope<StartIdentityBindingResponse>>, ApiError> {
    let _user = state.authenticate(&headers).await?;
    let request = json_payload(payload)?;
    let provider = normalize_unbind_provider(&request.provider)?.to_owned();
    let redirect = normalize_identity_redirect(&request.redirect_to)?;
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("intent", "bind_current_user")
        .append_pair("redirect", redirect)
        .finish();
    let authorize_url = format!("/api/v1/auth/oauth/{provider}/bind/start?{query}");
    Ok(Json(ApiEnvelope::success(StartIdentityBindingResponse {
        provider,
        authorize_url,
        method: "GET",
        use_browser_redirect: true,
    })))
}

async fn send_notification_email_code(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    payload: Result<Json<EmailRequest>, JsonRejection>,
) -> Result<Json<ApiEnvelope<serde_json::Value>>, ApiError> {
    let user = state.authenticate(&headers).await?;
    let request = json_payload(payload)?;
    let email = normalize_email(&request.email)?;
    reject_reserved_email(&email)?;
    state
        .send_notification_email_code(user.view.id, &email)
        .await?;
    Ok(Json(ApiEnvelope::success(serde_json::json!({
        "message": "Verification code sent successfully"
    }))))
}

async fn verify_notification_email(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    payload: Result<Json<VerifyNotificationEmailRequest>, JsonRejection>,
) -> Result<Json<ApiEnvelope<crate::control_api::UserProfile>>, ApiError> {
    let user = state.authenticate(&headers).await?;
    let request = json_payload(payload)?;
    let email = normalize_email(&request.email)?;
    reject_reserved_email(&email)?;
    let mut transaction = state.pool().begin().await?;
    let mut entries = lock_notification_emails(&mut transaction, user.view.id).await?;
    state
        .consume_notification_email_code(
            &mut transaction,
            user.view.id,
            &email,
            request.code.trim(),
        )
        .await?;
    if let Some(entry) = entries
        .iter_mut()
        .find(|entry| entry.email.eq_ignore_ascii_case(&email))
    {
        entry.email.clone_from(&email);
        entry.verified = true;
    } else {
        if entries.len() >= MAX_NOTIFICATION_EMAILS {
            return Err(ApiError::bad_request(
                "Maximum number of notification emails reached",
            ));
        }
        entries.push(NotificationEmailEntry {
            email,
            disabled: false,
            verified: true,
        });
    }
    save_notification_emails(&mut transaction, user.view.id, &entries).await?;
    transaction.commit().await?;
    Ok(Json(ApiEnvelope::success(
        state.profile_by_id(user.view.id).await?,
    )))
}

async fn remove_notification_email(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    payload: Result<Json<EmailRequest>, JsonRejection>,
) -> Result<Json<ApiEnvelope<crate::control_api::UserProfile>>, ApiError> {
    let user = state.authenticate(&headers).await?;
    let request = json_payload(payload)?;
    let email = normalize_email(&request.email)?;
    let mut transaction = state.pool().begin().await?;
    let mut entries = lock_notification_emails(&mut transaction, user.view.id).await?;
    let original_len = entries.len();
    entries.retain(|entry| !entry.email.eq_ignore_ascii_case(&email));
    if entries.len() == original_len {
        return Err(ApiError::bad_request("Notification email not found"));
    }
    save_notification_emails(&mut transaction, user.view.id, &entries).await?;
    transaction.commit().await?;
    Ok(Json(ApiEnvelope::success(
        state.profile_by_id(user.view.id).await?,
    )))
}

async fn toggle_notification_email(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    payload: Result<Json<ToggleNotificationEmailRequest>, JsonRejection>,
) -> Result<Json<ApiEnvelope<crate::control_api::UserProfile>>, ApiError> {
    let user = state.authenticate(&headers).await?;
    let request = json_payload(payload)?;
    let email = normalize_email(&request.email)?;
    let mut transaction = state.pool().begin().await?;
    let mut entries = lock_notification_emails(&mut transaction, user.view.id).await?;
    let entry = entries
        .iter_mut()
        .find(|entry| entry.email.eq_ignore_ascii_case(&email))
        .ok_or_else(|| ApiError::bad_request("Notification email not found"))?;
    entry.disabled = request.disabled;
    save_notification_emails(&mut transaction, user.view.id, &entries).await?;
    transaction.commit().await?;
    Ok(Json(ApiEnvelope::success(
        state.profile_by_id(user.view.id).await?,
    )))
}

async fn lock_notification_emails(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: i64,
) -> Result<Vec<NotificationEmailEntry>, ApiError> {
    let raw = sqlx::query_scalar::<_, String>(
        r"
SELECT balance_notify_extra_emails
FROM users
WHERE id = $1 AND deleted_at IS NULL
FOR UPDATE
",
    )
    .bind(user_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| ApiError::not_found("User not found"))?;
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(&raw)
        .map_err(|error| ApiError::internal("decode notification emails", error))
}

async fn save_notification_emails(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: i64,
    entries: &[NotificationEmailEntry],
) -> Result<(), ApiError> {
    let encoded = serde_json::to_string(entries)
        .map_err(|error| ApiError::internal("encode notification emails", error))?;
    sqlx::query(
        r"
UPDATE users
SET balance_notify_extra_emails = $2, updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL
",
    )
    .bind(user_id)
    .bind(encoded)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn revoke_user_sessions(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: i64,
) -> Result<(), ApiError> {
    sqlx::query(
        r"
UPDATE auth_refresh_sessions
SET revoked_at = COALESCE(revoked_at, NOW())
WHERE user_id = $1 AND revoked_at IS NULL
",
    )
    .bind(user_id)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        r"
UPDATE auth_security_tokens
SET consumed_at = COALESCE(consumed_at, NOW())
WHERE user_id = $1 AND consumed_at IS NULL
",
    )
    .bind(user_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn normalize_email(raw: &str) -> Result<String, ApiError> {
    let email = raw.trim().to_ascii_lowercase();
    let valid = email.len() <= 255
        && email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty()
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
                && !email.bytes().any(|byte| byte.is_ascii_whitespace())
        });
    if valid {
        Ok(email)
    } else {
        Err(ApiError::bad_request("Invalid email address"))
    }
}

fn reject_reserved_email(email: &str) -> Result<(), ApiError> {
    if is_reserved_email(email) {
        Err(ApiError::bad_request(
            "Reserved email address cannot be used",
        ))
    } else {
        Ok(())
    }
}

fn is_reserved_email(email: &str) -> bool {
    let email = email.trim().to_ascii_lowercase();
    [
        "@linuxdo-connect.invalid",
        "@oidc-connect.invalid",
        "@wechat-connect.invalid",
        "@dingtalk-connect.invalid",
    ]
    .iter()
    .any(|suffix| email.ends_with(suffix))
}

fn normalize_unbind_provider(raw: &str) -> Result<&'static str, ApiError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "linuxdo" => Ok("linuxdo"),
        "oidc" => Ok("oidc"),
        "wechat" => Ok("wechat"),
        "dingtalk" => Ok("dingtalk"),
        _ => Err(ApiError::bad_request("Invalid identity provider")),
    }
}

fn normalize_identity_redirect(raw: &str) -> Result<&str, ApiError> {
    let redirect = raw.trim();
    if redirect.is_empty() {
        return Ok("/settings/profile");
    }
    if redirect.len() > 2_048 || !redirect.starts_with('/') || redirect.starts_with("//") {
        return Err(ApiError::bad_request("Invalid redirect path"));
    }
    Ok(redirect)
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode},
    };
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    use super::*;
    use crate::control_api::ControlApiConfig;

    #[tokio::test]
    async fn binding_routes_require_authentication_before_database_access() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://unused:unused@127.0.0.1:9/unused")
            .expect("test PostgreSQL URL should be valid");
        let state = ControlApiState::new(pool, ControlApiConfig::new([7_u8; 32]))
            .expect("test control state should build");
        let app = routes().with_state(state);
        for (method, path) in [
            (
                Method::POST,
                "/api/v1/user/account-bindings/email/send-code",
            ),
            (Method::POST, "/api/v1/user/account-bindings/email"),
            (Method::DELETE, "/api/v1/user/account-bindings/linuxdo"),
            (Method::POST, "/api/v1/user/auth-identities/bind/start"),
            (Method::POST, "/api/v1/user/notify-email/send-code"),
            (Method::POST, "/api/v1/user/notify-email/verify"),
            (Method::PUT, "/api/v1/user/notify-email/toggle"),
            (Method::DELETE, "/api/v1/user/notify-email"),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header("content-type", "application/json")
                        .body(Body::from("{}"))
                        .expect("request should build"),
                )
                .await
                .expect("route should respond");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
        }
    }

    #[test]
    fn binding_inputs_are_fail_closed() {
        assert!(normalize_email("User@Example.com").is_ok());
        assert!(normalize_email("not-an-email").is_err());
        assert!(reject_reserved_email("user@oidc-connect.invalid").is_err());
        assert_eq!(normalize_unbind_provider(" LinuxDo ").ok(), Some("linuxdo"));
        assert!(normalize_unbind_provider("email").is_err());
        assert_eq!(
            normalize_identity_redirect("").ok(),
            Some("/settings/profile")
        );
        assert!(normalize_identity_redirect("https://evil.example").is_err());
        assert!(normalize_identity_redirect("//evil.example").is_err());
    }
}
