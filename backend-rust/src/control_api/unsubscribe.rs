use axum::{
    Router,
    extract::{Query, State},
    response::Html,
    routing::get,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::{ApiError, ControlApiState};

const SECRET_KEY: &str = "notification_email_unsubscribe_secret";
const PREFERENCE_PREFIX: &str = "notification_email_preference:v2:";
const MAX_TOKEN_BYTES: usize = 8 * 1024;

pub(super) fn routes() -> Router<ControlApiState> {
    Router::new().route("/api/v1/settings/email-unsubscribe", get(unsubscribe))
}

#[derive(Debug, Deserialize)]
struct UnsubscribeQuery {
    token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Claims {
    email: String,
    event: String,
    exp: i64,
}

async fn unsubscribe(
    State(state): State<ControlApiState>,
    Query(query): Query<UnsubscribeQuery>,
) -> Result<Html<String>, ApiError> {
    let token = query
        .token
        .as_deref()
        .map(str::trim)
        .filter(|token| !token.is_empty() && token.len() <= MAX_TOKEN_BYTES)
        .ok_or_else(|| ApiError::bad_request("token is required"))?;
    let claims = parse_token(&state, token).await?;
    let event = claims.event.trim().to_ascii_lowercase();
    if !matches!(
        event.as_str(),
        "subscription.expiry_reminder" | "balance.low"
    ) {
        return Err(ApiError::bad_request(
            "This email event is transactional and cannot be unsubscribed",
        ));
    }
    let email = claims.email.trim();
    let identity = format!("{event}\0{}", email.to_ascii_lowercase());
    let key = format!(
        "{PREFERENCE_PREFIX}{}",
        hex::encode(Sha256::digest(identity))
    );
    sqlx::query(
        r"
INSERT INTO settings (key, value, updated_at)
VALUES ($1, 'unsubscribed', NOW())
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
",
    )
    .bind(key)
    .execute(state.pool())
    .await?;

    Ok(Html(format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Unsubscribed</title></head><body style=\"font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;padding:32px;\"><h1>Unsubscribed</h1><p>You have unsubscribed <strong>{}</strong> from <strong>{}</strong> emails.</p></body></html>",
        escape_html(email),
        escape_html(&event),
    )))
}

async fn parse_token(state: &ControlApiState, token: &str) -> Result<Claims, ApiError> {
    let (encoded, signature) = token
        .split_once('.')
        .filter(|(payload, signature)| {
            !payload.is_empty() && !signature.is_empty() && !signature.contains('.')
        })
        .ok_or_else(|| ApiError::bad_request("Invalid unsubscribe token"))?;
    let secret = unsubscribe_secret(state).await?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| ApiError::bad_request("Invalid unsubscribe token signature"))?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|error| ApiError::internal("initialize unsubscribe HMAC", error))?;
    mac.update(encoded.as_bytes());
    mac.verify_slice(&signature)
        .map_err(|_| ApiError::bad_request("Invalid unsubscribe token signature"))?;
    let payload = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ApiError::bad_request("Invalid unsubscribe token payload"))?;
    let claims: Claims = serde_json::from_slice(&payload)
        .map_err(|_| ApiError::bad_request("Invalid unsubscribe token payload"))?;
    if claims.email.trim().is_empty() || claims.email.len() > 255 || claims.event.trim().is_empty()
    {
        return Err(ApiError::bad_request("Invalid unsubscribe token claims"));
    }
    if claims.exp <= chrono::Utc::now().timestamp() {
        return Err(ApiError::bad_request("Unsubscribe token expired"));
    }
    Ok(claims)
}

async fn unsubscribe_secret(state: &ControlApiState) -> Result<String, ApiError> {
    if let Some(secret) =
        sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key = $1 AND value <> ''")
            .bind(SECRET_KEY)
            .fetch_optional(state.pool())
            .await?
    {
        return Ok(secret.trim().to_owned());
    }
    let mut bytes = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let candidate = URL_SAFE_NO_PAD.encode(bytes);
    sqlx::query(
        r"
INSERT INTO settings (key, value, updated_at)
VALUES ($1, $2, NOW())
ON CONFLICT (key) DO NOTHING
",
    )
    .bind(SECRET_KEY)
    .bind(&candidate)
    .execute(state.pool())
    .await?;
    sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key = $1")
        .bind(SECRET_KEY)
        .fetch_one(state.pool())
        .await
        .map_err(ApiError::from)
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::escape_html;

    #[test]
    fn unsubscribe_confirmation_escapes_claim_values() {
        assert_eq!(
            escape_html("<user&\"x\">@example.com"),
            "&lt;user&amp;&quot;x&quot;&gt;@example.com"
        );
    }
}
