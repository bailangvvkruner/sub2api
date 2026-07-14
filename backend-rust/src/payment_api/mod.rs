mod config;
mod error;
mod models;
mod orders;
mod provider;
pub(crate) mod refund;
mod token;
mod webhook;

use std::{env, ops::Deref, sync::Arc};

use axum::{Json, Router, extract::rejection::JsonRejection, http::HeaderMap};
use sqlx::PgPool;

use crate::{
    control_api::{ControlApiState, UserView},
    security::secrets,
};

pub use error::PaymentError;

#[derive(Clone)]
pub struct PaymentApiState {
    provider_runtime: ProviderRuntime,
    control: ControlApiState,
    resume_signing_key: Arc<[u8]>,
}

#[derive(Clone)]
pub struct ProviderRuntime {
    pool: PgPool,
    client: reqwest::Client,
    legacy_config_key: Option<[u8; 32]>,
}

impl ProviderRuntime {
    #[must_use]
    pub(crate) fn new(pool: PgPool) -> Self {
        Self {
            pool,
            client: reqwest::Client::new(),
            legacy_config_key: secrets::optional_config_encryption_key().ok().flatten(),
        }
    }

    #[must_use]
    pub(crate) const fn pool(&self) -> &PgPool {
        &self.pool
    }

    #[must_use]
    pub(crate) const fn client(&self) -> &reqwest::Client {
        &self.client
    }
}

impl PaymentApiState {
    #[must_use]
    pub fn new(pool: PgPool, control: ControlApiState, legacy_signing_key: Vec<u8>) -> Self {
        let resume_signing_key = parse_signing_key(
            env::var("PAYMENT_RESUME_SIGNING_KEY")
                .ok()
                .as_deref()
                .unwrap_or_default(),
        );
        let resume_signing_key = if resume_signing_key.is_empty() {
            legacy_signing_key
        } else {
            resume_signing_key
        };
        Self {
            provider_runtime: ProviderRuntime::new(pool),
            control,
            resume_signing_key: resume_signing_key.into(),
        }
    }

    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        self.provider_runtime.pool()
    }

    #[must_use]
    pub const fn client(&self) -> &reqwest::Client {
        self.provider_runtime.client()
    }

    async fn authenticate(&self, headers: &HeaderMap) -> Result<UserView, PaymentError> {
        self.control
            .authenticate(headers)
            .await
            .map(|user| user.view)
            .map_err(|error| {
                if error.status() == axum::http::StatusCode::FORBIDDEN {
                    PaymentError::forbidden(
                        "BACKEND_MODE_ADMIN_ONLY",
                        "Backend mode is active. User self-service is disabled.",
                    )
                } else {
                    PaymentError::from_auth(&error)
                }
            })
    }
}

impl Deref for PaymentApiState {
    type Target = ProviderRuntime;

    fn deref(&self) -> &Self::Target {
        &self.provider_runtime
    }
}

pub fn router(state: PaymentApiState) -> Router {
    Router::new()
        .merge(config::routes())
        .merge(orders::routes())
        .merge(webhook::routes())
        .with_state(state)
}

fn json_payload<T>(payload: Result<Json<T>, JsonRejection>) -> Result<T, PaymentError> {
    payload
        .map(|Json(value)| value)
        .map_err(|_| PaymentError::bad_request("INVALID_JSON", "Invalid JSON request"))
}

fn parse_signing_key(raw: &str) -> Vec<u8> {
    let raw = raw.trim();
    if raw.len() >= 64
        && raw.len().is_multiple_of(2)
        && let Ok(decoded) = hex::decode(raw)
        && !decoded.is_empty()
    {
        return decoded;
    }
    raw.as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    use super::*;
    use crate::control_api::ControlApiConfig;

    #[test]
    fn signing_key_accepts_hex_and_text() {
        assert_eq!(parse_signing_key(&"ab".repeat(32)), vec![0xab; 32]);
        assert_eq!(parse_signing_key("plain-key"), b"plain-key");
    }

    #[tokio::test]
    async fn protected_payment_json_routes_authenticate_before_body_rejection() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://unused:unused@127.0.0.1:9/unused")
            .expect("test PostgreSQL URL should be valid");
        let control = ControlApiState::new(pool.clone(), ControlApiConfig::new([7_u8; 32]))
            .expect("test control state should build");
        let app = router(PaymentApiState::new(pool, control, vec![9_u8; 32]));

        for path in [
            "/api/v1/payment/orders",
            "/api/v1/payment/orders/verify",
            "/api/v1/payment/orders/1/refund-request",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::post(path)
                        .body(Body::empty())
                        .expect("request should build"),
                )
                .await
                .expect("route should respond");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
        }
    }
}
