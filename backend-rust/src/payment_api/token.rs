use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::{PaymentApiState, PaymentError};

const PAYMENT_RESUME_TTL_SECONDS: i64 = 24 * 60 * 60;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct ResumeClaims {
    #[serde(rename = "oid")]
    pub order_id: i64,
    #[serde(rename = "uid", default, skip_serializing_if = "is_zero")]
    pub user_id: i64,
    #[serde(rename = "pi", default, skip_serializing_if = "String::is_empty")]
    pub provider_instance_id: String,
    #[serde(rename = "pk", default, skip_serializing_if = "String::is_empty")]
    pub provider_key: String,
    #[serde(rename = "pt", default, skip_serializing_if = "String::is_empty")]
    pub payment_type: String,
    #[serde(rename = "ru", default, skip_serializing_if = "String::is_empty")]
    pub canonical_return_url: String,
    #[serde(rename = "iat")]
    pub issued_at: i64,
    #[serde(rename = "exp", default, skip_serializing_if = "is_zero")]
    pub expires_at: i64,
}

impl PaymentApiState {
    pub(super) fn create_resume_token(
        &self,
        mut claims: ResumeClaims,
    ) -> Result<String, PaymentError> {
        if self.resume_signing_key.is_empty() {
            return Err(PaymentError::unavailable(
                "PAYMENT_RESUME_NOT_CONFIGURED",
                "payment resume tokens require a configured signing key",
            ));
        }
        let now = chrono::Utc::now().timestamp();
        if claims.issued_at == 0 {
            claims.issued_at = now;
        }
        if claims.expires_at == 0 {
            claims.expires_at = now + PAYMENT_RESUME_TTL_SECONDS;
        }
        self.sign_token(&claims)
    }

    pub(super) fn parse_resume_token(&self, token: &str) -> Result<ResumeClaims, PaymentError> {
        let claims: ResumeClaims = self.parse_token(token, "INVALID_RESUME_TOKEN")?;
        if claims.order_id <= 0 {
            return Err(PaymentError::bad_request(
                "INVALID_RESUME_TOKEN",
                "resume token missing order id",
            ));
        }
        if claims.expires_at > 0 && chrono::Utc::now().timestamp() > claims.expires_at {
            return Err(PaymentError::bad_request(
                "INVALID_RESUME_TOKEN",
                "resume token has expired",
            ));
        }
        Ok(claims)
    }

    fn sign_token<T: Serialize>(&self, claims: &T) -> Result<String, PaymentError> {
        let payload = serde_json::to_vec(claims)
            .map_err(|error| PaymentError::internal("serialize payment resume token", error))?;
        let encoded = URL_SAFE_NO_PAD.encode(payload);
        let signature = token_signature(&encoded, &self.resume_signing_key)?;
        Ok(format!("{encoded}.{signature}"))
    }

    fn parse_token<T: DeserializeOwned>(
        &self,
        token: &str,
        reason: &'static str,
    ) -> Result<T, PaymentError> {
        let (payload, signature) = token.trim().split_once('.').ok_or_else(|| {
            PaymentError::bad_request(reason, "payment resume token is malformed")
        })?;
        if payload.is_empty() || signature.is_empty() || signature.contains('.') {
            return Err(PaymentError::bad_request(
                reason,
                "payment resume token is malformed",
            ));
        }
        let expected = token_signature(payload, &self.resume_signing_key)?;
        if expected.as_bytes().ct_eq(signature.as_bytes()).unwrap_u8() != 1 {
            return Err(PaymentError::bad_request(
                reason,
                "payment resume token signature mismatch",
            ));
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| PaymentError::bad_request(reason, "payment resume token is malformed"))?;
        serde_json::from_slice(&decoded)
            .map_err(|_| PaymentError::bad_request(reason, "payment resume token is invalid"))
    }
}

fn token_signature(payload: &str, key: &[u8]) -> Result<String, PaymentError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|error| PaymentError::internal("initialize payment token HMAC", error))?;
    mac.update(payload.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_zero(value: &i64) -> bool {
    *value == 0
}

#[cfg(test)]
mod tests {
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

    use super::*;
    use crate::control_api::{ControlApiConfig, ControlApiState};

    fn state() -> PaymentApiState {
        let pool = PgPoolOptions::new().connect_lazy_with(PgConnectOptions::new());
        let control =
            ControlApiState::new(pool.clone(), ControlApiConfig::new([9_u8; 32])).unwrap();
        PaymentApiState::new(pool, control, vec![3_u8; 32])
    }

    #[tokio::test]
    async fn resume_tokens_round_trip_and_reject_tampering() {
        let state = state();
        let token = state
            .create_resume_token(ResumeClaims {
                order_id: 7,
                user_id: 9,
                provider_instance_id: "1".to_owned(),
                provider_key: "stripe".to_owned(),
                payment_type: "stripe".to_owned(),
                canonical_return_url: String::new(),
                issued_at: 0,
                expires_at: 0,
            })
            .unwrap();
        assert_eq!(state.parse_resume_token(&token).unwrap().order_id, 7);
        assert!(state.parse_resume_token(&format!("{token}x")).is_err());
        state.pool().close().await;
    }
}
