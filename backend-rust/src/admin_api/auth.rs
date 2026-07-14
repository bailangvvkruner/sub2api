#![allow(clippy::missing_errors_doc)]

use std::{error::Error, fmt, time::SystemTime};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::models::AdminClaims;

pub trait AdminTokenVerifier: Send + Sync {
    fn verify(&self, token: &str) -> Result<AdminClaims, AdminTokenError>;
}

#[derive(Clone)]
pub struct Hs256AdminTokenVerifier {
    secret: Vec<u8>,
}

impl Hs256AdminTokenVerifier {
    pub fn new(secret: impl Into<Vec<u8>>) -> Result<Self, AdminTokenError> {
        let secret = secret.into();
        if secret.len() < 32 {
            return Err(AdminTokenError::WeakSecret);
        }
        Ok(Self { secret })
    }
}

impl AdminTokenVerifier for Hs256AdminTokenVerifier {
    fn verify(&self, token: &str) -> Result<AdminClaims, AdminTokenError> {
        if token.len() > 8_192 {
            return Err(AdminTokenError::Invalid);
        }
        let mut parts = token.split('.');
        let encoded_header = parts.next().ok_or(AdminTokenError::Invalid)?;
        let encoded_payload = parts.next().ok_or(AdminTokenError::Invalid)?;
        let encoded_signature = parts.next().ok_or(AdminTokenError::Invalid)?;
        if parts.next().is_some() {
            return Err(AdminTokenError::Invalid);
        }

        let header: Header = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(encoded_header)
                .map_err(|_| AdminTokenError::Invalid)?,
        )
        .map_err(|_| AdminTokenError::Invalid)?;
        if header.alg != "HS256" || header.typ.as_deref().is_some_and(|typ| typ != "JWT") {
            return Err(AdminTokenError::Invalid);
        }
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.secret).map_err(|_| AdminTokenError::Invalid)?;
        mac.update(format!("{encoded_header}.{encoded_payload}").as_bytes());
        let expected = mac.finalize().into_bytes();
        let actual = URL_SAFE_NO_PAD
            .decode(encoded_signature)
            .map_err(|_| AdminTokenError::Invalid)?;
        if actual.len() != expected.len() || !bool::from(expected.as_slice().ct_eq(&actual)) {
            return Err(AdminTokenError::Invalid);
        }
        let claims: AdminClaims = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(encoded_payload)
                .map_err(|_| AdminTokenError::Invalid)?,
        )
        .map_err(|_| AdminTokenError::Invalid)?;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| AdminTokenError::Invalid)?
            .as_secs();
        let now = i64::try_from(now).map_err(|_| AdminTokenError::Invalid)?;
        let expiry = claims.exp.ok_or(AdminTokenError::Invalid)?;
        if now >= expiry {
            return Err(AdminTokenError::Expired);
        }
        if claims.nbf.is_some_and(|not_before| now < not_before) {
            return Err(AdminTokenError::NotYetValid);
        }
        if claims.user_id <= 0 {
            return Err(AdminTokenError::Invalid);
        }
        Ok(claims)
    }
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    typ: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminTokenError {
    Expired,
    Invalid,
    NotYetValid,
    WeakSecret,
}

impl fmt::Display for AdminTokenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Expired => "administrator token expired",
            Self::Invalid => "administrator token is invalid",
            Self::NotYetValid => "administrator token is not active yet",
            Self::WeakSecret => "administrator JWT secret must contain at least 32 bytes",
        })
    }
}

impl Error for AdminTokenError {}
