use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const MAX_JWT_LENGTH: usize = 8_192;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JwtClaims {
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
    pub iat: Option<i64>,
    #[serde(default)]
    pub nbf: Option<i64>,
    #[serde(default)]
    pub iss: Option<String>,
    #[serde(default)]
    pub sub: Option<String>,
    #[serde(default)]
    pub aud: Option<Value>,
}

impl JwtClaims {
    /// Validates registered timestamps and the required positive user ID.
    ///
    /// # Errors
    ///
    /// Returns an error when claims are expired, premature, or identify an
    /// invalid user.
    pub fn validate(&self, now_unix_seconds: i64) -> Result<(), JwtError> {
        if self.user_id <= 0 {
            return Err(JwtError::InvalidClaims("user_id must be positive"));
        }
        if self
            .exp
            .is_some_and(|expires_at| now_unix_seconds >= expires_at)
        {
            return Err(JwtError::Expired);
        }
        if self
            .nbf
            .is_some_and(|not_before| now_unix_seconds < not_before)
        {
            return Err(JwtError::NotYetValid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JwtError {
    TooLarge,
    InvalidToken,
    InvalidSignature,
    UnsupportedAlgorithm,
    Expired,
    NotYetValid,
    InvalidClaims(&'static str),
}

impl fmt::Display for JwtError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => formatter.write_str("JWT exceeds the maximum supported length"),
            Self::InvalidToken => formatter.write_str("JWT is malformed"),
            Self::InvalidSignature => formatter.write_str("JWT signature is invalid"),
            Self::UnsupportedAlgorithm => {
                formatter.write_str("JWT signing algorithm is not allowed")
            }
            Self::Expired => formatter.write_str("JWT has expired"),
            Self::NotYetValid => formatter.write_str("JWT is not valid yet"),
            Self::InvalidClaims(message) => write!(formatter, "JWT claims are invalid: {message}"),
        }
    }
}

impl Error for JwtError {}

/// Signature-verification boundary used by the HTTP middleware. Implementors
/// must verify the signature and restrict accepted algorithms before returning
/// claims; there is intentionally no decode-without-verification fallback.
pub trait JwtVerifier: Send + Sync {
    /// Verifies the signature, allowed algorithm, and token representation.
    ///
    /// # Errors
    ///
    /// Returns a classified JWT error for invalid or rejected tokens.
    fn verify(&self, token: &str, now_unix_seconds: i64) -> Result<JwtClaims, JwtError>;
}

impl JwtVerifier for crate::security::jwt::JwtCodec {
    fn verify(&self, token: &str, _now_unix_seconds: i64) -> Result<JwtClaims, JwtError> {
        let claims = self.validate(token).map_err(|error| match error {
            crate::security::jwt::JwtError::Expired => JwtError::Expired,
            crate::security::jwt::JwtError::NotYetValid => JwtError::NotYetValid,
            crate::security::jwt::JwtError::TooLarge => JwtError::TooLarge,
            crate::security::jwt::JwtError::UnsupportedAlgorithm => JwtError::UnsupportedAlgorithm,
            crate::security::jwt::JwtError::Invalid
            | crate::security::jwt::JwtError::WeakSecret => JwtError::InvalidSignature,
        })?;
        Ok(JwtClaims {
            user_id: claims.user_id,
            email: claims.email,
            role: claims.role,
            token_version: claims.token_version,
            exp: Some(claims.exp),
            iat: Some(claims.iat),
            nbf: Some(claims.nbf),
            iss: None,
            sub: None,
            aud: None,
        })
    }
}

#[must_use]
pub fn password_fingerprint_token_version(email: &str, password_hash: &str) -> i64 {
    let material = format!("{}\n{password_hash}", email.trim().to_lowercase());
    let digest = Sha256::digest(material.as_bytes());
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    i64::from_be_bytes(prefix) & i64::MAX
}

/// Extends the Go-compatible password fingerprint with a `PostgreSQL` session
/// generation. Generation zero deliberately preserves the legacy value.
#[must_use]
pub fn session_token_version(email: &str, password_hash: &str, auth_generation: i64) -> i64 {
    let fingerprint = password_fingerprint_token_version(email, password_hash);
    if auth_generation == 0 {
        return fingerprint;
    }
    let mut hasher = Sha256::new();
    hasher.update(b"sub2api/auth-generation/v1\0");
    hasher.update(fingerprint.to_be_bytes());
    hasher.update(auth_generation.to_be_bytes());
    let digest = hasher.finalize();
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    i64::from_be_bytes(prefix) & i64::MAX
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims() -> JwtClaims {
        JwtClaims {
            user_id: 7,
            email: "user@example.com".to_owned(),
            role: "user".to_owned(),
            token_version: 3,
            exp: Some(2_000),
            iat: Some(1_000),
            nbf: Some(1_000),
            iss: None,
            sub: None,
            aud: None,
        }
    }

    #[test]
    fn registered_time_claims_are_enforced() {
        assert!(claims().validate(1_500).is_ok());
        assert_eq!(claims().validate(2_000), Err(JwtError::Expired));
        assert_eq!(claims().validate(999), Err(JwtError::NotYetValid));
    }

    #[test]
    fn password_fingerprint_matches_go_big_endian_contract() {
        let first = password_fingerprint_token_version(" User@Example.COM ", "$2a$hash");
        let second = password_fingerprint_token_version("user@example.com", "$2a$hash");
        assert_eq!(first, second);
        assert_eq!(first, 0x4245_44b4_2922_16a0);
        assert!(first >= 0);
        assert_ne!(
            first,
            password_fingerprint_token_version("other@example.com", "$2a$hash")
        );
    }

    #[test]
    fn session_generation_zero_is_legacy_compatible_and_later_values_rotate() {
        let legacy = password_fingerprint_token_version("user@example.com", "$2a$hash");
        assert_eq!(
            session_token_version("user@example.com", "$2a$hash", 0),
            legacy
        );
        assert_ne!(
            session_token_version("user@example.com", "$2a$hash", 1),
            legacy
        );
        assert_ne!(
            session_token_version("user@example.com", "$2a$hash", 1),
            session_token_version("user@example.com", "$2a$hash", 2)
        );
    }
}
