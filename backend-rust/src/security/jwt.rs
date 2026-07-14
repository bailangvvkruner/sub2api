use std::{error::Error, fmt, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;

const MAX_TOKEN_BYTES: usize = 8192;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JwtClaims {
    pub user_id: i64,
    pub email: String,
    pub role: String,
    pub token_version: i64,
    pub exp: i64,
    pub iat: i64,
    pub nbf: i64,
}

#[derive(Clone)]
pub struct JwtCodec {
    secret: Vec<u8>,
    lifetime: Duration,
}

impl JwtCodec {
    /// Creates the HMAC JWT codec shared by user and administrator auth.
    ///
    /// # Errors
    ///
    /// Returns an error when the secret is too short for production use.
    pub fn new(secret: impl Into<Vec<u8>>, lifetime: Duration) -> Result<Self, JwtError> {
        let secret = secret.into();
        if secret.len() < 32 {
            return Err(JwtError::WeakSecret);
        }
        Ok(Self { secret, lifetime })
    }

    /// Generates an HS256 token compatible with the Go backend's claims.
    ///
    /// # Errors
    ///
    /// Returns an error if claims cannot be serialized or the system clock is
    /// before the Unix epoch.
    pub fn issue(
        &self,
        user_id: i64,
        email: impl Into<String>,
        role: impl Into<String>,
        token_version: i64,
    ) -> Result<String, JwtError> {
        let now = unix_timestamp()?;
        let lifetime = i64::try_from(self.lifetime.as_secs()).map_err(|_| JwtError::Invalid)?;
        let claims = JwtClaims {
            user_id,
            email: email.into(),
            role: role.into(),
            token_version,
            exp: now.checked_add(lifetime).ok_or(JwtError::Invalid)?,
            iat: now,
            nbf: now,
        };
        self.issue_claims(&claims)
    }

    /// Signs an explicitly supplied claim set.
    ///
    /// # Errors
    ///
    /// Returns an error when claims cannot be encoded or signed.
    pub fn issue_claims(&self, claims: &JwtClaims) -> Result<String, JwtError> {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let claims = serde_json::to_vec(claims).map_err(|_| JwtError::Invalid)?;
        let payload = URL_SAFE_NO_PAD.encode(claims);
        let signing_input = format!("{header}.{payload}");
        let signature = sign_hmac("HS256", &self.secret, signing_input.as_bytes())?;
        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature)
        ))
    }

    /// Validates the signature plus `exp` and `nbf` timestamps.
    ///
    /// # Errors
    ///
    /// Returns a classified error for malformed, expired, premature, or
    /// oversized tokens.
    pub fn validate(&self, token: &str) -> Result<JwtClaims, JwtError> {
        let claims = self.validate_signature(token)?;
        let now = unix_timestamp()?;
        if claims.exp < now {
            return Err(JwtError::Expired);
        }
        if claims.nbf > now {
            return Err(JwtError::NotYetValid);
        }
        Ok(claims)
    }

    /// Validates a token signature while returning expired claims for refresh.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid signatures, malformed tokens, or future
    /// `nbf` timestamps.
    pub fn validate_allow_expired(&self, token: &str) -> Result<JwtClaims, JwtError> {
        let claims = self.validate_signature(token)?;
        if claims.nbf > unix_timestamp()? {
            return Err(JwtError::NotYetValid);
        }
        Ok(claims)
    }

    fn validate_signature(&self, token: &str) -> Result<JwtClaims, JwtError> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(JwtError::TooLarge);
        }
        let mut parts = token.split('.');
        let encoded_header = parts.next().ok_or(JwtError::Invalid)?;
        let payload = parts.next().ok_or(JwtError::Invalid)?;
        let signature = parts.next().ok_or(JwtError::Invalid)?;
        if parts.next().is_some() {
            return Err(JwtError::Invalid);
        }

        let header_bytes = URL_SAFE_NO_PAD
            .decode(encoded_header)
            .map_err(|_| JwtError::Invalid)?;
        let decoded_header: Header =
            serde_json::from_slice(&header_bytes).map_err(|_| JwtError::Invalid)?;
        if decoded_header
            .typ
            .as_deref()
            .is_some_and(|value| value != "JWT")
        {
            return Err(JwtError::Invalid);
        }
        let expected = sign_hmac(
            &decoded_header.alg,
            &self.secret,
            format!("{encoded_header}.{payload}").as_bytes(),
        )?;
        let actual = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| JwtError::Invalid)?;
        if expected.len() != actual.len() || !bool::from(expected.ct_eq(&actual)) {
            return Err(JwtError::Invalid);
        }

        let claims = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| JwtError::Invalid)?;
        serde_json::from_slice(&claims).map_err(|_| JwtError::Invalid)
    }
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    typ: Option<String>,
}

fn sign_hmac(algorithm: &str, secret: &[u8], input: &[u8]) -> Result<Vec<u8>, JwtError> {
    macro_rules! sign {
        ($digest:ty) => {{
            let mut mac = Hmac::<$digest>::new_from_slice(secret).map_err(|_| JwtError::Invalid)?;
            mac.update(input);
            Ok(mac.finalize().into_bytes().to_vec())
        }};
    }
    match algorithm {
        "HS256" => sign!(Sha256),
        "HS384" => sign!(Sha384),
        "HS512" => sign!(Sha512),
        _ => Err(JwtError::UnsupportedAlgorithm),
    }
}

fn unix_timestamp() -> Result<i64, JwtError> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| JwtError::Invalid)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| JwtError::Invalid)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JwtError {
    Expired,
    Invalid,
    NotYetValid,
    TooLarge,
    UnsupportedAlgorithm,
    WeakSecret,
}

impl fmt::Display for JwtError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Expired => "token expired",
            Self::Invalid => "invalid token",
            Self::NotYetValid => "token is not active yet",
            Self::TooLarge => "token is too large",
            Self::UnsupportedAlgorithm => "unsupported token algorithm",
            Self::WeakSecret => "JWT secret must be at least 32 bytes",
        })
    }
}

impl Error for JwtError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn codec() -> JwtCodec {
        JwtCodec::new(
            b"0123456789abcdef0123456789abcdef".to_vec(),
            Duration::from_hours(1),
        )
        .expect("test secret is strong")
    }

    #[test]
    fn issues_and_validates_go_compatible_claims() {
        let token = codec()
            .issue(42, "admin@example.com", "admin", 7)
            .expect("token should issue");
        let claims = codec().validate(&token).expect("token should validate");
        assert_eq!(claims.user_id, 42);
        assert_eq!(claims.role, "admin");
        assert_eq!(claims.token_version, 7);
    }

    #[test]
    fn rejects_tampering_and_expiry() {
        let mut claims = JwtClaims {
            user_id: 1,
            email: "user@example.com".to_owned(),
            role: "user".to_owned(),
            token_version: 0,
            exp: 1,
            iat: 1,
            nbf: 1,
        };
        let expired = codec().issue_claims(&claims).expect("token should issue");
        assert_eq!(codec().validate(&expired), Err(JwtError::Expired));

        claims.exp = i64::MAX;
        let token = codec().issue_claims(&claims).expect("token should issue");
        let mut bytes = token.into_bytes();
        let last = bytes.last_mut().expect("token has a signature");
        *last = if *last == b'A' { b'B' } else { b'A' };
        let token = String::from_utf8(bytes).expect("token remains UTF-8");
        assert_eq!(codec().validate(&token), Err(JwtError::Invalid));
    }
}
