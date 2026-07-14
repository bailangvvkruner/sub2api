use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use sqlx::PgPool;
use std::{env, sync::OnceLock};

const JWT_SECRET_KEY: &str = "jwt_secret";
const MIN_SECRET_BYTES: usize = 32;
const CONFIG_SECRET_PREFIX: &str = "enc:v1:";
const CONFIG_SECRET_AAD: &[u8] = b"sub2api/config-secret/v1";
const AES_GCM_NONCE_BYTES: usize = 12;
static CONFIG_ENCRYPTION_KEY: OnceLock<[u8; 32]> = OnceLock::new();

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedJwtSecret {
    value: String,
    pub created: bool,
    pub configured_value_mismatched: bool,
}

impl PersistedJwtSecret {
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.value
    }
}

/// Loads the cross-instance JWT secret from `PostgreSQL`, creating it exactly
/// once when this is a fresh installation.
///
/// # Errors
///
/// Returns an error for a short configured or persisted secret, random source
/// failure, or `PostgreSQL` failure.
pub async fn load_or_create_jwt_secret(
    pool: &PgPool,
    configured: Option<&str>,
) -> Result<PersistedJwtSecret> {
    let configured = configured.map(str::trim).filter(|value| !value.is_empty());
    if let Some(value) = configured {
        validate_secret(value, "configured JWT secret")?;
    }

    let candidate = configured.map_or_else(generate_secret, ToOwned::to_owned);
    let result = sqlx::query(
        r"
        INSERT INTO security_secrets (key, value)
        VALUES ($1, $2)
        ON CONFLICT (key) DO NOTHING
        ",
    )
    .bind(JWT_SECRET_KEY)
    .bind(&candidate)
    .execute(pool)
    .await
    .context("persist JWT secret")?;
    let value = sqlx::query_scalar::<_, String>(
        "SELECT value FROM security_secrets WHERE key = $1 LIMIT 1",
    )
    .bind(JWT_SECRET_KEY)
    .fetch_one(pool)
    .await
    .context("load persisted JWT secret")?;
    let value = value.trim().to_owned();
    validate_secret(&value, "persisted JWT secret")?;
    Ok(PersistedJwtSecret {
        configured_value_mismatched: configured.is_some_and(|configured| configured != value),
        created: result.rows_affected() == 1,
        value,
    })
}

fn validate_secret(value: &str, label: &str) -> Result<()> {
    if value.len() < MIN_SECRET_BYTES {
        bail!("{label} must be at least {MIN_SECRET_BYTES} bytes");
    }
    Ok(())
}

fn generate_secret() -> String {
    let mut bytes = [0_u8; MIN_SECRET_BYTES];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Encrypts one configuration secret using the persistent deployment key.
///
/// # Errors
///
/// Returns an error when `TOTP_ENCRYPTION_KEY` is missing/invalid or encryption fails.
pub fn encrypt_config_secret(plaintext: &str) -> Result<String> {
    if plaintext.is_empty() || plaintext.starts_with(CONFIG_SECRET_PREFIX) {
        return Ok(plaintext.to_owned());
    }
    encrypt_config_secret_with_key(plaintext, &config_encryption_key()?)
}

/// Decrypts a versioned configuration secret. Unversioned values are returned
/// unchanged so existing plaintext rows can be migrated on their next write.
///
/// # Errors
///
/// Returns an error when the encrypted value/key is invalid or authentication fails.
pub fn decrypt_config_secret(stored: &str) -> Result<String> {
    if !stored.starts_with(CONFIG_SECRET_PREFIX) {
        return Ok(stored.to_owned());
    }
    decrypt_config_secret_with_key(stored, &config_encryption_key()?)
}

/// Installs the deployment-wide configuration encryption key once.
///
/// # Errors
///
/// Returns an error when the value is invalid or a different key was already
/// installed in this process.
pub fn install_config_encryption_key(raw: &str) -> Result<()> {
    let key = parse_config_encryption_key(raw)?;
    if let Some(installed) = CONFIG_ENCRYPTION_KEY.get() {
        if installed == &key {
            return Ok(());
        }
        bail!("configuration encryption key is already initialized with a different value");
    }
    match CONFIG_ENCRYPTION_KEY.set(key) {
        Ok(()) => Ok(()),
        Err(key) if CONFIG_ENCRYPTION_KEY.get() == Some(&key) => Ok(()),
        Err(_) => bail!("configuration encryption key initialization raced with a different value"),
    }
}

/// Returns the configured deployment key when one is available.
///
/// # Errors
///
/// Returns an error when `TOTP_ENCRYPTION_KEY` is present but invalid.
pub fn optional_config_encryption_key() -> Result<Option<[u8; 32]>> {
    if let Some(key) = CONFIG_ENCRYPTION_KEY.get() {
        return Ok(Some(*key));
    }
    let raw = match env::var("TOTP_ENCRYPTION_KEY") {
        Ok(raw) if !raw.trim().is_empty() => raw,
        Ok(_) | Err(env::VarError::NotPresent) => return Ok(None),
        Err(error) => return Err(error).context("read TOTP_ENCRYPTION_KEY"),
    };
    parse_config_encryption_key(&raw).map(Some)
}

/// Returns the deployment-wide configuration encryption key.
///
/// # Errors
///
/// Returns an error when no key is configured or the configured value is invalid.
pub fn config_encryption_key() -> Result<[u8; 32]> {
    optional_config_encryption_key()?
        .context("TOTP_ENCRYPTION_KEY is required for encrypted configuration")
}

fn parse_config_encryption_key(raw: &str) -> Result<[u8; 32]> {
    let decoded = hex::decode(raw.trim())
        .context("TOTP_ENCRYPTION_KEY must contain 64 hexadecimal characters")?;
    decoded
        .try_into()
        .map_err(|_| anyhow!("TOTP_ENCRYPTION_KEY must decode to 32 bytes"))
}

fn encrypt_config_secret_with_key(plaintext: &str, key: &[u8; 32]) -> Result<String> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| anyhow!("configuration encryption key is invalid"))?;
    let mut nonce = [0_u8; AES_GCM_NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_bytes(),
                aad: CONFIG_SECRET_AAD,
            },
        )
        .map_err(|_| anyhow!("configuration secret encryption failed"))?;
    let mut encoded = Vec::with_capacity(nonce.len() + ciphertext.len());
    encoded.extend_from_slice(&nonce);
    encoded.extend_from_slice(&ciphertext);
    Ok(format!(
        "{CONFIG_SECRET_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(encoded)
    ))
}

fn decrypt_config_secret_with_key(stored: &str, key: &[u8; 32]) -> Result<String> {
    let encoded = stored
        .strip_prefix(CONFIG_SECRET_PREFIX)
        .ok_or_else(|| anyhow!("configuration secret version is unsupported"))?;
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .context("configuration secret encoding is invalid")?;
    if decoded.len() <= AES_GCM_NONCE_BYTES {
        bail!("configuration secret payload is truncated");
    }
    let (nonce, ciphertext) = decoded.split_at(AES_GCM_NONCE_BYTES);
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| anyhow!("configuration encryption key is invalid"))?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: CONFIG_SECRET_AAD,
            },
        )
        .map_err(|_| anyhow!("configuration secret authentication failed"))?;
    String::from_utf8(plaintext).context("configuration secret is not UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_secret_has_full_entropy_width() {
        let secret = generate_secret();
        assert_eq!(secret.len(), MIN_SECRET_BYTES * 2);
        assert!(validate_secret(&secret, "test").is_ok());
    }

    #[test]
    fn short_secrets_are_rejected() {
        let error = validate_secret("too-short", "configured JWT secret")
            .expect_err("short secrets must fail");
        assert!(error.to_string().contains("at least 32 bytes"));
    }

    #[test]
    fn configuration_secret_round_trip_is_authenticated() {
        let key = [0x42; 32];
        let encrypted = encrypt_config_secret_with_key("secret-value", &key).unwrap();
        assert!(encrypted.starts_with(CONFIG_SECRET_PREFIX));
        assert!(!encrypted.contains("secret-value"));
        assert_eq!(
            decrypt_config_secret_with_key(&encrypted, &key).unwrap(),
            "secret-value"
        );

        let mut tampered = encrypted.into_bytes();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(
            decrypt_config_secret_with_key(&String::from_utf8(tampered).unwrap(), &key).is_err()
        );
    }

    #[test]
    fn legacy_plaintext_is_read_without_requiring_a_key() {
        assert_eq!(
            decrypt_config_secret("legacy-secret").unwrap(),
            "legacy-secret"
        );
    }
}
