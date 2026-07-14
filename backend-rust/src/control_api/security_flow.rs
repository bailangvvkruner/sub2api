use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use parking_lot::Mutex;
use rand::{Rng, RngCore, rngs::OsRng};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const CIPHER_PREFIX: &str = "v1";
const CIPHER_AAD: &[u8] = b"sub2api/totp-secret/v1";
const MAX_RATE_LIMIT_KEYS: usize = 20_000;

#[derive(Clone, Debug)]
pub(super) struct ActionRateLimiter {
    state: Arc<Mutex<RateLimiterState>>,
}

#[derive(Debug, Default)]
struct RateLimiterState {
    windows: HashMap<String, RateWindow>,
}

#[derive(Clone, Copy, Debug)]
struct RateWindow {
    started_at: Instant,
    requests: u32,
}

impl ActionRateLimiter {
    pub(super) fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(RateLimiterState::default())),
        }
    }

    pub(super) fn allow(&self, key: &str, limit: u32, window: Duration) -> bool {
        let now = Instant::now();
        let mut state = self.state.lock();
        if state.windows.len() >= MAX_RATE_LIMIT_KEYS && !state.windows.contains_key(key) {
            state
                .windows
                .retain(|_, entry| now.duration_since(entry.started_at) < window);
            if state.windows.len() >= MAX_RATE_LIMIT_KEYS
                && let Some(oldest) = state
                    .windows
                    .iter()
                    .min_by_key(|(_, entry)| entry.started_at)
                    .map(|(key, _)| key.clone())
            {
                state.windows.remove(&oldest);
            }
        }
        let entry = state.windows.entry(key.to_owned()).or_insert(RateWindow {
            started_at: now,
            requests: 0,
        });
        if now.duration_since(entry.started_at) >= window {
            *entry = RateWindow {
                started_at: now,
                requests: 0,
            };
        }
        if entry.requests >= limit {
            return false;
        }
        entry.requests = entry.requests.saturating_add(1);
        true
    }
}

pub(super) fn derive_security_key(jwt_secret: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"sub2api/rust/auth-security-key/v1\0");
    hasher.update(jwt_secret);
    hasher.finalize().into()
}

pub(super) fn decode_security_key(raw: &str) -> Result<[u8; 32], &'static str> {
    let decoded = hex::decode(raw.trim()).map_err(|_| "TOTP encryption key must be hex encoded")?;
    decoded
        .try_into()
        .map_err(|_| "TOTP encryption key must contain exactly 32 bytes")
}

pub(super) fn token_hash(key: &[u8; 32], purpose: &str, raw: &str) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .expect("HMAC accepts a 32-byte authentication key");
    mac.update(purpose.as_bytes());
    mac.update(&[0]);
    mac.update(raw.as_bytes());
    mac.finalize().into_bytes().into()
}

pub(super) fn random_token(prefix: &str) -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    format!("{prefix}{}", hex::encode(bytes))
}

pub(super) fn verification_code() -> String {
    format!("{:06}", OsRng.gen_range(0_u32..1_000_000))
}

pub(super) fn generate_totp_secret() -> String {
    let mut bytes = [0_u8; 20];
    OsRng.fill_bytes(&mut bytes);
    BASE32_NOPAD.encode(&bytes)
}

pub(super) fn totp_uri(email: &str, secret: &str) -> String {
    let mut url = url::Url::parse("otpauth://totp/Sub2API").expect("static otpauth URL is valid");
    url.set_path(&format!("Sub2API:{email}"));
    url.query_pairs_mut()
        .append_pair("secret", secret)
        .append_pair("issuer", "Sub2API")
        .append_pair("algorithm", "SHA1")
        .append_pair("digits", "6")
        .append_pair("period", "30");
    url.to_string()
}

pub(super) fn validate_totp(secret: &str, code: &str, unix_seconds: i64) -> bool {
    if code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let normalized = secret.trim().replace([' ', '-'], "").to_ascii_uppercase();
    let Ok(secret) = BASE32_NOPAD.decode(normalized.as_bytes()) else {
        return false;
    };
    if secret.len() < 16 || unix_seconds < 0 {
        return false;
    }
    let counter = u64::try_from(unix_seconds / 30).unwrap_or_default();
    for candidate in [
        counter.saturating_sub(1),
        counter,
        counter.saturating_add(1),
    ] {
        let generated = hotp(&secret, candidate);
        let formatted = format!("{generated:06}");
        if bool::from(formatted.as_bytes().ct_eq(code.as_bytes())) {
            return true;
        }
    }
    false
}

fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret)
        .expect("HMAC accepts arbitrary non-empty TOTP keys");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 0x0f);
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    binary % 1_000_000
}

pub(super) fn encrypt_secret(key: &[u8; 32], plaintext: &str) -> Result<String, &'static str> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "invalid TOTP encryption key")?;
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_bytes(),
                aad: CIPHER_AAD,
            },
        )
        .map_err(|_| "failed to encrypt TOTP secret")?;
    Ok(format!(
        "{CIPHER_PREFIX}.{}.{}",
        URL_SAFE_NO_PAD.encode(nonce),
        URL_SAFE_NO_PAD.encode(ciphertext)
    ))
}

pub(super) fn decrypt_secret(key: &[u8; 32], encoded: &str) -> Result<String, &'static str> {
    if !encoded.starts_with("v1.") {
        return decrypt_legacy_go_secret(key, encoded);
    }
    let mut parts = encoded.split('.');
    let version = parts.next().ok_or("invalid TOTP ciphertext")?;
    let nonce = parts.next().ok_or("invalid TOTP ciphertext")?;
    let ciphertext = parts.next().ok_or("invalid TOTP ciphertext")?;
    if version != CIPHER_PREFIX || parts.next().is_some() {
        return Err("invalid TOTP ciphertext");
    }
    let nonce = URL_SAFE_NO_PAD
        .decode(nonce)
        .map_err(|_| "invalid TOTP ciphertext")?;
    let nonce: [u8; 12] = nonce
        .try_into()
        .map_err(|_| "invalid TOTP ciphertext nonce")?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(ciphertext)
        .map_err(|_| "invalid TOTP ciphertext")?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "invalid TOTP encryption key")?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: CIPHER_AAD,
            },
        )
        .map_err(|_| "invalid TOTP ciphertext authentication tag")?;
    String::from_utf8(plaintext).map_err(|_| "TOTP plaintext is not UTF-8")
}

fn decrypt_legacy_go_secret(key: &[u8; 32], encoded: &str) -> Result<String, &'static str> {
    let value = STANDARD
        .decode(encoded)
        .map_err(|_| "invalid legacy TOTP ciphertext")?;
    if value.len() <= 12 {
        return Err("invalid legacy TOTP ciphertext");
    }
    let (nonce, ciphertext) = value.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "invalid TOTP encryption key")?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| "invalid legacy TOTP ciphertext authentication tag")?;
    String::from_utf8(plaintext).map_err(|_| "TOTP plaintext is not UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_gcm_ciphertext_round_trips_and_detects_tampering() {
        let key = derive_security_key(b"0123456789abcdef0123456789abcdef");
        let encrypted = encrypt_secret(&key, "JBSWY3DPEHPK3PXP").expect("encrypt");
        assert_eq!(
            decrypt_secret(&key, &encrypted).expect("decrypt"),
            "JBSWY3DPEHPK3PXP"
        );
        let mut tampered = encrypted.into_bytes();
        let last = tampered.last_mut().expect("ciphertext is not empty");
        *last = if *last == b'A' { b'B' } else { b'A' };
        assert!(decrypt_secret(&key, &String::from_utf8(tampered).expect("ASCII")).is_err());
    }

    #[test]
    fn decrypts_the_go_nonce_ciphertext_tag_format() {
        let key = [7_u8; 32];
        let cipher = Aes256Gcm::new_from_slice(&key).expect("key");
        let nonce = [9_u8; 12];
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), b"JBSWY3DPEHPK3PXP".as_slice())
            .expect("encrypt");
        let legacy = STANDARD.encode([nonce.as_slice(), ciphertext.as_slice()].concat());
        assert_eq!(
            decrypt_secret(&key, &legacy).expect("decrypt"),
            "JBSWY3DPEHPK3PXP"
        );
    }

    #[test]
    fn rfc_6238_sha1_vector_is_supported_with_six_digits() {
        let secret = BASE32_NOPAD.encode(b"12345678901234567890");
        assert!(validate_totp(&secret, "287082", 59));
        assert!(!validate_totp(&secret, "287083", 59));
    }

    #[test]
    fn action_limiter_is_bounded_per_key() {
        let limiter = ActionRateLimiter::new();
        assert!(limiter.allow("register:a", 2, Duration::from_mins(1)));
        assert!(limiter.allow("register:a", 2, Duration::from_mins(1)));
        assert!(!limiter.allow("register:a", 2, Duration::from_mins(1)));
        assert!(limiter.allow("register:b", 2, Duration::from_mins(1)));
    }
}
