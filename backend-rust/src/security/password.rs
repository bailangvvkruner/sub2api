use anyhow::{Context, Result, bail, ensure};
use blowfish::Blowfish;
use rand::{RngCore, rngs::OsRng};
use subtle::ConstantTimeEq;

const BCRYPT_ALPHABET: &[u8; 64] =
    b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const MAGIC_CIPHER_DATA: &[u8; 24] = b"OrpheanBeholderScryDoubt";
const DEFAULT_COST: u32 = 10;
const MIN_COST: u32 = 4;
const MAX_COST: u32 = 31;
const MAX_PASSWORD_BYTES: usize = 72;

/// Hashes a password using the bcrypt format accepted by the Go backend.
///
/// # Errors
///
/// Returns an error for passwords longer than bcrypt's 72-byte limit or an
/// invalid work factor.
pub fn hash_password(password: &str) -> Result<String> {
    hash_password_with_cost(password.as_bytes(), DEFAULT_COST)
}

/// Verifies `$2a$`, `$2b$`, or `$2y$` bcrypt hashes in constant time.
///
/// # Errors
///
/// Returns an error when the encoded hash is malformed or uses an unsupported
/// cost. A valid hash with the wrong password returns `Ok(false)`.
pub fn verify_password(password: &str, encoded: &str) -> Result<bool> {
    ensure!(
        password.len() <= MAX_PASSWORD_BYTES,
        "password exceeds 72 bytes"
    );
    let parsed = ParsedHash::parse(encoded)?;
    let actual = bcrypt_hash(password.as_bytes(), parsed.cost, &parsed.salt)?;
    Ok(bool::from(actual.ct_eq(parsed.hash.as_slice())))
}

fn hash_password_with_cost(password: &[u8], cost: u32) -> Result<String> {
    ensure!(
        password.len() <= MAX_PASSWORD_BYTES,
        "password exceeds 72 bytes"
    );
    validate_cost(cost)?;
    let mut salt = [0_u8; 16];
    OsRng.fill_bytes(&mut salt);
    encode_hash(password, cost, &salt, "2b")
}

fn encode_hash(password: &[u8], cost: u32, salt: &[u8; 16], version: &str) -> Result<String> {
    let digest = bcrypt_hash(password, cost, salt)?;
    Ok(format!(
        "${version}${cost:02}${}{}",
        bcrypt_base64_encode(salt),
        bcrypt_base64_encode(&digest)
    ))
}

fn bcrypt_hash(password: &[u8], cost: u32, salt: &[u8; 16]) -> Result<Vec<u8>> {
    validate_cost(cost)?;
    ensure!(
        password.len() <= MAX_PASSWORD_BYTES,
        "password exceeds 72 bytes"
    );

    let mut key = Vec::with_capacity(password.len() + 1);
    key.extend_from_slice(password);
    key.push(0);

    let mut cipher = Blowfish::bc_init_state();
    cipher.salted_expand_key(salt, &key);
    for _ in 0..(1_u64 << cost) {
        cipher.bc_expand_key(&key);
        cipher.bc_expand_key(salt);
    }

    let mut words = [0_u32; 6];
    for (word, bytes) in words.iter_mut().zip(MAGIC_CIPHER_DATA.chunks_exact(4)) {
        *word = u32::from_be_bytes(bytes.try_into().expect("four-byte bcrypt word"));
    }
    for _ in 0..64 {
        for pair in words.chunks_exact_mut(2) {
            let encrypted = cipher.bc_encrypt([pair[0], pair[1]]);
            pair.copy_from_slice(&encrypted);
        }
    }

    let mut output = Vec::with_capacity(23);
    for word in words {
        output.extend_from_slice(&word.to_be_bytes());
    }
    output.truncate(23);
    Ok(output)
}

fn validate_cost(cost: u32) -> Result<()> {
    if !(MIN_COST..=MAX_COST).contains(&cost) {
        bail!("bcrypt cost must be between {MIN_COST} and {MAX_COST}");
    }
    Ok(())
}

struct ParsedHash {
    cost: u32,
    salt: [u8; 16],
    hash: Vec<u8>,
}

impl ParsedHash {
    fn parse(encoded: &str) -> Result<Self> {
        ensure!(encoded.len() == 60, "bcrypt hash must be 60 characters");
        let bytes = encoded.as_bytes();
        ensure!(bytes[0] == b'$', "invalid bcrypt prefix");
        ensure!(bytes[1] == b'2', "unsupported bcrypt major version");
        ensure!(
            matches!(bytes[2], b'a' | b'b' | b'y'),
            "unsupported bcrypt minor version"
        );
        ensure!(
            bytes[3] == b'$' && bytes[6] == b'$',
            "invalid bcrypt separators"
        );
        let cost = encoded[4..6]
            .parse::<u32>()
            .context("invalid bcrypt cost")?;
        validate_cost(cost)?;

        let decoded_salt = bcrypt_base64_decode(&encoded[7..29])?;
        ensure!(
            decoded_salt.len() == 16,
            "bcrypt salt must decode to 16 bytes"
        );
        let mut salt = [0_u8; 16];
        salt.copy_from_slice(&decoded_salt);
        let hash = bcrypt_base64_decode(&encoded[29..])?;
        ensure!(hash.len() == 23, "bcrypt digest must decode to 23 bytes");
        Ok(Self { cost, salt, hash })
    }
}

fn bcrypt_base64_encode(input: &[u8]) -> String {
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let first = chunk[0];
        output.push(BCRYPT_ALPHABET[(first >> 2) as usize] as char);
        let second_index = (first & 0x03) << 4;
        if chunk.len() == 1 {
            output.push(BCRYPT_ALPHABET[second_index as usize] as char);
            break;
        }

        let second = chunk[1];
        output.push(BCRYPT_ALPHABET[(second_index | (second >> 4)) as usize] as char);
        let third_index = (second & 0x0f) << 2;
        if chunk.len() == 2 {
            output.push(BCRYPT_ALPHABET[third_index as usize] as char);
            break;
        }

        let third = chunk[2];
        output.push(BCRYPT_ALPHABET[(third_index | (third >> 6)) as usize] as char);
        output.push(BCRYPT_ALPHABET[(third & 0x3f) as usize] as char);
    }
    output
}

fn bcrypt_base64_decode(input: &str) -> Result<Vec<u8>> {
    let mut values = Vec::with_capacity(input.len());
    for byte in input.bytes() {
        let value = BCRYPT_ALPHABET
            .iter()
            .position(|candidate| *candidate == byte)
            .with_context(|| format!("invalid bcrypt base64 character {byte:?}"))?;
        values.push(u8::try_from(value).expect("bcrypt alphabet index fits u8"));
    }

    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    for chunk in values.chunks(4) {
        ensure!(chunk.len() >= 2, "invalid bcrypt base64 length");
        output.push((chunk[0] << 2) | (chunk[1] >> 4));
        if chunk.len() >= 3 {
            output.push((chunk[1] << 4) | (chunk[2] >> 2));
        }
        if chunk.len() == 4 {
            output.push((chunk[2] << 6) | chunk[3]);
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_go_bcrypt_test_vector() {
        let salt = bcrypt_base64_decode("XajjQvNhvvRt5GSeFk1xFe")
            .expect("Go bcrypt vector salt should decode");
        let salt: [u8; 16] = salt.try_into().expect("salt should have 16 bytes");
        let encoded = encode_hash(b"allmine", 10, &salt, "2a").expect("bcrypt vector should hash");
        assert_eq!(
            encoded,
            "$2a$10$XajjQvNhvvRt5GSeFk1xFeyqRrsxkhBkUiQeg0dt.wU1qD4aFDcga"
        );
    }

    #[test]
    fn verifies_existing_go_hashes() {
        let encoded = "$2a$10$LK9XRuhNxHHCvjX3tdkRKei1QiCDUKrJRhZv7WWZPuQGRUM92rOUa";
        assert!(verify_password("passw0rd", encoded).expect("valid Go bcrypt hash"));
        assert!(!verify_password("wrong", encoded).expect("valid Go bcrypt hash"));
    }

    #[test]
    fn generated_hash_round_trips() {
        let encoded = hash_password_with_cost(b"secret-value", 4).expect("password should hash");
        assert!(verify_password("secret-value", &encoded).expect("hash should verify"));
        assert!(!verify_password("other-value", &encoded).expect("hash should verify"));
    }
}
