use aws_lc_rs::{
    rand::SystemRandom,
    signature::{
        RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
        RSA_PKCS1_SHA256, RSA_PSS_2048_8192_SHA256, RSA_PSS_2048_8192_SHA384,
        RSA_PSS_2048_8192_SHA512, RsaKeyPair, RsaParameters, RsaPublicKeyComponents,
        RsaSubjectPublicKey, UnparsedPublicKey,
    },
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RsaCryptoError {
    InvalidKey,
    InvalidSignature,
    SigningFailed,
    UnsupportedAlgorithm,
}

#[derive(Clone, Debug)]
pub(crate) struct RsaPublicKey {
    modulus: Vec<u8>,
    exponent: Vec<u8>,
}

impl RsaPublicKey {
    pub(crate) fn from_components(
        modulus: Vec<u8>,
        exponent: Vec<u8>,
    ) -> Result<Self, RsaCryptoError> {
        if modulus.is_empty() || exponent.is_empty() {
            return Err(RsaCryptoError::InvalidKey);
        }
        let key = Self { modulus, exponent };
        key.parsed(&RSA_PKCS1_2048_8192_SHA256)?;
        Ok(key)
    }

    pub(crate) fn verify(
        &self,
        algorithm: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), RsaCryptoError> {
        let algorithm = verification_algorithm(algorithm)?;
        self.parsed(algorithm)?
            .verify_sig(message, signature)
            .map_err(|_| RsaCryptoError::InvalidSignature)
    }

    fn parsed(
        &self,
        algorithm: &'static RsaParameters,
    ) -> Result<aws_lc_rs::signature::ParsedPublicKey, RsaCryptoError> {
        RsaPublicKeyComponents {
            n: self.modulus.as_slice(),
            e: self.exponent.as_slice(),
        }
        .to_parsed_public_key(algorithm)
        .map_err(|_| RsaCryptoError::InvalidKey)
    }
}

pub(crate) fn sign_rsa_pkcs1_sha256(
    private_key: &str,
    message: &[u8],
) -> Result<Vec<u8>, RsaCryptoError> {
    let (encoding, der) = decode_private_key(private_key)?;
    let key = match encoding {
        PrivateKeyEncoding::Pkcs8 => RsaKeyPair::from_pkcs8(&der),
        PrivateKeyEncoding::Pkcs1 => RsaKeyPair::from_der(&der),
        PrivateKeyEncoding::Unknown => {
            RsaKeyPair::from_pkcs8(&der).or_else(|_| RsaKeyPair::from_der(&der))
        }
    }
    .map_err(|_| RsaCryptoError::InvalidKey)?;
    let mut signature = vec![0_u8; key.public_modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        message,
        &mut signature,
    )
    .map_err(|_| RsaCryptoError::SigningFailed)?;
    Ok(signature)
}

pub(crate) fn verify_rsa_pkcs1_sha256(
    public_key: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<(), RsaCryptoError> {
    let der = decode_public_key(public_key)?;
    let key = RsaSubjectPublicKey::from_der(&der).map_err(|_| RsaCryptoError::InvalidKey)?;
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key.as_ref())
        .verify(message, signature)
        .map_err(|_| RsaCryptoError::InvalidSignature)
}

#[derive(Clone, Copy)]
enum PrivateKeyEncoding {
    Pkcs1,
    Pkcs8,
    Unknown,
}

fn decode_private_key(
    raw: &str,
) -> Result<(PrivateKeyEncoding, Zeroizing<Vec<u8>>), RsaCryptoError> {
    let trimmed = raw.trim();
    if trimmed.starts_with("-----BEGIN ") {
        let (label, der) =
            pem_rfc7468::decode_vec(trimmed.as_bytes()).map_err(|_| RsaCryptoError::InvalidKey)?;
        let encoding = match label {
            "PRIVATE KEY" => PrivateKeyEncoding::Pkcs8,
            "RSA PRIVATE KEY" => PrivateKeyEncoding::Pkcs1,
            _ => return Err(RsaCryptoError::InvalidKey),
        };
        return Ok((encoding, Zeroizing::new(der)));
    }

    let compact = Zeroizing::new(
        trimmed
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect::<String>(),
    );
    let der = STANDARD
        .decode(compact.as_bytes())
        .map_err(|_| RsaCryptoError::InvalidKey)?;
    Ok((PrivateKeyEncoding::Unknown, Zeroizing::new(der)))
}

fn decode_public_key(raw: &str) -> Result<Vec<u8>, RsaCryptoError> {
    let trimmed = raw.trim();
    if trimmed.starts_with("-----BEGIN ") {
        let (label, der) =
            pem_rfc7468::decode_vec(trimmed.as_bytes()).map_err(|_| RsaCryptoError::InvalidKey)?;
        if !matches!(label, "PUBLIC KEY" | "RSA PUBLIC KEY") {
            return Err(RsaCryptoError::InvalidKey);
        }
        return Ok(der);
    }

    let compact = trimmed
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>();
    STANDARD
        .decode(compact.as_bytes())
        .map_err(|_| RsaCryptoError::InvalidKey)
}

fn verification_algorithm(algorithm: &str) -> Result<&'static RsaParameters, RsaCryptoError> {
    match algorithm {
        "RS256" => Ok(&RSA_PKCS1_2048_8192_SHA256),
        "RS384" => Ok(&RSA_PKCS1_2048_8192_SHA384),
        "RS512" => Ok(&RSA_PKCS1_2048_8192_SHA512),
        "PS256" => Ok(&RSA_PSS_2048_8192_SHA256),
        "PS384" => Ok(&RSA_PSS_2048_8192_SHA384),
        "PS512" => Ok(&RSA_PSS_2048_8192_SHA512),
        _ => Err(RsaCryptoError::UnsupportedAlgorithm),
    }
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::{
        encoding::{AsDer as _, Pkcs8V1Der, PublicKeyX509Der},
        rsa::KeySize,
        signature::{
            KeyPair as _, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512, RSA_PSS_SHA256, RSA_PSS_SHA384,
            RSA_PSS_SHA512, RsaEncoding, RsaPublicKeyComponents,
        },
    };
    use pem_rfc7468::LineEnding;

    use super::*;

    #[test]
    fn pkcs1_and_pkcs8_private_keys_sign_for_both_public_key_encodings() {
        let key = RsaKeyPair::generate(KeySize::Rsa2048).expect("generate RSA key");
        let pkcs8: Pkcs8V1Der<'static> = key.as_der().expect("encode PKCS#8 private key");
        let private_info =
            pkcs8::PrivateKeyInfo::try_from(pkcs8.as_ref()).expect("parse generated PKCS#8");
        let spki: PublicKeyX509Der<'static> =
            key.public_key().as_der().expect("encode SPKI public key");

        let private_keys = [
            pem_rfc7468::encode_string("PRIVATE KEY", LineEnding::LF, pkcs8.as_ref())
                .expect("encode PKCS#8 PEM"),
            pem_rfc7468::encode_string("RSA PRIVATE KEY", LineEnding::LF, private_info.private_key)
                .expect("encode PKCS#1 PEM"),
            STANDARD.encode(pkcs8.as_ref()),
            STANDARD.encode(private_info.private_key),
        ];
        let public_keys = [
            pem_rfc7468::encode_string("PUBLIC KEY", LineEnding::LF, spki.as_ref())
                .expect("encode SPKI PEM"),
            pem_rfc7468::encode_string("RSA PUBLIC KEY", LineEnding::LF, key.public_key().as_ref())
                .expect("encode PKCS#1 public PEM"),
            STANDARD.encode(spki.as_ref()),
            STANDARD.encode(key.public_key().as_ref()),
        ];

        for private_key in private_keys {
            let signature = sign_rsa_pkcs1_sha256(&private_key, b"payment request")
                .expect("supported private key should sign");
            for public_key in &public_keys {
                verify_rsa_pkcs1_sha256(public_key, b"payment request", &signature)
                    .expect("supported public key should verify");
                assert_eq!(
                    verify_rsa_pkcs1_sha256(public_key, b"tampered", &signature),
                    Err(RsaCryptoError::InvalidSignature)
                );
            }
        }
    }

    #[test]
    fn oidc_rsa_components_verify_all_supported_algorithms() {
        let key = RsaKeyPair::generate(KeySize::Rsa2048).expect("generate RSA key");
        let components = RsaPublicKeyComponents::<Vec<u8>>::from(key.public_key());
        let public_key = RsaPublicKey::from_components(components.n, components.e)
            .expect("generated components should parse");
        let algorithms: [(&str, &'static dyn RsaEncoding); 6] = [
            ("RS256", &RSA_PKCS1_SHA256),
            ("RS384", &RSA_PKCS1_SHA384),
            ("RS512", &RSA_PKCS1_SHA512),
            ("PS256", &RSA_PSS_SHA256),
            ("PS384", &RSA_PSS_SHA384),
            ("PS512", &RSA_PSS_SHA512),
        ];
        let random = SystemRandom::new();

        for (name, signing_algorithm) in algorithms {
            let mut signature = vec![0_u8; key.public_modulus_len()];
            key.sign(signing_algorithm, &random, b"header.claims", &mut signature)
                .expect("sign OIDC input");
            public_key
                .verify(name, b"header.claims", &signature)
                .expect("matching OIDC algorithm should verify");
            signature[0] ^= 1;
            assert_eq!(
                public_key.verify(name, b"header.claims", &signature),
                Err(RsaCryptoError::InvalidSignature)
            );
        }
    }

    #[test]
    fn malformed_or_unsupported_key_material_fails_closed() {
        assert_eq!(
            sign_rsa_pkcs1_sha256("not base64", b"message"),
            Err(RsaCryptoError::InvalidKey)
        );
        assert_eq!(
            verify_rsa_pkcs1_sha256(
                "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----",
                b"message",
                b"signature",
            ),
            Err(RsaCryptoError::InvalidKey)
        );
        assert!(matches!(
            RsaPublicKey::from_components(Vec::new(), vec![1, 0, 1]),
            Err(RsaCryptoError::InvalidKey)
        ));

        let key = RsaKeyPair::generate(KeySize::Rsa2048).expect("generate RSA key");
        let components = RsaPublicKeyComponents::<Vec<u8>>::from(key.public_key());
        let public_key = RsaPublicKey::from_components(components.n, components.e)
            .expect("generated components should parse");
        assert_eq!(
            public_key.verify("HS256", b"message", b"signature"),
            Err(RsaCryptoError::UnsupportedAlgorithm)
        );
    }
}
