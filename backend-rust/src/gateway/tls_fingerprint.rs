use std::{collections::HashSet, fmt, sync::Arc};

use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, Error as RustlsError, ProtocolVersion,
    RootCertStore, SignatureScheme, SupportedCipherSuite, SupportedProtocolVersion,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::{SupportedKxGroup, aws_lc_rs},
    pki_types::{CertificateDer, ServerName, UnixTime},
    version::{TLS12, TLS13},
};
use serde_json::Value;
use sqlx::{PgPool, Row};

use crate::repository::AccountRecord;

const NODE24_CIPHER_SUITES: &[u16] = &[
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a,
    0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
];
const NODE24_CURVES: &[u16] = &[0x001d, 0x0017, 0x0018];
const NODE24_POINT_FORMATS: &[u16] = &[0];
const NODE24_SIGNATURE_ALGORITHMS: &[u16] = &[
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
];
const NODE24_SUPPORTED_VERSIONS: &[u16] = &[0x0304, 0x0303];
const NODE24_KEY_SHARE_GROUPS: &[u16] = &[0x001d];
const NODE24_PSK_MODES: &[u16] = &[1];
const NODE24_EXTENSIONS: &[u16] = &[0, 65037, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AccountTlsFingerprint {
    pub profile_id: i64,
}

impl AccountTlsFingerprint {
    pub(super) fn from_account(account: &AccountRecord) -> Result<Option<Self>, String> {
        if !account.platform.eq_ignore_ascii_case("anthropic")
            || !matches!(
                account.account_type.trim().to_ascii_lowercase().as_str(),
                "oauth" | "setup-token"
            )
        {
            return Ok(None);
        }
        let Some(enabled) = account.extra.get("enable_tls_fingerprint") else {
            return Ok(None);
        };
        let enabled = enabled
            .as_bool()
            .ok_or_else(|| "account extra.enable_tls_fingerprint must be a boolean".to_owned())?;
        if !enabled {
            return Ok(None);
        }
        let profile_id = match account.extra.get("tls_fingerprint_profile_id") {
            None | Some(Value::Null) => 0,
            Some(value) => value.as_i64().ok_or_else(|| {
                "account extra.tls_fingerprint_profile_id must be an integer".to_owned()
            })?,
        };
        if profile_id < 0 {
            return Err("account extra.tls_fingerprint_profile_id cannot be negative".to_owned());
        }
        Ok(Some(Self { profile_id }))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TlsFingerprintProfile {
    pub id: i64,
    pub name: String,
    pub enable_grease: bool,
    pub cipher_suites: Vec<u16>,
    pub curves: Vec<u16>,
    pub point_formats: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub alpn_protocols: Vec<String>,
    pub supported_versions: Vec<u16>,
    pub key_share_groups: Vec<u16>,
    pub psk_modes: Vec<u16>,
    pub extensions: Vec<u16>,
}

impl TlsFingerprintProfile {
    #[must_use]
    pub(super) fn node24() -> Self {
        Self {
            id: 0,
            name: "built-in Node.js 24".to_owned(),
            enable_grease: false,
            cipher_suites: NODE24_CIPHER_SUITES.to_vec(),
            curves: NODE24_CURVES.to_vec(),
            point_formats: NODE24_POINT_FORMATS.to_vec(),
            signature_algorithms: NODE24_SIGNATURE_ALGORITHMS.to_vec(),
            alpn_protocols: vec!["http/1.1".to_owned()],
            supported_versions: NODE24_SUPPORTED_VERSIONS.to_vec(),
            key_share_groups: NODE24_KEY_SHARE_GROUPS.to_vec(),
            psk_modes: NODE24_PSK_MODES.to_vec(),
            extensions: NODE24_EXTENSIONS.to_vec(),
        }
    }

    pub(super) async fn load(pool: &PgPool, profile_id: i64) -> Result<Self, String> {
        if profile_id == 0 {
            return Ok(Self::node24());
        }
        let row = sqlx::query(
            r"
SELECT id, name, enable_grease, cipher_suites, curves, point_formats,
       signature_algorithms, alpn_protocols, supported_versions,
       key_share_groups, psk_modes, extensions
FROM tls_fingerprint_profiles
WHERE id = $1
",
        )
        .bind(profile_id)
        .fetch_optional(pool)
        .await
        .map_err(|error| format!("load TLS fingerprint profile {profile_id}: {error}"))?
        .ok_or_else(|| format!("TLS fingerprint profile {profile_id} does not exist"))?;

        let defaults = Self::node24();
        Ok(Self {
            id: row
                .try_get("id")
                .map_err(|error| format!("decode TLS fingerprint profile id: {error}"))?,
            name: row
                .try_get("name")
                .map_err(|error| format!("decode TLS fingerprint profile name: {error}"))?,
            enable_grease: row.try_get("enable_grease").map_err(|error| {
                format!("decode TLS fingerprint profile enable_grease: {error}")
            })?,
            cipher_suites: json_u16s(&row, "cipher_suites", &defaults.cipher_suites)?,
            curves: json_u16s(&row, "curves", &defaults.curves)?,
            point_formats: json_u16s(&row, "point_formats", &defaults.point_formats)?,
            signature_algorithms: json_u16s(
                &row,
                "signature_algorithms",
                &defaults.signature_algorithms,
            )?,
            alpn_protocols: json_strings(&row, "alpn_protocols", &defaults.alpn_protocols)?,
            supported_versions: json_u16s(
                &row,
                "supported_versions",
                &defaults.supported_versions,
            )?,
            key_share_groups: json_u16s(&row, "key_share_groups", &defaults.key_share_groups)?,
            psk_modes: json_u16s(&row, "psk_modes", &defaults.psk_modes)?,
            extensions: json_u16s(&row, "extensions", &defaults.extensions)?,
        })
    }

    #[allow(clippy::too_many_lines)]
    pub(super) fn build(self) -> Result<BuiltTlsFingerprint, String> {
        let mut limitations = Vec::new();
        let mut provider = aws_lc_rs::default_provider();

        let (cipher_suites, unsupported_ciphers) =
            ordered_cipher_suites(&self.cipher_suites, aws_lc_rs::ALL_CIPHER_SUITES);
        if cipher_suites.is_empty() {
            return Err("TLS fingerprint profile has no rustls-supported cipher suite".to_owned());
        }
        if !unsupported_ciphers.is_empty() {
            limitations.push(format!(
                "rustls omitted unsupported cipher suites: {}",
                hex_list(&unsupported_ciphers)
            ));
        }
        provider.cipher_suites.clone_from(&cipher_suites);

        let (kx_groups, unsupported_groups) = ordered_kx_groups(
            &self.key_share_groups,
            &self.curves,
            aws_lc_rs::ALL_KX_GROUPS,
        );
        if kx_groups.is_empty() {
            return Err(
                "TLS fingerprint profile has no rustls-supported key exchange group".to_owned(),
            );
        }
        if !unsupported_groups.is_empty() {
            limitations.push(format!(
                "rustls omitted unsupported key exchange groups: {}",
                hex_list(&unsupported_groups)
            ));
        }
        if self.key_share_groups.len() > 1 {
            limitations.push(
                "rustls sends one initial key share and cannot reproduce multiple ordered key shares"
                    .to_owned(),
            );
        }
        provider.kx_groups.clone_from(&kx_groups);

        let versions = protocol_versions(&self.supported_versions)?;
        let roots = webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned()
            .collect::<RootCertStore>();
        let provider = Arc::new(provider);
        let base_verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
                .build()
                .map_err(|error| format!("build TLS certificate verifier: {error}"))?;
        let (signature_schemes, unsupported_signatures) = ordered_signature_schemes(
            &self.signature_algorithms,
            &base_verifier.supported_verify_schemes(),
        );
        if signature_schemes.is_empty() {
            return Err(
                "TLS fingerprint profile has no rustls-supported signature algorithm".to_owned(),
            );
        }
        if !unsupported_signatures.is_empty() {
            limitations.push(format!(
                "rustls omitted unsupported signature algorithms: {}",
                hex_list(&unsupported_signatures)
            ));
        }
        let verifier = Arc::new(OrderedServerCertVerifier {
            inner: base_verifier,
            schemes: signature_schemes.clone(),
        });
        let mut config = ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&versions)
            .map_err(|error| format!("configure TLS fingerprint versions: {error}"))?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        config.alpn_protocols = alpn_protocols(&self.alpn_protocols)?;

        if self.point_formats != NODE24_POINT_FORMATS {
            limitations.push(
                "rustls only advertises the uncompressed EC point format and ignores custom point formats"
                    .to_owned(),
            );
        }
        if self.psk_modes != NODE24_PSK_MODES {
            limitations.push(
                "rustls manages PSK modes through session resumption and cannot apply the requested PSK mode list"
                    .to_owned(),
            );
        }
        if self.enable_grease {
            limitations.push("rustls cannot reproduce the requested GREASE placement".to_owned());
        }
        limitations.push(
            "rustls controls extension contents but cannot reproduce the configured ClientHello extension order"
                .to_owned(),
        );
        if self.extensions.contains(&65037) {
            limitations.push(
                "rustls cannot emit the uTLS GREASE encrypted-client-hello extension".to_owned(),
            );
        }

        Ok(BuiltTlsFingerprint {
            profile_id: self.id,
            profile_name: self.name,
            config,
            limitations,
            cipher_suites,
            kx_groups: kx_groups
                .iter()
                .map(|group| u16::from(group.name()))
                .collect(),
            signature_schemes,
        })
    }
}

#[derive(Clone)]
pub(super) struct BuiltTlsFingerprint {
    pub profile_id: i64,
    pub profile_name: String,
    pub config: ClientConfig,
    pub limitations: Vec<String>,
    #[allow(dead_code)]
    pub cipher_suites: Vec<SupportedCipherSuite>,
    #[allow(dead_code)]
    pub kx_groups: Vec<u16>,
    #[allow(dead_code)]
    pub signature_schemes: Vec<SignatureScheme>,
}

fn json_u16s(
    row: &sqlx::postgres::PgRow,
    column: &str,
    defaults: &[u16],
) -> Result<Vec<u16>, String> {
    let value = row
        .try_get::<Option<Value>, _>(column)
        .map_err(|error| format!("decode TLS fingerprint profile {column}: {error}"))?;
    let Some(value) = value else {
        return Ok(defaults.to_vec());
    };
    let values = serde_json::from_value::<Vec<u16>>(value)
        .map_err(|error| format!("decode TLS fingerprint profile {column}: {error}"))?;
    Ok(if values.is_empty() {
        defaults.to_vec()
    } else {
        values
    })
}

fn json_strings(
    row: &sqlx::postgres::PgRow,
    column: &str,
    defaults: &[String],
) -> Result<Vec<String>, String> {
    let value = row
        .try_get::<Option<Value>, _>(column)
        .map_err(|error| format!("decode TLS fingerprint profile {column}: {error}"))?;
    let Some(value) = value else {
        return Ok(defaults.to_vec());
    };
    let values = serde_json::from_value::<Vec<String>>(value)
        .map_err(|error| format!("decode TLS fingerprint profile {column}: {error}"))?;
    Ok(if values.is_empty() {
        defaults.to_vec()
    } else {
        values
    })
}

fn ordered_cipher_suites(
    requested: &[u16],
    supported: &[SupportedCipherSuite],
) -> (Vec<SupportedCipherSuite>, Vec<u16>) {
    let mut selected = Vec::new();
    let mut unsupported = Vec::new();
    let mut seen = HashSet::new();
    for raw in requested.iter().copied().filter(|raw| seen.insert(*raw)) {
        if let Some(suite) = supported
            .iter()
            .find(|suite| u16::from(suite.suite()) == raw)
        {
            selected.push(*suite);
        } else {
            unsupported.push(raw);
        }
    }
    (selected, unsupported)
}

fn ordered_kx_groups(
    key_shares: &[u16],
    curves: &[u16],
    supported: &[&'static dyn SupportedKxGroup],
) -> (Vec<&'static dyn SupportedKxGroup>, Vec<u16>) {
    let mut selected = Vec::new();
    let mut unsupported = Vec::new();
    let mut seen = HashSet::new();
    for raw in key_shares
        .iter()
        .chain(curves)
        .copied()
        .filter(|raw| seen.insert(*raw))
    {
        if let Some(group) = supported
            .iter()
            .find(|group| u16::from(group.name()) == raw)
        {
            selected.push(*group);
        } else {
            unsupported.push(raw);
        }
    }
    (selected, unsupported)
}

fn protocol_versions(
    raw_versions: &[u16],
) -> Result<Vec<&'static SupportedProtocolVersion>, String> {
    let mut versions = Vec::new();
    let mut seen = HashSet::new();
    for raw in raw_versions.iter().copied().filter(|raw| seen.insert(*raw)) {
        versions.push(match ProtocolVersion::from(raw) {
            ProtocolVersion::TLSv1_3 => &TLS13,
            ProtocolVersion::TLSv1_2 => &TLS12,
            _ => {
                return Err(format!(
                    "TLS fingerprint profile requests unsupported TLS version 0x{raw:04x}"
                ));
            }
        });
    }
    if versions.is_empty() {
        return Err("TLS fingerprint profile must enable TLS 1.2 or TLS 1.3".to_owned());
    }
    Ok(versions)
}

fn ordered_signature_schemes(
    requested: &[u16],
    supported: &[SignatureScheme],
) -> (Vec<SignatureScheme>, Vec<u16>) {
    let mut selected = Vec::new();
    let mut unsupported = Vec::new();
    let mut seen = HashSet::new();
    for raw in requested.iter().copied().filter(|raw| seen.insert(*raw)) {
        let scheme = SignatureScheme::from(raw);
        if supported.contains(&scheme) {
            selected.push(scheme);
        } else {
            unsupported.push(raw);
        }
    }
    (selected, unsupported)
}

fn alpn_protocols(protocols: &[String]) -> Result<Vec<Vec<u8>>, String> {
    protocols
        .iter()
        .map(|protocol| {
            let protocol = protocol.trim();
            if !matches!(protocol, "h2" | "http/1.1") {
                return Err(format!(
                    "TLS fingerprint profile requests unsupported ALPN protocol {protocol:?}"
                ));
            }
            Ok(protocol.as_bytes().to_vec())
        })
        .collect()
}

fn hex_list(values: &[u16]) -> String {
    values
        .iter()
        .map(|value| format!("0x{value:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

#[derive(Clone)]
struct OrderedServerCertVerifier {
    inner: Arc<WebPkiServerVerifier>,
    schemes: Vec<SignatureScheme>,
}

impl fmt::Debug for OrderedServerCertVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OrderedServerCertVerifier")
            .field("schemes", &self.schemes)
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for OrderedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        self.inner.root_hint_subjects()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::repository::AccountRecord;

    use super::{AccountTlsFingerprint, TlsFingerprintProfile};

    fn account(platform: &str, account_type: &str, extra: serde_json::Value) -> AccountRecord {
        AccountRecord {
            id: 1,
            name: "test".to_owned(),
            notes: None,
            platform: platform.to_owned(),
            account_type: account_type.to_owned(),
            credentials: json!({}),
            extra,
            proxy_id: None,
            proxy: None,
            proxy_fallback_origin_id: None,
            concurrency: 1,
            load_factor: None,
            priority: 0,
            rate_multiplier: "1".to_owned(),
            status: "active".to_owned(),
            error_message: None,
            expires_at_unix_ms: None,
            auto_pause_on_expired: true,
            schedulable: true,
            rate_limit_reset_at_unix_ms: None,
            overload_until_unix_ms: None,
            temp_unschedulable_until_unix_ms: None,
            temp_unschedulable_reason: None,
            parent_account_id: None,
            quota_dimension: "daily".to_owned(),
            group_ids: vec![1],
        }
    }

    #[test]
    fn account_setting_is_scoped_and_strictly_typed() {
        let enabled = account(
            "anthropic",
            "oauth",
            json!({"enable_tls_fingerprint": true, "tls_fingerprint_profile_id": 17}),
        );
        assert_eq!(
            AccountTlsFingerprint::from_account(&enabled)
                .unwrap()
                .unwrap()
                .profile_id,
            17
        );
        let wrong_platform = account(
            "openai",
            "oauth",
            json!({"enable_tls_fingerprint": true, "tls_fingerprint_profile_id": 17}),
        );
        assert!(
            AccountTlsFingerprint::from_account(&wrong_platform)
                .unwrap()
                .is_none()
        );
        let malformed = account(
            "anthropic",
            "setup-token",
            json!({"enable_tls_fingerprint": "true"}),
        );
        assert!(AccountTlsFingerprint::from_account(&malformed).is_err());
    }

    #[test]
    fn node24_build_applies_supported_order_and_reports_protocol_gaps() {
        let built = TlsFingerprintProfile::node24().build().unwrap();
        let ciphers = built
            .cipher_suites
            .iter()
            .map(|suite| u16::from(suite.suite()))
            .collect::<Vec<_>>();
        assert_eq!(
            ciphers,
            vec![
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8
            ]
        );
        assert_eq!(built.kx_groups, vec![0x001d, 0x0017, 0x0018]);
        assert_eq!(built.config.alpn_protocols, vec![b"http/1.1".to_vec()]);
        assert!(
            built
                .limitations
                .iter()
                .any(|item| item.contains("extension order"))
        );
        assert!(built.limitations.iter().any(|item| item.contains("0xc009")));
    }

    #[test]
    fn unsafe_or_unusable_profile_values_fail_closed() {
        let mut profile = TlsFingerprintProfile::node24();
        profile.supported_versions = vec![0x0301];
        assert!(profile.build().is_err());

        let mut profile = TlsFingerprintProfile::node24();
        profile.cipher_suites = vec![0x002f, 0x0035];
        assert!(profile.build().is_err());

        let mut profile = TlsFingerprintProfile::node24();
        profile.alpn_protocols = vec!["acme-custom".to_owned()];
        assert!(profile.build().is_err());
    }
}
