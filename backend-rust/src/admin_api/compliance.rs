use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sqlx::PgPool;

use super::AdminError;

pub(super) const VERSION: &str = "v2026.06.10";
pub(super) const DOCUMENT_PATH_ZH: &str = "docs/legal/admin-compliance.zh.md";
pub(super) const DOCUMENT_PATH_EN: &str = "docs/legal/admin-compliance.en.md";
pub(super) const DOCUMENT_URL_ZH: &str =
    "https://github.com/Wei-Shaw/sub2api/blob/main/docs/legal/admin-compliance.zh.md";
pub(super) const DOCUMENT_URL_EN: &str =
    "https://github.com/Wei-Shaw/sub2api/blob/main/docs/legal/admin-compliance.en.md";
pub(super) const ACK_PHRASE_ZH: &str = "我已阅读、理解并同意 Sub2API 部署与运营合规承诺";
pub(super) const ACK_PHRASE_EN: &str = "I have read, understood, and agree to the Sub2API Deployment and Operation Compliance Commitment";

const SETTING_KEY_PREFIX: &str = "admin_compliance_acknowledgement";

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Acknowledgement {
    version: String,
    document_zh: String,
    document_en: String,
    admin_user_id: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ip_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user_agent: Option<String>,
    accepted_at: DateTime<Utc>,
}

pub(super) async fn is_acknowledged(pool: &PgPool, admin_user_id: i64) -> Result<bool, AdminError> {
    Ok(load_current_acknowledgement(pool, admin_user_id)
        .await?
        .is_some())
}

pub(super) async fn status(pool: &PgPool, admin_user_id: i64) -> Result<Value, AdminError> {
    let acknowledgement = load_current_acknowledgement(pool, admin_user_id).await?;
    Ok(status_value(acknowledgement))
}

pub(super) async fn accept(
    pool: &PgPool,
    admin_user_id: i64,
    payload: &Value,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
) -> Result<Value, AdminError> {
    let phrase = payload
        .get("phrase")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    let language = payload
        .get("language")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if phrase != expected_phrase(language) {
        return Err(AdminError::BadRequest(
            "confirmation phrase does not match".to_owned(),
        ));
    }

    let acknowledgement = Acknowledgement {
        version: VERSION.to_owned(),
        document_zh: DOCUMENT_PATH_ZH.to_owned(),
        document_en: DOCUMENT_PATH_EN.to_owned(),
        admin_user_id,
        ip_address: nonempty(ip_address),
        user_agent: nonempty(user_agent),
        accepted_at: Utc::now(),
    };
    let encoded = serde_json::to_string(&acknowledgement).map_err(|error| {
        AdminError::Probe(format!("encode compliance acknowledgement: {error}"))
    })?;
    sqlx::query(
        "INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, NOW()) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
    )
    .bind(acknowledgement_key(admin_user_id))
    .bind(encoded)
    .execute(pool)
    .await?;

    Ok(status_value(Some(acknowledgement)))
}

pub(super) fn required_metadata() -> Value {
    json!({
        "version": VERSION,
        "document_path_zh": DOCUMENT_PATH_ZH,
        "document_path_en": DOCUMENT_PATH_EN,
        "document_url_zh": DOCUMENT_URL_ZH,
        "document_url_en": DOCUMENT_URL_EN,
    })
}

async fn load_current_acknowledgement(
    pool: &PgPool,
    admin_user_id: i64,
) -> Result<Option<Acknowledgement>, AdminError> {
    let raw = sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key = $1")
        .bind(acknowledgement_key(admin_user_id))
        .fetch_optional(pool)
        .await?;
    let acknowledgement = raw
        .as_deref()
        .and_then(|raw| serde_json::from_str::<Acknowledgement>(raw).ok())
        .filter(|acknowledgement| {
            acknowledgement.version == VERSION && acknowledgement.admin_user_id == admin_user_id
        });
    Ok(acknowledgement)
}

fn status_value(acknowledgement: Option<Acknowledgement>) -> Value {
    let mut status = Map::from_iter([
        (
            "required".to_owned(),
            Value::Bool(acknowledgement.is_none()),
        ),
        ("version".to_owned(), Value::String(VERSION.to_owned())),
        (
            "document_path_zh".to_owned(),
            Value::String(DOCUMENT_PATH_ZH.to_owned()),
        ),
        (
            "document_path_en".to_owned(),
            Value::String(DOCUMENT_PATH_EN.to_owned()),
        ),
        (
            "document_url_zh".to_owned(),
            Value::String(DOCUMENT_URL_ZH.to_owned()),
        ),
        (
            "document_url_en".to_owned(),
            Value::String(DOCUMENT_URL_EN.to_owned()),
        ),
        (
            "ack_phrase_zh".to_owned(),
            Value::String(ACK_PHRASE_ZH.to_owned()),
        ),
        (
            "ack_phrase_en".to_owned(),
            Value::String(ACK_PHRASE_EN.to_owned()),
        ),
    ]);
    if let Some(acknowledgement) = acknowledgement {
        status.insert("acknowledgement".to_owned(), json!(acknowledgement));
    }
    Value::Object(status)
}

fn expected_phrase(language: &str) -> &'static str {
    if language.trim().to_ascii_lowercase().starts_with("zh") {
        ACK_PHRASE_ZH
    } else {
        ACK_PHRASE_EN
    }
}

fn acknowledgement_key(admin_user_id: i64) -> String {
    format!("{SETTING_KEY_PREFIX}:{admin_user_id}")
}

fn nonempty(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn status_contract_is_versioned_and_user_scoped() {
        let acknowledgement = Acknowledgement {
            version: VERSION.to_owned(),
            document_zh: DOCUMENT_PATH_ZH.to_owned(),
            document_en: DOCUMENT_PATH_EN.to_owned(),
            admin_user_id: 42,
            ip_address: Some("127.0.0.1".to_owned()),
            user_agent: None,
            accepted_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
        };
        let status = status_value(Some(acknowledgement));
        assert_eq!(status["required"], false);
        assert_eq!(status["version"], VERSION);
        assert_eq!(status["acknowledgement"]["admin_user_id"], 42);
        assert_eq!(
            acknowledgement_key(42),
            "admin_compliance_acknowledgement:42"
        );
    }

    #[test]
    fn confirmation_phrase_follows_normalized_language() {
        assert_eq!(expected_phrase("zh-CN"), ACK_PHRASE_ZH);
        assert_eq!(expected_phrase(" en "), ACK_PHRASE_EN);
        assert!(status_value(None).get("acknowledgement").is_none());
    }
}
