//! Domain-aware implementations for administrator resources that cannot use
//! the generic table CRUD fallback without changing the Go API contract.

use std::collections::BTreeMap;

use chrono::{DateTime, Datelike, Local, Timelike, Utc};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sqlx::{PgPool, Postgres, Row, Transaction};

use super::{AdminError, AdminIdentity, Patch, compat::required_path_id};

const INVALIDATION_CHANNEL: &str = "sub2api_auth_cache_invalidation";
const MAX_PAGE_SIZE: i64 = 1_000;
const MAX_CRON_SEARCH_MINUTES: i64 = 8 * 366 * 24 * 60;

const RESOURCE_HANDLERS: [&str; 23] = [
    "h.Admin.ErrorPassthrough.List",
    "h.Admin.ErrorPassthrough.GetByID",
    "h.Admin.ErrorPassthrough.Create",
    "h.Admin.ErrorPassthrough.Update",
    "h.Admin.ErrorPassthrough.Delete",
    "h.Admin.Promo.List",
    "h.Admin.Promo.GetByID",
    "h.Admin.Promo.Create",
    "h.Admin.Promo.Update",
    "h.Admin.Promo.Delete",
    "h.Admin.Redeem.List",
    "h.Admin.Redeem.GetByID",
    "h.Admin.Redeem.Delete",
    "h.Admin.ScheduledTest.Create",
    "h.Admin.ScheduledTest.Update",
    "h.Admin.ScheduledTest.Delete",
    "h.Admin.Subscription.List",
    "h.Admin.Subscription.GetByID",
    "h.Admin.TLSFingerprintProfile.List",
    "h.Admin.TLSFingerprintProfile.GetByID",
    "h.Admin.TLSFingerprintProfile.Create",
    "h.Admin.TLSFingerprintProfile.Update",
    "h.Admin.TLSFingerprintProfile.Delete",
];

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the compatibility dispatcher mirrors the fixed administrator resource route table"
)]
pub(super) async fn dispatch(
    pool: &PgPool,
    actor: &AdminIdentity,
    handler: &str,
    path: &str,
    query: &BTreeMap<String, String>,
    payload: Value,
) -> Option<Result<Value, AdminError>> {
    if !RESOURCE_HANDLERS.contains(&handler) {
        return None;
    }
    let result = match handler {
        "h.Admin.ErrorPassthrough.List" => list_error_rules(pool).await,
        "h.Admin.ErrorPassthrough.GetByID" => {
            get_error_rule(pool, required_path_id(path, "error passthrough rule").ok()?).await
        }
        "h.Admin.ErrorPassthrough.Create" => create_error_rule(pool, actor, payload).await,
        "h.Admin.ErrorPassthrough.Update" => {
            update_error_rule(
                pool,
                actor,
                required_path_id(path, "error passthrough rule").ok()?,
                payload,
            )
            .await
        }
        "h.Admin.ErrorPassthrough.Delete" => {
            delete_error_rule(
                pool,
                actor,
                required_path_id(path, "error passthrough rule").ok()?,
            )
            .await
        }
        "h.Admin.Promo.List" => list_promo_codes(pool, query).await,
        "h.Admin.Promo.GetByID" => {
            get_promo_code(pool, required_path_id(path, "promo code").ok()?).await
        }
        "h.Admin.Promo.Create" => create_promo_code(pool, actor, payload).await,
        "h.Admin.Promo.Update" => {
            update_promo_code(
                pool,
                actor,
                required_path_id(path, "promo code").ok()?,
                payload,
            )
            .await
        }
        "h.Admin.Promo.Delete" => {
            delete_promo_code(pool, actor, required_path_id(path, "promo code").ok()?).await
        }
        "h.Admin.Redeem.List" => list_redeem_codes(pool, query).await,
        "h.Admin.Redeem.GetByID" => {
            get_redeem_code(pool, required_path_id(path, "redeem code").ok()?).await
        }
        "h.Admin.Redeem.Delete" => {
            delete_redeem_code(pool, actor, required_path_id(path, "redeem code").ok()?).await
        }
        "h.Admin.ScheduledTest.Create" => create_scheduled_test(pool, actor, payload).await,
        "h.Admin.ScheduledTest.Update" => {
            update_scheduled_test(
                pool,
                actor,
                required_path_id(path, "scheduled test plan").ok()?,
                payload,
            )
            .await
        }
        "h.Admin.ScheduledTest.Delete" => {
            delete_scheduled_test(
                pool,
                actor,
                required_path_id(path, "scheduled test plan").ok()?,
            )
            .await
        }
        "h.Admin.Subscription.List" => list_subscriptions(pool, query).await,
        "h.Admin.Subscription.GetByID" => {
            get_subscription(pool, required_path_id(path, "subscription").ok()?).await
        }
        "h.Admin.TLSFingerprintProfile.List" => list_tls_profiles(pool).await,
        "h.Admin.TLSFingerprintProfile.GetByID" => {
            get_tls_profile(
                pool,
                required_path_id(path, "TLS fingerprint profile").ok()?,
            )
            .await
        }
        "h.Admin.TLSFingerprintProfile.Create" => create_tls_profile(pool, actor, payload).await,
        "h.Admin.TLSFingerprintProfile.Update" => {
            update_tls_profile(
                pool,
                actor,
                required_path_id(path, "TLS fingerprint profile").ok()?,
                payload,
            )
            .await
        }
        "h.Admin.TLSFingerprintProfile.Delete" => {
            delete_tls_profile(
                pool,
                actor,
                required_path_id(path, "TLS fingerprint profile").ok()?,
            )
            .await
        }
        _ => unreachable!("RESOURCE_HANDLERS and resource dispatch match must stay aligned"),
    };
    Some(result)
}

// --- Error passthrough rules -------------------------------------------------

#[allow(
    clippy::struct_excessive_bools,
    reason = "the request mirrors independent legacy error-passthrough switches"
)]
#[derive(Debug, Deserialize)]
struct CreateErrorRuleRequest {
    name: Option<String>,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    priority: i32,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    error_codes: Vec<i32>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    keywords: Vec<String>,
    #[serde(default = "default_match_mode")]
    match_mode: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    platforms: Vec<String>,
    #[serde(default = "default_true")]
    passthrough_code: bool,
    #[serde(default)]
    response_code: Option<i32>,
    #[serde(default = "default_true")]
    passthrough_body: bool,
    #[serde(default)]
    custom_message: Option<String>,
    #[serde(default)]
    skip_monitoring: bool,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct UpdateErrorRuleRequest {
    #[serde(default)]
    name: Patch<String>,
    #[serde(default)]
    enabled: Patch<bool>,
    #[serde(default)]
    priority: Patch<i32>,
    #[serde(default)]
    error_codes: Patch<Vec<i32>>,
    #[serde(default)]
    keywords: Patch<Vec<String>>,
    #[serde(default)]
    match_mode: Patch<String>,
    #[serde(default)]
    platforms: Patch<Vec<String>>,
    #[serde(default)]
    passthrough_code: Patch<bool>,
    #[serde(default)]
    response_code: Patch<i32>,
    #[serde(default)]
    passthrough_body: Patch<bool>,
    #[serde(default)]
    custom_message: Patch<String>,
    #[serde(default)]
    skip_monitoring: Patch<bool>,
    #[serde(default)]
    description: Patch<String>,
}

#[allow(
    clippy::struct_excessive_bools,
    reason = "the persisted compatibility state mirrors independent error-passthrough switches"
)]
#[derive(Debug)]
struct ErrorRuleState {
    name: String,
    enabled: bool,
    priority: i32,
    error_codes: Vec<i32>,
    keywords: Vec<String>,
    match_mode: String,
    platforms: Vec<String>,
    passthrough_code: bool,
    response_code: Option<i32>,
    passthrough_body: bool,
    custom_message: Option<String>,
    skip_monitoring: bool,
    description: Option<String>,
}

const ERROR_RULE_JSON: &str = r"
to_jsonb(rule)
|| jsonb_build_object(
     'error_codes', COALESCE(rule.error_codes, '[]'::jsonb),
     'keywords', COALESCE(rule.keywords, '[]'::jsonb),
     'platforms', COALESCE(rule.platforms, '[]'::jsonb)
   )
";

async fn list_error_rules(pool: &PgPool) -> Result<Value, AdminError> {
    let sql = format!(
        "SELECT {ERROR_RULE_JSON} FROM error_passthrough_rules rule ORDER BY rule.priority, rule.id"
    );
    Ok(Value::Array(
        sqlx::query_scalar::<_, Value>(&sql).fetch_all(pool).await?,
    ))
}

async fn get_error_rule(pool: &PgPool, id: i64) -> Result<Value, AdminError> {
    let sql = format!("SELECT {ERROR_RULE_JSON} FROM error_passthrough_rules rule WHERE id = $1");
    sqlx::query_scalar::<_, Value>(&sql)
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(AdminError::NotFound("error passthrough rule"))
}

async fn create_error_rule(
    pool: &PgPool,
    actor: &AdminIdentity,
    payload: Value,
) -> Result<Value, AdminError> {
    let request: CreateErrorRuleRequest = parse_payload(payload)?;
    let state = ErrorRuleState {
        name: request.name.unwrap_or_default(),
        enabled: request.enabled,
        priority: request.priority,
        error_codes: request.error_codes,
        keywords: normalize_string_list(request.keywords, 200, 500)?,
        match_mode: request.match_mode,
        platforms: normalize_platforms(request.platforms)?,
        passthrough_code: request.passthrough_code,
        response_code: request.response_code,
        passthrough_body: request.passthrough_body,
        custom_message: trim_optional(request.custom_message, 4_000),
        skip_monitoring: request.skip_monitoring,
        description: trim_optional(request.description, 4_000),
    };
    validate_error_rule(&state)?;
    let mut transaction = pool.begin().await?;
    let id = insert_error_rule(&mut transaction, &state).await?;
    notify_settings(&mut transaction).await?;
    transaction.commit().await?;
    let value = get_error_rule(pool, id).await?;
    audit_mutation(actor, "create", "error_passthrough_rule", id);
    Ok(value)
}

async fn update_error_rule(
    pool: &PgPool,
    actor: &AdminIdentity,
    id: i64,
    payload: Value,
) -> Result<Value, AdminError> {
    let request: UpdateErrorRuleRequest = parse_payload(payload)?;
    let mut transaction = pool.begin().await?;
    let mut state = load_error_rule(&mut transaction, id).await?;
    apply_required_string_patch(&mut state.name, request.name);
    apply_copy_patch(&mut state.enabled, &request.enabled);
    apply_copy_patch(&mut state.priority, &request.priority);
    apply_vec_patch(&mut state.error_codes, request.error_codes);
    apply_string_vec_patch(&mut state.keywords, request.keywords, "keywords", 200, 500)?;
    apply_required_string_patch(&mut state.match_mode, request.match_mode);
    match request.platforms {
        Patch::Value(value) => state.platforms = normalize_platforms(value)?,
        Patch::Null | Patch::Missing => {}
    }
    apply_copy_patch(&mut state.passthrough_code, &request.passthrough_code);
    apply_nullable_copy_patch(&mut state.response_code, &request.response_code);
    apply_copy_patch(&mut state.passthrough_body, &request.passthrough_body);
    apply_nullable_string_patch(&mut state.custom_message, request.custom_message, 4_000);
    apply_copy_patch(&mut state.skip_monitoring, &request.skip_monitoring);
    apply_nullable_string_patch(&mut state.description, request.description, 4_000);
    validate_error_rule(&state)?;
    persist_error_rule(&mut transaction, id, &state).await?;
    notify_settings(&mut transaction).await?;
    transaction.commit().await?;
    let value = get_error_rule(pool, id).await?;
    audit_mutation(actor, "update", "error_passthrough_rule", id);
    Ok(value)
}

async fn delete_error_rule(
    pool: &PgPool,
    actor: &AdminIdentity,
    id: i64,
) -> Result<Value, AdminError> {
    let mut transaction = pool.begin().await?;
    let deleted = sqlx::query("DELETE FROM error_passthrough_rules WHERE id = $1")
        .bind(id)
        .execute(&mut *transaction)
        .await?;
    if deleted.rows_affected() == 0 {
        return Err(AdminError::NotFound("error passthrough rule"));
    }
    notify_settings(&mut transaction).await?;
    transaction.commit().await?;
    audit_mutation(actor, "delete", "error_passthrough_rule", id);
    Ok(json!({ "message": "Rule deleted successfully" }))
}

async fn insert_error_rule(
    transaction: &mut Transaction<'_, Postgres>,
    state: &ErrorRuleState,
) -> Result<i64, AdminError> {
    Ok(sqlx::query_scalar::<_, i64>(
        r"
INSERT INTO error_passthrough_rules (
    name, enabled, priority, error_codes, keywords, match_mode, platforms,
    passthrough_code, response_code, passthrough_body, custom_message,
    skip_monitoring, description, created_at, updated_at
) VALUES ($1,$2,$3,$4::jsonb,$5::jsonb,$6,$7::jsonb,$8,$9,$10,$11,$12,$13,NOW(),NOW())
RETURNING id
",
    )
    .bind(&state.name)
    .bind(state.enabled)
    .bind(state.priority)
    .bind(json_string(&state.error_codes)?)
    .bind(json_string(&state.keywords)?)
    .bind(&state.match_mode)
    .bind(json_string(&state.platforms)?)
    .bind(state.passthrough_code)
    .bind(state.response_code)
    .bind(state.passthrough_body)
    .bind(&state.custom_message)
    .bind(state.skip_monitoring)
    .bind(&state.description)
    .fetch_one(&mut **transaction)
    .await?)
}

async fn load_error_rule(
    transaction: &mut Transaction<'_, Postgres>,
    id: i64,
) -> Result<ErrorRuleState, AdminError> {
    let row = sqlx::query(
        r"
SELECT name, enabled, priority, COALESCE(error_codes, '[]'::jsonb)::text AS error_codes,
       COALESCE(keywords, '[]'::jsonb)::text AS keywords, match_mode,
       COALESCE(platforms, '[]'::jsonb)::text AS platforms,
       passthrough_code, response_code, passthrough_body,
       custom_message, skip_monitoring, description
FROM error_passthrough_rules WHERE id = $1 FOR UPDATE
",
    )
    .bind(id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(AdminError::NotFound("error passthrough rule"))?;
    Ok(ErrorRuleState {
        name: row.try_get("name")?,
        enabled: row.try_get("enabled")?,
        priority: row.try_get("priority")?,
        error_codes: parse_json_column(&row.try_get::<String, _>("error_codes")?)?,
        keywords: parse_json_column(&row.try_get::<String, _>("keywords")?)?,
        match_mode: row.try_get("match_mode")?,
        platforms: parse_json_column(&row.try_get::<String, _>("platforms")?)?,
        passthrough_code: row.try_get("passthrough_code")?,
        response_code: row.try_get("response_code")?,
        passthrough_body: row.try_get("passthrough_body")?,
        custom_message: row.try_get("custom_message")?,
        skip_monitoring: row.try_get("skip_monitoring")?,
        description: row.try_get("description")?,
    })
}

async fn persist_error_rule(
    transaction: &mut Transaction<'_, Postgres>,
    id: i64,
    state: &ErrorRuleState,
) -> Result<(), AdminError> {
    sqlx::query(
        r"
UPDATE error_passthrough_rules SET
    name=$2, enabled=$3, priority=$4, error_codes=$5::jsonb, keywords=$6::jsonb,
    match_mode=$7, platforms=$8::jsonb, passthrough_code=$9, response_code=$10,
    passthrough_body=$11, custom_message=$12, skip_monitoring=$13,
    description=$14, updated_at=NOW()
WHERE id=$1
",
    )
    .bind(id)
    .bind(&state.name)
    .bind(state.enabled)
    .bind(state.priority)
    .bind(json_string(&state.error_codes)?)
    .bind(json_string(&state.keywords)?)
    .bind(&state.match_mode)
    .bind(json_string(&state.platforms)?)
    .bind(state.passthrough_code)
    .bind(state.response_code)
    .bind(state.passthrough_body)
    .bind(&state.custom_message)
    .bind(state.skip_monitoring)
    .bind(&state.description)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn validate_error_rule(rule: &ErrorRuleState) -> Result<(), AdminError> {
    if rule.name.is_empty() {
        return Err(AdminError::BadRequest("name: name is required".to_owned()));
    }
    if rule.name.chars().count() > 100 {
        return Err(AdminError::BadRequest(
            "name must not exceed 100 characters".to_owned(),
        ));
    }
    if !matches!(rule.match_mode.as_str(), "any" | "all") {
        return Err(AdminError::BadRequest(
            "match_mode: match_mode must be 'any' or 'all'".to_owned(),
        ));
    }
    if rule.error_codes.is_empty() && rule.keywords.is_empty() {
        return Err(AdminError::BadRequest(
            "conditions: at least one error_code or keyword is required".to_owned(),
        ));
    }
    if !rule.passthrough_code && rule.response_code.is_none_or(|code| code <= 0) {
        return Err(AdminError::BadRequest(
            "response_code: response_code is required when passthrough_code is false".to_owned(),
        ));
    }
    if !rule.passthrough_body && rule.custom_message.as_deref().is_none_or(str::is_empty) {
        return Err(AdminError::BadRequest(
            "custom_message: custom_message is required when passthrough_body is false".to_owned(),
        ));
    }
    Ok(())
}

// --- TLS fingerprint profiles ----------------------------------------------

#[derive(Debug, Deserialize)]
struct CreateTlsProfileRequest {
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    enable_grease: bool,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    cipher_suites: Vec<u16>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    curves: Vec<u16>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    point_formats: Vec<u16>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    signature_algorithms: Vec<u16>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    alpn_protocols: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    supported_versions: Vec<u16>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    key_share_groups: Vec<u16>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    psk_modes: Vec<u16>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    extensions: Vec<u16>,
}

#[derive(Debug, Default, Deserialize)]
struct UpdateTlsProfileRequest {
    #[serde(default)]
    name: Patch<String>,
    #[serde(default)]
    description: Patch<String>,
    #[serde(default)]
    enable_grease: Patch<bool>,
    #[serde(default)]
    cipher_suites: Patch<Vec<u16>>,
    #[serde(default)]
    curves: Patch<Vec<u16>>,
    #[serde(default)]
    point_formats: Patch<Vec<u16>>,
    #[serde(default)]
    signature_algorithms: Patch<Vec<u16>>,
    #[serde(default)]
    alpn_protocols: Patch<Vec<String>>,
    #[serde(default)]
    supported_versions: Patch<Vec<u16>>,
    #[serde(default)]
    key_share_groups: Patch<Vec<u16>>,
    #[serde(default)]
    psk_modes: Patch<Vec<u16>>,
    #[serde(default)]
    extensions: Patch<Vec<u16>>,
}

#[derive(Debug)]
struct TlsProfileState {
    name: String,
    description: Option<String>,
    enable_grease: bool,
    cipher_suites: Vec<u16>,
    curves: Vec<u16>,
    point_formats: Vec<u16>,
    signature_algorithms: Vec<u16>,
    alpn_protocols: Vec<String>,
    supported_versions: Vec<u16>,
    key_share_groups: Vec<u16>,
    psk_modes: Vec<u16>,
    extensions: Vec<u16>,
}

const TLS_PROFILE_JSON: &str = r"
to_jsonb(profile)
|| jsonb_build_object(
     'cipher_suites', COALESCE(profile.cipher_suites, '[]'::jsonb),
     'curves', COALESCE(profile.curves, '[]'::jsonb),
     'point_formats', COALESCE(profile.point_formats, '[]'::jsonb),
     'signature_algorithms', COALESCE(profile.signature_algorithms, '[]'::jsonb),
     'alpn_protocols', COALESCE(profile.alpn_protocols, '[]'::jsonb),
     'supported_versions', COALESCE(profile.supported_versions, '[]'::jsonb),
     'key_share_groups', COALESCE(profile.key_share_groups, '[]'::jsonb),
     'psk_modes', COALESCE(profile.psk_modes, '[]'::jsonb),
     'extensions', COALESCE(profile.extensions, '[]'::jsonb)
   )
";

async fn list_tls_profiles(pool: &PgPool) -> Result<Value, AdminError> {
    let sql = format!(
        "SELECT {TLS_PROFILE_JSON} FROM tls_fingerprint_profiles profile ORDER BY profile.id"
    );
    Ok(Value::Array(
        sqlx::query_scalar::<_, Value>(&sql).fetch_all(pool).await?,
    ))
}

async fn get_tls_profile(pool: &PgPool, id: i64) -> Result<Value, AdminError> {
    let sql = format!(
        "SELECT {TLS_PROFILE_JSON} FROM tls_fingerprint_profiles profile WHERE profile.id = $1"
    );
    sqlx::query_scalar::<_, Value>(&sql)
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(AdminError::NotFound("TLS fingerprint profile"))
}

async fn create_tls_profile(
    pool: &PgPool,
    actor: &AdminIdentity,
    payload: Value,
) -> Result<Value, AdminError> {
    let request: CreateTlsProfileRequest = parse_payload(payload)?;
    let state = TlsProfileState {
        name: request.name.unwrap_or_default(),
        description: trim_optional(request.description, 4_000),
        enable_grease: request.enable_grease,
        cipher_suites: bounded_u16(request.cipher_suites, "cipher_suites")?,
        curves: bounded_u16(request.curves, "curves")?,
        point_formats: bounded_u16(request.point_formats, "point_formats")?,
        signature_algorithms: bounded_u16(request.signature_algorithms, "signature_algorithms")?,
        alpn_protocols: normalize_string_list(request.alpn_protocols, 32, 255)?,
        supported_versions: bounded_u16(request.supported_versions, "supported_versions")?,
        key_share_groups: bounded_u16(request.key_share_groups, "key_share_groups")?,
        psk_modes: bounded_u16(request.psk_modes, "psk_modes")?,
        extensions: bounded_u16(request.extensions, "extensions")?,
    };
    validate_tls_profile(&state)?;
    let mut transaction = pool.begin().await?;
    let id = insert_tls_profile(&mut transaction, &state).await?;
    notify_settings(&mut transaction).await?;
    transaction.commit().await?;
    let value = get_tls_profile(pool, id).await?;
    audit_mutation(actor, "create", "tls_fingerprint_profile", id);
    Ok(value)
}

async fn update_tls_profile(
    pool: &PgPool,
    actor: &AdminIdentity,
    id: i64,
    payload: Value,
) -> Result<Value, AdminError> {
    let request: UpdateTlsProfileRequest = parse_payload(payload)?;
    let mut transaction = pool.begin().await?;
    let mut state = load_tls_profile(&mut transaction, id).await?;
    apply_required_string_patch(&mut state.name, request.name);
    apply_nullable_string_patch(&mut state.description, request.description, 4_000);
    apply_copy_patch(&mut state.enable_grease, &request.enable_grease);
    apply_u16_patch(
        &mut state.cipher_suites,
        request.cipher_suites,
        "cipher_suites",
    )?;
    apply_u16_patch(&mut state.curves, request.curves, "curves")?;
    apply_u16_patch(
        &mut state.point_formats,
        request.point_formats,
        "point_formats",
    )?;
    apply_u16_patch(
        &mut state.signature_algorithms,
        request.signature_algorithms,
        "signature_algorithms",
    )?;
    apply_string_vec_patch(
        &mut state.alpn_protocols,
        request.alpn_protocols,
        "alpn_protocols",
        32,
        255,
    )?;
    apply_u16_patch(
        &mut state.supported_versions,
        request.supported_versions,
        "supported_versions",
    )?;
    apply_u16_patch(
        &mut state.key_share_groups,
        request.key_share_groups,
        "key_share_groups",
    )?;
    apply_u16_patch(&mut state.psk_modes, request.psk_modes, "psk_modes")?;
    apply_u16_patch(&mut state.extensions, request.extensions, "extensions")?;
    validate_tls_profile(&state)?;
    persist_tls_profile(&mut transaction, id, &state).await?;
    notify_settings(&mut transaction).await?;
    transaction.commit().await?;
    let value = get_tls_profile(pool, id).await?;
    audit_mutation(actor, "update", "tls_fingerprint_profile", id);
    Ok(value)
}

async fn delete_tls_profile(
    pool: &PgPool,
    actor: &AdminIdentity,
    id: i64,
) -> Result<Value, AdminError> {
    let mut transaction = pool.begin().await?;
    let deleted = sqlx::query("DELETE FROM tls_fingerprint_profiles WHERE id = $1")
        .bind(id)
        .execute(&mut *transaction)
        .await?;
    if deleted.rows_affected() == 0 {
        return Err(AdminError::NotFound("TLS fingerprint profile"));
    }
    notify_settings(&mut transaction).await?;
    transaction.commit().await?;
    audit_mutation(actor, "delete", "tls_fingerprint_profile", id);
    Ok(json!({ "message": "Profile deleted successfully" }))
}

async fn insert_tls_profile(
    transaction: &mut Transaction<'_, Postgres>,
    state: &TlsProfileState,
) -> Result<i64, AdminError> {
    Ok(sqlx::query_scalar::<_, i64>(
        r"
INSERT INTO tls_fingerprint_profiles (
    name, description, enable_grease, cipher_suites, curves, point_formats,
    signature_algorithms, alpn_protocols, supported_versions, key_share_groups,
    psk_modes, extensions, created_at, updated_at
) VALUES ($1,$2,$3,$4::jsonb,$5::jsonb,$6::jsonb,$7::jsonb,$8::jsonb,$9::jsonb,$10::jsonb,$11::jsonb,$12::jsonb,NOW(),NOW())
RETURNING id
",
    )
    .bind(&state.name)
    .bind(&state.description)
    .bind(state.enable_grease)
    .bind(json_string(&state.cipher_suites)?)
    .bind(json_string(&state.curves)?)
    .bind(json_string(&state.point_formats)?)
    .bind(json_string(&state.signature_algorithms)?)
    .bind(json_string(&state.alpn_protocols)?)
    .bind(json_string(&state.supported_versions)?)
    .bind(json_string(&state.key_share_groups)?)
    .bind(json_string(&state.psk_modes)?)
    .bind(json_string(&state.extensions)?)
    .fetch_one(&mut **transaction)
    .await?)
}

async fn load_tls_profile(
    transaction: &mut Transaction<'_, Postgres>,
    id: i64,
) -> Result<TlsProfileState, AdminError> {
    let row = sqlx::query(
        r"
SELECT name, description, enable_grease,
       COALESCE(cipher_suites, '[]'::jsonb)::text AS cipher_suites,
       COALESCE(curves, '[]'::jsonb)::text AS curves,
       COALESCE(point_formats, '[]'::jsonb)::text AS point_formats,
       COALESCE(signature_algorithms, '[]'::jsonb)::text AS signature_algorithms,
       COALESCE(alpn_protocols, '[]'::jsonb)::text AS alpn_protocols,
       COALESCE(supported_versions, '[]'::jsonb)::text AS supported_versions,
       COALESCE(key_share_groups, '[]'::jsonb)::text AS key_share_groups,
       COALESCE(psk_modes, '[]'::jsonb)::text AS psk_modes,
       COALESCE(extensions, '[]'::jsonb)::text AS extensions
FROM tls_fingerprint_profiles WHERE id = $1 FOR UPDATE
",
    )
    .bind(id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(AdminError::NotFound("TLS fingerprint profile"))?;
    Ok(TlsProfileState {
        name: row.try_get("name")?,
        description: row.try_get("description")?,
        enable_grease: row.try_get("enable_grease")?,
        cipher_suites: parse_json_column(&row.try_get::<String, _>("cipher_suites")?)?,
        curves: parse_json_column(&row.try_get::<String, _>("curves")?)?,
        point_formats: parse_json_column(&row.try_get::<String, _>("point_formats")?)?,
        signature_algorithms: parse_json_column(
            &row.try_get::<String, _>("signature_algorithms")?,
        )?,
        alpn_protocols: parse_json_column(&row.try_get::<String, _>("alpn_protocols")?)?,
        supported_versions: parse_json_column(&row.try_get::<String, _>("supported_versions")?)?,
        key_share_groups: parse_json_column(&row.try_get::<String, _>("key_share_groups")?)?,
        psk_modes: parse_json_column(&row.try_get::<String, _>("psk_modes")?)?,
        extensions: parse_json_column(&row.try_get::<String, _>("extensions")?)?,
    })
}

async fn persist_tls_profile(
    transaction: &mut Transaction<'_, Postgres>,
    id: i64,
    state: &TlsProfileState,
) -> Result<(), AdminError> {
    sqlx::query(
        r"
UPDATE tls_fingerprint_profiles SET
    name=$2, description=$3, enable_grease=$4, cipher_suites=$5::jsonb,
    curves=$6::jsonb, point_formats=$7::jsonb, signature_algorithms=$8::jsonb,
    alpn_protocols=$9::jsonb, supported_versions=$10::jsonb,
    key_share_groups=$11::jsonb, psk_modes=$12::jsonb, extensions=$13::jsonb,
    updated_at=NOW()
WHERE id=$1
",
    )
    .bind(id)
    .bind(&state.name)
    .bind(&state.description)
    .bind(state.enable_grease)
    .bind(json_string(&state.cipher_suites)?)
    .bind(json_string(&state.curves)?)
    .bind(json_string(&state.point_formats)?)
    .bind(json_string(&state.signature_algorithms)?)
    .bind(json_string(&state.alpn_protocols)?)
    .bind(json_string(&state.supported_versions)?)
    .bind(json_string(&state.key_share_groups)?)
    .bind(json_string(&state.psk_modes)?)
    .bind(json_string(&state.extensions)?)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn validate_tls_profile(profile: &TlsProfileState) -> Result<(), AdminError> {
    if profile.name.is_empty() {
        return Err(AdminError::BadRequest("name: name is required".to_owned()));
    }
    if profile.name.chars().count() > 100 {
        return Err(AdminError::BadRequest(
            "name must not exceed 100 characters".to_owned(),
        ));
    }
    Ok(())
}

// --- Registration promo codes ----------------------------------------------

#[derive(Debug, Deserialize)]
struct CreatePromoRequest {
    #[serde(default)]
    code: String,
    bonus_amount: Option<f64>,
    #[serde(default)]
    max_uses: i32,
    #[serde(default)]
    expires_at: Option<i64>,
    #[serde(default)]
    notes: String,
}

#[derive(Debug, Default, Deserialize)]
struct UpdatePromoRequest {
    #[serde(default)]
    code: Patch<String>,
    #[serde(default)]
    bonus_amount: Patch<f64>,
    #[serde(default)]
    max_uses: Patch<i32>,
    #[serde(default)]
    status: Patch<String>,
    #[serde(default)]
    expires_at: Patch<i64>,
    #[serde(default)]
    notes: Patch<String>,
}

#[derive(Debug)]
struct PromoState {
    code: String,
    bonus_amount: f64,
    max_uses: i32,
    status: String,
    expires_at_epoch: Option<i64>,
    notes: String,
}

const PROMO_JSON: &str = r"
to_jsonb(promo)
|| jsonb_build_object('notes', COALESCE(promo.notes, ''))
";

async fn list_promo_codes(
    pool: &PgPool,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let page = query_positive_i64(query, "page").unwrap_or(1);
    let page_size = query_positive_i64(query, "page_size")
        .unwrap_or(20)
        .clamp(1, MAX_PAGE_SIZE);
    let status = trimmed_query(query, "status", 30);
    let search = trimmed_query(query, "search", 100);
    let sort_column = match query.get("sort_by").map(String::as_str) {
        Some("bonus_amount") => "promo.bonus_amount",
        Some("status") => "promo.status",
        Some("expires_at") => "promo.expires_at",
        Some("created_at") => "promo.created_at",
        Some("code") => "promo.code",
        _ => "promo.id",
    };
    let direction = sort_direction(query);
    let sql = format!(
        r"
SELECT {PROMO_JSON} AS data
FROM promo_codes promo
WHERE ($1::text IS NULL OR promo.status = $1)
  AND ($2::text IS NULL OR promo.code ILIKE '%' || $2 || '%')
ORDER BY {sort_column} {direction}, promo.id {direction}
LIMIT $3 OFFSET $4
"
    );
    let items = sqlx::query_scalar::<_, Value>(&sql)
        .bind(status.as_deref())
        .bind(search.as_deref())
        .bind(page_size)
        .bind((page - 1) * page_size)
        .fetch_all(pool)
        .await?;
    let total = sqlx::query_scalar::<_, i64>(
        r"
SELECT COUNT(*)::bigint FROM promo_codes promo
WHERE ($1::text IS NULL OR promo.status = $1)
  AND ($2::text IS NULL OR promo.code ILIKE '%' || $2 || '%')
",
    )
    .bind(status.as_deref())
    .bind(search.as_deref())
    .fetch_one(pool)
    .await?;
    Ok(paginated(&items, total, page, page_size))
}

async fn get_promo_code(pool: &PgPool, id: i64) -> Result<Value, AdminError> {
    let sql = format!("SELECT {PROMO_JSON} FROM promo_codes promo WHERE promo.id = $1");
    sqlx::query_scalar::<_, Value>(&sql)
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(AdminError::NotFound("promo code"))
}

async fn create_promo_code(
    pool: &PgPool,
    actor: &AdminIdentity,
    payload: Value,
) -> Result<Value, AdminError> {
    let request: CreatePromoRequest = parse_payload(payload)?;
    let mut code = request.code.trim().to_ascii_uppercase();
    if code.is_empty() {
        code = random_promo_code();
    }
    let state = PromoState {
        code,
        bonus_amount: request
            .bonus_amount
            .ok_or_else(|| AdminError::BadRequest("bonus_amount is required".to_owned()))?,
        max_uses: request.max_uses,
        status: "active".to_owned(),
        expires_at_epoch: request.expires_at,
        notes: request.notes,
    };
    validate_promo(&state)?;
    let id = sqlx::query_scalar::<_, i64>(
        r"
INSERT INTO promo_codes (
    code, bonus_amount, max_uses, used_count, status, expires_at, notes,
    created_at, updated_at
) VALUES ($1,$2,$3,0,'active',CASE WHEN $4::bigint IS NULL THEN NULL ELSE to_timestamp($4::double precision) END,$5,NOW(),NOW())
RETURNING id
",
    )
    .bind(&state.code)
    .bind(state.bonus_amount)
    .bind(state.max_uses)
    .bind(state.expires_at_epoch)
    .bind(&state.notes)
    .fetch_one(pool)
    .await?;
    audit_mutation(actor, "create", "promo_code", id);
    get_promo_code(pool, id).await
}

async fn update_promo_code(
    pool: &PgPool,
    actor: &AdminIdentity,
    id: i64,
    payload: Value,
) -> Result<Value, AdminError> {
    let request: UpdatePromoRequest = parse_payload(payload)?;
    let mut transaction = pool.begin().await?;
    let row = sqlx::query(
        r"
SELECT code, bonus_amount::float8 AS bonus_amount, max_uses, used_count, status,
       EXTRACT(EPOCH FROM expires_at)::bigint AS expires_at_epoch,
       COALESCE(notes, '') AS notes
FROM promo_codes WHERE id = $1 FOR UPDATE
",
    )
    .bind(id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(AdminError::NotFound("promo code"))?;
    let mut state = PromoState {
        code: row.try_get("code")?,
        bonus_amount: row.try_get("bonus_amount")?,
        max_uses: row.try_get("max_uses")?,
        status: row.try_get("status")?,
        expires_at_epoch: row.try_get("expires_at_epoch")?,
        notes: row.try_get("notes")?,
    };
    match request.code {
        Patch::Value(value) => state.code = value.trim().to_ascii_uppercase(),
        Patch::Null | Patch::Missing => {}
    }
    apply_copy_patch(&mut state.bonus_amount, &request.bonus_amount);
    apply_copy_patch(&mut state.max_uses, &request.max_uses);
    if let Patch::Value(value) = request.status {
        state.status = value.trim().to_ascii_lowercase();
    }
    state.expires_at_epoch = match request.expires_at {
        Patch::Missing | Patch::Null => state.expires_at_epoch,
        Patch::Value(0) => None,
        Patch::Value(value) => Some(value),
    };
    match request.notes {
        Patch::Value(value) => state.notes = value,
        Patch::Null | Patch::Missing => {}
    }
    validate_promo(&state)?;
    sqlx::query(
        r"
UPDATE promo_codes SET
    code=$2, bonus_amount=$3, max_uses=$4, status=$5,
    expires_at=CASE WHEN $6::bigint IS NULL THEN NULL ELSE to_timestamp($6::double precision) END,
    notes=$7, updated_at=NOW()
WHERE id=$1
",
    )
    .bind(id)
    .bind(&state.code)
    .bind(state.bonus_amount)
    .bind(state.max_uses)
    .bind(&state.status)
    .bind(state.expires_at_epoch)
    .bind(&state.notes)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    audit_mutation(actor, "update", "promo_code", id);
    get_promo_code(pool, id).await
}

async fn delete_promo_code(
    pool: &PgPool,
    actor: &AdminIdentity,
    id: i64,
) -> Result<Value, AdminError> {
    sqlx::query("DELETE FROM promo_codes WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    audit_mutation(actor, "delete", "promo_code", id);
    Ok(json!({ "message": "Promo code deleted successfully" }))
}

fn validate_promo(promo: &PromoState) -> Result<(), AdminError> {
    if promo.code.chars().count() > 32 {
        return Err(AdminError::BadRequest(
            "promo code must not exceed 32 characters".to_owned(),
        ));
    }
    if !promo.bonus_amount.is_finite() || promo.bonus_amount < 0.0 {
        return Err(AdminError::BadRequest(
            "bonus_amount must be non-negative".to_owned(),
        ));
    }
    if promo.max_uses < 0 {
        return Err(AdminError::BadRequest(
            "max_uses must be non-negative".to_owned(),
        ));
    }
    if !matches!(promo.status.as_str(), "active" | "disabled") {
        return Err(AdminError::BadRequest(
            "status must be active or disabled".to_owned(),
        ));
    }
    Ok(())
}

fn random_promo_code() -> String {
    let mut bytes = [0_u8; 8];
    OsRng.fill_bytes(&mut bytes);
    hex::encode_upper(bytes)
}

// --- Redeem codes -----------------------------------------------------------

const REDEEM_JSON: &str = r"
to_jsonb(redeem)
|| jsonb_build_object(
     'status', CASE
         WHEN redeem.status = 'expired' THEN 'expired'
         WHEN redeem.status = 'unused' AND redeem.expires_at IS NOT NULL
              AND redeem.expires_at <= NOW() THEN 'expired'
         ELSE redeem.status
       END,
     'notes', COALESCE(redeem.notes, '')
   )
|| CASE WHEN redeem_user.id IS NULL THEN '{}'::jsonb ELSE jsonb_build_object(
     'user', jsonb_build_object(
         'id', redeem_user.id,
         'email', redeem_user.email,
         'username', redeem_user.username,
         'role', redeem_user.role,
         'status', redeem_user.status
     )
   ) END
|| CASE WHEN redeem_group.id IS NULL THEN '{}'::jsonb ELSE jsonb_build_object(
     'group', jsonb_build_object(
         'id', redeem_group.id,
         'name', redeem_group.name,
         'description', redeem_group.description,
         'platform', redeem_group.platform,
         'status', redeem_group.status,
         'subscription_type', redeem_group.subscription_type,
         'rate_multiplier', redeem_group.rate_multiplier
     )
   ) END
";

const REDEEM_JOINS: &str = r"
LEFT JOIN users redeem_user
       ON redeem_user.id = redeem.used_by AND redeem_user.deleted_at IS NULL
LEFT JOIN groups redeem_group
       ON redeem_group.id = redeem.group_id AND redeem_group.deleted_at IS NULL
";

async fn list_redeem_codes(
    pool: &PgPool,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let page = query_positive_i64(query, "page").unwrap_or(1);
    let page_size = query_positive_i64(query, "page_size")
        .unwrap_or(20)
        .clamp(1, MAX_PAGE_SIZE);
    let code_type = trimmed_query(query, "type", 30);
    let status = trimmed_query(query, "status", 30);
    let search = trimmed_query(query, "search", 100);
    let sort_column = match query.get("sort_by").map(String::as_str) {
        Some("type") => "redeem.type",
        Some("value") => "redeem.value",
        Some("status") => "redeem.status",
        Some("used_at") => "redeem.used_at",
        Some("created_at") => "redeem.created_at",
        Some("expires_at") => "redeem.expires_at",
        Some("code") => "redeem.code",
        _ => "redeem.id",
    };
    let direction = sort_direction(query);
    let sql = format!(
        r"
SELECT {REDEEM_JSON} AS data
FROM redeem_codes redeem
{REDEEM_JOINS}
WHERE ($1::text IS NULL OR redeem.type = $1)
  AND (
       $2::text IS NULL
       OR ($2 = 'expired' AND (
             redeem.status = 'expired'
             OR (redeem.status = 'unused' AND redeem.expires_at IS NOT NULL
                 AND redeem.expires_at <= NOW())
          ))
       OR ($2 = 'unused' AND redeem.status = 'unused'
           AND (redeem.expires_at IS NULL OR redeem.expires_at > NOW()))
       OR ($2 NOT IN ('expired', 'unused') AND redeem.status = $2)
  )
  AND (
       $3::text IS NULL
       OR redeem.code ILIKE '%' || $3 || '%'
       OR redeem_user.email ILIKE '%' || $3 || '%'
  )
ORDER BY {sort_column} {direction}, redeem.id {direction}
LIMIT $4 OFFSET $5
"
    );
    let items = sqlx::query_scalar::<_, Value>(&sql)
        .bind(code_type.as_deref())
        .bind(status.as_deref())
        .bind(search.as_deref())
        .bind(page_size)
        .bind((page - 1) * page_size)
        .fetch_all(pool)
        .await?;
    let count_sql = format!(
        r"
SELECT COUNT(*)::bigint
FROM redeem_codes redeem
{REDEEM_JOINS}
WHERE ($1::text IS NULL OR redeem.type = $1)
  AND (
       $2::text IS NULL
       OR ($2 = 'expired' AND (
             redeem.status = 'expired'
             OR (redeem.status = 'unused' AND redeem.expires_at IS NOT NULL
                 AND redeem.expires_at <= NOW())
          ))
       OR ($2 = 'unused' AND redeem.status = 'unused'
           AND (redeem.expires_at IS NULL OR redeem.expires_at > NOW()))
       OR ($2 NOT IN ('expired', 'unused') AND redeem.status = $2)
  )
  AND (
       $3::text IS NULL
       OR redeem.code ILIKE '%' || $3 || '%'
       OR redeem_user.email ILIKE '%' || $3 || '%'
  )
"
    );
    let total = sqlx::query_scalar::<_, i64>(&count_sql)
        .bind(code_type.as_deref())
        .bind(status.as_deref())
        .bind(search.as_deref())
        .fetch_one(pool)
        .await?;
    Ok(paginated(&items, total, page, page_size))
}

async fn get_redeem_code(pool: &PgPool, id: i64) -> Result<Value, AdminError> {
    let sql = format!(
        r"
SELECT {REDEEM_JSON}
FROM redeem_codes redeem
{REDEEM_JOINS}
WHERE redeem.id = $1
"
    );
    sqlx::query_scalar::<_, Value>(&sql)
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(AdminError::NotFound("redeem code"))
}

async fn delete_redeem_code(
    pool: &PgPool,
    actor: &AdminIdentity,
    id: i64,
) -> Result<Value, AdminError> {
    sqlx::query("DELETE FROM redeem_codes WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    audit_mutation(actor, "delete", "redeem_code", id);
    Ok(json!({ "message": "Redeem code deleted successfully" }))
}

// --- Scheduled account tests ------------------------------------------------

#[derive(Debug, Deserialize)]
struct CreateScheduledTestRequest {
    account_id: Option<i64>,
    #[serde(default)]
    model_id: String,
    cron_expression: Option<String>,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    max_results: i32,
    #[serde(default)]
    auto_recover: bool,
}

#[derive(Debug, Default, Deserialize)]
struct UpdateScheduledTestRequest {
    model_id: Option<String>,
    cron_expression: Option<String>,
    enabled: Option<bool>,
    max_results: Option<i32>,
    auto_recover: Option<bool>,
}

#[derive(Debug)]
struct ScheduledTestState {
    account_id: i64,
    model_id: String,
    cron_expression: String,
    enabled: bool,
    max_results: i32,
    auto_recover: bool,
}

async fn create_scheduled_test(
    pool: &PgPool,
    actor: &AdminIdentity,
    payload: Value,
) -> Result<Value, AdminError> {
    let request: CreateScheduledTestRequest = parse_payload(payload)?;
    let state = ScheduledTestState {
        account_id: request
            .account_id
            .filter(|id| *id > 0)
            .ok_or_else(|| AdminError::BadRequest("account_id is required".to_owned()))?,
        model_id: request.model_id.trim().to_owned(),
        cron_expression: request
            .cron_expression
            .unwrap_or_default()
            .trim()
            .to_owned(),
        enabled: request.enabled,
        max_results: if request.max_results > 0 {
            request.max_results
        } else {
            50
        },
        auto_recover: request.auto_recover,
    };
    validate_scheduled_test(&state)?;
    let next_run = next_cron_epoch(&state.cron_expression, Utc::now())?;
    let mut transaction = pool.begin().await?;
    ensure_live_account(&mut transaction, state.account_id).await?;
    let value = sqlx::query_scalar::<_, Value>(
        r"
INSERT INTO scheduled_test_plans (
    account_id, model_id, cron_expression, enabled, max_results, auto_recover,
    next_run_at, created_at, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,to_timestamp($7::double precision),NOW(),NOW())
RETURNING to_jsonb(scheduled_test_plans)
",
    )
    .bind(state.account_id)
    .bind(&state.model_id)
    .bind(&state.cron_expression)
    .bind(state.enabled)
    .bind(state.max_results)
    .bind(state.auto_recover)
    .bind(next_run)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    let id = value.get("id").and_then(Value::as_i64).unwrap_or_default();
    audit_mutation(actor, "create", "scheduled_test_plan", id);
    Ok(value)
}

async fn update_scheduled_test(
    pool: &PgPool,
    actor: &AdminIdentity,
    id: i64,
    payload: Value,
) -> Result<Value, AdminError> {
    let request: UpdateScheduledTestRequest = parse_payload(payload)?;
    let mut transaction = pool.begin().await?;
    let row = sqlx::query(
        r"
SELECT account_id, model_id, cron_expression, enabled, max_results, auto_recover
FROM scheduled_test_plans WHERE id = $1 FOR UPDATE
",
    )
    .bind(id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(AdminError::NotFound("scheduled test plan"))?;
    let mut state = ScheduledTestState {
        account_id: row.try_get("account_id")?,
        model_id: row.try_get("model_id")?,
        cron_expression: row.try_get("cron_expression")?,
        enabled: row.try_get("enabled")?,
        max_results: row.try_get("max_results")?,
        auto_recover: row.try_get("auto_recover")?,
    };
    if let Some(value) = request.model_id
        && !value.is_empty()
    {
        value.trim().clone_into(&mut state.model_id);
    }
    if let Some(value) = request.cron_expression
        && !value.is_empty()
    {
        value.trim().clone_into(&mut state.cron_expression);
    }
    if let Some(value) = request.enabled {
        state.enabled = value;
    }
    if let Some(value) = request.max_results
        && value > 0
    {
        state.max_results = value;
    }
    if let Some(value) = request.auto_recover {
        state.auto_recover = value;
    }
    validate_scheduled_test(&state)?;
    let next_run = next_cron_epoch(&state.cron_expression, Utc::now())?;
    let value = sqlx::query_scalar::<_, Value>(
        r"
UPDATE scheduled_test_plans SET
    model_id=$2, cron_expression=$3, enabled=$4, max_results=$5,
    auto_recover=$6, next_run_at=to_timestamp($7::double precision), updated_at=NOW()
WHERE id=$1
RETURNING to_jsonb(scheduled_test_plans)
",
    )
    .bind(id)
    .bind(&state.model_id)
    .bind(&state.cron_expression)
    .bind(state.enabled)
    .bind(state.max_results)
    .bind(state.auto_recover)
    .bind(next_run)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    audit_mutation(actor, "update", "scheduled_test_plan", id);
    Ok(value)
}

async fn delete_scheduled_test(
    pool: &PgPool,
    actor: &AdminIdentity,
    id: i64,
) -> Result<Value, AdminError> {
    sqlx::query("DELETE FROM scheduled_test_plans WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    audit_mutation(actor, "delete", "scheduled_test_plan", id);
    Ok(json!({ "message": "deleted" }))
}

fn validate_scheduled_test(plan: &ScheduledTestState) -> Result<(), AdminError> {
    if plan.account_id <= 0 {
        return Err(AdminError::BadRequest(
            "account_id must be positive".to_owned(),
        ));
    }
    if plan.model_id.chars().count() > 100 {
        return Err(AdminError::BadRequest(
            "model_id must not exceed 100 characters".to_owned(),
        ));
    }
    if plan.cron_expression.is_empty() || plan.cron_expression.chars().count() > 100 {
        return Err(AdminError::BadRequest(
            "cron_expression is required and must not exceed 100 characters".to_owned(),
        ));
    }
    if plan.max_results <= 0 {
        return Err(AdminError::BadRequest(
            "max_results must be greater than zero".to_owned(),
        ));
    }
    Ok(())
}

async fn ensure_live_account(
    transaction: &mut Transaction<'_, Postgres>,
    id: i64,
) -> Result<(), AdminError> {
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM accounts WHERE id = $1 AND deleted_at IS NULL)",
    )
    .bind(id)
    .fetch_one(&mut **transaction)
    .await?;
    if exists {
        Ok(())
    } else {
        Err(AdminError::NotFound("account"))
    }
}

#[derive(Clone, Debug)]
struct CronSchedule {
    minutes: CronField,
    hours: CronField,
    days_of_month: CronField,
    months: CronField,
    days_of_week: CronField,
}

impl CronSchedule {
    fn parse(expression: &str) -> Result<Self, AdminError> {
        let fields = expression.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 5 {
            return Err(invalid_cron("cron expression must contain five fields"));
        }
        Ok(Self {
            minutes: CronField::parse(fields[0], 0, 59, &[], false)?,
            hours: CronField::parse(fields[1], 0, 23, &[], false)?,
            days_of_month: CronField::parse(fields[2], 1, 31, &[], false)?,
            months: CronField::parse(
                fields[3],
                1,
                12,
                &[
                    ("JAN", 1),
                    ("FEB", 2),
                    ("MAR", 3),
                    ("APR", 4),
                    ("MAY", 5),
                    ("JUN", 6),
                    ("JUL", 7),
                    ("AUG", 8),
                    ("SEP", 9),
                    ("OCT", 10),
                    ("NOV", 11),
                    ("DEC", 12),
                ],
                false,
            )?,
            days_of_week: CronField::parse(
                fields[4],
                0,
                7,
                &[
                    ("SUN", 0),
                    ("MON", 1),
                    ("TUE", 2),
                    ("WED", 3),
                    ("THU", 4),
                    ("FRI", 5),
                    ("SAT", 6),
                ],
                true,
            )?,
        })
    }

    fn next_after(&self, after: DateTime<Utc>) -> Result<DateTime<Utc>, AdminError> {
        let mut timestamp = after
            .timestamp()
            .div_euclid(60)
            .saturating_add(1)
            .saturating_mul(60);
        for _ in 0..MAX_CRON_SEARCH_MINUTES {
            let candidate = DateTime::<Utc>::from_timestamp(timestamp, 0)
                .ok_or_else(|| invalid_cron("cron search exceeded the timestamp range"))?;
            if self.matches(candidate.with_timezone(&Local)) {
                return Ok(candidate);
            }
            timestamp = timestamp.saturating_add(60);
        }
        Err(invalid_cron(
            "cron expression has no occurrence within eight years",
        ))
    }

    fn matches(&self, candidate: DateTime<Local>) -> bool {
        if !self.minutes.contains(candidate.minute())
            || !self.hours.contains(candidate.hour())
            || !self.months.contains(candidate.month())
        {
            return false;
        }
        let day_matches = self.days_of_month.contains(candidate.day());
        let weekday_matches = self
            .days_of_week
            .contains(candidate.weekday().num_days_from_sunday());
        if self.days_of_month.wildcard_syntax || self.days_of_week.wildcard_syntax {
            day_matches && weekday_matches
        } else {
            day_matches || weekday_matches
        }
    }
}

#[derive(Clone, Debug)]
struct CronField {
    allowed: Vec<bool>,
    wildcard_syntax: bool,
}

impl CronField {
    fn parse(
        raw: &str,
        min: u32,
        max: u32,
        names: &[(&str, u32)],
        normalize_sunday: bool,
    ) -> Result<Self, AdminError> {
        let raw = raw.trim().to_ascii_uppercase();
        if raw.is_empty() {
            return Err(invalid_cron("cron field is empty"));
        }
        let wildcard_syntax = raw == "?" || raw.starts_with('*');
        let raw = if raw == "?" { "*" } else { raw.as_str() };
        let canonical_max = if normalize_sunday { 6 } else { max };
        let mut allowed = vec![false; usize::try_from(canonical_max + 1).unwrap_or(0)];
        for item in raw.split(',') {
            let (base, step) = item.split_once('/').map_or((item, 1), |(base, step)| {
                (base, step.parse::<u32>().unwrap_or(0))
            });
            if step == 0 {
                return Err(invalid_cron("cron field step must be greater than zero"));
            }
            let (start, end) = if base == "*" {
                (min, max)
            } else if let Some((start, end)) = base.split_once('-') {
                (
                    parse_cron_value(start, min, max, names)?,
                    parse_cron_value(end, min, max, names)?,
                )
            } else {
                let start = parse_cron_value(base, min, max, names)?;
                (start, if item.contains('/') { max } else { start })
            };
            if start > end {
                return Err(invalid_cron("cron field ranges must be ascending"));
            }
            let mut value = start;
            while value <= end {
                let canonical = if normalize_sunday && value == 7 {
                    0
                } else {
                    value
                };
                if let Ok(index) = usize::try_from(canonical)
                    && let Some(slot) = allowed.get_mut(index)
                {
                    *slot = true;
                }
                let Some(next) = value.checked_add(step) else {
                    break;
                };
                value = next;
            }
        }
        if !allowed.iter().any(|value| *value) {
            return Err(invalid_cron("cron field does not select any values"));
        }
        Ok(Self {
            allowed,
            wildcard_syntax,
        })
    }

    fn contains(&self, value: u32) -> bool {
        self.allowed
            .get(usize::try_from(value).unwrap_or(usize::MAX))
            .copied()
            .unwrap_or(false)
    }
}

fn parse_cron_value(
    raw: &str,
    min: u32,
    max: u32,
    names: &[(&str, u32)],
) -> Result<u32, AdminError> {
    let value = names
        .iter()
        .find_map(|(name, value)| raw.eq_ignore_ascii_case(name).then_some(*value))
        .map_or_else(
            || {
                raw.parse::<u32>()
                    .map_err(|_| invalid_cron(&format!("invalid cron value {raw:?}")))
            },
            Ok,
        )?;
    if !(min..=max).contains(&value) {
        return Err(invalid_cron(&format!(
            "cron value {value} is outside [{min}, {max}]"
        )));
    }
    Ok(value)
}

fn next_cron_epoch(expression: &str, after: DateTime<Utc>) -> Result<i64, AdminError> {
    Ok(CronSchedule::parse(expression)?
        .next_after(after)?
        .timestamp())
}

fn invalid_cron(message: &str) -> AdminError {
    AdminError::BadRequest(format!("invalid cron expression: {message}"))
}

// --- Administrator subscription reads --------------------------------------

const SUBSCRIPTION_RELATIONS: &str = r"
LEFT JOIN users subscription_user
       ON subscription_user.id = subscription.user_id
      AND subscription_user.deleted_at IS NULL
LEFT JOIN groups subscription_group
       ON subscription_group.id = subscription.group_id
      AND subscription_group.deleted_at IS NULL
LEFT JOIN users assigning_user
       ON assigning_user.id = subscription.assigned_by
      AND assigning_user.deleted_at IS NULL
";

const SUBSCRIPTION_RELATION_JSON: &str = r"
CASE WHEN subscription_user.id IS NULL THEN '{}'::jsonb ELSE jsonb_build_object(
    'user', jsonb_build_object(
        'id', subscription_user.id,
        'email', subscription_user.email,
        'username', subscription_user.username,
        'role', subscription_user.role,
        'status', subscription_user.status
    )
) END
|| CASE WHEN subscription_group.id IS NULL THEN '{}'::jsonb ELSE jsonb_build_object(
    'group', jsonb_build_object(
        'id', subscription_group.id,
        'name', subscription_group.name,
        'description', subscription_group.description,
        'platform', subscription_group.platform,
        'status', subscription_group.status,
        'subscription_type', subscription_group.subscription_type,
        'rate_multiplier', subscription_group.rate_multiplier,
        'daily_limit_usd', subscription_group.daily_limit_usd,
        'weekly_limit_usd', subscription_group.weekly_limit_usd,
        'monthly_limit_usd', subscription_group.monthly_limit_usd
    )
) END
|| CASE WHEN assigning_user.id IS NULL THEN '{}'::jsonb ELSE jsonb_build_object(
    'assigned_by_user', jsonb_build_object(
        'id', assigning_user.id,
        'email', assigning_user.email,
        'username', assigning_user.username,
        'role', assigning_user.role,
        'status', assigning_user.status
    )
) END
";

const SUBSCRIPTION_LIST_JSON: &str = r"
(to_jsonb(subscription) - 'deleted_at')
|| jsonb_build_object(
    'status', CASE
        WHEN subscription.deleted_at IS NOT NULL THEN 'revoked'
        WHEN subscription.status = 'active' AND subscription.expires_at <= NOW() THEN 'expired'
        ELSE subscription.status
      END,
    'revoked_at', subscription.deleted_at,
    'notes', COALESCE(subscription.notes, ''),
    'daily_window_start', CASE
        WHEN subscription.daily_window_start IS NOT NULL
         AND subscription.expires_at > subscription.starts_at + INTERVAL '1 day'
         AND subscription.daily_window_start + INTERVAL '24 hours' <= NOW()
        THEN NULL ELSE subscription.daily_window_start END,
    'daily_usage_usd', CASE
        WHEN subscription.daily_window_start IS NOT NULL
         AND subscription.expires_at > subscription.starts_at + INTERVAL '1 day'
         AND subscription.daily_window_start + INTERVAL '24 hours' <= NOW()
        THEN 0 ELSE subscription.daily_usage_usd END,
    'weekly_window_start', CASE
        WHEN subscription.weekly_window_start IS NOT NULL
         AND subscription.weekly_window_start + INTERVAL '7 days' <= NOW()
        THEN NULL ELSE subscription.weekly_window_start END,
    'weekly_usage_usd', CASE
        WHEN subscription.weekly_window_start IS NOT NULL
         AND subscription.weekly_window_start + INTERVAL '7 days' <= NOW()
        THEN 0 ELSE subscription.weekly_usage_usd END,
    'monthly_window_start', CASE
        WHEN subscription.monthly_window_start IS NOT NULL
         AND subscription.monthly_window_start + INTERVAL '30 days' <= NOW()
        THEN NULL ELSE subscription.monthly_window_start END,
    'monthly_usage_usd', CASE
        WHEN subscription.monthly_window_start IS NOT NULL
         AND subscription.monthly_window_start + INTERVAL '30 days' <= NOW()
        THEN 0 ELSE subscription.monthly_usage_usd END
)
";

const SUBSCRIPTION_GET_JSON: &str = r"
(to_jsonb(subscription) - 'deleted_at')
|| jsonb_build_object(
    'revoked_at', subscription.deleted_at,
    'notes', COALESCE(subscription.notes, '')
)
";

async fn list_subscriptions(
    pool: &PgPool,
    query: &BTreeMap<String, String>,
) -> Result<Value, AdminError> {
    let page = query_positive_i64(query, "page").unwrap_or(1);
    let page_size = query_positive_i64(query, "page_size")
        .unwrap_or(20)
        .clamp(1, MAX_PAGE_SIZE);
    let user_id = query_positive_i64(query, "user_id");
    let group_id = query_positive_i64(query, "group_id");
    let status = trimmed_query(query, "status", 30);
    let platform = trimmed_query(query, "platform", 50);
    let sort_column = match query.get("sort_by").map(String::as_str) {
        Some("expires_at") => "subscription.expires_at",
        Some("status") => "subscription.status",
        _ => "subscription.created_at",
    };
    let direction = sort_direction(query);
    let where_clause = r"
WHERE ($1::bigint IS NULL OR subscription.user_id = $1)
  AND ($2::bigint IS NULL OR subscription.group_id = $2)
  AND ($4::text IS NULL OR subscription_group.platform = $4)
  AND (
       $3::text IS NULL
       OR ($3 = 'revoked' AND subscription.deleted_at IS NOT NULL)
       OR ($3 = 'active' AND subscription.deleted_at IS NULL
           AND subscription.status = 'active' AND subscription.expires_at > NOW())
       OR ($3 = 'expired' AND subscription.deleted_at IS NULL AND (
             subscription.status = 'expired'
             OR (subscription.status = 'active' AND subscription.expires_at <= NOW())
          ))
       OR ($3 NOT IN ('revoked', 'active', 'expired')
           AND subscription.deleted_at IS NULL AND subscription.status = $3)
  )
";
    let sql = format!(
        r"
SELECT ({SUBSCRIPTION_LIST_JSON}) || ({SUBSCRIPTION_RELATION_JSON}) AS data
FROM user_subscriptions subscription
{SUBSCRIPTION_RELATIONS}
{where_clause}
ORDER BY {sort_column} {direction}, subscription.id {direction}
LIMIT $5 OFFSET $6
"
    );
    let items = sqlx::query_scalar::<_, Value>(&sql)
        .bind(user_id)
        .bind(group_id)
        .bind(status.as_deref())
        .bind(platform.as_deref())
        .bind(page_size)
        .bind((page - 1) * page_size)
        .fetch_all(pool)
        .await?;
    let count_sql = format!(
        r"
SELECT COUNT(*)::bigint
FROM user_subscriptions subscription
{SUBSCRIPTION_RELATIONS}
{where_clause}
"
    );
    let total = sqlx::query_scalar::<_, i64>(&count_sql)
        .bind(user_id)
        .bind(group_id)
        .bind(status.as_deref())
        .bind(platform.as_deref())
        .fetch_one(pool)
        .await?;
    Ok(paginated(&items, total, page, page_size))
}

async fn get_subscription(pool: &PgPool, id: i64) -> Result<Value, AdminError> {
    let sql = format!(
        r"
SELECT ({SUBSCRIPTION_GET_JSON}) || ({SUBSCRIPTION_RELATION_JSON})
FROM user_subscriptions subscription
{SUBSCRIPTION_RELATIONS}
WHERE subscription.id = $1 AND subscription.deleted_at IS NULL
"
    );
    sqlx::query_scalar::<_, Value>(&sql)
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(AdminError::NotFound("subscription"))
}

// --- Shared validation and response helpers --------------------------------

const fn default_true() -> bool {
    true
}

fn default_match_mode() -> String {
    "any".to_owned()
}

fn parse_payload<T: DeserializeOwned>(payload: Value) -> Result<T, AdminError> {
    if !payload.is_object() {
        return Err(AdminError::BadRequest(
            "request body must be a JSON object".to_owned(),
        ));
    }
    serde_json::from_value(payload)
        .map_err(|error| AdminError::BadRequest(format!("invalid request: {error}")))
}

fn deserialize_null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

fn json_string<T: Serialize>(value: &T) -> Result<String, AdminError> {
    serde_json::to_string(value).map_err(|error| AdminError::BadRequest(error.to_string()))
}

fn parse_json_column<T: DeserializeOwned>(raw: &str) -> Result<T, AdminError> {
    serde_json::from_str(raw).map_err(|error| {
        AdminError::Probe(format!(
            "stored administrator resource JSON is invalid: {error}"
        ))
    })
}

fn normalize_string_list(
    values: Vec<String>,
    max_items: usize,
    max_chars: usize,
) -> Result<Vec<String>, AdminError> {
    if values.len() > max_items {
        return Err(AdminError::BadRequest(format!(
            "list must not contain more than {max_items} values"
        )));
    }
    values
        .into_iter()
        .map(|value| {
            if value.chars().count() > max_chars {
                Err(AdminError::BadRequest(format!(
                    "list values must not exceed {max_chars} characters"
                )))
            } else {
                Ok(value)
            }
        })
        .collect()
}

fn normalize_platforms(values: Vec<String>) -> Result<Vec<String>, AdminError> {
    normalize_string_list(values, 50, 50)
}

fn bounded_u16(values: Vec<u16>, field: &str) -> Result<Vec<u16>, AdminError> {
    if values.len() > 2_048 {
        return Err(AdminError::BadRequest(format!(
            "{field} must not contain more than 2048 values"
        )));
    }
    Ok(values)
}

fn apply_required_string_patch(target: &mut String, patch: Patch<String>) {
    if let Patch::Value(value) = patch {
        *target = value;
    }
}

fn apply_nullable_string_patch(
    target: &mut Option<String>,
    patch: Patch<String>,
    max_chars: usize,
) {
    if let Patch::Value(value) = patch {
        *target = trim_optional(Some(value), max_chars);
    }
}

fn apply_copy_patch<T: Copy>(target: &mut T, patch: &Patch<T>) {
    if let Patch::Value(value) = patch {
        *target = *value;
    }
}

fn apply_nullable_copy_patch<T: Copy>(target: &mut Option<T>, patch: &Patch<T>) {
    if let Patch::Value(value) = patch {
        *target = Some(*value);
    }
}

fn apply_vec_patch<T>(target: &mut Vec<T>, patch: Patch<Vec<T>>) {
    if let Patch::Value(value) = patch {
        *target = value;
    }
}

fn apply_string_vec_patch(
    target: &mut Vec<String>,
    patch: Patch<Vec<String>>,
    _field: &str,
    max_items: usize,
    max_chars: usize,
) -> Result<(), AdminError> {
    if let Patch::Value(value) = patch {
        *target = normalize_string_list(value, max_items, max_chars)?;
    }
    Ok(())
}

fn apply_u16_patch(
    target: &mut Vec<u16>,
    patch: Patch<Vec<u16>>,
    field: &str,
) -> Result<(), AdminError> {
    if let Patch::Value(value) = patch {
        *target = bounded_u16(value, field)?;
    }
    Ok(())
}

fn trim_optional(value: Option<String>, _max_chars: usize) -> Option<String> {
    value
}

async fn notify_settings(transaction: &mut Transaction<'_, Postgres>) -> Result<(), AdminError> {
    sqlx::query("SELECT pg_notify($1, $2)")
        .bind(INVALIDATION_CHANNEL)
        .bind(r#"{"version":1,"scope":"settings"}"#)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

fn audit_mutation(actor: &AdminIdentity, action: &str, resource: &str, resource_id: i64) {
    tracing::info!(
        actor_id = actor.user_id,
        actor_email = %actor.email,
        action,
        resource,
        resource_id,
        "administrator resource mutation"
    );
}

fn paginated(items: &[Value], total: i64, page: i64, page_size: i64) -> Value {
    json!({
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": ((total + page_size - 1) / page_size).max(1),
    })
}

fn query_positive_i64(query: &BTreeMap<String, String>, key: &str) -> Option<i64> {
    query
        .get(key)
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
}

fn trimmed_query(query: &BTreeMap<String, String>, key: &str, max_chars: usize) -> Option<String> {
    query
        .get(key)
        .map(|value| value.trim().chars().take(max_chars).collect::<String>())
        .filter(|value| !value.is_empty())
}

fn sort_direction(query: &BTreeMap<String, String>) -> &'static str {
    if query
        .get("sort_order")
        .is_some_and(|value| value.eq_ignore_ascii_case("asc"))
    {
        "ASC"
    } else {
        "DESC"
    }
}

#[cfg(test)]
mod tests {
    use sqlx::postgres::PgPoolOptions;

    use super::*;
    use crate::route_contract;

    #[test]
    fn dispatcher_claims_exactly_the_twenty_three_resource_routes() {
        assert_eq!(RESOURCE_HANDLERS.len(), 23);
        let owned = route_contract::routes()
            .filter(|route| RESOURCE_HANDLERS.contains(&route.handler))
            .collect::<Vec<_>>();
        assert_eq!(owned.len(), 23);
        assert!(
            owned
                .iter()
                .all(|route| route.category.starts_with("admin/"))
        );
    }

    #[test]
    fn error_rule_defaults_and_cross_field_validation_match_go() {
        let request: CreateErrorRuleRequest = parse_payload(json!({
            "name": "overload",
            "error_codes": [529]
        }))
        .unwrap();
        assert!(request.enabled);
        assert!(request.passthrough_code);
        assert!(request.passthrough_body);
        assert_eq!(request.match_mode, "any");
        let invalid = ErrorRuleState {
            name: "custom".to_owned(),
            enabled: true,
            priority: 0,
            error_codes: vec![500],
            keywords: Vec::new(),
            match_mode: "any".to_owned(),
            platforms: Vec::new(),
            passthrough_code: false,
            response_code: None,
            passthrough_body: true,
            custom_message: None,
            skip_monitoring: false,
            description: None,
        };
        assert!(validate_error_rule(&invalid).is_err());
    }

    #[test]
    fn tls_arrays_accept_null_and_preserve_order_and_duplicates() {
        let request: CreateTlsProfileRequest = parse_payload(json!({
            "name": "node",
            "cipher_suites": [4865, 4865, 4866],
            "curves": null
        }))
        .unwrap();
        assert_eq!(request.cipher_suites, vec![4865, 4865, 4866]);
        assert!(request.curves.is_empty());
        assert_eq!(
            bounded_u16(request.cipher_suites, "cipher_suites").unwrap(),
            vec![4865, 4865, 4866]
        );
    }

    #[test]
    fn scheduled_cron_is_five_field_and_next_run_is_minute_aligned() {
        let from = DateTime::<Utc>::from_timestamp(1_700_000_001, 0).unwrap();
        let next = CronSchedule::parse("*/15 * * * *")
            .unwrap()
            .next_after(from)
            .unwrap();
        assert!(next > from);
        assert_eq!(next.timestamp() % 60, 0);
        assert!(CronSchedule::parse("* * * * * *").is_err());
    }

    #[test]
    fn null_patch_keeps_go_pointer_semantics() {
        let mut status = "active".to_owned();
        apply_required_string_patch(&mut status, Patch::Null);
        assert_eq!(status, "active");
        let mut values = vec![1_u16, 2];
        apply_u16_patch(&mut values, Patch::Null, "values").unwrap();
        assert_eq!(values, vec![1, 2]);
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn postgres_error_rule_crud_applies_defaults_and_patch_semantics() {
        let database_url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL");
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .expect("connect PostgreSQL");
        let actor = AdminIdentity {
            user_id: 1,
            email: "admin@test.invalid".to_owned(),
        };
        let created = create_error_rule(
            &pool,
            &actor,
            json!({"name": "rust-pg-rule", "error_codes": [529]}),
        )
        .await
        .expect("create rule");
        let id = created["id"].as_i64().expect("rule id");
        assert_eq!(created["match_mode"], "any");
        let updated = update_error_rule(
            &pool,
            &actor,
            id,
            json!({"name": null, "priority": 7, "keywords": ["overload"]}),
        )
        .await
        .expect("update rule");
        assert_eq!(updated["name"], "rust-pg-rule");
        assert_eq!(updated["priority"], 7);
        delete_error_rule(&pool, &actor, id)
            .await
            .expect("delete rule");
    }
}
