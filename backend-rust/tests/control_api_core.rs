use std::{collections::HashMap, time::Duration};

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use sha2::Digest;
use sqlx::postgres::PgPoolOptions;
use sub2api_rust::control_api::{
    AUTH_RATE_LIMIT_DDL, AUTH_SECURITY_DDL, ApiKeyListQuery, ControlApiConfig, ControlApiState,
    LoginRateLimiter, PUBLIC_SETTING_KEYS, PublicRuntimeInfo, REFRESH_TOKENS_DDL,
    hash_refresh_token, public_settings_from_values, router, validate_custom_api_key,
    validate_ip_patterns,
};
use tower::ServiceExt;

#[test]
fn refresh_session_contract_is_postgres_only_and_hashes_raw_tokens() {
    let raw = format!("rt_{}", "ab".repeat(32));
    let digest = hash_refresh_token(&raw);
    assert_eq!(digest.len(), 32);
    assert_eq!(
        hex::encode(digest),
        hex::encode(sha2::Sha256::digest(raw.as_bytes()))
    );

    assert!(REFRESH_TOKENS_DDL.contains("auth_refresh_sessions"));
    assert!(REFRESH_TOKENS_DDL.contains("token_hash BYTEA"));
    assert!(REFRESH_TOKENS_DDL.contains("consumed_at"));
    assert!(REFRESH_TOKENS_DDL.contains("reuse_detected_at"));
    assert!(!REFRESH_TOKENS_DDL.to_lowercase().contains("redis"));
}

#[test]
fn local_auth_security_state_is_postgres_only_and_hash_only() {
    let sql = AUTH_SECURITY_DDL.to_ascii_lowercase();
    assert!(sql.contains("auth_generation"));
    assert!(sql.contains("auth_security_tokens"));
    assert!(sql.contains("token_hash bytea"));
    assert!(sql.contains("totp_setup"));
    assert!(sql.contains("password_reset"));
    assert!(!sql.contains("raw_token"));
    assert!(!sql.contains("redis"));

    let rate_sql = AUTH_RATE_LIMIT_DDL
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(rate_sql.contains("auth_rate_limit_windows"));
    assert!(rate_sql.contains("subject_hash bytea"));
    assert!(!rate_sql.contains("email"));
    assert!(!rate_sql.contains("redis"));
}

#[test]
fn api_key_and_ip_validation_rejects_unsafe_inputs() {
    assert!(validate_custom_api_key("sk-safe_key-1234567890").is_ok());
    assert_eq!(
        validate_custom_api_key("too-short")
            .expect_err("short keys must fail")
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert!(validate_custom_api_key("sk-invalid secret value").is_err());

    assert!(
        validate_ip_patterns(&[
            "127.0.0.1".to_owned(),
            "10.0.0.0/8".to_owned(),
            "2001:db8::/32".to_owned(),
        ])
        .is_ok()
    );
    assert!(validate_ip_patterns(&["10.0.0.999".to_owned()]).is_err());
}

#[test]
fn pagination_and_sorting_are_bounded_and_whitelisted() {
    let query = ApiKeyListQuery {
        page: Some(3),
        page_size: Some(50_000),
        sort_by: Some("key; DROP TABLE users".to_owned()),
        sort_order: Some("ASC".to_owned()),
        ..ApiKeyListQuery::default()
    };
    let pagination = query.pagination();
    assert_eq!(pagination.page, 3);
    assert_eq!(pagination.page_size, 1_000);
    assert_eq!(pagination.offset, 2_000);
    assert_eq!(query.order_by(), ("created_at", "ASC"));
}

#[test]
#[allow(clippy::too_many_lines)]
fn public_settings_have_an_exact_non_sensitive_response_surface() {
    assert!(
        PUBLIC_SETTING_KEYS
            .iter()
            .all(|key| !key.contains("secret") && *key != "admin_api_key")
    );
    let mut values = HashMap::from([
        ("site_name".to_owned(), "Rust Sub2API".to_owned()),
        ("email_verify_enabled".to_owned(), "true".to_owned()),
        ("password_reset_enabled".to_owned(), "true".to_owned()),
        (
            "registration_email_suffix_whitelist".to_owned(),
            json!(["@EXAMPLE.com", " example.com ", "*.EDU.CN", "@bad_domain"]).to_string(),
        ),
        ("table_default_page_size".to_owned(), "3".to_owned()),
        (
            "table_page_size_options".to_owned(),
            json!([1, 10, 20, 20, 5000]).to_string(),
        ),
        ("channel_monitor_enabled".to_owned(), "off".to_owned()),
        (
            "custom_menu_items".to_owned(),
            json!([
                {
                    "id": "user-docs",
                    "label": "Docs",
                    "icon_svg": "",
                    "url": "/docs",
                    "visibility": "user",
                    "sort_order": 1
                },
                {
                    "id": "admin-only",
                    "label": "Admin",
                    "icon_svg": "",
                    "url": "/admin",
                    "visibility": "admin",
                    "sort_order": 2
                }
            ])
            .to_string(),
        ),
    ]);
    values.insert("turnstile_secret_key".to_owned(), "super-secret".to_owned());
    values.insert("admin_api_key".to_owned(), "admin-secret".to_owned());
    let settings = public_settings_from_values(
        &values,
        &PublicRuntimeInfo {
            version: "test-version".to_owned(),
            server_timezone: "Asia/Shanghai".to_owned(),
            server_utc_offset: "+08:00".to_owned(),
        },
    );
    let json = serde_json::to_value(settings).expect("public settings should serialize");
    let object = json
        .as_object()
        .expect("public settings should be an object");
    let expected = [
        "registration_enabled",
        "email_verify_enabled",
        "force_email_on_third_party_signup",
        "registration_email_suffix_whitelist",
        "promo_code_enabled",
        "password_reset_enabled",
        "invitation_code_enabled",
        "totp_enabled",
        "login_agreement_enabled",
        "login_agreement_mode",
        "login_agreement_updated_at",
        "login_agreement_revision",
        "login_agreement_documents",
        "turnstile_enabled",
        "turnstile_site_key",
        "site_name",
        "site_logo",
        "site_subtitle",
        "api_base_url",
        "contact_info",
        "doc_url",
        "home_content",
        "hide_ccs_import_button",
        "purchase_subscription_enabled",
        "purchase_subscription_url",
        "table_default_page_size",
        "table_page_size_options",
        "custom_menu_items",
        "custom_endpoints",
        "dingtalk_oauth_enabled",
        "linuxdo_oauth_enabled",
        "wechat_oauth_enabled",
        "wechat_oauth_open_enabled",
        "wechat_oauth_mp_enabled",
        "wechat_oauth_mobile_enabled",
        "oidc_oauth_enabled",
        "oidc_oauth_provider_name",
        "github_oauth_enabled",
        "google_oauth_enabled",
        "sora_client_enabled",
        "backend_mode_enabled",
        "payment_enabled",
        "version",
        "server_timezone",
        "server_utc_offset",
        "balance_low_notify_enabled",
        "account_quota_notify_enabled",
        "balance_low_notify_threshold",
        "balance_low_notify_recharge_url",
        "channel_monitor_enabled",
        "channel_monitor_default_interval_seconds",
        "available_channels_enabled",
        "affiliate_enabled",
        "risk_control_enabled",
        "allow_user_view_error_requests",
    ];
    assert_eq!(object.len(), expected.len());
    for key in expected {
        assert!(object.contains_key(key), "missing public setting {key}");
    }
    let encoded = serde_json::to_string(object).expect("settings should encode");
    assert!(!encoded.contains("super-secret"));
    assert!(!encoded.contains("admin-secret"));
    assert_eq!(object["site_name"], "Rust Sub2API");
    assert_eq!(object["password_reset_enabled"], true);
    assert_eq!(
        object["custom_menu_items"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(
        object["registration_email_suffix_whitelist"],
        json!(["@example.com", "*.edu.cn"])
    );
    assert_eq!(object["table_default_page_size"], 20);
    assert_eq!(object["table_page_size_options"], json!([10, 20]));
    assert_eq!(object["channel_monitor_enabled"], false);
    assert_eq!(
        object["login_agreement_documents"][0]["title"],
        "\u{670d}\u{52a1}\u{6761}\u{6b3e}"
    );
}

#[test]
fn login_limiter_is_bounded_by_normalized_identity() {
    let limiter = LoginRateLimiter::new(2, Duration::from_mins(1));
    limiter.record_failure(" User@Example.com ");
    limiter.record_failure("user@example.com");
    assert!(limiter.is_limited("USER@EXAMPLE.COM"));
    limiter.clear("user@example.com");
    assert!(!limiter.is_limited("user@example.com"));
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn required_control_routes_are_mounted_and_use_the_go_error_envelope() {
    let pool = PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(10))
        .connect_lazy("postgresql://sub2api@127.0.0.1/sub2api")
        .expect("test PostgreSQL URL should be valid");
    let state = ControlApiState::new(
        pool,
        ControlApiConfig::new(b"0123456789abcdef0123456789abcdef".to_vec()),
    )
    .expect("test control state should build");
    let app = router(state);

    let cases = [
        ("GET", "/api/v1/auth/me", None, StatusCode::UNAUTHORIZED),
        (
            "POST",
            "/api/v1/auth/refresh",
            Some(json!({"refresh_token":"invalid"})),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "POST",
            "/api/v1/auth/login",
            Some(json!({"email":"invalid","password":"secret"})),
            StatusCode::BAD_REQUEST,
        ),
        (
            "POST",
            "/api/v1/auth/register",
            Some(json!({"email":"invalid","password":"secret"})),
            StatusCode::BAD_REQUEST,
        ),
        (
            "POST",
            "/api/v1/auth/login/2fa",
            Some(json!({"temp_token":"invalid","totp_code":"123456"})),
            StatusCode::BAD_REQUEST,
        ),
        (
            "POST",
            "/api/v1/auth/forgot-password",
            Some(json!({"email":"invalid"})),
            StatusCode::BAD_REQUEST,
        ),
        (
            "POST",
            "/api/v1/auth/reset-password",
            Some(json!({"email":"invalid","token":"bad","new_password":"secret"})),
            StatusCode::BAD_REQUEST,
        ),
        (
            "GET",
            "/api/v1/user/profile",
            None,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "PUT",
            "/api/v1/user",
            Some(json!({"username":"new-name"})),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "PUT",
            "/api/v1/user/password",
            Some(json!({"old_password":"old","new_password":"new-secret"})),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "POST",
            "/api/v1/auth/revoke-all-sessions",
            None,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "GET",
            "/api/v1/user/totp/status",
            None,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "POST",
            "/api/v1/user/totp/setup",
            Some(json!({"password":"secret"})),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "POST",
            "/api/v1/user/totp/enable",
            Some(json!({"totp_code":"123456","setup_token":"invalid"})),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "POST",
            "/api/v1/user/totp/disable",
            Some(json!({"password":"secret"})),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "GET",
            "/api/v1/user/api-keys",
            None,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "POST",
            "/api/v1/user/api-keys",
            Some(json!({"name":"test"})),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "PUT",
            "/api/v1/user/api-keys",
            Some(json!({"id":1,"name":"test"})),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "DELETE",
            "/api/v1/user/api-keys?id=1",
            None,
            StatusCode::UNAUTHORIZED,
        ),
    ];

    for (method, uri, body, expected_status) in cases {
        let body = body.map_or_else(Body::empty, |value| Body::from(value.to_string()));
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(body)
            .expect("request should build");
        let response = app
            .clone()
            .oneshot(request)
            .await
            .expect("router should respond");
        assert_eq!(response.status(), expected_status, "{method} {uri}");
        let body = axum::body::to_bytes(response.into_body(), 8_192)
            .await
            .expect("response body should be readable");
        let envelope: Value = serde_json::from_slice(&body).expect("response should be JSON");
        assert_eq!(envelope["code"], u64::from(expected_status.as_u16()));
        assert!(envelope["message"].is_string());
    }

    let malformed_login = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header("content-type", "application/json")
        .body(Body::from("{"))
        .expect("request should build");
    let response = app
        .clone()
        .oneshot(malformed_login)
        .await
        .expect("router should respond");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), 8_192)
        .await
        .expect("response body should be readable");
    let envelope: Value = serde_json::from_slice(&body).expect("response should be JSON");
    assert_eq!(envelope["code"], 400);

    let malformed_protected = Request::builder()
        .method("POST")
        .uri("/api/v1/user/api-keys")
        .header("content-type", "application/json")
        .body(Body::from("{"))
        .expect("request should build");
    let response = app
        .oneshot(malformed_protected)
        .await
        .expect("router should respond");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
