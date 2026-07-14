#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Method, Request},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::json;
use sha2::Sha256;
use sqlx::postgres::PgPoolOptions;
use sub2api_rust::admin_api::{
    self, ACCOUNT_SOFT_DELETE_SQL, API_KEY_SOFT_DELETE_SQL, AdminApi, AdminTokenVerifier,
    GROUP_SOFT_DELETE_SQL, Hs256AdminTokenVerifier, PROXY_SOFT_DELETE_SQL, PasswordHasher, Patch,
    USER_SOFT_DELETE_SQL, merge_credentials, redact_credentials, validate_public_probe_target,
};
use tower::ServiceExt;

const SECRET: &[u8] = b"a-test-secret-that-is-at-least-thirty-two-bytes-long";

struct TestHasher;

impl PasswordHasher for TestHasher {
    fn hash_password(&self, password: &str) -> Result<String, String> {
        Ok(format!("hashed:{password}"))
    }
}

#[test]
fn missing_sensitive_credentials_are_preserved() {
    let existing = json!({
        "access_token": "access-secret",
        "refresh_token": "refresh-secret",
        "region": "old",
        "removable": true
    });
    let incoming = json!({"region": "new"});

    let merged = merge_credentials(&existing, &incoming);

    assert_eq!(merged["access_token"], "access-secret");
    assert_eq!(merged["refresh_token"], "refresh-secret");
    assert_eq!(merged["region"], "new");
    assert!(merged.get("removable").is_none());
}

#[test]
fn explicit_sensitive_credentials_replace_existing_values() {
    let existing = json!({"api_key": "old", "cookie": "old-cookie"});
    let incoming = json!({"api_key": "new", "cookie": null});

    let merged = merge_credentials(&existing, &incoming);

    assert_eq!(merged["api_key"], "new");
    assert!(merged["cookie"].is_null());
}

#[test]
fn credential_responses_are_redacted_with_presence_flags() {
    let credentials = json!({
        "access_token": "secret",
        "refresh_token": "",
        "private_key": "pem",
        "region": "us-east-1"
    });

    let (redacted, status) = redact_credentials(&credentials);

    assert_eq!(redacted, json!({"region": "us-east-1"}));
    assert_eq!(status.get("has_access_token"), Some(&true));
    assert_eq!(status.get("has_private_key"), Some(&true));
    assert!(!status.contains_key("has_refresh_token"));
    assert!(!redacted.to_string().contains("secret"));
}

#[test]
fn all_delete_statements_are_guarded_soft_deletes() {
    for sql in [
        USER_SOFT_DELETE_SQL,
        GROUP_SOFT_DELETE_SQL,
        ACCOUNT_SOFT_DELETE_SQL,
        PROXY_SOFT_DELETE_SQL,
        API_KEY_SOFT_DELETE_SQL,
    ] {
        let normalized = sql.to_ascii_lowercase();
        assert!(normalized.contains("deleted_at = now()"));
        assert!(normalized.contains("where id = $1"));
        assert!(normalized.contains("deleted_at is null"));
        assert!(!normalized.starts_with("delete from"));
    }
}

#[derive(Debug, Deserialize, PartialEq)]
struct PatchFixture {
    #[serde(default)]
    value: Patch<String>,
}

#[test]
fn patch_distinguishes_missing_null_and_value() {
    let missing: PatchFixture = serde_json::from_value(json!({})).unwrap();
    let null: PatchFixture = serde_json::from_value(json!({"value": null})).unwrap();
    let value: PatchFixture = serde_json::from_value(json!({"value": "set"})).unwrap();

    assert_eq!(missing.value, Patch::Missing);
    assert_eq!(null.value, Patch::Null);
    assert_eq!(value.value, Patch::Value("set".to_owned()));
}

#[test]
fn jwt_signature_tampering_is_rejected() {
    let verifier = Hs256AdminTokenVerifier::new(SECRET).unwrap();
    let token = signed_token("admin");
    assert!(verifier.verify(&token).is_ok());

    let mut tampered = token.into_bytes();
    let last = tampered.last_mut().unwrap();
    *last = if *last == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(tampered).unwrap();
    assert!(verifier.verify(&tampered).is_err());
}

#[tokio::test]
async fn non_admin_jwt_is_rejected_before_database_access() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1:9/unused")
        .unwrap();
    let service = admin_api::AdminService::new(pool, Arc::new(TestHasher));
    let verifier = Arc::new(Hs256AdminTokenVerifier::new(SECRET).unwrap());
    let router = AdminApi::new(service, verifier).router();
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/users")
                .header("authorization", format!("Bearer {}", signed_token("user")))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 403);
}

#[tokio::test]
async fn affiliate_contract_routes_reject_non_admin_before_database_access() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1:9/unused")
        .unwrap();
    let service = admin_api::AdminService::new(pool, Arc::new(TestHasher));
    let verifier = Arc::new(Hs256AdminTokenVerifier::new(SECRET).unwrap());
    let router = AdminApi::new(service, verifier).router();
    for (method, path) in [
        (Method::GET, "/api/v1/admin/affiliates/invites"),
        (Method::GET, "/api/v1/admin/affiliates/rebates"),
        (Method::GET, "/api/v1/admin/affiliates/transfers"),
        (Method::GET, "/api/v1/admin/affiliates/users"),
        (Method::GET, "/api/v1/admin/affiliates/users/lookup"),
        (Method::POST, "/api/v1/admin/affiliates/users/batch-rate"),
        (Method::GET, "/api/v1/admin/affiliates/users/1/overview"),
        (Method::PUT, "/api/v1/admin/affiliates/users/1"),
        (Method::DELETE, "/api/v1/admin/affiliates/users/1"),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("authorization", format!("Bearer {}", signed_token("user")))
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 403, "{path}");
    }
}

#[tokio::test]
async fn ssrf_validation_rejects_local_targets_without_network_access() {
    assert!(
        validate_public_probe_target("http://127.0.0.1/admin")
            .await
            .is_err()
    );
    assert!(
        validate_public_probe_target("http://10.20.30.40/internal")
            .await
            .is_err()
    );
    assert!(
        validate_public_probe_target("http://localhost/metrics")
            .await
            .is_err()
    );
    assert!(
        validate_public_probe_target("file:///etc/passwd")
            .await
            .is_err()
    );
}

fn signed_token(role: &str) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "user_id": 1,
            "email": "admin@example.com",
            "role": role,
            "token_version": 1,
            "exp": 4_102_444_800_i64
        }))
        .unwrap(),
    );
    let signing_input = format!("{header}.{payload}");
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET).unwrap();
    mac.update(signing_input.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{signing_input}.{signature}")
}
