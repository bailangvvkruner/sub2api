#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Method, Request},
};
use sqlx::postgres::PgPoolOptions;
use sub2api_rust::admin_api::{AdminApi, AdminService, Hs256AdminTokenVerifier, PasswordHasher};
use tower::ServiceExt;

struct TestHasher;

impl PasswordHasher for TestHasher {
    fn hash_password(&self, password: &str) -> Result<String, String> {
        Ok(format!("hashed:{password}"))
    }
}

#[tokio::test]
async fn all_content_routes_are_mounted_behind_admin_authentication() {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1:9/unused")
        .unwrap();
    let service = AdminService::new(pool, Arc::new(TestHasher));
    let verifier = Arc::new(
        Hs256AdminTokenVerifier::new(b"content-contract-secret-that-is-long-enough").unwrap(),
    );
    let router = AdminApi::new(service, verifier).router();
    let route_cases = [
        (Method::GET, "/api/v1/admin/announcements"),
        (Method::POST, "/api/v1/admin/announcements"),
        (Method::GET, "/api/v1/admin/announcements/1"),
        (Method::PUT, "/api/v1/admin/announcements/1"),
        (Method::DELETE, "/api/v1/admin/announcements/1"),
        (Method::GET, "/api/v1/admin/announcements/1/read-status"),
        (Method::GET, "/api/v1/admin/channels"),
        (Method::POST, "/api/v1/admin/channels"),
        (
            Method::GET,
            "/api/v1/admin/channels/model-pricing?model=test",
        ),
        (
            Method::GET,
            "/api/v1/admin/channels/pricing/sync-models?platform=openai",
        ),
        (Method::GET, "/api/v1/admin/channels/1"),
        (Method::PUT, "/api/v1/admin/channels/1"),
        (Method::DELETE, "/api/v1/admin/channels/1"),
        (Method::GET, "/api/v1/admin/channel-monitors"),
        (Method::POST, "/api/v1/admin/channel-monitors"),
        (Method::GET, "/api/v1/admin/channel-monitors/1"),
        (Method::PUT, "/api/v1/admin/channel-monitors/1"),
        (Method::DELETE, "/api/v1/admin/channel-monitors/1"),
        (Method::POST, "/api/v1/admin/channel-monitors/1/run"),
        (Method::GET, "/api/v1/admin/channel-monitors/1/history"),
        (Method::GET, "/api/v1/admin/channel-monitor-templates"),
        (Method::POST, "/api/v1/admin/channel-monitor-templates"),
        (Method::GET, "/api/v1/admin/channel-monitor-templates/1"),
        (Method::PUT, "/api/v1/admin/channel-monitor-templates/1"),
        (Method::DELETE, "/api/v1/admin/channel-monitor-templates/1"),
        (
            Method::GET,
            "/api/v1/admin/channel-monitor-templates/1/monitors",
        ),
        (
            Method::POST,
            "/api/v1/admin/channel-monitor-templates/1/apply",
        ),
    ];

    assert_eq!(route_cases.len(), 27);
    for (method, uri) in route_cases {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 401, "route {uri} bypassed admin auth");
    }
}
