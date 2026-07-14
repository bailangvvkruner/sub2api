use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Instant,
};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{ConnectInfo, FromRequestParts, State, ws::WebSocketUpgrade},
    http::{HeaderName, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use ipnet::IpNet;
use serde::Serialize;
use serde_json::json;
use sqlx::PgPool;
use tower_http::{
    catch_panic::CatchPanicLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
};

use crate::{
    batch_image::BatchImageService,
    database,
    frontend::FrontendAssets,
    gateway::GatewayRuntime,
    setup::{self, InstallRequest, SetupDatabaseConfig, SetupError},
};

const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

#[derive(Clone)]
pub struct AppState {
    pool: PgPool,
    started_at: Instant,
    gateway: Option<GatewayRuntime>,
    batch_images: Option<BatchImageService>,
    max_request_body_bytes: usize,
    trust_proxy_headers: bool,
    trusted_proxy_networks: Vec<IpNet>,
    cors_policy: Arc<CorsPolicy>,
    frontend: Option<FrontendAssets>,
    setup_database_url: Option<Arc<str>>,
}

impl AppState {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            started_at: Instant::now(),
            gateway: None,
            batch_images: None,
            max_request_body_bytes: 256 * 1024 * 1024,
            trust_proxy_headers: false,
            trusted_proxy_networks: Vec::new(),
            cors_policy: Arc::new(CorsPolicy::from_env()),
            frontend: None,
            setup_database_url: None,
        }
    }

    #[must_use]
    pub fn with_gateway(mut self, gateway: GatewayRuntime) -> Self {
        self.gateway = Some(gateway);
        self
    }

    #[must_use]
    pub fn with_batch_images(mut self, batch_images: BatchImageService) -> Self {
        self.batch_images = Some(batch_images);
        self
    }

    #[must_use]
    pub const fn with_request_body_limit(mut self, bytes: usize) -> Self {
        self.max_request_body_bytes = bytes;
        self
    }

    #[must_use]
    pub const fn with_trusted_proxy_headers(mut self, enabled: bool) -> Self {
        self.trust_proxy_headers = enabled;
        self
    }

    #[must_use]
    pub fn with_trusted_proxy_networks(mut self, networks: Vec<IpNet>) -> Self {
        self.trusted_proxy_networks = networks;
        self
    }

    #[must_use]
    pub fn with_cors_policy(
        mut self,
        allowed_origins: Vec<String>,
        allow_credentials: bool,
    ) -> Self {
        self.cors_policy = Arc::new(CorsPolicy::new(allowed_origins, allow_credentials));
        self
    }

    #[must_use]
    pub fn with_frontend(mut self, frontend: FrontendAssets) -> Self {
        self.frontend = Some(frontend);
        self
    }

    #[must_use]
    pub fn with_setup_database_url(mut self, url: impl Into<Arc<str>>) -> Self {
        self.setup_database_url = Some(url.into());
        self
    }
}

pub fn router(state: AppState) -> Router {
    router_with_control(state, None)
}

pub fn router_with_control(state: AppState, control: Option<Router>) -> Router {
    let middleware_state = state.clone();
    let app = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/setup/status", get(setup_status))
        .route("/setup/test-db", post(setup_test_database))
        .route("/setup/install", post(setup_install))
        .route("/api/event_logging/batch", post(ignore_event_log_batch))
        .route(
            "/v1/responses",
            get(responses_websocket).post(gateway_or_not_found),
        )
        .route(
            "/responses",
            get(responses_websocket).post(gateway_or_not_found),
        )
        .route(
            "/openai/v1/responses",
            get(responses_websocket).post(gateway_or_not_found),
        )
        .route(
            "/backend-api/codex/responses",
            get(responses_websocket).post(gateway_or_not_found),
        )
        .route(
            "/v1/images/batches",
            get(batch_image_or_unavailable).post(batch_image_or_unavailable),
        )
        .route("/v1/images/batches/models", get(batch_image_or_unavailable))
        .route(
            "/v1/images/batches/{id}",
            get(batch_image_or_unavailable).delete(batch_image_or_unavailable),
        )
        .route(
            "/v1/images/batches/{id}/items",
            get(batch_image_or_unavailable),
        )
        .route(
            "/v1/images/batches/{id}/items/{custom_id}/content",
            get(batch_image_or_unavailable),
        )
        .route(
            "/v1/images/batches/{id}/download",
            get(batch_image_or_unavailable),
        )
        .route(
            "/v1/images/batches/{id}/cancel",
            post(batch_image_or_unavailable),
        )
        .route(
            "/v1/images/batches/{id}/outputs",
            axum::routing::delete(batch_image_or_unavailable),
        )
        .fallback(gateway_or_not_found)
        .with_state(state);
    let app = if let Some(control) = control {
        app.merge(control)
    } else {
        app
    };
    app.layer(
        TraceLayer::new_for_http().make_span_with(|request: &Request<Body>| {
            tracing::info_span!(
                "http.request",
                method = %request.method(),
                path = %request.uri().path(),
                request_id = ?request.headers().get(&REQUEST_ID_HEADER),
            )
        }),
    )
    .layer(CatchPanicLayer::new())
    .layer(middleware::from_fn_with_state(
        middleware_state,
        cors_and_security_headers,
    ))
    .layer(PropagateRequestIdLayer::new(REQUEST_ID_HEADER))
    .layer(SetRequestIdLayer::new(REQUEST_ID_HEADER, MakeRequestUuid))
}

async fn cors_and_security_headers(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let origin = request
        .headers()
        .get(axum::http::header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let origin_allowed = origin
        .as_deref()
        .is_some_and(|origin| state.cors_policy.allows(origin));
    if request.method() == axum::http::Method::OPTIONS {
        if !origin_allowed {
            return StatusCode::FORBIDDEN.into_response();
        }
        let mut response = StatusCode::NO_CONTENT.into_response();
        apply_cors_headers(&mut response, origin.as_deref(), &state.cors_policy);
        apply_security_headers(&mut response);
        return response;
    }

    let mut response = next.run(request).await;
    if origin_allowed {
        apply_cors_headers(&mut response, origin.as_deref(), &state.cors_policy);
    }
    apply_security_headers(&mut response);
    response
}

fn apply_security_headers(response: &mut Response) {
    for (name, value) in [
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "strict-origin-when-cross-origin"),
        (
            "permissions-policy",
            "camera=(), microphone=(), geolocation=()",
        ),
    ] {
        response.headers_mut().insert(
            HeaderName::from_static(name),
            value.parse().expect("static security header is valid"),
        );
    }
}

#[derive(Debug)]
struct CorsPolicy {
    allowed_origins: HashSet<String>,
    allow_all: bool,
    allow_credentials: bool,
}

impl CorsPolicy {
    fn new(values: Vec<String>, requested_credentials: bool) -> Self {
        let mut allowed_origins = HashSet::new();
        let mut allow_all = false;
        for value in values {
            if value == "*" {
                allow_all = true;
            } else {
                allowed_origins.insert(value);
            }
        }
        Self {
            allowed_origins,
            allow_all,
            allow_credentials: requested_credentials && !allow_all,
        }
    }

    fn from_env() -> Self {
        let values = std::env::var("CORS_ALLOWED_ORIGINS").unwrap_or_default();
        let values = values
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        let requested_credentials = std::env::var("CORS_ALLOW_CREDENTIALS").map_or(true, |value| {
            !matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "off"
            )
        });
        Self::new(values, requested_credentials)
    }

    fn allows(&self, origin: &str) -> bool {
        self.allow_all || self.allowed_origins.contains(origin)
    }
}

fn apply_cors_headers(response: &mut Response, origin: Option<&str>, policy: &CorsPolicy) {
    let headers = response.headers_mut();
    if policy.allow_all {
        headers.insert(
            axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
            axum::http::HeaderValue::from_static("*"),
        );
    } else if let Some(origin) = origin
        && let Ok(origin) = axum::http::HeaderValue::from_str(origin)
    {
        headers.insert(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        headers.append(
            axum::http::header::VARY,
            axum::http::HeaderValue::from_static("Origin"),
        );
    }
    if policy.allow_credentials {
        headers.insert(
            axum::http::header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            axum::http::HeaderValue::from_static("true"),
        );
    }
    headers.insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_METHODS,
        axum::http::HeaderValue::from_static("POST, OPTIONS, GET, PUT, DELETE, PATCH"),
    );
    headers.insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_HEADERS,
        axum::http::HeaderValue::from_static(
            "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, X-API-Key, X-Request-ID, Anthropic-Version, Anthropic-Beta, X-Goog-API-Key, x-stainless-lang, x-stainless-package-version, x-stainless-os, x-stainless-arch, x-stainless-retry-count, x-stainless-runtime, x-stainless-runtime-version, x-stainless-async, x-stainless-helper-method, x-stainless-poll-helper, x-stainless-custom-poll-interval, x-stainless-timeout",
        ),
    );
    headers.insert(
        axum::http::header::ACCESS_CONTROL_EXPOSE_HEADERS,
        axum::http::HeaderValue::from_static("ETag"),
    );
    headers.insert(
        axum::http::header::ACCESS_CONTROL_MAX_AGE,
        axum::http::HeaderValue::from_static("86400"),
    );
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

#[derive(Serialize)]
struct ReadinessBody {
    status: &'static str,
    postgres: &'static str,
    uptime_seconds: u64,
}

async fn ready(State(state): State<AppState>) -> Response {
    let uptime_seconds = state.started_at.elapsed().as_secs();
    match database::ping(&state.pool).await {
        Ok(()) => (
            StatusCode::OK,
            Json(ReadinessBody {
                status: "ready",
                postgres: "ok",
                uptime_seconds,
            }),
        )
            .into_response(),
        Err(error) => {
            tracing::warn!(error = %error, "PostgreSQL readiness check failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ReadinessBody {
                    status: "not_ready",
                    postgres: "unavailable",
                    uptime_seconds,
                }),
            )
                .into_response()
        }
    }
}

async fn setup_status(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, SetupError> {
    let status = setup::status(&state.pool).await?;
    Ok(Json(json!({
        "code": 0,
        "data": status
    })))
}

async fn setup_test_database(
    State(state): State<AppState>,
    Json(config): Json<SetupDatabaseConfig>,
) -> Result<Json<serde_json::Value>, SetupError> {
    let result = setup::test_database(&state.pool, config).await?;
    Ok(Json(json!({"code": 0, "data": result})))
}

async fn setup_install(
    State(state): State<AppState>,
    Json(request): Json<InstallRequest>,
) -> Result<Json<serde_json::Value>, SetupError> {
    setup::require_setup(&state.pool).await?;
    let result = setup::install_isolated(
        request,
        state.setup_database_url.as_deref().map(ToOwned::to_owned),
    )
    .await?;
    Ok(Json(json!({"code": 0, "data": result})))
}

async fn ignore_event_log_batch() -> StatusCode {
    StatusCode::OK
}

async fn gateway_or_not_found(State(state): State<AppState>, request: Request<Body>) -> Response {
    let request_path = request.uri().path().to_owned();
    if let Some(gateway) = &state.gateway {
        let (parts, body) = request.into_parts();
        let client_ip = client_ip(
            &parts,
            state.trust_proxy_headers,
            &state.trusted_proxy_networks,
        );
        let Ok(body) = to_bytes(body, state.max_request_body_bytes).await else {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({
                    "error": {
                        "type": "invalid_request_error",
                        "message": "request body is too large"
                    }
                })),
            )
                .into_response();
        };
        if let Some(response) = gateway
            .try_handle(
                parts.method,
                parts.uri,
                parts.headers,
                body,
                client_ip.as_deref(),
            )
            .await
        {
            return response;
        }
    }
    if let Some(frontend) = &state.frontend
        && let Some(response) = frontend.try_serve(&request_path).await
    {
        return response;
    }
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "error": {
                "type": "not_found_error",
                "message": "route not found"
            }
        })),
    )
        .into_response()
}

async fn responses_websocket(State(state): State<AppState>, request: Request<Body>) -> Response {
    let Some(gateway) = &state.gateway else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": {
                    "type": "server_error",
                    "message": "gateway is unavailable"
                }
            })),
        )
            .into_response();
    };
    let (mut parts, _) = request.into_parts();
    let client_ip = client_ip(
        &parts,
        state.trust_proxy_headers,
        &state.trusted_proxy_networks,
    );
    let upgrade = match WebSocketUpgrade::from_request_parts(&mut parts, &state).await {
        Ok(upgrade) => upgrade,
        Err(error) => return error.into_response(),
    };
    gateway
        .responses_websocket(upgrade, parts.uri, parts.headers, client_ip)
        .await
}

async fn batch_image_or_unavailable(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    let Some(batch_images) = &state.batch_images else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": {
                    "type": "invalid_request_error",
                    "code": "BATCH_IMAGE_DISABLED",
                    "message": "batch image service is unavailable"
                }
            })),
        )
            .into_response();
    };
    let (parts, body) = request.into_parts();
    let client_ip = client_ip(
        &parts,
        state.trust_proxy_headers,
        &state.trusted_proxy_networks,
    );
    let Ok(body) = to_bytes(body, state.max_request_body_bytes).await else {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({
                "error": {
                    "type": "invalid_request_error",
                    "code": "BATCH_IMAGE_INVALID_ITEMS",
                    "message": "request body is too large"
                }
            })),
        )
            .into_response();
    };
    batch_images
        .handle(
            parts.method,
            parts.uri,
            parts.headers,
            body,
            client_ip.as_deref(),
        )
        .await
}

fn client_ip(
    parts: &axum::http::request::Parts,
    trust_proxy_headers: bool,
    trusted_proxy_networks: &[IpNet],
) -> Option<String> {
    let peer_ip = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(address)| address.ip());
    let peer_is_trusted = trust_proxy_headers
        && (trusted_proxy_networks.is_empty()
            || peer_ip.is_some_and(|peer| {
                trusted_proxy_networks
                    .iter()
                    .any(|network| network.contains(&peer))
            }));
    if peer_is_trusted {
        if let Some(forwarded) = parts
            .headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
        {
            let chain = forwarded
                .split(',')
                .filter_map(|value| value.trim().parse::<IpAddr>().ok())
                .collect::<Vec<_>>();
            if trusted_proxy_networks.is_empty() {
                if let Some(client) = chain.first() {
                    return Some(client.to_string());
                }
            } else if let Some(client) = chain.iter().rev().find(|candidate| {
                !trusted_proxy_networks
                    .iter()
                    .any(|network| network.contains(*candidate))
            }) {
                return Some(client.to_string());
            } else if let Some(client) = chain.first() {
                return Some(client.to_string());
            }
        }
        if let Some(ip) = parts
            .headers
            .get("x-real-ip")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<IpAddr>().ok())
        {
            return Some(ip.to_string());
        }
    }
    peer_ip.map(|ip| ip.to_string())
}

#[cfg(test)]
mod tests {
    use axum::{body::to_bytes, http::Request};
    use serde_json::Value;
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    use super::*;

    fn test_app() -> Router {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://sub2api@127.0.0.1/sub2api")
            .expect("test PostgreSQL URL should be valid");
        router(AppState::new(pool))
    }

    fn test_app_with_cors(origins: Vec<String>, credentials: bool) -> Router {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://sub2api@127.0.0.1/sub2api")
            .expect("test PostgreSQL URL should be valid");
        router(AppState::new(pool).with_cors_policy(origins, credentials))
    }

    fn forwarded_request(peer: &str, forwarded: &str) -> axum::http::request::Parts {
        let address: SocketAddr = peer.parse().expect("peer address should parse");
        let request = Request::builder()
            .header("x-forwarded-for", forwarded)
            .extension(ConnectInfo(address))
            .body(Body::empty())
            .expect("request should build");
        request.into_parts().0
    }

    #[test]
    fn forwarded_ip_requires_a_trusted_direct_peer() {
        let trusted = vec!["10.0.0.0/8".parse::<IpNet>().unwrap()];
        let untrusted = forwarded_request("203.0.113.9:443", "198.51.100.7");
        assert_eq!(
            client_ip(&untrusted, true, &trusted).as_deref(),
            Some("203.0.113.9")
        );

        let proxied = forwarded_request("10.0.0.9:443", "198.51.100.7, 10.0.0.8");
        assert_eq!(
            client_ip(&proxied, true, &trusted).as_deref(),
            Some("198.51.100.7")
        );
    }

    #[test]
    fn explicit_trust_all_retains_legacy_first_forwarded_behavior() {
        let proxied = forwarded_request("10.0.0.9:443", "198.51.100.7, 10.0.0.8");
        assert_eq!(
            client_ip(&proxied, true, &[]).as_deref(),
            Some("198.51.100.7")
        );
    }

    #[tokio::test]
    async fn configured_cors_policy_is_applied_without_global_environment_state() {
        let response = test_app_with_cors(vec!["https://console.example".to_owned()], true)
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .header("origin", "https://console.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "https://console.example"
        );
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .unwrap(),
            "true"
        );

        let wildcard = test_app_with_cors(vec!["*".to_owned()], true)
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .header("origin", "https://any.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            wildcard
                .headers()
                .get(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "*"
        );
        assert!(
            wildcard
                .headers()
                .get(axum::http::header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .is_none()
        );
    }

    #[tokio::test]
    async fn health_matches_the_go_contract() {
        let response = test_app()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key(REQUEST_ID_HEADER));
        assert_eq!(
            response.headers().get("x-content-type-options").unwrap(),
            "nosniff"
        );
        let body = to_bytes(response.into_body(), 1024)
            .await
            .expect("body should be readable");
        let json: Value = serde_json::from_slice(&body).expect("body should be JSON");
        assert_eq!(json, json!({ "status": "ok" }));
    }

    #[tokio::test]
    async fn setup_status_matches_the_frontend_contract() {
        let response = test_app()
            .oneshot(
                Request::builder()
                    .uri("/setup/status")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 2048)
            .await
            .expect("body should be readable");
        let json: Value = serde_json::from_slice(&body).expect("body should be JSON");
        assert_eq!(json["data"]["needs_setup"], false);
        assert_eq!(json["data"]["step"], "completed");
    }

    #[tokio::test]
    async fn normal_mode_blocks_setup_writes_and_exposes_no_redis_probe() {
        if crate::setup::setup_mode_enabled() {
            return;
        }
        let database = r#"{
            "host":"localhost",
            "port":5432,
            "user":"sub2api",
            "password":"",
            "dbname":"sub2api",
            "sslmode":"disable"
        }"#;
        let response = test_app()
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/setup/test-db")
                    .header("content-type", "application/json")
                    .body(Body::from(database))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = test_app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/setup/test-redis")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn gateway_routes_are_explicitly_unavailable_without_runtime() {
        let response = test_app()
            .oneshot(
                Request::builder()
                    .uri("/v1/messages")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
