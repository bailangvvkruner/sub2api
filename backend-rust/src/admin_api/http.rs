#![allow(clippy::too_many_lines)]

use std::sync::Arc;

use axum::{
    Extension, Json, Router,
    extract::{Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header::AUTHORIZATION},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Serialize;
use serde_json::{Value, json};

use super::{
    auth::AdminTokenVerifier,
    compliance,
    models::{
        AdminError, AdminIdentity, CreateAccountRequest, CreateApiKeyRequest, CreateGroupRequest,
        CreateProxyRequest, CreateUserRequest, InvalidationKey, Mutation, PageQuery,
        SettingPatchRequest, UpdateAccountRequest, UpdateApiKeyRequest, UpdateGroupRequest,
        UpdateProxyRequest, UpdateUserRequest,
    },
    service::AdminService,
};

#[derive(Clone)]
pub struct AdminApiState {
    pub service: AdminService,
    verifier: Arc<dyn AdminTokenVerifier>,
}

impl AdminApiState {
    #[must_use]
    pub fn new(service: AdminService, verifier: Arc<dyn AdminTokenVerifier>) -> Self {
        Self { service, verifier }
    }
}

#[derive(Clone)]
pub struct AdminApi {
    state: AdminApiState,
}

impl AdminApi {
    #[must_use]
    pub fn new(service: AdminService, verifier: Arc<dyn AdminTokenVerifier>) -> Self {
        Self {
            state: AdminApiState::new(service, verifier),
        }
    }

    pub fn router(&self) -> Router {
        let state = self.state.clone();
        Router::new()
            .merge(super::affiliates::router())
            .merge(super::content::router())
            .merge(super::compat::router())
            .merge(super::ops_ws::router())
            .route("/api/v1/admin/users", get(list_users).post(create_user))
            .route(
                "/api/v1/admin/users/{id}",
                get(get_user).put(update_user).delete(delete_user),
            )
            .route("/api/v1/admin/groups", get(list_groups).post(create_group))
            .route(
                "/api/v1/admin/groups/{id}",
                get(get_group).put(update_group).delete(delete_group),
            )
            .route(
                "/api/v1/admin/accounts",
                get(list_accounts).post(create_account),
            )
            .route(
                "/api/v1/admin/accounts/{id}",
                get(get_account).put(update_account).delete(delete_account),
            )
            .route("/api/v1/admin/accounts/{id}/test", post(test_account))
            .route(
                "/api/v1/admin/proxies",
                get(list_proxies).post(create_proxy),
            )
            .route(
                "/api/v1/admin/proxies/{id}",
                get(get_proxy).put(update_proxy).delete(delete_proxy),
            )
            .route(
                "/api/v1/admin/api-keys",
                get(list_api_keys).post(create_api_key),
            )
            .route(
                "/api/v1/admin/api-keys/{id}",
                get(get_api_key).put(update_api_key).delete(delete_api_key),
            )
            .route(
                "/api/v1/admin/settings",
                get(get_settings).put(update_settings),
            )
            .route_layer(middleware::from_fn_with_state(state.clone(), require_admin))
            .with_state(state)
    }
}

#[derive(Debug, Serialize)]
struct Envelope<T> {
    code: u16,
    message: &'static str,
    data: T,
}

impl<T> Envelope<T> {
    const fn success(data: T) -> Self {
        Self {
            code: 0,
            message: "success",
            data,
        }
    }
}

#[derive(Debug, Serialize)]
struct ErrorEnvelope {
    code: u16,
    message: String,
}

#[derive(Debug, Serialize)]
struct ComplianceRequiredEnvelope {
    code: &'static str,
    message: &'static str,
    metadata: Value,
}

enum AdminGuardError {
    Api(AdminError),
    ComplianceRequired,
}

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        if let Self::Database(error) = &self {
            tracing::error!(error = %error, "administrator API database operation failed");
        }
        let body = ErrorEnvelope {
            code: status.as_u16(),
            message: self.to_string(),
        };
        (status, Json(body)).into_response()
    }
}

async fn require_admin(
    State(state): State<AdminApiState>,
    mut request: Request,
    next: Next,
) -> Response {
    let result: Result<(), AdminGuardError> = async {
        let token = bearer_token(request.headers()).map_err(AdminGuardError::Api)?;
        let claims = state
            .verifier
            .verify(token)
            .map_err(|_| AdminGuardError::Api(AdminError::Unauthorized))?;
        if claims.role != "admin" {
            return Err(AdminGuardError::Api(AdminError::Forbidden(
                "administrator role is required".to_owned(),
            )));
        }
        let identity = state
            .service
            .authorize_admin(&claims)
            .await
            .map_err(AdminGuardError::Api)?;
        if !is_admin_compliance_bypass_path(request.uri().path())
            && !compliance::is_acknowledged(state.service.pool(), identity.user_id)
                .await
                .map_err(AdminGuardError::Api)?
        {
            return Err(AdminGuardError::ComplianceRequired);
        }
        request.extensions_mut().insert(identity);
        Ok(())
    }
    .await;
    match result {
        Ok(()) => next.run(request).await,
        Err(AdminGuardError::Api(error)) => error.into_response(),
        Err(AdminGuardError::ComplianceRequired) => compliance_required_response(),
    }
}

fn is_admin_compliance_bypass_path(path: &str) -> bool {
    let path = path.trim();
    path == "/api/v1/admin/compliance" || path.starts_with("/api/v1/admin/compliance/")
}

fn compliance_required_response() -> Response {
    (
        StatusCode::LOCKED,
        Json(ComplianceRequiredEnvelope {
            code: "ADMIN_COMPLIANCE_ACK_REQUIRED",
            message: "administrator compliance acknowledgement is required",
            metadata: compliance::required_metadata(),
        }),
    )
        .into_response()
}

fn bearer_token(headers: &HeaderMap) -> Result<&str, AdminError> {
    if let Some(value) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    {
        let (scheme, token) = value.split_once(' ').ok_or(AdminError::Unauthorized)?;
        if scheme.eq_ignore_ascii_case("bearer")
            && !token.is_empty()
            && !token.chars().any(char::is_whitespace)
        {
            return Ok(token);
        }
        return Err(AdminError::Unauthorized);
    }
    websocket_subprotocol_token(headers).ok_or(AdminError::Unauthorized)
}

fn websocket_subprotocol_token(headers: &HeaderMap) -> Option<&str> {
    let upgrade = headers.get("upgrade")?.to_str().ok()?;
    let connection = headers.get("connection")?.to_str().ok()?;
    if !upgrade.eq_ignore_ascii_case("websocket")
        || !connection
            .split(',')
            .any(|value| value.trim().eq_ignore_ascii_case("upgrade"))
    {
        return None;
    }
    headers
        .get("sec-websocket-protocol")?
        .to_str()
        .ok()?
        .split(',')
        .map(str::trim)
        .find_map(|protocol| protocol.strip_prefix("jwt."))
        .filter(|token| !token.is_empty() && !token.chars().any(char::is_whitespace))
}

async fn list_users(
    State(state): State<AdminApiState>,
    Query(query): Query<PageQuery>,
) -> Result<Json<Envelope<super::models::Page<super::models::UserView>>>, AdminError> {
    Ok(Json(Envelope::success(
        state.service.list_users(query).await?,
    )))
}

async fn get_user(
    State(state): State<AdminApiState>,
    Path(id): Path<i64>,
) -> Result<Json<Envelope<super::models::UserView>>, AdminError> {
    Ok(Json(Envelope::success(state.service.get_user(id).await?)))
}

async fn create_user(
    State(state): State<AdminApiState>,
    Json(request): Json<CreateUserRequest>,
) -> Result<Response, AdminError> {
    mutation_response(state.service.create_user(request).await?, StatusCode::OK)
}

async fn update_user(
    State(state): State<AdminApiState>,
    Extension(identity): Extension<AdminIdentity>,
    Path(id): Path<i64>,
    Json(request): Json<UpdateUserRequest>,
) -> Result<Response, AdminError> {
    mutation_response(
        state.service.update_user(&identity, id, request).await?,
        StatusCode::OK,
    )
}

async fn delete_user(
    State(state): State<AdminApiState>,
    Extension(identity): Extension<AdminIdentity>,
    Path(id): Path<i64>,
) -> Result<Response, AdminError> {
    let mutation = state.service.delete_user(&identity, id).await?;
    delete_response(&mutation.invalidation_keys, "user deleted")
}

async fn list_groups(
    State(state): State<AdminApiState>,
    Query(query): Query<PageQuery>,
) -> Result<Json<Envelope<super::models::Page<super::models::GroupView>>>, AdminError> {
    Ok(Json(Envelope::success(
        state.service.list_groups(query).await?,
    )))
}

async fn get_group(
    State(state): State<AdminApiState>,
    Path(id): Path<i64>,
) -> Result<Json<Envelope<super::models::GroupView>>, AdminError> {
    Ok(Json(Envelope::success(state.service.get_group(id).await?)))
}

async fn create_group(
    State(state): State<AdminApiState>,
    Json(request): Json<CreateGroupRequest>,
) -> Result<Response, AdminError> {
    mutation_response(state.service.create_group(request).await?, StatusCode::OK)
}

async fn update_group(
    State(state): State<AdminApiState>,
    Path(id): Path<i64>,
    Json(request): Json<UpdateGroupRequest>,
) -> Result<Response, AdminError> {
    mutation_response(
        state.service.update_group(id, request).await?,
        StatusCode::OK,
    )
}

async fn delete_group(
    State(state): State<AdminApiState>,
    Path(id): Path<i64>,
) -> Result<Response, AdminError> {
    let mutation = state.service.delete_group(id).await?;
    delete_response(&mutation.invalidation_keys, "group deleted")
}

async fn list_accounts(
    State(state): State<AdminApiState>,
    Query(query): Query<PageQuery>,
) -> Result<Json<Envelope<super::models::Page<super::models::AccountView>>>, AdminError> {
    Ok(Json(Envelope::success(
        state.service.list_accounts(query).await?,
    )))
}

async fn get_account(
    State(state): State<AdminApiState>,
    Path(id): Path<i64>,
) -> Result<Json<Envelope<super::models::AccountView>>, AdminError> {
    Ok(Json(Envelope::success(
        state.service.get_account(id).await?,
    )))
}

async fn create_account(
    State(state): State<AdminApiState>,
    Json(request): Json<CreateAccountRequest>,
) -> Result<Response, AdminError> {
    mutation_response(state.service.create_account(request).await?, StatusCode::OK)
}

async fn update_account(
    State(state): State<AdminApiState>,
    Path(id): Path<i64>,
    Json(request): Json<UpdateAccountRequest>,
) -> Result<Response, AdminError> {
    mutation_response(
        state.service.update_account(id, request).await?,
        StatusCode::OK,
    )
}

async fn delete_account(
    State(state): State<AdminApiState>,
    Path(id): Path<i64>,
) -> Result<Response, AdminError> {
    let mutation = state.service.delete_account(id).await?;
    delete_response(&mutation.invalidation_keys, "account deleted")
}

async fn test_account(
    State(state): State<AdminApiState>,
    Path(id): Path<i64>,
) -> Result<Json<Envelope<super::models::ProbeResult>>, AdminError> {
    Ok(Json(Envelope::success(
        state.service.test_account(id).await?,
    )))
}

async fn list_proxies(
    State(state): State<AdminApiState>,
    Query(query): Query<PageQuery>,
) -> Result<Json<Envelope<super::models::Page<super::models::ProxyView>>>, AdminError> {
    Ok(Json(Envelope::success(
        state.service.list_proxies(query).await?,
    )))
}

async fn get_proxy(
    State(state): State<AdminApiState>,
    Path(id): Path<i64>,
) -> Result<Json<Envelope<super::models::ProxyView>>, AdminError> {
    Ok(Json(Envelope::success(state.service.get_proxy(id).await?)))
}

async fn create_proxy(
    State(state): State<AdminApiState>,
    Json(request): Json<CreateProxyRequest>,
) -> Result<Response, AdminError> {
    mutation_response(state.service.create_proxy(request).await?, StatusCode::OK)
}

async fn update_proxy(
    State(state): State<AdminApiState>,
    Path(id): Path<i64>,
    Json(request): Json<UpdateProxyRequest>,
) -> Result<Response, AdminError> {
    mutation_response(
        state.service.update_proxy(id, request).await?,
        StatusCode::OK,
    )
}

async fn delete_proxy(
    State(state): State<AdminApiState>,
    Path(id): Path<i64>,
) -> Result<Response, AdminError> {
    let mutation = state.service.delete_proxy(id).await?;
    delete_response(&mutation.invalidation_keys, "proxy deleted")
}

async fn list_api_keys(
    State(state): State<AdminApiState>,
    Query(query): Query<PageQuery>,
) -> Result<Json<Envelope<super::models::Page<super::models::ApiKeyView>>>, AdminError> {
    Ok(Json(Envelope::success(
        state.service.list_api_keys(query).await?,
    )))
}

async fn get_api_key(
    State(state): State<AdminApiState>,
    Path(id): Path<i64>,
) -> Result<Json<Envelope<super::models::ApiKeyView>>, AdminError> {
    Ok(Json(Envelope::success(
        state.service.get_api_key(id).await?,
    )))
}

async fn create_api_key(
    State(state): State<AdminApiState>,
    Json(request): Json<CreateApiKeyRequest>,
) -> Result<Response, AdminError> {
    mutation_response(state.service.create_api_key(request).await?, StatusCode::OK)
}

async fn update_api_key(
    State(state): State<AdminApiState>,
    Path(id): Path<i64>,
    Json(request): Json<UpdateApiKeyRequest>,
) -> Result<Response, AdminError> {
    mutation_response(
        state.service.update_api_key(id, request).await?,
        StatusCode::OK,
    )
}

async fn delete_api_key(
    State(state): State<AdminApiState>,
    Path(id): Path<i64>,
) -> Result<Response, AdminError> {
    let mutation = state.service.delete_api_key(id).await?;
    delete_response(&mutation.invalidation_keys, "API key deleted")
}

async fn get_settings(
    State(state): State<AdminApiState>,
) -> Result<Json<Envelope<std::collections::BTreeMap<String, Value>>>, AdminError> {
    Ok(Json(Envelope::success(state.service.get_settings().await?)))
}

async fn update_settings(
    State(state): State<AdminApiState>,
    Json(request): Json<SettingPatchRequest>,
) -> Result<Response, AdminError> {
    mutation_response(
        state.service.update_settings(request).await?,
        StatusCode::OK,
    )
}

fn mutation_response<T: Serialize>(
    mutation: Mutation<T>,
    status: StatusCode,
) -> Result<Response, AdminError> {
    let mut response = (status, Json(Envelope::success(mutation.value))).into_response();
    insert_invalidation_header(&mut response, &mutation.invalidation_keys)?;
    Ok(response)
}

fn delete_response(
    keys: &[InvalidationKey],
    message: &'static str,
) -> Result<Response, AdminError> {
    let mut response = Json(Envelope::success(json!({ "message": message }))).into_response();
    insert_invalidation_header(&mut response, keys)?;
    Ok(response)
}

fn insert_invalidation_header(
    response: &mut Response,
    keys: &[InvalidationKey],
) -> Result<(), AdminError> {
    let value = keys
        .iter()
        .map(|key| key.0.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let value = HeaderValue::from_str(&value)
        .map_err(|_| AdminError::Probe("cache invalidation key is invalid".to_owned()))?;
    response.headers_mut().insert("x-sub2api-invalidate", value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_jwt_is_extracted_from_subprotocol() {
        let mut headers = HeaderMap::new();
        headers.insert("upgrade", HeaderValue::from_static("websocket"));
        headers.insert(
            "connection",
            HeaderValue::from_static("keep-alive, Upgrade"),
        );
        headers.insert(
            "sec-websocket-protocol",
            HeaderValue::from_static("sub2api-admin, jwt.header.payload.signature"),
        );

        assert_eq!(
            websocket_subprotocol_token(&headers),
            Some("header.payload.signature")
        );
        assert_eq!(bearer_token(&headers).unwrap(), "header.payload.signature");
    }

    #[test]
    fn websocket_jwt_requires_a_websocket_upgrade() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "sec-websocket-protocol",
            HeaderValue::from_static("sub2api-admin, jwt.header.payload.signature"),
        );

        assert!(websocket_subprotocol_token(&headers).is_none());
        assert!(matches!(
            bearer_token(&headers),
            Err(AdminError::Unauthorized)
        ));
    }

    #[test]
    fn only_compliance_routes_bypass_the_acknowledgement_guard() {
        assert!(is_admin_compliance_bypass_path("/api/v1/admin/compliance"));
        assert!(is_admin_compliance_bypass_path(
            "/api/v1/admin/compliance/accept"
        ));
        assert!(!is_admin_compliance_bypass_path(
            "/api/v1/admin/compliance-report"
        ));
        assert!(!is_admin_compliance_bypass_path("/api/v1/admin/users"));
    }

    #[tokio::test]
    async fn compliance_guard_uses_the_frontend_423_contract() {
        let response = compliance_required_response();
        assert_eq!(response.status(), StatusCode::LOCKED);
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .expect("compliance response body should be readable");
        let body: Value =
            serde_json::from_slice(&body).expect("compliance response should be valid JSON");
        assert_eq!(body["code"], "ADMIN_COMPLIANCE_ACK_REQUIRED");
        assert_eq!(body["metadata"]["version"], compliance::VERSION);
        assert_eq!(
            body["metadata"]["document_path_en"],
            compliance::DOCUMENT_PATH_EN
        );
    }
}
