use axum::{
    Json, Router,
    extract::{
        Path, Query, State,
        rejection::{JsonRejection, PathRejection, QueryRejection},
    },
    http::HeaderMap,
    routing::{get, post, put},
};

use super::{
    models::{
        ApiEnvelope, ApiError, ApiKeyListQuery, ChangePasswordRequest, CreateApiKeyRequest,
        DeleteMessage, ForgotPasswordRequest, Login2faRequest, LoginRequest, LogoutRequest,
        RefreshRequest, RegisterRequest, ResetPasswordRequest, ResourceIdQuery,
        SendVerificationCodeRequest, TotpDisableRequest, TotpEnableRequest, TotpSetupRequest,
        UpdateApiKeyRequest, UpdateProfileRequest, ValidateCodeRequest,
    },
    service::ControlApiState,
};

pub fn router(state: ControlApiState) -> Router {
    Router::new()
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/register", post(register))
        .route("/api/v1/auth/login/2fa", post(login_2fa))
        .route("/api/v1/auth/send-verify-code", post(send_verify_code))
        .route(
            "/api/v1/auth/validate-promo-code",
            post(validate_promo_code),
        )
        .route(
            "/api/v1/auth/validate-invitation-code",
            post(validate_invitation_code),
        )
        .route("/api/v1/auth/refresh", post(refresh))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/forgot-password", post(forgot_password))
        .route("/api/v1/auth/reset-password", post(reset_password))
        .route("/api/v1/auth/me", get(current_user))
        .route(
            "/api/v1/auth/revoke-all-sessions",
            post(revoke_all_sessions),
        )
        .route("/api/v1/user/profile", get(profile))
        .route("/api/v1/user", put(update_profile))
        .route("/api/v1/user/password", put(change_password))
        .route("/api/v1/user/totp/status", get(totp_status))
        .route(
            "/api/v1/user/totp/verification-method",
            get(totp_verification_method),
        )
        .route("/api/v1/user/totp/send-code", post(totp_send_code))
        .route("/api/v1/user/totp/setup", post(totp_setup))
        .route("/api/v1/user/totp/enable", post(totp_enable))
        .route("/api/v1/user/totp/disable", post(totp_disable))
        .route(
            "/api/v1/user/api-keys",
            get(list_api_keys)
                .post(create_api_key)
                .put(update_api_key)
                .delete(delete_api_key),
        )
        .route(
            "/api/v1/user/api-keys/{id}",
            get(get_api_key_by_id)
                .put(update_api_key_by_id)
                .delete(delete_api_key_by_id),
        )
        // Preserve the current Go route while clients move to the user-scoped path.
        .route("/api/v1/keys", get(list_api_keys).post(create_api_key))
        .route(
            "/api/v1/keys/{id}",
            get(get_api_key_by_id)
                .put(update_api_key_by_id)
                .delete(delete_api_key_by_id),
        )
        .route("/api/v1/settings/public", get(public_settings))
        .merge(super::unsubscribe::routes())
        .merge(super::oauth::routes())
        .merge(super::pages::routes())
        .with_state(state)
}

async fn login(
    State(state): State<ControlApiState>,
    payload: Result<Json<LoginRequest>, JsonRejection>,
) -> Result<Json<ApiEnvelope<super::models::LoginResponse>>, ApiError> {
    let request = json_payload(payload)?;
    let response = state
        .login(request.email, request.password, request.turnstile_token)
        .await?;
    Ok(Json(ApiEnvelope::success(response)))
}

async fn register(
    State(state): State<ControlApiState>,
    payload: Result<Json<RegisterRequest>, JsonRejection>,
) -> Result<Json<ApiEnvelope<super::models::AuthResponse>>, ApiError> {
    Ok(Json(ApiEnvelope::success(
        state.register(json_payload(payload)?).await?,
    )))
}

async fn login_2fa(
    State(state): State<ControlApiState>,
    payload: Result<Json<Login2faRequest>, JsonRejection>,
) -> Result<Json<ApiEnvelope<super::models::AuthResponse>>, ApiError> {
    Ok(Json(ApiEnvelope::success(
        state.login_2fa(json_payload(payload)?).await?,
    )))
}

async fn send_verify_code(
    State(state): State<ControlApiState>,
    payload: Result<Json<SendVerificationCodeRequest>, JsonRejection>,
) -> Result<Json<ApiEnvelope<super::models::SendVerificationCodeResponse>>, ApiError> {
    Ok(Json(ApiEnvelope::success(
        state.send_verification_code(json_payload(payload)?).await?,
    )))
}

async fn validate_promo_code(
    State(state): State<ControlApiState>,
    payload: Result<Json<ValidateCodeRequest>, JsonRejection>,
) -> Result<Json<ApiEnvelope<super::models::PromoCodeValidation>>, ApiError> {
    Ok(Json(ApiEnvelope::success(
        state
            .validate_promo_code(&json_payload(payload)?.code)
            .await?,
    )))
}

async fn validate_invitation_code(
    State(state): State<ControlApiState>,
    payload: Result<Json<ValidateCodeRequest>, JsonRejection>,
) -> Result<Json<ApiEnvelope<super::models::InvitationCodeValidation>>, ApiError> {
    Ok(Json(ApiEnvelope::success(
        state
            .validate_invitation_code(&json_payload(payload)?.code)
            .await?,
    )))
}

async fn refresh(
    State(state): State<ControlApiState>,
    payload: Result<Json<RefreshRequest>, JsonRejection>,
) -> Result<Json<ApiEnvelope<super::models::RefreshResponse>>, ApiError> {
    let request = json_payload(payload)?;
    if request.refresh_token.trim().is_empty() {
        return Err(ApiError::bad_request("Refresh token is required"));
    }
    Ok(Json(ApiEnvelope::success(
        state.refresh(request.refresh_token.trim()).await?,
    )))
}

async fn logout(
    State(state): State<ControlApiState>,
    payload: Result<Json<LogoutRequest>, JsonRejection>,
) -> Json<ApiEnvelope<super::models::MessageResponse>> {
    let request = payload.map_or_else(|_| LogoutRequest::default(), |Json(value)| value);
    Json(ApiEnvelope::success(
        state.logout(request.refresh_token.trim()).await,
    ))
}

async fn forgot_password(
    State(state): State<ControlApiState>,
    payload: Result<Json<ForgotPasswordRequest>, JsonRejection>,
) -> Result<Json<ApiEnvelope<super::models::MessageResponse>>, ApiError> {
    Ok(Json(ApiEnvelope::success(
        state.forgot_password(json_payload(payload)?).await?,
    )))
}

async fn reset_password(
    State(state): State<ControlApiState>,
    payload: Result<Json<ResetPasswordRequest>, JsonRejection>,
) -> Result<Json<ApiEnvelope<super::models::MessageResponse>>, ApiError> {
    Ok(Json(ApiEnvelope::success(
        state.reset_password(json_payload(payload)?).await?,
    )))
}

async fn current_user(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
) -> Result<Json<ApiEnvelope<super::models::CurrentUser>>, ApiError> {
    let user = state.authenticate(&headers).await?;
    Ok(Json(ApiEnvelope::success(state.current_user(user).await?)))
}

async fn revoke_all_sessions(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
) -> Result<Json<ApiEnvelope<super::models::MessageResponse>>, ApiError> {
    let user = state.authenticate(&headers).await?;
    Ok(Json(ApiEnvelope::success(
        state.revoke_all_sessions(user.view.id).await?,
    )))
}

async fn profile(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
) -> Result<Json<ApiEnvelope<super::models::UserProfile>>, ApiError> {
    let user = state.authenticate(&headers).await?;
    Ok(Json(ApiEnvelope::success(
        state.profile_for_user(user).await?,
    )))
}

async fn update_profile(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    payload: Result<Json<UpdateProfileRequest>, JsonRejection>,
) -> Result<Json<ApiEnvelope<super::models::UserProfile>>, ApiError> {
    let user = state.authenticate(&headers).await?;
    let request = json_payload(payload)?;
    Ok(Json(ApiEnvelope::success(
        state.update_profile(user.view.id, request).await?,
    )))
}

async fn change_password(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    payload: Result<Json<ChangePasswordRequest>, JsonRejection>,
) -> Result<Json<ApiEnvelope<super::models::MessageResponse>>, ApiError> {
    let user = state.authenticate(&headers).await?;
    let request = json_payload(payload)?;
    Ok(Json(ApiEnvelope::success(
        state
            .change_password(user, request.old_password, request.new_password)
            .await?,
    )))
}

async fn totp_status(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
) -> Result<Json<ApiEnvelope<super::models::TotpStatus>>, ApiError> {
    let user = state.authenticate(&headers).await?;
    Ok(Json(ApiEnvelope::success(state.totp_status(&user).await?)))
}

async fn totp_verification_method(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
) -> Result<Json<ApiEnvelope<super::models::TotpVerificationMethod>>, ApiError> {
    let _user = state.authenticate(&headers).await?;
    Ok(Json(ApiEnvelope::success(
        state.totp_verification_method().await?,
    )))
}

async fn totp_send_code(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
) -> Result<Json<ApiEnvelope<super::models::SendVerificationCodeResponse>>, ApiError> {
    let user = state.authenticate(&headers).await?;
    Ok(Json(ApiEnvelope::success(
        state.send_totp_verification_code(&user.view.email).await?,
    )))
}

async fn totp_setup(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    payload: Result<Json<TotpSetupRequest>, JsonRejection>,
) -> Result<Json<ApiEnvelope<super::models::TotpSetupResponse>>, ApiError> {
    let user = state.authenticate(&headers).await?;
    Ok(Json(ApiEnvelope::success(
        state
            .initiate_totp_setup(user, json_payload(payload)?)
            .await?,
    )))
}

async fn totp_enable(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    payload: Result<Json<TotpEnableRequest>, JsonRejection>,
) -> Result<Json<ApiEnvelope<super::models::MessageResponse>>, ApiError> {
    let user = state.authenticate(&headers).await?;
    Ok(Json(ApiEnvelope::success(
        state
            .enable_totp(user.view.id, json_payload(payload)?)
            .await?,
    )))
}

async fn totp_disable(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    payload: Result<Json<TotpDisableRequest>, JsonRejection>,
) -> Result<Json<ApiEnvelope<super::models::MessageResponse>>, ApiError> {
    let user = state.authenticate(&headers).await?;
    Ok(Json(ApiEnvelope::success(
        state.disable_totp(user, json_payload(payload)?).await?,
    )))
}

async fn list_api_keys(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    query: Result<Query<ApiKeyListQuery>, QueryRejection>,
) -> Result<Json<ApiEnvelope<super::models::Paginated<super::models::ApiKeyView>>>, ApiError> {
    let user = state.authenticate(&headers).await?;
    let query = query_payload(query)?;
    Ok(Json(ApiEnvelope::success(
        state.list_api_keys(user.view.id, &query).await?,
    )))
}

async fn create_api_key(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    payload: Result<Json<CreateApiKeyRequest>, JsonRejection>,
) -> Result<Json<ApiEnvelope<super::models::ApiKeyView>>, ApiError> {
    let user = state.authenticate(&headers).await?;
    let request = json_payload(payload)?;
    Ok(Json(ApiEnvelope::success(
        state.create_api_key(user.view.id, request).await?,
    )))
}

async fn get_api_key_by_id(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    path: Result<Path<i64>, PathRejection>,
) -> Result<Json<ApiEnvelope<super::models::ApiKeyView>>, ApiError> {
    let user = state.authenticate(&headers).await?;
    Ok(Json(ApiEnvelope::success(
        state.get_api_key(user.view.id, path_payload(path)?).await?,
    )))
}

async fn update_api_key(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    payload: Result<Json<UpdateApiKeyRequest>, JsonRejection>,
) -> Result<Json<ApiEnvelope<super::models::ApiKeyView>>, ApiError> {
    let user = state.authenticate(&headers).await?;
    let request = json_payload(payload)?;
    let key_id = request
        .id
        .ok_or_else(|| ApiError::bad_request("API key ID is required"))?;
    Ok(Json(ApiEnvelope::success(
        state.update_api_key(user.view.id, key_id, request).await?,
    )))
}

async fn update_api_key_by_id(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    path: Result<Path<i64>, PathRejection>,
    payload: Result<Json<UpdateApiKeyRequest>, JsonRejection>,
) -> Result<Json<ApiEnvelope<super::models::ApiKeyView>>, ApiError> {
    let user = state.authenticate(&headers).await?;
    let key_id = path_payload(path)?;
    let request = json_payload(payload)?;
    Ok(Json(ApiEnvelope::success(
        state.update_api_key(user.view.id, key_id, request).await?,
    )))
}

async fn delete_api_key(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    query: Result<Query<ResourceIdQuery>, QueryRejection>,
) -> Result<Json<ApiEnvelope<DeleteMessage>>, ApiError> {
    let user = state.authenticate(&headers).await?;
    let query = query_payload(query)?;
    state.delete_api_key(user.view.id, query.id).await?;
    Ok(Json(ApiEnvelope::success(DeleteMessage {
        message: "API key deleted successfully",
    })))
}

async fn delete_api_key_by_id(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
    path: Result<Path<i64>, PathRejection>,
) -> Result<Json<ApiEnvelope<DeleteMessage>>, ApiError> {
    let user = state.authenticate(&headers).await?;
    let key_id = path_payload(path)?;
    state.delete_api_key(user.view.id, key_id).await?;
    Ok(Json(ApiEnvelope::success(DeleteMessage {
        message: "API key deleted successfully",
    })))
}

async fn public_settings(
    State(state): State<ControlApiState>,
) -> Result<Json<ApiEnvelope<super::models::PublicSettings>>, ApiError> {
    Ok(Json(ApiEnvelope::success(state.public_settings().await?)))
}

fn json_payload<T>(payload: Result<Json<T>, JsonRejection>) -> Result<T, ApiError> {
    payload
        .map(|Json(value)| value)
        .map_err(|_| ApiError::bad_request("Invalid JSON request"))
}

fn query_payload<T>(query: Result<Query<T>, QueryRejection>) -> Result<T, ApiError> {
    query
        .map(|Query(value)| value)
        .map_err(|_| ApiError::bad_request("Invalid query parameters"))
}

fn path_payload<T>(path: Result<Path<T>, PathRejection>) -> Result<T, ApiError> {
    path.map(|Path(value)| value)
        .map_err(|_| ApiError::bad_request("Invalid resource ID"))
}
