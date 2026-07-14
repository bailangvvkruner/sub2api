#![allow(
    clippy::module_name_repetitions,
    clippy::struct_excessive_bools,
    clippy::too_many_lines
)]

mod handlers;
mod limiter;
mod models;
mod oauth;
mod pages;
mod security_flow;
mod service;
mod unsubscribe;

pub use handlers::router;
pub use limiter::LoginRateLimiter;
pub use models::{
    ApiEnvelope, ApiError, ApiKeyListQuery, ApiKeyView, AuthNotifier, AuthResponse,
    ChangePasswordRequest, CreateApiKeyRequest, CurrentUser, DeleteMessage, ForgotPasswordRequest,
    IdentitySummary, IdentitySummarySet, InvitationCodeValidation, Login2faRequest, LoginRequest,
    LoginResponse, LogoutRequest, MessageResponse, PUBLIC_SETTING_KEYS, Paginated, Pagination,
    PromoCodeValidation, PublicRuntimeInfo, PublicSettings, RefreshRequest, RefreshResponse,
    RegisterRequest, ResetPasswordRequest, ResourceIdQuery, SendVerificationCodeRequest,
    SendVerificationCodeResponse, TotpDisableRequest, TotpEnableRequest, TotpLoginChallenge,
    TotpSetupRequest, TotpSetupResponse, TotpStatus, TotpVerificationMethod, UpdateApiKeyRequest,
    UpdateProfileRequest, UserProfile, UserView, ValidateCodeRequest, public_settings_from_values,
};
pub use service::{
    AUTH_RATE_LIMIT_DDL, AUTH_SECURITY_DDL, ControlApiConfig, ControlApiState,
    REFRESH_TOKEN_PREFIX, REFRESH_TOKENS_DDL, hash_refresh_token, validate_custom_api_key,
    validate_ip_patterns,
};
