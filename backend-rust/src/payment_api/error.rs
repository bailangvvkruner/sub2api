use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

use crate::control_api::ApiError;

#[derive(Debug)]
pub struct PaymentError {
    status: StatusCode,
    reason: &'static str,
    message: String,
    internal: Option<String>,
}

impl std::fmt::Display for PaymentError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for PaymentError {}

#[derive(Serialize)]
struct ErrorBody<'a> {
    code: u16,
    message: &'a str,
    reason: &'a str,
}

impl PaymentError {
    #[must_use]
    pub(super) const fn status(&self) -> StatusCode {
        self.status
    }

    #[must_use]
    pub fn bad_request(reason: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, reason, message)
    }

    #[must_use]
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", message)
    }

    #[must_use]
    pub fn forbidden(reason: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, reason, message)
    }

    #[must_use]
    pub fn not_found(reason: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, reason, message)
    }

    #[must_use]
    pub fn conflict(reason: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, reason, message)
    }

    #[must_use]
    pub fn too_many_requests(reason: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, reason, message)
    }

    #[must_use]
    pub fn unavailable(reason: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, reason, message)
    }

    #[must_use]
    pub fn internal(context: &'static str, error: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            reason: "PAYMENT_INTERNAL_ERROR",
            message: "Payment service temporarily unavailable".to_owned(),
            internal: Some(format!("{context}: {error}")),
        }
    }

    pub(super) fn from_auth(error: &ApiError) -> Self {
        match error.status() {
            StatusCode::UNAUTHORIZED => Self::unauthorized("User not authenticated"),
            StatusCode::FORBIDDEN => Self::forbidden("FORBIDDEN", "Access denied"),
            _ => Self::internal(
                "authenticate payment user",
                "control API authentication failed",
            ),
        }
    }

    fn new(status: StatusCode, reason: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            reason,
            message: message.into(),
            internal: None,
        }
    }
}

impl IntoResponse for PaymentError {
    fn into_response(self) -> Response {
        if let Some(error) = &self.internal {
            tracing::error!(error, reason = self.reason, "payment API request failed");
        }
        (
            self.status,
            Json(ErrorBody {
                code: self.status.as_u16(),
                message: &self.message,
                reason: self.reason,
            }),
        )
            .into_response()
    }
}

impl From<sqlx::Error> for PaymentError {
    fn from(error: sqlx::Error) -> Self {
        Self::internal("PostgreSQL payment operation", error)
    }
}

impl From<reqwest::Error> for PaymentError {
    fn from(error: reqwest::Error) -> Self {
        Self::unavailable("PAYMENT_GATEWAY_ERROR", error.to_string())
    }
}
