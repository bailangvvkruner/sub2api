mod account;
mod announcements;
mod bindings;
mod channels;
mod groups;
mod monitors;
mod redeem;
mod subscriptions;

use axum::{Json, Router, extract::rejection::JsonRejection, http::HeaderMap};

use crate::control_api::{ApiError, ControlApiState, UserView};

pub fn router(state: ControlApiState) -> Router {
    Router::new()
        .merge(account::routes())
        .merge(bindings::routes())
        .merge(groups::routes())
        .merge(channels::routes())
        .merge(announcements::routes())
        .merge(redeem::routes())
        .merge(subscriptions::routes())
        .merge(monitors::routes())
        .with_state(state)
}

async fn authenticated_user(
    state: &ControlApiState,
    headers: &HeaderMap,
) -> Result<UserView, ApiError> {
    Ok(state.authenticate(headers).await?.view)
}

fn json_payload<T>(payload: Result<Json<T>, JsonRejection>) -> Result<T, ApiError> {
    payload
        .map(|Json(value)| value)
        .map_err(|_| ApiError::bad_request("Invalid JSON request"))
}

fn decimal(raw: &str) -> Result<f64, sqlx::Error> {
    raw.parse::<f64>()
        .map_err(|error| sqlx::Error::Decode(Box::new(error)))
}

fn optional_decimal(raw: Option<String>) -> Result<Option<f64>, sqlx::Error> {
    raw.map(|value| decimal(&value)).transpose()
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode},
    };
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    use super::*;
    use crate::control_api::ControlApiConfig;

    #[tokio::test]
    async fn user_data_routes_require_authentication() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://sub2api@127.0.0.1/sub2api")
            .expect("test PostgreSQL URL should be valid");
        let state = ControlApiState::new(pool, ControlApiConfig::new([7_u8; 32]))
            .expect("test control state should build");
        let app = router(state);
        for (method, path) in [
            (Method::GET, "/api/v1/groups/available"),
            (Method::GET, "/api/v1/groups/rates"),
            (Method::GET, "/api/v1/channels/available"),
            (Method::GET, "/api/v1/announcements"),
            (Method::POST, "/api/v1/announcements/1/read"),
            (Method::GET, "/api/v1/subscriptions"),
            (Method::GET, "/api/v1/subscriptions/active"),
            (Method::GET, "/api/v1/subscriptions/progress"),
            (Method::GET, "/api/v1/subscriptions/summary"),
            (Method::GET, "/api/v1/channel-monitors"),
            (Method::GET, "/api/v1/channel-monitors/1/status"),
            (Method::GET, "/api/v1/user/aff"),
            (Method::POST, "/api/v1/user/aff/transfer"),
            (
                Method::POST,
                "/api/v1/user/account-bindings/email/send-code",
            ),
            (Method::POST, "/api/v1/user/auth-identities/bind/start"),
            (Method::GET, "/api/v1/user/platform-quotas"),
            (Method::GET, "/api/v1/user/api-keys/1/usage/daily"),
            (Method::POST, "/api/v1/redeem"),
            (Method::GET, "/api/v1/redeem/history"),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .body(Body::empty())
                        .expect("request should build"),
                )
                .await
                .expect("route should respond");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
        }
    }
}
