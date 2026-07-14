use std::collections::HashMap;

use axum::{
    Router,
    body::Bytes,
    extract::{OriginalUri, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::{Value, json};

use super::{
    PaymentApiState, PaymentError,
    orders::{confirm_notification, load_order_by_trade_no, provider_for_order},
    provider::{load_provider_instance, verify_notification},
};

const MAX_WEBHOOK_BODY_BYTES: usize = 1 << 20;

pub(super) fn routes() -> Router<PaymentApiState> {
    Router::new()
        .route(
            "/api/v1/payment/webhook/easypay",
            get(easypay_get).post(easypay_post),
        )
        .route("/api/v1/payment/webhook/alipay", post(alipay))
        .route("/api/v1/payment/webhook/wxpay", post(wxpay))
        .route("/api/v1/payment/webhook/stripe", post(stripe))
        .route("/api/v1/payment/webhook/airwallex", post(airwallex))
}

async fn easypay_get(
    State(state): State<PaymentApiState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
) -> Response {
    handle(
        state,
        "easypay",
        uri.query().unwrap_or_default().as_bytes(),
        &headers,
    )
    .await
}

async fn easypay_post(
    State(state): State<PaymentApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    handle(state, "easypay", &body, &headers).await
}

async fn alipay(State(state): State<PaymentApiState>, headers: HeaderMap, body: Bytes) -> Response {
    handle(state, "alipay", &body, &headers).await
}

async fn wxpay(State(state): State<PaymentApiState>, headers: HeaderMap, body: Bytes) -> Response {
    handle(state, "wxpay", &body, &headers).await
}

async fn stripe(State(state): State<PaymentApiState>, headers: HeaderMap, body: Bytes) -> Response {
    handle(state, "stripe", &body, &headers).await
}

async fn airwallex(
    State(state): State<PaymentApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    handle(state, "airwallex", &body, &headers).await
}

async fn handle(
    state: PaymentApiState,
    provider_key: &str,
    body: &[u8],
    request_headers: &HeaderMap,
) -> Response {
    if body.len() > MAX_WEBHOOK_BODY_BYTES {
        return (StatusCode::PAYLOAD_TOO_LARGE, "webhook body too large").into_response();
    }
    let Ok(raw_body) = std::str::from_utf8(body) else {
        return (StatusCode::BAD_REQUEST, "invalid webhook body").into_response();
    };
    let out_trade_no = extract_out_trade_no(raw_body, provider_key);
    let providers = match webhook_providers(&state, provider_key, &out_trade_no).await {
        Ok(providers) => providers,
        Err(error) => {
            tracing::error!(provider = provider_key, error = ?error, "payment webhook provider lookup failed");
            return retryable_failure_response();
        }
    };
    let headers = request_headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_ascii_lowercase(), value.to_owned()))
        })
        .collect::<HashMap<_, _>>();
    let mut verified = None;
    let mut verified_provider = provider_key;
    let mut last_error = None;
    for provider in &providers {
        match verify_notification(provider, raw_body, &headers) {
            Ok(notification) => {
                verified_provider = &provider.provider_key;
                verified = Some(notification);
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    let Some(notification) = verified else {
        if let Some(error) = last_error {
            tracing::warn!(provider = provider_key, error = ?error, "payment webhook verification failed");
        }
        return (StatusCode::BAD_REQUEST, "verify failed").into_response();
    };
    let Some(notification) = notification else {
        return success_response(verified_provider);
    };
    let known = match sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM payment_orders WHERE out_trade_no = $1)",
    )
    .bind(&notification.order_id)
    .fetch_one(state.pool())
    .await
    {
        Ok(known) => known,
        Err(error) => {
            tracing::error!(provider = verified_provider, error = %error, "query payment webhook order");
            return retryable_failure_response();
        }
    };
    if !known {
        tracing::warn!(
            provider = verified_provider,
            out_trade_no = notification.order_id,
            "unknown payment webhook order acknowledged"
        );
        return success_response(verified_provider);
    }
    if let Err(error) = confirm_notification(&state, &notification).await {
        tracing::error!(provider = verified_provider, error = ?error, "payment webhook fulfillment failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "handle failed").into_response();
    }
    success_response(verified_provider)
}

async fn webhook_providers(
    state: &PaymentApiState,
    provider_key: &str,
    out_trade_no: &str,
) -> Result<Vec<super::models::ProviderSelection>, PaymentError> {
    if !out_trade_no.is_empty() {
        match load_order_by_trade_no(state.pool(), out_trade_no).await {
            Ok(order) => return Ok(vec![provider_for_order(state, &order).await?]),
            Err(error) if error.status() == StatusCode::NOT_FOUND => {}
            Err(error) => return Err(error),
        }
    }
    let ids = sqlx::query_scalar::<_, i64>(
        r"
SELECT id FROM payment_provider_instances
WHERE enabled = TRUE AND provider_key = $1
ORDER BY sort_order, id
",
    )
    .bind(provider_key)
    .fetch_all(state.pool())
    .await?;
    if provider_key != "wxpay" && ids.len() > 1 {
        return Err(PaymentError::unavailable(
            "PAYMENT_PROVIDER_AMBIGUOUS",
            "Webhook cannot be mapped to a unique provider instance",
        ));
    }
    if ids.is_empty() {
        return Err(PaymentError::unavailable(
            "PAYMENT_PROVIDER_MISSING",
            "Webhook provider is not configured",
        ));
    }
    let mut providers = Vec::with_capacity(ids.len());
    for id in ids {
        providers.push(load_provider_instance(state, id).await?);
    }
    Ok(providers)
}

fn extract_out_trade_no(raw_body: &str, provider_key: &str) -> String {
    if matches!(provider_key, "easypay" | "alipay") {
        return url::form_urlencoded::parse(raw_body.as_bytes())
            .find_map(|(key, value)| (key == "out_trade_no").then(|| value.into_owned()))
            .unwrap_or_default();
    }
    let Ok(value) = serde_json::from_str::<Value>(raw_body) else {
        return String::new();
    };
    match provider_key {
        "stripe" => value
            .pointer("/data/object/metadata/orderId")
            .and_then(Value::as_str),
        "airwallex" => value
            .pointer("/data/object/merchant_order_id")
            .and_then(Value::as_str),
        _ => None,
    }
    .unwrap_or_default()
    .trim()
    .to_owned()
}

fn success_response(provider_key: &str) -> Response {
    match provider_key {
        "wxpay" => (
            StatusCode::OK,
            axum::Json(json!({"code": "SUCCESS", "message": "success"})),
        )
            .into_response(),
        "stripe" | "airwallex" => (StatusCode::OK, "").into_response(),
        _ => (StatusCode::OK, "success").into_response(),
    }
}

fn retryable_failure_response() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "payment webhook temporarily unavailable",
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_provider_order_references_without_logging_secrets() {
        assert_eq!(
            extract_out_trade_no("trade_no=x&out_trade_no=sub2_123", "easypay"),
            "sub2_123"
        );
        assert_eq!(
            extract_out_trade_no(
                r#"{"data":{"object":{"merchant_order_id":"sub2_456"}}}"#,
                "airwallex"
            ),
            "sub2_456"
        );
    }

    #[test]
    fn provider_lookup_failures_are_never_acknowledged() {
        assert_eq!(
            retryable_failure_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
