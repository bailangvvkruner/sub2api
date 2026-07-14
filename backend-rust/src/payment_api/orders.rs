use std::collections::HashMap;

use axum::{
    Json, Router,
    extract::{Path, Query, State, rejection::JsonRejection},
    http::{HeaderMap, header},
    routing::{get, post},
};
use rand::{Rng, distributions::Alphanumeric};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use url::Url;

use super::{
    PaymentApiState, PaymentError,
    config::load_payment_config,
    json_payload,
    models::{
        CreateOrderRequest, CreateOrderResponse, ORDER_BALANCE, ORDER_SELECT, ORDER_SUBSCRIPTION,
        OrderRecord, PublicOrderVerify, STATUS_CANCELLED, STATUS_COMPLETED, STATUS_EXPIRED,
        STATUS_FAILED, STATUS_PAID, STATUS_PENDING, STATUS_RECHARGING, STATUS_REFUND_REQUESTED,
        order_from_row, public_result,
    },
    provider::{
        CreatePaymentInput, ProviderQueryResult, cancel_payment, create_payment,
        load_provider_instance, normalize_payment_type, provider_currency, query_payment,
        select_provider,
    },
    token::ResumeClaims,
};
use crate::control_api::{ApiEnvelope, Paginated, Pagination};

const PAYMENT_ADVISORY_NAMESPACE: i64 = 0x5355_4232_5041_5900;
const PAYMENT_EXPIRY_GRACE_SECONDS: i64 = 5 * 60;

pub(super) fn routes() -> Router<PaymentApiState> {
    Router::new()
        .route("/api/v1/payment/orders", post(create_order))
        .route("/api/v1/payment/orders/verify", post(verify_order))
        .route("/api/v1/payment/orders/my", get(my_orders))
        .route(
            "/api/v1/payment/orders/refund-eligible-providers",
            get(refund_eligible_providers),
        )
        .route("/api/v1/payment/orders/{id}", get(get_order))
        .route("/api/v1/payment/orders/{id}/cancel", post(cancel_order))
        .route(
            "/api/v1/payment/orders/{id}/refund-request",
            post(request_refund),
        )
        .route("/api/v1/payment/public/orders/verify", post(public_verify))
        .route(
            "/api/v1/payment/public/orders/resolve",
            post(public_resolve),
        )
}

#[derive(Debug, Deserialize)]
struct VerifyRequest {
    out_trade_no: String,
}

#[derive(Debug, Deserialize)]
struct ResolveRequest {
    resume_token: String,
}

#[derive(Debug, Deserialize)]
struct RefundRequest {
    #[serde(default)]
    reason: String,
}

#[derive(Debug, Default, Deserialize)]
struct OrdersQuery {
    page: Option<u32>,
    page_size: Option<u32>,
    limit: Option<u32>,
    #[serde(default)]
    status: String,
    #[serde(default)]
    order_type: String,
    #[serde(default)]
    payment_type: String,
}

impl OrdersQuery {
    fn pagination(&self) -> Pagination {
        let page = self.page.unwrap_or(1).max(1);
        let page_size = self.page_size.or(self.limit).unwrap_or(20).clamp(1, 100);
        Pagination {
            page,
            page_size,
            offset: i64::from(page.saturating_sub(1)) * i64::from(page_size),
        }
    }
}

#[derive(Debug, Serialize)]
struct Message {
    message: String,
}

#[derive(Debug, Serialize)]
struct RefundEligibleProviders {
    provider_instance_ids: Vec<String>,
}

#[derive(Debug)]
struct Plan {
    id: i64,
    group_id: i64,
    name: String,
    product_name: String,
    price: f64,
    validity_days: i32,
    validity_unit: String,
}

#[derive(Debug)]
struct WechatResumeContext {
    token_hash: Vec<u8>,
    openid: String,
    payment_type: String,
    amount: String,
    order_type: String,
    plan_id: Option<i64>,
}

#[allow(clippy::too_many_lines)]
async fn create_order(
    State(state): State<PaymentApiState>,
    headers: HeaderMap,
    payload: Result<Json<CreateOrderRequest>, JsonRejection>,
) -> Result<Json<ApiEnvelope<CreateOrderResponse>>, PaymentError> {
    let user = state.authenticate(&headers).await?;
    let mut request = json_payload(payload)?;
    let wechat_resume = if request.wechat_resume_token.trim().is_empty() {
        None
    } else {
        let context = load_wechat_resume(&state, &request.wechat_resume_token, user.id).await?;
        apply_wechat_resume(&mut request, &context)?;
        Some(context)
    };
    request.payment_type = normalize_payment_type(&request.payment_type);
    request.order_type = normalize_order_type(&request.order_type)?;
    let config = load_payment_config(&state).await?;
    if !config.enabled {
        return Err(PaymentError::forbidden(
            "PAYMENT_DISABLED",
            "Payment system is disabled",
        ));
    }
    if user.status != "active" {
        return Err(PaymentError::forbidden(
            "USER_INACTIVE",
            "User account is disabled",
        ));
    }
    if request.order_type == ORDER_BALANCE && config.balance_disabled {
        return Err(PaymentError::forbidden(
            "BALANCE_PAYMENT_DISABLED",
            "Balance recharge has been disabled",
        ));
    }
    if !config.enabled_payment_types.is_empty()
        && !config
            .enabled_payment_types
            .iter()
            .any(|method| normalize_payment_type(method) == request.payment_type)
    {
        return Err(PaymentError::bad_request(
            "PAYMENT_METHOD_DISABLED",
            "Payment method is not enabled",
        ));
    }
    let plan = if request.order_type == ORDER_SUBSCRIPTION {
        Some(load_plan(&state, request.plan_id).await?)
    } else {
        validate_balance_amount(request.amount, config.min_amount, config.max_amount)?;
        None
    };
    let limit_amount = plan.as_ref().map_or(request.amount, |plan| plan.price);
    let provider = select_provider(
        &state,
        &request.payment_type,
        limit_amount,
        &config.load_balance_strategy,
    )
    .await?;
    let currency = provider_currency(&provider.provider_key, &provider.config);
    let gateway_base = if request.order_type == ORDER_SUBSCRIPTION
        && currency == "CNY"
        && config.subscription_usd_to_cny_rate > 0.0
    {
        round_currency(
            limit_amount * config.subscription_usd_to_cny_rate,
            &currency,
        )
    } else {
        limit_amount
    };
    let pay_amount = payment_amount(gateway_base, config.recharge_fee_rate, &currency)?;
    let credited_amount = if request.order_type == ORDER_BALANCE {
        round_decimal(request.amount * config.balance_recharge_multiplier, 8)
    } else {
        limit_amount
    };
    let canonical_return_url = canonical_return_url(&request.return_url, &headers)?;
    let is_mobile = request
        .is_mobile
        .unwrap_or_else(|| request_is_mobile(&headers));
    let client_ip = request_client_ip(&headers);
    let source_host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let source_url = headers
        .get(header::REFERER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let validity_days = plan
        .as_ref()
        .map(|plan| compute_validity_days(plan.validity_days, &plan.validity_unit));
    let snapshot = provider_snapshot(&provider, &request, &currency);
    let timeout = i64::from(config.order_timeout_minutes.max(1));
    let out_trade_no = allocate_out_trade_no();
    let recharge_code = format!("PAY-{}", &out_trade_no[5..]);

    let mut transaction = state.pool().begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(PAYMENT_ADVISORY_NAMESPACE ^ user.id)
        .execute(&mut *transaction)
        .await?;
    if let Some(context) = &wechat_resume {
        consume_wechat_resume(&mut transaction, context, user.id).await?;
    }
    expire_stale_orders(&mut transaction, user.id).await?;
    enforce_cancel_rate_limit(&mut transaction, user.id, &config).await?;
    enforce_pending_limit(&mut transaction, user.id, config.max_pending_orders).await?;
    enforce_daily_limit(&mut transaction, user.id, limit_amount, config.daily_limit).await?;
    let row = sqlx::query(
        r"
INSERT INTO payment_orders (
    user_id, user_email, user_name, amount, pay_amount, fee_rate,
    recharge_code, out_trade_no, payment_type, payment_trade_no,
    order_type, plan_id, subscription_group_id, subscription_days,
    provider_instance_id, provider_key, provider_snapshot, status,
    expires_at, client_ip, src_host, src_url, created_at, updated_at
) VALUES (
    $1, $2, $3, $4::numeric, $5::numeric, $6::numeric,
    $7, $8, $9, '', $10, $11, $12, $13, $14, $15, $16, 'PENDING',
    NOW() + make_interval(mins => $17), $18, $19, NULLIF($20, ''), NOW(), NOW()
)
RETURNING id
",
    )
    .bind(user.id)
    .bind(&user.email)
    .bind(&user.username)
    .bind(decimal_string(credited_amount, 8))
    .bind(decimal_string(pay_amount, 2))
    .bind(decimal_string(config.recharge_fee_rate, 4))
    .bind(&recharge_code)
    .bind(&out_trade_no)
    .bind(&request.payment_type)
    .bind(&request.order_type)
    .bind(plan.as_ref().map(|item| item.id))
    .bind(plan.as_ref().map(|item| item.group_id))
    .bind(validity_days)
    .bind(provider.instance_id.to_string())
    .bind(&provider.provider_key)
    .bind(&snapshot)
    .bind(timeout)
    .bind(&client_ip)
    .bind(&source_host)
    .bind(&source_url)
    .fetch_one(&mut *transaction)
    .await?;
    let order_id: i64 = row.try_get("id")?;
    transaction.commit().await?;

    let resume_token = if canonical_return_url.is_empty() {
        String::new()
    } else {
        state.create_resume_token(ResumeClaims {
            order_id,
            user_id: user.id,
            provider_instance_id: provider.instance_id.to_string(),
            provider_key: provider.provider_key.clone(),
            payment_type: request.payment_type.clone(),
            canonical_return_url: canonical_return_url.clone(),
            issued_at: 0,
            expires_at: 0,
        })?
    };
    let provider_return_url = payment_return_url(
        &canonical_return_url,
        order_id,
        &out_trade_no,
        &resume_token,
    )?;
    let subject = payment_subject(plan.as_ref(), limit_amount, &currency, &config);
    let provider_result = create_payment(
        &state,
        &provider,
        &CreatePaymentInput {
            out_trade_no: &out_trade_no,
            amount: pay_amount,
            subject: &subject,
            payment_type: &request.payment_type,
            openid: &request.openid,
            client_ip: &client_ip,
            is_mobile,
            return_url: &provider_return_url,
        },
    )
    .await;
    let provider_result = match provider_result {
        Ok(result) => result,
        Err(error) => {
            let _ = sqlx::query(
                "UPDATE payment_orders SET status = 'FAILED', failed_at = NOW(), failed_reason = $2, updated_at = NOW() WHERE id = $1 AND status = 'PENDING'",
            )
            .bind(order_id)
            .bind(error.to_string())
            .execute(state.pool())
            .await;
            let _ = write_audit(
                state.pool(),
                order_id,
                "ORDER_CREATE_FAILED",
                &format!("user:{}", user.id),
                json!({"provider": provider.provider_key}),
            )
            .await;
            return Err(error);
        }
    };
    sqlx::query(
        r"
UPDATE payment_orders
SET payment_trade_no = $2, pay_url = NULLIF($3, ''), qr_code = NULLIF($4, ''), updated_at = NOW()
WHERE id = $1 AND status = 'PENDING'
",
    )
    .bind(order_id)
    .bind(&provider_result.trade_no)
    .bind(&provider_result.pay_url)
    .bind(&provider_result.qr_code)
    .execute(state.pool())
    .await?;
    write_audit(
        state.pool(),
        order_id,
        "ORDER_CREATED",
        &format!("user:{}", user.id),
        json!({
            "paymentAmount": request.amount,
            "creditedAmount": credited_amount,
            "payAmount": pay_amount,
            "providerInstanceID": provider.instance_id,
            "providerKey": provider.provider_key,
            "paymentType": request.payment_type,
            "orderType": request.order_type,
            "paymentSource": request.payment_source,
        }),
    )
    .await?;
    let order = load_order_by_id(state.pool(), order_id).await?;
    let jsapi = provider_result.jsapi.clone();
    Ok(Json(ApiEnvelope::success(CreateOrderResponse {
        order_id,
        amount: credited_amount,
        pay_amount,
        fee_rate: config.recharge_fee_rate,
        status: STATUS_PENDING.to_owned(),
        result_type: if jsapi.is_some() {
            "jsapi_ready".to_owned()
        } else {
            "order_created".to_owned()
        },
        payment_type: request.payment_type,
        out_trade_no,
        pay_url: provider_result.pay_url,
        qr_code: provider_result.qr_code,
        client_secret: provider_result.client_secret,
        intent_id: provider_result.intent_id,
        currency: if provider_result.currency.is_empty() {
            currency
        } else {
            provider_result.currency
        },
        country_code: provider_result.country_code,
        payment_env: provider_result.payment_env,
        expires_at: order.view.expires_at,
        payment_mode: provider.payment_mode,
        resume_token,
        jsapi: jsapi.clone(),
        jsapi_payload: jsapi,
    })))
}

async fn my_orders(
    State(state): State<PaymentApiState>,
    headers: HeaderMap,
    Query(query): Query<OrdersQuery>,
) -> Result<Json<ApiEnvelope<Paginated<super::models::OrderView>>>, PaymentError> {
    let user = state.authenticate(&headers).await?;
    let pagination = query.pagination();
    let total = sqlx::query_scalar::<_, i64>(
        r"
SELECT COUNT(*)
FROM payment_orders
WHERE user_id = $1
  AND ($2 = '' OR status = $2)
  AND ($3 = '' OR order_type = $3)
  AND ($4 = '' OR payment_type = $4)
",
    )
    .bind(user.id)
    .bind(query.status.trim())
    .bind(query.order_type.trim())
    .bind(query.payment_type.trim())
    .fetch_one(state.pool())
    .await?;
    let sql = format!(
        "{ORDER_SELECT} WHERE o.user_id = $1 AND ($2 = '' OR o.status = $2) \
         AND ($3 = '' OR o.order_type = $3) AND ($4 = '' OR o.payment_type = $4) \
         ORDER BY o.created_at DESC, o.id DESC LIMIT $5 OFFSET $6"
    );
    let rows = sqlx::query(&sql)
        .bind(user.id)
        .bind(query.status.trim())
        .bind(query.order_type.trim())
        .bind(query.payment_type.trim())
        .bind(i64::from(pagination.page_size))
        .bind(pagination.offset)
        .fetch_all(state.pool())
        .await?;
    let orders = rows
        .iter()
        .map(order_from_row)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|order| order.view)
        .collect();
    Ok(Json(ApiEnvelope::success(Paginated::new(
        orders, total, pagination,
    ))))
}

async fn get_order(
    State(state): State<PaymentApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<ApiEnvelope<super::models::OrderView>>, PaymentError> {
    let user = state.authenticate(&headers).await?;
    let order = load_order_by_id(state.pool(), id).await?;
    ensure_owner(&order, user.id)?;
    Ok(Json(ApiEnvelope::success(order.view)))
}

async fn verify_order(
    State(state): State<PaymentApiState>,
    headers: HeaderMap,
    payload: Result<Json<VerifyRequest>, JsonRejection>,
) -> Result<Json<ApiEnvelope<super::models::OrderView>>, PaymentError> {
    let user = state.authenticate(&headers).await?;
    let request = json_payload(payload)?;
    let out_trade_no = validate_out_trade_no(&request.out_trade_no)?;
    let mut order = load_order_by_trade_no(state.pool(), &out_trade_no).await?;
    ensure_owner(&order, user.id)?;
    if matches!(order.view.status.as_str(), STATUS_PENDING | STATUS_EXPIRED) {
        reconcile_order(&state, &order).await?;
        order = load_order_by_id(state.pool(), order.view.id).await?;
    }
    Ok(Json(ApiEnvelope::success(order.view)))
}

async fn cancel_order(
    State(state): State<PaymentApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<ApiEnvelope<Message>>, PaymentError> {
    let user = state.authenticate(&headers).await?;
    let order = load_order_by_id(state.pool(), id).await?;
    ensure_owner(&order, user.id)?;
    if order.view.status != STATUS_PENDING {
        return Err(PaymentError::bad_request(
            "INVALID_STATUS",
            "Order cannot be cancelled in its current status",
        ));
    }
    if reconcile_order(&state, &order).await? {
        return Ok(Json(ApiEnvelope::success(Message {
            message: "already_paid".to_owned(),
        })));
    }
    let provider = provider_for_order(&state, &order).await?;
    cancel_payment(
        &state,
        &provider,
        &order.view.out_trade_no,
        &order.payment_trade_no,
    )
    .await?;
    let updated = sqlx::query(
        "UPDATE payment_orders SET status = 'CANCELLED', updated_at = NOW() WHERE id = $1 AND user_id = $2 AND status = 'PENDING'",
    )
    .bind(id)
    .bind(user.id)
    .execute(state.pool())
    .await?
    .rows_affected();
    if updated == 0 {
        return Err(PaymentError::conflict(
            "CONFLICT",
            "Order status changed while it was being cancelled",
        ));
    }
    write_audit(
        state.pool(),
        id,
        "ORDER_CANCELLED",
        &format!("user:{}", user.id),
        json!({"detail": "user cancelled order"}),
    )
    .await?;
    Ok(Json(ApiEnvelope::success(Message {
        message: "cancelled".to_owned(),
    })))
}

async fn request_refund(
    State(state): State<PaymentApiState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    payload: Result<Json<RefundRequest>, JsonRejection>,
) -> Result<Json<ApiEnvelope<Message>>, PaymentError> {
    let user = state.authenticate(&headers).await?;
    let request = json_payload(payload)?;
    let reason = request.reason.trim();
    if reason.len() > 2_000 {
        return Err(PaymentError::bad_request(
            "INVALID_REASON",
            "Refund reason is too long",
        ));
    }
    let affected = sqlx::query(
        r"
UPDATE payment_orders o
SET status = 'REFUND_REQUESTED', refund_requested_at = NOW(),
    refund_requested_by = 'user', refund_request_reason = NULLIF($3, ''), updated_at = NOW()
WHERE o.id = $1 AND o.user_id = $2 AND o.order_type = 'balance' AND o.status = 'COMPLETED'
  AND EXISTS (
    SELECT 1 FROM payment_provider_instances p
    WHERE p.id::text = o.provider_instance_id
      AND p.enabled = TRUE AND p.refund_enabled = TRUE AND p.allow_user_refund = TRUE
  )
",
    )
    .bind(id)
    .bind(user.id)
    .bind(reason)
    .execute(state.pool())
    .await?
    .rows_affected();
    if affected == 0 {
        let order = load_order_by_id(state.pool(), id).await?;
        ensure_owner(&order, user.id)?;
        if order.view.order_type != ORDER_BALANCE {
            return Err(PaymentError::bad_request(
                "INVALID_ORDER_TYPE",
                "Only balance orders can request a refund",
            ));
        }
        if order.view.status != STATUS_COMPLETED {
            return Err(PaymentError::bad_request(
                "INVALID_STATUS",
                "Only completed orders can request a refund",
            ));
        }
        return Err(PaymentError::forbidden(
            "USER_REFUND_DISABLED",
            "Refund is not enabled for this provider",
        ));
    }
    write_audit(
        state.pool(),
        id,
        "REFUND_REQUESTED",
        &format!("user:{}", user.id),
        json!({"reason": reason}),
    )
    .await?;
    Ok(Json(ApiEnvelope::success(Message {
        message: "refund requested".to_owned(),
    })))
}

async fn refund_eligible_providers(
    State(state): State<PaymentApiState>,
    headers: HeaderMap,
) -> Result<Json<ApiEnvelope<RefundEligibleProviders>>, PaymentError> {
    let _user = state.authenticate(&headers).await?;
    let ids = sqlx::query_scalar::<_, i64>(
        r"
SELECT id FROM payment_provider_instances
WHERE enabled = TRUE AND refund_enabled = TRUE AND allow_user_refund = TRUE
ORDER BY sort_order, id
",
    )
    .fetch_all(state.pool())
    .await?
    .into_iter()
    .map(|id| id.to_string())
    .collect();
    Ok(Json(ApiEnvelope::success(RefundEligibleProviders {
        provider_instance_ids: ids,
    })))
}

async fn public_verify(
    State(state): State<PaymentApiState>,
    Json(request): Json<VerifyRequest>,
) -> Result<Json<ApiEnvelope<PublicOrderVerify>>, PaymentError> {
    let out_trade_no = validate_out_trade_no(&request.out_trade_no)?;
    let order = load_order_by_trade_no(state.pool(), &out_trade_no).await?;
    let view = &order.view;
    Ok(Json(ApiEnvelope::success(PublicOrderVerify {
        out_trade_no: view.out_trade_no.clone(),
        status: view.status.clone(),
        paid: public_paid_status(&view.status),
        created_at: view.created_at.clone(),
        expires_at: view.expires_at.clone(),
        paid_at: view.paid_at.clone(),
        completed_at: view.completed_at.clone(),
    })))
}

async fn public_resolve(
    State(state): State<PaymentApiState>,
    Json(request): Json<ResolveRequest>,
) -> Result<Json<ApiEnvelope<super::models::PublicOrderResult>>, PaymentError> {
    let claims = state.parse_resume_token(request.resume_token.trim())?;
    let mut order = load_order_by_id(state.pool(), claims.order_id).await?;
    validate_resume_claims(&order, &claims)?;
    if matches!(order.view.status.as_str(), STATUS_PENDING | STATUS_EXPIRED) {
        reconcile_order(&state, &order).await?;
        order = load_order_by_id(state.pool(), order.view.id).await?;
    }
    Ok(Json(ApiEnvelope::success(public_result(&order))))
}

pub(super) async fn reconcile_order(
    state: &PaymentApiState,
    order: &OrderRecord,
) -> Result<bool, PaymentError> {
    if !matches!(order.view.status.as_str(), STATUS_PENDING | STATUS_EXPIRED) {
        return Ok(public_paid_status(&order.view.status));
    }
    let provider = match provider_for_order(state, order).await {
        Ok(provider) => provider,
        Err(error) => {
            tracing::warn!(order_id = order.view.id, error = ?error, "payment reconciliation provider is unavailable");
            return Ok(false);
        }
    };
    let result = match query_payment(
        state,
        &provider,
        &order.view.out_trade_no,
        &order.payment_trade_no,
    )
    .await
    {
        Ok(result) => result,
        Err(error) => {
            tracing::warn!(order_id = order.view.id, error = ?error, "payment reconciliation query failed");
            return Ok(false);
        }
    };
    if result.status == "paid" {
        return confirm_payment(state, order.view.id, &provider, &result).await;
    }
    Ok(false)
}

pub(super) async fn confirm_notification(
    state: &PaymentApiState,
    notification: &super::models::PaymentNotification,
) -> Result<(), PaymentError> {
    if !notification.success {
        return Ok(());
    }
    let order = load_order_by_trade_no(state.pool(), &notification.order_id).await?;
    let provider = provider_for_order(state, &order).await?;
    if provider.provider_key != notification.provider_key {
        return Err(PaymentError::bad_request(
            "PAYMENT_PROVIDER_MISMATCH",
            "Webhook provider does not match the payment order",
        ));
    }
    confirm_payment(
        state,
        order.view.id,
        &provider,
        &ProviderQueryResult {
            trade_no: notification.trade_no.clone(),
            status: "paid".to_owned(),
            amount: notification.amount,
            metadata: notification.metadata.clone(),
        },
    )
    .await
    .map(|_| ())
}

#[allow(clippy::too_many_lines)]
async fn confirm_payment(
    state: &PaymentApiState,
    order_id: i64,
    provider: &super::models::ProviderSelection,
    payment: &ProviderQueryResult,
) -> Result<bool, PaymentError> {
    if !payment.amount.is_finite() || payment.amount <= 0.0 {
        return Err(PaymentError::bad_request(
            "PAYMENT_INVALID_AMOUNT",
            "Payment provider returned an invalid amount",
        ));
    }
    let mut transaction = state.pool().begin().await?;
    let sql = format!("{ORDER_SELECT} WHERE o.id = $1 FOR UPDATE");
    let row = sqlx::query(&sql)
        .bind(order_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| PaymentError::not_found("NOT_FOUND", "Order not found"))?;
    let order = order_from_row(&row)?;
    if order.view.status == STATUS_COMPLETED || is_refund_status(&order.view.status) {
        transaction.commit().await?;
        return Ok(true);
    }
    if !matches!(
        order.view.status.as_str(),
        STATUS_PENDING
            | STATUS_CANCELLED
            | STATUS_EXPIRED
            | STATUS_PAID
            | STATUS_FAILED
            | STATUS_RECHARGING
    ) {
        return Err(PaymentError::conflict(
            "CONFLICT",
            "Order cannot be fulfilled in its current status",
        ));
    }
    let expected_provider_key = order
        .provider_snapshot
        .get("provider_key")
        .and_then(Value::as_str)
        .unwrap_or(&order.provider_key);
    if !expected_provider_key.is_empty()
        && !provider
            .provider_key
            .eq_ignore_ascii_case(expected_provider_key)
    {
        return Err(PaymentError::bad_request(
            "PAYMENT_PROVIDER_MISMATCH",
            "Payment provider does not match the order",
        ));
    }
    if order.view.status == STATUS_EXPIRED
        && chrono::Utc::now().timestamp() - order.updated_at_epoch > PAYMENT_EXPIRY_GRACE_SECONDS
    {
        insert_audit_tx(
            &mut transaction,
            order_id,
            "PAYMENT_AFTER_EXPIRY",
            &provider.provider_key,
            json!({"tradeNo": payment.trade_no, "paidAmount": payment.amount}),
        )
        .await?;
        transaction.commit().await?;
        return Ok(false);
    }
    validate_provider_metadata(&order, &payment.metadata)?;
    if (order.view.pay_amount - payment.amount).abs() > amount_tolerance(&order.view.currency) {
        return Err(PaymentError::bad_request(
            "PAYMENT_AMOUNT_MISMATCH",
            "Paid amount does not match the order",
        ));
    }
    let audit_action = if order.view.order_type == ORDER_SUBSCRIPTION {
        "SUBSCRIPTION_SUCCESS"
    } else {
        "RECHARGE_SUCCESS"
    };
    let already_fulfilled = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM payment_audit_logs WHERE order_id = $1 AND action = $2)",
    )
    .bind(order_id.to_string())
    .bind(audit_action)
    .fetch_one(&mut *transaction)
    .await?;
    if !already_fulfilled {
        if order.view.order_type == ORDER_SUBSCRIPTION {
            fulfill_subscription(&mut transaction, &order).await?;
        } else {
            fulfill_balance(&mut transaction, &order).await?;
        }
        insert_audit_tx(
            &mut transaction,
            order_id,
            audit_action,
            "system",
            json!({
                "creditedAmount": order.view.amount,
                "payAmount": payment.amount,
                "tradeNo": payment.trade_no,
                "rechargeCode": order.recharge_code,
            }),
        )
        .await?;
    }
    sqlx::query(
        r"
UPDATE payment_orders
SET status = 'COMPLETED', pay_amount = $2::numeric, payment_trade_no = $3,
    paid_at = COALESCE(paid_at, NOW()), completed_at = COALESCE(completed_at, NOW()),
    failed_at = NULL, failed_reason = NULL, updated_at = NOW()
WHERE id = $1
",
    )
    .bind(order_id)
    .bind(decimal_string(payment.amount, 2))
    .bind(&payment.trade_no)
    .execute(&mut *transaction)
    .await?;
    insert_audit_tx(
        &mut transaction,
        order_id,
        "ORDER_PAID",
        &provider.provider_key,
        json!({"tradeNo": payment.trade_no, "paidAmount": payment.amount}),
    )
    .await?;
    transaction.commit().await?;
    Ok(true)
}

async fn fulfill_balance(
    transaction: &mut Transaction<'_, Postgres>,
    order: &OrderRecord,
) -> Result<(), PaymentError> {
    let affected = sqlx::query(
        r"
UPDATE users
SET balance = balance + $2::numeric,
    total_recharged = total_recharged + $2::numeric,
    updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL
",
    )
    .bind(order.view.user_id)
    .bind(decimal_string(order.view.amount, 8))
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if affected != 1 {
        return Err(PaymentError::not_found(
            "USER_NOT_FOUND",
            "Payment user no longer exists",
        ));
    }
    Ok(())
}

async fn fulfill_subscription(
    transaction: &mut Transaction<'_, Postgres>,
    order: &OrderRecord,
) -> Result<(), PaymentError> {
    let group_id = order.subscription_group_id.ok_or_else(|| {
        PaymentError::bad_request("INVALID_STATUS", "Order is missing subscription group data")
    })?;
    let days = order.subscription_days.unwrap_or(30).clamp(1, 3_650);
    let group_active = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM groups WHERE id = $1 AND status = 'active' AND subscription_type = 'subscription' AND deleted_at IS NULL)",
    )
    .bind(group_id)
    .fetch_one(&mut **transaction)
    .await?;
    if !group_active {
        return Err(PaymentError::bad_request(
            "GROUP_NOT_FOUND",
            "Subscription group is no longer available",
        ));
    }
    let existing = sqlx::query(
        r"
SELECT id, expires_at > NOW() AS active
FROM user_subscriptions
WHERE user_id = $1 AND group_id = $2 AND deleted_at IS NULL
FOR UPDATE
",
    )
    .bind(order.view.user_id)
    .bind(group_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let note = format!("payment order {}", order.view.id);
    if let Some(row) = existing {
        let active: bool = row.try_get("active")?;
        let id: i64 = row.try_get("id")?;
        if active {
            sqlx::query(
                r"
UPDATE user_subscriptions
SET expires_at = expires_at + make_interval(days => $2), status = 'active',
    notes = CASE WHEN COALESCE(notes, '') = '' THEN $3 ELSE notes || E'\n' || $3 END,
    updated_at = NOW()
WHERE id = $1
",
            )
            .bind(id)
            .bind(days)
            .bind(&note)
            .execute(&mut **transaction)
            .await?;
        } else {
            sqlx::query(
                r"
UPDATE user_subscriptions
SET starts_at = NOW(), expires_at = NOW() + make_interval(days => $2), status = 'active',
    daily_window_start = NULL, weekly_window_start = NULL, monthly_window_start = NULL,
    daily_usage_usd = 0, weekly_usage_usd = 0, monthly_usage_usd = 0,
    assigned_by = NULL, assigned_at = NOW(), notes = $3, updated_at = NOW()
WHERE id = $1
",
            )
            .bind(id)
            .bind(days)
            .bind(&note)
            .execute(&mut **transaction)
            .await?;
        }
    } else {
        sqlx::query(
            r"
INSERT INTO user_subscriptions (
    user_id, group_id, starts_at, expires_at, status, assigned_by, assigned_at,
    notes, created_at, updated_at
) VALUES ($1, $2, NOW(), NOW() + make_interval(days => $3), 'active', NULL, NOW(), $4, NOW(), NOW())
",
        )
        .bind(order.view.user_id)
        .bind(group_id)
        .bind(days)
        .bind(&note)
        .execute(&mut **transaction)
        .await?;
    }
    insert_audit_tx(
        transaction,
        order.view.id,
        "SUBSCRIPTION_ASSIGNED",
        "system",
        json!({"groupID": group_id, "validityDays": days}),
    )
    .await?;
    Ok(())
}

async fn load_wechat_resume(
    state: &PaymentApiState,
    raw_token: &str,
    user_id: i64,
) -> Result<WechatResumeContext, PaymentError> {
    let token_hash = Sha256::digest(raw_token.trim().as_bytes()).to_vec();
    let row = sqlx::query(
        r"
SELECT openid, payment_type, amount, order_type, plan_id
FROM auth_wechat_payment_resume_tokens
WHERE token_hash = $1 AND (user_id IS NULL OR user_id = $2)
  AND consumed_at IS NULL AND expires_at > NOW()
",
    )
    .bind(&token_hash)
    .bind(user_id)
    .fetch_optional(state.pool())
    .await?
    .ok_or_else(|| {
        PaymentError::bad_request(
            "INVALID_WECHAT_PAYMENT_RESUME_TOKEN",
            "WeChat payment resume token is invalid or expired",
        )
    })?;
    Ok(WechatResumeContext {
        token_hash,
        openid: row.try_get("openid")?,
        payment_type: row.try_get("payment_type")?,
        amount: row.try_get("amount")?,
        order_type: row.try_get("order_type")?,
        plan_id: row.try_get("plan_id")?,
    })
}

fn apply_wechat_resume(
    request: &mut CreateOrderRequest,
    context: &WechatResumeContext,
) -> Result<(), PaymentError> {
    if context.openid.trim().is_empty() {
        return Err(PaymentError::bad_request(
            "INVALID_WECHAT_PAYMENT_RESUME_TOKEN",
            "WeChat payment resume token is missing openid",
        ));
    }
    let token_method = normalize_payment_type(&context.payment_type);
    if !request.payment_type.trim().is_empty()
        && normalize_payment_type(&request.payment_type) != token_method
    {
        return Err(PaymentError::bad_request(
            "INVALID_WECHAT_PAYMENT_RESUME_TOKEN",
            "WeChat payment resume token method does not match the request",
        ));
    }
    request.payment_type = if token_method.is_empty() {
        "wxpay".to_owned()
    } else {
        token_method
    };
    context.openid.trim().clone_into(&mut request.openid);
    if !context.amount.trim().is_empty() {
        request.amount = context.amount.trim().parse().map_err(|_| {
            PaymentError::bad_request(
                "INVALID_WECHAT_PAYMENT_RESUME_TOKEN",
                "WeChat payment resume amount is invalid",
            )
        })?;
    }
    if !context.order_type.trim().is_empty() {
        request.order_type.clone_from(&context.order_type);
    }
    if let Some(plan_id) = context.plan_id.filter(|id| *id > 0) {
        request.plan_id = plan_id;
    }
    Ok(())
}

async fn consume_wechat_resume(
    transaction: &mut Transaction<'_, Postgres>,
    context: &WechatResumeContext,
    user_id: i64,
) -> Result<(), PaymentError> {
    let affected = sqlx::query(
        r"
UPDATE auth_wechat_payment_resume_tokens
SET consumed_at = NOW(), user_id = COALESCE(user_id, $2)
WHERE token_hash = $1 AND (user_id IS NULL OR user_id = $2)
  AND consumed_at IS NULL AND expires_at > NOW()
",
    )
    .bind(&context.token_hash)
    .bind(user_id)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    if affected != 1 {
        return Err(PaymentError::bad_request(
            "INVALID_WECHAT_PAYMENT_RESUME_TOKEN",
            "WeChat payment resume token has already been used",
        ));
    }
    Ok(())
}

async fn load_plan(state: &PaymentApiState, plan_id: i64) -> Result<Plan, PaymentError> {
    if plan_id <= 0 {
        return Err(PaymentError::bad_request(
            "INVALID_INPUT",
            "Subscription order requires a plan",
        ));
    }
    let row = sqlx::query(
        r"
SELECT p.id, p.group_id, p.name, p.product_name, p.price::text AS price,
       p.validity_days, p.validity_unit
FROM subscription_plans p
JOIN groups g ON g.id = p.group_id
WHERE p.id = $1 AND p.for_sale = TRUE AND g.status = 'active'
  AND g.subscription_type = 'subscription' AND g.deleted_at IS NULL
",
    )
    .bind(plan_id)
    .fetch_optional(state.pool())
    .await?
    .ok_or_else(|| {
        PaymentError::not_found("PLAN_NOT_AVAILABLE", "Subscription plan is not available")
    })?;
    Ok(Plan {
        id: row.try_get("id")?,
        group_id: row.try_get("group_id")?,
        name: row.try_get("name")?,
        product_name: row.try_get("product_name")?,
        price: row
            .try_get::<String, _>("price")?
            .parse()
            .map_err(|error| PaymentError::internal("parse subscription plan price", error))?,
        validity_days: row.try_get("validity_days")?,
        validity_unit: row.try_get("validity_unit")?,
    })
}

async fn load_order_by_id(pool: &PgPool, id: i64) -> Result<OrderRecord, PaymentError> {
    if id <= 0 {
        return Err(PaymentError::bad_request(
            "INVALID_ORDER_ID",
            "Order id is invalid",
        ));
    }
    let sql = format!("{ORDER_SELECT} WHERE o.id = $1");
    sqlx::query(&sql)
        .bind(id)
        .fetch_optional(pool)
        .await?
        .as_ref()
        .map(order_from_row)
        .transpose()?
        .ok_or_else(|| PaymentError::not_found("NOT_FOUND", "Order not found"))
}

pub(super) async fn load_order_by_trade_no(
    pool: &PgPool,
    out_trade_no: &str,
) -> Result<OrderRecord, PaymentError> {
    let sql = format!("{ORDER_SELECT} WHERE o.out_trade_no = $1");
    sqlx::query(&sql)
        .bind(out_trade_no)
        .fetch_optional(pool)
        .await?
        .as_ref()
        .map(order_from_row)
        .transpose()?
        .ok_or_else(|| PaymentError::not_found("NOT_FOUND", "Order not found"))
}

pub(super) async fn provider_for_order(
    state: &PaymentApiState,
    order: &OrderRecord,
) -> Result<super::models::ProviderSelection, PaymentError> {
    let snapshot_instance = order
        .provider_snapshot
        .get("provider_instance_id")
        .and_then(|value| value.as_i64().or_else(|| value.as_str()?.parse().ok()));
    let instance_id = snapshot_instance.or_else(|| {
        order
            .view
            .provider_instance_id
            .as_deref()
            .and_then(|value| value.parse().ok())
    });
    if let Some(instance_id) = instance_id {
        return load_provider_instance(state, instance_id).await;
    }
    let provider_key = if order.provider_key.is_empty() {
        normalize_payment_type(&order.view.payment_type)
    } else {
        order.provider_key.clone()
    };
    let instance_id = sqlx::query_scalar::<_, i64>(
        "SELECT id FROM payment_provider_instances WHERE enabled = TRUE AND provider_key = $1 ORDER BY sort_order, id LIMIT 2",
    )
    .bind(&provider_key)
    .fetch_all(state.pool())
    .await?;
    if instance_id.len() != 1 {
        return Err(PaymentError::unavailable(
            "PAYMENT_PROVIDER_MISSING",
            "Payment order provider cannot be resolved unambiguously",
        ));
    }
    load_provider_instance(state, instance_id[0]).await
}

fn validate_resume_claims(order: &OrderRecord, claims: &ResumeClaims) -> Result<(), PaymentError> {
    let snapshot_instance = order
        .provider_snapshot
        .get("provider_instance_id")
        .and_then(|value| value.as_str())
        .map_or_else(
            || order.view.provider_instance_id.clone().unwrap_or_default(),
            str::to_owned,
        );
    let snapshot_key = order
        .provider_snapshot
        .get("provider_key")
        .and_then(Value::as_str)
        .unwrap_or(&order.provider_key);
    let matches = (claims.user_id <= 0 || claims.user_id == order.view.user_id)
        && (claims.provider_instance_id.is_empty()
            || claims.provider_instance_id == snapshot_instance)
        && (claims.provider_key.is_empty()
            || claims.provider_key.eq_ignore_ascii_case(snapshot_key))
        && (claims.payment_type.is_empty()
            || normalize_payment_type(&claims.payment_type)
                == normalize_payment_type(&order.view.payment_type));
    if !matches {
        return Err(PaymentError::bad_request(
            "INVALID_RESUME_TOKEN",
            "Resume token does not match the payment order",
        ));
    }
    Ok(())
}

fn validate_provider_metadata(
    order: &OrderRecord,
    actual: &HashMap<String, String>,
) -> Result<(), PaymentError> {
    for (snapshot_key, metadata_key) in [
        ("merchant_app_id", "merchant_app_id"),
        ("merchant_id", "merchant_id"),
        ("currency", "currency"),
    ] {
        let expected = order
            .provider_snapshot
            .get(snapshot_key)
            .and_then(Value::as_str)
            .unwrap_or_default();
        let actual = actual.get(metadata_key).map_or("", String::as_str);
        if !expected.is_empty() && !actual.is_empty() && !expected.eq_ignore_ascii_case(actual) {
            return Err(PaymentError::bad_request(
                "PAYMENT_PROVIDER_METADATA_MISMATCH",
                "Payment provider metadata does not match the order",
            ));
        }
    }
    Ok(())
}

fn provider_snapshot(
    provider: &super::models::ProviderSelection,
    request: &CreateOrderRequest,
    currency: &str,
) -> Value {
    let mut snapshot = serde_json::Map::from_iter([
        ("schema_version".to_owned(), json!(2)),
        (
            "provider_instance_id".to_owned(),
            json!(provider.instance_id.to_string()),
        ),
        ("provider_key".to_owned(), json!(provider.provider_key)),
        ("payment_mode".to_owned(), json!(provider.payment_mode)),
        ("currency".to_owned(), json!(currency)),
    ]);
    match provider.provider_key.as_str() {
        "easypay" => insert_config_snapshot(&mut snapshot, provider, "pid", "merchant_id"),
        "alipay" => insert_config_snapshot(&mut snapshot, provider, "appId", "merchant_app_id"),
        "wxpay" => {
            let app_id = if request.openid.trim().is_empty() {
                provider.config.get("appId")
            } else {
                provider
                    .config
                    .get("mpAppId")
                    .or_else(|| provider.config.get("appId"))
            };
            if let Some(app_id) = app_id.filter(|value| !value.trim().is_empty()) {
                snapshot.insert("merchant_app_id".to_owned(), json!(app_id));
            }
            insert_config_snapshot(&mut snapshot, provider, "mchId", "merchant_id");
        }
        "airwallex" => {
            insert_config_snapshot(&mut snapshot, provider, "accountId", "merchant_id");
        }
        _ => {}
    }
    Value::Object(snapshot)
}

fn insert_config_snapshot(
    snapshot: &mut serde_json::Map<String, Value>,
    provider: &super::models::ProviderSelection,
    config_key: &str,
    snapshot_key: &str,
) {
    if let Some(value) = provider
        .config
        .get(config_key)
        .filter(|value| !value.trim().is_empty())
    {
        snapshot.insert(snapshot_key.to_owned(), json!(value));
    }
}

async fn expire_stale_orders(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i64,
) -> Result<(), PaymentError> {
    sqlx::query(
        "UPDATE payment_orders SET status = 'EXPIRED', updated_at = NOW() WHERE user_id = $1 AND status = 'PENDING' AND expires_at <= NOW()",
    )
    .bind(user_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn enforce_pending_limit(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i64,
    maximum: i32,
) -> Result<(), PaymentError> {
    let maximum = maximum.max(1);
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM payment_orders WHERE user_id = $1 AND status = 'PENDING'",
    )
    .bind(user_id)
    .fetch_one(&mut **transaction)
    .await?;
    if count >= i64::from(maximum) {
        return Err(PaymentError::too_many_requests(
            "TOO_MANY_PENDING",
            "Too many pending payment orders",
        ));
    }
    Ok(())
}

async fn enforce_daily_limit(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i64,
    amount: f64,
    limit: f64,
) -> Result<(), PaymentError> {
    if limit <= 0.0 {
        return Ok(());
    }
    let used = sqlx::query_scalar::<_, String>(
        r"
SELECT COALESCE(SUM(CASE WHEN order_type = 'balance' THEN pay_amount ELSE amount END), 0)::text
FROM payment_orders
WHERE user_id = $1 AND status IN ('PAID', 'RECHARGING', 'COMPLETED')
  AND paid_at >= date_trunc('day', NOW() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'
",
    )
    .bind(user_id)
    .fetch_one(&mut **transaction)
    .await?
    .parse::<f64>()
    .unwrap_or_default();
    if used + amount > limit + f64::EPSILON {
        return Err(PaymentError::too_many_requests(
            "DAILY_LIMIT_EXCEEDED",
            "Daily payment limit has been exceeded",
        ));
    }
    Ok(())
}

async fn enforce_cancel_rate_limit(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i64,
    config: &super::models::PaymentConfig,
) -> Result<(), PaymentError> {
    if !config.cancel_rate_limit_enabled || config.cancel_rate_limit_max <= 0 {
        return Ok(());
    }
    let multiplier = match config.cancel_rate_limit_unit.as_str() {
        "minute" => 60,
        "hour" => 3_600,
        _ => 86_400,
    };
    let seconds = i64::from(config.cancel_rate_limit_window.max(1)) * multiplier;
    let count = sqlx::query_scalar::<_, i64>(
        r"
SELECT COUNT(*) FROM payment_audit_logs
WHERE action = 'ORDER_CANCELLED' AND operator = $1
  AND created_at >= NOW() - make_interval(secs => $2)
",
    )
    .bind(format!("user:{user_id}"))
    .bind(seconds)
    .fetch_one(&mut **transaction)
    .await?;
    if count >= i64::from(config.cancel_rate_limit_max) {
        return Err(PaymentError::too_many_requests(
            "CANCEL_RATE_LIMITED",
            "Too many recently cancelled payment orders",
        ));
    }
    Ok(())
}

async fn write_audit(
    pool: &PgPool,
    order_id: i64,
    action: &str,
    operator: &str,
    detail: Value,
) -> Result<(), PaymentError> {
    sqlx::query(
        r"
INSERT INTO payment_audit_logs (order_id, action, detail, operator, created_at)
VALUES ($1, $2, $3, $4, NOW())
ON CONFLICT (order_id, action) DO NOTHING
",
    )
    .bind(order_id.to_string())
    .bind(action)
    .bind(detail.to_string())
    .bind(operator)
    .execute(pool)
    .await?;
    Ok(())
}

async fn insert_audit_tx(
    transaction: &mut Transaction<'_, Postgres>,
    order_id: i64,
    action: &str,
    operator: &str,
    detail: Value,
) -> Result<(), PaymentError> {
    sqlx::query(
        r"
INSERT INTO payment_audit_logs (order_id, action, detail, operator, created_at)
VALUES ($1, $2, $3, $4, NOW())
ON CONFLICT (order_id, action) DO NOTHING
",
    )
    .bind(order_id.to_string())
    .bind(action)
    .bind(detail.to_string())
    .bind(operator)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn normalize_order_type(raw: &str) -> Result<String, PaymentError> {
    match raw.trim() {
        "" | ORDER_BALANCE => Ok(ORDER_BALANCE.to_owned()),
        ORDER_SUBSCRIPTION => Ok(ORDER_SUBSCRIPTION.to_owned()),
        _ => Err(PaymentError::bad_request(
            "INVALID_ORDER_TYPE",
            "Payment order type is invalid",
        )),
    }
}

fn validate_balance_amount(amount: f64, minimum: f64, maximum: f64) -> Result<(), PaymentError> {
    if !amount.is_finite() || amount <= 0.0 {
        return Err(PaymentError::bad_request(
            "INVALID_AMOUNT",
            "Amount must be a positive number",
        ));
    }
    if (minimum > 0.0 && amount < minimum) || (maximum > 0.0 && amount > maximum) {
        return Err(PaymentError::bad_request(
            "INVALID_AMOUNT",
            "Amount is outside the configured range",
        ));
    }
    Ok(())
}

fn validate_out_trade_no(raw: &str) -> Result<String, PaymentError> {
    let value = raw.trim();
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(PaymentError::bad_request(
            "INVALID_OUT_TRADE_NO",
            "out_trade_no is invalid",
        ));
    }
    Ok(value.to_owned())
}

fn ensure_owner(order: &OrderRecord, user_id: i64) -> Result<(), PaymentError> {
    if order.view.user_id != user_id {
        return Err(PaymentError::forbidden(
            "FORBIDDEN",
            "No permission for this order",
        ));
    }
    Ok(())
}

fn canonical_return_url(raw: &str, headers: &HeaderMap) -> Result<String, PaymentError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(String::new());
    }
    let mut url = Url::parse(raw).map_err(|_| {
        PaymentError::bad_request("INVALID_RETURN_URL", "return_url must be an absolute URL")
    })?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(PaymentError::bad_request(
            "INVALID_RETURN_URL",
            "return_url must use http or https",
        ));
    }
    if url.path() != "/payment/result" {
        return Err(PaymentError::bad_request(
            "INVALID_RETURN_URL",
            "return_url must target /payment/result",
        ));
    }
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let referer_host = headers
        .get(header::REFERER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Url::parse(value).ok())
        .and_then(|value| value.host_str().map(str::to_owned));
    let return_host = url.host_str().unwrap_or_default();
    let allowed = same_host(return_host, host)
        || referer_host
            .as_deref()
            .is_some_and(|referer| same_host(return_host, referer));
    if !allowed {
        return Err(PaymentError::bad_request(
            "INVALID_RETURN_URL",
            "return_url must use the current application host",
        ));
    }
    url.set_fragment(None);
    Ok(url.to_string())
}

fn payment_return_url(
    base: &str,
    order_id: i64,
    out_trade_no: &str,
    resume_token: &str,
) -> Result<String, PaymentError> {
    if base.is_empty() {
        return Ok(String::new());
    }
    let mut url = Url::parse(base)
        .map_err(|_| PaymentError::bad_request("INVALID_RETURN_URL", "return_url is invalid"))?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("order_id", &order_id.to_string());
        query.append_pair("out_trade_no", out_trade_no);
        query.append_pair("status", "success");
        if !resume_token.is_empty() {
            query.append_pair("resume_token", resume_token);
        }
    }
    Ok(url.to_string())
}

fn same_host(left: &str, right: &str) -> bool {
    let right = right.trim();
    left.eq_ignore_ascii_case(right)
        || right
            .split_once(':')
            .is_some_and(|(host, _)| left.eq_ignore_ascii_case(host))
}

fn request_client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
        })
        .map(str::trim)
        .unwrap_or_default()
        .chars()
        .take(50)
        .collect()
}

fn request_is_mobile(headers: &HeaderMap) -> bool {
    let agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    ["mobile", "android", "iphone", "ipad", "ipod"]
        .iter()
        .any(|keyword| agent.contains(keyword))
}

fn payment_subject(
    plan: Option<&Plan>,
    amount: f64,
    currency: &str,
    config: &super::models::PaymentConfig,
) -> String {
    let product = plan.map_or_else(
        || format!("Sub2API {} {currency}", decimal_string(amount, 2)),
        |plan| {
            if plan.product_name.trim().is_empty() {
                format!("Sub2API Subscription {}", plan.name)
            } else {
                plan.product_name.clone()
            }
        },
    );
    format!(
        "{} {} {}",
        config.product_name_prefix.trim(),
        product,
        config.product_name_suffix.trim()
    )
    .trim()
    .to_owned()
}

fn payment_amount(base: f64, fee_rate: f64, currency: &str) -> Result<f64, PaymentError> {
    if !base.is_finite() || base <= 0.0 || !fee_rate.is_finite() {
        return Err(PaymentError::bad_request(
            "INVALID_AMOUNT",
            "Payment amount is invalid",
        ));
    }
    let digits = currency_digits(currency);
    let multiplier = 10_f64.powi(digits);
    let fee = if fee_rate > 0.0 {
        (base * fee_rate / 100.0 * multiplier).ceil() / multiplier
    } else {
        0.0
    };
    Ok(round_decimal(
        base + fee,
        u32::try_from(digits).unwrap_or(2),
    ))
}

fn currency_digits(currency: &str) -> i32 {
    match currency {
        "JPY" | "KRW" => 0,
        "BHD" | "JOD" | "KWD" | "OMR" | "TND" => 3,
        _ => 2,
    }
}

fn round_currency(value: f64, currency: &str) -> f64 {
    round_decimal(value, u32::try_from(currency_digits(currency)).unwrap_or(2))
}

fn round_decimal(value: f64, digits: u32) -> f64 {
    let multiplier = 10_f64.powi(i32::try_from(digits).unwrap_or(8));
    (value * multiplier).round() / multiplier
}

fn decimal_string(value: f64, digits: usize) -> String {
    format!("{value:.digits$}")
}

fn compute_validity_days(days: i32, unit: &str) -> i32 {
    let multiplier = match unit {
        "week" | "weeks" => 7,
        "month" | "months" => 30,
        _ => 1,
    };
    days.saturating_mul(multiplier).clamp(1, 3_650)
}

fn allocate_out_trade_no() -> String {
    let suffix = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(12)
        .map(char::from)
        .collect::<String>();
    format!("sub2_{}{suffix}", chrono::Utc::now().format("%Y%m%d"))
}

fn public_paid_status(status: &str) -> bool {
    matches!(
        status,
        STATUS_PAID
            | STATUS_RECHARGING
            | STATUS_COMPLETED
            | STATUS_REFUND_REQUESTED
            | "REFUNDING"
            | "REFUND_PENDING"
            | "PARTIALLY_REFUNDED"
            | "REFUNDED"
            | "REFUND_FAILED"
    )
}

fn is_refund_status(status: &str) -> bool {
    matches!(
        status,
        STATUS_REFUND_REQUESTED
            | "REFUNDING"
            | "REFUND_PENDING"
            | "PARTIALLY_REFUNDED"
            | "REFUNDED"
            | "REFUND_FAILED"
    )
}

fn amount_tolerance(currency: &str) -> f64 {
    0.5 / 10_f64.powi(currency_digits(currency))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_order_ids_are_restricted() {
        assert!(validate_out_trade_no("sub2_20250101AbCd").is_ok());
        assert!(validate_out_trade_no("../../order").is_err());
        assert!(validate_out_trade_no("").is_err());
    }

    #[test]
    fn fee_is_rounded_up_at_currency_precision() {
        let amount = payment_amount(10.0, 1.23, "CNY").unwrap();
        assert!((amount - 10.13).abs() < f64::EPSILON);
    }

    #[test]
    fn validity_units_match_legacy_behavior() {
        assert_eq!(compute_validity_days(2, "weeks"), 14);
        assert_eq!(compute_validity_days(2, "months"), 60);
    }
}
