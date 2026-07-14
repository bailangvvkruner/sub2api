use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{Row, postgres::PgRow};

use super::PaymentError;

pub(super) const STATUS_PENDING: &str = "PENDING";
pub(super) const STATUS_PAID: &str = "PAID";
pub(super) const STATUS_RECHARGING: &str = "RECHARGING";
pub(super) const STATUS_COMPLETED: &str = "COMPLETED";
pub(super) const STATUS_EXPIRED: &str = "EXPIRED";
pub(super) const STATUS_CANCELLED: &str = "CANCELLED";
pub(super) const STATUS_FAILED: &str = "FAILED";
pub(super) const STATUS_REFUND_REQUESTED: &str = "REFUND_REQUESTED";

pub(super) const ORDER_BALANCE: &str = "balance";
pub(super) const ORDER_SUBSCRIPTION: &str = "subscription";

#[derive(Clone, Debug, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub(super) struct PaymentConfig {
    pub enabled: bool,
    pub min_amount: f64,
    pub max_amount: f64,
    pub daily_limit: f64,
    pub order_timeout_minutes: i32,
    pub max_pending_orders: i32,
    pub enabled_payment_types: Vec<String>,
    pub balance_disabled: bool,
    pub balance_recharge_multiplier: f64,
    pub subscription_usd_to_cny_rate: f64,
    pub recharge_fee_rate: f64,
    pub load_balance_strategy: String,
    pub product_name_prefix: String,
    pub product_name_suffix: String,
    pub help_image_url: String,
    pub help_text: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub stripe_publishable_key: String,
    pub cancel_rate_limit_enabled: bool,
    pub cancel_rate_limit_max: i32,
    pub cancel_rate_limit_window: i32,
    pub cancel_rate_limit_unit: String,
    pub cancel_rate_limit_window_mode: String,
    pub alipay_force_qrcode: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
pub(super) struct MethodLimits {
    pub payment_type: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub display_name: String,
    pub currency: String,
    pub fee_rate: f64,
    pub daily_limit: f64,
    pub single_min: f64,
    pub single_max: f64,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct MethodLimitsResponse {
    pub methods: BTreeMap<String, MethodLimits>,
    pub global_min: f64,
    pub global_max: f64,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct PlanView {
    pub id: i64,
    pub group_id: i64,
    pub group_platform: String,
    pub group_name: String,
    pub rate_multiplier: f64,
    pub peak_rate_enabled: bool,
    pub peak_start: String,
    pub peak_end: String,
    pub peak_rate_multiplier: f64,
    pub daily_limit_usd: Option<f64>,
    pub weekly_limit_usd: Option<f64>,
    pub monthly_limit_usd: Option<f64>,
    pub supported_model_scopes: Vec<String>,
    pub name: String,
    pub description: String,
    pub price: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_price: Option<f64>,
    pub validity_days: i32,
    pub validity_unit: String,
    pub features: Vec<String>,
    pub product_name: String,
    pub for_sale: bool,
    pub sort_order: i32,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct PaymentChannelView {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub status: String,
    pub billing_model_source: String,
    pub restrict_models: bool,
    pub features: String,
    pub group_ids: Vec<i64>,
    pub model_mapping: Value,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct CheckoutInfo {
    pub methods: BTreeMap<String, MethodLimits>,
    pub global_min: f64,
    pub global_max: f64,
    pub plans: Vec<PlanView>,
    pub balance_disabled: bool,
    pub balance_recharge_multiplier: f64,
    pub subscription_usd_to_cny_rate: f64,
    pub recharge_fee_rate: f64,
    pub help_text: String,
    pub help_image_url: String,
    pub stripe_publishable_key: String,
    pub alipay_force_qrcode: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub(super) struct CreateOrderRequest {
    #[serde(default)]
    pub amount: f64,
    pub payment_type: String,
    #[serde(default)]
    pub openid: String,
    #[serde(default)]
    pub wechat_resume_token: String,
    #[serde(default)]
    pub return_url: String,
    #[serde(default)]
    pub payment_source: String,
    #[serde(default)]
    pub order_type: String,
    #[serde(default)]
    pub plan_id: i64,
    pub is_mobile: Option<bool>,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct CreateOrderResponse {
    pub order_id: i64,
    pub amount: f64,
    pub pay_amount: f64,
    pub fee_rate: f64,
    pub status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub result_type: String,
    pub payment_type: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub out_trade_no: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub pay_url: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub qr_code: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub client_secret: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub intent_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub currency: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub country_code: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub payment_env: String,
    pub expires_at: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub payment_mode: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub resume_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jsapi: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jsapi_payload: Option<Value>,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct OrderView {
    pub id: i64,
    pub user_id: i64,
    pub amount: f64,
    pub pay_amount: f64,
    pub fee_rate: f64,
    pub currency: String,
    pub payment_type: String,
    pub out_trade_no: String,
    pub status: String,
    pub order_type: String,
    pub created_at: String,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paid_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    pub refund_amount: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_requested_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_requested_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_request_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_instance_id: Option<String>,
}

#[derive(Clone, Debug)]
pub(super) struct OrderRecord {
    pub view: OrderView,
    pub updated_at_epoch: i64,
    pub payment_trade_no: String,
    pub recharge_code: String,
    pub provider_key: String,
    pub provider_snapshot: Value,
    pub subscription_group_id: Option<i64>,
    pub subscription_days: Option<i32>,
}

#[derive(Debug, Serialize)]
pub(super) struct PublicOrderVerify {
    pub out_trade_no: String,
    pub status: String,
    pub paid: bool,
    pub created_at: String,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paid_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct PublicOrderResult {
    pub id: i64,
    pub out_trade_no: String,
    pub amount: f64,
    pub pay_amount: f64,
    pub fee_rate: f64,
    pub currency: String,
    pub payment_type: String,
    pub order_type: String,
    pub status: String,
    pub created_at: String,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paid_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    pub refund_amount: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_requested_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_requested_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_request_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_id: Option<i64>,
}

#[derive(Clone, Debug)]
pub(super) struct ProviderSelection {
    pub instance_id: i64,
    pub provider_key: String,
    pub config: HashMap<String, String>,
    pub supported_types: String,
    pub payment_mode: String,
}

#[derive(Clone, Debug, Default)]
pub(super) struct ProviderCreateResult {
    pub trade_no: String,
    pub pay_url: String,
    pub qr_code: String,
    pub client_secret: String,
    pub intent_id: String,
    pub currency: String,
    pub country_code: String,
    pub payment_env: String,
    pub jsapi: Option<Value>,
}

#[derive(Clone, Debug)]
pub(super) struct PaymentNotification {
    pub trade_no: String,
    pub order_id: String,
    pub amount: f64,
    pub success: bool,
    pub provider_key: String,
    pub metadata: HashMap<String, String>,
}

pub(super) const ORDER_SELECT: &str = r#"
SELECT
    o.id, o.user_id,
    o.amount::text AS amount, o.pay_amount::text AS pay_amount,
    o.fee_rate::text AS fee_rate,
    COALESCE(o.provider_snapshot->>'currency', 'CNY') AS currency,
    o.payment_type, o.out_trade_no, o.status, o.order_type,
    to_char(o.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at,
    to_char(o.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS expires_at,
    CASE WHEN o.paid_at IS NULL THEN NULL ELSE
      to_char(o.paid_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END AS paid_at,
    CASE WHEN o.completed_at IS NULL THEN NULL ELSE
      to_char(o.completed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END AS completed_at,
    o.refund_amount::text AS refund_amount, o.refund_reason,
    CASE WHEN o.refund_requested_at IS NULL THEN NULL ELSE
      to_char(o.refund_requested_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END AS refund_requested_at,
    o.refund_requested_by, o.refund_request_reason, o.plan_id,
    o.provider_instance_id, o.payment_trade_no, o.recharge_code,
    EXTRACT(EPOCH FROM o.updated_at)::bigint AS updated_at_epoch,
    COALESCE(o.provider_key, '') AS provider_key,
    COALESCE(o.provider_snapshot, '{}'::jsonb) AS provider_snapshot,
    o.subscription_group_id, o.subscription_days
FROM payment_orders o
"#;

pub(super) fn order_from_row(row: &PgRow) -> Result<OrderRecord, sqlx::Error> {
    Ok(OrderRecord {
        view: OrderView {
            id: row.try_get("id")?,
            user_id: row.try_get("user_id")?,
            amount: parse_decimal(row.try_get::<String, _>("amount")?.as_str())?,
            pay_amount: parse_decimal(row.try_get::<String, _>("pay_amount")?.as_str())?,
            fee_rate: parse_decimal(row.try_get::<String, _>("fee_rate")?.as_str())?,
            currency: row.try_get("currency")?,
            payment_type: row.try_get("payment_type")?,
            out_trade_no: row.try_get("out_trade_no")?,
            status: row.try_get("status")?,
            order_type: row.try_get("order_type")?,
            created_at: row.try_get("created_at")?,
            expires_at: row.try_get("expires_at")?,
            paid_at: row.try_get("paid_at")?,
            completed_at: row.try_get("completed_at")?,
            refund_amount: parse_decimal(row.try_get::<String, _>("refund_amount")?.as_str())?,
            refund_reason: row.try_get("refund_reason")?,
            refund_requested_at: row.try_get("refund_requested_at")?,
            refund_requested_by: row.try_get("refund_requested_by")?,
            refund_request_reason: row.try_get("refund_request_reason")?,
            plan_id: row.try_get("plan_id")?,
            provider_instance_id: row.try_get("provider_instance_id")?,
        },
        updated_at_epoch: row.try_get("updated_at_epoch")?,
        payment_trade_no: row.try_get("payment_trade_no")?,
        recharge_code: row.try_get("recharge_code")?,
        provider_key: row.try_get("provider_key")?,
        provider_snapshot: row.try_get("provider_snapshot")?,
        subscription_group_id: row.try_get("subscription_group_id")?,
        subscription_days: row.try_get("subscription_days")?,
    })
}

pub(super) fn public_result(order: &OrderRecord) -> PublicOrderResult {
    let view = &order.view;
    PublicOrderResult {
        id: view.id,
        out_trade_no: view.out_trade_no.clone(),
        amount: view.amount,
        pay_amount: view.pay_amount,
        fee_rate: view.fee_rate,
        currency: view.currency.clone(),
        payment_type: view.payment_type.clone(),
        order_type: view.order_type.clone(),
        status: view.status.clone(),
        created_at: view.created_at.clone(),
        expires_at: view.expires_at.clone(),
        paid_at: view.paid_at.clone(),
        completed_at: view.completed_at.clone(),
        refund_amount: view.refund_amount,
        refund_reason: view.refund_reason.clone(),
        refund_requested_at: view.refund_requested_at.clone(),
        refund_requested_by: view.refund_requested_by.clone(),
        refund_request_reason: view.refund_request_reason.clone(),
        plan_id: view.plan_id,
    }
}

pub(super) fn parse_decimal(raw: &str) -> Result<f64, sqlx::Error> {
    raw.parse::<f64>()
        .map_err(|error| sqlx::Error::Decode(Box::new(error)))
}

pub(super) fn optional_decimal(raw: Option<String>) -> Result<Option<f64>, PaymentError> {
    raw.map(|value| parse_decimal(&value).map_err(Into::into))
        .transpose()
}
