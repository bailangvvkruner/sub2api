use std::collections::{BTreeMap, HashMap};

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use md5::Md5;
use rand::{RngCore, rngs::OsRng};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;
use subtle::ConstantTimeEq;
use url::Url;

use crate::rsa_crypto::{RsaCryptoError, sign_rsa_pkcs1_sha256, verify_rsa_pkcs1_sha256};

use super::{
    PaymentError, ProviderRuntime,
    models::{PaymentNotification, ProviderCreateResult, ProviderSelection},
    refund::{ProviderRefundRequest, ProviderRefundResult, ProviderRefundStatus},
};

const MAX_PROVIDER_RESPONSE_BYTES: usize = 1 << 20;
const WEBHOOK_TOLERANCE_SECONDS: i64 = 5 * 60;

#[derive(Clone, Debug, Default)]
pub(super) struct ProviderQueryResult {
    pub trade_no: String,
    pub status: String,
    pub amount: f64,
    pub metadata: HashMap<String, String>,
}

pub(super) fn normalize_payment_type(raw: &str) -> String {
    match raw.trim().to_ascii_lowercase().as_str() {
        "alipay_direct" => "alipay".to_owned(),
        "wxpay_direct" | "wechat" => "wxpay".to_owned(),
        other => other.to_owned(),
    }
}

pub(super) fn provider_currency(provider_key: &str, config: &HashMap<String, String>) -> String {
    if matches!(provider_key, "stripe" | "airwallex") {
        let currency = config
            .get("currency")
            .map_or("CNY", String::as_str)
            .trim()
            .to_ascii_uppercase();
        if currency.len() == 3 && currency.bytes().all(|byte| byte.is_ascii_alphabetic()) {
            return currency;
        }
    }
    "CNY".to_owned()
}

pub(super) fn decode_provider_config(
    state: &ProviderRuntime,
    stored: &str,
) -> Result<HashMap<String, String>, PaymentError> {
    if stored.trim().is_empty() {
        return Ok(HashMap::new());
    }
    if let Ok(config) = serde_json::from_str(stored) {
        return Ok(config);
    }
    let Some(key) = state.legacy_config_key else {
        tracing::warn!(
            stored_len = stored.len(),
            "legacy payment config cannot be decrypted"
        );
        return Ok(HashMap::new());
    };
    let mut parts = stored.splitn(3, ':');
    let nonce = parts.next().and_then(|value| STANDARD.decode(value).ok());
    let tag = parts.next().and_then(|value| STANDARD.decode(value).ok());
    let ciphertext = parts.next().and_then(|value| STANDARD.decode(value).ok());
    let (Some(nonce), Some(tag), Some(mut ciphertext)) = (nonce, tag, ciphertext) else {
        tracing::warn!(
            stored_len = stored.len(),
            "payment provider config is unreadable"
        );
        return Ok(HashMap::new());
    };
    ciphertext.extend_from_slice(&tag);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|error| {
        PaymentError::internal("initialize legacy payment config cipher", error)
    })?;
    let plaintext = cipher
        .decrypt(nonce.as_slice().into(), ciphertext.as_ref())
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok());
    let config = plaintext
        .as_deref()
        .and_then(|value| serde_json::from_str(value).ok())
        .unwrap_or_default();
    Ok(config)
}

pub(super) async fn select_provider(
    state: &ProviderRuntime,
    payment_type: &str,
    amount: f64,
    strategy: &str,
) -> Result<ProviderSelection, PaymentError> {
    let payment_type = normalize_payment_type(payment_type);
    let source_key = match payment_type.as_str() {
        "alipay" => Some("payment_visible_method_alipay_source"),
        "wxpay" => Some("payment_visible_method_wxpay_source"),
        _ => None,
    };
    let configured_source = if let Some(key) = source_key {
        sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key = $1")
            .bind(key)
            .fetch_optional(state.pool())
            .await?
            .unwrap_or_default()
    } else {
        String::new()
    };
    let required_provider = match configured_source.as_str() {
        "official_alipay" => Some("alipay"),
        "official_wxpay" => Some("wxpay"),
        "easypay_alipay" | "easypay_wxpay" => Some("easypay"),
        _ => None,
    };

    let rows = sqlx::query(
        r"
SELECT p.id, p.provider_key, p.config, p.supported_types, p.payment_mode, p.limits,
       COALESCE(SUM(o.pay_amount) FILTER (
         WHERE o.status IN ('PAID', 'RECHARGING', 'COMPLETED')
           AND o.paid_at >= date_trunc('day', NOW() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'
       ), 0)::text AS daily_amount
FROM payment_provider_instances p
LEFT JOIN payment_orders o ON o.provider_instance_id = p.id::text
WHERE p.enabled = TRUE
GROUP BY p.id
ORDER BY p.sort_order, p.id
",
    )
    .fetch_all(state.pool())
    .await?;
    let mut candidates = Vec::new();
    for row in rows {
        let provider_key: String = row.try_get("provider_key")?;
        if required_provider.is_some_and(|required| required != provider_key) {
            continue;
        }
        let supported_types: String = row.try_get("supported_types")?;
        if !supports_method(&provider_key, &supported_types, &payment_type) {
            continue;
        }
        let limits_raw: String = row.try_get("limits")?;
        if !amount_allowed(&limits_raw, &provider_key, &payment_type, amount) {
            continue;
        }
        let stored: String = row.try_get("config")?;
        let mut config = decode_provider_config(state, &stored)?;
        let payment_mode: String = row.try_get("payment_mode")?;
        if !payment_mode.is_empty() {
            config.insert("paymentMode".to_owned(), payment_mode.clone());
        }
        let daily_amount = row
            .try_get::<String, _>("daily_amount")?
            .parse::<f64>()
            .unwrap_or_default();
        candidates.push((
            daily_amount,
            ProviderSelection {
                instance_id: row.try_get("id")?,
                provider_key,
                config,
                supported_types,
                payment_mode,
            },
        ));
    }
    if candidates.is_empty() {
        return Err(PaymentError::unavailable(
            "NO_AVAILABLE_INSTANCE",
            "No configured payment provider can accept this order",
        ));
    }
    if matches!(strategy, "least-load" | "adaptive") {
        candidates.sort_by(|left, right| left.0.total_cmp(&right.0));
    }
    Ok(candidates.remove(0).1)
}

pub(super) async fn load_provider_instance(
    state: &ProviderRuntime,
    instance_id: i64,
) -> Result<ProviderSelection, PaymentError> {
    let row = sqlx::query(
        "SELECT id, provider_key, config, supported_types, payment_mode FROM payment_provider_instances WHERE id = $1",
    )
    .bind(instance_id)
    .fetch_optional(state.pool())
    .await?
    .ok_or_else(|| PaymentError::unavailable("PAYMENT_PROVIDER_MISSING", "Payment provider is unavailable"))?;
    let stored: String = row.try_get("config")?;
    let payment_mode: String = row.try_get("payment_mode")?;
    let mut config = decode_provider_config(state, &stored)?;
    if !payment_mode.is_empty() {
        config.insert("paymentMode".to_owned(), payment_mode.clone());
    }
    Ok(ProviderSelection {
        instance_id: row.try_get("id")?,
        provider_key: row.try_get("provider_key")?,
        config,
        supported_types: row.try_get("supported_types")?,
        payment_mode,
    })
}

fn supports_method(provider_key: &str, supported: &str, method: &str) -> bool {
    if provider_key == "stripe" && method == "stripe" {
        return true;
    }
    if provider_key == "airwallex" && method == "airwallex" {
        return true;
    }
    if provider_key == method && matches!(provider_key, "alipay" | "wxpay") {
        return true;
    }
    supported
        .split(',')
        .map(normalize_payment_type)
        .any(|candidate| candidate == method)
}

fn amount_allowed(limits: &str, provider_key: &str, method: &str, amount: f64) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(limits) else {
        return true;
    };
    let key = if provider_key == "stripe" {
        "stripe"
    } else {
        method
    };
    let Some(limit) = value.get(key) else {
        return true;
    };
    let minimum = number(limit, &["singleMin", "single_min"]);
    let maximum = number(limit, &["singleMax", "single_max"]);
    (minimum <= 0.0 || amount >= minimum) && (maximum <= 0.0 || amount <= maximum)
}

fn number(value: &Value, keys: &[&str]) -> f64 {
    keys.iter()
        .find_map(|key| value.get(key))
        .and_then(Value::as_f64)
        .unwrap_or_default()
}

pub(super) struct CreatePaymentInput<'a> {
    pub out_trade_no: &'a str,
    pub amount: f64,
    pub subject: &'a str,
    pub payment_type: &'a str,
    pub openid: &'a str,
    pub client_ip: &'a str,
    pub is_mobile: bool,
    pub return_url: &'a str,
}

pub(super) async fn create_payment(
    state: &ProviderRuntime,
    provider: &ProviderSelection,
    input: &CreatePaymentInput<'_>,
) -> Result<ProviderCreateResult, PaymentError> {
    match provider.provider_key.as_str() {
        "easypay" => create_easypay(state, provider, input).await,
        "alipay" => create_alipay(state, provider, input).await,
        "stripe" => create_stripe(state, provider, input).await,
        "airwallex" => create_airwallex(state, provider, input).await,
        "wxpay" => create_wxpay(state, provider, input).await,
        _ => Err(PaymentError::unavailable(
            "PAYMENT_PROVIDER_MISCONFIGURED",
            "Unsupported payment provider",
        )),
    }
}

async fn create_easypay(
    state: &ProviderRuntime,
    provider: &ProviderSelection,
    input: &CreatePaymentInput<'_>,
) -> Result<ProviderCreateResult, PaymentError> {
    require_config(provider, &["pid", "pkey", "apiBase"])?;
    let base = normalize_easypay_base(config(provider, "apiBase"));
    let upstream_type = easypay_upstream_method(provider, input.payment_type);
    let mut params = BTreeMap::from([
        ("pid".to_owned(), config(provider, "pid").to_owned()),
        ("type".to_owned(), upstream_type),
        ("out_trade_no".to_owned(), input.out_trade_no.to_owned()),
        (
            "notify_url".to_owned(),
            config(provider, "notifyUrl").to_owned(),
        ),
        (
            "return_url".to_owned(),
            nonempty(input.return_url, config(provider, "returnUrl")).to_owned(),
        ),
        ("name".to_owned(), input.subject.to_owned()),
        ("money".to_owned(), format_amount(input.amount, "CNY")),
    ]);
    if input.is_mobile {
        params.insert("device".to_owned(), "mobile".to_owned());
    }
    if matches!(provider.payment_mode.as_str(), "redirect" | "popup") {
        params.insert(
            "sign".to_owned(),
            easypay_sign(&params, config(provider, "pkey")),
        );
        params.insert("sign_type".to_owned(), "MD5".to_owned());
        let mut url = Url::parse(&format!("{base}/submit.php"))
            .map_err(|error| PaymentError::internal("build EasyPay redirect URL", error))?;
        url.query_pairs_mut().extend_pairs(params.iter());
        return Ok(ProviderCreateResult {
            pay_url: url.to_string(),
            ..ProviderCreateResult::default()
        });
    }
    params.insert("clientip".to_owned(), input.client_ip.to_owned());
    params.insert(
        "sign".to_owned(),
        easypay_sign(&params, config(provider, "pkey")),
    );
    params.insert("sign_type".to_owned(), "MD5".to_owned());
    let response = state
        .client()
        .post(format!("{base}/mapi.php"))
        .form(&params)
        .send()
        .await?;
    let value = checked_json(response, "EasyPay create payment").await?;
    if value.get("code").and_then(Value::as_i64) != Some(1) {
        return Err(PaymentError::unavailable(
            "PAYMENT_GATEWAY_ERROR",
            value
                .get("msg")
                .and_then(Value::as_str)
                .unwrap_or("EasyPay rejected the payment"),
        ));
    }
    Ok(ProviderCreateResult {
        trade_no: string(&value, "trade_no"),
        pay_url: if input.is_mobile {
            let mobile = string(&value, "payurl2");
            nonempty(&mobile, &string(&value, "payurl")).to_owned()
        } else {
            string(&value, "payurl")
        },
        qr_code: string(&value, "qrcode"),
        ..ProviderCreateResult::default()
    })
}

async fn create_alipay(
    state: &ProviderRuntime,
    provider: &ProviderSelection,
    input: &CreatePaymentInput<'_>,
) -> Result<ProviderCreateResult, PaymentError> {
    require_config(provider, &["appId", "privateKey"])?;
    let method = if input.is_mobile {
        "alipay.trade.wap.pay"
    } else if provider.payment_mode == "redirect" {
        "alipay.trade.page.pay"
    } else {
        "alipay.trade.precreate"
    };
    let product = match method {
        "alipay.trade.wap.pay" => "QUICK_WAP_WAY",
        "alipay.trade.page.pay" => "FAST_INSTANT_TRADE_PAY",
        _ => "FACE_TO_FACE_PAYMENT",
    };
    let biz = json!({
        "out_trade_no": input.out_trade_no,
        "total_amount": format_amount(input.amount, "CNY"),
        "subject": input.subject,
        "product_code": product,
    });
    let mut params = alipay_parameters(provider, method, &biz)?;
    if !config(provider, "notifyUrl").is_empty() {
        params.insert(
            "notify_url".to_owned(),
            config(provider, "notifyUrl").to_owned(),
        );
    }
    if !input.return_url.is_empty() || !config(provider, "returnUrl").is_empty() {
        params.insert(
            "return_url".to_owned(),
            nonempty(input.return_url, config(provider, "returnUrl")).to_owned(),
        );
    }
    sign_alipay_parameters(&mut params, config(provider, "privateKey"))?;
    let gateway = nonempty(
        config(provider, "gateway"),
        "https://openapi.alipay.com/gateway.do",
    );
    if method != "alipay.trade.precreate" {
        let mut url = Url::parse(gateway)
            .map_err(|error| PaymentError::internal("build Alipay checkout URL", error))?;
        url.query_pairs_mut().extend_pairs(params.iter());
        return Ok(ProviderCreateResult {
            trade_no: input.out_trade_no.to_owned(),
            pay_url: url.to_string(),
            ..ProviderCreateResult::default()
        });
    }
    let response = state.client().post(gateway).form(&params).send().await?;
    let value = checked_json(response, "Alipay precreate").await?;
    let response = value
        .get("alipay_trade_precreate_response")
        .cloned()
        .unwrap_or_default();
    let qr_code = string(&response, "qr_code");
    if qr_code.is_empty() {
        return Err(PaymentError::unavailable(
            "PAYMENT_GATEWAY_ERROR",
            string(&response, "sub_msg"),
        ));
    }
    Ok(ProviderCreateResult {
        trade_no: input.out_trade_no.to_owned(),
        qr_code,
        ..ProviderCreateResult::default()
    })
}

async fn create_stripe(
    state: &ProviderRuntime,
    provider: &ProviderSelection,
    input: &CreatePaymentInput<'_>,
) -> Result<ProviderCreateResult, PaymentError> {
    require_config(provider, &["secretKey"])?;
    let currency = provider_currency("stripe", &provider.config);
    let minor = to_minor_units(input.amount, &currency)?;
    let methods = stripe_methods(&provider.supported_types);
    let mut form = vec![
        ("amount".to_owned(), minor.to_string()),
        ("currency".to_owned(), currency.to_ascii_lowercase()),
        ("description".to_owned(), input.subject.to_owned()),
        (
            "metadata[orderId]".to_owned(),
            input.out_trade_no.to_owned(),
        ),
    ];
    for method in methods {
        form.push(("payment_method_types[]".to_owned(), method));
    }
    let response = state
        .client()
        .post("https://api.stripe.com/v1/payment_intents")
        .bearer_auth(config(provider, "secretKey"))
        .header("Idempotency-Key", format!("pi-{}", input.out_trade_no))
        .form(&form)
        .send()
        .await?;
    let value = checked_json(response, "Stripe create payment").await?;
    Ok(ProviderCreateResult {
        trade_no: string(&value, "id"),
        client_secret: string(&value, "client_secret"),
        currency,
        ..ProviderCreateResult::default()
    })
}

async fn create_airwallex(
    state: &ProviderRuntime,
    provider: &ProviderSelection,
    input: &CreatePaymentInput<'_>,
) -> Result<ProviderCreateResult, PaymentError> {
    let token = airwallex_token(state, provider).await?;
    let currency = provider_currency("airwallex", &provider.config);
    let api_base = airwallex_base(provider)?;
    let request_id = deterministic_uuid(&[
        "payment-intent",
        input.out_trade_no,
        &format_amount(input.amount, &currency),
        &currency,
    ]);
    let response = airwallex_request(
        state,
        provider,
        Method::POST,
        format!("{api_base}/pa/payment_intents/create"),
        &token,
        Some(json!({
            "request_id": request_id,
            "amount": input.amount,
            "currency": currency,
            "merchant_order_id": input.out_trade_no,
            "return_url": input.return_url,
            "metadata": {"order_id": input.out_trade_no},
        })),
    )
    .await?;
    let intent_id = string(&response, "id");
    if intent_id.is_empty() {
        return Err(PaymentError::unavailable(
            "PAYMENT_GATEWAY_ERROR",
            "Airwallex response omitted an intent id",
        ));
    }
    Ok(ProviderCreateResult {
        trade_no: intent_id.clone(),
        intent_id,
        client_secret: string(&response, "client_secret"),
        currency,
        country_code: nonempty(config(provider, "countryCode"), "CN").to_ascii_uppercase(),
        payment_env: if api_base.contains("api-demo") {
            "demo"
        } else {
            "prod"
        }
        .to_owned(),
        ..ProviderCreateResult::default()
    })
}

async fn create_wxpay(
    state: &ProviderRuntime,
    provider: &ProviderSelection,
    input: &CreatePaymentInput<'_>,
) -> Result<ProviderCreateResult, PaymentError> {
    require_config(provider, &["appId", "mchId", "privateKey", "certSerial"])?;
    let (mode, path) = if !input.openid.trim().is_empty() {
        ("jsapi", "/v3/pay/transactions/jsapi")
    } else if input.is_mobile {
        ("h5", "/v3/pay/transactions/h5")
    } else {
        ("native", "/v3/pay/transactions/native")
    };
    let app_id = if mode == "jsapi" {
        nonempty(config(provider, "mpAppId"), config(provider, "appId"))
    } else {
        config(provider, "appId")
    };
    let mut body = json!({
        "appid": app_id,
        "mchid": config(provider, "mchId"),
        "description": input.subject,
        "out_trade_no": input.out_trade_no,
        "notify_url": config(provider, "notifyUrl"),
        "amount": {"total": to_minor_units(input.amount, "CNY")?, "currency": "CNY"},
    });
    if mode == "jsapi" {
        body["payer"] = json!({"openid": input.openid.trim()});
    } else if mode == "h5" {
        body["scene_info"] = json!({
            "payer_client_ip": input.client_ip,
            "h5_info": {"type": "Wap", "app_name": config(provider, "h5AppName"), "app_url": config(provider, "h5AppUrl")}
        });
    }
    let response = wxpay_request(state, provider, Method::POST, path, Some(body)).await?;
    if mode == "jsapi" {
        let prepay_id = string(&response, "prepay_id");
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let nonce = random_nonce();
        let package = format!("prepay_id={prepay_id}");
        let message = format!("{app_id}\n{timestamp}\n{nonce}\n{package}\n");
        let pay_sign = rsa_sign(config(provider, "privateKey"), message.as_bytes())?;
        let jsapi = json!({
            "appId": app_id,
            "timeStamp": timestamp,
            "nonceStr": nonce,
            "package": package,
            "signType": "RSA",
            "paySign": pay_sign,
        });
        return Ok(ProviderCreateResult {
            trade_no: input.out_trade_no.to_owned(),
            jsapi: Some(jsapi),
            ..ProviderCreateResult::default()
        });
    }
    Ok(ProviderCreateResult {
        trade_no: input.out_trade_no.to_owned(),
        pay_url: string(&response, "h5_url"),
        qr_code: string(&response, "code_url"),
        ..ProviderCreateResult::default()
    })
}

pub(super) async fn query_payment(
    state: &ProviderRuntime,
    provider: &ProviderSelection,
    out_trade_no: &str,
    payment_trade_no: &str,
) -> Result<ProviderQueryResult, PaymentError> {
    match provider.provider_key.as_str() {
        "easypay" => query_easypay(state, provider, out_trade_no).await,
        "alipay" => query_alipay(state, provider, out_trade_no).await,
        "stripe" => query_stripe(state, provider, nonempty(payment_trade_no, out_trade_no)).await,
        "airwallex" => {
            query_airwallex(state, provider, nonempty(payment_trade_no, out_trade_no)).await
        }
        "wxpay" => query_wxpay(state, provider, out_trade_no).await,
        _ => Err(PaymentError::unavailable(
            "PAYMENT_PROVIDER_MISCONFIGURED",
            "Unsupported payment provider",
        )),
    }
}

async fn query_easypay(
    state: &ProviderRuntime,
    provider: &ProviderSelection,
    out_trade_no: &str,
) -> Result<ProviderQueryResult, PaymentError> {
    let response = state
        .client()
        .post(format!(
            "{}/api.php",
            normalize_easypay_base(config(provider, "apiBase"))
        ))
        .form(&[
            ("act", "order"),
            ("pid", config(provider, "pid")),
            ("key", config(provider, "pkey")),
            ("out_trade_no", out_trade_no),
        ])
        .send()
        .await?;
    let value = checked_json(response, "EasyPay query order").await?;
    let data = value.get("data").unwrap_or(&value);
    let paid = data.get("trade_status").and_then(Value::as_str) == Some("TRADE_SUCCESS")
        || data.get("status").and_then(Value::as_i64) == Some(1);
    Ok(ProviderQueryResult {
        trade_no: nonempty(&string(data, "trade_no"), out_trade_no).to_owned(),
        status: if paid { "paid" } else { "pending" }.to_owned(),
        amount: value_number(data, "money"),
        metadata: HashMap::from([("pid".to_owned(), config(provider, "pid").to_owned())]),
    })
}

async fn query_alipay(
    state: &ProviderRuntime,
    provider: &ProviderSelection,
    out_trade_no: &str,
) -> Result<ProviderQueryResult, PaymentError> {
    let mut params = alipay_parameters(
        provider,
        "alipay.trade.query",
        &json!({"out_trade_no": out_trade_no}),
    )?;
    sign_alipay_parameters(&mut params, config(provider, "privateKey"))?;
    let gateway = nonempty(
        config(provider, "gateway"),
        "https://openapi.alipay.com/gateway.do",
    );
    let value = checked_json(
        state.client().post(gateway).form(&params).send().await?,
        "Alipay query order",
    )
    .await?;
    let response = value.get("alipay_trade_query_response").unwrap_or(&value);
    let status = match string(response, "trade_status").as_str() {
        "TRADE_SUCCESS" | "TRADE_FINISHED" => "paid",
        "TRADE_CLOSED" => "failed",
        _ => "pending",
    };
    Ok(ProviderQueryResult {
        trade_no: nonempty(&string(response, "trade_no"), out_trade_no).to_owned(),
        status: status.to_owned(),
        amount: value_number(response, "total_amount"),
        metadata: HashMap::from([("app_id".to_owned(), config(provider, "appId").to_owned())]),
    })
}

async fn query_stripe(
    state: &ProviderRuntime,
    provider: &ProviderSelection,
    trade_no: &str,
) -> Result<ProviderQueryResult, PaymentError> {
    let value = checked_json(
        state
            .client()
            .get(format!(
                "https://api.stripe.com/v1/payment_intents/{trade_no}"
            ))
            .bearer_auth(config(provider, "secretKey"))
            .send()
            .await?,
        "Stripe query order",
    )
    .await?;
    let currency = string(&value, "currency").to_ascii_uppercase();
    Ok(ProviderQueryResult {
        trade_no: string(&value, "id"),
        status: match string(&value, "status").as_str() {
            "succeeded" => "paid",
            "canceled" => "failed",
            _ => "pending",
        }
        .to_owned(),
        amount: from_minor_units(
            value
                .get("amount")
                .and_then(Value::as_i64)
                .unwrap_or_default(),
            &currency,
        ),
        metadata: HashMap::from([("currency".to_owned(), currency)]),
    })
}

async fn query_airwallex(
    state: &ProviderRuntime,
    provider: &ProviderSelection,
    trade_no: &str,
) -> Result<ProviderQueryResult, PaymentError> {
    let token = airwallex_token(state, provider).await?;
    let value = airwallex_request(
        state,
        provider,
        Method::GET,
        format!(
            "{}/pa/payment_intents/{trade_no}",
            airwallex_base(provider)?
        ),
        &token,
        None,
    )
    .await?;
    let currency = string(&value, "currency").to_ascii_uppercase();
    Ok(ProviderQueryResult {
        trade_no: string(&value, "id"),
        status: match string(&value, "status").as_str() {
            "SUCCEEDED" => "paid",
            "CANCELLED" => "failed",
            _ => "pending",
        }
        .to_owned(),
        amount: value_number(&value, "amount"),
        metadata: merchant_metadata(provider, Some(&currency)),
    })
}

async fn query_wxpay(
    state: &ProviderRuntime,
    provider: &ProviderSelection,
    out_trade_no: &str,
) -> Result<ProviderQueryResult, PaymentError> {
    let path = format!(
        "/v3/pay/transactions/out-trade-no/{out_trade_no}?mchid={}",
        config(provider, "mchId")
    );
    let value = wxpay_request(state, provider, Method::GET, &path, None).await?;
    let currency = value
        .pointer("/amount/currency")
        .and_then(Value::as_str)
        .unwrap_or("CNY")
        .to_owned();
    Ok(ProviderQueryResult {
        trade_no: string(&value, "transaction_id"),
        status: match string(&value, "trade_state").as_str() {
            "SUCCESS" => "paid",
            "CLOSED" | "PAYERROR" => "failed",
            _ => "pending",
        }
        .to_owned(),
        amount: from_minor_units(
            value
                .pointer("/amount/total")
                .and_then(Value::as_i64)
                .unwrap_or_default(),
            &currency,
        ),
        metadata: HashMap::from([
            ("merchant_app_id".to_owned(), string(&value, "appid")),
            ("merchant_id".to_owned(), string(&value, "mchid")),
            ("currency".to_owned(), currency),
        ]),
    })
}

pub(super) async fn cancel_payment(
    state: &ProviderRuntime,
    provider: &ProviderSelection,
    out_trade_no: &str,
    payment_trade_no: &str,
) -> Result<(), PaymentError> {
    let reference = nonempty(payment_trade_no, out_trade_no);
    match provider.provider_key.as_str() {
        "stripe" => {
            checked_json(
                state
                    .client()
                    .post(format!(
                        "https://api.stripe.com/v1/payment_intents/{reference}/cancel"
                    ))
                    .bearer_auth(config(provider, "secretKey"))
                    .send()
                    .await?,
                "Stripe cancel order",
            )
            .await?;
        }
        "airwallex" => {
            let token = airwallex_token(state, provider).await?;
            airwallex_request(
                state,
                provider,
                Method::POST,
                format!(
                    "{}/pa/payment_intents/{reference}/cancel",
                    airwallex_base(provider)?
                ),
                &token,
                None,
            )
            .await?;
        }
        "alipay" => {
            let mut params = alipay_parameters(
                provider,
                "alipay.trade.close",
                &json!({"out_trade_no": out_trade_no}),
            )?;
            sign_alipay_parameters(&mut params, config(provider, "privateKey"))?;
            let gateway = nonempty(
                config(provider, "gateway"),
                "https://openapi.alipay.com/gateway.do",
            );
            checked_json(
                state.client().post(gateway).form(&params).send().await?,
                "Alipay close order",
            )
            .await?;
        }
        "wxpay" => {
            let path = format!("/v3/pay/transactions/out-trade-no/{out_trade_no}/close");
            wxpay_request(
                state,
                provider,
                Method::POST,
                &path,
                Some(json!({"mchid": config(provider, "mchId")})),
            )
            .await?;
        }
        _ => {}
    }
    Ok(())
}

pub(super) async fn refund_payment(
    state: &ProviderRuntime,
    provider: &ProviderSelection,
    request: &ProviderRefundRequest,
) -> Result<ProviderRefundResult, PaymentError> {
    match provider.provider_key.as_str() {
        "easypay" => refund_easypay(state, provider, request).await,
        "alipay" => refund_alipay(state, provider, request).await,
        "stripe" => refund_stripe(state, provider, request).await,
        "airwallex" => refund_airwallex(state, provider, request).await,
        "wxpay" => refund_wxpay(state, provider, request).await,
        _ => Err(PaymentError::unavailable(
            "PAYMENT_PROVIDER_MISCONFIGURED",
            "Unsupported payment refund provider",
        )),
    }
}

pub(super) async fn query_refund(
    state: &ProviderRuntime,
    provider: &ProviderSelection,
    request: &ProviderRefundRequest,
) -> Result<ProviderRefundResult, PaymentError> {
    match provider.provider_key.as_str() {
        "alipay" => query_alipay_refund(state, provider, request).await,
        "stripe" => query_stripe_refund(state, provider, request).await,
        "airwallex" => query_airwallex_refund(state, provider, request).await,
        "wxpay" => query_wxpay_refund(state, provider, request).await,
        "easypay" => Err(PaymentError::bad_request(
            "REFUND_QUERY_UNSUPPORTED",
            "EasyPay does not provide a reliable refund status query",
        )),
        _ => Err(PaymentError::bad_request(
            "REFUND_QUERY_UNSUPPORTED",
            "This payment provider does not support refund status queries",
        )),
    }
}

async fn refund_easypay(
    state: &ProviderRuntime,
    provider: &ProviderSelection,
    request: &ProviderRefundRequest,
) -> Result<ProviderRefundResult, PaymentError> {
    require_config(provider, &["pid", "pkey", "apiBase"])?;
    let amount = format_amount(request.amount, "CNY");
    let mut attempts = Vec::with_capacity(2);
    if !request.order_id.trim().is_empty() {
        attempts.push(("out_trade_no", request.order_id.as_str()));
    }
    if !request.trade_no.trim().is_empty() {
        attempts.push(("trade_no", request.trade_no.as_str()));
    }
    if attempts.is_empty() {
        return Err(PaymentError::bad_request(
            "REFUND_PROVIDER_REFERENCE_MISSING",
            "EasyPay refund requires an order identifier",
        ));
    }
    let endpoint = format!(
        "{}/api.php?act=refund",
        normalize_easypay_base(config(provider, "apiBase"))
    );
    for (index, (reference_key, reference)) in attempts.iter().enumerate() {
        let value = checked_json(
            state
                .client()
                .post(&endpoint)
                .form(&[
                    ("pid", config(provider, "pid")),
                    ("key", config(provider, "pkey")),
                    ("money", amount.as_str()),
                    (*reference_key, *reference),
                ])
                .send()
                .await?,
            "EasyPay refund",
        )
        .await?;
        if easypay_code_succeeded(value.get("code")) {
            return Ok(ProviderRefundResult {
                refund_id: (*reference).to_owned(),
                status: ProviderRefundStatus::Succeeded,
            });
        }
        let message = provider_message(&value, "EasyPay rejected the refund");
        if index + 1 < attempts.len() && easypay_order_missing(&message) {
            continue;
        }
        return Err(PaymentError::unavailable("PAYMENT_GATEWAY_ERROR", message));
    }
    Err(PaymentError::unavailable(
        "PAYMENT_GATEWAY_ERROR",
        "EasyPay rejected the refund",
    ))
}

async fn refund_alipay(
    state: &ProviderRuntime,
    provider: &ProviderSelection,
    request: &ProviderRefundRequest,
) -> Result<ProviderRefundResult, PaymentError> {
    require_config(provider, &["appId", "privateKey"])?;
    if request.order_id.trim().is_empty() {
        return Err(PaymentError::bad_request(
            "REFUND_PROVIDER_REFERENCE_MISSING",
            "Alipay refund requires the original order number",
        ));
    }
    let refund_id = alipay_refund_id(request);
    let mut params = alipay_parameters(
        provider,
        "alipay.trade.refund",
        &json!({
            "out_trade_no": request.order_id,
            "refund_amount": format_amount(request.amount, &request.currency),
            "refund_reason": request.reason,
            "out_request_no": refund_id,
        }),
    )?;
    sign_alipay_parameters(&mut params, config(provider, "privateKey"))?;
    let gateway = nonempty(
        config(provider, "gateway"),
        "https://openapi.alipay.com/gateway.do",
    );
    let value = checked_json(
        state.client().post(gateway).form(&params).send().await?,
        "Alipay refund",
    )
    .await?;
    let response = alipay_response(&value, "alipay_trade_refund_response", "Alipay refund")?;
    let status = if string(response, "fund_change").eq_ignore_ascii_case("Y") {
        ProviderRefundStatus::Succeeded
    } else {
        ProviderRefundStatus::Pending
    };
    Ok(ProviderRefundResult { refund_id, status })
}

async fn query_alipay_refund(
    state: &ProviderRuntime,
    provider: &ProviderSelection,
    request: &ProviderRefundRequest,
) -> Result<ProviderRefundResult, PaymentError> {
    require_config(provider, &["appId", "privateKey"])?;
    if request.order_id.trim().is_empty() {
        return Err(PaymentError::bad_request(
            "REFUND_PROVIDER_REFERENCE_MISSING",
            "Alipay refund query requires the original order number",
        ));
    }
    let refund_id = if request.refund_id.trim().is_empty() {
        alipay_refund_id(request)
    } else {
        request.refund_id.trim().to_owned()
    };
    let mut params = alipay_parameters(
        provider,
        "alipay.trade.fastpay.refund.query",
        &json!({
            "out_trade_no": request.order_id,
            "out_request_no": refund_id,
        }),
    )?;
    sign_alipay_parameters(&mut params, config(provider, "privateKey"))?;
    let gateway = nonempty(
        config(provider, "gateway"),
        "https://openapi.alipay.com/gateway.do",
    );
    let value = checked_json(
        state.client().post(gateway).form(&params).send().await?,
        "Alipay query refund",
    )
    .await?;
    let response = alipay_response(
        &value,
        "alipay_trade_fastpay_refund_query_response",
        "Alipay query refund",
    )?;
    let refund_status = string(response, "refund_status").to_ascii_uppercase();
    let status = match refund_status.as_str() {
        "REFUND_SUCCESS" => ProviderRefundStatus::Succeeded,
        "REFUND_FAIL" | "REFUND_FAILED" | "REFUND_CLOSED" => ProviderRefundStatus::Failed,
        _ if value_number(response, "refund_amount") > 0.0 => ProviderRefundStatus::Succeeded,
        _ => ProviderRefundStatus::Pending,
    };
    Ok(ProviderRefundResult { refund_id, status })
}

async fn refund_stripe(
    state: &ProviderRuntime,
    provider: &ProviderSelection,
    request: &ProviderRefundRequest,
) -> Result<ProviderRefundResult, PaymentError> {
    require_config(provider, &["secretKey"])?;
    if request.trade_no.trim().is_empty() {
        return Err(PaymentError::bad_request(
            "REFUND_PROVIDER_REFERENCE_MISSING",
            "Stripe refund requires a PaymentIntent id",
        ));
    }
    let amount = to_minor_units(request.amount, &request.currency)?;
    let form = [
        ("payment_intent", request.trade_no.clone()),
        ("amount", amount.to_string()),
        ("reason", "requested_by_customer".to_owned()),
    ];
    let value = checked_json(
        state
            .client()
            .post("https://api.stripe.com/v1/refunds")
            .bearer_auth(config(provider, "secretKey"))
            .header(
                "Idempotency-Key",
                format!(
                    "refund-{}",
                    deterministic_uuid(&[
                        request.trade_no.as_str(),
                        format_amount(request.amount, &request.currency).as_str(),
                    ])
                ),
            )
            .form(&form)
            .send()
            .await?,
        "Stripe refund",
    )
    .await?;
    stripe_refund_result(&value)
}

async fn query_stripe_refund(
    state: &ProviderRuntime,
    provider: &ProviderSelection,
    request: &ProviderRefundRequest,
) -> Result<ProviderRefundResult, PaymentError> {
    require_config(provider, &["secretKey"])?;
    let value = if request.refund_id.trim().is_empty() {
        if request.trade_no.trim().is_empty() {
            return Err(PaymentError::bad_request(
                "REFUND_PROVIDER_REFERENCE_MISSING",
                "Stripe refund query requires a refund or PaymentIntent id",
            ));
        }
        let value = checked_json(
            state
                .client()
                .get("https://api.stripe.com/v1/refunds")
                .bearer_auth(config(provider, "secretKey"))
                .query(&[
                    ("payment_intent", request.trade_no.as_str()),
                    ("limit", "1"),
                ])
                .send()
                .await?,
            "Stripe query refund",
        )
        .await?;
        value
            .get("data")
            .and_then(Value::as_array)
            .and_then(|items| items.first())
            .cloned()
            .ok_or_else(|| {
                PaymentError::unavailable(
                    "PAYMENT_GATEWAY_ERROR",
                    "Stripe did not return a refund for this PaymentIntent",
                )
            })?
    } else {
        checked_json(
            state
                .client()
                .get(format!(
                    "https://api.stripe.com/v1/refunds/{}",
                    request.refund_id.trim()
                ))
                .bearer_auth(config(provider, "secretKey"))
                .send()
                .await?,
            "Stripe query refund",
        )
        .await?
    };
    stripe_refund_result(&value)
}

async fn refund_airwallex(
    state: &ProviderRuntime,
    provider: &ProviderSelection,
    request: &ProviderRefundRequest,
) -> Result<ProviderRefundResult, PaymentError> {
    if request.trade_no.trim().is_empty() {
        return Err(PaymentError::bad_request(
            "REFUND_PROVIDER_REFERENCE_MISSING",
            "Airwallex refund requires a payment intent id",
        ));
    }
    let token = airwallex_token(state, provider).await?;
    let value = airwallex_request(
        state,
        provider,
        Method::POST,
        format!("{}/pa/refunds/create", airwallex_base(provider)?),
        &token,
        Some(json!({
            "request_id": deterministic_uuid(&[
                "refund",
                request.trade_no.as_str(),
                format_amount(request.amount, &request.currency).as_str(),
            ]),
            "payment_intent_id": request.trade_no,
            "amount": request.amount,
            "reason": nonempty(request.reason.trim(), "refund"),
        })),
    )
    .await?;
    airwallex_refund_result(&value, "")
}

async fn query_airwallex_refund(
    state: &ProviderRuntime,
    provider: &ProviderSelection,
    request: &ProviderRefundRequest,
) -> Result<ProviderRefundResult, PaymentError> {
    if request.refund_id.trim().is_empty() {
        return Err(PaymentError::bad_request(
            "REFUND_PROVIDER_REFERENCE_MISSING",
            "Airwallex refund query requires a refund id",
        ));
    }
    let token = airwallex_token(state, provider).await?;
    let value = airwallex_request(
        state,
        provider,
        Method::GET,
        format!(
            "{}/pa/refunds/{}",
            airwallex_base(provider)?,
            request.refund_id.trim()
        ),
        &token,
        None,
    )
    .await?;
    airwallex_refund_result(&value, request.refund_id.trim())
}

async fn refund_wxpay(
    state: &ProviderRuntime,
    provider: &ProviderSelection,
    request: &ProviderRefundRequest,
) -> Result<ProviderRefundResult, PaymentError> {
    require_config(provider, &["mchId", "privateKey", "certSerial"])?;
    if request.order_id.trim().is_empty() {
        return Err(PaymentError::bad_request(
            "REFUND_PROVIDER_REFERENCE_MISSING",
            "WeChat Pay refund requires the original order number",
        ));
    }
    let refund_id = wxpay_refund_id(request);
    let body = json!({
        "out_trade_no": request.order_id,
        "out_refund_no": refund_id,
        "reason": request.reason,
        "amount": {
            "refund": to_minor_units(request.amount, &request.currency)?,
            "total": to_minor_units(request.total_amount, &request.currency)?,
            "currency": request.currency.to_ascii_uppercase(),
        },
    });
    let value = wxpay_request(
        state,
        provider,
        Method::POST,
        "/v3/refund/domestic/refunds",
        Some(body),
    )
    .await?;
    Ok(wxpay_refund_result(&value, refund_id))
}

async fn query_wxpay_refund(
    state: &ProviderRuntime,
    provider: &ProviderSelection,
    request: &ProviderRefundRequest,
) -> Result<ProviderRefundResult, PaymentError> {
    require_config(provider, &["mchId", "privateKey", "certSerial"])?;
    let refund_id = if request.refund_id.trim().is_empty() {
        wxpay_refund_id(request)
    } else {
        request.refund_id.trim().to_owned()
    };
    if refund_id.is_empty() {
        return Err(PaymentError::bad_request(
            "REFUND_PROVIDER_REFERENCE_MISSING",
            "WeChat Pay refund query requires a refund id",
        ));
    }
    let value = wxpay_request(
        state,
        provider,
        Method::GET,
        &format!("/v3/refund/domestic/refunds/{refund_id}"),
        None,
    )
    .await?;
    Ok(wxpay_refund_result(&value, refund_id))
}

fn stripe_refund_result(value: &Value) -> Result<ProviderRefundResult, PaymentError> {
    let refund_id = string(value, "id");
    if refund_id.is_empty() {
        return Err(PaymentError::unavailable(
            "PAYMENT_GATEWAY_ERROR",
            "Stripe refund response omitted a refund id",
        ));
    }
    let status = match string(value, "status").as_str() {
        "succeeded" => ProviderRefundStatus::Succeeded,
        "failed" | "canceled" => ProviderRefundStatus::Failed,
        _ => ProviderRefundStatus::Pending,
    };
    Ok(ProviderRefundResult { refund_id, status })
}

fn airwallex_refund_result(
    value: &Value,
    fallback_id: &str,
) -> Result<ProviderRefundResult, PaymentError> {
    let refund_id = nonempty(&string(value, "id"), fallback_id).to_owned();
    if refund_id.is_empty() {
        return Err(PaymentError::unavailable(
            "PAYMENT_GATEWAY_ERROR",
            "Airwallex refund response omitted a refund id",
        ));
    }
    let status = match string(value, "status").to_ascii_uppercase().as_str() {
        "SETTLED" => ProviderRefundStatus::Succeeded,
        "FAILED" => ProviderRefundStatus::Failed,
        _ => ProviderRefundStatus::Pending,
    };
    Ok(ProviderRefundResult { refund_id, status })
}

fn wxpay_refund_result(value: &Value, refund_id: String) -> ProviderRefundResult {
    let status = match string(value, "status").to_ascii_uppercase().as_str() {
        "SUCCESS" => ProviderRefundStatus::Succeeded,
        "CLOSED" | "ABNORMAL" => ProviderRefundStatus::Failed,
        _ => ProviderRefundStatus::Pending,
    };
    ProviderRefundResult { refund_id, status }
}

fn alipay_response<'a>(
    value: &'a Value,
    response_key: &str,
    context: &str,
) -> Result<&'a Value, PaymentError> {
    let response = value.get(response_key).unwrap_or(value);
    let code_succeeded = response
        .get("code")
        .is_some_and(|code| code.as_str() == Some("10000") || code.as_i64() == Some(10_000));
    if !code_succeeded {
        return Err(PaymentError::unavailable(
            "PAYMENT_GATEWAY_ERROR",
            format!(
                "{context}: {}",
                provider_message(response, "request rejected")
            ),
        ));
    }
    Ok(response)
}

fn easypay_code_succeeded(code: Option<&Value>) -> bool {
    code.is_some_and(|value| {
        value.as_i64() == Some(1)
            || value
                .as_str()
                .is_some_and(|raw| raw.trim().parse::<i64>().ok() == Some(1))
    })
}

fn easypay_order_missing(message: &str) -> bool {
    let normalized = message.to_ascii_lowercase();
    normalized.contains("order not found")
        || normalized.contains("not exist")
        || message.contains("订单不存在")
        || message.contains("订单编号不存在")
}

fn provider_message(value: &Value, fallback: &str) -> String {
    ["sub_msg", "msg", "message"]
        .iter()
        .find_map(|key| value.get(key).and_then(Value::as_str))
        .filter(|message| !message.trim().is_empty())
        .unwrap_or(fallback)
        .to_owned()
}

fn alipay_refund_id(request: &ProviderRefundRequest) -> String {
    format!(
        "rf-{}",
        deterministic_uuid(&[
            "alipay",
            request.order_id.as_str(),
            format_amount(request.amount, &request.currency).as_str(),
        ])
    )
}

fn wxpay_refund_id(request: &ProviderRefundRequest) -> String {
    if request.order_id.trim().is_empty() {
        return String::new();
    }
    format!(
        "rf-{}",
        deterministic_uuid(&[
            "wxpay",
            request.order_id.as_str(),
            format_amount(request.amount, &request.currency).as_str(),
        ])
    )
}

pub(super) fn verify_notification(
    provider: &ProviderSelection,
    raw_body: &str,
    headers: &HashMap<String, String>,
) -> Result<Option<PaymentNotification>, PaymentError> {
    match provider.provider_key.as_str() {
        "easypay" => verify_easypay(provider, raw_body).map(Some),
        "alipay" => verify_alipay(provider, raw_body).map(Some),
        "stripe" => verify_stripe(provider, raw_body, headers),
        "airwallex" => verify_airwallex(provider, raw_body, headers),
        "wxpay" => verify_wxpay(provider, raw_body, headers).map(Some),
        _ => Err(PaymentError::bad_request(
            "WEBHOOK_VERIFY_FAILED",
            "Unknown payment provider",
        )),
    }
}

fn verify_easypay(
    provider: &ProviderSelection,
    raw_body: &str,
) -> Result<PaymentNotification, PaymentError> {
    let params = url::form_urlencoded::parse(raw_body.as_bytes())
        .into_owned()
        .collect::<BTreeMap<_, _>>();
    let signature = params.get("sign").cloned().unwrap_or_default();
    let expected = easypay_sign(&params, config(provider, "pkey"));
    if expected.as_bytes().ct_eq(signature.as_bytes()).unwrap_u8() != 1 {
        return Err(PaymentError::bad_request(
            "WEBHOOK_VERIFY_FAILED",
            "EasyPay signature is invalid",
        ));
    }
    Ok(PaymentNotification {
        trade_no: params.get("trade_no").cloned().unwrap_or_default(),
        order_id: params.get("out_trade_no").cloned().unwrap_or_default(),
        amount: params
            .get("money")
            .and_then(|value| value.parse().ok())
            .unwrap_or_default(),
        success: params
            .get("trade_status")
            .is_some_and(|value| value == "TRADE_SUCCESS"),
        provider_key: "easypay".to_owned(),
        metadata: HashMap::from([(
            "merchant_id".to_owned(),
            params.get("pid").cloned().unwrap_or_default(),
        )]),
    })
}

fn verify_alipay(
    provider: &ProviderSelection,
    raw_body: &str,
) -> Result<PaymentNotification, PaymentError> {
    let params = url::form_urlencoded::parse(raw_body.as_bytes())
        .into_owned()
        .collect::<BTreeMap<_, _>>();
    let signature = params.get("sign").cloned().unwrap_or_default();
    let canonical = params
        .iter()
        .filter(|(key, value)| {
            key.as_str() != "sign" && key.as_str() != "sign_type" && !value.is_empty()
        })
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&");
    let public_key = nonempty(
        config(provider, "publicKey"),
        config(provider, "alipayPublicKey"),
    );
    rsa_verify(public_key, canonical.as_bytes(), &signature)?;
    Ok(PaymentNotification {
        trade_no: params.get("trade_no").cloned().unwrap_or_default(),
        order_id: params.get("out_trade_no").cloned().unwrap_or_default(),
        amount: params
            .get("total_amount")
            .and_then(|value| value.parse().ok())
            .unwrap_or_default(),
        success: params
            .get("trade_status")
            .is_some_and(|value| matches!(value.as_str(), "TRADE_SUCCESS" | "TRADE_FINISHED")),
        provider_key: "alipay".to_owned(),
        metadata: HashMap::from([(
            "merchant_app_id".to_owned(),
            params.get("app_id").cloned().unwrap_or_default(),
        )]),
    })
}

fn verify_stripe(
    provider: &ProviderSelection,
    raw_body: &str,
    headers: &HashMap<String, String>,
) -> Result<Option<PaymentNotification>, PaymentError> {
    let secret = config(provider, "webhookSecret");
    let signature = headers.get("stripe-signature").map_or("", String::as_str);
    let mut timestamp = None;
    let mut signatures = Vec::new();
    for part in signature.split(',') {
        if let Some((key, value)) = part.trim().split_once('=') {
            match key {
                "t" => timestamp = value.parse::<i64>().ok(),
                "v1" => signatures.push(value),
                _ => {}
            }
        }
    }
    let timestamp = timestamp.ok_or_else(|| {
        PaymentError::bad_request("WEBHOOK_VERIFY_FAILED", "Stripe signature is malformed")
    })?;
    if (chrono::Utc::now().timestamp() - timestamp).abs() > WEBHOOK_TOLERANCE_SECONDS {
        return Err(PaymentError::bad_request(
            "WEBHOOK_VERIFY_FAILED",
            "Stripe webhook timestamp is stale",
        ));
    }
    let signed = format!("{timestamp}.{raw_body}");
    let expected = hmac_hex(secret.as_bytes(), signed.as_bytes())?;
    if !signatures
        .iter()
        .any(|actual| expected.as_bytes().ct_eq(actual.as_bytes()).unwrap_u8() == 1)
    {
        return Err(PaymentError::bad_request(
            "WEBHOOK_VERIFY_FAILED",
            "Stripe signature is invalid",
        ));
    }
    let value: Value = serde_json::from_str(raw_body).map_err(|_| {
        PaymentError::bad_request("WEBHOOK_VERIFY_FAILED", "Stripe payload is invalid")
    })?;
    let event_type = string(&value, "type");
    if !matches!(
        event_type.as_str(),
        "payment_intent.succeeded" | "payment_intent.payment_failed"
    ) {
        return Ok(None);
    }
    let intent = value.pointer("/data/object").cloned().unwrap_or_default();
    let currency = string(&intent, "currency").to_ascii_uppercase();
    Ok(Some(PaymentNotification {
        trade_no: string(&intent, "id"),
        order_id: intent
            .pointer("/metadata/orderId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        amount: from_minor_units(
            intent
                .get("amount")
                .and_then(Value::as_i64)
                .unwrap_or_default(),
            &currency,
        ),
        success: event_type == "payment_intent.succeeded",
        provider_key: "stripe".to_owned(),
        metadata: HashMap::from([("currency".to_owned(), currency)]),
    }))
}

fn verify_airwallex(
    provider: &ProviderSelection,
    raw_body: &str,
    headers: &HashMap<String, String>,
) -> Result<Option<PaymentNotification>, PaymentError> {
    let timestamp = headers.get("x-timestamp").map_or("", String::as_str);
    let signature = headers
        .get("x-signature")
        .map_or("", String::as_str)
        .to_ascii_lowercase();
    let expected = hmac_hex(
        config(provider, "webhookSecret").as_bytes(),
        format!("{timestamp}{raw_body}").as_bytes(),
    )?;
    if expected.as_bytes().ct_eq(signature.as_bytes()).unwrap_u8() != 1 {
        return Err(PaymentError::bad_request(
            "WEBHOOK_VERIFY_FAILED",
            "Airwallex signature is invalid",
        ));
    }
    let millis = timestamp
        .split('.')
        .next()
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(|| {
            PaymentError::bad_request("WEBHOOK_VERIFY_FAILED", "Airwallex timestamp is invalid")
        })?;
    if (chrono::Utc::now().timestamp_millis() - millis).abs() > WEBHOOK_TOLERANCE_SECONDS * 1_000 {
        return Err(PaymentError::bad_request(
            "WEBHOOK_VERIFY_FAILED",
            "Airwallex webhook timestamp is stale",
        ));
    }
    let value: Value = serde_json::from_str(raw_body).map_err(|_| {
        PaymentError::bad_request("WEBHOOK_VERIFY_FAILED", "Airwallex payload is invalid")
    })?;
    let event = string(&value, "name");
    if !matches!(
        event.as_str(),
        "payment_intent.succeeded" | "payment_intent.cancelled"
    ) {
        return Ok(None);
    }
    let intent = value.pointer("/data/object").cloned().unwrap_or_default();
    let currency = string(&intent, "currency").to_ascii_uppercase();
    Ok(Some(PaymentNotification {
        trade_no: string(&intent, "id"),
        order_id: string(&intent, "merchant_order_id"),
        amount: value_number(&intent, "amount"),
        success: event == "payment_intent.succeeded" && string(&intent, "status") == "SUCCEEDED",
        provider_key: "airwallex".to_owned(),
        metadata: merchant_metadata(provider, Some(&currency)),
    }))
}

fn verify_wxpay(
    provider: &ProviderSelection,
    raw_body: &str,
    headers: &HashMap<String, String>,
) -> Result<PaymentNotification, PaymentError> {
    let timestamp = headers
        .get("wechatpay-timestamp")
        .map_or("", String::as_str);
    let nonce = headers.get("wechatpay-nonce").map_or("", String::as_str);
    let signature = headers
        .get("wechatpay-signature")
        .map_or("", String::as_str);
    let canonical = format!("{timestamp}\n{nonce}\n{raw_body}\n");
    rsa_verify(
        config(provider, "publicKey"),
        canonical.as_bytes(),
        signature,
    )?;
    let value: Value = serde_json::from_str(raw_body).map_err(|_| {
        PaymentError::bad_request("WEBHOOK_VERIFY_FAILED", "WeChat Pay payload is invalid")
    })?;
    let resource = value.get("resource").cloned().unwrap_or_default();
    let resource_nonce = string(&resource, "nonce");
    let associated = string(&resource, "associated_data");
    let ciphertext = STANDARD
        .decode(string(&resource, "ciphertext"))
        .map_err(|_| {
            PaymentError::bad_request("WEBHOOK_VERIFY_FAILED", "WeChat Pay ciphertext is invalid")
        })?;
    let cipher =
        Aes256Gcm::new_from_slice(config(provider, "apiV3Key").as_bytes()).map_err(|_| {
            PaymentError::bad_request("WEBHOOK_VERIFY_FAILED", "WeChat Pay API v3 key is invalid")
        })?;
    let plaintext = cipher
        .decrypt(
            resource_nonce.as_bytes().into(),
            Payload {
                msg: &ciphertext,
                aad: associated.as_bytes(),
            },
        )
        .map_err(|_| {
            PaymentError::bad_request(
                "WEBHOOK_VERIFY_FAILED",
                "WeChat Pay resource authentication failed",
            )
        })?;
    let transaction: Value = serde_json::from_slice(&plaintext).map_err(|_| {
        PaymentError::bad_request("WEBHOOK_VERIFY_FAILED", "WeChat Pay transaction is invalid")
    })?;
    let currency = transaction
        .pointer("/amount/currency")
        .and_then(Value::as_str)
        .unwrap_or("CNY");
    Ok(PaymentNotification {
        trade_no: string(&transaction, "transaction_id"),
        order_id: string(&transaction, "out_trade_no"),
        amount: from_minor_units(
            transaction
                .pointer("/amount/total")
                .and_then(Value::as_i64)
                .unwrap_or_default(),
            currency,
        ),
        success: string(&value, "event_type") == "TRANSACTION.SUCCESS"
            && string(&transaction, "trade_state") == "SUCCESS",
        provider_key: "wxpay".to_owned(),
        metadata: HashMap::from([
            ("merchant_app_id".to_owned(), string(&transaction, "appid")),
            ("merchant_id".to_owned(), string(&transaction, "mchid")),
            ("currency".to_owned(), currency.to_owned()),
        ]),
    })
}

fn easypay_sign(params: &BTreeMap<String, String>, key: &str) -> String {
    let canonical = params
        .iter()
        .filter(|(name, value)| {
            !value.is_empty() && name.as_str() != "sign" && name.as_str() != "sign_type"
        })
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&");
    hex::encode(Md5::digest(format!("{canonical}{key}").as_bytes()))
}

fn easypay_upstream_method(provider: &ProviderSelection, method: &str) -> String {
    let method = normalize_payment_type(method);
    provider
        .config
        .get("customMethods")
        .and_then(|raw| serde_json::from_str::<Vec<Value>>(raw).ok())
        .and_then(|items| {
            items.into_iter().find_map(|item| {
                (item.get("type").and_then(Value::as_str) == Some(method.as_str()))
                    .then(|| {
                        item.get("upstreamType")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })
                    .flatten()
            })
        })
        .unwrap_or(method)
}

fn normalize_easypay_base(raw: &str) -> String {
    let mut value = raw.trim().trim_end_matches('/').to_owned();
    for suffix in ["/submit.php", "/mapi.php", "/api.php"] {
        if value.to_ascii_lowercase().ends_with(suffix) {
            value.truncate(value.len() - suffix.len());
            break;
        }
    }
    value
}

fn alipay_parameters(
    provider: &ProviderSelection,
    method: &str,
    biz_content: &Value,
) -> Result<BTreeMap<String, String>, PaymentError> {
    Ok(BTreeMap::from([
        ("app_id".to_owned(), config(provider, "appId").to_owned()),
        ("method".to_owned(), method.to_owned()),
        ("format".to_owned(), "JSON".to_owned()),
        ("charset".to_owned(), "utf-8".to_owned()),
        ("sign_type".to_owned(), "RSA2".to_owned()),
        (
            "timestamp".to_owned(),
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        ),
        ("version".to_owned(), "1.0".to_owned()),
        (
            "biz_content".to_owned(),
            serde_json::to_string(&biz_content)
                .map_err(|error| PaymentError::internal("serialize Alipay request", error))?,
        ),
    ]))
}

fn sign_alipay_parameters(
    params: &mut BTreeMap<String, String>,
    private_key: &str,
) -> Result<(), PaymentError> {
    let canonical = params
        .iter()
        .filter(|(_, value)| !value.is_empty())
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&");
    params.insert(
        "sign".to_owned(),
        rsa_sign(private_key, canonical.as_bytes())?,
    );
    Ok(())
}

fn rsa_sign(private_key: &str, message: &[u8]) -> Result<String, PaymentError> {
    let signature = sign_rsa_pkcs1_sha256(private_key, message).map_err(|_| {
        PaymentError::unavailable(
            "PAYMENT_PROVIDER_MISCONFIGURED",
            "Payment provider private key is invalid",
        )
    })?;
    Ok(STANDARD.encode(signature))
}

fn rsa_verify(public_key: &str, message: &[u8], signature: &str) -> Result<(), PaymentError> {
    let signature = STANDARD.decode(signature).map_err(|_| {
        PaymentError::bad_request("WEBHOOK_VERIFY_FAILED", "Payment signature is malformed")
    })?;
    verify_rsa_pkcs1_sha256(public_key, message, &signature).map_err(|error| match error {
        RsaCryptoError::InvalidKey => PaymentError::bad_request(
            "WEBHOOK_VERIFY_FAILED",
            "Payment provider public key is invalid",
        ),
        RsaCryptoError::InvalidSignature
        | RsaCryptoError::SigningFailed
        | RsaCryptoError::UnsupportedAlgorithm => {
            PaymentError::bad_request("WEBHOOK_VERIFY_FAILED", "Payment signature is invalid")
        }
    })
}

async fn wxpay_request(
    state: &ProviderRuntime,
    provider: &ProviderSelection,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value, PaymentError> {
    let body = body
        .map(|value| serde_json::to_string(&value))
        .transpose()
        .map_err(|error| PaymentError::internal("serialize WeChat Pay request", error))?
        .unwrap_or_default();
    let timestamp = chrono::Utc::now().timestamp().to_string();
    let nonce = random_nonce();
    let canonical = format!(
        "{}\n{path}\n{timestamp}\n{nonce}\n{body}\n",
        method.as_str()
    );
    let signature = rsa_sign(config(provider, "privateKey"), canonical.as_bytes())?;
    let authorization = format!(
        "WECHATPAY2-SHA256-RSA2048 mchid=\"{}\",nonce_str=\"{}\",timestamp=\"{}\",serial_no=\"{}\",signature=\"{}\"",
        config(provider, "mchId"),
        nonce,
        timestamp,
        config(provider, "certSerial"),
        signature
    );
    let mut request = state
        .client()
        .request(method, format!("https://api.mch.weixin.qq.com{path}"))
        .header("Authorization", authorization)
        .header("Accept", "application/json");
    if !body.is_empty() {
        request = request
            .header("Content-Type", "application/json")
            .body(body);
    }
    let response = request.send().await?;
    if response.status() == StatusCode::NO_CONTENT {
        return Ok(Value::Null);
    }
    checked_json(response, "WeChat Pay request").await
}

fn random_nonce() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

async fn airwallex_token(
    state: &ProviderRuntime,
    provider: &ProviderSelection,
) -> Result<String, PaymentError> {
    require_config(provider, &["clientId", "apiKey", "apiBase"])?;
    let mut request = state
        .client()
        .post(format!(
            "{}/authentication/login",
            airwallex_base(provider)?
        ))
        .header("x-client-id", config(provider, "clientId"))
        .header("x-api-key", config(provider, "apiKey"));
    if !config(provider, "accountId").is_empty() {
        request = request.header("x-login-as", config(provider, "accountId"));
    }
    let value = checked_json(request.send().await?, "Airwallex authentication").await?;
    let token = string(&value, "token");
    if token.is_empty() {
        return Err(PaymentError::unavailable(
            "PAYMENT_GATEWAY_ERROR",
            "Airwallex authentication omitted a token",
        ));
    }
    Ok(token)
}

fn airwallex_base(provider: &ProviderSelection) -> Result<String, PaymentError> {
    let base = config(provider, "apiBase").trim().trim_end_matches('/');
    let parsed = Url::parse(base).ok();
    let allowed = parsed.as_ref().is_some_and(|url| {
        url.scheme() == "https"
            && matches!(
                url.host_str(),
                Some("api-demo.airwallex.com" | "api.airwallex.com")
            )
            && matches!(url.path(), "" | "/" | "/api/v1")
    });
    if !allowed {
        return Err(PaymentError::unavailable(
            "PAYMENT_PROVIDER_MISCONFIGURED",
            "Airwallex API base is invalid",
        ));
    }
    Ok(if base.ends_with("/api/v1") {
        base.to_owned()
    } else {
        format!("{base}/api/v1")
    })
}

async fn airwallex_request(
    state: &ProviderRuntime,
    provider: &ProviderSelection,
    method: Method,
    url: String,
    token: &str,
    body: Option<Value>,
) -> Result<Value, PaymentError> {
    let mut request = state.client().request(method, url).bearer_auth(token);
    if !config(provider, "accountId").is_empty() {
        request = request.header("x-on-behalf-of", config(provider, "accountId"));
    }
    if let Some(body) = body {
        request = request.json(&body);
    }
    checked_json(request.send().await?, "Airwallex request").await
}

fn merchant_metadata(
    provider: &ProviderSelection,
    currency: Option<&str>,
) -> HashMap<String, String> {
    let mut metadata = HashMap::new();
    match provider.provider_key.as_str() {
        "easypay" => {
            metadata.insert("merchant_id".to_owned(), config(provider, "pid").to_owned());
        }
        "alipay" => {
            metadata.insert(
                "merchant_app_id".to_owned(),
                config(provider, "appId").to_owned(),
            );
        }
        "wxpay" => {
            metadata.insert(
                "merchant_id".to_owned(),
                config(provider, "mchId").to_owned(),
            );
            metadata.insert(
                "merchant_app_id".to_owned(),
                config(provider, "appId").to_owned(),
            );
        }
        "airwallex" if !config(provider, "accountId").is_empty() => {
            metadata.insert(
                "merchant_id".to_owned(),
                config(provider, "accountId").to_owned(),
            );
        }
        _ => {}
    }
    if let Some(currency) = currency {
        metadata.insert("currency".to_owned(), currency.to_owned());
    }
    metadata
}

fn stripe_methods(supported: &str) -> Vec<String> {
    let mut methods = supported
        .split(',')
        .filter_map(|method| match normalize_payment_type(method).as_str() {
            "card" => Some("card".to_owned()),
            "alipay" => Some("alipay".to_owned()),
            "wxpay" => Some("wechat_pay".to_owned()),
            "link" => Some("link".to_owned()),
            _ => None,
        })
        .collect::<Vec<_>>();
    if methods.is_empty() {
        methods.push("card".to_owned());
    }
    methods.sort();
    methods.dedup();
    methods
}

fn require_config(provider: &ProviderSelection, keys: &[&str]) -> Result<(), PaymentError> {
    if let Some(key) = keys
        .iter()
        .find(|key| config(provider, key).trim().is_empty())
    {
        return Err(PaymentError::unavailable(
            "PAYMENT_PROVIDER_MISCONFIGURED",
            format!("Payment provider config is missing {key}"),
        ));
    }
    Ok(())
}

fn config<'a>(provider: &'a ProviderSelection, key: &str) -> &'a str {
    provider.config.get(key).map_or("", String::as_str)
}

fn format_amount(amount: f64, currency: &str) -> String {
    let digits = currency_minor_units(currency);
    format!("{amount:.digits$}")
}

fn currency_minor_units(currency: &str) -> usize {
    match currency.to_ascii_uppercase().as_str() {
        "JPY" | "KRW" => 0,
        "BHD" | "JOD" | "KWD" | "OMR" | "TND" => 3,
        _ => 2,
    }
}

#[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
fn to_minor_units(amount: f64, currency: &str) -> Result<i64, PaymentError> {
    if !amount.is_finite() || amount <= 0.0 {
        return Err(PaymentError::bad_request(
            "INVALID_AMOUNT",
            "Payment amount is invalid",
        ));
    }
    let multiplier = 10_f64.powi(i32::try_from(currency_minor_units(currency)).unwrap_or(2));
    let value = (amount * multiplier).round();
    if value > i64::MAX as f64 {
        return Err(PaymentError::bad_request(
            "INVALID_AMOUNT",
            "Payment amount is too large",
        ));
    }
    Ok(value as i64)
}

#[allow(clippy::cast_precision_loss)]
fn from_minor_units(amount: i64, currency: &str) -> f64 {
    let multiplier = 10_f64.powi(i32::try_from(currency_minor_units(currency)).unwrap_or(2));
    amount as f64 / multiplier
}

fn deterministic_uuid(parts: &[&str]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part.as_bytes());
        digest.update([0]);
    }
    let mut bytes: [u8; 16] = digest.finalize()[..16].try_into().unwrap_or_default();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes).to_string()
}

fn hmac_hex(key: &[u8], message: &[u8]) -> Result<String, PaymentError> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .map_err(|error| PaymentError::internal("initialize payment webhook HMAC", error))?;
    mac.update(message);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

async fn checked_json(
    response: reqwest::Response,
    context: &'static str,
) -> Result<Value, PaymentError> {
    let status = response.status();
    let bytes = response.bytes().await?;
    if bytes.len() > MAX_PROVIDER_RESPONSE_BYTES {
        return Err(PaymentError::unavailable(
            "PAYMENT_GATEWAY_ERROR",
            "Payment provider response was too large",
        ));
    }
    if !status.is_success() {
        let summary = String::from_utf8_lossy(&bytes);
        return Err(PaymentError::unavailable(
            "PAYMENT_GATEWAY_ERROR",
            format!(
                "{context} returned HTTP {status}: {}",
                summary.chars().take(300).collect::<String>()
            ),
        ));
    }
    if bytes.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| PaymentError::internal("parse payment provider response", error))
}

fn string(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn value_number(value: &Value, key: &str) -> f64 {
    value
        .get(key)
        .and_then(|item| item.as_f64().or_else(|| item.as_str()?.parse().ok()))
        .unwrap_or_default()
}

fn nonempty<'a>(preferred: &'a str, fallback: &'a str) -> &'a str {
    if preferred.trim().is_empty() {
        fallback
    } else {
        preferred
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn easypay_signature_matches_sorted_nonempty_parameters() {
        let params = BTreeMap::from([
            ("b".to_owned(), "2".to_owned()),
            ("a".to_owned(), "1".to_owned()),
            ("sign".to_owned(), "ignored".to_owned()),
        ]);
        let expected = hex::encode(Md5::digest(b"a=1&b=2secret"));
        assert_eq!(easypay_sign(&params, "secret"), expected);
    }

    #[test]
    fn payment_type_aliases_are_normalized() {
        assert_eq!(normalize_payment_type("alipay_direct"), "alipay");
        assert_eq!(normalize_payment_type("wechat"), "wxpay");
    }

    #[test]
    fn deterministic_request_ids_are_stable() {
        let first = deterministic_uuid(&["payment", "order-1"]);
        assert_eq!(first, deterministic_uuid(&["payment", "order-1"]));
        assert_ne!(first, deterministic_uuid(&["payment", "order-2"]));
    }

    #[test]
    fn provider_refund_statuses_do_not_treat_pending_as_success() {
        assert_eq!(
            stripe_refund_result(&json!({"id": "re_1", "status": "pending"}))
                .unwrap()
                .status,
            ProviderRefundStatus::Pending
        );
        assert_eq!(
            airwallex_refund_result(&json!({"id": "rf_1", "status": "FAILED"}), "")
                .unwrap()
                .status,
            ProviderRefundStatus::Failed
        );
        assert_eq!(
            wxpay_refund_result(&json!({"status": "SUCCESS"}), "wx-rf".to_owned()).status,
            ProviderRefundStatus::Succeeded
        );
    }

    #[test]
    fn easypay_refund_codes_accept_only_explicit_success() {
        assert!(easypay_code_succeeded(Some(&json!(1))));
        assert!(easypay_code_succeeded(Some(&json!("1"))));
        assert!(!easypay_code_succeeded(Some(&json!(0))));
        assert!(!easypay_code_succeeded(None));
    }

    #[test]
    fn provider_refund_ids_are_deterministic_and_provider_scoped() {
        let request = ProviderRefundRequest {
            trade_no: "trade-1".to_owned(),
            order_id: "order-1".to_owned(),
            refund_id: String::new(),
            amount: 12.34,
            total_amount: 20.0,
            currency: "CNY".to_owned(),
            reason: "test".to_owned(),
        };
        assert_eq!(alipay_refund_id(&request), alipay_refund_id(&request));
        assert_eq!(wxpay_refund_id(&request), wxpay_refund_id(&request));
        assert_ne!(alipay_refund_id(&request), wxpay_refund_id(&request));
    }
}
