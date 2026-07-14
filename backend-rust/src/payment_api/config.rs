use std::collections::{BTreeMap, HashMap, HashSet};

use axum::{Json, Router, extract::State, http::HeaderMap, routing::get};
use serde::Deserialize;
use serde_json::Value;
use sqlx::Row;

use super::{
    PaymentApiState, PaymentError,
    models::{
        CheckoutInfo, MethodLimits, MethodLimitsResponse, PaymentChannelView, PaymentConfig,
        PlanView, optional_decimal, parse_decimal,
    },
    provider::{decode_provider_config, normalize_payment_type, provider_currency},
};
use crate::control_api::ApiEnvelope;

const CONFIG_KEYS: &[&str] = &[
    "payment_enabled",
    "MIN_RECHARGE_AMOUNT",
    "MAX_RECHARGE_AMOUNT",
    "DAILY_RECHARGE_LIMIT",
    "ORDER_TIMEOUT_MINUTES",
    "MAX_PENDING_ORDERS",
    "ENABLED_PAYMENT_TYPES",
    "LOAD_BALANCE_STRATEGY",
    "BALANCE_PAYMENT_DISABLED",
    "BALANCE_RECHARGE_MULTIPLIER",
    "SUBSCRIPTION_USD_TO_CNY_RATE",
    "RECHARGE_FEE_RATE",
    "PRODUCT_NAME_PREFIX",
    "PRODUCT_NAME_SUFFIX",
    "PAYMENT_HELP_IMAGE_URL",
    "PAYMENT_HELP_TEXT",
    "CANCEL_RATE_LIMIT_ENABLED",
    "CANCEL_RATE_LIMIT_MAX",
    "CANCEL_RATE_LIMIT_WINDOW",
    "CANCEL_RATE_LIMIT_UNIT",
    "CANCEL_RATE_LIMIT_WINDOW_MODE",
    "ALIPAY_FORCE_QRCODE",
    "payment_visible_method_alipay_source",
    "payment_visible_method_wxpay_source",
    "payment_visible_method_alipay_enabled",
    "payment_visible_method_wxpay_enabled",
];

pub(super) fn routes() -> Router<PaymentApiState> {
    Router::new()
        .route("/api/v1/payment/config", get(payment_config))
        .route("/api/v1/payment/checkout-info", get(checkout_info))
        .route("/api/v1/payment/plans", get(plans))
        .route("/api/v1/payment/channels", get(channels))
        .route("/api/v1/payment/limits", get(limits))
}

#[derive(Clone, Debug)]
struct ProviderInstance {
    provider_key: String,
    config: HashMap<String, String>,
    supported_types: String,
    limits: HashMap<String, ChannelLimit>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChannelLimit {
    daily_limit: f64,
    single_min: f64,
    single_max: f64,
}

async fn payment_config(
    State(state): State<PaymentApiState>,
    headers: HeaderMap,
) -> Result<Json<ApiEnvelope<PaymentConfig>>, PaymentError> {
    let _user = state.authenticate(&headers).await?;
    Ok(Json(ApiEnvelope::success(
        load_payment_config(&state).await?,
    )))
}

async fn plans(
    State(state): State<PaymentApiState>,
    headers: HeaderMap,
) -> Result<Json<ApiEnvelope<Vec<PlanView>>>, PaymentError> {
    let _user = state.authenticate(&headers).await?;
    Ok(Json(ApiEnvelope::success(load_plans(&state).await?)))
}

async fn channels(
    State(state): State<PaymentApiState>,
    headers: HeaderMap,
) -> Result<Json<ApiEnvelope<Vec<PaymentChannelView>>>, PaymentError> {
    let _user = state.authenticate(&headers).await?;
    Ok(Json(ApiEnvelope::success(load_channels(&state).await?)))
}

async fn limits(
    State(state): State<PaymentApiState>,
    headers: HeaderMap,
) -> Result<Json<ApiEnvelope<MethodLimitsResponse>>, PaymentError> {
    let _user = state.authenticate(&headers).await?;
    Ok(Json(ApiEnvelope::success(
        load_method_limits(&state).await?,
    )))
}

async fn checkout_info(
    State(state): State<PaymentApiState>,
    headers: HeaderMap,
) -> Result<Json<ApiEnvelope<CheckoutInfo>>, PaymentError> {
    let _user = state.authenticate(&headers).await?;
    let config = load_payment_config(&state).await?;
    let limits = load_method_limits(&state).await?;
    let plans = load_plans(&state).await.unwrap_or_default();
    Ok(Json(ApiEnvelope::success(CheckoutInfo {
        methods: limits.methods,
        global_min: limits.global_min,
        global_max: limits.global_max,
        plans,
        balance_disabled: config.balance_disabled,
        balance_recharge_multiplier: config.balance_recharge_multiplier,
        subscription_usd_to_cny_rate: config.subscription_usd_to_cny_rate,
        recharge_fee_rate: config.recharge_fee_rate,
        help_text: config.help_text,
        help_image_url: config.help_image_url,
        stripe_publishable_key: config.stripe_publishable_key,
        alipay_force_qrcode: config.alipay_force_qrcode,
    })))
}

pub(super) async fn load_payment_config(
    state: &PaymentApiState,
) -> Result<PaymentConfig, PaymentError> {
    let settings = load_settings(state, CONFIG_KEYS).await?;
    let mut enabled_payment_types = split_csv(value(&settings, "ENABLED_PAYMENT_TYPES"))
        .into_iter()
        .map(|item| normalize_payment_type(&item))
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>();
    enabled_payment_types.dedup();
    let stripe_publishable_key = load_provider_instances(state)
        .await?
        .into_iter()
        .find(|instance| instance.provider_key == "stripe")
        .and_then(|instance| instance.config.get("publishableKey").cloned())
        .unwrap_or_default();
    Ok(PaymentConfig {
        enabled: is_true(value(&settings, "payment_enabled")),
        min_amount: parse_float(value(&settings, "MIN_RECHARGE_AMOUNT"), 1.0),
        max_amount: parse_float(value(&settings, "MAX_RECHARGE_AMOUNT"), 0.0),
        daily_limit: parse_float(value(&settings, "DAILY_RECHARGE_LIMIT"), 0.0),
        order_timeout_minutes: parse_int(value(&settings, "ORDER_TIMEOUT_MINUTES"), 30),
        max_pending_orders: parse_int(value(&settings, "MAX_PENDING_ORDERS"), 3),
        enabled_payment_types,
        balance_disabled: is_true(value(&settings, "BALANCE_PAYMENT_DISABLED")),
        balance_recharge_multiplier: positive_or(
            parse_float(value(&settings, "BALANCE_RECHARGE_MULTIPLIER"), 1.0),
            1.0,
        ),
        subscription_usd_to_cny_rate: nonnegative_or_zero(parse_float(
            value(&settings, "SUBSCRIPTION_USD_TO_CNY_RATE"),
            0.0,
        )),
        recharge_fee_rate: parse_float(value(&settings, "RECHARGE_FEE_RATE"), 0.0),
        load_balance_strategy: default_string(
            value(&settings, "LOAD_BALANCE_STRATEGY"),
            "round-robin",
        ),
        product_name_prefix: value(&settings, "PRODUCT_NAME_PREFIX").to_owned(),
        product_name_suffix: value(&settings, "PRODUCT_NAME_SUFFIX").to_owned(),
        help_image_url: value(&settings, "PAYMENT_HELP_IMAGE_URL").to_owned(),
        help_text: value(&settings, "PAYMENT_HELP_TEXT").to_owned(),
        stripe_publishable_key,
        cancel_rate_limit_enabled: is_true(value(&settings, "CANCEL_RATE_LIMIT_ENABLED")),
        cancel_rate_limit_max: parse_int(value(&settings, "CANCEL_RATE_LIMIT_MAX"), 10),
        cancel_rate_limit_window: parse_int(value(&settings, "CANCEL_RATE_LIMIT_WINDOW"), 1),
        cancel_rate_limit_unit: value(&settings, "CANCEL_RATE_LIMIT_UNIT").to_owned(),
        cancel_rate_limit_window_mode: value(&settings, "CANCEL_RATE_LIMIT_WINDOW_MODE").to_owned(),
        alipay_force_qrcode: is_true(value(&settings, "ALIPAY_FORCE_QRCODE")),
    })
}

pub(super) async fn load_method_limits(
    state: &PaymentApiState,
) -> Result<MethodLimitsResponse, PaymentError> {
    let instances = load_provider_instances(state).await?;
    let settings = load_settings(
        state,
        &[
            "payment_visible_method_alipay_source",
            "payment_visible_method_wxpay_source",
        ],
    )
    .await?;
    let mut grouped = BTreeMap::<String, Vec<&ProviderInstance>>::new();
    for instance in &instances {
        for method in provider_methods(instance) {
            grouped.entry(method).or_default().push(instance);
        }
    }
    apply_visible_source_filter(&mut grouped, &settings);
    let mut methods = BTreeMap::new();
    for (method, providers) in grouped {
        if providers.is_empty() {
            continue;
        }
        let currencies = providers
            .iter()
            .map(|provider| provider_currency(&provider.provider_key, &provider.config))
            .collect::<HashSet<_>>();
        if currencies.len() != 1 {
            continue;
        }
        let currency = currencies
            .into_iter()
            .next()
            .unwrap_or_else(|| "CNY".to_owned());
        let mut limit = aggregate_limits(&method, &providers);
        limit.currency = currency;
        limit.display_name = providers
            .iter()
            .find_map(|provider| custom_display_name(provider, &method))
            .unwrap_or_default();
        methods.insert(method, limit);
    }
    let (global_min, global_max) = global_range(&methods);
    Ok(MethodLimitsResponse {
        methods,
        global_min,
        global_max,
    })
}

pub(super) async fn load_plans(state: &PaymentApiState) -> Result<Vec<PlanView>, PaymentError> {
    let rows = sqlx::query(
        r"
SELECT
    p.id, p.group_id, g.platform AS group_platform, g.name AS group_name,
    g.rate_multiplier::text AS rate_multiplier,
    g.peak_rate_enabled, g.peak_start, g.peak_end,
    g.peak_rate_multiplier::text AS peak_rate_multiplier,
    g.daily_limit_usd::text AS daily_limit_usd,
    g.weekly_limit_usd::text AS weekly_limit_usd,
    g.monthly_limit_usd::text AS monthly_limit_usd,
    g.supported_model_scopes,
    p.name, p.description, p.price::text AS price,
    p.original_price::text AS original_price,
    p.validity_days, p.validity_unit, p.features, p.product_name,
    p.for_sale, p.sort_order
FROM subscription_plans p
JOIN groups g ON g.id = p.group_id AND g.deleted_at IS NULL
WHERE p.for_sale = TRUE
ORDER BY p.sort_order, p.id
",
    )
    .fetch_all(state.pool())
    .await?;
    let mut plans = Vec::with_capacity(rows.len());
    for row in rows {
        let scopes: Value = row.try_get("supported_model_scopes")?;
        plans.push(PlanView {
            id: row.try_get("id")?,
            group_id: row.try_get("group_id")?,
            group_platform: row.try_get("group_platform")?,
            group_name: row.try_get("group_name")?,
            rate_multiplier: parse_decimal(row.try_get::<String, _>("rate_multiplier")?.as_str())?,
            peak_rate_enabled: row.try_get("peak_rate_enabled")?,
            peak_start: row.try_get("peak_start")?,
            peak_end: row.try_get("peak_end")?,
            peak_rate_multiplier: parse_decimal(
                row.try_get::<String, _>("peak_rate_multiplier")?.as_str(),
            )?,
            daily_limit_usd: optional_decimal(row.try_get("daily_limit_usd")?)?,
            weekly_limit_usd: optional_decimal(row.try_get("weekly_limit_usd")?)?,
            monthly_limit_usd: optional_decimal(row.try_get("monthly_limit_usd")?)?,
            supported_model_scopes: serde_json::from_value(scopes).unwrap_or_default(),
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            price: parse_decimal(row.try_get::<String, _>("price")?.as_str())?,
            original_price: optional_decimal(row.try_get("original_price")?)?,
            validity_days: row.try_get("validity_days")?,
            validity_unit: row.try_get("validity_unit")?,
            features: parse_features(row.try_get::<String, _>("features")?.as_str()),
            product_name: row.try_get("product_name")?,
            for_sale: row.try_get("for_sale")?,
            sort_order: row.try_get("sort_order")?,
        });
    }
    Ok(plans)
}

async fn load_channels(state: &PaymentApiState) -> Result<Vec<PaymentChannelView>, PaymentError> {
    let rows = sqlx::query(
        r"
SELECT
    c.id, c.name, COALESCE(c.description, '') AS description, c.status,
    COALESCE(NULLIF(c.billing_model_source, ''), 'channel_mapped') AS billing_model_source,
    COALESCE(c.restrict_models, FALSE) AS restrict_models,
    COALESCE(c.features, '') AS features,
    COALESCE(ARRAY_AGG(cg.group_id ORDER BY cg.group_id)
      FILTER (WHERE cg.group_id IS NOT NULL), ARRAY[]::bigint[]) AS group_ids,
    COALESCE(c.model_mapping, '{}'::jsonb) AS model_mapping
FROM channels c
LEFT JOIN channel_groups cg ON cg.channel_id = c.id
WHERE c.status = 'active'
GROUP BY c.id
ORDER BY LOWER(c.name), c.id
",
    )
    .fetch_all(state.pool())
    .await?;
    rows.iter()
        .map(|row| {
            Ok(PaymentChannelView {
                id: row.try_get("id")?,
                name: row.try_get("name")?,
                description: row.try_get("description")?,
                status: row.try_get("status")?,
                billing_model_source: row.try_get("billing_model_source")?,
                restrict_models: row.try_get("restrict_models")?,
                features: row.try_get("features")?,
                group_ids: row.try_get("group_ids")?,
                model_mapping: row.try_get("model_mapping")?,
            })
        })
        .collect::<Result<_, sqlx::Error>>()
        .map_err(Into::into)
}

async fn load_provider_instances(
    state: &PaymentApiState,
) -> Result<Vec<ProviderInstance>, PaymentError> {
    let rows = sqlx::query(
        r"
SELECT provider_key, config, supported_types, limits
FROM payment_provider_instances
WHERE enabled = TRUE
ORDER BY sort_order, id
",
    )
    .fetch_all(state.pool())
    .await?;
    let mut instances = Vec::with_capacity(rows.len());
    for row in rows {
        let stored: String = row.try_get("config")?;
        let config = decode_provider_config(state, &stored)?;
        let limits_raw: String = row.try_get("limits")?;
        instances.push(ProviderInstance {
            provider_key: row.try_get("provider_key")?,
            config,
            supported_types: row.try_get("supported_types")?,
            limits: serde_json::from_str(&limits_raw).unwrap_or_default(),
        });
    }
    Ok(instances)
}

pub(super) async fn load_settings(
    state: &PaymentApiState,
    keys: &[&str],
) -> Result<HashMap<String, String>, PaymentError> {
    let rows = sqlx::query("SELECT key, value FROM settings WHERE key = ANY($1)")
        .bind(keys)
        .fetch_all(state.pool())
        .await?;
    rows.iter()
        .map(|row| Ok((row.try_get("key")?, row.try_get("value")?)))
        .collect::<Result<_, sqlx::Error>>()
        .map_err(Into::into)
}

fn provider_methods(instance: &ProviderInstance) -> Vec<String> {
    if instance.provider_key == "stripe" {
        return vec!["stripe".to_owned()];
    }
    if matches!(instance.provider_key.as_str(), "alipay" | "wxpay")
        && instance.supported_types.trim().is_empty()
    {
        return vec![instance.provider_key.clone()];
    }
    let mut methods = split_csv(&instance.supported_types)
        .into_iter()
        .map(|item| normalize_payment_type(&item))
        .filter(|item| !item.is_empty() && item != "easypay")
        .collect::<Vec<_>>();
    if instance.provider_key == "airwallex" && methods.is_empty() {
        methods.push("airwallex".to_owned());
    }
    methods.sort();
    methods.dedup();
    methods
}

fn apply_visible_source_filter(
    grouped: &mut BTreeMap<String, Vec<&ProviderInstance>>,
    settings: &HashMap<String, String>,
) {
    for (method, key) in [
        ("alipay", "payment_visible_method_alipay_source"),
        ("wxpay", "payment_visible_method_wxpay_source"),
    ] {
        let source = value(settings, key);
        let provider_key = match source {
            "official_alipay" => "alipay",
            "official_wxpay" => "wxpay",
            "easypay_alipay" | "easypay_wxpay" => "easypay",
            _ => continue,
        };
        if let Some(instances) = grouped.get_mut(method) {
            instances.retain(|instance| instance.provider_key == provider_key);
        }
    }
}

fn aggregate_limits(method: &str, providers: &[&ProviderInstance]) -> MethodLimits {
    let mut result = MethodLimits {
        payment_type: method.to_owned(),
        ..MethodLimits::default()
    };
    let mut min_limited = true;
    let mut max_limited = true;
    let mut daily_limited = true;
    for provider in providers {
        let lookup = if provider.provider_key == "stripe" {
            "stripe"
        } else {
            method
        };
        let Some(limit) = provider.limits.get(lookup) else {
            return result;
        };
        (result.single_min, min_limited) =
            union_limit(result.single_min, min_limited, limit.single_min, true);
        (result.single_max, max_limited) =
            union_limit(result.single_max, max_limited, limit.single_max, false);
        (result.daily_limit, daily_limited) =
            union_limit(result.daily_limit, daily_limited, limit.daily_limit, false);
    }
    if !min_limited {
        result.single_min = 0.0;
    }
    if !max_limited {
        result.single_max = 0.0;
    }
    if !daily_limited {
        result.daily_limit = 0.0;
    }
    result
}

fn union_limit(current: f64, limited: bool, value: f64, minimum: bool) -> (f64, bool) {
    if value == 0.0 || !limited {
        return (current, false);
    }
    if current == 0.0 || (minimum && value < current) || (!minimum && value > current) {
        (value, true)
    } else {
        (current, true)
    }
}

fn global_range(methods: &BTreeMap<String, MethodLimits>) -> (f64, f64) {
    let mut minimum = 0.0;
    let mut maximum = 0.0;
    let mut min_limited = true;
    let mut max_limited = true;
    for limits in methods.values() {
        (minimum, min_limited) = union_limit(minimum, min_limited, limits.single_min, true);
        (maximum, max_limited) = union_limit(maximum, max_limited, limits.single_max, false);
    }
    if !min_limited {
        minimum = 0.0;
    }
    if !max_limited {
        maximum = 0.0;
    }
    (minimum, maximum)
}

fn custom_display_name(instance: &ProviderInstance, method: &str) -> Option<String> {
    if instance.provider_key != "easypay" {
        return None;
    }
    let raw = instance.config.get("customMethods")?;
    let methods: Vec<Value> = serde_json::from_str(raw).ok()?;
    methods.into_iter().find_map(|item| {
        (item.get("type")?.as_str()? == method)
            .then(|| {
                item.get("displayName")?
                    .as_str()
                    .map(str::trim)
                    .map(str::to_owned)
            })
            .flatten()
    })
}

fn parse_features(raw: &str) -> Vec<String> {
    raw.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

fn split_csv(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

fn value<'a>(settings: &'a HashMap<String, String>, key: &str) -> &'a str {
    settings.get(key).map_or("", String::as_str)
}

fn is_true(raw: &str) -> bool {
    raw == "true"
}

fn parse_float(raw: &str, default: f64) -> f64 {
    raw.parse().unwrap_or(default)
}

fn parse_int(raw: &str, default: i32) -> i32 {
    raw.parse().unwrap_or(default)
}

fn positive_or(value: f64, default: f64) -> f64 {
    if value.is_finite() && value > 0.0 {
        value
    } else {
        default
    }
}

fn nonnegative_or_zero(value: f64) -> f64 {
    if value.is_finite() && value >= 0.0 {
        value
    } else {
        0.0
    }
}

fn default_string(raw: &str, default: &str) -> String {
    if raw.is_empty() {
        default.to_owned()
    } else {
        raw.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limit_union_is_least_restrictive() {
        assert_eq!(union_limit(10.0, true, 5.0, true), (5.0, true));
        assert_eq!(union_limit(10.0, true, 20.0, false), (20.0, true));
        assert_eq!(union_limit(10.0, true, 0.0, false), (10.0, false));
    }
}
