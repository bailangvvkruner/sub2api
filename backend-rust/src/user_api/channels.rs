use std::collections::{BTreeMap, HashMap, HashSet};

use axum::{Json, Router, extract::State, http::HeaderMap, routing::get};
use serde::Serialize;
use serde_json::Value;
use sqlx::Row;

use super::{authenticated_user, decimal, groups::available_group_ids, optional_decimal};
use crate::control_api::{ApiEnvelope, ApiError, ControlApiState};

pub(super) fn routes() -> Router<ControlApiState> {
    Router::new().route("/api/v1/channels/available", get(available))
}

#[derive(Debug, Serialize)]
struct ChannelView {
    name: String,
    description: String,
    platforms: Vec<PlatformSection>,
}

#[derive(Debug, Serialize)]
struct PlatformSection {
    platform: String,
    groups: Vec<ChannelGroup>,
    supported_models: Vec<SupportedModel>,
}

#[derive(Clone, Debug, Serialize)]
struct ChannelGroup {
    id: i64,
    name: String,
    platform: String,
    subscription_type: String,
    rate_multiplier: f64,
    peak_rate_enabled: bool,
    peak_start: String,
    peak_end: String,
    peak_rate_multiplier: f64,
    is_exclusive: bool,
}

#[derive(Clone, Debug, Serialize)]
struct SupportedModel {
    name: String,
    platform: String,
    pricing: Option<PricingView>,
}

#[derive(Clone, Debug, Serialize)]
struct PricingView {
    billing_mode: String,
    input_price: Option<f64>,
    output_price: Option<f64>,
    cache_write_price: Option<f64>,
    cache_read_price: Option<f64>,
    image_output_price: Option<f64>,
    per_request_price: Option<f64>,
    intervals: Vec<PricingInterval>,
}

#[derive(Clone, Debug, Serialize)]
struct PricingInterval {
    min_tokens: i32,
    max_tokens: Option<i32>,
    #[serde(skip_serializing_if = "String::is_empty")]
    tier_label: String,
    input_price: Option<f64>,
    output_price: Option<f64>,
    cache_write_price: Option<f64>,
    cache_read_price: Option<f64>,
    per_request_price: Option<f64>,
}

#[derive(Debug)]
struct ChannelRow {
    id: i64,
    name: String,
    description: String,
    mapping: BTreeMap<String, BTreeMap<String, String>>,
}

#[derive(Clone, Debug)]
struct PricingEntry {
    platform: String,
    models: Vec<String>,
    view: PricingView,
}

#[derive(Default)]
struct PlatformPricingIndex {
    entries: HashMap<String, (String, PricingView)>,
    names: Vec<String>,
}

async fn available(
    State(state): State<ControlApiState>,
    headers: HeaderMap,
) -> Result<Json<ApiEnvelope<Vec<ChannelView>>>, ApiError> {
    let user = authenticated_user(&state, &headers).await?;
    if !feature_enabled(&state).await {
        return Ok(Json(ApiEnvelope::success(Vec::new())));
    }
    let visible_group_ids = available_group_ids(&state, &user).await?;
    let channels = load_channels(&state).await?;
    if channels.is_empty() {
        return Ok(Json(ApiEnvelope::success(Vec::new())));
    }
    let channel_ids = channels
        .iter()
        .map(|channel| channel.id)
        .collect::<Vec<_>>();
    let mut groups = load_channel_groups(&state, &channel_ids, &visible_group_ids).await?;
    let pricing = load_pricing(&state, &channel_ids).await?;
    let mut result = Vec::with_capacity(channels.len());
    for channel in channels {
        let channel_groups = groups.remove(&channel.id).unwrap_or_default();
        if channel_groups.is_empty() {
            continue;
        }
        let supported = supported_models(
            &channel.mapping,
            pricing.get(&channel.id).map_or(&[], Vec::as_slice),
        );
        let mut by_platform = BTreeMap::<String, Vec<ChannelGroup>>::new();
        for group in channel_groups {
            by_platform
                .entry(group.platform.clone())
                .or_default()
                .push(group);
        }
        let platforms = by_platform
            .into_iter()
            .map(|(platform, groups)| PlatformSection {
                supported_models: supported
                    .iter()
                    .filter(|model| model.platform == platform)
                    .cloned()
                    .collect(),
                platform,
                groups,
            })
            .collect();
        result.push(ChannelView {
            name: channel.name,
            description: channel.description,
            platforms,
        });
    }
    Ok(Json(ApiEnvelope::success(result)))
}

async fn feature_enabled(state: &ControlApiState) -> bool {
    match sqlx::query_scalar::<_, String>(
        "SELECT value FROM settings WHERE key = 'available_channels_enabled'",
    )
    .fetch_optional(state.pool())
    .await
    {
        Ok(Some(value)) => value == "true",
        Ok(None) => false,
        Err(error) => {
            tracing::warn!(%error, "failed to read available channels feature flag; failing closed");
            false
        }
    }
}

async fn load_channels(state: &ControlApiState) -> Result<Vec<ChannelRow>, ApiError> {
    let rows = sqlx::query(
        r"
SELECT id, name, COALESCE(description, '') AS description, model_mapping
FROM channels
WHERE status = 'active'
ORDER BY LOWER(name), id
",
    )
    .fetch_all(state.pool())
    .await?;
    rows.iter()
        .map(|row| {
            Ok(ChannelRow {
                id: row.try_get("id")?,
                name: row.try_get("name")?,
                description: row.try_get("description")?,
                mapping: decode_mapping(row.try_get("model_mapping")?),
            })
        })
        .collect::<Result<_, sqlx::Error>>()
        .map_err(Into::into)
}

async fn load_channel_groups(
    state: &ControlApiState,
    channel_ids: &[i64],
    visible_group_ids: &HashSet<i64>,
) -> Result<HashMap<i64, Vec<ChannelGroup>>, ApiError> {
    let rows = sqlx::query(
        r"
SELECT
    cg.channel_id, g.id, g.name, g.platform, g.subscription_type,
    g.rate_multiplier::text AS rate_multiplier,
    g.peak_rate_enabled, g.peak_start, g.peak_end,
    g.peak_rate_multiplier::text AS peak_rate_multiplier,
    g.is_exclusive
FROM channel_groups cg
JOIN groups g ON g.id = cg.group_id
WHERE cg.channel_id = ANY($1) AND g.status = 'active' AND g.deleted_at IS NULL
ORDER BY cg.channel_id, g.name, g.id
",
    )
    .bind(channel_ids)
    .fetch_all(state.pool())
    .await?;
    let mut groups = HashMap::<i64, Vec<ChannelGroup>>::new();
    for row in rows {
        let id: i64 = row.try_get("id")?;
        if !visible_group_ids.contains(&id) {
            continue;
        }
        groups
            .entry(row.try_get("channel_id")?)
            .or_default()
            .push(ChannelGroup {
                id,
                name: row.try_get("name")?,
                platform: row.try_get("platform")?,
                subscription_type: row.try_get("subscription_type")?,
                rate_multiplier: decimal(row.try_get::<String, _>("rate_multiplier")?.as_str())?,
                peak_rate_enabled: row.try_get("peak_rate_enabled")?,
                peak_start: row.try_get("peak_start")?,
                peak_end: row.try_get("peak_end")?,
                peak_rate_multiplier: decimal(
                    row.try_get::<String, _>("peak_rate_multiplier")?.as_str(),
                )?,
                is_exclusive: row.try_get("is_exclusive")?,
            });
    }
    Ok(groups)
}

async fn load_pricing(
    state: &ControlApiState,
    channel_ids: &[i64],
) -> Result<HashMap<i64, Vec<PricingEntry>>, ApiError> {
    let rows = sqlx::query(
        r"
SELECT
    id, channel_id, platform, models, billing_mode,
    input_price::text AS input_price,
    output_price::text AS output_price,
    cache_write_price::text AS cache_write_price,
    cache_read_price::text AS cache_read_price,
    image_output_price::text AS image_output_price,
    per_request_price::text AS per_request_price
FROM channel_model_pricing
WHERE channel_id = ANY($1)
ORDER BY id
",
    )
    .bind(channel_ids)
    .fetch_all(state.pool())
    .await?;
    let pricing_ids = rows
        .iter()
        .map(|row| row.try_get::<i64, _>("id"))
        .collect::<Result<Vec<_>, _>>()?;
    let mut intervals = load_intervals(state, &pricing_ids).await?;
    let mut pricing = HashMap::<i64, Vec<PricingEntry>>::new();
    for row in rows {
        let id: i64 = row.try_get("id")?;
        let raw_models: Value = row.try_get("models")?;
        let models = serde_json::from_value(raw_models)
            .map_err(|error| ApiError::internal("decode channel pricing models", error))?;
        pricing
            .entry(row.try_get("channel_id")?)
            .or_default()
            .push(PricingEntry {
                platform: row.try_get("platform")?,
                models,
                view: PricingView {
                    billing_mode: row.try_get("billing_mode")?,
                    input_price: optional_decimal(row.try_get("input_price")?)?,
                    output_price: optional_decimal(row.try_get("output_price")?)?,
                    cache_write_price: optional_decimal(row.try_get("cache_write_price")?)?,
                    cache_read_price: optional_decimal(row.try_get("cache_read_price")?)?,
                    image_output_price: optional_decimal(row.try_get("image_output_price")?)?,
                    per_request_price: optional_decimal(row.try_get("per_request_price")?)?,
                    intervals: intervals.remove(&id).unwrap_or_default(),
                },
            });
    }
    Ok(pricing)
}

async fn load_intervals(
    state: &ControlApiState,
    pricing_ids: &[i64],
) -> Result<HashMap<i64, Vec<PricingInterval>>, ApiError> {
    if pricing_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows = sqlx::query(
        r"
SELECT
    pricing_id, min_tokens, max_tokens, COALESCE(tier_label, '') AS tier_label,
    input_price::text AS input_price,
    output_price::text AS output_price,
    cache_write_price::text AS cache_write_price,
    cache_read_price::text AS cache_read_price,
    per_request_price::text AS per_request_price
FROM channel_pricing_intervals
WHERE pricing_id = ANY($1)
ORDER BY pricing_id, sort_order, min_tokens, id
",
    )
    .bind(pricing_ids)
    .fetch_all(state.pool())
    .await?;
    let mut intervals = HashMap::<i64, Vec<PricingInterval>>::new();
    for row in rows {
        intervals
            .entry(row.try_get("pricing_id")?)
            .or_default()
            .push(PricingInterval {
                min_tokens: row.try_get("min_tokens")?,
                max_tokens: row.try_get("max_tokens")?,
                tier_label: row.try_get("tier_label")?,
                input_price: optional_decimal(row.try_get("input_price")?)?,
                output_price: optional_decimal(row.try_get("output_price")?)?,
                cache_write_price: optional_decimal(row.try_get("cache_write_price")?)?,
                cache_read_price: optional_decimal(row.try_get("cache_read_price")?)?,
                per_request_price: optional_decimal(row.try_get("per_request_price")?)?,
            });
    }
    Ok(intervals)
}

fn decode_mapping(value: Value) -> BTreeMap<String, BTreeMap<String, String>> {
    let Value::Object(root) = value else {
        return BTreeMap::new();
    };
    let nested = root.values().any(Value::is_object);
    if !nested {
        return BTreeMap::from([(
            "anthropic".to_owned(),
            root.into_iter()
                .filter_map(|(source, value)| {
                    value.as_str().map(|target| (source, target.to_owned()))
                })
                .collect(),
        )]);
    }
    root.into_iter()
        .filter_map(|(platform, value)| {
            let Value::Object(mapping) = value else {
                return None;
            };
            Some((
                platform,
                mapping
                    .into_iter()
                    .filter_map(|(source, value)| {
                        value.as_str().map(|target| (source, target.to_owned()))
                    })
                    .collect(),
            ))
        })
        .collect()
}

fn supported_models(
    mapping: &BTreeMap<String, BTreeMap<String, String>>,
    pricing: &[PricingEntry],
) -> Vec<SupportedModel> {
    let indexes = pricing_index(pricing);
    let mut seen = HashSet::<(String, String)>::new();
    let mut result = Vec::new();
    for (platform, mappings) in mapping {
        let index = indexes.get(platform);
        for (source, target) in mappings {
            if let Some(prefix) = source.strip_suffix('*') {
                if let Some(index) = index {
                    for name in &index.names {
                        if name.to_lowercase().starts_with(&prefix.to_lowercase()) {
                            let (display, price) = lookup_pricing(index, name);
                            push_supported(&mut result, &mut seen, platform, display, price);
                        }
                    }
                }
                continue;
            }
            let pricing_key = if target.is_empty() || target.ends_with('*') {
                source
            } else {
                target
            };
            let (_, price) = index.map_or((pricing_key.clone(), None), |value| {
                lookup_pricing(value, pricing_key)
            });
            let display =
                index.map_or_else(|| source.clone(), |value| lookup_pricing(value, source).0);
            push_supported(&mut result, &mut seen, platform, display, price);
        }
    }
    for (platform, index) in &indexes {
        for name in &index.names {
            let (display, price) = lookup_pricing(index, name);
            push_supported(&mut result, &mut seen, platform, display, price);
        }
    }
    result.sort_by(|left, right| {
        (&left.platform, left.name.to_lowercase())
            .cmp(&(&right.platform, right.name.to_lowercase()))
    });
    result
}

fn pricing_index(pricing: &[PricingEntry]) -> BTreeMap<String, PlatformPricingIndex> {
    let mut indexes = BTreeMap::<String, PlatformPricingIndex>::new();
    for entry in pricing {
        let index = indexes.entry(entry.platform.clone()).or_default();
        for model in &entry.models {
            if model.ends_with('*') {
                continue;
            }
            let lower = model.to_lowercase();
            if index.entries.contains_key(&lower) {
                continue;
            }
            index.names.push(model.clone());
            index
                .entries
                .insert(lower, (model.clone(), entry.view.clone()));
        }
    }
    indexes
}

fn lookup_pricing(index: &PlatformPricingIndex, name: &str) -> (String, Option<PricingView>) {
    index.entries.get(&name.to_lowercase()).map_or_else(
        || (name.to_owned(), None),
        |(display, pricing)| (display.clone(), Some(pricing.clone())),
    )
}

fn push_supported(
    result: &mut Vec<SupportedModel>,
    seen: &mut HashSet<(String, String)>,
    platform: &str,
    name: String,
    pricing: Option<PricingView>,
) {
    let key = (platform.to_owned(), name.to_lowercase());
    if !seen.insert(key) {
        return;
    }
    result.push(SupportedModel {
        pricing: pricing_with_fallback(&name, pricing),
        name,
        platform: platform.to_owned(),
    });
}

fn pricing_with_fallback(name: &str, pricing: Option<PricingView>) -> Option<PricingView> {
    if pricing
        .as_ref()
        .is_some_and(|value| !value.needs_fallback())
    {
        return pricing;
    }
    let global = match crate::billing::active_model_pricing(name) {
        Ok(Some(pricing)) => pricing,
        Ok(None) => return None,
        Err(error) => {
            tracing::warn!(%error, "active model pricing is unavailable");
            return None;
        }
    };
    Some(PricingView {
        billing_mode: pricing
            .as_ref()
            .map_or_else(|| "token".to_owned(), |value| value.billing_mode.clone()),
        input_price: global.input_cost_per_token.and_then(decimal_value),
        output_price: global.output_cost_per_token.and_then(decimal_value),
        cache_write_price: global
            .cache_creation_input_token_cost
            .and_then(decimal_value),
        cache_read_price: global.cache_read_input_token_cost.and_then(decimal_value),
        image_output_price: None,
        per_request_price: None,
        intervals: Vec::new(),
    })
}

fn decimal_value(value: crate::billing::Decimal) -> Option<f64> {
    value.to_string().parse().ok()
}

impl PricingView {
    fn needs_fallback(&self) -> bool {
        self.input_price.is_none()
            && self.output_price.is_none()
            && self.cache_write_price.is_none()
            && self.cache_read_price.is_none()
            && self.image_output_price.is_none()
            && self.per_request_price.is_none()
            && self.intervals.iter().all(|interval| {
                interval.input_price.is_none()
                    && interval.output_price.is_none()
                    && interval.cache_write_price.is_none()
                    && interval.cache_read_price.is_none()
                    && interval.per_request_price.is_none()
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_flat_mapping_is_normalized() {
        let mapping = decode_mapping(serde_json::json!({"claude-*": "claude-*"}));
        assert_eq!(mapping["anthropic"]["claude-*"], "claude-*");
    }

    #[test]
    fn mapping_and_pricing_models_are_unioned_without_wildcards() {
        let pricing = vec![PricingEntry {
            platform: "anthropic".to_owned(),
            models: vec!["claude-a".to_owned(), "claude-b".to_owned()],
            view: PricingView {
                billing_mode: "token".to_owned(),
                input_price: Some(1.0),
                output_price: None,
                cache_write_price: None,
                cache_read_price: None,
                image_output_price: None,
                per_request_price: None,
                intervals: Vec::new(),
            },
        }];
        let mapping = BTreeMap::from([(
            "anthropic".to_owned(),
            BTreeMap::from([("claude-*".to_owned(), "claude-*".to_owned())]),
        )]);
        let models = supported_models(&mapping, &pricing);
        assert_eq!(models.len(), 2);
        assert!(models.iter().all(|model| !model.name.contains('*')));
    }
}
