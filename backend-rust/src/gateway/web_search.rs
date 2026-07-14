use std::{collections::HashSet, fmt::Write as _, time::Duration};

use axum::{
    body::Body,
    http::{HeaderValue, StatusCode, header},
    response::Response as AxumResponse,
};
use chrono::{Datelike, TimeZone, Utc};
use futures_util::StreamExt;
use reqwest::{Client, Response as HttpResponse, redirect::Policy};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use sqlx::{PgPool, Row};
use url::Url;
use uuid::Uuid;

use crate::{
    repository::{AccountProxyRecord, AccountRecord, ChannelPolicyRecord},
    security::secrets,
};

use super::route::{GatewayRoute, Protocol, RouteKind};

const CONFIG_KEY: &str = "web_search_emulation_config";
const USAGE_KEY_PREFIX: &str = "web_search_usage:";
const USAGE_RESET_KEY_PREFIX: &str = "web_search_usage_reset_at:";
const FEATURE_KEY: &str = "web_search_emulation";
const TOOL_USE_ID_PREFIX: &str = "srvtoolu_ws_";
const DEFAULT_MAX_RESULTS: usize = 5;
const MAX_QUERY_CHARS: usize = 2_000;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(63);
const DEFAULT_USAGE_PERIOD_SECONDS: i64 = 31 * 24 * 60 * 60;
const BRAVE_ENDPOINT: &str = "https://api.search.brave.com/res/v1/web/search";
const TAVILY_ENDPOINT: &str = "https://api.tavily.com/search";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WebSearchFailureKind {
    InvalidRequest,
    AccountProxy,
    Unavailable,
}

#[derive(Debug)]
pub(super) struct WebSearchFailure {
    kind: WebSearchFailureKind,
    internal: String,
}

impl WebSearchFailure {
    #[must_use]
    pub(super) const fn kind(&self) -> WebSearchFailureKind {
        self.kind
    }

    #[must_use]
    pub(super) const fn public_message(&self) -> &'static str {
        match self.kind {
            WebSearchFailureKind::InvalidRequest => {
                "web search emulation requires a non-empty user query"
            }
            WebSearchFailureKind::AccountProxy => "account proxy is unavailable",
            WebSearchFailureKind::Unavailable => "web search emulation is temporarily unavailable",
        }
    }

    #[must_use]
    pub(super) fn internal_message(&self) -> &str {
        &self.internal
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self {
            kind: WebSearchFailureKind::InvalidRequest,
            internal: message.into(),
        }
    }

    fn account_proxy(message: impl Into<String>) -> Self {
        Self {
            kind: WebSearchFailureKind::AccountProxy,
            internal: message.into(),
        }
    }

    fn unavailable(message: impl Into<String>) -> Self {
        Self {
            kind: WebSearchFailureKind::Unavailable,
            internal: message.into(),
        }
    }
}

#[derive(Clone, Debug)]
struct SearchRequest {
    query: String,
    model: String,
    stream: bool,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct WebSearchConfig {
    enabled: bool,
    providers: Vec<ProviderConfig>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct ProviderConfig {
    #[serde(rename = "type")]
    provider_type: String,
    api_key: String,
    quota_limit: Option<i64>,
    subscribed_at: Option<i64>,
    proxy_id: Option<i64>,
    expires_at: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SearchResult {
    url: String,
    title: String,
    snippet: String,
    page_age: String,
}

#[derive(Debug)]
struct ProviderFailure {
    network: bool,
    message: String,
}

/// Intercepts a web-search-only request after account selection and before any
/// upstream request is built. Non-matching or disabled requests return `None`.
pub(super) async fn try_emulate(
    pool: &PgPool,
    route: &GatewayRoute,
    body: &[u8],
    account: &AccountRecord,
    channel: Option<&ChannelPolicyRecord>,
) -> Result<Option<AxumResponse>, WebSearchFailure> {
    let Some(request) = parse_search_request(route, body)? else {
        return Ok(None);
    };
    if !emulation_enabled(account, channel) {
        return Ok(None);
    }

    let config = load_config(pool).await?;
    if !config.enabled || config.providers.is_empty() {
        return Ok(None);
    }
    let results = execute_search(pool, account, &config, &request.query).await?;
    render_response(route, &request, &results).map(Some)
}

fn parse_search_request(
    route: &GatewayRoute,
    body: &[u8],
) -> Result<Option<SearchRequest>, WebSearchFailure> {
    if !matches!(
        route.kind,
        RouteKind::AnthropicMessages
            | RouteKind::OpenAiResponses
            | RouteKind::OpenAiChatCompletions
    ) {
        return Ok(None);
    }
    let root: Value = serde_json::from_slice(body)
        .map_err(|error| WebSearchFailure::invalid(format!("invalid request JSON: {error}")))?;
    let Some(tools) = root.get("tools").and_then(Value::as_array) else {
        return Ok(None);
    };
    if tools.len() != 1 || !is_web_search_tool(&tools[0]) {
        return Ok(None);
    }

    let query = match route.kind {
        RouteKind::OpenAiResponses => extract_responses_query(&root),
        RouteKind::AnthropicMessages | RouteKind::OpenAiChatCompletions => {
            extract_messages_query(&root)
        }
        _ => None,
    }
    .map(|query| {
        query
            .trim()
            .chars()
            .take(MAX_QUERY_CHARS)
            .collect::<String>()
    })
    .filter(|query| !query.is_empty())
    .ok_or_else(|| WebSearchFailure::invalid("web search request has no user query"))?;
    let model = root
        .get("model")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|model| !model.is_empty())
        .unwrap_or(match route.protocol {
            Protocol::Anthropic => "claude-sonnet-4-6",
            Protocol::OpenAi | Protocol::Gemini => "gpt-4o-mini",
        })
        .to_owned();
    let stream = root.get("stream").and_then(Value::as_bool).unwrap_or(false);
    Ok(Some(SearchRequest {
        query,
        model,
        stream,
    }))
}

fn is_web_search_tool(tool: &Value) -> bool {
    let Some(object) = tool.as_object() else {
        return false;
    };
    [
        object.get("type").and_then(Value::as_str),
        object.get("name").and_then(Value::as_str),
        object
            .get("function")
            .and_then(Value::as_object)
            .and_then(|function| function.get("name"))
            .and_then(Value::as_str),
    ]
    .into_iter()
    .flatten()
    .any(is_web_search_name)
}

fn is_web_search_name(value: &str) -> bool {
    let value = value.trim().to_ascii_lowercase();
    value.starts_with("web_search") || value == "google_search"
}

fn extract_messages_query(root: &Value) -> Option<String> {
    let message = root
        .get("messages")?
        .as_array()?
        .iter()
        .rev()
        .find(|message| message.get("role").and_then(Value::as_str) == Some("user"))?;
    extract_content_text(message.get("content")?)
}

fn extract_responses_query(root: &Value) -> Option<String> {
    let input = root.get("input")?;
    if let Some(input) = input.as_str() {
        return Some(input.to_owned());
    }
    let item = input.as_array()?.iter().rev().find(|item| {
        item.get("role").and_then(Value::as_str) == Some("user")
            || item.get("type").and_then(Value::as_str) == Some("message")
    })?;
    extract_content_text(item.get("content").unwrap_or(item))
}

fn extract_content_text(content: &Value) -> Option<String> {
    if let Some(text) = content.as_str() {
        return Some(text.to_owned());
    }
    content.as_array()?.iter().find_map(|block| {
        let block_type = block
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        matches!(block_type, "text" | "input_text")
            .then(|| block.get("text").and_then(Value::as_str).map(str::to_owned))
            .flatten()
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AccountMode {
    Default,
    Enabled,
    Disabled,
}

fn emulation_enabled(account: &AccountRecord, channel: Option<&ChannelPolicyRecord>) -> bool {
    match account_mode(account) {
        AccountMode::Enabled => true,
        AccountMode::Disabled => false,
        AccountMode::Default => {
            channel.is_some_and(|channel| channel_web_search_enabled(channel, &account.platform))
        }
    }
}

fn account_mode(account: &AccountRecord) -> AccountMode {
    if !account.platform.eq_ignore_ascii_case("anthropic")
        || !account.account_type.eq_ignore_ascii_case("apikey")
    {
        return AccountMode::Default;
    }
    match account.extra.get(FEATURE_KEY) {
        Some(Value::Bool(true)) => AccountMode::Enabled,
        Some(Value::String(mode)) if mode.eq_ignore_ascii_case("enabled") => AccountMode::Enabled,
        Some(Value::String(mode)) if mode.eq_ignore_ascii_case("disabled") => AccountMode::Disabled,
        _ => AccountMode::Default,
    }
}

fn channel_web_search_enabled(channel: &ChannelPolicyRecord, platform: &str) -> bool {
    if let Some(enabled) = explicit_channel_feature(&channel.features_config, platform) {
        return enabled;
    }
    legacy_channel_feature_enabled(&channel.features, platform)
}

fn explicit_channel_feature(config: &Value, platform: &str) -> Option<bool> {
    let feature = object_value_case_insensitive(config.as_object()?, FEATURE_KEY)?;
    if let Some(enabled) = feature.as_bool() {
        return Some(enabled);
    }
    object_value_case_insensitive(feature.as_object()?, platform)?.as_bool()
}

fn legacy_channel_feature_enabled(features: &str, platform: &str) -> bool {
    let raw = features.trim();
    if raw.is_empty() {
        return false;
    }
    if let Ok(value) = serde_json::from_str::<Value>(raw) {
        return match value {
            Value::Array(items) => items.iter().any(|item| {
                item.as_str().is_some_and(|feature| {
                    feature.eq_ignore_ascii_case(FEATURE_KEY)
                        || feature.eq_ignore_ascii_case("web_search")
                })
            }),
            Value::Object(object) => object_value_case_insensitive(&object, FEATURE_KEY)
                .and_then(|feature| {
                    feature.as_bool().or_else(|| {
                        feature.as_object().and_then(|platforms| {
                            object_value_case_insensitive(platforms, platform)
                                .and_then(Value::as_bool)
                        })
                    })
                })
                .unwrap_or(false),
            _ => false,
        };
    }
    raw.split(',')
        .map(str::trim)
        .any(|feature| feature.eq_ignore_ascii_case(FEATURE_KEY))
}

fn object_value_case_insensitive<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Option<&'a Value> {
    object
        .iter()
        .find_map(|(candidate, value)| candidate.eq_ignore_ascii_case(key).then_some(value))
}

async fn load_config(pool: &PgPool) -> Result<WebSearchConfig, WebSearchFailure> {
    let raw = sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key = $1")
        .bind(CONFIG_KEY)
        .fetch_optional(pool)
        .await
        .map_err(|error| WebSearchFailure::unavailable(format!("load config: {error}")))?;
    let Some(raw) = raw.filter(|raw| !raw.trim().is_empty()) else {
        return Ok(WebSearchConfig::default());
    };
    let mut config = serde_json::from_str::<WebSearchConfig>(&raw)
        .map_err(|error| WebSearchFailure::unavailable(format!("decode config: {error}")))?;
    if config.providers.len() > 10 {
        return Err(WebSearchFailure::unavailable(
            "web search config has too many providers",
        ));
    }
    let mut seen = HashSet::with_capacity(config.providers.len());
    for provider in &mut config.providers {
        provider.provider_type = provider.provider_type.trim().to_ascii_lowercase();
        if !matches!(provider.provider_type.as_str(), "brave" | "tavily")
            || !seen.insert(provider.provider_type.clone())
            || provider.quota_limit.is_some_and(|limit| limit < 0)
            || provider.proxy_id.is_some_and(|id| id <= 0)
        {
            return Err(WebSearchFailure::unavailable(
                "web search provider config is invalid",
            ));
        }
    }
    Ok(config)
}

async fn execute_search(
    pool: &PgPool,
    account: &AccountRecord,
    config: &WebSearchConfig,
    query: &str,
) -> Result<Vec<SearchResult>, WebSearchFailure> {
    let now = Utc::now().timestamp();
    let account_proxy = if account.proxy_id.is_some() {
        Some(account_proxy_url(account).map_err(WebSearchFailure::account_proxy)?)
    } else {
        None
    };
    let mut attempted = false;
    let mut last_error = None;

    for provider in &config.providers {
        if provider.api_key.trim().is_empty()
            || provider
                .expires_at
                .is_some_and(|expires_at| expires_at <= now)
        {
            continue;
        }
        attempted = true;
        if !reserve_usage(pool, provider, now).await? {
            continue;
        }
        let api_key = match secrets::decrypt_config_secret(&provider.api_key) {
            Ok(api_key) if !api_key.trim().is_empty() => api_key,
            Ok(_) => {
                rollback_usage(pool, &provider.provider_type).await;
                last_error = Some("provider API key is empty".to_owned());
                continue;
            }
            Err(error) => {
                rollback_usage(pool, &provider.provider_type).await;
                last_error = Some(format!("decrypt provider API key: {error}"));
                continue;
            }
        };
        let proxy_url = if let Some(proxy_url) = account_proxy.as_deref() {
            Some(proxy_url.to_owned())
        } else if let Some(proxy_id) = provider.proxy_id {
            match load_provider_proxy(pool, proxy_id).await {
                Ok(proxy_url) => Some(proxy_url),
                Err(error) => {
                    rollback_usage(pool, &provider.provider_type).await;
                    last_error = Some(error.internal);
                    continue;
                }
            }
        } else {
            None
        };
        let client = match web_search_client(proxy_url.as_deref()) {
            Ok(client) => client,
            Err(error) => {
                rollback_usage(pool, &provider.provider_type).await;
                if account_proxy.is_some() {
                    return Err(WebSearchFailure::account_proxy(error));
                }
                last_error = Some(error);
                continue;
            }
        };
        let result = match provider.provider_type.as_str() {
            "brave" => search_brave(&client, &api_key, query).await,
            "tavily" => search_tavily(&client, &api_key, query).await,
            _ => unreachable!("provider types are validated while loading config"),
        };
        match result {
            Ok(results) => return Ok(results),
            Err(error) => {
                rollback_usage(pool, &provider.provider_type).await;
                if account_proxy.is_some() && error.network {
                    return Err(WebSearchFailure::account_proxy(error.message));
                }
                last_error = Some(error.message);
            }
        }
    }

    Err(WebSearchFailure::unavailable(if attempted {
        last_error.unwrap_or_else(|| "all provider quotas are exhausted".to_owned())
    } else {
        "no usable provider is configured".to_owned()
    }))
}

async fn reserve_usage(
    pool: &PgPool,
    provider: &ProviderConfig,
    now: i64,
) -> Result<bool, WebSearchFailure> {
    let usage_key = format!("{USAGE_KEY_PREFIX}{}", provider.provider_type);
    let reset_key = format!("{USAGE_RESET_KEY_PREFIX}{}", provider.provider_type);
    let default_reset = next_reset_at(provider.subscribed_at, now);
    let mut transaction = pool
        .begin()
        .await
        .map_err(|error| WebSearchFailure::unavailable(format!("begin usage update: {error}")))?;
    for (key, value) in [
        (usage_key.as_str(), "0".to_owned()),
        (reset_key.as_str(), default_reset.to_string()),
    ] {
        sqlx::query(
            "INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, NOW()) ON CONFLICT (key) DO NOTHING",
        )
        .bind(key)
        .bind(value)
        .execute(&mut *transaction)
        .await
        .map_err(|error| WebSearchFailure::unavailable(format!("initialize usage: {error}")))?;
    }
    let rows =
        sqlx::query("SELECT key, value FROM settings WHERE key = ANY($1) ORDER BY key FOR UPDATE")
            .bind(vec![usage_key.clone(), reset_key.clone()])
            .fetch_all(&mut *transaction)
            .await
            .map_err(|error| WebSearchFailure::unavailable(format!("lock usage: {error}")))?;
    let mut used = None;
    let mut reset_at = None;
    for row in rows {
        let key: String = row
            .try_get("key")
            .map_err(|error| WebSearchFailure::unavailable(format!("read usage key: {error}")))?;
        let value: String = row
            .try_get("value")
            .map_err(|error| WebSearchFailure::unavailable(format!("read usage value: {error}")))?;
        if key == usage_key {
            used = value.parse::<i64>().ok();
        } else if key == reset_key {
            reset_at = value.parse::<i64>().ok();
        }
    }
    let mut used = used
        .filter(|used| *used >= 0)
        .ok_or_else(|| WebSearchFailure::unavailable("stored provider usage is invalid"))?;
    let mut reset_at = reset_at.unwrap_or_default();
    if reset_at <= now {
        used = 0;
        reset_at = next_reset_at(provider.subscribed_at, now);
    }
    if provider
        .quota_limit
        .is_some_and(|limit| limit > 0 && used >= limit)
    {
        transaction
            .commit()
            .await
            .map_err(|error| WebSearchFailure::unavailable(format!("commit usage: {error}")))?;
        return Ok(false);
    }
    sqlx::query("UPDATE settings SET value = $2, updated_at = NOW() WHERE key = $1")
        .bind(&usage_key)
        .bind(used.saturating_add(1).to_string())
        .execute(&mut *transaction)
        .await
        .map_err(|error| WebSearchFailure::unavailable(format!("increment usage: {error}")))?;
    sqlx::query("UPDATE settings SET value = $2, updated_at = NOW() WHERE key = $1")
        .bind(&reset_key)
        .bind(reset_at.to_string())
        .execute(&mut *transaction)
        .await
        .map_err(|error| WebSearchFailure::unavailable(format!("update usage reset: {error}")))?;
    transaction
        .commit()
        .await
        .map_err(|error| WebSearchFailure::unavailable(format!("commit usage: {error}")))?;
    Ok(true)
}

async fn rollback_usage(pool: &PgPool, provider_type: &str) {
    let key = format!("{USAGE_KEY_PREFIX}{provider_type}");
    if let Err(error) = sqlx::query(
        "UPDATE settings SET value = GREATEST(COALESCE(NULLIF(value, '')::bigint, 0) - 1, 0)::text, updated_at = NOW() WHERE key = $1",
    )
    .bind(key)
    .execute(pool)
    .await
    {
        tracing::warn!(provider = provider_type, error = %error, "rollback web search provider usage");
    }
}

fn next_reset_at(subscribed_at: Option<i64>, now: i64) -> i64 {
    let Some(subscribed_at) = subscribed_at.filter(|timestamp| *timestamp > 0) else {
        return now.saturating_add(DEFAULT_USAGE_PERIOD_SECONDS);
    };
    let Some(base) = Utc.timestamp_opt(subscribed_at, 0).single() else {
        return now.saturating_add(DEFAULT_USAGE_PERIOD_SECONDS);
    };
    let Some(now_at) = Utc.timestamp_opt(now, 0).single() else {
        return now.saturating_add(DEFAULT_USAGE_PERIOD_SECONDS);
    };
    let month_delta = (now_at.year() - base.year()) * 12
        + i32::try_from(now_at.month()).unwrap_or_default()
        - i32::try_from(base.month()).unwrap_or_default();
    let month_delta = month_delta.max(0);
    let candidate = add_months_clamped(base.timestamp(), month_delta);
    if candidate > now {
        candidate
    } else {
        add_months_clamped(base.timestamp(), month_delta.saturating_add(1))
    }
}

fn add_months_clamped(timestamp: i64, months: i32) -> i64 {
    let Some(base) = Utc.timestamp_opt(timestamp, 0).single() else {
        return timestamp;
    };
    let total_month = base
        .year()
        .saturating_mul(12)
        .saturating_add(i32::try_from(base.month0()).unwrap_or_default())
        .saturating_add(months);
    let year = total_month.div_euclid(12);
    let month = u32::try_from(total_month.rem_euclid(12) + 1).unwrap_or(1);
    let mut day = base.day();
    while day > 1
        && Utc
            .with_ymd_and_hms(year, month, day, 0, 0, 0)
            .single()
            .is_none()
    {
        day -= 1;
    }
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0)
        .single()
        .map_or(timestamp, |value| value.timestamp())
}

fn account_proxy_url(account: &AccountRecord) -> Result<String, String> {
    let proxy = account
        .proxy
        .as_ref()
        .ok_or_else(|| "account proxy record is missing".to_owned())?;
    proxy_record_url(proxy)
}

async fn load_provider_proxy(pool: &PgPool, proxy_id: i64) -> Result<String, WebSearchFailure> {
    let row = sqlx::query(
        "SELECT protocol, host, port, username, password FROM proxies WHERE id = $1 AND deleted_at IS NULL AND status = 'active' AND (expires_at IS NULL OR expires_at > NOW())",
    )
    .bind(proxy_id)
    .fetch_optional(pool)
    .await
    .map_err(|error| WebSearchFailure::unavailable(format!("load provider proxy: {error}")))?
    .ok_or_else(|| WebSearchFailure::unavailable("provider proxy is unavailable"))?;
    let proxy = AccountProxyRecord {
        id: proxy_id,
        protocol: row.try_get("protocol").map_err(|error| {
            WebSearchFailure::unavailable(format!("read proxy protocol: {error}"))
        })?,
        host: row
            .try_get("host")
            .map_err(|error| WebSearchFailure::unavailable(format!("read proxy host: {error}")))?,
        port: row
            .try_get("port")
            .map_err(|error| WebSearchFailure::unavailable(format!("read proxy port: {error}")))?,
        username: row.try_get("username").map_err(|error| {
            WebSearchFailure::unavailable(format!("read proxy username: {error}"))
        })?,
        password: row.try_get("password").map_err(|error| {
            WebSearchFailure::unavailable(format!("read proxy password: {error}"))
        })?,
        status: "active".to_owned(),
        expires_at_unix_ms: None,
    };
    proxy_record_url(&proxy).map_err(WebSearchFailure::unavailable)
}

fn proxy_record_url(proxy: &AccountProxyRecord) -> Result<String, String> {
    let protocol = proxy.protocol.trim().to_ascii_lowercase();
    if !matches!(protocol.as_str(), "http" | "https" | "socks5" | "socks5h") {
        return Err("proxy protocol is invalid".to_owned());
    }
    let port = u16::try_from(proxy.port).map_err(|_| "proxy port is invalid".to_owned())?;
    if port == 0 || proxy.host.trim().is_empty() {
        return Err("proxy address is invalid".to_owned());
    }
    let host = if proxy.host.contains(':') && !proxy.host.starts_with('[') {
        format!("[{}]", proxy.host.trim())
    } else {
        proxy.host.trim().to_owned()
    };
    let mut url = Url::parse(&format!("{protocol}://{host}:{port}"))
        .map_err(|_| "proxy URL is invalid".to_owned())?;
    if let Some(username) = proxy.username.as_deref().filter(|value| !value.is_empty()) {
        url.set_username(username)
            .map_err(|()| "proxy username is invalid".to_owned())?;
        url.set_password(proxy.password.as_deref())
            .map_err(|()| "proxy password is invalid".to_owned())?;
    }
    Ok(url.into())
}

fn web_search_client(proxy_url: Option<&str>) -> Result<Client, String> {
    let mut builder = Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .user_agent("sub2api-rust-web-search/1");
    if let Some(proxy_url) = proxy_url {
        let proxy = reqwest::Proxy::all(proxy_url)
            .map_err(|error| format!("configure web search proxy: {error}"))?;
        builder = builder.proxy(proxy);
    }
    builder
        .build()
        .map_err(|error| format!("build web search client: {error}"))
}

async fn search_brave(
    client: &Client,
    api_key: &str,
    query: &str,
) -> Result<Vec<SearchResult>, ProviderFailure> {
    search_brave_at(client, api_key, query, BRAVE_ENDPOINT).await
}

async fn search_brave_at(
    client: &Client,
    api_key: &str,
    query: &str,
    endpoint: &str,
) -> Result<Vec<SearchResult>, ProviderFailure> {
    let mut endpoint = Url::parse(endpoint).map_err(|error| ProviderFailure {
        network: false,
        message: format!("invalid Brave endpoint: {error}"),
    })?;
    endpoint
        .query_pairs_mut()
        .append_pair("q", query)
        .append_pair("count", &DEFAULT_MAX_RESULTS.to_string());
    let response = client
        .get(endpoint)
        .header("X-Subscription-Token", api_key)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(provider_request_failure)?;
    let body = bounded_response(response, "brave").await?;
    let response: BraveResponse =
        serde_json::from_slice(&body).map_err(|error| ProviderFailure {
            network: false,
            message: format!("decode Brave response: {error}"),
        })?;
    Ok(response
        .web
        .results
        .into_iter()
        .take(DEFAULT_MAX_RESULTS)
        .map(|result| SearchResult {
            url: result.url,
            title: result.title,
            snippet: result.description,
            page_age: result.age,
        })
        .collect())
}

async fn search_tavily(
    client: &Client,
    api_key: &str,
    query: &str,
) -> Result<Vec<SearchResult>, ProviderFailure> {
    search_tavily_at(client, api_key, query, TAVILY_ENDPOINT).await
}

async fn search_tavily_at(
    client: &Client,
    api_key: &str,
    query: &str,
    endpoint: &str,
) -> Result<Vec<SearchResult>, ProviderFailure> {
    let response = client
        .post(endpoint)
        .json(&json!({
            "api_key": api_key,
            "query": query,
            "max_results": DEFAULT_MAX_RESULTS,
            "search_depth": "basic",
        }))
        .send()
        .await
        .map_err(provider_request_failure)?;
    let body = bounded_response(response, "tavily").await?;
    let response: TavilyResponse =
        serde_json::from_slice(&body).map_err(|error| ProviderFailure {
            network: false,
            message: format!("decode Tavily response: {error}"),
        })?;
    Ok(response
        .results
        .into_iter()
        .take(DEFAULT_MAX_RESULTS)
        .map(|result| SearchResult {
            url: result.url,
            title: result.title,
            snippet: result.content,
            page_age: String::new(),
        })
        .collect())
}

#[allow(clippy::needless_pass_by_value)]
fn provider_request_failure(error: reqwest::Error) -> ProviderFailure {
    ProviderFailure {
        network: error.is_connect()
            || error.is_timeout()
            || error.to_string().to_ascii_lowercase().contains("proxy"),
        message: error.to_string(),
    }
}

async fn bounded_response(
    response: HttpResponse,
    provider: &str,
) -> Result<Vec<u8>, ProviderFailure> {
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(ProviderFailure {
            network: false,
            message: format!("{provider} response exceeds the configured limit"),
        });
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(provider_request_failure)?;
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(ProviderFailure {
                network: false,
                message: format!("{provider} response exceeds the configured limit"),
            });
        }
        body.extend_from_slice(&chunk);
    }
    if !status.is_success() {
        let detail = String::from_utf8_lossy(&body)
            .chars()
            .take(200)
            .collect::<String>();
        return Err(ProviderFailure {
            network: false,
            message: format!("{provider} returned HTTP {}: {detail}", status.as_u16()),
        });
    }
    Ok(body)
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct BraveResponse {
    web: BraveWeb,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct BraveWeb {
    results: Vec<BraveResult>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct BraveResult {
    url: String,
    title: String,
    description: String,
    age: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct TavilyResponse {
    results: Vec<TavilyResult>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct TavilyResult {
    url: String,
    title: String,
    content: String,
}

fn render_response(
    route: &GatewayRoute,
    request: &SearchRequest,
    results: &[SearchResult],
) -> Result<AxumResponse, WebSearchFailure> {
    let body = match (route.kind, request.stream) {
        (RouteKind::AnthropicMessages, false) => anthropic_response(request, results),
        (RouteKind::AnthropicMessages, true) => anthropic_sse(request, results),
        (RouteKind::OpenAiResponses, false) => openai_responses_response(request, results),
        (RouteKind::OpenAiResponses, true) => openai_responses_sse(request, results),
        (RouteKind::OpenAiChatCompletions, false) => openai_chat_response(request, results),
        (RouteKind::OpenAiChatCompletions, true) => openai_chat_sse(request, results),
        _ => return Err(WebSearchFailure::invalid("unsupported web search route")),
    };
    let content_type = if request.stream {
        "text/event-stream"
    } else {
        "application/json"
    };
    let mut response = AxumResponse::new(Body::from(body));
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    if request.stream {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        response
            .headers_mut()
            .insert("x-accel-buffering", HeaderValue::from_static("no"));
    }
    Ok(response)
}

fn anthropic_response(request: &SearchRequest, results: &[SearchResult]) -> Vec<u8> {
    let tool_use_id = tool_use_id();
    let summary = build_summary(&request.query, results);
    serde_json::to_vec(&json!({
        "id": format!("msg_ws_{}", Uuid::new_v4()),
        "type": "message",
        "role": "assistant",
        "model": request.model,
        "content": [
            {"type":"server_tool_use","id":tool_use_id,"name":"web_search","input":{"query":request.query}},
            {"type":"web_search_tool_result","tool_use_id":tool_use_id,"content":anthropic_result_blocks(results)},
            {"type":"text","text":summary},
        ],
        "stop_reason": "end_turn",
        "stop_sequence": null,
        "usage": {"input_tokens":0,"output_tokens":estimate_tokens(&summary)},
    }))
    .expect("web search response JSON is serializable")
}

fn anthropic_sse(request: &SearchRequest, results: &[SearchResult]) -> Vec<u8> {
    let message_id = format!("msg_ws_{}", Uuid::new_v4());
    let tool_use_id = tool_use_id();
    let summary = build_summary(&request.query, results);
    let mut events = String::new();
    push_sse_event(
        &mut events,
        "message_start",
        &json!({
            "type":"message_start","message":{"id":message_id,"type":"message","role":"assistant","model":request.model,"content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":0,"output_tokens":0}}
        }),
    );
    push_anthropic_block(
        &mut events,
        0,
        &json!({
            "type":"server_tool_use","id":tool_use_id,"name":"web_search","input":{"query":request.query}
        }),
    );
    push_anthropic_block(
        &mut events,
        1,
        &json!({
            "type":"web_search_tool_result","tool_use_id":tool_use_id,"content":anthropic_result_blocks(results)
        }),
    );
    push_sse_event(
        &mut events,
        "content_block_start",
        &json!({
            "type":"content_block_start","index":2,"content_block":{"type":"text","text":""}
        }),
    );
    push_sse_event(
        &mut events,
        "content_block_delta",
        &json!({
            "type":"content_block_delta","index":2,"delta":{"type":"text_delta","text":summary}
        }),
    );
    push_sse_event(
        &mut events,
        "content_block_stop",
        &json!({"type":"content_block_stop","index":2}),
    );
    push_sse_event(
        &mut events,
        "message_delta",
        &json!({
            "type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":estimate_tokens(&summary)}
        }),
    );
    push_sse_event(&mut events, "message_stop", &json!({"type":"message_stop"}));
    events.into_bytes()
}

fn push_anthropic_block(events: &mut String, index: usize, block: &Value) {
    push_sse_event(
        events,
        "content_block_start",
        &json!({
            "type":"content_block_start","index":index,"content_block":block
        }),
    );
    push_sse_event(
        events,
        "content_block_stop",
        &json!({
            "type":"content_block_stop","index":index
        }),
    );
}

fn openai_responses_response(request: &SearchRequest, results: &[SearchResult]) -> Vec<u8> {
    serde_json::to_vec(&openai_response_value(request, results, "completed"))
        .expect("web search response JSON is serializable")
}

fn openai_response_value(request: &SearchRequest, results: &[SearchResult], status: &str) -> Value {
    let summary = build_summary(&request.query, results);
    let response_id = format!("resp_ws_{}", Uuid::new_v4());
    let call_id = format!("ws_{}", Uuid::new_v4().simple());
    let message_id = format!("msg_{}", Uuid::new_v4().simple());
    json!({
        "id":response_id,
        "object":"response",
        "created_at":Utc::now().timestamp(),
        "status":status,
        "error":null,
        "model":request.model,
        "output":[
            {"id":call_id,"type":"web_search_call","status":"completed","action":{"type":"search","query":request.query,"sources":results.iter().map(|result| json!({"type":"url","url":result.url})).collect::<Vec<_>>() }},
            {"id":message_id,"type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":summary,"annotations":url_citations(&summary, results)}]},
        ],
        "parallel_tool_calls":false,
        "usage":{"input_tokens":0,"output_tokens":estimate_tokens(&summary),"total_tokens":estimate_tokens(&summary)},
    })
}

fn openai_responses_sse(request: &SearchRequest, results: &[SearchResult]) -> Vec<u8> {
    let completed = openai_response_value(request, results, "completed");
    let mut created = completed.clone();
    created["status"] = Value::String("in_progress".to_owned());
    created["output"] = Value::Array(Vec::new());
    let call = completed["output"][0].clone();
    let message = completed["output"][1].clone();
    let part = message["content"][0].clone();
    let text = part["text"].clone();
    let mut events = String::new();
    push_sse_event(
        &mut events,
        "response.created",
        &json!({"type":"response.created","sequence_number":0,"response":created}),
    );
    push_sse_event(
        &mut events,
        "response.output_item.added",
        &json!({"type":"response.output_item.added","sequence_number":1,"output_index":0,"item":call}),
    );
    push_sse_event(
        &mut events,
        "response.output_item.done",
        &json!({"type":"response.output_item.done","sequence_number":2,"output_index":0,"item":call}),
    );
    let mut empty_message = message.clone();
    empty_message["content"] = Value::Array(Vec::new());
    push_sse_event(
        &mut events,
        "response.output_item.added",
        &json!({"type":"response.output_item.added","sequence_number":3,"output_index":1,"item":empty_message}),
    );
    let mut empty_part = part.clone();
    empty_part["text"] = Value::String(String::new());
    push_sse_event(
        &mut events,
        "response.content_part.added",
        &json!({"type":"response.content_part.added","sequence_number":4,"output_index":1,"content_index":0,"part":empty_part}),
    );
    push_sse_event(
        &mut events,
        "response.output_text.delta",
        &json!({"type":"response.output_text.delta","sequence_number":5,"output_index":1,"content_index":0,"delta":text}),
    );
    push_sse_event(
        &mut events,
        "response.output_text.done",
        &json!({"type":"response.output_text.done","sequence_number":6,"output_index":1,"content_index":0,"text":text}),
    );
    push_sse_event(
        &mut events,
        "response.content_part.done",
        &json!({"type":"response.content_part.done","sequence_number":7,"output_index":1,"content_index":0,"part":part}),
    );
    push_sse_event(
        &mut events,
        "response.output_item.done",
        &json!({"type":"response.output_item.done","sequence_number":8,"output_index":1,"item":message}),
    );
    push_sse_event(
        &mut events,
        "response.completed",
        &json!({"type":"response.completed","sequence_number":9,"response":completed}),
    );
    events.into_bytes()
}

fn openai_chat_response(request: &SearchRequest, results: &[SearchResult]) -> Vec<u8> {
    let summary = build_summary(&request.query, results);
    serde_json::to_vec(&json!({
        "id":format!("chatcmpl-ws-{}",Uuid::new_v4().simple()),
        "object":"chat.completion",
        "created":Utc::now().timestamp(),
        "model":request.model,
        "choices":[{"index":0,"message":{"role":"assistant","content":summary,"annotations":url_citations(&summary,results)},"finish_reason":"stop"}],
        "usage":{"prompt_tokens":0,"completion_tokens":estimate_tokens(&summary),"total_tokens":estimate_tokens(&summary)},
    }))
    .expect("web search response JSON is serializable")
}

fn openai_chat_sse(request: &SearchRequest, results: &[SearchResult]) -> Vec<u8> {
    let id = format!("chatcmpl-ws-{}", Uuid::new_v4().simple());
    let created = Utc::now().timestamp();
    let summary = build_summary(&request.query, results);
    let chunks = [
        json!({"id":id,"object":"chat.completion.chunk","created":created,"model":request.model,"choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}),
        json!({"id":id,"object":"chat.completion.chunk","created":created,"model":request.model,"choices":[{"index":0,"delta":{"content":summary},"finish_reason":null}]}),
        json!({"id":id,"object":"chat.completion.chunk","created":created,"model":request.model,"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}),
    ];
    let mut body = String::new();
    for chunk in chunks {
        body.push_str("data: ");
        body.push_str(&chunk.to_string());
        body.push_str("\n\n");
    }
    body.push_str("data: [DONE]\n\n");
    body.into_bytes()
}

fn push_sse_event(events: &mut String, name: &str, value: &Value) {
    events.push_str("event: ");
    events.push_str(name);
    events.push_str("\ndata: ");
    events.push_str(&value.to_string());
    events.push_str("\n\n");
}

fn anthropic_result_blocks(results: &[SearchResult]) -> Vec<Value> {
    results
        .iter()
        .map(|result| {
            let mut block = json!({
                "type":"web_search_result",
                "url":result.url,
                "title":result.title,
            });
            if !result.snippet.is_empty() {
                block["page_content"] = Value::String(result.snippet.clone());
            }
            if !result.page_age.is_empty() {
                block["page_age"] = Value::String(result.page_age.clone());
            }
            block
        })
        .collect()
}

fn build_summary(query: &str, results: &[SearchResult]) -> String {
    if results.is_empty() {
        return format!("No search results found for: {query}");
    }
    let mut summary = format!("Here are the search results for \"{query}\":\n\n");
    for (index, result) in results.iter().enumerate() {
        write!(
            summary,
            "{}. **{}**\n   {}\n   {}\n\n",
            index + 1,
            result.title,
            result.url,
            result.snippet
        )
        .expect("writing to a String cannot fail");
    }
    summary
}

fn url_citations(summary: &str, results: &[SearchResult]) -> Vec<Value> {
    results
        .iter()
        .filter_map(|result| {
            let start = summary.find(&result.url)?;
            let start_index = summary[..start].chars().count();
            Some(json!({
                "type":"url_citation",
                "url":result.url,
                "title":result.title,
                "start_index":start_index,
                "end_index":start_index + result.url.chars().count(),
            }))
        })
        .collect()
}

fn estimate_tokens(text: &str) -> usize {
    text.chars().count().div_ceil(4)
}

fn tool_use_id() -> String {
    format!(
        "{TOOL_USE_ID_PREFIX}{}",
        &Uuid::new_v4().simple().to_string()[..16]
    )
}

/// Removes locally synthesized web-search blocks from replayed Anthropic
/// history. Cross-protocol upstreams additionally reject all server blocks.
pub(super) fn filter_history_blocks(body: &[u8], strip_all: bool) -> Option<Vec<u8>> {
    if !body
        .windows("server_tool_use".len())
        .any(|window| window == b"server_tool_use")
        && !body
            .windows("web_search_tool_result".len())
            .any(|window| window == b"web_search_tool_result")
    {
        return None;
    }
    let mut root: Value = serde_json::from_slice(body).ok()?;
    let messages = root.get_mut("messages")?.as_array_mut()?;
    let mut modified = false;
    for message in messages {
        let role = message
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let Some(content) = message.get_mut("content").and_then(Value::as_array_mut) else {
            continue;
        };
        let old_len = content.len();
        content.retain(|block| !strip_history_block(block, strip_all));
        if content.len() == old_len {
            continue;
        }
        modified = true;
        if content.is_empty() {
            content.push(json!({
                "type":"text",
                "text":if role == "assistant" { "(assistant content removed)" } else { "(content removed)" }
            }));
        }
    }
    modified.then(|| serde_json::to_vec(&root).ok()).flatten()
}

fn strip_history_block(block: &Value, strip_all: bool) -> bool {
    match block.get("type").and_then(Value::as_str) {
        Some("server_tool_use") => {
            strip_all
                || block
                    .get("id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| id.starts_with(TOOL_USE_ID_PREFIX))
        }
        Some("web_search_tool_result") => {
            strip_all
                || block
                    .get("tool_use_id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| id.starts_with(TOOL_USE_ID_PREFIX))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use axum::http::Method;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
    };

    use super::*;

    fn route(kind: RouteKind, protocol: Protocol) -> GatewayRoute {
        GatewayRoute {
            protocol,
            kind,
            method: Method::POST,
            upstream_path: "/v1/test".to_owned(),
            model_from_path: None,
        }
    }

    fn account(extra: Value) -> AccountRecord {
        AccountRecord {
            id: 1,
            name: "search".to_owned(),
            notes: None,
            platform: "anthropic".to_owned(),
            account_type: "apikey".to_owned(),
            credentials: json!({}),
            extra,
            proxy_id: None,
            proxy: None,
            proxy_fallback_origin_id: None,
            concurrency: 1,
            load_factor: None,
            priority: 1,
            rate_multiplier: "1".to_owned(),
            status: "active".to_owned(),
            error_message: None,
            expires_at_unix_ms: None,
            auto_pause_on_expired: false,
            schedulable: true,
            rate_limit_reset_at_unix_ms: None,
            overload_until_unix_ms: None,
            temp_unschedulable_until_unix_ms: None,
            temp_unschedulable_reason: None,
            parent_account_id: None,
            quota_dimension: String::new(),
            group_ids: vec![1],
        }
    }

    fn channel(features: &str, features_config: Value) -> ChannelPolicyRecord {
        ChannelPolicyRecord {
            id: 1,
            features: features.to_owned(),
            features_config,
            model_mapping: std::collections::BTreeMap::default(),
            billing_model_source: "channel_mapped".to_owned(),
            restrict_models: false,
            allowed_models: Vec::new(),
            model_pricing: Vec::new(),
        }
    }

    fn results() -> Vec<SearchResult> {
        vec![SearchResult {
            url: "https://example.test/result".to_owned(),
            title: "Result".to_owned(),
            snippet: "Summary".to_owned(),
            page_age: "2 days".to_owned(),
        }]
    }

    async fn serve_once(response: Vec<u8>) -> (String, JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut expected_length = None;
            loop {
                let mut buffer = [0_u8; 4_096];
                let read = socket.read(&mut buffer).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if expected_length.is_none()
                    && let Some(header_end) =
                        request.windows(4).position(|window| window == b"\r\n\r\n")
                {
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    let content_length = headers.lines().find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    });
                    expected_length = Some(header_end + 4 + content_length.unwrap_or_default());
                }
                if expected_length.is_some_and(|length| request.len() >= length) {
                    break;
                }
            }
            let _ = socket.write_all(&response).await;
            let _ = socket.shutdown().await;
            request
        });
        (format!("http://{address}/search"), task)
    }

    fn http_response(status: &str, body: &[u8]) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        response
    }

    #[test]
    fn recognizes_anthropic_and_openai_web_search_tools() {
        let anthropic = br#"{"model":"claude","tools":[{"type":"web_search_20250305"}],"messages":[{"role":"user","content":"rust news"}]}"#;
        let parsed = parse_search_request(
            &route(RouteKind::AnthropicMessages, Protocol::Anthropic),
            anthropic,
        )
        .unwrap()
        .unwrap();
        assert_eq!(parsed.query, "rust news");

        let openai = br#"{"model":"gpt-5","tools":[{"type":"web_search_preview"}],"input":[{"role":"user","content":[{"type":"input_text","text":"latest rust"}]}]}"#;
        let parsed =
            parse_search_request(&route(RouteKind::OpenAiResponses, Protocol::OpenAi), openai)
                .unwrap()
                .unwrap();
        assert_eq!(parsed.query, "latest rust");

        let multiple = br#"{"tools":[{"type":"web_search"},{"type":"function","function":{"name":"other"}}],"messages":[{"role":"user","content":"q"}]}"#;
        assert!(
            parse_search_request(
                &route(RouteKind::OpenAiChatCompletions, Protocol::OpenAi),
                multiple,
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn account_tristate_overrides_channel_and_legacy_bool_is_supported() {
        let enabled_channel = channel("", json!({"web_search_emulation":{"anthropic":true}}));
        assert!(emulation_enabled(
            &account(json!({})),
            Some(&enabled_channel)
        ));
        assert!(!emulation_enabled(
            &account(json!({"web_search_emulation":"disabled"})),
            Some(&enabled_channel)
        ));
        assert!(emulation_enabled(
            &account(json!({"web_search_emulation":"enabled"})),
            None
        ));
        assert!(emulation_enabled(
            &account(json!({"web_search_emulation":true})),
            None
        ));
    }

    #[test]
    fn channel_config_is_authoritative_with_features_as_legacy_fallback() {
        assert!(channel_web_search_enabled(
            &channel("[\"web_search_emulation\"]", json!({})),
            "anthropic"
        ));
        assert!(!channel_web_search_enabled(
            &channel(
                "[\"web_search_emulation\"]",
                json!({"web_search_emulation":{"anthropic":false}}),
            ),
            "anthropic"
        ));
        assert!(channel_web_search_enabled(
            &channel("", json!({"web_search_emulation":{"Anthropic":true}}),),
            "anthropic"
        ));
    }

    #[test]
    fn protocol_responses_include_compatible_search_result_blocks() {
        let request = SearchRequest {
            query: "rust".to_owned(),
            model: "model".to_owned(),
            stream: false,
        };
        let anthropic: Value = serde_json::from_slice(&anthropic_response(&request, &results()))
            .expect("Anthropic response should decode");
        assert_eq!(anthropic["content"][0]["type"], "server_tool_use");
        assert_eq!(
            anthropic["content"][1]["content"][0]["type"],
            "web_search_result"
        );

        let openai: Value =
            serde_json::from_slice(&openai_responses_response(&request, &results()))
                .expect("OpenAI response should decode");
        assert_eq!(openai["output"][0]["type"], "web_search_call");
        assert_eq!(openai["output"][1]["content"][0]["type"], "output_text");
    }

    #[test]
    fn replay_filter_strips_synthetic_blocks_and_preserves_genuine_blocks() {
        let body = br#"{"messages":[{"role":"assistant","content":[{"type":"server_tool_use","id":"srvtoolu_ws_123"},{"type":"web_search_tool_result","tool_use_id":"srvtoolu_ws_123"},{"type":"text","text":"kept"}]},{"role":"assistant","content":[{"type":"server_tool_use","id":"srvtoolu_real"}]}]}"#;
        let filtered = filter_history_blocks(body, false).expect("synthetic blocks should change");
        let filtered: Value = serde_json::from_slice(&filtered).unwrap();
        assert_eq!(
            filtered["messages"][0]["content"].as_array().unwrap().len(),
            1
        );
        assert_eq!(
            filtered["messages"][1]["content"].as_array().unwrap().len(),
            1
        );

        let filtered = filter_history_blocks(body, true).expect("all blocks should change");
        let filtered: Value = serde_json::from_slice(&filtered).unwrap();
        assert_eq!(filtered["messages"][1]["content"][0]["type"], "text");
    }

    #[test]
    fn monthly_reset_clamps_end_of_month() {
        let subscribed = Utc.with_ymd_and_hms(2026, 1, 31, 0, 0, 0).unwrap();
        let now = Utc.with_ymd_and_hms(2026, 2, 1, 0, 0, 0).unwrap();
        let reset = Utc
            .timestamp_opt(
                next_reset_at(Some(subscribed.timestamp()), now.timestamp()),
                0,
            )
            .unwrap();
        assert_eq!((reset.year(), reset.month(), reset.day()), (2026, 2, 28));
    }

    #[tokio::test]
    async fn brave_request_carries_query_count_and_subscription_token() {
        let response = http_response(
            "200 OK",
            br#"{"web":{"results":[{"url":"https://example.test","title":"Rust","description":"News","age":"today"}]}}"#,
        );
        let (endpoint, server) = serve_once(response).await;
        let client = web_search_client(None).unwrap();
        let results = search_brave_at(&client, "brave-secret", "rust search", &endpoint)
            .await
            .unwrap();
        assert_eq!(results[0].title, "Rust");

        let request = String::from_utf8(server.await.unwrap()).unwrap();
        let request_line = request.lines().next().unwrap();
        let target = request_line.split_whitespace().nth(1).unwrap();
        let target = Url::parse(&format!("http://localhost{target}")).unwrap();
        assert_eq!(
            target
                .query_pairs()
                .find(|(key, _)| key == "q")
                .map(|(_, value)| value.into_owned()),
            Some("rust search".to_owned())
        );
        assert_eq!(
            target
                .query_pairs()
                .find(|(key, _)| key == "count")
                .map(|(_, value)| value.into_owned()),
            Some(DEFAULT_MAX_RESULTS.to_string())
        );
        assert!(
            request
                .to_ascii_lowercase()
                .contains("x-subscription-token: brave-secret")
        );
    }

    #[tokio::test]
    async fn tavily_request_is_json_and_provider_errors_do_not_expose_api_key() {
        let response = http_response(
            "200 OK",
            br#"{"results":[{"url":"https://example.test","title":"Rust","content":"News"}]}"#,
        );
        let (endpoint, server) = serve_once(response).await;
        let client = web_search_client(None).unwrap();
        let results = search_tavily_at(&client, "tavily-secret", "rust search", &endpoint)
            .await
            .unwrap();
        assert_eq!(results[0].snippet, "News");

        let request = server.await.unwrap();
        let body_start = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;
        let body: Value = serde_json::from_slice(&request[body_start..]).unwrap();
        assert_eq!(body["api_key"], "tavily-secret");
        assert_eq!(body["query"], "rust search");
        assert_eq!(body["max_results"], DEFAULT_MAX_RESULTS);
        assert_eq!(body["search_depth"], "basic");

        let (endpoint, server) = serve_once(http_response("401 Unauthorized", b"denied")).await;
        let error = search_tavily_at(&client, "never-log-this-key", "rust", &endpoint)
            .await
            .unwrap_err();
        let _ = server.await.unwrap();
        assert!(!error.message.contains("never-log-this-key"));
        assert!(error.message.contains("HTTP 401"));
    }

    #[tokio::test]
    async fn chunked_provider_response_over_one_mib_is_rejected() {
        let oversized = vec![b'x'; MAX_RESPONSE_BYTES + 1];
        let mut response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
        response.extend_from_slice(format!("{:X}\r\n", oversized.len()).as_bytes());
        response.extend_from_slice(&oversized);
        response.extend_from_slice(b"\r\n0\r\n\r\n");
        let (endpoint, server) = serve_once(response).await;
        let client = web_search_client(None).unwrap();
        let error = search_brave_at(&client, "secret", "rust", &endpoint)
            .await
            .unwrap_err();
        let _ = server.await.unwrap();
        assert!(error.message.contains("exceeds the configured limit"));
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL pointing at a migrated disposable *_test database"]
    async fn postgres_usage_reservation_is_atomic_and_rollback_reopens_quota() {
        let database_url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL is set");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .expect("connect test PostgreSQL");
        let provider_type = format!("test-{}", Uuid::new_v4().simple());
        let provider = ProviderConfig {
            provider_type: provider_type.clone(),
            quota_limit: Some(1),
            ..ProviderConfig::default()
        };
        let now = Utc::now().timestamp();
        assert!(reserve_usage(&pool, &provider, now).await.unwrap());
        assert!(!reserve_usage(&pool, &provider, now).await.unwrap());
        rollback_usage(&pool, &provider_type).await;
        assert!(reserve_usage(&pool, &provider, now).await.unwrap());
        sqlx::query("DELETE FROM settings WHERE key = ANY($1)")
            .bind(vec![
                format!("{USAGE_KEY_PREFIX}{provider_type}"),
                format!("{USAGE_RESET_KEY_PREFIX}{provider_type}"),
            ])
            .execute(&pool)
            .await
            .unwrap();
    }
}
