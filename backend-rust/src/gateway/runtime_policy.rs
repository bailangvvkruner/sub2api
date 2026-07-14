use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use serde::Deserialize;
use serde_json::Value;
use sqlx::{PgPool, Row};

use super::rectifier::RectifierSettings;

const MAX_MATCH_BODY_BYTES: usize = 8 * 1024;
const OVERLOAD_COOLDOWN_KEY: &str = "overload_cooldown_settings";
const RATE_LIMIT_429_COOLDOWN_KEY: &str = "rate_limit_429_cooldown_settings";
const STREAM_TIMEOUT_KEY: &str = "stream_timeout_settings";
const BETA_POLICY_KEY: &str = "beta_policy_settings";
const RECTIFIER_KEY: &str = "rectifier_settings";
const OPS_MONITORING_KEY: &str = "ops_monitoring_enabled";

#[derive(Clone, Debug)]
pub(super) struct RuntimePolicies {
    pub overload: OverloadCooldownSettings,
    pub rate_limit_429: RateLimit429CooldownSettings,
    pub stream_timeout: StreamTimeoutSettings,
    pub beta: BetaPolicySettings,
    pub rectifier: RectifierSettings,
    error_rules: Vec<ErrorPassthroughRule>,
    pub ops_monitoring_enabled: bool,
}

impl RuntimePolicies {
    pub(super) async fn load(pool: &PgPool) -> Result<Self> {
        let rows = sqlx::query(
            r"
SELECT key, value
FROM settings
WHERE key = ANY($1)
",
        )
        .bind(
            &[
                OVERLOAD_COOLDOWN_KEY,
                RATE_LIMIT_429_COOLDOWN_KEY,
                STREAM_TIMEOUT_KEY,
                BETA_POLICY_KEY,
                RECTIFIER_KEY,
                OPS_MONITORING_KEY,
            ][..],
        )
        .fetch_all(pool)
        .await?;
        let settings = rows
            .into_iter()
            .map(|row| {
                Ok((
                    row.try_get::<String, _>("key")?,
                    row.try_get::<String, _>("value")?,
                ))
            })
            .collect::<Result<HashMap<_, _>>>()?;

        let error_rules = sqlx::query(
            r"
SELECT id, priority,
       COALESCE(error_codes, '[]'::jsonb) AS error_codes,
       COALESCE(keywords, '[]'::jsonb) AS keywords,
       match_mode,
       COALESCE(platforms, '[]'::jsonb) AS platforms,
       passthrough_code, response_code, passthrough_body, custom_message,
       skip_monitoring
FROM error_passthrough_rules
WHERE enabled = TRUE
ORDER BY priority, id
",
        )
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|row| ErrorPassthroughRule::from_row(&row))
        .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            overload: json_setting(&settings, OVERLOAD_COOLDOWN_KEY)
                .unwrap_or_else(OverloadCooldownSettings::production_default)
                .normalized(),
            rate_limit_429: json_setting(&settings, RATE_LIMIT_429_COOLDOWN_KEY)
                .unwrap_or_else(RateLimit429CooldownSettings::production_default)
                .normalized(),
            stream_timeout: json_setting(&settings, STREAM_TIMEOUT_KEY)
                .unwrap_or_else(StreamTimeoutSettings::production_default)
                .normalized(),
            beta: json_setting(&settings, BETA_POLICY_KEY)
                .unwrap_or_else(BetaPolicySettings::production_default),
            rectifier: json_setting(&settings, RECTIFIER_KEY).unwrap_or_default(),
            error_rules,
            ops_monitoring_enabled: settings
                .get(OPS_MONITORING_KEY)
                .is_none_or(|value| !value.trim().eq_ignore_ascii_case("false")),
        })
    }

    pub(super) fn match_error(
        &self,
        platform: &str,
        status: StatusCode,
        body: &[u8],
    ) -> Option<ErrorPassthroughDecision> {
        self.error_rules
            .iter()
            .find(|rule| rule.matches(platform, status, body))
            .map(|rule| rule.decision(status, body))
    }

    pub(super) fn failure_cooldown_seconds(
        &self,
        status: StatusCode,
        upstream_retry_seconds: Option<i32>,
    ) -> Option<i32> {
        let seconds = if status == StatusCode::TOO_MANY_REQUESTS {
            upstream_retry_seconds.or_else(|| {
                self.rate_limit_429
                    .enabled
                    .then_some(self.rate_limit_429.cooldown_seconds)
            })
        } else if status.as_u16() == 529 {
            self.overload
                .enabled
                .then_some(self.overload.cooldown_minutes.saturating_mul(60))
        } else if status.is_server_error() {
            Some(upstream_retry_seconds.unwrap_or(30))
        } else {
            Some(15)
        };
        seconds.map(|seconds| seconds.clamp(1, 86_400))
    }
}

fn json_setting<T: for<'de> Deserialize<'de>>(
    settings: &HashMap<String, String>,
    key: &str,
) -> Option<T> {
    serde_json::from_str(settings.get(key)?.trim()).ok()
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub(super) struct OverloadCooldownSettings {
    pub enabled: bool,
    pub cooldown_minutes: i32,
}

impl OverloadCooldownSettings {
    const fn production_default() -> Self {
        Self {
            enabled: true,
            cooldown_minutes: 10,
        }
    }

    fn normalized(mut self) -> Self {
        self.cooldown_minutes = self.cooldown_minutes.clamp(1, 120);
        self
    }
}

impl Default for OverloadCooldownSettings {
    fn default() -> Self {
        Self::production_default()
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub(super) struct RateLimit429CooldownSettings {
    pub enabled: bool,
    pub cooldown_seconds: i32,
}

impl RateLimit429CooldownSettings {
    const fn production_default() -> Self {
        Self {
            enabled: true,
            cooldown_seconds: 5,
        }
    }

    fn normalized(mut self) -> Self {
        self.cooldown_seconds = self.cooldown_seconds.clamp(1, 7_200);
        self
    }
}

impl Default for RateLimit429CooldownSettings {
    fn default() -> Self {
        Self::production_default()
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub(super) struct StreamTimeoutSettings {
    pub enabled: bool,
    pub action: String,
    pub temp_unsched_minutes: i32,
    pub threshold_count: i32,
    pub threshold_window_minutes: i32,
}

impl StreamTimeoutSettings {
    fn production_default() -> Self {
        Self {
            enabled: false,
            action: "temp_unsched".to_owned(),
            temp_unsched_minutes: 5,
            threshold_count: 3,
            threshold_window_minutes: 10,
        }
    }

    fn normalized(mut self) -> Self {
        self.temp_unsched_minutes = self.temp_unsched_minutes.clamp(1, 60);
        self.threshold_count = self.threshold_count.clamp(1, 10);
        self.threshold_window_minutes = self.threshold_window_minutes.clamp(1, 60);
        if !matches!(self.action.as_str(), "temp_unsched" | "error" | "none") {
            "temp_unsched".clone_into(&mut self.action);
        }
        self
    }

    pub(super) fn tracks_account_health(&self) -> bool {
        self.enabled && self.action != "none"
    }
}

impl Default for StreamTimeoutSettings {
    fn default() -> Self {
        Self::production_default()
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub(super) struct BetaPolicySettings {
    rules: Vec<BetaPolicyRule>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
struct BetaPolicyRule {
    beta_token: String,
    action: String,
    scope: String,
    error_message: String,
    model_whitelist: Vec<String>,
    fallback_action: String,
    fallback_error_message: String,
}

impl BetaPolicySettings {
    fn production_default() -> Self {
        Self {
            rules: vec![
                BetaPolicyRule {
                    beta_token: "fast-mode-2026-02-01".to_owned(),
                    action: "filter".to_owned(),
                    scope: "all".to_owned(),
                    ..BetaPolicyRule::default()
                },
                BetaPolicyRule {
                    beta_token: "context-1m-2025-08-07".to_owned(),
                    action: "pass".to_owned(),
                    scope: "all".to_owned(),
                    model_whitelist: [
                        "claude-sonnet-5",
                        "claude-sonnet-5-*",
                        "claude-sonnet-5@*",
                        "us.anthropic.claude-sonnet-5*",
                        "eu.anthropic.claude-sonnet-5*",
                        "apac.anthropic.claude-sonnet-5*",
                        "jp.anthropic.claude-sonnet-5*",
                        "au.anthropic.claude-sonnet-5*",
                        "us-gov.anthropic.claude-sonnet-5*",
                        "global.anthropic.claude-sonnet-5*",
                        "anthropic.claude-sonnet-5*",
                    ]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                    fallback_action: "filter".to_owned(),
                    ..BetaPolicyRule::default()
                },
            ],
        }
    }

    pub(super) fn apply(
        &self,
        headers: &mut HeaderMap,
        account_type: &str,
        model: &str,
    ) -> Result<(), String> {
        let tokens = beta_tokens(headers);
        let token_set = tokens.iter().map(String::as_str).collect::<HashSet<_>>();
        let mut filtered = HashSet::new();
        for rule in &self.rules {
            if rule.beta_token.trim().is_empty() || !scope_matches(&rule.scope, account_type) {
                continue;
            }
            let (action, message) = rule.resolve_action(model);
            match action {
                "block" if token_set.contains(rule.beta_token.trim()) => {
                    return Err(if message.trim().is_empty() {
                        format!("beta feature {} is not allowed", rule.beta_token.trim())
                    } else {
                        message.to_owned()
                    });
                }
                "filter" => {
                    filtered.insert(rule.beta_token.trim());
                }
                _ => {}
            }
        }
        if filtered.is_empty() {
            return Ok(());
        }
        let kept = tokens
            .into_iter()
            .filter(|token| !filtered.contains(token.as_str()))
            .collect::<Vec<_>>();
        headers.remove("anthropic-beta");
        if !kept.is_empty() {
            let value = kept.join(",");
            let value = HeaderValue::from_str(&value)
                .map_err(|_| "anthropic-beta contains an invalid value".to_owned())?;
            headers.insert("anthropic-beta", value);
        }
        Ok(())
    }
}

impl BetaPolicyRule {
    fn resolve_action<'a>(&'a self, model: &str) -> (&'a str, &'a str) {
        if self.model_whitelist.is_empty()
            || self
                .model_whitelist
                .iter()
                .any(|pattern| model_pattern_matches(pattern.trim(), model))
        {
            return (self.action.as_str(), self.error_message.as_str());
        }
        if self.fallback_action.is_empty() {
            ("pass", "")
        } else {
            (
                self.fallback_action.as_str(),
                self.fallback_error_message.as_str(),
            )
        }
    }
}

fn beta_tokens(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all("anthropic-beta")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
        .collect()
}

fn scope_matches(scope: &str, account_type: &str) -> bool {
    let is_oauth = matches!(account_type, "oauth" | "setup-token");
    let is_bedrock = account_type == "bedrock";
    match scope {
        "oauth" => is_oauth,
        "apikey" => !is_oauth && !is_bedrock,
        "bedrock" => is_bedrock,
        _ => true,
    }
}

fn model_pattern_matches(pattern: &str, model: &str) -> bool {
    pattern == model
        || pattern
            .strip_suffix('*')
            .is_some_and(|prefix| model.starts_with(prefix))
}

#[derive(Clone, Debug)]
#[allow(clippy::struct_excessive_bools)]
struct ErrorPassthroughRule {
    error_codes: Vec<i32>,
    keywords: Vec<String>,
    match_all: bool,
    platforms: Vec<String>,
    passthrough_code: bool,
    response_code: Option<i32>,
    passthrough_body: bool,
    custom_message: Option<String>,
    skip_monitoring: bool,
}

impl ErrorPassthroughRule {
    fn from_row(row: &sqlx::postgres::PgRow) -> Result<Self> {
        Ok(Self {
            error_codes: serde_json::from_value(row.try_get::<Value, _>("error_codes")?)
                .context("decode error passthrough status codes")?,
            keywords: serde_json::from_value::<Vec<String>>(row.try_get::<Value, _>("keywords")?)
                .context("decode error passthrough keywords")?
                .into_iter()
                .map(|keyword| keyword.to_lowercase())
                .collect(),
            match_all: row
                .try_get::<String, _>("match_mode")?
                .eq_ignore_ascii_case("all"),
            platforms: serde_json::from_value::<Vec<String>>(row.try_get::<Value, _>("platforms")?)
                .context("decode error passthrough platforms")?
                .into_iter()
                .map(|platform| platform.to_ascii_lowercase())
                .collect(),
            passthrough_code: row.try_get("passthrough_code")?,
            response_code: row.try_get("response_code")?,
            passthrough_body: row.try_get("passthrough_body")?,
            custom_message: row.try_get("custom_message")?,
            skip_monitoring: row.try_get("skip_monitoring")?,
        })
    }

    fn matches(&self, platform: &str, status: StatusCode, body: &[u8]) -> bool {
        if !self.platforms.is_empty()
            && !self
                .platforms
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(platform))
        {
            return false;
        }
        let has_codes = !self.error_codes.is_empty();
        let has_keywords = !self.keywords.is_empty();
        if !has_codes && !has_keywords {
            return false;
        }
        let code_matches = self.error_codes.contains(&i32::from(status.as_u16()));
        let keyword_matches = has_keywords && {
            let body = &body[..body.len().min(MAX_MATCH_BODY_BYTES)];
            let body = String::from_utf8_lossy(body).to_lowercase();
            self.keywords
                .iter()
                .any(|keyword| body.contains(keyword.as_str()))
        };
        if self.match_all {
            (!has_codes || code_matches) && (!has_keywords || keyword_matches)
        } else {
            (has_codes && code_matches) || (has_keywords && keyword_matches)
        }
    }

    fn decision(&self, upstream_status: StatusCode, body: &[u8]) -> ErrorPassthroughDecision {
        let status = if self.passthrough_code {
            upstream_status
        } else {
            self.response_code
                .and_then(|status| u16::try_from(status).ok())
                .and_then(|status| StatusCode::from_u16(status).ok())
                .unwrap_or(upstream_status)
        };
        let custom_message = (!self.passthrough_body)
            .then(|| self.custom_message.clone())
            .flatten()
            .filter(|message| !message.trim().is_empty());
        ErrorPassthroughDecision {
            status,
            message: custom_message.or_else(|| extract_error_message(body)),
            skip_monitoring: self.skip_monitoring,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ErrorPassthroughDecision {
    pub status: StatusCode,
    pub message: Option<String>,
    pub skip_monitoring: bool,
}

fn extract_error_message(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    [
        value.pointer("/error/message"),
        value.pointer("/response/error/message"),
        value.get("message"),
        value.get("detail"),
    ]
    .into_iter()
    .flatten()
    .find_map(Value::as_str)
    .map(str::trim)
    .filter(|message| !message.is_empty())
    .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, StatusCode};

    use super::{
        BetaPolicyRule, BetaPolicySettings, ErrorPassthroughRule, OverloadCooldownSettings,
        RateLimit429CooldownSettings, RectifierSettings, RuntimePolicies, StreamTimeoutSettings,
    };

    #[test]
    fn error_rule_matches_condition_groups_and_rewrites_response() {
        let rule = ErrorPassthroughRule {
            error_codes: vec![422],
            keywords: vec!["invalid schema".to_owned()],
            match_all: true,
            platforms: vec!["anthropic".to_owned()],
            passthrough_code: false,
            response_code: Some(418),
            passthrough_body: false,
            custom_message: Some("request rejected by upstream".to_owned()),
            skip_monitoring: true,
        };
        let body = br#"{"error":{"message":"Invalid Schema for messages"}}"#;
        assert!(rule.matches("ANTHROPIC", StatusCode::UNPROCESSABLE_ENTITY, body));
        assert!(!rule.matches("openai", StatusCode::UNPROCESSABLE_ENTITY, body));
        assert!(!rule.matches("anthropic", StatusCode::BAD_REQUEST, body));
        let decision = rule.decision(StatusCode::UNPROCESSABLE_ENTITY, body);
        assert_eq!(decision.status, StatusCode::IM_A_TEAPOT);
        assert_eq!(
            decision.message.as_deref(),
            Some("request rejected by upstream")
        );
        assert!(decision.skip_monitoring);
    }

    #[test]
    fn beta_policy_blocks_and_filters_by_scope_and_model() {
        let policy = BetaPolicySettings {
            rules: vec![
                BetaPolicyRule {
                    beta_token: "blocked".to_owned(),
                    action: "block".to_owned(),
                    scope: "oauth".to_owned(),
                    error_message: "blocked by policy".to_owned(),
                    ..BetaPolicyRule::default()
                },
                BetaPolicyRule {
                    beta_token: "model-beta".to_owned(),
                    action: "pass".to_owned(),
                    scope: "all".to_owned(),
                    model_whitelist: vec!["claude-sonnet-5-*".to_owned()],
                    fallback_action: "filter".to_owned(),
                    ..BetaPolicyRule::default()
                },
            ],
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            "anthropic-beta",
            HeaderValue::from_static("blocked,model-beta,keep"),
        );
        assert_eq!(
            policy
                .apply(&mut headers, "oauth", "claude-sonnet-4-5")
                .unwrap_err(),
            "blocked by policy"
        );
        policy
            .apply(&mut headers, "apikey", "claude-sonnet-4-5")
            .unwrap();
        assert_eq!(headers["anthropic-beta"], "blocked,keep");
    }

    #[test]
    fn dynamic_cooldowns_only_replace_missing_upstream_rate_limit_reset() {
        let mut policies = RuntimePolicies {
            overload: OverloadCooldownSettings {
                enabled: true,
                cooldown_minutes: 12,
            },
            rate_limit_429: RateLimit429CooldownSettings {
                enabled: true,
                cooldown_seconds: 7,
            },
            stream_timeout: StreamTimeoutSettings::default(),
            beta: BetaPolicySettings::default(),
            rectifier: RectifierSettings::default(),
            error_rules: Vec::new(),
            ops_monitoring_enabled: true,
        };
        assert_eq!(
            policies.failure_cooldown_seconds(StatusCode::TOO_MANY_REQUESTS, Some(90)),
            Some(90)
        );
        assert_eq!(
            policies.failure_cooldown_seconds(StatusCode::TOO_MANY_REQUESTS, None),
            Some(7)
        );
        assert_eq!(
            policies.failure_cooldown_seconds(StatusCode::from_u16(529).unwrap(), None),
            Some(12 * 60)
        );
        policies.rate_limit_429.enabled = false;
        policies.overload.enabled = false;
        assert_eq!(
            policies.failure_cooldown_seconds(StatusCode::TOO_MANY_REQUESTS, None),
            None
        );
        assert_eq!(
            policies.failure_cooldown_seconds(StatusCode::from_u16(529).unwrap(), None),
            None
        );
    }
}
