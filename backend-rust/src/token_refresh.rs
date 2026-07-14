use std::{error::Error, fmt, time::Duration};

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{PgPool, Row};
use tokio::{task::JoinHandle, time};
use tokio_util::sync::CancellationToken;

use crate::{admin_api, gateway::AuthCacheInvalidator};

const REFRESH_LEASE_KEY: &str = "rust_token_refresh_lease_until";
const REFRESH_LEASE_SECONDS: i64 = 120;
const RETRYABLE_BLOCK_MINUTES: i32 = 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenRefreshConfig {
    pub interval: Duration,
    pub refresh_before_expiry: Duration,
    pub shutdown_timeout: Duration,
}

impl Default for TokenRefreshConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_mins(5),
            refresh_before_expiry: Duration::from_hours(2),
            shutdown_timeout: Duration::from_secs(30),
        }
    }
}

impl TokenRefreshConfig {
    fn validate(self) -> Result<Self, TokenRefreshError> {
        if self.interval.is_zero() {
            return Err(TokenRefreshError::Configuration(
                "token refresh interval must be greater than zero",
            ));
        }
        if self.refresh_before_expiry.is_zero() {
            return Err(TokenRefreshError::Configuration(
                "token refresh window must be greater than zero",
            ));
        }
        if self.shutdown_timeout.is_zero() {
            return Err(TokenRefreshError::Configuration(
                "token refresh shutdown timeout must be greater than zero",
            ));
        }
        Ok(self)
    }
}

#[derive(Debug)]
pub enum TokenRefreshError {
    Configuration(&'static str),
    Database(sqlx::Error),
    InvalidData(String),
    Shutdown(String),
}

impl fmt::Display for TokenRefreshError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(message) => formatter.write_str(message),
            Self::Database(error) => write!(formatter, "PostgreSQL token refresh failed: {error}"),
            Self::InvalidData(message) | Self::Shutdown(message) => formatter.write_str(message),
        }
    }
}

impl Error for TokenRefreshError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            Self::Configuration(_) | Self::InvalidData(_) | Self::Shutdown(_) => None,
        }
    }
}

impl From<sqlx::Error> for TokenRefreshError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

pub struct TokenRefreshRuntime {
    cancellation: CancellationToken,
    task: JoinHandle<()>,
    shutdown_timeout: Duration,
}

impl TokenRefreshRuntime {
    /// Starts the PostgreSQL-leased OAuth token refresh loop.
    ///
    /// # Errors
    ///
    /// Returns an error when a lifecycle duration is zero.
    pub fn spawn(
        pool: PgPool,
        invalidator: AuthCacheInvalidator,
        config: TokenRefreshConfig,
    ) -> Result<Self, TokenRefreshError> {
        let config = config.validate()?;
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            refresh_loop(pool, invalidator, config, task_cancellation).await;
        });
        Ok(Self {
            cancellation,
            task,
            shutdown_timeout: config.shutdown_timeout,
        })
    }

    /// Cancels future refresh work and waits for the active network request.
    ///
    /// # Errors
    ///
    /// Returns an error when the task panics or exceeds the shutdown timeout.
    pub async fn shutdown(self) -> Result<(), TokenRefreshError> {
        self.cancellation.cancel();
        match time::timeout(self.shutdown_timeout, self.task).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(TokenRefreshError::Shutdown(format!(
                "token refresh task failed: {error}"
            ))),
            Err(_) => Err(TokenRefreshError::Shutdown(format!(
                "token refresh task did not stop within {:?}",
                self.shutdown_timeout
            ))),
        }
    }
}

async fn refresh_loop(
    pool: PgPool,
    invalidator: AuthCacheInvalidator,
    config: TokenRefreshConfig,
    cancellation: CancellationToken,
) {
    let mut ticker = time::interval(config.interval);
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            () = cancellation.cancelled() => break,
            _ = ticker.tick() => {
                match run_refresh_cycle(&pool, &invalidator, config.refresh_before_expiry, &cancellation).await {
                    Ok(report) if report.claimed > 0 || report.failed > 0 => {
                        tracing::info!(?report, "OAuth token refresh cycle completed");
                    }
                    Ok(_) => tracing::debug!("OAuth token refresh cycle had no due accounts"),
                    Err(error) => tracing::error!(error = %error, "OAuth token refresh cycle failed"),
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct TokenRefreshReport {
    candidates: u64,
    due: u64,
    claimed: u64,
    refreshed: u64,
    failed: u64,
}

async fn run_refresh_cycle(
    pool: &PgPool,
    invalidator: &AuthCacheInvalidator,
    refresh_before_expiry: Duration,
    cancellation: &CancellationToken,
) -> Result<TokenRefreshReport, TokenRefreshError> {
    let rows = sqlx::query(
        r"
SELECT id, platform, credentials::text AS credentials_json,
       COALESCE(extra, '{}'::jsonb)::text AS extra_json
FROM accounts
WHERE deleted_at IS NULL
  AND parent_account_id IS NULL
  AND type IN ('oauth', 'setup-token')
  AND status = 'active'
  AND schedulable = TRUE
  AND COALESCE(credentials->>'refresh_token', '') <> ''
  AND platform IN ('anthropic', 'openai', 'gemini', 'antigravity', 'grok')
ORDER BY id
",
    )
    .fetch_all(pool)
    .await?;
    let mut report = TokenRefreshReport {
        candidates: u64::try_from(rows.len()).unwrap_or(u64::MAX),
        ..TokenRefreshReport::default()
    };
    let now = Utc::now();
    for row in rows {
        if cancellation.is_cancelled() {
            break;
        }
        let account_id: i64 = row.try_get("id")?;
        let platform: String = row.try_get("platform")?;
        let credentials_json: String = row.try_get("credentials_json")?;
        let extra_json: String = row.try_get("extra_json")?;
        let credentials = parse_object(&credentials_json, "account credentials")?;
        let extra = parse_object(&extra_json, "account extra")?;
        if !refresh_due(&credentials, &extra, now, refresh_before_expiry) {
            continue;
        }
        report.due = report.due.saturating_add(1);
        if !claim_refresh_lease(pool, account_id).await? {
            continue;
        }
        report.claimed = report.claimed.saturating_add(1);
        let result = admin_api::refresh_oauth_account(pool, account_id).await;
        match result {
            Ok(()) => {
                clear_refresh_state(pool, account_id).await?;
                report.refreshed = report.refreshed.saturating_add(1);
                tracing::info!(account_id, platform, "OAuth account token refreshed");
            }
            Err(error) => {
                record_refresh_failure(pool, account_id, is_non_retryable(&error.to_string()))
                    .await?;
                report.failed = report.failed.saturating_add(1);
                tracing::warn!(
                    account_id,
                    platform,
                    error = %error,
                    "OAuth account token refresh failed"
                );
            }
        }
    }
    if (report.refreshed > 0 || report.failed > 0)
        && let Err(error) = invalidator.invalidate_account_cache().await
    {
        tracing::warn!(error = %error, "token refresh committed but account cache notification failed");
    }
    Ok(report)
}

fn parse_object(raw: &str, label: &'static str) -> Result<Value, TokenRefreshError> {
    serde_json::from_str(raw).map_err(|error| {
        TokenRefreshError::InvalidData(format!("stored {label} is invalid JSON: {error}"))
    })
}

fn refresh_due(
    credentials: &Value,
    extra: &Value,
    now: DateTime<Utc>,
    refresh_before_expiry: Duration,
) -> bool {
    if extra
        .get("force_token_refresh")
        .or_else(|| extra.get("antigravity_force_token_refresh"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return true;
    }
    let Some(expires_at) = token_expiry(credentials) else {
        return false;
    };
    let window = chrono::Duration::from_std(refresh_before_expiry)
        .unwrap_or_else(|_| chrono::Duration::hours(2));
    expires_at <= now + window
}

fn token_expiry(credentials: &Value) -> Option<DateTime<Utc>> {
    let value = credentials.get("expires_at")?;
    let seconds = match value {
        Value::Number(number) => number.as_i64(),
        Value::String(raw) => {
            let trimmed = raw.trim();
            if let Ok(seconds) = trimmed.parse::<i64>() {
                Some(seconds)
            } else {
                return DateTime::parse_from_rfc3339(trimmed)
                    .ok()
                    .map(|value| value.with_timezone(&Utc));
            }
        }
        _ => None,
    }?;
    let seconds = if seconds > 10_000_000_000 {
        seconds / 1_000
    } else {
        seconds
    };
    DateTime::from_timestamp(seconds, 0)
}

async fn claim_refresh_lease(pool: &PgPool, account_id: i64) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        r"
UPDATE accounts
SET extra = jsonb_set(
        COALESCE(extra, '{}'::jsonb),
        ARRAY[$2::text],
        to_jsonb((EXTRACT(EPOCH FROM NOW())::bigint + $3)),
        TRUE
    ),
    updated_at = NOW()
WHERE id = $1
  AND deleted_at IS NULL
  AND status = 'active'
  AND (
      CASE
          WHEN COALESCE(extra->>$2, '') ~ '^[0-9]+$' THEN (extra->>$2)::bigint
          ELSE 0
      END
  ) <= EXTRACT(EPOCH FROM NOW())::bigint
",
    )
    .bind(account_id)
    .bind(REFRESH_LEASE_KEY)
    .bind(REFRESH_LEASE_SECONDS)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

async fn clear_refresh_state(pool: &PgPool, account_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        r"
UPDATE accounts
SET extra = COALESCE(extra, '{}'::jsonb) - ARRAY[
        $2::text,
        'antigravity_force_token_refresh',
        'antigravity_force_token_refresh_reason',
        'antigravity_force_token_refresh_at'
    ],
    temp_unschedulable_until = NULL,
    temp_unschedulable_reason = NULL,
    error_message = NULL,
    status = 'active',
    updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL
",
    )
    .bind(account_id)
    .bind(REFRESH_LEASE_KEY)
    .execute(pool)
    .await?;
    Ok(())
}

async fn record_refresh_failure(
    pool: &PgPool,
    account_id: i64,
    non_retryable: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r"
UPDATE accounts
SET extra = COALESCE(extra, '{}'::jsonb) - ARRAY[
        $2::text,
        'antigravity_force_token_refresh',
        'antigravity_force_token_refresh_reason',
        'antigravity_force_token_refresh_at'
    ],
    status = CASE WHEN $3 THEN 'error' ELSE status END,
    schedulable = CASE WHEN $3 THEN FALSE ELSE schedulable END,
    error_message = CASE WHEN $3 THEN 'OAuth token refresh requires re-authorization' ELSE error_message END,
    temp_unschedulable_until = CASE WHEN $3 THEN NULL ELSE NOW() + make_interval(mins => $4) END,
    temp_unschedulable_reason = CASE WHEN $3 THEN NULL ELSE 'OAuth token refresh temporarily failed' END,
    updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL
",
    )
    .bind(account_id)
    .bind(REFRESH_LEASE_KEY)
    .bind(non_retryable)
    .bind(RETRYABLE_BLOCK_MINUTES)
    .execute(pool)
    .await?;
    Ok(())
}

fn is_non_retryable(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    [
        "invalid_grant",
        "invalid_refresh_token",
        "refresh_token_reused",
        "refresh_token_invalidated",
        "invalid_client",
        "unauthorized_client",
        "access_denied",
        "invalid_scope",
        "entitlement_denied",
        "subscription required",
    ]
    .iter()
    .any(|needle| message.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_rfc3339_seconds_and_millisecond_expiries() {
        let instant = DateTime::parse_from_rfc3339("2030-01-02T03:04:05Z")
            .expect("fixed timestamp should parse")
            .with_timezone(&Utc);
        assert_eq!(
            token_expiry(&json!({"expires_at": instant.to_rfc3339()})),
            Some(instant)
        );
        assert_eq!(
            token_expiry(&json!({"expires_at": instant.timestamp().to_string()})),
            Some(instant)
        );
        assert_eq!(
            token_expiry(&json!({"expires_at": instant.timestamp_millis()})),
            Some(instant)
        );
    }

    #[test]
    fn refreshes_only_inside_window_or_when_forced() {
        let now = Utc::now();
        assert!(!refresh_due(
            &json!({"expires_at": (now + chrono::Duration::hours(3)).timestamp()}),
            &json!({}),
            now,
            Duration::from_hours(2),
        ));
        assert!(refresh_due(
            &json!({"expires_at": (now + chrono::Duration::hours(1)).timestamp()}),
            &json!({}),
            now,
            Duration::from_hours(2),
        ));
        assert!(refresh_due(
            &json!({}),
            &json!({"antigravity_force_token_refresh": true}),
            now,
            Duration::from_hours(2),
        ));
    }

    #[test]
    fn classifies_only_reauthorization_failures_as_non_retryable() {
        assert!(is_non_retryable("provider returned invalid_grant"));
        assert!(is_non_retryable("ENTITLEMENT_DENIED"));
        assert!(!is_non_retryable("connection reset by peer"));
        assert!(!is_non_retryable("provider returned 503"));
    }
}
