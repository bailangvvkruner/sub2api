use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};

use crate::runtime::{BatchSink, BoxFlushFuture};

use super::BillingEvent;

const CACHE_INVALIDATION_CHANNEL: &str = "sub2api_auth_cache_invalidation";
const AUTH_INVALIDATION_PAYLOAD: &str = r#"{"version":1,"scope":"auth"}"#;
const ACCOUNT_INVALIDATION_PAYLOAD: &str = r#"{"version":1,"scope":"accounts"}"#;

#[derive(Clone, Debug)]
pub struct PostgresBillingSink {
    pool: PgPool,
}

impl PostgresBillingSink {
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Applies a batch in one transaction. Matching duplicate requests are
    /// skipped; a duplicate with a different fingerprint aborts the batch.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid events, fingerprint conflicts, missing
    /// database entities, SQL failures, or a failed commit. Every such failure
    /// rolls back all effects from the batch.
    pub async fn apply_batch(&self, batch: &[BillingEvent]) -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }

        let prepared = batch
            .iter()
            .enumerate()
            .map(|(index, event)| {
                PreparedEvent::new(event)
                    .with_context(|| format!("validate billing event at batch index {index}"))
            })
            .collect::<Result<Vec<_>>>()?;

        let mut transaction = self
            .pool
            .begin()
            .await
            .context("begin billing batch transaction")?;
        let mut applied = false;
        for event in &prepared {
            if claim_request(&mut transaction, event).await? {
                apply_event(&mut transaction, event).await?;
                applied = true;
            }
            settle_durable_reservation(&mut transaction, event.event).await?;
        }
        if applied {
            publish_cache_invalidations(&mut transaction).await?;
        }
        transaction
            .commit()
            .await
            .context("commit billing batch transaction")
    }
}

async fn settle_durable_reservation(
    transaction: &mut Transaction<'_, Postgres>,
    event: &BillingEvent,
) -> Result<()> {
    let result = sqlx::query(
        r"
        UPDATE gateway_billing_reservations
        SET state='settled',settled_at=COALESCE(settled_at,NOW()),
            recovery_owner=NULL,recovery_until=NULL,updated_at=NOW()
        WHERE request_id=$1 AND api_key_id=$2
          AND request_fingerprint=$3 AND state IN ('ready','settled')
        ",
    )
    .bind(&event.request_id)
    .bind(event.api_key_id)
    .bind(&event.request_fingerprint)
    .execute(&mut **transaction)
    .await
    .context("settle durable billing reservation")?;
    if result.rows_affected() == 0 {
        let conflicting = sqlx::query_scalar::<_, String>(
            "SELECT request_fingerprint FROM gateway_billing_reservations WHERE request_id=$1 AND api_key_id=$2",
        )
        .bind(&event.request_id)
        .bind(event.api_key_id)
        .fetch_optional(&mut **transaction)
        .await
        .context("inspect durable billing reservation settlement")?;
        if conflicting.is_some_and(|fingerprint| fingerprint != event.request_fingerprint) {
            bail!(
                "durable billing reservation fingerprint conflict for request_id {:?} and api_key_id {}",
                event.request_id,
                event.api_key_id
            );
        }
    }
    Ok(())
}

async fn publish_cache_invalidations(transaction: &mut Transaction<'_, Postgres>) -> Result<()> {
    for payload in [AUTH_INVALIDATION_PAYLOAD, ACCOUNT_INVALIDATION_PAYLOAD] {
        sqlx::query("SELECT pg_notify($1, $2)")
            .bind(CACHE_INVALIDATION_CHANNEL)
            .bind(payload)
            .execute(&mut **transaction)
            .await
            .context("publish committed billing cache invalidation")?;
    }
    Ok(())
}

impl BatchSink<BillingEvent> for PostgresBillingSink {
    fn write_batch<'a>(&'a self, batch: &'a [BillingEvent]) -> BoxFlushFuture<'a> {
        Box::pin(async move { self.apply_batch(batch).await })
    }
}

struct PreparedEvent<'a> {
    event: &'a BillingEvent,
    input_tokens: i32,
    output_tokens: i32,
    cache_creation_tokens: i32,
    cache_read_tokens: i32,
    input_cost: String,
    output_cost: String,
    cache_creation_cost: String,
    cache_read_cost: String,
    total_cost: String,
    actual_cost: String,
    quota_cost: String,
    account_quota_cost: String,
    group_multiplier: String,
    account_multiplier: String,
    stream: bool,
    openai_ws_mode: bool,
}

impl<'a> PreparedEvent<'a> {
    fn new(event: &'a BillingEvent) -> Result<Self> {
        event.validate()?;
        let input_cost = event.costs.input_cost.format_fixed(10)?;
        let output_cost = event.costs.output_cost.format_fixed(10)?;
        let cache_creation_cost = event.costs.cache_creation_cost.format_fixed(10)?;
        let cache_read_cost = event.costs.cache_read_cost.format_fixed(10)?;
        let total_cost = event.costs.total_cost.format_fixed(10)?;
        let actual_cost = event.costs.actual_cost.format_fixed(10)?;
        let quota_cost = event.costs.actual_cost.format_fixed(8)?;
        let account_quota_cost = event.costs.account_cost.format_fixed(8)?;
        let group_multiplier = event.group_multiplier.format_fixed(4)?;
        let account_multiplier = event.account_multiplier.format_fixed(4)?;

        for (field, value) in [
            ("input_cost", input_cost.as_str()),
            ("output_cost", output_cost.as_str()),
            ("cache_creation_cost", cache_creation_cost.as_str()),
            ("cache_read_cost", cache_read_cost.as_str()),
            ("total_cost", total_cost.as_str()),
            ("actual_cost", actual_cost.as_str()),
        ] {
            ensure_numeric_width(field, value, 10)?;
        }
        ensure_numeric_width("quota cost", &quota_cost, 12)?;
        ensure_numeric_width("account quota cost", &account_quota_cost, 12)?;
        ensure_numeric_width("group multiplier", &group_multiplier, 6)?;
        ensure_numeric_width("account multiplier", &account_multiplier, 6)?;

        let (stream, openai_ws_mode) = event.request_type.legacy_fields(event.stream);
        Ok(Self {
            event,
            input_tokens: i32::try_from(event.usage.input_tokens)?,
            output_tokens: i32::try_from(event.usage.output_tokens)?,
            cache_creation_tokens: i32::try_from(event.usage.cache_creation_input_tokens)?,
            cache_read_tokens: i32::try_from(event.usage.cache_read_input_tokens)?,
            input_cost,
            output_cost,
            cache_creation_cost,
            cache_read_cost,
            total_cost,
            actual_cost,
            quota_cost,
            account_quota_cost,
            group_multiplier,
            account_multiplier,
            stream,
            openai_ws_mode,
        })
    }
}

fn ensure_numeric_width(field: &str, value: &str, max_integer_digits: usize) -> Result<()> {
    let unsigned = value.strip_prefix('-').unwrap_or(value);
    let integer = unsigned
        .split_once('.')
        .map_or(unsigned, |(integer, _)| integer);
    ensure!(
        integer.len() <= max_integer_digits,
        "{field} exceeds the PostgreSQL numeric range"
    );
    Ok(())
}

async fn claim_request(
    transaction: &mut Transaction<'_, Postgres>,
    prepared: &PreparedEvent<'_>,
) -> Result<bool> {
    let event = prepared.event;
    let archived = sqlx::query_scalar::<_, String>(
        r"
        SELECT request_fingerprint
        FROM usage_billing_dedup_archive
        WHERE request_id = $1 AND api_key_id = $2
        ",
    )
    .bind(&event.request_id)
    .bind(event.api_key_id)
    .fetch_optional(&mut **transaction)
    .await
    .context("check archived billing request")?;
    if let Some(existing) = archived {
        ensure_matching_fingerprint(event, &existing)?;
        return Ok(false);
    }

    let claimed = sqlx::query_scalar::<_, i64>(
        r"
        INSERT INTO usage_billing_dedup (request_id, api_key_id, request_fingerprint)
        VALUES ($1, $2, $3)
        ON CONFLICT (request_id, api_key_id) DO NOTHING
        RETURNING id
        ",
    )
    .bind(&event.request_id)
    .bind(event.api_key_id)
    .bind(&event.request_fingerprint)
    .fetch_optional(&mut **transaction)
    .await
    .context("claim billing request")?;
    if claimed.is_some() {
        return Ok(true);
    }

    let existing = sqlx::query_scalar::<_, String>(
        r"
        SELECT request_fingerprint
        FROM usage_billing_dedup
        WHERE request_id = $1 AND api_key_id = $2
        ",
    )
    .bind(&event.request_id)
    .bind(event.api_key_id)
    .fetch_optional(&mut **transaction)
    .await
    .context("read claimed billing request")?
    .context("billing dedup conflict disappeared before it could be checked")?;
    ensure_matching_fingerprint(event, &existing)?;
    Ok(false)
}

fn ensure_matching_fingerprint(event: &BillingEvent, existing: &str) -> Result<()> {
    if existing == event.request_fingerprint {
        Ok(())
    } else {
        bail!(
            "billing request fingerprint conflict for request_id {:?} and api_key_id {}",
            event.request_id,
            event.api_key_id
        )
    }
}

async fn apply_event(
    transaction: &mut Transaction<'_, Postgres>,
    prepared: &PreparedEvent<'_>,
) -> Result<()> {
    let event = prepared.event;
    let target = resolve_billing_target(transaction, event).await?;
    let billing_type = i16::from(target.subscription_id.is_some());

    sqlx::query(
        r"
        INSERT INTO usage_logs (
            user_id, api_key_id, account_id, request_id, model, group_id, subscription_id,
            channel_id, model_mapping_chain, billing_mode,
            input_tokens, output_tokens, cache_creation_tokens, cache_read_tokens,
            input_cost, output_cost, cache_creation_cost, cache_read_cost,
            total_cost, actual_cost, rate_multiplier, account_rate_multiplier,
            billing_type, request_type, stream, openai_ws_mode, duration_ms
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7,
            $8, $9, $10,
            $11, $12, $13, $14,
            $15::numeric, $16::numeric, $17::numeric, $18::numeric,
            $19::numeric, $20::numeric, $21::numeric, $22::numeric,
            $23, $24, $25, $26, $27
        )
        ",
    )
    .bind(event.user_id)
    .bind(event.api_key_id)
    .bind(event.account_id)
    .bind(&event.request_id)
    .bind(&event.model)
    .bind(event.group_id)
    .bind(target.subscription_id)
    .bind(event.channel_id)
    .bind(event.model_mapping_chain.as_deref())
    .bind(&event.billing_mode)
    .bind(prepared.input_tokens)
    .bind(prepared.output_tokens)
    .bind(prepared.cache_creation_tokens)
    .bind(prepared.cache_read_tokens)
    .bind(&prepared.input_cost)
    .bind(&prepared.output_cost)
    .bind(&prepared.cache_creation_cost)
    .bind(&prepared.cache_read_cost)
    .bind(&prepared.total_cost)
    .bind(&prepared.actual_cost)
    .bind(&prepared.group_multiplier)
    .bind(&prepared.account_multiplier)
    .bind(billing_type)
    .bind(event.request_type.as_i16())
    .bind(prepared.stream)
    .bind(prepared.openai_ws_mode)
    .bind(event.duration_ms)
    .execute(&mut **transaction)
    .await
    .context("insert usage log")?;

    if !event.costs.actual_cost.is_zero() {
        increment_api_key(transaction, prepared).await?;
        if let Some(subscription_id) = target.subscription_id {
            increment_subscription(transaction, event, subscription_id, &prepared.actual_cost)
                .await?;
        } else {
            deduct_balance(transaction, event.user_id, &prepared.quota_cost).await?;
            increment_user_platform_quota(transaction, event, &prepared.actual_cost).await?;
        }
    }

    if target.account_quota_enabled && !event.costs.account_cost.is_zero() {
        increment_account_quota(transaction, event.account_id, &prepared.account_quota_cost)
            .await?;
    }

    Ok(())
}

async fn increment_user_platform_quota(
    transaction: &mut Transaction<'_, Postgres>,
    event: &BillingEvent,
    cost: &str,
) -> Result<()> {
    sqlx::query(
        r"
        UPDATE user_platform_quotas
        SET daily_usage_usd = CASE
                WHEN daily_window_start IS NULL
                  OR daily_window_start < (
                      date_trunc('day', NOW() AT TIME ZONE 'Asia/Shanghai')
                      AT TIME ZONE 'Asia/Shanghai'
                  )
                THEN $1::numeric
                ELSE daily_usage_usd + $1::numeric
            END,
            weekly_usage_usd = CASE
                WHEN weekly_window_start IS NULL
                  OR weekly_window_start < (
                      date_trunc('week', NOW() AT TIME ZONE 'Asia/Shanghai')
                      AT TIME ZONE 'Asia/Shanghai'
                  )
                THEN $1::numeric
                ELSE weekly_usage_usd + $1::numeric
            END,
            monthly_usage_usd = CASE
                WHEN monthly_window_start IS NULL
                  OR monthly_window_start + INTERVAL '30 days' <= NOW()
                THEN $1::numeric
                ELSE monthly_usage_usd + $1::numeric
            END,
            daily_window_start = CASE
                WHEN daily_window_start IS NULL
                  OR daily_window_start < (
                      date_trunc('day', NOW() AT TIME ZONE 'Asia/Shanghai')
                      AT TIME ZONE 'Asia/Shanghai'
                  )
                THEN date_trunc('day', NOW() AT TIME ZONE 'Asia/Shanghai')
                     AT TIME ZONE 'Asia/Shanghai'
                ELSE daily_window_start
            END,
            weekly_window_start = CASE
                WHEN weekly_window_start IS NULL
                  OR weekly_window_start < (
                      date_trunc('week', NOW() AT TIME ZONE 'Asia/Shanghai')
                      AT TIME ZONE 'Asia/Shanghai'
                  )
                THEN date_trunc('week', NOW() AT TIME ZONE 'Asia/Shanghai')
                     AT TIME ZONE 'Asia/Shanghai'
                ELSE weekly_window_start
            END,
            monthly_window_start = CASE
                WHEN monthly_window_start IS NULL
                  OR monthly_window_start + INTERVAL '30 days' <= NOW()
                THEN NOW()
                ELSE monthly_window_start
            END,
            updated_at = NOW()
        WHERE user_id = $2
          AND platform = $3
          AND deleted_at IS NULL
          AND (
              daily_limit_usd IS NOT NULL
              OR weekly_limit_usd IS NOT NULL
              OR monthly_limit_usd IS NOT NULL
          )
        ",
    )
    .bind(cost)
    .bind(event.user_id)
    .bind(&event.platform)
    .execute(&mut **transaction)
    .await
    .context("increment user platform quota")?;
    Ok(())
}

struct BillingTarget {
    subscription_id: Option<i64>,
    account_quota_enabled: bool,
}

async fn resolve_billing_target(
    transaction: &mut Transaction<'_, Postgres>,
    event: &BillingEvent,
) -> Result<BillingTarget> {
    let account_type = sqlx::query_scalar::<_, String>(
        "SELECT type FROM accounts WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(event.account_id)
    .fetch_optional(&mut **transaction)
    .await
    .context("load billing account type")?
    .with_context(|| format!("billing account {} is missing or deleted", event.account_id))?;

    let subscription = is_subscription_group(transaction, event.group_id).await?;
    let subscription_id = if subscription {
        let group_id = event
            .group_id
            .context("subscription billing event is missing its group")?;
        Some(
            sqlx::query_scalar::<_, i64>(
                r"
                SELECT id
                FROM user_subscriptions
                WHERE user_id = $1
                  AND group_id = $2
                  AND deleted_at IS NULL
                ORDER BY id DESC
                LIMIT 1
                FOR UPDATE
                ",
            )
            .bind(event.user_id)
            .bind(group_id)
            .fetch_optional(&mut **transaction)
            .await
            .context("resolve billing subscription")?
            .with_context(|| {
                format!(
                    "no billable subscription exists for user {} and group {group_id}",
                    event.user_id
                )
            })?,
        )
    } else {
        None
    };

    Ok(BillingTarget {
        subscription_id,
        account_quota_enabled: matches!(
            account_type.to_ascii_lowercase().as_str(),
            "apikey" | "bedrock"
        ),
    })
}

async fn increment_api_key(
    transaction: &mut Transaction<'_, Postgres>,
    prepared: &PreparedEvent<'_>,
) -> Result<()> {
    let event = prepared.event;
    let updated_api_key = sqlx::query_scalar::<_, i64>(
        r"
        UPDATE api_keys
        SET quota_used = quota_used + $1::numeric,
            status = CASE
                WHEN quota > 0
                  AND status = 'active'
                  AND quota_used < quota
                  AND quota_used + $1::numeric >= quota
                THEN 'quota_exhausted'
                ELSE status
            END,
            usage_5h = CASE
                WHEN window_5h_start IS NOT NULL
                  AND window_5h_start + INTERVAL '5 hours' <= NOW()
                THEN $1::numeric
                ELSE usage_5h + $1::numeric
            END,
            usage_1d = CASE
                WHEN window_1d_start IS NOT NULL
                  AND window_1d_start + INTERVAL '24 hours' <= NOW()
                THEN $1::numeric
                ELSE usage_1d + $1::numeric
            END,
            usage_7d = CASE
                WHEN window_7d_start IS NOT NULL
                  AND window_7d_start + INTERVAL '7 days' <= NOW()
                THEN $1::numeric
                ELSE usage_7d + $1::numeric
            END,
            window_5h_start = CASE
                WHEN window_5h_start IS NULL
                  OR window_5h_start + INTERVAL '5 hours' <= NOW()
                THEN NOW()
                ELSE window_5h_start
            END,
            window_1d_start = CASE
                WHEN window_1d_start IS NULL
                  OR window_1d_start + INTERVAL '24 hours' <= NOW()
                THEN date_trunc('day', NOW())
                ELSE window_1d_start
            END,
            window_7d_start = CASE
                WHEN window_7d_start IS NULL
                  OR window_7d_start + INTERVAL '7 days' <= NOW()
                THEN date_trunc('day', NOW())
                ELSE window_7d_start
            END,
            updated_at = NOW()
        WHERE id = $2
          AND user_id = $3
          AND group_id IS NOT DISTINCT FROM $4
          AND deleted_at IS NULL
        RETURNING id
        ",
    )
    .bind(&prepared.quota_cost)
    .bind(event.api_key_id)
    .bind(event.user_id)
    .bind(event.group_id)
    .fetch_optional(&mut **transaction)
    .await
    .context("increment API key billing counters")?;
    ensure!(
        updated_api_key.is_some(),
        "API key {} is missing, deleted, or does not match the billing event owner/group",
        event.api_key_id
    );

    Ok(())
}

async fn increment_subscription(
    transaction: &mut Transaction<'_, Postgres>,
    event: &BillingEvent,
    subscription_id: i64,
    cost: &str,
) -> Result<()> {
    let updated = sqlx::query_scalar::<_, i64>(
        r"
        UPDATE user_subscriptions AS subscription
        SET daily_usage_usd = CASE
                WHEN subscription.daily_window_start IS NOT NULL
                  AND subscription.expires_at > subscription.starts_at + INTERVAL '1 day'
                  AND subscription.daily_window_start + INTERVAL '24 hours' <= NOW()
                THEN $1::numeric
                ELSE subscription.daily_usage_usd + $1::numeric
            END,
            weekly_usage_usd = CASE
                WHEN subscription.weekly_window_start IS NOT NULL
                  AND subscription.weekly_window_start + INTERVAL '7 days' <= NOW()
                THEN $1::numeric
                ELSE subscription.weekly_usage_usd + $1::numeric
            END,
            monthly_usage_usd = CASE
                WHEN subscription.monthly_window_start IS NOT NULL
                  AND subscription.monthly_window_start + INTERVAL '30 days' <= NOW()
                THEN $1::numeric
                ELSE subscription.monthly_usage_usd + $1::numeric
            END,
            daily_window_start = CASE
                WHEN subscription.daily_window_start IS NULL
                  OR (
                      subscription.expires_at > subscription.starts_at + INTERVAL '1 day'
                      AND subscription.daily_window_start + INTERVAL '24 hours' <= NOW()
                  )
                THEN date_trunc('day', NOW())
                ELSE subscription.daily_window_start
            END,
            weekly_window_start = CASE
                WHEN subscription.weekly_window_start IS NULL
                  OR subscription.weekly_window_start + INTERVAL '7 days' <= NOW()
                THEN date_trunc('day', NOW())
                ELSE subscription.weekly_window_start
            END,
            monthly_window_start = CASE
                WHEN subscription.monthly_window_start IS NULL
                  OR subscription.monthly_window_start + INTERVAL '30 days' <= NOW()
                THEN date_trunc('day', NOW())
                ELSE subscription.monthly_window_start
            END,
            updated_at = NOW()
        FROM groups AS billing_group
        WHERE subscription.id = $2
          AND subscription.user_id = $3
          AND subscription.group_id = $4
          AND subscription.deleted_at IS NULL
          AND billing_group.id = subscription.group_id
          AND billing_group.deleted_at IS NULL
        RETURNING subscription.id
        ",
    )
    .bind(cost)
    .bind(subscription_id)
    .bind(event.user_id)
    .bind(event.group_id)
    .fetch_optional(&mut **transaction)
    .await
    .context("increment subscription billing counters")?;
    ensure!(
        updated.is_some(),
        "subscription {subscription_id} is missing, deleted, or does not match the billing event"
    );
    Ok(())
}

async fn deduct_balance(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i64,
    cost: &str,
) -> Result<()> {
    let updated_user = sqlx::query_scalar::<_, i64>(
        r"
        UPDATE users
        SET balance = balance - $1::numeric,
            updated_at = NOW()
        WHERE id = $2 AND deleted_at IS NULL
        RETURNING id
        ",
    )
    .bind(cost)
    .bind(user_id)
    .fetch_optional(&mut **transaction)
    .await
    .context("deduct user balance")?;
    ensure!(
        updated_user.is_some(),
        "user {user_id} is missing or deleted"
    );
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn increment_account_quota(
    transaction: &mut Transaction<'_, Postgres>,
    account_id: i64,
    cost: &str,
) -> Result<()> {
    let state = sqlx::query_as::<_, (String, String, String, String, String, String)>(
        r#"
        UPDATE accounts
        SET extra = (
            COALESCE(extra, '{}'::jsonb)
            || jsonb_build_object(
                'quota_used',
                COALESCE((extra->>'quota_used')::numeric, 0) + $1::numeric
            )
            || CASE
                WHEN COALESCE((extra->>'quota_daily_limit')::numeric, 0) > 0
                THEN jsonb_build_object(
                    'quota_daily_used',
                    CASE
                        WHEN CASE
                            WHEN COALESCE(extra->>'quota_daily_reset_mode', 'rolling') = 'fixed'
                            THEN NOW() >= COALESCE(
                                (extra->>'quota_daily_reset_at')::timestamptz,
                                '1970-01-01'::timestamptz
                            )
                            ELSE COALESCE(
                                (extra->>'quota_daily_start')::timestamptz,
                                '1970-01-01'::timestamptz
                            ) + INTERVAL '24 hours' <= NOW()
                        END
                        THEN $1::numeric
                        ELSE COALESCE((extra->>'quota_daily_used')::numeric, 0) + $1::numeric
                    END,
                    'quota_daily_start',
                    CASE
                        WHEN CASE
                            WHEN COALESCE(extra->>'quota_daily_reset_mode', 'rolling') = 'fixed'
                            THEN NOW() >= COALESCE(
                                (extra->>'quota_daily_reset_at')::timestamptz,
                                '1970-01-01'::timestamptz
                            )
                            ELSE COALESCE(
                                (extra->>'quota_daily_start')::timestamptz,
                                '1970-01-01'::timestamptz
                            ) + INTERVAL '24 hours' <= NOW()
                        END
                        THEN to_char(
                            NOW() AT TIME ZONE 'UTC',
                            'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
                        )
                        ELSE COALESCE(
                            extra->>'quota_daily_start',
                            to_char(
                                NOW() AT TIME ZONE 'UTC',
                                'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
                            )
                        )
                    END
                )
                || CASE
                    WHEN COALESCE(extra->>'quota_daily_reset_mode', 'rolling') = 'fixed'
                      AND NOW() >= COALESCE(
                          (extra->>'quota_daily_reset_at')::timestamptz,
                          '1970-01-01'::timestamptz
                      )
                    THEN jsonb_build_object(
                        'quota_daily_reset_at',
                        to_char(
                            (
                                CASE
                                    WHEN NOW() >= (
                                        date_trunc(
                                            'day',
                                            NOW() AT TIME ZONE COALESCE(
                                                extra->>'quota_reset_timezone',
                                                'UTC'
                                            )
                                        )
                                        + (
                                            COALESCE(
                                                (extra->>'quota_daily_reset_hour')::int,
                                                0
                                            ) || ' hours'
                                        )::interval
                                    ) AT TIME ZONE COALESCE(
                                        extra->>'quota_reset_timezone',
                                        'UTC'
                                    )
                                    THEN (
                                        date_trunc(
                                            'day',
                                            NOW() AT TIME ZONE COALESCE(
                                                extra->>'quota_reset_timezone',
                                                'UTC'
                                            )
                                        )
                                        + (
                                            COALESCE(
                                                (extra->>'quota_daily_reset_hour')::int,
                                                0
                                            ) || ' hours'
                                        )::interval
                                        + INTERVAL '1 day'
                                    ) AT TIME ZONE COALESCE(
                                        extra->>'quota_reset_timezone',
                                        'UTC'
                                    )
                                    ELSE (
                                        date_trunc(
                                            'day',
                                            NOW() AT TIME ZONE COALESCE(
                                                extra->>'quota_reset_timezone',
                                                'UTC'
                                            )
                                        )
                                        + (
                                            COALESCE(
                                                (extra->>'quota_daily_reset_hour')::int,
                                                0
                                            ) || ' hours'
                                        )::interval
                                    ) AT TIME ZONE COALESCE(
                                        extra->>'quota_reset_timezone',
                                        'UTC'
                                    )
                                END
                            ) AT TIME ZONE 'UTC',
                            'YYYY-MM-DD"T"HH24:MI:SS"Z"'
                        )
                    )
                    ELSE '{}'::jsonb
                END
                ELSE '{}'::jsonb
            END
            || CASE
                WHEN COALESCE((extra->>'quota_weekly_limit')::numeric, 0) > 0
                THEN jsonb_build_object(
                    'quota_weekly_used',
                    CASE
                        WHEN CASE
                            WHEN COALESCE(extra->>'quota_weekly_reset_mode', 'rolling') = 'fixed'
                            THEN NOW() >= COALESCE(
                                (extra->>'quota_weekly_reset_at')::timestamptz,
                                '1970-01-01'::timestamptz
                            )
                            ELSE COALESCE(
                                (extra->>'quota_weekly_start')::timestamptz,
                                '1970-01-01'::timestamptz
                            ) + INTERVAL '168 hours' <= NOW()
                        END
                        THEN $1::numeric
                        ELSE COALESCE((extra->>'quota_weekly_used')::numeric, 0) + $1::numeric
                    END,
                    'quota_weekly_start',
                    CASE
                        WHEN CASE
                            WHEN COALESCE(extra->>'quota_weekly_reset_mode', 'rolling') = 'fixed'
                            THEN NOW() >= COALESCE(
                                (extra->>'quota_weekly_reset_at')::timestamptz,
                                '1970-01-01'::timestamptz
                            )
                            ELSE COALESCE(
                                (extra->>'quota_weekly_start')::timestamptz,
                                '1970-01-01'::timestamptz
                            ) + INTERVAL '168 hours' <= NOW()
                        END
                        THEN to_char(
                            NOW() AT TIME ZONE 'UTC',
                            'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
                        )
                        ELSE COALESCE(
                            extra->>'quota_weekly_start',
                            to_char(
                                NOW() AT TIME ZONE 'UTC',
                                'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
                            )
                        )
                    END
                )
                || CASE
                    WHEN COALESCE(extra->>'quota_weekly_reset_mode', 'rolling') = 'fixed'
                      AND NOW() >= COALESCE(
                          (extra->>'quota_weekly_reset_at')::timestamptz,
                          '1970-01-01'::timestamptz
                      )
                    THEN jsonb_build_object(
                        'quota_weekly_reset_at',
                        to_char(
                            (
                                CASE
                                    WHEN (
                                        COALESCE(
                                            (extra->>'quota_weekly_reset_day')::int,
                                            1
                                        )
                                        - EXTRACT(
                                            DOW FROM NOW() AT TIME ZONE COALESCE(
                                                extra->>'quota_reset_timezone',
                                                'UTC'
                                            )
                                        )::int
                                        + 7
                                    ) % 7 = 0
                                    AND NOW() >= (
                                        date_trunc(
                                            'day',
                                            NOW() AT TIME ZONE COALESCE(
                                                extra->>'quota_reset_timezone',
                                                'UTC'
                                            )
                                        )
                                        + (
                                            COALESCE(
                                                (extra->>'quota_weekly_reset_hour')::int,
                                                0
                                            ) || ' hours'
                                        )::interval
                                    ) AT TIME ZONE COALESCE(
                                        extra->>'quota_reset_timezone',
                                        'UTC'
                                    )
                                    THEN (
                                        date_trunc(
                                            'day',
                                            NOW() AT TIME ZONE COALESCE(
                                                extra->>'quota_reset_timezone',
                                                'UTC'
                                            )
                                        )
                                        + (
                                            COALESCE(
                                                (extra->>'quota_weekly_reset_hour')::int,
                                                0
                                            ) || ' hours'
                                        )::interval
                                        + INTERVAL '7 days'
                                    ) AT TIME ZONE COALESCE(
                                        extra->>'quota_reset_timezone',
                                        'UTC'
                                    )
                                    ELSE (
                                        date_trunc(
                                            'day',
                                            NOW() AT TIME ZONE COALESCE(
                                                extra->>'quota_reset_timezone',
                                                'UTC'
                                            )
                                        )
                                        + (
                                            COALESCE(
                                                (extra->>'quota_weekly_reset_hour')::int,
                                                0
                                            ) || ' hours'
                                        )::interval
                                        + (
                                            (
                                                COALESCE(
                                                    (extra->>'quota_weekly_reset_day')::int,
                                                    1
                                                )
                                                - EXTRACT(
                                                    DOW FROM NOW() AT TIME ZONE COALESCE(
                                                        extra->>'quota_reset_timezone',
                                                        'UTC'
                                                    )
                                                )::int
                                                + 7
                                            ) % 7 || ' days'
                                        )::interval
                                    ) AT TIME ZONE COALESCE(
                                        extra->>'quota_reset_timezone',
                                        'UTC'
                                    )
                                END
                            ) AT TIME ZONE 'UTC',
                            'YYYY-MM-DD"T"HH24:MI:SS"Z"'
                        )
                    )
                    ELSE '{}'::jsonb
                END
                ELSE '{}'::jsonb
            END
        ),
        updated_at = NOW()
        WHERE id = $2 AND deleted_at IS NULL
        RETURNING
            COALESCE((extra->>'quota_used')::numeric, 0)::text,
            COALESCE((extra->>'quota_limit')::numeric, 0)::text,
            COALESCE((extra->>'quota_daily_used')::numeric, 0)::text,
            COALESCE((extra->>'quota_daily_limit')::numeric, 0)::text,
            COALESCE((extra->>'quota_weekly_used')::numeric, 0)::text,
            COALESCE((extra->>'quota_weekly_limit')::numeric, 0)::text
        "#,
    )
    .bind(cost)
    .bind(account_id)
    .fetch_optional(&mut **transaction)
    .await
    .context("increment account quota counters")?
    .with_context(|| format!("account {account_id} is missing or deleted"))?;

    let amount = cost
        .parse::<super::Decimal>()
        .context("parse applied account quota cost")?;
    let values = [
        state.0.as_str(),
        state.1.as_str(),
        state.2.as_str(),
        state.3.as_str(),
        state.4.as_str(),
        state.5.as_str(),
    ]
    .map(str::parse::<super::Decimal>)
    .into_iter()
    .collect::<std::result::Result<Vec<_>, _>>()
    .context("parse account quota state")?;
    let crossed = quota_crossed(values[0], values[1], amount)?
        || quota_crossed(values[2], values[3], amount)?
        || quota_crossed(values[4], values[5], amount)?;
    if crossed {
        enqueue_account_changed(transaction, account_id).await?;
    }
    Ok(())
}

fn quota_crossed(
    used: super::Decimal,
    limit: super::Decimal,
    amount: super::Decimal,
) -> Result<bool> {
    if limit <= super::Decimal::ZERO || used < limit {
        return Ok(false);
    }
    Ok(used.checked_sub(amount)? < limit)
}

async fn enqueue_account_changed(
    transaction: &mut Transaction<'_, Postgres>,
    account_id: i64,
) -> Result<()> {
    let mut digest = Sha256::new();
    digest.update(b"account_changed");
    digest.update([0]);
    digest.update(account_id.to_string().as_bytes());
    digest.update([0, 0]);
    let dedup_key = format!("scheduler_outbox:{}", hex::encode(digest.finalize()));
    sqlx::query(
        r"
        INSERT INTO scheduler_outbox (event_type, account_id, group_id, payload, dedup_key)
        VALUES ('account_changed', $1, NULL, NULL, $2)
        ON CONFLICT (dedup_key) WHERE dedup_key IS NOT NULL DO NOTHING
        ",
    )
    .bind(account_id)
    .bind(dedup_key)
    .execute(&mut **transaction)
    .await
    .context("enqueue account quota scheduler invalidation")?;
    Ok(())
}

async fn is_subscription_group(
    transaction: &mut Transaction<'_, Postgres>,
    group_id: Option<i64>,
) -> Result<bool> {
    let Some(group_id) = group_id else {
        return Ok(false);
    };
    let subscription_type = sqlx::query_scalar::<_, String>(
        "SELECT subscription_type FROM groups WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(group_id)
    .fetch_optional(&mut **transaction)
    .await
    .context("load billing group type")?
    .with_context(|| format!("billing group {group_id} does not exist or is deleted"))?;
    Ok(subscription_type.eq_ignore_ascii_case("subscription"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::RequestType;

    #[test]
    fn numeric_width_matches_postgres_precision() {
        ensure_numeric_width("cost", "9999999999.0000000000", 10).unwrap();
        assert!(ensure_numeric_width("cost", "10000000000.0000000000", 10).is_err());
    }

    #[test]
    fn request_type_drives_legacy_transport_columns() {
        assert_eq!(RequestType::Sync.legacy_fields(true), (false, false));
        assert_eq!(RequestType::Stream.legacy_fields(false), (true, false));
        assert_eq!(
            RequestType::OpenAiWebSocket.legacy_fields(false),
            (true, true)
        );
    }
}
