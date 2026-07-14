use std::{
    error::Error,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use sqlx::{PgPool, Postgres, Row, Transaction};
use tokio_util::sync::CancellationToken;

use crate::{
    auth::AuthContext,
    billing::{BillingEvent, CostBreakdown, Decimal, RequestType, TokenUsage},
    repository::GroupRecord,
};

const LEASE_TTL_SECONDS: i32 = 90;
const LEASE_HEARTBEAT: Duration = Duration::from_secs(20);
const RATE_RETENTION_SECONDS: i32 = 120;
const RECOVERY_LEASE_SECONDS: i32 = 30;
const INITIAL_DELIVERY_LEASE_SECONDS: i32 = 90;
const BILLING_RETENTION_DAYS: i32 = 7;
const CLEANUP_BATCH_SIZE: i64 = 1_000;
const DAY_MILLIS: i64 = 24 * 60 * 60 * 1_000;
const WEEK_MILLIS: i64 = 7 * DAY_MILLIS;
const MONTH_MILLIS: i64 = 30 * DAY_MILLIS;

#[derive(Clone)]
pub(super) struct GatewayAuthority {
    pool: PgPool,
    instance_id: String,
    ready_count: Arc<AtomicU64>,
}

impl GatewayAuthority {
    pub(super) fn new(pool: PgPool) -> Self {
        Self {
            pool,
            instance_id: uuid::Uuid::new_v4().to_string(),
            ready_count: Arc::new(AtomicU64::new(0)),
        }
    }

    pub(super) fn ready_count(&self) -> u64 {
        self.ready_count.load(Ordering::Relaxed)
    }

    pub(super) async fn refresh_ready_count(&self) -> Result<(), AuthorityError> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM gateway_billing_reservations WHERE state='ready'",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(AuthorityError::database)?;
        self.ready_count
            .store(u64::try_from(count).unwrap_or(u64::MAX), Ordering::Relaxed);
        Ok(())
    }

    pub(super) async fn acquire_user_lease(
        &self,
        user_id: i64,
        request_id: &str,
        limit: i32,
    ) -> Result<Option<AuthorityLease>, AuthorityError> {
        self.acquire_lease("user", user_id, 0, request_id, limit)
            .await
    }

    pub(super) async fn acquire_account_lease(
        &self,
        account_id: i64,
        request_id: &str,
        limit: i32,
    ) -> Result<Option<AuthorityLease>, AuthorityError> {
        self.acquire_lease("account", account_id, 0, request_id, limit)
            .await
    }

    async fn acquire_lease(
        &self,
        scope: &'static str,
        subject_id: i64,
        secondary_id: i64,
        request_id: &str,
        limit: i32,
    ) -> Result<Option<AuthorityLease>, AuthorityError> {
        let mut transaction = self.pool.begin().await.map_err(AuthorityError::database)?;
        lock_resource(
            &mut transaction,
            &format!("lease:{scope}:{subject_id}:{secondary_id}"),
        )
        .await?;
        sqlx::query(
            "DELETE FROM gateway_runtime_leases WHERE scope=$1 AND subject_id=$2 AND secondary_id=$3 AND expires_at <= NOW()",
        )
        .bind(scope)
        .bind(subject_id)
        .bind(secondary_id)
        .execute(&mut *transaction)
        .await
        .map_err(AuthorityError::database)?;

        let existing = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM gateway_runtime_leases WHERE scope=$1 AND subject_id=$2 AND secondary_id=$3 AND request_id=$4 AND expires_at > NOW())",
        )
        .bind(scope)
        .bind(subject_id)
        .bind(secondary_id)
        .bind(request_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(AuthorityError::database)?;
        if !existing && limit > 0 {
            let active = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM gateway_runtime_leases WHERE scope=$1 AND subject_id=$2 AND secondary_id=$3 AND expires_at > NOW()",
            )
            .bind(scope)
            .bind(subject_id)
            .bind(secondary_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(AuthorityError::database)?;
            if active >= i64::from(limit) {
                transaction
                    .rollback()
                    .await
                    .map_err(AuthorityError::database)?;
                return Ok(None);
            }
        }
        sqlx::query(
            r"
            INSERT INTO gateway_runtime_leases (
                scope, subject_id, secondary_id, request_id, instance_id, expires_at
            )
            VALUES ($1,$2,$3,$4,$5,NOW()+make_interval(secs=>$6))
            ON CONFLICT (scope,subject_id,secondary_id,request_id) DO UPDATE
            SET instance_id=EXCLUDED.instance_id,
                expires_at=EXCLUDED.expires_at,
                updated_at=NOW()
            ",
        )
        .bind(scope)
        .bind(subject_id)
        .bind(secondary_id)
        .bind(request_id)
        .bind(&self.instance_id)
        .bind(LEASE_TTL_SECONDS)
        .execute(&mut *transaction)
        .await
        .map_err(AuthorityError::database)?;
        transaction
            .commit()
            .await
            .map_err(AuthorityError::database)?;
        Ok(Some(AuthorityLease::spawn(
            self.pool.clone(),
            scope,
            subject_id,
            secondary_id,
            request_id.to_owned(),
            self.instance_id.clone(),
        )))
    }

    #[allow(clippy::too_many_lines)]
    pub(super) async fn acquire_rate_limits(
        &self,
        auth: &AuthContext,
        request_id: &str,
    ) -> Result<(), AuthorityError> {
        let api_key = auth
            .api_key
            .as_ref()
            .ok_or_else(|| AuthorityError::state("missing API key for global RPM admission"))?;
        let mut limits = Vec::with_capacity(2);
        if let Some(group) = auth.group.as_ref() {
            let limit = api_key.group_rpm_override.unwrap_or(group.rpm_limit);
            if limit > 0 {
                limits.push(RateLimit {
                    scope: "user_group",
                    subject_id: auth.user.id,
                    secondary_id: group.id,
                    limit,
                    message: "group requests-per-minute limit exceeded",
                });
            }
        }
        if auth.user.rpm_limit > 0 {
            limits.push(RateLimit {
                scope: "user",
                subject_id: auth.user.id,
                secondary_id: 0,
                limit: auth.user.rpm_limit,
                message: "user requests-per-minute limit exceeded",
            });
        }
        if limits.is_empty() {
            return Ok(());
        }
        limits.sort_by_key(|limit| (limit.scope, limit.subject_id, limit.secondary_id));
        let mut transaction = self.pool.begin().await.map_err(AuthorityError::database)?;
        for limit in &limits {
            lock_resource(
                &mut transaction,
                &format!(
                    "rpm:{}:{}:{}",
                    limit.scope, limit.subject_id, limit.secondary_id
                ),
            )
            .await?;
        }
        for limit in &limits {
            sqlx::query(
                "DELETE FROM gateway_runtime_rate_events WHERE scope=$1 AND subject_id=$2 AND secondary_id=$3 AND expires_at <= NOW()",
            )
            .bind(limit.scope)
            .bind(limit.subject_id)
            .bind(limit.secondary_id)
            .execute(&mut *transaction)
            .await
            .map_err(AuthorityError::database)?;
            let existing = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM gateway_runtime_rate_events WHERE scope=$1 AND subject_id=$2 AND secondary_id=$3 AND request_id=$4 AND bucket_start=date_trunc('minute',NOW()))",
            )
            .bind(limit.scope)
            .bind(limit.subject_id)
            .bind(limit.secondary_id)
            .bind(request_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(AuthorityError::database)?;
            if !existing {
                let active = sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM gateway_runtime_rate_events WHERE scope=$1 AND subject_id=$2 AND secondary_id=$3 AND bucket_start=date_trunc('minute',NOW())",
                )
                .bind(limit.scope)
                .bind(limit.subject_id)
                .bind(limit.secondary_id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(AuthorityError::database)?;
                if active >= i64::from(limit.limit) {
                    transaction
                        .rollback()
                        .await
                        .map_err(AuthorityError::database)?;
                    return Err(AuthorityError::limited(limit.message));
                }
            }
        }
        for limit in &limits {
            sqlx::query(
                r"
                INSERT INTO gateway_runtime_rate_events (
                    scope,subject_id,secondary_id,request_id,instance_id,bucket_start,expires_at
                ) VALUES ($1,$2,$3,$4,$5,date_trunc('minute',NOW()),date_trunc('minute',NOW())+make_interval(secs=>$6))
                ON CONFLICT (scope,subject_id,secondary_id,request_id) DO NOTHING
                ",
            )
            .bind(limit.scope)
            .bind(limit.subject_id)
            .bind(limit.secondary_id)
            .bind(request_id)
            .bind(&self.instance_id)
            .bind(RATE_RETENTION_SECONDS)
            .execute(&mut *transaction)
            .await
            .map_err(AuthorityError::database)?;
        }
        transaction.commit().await.map_err(AuthorityError::database)
    }

    pub(super) async fn begin_billing(
        &self,
        auth: &AuthContext,
        account_id: i64,
        platform: &str,
        request_id: &str,
        request_fingerprint: &str,
    ) -> Result<BillingReservation, AuthorityError> {
        let api_key = auth
            .api_key
            .as_ref()
            .ok_or_else(|| AuthorityError::state("missing API key for billing admission"))?;
        let mut transaction = self.pool.begin().await.map_err(AuthorityError::database)?;
        lock_quota_resources(
            &mut transaction,
            auth.user.id,
            api_key.id,
            api_key.group_id,
            platform,
        )
        .await?;
        validate_global_quotas(&mut transaction, auth, platform).await?;

        if let Some(existing) = sqlx::query(
            "SELECT request_fingerprint,state FROM gateway_billing_reservations WHERE request_id=$1 AND api_key_id=$2 FOR UPDATE",
        )
        .bind(request_id)
        .bind(api_key.id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(AuthorityError::database)?
        {
            let fingerprint: String = existing
                .try_get("request_fingerprint")
                .map_err(AuthorityError::database)?;
            let state: String = existing.try_get("state").map_err(AuthorityError::database)?;
            if fingerprint != request_fingerprint {
                return Err(AuthorityError::state("billing request fingerprint conflict"));
            }
            if state != "inflight" {
                return Err(AuthorityError::state("billing request was already finalized"));
            }
        }

        sqlx::query(
            r"
            INSERT INTO gateway_billing_reservations (
                request_id,api_key_id,request_fingerprint,user_id,account_id,group_id,
                platform,state,instance_id,inflight_expires_at
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,'inflight',$8,NOW()+make_interval(secs=>$9))
            ON CONFLICT (request_id,api_key_id) DO UPDATE
            SET account_id=EXCLUDED.account_id,
                group_id=EXCLUDED.group_id,
                platform=EXCLUDED.platform,
                instance_id=EXCLUDED.instance_id,
                inflight_expires_at=EXCLUDED.inflight_expires_at,
                updated_at=NOW()
            WHERE gateway_billing_reservations.state='inflight'
              AND gateway_billing_reservations.request_fingerprint=EXCLUDED.request_fingerprint
            ",
        )
        .bind(request_id)
        .bind(api_key.id)
        .bind(request_fingerprint)
        .bind(auth.user.id)
        .bind(account_id)
        .bind(api_key.group_id)
        .bind(platform)
        .bind(&self.instance_id)
        .bind(LEASE_TTL_SECONDS)
        .execute(&mut *transaction)
        .await
        .map_err(AuthorityError::database)?;
        transaction
            .commit()
            .await
            .map_err(AuthorityError::database)?;
        Ok(BillingReservation::spawn(
            self.clone(),
            request_id.to_owned(),
            api_key.id,
            request_fingerprint.to_owned(),
        ))
    }

    async fn stage_billing_event(&self, event: &BillingEvent) -> Result<(), AuthorityError> {
        event
            .validate()
            .map_err(|error| AuthorityError::state(error.to_string()))?;
        let mut transaction = self.pool.begin().await.map_err(AuthorityError::database)?;
        lock_quota_resources(
            &mut transaction,
            event.user_id,
            event.api_key_id,
            event.group_id,
            &event.platform,
        )
        .await?;
        let result = sqlx::query(
            r"
            UPDATE gateway_billing_reservations
            SET account_id=$3,group_id=$4,platform=$5,model=$6,
                channel_id=$7,model_mapping_chain=$8,billing_mode=$9,state='ready',
                input_tokens=$10,output_tokens=$11,cache_creation_tokens=$12,cache_read_tokens=$13,
                input_cost=$14::numeric,output_cost=$15::numeric,
                cache_creation_cost=$16::numeric,cache_read_cost=$17::numeric,
                total_cost=$18::numeric,actual_cost=$19::numeric,account_cost=$20::numeric,
                group_multiplier=$21::numeric,account_multiplier=$22::numeric,
                stream=$23,request_type=$24,duration_ms=$25,
                inflight_expires_at=NULL,recovery_owner=$26,
                recovery_until=NOW()+make_interval(secs=>$27),
                ready_at=COALESCE(ready_at,NOW()),updated_at=NOW()
            WHERE request_id=$1 AND api_key_id=$2
              AND request_fingerprint=$28 AND state IN ('inflight','ready')
            ",
        )
        .bind(&event.request_id)
        .bind(event.api_key_id)
        .bind(event.account_id)
        .bind(event.group_id)
        .bind(&event.platform)
        .bind(&event.model)
        .bind(event.channel_id)
        .bind(event.model_mapping_chain.as_deref())
        .bind(&event.billing_mode)
        .bind(
            i64::try_from(event.usage.input_tokens)
                .map_err(|_| AuthorityError::state("input token count exceeds PostgreSQL range"))?,
        )
        .bind(
            i64::try_from(event.usage.output_tokens).map_err(|_| {
                AuthorityError::state("output token count exceeds PostgreSQL range")
            })?,
        )
        .bind(
            i64::try_from(event.usage.cache_creation_input_tokens).map_err(|_| {
                AuthorityError::state("cache creation token count exceeds PostgreSQL range")
            })?,
        )
        .bind(
            i64::try_from(event.usage.cache_read_input_tokens).map_err(|_| {
                AuthorityError::state("cache read token count exceeds PostgreSQL range")
            })?,
        )
        .bind(event.costs.input_cost.to_string())
        .bind(event.costs.output_cost.to_string())
        .bind(event.costs.cache_creation_cost.to_string())
        .bind(event.costs.cache_read_cost.to_string())
        .bind(event.costs.total_cost.to_string())
        .bind(event.costs.actual_cost.to_string())
        .bind(event.costs.account_cost.to_string())
        .bind(event.group_multiplier.to_string())
        .bind(event.account_multiplier.to_string())
        .bind(event.stream)
        .bind(event.request_type.as_i16())
        .bind(event.duration_ms)
        .bind(&self.instance_id)
        .bind(INITIAL_DELIVERY_LEASE_SECONDS)
        .bind(&event.request_fingerprint)
        .execute(&mut *transaction)
        .await
        .map_err(AuthorityError::database)?;
        if result.rows_affected() != 1 {
            return Err(AuthorityError::state(
                "billing reservation is missing, settled, or has a conflicting fingerprint",
            ));
        }
        transaction.commit().await.map_err(AuthorityError::database)
    }

    pub(super) async fn claim_ready_events(
        &self,
        limit: i64,
    ) -> Result<Vec<BillingEvent>, AuthorityError> {
        let rows = sqlx::query(
            r"
            WITH claimed AS (
                SELECT request_id,api_key_id
                FROM gateway_billing_reservations
                WHERE state='ready'
                  AND (recovery_until IS NULL OR recovery_until <= NOW())
                ORDER BY ready_at,request_id,api_key_id
                FOR UPDATE SKIP LOCKED
                LIMIT $1
            )
            UPDATE gateway_billing_reservations reservation
            SET recovery_owner=$2,
                recovery_until=NOW()+make_interval(secs=>$3),
                updated_at=NOW()
            FROM claimed
            WHERE reservation.request_id=claimed.request_id
              AND reservation.api_key_id=claimed.api_key_id
            RETURNING reservation.*,
                      reservation.input_cost::text AS input_cost_text,
                      reservation.output_cost::text AS output_cost_text,
                      reservation.cache_creation_cost::text AS cache_creation_cost_text,
                      reservation.cache_read_cost::text AS cache_read_cost_text,
                      reservation.total_cost::text AS total_cost_text,
                      reservation.actual_cost::text AS actual_cost_text,
                      reservation.account_cost::text AS account_cost_text,
                      reservation.group_multiplier::text AS group_multiplier_text,
                      reservation.account_multiplier::text AS account_multiplier_text
            ",
        )
        .bind(limit.clamp(1, 1_000))
        .bind(&self.instance_id)
        .bind(RECOVERY_LEASE_SECONDS)
        .fetch_all(&self.pool)
        .await
        .map_err(AuthorityError::database)?;
        rows.iter().map(event_from_row).collect()
    }

    pub(super) async fn cleanup_once(&self) -> Result<(), AuthorityError> {
        for sql in [
            "WITH doomed AS (SELECT ctid FROM gateway_runtime_leases WHERE expires_at<=NOW() LIMIT $1) DELETE FROM gateway_runtime_leases WHERE ctid IN (SELECT ctid FROM doomed)",
            "WITH doomed AS (SELECT ctid FROM gateway_runtime_rate_events WHERE expires_at<=NOW() LIMIT $1) DELETE FROM gateway_runtime_rate_events WHERE ctid IN (SELECT ctid FROM doomed)",
        ] {
            sqlx::query(sql)
                .bind(CLEANUP_BATCH_SIZE)
                .execute(&self.pool)
                .await
                .map_err(AuthorityError::database)?;
        }
        sqlx::query(
            "WITH expired AS (SELECT ctid FROM gateway_billing_reservations WHERE state='inflight' AND inflight_expires_at<=NOW() LIMIT $1) UPDATE gateway_billing_reservations SET state='cancelled',cancelled_at=NOW(),inflight_expires_at=NULL,updated_at=NOW() WHERE ctid IN (SELECT ctid FROM expired)",
        )
        .bind(CLEANUP_BATCH_SIZE)
        .execute(&self.pool)
        .await
        .map_err(AuthorityError::database)?;
        sqlx::query(
            "WITH doomed AS (SELECT ctid FROM gateway_billing_reservations WHERE state IN ('settled','cancelled') AND updated_at < NOW()-make_interval(days=>$1) LIMIT $2) DELETE FROM gateway_billing_reservations WHERE ctid IN (SELECT ctid FROM doomed)",
        )
        .bind(BILLING_RETENTION_DAYS)
        .bind(CLEANUP_BATCH_SIZE)
        .execute(&self.pool)
        .await
        .map_err(AuthorityError::database)?;
        Ok(())
    }
}

struct RateLimit {
    scope: &'static str,
    subject_id: i64,
    secondary_id: i64,
    limit: i32,
    message: &'static str,
}

pub(super) struct AuthorityLease {
    cancellation: CancellationToken,
}

impl AuthorityLease {
    fn spawn(
        pool: PgPool,
        scope: &'static str,
        subject_id: i64,
        secondary_id: i64,
        request_id: String,
        instance_id: String,
    ) -> Self {
        let cancellation = CancellationToken::new();
        let worker_cancellation = cancellation.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    () = worker_cancellation.cancelled() => {
                        let _ = sqlx::query(
                            "DELETE FROM gateway_runtime_leases WHERE scope=$1 AND subject_id=$2 AND secondary_id=$3 AND request_id=$4 AND instance_id=$5",
                        )
                        .bind(scope)
                        .bind(subject_id)
                        .bind(secondary_id)
                        .bind(&request_id)
                        .bind(&instance_id)
                        .execute(&pool)
                        .await;
                        break;
                    }
                    () = tokio::time::sleep(LEASE_HEARTBEAT) => {
                        let result = sqlx::query(
                            "UPDATE gateway_runtime_leases SET expires_at=NOW()+make_interval(secs=>$6),updated_at=NOW() WHERE scope=$1 AND subject_id=$2 AND secondary_id=$3 AND request_id=$4 AND instance_id=$5",
                        )
                        .bind(scope)
                        .bind(subject_id)
                        .bind(secondary_id)
                        .bind(&request_id)
                        .bind(&instance_id)
                        .bind(LEASE_TTL_SECONDS)
                        .execute(&pool)
                        .await;
                        if result.as_ref().is_ok_and(|result| result.rows_affected() == 0) {
                            break;
                        }
                    }
                }
            }
        });
        Self { cancellation }
    }
}

impl Drop for AuthorityLease {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

pub(super) struct BillingReservation {
    authority: GatewayAuthority,
    request_id: String,
    api_key_id: i64,
    request_fingerprint: String,
    cancellation: CancellationToken,
    ready: bool,
}

impl BillingReservation {
    fn spawn(
        authority: GatewayAuthority,
        request_id: String,
        api_key_id: i64,
        request_fingerprint: String,
    ) -> Self {
        let cancellation = CancellationToken::new();
        let worker_cancellation = cancellation.clone();
        let pool = authority.pool.clone();
        let heartbeat_request_id = request_id.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    () = worker_cancellation.cancelled() => break,
                    () = tokio::time::sleep(LEASE_HEARTBEAT) => {
                        let result = sqlx::query(
                            "UPDATE gateway_billing_reservations SET inflight_expires_at=NOW()+make_interval(secs=>$3),updated_at=NOW() WHERE request_id=$1 AND api_key_id=$2 AND state='inflight'",
                        )
                        .bind(&heartbeat_request_id)
                        .bind(api_key_id)
                        .bind(LEASE_TTL_SECONDS)
                        .execute(&pool)
                        .await;
                        if result.as_ref().is_ok_and(|result| result.rows_affected() == 0) {
                            break;
                        }
                    }
                }
            }
        });
        Self {
            authority,
            request_id,
            api_key_id,
            request_fingerprint,
            cancellation,
            ready: false,
        }
    }

    pub(super) async fn stage(&mut self, event: &BillingEvent) -> Result<(), AuthorityError> {
        if event.request_id != self.request_id
            || event.api_key_id != self.api_key_id
            || event.request_fingerprint != self.request_fingerprint
        {
            return Err(AuthorityError::state(
                "billing event does not match its durable reservation",
            ));
        }
        self.authority.stage_billing_event(event).await?;
        self.ready = true;
        self.cancellation.cancel();
        Ok(())
    }
}

impl Drop for BillingReservation {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if self.ready {
            return;
        }
        let pool = self.authority.pool.clone();
        let request_id = self.request_id.clone();
        let api_key_id = self.api_key_id;
        let fingerprint = self.request_fingerprint.clone();
        tokio::spawn(async move {
            let _ = sqlx::query(
                "UPDATE gateway_billing_reservations SET state='cancelled',cancelled_at=NOW(),inflight_expires_at=NULL,updated_at=NOW() WHERE request_id=$1 AND api_key_id=$2 AND request_fingerprint=$3 AND state='inflight'",
            )
            .bind(request_id)
            .bind(api_key_id)
            .bind(fingerprint)
            .execute(&pool)
            .await;
        });
    }
}

async fn lock_resource(
    transaction: &mut Transaction<'_, Postgres>,
    resource: &str,
) -> Result<(), AuthorityError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(resource)
        .execute(&mut **transaction)
        .await
        .map_err(AuthorityError::database)?;
    Ok(())
}

async fn lock_quota_resources(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i64,
    api_key_id: i64,
    group_id: Option<i64>,
    platform: &str,
) -> Result<(), AuthorityError> {
    let mut resources = vec![
        format!("quota:api_key:{api_key_id}"),
        format!("quota:user:{user_id}"),
        format!(
            "quota:user_platform:{user_id}:{}",
            platform.to_ascii_lowercase()
        ),
    ];
    if let Some(group_id) = group_id {
        resources.push(format!("quota:user_group:{user_id}:{group_id}"));
    }
    resources.sort();
    for resource in resources {
        lock_resource(transaction, &resource).await?;
    }
    Ok(())
}

async fn validate_global_quotas(
    transaction: &mut Transaction<'_, Postgres>,
    auth: &AuthContext,
    platform: &str,
) -> Result<(), AuthorityError> {
    let api_key = auth
        .api_key
        .as_ref()
        .ok_or_else(|| AuthorityError::state("missing API key for quota admission"))?;
    let key = sqlx::query(
        r"
        SELECT quota::text,quota_used::text,
               rate_limit_5h::text,rate_limit_1d::text,rate_limit_7d::text,
               usage_5h::text,usage_1d::text,usage_7d::text,
               (EXTRACT(EPOCH FROM window_5h_start)*1000)::bigint AS start_5h,
               (EXTRACT(EPOCH FROM window_1d_start)*1000)::bigint AS start_1d,
               (EXTRACT(EPOCH FROM window_7d_start)*1000)::bigint AS start_7d
        FROM api_keys WHERE id=$1 AND deleted_at IS NULL FOR UPDATE
        ",
    )
    .bind(api_key.id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(AuthorityError::database)?
    .ok_or_else(|| AuthorityError::state("API key disappeared during quota admission"))?;
    let now = now_unix_millis();
    validate_api_key_total(transaction, api_key.id, &key).await?;
    for (name, limit, usage, start, duration) in [
        (
            "5-hour",
            "rate_limit_5h",
            "usage_5h",
            "start_5h",
            5 * 60 * 60 * 1_000,
        ),
        ("daily", "rate_limit_1d", "usage_1d", "start_1d", DAY_MILLIS),
        (
            "weekly",
            "rate_limit_7d",
            "usage_7d",
            "start_7d",
            WEEK_MILLIS,
        ),
    ] {
        let raw_limit: String = key.try_get(limit).map_err(AuthorityError::database)?;
        let raw_usage: String = key.try_get(usage).map_err(AuthorityError::database)?;
        let start: Option<i64> = key.try_get(start).map_err(AuthorityError::database)?;
        validate_api_key_window(
            transaction,
            api_key.id,
            name,
            &raw_limit,
            &raw_usage,
            start,
            duration,
            now,
        )
        .await?;
    }

    if auth
        .group
        .as_ref()
        .is_some_and(GroupRecord::is_subscription_type)
    {
        validate_subscription(transaction, auth.user.id, api_key.group_id, now).await?;
    } else {
        let balance = sqlx::query_scalar::<_, String>(
            "SELECT balance::text FROM users WHERE id=$1 AND deleted_at IS NULL FOR UPDATE",
        )
        .bind(auth.user.id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(AuthorityError::database)?
        .ok_or_else(|| AuthorityError::state("user disappeared during quota admission"))?;
        let balance = decimal(&balance, "user balance")?;
        let pending = sum_ready_user(transaction, auth.user.id).await?;
        if balance
            .checked_sub(pending)
            .map_err(AuthorityError::decimal)?
            <= Decimal::ZERO
        {
            return Err(AuthorityError::permission("insufficient balance"));
        }
        validate_platform_quota(transaction, auth.user.id, platform, now).await?;
    }
    Ok(())
}

async fn validate_api_key_total(
    transaction: &mut Transaction<'_, Postgres>,
    api_key_id: i64,
    row: &sqlx::postgres::PgRow,
) -> Result<(), AuthorityError> {
    let limit = decimal(
        &row.try_get::<String, _>("quota")
            .map_err(AuthorityError::database)?,
        "API key quota",
    )?;
    if limit <= Decimal::ZERO {
        return Ok(());
    }
    let used = decimal(
        &row.try_get::<String, _>("quota_used")
            .map_err(AuthorityError::database)?,
        "API key quota usage",
    )?;
    let pending = sum_ready_api_key(transaction, api_key_id, None).await?;
    if used.checked_add(pending).map_err(AuthorityError::decimal)? >= limit {
        return Err(AuthorityError::limited("API key quota exhausted"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn validate_api_key_window(
    transaction: &mut Transaction<'_, Postgres>,
    api_key_id: i64,
    name: &str,
    raw_limit: &str,
    raw_usage: &str,
    start: Option<i64>,
    duration: i64,
    now: i64,
) -> Result<(), AuthorityError> {
    let limit = decimal(raw_limit, "API key rate limit")?;
    if limit <= Decimal::ZERO {
        return Ok(());
    }
    let expired = start
        .and_then(|start| start.checked_add(duration))
        .is_none_or(|deadline| deadline <= now);
    let used = if expired {
        Decimal::ZERO
    } else {
        decimal(raw_usage, "API key rate usage")?
    };
    let since = if expired {
        start
            .and_then(|start| start.checked_add(duration))
            .unwrap_or(now)
    } else {
        start.unwrap_or(now)
    };
    let pending = sum_ready_api_key(transaction, api_key_id, Some(since)).await?;
    if used.checked_add(pending).map_err(AuthorityError::decimal)? >= limit {
        return Err(AuthorityError::limited(format!(
            "API key {name} rate limit exhausted"
        )));
    }
    Ok(())
}

async fn validate_subscription(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i64,
    group_id: Option<i64>,
    now: i64,
) -> Result<(), AuthorityError> {
    let group_id =
        group_id.ok_or_else(|| AuthorityError::state("subscription group is missing"))?;
    let row = sqlx::query(
        r"
        SELECT g.daily_limit_usd::text,g.weekly_limit_usd::text,g.monthly_limit_usd::text,
               s.daily_usage_usd::text,s.weekly_usage_usd::text,s.monthly_usage_usd::text,
               (EXTRACT(EPOCH FROM s.daily_window_start)*1000)::bigint AS daily_start,
               (EXTRACT(EPOCH FROM s.weekly_window_start)*1000)::bigint AS weekly_start,
               (EXTRACT(EPOCH FROM s.monthly_window_start)*1000)::bigint AS monthly_start
        FROM user_subscriptions s JOIN groups g ON g.id=s.group_id
        WHERE s.user_id=$1 AND s.group_id=$2 AND s.deleted_at IS NULL
          AND s.status='active' AND s.starts_at<=NOW() AND s.expires_at>NOW()
          AND g.deleted_at IS NULL
        ORDER BY s.id DESC LIMIT 1 FOR UPDATE OF s
        ",
    )
    .bind(user_id)
    .bind(group_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(AuthorityError::database)?
    .ok_or_else(|| AuthorityError::permission("subscription is not active"))?;
    for (name, limit, usage, start, duration) in [
        (
            "daily",
            "daily_limit_usd",
            "daily_usage_usd",
            "daily_start",
            DAY_MILLIS,
        ),
        (
            "weekly",
            "weekly_limit_usd",
            "weekly_usage_usd",
            "weekly_start",
            WEEK_MILLIS,
        ),
        (
            "monthly",
            "monthly_limit_usd",
            "monthly_usage_usd",
            "monthly_start",
            MONTH_MILLIS,
        ),
    ] {
        let limit: Option<String> = row.try_get(limit).map_err(AuthorityError::database)?;
        let Some(limit) = limit else { continue };
        let limit = decimal(&limit, "subscription quota limit")?;
        let usage = decimal(
            &row.try_get::<String, _>(usage)
                .map_err(AuthorityError::database)?,
            "subscription quota usage",
        )?;
        let start: Option<i64> = row.try_get(start).map_err(AuthorityError::database)?;
        let expired = start
            .and_then(|start| start.checked_add(duration))
            .is_some_and(|deadline| deadline <= now);
        let since = if expired {
            start
                .and_then(|start| start.checked_add(duration))
                .unwrap_or(now)
        } else {
            start.unwrap_or(0)
        };
        let pending = sum_ready_group(transaction, user_id, group_id, since).await?;
        let effective = (if expired { Decimal::ZERO } else { usage })
            .checked_add(pending)
            .map_err(AuthorityError::decimal)?;
        if effective >= limit {
            return Err(AuthorityError::limited(format!(
                "subscription {name} quota exhausted"
            )));
        }
    }
    Ok(())
}

async fn validate_platform_quota(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i64,
    platform: &str,
    now: i64,
) -> Result<(), AuthorityError> {
    let Some(row) = sqlx::query(
        r"
        SELECT daily_limit_usd::text,weekly_limit_usd::text,monthly_limit_usd::text,
               daily_usage_usd::text,weekly_usage_usd::text,monthly_usage_usd::text,
               (EXTRACT(EPOCH FROM daily_window_start)*1000)::bigint AS daily_start,
               (EXTRACT(EPOCH FROM weekly_window_start)*1000)::bigint AS weekly_start,
               (EXTRACT(EPOCH FROM monthly_window_start)*1000)::bigint AS monthly_start
        FROM user_platform_quotas
        WHERE user_id=$1 AND platform=$2 AND deleted_at IS NULL FOR UPDATE
        ",
    )
    .bind(user_id)
    .bind(platform)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(AuthorityError::database)?
    else {
        return Ok(());
    };
    let day_start = shanghai_day_start(now);
    let week_start = shanghai_week_start(now);
    for (name, limit, usage, start, boundary, rolling) in [
        (
            "daily",
            "daily_limit_usd",
            "daily_usage_usd",
            "daily_start",
            day_start,
            None,
        ),
        (
            "weekly",
            "weekly_limit_usd",
            "weekly_usage_usd",
            "weekly_start",
            week_start,
            None,
        ),
        (
            "monthly",
            "monthly_limit_usd",
            "monthly_usage_usd",
            "monthly_start",
            now,
            Some(MONTH_MILLIS),
        ),
    ] {
        let limit: Option<String> = row.try_get(limit).map_err(AuthorityError::database)?;
        let Some(limit) = limit else { continue };
        let limit = decimal(&limit, "platform quota limit")?;
        let usage = decimal(
            &row.try_get::<String, _>(usage)
                .map_err(AuthorityError::database)?,
            "platform quota usage",
        )?;
        let start: Option<i64> = row.try_get(start).map_err(AuthorityError::database)?;
        let expired = rolling.map_or_else(
            || start.is_none_or(|start| start < boundary),
            |duration| {
                start
                    .and_then(|start| start.checked_add(duration))
                    .is_none_or(|deadline| deadline <= now)
            },
        );
        let since = if let Some(duration) = rolling {
            if expired {
                start
                    .and_then(|start| start.checked_add(duration))
                    .unwrap_or(0)
            } else {
                start.unwrap_or(0)
            }
        } else if expired {
            boundary
        } else {
            start.unwrap_or(boundary)
        };
        let pending = sum_ready_platform(transaction, user_id, platform, since).await?;
        let effective = (if expired { Decimal::ZERO } else { usage })
            .checked_add(pending)
            .map_err(AuthorityError::decimal)?;
        if effective >= limit {
            return Err(AuthorityError::limited(format!(
                "{name} {platform} quota exhausted"
            )));
        }
    }
    Ok(())
}

async fn sum_ready_api_key(
    transaction: &mut Transaction<'_, Postgres>,
    api_key_id: i64,
    since: Option<i64>,
) -> Result<Decimal, AuthorityError> {
    let value = sqlx::query_scalar::<_, String>(
        "SELECT COALESCE(SUM(actual_cost) FILTER (WHERE $2::bigint IS NULL OR ready_at>=to_timestamp($2::double precision/1000.0)),0)::text FROM gateway_billing_reservations WHERE state='ready' AND api_key_id=$1",
    )
    .bind(api_key_id)
    .bind(since)
    .fetch_one(&mut **transaction)
    .await
    .map_err(AuthorityError::database)?;
    decimal(&value, "pending API key cost")
}

async fn sum_ready_user(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i64,
) -> Result<Decimal, AuthorityError> {
    let value = sqlx::query_scalar::<_, String>(
        "SELECT COALESCE(SUM(actual_cost),0)::text FROM gateway_billing_reservations WHERE state='ready' AND user_id=$1",
    )
    .bind(user_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(AuthorityError::database)?;
    decimal(&value, "pending user cost")
}

async fn sum_ready_group(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i64,
    group_id: i64,
    since: i64,
) -> Result<Decimal, AuthorityError> {
    let value = sqlx::query_scalar::<_, String>(
        "SELECT COALESCE(SUM(actual_cost),0)::text FROM gateway_billing_reservations WHERE state='ready' AND user_id=$1 AND group_id=$2 AND ready_at>=to_timestamp($3::double precision/1000.0)",
    )
    .bind(user_id)
    .bind(group_id)
    .bind(since)
    .fetch_one(&mut **transaction)
    .await
    .map_err(AuthorityError::database)?;
    decimal(&value, "pending subscription cost")
}

async fn sum_ready_platform(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i64,
    platform: &str,
    since: i64,
) -> Result<Decimal, AuthorityError> {
    let value = sqlx::query_scalar::<_, String>(
        "SELECT COALESCE(SUM(actual_cost),0)::text FROM gateway_billing_reservations WHERE state='ready' AND user_id=$1 AND platform=$2 AND ready_at>=to_timestamp($3::double precision/1000.0)",
    )
    .bind(user_id)
    .bind(platform)
    .bind(since)
    .fetch_one(&mut **transaction)
    .await
    .map_err(AuthorityError::database)?;
    decimal(&value, "pending platform cost")
}

fn event_from_row(row: &sqlx::postgres::PgRow) -> Result<BillingEvent, AuthorityError> {
    let request_type: i16 = row
        .try_get("request_type")
        .map_err(AuthorityError::database)?;
    Ok(BillingEvent {
        request_id: row
            .try_get("request_id")
            .map_err(AuthorityError::database)?,
        request_fingerprint: row
            .try_get("request_fingerprint")
            .map_err(AuthorityError::database)?,
        user_id: row.try_get("user_id").map_err(AuthorityError::database)?,
        api_key_id: row
            .try_get("api_key_id")
            .map_err(AuthorityError::database)?,
        account_id: row
            .try_get("account_id")
            .map_err(AuthorityError::database)?,
        group_id: row.try_get("group_id").map_err(AuthorityError::database)?,
        channel_id: row
            .try_get("channel_id")
            .map_err(AuthorityError::database)?,
        platform: row.try_get("platform").map_err(AuthorityError::database)?,
        model: row.try_get("model").map_err(AuthorityError::database)?,
        model_mapping_chain: row
            .try_get("model_mapping_chain")
            .map_err(AuthorityError::database)?,
        billing_mode: row
            .try_get("billing_mode")
            .map_err(AuthorityError::database)?,
        usage: TokenUsage {
            input_tokens: token_count(row, "input_tokens")?,
            output_tokens: token_count(row, "output_tokens")?,
            cache_creation_input_tokens: token_count(row, "cache_creation_tokens")?,
            cache_read_input_tokens: token_count(row, "cache_read_tokens")?,
        },
        costs: CostBreakdown {
            input_cost: decimal_column(row, "input_cost_text")?,
            output_cost: decimal_column(row, "output_cost_text")?,
            cache_creation_cost: decimal_column(row, "cache_creation_cost_text")?,
            cache_read_cost: decimal_column(row, "cache_read_cost_text")?,
            total_cost: decimal_column(row, "total_cost_text")?,
            actual_cost: decimal_column(row, "actual_cost_text")?,
            account_cost: decimal_column(row, "account_cost_text")?,
        },
        group_multiplier: decimal_column(row, "group_multiplier_text")?,
        account_multiplier: decimal_column(row, "account_multiplier_text")?,
        stream: row.try_get("stream").map_err(AuthorityError::database)?,
        request_type: RequestType::from_i16(request_type)
            .ok_or_else(|| AuthorityError::state("invalid durable billing request type"))?,
        duration_ms: row
            .try_get("duration_ms")
            .map_err(AuthorityError::database)?,
    })
}

fn token_count(row: &sqlx::postgres::PgRow, column: &str) -> Result<u64, AuthorityError> {
    let value: i64 = row.try_get(column).map_err(AuthorityError::database)?;
    u64::try_from(value).map_err(|_| AuthorityError::state("negative durable token count"))
}

fn decimal_column(row: &sqlx::postgres::PgRow, column: &str) -> Result<Decimal, AuthorityError> {
    let value: String = row.try_get(column).map_err(AuthorityError::database)?;
    decimal(&value, column)
}

fn decimal(value: &str, field: &str) -> Result<Decimal, AuthorityError> {
    value
        .parse()
        .map_err(|error| AuthorityError::state(format!("invalid {field}: {error}")))
}

fn now_unix_millis() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn shanghai_day_start(now_unix_ms: i64) -> i64 {
    const OFFSET: i64 = 8 * 60 * 60 * 1_000;
    now_unix_ms
        .saturating_add(OFFSET)
        .div_euclid(DAY_MILLIS)
        .saturating_mul(DAY_MILLIS)
        .saturating_sub(OFFSET)
}

fn shanghai_week_start(now_unix_ms: i64) -> i64 {
    const OFFSET: i64 = 8 * 60 * 60 * 1_000;
    let local_day = now_unix_ms.saturating_add(OFFSET).div_euclid(DAY_MILLIS);
    let days_since_monday = local_day.saturating_add(3).rem_euclid(7);
    local_day
        .saturating_sub(days_since_monday)
        .saturating_mul(DAY_MILLIS)
        .saturating_sub(OFFSET)
}

#[derive(Clone, Debug)]
pub(super) struct AuthorityError {
    kind: AuthorityErrorKind,
    message: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AuthorityErrorKind {
    Limited,
    Permission,
    Unavailable,
    InvalidState,
}

impl AuthorityError {
    #[allow(clippy::needless_pass_by_value)]
    fn database(error: sqlx::Error) -> Self {
        Self {
            kind: AuthorityErrorKind::Unavailable,
            message: format!("PostgreSQL gateway authority: {error}"),
        }
    }

    fn decimal(error: impl fmt::Display) -> Self {
        Self::state(format!("gateway authority decimal arithmetic: {error}"))
    }

    fn state(message: impl Into<String>) -> Self {
        Self {
            kind: AuthorityErrorKind::InvalidState,
            message: message.into(),
        }
    }

    fn limited(message: impl Into<String>) -> Self {
        Self {
            kind: AuthorityErrorKind::Limited,
            message: message.into(),
        }
    }

    fn permission(message: impl Into<String>) -> Self {
        Self {
            kind: AuthorityErrorKind::Permission,
            message: message.into(),
        }
    }

    pub(super) const fn kind(&self) -> AuthorityErrorKind {
        self.kind
    }
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for AuthorityError {}

#[cfg(test)]
mod tests {
    use sqlx::postgres::PgPoolOptions;

    use super::*;
    use crate::{
        auth::AuthSubject,
        repository::{ApiKeyRecord, STATUS_ACTIVE, UserRecord},
    };

    #[test]
    fn request_type_round_trip_rejects_unknown_database_values() {
        assert_eq!(RequestType::from_i16(3), Some(RequestType::OpenAiWebSocket));
        assert_eq!(RequestType::from_i16(99), None);
    }

    #[test]
    fn shanghai_boundaries_are_stable() {
        let monday = chrono::DateTime::parse_from_rfc3339("2026-07-13T00:00:00+08:00")
            .unwrap()
            .timestamp_millis();
        let midday = monday + 12 * 60 * 60 * 1_000;
        assert_eq!(shanghai_day_start(midday), monday);
        assert_eq!(shanghai_week_start(midday), monday);
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL pointing to a fully migrated disposable PostgreSQL database"]
    #[allow(clippy::too_many_lines)]
    async fn postgres_authority_is_cross_replica_and_recovers_ready_billing() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for the ignored database test");
        let pool_a = PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .expect("connect first authority pool");
        let pool_b = PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .expect("connect second authority pool");
        let authority_a = GatewayAuthority::new(pool_a.clone());
        let authority_b = GatewayAuthority::new(pool_b.clone());
        let unique = i64::try_from(uuid::Uuid::new_v4().as_u128() & 0x3fff_ffff_ffff_ffff)
            .expect("masked UUID fits i64")
            .max(1);

        let first = authority_a
            .acquire_user_lease(unique, "physical-a", 1)
            .await
            .expect("first replica lease admission should run")
            .expect("first replica should acquire the global slot");
        assert!(
            authority_b
                .acquire_user_lease(unique, "physical-b", 1)
                .await
                .expect("second replica lease admission should run")
                .is_none(),
            "a second runtime must observe the first runtime's slot"
        );
        drop(first);
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let count = sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM gateway_runtime_leases WHERE scope='user' AND subject_id=$1",
                )
                .bind(unique)
                .fetch_one(&pool_a)
                .await
                .unwrap();
                if count == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("dropping a lease should release it promptly");

        let auth = rpm_auth(unique);
        authority_a
            .acquire_rate_limits(&auth, "physical-rate-a")
            .await
            .expect("first fixed-minute RPM event should pass");
        let limited = authority_b
            .acquire_rate_limits(&auth, "physical-rate-b")
            .await
            .expect_err("second replica must observe the same fixed-minute bucket");
        assert_eq!(limited.kind(), AuthorityErrorKind::Limited);
        sqlx::query(
            "UPDATE gateway_runtime_rate_events SET bucket_start=date_trunc('minute',NOW())-INTERVAL '1 minute' WHERE subject_id=$1",
        )
        .bind(unique)
        .execute(&pool_a)
        .await
        .unwrap();
        authority_b
            .acquire_rate_limits(&auth, "physical-rate-b")
            .await
            .expect("the next PostgreSQL minute bucket must reset RPM");

        sqlx::query(
            "INSERT INTO gateway_runtime_rate_events(scope,subject_id,secondary_id,request_id,instance_id,bucket_start,expires_at) VALUES('user',$1,0,'cold-expired','test',date_trunc('minute',NOW())-INTERVAL '2 minutes',NOW()-INTERVAL '1 second') ON CONFLICT DO NOTHING",
        )
        .bind(unique.saturating_add(1))
        .execute(&pool_a)
        .await
        .unwrap();
        authority_a.cleanup_once().await.unwrap();
        let cold = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM gateway_runtime_rate_events WHERE subject_id=$1",
        )
        .bind(unique.saturating_add(1))
        .fetch_one(&pool_a)
        .await
        .unwrap();
        assert_eq!(cold, 0, "global cleanup must remove cold expired RPM rows");

        let request_id = format!("ready-{unique}");
        sqlx::query(
            r"
            INSERT INTO gateway_billing_reservations(
                request_id,api_key_id,request_fingerprint,user_id,account_id,platform,model,state,
                input_tokens,output_tokens,cache_creation_tokens,cache_read_tokens,
                input_cost,output_cost,cache_creation_cost,cache_read_cost,total_cost,actual_cost,account_cost,
                group_multiplier,account_multiplier,stream,request_type,instance_id,ready_at
            ) VALUES($1,$2,$3,$4,$5,'openai','test','ready',1,0,0,0,0,0,0,0,0,0,0,1,1,FALSE,1,'test',NOW())
            ",
        )
        .bind(&request_id)
        .bind(unique.saturating_add(10))
        .bind("a".repeat(64))
        .bind(unique.saturating_add(20))
        .bind(unique.saturating_add(30))
        .execute(&pool_a)
        .await
        .unwrap();
        assert_eq!(authority_a.claim_ready_events(10).await.unwrap().len(), 1);
        assert!(authority_b.claim_ready_events(10).await.unwrap().is_empty());
        sqlx::query(
            "UPDATE gateway_billing_reservations SET updated_at=NOW()-INTERVAL '30 days' WHERE request_id=$1",
        )
        .bind(&request_id)
        .execute(&pool_a)
        .await
        .unwrap();
        authority_b.cleanup_once().await.unwrap();
        let state = sqlx::query_scalar::<_, String>(
            "SELECT state FROM gateway_billing_reservations WHERE request_id=$1",
        )
        .bind(&request_id)
        .fetch_one(&pool_a)
        .await
        .unwrap();
        assert_eq!(state, "ready", "ready financial rows must never expire");

        sqlx::query("DELETE FROM gateway_runtime_leases WHERE subject_id=$1")
            .bind(unique)
            .execute(&pool_a)
            .await
            .unwrap();
        sqlx::query("DELETE FROM gateway_runtime_rate_events WHERE subject_id=$1")
            .bind(unique)
            .execute(&pool_a)
            .await
            .unwrap();
        sqlx::query("DELETE FROM gateway_billing_reservations WHERE request_id=$1")
            .bind(request_id)
            .execute(&pool_a)
            .await
            .unwrap();
        pool_a.close().await;
        pool_b.close().await;
    }

    fn rpm_auth(user_id: i64) -> AuthContext {
        let user = UserRecord {
            id: user_id,
            email: "authority@example.invalid".to_owned(),
            username: "authority".to_owned(),
            password_hash: "test".to_owned(),
            auth_generation: 0,
            role: "user".to_owned(),
            balance: "10".to_owned(),
            concurrency: 1,
            status: STATUS_ACTIVE.to_owned(),
            rpm_limit: 1,
            allowed_group_ids: Vec::new(),
        };
        AuthContext {
            subject: AuthSubject {
                user_id,
                concurrency: 1,
            },
            role: user.role.clone(),
            user,
            api_key: Some(ApiKeyRecord {
                id: user_id.saturating_add(100),
                user_id,
                key: "sk-authority".to_owned(),
                name: "authority".to_owned(),
                group_id: None,
                status: STATUS_ACTIVE.to_owned(),
                ip_whitelist: Vec::new(),
                ip_blacklist: Vec::new(),
                quota: "0".to_owned(),
                quota_used: "0".to_owned(),
                expires_at_unix_ms: None,
                rate_limit_5h: "0".to_owned(),
                rate_limit_1d: "0".to_owned(),
                rate_limit_7d: "0".to_owned(),
                usage_5h: "0".to_owned(),
                usage_1d: "0".to_owned(),
                usage_7d: "0".to_owned(),
                window_5h_start_unix_ms: None,
                window_1d_start_unix_ms: None,
                window_7d_start_unix_ms: None,
                group_rpm_override: None,
            }),
            group: None,
            subscription: None,
            platform_quotas: Vec::new(),
            jwt_claims: None,
        }
    }
}
