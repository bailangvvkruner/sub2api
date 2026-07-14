use std::{
    collections::{BTreeSet, HashMap},
    error::Error,
    fmt,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use parking_lot::Mutex;

use crate::runtime::{
    BatchSink, BoxFlushFuture, EnqueueError, WriteBehindMetricsSnapshot, WriteBehindSender,
};

use super::{BillingEvent, BillingEventError, Decimal, DecimalError};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct RequestKey {
    request_id: String,
    api_key_id: i64,
}

impl RequestKey {
    fn from_event(event: &BillingEvent) -> Self {
        Self {
            request_id: event.request_id.clone(),
            api_key_id: event.api_key_id,
        }
    }
}

#[derive(Clone, Debug)]
struct PendingEntry {
    request_fingerprint: String,
    user_id: i64,
    api_key_id: i64,
    account_id: i64,
    group_id: Option<i64>,
    platform: String,
    billed_cost: Decimal,
    account_cost: Decimal,
    reserved_at_unix_ms: i64,
}

#[derive(Debug, Default)]
struct PendingState {
    requests: HashMap<RequestKey, PendingEntry>,
    by_user: HashMap<i64, Decimal>,
    by_api_key: HashMap<i64, Decimal>,
    by_user_group: HashMap<(i64, i64), Decimal>,
    by_user_platform: HashMap<(i64, String), Decimal>,
    by_account: HashMap<i64, Decimal>,
}

/// Process-local overlay for costs accepted by the billing queue but not yet
/// committed to `PostgreSQL`.
#[derive(Clone, Debug, Default)]
pub struct PendingBilling {
    state: Arc<Mutex<PendingState>>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PendingBillingKeyCounts {
    pub users: usize,
    pub api_keys: usize,
    pub user_groups: usize,
    pub user_platforms: usize,
    pub accounts: usize,
}

impl PendingBilling {
    /// Reserves an event's user and API-key costs atomically.
    ///
    /// A matching `(request_id, api_key_id, request_fingerprint)` is
    /// idempotent. Reusing the request key with another fingerprint fails
    /// closed.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid event, a fingerprint conflict, or
    /// decimal overflow.
    pub fn reserve(&self, event: &BillingEvent) -> Result<PendingReservation, PendingBillingError> {
        event.validate()?;
        let key = RequestKey::from_event(event);
        let mut state = self.state.lock();
        if let Some(existing) = state.requests.get(&key) {
            if existing.request_fingerprint == event.request_fingerprint {
                return Ok(PendingReservation {
                    pending: self.clone(),
                    key,
                    fingerprint: event.request_fingerprint.clone(),
                    owns_reservation: false,
                });
            }
            return Err(PendingBillingError::FingerprintConflict {
                request_id: event.request_id.clone(),
                api_key_id: event.api_key_id,
            });
        }

        let billed_cost = event.costs.actual_cost;
        let account_cost = event.costs.account_cost;
        let user_total = state
            .by_user
            .get(&event.user_id)
            .copied()
            .unwrap_or(Decimal::ZERO)
            .checked_add(billed_cost)?;
        let api_key_total = state
            .by_api_key
            .get(&event.api_key_id)
            .copied()
            .unwrap_or(Decimal::ZERO)
            .checked_add(billed_cost)?;
        let group_total = event
            .group_id
            .map(|group_id| {
                state
                    .by_user_group
                    .get(&(event.user_id, group_id))
                    .copied()
                    .unwrap_or(Decimal::ZERO)
                    .checked_add(billed_cost)
            })
            .transpose()?;
        let account_total = state
            .by_account
            .get(&event.account_id)
            .copied()
            .unwrap_or(Decimal::ZERO)
            .checked_add(account_cost)?;
        let platform_total = state
            .by_user_platform
            .get(&(event.user_id, event.platform.clone()))
            .copied()
            .unwrap_or(Decimal::ZERO)
            .checked_add(billed_cost)?;

        state.by_user.insert(event.user_id, user_total);
        state.by_api_key.insert(event.api_key_id, api_key_total);
        if let (Some(group_id), Some(group_total)) = (event.group_id, group_total) {
            state
                .by_user_group
                .insert((event.user_id, group_id), group_total);
        }
        state.by_account.insert(event.account_id, account_total);
        state
            .by_user_platform
            .insert((event.user_id, event.platform.clone()), platform_total);
        state.requests.insert(
            key.clone(),
            PendingEntry {
                request_fingerprint: event.request_fingerprint.clone(),
                user_id: event.user_id,
                api_key_id: event.api_key_id,
                account_id: event.account_id,
                group_id: event.group_id,
                platform: event.platform.clone(),
                billed_cost,
                account_cost,
                reserved_at_unix_ms: now_unix_millis(),
            },
        );
        Ok(PendingReservation {
            pending: self.clone(),
            key,
            fingerprint: event.request_fingerprint.clone(),
            owns_reservation: true,
        })
    }

    /// Returns the uncommitted cost attributed to a user.
    #[must_use]
    pub fn user_cost(&self, user_id: i64) -> Decimal {
        self.state
            .lock()
            .by_user
            .get(&user_id)
            .copied()
            .unwrap_or(Decimal::ZERO)
    }

    /// Returns the uncommitted quota/rate cost attributed to an API key.
    #[must_use]
    pub fn api_key_cost(&self, api_key_id: i64) -> Decimal {
        self.state
            .lock()
            .by_api_key
            .get(&api_key_id)
            .copied()
            .unwrap_or(Decimal::ZERO)
    }

    /// Returns the uncommitted API-key cost reserved at or after a window
    /// boundary. This keeps write-behind costs from a previous quota window
    /// out of a newly reset window.
    #[must_use]
    pub fn api_key_cost_since(&self, api_key_id: i64, since_unix_ms: i64) -> Decimal {
        self.state
            .lock()
            .requests
            .values()
            .filter(|entry| {
                entry.api_key_id == api_key_id && entry.reserved_at_unix_ms >= since_unix_ms
            })
            .fold(Decimal::ZERO, |total, entry| {
                total.checked_add(entry.billed_cost).unwrap_or_else(|_| {
                    debug_assert!(false, "validated pending API-key costs cannot overflow");
                    total
                })
            })
    }

    /// Returns the uncommitted cost attributed to one user's group. Callers
    /// can use this as the subscription-window overlay after confirming the
    /// group is subscription-backed.
    #[must_use]
    pub fn user_group_cost(&self, user_id: i64, group_id: i64) -> Decimal {
        self.state
            .lock()
            .by_user_group
            .get(&(user_id, group_id))
            .copied()
            .unwrap_or(Decimal::ZERO)
    }

    /// Returns pending cost for a user's platform at or after the supplied timestamp.
    ///
    /// # Panics
    ///
    /// Panics only if validated pending costs overflow their fixed-point range.
    #[must_use]
    pub fn user_platform_cost_since(
        &self,
        user_id: i64,
        platform: &str,
        since_unix_ms: i64,
    ) -> Decimal {
        self.state
            .lock()
            .requests
            .values()
            .filter(|entry| {
                entry.user_id == user_id
                    && entry.platform == platform
                    && entry.reserved_at_unix_ms >= since_unix_ms
            })
            .fold(Decimal::ZERO, |total, entry| {
                total
                    .checked_add(entry.billed_cost)
                    .expect("pending platform costs are a subset of validated totals")
            })
    }

    /// Returns the uncommitted upstream-account quota cost.
    #[must_use]
    pub fn account_cost(&self, account_id: i64) -> Decimal {
        self.state
            .lock()
            .by_account
            .get(&account_id)
            .copied()
            .unwrap_or(Decimal::ZERO)
    }

    /// Returns the total pending cost billed to API keys.
    ///
    /// # Panics
    ///
    /// Panics only if validated pending costs overflow their fixed-point range.
    #[must_use]
    pub fn total_billed_cost(&self) -> Decimal {
        self.state
            .lock()
            .by_api_key
            .values()
            .copied()
            .fold(Decimal::ZERO, |total, cost| {
                total
                    .checked_add(cost)
                    .expect("pending billed totals were validated on reservation")
            })
    }

    /// Returns the total pending upstream-account cost.
    ///
    /// # Panics
    ///
    /// Panics only if validated pending costs overflow their fixed-point range.
    #[must_use]
    pub fn total_account_cost(&self) -> Decimal {
        self.state
            .lock()
            .by_account
            .values()
            .copied()
            .fold(Decimal::ZERO, |total, cost| {
                total
                    .checked_add(cost)
                    .expect("pending account totals were validated on reservation")
            })
    }

    /// Applies the pending overlay to a durable balance snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error if subtraction exceeds the fixed-point range.
    pub fn effective_user_balance(
        &self,
        user_id: i64,
        durable_balance: Decimal,
    ) -> Result<Decimal, DecimalError> {
        durable_balance.checked_sub(self.user_cost(user_id))
    }

    /// Applies the pending overlay to a durable API-key usage snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error if addition exceeds the fixed-point range.
    pub fn effective_api_key_usage(
        &self,
        api_key_id: i64,
        durable_usage: Decimal,
    ) -> Result<Decimal, DecimalError> {
        durable_usage.checked_add(self.api_key_cost(api_key_id))
    }

    /// Applies the pending overlay to a durable subscription usage snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error if addition exceeds the fixed-point range.
    pub fn effective_user_group_usage(
        &self,
        user_id: i64,
        group_id: i64,
        durable_usage: Decimal,
    ) -> Result<Decimal, DecimalError> {
        durable_usage.checked_add(self.user_group_cost(user_id, group_id))
    }

    /// Applies the pending overlay to a durable upstream-account quota
    /// snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error if addition exceeds the fixed-point range.
    pub fn effective_account_usage(
        &self,
        account_id: i64,
        durable_usage: Decimal,
    ) -> Result<Decimal, DecimalError> {
        durable_usage.checked_add(self.account_cost(account_id))
    }

    /// Reports whether a request key currently has an uncommitted reservation.
    #[must_use]
    pub fn contains(&self, request_id: &str, api_key_id: i64) -> bool {
        self.state.lock().requests.contains_key(&RequestKey {
            request_id: request_id.to_owned(),
            api_key_id,
        })
    }

    /// Returns the number of unique pending request keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.state.lock().requests.len()
    }

    /// Reports whether the overlay contains no reservations.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.state.lock().requests.is_empty()
    }

    #[must_use]
    pub fn key_counts(&self) -> PendingBillingKeyCounts {
        let state = self.state.lock();
        PendingBillingKeyCounts {
            users: state.by_user.len(),
            api_keys: state.by_api_key.len(),
            user_groups: state.by_user_group.len(),
            user_platforms: state.by_user_platform.len(),
            accounts: state.by_account.len(),
        }
    }

    /// Creates a producer that reserves before enqueue and automatically
    /// releases newly-created reservations when enqueue is rejected.
    #[must_use]
    pub fn queue(&self, sender: WriteBehindSender<BillingEvent>) -> PendingBillingQueue {
        PendingBillingQueue {
            pending: self.clone(),
            sender,
        }
    }

    /// Wraps a sink so reservations are released only after a successful batch
    /// write.
    #[must_use]
    pub fn sink<S>(&self, sink: S) -> PendingBillingSink<S> {
        PendingBillingSink {
            pending: self.clone(),
            sink,
            invalidator: Arc::new(NoopBillingInvalidator),
        }
    }

    /// Wraps a sink with synchronous post-commit cache invalidation. The
    /// invalidator runs after the durable write succeeds and before pending
    /// costs are removed, so stale L1 snapshots cannot become visible between
    /// those operations in the local process.
    #[must_use]
    pub fn sink_with_invalidator<S, I>(&self, sink: S, invalidator: I) -> PendingBillingSink<S>
    where
        I: BillingInvalidator,
    {
        PendingBillingSink {
            pending: self.clone(),
            sink,
            invalidator: Arc::new(invalidator),
        }
    }

    fn release_matching(&self, key: &RequestKey, fingerprint: &str) {
        let mut state = self.state.lock();
        let Some(entry) = state.requests.get(key) else {
            return;
        };
        if entry.request_fingerprint != fingerprint {
            return;
        }
        let entry = state
            .requests
            .remove(key)
            .expect("the matching pending entry was just observed");
        subtract_cost(&mut state.by_user, entry.user_id, entry.billed_cost);
        subtract_cost(&mut state.by_api_key, entry.api_key_id, entry.billed_cost);
        if let Some(group_id) = entry.group_id {
            subtract_cost(
                &mut state.by_user_group,
                (entry.user_id, group_id),
                entry.billed_cost,
            );
        }
        subtract_cost(
            &mut state.by_user_platform,
            (entry.user_id, entry.platform),
            entry.billed_cost,
        );
        subtract_cost(&mut state.by_account, entry.account_id, entry.account_cost);
    }

    fn settle_batch(&self, batch: &[BillingEvent]) {
        for event in batch {
            self.release_matching(&RequestKey::from_event(event), &event.request_fingerprint);
        }
    }
}

fn now_unix_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
        })
}

fn subtract_cost<K>(totals: &mut HashMap<K, Decimal>, id: K, cost: Decimal)
where
    K: Eq + std::hash::Hash,
{
    let Some(total) = totals.get(&id).copied() else {
        return;
    };
    let Ok(remaining) = total.checked_sub(cost) else {
        debug_assert!(false, "pending billing totals cannot underflow");
        return;
    };
    if remaining.is_zero() {
        totals.remove(&id);
    } else {
        totals.insert(id, remaining);
    }
}

/// A reservation that rolls itself back unless ownership is transferred to the
/// write-behind queue.
#[derive(Debug)]
pub struct PendingReservation {
    pending: PendingBilling,
    key: RequestKey,
    fingerprint: String,
    owns_reservation: bool,
}

impl PendingReservation {
    /// Reports whether this call created the reservation. `false` means the
    /// same request and fingerprint was already reserved.
    #[must_use]
    pub const fn is_new(&self) -> bool {
        self.owns_reservation
    }

    fn retain(mut self) -> ReserveStatus {
        let status = if self.owns_reservation {
            ReserveStatus::Reserved
        } else {
            ReserveStatus::Duplicate
        };
        self.owns_reservation = false;
        status
    }
}

impl Drop for PendingReservation {
    fn drop(&mut self) {
        if self.owns_reservation {
            self.pending.release_matching(&self.key, &self.fingerprint);
        }
    }
}

/// Result of an accepted reservation/enqueue operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReserveStatus {
    Reserved,
    Duplicate,
}

/// Billing producer that keeps queue admission and the pending overlay
/// consistent.
#[derive(Clone)]
pub struct PendingBillingQueue {
    pending: PendingBilling,
    sender: WriteBehindSender<BillingEvent>,
}

impl PendingBillingQueue {
    /// Waits for queue capacity after reserving the event.
    ///
    /// # Errors
    ///
    /// Returns the event on a reservation conflict, validation/arithmetic
    /// failure, or queue shutdown. A newly-created reservation is released on
    /// every error path.
    pub async fn enqueue(&self, event: BillingEvent) -> Result<ReserveStatus, PendingEnqueueError> {
        let reservation =
            self.pending
                .reserve(&event)
                .map_err(|error| PendingEnqueueError::Reservation {
                    error,
                    event: Box::new(event.clone()),
                })?;
        self.sender
            .enqueue(event)
            .await
            .map_err(|error| PendingEnqueueError::Queue(Box::new(error)))?;
        Ok(reservation.retain())
    }

    /// Attempts queue admission without waiting.
    ///
    /// # Errors
    ///
    /// Returns the event on a reservation conflict, validation/arithmetic
    /// failure, a full queue, or queue shutdown. A newly-created reservation is
    /// released on every error path.
    pub fn try_enqueue(&self, event: BillingEvent) -> Result<ReserveStatus, PendingEnqueueError> {
        let reservation =
            self.pending
                .reserve(&event)
                .map_err(|error| PendingEnqueueError::Reservation {
                    error,
                    event: Box::new(event.clone()),
                })?;
        self.sender
            .try_enqueue(event)
            .map_err(|error| PendingEnqueueError::Queue(Box::new(error)))?;
        Ok(reservation.retain())
    }

    #[must_use]
    pub const fn pending(&self) -> &PendingBilling {
        &self.pending
    }

    #[must_use]
    pub fn metrics(&self) -> WriteBehindMetricsSnapshot {
        self.sender.metrics()
    }

    #[must_use]
    pub const fn sender(&self) -> &WriteBehindSender<BillingEvent> {
        &self.sender
    }
}

/// Sink adapter that settles the overlay only after durable batch success.
#[derive(Clone)]
pub struct PendingBillingSink<S> {
    pending: PendingBilling,
    sink: S,
    invalidator: Arc<dyn BillingInvalidator>,
}

impl<S> PendingBillingSink<S> {
    #[must_use]
    pub const fn inner(&self) -> &S {
        &self.sink
    }

    #[must_use]
    pub const fn pending(&self) -> &PendingBilling {
        &self.pending
    }
}

impl<S> BatchSink<BillingEvent> for PendingBillingSink<S>
where
    S: BatchSink<BillingEvent>,
{
    fn write_batch<'a>(&'a self, batch: &'a [BillingEvent]) -> BoxFlushFuture<'a> {
        Box::pin(async move {
            self.sink.write_batch(batch).await?;
            let invalidation = BillingInvalidation::from_events(batch);
            if !invalidation.is_empty() {
                self.invalidator.invalidate(&invalidation);
            }
            self.pending.settle_batch(batch);
            Ok(())
        })
    }
}

/// Stable, de-duplicated entity IDs affected by a committed billing batch.
#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BillingInvalidation {
    user_ids: Vec<i64>,
    api_key_ids: Vec<i64>,
    account_ids: Vec<i64>,
    group_ids: Vec<i64>,
}

impl BillingInvalidation {
    #[must_use]
    pub fn from_events(events: &[BillingEvent]) -> Self {
        Self {
            user_ids: sorted_ids(events.iter().map(|event| event.user_id)),
            api_key_ids: sorted_ids(events.iter().map(|event| event.api_key_id)),
            account_ids: sorted_ids(events.iter().map(|event| event.account_id)),
            group_ids: sorted_ids(events.iter().filter_map(|event| event.group_id)),
        }
    }

    #[must_use]
    pub fn user_ids(&self) -> &[i64] {
        &self.user_ids
    }

    #[must_use]
    pub fn api_key_ids(&self) -> &[i64] {
        &self.api_key_ids
    }

    #[must_use]
    pub fn account_ids(&self) -> &[i64] {
        &self.account_ids
    }

    #[must_use]
    pub fn group_ids(&self) -> &[i64] {
        &self.group_ids
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.user_ids.is_empty()
            && self.api_key_ids.is_empty()
            && self.account_ids.is_empty()
            && self.group_ids.is_empty()
    }
}

fn sorted_ids(ids: impl IntoIterator<Item = i64>) -> Vec<i64> {
    ids.into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Synchronous local invalidation hook invoked after a durable billing batch
/// commits and before its pending overlay is removed.
pub trait BillingInvalidator: Send + Sync + 'static {
    fn invalidate(&self, invalidation: &BillingInvalidation);
}

impl<F> BillingInvalidator for F
where
    F: Fn(&BillingInvalidation) + Send + Sync + 'static,
{
    fn invalidate(&self, invalidation: &BillingInvalidation) {
        self(invalidation);
    }
}

struct NoopBillingInvalidator;

impl BillingInvalidator for NoopBillingInvalidator {
    fn invalidate(&self, _invalidation: &BillingInvalidation) {}
}

#[derive(Debug)]
pub enum PendingBillingError {
    InvalidEvent(BillingEventError),
    FingerprintConflict { request_id: String, api_key_id: i64 },
    Arithmetic(DecimalError),
}

impl fmt::Display for PendingBillingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEvent(error) => error.fmt(formatter),
            Self::FingerprintConflict {
                request_id,
                api_key_id,
            } => write!(
                formatter,
                "pending billing fingerprint conflict for request_id {request_id:?} and api_key_id {api_key_id}"
            ),
            Self::Arithmetic(error) => write!(formatter, "pending billing arithmetic: {error}"),
        }
    }
}

impl Error for PendingBillingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidEvent(error) => Some(error),
            Self::Arithmetic(error) => Some(error),
            Self::FingerprintConflict { .. } => None,
        }
    }
}

impl From<BillingEventError> for PendingBillingError {
    fn from(error: BillingEventError) -> Self {
        Self::InvalidEvent(error)
    }
}

impl From<DecimalError> for PendingBillingError {
    fn from(error: DecimalError) -> Self {
        Self::Arithmetic(error)
    }
}

#[derive(Debug)]
pub enum PendingEnqueueError {
    Reservation {
        error: PendingBillingError,
        event: Box<BillingEvent>,
    },
    Queue(Box<EnqueueError<BillingEvent>>),
}

impl PendingEnqueueError {
    #[must_use]
    pub fn into_event(self) -> BillingEvent {
        match self {
            Self::Reservation { event, .. } => *event,
            Self::Queue(error) => error.into_inner(),
        }
    }

    #[must_use]
    pub const fn is_full(&self) -> bool {
        matches!(self, Self::Queue(error) if error.is_full())
    }
}

impl fmt::Display for PendingEnqueueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reservation { error, .. } => error.fmt(formatter),
            Self::Queue(error) => error.fmt(formatter),
        }
    }
}

impl Error for PendingEnqueueError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Reservation { error, .. } => Some(error),
            Self::Queue(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use anyhow::bail;

    use crate::{
        billing::{CostBreakdown, RequestType, TokenUsage, request_fingerprint},
        runtime::{WriteBehind, WriteBehindConfig},
    };

    use super::*;

    fn event(request_id: &str, fingerprint_payload: &[u8]) -> BillingEvent {
        BillingEvent {
            request_id: request_id.to_owned(),
            request_fingerprint: request_fingerprint(fingerprint_payload),
            user_id: 10,
            api_key_id: 20,
            account_id: 30,
            group_id: Some(40),
            channel_id: None,
            platform: "anthropic".to_owned(),
            model: "model".to_owned(),
            model_mapping_chain: None,
            billing_mode: "token".to_owned(),
            usage: TokenUsage {
                input_tokens: 1,
                ..TokenUsage::default()
            },
            costs: CostBreakdown {
                input_cost: "0.5".parse().unwrap(),
                total_cost: "0.5".parse().unwrap(),
                actual_cost: "0.75".parse().unwrap(),
                account_cost: "0.25".parse().unwrap(),
                ..CostBreakdown::default()
            },
            group_multiplier: "1.5".parse().unwrap(),
            account_multiplier: "0.5".parse().unwrap(),
            stream: false,
            request_type: RequestType::Sync,
            duration_ms: None,
        }
    }

    #[test]
    fn reservations_are_atomic_idempotent_and_conflict_on_fingerprint() {
        let pending = PendingBilling::default();
        let first = event("request", b"same");
        let reservation = pending.reserve(&first).unwrap();
        assert!(reservation.is_new());
        assert_eq!(pending.user_cost(10).to_string(), "0.75");
        assert_eq!(pending.api_key_cost(20).to_string(), "0.75");
        assert_eq!(pending.user_group_cost(10, 40).to_string(), "0.75");
        assert_eq!(pending.account_cost(30).to_string(), "0.25");

        let duplicate = pending.reserve(&first).unwrap();
        assert!(!duplicate.is_new());
        assert_eq!(pending.len(), 1);
        drop(duplicate);
        assert_eq!(pending.len(), 1);

        let conflict = pending.reserve(&event("request", b"different"));
        assert!(matches!(
            conflict,
            Err(PendingBillingError::FingerprintConflict { .. })
        ));

        drop(reservation);
        assert!(pending.is_empty());
        assert!(pending.user_cost(10).is_zero());
        assert!(pending.api_key_cost(20).is_zero());
        assert!(pending.user_group_cost(10, 40).is_zero());
        assert!(pending.account_cost(30).is_zero());
    }

    struct ControlledSink {
        fail: Arc<AtomicBool>,
    }

    impl BatchSink<BillingEvent> for ControlledSink {
        fn write_batch<'a>(&'a self, _batch: &'a [BillingEvent]) -> BoxFlushFuture<'a> {
            Box::pin(async move {
                if self.fail.load(Ordering::Relaxed) {
                    bail!("injected sink failure");
                }
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn sink_failure_retains_pending_and_success_settles_it() {
        let pending = PendingBilling::default();
        let item = event("request", b"payload");
        pending.reserve(&item).unwrap().retain();
        let fail = Arc::new(AtomicBool::new(true));
        let invalidated = Arc::new(parking_lot::Mutex::new(None));
        let invalidated_from_hook = Arc::clone(&invalidated);
        let pending_from_hook = pending.clone();
        let hook_observed_pending = Arc::new(AtomicBool::new(false));
        let hook_observed_pending_from_hook = Arc::clone(&hook_observed_pending);
        let sink = pending.sink_with_invalidator(
            ControlledSink {
                fail: Arc::clone(&fail),
            },
            move |keys: &BillingInvalidation| {
                hook_observed_pending_from_hook
                    .store(pending_from_hook.contains("request", 20), Ordering::Relaxed);
                *invalidated_from_hook.lock() = Some(keys.clone());
            },
        );

        assert!(sink.write_batch(std::slice::from_ref(&item)).await.is_err());
        assert!(pending.contains("request", 20));
        assert!(invalidated.lock().is_none());

        fail.store(false, Ordering::Relaxed);
        sink.write_batch(std::slice::from_ref(&item)).await.unwrap();
        assert!(hook_observed_pending.load(Ordering::Relaxed));
        let invalidated = invalidated.lock().clone().unwrap();
        assert_eq!(invalidated.user_ids(), &[10]);
        assert_eq!(invalidated.api_key_ids(), &[20]);
        assert_eq!(invalidated.account_ids(), &[30]);
        assert_eq!(invalidated.group_ids(), &[40]);
        assert!(pending.is_empty());
    }

    #[test]
    fn invalidation_keys_are_sorted_and_deduplicated() {
        let first = event("first", b"first");
        let mut second = event("second", b"second");
        second.user_id = 9;
        second.api_key_id = 19;
        second.account_id = 29;
        second.group_id = Some(39);
        let invalidation = BillingInvalidation::from_events(&[first.clone(), second, first]);
        assert_eq!(invalidation.user_ids(), &[9, 10]);
        assert_eq!(invalidation.api_key_ids(), &[19, 20]);
        assert_eq!(invalidation.account_ids(), &[29, 30]);
        assert_eq!(invalidation.group_ids(), &[39, 40]);
    }

    #[tokio::test]
    async fn closed_queue_releases_new_reservation() {
        let config = WriteBehindConfig {
            flush_interval: std::time::Duration::from_mins(1),
            ..WriteBehindConfig::default()
        };
        let writer = WriteBehind::spawn(
            ControlledSink {
                fail: Arc::new(AtomicBool::new(false)),
            },
            config,
        )
        .unwrap();
        let sender = writer.sender();
        writer.shutdown().await.unwrap();

        let pending = PendingBilling::default();
        let queue = pending.queue(sender);
        let error = queue.try_enqueue(event("request", b"payload")).unwrap_err();
        assert!(!error.is_full());
        assert!(pending.is_empty());
    }
}
