use std::{
    collections::HashMap,
    future::Future,
    hash::Hash,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use tokio::sync::watch;

pub type SharedResult<T, E> = Arc<Result<T, E>>;

/// Coalesces concurrent work for the same key. The result is reference counted
/// so neither successful values nor errors need to implement `Clone`.
pub struct Singleflight<K, T, E> {
    flights: Mutex<HashMap<K, Arc<Flight<T, E>>>>,
    metrics: SingleflightMetrics,
}

struct Flight<T, E> {
    state: watch::Sender<FlightState<T, E>>,
}

enum FlightState<T, E> {
    Running,
    Complete(SharedResult<T, E>),
    Abandoned,
}

impl<T, E> Clone for FlightState<T, E> {
    fn clone(&self) -> Self {
        match self {
            Self::Running => Self::Running,
            Self::Complete(result) => Self::Complete(Arc::clone(result)),
            Self::Abandoned => Self::Abandoned,
        }
    }
}

#[derive(Default)]
struct SingleflightMetrics {
    started: AtomicU64,
    shared: AtomicU64,
    succeeded: AtomicU64,
    failed: AtomicU64,
    abandoned: AtomicU64,
    in_flight: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SingleflightMetricsSnapshot {
    pub started: u64,
    pub shared: u64,
    pub succeeded: u64,
    pub failed: u64,
    pub abandoned: u64,
    pub in_flight: u64,
}

impl<K, T, E> Default for Singleflight<K, T, E> {
    fn default() -> Self {
        Self {
            flights: Mutex::new(HashMap::new()),
            metrics: SingleflightMetrics::default(),
        }
    }
}

impl<K, T, E> Singleflight<K, T, E>
where
    K: Clone + Eq + Hash,
{
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Runs `work` once for a key and shares its result with concurrent callers.
    ///
    /// If the elected leader is canceled or panics, its flight is marked
    /// abandoned. Waiters then compete to become a replacement leader using
    /// their own still-unconsumed closure instead of waiting forever.
    ///
    /// # Panics
    ///
    /// Panics only if an internal invariant is violated and one caller is
    /// elected leader twice after its `FnOnce` closure has already completed.
    pub async fn run<F, Fut>(&self, key: K, work: F) -> SharedResult<T, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        let mut work = Some(work);
        loop {
            let (flight, leader) = {
                let mut flights = self.lock_flights();
                if let Some(flight) = flights.get(&key) {
                    self.metrics.shared.fetch_add(1, Ordering::Relaxed);
                    (Arc::clone(flight), false)
                } else {
                    let (state, receiver) = watch::channel(FlightState::Running);
                    drop(receiver);
                    let flight = Arc::new(Flight { state });
                    flights.insert(key.clone(), Arc::clone(&flight));
                    self.metrics.started.fetch_add(1, Ordering::Relaxed);
                    self.metrics.in_flight.fetch_add(1, Ordering::Relaxed);
                    (flight, true)
                }
            };

            if leader {
                let guard = LeaderGuard::new(self, key.clone(), Arc::clone(&flight));
                let result = Arc::new(
                    work.take()
                        .expect("singleflight work closure can only be consumed by its caller")(
                    )
                    .await,
                );
                guard.complete(Arc::clone(&result));
                return result;
            }

            let mut receiver = flight.state.subscribe();
            loop {
                match receiver.borrow().clone() {
                    FlightState::Complete(result) => return result,
                    FlightState::Abandoned => break,
                    FlightState::Running => {}
                }
                if receiver.changed().await.is_err() {
                    break;
                }
            }
        }
    }

    #[must_use]
    pub fn metrics(&self) -> SingleflightMetricsSnapshot {
        SingleflightMetricsSnapshot {
            started: self.metrics.started.load(Ordering::Relaxed),
            shared: self.metrics.shared.load(Ordering::Relaxed),
            succeeded: self.metrics.succeeded.load(Ordering::Relaxed),
            failed: self.metrics.failed.load(Ordering::Relaxed),
            abandoned: self.metrics.abandoned.load(Ordering::Relaxed),
            in_flight: self.metrics.in_flight.load(Ordering::Relaxed),
        }
    }

    fn lock_flights(&self) -> std::sync::MutexGuard<'_, HashMap<K, Arc<Flight<T, E>>>> {
        self.flights
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn remove_if_current(&self, key: &K, flight: &Arc<Flight<T, E>>) {
        let mut flights = self.lock_flights();
        if flights
            .get(key)
            .is_some_and(|current| Arc::ptr_eq(current, flight))
        {
            flights.remove(key);
            self.metrics.in_flight.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

struct LeaderGuard<'a, K, T, E>
where
    K: Clone + Eq + Hash,
{
    group: &'a Singleflight<K, T, E>,
    key: K,
    flight: Arc<Flight<T, E>>,
    active: bool,
}

impl<'a, K, T, E> LeaderGuard<'a, K, T, E>
where
    K: Clone + Eq + Hash,
{
    fn new(group: &'a Singleflight<K, T, E>, key: K, flight: Arc<Flight<T, E>>) -> Self {
        Self {
            group,
            key,
            flight,
            active: true,
        }
    }

    fn complete(mut self, result: SharedResult<T, E>) {
        if result.is_ok() {
            self.group.metrics.succeeded.fetch_add(1, Ordering::Relaxed);
        } else {
            self.group.metrics.failed.fetch_add(1, Ordering::Relaxed);
        }
        self.flight
            .state
            .send_replace(FlightState::Complete(result));
        self.group.remove_if_current(&self.key, &self.flight);
        self.active = false;
    }
}

impl<K, T, E> Drop for LeaderGuard<'_, K, T, E>
where
    K: Clone + Eq + Hash,
{
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        self.flight.state.send_replace(FlightState::Abandoned);
        self.group.remove_if_current(&self.key, &self.flight);
        self.group.metrics.abandoned.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::{sync::Notify, time};

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn coalesces_concurrent_work() {
        let group = Arc::new(Singleflight::<&'static str, usize, &'static str>::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(Notify::new());
        let mut tasks = Vec::new();

        for _ in 0..12 {
            let group = Arc::clone(&group);
            let calls = Arc::clone(&calls);
            let gate = Arc::clone(&gate);
            tasks.push(tokio::spawn(async move {
                group
                    .run("same-key", || async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        gate.notified().await;
                        Ok(42)
                    })
                    .await
            }));
        }

        while calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        time::timeout(std::time::Duration::from_secs(1), async {
            while group.metrics().shared < 11 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("all followers should join the active flight");
        gate.notify_waiters();

        for task in tasks {
            let result = task.await.expect("singleflight caller should not panic");
            assert_eq!(result.as_ref(), &Ok(42));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let metrics = group.metrics();
        assert_eq!(metrics.started, 1);
        assert_eq!(metrics.shared, 11);
        assert_eq!(metrics.succeeded, 1);
        assert_eq!(metrics.in_flight, 0);
    }

    #[tokio::test]
    async fn canceled_leader_allows_a_replacement() {
        let group = Arc::new(Singleflight::<u8, u8, &'static str>::new());
        let started = Arc::new(Notify::new());
        let leader = {
            let group = Arc::clone(&group);
            let started = Arc::clone(&started);
            tokio::spawn(async move {
                group
                    .run(1, || async move {
                        started.notify_one();
                        std::future::pending::<Result<u8, &'static str>>().await
                    })
                    .await
            })
        };
        started.notified().await;
        leader.abort();
        let _ = leader.await;

        let replacement = time::timeout(
            std::time::Duration::from_secs(1),
            group.run(1, || async { Ok(9) }),
        )
        .await
        .expect("replacement leader should not remain blocked");
        assert_eq!(replacement.as_ref(), &Ok(9));
        assert_eq!(group.metrics().abandoned, 1);
    }

    #[tokio::test]
    async fn shares_errors_without_requiring_clone() {
        #[derive(Debug, Eq, PartialEq)]
        struct NonCloneError(&'static str);

        let group = Singleflight::<u8, u8, NonCloneError>::new();
        let result = group
            .run(1, || async { Err(NonCloneError("failed")) })
            .await;
        assert_eq!(result.as_ref(), &Err(NonCloneError("failed")));
        assert_eq!(group.metrics().failed, 1);
    }
}
