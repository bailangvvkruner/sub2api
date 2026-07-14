use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    hash::Hash,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use super::singleflight::{SharedResult, Singleflight};

/// A bounded, process-local cache with per-entry expiry and approximate LRU
/// eviction. Values are cloned out so no lock is held by callers.
pub struct L1Cache<K, V> {
    capacity: usize,
    default_ttl: Duration,
    inner: Mutex<CacheInner<K, V>>,
    metrics: CacheMetrics,
}

struct CacheInner<K, V> {
    entries: HashMap<K, CacheEntry<V>>,
    order: VecDeque<(K, u64)>,
    sequence: u64,
}

struct CacheEntry<V> {
    value: V,
    // `None` means the requested TTL exceeds this platform's Instant range and
    // is therefore effectively bounded by capacity eviction instead.
    expires_at: Option<Instant>,
    generation: u64,
}

#[derive(Default)]
struct CacheMetrics {
    hits: AtomicU64,
    misses: AtomicU64,
    inserts: AtomicU64,
    evictions: AtomicU64,
    expirations: AtomicU64,
    invalidations: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CacheMetricsSnapshot {
    pub hits: u64,
    pub misses: u64,
    pub inserts: u64,
    pub evictions: u64,
    pub expirations: u64,
    pub invalidations: u64,
    pub entries: usize,
}

impl<K, V> L1Cache<K, V>
where
    K: Clone + Eq + Hash,
    V: Clone,
{
    #[must_use]
    pub fn new(capacity: usize, default_ttl: Duration) -> Self {
        Self {
            capacity,
            default_ttl,
            inner: Mutex::new(CacheInner {
                entries: HashMap::with_capacity(capacity),
                order: VecDeque::with_capacity(capacity),
                sequence: 0,
            }),
            metrics: CacheMetrics::default(),
        }
    }

    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    #[must_use]
    pub const fn default_ttl(&self) -> Duration {
        self.default_ttl
    }

    pub fn get(&self, key: &K) -> Option<V> {
        let now = Instant::now();
        let mut inner = self.lock_inner();
        let Some(entry) = inner.entries.get(key) else {
            self.metrics.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        if entry.expires_at.is_some_and(|expires_at| expires_at <= now) {
            inner.entries.remove(key);
            self.metrics.misses.fetch_add(1, Ordering::Relaxed);
            self.metrics.expirations.fetch_add(1, Ordering::Relaxed);
            Self::compact_if_needed(&mut inner, self.capacity);
            return None;
        }

        let value = entry.value.clone();
        let generation = Self::next_generation(&mut inner);
        if let Some(entry) = inner.entries.get_mut(key) {
            entry.generation = generation;
        }
        inner.order.push_back((key.clone(), generation));
        Self::compact_if_needed(&mut inner, self.capacity);
        self.metrics.hits.fetch_add(1, Ordering::Relaxed);
        Some(value)
    }

    /// Returns an L1 hit immediately, otherwise coalesces concurrent loads for
    /// the key and inserts the successful result using the default TTL.
    pub async fn get_or_load<E, F, Fut>(
        &self,
        flights: &Singleflight<K, V, E>,
        key: K,
        load: F,
    ) -> SharedResult<V, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<V, E>>,
    {
        if let Some(value) = self.get(&key) {
            return Arc::new(Ok(value));
        }

        let load_key = key.clone();
        flights
            .run(key, || async move {
                let value = load().await?;
                self.insert(load_key, value.clone());
                Ok(value)
            })
            .await
    }

    pub fn insert(&self, key: K, value: V) -> Option<V> {
        self.insert_with_ttl(key, value, self.default_ttl)
    }

    pub fn insert_with_ttl(&self, key: K, value: V, ttl: Duration) -> Option<V> {
        let now = Instant::now();
        let mut inner = self.lock_inner();
        let previous = inner.entries.remove(&key).and_then(|entry| {
            if entry.expires_at.is_some_and(|expires_at| expires_at <= now) {
                self.metrics.expirations.fetch_add(1, Ordering::Relaxed);
                None
            } else {
                Some(entry.value)
            }
        });

        // A zero-capacity cache and a zero TTL are useful ways to disable L1
        // without changing call sites.
        if self.capacity == 0 || ttl.is_zero() {
            Self::compact_if_needed(&mut inner, self.capacity);
            return previous;
        }

        let generation = Self::next_generation(&mut inner);
        inner.entries.insert(
            key.clone(),
            CacheEntry {
                value,
                expires_at: now.checked_add(ttl),
                generation,
            },
        );
        inner.order.push_back((key, generation));
        self.metrics.inserts.fetch_add(1, Ordering::Relaxed);
        self.evict_to_capacity(&mut inner);
        Self::compact_if_needed(&mut inner, self.capacity);
        previous
    }

    pub fn remove(&self, key: &K) -> Option<V> {
        let now = Instant::now();
        let mut inner = self.lock_inner();
        let removed = inner.entries.remove(key);
        Self::compact_if_needed(&mut inner, self.capacity);
        match removed {
            Some(entry) if entry.expires_at.is_none_or(|expires_at| expires_at > now) => {
                self.metrics.invalidations.fetch_add(1, Ordering::Relaxed);
                Some(entry.value)
            }
            Some(_) => {
                self.metrics.expirations.fetch_add(1, Ordering::Relaxed);
                None
            }
            None => None,
        }
    }

    /// Invalidates every live entry accepted by `predicate` and returns the
    /// number removed. This is intended for bounded secondary-key
    /// invalidation where maintaining another index would cost more than a
    /// rare cache scan.
    pub fn remove_where<F>(&self, mut predicate: F) -> usize
    where
        F: FnMut(&K, &V) -> bool,
    {
        let now = Instant::now();
        let mut inner = self.lock_inner();
        let matching = inner
            .entries
            .iter()
            .filter(|(key, entry)| {
                entry.expires_at.is_none_or(|expires_at| expires_at > now)
                    && predicate(key, &entry.value)
            })
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in &matching {
            inner.entries.remove(key);
        }
        if !matching.is_empty() {
            let removed = u64::try_from(matching.len()).unwrap_or(u64::MAX);
            self.metrics
                .invalidations
                .fetch_add(removed, Ordering::Relaxed);
            Self::compact_if_needed(&mut inner, self.capacity);
        }
        matching.len()
    }

    pub fn clear(&self) {
        let mut inner = self.lock_inner();
        let removed = inner.entries.len();
        inner.entries.clear();
        inner.order.clear();
        let removed = u64::try_from(removed).unwrap_or(u64::MAX);
        self.metrics
            .invalidations
            .fetch_add(removed, Ordering::Relaxed);
    }

    pub fn prune_expired(&self) -> usize {
        let now = Instant::now();
        let mut inner = self.lock_inner();
        let before = inner.entries.len();
        inner
            .entries
            .retain(|_, entry| entry.expires_at.is_none_or(|expires_at| expires_at > now));
        let removed = before - inner.entries.len();
        if removed > 0 {
            let removed_count = u64::try_from(removed).unwrap_or(u64::MAX);
            self.metrics
                .expirations
                .fetch_add(removed_count, Ordering::Relaxed);
            Self::rebuild_order(&mut inner);
        }
        removed
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.prune_expired();
        self.lock_inner().entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[must_use]
    pub fn metrics(&self) -> CacheMetricsSnapshot {
        CacheMetricsSnapshot {
            hits: self.metrics.hits.load(Ordering::Relaxed),
            misses: self.metrics.misses.load(Ordering::Relaxed),
            inserts: self.metrics.inserts.load(Ordering::Relaxed),
            evictions: self.metrics.evictions.load(Ordering::Relaxed),
            expirations: self.metrics.expirations.load(Ordering::Relaxed),
            invalidations: self.metrics.invalidations.load(Ordering::Relaxed),
            entries: self.len(),
        }
    }

    fn lock_inner(&self) -> std::sync::MutexGuard<'_, CacheInner<K, V>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn next_generation(inner: &mut CacheInner<K, V>) -> u64 {
        inner.sequence = inner.sequence.wrapping_add(1).max(1);
        inner.sequence
    }

    fn evict_to_capacity(&self, inner: &mut CacheInner<K, V>) {
        while inner.entries.len() > self.capacity {
            let mut evicted = false;
            while let Some((key, generation)) = inner.order.pop_front() {
                if inner
                    .entries
                    .get(&key)
                    .is_some_and(|entry| entry.generation == generation)
                {
                    inner.entries.remove(&key);
                    self.metrics.evictions.fetch_add(1, Ordering::Relaxed);
                    evicted = true;
                    break;
                }
            }
            if !evicted {
                let Some(key) = inner.entries.keys().next().cloned() else {
                    break;
                };
                inner.entries.remove(&key);
                self.metrics.evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn compact_if_needed(inner: &mut CacheInner<K, V>, capacity: usize) {
        let threshold = capacity.saturating_mul(4).max(64);
        if inner.order.len() > threshold {
            Self::rebuild_order(inner);
        }
    }

    fn rebuild_order(inner: &mut CacheInner<K, V>) {
        let mut current = inner
            .entries
            .iter()
            .map(|(key, entry)| (entry.generation, key.clone()))
            .collect::<Vec<_>>();
        current.sort_unstable_by_key(|(generation, _)| *generation);
        inner.order = current
            .into_iter()
            .map(|(generation, key)| (key, generation))
            .collect();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, atomic::AtomicUsize},
        thread,
    };

    use super::*;

    #[test]
    fn evicts_the_least_recently_used_entry() {
        let cache = L1Cache::new(2, Duration::from_secs(90));
        cache.insert("a", 1);
        cache.insert("b", 2);
        assert_eq!(cache.get(&"a"), Some(1));

        cache.insert("c", 3);

        assert_eq!(cache.get(&"a"), Some(1));
        assert_eq!(cache.get(&"b"), None);
        assert_eq!(cache.get(&"c"), Some(3));
        assert_eq!(cache.metrics().evictions, 1);
    }

    #[test]
    fn expires_entries_and_tracks_misses() {
        let cache = L1Cache::new(4, Duration::from_secs(90));
        cache.insert_with_ttl("short", 7, Duration::from_millis(5));
        thread::sleep(Duration::from_millis(20));

        assert_eq!(cache.get(&"short"), None);
        let metrics = cache.metrics();
        assert_eq!(metrics.expirations, 1);
        assert_eq!(metrics.misses, 1);
        assert_eq!(metrics.entries, 0);
    }

    #[test]
    fn supports_concurrent_access_without_exceeding_capacity() {
        let cache = Arc::new(L1Cache::new(64, Duration::from_secs(90)));
        let threads = (0..8)
            .map(|worker| {
                let cache = Arc::clone(&cache);
                thread::spawn(move || {
                    for offset in 0..100 {
                        let key = worker * 100 + offset;
                        cache.insert(key, key);
                        let _ = cache.get(&key);
                    }
                })
            })
            .collect::<Vec<_>>();
        for worker in threads {
            worker.join().expect("cache worker should not panic");
        }

        assert!(cache.len() <= cache.capacity());
        assert!(cache.metrics().hits > 0);
    }

    #[test]
    fn zero_capacity_disables_storage() {
        let cache = L1Cache::new(0, Duration::from_secs(90));
        cache.insert("key", 1);
        assert_eq!(cache.get(&"key"), None);
        assert!(cache.is_empty());
    }

    #[test]
    fn removes_entries_by_secondary_value_predicate() {
        let cache = L1Cache::new(4, Duration::from_secs(90));
        cache.insert("first", (7, "a"));
        cache.insert("second", (8, "b"));
        cache.insert("third", (7, "c"));

        assert_eq!(cache.remove_where(|_, value| value.0 == 7), 2);
        assert_eq!(cache.get(&"first"), None);
        assert_eq!(cache.get(&"second"), Some((8, "b")));
        assert_eq!(cache.get(&"third"), None);
        assert_eq!(cache.metrics().invalidations, 2);
    }

    #[test]
    fn oversized_ttl_does_not_overflow_instant() {
        let cache = L1Cache::new(1, Duration::MAX);
        cache.insert("key", 1);
        assert_eq!(cache.get(&"key"), Some(1));
    }

    #[tokio::test]
    async fn get_or_load_is_l1_first() {
        let cache = L1Cache::new(4, Duration::from_secs(90));
        let flights = Singleflight::<&str, usize, &str>::new();
        let loads = AtomicUsize::new(0);

        let first = cache
            .get_or_load(&flights, "key", || async {
                loads.fetch_add(1, Ordering::SeqCst);
                Ok(7)
            })
            .await;
        let second = cache
            .get_or_load(&flights, "key", || async {
                loads.fetch_add(1, Ordering::SeqCst);
                Ok(99)
            })
            .await;

        assert_eq!(first.as_ref(), &Ok(7));
        assert_eq!(second.as_ref(), &Ok(7));
        assert_eq!(loads.load(Ordering::SeqCst), 1);
    }
}
