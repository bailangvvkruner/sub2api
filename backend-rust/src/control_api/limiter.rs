use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use parking_lot::Mutex;

const DEFAULT_MAX_TRACKED_IDENTITIES: usize = 10_000;

#[derive(Clone, Debug)]
pub struct LoginRateLimiter {
    inner: Arc<Mutex<LimiterState>>,
    max_failures: u32,
    window: Duration,
    max_entries: usize,
}

#[derive(Debug, Default)]
struct LimiterState {
    attempts: HashMap<String, AttemptWindow>,
}

#[derive(Clone, Copy, Debug)]
struct AttemptWindow {
    started_at: Instant,
    failures: u32,
}

impl LoginRateLimiter {
    #[must_use]
    pub fn new(max_failures: u32, window: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(LimiterState::default())),
            max_failures: max_failures.max(1),
            window: window.max(Duration::from_secs(1)),
            max_entries: DEFAULT_MAX_TRACKED_IDENTITIES,
        }
    }

    #[must_use]
    pub fn is_limited(&self, identity: &str) -> bool {
        let key = normalize_identity(identity);
        let now = Instant::now();
        let mut state = self.inner.lock();
        let Some(attempt) = state.attempts.get(&key).copied() else {
            return false;
        };
        if now.duration_since(attempt.started_at) >= self.window {
            state.attempts.remove(&key);
            return false;
        }
        attempt.failures >= self.max_failures
    }

    pub fn record_failure(&self, identity: &str) {
        let key = normalize_identity(identity);
        let now = Instant::now();
        let mut state = self.inner.lock();
        if state.attempts.len() >= self.max_entries && !state.attempts.contains_key(&key) {
            state
                .attempts
                .retain(|_, attempt| now.duration_since(attempt.started_at) < self.window);
            if state.attempts.len() >= self.max_entries
                && let Some(oldest) = state
                    .attempts
                    .iter()
                    .min_by_key(|(_, attempt)| attempt.started_at)
                    .map(|(identity, _)| identity.clone())
            {
                state.attempts.remove(&oldest);
            }
        }

        let attempt = state.attempts.entry(key).or_insert(AttemptWindow {
            started_at: now,
            failures: 0,
        });
        if now.duration_since(attempt.started_at) >= self.window {
            *attempt = AttemptWindow {
                started_at: now,
                failures: 1,
            };
        } else {
            attempt.failures = attempt.failures.saturating_add(1);
        }
    }

    pub fn clear(&self, identity: &str) {
        self.inner
            .lock()
            .attempts
            .remove(&normalize_identity(identity));
    }
}

fn normalize_identity(identity: &str) -> String {
    identity.trim().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_normalized_identity_after_configured_failures() {
        let limiter = LoginRateLimiter::new(2, Duration::from_mins(1));
        limiter.record_failure(" User@Example.com ");
        assert!(!limiter.is_limited("user@example.com"));
        limiter.record_failure("user@example.com");
        assert!(limiter.is_limited("USER@example.com"));
        limiter.clear(" user@example.com ");
        assert!(!limiter.is_limited("user@example.com"));
    }
}
