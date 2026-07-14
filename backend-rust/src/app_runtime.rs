use std::{hash::Hash, sync::Arc, time::Duration};

use crate::runtime::{
    BatchSink, EnqueueError, FlushError, L1Cache, ShutdownError, ShutdownReport, WriteBehind,
    WriteBehindConfig, WriteBehindConfigError, WriteBehindSender,
};

pub const DEFAULT_WRITE_BEHIND_FLUSH_INTERVAL: Duration = Duration::from_secs(30);

/// Conservative process-local cache and write-behind lifecycle defaults.
///
/// The write-behind flush interval is intentionally not configurable here. It
/// remains exactly 30 seconds so applications cannot accidentally extend the
/// acknowledged-but-not-durable window through this wrapper.
#[derive(Clone, Debug)]
pub struct AppRuntimeConfig {
    pub l1_capacity: usize,
    pub l1_ttl: Duration,
    pub write_queue_capacity: usize,
    pub write_batch_size: usize,
    pub shutdown_timeout: Duration,
}

impl AppRuntimeConfig {
    #[must_use]
    pub const fn write_behind_flush_interval() -> Duration {
        DEFAULT_WRITE_BEHIND_FLUSH_INTERVAL
    }

    fn write_behind_config(&self) -> WriteBehindConfig {
        WriteBehindConfig {
            queue_capacity: self.write_queue_capacity,
            batch_size: self.write_batch_size,
            flush_interval: DEFAULT_WRITE_BEHIND_FLUSH_INTERVAL,
            shutdown_timeout: self.shutdown_timeout,
            ..WriteBehindConfig::default()
        }
    }
}

impl Default for AppRuntimeConfig {
    fn default() -> Self {
        Self {
            l1_capacity: 4_096,
            l1_ttl: Duration::from_secs(30),
            write_queue_capacity: 1_024,
            write_batch_size: 100,
            shutdown_timeout: Duration::from_secs(30),
        }
    }
}

/// Owns one bounded L1 cache and one durable write-behind worker.
///
/// Dropping this value only requests best-effort worker shutdown. Call
/// [`Self::shutdown`] on every normal application exit to stop intake, drain
/// all accepted items, and observe any unflushed records.
pub struct AppRuntime<Key, Value, Item> {
    l1: Arc<L1Cache<Key, Value>>,
    writes: WriteBehind<Item>,
}

impl<Key, Value, Item> AppRuntime<Key, Value, Item>
where
    Key: Clone + Eq + Hash,
    Value: Clone,
    Item: Send + Sync + 'static,
{
    /// Starts the write-behind worker on the current Tokio runtime.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid queue, batch, or shutdown configuration.
    pub fn start<S>(sink: S, config: &AppRuntimeConfig) -> Result<Self, WriteBehindConfigError>
    where
        S: BatchSink<Item>,
    {
        let l1 = Arc::new(L1Cache::new(config.l1_capacity, config.l1_ttl));
        let writes = WriteBehind::spawn(sink, config.write_behind_config())?;
        Ok(Self { l1, writes })
    }

    #[must_use]
    pub fn l1(&self) -> &L1Cache<Key, Value> {
        &self.l1
    }

    #[must_use]
    pub fn l1_handle(&self) -> Arc<L1Cache<Key, Value>> {
        Arc::clone(&self.l1)
    }

    #[must_use]
    pub fn write_sender(&self) -> WriteBehindSender<Item> {
        self.writes.sender()
    }

    /// Waits for queue capacity and accepts one durable update.
    ///
    /// # Errors
    ///
    /// Returns the original item when shutdown has closed intake.
    pub async fn enqueue(&self, item: Item) -> Result<(), EnqueueError<Item>> {
        self.writes.enqueue(item).await
    }

    /// Flushes the worker's current batch without stopping intake.
    ///
    /// # Errors
    ///
    /// Returns an error when `PostgreSQL` retries are exhausted or the worker is
    /// already closed.
    pub async fn flush_now(&self) -> Result<(), FlushError> {
        self.writes.flush_now().await
    }

    /// Stops intake, drains every accepted queue item, and then clears L1.
    ///
    /// A successful return can still contain unflushed items when the durable
    /// sink exhausted its retries; callers must inspect `ShutdownReport` before
    /// declaring a clean shutdown.
    ///
    /// # Errors
    ///
    /// Returns an error when the worker panics or exceeds the shutdown deadline.
    pub async fn shutdown(self) -> Result<ShutdownReport<Item>, ShutdownError> {
        let Self { l1, writes } = self;
        let result = writes.shutdown().await;
        l1.clear();
        result
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use anyhow::Result as AnyResult;

    use super::*;
    use crate::runtime::BoxFlushFuture;

    struct RecordingSink {
        items: Arc<Mutex<Vec<u64>>>,
    }

    impl BatchSink<u64> for RecordingSink {
        fn write_batch<'a>(&'a self, batch: &'a [u64]) -> BoxFlushFuture<'a> {
            Box::pin(async move {
                self.items
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .extend_from_slice(batch);
                AnyResult::Ok(())
            })
        }
    }

    #[test]
    fn default_flush_interval_is_strictly_thirty_seconds() {
        assert_eq!(
            AppRuntimeConfig::write_behind_flush_interval(),
            Duration::from_secs(30)
        );
        let config = AppRuntimeConfig::default();
        assert_eq!(
            config.write_behind_config().flush_interval,
            Duration::from_secs(30)
        );
    }

    #[tokio::test]
    async fn shutdown_drains_writes_closes_senders_and_clears_l1() {
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let runtime = AppRuntime::<String, String, u64>::start(
            RecordingSink {
                items: Arc::clone(&recorded),
            },
            &AppRuntimeConfig::default(),
        )
        .expect("runtime should start");
        runtime.l1().insert("key".to_owned(), "cached".to_owned());
        let l1 = runtime.l1_handle();
        let sender = runtime.write_sender();
        runtime.enqueue(1).await.expect("first item should enqueue");
        runtime
            .enqueue(2)
            .await
            .expect("second item should enqueue");

        let report = runtime.shutdown().await.expect("shutdown should join");

        assert!(report.is_clean());
        assert!(l1.is_empty());
        assert!(sender.try_enqueue(3).is_err());
        assert_eq!(
            *recorded
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            [1, 2]
        );
    }
}
