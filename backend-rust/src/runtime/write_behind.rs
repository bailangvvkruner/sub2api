use std::{
    error::Error,
    fmt,
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::Result;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::{self, MissedTickBehavior},
};

const STATE_RUNNING: u8 = 0;
const STATE_SHUTTING_DOWN: u8 = 1;
const STATE_STOPPED: u8 = 2;

pub type BoxFlushFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

/// A durable batch sink. Implementations should make a batch idempotent because
/// a transport error can make it impossible to know whether `PostgreSQL` committed
/// the previous attempt. The returned future must also be cancellation-safe;
/// timed-out attempts are dropped by the framework.
pub trait BatchSink<T>: Send + Sync + 'static {
    fn write_batch<'a>(&'a self, batch: &'a [T]) -> BoxFlushFuture<'a>;
}

impl<T, F> BatchSink<T> for F
where
    T: Sync,
    F: for<'a> Fn(&'a [T]) -> BoxFlushFuture<'a> + Send + Sync + 'static,
{
    fn write_batch<'a>(&'a self, batch: &'a [T]) -> BoxFlushFuture<'a> {
        self(batch)
    }
}

#[derive(Clone, Debug)]
pub struct WriteBehindConfig {
    pub queue_capacity: usize,
    pub batch_size: usize,
    pub flush_interval: Duration,
    pub max_retries: u32,
    pub retry_initial_delay: Duration,
    pub retry_max_delay: Duration,
    pub attempt_timeout: Duration,
    pub shutdown_timeout: Duration,
}

impl Default for WriteBehindConfig {
    fn default() -> Self {
        Self {
            queue_capacity: 1_024,
            batch_size: 100,
            flush_interval: Duration::from_secs(30),
            max_retries: 2,
            retry_initial_delay: Duration::from_millis(100),
            retry_max_delay: Duration::from_secs(2),
            attempt_timeout: Duration::from_secs(3),
            shutdown_timeout: Duration::from_secs(30),
        }
    }
}

impl WriteBehindConfig {
    /// # Errors
    ///
    /// Returns an error for zero capacities/durations or an inverted retry
    /// delay range.
    pub fn validate(&self) -> std::result::Result<(), WriteBehindConfigError> {
        if self.queue_capacity == 0 {
            return Err(WriteBehindConfigError(
                "queue_capacity must be greater than zero",
            ));
        }
        if self.batch_size == 0 {
            return Err(WriteBehindConfigError(
                "batch_size must be greater than zero",
            ));
        }
        if self.flush_interval.is_zero() {
            return Err(WriteBehindConfigError(
                "flush_interval must be greater than zero",
            ));
        }
        if self.retry_initial_delay.is_zero() {
            return Err(WriteBehindConfigError(
                "retry_initial_delay must be greater than zero",
            ));
        }
        if self.retry_max_delay < self.retry_initial_delay {
            return Err(WriteBehindConfigError(
                "retry_max_delay cannot be less than retry_initial_delay",
            ));
        }
        if self.attempt_timeout.is_zero() {
            return Err(WriteBehindConfigError(
                "attempt_timeout must be greater than zero",
            ));
        }
        if self.shutdown_timeout.is_zero() {
            return Err(WriteBehindConfigError(
                "shutdown_timeout must be greater than zero",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteBehindConfigError(&'static str);

impl fmt::Display for WriteBehindConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for WriteBehindConfigError {}

pub enum EnqueueError<T> {
    Full(T),
    Closed(T),
}

impl<T> EnqueueError<T> {
    #[must_use]
    pub fn into_inner(self) -> T {
        match self {
            Self::Full(item) | Self::Closed(item) => item,
        }
    }

    #[must_use]
    pub const fn is_full(&self) -> bool {
        matches!(self, Self::Full(_))
    }
}

impl<T> fmt::Debug for EnqueueError<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Full(_) => "EnqueueError::Full(..)",
            Self::Closed(_) => "EnqueueError::Closed(..)",
        })
    }
}

impl<T> fmt::Display for EnqueueError<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Full(_) => "write-behind queue is full",
            Self::Closed(_) => "write-behind queue is closed",
        })
    }
}

impl<T> Error for EnqueueError<T> {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlushError {
    Sink(String),
    Closed,
}

impl fmt::Display for FlushError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sink(message) => write!(formatter, "write-behind sink failed: {message}"),
            Self::Closed => formatter.write_str("write-behind worker is closed"),
        }
    }
}

impl Error for FlushError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShutdownError {
    WorkerUnavailable,
    WorkerPanicked(String),
    TimedOut(Duration),
}

impl fmt::Display for ShutdownError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkerUnavailable => formatter.write_str("write-behind worker is unavailable"),
            Self::WorkerPanicked(message) => {
                write!(formatter, "write-behind worker failed to join: {message}")
            }
            Self::TimedOut(timeout) => {
                write!(
                    formatter,
                    "write-behind shutdown timed out after {timeout:?}"
                )
            }
        }
    }
}

impl Error for ShutdownError {}

#[derive(Debug)]
pub struct ShutdownReport<T> {
    pub unflushed: Vec<T>,
    pub last_error: Option<String>,
}

impl<T> ShutdownReport<T> {
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.unflushed.is_empty() && self.last_error.is_none()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WriteBehindMetricsSnapshot {
    pub accepted: u64,
    pub rejected_full: u64,
    pub rejected_closed: u64,
    pub pending_items: u64,
    pub high_watermark: u64,
    pub flush_attempts: u64,
    pub successful_flushes: u64,
    pub failed_attempts: u64,
    pub exhausted_flushes: u64,
    pub retry_attempts: u64,
    pub flushed_items: u64,
    pub shutdowns: u64,
    pub abandoned_items: u64,
}

#[derive(Default)]
struct WriteBehindMetrics {
    accepted: AtomicU64,
    rejected_full: AtomicU64,
    rejected_closed: AtomicU64,
    pending_items: AtomicU64,
    high_watermark: AtomicU64,
    flush_attempts: AtomicU64,
    successful_flushes: AtomicU64,
    failed_attempts: AtomicU64,
    exhausted_flushes: AtomicU64,
    retry_attempts: AtomicU64,
    flushed_items: AtomicU64,
    shutdowns: AtomicU64,
    abandoned_items: AtomicU64,
}

impl WriteBehindMetrics {
    fn snapshot(&self) -> WriteBehindMetricsSnapshot {
        WriteBehindMetricsSnapshot {
            accepted: self.accepted.load(Ordering::Relaxed),
            rejected_full: self.rejected_full.load(Ordering::Relaxed),
            rejected_closed: self.rejected_closed.load(Ordering::Relaxed),
            pending_items: self.pending_items.load(Ordering::Relaxed),
            high_watermark: self.high_watermark.load(Ordering::Relaxed),
            flush_attempts: self.flush_attempts.load(Ordering::Relaxed),
            successful_flushes: self.successful_flushes.load(Ordering::Relaxed),
            failed_attempts: self.failed_attempts.load(Ordering::Relaxed),
            exhausted_flushes: self.exhausted_flushes.load(Ordering::Relaxed),
            retry_attempts: self.retry_attempts.load(Ordering::Relaxed),
            flushed_items: self.flushed_items.load(Ordering::Relaxed),
            shutdowns: self.shutdowns.load(Ordering::Relaxed),
            abandoned_items: self.abandoned_items.load(Ordering::Relaxed),
        }
    }

    fn update_high_watermark(&self, value: u64) {
        let mut current = self.high_watermark.load(Ordering::Relaxed);
        while value > current {
            match self.high_watermark.compare_exchange_weak(
                current,
                value,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(actual) => current = actual,
            }
        }
    }
}

enum Control {
    Flush(oneshot::Sender<std::result::Result<(), FlushError>>),
    Shutdown,
}

pub struct WriteBehindSender<T> {
    sender: mpsc::Sender<T>,
    state: Arc<AtomicU8>,
    metrics: Arc<WriteBehindMetrics>,
}

impl<T> Clone for WriteBehindSender<T> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            state: Arc::clone(&self.state),
            metrics: Arc::clone(&self.metrics),
        }
    }
}

impl<T> WriteBehindSender<T> {
    /// Waits for bounded queue capacity and enqueues one item.
    ///
    /// # Errors
    ///
    /// Returns the original item when shutdown closes the queue before it can
    /// be accepted.
    pub async fn enqueue(&self, item: T) -> std::result::Result<(), EnqueueError<T>> {
        if self.state.load(Ordering::Acquire) != STATE_RUNNING {
            self.metrics.rejected_closed.fetch_add(1, Ordering::Relaxed);
            return Err(EnqueueError::Closed(item));
        }
        let Ok(permit) = self.sender.reserve().await else {
            self.metrics.rejected_closed.fetch_add(1, Ordering::Relaxed);
            return Err(EnqueueError::Closed(item));
        };
        if self.state.load(Ordering::Acquire) != STATE_RUNNING {
            self.metrics.rejected_closed.fetch_add(1, Ordering::Relaxed);
            return Err(EnqueueError::Closed(item));
        }

        let pending = self.metrics.pending_items.fetch_add(1, Ordering::Relaxed) + 1;
        permit.send(item);
        self.metrics.accepted.fetch_add(1, Ordering::Relaxed);
        self.metrics.update_high_watermark(pending);
        Ok(())
    }

    /// Attempts to enqueue one item without waiting for capacity.
    ///
    /// # Errors
    ///
    /// Returns the original item when the queue is full or closed.
    pub fn try_enqueue(&self, item: T) -> std::result::Result<(), EnqueueError<T>> {
        if self.state.load(Ordering::Acquire) != STATE_RUNNING {
            self.metrics.rejected_closed.fetch_add(1, Ordering::Relaxed);
            return Err(EnqueueError::Closed(item));
        }
        let permit = match self.sender.try_reserve() {
            Ok(permit) => permit,
            Err(mpsc::error::TrySendError::Full(())) => {
                self.metrics.rejected_full.fetch_add(1, Ordering::Relaxed);
                return Err(EnqueueError::Full(item));
            }
            Err(mpsc::error::TrySendError::Closed(())) => {
                self.metrics.rejected_closed.fetch_add(1, Ordering::Relaxed);
                return Err(EnqueueError::Closed(item));
            }
        };
        if self.state.load(Ordering::Acquire) != STATE_RUNNING {
            self.metrics.rejected_closed.fetch_add(1, Ordering::Relaxed);
            return Err(EnqueueError::Closed(item));
        }

        let pending = self.metrics.pending_items.fetch_add(1, Ordering::Relaxed) + 1;
        permit.send(item);
        self.metrics.accepted.fetch_add(1, Ordering::Relaxed);
        self.metrics.update_high_watermark(pending);
        Ok(())
    }

    #[must_use]
    pub fn metrics(&self) -> WriteBehindMetricsSnapshot {
        self.metrics.snapshot()
    }

    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.state.load(Ordering::Acquire) != STATE_RUNNING || self.sender.is_closed()
    }
}

pub struct WriteBehind<T> {
    sender: WriteBehindSender<T>,
    control: mpsc::Sender<Control>,
    worker: Mutex<Option<JoinHandle<ShutdownReport<T>>>>,
    shutdown_timeout: Duration,
}

impl<T> WriteBehind<T>
where
    T: Send + Sync + 'static,
{
    /// Starts a worker on the current Tokio runtime.
    ///
    /// # Errors
    ///
    /// Returns an error when the queue or timing configuration is invalid.
    pub fn spawn<S>(
        sink: S,
        config: WriteBehindConfig,
    ) -> std::result::Result<Self, WriteBehindConfigError>
    where
        S: BatchSink<T>,
    {
        config.validate()?;
        let (sender, receiver) = mpsc::channel(config.queue_capacity);
        let (control, control_receiver) = mpsc::channel(8);
        let state = Arc::new(AtomicU8::new(STATE_RUNNING));
        let metrics = Arc::new(WriteBehindMetrics::default());
        let worker_state = Arc::clone(&state);
        let worker_metrics = Arc::clone(&metrics);
        let shutdown_timeout = config.shutdown_timeout;
        let worker = tokio::spawn(run_worker(
            receiver,
            control_receiver,
            sink,
            config,
            worker_state,
            worker_metrics,
        ));
        Ok(Self {
            sender: WriteBehindSender {
                sender,
                state,
                metrics,
            },
            control,
            worker: Mutex::new(Some(worker)),
            shutdown_timeout,
        })
    }

    #[must_use]
    pub fn sender(&self) -> WriteBehindSender<T> {
        self.sender.clone()
    }

    /// Waits for bounded queue capacity and enqueues one item.
    ///
    /// # Errors
    ///
    /// Returns the original item when shutdown closes the queue before it can
    /// be accepted.
    pub async fn enqueue(&self, item: T) -> std::result::Result<(), EnqueueError<T>> {
        self.sender.enqueue(item).await
    }

    /// Attempts to enqueue one item without waiting for capacity.
    ///
    /// # Errors
    ///
    /// Returns the original item when the queue is full or closed.
    pub fn try_enqueue(&self, item: T) -> std::result::Result<(), EnqueueError<T>> {
        self.sender.try_enqueue(item)
    }

    /// Flushes the worker's current in-memory batch. Items still waiting in the
    /// bounded producer channel remain ordered for a subsequent batch. Use
    /// `shutdown` when a full queue barrier is required.
    ///
    /// # Errors
    ///
    /// Returns an error when the current batch exhausts sink retries or the
    /// worker has already stopped.
    pub async fn flush_now(&self) -> std::result::Result<(), FlushError> {
        if self.sender.state.load(Ordering::Acquire) != STATE_RUNNING {
            return Err(FlushError::Closed);
        }
        let (reply, result) = oneshot::channel();
        self.control
            .send(Control::Flush(reply))
            .await
            .map_err(|_| FlushError::Closed)?;
        result.await.unwrap_or(Err(FlushError::Closed))
    }

    /// Stops intake, drains the bounded queue, and flushes it in batches. If
    /// `PostgreSQL` remains unavailable after retries, the caller receives every
    /// item that was not confirmed written.
    ///
    /// # Errors
    ///
    /// Returns an error if the worker panics, cannot be joined, or exceeds the
    /// configured shutdown deadline. Sink failures are returned inside a
    /// successful `ShutdownReport` together with the unflushed items.
    pub async fn shutdown(self) -> std::result::Result<ShutdownReport<T>, ShutdownError> {
        self.sender
            .state
            .store(STATE_SHUTTING_DOWN, Ordering::Release);
        let Some(mut worker) = self
            .worker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        else {
            return Err(ShutdownError::WorkerUnavailable);
        };

        let stop_and_join = async {
            let _ = self.control.send(Control::Shutdown).await;
            (&mut worker).await
        };
        match time::timeout(self.shutdown_timeout, stop_and_join).await {
            Ok(Ok(report)) => Ok(report),
            Ok(Err(error)) => {
                self.mark_abandoned();
                Err(ShutdownError::WorkerPanicked(error.to_string()))
            }
            Err(_) => {
                worker.abort();
                let _ = worker.await;
                self.mark_abandoned();
                Err(ShutdownError::TimedOut(self.shutdown_timeout))
            }
        }
    }

    #[must_use]
    pub fn metrics(&self) -> WriteBehindMetricsSnapshot {
        self.sender.metrics()
    }

    fn mark_abandoned(&self) {
        self.sender.state.store(STATE_STOPPED, Ordering::Release);
        let abandoned = self.sender.metrics.pending_items.swap(0, Ordering::Relaxed);
        self.sender
            .metrics
            .abandoned_items
            .fetch_add(abandoned, Ordering::Relaxed);
    }
}

impl<T> Drop for WriteBehind<T> {
    fn drop(&mut self) {
        if self
            .sender
            .state
            .compare_exchange(
                STATE_RUNNING,
                STATE_SHUTTING_DOWN,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            let _ = self.control.try_send(Control::Shutdown);
        }
    }
}

async fn run_worker<T, S>(
    mut receiver: mpsc::Receiver<T>,
    mut control: mpsc::Receiver<Control>,
    sink: S,
    config: WriteBehindConfig,
    state: Arc<AtomicU8>,
    metrics: Arc<WriteBehindMetrics>,
) -> ShutdownReport<T>
where
    T: Send + Sync + 'static,
    S: BatchSink<T>,
{
    let mut pending = Vec::with_capacity(config.batch_size);
    let mut ticker = time::interval(config.flush_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    ticker.tick().await;

    loop {
        if pending.len() >= config.batch_size {
            let error = match control.try_recv() {
                Ok(Control::Flush(reply)) => {
                    let result = flush_pending(&sink, &config, &metrics, &mut pending).await;
                    let error = result.as_ref().err().cloned();
                    let _ = reply.send(result.map_err(FlushError::Sink));
                    error
                }
                Ok(Control::Shutdown) | Err(mpsc::error::TryRecvError::Disconnected) => {
                    return finish_shutdown(receiver, sink, config, state, metrics, pending).await;
                }
                Err(mpsc::error::TryRecvError::Empty) => {
                    flush_pending(&sink, &config, &metrics, &mut pending)
                        .await
                        .err()
                }
            };
            if let Some(error) = error
                && wait_retry_or_shutdown(&mut control, config.retry_max_delay, &error).await
            {
                return finish_shutdown(receiver, sink, config, state, metrics, pending).await;
            }
            continue;
        }

        tokio::select! {
            biased;
            command = control.recv() => {
                match command {
                    Some(Control::Flush(reply)) => {
                        let result = flush_pending(&sink, &config, &metrics, &mut pending)
                            .await
                            .map_err(FlushError::Sink);
                        let _ = reply.send(result);
                    }
                    Some(Control::Shutdown) | None => {
                        return finish_shutdown(receiver, sink, config, state, metrics, pending).await;
                    }
                }
            }
            item = receiver.recv() => {
                match item {
                    Some(item) => pending.push(item),
                    None => {
                        return finish_shutdown(receiver, sink, config, state, metrics, pending).await;
                    }
                }
            }
            _ = ticker.tick() => {
                let _ = flush_pending(&sink, &config, &metrics, &mut pending).await;
            }
        }
    }
}

async fn wait_retry_or_shutdown(
    control: &mut mpsc::Receiver<Control>,
    delay: Duration,
    error: &str,
) -> bool {
    tokio::select! {
        biased;
        command = control.recv() => {
            match command {
                Some(Control::Flush(reply)) => {
                    let _ = reply.send(Err(FlushError::Sink(error.to_owned())));
                    false
                }
                Some(Control::Shutdown) | None => true,
            }
        }
        () = time::sleep(delay) => false,
    }
}

async fn finish_shutdown<T, S>(
    mut receiver: mpsc::Receiver<T>,
    sink: S,
    config: WriteBehindConfig,
    state: Arc<AtomicU8>,
    metrics: Arc<WriteBehindMetrics>,
    mut pending: Vec<T>,
) -> ShutdownReport<T>
where
    T: Send + Sync + 'static,
    S: BatchSink<T>,
{
    receiver.close();
    while let Some(item) = receiver.recv().await {
        pending.push(item);
    }

    while !pending.is_empty() {
        let batch_len = pending.len().min(config.batch_size);
        if let Err(error) = write_with_retry(&sink, &pending[..batch_len], &config, &metrics).await
        {
            state.store(STATE_STOPPED, Ordering::Release);
            metrics.shutdowns.fetch_add(1, Ordering::Relaxed);
            return ShutdownReport {
                unflushed: pending,
                last_error: Some(error),
            };
        }
        pending.drain(..batch_len);
        record_flushed(&metrics, batch_len);
    }

    state.store(STATE_STOPPED, Ordering::Release);
    metrics.shutdowns.fetch_add(1, Ordering::Relaxed);
    ShutdownReport {
        unflushed: Vec::new(),
        last_error: None,
    }
}

async fn flush_pending<T, S>(
    sink: &S,
    config: &WriteBehindConfig,
    metrics: &WriteBehindMetrics,
    pending: &mut Vec<T>,
) -> std::result::Result<(), String>
where
    T: Send + Sync + 'static,
    S: BatchSink<T>,
{
    if pending.is_empty() {
        return Ok(());
    }
    write_with_retry(sink, pending, config, metrics).await?;
    let flushed = pending.len();
    pending.clear();
    record_flushed(metrics, flushed);
    Ok(())
}

async fn write_with_retry<T, S>(
    sink: &S,
    batch: &[T],
    config: &WriteBehindConfig,
    metrics: &WriteBehindMetrics,
) -> std::result::Result<(), String>
where
    T: Sync,
    S: BatchSink<T>,
{
    let mut delay = config.retry_initial_delay;
    for attempt in 0..=config.max_retries {
        metrics.flush_attempts.fetch_add(1, Ordering::Relaxed);
        let error = match time::timeout(config.attempt_timeout, sink.write_batch(batch)).await {
            Ok(Ok(())) => {
                metrics.successful_flushes.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            Ok(Err(error)) => format!("{error:#}"),
            Err(_) => format!("sink attempt timed out after {:?}", config.attempt_timeout),
        };
        metrics.failed_attempts.fetch_add(1, Ordering::Relaxed);
        if attempt == config.max_retries {
            metrics.exhausted_flushes.fetch_add(1, Ordering::Relaxed);
            return Err(error);
        }
        metrics.retry_attempts.fetch_add(1, Ordering::Relaxed);
        time::sleep(delay).await;
        delay = std::cmp::min(delay.saturating_mul(2), config.retry_max_delay);
    }
    unreachable!("the inclusive retry loop always executes at least once")
}

fn record_flushed(metrics: &WriteBehindMetrics, flushed: usize) {
    let flushed = u64::try_from(flushed).unwrap_or(u64::MAX);
    metrics.flushed_items.fetch_add(flushed, Ordering::Relaxed);
    metrics.pending_items.fetch_sub(flushed, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    use anyhow::bail;
    use tokio::sync::Notify;

    use super::*;

    struct RecordingSink {
        values: Arc<Mutex<Vec<u64>>>,
        failures_left: Arc<AtomicUsize>,
    }

    impl BatchSink<u64> for RecordingSink {
        fn write_batch<'a>(&'a self, batch: &'a [u64]) -> BoxFlushFuture<'a> {
            Box::pin(async move {
                if self
                    .failures_left
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                        value.checked_sub(1)
                    })
                    .is_ok()
                {
                    bail!("injected sink failure");
                }
                self.values
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .extend_from_slice(batch);
                Ok(())
            })
        }
    }

    fn test_config() -> WriteBehindConfig {
        WriteBehindConfig {
            queue_capacity: 8,
            batch_size: 4,
            flush_interval: Duration::from_millis(20),
            max_retries: 2,
            retry_initial_delay: Duration::from_millis(1),
            retry_max_delay: Duration::from_millis(4),
            attempt_timeout: Duration::from_millis(100),
            shutdown_timeout: Duration::from_secs(2),
        }
    }

    #[tokio::test]
    async fn periodic_flush_writes_partial_batches() {
        let values = Arc::new(Mutex::new(Vec::new()));
        let writer = WriteBehind::spawn(
            RecordingSink {
                values: Arc::clone(&values),
                failures_left: Arc::new(AtomicUsize::new(0)),
            },
            test_config(),
        )
        .expect("valid writer config");
        writer.enqueue(1).await.expect("enqueue should succeed");

        time::timeout(Duration::from_secs(1), async {
            loop {
                if !values
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .is_empty()
                {
                    break;
                }
                time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("periodic flush should run");

        let report = writer.shutdown().await.expect("shutdown should join");
        assert!(report.is_clean());
        assert_eq!(
            *values
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            vec![1]
        );
    }

    #[tokio::test]
    async fn retries_failed_batches_without_dropping_items() {
        let values = Arc::new(Mutex::new(Vec::new()));
        let failures = Arc::new(AtomicUsize::new(2));
        let mut config = test_config();
        config.batch_size = 1;
        let writer = WriteBehind::spawn(
            RecordingSink {
                values: Arc::clone(&values),
                failures_left: Arc::clone(&failures),
            },
            config,
        )
        .expect("valid writer config");
        writer.enqueue(7).await.expect("enqueue should succeed");

        time::timeout(Duration::from_secs(1), async {
            loop {
                if !values
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .is_empty()
                {
                    break;
                }
                time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("retry should eventually succeed");
        let metrics = writer.metrics();
        assert_eq!(metrics.retry_attempts, 2);
        assert_eq!(metrics.flushed_items, 1);
        assert!(
            writer
                .shutdown()
                .await
                .expect("shutdown should join")
                .is_clean()
        );
    }

    #[tokio::test]
    async fn shutdown_drains_the_full_queue_in_order() {
        let values = Arc::new(Mutex::new(Vec::new()));
        let mut config = test_config();
        config.batch_size = 3;
        config.flush_interval = Duration::from_secs(61);
        let writer = WriteBehind::spawn(
            RecordingSink {
                values: Arc::clone(&values),
                failures_left: Arc::new(AtomicUsize::new(0)),
            },
            config,
        )
        .expect("valid writer config");
        for value in 0..8 {
            writer.enqueue(value).await.expect("enqueue should succeed");
        }

        let report = writer.shutdown().await.expect("shutdown should join");
        assert!(report.is_clean());
        assert_eq!(
            *values
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            (0..8).collect::<Vec<_>>()
        );
    }

    struct GateSink {
        first: AtomicBool,
        started: Arc<Notify>,
        release: Arc<Notify>,
        values: Arc<Mutex<Vec<u64>>>,
    }

    impl BatchSink<u64> for GateSink {
        fn write_batch<'a>(&'a self, batch: &'a [u64]) -> BoxFlushFuture<'a> {
            Box::pin(async move {
                if !self.first.swap(true, Ordering::SeqCst) {
                    self.started.notify_one();
                    self.release.notified().await;
                }
                self.values
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .extend_from_slice(batch);
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn bounded_queue_applies_backpressure() {
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let values = Arc::new(Mutex::new(Vec::new()));
        let mut config = test_config();
        config.queue_capacity = 1;
        config.batch_size = 1;
        let writer = WriteBehind::spawn(
            GateSink {
                first: AtomicBool::new(false),
                started: Arc::clone(&started),
                release: Arc::clone(&release),
                values,
            },
            config,
        )
        .expect("valid writer config");

        writer
            .enqueue(1)
            .await
            .expect("first enqueue should succeed");
        started.notified().await;
        writer
            .enqueue(2)
            .await
            .expect("second enqueue should fill queue");
        assert!(matches!(writer.try_enqueue(3), Err(EnqueueError::Full(3))));
        release.notify_waiters();

        let report = writer.shutdown().await.expect("shutdown should join");
        assert!(report.is_clean());
    }

    #[tokio::test]
    async fn shutdown_returns_items_when_the_sink_stays_down() {
        let mut config = test_config();
        config.max_retries = 1;
        config.batch_size = 1;
        config.flush_interval = Duration::from_secs(61);
        let writer = WriteBehind::spawn(
            RecordingSink {
                values: Arc::new(Mutex::new(Vec::new())),
                failures_left: Arc::new(AtomicUsize::new(usize::MAX)),
            },
            config,
        )
        .expect("valid writer config");
        writer.enqueue(9).await.expect("enqueue should succeed");

        time::timeout(Duration::from_secs(1), async {
            while writer.metrics().failed_attempts == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("worker should enter its retry loop");

        let report = writer
            .shutdown()
            .await
            .expect("worker should return report");
        assert_eq!(report.unflushed, vec![9]);
        assert!(report.last_error.is_some());
    }

    #[test]
    fn default_interval_is_thirty_seconds() {
        assert_eq!(
            WriteBehindConfig::default().flush_interval,
            Duration::from_secs(30)
        );
    }
}
