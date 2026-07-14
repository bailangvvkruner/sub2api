//! L1 and `PostgreSQL` runtime primitives for the Redis-free backend.
//!
//! The modules in this directory are deliberately storage-agnostic. Durable
//! correctness remains the responsibility of `PostgreSQL`; these helpers only
//! provide bounded process-local acceleration and write coalescing.

mod l1;
mod singleflight;
mod write_behind;

pub use l1::{CacheMetricsSnapshot, L1Cache};
pub use singleflight::{SharedResult, Singleflight, SingleflightMetricsSnapshot};
pub use write_behind::{
    BatchSink, BoxFlushFuture, EnqueueError, FlushError, ShutdownError, ShutdownReport,
    WriteBehind, WriteBehindConfig, WriteBehindConfigError, WriteBehindMetricsSnapshot,
    WriteBehindSender,
};
