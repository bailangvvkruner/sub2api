//! Exact token billing and PostgreSQL-backed durable accounting.

mod decimal;
mod event;
mod observer;
mod pending;
mod postgres;
mod pricing;
mod usage;

pub use decimal::{Decimal, DecimalError};
pub use event::{BillingEvent, BillingEventError, RequestType, request_fingerprint};
pub use observer::{BillingContext, BillingObservationError, BillingObserver, SseBillingObserver};
pub use pending::{
    BillingInvalidation, BillingInvalidator, PendingBilling, PendingBillingError,
    PendingBillingKeyCounts, PendingBillingQueue, PendingBillingSink, PendingEnqueueError,
    PendingReservation, ReserveStatus,
};
pub use postgres::PostgresBillingSink;
pub(crate) use pricing::active_pricing_source;
pub use pricing::{
    BillingPricingInterval, BillingPricingMode, BillingPricingOverride, CostBreakdown,
    ModelPricing, PricingCatalog, PricingError, active_model_pricing,
    replace_active_pricing_catalog,
};
pub use usage::{
    SseUsageAccumulator, TokenUsage, UsageError, UsageProvider, parse_json_usage, parse_sse_usage,
    parse_usage,
};
