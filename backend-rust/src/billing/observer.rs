use std::{error::Error, fmt, sync::Arc};

use parking_lot::RwLock;

use super::{
    BillingEvent, BillingEventError, BillingPricingOverride, Decimal, PricingCatalog, PricingError,
    RequestType, SseUsageAccumulator, TokenUsage, UsageError, UsageProvider, parse_json_usage,
    pricing::active_pricing_catalog,
};

#[derive(Clone, Debug)]
pub struct BillingObserver {
    catalog: Arc<RwLock<Arc<PricingCatalog>>>,
}

impl BillingObserver {
    #[must_use]
    pub fn new(catalog: PricingCatalog) -> Self {
        Self {
            catalog: Arc::new(RwLock::new(Arc::new(catalog))),
        }
    }

    /// Loads the bundled model catalog.
    ///
    /// # Errors
    ///
    /// Returns an error when the bundled catalog is invalid.
    pub fn bundled() -> Result<Self, PricingError> {
        active_pricing_catalog().map(|catalog| Self { catalog })
    }

    /// Verifies model and base pricing before an upstream request is sent.
    ///
    /// # Errors
    ///
    /// Returns an error when the model is unknown or lacks an input/output
    /// price.
    pub fn preflight_model(&self, model: &str) -> Result<(), PricingError> {
        self.catalog.read().validate_base_prices(model)
    }

    /// Verifies the effective model price after an optional channel override.
    ///
    /// # Errors
    ///
    /// Returns an error when neither global nor channel pricing can bill the
    /// request.
    pub fn preflight_model_with_override(
        &self,
        model: &str,
        pricing_override: Option<&BillingPricingOverride>,
    ) -> Result<(), PricingError> {
        self.catalog
            .read()
            .validate_with_override(model, pricing_override)
    }

    /// Builds a billing event from a successful buffered JSON response.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed usage, missing pricing, arithmetic
    /// overflow, or invalid event metadata.
    pub fn observe_json(
        &self,
        provider: UsageProvider,
        context: BillingContext,
        body: &[u8],
        duration_ms: Option<i32>,
    ) -> Result<BillingEvent, BillingObservationError> {
        let usage = parse_json_usage(provider, body)?;
        self.observe_usage(context, usage, duration_ms)
    }

    /// Builds a billing event from normalized token usage.
    ///
    /// # Errors
    ///
    /// Returns an error for missing pricing, arithmetic overflow, or invalid
    /// event metadata.
    pub fn observe_usage(
        &self,
        context: BillingContext,
        usage: TokenUsage,
        duration_ms: Option<i32>,
    ) -> Result<BillingEvent, BillingObservationError> {
        let catalog = self.catalog.read().clone();
        let costs = catalog.calculate_with_override(
            &context.model,
            usage,
            context.group_multiplier,
            context.account_multiplier,
            context.pricing_override.as_ref(),
        )?;
        let billing_mode = context
            .pricing_override
            .as_ref()
            .map_or("token", |pricing| pricing.mode.as_str());
        let event = BillingEvent {
            request_id: context.request_id,
            request_fingerprint: context.request_fingerprint,
            user_id: context.user_id,
            api_key_id: context.api_key_id,
            account_id: context.account_id,
            group_id: context.group_id,
            channel_id: context.channel_id,
            platform: context.platform,
            model: context.model,
            model_mapping_chain: context.model_mapping_chain,
            billing_mode: billing_mode.to_owned(),
            usage,
            costs,
            group_multiplier: context.group_multiplier,
            account_multiplier: context.account_multiplier,
            stream: context.stream,
            request_type: context.request_type,
            duration_ms,
        };
        event.validate()?;
        Ok(event)
    }

    #[must_use]
    pub fn start_sse(
        &self,
        provider: UsageProvider,
        context: BillingContext,
    ) -> SseBillingObserver {
        SseBillingObserver {
            observer: self.clone(),
            accumulator: SseUsageAccumulator::new(provider),
            context,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BillingContext {
    pub request_id: String,
    pub request_fingerprint: String,
    pub user_id: i64,
    pub api_key_id: i64,
    pub account_id: i64,
    pub group_id: Option<i64>,
    pub channel_id: Option<i64>,
    pub platform: String,
    pub model: String,
    pub model_mapping_chain: Option<String>,
    pub pricing_override: Option<BillingPricingOverride>,
    pub group_multiplier: Decimal,
    pub account_multiplier: Decimal,
    pub stream: bool,
    pub request_type: RequestType,
}

#[derive(Debug)]
pub struct SseBillingObserver {
    observer: BillingObserver,
    accumulator: SseUsageAccumulator,
    context: BillingContext,
}

impl SseBillingObserver {
    /// Observes one upstream SSE byte chunk.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or oversized SSE usage data.
    pub fn push(&mut self, chunk: &[u8]) -> Result<(), UsageError> {
        self.accumulator.push(chunk)
    }

    /// Finalizes usage and builds the durable billing event.
    ///
    /// # Errors
    ///
    /// Returns an error for missing/malformed usage, pricing failures, or
    /// invalid event metadata.
    pub fn finish(self, duration_ms: Option<i32>) -> Result<BillingEvent, BillingObservationError> {
        let usage = self.accumulator.finish()?;
        self.observer
            .observe_usage(self.context, usage, duration_ms)
    }
}

#[derive(Debug)]
pub enum BillingObservationError {
    Usage(UsageError),
    Pricing(PricingError),
    Event(BillingEventError),
}

impl fmt::Display for BillingObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(error) => write!(formatter, "extract billing usage: {error}"),
            Self::Pricing(error) => write!(formatter, "calculate billing cost: {error}"),
            Self::Event(error) => write!(formatter, "build billing event: {error}"),
        }
    }
}

impl Error for BillingObservationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Usage(error) => Some(error),
            Self::Pricing(error) => Some(error),
            Self::Event(error) => Some(error),
        }
    }
}

impl From<UsageError> for BillingObservationError {
    fn from(error: UsageError) -> Self {
        Self::Usage(error)
    }
}

impl From<PricingError> for BillingObservationError {
    fn from(error: PricingError) -> Self {
        Self::Pricing(error)
    }
}

impl From<BillingEventError> for BillingObservationError {
    fn from(error: BillingEventError) -> Self {
        Self::Event(error)
    }
}
