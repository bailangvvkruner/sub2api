use std::{
    collections::HashMap,
    error::Error,
    fmt,
    str::FromStr,
    sync::{Arc, OnceLock},
};

use parking_lot::RwLock;

use super::{Decimal, DecimalError, TokenUsage};

const BUNDLED_PRICES: &str =
    include_str!("../../resources/model-pricing/model_prices_and_context_window.json");
const MAX_JSON_DEPTH: usize = 128;

type SharedPricingCatalog = Arc<RwLock<Arc<PricingCatalog>>>;
static ACTIVE_PRICING_CATALOG: OnceLock<SharedPricingCatalog> = OnceLock::new();

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ModelPricing {
    pub input_cost_per_token: Option<Decimal>,
    pub output_cost_per_token: Option<Decimal>,
    pub cache_creation_input_token_cost: Option<Decimal>,
    pub cache_read_input_token_cost: Option<Decimal>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum BillingPricingMode {
    #[default]
    Token,
    PerRequest,
    Image,
}

impl BillingPricingMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::PerRequest => "per_request",
            Self::Image => "image",
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BillingPricingInterval {
    pub min_tokens: u64,
    pub max_tokens: Option<u64>,
    pub pricing: ModelPricing,
    pub per_request_price: Option<Decimal>,
}

impl BillingPricingInterval {
    #[must_use]
    pub fn matches(&self, total_context_tokens: u64) -> bool {
        total_context_tokens > self.min_tokens
            && self
                .max_tokens
                .is_none_or(|maximum| total_context_tokens <= maximum)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BillingPricingOverride {
    pub mode: BillingPricingMode,
    pub pricing: ModelPricing,
    pub per_request_price: Option<Decimal>,
    pub intervals: Vec<BillingPricingInterval>,
}

#[allow(clippy::struct_field_names)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CostBreakdown {
    pub input_cost: Decimal,
    pub output_cost: Decimal,
    pub cache_creation_cost: Decimal,
    pub cache_read_cost: Decimal,
    pub total_cost: Decimal,
    pub actual_cost: Decimal,
    pub account_cost: Decimal,
}

#[derive(Clone, Debug, Default)]
pub struct PricingCatalog {
    models: HashMap<String, ModelPricing>,
    source: Arc<str>,
}

impl PricingCatalog {
    /// Parses a model-pricing catalog without converting JSON numbers through
    /// floating point.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed JSON, duplicate model/price fields,
    /// negative prices, or prices outside the fixed-point range.
    pub fn from_json(source: &str) -> Result<Self, PricingError> {
        let mut catalog = CatalogParser::new(source).parse()?;
        catalog.source = Arc::from(source);
        Ok(catalog)
    }

    /// Loads the pricing catalog bundled with the Go backend.
    ///
    /// # Errors
    ///
    /// Returns an error if the bundled catalog violates the same constraints as
    /// [`Self::from_json`].
    pub fn bundled() -> Result<Self, PricingError> {
        Self::from_json(BUNDLED_PRICES)
    }

    #[must_use]
    pub fn get(&self, model: &str) -> Option<&ModelPricing> {
        self.models.get(model)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.models.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.models.is_empty()
    }

    /// Verifies that a model can be billed before an upstream request starts.
    ///
    /// Input and output prices are required because either category can be
    /// produced by a successful request. Cache prices remain response-driven:
    /// they are required by [`Self::calculate`] only when the provider reports
    /// tokens in that category.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown model or a missing input/output price.
    pub fn validate_base_prices(&self, model: &str) -> Result<(), PricingError> {
        let pricing = self
            .get(model)
            .ok_or_else(|| PricingError::UnknownModel(model.to_owned()))?;
        require_price(model, "input", pricing.input_cost_per_token)?;
        require_price(model, "output", pricing.output_cost_per_token)?;
        Ok(())
    }

    /// Calculates token costs using exact fixed-point prices.
    ///
    /// Missing prices fail closed when the corresponding token category is
    /// nonzero. An explicitly configured zero price remains valid.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown model, a required missing price,
    /// negative multipliers, or arithmetic overflow.
    pub fn calculate(
        &self,
        model: &str,
        usage: TokenUsage,
        group_multiplier: Decimal,
        account_multiplier: Decimal,
    ) -> Result<CostBreakdown, PricingError> {
        let pricing = self
            .get(model)
            .ok_or_else(|| PricingError::UnknownModel(model.to_owned()))?;
        calculate_token_cost(model, *pricing, usage, group_multiplier, account_multiplier)
    }

    /// Verifies the effective base price after applying a channel override.
    /// Unknown globally-priced models are valid when the channel explicitly
    /// owns their pricing; unspecified channel fields are treated as free.
    ///
    /// # Errors
    ///
    /// Returns an error when the selected pricing mode has no usable price.
    pub fn validate_with_override(
        &self,
        model: &str,
        pricing_override: Option<&BillingPricingOverride>,
    ) -> Result<(), PricingError> {
        let Some(pricing_override) = pricing_override else {
            return self.validate_base_prices(model);
        };
        match pricing_override.mode {
            BillingPricingMode::Token => {
                let pricing = effective_base_pricing(self.get(model).copied(), pricing_override);
                require_price(model, "input", pricing.input_cost_per_token)?;
                require_price(model, "output", pricing.output_cost_per_token)?;
                Ok(())
            }
            BillingPricingMode::PerRequest | BillingPricingMode::Image => {
                if pricing_override.per_request_price.is_some()
                    || pricing_override
                        .intervals
                        .iter()
                        .any(|interval| interval.per_request_price.is_some())
                {
                    Ok(())
                } else {
                    Err(PricingError::MissingPrice {
                        model: model.to_owned(),
                        category: "per request",
                    })
                }
            }
        }
    }

    /// Calculates a cost with channel pricing taking precedence over the
    /// bundled model catalog.
    ///
    /// # Errors
    ///
    /// Returns an error for incomplete prices, invalid multipliers, or
    /// arithmetic overflow.
    pub fn calculate_with_override(
        &self,
        model: &str,
        usage: TokenUsage,
        group_multiplier: Decimal,
        account_multiplier: Decimal,
        pricing_override: Option<&BillingPricingOverride>,
    ) -> Result<CostBreakdown, PricingError> {
        let Some(pricing_override) = pricing_override else {
            return self.calculate(model, usage, group_multiplier, account_multiplier);
        };
        match pricing_override.mode {
            BillingPricingMode::Token => {
                let total_context_tokens = usage
                    .input_tokens
                    .saturating_add(usage.cache_creation_input_tokens)
                    .saturating_add(usage.cache_read_input_tokens);
                let pricing = if pricing_override.intervals.is_empty() {
                    effective_base_pricing(self.get(model).copied(), pricing_override)
                } else if let Some(interval) = pricing_override
                    .intervals
                    .iter()
                    .find(|interval| interval.matches(total_context_tokens))
                {
                    overlay_pricing(zero_model_pricing(), interval.pricing)
                } else {
                    self.get(model).copied().unwrap_or_else(zero_model_pricing)
                };
                calculate_token_cost(model, pricing, usage, group_multiplier, account_multiplier)
            }
            BillingPricingMode::PerRequest | BillingPricingMode::Image => {
                let total_context_tokens = usage
                    .input_tokens
                    .saturating_add(usage.cache_creation_input_tokens)
                    .saturating_add(usage.cache_read_input_tokens);
                let price = pricing_override
                    .intervals
                    .iter()
                    .find(|interval| interval.matches(total_context_tokens))
                    .and_then(|interval| interval.per_request_price)
                    .or(pricing_override.per_request_price)
                    .ok_or_else(|| PricingError::MissingPrice {
                        model: model.to_owned(),
                        category: "per request",
                    })?;
                calculate_request_cost(price, group_multiplier, account_multiplier)
            }
        }
    }
}

pub(crate) fn active_pricing_catalog() -> Result<SharedPricingCatalog, PricingError> {
    if let Some(catalog) = ACTIVE_PRICING_CATALOG.get() {
        return Ok(Arc::clone(catalog));
    }
    let initial = Arc::new(PricingCatalog::bundled()?);
    let catalog = Arc::new(RwLock::new(initial));
    Ok(Arc::clone(ACTIVE_PRICING_CATALOG.get_or_init(|| catalog)))
}

/// Atomically replaces the catalog used by newly observed billing events.
///
/// # Errors
///
/// Returns an error if the bundled fallback cannot initialize the shared slot.
pub fn replace_active_pricing_catalog(catalog: PricingCatalog) -> Result<(), PricingError> {
    let active = active_pricing_catalog()?;
    *active.write() = Arc::new(catalog);
    Ok(())
}

/// Returns a copied model entry from the current validated catalog snapshot.
///
/// # Errors
///
/// Returns an error if the bundled fallback cannot initialize the shared slot.
pub fn active_model_pricing(model: &str) -> Result<Option<ModelPricing>, PricingError> {
    let active = active_pricing_catalog()?;
    let catalog = active.read().clone();
    Ok(catalog.get(model).copied())
}

pub(crate) fn active_pricing_source() -> Result<Arc<str>, PricingError> {
    let active = active_pricing_catalog()?;
    let catalog = active.read().clone();
    Ok(Arc::clone(&catalog.source))
}

fn category_cost(
    model: &str,
    category: &'static str,
    tokens: u64,
    price: Option<Decimal>,
) -> Result<Decimal, PricingError> {
    if tokens == 0 {
        return Ok(Decimal::ZERO);
    }
    let price = require_price(model, category, price)?;
    Ok(price.checked_mul_u64(tokens)?)
}

fn calculate_token_cost(
    model: &str,
    pricing: ModelPricing,
    usage: TokenUsage,
    group_multiplier: Decimal,
    account_multiplier: Decimal,
) -> Result<CostBreakdown, PricingError> {
    validate_multipliers(group_multiplier, account_multiplier)?;
    let input_cost = category_cost(
        model,
        "input",
        usage.input_tokens,
        pricing.input_cost_per_token,
    )?;
    let output_cost = category_cost(
        model,
        "output",
        usage.output_tokens,
        pricing.output_cost_per_token,
    )?;
    let cache_creation_cost = category_cost(
        model,
        "cache creation",
        usage.cache_creation_input_tokens,
        pricing.cache_creation_input_token_cost,
    )?;
    let cache_read_cost = category_cost(
        model,
        "cache read",
        usage.cache_read_input_tokens,
        pricing.cache_read_input_token_cost,
    )?;
    let total_cost = input_cost
        .checked_add(output_cost)?
        .checked_add(cache_creation_cost)?
        .checked_add(cache_read_cost)?;
    Ok(CostBreakdown {
        input_cost,
        output_cost,
        cache_creation_cost,
        cache_read_cost,
        total_cost,
        actual_cost: total_cost.checked_mul(group_multiplier)?,
        account_cost: total_cost.checked_mul(account_multiplier)?,
    })
}

fn calculate_request_cost(
    price: Decimal,
    group_multiplier: Decimal,
    account_multiplier: Decimal,
) -> Result<CostBreakdown, PricingError> {
    validate_multipliers(group_multiplier, account_multiplier)?;
    Ok(CostBreakdown {
        input_cost: price,
        total_cost: price,
        actual_cost: price.checked_mul(group_multiplier)?,
        account_cost: price.checked_mul(account_multiplier)?,
        ..CostBreakdown::default()
    })
}

fn validate_multipliers(
    group_multiplier: Decimal,
    account_multiplier: Decimal,
) -> Result<(), PricingError> {
    if group_multiplier.is_negative() {
        return Err(PricingError::NegativeMultiplier("group"));
    }
    if account_multiplier.is_negative() {
        return Err(PricingError::NegativeMultiplier("account"));
    }
    Ok(())
}

fn effective_base_pricing(
    catalog_pricing: Option<ModelPricing>,
    pricing_override: &BillingPricingOverride,
) -> ModelPricing {
    overlay_pricing(
        catalog_pricing.unwrap_or_else(zero_model_pricing),
        pricing_override.pricing,
    )
}

fn overlay_pricing(mut base: ModelPricing, pricing_override: ModelPricing) -> ModelPricing {
    if pricing_override.input_cost_per_token.is_some() {
        base.input_cost_per_token = pricing_override.input_cost_per_token;
    }
    if pricing_override.output_cost_per_token.is_some() {
        base.output_cost_per_token = pricing_override.output_cost_per_token;
    }
    if pricing_override.cache_creation_input_token_cost.is_some() {
        base.cache_creation_input_token_cost = pricing_override.cache_creation_input_token_cost;
    }
    if pricing_override.cache_read_input_token_cost.is_some() {
        base.cache_read_input_token_cost = pricing_override.cache_read_input_token_cost;
    }
    base
}

const fn zero_model_pricing() -> ModelPricing {
    ModelPricing {
        input_cost_per_token: Some(Decimal::ZERO),
        output_cost_per_token: Some(Decimal::ZERO),
        cache_creation_input_token_cost: Some(Decimal::ZERO),
        cache_read_input_token_cost: Some(Decimal::ZERO),
    }
}

fn require_price(
    model: &str,
    category: &'static str,
    price: Option<Decimal>,
) -> Result<Decimal, PricingError> {
    price.ok_or_else(|| PricingError::MissingPrice {
        model: model.to_owned(),
        category,
    })
}

struct CatalogParser<'a> {
    cursor: JsonCursor<'a>,
}

impl<'a> CatalogParser<'a> {
    const fn new(source: &'a str) -> Self {
        Self {
            cursor: JsonCursor::new(source),
        }
    }

    fn parse(mut self) -> Result<PricingCatalog, PricingError> {
        self.cursor.skip_whitespace();
        self.cursor.expect_byte(b'{')?;
        let mut models = HashMap::new();
        self.cursor.skip_whitespace();
        if self.cursor.consume_byte(b'}') {
            self.finish()?;
            return Ok(PricingCatalog {
                models,
                source: Arc::from(""),
            });
        }

        loop {
            self.cursor.skip_whitespace();
            let model = self.cursor.parse_string()?;
            self.cursor.skip_whitespace();
            self.cursor.expect_byte(b':')?;
            self.cursor.skip_whitespace();
            let pricing = self.parse_model(&model)?;
            if models.insert(model.clone(), pricing).is_some() {
                return Err(PricingError::InvalidCatalog(format!(
                    "duplicate model {model:?}"
                )));
            }

            self.cursor.skip_whitespace();
            if self.cursor.consume_byte(b'}') {
                break;
            }
            self.cursor.expect_byte(b',')?;
        }
        self.finish()?;
        Ok(PricingCatalog {
            models,
            source: Arc::from(""),
        })
    }

    fn parse_model(&mut self, model: &str) -> Result<ModelPricing, PricingError> {
        self.cursor.expect_byte(b'{')?;
        let mut pricing = ModelPricing::default();
        let mut seen = [false; 4];
        self.cursor.skip_whitespace();
        if self.cursor.consume_byte(b'}') {
            return Ok(pricing);
        }

        loop {
            self.cursor.skip_whitespace();
            let field = self.cursor.parse_string()?;
            self.cursor.skip_whitespace();
            self.cursor.expect_byte(b':')?;
            self.cursor.skip_whitespace();
            match field.as_str() {
                "input_cost_per_token" => {
                    set_price(
                        model,
                        &field,
                        &mut seen[0],
                        &mut pricing.input_cost_per_token,
                        &mut self.cursor,
                    )?;
                }
                "output_cost_per_token" => {
                    set_price(
                        model,
                        &field,
                        &mut seen[1],
                        &mut pricing.output_cost_per_token,
                        &mut self.cursor,
                    )?;
                }
                "cache_creation_input_token_cost" => {
                    set_price(
                        model,
                        &field,
                        &mut seen[2],
                        &mut pricing.cache_creation_input_token_cost,
                        &mut self.cursor,
                    )?;
                }
                "cache_read_input_token_cost" => {
                    set_price(
                        model,
                        &field,
                        &mut seen[3],
                        &mut pricing.cache_read_input_token_cost,
                        &mut self.cursor,
                    )?;
                }
                _ => self.cursor.skip_value(1)?,
            }

            self.cursor.skip_whitespace();
            if self.cursor.consume_byte(b'}') {
                break;
            }
            self.cursor.expect_byte(b',')?;
        }
        Ok(pricing)
    }

    fn finish(&mut self) -> Result<(), PricingError> {
        self.cursor.skip_whitespace();
        if self.cursor.is_finished() {
            Ok(())
        } else {
            Err(self.cursor.error("trailing data after root object"))
        }
    }
}

fn set_price(
    model: &str,
    field: &str,
    seen: &mut bool,
    destination: &mut Option<Decimal>,
    cursor: &mut JsonCursor<'_>,
) -> Result<(), PricingError> {
    if *seen {
        return Err(PricingError::InvalidCatalog(format!(
            "duplicate field {field:?} for model {model:?}"
        )));
    }
    *seen = true;
    if cursor.consume_keyword("null") {
        *destination = None;
        return Ok(());
    }

    let lexeme = cursor.parse_number()?;
    let value = Decimal::from_str(lexeme).map_err(|error| {
        PricingError::InvalidCatalog(format!("invalid {field} for model {model:?}: {error}"))
    })?;
    if value.is_negative() {
        return Err(PricingError::NegativePrice {
            model: model.to_owned(),
            field: field.to_owned(),
        });
    }
    *destination = Some(value);
    Ok(())
}

struct JsonCursor<'a> {
    source: &'a str,
    bytes: &'a [u8],
    index: usize,
}

impl<'a> JsonCursor<'a> {
    const fn new(source: &'a str) -> Self {
        Self {
            source,
            bytes: source.as_bytes(),
            index: 0,
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(
            self.bytes.get(self.index),
            Some(b' ' | b'\n' | b'\r' | b'\t')
        ) {
            self.index += 1;
        }
    }

    fn is_finished(&self) -> bool {
        self.index == self.bytes.len()
    }

    fn consume_byte(&mut self, expected: u8) -> bool {
        if self.bytes.get(self.index) == Some(&expected) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn expect_byte(&mut self, expected: u8) -> Result<(), PricingError> {
        if self.consume_byte(expected) {
            Ok(())
        } else {
            Err(self.error(&format!("expected {:?}", char::from(expected))))
        }
    }

    fn consume_keyword(&mut self, keyword: &str) -> bool {
        let end = self.index.saturating_add(keyword.len());
        if self.bytes.get(self.index..end) == Some(keyword.as_bytes()) {
            self.index = end;
            true
        } else {
            false
        }
    }

    fn parse_string(&mut self) -> Result<String, PricingError> {
        let start = self.index;
        if !self.consume_byte(b'"') {
            return Err(self.error("expected JSON string"));
        }
        let mut escaped = false;
        while let Some(&byte) = self.bytes.get(self.index) {
            self.index += 1;
            if escaped {
                escaped = false;
                continue;
            }
            match byte {
                b'\\' => escaped = true,
                b'"' => {
                    let raw = &self.source[start..self.index];
                    return serde_json::from_str(raw)
                        .map_err(|error| self.error(&format!("invalid JSON string: {error}")));
                }
                _ => {}
            }
        }
        Err(self.error("unterminated JSON string"))
    }

    fn parse_number(&mut self) -> Result<&'a str, PricingError> {
        let start = self.index;
        self.consume_byte(b'-');

        match self.bytes.get(self.index) {
            Some(b'0') => {
                self.index += 1;
                if matches!(self.bytes.get(self.index), Some(b'0'..=b'9')) {
                    return Err(self.error("JSON number has a leading zero"));
                }
            }
            Some(b'1'..=b'9') => {
                self.index += 1;
                while matches!(self.bytes.get(self.index), Some(b'0'..=b'9')) {
                    self.index += 1;
                }
            }
            _ => return Err(self.error("expected JSON number")),
        }

        if self.consume_byte(b'.') {
            let fraction_start = self.index;
            while matches!(self.bytes.get(self.index), Some(b'0'..=b'9')) {
                self.index += 1;
            }
            if self.index == fraction_start {
                return Err(self.error("JSON number has an empty fraction"));
            }
        }

        if matches!(self.bytes.get(self.index), Some(b'e' | b'E')) {
            self.index += 1;
            if matches!(self.bytes.get(self.index), Some(b'+' | b'-')) {
                self.index += 1;
            }
            let exponent_start = self.index;
            while matches!(self.bytes.get(self.index), Some(b'0'..=b'9')) {
                self.index += 1;
            }
            if self.index == exponent_start {
                return Err(self.error("JSON number has an empty exponent"));
            }
        }

        Ok(&self.source[start..self.index])
    }

    fn skip_value(&mut self, depth: usize) -> Result<(), PricingError> {
        if depth > MAX_JSON_DEPTH {
            return Err(self.error("JSON nesting exceeds 128 levels"));
        }
        self.skip_whitespace();
        match self.bytes.get(self.index) {
            Some(b'"') => {
                self.parse_string()?;
                Ok(())
            }
            Some(b'{') => self.skip_object(depth),
            Some(b'[') => self.skip_array(depth),
            Some(b't') if self.consume_keyword("true") => Ok(()),
            Some(b'f') if self.consume_keyword("false") => Ok(()),
            Some(b'n') if self.consume_keyword("null") => Ok(()),
            Some(b'-' | b'0'..=b'9') => self.parse_number().map(|_| ()),
            _ => Err(self.error("invalid JSON value")),
        }
    }

    fn skip_object(&mut self, depth: usize) -> Result<(), PricingError> {
        self.expect_byte(b'{')?;
        self.skip_whitespace();
        if self.consume_byte(b'}') {
            return Ok(());
        }
        loop {
            self.skip_whitespace();
            self.parse_string()?;
            self.skip_whitespace();
            self.expect_byte(b':')?;
            self.skip_value(depth + 1)?;
            self.skip_whitespace();
            if self.consume_byte(b'}') {
                return Ok(());
            }
            self.expect_byte(b',')?;
        }
    }

    fn skip_array(&mut self, depth: usize) -> Result<(), PricingError> {
        self.expect_byte(b'[')?;
        self.skip_whitespace();
        if self.consume_byte(b']') {
            return Ok(());
        }
        loop {
            self.skip_value(depth + 1)?;
            self.skip_whitespace();
            if self.consume_byte(b']') {
                return Ok(());
            }
            self.expect_byte(b',')?;
        }
    }

    fn error(&self, message: &str) -> PricingError {
        PricingError::InvalidCatalog(format!("{message} at byte {}", self.index))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PricingError {
    InvalidCatalog(String),
    UnknownModel(String),
    MissingPrice {
        model: String,
        category: &'static str,
    },
    NegativePrice {
        model: String,
        field: String,
    },
    NegativeMultiplier(&'static str),
    Arithmetic(DecimalError),
}

impl fmt::Display for PricingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCatalog(message) => {
                write!(formatter, "invalid pricing catalog: {message}")
            }
            Self::UnknownModel(model) => {
                write!(formatter, "pricing is missing for model {model:?}")
            }
            Self::MissingPrice { model, category } => {
                write!(formatter, "{category} price is missing for model {model:?}")
            }
            Self::NegativePrice { model, field } => {
                write!(
                    formatter,
                    "price field {field:?} is negative for model {model:?}"
                )
            }
            Self::NegativeMultiplier(kind) => {
                write!(formatter, "{kind} multiplier cannot be negative")
            }
            Self::Arithmetic(error) => write!(formatter, "cost calculation failed: {error}"),
        }
    }
}

impl Error for PricingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Arithmetic(error) => Some(error),
            _ => None,
        }
    }
}

impl From<DecimalError> for PricingError {
    fn from(error: DecimalError) -> Self {
        Self::Arithmetic(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_numeric_lexemes_preserve_scientific_prices() {
        let catalog = PricingCatalog::from_json(
            r#"{"model":{"input_cost_per_token":1.25e-06,"output_cost_per_token":1e-05,"cache_read_input_token_cost":0}}"#,
        )
        .unwrap();
        let prices = catalog.get("model").unwrap();
        assert_eq!(
            prices.input_cost_per_token.unwrap().to_string(),
            "0.00000125"
        );
        assert_eq!(prices.cache_read_input_token_cost, Some(Decimal::ZERO));
    }

    #[test]
    fn missing_required_price_fails_but_explicit_zero_is_valid() {
        let catalog = PricingCatalog::from_json(
            r#"{"model":{"input_cost_per_token":0,"output_cost_per_token":2e-06}}"#,
        )
        .unwrap();
        let free = catalog
            .calculate(
                "model",
                TokenUsage {
                    input_tokens: 10,
                    ..TokenUsage::default()
                },
                Decimal::ONE,
                Decimal::ONE,
            )
            .unwrap();
        assert_eq!(free.total_cost, Decimal::ZERO);

        let error = catalog
            .calculate(
                "model",
                TokenUsage {
                    cache_read_input_tokens: 1,
                    ..TokenUsage::default()
                },
                Decimal::ONE,
                Decimal::ONE,
            )
            .unwrap_err();
        assert!(matches!(error, PricingError::MissingPrice { .. }));
    }

    #[test]
    fn cost_breakdown_uses_independent_group_and_account_multipliers() {
        let catalog = PricingCatalog::from_json(
            r#"{"model":{"input_cost_per_token":1e-06,"output_cost_per_token":2e-06}}"#,
        )
        .unwrap();
        let costs = catalog
            .calculate(
                "model",
                TokenUsage {
                    input_tokens: 1_000_000,
                    output_tokens: 500_000,
                    ..TokenUsage::default()
                },
                "1.5".parse().unwrap(),
                "0.25".parse().unwrap(),
            )
            .unwrap();
        assert_eq!(costs.total_cost.to_string(), "2");
        assert_eq!(costs.actual_cost.to_string(), "3");
        assert_eq!(costs.account_cost.to_string(), "0.5");
    }

    #[test]
    fn channel_flat_prices_override_catalog_fields() {
        let catalog = PricingCatalog::from_json(
            r#"{"model":{"input_cost_per_token":1,"output_cost_per_token":2}}"#,
        )
        .unwrap();
        let pricing_override = BillingPricingOverride {
            pricing: ModelPricing {
                input_cost_per_token: Some("3".parse().unwrap()),
                ..ModelPricing::default()
            },
            ..BillingPricingOverride::default()
        };
        let costs = catalog
            .calculate_with_override(
                "model",
                TokenUsage {
                    input_tokens: 1,
                    output_tokens: 1,
                    ..TokenUsage::default()
                },
                Decimal::ONE,
                Decimal::ONE,
                Some(&pricing_override),
            )
            .unwrap();
        assert_eq!(costs.input_cost.to_string(), "3");
        assert_eq!(costs.output_cost.to_string(), "2");
        assert_eq!(costs.total_cost.to_string(), "5");
    }

    #[test]
    fn channel_interval_prices_use_input_side_context_tokens() {
        let catalog = PricingCatalog::default();
        let pricing_override = BillingPricingOverride {
            intervals: vec![BillingPricingInterval {
                min_tokens: 100,
                max_tokens: Some(200),
                pricing: ModelPricing {
                    input_cost_per_token: Some("0.5".parse().unwrap()),
                    output_cost_per_token: Some(Decimal::ZERO),
                    ..ModelPricing::default()
                },
                per_request_price: None,
            }],
            ..BillingPricingOverride::default()
        };
        let costs = catalog
            .calculate_with_override(
                "channel-only-model",
                TokenUsage {
                    input_tokens: 80,
                    cache_read_input_tokens: 40,
                    ..TokenUsage::default()
                },
                Decimal::ONE,
                Decimal::ONE,
                Some(&pricing_override),
            )
            .unwrap();
        assert_eq!(costs.total_cost.to_string(), "40");
    }

    #[test]
    fn channel_per_request_price_is_billed_once() {
        let catalog = PricingCatalog::default();
        let pricing_override = BillingPricingOverride {
            mode: BillingPricingMode::PerRequest,
            per_request_price: Some("0.25".parse().unwrap()),
            ..BillingPricingOverride::default()
        };
        let costs = catalog
            .calculate_with_override(
                "channel-only-model",
                TokenUsage {
                    input_tokens: 10_000,
                    output_tokens: 1_000,
                    ..TokenUsage::default()
                },
                "2".parse().unwrap(),
                "0.5".parse().unwrap(),
                Some(&pricing_override),
            )
            .unwrap();
        assert_eq!(costs.total_cost.to_string(), "0.25");
        assert_eq!(costs.actual_cost.to_string(), "0.5");
        assert_eq!(costs.account_cost.to_string(), "0.125");
    }

    #[test]
    fn duplicate_security_sensitive_fields_are_rejected() {
        let error = PricingCatalog::from_json(
            r#"{"model":{"input_cost_per_token":1,"input_cost_per_token":0}}"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("duplicate field"));
    }
}
