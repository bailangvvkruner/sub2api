use std::{error::Error, fmt};

use sha2::{Digest, Sha256};

use super::{CostBreakdown, Decimal, TokenUsage};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(i16)]
pub enum RequestType {
    #[default]
    Unknown = 0,
    Sync = 1,
    Stream = 2,
    OpenAiWebSocket = 3,
    CyberBlocked = 4,
}

impl RequestType {
    #[must_use]
    pub const fn as_i16(self) -> i16 {
        self as i16
    }

    #[must_use]
    pub const fn legacy_fields(self, fallback_stream: bool) -> (bool, bool) {
        match self {
            Self::Unknown | Self::CyberBlocked => (fallback_stream, false),
            Self::Sync => (false, false),
            Self::Stream => (true, false),
            Self::OpenAiWebSocket => (true, true),
        }
    }

    #[must_use]
    pub const fn from_i16(value: i16) -> Option<Self> {
        match value {
            0 => Some(Self::Unknown),
            1 => Some(Self::Sync),
            2 => Some(Self::Stream),
            3 => Some(Self::OpenAiWebSocket),
            4 => Some(Self::CyberBlocked),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BillingEvent {
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
    pub billing_mode: String,
    pub usage: TokenUsage,
    pub costs: CostBreakdown,
    pub group_multiplier: Decimal,
    pub account_multiplier: Decimal,
    pub stream: bool,
    pub request_type: RequestType,
    pub duration_ms: Option<i32>,
}

impl BillingEvent {
    /// Validates all values that cross the billing/database boundary.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identifiers, database-width violations,
    /// negative values, or a cost breakdown that is internally inconsistent.
    #[allow(
        clippy::too_many_lines,
        reason = "billing boundary validation intentionally checks the complete event invariant in one place"
    )]
    pub fn validate(&self) -> Result<(), BillingEventError> {
        validate_text("request_id", &self.request_id, 64)?;
        if self.request_fingerprint.len() != 64
            || !self
                .request_fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(BillingEventError::InvalidField(
                "request_fingerprint must contain exactly 64 hexadecimal characters".to_owned(),
            ));
        }
        validate_positive_id("user_id", self.user_id)?;
        validate_positive_id("api_key_id", self.api_key_id)?;
        validate_positive_id("account_id", self.account_id)?;
        if let Some(group_id) = self.group_id {
            validate_positive_id("group_id", group_id)?;
        }
        if let Some(channel_id) = self.channel_id {
            validate_positive_id("channel_id", channel_id)?;
        }
        validate_text("platform", &self.platform, 32)?;
        validate_text("model", &self.model, 100)?;
        if let Some(mapping_chain) = self.model_mapping_chain.as_deref() {
            validate_text("model_mapping_chain", mapping_chain, 500)?;
        }
        validate_text("billing_mode", &self.billing_mode, 20)?;
        if !matches!(
            self.billing_mode.as_str(),
            "token" | "per_request" | "image"
        ) {
            return Err(BillingEventError::InvalidField(
                "billing_mode must be token, per_request, or image".to_owned(),
            ));
        }
        if self.duration_ms.is_some_and(|duration| duration < 0) {
            return Err(BillingEventError::InvalidField(
                "duration_ms cannot be negative".to_owned(),
            ));
        }

        for (field, tokens) in [
            ("input_tokens", self.usage.input_tokens),
            ("output_tokens", self.usage.output_tokens),
            (
                "cache_creation_input_tokens",
                self.usage.cache_creation_input_tokens,
            ),
            (
                "cache_read_input_tokens",
                self.usage.cache_read_input_tokens,
            ),
        ] {
            if tokens > i32::MAX as u64 {
                return Err(BillingEventError::InvalidField(format!(
                    "{field} exceeds the PostgreSQL integer range"
                )));
            }
        }

        if self.group_multiplier.is_negative() {
            return Err(BillingEventError::InvalidField(
                "group_multiplier cannot be negative".to_owned(),
            ));
        }
        if self.account_multiplier.is_negative() {
            return Err(BillingEventError::InvalidField(
                "account_multiplier cannot be negative".to_owned(),
            ));
        }
        for (field, cost) in [
            ("input_cost", self.costs.input_cost),
            ("output_cost", self.costs.output_cost),
            ("cache_creation_cost", self.costs.cache_creation_cost),
            ("cache_read_cost", self.costs.cache_read_cost),
            ("total_cost", self.costs.total_cost),
            ("actual_cost", self.costs.actual_cost),
            ("account_cost", self.costs.account_cost),
        ] {
            if cost.is_negative() {
                return Err(BillingEventError::InvalidField(format!(
                    "{field} cannot be negative"
                )));
            }
        }

        let total = self
            .costs
            .input_cost
            .checked_add(self.costs.output_cost)?
            .checked_add(self.costs.cache_creation_cost)?
            .checked_add(self.costs.cache_read_cost)?;
        if total != self.costs.total_cost {
            return Err(BillingEventError::InvalidField(
                "total_cost does not equal the category cost sum".to_owned(),
            ));
        }
        if total.checked_mul(self.group_multiplier)? != self.costs.actual_cost {
            return Err(BillingEventError::InvalidField(
                "actual_cost does not match the group multiplier".to_owned(),
            ));
        }
        if total.checked_mul(self.account_multiplier)? != self.costs.account_cost {
            return Err(BillingEventError::InvalidField(
                "account_cost does not match the account multiplier".to_owned(),
            ));
        }

        Ok(())
    }
}

fn validate_text(field: &str, value: &str, max_chars: usize) -> Result<(), BillingEventError> {
    if value.trim().is_empty() {
        return Err(BillingEventError::InvalidField(format!(
            "{field} cannot be empty"
        )));
    }
    if value.chars().count() > max_chars {
        return Err(BillingEventError::InvalidField(format!(
            "{field} exceeds {max_chars} characters"
        )));
    }
    Ok(())
}

fn validate_positive_id(field: &str, value: i64) -> Result<(), BillingEventError> {
    if value <= 0 {
        return Err(BillingEventError::InvalidField(format!(
            "{field} must be positive"
        )));
    }
    Ok(())
}

#[must_use]
pub fn request_fingerprint(payload: &[u8]) -> String {
    hex::encode(Sha256::digest(payload))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BillingEventError {
    InvalidField(String),
    Arithmetic(super::DecimalError),
}

impl fmt::Display for BillingEventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(message) => write!(formatter, "invalid billing event: {message}"),
            Self::Arithmetic(error) => {
                write!(formatter, "invalid billing event arithmetic: {error}")
            }
        }
    }
}

impl Error for BillingEventError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Arithmetic(error) => Some(error),
            Self::InvalidField(_) => None,
        }
    }
}

impl From<super::DecimalError> for BillingEventError {
    fn from(error: super::DecimalError) -> Self {
        Self::Arithmetic(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> BillingEvent {
        let total = "0.75".parse::<Decimal>().unwrap();
        BillingEvent {
            request_id: "request-1".to_owned(),
            request_fingerprint: request_fingerprint(b"payload"),
            user_id: 1,
            api_key_id: 2,
            account_id: 3,
            group_id: Some(4),
            channel_id: Some(5),
            platform: "anthropic".to_owned(),
            model: "model".to_owned(),
            model_mapping_chain: Some("public->model".to_owned()),
            billing_mode: "token".to_owned(),
            usage: TokenUsage {
                input_tokens: 10,
                ..TokenUsage::default()
            },
            costs: CostBreakdown {
                input_cost: total,
                total_cost: total,
                actual_cost: "1.5".parse().unwrap(),
                account_cost: "0.375".parse().unwrap(),
                ..CostBreakdown::default()
            },
            group_multiplier: "2".parse().unwrap(),
            account_multiplier: "0.5".parse().unwrap(),
            stream: true,
            request_type: RequestType::Stream,
            duration_ms: Some(25),
        }
    }

    #[test]
    fn valid_event_has_consistent_costs_and_ids() {
        event().validate().unwrap();
    }

    #[test]
    fn rejects_fingerprint_and_cost_tampering() {
        let mut invalid = event();
        invalid.request_fingerprint = "short".to_owned();
        assert!(invalid.validate().is_err());

        let mut invalid = event();
        invalid.costs.actual_cost = Decimal::ZERO;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn fingerprint_is_lowercase_sha256() {
        assert_eq!(
            request_fingerprint(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
