use serde_json::Value;

use super::{
    PaymentError, ProviderRuntime,
    models::ProviderSelection,
    provider::{
        load_provider_instance, provider_currency, query_refund as query_provider_refund,
        refund_payment,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProviderRefundStatus {
    Succeeded,
    Pending,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProviderRefundResult {
    pub refund_id: String,
    pub status: ProviderRefundStatus,
}

#[derive(Clone, Debug)]
pub(crate) struct ProviderRefundRequest {
    pub trade_no: String,
    pub order_id: String,
    pub refund_id: String,
    pub amount: f64,
    pub total_amount: f64,
    pub currency: String,
    pub reason: String,
}

pub(crate) struct RefundProvider {
    selection: ProviderSelection,
}

impl RefundProvider {
    pub(crate) async fn load(
        runtime: &ProviderRuntime,
        instance_id: i64,
    ) -> Result<Self, PaymentError> {
        Ok(Self {
            selection: load_provider_instance(runtime, instance_id).await?,
        })
    }

    #[must_use]
    pub(crate) fn provider_key(&self) -> &str {
        &self.selection.provider_key
    }

    #[must_use]
    pub(crate) fn supports_query(&self) -> bool {
        matches!(
            self.selection.provider_key.as_str(),
            "alipay" | "stripe" | "airwallex" | "wxpay"
        )
    }

    pub(crate) fn validate_order_binding(
        &self,
        instance_id: &str,
        provider_key: &str,
        snapshot: &Value,
    ) -> Result<(), PaymentError> {
        if instance_id.trim().parse::<i64>().ok() != Some(self.selection.instance_id) {
            return Err(provider_mismatch());
        }
        for expected in [
            provider_key.trim(),
            snapshot
                .get("provider_key")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim(),
        ] {
            if !expected.is_empty() && !self.selection.provider_key.eq_ignore_ascii_case(expected) {
                return Err(provider_mismatch());
            }
        }
        let snapshot_instance = snapshot
            .get("provider_instance_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim();
        if !snapshot_instance.is_empty()
            && snapshot_instance.parse::<i64>().ok() != Some(self.selection.instance_id)
        {
            return Err(provider_mismatch());
        }
        self.validate_merchant_snapshot(snapshot)?;
        let expected_currency = snapshot
            .get("currency")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim();
        let actual_currency =
            provider_currency(&self.selection.provider_key, &self.selection.config);
        if !expected_currency.is_empty() && !actual_currency.eq_ignore_ascii_case(expected_currency)
        {
            return Err(provider_mismatch());
        }
        Ok(())
    }

    pub(crate) async fn refund(
        &self,
        runtime: &ProviderRuntime,
        request: &ProviderRefundRequest,
    ) -> Result<ProviderRefundResult, PaymentError> {
        refund_payment(runtime, &self.selection, request).await
    }

    pub(crate) async fn query_refund(
        &self,
        runtime: &ProviderRuntime,
        request: &ProviderRefundRequest,
    ) -> Result<ProviderRefundResult, PaymentError> {
        query_provider_refund(runtime, &self.selection, request).await
    }

    fn validate_merchant_snapshot(&self, snapshot: &Value) -> Result<(), PaymentError> {
        let merchant_id = snapshot
            .get("merchant_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim();
        let merchant_app_id = snapshot
            .get("merchant_app_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim();
        let config = &self.selection.config;
        let identity_matches = match self.selection.provider_key.as_str() {
            "easypay" => matches_config(merchant_id, config.get("pid").map(String::as_str)),
            "alipay" => matches_config(merchant_app_id, config.get("appId").map(String::as_str)),
            "wxpay" => {
                matches_config(merchant_id, config.get("mchId").map(String::as_str))
                    && (matches_config(merchant_app_id, config.get("appId").map(String::as_str))
                        || matches_config(
                            merchant_app_id,
                            config.get("mpAppId").map(String::as_str),
                        ))
            }
            "airwallex" => matches_config(merchant_id, config.get("accountId").map(String::as_str)),
            _ => true,
        };
        if identity_matches {
            Ok(())
        } else {
            Err(provider_mismatch())
        }
    }
}

fn matches_config(expected: &str, actual: Option<&str>) -> bool {
    expected.is_empty()
        || actual.is_some_and(|actual| {
            !actual.trim().is_empty() && actual.eq_ignore_ascii_case(expected)
        })
}

fn provider_mismatch() -> PaymentError {
    PaymentError::conflict(
        "PAYMENT_PROVIDER_METADATA_MISMATCH",
        "Payment provider configuration no longer matches the order snapshot",
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::json;

    use super::*;

    fn provider(provider_key: &str, config: &[(&str, &str)]) -> RefundProvider {
        RefundProvider {
            selection: ProviderSelection {
                instance_id: 7,
                provider_key: provider_key.to_owned(),
                config: config
                    .iter()
                    .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                    .collect::<HashMap<_, _>>(),
                supported_types: String::new(),
                payment_mode: String::new(),
            },
        }
    }

    #[test]
    fn historical_provider_binding_rejects_changed_merchant_credentials() {
        let provider = provider("alipay", &[("appId", "current-app")]);
        let snapshot = json!({
            "provider_instance_id": "7",
            "provider_key": "alipay",
            "merchant_app_id": "historical-app",
            "currency": "CNY",
        });
        assert!(
            provider
                .validate_order_binding("7", "alipay", &snapshot)
                .is_err()
        );
    }

    #[test]
    fn wxpay_binding_accepts_snapshot_from_mp_app() {
        let provider = provider(
            "wxpay",
            &[
                ("mchId", "merchant"),
                ("appId", "native-app"),
                ("mpAppId", "mp-app"),
            ],
        );
        let snapshot = json!({
            "provider_instance_id": "7",
            "provider_key": "wxpay",
            "merchant_id": "merchant",
            "merchant_app_id": "mp-app",
            "currency": "CNY",
        });
        assert!(
            provider
                .validate_order_binding("7", "wxpay", &snapshot)
                .is_ok()
        );
    }

    #[test]
    fn query_capability_is_never_claimed_for_easypay() {
        assert!(!provider("easypay", &[]).supports_query());
        assert!(provider("stripe", &[]).supports_query());
    }
}
