-- Preserve channel attribution while durable Rust billing events are queued or recovered.

ALTER TABLE gateway_billing_reservations
    ADD COLUMN IF NOT EXISTS channel_id BIGINT,
    ADD COLUMN IF NOT EXISTS model_mapping_chain VARCHAR(500),
    ADD COLUMN IF NOT EXISTS billing_mode VARCHAR(20);

UPDATE gateway_billing_reservations
SET billing_mode = 'token'
WHERE state IN ('ready', 'settled') AND billing_mode IS NULL;
