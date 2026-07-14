-- Cross-replica stream idle timeout threshold accounting.

CREATE TABLE IF NOT EXISTS gateway_stream_timeout_events (
    id          BIGSERIAL PRIMARY KEY,
    account_id  BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    model       VARCHAR(200) NOT NULL DEFAULT '',
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_gateway_stream_timeout_events_account_window
    ON gateway_stream_timeout_events (account_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_gateway_stream_timeout_events_cleanup
    ON gateway_stream_timeout_events (occurred_at);

-- Bound retained state even when no account reaches its configured threshold.
DELETE FROM gateway_stream_timeout_events
WHERE occurred_at < NOW() - INTERVAL '24 hours';
