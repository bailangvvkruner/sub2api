-- Cross-replica gateway admission and durable billing outbox.

CREATE TABLE IF NOT EXISTS gateway_runtime_leases (
    scope          VARCHAR(16) NOT NULL CHECK (scope IN ('user', 'account', 'api_key')),
    subject_id     BIGINT NOT NULL,
    secondary_id   BIGINT NOT NULL DEFAULT 0,
    request_id     VARCHAR(64) NOT NULL,
    instance_id    VARCHAR(64) NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (scope, subject_id, secondary_id, request_id)
);

CREATE INDEX IF NOT EXISTS idx_gateway_runtime_leases_expires
    ON gateway_runtime_leases (expires_at);
CREATE INDEX IF NOT EXISTS idx_gateway_runtime_leases_subject
    ON gateway_runtime_leases (scope, subject_id, secondary_id, expires_at);

CREATE TABLE IF NOT EXISTS gateway_runtime_rate_events (
    scope          VARCHAR(16) NOT NULL CHECK (scope IN ('user', 'user_group')),
    subject_id     BIGINT NOT NULL,
    secondary_id   BIGINT NOT NULL DEFAULT 0,
    request_id     VARCHAR(64) NOT NULL,
    instance_id    VARCHAR(64) NOT NULL,
    bucket_start   TIMESTAMPTZ NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (scope, subject_id, secondary_id, request_id)
);

CREATE INDEX IF NOT EXISTS idx_gateway_runtime_rate_events_expires
    ON gateway_runtime_rate_events (expires_at);
CREATE INDEX IF NOT EXISTS idx_gateway_runtime_rate_events_subject
    ON gateway_runtime_rate_events (scope, subject_id, secondary_id, bucket_start);

CREATE TABLE IF NOT EXISTS gateway_billing_reservations (
    request_id                 VARCHAR(64) NOT NULL,
    api_key_id                 BIGINT NOT NULL,
    request_fingerprint        CHAR(64) NOT NULL,
    user_id                    BIGINT NOT NULL,
    account_id                 BIGINT,
    group_id                   BIGINT,
    platform                   VARCHAR(32) NOT NULL,
    model                      VARCHAR(100),
    state                      VARCHAR(16) NOT NULL DEFAULT 'inflight'
                               CHECK (state IN ('inflight', 'ready', 'settled', 'cancelled')),
    input_tokens               BIGINT,
    output_tokens              BIGINT,
    cache_creation_tokens      BIGINT,
    cache_read_tokens          BIGINT,
    input_cost                 NUMERIC(20,10),
    output_cost                NUMERIC(20,10),
    cache_creation_cost        NUMERIC(20,10),
    cache_read_cost            NUMERIC(20,10),
    total_cost                 NUMERIC(20,10),
    actual_cost                NUMERIC(20,10),
    account_cost               NUMERIC(20,10),
    group_multiplier           NUMERIC(20,10),
    account_multiplier         NUMERIC(20,10),
    stream                     BOOLEAN,
    request_type               SMALLINT,
    duration_ms                INTEGER,
    instance_id                VARCHAR(64) NOT NULL,
    inflight_expires_at        TIMESTAMPTZ,
    recovery_owner             VARCHAR(64),
    recovery_until             TIMESTAMPTZ,
    ready_at                   TIMESTAMPTZ,
    settled_at                 TIMESTAMPTZ,
    cancelled_at               TIMESTAMPTZ,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (request_id, api_key_id),
    CHECK (
        state IN ('inflight', 'cancelled')
        OR (
            account_id IS NOT NULL AND model IS NOT NULL
            AND input_tokens IS NOT NULL AND output_tokens IS NOT NULL
            AND cache_creation_tokens IS NOT NULL AND cache_read_tokens IS NOT NULL
            AND input_cost IS NOT NULL AND output_cost IS NOT NULL
            AND cache_creation_cost IS NOT NULL AND cache_read_cost IS NOT NULL
            AND total_cost IS NOT NULL AND actual_cost IS NOT NULL AND account_cost IS NOT NULL
            AND group_multiplier IS NOT NULL AND account_multiplier IS NOT NULL
            AND stream IS NOT NULL AND request_type IS NOT NULL
        )
    )
);

CREATE INDEX IF NOT EXISTS idx_gateway_billing_reservations_ready_recovery
    ON gateway_billing_reservations (updated_at, request_id, api_key_id)
    WHERE state = 'ready';
CREATE INDEX IF NOT EXISTS idx_gateway_billing_reservations_inflight_expiry
    ON gateway_billing_reservations (inflight_expires_at)
    WHERE state = 'inflight';
CREATE INDEX IF NOT EXISTS idx_gateway_billing_reservations_retention
    ON gateway_billing_reservations (updated_at)
    WHERE state IN ('settled', 'cancelled');
CREATE INDEX IF NOT EXISTS idx_gateway_billing_reservations_user_ready
    ON gateway_billing_reservations (user_id, platform)
    WHERE state = 'ready';
CREATE INDEX IF NOT EXISTS idx_gateway_billing_reservations_api_key_ready
    ON gateway_billing_reservations (api_key_id)
    WHERE state = 'ready';
