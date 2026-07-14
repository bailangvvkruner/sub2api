-- Durable, single-use OAuth authorization state for the PostgreSQL-only runtime.
-- Only SHA-256 digests of browser bearer values are persisted.

CREATE TABLE IF NOT EXISTS auth_oauth_states (
    id UUID PRIMARY KEY,
    state_hash BYTEA NOT NULL UNIQUE,
    provider_type VARCHAR(20) NOT NULL,
    redirect_to TEXT NOT NULL DEFAULT '/dashboard',
    promo_code VARCHAR(64) NOT NULL DEFAULT '',
    affiliate_code VARCHAR(64) NOT NULL DEFAULT '',
    intent VARCHAR(40) NOT NULL DEFAULT 'login',
    target_user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
    verifier_hash BYTEA,
    nonce_hash BYTEA,
    provider_context JSONB NOT NULL DEFAULT '{}'::jsonb,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT auth_oauth_states_provider_check CHECK (
        provider_type IN ('github', 'google', 'linuxdo', 'oidc', 'wechat', 'dingtalk')
    ),
    CONSTRAINT auth_oauth_states_intent_check CHECK (
        intent IN ('login', 'bind_current_user')
    ),
    CONSTRAINT auth_oauth_states_hash_length CHECK (octet_length(state_hash) = 32),
    CONSTRAINT auth_oauth_states_verifier_hash_length CHECK (
        verifier_hash IS NULL OR octet_length(verifier_hash) = 32
    ),
    CONSTRAINT auth_oauth_states_nonce_hash_length CHECK (
        nonce_hash IS NULL OR octet_length(nonce_hash) = 32
    ),
    CONSTRAINT auth_oauth_states_expiry_order CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS auth_oauth_states_active_provider_idx
    ON auth_oauth_states (provider_type, expires_at)
    WHERE consumed_at IS NULL;

CREATE INDEX IF NOT EXISTS auth_oauth_states_expires_at_idx
    ON auth_oauth_states (expires_at);

CREATE TABLE IF NOT EXISTS auth_wechat_payment_resume_tokens (
    id UUID PRIMARY KEY,
    token_hash BYTEA NOT NULL UNIQUE,
    user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
    openid TEXT NOT NULL,
    payment_type VARCHAR(32) NOT NULL,
    amount VARCHAR(64) NOT NULL DEFAULT '',
    order_type VARCHAR(32) NOT NULL DEFAULT '',
    plan_id BIGINT,
    redirect_to TEXT NOT NULL DEFAULT '/purchase',
    scope VARCHAR(32) NOT NULL DEFAULT 'snsapi_base',
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT auth_wechat_payment_resume_tokens_hash_length
        CHECK (octet_length(token_hash) = 32),
    CONSTRAINT auth_wechat_payment_resume_tokens_expiry_order
        CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS auth_wechat_payment_resume_tokens_active_idx
    ON auth_wechat_payment_resume_tokens (expires_at)
    WHERE consumed_at IS NULL;
