-- PostgreSQL-only refresh-token sessions used by the Rust service.
-- Raw refresh tokens are never persisted; only their SHA-256 digest is stored.
CREATE TABLE IF NOT EXISTS auth_refresh_sessions (
    id UUID PRIMARY KEY,
    token_hash BYTEA NOT NULL UNIQUE,
    family_id UUID NOT NULL,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_version BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    replaced_by UUID REFERENCES auth_refresh_sessions(id) ON DELETE SET NULL,
    reuse_detected_at TIMESTAMPTZ,
    CONSTRAINT auth_refresh_sessions_hash_length
        CHECK (octet_length(token_hash) = 32),
    CONSTRAINT auth_refresh_sessions_expiry_order
        CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS idx_auth_refresh_sessions_active_user
    ON auth_refresh_sessions (user_id)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_auth_refresh_sessions_active_family
    ON auth_refresh_sessions (family_id)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_auth_refresh_sessions_expires_at
    ON auth_refresh_sessions (expires_at);
