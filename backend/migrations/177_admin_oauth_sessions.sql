-- Durable, encrypted PKCE sessions for administrator-managed upstream accounts.
CREATE TABLE IF NOT EXISTS admin_oauth_sessions (
    id UUID PRIMARY KEY,
    provider VARCHAR(32) NOT NULL,
    state_hash BYTEA NOT NULL UNIQUE,
    verifier_ciphertext TEXT NOT NULL,
    context JSONB NOT NULL DEFAULT '{}'::jsonb,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT admin_oauth_sessions_provider_check CHECK (
        provider IN ('anthropic', 'openai', 'gemini', 'antigravity', 'grok')
    ),
    CONSTRAINT admin_oauth_sessions_state_hash_length CHECK (octet_length(state_hash) = 32),
    CONSTRAINT admin_oauth_sessions_expiry_order CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS admin_oauth_sessions_active_idx
    ON admin_oauth_sessions (provider, expires_at)
    WHERE consumed_at IS NULL;

CREATE INDEX IF NOT EXISTS admin_oauth_sessions_expiry_idx
    ON admin_oauth_sessions (expires_at);
