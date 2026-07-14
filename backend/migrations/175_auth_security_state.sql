-- PostgreSQL-only state for local authentication and TOTP flows.
-- Raw reset, verification, setup, and login tokens are never persisted.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS auth_generation BIGINT NOT NULL DEFAULT 0;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'users_auth_generation_nonnegative'
    ) THEN
        ALTER TABLE users
            ADD CONSTRAINT users_auth_generation_nonnegative
            CHECK (auth_generation >= 0);
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS auth_security_tokens (
    id UUID PRIMARY KEY,
    purpose VARCHAR(32) NOT NULL,
    token_hash BYTEA NOT NULL,
    user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
    subject VARCHAR(255) NOT NULL DEFAULT '',
    secret_ciphertext TEXT,
    attempts INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 5,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT auth_security_tokens_purpose_check CHECK (
        purpose IN (
            'email_verify', 'email_bind', 'notify_email',
            'password_reset', 'totp_setup', 'totp_login'
        )
    ),
    CONSTRAINT auth_security_tokens_hash_length CHECK (octet_length(token_hash) = 32),
    CONSTRAINT auth_security_tokens_attempts_check CHECK (
        attempts >= 0 AND max_attempts > 0 AND attempts <= max_attempts
    ),
    CONSTRAINT auth_security_tokens_expiry_order CHECK (expires_at > created_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS auth_security_tokens_purpose_hash_key
    ON auth_security_tokens (purpose, token_hash);

CREATE INDEX IF NOT EXISTS auth_security_tokens_active_user_idx
    ON auth_security_tokens (user_id, purpose, expires_at)
    WHERE consumed_at IS NULL;

CREATE INDEX IF NOT EXISTS auth_security_tokens_active_subject_idx
    ON auth_security_tokens (subject, purpose, expires_at)
    WHERE consumed_at IS NULL;

CREATE INDEX IF NOT EXISTS auth_security_tokens_expires_at_idx
    ON auth_security_tokens (expires_at);
