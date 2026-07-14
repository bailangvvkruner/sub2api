-- Cross-replica authentication abuse limits without persisting raw identities.

CREATE TABLE IF NOT EXISTS auth_rate_limit_windows (
    scope          VARCHAR(32) NOT NULL,
    subject_hash   BYTEA NOT NULL,
    attempts       INTEGER NOT NULL DEFAULT 0,
    window_started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at     TIMESTAMPTZ NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (scope, subject_hash),
    CONSTRAINT auth_rate_limit_windows_scope_check CHECK (
        scope IN ('login_failure', 'auth_action')
    ),
    CONSTRAINT auth_rate_limit_windows_hash_length CHECK (
        octet_length(subject_hash) = 32
    ),
    CONSTRAINT auth_rate_limit_windows_attempts_check CHECK (attempts >= 0),
    CONSTRAINT auth_rate_limit_windows_expiry_order CHECK (
        expires_at > window_started_at
    )
);

CREATE INDEX IF NOT EXISTS idx_auth_rate_limit_windows_expires_at
    ON auth_rate_limit_windows (expires_at);
