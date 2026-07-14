-- Durable replacement for the legacy Redis flagged-input hash set.
CREATE TABLE IF NOT EXISTS content_moderation_flagged_hashes (
    input_hash VARCHAR(64) PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT content_moderation_flagged_hashes_format_check
        CHECK (input_hash ~ '^[0-9a-f]{64}$')
);

CREATE INDEX IF NOT EXISTS content_moderation_flagged_hashes_created_at_idx
    ON content_moderation_flagged_hashes (created_at DESC);
