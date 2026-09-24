-- Phase 12 rule lifecycle and shadow-mode metadata.

ALTER TABLE ahr.rules
    ADD COLUMN IF NOT EXISTS shadow_metrics jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS promotion_requires_approval boolean NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS disabled_reason text;

CREATE INDEX IF NOT EXISTS ix_rules_shadow_status
    ON ahr.rules (status, updated_at DESC)
    WHERE status IN ('shadow', 'active', 'rejected', 'disabled');
