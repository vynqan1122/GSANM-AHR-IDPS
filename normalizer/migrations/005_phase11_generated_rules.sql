-- Phase 11 generated-rule metadata. Generated rules remain candidate-only;
-- activation and validation are handled by later lifecycle phases.

ALTER TABLE ahr.rules
    ADD COLUMN IF NOT EXISTS origin varchar(64) NOT NULL DEFAULT 'manual',
    ADD COLUMN IF NOT EXISTS generator varchar(128),
    ADD COLUMN IF NOT EXISTS pattern jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS support integer NOT NULL DEFAULT 0 CHECK (support >= 0),
    ADD COLUMN IF NOT EXISTS confidence double precision CHECK (confidence BETWEEN 0 AND 1),
    ADD COLUMN IF NOT EXISTS model_versions jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS parent_rule_id text REFERENCES ahr.rules(rule_id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS ix_rules_generated_candidates
    ON ahr.rules (engine, confidence DESC, updated_at DESC)
    WHERE source = 'generated' AND status = 'candidate';

CREATE INDEX IF NOT EXISTS ix_rules_pattern_gin ON ahr.rules USING gin (pattern);
