-- Phase 10 incident correlation enriches the Phase 3 incident schema without
-- replacing existing tables or requiring elevated database privileges.

ALTER TABLE ahr.incidents
    ADD COLUMN IF NOT EXISTS attack_type text,
    ADD COLUMN IF NOT EXISTS source_ips jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS targets jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS event_count integer NOT NULL DEFAULT 0 CHECK (event_count >= 0),
    ADD COLUMN IF NOT EXISTS highest_severity smallint CHECK (highest_severity BETWEEN 0 AND 10),
    ADD COLUMN IF NOT EXISTS ai_summary jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS rule_summary jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS response_status varchar(32) NOT NULL DEFAULT 'none',
    ADD COLUMN IF NOT EXISTS attack_graph jsonb NOT NULL DEFAULT '{"nodes":[],"edges":[]}'::jsonb,
    ADD COLUMN IF NOT EXISTS timeline jsonb NOT NULL DEFAULT '[]'::jsonb;

CREATE INDEX IF NOT EXISTS ix_incidents_status_last_seen ON ahr.incidents (status, last_seen DESC);
CREATE INDEX IF NOT EXISTS ix_incidents_risk_score ON ahr.incidents (risk_score DESC, last_seen DESC);
CREATE INDEX IF NOT EXISTS ix_incidents_attack_type ON ahr.incidents (attack_type, last_seen DESC)
    WHERE attack_type IS NOT NULL;
