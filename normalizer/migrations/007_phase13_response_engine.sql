-- Phase 13 controlled incident response, rollback, and evidence metadata.

ALTER TABLE ahr.responses
    ADD COLUMN IF NOT EXISTS action varchar(64),
    ADD COLUMN IF NOT EXISTS reason text,
    ADD COLUMN IF NOT EXISTS risk double precision CHECK (risk BETWEEN 0 AND 1),
    ADD COLUMN IF NOT EXISTS rollback_status varchar(32) NOT NULL DEFAULT 'not_required',
    ADD COLUMN IF NOT EXISTS action_audit jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();

UPDATE ahr.responses
SET action = coalesce(action, action_type)
WHERE action IS NULL;

ALTER TABLE ahr.responses
    ALTER COLUMN action SET DEFAULT 'log';

CREATE INDEX IF NOT EXISTS ix_responses_action_started_at
    ON ahr.responses (action, started_at DESC);

CREATE INDEX IF NOT EXISTS ix_responses_expires_at
    ON ahr.responses (expires_at)
    WHERE expires_at IS NOT NULL AND status IN ('active', 'pending');

CREATE TABLE IF NOT EXISTS ahr.evidence (
    evidence_id text PRIMARY KEY,
    incident_id text NOT NULL REFERENCES ahr.incidents(incident_id) ON DELETE CASCADE,
    response_id text REFERENCES ahr.responses(response_id) ON DELETE SET NULL,
    path text NOT NULL,
    manifest jsonb NOT NULL,
    bundle_sha256 char(64) NOT NULL,
    file_count integer NOT NULL CHECK (file_count >= 0),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_evidence_incident_id
    ON ahr.evidence (incident_id, created_at DESC);

