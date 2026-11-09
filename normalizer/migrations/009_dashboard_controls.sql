CREATE TABLE IF NOT EXISTS ahr.ai_runtime_policy (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    enabled boolean NOT NULL DEFAULT true,
    fusion_threshold double precision NOT NULL DEFAULT 0.55 CHECK (fusion_threshold BETWEEN 0.05 AND 0.95),
    revision bigint NOT NULL DEFAULT 1,
    updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO ahr.ai_runtime_policy(singleton) VALUES (true) ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS ahr.dashboard_action_audit (
    action_id bigserial PRIMARY KEY,
    target text NOT NULL,
    action text NOT NULL,
    reason text NOT NULL,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_dashboard_action_target ON ahr.dashboard_action_audit(target, created_at DESC);
