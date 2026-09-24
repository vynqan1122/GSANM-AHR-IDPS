-- Phase 14 research evaluation, ablation, and final dashboard metadata.

CREATE TABLE IF NOT EXISTS ahr.experiment_runs (
    experiment_id text PRIMARY KEY,
    name text NOT NULL,
    model_config jsonb NOT NULL,
    dataset_split varchar(64) NOT NULL DEFAULT 'evaluation',
    status varchar(32) NOT NULL DEFAULT 'completed',
    started_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    results_path text,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS ahr.experiment_metrics (
    experiment_id text NOT NULL REFERENCES ahr.experiment_runs(experiment_id) ON DELETE CASCADE,
    metric_name varchar(128) NOT NULL,
    metric_value double precision NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (experiment_id, metric_name)
);

CREATE TABLE IF NOT EXISTS ahr.rule_shadow_metrics (
    rule_id text NOT NULL REFERENCES ahr.rules(rule_id) ON DELETE CASCADE,
    measured_at timestamptz NOT NULL DEFAULT now(),
    matches integer NOT NULL DEFAULT 0 CHECK (matches >= 0),
    precision double precision CHECK (precision BETWEEN 0 AND 1),
    recall double precision CHECK (recall BETWEEN 0 AND 1),
    fpr double precision CHECK (fpr BETWEEN 0 AND 1),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (rule_id, measured_at)
);

CREATE INDEX IF NOT EXISTS ix_experiment_runs_started_at
    ON ahr.experiment_runs (started_at DESC);

CREATE INDEX IF NOT EXISTS ix_rule_shadow_metrics_rule_id
    ON ahr.rule_shadow_metrics (rule_id, measured_at DESC);

