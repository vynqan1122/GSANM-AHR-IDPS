CREATE TABLE IF NOT EXISTS ahr.scenario_runs (
    scenario_id            text PRIMARY KEY,
    name                   text NOT NULL,
    label                  varchar(64) NOT NULL,
    attack_type            varchar(128),
    mode                   varchar(32) NOT NULL,
    start_time             timestamptz NOT NULL,
    end_time               timestamptz,
    source                 text NOT NULL,
    target                 text NOT NULL,
    notes                  text,
    request_count          integer NOT NULL DEFAULT 0 CHECK (request_count >= 0),
    created_at             timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_scenario_runs_time
    ON ahr.scenario_runs (start_time DESC, end_time DESC);
CREATE INDEX IF NOT EXISTS ix_scenario_runs_label
    ON ahr.scenario_runs (label, attack_type);

CREATE TABLE IF NOT EXISTS ahr.event_labels (
    event_id               text NOT NULL REFERENCES ahr.events(event_id) ON DELETE CASCADE,
    scenario_id            text NOT NULL REFERENCES ahr.scenario_runs(scenario_id) ON DELETE CASCADE,
    label                  varchar(64) NOT NULL,
    attack_type            varchar(128),
    match_reason           text NOT NULL,
    assigned_at            timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (event_id, scenario_id)
);
CREATE INDEX IF NOT EXISTS ix_event_labels_scenario
    ON ahr.event_labels (scenario_id, assigned_at);
CREATE INDEX IF NOT EXISTS ix_event_labels_label
    ON ahr.event_labels (label, attack_type);
