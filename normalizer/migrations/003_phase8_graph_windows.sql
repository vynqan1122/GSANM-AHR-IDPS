CREATE TABLE IF NOT EXISTS ahr.graph_windows (
    graph_id          text PRIMARY KEY,
    session_key       text NOT NULL,
    window_start      timestamptz NOT NULL,
    window_seconds    integer NOT NULL CHECK (window_seconds IN (10, 30, 60, 120)),
    event_ids         jsonb NOT NULL DEFAULT '[]'::jsonb,
    node_count        integer NOT NULL CHECK (node_count >= 0),
    edge_count        integer NOT NULL CHECK (edge_count >= 0),
    graph_json        jsonb NOT NULL DEFAULT '{}'::jsonb,
    embedding         jsonb NOT NULL DEFAULT '[]'::jsonb,
    explanation       jsonb NOT NULL DEFAULT '{}'::jsonb,
    score             double precision CHECK (score BETWEEN 0 AND 1),
    model_id          text REFERENCES ahr.models(model_id) ON DELETE SET NULL,
    model_version     text,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_graph_windows_time
    ON ahr.graph_windows (window_start DESC);
CREATE INDEX IF NOT EXISTS ix_graph_windows_session
    ON ahr.graph_windows (session_key, window_start DESC);
