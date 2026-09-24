-- AHR-IDPS Phase 3 event store. No extension, database CREATE, or superuser
-- privilege is required; Phase 1 provisions schema ahr for the app role.

CREATE TABLE IF NOT EXISTS ahr.events (
    event_id               text PRIMARY KEY,
    source_event_id        text,
    timestamp              timestamptz NOT NULL,
    ingestion_timestamp    timestamptz NOT NULL,
    source                 varchar(64) NOT NULL,
    event_type             varchar(128) NOT NULL,
    category               varchar(128),
    src_ip                 text,
    src_port               integer CHECK (src_port BETWEEN 0 AND 65535),
    dst_ip                 text,
    dst_port               integer CHECK (dst_port BETWEEN 0 AND 65535),
    protocol               varchar(32),
    http                   jsonb,
    container              jsonb,
    process                jsonb,
    user_details           jsonb,
    file_details           jsonb,
    network                jsonb,
    rule                   jsonb,
    severity               smallint CHECK (severity BETWEEN 0 AND 10),
    labels                 jsonb NOT NULL DEFAULT '{}'::jsonb,
    ai                     jsonb NOT NULL DEFAULT '{
      "network_score": null,
      "network_class": null,
      "log_score": null,
      "graph_score": null,
      "fusion_score": null,
      "risk_level": null,
      "model_versions": {}
    }'::jsonb,
    raw_event              jsonb NOT NULL,
    metadata               jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at             timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_events_source_source_event_id
    ON ahr.events (source, source_event_id)
    WHERE source_event_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_events_timestamp ON ahr.events (timestamp DESC);
CREATE INDEX IF NOT EXISTS ix_events_source_timestamp ON ahr.events (source, timestamp DESC);
CREATE INDEX IF NOT EXISTS ix_events_event_type_timestamp ON ahr.events (event_type, timestamp DESC);
CREATE INDEX IF NOT EXISTS ix_events_src_ip_timestamp ON ahr.events (src_ip, timestamp DESC)
    WHERE src_ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_events_container_name
    ON ahr.events ((container ->> 'name'), timestamp DESC)
    WHERE container IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_events_severity_timestamp ON ahr.events (severity, timestamp DESC)
    WHERE severity IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_events_labels_gin ON ahr.events USING gin (labels);
CREATE INDEX IF NOT EXISTS ix_events_raw_event_gin ON ahr.events USING gin (raw_event jsonb_path_ops);

CREATE TABLE IF NOT EXISTS ahr.alerts (
    alert_id               text PRIMARY KEY,
    event_id               text NOT NULL UNIQUE REFERENCES ahr.events(event_id) ON DELETE CASCADE,
    timestamp              timestamptz NOT NULL,
    source                 varchar(64) NOT NULL,
    engine                 varchar(64),
    rule_id                text,
    title                  text,
    category               varchar(128),
    severity               smallint CHECK (severity BETWEEN 0 AND 10),
    status                 varchar(32) NOT NULL DEFAULT 'new',
    created_at             timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_alerts_timestamp ON ahr.alerts (timestamp DESC);
CREATE INDEX IF NOT EXISTS ix_alerts_severity_timestamp ON ahr.alerts (severity, timestamp DESC);
CREATE INDEX IF NOT EXISTS ix_alerts_status_timestamp ON ahr.alerts (status, timestamp DESC);

CREATE TABLE IF NOT EXISTS ahr.incidents (
    incident_id            text PRIMARY KEY,
    title                  text NOT NULL,
    description            text,
    status                 varchar(32) NOT NULL DEFAULT 'open',
    severity               smallint CHECK (severity BETWEEN 0 AND 10),
    risk_score             double precision,
    confidence             double precision CHECK (confidence BETWEEN 0 AND 1),
    first_seen             timestamptz NOT NULL,
    last_seen              timestamptz NOT NULL,
    attack_chain_stage     varchar(128),
    mitre_techniques       jsonb NOT NULL DEFAULT '[]'::jsonb,
    entities               jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_incidents_last_seen ON ahr.incidents (last_seen DESC);
CREATE INDEX IF NOT EXISTS ix_incidents_severity ON ahr.incidents (severity, last_seen DESC);

CREATE TABLE IF NOT EXISTS ahr.incident_events (
    incident_id            text NOT NULL REFERENCES ahr.incidents(incident_id) ON DELETE CASCADE,
    event_id               text NOT NULL REFERENCES ahr.events(event_id) ON DELETE CASCADE,
    relationship           varchar(64) NOT NULL DEFAULT 'correlated',
    confidence             double precision CHECK (confidence BETWEEN 0 AND 1),
    added_at               timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (incident_id, event_id)
);
CREATE INDEX IF NOT EXISTS ix_incident_events_incident_id ON ahr.incident_events (incident_id, added_at);
CREATE INDEX IF NOT EXISTS ix_incident_events_event_id ON ahr.incident_events (event_id);

CREATE TABLE IF NOT EXISTS ahr.network_flows (
    flow_row_id            text PRIMARY KEY REFERENCES ahr.events(event_id) ON DELETE CASCADE,
    flow_id                text,
    timestamp              timestamptz NOT NULL,
    src_ip                 text,
    src_port               integer CHECK (src_port BETWEEN 0 AND 65535),
    dst_ip                 text,
    dst_port               integer CHECK (dst_port BETWEEN 0 AND 65535),
    protocol               varchar(32),
    packets_to_server      bigint CHECK (packets_to_server >= 0),
    packets_to_client      bigint CHECK (packets_to_client >= 0),
    bytes_to_server        bigint CHECK (bytes_to_server >= 0),
    bytes_to_client        bigint CHECK (bytes_to_client >= 0),
    state                  varchar(64),
    features               jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at             timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_network_flows_timestamp ON ahr.network_flows (timestamp DESC);
CREATE INDEX IF NOT EXISTS ix_network_flows_flow_id ON ahr.network_flows (flow_id)
    WHERE flow_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_network_flows_src_ip ON ahr.network_flows (src_ip, timestamp DESC);

CREATE TABLE IF NOT EXISTS ahr.models (
    model_id               text PRIMARY KEY,
    name                   text NOT NULL,
    model_type             varchar(64) NOT NULL,
    version                text NOT NULL,
    status                 varchar(32) NOT NULL DEFAULT 'registered',
    artifact_uri           text,
    artifact_sha256        char(64),
    feature_schema         jsonb NOT NULL DEFAULT '{}'::jsonb,
    training_metadata      jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at             timestamptz NOT NULL DEFAULT now(),
    activated_at           timestamptz,
    UNIQUE (name, version)
);

CREATE TABLE IF NOT EXISTS ahr.ai_predictions (
    prediction_id          text PRIMARY KEY,
    event_id               text REFERENCES ahr.events(event_id) ON DELETE CASCADE,
    model_id               text REFERENCES ahr.models(model_id) ON DELETE RESTRICT,
    model_version          text NOT NULL,
    task                   varchar(64) NOT NULL,
    score                  double precision,
    predicted_class        text,
    risk_level             varchar(32),
    confidence             double precision CHECK (confidence BETWEEN 0 AND 1),
    explanation            jsonb NOT NULL DEFAULT '{}'::jsonb,
    missing_components     jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at             timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_ai_predictions_event_id ON ahr.ai_predictions (event_id);
CREATE INDEX IF NOT EXISTS ix_ai_predictions_created_at ON ahr.ai_predictions (created_at DESC);

CREATE TABLE IF NOT EXISTS ahr.model_metrics (
    metric_id              bigserial PRIMARY KEY,
    model_id               text NOT NULL REFERENCES ahr.models(model_id) ON DELETE CASCADE,
    dataset_split          varchar(32) NOT NULL,
    metric_name            varchar(128) NOT NULL,
    metric_value           double precision NOT NULL,
    threshold              double precision,
    measured_at            timestamptz NOT NULL DEFAULT now(),
    metadata               jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS ix_model_metrics_model_id ON ahr.model_metrics (model_id, measured_at DESC);

CREATE TABLE IF NOT EXISTS ahr.rules (
    rule_id                text PRIMARY KEY,
    engine                 varchar(64) NOT NULL,
    name                   text NOT NULL,
    description            text,
    status                 varchar(32) NOT NULL DEFAULT 'candidate',
    source                 varchar(64) NOT NULL DEFAULT 'manual',
    current_version        integer NOT NULL DEFAULT 1 CHECK (current_version > 0),
    created_by             text,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_rules_status ON ahr.rules (status, updated_at DESC);

CREATE TABLE IF NOT EXISTS ahr.rule_versions (
    rule_id                text NOT NULL REFERENCES ahr.rules(rule_id) ON DELETE CASCADE,
    version                integer NOT NULL CHECK (version > 0),
    content                text NOT NULL,
    content_sha256         char(64) NOT NULL,
    metadata               jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_by             text,
    created_at             timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (rule_id, version)
);

-- Cross-rule duplicate/conflict checks require engine-aware semantic validation
-- and belong to Phase 12. This index prevents duplicate content per rule.
CREATE UNIQUE INDEX IF NOT EXISTS uq_rule_versions_rule_content
    ON ahr.rule_versions (rule_id, content_sha256);

CREATE TABLE IF NOT EXISTS ahr.rule_validation_runs (
    validation_id          text PRIMARY KEY,
    rule_id                text NOT NULL,
    rule_version           integer NOT NULL,
    status                 varchar(32) NOT NULL,
    syntax_valid           boolean,
    duplicate_of           text REFERENCES ahr.rules(rule_id) ON DELETE SET NULL,
    conflicts              jsonb NOT NULL DEFAULT '[]'::jsonb,
    replay_metrics         jsonb NOT NULL DEFAULT '{}'::jsonb,
    performance_metrics    jsonb NOT NULL DEFAULT '{}'::jsonb,
    error_message          text,
    started_at             timestamptz NOT NULL DEFAULT now(),
    completed_at           timestamptz,
    FOREIGN KEY (rule_id, rule_version)
        REFERENCES ahr.rule_versions(rule_id, version) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_rule_validation_runs_rule_id
    ON ahr.rule_validation_runs (rule_id, started_at DESC);

CREATE TABLE IF NOT EXISTS ahr.responses (
    response_id            text PRIMARY KEY,
    incident_id            text REFERENCES ahr.incidents(incident_id) ON DELETE SET NULL,
    event_id               text REFERENCES ahr.events(event_id) ON DELETE SET NULL,
    action_type            varchar(64) NOT NULL,
    response_level         varchar(32) NOT NULL DEFAULT 'alert_only',
    status                 varchar(32) NOT NULL,
    target                 text,
    parameters             jsonb NOT NULL DEFAULT '{}'::jsonb,
    rollback_data          jsonb NOT NULL DEFAULT '{}'::jsonb,
    requested_by           text,
    started_at             timestamptz NOT NULL DEFAULT now(),
    expires_at             timestamptz,
    completed_at           timestamptz,
    error_message          text
);
CREATE INDEX IF NOT EXISTS ix_responses_incident_id ON ahr.responses (incident_id, started_at DESC);
CREATE INDEX IF NOT EXISTS ix_responses_status ON ahr.responses (status, started_at DESC);

CREATE TABLE IF NOT EXISTS ahr.sensor_health (
    sensor                 varchar(64) PRIMARY KEY,
    status                 varchar(32) NOT NULL,
    last_event_at          timestamptz,
    last_ingestion_at      timestamptz,
    last_error_at          timestamptz,
    error_count            bigint NOT NULL DEFAULT 0 CHECK (error_count >= 0),
    details                jsonb NOT NULL DEFAULT '{}'::jsonb,
    updated_at             timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_sensor_health_status ON ahr.sensor_health (status, updated_at DESC);
