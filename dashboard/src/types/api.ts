export interface EventRow {
  event_id: string;
  timestamp: string;
  source: string;
  event_type: string;
  src_ip?: string | null;
  dst_ip?: string | null;
  container?: { name?: string; image?: string } | null;
  rule?: { name?: string; rule_id?: string } | null;
  severity?: number | null;
  ai?: {
    rule_score?: number | null;
    network_score?: number | null;
    log_score?: number | null;
    graph_score?: number | null;
    context_score?: number | null;
    fusion_score?: number | null;
    risk_level?: string | null;
    fusion_breakdown?: unknown;
  } | null;
}

export interface Paged<T> {
  page: number;
  page_size: number;
  total: number;
  items: T[];
}

export interface SensorRow {
  sensor: string;
  status: string;
  last_event_at?: string | null;
  last_ingestion_at?: string | null;
  updated_at?: string | null;
  error_count: number;
}

export interface IncidentRow {
  incident_id: string;
  title: string;
  status: string;
  first_seen: string;
  last_seen: string;
  risk_score?: number | null;
  attack_type?: string | null;
  source_ips?: string[] | null;
  targets?: string[] | null;
  event_count: number;
  highest_severity?: number | null;
  ai_summary?: unknown;
  rule_summary?: unknown;
  attack_graph?: {
    nodes?: Array<{ id: string; kind: string; label: string }>;
    edges?: Array<{ source: string; target: string; relationship: string }>;
  } | null;
  timeline?: unknown[] | null;
  events?: EventRow[];
}

export interface RuleRow {
  rule_id: string;
  engine: string;
  name: string;
  status: string;
  source: string;
  origin?: string | null;
  generator?: string | null;
  support?: number | null;
  confidence?: number | null;
  pattern?: unknown;
  model_versions?: unknown;
  content?: string | null;
  shadow_metrics?: unknown;
  promotion_requires_approval?: boolean;
  validation_status?: string | null;
  validation_syntax_valid?: boolean | null;
  validation_replay_metrics?: {
    precision?: number;
    recall?: number;
    fpr?: number;
    match_count?: number;
  } | null;
}

export interface ResponseRow {
  response_id: string;
  incident_id?: string | null;
  action: string;
  action_type?: string | null;
  response_level?: string | null;
  status: string;
  target?: string | null;
  reason?: string | null;
  requested_by?: string | null;
  risk?: number | null;
  started_at: string;
  expires_at?: string | null;
  rollback_status?: string | null;
  evidence_path?: string | null;
  bundle_sha256?: string | null;
  evidence_file_count?: number | null;
}

export interface AlertRow {
  alert_id: string;
  timestamp: string;
  source: string;
  rule_id?: string | null;
  title?: string | null;
  severity?: number | null;
  src_ip?: string | null;
  dst_ip?: string | null;
  status: string;
}

export interface ContainerRow {
  name: string;
  image?: string | null;
  event_count?: number;
  last_seen?: string | null;
  falco_alert_count?: number;
  current_risk?: number | null;
}

export interface ModelRow {
  model_id: string;
  name: string;
  model_type?: string;
  version?: string;
  status?: string;
  artifact_uri?: string | null;
  artifact_metrics?: Record<string, unknown> | null;
  training_metadata?: { metrics?: Record<string, unknown>; training_rows?: number; source?: string; [key: string]: unknown } | null;
  activated_at?: string | null;
}

export interface ExperimentRow {
  experiment_id: string;
  name: string;
  model_config: unknown;
  status: string;
  results_path?: string | null;
  metrics?: Record<string, number>;
}

export interface TimeseriesPoint {
  bucket: string;
  source: string;
  count: number;
}

export interface OverviewData {
  cards: {
    total_events?: number;
    events_per_min?: number;
    active_alerts?: number;
    critical_alerts?: number;
    open_incidents?: number;
    critical_incidents?: number;
    overall_security_risk?: number;
    active_rules?: number;
    shadow_rules?: number;
    [key: string]: number | undefined;
  };
  events_by_source: Array<{ source: string; count: number }>;
  alerts_by_severity: Array<{ severity: number; count: number }>;
  top_source_ips: Array<{ src_ip: string; count: number }>;
  top_event_types: Array<{ event_type: string; count: number }>;
}

export interface NetworkSummaryData {
  summary: {
    flows_per_sec?: number;
    bytes_per_sec?: number;
    suricata_alerts?: number;
  };
  protocols: Array<{ protocol: string; count: number }>;
  top_sources: Array<{ src_ip: string; count: number }>;
  top_destinations: Array<{ dst_ip: string; count: number }>;
  top_destination_ports: Array<{ dst_port: number; count: number }>;
}

export interface SystemHealthData {
  overall: string;
  status: string;
  services: Record<string, string>;
}
