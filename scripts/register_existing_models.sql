-- Register shipped model artifacts so realtime inference can satisfy the
-- ahr.ai_predictions -> ahr.models foreign key after a fresh database.
INSERT INTO ahr.models (model_id, name, model_type, version, status, artifact_uri, feature_schema, training_metadata, activated_at)
VALUES
  ('network-xgboost', 'network-ai', 'xgboost', 'network-v1', 'active', '/opt/ahr-idps/experiments/models/network-xgboost.json', '{"features_version":"network-v1"}'::jsonb, '{"source":"shipped-artifact"}'::jsonb, now()),
  ('log-minilm-iforest-mlp', 'log-ai', 'minilm-iforest-mlp', 'log-v1', 'active', '/opt/ahr-idps/experiments/models/log-ai.joblib', '{"embedding_model":"all-MiniLM-L6-v2-compatible-384"}'::jsonb, '{"source":"shipped-artifact"}'::jsonb, now()),
  ('graphsage-security-event', 'graph-ai', 'graphsage-window', 'graphsage-v1', 'active', '/opt/ahr-idps/experiments/models/graphsage-security-event.joblib', '{"window_seconds":30}'::jsonb, '{"source":"shipped-artifact"}'::jsonb, now()),
  ('fusion-hybrid-xgboost', 'fusion-ai', 'xgboost-meta-fusion', 'fusion-v1', 'active', '/opt/ahr-idps/experiments/models/fusion-hybrid-xgboost.json', '{"features":["rule_score","network_score","log_score","graph_score","context_score","severity","event_density","missing_count"]}'::jsonb, '{"source":"shipped-artifact"}'::jsonb, now())
ON CONFLICT (model_id) DO UPDATE SET
  status = 'active',
  artifact_uri = excluded.artifact_uri,
  feature_schema = excluded.feature_schema,
  training_metadata = excluded.training_metadata,
  activated_at = now();
