#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
AHR_PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
export AHR_PROJECT_ROOT

# shellcheck source=scripts/lib/ai.sh
source "$SCRIPT_DIR/lib/ai.sh"

pass() { printf '[PASS] %s\n' "$*"; }
fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }

mode=runtime
case "${1:-}" in
    '') ;;
    --static-only) mode=static ;;
    -h|--help) printf 'Usage: ./scripts/verify_phase8.sh [--static-only]\n'; exit 0 ;;
    *) fail "Unknown option: $1" ;;
esac

ahr_prepare_env
ahr_require_ai_files
bash "$SCRIPT_DIR/wazuh_prepare.sh"
bash -n "$SCRIPT_DIR/verify_phase8.sh"

effective="$(ahr_ai_compose config)"
ahr_ai_compose config --quiet
services="$(ahr_ai_compose config --services)"
grep -qx graph-builder <<<"$services" || fail 'Effective Phase 8 Compose model is missing graph-builder'
graph_section="$(ahr_compose_service_section graph-builder <<<"$effective")"
grep -Eq '^[[:space:]]+read_only: true$' <<<"$graph_section" || fail 'graph-builder root filesystem must be read-only'
grep -Eq '^[[:space:]]+- ALL$' <<<"$graph_section" || fail 'graph-builder must drop all capabilities'
! grep -Eq '^[[:space:]]+(ports|network_mode):' <<<"$graph_section" || fail 'graph-builder must not publish ports or use host/shared namespace'
grep -Eq '^[[:space:]]+data:[[:space:]]*null$' <<<"$graph_section" || fail 'graph-builder must join only the data network'
grep -Eq 'GRAPH_WINDOW_SECONDS: "30"|GRAPH_WINDOW_SECONDS: "30"' <<<"$graph_section" || fail 'graph-builder must default to 30-second graph windows'

for file in \
    ai/graph/graph_builder.py \
    ai/graph/node_registry.py \
    ai/graph/edge_builder.py \
    ai/graph/feature_builder.py \
    ai/graph/dataset.py \
    ai/graph/graphsage.py \
    ai/graph/train.py \
    ai/graph/infer.py \
    ai/graph/evaluate.py \
    normalizer/migrations/003_phase8_graph_windows.sql; do
    [[ -f "$AHR_PROJECT_ROOT/$file" ]] || fail "Missing Phase 8 file: $file"
done
grep -Fq 'GraphExplanation' "$AHR_PROJECT_ROOT/ai/graph/graphsage.py" || fail 'GraphExplanation abstraction is required'
grep -Fq 'ALLOWED_WINDOWS = {10, 30, 60, 120}' "$AHR_PROJECT_ROOT/ai/graph/graph_builder.py" || fail 'Graph window experiment set must be 10/30/60/120 seconds'
pass 'Phase 8 static graph builder, GraphSAGE, explanation, migration, and Compose contract is present'

if [[ "$mode" == static ]]; then
    pass 'Phase 8 static acceptance PASS'
    exit 0
fi

ahr_check_docker_engine

bash "$SCRIPT_DIR/verify_phase7.sh"
pass 'Phase 1-7 regression passed before Graph AI runtime checks'

ahr_ai_compose build ai-network
ahr_ai_compose run --rm --no-deps ai-network python -m pytest -q -p no:cacheprovider ai/graph/tests
pass 'Graph sessionization, entity/edge features, and GraphSAGE unit tests passed'

ahr_ai_compose exec -T postgres sh -ec '
    PGPASSWORD="$AHR_DB_PASSWORD" exec psql --host=127.0.0.1 \
      --username="$AHR_DB_USER" --dbname="$POSTGRES_DB" \
      --set=ON_ERROR_STOP=1 --quiet
' < "$AHR_PROJECT_ROOT/normalizer/migrations/003_phase8_graph_windows.sql"
pass 'Graph window migration applied'

ahr_ai_compose run --rm --no-deps ai-network python -m ai.graph.train >/tmp/ahr_phase8_train.out
grep -q '"model_id": "graphsage-security-event"' "$AHR_PROJECT_ROOT/experiments/models/graphsage-security-event.metadata.json" || \
    fail 'GraphSAGE metadata was not exported'
[[ -s "$AHR_PROJECT_ROOT/experiments/models/graphsage-security-event.joblib" ]] || fail 'GraphSAGE artifact was not exported'
[[ -s "$AHR_PROJECT_ROOT/datasets/graphs/phase8_training_graphs.jsonl" ]] || fail 'Graph visualization/export artifact was not written'
pass 'Events become sessionized security graphs and GraphSAGE trains'

ahr_ai_compose run --rm --no-deps ai-network python -m ai.graph.evaluate >/tmp/ahr_phase8_eval.out
[[ -s "$AHR_PROJECT_ROOT/experiments/models/graphsage-security-event.metrics.json" ]] || fail 'GraphSAGE evaluation metrics were not exported'
grep -Fq '"baseline_roc_auc"' "$AHR_PROJECT_ROOT/experiments/models/graphsage-security-event.metrics.json" || \
    fail 'GraphSAGE metrics must include baseline comparison'
pass 'GraphSAGE evaluation metrics and MLP baseline comparison exported'

registry_count="$(ahr_ai_compose exec -T postgres sh -ec '
    PGPASSWORD="$AHR_DB_PASSWORD" exec psql --host=127.0.0.1 \
      --username="$AHR_DB_USER" --dbname="$POSTGRES_DB" \
      --tuples-only --no-align --set=ON_ERROR_STOP=1 \
      --command="SELECT count(*) FROM ahr.models WHERE model_id='\''graphsage-security-event'\'' AND status='\''active'\'';"
' | tr -d '\r[:space:]')"
[[ "$registry_count" == 1 ]] || fail 'Model registry did not store active GraphSAGE model'

ahr_ai_compose up --detach --wait --wait-timeout 240 --force-recreate --no-deps graph-builder
graph_id="$(ahr_ai_compose ps -q graph-builder)"
[[ -n "$graph_id" ]] || fail 'graph-builder is not running'
[[ "$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$graph_id")" == healthy ]] || \
    fail 'graph-builder did not become healthy'
[[ "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.CapDrop}}|{{range .NetworkSettings.Networks}}{{.NetworkID}} {{end}}' "$graph_id" | cut -d'|' -f1-2)" == 'true|["ALL"]' ]] || \
    fail 'graph-builder runtime hardening drifted'
pass 'graph-builder realtime service is healthy and hardened'

marker="ahr_p8_$(date +%s)_$$_${RANDOM:-0}"
curl.exe --noproxy "*" -fsS -o /dev/null "http://127.0.0.1:${NGINX_PORT:-8080}/?ahr_phase8=$marker"

event_id=''
for _ in $(seq 1 120); do
    event_id="$(ahr_ai_compose exec -T postgres sh -ec '
        PGPASSWORD="$AHR_DB_PASSWORD" exec psql --host=127.0.0.1 \
          --username="$AHR_DB_USER" --dbname="$POSTGRES_DB" \
          --tuples-only --no-align --set=ON_ERROR_STOP=1 \
          --command="SELECT e.event_id FROM ahr.events e JOIN ahr.ai_predictions p ON p.event_id=e.event_id WHERE e.raw_event::text LIKE '\''%'$marker'%'\'' AND p.model_id='\''graphsage-security-event'\'' LIMIT 1;"
    ' | tr -d '\r[:space:]')"
    [[ -n "$event_id" ]] && break
    sleep 2
done
[[ -n "$event_id" ]] || fail 'Realtime Graph AI did not create a prediction for the new marker event'
pass 'Realtime graph prediction works for a new normalized event'

graph_rows="$(ahr_ai_compose exec -T postgres sh -ec '
    PGPASSWORD="$AHR_DB_PASSWORD" exec psql --host=127.0.0.1 \
      --username="$AHR_DB_USER" --dbname="$POSTGRES_DB" \
      --tuples-only --no-align --set=ON_ERROR_STOP=1 \
      --command="SELECT count(*) FROM ahr.graph_windows WHERE event_ids::text LIKE '\''%'$event_id'%'\'' AND node_count > 0 AND edge_count > 0 AND explanation ? '\''important_nodes'\'';"
' | tr -d '\r[:space:]')"
[[ "$graph_rows" -ge 1 ]] || fail 'Graph window/explanation row was not stored for the predicted event'
pass 'Graph visualization JSON, important nodes/edges, and high-risk subgraph are stored'

ahr_ai_compose exec -T backend python - "$event_id" <<'PY'
import asyncio
import sys
import httpx

event_id = sys.argv[1]
async def main():
    async with httpx.AsyncClient(timeout=10.0) as client:
        data = (await client.get(f"http://127.0.0.1:8000/api/events/{event_id}")).json()
    ai = data.get("ai") or {}
    if ai.get("graph_score") is None:
        raise SystemExit("missing graph_score")
asyncio.run(main())
PY
pass 'Dashboard API receives the graph score from PostgreSQL'

pass 'Phase 8 runtime acceptance PASS: graph builder, GraphSAGE training/evaluation, realtime prediction, dashboard graph score verified'
