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
    -h|--help) printf 'Usage: ./scripts/verify_phase7.sh [--static-only]\n'; exit 0 ;;
    *) fail "Unknown option: $1" ;;
esac

ahr_prepare_env
ahr_require_ai_files
bash "$SCRIPT_DIR/wazuh_prepare.sh"
bash -n "$SCRIPT_DIR/verify_phase7.sh"

effective="$(ahr_ai_compose config)"
ahr_ai_compose config --quiet
services="$(ahr_ai_compose config --services)"
grep -qx ai-log <<<"$services" || fail 'Effective Phase 7 Compose model is missing ai-log'
log_section="$(ahr_compose_service_section ai-log <<<"$effective")"
grep -Eq '^[[:space:]]+read_only: true$' <<<"$log_section" || fail 'ai-log root filesystem must be read-only'
grep -Eq '^[[:space:]]+- ALL$' <<<"$log_section" || fail 'ai-log must drop all capabilities'
! grep -Eq '^[[:space:]]+(ports|network_mode):' <<<"$log_section" || fail 'ai-log must not publish ports or use host/shared namespace'
grep -Eq '^[[:space:]]+data:[[:space:]]*null$' <<<"$log_section" || fail 'ai-log must join only the data network'

for file in \
    ai/logs/sanitizer.py \
    ai/logs/representation.py \
    ai/logs/minilm.py \
    ai/logs/dataset.py \
    ai/logs/train.py \
    ai/logs/infer.py; do
    [[ -f "$AHR_PROJECT_ROOT/$file" ]] || fail "Missing Phase 7 file: $file"
done
grep -Fq 'EMBEDDING_DIM = 384' "$AHR_PROJECT_ROOT/ai/logs/minilm.py" || fail 'MiniLM embedding contract must be 384 dimensions'
pass 'Phase 7 static sanitizer, MiniLM embedding contract, training, inference, and Compose contract is present'

if [[ "$mode" == static ]]; then
    pass 'Phase 7 static acceptance PASS'
    exit 0
fi

ahr_check_docker_engine

ahr_ai_compose build ai-network
ahr_ai_compose run --rm --no-deps ai-network python -m pytest -q -p no:cacheprovider ai/logs/tests
pass 'Sanitizer, structured text representation, and 384-dim embedding tests passed'

ahr_ai_compose run --rm --no-deps ai-network python -m ai.logs.train >/tmp/ahr_phase7_train.out
grep -q '"model_id": "log-minilm-iforest-mlp"' "$AHR_PROJECT_ROOT/experiments/models/log-ai.metadata.json" || \
    fail 'Log AI metadata was not exported'
[[ -s "$AHR_PROJECT_ROOT/experiments/models/log-ai.joblib" ]] || fail 'Log AI artifact was not exported'
pass 'MiniLM-compatible embeddings, IsolationForest, and log classifier trained on labeled logs'

registry_count="$(ahr_ai_compose exec -T postgres sh -ec '
    PGPASSWORD="$AHR_DB_PASSWORD" exec psql --host=127.0.0.1 \
      --username="$AHR_DB_USER" --dbname="$POSTGRES_DB" \
      --tuples-only --no-align --set=ON_ERROR_STOP=1 \
      --command="SELECT count(*) FROM ahr.models WHERE model_id='\''log-minilm-iforest-mlp'\'' AND status='\''active'\'';"
' | tr -d '\r[:space:]')"
[[ "$registry_count" == 1 ]] || fail 'Model registry did not store active log AI model'

ahr_ai_compose up --detach --wait --wait-timeout 240 --force-recreate --no-deps ai-log
log_id="$(ahr_ai_compose ps -q ai-log)"
[[ -n "$log_id" ]] || fail 'ai-log is not running'
[[ "$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$log_id")" == healthy ]] || \
    fail 'ai-log did not become healthy'

marker="ahr_p7_$(date +%s)_$$_${RANDOM:-0}"
ahr_ai_compose exec -T dvwa sh -c ": ${marker}"

event_id=''
for _ in $(seq 1 90); do
    event_id="$(ahr_ai_compose exec -T postgres sh -ec '
        PGPASSWORD="$AHR_DB_PASSWORD" exec psql --host=127.0.0.1 \
          --username="$AHR_DB_USER" --dbname="$POSTGRES_DB" \
          --tuples-only --no-align --set=ON_ERROR_STOP=1 \
          --command="SELECT e.event_id FROM ahr.events e JOIN ahr.ai_predictions p ON p.event_id=e.event_id WHERE e.raw_event::text LIKE '\''%'$marker'%'\'' AND p.model_id='\''log-minilm-iforest-mlp'\'' LIMIT 1;"
    ' | tr -d '\r[:space:]')"
    [[ -n "$event_id" ]] && break
    sleep 2
done
[[ -n "$event_id" ]] || fail 'Realtime log inference did not create a prediction for the new marker event'
pass 'Realtime log inference writes true predictions for new normalized log events'

ahr_ai_compose exec -T backend python - "$event_id" <<'PY'
import asyncio
import sys
import httpx

event_id = sys.argv[1]
async def main():
    async with httpx.AsyncClient(timeout=10.0) as client:
        data = (await client.get(f"http://127.0.0.1:8000/api/events/{event_id}")).json()
    ai = data.get("ai") or {}
    if ai.get("log_score") is None:
        raise SystemExit("missing log_score")
asyncio.run(main())
PY
pass 'Dashboard API receives the log anomaly score from PostgreSQL'

bash "$SCRIPT_DIR/verify_phase6.sh"
pass 'Phase 7 runtime acceptance PASS: sanitizer, embeddings, IsolationForest, classifier, realtime prediction, dashboard score verified'
