#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
AHR_PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
export AHR_PROJECT_ROOT

# shellcheck source=scripts/lib/ai.sh
source "$SCRIPT_DIR/lib/ai.sh"

pass() {
    printf '[PASS] %s\n' "$*"
}

fail() {
    printf '[FAIL] %s\n' "$*" >&2
    exit 1
}

mode=runtime
case "${1:-}" in
    '') ;;
    --static-only) mode=static ;;
    -h|--help)
        printf 'Usage: ./scripts/verify_phase6.sh [--static-only]\n'
        exit 0
        ;;
    *) fail "Unknown option: $1" ;;
esac

ahr_prepare_env
ahr_require_ai_files
bash "$SCRIPT_DIR/wazuh_prepare.sh"

for script in "$SCRIPT_DIR/lib/ai.sh" "$SCRIPT_DIR/verify_phase6.sh"; do
    bash -n "$script"
done

effective="$(ahr_ai_compose config)"
ahr_ai_compose config --quiet
services="$(ahr_ai_compose config --services)"
grep -qx ai-network <<<"$services" || fail 'Effective Phase 6 Compose model is missing ai-network'

ai_section="$(ahr_compose_service_section ai-network <<<"$effective")"
[[ -n "$ai_section" ]] || fail 'Cannot inspect effective ai-network service'
grep -Eq '^[[:space:]]+read_only: true$' <<<"$ai_section" || fail 'ai-network root filesystem must be read-only'
grep -Eq '^[[:space:]]+- ALL$' <<<"$ai_section" || fail 'ai-network must drop all capabilities'
! grep -Eq '^[[:space:]]+(ports|network_mode):' <<<"$ai_section" || fail 'ai-network must not publish ports or use host/shared namespace'
grep -Eq '^[[:space:]]+data:[[:space:]]*null$' <<<"$ai_section" || fail 'ai-network must join only the data network'

for file in \
    feature_engine/network_features.py \
    feature_engine/window_features.py \
    feature_engine/encoders.py \
    feature_engine/scaler.py \
    feature_engine/versioning.py \
    ai/network/dataset.py \
    ai/network/xgboost_model.py \
    ai/network/train_xgboost.py \
    ai/network/evaluate.py \
    ai/network/infer.py \
    ai/network/registry.py; do
    [[ -f "$AHR_PROJECT_ROOT/$file" ]] || fail "Missing Phase 6 file: $file"
done

feature_block="$(awk '
    /^NETWORK_FEATURES = \[/ { in_block=1 }
    in_block { print }
    in_block && /^\]/ { exit }
' "$AHR_PROJECT_ROOT/feature_engine/versioning.py")"
for banned in scenario_id label attack_type timestamp container_id attacker_ip; do
    ! grep -Eq "\"$banned\"|'$banned'" <<<"$feature_block" || \
        fail "Feature schema leaks forbidden field: $banned"
done

pass 'Phase 6 static feature engineering, XGBoost, registry, inference, and Compose contract is present'

if [[ "$mode" == static ]]; then
    pass 'Phase 6 static acceptance PASS'
    exit 0
fi

ahr_check_docker_engine

scenario_rows="$(ahr_ai_compose exec -T postgres sh -ec '
    PGPASSWORD="$AHR_DB_PASSWORD" exec psql --host=127.0.0.1 \
      --username="$AHR_DB_USER" --dbname="$POSTGRES_DB" \
      --tuples-only --no-align --set=ON_ERROR_STOP=1 \
      --command="SELECT count(*) FROM ahr.event_labels;"
' | tr -d '\r[:space:]')"
[[ "$scenario_rows" =~ ^[0-9]+$ ]] && (( scenario_rows > 0 )) || \
    fail 'Phase 6 requires labeled Phase 5 events; run scripts/verify_phase5.sh first'

ahr_ai_compose build ai-network
ahr_ai_compose run --rm --no-deps ai-network python -m pytest -q -p no:cacheprovider ai/network/tests
pass 'Network feature tests passed and no leakage fields are present'

ahr_ai_compose run --rm --no-deps ai-network python -m ai.network.train_xgboost >/tmp/ahr_phase6_train.out
grep -q '"model_id": "network-xgboost"' "$AHR_PROJECT_ROOT/experiments/models/network-xgboost.metadata.json" || \
    fail 'XGBoost metadata was not exported'
[[ -s "$AHR_PROJECT_ROOT/experiments/models/network-xgboost.json" ]] || \
    fail 'XGBoost model artifact was not exported'
pass 'XGBoost trained on the Phase 5 dataset and exported metrics/artifact'

registry_count="$(ahr_ai_compose exec -T postgres sh -ec '
    PGPASSWORD="$AHR_DB_PASSWORD" exec psql --host=127.0.0.1 \
      --username="$AHR_DB_USER" --dbname="$POSTGRES_DB" \
      --tuples-only --no-align --set=ON_ERROR_STOP=1 \
      --command="SELECT count(*) FROM ahr.models WHERE model_id='\''network-xgboost'\'' AND status='\''active'\'';"
' | tr -d '\r[:space:]')"
[[ "$registry_count" == 1 ]] || fail 'Model registry did not store active network-xgboost model'
pass 'Model registry stores the active network XGBoost model'

ahr_ai_compose up --detach --wait --wait-timeout 240 --force-recreate --no-deps ai-network
ai_id="$(ahr_ai_compose ps -q ai-network)"
[[ -n "$ai_id" ]] || fail 'ai-network is not running'
[[ "$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$ai_id")" == healthy ]] || \
    fail 'ai-network did not become healthy'

marker="ahr_p6_$(date +%s)_$$_${RANDOM:-0}"
ahr_ai_compose exec -T backend python - "$marker" <<'PY'
import httpx
import sys

marker = sys.argv[1]
response = httpx.get(
    "http://nginx/ahr-phase6",
    params={"ahr_phase6": marker},
    headers={"Host": "dvwa.local", "Connection": "close"},
    timeout=15.0,
    follow_redirects=True,
)
if response.status_code >= 500:
    raise SystemExit(response.status_code)
PY

event_id=''
for _ in $(seq 1 90); do
    event_id="$(ahr_ai_compose exec -T postgres sh -ec '
        PGPASSWORD="$AHR_DB_PASSWORD" exec psql --host=127.0.0.1 \
          --username="$AHR_DB_USER" --dbname="$POSTGRES_DB" \
          --tuples-only --no-align --set=ON_ERROR_STOP=1 \
          --command="SELECT e.event_id FROM ahr.events e JOIN ahr.ai_predictions p ON p.event_id=e.event_id WHERE e.raw_event::text LIKE '\''%'$marker'%'\'' AND p.model_id='\''network-xgboost'\'' LIMIT 1;"
    ' | tr -d '\r[:space:]')"
    [[ -n "$event_id" ]] && break
    sleep 2
done
[[ -n "$event_id" ]] || fail 'Realtime network inference did not create a prediction for the new marker event'
pass 'Realtime network inference writes true predictions for new normalized events'

ahr_ai_compose exec -T backend python - "$event_id" <<'PY'
import asyncio
import sys
import httpx

event_id = sys.argv[1]

async def main():
    async with httpx.AsyncClient(timeout=10.0) as client:
        data = (await client.get(f"http://127.0.0.1:8000/api/events/{event_id}")).json()
    ai = data.get("ai") or {}
    if ai.get("network_score") is None:
        raise SystemExit("missing network_score")

asyncio.run(main())
PY
pass 'Dashboard API receives the AI network score from PostgreSQL'

bash "$SCRIPT_DIR/verify_phase5.sh"
pass 'Phase 6 runtime acceptance PASS: dataset loads, XGBoost trains, registry stores, realtime inference and dashboard score verified'
