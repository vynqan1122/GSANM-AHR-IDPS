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
    -h|--help) printf 'Usage: ./scripts/verify_phase9.sh [--static-only]\n'; exit 0 ;;
    *) fail "Unknown option: $1" ;;
esac

ahr_prepare_env
ahr_require_ai_files
bash "$SCRIPT_DIR/wazuh_prepare.sh"
bash -n "$SCRIPT_DIR/verify_phase9.sh"

effective="$(ahr_ai_compose config)"
ahr_ai_compose config --quiet
services="$(ahr_ai_compose config --services)"
grep -qx fusion-engine <<<"$services" || fail 'Effective Phase 9 Compose model is missing fusion-engine'
fusion_section="$(ahr_compose_service_section fusion-engine <<<"$effective")"
grep -Eq '^[[:space:]]+read_only: true$' <<<"$fusion_section" || fail 'fusion-engine root filesystem must be read-only'
grep -Eq '^[[:space:]]+- ALL$' <<<"$fusion_section" || fail 'fusion-engine must drop all capabilities'
! grep -Eq '^[[:space:]]+(ports|network_mode):' <<<"$fusion_section" || fail 'fusion-engine must not publish ports or use host/shared namespace'
grep -Eq '^[[:space:]]+data:[[:space:]]*null$' <<<"$fusion_section" || fail 'fusion-engine must join only the data network'
grep -Eq 'FUSION_START_AT_END: "true"|FUSION_START_AT_END: true' <<<"$fusion_section" || fail 'fusion-engine must start at stream tail to avoid old prediction replay'

for file in \
    ai/fusion/scoring.py \
    ai/fusion/dataset.py \
    ai/fusion/train.py \
    ai/fusion/evaluate.py \
    ai/fusion/infer.py \
    ai/fusion/tests/test_fusion.py; do
    [[ -f "$AHR_PROJECT_ROOT/$file" ]] || fail "Missing Phase 9 file: $file"
done

grep -Fq '"rule_score": 0.25' "$AHR_PROJECT_ROOT/ai/fusion/scoring.py" || fail 'Fusion baseline must include rule weight 0.25'
grep -Fq '"network_score": 0.25' "$AHR_PROJECT_ROOT/ai/fusion/scoring.py" || fail 'Fusion baseline must include network weight 0.25'
grep -Fq '"log_score": 0.20' "$AHR_PROJECT_ROOT/ai/fusion/scoring.py" || fail 'Fusion baseline must include log weight 0.20'
grep -Fq '"graph_score": 0.25' "$AHR_PROJECT_ROOT/ai/fusion/scoring.py" || fail 'Fusion baseline must include graph weight 0.25'
grep -Fq '"context_score": 0.05' "$AHR_PROJECT_ROOT/ai/fusion/scoring.py" || fail 'Fusion baseline must include context weight 0.05'
grep -Fq 'normalized_weights' "$AHR_PROJECT_ROOT/ai/fusion/scoring.py" || fail 'Fusion baseline must renormalize available weights'
grep -Fq 'fusion-hybrid-xgboost' "$AHR_PROJECT_ROOT/ai/fusion/train.py" || fail 'Fusion meta-classifier model id is missing'
dashboard_assets="$AHR_PROJECT_ROOT/dashboard/dist/assets"
grep -R -Fq --include='*.js' 'AI Monitor' "$dashboard_assets" || fail 'Dashboard must display the AI monitor'
grep -R -Fq --include='*.js' 'Fusion score' "$dashboard_assets" || fail 'Dashboard must display fusion score'
grep -R -Fq --include='*.js' 'Generated rules' "$dashboard_assets" || fail 'Dashboard must display generated rules'
pass 'Phase 9 static fusion scoring, XGBoost meta-classifier, Compose, and dashboard contracts are present'

if [[ "$mode" == static ]]; then
    pass 'Phase 9 static acceptance PASS'
    exit 0
fi

ahr_check_docker_engine

bash "$SCRIPT_DIR/verify_phase8.sh"
pass 'Phase 1-8 regression passed before hybrid fusion runtime checks'

ahr_ai_compose build ai-network
ahr_ai_compose run --rm --no-deps ai-network python -m pytest -q -p no:cacheprovider ai/fusion/tests
pass 'Fusion unit tests passed: non-binary rule score and missing-score renormalization'

ahr_ai_compose run --rm --no-deps ai-network python - <<'PY'
from ai.fusion.scoring import weighted_baseline

result = weighted_baseline({
    "rule_score": 0.70,
    "network_score": 0.80,
    "log_score": None,
    "graph_score": None,
    "context_score": 0.20,
})
assert "graph_score" in result.missing_scores
assert "log_score" in result.missing_scores
assert abs(sum(result.normalized_weights.values()) - 1.0) < 1e-6
assert result.fusion_score > 0.0
print(result.to_dict())
PY
pass 'Missing AI scores are renormalized instead of treated as zero'

ahr_ai_compose run --rm --no-deps ai-network python -m ai.fusion.train >/tmp/ahr_phase9_train.out
grep -q '"model_id": "fusion-hybrid-xgboost"' "$AHR_PROJECT_ROOT/experiments/models/fusion-hybrid-xgboost.metadata.json" || \
    fail 'Fusion metadata was not exported'
[[ -s "$AHR_PROJECT_ROOT/experiments/models/fusion-hybrid-xgboost.json" ]] || fail 'Fusion XGBoost artifact was not exported'
pass 'XGBoost meta-classifier trained on real rule/network/log/graph/context features'

ahr_ai_compose run --rm --no-deps ai-network python -m ai.fusion.evaluate >/tmp/ahr_phase9_eval.out
[[ -s "$AHR_PROJECT_ROOT/experiments/models/fusion-hybrid-xgboost.metrics.json" ]] || fail 'Fusion evaluation metrics were not exported'
grep -Fq '"roc_auc"' "$AHR_PROJECT_ROOT/experiments/models/fusion-hybrid-xgboost.metrics.json" || \
    fail 'Fusion metrics must include roc_auc'
pass 'Fusion meta-classifier evaluation metrics exported'

registry_count="$(ahr_ai_compose exec -T postgres sh -ec '
    PGPASSWORD="$AHR_DB_PASSWORD" exec psql --host=127.0.0.1 \
      --username="$AHR_DB_USER" --dbname="$POSTGRES_DB" \
      --tuples-only --no-align --set=ON_ERROR_STOP=1 \
      --command="SELECT count(*) FROM ahr.models WHERE model_id='\''fusion-hybrid-xgboost'\'' AND status='\''active'\'';"
' | tr -d '\r[:space:]')"
[[ "$registry_count" == 1 ]] || fail 'Model registry did not store active fusion model'

ahr_ai_compose up --detach --wait --wait-timeout 240 --force-recreate --no-deps fusion-engine
fusion_id="$(ahr_ai_compose ps -q fusion-engine)"
[[ -n "$fusion_id" ]] || fail 'fusion-engine is not running'
[[ "$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$fusion_id")" == healthy ]] || \
    fail 'fusion-engine did not become healthy'
[[ "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.CapDrop}}|{{range .NetworkSettings.Networks}}{{.NetworkID}} {{end}}' "$fusion_id" | cut -d'|' -f1-2)" == 'true|["ALL"]' ]] || \
    fail 'fusion-engine runtime hardening drifted'
pass 'fusion-engine realtime service is healthy and hardened'

marker="ahr_p9_$(date +%s)_$$_${RANDOM:-0}"
curl --noproxy '*' -fsS -o /dev/null "http://127.0.0.1:${NGINX_PORT:-8080}/?ahr_phase9=$marker"

event_id=''
for _ in $(seq 1 150); do
    event_id="$(ahr_ai_compose exec -T postgres sh -ec '
        PGPASSWORD="$AHR_DB_PASSWORD" exec psql --host=127.0.0.1 \
          --username="$AHR_DB_USER" --dbname="$POSTGRES_DB" \
          --tuples-only --no-align --set=ON_ERROR_STOP=1 \
          --command="SELECT e.event_id
                    FROM ahr.events e
                    JOIN ahr.ai_predictions p ON p.event_id = e.event_id
                    WHERE e.raw_event::text LIKE '\''%'$marker'%'\'' 
                      AND p.model_id = '\''fusion-hybrid-xgboost'\''
                      AND e.ai ? '\''fusion_breakdown'\''
                      AND e.ai->>'\''fusion_score'\'' IS NOT NULL
                      AND e.ai->>'\''risk_level'\'' IN ('\''low'\'','\''medium'\'','\''high'\'','\''critical'\'')
                      AND (
                        e.ai->'\''fusion_breakdown'\''->'\''components'\''->>'\''network_score'\'' IS NOT NULL
                        OR e.ai->'\''fusion_breakdown'\''->'\''components'\''->>'\''log_score'\'' IS NOT NULL
                        OR e.ai->'\''fusion_breakdown'\''->'\''components'\''->>'\''graph_score'\'' IS NOT NULL
                      )
                    LIMIT 1;"
    ' | tr -d '\r[:space:]')"
    [[ -n "$event_id" ]] && break
    sleep 2
done
[[ -n "$event_id" ]] || fail 'Realtime fusion did not create a scored risk breakdown for the new marker event'
pass 'Fusion receives real AI scores, creates final score, and assigns a risk level'

ahr_ai_compose exec -T backend python - "$event_id" <<'PY'
import asyncio
import sys
import httpx

event_id = sys.argv[1]

async def main():
    async with httpx.AsyncClient(timeout=10.0) as client:
        data = (await client.get(f"http://127.0.0.1:8000/api/events/{event_id}")).json()
    ai = data.get("ai") or {}
    required = [
        "rule_score",
        "network_score",
        "log_score",
        "graph_score",
        "context_score",
        "fusion_score",
        "risk_level",
        "fusion_breakdown",
    ]
    missing = [key for key in required if key not in ai]
    if missing:
        raise SystemExit(f"missing dashboard API keys: {missing}")
    if ai.get("fusion_score") is None or not ai.get("risk_level"):
        raise SystemExit("missing fusion score/risk level")
    breakdown = ai.get("fusion_breakdown") or {}
    components = breakdown.get("components") or {}
    if not any(components.get(key) is not None for key in ("network_score", "log_score", "graph_score")):
        raise SystemExit("fusion breakdown did not include real AI component scores")
asyncio.run(main())
PY
pass 'Dashboard API exposes rule/network/log/graph/context/fusion score breakdown'

dashboard_html="$(curl --noproxy '*' -fsS "http://127.0.0.1:${NGINX_PORT:-8080}/dashboard/")"
dashboard_asset="$(sed -n 's/.*src="\([^"]*\.js\)".*/\1/p' <<<"$dashboard_html" | head -n 1)"
[[ "$dashboard_asset" == /dashboard/assets/*.js ]] || fail 'Dashboard HTML does not reference a built JavaScript asset'
dashboard_bundle="$(curl --noproxy '*' -fsS "http://127.0.0.1:${NGINX_PORT:-8080}${dashboard_asset}")"
grep -Fq 'Fusion score' <<<"$dashboard_bundle" || fail 'Dashboard bundle does not render fusion score'
pass 'Dashboard displays the Phase 9 fusion score breakdown'

pass 'Phase 9 runtime acceptance PASS: hybrid fusion, missing-score handling, meta-classifier, risk levels, realtime service, and dashboard breakdown verified'
