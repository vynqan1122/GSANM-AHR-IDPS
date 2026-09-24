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
    -h|--help) printf 'Usage: ./scripts/verify_phase14.sh [--static-only]\n'; exit 0 ;;
    *) fail "Unknown option: $1" ;;
esac

ahr_prepare_env
ahr_require_ai_files
bash -n "$SCRIPT_DIR/verify_phase14.sh"

for file in \
    normalizer/migrations/008_phase14_research_evaluation.sql \
    backend/api/experiments.py \
    backend/api/models.py \
    backend/api/network.py \
    dashboard/src/pages/ResearchPages.tsx \
    scripts/demo.sh \
    scripts/run_ablation.sh \
    scripts/health_check.sh \
    scripts/train_all.sh; do
    [[ -f "$AHR_PROJECT_ROOT/$file" ]] || fail "Missing Phase 14 file: $file"
done

for label in Giám sát Điều tra Quản trị LiveEvents Incidents Rules AIMonitorPage SensorHealth WazuhManagerPage Responses; do
    grep -Fq "$label" "$AHR_PROJECT_ROOT/dashboard/src/layouts/AppLayout.tsx" || fail "Dashboard operating view missing $label"
done
grep -Fq 'E9_full_hybrid_generated_rules' "$AHR_PROJECT_ROOT/backend/api/experiments.py" || fail 'Ablation E1-E9 must include generated rules experiment'
grep -Fq 'unknown_attack_recall_before' "$AHR_PROJECT_ROOT/backend/api/experiments.py" || fail 'Unknown attack before/after metrics missing'
grep -Fq 'results.csv' "$AHR_PROJECT_ROOT/backend/api/experiments.py" || fail 'Experiment runner must export results.csv'
grep -Fq 'GET /api/system/health' "$AHR_PROJECT_ROOT/README.md" 2>/dev/null || true
grep -Fq 'make demo' "$AHR_PROJECT_ROOT/Makefile" || fail 'Makefile must expose demo target'
grep -Fq 'make integration-test' "$AHR_PROJECT_ROOT/Makefile" || fail 'Makefile must expose integration-test target'
pass 'Phase 14 static dashboard, APIs, experiments, scripts, and Makefile contracts are present'

if [[ "$mode" == static ]]; then
    pass 'Phase 14 static acceptance PASS'
    exit 0
fi

ahr_check_docker_engine

bash "$SCRIPT_DIR/verify_phase13.sh" --static-only
pass 'Phase 13 static regression passed before final research runtime checks'

ahr_ai_compose exec -T postgres sh -ec '
    PGPASSWORD="$AHR_DB_PASSWORD" exec psql --host=127.0.0.1 \
      --username="$AHR_DB_USER" --dbname="$POSTGRES_DB" \
      --set=ON_ERROR_STOP=1 --quiet
' < "$AHR_PROJECT_ROOT/normalizer/migrations/008_phase14_research_evaluation.sql"
pass 'Research evaluation migration applied'

ahr_ai_compose build backend ai-network
ahr_ai_compose up --detach --wait --wait-timeout 240 --force-recreate --no-deps backend nginx

ahr_ai_compose exec -T backend python - <<'PY'
import asyncio, json, httpx

async def main():
    async with httpx.AsyncClient(timeout=120.0) as client:
        for path in (
            "/api/health",
            "/api/events",
            "/api/alerts",
            "/api/incidents",
            "/api/network/summary",
            "/api/containers",
            "/api/models",
            "/api/rules",
            "/api/responses",
            "/api/dashboard/overview",
            "/api/dashboard/timeseries",
            "/api/system/health",
        ):
            response = await client.get(f"http://127.0.0.1:8000{path}")
            assert response.status_code == 200, (path, response.status_code, response.text[:200])
        run = (await client.post("http://127.0.0.1:8000/api/experiments/run")).json()
        assert run["status"] == "completed", run
        assert len(run["rows"]) >= 9, run
        assert run["results_path"].endswith("results.csv"), run
        health = (await client.get("http://127.0.0.1:8000/api/system/health")).json()
        for key in ("dvwa","nginx","mariadb","postgres","redis","suricata","falco","wazuh","collector","normalizer","network_ai","log_ai","graph_ai","fusion","correlation","rule_engine","response_engine","backend","dashboard"):
            assert key in health["services"], (key, health)
        print(json.dumps({"experiments": len(run["rows"]), "results_path": run["results_path"], "overall": health["overall"]}, sort_keys=True))

asyncio.run(main())
PY
pass 'Final backend API, experiment runner, system health, and dashboard data contracts work'

[[ -s "$AHR_PROJECT_ROOT/experiments/results/results.csv" ]] || fail 'experiments/results/results.csv was not exported'
header="$(head -n 1 "$AHR_PROJECT_ROOT/experiments/results/results.csv" | tr -d '\r')"
[[ "$header" == "experiment_id,model_config,dataset_split,precision,recall,f1,fpr,roc_auc,pr_auc,detection_latency_ms,inference_latency_ms,throughput_eps,cpu_percent,ram_mb,gpu_mb" ]] || fail "Unexpected results.csv schema: $header"
pass 'Research results CSV exported with required schema'

pass 'Phase 14 runtime acceptance PASS: final dashboard APIs, ablation/results export, system health, scripts, and regressions verified'
