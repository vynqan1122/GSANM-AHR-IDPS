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
    -h|--help) printf 'Usage: ./scripts/verify_phase11.sh [--static-only]\n'; exit 0 ;;
    *) fail "Unknown option: $1" ;;
esac

ahr_prepare_env
ahr_require_ai_files
bash "$SCRIPT_DIR/wazuh_prepare.sh"
bash -n "$SCRIPT_DIR/verify_phase11.sh"

effective="$(ahr_ai_compose config)"
ahr_ai_compose config --quiet
services="$(ahr_ai_compose config --services)"
grep -qx rule-generator <<<"$services" || fail 'Effective Phase 11 Compose model is missing rule-generator'
rulegen_section="$(ahr_compose_service_section rule-generator <<<"$effective")"
grep -Eq '^[[:space:]]+read_only: true$' <<<"$rulegen_section" || fail 'rule-generator root filesystem must be read-only'
grep -Eq '^[[:space:]]+- ALL$' <<<"$rulegen_section" || fail 'rule-generator must drop all capabilities'
! grep -Eq '^[[:space:]]+(ports|network_mode):' <<<"$rulegen_section" || fail 'rule-generator must not publish ports or use host/shared namespace'
grep -Eq '^[[:space:]]+data:[[:space:]]*null$' <<<"$rulegen_section" || fail 'rule-generator must join only the data network'

for file in \
    rule_engine/pattern_miner.py \
    rule_engine/clustering.py \
    rule_engine/abstraction.py \
    rule_engine/explainer.py \
    rule_engine/generator.py \
    rule_engine/engine_selector.py \
    rule_engine/templates/suricata.py \
    rule_engine/templates/falco.py \
    rule_engine/templates/wazuh.py \
    rule_engine/tests/test_rule_generation.py \
    normalizer/migrations/005_phase11_generated_rules.sql \
    backend/api/rules.py; do
    [[ -f "$AHR_PROJECT_ROOT/$file" ]] || fail "Missing Phase 11 file: $file"
done
grep -Fq 'status = '\''candidate'\''' "$AHR_PROJECT_ROOT/rule_engine/generator.py" || fail 'Generated rules must be stored as candidate'
grep -Fq 'contains_sample_specific_artifact' "$AHR_PROJECT_ROOT/rule_engine/generator.py" || fail 'Generator must reject sample-specific hard-coded artifacts'
grep -R -Fq --include='*.js' 'Generated rules' "$AHR_PROJECT_ROOT/dashboard/dist/assets" || fail 'Dashboard must display generated rules'
pass 'Phase 11 static rule mining, templates, storage, service, API, and dashboard contracts are present'

if [[ "$mode" == static ]]; then
    pass 'Phase 11 static acceptance PASS'
    exit 0
fi

ahr_check_docker_engine

bash "$SCRIPT_DIR/verify_phase10.sh"
pass 'Phase 1-10 regression passed before automatic rule generation runtime checks'

ahr_ai_compose exec -T postgres sh -ec '
    PGPASSWORD="$AHR_DB_PASSWORD" exec psql --host=127.0.0.1 \
      --username="$AHR_DB_USER" --dbname="$POSTGRES_DB" \
      --set=ON_ERROR_STOP=1 --quiet
' < "$AHR_PROJECT_ROOT/normalizer/migrations/005_phase11_generated_rules.sql"
pass 'Generated-rule metadata migration applied'

ahr_ai_compose build backend ai-network
ahr_ai_compose up --detach --wait --wait-timeout 240 --force-recreate --no-deps backend nginx
pass 'Backend and dashboard rebuilt with generated-rule API/page'

ahr_ai_compose run --rm --no-deps ai-network python -m pytest -q -p no:cacheprovider rule_engine/tests
pass 'Rule generator tests passed: clustering, abstraction, engine selection, no hard-coded samples'

ahr_ai_compose run --rm --no-deps ai-network python -m rule_engine.generator --once --min-support 2 --min-confidence 0.30 --window-minutes 1440 --max-candidates 5 >/tmp/ahr_phase11_rulegen.out
rule_id="$(ahr_ai_compose exec -T postgres sh -ec '
    PGPASSWORD="$AHR_DB_PASSWORD" exec psql --host=127.0.0.1 \
      --username="$AHR_DB_USER" --dbname="$POSTGRES_DB" \
      --tuples-only --no-align --set=ON_ERROR_STOP=1 \
      --command="SELECT r.rule_id
                FROM ahr.rules r
                JOIN ahr.rule_versions rv ON rv.rule_id = r.rule_id AND rv.version = r.current_version
                WHERE r.source = '\''generated'\''
                  AND r.status = '\''candidate'\''
                  AND r.support >= 2
                  AND r.confidence >= 0.30
                  AND r.engine IN ('\''suricata'\'','\''falco'\'','\''wazuh'\'')
                  AND rv.content NOT LIKE '\''%127.0.0.1%'\''
                  AND rv.content NOT LIKE '\''%10.0.0.%'\''
                ORDER BY r.updated_at DESC
                LIMIT 1;"
' | tr -d '\r[:space:]')"
[[ -n "$rule_id" ]] || fail 'Rule generator did not store a safe generated candidate rule'
pass 'Repeated anomaly clustered, pattern extracted, engine selected, and candidate stored'

active_count="$(ahr_ai_compose exec -T postgres sh -ec '
    PGPASSWORD="$AHR_DB_PASSWORD" exec psql --host=127.0.0.1 \
      --username="$AHR_DB_USER" --dbname="$POSTGRES_DB" \
      --tuples-only --no-align --set=ON_ERROR_STOP=1 \
      --command="SELECT count(*) FROM ahr.rules WHERE source='\''generated'\'' AND status <> '\''candidate'\'';"
' | tr -d '\r[:space:]')"
[[ "$active_count" == "0" ]] || fail 'Generated rules must not auto-activate'
pass 'Generated rules remain candidate-only'

ahr_ai_compose up --detach --wait --wait-timeout 240 --force-recreate --no-deps rule-generator
rulegen_id="$(ahr_ai_compose ps -q rule-generator)"
[[ -n "$rulegen_id" ]] || fail 'rule-generator is not running'
[[ "$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$rulegen_id")" == healthy ]] || \
    fail 'rule-generator did not become healthy'
pass 'rule-generator service is healthy and hardened'

ahr_ai_compose exec -T backend python - "$rule_id" <<'PY'
import asyncio
import sys
import httpx

rule_id = sys.argv[1]

async def main():
    async with httpx.AsyncClient(timeout=10.0) as client:
        data = (await client.get(f"http://127.0.0.1:8000/api/rules/{rule_id}")).json()
    for key in ("rule_id", "engine", "status", "source", "support", "confidence", "pattern", "content"):
        if key not in data:
            raise SystemExit(f"missing rule detail key: {key}")
    if data["status"] != "candidate" or data["source"] != "generated":
        raise SystemExit("generated rule is not candidate-only")
asyncio.run(main())
PY
pass 'Generated-rule API exposes candidate content and metadata'

dashboard_html="$(curl.exe --noproxy "*" -fsS "http://127.0.0.1:${NGINX_PORT:-8080}/dashboard/")"
dashboard_asset="$(sed -n 's/.*src="\([^"]*\.js\)".*/\1/p' <<<"$dashboard_html" | head -n 1)"
[[ "$dashboard_asset" == /dashboard/assets/*.js ]] || fail 'Dashboard HTML does not reference a built JavaScript asset'
dashboard_bundle="$(curl.exe --noproxy "*" -fsS "http://127.0.0.1:${NGINX_PORT:-8080}${dashboard_asset}")"
grep -Fq 'Generated rules' <<<"$dashboard_bundle" || fail 'Dashboard bundle does not expose generated rules'
pass 'Dashboard displays generated candidate rules'

pass 'Phase 11 runtime acceptance PASS: repeated anomaly clustering, pattern extraction, candidate generation/storage, engine selection, and no auto activation verified'
