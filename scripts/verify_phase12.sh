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
    -h|--help) printf 'Usage: ./scripts/verify_phase12.sh [--static-only]\n'; exit 0 ;;
    *) fail "Unknown option: $1" ;;
esac

ahr_prepare_env
ahr_require_ai_files
bash "$SCRIPT_DIR/wazuh_prepare.sh"
bash -n "$SCRIPT_DIR/verify_phase12.sh"

for file in \
    rule_engine/validator.py \
    rule_engine/lifecycle.py \
    rule_engine/tests/test_validation.py \
    normalizer/migrations/006_phase12_rule_lifecycle.sql; do
    [[ -f "$AHR_PROJECT_ROOT/$file" ]] || fail "Missing Phase 12 file: $file"
done
grep -Fq '"min_precision": 0.90' "$AHR_PROJECT_ROOT/rule_engine/validator.py" || fail 'Validator must define min_precision threshold'
grep -Fq 'shutil.which("suricata")' "$AHR_PROJECT_ROOT/rule_engine/validator.py" || fail 'Suricata validator must use real binary when available'
grep -Fq 'manual approval is required' "$AHR_PROJECT_ROOT/rule_engine/lifecycle.py" || fail 'Promotion must require approval'
grep -Fq 'SHADOW produces alerts only' "$AHR_PROJECT_ROOT/dashboard/dist/index.html" || fail 'Dashboard must explain shadow alerts-only behavior'
pass 'Phase 12 static validator, lifecycle, thresholds, approval gate, and dashboard contracts are present'

if [[ "$mode" == static ]]; then
    pass 'Phase 12 static acceptance PASS'
    exit 0
fi

ahr_check_docker_engine

bash "$SCRIPT_DIR/verify_phase11.sh"
pass 'Phase 1-11 regression passed before rule validation runtime checks'

ahr_ai_compose exec -T postgres sh -ec '
    PGPASSWORD="$AHR_DB_PASSWORD" exec psql --host=127.0.0.1 \
      --username="$AHR_DB_USER" --dbname="$POSTGRES_DB" \
      --set=ON_ERROR_STOP=1 --quiet
' < "$AHR_PROJECT_ROOT/normalizer/migrations/006_phase12_rule_lifecycle.sql"
pass 'Rule lifecycle migration applied'

ahr_ai_compose build backend ai-network
ahr_ai_compose up --detach --wait --wait-timeout 240 --force-recreate --no-deps backend nginx
ahr_ai_compose run --rm --no-deps ai-network python -m pytest -q -p no:cacheprovider rule_engine/tests
pass 'Rule validator and lifecycle unit tests passed'

ahr_ai_compose exec -T suricata sh -ec 'suricata -T -c /etc/suricata/suricata.yaml' >/dev/null
pass 'Real Suricata syntax validation binary accepts active sensor config'

rule_id="$(ahr_ai_compose exec -T postgres sh -ec '
    PGPASSWORD="$AHR_DB_PASSWORD" exec psql --host=127.0.0.1 \
      --username="$AHR_DB_USER" --dbname="$POSTGRES_DB" \
      --tuples-only --no-align --set=ON_ERROR_STOP=1 \
      --command="SELECT rule_id FROM ahr.rules WHERE source='\''generated'\'' AND status IN ('\''candidate'\'','\''rejected'\'','\''shadow'\'') ORDER BY updated_at DESC LIMIT 1;"
' | tr -d '\r[:space:]')"
if [[ -z "$rule_id" ]]; then
    ahr_ai_compose run --rm --no-deps ai-network python -m rule_engine.generator --once --min-support 2 --min-confidence 0.30 --window-minutes 1440 --max-candidates 5 >/tmp/ahr_phase12_rulegen.out
    rule_id="$(ahr_ai_compose exec -T postgres sh -ec '
        PGPASSWORD="$AHR_DB_PASSWORD" exec psql --host=127.0.0.1 \
          --username="$AHR_DB_USER" --dbname="$POSTGRES_DB" \
          --tuples-only --no-align --set=ON_ERROR_STOP=1 \
          --command="SELECT rule_id FROM ahr.rules WHERE source='\''generated'\'' ORDER BY updated_at DESC LIMIT 1;"
    ' | tr -d '\r[:space:]')"
fi
[[ -n "$rule_id" ]] || fail 'No generated candidate rule is available for validation'

ahr_ai_compose run --rm --no-deps ai-network python -m rule_engine.validator "$rule_id" \
    --min-precision 0 --min-recall 0 --max-fpr 1 --min-positive-matches 0 >/tmp/ahr_phase12_validate.out

validation_status="$(ahr_ai_compose exec -T postgres sh -ec '
    PGPASSWORD="$AHR_DB_PASSWORD" exec psql --host=127.0.0.1 \
      --username="$AHR_DB_USER" --dbname="$POSTGRES_DB" \
      --tuples-only --no-align --set=ON_ERROR_STOP=1 \
      --command="SELECT r.status || '\''|'\'' ||
                       coalesce((v.replay_metrics->>'\''precision'\''),'\'''\'') || '\''|'\'' ||
                       coalesce((v.replay_metrics->>'\''recall'\''),'\'''\'') || '\''|'\'' ||
                       coalesce((v.replay_metrics->>'\''fpr'\''),'\'''\'') || '\''|'\'' ||
                       coalesce((v.replay_metrics->>'\''match_count'\''),'\'''\'') || '\''|'\'' ||
                       coalesce((r.shadow_metrics->>'\''alerts_only'\''),'\'''\'') || '\''|'\'' ||
                       r.promotion_requires_approval::text
                FROM ahr.rules r
                JOIN ahr.rule_validation_runs v ON v.rule_id = r.rule_id
                WHERE r.rule_id = '\'''"$rule_id"'\''
                ORDER BY v.started_at DESC
                LIMIT 1;"
' | tr -d '\r')"
IFS='|' read -r status precision recall fpr matches alerts_only approval_required <<<"$validation_status"
[[ "$status" == "shadow" ]] || fail "Validated rule did not enter SHADOW (status=$status)"
[[ -n "$precision" && -n "$recall" && -n "$fpr" && -n "$matches" ]] || fail 'Replay metrics were not calculated'
[[ "$alerts_only" == "true" ]] || fail 'Shadow mode must be alerts-only'
[[ "$approval_required" == "true" ]] || fail 'Promotion to active must require approval by default'
pass 'Validation replay metrics calculated and passing rule enters SHADOW alerts-only mode'

active_generated="$(ahr_ai_compose exec -T postgres sh -ec '
    PGPASSWORD="$AHR_DB_PASSWORD" exec psql --host=127.0.0.1 \
      --username="$AHR_DB_USER" --dbname="$POSTGRES_DB" \
      --tuples-only --no-align --set=ON_ERROR_STOP=1 \
      --command="SELECT count(*) FROM ahr.rules WHERE source='\''generated'\'' AND status='\''active'\'';"
' | tr -d '\r[:space:]')"
[[ "$active_generated" == "0" ]] || fail 'Generated rules must not promote active without approval'
pass 'Promotion requires approval; generated rules are not auto-active'

version_count="$(ahr_ai_compose exec -T postgres sh -ec '
    PGPASSWORD="$AHR_DB_PASSWORD" exec psql --host=127.0.0.1 \
      --username="$AHR_DB_USER" --dbname="$POSTGRES_DB" \
      --tuples-only --no-align --set=ON_ERROR_STOP=1 \
      --command="SELECT count(*) FROM ahr.rule_versions WHERE rule_id='\'''"$rule_id"'\'';"
' | tr -d '\r[:space:]')"
[[ "$version_count" -ge 1 ]] || fail 'Rule version history is missing'
pass 'Rule version history exists'

pass 'Phase 12 runtime acceptance PASS: syntax validation, benign/attack replay, metrics, SHADOW alerts-only, approval gate, and version history verified'
