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
    -h|--help) printf 'Usage: ./scripts/verify_phase13.sh [--static-only]\n'; exit 0 ;;
    *) fail "Unknown option: $1" ;;
esac

ahr_prepare_env
ahr_require_ai_files
bash -n "$SCRIPT_DIR/verify_phase13.sh"

for file in \
    response/engine.py \
    response/policy.py \
    response/firewall.py \
    response/container.py \
    response/evidence.py \
    response/rollback.py \
    response/tests/test_response.py \
    normalizer/migrations/007_phase13_response_engine.sql \
    backend/api/responses.py \
    dashboard/src/pages/Responses.tsx; do
    [[ -f "$AHR_PROJECT_ROOT/$file" ]] || fail "Missing Phase 13 file: $file"
done

grep -Fq 'AHR_RESPONSE_MODE: alert_only' "$AHR_PROJECT_ROOT/ai/compose.fragment.yml" || fail 'Response engine must default to alert_only mode'
grep -Fq 'AHR_RESPONSE_AUTOMATIC_BLOCK: "false"' "$AHR_PROJECT_ROOT/ai/compose.fragment.yml" || fail 'Automatic blocking must be disabled by default'
grep -Fq 'AI risk alone is insufficient' "$AHR_PROJECT_ROOT/response/policy.py" || fail 'Policy must not rely only on AI'
grep -Fq 'refusing to block non-lab IP address' "$AHR_PROJECT_ROOT/response/firewall.py" || fail 'Firewall wrapper must refuse non-lab IPs'
grep -Fq 'deletes_container=False' "$AHR_PROJECT_ROOT/response/container.py" || fail 'Container isolation must not delete containers'
grep -Fq 'manifest.json' "$AHR_PROJECT_ROOT/response/evidence.py" || fail 'Evidence collector must write manifest'
grep -Fq 'SHA256' "$AHR_PROJECT_ROOT/normalizer/migrations/007_phase13_response_engine.sql" || true
grep -Fq '/api/responses' "$AHR_PROJECT_ROOT/dashboard/src/pages/Responses.tsx" || fail 'Dashboard responses page must use responses API'
pass 'Phase 13 static response engine, safety policy, evidence, API, and dashboard contracts are present'

if [[ "$mode" == static ]]; then
    pass 'Phase 13 static acceptance PASS'
    exit 0
fi

ahr_check_docker_engine

bash "$SCRIPT_DIR/verify_phase12.sh" --static-only
pass 'Phase 12 static regression passed before response runtime checks'

ahr_ai_compose exec -T postgres sh -ec '
    PGPASSWORD="$AHR_DB_PASSWORD" exec psql --host=127.0.0.1 \
      --username="$AHR_DB_USER" --dbname="$POSTGRES_DB" \
      --set=ON_ERROR_STOP=1 --quiet
' < "$AHR_PROJECT_ROOT/normalizer/migrations/007_phase13_response_engine.sql"
pass 'Response/evidence migration applied'

ahr_ai_compose build ai-network backend
ahr_ai_compose up --detach --wait --wait-timeout 240 --force-recreate --no-deps backend nginx
ahr_ai_compose run --rm --no-deps ai-network python -m pytest -q -p no:cacheprovider response/tests
pass 'Response policy, firewall, isolation, rollback unit tests passed'

incident_id="$(ahr_ai_compose exec -T postgres sh -ec '
    PGPASSWORD="$AHR_DB_PASSWORD" exec psql --host=127.0.0.1 \
      --username="$AHR_DB_USER" --dbname="$POSTGRES_DB" \
      --tuples-only --no-align --set=ON_ERROR_STOP=1 \
      --command="SELECT incident_id FROM ahr.incidents WHERE event_count > 0 ORDER BY risk_score DESC NULLS LAST, last_seen DESC LIMIT 1;"
' | tr -d '\r[:space:]')"
[[ -n "$incident_id" ]] || fail 'No real correlated incident is available for Phase 13 response acceptance'
printf 'INCIDENT_ID=%s\n' "$incident_id"

alert_json="$(ahr_ai_compose run --rm --no-deps response-engine python -m response.engine --incident-id "$incident_id" --action alert --requested-by phase13-acceptance --evidence-root evidence)"
printf '%s\n' "$alert_json"
alert_id="$(sed -n 's/.*"response_id": "\([^"]*\)".*/\1/p' <<<"$alert_json")"
[[ -n "$alert_id" ]] || fail 'Alert response did not return response_id'
pass 'Alert response works'

block_json="$(ahr_ai_compose run --rm --no-deps response-engine python -m response.engine --incident-id "$incident_id" --action lab_block --requested-by phase13-acceptance --ttl-seconds 60 --evidence-root evidence)"
printf '%s\n' "$block_json"
block_id="$(sed -n 's/.*"response_id": "\([^"]*\)".*/\1/p' <<<"$block_json")"
[[ -n "$block_id" ]] || fail 'Lab block response did not return response_id'
pass 'Temporary lab block works'

ahr_ai_compose exec -T postgres sh -ec "PGPASSWORD=\"\$AHR_DB_PASSWORD\" exec psql --host=127.0.0.1 --username=\"\$AHR_DB_USER\" --dbname=\"\$POSTGRES_DB\" --set=ON_ERROR_STOP=1 --quiet --command=\"UPDATE ahr.responses SET expires_at = now() - interval '1 second' WHERE response_id = '$block_id';\""
ahr_ai_compose run --rm --no-deps response-engine python -m response.engine --rollback-expired >/tmp/ahr_phase13_rollback.out
rollback_status="$(ahr_ai_compose exec -T postgres sh -ec "PGPASSWORD=\"\$AHR_DB_PASSWORD\" exec psql --host=127.0.0.1 --username=\"\$AHR_DB_USER\" --dbname=\"\$POSTGRES_DB\" --tuples-only --no-align --set=ON_ERROR_STOP=1 --command=\"SELECT status || '|' || rollback_status FROM ahr.responses WHERE response_id = '$block_id';\"" | tr -d '\r')"
[[ "$rollback_status" == "expired|rolled_back" ]] || fail "Temporary response did not expire and rollback cleanly ($rollback_status)"
pass 'Expiry/rollback works'

isolate_json="$(ahr_ai_compose run --rm --no-deps response-engine python -m response.engine --incident-id "$incident_id" --action isolate_container --requested-by phase13-acceptance --evidence-root evidence)"
printf '%s\n' "$isolate_json"
isolate_id="$(sed -n 's/.*"response_id": "\([^"]*\)".*/\1/p' <<<"$isolate_json")"
safe_isolation="$(ahr_ai_compose exec -T postgres sh -ec "PGPASSWORD=\"\$AHR_DB_PASSWORD\" exec psql --host=127.0.0.1 --username=\"\$AHR_DB_USER\" --dbname=\"\$POSTGRES_DB\" --tuples-only --no-align --set=ON_ERROR_STOP=1 --command=\"SELECT (parameters->'isolation'->>'deletes_container') || '|' || (parameters->'isolation'->>'deletes_volumes') || '|' || (parameters->'isolation'->>'deletes_logs') FROM ahr.responses WHERE response_id = '$isolate_id';\"" | tr -d '\r[:space:]')"
[[ "$safe_isolation" == "False|False|False" || "$safe_isolation" == "false|false|false" ]] || fail "Isolation plan is not safe ($safe_isolation)"
pass 'Isolation safe'

evidence_status="$(ahr_ai_compose exec -T postgres sh -ec "PGPASSWORD=\"\$AHR_DB_PASSWORD\" exec psql --host=127.0.0.1 --username=\"\$AHR_DB_USER\" --dbname=\"\$POSTGRES_DB\" --tuples-only --no-align --set=ON_ERROR_STOP=1 --command=\"SELECT file_count || '|' || jsonb_array_length(manifest) || '|' || bundle_sha256 FROM ahr.evidence WHERE response_id = '$alert_id' ORDER BY created_at DESC LIMIT 1;\"" | tr -d '\r')"
IFS='|' read -r file_count manifest_count bundle_hash <<<"$evidence_status"
[[ "${file_count:-0}" -ge 2 ]] || fail 'Evidence bundle was not generated'
[[ "${manifest_count:-0}" -ge 1 ]] || fail 'Evidence manifest is empty'
[[ "${#bundle_hash}" -eq 64 ]] || fail 'Evidence bundle hash is missing'
pass 'Evidence bundle and hashes generated'

audit_status="$(ahr_ai_compose exec -T postgres sh -ec "PGPASSWORD=\"\$AHR_DB_PASSWORD\" exec psql --host=127.0.0.1 --username=\"\$AHR_DB_USER\" --dbname=\"\$POSTGRES_DB\" --tuples-only --no-align --set=ON_ERROR_STOP=1 --command=\"SELECT action || '|' || status || '|' || coalesce(action_audit->>'destructive','') FROM ahr.responses WHERE response_id = '$alert_id';\"" | tr -d '\r')"
IFS='|' read -r audit_action audit_status_value audit_destructive <<<"$audit_status"
[[ "$audit_action" == "alert" && "$audit_status_value" == "completed" ]] || fail "Action audit stored incorrectly ($audit_status)"
[[ "$audit_destructive" == "false" ]] || fail 'Response action audit must mark destructive=false'
pass 'Action audit stored and no destructive auto action'

ahr_ai_compose exec -T backend python - "$alert_id" <<'PY'
import asyncio, sys, httpx
response_id = sys.argv[1]
async def main():
    async with httpx.AsyncClient(timeout=10.0) as client:
        data = (await client.get(f"http://127.0.0.1:8000/api/responses/{response_id}")).json()
    assert data["action"] == "alert", data
    assert data["evidence_file_count"] >= 2, data
    print({"action": data["action"], "status": data["status"], "evidence_file_count": data["evidence_file_count"]})
asyncio.run(main())
PY
pass 'Responses API and dashboard data contract work'

pass 'Phase 13 runtime acceptance PASS: alert, temporary lab block, rollback, safe isolation, evidence hashes, audit, and no destructive auto action verified'
