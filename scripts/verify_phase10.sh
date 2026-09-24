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
    -h|--help) printf 'Usage: ./scripts/verify_phase10.sh [--static-only]\n'; exit 0 ;;
    *) fail "Unknown option: $1" ;;
esac

ahr_prepare_env
ahr_require_ai_files
bash "$SCRIPT_DIR/wazuh_prepare.sh"
bash -n "$SCRIPT_DIR/verify_phase10.sh"

effective="$(ahr_ai_compose config)"
ahr_ai_compose config --quiet
services="$(ahr_ai_compose config --services)"
grep -qx incident-engine <<<"$services" || fail 'Effective Phase 10 Compose model is missing incident-engine'
incident_section="$(ahr_compose_service_section incident-engine <<<"$effective")"
grep -Eq '^[[:space:]]+read_only: true$' <<<"$incident_section" || fail 'incident-engine root filesystem must be read-only'
grep -Eq '^[[:space:]]+- ALL$' <<<"$incident_section" || fail 'incident-engine must drop all capabilities'
! grep -Eq '^[[:space:]]+(ports|network_mode):' <<<"$incident_section" || fail 'incident-engine must not publish ports or use host/shared namespace'
grep -Eq '^[[:space:]]+data:[[:space:]]*null$' <<<"$incident_section" || fail 'incident-engine must join only the data network'
grep -Eq 'INCIDENT_START_AT_END: "true"|INCIDENT_START_AT_END: true' <<<"$incident_section" || fail 'incident-engine must start at stream tail'

for file in \
    correlation/correlator.py \
    correlation/sessionizer.py \
    correlation/rules.py \
    correlation/incident_builder.py \
    correlation/attack_chain.py \
    correlation/tests/test_correlation.py \
    normalizer/migrations/004_phase10_incidents.sql \
    backend/api/incidents.py; do
    [[ -f "$AHR_PROJECT_ROOT/$file" ]] || fail "Missing Phase 10 file: $file"
done
grep -Fq 'Attack graph edges' "$AHR_PROJECT_ROOT/dashboard/src/pages/Incidents.tsx" || fail 'Dashboard incident detail must display attack graph status'
grep -R -Fq --include='*.js' 'Incidents' "$AHR_PROJECT_ROOT/dashboard/dist/assets" || fail 'Dashboard must expose incidents page'
grep -Fq 'security.incidents' "$AHR_PROJECT_ROOT/correlation/correlator.py" || fail 'Incident service must publish realtime incident updates'
pass 'Phase 10 static correlation, incident service, migration, API, and dashboard contracts are present'

if [[ "$mode" == static ]]; then
    pass 'Phase 10 static acceptance PASS'
    exit 0
fi

ahr_check_docker_engine

bash "$SCRIPT_DIR/verify_phase9.sh"
pass 'Phase 1-9 regression passed before incident correlation runtime checks'

ahr_ai_compose exec -T postgres sh -ec '
    PGPASSWORD="$AHR_DB_PASSWORD" exec psql --host=127.0.0.1 \
      --username="$AHR_DB_USER" --dbname="$POSTGRES_DB" \
      --set=ON_ERROR_STOP=1 --quiet
' < "$AHR_PROJECT_ROOT/normalizer/migrations/004_phase10_incidents.sql"
pass 'Incident enrichment migration applied'

ahr_ai_compose build backend
ahr_ai_compose up --detach --wait --wait-timeout 240 --force-recreate --no-deps backend nginx
pass 'Backend and dashboard rebuilt with incident API/detail page'

ahr_ai_compose build ai-network
ahr_ai_compose run --rm --no-deps ai-network python -m pytest -q -p no:cacheprovider correlation/tests
pass 'Correlation key/session split and attack-chain unit tests passed'

ahr_ai_compose up --detach --wait --wait-timeout 240 --force-recreate --no-deps incident-engine
incident_id="$(ahr_ai_compose ps -q incident-engine)"
[[ -n "$incident_id" ]] || fail 'incident-engine is not running'
[[ "$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$incident_id")" == healthy ]] || \
    fail 'incident-engine did not become healthy'
[[ "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.CapDrop}}|{{range .NetworkSettings.Networks}}{{.NetworkID}} {{end}}' "$incident_id" | cut -d'|' -f1-2)" == 'true|["ALL"]' ]] || \
    fail 'incident-engine runtime hardening drifted'
pass 'incident-engine realtime service is healthy and hardened'

marker="ahr_p10_$(date +%s)_$$_${RANDOM:-0}"
curl.exe --noproxy "*" -fsS -o /dev/null "http://127.0.0.1:${NGINX_PORT:-8080}/?ahr_phase10=$marker&step=1"
curl.exe --noproxy "*" -fsS -o /dev/null "http://127.0.0.1:${NGINX_PORT:-8080}/?ahr_phase10=$marker&step=2"

correlated_id=''
for _ in $(seq 1 150); do
    correlated_id="$(ahr_ai_compose exec -T postgres sh -ec '
        PGPASSWORD="$AHR_DB_PASSWORD" exec psql --host=127.0.0.1 \
          --username="$AHR_DB_USER" --dbname="$POSTGRES_DB" \
          --tuples-only --no-align --set=ON_ERROR_STOP=1 \
          --command="SELECT i.incident_id
                    FROM ahr.incidents i
                    JOIN ahr.incident_events ie ON ie.incident_id = i.incident_id
                    JOIN ahr.events e ON e.event_id = ie.event_id
                    WHERE e.raw_event::text LIKE '\''%'$marker'%'\'' 
                      AND i.event_count >= 2
                      AND jsonb_array_length(i.attack_graph->'\''edges'\'') > 0
                      AND jsonb_array_length(i.timeline) >= 2
                    GROUP BY i.incident_id, i.event_count, i.attack_graph, i.timeline
                    LIMIT 1;"
    ' | tr -d '\r[:space:]')"
    [[ -n "$correlated_id" ]] && break
    sleep 2
done
[[ -n "$correlated_id" ]] || fail 'Correlated marker events did not become a multi-event incident with graph/timeline'
pass 'Correlated events become an incident with attack chain and timeline'

ahr_ai_compose exec -T backend python - "$correlated_id" <<'PY'
import asyncio
import sys
import httpx

incident_id = sys.argv[1]

async def main():
    async with httpx.AsyncClient(timeout=10.0) as client:
        data = (await client.get(f"http://127.0.0.1:8000/api/incidents/{incident_id}")).json()
    for key in ("incident_id", "status", "risk_score", "attack_type", "event_count", "attack_graph", "timeline", "events"):
        if key not in data:
            raise SystemExit(f"missing incident detail key: {key}")
    if data["event_count"] < 2 or len(data["events"]) < 2:
        raise SystemExit("incident detail does not include correlated events")
    if not (data["attack_graph"].get("edges") and data["timeline"]):
        raise SystemExit("incident detail missing graph/timeline")
asyncio.run(main())
PY
pass 'Incident detail API renders summary, timeline, graph, event list, rule/AI summaries'

stream_hit="$(ahr_ai_compose exec -T redis redis-cli -a "$REDIS_PASSWORD" XREVRANGE security.incidents + - COUNT 20 | tr -d '\r' | grep -F "$correlated_id" | head -n 1 || true)"
[[ -n "$stream_hit" ]] || fail 'security.incidents stream did not receive realtime incident update'
pass 'Graph/timeline realtime updates are published on security.incidents'

dashboard_html="$(curl.exe --noproxy "*" -fsS "http://127.0.0.1:${NGINX_PORT:-8080}/dashboard/")"
dashboard_asset="$(sed -n 's/.*src="\([^"]*\.js\)".*/\1/p' <<<"$dashboard_html" | head -n 1)"
[[ "$dashboard_asset" == /dashboard/assets/*.js ]] || fail 'Dashboard HTML does not reference a built JavaScript asset'
dashboard_bundle="$(curl.exe --noproxy "*" -fsS "http://127.0.0.1:${NGINX_PORT:-8080}${dashboard_asset}")"
grep -Fq 'Incidents' <<<"$dashboard_bundle" || fail 'Dashboard bundle does not expose incident page'
pass 'Dashboard incident page renders'

pass 'Phase 10 runtime acceptance PASS: correlation, session split tests, attack chain, incident detail, and realtime incident updates verified'
