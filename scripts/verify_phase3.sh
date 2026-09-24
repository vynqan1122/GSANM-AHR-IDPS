#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
AHR_PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
export AHR_PROJECT_ROOT

# shellcheck source=scripts/lib/pipeline.sh
source "$SCRIPT_DIR/lib/pipeline.sh"

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
        printf 'Usage: ./scripts/verify_phase3.sh [--static-only]\n'
        exit 0
        ;;
    *) fail "Unknown option: $1" ;;
esac

ahr_prepare_env
ahr_require_pipeline_files
bash "$SCRIPT_DIR/wazuh_prepare.sh"

for script in \
    "$SCRIPT_DIR/lib/pipeline.sh" \
    "$SCRIPT_DIR/start_pipeline.sh" \
    "$SCRIPT_DIR/stop_pipeline.sh" \
    "$SCRIPT_DIR/verify_phase3.sh"; do
    bash -n "$script"
done

effective="$(ahr_pipeline_compose config)"
ahr_pipeline_compose config --quiet

services="$(ahr_pipeline_compose config --services)"
for service in nginx dvwa mariadb postgres redis suricata falco wazuh-manager collector normalizer; do
    grep -qx "$service" <<<"$services" || fail "Effective Phase 3 Compose model is missing service: $service"
done

for service in collector normalizer; do
    section="$(ahr_compose_service_section "$service" <<<"$effective")"
    [[ -n "$section" ]] || fail "Cannot inspect effective Compose service: $service"
    ! grep -Eq '^[[:space:]]+privileged: true$' <<<"$section" || \
        fail "$service must not run privileged"
    ! grep -Eq '^[[:space:]]+(ports|network_mode):' <<<"$section" || \
        fail "$service must not publish ports or use a shared/host network namespace"
    grep -Eq '^[[:space:]]+read_only: true$' <<<"$section" || \
        fail "$service root filesystem must be read-only"
    grep -Eq '^[[:space:]]+- ALL$' <<<"$section" || \
        fail "$service must drop all Linux capabilities"
    grep -Eq '^[[:space:]]+data:[[:space:]]*null$' <<<"$section" || \
        fail "$service must join only the internal data network"
    grep -Eq '^[[:space:]]+restart: "?no"?$' <<<"$section" || \
        fail "$service restart policy must remain opt-in for this vulnerable lab"
done

collector_section="$(ahr_compose_service_section collector <<<"$effective")"
for log_group in 998 999; do
    grep -Eq "^[[:space:]]+- ['\"]?${log_group}['\"]?$" <<<"$collector_section" || \
        fail "collector needs supplementary read-only sensor log group $log_group"
done

required_python_files=(
    collector/main.py
    collector/config.py
    collector/base.py
    collector/checkpoint.py
    collector/collectors/suricata.py
    collector/collectors/falco.py
    collector/collectors/wazuh.py
    collector/collectors/nginx.py
    collector/collectors/docker_events.py
    collector/collectors/system.py
    normalizer/schemas.py
    normalizer/normalizer.py
)
for file in "${required_python_files[@]}"; do
    [[ -f "$AHR_PROJECT_ROOT/$file" ]] || fail "Missing required Phase 3 implementation file: $file"
done

find "$AHR_PROJECT_ROOT" -maxdepth 3 -type f -name '*.sql' -print -quit | grep -q . || \
    fail 'No PostgreSQL migration was implemented for Phase 3'
grep -Fq 'collector_state' <<<"$effective" || \
    fail 'Collector checkpoints must use a persistent named volume'

pass 'Phase 3 scripts, service hardening, source modules, checkpoint volume, and migration are present'

if [[ "$mode" == static ]]; then
    pass 'Phase 3 static acceptance PASS'
    exit 0
fi

ahr_check_docker_engine
ahr_require_phase2_healthy
bash "$SCRIPT_DIR/start_pipeline.sh"

for service in collector normalizer; do
    id="$(ahr_pipeline_compose ps -q "$service")"
    [[ -n "$id" ]] || fail "$service is not running"
    state="$(docker inspect --format '{{.State.Status}}' "$id")"
    health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$id")"
    [[ "$state" == running && "$health" == healthy ]] || \
        fail "$service is $state/$health"
    [[ "$(docker inspect --format '{{.HostConfig.Privileged}}' "$id")" == false ]] || \
        fail "$service unexpectedly runs privileged"
    [[ "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$id")" == true ]] || \
        fail "$service root filesystem is not read-only"
    [[ "$(docker inspect --format '{{json .HostConfig.CapDrop}}' "$id")" == '["ALL"]' ]] || \
        fail "$service must drop all capabilities"
    [[ -z "$(docker port "$id" 2>/dev/null || true)" ]] || \
        fail "$service unexpectedly publishes a host port"
    network_count="$(docker inspect --format '{{len .NetworkSettings.Networks}}' "$id")"
    [[ "$network_count" == 1 ]] || fail "$service must join exactly one network"
    network_id="$(docker inspect --format '{{range .NetworkSettings.Networks}}{{println .NetworkID}}{{end}}' "$id" | tr -d '\r[:space:]')"
    [[ "$(docker network inspect --format '{{index .Labels "com.docker.compose.network"}}' "$network_id")" == data ]] || \
        fail "$service is not isolated on the data network"
done

collector_id="$(ahr_pipeline_compose ps -q collector)"
collector_groups="$(docker inspect --format '{{json .HostConfig.GroupAdd}}' "$collector_id")"
for log_group in 998 999; do
    grep -Eq "(^|[^0-9])${log_group}([^0-9]|$)" <<<"$collector_groups" || \
        fail "collector runtime is missing supplementary sensor log group $log_group"
done
pass 'Collector and normalizer are healthy, non-privileged, capability-free, unpublished, and data-network-only'

# These tests use temporary files inside the container. They exercise partial
# writes, malformed JSON, truncation/rotation, restart offsets, and deterministic
# IDs without placing fabricated records on the production Redis streams.
ahr_pipeline_compose exec -T collector sh -ec \
    'cd /opt/ahr-idps && exec python -m pytest -q -p no:cacheprovider collector/tests normalizer/tests'
pass 'Isolated collector/normalizer tests passed without injecting fake production events'

redis_cli() {
    ahr_pipeline_compose exec -T redis sh -ec \
        'REDISCLI_AUTH="$REDIS_PASSWORD" exec redis-cli --no-auth-warning "$@"' \
        sh "$@" | tr -d '\r'
}

required_streams=(
    security.events.raw
    security.events.normalized
    security.predictions
    security.incidents
    security.rules
    security.responses
)
for stream in "${required_streams[@]}"; do
    [[ "$(redis_cli TYPE "$stream" | tr -d '[:space:]')" == stream ]] || \
        fail "Redis stream is missing: $stream"
done
require_stream_group() {
    local stream="$1"
    local group="$2"
    redis_cli --raw XINFO GROUPS "$stream" | awk -v wanted="$group" '
        previous == "name" && $0 == wanted { found=1 }
        { previous=$0 }
        END { exit(found ? 0 : 1) }
    ' || fail "Redis stream $stream is missing consumer group: $group"
}

require_stream_group security.events.raw normalizer
for group in feature-engine ai-network ai-log graph-builder dashboard-publisher; do
    require_stream_group security.events.normalized "$group"
done
for group in fusion-engine incident-engine dashboard-publisher; do
    require_stream_group security.predictions "$group"
done
for stream in security.incidents security.rules security.responses; do
    require_stream_group "$stream" dashboard-publisher
done
pass 'All required Redis Streams and consumer groups are materialized without seed events'

postgres_query() {
    local query="$1"
    ahr_pipeline_compose exec -T postgres sh -ec '
        PGPASSWORD="$AHR_DB_PASSWORD" exec psql \
          --host=127.0.0.1 \
          --username="$AHR_DB_USER" \
          --dbname="$POSTGRES_DB" \
          --tuples-only --no-align --set=ON_ERROR_STOP=1 \
          --command="$1"
    ' sh "$query" | tr -d '\r'
}

tables="$(postgres_query "SELECT table_name FROM information_schema.tables WHERE table_schema = 'ahr' ORDER BY table_name;")"
required_tables=(
    events
    alerts
    incidents
    incident_events
    network_flows
    ai_predictions
    models
    model_metrics
    rules
    rule_versions
    rule_validation_runs
    responses
    sensor_health
)
for table in "${required_tables[@]}"; do
    grep -Fxq "$table" <<<"$tables" || fail "PostgreSQL schema is missing table: $table"
done
pass 'Phase 3 PostgreSQL event, model, rule, response, and health schema is installed'

lab_port="$(ahr_env_value LAB_HTTP_PORT)"
run_marker="ahr_p3_$(date +%s)_$$_${RANDOM:-0}"
http_marker="${run_marker}_http"
falco_marker="${run_marker}_falco"
wazuh_marker="${run_marker}_wazuh"

# One loopback request is observed independently by Nginx and Suricata. It is
# benign and cannot leave the explicitly exposed local DVWA lab boundary.
curl --noproxy '*' --silent --show-error --output /dev/null --max-time 15 \
    --header 'Host: dvwa.local' --header 'Connection: close' \
    "http://127.0.0.1:${lab_port}/ahr-phase3/${http_marker}?source=acceptance"

# A shell no-op causes a real exec syscall inside the isolated DVWA container;
# no line is written to Falco output by the verifier.
ahr_pipeline_compose exec -T dvwa sh -c ": ${falco_marker}"

# Wazuh's Docker listener has a delayed subscription after manager startup.
# A prior Phase 2 acceptance leaves it ready, but this bounded wait also covers
# a newly started sensor stack.
wazuh_ready=no
for _ in $(seq 1 90); do
    if ahr_pipeline_compose exec -T wazuh-manager sh -ec \
        "grep -Fq 'docker-listener: INFO: Starting to listening Docker events.' /var/ossec/logs/ossec.log"; then
        wazuh_ready=yes
        break
    fi
    sleep 1
done
[[ "$wazuh_ready" == yes ]] || fail 'Wazuh Docker listener did not become subscription-ready'

MSYS_NO_PATHCONV=1 docker run --rm \
    --name "$wazuh_marker" \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --entrypoint /bin/true \
    nginx@sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236

event_marker_count() {
    local source="$1"
    local marker="$2"
    local query
    [[ "$source" =~ ^[a-z_]+$ && "$marker" =~ ^[A-Za-z0-9_-]+$ ]] || \
        fail 'Internal acceptance marker validation failed'

    if [[ "$source" == wazuh ]]; then
        # Wazuh also observes the verifier's later docker exec/psql commands.
        # Count only the actual probe container creation, not command lines
        # that merely contain the marker inside an acceptance SQL query.
        query="SELECT count(*) FROM ahr.events WHERE source::text = 'wazuh' AND raw_event->'data'->'docker'->'Actor'->'Attributes'->>'name' = '${marker}' AND raw_event->'data'->'docker'->>'Action' = 'create';"
    else
        query="SELECT count(*) FROM ahr.events WHERE source::text = '${source}' AND raw_event::text LIKE '%${marker}%';"
    fi

    postgres_query "$query" |
        tr -d '[:space:]'
}

wait_for_event_marker() {
    local source="$1"
    local marker="$2"
    local count
    for _ in $(seq 1 90); do
        count="$(event_marker_count "$source" "$marker")"
        if [[ "$count" =~ ^[0-9]+$ ]] && (( count > 0 )); then
            printf '%s' "$count"
            return 0
        fi
        sleep 1
    done
    return 1
}

nginx_before="$(wait_for_event_marker nginx "$http_marker")" || \
    fail "No normalized Nginx event reached PostgreSQL for $http_marker"
suricata_before="$(wait_for_event_marker suricata "$http_marker")" || \
    fail "No normalized Suricata event reached PostgreSQL for $http_marker"
falco_before="$(wait_for_event_marker falco "$falco_marker")" || \
    fail "No normalized Falco event reached PostgreSQL for $falco_marker"
wazuh_before="$(wait_for_event_marker wazuh "$wazuh_marker")" || \
    fail "No normalized Wazuh event reached PostgreSQL for $wazuh_marker"
pass 'Real Nginx, Suricata, Falco, and Wazuh records crossed raw stream, normalization, and PostgreSQL persistence'

ahr_pipeline_compose exec -T collector python - <<'PY'
import json
from pathlib import Path

path = Path('/var/lib/ahr-idps/collector/health.json')
document = json.loads(path.read_text(encoding='utf-8'))
for source in ('suricata', 'falco', 'wazuh', 'nginx'):
    state = document.get('sources', {}).get(source, {})
    if state.get('status') != 'healthy':
        raise SystemExit(f'{source} collector status is not healthy: {state}')
    if int(state.get('published', 0)) <= 0:
        raise SystemExit(f'{source} collector has published no real records: {state}')
PY
pass 'Collector health registry confirms all four file sources are readable and publishing'

row_counts="$(postgres_query "SELECT count(*)::text || '|' || count(DISTINCT event_id)::text FROM ahr.events;")"
total_rows="${row_counts%%|*}"
unique_rows="${row_counts##*|}"
[[ "$total_rows" =~ ^[0-9]+$ && "$unique_rows" =~ ^[0-9]+$ && "$total_rows" == "$unique_rows" ]] || \
    fail "events.event_id is not globally idempotent ($total_rows rows, $unique_rows unique IDs)"

# Restart only Phase 3. The checkpoint volume and database uniqueness contract
# must prevent every already accepted marker from being replayed as a new row.
ahr_pipeline_compose restart collector normalizer >/dev/null
for _ in $(seq 1 60); do
    healthy=yes
    for service in collector normalizer; do
        id="$(ahr_pipeline_compose ps -q "$service")"
        [[ -n "$id" ]] || { healthy=no; continue; }
        [[ "$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$id")" == healthy ]] || \
            healthy=no
    done
    [[ "$healthy" == yes ]] && break
    sleep 2
done
[[ "$healthy" == yes ]] || fail 'Pipeline did not become healthy after restart'
sleep 5

nginx_after="$(event_marker_count nginx "$http_marker")"
suricata_after="$(event_marker_count suricata "$http_marker")"
falco_after="$(event_marker_count falco "$falco_marker")"
wazuh_after="$(event_marker_count wazuh "$wazuh_marker")"
[[ "$nginx_after" == "$nginx_before" ]] || fail 'Nginx marker was duplicated after checkpoint restart'
[[ "$suricata_after" == "$suricata_before" ]] || fail 'Suricata marker was duplicated after checkpoint restart'
[[ "$falco_after" == "$falco_before" ]] || fail 'Falco marker was duplicated after checkpoint restart'
[[ "$wazuh_after" == "$wazuh_before" ]] || fail 'Wazuh marker was duplicated after checkpoint restart'
pass 'Persistent checkpoints survived restart without duplicating any accepted sensor record'

normalized_length="$(redis_cli XLEN security.events.normalized | tr -d '[:space:]')"
[[ "$normalized_length" =~ ^[0-9]+$ ]] && (( normalized_length > 0 )) || \
    fail 'Normalized Redis stream is empty after real-event acceptance'

# Phase 3 may add containers and volumes, but must not weaken the Phase 1
# exposure, network, credential, or database isolation contract.
bash "$SCRIPT_DIR/verify_phase1.sh"
pass 'Phase 3 runtime acceptance PASS: real multi-sensor ingestion, normalization, streams, persistence, and restart idempotency verified'
