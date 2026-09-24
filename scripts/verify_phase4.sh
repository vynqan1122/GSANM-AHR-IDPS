#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
AHR_PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
export AHR_PROJECT_ROOT

# shellcheck source=scripts/lib/app.sh
source "$SCRIPT_DIR/lib/app.sh"

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
        printf 'Usage: ./scripts/verify_phase4.sh [--static-only]\n'
        exit 0
        ;;
    *) fail "Unknown option: $1" ;;
esac

ahr_prepare_env
ahr_require_app_files
bash "$SCRIPT_DIR/wazuh_prepare.sh"

for script in \
    "$SCRIPT_DIR/lib/app.sh" \
    "$SCRIPT_DIR/start_app.sh" \
    "$SCRIPT_DIR/stop_app.sh" \
    "$SCRIPT_DIR/verify_phase4.sh"; do
    bash -n "$script"
done

effective="$(ahr_app_compose config)"
ahr_app_compose config --quiet

services="$(ahr_app_compose config --services)"
for service in nginx backend collector normalizer redis postgres; do
    grep -qx "$service" <<<"$services" || fail "Effective Phase 4 Compose model is missing service: $service"
done

backend_section="$(ahr_compose_service_section backend <<<"$effective")"
[[ -n "$backend_section" ]] || fail 'Cannot inspect effective backend service'
grep -Eq '^[[:space:]]+read_only: true$' <<<"$backend_section" || fail 'backend root filesystem must be read-only'
grep -Eq '^[[:space:]]+- ALL$' <<<"$backend_section" || fail 'backend must drop all Linux capabilities'
! grep -Eq '^[[:space:]]+(ports|network_mode):' <<<"$backend_section" || fail 'backend must not publish ports or use host/shared namespace'
grep -Eq '^[[:space:]]+data:[[:space:]]*null$' <<<"$backend_section" || fail 'backend must join the data network'
grep -Eq '^[[:space:]]+app_front:[[:space:]]*null$' <<<"$backend_section" || fail 'backend must join the app_front network'
grep -Eq '^[[:space:]]+restart: "?no"?$' <<<"$backend_section" || fail 'backend restart policy must remain opt-in'

for file in \
    backend/main.py \
    backend/api/events.py \
    backend/api/alerts.py \
    backend/api/sensors.py \
    backend/api/dashboard.py \
    backend/websocket/events.py \
    dashboard/src/main.tsx \
    dashboard/dist/index.html; do
    [[ -f "$AHR_PROJECT_ROOT/$file" ]] || fail "Missing Phase 4 file: $file"
done

pass 'Phase 4 static API, dashboard, WebSocket, and Compose contract is present'

if [[ "$mode" == static ]]; then
    pass 'Phase 4 static acceptance PASS'
    exit 0
fi

ahr_check_docker_engine
ahr_require_phase3_healthy
bash "$SCRIPT_DIR/start_app.sh"

backend_id="$(ahr_app_compose ps -q backend)"
[[ -n "$backend_id" ]] || fail 'backend is not running'
[[ "$(docker inspect --format '{{.State.Status}}' "$backend_id")" == running ]] || fail 'backend is not running'
[[ "$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$backend_id")" == healthy ]] || fail 'backend is not healthy'
[[ "$(docker inspect --format '{{.HostConfig.Privileged}}' "$backend_id")" == false ]] || fail 'backend unexpectedly runs privileged'
[[ "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$backend_id")" == true ]] || fail 'backend root filesystem is not read-only'
[[ "$(docker inspect --format '{{json .HostConfig.CapDrop}}' "$backend_id")" == '["ALL"]' ]] || fail 'backend must drop all capabilities'
[[ -z "$(docker port "$backend_id" 2>/dev/null || true)" ]] || fail 'backend unexpectedly publishes a host port'
pass 'Backend container is healthy, non-privileged, capability-free, and unpublished'

lab_port="$(ahr_env_value LAB_HTTP_PORT)"
curl --noproxy '*' --silent --show-error --fail --max-time 15 \
    "http://127.0.0.1:${lab_port}/api/health" | grep -q '"status":"healthy"' || \
    fail 'Backend health API did not respond through Nginx'
curl --noproxy '*' --silent --show-error --fail --max-time 15 \
    "http://127.0.0.1:${lab_port}/dashboard/" | grep -q 'AHR-IDPS' || \
    fail 'Dashboard did not load through Nginx'
pass 'Dashboard and API load through the single loopback Nginx entrypoint'

ahr_app_compose exec -T backend python - <<'PY'
import asyncio
import httpx
import json

async def main():
    async with httpx.AsyncClient(timeout=10.0) as client:
        events = (await client.get("http://127.0.0.1:8000/api/events?page_size=5")).json()
        assert events["total"] > 0 and events["items"], "events endpoint returned no real rows"
        overview = (await client.get("http://127.0.0.1:8000/api/dashboard/overview")).json()
        assert overview["cards"]["total_events"] > 0, "overview cards are not backed by real events"
        assert overview["events_by_source"], "events-by-source chart has no real data"
        sensors = (await client.get("http://127.0.0.1:8000/api/sensors")).json()
        names = {item["sensor"] for item in sensors["items"]}
        required = {"suricata", "falco", "wazuh", "collector", "normalizer", "redis", "postgresql"}
        missing = sorted(required - names)
        assert not missing, f"missing sensor statuses: {missing}"

asyncio.run(main())
PY
pass 'REST endpoints expose real events, charts, and sensor health'

marker="ahr_p4_$(date +%s)_$$_${RANDOM:-0}"
ahr_app_compose exec -T backend python - "$marker" <<'PY'
import asyncio
import sys

import httpx
import websockets

marker = sys.argv[1]

async def main():
    async with websockets.connect("ws://127.0.0.1:8000/ws/events") as ws:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(
                f"http://nginx/ahr-phase4/{marker}",
                headers={"Host": "dvwa.local", "Connection": "close"},
            )
            assert response.status_code < 500
        for _ in range(90):
            message = await asyncio.wait_for(ws.recv(), timeout=2.0)
            if marker in message:
                return
    raise SystemExit(f"websocket did not receive marker {marker}")

asyncio.run(main())
PY
pass 'WebSocket realtime stream delivered a newly generated lab event'

ahr_app_compose restart backend >/dev/null
for _ in $(seq 1 60); do
    [[ "$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$backend_id")" == healthy ]] && break
    sleep 2
done
[[ "$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$backend_id")" == healthy ]] || \
    fail 'Backend did not recover after Docker restart'
curl --noproxy '*' --silent --show-error --fail --max-time 15 \
    "http://127.0.0.1:${lab_port}/api/system/health" | grep -q '"status":"healthy"' || \
    fail 'System health did not recover after backend restart'
pass 'Docker restart recovers backend API and health checks'

bash "$SCRIPT_DIR/verify_phase3.sh"
pass 'Phase 4 runtime acceptance PASS: dashboard, API, WebSockets, real data, sensor health, restart recovery verified'
