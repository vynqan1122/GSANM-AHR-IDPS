#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
AHR_PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
export AHR_PROJECT_ROOT

# shellcheck source=scripts/lib/sensors.sh
source "$SCRIPT_DIR/lib/sensors.sh"

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
    --docker-only) mode=docker-only ;;
    --require-host-auth) mode=host-auth ;;
    -h|--help)
        printf 'Usage: ./scripts/wazuh_acceptance.sh [--static-only|--docker-only|--require-host-auth]\n'
        exit 0
        ;;
    *) fail "Unknown option: $1" ;;
esac

ahr_prepare_env
bash "$SCRIPT_DIR/wazuh_prepare.sh"
ahr_require_sensor_files
ahr_sensors_compose config --quiet

required=(
    sensors/wazuh/compose.fragment.yml
    sensors/wazuh/manager/ossec.conf
    sensors/wazuh/rules/ahr_falco_rules.xml
    sensors/wazuh/entrypoint-scripts/10-manager-only.sh
    scripts/wazuh_prepare.sh
    scripts/wazuh_auth_probe.ps1
)
for file in "${required[@]}"; do
    [[ -f "$AHR_PROJECT_ROOT/$file" ]] || fail "Missing required file: $file"
done

grep -Fq '<wodle name="docker-listener">' "$AHR_PROJECT_ROOT/sensors/wazuh/manager/ossec.conf" || \
    fail 'Wazuh Docker listener is not configured'
grep -Fq '<location>/var/log/suricata/eve*.json</location>' "$AHR_PROJECT_ROOT/sensors/wazuh/manager/ossec.conf" || \
    fail 'Wazuh Suricata localfile input is not configured'
grep -Fq '<location>/var/log/falco/events*.jsonl</location>' "$AHR_PROJECT_ROOT/sensors/wazuh/manager/ossec.conf" || \
    fail 'Wazuh Falco localfile input is not configured'
grep -Fq '<rule id="100101"' "$AHR_PROJECT_ROOT/sensors/wazuh/rules/ahr_falco_rules.xml" || \
    fail 'Wazuh Falco elevated rule is missing'

effective="$(ahr_sensors_compose config)"
wazuh_effective="$(awk '
    /^  wazuh-manager:$/ { in_service=1 }
    in_service && seen && /^  [A-Za-z0-9_.-]+:$/ { exit }
    in_service { print; seen=1 }
' <<<"$effective")"
grep -Fq 'sha256:c364ef100ba40d501537b1668a5a72bba4c4fbcf39bbef6a02123ff221fc40d0' <<<"$wazuh_effective" || \
    fail 'Effective Wazuh image is not pinned to the accepted digest'
grep -Eq '^[[:space:]]+restart: "?no"?$' <<<"$wazuh_effective" || \
    fail 'Wazuh restart policy must be no for this opt-in vulnerable lab'
[[ "$(grep -Ec '^[[:space:]]+host_ip: 127\.0\.0\.1$' <<<"$wazuh_effective")" == 2 ]] || \
    fail 'Both Wazuh agent ports must bind only to 127.0.0.1'
wazuh_ports="$(awk '
    /^    ports:$/ { in_ports=1; next }
    in_ports && /^    [A-Za-z0-9_.-]+:/ { exit }
    in_ports { print }
' <<<"$wazuh_effective")"
[[ "$(grep -Ec '^[[:space:]]+target:' <<<"$wazuh_ports")" == 2 ]] || \
    fail 'Wazuh must define exactly two container port targets'
[[ "$(grep -Ec '^[[:space:]]+published:' <<<"$wazuh_ports")" == 2 ]] || \
    fail 'Wazuh must define exactly two published ports'
[[ "$(grep -Ec '^[[:space:]]+host_ip:' <<<"$wazuh_ports")" == 2 ]] || \
    fail 'Wazuh must define exactly two host bindings'
[[ "$(grep -Ec '^[[:space:]]+target: (1514|1515)$' <<<"$wazuh_ports")" == 2 ]] || \
    fail 'Wazuh must expose exactly agent targets 1514 and 1515'
[[ "$(grep -Ec '^[[:space:]]+published: "?(1514|1515)"?$' <<<"$wazuh_ports")" == 2 ]] || \
    fail 'Wazuh must publish exactly agent ports 1514 and 1515'
[[ "$(grep -Ec '^[[:space:]]+host_ip: 127\.0\.0\.1$' <<<"$wazuh_ports")" == 2 ]] || \
    fail 'Every Wazuh port must be loopback-only'
! grep -Eq '^[[:space:]]+privileged: true$' <<<"$wazuh_effective" || fail 'Wazuh must not run privileged'
grep -Eq '^[[:space:]]+wazuh_agent:[[:space:]]*null$' <<<"$wazuh_effective" || \
    fail 'Wazuh must use the explicit dedicated agent network'
pass 'Wazuh files and effective Compose security policy are valid'

if [[ "$mode" == static ]]; then
    pass 'Wazuh static acceptance complete'
    exit 0
fi

ahr_check_docker_engine
ahr_require_phase1_healthy

if [[ "$mode" != docker-only ]]; then
    for sensor in suricata falco; do
        sensor_id="$(ahr_sensors_compose ps -q "$sensor")"
        [[ -n "$sensor_id" ]] || fail "$sensor is not running"
        [[ "$(docker inspect --format '{{.State.Health.Status}}' "$sensor_id")" == healthy ]] || \
            fail "$sensor is not healthy"
    done
fi

docker_listener_first_line=1
existing_wazuh_id="$(ahr_sensors_compose ps -q wazuh-manager)"
if [[ -n "$existing_wazuh_id" && "$(docker inspect --format '{{.State.Running}}' "$existing_wazuh_id")" == true ]]; then
    existing_log_lines="$(ahr_sensors_compose exec -T wazuh-manager sh -ec \
        'wc -l < /var/ossec/logs/ossec.log 2>/dev/null || echo 0' | tr -d '\r[:space:]')"
    [[ "$existing_log_lines" =~ ^[0-9]+$ ]] || existing_log_lines=0
    docker_listener_first_line=$((existing_log_lines + 1))
fi

ahr_sensors_compose up --detach --wait --wait-timeout 300 --force-recreate --no-deps wazuh-manager
wazuh_id="$(ahr_sensors_compose ps -q wazuh-manager)"
[[ -n "$wazuh_id" ]] || fail 'Wazuh manager is not running'
[[ "$(docker inspect --format '{{.State.Health.Status}}' "$wazuh_id")" == healthy ]] || \
    fail 'Wazuh manager is not healthy'

runtime_image="$(docker inspect --format '{{.Config.Image}}' "$wazuh_id")"
[[ "$runtime_image" == *'@sha256:c364ef100ba40d501537b1668a5a72bba4c4fbcf39bbef6a02123ff221fc40d0' ]] || \
    fail "Unexpected Wazuh runtime image: $runtime_image"
[[ "$(docker inspect --format '{{.HostConfig.Privileged}}' "$wazuh_id")" == false ]] || \
    fail 'Wazuh manager unexpectedly runs privileged'
grep -Fq 'no-new-privileges:true' <<<"$(docker inspect --format '{{json .HostConfig.SecurityOpt}}' "$wazuh_id")" || \
    fail 'Wazuh manager must enforce no-new-privileges'

wazuh_networks="$(docker inspect --format '{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}' "$wazuh_id" | tr -d '\r')"
[[ "$(wc -l <<<"$wazuh_networks" | tr -d '[:space:]')" == 1 ]] || \
    fail "Wazuh must join exactly one network; found: $wazuh_networks"
wazuh_network_id="$(docker inspect --format '{{range .NetworkSettings.Networks}}{{println .NetworkID}}{{end}}' "$wazuh_id" | tr -d '\r[:space:]')"
[[ "$(docker network inspect --format '{{index .Labels "com.docker.compose.network"}}' "$wazuh_network_id")" == wazuh_agent ]] || \
    fail 'Wazuh runtime network is not the dedicated agent bridge'

ports="$(docker port "$wazuh_id" | tr -d '\r')"
expected_ports=$'1514/tcp -> 127.0.0.1:1514\n1515/tcp -> 127.0.0.1:1515'
[[ "$(sort <<<"$ports")" == "$expected_ports" ]] || \
    fail "Unexpected Wazuh runtime port bindings: $ports"

wazuh_version="$(ahr_sensors_compose exec -T wazuh-manager \
    sh -ec 'exec /var/ossec/bin/wazuh-logtest -V' 2>&1 | tr -d '\r')"
grep -Fq 'Wazuh v4.14.7' <<<"$wazuh_version" || fail 'Unexpected Wazuh runtime version'
ahr_sensors_compose exec -T wazuh-manager sh -ec \
    "grep -Fq 'Module docker-listener started.' /var/ossec/logs/ossec.log" || \
    fail 'Wazuh Docker listener did not start'

# The bundled Docker listener starts its module process first, then performs a
# deliberate delayed subscription. Wait for a readiness line appended by this
# container instance so the first acceptance event cannot be lost.
docker_listener_ready=no
for _ in $(seq 1 90); do
    if ahr_sensors_compose exec -T wazuh-manager sh -ec '
        tail -n +"$1" /var/ossec/logs/ossec.log |
          grep -Fq "docker-listener: INFO: Starting to listening Docker events."
    ' sh "$docker_listener_first_line"; then
        docker_listener_ready=yes
        break
    fi
    sleep 1
done
[[ "$docker_listener_ready" == yes ]] || \
    fail 'Wazuh Docker listener process started but did not become subscription-ready'
pass 'Wazuh 4.14.7 manager, localfile readers, and Docker event subscription are healthy'

json_error_count_before="$(ahr_sensors_compose exec -T wazuh-manager \
    sh -ec "grep -c 'Too many fields for JSON decoder' /var/ossec/logs/ossec.log || true" | tr -d '\r[:space:]')"

wait_for_alert() {
    local marker="$1"
    local required_rule_id="$2"
    local source_key="$3"
    ahr_sensors_compose exec -T wazuh-manager sh -ec \
        'exec /var/ossec/framework/python/bin/python3 "$@"' \
        sh - "$marker" "$required_rule_id" "$source_key" <<'PY'
import json
import pathlib
import sys
import time

marker, required_rule_id, source_key = sys.argv[1:]
required_location = {
    'docker': 'Wazuh-Docker',
    'suricata': '/var/log/suricata/eve.json',
    'falco': '/var/log/falco/events.jsonl',
}[source_key]
path = pathlib.Path('/var/ossec/logs/alerts/alerts.json')
deadline = time.monotonic() + 30
while time.monotonic() < deadline:
    if path.exists():
        for raw in path.open(encoding='utf-8', errors='replace'):
            try:
                event = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if marker not in raw:
                continue
            if str(event.get('rule', {}).get('id')) != required_rule_id:
                continue
            if event.get('location') != required_location:
                continue
            print(json.dumps(event, separators=(',', ':'), sort_keys=True))
            raise SystemExit(0)
    time.sleep(1)
raise SystemExit(1)
PY
}

docker_marker="ahr-wazuh-$(date +%s)-$$_${RANDOM:-0}"
MSYS_NO_PATHCONV=1 docker run --rm \
    --name "$docker_marker" \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --entrypoint /bin/true \
    nginx@sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236
wait_for_alert "$docker_marker" 87901 docker || \
    fail "No fresh Wazuh Docker create alert for $docker_marker"
pass 'real Docker lifecycle event was persisted as Wazuh rule 87901'

if [[ "$mode" != docker-only ]]; then
    lab_port="$(ahr_env_value LAB_HTTP_PORT)"
    suricata_marker="ahr_wazuh_suri_$(date +%s)_$$_${RANDOM:-0}"
    curl --noproxy '*' --silent --show-error --output /dev/null --max-time 15 \
        --header 'Host: dvwa.local' --header 'Connection: close' \
        "http://127.0.0.1:${lab_port}/ahr-suricata-acceptance/${suricata_marker}?source=wazuh"
    wait_for_alert "$suricata_marker" 86601 suricata || \
        fail "No fresh Wazuh Suricata alert for $suricata_marker"
    pass 'real Suricata SID 9000001 event was persisted as Wazuh rule 86601'

    falco_marker="ahr_wazuh_falco_$(date +%s)_$$_${RANDOM:-0}"
    ahr_sensors_compose exec -T dvwa sh -c ':' "$falco_marker"
    wait_for_alert "$falco_marker" 100101 falco || \
        fail "No fresh Wazuh Falco alert for $falco_marker"
    pass 'real Falco eBPF shell event was persisted as Wazuh rule 100101'
fi

json_error_count_after="$(ahr_sensors_compose exec -T wazuh-manager \
    sh -ec "grep -c 'Too many fields for JSON decoder' /var/ossec/logs/ossec.log || true" | tr -d '\r[:space:]')"
[[ "$json_error_count_after" == "$json_error_count_before" ]] || \
    fail 'Fresh sensor traffic caused a Wazuh JSON decoder overflow'

ahr_sensors_compose exec -T wazuh-manager sh -ec \
    'exec /var/ossec/framework/python/bin/python3 "$@"' sh - <<'PY'
import json
import pathlib

path = pathlib.Path('/var/ossec/logs/alerts/alerts.json')
records = path.read_bytes().splitlines(keepends=True)
# Wazuh is live and may be between write(2) calls for the final JSONL record.
# Validate every complete newline-terminated record in the snapshot.
complete = [raw for raw in records if raw.endswith(b'\n')]
for raw in complete:
    json.loads(raw)
if not complete:
    raise SystemExit('alerts.json is empty')
print(f'[PASS] Wazuh alerts.json contains {len(complete)} complete valid native JSON events')
PY

if [[ "$mode" == host-auth ]]; then
    active_agents="$(ahr_sensors_compose exec -T wazuh-manager sh -ec \
        'exec /var/ossec/bin/agent_control -lc' 2>/dev/null || true)"
    grep -Eq 'ID: [0-9]{3},' <<<"$active_agents" || \
        fail 'No active native host agent; install/enroll it before --require-host-auth'
    command -v powershell.exe >/dev/null 2>&1 || fail 'powershell.exe is required for the Windows auth probe'
    auth_marker="$(powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$AHR_PROJECT_ROOT/scripts/wazuh_auth_probe.ps1" | tr -d '\r[:space:]')"
    [[ "$auth_marker" == ahr_wazuh_* ]] || fail 'Windows auth probe did not return its unique marker'
    # Require the exact Windows failed-logon event and target account, not an
    # arbitrary native-agent alert that happens to contain the marker.
    found=no
    for _ in $(seq 1 60); do
        if ahr_sensors_compose exec -T wazuh-manager sh -ec \
            'exec /var/ossec/framework/python/bin/python3 "$@"' \
            sh - "$auth_marker" <<'PY'
import json, pathlib, sys
marker = sys.argv[1]
for raw in pathlib.Path('/var/ossec/logs/alerts/alerts.json').open(encoding='utf-8', errors='replace'):
    if marker not in raw:
        continue
    event = json.loads(raw)
    win = event.get('data', {}).get('win', {})
    system = win.get('system', {})
    eventdata = win.get('eventdata', {})
    event_id = str(system.get('eventID', system.get('eventId', '')))
    target_user = eventdata.get('targetUserName', eventdata.get('targetUsername', ''))
    if (
        event.get('agent', {}).get('id') not in (None, '000')
        and event_id == '4625'
        and target_user == marker
    ):
        print(json.dumps(event, separators=(',', ':'), sort_keys=True))
        raise SystemExit(0)
raise SystemExit(1)
PY
        then
            found=yes
            break
        fi
        sleep 2
    done
    [[ "$found" == yes ]] || fail "No native-agent Windows authentication alert for $auth_marker"
    pass 'real Windows failed-logon event arrived through a native Wazuh agent'
fi

pass 'Wazuh Phase 2 real-event acceptance complete'
