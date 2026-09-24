#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
AHR_PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
export AHR_PROJECT_ROOT

# shellcheck source=scripts/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

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
        printf 'Usage: ./scripts/suricata_acceptance.sh [--static-only]\n'
        exit 0
        ;;
    *) fail "Unknown option: $1" ;;
esac

cd "$AHR_PROJECT_ROOT"
ahr_prepare_env

compose_args=(--env-file "$AHR_PROJECT_ROOT/.env" -f "$AHR_PROJECT_ROOT/docker-compose.yml")
if ! docker compose "${compose_args[@]}" config --services | grep -qx suricata; then
    compose_args+=(-f "$AHR_PROJECT_ROOT/sensors/suricata/compose.fragment.yml")
fi

compose() {
    docker compose "${compose_args[@]}" "$@"
}

compose config --quiet
compose config --services | grep -qx suricata || fail 'Compose does not define the suricata service'

for required_file in \
    sensors/suricata/suricata.yaml \
    sensors/suricata/rules/base.rules \
    sensors/suricata/rules/generated.rules \
    sensors/suricata/rules/shadow.rules \
    sensors/suricata/scripts/suricata-entrypoint.sh; do
    [[ -f "$required_file" ]] || fail "Missing required file: $required_file"
done
pass 'Suricata configuration, rule lifecycle files, and entrypoint exist'

bash -n sensors/suricata/scripts/suricata-entrypoint.sh
effective="$(compose config)"
suricata_effective="$(awk '
    /^  suricata:$/ { in_service=1 }
    in_service && seen && /^  [A-Za-z0-9_.-]+:$/ { exit }
    in_service { print; seen=1 }
' <<<"$effective")"
grep -Fq 'sha256:581dca6c8cc8a8a2fafd3fff33368573b547b7600a22b21a18866da05727508f' \
    <<<"$suricata_effective" || fail 'Effective Suricata image is not pinned to the accepted digest'
grep -Eq '^[[:space:]]+network_mode: service:nginx$' <<<"$suricata_effective" || \
    fail 'Suricata must share only the Nginx network namespace'
! grep -Eq '^[[:space:]]+privileged: true$' <<<"$suricata_effective" || \
    fail 'Suricata must not run privileged'
grep -Fq 'alert http flow dns tls' < <(
    awk '
        /^[[:space:]]*- alert:/ { alert=1 }
        /^[[:space:]]*- http:/ { http=1 }
        /^[[:space:]]*- flow$/ { flow=1 }
        /^[[:space:]]*- dns:/ { dns=1 }
        /^[[:space:]]*- tls:/ { tls=1 }
        END { if (alert && http && flow && dns && tls) print "alert http flow dns tls" }
    ' sensors/suricata/suricata.yaml
) || fail 'Suricata EVE must enable alert, http, flow, dns, and tls'
grep -Fq 'sid:9000001;' sensors/suricata/rules/base.rules || \
    fail 'Harmless acceptance signature SID 9000001 is missing'
for interface in eth0 eth1 lo; do
    grep -Eq "^[[:space:]]+- interface: ${interface}$" sensors/suricata/suricata.yaml || \
        fail "Suricata capture interface is missing: $interface"
done
pass 'Suricata static policy, EVE outputs, pinned image, and rules are valid'

if [[ "$mode" == static ]]; then
    pass 'Suricata static acceptance complete'
    exit 0
fi

ahr_check_docker_engine

nginx_id="$(compose ps -q nginx)"
[[ -n "$nginx_id" ]] || fail 'Nginx is not running; start and verify Phase 1 before sensor acceptance'
nginx_state="$(docker inspect --format '{{.State.Status}}' "$nginx_id")"
nginx_health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$nginx_id")"
[[ "$nginx_state" == running && "$nginx_health" == healthy ]] || \
    fail "Nginx must be running and healthy (state=$nginx_state health=$nginx_health)"

printf '[INFO] Recreating only the Suricata sensor against the healthy Phase 1 lab...\n'
if ! compose up --detach --wait --wait-timeout 180 --force-recreate --no-deps suricata; then
    compose ps --all || true
    compose logs --no-color --tail 200 suricata || true
    fail 'Suricata did not become healthy'
fi

suricata_id="$(compose ps -q suricata)"
[[ -n "$suricata_id" && -n "$nginx_id" ]] || fail 'Suricata or Nginx container is missing'

suricata_state="$(docker inspect --format '{{.State.Status}}' "$suricata_id")"
suricata_health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$suricata_id")"
[[ "$suricata_state" == running ]] || fail "Suricata state is $suricata_state"
[[ "$suricata_health" == healthy ]] || fail "Suricata health is $suricata_health"

configured_image="$(docker inspect --format '{{.Config.Image}}' "$suricata_id")"
expected_image='jasonish/suricata@sha256:581dca6c8cc8a8a2fafd3fff33368573b547b7600a22b21a18866da05727508f'
[[ "$configured_image" == "$expected_image" ]] || \
    fail "Suricata image is '$configured_image'; expected pinned 8.0.6 image '$expected_image'"

[[ "$(docker inspect --format '{{.HostConfig.Privileged}}' "$suricata_id")" == false ]] || \
    fail 'Suricata unexpectedly runs privileged'
[[ "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$suricata_id")" == true ]] || \
    fail 'Suricata root filesystem must be read-only'
[[ "$(docker inspect --format '{{json .HostConfig.CapDrop}}' "$suricata_id")" == '["ALL"]' ]] || \
    fail 'Suricata must drop all default capabilities'
grep -Fq 'no-new-privileges:true' <<<"$(docker inspect --format '{{json .HostConfig.SecurityOpt}}' "$suricata_id")" || \
    fail 'Suricata must enforce no-new-privileges'
[[ "$(docker inspect --format '{{json .NetworkSettings.Ports}}' "$suricata_id")" == '{}' ]] || \
    fail 'Suricata unexpectedly publishes a port'

suricata_network_mode="$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$suricata_id")"
[[ "$suricata_network_mode" == "container:${nginx_id}" ]] || \
    fail 'Suricata does not share the Nginx network namespace'

runtime_uid="$(compose exec -T suricata sh -ec '
    pid="$(cat /var/run/suricata/suricata.pid)"
    awk '\''/^Uid:/ { print $2; exit }'\'' "/proc/$pid/status"
' | tr -d '\r[:space:]')"
[[ "$runtime_uid" == 998 ]] || fail "Suricata engine did not drop privileges (runtime UID: $runtime_uid)"

actual_caps="$(
    docker inspect --format '{{range .HostConfig.CapAdd}}{{println .}}{{end}}' "$suricata_id" |
        tr -d '\r' | sed -e '/^$/d' -e 's/^CAP_//' | sort | paste -sd ',' -
)"
expected_caps='CHOWN,DAC_OVERRIDE,NET_ADMIN,NET_RAW,SETGID,SETPCAP,SETUID,SYS_NICE'
[[ "$actual_caps" == "$expected_caps" ]] || \
    fail "Suricata capabilities are '$actual_caps'; expected '$expected_caps'"
pass 'Sensor is healthy, digest-pinned, least-capability, unpublished, and scoped to Nginx traffic'

suricata_version="$(compose exec -T suricata suricata -V | tr -d '\r')"
[[ "$suricata_version" == *'Suricata version 8.0.6 RELEASE'* ]] || \
    fail "Unexpected runtime version: $suricata_version"

# Keep the container path inside the shell program so Git Bash/MSYS does not
# rewrite it to a Windows path before Docker passes it into the Linux container.
compose exec -T suricata \
    sh -ec 'suricata -T -c /etc/suricata/suricata.yaml' >/dev/null
pass 'Suricata 8.0.6 accepted the mounted configuration and all local rules'

compose exec -T suricata python3 - <<'PY'
import pathlib
import sys
import yaml

config = yaml.safe_load(pathlib.Path('/etc/suricata/suricata.yaml').read_text())
eve = next(
    item['eve-log']
    for item in config.get('outputs', [])
    if isinstance(item, dict) and 'eve-log' in item
)
enabled = set()
for item in eve.get('types', []):
    if isinstance(item, str):
        enabled.add(item)
    elif isinstance(item, dict):
        enabled.update(item)
required = {'alert', 'http', 'flow', 'dns', 'tls'}
missing = sorted(required - enabled)
if missing:
    print('missing EVE types: ' + ', '.join(missing), file=sys.stderr)
    raise SystemExit(1)
PY
pass 'EVE JSON enables alert, http, flow, dns, and tls records'

lab_port="$(ahr_env_value LAB_HTTP_PORT)"
probe="ahr_suri_$(date +%s)_$$_${RANDOM:-0}"
probe_path="/ahr-suricata-acceptance/${probe}?source=phase2"

curl --noproxy '*' --silent --show-error --output /dev/null \
    --max-time 15 --header 'Host: dvwa.local' --header 'Connection: close' \
    "http://127.0.0.1:${lab_port}${probe_path}"

found=no
for _ in $(seq 1 30); do
    if compose exec -T suricata python3 - "$probe" <<'PY'
import json
import pathlib
import sys

probe = sys.argv[1]
pairs = {}
for raw_line in pathlib.Path('/var/log/suricata/eve.json').open(
    encoding='utf-8', errors='replace'
):
    try:
        event = json.loads(raw_line)
    except json.JSONDecodeError:
        continue
    url = event.get('http', {}).get('url', '')
    if probe not in url:
        continue
    key = (event.get('flow_id'), event.get('in_iface'))
    pairs.setdefault(key, set())
    if event.get('event_type') == 'http':
        pairs[key].add('http')
    if (
        event.get('event_type') == 'alert'
        and event.get('alert', {}).get('signature_id') == 9000001
    ):
        pairs[key].add('alert')
complete = [key for key, kinds in pairs.items() if {'alert', 'http'} <= kinds]
if len({key[0] for key in complete}) < 2:
    raise SystemExit(1)
if not {'eth0', 'eth1'} <= {key[1] for key in complete}:
    raise SystemExit(1)
PY
    then
        found=yes
        break
    fi
    sleep 1
done

[[ "$found" == yes ]] || {
    compose logs --no-color --tail 200 suricata || true
    fail "No matching real HTTP + alert EVE records appeared for probe $probe"
}

compose exec -T suricata python3 - "$probe" <<'PY'
import json
import pathlib
import sys

probe = sys.argv[1]
for raw_line in pathlib.Path('/var/log/suricata/eve.json').open(
    encoding='utf-8', errors='replace'
):
    try:
        event = json.loads(raw_line)
    except json.JSONDecodeError:
        continue
    if probe in event.get('http', {}).get('url', '') and event.get('event_type') in {'alert', 'http'}:
        print(json.dumps(event, separators=(',', ':'), sort_keys=True))
PY

pass "Real traffic produced paired HTTP + SID 9000001 events on both ingress and proxy legs ($probe)"
pass 'Suricata Phase 2 acceptance complete'
