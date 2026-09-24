#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
AHR_PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
FALCO_FRAGMENT="$AHR_PROJECT_ROOT/sensors/falco/compose.fragment.yml"
FALCO_RULES="$AHR_PROJECT_ROOT/sensors/falco/falco_rules.local.yaml"
FALCO_CONFIG="$AHR_PROJECT_ROOT/sensors/falco/90-ahr-idps.yaml"

pass() {
    printf '[PASS] %s\n' "$*"
}

fail() {
    printf '[FAIL] %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"
}

compose() {
    COMPOSE_IGNORE_ORPHANS=true docker compose \
        --project-directory "$AHR_PROJECT_ROOT" \
        --env-file "$AHR_PROJECT_ROOT/.env" \
        -f "$AHR_PROJECT_ROOT/docker-compose.yml" \
        -f "$FALCO_FRAGMENT" \
        "$@"
}

jsonl_line_count() {
    compose exec -T falco sh -ec \
        'wc -l < /var/log/falco/events.jsonl' | tr -d '\r[:space:]'
}

rule_seen_after() {
    local completed_lines="$1"
    local rule="$2"
    local marker="$3"
    local first_line=$((completed_lines + 1))
    compose exec -T falco sh -ec '
        tail -n +"$1" /var/log/falco/events.jsonl |
          grep -F -- "$3" |
          grep -F -- "\"rule\":\"$2\"" |
          jq -e --arg wanted_rule "$2" --arg marker "$3" \
            '\''select(.rule == $wanted_rule and (tostring | contains($marker)))'\'' \
            >/dev/null
    ' sh "$first_line" "$rule" "$marker"
}

wait_for_rule() {
    local offset="$1"
    local rule="$2"
    local marker="$3"
    local attempt
    for attempt in $(seq 1 30); do
        if rule_seen_after "$offset" "$rule" "$marker"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

validate_jsonl() {
    # The awk program emits every record except the possibly active final
    # record, bounding the snapshot while avoiding a partial-write race.
    compose exec -T falco sh -ec '
        tail -n 201 /var/log/falco/events.jsonl | awk "$1" |
          jq -e -s "$2"
    ' sh \
        'NR > 1 { print previous } { previous = $0 }' \
        'length > 0 and all(.[]; (.time | type == "string") and (.rule | type == "string") and (.output_fields | type == "object"))'
}

mode=runtime
case "${1:-}" in
    '') ;;
    --static-only) mode=static ;;
    -h|--help)
        printf 'Usage: ./scripts/falco_acceptance.sh [--static-only]\n'
        exit 0
        ;;
    *) fail "Unknown option: $1" ;;
esac

require_command docker

[[ -f "$AHR_PROJECT_ROOT/.env" ]] || fail "Missing .env; run the Phase 1 preparation first"
[[ -f "$FALCO_FRAGMENT" ]] || fail "Missing $FALCO_FRAGMENT"
[[ -f "$FALCO_RULES" ]] || fail "Missing $FALCO_RULES"
[[ -f "$FALCO_CONFIG" ]] || fail "Missing $FALCO_CONFIG"

bash -n "$0"
pass "acceptance script parses cleanly"

effective="$(compose config)"
falco_effective="$(awk '
    /^  falco:$/ { in_service=1 }
    in_service && seen && /^  [A-Za-z0-9_.-]+:$/ { exit }
    in_service { print; seen=1 }
' <<<"$effective")"
[[ -n "$falco_effective" ]] || fail "Merged Compose model has no falco service"
grep -Fq 'sha256:85ad8559039c97f40d71f1491ef6a0d7c613f7ae9a530fea0a415a1644c09eb1' \
    <<<"$falco_effective" || fail 'Effective Falco image is not pinned to the accepted digest'
grep -Eq '^[[:space:]]+network_mode: none$' <<<"$falco_effective" || \
    fail 'Falco must have no container network'
grep -Eq '^[[:space:]]+pid: host$' <<<"$falco_effective" || \
    fail 'Falco must observe the Linux host PID namespace'
! grep -Eq '^[[:space:]]+privileged: true$' <<<"$falco_effective" || \
    fail 'Falco must not run privileged'
for capability in SYS_ADMIN SYS_PTRACE SYS_RESOURCE; do
    grep -Fq -- "- $capability" <<<"$falco_effective" || \
        fail "Falco is missing required capability $capability"
done
grep -Eq '^[[:space:]]+kind:[[:space:]]+modern_ebpf' "$FALCO_CONFIG" || \
    fail "modern eBPF is not configured"
grep -q 'json_output: true' "$FALCO_CONFIG" || fail "Falco JSON output is not enabled"
grep -q 'filename: /var/log/falco/events.jsonl' "$FALCO_CONFIG" || \
    fail "Falco JSONL file output is not configured"

for rule in \
    'AHR Shell Spawned Inside Web Container' \
    'AHR Unexpected Child Process In Web Container' \
    'AHR Suspicious Executable In Web Container' \
    'AHR Sensitive Path Write In Web Container' \
    'AHR Unexpected Outbound Connection From Web Container' \
    'AHR Privilege Activity In Web Container'; do
    grep -Fq -- "- rule: $rule" "$FALCO_RULES" || fail "Missing rule: $rule"
done
pass "six required Falco runtime detections are present"

if [[ "$mode" == static ]]; then
    pass "Falco static acceptance complete"
    exit 0
fi

docker info >/dev/null 2>&1 || fail "Docker Engine is not reachable"
[[ "$(docker info --format '{{.OSType}}')" == linux ]] || \
    fail "Falco requires Docker Linux-container mode"

# Keep path-like arguments inside a shell command so Git Bash/MSYS does not
# rewrite Linux container paths into Windows paths. This is a runtime config
# test because it executes the pinned Falco image.
compose run --rm --no-deps --entrypoint sh falco \
    -ec 'exec falco --dry-run -c /etc/falco/falco.yaml' >/dev/null
pass "Falco 0.44.1 accepts the mounted configuration and rules"

# Start only the host sensor. Phase 1 owns the intentionally vulnerable target
# lifecycle, so this verifier neither starts nor restarts DVWA or its database.
compose up -d --wait --force-recreate --no-deps falco

falco_id="$(compose ps -q falco)"
dvwa_id="$(compose ps -q dvwa)"
[[ -n "$falco_id" ]] || fail "Falco is not running"
[[ -n "$dvwa_id" ]] || fail "DVWA is not running"

falco_state="$(docker inspect --format '{{.State.Status}}' "$falco_id")"
falco_health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$falco_id")"
[[ "$falco_state" == running ]] || fail "Falco state is $falco_state"
[[ "$falco_health" == healthy ]] || fail "Falco health is $falco_health"

expected_image='docker.io/falcosecurity/falco:0.44.1-debian@sha256:85ad8559039c97f40d71f1491ef6a0d7c613f7ae9a530fea0a415a1644c09eb1'
[[ "$(docker inspect --format '{{.Config.Image}}' "$falco_id")" == "$expected_image" ]] || \
    fail 'Runtime Falco image is not the accepted digest'
[[ "$(docker inspect --format '{{.HostConfig.Privileged}}' "$falco_id")" == false ]] || \
    fail 'Falco unexpectedly runs privileged'
[[ "$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$falco_id")" == none ]] || \
    fail 'Falco unexpectedly has a container network'
[[ "$(docker inspect --format '{{.HostConfig.PidMode}}' "$falco_id")" == host ]] || \
    fail 'Falco does not observe the Linux host PID namespace'
[[ -z "$(docker port "$falco_id")" ]] || fail 'Falco unexpectedly publishes a port'

actual_caps="$(
    docker inspect --format '{{range .HostConfig.CapAdd}}{{println .}}{{end}}' "$falco_id" |
        tr -d '\r' | sed -e '/^$/d' -e 's/^CAP_//' | sort | paste -sd ',' -
)"
[[ "$actual_caps" == 'SYS_ADMIN,SYS_PTRACE,SYS_RESOURCE' ]] || \
    fail "Unexpected Falco capabilities: $actual_caps"

mounts="$(docker inspect --format '{{range .Mounts}}{{println .Destination "|" .RW}}{{end}}' "$falco_id" | tr -d '\r ')"
for mount in \
    '/sys/kernel/tracing|false' \
    '/host/var/run/docker.sock|false' \
    '/host/proc|false' \
    '/host/etc|false' \
    '/var/log/falco|true'; do
    grep -Fxq "$mount" <<<"$mounts" || fail "Falco mount contract missing: $mount"
done
[[ "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$falco_id")" == true ]] || \
    fail 'Falco root filesystem must be read-only'
[[ "$(docker inspect --format '{{json .HostConfig.CapDrop}}' "$falco_id")" == '["ALL"]' ]] || \
    fail 'Falco must drop all default capabilities'
pass "Falco is healthy, digest-pinned, non-privileged, unpublished, and bounded to its required host views"

compose exec -T falco sh -ec 'test -f /var/log/falco/events.jsonl'
pass "Falco native JSONL output file is present"

# Every probe executes only inside the isolated DVWA lab. A unique marker must
# appear in the native Falco event, so unrelated background activity cannot
# satisfy acceptance; no line is ever written into Falco's output.
run_marker="ahr_falco_$(date +%s)_$$_${RANDOM:-0}"

shell_marker="${run_marker}_shell"
offset="$(jsonl_line_count)"
compose exec -T dvwa sh -c ": $shell_marker"
wait_for_rule "$offset" 'AHR Shell Spawned Inside Web Container' "$shell_marker" || \
    fail "No real shell-spawn event observed"
pass "real shell spawn event observed"

child_marker="${run_marker}_child"
offset="$(jsonl_line_count)"
compose exec -T dvwa git -c "ahr.acceptance=$child_marker" --version >/dev/null
wait_for_rule "$offset" 'AHR Unexpected Child Process In Web Container' "$child_marker" || \
    fail "No real unexpected-child event observed"
pass "real unexpected child process event observed"

exec_marker="${run_marker}_exec"
offset="$(jsonl_line_count)"
compose exec -T dvwa sh -c "cp /bin/echo /tmp/$exec_marker && chmod 0700 /tmp/$exec_marker && /tmp/$exec_marker acceptance >/dev/null; rm -f /tmp/$exec_marker"
wait_for_rule "$offset" 'AHR Suspicious Executable In Web Container' "$exec_marker" || \
    fail "No real suspicious-executable event observed"
pass "real suspicious executable event observed"

write_marker="${run_marker}_write"
offset="$(jsonl_line_count)"
compose exec -T dvwa sh -c ": > /etc/$write_marker && rm -f /etc/$write_marker"
wait_for_rule "$offset" 'AHR Sensitive Path Write In Web Container' "$write_marker" || \
    fail "No real sensitive-write event observed"
pass "real sensitive path write event observed"

# 3306 is the lab MariaDB endpoint. The shell redirection opens a TCP socket
# without sending a query and cannot reach an external target.
network_marker="${run_marker}_network"
offset="$(jsonl_line_count)"
compose exec -T dvwa php -r '$s=@fsockopen("mariadb",3306,$e,$m,2); if (!$s) { exit(1); } fclose($s);' "$network_marker"
wait_for_rule "$offset" 'AHR Unexpected Outbound Connection From Web Container' "$network_marker" || \
    fail "No real outbound-connection event observed"
pass "real lab-internal outbound connection event observed"

priv_marker="${run_marker}_priv"
offset="$(jsonl_line_count)"
compose exec -T dvwa sh -c "cp /bin/true /tmp/$priv_marker && chmod 04700 /tmp/$priv_marker && chmod 0700 /tmp/$priv_marker && rm -f /tmp/$priv_marker"
wait_for_rule "$offset" 'AHR Privilege Activity In Web Container' "$priv_marker" || \
    fail "No real privilege-activity event observed"
pass "real privilege activity event observed"

validate_jsonl >/dev/null || fail "Falco JSONL output is malformed"

pass "Falco runtime acceptance complete; all alerts came from controlled syscalls"
