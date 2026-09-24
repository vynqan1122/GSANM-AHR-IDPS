#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
AHR_PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
export AHR_PROJECT_ROOT

# shellcheck source=scripts/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

mode=full
case "${1:-}" in
    '') ;;
    --static-only) mode=static ;;
    -h|--help)
        printf 'Usage: ./scripts/verify_phase1.sh [--static-only]\n'
        exit 0
        ;;
    *)
        printf 'Unknown option: %s\n' "$1" >&2
        exit 2
        ;;
esac

pass() {
    printf '[PASS] %s\n' "$*"
}

fail() {
    printf '[FAIL] %s\n' "$*" >&2
    exit 1
}

assert_file() {
    [[ -f "$AHR_PROJECT_ROOT/$1" ]] || fail "Missing required file: $1"
}

network_labels_for_service() {
    local service="$1"
    local container_id network_id
    container_id="$(ahr_compose ps -q "$service")"
    [[ -n "$container_id" ]] || fail "No container found for $service"

    while IFS= read -r network_id; do
        [[ -n "$network_id" ]] || continue
        docker network inspect \
            --format '{{index .Labels "com.docker.compose.network"}}' \
            "$network_id"
    done < <(
        docker inspect \
            --format '{{range .NetworkSettings.Networks}}{{println .NetworkID}}{{end}}' \
            "$container_id"
    ) | sort
}

assert_networks() {
    local service="$1"
    local expected="$2"
    local actual
    actual="$(network_labels_for_service "$service" | paste -sd ',' -)"
    [[ "$actual" == "$expected" ]] || \
        fail "$service networks are '$actual'; expected '$expected'"
}

assert_networks_with_allowed_extra() {
    local service="$1"
    local required_csv="$2"
    local allowed_extra_csv="$3"
    local actual required allowed network
    actual="$(network_labels_for_service "$service" | paste -sd ',' -)"
    IFS=',' read -r -a required <<<"$required_csv"
    IFS=',' read -r -a allowed <<<"${required_csv},${allowed_extra_csv}"

    for network in "${required[@]}"; do
        grep -Eq "(^|,)${network}(,|$)" <<<"$actual" || \
            fail "$service networks are '$actual'; missing required network '$network'"
    done
    IFS=',' read -r -a actual_networks <<<"$actual"
    for network in "${actual_networks[@]}"; do
        [[ -z "$network" ]] && continue
        local ok=no
        local allowed_network
        for allowed_network in "${allowed[@]}"; do
            [[ "$network" == "$allowed_network" ]] && ok=yes
        done
        [[ "$ok" == yes ]] || \
            fail "$service networks are '$actual'; unexpected network '$network'"
    done
}

cd "$AHR_PROJECT_ROOT"
ahr_prepare_env

for required_file in \
    docker-compose.yml \
    .env.example \
    Makefile \
    README.md \
    infrastructure/nginx/nginx.conf \
    infrastructure/mariadb/conf.d/ahr.cnf \
    infrastructure/postgres/init/01-init-ahr.sh \
    infrastructure/redis/redis.conf \
    infrastructure/redis/redis-entrypoint.sh \
    scripts/start_lab.sh \
    scripts/stop_lab.sh; do
    assert_file "$required_file"
done
pass "required Phase 1 files exist"

bash -n scripts/lib/common.sh scripts/start_lab.sh scripts/stop_lab.sh \
    scripts/init_dvwa.sh scripts/verify_phase1.sh
pass "Bash lifecycle scripts parse cleanly"

ahr_validate_compose
pass "Docker Compose configuration is valid"

actual_services="$(ahr_compose config --services | sort | paste -sd ',' -)"
expected_services='dvwa,mariadb,nginx,postgres,redis'
[[ "$actual_services" == "$expected_services" ]] || \
    fail "Compose services are '$actual_services'; expected '$expected_services'"
pass "Compose defines the five Phase 1 services"

effective_config="$(ahr_compose config)"
published_count="$(grep -c 'published:' <<<"$effective_config" || true)"
loopback_count="$(grep -c 'host_ip: 127.0.0.1' <<<"$effective_config" || true)"
healthcheck_count="$(grep -c '^    healthcheck:' <<<"$effective_config" || true)"
internal_network_count="$(grep -c '^    internal: true' <<<"$effective_config" || true)"

[[ "$published_count" == 1 ]] || fail "Expected one published port; found $published_count"
[[ "$loopback_count" == 1 ]] || fail "Expected one 127.0.0.1 binding; found $loopback_count"
[[ "$healthcheck_count" == 5 ]] || fail "Expected five health checks; found $healthcheck_count"
[[ "$internal_network_count" == 3 ]] || \
    fail "Expected three internal networks; found $internal_network_count"
! grep -q 'network_mode: host' <<<"$effective_config" || fail "Host networking is forbidden"
! grep -q 'DISABLE_AUTHENTICATION' <<<"$effective_config" || \
    fail "DVWA authentication override must remain unset"
pass "static exposure, health-check, and internal-network policy"

if [[ "$mode" == static ]]; then
    pass "Phase 1 static acceptance suite complete"
    exit 0
fi

ahr_check_docker_engine

for service in mariadb dvwa nginx postgres redis; do
    container_id="$(ahr_compose ps -q "$service")"
    [[ -n "$container_id" ]] || fail "$service is not running"
    state="$(docker inspect --format '{{.State.Status}}' "$container_id")"
    health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$container_id")"
    [[ "$state" == running ]] || fail "$service state is $state"
    [[ "$health" == healthy ]] || fail "$service health is $health"
done
pass "all five services are running and healthy"

binding_lines=0
for service in mariadb dvwa nginx postgres redis; do
    container_id="$(ahr_compose ps -q "$service")"
    bindings="$(docker port "$container_id" 2>/dev/null || true)"
    if [[ "$service" == nginx ]]; then
        [[ "$bindings" =~ ^80/tcp[[:space:]]+\-\>[[:space:]]+127\.0\.0\.1:[0-9]+$ ]] || \
            fail "Unexpected Nginx binding: $bindings"
        binding_lines=$((binding_lines + 1))
    elif [[ -n "$bindings" ]]; then
        fail "$service unexpectedly publishes a host port: $bindings"
    fi
done
[[ "$binding_lines" == 1 ]] || fail "Expected exactly one Phase 1 runtime port binding"
pass "only the Phase 1 Nginx service is published, on host loopback"

assert_networks_with_allowed_extra nginx 'dvwa_front,ingress' 'app_front'
assert_networks dvwa 'dvwa_db,dvwa_front'
assert_networks mariadb 'dvwa_db'
assert_networks postgres 'data'
assert_networks redis 'data'

project_name="$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$(ahr_compose ps -q nginx)")"
core_networks_seen=''
while IFS='|' read -r logical_name internal driver; do
    case "$logical_name" in
        ingress)
            [[ "$driver" == bridge ]] || fail "ingress uses unexpected network driver $driver"
            [[ "$internal" == false ]] || fail "ingress must not be internal"
            core_networks_seen="${core_networks_seen} ingress"
            ;;
        data|dvwa_db|dvwa_front)
            [[ "$driver" == bridge ]] || fail "$logical_name uses unexpected network driver $driver"
            [[ "$internal" == true ]] || fail "$logical_name must be internal"
            core_networks_seen="${core_networks_seen} ${logical_name}"
            ;;
        *)
            # Later phases may add project-scoped networks. Exact service
            # membership assertions above ensure no Phase 1 container joins
            # them, so they are outside this regression gate's ownership.
            continue
            ;;
    esac
done < <(
    docker network ls \
        --filter "label=com.docker.compose.project=$project_name" \
        --format '{{.ID}}' | while IFS= read -r network_id; do
            docker network inspect \
                --format '{{index .Labels "com.docker.compose.network"}}|{{.Internal}}|{{.Driver}}' \
                "$network_id"
        done
)
for required_network in ingress data dvwa_db dvwa_front; do
    grep -Eq "(^|[[:space:]])${required_network}([[:space:]]|$)" <<<"$core_networks_seen" || \
        fail "Required Phase 1 network is missing: $required_network"
done
pass "runtime network membership and isolation policy"

lab_port="$(ahr_env_value LAB_HTTP_PORT)"
health_body="$(curl --noproxy '*' --fail --silent --show-error "http://127.0.0.1:${lab_port}/healthz")"
grep -q '"status":"ok"' <<<"$health_body" || fail "Nginx health endpoint returned unexpected content"

login_probe="$(
    curl --noproxy '*' --fail --silent --show-error --location \
        --write-out $'\n%{url_effective}' \
        "http://127.0.0.1:${lab_port}/"
)"
page_body="${login_probe%$'\n'*}"
effective_url="${login_probe##*$'\n'}"
grep -Eqi 'DVWA|Damn Vulnerable Web Application' <<<"$page_body" || \
    fail "DVWA content was not found through Nginx"
[[ "$effective_url" == */login.php ]] || \
    fail "Unauthenticated DVWA request did not end at login.php: $effective_url"
grep -Eqi "name=[\"']username[\"']|Username" <<<"$page_body" || \
    fail "DVWA login form was not present for an unauthenticated request"

probe="ahr_phase1_$(date +%s)_$$"
curl --noproxy '*' --fail --silent --show-error --location \
    "http://127.0.0.1:${lab_port}/?ahr_probe=${probe}" >/dev/null
nginx_recent_logs="$(ahr_compose logs --no-color --since 1m nginx)"
grep -q "$probe" <<<"$nginx_recent_logs" || \
    fail "Nginx logs did not contain the HTTP probe"
pass "Nginx health, DVWA proxy, and real access logging"

mariadb_result="$(ahr_compose exec -T mariadb sh -ec '
    mariadb --protocol=tcp --host=127.0.0.1 \
      --user="$MARIADB_USER" --password="$MARIADB_PASSWORD" \
      --database="$MARIADB_DATABASE" --batch --skip-column-names \
      --execute="SELECT 1;"
' | tr -d '\r[:space:]')"
[[ "$mariadb_result" == 1 ]] || fail "MariaDB DVWA-user query failed"

postgres_result="$(ahr_compose exec -T postgres sh -ec '
    PGPASSWORD="$AHR_DB_PASSWORD" psql --host=127.0.0.1 \
      --username="$AHR_DB_USER" --dbname="$POSTGRES_DB" \
      --tuples-only --no-align --command="SELECT 1;"
' | tr -d '\r[:space:]')"
[[ "$postgres_result" == 1 ]] || fail "PostgreSQL application-role query failed"

redis_result="$(ahr_compose exec -T redis sh -ec '
    unauthenticated="$(redis-cli ping 2>&1 || true)"
    case "$unauthenticated" in
      *"NOAUTH Authentication required"*) ;;
      *) echo "UNAUTHENTICATED_ACCESS_NOT_DENIED"; exit 1 ;;
    esac
    REDISCLI_AUTH="$REDIS_PASSWORD" redis-cli --no-auth-warning ping 2>/dev/null
' | tr -d '\r[:space:]')"
[[ "$redis_result" == PONG ]] || fail "Authenticated Redis PING failed"

dvwa_table_count="$(ahr_compose exec -T mariadb sh -ec '
    mariadb --protocol=tcp --host=127.0.0.1 \
      --user="$MARIADB_USER" --password="$MARIADB_PASSWORD" \
      --database="$MARIADB_DATABASE" --batch --skip-column-names \
      --execute="SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name IN (0x7573657273, 0x6775657374626f6f6b);"
' | tr -d '\r[:space:]')"
[[ "$dvwa_table_count" == 2 ]] || fail "DVWA schema is not initialized"

postgres_role_flags="$(ahr_compose exec -T postgres sh -ec '
    PGPASSWORD="$POSTGRES_PASSWORD" psql --host=127.0.0.1 \
      --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" \
      --tuples-only --no-align \
      --command="SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls FROM pg_roles WHERE rolname = '\''$AHR_DB_USER'\'';"
' | tr -d '\r[:space:]')"
[[ "$postgres_role_flags" == 'f|f|f|f|f' ]] || \
    fail "PostgreSQL application role is absent or over-privileged: $postgres_role_flags"
pass "MariaDB, PostgreSQL, and Redis functional probes"

dns_isolated="$(ahr_compose exec -T dvwa php -r '
    $ok = gethostbyname("postgres") === "postgres" && gethostbyname("redis") === "redis";
    echo $ok ? "yes" : "no";
' | tr -d '\r[:space:]')"
[[ "$dns_isolated" == yes ]] || fail "DVWA can resolve a platform data service"
pass "DVWA cannot resolve PostgreSQL or Redis"

pass "Phase 1 runtime acceptance suite complete"
