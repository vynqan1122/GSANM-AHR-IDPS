#!/usr/bin/env bash
set -Eeuo pipefail
set +x

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
AHR_PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
export AHR_PROJECT_ROOT

# shellcheck source=scripts/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

umask 077
stage=''
diagnostic=''
mutation_started=no

cleanup() {
    local status=$?
    if [[ -n "$diagnostic" && -f "$diagnostic" ]]; then
        rm -f -- "$diagnostic"
    fi
    if [[ -n "$stage" && -f "$stage" ]]; then
        if [[ "$mutation_started" == no ]]; then
            rm -f -- "$stage"
        elif (( status != 0 )); then
            ahr_warn "Rotation stopped after database mutation began. Recovery environment retained at: $stage"
            ahr_warn 'Do not delete it until database credentials and .env are reconciled.'
        fi
    fi
    return "$status"
}
trap cleanup EXIT

ahr_prepare_env
ahr_check_docker_engine

for service in mariadb postgres redis dvwa nginx; do
    id="$(ahr_compose ps -q "$service")"
    [[ -n "$id" ]] || ahr_die "Phase 1 service is not running: $service"
    state="$(docker inspect --format '{{.State.Status}}' "$id")"
    health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$id")"
    [[ "$state" == running && "$health" == healthy ]] || \
        ahr_die "Phase 1 service is not healthy: $service ($state/$health)"
done

dvwa_user="$(ahr_env_value DVWA_DB_USER)"
pg_admin="$(ahr_env_value POSTGRES_SUPERUSER)"
pg_app="$(ahr_env_value AHR_DB_USER)"

# Verify exact principals before issuing MariaDB's multi-account ALTER USER.
maria_accounts="$(ahr_compose exec -T mariadb sh -ec '
    MYSQL_PWD="$MARIADB_ROOT_PASSWORD" mariadb --protocol=socket --user=root \
      --batch --skip-column-names --execute="SELECT CONCAT(User, 0x40, Host) FROM mysql.user ORDER BY User,Host;"
' | tr -d '\r')"
for required_account in "${dvwa_user}@%" 'root@%' 'root@localhost'; do
    grep -Fxq "$required_account" <<<"$maria_accounts" || \
        ahr_die 'MariaDB principal preflight failed; no credentials were changed.'
done

pg_roles="$(ahr_compose exec -T postgres sh -ec '
    PGPASSWORD="$POSTGRES_PASSWORD" psql --host=127.0.0.1 \
      --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" \
      --tuples-only --no-align --command="SELECT rolname FROM pg_roles ORDER BY rolname;"
' 2>/dev/null | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | tr -d '\r')"
for required_role in "$pg_admin" "$pg_app"; do
    grep -Fxq "$required_role" <<<"$pg_roles" || \
        ahr_die 'PostgreSQL role preflight failed; no credentials were changed.'
done

new_dvwa="$(ahr_random_secret)"
new_maria_root="$(ahr_random_secret)"
new_pg_admin="$(ahr_random_secret)"
new_pg_app="$(ahr_random_secret)"
new_redis="$(ahr_random_secret)"

stage="$(mktemp "$AHR_PROJECT_ROOT/.env.next.XXXXXX")"
chmod 600 "$stage" 2>/dev/null || true
cp -- "$AHR_ENV_FILE" "$stage"

original_env_file="$AHR_ENV_FILE"
AHR_ENV_FILE="$stage"
ahr_replace_env_value DVWA_DB_PASSWORD "$new_dvwa"
ahr_replace_env_value MARIADB_ROOT_PASSWORD "$new_maria_root"
ahr_replace_env_value POSTGRES_SUPERUSER_PASSWORD "$new_pg_admin"
ahr_replace_env_value AHR_DB_PASSWORD "$new_pg_app"
ahr_replace_env_value REDIS_PASSWORD "$new_redis"
ahr_validate_env
AHR_ENV_FILE="$original_env_file"

diagnostic="$(mktemp "$AHR_PROJECT_ROOT/.rotate-diagnostic.XXXXXX")"
chmod 600 "$diagnostic" 2>/dev/null || true
mutation_started=yes

maria_sql="ALTER USER 'root'@'localhost' IDENTIFIED BY '$new_maria_root', 'root'@'%' IDENTIFIED BY '$new_maria_root', '$dvwa_user'@'%' IDENTIFIED BY '$new_dvwa';"
if ! printf '%s\n' "$maria_sql" | ahr_compose exec -T mariadb sh -ec '
    MYSQL_PWD="$MARIADB_ROOT_PASSWORD" exec mariadb --protocol=socket --user=root --batch --skip-column-names
' >"$diagnostic" 2>&1; then
    rm -f -- "$diagnostic"
    ahr_die 'MariaDB credential rotation failed; private recovery environment was retained.'
fi

pg_sql="SET password_encryption='scram-sha-256'; BEGIN; ALTER ROLE \"$pg_admin\" PASSWORD '$new_pg_admin'; ALTER ROLE \"$pg_app\" PASSWORD '$new_pg_app'; COMMIT;"
if ! printf '%s\n' "$pg_sql" | ahr_compose exec -T postgres sh -ec '
    PGPASSWORD="$POSTGRES_PASSWORD" exec psql --host=127.0.0.1 \
      --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" \
      --set=ON_ERROR_STOP=1 --quiet
' >"$diagnostic" 2>&1; then
    rm -f -- "$diagnostic"
    ahr_die 'PostgreSQL credential rotation failed; private recovery environment was retained.'
fi
rm -f -- "$diagnostic"
diagnostic=''

mv -- "$stage" "$AHR_ENV_FILE"
stage=''
chmod 600 "$AHR_ENV_FILE" 2>/dev/null || true

unset maria_sql pg_sql new_dvwa new_maria_root new_pg_admin new_pg_app new_redis

ahr_info 'Recreating credential-consuming services without deleting persistent volumes...'
if ! ahr_compose up --detach --force-recreate --wait --wait-timeout 300 \
    mariadb postgres redis dvwa; then
    ahr_compose ps --all || true
    ahr_die 'Services did not become healthy after rotation; .env contains the new credentials.'
fi

bash "$SCRIPT_DIR/verify_phase1.sh"
ahr_info 'All five local lab secrets were rotated and Phase 1 acceptance passed.'
