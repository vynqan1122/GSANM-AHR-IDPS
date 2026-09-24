#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
AHR_PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
export AHR_PROJECT_ROOT

# shellcheck source=scripts/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

cd "$AHR_PROJECT_ROOT"
ahr_prepare_env
ahr_validate_compose
ahr_check_docker_engine

dvwa_table_count() {
    ahr_compose exec -T mariadb sh -ec '
        mariadb \
          --protocol=tcp \
          --host=127.0.0.1 \
          --user="$MARIADB_USER" \
          --password="$MARIADB_PASSWORD" \
          --database="$MARIADB_DATABASE" \
          --batch \
          --skip-column-names \
          --execute="SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name IN (0x7573657273, 0x6775657374626f6f6b);"
    ' | tr -d '\r[:space:]'
}

if ! initial_table_count="$(dvwa_table_count)"; then
    ahr_die "Cannot inspect the DVWA schema; refusing to call the destructive setup endpoint"
fi
[[ "$initial_table_count" =~ ^[0-9]+$ ]] || \
    ahr_die "DVWA schema probe returned an invalid table count; refusing to reset"

if [[ "$initial_table_count" == 2 ]]; then
    ahr_info "DVWA database is already initialized; no reset was performed."
    exit 0
fi

ahr_require_command curl

temporary_dir="$(mktemp -d "${TMPDIR:-/tmp}/ahr-dvwa-init.XXXXXX")"
cleanup() {
    case "$temporary_dir" in
        "${TMPDIR:-/tmp}"/ahr-dvwa-init.*) rm -rf -- "$temporary_dir" ;;
        *) ahr_warn "Refusing to remove unexpected temporary path: $temporary_dir" ;;
    esac
}
trap cleanup EXIT

lab_port="$(ahr_env_value LAB_HTTP_PORT)"
base_url="http://127.0.0.1:${lab_port}"
cookie_jar="$temporary_dir/cookies.txt"
setup_page="$temporary_dir/setup.html"
setup_result="$temporary_dir/result.html"

ahr_info "Initializing the DVWA schema through its local setup endpoint..."
curl --noproxy '*' --fail --silent --show-error --location \
    --cookie-jar "$cookie_jar" \
    "$base_url/setup.php" \
    --output "$setup_page"

user_token="$(
    sed -n "s/.*name=['\"]user_token['\"][^>]*value=['\"]\([^'\"]*\)['\"].*/\1/p" \
        "$setup_page" | head -n 1
)"
[[ -n "$user_token" ]] || ahr_die "DVWA setup page did not contain an anti-CSRF token"

curl --noproxy '*' --fail --silent --show-error --location \
    --cookie "$cookie_jar" \
    --cookie-jar "$cookie_jar" \
    --data-urlencode "create_db=Create / Reset Database" \
    --data-urlencode "user_token=$user_token" \
    "$base_url/setup.php" \
    --output "$setup_result"

if ! final_table_count="$(dvwa_table_count)"; then
    ahr_die "Cannot verify the DVWA schema after setup"
fi
if [[ "$final_table_count" != 2 ]]; then
    ahr_die "DVWA setup completed without creating the expected users and guestbook tables"
fi

ahr_info "DVWA database initialized successfully."
