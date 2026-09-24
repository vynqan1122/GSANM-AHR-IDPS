#!/usr/bin/env bash

if [[ -z "${BASH_VERSION:-}" ]]; then
    echo "AHR-IDPS lifecycle scripts require Bash." >&2
    return 1 2>/dev/null || exit 1
fi

set -Eeuo pipefail

if [[ -z "${AHR_PROJECT_ROOT:-}" ]]; then
    AHR_COMMON_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
    AHR_PROJECT_ROOT="$(CDPATH= cd -- "$AHR_COMMON_DIR/../.." && pwd -P)"
fi

AHR_ENV_FILE="${AHR_ENV_FILE:-$AHR_PROJECT_ROOT/.env}"
AHR_ENV_EXAMPLE="$AHR_PROJECT_ROOT/.env.example"

ahr_info() {
    printf '[AHR-IDPS] %s\n' "$*"
}

ahr_warn() {
    printf '[AHR-IDPS] WARNING: %s\n' "$*" >&2
}

ahr_die() {
    printf '[AHR-IDPS] ERROR: %s\n' "$*" >&2
    exit 1
}

ahr_require_command() {
    command -v "$1" >/dev/null 2>&1 || ahr_die "Required command not found: $1"
}

ahr_env_value() {
    local key="$1"
    awk -v wanted="$key" '
        index($0, wanted "=") == 1 {
            sub(/^[^=]*=/, "")
            sub(/\r$/, "")
            print
            exit
        }
    ' "$AHR_ENV_FILE"
}

ahr_random_secret() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 24
        return
    fi

    if [[ -r /dev/urandom ]] && command -v od >/dev/null 2>&1; then
        od -An -N24 -tx1 /dev/urandom | tr -d ' \n'
        return
    fi

    ahr_die "Cannot generate secrets: install openssl or provide /dev/urandom and od"
}

ahr_replace_env_value() {
    local key="$1"
    local value="$2"
    local temporary
    temporary="$(mktemp "${AHR_ENV_FILE}.tmp.XXXXXX")"

    awk -v wanted="$key" -v replacement="$value" '
        index($0, wanted "=") == 1 {
            print wanted "=" replacement
            found = 1
            next
        }
        { print }
        END {
            if (!found) {
                print wanted "=" replacement
            }
        }
    ' "$AHR_ENV_FILE" > "$temporary"

    mv -- "$temporary" "$AHR_ENV_FILE"
}

ahr_prepare_env() {
    [[ -f "$AHR_ENV_EXAMPLE" ]] || ahr_die "Missing $AHR_ENV_EXAMPLE"

    if [[ ! -f "$AHR_ENV_FILE" ]]; then
        umask 077
        cp -- "$AHR_ENV_EXAMPLE" "$AHR_ENV_FILE"
        ahr_info "Created $AHR_ENV_FILE from .env.example"
    fi

    local key current
    local secret_keys=(
        DVWA_DB_PASSWORD
        MARIADB_ROOT_PASSWORD
        POSTGRES_SUPERUSER_PASSWORD
        AHR_DB_PASSWORD
        REDIS_PASSWORD
    )

    for key in "${secret_keys[@]}"; do
        current="$(ahr_env_value "$key")"
        if [[ "$current" == CHANGE_ME_* ]]; then
            ahr_replace_env_value "$key" "$(ahr_random_secret)"
        fi
    done

    chmod 600 "$AHR_ENV_FILE" 2>/dev/null || true
    ahr_validate_env
}

ahr_validate_env() {
    local key value
    local required_keys=(
        COMPOSE_PROJECT_NAME
        LAB_HTTP_PORT
        NGINX_IMAGE
        DVWA_IMAGE
        MARIADB_IMAGE
        POSTGRES_IMAGE
        REDIS_IMAGE
        DVWA_DB_NAME
        DVWA_DB_USER
        DVWA_DB_PASSWORD
        MARIADB_ROOT_PASSWORD
        POSTGRES_DB
        POSTGRES_SUPERUSER
        POSTGRES_SUPERUSER_PASSWORD
        AHR_DB_USER
        AHR_DB_PASSWORD
        REDIS_PASSWORD
    )

    for key in "${required_keys[@]}"; do
        value="$(ahr_env_value "$key")"
        [[ -n "$value" ]] || ahr_die "$key is empty in $AHR_ENV_FILE"
        [[ "$value" != CHANGE_ME_* ]] || ahr_die "$key still contains a CHANGE_ME value"
    done

    local port
    port="$(ahr_env_value LAB_HTTP_PORT)"
    [[ "$port" =~ ^[0-9]+$ ]] || ahr_die "LAB_HTTP_PORT must be numeric"
    (( 10#$port >= 1024 && 10#$port <= 65535 )) || \
        ahr_die "LAB_HTTP_PORT must be between 1024 and 65535"

    for key in DVWA_DB_NAME DVWA_DB_USER POSTGRES_DB POSTGRES_SUPERUSER AHR_DB_USER; do
        value="$(ahr_env_value "$key")"
        [[ "$value" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || \
            ahr_die "$key must start with a letter or underscore and contain only letters, digits, and underscores"
    done

    [[ "$(ahr_env_value DVWA_DB_USER)" != root ]] || \
        ahr_die "DVWA_DB_USER must not be root"
    [[ "$(ahr_env_value AHR_DB_USER)" != "$(ahr_env_value POSTGRES_SUPERUSER)" ]] || \
        ahr_die "AHR_DB_USER must differ from POSTGRES_SUPERUSER"

    local allow_legacy_secrets="$(ahr_env_value AHR_ALLOW_LEGACY_LAB_SECRETS 2>/dev/null || true)"
    for key in DVWA_DB_PASSWORD MARIADB_ROOT_PASSWORD POSTGRES_SUPERUSER_PASSWORD AHR_DB_PASSWORD REDIS_PASSWORD; do
        value="$(ahr_env_value "$key")"
        if (( ${#value} < 24 )); then
            [[ "$allow_legacy_secrets" == true && ${#value} -ge 8 ]] || \
                ahr_die "$key must contain at least 24 characters"
            ahr_warn "$key uses a legacy short lab secret; rotate with scripts/rotate_lab_secrets.sh"
        fi
        [[ "$value" =~ ^[A-Za-z0-9._~-]+$ ]] || \
            ahr_die "$key may contain only letters, digits, dot, underscore, tilde, and hyphen"
    done
}

ahr_compose() {
    docker compose \
        --project-directory "$AHR_PROJECT_ROOT" \
        --env-file "$AHR_ENV_FILE" \
        "$@"
}

ahr_validate_compose() {
    ahr_require_command docker
    ahr_compose config --quiet
}

ahr_retry() {
    local attempts="$1"
    local delay_seconds="$2"
    shift 2

    local attempt=1
    until "$@"; do
        if (( attempt >= attempts )); then
            return 1
        fi

        ahr_warn "Command failed (attempt ${attempt}/${attempts}); retrying in ${delay_seconds}s."
        sleep "$delay_seconds"
        attempt=$((attempt + 1))
    done
}

ahr_check_docker_engine() {
    ahr_check_docker_engine_reachable

    local os_type server_version major
    os_type="$(docker info --format '{{.OSType}}')"
    [[ "$os_type" == linux ]] || ahr_die "AHR-IDPS requires Docker Linux containers; daemon reports '$os_type'"

    server_version="$(docker version --format '{{.Server.Version}}')"
    major="${server_version%%.*}"
    [[ "$major" =~ ^[0-9]+$ ]] || ahr_die "Cannot parse Docker Engine version: $server_version"
    (( major >= 28 )) || \
        ahr_die "Docker Engine 28+ is required for safe localhost port publishing; found $server_version"
}

ahr_check_docker_engine_reachable() {
    ahr_require_command docker

    if ! docker info >/dev/null 2>&1; then
        ahr_die "Docker Engine is not reachable. Start Docker Desktop or the Docker daemon and try again."
    fi
}
