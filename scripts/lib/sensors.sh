#!/usr/bin/env bash

# shellcheck source=scripts/lib/common.sh
source "$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/common.sh"

AHR_SURICATA_FRAGMENT="$AHR_PROJECT_ROOT/sensors/suricata/compose.fragment.yml"
AHR_FALCO_FRAGMENT="$AHR_PROJECT_ROOT/sensors/falco/compose.fragment.yml"
AHR_WAZUH_FRAGMENT="$AHR_PROJECT_ROOT/sensors/wazuh/compose.fragment.yml"

ahr_require_sensor_files() {
    local path
    for path in \
        "$AHR_SURICATA_FRAGMENT" \
        "$AHR_FALCO_FRAGMENT" \
        "$AHR_WAZUH_FRAGMENT"; do
        [[ -f "$path" ]] || ahr_die "Missing Phase 2 Compose fragment: $path"
    done
}

ahr_sensors_compose() {
    ahr_require_sensor_files
    COMPOSE_IGNORE_ORPHANS=true docker compose \
        --project-directory "$AHR_PROJECT_ROOT" \
        --env-file "$AHR_ENV_FILE" \
        -f "$AHR_PROJECT_ROOT/docker-compose.yml" \
        -f "$AHR_SURICATA_FRAGMENT" \
        -f "$AHR_FALCO_FRAGMENT" \
        -f "$AHR_WAZUH_FRAGMENT" \
        "$@"
}

ahr_require_phase1_healthy() {
    local service id state health
    for service in nginx dvwa mariadb postgres redis; do
        id="$(ahr_compose ps -q "$service")"
        [[ -n "$id" ]] || ahr_die "Phase 1 service '$service' is not running; run scripts/start_lab.sh first"
        state="$(docker inspect --format '{{.State.Status}}' "$id")"
        health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$id")"
        [[ "$state" == running && "$health" == healthy ]] || \
            ahr_die "Phase 1 service '$service' is $state/$health; repair Phase 1 before starting sensors"
    done
}
