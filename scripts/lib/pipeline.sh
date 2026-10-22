#!/usr/bin/env bash

# shellcheck source=scripts/lib/sensors.sh
source "$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/sensors.sh"

AHR_PIPELINE_FRAGMENT="$AHR_PROJECT_ROOT/pipeline/compose.fragment.yml"

ahr_require_pipeline_files() {
    ahr_require_sensor_files
    [[ -f "$AHR_PIPELINE_FRAGMENT" ]] || \
        ahr_die "Missing Phase 3 Compose fragment: $AHR_PIPELINE_FRAGMENT"
}

# Resolve every Phase 1-3 service through one deterministic Compose model.
# Keeping this in one helper prevents lifecycle and acceptance scripts from
# accidentally addressing similarly named containers in another project.
ahr_pipeline_compose() {
    ahr_require_pipeline_files
    COMPOSE_IGNORE_ORPHANS=true docker compose \
        --project-directory "$AHR_PROJECT_ROOT" \
        --env-file "$AHR_ENV_FILE" \
        -f "$AHR_PROJECT_ROOT/docker-compose.yml" \
        -f "$AHR_SURICATA_FRAGMENT" \
        -f "$AHR_FALCO_FRAGMENT" \
        -f "$AHR_WAZUH_FRAGMENT" \
        -f "$AHR_PIPELINE_FRAGMENT" \
        "$@"
}

ahr_require_phase2_healthy() {
    ahr_require_phase1_healthy

    local service id state health
    for service in suricata falco wazuh-manager; do
        id="$(ahr_pipeline_compose ps -q "$service")"
        [[ -n "$id" ]] || \
            ahr_die "Phase 2 service '$service' is not running; run scripts/start_sensors.sh first"
        for _ in $(seq 1 30); do
            state="$(docker inspect --format '{{.State.Status}}' "$id")"
            health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$id")"
            if [[ "$state" == running && "$health" == healthy ]]; then
                break
            fi
            sleep 1
        done
        [[ "$state" == running && "$health" == healthy ]] || \
            ahr_die "Phase 2 service '$service' is $state/$health; repair Phase 2 before starting the pipeline"
    done
}

# Print only one service from an already-rendered Compose document supplied on
# stdin. The function deliberately stops before top-level networks/volumes too.
ahr_compose_service_section() {
    local wanted="$1"
    awk -v wanted="$wanted" '
        $0 == "  " wanted ":" { in_service=1 }
        in_service && seen && /^  [A-Za-z0-9_.-]+:$/ { exit }
        in_service { print; seen=1 }
    '
}
