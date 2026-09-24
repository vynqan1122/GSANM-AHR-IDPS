#!/usr/bin/env bash

# shellcheck source=scripts/lib/pipeline.sh
source "$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/pipeline.sh"

AHR_APP_FRAGMENT="$AHR_PROJECT_ROOT/app/compose.fragment.yml"

ahr_require_app_files() {
    ahr_require_pipeline_files
    [[ -f "$AHR_APP_FRAGMENT" ]] || \
        ahr_die "Missing Phase 4 Compose fragment: $AHR_APP_FRAGMENT"
    [[ -f "$AHR_PROJECT_ROOT/backend/main.py" ]] || \
        ahr_die "Missing Phase 4 backend application"
    [[ -f "$AHR_PROJECT_ROOT/dashboard/dist/index.html" ]] || \
        ahr_die "Missing Phase 4 dashboard distribution"
    [[ -f "$AHR_PROJECT_ROOT/infrastructure/nginx/nginx.phase4.conf" ]] || \
        ahr_die "Missing Phase 4 Nginx config"
}

ahr_app_compose() {
    ahr_require_app_files
    COMPOSE_IGNORE_ORPHANS=true docker compose \
        --project-directory "$AHR_PROJECT_ROOT" \
        --env-file "$AHR_ENV_FILE" \
        -f "$AHR_PROJECT_ROOT/docker-compose.yml" \
        -f "$AHR_SURICATA_FRAGMENT" \
        -f "$AHR_FALCO_FRAGMENT" \
        -f "$AHR_WAZUH_FRAGMENT" \
        -f "$AHR_PIPELINE_FRAGMENT" \
        -f "$AHR_APP_FRAGMENT" \
        "$@"
}

ahr_require_phase3_healthy() {
    ahr_require_phase2_healthy

    local service id state health
    for service in collector normalizer; do
        id="$(ahr_app_compose ps -q "$service")"
        [[ -n "$id" ]] || \
            ahr_die "Phase 3 service '$service' is not running; run scripts/start_pipeline.sh first"
        state="$(docker inspect --format '{{.State.Status}}' "$id")"
        health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$id")"
        [[ "$state" == running && "$health" == healthy ]] || \
            ahr_die "Phase 3 service '$service' is $state/$health; repair Phase 3 before starting Phase 4"
    done
}
