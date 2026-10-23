#!/usr/bin/env bash

# shellcheck source=scripts/lib/app.sh
source "$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/app.sh"

AHR_AI_FRAGMENT="$AHR_PROJECT_ROOT/ai/compose.fragment.yml"

# Same precedence as Compose: shell COMPOSE_PROJECT_NAME, then the env file.
# Avoids python3, which is only a Microsoft Store stub under Git Bash.
ahr_compose_project_name() {
    printf '%s\n' "${COMPOSE_PROJECT_NAME:-$(ahr_env_value COMPOSE_PROJECT_NAME)}"
}

ahr_require_legacy_ai_mode() {
    local project service
    project="$(ahr_compose_project_name)"
    for service in ai-bundle colab-bridge; do
        [[ -z "$(docker ps -q --filter "label=com.docker.compose.project=$project" --filter "label=com.docker.compose.service=$service")" ]] || \
            ahr_die "Stop $service before starting legacy AI to avoid overlapping scorers."
    done
}

ahr_stop_alternative_ai() {
    local project service id
    project="$(ahr_compose_project_name)"
    for service in ai-bundle colab-bridge; do
        id="$(docker ps -q --filter "label=com.docker.compose.project=$project" --filter "label=com.docker.compose.service=$service")"
        [[ -z "$id" ]] || docker stop --time 20 "$id"
    done
}

ahr_require_ai_files() {
    ahr_require_app_files
    [[ -f "$AHR_AI_FRAGMENT" ]] || \
        ahr_die "Missing Phase 6 Compose fragment: $AHR_AI_FRAGMENT"
    [[ -f "$AHR_PROJECT_ROOT/ai/network/train_xgboost.py" ]] || \
        ahr_die "Missing Phase 6 network training module"
    [[ -f "$AHR_PROJECT_ROOT/feature_engine/network_features.py" ]] || \
        ahr_die "Missing Phase 6 feature engineering module"
}

ahr_ai_compose() {
    ahr_require_ai_files
    COMPOSE_IGNORE_ORPHANS=true docker compose \
        --project-directory "$AHR_PROJECT_ROOT" \
        --env-file "$AHR_ENV_FILE" \
        -f "$AHR_PROJECT_ROOT/docker-compose.yml" \
        -f "$AHR_SURICATA_FRAGMENT" \
        -f "$AHR_FALCO_FRAGMENT" \
        -f "$AHR_WAZUH_FRAGMENT" \
        -f "$AHR_PIPELINE_FRAGMENT" \
        -f "$AHR_APP_FRAGMENT" \
        -f "$AHR_AI_FRAGMENT" \
        "$@"
}
