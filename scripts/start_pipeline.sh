#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
AHR_PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
export AHR_PROJECT_ROOT

# shellcheck source=scripts/lib/pipeline.sh
source "$SCRIPT_DIR/lib/pipeline.sh"

mode=start
case "${1:-}" in
    '') ;;
    --install-only) mode=install ;;
    -h|--help)
        printf 'Usage: ./scripts/start_pipeline.sh [--install-only]\n'
        exit 0
        ;;
    *) ahr_die "Unknown option: $1" ;;
esac

ahr_prepare_env
ahr_check_docker_engine
ahr_require_pipeline_files
# The Wazuh fragment references an untracked enrollment secret even when a
# command targets only Phase 3 services.
bash "$SCRIPT_DIR/wazuh_prepare.sh"
ahr_pipeline_compose config --quiet

if [[ "$mode" == install ]]; then
    ahr_info "Building the Phase 3 collector and normalizer images..."
    # Both services intentionally share one immutable build artifact.
    ahr_pipeline_compose build --pull collector
    ahr_info "Phase 3 pipeline images are installed."
    exit 0
fi

ahr_require_phase2_healthy

# Phase 3 adds a persistent structured Nginx access-log sink. Existing Phase 1
# containers created before that volume existed do not acquire new mounts via a
# config reload. Reconcile exactly once when the mount is absent, and then
# recreate Suricata immediately because it shares Nginx's network namespace.
nginx_id="$(ahr_pipeline_compose ps -q nginx)"
nginx_has_log_mount="$({
    docker inspect \
        --format '{{range .Mounts}}{{if eq .Destination "/var/log/ahr-idps"}}{{println "yes"}}{{end}}{{end}}' \
        "$nginx_id"
} | tr -d '\r[:space:]')"
if [[ "$nginx_has_log_mount" != yes ]]; then
    ahr_info "Installing the Phase 3 Nginx structured-log volume..."
    ahr_pipeline_compose up \
        --detach --wait --wait-timeout 180 --force-recreate --no-deps nginx
    ahr_pipeline_compose up \
        --detach --wait --wait-timeout 180 --force-recreate --no-deps suricata
fi

# Phase 1 owns PostgreSQL/Redis and Phase 2 owns the sensor containers. Avoid
# reconciling either accepted layer while bringing up only the new consumers.
ahr_info "Starting the Phase 3 collector and normalizer..."
ahr_pipeline_compose build collector
ahr_pipeline_compose up \
    --detach \
    --wait \
    --wait-timeout 240 \
    --no-build \
    --no-deps \
    collector normalizer

ahr_pipeline_compose ps collector normalizer
ahr_info "Phase 3 pipeline is healthy. Run scripts/verify_phase3.sh for real-event acceptance."
