#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
AHR_PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
export AHR_PROJECT_ROOT

# shellcheck source=scripts/lib/app.sh
source "$SCRIPT_DIR/lib/app.sh"

mode=start
case "${1:-}" in
    '') ;;
    --install-only) mode=install ;;
    -h|--help)
        printf 'Usage: ./scripts/start_app.sh [--install-only]\n'
        exit 0
        ;;
    *) ahr_die "Unknown option: $1" ;;
esac

ahr_prepare_env
ahr_check_docker_engine
ahr_require_app_files
bash "$SCRIPT_DIR/wazuh_prepare.sh"
ahr_app_compose config --quiet

if [[ "$mode" == install ]]; then
    ahr_info "Building the Phase 4 backend image..."
    ahr_app_compose build --pull backend
    ahr_info "Phase 4 app image is installed."
    exit 0
fi

ahr_require_phase3_healthy

ahr_info "Building and starting the Phase 4 backend..."
ahr_app_compose build backend
ahr_app_compose up --detach --wait --wait-timeout 240 --no-build --no-deps backend

ahr_info "Installing the Phase 4 Nginx routes..."
ahr_app_compose up --detach --wait --wait-timeout 180 --force-recreate --no-deps nginx

# Suricata shares Nginx's network namespace, so recreating Nginx requires
# recreating Suricata immediately afterwards.
ahr_app_compose up --detach --wait --wait-timeout 180 --force-recreate --no-deps suricata

ahr_app_compose ps backend nginx suricata
ahr_info "Phase 4 app is healthy: http://127.0.0.1:$(ahr_env_value LAB_HTTP_PORT)/dashboard/"
