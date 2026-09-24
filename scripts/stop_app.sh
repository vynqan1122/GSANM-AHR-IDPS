#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
AHR_PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
export AHR_PROJECT_ROOT

# shellcheck source=scripts/lib/app.sh
source "$SCRIPT_DIR/lib/app.sh"

ahr_prepare_env
ahr_check_docker_engine
ahr_require_app_files

ahr_info "Stopping the Phase 4 backend..."
ahr_app_compose stop --timeout 20 backend
ahr_info "Phase 4 backend stopped. Phase 1-3 services were left running."
