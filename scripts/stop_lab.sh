#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
AHR_PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
export AHR_PROJECT_ROOT

# shellcheck source=scripts/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

cd "$AHR_PROJECT_ROOT"

if [[ ! -f "$AHR_ENV_FILE" ]]; then
    AHR_ENV_FILE="$AHR_ENV_EXAMPLE"
fi
ahr_check_docker_engine_reachable

ahr_info "Stopping Phase 1 containers without deleting persistent volumes..."
ahr_compose down --remove-orphans --timeout 30
ahr_info "Lab stopped. Named volumes and evidence remain intact."
