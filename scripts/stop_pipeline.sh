#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
AHR_PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
export AHR_PROJECT_ROOT

# shellcheck source=scripts/lib/pipeline.sh
source "$SCRIPT_DIR/lib/pipeline.sh"

ahr_check_docker_engine_reachable
[[ -f "$AHR_ENV_FILE" ]] || \
    ahr_die "Missing $AHR_ENV_FILE; no AHR-IDPS pipeline project can be resolved safely"

# Compose must resolve the Wazuh fragment even though only Phase 3 services are
# stopped. Recreating a missing enrollment file does not alter stored events.
bash "$SCRIPT_DIR/wazuh_prepare.sh"

ahr_info "Stopping the Phase 3 pipeline without deleting checkpoints or event data..."
ahr_pipeline_compose stop normalizer collector
ahr_info "Phase 3 pipeline stopped. Named checkpoints, Redis streams, and PostgreSQL data were preserved."
