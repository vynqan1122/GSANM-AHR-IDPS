#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
AHR_PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
export AHR_PROJECT_ROOT

# shellcheck source=scripts/lib/sensors.sh
source "$SCRIPT_DIR/lib/sensors.sh"

ahr_check_docker_engine_reachable
if [[ ! -f "$AHR_ENV_FILE" ]]; then
    ahr_die "Missing $AHR_ENV_FILE; no AHR-IDPS sensor project can be resolved safely"
fi

# Compose resolves secret files even for `stop`. Recreate only the untracked
# enrollment file if it was removed; this never changes a running manager's
# already-mounted secret and keeps emergency stop deterministic.
bash "$SCRIPT_DIR/wazuh_prepare.sh"

ahr_info "Stopping Phase 2 sensors without deleting event volumes..."
ahr_sensors_compose stop wazuh-manager falco suricata
ahr_info "Phase 2 sensors stopped. Named event volumes were preserved."
