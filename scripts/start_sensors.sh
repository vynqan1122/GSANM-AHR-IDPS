#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
AHR_PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
export AHR_PROJECT_ROOT

# shellcheck source=scripts/lib/sensors.sh
source "$SCRIPT_DIR/lib/sensors.sh"

mode=start
case "${1:-}" in
    '') ;;
    --install-only) mode=install ;;
    -h|--help)
        printf 'Usage: ./scripts/start_sensors.sh [--install-only]\n'
        exit 0
        ;;
    *) ahr_die "Unknown option: $1" ;;
esac

ahr_prepare_env
ahr_check_docker_engine
ahr_require_sensor_files
bash "$SCRIPT_DIR/wazuh_prepare.sh"
ahr_sensors_compose config --quiet

if [[ "$mode" == install ]]; then
    ahr_info "Pulling digest-pinned Phase 2 sensor images..."
    ahr_sensors_compose pull suricata falco wazuh-manager
    ahr_info "Phase 2 sensor images are installed."
    exit 0
fi

ahr_require_phase1_healthy

# Start capture engines first so Wazuh's localfile readers see real files on
# their shared volumes at manager startup. --no-deps prevents Compose from
# reconciling or recreating the already accepted Phase 1 lab.
ahr_info "Starting Suricata and Falco..."
ahr_sensors_compose up --detach --wait --wait-timeout 180 --force-recreate --no-deps suricata falco

ahr_info "Starting Wazuh manager and its local sensor integrations..."
ahr_sensors_compose up --detach --wait --wait-timeout 300 --force-recreate --no-deps wazuh-manager

ahr_sensors_compose ps suricata falco wazuh-manager
ahr_info "Phase 2 sensors are healthy. Run scripts/verify_phase2.sh for real-event acceptance."
