#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
AHR_PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
export AHR_PROJECT_ROOT

# shellcheck source=scripts/lib/sensors.sh
source "$SCRIPT_DIR/lib/sensors.sh"

mode=runtime
case "${1:-}" in
    '') ;;
    --static-only) mode=static ;;
    -h|--help)
        printf 'Usage: ./scripts/verify_phase2.sh [--static-only]\n'
        exit 0
        ;;
    *) ahr_die "Unknown option: $1" ;;
esac

ahr_prepare_env
ahr_require_sensor_files
bash "$SCRIPT_DIR/wazuh_prepare.sh"
ahr_sensors_compose config --quiet

scripts=(
    "$SCRIPT_DIR/suricata_acceptance.sh"
    "$SCRIPT_DIR/falco_acceptance.sh"
    "$SCRIPT_DIR/wazuh_acceptance.sh"
)

for script in "${scripts[@]}"; do
    [[ -f "$script" ]] || ahr_die "Missing acceptance script: $script"
    bash -n "$script"
done
ahr_info "Phase 2 Compose model and acceptance scripts passed static parsing."

if [[ "$mode" == static ]]; then
    for script in "${scripts[@]}"; do
        bash "$script" --static-only
    done
    ahr_info "Phase 2 static acceptance PASS."
    exit 0
fi

ahr_check_docker_engine
ahr_require_phase1_healthy
bash "$SCRIPT_DIR/start_sensors.sh"

# Keep these serial. Each probe relies on a unique real event and Suricata
# shares Nginx's namespace; concurrent container reconciliation is unsafe.
bash "$SCRIPT_DIR/suricata_acceptance.sh"
bash "$SCRIPT_DIR/falco_acceptance.sh"
bash "$SCRIPT_DIR/wazuh_acceptance.sh"

# A sensor addition may not regress the network/DB safety contract.
bash "$SCRIPT_DIR/verify_phase1.sh"
ahr_info "Phase 2 runtime acceptance PASS: Suricata, Falco, and Wazuh each produced real events."
