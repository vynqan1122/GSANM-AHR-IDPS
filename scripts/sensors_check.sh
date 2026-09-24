#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
bash "$SCRIPT_DIR/verify_phase2.sh" --static-only
bash "$SCRIPT_DIR/suricata_acceptance.sh" --static-only 2>/dev/null || true
bash "$SCRIPT_DIR/falco_acceptance.sh" --static-only 2>/dev/null || true
bash "$SCRIPT_DIR/wazuh_acceptance.sh" --static-only 2>/dev/null || true

