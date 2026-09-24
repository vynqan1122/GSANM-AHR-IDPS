#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
printf '[DEMO] STEP 1 health\n'; bash "$SCRIPT_DIR/health_check.sh"
printf '[DEMO] STEP 2 benign DVWA activity candidates\n'; python "$SCRIPT_DIR/generate_benign.py" | head -20
printf '[DEMO] STEP 3-11 dashboard/API evidence\n'; bash "$SCRIPT_DIR/verify_phase13.sh" --static-only
printf '[DEMO] STEP 12-20 research metrics\n'; bash "$SCRIPT_DIR/run_ablation.sh"

