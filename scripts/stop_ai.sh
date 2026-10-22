#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
AHR_PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
export AHR_PROJECT_ROOT

# shellcheck source=scripts/lib/ai.sh
source "$SCRIPT_DIR/lib/ai.sh"

ahr_check_docker_engine_reachable
[[ -f "$AHR_ENV_FILE" ]] || \
    ahr_die "Missing $AHR_ENV_FILE; no AHR-IDPS project can be resolved safely"

bash "$SCRIPT_DIR/wazuh_prepare.sh"

ahr_info "Stopping AI correlation and active response engines..."
ahr_stop_alternative_ai
ahr_ai_compose stop --timeout 20 \
  response-engine rule-generator incident-engine fusion-engine graph-builder ai-log ai-network
ahr_info "AI and response engines stopped. Model registries and stream data were preserved."
