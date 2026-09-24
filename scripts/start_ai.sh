#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/ai.sh"

ahr_prepare_env
ahr_require_phase3_healthy
ahr_ai_compose config --quiet
"$SCRIPT_DIR/register_existing_models.sh"
ahr_ai_compose up --detach --wait --wait-timeout 300 --no-build --no-deps \
  ai-network ai-log graph-builder fusion-engine incident-engine rule-generator response-engine
ahr_ai_compose ps ai-network ai-log graph-builder fusion-engine incident-engine rule-generator response-engine
