#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/ai.sh"

ahr_prepare_env
ahr_require_phase3_healthy
ahr_bundle_compose config --quiet
ahr_bundle_compose build ai-bundle incident-engine
ahr_ai_compose stop ai-network ai-log graph-builder fusion-engine
ahr_bundle_compose up --detach --wait --wait-timeout 300 --no-build --no-deps \
  ai-bundle incident-engine rule-generator response-engine
ahr_bundle_compose ps ai-bundle incident-engine rule-generator response-engine
