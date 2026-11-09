#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/pipeline.sh"
ahr_prepare_env
ahr_check_docker_engine
ahr_require_phase2_healthy
ahr_sensors_compose ps --all

