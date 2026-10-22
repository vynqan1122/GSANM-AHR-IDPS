#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
cd "$PROJECT_ROOT"
ROUNDS="${ROUNDS:-2}"
if [[ "${1:-}" != "--execute" ]]; then
    python3 -m dataset_collection.campaign --rounds "$ROUNDS"
    exit 0
fi
source "$SCRIPT_DIR/lib/app.sh"
ahr_prepare_env
ahr_check_docker_engine
ahr_require_phase3_healthy
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SNAPSHOT="/opt/ahr-idps/datasets/snapshots/campaign-$STAMP"
ahr_app_compose build backend
ahr_app_compose run --rm --no-deps backend python -m dataset_collection.campaign \
    --execute --target http://nginx --rounds "$ROUNDS" --delay 0.5 \
    --output "/opt/ahr-idps/datasets/metadata/campaign-$STAMP.json"
ahr_app_compose run --rm --no-deps backend python -m dataset_collection.cli \
    export --output "$SNAPSHOT"
echo "Dataset snapshot: datasets/snapshots/campaign-$STAMP"
echo 'Review labels/schema and holdout groups before training; the current exporter has limitations documented in the audit.'
