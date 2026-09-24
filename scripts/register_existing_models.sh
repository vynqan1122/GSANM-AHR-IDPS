#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
source "$SCRIPT_DIR/lib/ai.sh"

ahr_prepare_env
ahr_ai_compose exec -T postgres sh -ec \
  'PGPASSWORD="$AHR_DB_PASSWORD" psql --host=127.0.0.1 --username="$AHR_DB_USER" --dbname="$POSTGRES_DB" --set=ON_ERROR_STOP=1' \
  < "$PROJECT_ROOT/scripts/register_existing_models.sql"
