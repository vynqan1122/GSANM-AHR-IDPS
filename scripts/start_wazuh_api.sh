#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
source "$SCRIPT_DIR/lib/sensors.sh"

ahr_prepare_env
ahr_check_docker_engine
bash "$SCRIPT_DIR/wazuh_prepare.sh"

docker compose \
  --project-directory "$PROJECT_ROOT" \
  --env-file "$AHR_ENV_FILE" \
  -f "$PROJECT_ROOT/docker-compose.yml" \
  -f "$AHR_SURICATA_FRAGMENT" \
  -f "$AHR_FALCO_FRAGMENT" \
  -f "$AHR_WAZUH_FRAGMENT" \
  -f "$PROJECT_ROOT/sensors/wazuh/compose.api.fragment.yml" \
  up --detach --wait --wait-timeout 300 --force-recreate --no-deps wazuh-manager

printf '%s\n' 'Wazuh manager API: https://127.0.0.1:55000'
printf '%s\n' 'Manager status: run scripts/wazuh_manager_console.ps1'
