#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
AHR_PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
export AHR_PROJECT_ROOT

# shellcheck source=scripts/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
    cat <<'USAGE'
Usage: ./scripts/start_lab.sh [--prepare-only | --install-only]

  no option       Validate configuration, start the stack, wait for health,
                  and initialize the DVWA database once when needed.
  --prepare-only  Create a protected .env with random lab secrets and validate it.
  --install-only  Prepare configuration and pull all Phase 1 images without starting.
USAGE
}

mode=start
case "${1:-}" in
    '') ;;
    --prepare-only) mode=prepare ;;
    --install-only) mode=install ;;
    -h|--help)
        usage
        exit 0
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac

cd "$AHR_PROJECT_ROOT"
ahr_prepare_env
ahr_validate_compose

if [[ "$mode" == prepare ]]; then
    ahr_info "Environment and Compose configuration are valid."
    exit 0
fi

ahr_check_docker_engine

if [[ "$mode" == install ]]; then
    ahr_info "Pulling Phase 1 container images..."
    ahr_retry 3 5 ahr_compose pull
    ahr_info "Image installation complete."
    exit 0
fi

ahr_info "Starting the isolated Phase 1 lab..."
if ! ahr_compose up --detach --wait --wait-timeout 300; then
    ahr_warn "Startup failed; current container state and recent logs follow."
    ahr_compose ps --all || true
    ahr_compose logs --no-color --tail 200 || true
    exit 1
fi

bash "$SCRIPT_DIR/init_dvwa.sh"

lab_port="$(ahr_env_value LAB_HTTP_PORT)"
ahr_compose ps
ahr_info "Phase 1 lab is healthy: http://127.0.0.1:${lab_port}"
ahr_info "Run './scripts/verify_phase1.sh' for the full acceptance check."
