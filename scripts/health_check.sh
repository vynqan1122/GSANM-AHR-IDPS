#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/lib/ai.sh
source "$SCRIPT_DIR/lib/ai.sh"
ahr_prepare_env
ahr_ai_compose ps --all
ahr_ai_compose exec -T backend python - <<'PY'
import json, urllib.request
print(json.dumps(json.load(urllib.request.urlopen("http://127.0.0.1:8000/api/system/health", timeout=5)), indent=2))
PY

