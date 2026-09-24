#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/lib/ai.sh
source "$SCRIPT_DIR/lib/ai.sh"
ahr_prepare_env
ahr_ai_compose exec -T backend python - <<'PY'
import json, urllib.request
req = urllib.request.Request("http://127.0.0.1:8000/api/experiments/run", method="POST")
print(json.dumps(json.load(urllib.request.urlopen(req, timeout=120)), indent=2))
PY

