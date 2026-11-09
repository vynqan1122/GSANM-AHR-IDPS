#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/lib/ai.sh"
ahr_prepare_env
ahr_check_docker_engine
bash "$SCRIPT_DIR/wazuh_prepare.sh"
genti_extra=()
genti_workers=(genti-automation genti genti-check)
model_contract=""
model_dir="${GENTI_MODEL_PATH:-$AHR_PROJECT_ROOT/experiments/genti/main}"
if [[ -f "$model_dir/genti-manifest.json" ]]; then
    model_contract="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["contract"])' "$model_dir/genti-manifest.json")"
    if [[ "$model_contract" == ahr-genti-gguf ]]; then
        export GENTI_LLAMA_IMAGE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["conversion_image"])' "$model_dir/genti-manifest.json")"
        genti_extra=(-f "$AHR_PROJECT_ROOT/ai/compose.genti.gguf.yml")
        genti_workers+=(genti-llama)
    fi
fi
genti_compose() { ahr_ai_compose -f "$AHR_PROJECT_ROOT/ai/compose.genti.yml" "${genti_extra[@]}" "$@"; }
case "${1:-status}" in
  start)
    python3 - "$AHR_PROJECT_ROOT" "$model_dir" <<'PY'
import sys
from pathlib import Path
root=Path(sys.argv[1]);sys.path.insert(0,str(root))
from ai.genti.contract import verify_bundle
print('GenTI:', verify_bundle(sys.argv[2])['artifact_sha256'])
PY
    mkdir -p "$AHR_PROJECT_ROOT/output/genti-self-test"
    bash "$SCRIPT_DIR/start_lab.sh"
    bash "$SCRIPT_DIR/start_sensors.sh"
    bash "$SCRIPT_DIR/start_wazuh_api.sh"
    bash "$SCRIPT_DIR/start_pipeline.sh"
    if [[ "${2:-}" != --no-build ]]; then
      if [[ "$model_contract" == ahr-genti-gguf ]] && ! docker image inspect ahr-idps/genti:local >/dev/null 2>&1; then
        docker build -f "$AHR_PROJECT_ROOT/ai/genti/Dockerfile" -t ahr-idps/genti:local "$AHR_PROJECT_ROOT"
      fi
      genti_compose build backend genti incident-engine
    fi
    ahr_stop_alternative_ai
    ahr_ai_compose stop ai-network ai-log graph-builder fusion-engine rule-generator
    if [[ "$model_contract" == ahr-genti-gguf ]]; then
      genti_compose up --detach --wait --wait-timeout 600 --no-build --no-deps genti-llama
    fi
    genti_compose up --detach --wait --wait-timeout 360 --no-build --no-deps backend genti incident-engine response-engine
    # Nginx routes and its shared Suricata network namespace are recreated together.
    genti_compose up --detach --wait --wait-timeout 240 --force-recreate --no-build --no-deps nginx suricata
    ahr_replace_env_value AHR_AI_MODE genti
    genti_compose up --detach --no-build --no-deps genti-check
    # Stop startup immediately on a failed test instead of waiting out Docker's grace period.
    genti_compose exec -T backend python - <<'PY'
import json,time,urllib.request
deadline=time.monotonic()+2100
boot=None;previous=None
while time.monotonic()<deadline:
    with urllib.request.urlopen('http://genti:8090/status',timeout=5) as response:
        state=json.load(response)
    if boot is None:boot=state['startup_id']
    if state['startup_id']!=boot:raise RuntimeError('Model restarted during startup checks')
    report=state.get('self_test') or {};status=report.get('status','pending')
    if status!=previous:print('GenTI Docker self test:',status,flush=True);previous=status
    if status=='failed':raise RuntimeError(report.get('error','Native smoke test failed'))
    if status=='passed':break
    time.sleep(5)
else:raise TimeoutError('Model smoke test exceeded 35 minutes; inspect the retained report')
PY
    genti_compose up --detach --wait --wait-timeout 60 --no-build --no-deps genti-check
    genti_compose up --detach --wait --wait-timeout 90 --no-build --no-deps genti-automation
    printf 'Docker model smoke test passed. Evidence: output/genti-self-test/latest.json\n'
    printf 'GenTI: http://127.0.0.1:%s/dashboard/#/ai\n' "$(ahr_env_value LAB_HTTP_PORT)"
    ;;
  status) genti_compose ps --all ;;
  health)
    genti_compose exec -T backend python -c "import json,urllib.request; base='http://127.0.0.1:8000/api/'; h=json.load(urllib.request.urlopen(base+'health',timeout=5)); g=json.load(urllib.request.urlopen(base+'genti/status',timeout=10)); print('Backend/DB/Redis:',h['status']); print('GenTI ready:',g['ready']); print('Artifact:',(g.get('model') or {}).get('artifact_sha256')); print('Docker self test:',g.get('self_test',{}).get('status')); assert h['status']=='healthy' and g['ready'] and g.get('self_test',{}).get('status')=='passed'"
    ;;
  stop) genti_compose stop --timeout 30 "${genti_workers[@]}" ;;
  logs) genti_compose logs --tail 100 "${genti_workers[@]}" ;;
  rollback)
    genti_compose stop --timeout 30 "${genti_workers[@]}"
    ahr_replace_env_value AHR_AI_MODE bundle
    bash "$SCRIPT_DIR/ahr_control.sh" start
    ;;
  *) printf 'Usage: genti_control.sh start|status|health|stop|logs|rollback\n' >&2; exit 1 ;;
esac
