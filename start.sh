#!/usr/bin/env bash
# ==============================================================================
# AHR-IDPS: khởi động toàn bộ dự án bằng một lệnh.
#
#   bash start.sh                  Bật toàn bộ stack (tự chọn AI bundle/legacy)
#   bash start.sh stop             Tắt toàn bộ, giữ nguyên volume dữ liệu
#   bash start.sh status           Xem container của project và URL truy cập
#
# Chạy bằng Git Bash (Windows + Docker Desktop), WSL hoặc Linux.
# Trên Windows có thể double-click start.cmd.
# ==============================================================================
set -Eeuo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SCRIPTS="$ROOT/scripts"
AHR_PROJECT_ROOT="$ROOT"
export AHR_PROJECT_ROOT

# shellcheck source=scripts/lib/ai.sh
source "$SCRIPTS/lib/ai.sh"

BUNDLE_DIR="$ROOT/experiments/bundles/colab-v2"
BUNDLE_ZIP="$ROOT/dist/ahr-models-v2.zip"
BUNDLE_FRAGMENT="$ROOT/ai/compose.bundle.yml"
LEGACY_AI_SERVICES=(ai-network ai-log graph-builder fusion-engine)
ENGINE_SERVICES=(incident-engine rule-generator response-engine)

usage() {
    cat <<'USAGE'
Cách dùng: bash start.sh [lệnh] [tùy chọn]

Lệnh:
  start (mặc định)    Bật lab -> sensors -> pipeline -> backend/dashboard -> AI
  stop                Tắt toàn bộ theo thứ tự ngược lại (không xóa volume)
  restart             stop rồi start
  status              Trạng thái container của project và URL truy cập
  health              Kiểm tra DB, Redis, API, dashboard, sensor, model registry
  logs [service]      Theo dõi log (ví dụ: bash start.sh logs backend)

Tùy chọn cho start/restart:
  --ai auto|bundle|legacy|none
                      auto (mặc định): dùng bundle Colab v2 nếu đã cài trong
                      experiments/bundles/colab-v2 hoặc có dist/ahr-models-v2.zip,
                      ngược lại dùng model legacy trong experiments/models.
  --build-dashboard   npm ci + typecheck + build dashboard trước khi bật backend
  --wazuh-api         Mở thêm Wazuh Manager API tại https://127.0.0.1:55000
  --open              Mở dashboard trên trình duyệt khi xong
  -h, --help          Hiện hướng dẫn này
USAGE
}

step() {
    printf '\n\033[1;36m==> [%s] %s\033[0m\n' "$1" "$2"
}

ok() {
    printf '\033[1;32m[OK]\033[0m %s\n' "$*"
}

# python3 trên Windows thường là stub của Microsoft Store, nên thử python trước.
ahr_python() {
    local candidate
    for candidate in ${AHR_PYTHON:-} python python3 py; do
        if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys' >/dev/null 2>&1; then
            printf '%s\n' "$candidate"
            return
        fi
    done
    ahr_die "Không tìm thấy Python dùng được (đặt AHR_PYTHON=/đường/dẫn/python nếu cần)"
}

ahr_bundle_compose() {
    ahr_ai_compose -f "$BUNDLE_FRAGMENT" "$@"
}

resolve_ai_mode() {
    case "$ai_mode" in
        auto)
            if [[ -f "$BUNDLE_DIR/manifest.json" || -f "$BUNDLE_ZIP" ]]; then
                printf 'bundle\n'
            else
                printf 'legacy\n'
            fi
            ;;
        bundle|legacy|none) printf '%s\n' "$ai_mode" ;;
        *) ahr_die "--ai phải là auto, bundle, legacy hoặc none (nhận: $ai_mode)" ;;
    esac
}

build_dashboard() {
    ahr_require_command npm
    (
        cd "$ROOT/dashboard"
        npm ci
        npm run typecheck
        npm run build
    )
}

# Tương đương scripts/start_bundle_ai.ps1: build trước, chỉ dừng scorer cũ khi
# image mới đã sẵn sàng, rồi bật ai-bundle cùng các engine.
start_ai_bundle() {
    if [[ ! -f "$BUNDLE_DIR/manifest.json" ]]; then
        [[ -f "$BUNDLE_ZIP" ]] || \
            ahr_die "Chưa có bundle: đặt file vào $BUNDLE_ZIP hoặc chạy với --ai legacy"
        ahr_info "Cài và kiểm tra bundle Colab v2 từ $BUNDLE_ZIP..."
        "$(ahr_python)" "$SCRIPTS/install_model_bundle.py" || \
            ahr_die "Cài bundle thất bại; model hiện có được giữ nguyên"
    fi

    ahr_bundle_compose config --quiet
    ahr_bundle_compose build ai-bundle incident-engine
    ahr_ai_compose stop --timeout 20 "${LEGACY_AI_SERVICES[@]}"

    local bridge
    bridge="$(docker ps -q \
        --filter "label=com.docker.compose.project=$(ahr_compose_project_name)" \
        --filter "label=com.docker.compose.service=colab-bridge")"
    [[ -z "$bridge" ]] || docker stop --time 20 "$bridge"

    ahr_bundle_compose up --detach --wait --wait-timeout 180 --no-build --no-deps \
        ai-bundle "${ENGINE_SERVICES[@]}"
}

start_ai_legacy() {
    ahr_require_legacy_ai_mode
    bash "$SCRIPTS/register_existing_models.sh"
    # Không dùng --no-build để lần chạy đầu tự build image AI nếu chưa có.
    ahr_ai_compose up --detach --wait --wait-timeout 300 --no-deps \
        "${LEGACY_AI_SERVICES[@]}" "${ENGINE_SERVICES[@]}"
}

open_dashboard() {
    local url="$1" opener
    for opener in xdg-open open start; do
        if command -v "$opener" >/dev/null 2>&1; then
            "$opener" "$url" >/dev/null 2>&1 || true
            return
        fi
    done
    ahr_warn "Không tìm thấy lệnh mở trình duyệt; mở thủ công: $url"
}

print_urls() {
    local port
    port="$(ahr_env_value LAB_HTTP_PORT 2>/dev/null || true)"
    port="${port:-8080}"
    printf '\n\033[1mĐịa chỉ truy cập:\033[0m\n'
    printf '  SOC Dashboard : http://127.0.0.1:%s/dashboard/\n' "$port"
    printf '  DVWA lab      : http://127.0.0.1:%s/   (admin/password)\n' "$port"
    printf '  Backend API   : http://127.0.0.1:%s/api/health\n' "$port"
    printf '  Wazuh agent   : 127.0.0.1:1514 (events), 127.0.0.1:1515 (enrollment)\n'
    if [[ "$wazuh_api" == 1 ]]; then
        printf '  Wazuh API     : https://127.0.0.1:55000\n'
    fi
}

cmd_start() {
    local started=$SECONDS mode
    mode="$(resolve_ai_mode)"
    ahr_info "Chế độ AI: $mode"

    step 1/6 "Hạ tầng lab: MariaDB, PostgreSQL, Redis, DVWA, Nginx"
    bash "$SCRIPTS/start_lab.sh"

    step 2/6 "Sensors: Suricata, Falco, Wazuh manager"
    bash "$SCRIPTS/start_sensors.sh"

    step 3/6 "Pipeline: collector, normalizer"
    bash "$SCRIPTS/start_pipeline.sh"

    step 4/6 "Dashboard"
    if [[ "$build_dashboard" == 1 || ! -f "$ROOT/dashboard/dist/index.html" ]]; then
        build_dashboard
    else
        ok "Dùng bản build có sẵn trong dashboard/dist (thêm --build-dashboard để build lại)"
    fi

    step 5/6 "Backend API + định tuyến dashboard"
    bash "$SCRIPTS/start_app.sh"

    step 6/6 "AI engines ($mode)"
    case "$mode" in
        bundle) start_ai_bundle ;;
        legacy) start_ai_legacy ;;
        none) ok "Bỏ qua AI theo yêu cầu (--ai none)" ;;
    esac

    if [[ "$wazuh_api" == 1 ]]; then
        step + "Wazuh Manager API"
        bash "$SCRIPTS/start_wazuh_api.sh"
    fi

    printf '\n'
    ok "AHR-IDPS đã khởi động xong sau $(( SECONDS - started )) giây."
    cmd_status

    if [[ "$open_browser" == 1 ]]; then
        open_dashboard "http://127.0.0.1:$(ahr_env_value LAB_HTTP_PORT)/dashboard/"
    fi
}

cmd_status() {
    ahr_check_docker_engine_reachable
    [[ -f "$AHR_ENV_FILE" ]] || ahr_die "Chưa có $AHR_ENV_FILE; chạy 'bash start.sh' trước"
    printf '\n\033[1mContainer của project %s:\033[0m\n' "$(ahr_compose_project_name)"
    docker ps --all \
        --filter "label=com.docker.compose.project=$(ahr_compose_project_name)" \
        --format 'table {{.Label "com.docker.compose.service"}}\t{{.Status}}'
    print_urls
}

command=start
ai_mode=auto
build_dashboard=0
wazuh_api=0
open_browser=0
log_service=''

if [[ $# -gt 0 && "$1" != -* ]]; then
    command="$1"
    shift
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ai)
            [[ $# -ge 2 ]] || ahr_die "--ai cần một giá trị"
            ai_mode="$2"
            shift
            ;;
        --ai=*) ai_mode="${1#--ai=}" ;;
        --build-dashboard) build_dashboard=1 ;;
        --wazuh-api) wazuh_api=1 ;;
        --open) open_browser=1 ;;
        -h|--help) usage; exit 0 ;;
        -*) usage >&2; ahr_die "Tùy chọn không hợp lệ: $1" ;;
        *)
            [[ "$command" == logs && -z "$log_service" ]] || ahr_die "Tham số thừa: $1"
            log_service="$1"
            ;;
    esac
    shift
done

# `bash start.sh` gõ trong PowerShell sẽ chạy trong WSL, thường chưa bật Docker
# Desktop WSL integration; báo cách chạy đúng thay vì lỗi chung chung.
if grep -qi microsoft /proc/version 2>/dev/null && ! docker version >/dev/null 2>&1; then
    ahr_die "Đang chạy trong WSL nhưng không thấy Docker. Trên PowerShell hãy dùng '.\\start.ps1' (hoặc start.cmd / Git Bash), hoặc bật Docker Desktop > Settings > Resources > WSL integration cho distro này."
fi

cd "$ROOT"
case "$command" in
    start|up) cmd_start ;;
    stop|down) bash "$SCRIPTS/ahr_control.sh" stop ;;
    restart)
        bash "$SCRIPTS/ahr_control.sh" stop
        cmd_start
        ;;
    status|ps) cmd_status ;;
    health) bash "$SCRIPTS/ahr_control.sh" health ;;
    logs) bash "$SCRIPTS/ahr_control.sh" logs "$log_service" ;;
    help) usage ;;
    *) usage >&2; ahr_die "Lệnh không hợp lệ: $command" ;;
esac
