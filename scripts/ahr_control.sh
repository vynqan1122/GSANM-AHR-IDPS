#!/usr/bin/env bash
# ==============================================================================
# AHR-IDPS Unified Lifecycle Management Controller
# Controls all 18 containers across Phases 1 through 14
# Supports: start | stop | restart | status | health | logs [service]
# ==============================================================================
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
AHR_PROJECT_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
export AHR_PROJECT_ROOT

# shellcheck source=scripts/lib/ai.sh
source "$SCRIPT_DIR/lib/ai.sh"

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

log_step() {
    printf "${BLUE}${BOLD}[PHASE STEP]${NC} %s\n" "$1"
}

log_ok() {
    printf "${GREEN}${BOLD}[OK]${NC} %s\n" "$1"
}

log_warn() {
    printf "${YELLOW}${BOLD}[WARN]${NC} %s\n" "$1"
}

log_err() {
    printf "${RED}${BOLD}[ERROR]${NC} %s\n" "$1"
}

usage() {
    cat <<EOF
${BOLD}AHR-IDPS Master Control Tool${NC}
Usage: $0 [COMMAND] [OPTIONS]

${BOLD}Commands:${NC}
  start               Khởi động toàn bộ 18 dịch vụ theo đúng thứ tự phụ thuộc (Phase 1 -> 13)
  stop                Tắt toàn bộ 18 dịch vụ theo thứ tự ngược lại (bảo tồn toàn vẹn dữ liệu)
  restart             Khởi động lại toàn bộ hệ thống (stop graceful -> start)
  status              Hiển thị trạng thái chi tiết của 18 container và URL truy cập
  health              Kiểm tra tính sẵn sàng thực tế (Postgres, Redis, API, Sensors, AI)
  logs [service]      Xem log thời gian thực (nếu không truyền service sẽ xem toàn bộ)

${BOLD}Examples:${NC}
  $0 start
  $0 stop
  $0 status
  $0 health
  $0 logs backend
EOF
}

cmd_start() {
    printf "${CYAN}${BOLD}====================================================================${NC}\n"
    printf "${CYAN}${BOLD}       AHR-IDPS: BẮT ĐẦU KHỞI ĐỘNG HỆ THỐNG THEO ĐÚNG THỨ TỰ       ${NC}\n"
    printf "${CYAN}${BOLD}====================================================================${NC}\n"

    ahr_check_docker_engine_reachable
    ahr_prepare_env
    bash "$SCRIPT_DIR/wazuh_prepare.sh"
    ahr_require_legacy_ai_mode

    # -------------------------------------------------------------
    # BƯỚC 1: PHASE 1 - CƠ SỞ HẠ TẦNG & CSDL (mariadb, postgres, redis, dvwa, nginx)
    # -------------------------------------------------------------
    log_step "Bước 1/5: Khởi động Hạ tầng Core & Cơ sở dữ liệu (Phase 1)..."
    ahr_compose up --detach --wait --wait-timeout 300
    bash "$SCRIPT_DIR/init_dvwa.sh"
    log_ok "Phase 1 Hạ tầng & CSDL đã sẵn sàng."

    # -------------------------------------------------------------
    # BƯỚC 2: PHASE 2 - HỆ THỐNG CẢM BIẾN (suricata, falco, wazuh-manager)
    # -------------------------------------------------------------
    log_step "Bước 2/5: Khởi động Cảm biến an ninh (Phase 2)..."
    ahr_require_sensor_files
    ahr_sensors_compose up --detach --wait --wait-timeout 180 --no-deps suricata falco
    ahr_sensors_compose up --detach --wait --wait-timeout 300 --no-deps wazuh-manager
    log_ok "Phase 2 Sensors (Suricata, Falco, Wazuh) đã sẵn sàng."

    # -------------------------------------------------------------
    # BƯỚC 3: PHASE 3 - STREAMING PIPELINE (collector, normalizer)
    # -------------------------------------------------------------
    log_step "Bước 3/5: Khởi động Streaming Pipeline (Phase 3)..."
    ahr_require_pipeline_files
    ahr_pipeline_compose up --detach --wait --wait-timeout 240 --no-deps collector normalizer
    log_ok "Phase 3 Pipeline (Collector, Normalizer) đã sẵn sàng."

    # -------------------------------------------------------------
    # BƯỚC 4: PHASE 4 - SOC BACKEND & WEB ROUTING (backend, nginx, suricata)
    # -------------------------------------------------------------
    log_step "Bước 4/5: Khởi động Backend API & Dashboard Routing (Phase 4)..."
    ahr_require_app_files
    ahr_app_compose up --detach --wait --wait-timeout 240 --no-deps backend
    ahr_app_compose up --detach --wait --wait-timeout 180 --no-deps nginx
    ahr_app_compose up --detach --wait --wait-timeout 180 --no-deps suricata
    log_ok "Phase 4 Backend & SOC Dashboard đã sẵn sàng."

    # -------------------------------------------------------------
    # BƯỚC 5: PHASE 6-13 - AI ENGINES & ACTIVE RESPONSE
    # -------------------------------------------------------------
    log_step "Bước 5/5: Đăng ký Models và Khởi động AI Correlation & Response Engines..."
    ahr_require_ai_files
    bash "$SCRIPT_DIR/register_existing_models.sh"
    ahr_ai_compose up --detach --wait --wait-timeout 300 --no-deps \
        ai-network ai-log graph-builder fusion-engine incident-engine rule-generator response-engine
    log_ok "Phase 6-13 AI Engines & Active Response đã sẵn sàng."

    printf "\n${GREEN}${BOLD}====================================================================${NC}\n"
    printf "${GREEN}${BOLD}       TẤT CẢ 18 CONTAINERS ĐÃ ĐƯỢC KHỞI ĐỘNG VÀ HEALTHY HOÀN TOÀN!   ${NC}\n"
    printf "${GREEN}${BOLD}====================================================================${NC}\n\n"
    cmd_status
}

cmd_stop() {
    printf "${YELLOW}${BOLD}====================================================================${NC}\n"
    printf "${YELLOW}${BOLD}       AHR-IDPS: TIẾN HÀNH TẮT HỆ THỐNG AN TOÀN (GRACEFUL SHUTDOWN)  ${NC}\n"
    printf "${YELLOW}${BOLD}====================================================================${NC}\n"

    ahr_check_docker_engine_reachable
    [[ -f "$AHR_ENV_FILE" ]] || AHR_ENV_FILE="$AHR_ENV_EXAMPLE"
    bash "$SCRIPT_DIR/wazuh_prepare.sh"

    # Dừng theo thứ tự ngược lại để tránh thất thoát dữ liệu và lỗi stream
    log_step "Bước 1/5: Tắt AI Engines & Active Response (Phase 6-13)..."
    ahr_stop_alternative_ai
    ahr_ai_compose stop --timeout 20 \
        response-engine rule-generator incident-engine fusion-engine graph-builder ai-log ai-network || true
    log_ok "AI Engines & Active Response đã dừng."

    log_step "Bước 2/5: Tắt Backend API (Phase 4)..."
    ahr_app_compose stop --timeout 20 backend || true
    log_ok "Backend đã dừng."

    log_step "Bước 3/5: Tắt Streaming Pipeline (Phase 3)..."
    ahr_pipeline_compose stop --timeout 20 normalizer collector || true
    log_ok "Streaming Pipeline đã dừng (named checkpoints và redis streams được giữ nguyên)."

    log_step "Bước 4/5: Tắt Sensors (Phase 2)..."
    ahr_sensors_compose stop --timeout 20 wazuh-manager falco suricata || true
    log_ok "Sensors đã dừng (volumes log được bảo tồn)."

    log_step "Bước 5/5: Tắt Core Infra & Databases (Phase 1)..."
    ahr_compose stop --timeout 20 nginx dvwa redis postgres mariadb || true
    log_ok "Core Infra & Databases đã dừng an toàn (toàn bộ data volume giữ nguyên)."

    printf "\n${GREEN}${BOLD}====================================================================${NC}\n"
    printf "${GREEN}${BOLD}       HỆ THỐNG ĐÃ TẮT HOÀN TOÀN MÀ KHÔNG LÀM MẤT DỮ LIỆU!            ${NC}\n"
    printf "${GREEN}${BOLD}====================================================================${NC}\n"
}

cmd_restart() {
    cmd_stop
    printf "\nChờ 3 giây trước khi khởi động lại...\n"
    sleep 3
    cmd_start
}

cmd_status() {
    ahr_check_docker_engine_reachable
    [[ -f "$AHR_ENV_FILE" ]] || ahr_prepare_env
    bash "$SCRIPT_DIR/wazuh_prepare.sh"

    printf "${CYAN}${BOLD}[TRẠNG THÁI 18 CONTAINERS AHR-IDPS]${NC}\n"
    ahr_ai_compose ps --all

    lab_port="$(ahr_env_value LAB_HTTP_PORT 2>/dev/null || echo "8080")"
    printf "\n${BOLD}Địa chỉ truy cập dịch vụ:${NC}\n"
    printf "  - SOC Web Dashboard:   ${GREEN}http://localhost:${lab_port}/dashboard/${NC}\n"
    printf "  - DVWA Vulnerable Lab:  ${GREEN}http://localhost:${lab_port}/${NC}\n"
    printf "  - Backend API:          ${GREEN}http://localhost:${lab_port}/api/health${NC}\n"
    printf "  - Wazuh Manager:        ${GREEN}localhost:1514 (Agent), localhost:1515 (Auth)${NC}\n"
}

cmd_health() {
    ahr_check_docker_engine_reachable
    [[ -f "$AHR_ENV_FILE" ]] || ahr_prepare_env

    printf "${CYAN}${BOLD}[KIỂM TRA TÍNH SẴN SÀNG TOÀN DIỆN CỦA HỆ THỐNG]${NC}\n"

    # 1. DB Checks
    printf "1. Kiểm tra CSDL Postgres: "
    if ahr_compose exec -T postgres sh -ec 'PGPASSWORD="$AHR_DB_PASSWORD" psql -h 127.0.0.1 -U "$AHR_DB_USER" -d "$POSTGRES_DB" -c "SELECT 1;"' >/dev/null 2>&1; then
        printf "${GREEN}PASS${NC}\n"
    else
        printf "${RED}FAIL${NC}\n"
    fi

    printf "2. Kiểm tra CSDL MariaDB: "
    if ahr_compose exec -T mariadb healthcheck.sh --connect --innodb_initialized >/dev/null 2>&1; then
        printf "${GREEN}PASS${NC}\n"
    else
        printf "${RED}FAIL${NC}\n"
    fi

    printf "3. Kiểm tra Redis Event Bus: "
    if ahr_compose exec -T redis sh -ec 'REDISCLI_AUTH="$REDIS_PASSWORD" redis-cli ping' 2>/dev/null | grep -q 'PONG'; then
        printf "${GREEN}PASS${NC}\n"
    else
        printf "${RED}FAIL${NC}\n"
    fi

    # 2. Web & Backend Checks
    lab_port="$(ahr_env_value LAB_HTTP_PORT 2>/dev/null || echo "8080")"
    printf "4. Kiểm tra Backend API (/api/health): "
    if curl -s -f "http://127.0.0.1:${lab_port}/api/health" >/dev/null 2>&1; then
        printf "${GREEN}PASS${NC}\n"
    else
        printf "${RED}FAIL${NC}\n"
    fi

    printf "5. Kiểm tra SOC Dashboard HTTP (/dashboard/): "
    if curl -s -f "http://127.0.0.1:${lab_port}/dashboard/" >/dev/null 2>&1; then
        printf "${GREEN}PASS${NC}\n"
    else
        printf "${RED}FAIL${NC}\n"
    fi

    # 3. Sensor checks
    printf "6. Kiểm tra Suricata Sensor (eve.json): "
    if ahr_sensors_compose exec -T suricata test -f /var/log/suricata/eve.json; then
        printf "${GREEN}PASS${NC}\n"
    else
        printf "${RED}FAIL${NC}\n"
    fi

    printf "7. Kiểm tra Wazuh Manager Core (analysisd): "
    if (ahr_ai_compose exec -T wazuh-manager /var/ossec/bin/wazuh-control status 2>&1 || true) | grep -q 'wazuh-analysisd is running'; then
        printf "${GREEN}PASS${NC}\n"
    else
        printf "${RED}FAIL${NC}\n"
    fi

    # 4. AI Engine check
    printf "8. Kiểm tra AI Model Registry trong Postgres: "
    model_count=$(ahr_ai_compose exec -T postgres sh -ec 'PGPASSWORD="$AHR_DB_PASSWORD" psql -h 127.0.0.1 -U "$AHR_DB_USER" -d "$POSTGRES_DB" -t -A -c "SELECT count(*) FROM ahr.models;"' 2>/dev/null || echo "0")
    if [[ -n "$model_count" && "$model_count" -gt 0 ]]; then
        printf "${GREEN}PASS ($model_count models registered)${NC}\n"
    else
        printf "${RED}FAIL (Không tìm thấy model nào trong bảng ahr.models)${NC}\n"
    fi
}

cmd_logs() {
    service="${1:-}"
    ahr_check_docker_engine_reachable
    [[ -f "$AHR_ENV_FILE" ]] || ahr_prepare_env
    bash "$SCRIPT_DIR/wazuh_prepare.sh"

    if [[ -n "$service" ]]; then
        ahr_ai_compose logs -f --tail 100 "$service"
    else
        ahr_ai_compose logs -f --tail 50
    fi
}

case "${1:-}" in
    start|up)
        cmd_start
        ;;
    stop|down)
        cmd_stop
        ;;
    restart)
        cmd_restart
        ;;
    status|ps)
        cmd_status
        ;;
    health)
        cmd_health
        ;;
    logs)
        shift
        cmd_logs "${1:-}"
        ;;
    -h|--help|help)
        usage
        exit 0
        ;;
    *)
        usage >&2
        exit 1
        ;;
esac
