# Khôi phục hệ thống trước chuyển HTTP IDS/LLM

Ngày 12/10/2026, đã khôi phục file default từ các bản legacy có sẵn:

- docker-compose.yml: core MariaDB/DVWA/Nginx/PostgreSQL/Redis.
- Makefile và README: workflow cũ.
- scripts/lib và start/train/acceptance scripts: dùng docker-compose.yml gốc.
- rule_engine/genti.py: GenTI-lite xác định trước chuyển LLM; package HTTP
  không còn chiếm import rule_engine.genti của hệ thống chính.
- SCRIPTS_README_V2.md: bỏ thông báo HTTP default.

Giữ các AI, Falco, Wazuh, pipeline và API/dashboard trong overlays ban đầu.
Chế độ đầy đủ gộp core + sensors + pipeline + app + ai có 18 service.
Các lỗi hiện trạng từng nêu trong báo cáo audit không được tự sửa hoặc biến
thành đã khắc phục trong thao tác restore này.

Bản LLM ở ../llm-system/, có Compose và scripts riêng, project ahr-idps-llm,
cổng DVWA 8081. Không có bản sao .env hoặc credential hệ thống chính.
Tạo virtualenv/.env riêng khi chạy. Không dùng lại virtualenv cũ đã di chuyển
vì virtualenv chứa đường dẫn tuyệt đối.

Backup thao tác restore: restore-backups/pre-llm-20261012-222239/.
Các file HTTP-only đã được chuyển vào backup sau khi sao chép sang folder LLM;
không xóa dữ liệu database, model, named volume hoặc .env.

Khởi động hệ thống chính theo workflow ban đầu (Ubuntu/WSL2):

```bash
cd /mnt/d/GSANM/ahr-idps
bash scripts/start_lab.sh
bash scripts/start_sensors.sh
bash scripts/start_pipeline.sh
bash scripts/start_app.sh
bash scripts/start_ai.sh
```

Sửa Compose/source không tự restart container đang chạy. Thao tác này không
tự dựng lại hoặc deploy stack runtime; chạy workflow trên khi bạn muốn bật
cấu hình đã khôi phục. Những volume cũ được giữ để dùng lại.

Kiểm tra sau restore: hash Compose và README gốc khớp bản legacy, cấu hình
hợp nhất đủ 18 service; GenTI-lite chính 9 test pass. Folder LLM 21 test pass,
1 test tích hợp live skipped. Compose LLM parse hợp lệ, project ahr-idps-llm,
volume ahr-idps-llm_mariadb_data và cổng 8081; khác volume chính
ahr-idps_mariadb_data. Không restart hoặc thay các container đang chạy.
