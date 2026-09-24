# AHR-IDPS Scripts

Đây là workflow hỗ trợ cho lab DVWA nhỏ. Các tên cũ như
`start_system.sh`, `check_system.sh`, `test_attacks.sh` và `wazuh_dashboard.sh`
không tồn tại trong repository hiện tại.

## Khởi động

```bash
bash ./scripts/start_lab.sh
bash ./scripts/start_sensors.sh
bash ./scripts/start_pipeline.sh
bash ./scripts/start_app.sh
```

Mở Wazuh Manager API loopback:

```bash
bash ./scripts/start_wazuh_api.sh
```

API: `https://127.0.0.1:55000`  
Agent events: `127.0.0.1:1514`  
Enrollment: `127.0.0.1:1515`

Bật toàn bộ AI bằng PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start_ai.ps1
```

Script đăng ký các model artifact đã có vào PostgreSQL trước khi bật inference;
không cần train lại nếu thư mục `experiments/models` còn đủ file.

Kiểm tra:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\interface_acceptance.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\wazuh_manager_console.ps1
```

## Ba kịch bản pentest

Mỗi scenario tự login DVWA `admin/password`, chỉ chấp nhận loopback và thêm
`ahr_scenario` vào từng request:

```powershell
python .\scripts\authorized_monitoring_scenarios.py --target http://127.0.0.1:8080 --scenario baseline --scenario-id pentest_baseline_001
python .\scripts\authorized_monitoring_scenarios.py --target http://127.0.0.1:8080 --scenario web_injection --scenario-id pentest_web_001
python .\scripts\authorized_monitoring_scenarios.py --target http://127.0.0.1:8080 --scenario auth_abuse --scenario-id pentest_auth_001
```

`baseline` đo traffic hợp lệ; `web_injection` kiểm tra SQLi, XSS, command
injection và LFI; `auth_abuse` kiểm tra path probe và đăng nhập sai có giới
hạn. Không có DoS, reverse shell, persistence hoặc exfiltration.

## Dataset va train

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\collect_dvwa_training_dataset.ps1 -Profile all
powershell -ExecutionPolicy Bypass -File .\scripts\train_dvwa_models.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\start_ai.ps1
```

Huong dan ve label, split theo scenario va quy mo dataset: [docs/dataset_training_guide.md](docs/dataset_training_guide.md).

## Dừng

```bash
bash ./scripts/stop_app.sh
bash ./scripts/stop_pipeline.sh
bash ./scripts/stop_sensors.sh
bash ./scripts/stop_lab.sh
```

Các lệnh stop giữ nguyên volume dữ liệu. Không dùng `docker compose down -v`.
