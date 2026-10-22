# Campaign dataset DVWA có đăng nhập

Chạy từ thư mục project. Mặc định chỉ tạo kế hoạch, không phát traffic và không cần DB:

```powershell
python -m dataset_collection.campaign --rounds 2 --seed 42 --output output/campaign-plan.json
```

Trong Bash/WSL cũng có thể dùng:

```bash
bash scripts/run_dvwa_campaign.sh
```

Sau khi core, sensors, pipeline và backend healthy, chạy campaign và xuất snapshot:

```bash
ROUNDS=2 bash scripts/run_dvwa_campaign.sh --execute
```

Script rebuild backend để thêm module mới, chạy một container backend tạm với cùng
database/network của project, rồi export dataset vào một thư mục snapshot có timestamp.
Các secret được lấy từ môi trường container, không truyền password qua command line.
Snapshot exporter lấy toàn bộ event đã có nhãn trong DB, không chỉ campaign cuối.

Mỗi vòng có hai benign và sáu họ: SQLi, reflected XSS, command injection, file
inclusion, một lần login sai và một path probe. Mỗi case có session/scenario mới.
Command injection dùng POST và chỉ in AHR_LAB_OK sau lệnh ping trong lab. File
inclusion thử đọc hostname của container. Không upload file thực thi hoặc tạo stored XSS.

Runner đăng nhập bằng CSRF token, probe challenge rồi mới mở cửa sổ nhãn. Khi
request về trang login hoặc gặp 5xx, nó dừng. Nhãn là **ý định request**; thành công
khai thác cần review response/runtime riêng. Nếu task dừng sau khi tạo scenario,
hãy review record chưa kết thúc trước khi dùng snapshot để train.

IP `192.0.2.x` là metadata mô phỏng trong scenario notes và header
`X-AHR-Simulated-IP`. Nginx chưa log header này; nó không thay IP packet hoặc
`remote_addr`. Không dùng IP/marker/attack_type làm feature. Muốn IP thật khác nhau,
dùng nhiều client container trong bridge lab và kiểm tra capture leg/flow_id.

Sau collection, review `linked_events`, marker ở Nginx/Suricata, label conflict và
benign cùng challenge. Exporter hiện thiếu một số canonical fields và chưa gán nhãn
Falco bằng correlation: xem báo cáo kiểm toán trước khi gọi dataset đầy đủ cho tất cả AI.
Giữ toàn bộ campaign/client session trong một split; unknown test phải giữ họ hoặc
biến thể ngoài train, không tự suy từ tên split.

Module mới đã qua test plan/allowlist/CSRF/login rejection; chưa chạy end-to-end
vì Docker daemon không hoạt động trong phiên lập báo cáo ngày 08/10/2026.
