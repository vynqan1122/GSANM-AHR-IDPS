# Dùng ahr-models-v2.zip trong lab

Bundle của bạn được đặt tại `dist/ahr-models-v2.zip`. Không chép bốn file model
đè lên `experiments/models/`: bundle v2 dùng graph causal và scorer chung khác
model legacy. Joblib chỉ được nạp từ bundle tin cậy do chính bạn train.

## 1. Cài và kiểm tra model

Tại `D:\GSANM\ahr-idps`:

```powershell
python scripts/install_model_bundle.py
```

Script kiểm tra đường dẫn ZIP, checksum theo manifest, contract v2, đủ bốn model,
nạp model và thử inference CPU. Kết quả được đặt tại
`experiments/bundles/colab-v2/`. Nếu thư mục đã tồn tại, script dừng để giữ nguyên
model. Cài phiên bản khác bằng `--output experiments/bundles/ten-phien-ban`;
overlay hiện tại mount cố định `colab-v2`, cần đổi mount nếu chủ động đổi phiên bản.

## 2. Khởi động

Mở Docker Desktop, Linux containers. Nếu core/pipeline/app chưa chạy, dùng Git
Bash trong thư mục dự án theo thứ tự:

```bash
bash scripts/start_lab.sh
bash scripts/start_sensors.sh
bash scripts/start_pipeline.sh
cd dashboard && npm ci && npm run typecheck && npm run build && cd ..
bash scripts/start_app.sh
```

Sau đó trong PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/start_bundle_ai.ps1
```

Script build trước khi dừng scorer cũ, sau đó dừng ai-network/ai-log/
graph-builder/fusion-engine và Colab bridge đang chạy của cùng Compose project.
Nó bật `ai-bundle`, `incident-engine`, `rule-generator` và `response-engine`. Không cần Colab/ngrok online sau khi
tải model. Network/Fusion/Log/Graph đều inference CPU local; file được train GPU
vẫn dùng CPU để inference được. Các service rule/response hiện có không bị đổi
policy, active response vẫn alert_only nếu cấu hình lab giữ mặc định.

Khi cần API Wazuh Manager, chạy trong Git Bash:

```bash
bash scripts/start_wazuh_api.sh
```

API mở tại `https://127.0.0.1:55000`, yêu cầu xác thực; HTTP 401 khi chưa đăng
nhập là phản hồi đúng. Đây là API Manager, không phải một Wazuh Dashboard riêng.
Stack bundle đầy đủ có 15 container: 5 core, 3 sensor, collector/normalizer,
backend và 4 node ai-bundle/incident-engine/rule-generator/response-engine.
Network/Log/Graph/Fusion đều được chấm trong ai-bundle; không bật bốn scorer
legacy đồng thời. Colab bridge chỉ dùng thay thế khi chủ động chạy AI remote.

Trang Sức khỏe hiển thị collector/normalizer qua ingestion gần nhất: `reporting`
khi dữ liệu mới trong 120 giây, `stale` khi không có sự kiện mới. Đây là bằng
chứng luồng dữ liệu, không thay Docker healthcheck của tiến trình. Thời gian
ingestion hiện timestamp thật; không tự ghi độ trễ `<1s` khi chưa đo.

Xem log:

```powershell
docker logs --tail 100 ahr-idps-ai-bundle-1
docker logs --tail 100 ahr-idps-incident-engine-1
```

Ai-bundle bắt đầu từ sự kiện mới, không chấm lại toàn bộ lịch sử. Group Redis
riêng giữ pending; lỗi không ACK và không bịa score. DB hiển thị model
`local-network-v2`, `local-log-v2`, `local-graph-v2`, `local-fusion-v2`. Các model
legacy trong DB/file có thể vẫn tồn tại như lịch sử, nhưng scorer legacy đã dừng.

Rollback: `docker stop ahr-idps-ai-bundle-1`, sau đó chạy
`powershell -ExecutionPolicy Bypass -File scripts/start_ai.ps1`.
Không chạy legacy và bundle/Colab đồng thời.

## 3. Xem graph

Mở `http://127.0.0.1:8080/dashboard/` → **Graph 20 request** → **Tải lại graph**.

Graph dùng `/api/attack-graph`, lấy tối đa 20 request HTTP đầu tiên theo thời gian
tăng dần trong toàn bộ lịch sử đã thu thập. Request cần method/URI và có rule
hoặc Fusion >= 0.55. Mẫu probe xác minh Suricata vô hại đã biết được loại khỏi
graph (vẫn giữ log); query bất thường trên đường dẫn đó không được miễn.
GET/HEAD điều hướng sạch không có rule cũng không được vẽ thành tấn công chỉ
vì điểm lịch sử cao, kể cả bản ghi Suricata thiếu response status. Việc lọc
hiển thị này không xóa event, prediction hay alert gốc.
Các asset giao diện DVWA sạch và probe Phase 3 đã biết cũng được loại khỏi
graph nếu không có rule; query khác thường hoặc rule vẫn được xét bình thường.
Các route `/api/`, `/dashboard/`, `/ws/` của SOC nằm ngoài phạm vi graph web
DVWA; log của chúng vẫn còn trong phần sự kiện để điều tra riêng.
Đây là phát hiện nghi vấn, không xác nhận exploit thành công.
Nhóm cùng request_id/trace_id hoặc Suricata flow_id+tx_id được gộp trong cùng sensor;
khi sensor không có chung ID, bản ghi
từ hai chân capture có thể vẫn hiện riêng. Không gộp các request độc lập chỉ vì
trùng URL/IP. Graph trong chi tiết sự cố chỉ lấy 20 request đầu của sự cố đó.

Luồng: **IP nguồn quan sát → HTTP request → Web đích**. Request được đánh số,
có thời gian; bấm hoặc Enter vào node để xem URL đầy đủ, rule, score và nguồn IP.
Cuộn dọc để xem hết 20 request; màn hình nhỏ cuộn ngang trong graph.

IP lấy từ canonical src_ip, rồi các trường nguồn gốc remote_addr/src_ip/srcip
trong log. Không dùng Wazuh agent.ip hoặc X-Forwarded-For tự khai làm IP attacker.
Docker/NAT có thể làm IP quan sát là gateway: muốn biết máy gốc cần sensor tại
ingress trước NAT hoặc proxy tin cậy được cấu hình riêng. Thiếu IP sẽ ghi
**IP client chưa ghi nhận**, không gán IP giả. Log host/runtime không có HTTP
vẫn nằm trong sự kiện/bằng chứng, không bị vẽ thành request web.

## 4. Giới hạn dữ liệu đã train

Manifest bundle bạn cung cấp ghi 340 sự kiện: train 185, validation 87, test 68,
device yêu cầu cuda. Đây là dataset lab nhỏ, chưa đủ kết luận phát hiện tốt mọi
thử thách DVWA. Cần thu thêm benign/login thật và các chiến dịch attack được gán
nhãn độc lập; không whitelist toàn bộ IP máy chủ vì cùng IP vẫn có thể pentest.

Bundle, dataset, prediction và secret giữ local. GitHub chứa code, notebook,
hướng dẫn; không tự đưa raw log/token hoặc bundle chứa lịch sử request lên public.
