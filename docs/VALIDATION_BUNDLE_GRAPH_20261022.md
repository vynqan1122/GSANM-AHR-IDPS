# Kiểm thử bundle v2 và graph DVWA — 22/10/2026

Đã áp dụng skill Ponytail 5.3.2 cài trong môi trường: tái sử dụng
scorer/persistence có sẵn, không thêm framework
graph hoặc service inference HTTP trung gian cho inference CPU local.

## Model

`dist/ahr-models-v2.zip` đã kiểm tra checksum theo manifest và cài vào
`experiments/bundles/colab-v2`. Version: `b2f6ea1bee2a0e7f`.
Manifest ghi 340 mẫu, split 185/87/68, device_requested=cuda; đây là thông tin
bundle, không phải lời khẳng định phiên kiểm thử local đã dùng GPU.

Docker ai-bundle và incident-engine đã healthy, đủ bốn local-*-v2 được đăng ký.
Scorer legacy network/log/graph/fusion được dừng; không cần Colab/ngrok online.
Đã gửi request GET /login.php có marker request_id; event được chấm bởi bundle
local, Fusion xấp xỉ 0.01381, không có incident_events liên kết. Request này là
kiểm tra benign navigation, không phải thử toàn bộ POST login/bruteforce.

## Graph

Endpoint `/api/attack-graph` đọc dữ liệu database thật, trả tối đa 20 request web
DVWA nghi vấn đầu tiên theo timestamp tăng dần. Đã thấy request brute-force,
SQLi, dò /.env và /admin trong lịch sử. Không tạo request hoặc IP giả để đủ 20.
Loại luồng API/dashboard SOC khỏi phạm vi, loại GET điều hướng/asset sạch và
probe kiểm tra cảm biến đã biết; giữ nguyên raw events/predictions.

IP có provenance, hỗ trợ canonical/raw IPv4/IPv6; không suy ra từ Wazuh agent
hoặc header do client tự gửi. Thiếu IP được ghi rõ. NAT có thể làm IP là địa
chỉ bridge; điều này phản ánh vị trí sensor, không phải lỗi hiển thị.

Kiểm thử trình duyệt dùng Playwright vì Browser plugin không có trong session.
URL `http://127.0.0.1:8080/dashboard/`, Chromium, viewport 1440×1000 và 390×844.
Page title đúng, có nội dung, không framework overlay/JS error. Click node, Enter
node, đóng chi tiết và tải lại đều đạt; bản sửa mobile không tràn ngang trang.
Screenshot/QA script lưu ngoài repository, không publish log hoặc ảnh request cá nhân.

## Kiểm tra mã

- TypeScript typecheck và Vite production build đạt. Bổ sung React type declarations,
  sửa moduleResolution cho TypeScript mới và khai báo Vite CSS imports.
- 98 tests toàn bộ ai/correlation/backend/normalizer/collector/dataset_collection/
  rule_engine/response và installer: kiểm tra parser, split, model, graph, ZIP
  traversal/tamper, missing IP, malformed URI và benign navigation.
- Compose bundle build/start thật, backend API thật và inference/DB thật đạt.
- Mẫu cấu hình .env.example dùng CHANGE_ME để tạo secret riêng cho cài mới.
  .env hiện có không bị thay mật khẩu hoặc reset volume.

## Giới hạn và phần chưa xác minh

Dataset 340 sự kiện còn nhỏ; không suy ra chất lượng phát hiện đầy đủ DVWA từ
smoke/integration test. Request từ hai chân sensor không có cùng request_id có
thể xuất hiện riêng; chỉ gộp khi có định danh chung, không đoán theo URL/IP.
Không chạy lại full pentest, GPU L4, remote ngrok hoặc kiểm chứng mọi workflow
nghiên cứu. Trang Experiments E1–E9 legacy vẫn dùng metric ước lượng theo count;
không dùng số đó cho báo cáo học thuật. Dùng comparison.csv/JSON từ training
held-out test và manifest của bundle làm nguồn đánh giá.
