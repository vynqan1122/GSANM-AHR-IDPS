# Network Analytics trắng/đen sau khi mở trang — 22/10/2026

Đã tái hiện tại `http://127.0.0.1:8080/dashboard/` → Lưu lượng mạng & IDS.
Console: `TypeError: a.flows_per_sec.toFixed is not a function`; body rỗng sau
khi request API hoàn tất. API trả PostgreSQL NUMERIC dưới dạng chuỗi JSON
`"3.4000000000000000"`, trong khi component giả định là JavaScript number.

Đã sửa:

- `_jsonable` chuyển Decimal hữu hạn sang số JSON tại boundary API.
- Frontend đổi giá trị hợp lệ sang Number trước format; giá trị không hữu hạn
  có fallback, không làm crash React root.
- Refresh lỗi giữ dữ liệu đã tải và hiện thông báo/retry, không xóa biểu đồ.
- Chặn request refresh chồng nhau. IP thiếu được ghi thiếu, không thay IP giả.
- Analytics dùng bản ghi Suricata; tốc độ lấy `event_type=flow`, bytes theo
  `bytes_to_server + bytes_to_client`, không đếm mọi event như flow hoặc đọc
  trường `network.bytes` không tồn tại. Các phân bố vẫn là lịch sử, được ghi rõ.

Test: regression Decimal→number; TypeScript/Vite build; API live trả number
cho flows/bytes. Chromium 1440×1000 và 390×844: legacy numeric string vẫn render;
API 503 giả lập giữ dữ liệu cũ; retry trở lại không reload trang; chuyển tab nhiều
lần không pageerror. Browser plugin không có trong session, dùng Playwright cài sẵn.

Screenshot/QA scripts nằm ngoài repository. Phần throughput là bytes của flow
kết thúc trong phút gần nhất, không phải băng thông NIC tại mọi mili-giây; capture
hai chân Nginx có thể tạo nhiều record cho một logical request.
