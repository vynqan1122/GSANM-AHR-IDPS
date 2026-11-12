# Hệ thống chính và kết quả kiểm chứng ngày 12/11/2026

Đây là ảnh chụp kết quả đo tại máy triển khai, không phải lời bảo đảm mọi máy clone repo sẽ có sẵn model, dữ liệu hay rule trong PostgreSQL. Trọng số, dữ liệu cá nhân và evidence vận hành không được công khai trong repo.

## Mô hình chính

- Qwen/Qwen2.5-Coder-1.5B-Instruct; LoRA/NF4 khi huấn luyện, GGUF Q4_K_M khi chạy CPU trong Docker.
- Corpus 50.000 prompt tăng cường, 1.696 rule tham chiếu khác nhau, 53 họ. Chia train 35.856, validation 4.704, test 4.736, unknown-test 4.704. Chưa có dòng được chuyên gia phê duyệt.
- Lượt chạy đã hoàn tất stage 4 trên toàn tập train. Chọn stage 3 theo validation loss 0,14343925, so với 0,32502496 của stage 4. Adapter được chọn đã qua 300 bước optimizer tích lũy / 600 lượt trình bày mẫu; không được mô tả chính adapter này đã đi hết epoch train.
- Artifact runtime: `ecc4941e369a49a2833907a208029245e183708234ee2e21e4d18b3ddca96697`.
- Model chính đặt tại `experiments/genti/main`. Bản trước được giữ riêng để khôi phục, không đưa vào Git.

## Luồng sinh rule và IPS

Lượt nghiệm thu đạt **12/12 bước**: đúng model/worker, endpoint nội bộ, policy, evidence HTTP mới, model sinh rule và native, quan sát Shadow không tự chặn, tự Active, chặn/cho qua, tắt/bật policy và chống revision cũ, tra cứu lịch sử/phản ứng, chứng minh không tới upstream DVWA, worker gián đoạn và khôi phục.

Rule model của lượt nghiệm thu: `genti-b69220d1ac9e403a49a95da3`. Native Suricata kiểm 50 control dương và 50 control lành: TP=50, TN=50, FP=FN=0. Shadow quan sát 5 URI khớp và 20 URI không khớp; không hạ các ngưỡng 60 giây / 20 URI khác nhau / 3 khớp / 10 không khớp để đạt kết quả. Không có thao tác duyệt Active thủ công.

Khi Active, 5 request khớp bị trả 403 và không có upstream; 5 request lành được chuyển tới DVWA. Ma trận riêng gồm 24 trường hợp method, encoding và endpoint: 12 khớp bị chặn, 12 ngoài điều kiện đi qua; quyết định gateway thống nhất với Suricata trên cùng mẫu. Mẫu ngoài phạm vi chữ ký không đồng nghĩa vô hại về an ninh.

IPS ở đây là Nginx `auth_request` cho GET `/vulnerabilities/xss_r/?...` chứa `<script` sau chuẩn hóa. Đây không phải NFQUEUE IPS toàn mạng, không bao phủ mọi XSS hay POST body. Active có lease một giờ. Khi checker/worker không sẵn sàng, đường bảo vệ fail-closed có thể trả 500; không tính lỗi hạ tầng này thành phát hiện tấn công đúng.

## Quy tắc IDS Active

Đối chiếu lúc 18:43 ngày 12/11/2026 (UTC+7): **33 quy tắc Active trong registry**, gồm **32 chữ ký IDS nền Suricata** và **1 rule GenTI đang chặn HTTP**. Suricata thực nạp 33 luật: 32 chữ ký bảo vệ và 1 probe bắt gói. Probe không được nhập vào danh mục 32 luật bảo vệ. Không nhân bản cùng chữ ký để tăng số lượng.

32 chữ ký nền có SID 9000101–9000132, gồm SQLi, XSS, file inclusion, command injection, upload và reconnaissance. File trong container khớp hash nguồn; parser đạt, 130 case native replay lại đạt và socket runtime báo 0 luật lỗi. Registry dùng nguồn `sensor`, origin `sensor_baseline`, không gắn nhãn AI. Thao tác registry không được giả lập bật/tắt luật file cảm biến; cập nhật phải đi qua cấu hình, kiểm định, nạp lại sensor và đối chiếu registry.

Mở **Quản lý Rules → Active**. Tìm `suricata-` để xem luật IDS hoặc `genti-` để xem rule model. Cột **Thực thi IPS** phân biệt chặn thật với cảnh báo. Bản clone mới tự nạp luật IDS qua Compose; snapshot registry 33 Active là dữ liệu tại máy triển khai, không được chèn giả bằng seed cho mọi máy.

## Tệp bàn giao và giới hạn

- [Báo cáo Word](reports/AHR-IDPS_Bao_Cao.docx), [PDF](reports/AHR-IDPS_Bao_Cao.pdf): 116 trang, 7 chương × 5 mục, 82 biểu thức toán, 32 hình và 36 bảng. Kết quả đồng bộ registry sau khi xuất báo cáo được cập nhật tại trang này và [danh mục luật nền](BASELINE_RULES.md).
- [Kiến trúc hệ thống](AHR_IDPS_Kien_Truc_Toan_He_Thong.png), [hướng dẫn vận hành](GENTI_AUTOMATIC_IPS.md).
- Kiểm hồi quy liên quan registry/lifecycle: 26 test đạt. Dashboard typecheck và production build đạt; 17 container healthy tại lần kiểm cuối.
- Hồ sơ cục bộ được giữ tại `output/deployment-local-20261112/` và `output/active-rules-20261112/`, gồm cả lượt thất bại trước khi hiệu chỉnh.

Control tổng hợp và tập diagnostic từ corpus chưa thay cho capture độc lập có nhãn; chưa kết luận DR/FPR thực địa, bao phủ zero-day hoặc sẵn sàng production. Không công bố raw log, PCAP, thông tin bí mật, model weights, script pentest hoặc bộ script nghiệm thu độc lập. Các cổng kiểm định native dùng khi vận hành (`ai/genti/self_test.py`, `native_validation.py`, worker) được giữ vì hệ thống cần chúng để chạy.
