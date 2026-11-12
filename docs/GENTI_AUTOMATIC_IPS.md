# Vận hành GenTI tự động và IPS HTTP trong lab

Hệ thống dùng model chính Qwen2.5-Coder-7B-Instruct đã fine-tune, triển khai GGUF Q4_K_M từ gói `D:\GSANM\AHR-IDPS-GenTI-Model.zip`. Tự động hóa hiện áp dụng cho **GET `/vulnerabilities/xss_r/?...` có `<script`**, không phân biệt hoa/thường ở payload. Rule ngoài profile được giữ Candidate và ghi cảnh báo `auto-held`.

## Phân biệt vai trò

| Thành phần | Vai trò thực tế |
|---|---|
| Suricata, Falco, Wazuh | IDS: phát hiện và ghi sự kiện, không tự chặn lưu lượng trong cấu hình sensor này. |
| Nginx access log → Collector → Redis → Normalizer → PostgreSQL | Thu thập, chuẩn hóa và lưu bằng chứng. |
| Incident Engine | Gom sự kiện theo phiên/đối tượng và mức độ nghiêm trọng thành sự cố. Graph điều tra không phải Graph AI. |
| GenTI | AI sinh một Candidate từ yêu cầu, evidence và phản ví dụ; không cần điểm Network/Log/Graph/Fusion. |
| `genti-check` | Mỗi lần bật model, chạy smoke test native 3 attack + 5 benign theo đúng hash model và mã phiên. |
| `genti-automation` | Tìm evidence mới, gọi GenTI, kiểm định native, nhập receipt, theo dõi Shadow, tự Active và hết hạn. |
| Nginx + `/api/internal/ips/check` | IPS HTTP: kiểm tra trước khi proxy sang DVWA; rule Active hợp lệ trả 403 cho request khớp. |

Đây là IPS tại gateway HTTP của lab, chưa phải Suricata NFQUEUE inline hay chặn mạng toàn máy. Không kiểm tra POST body, TLS đi ngoài gateway hoặc các profile tấn công khác. Không mở cổng ra LAN, không thay đổi Windows Firewall hay mạng VMware/Kali trong lượt này.

## Bật và thao tác

1. Mở Docker Desktop, chờ Linux Engine sẵn sàng.
2. Tại PowerShell trong `D:\GSANM\ahr-idps`, chạy:

   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts/genti_control.ps1 start
   ```

   Khi chưa sửa mã nguồn, có thể thêm `-NoBuild`. Lệnh chờ model, smoke test và worker tự động sẵn sàng. Chính sách bật/tắt được giữ trong Redis qua lần khởi động, không tự xóa dữ liệu.

3. Mở `http://127.0.0.1:8080/dashboard/#/health`: kiểm tra sensor, pipeline, DB và backend.
4. Mở **Mô hình AI** để xem model hash, smoke test, worker và chu kỳ tự động. Hệ thống tự vận hành, không có bảng chọn vai trò mẫu, ô nhập yêu cầu hay checkbox xác nhận. Nút **Dừng tự động và gỡ chặn / Khôi phục tự động** chỉ dành cho can thiệp khi cần; lựa chọn dừng đã lưu vẫn được tôn trọng.
5. Khi có traffic DVWA mới, bộ lọc lấy tối đa 6 HTTP GET quan sát phù hợp cùng endpoint; loại API, dashboard, tệp tĩnh và mẫu lặp. Chính model fine-tune hiện tại phân loại evidence, phản ví dụ, mẫu chưa kết luận và viết nhận định/yêu cầu phát hiện. Các slot do model trả được kiểm tra để không bịa ID, không dùng cùng mẫu cho hai vai trò; chỉ sinh rule khi đủ cả hai nhóm. Phản ví dụ AI chọn chưa phải nhãn đã được chuyên gia phê duyệt.
6. Mở **Sự kiện**: lọc `nginx`, `suricata`, xem URI, thời gian, status và nguồn. Chọn cùng phiên trong **Sự cố** để điều tra chuỗi bằng chứng. Không phải mỗi HTTP request đều trở thành sự cố nghiêm trọng.
7. Mở **Quy tắc** → **Candidate**: cột **Tiến trình / lý do chờ** cho biết đang chờ native, ngoài phạm vi, sai model hoặc native lỗi; **Thực thi IPS** cho biết có chặn thật hay không. Bấm rule `genti-...` để xem nội dung, kết quả native và từng điều kiện Shadow (60 giây, ≥3 URI khớp, ≥10 không khớp, tổng ≥20). Worker tự chuyển Shadow/Active; không cần duyệt GenTI bằng tay. Rule ngoài profile hoặc kiểm định không đạt vẫn giữ Candidate, không bỏ qua cổng kiểm soát. Rule IDS khác có quản lý registry riêng.
8. Mở **Phản ứng**: `http_block` là request đã bị chặn thật; `parameters.applied=true`, URI và rule hash là bằng chứng. Các bản ghi `lab-audit-wrapper` của Response Engine không được coi là chặn thật.

Thông báo xuất hiện trên mọi trang dashboard khi có hành động mới; trang AI lưu danh sách cảnh báo gần nhất. Nếu tạm dừng làm mới toàn dashboard, các thông báo cũng tạm dừng. Không có email/Telegram/SMS hay thông báo hệ điều hành khi đóng trình duyệt.

Trang AI có mục **Kết quả do model của bạn sinh**: lấy rule đã lưu trong PostgreSQL theo đúng model hash đang chạy, gồm nội dung, yêu cầu, nhận định chọn mẫu, thời gian suy luận nếu đã ghi, native TP/TN/FP/FN và trạng thái. Tải lại trang không mất kết quả. Không dùng số liệu mô phỏng hoặc kết quả model khác thay cho model của bạn. Bước review dùng khả năng suy luận của cùng model; nó không sửa trọng số và không tự cấp phê duyệt native cho đầu ra của chính mình.

## Các cổng kiểm soát tự động

| Bước | Điều kiện |
|---|---|
| Candidate | Đúng model chính, smoke test của phiên hiện tại đạt, rule thuộc grammar profile đã kiểm tra. |
| Native | Suricata 8.0.6 thực thi chính nội dung rule sau cấp SID; 50 attack + 50 benign tổng hợp; FP=FN=0; đối chiếu quyết định gateway trên cùng case. |
| Shadow | Không tự chặn; ít nhất 60 giây, 20 URI khác nhau, ≥3 URI khớp và ≥10 URI không khớp. Mỗi method + URI chỉ tính một lần; mọi rule Shadow đều ghi nhận trước quyết định chặn của rule Active khác. Đây là kiểm tra mức phơi nhiễm, không phải đo FPR live có nhãn. |
| Active | Đạt native và Shadow; gateway đọc đúng version/hash; có lease 3.600 giây. Không cần người bấm duyệt trong profile được phép. |
| Hết hạn / Disable | Ngừng chặn; worker ghi `auto-expired` khi lease hết. Có evidence mới thì một chu kỳ mới có thể bắt đầu. |

Trong grammar hiện tại, header có thể là `alert http any any -> any any` hoặc `alert tcp any any -> any any`, nhưng đều phải dùng các HTTP sticky buffer, `flow:established,to_server`, method GET với `bsize:3`, URI bắt đầu `/vulnerabilities/xss_r/?` và chứa `<script` với `nocase`, một SID và một rev. Cả hai đều cần native replay và parity. Điều kiện khác không được dịch gần đúng để chặn.

Rule vẫn mang action Suricata `alert`. Ngăn chặn xảy ra tại gateway dựa trên profile đã kiểm chứng, **không phải** đổi `alert` thành `drop` hoặc reload sensor. `sensor_deployed=false` trong hồ sơ là đúng với thiết kế này.

## Dừng, khôi phục và cảnh báo

- **Gỡ chặn ngay**: trang AI → **Tắt tự động và gỡ chặn ngay**. Các request mới không qua chính sách chặn. Dữ liệu và rule vẫn được giữ.
- **Gỡ riêng rule**: Quy tắc → chọn rule → **Vô hiệu hóa quy tắc** → nhập lý do → xác nhận. Rule disabled không còn được gateway thực thi. Khi tự động vẫn bật, evidence mới có thể tạo rule khác; dùng nút tắt toàn bộ nếu muốn dừng mọi chu kỳ.
- Worker/kiểm thử model mất trạng thái sẵn sàng: heartbeat hết hạn sau 15 giây. Khi chính sách đang bật, request thuộc phạm vi được bảo vệ bị từ chối do lỗi kiểm tra (Nginx thường trả 500); dashboard/API vẫn truy cập được để xử lý.
- Backend/Redis/DB lỗi: auth subrequest thất bại, không chuyển request sang DVWA qua đường được kiểm tra. Đây là từ chối do lỗi hạ tầng, không đếm thành phát hiện chính xác.
- Sinh rule bận/lỗi: giữ Candidate hoặc đợi, ghi `auto-generation-failed`, thử lại sau 30 giây. Khóa tự động bao trùm review + sinh rule có hạn 1.320 giây; tiến trình bị dừng đột ngột có thể phải chờ khóa tự hết. Không xóa khóa khi chưa xác định model đã ngừng công việc cũ.
- Sau khi khởi động lại worker, vòng kiểm tra tiếp tục. Nếu thay model, rule có artifact khác không được tự chấp nhận; cần receipt và chu kỳ mới.

## Hồ sơ nghiệm thu và lưu kết quả

Kết quả vận hành mới nhất được tổng hợp tại [Kết quả hệ thống chính](LATEST_SYSTEM_RESULTS.md). Bộ mã công khai giữ cổng kiểm định native, startup smoke test và worker vì đây là thành phần vận hành bắt buộc. Các script pentest, benchmark và nghiệm thu độc lập cùng raw log/PCAP được giữ tại máy nghiên cứu, không nằm trong bản bàn giao GitHub.

Hồ sơ cục bộ: `output/deployment-local-20261112/`, `output/active-rules-20261112/`, `output/genti-self-test/<startup_id>/report.json` và biên nhận automation. Giữ cả lượt thất bại; kết quả của startup ID hoặc artifact khác không chứng nhận cho lượt chạy hiện tại.

## Đọc kết quả cho đúng

137.242 event telemetry là dữ liệu hệ thống; corpus fine-tune cục bộ mới gồm 50.000 prompt, với 35.856 train, 4.704 validation, 4.736 test và 4.704 unknown-test. Các prompt tăng cường dựa trên 1.696 rule tham chiếu khác nhau; không gọi 50.000 prompt là 50.000 rule độc lập. Số event không thay thế số cặp train. Corpus có 0 dòng được người phê duyệt. Chỉ số 50/50 được tính trên case tổng hợp có kiểm soát, không chứng minh FPR thực địa hay phát hiện zero-day.

Muốn mở rộng SQLi, command injection, file access hoặc POST/body cần thêm profile có giới hạn rõ, corpus riêng và kiểm thử native/đối chiếu gateway tương ứng. Muốn IPS mạng cần triển khai đường inline/NFQUEUE hoặc firewall có kiểm chứng riêng; không dùng kết quả HTTP này thay thế.

## Quyết định triển khai

Ngày 02/11/2026, theo yêu cầu bật tự động Shadow/Active và enforcement của chủ hệ thống: chọn phạm vi HTTP lab có grammar chặt, native receipt gắn version/hash, live Shadow, lease một giờ, nút dừng và fail-closed trong phạm vi bảo vệ. Không cấp Docker socket hay quyền firewall cho worker. Đây là thay đổi có thể đảo ngược trong lab; chưa có nghiệm thu độc lập cho môi trường production.
