# Bộ luật nền AHR-IDPS đang sử dụng

Đã thêm **70 luật** vào cấu hình cảm biến: **32 Suricata, 10 Falco và 28 Wazuh**. Bộ đang nạp có **33 luật Suricata**, **41 luật Falco được bật** (25 chuẩn và 16 AHR), cùng **31 luật AHR trong Wazuh**. Các luật chuẩn của Wazuh vẫn được giữ.

Đây là luật nền được soạn và kiểm chứng cho lab, không phải kết quả sinh của model GenTI và không được gắn nhãn human-reviewed. Các file generated/shadow của cảm biến được giữ riêng. Luật mới dùng alert; không mở rộng tự động phạm vi chặn của IPS GenTI.

## Phạm vi kiểm chứng

- Suricata 8.0.6: parser đạt; replay 130 trường hợp, gồm 33 mẫu dương (32 mới và probe cũ), 33 mẫu lành và 64 mẫu kiểm tra ranh giới method/đường dẫn; không có sai khác với kỳ vọng.
- Falco 0.44.1: schema/compiler đạt; 10/10 mẫu syscall dương thực tế trong DVWA và 3/3 mẫu lành đúng kỳ vọng. Có mô phỏng tên công cụ nc bằng executable vô hại và socket Docker giả trong container; không kết nối Docker API thật. Tệp credential chỉ được mở rồi đóng, không đọc nội dung; tệp kiểm tra được thu dọn.
- Wazuh 4.14.7: 118 trường hợp logtest trên cấu hình đã triển khai đạt, gồm ánh xạ, mẫu không khớp và phân tách IP nguồn/đích. Ba luật tương quan kích hoạt tại lần thứ 5 trong cửa sổ 60 giây. Cả 10 ánh xạ Falco mới cũng xuất hiện trong alerts.json từ syscall thực tế.
- Đây là kiểm tra có kiểm soát, chưa phải DR/FPR trên một tập tấn công độc lập. Các mẫu ngoài method/endpoint là kiểm tra ranh giới, không được gọi là traffic lành để làm đẹp FPR.

## Luật HTTP mới

Suricata quan sát namespace của Nginx. Luật payload giới hạn theo endpoint và method DVWA; rule dò file áp dụng các đường dẫn cụ thể tại gateway. Chữ ký chỉ nhận diện dấu hiệu trong request, không chứng minh khai thác thành công.

| SID | Nhóm | Phát hiện |
|---|---|---|
| 9000101 | sqli | SQLi UNION SELECT |
| 9000102 | sqli | SQLi quoted boolean condition |
| 9000103 | sqli | SQLi time delay SLEEP |
| 9000104 | sqli | SQLi time delay BENCHMARK |
| 9000105 | sqli | SQLi schema discovery |
| 9000106 | sqli | SQLi server file read |
| 9000107 | sqli | SQLi server file write |
| 9000108 | xss | reflected XSS script tag |
| 9000109 | xss | reflected XSS event handler |
| 9000110 | xss | reflected XSS javascript URI |
| 9000111 | xss | reflected XSS cookie access |
| 9000112 | xss | stored XSS script in form body |
| 9000113 | xss | stored XSS event handler in form body |
| 9000114 | file_inclusion | file inclusion directory traversal |
| 9000115 | file_inclusion | file inclusion passwd path |
| 9000116 | file_inclusion | file inclusion PHP filter wrapper |
| 9000117 | file_inclusion | file inclusion data wrapper |
| 9000118 | command_injection | command injection shell separator and identity command |
| 9000119 | command_injection | command injection shell separator and downloader |
| 9000120 | command_injection | command injection shell executable path |
| 9000121 | command_injection | command injection command substitution |
| 9000122 | recon | recon environment file |
| 9000123 | recon | recon Git configuration |
| 9000124 | recon | recon Subversion entries |
| 9000125 | recon | recon Apache password file |
| 9000126 | recon | recon SQL backup |
| 9000127 | upload | upload server-side PHP extension |
| 9000128 | upload | upload PHP command execution code |
| 9000129 | metadata_target | file inclusion metadata target |
| 9000130 | file_inclusion | remote HTTP file inclusion |
| 9000131 | http_indicator | sqlmap user agent on DVWA |
| 9000132 | http_indicator | diagnostic HTTP method on DVWA |

SQLi hiện xét GET của sqli/sqli_blind; XSS có GET reflected và POST form stored; command injection xét POST form ip; upload kiểm tra multipart. Không có tuyên bố bao phủ mọi JSON body, encoding, SQLi POST hay traffic TLS đi ngoài gateway. Các rule có thể cùng khớp một request; số alert không bằng số cuộc tấn công độc lập. Dò file hay dùng sqlmap có thể là kiểm thử được phép; cần đọc bối cảnh.

## Luật runtime mới

| Luật | Mức | Phạm vi |
|---|---|---|
| AHR Web Parent Shell Execution | ERROR | Shell interpreter launched by a web-serving process; verify the request context. |
| AHR Web Parent Downloader Execution | WARNING | Downloader utility launched by a web-serving process; execution alone does not prove a transfer. |
| AHR Network Utility In Web Container | WARNING | Network relay utility executed in DVWA; review its arguments and connections. |
| AHR Web Parent Script Interpreter Execution | ERROR | Secondary interpreter launched by the web process; normal PHP workers are excluded. |
| AHR Web Process Credential File Read | ERROR | Successful read-open of a credential path by a web process; no file contents are collected. |
| AHR PHP Upload File Write | ERROR | A server-side script filename is opened for writing in the DVWA upload directory. |
| AHR Scheduled Task File Write | ERROR | A file in a scheduled-task directory is opened for writing in DVWA; review persistence intent. |
| AHR Docker Socket Connection In Web Container | CRITICAL | DVWA connects to a Unix socket at the Docker API path; requires such a socket to be present. |
| AHR Namespace Utility In Web Container | ERROR | Namespace or mount utility execution in DVWA; not evidence of a successful escape. |
| AHR Web Parent Reconnaissance Tool Execution | WARNING | Identity or host discovery utility launched by the web process. |

Các luật chỉ theo dõi image DVWA. Tool launch là dấu hiệu cần điều tra, không tự chứng minh chuyển file, leo quyền hoặc thoát container. Khi thay image, phải rà lại macro ahr_dvwa_container.

## Ánh xạ và tương quan Wazuh

- 100110–100125: 16 ánh xạ tên luật runtime AHR cụ thể, kế thừa mức priority từ 100101 hoặc 100102.
- 100200: nhận diện dải SID HTTP nền AHR; 100201–100208 phân nhóm SQLi, XSS, LFI/RFI, command injection, reconnaissance, upload, URL metadata và dấu hiệu HTTP.
- 100250–100252: lặp SQLi, dò file và XSS, theo cùng src_ip và dest_ip, frequency=5, timeframe=60.
- Giữ 100100–100102 cùng các luật chuẩn. IP của leg Nginx → DVWA có thể là IP proxy; phải đối chiếu access log/trace trước khi quy nguồn hoặc chặn IP.

## Sử dụng và cập nhật

Luật cảm biến được nạp từ `sensors/suricata/rules/ahr-web.rules`, `sensors/falco/falco_rules.local.yaml` và `sensors/wazuh/rules/ahr_falco_rules.xml`. Sửa file nguồn rồi kiểm chứng trước khi restart cảm biến. Wazuh startup đồng bộ luật AHR vào volume etc để tránh giữ bản cũ sau restart; chỉnh trực tiếp file bên trong container sẽ bị thay bằng file nguồn khi khởi động lại.

Luật nền cảm biến hiện chưa tự nhập vào registry Candidate của dashboard. Xem SID/tên luật trong Sự kiện hoặc log cảm biến; tab Candidate dành cho quy trình sinh/kiểm chứng của ứng dụng. Không thay đổi trạng thái Candidate để giả lập việc bật/tắt một luật file cảm biến.

Sau khi bật backend và pipeline, sự kiện cảm biến mới được thu thập theo checkpoint như bình thường. Lượt triển khai này không bật model GenTI, không thay trọng số, không tự cấp Active cho candidate và không bật thêm profile chặn ngoài GET XSS đã kiểm soát.

[Biên bản kiểm chứng và checksum](BASELINE_RULES_VALIDATION.json)

Nguồn cú pháp: [Suricata HTTP keywords](https://docs.suricata.io/en/latest/rules/http-keywords.html), [Falco supported fields](https://falco.org/docs/reference/rules/supported-fields/), [Wazuh rule syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html).
