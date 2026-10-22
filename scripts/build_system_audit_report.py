"""Author a standalone Vietnamese LaTeX audit, two pages per function."""
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'output/pdf'

def esc(s):
    return ''.join({'\\':r'\textbackslash{}','&':r'\&','%':r'\%','$':r'\$','#':r'\#','_':r'\_','{':r'\{','}':r'\}','~':r'\textasciitilde{}','^':r'\textasciicircum{}'}.get(c,c) for c in s)

# Each record describes a real component; proposals are explicitly separated.
NODES = [
dict(name='Máy khách kiểm thử và campaign DVWA', kind='Công cụ chạy theo đợt; không phải service thường trực', source='dataset_collection/campaign.py; scripts/authorized_monitoring_scenarios.py',
 role='Tạo traffic có kiểm soát để kiểm chứng cảm biến và thu mẫu có nhãn. Mỗi lượt có scenario_id độc lập, session mới và provenance; nguồn gốc thí nghiệm phải được tách khỏi vector đặc trưng.',
 inp='DVWA đã khởi tạo; tài khoản lab; kế hoạch scenario; seed; giới hạn tốc độ; mục tiêu nginx hoặc loopback.',
 out='HTTP thật, marker ahr_scenario, bản ghi scenario_runs, event_labels và JSON nhật ký campaign. IP mô phỏng được lưu trong metadata thí nghiệm.',
 flow='Campaign mới lập kế hoạch khi chưa có --execute. Khi chạy, nó đăng nhập lấy CSRF token, xác nhận trang challenge sau login, mở cửa sổ scenario rồi gửi request. Command injection dùng POST; các mẫu khác dùng GET. Lượt login không nằm trong cửa sổ nhãn attack.',
 algo=r'N_{\mathrm{req}}=8R,\quad \Delta t\geq 0.2\,\mathrm{s},\quad \mathrm{SID}_i\neq\mathrm{SID}_j\;(i\neq j).',
 risk='Runner cũ trong traffic.py không login nên response 302 về login có thể bị gắn attack. Một lượt request tấn công được phát ra không chứng minh đã khai thác thành công. Campaign mới ghi rõ label_semantics là request_intent_not_exploit_success.',
 overlap='Hợp nhất vai trò tạo traffic dưới một campaign, không duy trì song song nhiều script khác payload và nhãn. Giữ authorized_monitoring_scenarios.py cho demo, campaign cho thu dữ liệu có DB.',
 test='Chạy mặc định để kiểm tra plan không gửi traffic; chạy một vòng trong backend; kiểm tra response không kết thúc ở login.php; đối chiếu marker trong Nginx và Suricata; đếm linked_events trước khi export.',
 keep='Giữ công cụ mới, nhưng chỉ chạy --execute khi lab healthy. Thêm các biến thể benign trên chính đường dẫn challenge để model không học rằng mọi /vulnerabilities/ đều là attack.',
 metric='Số scenario độc lập, nhãn hai lớp, coverage từng họ, số redirect ngoài dự kiến, tỷ lệ marker liên kết và số request thực sự tới challenge.'),
dict(name='Docker Desktop và Linux runtime',kind='Nền tảng điều phối bên dưới toàn bộ service',source='docker-compose.yml; sensors/falco/compose.fragment.yml; scripts/lib/common.sh',
 role='Cung cấp network namespace, volume bền vững, giới hạn tài nguyên và môi trường Linux cho eBPF. Đây là nền tảng triển khai, không phải thuật toán phát hiện xâm nhập.',
 inp='Docker Engine Linux, WSL2, image pin digest, .env và các Compose fragment. CPU/GPU train chia sẻ tài nguyên vật lý với các service giám sát.',
 out='18 service trong cấu hình hợp nhất; mạng ingress, dvwa_front, dvwa_db, data, app_front và wazuh_agent. Tổng mem_limit là 13,5 GiB; đây là tổng trần, không phải RAM đang dùng.',
 flow='Core khởi động database và proxy; sensor phụ thuộc namespace/proc của core; pipeline cần Redis/PostgreSQL; backend cần pipeline; AI cần model và stream. Falco dùng host PID nên phụ thuộc kernel Docker, không giám sát trực tiếp Windows.',
 algo=r'M_{\mathrm{limits}}=\sum_{s=1}^{18}m_s=13.5\,\mathrm{GiB};\quad M_{\mathrm{actual}}\neq M_{\mathrm{limits}}.',
 risk='Engine hiện không reachable qua dockerDesktopLinuxEngine. restart:no làm các service không tự phục hồi sau process exit; heartbeat dạng tồn tại file chưa chứng minh consumer sống. Không có kiểm thử live trong phiên đánh giá này.',
 overlap='Tránh tạo nhiều project Compose với tên khác nhau vô tình nhân đôi Redis/DB. Dùng cùng project name và cùng danh sách overlay khi ps, logs, up, exec.',
 test='Bật Docker Desktop Linux containers; docker info phải thành công; kiểm tra từng service healthy và số restart; tạo request có marker rồi xác nhận dữ liệu đi xuyên pipeline.',
 keep='Giữ một project lab. Sau khi sửa contract, dùng restart policy có chọn lọc cho service không chứa thao tác destructive. Dừng train nặng khi chạy acceptance latency.',
 metric='RAM/CPU thực đo bằng docker stats, restart count, disk volume, stream lag, kernel/eBPF availability và GPU passthrough.'),
dict(name='Nginx Gateway và access JSONL',kind='Service nginx; 256 MiB, 1 CPU',source='infrastructure/nginx/nginx.phase4.conf; app/compose.fragment.yml',
 role='Là điểm HTTP vào lab và nơi gắn trace_id. Proxy DVWA, /api/, /ws/ và /dashboard/; ghi access JSONL để Log AI và điều tra dùng dữ liệu ứng dụng thật.',
 inp='Request tại 127.0.0.1:8080; Host hợp lệ; DNS Docker tới dvwa và backend. Khi bật app overlay phải dùng nginx.phase4.conf thay cho bản core.',
 out='Response HTTP/WebSocket, X-Request-ID và JSONL gồm remote_addr, method, URI, status, thời gian request, upstream và user agent. Collector đọc named volume nginx_logs.',
 flow='Nginx chấp nhận dvwa.local/localhost/127.0.0.1; host lạ trả 444. /healthz chỉ xác nhận proxy sống; các URL /api/ và /dashboard/ cần backend khỏe. Header X-Forwarded-For gửi upstream được ghi đè bằng remote_addr.',
 algo=r'\ell_i=t_{\mathrm{response},i}-t_{\mathrm{request},i},\quad e_i=\mathbb{1}[\mathrm{status}_i\geq400].',
 risk='Client tự đặt X-Forwarded-For không làm remote_addr thay đổi. Nếu báo cáo dùng IP giả trong header như IP thật sẽ sai phân tích mạng. Healthz thành công không chứng minh backend hoặc DVWA dùng được.',
 overlap='Access log và Suricata HTTP là hai quan sát khác tầng của cùng request. Gắn trace/request hoặc flow correlation; không cộng hai bản ghi thành hai lần tấn công độc lập.',
 test='Gửi baseline, kiểm tra JSON escape với URI chứa ký tự đặc biệt; kiểm tra /dashboard/, /api/health và WebSocket; đối chiếu trace_id với raw_event và normalized http.',
 keep='Giữ. Có thể giảm log trùng ở stdout sau khi có retention; giữ JSONL làm nguồn chuẩn. Với IP thí nghiệm, lưu trường simulated_client_ip riêng thay vì sửa remote_addr.',
 metric='HTTP 2xx/4xx/5xx, p50/p95 latency, số access event bị mất, thời điểm log cuối và tỷ lệ request liên kết tới event.'),
dict(name='DVWA',kind='Service dvwa; 768 MiB, 1,5 CPU',source='docker-compose.yml; scripts/init_dvwa.sh; dataset_collection/traffic.py',
 role='Ứng dụng web cố ý có lỗ hổng để minh họa phát hiện và phản ứng. SQLi, reflected XSS, command injection, file inclusion và brute-force là nguồn tín hiệu cho đề tài.',
 inp='HTTP đã đi qua Nginx, PHP session/CSRF token và database MariaDB. Mức security phải được ghi trong provenance, mặc định low trong Compose.',
 out='HTML, HTTP status, truy vấn DB, process/syscall và log liên quan. Đây là ứng dụng được giám sát, không tự tạo alert an ninh có nhãn chuẩn.',
 flow='Khởi tạo DB khi thiếu schema; login; xác minh challenge; chọn payload nhẹ; lưu response metadata; đối chiếu sensor. Chức năng setup reset chỉ dùng khi DB chưa khởi tạo và script đã kiểm tra bảng.',
 algo=r'y_i^{\mathrm{intent}}\in\{0,1\},\quad y_i^{\mathrm{success}}\in\{0,1,\mathrm{unknown}\};\quad y_i^{\mathrm{intent}}\neq y_i^{\mathrm{success}}\ \text{nói chung}.',
 risk='GET tới /exec/ không tương đương submit POST; response 200 cũng có thể là trang login. file_upload hiện trong runner cũ chỉ mở trang upload nên không đủ gọi là attack upload. Mẫu sai method có thể làm Falco hoàn toàn im lặng.',
 overlap='Không cần thêm nhiều ứng dụng web khác trước khi DVWA có tập test và nhãn đáng tin. Mỗi challenge nên có benign counterpart cùng endpoint.',
 test='Xác nhận login không bị redirect lại; truy cập id hợp lệ có user record; command test chỉ in marker; kiểm tra status và final URL; giữ output proof đã loại cookie/token.',
 keep='Giữ làm mục tiêu duy nhất cho phạm vi bài tập lớn. Chưa đưa stored XSS, upload thực thi hoặc thao tác phá dữ liệu vào campaign mặc định.',
 metric='Tỷ lệ login thành công, challenge reached, exploit evidence khi có, benign/attack cùng endpoint và coverage sensor theo từng challenge.'),
dict(name='MariaDB',kind='Service mariadb; 1 GiB, 2 CPU',source='docker-compose.yml; infrastructure/mariadb/conf.d/ahr.cnf; scripts/init_dvwa.sh',
 role='Lưu dữ liệu của DVWA: tài khoản và dữ liệu ứng dụng. Tách biệt khỏi PostgreSQL vốn lưu security events, nên hai database có vai trò khác nhau.',
 inp='Query từ PHP/DVWA trong mạng dvwa_db và credentials lab. Volume mariadb_data giữ dữ liệu qua lần dừng container.',
 out='Kết quả query cho DVWA và trạng thái health. Không có node thu audit SQL đầy đủ trong cấu hình đang được kiểm tra.',
 flow='MariaDB healthy trước DVWA. init_dvwa.sh kiểm tra bảng users/guestbook rồi mới gọi setup nếu cần. Khi dữ liệu lab đã có, script không reset DB.',
 algo=r'\mathrm{Ready}_{\mathrm{DVWA}}=\mathrm{Health}_{\mathrm{DB}}\land\mathrm{SchemaExists}\land\mathrm{LoginWorks}.',
 risk='Health server không chứng minh schema đúng hoặc tài khoản DVWA còn login được. Gọi reset thủ công có thể mất dữ liệu bài thực hành. Không suy luận SQL Injection đã chạy chỉ từ trạng thái DB healthy.',
 overlap='Không gộp MariaDB với PostgreSQL vì DVWA cần MySQL-compatible backend. Có thể giảm resource cap sau đo thực tế; không thêm replication cho lab này.',
 test='Kiểm tra health, bảng ứng dụng và một login DVWA; stop/start giữ dữ liệu; xác nhận không publish port 3306 ra host; không in mật khẩu trong báo cáo.',
 keep='Giữ, backup volume trước đổi image/schema. Nếu cần chứng minh SQL query, dùng instrumentation lab riêng và ghi rõ overhead, không tự coi là sensor đã có.',
 metric='Kết nối hoạt động, lỗi query ứng dụng, latency truy vấn baseline, dung lượng volume và số lần khởi tạo lại schema.'),
dict(name='Suricata NIDS',kind='Service suricata; 768 MiB, 2 CPU',source='sensors/suricata/compose.fragment.yml; sensors/suricata/suricata.yaml; sensors/suricata/rules/base.rules',
 role='Quan sát packet/HTTP/flow và áp signature rule ở tầng mạng. Là nguồn Network AI và rule score; không cần AI mới thấy dấu hiệu payload rõ.',
 inp='Traffic namespace Nginx qua chế độ --pcap -k none, rule files và config parser. Chia sẻ namespace khiến capture nhìn thấy ingress và upstream.',
 out='EVE JSON alert/http/flow/dns/tls nếu traffic có các giao thức tương ứng. Collector đọc eve.json; Wazuh có thể tạo alert dẫn xuất từ cùng EVE.',
 flow='Capture, decode, flow tracking, signature match, xuất EVE. Một request có thể tạo hai HTTP record do hai chân proxy; phải giữ capture leg hoặc flow_id để phân tích đúng.',
 algo=r'a_i=\mathbb{1}[\mathrm{header}(e_i)\land\mathrm{flow}(e_i)\land\mathrm{payload}(e_i)],\quad \mathrm{DR}=\frac{TP}{TP+FN}.',
 risk='Topology hiện là IDS quan sát; chữ drop trong rule không tự tạo IPS inline. Template chỉ match đường dẫn DVWA dễ báo false positive với thao tác hợp lệ trên challenge.',
 overlap='Giữ raw EVE là nguồn sự thật của signature mạng. Wazuh alert dựa trên EVE phải có parent/source_event để không tính thành nguồn độc lập thứ hai.',
 test='Probe marker vô hại; kiểm tra native HTTP và SID được mong đợi; parse candidate bằng suricata -T với config đầy đủ; replay PCAP riêng benign/attack để đo FPR.',
 keep='Giữ là cảm biến cốt lõi. Candidate chỉ alert và chỉ đưa vào shadow rules sau kiểm thử engine thật. Chưa triển khai drop/reject trong lab quan sát.',
 metric='Packet loss, flow count, rule matches, detection latency, FPR benign, parser load errors và provenance từng capture leg.'),
dict(name='Falco eBPF',kind='Service falco; 768 MiB, 1,5 CPU',source='sensors/falco/compose.fragment.yml; sensors/falco/falco_rules.local.yaml; normalizer/mappings/falco.py',
 role='Giám sát syscall/process/container để thấy hành vi phía server khi web attack sinh shell hoặc child process. Bổ sung góc nhìn khác traffic HTTP.',
 inp='Linux kernel/eBPF, host PID, tracefs, thông tin container và rule Falco. Docker Desktop chỉ expose Linux VM; không thu Windows Security log.',
 out='JSONL có proc.name, parent, cmdline, container, rule, priority và timestamp. Runtime event có thể không mang marker HTTP trực tiếp.',
 flow='Rule phát hiện spawned process hoặc file/network/privilege behavior; Collector chuẩn hóa; Incident Engine phải tương quan qua container/time/request evidence.',
 algo=r'\mathrm{link}(e_h,e_r)=\mathbb{1}[c_h=c_r\land0\leq t_r-t_h\leq\Delta],\quad\Delta\text{ cần kiểm chứng}.',
 risk='Collector label hiện dựa raw marker nên không bao phủ tốt syscall không có marker. Không được gán tất cả syscall trong cùng phút thành attack; phải ghi confidence của correlation.',
 overlap='Falco là nguồn runtime gốc; Wazuh đọc lại Falco không tạo telemetry độc lập. Có thể bật Falco chỉ khi đánh giá command injection để giảm chi phí.',
 test='Command test POST sinh output AHR_LAB_OK; tìm process event đúng container/timestamp; đảm bảo không lấy syscall của công cụ kiểm thử làm hành vi DVWA.',
 keep='Giữ ở profile mở rộng và khi cần minh chứng runtime. Không dùng Falco để bù nhãn sai từ runner HTTP. Giữ sự kiện thô phục vụ kiểm chứng.',
 metric='eBPF drop events, số runtime alert, liên kết HTTP-runtime có bằng chứng, thời gian xử lý và resource overhead theo kernel.'),
dict(name='Wazuh Manager',kind='Service wazuh-manager; 1,5 GiB, 2 CPU',source='sensors/wazuh/manager/ossec.conf; sensors/wazuh/compose.api.fragment.yml; scripts/wazuh_manager_console.ps1',
 role='Phân tích log qua decoder/rule Wazuh, nhận Docker lifecycle và agent. Bản này là manager-only; giao diện SOC của AHR-IDPS và Wazuh Dashboard là hai hệ thống khác nhau.',
 inp='Log Suricata/Falco đọc từ volume, Docker listener và agent transport. API quản trị 55000 là overlay tùy chọn, dùng HTTPS và xác thực.',
 out='alerts.json, rule ID, severity và trạng thái daemon/agent. Không có indexer hay Wazuh Dashboard container trong cấu hình mặc định.',
 flow='Manager phân tích nguồn, tạo alert dẫn xuất; Collector đưa về schema AHR-IDPS. 1514/1515 là transport/enrollment, không phải web UI.',
 algo=r'\mathrm{alert}_{W}=\mathrm{decode}(e)\land\mathrm{match}_{W}(e);\quad e\leadsto a_W\text{ phải giữ lineage}.',
 risk='Click một URL Dashboard không được triển khai sẽ báo site unreachable. Inference health dựa alert cũ có thể cho cảm giác manager còn sống. Alert lại từ sensor gây đếm trùng.',
 overlap='Wazuh chồng phần ingestion/rule management với AHR-IDPS. Giữ tùy chọn nếu môn học yêu cầu SIEM hoặc Windows agent; không cần cài indexer/dashboard chỉ để xem lại log.',
 test='Mở console manager hoặc API thực; kiểm tra daemon, agent, alert mới có marker; đối chiếu raw alert parent với EVE/Falco; kiểm tra loopback binding.',
 keep='Chuyển thành profile tùy chọn trong thiết kế đề xuất. Nếu bỏ phải điều chỉnh collector sources, health gate và script lib đang bắt buộc Wazuh; không chỉ stop service.',
 metric='Alert dẫn xuất/độc lập, last_event_age, decoder failure, agent active, API reachability và memory footprint.'),
dict(name='Windows Wazuh Agent tùy chọn',kind='Phần mềm native trên Windows; không nằm trong 18 service',source='sensors/wazuh/README.md; scripts/wazuh_acceptance.sh',
 role='Thu Security/System/Application log của Windows host khi phạm vi mở rộng tới host-auth. Không cần để chứng minh giám sát ứng dụng DVWA trên Linux.',
 inp='Agent native đã enroll đúng manager, quyền đọc Event Log, cấu hình channel và registration secret.',
 out='Event Windows gửi về Wazuh qua 1514; thông tin enrollment qua 1515. Event phải có agent identity khác manager để chứng minh host coverage.',
 flow='Cài agent, enroll, xác thực kết nối, tạo probe failed logon có kiểm soát, tìm alert từ đúng agent. Phải tách hoạt động host cá nhân khỏi campaign DVWA.',
 algo=r'\mathrm{HostCoverage}=\mathbb{1}[\mathrm{nativeAgent}\land\mathrm{newWindowsEvent}\land\mathrm{managerReceipt}].',
 risk='Mount /host trong container không thu Windows Event Log. Dữ liệu host không tương đương attack vào DVWA và có thể làm dataset mất tính nhất quán phạm vi.',
 overlap='Wazuh agent và Falco giám sát hai OS khác nhau. Không gộp chỉ số host-auth vào recall web attack nếu không có scenario định nghĩa trước.',
 test='Agent active trong manager, probe tài khoản lab không tồn tại, event timestamp mới và agent ID đúng; dữ liệu cá nhân không được đưa vào report artifact.',
 keep='Cắt khỏi cấu hình bài tập lớn mặc định; mô tả như phần mở rộng. Chỉ bật khi người nghiên cứu thực sự cần chứng minh coverage Windows.',
 metric='Agent connectivity, event freshness, receipt latency và số event liên quan trực tiếp phạm vi DVWA.'),
dict(name='Collector',kind='Service collector; 384 MiB, 1 CPU',source='collector/main.py; collector/base.py; collector/checkpoint.py; pipeline/config.yml',
 role='Tail JSONL từ các nguồn thật, giữ checkpoint và publish raw event vào Redis. Không tự kết luận attack; bảo toàn raw payload và provenance trước chuẩn hóa.',
 inp='Named volumes Nginx, Suricata, Falco, Wazuh; đường dẫn config; Redis auth. Docker events/system metrics collector đang bị tắt trong overlay.',
 out='security.events.raw, checkpoint SQLite, health registry và quarantine cho record lỗi. Event identity ổn định giúp không publish lặp khi restart.',
 flow='Đọc chỉ phần tăng thêm; giữ partial line tới khi hoàn chỉnh; theo dõi inode/rotation/truncation; publish rồi lưu offset phù hợp. START_AT_END bỏ backlog theo chủ đích.',
 algo=r'\mathrm{id}(e)=H(\mathrm{source},\mathrm{identity});\quad\mathrm{offset}_{n+1}\geq\mathrm{offset}_n\ \text{trong cùng generation}.',
 risk='Thu từ cuối file giúp realtime nhanh nhưng không phải cơ chế replay lịch sử. Collector chạy root để đọc permission nguồn dù cap_drop ALL; cần giới hạn mounts và xác nhận quarantine không mất dấu vết.',
 overlap='Collector là ingestion duy nhất vào AHR-IDPS. Không bật Docker events lần nữa nếu đã lấy từ Wazuh mà không có lý do phân biệt lineage.',
 test='Partial JSON, rotate file, truncate, restart checkpoint, duplicate event, Redis outage; test hiện có bao phủ nhiều trường hợp nhưng không thay real sensor acceptance.',
 keep='Giữ. Khi chuyển Wazuh/Falco sang tùy chọn phải disable source tương ứng trong config để health không báo nhầm lỗi.',
 metric='Read lag, publish count, duplicates suppressed, quarantine count, checkpoint age và heartbeat freshness.'),
dict(name='Redis Streams',kind='Service redis; 1 GiB, 1 CPU',source='infrastructure/redis/redis.conf; normalizer/normalizer.py; ai/fusion/infer.py',
 role='Event bus cho raw, normalized, prediction, incident, rule và response streams. Tách producer khỏi consumer; PostgreSQL mới là kho truy vấn lâu dài.',
 inp='XADD từ Collector/Normalizer/AI; consumer groups độc lập cho từng nhánh; auth và persistent volume redis_data.',
 out='XREADGROUP batch, PEL và ACK state. Các AI khác group cùng thấy một event; cùng group thì chia tải, không còn fan-out độc lập.',
 flow='Raw vào normalizer; normalized fan-out tới AI; predictions tới Fusion/Incident. Fusion bỏ qua prediction do chính nó tạo nên không có vòng lặp tự chấm vô hạn.',
 algo=r'\mathrm{lag}_g=\mathrm{produced}-\mathrm{delivered}_g;\quad\mathrm{ACK}(e)\Rightarrow\mathrm{durableProcessing}(e).',
 risk='Graph/Incident/Fusion đặt group về cuối và ACK pending khi startup có thể bỏ dữ liệu chưa xử lý. Existence file heartbeat không đo lag. AOF rewrite cần headroom RAM.',
 overlap='Không dùng Redis như kho báo cáo thứ hai; dữ liệu nghiên cứu query từ PostgreSQL/export. Không tính số message predictions là số mẫu độc lập.',
 test='Kiểm tra XPENDING, XINFO GROUPS, consumer chết trước ACK, restart không mất event; đối chiếu DB count và stream lag theo cùng cửa sổ.',
 keep='Giữ vì fan-out nhiều nhánh. Thêm retry/claim bounded và DLQ trước khi gọi pipeline đáng tin cậy; dùng replay group riêng thay đổi group live.',
 metric='used_memory, stream length, pending age, lag, evictions, AOF error và producer/consumer throughput.'),
dict(name='Normalizer',kind='Service normalizer; 384 MiB, 1 CPU',source='normalizer/normalizer.py; normalizer/mappings/; normalizer/schemas.py; normalizer/repository.py',
 role='Đưa các log khác schema về canonical event, ghi DB và publish normalized stream. Là ranh giới dữ liệu quan trọng nhất giữa sensor và model.',
 inp='Raw payload, source, timestamps và provenance từ Redis. Mappings Nginx/Suricata/Falco/Wazuh không được làm mất field dùng cho AI.',
 out='ahr.events, alerts/flows liên quan, security.events.normalized, sensor health và record quarantine khi không hợp lệ.',
 flow='Nhận raw; parse mapping; validate schema; lưu event deduplicate; publish normalized; ACK. Cần xử lý thứ tự DB/stream đúng khi crash giữa hai bước.',
 algo=r'e_{\mathrm{canonical}}=N_s(e_{\mathrm{raw}}),\quad\mathrm{event\_id}=H(\mathrm{stableSourceIdentity}).',
 risk='asyncpg JSON có thể trả chuỗi; downstream build_network_features chỉ đọc dict ở một số nhánh. Parse không thống nhất làm feature bằng 0 dù dữ liệu DB có giá trị.',
 overlap='Normalizer chỉ chuẩn hóa, không duplicate quyết định Fusion hay label campaign. Severity gốc cần lưu trước quy đổi thang chung.',
 test='Golden samples từng nguồn; unknown field; datetime; JSON string/dict parity; duplicate event; DB unavailable; publish fail sau commit; quarantine vẫn có raw.',
 keep='Giữ một schema version và một helper JSON decode dùng toàn bộ module. Cần contract tests train/export/infer trên chính event normalized.',
 metric='Schema failure rate, normalization latency, missing-field coverage, duplicates, source lag và DB/stream parity.'),
dict(name='PostgreSQL Event Store',kind='Service postgres; 1 GiB, 2 CPU',source='normalizer/migrations/; normalizer/repository.py; backend/services/repository.py',
 role='Lưu sự kiện, label, prediction, incident, rule version, validation và evidence metadata. Là nền tảng tái lập nghiên cứu và truy vấn SOC.',
 inp='Canonical event từ Normalizer; cập nhật score từ AI; label từ campaign; incident/response records. Các foreign key đòi model được đăng ký trước prediction.',
 out='SQL result cho API, training, exporter và evidence. Schema được nâng qua migration, không reset volume để giải quyết lỗi ứng dụng.',
 flow='Normalizer migrate; producer upsert theo identity; backend paginate/filter; trainer join event_labels; registry lưu artifact/checksum. JSONB phải được decode rõ ở client.',
 algo=r'\mathrm{UNIQUE}(\mathrm{event\_id}),\quad\mathrm{prediction.event\_id}\rightarrow\mathrm{events.event\_id}.',
 risk='Join nhiều label cho cùng event có thể nhân bản mẫu; serializer string/dict không nhất quán. Query graph/density trên cửa sổ hai chiều có thể thấy tương lai trong offline evaluation.',
 overlap='MariaDB phục vụ ứng dụng, PostgreSQL phục vụ nghiên cứu; giữ cả hai. Tránh lưu bản sao feature chưa version hóa ở nhiều bảng khó đồng bộ.',
 test='Migration trên DB mới; schema query; FK model; upsert idempotent; event có hai label; JSONB codec; backup/restore sample và paginate không trùng.',
 keep='Giữ. Khóa snapshot dataset và model version khi đánh giá, không query một DB đang thay đổi để làm kết quả holdout.',
 metric='DB size, query p95, connection pool, duplicate labels, orphan records và tỷ lệ sample có provenance đầy đủ.'),
dict(name='Feature Engineering',kind='Thư viện dùng trong trainer và inference; không có service riêng',source='feature_engine/network_features.py; feature_engine/window_features.py; scripts/train_kaggle_network.py',
 role='Chuyển event thành 21 đặc trưng network-v1. Encoding, thứ tự cột, window semantics và missing policy phải giống nhau giữa train và inference.',
 inp='Port, protocol, HTTP status, bytes/packets, source/destination presence, rule/severity và thống kê cửa sổ. Không dùng nhãn, marker, scenario_id làm feature.',
 out='Vector float32 theo NETWORK_FEATURES và feature version. Hiện window_features tính trên toàn bộ danh sách truyền vào; chưa có rolling window online tương đương.',
 flow='Runtime build_network_features trực tiếp trên mỗi event; trainer DB attach_window_features trước. Adapter Kaggle định nghĩa lại port_class và protocol flags, gây lệch semantics.',
 algo=r'x_i=\phi_v(e_i,W_{t_i-\Delta:t_i}),\quad\phi^{\mathrm{train}}_v=\phi^{\mathrm{infer}}_v;\quad W\text{ chỉ dùng quá khứ}.',
 risk='Probe cho cổng 389: runtime=2, offline=1. Adapter offline coi attack_type là rule; raw source tên suricata có thể bị dùng như IP khi thiếu src_ip. Aggregation trước split có thể dùng test context.',
 overlap='Chỉ duy trì một implementation feature contract; adapter bên ngoài phải gọi nó hoặc khai báo schema khác. Không giả định cùng 21 tên đồng nghĩa cùng 21 giá trị.',
 test='Cùng event qua export/train/infer phải cho vector bằng nhau; test cổng web/LDAP/high port, missing protocol, JSON string/dict, window boundary và marker removal.',
 keep='Giữ và ưu tiên sửa trước train lớn. Model Kaggle hiện chỉ được xem là benchmark offline tới khi parity được chứng minh.',
 metric='Feature parity, missing fraction, drift theo nguồn, schema hash và tỷ lệ event ngoài phân bố train.'),
dict(name='Network AI',kind='Service ai-network; 1 GiB, 2 CPU',source='ai/network/train_xgboost.py; ai/network/infer.py; ai/network/dataset.py; scripts/train_kaggle_network.py',
 role='XGBoost nhị phân benign/attack trên vector mạng. Hỗ trợ rule bằng điểm xác suất, không chứng minh payload đã thực thi thành công.',
 inp='Canonical features, model JSON, model registry và normalized stream. DB trainer dùng labels attack/benign; Kaggle Web Attacks dùng flow khác miền DVWA.',
 out='network_score, network_class, ai_predictions và Redis prediction với event_id/model version. Runtime ngưỡng 0,5 cho attack và 0,8 cho high.',
 flow='Load Booster; nhận event; build DMatrix; predict; update DB; publish; ACK. Batch/context cần thống nhất trainer; artifact named features phải match input names.',
 algo=r'\hat p_i=\sigma\!\left(\sum_{k=1}^{K}f_k(x_i)\right),\quad\hat y_i=\mathbb{1}[\hat p_i\geq0.5].',
 risk='DB trainer đo trên dtrain. Export thiếu port/http/network ở SELECT. Model có tên cột từ kit gặp DMatrix không tên trong infer và có thể ValueError; probe đã xác nhận dạng lỗi.',
 overlap='Giữ một network score, không dùng nhiều thuật toán như nhiều nguồn độc lập. RF/LR/HGB phục vụ benchmark offline cùng split, không cần bốn service realtime.',
 test='Model save/load, schema count/order/names, predict một event thật, heldout scenario không trùng train, load old/new artifact trong thư mục staging trước promotion.',
 keep='Giữ ở profile nghiên cứu; chỉ đưa vào đường quyết định chính sau sửa parity. XGBoost train dùng GPU, inference CPU là lựa chọn phù hợp tập nhỏ.',
 metric='F1/PR-AUC/FPR holdout, per-family recall, inference p95, drift và calibration; không dùng train accuracy làm chất lượng triển khai.'),
dict(name='Log AI',kind='Service ai-log; 1 GiB, 2 CPU',source='ai/logs/minilm.py; ai/logs/representation.py; ai/logs/train.py; ai/logs/infer.py',
 role='Mã hóa log thành vector 384 chiều rồi dùng Isolation Forest và MLP. Tên MiniLMEmbedder chỉ mô phỏng kích thước giao diện; thực tế là HashingVectorizer, không tải Transformer.',
 inp='Text từ source/type/category, rule, process, command, container, HTTP URI/status và severity; sanitizer loại một số timestamp/IP/hash nhưng chưa loại marker scenario đầy đủ.',
 out='log_score bằng max của anomaly score và class probability, predicted benign/suspicious, DB update và prediction stream.',
 flow='Hashing token, L2 normalize, fit IF trên benign, fit MLP trên hai lớp. Runtime tính -decision_function rồi clip(0,5 + anomaly_raw); lấy max với MLP.',
 algo=r'z=\mathrm{Hash}_{384}(T(e)),\quad s_{\log}=\max\{\mathrm{clip}(0.5-d_{IF}(z)),p_{MLP}(z)\}.',
 risk='Metric train chỉ dùng classifier.predict, không dùng hàm max thực tế của runtime. URI chứa marker và suffix có thể rò rỉ nhãn; cache embedding hiện không giới hạn kích thước.',
 overlap='Log AI và Network AI cùng có rule/severity nên không tự coi là hai nguồn độc lập. Cần benchmark bỏ rule/severity để xem AI học gì ngoài chữ ký.',
 test='Remove scenario marker trước representation; test IF+MLP runtime scorer trên benign holdout; cache budget; malformed message; empty text; threshold tuning trên validation.',
 keep='Giữ như baseline nhẹ, đổi mô tả báo cáo thành hashing embedding. Không cần chuyển sang LLM/MiniLM thật trước khi dataset và split đáng tin.',
 metric='Runtime F1/FPR, MLP-only vs IF-only vs combined, log template drift, cache size và per-source latency.'),
dict(name='Graph AI',kind='Service graph-builder; 1 GiB, 2 CPU',source='ai/graph/graphsage.py; ai/graph/graph_builder.py; ai/graph/infer.py',
 role='Xây graph entity theo cửa sổ/session và dự đoán nguy cơ từ embedding graph. Implementation là gom trung bình đặc trưng láng giềng cố định, pooling rồi StandardScaler+MLP.',
 inp='IP, container, process, HTTP, file, rule và quan hệ trong event. Cửa sổ mặc định 30 giây, session key có src port/flow_id nên có thể phân mảnh rất nhỏ.',
 out='graph_windows, graph_score, embedding, important_nodes/edges. Giải thích được xếp hạng degree/support, không phải attribution học được của GNN.',
 flow='Build node features và adjacency; nối self/mean neighbor; mean/max pool; fit MLP. Trainer đánh giá graph vừa train. Online query context từ DB theo thời gian.',
 algo=r'h_v=[x_v\Vert |N(v)|^{-1}\!\sum_{u\in N(v)}x_u],\quad g=[\mathrm{mean}_v h_v\Vert\mathrm{max}_v h_v\Vert q(G)].',
 risk='Không có lớp message passing trainable như GraphSAGE chuẩn. Có URI hash/marker và query cửa sổ tương lai, dễ làm offline lạc quan. Chưa chứng minh graph tốt hơn log/rule trên holdout.',
 overlap='Incident Engine đã dựng attack graph cho điều tra. Có thể giữ đồ thị điều tra nhưng tắt graph model, tránh người dùng hiểu graph visualization bắt buộc cần GNN.',
 test='Đo graph sizes và label distribution, split trước graph window, cùng campaign không vượt split; so sánh MLP graph stats với aggregation model; báo latency DB query riêng.',
 keep='Chuyển thành chức năng nghiên cứu tùy chọn, không nằm đường demo tối thiểu. Nếu sau này dùng PyTorch Geometric, đổi artifact/version và thiết kế deployment riêng.',
 metric='Graph/window count, node/edge distribution, isolated graph ratio, heldout F1, GNN ablation và query/inference latency.'),
dict(name='Fusion Engine',kind='Service fusion-engine; 1 GiB, 2 CPU',source='ai/fusion/scoring.py; ai/fusion/dataset.py; ai/fusion/train.py; ai/fusion/infer.py',
 role='Kết hợp rule, network/log/graph score và context thành risk cuối. Có baseline trọng số chuẩn hóa lại khi thiếu nguồn và meta-classifier XGBoost khi artifact sẵn.',
 inp='Predictions stream với event_id; DB event.ai; severity và event density. Các model con cập nhật bất đồng bộ nên một lượt fusion có thể chưa đủ điểm.',
 out='fusion_score, risk_level, breakdown, missing_scores, model version và prediction cho Incident Engine. Không tự thay firewall hay promote rule.',
 flow='Bỏ qua prediction có model chính Fusion để tránh vòng lặp; fetch event; tính component; ưu tiên meta-model, lỗi thì fallback weighted. Recompute khi điểm mới đến nhưng chưa có barrier/version đầy đủ.',
 algo=r's_F=\sum_{j\in A}\frac{w_j}{\sum_{k\in A}w_k}s_j,\quad w=(.25,.25,.20,.25,.05).',
 risk='context_score dùng labels.scenario_id/attack_type làm hint nên có nguy cơ leakage. Meta-model train từ prediction trên chính training events sẽ optimistic; density hai chiều thấy tương lai.',
 overlap='Fusion là nơi tính score duy nhất. Incident Engine chỉ gom theo timeline; không tạo nhiều định nghĩa risk mâu thuẫn. Các model có chung input không mặc định độc lập thống kê.',
 test='Thiếu từng nguồn vẫn finite; out-of-order predictions; không tự vòng lặp; model error có fallback và ghi method; so sánh đủ điểm với timeout thiếu điểm.',
 keep='Giữ weighted baseline trước, chỉ bật meta-model khi có out-of-fold scores và heldout validation. Loại test labels khỏi context trước đo.',
 metric='Missing-component rate, fusion lag, recalculation count, calibration, FPR cùng threshold và weighted vs stacked holdout.'),
dict(name='Incident Engine và attack graph điều tra',kind='Service incident-engine; 512 MiB, 1 CPU',source='correlation/correlator.py; correlation/sessionizer.py; correlation/attack_chain.py; correlation/incident_builder.py',
 role='Liên kết event thành incident, timeline và graph quan hệ để người vận hành điều tra. Đây là correlation dựa quy tắc/session, không phải Graph AI classifier.',
 inp='Predictions và event.ai từ DB; entities/IP/container/time, rule và severity. Một event có nhiều prediction không được trở thành nhiều event trong incident.',
 out='ahr.incidents, incident_events unique, attack_graph, timeline, AI/rule summary và security.incidents stream.',
 flow='Tạo correlation key; upsert incident; liên kết event idempotent; đọc lại các event; lấy max risk/severity; dựng chain/timeline và publish incident cập nhật.',
 algo=r'R_I=\max_{e\in I}R_e,\quad E_I=\bigcup\mathrm{event\_id};\quad\mathrm{count}(I)=|E_I|.',
 risk='Lấy max khiến một false positive duy trì risk cao; correlation key dựa IP/port có thể tách một chuỗi hoặc gộp client chung NAT. Exception có nhánh ACK rồi bỏ event mà chưa có retry/DLQ.',
 overlap='Giữ attack graph tại đây; Graph AI chỉ bổ sung score tùy chọn. Wazuh correlation không nên tạo incident trùng nếu cùng parent sensor event.',
 test='Một event phát ba model prediction vẫn count=1; sự kiện đến sai thứ tự; NAT clients; incident timeline ISO8601; lỗi DB không ACK mất bằng chứng.',
 keep='Giữ làm đầu mối điều tra. Bổ sung finalized/reviewed state và risk recalculation để phản hồi false positive có tác dụng; tăng observability cho retries.',
 metric='Incident dedup, link precision, event_count, age/open time, correlation latency và tỷ lệ incident được analyst xác nhận.'),
dict(name='Rule Generator',kind='Service rule-generator; 512 MiB, 1 CPU',source='rule_engine/generator.py; rule_engine/pattern_miner.py; rule_engine/abstraction.py; rule_engine/templates/',
 role='Khai phá hành vi lặp có score cao, trừ sample-specific identifier rồi render candidate Suricata/Falco/Wazuh. Hiện dùng template xác định, không gọi LLM.',
 inp='Event trong cửa sổ gần nhất, fusion confidence, min_support, cluster key và các field HTTP/process/container. Việc dữ liệu lặp không tự chứng minh độc hại.',
 out='ahr.rules candidate, rule_versions content/hash/metadata, genti_context và security.rules. Không tự nạp rule vào sensor.',
 flow='Lọc confidence; cluster behavior; abstract URI/method; chọn engine; render; kiểm tra identifier; store candidate. SID từ hash có không gian hữu hạn nên cần phát hiện collision.',
 algo=r'\mathcal C=\{e:s_F(e)\geq\tau\},\quad |C_j|\geq m;\quad r_j=\mathrm{Template}(\mathrm{Abstract}(C_j)).',
 risk='Template chỉ có URI có thể khớp benign cùng challenge. URI generalize dấu * không tự thành wildcard trong content Suricata. Upsert hiện có thể đưa rule tồn tại về candidate và sửa version1.',
 overlap='Rule Generator đề xuất luật, Validator chứng minh, lifecycle phê duyệt. Không đặt cùng một logic tự-block ở cả generator và response.',
 test='Đổi IP/UUID không đổi semantic rule; benign cùng URI không khớp quá rộng; duplicate không reset active rule; SID collision và version history bất biến.',
 keep='Giữ vì là đóng góp luật tự sinh, nhưng thu hẹp target Suricata trước. Falco/Wazuh template generation chỉ bật khi có engine-native validation.',
 metric='Candidate support, duplicate ratio, generation latency, acceptance/rejection, false-positive shadow và rule version lineage.'),
dict(name='Validator CoVe và vòng đời luật',kind='Module chạy theo lệnh; không có container riêng',source='rule_engine/validator.py; rule_engine/genti.py; rule_engine/lifecycle.py',
 role='Thực hiện gate cú pháp, logic, false positive trước trạng thái shadow; active cần approved trong lifecycle. GenTI-lite mới thêm context và composite score nhưng chưa là tái lập đầy đủ paper.',
 inp='Rule engine/content/version/pattern; event có nhãn; thresholds; binary Suricata/Falco hoặc XML Wazuh. DB pattern JSON cần decode trước dùng.',
 out='rule_validation_runs, replay/performance metrics, genti_cove, rule status shadow/rejected. Shadow hiện chủ yếu là trạng thái trong DB, chưa chứng minh sensor đã load.',
 flow='Mark validating; syntax check; replay heuristic; logic_check; ngưỡng FPR/precision/recall/support; store result. Binary absent sẽ dùng structural fallback nên độ tin cậy giảm mạnh.',
 algo=r'\mathrm{Accept}=S\land L\land(FPR\leq\epsilon)\land(P\geq p_0)\land(R\geq r_0)\land(TP\geq m).',
 risk='rule_matches Suricata nhận /login dù luật chỉ /only-this-path; không replay thật điều kiện content. genti.logic_check nhận pattern dạng str gây AttributeError; zero benign khiến FPR=0 không có ý nghĩa.',
 overlap='CoVe là cấu trúc gate, không tự khiến evaluator đúng. Chấm composite cao không thay parser+PCAP replay và shadow sensor metrics.',
 test='Candidate sai URI phải không match; thiếu benign phải insufficient_data; parser thật ghi engine_used; exception reset validating; manual approval không tự bypass parser.',
 keep='Giữ, nhưng tạm chỉ xuất candidate report. Chặn promotion khi mới structural/heuristic validation; bổ sung engine-native replay trước gọi rule dùng được.',
 metric='Parser native pass rate, benign count, DR/FPR PCAP thật, duplicate/conflict result và deployment receipt/version/hash.'),
dict(name='Response Engine',kind='Service response-engine; 256 MiB, 0,5 CPU',source='response/engine.py; response/policy.py; response/firewall.py; response/container.py',
 role='Quyết định log/alert/rate-limit/block/isolation theo policy và tạo audit/evidence. Mặc định alert_only; chỉ có điểm AI cao không đủ quyết định containment nghiêm trọng.',
 inp='Incident risk/severity, matched rules, AI summary và graph/runtime relations; env policy automatic_block/isolation mặc định false.',
 out='Response record, policy reason, TTL, rollback metadata và evidence. firewall/container helpers hiện trả plan có applied flag, không gọi iptables/Docker API thực.',
 flow='Đọc incident; kiểm eligibility; giới hạn mode; tạo record và evidence; kiểm expired rollback. Mỗi hành động cần phân biệt planned, simulated, applied và verified.',
 algo=r'B=(R_I\geq\tau_R)\land(\mathrm{rule}\lor n_{AI}\geq2\lor\mathrm{runtimeLink});\quad\mathrm{mode}=alert\_only\Rightarrow\ell\leq1.',
 risk='applied=True trong dataclass không chứng minh firewall đã chặn hay container đã bị disconnect. Hai AI cùng input không phải nguồn độc lập; graph association tự tạo không đảm bảo quan hệ nhân quả.',
 overlap='Không gộp rule promotion với response action. Để lab ổn định, cắt block/isolation khỏi demo mặc định và dùng alert+evidence có thể kiểm chứng.',
 test='Policy thấp/cao, missing model, mode alert_only, TTL; nếu tương lai apply thật phải có before/after connection probe, rollback receipt và bảo vệ database.',
 keep='Giữ alert_only và evidence, đánh dấu containment là kế hoạch mô phỏng trong báo cáo. Chưa tuyên bố prevention thực tế.',
 metric='Alert delivery, action reason, duplicate actions, evidence success, TTL expiry và actual-effect verification nếu triển khai sau.'),
dict(name='Evidence Bundle',kind='Thư viện xuất file được Response gọi',source='response/evidence.py; normalizer/migrations/007_phase13_response_engine.sql',
 role='Đóng gói incident, event, prediction, rule match, graph/timeline và checksum để analyst xem lại. SHA-256 phát hiện thay đổi bytes so với manifest, không xác nhận ground truth.',
 inp='Incident_id và các bản ghi DB liên quan; thư mục evidence có quyền ghi; thời gian xuất và model/rule version.',
 out='incident.json, events.jsonl, timeline, flow/process/container files, manifest.json và bundle_sha256. Một số file không có event được xuất rỗng.',
 flow='Query incident/event; serialize timestamp/JSON; viết file; hash từng file; hash manifest chuẩn hóa. Cần snapshot và atomic finalize để không xuất nửa bộ.',
 algo=r'h_k=\mathrm{SHA256}(b_k),\quad H_B=\mathrm{SHA256}(\mathrm{CanonicalJSON}(\{p_k,h_k,n_k\})).',
 risk='File tên process_tree hiện là danh sách process object, chưa phải cây nhân-quả hoàn chỉnh. Snapshot DB đang thay đổi có thể làm timeline/predictions không nhất quán.',
 overlap='Evidence là xuất hiện trạng, không cần thêm forensic platform nặng. Giữ raw_event và manifest thay vì sao chép mọi volume sensor mỗi incident.',
 test='Sửa một byte phải mismatch; timestamp serializable; incident không tồn tại; empty source; rerun cùng incident không trộn dữ liệu cũ; chỉ final sau đủ file.',
 keep='Giữ là đầu ra hữu ích cho bài tập lớn. Đổi tên file/description đúng nội dung, thêm snapshot/run_id và đường dẫn model hash.',
 metric='File count, missing source, export duration, hash verification rate, snapshot timestamp và artifact version coverage.'),
dict(name='FastAPI Backend',kind='Service backend; 512 MiB, 1 CPU',source='backend/main.py; backend/services/repository.py; backend/api/; backend/websocket/',
 role='Cung cấp API REST, WebSocket và dashboard static từ dữ liệu PostgreSQL/Redis. Là cửa sổ quản trị chứ không thay cảm biến.',
 inp='DB session, Redis, các endpoint query và dashboard/dist. Nginx app overlay proxy tới port 8000 nội bộ, không publish trực tiếp.',
 out='Events, alerts, incidents, models, rules, responses, overview/health và WebSocket. Có endpoints nghiên cứu experiments cần sửa cách tính metrics.',
 flow='Filter/paginate SQL, serialize JSON/datetime, stream update và phục vụ bundle. Một request health chỉ test DB/Redis không đánh giá đầy đủ AI/sensor freshness.',
 algo=r'\mathrm{UIData}=\mathrm{Serialize}(\mathrm{Query}_{filters,limit,offset}(D));\quad\mathrm{fresh}=t_{now}-t_{last}<\Delta.',
 risk='system/health gán DVWA/Nginx/MariaDB up cố định; AI up khi từng có prediction trong DB nên trạng thái cũ có thể hiển thị xanh. Không dùng làm bằng chứng mọi node còn sống.',
 overlap='Chỉ một API cho dashboard; Wazuh Manager API là control-plane khác. Không mở thêm admin server chỉ để đọc cùng DB.',
 test='API count/timestamps đúng DB; SQL filters; datetime WebSocket; Redis down có degraded; health freshness; 404/empty state không crash.',
 keep='Giữ. Tách health live/readiness/history rõ; Experiments phải ghi measured/estimated hoặc disabled trước báo cáo nghiên cứu.',
 metric='REST p95, WS reconnect, serialization errors, DB query p95, stale health entries và rate of 5xx.'),
dict(name='SOC Dashboard',kind='React bundle do backend phục vụ; không phải service Compose riêng',source='dashboard/src/; dashboard/src/components/AttackGraph.tsx; backend/main.py',
 role='Tổ chức Giám sát, Điều tra, Quản trị để xem dữ liệu và đánh giá chất lượng vận hành. AttackGraph SVG vẽ quan hệ từ incident, không tự suy luận GNN.',
 inp='API JSON và WebSocket từ cùng Nginx. Bundle phải build đúng base path /dashboard/ và hợp với backend schema.',
 out='Event/alert tables, incident timeline/graph, AI/model/rule metadata, response và system health. Giá trị hiển thị không có nguồn đo phải là unknown.',
 flow='Mở overview; lọc marker; xem alert; mở incident; inspect rule/AI breakdown; xuất evidence. Link Wazuh phải mô tả manager API/console, không mặc định dashboard vắng mặt.',
 algo=r'\mathrm{ViewState}\in\{loading,empty,ready,stale,error\};\quad\mathrm{Unknown}\neq0.',
 risk='Số liệu ước lượng từ backend hoặc health lịch sử được vẽ đẹp vẫn là dữ liệu thiếu độ đúng. Graph thật ở mức SVG không chứng minh model graph có hiệu quả.',
 overlap='Gộp overview/live/alerts theo workflow triage thay vì nhiều màn hình trùng. Ẩn graph-model/experiments/containment khi profile không bật.',
 test='Build TypeScript; load API/WS; empty DB; missing AI; stale sensor; graph không có edges; URL manager không gọi là Wazuh Dashboard.',
 keep='Giữ ba view hiện tại và giảm panel không có dữ liệu đo. Không cần thêm UI mới trước khi sửa semantics E1-E9/health.',
 metric='Page/API errors, time to open incident, missing-value disclosure, WS recovery và khả năng truy vết tới event/evidence.'),
dict(name='Dataset Exporter và chia tập',kind='Module theo đợt, chạy trong backend',source='dataset_collection/exporter.py; dataset_collection/db.py; scripts/collect_dvwa_training_dataset.ps1',
 role='Liên kết request thử nghiệm với event, xuất dataset và gán split. Nhiệm vụ là provenance và dữ liệu nghiên cứu có thể tái lập, không tự huấn luyện model.',
 inp='Scenario start/end, marker, attack_type/label và event store. Nhãn hiện chỉ join raw_event chứa marker trong cửa sổ thời gian.',
 out='Raw/normalized/network/log JSONL, labels/splits CSV, Parquet, manifest và graph artifact .pt. .pt hiện là pickle graph đơn giản, không phải tensor PyTorch đã kiểm chứng.',
 flow='Load labeled event, sắp scenario theo thời gian, chia 60/15/10/10/5 rồi xuất. Tên unknown_test hiện chỉ do vị trí cuối, không bảo đảm attack type bị giữ ngoài train.',
 algo=r'\mathcal S_{tr}\cap\mathcal S_{te}=\varnothing;\quad\mathrm{unknown}(a)\Rightarrow a\notin\mathcal A_{train}.',
 risk='SELECT thiếu src_port,dst_port,http,network,process,file nên mất đặc trưng. Falco không có marker khó nhận label; graph có thể nghèo dù raw có dữ liệu. Split chưa được DB trainer sử dụng.',
 overlap='Duy trì một manifest nguồn và split bất biến; không dùng nhiều dataset flows JSONL khác schema nhưng cùng tên version. Phân biệt request, event, incident.',
 test='Export/reimport round trip giữ field; scenario không cross split; label conflict; attack family heldout thật; balance đa dạng; checksum và source version.',
 keep='Giữ, ưu tiên sửa SELECT và explicit split policy. Ghi unknown theo thiết kế holdout family/session, không theo tên thư mục tự suy.',
 metric='Scenario count, independent groups, retained schema fields, event-label confidence, duplicates và unseen-family integrity.'),
dict(name='Model Registry và artifact promotion',kind='Thư viện + bảng PostgreSQL; không có daemon riêng',source='ai/network/registry.py; scripts/register_existing_models.sql; experiments/models/',
 role='Gắn model identity, feature schema, checksum và metric với artifact. Điều kiện nạp model cần vượt ngoài việc file tồn tại và DB có model_id.',
 inp='JSON/Joblib artifact, metadata, hash, feature version, dataset manifest và evaluation report. Joblib chỉ load artifact do nhóm tin cậy tạo.',
 out='ahr.models, model_metrics và artifact_uri cho runtime. Hiện register_existing_models.sql dùng metadata shipped-artifact và chưa kiểm tra checksum file thực tế.',
 flow='Trainer lưu file rồi register active; runtime load lúc process start. ID prediction hiện chỉ model_id:event_id nên retrain cùng ID có thể ghi đè lịch sử dự đoán.',
 algo=r'\mathrm{Promote}(m)\Rightarrow H(m)=H_{meta}\land v_{features}=v_{runtime}\land\mathrm{HoldoutPass}(m).',
 risk='ON CONFLICT chưa cập nhật đầy đủ version/name/type; schema hash chưa enforce. Train ghi trực tiếp active file có thể làm service restart nạp artifact chưa hoàn chỉnh.',
 overlap='Gộp registry với event DB và local artifacts phù hợp lab; không cần MLflow server riêng khi chưa có repeatable run.',
 test='Load staging artifact; compare schema/names; checksum; sample prediction; register immutable version; restart verify model_loaded; rollback file và DB version.',
 keep='Giữ registry nhưng promotion thủ công có staging, atomic rename và measured holdout. Lưu prediction khóa cả model version.',
 metric='Model hash match, active version consistency, load failures, rollback time, dataset snapshot và holdout metric provenance.'),
dict(name='Experiments và benchmark E1-E9',kind='API /experiments/run và script run_ablation.sh',source='backend/api/experiments.py; scripts/run_ablation.sh; experiments/results/results.csv',
 role='Theo thiết kế sẽ so sánh rule-only, từng AI và hybrid. Hiện implementation tạo precision/recall/FPR/AUC/resource từ công thức dựa số alert/prediction, không chạy dự đoán từng mẫu.',
 inp='Count mẫu/attack/benign, số predictions/rule alerts/generated shadow. Không có test label-score pairs hay measured GPU/CPU thực cho từng cấu hình.',
 out='CSV và model_metrics có số ước lượng; E7 và E8 hiện cấu hình boolean giống nhau nên không phải ablation khác biệt.',
 flow='Dataset stats vào _metrics_for; tính recall=0,25+0,35*rule_signal+0,30*ai_signal+bonus, rồi write DB/CSV. Đây là giả định mô hình hóa, không phải kết quả thực nghiệm.',
 algo=r'\widehat R_{\mathrm{heuristic}}=\min(.99,.25+.35s_r+.30s_{AI}+b),\quad\widehat R_{\mathrm{heuristic}}\neq\frac{TP}{TP+FN}.',
 risk='Dashboard hoặc báo cáo có thể trình bày ước lượng như độ chính xác thật. generated_bonus tự tăng metric theo số rule không chứng minh rule cải thiện unknown detection.',
 overlap='Giữ benchmark offline train_kaggle_network chỉ như baseline dữ liệu ngoài, nhưng sửa parity/leakage trước dùng; bỏ API tự sinh điểm khỏi kết quả khoa học.',
 test='Chỉ nhận y_true/y_score heldout theo event_id; confusion matrix thật; same sample IDs cho các model; latency đo đồng hồ, CPU/GPU đo công cụ; missing run phải failed.',
 keep='Tạm vô hiệu cho sử dụng kết quả nghiên cứu; thay bằng evaluator offline measured. Ghi rõ đây là phát hiện kiểm toán, chưa sửa API trong nhiệm vụ báo cáo.',
 metric='TP/FP/TN/FN, PR-AUC, group bootstrap CI, per-family recall, latency percentiles và resources measured từng run.'),
dict(name='LLM và GenTI-lite',kind='GenTI-lite là module xác định; chưa có LLM inference service',source='rule_engine/genti.py; docs/paper_genti_analysis.md; 2606.05844v1.pdf',
 role='Bài GenTI gợi ý rule synthesis từ payload+CTI và CoVe. AHR-IDPS hiện chỉ triển khai mapping taxonomy, difficulty và gate deterministic; không có token generation, weights hoặc QLoRA.',
 inp='Pattern trừ identifier, URI/process/event anchors và metadata. CTI mapping là heuristic DVWA; một endpoint tên sqli không tự chứng minh CWE đã được khai thác.',
 out='genti_context, threat_context, difficulty, verification stages và composite score nội bộ. Chưa có GTI corpus đã tải/kiểm giấy phép hoặc LLM model registered.',
 flow='Build context; render template; syntax/logic/replay gates. Nếu thêm LLM sau này: candidate JSON theo schema, timeout, bounded repair, local evidence và parser/replay độc lập.',
 algo=r'p_\theta(r\mid P,S,C)=\prod_t p_\theta(r_t\mid r_{<t},P,S,C);\quad\theta\text{ chưa tồn tại trong runtime hiện tại}.',
 risk='Composite AHR dùng precision thay CTI coverage, logic boolean thay semantic similarity nên không đồng nhất metric paper. Chưa có vòng tinh chỉnh LLM hoặc native replay nên không gọi tái lập GenTI.',
 overlap='Không cần thêm LLM để sửa dữ liệu và train parity. RTX 3050 4 GB không phù hợp mặc định fine-tune DeepSeek-7B như cấu hình 8 A100 của paper.',
 test='LLM optional phải offline/local by default, structured output, parser reject bad rule, bounded feedback; không tự ghi active file. Đối chiếu từng thuật ngữ paper với code thật.',
 keep='Giữ GenTI-lite như ý tưởng nghiên cứu có giới hạn; ghi rõ LLM/QLoRA là thiết kế tương lai, chưa chạy. Ưu tiên evidence+rule validation trước model lớn.',
 metric='Native syntax pass, semantic intent, CTI mapping precision, benign replay FPR, rule coverage và cost; chưa gán số paper thành số AHR-IDPS.'),
]

PREAMBLE = r'''\documentclass[12pt,a4paper]{article}
\usepackage[margin=2.1cm,headheight=16pt]{geometry}
\usepackage{fontspec}
\IfFontExistsTF{Times New Roman}{\setmainfont{Times New Roman}}{\setmainfont{TeX Gyre Termes}}
\IfFontExistsTF{Arial}{\setsansfont{Arial}}{\setsansfont{TeX Gyre Heros}}
\IfFontExistsTF{Consolas}{\setmonofont{Consolas}[Scale=.86]}{\setmonofont{TeX Gyre Cursor}[Scale=.86]}
\usepackage{amsmath,amssymb,booktabs,tabularx,array,longtable,enumitem,fancyhdr,xcolor,hyperref,fvextra}
\hypersetup{colorlinks=true,linkcolor=black,urlcolor=blue,pdftitle={Kiểm toán chức năng AHR-IDPS},pdfauthor={Nhóm AHR-IDPS}}
\setlength{\parindent}{0pt}\setlength{\parskip}{6pt}
\setlist{nosep,leftmargin=1.6em,topsep=4pt}
\emergencystretch=3em
\pagestyle{fancy}\fancyhf{}
\fancyhead[L]{\small AHR-IDPS / Kiểm toán chức năng}
\fancyhead[R]{\small 08/10/2026}
\fancyfoot[C]{\small\thepage}
\newcommand{\block}[2]{\subsection*{#1}#2\par}
\newcommand{\pathref}[1]{\texttt{\small\detokenize{#1}}}
\DefineVerbatimEnvironment{Code}{Verbatim}{fontsize=\small,breaklines=true,breakanywhere=true}
\renewcommand{\contentsname}{Mục lục}
\makeatletter
\renewcommand*\l@section{\@dottedtocline{1}{0em}{2.5em}}
\makeatother
\begin{document}
\begin{titlepage}
\vspace*{1.5cm}
{\Large\bfseries BÁO CÁO KIỂM TRA HỆ THỐNG\par}
\vspace{.5cm}{\Huge\bfseries AHR-IDPS\par}
\vspace{.8cm}{\Large Chức năng các node và thuật toán AI\par}
\vspace{.8cm}Hybrid Intrusion Detection and Response System kết hợp luật tự sinh và mô hình AI thích nghi cho ứng dụng web DVWA.\par
\vspace{.8cm}Tài liệu kiểm toán hiện trạng mã nguồn, đề xuất thu gọn kiến trúc, hướng dẫn khởi động, huấn luyện CPU/GPU và tự sinh dataset có truy vết.\par
\vfill
\textbf{Phạm vi:} 18 service Compose và 11 chức năng hỗ trợ. Mỗi chức năng có đúng hai trang: một trang thiết kế/contract và một trang đánh giá/vận hành.\par
\textbf{Trạng thái:} kiểm tra cấu hình và unit/probe trong bộ nhớ; Docker Engine đang tắt nên chưa nghiệm thu vận hành live.\par
\textbf{Máy khảo sát:} Intel i5-12500H, 12 core/16 thread; RAM gần 32 GB; RTX 3050 Laptop 4 GB VRAM.\par
\textbf{Ngày lập:} 08/10/2026. Bản nguồn LaTeX độc lập được bàn giao cùng bản PDF.\par
\end{titlepage}
{\small\tableofcontents}
\clearpage
'''

def page(title, body):
    return '\\clearpage\n\\section{'+esc(title)+'}\n'+body+'\n'

def node_pages(index, n):
    a = '\\clearpage\n\\section{'+esc(f'N{index:02d} {n["name"]}')+'}\\label{node'+str(index)+'start}\n'
    a += '\\textbf{Trang chức năng 1/2: thiết kế và hợp đồng dữ liệu.}\\par\n'
    a += '\\textit{'+esc(n['kind'])+'}\\par\n'
    for title,key in [('Vai trò trong đề tài','role'),('Đầu vào và điều kiện tiền đề','inp'),('Đầu ra quan sát được','out'),('Quy trình xử lý thực tế','flow')]:
        a+='\\block{'+title+'}{'+esc(n[key])+'}\n'
    a+='\\block{Mô hình xử lý}{\\begin{equation*}'+n['algo']+'\\end{equation*}}\n'
    a+='\\block{Nguồn kiểm chứng}{'+ '\\par '.join('\\pathref{'+s.strip()+'}' for s in n['source'].split(';'))+'}\n'
    a+='\\vfill\\textbf{Ranh giới trách nhiệm:} đầu ra của node cần được kiểm tra bằng dữ liệu và thời gian cụ thể; sự tồn tại của file, score hoặc UI không thay thế kiểm thử xuyên luồng.\n'
    a+='\\clearpage\\subsection*{'+esc(f'N{index:02d} {n["name"]}')+'}\\label{node'+str(index)+'second}\n'
    a+='\\textbf{Trang chức năng 2/2: đánh giá và vận hành.}\\par\n'
    for title,key in [('Sai lệch và tình huống lỗi cần lưu ý','risk'),('Chồng chéo và phương án thu gọn','overlap'),('Quy trình kiểm thử chấp nhận','test'),('Quyết định đề xuất','keep'),('Các chỉ số cần giám sát','metric')]:
        a+='\\block{'+title+'}{'+esc(n[key])+'}\n'
    a+='\\block{Bằng chứng cần lưu khi nghiệm thu}{Ghi phiên bản cấu hình/mã nguồn, timestamp, marker hoặc event ID, thao tác đã chạy, đầu ra thực tế và kết luận pass/fail. Với node tùy chọn, đánh dấu không bật và mô tả ảnh hưởng tới downstream; không đổi giá trị thiếu thành số 0.}\n'
    a+='\\vfill\\textbf{Phân loại kết luận:} các lỗi mô tả ở đây là kết quả đọc mã và probe được chỉ định; phép đo runtime phải bổ sung sau khi Docker Engine hoạt động.\\label{node'+str(index)+'end}\n'
    return a

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    parts=[PREAMBLE]
    parts.append(page('Kết luận điều hành và giới hạn kiểm tra',r'''
\block{Kết luận chính}{Nên thu gọn theo profile vận hành thay vì xóa chức năng vội. Hệ thống có nền tảng thu thập, lưu trữ, dashboard và tương quan; các vấn đề ưu tiên nằm ở độ đúng của dataset, feature contract, evaluator và lifecycle rule. Tăng GPU hoặc dữ liệu không tự sửa những vấn đề này.}
\begin{enumerate}
\item Giữ DVWA, proxy, DB, event bus, sensor mạng, pipeline, API/dashboard và incident workflow.
\item Wazuh/Windows agent chỉ bật khi cần SIEM/host coverage; Graph AI chỉ bật cho ablation nghiên cứu. Giữ attack graph điều tra dù graph model tắt.
\item Giữ Response alert/evidence; containment hiện là plan/audit wrapper, chưa chứng minh chặn thực tế.
\item Rule tự sinh vẫn là đóng góp chính nhưng cần parser và replay native; GenTI-lite chưa là LLM và chưa tái lập paper.
\item Không sử dụng E1--E9 API hiện tại như số liệu nghiên cứu; số liệu ở đó được ước lượng theo count.
\end{enumerate}
\block{Kết quả kiểm tra đã thực hiện}{Compose hợp nhất hợp lệ: 18 service, tổng mem\_limit 13,5 GiB. Bộ unit được chạy trên Windows: 73 pass, 1 fail do chuỗi đường dẫn Linux khác Windows. Năm probe về feature/schema/replay đã tái hiện lỗi. Không chạy traffic tấn công live, không train/ghi đè model và không cắt bỏ service hiện có trong nhiệm vụ đánh giá.}
\block{Cách đọc báo cáo}{N01--N29 là bản mô tả chi tiết hai trang mỗi chức năng. Các phần sau là runbook, lịch train, dataset, công thức thuật toán và kế hoạch chỉnh sửa. Phân biệt rõ hiện trạng, đề xuất và kết quả đo; mọi con số paper hoặc lần test trước không phải nghiệm thu hệ thống hôm nay.}
'''))
    for i,n in enumerate(NODES,1): parts.append(node_pages(i,n))
    parts += appendices()
    parts.append('\\end{document}\n')
    tex=OUT/'ahr-idps-system-audit.tex'
    tex.write_text(''.join(parts),encoding='utf-8')
    (OUT/'ahr-idps-node-index.json').write_text(json.dumps([dict(id=f'N{i:02}',name=n['name']) for i,n in enumerate(NODES,1)],ensure_ascii=False,indent=2),encoding='utf-8')
    print('Created standalone LaTeX; nodes:',len(NODES))


def appendices():
    p=[]
    p.append(page('Phát hiện ưu tiên sửa trước khi train lớn',r'''
\block{F01 Số liệu Experiments không phải phép đo}{Trong backend/api/experiments.py, hàm \_metrics\_for tính recall, precision, FPR, AUC, CPU/RAM/GPU bằng hằng số và số lượng alert/prediction. Không có đối chiếu y\_true/y\_score theo mẫu. E7/E8 dùng cùng cấu hình boolean. Kết luận: không đưa CSV này vào kết quả khoa học; thay evaluator trên cùng holdout snapshot.}
\block{F02 Dataset runner cũ chưa xác nhận login}{dataset\_collection/traffic.py tạo AsyncClient nhưng không đăng nhập. Request challenge có thể chuyển hướng tới login và vẫn được xem là thành công vì status cuối là 200. Command injection cũ dùng GET trong khi challenge cần POST. file\_upload chỉ GET trang upload. Cần xác minh challenge reached và tách nhãn ý định khỏi nhãn khai thác thành công.}
\block{F03 Train và test đang trùng}{Network DB trainer predict dtrain; Log trainer predict x vừa fit; Graph evaluate graphs vừa fit; Fusion predict dtrain. Exporter có split nhưng các trainer DB không đọc split. Accuracy/F1 này là train fit, không chứng minh tổng quát hóa. Giữ cả campaign/session trong một split, fit preprocessing trên train và lưu test bất biến.}
\block{F04 Đặc trưng và artifact không tương thích đầy đủ}{Cổng 389 có runtime port\_class=2 nhưng adapter offline=1. Adapter có thể lấy source như IP và attack\_type như has\_rule. Trong JSONL local, trường attack\_type này là nhãn nghiên cứu: dùng làm feature là leakage. Window train tính toàn tập, infer đơn lẻ không attach. Named XGBoost model có thể ValueError khi DMatrix runtime không có feature\_names. Cùng 21 tên không đảm bảo đúng semantics.}
\block{Ưu tiên}{P0: thay số liệu ước lượng bằng measured; sửa nhãn/login; dùng một feature implementation; staging artifact + smoke prediction trước promotion. Những việc này phải xong trước tối ưu tốc độ train.}
'''))
    p.append(page('Phát hiện về rule và phản ứng',r'''
\block{F05 Export mất field và nhãn thiếu runtime}{Exporter SELECT bỏ src\_port, dst\_port, http, network, process và file\_details dù model cần. Labels chỉ raw\_event LIKE marker trong cửa sổ, nên Falco syscall thường không được nối. Một số event Nginx, Suricata, Wazuh là nhiều góc nhìn cùng request chứ không phải nhiều mẫu độc lập.}
\block{F06 Replay heuristic chưa chứng minh luật}{Probe luật chỉ có /only-this-path vẫn được rule\_matches đánh khớp với /login.php. Structural fallback Suricata chỉ nhìn prefix, SID và dấu ngoặc. XML parse Wazuh cũng không tương đương decoder/rule semantics. CoVe hiện bao quanh heuristic nên không thể kết luận rule đã qua kiểm thử engine.}
\block{F07 GenTI context JSON và state}{asyncpg mặc định có thể trả JSONB dạng chuỗi; logic\_check gọi pattern.get gây AttributeError, probe đã tái hiện. Exception sau status validating chưa có đảm bảo phục hồi. Upsert generator có thể reset rule cũ về candidate và ghi lại version1. Cần version bất biến, decode và transaction/rollback state.}
\block{F08 Shadow và active chưa là deployment receipt}{Chuyển status DB không tự ghi generated.rules, không tự reload sensor và chưa có hash/version xác nhận engine đã nạp. Phê duyệt active trong lifecycle chỉ là đổi DB state. Để sử dụng thật cần parser native, replay, atomic deployment, reload probe và rollback.}
\block{F09 Containment là kế hoạch}{temporary\_lab\_block và safe\_isolation\_plan tạo dataclass/audit wrapper; applied=True chưa tạo firewall rule hay Docker network disconnect. Báo cáo chỉ nên tuyên bố alert/evidence và planned containment. Giữ alert\_only là hợp lý cho lab ổn định.}
\block{Ưu tiên}{P0/P1: không promote rule dựa heuristic; không mô tả containment như đã thi hành. Giữ raw/evidence để kiểm chứng, triển khai parser/replay theo một engine Suricata trước.}
'''))
    p.append(page('Phát hiện về sức khỏe và tính thích nghi',r'''
\block{F10 Health mang tính lịch sử}{system/health gán up cho DVWA/Nginx/MariaDB, đánh AI up khi từng có prediction. AI Compose healthcheck chỉ kiểm tra file tồn tại. Phải đo heartbeat age, process, lỗi mới và consumer lag. Kết quả database cũ không xác nhận service sống.}
\block{F11 Mất backlog khi restart}{Graph/Fusion/Incident có startup reset group tới cuối và ACK pending. Việc này giúp realtime nhanh nhưng có thể bỏ event chưa xử lý. Incident có nhánh lỗi ACK rồi tiếp tục mà không DLQ. Muốn ổn định cần retry bounded, claim pending, quarantine và replay group riêng.}
\block{F12 Fusion có rò rỉ context và score chưa hoàn tất}{context\_score có scenario\_id/attack\_type hint; density/graph query dùng cửa sổ hai phía. Không được đưa nhãn test hay event tương lai vào quyết định causal. Stacking phải dùng out-of-fold prediction của base models. Tính lại risk khi từng model đến cần score version và thời hạn chờ.}
\block{F13 Thuật ngữ và thích nghi}{MiniLM thực tế HashingVectorizer; GraphSAGE là aggregation cố định+MLP; GenTI-lite không có LLM. Chưa thấy drift detector và retrain promotion có đánh giá độc lập. Tên Adaptive nên được định nghĩa là vòng thu thập, phản hồi, tái huấn luyện và phê duyệt, chưa phải online continual learning tự động.}
\block{F14 Log và registry}{Log train metric chỉ đánh MLP trong khi runtime max(IF,MLP). Marker scenario có thể tồn tại trong text. Registry conflict chưa cập nhật tất cả trường version; prediction ID không chứa version. Nên dùng immutable run/model version và ghi rõ evaluation split.}
\block{Quyết định kiểm toán}{Các unit test đã pass phần lớn xác nhận logic nội bộ, không xác nhận ground truth, parser native hay năng lực unknown attack. Các phát hiện này là backlog sửa có bằng chứng, không được xem là đã khắc phục trong bản báo cáo.}
'''))
    p.append(page('Kiến trúc gọn và trách nhiệm không chồng chéo',r'''
\begin{tabularx}{\textwidth}{p{2.8cm}Xp{3.1cm}}\toprule
Nhóm & Thành phần và trách nhiệm & Quyết định đề xuất\\\midrule
Lab & Nginx, DVWA, MariaDB, Docker & Bắt buộc\\
Pipeline & Redis, PostgreSQL, Collector, Normalizer & Bắt buộc\\
Giám sát & Suricata, backend, dashboard, Incident & Bắt buộc\\
Hybrid & Một Log AI baseline, weighted Fusion & Bật sau sửa nhãn/scorer\\
Nghiên cứu & Network AI, Graph AI, Fusion stacking & Bật khi có holdout\\
Runtime & Falco & Bật cho command/runtime\\
SIEM/host & Wazuh Manager, Windows agent & Tùy chọn\\
Rule & Generator + native Validator + lifecycle & Candidate trước\\
Response & Alert, evidence; block/isolate & Giữ alert, hoãn containment\\
LLM & GTI corpus, RAG/LoRA nếu cần & Chưa cần cho demo\\\bottomrule\end{tabularx}
\block{Luồng chuẩn đề xuất}{Client $\to$ Nginx/DVWA $\to$ sensor/access log $\to$ Collector $\to$ Normalizer $\to$ DB/stream $\to$ rule+AI $\to$ Fusion $\to$ Incident $\to$ analyst/evidence. Generator đọc pattern và tạo candidate bên cạnh đường realtime; Validator chạy theo đợt.}
\block{Cắt giảm đúng cách}{Đây là thiết kế đề xuất, chưa thay Compose hiện có. Wazuh/Falco đang bị các script lib và mounts coi là bắt buộc. Tạo profile nhẹ phải sửa đồng bộ source enabled, volume, gate, expected health và missing-score handling; chỉ dừng container có thể làm khởi động sau thất bại.}
\block{Tránh gộp sai}{Không gộp MariaDB/PostgreSQL; không bỏ Normalizer; không bỏ evidence. Có thể gộp các màn hình UI và dùng chung graph representation cho điều tra/AI, nhưng giữ phân biệt graph visualization với graph classifier.}
'''))
    p.append(page('Runbook khởi động tuần tự',r'''
\block{Bước 1 Kiểm tra máy}{Bật Docker Desktop và chọn Linux containers; docker info phải thành công. Với shell WSL, xác nhận Docker Desktop integration. Không xóa volume để xử lý một container unhealthy.}
\begin{Code}
docker info
docker compose version
nvidia-smi
\end{Code}
\block{Bước 2 Chuẩn bị môi trường}{Đứng tại thư mục project. Kiểm tra .env tồn tại và có quyền hạn phù hợp; không paste nội dung chứa secret vào log/báo cáo. Trong WSL, project thường là /mnt/d/GSANM/ahr-idps. Core script có chế độ prepare-only và guard schema DVWA.}
\begin{Code}
cd /mnt/d/GSANM/ahr-idps
bash scripts/start_lab.sh --prepare-only
bash scripts/start_lab.sh
\end{Code}
\block{Bước 3 Sensor rồi pipeline rồi app}{Chờ từng lớp hoàn thành health gate. Nginx namespace thay khi bật app overlay có thể ảnh hưởng capture Suricata, vì vậy đọc đúng workflow scripts và retest marker sau thay cấu hình.}
\begin{Code}
bash scripts/start_sensors.sh
bash scripts/start_pipeline.sh
bash scripts/start_app.sh
\end{Code}
\block{Điểm dừng khi lỗi}{Không chạy tiếp AI nếu Redis/DB/pipeline chưa healthy. Dùng Compose cùng overlays để ps --all và logs --tail 100. Health API và healthz là các phép kiểm tra khác phạm vi; cần cả request DVWA có login và event mới.}
'''))
    p.append(page('Runbook giao diện và bật AI',r'''
\block{Bước 4 Kiểm thử chức năng trước AI}{Mở http://127.0.0.1:8080, đăng nhập DVWA; mở /dashboard/ và /api/health. Chạy script interface acceptance trên PowerShell. WebSocket, marker và sensor freshness mới là bằng chứng xuyên luồng.}
\begin{Code}
powershell -ExecutionPolicy Bypass -File .\scripts\interface_acceptance.ps1
python scripts/authorized_monitoring_scenarios.py --target http://127.0.0.1:8080 --scenario baseline --scenario-id audit_baseline_001
\end{Code}
\block{Bước 5 Bật AI sau smoke-test model}{Kiểm tra đủ artifact trong experiments/models. Lưu bản cũ, load model staging, kiểm tra tên/order/encoding của vector và predict ít nhất một canonical event. Kit Kaggle hiện có lỗi parity cần sửa theo F04 trước promotion.}
\begin{Code}
powershell -ExecutionPolicy Bypass -File .\scripts\start_ai.ps1
\end{Code}
\block{Wazuh tùy chọn}{Manager API không phải dashboard. Bật API overlay bằng start\_wazuh\_api.sh nếu cần quản trị; console bằng wazuh\_manager\_console.ps1. Dùng 55000 HTTPS, 1514/1515 không mở trình duyệt.}
\block{Dừng có bảo toàn dữ liệu}{Dừng AI đang chạy bằng Compose cùng overlays, rồi app/pipeline/sensors/core theo thứ tự. Scripts stop hiện chỉ đảm nhận lớp được đặt tên; đọc danh sách service trước stop. Không dùng down -v.}
\begin{Code}
bash scripts/stop_app.sh
bash scripts/stop_pipeline.sh
bash scripts/stop_sensors.sh
bash scripts/stop_lab.sh
\end{Code}
\block{Tiêu chí hoàn tất}{Container chạy, readiness đúng, event mới tới DB, model score có provenance, incident/evidence có thể truy ngược. Không lấy màu xanh lịch sử trên dashboard làm tiêu chí duy nhất.}
'''))
    p.append(page('Kế hoạch train kết hợp CPU và GPU',r'''
\block{Phù hợp với máy thực tế}{RAM gần 32 GB đủ cho lab 18 service và thí nghiệm nhỏ, nhưng tổng cap 13,5 GiB không phải mức sử dụng đo. RTX 3050 4 GB phù hợp XGBoost hist/CUDA tập nhỏ; không chọn fine-tune 7B làm mặc định. CPU i5 12 core/16 thread đủ các baseline.}
\begin{tabularx}{\textwidth}{p{3cm}p{2cm}X}\toprule
Tác vụ & Thiết bị & Cách dùng\\\midrule
XGBoost Network & GPU train & tree\_method=hist, device=cuda\\
XGBoost Fusion & GPU train & Chỉ sau OOF scores và heldout\\
Log IF/MLP & CPU & scikit-learn; 4 thread khởi đầu\\
Graph aggregation/MLP & CPU & Implementation hiện tại không Torch\\
LR/RF/HGB benchmark & CPU & Chạy nối tiếp, cùng split\\
Inference thường trực & CPU & Bộ nhỏ, giảm GPU transfer overhead\\
LLM/QLoRA & Hoãn & VRAM 4 GB không tái lập cấu hình paper\\\bottomrule\end{tabularx}
\block{CPU+GPU kết hợp có nghĩa gì}{CPU chuẩn hóa/đọc data, GPU fit các cây XGBoost, CPU chạy các model sklearn và suy luận realtime. Không có một lệnh khiến IF/MLP sklearn tự sử dụng GPU. Chạy đồng thời chỉ khi đã đo RAM/VRAM và nhiệt; ưu tiên nối tiếp để kết quả tái lập.}
\block{Gate trước train}{Login và nhãn đúng; schema đủ field; marker bỏ khỏi feature; group split bất biến; causal rolling window; model staging. Sau đó mới tăng số mẫu hoặc num\_boost\_round.}
\begin{Code}
set OMP_NUM_THREADS=4
set OPENBLAS_NUM_THREADS=4
\end{Code}
Đây là cú pháp CMD. Trong PowerShell:\par
\begin{Code}
$env:OMP_NUM_THREADS='4'
$env:OPENBLAS_NUM_THREADS='4'
\end{Code}
Giữ seed và phiên bản thư viện trong metadata.\par
'''))
    p.append(page('Train Network từ CICIDS2017 và kiểm tra GPU',r'''
\block{Bước 1 Dataset bên ngoài}{Dùng file Web Attacks buổi sáng thứ Năm trong D:/GSANM/archive, tên đầy đủ nằm trong lệnh bên dưới. Có 168.186 BENIGN, 1.507 brute force, 652 XSS và 21 SQLi. Lấy cân bằng 2.180 attack và 2.180 benign cho khởi đầu; số SQLi quá ít để kết luận per-family tốt.}
\block{Bước 2 Chạy benchmark riêng}{Gói GPU đã tạo ở dist có run\_train.ps1. Trong repository, script dưới đây chạy được benchmark nhưng có các lỗi adapter F04 nên chỉ dùng offline tới khi sửa contract. Không thêm --install-xgboost ở bước thăm dò.}
\begin{Code}
python -m venv .venv-train
.\.venv-train\Scripts\python.exe -m pip install -r ai/requirements.txt
.\.venv-train\Scripts\python.exe scripts/train_kaggle_network.py --input "D:/GSANM/archive/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv" --max-rows 20000 --device cuda --output-dir experiments/comparison/cic-web-new
\end{Code}
\block{Bước 3 GPU thật hay fallback}{XGBoost có thể cảnh báo rồi chạy CPU khi CUDA không khả dụng; exception handler hiện không chứng minh GPU được dùng. Kiểm tra nvidia-smi, build\_info USE\_CUDA và cấu hình booster sau train. Báo cáo device\_requested và device\_actual riêng.}
\block{Bước 4 Cài artifact}{Chỉ sau sửa adapter và smoke parity: model JSON về experiments/models/network-xgboost.json, metadata đi cùng; registry cập nhật đúng hash/version. Restart service để load file mới. Không đổi file đang nạp giữa chừng.}
\block{Giới hạn khoa học}{Random row split CICIDS có thể lạc quan vì flow trùng/tương tự; deduplicate fingerprint rồi group split. Flow CSV thiếu HTTP payload nên không train Log/Graph/LLM từ các cột này bằng cách tạo log giả.}
'''))
    p.append(page('Train Log và Graph trên telemetry DVWA',r'''
\block{Thứ tự đúng}{Thu dữ liệu có login; export đầy đủ canonical schema; chia campaign/session trước feature extraction. Fit hashing+IF+MLP trên train, chọn threshold trên validation, test một lần bằng chính runtime scorer. Graphs không được gộp event khác split.}
\block{Lệnh trainer hiện có}{Các lệnh sau là smoke training vì hiện đo trên train, chưa phải evaluator holdout. Chạy trong container ai-network với DB/Redis env; bật .env/Compose đầy đủ như runbook. Không cần GPU cho sklearn.}
\begin{Code}
python -m ai.logs.train
python -m ai.graph.train --window-seconds 30
\end{Code}
\block{Sửa trainer trước kết quả cuối}{Mỗi loader cần nhận danh sách scenario/run IDs của split. Log text bỏ marker và secret; preprocessing fit trên train. Đánh IF+MLP đúng công thức runtime, không chỉ predict MLP. Graph model lưu graph construction version và hash code; không gọi aggregation cố định là GraphSAGE trainable.}
\block{Thích nghi có kiểm soát}{Lưu model baseline, drift statistics và false positives analyst xác nhận. Chạy challenger theo đợt, so cùng holdout, chỉ promote khi FPR không tăng quá ngưỡng và có cải thiện kiểm chứng. Không tự gán nhãn từ model rồi train lại vòng kín không có analyst ground truth.}
\begin{equation*}
\mathrm{promote}(m')=\mathbb{1}[FPR_{m'}\leq\epsilon\land F1_{m'}\geq F1_m-\delta\land\mathrm{parity}(m')].
\end{equation*}
\block{Artifact}{log-ai.joblib cần dictionary iforest/classifier/version; graph artifact cần class path \nolinkurl{ai.graph.graphsage.GraphSAGEWindowClassifier}. Không chuyển joblib sang máy thiếu cùng module/version rồi coi lỗi load là dữ liệu hỏng.}
'''))
    p.append(page('Train Fusion bằng GPU và triển khai',r'''
\block{Out-of-fold stacking}{Chia train thành K group folds. Với fold k, train base models trên phần còn lại và dự đoán fold k; ghép score OOF để train Fusion. Base score trên chính mẫu fit sẽ rò rỉ độ tự tin. Sau train meta-model, fit base final trên train rồi đánh test chưa thấy.}
\begin{equation*}
z_i=[s_r,s_N^{(-k(i))},s_L^{(-k(i))},s_G^{(-k(i))},s_C,\mathrm{sev},d,\mathrm{miss}],\quad s_F=\sigma(F(z_i)).
\end{equation*}
\block{GPU overlay hiện có}{dist/AHR-IDPS-AI-Training-Kit-GPU/gpu.compose.yml cấu hình gpus: all cho service training. Docker phải có WSL2 GPU passthrough. Với Compose CLI, dùng overlay này, không dùng --gpus trên compose run vì phiên bản CLI khảo sát không có option đó.}
\begin{Code}
# Trong Bash sau khi source scripts/lib/ai.sh:
ahr_ai_compose -f dist/AHR-IDPS-AI-Training-Kit-GPU/gpu.compose.yml run --rm --no-deps -e AHR_XGBOOST_DEVICE=cuda ai-network python -m ai.fusion.train
\end{Code}
Lệnh trên vẫn là trainer hiện có, chưa OOF. Không dùng metric train của nó làm kết quả stacking heldout. source helper và chuẩn bị env trước khi gọi ahr\_ai\_compose.\par
\block{Triển khai an toàn}{Train vào thư mục staging, kiểm tra checksum/schema/load, so benchmark, đăng ký version mới, atomic promotion rồi restart. Chạy baseline và web scenario kiểm tra live score. Giữ artifact cũ để rollback; không dùng apply patch từ kit cũ ghi đè file đã thay đổi nếu chưa diff.}
\block{Khi thiếu score}{Weighted Fusion là fallback hợp lý. Ghi missing components, chờ tối đa timeout có giới hạn, quyết định finalized một lần/version; nếu recalculation phải có audit để incident risk không bị số tạm thời chi phối mãi.}
'''))
    p.append(page('Làm giàu dataset theo mục tiêu nghiên cứu',r'''
\block{Có cần làm giàu không}{Có, nhưng ưu tiên dữ liệu đúng và đa dạng thay số dòng. Dataset local hiện có 250 event từ 30 scenario trong network export, hai lớp gần cân bằng. Bộ này đủ smoke-test, chưa đủ kết luận unknown/generalization. Nhiều log của một request không làm tăng số thí nghiệm độc lập.}
\begin{tabularx}{\textwidth}{p{3.1cm}Xp{2.5cm}}\toprule
Nhóm & Nội dung bổ sung & Mục tiêu ban đầu\\\midrule
Benign & Cùng endpoint challenge; id hợp lệ, query bình thường; session/user agent/time khác & 40--60 scenario\\
Web injection & SQLi/XSS/command/LFI biến thể được kiểm chứng; đúng method và security level & 40--60 scenario\\
Auth/scanner & Sai mật khẩu giới hạn, path probe; không DoS & 20--40 scenario\\
Runtime & Falco đúng container và time liên quan request, có mức tin cậy correlation & Theo coverage\\
Unknown & Giữ toàn bộ một họ hoặc biến thể chưa train và test vào ngày khác & Snapshot riêng\\\bottomrule\end{tabularx}
\block{Không làm giàu giả}{Không nhân đôi 21 SQLi rồi chia ngẫu nhiên vào train/test. Không chèn attack\_type, scenario marker hoặc simulated IP vào feature. Không tạo log Falco/Wazuh giả để lấp cột thiếu và gọi đó là cảm biến thật.}
\block{Thêm dữ liệu cần đi kèm}{Schema version, source, capture leg, actual/simulated client ID, timestamp, HTTP final URL, intent label, success evidence, source of label, confidence và model/rule version. Không lưu password/cookie/token trong artifact chia sẻ.}
\block{Ngưỡng mở rộng}{Sau 120--160 scenario mới xem learning curves theo số group. Chỉ tăng mẫu khi test FPR/recall chưa bão hòa và label QA đạt. Chọn challenge/biến thể thiếu coverage thay chạy lại cùng payload vô hạn.}
'''))
    p.append(page('Luồng tự sinh dataset có đăng nhập',r'''
\block{Công cụ mới}{dataset\_collection/campaign.py được bổ sung trong nhiệm vụ này. Mặc định chỉ in plan, không kết nối Docker/DB/HTTP. Mỗi vòng có tám scenario: hai benign và sáu họ attack. Mỗi scenario có ID riêng, session mới, marker và notes; command injection dùng POST.}
\begin{Code}
python -m dataset_collection.campaign --rounds 2 --seed 42 --output output/campaign-plan.json
\end{Code}
\block{Luồng thực thi}{Plan $\to$ login CSRF $\to$ probe challenge $\to$ scenario start $\to$ request marker $\to$ sensor/normalizer $\to$ finish/label $\to$ chờ event marker $\to$ audit JSON $\to$ export snapshot. Nếu login thất bại, không tạo attack label. Nếu challenge về login hoặc 5xx, dừng để xem lại.}
\block{Chạy trong backend}{Backend có module dataset\_collection và credentials DB trong env. Rebuild image backend sau thêm module; dùng cùng Compose overlays và run backend để có network app\_front/data. Không chạy trên Internet.}
\begin{Code}
# BASH / WSL, trong project:
ROUNDS=2 bash scripts/run_dvwa_campaign.sh --execute
\end{Code}
Wrapper rebuild backend, chạy campaign trong container tạm rồi export vào thư mục snapshot có timestamp. Exporter lấy toàn bộ event đã gắn nhãn trong DB, không chỉ lượt campaign cuối. Hướng dẫn riêng ở docs/dvwa\_dataset\_campaign.md.\par
\block{Giới hạn hiện tại}{Collection mới xác thực session và request intent, chưa tự chứng minh exploit success cho mọi challenge. Mỗi lượt brute\_force chỉ một thử sai; tăng vòng để lấy chuỗi, không gọi đó là brute-force quy mô lớn. Nhãn Falco thiếu marker vẫn cần correlation QA.}
'''))
    p.append(page('IP mô phỏng và nhiều client trong lab',r'''
\block{IP mô phỏng của campaign}{Campaign dùng dải tài liệu 192.0.2.0/24, đặt X-AHR-Simulated-IP và notes JSON. Đây là client identity phục vụ thí nghiệm, không đổi source IP của packet. Nginx hiện không log header này, nhưng campaign/scenario notes giữ nó; Normalizer chưa ánh xạ thành field riêng.}
\block{Vì sao đổi X-Forwarded-For không đủ}{Nginx ghi remote\_addr và ghi đè X-Forwarded-For upstream bằng remote\_addr. Suricata nhìn địa chỉ mạng thật; các header HTTP không thay 3-way handshake. Không thay src\_ip trong raw data để tạo vẻ đa nguồn.}
\block{Nếu cần IP mạng thật}{Tạo nhiều client container trong mạng lab có thể tới Nginx. Mỗi container có IP riêng, session riêng, cùng script campaign; chạy tuần tự và ghi Docker network inspect để xác minh. Client gửi tới nginx trong Docker bridge nên tránh NAT ingress; Suricata vẫn thấy upstream proxy leg với IP Nginx, cần capture-leg lineage.}
\begin{equation*}
\mathrm{source}_{\mathrm{observed}}\in\{\mathrm{clientIP},\mathrm{proxyIP},\mathrm{NATIP}\},\quad
\mathrm{simulatedIP}\not\equiv\mathrm{source}_{\mathrm{observed}}.
\end{equation*}
\block{Cách tận dụng cấu hình hiện có}{docker compose run --rm --no-deps backend tạo một container client tạm trong mạng app\_front/data; từng lần run có thể nhận IP khác nhưng Docker có thể tái sử dụng IP. Để có nhiều IP đồng thời, tạo tên client riêng và giới hạn số lượng, rồi kiểm tra mạng thật trước thu mẫu. Đây là đề xuất topology, chưa tạo các client trong phiên kiểm tra.}
\block{Chống leakage}{Giữ toàn bộ một client session/campaign trong một split; mã client/IP chỉ dùng để nhóm và lưu bằng chứng, không feature. Không gán mọi event từ IP đỏ là attack: cả benign và attack phải xuất hiện ở mỗi client.}
'''))
    p.append(page('Nhãn, split và chất lượng dataset',r'''
\block{Ba mức ground truth}{Request intent: payload được kế hoạch gửi. Endpoint reached: đã login, final URL đúng challenge. Exploit outcome: có bằng chứng hiệu ứng ứng dụng/runtime. Dùng ba field khác nhau; mẫu không chứng minh outcome giữ unknown thay tự ép success.}
\block{Nhãn đa nguồn}{Nginx/Suricata dùng marker/flow/time. Wazuh dẫn xuất giữ parent event. Falco liên kết container, process ancestry và time với confidence; không tự label chỉ vì cùng cửa sổ. Review ít nhất một tập mẫu cả benign/attack từng nguồn trước export.}
\begin{equation*}
\mathcal D=\mathcal D_{tr}\cup\mathcal D_{val}\cup\mathcal D_{test},\quad
\mathrm{campaign}(\mathcal D_a)\cap\mathrm{campaign}(\mathcal D_b)=\varnothing\;(a\neq b).
\end{equation*}
\block{Thiết kế split đề xuất}{60\% train, 20\% validation, 20\% known test theo campaign/day/client groups và có hai lớp. Unknown family giữ riêng ngoài các tập đó. Exporter hiện chia theo thời gian scenario 60/15/10/10/5: khác đề xuất và chưa đảm bảo unknown thật. Ghi split policy vào manifest, không thay ngẫu nhiên sau khi xem test.}
\block{Kiểm tra bắt buộc}{Schema đủ port/http/network/process; hash duplicate không cross split; markers bị loại khỏi text; normalization fit trên train; không dùng future window; giữ benign same-endpoint. Đối với flow duplicates, group theo fingerprint trước random split.}
\block{Tái lập}{Lưu seed, commit/snapshot, capture config, label version, canonical schema hash, dataset SHA-256, library version và split IDs. Metric không có những thông tin này chỉ là thăm dò.}
'''))
    p.append(page('Thuật toán XGBoost và các baseline cây',r'''
\block{XGBoost nhị phân}{Với $y_i\in\{0,1\}$, $F_K(x_i)=\sum_{k=1}^{K}f_k(x_i)$ và $\hat p_i=\sigma(F_K(x_i))$. Minimize log loss và regularization cây:}
\begin{align*}
\mathcal L&=\sum_i[-y_i\log\hat p_i-(1-y_i)\log(1-\hat p_i)]+\sum_k\Omega(f_k),\\
\Omega(f)&=\gamma T+\tfrac\lambda2\sum_{j=1}^T w_j^2,\quad g_i=\hat p_i-y_i,\quad h_i=\hat p_i(1-\hat p_i),\\
w_j^*&=-\frac{\sum_{i\in I_j}g_i}{\sum_{i\in I_j}h_i+\lambda},\\
\mathrm{Gain}&=\tfrac12\left[\frac{G_L^2}{H_L+\lambda}+\frac{G_R^2}{H_R+\lambda}-\frac{(G_L+G_R)^2}{H_L+H_R+\lambda}\right]-\gamma.
\end{align*}
Histogram tree method gộp bins để tìm split; CUDA tăng tốc một số bước fit, không thay ngữ nghĩa feature/split. Với score xuất GPU, latency transfer có thể lớn hơn tính toán trên tập nhỏ.\par
\block{Random Forest}{Mỗi cây $T_b$ fit bootstrap và chọn tập feature ngẫu nhiên ở split. Xác suất nhị phân là trung bình xác suất lá: $\hat p(x)=B^{-1}\sum_b\hat p_b(x)$. Gini impurity: $I(t)=1-\sum_c p(c\mid t)^2$. Bằng chứng so sánh phải cùng train/test IDs với XGBoost.}
\block{HistGradientBoosting}{Tối ưu boosting qua histogram bins với cập nhật $F_m=F_{m-1}+\eta h_m$. Trainer dùng max\_iter và max\_leaf\_nodes; không tương đương tăng cây RF. Preprocessing và target vẫn cùng contract.}
\block{Trạng thái triển khai}{XGBoost là runtime Network/Fusion; RF/HGB là artifact benchmark offline. Không có service realtime riêng cho RF/HGB. Không copy joblib baseline vào tên network-xgboost.json.}
'''))
    p.append(page('Thuật toán hashing, Isolation Forest và MLP',r'''
\block{Hashing representation}{Text chuẩn hóa $T(e)$ gồm source, event type, HTTP, process/rule. Với $d=384$, token hashing không cần học vocabulary:}
\begin{equation*}
z_j=\sum_{t\in T(e)}c(t)\mathbb1[h(t)\bmod d=j],\quad \bar z=\frac{z}{\|z\|_2+\varepsilon}.
\end{equation*}
alternate\_sign=False theo code. Hash collision tồn tại; tên MiniLM-compatible chỉ nói output dimension. Không có attention hay pretrained sentence embedding trong runtime này.\par
\block{Isolation Forest}{Cây chọn feature/split ngẫu nhiên để cô lập điểm; độ dài đường đi trung bình ngắn là bất thường. Với sample size $n$:}
\begin{equation*}
c(n)=2H_{n-1}-2(n-1)/n,\quad s(x)=2^{-\mathbb E[h(x)]/c(n)}.
\end{equation*}
Trong sklearn, decision\_function đã dịch theo offset; code AHR dùng $s_{IF}'=\mathrm{clip}_{[0,1]}(0.5-\mathrm{decision\_function}(z))$, không dùng trực tiếp biểu thức $s(x)$ ở trên. Fit IF trên benign train; tune ngưỡng bằng benign validation.\par
\block{MLP classifier}{Một hidden layer ReLU 32 units trong Log AI: $a=\max(0,W_1\bar z+b_1)$, $p=\sigma(W_2a+b_2)$. Minimize binary cross-entropy có regularization. Runtime $s_L=\max(s_{IF}',p)$; metrics cuối phải dùng $s_L$.}
\block{Logistic Regression baseline}{Với $\tilde x=(x-\mu_{tr})/(\sigma_{tr}+\epsilon)$, $p=\sigma(w^\top\tilde x+b)$. Minimize weighted cross-entropy và $\lambda\|w\|_2^2/2$. StandardScaler chỉ fit train; class\_weight=balanced thay trọng số loss chứ không sửa số mẫu test.}
'''))
    p.append(page('Thuật toán graph và tương quan',r'''
\block{Implementation AHR hiện tại}{Mỗi node có đặc trưng loại/entity/degree/attrs. Lấy trung bình láng giềng cố định, nối self, pooling mean/max rồi thêm graph statistics:}
\begin{align*}
h_v&=[x_v\Vert\operatorname{mean}_{u\in N(v)}x_u],\\
g&=[\operatorname{mean}_v h_v\Vert\operatorname{max}_v h_v\Vert q(G)],\\
\hat p_G&=\operatorname{MLP}(\operatorname{StandardScaler}(g)).
\end{align*}
Chỉ MLP/scaler được fit. MLP baseline thứ hai dùng $q(G)$ không có neighbor embedding. Graph explanation hiện là degree/support ranking; không thể gọi là attention weights.\par
\block{GraphSAGE chuẩn để tham khảo}{Nếu triển khai GNN trainable trong tương lai, từng lớp sẽ có tham số $W^{(k)}$ và neighborhood sampling:}
\begin{equation*}
h_{N(v)}^{(k)}=\mathrm{AGG}_k(\{h_u^{(k-1)}\}),\quad
h_v^{(k)}=\sigma\left(W^{(k)}[h_v^{(k-1)}\Vert h_{N(v)}^{(k)}]\right).
\end{equation*}
Huấn luyện với loss nhãn node/graph, regularization và holdout graph. PyTorch/CUDA cần model artifact mới, không chỉ sửa biến device trên joblib hiện tại.\par
\block{Incident correlation}{Event nhóm theo session key và time bucket; incident risk lấy max score. Attack graph trình bày quan hệ HTTP/IP/process/file/rule. Grouping không chứng minh causal relation; lưu confidence/source edge. Không gộp graph từ train/test khác campaign.}
\block{Causal window}{Để đo online, context tại $t$ chỉ dùng $[t-\Delta,t]$; nếu cần đợi cửa sổ kết thúc phải báo detection latency thêm $\Delta$. Query $[t-\Delta,t+\Delta]$ trong offline mà không cộng độ trễ là không công bằng.}
'''))
    p.append(page('Thuật toán Fusion và CoVe chi tiết',r'''
\block{Weighted baseline có thiếu nguồn}{Tập thành phần sẵn $A$, $\tilde w_j=w_j/\sum_{k\in A}w_k$, $s_F=\sum_{j\in A}\tilde w_js_j$. Quy tắc risk trong Fusion: medium 0,30, high 0,55, critical 0,80. Threshold train/evaluate phải ghi đúng task; Network dùng 0,5 không đồng nghĩa Fusion attack threshold.}
\block{Feature Fusion thực tế}{Vector tám chiều: rule/network/log/graph/context score, severity/10, min(density,25)/25 và missing\_count/5. Rule score code dùng trọng số severity/confidence/engine; context dùng density, max AI và scenario hint. Scenario hint là field nghiên cứu phải bỏ khi đánh giá để tránh leakage.}
\begin{equation*}
s_r=\mathrm{clip}(.55\,\mathrm{sev}/10+.25\,\mathrm{conf}+.20\,\mathrm{engineWeight}).
\end{equation*}
\block{CoVe của bài báo}{Syntax engine accepted, semantic/logic align CTI, benign replay FPR. Security effectiveness: $SE=\alpha DR+(1-\alpha)(1-FPR)$ với $\alpha=.5$. Composite paper: $CS=.2SA+.3SS+.2CC+.3SE$. Công thức paper in biến MC ở một chỗ thay CC nên cần ghi chú khi trích.}
\block{CoVe-lite của AHR}{Code dùng syntax boolean, logic boolean, precision và security effectiveness: $CS_A=.2S+.3L+.2P+.3SE$. Đây là proxy nội bộ, không phải cùng metric của paper. Difficulty code dựa số constraint, độ dài URI, support và CTI count, không phải curriculum LLM đã chạy.}
\block{Vòng tinh chỉnh đề xuất}{Tối đa K lần: generate candidate; native syntax; replay attack/benign; nếu fail tạo feedback gồm parser error và false-positive examples; sửa rule; lưu version bất biến. Hết K hoặc thiếu benign trả insufficient/rejected. Chỉ sau engine validation mới shadow; active có deployment receipt.}
'''))
    p.append(page('LLM, LoRA và curriculum trong bài GenTI',r'''
\block{Mô hình ngôn ngữ}{Cho analyst prompt $P$, payload $S$ và ngữ cảnh CTI $C$, LLM sinh token rule $r=(r_1,\ldots,r_T)$. Loss supervised fine-tuning:}
\begin{align*}
p_\theta(r\mid P,S,C)&=\prod_{t=1}^T p_\theta(r_t\mid r_{<t},P,S,C),\\
\mathcal L_{SFT}&=-\sum_{(P,S,C,r)\in D}\sum_t\log p_\theta(r_t\mid r_{<t},P,S,C).
\end{align*}
\block{LoRA/QLoRA}{Đóng băng $W_0$, học hạng thấp $\Delta W=(\alpha/r)BA$, $A\in\mathbb R^{r\times d_{in}}$, $B\in\mathbb R^{d_{out}\times r}$. Với QLoRA, base weights quantized rồi dequantize khi tính; gradient update adapter, không toàn bộ base. Quantization/optimizer/activation memory vẫn cần VRAM.}
\begin{equation*}
y=\operatorname{dequant}(Q(W_0))x+\frac\alpha r BAx.
\end{equation*}
\block{Curriculum được mô tả}{Stage 1 học cấu trúc/header; stage 2 thêm CTI/semantic; stage 3 thêm verification/false-positive; stage 4 toàn độ khó, warm-start từng stage. Bài mô tả DeepSeek-7B QLoRA, learning rate $10^{-4}$ và 8 A100, không cung cấp đủ hyperparameter trong PDF để coi là cấu hình tái lập đầy đủ.}
\block{Áp dụng thực tế ở máy này}{Hiện không có LLM service/weights/adapter train. Nếu nghiên cứu tiếp, chọn model nhỏ hoặc GPU khác sau khi có GTI rule corpus, giấy phép và holdout. RAG/template+native validation có thể phù hợp hơn fine-tune 7B. Không gửi raw logs/secret ra API bên ngoài khi chưa chọn rõ workflow.}
\block{Giải thích và kiểm chứng}{Lưu lý do ngắn, CTI sources, parser/replay receipt; không cần lưu suy luận nội bộ dài. CTI tự sinh bởi LLM cần xác minh nguồn, không biến thông tin synthetic thành ground truth.}
'''))
    p.append(page('Đánh giá thực nghiệm công bằng',r'''
\begin{align*}
P&=\frac{TP}{TP+FP},\quad R=\frac{TP}{TP+FN},\quad F1=\frac{2PR}{P+R},\\
FPR&=\frac{FP}{FP+TN},\quad TNR=1-FPR,\\
\mathrm{AP}&=\sum_n(R_n-R_{n-1})P_n,\quad
\mathrm{latency}_i=t_{\mathrm{decision},i}-t_{\mathrm{ingress},i}.
\end{align*}
\block{Đơn vị mẫu}{Báo cáo rõ request, event hoặc incident. Đếm request attack có Nginx/Suricata/Wazuh không được tính thành ba detection độc lập. Khi evaluation theo event, có thêm metric request/scenario coverage để tránh score lạc quan do nhiều bản sao.}
\block{Ablation đề xuất}{B1 signature-only, B2 log-only, B3 network-only sau parity, B4 rule+log weighted, B5 thêm network, B6 thêm graph, B7 stacking OOF, B8 rule generation trước/sau native validation. Mỗi cấu hình phải có khác biệt thực, cùng holdout IDs và threshold chọn trước test.}
\block{Unknown test}{Giữ một attack family hoặc payload variant khỏi generation/training và tune. Không dựa thứ tự cuối CSV để gọi unknown. Paper GenTI nêu các số known/unseen khác nhau giữa abstract/nội dung/figure, nên chỉ trích như tác giả báo cáo, không chuyển thành benchmark AHR.}
\block{Tài nguyên và thống kê}{Đo CPU/RAM/GPU bằng công cụ thật; training time tách inference time; p50/p95/p99 trên repeated runs. Bootstrap confidence interval theo campaign group, không theo log duplicate. Missing data là unavailable, không phải 0.}
\block{Kết quả cần bàn giao}{CSV từng mẫu gồm event/request/scenario ID, y\_true, y\_score, model\_version, split, threshold và latency; summary confusion matrix và checksum dataset. Mọi biểu đồ phải tái tính được từ CSV này.}
'''))
    p.append(page('Lộ trình sửa và tiêu chí nghiệm thu',r'''
\begin{enumerate}
\item \textbf{Giai đoạn dữ liệu}: thay runner không login bằng campaign có proof; đủ canonical fields; QA nhãn; loại marker; campaign/day holdout. Nghiệm thu khi cùng request liên kết được event gốc và nhãn không lẫn session.
\item \textbf{Giai đoạn model}: feature train/infer parity, model named schema, JSON decode chung; staging/registry immutable version; Log runtime scorer đúng. Nghiệm thu bằng load/predict golden canonical event và holdout.
\item \textbf{Giai đoạn vận hành}: restart/retry/claim/DLQ, causal context, healthy theo freshness, score completion. Nghiệm thu bằng restart/outage/recovery không mất event chưa ACK.
\item \textbf{Giai đoạn luật}: native parser+PCAP replay, min benign count, conflict/SID check, immutable version, atomic deploy/receipt/rollback. Nghiệm thu bằng rule thật nạp sensor và match expected traffic, không chỉ state DB.
\item \textbf{Giai đoạn nghiên cứu}: evaluator measured, ablation khác biệt, unknown holdout, resources/CI. Nghiệm thu bằng script tái tạo bảng từ prediction CSV.
\item \textbf{Giai đoạn thu gọn}: tạo profile nhẹ sau sửa dependencies; Wazuh/Graph/containment/LLM tùy chọn. Chạy cùng acceptance trước/sau thu gọn để chứng minh giảm tài nguyên không mất coverage cốt lõi.
\end{enumerate}
\block{Nghiệm thu cuối}{Một demo hoàn chỉnh gồm baseline có benign challenge, web injection có login, auth abuse có giới hạn; telemetry từ sensor thật; risk có breakdown; incident timeline/graph; candidate rule native-valid; alert-only và evidence có checksum. Chưa đáp ứng phần nào phải ghi rõ thay vì đánh PASS toàn hệ thống.}
\block{Phạm vi thay đổi của nhiệm vụ này}{Đã thêm campaign mới, unit test campaign, probe audit và báo cáo. Không tự sửa 18 service, không tắt node, không train/replace model và không deploy rule. Các phát hiện là cơ sở để sửa theo thứ tự, giúp tránh biến đánh giá thành một đợt thay đổi khó kiểm soát.}
'''))
    p.append(page('Bằng chứng kiểm tra và tài liệu tham khảo',r'''
\block{Kết quả trong phiên}{Compose parse hợp lệ, 18 service và trần RAM 13,5 GiB; Docker Engine không hoạt động nên mọi port/service live chưa xác minh. Unit suite: 73 pass/1 fail trên Windows; test fail là collector/tests/test\_config.py so đường dẫn /state/checkpoints.sqlite3 với dạng Windows. Campaign có bốn test mới: plan/markers, target allowlist, CSRF parsing và login rejection.}
\block{Probe tái hiện}{output/pdf/ahr-idps-audit-evidence.json chứa năm probe: port\_class mismatch, attack\_type thành has\_rule, URI replay sai, pattern JSON string exception và XGBoost named/unnamed DMatrix. Các probe chạy trong bộ nhớ, không gửi traffic và không ghi model runtime.}
\begin{Code}
python scripts/audit_system_contracts.py
python -m dataset_collection.campaign --rounds 2
python -m pytest ai collector normalizer correlation rule_engine response dataset_collection backend/tests -q
\end{Code}
\block{Mã nguồn chính}{Nguồn mỗi chức năng được ghi trên trang đầu của chức năng đó. Cấu hình Docker hợp nhất: core + suricata + falco + wazuh + pipeline + app + ai; không đưa secrets/env values vào tài liệu.}
\block{Tài liệu học thuật}{H. J. Hadi, R. Yasmin, A. Shoker, \emph{GenTI: Benchmarking LLMs for Autonomous IDPS Rule Generation for Unseen Attacks}, arXiv:2606.05844v1, 04/06/2026. Các thành phần tham khảo gồm Algorithm 1, Sections V--VI, Table III và data availability Figshare. Báo cáo này phân biệt paper methodology với implementation GenTI-lite.}
\block{Tài liệu công nghệ}{Tài liệu chính thức XGBoost, scikit-learn (HashingVectorizer, IsolationForest, MLPClassifier, metrics), Suricata, Falco, Wazuh, Docker Compose, Redis Streams và DVWA. Công thức graph tham khảo GraphSAGE, Hamilton et al., 2017; LoRA, Hu et al., 2021; QLoRA, Dettmers et al., 2023. Những phương pháp này chỉ được gọi đã triển khai khi code có mô hình tương ứng.}
'''))
    return p


if __name__=='__main__':
    main()
