import { Link } from 'react-router';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Page, PageHeader } from '@/components/soc/primitives';
import { useApi } from '@/api/query';

const steps = [
  ['Sức khỏe hệ thống', '/health', 'Kiểm tra dịch vụ, thời điểm sensor gửi dữ liệu và Wazuh. Healthy của container và dữ liệu sensor mới là hai kiểm tra riêng.'],
  ['Tổng quan', '/', 'Xem sự kiện, cảnh báo và sự cố. Các số đếm là sự kiện quan sát, không phải số cuộc tấn công độc lập.'],
  ['Sự kiện realtime', '/events', 'Tìm theo marker, IP hoặc event ID; chọn dòng để xem nguồn, HTTP, rule và điểm AI. Dùng cùng marker để đối chiếu request với sensor.'],
  ['Mạng & IDS', '/network', 'Đọc thống kê lưu lượng Suricata, địa chỉ và cổng. Suricata hiện bắt gói thụ động, chưa chạy inline để drop gói.'],
  ['Containers', '/containers', 'Đối chiếu container và cảnh báo runtime Falco. Không có sự kiện mới không đồng nghĩa không có rủi ro.'],
  ['Mô hình AI & Fusion', '/ai', 'Kiểm tra AI chính và số mẫu train. Chọn model để đọc metric offline; thay ngưỡng rồi chờ worker xác nhận. Tạm dừng AI vẫn để pipeline thu dữ liệu.'],
  ['Sự cố', '/incidents', 'Mở incident, đọc timeline và bằng chứng từng nguồn trước khi kết luận. Điểm AI cao hoặc HTTP 200 chưa chứng minh khai thác thành công.'],
  ['Graph 20 request', '/attack-graph', 'Dùng đồ thị để điều tra các request lịch sử được chọn theo bằng chứng. Đồ thị này không phải toàn bộ lưu lượng hiện tại.'],
  ['Quản lý Rules', '/rules', 'Lọc Candidate, xem nội dung và support/confidence; nhập lý do rồi kiểm tra. Chỉ duyệt Shadow sau khi kiểm tra bằng engine thật và benign replay. Active hiện chỉ là trạng thái registry.'],
  ['Phản ứng / IPS', '/responses', 'Đọc quyết định, kế hoạch và evidence. Chế độ hiện tại chỉ cảnh báo; chưa có adapter thực thi chặn IP hoặc cô lập mạng.'],
  ['Thực nghiệm', '/experiments', 'Đọc kết quả test giữ riêng của AI chính và tải lại dữ liệu đã kiểm tra checksum. Chưa có runner ablation đo thực tế; không diễn giải metric offline thành số đo IPS hoặc hiệu năng live.'],
] as const;

export function Guide() {
  const mode = useApi<{ enabled: boolean }>('/api/genti/status', 10_000);
  const genti = mode.data?.enabled;
  const currentSteps = genti ? steps.map(([name, path, text]) => path === '/ai'
    ? ['GenTI · AI sinh quy tắc', path, 'Model tự chọn evidence và phản ví dụ, viết yêu cầu phát hiện rồi sinh rule. Trang AI hiển thị bảng mẫu chỉ đọc, nhận định, nội dung rule và kết quả native. Không cần nhập yêu cầu hoặc tích xác nhận.']
    : path === '/rules' ? [name, path, 'Xem nội dung, model hash, native receipt và lịch sử. Profile lab phải đạt 50 attack + 50 benign và live Shadow mới tự Active tại gateway trong 1 giờ. Rule ngoài profile giữ Candidate; sensor không tự reload.']
    : path === '/responses' ? [name, path, 'Chặn HTTP (http_block) ghi request đã bị từ chối trước DVWA. Xem parameters để biết rule/URI; các kế hoạch chặn IP hoặc cô lập của Response Engine vẫn chưa thực thi firewall.']
    : path === '/experiments' ? [name, path, 'Các metric đã lưu không phải kết quả GenTI mới. Hồ sơ LLM nằm trong run Colab; cần đánh giá merged model và PCAP riêng.']
    : [name, path, text]) : steps;
  return <Page>
    <PageHeader title="Hướng dẫn vận hành" description="Quy trình của hệ thống chính: thu dữ liệu → phát hiện → điều tra → kiểm định rule → ghi phản ứng và bằng chứng." />
    <section className="grid gap-3 lg:grid-cols-3" aria-label="Phân biệt IDS IPS và AI sinh rule">
      <Card><CardHeader title="IDS · đang phát hiện" /><CardContent><p className="text-sm text-muted-foreground">{genti ? 'Suricata quan sát mạng; Falco quan sát runtime; Wazuh phân tích log. Incident Engine đọc sự kiện sensor trực tiếp và tương quan theo rule/severity, không chờ Fusion.' : 'Suricata quan sát mạng; Falco quan sát runtime; Wazuh phân tích log. Network AI, Log AI, Graph AI và Fusion bổ sung điểm phát hiện; Incident Engine tương quan bằng chứng.'}</p></CardContent></Card>
      <Card><CardHeader title={genti ? 'IPS · chặn HTTP trong lab' : 'IPS · khung phản ứng'} /><CardContent><p className="text-sm text-muted-foreground">{genti ? 'Gateway Nginx chặn request GET XSS thuộc profile đã kiểm định trước khi tới DVWA. GenTI → native PCAP → Shadow → Active được tự động hóa, có cảnh báo và nút gỡ chặn. Chưa phải IPS toàn mạng, TLS hay POST body.' : 'Response Engine ghi kế hoạch, audit và evidence. Hiện chạy alert_only, chưa thực thi firewall hoặc ngắt mạng. Muốn nghiệm thu IPS phải chứng minh traffic bị chặn và khôi phục được.'}</p></CardContent></Card>
      <Card><CardHeader title="AI sinh rule · đề xuất" /><CardContent><p className="text-sm text-muted-foreground">{genti ? 'GenTI dùng LLM đã fine-tune để tạo Candidate từ yêu cầu, evidence và phản ví dụ. Chỉ profile được phép mới có đường tự kiểm định và Active tại gateway. Mẫu PCAP tổng hợp chưa chứng minh chất lượng trên traffic thực địa.' : 'Điểm Fusion chọn hành vi lặp, pattern miner và template tạo Candidate cho Suricata/Falco/Wazuh. Đây là khai phá mẫu có hỗ trợ AI. Rule cần kiểm định, Shadow và duyệt; registry Active chưa reload sensor.'}</p></CardContent></Card>
    </section>
    <Card><CardHeader title="Thao tác theo thứ tự" description="Chọn tên trang để mở trực tiếp." /><CardContent><ol className="flex list-decimal flex-col gap-4 pl-5 text-sm">{currentSteps.map(([name, path, text]) => <li key={name}><Link className="font-medium text-primary hover:underline" to={path}>{name}</Link><p className="mt-1 text-muted-foreground">{text}</p></li>)}</ol></CardContent></Card>
    <Card><CardHeader title="Khởi động và Wazuh 55000" /><CardContent className="space-y-3 text-sm text-muted-foreground">
      <p>Tại thư mục dự án, chạy PowerShell:</p>
      <pre className="overflow-x-auto rounded bg-muted p-3 text-xs"><code>{genti ? 'powershell -ExecutionPolicy Bypass -File scripts/genti_control.ps1 start\npowershell -ExecutionPolicy Bypass -File scripts/genti_control.ps1 status' : 'powershell -ExecutionPolicy Bypass -File .\\ahr_control.ps1 start\npowershell -ExecutionPolicy Bypass -File .\\ahr_control.ps1 status\npowershell -ExecutionPolicy Bypass -File .\\scripts\\wazuh_manager_console.ps1'}</code></pre>
      <p>Cổng 55000 là HTTPS API của Wazuh Manager, dùng token. Mở trình duyệt có thể nhận 401; đó không phải Wazuh Dashboard. Script console xác thực và kiểm tra trạng thái mà không in token.</p>
      <p>{genti ? 'Bật model sẽ tự kiểm thử Docker. Kiểm chứng Shadow/Active và IPS: python scripts/test_genti_automation.py --output output/acceptance/ips-NEW-RUN (chọn tên thư mục mới). Xem docs/GENTI_AUTOMATIC_IPS.md để đọc ngưỡng, cảnh báo, cách tắt và giới hạn của profile.' : <>Test rule: <code>python scripts/test_rule_generation_live.py</code>. Phép thử dùng sự kiện thật, rollback các bản ghi thử và không triển khai rule lên sensor.</>}</p>
      <p>Kết thúc: <code>powershell -ExecutionPolicy Bypass -File .\ahr_control.ps1 stop</code>. Dữ liệu được giữ trong volume.</p>
    </CardContent></Card>
  </Page>;
}
