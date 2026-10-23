import { Activity, ArrowDownUp, RefreshCw, ShieldAlert } from 'lucide-react';
import { useApi } from '@/api/query';
import { fmtBytes, fmtNumber, isNum } from '@/lib/format';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/overlays';
import { BarList, KpiCard, Page, PageHeader, StaleNotice } from '@/components/soc/primitives';
import type { NetworkSummaryData } from '@/types/api';

const PORT_NAMES: Record<number, string> = {
  80: 'HTTP · DVWA',
  3306: 'MariaDB',
  8000: 'Backend API',
  5173: 'Dashboard (Vite dev)',
  6379: 'Redis Streams',
};

const num = (value: unknown) => (isNum(Number(value)) ? Number(value) : 0);

export function NetworkPage() {
  const query = useApi<NetworkSummaryData>('/api/network/summary', 8_000);
  const data = query.data;
  const summary = data?.summary ?? {};
  const alerts = num(summary.suricata_alerts);

  return (
    <Page>
      <PageHeader
        title="Lưu lượng mạng & IDS"
        description="Dữ liệu Suricata quan sát tại Nginx. Tốc độ tính từ flow kết thúc trong phút gần nhất; biểu đồ phân bố và tổng alert dùng toàn bộ lịch sử thu thập."
        actions={
          <Button onClick={() => void query.refetch()} disabled={query.isFetching}>
            <RefreshCw className={query.isFetching ? 'animate-spin' : ''} /> Làm mới
          </Button>
        }
      />
      <StaleNotice error={query.error} hasData={Boolean(data)} />

      <section className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        {query.isPending ? (
          Array.from({ length: 3 }, (_, index) => <Skeleton key={index} className="h-28" />)
        ) : (
          <>
            <KpiCard label="Flow mỗi giây" value={num(summary.flows_per_sec).toFixed(2)} hint="Trung bình 1 phút" icon={<ArrowDownUp />} tone="primary" />
            <KpiCard label="Băng thông" value={`${fmtBytes(num(summary.bytes_per_sec))}/s`} hint="Byte từ flow hoàn tất, trung bình 1 phút" icon={<Activity />} tone="success" />
            <KpiCard
              label="Cảnh báo Suricata"
              value={fmtNumber(alerts)}
              hint={alerts > 0 ? 'Có dấu hiệu tấn công mạng' : 'Chưa có cảnh báo mạng'}
              icon={<ShieldAlert />}
              tone={alerts > 0 ? 'warning' : 'neutral'}
            />
          </>
        )}
      </section>

      <section className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <Card>
          <CardHeader title="Giao thức" description="Phân bố theo số flow" />
          <CardContent>
            <BarList items={(data?.protocols ?? []).map((row) => ({ label: String(row.protocol || 'chưa rõ').toUpperCase(), value: num(row.count) }))} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader title="Cổng đích" description="Dịch vụ nhận nhiều lưu lượng nhất" />
          <CardContent>
            <BarList
              color="var(--color-success)"
              items={(data?.top_destination_ports ?? []).map((row) => ({
                label: PORT_NAMES[row.dst_port] ? `${row.dst_port} · ${PORT_NAMES[row.dst_port]}` : String(row.dst_port),
                value: num(row.count),
              }))}
            />
          </CardContent>
        </Card>
        <Card>
          <CardHeader title="IP nguồn" description="Điểm xuất phát của lưu lượng" />
          <CardContent>
            <BarList
              mono
              color="var(--color-sev-high)"
              items={(data?.top_sources ?? []).map((row) => ({ label: row.src_ip || 'Chưa ghi nhận IP', value: num(row.count) }))}
            />
          </CardContent>
        </Card>
        <Card>
          <CardHeader title="IP đích" description="Điểm đến của gói tin" />
          <CardContent>
            <BarList mono items={(data?.top_destinations ?? []).map((row) => ({ label: row.dst_ip || 'Chưa ghi nhận IP', value: num(row.count) }))} />
          </CardContent>
        </Card>
      </section>
    </Page>
  );
}
