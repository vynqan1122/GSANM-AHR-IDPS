import { useApi } from '@/api/query';
import { fmtDateTime, fmtNumber, timeAgo } from '@/lib/format';
import { isHealthy, statusTone } from '@/lib/severity';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/overlays';
import { DataTable, type Column } from '@/components/soc/DataTable';
import { EmptyState, Mono, Page, PageHeader, StaleNotice, StatusBadge, StatusDot, Truncate } from '@/components/soc/primitives';
import type { EventRow, Paged, SensorRow, SystemHealthData } from '@/types/api';

const SERVICES: Record<string, { label: string; group: string }> = {
  backend: { label: 'Backend FastAPI', group: 'Hạ tầng cốt lõi' },
  dashboard: { label: 'Dashboard', group: 'Hạ tầng cốt lõi' },
  postgres: { label: 'PostgreSQL', group: 'Hạ tầng cốt lõi' },
  redis: { label: 'Redis Streams', group: 'Hạ tầng cốt lõi' },
  dvwa: { label: 'DVWA', group: 'Lab DVWA' },
  nginx: { label: 'Nginx', group: 'Lab DVWA' },
  mariadb: { label: 'MariaDB', group: 'Lab DVWA' },
  suricata: { label: 'Suricata', group: 'Sensor và pipeline' },
  falco: { label: 'Falco', group: 'Sensor và pipeline' },
  wazuh: { label: 'Wazuh', group: 'Sensor và pipeline' },
  collector: { label: 'Collector', group: 'Sensor và pipeline' },
  normalizer: { label: 'Normalizer', group: 'Sensor và pipeline' },
  network_ai: { label: 'Network AI', group: 'AI và phản ứng' },
  log_ai: { label: 'Log AI', group: 'AI và phản ứng' },
  graph_ai: { label: 'Graph AI', group: 'AI và phản ứng' },
  fusion: { label: 'Fusion engine', group: 'AI và phản ứng' },
  correlation: { label: 'Correlation engine', group: 'AI và phản ứng' },
  rule_engine: { label: 'Rule engine', group: 'AI và phản ứng' },
  response_engine: { label: 'Response engine', group: 'AI và phản ứng' },
};
const GROUP_ORDER = ['Hạ tầng cốt lõi', 'Lab DVWA', 'Sensor và pipeline', 'AI và phản ứng', 'Khác'];

export function SystemHealth() {
  const health = useApi<SystemHealthData & { pipeline_activity_evidence?: { last_ingestion_at?: string; note?: string } }>('/api/system/health');
  const sensors = useApi<Paged<SensorRow>>('/api/sensors');
  const wazuh = useApi<Paged<EventRow>>('/api/events?source=wazuh&page_size=12', 10_000);

  const grouped = new Map<string, Array<{ key: string; status: string }>>();
  for (const [key, status] of Object.entries(health.data?.services ?? {})) {
    const group = SERVICES[key]?.group ?? 'Khác';
    grouped.set(group, [...(grouped.get(group) ?? []), { key, status }]);
  }
  const total = Object.keys(health.data?.services ?? {}).length;
  const healthy = Object.values(health.data?.services ?? {}).filter(isHealthy).length;

  const sensorColumns: Column<SensorRow>[] = [
    { key: 'sensor', header: 'Sensor', width: '140px', cell: (s) => <span className="font-medium capitalize">{s.sensor}</span> },
    { key: 'status', header: 'Trạng thái', width: '120px', cell: (s) => <StatusBadge status={s.status} /> },
    { key: 'event', header: 'Sự kiện gần nhất', width: 'minmax(150px, 1fr)', cell: (s) => <span className="text-muted-foreground">{s.last_event_at ? `${fmtDateTime(s.last_event_at)} · ${timeAgo(s.last_event_at)}` : '—'}</span> },
    { key: 'ingest', header: 'Ingestion gần nhất', width: 'minmax(150px, 1fr)', cell: (s) => <span className="text-muted-foreground">{s.last_ingestion_at ? timeAgo(s.last_ingestion_at) : '—'}</span> },
    { key: 'errors', header: 'Lỗi', width: '64px', align: 'right', cell: (s) => <span className="num">{fmtNumber(s.error_count)}</span> },
  ];

  const wazuhColumns: Column<EventRow>[] = [
    { key: 'time', header: 'Thời gian', width: '150px', cell: (e) => <Mono className="text-muted-foreground">{fmtDateTime(e.timestamp)}</Mono> },
    { key: 'rule', header: 'Rule', width: 'minmax(200px, 1fr)', cell: (e) => <Truncate text={e.rule?.name || e.rule?.rule_id} /> },
    { key: 'container', header: 'Container', width: 'minmax(140px, 0.7fr)', cell: (e) => <Truncate text={e.container?.name} className="text-muted-foreground" /> },
    { key: 'severity', header: 'Severity', width: '72px', align: 'right', cell: (e) => <span className="num">{e.severity ?? '—'}</span> },
  ];

  return (
    <Page>
      <PageHeader
        title="Sức khỏe hệ thống"
        description="Reporting: có dữ liệu trong 120 giây gần nhất. Stale: chưa có dữ liệu mới, chưa chắc container đã dừng. Trạng thái tiến trình kiểm tra riêng bằng Docker healthcheck."
        actions={
          health.data && (
            <span className="inline-flex h-7 items-center gap-2 rounded-md border border-border bg-card px-2.5 text-xs">
              <StatusDot tone={statusTone(health.data.overall)} />
              <span className="num">{healthy}/{total}</span> dịch vụ hoạt động
            </span>
          )
        }
      />
      <StaleNotice error={health.error} hasData={Boolean(health.data)} />

      {health.isPending ? (
        <Skeleton className="h-64" />
      ) : (
        GROUP_ORDER.filter((group) => grouped.has(group)).map((group) => (
          <section key={group}>
            <h2 className="mb-3 text-sm font-medium text-muted-foreground">{group}</h2>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6">
              {grouped.get(group)!.map(({ key, status }) => (
                <div key={key} className="glass flex min-w-0 flex-col gap-2 rounded-2xl p-4">
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-sm font-medium">{SERVICES[key]?.label ?? key}</span>
                    <StatusDot tone={statusTone(status)} />
                  </div>
                  <div className="flex items-center justify-between gap-2 text-[13px] text-subtle">
                    <span className="truncate font-mono">{key}</span>
                    <span className="capitalize text-muted-foreground">{status}</span>
                  </div>
                </div>
              ))}
            </div>
          </section>
        ))
      )}

      {health.data?.pipeline_activity_evidence?.last_ingestion_at && (
        <p className="text-xs text-muted-foreground">
          Ingestion gần nhất: <span className="text-foreground">{fmtDateTime(health.data.pipeline_activity_evidence.last_ingestion_at)}</span> ·{' '}
          {health.data.pipeline_activity_evidence.note}
        </p>
      )}

      <Card className="overflow-hidden">
        <CardHeader title="Sensor và thời điểm ingestion" />
        <DataTable label="Trạng thái sensor" columns={sensorColumns} rows={sensors.data?.items ?? []} rowKey={(s) => s.sensor} loading={sensors.isPending} minWidth={700} maxHeight={420} empty={<EmptyState title="Chưa có dữ liệu sensor" />} />
      </Card>

      <Card className="overflow-hidden">
        <CardHeader
          title="Wazuh Manager"
          description="Sự kiện Wazuh gần nhất. API Manager chỉ mở khi chạy start.sh --wazuh-api, tại https://127.0.0.1:55000 (HTTP 401 khi chưa đăng nhập là bình thường)."
        />
        <CardContent className="px-0 pb-0">
          <DataTable label="Sự kiện Wazuh" columns={wazuhColumns} rows={wazuh.data?.items ?? []} rowKey={(e) => e.event_id} loading={wazuh.isPending} minWidth={620} maxHeight={380} empty={<EmptyState title="Chưa có sự kiện Wazuh" />} />
        </CardContent>
      </Card>
    </Page>
  );
}
