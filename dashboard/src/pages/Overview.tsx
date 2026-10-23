import { useMemo } from 'react';
import { useNavigate } from 'react-router';
import { Activity, AlertTriangle, FileCheck2, Radio, ShieldAlert } from 'lucide-react';
import { useApi } from '@/api/query';
import { fmtCompact, fmtDateTime, fmtNumber, shortId, timeAgo } from '@/lib/format';
import { isHealthy, scoreTone, severityLabel, severityTone, sourceMeta, toneColor, type Tone } from '@/lib/severity';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/overlays';
import {
  BarList,
  EmptyState,
  KpiCard,
  MiniBar,
  Page,
  PageHeader,
  RiskBadge,
  ScoreGauge,
  Sparkline,
  StaleNotice,
  StatusBadge,
  StatusDot,
} from '@/components/soc/primitives';
import { EventsAreaChart, pivotTimeseries } from '@/components/soc/charts';
import type { IncidentRow, OverviewData, Paged, SensorRow, TimeseriesPoint } from '@/types/api';

export function Overview() {
  const navigate = useNavigate();
  const overview = useApi<OverviewData>('/api/dashboard/overview');
  const series = useApi<{ items: TimeseriesPoint[] }>('/api/dashboard/timeseries?minutes=60');
  const sensors = useApi<Paged<SensorRow>>('/api/sensors');
  const incidents = useApi<Paged<IncidentRow>>('/api/incidents?page_size=5', 10_000);

  const cards = overview.data?.cards ?? {};
  const points = series.data?.items ?? [];
  const sensorRows = sensors.data?.items ?? [];
  const reporting = sensorRows.filter((row) => isHealthy(row.status)).length;
  const critical = (cards.critical_alerts ?? 0) > 0 || (cards.critical_incidents ?? 0) > 0;
  const risk = cards.overall_security_risk;

  // Per-minute totals feed the event sparkline.
  const totals = useMemo(() => {
    const { sources, rows } = pivotTimeseries(points);
    return rows.map((row) => sources.reduce((sum, source) => sum + Number(row[source] ?? 0), 0));
  }, [points]);

  const loading = overview.isPending;

  return (
    <Page>
      <PageHeader
        title="Tổng quan an ninh"
        description="Giám sát hybrid trên lab DVWA: Network (Suricata), Runtime (Falco), Host/SIEM (Wazuh), Nginx và các mô hình AI."
        actions={
          <span
            className={`inline-flex h-7 items-center gap-2 rounded-md border px-2.5 text-xs font-medium ${
              critical ? 'border-sev-critical/30 bg-sev-critical/10 text-sev-critical' : 'border-success/30 bg-success/10 text-success'
            }`}
          >
            <StatusDot tone={critical ? 'critical' : 'success'} pulse={critical} />
            {critical ? 'Phát hiện dấu hiệu tấn công' : 'Hoạt động bình thường'}
          </span>
        }
      />
      <StaleNotice error={overview.error} hasData={Boolean(overview.data)} />

      <section aria-label="Chỉ số chính" className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-5">
        {loading ? (
          Array.from({ length: 5 }, (_, index) => <Skeleton key={index} className="h-38" />)
        ) : (
          <>
            <KpiCard
              label="Tổng sự kiện"
              value={fmtNumber(cards.total_events)}
              hint={`${fmtNumber(cards.events_per_min)} sự kiện/phút`}
              icon={<Activity />}
              tone="primary"
              onClick={() => navigate('/events')}
            >
              <Sparkline data={totals} />
            </KpiCard>
            <KpiCard
              label="Cảnh báo đang mở"
              value={fmtNumber(cards.active_alerts)}
              hint={`${fmtNumber(cards.critical_alerts)} mức nghiêm trọng`}
              icon={<AlertTriangle />}
              tone={cards.critical_alerts ? 'critical' : cards.active_alerts ? 'warning' : 'success'}
              onClick={() => navigate('/events')}
            >
              <MiniBar value={(cards.critical_alerts ?? 0) / Math.max(1, cards.active_alerts ?? 0)} tone="critical" />
            </KpiCard>
            <KpiCard
              label="Sự cố đang mở"
              value={fmtNumber(cards.open_incidents)}
              hint={`${fmtNumber(cards.critical_incidents)} sự cố nghiêm trọng`}
              icon={<ShieldAlert />}
              tone={cards.critical_incidents ? 'critical' : 'neutral'}
              onClick={() => navigate('/incidents')}
            >
              <MiniBar value={(cards.critical_incidents ?? 0) / Math.max(1, cards.open_incidents ?? 0)} tone="critical" />
            </KpiCard>
            <KpiCard
              label="Sensor đang báo cáo"
              value={sensorRows.length ? `${reporting}/${sensorRows.length}` : '—'}
              hint={sensorRows.length && reporting === sensorRows.length ? 'Tất cả hoạt động' : 'Có sensor chưa báo cáo'}
              icon={<Radio />}
              tone={sensorRows.length && reporting === sensorRows.length ? 'success' : 'warning'}
              onClick={() => navigate('/health')}
            >
              <MiniBar value={sensorRows.length ? reporting / sensorRows.length : 0} tone="success" />
            </KpiCard>
            <KpiCard
              label="Quy tắc Active"
              value={fmtNumber(cards.active_rules)}
              hint={`${fmtNumber(cards.shadow_rules)} quy tắc Shadow`}
              icon={<FileCheck2 />}
              onClick={() => navigate('/rules')}
            >
              <MiniBar value={0} />
            </KpiCard>
          </>
        )}
      </section>

      <section className="grid grid-cols-1 gap-3 xl:grid-cols-[minmax(0,1fr)_320px]">
        <Card>
          <CardHeader title="Sự kiện theo thời gian" description="60 phút gần nhất, xếp chồng theo sensor nguồn" />
          <CardContent>
            {series.isPending ? <Skeleton className="h-72.5" /> : <EventsAreaChart points={points} />}
          </CardContent>
        </Card>
        <Card>
          <CardHeader title="Rủi ro tổng hợp" description="Fusion AI kết hợp rule correlation" />
          <CardContent className="flex flex-col items-center gap-3 pt-2">
            <ScoreGauge value={risk} />
            <RiskBadge level={risk == null ? null : scoreTone(risk)} />
          </CardContent>
        </Card>
      </section>

      <section className="grid grid-cols-1 gap-3 lg:grid-cols-3">
        <Card>
          <CardHeader title="Sự kiện theo sensor" description="Toàn bộ lịch sử thu thập" />
          <CardContent>
            <BarList
              items={(overview.data?.events_by_source ?? []).map((row) => ({
                label: sourceMeta(row.source).label,
                value: row.count,
                color: sourceMeta(row.source).color,
              }))}
            />
          </CardContent>
        </Card>
        <Card>
          <CardHeader title="Cảnh báo theo mức độ" description="Severity chuẩn hóa thang 1–10" />
          <CardContent>
            <BarList
              items={(overview.data?.alerts_by_severity ?? []).map((row) => ({
                label: `${row.severity} · ${severityLabel(row.severity)}`,
                value: row.count,
                color: toneColor[severityTone(row.severity) as Tone],
              }))}
            />
          </CardContent>
        </Card>
        <Card>
          <CardHeader title="IP nguồn nhiều nhất" description="Theo số sự kiện ghi nhận" />
          <CardContent>
            <BarList
              mono
              color="var(--color-sev-high)"
              empty="Chưa ghi nhận IP nguồn."
              items={(overview.data?.top_source_ips ?? []).map((row) => ({ label: row.src_ip || 'Chưa ghi nhận IP', value: row.count }))}
            />
          </CardContent>
        </Card>
      </section>

      <Card>
        <CardHeader
          title="Sự cố gần đây"
          description={`${fmtCompact(incidents.data?.total)} sự cố đã tương quan`}
          actions={
            <button type="button" onClick={() => navigate('/incidents')} className="text-xs text-primary hover:underline">
              Xem tất cả
            </button>
          }
        />
        <CardContent className="px-0">
          {incidents.isPending ? (
            <Skeleton className="mx-4 h-24" />
          ) : !incidents.data?.items.length ? (
            <EmptyState title="Chưa có sự cố nào được tương quan" description="Sự cố xuất hiện khi correlation engine gom đủ sự kiện liên quan." />
          ) : (
            <ul>
              {incidents.data.items.map((incident) => (
                <li key={incident.incident_id}>
                  <button
                    type="button"
                    onClick={() => navigate(`/incidents/${encodeURIComponent(incident.incident_id)}`)}
                    className="flex w-full items-center gap-3 border-t border-border/60 px-4 py-2.5 text-left hover:bg-hover/50"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-[13px] font-medium text-foreground">{incident.title}</div>
                      <div className="mt-0.5 text-xs text-muted-foreground">
                        <span className="font-mono">{shortId(incident.incident_id, 14)}</span> · {fmtNumber(incident.event_count)} sự kiện ·{' '}
                        <span title={fmtDateTime(incident.last_seen)}>{timeAgo(incident.last_seen)}</span>
                      </div>
                    </div>
                    <RiskBadge level={incident.risk_score == null ? null : scoreTone(incident.risk_score)} />
                    <StatusBadge status={incident.status} />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </Page>
  );
}
