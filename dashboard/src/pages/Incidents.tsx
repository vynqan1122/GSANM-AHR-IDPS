import { useMemo, useState } from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router';
import { Clock, FileText, GitBranch, Search, Sparkles } from 'lucide-react';
import { useApi } from '@/api/query';
import { fmtDateTime, fmtDuration, fmtNumber, fmtScore, shortId, timeAgo } from '@/lib/format';
import { scoreTone } from '@/lib/severity';
import { Badge } from '@/components/ui/badge';
import { Card } from '@/components/ui/card';
import { Input, Segmented } from '@/components/ui/input';
import { Skeleton, Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/overlays';
import { AttackGraph } from '@/components/AttackGraph';
import { DataTable, type Column } from '@/components/soc/DataTable';
import { EventDetailSheet } from '@/components/soc/EventDetailSheet';
import {
  CopyButton,
  EmptyState,
  Field,
  JsonView,
  Mono,
  Page,
  PageHeader,
  RiskBadge,
  SectionLabel,
  SeverityBadge,
  SourceBadge,
  StaleNotice,
  StatusBadge,
  Truncate,
} from '@/components/soc/primitives';
import type { EventRow, IncidentRow, Paged } from '@/types/api';

type TimelineStep = {
  timestamp?: string;
  event_type?: string;
  source?: string;
  severity?: number;
  fusion_score?: number;
  risk_level?: string;
  action?: string;
  description?: string;
};

const STATUS_OPTIONS = ['all', 'open', 'investigating', 'contained', 'resolved'] as const;
const statusText: Record<string, string> = {
  all: 'Tất cả',
  open: 'Đang mở',
  investigating: 'Điều tra',
  contained: 'Khoanh vùng',
  resolved: 'Đã xử lý',
};

export function Incidents() {
  const { incidentId } = useParams();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const [status, setStatus] = useState<string>('all');
  const [event, setEvent] = useState<EventRow | null>(null);
  const query = params.get('q') ?? '';

  const list = useApi<Paged<IncidentRow>>('/api/incidents?page_size=50', 10_000);
  const detail = useApi<IncidentRow>(incidentId ? `/api/incidents/${encodeURIComponent(incidentId)}` : null, 10_000);
  const incidents = list.data?.items ?? [];

  const rows = useMemo(() => {
    const term = query.trim().toLowerCase();
    return incidents.filter((incident) => {
      if (status !== 'all' && incident.status?.toLowerCase() !== status) return false;
      if (!term) return true;
      return [incident.incident_id, incident.title, incident.attack_type, ...(incident.source_ips ?? []), ...(incident.targets ?? [])].some((value) =>
        value?.toLowerCase().includes(term),
      );
    });
  }, [incidents, status, query]);

  const open = (id: string) => navigate(`/incidents/${encodeURIComponent(id)}${params.toString() ? `?${params}` : ''}`);

  const columns: Column<IncidentRow>[] = [
    { key: 'risk', header: 'Rủi ro', width: '64px', cell: (i) => (i.risk_score == null ? <span className="text-subtle">—</span> : <Badge tone={scoreTone(i.risk_score)} className="num">{fmtScore(i.risk_score)}</Badge>) },
    {
      key: 'title',
      header: 'Sự cố',
      width: 'minmax(220px, 1fr)',
      cell: (i) => (
        <div className="min-w-0 leading-tight">
          <Truncate text={i.title || 'Phát hiện bất thường'} className="font-medium" />
          <div className="mt-0.5 truncate text-[11px] text-subtle">
            <span className="font-mono">{shortId(i.incident_id, 16)}</span> · {i.attack_type || 'chưa phân loại'}
          </div>
        </div>
      ),
    },
    { key: 'events', header: 'Sự kiện', width: '64px', align: 'right', cell: (i) => <span className="num">{fmtNumber(i.event_count)}</span> },
    { key: 'status', header: 'Trạng thái', width: '112px', cell: (i) => <StatusBadge status={i.status} /> },
  ];

  return (
    <Page>
      <PageHeader
        title="Sự cố & chuỗi tấn công"
        description="Các sự cố do correlation engine gom từ sự kiện của nhiều sensor. Chọn một sự cố để xem graph, timeline, giải thích AI và bằng chứng."
      />
      <StaleNotice error={list.error} hasData={Boolean(list.data)} />

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-[minmax(500px,0.85fr)_minmax(0,1.4fr)]">
        <Card className="flex min-w-0 flex-col overflow-hidden xl:sticky xl:top-0 xl:max-h-[calc(100vh-14rem)]">
          <div className="flex flex-col gap-2 border-b border-border p-3">
            <div className="relative">
              <Search className="pointer-events-none absolute top-2.5 left-2.5 size-3.5 text-subtle" />
              <Input
                value={query}
                onChange={(e) => {
                  const next = new URLSearchParams(params);
                  if (e.target.value) next.set('q', e.target.value);
                  else next.delete('q');
                  setParams(next, { replace: true });
                }}
                placeholder="Tìm theo mã, tiêu đề, IP, loại tấn công…"
                className="pl-8"
                aria-label="Tìm sự cố"
              />
            </div>
            <Segmented
              label="Lọc theo trạng thái"
              value={status}
              onChange={setStatus}
              options={STATUS_OPTIONS.map((value) => ({ value, label: statusText[value] }))}
            />
            <div className="num text-xs text-muted-foreground">
              {rows.length} / {fmtNumber(list.data?.total)} sự cố
            </div>
          </div>
          <DataTable
            label="Danh sách sự cố"
            columns={columns}
            rows={rows}
            rowKey={(i) => i.incident_id}
            selectedKey={incidentId}
            onRowClick={(i) => open(i.incident_id)}
            rowHeight={52}
            minWidth={440}
            maxHeight="calc(100vh - 21rem)"
            loading={list.isPending}
            empty={<EmptyState title="Không có sự cố phù hợp" description="Thử đổi bộ lọc trạng thái hoặc từ khóa." />}
          />
        </Card>

        <div className="min-w-0">
          {!incidentId ? (
            <Card>
              <EmptyState className="py-20" icon={<GitBranch />} title="Chọn một sự cố" description="Danh sách bên trái cho phép mở graph attack chain, timeline và bằng chứng của từng sự cố." />
            </Card>
          ) : detail.isPending ? (
            <Skeleton className="h-96" />
          ) : detail.error && !detail.data ? (
            <Card>
              <EmptyState className="py-20" title="Không tải được sự cố" description={`Mã ${incidentId} không tồn tại hoặc API đang lỗi.`} />
            </Card>
          ) : detail.data ? (
            <IncidentDetail incident={detail.data} onEvent={setEvent} />
          ) : null}
        </div>
      </div>

      <EventDetailSheet event={event} onClose={() => setEvent(null)} />
    </Page>
  );
}

function IncidentDetail({ incident, onEvent }: { incident: IncidentRow; onEvent: (event: EventRow) => void }) {
  const timeline = (incident.timeline ?? []) as TimelineStep[];
  const events = (incident.events ?? []) as EventRow[];
  const edgeCount = incident.attack_graph?.edges?.length ?? 0;

  const eventColumns: Column<EventRow>[] = [
    { key: 'time', header: 'Thời gian', width: '150px', cell: (e) => <Mono className="text-muted-foreground">{fmtDateTime(e.timestamp)}</Mono> },
    { key: 'source', header: 'Sensor', width: '96px', cell: (e) => <SourceBadge source={e.source} /> },
    { key: 'type', header: 'Loại sự kiện', width: 'minmax(140px, 1fr)', cell: (e) => <Truncate text={e.event_type} /> },
    { key: 'ip', header: 'IP nguồn', width: '130px', cell: (e) => (e.src_ip ? <Mono>{e.src_ip}</Mono> : <span className="text-subtle">—</span>) },
    { key: 'severity', header: 'Severity', width: '72px', cell: (e) => <SeverityBadge severity={e.severity} /> },
  ];

  return (
    <Card className="min-w-0 overflow-hidden">
      <div className="flex flex-col gap-3 border-b border-border p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex items-center gap-1 text-xs text-subtle">
              <span className="font-mono">{incident.incident_id}</span>
              <CopyButton value={incident.incident_id} label="Sao chép mã sự cố" />
            </div>
            <h2 className="mt-0.5 text-base leading-snug font-semibold wrap-anywhere">{incident.title}</h2>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <RiskBadge level={incident.risk_score == null ? null : scoreTone(incident.risk_score)} />
            <StatusBadge status={incident.status} />
          </div>
        </div>
        <div className="grid grid-cols-2 gap-2 lg:grid-cols-4">
          <Field label="Rủi ro">
            <span className="num">{fmtScore(incident.risk_score)}</span> / 1.00
          </Field>
          <Field label="Bắt đầu">{fmtDateTime(incident.first_seen)}</Field>
          <Field label="Thời lượng">{fmtDuration(incident.first_seen, incident.last_seen)}</Field>
          <Field label="Sự kiện liên quan">
            <span className="num">{fmtNumber(incident.event_count)}</span>
          </Field>
        </div>
        <div className="flex flex-wrap gap-x-5 gap-y-1 text-xs text-muted-foreground">
          <span>
            Loại tấn công: <span className="text-foreground">{incident.attack_type || 'chưa phân loại'}</span>
          </span>
          <span>
            IP nguồn: <span className="font-mono text-foreground">{incident.source_ips?.join(', ') || 'chưa ghi nhận'}</span>
          </span>
          <span>
            Mục tiêu: <span className="text-foreground">{incident.targets?.join(', ') || 'chưa ghi nhận'}</span>
          </span>
        </div>
      </div>

      <Tabs defaultValue="graph">
        <TabsList>
          <TabsTrigger value="graph">
            <GitBranch /> Attack chain
          </TabsTrigger>
          <TabsTrigger value="timeline">
            <Clock /> Timeline
          </TabsTrigger>
          <TabsTrigger value="ai">
            <Sparkles /> AI & Rules
          </TabsTrigger>
          <TabsTrigger value="evidence">
            <FileText /> Bằng chứng <span className="num text-subtle">{events.length}</span>
          </TabsTrigger>
        </TabsList>

        <TabsContent value="graph">
          <p className="mb-3 text-xs text-muted-foreground">
            Attack graph edges: <span className="num text-foreground">{edgeCount}</span> · tối đa 20 request HTTP đầu tiên của sự cố này. Toàn bộ lịch sử ở trang Graph 20 request.
          </p>
          <AttackGraph graph={incident.attack_graph} />
        </TabsContent>

        <TabsContent value="timeline">
          {timeline.length === 0 ? (
            <EmptyState title="Chưa có timeline" description="Chuỗi sự kiện sẽ xuất hiện khi correlation engine phân tích xong." />
          ) : (
            <ol className="relative ml-2 flex max-h-130 flex-col gap-4 overflow-y-auto border-l border-border pl-5">
              {timeline.map((step, index) => (
                <li key={index} className="relative">
                  <span className="absolute top-1.5 -left-6.25 size-2 rounded-full bg-primary ring-4 ring-card" />
                  <div className="flex flex-wrap items-center gap-2 text-xs text-subtle">
                    <Mono className="text-muted-foreground">{fmtDateTime(step.timestamp) !== '—' ? fmtDateTime(step.timestamp) : `Giai đoạn ${index + 1}`}</Mono>
                    {step.source && <SourceBadge source={step.source} />}
                    {step.severity != null && <SeverityBadge severity={step.severity} />}
                    {step.risk_level && <RiskBadge level={step.risk_level} />}
                  </div>
                  <div className="mt-1 text-[13px] font-medium">{step.action || step.event_type || 'Hành vi được phát hiện'}</div>
                  {step.description && <p className="text-xs text-muted-foreground">{step.description}</p>}
                  {step.fusion_score != null && <p className="num text-xs text-subtle">Fusion score {fmtScore(step.fusion_score)}</p>}
                </li>
              ))}
            </ol>
          )}
        </TabsContent>

        <TabsContent value="ai">
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <section>
              <SectionLabel>Tóm tắt AI</SectionLabel>
              <JsonView value={incident.ai_summary ?? { note: 'Không có tóm tắt AI cho sự cố này.' }} />
            </section>
            <section>
              <SectionLabel>Rule liên quan</SectionLabel>
              <JsonView value={incident.rule_summary ?? { note: 'Không có rule khớp.' }} />
            </section>
          </div>
        </TabsContent>

        <TabsContent value="evidence" className="px-0 pb-0">
          <DataTable
            label="Sự kiện bằng chứng"
            columns={eventColumns}
            rows={events}
            rowKey={(e) => e.event_id}
            onRowClick={onEvent}
            maxHeight={440}
            minWidth={640}
            empty={<EmptyState title="Chưa có sự kiện bằng chứng" />}
          />
        </TabsContent>
      </Tabs>
    </Card>
  );
}
