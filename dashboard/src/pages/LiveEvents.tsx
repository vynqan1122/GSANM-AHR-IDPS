import { useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'react-router';
import { Pause, Play, Search, Trash2 } from 'lucide-react';
import { useApi } from '@/api/query';
import { useLiveEventsContext } from '@/hooks/useLiveEvents';
import { fmtDateTime } from '@/lib/format';
import { KNOWN_SOURCES, sourceMeta } from '@/lib/severity';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input, NativeSelect, Segmented } from '@/components/ui/input';
import { DataTable, type Column } from '@/components/soc/DataTable';
import { EventDetailSheet } from '@/components/soc/EventDetailSheet';
import { EmptyState, Mono, Page, PageHeader, RiskBadge, ScoreBar, SeverityBadge, SourceBadge, StaleNotice, Truncate } from '@/components/soc/primitives';
import type { EventRow, Paged } from '@/types/api';

const MAX_ROWS = 500;

export function LiveEvents() {
  const [params, setParams] = useSearchParams();
  const live = useLiveEventsContext();
  // History is loaded once; live events arrive over the shared socket.
  const history = useApi<Paged<EventRow>>('/api/events?page_size=100', 0);

  const [paused, setPaused] = useState(false);
  const [frozen, setFrozen] = useState<EventRow[]>([]);
  const [cleared, setCleared] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<EventRow | null>(null);
  const [source, setSource] = useState('all');
  const [minSeverity, setMinSeverity] = useState(0);
  const query = params.get('q') ?? '';

  const merged = useMemo(() => {
    const map = new Map<string, EventRow>();
    for (const event of [...live.events, ...(history.data?.items ?? [])]) {
      if (!map.has(event.event_id) && !cleared.has(event.event_id)) map.set(event.event_id, event);
    }
    return Array.from(map.values()).slice(0, MAX_ROWS);
  }, [live.events, history.data, cleared]);

  // While paused, show the snapshot taken at the moment of pausing.
  const pausedRef = useRef(paused);
  pausedRef.current = paused;
  useEffect(() => {
    if (!pausedRef.current) setFrozen(merged);
  }, [merged]);
  const base = paused ? frozen : merged;

  const rows = useMemo(() => {
    const term = query.trim().toLowerCase();
    return base.filter((event) => {
      if (source !== 'all' && event.source?.toLowerCase() !== source) return false;
      if ((event.severity ?? 0) < minSeverity) return false;
      if (!term) return true;
      return [event.event_id, event.src_ip, event.dst_ip, event.event_type, event.rule?.name, event.rule?.rule_id, event.container?.name].some((value) =>
        value?.toLowerCase().includes(term),
      );
    });
  }, [base, source, minSeverity, query]);

  const sourceCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const event of base) counts[event.source?.toLowerCase()] = (counts[event.source?.toLowerCase()] ?? 0) + 1;
    return counts;
  }, [base]);

  const columns: Column<EventRow>[] = [
    { key: 'time', header: 'Thời gian', width: '128px', cell: (e) => <Mono className="text-muted-foreground">{fmtDateTime(e.timestamp)}</Mono> },
    { key: 'source', header: 'Sensor', width: '96px', cell: (e) => <SourceBadge source={e.source} /> },
    {
      key: 'activity',
      header: 'Hoạt động',
      width: 'minmax(130px, 1.2fr)',
      cell: (e) => (
        <span className="flex min-w-0 items-center gap-2">
          <span className="shrink-0 font-medium">{e.event_type}</span>
          {e.container?.name && <span className="truncate text-xs text-subtle">{e.container.name}</span>}
        </span>
      ),
    },
    {
      key: 'ip',
      header: 'Nguồn → Đích',
      width: 'minmax(190px, 1.1fr)',
      cell: (e) =>
        e.src_ip || e.dst_ip ? (
          <Truncate mono text={`${e.src_ip ?? '?'} → ${e.dst_ip ?? '?'}`} />
        ) : (
          <span className="text-subtle">—</span>
        ),
    },
    { key: 'rule', header: 'Rule', width: 'minmax(120px, 1fr)', cell: (e) => <Truncate text={e.rule?.name || e.rule?.rule_id} className="text-muted-foreground" /> },
    { key: 'severity', header: 'Severity', width: '68px', cell: (e) => <SeverityBadge severity={e.severity} /> },
    { key: 'fusion', header: 'Fusion score', width: '116px', cell: (e) => <ScoreBar value={e.ai?.fusion_score} /> },
    { key: 'risk', header: 'Mức rủi ro', width: '120px', cell: (e) => <RiskBadge level={e.ai?.risk_level} /> },
  ];

  const togglePause = () => {
    if (!paused) setFrozen(merged);
    setPaused(!paused);
  };

  const setQuery = (value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set('q', value);
    else next.delete('q');
    setParams(next, { replace: true });
  };

  return (
    <Page>
      <PageHeader
        title="Sự kiện realtime"
        description="Sự kiện chuẩn hóa từ Suricata, Falco, Wazuh và Nginx. Bấm vào một dòng để xem điểm AI và payload gốc."
        actions={
          <>
            <Button variant={paused ? 'default' : 'secondary'} onClick={togglePause}>
              {paused ? <Play /> : <Pause />}
              {paused ? 'Tiếp tục' : 'Tạm dừng'}
            </Button>
            <Button
              variant="secondary"
              onClick={() => {
                setCleared(new Set([...cleared, ...merged.map((event) => event.event_id)]));
                setFrozen([]);
                live.clear();
              }}
            >
              <Trash2 /> Xóa bộ đệm
            </Button>
          </>
        }
      />
      <StaleNotice error={history.error} hasData={Boolean(history.data)} />

      <Card className="overflow-hidden">
        <div className="flex flex-wrap items-center gap-2 border-b border-border p-3">
          <div className="relative min-w-44 flex-1 sm:max-w-60">
            <Search className="pointer-events-none absolute top-2.5 left-2.5 size-3.5 text-subtle" />
            <Input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Tìm IP, rule, container…"
              className="pl-8"
              aria-label="Tìm sự kiện"
            />
          </div>
          <Segmented
            label="Lọc theo sensor"
            value={source}
            onChange={setSource}
            options={[
              { value: 'all', label: 'Tất cả', count: base.length },
              ...KNOWN_SOURCES.filter((key) => sourceCounts[key]).map((key) => ({ value: key, label: sourceMeta(key).label, count: sourceCounts[key] })),
            ]}
          />
          <NativeSelect value={minSeverity} onChange={(event) => setMinSeverity(Number(event.target.value))} aria-label="Severity tối thiểu">
            <option value={0}>Mọi severity</option>
            <option value={4}>Severity ≥ 4 · Trung bình+</option>
            <option value={6}>Severity ≥ 6 · Cao+</option>
            <option value={8}>Severity ≥ 8 · Nghiêm trọng</option>
          </NativeSelect>
          <span className="num ml-auto text-[13px] whitespace-nowrap text-muted-foreground">
            {rows.length.toLocaleString('vi-VN')} sự kiện{paused && ' · tạm dừng'}
          </span>
        </div>

        <DataTable
          label="Danh sách sự kiện"
          columns={columns}
          rows={rows}
          rowKey={(event) => event.event_id}
          selectedKey={selected?.event_id}
          onRowClick={setSelected}
          rowClassName={(event) => (live.freshIds.has(event.event_id) && !paused ? 'animate-row-flash' : undefined)}
          loading={history.isPending}
          maxHeight="calc(100vh - 290px)"
          minWidth={1040}
          empty={
            <EmptyState
              title="Không có sự kiện phù hợp"
              description={base.length ? 'Thử bỏ bớt bộ lọc hoặc từ khóa tìm kiếm.' : 'Chưa nhận được sự kiện nào. Luồng sẽ tự cập nhật khi sensor báo cáo.'}
            />
          }
        />
      </Card>

      <EventDetailSheet event={selected} onClose={() => setSelected(null)} />
    </Page>
  );
}
