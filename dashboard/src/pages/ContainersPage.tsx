import { useState } from 'react';
import { Boxes } from 'lucide-react';
import { useApi } from '@/api/query';
import { fmtDateTime, fmtNumber, fmtPct, isNum, timeAgo } from '@/lib/format';
import { scoreTone } from '@/lib/severity';
import { Card } from '@/components/ui/card';
import { Sheet } from '@/components/ui/overlays';
import { DataTable, type Column } from '@/components/soc/DataTable';
import { EmptyState, Field, JsonView, Mono, Page, PageHeader, RiskBadge, StaleNotice, Truncate } from '@/components/soc/primitives';
import { Badge } from '@/components/ui/badge';
import type { ContainerRow } from '@/types/api';

export function ContainersPage() {
  const query = useApi<{ items: ContainerRow[] }>('/api/containers', 10_000);
  const rows = query.data?.items ?? [];
  const [selected, setSelected] = useState<ContainerRow | null>(null);

  const columns: Column<ContainerRow>[] = [
    { key: 'name', header: 'Container', width: 'minmax(200px, 1.2fr)', cell: (c) => <Truncate text={c.name} className="font-medium" /> },
    { key: 'image', header: 'Image', width: 'minmax(200px, 1.4fr)', cell: (c) => <Truncate mono text={c.image} className="text-muted-foreground" /> },
    { key: 'events', header: 'Sự kiện', width: '88px', align: 'right', cell: (c) => <span className="num">{fmtNumber(c.event_count)}</span> },
    { key: 'falco', header: 'Cảnh báo Falco', width: '124px', align: 'right', cell: (c) =>
      isNum(c.falco_alert_count) ? <Badge tone={c.falco_alert_count > 0 ? 'warning' : 'neutral'} className="num">{c.falco_alert_count}</Badge> : <span className="text-subtle">—</span> },
    { key: 'risk', header: 'Rủi ro', width: '96px', cell: (c) => (isNum(c.current_risk) ? <RiskBadge level={scoreTone(c.current_risk)} /> : <span className="text-subtle">—</span>) },
    { key: 'seen', header: 'Thấy lần cuối', width: '120px', cell: (c) => <span className="text-xs text-muted-foreground">{timeAgo(c.last_seen)}</span> },
  ];

  return (
    <Page>
      <PageHeader
        title="Containers & runtime"
        description="Container xuất hiện trong sự kiện của Falco, Wazuh và Docker. Số liệu CPU/RAM không được thu thập nên không hiển thị."
      />
      <StaleNotice error={query.error} hasData={Boolean(query.data)} />
      <Card className="overflow-hidden">
        <DataTable
          label="Containers"
          columns={columns}
          rows={rows}
          rowKey={(c) => c.name}
          selectedKey={selected?.name}
          onRowClick={setSelected}
          loading={query.isPending}
          minWidth={860}
          empty={<EmptyState icon={<Boxes />} title="Chưa có container nào trong phạm vi giám sát" />}
        />
      </Card>
      <Sheet open={selected !== null} onOpenChange={(open) => !open && setSelected(null)} title={selected?.name ?? ''} description={selected?.image ?? undefined}>
        {selected && (
          <div className="flex flex-col gap-4">
            <div className="grid grid-cols-2 gap-2">
              <Field label="Sự kiện"><span className="num">{fmtNumber(selected.event_count)}</span></Field>
              <Field label="Thấy lần cuối">{fmtDateTime(selected.last_seen)}</Field>
              <Field label="Rủi ro hiện tại"><span className="num">{fmtPct(selected.current_risk)}</span></Field>
              <Field label="Image">{selected.image ? <Mono>{selected.image}</Mono> : '—'}</Field>
            </div>
            <JsonView value={selected} />
          </div>
        )}
      </Sheet>
    </Page>
  );
}
