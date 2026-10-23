import { useState } from 'react';
import { Lock } from 'lucide-react';
import { Link } from 'react-router';
import { useApi } from '@/api/query';
import { fmtDateTime, fmtPct, shortId } from '@/lib/format';
import { scoreTone } from '@/lib/severity';
import { Card } from '@/components/ui/card';
import { Sheet } from '@/components/ui/overlays';
import { DataTable, type Column } from '@/components/soc/DataTable';
import { CopyButton, EmptyState, Field, JsonView, Mono, Page, PageHeader, RiskBadge, SectionLabel, StaleNotice, StatusBadge, Truncate } from '@/components/soc/primitives';
import type { Paged, ResponseRow } from '@/types/api';

export function Responses() {
  const query = useApi<Paged<ResponseRow>>('/api/responses?page_size=50', 15_000);
  const rows = query.data?.items ?? [];
  const [selected, setSelected] = useState<ResponseRow | null>(null);

  const columns: Column<ResponseRow>[] = [
    { key: 'time', header: 'Thời gian', width: '150px', cell: (r) => <Mono className="text-muted-foreground">{fmtDateTime(r.started_at)}</Mono> },
    { key: 'incident', header: 'Sự cố', width: '120px', cell: (r) => (r.incident_id ? <Mono className="text-primary">{shortId(r.incident_id, 12)}</Mono> : <span className="text-subtle">—</span>) },
    { key: 'action', header: 'Hành động', width: '110px', cell: (r) => <span className="font-medium capitalize">{r.action}</span> },
    { key: 'level', header: 'Mức', width: '80px', cell: (r) => <span className="text-muted-foreground">{r.response_level?.replace('level_', 'L') ?? '—'}</span> },
    { key: 'target', header: 'Mục tiêu', width: 'minmax(120px, 0.7fr)', cell: (r) => <Truncate mono text={r.target} /> },
    { key: 'reason', header: 'Lý do', width: 'minmax(220px, 1.4fr)', cell: (r) => <Truncate text={r.reason} className="text-muted-foreground" /> },
    { key: 'risk', header: 'Rủi ro', width: '88px', cell: (r) => <RiskBadge level={r.risk == null ? null : scoreTone(r.risk)} /> },
    { key: 'status', header: 'Trạng thái', width: '112px', cell: (r) => <StatusBadge status={r.status} /> },
    { key: 'evidence', header: 'Bằng chứng', width: '96px', align: 'right', cell: (r) => (r.evidence_file_count ? <span className="num">{r.evidence_file_count} tệp</span> : <span className="text-subtle">—</span>) },
  ];

  return (
    <Page>
      <PageHeader
        title="Phản ứng chủ động"
        description="Chính sách an toàn của lab: mọi chặn IP hoặc cách ly container đều có TTL, có rollback và lưu bằng chứng. Mặc định hệ thống chỉ cảnh báo (alert_only), không tự chặn."
      />
      <StaleNotice error={query.error} hasData={Boolean(query.data)} />

      <Card className="overflow-hidden">
        <DataTable
          label="Lịch sử phản ứng"
          columns={columns}
          rows={rows}
          rowKey={(r) => r.response_id}
          selectedKey={selected?.response_id}
          onRowClick={setSelected}
          loading={query.isPending}
          minWidth={1100}
          maxHeight="calc(100vh - 220px)"
          empty={<EmptyState icon={<Lock />} title="Chưa có hành động phản ứng nào" description="Response engine ghi lại mỗi quyết định, kể cả khi chỉ cảnh báo." />}
        />
      </Card>

      <Sheet open={selected !== null} onOpenChange={(open) => !open && setSelected(null)} title={`Phản ứng: ${selected?.action ?? ''}`} description={selected?.response_id}>
        {selected && (
          <div className="flex flex-col gap-5">
            <div className="grid grid-cols-2 gap-2">
              <Field label="Trạng thái"><StatusBadge status={selected.status} /></Field>
              <Field label="Rủi ro"><span className="num">{fmtPct(selected.risk, 0)}</span></Field>
              <Field label="Mục tiêu">{selected.target ? <Mono>{selected.target}</Mono> : 'Không có (chỉ cảnh báo)'}</Field>
              <Field label="Người yêu cầu">{selected.requested_by ?? '—'}</Field>
              <Field label="Bắt đầu">{fmtDateTime(selected.started_at)}</Field>
              <Field label="Hết hạn">{selected.expires_at ? fmtDateTime(selected.expires_at) : 'Không đặt TTL'}</Field>
              <Field label="Rollback">{selected.rollback_status ?? '—'}</Field>
              <Field label="Mức phản ứng">{selected.response_level ?? '—'}</Field>
              <Field label="Lý do" className="col-span-2">{selected.reason ?? '—'}</Field>
            </div>
            {selected.incident_id && (
              <Link to={`/incidents/${encodeURIComponent(selected.incident_id)}`} className="text-xs text-primary hover:underline">
                Mở sự cố {selected.incident_id}
              </Link>
            )}
            <section>
              <SectionLabel>Bằng chứng</SectionLabel>
              <div className="grid grid-cols-1 gap-2">
                <Field label="Đường dẫn">{selected.evidence_path ? <Mono>{selected.evidence_path}</Mono> : '—'}</Field>
                <Field label="SHA-256 của bundle">
                  {selected.bundle_sha256 ? (
                    <span className="flex items-center gap-1"><Mono className="break-all">{selected.bundle_sha256}</Mono><CopyButton value={selected.bundle_sha256} label="Sao chép SHA-256" /></span>
                  ) : '—'}
                </Field>
                <Field label="Số tệp"><span className="num">{selected.evidence_file_count ?? 0}</span></Field>
              </div>
            </section>
            <section>
              <SectionLabel>Bản ghi đầy đủ</SectionLabel>
              <JsonView value={selected} />
            </section>
          </div>
        )}
      </Sheet>
    </Page>
  );
}
