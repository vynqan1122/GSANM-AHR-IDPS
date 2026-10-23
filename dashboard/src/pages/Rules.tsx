import { useMemo, useState } from 'react';
import { ArrowRight, Search, ShieldCheck, Sparkles } from 'lucide-react';
import { useApi } from '@/api/query';
import { fmtDateTime, fmtNumber, fmtScore } from '@/lib/format';
import { Card } from '@/components/ui/card';
import { Input, Segmented } from '@/components/ui/input';
import { Sheet } from '@/components/ui/overlays';
import { DataTable, type Column } from '@/components/soc/DataTable';
import { EmptyState, Field, JsonView, Mono, Page, PageHeader, SectionLabel, StaleNotice, StatusBadge, Truncate } from '@/components/soc/primitives';
import { Badge } from '@/components/ui/badge';
import type { Paged, RuleRow } from '@/types/api';

const TABS = ['all', 'candidate', 'shadow', 'active', 'rejected'] as const;
const tabText: Record<string, string> = { all: 'Tất cả', candidate: 'Candidate', shadow: 'Shadow', active: 'Active', rejected: 'Rejected' };

const originText = (rule: RuleRow) =>
  rule.origin === 'ai_generated' || rule.origin === 'ai_pattern_mining' ? 'AI sinh' : rule.source === 'generated' ? 'Sinh tự động' : rule.source || 'Signature gốc';

export function Rules() {
  const query = useApi<Paged<RuleRow>>('/api/rules?page_size=100', 15_000);
  const rules = query.data?.items ?? [];
  const [tab, setTab] = useState<string>('all');
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<RuleRow | null>(null);

  const counts = useMemo(() => {
    const result: Record<string, number> = { all: rules.length };
    for (const rule of rules) result[rule.status?.toLowerCase()] = (result[rule.status?.toLowerCase()] ?? 0) + 1;
    return result;
  }, [rules]);

  const rows = useMemo(() => {
    const term = search.trim().toLowerCase();
    return rules.filter((rule) => {
      if (tab !== 'all' && rule.status?.toLowerCase() !== tab) return false;
      return !term || [rule.rule_id, rule.name, rule.engine, rule.origin].some((value) => value?.toLowerCase().includes(term));
    });
  }, [rules, tab, search]);

  const columns: Column<RuleRow>[] = [
    { key: 'name', header: 'Quy tắc', width: 'minmax(220px, 1.4fr)', cell: (r) => (
      <div className="min-w-0 leading-tight">
        <Truncate text={r.name} className="font-medium" />
        <div className="truncate font-mono text-[11px] text-subtle">{r.rule_id}</div>
      </div>
    ) },
    { key: 'engine', header: 'Engine', width: '88px', cell: (r) => <span className="capitalize">{r.engine}</span> },
    { key: 'origin', header: 'Nguồn gốc', width: '116px', cell: (r) => <span className="text-muted-foreground">{originText(r)}</span> },
    { key: 'status', header: 'Trạng thái', width: '112px', cell: (r) => <StatusBadge status={r.status} /> },
    { key: 'support', header: 'Support', width: '72px', align: 'right', cell: (r) => <span className="num">{fmtNumber(r.support)}</span> },
    { key: 'precision', header: 'Precision', width: '82px', align: 'right', cell: (r) => <span className="num">{fmtScore(r.validation_replay_metrics?.precision)}</span> },
    { key: 'recall', header: 'Recall', width: '72px', align: 'right', cell: (r) => <span className="num">{fmtScore(r.validation_replay_metrics?.recall)}</span> },
    { key: 'fpr', header: 'FPR', width: '72px', align: 'right', cell: (r) => <span className="num">{fmtScore(r.validation_replay_metrics?.fpr)}</span> },
    { key: 'approval', header: 'Kích hoạt', width: '124px', cell: (r) =>
      r.promotion_requires_approval === false ? <Badge tone="neutral">Tự động</Badge> : <Badge tone="warning">Duyệt thủ công</Badge> },
  ];

  return (
    <Page>
      <PageHeader
        title="Quy tắc phát hiện"
        description="Generated rules đi qua ba cổng an toàn: Candidate (AI sinh) → Shadow (chạy ngầm, chỉ cảnh báo) → Active (cần duyệt thủ công). Trang này chỉ xem; việc chuyển trạng thái do rule lifecycle engine thực hiện."
      />
      <div className="flex items-center gap-2 rounded-lg border border-border bg-card px-3 py-2 text-xs text-muted-foreground">
        <ShieldCheck className="size-4 text-success" />
        <span className="flex flex-wrap items-center gap-1.5">
          <Badge tone="primary">Candidate</Badge>
          <ArrowRight className="size-3" />
          <Badge tone="warning">Shadow</Badge>
          <ArrowRight className="size-3" />
          <Badge tone="success">Active</Badge>
          <span className="ml-2">Không có rule nào tự động Active khi chưa được duyệt.</span>
        </span>
      </div>
      <StaleNotice error={query.error} hasData={Boolean(query.data)} />

      <Card className="overflow-hidden">
        <div className="flex flex-wrap items-center gap-2 border-b border-border p-3">
          <Segmented
            label="Lọc theo trạng thái"
            value={tab}
            onChange={setTab}
            options={TABS.map((value) => ({ value, label: tabText[value], count: counts[value] ?? 0 }))}
          />
          <div className="relative min-w-56 flex-1 sm:max-w-xs">
            <Search className="pointer-events-none absolute top-2.5 left-2.5 size-3.5 text-subtle" />
            <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Tìm rule, engine…" className="pl-8" aria-label="Tìm quy tắc" />
          </div>
        </div>
        <DataTable
          label="Generated rules"
          columns={columns}
          rows={rows}
          rowKey={(r) => r.rule_id}
          selectedKey={selected?.rule_id}
          onRowClick={setSelected}
          loading={query.isPending}
          minWidth={1000}
          maxHeight="calc(100vh - 340px)"
          empty={<EmptyState title="Không có quy tắc phù hợp" description="Rule được sinh khi rule generator phát hiện pattern lặp lại với độ tin cậy cao." />}
        />
      </Card>

      <Sheet open={selected !== null} onOpenChange={(open) => !open && setSelected(null)} title={selected?.name ?? ''} description={selected?.rule_id} width="max-w-2xl">
        {selected && <RuleDetail rule={selected} />}
      </Sheet>
    </Page>
  );
}

function RuleDetail({ rule }: { rule: RuleRow }) {
  const metrics = rule.validation_replay_metrics;
  return (
    <div className="flex flex-col gap-5">
      <div className="grid grid-cols-2 gap-2">
        <Field label="Trạng thái"><StatusBadge status={rule.status} /></Field>
        <Field label="Engine"><span className="capitalize">{rule.engine}</span></Field>
        <Field label="Nguồn gốc"><span className="inline-flex items-center gap-1.5">{originText(rule) === 'AI sinh' && <Sparkles className="size-3.5 text-primary" />}{originText(rule)}</span></Field>
        <Field label="Chính sách kích hoạt">{rule.promotion_requires_approval === false ? 'Tự động' : 'Bắt buộc duyệt thủ công'}</Field>
        <Field label="Support"><span className="num">{fmtNumber(rule.support)}</span></Field>
        <Field label="Độ tin cậy"><span className="num">{fmtScore(rule.confidence)}</span></Field>
      </div>

      {'description' in rule && typeof (rule as { description?: unknown }).description === 'string' && (
        <p className="text-[13px] leading-relaxed text-muted-foreground">{(rule as { description?: string }).description}</p>
      )}

      <section>
        <SectionLabel>Kết quả replay trên dữ liệu lịch sử</SectionLabel>
        {metrics ? (
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            <Field label="Precision"><span className="num">{fmtScore(metrics.precision)}</span></Field>
            <Field label="Recall"><span className="num">{fmtScore(metrics.recall)}</span></Field>
            <Field label="FPR"><span className="num">{fmtScore(metrics.fpr)}</span></Field>
            <Field label="Số lần khớp"><span className="num">{fmtNumber(metrics.match_count)}</span></Field>
          </div>
        ) : (
          <p className="rounded-lg border border-border bg-background/40 px-3 py-2 text-xs text-muted-foreground">
            Quy tắc chưa được validate/replay nên chưa có Precision, Recall và FPR.
          </p>
        )}
      </section>

      <section>
        <SectionLabel>Nội dung quy tắc ({rule.engine})</SectionLabel>
        {rule.content ? (
          <pre className="max-h-80 overflow-auto rounded-lg border border-border bg-background p-3 font-mono text-[12px] leading-relaxed whitespace-pre-wrap text-foreground">{rule.content}</pre>
        ) : (
          <p className="text-xs text-muted-foreground">Backend không trả nội dung cho quy tắc này.</p>
        )}
      </section>

      {rule.pattern != null && (
        <section>
          <SectionLabel>Pattern đã khai thác</SectionLabel>
          <JsonView value={rule.pattern} />
        </section>
      )}
      {(rule as { updated_at?: string }).updated_at && (
        <p className="text-xs text-subtle">Cập nhật <Mono className="text-muted-foreground">{fmtDateTime((rule as { updated_at?: string }).updated_at)}</Mono></p>
      )}
    </div>
  );
}
