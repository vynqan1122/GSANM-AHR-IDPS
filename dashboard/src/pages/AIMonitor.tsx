import { useMemo, useState } from 'react';
import { Cpu } from 'lucide-react';
import { useApi } from '@/api/query';
import { fmtDateTime, fmtPct, fmtScore, isNum } from '@/lib/format';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/overlays';
import { DataTable, type Column } from '@/components/soc/DataTable';
import { SimpleBarChart } from '@/components/soc/charts';
import { BarList, EmptyState, Mono, Page, PageHeader, StaleNotice, StatusBadge } from '@/components/soc/primitives';
import { scoreTone, toneColor } from '@/lib/severity';
import type { EventRow, ModelRow, Paged } from '@/types/api';
import { Button } from '@/components/ui/button';
import { Sheet } from '@/components/ui/overlays';
import { Field, JsonView } from '@/components/soc/primitives';
import { postJson } from '@/api/client';
import { queryClient } from '@/api/query';
import { toast } from 'sonner';
import { GenTIMonitor, type GenTIState } from './GenTIMonitor';

const WEIGHT_LABELS: Record<string, string> = {
  rule_score: 'Rule (Suricata / Falco / Wazuh)',
  network_score: 'Network AI · XGBoost',
  log_score: 'Log AI · IF / MLP',
  graph_score: 'Graph aggregation + MLP',
  context_score: 'Context',
};

/** Real evaluation metrics live in artifact_metrics, or training metadata for models trained offline. */
function metricsOf(model: ModelRow): Record<string, unknown> {
  return { ...(model.training_metadata?.metrics ?? {}), ...(model.artifact_metrics ?? {}) };
}

export function AIMonitor() {
  const mode = useApi<GenTIState>('/api/genti/status', 10_000);
  if (mode.isPending) return <Page><PageHeader title="Mô hình AI" /><Skeleton className="h-28" /></Page>;
  if (mode.error) return <Page><PageHeader title="Mô hình AI" /><StaleNotice error={mode.error} hasData={false} /></Page>;
  return mode.data?.enabled ? <GenTIMonitor state={mode.data} /> : <ClassifierMonitor />;
}

function ClassifierMonitor() {
  const models = useApi<{ items: ModelRow[] }>('/api/models', 15_000);
  const recent = useApi<Paged<EventRow>>('/api/events?page_size=200', 15_000);
  const rows = models.data?.items ?? [];
  const [selected, setSelected] = useState<ModelRow | null>(null);

  const scored = useMemo(() => (recent.data?.items ?? []).filter((event) => isNum(event.ai?.fusion_score)), [recent.data]);

  const histogram = useMemo(() => {
    const bins = Array.from({ length: 10 }, (_, index) => ({ label: (index / 10).toFixed(1), value: 0, color: toneColor[scoreTone(index / 10 + 0.05)] }));
    for (const event of scored) {
      const score = event.ai?.fusion_score as number;
      bins[Math.min(9, Math.max(0, Math.floor(score * 10)))].value += 1;
    }
    return bins;
  }, [scored]);

  // Latest fusion decision shows the weights actually used, not nominal ones.
  const breakdown = scored[0]?.ai?.fusion_breakdown as
    | { normalized_weights?: Record<string, number>; selected_method?: string; method?: string }
    | undefined;
  const weights = Object.entries(breakdown?.normalized_weights ?? {}).map(([key, value]) => ({ label: WEIGHT_LABELS[key] ?? key, value: Math.round(value * 100) }));
  const components = Object.entries(WEIGHT_LABELS).flatMap(([key, label]) => {
    const value = scored[0]?.ai?.[key as keyof NonNullable<EventRow['ai']>];
    return typeof value === 'number' ? [{ label, value: Math.round(value * 100) }] : [];
  });

  const columns: Column<ModelRow>[] = [
    { key: 'name', header: 'Mô hình', width: 'minmax(140px, 1fr)', cell: (m) => <span className="font-medium">{m.name}</span> },
    { key: 'version', header: 'Phiên bản', width: '120px', cell: (m) => <Mono>{m.version ?? '—'}</Mono> },
    { key: 'type', header: 'Loại', width: 'minmax(150px, 1fr)', cell: (m) => <span className="text-muted-foreground">{m.model_type ?? '—'}</span> },
    { key: 'precision', header: 'Precision', width: '88px', align: 'right', cell: (m) => <span className="num">{fmtPct(metricsOf(m).precision)}</span> },
    { key: 'recall', header: 'Recall', width: '88px', align: 'right', cell: (m) => <span className="num">{fmtPct(metricsOf(m).recall)}</span> },
    { key: 'f1', header: 'F1', width: '88px', align: 'right', cell: (m) => <span className="num">{fmtPct(metricsOf(m).f1)}</span> },
    { key: 'rows', header: 'Mẫu huấn luyện', width: '112px', align: 'right', cell: (m) => <span className="num">{m.training_metadata?.training_rows ?? '—'}</span> },
    { key: 'status', header: 'Trạng thái', width: '120px', cell: (m) => <StatusBadge status={m.status} /> },
  ];

  const active = rows.filter((model) => model.status?.toLowerCase() === 'active');

  return (
    <Page>
      <PageHeader
        title="Mô hình AI & Fusion"
        description="IDS dùng Network AI, Log AI, Graph AI và Fusion để phát hiện. AI đề xuất rule nằm trong Quản lý Rules; các model dưới đây thuộc AI chính đang chạy."
      />
      <StaleNotice error={models.error} hasData={Boolean(models.data)} />
      <RuntimeControls />

      <section className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4" aria-label="Mô hình trong bundle local">
        {models.isPending ? (
          Array.from({ length: 4 }, (_, index) => <Skeleton key={index} className="h-28" />)
        ) : active.length === 0 ? (
          <Card className="sm:col-span-2 xl:col-span-4">
            <EmptyState icon={<Cpu />} title="Chưa có mô hình Active" description="Kiểm tra AI chính trong trang Sức khỏe hệ thống." />
          </Card>
        ) : (
          active.map((model) => (
            <Card key={model.model_id} className="p-4">
              <button className="w-full text-left focus-visible:outline-2 focus-visible:outline-primary" onClick={() => setSelected(model)} aria-label={`Xem mô hình ${model.name}`}>
              <div className="flex items-center justify-between gap-2">
                <span className="truncate text-sm font-semibold">{model.name}</span>
                <StatusBadge status={model.status} />
              </div>
              <div className="mt-1 truncate text-xs text-muted-foreground">{model.model_type}</div>
              <div className="mt-3 flex items-end justify-between text-xs">
                <Mono>{model.version}</Mono>
                <span className="text-subtle">{model.activated_at ? fmtDateTime(model.activated_at) : ''}</span>
              </div>
              </button>
            </Card>
          ))
        )}
      </section>

      <Card className="overflow-hidden">
        <CardHeader title="Model registry" description="Chỉ số đánh giá offline được lưu cùng mô hình" />
        <DataTable
          label="Model registry"
          columns={columns}
          rows={rows}
          rowKey={(m) => `${m.model_id}-${m.status}`}
          onRowClick={setSelected}
          selectedKey={selected ? `${selected.model_id}-${selected.status}` : null}
          loading={models.isPending}
          maxHeight={420}
          minWidth={900}
          empty={<EmptyState title="Chưa có mô hình nào được đăng ký" />}
        />
      </Card>

      <section className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <Card>
          <CardHeader title="Phân bố Fusion score" description={`${scored.length} sự kiện gần nhất đã được chấm điểm`} />
          <CardContent>
            {scored.length ? (
              <SimpleBarChart data={histogram} valueLabel="Số sự kiện" />
            ) : (
              <EmptyState title="Chưa có sự kiện nào được chấm điểm" />
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader
            title={weights.length ? 'Trọng số Fusion thực tế' : 'Điểm thành phần Fusion mới nhất'}
            description={weights.length ? `Phương pháp: ${breakdown?.selected_method ?? breakdown?.method ?? 'weighted'}` : 'AI chính dùng XGBoost Fusion; các thanh là điểm đầu vào, không phải trọng số tuyến tính.'}
          />
          <CardContent>
            <BarList items={weights.length ? weights : components} empty="Chưa có điểm thành phần từ sự kiện mới." />
            {scored[0]?.ai && (
              <p className="num mt-4 text-xs text-muted-foreground">Fusion score gần nhất: <span className="text-foreground">{fmtScore(scored[0].ai.fusion_score)}</span></p>
            )}
            <p className="mt-3 border-t border-border pt-3 text-xs leading-relaxed text-muted-foreground">
              Generated rules chỉ ở trạng thái Candidate; quy tắc phải qua Shadow và được duyệt thủ công trước khi Active.
            </p>
          </CardContent>
        </Card>
      </section>
      <Sheet open={selected !== null} onOpenChange={(open) => !open && setSelected(null)} title={selected?.name ?? 'Chi tiết mô hình'} description={selected?.version}>
        {selected && <div className="flex flex-col gap-5">
          <div className="grid grid-cols-2 gap-3"><Field label="Model ID"><Mono>{selected.model_id}</Mono></Field><Field label="Trạng thái registry"><StatusBadge status={selected.status} /></Field><Field label="Loại mô hình">{selected.model_type ?? '—'}</Field><Field label="Số mẫu train">{selected.training_metadata?.training_rows ?? '—'}</Field></div>
          <div className="grid grid-cols-2 gap-3">{['precision', 'recall', 'f1', 'fpr', 'roc_auc', 'pr_auc'].map((key) => <Field key={key} label={key}><span className="num">{fmtPct(metricsOf(selected)[key])}</span></Field>)}</div>
          <p className="text-xs text-muted-foreground">Đây là kết quả đánh giá offline của đúng artifact. Giá trị “—” là chưa có dữ liệu.</p>
          <JsonView value={selected.training_metadata ?? {}} />
        </div>}
      </Sheet>
    </Page>
  );
}

interface Policy {
  enabled: boolean;
  fusion_threshold: number;
  revision: number;
  worker: { status: string; updated: string; revision: number; bundle_version: string } | null;
}

function RuntimeControls() {
  const query = useApi<Policy>('/api/models/runtime', 2000);
  const [draft, setDraft] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const policy = query.data;
  const save = async (enabled: boolean, threshold: number) => {
    if (!policy) return;
    setBusy(true); setError('');
    try {
      await postJson('/api/models/runtime', { enabled, fusion_threshold: threshold, revision: policy.revision });
      setDraft(null);
      await queryClient.invalidateQueries({ queryKey: ['/api/models/runtime'] });
      toast.success('Đã lưu cấu hình. Worker sẽ áp dụng ở lượt xử lý kế tiếp.');
    } catch (e) { setError(e instanceof Error ? e.message : 'Không lưu được cấu hình.'); }
    finally { setBusy(false); }
  };
  return <Card>
    <CardHeader title="Điều khiển AI bundle" description="Cấu hình được lưu trong database và áp dụng cho sự kiện mới; không cần khởi động lại hệ thống." />
    <CardContent>
      <StaleNotice error={query.error} hasData={Boolean(policy)} />
      {policy ? <div className="flex flex-col gap-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="text-sm"><StatusBadge status={policy.worker?.status ?? 'unknown'} /><span className="ml-3 text-muted-foreground">CPU local · {policy.worker?.bundle_version ?? 'Đang chờ worker'}</span><p className="mt-2 text-xs text-subtle">{policy.worker?.revision === policy.revision ? 'Worker đã nhận cấu hình' : 'Đang chờ worker áp dụng cấu hình'} · phiên bản cấu hình {policy.revision}</p></div>
          <Button disabled={busy || !policy.worker} onClick={() => save(!policy.enabled, policy.fusion_threshold)}>{busy ? 'Đang lưu…' : policy.enabled ? 'Tạm dừng AI' : 'Tiếp tục AI'}</Button>
        </div>
        <div className="grid items-center gap-3 sm:grid-cols-[minmax(0,1fr)_auto]">
          <div><label htmlFor="fusion-threshold" className="mb-2 block text-sm">Ngưỡng phân loại Fusion: <span className="num">{(draft ?? policy.fusion_threshold).toFixed(2)}</span></label><input id="fusion-threshold" aria-label="Ngưỡng phân loại Fusion" type="range" min="0.05" max="0.95" step="0.05" value={draft ?? policy.fusion_threshold} disabled={busy} onChange={(e) => setDraft(Number(e.target.value))} className="w-full accent-primary" /></div>
          <Button disabled={busy || draft === null || draft === policy.fusion_threshold} onClick={() => save(policy.enabled, draft ?? policy.fusion_threshold)}>Lưu ngưỡng</Button>
        </div>
        <p className="text-xs leading-relaxed text-muted-foreground">Ngưỡng này đổi nhãn dự đoán Fusion và mức rủi ro của sự kiện mới, không thay luật IDS hoặc chính sách tương quan sự cố. Khi tạm dừng, Collector và Normalizer vẫn thu dữ liệu; AI tiếp tục từ stream khi bật lại.</p>
        {error && <p role="alert" className="text-sm text-sev-critical">{error}</p>}
      </div> : query.isPending ? <Skeleton className="h-28" /> : null}
    </CardContent>
  </Card>;
}
