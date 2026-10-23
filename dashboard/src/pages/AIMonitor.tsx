import { useMemo } from 'react';
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

const WEIGHT_LABELS: Record<string, string> = {
  rule_score: 'Rule (Suricata / Falco / Wazuh)',
  network_score: 'Network AI · XGBoost',
  log_score: 'Log AI · MiniLM + Isolation Forest',
  graph_score: 'Graph AI · GraphSAGE',
  context_score: 'Context',
};

/** Real evaluation metrics live in artifact_metrics, or training metadata for models trained offline. */
function metricsOf(model: ModelRow): Record<string, unknown> {
  return { ...(model.training_metadata?.metrics ?? {}), ...(model.artifact_metrics ?? {}) };
}

export function AIMonitor() {
  const models = useApi<{ items: ModelRow[] }>('/api/models', 15_000);
  const recent = useApi<Paged<EventRow>>('/api/events?page_size=200', 15_000);
  const rows = models.data?.items ?? [];

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
  const breakdown = scored.find((event) => event.ai?.fusion_breakdown)?.ai?.fusion_breakdown as
    | { normalized_weights?: Record<string, number>; selected_method?: string; method?: string }
    | undefined;
  const weights = Object.entries(breakdown?.normalized_weights ?? {}).map(([key, value]) => ({ label: WEIGHT_LABELS[key] ?? key, value: Math.round(value * 100) }));

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
        description="AI Monitor: Network AI, Log AI, Graph AI và Fusion score. Các chỉ số lấy từ model registry; mô hình chưa có đánh giá thì hiển thị “—”, không điền số giả."
      />
      <StaleNotice error={models.error} hasData={Boolean(models.data)} />

      <section className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4" aria-label="Mô hình đang hoạt động">
        {models.isPending ? (
          Array.from({ length: 4 }, (_, index) => <Skeleton key={index} className="h-28" />)
        ) : active.length === 0 ? (
          <Card className="sm:col-span-2 xl:col-span-4">
            <EmptyState icon={<Cpu />} title="Chưa có mô hình Active" description="Đăng ký model bằng scripts/register_existing_models.sh hoặc cài bundle Colab v2." />
          </Card>
        ) : (
          active.map((model) => (
            <Card key={model.model_id} className="p-4">
              <div className="flex items-center justify-between gap-2">
                <span className="truncate text-sm font-semibold">{model.name}</span>
                <StatusBadge status={model.status} />
              </div>
              <div className="mt-1 truncate text-xs text-muted-foreground">{model.model_type}</div>
              <div className="mt-3 flex items-end justify-between text-xs">
                <Mono>{model.version}</Mono>
                <span className="text-subtle">{model.activated_at ? fmtDateTime(model.activated_at) : ''}</span>
              </div>
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
            title="Trọng số Fusion thực tế"
            description={breakdown ? `Phương pháp: ${breakdown.selected_method ?? breakdown.method ?? 'không rõ'} · lấy từ quyết định gần nhất` : 'Lấy từ quyết định Fusion gần nhất'}
          />
          <CardContent>
            <BarList items={weights} empty="Chưa có quyết định Fusion nào kèm trọng số." />
            {scored[0]?.ai && (
              <p className="num mt-4 text-xs text-muted-foreground">Fusion score gần nhất: <span className="text-foreground">{fmtScore(scored[0].ai.fusion_score)}</span></p>
            )}
            <p className="mt-3 border-t border-border pt-3 text-xs leading-relaxed text-muted-foreground">
              Generated rules chỉ ở trạng thái Candidate; quy tắc phải qua Shadow và được duyệt thủ công trước khi Active.
            </p>
          </CardContent>
        </Card>
      </section>
    </Page>
  );
}
