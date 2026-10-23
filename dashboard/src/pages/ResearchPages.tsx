import { useMutation, useQueryClient } from '@tanstack/react-query';
import { FlaskConical, Play, RefreshCw } from 'lucide-react';
import { toast } from 'sonner';
import { useApi } from '@/api/query';
import { postJson } from '@/api/client';
import { fmtPct, fmtScore } from '@/lib/format';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/overlays';
import { AttackGraph, type GraphData } from '@/components/AttackGraph';
import { SimpleBarChart } from '@/components/soc/charts';
import { DataTable, type Column } from '@/components/soc/DataTable';
import { EmptyState, Mono, Page, PageHeader, StaleNotice, StatusBadge, Truncate } from '@/components/soc/primitives';
import type { ExperimentRow } from '@/types/api';

export function AttackGraphPage() {
  const query = useApi<GraphData>('/api/attack-graph', 0);
  return (
    <Page>
      <PageHeader
        title="20 request tấn công đầu tiên"
        description="Toàn bộ lịch sử web đã thu thập, từ cũ đến mới. Chỉ vẽ request HTTP có bằng chứng rule hoặc Fusion score đạt ngưỡng; đây là phát hiện nghi vấn, chưa xác nhận khai thác thành công."
        actions={
          <Button onClick={() => void query.refetch()} disabled={query.isFetching}>
            <RefreshCw className={query.isFetching ? 'animate-spin' : ''} /> Tải lại graph
          </Button>
        }
      />
      <StaleNotice error={query.error} hasData={Boolean(query.data)} />
      <Card>
        <CardContent className="pt-4">
          {query.isPending ? <Skeleton className="h-80" /> : <AttackGraph graph={query.data} />}
        </CardContent>
      </Card>
    </Page>
  );
}

const DESCRIPTIONS: Record<string, string> = {
  E1_rule_only: 'Chỉ dùng tập luật signature (Suricata + Falco)',
  E2_network_ai_only: 'Chỉ dùng Network AI',
  E3_log_ai_only: 'Chỉ dùng Log AI',
  E4_graph_ai_only: 'Chỉ dùng Graph AI',
  E5_rule_network: 'Rule + Network AI',
  E6_rule_network_log: 'Rule + Network AI + Log AI',
  E7_rule_network_log_graph: 'Bốn thành phần, chưa có rule tự sinh',
  E8_full_hybrid: 'Hybrid đầy đủ',
  E9_full_hybrid_generated_rules: 'Hybrid đầy đủ + generated rules',
};

export function ExperimentsPage() {
  const client = useQueryClient();
  const query = useApi<{ items: ExperimentRow[] }>('/api/experiments', 0);
  const rows = query.data?.items ?? [];

  const run = useMutation({
    mutationFn: () => postJson<{ results_path?: string }>('/api/experiments/run'),
    onSuccess: (result) => {
      toast.success('Đã chạy xong ablation E1–E9', { description: result.results_path ? `Kết quả: ${result.results_path}` : undefined });
      void client.invalidateQueries({ queryKey: ['/api/experiments'] });
    },
    onError: (error) => toast.error('Không chạy được thực nghiệm', { description: error instanceof Error ? error.message : 'Lỗi kết nối runner' }),
  });

  const columns: Column<ExperimentRow>[] = [
    { key: 'id', header: 'Mã', width: '84px', cell: (r) => <Mono className="font-semibold text-primary">{r.experiment_id.split('_')[0]}</Mono> },
    { key: 'name', header: 'Cấu hình', width: 'minmax(220px, 1.6fr)', cell: (r) => (
      <div className="min-w-0 leading-tight">
        <Truncate text={r.name || r.experiment_id} className="font-medium" />
        <div className="truncate text-[11px] text-subtle">{DESCRIPTIONS[r.experiment_id] ?? ''}</div>
      </div>
    ), },
    { key: 'precision', header: 'Precision', width: '88px', align: 'right', cell: (r) => <span className="num">{fmtPct(r.metrics?.precision)}</span> },
    { key: 'recall', header: 'Recall', width: '88px', align: 'right', cell: (r) => <span className="num">{fmtPct(r.metrics?.recall)}</span> },
    { key: 'f1', header: 'F1', width: '88px', align: 'right', cell: (r) => <span className="num font-medium">{fmtPct(r.metrics?.f1)}</span> },
    { key: 'fpr', header: 'FPR', width: '88px', align: 'right', cell: (r) => <span className="num">{fmtPct(r.metrics?.fpr)}</span> },
    { key: 'status', header: 'Trạng thái', width: '112px', cell: (r) => <StatusBadge status={r.status} /> },
  ];

  const chart = rows
    .filter((row) => typeof row.metrics?.f1 === 'number')
    .map((row) => ({ label: row.experiment_id.split('_')[0], value: Number(fmtScore(row.metrics?.f1, 3)) }));
  const resultsPath = rows.find((row) => row.results_path)?.results_path;

  return (
    <Page>
      <PageHeader
        title="Thực nghiệm E1–E9"
        description="Ablation: đánh giá đóng góp của từng thành phần và toàn bộ hệ thống. Bảng chỉ hiển thị kết quả đã được runner ghi lại."
        actions={
          <Button variant="default" onClick={() => run.mutate()} disabled={run.isPending}>
            {run.isPending ? <RefreshCw className="animate-spin" /> : <Play />}
            {run.isPending ? 'Đang chạy…' : 'Chạy E1–E9'}
          </Button>
        }
      />
      <StaleNotice error={query.error} hasData={Boolean(query.data)} />

      {chart.length > 0 && (
        <Card>
          <CardHeader title="F1 theo cấu hình" description={resultsPath ? `Nguồn: ${resultsPath}` : undefined} />
          <CardContent><SimpleBarChart data={chart} valueLabel="F1" /></CardContent>
        </Card>
      )}

      <Card className="overflow-hidden">
        <DataTable
          label="Kết quả ablation"
          columns={columns}
          rows={rows}
          rowKey={(r) => r.experiment_id}
          loading={query.isPending}
          minWidth={820}
          maxHeight={560}
          empty={<EmptyState icon={<FlaskConical />} title="Chưa có kết quả thực nghiệm" description="Bấm “Chạy E1–E9” để runner sinh ma trận đánh giá và ghi results.csv." />}
        />
      </Card>
    </Page>
  );
}
