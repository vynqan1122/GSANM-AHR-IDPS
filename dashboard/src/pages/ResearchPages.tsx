import { FlaskConical, RefreshCw } from 'lucide-react';
import { useApi } from '@/api/query';
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

export function ExperimentsPage() {
  const query = useApi<{ items: ExperimentRow[] }>('/api/experiments', 0);
  const rows = query.data?.items ?? [];

  const columns: Column<ExperimentRow>[] = [
    { key: 'id', header: 'Mã', width: '84px', cell: (r) => <Mono className="font-semibold text-primary">{r.name}</Mono> },
    { key: 'name', header: 'Cấu hình', width: 'minmax(220px, 1.6fr)', cell: (r) => (
      <div className="min-w-0 leading-tight">
        <Truncate text={r.name || r.experiment_id} className="font-medium" />
        <div className="truncate text-[11px] text-subtle">{'Test giữ riêng · AI chính'}</div>
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
    .map((row) => ({ label: row.name, value: Number(fmtScore(row.metrics?.f1, 3)) }));
  const resultsPath = rows.find((row) => row.results_path)?.results_path;

  return (
    <Page>
      <PageHeader
        title="Đánh giá AI chính"
        description="Kết quả đo trên 21.949 sự kiện test giữ riêng của bundle chính. Chỉ đọc dữ liệu đã kiểm tra checksum; chưa có runner ablation đo thực tế hoặc số đo hiệu năng live."
        actions={
          <Button variant="default" onClick={() => void query.refetch()} disabled={query.isFetching}>
            <RefreshCw className={query.isFetching ? 'animate-spin' : ''} /> Tải lại kết quả
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
          label="Kết quả test AI chính"
          columns={columns}
          rows={rows}
          rowKey={(r) => r.experiment_id}
          loading={query.isPending}
          minWidth={820}
          maxHeight={560}
          empty={<EmptyState icon={<FlaskConical />} title="Chưa có kết quả thực nghiệm" description="Kiểm tra AI chính và file kết quả đánh giá trong bundle." />}
        />
      </Card>
    </Page>
  );
}
