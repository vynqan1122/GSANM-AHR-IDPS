import { useState } from 'react';
import { useApi, queryClient } from '@/api/query';
import { postJson } from '@/api/client';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { DataTable, type Column } from '@/components/soc/DataTable';
import { Mono, Page, PageHeader, StaleNotice, StatusBadge } from '@/components/soc/primitives';
import type { RuleRow } from '@/types/api';

export interface GenTIState {
  enabled: boolean;
  ready: boolean;
  busy?: boolean;
  error?: string;
  self_test?: { status: string; error?: string; scope?: string };
  model?: { base_model: string; artifact_sha256: string; selected_stage?: number;
    training?: { rows?: number; corpus_rows?: number; human_reviewed_rows?: number } };
}
interface Observation {
  event_id: string;
  role?: 'evidence' | 'benign' | 'uncertain';
  input: { source?: string; http?: { method?: string; uri?: string } };
}
interface Selection {
  status: string;
  artifact_sha256: string;
  updated_at: string;
  observations?: Observation[];
  task?: string;
  reason?: string;
  review_seconds?: number;
  rule_id?: string;
}
interface ModelResult extends RuleRow {
  created_at?: string;
  automatic_supported?: boolean;
  version_metadata?: { task?: string; generation_seconds?: number;
    automatic_selection?: { reason?: string; review_seconds?: number; observations?: Observation[] } };
}
const stages: Record<string, string> = {
  waiting: 'Đang chờ traffic DVWA mới', reviewing: 'Model đang phân loại và chọn bằng chứng',
  insufficient: 'AI chưa đủ bằng chứng để kết luận', generating: 'Model đang sinh quy tắc',
  generated: 'Đã lưu kết quả sinh quy tắc', failed: 'Chưa hoàn tất — hệ thống sẽ tự thử lại',
};
const roleText = (role?: Observation['role']) => role ? ({ evidence: 'Evidence · AI chọn', benign: 'Phản ví dụ · AI chọn', uncertain: 'Chưa kết luận' }[role]) : 'Đang phân loại';

export function GenTIMonitor({ state }: { state: GenTIState }) {
  const automation = useApi<{ policy: { enabled: boolean; revision: number }; worker_fresh: boolean; scope: string;
    selection?: Selection | null; alerts: Array<{ action_id: number; action: string; reason: string; created_at: string }> }>('/api/automation/status', 5000);
  const results = useApi<{ items: ModelResult[]; counts: Record<string, number>; artifact_sha256: string | null }>('/api/automation/results', 5000);
  const [policyBusy, setPolicyBusy] = useState(false);
  const [policyError, setPolicyError] = useState('');
  const selection = automation.data?.selection?.artifact_sha256 === state.model?.artifact_sha256 ? automation.data?.selection : null;
  const modelResults = results.data?.artifact_sha256 === state.model?.artifact_sha256 ? results.data?.items ?? [] : [];
  const observations = selection?.observations ?? modelResults.find(r => r.version_metadata?.automatic_selection)?.version_metadata?.automatic_selection?.observations ?? [];
  const columns: Column<Observation>[] = [
    { key: 'role', header: 'Nhận định của AI', width: '180px', cell: (r) => <span className="text-xs">{roleText(r.role)}</span> },
    { key: 'source', header: 'Nguồn', width: '90px', cell: (r) => r.input.source ?? 'nginx' },
    { key: 'uri', header: 'HTTP đã khử trường nhạy cảm', width: 'minmax(250px,1fr)', cell: (r) => <span className="break-all text-xs">{r.input.http?.method} {r.input.http?.uri}</span> },
    { key: 'id', header: 'Event ID', width: '200px', cell: (r) => <Mono className="break-all text-xs">{r.event_id}</Mono> },
  ];
  const togglePolicy = async () => {
    if (!automation.data) return;
    setPolicyBusy(true); setPolicyError('');
    try {
      await postJson('/api/automation/policy', { enabled: !automation.data.policy.enabled, revision: automation.data.policy.revision });
      await queryClient.invalidateQueries({ queryKey: ['/api/automation/status'] });
    } catch (e) { setPolicyError(e instanceof Error ? e.message : 'Không cập nhật được tự động hóa.'); }
    finally { setPolicyBusy(false); }
  };
  return <Page>
    <PageHeader title="GenTI · AI sinh quy tắc tự động" description="Model fine-tune của bạn tự chọn evidence, chọn phản ví dụ, nhận định hành vi và sinh rule. Kết quả được lưu và cập nhật tại đây." />
    <Card><CardHeader title="Mô hình AI của bạn" description="Trọng số fine-tune đã triển khai trong hệ thống chính." /><CardContent>
      <p className="text-sm" role="status">{state.ready ? (state.busy ? 'Đang phân tích hoặc sinh quy tắc' : 'Model sẵn sàng') : 'Đang chờ model sẵn sàng'} · Worker: {automation.data?.worker_fresh ? 'Đang hoạt động' : 'Chưa sẵn sàng'}</p>
      {state.model && <div className="mt-3 space-y-2 text-xs"><p>Base: {state.model.base_model} · Stage được chọn: {state.model.selected_stage ?? 'Chưa có dữ liệu'}</p><p>Train: {state.model.training?.rows ?? 'Chưa có dữ liệu'} cặp · Corpus: {state.model.training?.corpus_rows ?? 'Chưa có dữ liệu'} cặp</p><p>Model hash: <Mono className="break-all">{state.model.artifact_sha256}</Mono></p></div>}
      <p className="mt-3 text-xs">Kiểm thử khởi động: {state.self_test?.status === 'passed' ? 'Đạt' : state.self_test?.status === 'failed' ? 'Chưa đạt' : 'Đang chờ'}. {state.self_test?.error} Bộ 3 attack + 5 benign tổng hợp kiểm tra đường suy luận và native replay.</p>
      {!state.ready && <p role="status" className="mt-2 text-xs text-muted-foreground">Hệ thống sẽ tiếp tục khi model sẵn sàng. {state.error}</p>}
    </CardContent></Card>
    <Card><CardHeader title="Chu kỳ tự động đang vận hành" description="Thu thập → AI chọn mẫu → AI sinh rule → kiểm định native → Shadow → Active → phản ứng." /><CardContent>
      <StaleNotice error={automation.error} hasData={Boolean(automation.data)} />
      <p className="text-sm" role="status">{automation.data?.policy.enabled ? 'Đã bật tự động · Không cần chọn mẫu, nhập yêu cầu hoặc tích xác nhận' : 'Tự động đang tắt theo chính sách đã lưu'}</p>
      <p className="mt-2 text-sm" aria-live="polite">{selection ? stages[selection.status] ?? selection.status : 'Đang đọc trạng thái chu kỳ'}</p>
      {selection?.reason && <p className="mt-2 break-words text-xs text-muted-foreground">{selection.reason}</p>}
      <p className="mt-3 text-xs text-muted-foreground">AI đưa ra nhận định; Suricata và PCAP xác nhận cú pháp/hành vi rule. Tự Active hiện áp dụng cho {automation.data?.scope ?? 'profile HTTP lab'} sau 50 attack + 50 benign, ít nhất 60 giây Shadow và 20 URI khác nhau. Lease Active: 1 giờ.</p>
      <Button className="mt-3" disabled={policyBusy || !automation.data} onClick={togglePolicy}>{policyBusy ? 'Đang lưu…' : automation.data?.policy.enabled ? 'Dừng tự động và gỡ chặn' : 'Khôi phục tự động'}</Button>
      <p className="mt-2 text-xs text-muted-foreground">Đây là nút dừng/khôi phục khi cần; chu kỳ không yêu cầu bạn bấm để sinh từng rule.</p>
      {policyError && <p role="alert" className="mt-2 text-sm text-sev-critical">{policyError}</p>}
    </CardContent></Card>
    <Card><CardHeader title="Bằng chứng và phản ví dụ do AI lựa chọn" description="Bảng chỉ đọc. Lọc bỏ API, dashboard và tệp tĩnh; chính model hiện tại phân loại các quan sát DVWA." />
      <DataTable label="Bằng chứng AI tự lựa chọn" columns={columns} rows={observations} rowKey={(r) => r.event_id} loading={automation.isPending} minWidth={760} maxHeight={330} />
      <CardContent><p className="text-xs text-muted-foreground">Evidence: {observations.filter(r => r.role === 'evidence').length} · Phản ví dụ: {observations.filter(r => r.role === 'benign').length} · Chưa kết luận: {observations.filter(r => r.role === 'uncertain').length}. Nhận định AI chưa phải nhãn được chuyên gia phê duyệt.</p>
        {selection?.review_seconds != null && <p className="mt-2 text-xs">Thời gian model chọn mẫu: {selection.review_seconds.toFixed(1)} giây.</p>}
        {!observations.length && <p className="mt-2 text-xs">Chưa có lượt chọn mẫu AI mới. Hệ thống chờ traffic DVWA và sẽ tự xử lý khi có dữ liệu phù hợp.</p>}
      </CardContent>
    </Card>
    <Card><CardHeader title="Kết quả do model của bạn sinh" description="Rule thật đã lưu trong registry, chỉ lấy từ đúng model hash đang triển khai. Kết quả giữ lại qua lần tải lại trang." /><CardContent>
      <StaleNotice error={results.error} hasData={Boolean(results.data)} />
      <p className="mb-3 text-xs">{Object.entries(results.data?.counts ?? {}).map(([status, count]) => `${status.toUpperCase()}: ${count}`).join(' · ') || 'Đang chờ kết quả của model'}</p>
      {!modelResults.length && <p className="text-sm text-muted-foreground">Khi chu kỳ sinh rule hoàn tất, nội dung, nhận định, model hash và kết quả kiểm định sẽ xuất hiện tại đây.</p>}
      {modelResults.map((rule) => <section key={rule.rule_id} className="border-t border-border py-4 first:border-t-0">
        <div className="flex flex-wrap items-center gap-2"><Mono className="break-all text-xs">{rule.rule_id}</Mono><StatusBadge status={rule.status} /></div>
        <p className="mt-2 text-sm">{rule.description}</p>
        {rule.version_metadata?.task && <p className="mt-2 break-words text-xs text-muted-foreground">Yêu cầu phát hiện: {rule.version_metadata.task}</p>}
        {rule.version_metadata?.automatic_selection?.reason && <p className="mt-2 text-xs">Nhận định chọn mẫu: {rule.version_metadata.automatic_selection.reason}</p>}
        <pre className="mt-3 overflow-x-auto whitespace-pre-wrap break-words rounded-lg bg-background p-3 text-xs">{rule.content}</pre>
        <p className="mt-2 text-xs">Native: {rule.validation_status === 'passed' ? 'Đạt kiểm định đã lưu' : 'Chưa đạt hoặc đang chờ kiểm định'} · Tự triển khai: {rule.automatic_supported ? 'Thuộc profile đã kiểm chứng' : 'Ngoài profile hiện được phép'}</p>
        {rule.validation_replay_metrics && <p className="mt-2 text-xs">PCAP kiểm soát: TP {rule.validation_replay_metrics.tp ?? '—'} · TN {rule.validation_replay_metrics.tn ?? '—'} · FP {rule.validation_replay_metrics.fp ?? '—'} · FN {rule.validation_replay_metrics.fn ?? '—'}. Chưa phải benchmark độc lập.</p>}
        {rule.version_metadata?.generation_seconds != null && <p className="mt-2 text-xs">Thời gian sinh: {rule.version_metadata.generation_seconds.toFixed(1)} giây.</p>}
        <a className="mt-2 inline-block text-xs text-primary underline" href="#/rules">Xem nội dung, bằng chứng và lịch sử trong Quy tắc</a>
      </section>)}
    </CardContent></Card>
    <Card><CardHeader title="Cảnh báo và phản ứng tự động" /><CardContent>
      <div className="space-y-2" aria-live="polite">{(automation.data?.alerts ?? []).slice(0, 5).map((a) => <p key={a.action_id} className="text-xs"><strong>{a.action}</strong> · {a.reason} · {new Date(a.created_at).toLocaleString('vi-VN')}</p>)}</div>
      <a href="#/responses" className="mt-3 inline-block text-xs text-primary underline">Xem các request đã chặn trong Phản ứng</a>
    </CardContent></Card>
  </Page>;
}
