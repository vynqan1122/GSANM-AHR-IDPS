import { useState } from 'react';
import { ArrowRight, Search, ShieldCheck, Sparkles } from 'lucide-react';
import { useApi } from '@/api/query';
import { fmtDateTime, fmtNumber, fmtScore } from '@/lib/format';
import { Card } from '@/components/ui/card';
import { Input, Segmented } from '@/components/ui/input';
import { Sheet } from '@/components/ui/overlays';
import { DataTable, type Column } from '@/components/soc/DataTable';
import { EmptyState, Field, JsonView, Mono, Page, PageHeader, SectionLabel, StaleNotice, StatusBadge, Truncate } from '@/components/soc/primitives';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { postJson } from '@/api/client';
import { queryClient } from '@/api/query';
import { toast } from 'sonner';
import type { Paged, RuleRow } from '@/types/api';

const TABS = ['all', 'candidate', 'validating', 'shadow', 'active', 'rejected', 'disabled'] as const;

function downloadNativeCandidate(rule: RuleRow) {
  const row = { id: rule.rule_id, model_versions: rule.model_versions,
    generated: JSON.stringify({ rule: rule.content, summary: rule.description ?? rule.name, mitre_attack: [] }) };
  const url = URL.createObjectURL(new Blob([JSON.stringify(row) + '\n'], { type: 'application/x-ndjson;charset=utf-8' }));
  const link = document.createElement('a'); link.href = url; link.download = `${rule.rule_id}.jsonl`; link.click();
  URL.revokeObjectURL(url);
}
const tabText: Record<string, string> = { all: 'Tất cả', candidate: 'Candidate', validating: 'Đang kiểm tra', shadow: 'Shadow', active: 'Active', rejected: 'Rejected', disabled: 'Disabled' };

const originText = (rule: RuleRow) =>
  rule.origin === 'sensor_baseline' ? 'Luật nền · IDS Suricata' : rule.generator === 'genti-llm' ? 'GenTI · model của bạn' : rule.origin === 'ai_generated' || rule.origin === 'ai_pattern_mining' ? 'AI sinh' : rule.source === 'generated' ? 'Sinh tự động' : rule.source || 'Signature gốc';

const actionText: Record<string, string> = { 'auto-generated': 'AI đã sinh Candidate', 'auto-held': 'Giữ Candidate',
  'auto-native-failed': 'Kiểm định native chưa đạt', 'auto-shadow': 'Tự chuyển Shadow', 'auto-active': 'Tự chuyển Active',
  'auto-expired': 'Hết thời hạn chặn', 'ips-block': 'IPS đã chặn HTTP', reject: 'Đã từ chối', disable: 'Đã vô hiệu hóa' };

export function Rules() {
  const [tab, setTab] = useState<string>('all');
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<RuleRow | null>(null);
  const [page, setPage] = useState(1);
  const path = `/api/rules?page_size=50&page=${page}${tab === 'all' ? '' : `&status=${tab}`}&search=${encodeURIComponent(search)}`;
  const query = useApi<Paged<RuleRow>>(path, 15_000);
  const rules = query.data?.items ?? [];
  const detail = useApi<RuleRow>(selected ? `/api/rules/${encodeURIComponent(selected.rule_id)}` : null, 5000);
  const automation = useApi<{ policy: { enabled: boolean }; worker_fresh: boolean }>('/api/automation/status', 5000);

  const columns: Column<RuleRow>[] = [
    { key: 'name', header: 'Quy tắc', width: 'minmax(200px, 1.4fr)', cell: (r) => (
      <div className="min-w-0 leading-tight">
        <Truncate text={r.name} className="font-medium" />
        <div className="truncate font-mono text-[11px] text-subtle">{r.rule_id}</div>
        <div className="mt-1 text-[11px] text-muted-foreground">{originText(r)}</div>
      </div>
    ) },
    { key: 'engine', header: 'Engine', width: '72px', cell: (r) => <span className="capitalize">{r.engine}</span> },
    { key: 'status', header: 'Trạng thái', width: '90px', cell: (r) => <StatusBadge status={r.status} /> },
    { key: 'next', header: 'Tiến trình / lý do chờ', width: 'minmax(200px, 1.3fr)', cell: (r) => <div className="space-y-1 whitespace-normal text-xs">
      <p className="font-medium">{r.automation?.label ?? 'Quy tắc IDS · quản lý riêng'}</p>
      <p className="line-clamp-2 text-muted-foreground">{r.automation?.stage === 'shadow' || r.automation?.stage === 'ready'
        ? `Thời gian ${r.automation.shadow.elapsed_seconds}/60s · Khớp ${r.automation.shadow.matches}/3 · Không khớp ${r.automation.shadow.nonmatches}/10 · Tổng ${r.automation.shadow.unique}/20 URI`
        : r.automation?.reason ?? (r.origin === 'sensor_baseline' ? 'Đã nạp tại Suricata · phát hiện và cảnh báo; không chặn HTTP.' : 'Mở chi tiết để xem kiểm định và thao tác registry.')}</p>
    </div> },
    { key: 'native', header: 'Kiểm định', width: '100px', cell: (r) => <span className="text-xs">{r.automation ? (r.automation.native_passed ? 'Native đạt' : r.automation.stage === 'native_failed' ? 'Native chưa đạt' : 'Chưa có native đạt') : r.validation_status ?? 'Chưa kiểm tra'}</span> },
    { key: 'enforcement', header: 'Thực thi IPS', width: '120px', cell: (r) => <Badge tone={r.automation?.enforcing ? 'success' : 'neutral'}>{r.automation?.enforcing ? 'Đang chặn HTTP' : 'Không chặn'}</Badge> },
  ];

  return (
    <Page>
      <PageHeader
        title="Quy tắc phát hiện"
        description="Active gồm luật IDS đang nạp tại cảm biến và luật GenTI đã qua native → Shadow. Xem cột Thực thi IPS để biết rule nào thực sự đang chặn HTTP. Candidate chưa chặn."
      />
      <div className="flex items-center gap-2 rounded-lg border border-border bg-card px-3 py-2 text-xs text-muted-foreground">
        <ShieldCheck className="size-4 text-success" />
        <span className="flex flex-wrap items-center gap-1.5">
          <Badge tone="primary">Candidate</Badge>
          <ArrowRight className="size-3" />
          <Badge tone="warning">Shadow</Badge>
          <ArrowRight className="size-3" />
          <Badge tone="success">Active</Badge>
          <span className="ml-2">{automation.data ? `Tự động: ${automation.data.policy.enabled ? 'đang bật' : 'đã dừng'} · Worker: ${automation.data.worker_fresh ? 'hoạt động' : 'chưa sẵn sàng'}` : 'Đang đọc trạng thái tự động…'}</span>
          <a className="ml-2 underline underline-offset-4" href="#/ai">Xem mô hình AI và điều khiển tự động</a>
        </span>
      </div>
      <StaleNotice error={query.error} hasData={Boolean(query.data)} />
      <StaleNotice error={automation.error} hasData={Boolean(automation.data)} />

      <Card className="overflow-hidden">
        <div className="flex flex-wrap items-center gap-2 border-b border-border p-3">
          <Segmented
            label="Lọc theo trạng thái"
            value={tab}
            onChange={(value) => { setTab(value); setPage(1); }}
            options={TABS.map((value) => ({ value, label: tabText[value] }))}
            className="max-w-full overflow-x-auto [&_button]:shrink-0 [&_button]:whitespace-nowrap"
          />
          <div className="relative min-w-56 flex-1 sm:max-w-xs">
            <Search className="pointer-events-none absolute top-2.5 left-2.5 size-3.5 text-subtle" />
            <Input value={search} onChange={(e) => { setSearch(e.target.value); setPage(1); }} placeholder="Tìm toàn bộ rule, engine…" className="pl-8" aria-label="Tìm quy tắc" />
          </div>
        </div>
        {tab === 'candidate' && <p className="border-b border-border px-4 py-3 text-xs leading-relaxed text-muted-foreground">Không cần duyệt từng rule GenTI. Rule trong phạm vi được worker tự kiểm định; rule ngoài phạm vi hoặc native lỗi được giữ Candidate với lý do bên dưới. Bấm vào một dòng để xem nội dung, bằng chứng kiểm định và điều kiện còn thiếu.</p>}
        <DataTable
          label="Quy tắc và tiến trình tự động"
          columns={columns}
          rows={rules}
          rowKey={(r) => r.rule_id}
          selectedKey={selected?.rule_id}
          onRowClick={setSelected}
          loading={query.isPending}
          minWidth={900}
          rowHeight={88}
          maxHeight="calc(100vh - 340px)"
          empty={<EmptyState title="Không có quy tắc phù hợp" description={tab === 'candidate' ? 'Candidate có thể đã tự chuyển Shadow/Active. Xem các trạng thái đó hoặc trang Mô hình AI để theo dõi lần sinh tiếp theo.' : 'Thử trạng thái khác hoặc thay đổi từ khóa tìm kiếm.'} />}
        />
        <div className="flex items-center justify-between gap-3 border-t border-border p-3 text-xs text-muted-foreground">
          <span>Trang {page} · {query.data?.total ?? 0} quy tắc phù hợp</span>
          <div className="flex gap-2">
            <Button size="sm" disabled={page === 1 || query.isFetching} onClick={() => setPage(page - 1)}>Trước</Button>
            <Button size="sm" disabled={page * 50 >= (query.data?.total ?? 0) || query.isFetching} onClick={() => setPage(page + 1)}>Sau</Button>
          </div>
        </div>
      </Card>

      <Sheet open={selected !== null} onOpenChange={(open) => !open && setSelected(null)} title={selected?.name ?? ''} description={selected?.rule_id} width="max-w-2xl">
        <StaleNotice error={detail.error} hasData={Boolean(detail.data)} />
        {selected && <RuleDetail key={selected.rule_id} rule={detail.data ?? selected} />}
      </Sheet>
    </Page>
  );
}

function RuleDetail({ rule }: { rule: RuleRow }) {
  const metrics = rule.validation_replay_metrics;
  const [action, setAction] = useState<string | null>(null);
  const [reason, setReason] = useState('');
  const [approved, setApproved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const history = useApi<{ items: Array<{ action_id: number; action: string; reason: string; created_at: string }> }>(`/api/rules/${encodeURIComponent(rule.rule_id)}/history`, 5000);
  const submit = async () => {
    setBusy(true); setError('');
    try {
      const updated = await postJson<RuleRow>(`/api/rules/${encodeURIComponent(rule.rule_id)}/actions`, {
        action, reason, approved, expected_status: rule.status, expected_version: rule.current_version,
      });
      toast.success(`Đã lưu: ${updated.status.toUpperCase()}`);
      setAction(null); setReason(''); setApproved(false);
      await queryClient.invalidateQueries({ predicate: (q) => String(q.queryKey[0]).startsWith('/api/rules') });
    } catch (e) { setError(e instanceof Error ? e.message : 'Không lưu được thao tác.'); }
    finally { setBusy(false); }
  };
  return (
    <div className="flex flex-col gap-5">
      {rule.automation && <AutomationDetail rule={rule} />}
      <section className="rounded-lg border border-border p-3">
        <SectionLabel>Thao tác quy tắc · phiên bản {rule.current_version}</SectionLabel>
        {rule.origin === 'sensor_baseline' ? <p className="mt-2 text-xs text-muted-foreground">Luật IDS được quản lý bằng cấu hình cảm biến. Muốn bật/tắt phải sửa file luật, kiểm định và nạp lại Suricata; trạng thái registry không thay thế thao tác này.</p> : <div className="flex flex-wrap gap-2">
          {['candidate', 'rejected', 'disabled'].includes(rule.status) && rule.generator !== 'genti-llm' && <Button size="sm" disabled={busy} onClick={() => setAction('validate')}>Kiểm tra → Shadow</Button>}
          {rule.status === 'shadow' && rule.generator !== 'genti-llm' && <Button size="sm" disabled={busy || rule.validation_status !== 'passed' || rule.validation_rule_version !== rule.current_version} onClick={() => setAction('activate')}>Phê duyệt Active</Button>}
          {['candidate', 'shadow'].includes(rule.status) && <Button size="sm" disabled={busy} onClick={() => setAction('reject')}>Từ chối</Button>}
          {['active', 'shadow'].includes(rule.status) && <Button size="sm" variant="danger" disabled={busy} onClick={() => setAction('disable')}>Vô hiệu hóa quy tắc</Button>}
          {rule.status === 'validating' && <span className="text-sm text-muted-foreground">Đang kiểm tra quy tắc…</span>}
        </div>}
        {rule.generator === 'genti-llm' && <div className="mt-3 space-y-3"><p className="text-xs text-muted-foreground">Bật tự động tại Mô hình AI. Rule trong profile lab được Suricata kiểm định rồi Shadow trước khi gateway HTTP thực thi; rule ngoài profile được giữ Candidate. Vô hiệu hóa sẽ ngừng thực thi tại gateway ngay. Không tự nạp rule vào sensor Suricata.</p><Button size="sm" variant="ghost" disabled={!rule.content} onClick={() => downloadNativeCandidate(rule)}>Tải Candidate JSONL để kiểm định native</Button></div>}
        {action && <div className="mt-3 flex flex-col gap-3">
          <label className="text-xs text-muted-foreground" htmlFor="rule-action-reason">Lý do thao tác</label>
          <Input id="rule-action-reason" value={reason} maxLength={500} disabled={busy} onChange={(e) => setReason(e.target.value)} placeholder="Ghi lý do để lưu vào lịch sử…" />
          {action === 'activate' && <label className="flex items-start gap-2 text-xs"><input type="checkbox" checked={approved} onChange={(e) => setApproved(e.target.checked)} disabled={busy} />Tôi đã kiểm tra validation và phê duyệt phiên bản này vào registry Active.</label>}
          <div className="flex gap-2"><Button size="sm" disabled={busy || reason.trim().length < 3 || (action === 'activate' && !approved)} onClick={submit}>{busy ? 'Đang xử lý…' : 'Xác nhận'}</Button><Button size="sm" variant="ghost" disabled={busy} onClick={() => setAction(null)}>Hủy</Button></div>
          <p className="text-xs text-muted-foreground">Validation chỉ chuyển Shadow khi vượt qua kiểm tra; kết quả không đạt sẽ được ghi rõ là Rejected.</p>
        </div>}
        {error && <p role="alert" className="mt-2 text-sm text-sev-critical">{error}</p>}
      </section>
      <div className="grid grid-cols-2 gap-2">
        <Field label="Trạng thái"><StatusBadge status={rule.status} /></Field>
        <Field label="Engine"><span className="capitalize">{rule.engine}</span></Field>
        <Field label="Nguồn gốc"><span className="inline-flex items-center gap-1.5">{originText(rule) === 'AI sinh' && <Sparkles className="size-3.5 text-primary" />}{originText(rule)}</span></Field>
        <Field label="Chính sách kích hoạt">{rule.origin === 'sensor_baseline' ? 'Theo cấu hình cảm biến · IDS' : rule.generator === 'genti-llm' ? 'Tự động khi đạt các điều kiện' : rule.promotion_requires_approval === false ? 'Tự động' : 'Duyệt registry thủ công'}</Field>
        <Field label="Support"><span className="num">{fmtNumber(rule.support)}</span></Field>
        <Field label="Độ tin cậy"><span className="num">{fmtScore(rule.confidence)}</span></Field>
      </div>

      {'description' in rule && typeof (rule as { description?: unknown }).description === 'string' && (
        <p className="text-[13px] leading-relaxed text-muted-foreground">{(rule as { description?: string }).description}</p>
      )}

      <section>
        <SectionLabel>Kết quả replay · xem nguồn mẫu trong lịch sử</SectionLabel>
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
      <section>
        <SectionLabel>Lịch sử thao tác</SectionLabel>
        <StaleNotice error={history.error} hasData={Boolean(history.data)} />
        {(history.data?.items ?? []).map((item) => <div key={item.action_id} className="border-b border-border py-2 text-xs"><span className="font-medium">{actionText[item.action] ?? item.action}</span> · {fmtDateTime(item.created_at)}<p className="mt-1 break-words text-muted-foreground">{item.reason}</p></div>)}
        {history.data?.items.length === 0 && <p className="text-xs text-muted-foreground">Chưa có thao tác từ dashboard.</p>}
      </section>
      {(rule as { updated_at?: string }).updated_at && (
        <p className="text-xs text-subtle">Cập nhật <Mono className="text-muted-foreground">{fmtDateTime((rule as { updated_at?: string }).updated_at)}</Mono></p>
      )}
    </div>
  );
}

function AutomationDetail({ rule }: { rule: RuleRow }) {
  const progress = rule.automation!;
  const shadow = progress.shadow;
  const replay = rule.validation_replay_metrics;
  return <section className="space-y-3" aria-label="Điều kiện triển khai tự động">
    <h3 className="text-sm font-semibold">{progress.label}</h3>
    <p className="text-xs leading-relaxed text-muted-foreground">{progress.reason}</p>
    <dl className="divide-y divide-border text-xs">
      {[
        ['Model đang chạy', progress.model_current ? 'Khớp model đã sinh rule' : 'Chưa khớp / chưa sẵn sàng'],
        ['Phạm vi tự động', progress.profile_supported ? 'GET XSS · gateway DVWA' : 'Chưa hỗ trợ tự động thực thi'],
        ['Native + gateway parity', progress.native_passed ? `Đạt · TP ${replay?.tp}, TN ${replay?.tn}, FP ${replay?.fp}, FN ${replay?.fn}` : 'Chưa có biên nhận đạt cho đúng nội dung và phiên bản'],
        ['Shadow · thời gian tối thiểu', `${shadow.elapsed_seconds} / 60 giây`],
        ['Shadow · URI khớp rule', `${shadow.matches} / 3`],
        ['Shadow · URI không khớp', `${shadow.nonmatches} / 10`],
        ['Shadow · tổng URI khác nhau', `${shadow.unique} / 20`],
        ['Thực thi hiện tại', progress.enforcing ? `Đang chặn HTTP · còn ${Math.ceil(progress.lease_remaining_seconds / 60)} phút` : 'Không chặn bằng rule này'],
      ].map(([label, value]) => <div key={label} className="grid grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)] gap-3 py-2"><dt className="text-muted-foreground">{label}</dt><dd className="break-words">{value}</dd></div>)}
    </dl>
    <p className="text-xs text-muted-foreground">Số lượt Shadow là quan sát HTTP, không phải nhãn TP/TN. Lặp lại cùng method + URI chỉ tính một lần. Các điều kiện phải cùng đạt; không cần checkbox phê duyệt.</p>
    {progress.native_failure && <details className="text-xs"><summary className="cursor-pointer font-medium">Xem lỗi kiểm định native · {fmtDateTime(progress.native_failure.created_at)}</summary><JsonView value={progress.native_failure.details} /></details>}
  </section>;
}
