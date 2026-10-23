import { useId, useState } from 'react';
import { ShieldAlert, X } from 'lucide-react';
import { EmptyState, JsonView } from '@/components/soc/primitives';

interface GraphNode {
  id: string;
  kind: string;
  label: string;
  details?: Record<string, unknown>;
}
export interface GraphData {
  nodes?: GraphNode[];
  edges?: Array<{ source: string; target: string; relationship: string }>;
  request_count?: number;
  criteria?: string;
}

const COLUMN_X = [150, 550, 950];
const COLORS = {
  source: 'var(--color-primary)',
  request: 'var(--color-sev-high)',
  target: 'var(--color-success)',
};

export function AttackGraph({ graph }: { graph?: GraphData | null }) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const arrow = useId().replace(/:/g, '');
  const nodes = graph?.nodes ?? [];
  const edges = graph?.edges ?? [];
  const requests = nodes.filter((n) => n.kind === 'request');
  const sources = nodes.filter((n) => ['ip', 'attacker', 'unattributed'].includes(n.kind));
  const targets = nodes.filter((n) => !requests.includes(n) && !sources.includes(n));
  const height = Math.max(320, Math.max(requests.length, sources.length, targets.length) * 78 + 90);
  const positioned = [sources, requests, targets].flatMap((column, col) => column.map((node, i) => ({
    ...node, x: COLUMN_X[col],
    y: column.length === 1 ? height / 2 : 80 + i * ((height - 140) / Math.max(1, column.length - 1)),
  })));
  const index = new Map(positioned.map((n) => [n.id, n]));
  const selected = nodes.find((n) => n.id === selectedId);

  if (!requests.length) {
    return (
      <EmptyState
        icon={<ShieldAlert />}
        title="Chưa ghi nhận request HTTP có dấu hiệu tấn công trong phạm vi này."
        description="Log host/runtime không có HTTP được giữ ở phần bằng chứng."
      />
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
        <span className="font-medium text-foreground">
          <span className="num">{requests.length}</span>/20 request đầu tiên · theo thời gian tăng dần
        </span>
        <span className="text-muted-foreground">Chọn node (hoặc Tab + Enter) để xem thời gian, URL và nguồn IP</span>
      </div>
      {graph?.criteria && <p className="text-xs leading-relaxed text-muted-foreground">{graph.criteria}</p>}

      <div className="overflow-auto rounded-2xl border border-border bg-black/25" tabIndex={0} aria-label="Sơ đồ request, cuộn để xem tối đa 20 request">
        <svg viewBox={`0 0 1100 ${height}`} style={{ minWidth: 1000, height }} role="group" aria-label="Nguồn quan sát gửi HTTP request tới web đích">
          <defs>
            <marker id={arrow} markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
              <path d="M0,1 L7,4 L0,7" fill="none" stroke="rgb(255 255 255 / 0.3)" />
            </marker>
          </defs>
          {['Nguồn IP quan sát', 'HTTP request · thứ tự thời gian', 'Web đích'].map((label, i) => (
            <text key={label} x={COLUMN_X[i]} y="30" textAnchor="middle" fill="var(--color-subtle)" fontSize="13" fontWeight="500">
              {label}
            </text>
          ))}
          {edges.map((edge, i) => {
            const src = index.get(edge.source), dst = index.get(edge.target);
            if (!src || !dst) return null;
            const start = src.x + (src.kind === 'request' ? 170 : 125);
            const end = dst.x - (dst.kind === 'request' ? 170 : 125);
            const active = selectedId === src.id || selectedId === dst.id;
            return (
              <path
                key={i}
                d={`M${start},${src.y} C${(start + end) / 2},${src.y} ${(start + end) / 2},${dst.y} ${end},${dst.y}`}
                fill="none"
                stroke={active ? 'var(--color-primary)' : 'rgb(255 255 255 / 0.18)'}
                strokeWidth={active ? 1.8 : 1.2}
                markerEnd={`url(#${arrow})`}
              />
            );
          })}
          {positioned.map((n) => {
            const request = n.kind === 'request', width = request ? 340 : 250;
            const active = selectedId === n.id;
            const color = request ? COLORS.request : n.kind === 'target' ? COLORS.target : COLORS.source;
            const caption = request
              ? `${n.details?.method ?? 'HTTP'} · ${String(n.details?.timestamp ?? '')}`
              : n.kind === 'unattributed' ? 'Sensor thiếu IP client' : n.kind === 'target' ? 'Đích quan sát' : 'IP nguồn quan sát';
            return (
              <g
                key={n.id}
                transform={`translate(${n.x},${n.y})`}
                role="button"
                tabIndex={0}
                aria-label={n.label}
                aria-pressed={active}
                className="cursor-pointer outline-none"
                onClick={() => setSelectedId(n.id)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSelectedId(n.id); }
                }}
              >
                <title>{n.label}</title>
                <rect
                  x={-width / 2}
                  y="-29"
                  width={width}
                  height="58"
                  rx="14"
                  fill={active ? 'rgb(255 255 255 / 0.14)' : 'rgb(255 255 255 / 0.05)'}
                  stroke={active ? 'var(--color-primary)' : 'rgb(255 255 255 / 0.12)'}
                  strokeWidth={active ? 1.5 : 1}
                />
                <rect x={-width / 2 + 10} y="-17" width="3" height="34" rx="1.5" fill={color} />
                <text x={-width / 2 + 24} y="-6" fill={color} fontSize="11.5" fontWeight="500">{caption.length > 56 ? `${caption.slice(0, 55)}…` : caption}</text>
                <text x={-width / 2 + 24} y="15" fill="var(--color-foreground)" fontSize="13" fontFamily="var(--font-mono)">
                  {n.label.length > (request ? 43 : 28) ? `${n.label.slice(0, request ? 42 : 27)}…` : n.label}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      <p className="text-xs leading-relaxed text-subtle">
        IP là địa chỉ sensor quan sát. Docker/NAT có thể che IP máy gốc; không tin X-Forwarded-For tùy ý. Thiếu IP được ghi rõ, không tự gán IP.
      </p>

      {selected && (
        <div className="animate-fade-in rounded-2xl border border-border bg-black/25 p-4" aria-live="polite">
          <div className="mb-2 flex items-start justify-between gap-3">
            <strong className="text-sm font-medium wrap-anywhere">{selected.label}</strong>
            <button
              type="button"
              onClick={() => setSelectedId(null)}
              className="inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-xs text-muted-foreground hover:bg-muted hover:text-foreground"
            >
              <X className="size-3.5" /> Đóng chi tiết
            </button>
          </div>
          <JsonView value={selected.details ?? { id: selected.id }} />
        </div>
      )}
    </div>
  );
}
