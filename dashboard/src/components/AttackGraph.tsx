import { useId, useState } from 'react';
import { ShieldAlert } from 'lucide-react';

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
    ...node, x: [150, 550, 950][col],
    y: column.length === 1 ? height / 2 : 80 + i * ((height - 140) / Math.max(1, column.length - 1)),
  })));
  const index = new Map(positioned.map((n) => [n.id, n]));
  const selected = nodes.find((n) => n.id === selectedId);
  if (!requests.length) return <div className="attack-graph-empty">
    <ShieldAlert size={30} aria-hidden="true" />
    <p>Chưa ghi nhận request HTTP có dấu hiệu tấn công trong phạm vi này.</p>
    <p>Log host/runtime không có HTTP được giữ ở phần bằng chứng.</p>
  </div>;
  return <div className="soc-attack-graph-wrapper">
    <div className="graph-controls-bar">
      <strong>{requests.length}/20 request đầu tiên · theo thời gian tăng dần</strong>
      <span>Chọn node để xem thời gian, URL và nguồn IP</span>
    </div>
    {graph?.criteria && <p className="request-graph-note">{graph.criteria}</p>}
    <div className="attack-graph-svg-canvas" tabIndex={0} aria-label="Sơ đồ request, cuộn để xem tối đa 20 request">
      <svg viewBox={`0 0 1100 ${height}`} style={{ minWidth: 1000, height }} role="group" aria-label="Nguồn quan sát gửi HTTP request tới web đích">
        <defs><marker id={arrow} markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
          <path d="M0,1 L7,4 L0,7" fill="none" stroke="#7dd3fc" />
        </marker></defs>
        {['Nguồn IP quan sát', 'HTTP request · thứ tự thời gian', 'Web đích'].map((label, i) =>
          <text key={label} x={[150, 550, 950][i]} y="28" textAnchor="middle" fill="#cbd5e1" fontSize="13">{label}</text>)}
        {edges.map((edge, i) => {
          const src = index.get(edge.source), dst = index.get(edge.target);
          if (!src || !dst) return null;
          const start = src.x + (src.kind === 'request' ? 170 : 125);
          const end = dst.x - (dst.kind === 'request' ? 170 : 125);
          return <path key={i} d={`M${start},${src.y} C${(start+end)/2},${src.y} ${(start+end)/2},${dst.y} ${end},${dst.y}`}
            fill="none" stroke="#64748b" strokeWidth="1.4" markerEnd={`url(#${arrow})`} />;
        })}
        {positioned.map((n) => {
          const request = n.kind === 'request', width = request ? 340 : 250;
          const active = selectedId === n.id;
          const color = request ? '#fbbf24' : n.kind === 'target' ? '#6ee7b7' : '#7dd3fc';
          return <g key={n.id} transform={`translate(${n.x},${n.y})`} role="button" tabIndex={0}
            aria-label={n.label} aria-pressed={active} className="request-graph-node"
            onClick={() => setSelectedId(n.id)} onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSelectedId(n.id); }
            }}>
            <title>{n.label}</title>
            <rect x={-width/2} y="-29" width={width} height="58" rx="8" fill={active ? '#1e293b' : '#101b2e'} stroke={active ? '#f8fafc' : color} strokeWidth={active ? 2 : 1} />
            <text x={-width/2+12} y="-8" fill={color} fontSize="10">
              {request ? `${n.details?.method ?? 'HTTP'} · ${String(n.details?.timestamp ?? '')}` : n.kind === 'unattributed' ? 'SENSOR THIẾU IP CLIENT' : n.kind === 'target' ? 'ĐÍCH QUAN SÁT' : 'IP NGUỒN QUAN SÁT'}
            </text>
            <text x={-width/2+12} y="14" fill="#f1f5f9" fontSize="12" fontFamily="monospace">
              {n.label.length > (request ? 43 : 28) ? `${n.label.slice(0, request ? 42 : 27)}…` : n.label}
            </text>
          </g>;
        })}
      </svg>
    </div>
    <p className="request-graph-note">IP là địa chỉ sensor quan sát. Docker/NAT có thể che IP máy gốc; không tin X-Forwarded-For tùy ý. Thiếu IP được ghi rõ, không tự gán IP.</p>
    {selected && <div className="node-detail-panel" aria-live="polite">
      <div className="node-detail-header"><strong style={{ overflowWrap: 'anywhere' }}>{selected.label}</strong>
        <button type="button" onClick={() => setSelectedId(null)}>Đóng chi tiết</button></div>
      <pre className="node-raw-json">{JSON.stringify(selected.details ?? { id: selected.id }, null, 2)}</pre>
    </div>}
  </div>;
}
