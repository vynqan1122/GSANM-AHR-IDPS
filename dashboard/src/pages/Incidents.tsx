import { useEffect, useState } from 'react';
import {
  ShieldAlert,
  Clock,
  Crosshair,
  FileText,
  Activity,
  Layers,
  Sparkles,
} from 'lucide-react';
import { getJson } from '../api/client';
import { AttackGraph } from '../components/AttackGraph';
import { Badge, riskVariant, statusVariant } from '../components/Badge';
import type { IncidentRow, Paged } from '../types/api';

function formatDuration(start?: string, end?: string) {
  if (!start || !end) return '—';
  const ms = new Date(end).getTime() - new Date(start).getTime();
  if (!Number.isFinite(ms) || ms < 0) return '0s';
  const sec = Math.round(ms / 1000);
  if (sec < 60) return `${sec}s`;
  const min = Math.floor(sec / 60);
  return `${min}m ${sec % 60}s`;
}

export function Incidents() {
  const [incidents, setIncidents] = useState<IncidentRow[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<IncidentRow | null>(null);
  const [activeTab, setActiveTab] = useState<'graph' | 'timeline' | 'evidence' | 'ai'>('graph');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [isLoading, setIsLoading] = useState(false);

  const loadIncidents = async () => {
    setIsLoading(true);
    try {
      const data = await getJson<Paged<IncidentRow>>('/api/incidents?page_size=50');
      setIncidents(data.items || []);
      if (data.items?.length && !selectedIncident) {
        // Load first incident with details
        openIncident(data.items[0].incident_id);
      }
    } catch {
      setIncidents([]);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadIncidents();
    const timer = window.setInterval(loadIncidents, 10000);
    return () => window.clearInterval(timer);
  }, []);

  const openIncident = async (incidentId: string) => {
    try {
      const full = await getJson<IncidentRow>(`/api/incidents/${incidentId}`);
      setSelectedIncident(full);
    } catch {
      // fallback to current in list
      const fallback = incidents.find((i) => i.incident_id === incidentId);
      if (fallback) setSelectedIncident(fallback);
    }
  };

  const filteredIncidents = incidents.filter((inc) => {
    if (statusFilter === 'all') return true;
    return inc.status?.toLowerCase() === statusFilter.toLowerCase();
  });

  return (
    <div className="soc-page-container">
      {/* Top Filter and Stats Bar */}
      <div className="soc-filter-bar">
        <div className="filter-group-left">
          <div className="flex items-center gap-2">
            <ShieldAlert size={18} className="text-rose-400" />
            <h3 className="text-sm font-bold text-white tracking-wide">
              QUẢN LÝ SỰ CỐ & CHUỖI TẤN CÔNG (CORRELATED INCIDENTS)
            </h3>
          </div>
          <Badge variant="critical" size="sm">
            {incidents.filter((i) => (i.risk_score ?? 0) >= 0.7).length} Sự cố nguy cấp
          </Badge>
        </div>

        <div className="filter-group-right">
          <div className="source-filter-tabs">
            {['all', 'open', 'investigating', 'contained', 'resolved'].map((st) => (
              <button
                key={st}
                className={`tab-btn ${statusFilter === st ? 'is-active' : ''}`}
                onClick={() => setStatusFilter(st)}
              >
                {st === 'all' ? 'Tất cả' : st.toUpperCase()}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Main Split Layout: Incidents Table (Top or Left) + Incident Detail (Bottom or Right) */}
      <div className="soc-incidents-layout">
        {/* Incident List Table */}
        <div className="soc-panel p-0 overflow-hidden">
          <div className="panel-header px-4 py-3 border-b border-slate-800">
            <span className="font-semibold text-sm text-slate-200">
              Danh sách các sự cố an ninh ({filteredIncidents.length})
            </span>
            <span className="text-xs text-slate-400">Chọn sự cố để mở đồ thị lan truyền</span>
          </div>

          <div className="table-responsive max-h-72">
            <table className="soc-table">
              <thead>
                <tr>
                  <th>Mã Incident</th>
                  <th>Tiêu đề sự cố</th>
                  <th>Loại tấn công</th>
                  <th>IP Nguồn (Attacker)</th>
                  <th>Mục tiêu (Target)</th>
                  <th>Mức rủi ro</th>
                  <th>Số sự kiện</th>
                  <th>Thời lượng</th>
                  <th>Trạng thái</th>
                </tr>
              </thead>
              <tbody>
                {filteredIncidents.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="text-center py-6 text-slate-400">
                      {isLoading ? 'Đang tải danh sách sự cố...' : 'Không có sự cố nào được ghi nhận.'}
                    </td>
                  </tr>
                ) : (
                  filteredIncidents.map((inc) => {
                    const isSelected = selectedIncident?.incident_id === inc.incident_id;
                    return (
                      <tr
                        key={inc.incident_id}
                        onClick={() => openIncident(inc.incident_id)}
                        className={`clickable-row ${isSelected ? 'row-selected' : ''}`}
                      >
                        <td className="font-mono text-xs text-sky-400 font-semibold">
                          {inc.incident_id.slice(0, 8)}…
                        </td>
                        <td className="font-medium text-white">{inc.title || 'Phát hiện bất thường'}</td>
                        <td>
                          <span className="attack-type-badge">
                            <Crosshair size={12} />
                            {inc.attack_type || 'Unknown'}
                          </span>
                        </td>
                        <td className="font-mono text-xs text-slate-300">
                          {inc.source_ips?.join(', ') || '127.0.0.1'}
                        </td>
                        <td className="text-xs text-emerald-400">
                          {inc.targets?.join(', ') || 'dvwa_web'}
                        </td>
                        <td>
                          <Badge variant={riskVariant(inc.risk_score)} size="sm">
                            {(inc.risk_score ?? 0).toFixed(2)}
                          </Badge>
                        </td>
                        <td className="font-mono text-xs text-slate-300">{inc.event_count}</td>
                        <td className="text-xs text-slate-400">
                          {formatDuration(inc.first_seen, inc.last_seen)}
                        </td>
                        <td>
                          <Badge variant={statusVariant(inc.status)} size="sm" dot>
                            {inc.status?.toUpperCase() || 'OPEN'}
                          </Badge>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Selected Incident Detail View */}
        {selectedIncident ? (
          <div className="soc-panel incident-detail-card">
            {/* Header of Detail Card */}
            <div className="incident-header-banner">
              <div className="incident-header-left">
                <span className="incident-id-tag font-mono">
                  INCIDENT #{selectedIncident.incident_id}
                </span>
                <h2 className="incident-title-text">{selectedIncident.title}</h2>
                <div className="incident-meta-row">
                  <span className="meta-pill">
                    <Clock size={12} />
                    Bắt đầu: {selectedIncident.first_seen?.replace('T', ' ').slice(0, 19)}
                  </span>
                  <span className="meta-pill">
                    Thời lượng: {formatDuration(selectedIncident.first_seen, selectedIncident.last_seen)}
                  </span>
                  <span className="meta-pill">
                    <Layers size={12} />
                    {selectedIncident.event_count} Sự kiện liên quan
                  </span>
                </div>
              </div>

              <div className="incident-header-right">
                <div className="text-right">
                  <span className="text-xs text-slate-400 block mb-1">Mức độ rủi ro (Risk Score)</span>
                  <Badge variant={riskVariant(selectedIncident.risk_score)} size="md">
                    {(selectedIncident.risk_score ?? 0).toFixed(2)} / 1.0
                  </Badge>
                </div>
                <Badge variant={statusVariant(selectedIncident.status)} size="md" dot>
                  {selectedIncident.status?.toUpperCase()}
                </Badge>
              </div>
            </div>

            {/* Navigation Tabs for Detail View */}
            <div className="detail-tabs-bar">
              <button
                className={`detail-tab ${activeTab === 'graph' ? 'active' : ''}`}
                onClick={() => setActiveTab('graph')}
              >
                <Activity size={14} />
                Đồ thị Attack Chain (Graph)
              </button>
              <button
                className={`detail-tab ${activeTab === 'timeline' ? 'active' : ''}`}
                onClick={() => setActiveTab('timeline')}
              >
                <Clock size={14} />
                Dòng thời gian (Timeline)
              </button>
              <button
                className={`detail-tab ${activeTab === 'ai' ? 'active' : ''}`}
                onClick={() => setActiveTab('ai')}
              >
                <Sparkles size={14} />
                Giải thích AI & Rules
              </button>
              <button
                className={`detail-tab ${activeTab === 'evidence' ? 'active' : ''}`}
                onClick={() => setActiveTab('evidence')}
              >
                <FileText size={14} />
                Sự kiện chứng cứ ({selectedIncident.events?.length ?? 0})
              </button>
            </div>

            {/* Tab 1: Attack Chain Graph */}
            {activeTab === 'graph' && (
              <div className="tab-pane-content">
                <div className="text-xs text-slate-400 mb-2 font-mono">
                  Tối đa 20 request HTTP tấn công đầu tiên của sự cố này. Xem toàn bộ lịch sử tại Graph 20 request.
                </div>
                <AttackGraph graph={selectedIncident.attack_graph} />
              </div>
            )}

            {/* Tab 2: Attack Timeline */}
            {activeTab === 'timeline' && (
              <div className="tab-pane-content">
                <div className="soc-timeline">
                  {selectedIncident.timeline && selectedIncident.timeline.length > 0 ? (
                    (selectedIncident.timeline as any[]).map((step, idx) => (
                      <div className="timeline-step" key={idx}>
                        <div className="timeline-dot" />
                        <div className="timeline-content">
                          <span className="timeline-time font-mono text-xs text-slate-400">
                            {step.timestamp || `Giai đoạn ${idx + 1}`}
                          </span>
                          <h4 className="timeline-action text-white text-sm font-semibold">
                            {step.action || step.event_type || 'Hành vi phát hiện'}
                          </h4>
                          <p className="timeline-desc text-xs text-slate-300">
                            {step.description || JSON.stringify(step)}
                          </p>
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="py-6 text-center text-slate-400">
                      Chuỗi sự kiện đang được phân tích tự động vào timeline.
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Tab 3: AI Explanation & Triggered Rules */}
            {activeTab === 'ai' && (
              <div className="tab-pane-content">
                <div className="soc-grid-2col">
                  <div className="soc-card-inner">
                    <h4 className="card-inner-title flex items-center gap-2">
                      <Sparkles size={16} className="text-purple-400" />
                      Phân tích suy luận từ AI (AI Summary & SHAP)
                    </h4>
                    <pre className="soc-raw-code">
                      {JSON.stringify(selectedIncident.ai_summary || { note: 'Không có bất thường phụ từ AI' }, null, 2)}
                    </pre>
                  </div>

                  <div className="soc-card-inner">
                    <h4 className="card-inner-title flex items-center gap-2">
                      <ShieldAlert size={16} className="text-sky-400" />
                      Quy tắc phát hiện liên quan (Triggered Rules)
                    </h4>
                    <pre className="soc-raw-code">
                      {JSON.stringify(selectedIncident.rule_summary || { note: 'Quy tắc tương quan mặc định' }, null, 2)}
                    </pre>
                  </div>
                </div>
              </div>
            )}

            {/* Tab 4: Evidence Events */}
            {activeTab === 'evidence' && (
              <div className="tab-pane-content">
                <div className="table-responsive">
                  <table className="soc-table">
                    <thead>
                      <tr>
                        <th>Thời gian</th>
                        <th>Nguồn</th>
                        <th>Loại sự kiện</th>
                        <th>Quan hệ tương quan</th>
                        <th>IP Nguồn</th>
                        <th>Severity</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(selectedIncident.events ?? []).map((ev: any) => (
                        <tr key={ev.event_id}>
                          <td className="font-mono text-xs">{ev.timestamp?.slice(0, 19)}</td>
                          <td>
                            <span className={`sensor-tag sensor-${ev.source?.toLowerCase()}`}>
                              {ev.source?.toUpperCase()}
                            </span>
                          </td>
                          <td className="text-white text-xs">{ev.event_type}</td>
                          <td className="text-sky-300 text-xs font-semibold">{ev.relationship || 'CORRELATED'}</td>
                          <td className="font-mono text-xs">{ev.src_ip || '—'}</td>
                          <td>
                            <Badge variant={riskVariant(ev.severity)} size="sm">
                              {ev.severity ?? 0}
                            </Badge>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="soc-panel text-center py-12 text-slate-400">
            Chọn một sự cố từ danh sách ở trên để xem chi tiết chuỗi tấn công và bằng chứng.
          </div>
        )}
      </div>
    </div>
  );
}
