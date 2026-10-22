import { useEffect, useState, useMemo } from 'react';
import {
  Play,
  Pause,
  Trash2,
  Search,
  Filter,
  Eye,
  Radio,
  Cpu,
  Layers,
} from 'lucide-react';
import { getJson } from '../api/client';
import { useLiveEvents } from '../hooks/useLiveEvents';
import { Badge, severityVariant, riskVariant } from '../components/Badge';
import { Modal } from '../components/Modal';
import type { EventRow, Paged } from '../types/api';

export function LiveEvents() {
  const liveEvents = useLiveEvents(80);
  const [initialEvents, setInitialEvents] = useState<EventRow[]>([]);
  const [isPaused, setIsPaused] = useState(false);
  const [cachedEvents, setCachedEvents] = useState<EventRow[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<EventRow | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSource, setSelectedSource] = useState<string>('all');
  const [minSeverity, setMinSeverity] = useState<number>(0);

  // Initial load
  useEffect(() => {
    getJson<Paged<EventRow>>('/api/events?page_size=50')
      .then((data) => {
        setInitialEvents(data.items || []);
      })
      .catch(() => setInitialEvents([]));
  }, []);

  // Update cached events when not paused
  useEffect(() => {
    if (!isPaused) {
      // Merge live + initial, deduplicate by event_id
      const map = new Map<string, EventRow>();
      [...liveEvents, ...initialEvents].forEach((e) => {
        if (!map.has(e.event_id)) map.set(e.event_id, e);
      });
      setCachedEvents(Array.from(map.values()).slice(0, 100));
    }
  }, [liveEvents, initialEvents, isPaused]);

  // Filtered rows
  const filteredRows = useMemo(() => {
    return cachedEvents.filter((ev) => {
      // Source filter
      if (selectedSource !== 'all' && ev.source?.toLowerCase() !== selectedSource.toLowerCase()) {
        return false;
      }
      // Severity filter
      if ((ev.severity ?? 0) < minSeverity) {
        return false;
      }
      // Search query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const match =
          (ev.event_id && ev.event_id.toLowerCase().includes(q)) ||
          (ev.src_ip && ev.src_ip.toLowerCase().includes(q)) ||
          (ev.dst_ip && ev.dst_ip.toLowerCase().includes(q)) ||
          (ev.event_type && ev.event_type.toLowerCase().includes(q)) ||
          (ev.rule?.name && ev.rule.name.toLowerCase().includes(q)) ||
          (ev.container?.name && ev.container.name.toLowerCase().includes(q));
        if (!match) return false;
      }
      return true;
    });
  }, [cachedEvents, selectedSource, minSeverity, searchQuery]);

  const handleClear = () => {
    setInitialEvents([]);
    setCachedEvents([]);
  };

  const formatScore = (val?: number | null) => (typeof val === 'number' ? val.toFixed(2) : '—');

  return (
    <div className="soc-page-container">
      {/* Control & Filter Bar */}
      <div className="soc-filter-bar">
        {/* Left: Stream status & controls */}
        <div className="filter-group-left">
          <div className="stream-status-pill">
            <Radio size={14} className={isPaused ? 'text-amber-400' : 'text-emerald-400 pulse-anim'} />
            <span className="text-xs font-semibold">
              {isPaused ? 'TẠM DỪNG STREAM' : 'WEBSOCKET ĐANG PHÁT'}
            </span>
          </div>

          <button
            className={`soc-btn-secondary ${isPaused ? 'btn-active' : ''}`}
            onClick={() => setIsPaused(!isPaused)}
            title={isPaused ? 'Tiếp tục nhận luồng sự kiện' : 'Tạm dừng để kiểm tra'}
          >
            {isPaused ? <Play size={14} /> : <Pause size={14} />}
            {isPaused ? 'Tiếp tục' : 'Tạm dừng'}
          </button>

          <button
            className="soc-btn-secondary"
            onClick={handleClear}
            title="Xóa bộ đệm sự kiện hiện tại"
          >
            <Trash2 size={14} />
            Xóa bộ đệm
          </button>
        </div>

        {/* Right: Search and filter pills */}
        <div className="filter-group-right">
          <div className="soc-search-input-wrap">
            <Search size={14} className="search-icon" />
            <input
              type="text"
              placeholder="Tìm theo IP, loại sự kiện, Rule, Container..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="soc-search-input"
            />
          </div>

          <div className="source-filter-tabs">
            {['all', 'suricata', 'falco', 'wazuh'].map((src) => (
              <button
                key={src}
                className={`tab-btn ${selectedSource === src ? 'is-active' : ''}`}
                onClick={() => setSelectedSource(src)}
              >
                {src === 'all' ? 'Tất cả' : src.toUpperCase()}
              </button>
            ))}
          </div>

          <div className="severity-select-wrap">
            <Filter size={14} className="text-slate-400" />
            <select
              value={minSeverity}
              onChange={(e) => setMinSeverity(Number(e.target.value))}
              className="soc-select"
            >
              <option value="0">Tất cả Severity</option>
              <option value="3">Severity ≥ 3 (Medium+)</option>
              <option value="6">Severity ≥ 6 (High+)</option>
              <option value="8">Severity ≥ 8 (Critical)</option>
            </select>
          </div>
        </div>
      </div>

      {/* Main Events Table Panel */}
      <div className="soc-panel p-0 overflow-hidden">
        <div className="panel-header px-4 py-3 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Layers size={18} className="text-sky-400" />
            <h3 className="panel-title">Danh sách sự kiện thu thập thời gian thực</h3>
            <Badge variant="cyan" size="sm">
              {filteredRows.length} sự kiện
            </Badge>
          </div>
          <span className="text-xs text-slate-400">
            Click vào dòng bất kỳ để phân tích chi tiết Payload & AI Fusion
          </span>
        </div>

        <div className="table-responsive">
          <table className="soc-table">
            <thead>
              <tr>
                <th style={{ width: '150px' }}>Thời gian</th>
                <th style={{ width: '100px' }}>Nguồn (Sensor)</th>
                <th>Hoạt động / Container</th>
                <th>Địa chỉ IP</th>
                <th>Rule kích hoạt</th>
                <th style={{ width: '90px' }}>Severity</th>
                <th style={{ width: '110px' }}>Fusion score</th>
                <th style={{ width: '100px' }}>Mức rủi ro</th>
                <th style={{ width: '60px' }}>Thao tác</th>
              </tr>
            </thead>
            <tbody>
              {filteredRows.length === 0 ? (
                <tr>
                  <td colSpan={9} className="text-center py-8 text-slate-400">
                    Không tìm thấy sự kiện nào phù hợp với bộ lọc hiện tại.
                  </td>
                </tr>
              ) : (
                filteredRows.map((ev) => (
                  <tr
                    key={ev.event_id}
                    onClick={() => setSelectedEvent(ev)}
                    className="clickable-row"
                  >
                    <td className="font-mono text-xs text-slate-300">
                      {ev.timestamp ? ev.timestamp.replace('T', ' ').slice(0, 19) : '—'}
                    </td>
                    <td>
                      <span className={`sensor-tag sensor-${ev.source?.toLowerCase()}`}>
                        {ev.source?.toUpperCase()}
                      </span>
                    </td>
                    <td>
                      <div className="event-activity-cell">
                        <span className="event-type-name">{ev.event_type}</span>
                        {ev.container?.name && (
                          <span className="event-container-pill">
                            <Cpu size={10} />
                            {ev.container.name}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="font-mono text-xs text-slate-300">
                      {ev.src_ip ? (
                        <div>
                          <span>{ev.src_ip}</span>
                          {ev.dst_ip && <span className="text-slate-500"> → {ev.dst_ip}</span>}
                        </div>
                      ) : (
                        '—'
                      )}
                    </td>
                    <td>
                      <span className="rule-name-text">
                        {ev.rule?.name || ev.rule?.rule_id || '—'}
                      </span>
                    </td>
                    <td>
                      <Badge variant={severityVariant(ev.severity)} size="sm">
                        Mức {ev.severity ?? 0}
                      </Badge>
                    </td>
                    <td>
                      <div className="fusion-score-cell">
                        <span className="fusion-num font-mono text-xs">
                          {formatScore(ev.ai?.fusion_score)}
                        </span>
                        {typeof ev.ai?.fusion_score === 'number' && (
                          <div className="fusion-mini-bar">
                            <div
                              className="fusion-mini-fill"
                              style={{
                                width: `${Math.min(100, ev.ai.fusion_score * 100)}%`,
                                backgroundColor:
                                  ev.ai.fusion_score >= 0.7
                                    ? '#EF4444'
                                    : ev.ai.fusion_score >= 0.4
                                    ? '#F59E0B'
                                    : '#10B981',
                              }}
                            />
                          </div>
                        )}
                      </div>
                    </td>
                    <td>
                      <Badge variant={riskVariant(ev.ai?.risk_level)} size="sm" dot>
                        {ev.ai?.risk_level ? ev.ai.risk_level.toUpperCase() : 'INFO'}
                      </Badge>
                    </td>
                    <td>
                      <button
                        className="soc-btn-ghost btn-icon-only"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedEvent(ev);
                        }}
                        title="Xem chi tiết"
                      >
                        <Eye size={14} />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Event Details Drawer Modal */}
      <Modal
        isOpen={selectedEvent !== null}
        onClose={() => setSelectedEvent(null)}
        title="Chi tiết sự kiện an ninh"
        subtitle={`Event ID: ${selectedEvent?.event_id ?? ''}`}
        width="lg"
        drawer
      >
        {selectedEvent && (
          <div className="event-detail-drawer">
            {/* Top Metrics Row */}
            <div className="detail-meta-grid">
              <div className="meta-box">
                <span className="meta-label">Sensor Nguồn</span>
                <span className="meta-val font-semibold">{selectedEvent.source?.toUpperCase()}</span>
              </div>
              <div className="meta-box">
                <span className="meta-label">Loại sự kiện</span>
                <span className="meta-val">{selectedEvent.event_type}</span>
              </div>
              <div className="meta-box">
                <span className="meta-label">Mức Severity</span>
                <Badge variant={severityVariant(selectedEvent.severity)}>
                  Severity {selectedEvent.severity ?? 0}
                </Badge>
              </div>
              <div className="meta-box">
                <span className="meta-label">Fusion score</span>
                <Badge variant={riskVariant(selectedEvent.ai?.risk_level)} dot>
                  {selectedEvent.ai?.risk_level?.toUpperCase() || 'NORMAL'} (
                  {formatScore(selectedEvent.ai?.fusion_score)})
                </Badge>
              </div>
            </div>

            {/* AI Fusion Breakdown Section */}
            {selectedEvent.ai && (
              <div className="drawer-section">
                <h4 className="section-title">Phân tích điểm số AI (Score Breakdown)</h4>
                <div className="ai-scores-grid">
                  <div className="ai-score-item">
                    <span>Rule Match Score:</span>
                    <strong>{formatScore(selectedEvent.ai.rule_score)}</strong>
                  </div>
                  <div className="ai-score-item">
                    <span>Network Anomaly:</span>
                    <strong>{formatScore(selectedEvent.ai.network_score)}</strong>
                  </div>
                  <div className="ai-score-item">
                    <span>Log / NLP Anomaly:</span>
                    <strong>{formatScore(selectedEvent.ai.log_score)}</strong>
                  </div>
                  <div className="ai-score-item">
                    <span>Graph Correlation:</span>
                    <strong>{formatScore(selectedEvent.ai.graph_score)}</strong>
                  </div>
                </div>
              </div>
            )}

            {/* Network & Container Info */}
            <div className="drawer-section">
              <h4 className="section-title">Thông tin mạng & Container</h4>
              <div className="context-list">
                <div>
                  <strong>IP Nguồn (Src):</strong>{' '}
                  <code className="text-sky-300">{selectedEvent.src_ip || 'n/a'}</code>
                </div>
                <div>
                  <strong>IP Đích (Dst):</strong>{' '}
                  <code className="text-sky-300">{selectedEvent.dst_ip || 'n/a'}</code>
                </div>
                <div>
                  <strong>Container mục tiêu:</strong>{' '}
                  <code className="text-emerald-300">{selectedEvent.container?.name || 'n/a'}</code>
                </div>
                <div>
                  <strong>Container Image:</strong>{' '}
                  <code className="text-slate-300">{selectedEvent.container?.image || 'n/a'}</code>
                </div>
                <div>
                  <strong>Rule ID / Pattern:</strong>{' '}
                  <code className="text-amber-300">
                    {selectedEvent.rule?.rule_id || selectedEvent.rule?.name || 'n/a'}
                  </code>
                </div>
              </div>
            </div>

            {/* Raw JSON Data */}
            <div className="drawer-section">
              <h4 className="section-title">Raw Event JSON Payload</h4>
              <pre className="soc-raw-code">
                {JSON.stringify(selectedEvent, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
