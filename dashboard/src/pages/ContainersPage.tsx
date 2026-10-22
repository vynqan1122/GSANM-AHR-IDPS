import { useEffect, useState } from 'react';
import {
  Cpu,
  Layers,
  ShieldAlert,
  Clock,
  RefreshCw,
  Eye,
  Server,
} from 'lucide-react';
import { getJson } from '../api/client';
import { Badge, riskVariant } from '../components/Badge';
import { Modal } from '../components/Modal';
import type { ContainerRow } from '../types/api';

export function ContainersPage() {
  const [containers, setContainers] = useState<ContainerRow[]>([]);
  const [selectedContainer, setSelectedContainer] = useState<ContainerRow | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const loadContainers = () => {
    setIsLoading(true);
    getJson<{ items: ContainerRow[] }>('/api/containers')
      .then((data) => setContainers(data.items || []))
      .catch(() => setContainers([]))
      .finally(() => setIsLoading(false));
  };

  useEffect(() => {
    loadContainers();
    const timer = window.setInterval(loadContainers, 10000);
    return () => window.clearInterval(timer);
  }, []);

  const formatPct = (val?: unknown) =>
    typeof val === 'number' ? `${(val * 100).toFixed(1)}%` : '0.0%';

  return (
    <div className="soc-page-container">
      {/* Banner */}
      <div className="soc-status-banner banner-healthy">
        <div className="banner-left">
          <Cpu size={24} className="text-sky-400" />
          <div>
            <h2 className="banner-title">
              GIÁM SÁT THỜI GIAN THỰC CONTAINERS & FALCO RUNTIME SECURITY
            </h2>
            <p className="banner-desc">
              Theo dõi sâu mức nhân Linux (eBPF / kernel syscalls) phát hiện hành vi leo thang đặc quyền, spawn shell, đọc file nhạy cảm trong DVWA & MariaDB.
            </p>
          </div>
        </div>
        <div className="banner-actions">
          <button
            className="soc-btn-ghost btn-sm"
            onClick={loadContainers}
            disabled={isLoading}
          >
            <RefreshCw size={14} className={isLoading ? 'spin-anim' : ''} />
            Làm mới
          </button>
        </div>
      </div>

      {/* Container Cards Grid */}
      <div className="soc-cards-grid">
        {containers.map((c) => {
          const risk = c.current_risk ?? 0;
          const falcoAlerts = c.falco_alert_count ?? 0;
          return (
            <div
              key={c.name}
              className={`soc-stat-card clickable ${
                risk >= 0.7
                  ? 'card-variant-rose'
                  : falcoAlerts > 0
                  ? 'card-variant-amber'
                  : 'card-variant-cyan'
              }`}
              onClick={() => setSelectedContainer(c)}
            >
              <div className="stat-card-header">
                <span className="stat-card-label font-bold text-white">{c.name}</span>
                <Cpu size={18} className="text-sky-400" />
              </div>

              <div className="stat-card-body">
                <div className="text-xs text-slate-400 font-mono mb-2 truncate" title={c.image || ''}>
                  {c.image || 'vulnerable/web-dvwa:latest'}
                </div>
                <div className="flex items-center justify-between w-full">
                  <Badge variant={riskVariant(risk)} size="sm">
                    Risk: {formatPct(risk)}
                  </Badge>
                  <span className="text-xs text-slate-300">
                    <b className={falcoAlerts > 0 ? 'text-amber-400' : 'text-slate-400'}>
                      {falcoAlerts}
                    </b>{' '}
                    Falco alerts
                  </span>
                </div>
              </div>

              <div className="stat-card-footer justify-between text-xs text-slate-400 pt-2 border-t border-slate-800">
                <span>Events: <b>{c.event_count || 0}</b></span>
                <span>Thấy lần cuối: <b>{c.last_seen ? c.last_seen.slice(11, 19) : 'Vừa xong'}</b></span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Containers Detail Table */}
      <div className="soc-panel p-0 overflow-hidden">
        <div className="panel-header px-4 py-3 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Layers size={18} className="text-emerald-400" />
            <h3 className="panel-title">Bảng thống kê giám sát Runtime Security Containers</h3>
          </div>
          <span className="text-xs text-slate-400">
            Dữ liệu tích hợp từ Falco Runtime Security & Docker daemon
          </span>
        </div>

        <div className="table-responsive">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Container Name</th>
                <th>Docker Image</th>
                <th>Trạng thái</th>
                <th>Số sự kiện Runtime</th>
                <th>Cảnh báo Falco (Syscalls)</th>
                <th>Chỉ số rủi ro (Risk Score)</th>
                <th>Hoạt động gần nhất</th>
                <th>Chi tiết</th>
              </tr>
            </thead>
            <tbody>
              {containers.length === 0 ? (
                <tr>
                  <td colSpan={8} className="text-center py-8 text-slate-400">
                    {isLoading ? 'Đang đọc danh sách containers...' : 'Không có container nào trong phạm vi giám sát.'}
                  </td>
                </tr>
              ) : (
                containers.map((c) => (
                  <tr
                    key={c.name}
                    onClick={() => setSelectedContainer(c)}
                    className="clickable-row"
                  >
                    <td className="font-semibold text-white flex items-center gap-2">
                      <Server size={14} className="text-sky-400" />
                      {c.name}
                    </td>
                    <td className="font-mono text-xs text-slate-300 truncate max-w-xs">{c.image || '—'}</td>
                    <td>
                      <Badge variant="success" size="sm" dot>
                        OBSERVED / HEALTHY
                      </Badge>
                    </td>
                    <td className="font-mono text-xs text-slate-300">{c.event_count || 0}</td>
                    <td>
                      <Badge variant={(c.falco_alert_count ?? 0) > 0 ? 'warning' : 'neutral'} size="sm">
                        {c.falco_alert_count || 0} alerts
                      </Badge>
                    </td>
                    <td>
                      <Badge variant={riskVariant(c.current_risk)} size="sm">
                        {formatPct(c.current_risk)}
                      </Badge>
                    </td>
                    <td className="text-xs text-slate-400 font-mono">
                      {c.last_seen ? c.last_seen.replace('T', ' ').slice(0, 19) : '—'}
                    </td>
                    <td>
                      <button
                        className="soc-btn-ghost btn-icon-only"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedContainer(c);
                        }}
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

      {/* Container Details Modal */}
      <Modal
        isOpen={selectedContainer !== null}
        onClose={() => setSelectedContainer(null)}
        title={`Thông tin Container: ${selectedContainer?.name || ''}`}
        subtitle={`Docker Image: ${selectedContainer?.image || ''}`}
        width="md"
      >
        {selectedContainer && (
          <div className="space-y-4">
            <div className="detail-meta-grid">
              <div className="meta-box">
                <span className="meta-label">Tổng sự kiện</span>
                <span className="meta-val font-mono">{selectedContainer.event_count || 0}</span>
              </div>
              <div className="meta-box">
                <span className="meta-label">Cảnh báo Falco</span>
                <span className="meta-val font-mono text-amber-400">
                  {selectedContainer.falco_alert_count || 0}
                </span>
              </div>
              <div className="meta-box">
                <span className="meta-label">Chỉ số rủi ro hiện tại</span>
                <Badge variant={riskVariant(selectedContainer.current_risk)}>
                  {formatPct(selectedContainer.current_risk)}
                </Badge>
              </div>
            </div>

            <div className="drawer-section">
              <h4 className="section-title">Chính sách giám sát Runtime Container</h4>
              <ul className="text-xs text-slate-300 space-y-1.5 list-disc pl-4">
                <li>Phát hiện mở shell tương tác bên trong container (Terminal Spawn).</li>
                <li>Phát hiện chỉnh sửa hoặc đọc tệp cấu hình hệ thống (/etc/passwd, /etc/shadow).</li>
                <li>Phát hiện kết nối outbound bất thường ra địa chỉ IP ngoài lab.</li>
                <li>Tự động kích hoạt cơ chế cô lập container (Network Quarantining) khi Risk &gt; 0.9.</li>
              </ul>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
