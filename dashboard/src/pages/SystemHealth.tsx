import { useEffect, useState } from 'react';
import {
  Server,
  Activity,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Radio,
  Cpu,
  RefreshCw,
  Database,
  Layers,
} from 'lucide-react';
import { getJson } from '../api/client';
import { Badge, statusVariant } from '../components/Badge';
import type { Paged, SensorRow, SystemHealthData } from '../types/api';

const SERVICE_LABELS: Record<string, { label: string; group: string; icon: any }> = {
  backend: { label: 'Backend FastAPI', group: 'Hạ tầng cốt lõi', icon: Server },
  dashboard: { label: 'Web Dashboard Vite', group: 'Hạ tầng cốt lõi', icon: Server },
  postgres: { label: 'PostgreSQL Database', group: 'Hạ tầng cốt lõi', icon: Database },
  redis: { label: 'Redis Streams (Event Bus)', group: 'Hạ tầng cốt lõi', icon: Layers },

  dvwa: { label: 'DVWA Target Webapp', group: 'Môi trường Lab DVWA', icon: Server },
  nginx: { label: 'Nginx Reverse Proxy', group: 'Môi trường Lab DVWA', icon: Server },
  mariadb: { label: 'MariaDB Database', group: 'Môi trường Lab DVWA', icon: Database },

  suricata: { label: 'Suricata Network IDS', group: 'Cảm biến an ninh (Sensors)', icon: Radio },
  falco: { label: 'Falco Runtime Security', group: 'Cảm biến an ninh (Sensors)', icon: Radio },
  wazuh: { label: 'Wazuh Agent / SIEM', group: 'Cảm biến an ninh (Sensors)', icon: Radio },
  collector: { label: 'Event Collector', group: 'Cảm biến an ninh (Sensors)', icon: Layers },
  normalizer: { label: 'Event Normalizer', group: 'Cảm biến an ninh (Sensors)', icon: Layers },

  network_ai: { label: 'Network AI · XGBoost', group: 'Mô hình AI & Phân tích', icon: Cpu },
  log_ai: { label: 'Log AI · MLP / Isolation Forest', group: 'Mô hình AI & Phân tích', icon: Cpu },
  graph_ai: { label: 'Graph aggregation + MLP', group: 'Mô hình AI & Phân tích', icon: Cpu },
  fusion: { label: 'Hybrid Risk Fusion Engine', group: 'Mô hình AI & Phân tích', icon: Cpu },
  correlation: { label: 'Incident Correlation Engine', group: 'Mô hình AI & Phân tích', icon: Cpu },
  rule_engine: { label: 'Rule Lifecycle Engine', group: 'Mô hình AI & Phân tích', icon: Cpu },
  response_engine: { label: 'Active Response Engine', group: 'Mô hình AI & Phân tích', icon: Cpu },
};

export function SystemHealth() {
  const [healthData, setHealthData] = useState<SystemHealthData | null>(null);
  const [sensorsData, setSensorsData] = useState<Paged<SensorRow> | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [lastCheck, setLastCheck] = useState<Date>(new Date());

  const loadHealth = () => {
    setIsLoading(true);
    Promise.all([
      getJson<SystemHealthData>('/api/system/health').catch(() => null),
      getJson<Paged<SensorRow>>('/api/sensors').catch(() => null),
    ])
      .then(([health, sensors]) => {
        if (health) setHealthData(health);
        if (sensors) setSensorsData(sensors);
        setLastCheck(new Date());
      })
      .finally(() => setIsLoading(false));
  };

  useEffect(() => {
    loadHealth();
    const timer = window.setInterval(loadHealth, 5000);
    return () => window.clearInterval(timer);
  }, []);

  const services = healthData?.services || {};
  const isOverallHealthy = healthData?.overall === 'healthy';

  // Group services
  const groupedServices: Record<string, Array<{ key: string; status: string }>> = {
    'Hạ tầng cốt lõi': [],
    'Môi trường Lab DVWA': [],
    'Cảm biến an ninh (Sensors)': [],
    'Mô hình AI & Phân tích': [],
  };

  Object.entries(services).forEach(([key, status]) => {
    const meta = SERVICE_LABELS[key];
    const groupName = meta ? meta.group : 'Dịch vụ phụ trợ';
    if (!groupedServices[groupName]) groupedServices[groupName] = [];
    groupedServices[groupName].push({ key, status });
  });

  return (
    <div className="soc-page-container">
      {/* Banner */}
      <div
        className={`soc-status-banner ${
          isOverallHealthy ? 'banner-healthy' : 'banner-critical'
        }`}
      >
        <div className="banner-left">
          <div className="banner-status-pulse">
            <span className="pulse-ring" />
            <span className="pulse-core" />
          </div>
          <div>
            <h2 className="banner-title">
              {isOverallHealthy
                ? 'API VÀ KẾT NỐI DỮ LIỆU SẴN SÀNG'
                : 'CẢNH BÁO: MỘT SỐ DỊCH VỤ HOẠT ĐỘNG CHƯA ĐỒNG BỘ'}
            </h2>
            <p className="banner-desc">
              Reporting: có dữ liệu trong 120 giây gần nhất. Stale: chưa có dữ liệu mới, không đồng nghĩa container dừng. Kiểm tra trạng thái tiến trình bằng Docker healthcheck.
            </p>
          </div>
        </div>
        <div className="banner-actions">
          <span className="text-xs text-slate-400">
            Kiểm tra lúc: {lastCheck.toLocaleTimeString()}
          </span>
          <button
            className="soc-btn-ghost btn-sm"
            onClick={loadHealth}
            disabled={isLoading}
          >
            <RefreshCw size={14} className={isLoading ? 'spin-anim' : ''} />
            Làm mới
          </button>
        </div>
      </div>

      {/* Grouped Service Microservice Architecture Grid */}
      {Object.entries(groupedServices).map(([groupTitle, list]) => {
        if (!list.length) return null;
        return (
          <div key={groupTitle} className="soc-service-group-section mb-6">
            <h3 className="service-group-title text-sm font-bold text-slate-300 uppercase tracking-wider mb-3">
              {groupTitle}
            </h3>
            <div className="soc-service-cards-grid">
              {list.map(({ key, status }) => {
                const meta = SERVICE_LABELS[key] || {
                  label: key,
                  icon: Server,
                };
                const Icon = meta.icon;
                const isUp = ['up','healthy','reporting','running','idle'].includes(status.toLowerCase());

                return (
                  <div
                    key={key}
                    className={`soc-service-card ${isUp ? 'is-up' : 'is-down'}`}
                  >
                    <div className="service-card-top">
                      <div className="service-icon-box">
                        <Icon size={16} />
                      </div>
                      <Badge variant={isUp ? 'success' : status === 'stale' || status === 'unknown' ? 'warning' : 'critical'} size="sm" dot>
                        {status.toUpperCase()}
                      </Badge>
                    </div>
                    <div className="service-card-name">{meta.label}</div>
                    <div className="service-card-key font-mono">{key}</div>
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}

      {/* Sensor Health Detailed Table */}
      <div className="soc-panel p-0 overflow-hidden mt-6">
        <div className="panel-header px-4 py-3 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Radio size={18} className="text-emerald-400" />
            <h3 className="panel-title">Chi tiết trạng thái Sensor Health & Thời gian Ingestion</h3>
          </div>
        </div>

        <div className="table-responsive">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Tên Sensor</th>
                <th>Trạng thái</th>
                <th>Sự kiện gần nhất</th>
                <th>Thời gian Ingestion</th>
                <th>Số lỗi tích lũy</th>
                <th>Cập nhật</th>
              </tr>
            </thead>
            <tbody>
              {sensorsData?.items?.length ? (
                sensorsData.items.map((s) => (
                  <tr key={s.sensor}>
                    <td className="font-semibold text-white font-mono uppercase">
                      {s.sensor}
                    </td>
                    <td>
                      <Badge variant={statusVariant(s.status)} size="sm" dot>
                        {s.status.toUpperCase()}
                      </Badge>
                    </td>
                    <td className="font-mono text-xs text-slate-300">
                      {s.last_event_at ? s.last_event_at.replace('T', ' ').slice(0, 19) : '—'}
                    </td>
                    <td className="font-mono text-xs text-slate-400">
                      {s.last_ingestion_at ? s.last_ingestion_at.replace('T', ' ').slice(0,19) : 'Chưa có timestamp'}
                    </td>
                    <td className="font-mono text-xs">
                      <span className={s.error_count > 0 ? 'text-amber-400 font-bold' : 'text-slate-400'}>
                        {s.error_count} lỗi
                      </span>
                    </td>
                    <td className="text-xs text-slate-400">{s.updated_at ? s.updated_at.replace('T',' ').slice(0,19) : '—'}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="text-center py-6 text-slate-400">
                    Đang đồng bộ dữ liệu cảm biến...
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
