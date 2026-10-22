import { useEffect, useRef, useState } from 'react';
import {
  Network,
  Activity,
  ShieldAlert,
  ArrowDownUp,
  Server,
  Globe,
  RefreshCw,
} from 'lucide-react';
import { getJson } from '../api/client';
import { StatCard } from '../components/StatCard';
import { BarList } from '../charts/BarList';
import type { NetworkSummaryData } from '../types/api';

export function NetworkPage() {
  const [data, setData] = useState<NetworkSummaryData | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const requestInFlight = useRef(false);

  const loadNetwork = () => {
    if(requestInFlight.current) return;
    requestInFlight.current = true;
    setIsLoading(true);
    getJson<NetworkSummaryData>('/api/network/summary')
      .then((next) => { setData(next); setError(''); })
      .catch(() => setError('Không tải được dữ liệu mới. Đang giữ bản gần nhất; bấm Làm mới để thử lại.'))
      .finally(() => {setIsLoading(false);requestInFlight.current=false;});
  };

  useEffect(() => {
    loadNetwork();
    const timer = window.setInterval(loadNetwork, 8000);
    return () => window.clearInterval(timer);
  }, []);

  const summary = data?.summary || {};
  const numeric = (value: unknown) => Number.isFinite(Number(value)) ? Number(value) : 0;
  const flowsPerSec = numeric(summary.flows_per_sec).toFixed(1);
  const bytesPerSec = (numeric(summary.bytes_per_sec)/1024).toFixed(1)+' KB/s';
  const suricataAlerts = numeric(summary.suricata_alerts);

  return (
    <div className="soc-page-container">
      {/* Network Header */}
      <div className="soc-status-banner banner-healthy">
        <div className="banner-left">
          <Network size={24} className="text-sky-400" />
          <div>
            <h2 className="banner-title">
              PHÂN TÍCH LƯU LƯỢNG MẠNG & SURICATA NETWORK IDS
            </h2>
            <p className="banner-desc">
              Dữ liệu Suricata quan sát tại Nginx. Tốc độ tính từ flow kết thúc trong phút gần nhất; biểu đồ phân bố và tổng alert dùng toàn bộ lịch sử thu thập.
            </p>
          </div>
        </div>
        <div className="banner-actions">
          <button
            className="soc-btn-ghost btn-sm"
            onClick={loadNetwork}
            disabled={isLoading}
          >
            <RefreshCw size={14} className={isLoading ? 'spin-anim' : ''} />
            Làm mới
          </button>
        </div>
      </div>

      {error && <p role="alert">{error}</p>}
      {isLoading && !data && <p role="status">Đang tải dữ liệu Suricata…</p>}

      {/* KPI Cards */}
      <div className="soc-cards-grid">
        <StatCard
          label="TỐC ĐỘ LUỒNG (FLOWS/SEC)"
          value={flowsPerSec}
          icon={<ArrowDownUp size={18} />}
          subtext="Flow records/giây · trung bình 1 phút"
          variant="cyan"
        />
        <StatCard
          label="BĂNG THÔNG MẠNG (THROUGHPUT)"
          value={bytesPerSec}
          icon={<Activity size={18} />}
          subtext="Byte từ flow hoàn tất · trung bình 1 phút"
          variant="emerald"
        />
        <StatCard
          label="CẢNH BÁO SURICATA (IDS ALERTS)"
          value={suricataAlerts}
          icon={<ShieldAlert size={18} />}
          subtext="Phát hiện dấu hiệu tấn công mạng"
          variant={suricataAlerts > 0 ? 'amber' : 'slate'}
          badge={suricataAlerts > 0 ? 'SUSPICIOUS' : 'CLEAN'}
        />
        <StatCard
          label="GIAO THỨC CHÍNH"
          value="HTTP / TCP"
          icon={<Globe size={18} />}
          subtext="DVWA Web & REST API"
          variant="violet"
        />
      </div>

      {/* Main Grid: Protocols & Top Ports */}
      <div className="soc-grid-2col">
        {/* Protocol Distribution */}
        <div className="soc-panel">
          <div className="panel-header">
            <h3 className="panel-title flex items-center gap-2">
              <Globe size={18} className="text-sky-400" />
              Phân bổ Giao thức mạng (Protocols)
            </h3>
          </div>
          <BarList
            items={(data?.protocols || []).map((p) => ({
              label: String(p.protocol || 'chưa rõ').toUpperCase(),
              value: numeric(p.count),
            }))}
            colorVariant="cyan"
          />
        </div>

        {/* Top Destination Ports */}
        <div className="soc-panel">
          <div className="panel-header">
            <h3 className="panel-title flex items-center gap-2">
              <Server size={18} className="text-emerald-400" />
              Top Cổng dịch vụ đích (Destination Ports)
            </h3>
          </div>
          <BarList
            items={(data?.top_destination_ports || []).map((p) => {
              let portName = `Port ${p.dst_port}`;
              if (p.dst_port === 80) portName = 'Port 80 (HTTP / DVWA)';
              else if (p.dst_port === 3306) portName = 'Port 3306 (MariaDB)';
              else if (p.dst_port === 8000) portName = 'Port 8000 (Backend API)';
              else if (p.dst_port === 5173) portName = 'Port 5173 (Dashboard Vite)';
              else if (p.dst_port === 6379) portName = 'Port 6379 (Redis Stream)';
              return {
                label: portName,
                value: numeric(p.count),
              };
            })}
            colorVariant="emerald"
          />
        </div>
      </div>

      {/* Bottom Grid: Top Sources & Destinations */}
      <div className="soc-grid-2col">
        {/* Top Source IPs */}
        <div className="soc-panel">
          <div className="panel-header">
            <h3 className="panel-title">Top Địa chỉ IP Nguồn (Source IPs)</h3>
            <span className="panel-subtitle">Điểm xuất phát của lưu lượng truy cập</span>
          </div>
          <BarList
            items={(data?.top_sources || []).map((s) => ({
              label: s.src_ip || 'Chưa ghi nhận IP nguồn',
              value: numeric(s.count),
            }))}
            colorVariant="amber"
          />
        </div>

        {/* Top Destination IPs */}
        <div className="soc-panel">
          <div className="panel-header">
            <h3 className="panel-title">Top Địa chỉ IP Đích (Destination IPs)</h3>
            <span className="panel-subtitle">Điểm đến của các gói tin</span>
          </div>
          <BarList
            items={(data?.top_destinations || []).map((d) => ({
              label: d.dst_ip || 'Chưa ghi nhận IP đích',
              value: numeric(d.count),
            }))}
            colorVariant="cyan"
          />
        </div>
      </div>
    </div>
  );
}
