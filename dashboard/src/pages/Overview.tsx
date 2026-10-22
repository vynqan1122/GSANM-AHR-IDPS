import { useEffect, useState } from 'react';
import {
  ShieldAlert,
  Activity,
  Flame,
  Radio,
  FileCheck2,
  AlertTriangle,
  RefreshCw,
} from 'lucide-react';
import { getJson } from '../api/client';
import { BarList } from '../charts/BarList';
import { StatCard } from '../components/StatCard';
import { ScoreGauge } from '../components/ScoreGauge';
import { TimeseriesChart } from '../components/TimeseriesChart';
import { Badge } from '../components/Badge';
import type { OverviewData, Paged, SensorRow, TimeseriesPoint } from '../types/api';

export function Overview({ onNavigate }: { onNavigate?: (view: string) => void }) {
  const [overview, setOverview] = useState<OverviewData | null>(null);
  const [timeseries, setTimeseries] = useState<TimeseriesPoint[]>([]);
  const [sensors, setSensors] = useState<Paged<SensorRow> | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [lastRefreshed, setLastRefreshed] = useState<Date>(new Date());

  const loadData = () => {
    setIsLoading(true);
    Promise.all([
      getJson<OverviewData>('/api/dashboard/overview').catch(() => null),
      getJson<{ items: TimeseriesPoint[] }>('/api/dashboard/timeseries?minutes=60').catch(() => ({ items: [] })),
      getJson<Paged<SensorRow>>('/api/sensors').catch(() => null),
    ]).then(([ov, ts, sens]) => {
      if (ov) setOverview(ov);
      if (ts?.items) setTimeseries(ts.items);
      if (sens) setSensors(sens);
      setLastRefreshed(new Date());
      setIsLoading(false);
    });
  };

  useEffect(() => {
    loadData();
    const timer = window.setInterval(loadData, 5000);
    return () => window.clearInterval(timer);
  }, []);

  const reportingSensors = (sensors?.items ?? []).filter((item) =>
    ['healthy', 'reporting', 'up', 'running'].includes(item.status.toLowerCase()),
  ).length;

  const totalSensors = sensors?.items.length ?? 0;
  const cards = overview?.cards ?? {};
  const riskScore = cards.overall_security_risk ?? 0;
  const isCritical = (cards.critical_alerts ?? 0) > 0 || (cards.critical_incidents ?? 0) > 0;

  return (
    <div className="soc-page-container">
      {/* Top Banner Status */}
      <div className={`soc-status-banner ${isCritical ? 'banner-critical' : 'banner-healthy'}`}>
        <div className="banner-left">
          <div className="banner-status-pulse">
            <span className="pulse-ring" />
            <span className="pulse-core" />
          </div>
          <div>
            <h2 className="banner-title">
              {isCritical ? 'HỆ THỐNG PHÁT HIỆN DẤU HIỆU TẤN CÔNG BẤT THƯỜNG' : 'HỆ THỐNG AN NINH HOẠT ĐỘNG BÌNH THƯỜNG'}
            </h2>
            <p className="banner-desc">
              Giám sát hybrid đa tầng: Network (Suricata), Runtime (Falco), Host/SIEM (Wazuh), AI Anomaly Detection trên DVWA Lab.
            </p>
          </div>
        </div>
        <div className="banner-actions">
          <span className="text-xs text-slate-400">
            Cập nhật lúc: {lastRefreshed.toLocaleTimeString()}
          </span>
          <button
            className="soc-btn-ghost btn-sm"
            onClick={loadData}
            title="Làm mới ngay"
            disabled={isLoading}
          >
            <RefreshCw size={14} className={isLoading ? 'spin-anim' : ''} />
            Làm mới
          </button>
        </div>
      </div>

      {/* KPI Cards Row */}
      <div className="soc-cards-grid">
        <StatCard
          label="TỔNG SỰ KIỆN GHI NHẬN"
          value={(cards.total_events ?? 0).toLocaleString()}
          icon={<Activity size={18} />}
          subtext="Toàn bộ luồng dữ liệu chuẩn hóa"
          variant="cyan"
          trend={{ value: `${cards.events_per_min ?? 0}/phút`, isUp: true, isPositive: true }}
          onClick={() => onNavigate?.('live-events')}
        />
        <StatCard
          label="CẢNH BÁO ĐANG MỞ"
          value={cards.active_alerts ?? 0}
          icon={<AlertTriangle size={18} />}
          subtext={`Trong đó ${cards.critical_alerts ?? 0} mức nguy hiểm cao`}
          variant={cards.active_alerts ? 'amber' : 'emerald'}
          badge={cards.critical_alerts ? 'CẦN XỬ LÝ' : 'BÌNH THƯỜNG'}
          onClick={() => onNavigate?.('live-events')}
        />
        <StatCard
          label="SỰ CỐ AN NINH (INCIDENTS)"
          value={cards.open_incidents ?? 0}
          icon={<ShieldAlert size={18} />}
          subtext={`Chuỗi tấn công liên quan: ${cards.critical_incidents ?? 0}`}
          variant={cards.critical_incidents ? 'rose' : 'violet'}
          badge={cards.open_incidents ? 'INVESTIGATING' : 'ZERO OPEN'}
          onClick={() => onNavigate?.('incidents')}
        />
        <StatCard
          label="SENSORS ĐANG BÁO CÁO"
          value={`${reportingSensors}/${totalSensors}`}
          icon={<Radio size={18} />}
          subtext="Suricata · Falco · Wazuh Agent"
          variant="emerald"
          badge={reportingSensors === totalSensors ? '100% ONLINE' : 'DEGRADED'}
          onClick={() => onNavigate?.('system-health')}
        />
        <StatCard
          label="RULES ĐANG KÍCH HOẠT"
          value={cards.active_rules ?? 0}
          icon={<FileCheck2 size={18} />}
          subtext={`Shadow testing: ${cards.shadow_rules ?? 0} rule`}
          variant="violet"
          onClick={() => onNavigate?.('rules')}
        />
      </div>

      {/* Main Grid: Timeseries & Score Gauge */}
      <div className="soc-grid-2col">
        {/* Left Column: Events Over Time Chart */}
        <div className="soc-panel">
          <div className="panel-header">
            <div className="flex items-center gap-2">
              <Activity size={18} className="text-sky-400" />
              <h3 className="panel-title">Lưu lượng sự kiện theo thời gian (Events/Time)</h3>
            </div>
            <Badge variant="cyan" size="sm">
              60 Phút gần nhất
            </Badge>
          </div>
          <TimeseriesChart data={timeseries} height={240} />
        </div>

        {/* Right Column: Security Risk Gauge */}
        <div className="soc-panel flex flex-col justify-center items-center">
          <div className="panel-header w-full">
            <div className="flex items-center gap-2">
              <Flame size={18} className="text-amber-400" />
              <h3 className="panel-title">Mức độ rủi ro hệ thống (Risk Score)</h3>
            </div>
          </div>
          <div className="py-2 flex justify-center items-center w-full">
            <ScoreGauge
              score={riskScore}
              size={190}
              label="Chỉ số nguy cơ tổng hợp"
              sublabel="Kết hợp từ AI Fusion + Rule Correlations"
            />
          </div>
        </div>
      </div>

      {/* Distribution Breakdown Grid */}
      <div className="soc-grid-3col">
        {/* Panel 1: Events by Source */}
        <div className="soc-panel">
          <div className="panel-header">
            <h3 className="panel-title">Sự kiện theo Sensor nguồn</h3>
            <span className="panel-subtitle">24 Giờ qua</span>
          </div>
          <BarList
            items={(overview?.events_by_source ?? []).map((x) => ({
              label: x.source.toUpperCase(),
              value: x.count,
            }))}
            colorVariant="cyan"
          />
        </div>

        {/* Panel 2: Alerts by Severity */}
        <div className="soc-panel">
          <div className="panel-header">
            <h3 className="panel-title">Cảnh báo theo Mức độ nghiêm trọng</h3>
            <span className="panel-subtitle">Thang điểm 1 - 10</span>
          </div>
          <BarList
            items={(overview?.alerts_by_severity ?? []).map((x) => ({
              label: `Mức ${x.severity}`,
              value: x.count,
            }))}
            colorVariant="severity"
          />
        </div>

        {/* Panel 3: Top Threat Source IPs */}
        <div className="soc-panel">
          <div className="panel-header">
            <h3 className="panel-title">Top Địa chỉ IP Nguồn</h3>
            <span className="panel-subtitle">Lưu lượng tấn công / truy vấn</span>
          </div>
          <BarList
            items={(overview?.top_source_ips ?? []).map((x) => ({
              label: x.src_ip || '127.0.0.1 (local)',
              value: x.count,
            }))}
            colorVariant="amber"
          />
        </div>
      </div>
    </div>
  );
}
