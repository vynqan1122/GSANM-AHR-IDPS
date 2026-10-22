import { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Activity,
  Layers,
  Cpu,
  FileCode2,
  Network,
  Boxes,
  Lock,
  HeartPulse,
  FlaskConical,
  Radio,
  ChevronLeft,
  ChevronRight,
  ShieldCheck,
  AlertTriangle,
} from 'lucide-react';

import { Overview } from '../pages/Overview';
import { LiveEvents } from '../pages/LiveEvents';
import { Incidents } from '../pages/Incidents';
import { AIMonitor } from '../pages/AIMonitor';
import { Rules } from '../pages/Rules';
import { NetworkPage } from '../pages/NetworkPage';
import { ContainersPage } from '../pages/ContainersPage';
import { Responses } from '../pages/Responses';
import { SystemHealth } from '../pages/SystemHealth';
import { Experiments } from '../pages/Experiments';
import { AttackGraphPage } from '../pages/ResearchPages';

export type DashboardView =
  | 'overview'
  | 'live-events'
  | 'network'
  | 'incidents'
  | 'attack-graph'
  | 'ai-monitor'
  | 'containers'
  | 'rules'
  | 'responses'
  | 'system-health'
  | 'experiments';

interface NavItem {
  id: DashboardView;
  label: string;
  sublabel: string;
  icon: any;
  badge?: string;
}

interface NavSection {
  title: string;
  items: NavItem[];
}

const NAV_SECTIONS: NavSection[] = [
  {
    title: 'Giám sát',
    items: [
      { id: 'overview', label: 'Tổng quan Security', sublabel: 'Executive SOC summary', icon: Activity },
      { id: 'live-events', label: 'Sự kiện Realtime', sublabel: 'WebSocket event stream (LiveEvents)', icon: Layers, badge: 'LIVE' },
      { id: 'network', label: 'Lưu lượng mạng & IDS', sublabel: 'Suricata network analytics', icon: Network },
    ],
  },
  {
    title: 'Điều tra',
    items: [
      { id: 'incidents', label: 'Sự cố & Attack Chain', sublabel: 'Correlated attack graphs (Incidents)', icon: ShieldAlert },
      { id: 'attack-graph', label: 'Graph 20 request', sublabel: '20 request tấn công đầu tiên', icon: Network },
      { id: 'ai-monitor', label: 'Mô hình AI & Fusion', sublabel: 'AIMonitorPage & Fusion metrics', icon: Cpu },
      { id: 'containers', label: 'Containers & Runtime', sublabel: 'DVWA, MariaDB & Falco', icon: Boxes },
    ],
  },
  {
    title: 'Quản trị',
    items: [
      { id: 'rules', label: 'Quản lý Quy tắc (Rules)', sublabel: 'Candidate → Shadow → Active', icon: FileCode2 },
      { id: 'responses', label: 'Phản ứng chủ động', sublabel: 'Active defense & containment (Responses)', icon: Lock },
      { id: 'system-health', label: 'Sức khỏe Hệ thống', sublabel: 'SensorHealth & WazuhManagerPage', icon: HeartPulse },
      { id: 'experiments', label: 'Thực nghiệm E1–E9', sublabel: 'Ablation research benchmarks', icon: FlaskConical },
    ],
  },
];

export function AppLayout() {
  const [activeView, setActiveView] = useState<DashboardView>('overview');
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false);
  const [currentTime, setCurrentTime] = useState<string>('');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setCurrentTime(
        now.toLocaleDateString('vi-VN', {
          weekday: 'short',
          month: 'numeric',
          day: 'numeric',
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        })
      );
    };
    updateTime();
    const timer = setInterval(updateTime, 1000);
    return () => clearInterval(timer);
  }, []);

  const activeMeta = NAV_SECTIONS.flatMap((s) => s.items).find((i) => i.id === activeView);

  return (
    <div className={`soc-app-container ${isSidebarCollapsed ? 'sidebar-collapsed' : ''}`}>
      {/* Sidebar Navigation */}
      <aside className="soc-sidebar">
        {/* Brand Header */}
        <div className="sidebar-brand">
          <div className="brand-logo-glow">
            <ShieldCheck size={22} className="text-sky-400" />
          </div>
          {!isSidebarCollapsed && (
            <div className="brand-text">
              <h1 className="brand-title">AHR-IDPS</h1>
              <span className="brand-sub">Adaptive Hybrid IDPS</span>
            </div>
          )}
          <button
            className="sidebar-collapse-toggle"
            onClick={() => setIsSidebarCollapsed(!isSidebarCollapsed)}
            title={isSidebarCollapsed ? 'Mở rộng sidebar' : 'Thu gọn sidebar'}
          >
            {isSidebarCollapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
          </button>
        </div>

        {/* System Heartbeat Pill */}
        {!isSidebarCollapsed && (
          <div className="sidebar-status-box">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
              <span className="text-xs font-semibold text-slate-200">LAB DVWA GIÁM SÁT</span>
            </div>
            <span className="text-[10px] text-slate-400 font-mono">127.0.0.1 · ISOLATED BRIDGE</span>
          </div>
        )}

        {/* Navigation Sections */}
        <nav className="sidebar-nav">
          {NAV_SECTIONS.map((section) => (
            <div key={section.title} className="nav-section-group">
              {!isSidebarCollapsed && (
                <div className="nav-section-title">{section.title}</div>
              )}
              <div className="nav-items-list">
                {section.items.map((item) => {
                  const Icon = item.icon;
                  const isActive = activeView === item.id;
                  return (
                    <button
                      key={item.id}
                      className={`nav-item-btn ${isActive ? 'is-active' : ''}`}
                      aria-label={item.label}
                      onClick={() => setActiveView(item.id)}
                      title={item.label}
                    >
                      <div className="nav-item-icon">
                        <Icon size={18} />
                      </div>
                      {!isSidebarCollapsed && (
                        <div className="nav-item-content">
                          <div className="nav-item-label">{item.label}</div>
                          <div className="nav-item-sub">{item.sublabel}</div>
                        </div>
                      )}
                      {!isSidebarCollapsed && item.badge && (
                        <span className="nav-item-badge">{item.badge}</span>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        {/* Bottom Lab Info */}
        {!isSidebarCollapsed && (
          <div className="sidebar-footer">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <Radio size={14} className="text-sky-400" />
              <span>Sensors: Suricata · Falco · Wazuh</span>
            </div>
          </div>
        )}
      </aside>

      {/* Main App Workspace */}
      <div className="soc-main-workspace">
        {/* Top Header Bar */}
        <header className="soc-topbar">
          <div className="topbar-left">
            <h2 className="topbar-title">{activeMeta?.label}</h2>
            <span className="topbar-breadcrumb">{activeMeta?.sublabel}</span>
          </div>

          <div className="topbar-right">
            <div className="topbar-time font-mono">
              {currentTime}
            </div>
            <div className="topbar-status-chip">
              <ShieldCheck size={14} className="text-emerald-400" />
              <span className="text-xs font-semibold text-slate-200">LAB LOCAL</span>
            </div>
          </div>
        </header>

        {/* Dynamic Content View */}
        <main className="soc-content-area">
          {activeView === 'overview' && <Overview onNavigate={(v) => setActiveView(v as DashboardView)} />}
          {activeView === 'live-events' && <LiveEvents />}
          {activeView === 'network' && <NetworkPage />}
          {activeView === 'incidents' && <Incidents />}
          {activeView === 'attack-graph' && <AttackGraphPage />}
          {activeView === 'ai-monitor' && <AIMonitor />}
          {activeView === 'containers' && <ContainersPage />}
          {activeView === 'rules' && <Rules />}
          {activeView === 'responses' && <Responses />}
          {activeView === 'system-health' && <SystemHealth />}
          {activeView === 'experiments' && <Experiments />}
        </main>
      </div>
    </div>
  );
}
