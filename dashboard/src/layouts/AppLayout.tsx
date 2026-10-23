import { Component, Suspense, useEffect, useRef, useState, type ReactNode } from 'react';
import { Link, NavLink, Outlet, useLocation } from 'react-router';
import { useQueryClient } from '@tanstack/react-query';
import {
  Activity,
  ArrowUp,
  Boxes,
  ChevronsLeft,
  ChevronsRight,
  Cpu,
  FileCode2,
  FlaskConical,
  GitBranch,
  HeartPulse,
  Layers,
  Menu,
  Network,
  Pause,
  Play,
  Search,
  ShieldAlert,
  ShieldCheck,
  type LucideIcon,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { usePolling, useApi } from '@/api/query';
import { LiveEventsContext, useLiveEvents, type LiveStatus } from '@/hooks/useLiveEvents';
import { isHealthy, type Tone } from '@/lib/severity';
import { Button } from '@/components/ui/button';
import { Skeleton, Tip } from '@/components/ui/overlays';
import { EmptyState, StatusDot } from '@/components/soc/primitives';
import type { Paged, SensorRow } from '@/types/api';
import { LogoMark } from '@/components/soc/Logo';
import { CommandPalette } from './CommandPalette';

interface NavItem {
  path: string;
  label: string;
  description: string;
  icon: LucideIcon;
  /** Page component(s) rendered at this route; also checked by scripts/verify_phase14.sh. */
  page: string;
  live?: boolean;
}

const NAV_SECTIONS: Array<{ title: string; items: NavItem[] }> = [
  {
    title: 'Giám sát',
    items: [
      { path: '/', label: 'Tổng quan', description: 'Tình trạng an ninh của lab DVWA', icon: Activity, page: 'Overview' },
      { path: '/events', label: 'Sự kiện realtime', description: 'Luồng sự kiện chuẩn hóa qua WebSocket', icon: Layers, page: 'LiveEvents', live: true },
      { path: '/network', label: 'Mạng & IDS', description: 'Phân tích lưu lượng Suricata', icon: Network, page: 'NetworkPage' },
    ],
  },
  {
    title: 'Điều tra',
    items: [
      { path: '/incidents', label: 'Sự cố', description: 'Incidents và chuỗi tấn công tương quan', icon: ShieldAlert, page: 'Incidents' },
      { path: '/attack-graph', label: 'Graph 20 request', description: '20 request tấn công đầu tiên trong lịch sử', icon: GitBranch, page: 'AttackGraphPage' },
      { path: '/ai', label: 'Mô hình AI', description: 'AI Monitor và Fusion score', icon: Cpu, page: 'AIMonitorPage' },
      { path: '/containers', label: 'Containers', description: 'Runtime và cảnh báo Falco theo container', icon: Boxes, page: 'ContainersPage' },
    ],
  },
  {
    title: 'Quản trị',
    items: [
      { path: '/rules', label: 'Quy tắc', description: 'Vòng đời Candidate → Shadow → Active', icon: FileCode2, page: 'Rules' },
      { path: '/responses', label: 'Phản ứng', description: 'Active response và bằng chứng', icon: ShieldCheck, page: 'Responses' },
      { path: '/health', label: 'Sức khỏe hệ thống', description: 'Dịch vụ, sensor và Wazuh Manager', icon: HeartPulse, page: 'SensorHealth + WazuhManagerPage' },
      { path: '/experiments', label: 'Thực nghiệm', description: 'Ablation E1–E9', icon: FlaskConical, page: 'Experiments' },
    ],
  },
];

const NAV_ITEMS = NAV_SECTIONS.flatMap((section) => section.items.map((item) => ({ ...item, section: section.title })));

function findNav(pathname: string) {
  return (
    NAV_ITEMS.find((item) => item.path !== '/' && pathname.startsWith(item.path)) ??
    NAV_ITEMS.find((item) => item.path === pathname)
  );
}

const SIDEBAR_KEY = 'ahr.sidebar.collapsed';

function readCollapsed() {
  try {
    return window.localStorage.getItem(SIDEBAR_KEY) === '1';
  } catch {
    return false;
  }
}

const liveMeta: Record<LiveStatus, { tone: Tone; label: string }> = {
  live: { tone: 'success', label: 'Live' },
  connecting: { tone: 'warning', label: 'Đang kết nối' },
  reconnecting: { tone: 'critical', label: 'Mất kết nối' },
};

export function AppLayout() {
  const location = useLocation();
  const live = useLiveEvents(300);
  const [collapsed, setCollapsed] = useState(readCollapsed);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [showTop, setShowTop] = useState(false);
  const mainRef = useRef<HTMLElement>(null);
  const active = findNav(location.pathname);

  useEffect(() => {
    try {
      window.localStorage.setItem(SIDEBAR_KEY, collapsed ? '1' : '0');
    } catch {
      /* storage unavailable: keep in-memory state only */
    }
  }, [collapsed]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setPaletteOpen((open) => !open);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  useEffect(() => {
    setMobileOpen(false);
    mainRef.current?.scrollTo({ top: 0 });
    document.title = active ? `${active.label} · AHR-IDPS` : 'AHR-IDPS · Security Operations Center';
  }, [location.pathname, active]);

  return (
    <LiveEventsContext.Provider value={live}>
      <div className="flex h-screen overflow-hidden">
        {mobileOpen && <div className="fixed inset-0 z-30 animate-fade-in bg-black/50 lg:hidden" onClick={() => setMobileOpen(false)} />}
        <Sidebar collapsed={collapsed} mobileOpen={mobileOpen} onToggle={() => setCollapsed((value) => !value)} liveStatus={live.status} />

        <div className="relative flex min-h-0 min-w-0 flex-1 flex-col">
          <Topbar
            section={active?.section}
            title={active?.label ?? 'Không tìm thấy trang'}
            liveStatus={live.status}
            onMenu={() => setMobileOpen(true)}
            onSearch={() => setPaletteOpen(true)}
          />
          <main
            ref={mainRef}
            onScroll={(event) => setShowTop(event.currentTarget.scrollTop > 400)}
            className="min-h-0 min-w-0 flex-1 overflow-y-auto overscroll-contain"
            data-page={active?.page}
          >
            <RouteErrorBoundary key={location.pathname}>
              <Suspense fallback={<PageFallback />}>
                <Outlet />
              </Suspense>
            </RouteErrorBoundary>
          </main>
          <ScrollTopButton visible={showTop} onClick={() => mainRef.current?.scrollTo({ top: 0, behavior: 'smooth' })} />
        </div>
      </div>
      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} items={NAV_ITEMS} />
    </LiveEventsContext.Provider>
  );
}

function Sidebar({
  collapsed,
  mobileOpen,
  onToggle,
  liveStatus,
}: {
  collapsed: boolean;
  mobileOpen: boolean;
  onToggle: () => void;
  liveStatus: LiveStatus;
}) {
  const sensors = useApi<Paged<SensorRow>>('/api/sensors', 15_000);
  const sensorRows = (sensors.data?.items ?? []).filter((row) => ['suricata', 'falco', 'wazuh', 'nginx'].includes(row.sensor));
  const healthyCount = sensorRows.filter((row) => isHealthy(row.status)).length;
  const narrow = collapsed && !mobileOpen;

  return (
    <aside
      className={cn(
        'glass fixed inset-y-0 left-0 z-40 flex w-64 shrink-0 flex-col bg-[#0a1020]/90 transition-[width,transform] duration-200 lg:static lg:m-3 lg:h-[calc(100vh-1.5rem)] lg:translate-x-0 lg:rounded-[28px] lg:bg-transparent',
        mobileOpen ? 'translate-x-0' : '-translate-x-full',
        collapsed && 'lg:w-20',
      )}
    >
      <Link
        to="/"
        aria-label="AHR-IDPS · về trang Tổng quan"
        title="Về trang Tổng quan"
        className={cn('flex h-17 shrink-0 items-center gap-3 px-6 pt-1 text-foreground transition-opacity hover:opacity-80', narrow && 'lg:justify-center lg:px-0')}
      >
        <LogoMark size={30} className="shrink-0" />
        <span className={cn('min-w-0 text-[18px] leading-none font-semibold tracking-[-0.01em]', narrow && 'lg:hidden')}>AHR-IDPS</span>
      </Link>

      <nav
        className={cn('min-h-0 flex-1 overflow-y-auto overscroll-contain px-3.5 py-5', narrow && 'lg:[&::-webkit-scrollbar]:hidden')}
        style={narrow ? { scrollbarWidth: 'none' } : undefined}
        aria-label="Điều hướng chính"
      >
        {NAV_SECTIONS.map((section) => (
          <div key={section.title} className="mb-6">
            <div className={cn('eyebrow px-3 pb-2', narrow && 'lg:sr-only')}>{section.title}</div>
            <ul className="flex flex-col gap-0.5">
              {section.items.map((item) => {
                const Icon = item.icon;
                const link = (
                  <NavLink
                    to={item.path}
                    end={item.path === '/'}
                    aria-label={item.label}
                    className={({ isActive }) =>
                      cn(
                        'relative flex h-10.5 items-center gap-3 rounded-full px-4 text-sm font-medium transition-colors',
                        isActive ? 'bg-white/[0.12] text-foreground shadow-[inset_0_1px_0_rgb(255_255_255/0.14)]' : 'text-muted-foreground hover:bg-white/[0.05] hover:text-foreground',
                        narrow && 'lg:mx-auto lg:w-11 lg:justify-center lg:px-0',
                      )
                    }
                  >
                    {({ isActive }) => (
                      <>
                        <Icon className={cn('size-[18px] shrink-0', isActive && 'text-primary')} />
                        <span className={cn('flex-1 truncate', narrow && 'lg:hidden')}>{item.label}</span>
                        {item.live && <StatusDot tone={liveMeta[liveStatus].tone} pulse={liveStatus === 'live'} className={cn(narrow && 'lg:hidden')} />}
                      </>
                    )}
                  </NavLink>
                );
                // Tip (Radix asChild) merges className as a string, which would break NavLink's className function; wrap it in a span.
                return <li key={item.path}>{narrow ? <Tip content={item.label} side="right"><span className="block">{link}</span></Tip> : link}</li>;
              })}
            </ul>
          </div>
        ))}
      </nav>

      <div className={cn('flex items-center justify-between gap-2 border-t border-white/[0.06] px-5 py-3.5', narrow && 'lg:justify-center lg:px-0')}>
        <Link
          to="/health"
          className={cn('flex min-w-0 items-center gap-2 text-[13px] text-muted-foreground transition-colors hover:text-foreground', narrow && 'lg:hidden')}
        >
          <StatusDot tone={sensorRows.length && healthyCount === sensorRows.length ? 'success' : 'warning'} />
          <span className="num truncate">
            {sensorRows.length ? `${healthyCount}/${sensorRows.length} sensor hoạt động` : 'Chưa có sensor'}
          </span>
        </Link>
        <button
          type="button"
          onClick={onToggle}
          className="hidden size-8 shrink-0 items-center justify-center rounded-full text-subtle hover:bg-white/[0.07] hover:text-foreground lg:flex"
          aria-label={collapsed ? 'Mở rộng sidebar' : 'Thu gọn sidebar'}
          title={collapsed ? 'Mở rộng sidebar' : 'Thu gọn sidebar'}
        >
          {collapsed ? <ChevronsRight className="size-4" /> : <ChevronsLeft className="size-4" />}
        </button>
      </div>
    </aside>
  );
}

function Topbar({
  section,
  title,
  liveStatus,
  onMenu,
  onSearch,
}: {
  section?: string;
  title: string;
  liveStatus: LiveStatus;
  onMenu: () => void;
  onSearch: () => void;
}) {
  const { paused, setPaused } = usePolling();
  const lastUpdate = useLastUpdate();
  const meta = liveMeta[liveStatus];

  return (
    <header className="z-20 flex h-17 shrink-0 items-center gap-3 border-b border-white/[0.06] bg-transparent px-5 backdrop-blur-md md:px-10">
      <Button variant="ghost" size="icon" className="lg:hidden" onClick={onMenu} aria-label="Mở menu">
        <Menu />
      </Button>
      <div className="flex min-w-0 items-center gap-2 text-sm">
        {section && <span className="hidden text-subtle sm:inline">{section}</span>}
        {section && <span className="hidden text-border-strong sm:inline">/</span>}
        <span className="truncate font-medium text-foreground">{title}</span>
      </div>

      <div className="ml-auto flex items-center gap-2">
        <button
          type="button"
          onClick={onSearch}
          className="hidden h-9.5 w-72 items-center gap-2.5 rounded-full border border-border bg-white/[0.04] px-4 text-sm text-subtle transition-colors hover:border-border-strong hover:text-muted-foreground md:flex"
        >
          <Search className="size-4" />
          <span className="flex-1 text-left">Tìm trang, IP, event…</span>
          <kbd className="rounded-md bg-white/[0.07] px-1.5 py-0.5 font-sans text-[11px]">Ctrl K</kbd>
        </button>
        <Button variant="ghost" size="icon" className="md:hidden" onClick={onSearch} aria-label="Tìm kiếm">
          <Search />
        </Button>

        <Tip content={paused ? 'Tiếp tục tự động làm mới dữ liệu' : 'Tạm dừng tự động làm mới (WebSocket vẫn nhận sự kiện)'}>
          <Button variant={paused ? 'default' : 'outline'} size="icon" onClick={() => setPaused(!paused)} aria-label={paused ? 'Tiếp tục làm mới' : 'Tạm dừng làm mới'}>
            {paused ? <Play /> : <Pause />}
          </Button>
        </Tip>
        <Tip content={paused ? 'Đã tạm dừng làm mới dữ liệu' : `WebSocket /ws/events${lastUpdate ? ` · làm mới lúc ${lastUpdate}` : ''}`}>
          <span className="inline-flex h-10 items-center gap-2 rounded-full border border-border bg-white/[0.05] px-4 text-[13px] font-medium text-muted-foreground">
            <StatusDot tone={meta.tone} pulse={liveStatus === 'live'} />
            {meta.label}
          </span>
        </Tip>
      </div>
    </header>
  );
}

/** Wall-clock time of the most recent successful API refresh. */
function useLastUpdate() {
  const client = useQueryClient();
  const [last, setLast] = useState<string>('');
  useEffect(() => {
    return client.getQueryCache().subscribe((event) => {
      if (event.type === 'updated' && event.action.type === 'success') {
        setLast(new Date().toLocaleTimeString('vi-VN', { hour12: false }));
      }
    });
  }, [client]);
  return last;
}

class RouteErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  render() {
    if (this.state.error) {
      return (
        <EmptyState
          className="py-24"
          title="Trang gặp lỗi khi hiển thị"
          description={`${this.state.error.message}. Tải lại trang hoặc chuyển sang trang khác; dữ liệu backend không bị ảnh hưởng.`}
        />
      );
    }
    return this.props.children;
  }
}

function ScrollTopButton({ visible, onClick }: { visible: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label="Lên đầu trang"
      title="Lên đầu trang"
      tabIndex={visible ? 0 : -1}
      className={cn(
        'glass absolute right-6 bottom-6 z-30 flex size-11 items-center justify-center rounded-full text-foreground shadow-[0_8px_30px_rgb(0_0_0/0.45)] transition-all duration-200 hover:border-white/30 hover:bg-white/[0.14] md:right-10 md:bottom-8',
        visible ? 'translate-y-0 opacity-100' : 'pointer-events-none translate-y-3 opacity-0',
      )}
    >
      <ArrowUp className="size-5" />
    </button>
  );
}

function PageFallback() {
  return (
    <div className="mx-auto flex w-full max-w-[1560px] flex-col gap-7 px-5 py-6 md:px-10 md:py-9" aria-busy="true">
      <div className="flex flex-col gap-3">
        <Skeleton className="h-9 w-72" />
        <Skeleton className="h-4 w-[28rem] max-w-full" />
      </div>
      <Skeleton className="h-44 rounded-3xl" />
      <Skeleton className="h-80 rounded-3xl" />
    </div>
  );
}

export function NotFound() {
  return <EmptyState className="py-24" title="Không tìm thấy trang" description="Đường dẫn không tồn tại. Dùng menu bên trái hoặc Ctrl K để điều hướng." />;
}
