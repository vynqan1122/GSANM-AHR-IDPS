import { useEffect, useState } from 'react';
import { getJson } from '../api/client';
import { BarList } from '../charts/BarList';
import { StatCard } from '../components/StatCard';
import type { Paged, SensorRow } from '../types/api';

interface OverviewData {
  cards: Record<string, number>;
  events_by_source: Array<{ source: string; count: number }>;
  alerts_by_severity: Array<{ severity: number; count: number }>;
  top_source_ips: Array<{ src_ip: string; count: number }>;
  top_event_types: Array<{ event_type: string; count: number }>;
}

export function Overview() {
  const [overview, setOverview] = useState<OverviewData | null>(null);
  const [sensors, setSensors] = useState<Paged<SensorRow> | null>(null);

  useEffect(() => {
    const load = () => {
      getJson<OverviewData>('/api/dashboard/overview').then(setOverview).catch(() => setOverview(null));
      getJson<Paged<SensorRow>>('/api/sensors').then(setSensors).catch(() => setSensors(null));
    };
    load();
    const timer = window.setInterval(load, 5000);
    return () => window.clearInterval(timer);
  }, []);

  const reportingSensors = (sensors?.items ?? []).filter((item) =>
    ['healthy', 'reporting'].includes(item.status),
  ).length;

  return (
    <main>
      <div className="cards">
        <StatCard label="Security status" value={overview?.cards.critical_alerts ? 'Needs review' : 'Monitoring'} />
        <StatCard label="Events/min" value={overview?.cards.events_per_min ?? 0} />
        <StatCard label="Active Alerts" value={overview?.cards.active_alerts ?? 0} />
        <StatCard label="Reporting sensors" value={`${reportingSensors}/${sensors?.items.length ?? 0}`} />
      </div>
      <section className="grid">
        <article><h2>Events by source</h2><BarList items={(overview?.events_by_source ?? []).map((x) => ({ label: x.source, value: x.count }))} /></article>
        <article><h2>Alerts by severity</h2><BarList items={(overview?.alerts_by_severity ?? []).map((x) => ({ label: String(x.severity), value: x.count }))} /></article>
      </section>
    </main>
  );
}
