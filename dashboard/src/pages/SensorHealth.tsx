import { useEffect, useState } from 'react';
import { getJson } from '../api/client';
import type { Paged, SensorRow } from '../types/api';

export function SensorHealth() {
  const [data, setData] = useState<Paged<SensorRow> | null>(null);
  useEffect(() => {
    const load = () => getJson<Paged<SensorRow>>('/api/sensors').then(setData).catch(() => setData({ items: [], total: 0, page: 1, page_size: 50 }));
    load();
    const timer = window.setInterval(load, 5000);
    return () => window.clearInterval(timer);
  }, []);

  return (
    <section className="table-shell">
      <h2>Sensor health</h2>
      <table>
        <thead><tr><th>Sensor</th><th>Status</th><th>Last event</th><th>Error count</th></tr></thead>
        <tbody>
          {(data?.items ?? []).map((sensor) => (
            <tr key={sensor.sensor}>
              <td>{sensor.sensor}</td>
              <td>{sensor.status}</td>
              <td>{sensor.last_event_at ?? ''}</td>
              <td>{sensor.error_count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
