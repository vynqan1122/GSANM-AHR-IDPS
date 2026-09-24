import { useEffect, useState } from 'react';
import { getJson } from '../api/client';
import { useLiveEvents } from '../hooks/useLiveEvents';
import type { EventRow, Paged } from '../types/api';

function score(value: number | null | undefined) {
  return typeof value === 'number' ? value.toFixed(2) : '';
}

function risk(value: string | null | undefined) {
  return value ? value.toUpperCase() : '';
}

export function LiveEvents() {
  const live = useLiveEvents();
  const [initial, setInitial] = useState<EventRow[]>([]);

  useEffect(() => {
    getJson<Paged<EventRow>>('/api/events?page_size=25').then((data) => setInitial(data.items)).catch(() => setInitial([]));
  }, []);

  const rows = [...live, ...initial].slice(0, 30);
  return (
    <section className="table-shell">
      <h2>Live events</h2>
      <table>
        <thead>
          <tr>
            <th>Time</th><th>Source</th><th>Activity</th><th>Rule</th><th>Severity</th><th>Fusion score</th><th>Risk</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((event) => (
            <tr key={event.event_id}>
              <td>{event.timestamp}</td>
              <td>{event.source}</td>
              <td>{event.event_type}{event.container?.name ? ` · ${event.container.name}` : ''}</td>
              <td>{event.rule?.name ?? event.rule?.rule_id ?? ''}</td>
              <td>{event.severity ?? ''}</td>
              <td>{score(event.ai?.fusion_score)}</td>
              <td>{risk(event.ai?.risk_level)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
