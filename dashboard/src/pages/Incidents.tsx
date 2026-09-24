import { useEffect, useState } from 'react';
import { getJson } from '../api/client';
import { AttackGraph } from '../components/AttackGraph';
import type { IncidentRow, Paged } from '../types/api';

function text(value: unknown) {
  return value === undefined || value === null ? '' : String(value);
}

function score(value: number | null | undefined) {
  return typeof value === 'number' ? value.toFixed(2) : '';
}

function duration(start: string, end: string) {
  const ms = new Date(end).getTime() - new Date(start).getTime();
  if (!Number.isFinite(ms) || ms < 0) return '';
  return `${Math.round(ms / 1000)}s`;
}

export function Incidents() {
  const [incidents, setIncidents] = useState<IncidentRow[]>([]);
  const [selected, setSelected] = useState<IncidentRow | null>(null);

  useEffect(() => {
    const load = async () => {
      try {
        const data = await getJson<Paged<IncidentRow>>('/api/incidents?page_size=25');
        setIncidents(data.items);
        if (data.items[0]) {
          setSelected((current) => current ?? data.items[0]);
        }
      } catch {
        setIncidents([]);
      }
    };
    load();
    const timer = window.setInterval(load, 10000);
    return () => window.clearInterval(timer);
  }, []);

  const openIncident = async (incidentId: string) => {
    try {
      setSelected(await getJson<IncidentRow>(`/api/incidents/${incidentId}`));
    } catch {
      setSelected(null);
    }
  };

  return (
    <section className="table-shell">
      <h2>Incidents</h2>
      <table>
        <thead>
          <tr><th>ID</th><th>Start</th><th>Duration</th><th>Source</th><th>Target</th><th>Risk</th><th>Attack Type</th><th>Events</th><th>Status</th></tr>
        </thead>
        <tbody>
          {incidents.map((incident) => (
            <tr key={incident.incident_id} onClick={() => openIncident(incident.incident_id)}>
              <td>{incident.incident_id.slice(0, 12)}</td>
              <td>{incident.first_seen}</td>
              <td>{duration(incident.first_seen, incident.last_seen)}</td>
              <td>{text(incident.source_ips?.join(', '))}</td>
              <td>{text(incident.targets?.join(', '))}</td>
              <td>{score(incident.risk_score)}</td>
              <td>{text(incident.attack_type)}</td>
              <td>{incident.event_count}</td>
              <td>{text(incident.status).toUpperCase()}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {selected && (
        <article className="incident-detail">
          <h2>Incident detail</h2>
          <p>{selected.title}</p>
          <p>Timeline events: {selected.timeline?.length ?? 0} · Attack graph edges: {selected.attack_graph?.edges?.length ?? 0}</p>
          <AttackGraph graph={selected.attack_graph} />
          <pre>{JSON.stringify({
            ai_summary: selected.ai_summary,
            rule_summary: selected.rule_summary,
            evidence_events: selected.events?.length ?? 0,
          }, null, 2)}</pre>
        </article>
      )}
    </section>
  );
}
