import { useEffect, useState } from 'react';
import { getJson } from '../api/client';
import type { Paged, ResponseRow } from '../types/api';
import { formatTime } from '../utils/format';

function pct(value: number | null | undefined) {
  return typeof value === 'number' ? `${Math.round(value * 100)}%` : '';
}

export function Responses() {
  const [responses, setResponses] = useState<ResponseRow[]>([]);
  useEffect(() => {
    const load = () => getJson<Paged<ResponseRow>>('/api/responses?page_size=25').then((data) => setResponses(data.items)).catch(() => setResponses([]));
    load();
    const timer = window.setInterval(load, 15000);
    return () => window.clearInterval(timer);
  }, []);

  return (
    <section className="table-shell">
      <h2>Responses</h2>
      <table>
        <thead>
          <tr><th>Time</th><th>Incident</th><th>Action</th><th>Target</th><th>Reason</th><th>Risk</th><th>Status</th><th>Expires</th><th>Rollback</th><th>Evidence</th></tr>
        </thead>
        <tbody>
          {responses.map((response) => (
            <tr key={response.response_id}>
              <td>{formatTime(response.started_at)}</td>
              <td>{response.incident_id}</td>
              <td>{response.action}</td>
              <td>{response.target ?? ''}</td>
              <td>{response.reason ?? ''}</td>
              <td>{pct(response.risk)}</td>
              <td>{response.status}</td>
              <td>{response.expires_at ? formatTime(response.expires_at) : ''}</td>
              <td>{response.rollback_status ?? ''}</td>
              <td>{response.evidence_file_count ? `${response.evidence_file_count} files` : ''}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p>Default response mode is alert-only. Temporary lab blocks and isolation are allowlisted, tagged, expiring, rollbackable, and never delete containers, volumes, or logs.</p>
    </section>
  );
}
