import { useEffect, useState } from 'react';
import { getJson, postJson } from '../api/client';
import type { AlertRow, ContainerRow, EventRow, ExperimentRow, ModelRow, Paged, SensorRow } from '../types/api';

const val = (x: unknown) => x === undefined || x === null ? '' : String(x);
const pct = (x: unknown) => typeof x === 'number' ? x.toFixed(3) : '';

export function AlertsPage() {
  const [rows, setRows] = useState<AlertRow[]>([]);
  useEffect(() => { getJson<Paged<AlertRow>>('/api/alerts?page_size=25').then((d) => setRows(d.items)).catch(() => setRows([])); }, []);
  return <section className="table-shell"><h2>Alerts</h2><table><thead><tr><th>Time</th><th>Source</th><th>Rule</th><th>Severity</th><th>Src</th><th>Dst</th><th>Incident</th><th>Status</th></tr></thead><tbody>{rows.map((r) => <tr key={r.alert_id}><td>{r.timestamp}</td><td>{r.source}</td><td>{r.title ?? r.rule_id}</td><td>{r.severity}</td><td>{r.src_ip}</td><td>{r.dst_ip}</td><td></td><td>{r.status}</td></tr>)}</tbody></table></section>;
}

export function AttackGraphPage() {
  const [data, setData] = useState<any>(null);
  useEffect(() => { getJson<Paged<any>>('/api/incidents?page_size=1').then(async (d) => d.items[0] && setData(await getJson(`/api/incidents/${d.items[0].incident_id}`))).catch(() => setData(null)); }, []);
  const nodes = data?.attack_graph?.nodes ?? [];
  const edges = data?.attack_graph?.edges ?? [];
  return <section className="table-shell"><h2>Attack Graph</h2><p>Filters: time · node type · risk · incident</p><p>Nodes: {nodes.length} · Edges: {edges.length}</p><pre>{JSON.stringify({ nodes: nodes.slice(0, 8), edges: edges.slice(0, 8) }, null, 2)}</pre></section>;
}

export function NetworkPage() {
  const [data, setData] = useState<any>(null);
  useEffect(() => { getJson('/api/network/summary').then(setData).catch(() => setData(null)); }, []);
  return <section className="table-shell"><h2>Network</h2><p>Flows/sec: {pct(data?.summary?.flows_per_sec)} · Bytes/sec: {pct(data?.summary?.bytes_per_sec)} · Suricata alerts: {val(data?.summary?.suricata_alerts)}</p><pre>{JSON.stringify({ protocols: data?.protocols, top_sources: data?.top_sources, top_destinations: data?.top_destinations, top_destination_ports: data?.top_destination_ports }, null, 2)}</pre></section>;
}

export function ContainersPage() {
  const [rows, setRows] = useState<ContainerRow[]>([]);
  useEffect(() => { getJson<{items: ContainerRow[]}>('/api/containers').then((d) => setRows(d.items)).catch(() => setRows([])); }, []);
  return <section className="table-shell"><h2>Containers</h2><table><thead><tr><th>Name</th><th>Image</th><th>Status</th><th>CPU</th><th>RAM</th><th>RX</th><th>TX</th><th>Process count</th><th>Falco alerts</th><th>Risk</th></tr></thead><tbody>{rows.map((r) => <tr key={r.name}><td>{r.name}</td><td>{r.image}</td><td>observed</td><td>n/a</td><td>n/a</td><td>n/a</td><td>n/a</td><td>n/a</td><td>{r.falco_alert_count ?? 0}</td><td>{pct(r.current_risk)}</td></tr>)}</tbody></table></section>;
}

export function AIMonitorPage() {
  const [rows, setRows] = useState<ModelRow[]>([]);
  useEffect(() => { getJson<{items: ModelRow[]}>('/api/models').then((d) => setRows(d.items)).catch(() => setRows([])); }, []);
  return <section className="table-shell"><h2>AI Monitor</h2><table><thead><tr><th>Model</th><th>Version</th><th>Status</th><th>Latency</th><th>Throughput</th><th>Precision</th><th>Recall</th><th>F1</th><th>FPR</th><th>ROC-AUC</th><th>PR-AUC</th></tr></thead><tbody>{rows.map((m) => <tr key={m.model_id}><td>{m.name}</td><td>{m.version}</td><td>{m.status}</td><td>{val((m.artifact_metrics as any)?.latency_ms)}</td><td>{val((m.artifact_metrics as any)?.throughput_eps)}</td><td>{pct((m.artifact_metrics as any)?.precision)}</td><td>{pct((m.artifact_metrics as any)?.recall)}</td><td>{pct((m.artifact_metrics as any)?.f1)}</td><td>{pct((m.artifact_metrics as any)?.fpr)}</td><td>{pct((m.artifact_metrics as any)?.roc_auc)}</td><td>{pct((m.artifact_metrics as any)?.pr_auc)}</td></tr>)}</tbody></table><p>Score exploration: distributions, attack-vs-benign, FP/FN, confidence histogram.</p></section>;
}

export function ExperimentsPage() {
  const [rows, setRows] = useState<ExperimentRow[]>([]);
  const [path, setPath] = useState('');
  const load = () => getJson<{items: ExperimentRow[]}>('/api/experiments').then((d) => setRows(d.items)).catch(() => setRows([]));
  useEffect(() => { load(); }, []);
  const run = async () => { try { const result = await postJson<any>('/api/experiments/run'); setPath(result.results_path); await load(); } catch { setPath('experiment run unavailable'); } };
  return <section className="table-shell"><h2>Experiments</h2><button onClick={run}>Run ablation E1–E9</button><p>Results CSV: {path || rows[0]?.results_path || 'not generated yet'}</p><table><thead><tr><th>ID</th><th>Name</th><th>Precision</th><th>Recall</th><th>F1</th><th>FPR</th></tr></thead><tbody>{rows.map((r) => <tr key={r.experiment_id}><td>{r.experiment_id}</td><td>{r.name}</td><td>{pct(r.metrics?.precision)}</td><td>{pct(r.metrics?.recall)}</td><td>{pct(r.metrics?.f1)}</td><td>{pct(r.metrics?.fpr)}</td></tr>)}</tbody></table><p>Unknown attack before/after generated-rule effectiveness is exported with recall, FPR, latency, rule coverage, and AI inference requirement.</p></section>;
}

export function SystemHealthPage() {
  const [data, setData] = useState<any>(null);
  useEffect(() => { const load = () => getJson('/api/system/health').then(setData).catch(() => setData({ overall: 'degraded', services: {} })); load(); const t = window.setInterval(load, 10000); return () => window.clearInterval(t); }, []);
  return <section className="table-shell"><h2>System Health</h2><p>Overall: {data?.overall}</p><pre>{JSON.stringify(data?.services ?? {}, null, 2)}</pre></section>;
}

export function WazuhManagerPage() {
  const [sensors, setSensors] = useState<SensorRow[]>([]);
  const [events, setEvents] = useState<EventRow[]>([]);
  const wazuh = sensors.find((row) => row.sensor === 'wazuh');

  useEffect(() => {
    const load = () => {
      getJson<Paged<SensorRow>>('/api/sensors').then((data) => setSensors(data.items)).catch(() => setSensors([]));
      getJson<Paged<EventRow>>('/api/events?source=wazuh&page_size=12').then((data) => setEvents(data.items)).catch(() => setEvents([]));
    };
    load();
    const timer = window.setInterval(load, 10000);
    return () => window.clearInterval(timer);
  }, []);

  return (
    <section className="table-shell">
      <h2>Wazuh Manager</h2>
      <p>Status: {wazuh?.status ?? 'unknown'} · Last event: {wazuh?.last_event_at ?? 'unknown'}</p>
      <table>
        <thead><tr><th>Time</th><th>Rule</th><th>Severity</th><th>Container</th></tr></thead>
        <tbody>{events.map((event) => <tr key={event.event_id}>
          <td>{event.timestamp}</td><td>{event.rule?.name ?? event.rule?.rule_id ?? ''}</td><td>{event.severity ?? ''}</td><td>{event.container?.name ?? ''}</td>
        </tr>)}</tbody>
      </table>
    </section>
  );
}

export function SettingsPage() {
  return <section className="table-shell"><h2>Settings</h2><p>Resource profiles: light · normal · research. GPU target: RTX 3060 12GB with lazy loading, batch inference, torch.inference_mode, mixed precision where appropriate, and model unload controls at service layer.</p><p>Security: DVWA local-only, restricted CORS-ready API, allowlisted response actions, parameterized SQL, no arbitrary shell/firewall/Docker command API.</p></section>;
}
