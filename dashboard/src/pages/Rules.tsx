import { useEffect, useState } from 'react';
import { getJson } from '../api/client';
import type { Paged, RuleRow } from '../types/api';

function score(value: number | null | undefined) {
  return typeof value === 'number' ? value.toFixed(2) : '';
}

export function Rules() {
  const [rules, setRules] = useState<RuleRow[]>([]);
  useEffect(() => {
    const load = () => getJson<Paged<RuleRow>>('/api/rules?source=generated&page_size=25').then((data) => setRules(data.items)).catch(() => setRules([]));
    load();
    const timer = window.setInterval(load, 15000);
    return () => window.clearInterval(timer);
  }, []);

  return (
    <section className="table-shell">
      <h2>Generated rules</h2>
      <table>
        <thead>
          <tr><th>ID</th><th>Engine</th><th>Status</th><th>Support</th><th>Precision</th><th>Recall</th><th>FPR</th><th>Matches</th><th>Version gate</th></tr>
        </thead>
        <tbody>
          {rules.map((rule) => (
            <tr key={rule.rule_id}>
              <td>{rule.rule_id}</td>
              <td>{rule.engine}</td>
              <td>{rule.status.toUpperCase()}</td>
              <td>{rule.support ?? ''}</td>
              <td>{score(rule.validation_replay_metrics?.precision)}</td>
              <td>{score(rule.validation_replay_metrics?.recall)}</td>
              <td>{score(rule.validation_replay_metrics?.fpr)}</td>
              <td>{rule.validation_replay_metrics?.match_count ?? ''}</td>
              <td>{rule.promotion_requires_approval ? 'Manual approval' : 'Auto disabled'}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p>Generated rules are candidate-only; validation/shadow/activation are separate lifecycle gates.</p>
    </section>
  );
}
