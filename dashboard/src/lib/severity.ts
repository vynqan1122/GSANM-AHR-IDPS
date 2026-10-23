/** One mapping from backend severity/risk/status values to UI tones. */
export type Tone = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'success' | 'warning' | 'neutral' | 'primary';

export const toneText: Record<Tone, string> = {
  critical: 'text-sev-critical',
  high: 'text-sev-high',
  medium: 'text-sev-medium',
  low: 'text-sev-low',
  info: 'text-sev-info',
  success: 'text-success',
  warning: 'text-warning',
  neutral: 'text-muted-foreground',
  primary: 'text-primary',
};

export const toneBg: Record<Tone, string> = {
  critical: 'bg-sev-critical',
  high: 'bg-sev-high',
  medium: 'bg-sev-medium',
  low: 'bg-sev-low',
  info: 'bg-sev-info',
  success: 'bg-success',
  warning: 'bg-warning',
  neutral: 'bg-subtle',
  primary: 'bg-primary',
};

export const toneSoft: Record<Tone, string> = {
  critical: 'bg-sev-critical/12 text-sev-critical ring-sev-critical/25',
  high: 'bg-sev-high/12 text-sev-high ring-sev-high/25',
  medium: 'bg-sev-medium/12 text-sev-medium ring-sev-medium/25',
  low: 'bg-sev-low/12 text-sev-low ring-sev-low/25',
  info: 'bg-sev-info/12 text-sev-info ring-sev-info/20',
  success: 'bg-success/12 text-success ring-success/25',
  warning: 'bg-warning/12 text-warning ring-warning/25',
  neutral: 'bg-muted text-muted-foreground ring-border',
  primary: 'bg-primary/12 text-primary ring-primary/25',
};

/** CSS color for charts and SVG, matching the Tailwind tokens. */
export const toneColor: Record<Tone, string> = {
  critical: 'var(--color-sev-critical)',
  high: 'var(--color-sev-high)',
  medium: 'var(--color-sev-medium)',
  low: 'var(--color-sev-low)',
  info: 'var(--color-sev-info)',
  success: 'var(--color-success)',
  warning: 'var(--color-warning)',
  neutral: 'var(--color-subtle)',
  primary: 'var(--color-primary)',
};

const toneLabel: Partial<Record<Tone, string>> = {
  critical: 'Nghiêm trọng',
  high: 'Cao',
  medium: 'Trung bình',
  low: 'Thấp',
  info: 'Thông tin',
};

/** Severity is reported on a 1–10 scale by the normalizer. */
export function severityTone(severity: number | null | undefined): Tone {
  if (severity == null) return 'neutral';
  if (severity >= 8) return 'critical';
  if (severity >= 6) return 'high';
  if (severity >= 4) return 'medium';
  if (severity >= 2) return 'low';
  return 'info';
}

export function scoreTone(score: number | null | undefined): Tone {
  if (score == null || !Number.isFinite(score)) return 'neutral';
  if (score >= 0.8) return 'critical';
  if (score >= 0.6) return 'high';
  if (score >= 0.4) return 'medium';
  if (score >= 0.2) return 'low';
  return 'info';
}

export function riskTone(level: string | number | null | undefined): Tone {
  if (level == null) return 'neutral';
  if (typeof level === 'number') return scoreTone(level);
  const value = level.toLowerCase();
  if (value.includes('crit')) return 'critical';
  if (value.includes('high')) return 'high';
  if (value.includes('med')) return 'medium';
  if (value.includes('low')) return 'low';
  return 'info';
}

export function riskLabel(level: string | null | undefined) {
  if (!level) return '—';
  return toneLabel[riskTone(level)] ?? level;
}

export function severityLabel(severity: number | null | undefined) {
  if (severity == null) return '—';
  return toneLabel[severityTone(severity)] ?? String(severity);
}

const healthyStatuses = ['healthy', 'up', 'running', 'reporting', 'active', 'completed', 'idle', 'not_required'];
const warningStatuses = ['stale', 'unknown', 'degraded', 'shadow', 'investigating', 'pending', 'new', 'open', 'registered'];
const badStatuses = ['down', 'error', 'failed', 'critical', 'rejected', 'unhealthy'];

export function statusTone(status: string | null | undefined): Tone {
  if (!status) return 'neutral';
  const value = status.toLowerCase();
  if (value === 'candidate') return 'primary';
  if (healthyStatuses.includes(value)) return 'success';
  if (badStatuses.includes(value)) return 'critical';
  if (warningStatuses.includes(value)) return 'warning';
  return 'neutral';
}

export const isHealthy = (status: string | null | undefined) => statusTone(status) === 'success';

export interface SourceMeta {
  label: string;
  color: string;
  dot: string;
}

const SOURCES: Record<string, SourceMeta> = {
  suricata: { label: 'Suricata', color: 'var(--color-src-suricata)', dot: 'bg-src-suricata' },
  falco: { label: 'Falco', color: 'var(--color-src-falco)', dot: 'bg-src-falco' },
  wazuh: { label: 'Wazuh', color: 'var(--color-src-wazuh)', dot: 'bg-src-wazuh' },
  nginx: { label: 'Nginx', color: 'var(--color-src-nginx)', dot: 'bg-src-nginx' },
  docker: { label: 'Docker', color: 'var(--color-src-docker)', dot: 'bg-src-docker' },
};

export function sourceMeta(source: string | null | undefined): SourceMeta {
  const key = (source ?? '').toLowerCase();
  return SOURCES[key] ?? {
    label: source || 'Không rõ',
    color: 'var(--color-src-other)',
    dot: 'bg-src-other',
  };
}

export const KNOWN_SOURCES = Object.keys(SOURCES);
