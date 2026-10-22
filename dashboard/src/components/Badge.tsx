import React from 'react';

export type BadgeVariant =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'info'
  | 'success'
  | 'warning'
  | 'danger'
  | 'neutral'
  | 'purple'
  | 'cyan';

interface BadgeProps {
  children: React.ReactNode;
  variant?: BadgeVariant;
  size?: 'sm' | 'md';
  dot?: boolean;
  className?: string;
}

export function Badge({
  children,
  variant = 'neutral',
  size = 'md',
  dot = false,
  className = '',
}: BadgeProps) {
  return (
    <span className={`soc-badge badge-${variant} badge-${size} ${className}`}>
      {dot && <span className="badge-dot" />}
      {children}
    </span>
  );
}

export function severityVariant(severity: number | null | undefined): BadgeVariant {
  if (severity == null) return 'neutral';
  if (severity >= 8) return 'critical';
  if (severity >= 6) return 'high';
  if (severity >= 4) return 'medium';
  if (severity >= 2) return 'low';
  return 'info';
}

export function riskVariant(risk: number | string | null | undefined): BadgeVariant {
  if (risk == null) return 'neutral';
  if (typeof risk === 'number') {
    if (risk >= 0.8) return 'critical';
    if (risk >= 0.6) return 'high';
    if (risk >= 0.4) return 'medium';
    if (risk >= 0.2) return 'low';
    return 'success';
  }
  const r = risk.toLowerCase();
  if (r.includes('crit') || r.includes('high')) return 'critical';
  if (r.includes('med') || r.includes('warn')) return 'warning';
  if (r.includes('low') || r.includes('info')) return 'low';
  return 'success';
}

export function statusVariant(status: string | null | undefined): BadgeVariant {
  if (!status) return 'neutral';
  const s = status.toLowerCase();
  if (['healthy', 'up', 'active', 'completed', 'open'].includes(s)) return 'success';
  if (['shadow', 'investigating', 'warning', 'reporting'].includes(s)) return 'warning';
  if (['critical', 'danger', 'down', 'error', 'failed', 'rejected'].includes(s)) return 'critical';
  if (['candidate', 'registered', 'loaded'].includes(s)) return 'purple';
  return 'neutral';
}
