import React from 'react';

export type StatCardVariant = 'cyan' | 'emerald' | 'amber' | 'rose' | 'violet' | 'slate';

interface StatCardProps {
  label: string;
  value: string | number;
  subtext?: string;
  icon?: React.ReactNode;
  trend?: {
    value: string;
    isUp?: boolean;
    isPositive?: boolean;
  };
  variant?: StatCardVariant;
  badge?: string;
  onClick?: () => void;
}

export function StatCard({
  label,
  value,
  subtext,
  icon,
  trend,
  variant = 'cyan',
  badge,
  onClick,
}: StatCardProps) {
  return (
    <div
      className={`soc-stat-card card-variant-${variant} ${onClick ? 'clickable' : ''}`}
      onClick={onClick}
    >
      <div className="stat-card-header">
        <span className="stat-card-label">{label}</span>
        {icon && <div className="stat-card-icon-wrapper">{icon}</div>}
      </div>

      <div className="stat-card-body">
        <div className="stat-card-value">{value}</div>
        {badge && <span className="stat-card-pill">{badge}</span>}
      </div>

      {(subtext || trend) && (
        <div className="stat-card-footer">
          {trend && (
            <span
              className={`stat-card-trend ${
                trend.isPositive !== false ? 'trend-good' : 'trend-warn'
              }`}
            >
              {trend.isUp ? '↑' : '↓'} {trend.value}
            </span>
          )}
          {subtext && <span className="stat-card-subtext">{subtext}</span>}
        </div>
      )}
    </div>
  );
}
