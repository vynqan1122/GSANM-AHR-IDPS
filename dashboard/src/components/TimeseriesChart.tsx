import { useState, useId } from 'react';
import type { TimeseriesPoint } from '../types/api';

interface TimeseriesChartProps {
  data: TimeseriesPoint[];
  height?: number;
  title?: string;
}

const SOURCE_COLORS: Record<string, { stroke: string; fill: string; label: string }> = {
  suricata: { stroke: '#38BDF8', fill: 'rgba(56, 189, 248, 0.2)', label: 'Suricata (Network)' },
  falco: { stroke: '#F59E0B', fill: 'rgba(245, 158, 11, 0.2)', label: 'Falco (Runtime)' },
  wazuh: { stroke: '#10B981', fill: 'rgba(16, 185, 129, 0.2)', label: 'Wazuh (Host/SIEM)' },
  nginx: { stroke: '#A855F7', fill: 'rgba(168, 85, 247, 0.2)', label: 'Nginx (HTTP)' },
  other: { stroke: '#94A3B8', fill: 'rgba(148, 163, 184, 0.2)', label: 'Khác' },
};

export function TimeseriesChart({ data, height = 220, title }: TimeseriesChartProps) {
  const chartId = useId().replace(/:/g, '');
  const [hoverIndex, setHoverIndex] = useState<number | null>(null);

  // Group data by bucket timestamp
  const bucketMap = new Map<string, Record<string, number>>();
  const sourcesSet = new Set<string>();

  data.forEach((p) => {
    const timeKey = p.bucket;
    if (!bucketMap.has(timeKey)) {
      bucketMap.set(timeKey, {});
    }
    const current = bucketMap.get(timeKey)!;
    current[p.source] = (current[p.source] || 0) + Number(p.count || 0);
    sourcesSet.add(p.source);
  });

  const buckets = Array.from(bucketMap.keys()).sort();
  const sources = Array.from(sourcesSet);

  if (buckets.length === 0) {
    return (
      <div className="soc-chart-card">
        {title && <h3 className="chart-card-title">{title}</h3>}
        <div className="chart-empty">Đang thu thập dữ liệu chuỗi thời gian...</div>
      </div>
    );
  }

  // Find max value
  let maxTotal = 1;
  const totalsByBucket = buckets.map((b) => {
    const counts = bucketMap.get(b)!;
    const sum = Object.values(counts).reduce((a, b) => a + b, 0);
    if (sum > maxTotal) maxTotal = sum;
    return sum;
  });

  const paddingLeft = 45;
  const paddingRight = 20;
  const paddingTop = 20;
  const paddingBottom = 30;
  const width = 680;

  const innerWidth = width - paddingLeft - paddingRight;
  const innerHeight = height - paddingTop - paddingBottom;

  const getX = (index: number) => {
    if (buckets.length <= 1) return paddingLeft + innerWidth / 2;
    return paddingLeft + (index / (buckets.length - 1)) * innerWidth;
  };

  const getY = (val: number) => {
    return paddingTop + innerHeight - (val / (maxTotal * 1.15)) * innerHeight;
  };

  // Generate paths for overall or primary sources
  const points = buckets.map((b, i) => {
    const total = totalsByBucket[i];
    return { x: getX(i), y: getY(total), total, time: b };
  });

  const lineD = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join(' ');
  const areaD = `${lineD} L ${points[points.length - 1].x.toFixed(1)} ${(paddingTop + innerHeight).toFixed(1)} L ${points[0].x.toFixed(1)} ${(paddingTop + innerHeight).toFixed(1)} Z`;

  // Format time label for x-axis
  const formatTimeLabel = (iso: string) => {
    try {
      const d = new Date(iso);
      return `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`;
    } catch {
      return iso.slice(11, 16);
    }
  };

  return (
    <div className="soc-chart-card">
      <div className="chart-card-header">
        {title && <h3 className="chart-card-title">{title}</h3>}
        <div className="chart-legend">
          {sources.map((s) => {
            const cfg = SOURCE_COLORS[s] || SOURCE_COLORS.other;
            return (
              <span key={s} className="legend-item">
                <span className="legend-dot" style={{ backgroundColor: cfg.stroke }} />
                {cfg.label}
              </span>
            );
          })}
        </div>
      </div>

      <div className="chart-svg-wrap">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          className="timeseries-svg"
          preserveAspectRatio="none"
          onMouseLeave={() => setHoverIndex(null)}
        >
          <defs>
            <linearGradient id={`areaGrad-${chartId}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#38BDF8" stopOpacity="0.4" />
              <stop offset="90%" stopColor="#38BDF8" stopOpacity="0.0" />
            </linearGradient>
            <linearGradient id={`lineGrad-${chartId}`} x1="0" y1="0" x2="1" y2="0">
              <stop offset="0%" stopColor="#06B6D4" />
              <stop offset="100%" stopColor="#38BDF8" />
            </linearGradient>
          </defs>

          {/* Grid lines */}
          {[0, 0.25, 0.5, 0.75, 1].map((pct, idx) => {
            const y = paddingTop + innerHeight * (1 - pct);
            const val = Math.round(maxTotal * 1.15 * pct);
            return (
              <g key={idx}>
                <line
                  x1={paddingLeft}
                  y1={y}
                  x2={width - paddingRight}
                  y2={y}
                  stroke="#1E293B"
                  strokeDasharray="3 3"
                />
                <text x={paddingLeft - 8} y={y + 3} fill="#64748B" fontSize="10" textAnchor="end">
                  {val}
                </text>
              </g>
            );
          })}

          {/* Area fill */}
          <path d={areaD} fill={`url(#areaGrad-${chartId})`} />

          {/* Trend line */}
          <path
            d={lineD}
            fill="none"
            stroke={`url(#lineGrad-${chartId})`}
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
          />

          {/* Data points & hover triggers */}
          {points.map((p, idx) => (
            <g
              key={idx}
              onMouseEnter={() => setHoverIndex(idx)}
              style={{ cursor: 'pointer' }}
            >
              {/* Invisible wide hit area */}
              <rect
                x={p.x - 12}
                y={paddingTop}
                width={24}
                height={innerHeight}
                fill="transparent"
              />
              {/* Visible dot */}
              <circle
                cx={p.x}
                cy={p.y}
                r={hoverIndex === idx ? 5 : 2.5}
                fill="#38BDF8"
                stroke="#0F172A"
                strokeWidth={hoverIndex === idx ? 2 : 1}
              />
            </g>
          ))}

          {/* Active scrubber line */}
          {hoverIndex !== null && points[hoverIndex] && (
            <line
              x1={points[hoverIndex].x}
              y1={paddingTop}
              x2={points[hoverIndex].x}
              y2={paddingTop + innerHeight}
              stroke="#38BDF8"
              strokeDasharray="2 2"
              strokeWidth="1.5"
            />
          )}

          {/* X Axis labels */}
          {points.filter((_, i) => i === 0 || i === Math.floor(points.length / 2) || i === points.length - 1).map((p, i) => (
            <text
              key={i}
              x={p.x}
              y={height - 8}
              fill="#94A3B8"
              fontSize="10"
              textAnchor={i === 0 ? 'start' : i === 2 ? 'end' : 'middle'}
            >
              {formatTimeLabel(p.time)}
            </text>
          ))}
        </svg>

        {/* Hover Tooltip Overlay */}
        {hoverIndex !== null && points[hoverIndex] && (
          <div
            className="chart-tooltip"
            style={{
              left: `${(points[hoverIndex].x / width) * 100}%`,
              top: `${(points[hoverIndex].y / height) * 100}%`,
            }}
          >
            <div className="tooltip-time">{formatTimeLabel(points[hoverIndex].time)}</div>
            <div className="tooltip-val">
              <strong>{points[hoverIndex].total}</strong> sự kiện
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
