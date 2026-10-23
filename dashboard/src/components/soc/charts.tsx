import { useMemo } from 'react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { sourceMeta } from '@/lib/severity';
import type { TimeseriesPoint } from '@/types/api';

const axisProps = {
  stroke: 'var(--color-subtle)',
  fontSize: 12,
  tickLine: false,
  axisLine: false,
} as const;

interface TooltipEntry {
  name?: string | number;
  value?: number | string;
  color?: string;
  dataKey?: string | number;
}

function ChartTooltip({ active, payload, label, labelFormatter }: {
  active?: boolean;
  payload?: TooltipEntry[];
  label?: string | number;
  labelFormatter?: (label: string | number) => string;
}) {
  if (!active || !payload?.length) return null;
  const total = payload.reduce((sum, entry) => sum + Number(entry.value ?? 0), 0);
  return (
    <div className="min-w-40 rounded-lg border border-border bg-muted/95 px-3 py-2 text-xs shadow-xl backdrop-blur">
      <div className="mb-1.5 font-medium text-foreground">{labelFormatter && label !== undefined ? labelFormatter(label) : label}</div>
      {payload.map((entry) => (
        <div key={String(entry.dataKey)} className="flex items-center justify-between gap-4 py-0.5">
          <span className="flex items-center gap-1.5 text-muted-foreground">
            <span className="size-2 rounded-[3px]" style={{ background: entry.color }} />
            {entry.name}
          </span>
          <span className="num text-foreground">{Number(entry.value ?? 0).toLocaleString('vi-VN')}</span>
        </div>
      ))}
      {payload.length > 1 && (
        <div className="mt-1 flex justify-between border-t border-border pt-1 text-muted-foreground">
          <span>Tổng</span>
          <span className="num text-foreground">{total.toLocaleString('vi-VN')}</span>
        </div>
      )}
    </div>
  );
}

const hhmm = (value: string | number) =>
  new Date(String(value)).toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit', hour12: false });

/** Pivot backend {bucket, source, count} rows into one row per bucket. */
export function pivotTimeseries(points: TimeseriesPoint[]) {
  const sources = Array.from(new Set(points.map((point) => point.source))).sort();
  const buckets = new Map<string, Record<string, number | string>>();
  for (const point of points) {
    const row = buckets.get(point.bucket) ?? { bucket: point.bucket };
    row[point.source] = Number(row[point.source] ?? 0) + Number(point.count ?? 0);
    buckets.set(point.bucket, row);
  }
  const rows = Array.from(buckets.values())
    .sort((a, b) => String(a.bucket).localeCompare(String(b.bucket)))
    .map((row) => {
      for (const source of sources) row[source] = Number(row[source] ?? 0);
      return row;
    });
  return { sources, rows };
}

export function EventsAreaChart({ points, height = 260 }: { points: TimeseriesPoint[]; height?: number }) {
  const { sources, rows } = useMemo(() => pivotTimeseries(points), [points]);
  if (!rows.length) {
    return (
      <div className="flex items-center justify-center text-xs text-muted-foreground" style={{ height }}>
        Chưa có sự kiện trong 60 phút gần nhất.
      </div>
    );
  }
  return (
    <div>
      <div className="mb-3 flex flex-wrap gap-x-4 gap-y-1 px-1">
        {sources.map((source) => (
          <span key={source} className="flex items-center gap-2 text-[13px] text-muted-foreground">
            <span className="size-2 rounded-[3px]" style={{ background: sourceMeta(source).color }} />
            {sourceMeta(source).label}
          </span>
        ))}
      </div>
      <ResponsiveContainer width="100%" height={height}>
        <AreaChart data={rows} margin={{ top: 4, right: 8, left: -12, bottom: 0 }}>
          <defs>
            {sources.map((source) => (
              <linearGradient key={source} id={`area-${source}`} x1="0" x2="0" y1="0" y2="1">
                <stop offset="0%" stopColor={sourceMeta(source).color} stopOpacity={0.35} />
                <stop offset="100%" stopColor={sourceMeta(source).color} stopOpacity={0.02} />
              </linearGradient>
            ))}
          </defs>
          <CartesianGrid stroke="var(--color-border)" strokeDasharray="3 4" vertical={false} />
          <XAxis dataKey="bucket" tickFormatter={hhmm} minTickGap={36} {...axisProps} />
          <YAxis allowDecimals={false} width={44} {...axisProps} />
          <Tooltip content={<ChartTooltip labelFormatter={hhmm} />} cursor={{ stroke: 'var(--color-border-strong)' }} />
          {sources.map((source) => (
            <Area
              key={source}
              type="monotone"
              dataKey={source}
              name={sourceMeta(source).label}
              stackId="events"
              stroke={sourceMeta(source).color}
              strokeWidth={2}
              fill={`url(#area-${source})`}
              isAnimationActive={false}
            />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

export function SimpleBarChart({
  data,
  height = 220,
  color = 'var(--color-primary)',
  valueLabel,
}: {
  data: Array<{ label: string; value: number; color?: string }>;
  height?: number;
  color?: string;
  valueLabel: string;
}) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 4, right: 8, left: -12, bottom: 0 }}>
        <CartesianGrid stroke="var(--color-border)" strokeDasharray="3 4" vertical={false} />
        <XAxis dataKey="label" {...axisProps} />
        <YAxis allowDecimals={false} width={44} {...axisProps} />
        <Tooltip content={<ChartTooltip />} cursor={{ fill: 'var(--color-hover)', opacity: 0.5 }} />
        <Bar dataKey="value" name={valueLabel} fill={color} radius={[4, 4, 0, 0]} isAnimationActive={false}>
          {data.map((item) => (
            <Cell key={item.label} fill={item.color ?? color} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
