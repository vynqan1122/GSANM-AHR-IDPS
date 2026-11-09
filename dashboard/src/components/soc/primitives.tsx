import * as React from 'react';
import { AlertTriangle, Check, Copy, Inbox } from 'lucide-react';
import { cn } from '@/lib/utils';
import { fmtScore, isNum } from '@/lib/format';
import {
  riskLabel,
  riskTone,
  scoreTone,
  severityTone,
  sourceMeta,
  statusTone,
  toneBg,
  toneColor,
  type Tone,
} from '@/lib/severity';
import { Badge } from '@/components/ui/badge';
import { Tip } from '@/components/ui/overlays';

/* --------------------------------- Layout ---------------------------------- */

export function PageHeader({
  title,
  description,
  actions,
  eyebrow,
}: {
  title: React.ReactNode;
  description?: React.ReactNode;
  actions?: React.ReactNode;
  eyebrow?: string;
}) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-x-6 gap-y-3">
      <div className="min-w-0 max-w-3xl">
        {eyebrow && <div className="eyebrow mb-1">{eyebrow}</div>}
        <h1 className="text-[32px] leading-tight font-semibold tracking-[-0.025em] text-foreground">{title}</h1>
        {description && <p className="mt-2.5 text-[15px] leading-relaxed text-muted-foreground">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Page({ children, className }: { children: React.ReactNode; className?: string }) {
  return <div className={cn('mx-auto flex w-full max-w-[1560px] flex-col gap-7 px-5 py-6 md:px-10 md:py-9', className)}>{children}</div>;
}

export function SectionLabel({ children, className }: { children: React.ReactNode; className?: string }) {
  return <h4 className={cn('eyebrow mb-2', className)}>{children}</h4>;
}

/* ----------------------------------- KPI ----------------------------------- */

export function KpiCard({
  label,
  value,
  hint,
  tone = 'neutral',
  onClick,
  children,
}: {
  label: string;
  value: React.ReactNode;
  hint?: React.ReactNode;
  icon?: React.ReactNode;
  tone?: Tone;
  onClick?: () => void;
  children?: React.ReactNode;
}) {
  const Comp = onClick ? 'button' : 'div';
  return (
    <Comp
      type={onClick ? 'button' : undefined}
      onClick={onClick}
      className={cn(
        'glass flex min-w-0 flex-col gap-3.5 rounded-3xl p-6 text-left',
        onClick && 'cursor-pointer transition-colors hover:border-white/25',
      )}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="eyebrow truncate">{label}</span>
        <span className={cn('size-2 shrink-0 rounded-full', tone === 'neutral' ? 'bg-subtle/60' : toneBg[tone])} />
      </div>
      <div className="num text-[40px] leading-none font-semibold tracking-[-0.03em] text-foreground">{value}</div>
      {hint && <div className="truncate text-[13px] text-muted-foreground">{hint}</div>}
      {children}
    </Comp>
  );
}

export function MiniBar({ value, tone = 'primary' }: { value: number | null | undefined; tone?: Tone }) {
  const ratio = isNum(value) ? Math.min(1, Math.max(0, value)) : 0;
  return (
    <div className="mt-auto h-1.5 overflow-hidden rounded-full bg-white/[0.08]">
      <div className={cn('h-full rounded-full', toneBg[tone])} style={{ width: `${ratio * 100}%`, boxShadow: `0 0 10px ${toneColor[tone]}` }} />
    </div>
  );
}

/* ---------------------------------- Badges --------------------------------- */

export function StatusDot({ tone, pulse = false, className }: { tone: Tone; pulse?: boolean; className?: string }) {
  return (
    <span className={cn('relative inline-flex size-2 shrink-0', className)}>
      {pulse && <span className={cn('absolute inline-flex size-full animate-ping rounded-full opacity-60', toneBg[tone])} />}
      <span className={cn('relative inline-flex size-2 rounded-full', toneBg[tone])} />
    </span>
  );
}

export function SourceBadge({ source }: { source: string | null | undefined }) {
  const meta = sourceMeta(source);
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium text-foreground">
      <span className={cn('size-2 rounded-[3px]', meta.dot)} />
      {meta.label}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: number | null | undefined }) {
  if (severity == null) return <span className="text-subtle">—</span>;
  return (
    <Badge tone={severityTone(severity)} className="num min-w-7 justify-center">
      {severity}
    </Badge>
  );
}

export function RiskBadge({ level }: { level: string | null | undefined }) {
  if (!level) return <span className="text-subtle">—</span>;
  return (
    <Badge tone={riskTone(level)} dot>
      {riskLabel(level)}
    </Badge>
  );
}

const statusLabels: Record<string, string> = {
  open: 'Đang mở',
  investigating: 'Đang điều tra',
  contained: 'Đã khoanh vùng',
  resolved: 'Đã xử lý',
  closed: 'Đã đóng',
  candidate: 'Candidate',
  shadow: 'Shadow',
  active: 'Active',
  rejected: 'Rejected',
  completed: 'Hoàn tất',
  failed: 'Thất bại',
  pending: 'Đang chờ',
  reporting: 'Reporting',
  stale: 'Stale',
  healthy: 'Healthy',
  up: 'Up',
  down: 'Down',
  registered: 'Đã đăng ký',
  new: 'Mới',
  not_required: 'Không cần',
};

export function StatusBadge({ status }: { status: string | null | undefined }) {
  if (!status) return <span className="text-subtle">—</span>;
  return (
    <Badge tone={statusTone(status)} dot>
      {statusLabels[status.toLowerCase()] ?? status}
    </Badge>
  );
}

/* ---------------------------------- Scores --------------------------------- */

export function ScoreBar({ value, className }: { value: number | null | undefined; className?: string }) {
  if (!isNum(value)) return <span className="text-subtle">—</span>;
  const tone = scoreTone(value);
  return (
    <div className={cn('flex items-center gap-2', className)}>
      <span className="num w-9 text-xs text-foreground">{fmtScore(value)}</span>
      <div className="h-1.5 w-14 overflow-hidden rounded-full bg-muted">
        <div className="h-full rounded-full" style={{ width: `${Math.min(100, Math.max(0, value * 100))}%`, background: toneColor[tone] }} />
      </div>
    </div>
  );
}

export function ScoreGauge({ value, label }: { value: number | null | undefined; label?: string }) {
  const score = isNum(value) ? Math.min(1, Math.max(0, value)) : null;
  const tone = scoreTone(score);
  const radius = 70;
  const circumference = 2 * Math.PI * radius;
  const arc = circumference * 0.75;
  return (
    <div className="relative mx-auto size-48">
      <svg viewBox="0 0 180 180" className="size-full rotate-[-225deg]" aria-hidden="true">
        <circle cx="90" cy="90" r={radius} fill="none" stroke="var(--color-muted)" strokeWidth="12" strokeLinecap="round" strokeDasharray={`${arc} ${circumference}`} />
        {score !== null && (
          <circle
            cx="90"
            cy="90"
            r={radius}
            fill="none"
            stroke={toneColor[tone]}
            strokeWidth="12"
            strokeLinecap="round"
            strokeDasharray={`${arc * score} ${circumference}`}
            className="transition-[stroke-dasharray] duration-700" style={{ filter: `drop-shadow(0 0 8px ${toneColor[tone]})` }}
          />
        )}
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="num text-[44px] leading-none font-semibold tracking-[-0.03em] text-foreground">{score === null ? '—' : score.toFixed(2)}</span>
        {label && <span className="mt-1.5 text-xs text-subtle">{label}</span>}
      </div>
    </div>
  );
}

/* ---------------------------------- States --------------------------------- */

export function EmptyState({
  icon,
  title,
  description,
  className,
}: {
  icon?: React.ReactNode;
  title: React.ReactNode;
  description?: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn('flex flex-col items-center justify-center gap-2 px-6 py-10 text-center', className)}>
      <span className="text-subtle [&_svg]:size-6">{icon ?? <Inbox />}</span>
      <p className="text-sm font-medium text-foreground">{title}</p>
      {description && <p className="max-w-md text-xs leading-relaxed text-muted-foreground">{description}</p>}
    </div>
  );
}

/** Shown when a refresh failed; previous data stays on screen. */
export function StaleNotice({ error, hasData }: { error: unknown; hasData: boolean }) {
  if (!error) return null;
  return (
    <div role="alert" className="flex items-center gap-2 rounded-lg border border-warning/30 bg-warning/10 px-3 py-2 text-xs text-warning">
      <AlertTriangle className="size-3.5 shrink-0" />
      {hasData
        ? 'Không tải được dữ liệu mới. Đang hiển thị bản gần nhất và sẽ tự thử lại.'
        : `Không tải được dữ liệu từ API (${error instanceof Error ? error.message : 'lỗi kết nối'}).`}
    </div>
  );
}

/* ------------------------------- Text helpers ------------------------------ */

export function Mono({ children, className, title }: { children: React.ReactNode; className?: string; title?: string }) {
  return (
    <span className={cn('font-mono text-[13px] text-foreground', className)} title={title}>
      {children}
    </span>
  );
}

export function Truncate({ text, className, mono = false }: { text: string | null | undefined; className?: string; mono?: boolean }) {
  if (!text) return <span className="text-subtle">—</span>;
  return (
    <Tip content={text}>
      <span className={cn('block truncate', mono && 'font-mono text-[13px]', className)}>{text}</span>
    </Tip>
  );
}

export function CopyButton({ value, label = 'Sao chép' }: { value: string; label?: string }) {
  const [copied, setCopied] = React.useState(false);
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={(event) => {
        event.stopPropagation();
        void navigator.clipboard?.writeText(value).then(() => {
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1200);
        });
      }}
      className="inline-flex size-6 items-center justify-center rounded-md text-subtle hover:bg-muted hover:text-foreground"
    >
      {copied ? <Check className="size-3.5 text-success" /> : <Copy className="size-3.5" />}
    </button>
  );
}

export function Field({ label, children, className }: { label: string; children: React.ReactNode; className?: string }) {
  return (
    <div className={cn('min-w-0 rounded-2xl border border-border bg-white/[0.03] px-4 py-3', className)}>
      <div className="text-xs text-subtle">{label}</div>
      <div className="mt-1 min-w-0 text-sm text-foreground wrap-anywhere">{children}</div>
    </div>
  );
}

export function JsonView({ value, className }: { value: unknown; className?: string }) {
  const text = React.useMemo(() => JSON.stringify(value ?? null, null, 2), [value]);
  return (
    <div className={cn('relative rounded-2xl border border-border bg-black/25', className)}>
      <div className="absolute top-1.5 right-1.5">
        <CopyButton value={text} label="Sao chép JSON" />
      </div>
      <pre className="max-h-96 overflow-auto p-3 pr-9 font-mono text-[12.5px] leading-relaxed text-muted-foreground">{text}</pre>
    </div>
  );
}

/* --------------------------------- Bar list -------------------------------- */

export function BarList({
  items,
  color = 'var(--color-primary)',
  empty = 'Chưa có dữ liệu.',
  mono = false,
}: {
  items: Array<{ label: string; value: number; color?: string }>;
  color?: string;
  empty?: string;
  mono?: boolean;
}) {
  if (!items.length) return <p className="py-6 text-center text-xs text-muted-foreground">{empty}</p>;
  const max = Math.max(...items.map((item) => item.value), 1);
  const total = items.reduce((sum, item) => sum + item.value, 0) || 1;
  return (
    <ul className="flex flex-col gap-4">
      {items.map((item) => (
        <li key={item.label} className="min-w-0">
          <div className="mb-2 flex items-baseline justify-between gap-3 text-sm">
            <span className={cn('truncate text-foreground', mono && 'font-mono text-[13px]')} title={item.label}>
              {item.label}
            </span>
            <span className="num shrink-0 text-muted-foreground">
              <span className="text-foreground">{item.value.toLocaleString('vi-VN')}</span>
              <span className="ml-1.5 text-subtle">{Math.round((item.value / total) * 100)}%</span>
            </span>
          </div>
          <div className="h-1.5 overflow-hidden rounded-full bg-muted">
            <div className="h-full rounded-full" style={{ width: `${(item.value / max) * 100}%`, background: item.color ?? color }} />
          </div>
        </li>
      ))}
    </ul>
  );
}

/* -------------------------------- Sparkline -------------------------------- */

export function Sparkline({ data, color = 'var(--color-primary)', className }: { data: number[]; color?: string; className?: string }) {
  const id = React.useId().replace(/:/g, '');
  if (data.length < 2) return null;
  const max = Math.max(...data, 1);
  const points = data.map((value, index) => [(index / (data.length - 1)) * 100, 28 - (value / max) * 26]);
  const line = points.map(([x, y]) => `${x.toFixed(2)},${y.toFixed(2)}`).join(' ');
  return (
    <svg viewBox="0 0 100 30" preserveAspectRatio="none" className={cn('h-8 w-full', className)} aria-hidden="true">
      <defs>
        <linearGradient id={id} x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.25" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <polygon points={`0,30 ${line} 100,30`} fill={`url(#${id})`} />
      <polyline points={line} fill="none" stroke={color} strokeWidth="1.8" vectorEffect="non-scaling-stroke" style={{ filter: `drop-shadow(0 0 4px ${color})` }} />
    </svg>
  );
}
