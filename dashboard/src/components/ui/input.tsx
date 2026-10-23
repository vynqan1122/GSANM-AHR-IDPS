import * as React from 'react';
import { cn } from '@/lib/utils';

export function Input({ className, ...props }: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cn(
        'h-9.5 w-full rounded-[10px] border border-border bg-white/[0.04] px-3 text-sm text-foreground placeholder:text-subtle focus-visible:border-primary focus-visible:shadow-[0_0_0_3px_rgb(127_176_255/0.2)] focus-visible:outline-none',
        className,
      )}
      {...props}
    />
  );
}

export function NativeSelect({ className, children, ...props }: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      className={cn(
        'h-9.5 rounded-[10px] border border-border bg-[#0d1424] px-3 text-sm text-foreground focus-visible:border-primary focus-visible:shadow-[0_0_0_3px_rgb(127_176_255/0.2)] focus-visible:outline-none',
        className,
      )}
      {...props}
    >
      {children}
    </select>
  );
}

/** Small segmented control used for filters (source, status). */
export function Segmented<T extends string>({
  value,
  onChange,
  options,
  className,
  label,
}: {
  value: T;
  onChange: (value: T) => void;
  options: Array<{ value: T; label: React.ReactNode; count?: number }>;
  className?: string;
  label: string;
}) {
  return (
    <div role="radiogroup" aria-label={label} className={cn('inline-flex h-9.5 items-center gap-0.5 rounded-full border border-border bg-white/[0.04] p-[3px]', className)}>
      {options.map((option) => {
        const active = option.value === value;
        return (
          <button
            key={option.value}
            type="button"
            role="radio"
            aria-checked={active}
            onClick={() => onChange(option.value)}
            className={cn(
              'inline-flex h-full items-center gap-2 rounded-full px-4 text-[13.5px] font-medium transition-colors',
              active ? 'bg-white/[0.14] text-foreground shadow-[inset_0_1px_0_rgb(255_255_255/0.15)]' : 'text-muted-foreground hover:text-foreground',
            )}
          >
            {option.label}
            {option.count !== undefined && <span className="num text-subtle">{option.count}</span>}
          </button>
        );
      })}
    </div>
  );
}
