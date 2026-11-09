import * as React from 'react';
import { cn } from '@/lib/utils';
import { toneBg, toneSoft, type Tone } from '@/lib/severity';

export function Badge({
  tone = 'neutral',
  dot = false,
  className,
  children,
  ...props
}: React.HTMLAttributes<HTMLSpanElement> & { tone?: Tone; dot?: boolean }) {
  return (
    <span
      className={cn(
        'inline-flex h-6 shrink-0 items-center gap-1.5 rounded-full px-2.5 text-xs font-medium whitespace-nowrap',
        toneSoft[tone],
        className,
      )}
      {...props}
    >
      {dot && <span className={cn('size-1.5 rounded-full', toneBg[tone])} />}
      {children}
    </span>
  );
}
