import * as React from 'react';
import { cn } from '@/lib/utils';

export function Card({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('glass rounded-3xl', className)} {...props} />;
}

export function CardHeader({
  className,
  title,
  description,
  icon,
  actions,
  children,
}: {
  className?: string;
  title: React.ReactNode;
  description?: React.ReactNode;
  icon?: React.ReactNode;
  actions?: React.ReactNode;
  children?: React.ReactNode;
}) {
  return (
    <div className={cn('flex items-start justify-between gap-3 px-7 pt-6 pb-4', className)}>
      <div className="flex min-w-0 items-start gap-2.5">
        {icon && <span className="mt-0.5 text-muted-foreground [&_svg]:size-4">{icon}</span>}
        <div className="min-w-0">
          <h3 className="text-base font-semibold tracking-tight text-foreground">{title}</h3>
          {description && <p className="mt-1 text-[13px] leading-snug text-subtle">{description}</p>}
          {children}
        </div>
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </div>
  );
}

export function CardContent({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('px-7 pb-7', className)} {...props} />;
}
