import * as React from 'react';
import { Dialog as DialogPrimitive, Tabs as TabsPrimitive, Tooltip as TooltipPrimitive } from 'radix-ui';
import { X } from 'lucide-react';
import { cn } from '@/lib/utils';

/* ---------------------------------- Tooltip --------------------------------- */

export const TooltipProvider = TooltipPrimitive.Provider;

export function Tip({ content, children, side = 'top' }: {
  content: React.ReactNode;
  children: React.ReactElement;
  side?: 'top' | 'bottom' | 'left' | 'right';
}) {
  if (!content) return children;
  return (
    <TooltipPrimitive.Root delayDuration={250}>
      <TooltipPrimitive.Trigger asChild>{children}</TooltipPrimitive.Trigger>
      <TooltipPrimitive.Portal>
        <TooltipPrimitive.Content
          side={side}
          sideOffset={6}
          className="z-50 max-w-sm animate-fade-in rounded-md border border-border bg-muted px-2 py-1 text-xs text-foreground shadow-lg wrap-anywhere"
        >
          {content}
        </TooltipPrimitive.Content>
      </TooltipPrimitive.Portal>
    </TooltipPrimitive.Root>
  );
}

/* ----------------------------------- Tabs ----------------------------------- */

export const Tabs = TabsPrimitive.Root;

export function TabsList({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.List>) {
  return <TabsPrimitive.List className={cn('flex items-center gap-1 border-b border-border px-5', className)} {...props} />;
}

export function TabsTrigger({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.Trigger>) {
  return (
    <TabsPrimitive.Trigger
      className={cn(
        '-mb-px inline-flex h-11 items-center gap-2 border-b-2 border-transparent px-3 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground data-[state=active]:border-primary data-[state=active]:text-foreground [&_svg]:size-3.5',
        className,
      )}
      {...props}
    />
  );
}

export function TabsContent({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.Content>) {
  return <TabsPrimitive.Content className={cn('p-5 focus-visible:outline-none', className)} {...props} />;
}

/* ------------------------------- Sheet / Dialog ------------------------------ */

export function Sheet({
  open,
  onOpenChange,
  title,
  description,
  children,
  width = 'max-w-xl',
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: React.ReactNode;
  description?: React.ReactNode;
  children: React.ReactNode;
  width?: string;
}) {
  return (
    <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="fixed inset-0 z-40 animate-fade-in bg-black/55 backdrop-blur-[2px]" />
        <DialogPrimitive.Content
          className={cn(
            'fixed inset-y-0 right-0 z-50 glass flex w-full animate-sheet-in flex-col border-l border-white/15 bg-[#0a1020]/85 shadow-2xl focus-visible:outline-none',
            width,
          )}
        >
          <div className="flex items-start justify-between gap-4 border-b border-border px-5 py-4">
            <div className="min-w-0">
              <DialogPrimitive.Title className="text-base font-semibold text-foreground">{title}</DialogPrimitive.Title>
              <DialogPrimitive.Description className="mt-0.5 truncate text-xs text-muted-foreground">
                {description ?? ' '}
              </DialogPrimitive.Description>
            </div>
            <DialogPrimitive.Close className="rounded-md p-1 text-muted-foreground hover:bg-muted hover:text-foreground" aria-label="Đóng">
              <X className="size-4" />
            </DialogPrimitive.Close>
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">{children}</div>
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}

export function Dialog({
  open,
  onOpenChange,
  title,
  children,
  className,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="fixed inset-0 z-40 animate-fade-in bg-black/55 backdrop-blur-[2px]" />
        <DialogPrimitive.Content
          className={cn(
            'fixed top-[12vh] left-1/2 z-50 w-[calc(100%-2rem)] max-w-xl -translate-x-1/2 animate-pop-in overflow-hidden glass rounded-3xl bg-[#0a1020]/90 shadow-2xl focus-visible:outline-none',
            className,
          )}
        >
          <DialogPrimitive.Title className="sr-only">{title}</DialogPrimitive.Title>
          <DialogPrimitive.Description className="sr-only">{title}</DialogPrimitive.Description>
          {children}
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}

/* --------------------------------- Skeleton --------------------------------- */

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn('animate-pulse rounded-xl bg-white/[0.06]', className)} />;
}
