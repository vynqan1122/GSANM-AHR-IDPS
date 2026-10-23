import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

export const buttonVariants = cva(
  'inline-flex shrink-0 items-center justify-center gap-2 whitespace-nowrap rounded-full text-sm font-medium transition-colors disabled:pointer-events-none disabled:opacity-50 [&_svg]:size-4 [&_svg]:shrink-0',
  {
    variants: {
      variant: {
        default: 'bg-foreground text-background shadow-[0_0_24px_rgb(255_255_255/0.18)] hover:bg-white',
        secondary: 'border border-border bg-white/[0.07] text-foreground hover:bg-white/[0.12]',
        outline: 'border border-border-strong bg-transparent text-foreground hover:bg-white/[0.06]',
        ghost: 'text-muted-foreground hover:bg-white/[0.06] hover:text-foreground',
        danger: 'bg-sev-critical/14 text-sev-critical hover:bg-sev-critical/24',
      },
      size: {
        sm: 'h-8 px-3 text-[13px] [&_svg]:size-3.5',
        default: 'h-10 px-5',
        icon: 'size-10',
        'icon-sm': 'size-8 [&_svg]:size-3.5',
      },
    },
    defaultVariants: { variant: 'secondary', size: 'default' },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {}

export function Button({ className, variant, size, type = 'button', ...props }: ButtonProps) {
  return <button type={type} className={cn(buttonVariants({ variant, size }), className)} {...props} />;
}
