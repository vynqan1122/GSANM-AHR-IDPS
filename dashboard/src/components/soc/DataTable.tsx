import * as React from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import { cn } from '@/lib/utils';
import { EmptyState } from './primitives';
import { Skeleton } from '@/components/ui/overlays';

export interface Column<T> {
  key: string;
  header: React.ReactNode;
  /** CSS grid track, e.g. "120px" or "minmax(220px, 2fr)". */
  width: string;
  cell: (row: T) => React.ReactNode;
  align?: 'left' | 'right';
  className?: string;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  onRowClick?: (row: T) => void;
  selectedKey?: string | null;
  rowClassName?: (row: T) => string | undefined;
  /** Maximum height of the scroll area; the table shrinks to fit fewer rows. */
  maxHeight?: number | string;
  rowHeight?: number;
  minWidth?: number;
  loading?: boolean;
  empty?: React.ReactNode;
  label: string;
}

/**
 * Div-based grid table with row virtualisation. Rows are single-line; long
 * values should truncate inside cells (see Truncate).
 */
export function DataTable<T>({
  columns,
  rows,
  rowKey,
  onRowClick,
  selectedKey,
  rowClassName,
  maxHeight = 560,
  rowHeight = 48,
  minWidth = 760,
  loading = false,
  empty,
  label,
}: DataTableProps<T>) {
  const scrollRef = React.useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => rowHeight,
    overscan: 12,
  });
  const template = columns.map((column) => column.width).join(' ');

  return (
    <div ref={scrollRef} role="table" aria-label={label} aria-rowcount={rows.length} className="overflow-auto" style={{ maxHeight }}>
      <div style={{ minWidth }}>
        <div
          role="row"
          className="sticky top-0 z-10 grid items-center gap-3 border-b border-border bg-[#0b1222]/90 px-7 text-xs backdrop-blur font-medium text-subtle"
          style={{ gridTemplateColumns: template, height: 40 }}
        >
          {columns.map((column) => (
            <div key={column.key} role="columnheader" className={cn('truncate', column.align === 'right' && 'text-right')}>
              {column.header}
            </div>
          ))}
        </div>

        {loading && !rows.length ? (
          <div className="flex flex-col gap-2 p-4">
            {Array.from({ length: 6 }, (_, index) => (
              <Skeleton key={index} className="h-6 w-full" />
            ))}
          </div>
        ) : !rows.length ? (
          <div role="row">
            <div role="cell">{empty ?? <EmptyState title="Không có dữ liệu" />}</div>
          </div>
        ) : (
          <div className="relative" style={{ height: virtualizer.getTotalSize() }}>
            {virtualizer.getVirtualItems().map((item) => {
              const row = rows[item.index];
              const key = rowKey(row);
              const selected = selectedKey === key;
              return (
                <div
                  key={key}
                  role="row"
                  aria-rowindex={item.index + 1}
                  aria-selected={onRowClick ? selected : undefined}
                  tabIndex={onRowClick ? 0 : undefined}
                  onClick={onRowClick ? () => onRowClick(row) : undefined}
                  onKeyDown={
                    onRowClick
                      ? (event) => {
                          if (event.key === 'Enter' || event.key === ' ') {
                            event.preventDefault();
                            onRowClick(row);
                          }
                        }
                      : undefined
                  }
                  className={cn(
                    'absolute inset-x-0 top-0 grid items-center gap-3 border-b border-white/[0.06] px-7 text-sm',
                    onRowClick && 'cursor-pointer hover:bg-hover/50 focus-visible:bg-hover/60 focus-visible:outline-none',
                    selected && 'bg-primary/10 shadow-[inset_2px_0_0_var(--color-primary)]',
                    rowClassName?.(row),
                  )}
                  style={{ gridTemplateColumns: template, height: item.size, transform: `translateY(${item.start}px)` }}
                >
                  {columns.map((column) => (
                    <div
                      key={column.key}
                      role="cell"
                      className={cn('min-w-0 truncate', column.align === 'right' && 'text-right', column.className)}
                    >
                      {column.cell(row)}
                    </div>
                  ))}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
