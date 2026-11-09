import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router';
import { Command } from 'cmdk';
import { CornerDownLeft, Search, ShieldAlert, Layers } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { Dialog } from '@/components/ui/overlays';

export interface PaletteItem {
  path: string;
  label: string;
  description: string;
  icon: LucideIcon;
  section: string;
}

const itemClass =
  'flex cursor-pointer items-center gap-3 rounded-md px-2.5 py-2 text-[13px] text-foreground data-[selected=true]:bg-muted [&_svg]:size-4 [&_svg]:text-muted-foreground';

export function CommandPalette({
  open,
  onOpenChange,
  items,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  items: PaletteItem[];
}) {
  const navigate = useNavigate();
  const [query, setQuery] = useState('');

  useEffect(() => {
    if (!open) setQuery('');
  }, [open]);

  const go = (path: string) => {
    onOpenChange(false);
    navigate(path);
  };

  const term = query.trim();
  const sections = Array.from(new Set(items.map((item) => item.section)));

  return (
    <Dialog open={open} onOpenChange={onOpenChange} title="Tìm kiếm và điều hướng">
      <Command label="Tìm kiếm và điều hướng" loop>
        <div className="flex items-center gap-2 border-b border-border px-3">
          <Search className="size-4 text-subtle" />
          <Command.Input
            value={query}
            onValueChange={setQuery}
            placeholder="Đi tới trang, hoặc nhập IP / event_id / incident_id…"
            className="h-11 flex-1 bg-transparent text-sm text-foreground outline-none placeholder:text-subtle"
          />
        </div>
        <Command.List className="max-h-[min(60vh,420px)] overflow-y-auto p-1.5">
          <Command.Empty className="px-3 py-6 text-center text-xs text-muted-foreground">Không tìm thấy trang phù hợp.</Command.Empty>

          {term && (
            <Command.Group heading="Tìm dữ liệu" className="[&_[cmdk-group-heading]]:eyebrow [&_[cmdk-group-heading]]:px-2.5 [&_[cmdk-group-heading]]:py-1.5">
              <Command.Item value={`search-events ${term}`} onSelect={() => go(`/events?q=${encodeURIComponent(term)}`)} className={itemClass}>
                <Layers />
                <span className="flex-1">
                  Tìm sự kiện chứa <span className="font-mono text-primary">{term}</span>
                </span>
                <CornerDownLeft className="size-3.5" />
              </Command.Item>
              {term.startsWith('inc-') ? (
                <Command.Item value={`open-incident ${term}`} onSelect={() => go(`/incidents/${encodeURIComponent(term)}`)} className={itemClass}>
                  <ShieldAlert />
                  <span className="flex-1">
                    Mở sự cố <span className="font-mono text-primary">{term}</span>
                  </span>
                </Command.Item>
              ) : (
                <Command.Item value={`search-incidents ${term}`} onSelect={() => go(`/incidents?q=${encodeURIComponent(term)}`)} className={itemClass}>
                  <ShieldAlert />
                  <span className="flex-1">
                    Tìm sự cố liên quan <span className="font-mono text-primary">{term}</span>
                  </span>
                </Command.Item>
              )}
            </Command.Group>
          )}

          {sections.map((section) => (
            <Command.Group
              key={section}
              heading={section}
              className="[&_[cmdk-group-heading]]:eyebrow [&_[cmdk-group-heading]]:px-2.5 [&_[cmdk-group-heading]]:py-1.5"
            >
              {items
                .filter((item) => item.section === section)
                .map((item) => {
                  const Icon = item.icon;
                  return (
                    <Command.Item key={item.path} value={`${item.label} ${item.description}`} onSelect={() => go(item.path)} className={itemClass}>
                      <Icon />
                      <span className="flex-1">{item.label}</span>
                      <span className="truncate text-xs text-subtle">{item.description}</span>
                    </Command.Item>
                  );
                })}
            </Command.Group>
          ))}
        </Command.List>
      </Command>
    </Dialog>
  );
}
