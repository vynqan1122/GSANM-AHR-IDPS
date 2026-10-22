interface Item {
  label: string;
  value: number;
  sublabel?: string;
  color?: string;
}

interface BarListProps {
  items: Item[];
  showPercent?: boolean;
  colorVariant?: 'cyan' | 'severity' | 'emerald' | 'amber';
}

function getSeverityColor(label: string): string {
  const num = parseInt(label, 10);
  if (!isNaN(num)) {
    if (num >= 8) return '#EF4444'; // Red
    if (num >= 6) return '#F97316'; // Orange
    if (num >= 4) return '#F59E0B'; // Amber
    if (num >= 2) return '#38BDF8'; // Sky
    return '#10B981'; // Green
  }
  const l = label.toLowerCase();
  if (l.includes('crit') || l.includes('high')) return '#EF4444';
  if (l.includes('med') || l.includes('warn')) return '#F59E0B';
  return '#38BDF8';
}

export function BarList({
  items,
  showPercent = true,
  colorVariant = 'cyan',
}: BarListProps) {
  const total = items.reduce((sum, item) => sum + item.value, 0);
  const max = Math.max(1, ...items.map((item) => item.value));

  if (!items.length) {
    return <div className="bar-list-empty">Không có dữ liệu phân bổ</div>;
  }

  return (
    <div className="soc-bar-list">
      {items.map((item) => {
        const percent = total > 0 ? Math.round((item.value / total) * 100) : 0;
        const widthPct = Math.min(100, Math.max(2, (item.value / max) * 100));

        let barColor = '#38BDF8';
        if (item.color) {
          barColor = item.color;
        } else if (colorVariant === 'severity') {
          barColor = getSeverityColor(item.label);
        } else if (colorVariant === 'emerald') {
          barColor = '#10B981';
        } else if (colorVariant === 'amber') {
          barColor = '#F59E0B';
        }

        return (
          <div className="soc-bar-row" key={item.label}>
            <div className="bar-row-header">
              <span className="bar-label-text" title={item.label}>
                {item.label}
              </span>
              <div className="bar-val-group">
                <span className="bar-val-count">{item.value.toLocaleString()}</span>
                {showPercent && (
                  <span className="bar-val-percent">({percent}%)</span>
                )}
              </div>
            </div>
            <div className="bar-track">
              <div
                className="bar-fill"
                style={{
                  width: `${widthPct}%`,
                  backgroundColor: barColor,
                  boxShadow: `0 0 8px ${barColor}44`,
                }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}
