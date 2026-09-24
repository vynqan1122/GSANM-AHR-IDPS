interface Item {
  label: string;
  value: number;
}

export function BarList({ items }: { items: Item[] }) {
  const max = Math.max(1, ...items.map((item) => item.value));
  return (
    <div className="bar-list">
      {items.map((item) => (
        <div className="bar-row" key={item.label}>
          <span>{item.label}</span>
          <div><i style={{ width: `${(item.value / max) * 100}%` }} /></div>
          <b>{item.value}</b>
        </div>
      ))}
    </div>
  );
}
