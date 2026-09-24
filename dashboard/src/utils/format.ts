export function compact(value: number | undefined) {
  return new Intl.NumberFormat('en', { notation: 'compact' }).format(value ?? 0);
}

export function formatTime(value: string | null | undefined) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}
