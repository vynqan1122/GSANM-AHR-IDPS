const numberFormat = new Intl.NumberFormat('vi-VN');
const compactFormat = new Intl.NumberFormat('vi-VN', { notation: 'compact', maximumFractionDigits: 1 });

export const isNum = (value: unknown): value is number =>
  typeof value === 'number' && Number.isFinite(value);

export function fmtNumber(value: unknown) {
  return isNum(value) ? numberFormat.format(value) : '—';
}

export function fmtCompact(value: unknown) {
  return isNum(value) ? compactFormat.format(value) : '—';
}

export function fmtScore(value: unknown, digits = 2) {
  return isNum(value) ? value.toFixed(digits) : '—';
}

export function fmtPct(value: unknown, digits = 1) {
  return isNum(value) ? `${(value * 100).toFixed(digits)}%` : '—';
}

export function fmtBytes(value: unknown) {
  if (!isNum(value)) return '—';
  const units = ['B', 'KB', 'MB', 'GB'];
  let size = value;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(size < 10 && unit > 0 ? 1 : 0)} ${units[unit]}`;
}

function toDate(value: string | null | undefined) {
  if (!value) return null;
  // Some backends emit "2026-10-23 11:20:02+00:00"; normalise the separator.
  const date = new Date(value.includes('T') ? value : value.replace(' ', 'T'));
  return Number.isNaN(date.getTime()) ? null : date;
}

export function fmtTime(value: string | null | undefined) {
  const date = toDate(value);
  return date ? date.toLocaleTimeString('vi-VN', { hour12: false }) : '—';
}

export function fmtDateTime(value: string | null | undefined) {
  const date = toDate(value);
  if (!date) return '—';
  const pad = (value: number) => String(value).padStart(2, '0');
  return `${pad(date.getDate())}/${pad(date.getMonth() + 1)} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

export function timeAgo(value: string | null | undefined, now = Date.now()) {
  const date = toDate(value);
  if (!date) return '—';
  const seconds = Math.round((now - date.getTime()) / 1000);
  if (seconds < 5) return 'vừa xong';
  if (seconds < 60) return `${seconds} giây trước`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} phút trước`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} giờ trước`;
  return `${Math.floor(hours / 24)} ngày trước`;
}

export function fmtDuration(start?: string | null, end?: string | null) {
  const a = toDate(start);
  const b = toDate(end);
  if (!a || !b) return '—';
  const total = Math.max(0, Math.round((b.getTime() - a.getTime()) / 1000));
  if (total < 60) return `${total}s`;
  const minutes = Math.floor(total / 60);
  if (minutes < 60) return `${minutes}m ${total % 60}s`;
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
}

export function shortId(value: string | null | undefined, length = 10) {
  if (!value) return '—';
  return value.length > length ? `${value.slice(0, length)}…` : value;
}
