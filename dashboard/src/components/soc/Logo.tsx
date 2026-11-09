/** AHR-IDPS mark: a bare monochrome shield with a single sensor node (no tile behind it). */
export function LogoMark({ size = 28, className }: { size?: number; className?: string }) {
  return (
    <svg width={Math.round(size * 0.92)} height={size} viewBox="8 7 24 26" fill="none" className={className} role="img" aria-label="AHR-IDPS">
      <path
        d="M20 9l9.5 3.4v7.4c0 5.3-3.9 9.2-9.5 10.9-5.6-1.7-9.5-5.6-9.5-10.9v-7.4L20 9z"
        stroke="currentColor"
        strokeWidth="1.9"
        strokeLinejoin="round"
      />
      <circle cx="20" cy="19.5" r="2.8" fill="currentColor" />
    </svg>
  );
}
