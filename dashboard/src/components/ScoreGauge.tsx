interface ScoreGaugeProps {
  score: number; // 0.0 to 1.0
  size?: number;
  label?: string;
  sublabel?: string;
}

export function ScoreGauge({
  score,
  size = 180,
  label = 'Security Risk',
  sublabel,
}: ScoreGaugeProps) {
  const normalized = Math.min(1, Math.max(0, score || 0));
  const percent = Math.round(normalized * 100);

  // SVG dimensions
  const strokeWidth = 14;
  const radius = (size - strokeWidth * 2) / 2;
  const center = size / 2;
  const circumference = 2 * Math.PI * radius;

  // Arc covers 240 degrees (from 150 deg to 390 deg)
  const arcFraction = 0.75; // 270 deg
  const arcLength = circumference * arcFraction;
  const strokeDashoffset = arcLength - arcLength * normalized;

  // Color determination
  let color = '#10B981'; // Green
  let riskStatus = 'AN TOÀN / LOW';
  let glowColor = 'rgba(16, 185, 129, 0.3)';

  if (normalized >= 0.75) {
    color = '#EF4444'; // Red
    riskStatus = 'NGUY HIỂM / CRITICAL';
    glowColor = 'rgba(239, 68, 68, 0.4)';
  } else if (normalized >= 0.45) {
    color = '#F59E0B'; // Amber
    riskStatus = 'CẢNH BÁO / ELEVATED';
    glowColor = 'rgba(245, 158, 11, 0.35)';
  } else if (normalized >= 0.2) {
    color = '#38BDF8'; // Sky
    riskStatus = 'GIÁM SÁT / MODERATE';
    glowColor = 'rgba(56, 189, 248, 0.3)';
  }

  return (
    <div className="soc-gauge-card" style={{ minWidth: size + 40 }}>
      <div className="gauge-svg-container" style={{ width: size, height: size }}>
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
          <defs>
            <linearGradient id="gaugeGradient" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#38BDF8" />
              <stop offset="50%" stopColor="#F59E0B" />
              <stop offset="100%" stopColor="#EF4444" />
            </linearGradient>
            <filter id="gaugeGlow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="4" result="glow" />
              <feComposite in="SourceGraphic" in2="glow" operator="over" />
            </filter>
          </defs>

          {/* Background track */}
          <circle
            cx={center}
            cy={center}
            r={radius}
            fill="none"
            stroke="#1E293B"
            strokeWidth={strokeWidth}
            strokeDasharray={`${arcLength} ${circumference}`}
            strokeLinecap="round"
            transform={`rotate(135 ${center} ${center})`}
          />

          {/* Value track */}
          <circle
            cx={center}
            cy={center}
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth={strokeWidth}
            strokeDasharray={`${arcLength} ${circumference}`}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            filter="url(#gaugeGlow)"
            transform={`rotate(135 ${center} ${center})`}
            style={{
              transition: 'stroke-dashoffset 0.8s cubic-bezier(0.4, 0, 0.2, 1), stroke 0.5s ease',
            }}
          />
        </svg>

        {/* Center content */}
        <div className="gauge-center-content">
          <span className="gauge-score-num" style={{ color }}>
            {score.toFixed(2)}
          </span>
          <span className="gauge-score-pct">{percent}%</span>
        </div>
      </div>

      <div className="gauge-meta">
        <div className="gauge-label">{label}</div>
        <div
          className="gauge-status-badge"
          style={{ color, borderColor: color, boxShadow: `0 0 10px ${glowColor}` }}
        >
          <span className="gauge-pulse-dot" style={{ backgroundColor: color }} />
          {riskStatus}
        </div>
        {sublabel && <div className="gauge-sublabel">{sublabel}</div>}
      </div>
    </div>
  );
}
