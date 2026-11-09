import type { AnalysisReport, RiskLevel } from '../../types'

interface Props {
  report: AnalysisReport
  reason?: string
}

interface PostureConfig {
  score: number
  label: string
  color: string
  ringStroke: string
  summary: string
}

const CONFIG: Record<RiskLevel, PostureConfig> = {
  confirmed_malicious: {
    score: 12,
    label: 'Critical Hazard',
    color: 'text-risk-malicious',
    ringStroke: '#f25c5c',
    summary: 'Active malicious signatures or blacklist feeds triggered. Absolute avoidance mandated.',
  },
  high_risk: {
    score: 28,
    label: 'Severe Danger',
    color: 'text-risk-high',
    ringStroke: '#f0894b',
    summary: 'High-severity findings compromise trust (e.g. credential theft heuristics or expired keys).',
  },
  suspicious: {
    score: 58,
    label: 'Elevated Caution',
    color: 'text-risk-suspicious',
    ringStroke: '#e3b341',
    summary: 'Anomalies detected. Verify certificate and domain registration before submitting information.',
  },
  low_risk: {
    score: 96,
    label: 'Clean Posture',
    color: 'text-risk-low',
    ringStroke: '#3fb27f',
    summary: 'No threats detected in the applied security checks. Maintain routine zero-trust vigilance.',
  },
  inconclusive: {
    score: 50,
    label: 'Inconclusive',
    color: 'text-risk-inconclusive',
    ringStroke: '#8e9098',
    summary: 'Insufficient data collected due to timeouts or target resolution errors.',
  },
}

export function SecurityPostureGauge({ report, reason }: Props) {
  const cfg = CONFIG[report.risk_level]
  const radius = 38
  const circumference = 2 * Math.PI * radius
  const strokeDashoffset = circumference - (cfg.score / 100) * circumference

  return (
    <div className="panel flex flex-col justify-between border border-line bg-raised p-5 sm:p-6">
      <div className="flex items-center justify-between border-b border-line pb-3">
        <h3 className="text-[14px] font-medium text-ink">Security Health Posture</h3>
        <span className={`text-[12px] font-mono font-medium ${cfg.color}`}>
          {cfg.label}
        </span>
      </div>

      <div className="my-5 flex flex-col items-center gap-6 sm:flex-row sm:items-center">
        {/* Circular Gauge Ring */}
        <div className="relative shrink-0">
          <svg width="96" height="96" viewBox="0 0 96 96" className="-rotate-90">
            {/* Background circle track */}
            <circle
              cx="48"
              cy="48"
              r={radius}
              fill="transparent"
              stroke="var(--color-line)"
              strokeWidth="7"
            />
            {/* Colored progress arc */}
            <circle
              cx="48"
              cy="48"
              r={radius}
              fill="transparent"
              stroke={cfg.ringStroke}
              strokeWidth="7"
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              className="transition-all duration-1000 ease-out"
            />
          </svg>
          {/* Centered score text */}
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="font-mono text-xl font-bold text-ink">{cfg.score}%</span>
            <span className="text-[10px] text-faint uppercase font-mono">Score</span>
          </div>
        </div>

        {/* Text statement */}
        <div className="flex-1">
          <p className="text-[13px] leading-relaxed text-muted">
            {cfg.summary}
          </p>
          {reason && (
            <p className="mt-1 text-[12px] font-mono text-faint">
              {reason}
            </p>
          )}
          <div className="mt-3 flex items-center gap-3 text-[12px] font-mono text-faint">
            <span>Coverage: {Math.round(report.coverage * 100)}%</span>
            <span>·</span>
            <span>{report.recommendations.length} Recommendations</span>
          </div>
        </div>
      </div>

      <div className="border-t border-line pt-3 text-[12px] text-faint">
        Deterministic rating generated from {report.checks.length} parallel modules.
      </div>
    </div>
  )
}
