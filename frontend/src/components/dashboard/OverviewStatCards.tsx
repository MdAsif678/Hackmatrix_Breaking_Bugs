import type { AnalysisReport, Finding, Severity } from '../../types'

interface Props {
  report: AnalysisReport
  findings: Finding[]
}

export function OverviewStatCards({ report, findings }: Props) {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  for (const f of findings) {
    if (f.severity in counts) {
      counts[f.severity]++
    }
  }

  const activeThreats = counts.critical + counts.high
  const warnings = counts.medium
  const totalRan = report.checks.filter((c) => c.status === 'ok').length
  const totalChecks = report.checks.length

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      {/* 1. Overall Security Posture */}
      <div className="panel border border-line bg-raised p-5 transition-colors hover:border-line-strong">
        <div className="flex items-start justify-between">
          <div>
            <span className="text-[12px] font-medium uppercase tracking-wider text-faint">Security Posture</span>
            <div className="mt-2 font-mono text-2xl font-bold capitalize text-ink">
              {report.risk_level.replace('_', ' ')}
            </div>
          </div>
          <div className={`rounded-lg p-2.5 ${
            report.risk_level === 'confirmed_malicious' || report.risk_level === 'high_risk'
              ? 'bg-red-500/15 text-risk-malicious'
              : report.risk_level === 'suspicious'
              ? 'bg-amber-500/15 text-risk-suspicious'
              : 'bg-emerald-500/15 text-risk-low'
          }`}>
            <svg className="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
        </div>
        <div className="mt-3 flex items-center gap-2 text-[12px] text-faint">
          <span className="h-1.5 w-1.5 rounded-full bg-link" />
          <span>Verdict: {report.risk_reasons[0] ?? 'Deterministic classification'}</span>
        </div>
      </div>

      {/* 2. Active Severe Threats */}
      <div className="panel border border-line bg-raised p-5 transition-colors hover:border-line-strong">
        <div className="flex items-start justify-between">
          <div>
            <span className="text-[12px] font-medium uppercase tracking-wider text-faint">Critical & High Threats</span>
            <div className={`mt-2 font-mono text-2xl font-bold ${activeThreats > 0 ? 'text-risk-malicious' : 'text-ink'}`}>
              {activeThreats}
            </div>
          </div>
          <div className="rounded-lg bg-red-500/10 p-2.5 text-risk-malicious">
            <svg className="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
              <line x1="12" y1="9" x2="12" y2="13" />
              <line x1="12" y1="17" x2="12.01" y2="17" />
            </svg>
          </div>
        </div>
        <div className="mt-3 flex items-center gap-2 text-[12px] text-faint">
          <span>{warnings} medium warning{warnings === 1 ? '' : 's'} recorded</span>
        </div>
      </div>

      {/* 3. Analyzers Completed */}
      <div className="panel border border-line bg-raised p-5 transition-colors hover:border-line-strong">
        <div className="flex items-start justify-between">
          <div>
            <span className="text-[12px] font-medium uppercase tracking-wider text-faint">Analyzers Ran</span>
            <div className="mt-2 font-mono text-2xl font-bold text-ink">
              {totalRan} <span className="text-[16px] font-normal text-faint">/ {totalChecks}</span>
            </div>
          </div>
          <div className="rounded-lg bg-link/10 p-2.5 text-link">
            <svg className="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
            </svg>
          </div>
        </div>
        <div className="mt-3 flex items-center gap-2 text-[12px] text-faint">
          <span className="text-risk-low font-medium">{Math.round(report.coverage * 100)}%</span>
          <span>evidence coverage</span>
        </div>
      </div>

      {/* 4. Blockchain Seal Status */}
      <div className="panel border border-line bg-raised p-5 transition-colors hover:border-line-strong">
        <div className="flex items-start justify-between">
          <div>
            <span className="text-[12px] font-medium uppercase tracking-wider text-faint">On-Chain Registry</span>
            <div className="mt-2 font-mono text-xl font-bold text-ink">
              {report.chain ? 'Sealed' : 'Unregistered'}
            </div>
          </div>
          <div className="rounded-lg bg-purple-500/10 p-2.5 text-purple-400">
            <svg className="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <rect width="18" height="11" x="3" y="11" rx="2" ry="2" />
              <path d="M7 11V7a5 5 0 0 1 10 0v4" />
            </svg>
          </div>
        </div>
        <div className="mt-3 flex items-center gap-2 text-[12px] text-faint truncate font-mono">
          <span>{report.chain ? `#${report.chain.chain_report_id} on Sepolia` : 'Cryptographic SHA-256 ready'}</span>
        </div>
      </div>
    </div>
  )
}

