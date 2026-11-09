import type { AnalysisReport, Finding, RiskLevel, Severity } from '../types'
import { RISK_META } from './labels'
import { RiskBadge } from './RiskBadge'

interface RiskConfig {
  accentBorder: string
  actionDirective: string
}

const CONFIG: Record<RiskLevel, RiskConfig> = {
  confirmed_malicious: {
    accentBorder: 'border-l-risk-malicious',
    actionDirective: 'Active threat confirmed by security intelligence. Do not enter passwords, share OTPs, or approve transactions.',
  },
  high_risk: {
    accentBorder: 'border-l-risk-high',
    actionDirective: 'Multiple severe threat indicators identified. Interaction with this site or message presents substantial security risk.',
  },
  suspicious: {
    accentBorder: 'border-l-risk-suspicious',
    actionDirective: 'Anomalous indicators detected. Independently verify the domain and sender before trusting.',
  },
  low_risk: {
    accentBorder: 'border-l-risk-low',
    actionDirective: 'No known threat indicators detected in completed checks. Absence of threats is never proof of complete safety.',
  },
  inconclusive: {
    accentBorder: 'border-l-risk-inconclusive',
    actionDirective: 'Insufficient evidence to classify. Checks timed out or the destination was unreachable.',
  },
}

export function ThreatBanner({
  report,
  findings,
  reason,
}: {
  report: AnalysisReport
  findings: Finding[]
  reason?: string
}) {
  const cfg = CONFIG[report.risk_level]
  const targetLabel =
    report.input_type === 'message'
      ? 'Pasted Message'
      : report.normalized_target ?? report.input

  // Count findings by severity
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  for (const f of findings) {
    if (f.severity in counts) {
      counts[f.severity]++
    }
  }

  const checksTotal = report.checks.length
  const checksRan = report.checks.filter((c) => c.status === 'ok').length
  const coveragePct = Math.round(report.coverage * 100)

  return (
    <section
      aria-label="Threat assessment overview"
      className={`panel overflow-hidden border-l-4 ${cfg.accentBorder} p-5 sm:p-6`}
    >
      {/* Top Header Line */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line pb-4">
        <div className="flex items-center gap-3">
          <RiskBadge level={report.risk_level} size="lg" />
          <span className="font-mono text-[14px] text-ink font-medium break-all">
            {targetLabel}
          </span>
        </div>

        <div className="flex items-center gap-3 text-[13px] font-mono text-faint">
          <span>{coveragePct}% coverage</span>
          <span className="text-line-strong">·</span>
          <span>{checksRan}/{checksTotal} checks ran</span>
          <span className="text-line-strong">·</span>
          <span>{findings.length} finding{findings.length === 1 ? '' : 's'}</span>
        </div>
      </div>

      {/* Description & Directive */}
      <div className="mt-4">
        <h2 className="text-[17px] font-medium text-ink">
          {RISK_META[report.risk_level].description}
        </h2>
        {reason && (
          <p className="mt-1 text-[14px] text-muted">
            {reason}
          </p>
        )}
        <p className="mt-2 rounded-sm border border-line bg-sunken px-3.5 py-2 text-[13px] leading-relaxed text-muted">
          <span className="font-medium text-ink">Security notice: </span>
          {cfg.actionDirective}
        </p>
      </div>

      {/* Metrics Row: Tabular Findings Counter */}
      <div className="mt-5 grid grid-cols-2 divide-x divide-line border-t border-line pt-4 text-center sm:grid-cols-4 sm:text-left">
        <div className="px-3 sm:first:pl-0">
          <div className="text-[11px] font-medium uppercase tracking-wider text-faint">Danger / Critical</div>
          <div className={`mt-0.5 font-mono text-[18px] font-medium ${counts.critical > 0 ? 'text-risk-malicious' : 'text-faint'}`}>
            {counts.critical}
          </div>
        </div>

        <div className="px-3">
          <div className="text-[11px] font-medium uppercase tracking-wider text-faint">Serious / High</div>
          <div className={`mt-0.5 font-mono text-[18px] font-medium ${counts.high > 0 ? 'text-risk-high' : 'text-faint'}`}>
            {counts.high}
          </div>
        </div>

        <div className="px-3">
          <div className="text-[11px] font-medium uppercase tracking-wider text-faint">Warning / Medium</div>
          <div className={`mt-0.5 font-mono text-[18px] font-medium ${counts.medium > 0 ? 'text-risk-suspicious' : 'text-faint'}`}>
            {counts.medium}
          </div>
        </div>

        <div className="px-3 sm:last:pr-0">
          <div className="text-[11px] font-medium uppercase tracking-wider text-faint">Minor / Info</div>
          <div className="mt-0.5 font-mono text-[18px] font-medium text-faint">
            {counts.low + counts.info}
          </div>
        </div>
      </div>
    </section>
  )
}
