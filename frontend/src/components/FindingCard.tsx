import type { Finding } from '../types'
import { SeverityTag } from './Severity'

export function FindingCard({ finding }: { finding: Finding }) {
  return (
    <li className="grid gap-3 px-5 py-4 sm:grid-cols-[84px_1fr] sm:gap-4">
      <span>
        <SeverityTag sev={finding.severity} />
      </span>
      <div className="min-w-0">
        <p className="flex flex-wrap items-center gap-2 text-[15px] text-ink">
          {finding.title}
          {finding.authoritative && (
            <span className="rounded-sm bg-[color-mix(in_oklab,var(--color-risk-malicious)_16%,transparent)] px-1.5 py-0.5 text-[12px] font-medium text-risk-malicious">
              Threat list match
            </span>
          )}
        </p>
        <p className="mt-1 break-words font-mono text-[13px] leading-relaxed text-muted">{finding.evidence}</p>
        {(finding.impact || finding.recommendation) && (
          <p className="mt-2 text-[14px] leading-relaxed text-muted">
            {finding.impact}
            {finding.impact && finding.recommendation ? ' ' : ''}
            {finding.recommendation && <span className="text-ink">{finding.recommendation}</span>}
          </p>
        )}
        <p className="mt-2 text-[12px] text-faint">
          {finding.source} · <span className="font-mono">{finding.id}</span>
        </p>
      </div>
    </li>
  )
}
