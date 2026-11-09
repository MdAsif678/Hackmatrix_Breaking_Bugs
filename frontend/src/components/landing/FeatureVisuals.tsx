// Small product fragments for the feature cards: each shows the real thing it describes. Owner: P1.
import { RiskBadge } from '../RiskBadge'

export function MessageVisual() {
  return (
    <div className="space-y-3" role="img" aria-label="An SMS with its link found and checked">
      <div className="max-w-[340px] rounded-lg rounded-bl-sm border border-line bg-sunken px-4 py-3 text-[14px] leading-relaxed text-muted">
        Dear customer, your KYC expires today. Update now at{' '}
        <span className="rounded-sm bg-[rgb(37_99_235/0.18)] px-1 font-mono text-[13px] text-ink">sbi-kyc-update.in/verify</span>{' '}
        or your account will be blocked.
      </div>
      <div className="flex flex-wrap items-center gap-2 text-[13px] text-faint">
        <span>1 link found</span>
        <span aria-hidden="true">·</span>
        <span>checked</span>
        <RiskBadge level="suspicious" />
      </div>
    </div>
  )
}

export function ExplainVisual() {
  return (
    <div className="space-y-3 text-[14px] leading-relaxed" role="img" aria-label="An explanation where each sentence cites a finding">
      <p className="text-ink">
        <span className="mr-2 rounded-sm border border-line px-1.5 py-0.5 font-mono text-[12px] text-link">tls.expired</span>
        The site’s certificate ran out in 2015, so your browser cannot confirm who runs it.
      </p>
      <p className="text-muted line-through decoration-risk-malicious/70">
        <span className="mr-2 rounded-sm border border-line px-1.5 py-0.5 font-mono text-[12px] text-faint">no finding</span>
        The site is run by a known criminal group.
      </p>
    </div>
  )
}

export function CampaignVisual() {
  const rows = [
    { target: 'fast-refund-portal.top', level: 'high_risk' as const },
    { target: 'Pasted message', level: 'suspicious' as const },
  ]
  return (
    <div role="img" aria-label="Two different reports linked by the same server IP address">
      <ul className="divide-y divide-line rounded-lg border border-line bg-sunken">
        {rows.map((r) => (
          <li key={r.target} className="flex items-center justify-between gap-3 px-4 py-3">
            <span className="truncate font-mono text-[13px] text-muted">{r.target}</span>
            <RiskBadge level={r.level} />
          </li>
        ))}
      </ul>
      <p className="mt-3 inline-flex rounded-sm border border-line px-2 py-1 font-mono text-[12px] text-muted">
        same server IP: 203.0.113.24
      </p>
    </div>
  )
}

export function BlockedVisual() {
  return (
    <div className="space-y-3" role="img" aria-label="An internal cloud address refused by the checker">
      <div className="field flex h-11 items-center px-3 font-mono text-[13px] text-muted">
        <span className="truncate">http://169.254.169.254/latest/meta-data/</span>
      </div>
      <p className="rounded-md border border-[color-mix(in_oklab,var(--color-risk-malicious)_35%,transparent)] px-3 py-2.5 text-[14px] text-[color-mix(in_oklab,var(--color-risk-malicious)_80%,white)]">
        Blocked for safety: this address points to a private or internal network.
      </p>
    </div>
  )
}
