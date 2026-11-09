// The product big: the report screen as live HTML, its list of checks beside the open report. Owner: P1.
import type { RiskLevel } from '../../types'
import { RiskBadge } from '../RiskBadge'
import { SeverityTag } from '../Severity'

const RECENT: { target: string; level: RiskLevel; when: string; active?: boolean }[] = [
  { target: 'paypa1-secure-login.com', level: 'high_risk', when: '10:42', active: true },
  { target: 'Pasted message', level: 'suspicious', when: '10:31' },
  { target: 'expired.badssl.com', level: 'suspicious', when: '10:18' },
  { target: 'github.com', level: 'low_risk', when: '09:57' },
  { target: 'sbi.co.in', level: 'low_risk', when: '09:40' },
]

const FINDINGS = [
  {
    sev: 'high',
    title: 'Domain imitates paypal.com',
    evidence: "'paypa1' uses look-alike characters for 'paypal'",
    source: 'Lookalike names',
  },
  {
    sev: 'high',
    title: 'Domain registered very recently',
    evidence: 'Registered 4 days ago (RDAP)',
    source: 'Domain age',
  },
  {
    sev: 'medium',
    title: 'First certificate issued 3 days ago',
    evidence: '1 certificate in Certificate Transparency logs',
    source: 'Certificate',
  },
  {
    sev: 'low',
    title: 'No Content-Security-Policy',
    evidence: 'Header missing from the response',
    source: 'Security settings',
  },
] as const

export function ProductFrame() {
  return (
    <div className="window grid lg:grid-cols-[300px_1fr]" role="img" aria-label="A TrustLens report for paypa1-secure-login.com beside the list of recent checks">
      <aside className="hidden border-r border-line bg-sunken lg:block">
        <p className="t-label px-5 pb-3 pt-5">Recent checks</p>
        <ul>
          {RECENT.map((r) => (
            <li
              key={r.target}
              className={`flex flex-col gap-2 border-t border-line px-5 py-3.5 ${r.active ? 'bg-raised' : ''}`}
            >
              <span className={`truncate font-mono text-[13px] ${r.active ? 'text-ink' : 'text-muted'}`}>{r.target}</span>
              <span className="flex items-center justify-between">
                <RiskBadge level={r.level} />
                <span className="text-[13px] text-faint">{r.when}</span>
              </span>
            </li>
          ))}
        </ul>
      </aside>

      <div className="min-w-0 p-5 sm:p-8">
        <div className="flex flex-wrap items-center gap-4">
          <RiskBadge level="high_risk" size="lg" />
          <div className="min-w-0">
            <p className="truncate font-mono text-[15px] text-ink">https://paypa1-secure-login.com/verify</p>
            <p className="text-[13px] text-faint">Checked at 10:42 · 5 of 5 checks ran · 4 findings</p>
          </div>
        </div>

        <div className="mt-6 border-l-2 border-action pl-4">
          <p className="t-label">What this means</p>
          <p className="mt-1 text-[16px] leading-relaxed text-ink">
            This link is High Risk. The address copies PayPal’s name with a 1 in place of the l, and the domain was
            registered four days ago. Do not sign in, and reach PayPal by typing paypal.com yourself.
          </p>
        </div>

        <div className="mt-6 overflow-hidden rounded-lg border border-line">
          <div className="hidden grid-cols-[84px_1fr_1fr_150px] gap-4 border-b border-line bg-sunken px-4 py-2.5 sm:grid">
            <span className="t-label">Severity</span>
            <span className="t-label">Finding</span>
            <span className="t-label">Evidence</span>
            <span className="t-label">Check</span>
          </div>
          <ul className="divide-y divide-line">
            {FINDINGS.map((f) => (
              <li key={f.title} className="grid gap-2 px-4 py-3 sm:grid-cols-[84px_1fr_1fr_150px] sm:items-center sm:gap-4">
                <span>
                  <SeverityTag sev={f.sev} />
                </span>
                <span className="text-[15px] text-ink">{f.title}</span>
                <span className="font-mono text-[13px] text-muted">{f.evidence}</span>
                <span className="text-[13px] text-faint">{f.source}</span>
              </li>
            ))}
          </ul>
        </div>

        <div className="mt-6 flex flex-wrap items-center justify-between gap-3 border-t border-line pt-5 text-[13px]">
          <span className="text-faint">Fingerprint 0x7a3f…91c2 · sealed on Ethereum</span>
          <span className="inline-flex items-center gap-2 text-risk-low">
            <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true">
              <path d="M3 7.2l2.6 2.6L11 4.4" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            Report matches its seal
          </span>
        </div>
      </div>
    </div>
  )
}
