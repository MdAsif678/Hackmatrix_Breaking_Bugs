// Hero visual: the checker as live HTML. The five checks tick in turn, the verdict lands, the
// finished picture holds, then it starts again (4 s). Pausable; still under reduced motion. Owner: P1.
import { useState } from 'react'
import { RiskBadge } from '../RiskBadge'
import { SeverityTag } from '../Severity'

const ROWS = [
  { name: 'Lookalike names', result: 'Imitates paypal.com', sev: 'high' },
  { name: 'Domain age', result: 'Registered 4 days ago', sev: 'high' },
  { name: 'Known phishing lists', result: 'Not listed yet', sev: 'info' },
  { name: 'Certificate', result: 'Valid, first issued 3 days ago', sev: 'medium' },
  { name: 'Security settings', result: '2 protections missing', sev: 'low' },
] as const

function Check() {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true">
      <path d="M3 7.2l2.6 2.6L11 4.4" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function Spinner() {
  return (
    <svg className="spin" width="14" height="14" viewBox="0 0 14 14" aria-hidden="true">
      <circle cx="7" cy="7" r="5.5" fill="none" stroke="currentColor" strokeOpacity="0.25" strokeWidth="1.6" />
      <path d="M7 1.5a5.5 5.5 0 0 1 5.5 5.5" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  )
}

export function HeroWindow() {
  const [paused, setPaused] = useState(false)

  return (
    <div
      className={`window loop relative ${paused ? 'is-paused' : ''}`}
      role="img"
      aria-label="TrustLens checking paypa1-secure-login.com: five checks complete, verdict High Risk"
    >
      <div className="flex h-11 items-center gap-2 border-b border-line px-4">
        <span className="h-2.5 w-2.5 rounded-full bg-line-strong" />
        <span className="h-2.5 w-2.5 rounded-full bg-line-strong" />
        <span className="h-2.5 w-2.5 rounded-full bg-line-strong" />
        <span className="ml-3 font-mono text-[13px] text-faint">trustlens / check</span>
      </div>

      <div className="p-5 sm:p-6">
        <div className="flex gap-2">
          <div className="field flex h-11 min-w-0 flex-1 items-center px-3 font-mono text-[14px] text-ink">
            <span className="truncate">https://paypa1-secure-login.com/verify</span>
          </div>
          <span className="btn btn-primary pointer-events-none h-11 px-4">Check</span>
        </div>

        <ul className="mt-5 divide-y divide-line rounded-[var(--radius-lg)] border border-line bg-sunken">
          {ROWS.map((row, i) => (
            <li key={row.name} className="flex h-12 items-center gap-3 px-4 text-[14px]">
              <span className="relative inline-flex h-4 w-4 items-center justify-center text-muted">
                <span className="wait absolute inset-0 flex items-center justify-center" data-step={i + 1}>
                  <Spinner />
                </span>
                <span className="done absolute inset-0 flex items-center justify-center text-ink" data-step={i + 1}>
                  <Check />
                </span>
              </span>
              <span className="w-[42%] shrink-0 truncate text-ink sm:w-44">{row.name}</span>
              <span className="done flex min-w-0 flex-1 items-center justify-end gap-3" data-step={i + 1}>
                <span className="hidden truncate text-muted sm:inline">{row.result}</span>
                <SeverityTag sev={row.sev} />
              </span>
            </li>
          ))}
        </ul>

        <div className="verdict mt-5 border-t border-line pt-5" data-step="v">
          <div className="flex flex-wrap items-center gap-3">
            <RiskBadge level="high_risk" size="lg" />
            <span className="text-[14px] text-faint">2 high findings, 5 of 5 checks ran</span>
          </div>
          <p className="mt-3 text-[15px] leading-relaxed text-muted">
            This page copies PayPal’s name with a 1 in place of the l, and the domain is four days old. Do not sign
            in or enter card details.
          </p>
        </div>
      </div>

      <button
        type="button"
        onClick={() => setPaused((p) => !p)}
        aria-label={paused ? 'Play the demo' : 'Pause the demo'}
        className="absolute bottom-3 right-3 flex h-8 w-8 items-center justify-center rounded-full border border-line-strong bg-raised text-muted transition-colors hover:text-ink"
      >
        <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true">
          {paused ? <path d="M3 2l7 4-7 4z" fill="currentColor" /> : <path d="M3 2h2v8H3zM7 2h2v8H7z" fill="currentColor" />}
        </svg>
      </button>
    </div>
  )
}
