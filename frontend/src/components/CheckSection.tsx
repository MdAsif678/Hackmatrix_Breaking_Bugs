import { useState } from 'react'
import type { CheckResult } from '../types'
import { checkSummary } from './checkSummary'
import { FindingCard } from './FindingCard'
import { CHECK_LABEL, STATUS_LABEL } from './labels'

const STATUS_COLOR = { ok: 'text-risk-low', error: 'text-risk-suspicious', skipped: 'text-faint' } as const

export function CheckSection({ check }: { check: CheckResult }) {
  const [showData, setShowData] = useState(false)
  const hasData = Object.keys(check.data).length > 0
  const notable = check.findings.filter((f) => f.severity !== 'info').length
  const summary = checkSummary(check)

  return (
    <section className="panel overflow-hidden">
      <header className="flex flex-wrap items-center gap-x-4 gap-y-1 border-b border-line px-5 py-4">
        <h3 className="text-[16px] font-medium">{CHECK_LABEL[check.check]}</h3>
        <span className={`text-[13px] font-medium ${STATUS_COLOR[check.status]}`}>{STATUS_LABEL[check.status]}</span>
        <span className="ml-auto text-[13px] text-faint">
          {check.status === 'ok' && (notable ? `${notable} issue${notable > 1 ? 's' : ''} · ` : 'No issues · ')}
          {(check.duration_ms / 1000).toFixed(1)} s
        </span>
        {check.target && check.check !== 'message' && (
          <span className="w-full truncate font-mono text-[12px] text-faint">{check.target}</span>
        )}
      </header>

      {summary && (
        <p className="flex gap-3 border-b border-line px-5 py-4 text-[15px] leading-relaxed text-muted last:border-b-0">
          {notable === 0 && (
            <svg className="mt-[5px] shrink-0 text-risk-low" width="14" height="14" viewBox="0 0 14 14" aria-hidden="true">
              <path d="M3 7.2l2.6 2.6L11 4.4" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          )}
          <span>{summary}</span>
        </p>
      )}

      {check.findings.length > 0 && (
        <ul className="divide-y divide-line">
          {check.findings.map((f) => (
            <FindingCard key={f.id} finding={f} />
          ))}
        </ul>
      )}

      {(check.limitations.length > 0 || hasData) && (
        <footer className="border-t border-line bg-sunken px-5 py-3">
          {check.limitations.length > 0 && (
            <ul className="grid gap-1 text-[13px] leading-relaxed text-faint">
              {check.limitations.map((l) => (
                <li key={l}>{l}</li>
              ))}
            </ul>
          )}
          {hasData && (
            <div className={check.limitations.length > 0 ? 'mt-2' : ''}>
              <button
                type="button"
                onClick={() => setShowData((s) => !s)}
                aria-expanded={showData}
                className="link text-[13px] text-muted"
              >
                {showData ? 'Hide' : 'Show'} technical details
              </button>
              {showData && (
                <pre className="mt-3 max-h-80 overflow-auto rounded-md border border-line bg-ground p-3 font-mono text-[12px] leading-relaxed text-muted">
                  {JSON.stringify(check.data, null, 2)}
                </pre>
              )}
            </div>
          )}
        </footer>
      )}
    </section>
  )
}
