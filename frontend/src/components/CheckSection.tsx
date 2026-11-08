import { useState } from 'react'
import type { CheckResult } from '../types'
import { FindingCard } from './FindingCard'
import { CHECK_LABEL, STATUS_CLASS } from './labels'

export function CheckSection({ check }: { check: CheckResult }) {
  const [showData, setShowData] = useState(false)
  const hasData = Object.keys(check.data).length > 0

  return (
    <section className="rounded-xl border border-slate-800 bg-slate-900/30 p-4">
      <header className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <h3 className="font-semibold">{CHECK_LABEL[check.check]}</h3>
        <span className={`text-xs font-medium uppercase ${STATUS_CLASS[check.status]}`}>{check.status}</span>
        {check.target && <span className="truncate text-xs text-slate-500">{check.target}</span>}
        <span className="ml-auto text-xs text-slate-600">{check.duration_ms} ms</span>
      </header>

      {check.findings.length > 0 ? (
        <div className="mt-3 grid gap-2">
          {check.findings.map((f) => (
            <FindingCard key={f.id} finding={f} />
          ))}
        </div>
      ) : (
        check.status === 'ok' && <p className="mt-2 text-sm text-slate-400">No findings from this check.</p>
      )}

      {check.limitations.length > 0 && (
        <ul className="mt-3 list-inside list-disc text-xs text-slate-500">
          {check.limitations.map((l) => (
            <li key={l}>{l}</li>
          ))}
        </ul>
      )}

      {hasData && (
        <div className="mt-3">
          <button
            type="button"
            onClick={() => setShowData((s) => !s)}
            className="text-xs text-sky-400 hover:underline"
          >
            {showData ? 'Hide' : 'Show'} technical details
          </button>
          {showData && (
            <pre className="mt-2 max-h-80 overflow-auto rounded-lg bg-slate-950 p-3 text-xs text-slate-300">
              {JSON.stringify(check.data, null, 2)}
            </pre>
          )}
        </div>
      )}
    </section>
  )
}
