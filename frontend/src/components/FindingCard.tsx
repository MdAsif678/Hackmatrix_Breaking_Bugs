import type { Finding } from '../types'
import { SEVERITY_CLASS } from './labels'

export function FindingCard({ finding }: { finding: Finding }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className={`rounded px-2 py-0.5 text-xs font-semibold uppercase ${SEVERITY_CLASS[finding.severity]}`}>
          {finding.severity}
        </span>
        <span className="font-medium">{finding.title}</span>
        {finding.authoritative && (
          <span className="rounded bg-red-600/30 px-2 py-0.5 text-xs font-semibold text-red-200">
            Threat-intel match
          </span>
        )}
        <code className="ml-auto text-xs text-slate-500">{finding.id}</code>
      </div>
      <dl className="mt-2 grid gap-1 text-sm">
        <div className="flex gap-2">
          <dt className="w-28 shrink-0 text-slate-500">Evidence</dt>
          <dd className="break-all font-mono text-xs text-slate-300">{finding.evidence}</dd>
        </div>
        <div className="flex gap-2">
          <dt className="w-28 shrink-0 text-slate-500">Source</dt>
          <dd className="text-slate-300">{finding.source}</dd>
        </div>
        {finding.impact && (
          <div className="flex gap-2">
            <dt className="w-28 shrink-0 text-slate-500">Impact</dt>
            <dd className="text-slate-300">{finding.impact}</dd>
          </div>
        )}
        {finding.recommendation && (
          <div className="flex gap-2">
            <dt className="w-28 shrink-0 text-slate-500">Recommendation</dt>
            <dd className="text-slate-300">{finding.recommendation}</dd>
          </div>
        )}
      </dl>
    </div>
  )
}
