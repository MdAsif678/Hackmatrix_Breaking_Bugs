// Severity tag + the legend that explains it. Owner: P1.
import type { Severity } from '../types'
import { SEVERITY_META, SEVERITY_ORDER } from './labels'

export function SeverityTag({ sev }: { sev: Severity }) {
  return (
    <span className="sev" data-sev={sev} title={SEVERITY_META[sev].meaning}>
      {SEVERITY_META[sev].label}
    </span>
  )
}

export function SeverityLegend() {
  return (
    <dl className="grid gap-x-6 gap-y-2 text-[13px] sm:grid-cols-2 lg:grid-cols-3">
      {SEVERITY_ORDER.map((s) => (
        <div key={s} className="flex items-start gap-3">
          <dt className="shrink-0">
            <SeverityTag sev={s} />
          </dt>
          <dd className="pt-0.5 leading-snug text-faint">{SEVERITY_META[s].meaning}</dd>
        </div>
      ))}
    </dl>
  )
}
