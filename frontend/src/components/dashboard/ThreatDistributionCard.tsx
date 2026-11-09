import type { CheckResult } from '../../types'
import { CHECK_LABEL } from '../labels'

interface Props {
  checks: CheckResult[]
}

export function ThreatDistributionCard({ checks }: Props) {
  return (
    <div className="panel flex flex-col justify-between border border-line bg-raised p-5 sm:p-6">
      <div className="flex items-center justify-between border-b border-line pb-3">
        <h3 className="text-[14px] font-medium text-ink">Analyzer Coverage & Distribution</h3>
        <span className="text-[12px] font-mono text-faint">
          {checks.filter((c) => c.status === 'ok').length} of {checks.length} active
        </span>
      </div>

      <div className="my-3 space-y-3">
        {checks.map((c) => {
          const notable = c.findings.filter((f) => f.severity !== 'info').length
          const isClean = notable === 0 && c.status === 'ok'

          return (
            <div key={c.check} className="space-y-1">
              <div className="flex items-center justify-between text-[13px]">
                <span className="font-mono text-ink text-[12px]">
                  {CHECK_LABEL[c.check]}
                </span>
                <span className="text-[12px] font-mono">
                  {c.status !== 'ok' ? (
                    <span className="text-zinc-500">Could not run</span>
                  ) : isClean ? (
                    <span className="text-risk-low">Clean · {(c.duration_ms / 1000).toFixed(1)}s</span>
                  ) : (
                    <span className="text-risk-high">{notable} issue{notable > 1 ? 's' : ''}</span>
                  )}
                </span>
              </div>

              {/* Progress track bar */}
              <div className="h-1.5 w-full overflow-hidden rounded-full bg-sunken border border-line">
                <div
                  className={`h-full rounded-full transition-all duration-500 ${
                    c.status !== 'ok'
                      ? 'w-1/4 bg-zinc-600'
                      : isClean
                      ? 'w-full bg-risk-low'
                      : 'w-4/5 bg-risk-high'
                  }`}
                />
              </div>
            </div>
          )
        })}
      </div>

      <div className="border-t border-line pt-3 flex items-center justify-between text-[12px] text-faint">
        <span>Zero-trust passive inspection</span>
        <span className="font-mono">Timeout limit: 8s</span>
      </div>
    </div>
  )
}

