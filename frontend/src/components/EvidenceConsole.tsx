import { useState } from 'react'
import type { CheckName, CheckResult } from '../types'
import { CheckSection } from './CheckSection'
import { CHECK_LABEL } from './labels'
import { SeverityLegend } from './Severity'

type FilterMode = 'all' | 'issues' | 'clean' | CheckName

export function EvidenceConsole({ checks }: { checks: CheckResult[] }) {
  const [filter, setFilter] = useState<FilterMode>('all')

  const totalChecks = checks.length
  const issuesChecks = checks.filter((c) => c.findings.some((f) => f.severity !== 'info'))
  const cleanChecks = checks.filter((c) => !c.findings.some((f) => f.severity !== 'info') && c.status === 'ok')

  const filteredChecks = checks.filter((c) => {
    if (filter === 'all') return true
    if (filter === 'issues') return c.findings.some((f) => f.severity !== 'info')
    if (filter === 'clean') return !c.findings.some((f) => f.severity !== 'info') && c.status === 'ok'
    return c.check === filter
  })

  return (
    <section className="space-y-4">
      {/* Console Header & Filter Bar */}
      <div className="flex flex-col gap-4 border-b border-line pb-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h2 className="text-[20px] font-medium tracking-tight text-ink">Evidence by Check</h2>
          <p className="mt-1 text-[14px] text-muted">
            Independent security analyzers executed in parallel.
          </p>
        </div>

        {/* View Filter Segmented Controls */}
        <div className="inline-flex rounded-lg border border-line bg-sunken p-1 text-[13px] font-medium">
          <button
            type="button"
            onClick={() => setFilter('all')}
            className={`rounded-md px-3 py-1.5 transition-colors ${
              filter === 'all'
                ? 'bg-raised text-ink shadow-sm'
                : 'text-muted hover:text-ink'
            }`}
          >
            All ({totalChecks})
          </button>

          {issuesChecks.length > 0 && (
            <button
              type="button"
              onClick={() => setFilter('issues')}
              className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 transition-colors ${
                filter === 'issues'
                  ? 'bg-raised text-risk-high shadow-sm'
                  : 'text-muted hover:text-risk-high'
              }`}
            >
              <span className="h-1.5 w-1.5 rounded-full bg-risk-high" />
              Issues ({issuesChecks.length})
            </button>
          )}

          <button
            type="button"
            onClick={() => setFilter('clean')}
            className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 transition-colors ${
              filter === 'clean'
                ? 'bg-raised text-risk-low shadow-sm'
                : 'text-muted hover:text-risk-low'
            }`}
          >
            <span className="h-1.5 w-1.5 rounded-full bg-risk-low" />
            Clean ({cleanChecks.length})
          </button>
        </div>
      </div>

      {/* Horizontal Check Navigation Chips */}
      <div className="flex flex-wrap items-center gap-2 overflow-x-auto py-1 text-[13px]">
        {checks.map((c) => {
          const hasIssues = c.findings.some((f) => f.severity !== 'info')
          const isSelected = filter === c.check
          return (
            <button
              key={c.check}
              type="button"
              onClick={() => setFilter(isSelected ? 'all' : c.check)}
              className={`inline-flex items-center gap-2 rounded-full border px-3 py-1.5 font-mono text-[12px] transition-all ${
                isSelected
                  ? 'border-link bg-link/10 text-link'
                  : 'border-line bg-raised text-muted hover:border-line-strong hover:text-ink'
              }`}
            >
              <span
                className={`h-2 w-2 rounded-full ${
                  c.status !== 'ok'
                    ? 'bg-zinc-500'
                    : hasIssues
                    ? 'bg-risk-high'
                    : 'bg-risk-low'
                }`}
              />
              <span>{CHECK_LABEL[c.check].split(' ')[0]}</span>
              {hasIssues && (
                <span className="rounded bg-risk-high/20 px-1 py-0.2 text-[10px] text-risk-high">
                  {c.findings.filter((f) => f.severity !== 'info').length}
                </span>
              )}
            </button>
          )
        })}
      </div>

      {/* Compact Severity Reference Bar */}
      <div className="rounded-lg border border-line bg-raised/50 px-4 py-3">
        <SeverityLegend />
      </div>

      {/* Rendered Check Cards List */}
      <div className="grid gap-4 pt-2">
        {filteredChecks.length > 0 ? (
          filteredChecks.map((c, i) => (
            <CheckSection key={`${c.check}-${c.target}-${i}`} check={c} />
          ))
        ) : (
          <div className="panel p-8 text-center text-muted">
            <p className="text-[15px]">No checks match the current filter.</p>
            <button
              type="button"
              onClick={() => setFilter('all')}
              className="mt-3 text-[13px] text-link hover:underline"
            >
              Show all checks
            </button>
          </div>
        )}
      </div>
    </section>
  )
}

