// The evidence on the report page: an overview of every check (click to jump to it), then each check in full,
// filterable with one sliding pill (All / With issues / No issues). Owner: P1.
import { AnimatePresence, motion } from 'motion/react'
import { useState } from 'react'
import type { CheckResult, Severity } from '../types'
import { CheckSection } from './CheckSection'
import { CHECK_LABEL } from './labels'
import { scrollToTarget } from './motion/smooth'
import { SeverityLegend, SeverityTag } from './Severity'

const RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
const ease = [0.22, 1, 0.36, 1] as const

const worstOf = (c: CheckResult) =>
  c.findings.filter((f) => f.severity !== 'info').sort((a, b) => RANK[b.severity] - RANK[a.severity])[0]
const hasIssues = (c: CheckResult) => !!worstOf(c)

/** One row per check: what it is, what it found, how long it took. Clicking jumps to the check's full section. */
export function CheckOverview({ checks }: { checks: CheckResult[] }) {
  return (
    <ul className="panel divide-y divide-line overflow-hidden">
      {checks.map((c, i) => {
        const worst = worstOf(c)
        const dot = c.status !== 'ok' ? 'bg-line-strong' : worst ? (RANK[worst.severity] >= 3 ? 'bg-risk-high' : 'bg-risk-suspicious') : 'bg-risk-low'
        return (
          <li key={`${c.check}-${i}`}>
            <button
              type="button"
              onClick={() => scrollToTarget(`#check-${i}`, -96)}
              className="group flex min-h-14 w-full items-center gap-4 px-5 py-3 text-left transition-colors hover:bg-ink/[0.025]"
            >
              <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${dot}`} />
              <span className="min-w-0 flex-1">
                <span className="block text-[15px] text-ink">{CHECK_LABEL[c.check]}</span>
                {c.target && c.check !== 'message' && checks.filter((x) => x.check === c.check).length > 1 && (
                  <span className="block truncate font-mono text-[12px] text-faint">{c.target}</span>
                )}
              </span>
              <span className="flex shrink-0 items-center gap-4">
                {c.status !== 'ok' ? (
                  <span className="text-[13px] text-faint">Could not run</span>
                ) : worst ? (
                  <SeverityTag sev={worst.severity} />
                ) : (
                  <span className="text-[13px] text-muted">No issues</span>
                )}
                <span className="hidden w-12 text-right font-mono text-[12px] text-faint sm:block">
                  {(c.duration_ms / 1000).toFixed(1)} s
                </span>
                <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true" className="text-faint transition-transform duration-200 group-hover:translate-y-0.5">
                  <path d="M3 4.5l3 3 3-3" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </span>
            </button>
          </li>
        )
      })}
    </ul>
  )
}

type Filter = 'all' | 'issues' | 'clean'

export function EvidenceConsole({ checks }: { checks: CheckResult[] }) {
  const [filter, setFilter] = useState<Filter>('all')
  const indexed = checks.map((c, i) => ({ c, i }))
  const issues = indexed.filter(({ c }) => hasIssues(c))
  const clean = indexed.filter(({ c }) => c.status === 'ok' && !hasIssues(c)) // checks that could not run are in neither
  const shown = filter === 'issues' ? issues : filter === 'clean' ? clean : indexed

  const options: { key: Filter; label: string; count: number }[] = [
    { key: 'all', label: 'All', count: checks.length },
    { key: 'issues', label: 'With issues', count: issues.length },
    { key: 'clean', label: 'No issues', count: clean.length },
  ]

  return (
    <section aria-labelledby="evidence-h">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h2 id="evidence-h" className="text-[22px] font-medium tracking-[-0.02em]">Evidence</h2>
          <p className="mt-1 text-[15px] text-muted">What each check saw, and where it came from.</p>
        </div>
        <div className="inline-flex isolate rounded-full border border-line p-1" role="tablist" aria-label="Filter checks">
          {options.map((o) => (
            <button
              key={o.key}
              type="button"
              role="tab"
              aria-selected={filter === o.key}
              aria-label={`${o.label} (${o.count})`}
              onClick={() => setFilter(o.key)}
              className="group relative h-8 rounded-full px-3.5 text-[14px] font-medium"
            >
              {filter === o.key && (
                <motion.span
                  layoutId="evidence-filter-pill"
                  className="absolute inset-0 rounded-full bg-ink"
                  transition={{ type: 'spring', stiffness: 420, damping: 36 }}
                />
              )}
              <span
                className={`relative text-white mix-blend-difference transition-opacity duration-300 ${
                  filter === o.key ? 'opacity-100' : 'opacity-60 group-hover:opacity-100'
                }`}
              >
                {o.label} <span className="tabular-nums">{o.count}</span>
              </span>
            </button>
          ))}
        </div>
      </div>

      <details className="group mt-4">
        <summary className="inline-flex cursor-pointer list-none items-center gap-1.5 text-[13px] text-faint transition-colors hover:text-muted">
          What the labels mean
          <svg width="10" height="10" viewBox="0 0 12 12" aria-hidden="true" className="transition-transform duration-200 group-open:rotate-180">
            <path d="M3 4.5l3 3 3-3" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </summary>
        <div className="mt-3">
          <SeverityLegend />
        </div>
      </details>

      <div className="mt-6 grid gap-4">
        <AnimatePresence mode="popLayout" initial={false}>
          {shown.map(({ c, i }) => (
            <motion.div
              key={`${c.check}-${i}`}
              id={`check-${i}`}
              layout
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, transition: { duration: 0.15 } }}
              transition={{ duration: 0.4, ease }}
            >
              <CheckSection check={c} />
            </motion.div>
          ))}
        </AnimatePresence>
        {shown.length === 0 && (
          <p className="panel px-5 py-8 text-center text-[15px] text-muted">
            {filter === 'issues' ? 'No check found an issue.' : 'Every check found something to look at.'}
          </p>
        )}
      </div>
    </section>
  )
}
