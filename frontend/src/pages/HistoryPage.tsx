// List of past checks. Owner: P1.
import { motion } from 'motion/react'
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { LensSpinner, Skeleton, Swap } from '../components/Loading'
import { RiskBadge } from '../components/RiskBadge'
import type { AnalysisReport } from '../types'

const ROW = 'grid gap-2 px-5 py-4 md:grid-cols-[180px_1fr_170px] md:items-center md:gap-6'

function TableHead({ loading = false }: { loading?: boolean }) {
  return (
    <div className="hidden grid-cols-[180px_1fr_170px] gap-6 border-b border-line bg-sunken px-5 py-3 md:grid">
      <span className="t-label">Verdict</span>
      <span className="t-label">Link or message</span>
      {loading ? <LensSpinner label="Loading…" className="-my-1" /> : <span className="t-label">Checked</span>}
    </div>
  )
}

/** The table's shape, in grey, while the list loads. */
function HistorySkeleton() {
  const widths = ['62%', '48%', '71%', '39%', '56%', '66%']
  return (
    <>
      {/* Phones have no table header, so the label sits above the rows there; on wider screens it takes the place of
          the "Checked" column title, so nothing moves when the real rows arrive. */}
      <LensSpinner label="Loading the history…" className="mb-4 md:hidden" />
      <div className="panel overflow-hidden">
        <TableHead loading />
        <ul className="divide-y divide-line">
          {widths.map((w, i) => (
            <li key={i} className={ROW}>
              <Skeleton className="h-[26px] w-28 rounded-full" />
              <span className="block" style={{ width: w }}>
                <Skeleton className="h-3.5 w-full" />
              </span>
              <Skeleton className="h-3 w-32" />
            </li>
          ))}
        </ul>
      </div>
    </>
  )
}

export default function HistoryPage() {
  const [reports, setReports] = useState<AnalysisReport[] | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api.listReports().then(setReports).catch((e: Error) => setError(e.message))
  }, [])

  return (
    <div>
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="t-h2">History</h1>
          <p className="t-lead mt-2">Every link and message checked on this TrustLens server, newest first.</p>
        </div>
        <Link to="/check" className="btn btn-primary">
          Check a link
        </Link>
      </div>

      <div className="mt-10">
        <Swap loading={!error && !reports} skeleton={<HistorySkeleton />}>
          {error && <p className="text-risk-malicious">Could not load the history: {error}</p>}
          {reports && reports.length === 0 && (
            <div className="panel p-8 text-muted">
              Nothing checked yet.{' '}
              <Link to="/check" className="link">
                Check your first link
              </Link>
              .
            </div>
          )}
          {reports && reports.length > 0 && (
            <div className="panel overflow-hidden">
              <TableHead />
              <ul className="divide-y divide-line">
                {reports.map((r, i) => (
                  <motion.li
                    key={r.id}
                    // The first rows arrive one after another; the rest (off screen) come in together.
                    initial={{ opacity: 0, transform: 'translateY(6px)' }}
                    animate={{ opacity: 1, transform: 'translateY(0px)', transitionEnd: { transform: 'none' } }}
                    transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1], delay: Math.min(i, 10) * 0.035 }}
                  >
                    <Link to={`/report/${r.id}`} className={`${ROW} transition-colors hover:bg-[rgb(237_237_239/0.03)]`}>
                      <span className="flex items-center gap-2">
                        <RiskBadge level={r.risk_level} />
                        {r.chain && <span className="text-[12px] text-faint">sealed</span>}
                      </span>
                      <span className="min-w-0 truncate font-mono text-[14px] text-ink">
                        {r.input_type === 'message' ? `Message: ${r.input}` : r.normalized_target ?? r.input}
                      </span>
                      <span className="text-[13px] text-faint">{new Date(r.created_at).toLocaleString()}</span>
                    </Link>
                  </motion.li>
                ))}
              </ul>
            </div>
          )}
        </Swap>
      </div>
    </div>
  )
}
