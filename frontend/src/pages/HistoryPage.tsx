// List of past checks. Owner: P1.
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import { RiskBadge } from '../components/RiskBadge'
import type { AnalysisReport } from '../types'

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
        {error && <p className="text-risk-malicious">Could not load the history: {error}</p>}
        {!error && !reports && <p className="text-muted">Loading…</p>}
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
            <div className="hidden grid-cols-[180px_1fr_170px] gap-6 border-b border-line bg-sunken px-5 py-3 md:grid">
              <span className="t-label">Verdict</span>
              <span className="t-label">Link or message</span>
              <span className="t-label">Checked</span>
            </div>
            <ul className="divide-y divide-line">
              {reports.map((r) => (
                <li key={r.id}>
                  <Link
                    to={`/report/${r.id}`}
                    className="grid gap-2 px-5 py-4 transition-colors hover:bg-[rgb(237_237_239/0.03)] md:grid-cols-[180px_1fr_170px] md:items-center md:gap-6"
                  >
                    <span className="flex items-center gap-2">
                      <RiskBadge level={r.risk_level} />
                      {r.chain && <span className="text-[12px] text-faint">sealed</span>}
                    </span>
                    <span className="min-w-0 truncate font-mono text-[14px] text-ink">
                      {r.input_type === 'message' ? `Message: ${r.input}` : r.normalized_target ?? r.input}
                    </span>
                    <span className="text-[13px] text-faint">{new Date(r.created_at).toLocaleString()}</span>
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  )
}
