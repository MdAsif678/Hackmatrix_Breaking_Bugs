// List of past investigations. Owner: P1.
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

  if (error) return <p className="text-red-300">Could not load history: {error}</p>
  if (!reports) return <p className="text-slate-400">Loading…</p>

  return (
    <div>
      <h1 className="text-2xl font-bold">Investigation history</h1>
      {reports.length === 0 ? (
        <p className="mt-4 text-slate-400">
          No investigations yet. <Link to="/" className="text-sky-400 hover:underline">Start one</Link>.
        </p>
      ) : (
        <ul className="mt-6 divide-y divide-slate-800 rounded-xl border border-slate-800">
          {reports.map((r) => (
            <li key={r.id}>
              <Link to={`/report/${r.id}`} className="flex items-center gap-4 px-4 py-3 hover:bg-slate-900">
                <RiskBadge level={r.risk_level} />
                <span className="min-w-0 flex-1 truncate font-mono text-sm">
                  {r.input_type === 'message' ? `✉ ${r.input}` : r.normalized_target ?? r.input}
                </span>
                {r.chain && <span className="text-xs text-violet-300">on-chain</span>}
                <span className="shrink-0 text-xs text-slate-500">{new Date(r.created_at).toLocaleString()}</span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
