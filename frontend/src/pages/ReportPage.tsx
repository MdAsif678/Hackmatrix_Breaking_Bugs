// Full investigation report. Owner: P1 (RegistryPanel is P4's).
import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api/client'
import { CheckSection } from '../components/CheckSection'
import { RISK_META } from '../components/labels'
import { RiskBadge } from '../components/RiskBadge'
import { RegistryPanel } from '../features/registry/RegistryPanel'
import type { AnalysisReport } from '../types'

export default function ReportPage() {
  const { id } = useParams()
  const [report, setReport] = useState<AnalysisReport | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!id) return
    api.getReport(id).then(setReport).catch((e: Error) => setError(e.message))
  }, [id])

  if (error) return <p className="text-red-300">Could not load report: {error}</p>
  if (!report) return <p className="text-slate-400">Loading report…</p>

  const findingsCount = report.checks.reduce((n, c) => n + c.findings.length, 0)
  const indicatorEntries = Object.entries(report.extracted_indicators).filter(([, v]) => v.length > 0)

  return (
    <div className="grid gap-6">
      {/* Verdict */}
      <section className="rounded-2xl border border-slate-800 bg-slate-900/50 p-6">
        <div className="flex flex-wrap items-center gap-4">
          <RiskBadge level={report.risk_level} size="lg" />
          <div className="min-w-0 flex-1">
            <p className="truncate font-mono text-sm text-slate-300" title={report.input}>
              {report.input_type === 'message' ? 'Pasted message' : report.normalized_target ?? report.input}
            </p>
            <p className="text-xs text-slate-500">
              Analysed {new Date(report.created_at).toLocaleString()} · {findingsCount} finding(s) · evidence
              coverage {Math.round(report.coverage * 100)}%
            </p>
          </div>
        </div>
        <p className="mt-4 text-sm text-slate-400">{RISK_META[report.risk_level].description}</p>
        <ul className="mt-2 list-inside list-disc text-sm text-slate-300">
          {report.risk_reasons.map((r) => (
            <li key={r}>{r}</li>
          ))}
        </ul>
      </section>

      {/* AI explanation */}
      {report.explanation && (
        <section className="rounded-xl border border-sky-900/60 bg-sky-950/20 p-5">
          <h2 className="font-semibold text-sky-300">What this means</h2>
          <p className="mt-2">{report.explanation.summary}</p>
          {report.explanation.key_points.length > 0 && (
            <ul className="mt-3 grid gap-1 text-sm text-slate-300">
              {report.explanation.key_points.map((k) => (
                <li key={k}>• {k}</li>
              ))}
            </ul>
          )}
        </section>
      )}

      {/* Recommendations */}
      {report.recommendations.length > 0 && (
        <section className="rounded-xl border border-slate-800 p-5">
          <h2 className="font-semibold">Recommended actions</h2>
          <ul className="mt-2 grid gap-1 text-sm text-slate-300">
            {report.recommendations.map((r) => (
              <li key={r}>✓ {r}</li>
            ))}
          </ul>
        </section>
      )}

      {/* Message input + extracted indicators */}
      {report.input_type === 'message' && (
        <section className="rounded-xl border border-slate-800 p-5">
          <h2 className="font-semibold">Submitted message</h2>
          <p className="mt-2 whitespace-pre-wrap rounded-lg bg-slate-900 p-3 text-sm text-slate-300">{report.input}</p>
        </section>
      )}
      {indicatorEntries.length > 0 && (
        <section className="rounded-xl border border-slate-800 p-5">
          <h2 className="font-semibold">Extracted indicators</h2>
          <dl className="mt-2 grid gap-2 text-sm">
            {indicatorEntries.map(([kind, values]) => (
              <div key={kind} className="flex gap-3">
                <dt className="w-24 shrink-0 capitalize text-slate-500">{kind.replace('_', ' ')}</dt>
                <dd className="grid gap-0.5 break-all font-mono text-xs text-slate-300">
                  {values.map((v) => (
                    <span key={v}>{v}</span>
                  ))}
                </dd>
              </div>
            ))}
          </dl>
        </section>
      )}

      {/* Per-check evidence */}
      <section className="grid gap-3">
        <h2 className="text-lg font-semibold">Evidence by check</h2>
        {report.checks.map((c, i) => (
          <CheckSection key={`${c.check}-${c.target}-${i}`} check={c} />
        ))}
      </section>

      {/* Related reports */}
      {report.related_report_ids.length > 0 && (
        <section className="rounded-xl border border-slate-800 p-5">
          <h2 className="font-semibold">Related reports</h2>
          <ul className="mt-2 grid gap-1 text-sm">
            {report.related_report_ids.map((rid) => (
              <li key={rid}>
                <Link to={`/report/${rid}`} className="font-mono text-sky-400 hover:underline">{rid}</Link>
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* Limitations */}
      <section className="rounded-xl border border-slate-800 p-5">
        <h2 className="font-semibold">Limitations & unavailable checks</h2>
        <ul className="mt-2 list-inside list-disc text-sm text-slate-400">
          {report.limitations.map((l) => (
            <li key={l}>{l}</li>
          ))}
        </ul>
      </section>

      {/* On-chain registry (P4) */}
      <RegistryPanel report={report} onRegistered={(chain) => setReport({ ...report, chain })} />
    </div>
  )
}
