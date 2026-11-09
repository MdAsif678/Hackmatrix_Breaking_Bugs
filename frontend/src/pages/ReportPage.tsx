// Full investigation report. Owner: P1 (RegistryPanel is P4's).
import { useEffect, useState, type ReactNode } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api/client'
import { CheckSection } from '../components/CheckSection'
import { CHECK_LABEL, RISK_META } from '../components/labels'
import { RiskBadge } from '../components/RiskBadge'
import { SeverityLegend, SeverityTag } from '../components/Severity'
import { RegistryPanel } from '../features/registry/RegistryPanel'
import type { AnalysisReport, Finding, RelatedReport, Severity } from '../types'

function SideBlock({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="border-t border-line pt-5">
      <h2 className="text-[15px] font-medium">{title}</h2>
      <div className="mt-3">{children}</div>
    </section>
  )
}

function RelatedList({ items, showShared }: { items: RelatedReport[]; showShared: boolean }) {
  return (
    <ul className="grid gap-2">
      {items.map((r) => (
        <li key={r.report_id}>
          <Link to={`/report/${r.report_id}`} className="panel card-link block px-4 py-3">
            <span className="flex items-center justify-between gap-3">
              <span className="min-w-0 truncate font-mono text-[13px] text-ink">{r.label ?? r.report_id}</span>
              {r.risk_level && <RiskBadge level={r.risk_level} />}
            </span>
            {showShared ? (
              <span className="mt-2 flex flex-wrap gap-1.5">
                {r.shared_indicators.slice(0, 3).map((s) => (
                  <span key={s} className="max-w-full truncate rounded-sm border border-line px-1.5 py-0.5 font-mono text-[12px] text-muted">
                    {s.length > 48 ? `${s.slice(0, 48)}…` : s}
                  </span>
                ))}
              </span>
            ) : (
              r.created_at && <span className="mt-1 block text-[13px] text-faint">{new Date(r.created_at).toLocaleString()}</span>
            )}
          </Link>
        </li>
      ))}
    </ul>
  )
}

// "[tls.expired] The certificate…" -> the cited finding's severity tag + the sentence (no internal ids)
function KeyPoint({ text, findings }: { text: string; findings: Map<string, Finding> }) {
  const m = text.match(/^\[([^\]]+)\]\s*(.*)$/)
  const finding = m ? findings.get(m[1]) : undefined
  return (
    <li className="grid gap-2 py-3 sm:grid-cols-[84px_1fr] sm:gap-4">
      <span>{finding && <SeverityTag sev={finding.severity} />}</span>
      <span className="text-[15px] leading-relaxed text-muted">{m ? m[2] : text}</span>
    </li>
  )
}

const RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }

// The verdict in plain words: the titles of the findings that drove it, most serious first.
function verdictReason(report: AnalysisReport, all: Finding[]): string {
  if (report.risk_level === 'inconclusive') {
    const ran = report.checks.filter((c) => c.status === 'ok').length
    return `Only ${ran} of ${report.checks.length} checks could run, so there is not enough evidence either way.`
  }
  const main = all.filter((f) => RANK[f.severity] >= 2).sort((a, b) => RANK[b.severity] - RANK[a.severity])
  if (!main.length) return 'Nothing serious was found in the checks that ran.'
  const titles = [...new Set(main.map((f) => f.title))].slice(0, 3)
  return `Main reason${titles.length > 1 ? 's' : ''}: ${titles.join('; ')}.`
}

export default function ReportPage() {
  const { id } = useParams()
  const [report, setReport] = useState<AnalysisReport | null>(null)
  const [related, setRelated] = useState<RelatedReport[]>([])
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!id) return
    api.getReport(id).then(setReport).catch((e: Error) => setError(e.message))
    // Correlations are computed live, so this also shows reports submitted after this one.
    api.correlations(id).then((r) => setRelated(r.related)).catch(() => setRelated([]))
  }, [id])

  if (error) return <p className="text-risk-malicious">Could not load this report: {error}</p>
  if (!report) return <p className="text-muted">Loading the report…</p>

  const allFindings = report.checks.flatMap((c) => c.findings)
  const findingsById = new Map(allFindings.map((f) => [f.id, f]))
  const findingsCount = allFindings.length
  const ran = report.checks.filter((c) => c.status === 'ok').length
  const sameSite = related.filter((r) => r.relation === 'same_site')
  const campaign = related.filter((r) => r.relation !== 'same_site')
  const indicatorEntries = Object.entries(report.extracted_indicators).filter(([, v]) => v.length > 0)
  const target = report.input_type === 'message' ? 'Pasted message' : report.normalized_target ?? report.input

  return (
    <div>
      <Link to="/check" className="link text-[14px] text-muted">
        New check
      </Link>

      {/* Verdict */}
      <header className="mt-6 border-b border-line pb-8">
        <RiskBadge level={report.risk_level} size="lg" />
        <h1 className="mt-4 break-all font-mono text-[clamp(20px,1.2vw+14px,28px)] leading-snug tracking-[-0.01em]" title={report.input}>
          {target}
        </h1>
        <p className="mt-2 text-[14px] text-faint">
          {new Date(report.created_at).toLocaleString()} · {ran} of {report.checks.length} checks ran · {findingsCount}{' '}
          finding{findingsCount === 1 ? '' : 's'}
        </p>
        <p className="mt-4 max-w-[62ch] text-[16px] text-muted">
          {RISK_META[report.risk_level].description} {verdictReason(report, allFindings)}
        </p>
      </header>

      <div className="mt-10 grid gap-12 lg:grid-cols-12 lg:gap-6">
        <div className="min-w-0 space-y-12 lg:col-span-8">
          {report.explanation && (
            <section>
              <h2 className="t-label">What this means</h2>
              <p className="mt-2 max-w-[62ch] border-l-2 border-action pl-4 text-[18px] leading-relaxed">
                {report.explanation.summary}
              </p>
              {report.explanation.key_points.length > 0 && (
                <ul className="mt-4 divide-y divide-line border-y border-line">
                  {report.explanation.key_points.map((k) => (
                    <KeyPoint key={k} text={k} findings={findingsById} />
                  ))}
                </ul>
              )}
            </section>
          )}

          {report.input_type === 'message' && (
            <section>
              <h2 className="t-label">The message you pasted</h2>
              <p className="panel mt-2 whitespace-pre-wrap p-4 text-[15px] leading-relaxed text-muted">{report.input}</p>
              {indicatorEntries.length > 0 && (
                <dl className="mt-4 grid gap-2 text-[14px]">
                  {indicatorEntries.map(([kind, values]) => (
                    <div key={kind} className="grid grid-cols-[110px_1fr] gap-3">
                      <dt className="capitalize text-faint">{kind.replace('_', ' ')}</dt>
                      <dd className="grid gap-1 break-all font-mono text-[13px] text-ink">
                        {values.map((v) => (
                          <span key={v}>{v}</span>
                        ))}
                      </dd>
                    </div>
                  ))}
                </dl>
              )}
            </section>
          )}

          <section>
            <h2 className="t-h3">Evidence by check</h2>
            <p className="mt-1 text-[15px] text-muted">What each check looked at, what it found and how serious it is.</p>
            <div className="panel mt-4 px-5 py-4">
              <SeverityLegend />
            </div>
            <div className="mt-4 grid gap-4">
              {report.checks.map((c, i) => (
                <CheckSection key={`${c.check}-${c.target}-${i}`} check={c} />
              ))}
            </div>
          </section>
        </div>

        <aside className="space-y-8 lg:col-span-4">
          {report.recommendations.length > 0 && (
            <SideBlock title="What to do">
              <ul className="grid gap-2.5">
                {report.recommendations.map((r) => (
                  <li key={r} className="flex gap-3 text-[15px] leading-relaxed text-muted">
                    <span className="mt-[9px] h-1.5 w-1.5 shrink-0 rounded-full bg-ink" aria-hidden="true" />
                    {r}
                  </li>
                ))}
              </ul>
            </SideBlock>
          )}

          {sameSite.length > 0 && (
            <SideBlock title={`Checked ${sameSite.length} other time${sameSite.length > 1 ? 's' : ''}`}>
              <p className="mb-3 text-[14px] text-faint">Earlier results for the same address. Each check is run fresh.</p>
              <RelatedList items={sameSite} showShared={false} />
            </SideBlock>
          )}

          {campaign.length > 0 && (
            <SideBlock title="Possibly the same campaign">
              <p className="mb-3 text-[14px] text-faint">
                Other sites or messages that share a domain, server, certificate or contact detail with this one.
              </p>
              <RelatedList items={campaign} showShared />
            </SideBlock>
          )}

          <RegistryPanel report={report} onRegistered={(chain) => setReport({ ...report, chain })} />

          <SideBlock title="Limitations">
            <ul className="grid gap-2 text-[14px] leading-relaxed text-faint">
              {report.limitations.map((l) => {
                // "[tls] text" -> "Certificate and trust: text"
                const m = l.match(/^\[(\w+)\]\s*(.*)$/)
                const name = m && m[1] in CHECK_LABEL ? CHECK_LABEL[m[1] as keyof typeof CHECK_LABEL] : null
                return (
                  <li key={l}>
                    {name && <span className="text-muted">{name}: </span>}
                    {m ? m[2] : l}
                  </li>
                )
              })}
            </ul>
          </SideBlock>
        </aside>
      </div>
    </div>
  )
}
