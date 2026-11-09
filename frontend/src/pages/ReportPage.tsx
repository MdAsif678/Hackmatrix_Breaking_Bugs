// Full investigation report. Owner: P1 (RegistryPanel is P4's).
// Reads top to bottom: the verdict and the numbers behind it, what it means (the explanation), the checks at a
// glance, then the evidence in full. The sidebar holds what you can do with the report.
// Every number shown comes from the report itself; nothing is scored or estimated here.
import { motion } from 'motion/react'
import { useEffect, useState, type ReactNode } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api/client'
import { CheckOverview, EvidenceConsole } from '../components/EvidenceConsole'
import { CHECK_LABEL, RISK_META } from '../components/labels'
import { PipelineSummary } from '../components/PipelineSummary'
import { RiskBadge } from '../components/RiskBadge'
import { SeverityTag } from '../components/Severity'
import { RegistryPanel } from '../features/registry/RegistryPanel'
import type { AnalysisReport, Finding, RelatedReport, Severity } from '../types'

const ease = [0.22, 1, 0.36, 1] as const
const RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }

/** Fades and rises in, a little after the one before it. */
function Rise({ i, children, className }: { i: number; children: ReactNode; className?: string }) {
  return (
    <motion.div
      className={className}
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.7, ease, delay: 0.06 * i }}
    >
      {children}
    </motion.div>
  )
}

function SideBlock({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="border-t border-line pt-6">
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
    <li className="grid gap-2 py-3.5 sm:grid-cols-[84px_1fr] sm:gap-4">
      <span>{finding && <SeverityTag sev={finding.severity} />}</span>
      <span className="text-[15px] leading-relaxed text-muted">{m ? m[2] : text}</span>
    </li>
  )
}

// The verdict in plain words: the titles of the findings that drove it, most serious first.
function verdictReason(report: AnalysisReport, all: Finding[]): string {
  if (report.risk_level === 'inconclusive') {
    const ran = report.checks.filter((c) => c.status === 'ok').length
    return `Only ${ran} of ${report.checks.length} checks could run, so there is not enough evidence either way.`
  }
  const main = all.filter((f) => RANK[f.severity] >= 2).sort((a, b) => RANK[b.severity] - RANK[a.severity])
  if (!main.length) return 'Nothing serious was found in the checks that ran. That is not proof the site is safe.'
  const titles = [...new Set(main.map((f) => f.title))].slice(0, 3)
  return `Main reason${titles.length > 1 ? 's' : ''}: ${titles.join('; ')}.`
}

function Stat({ label, value, sub, tone }: { label: string; value: ReactNode; sub?: ReactNode; tone?: string }) {
  return (
    <div className="bg-ground px-5 py-5 sm:px-6">
      <dt className="text-[13px] text-faint">{label}</dt>
      <dd className={`mt-1.5 text-[28px] font-medium leading-none tracking-[-0.03em] tabular-nums ${tone ?? 'text-ink'}`}>{value}</dd>
      {sub && <dd className="mt-2 text-[13px] text-faint">{sub}</dd>}
    </div>
  )
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
  const sameSite = related.filter((r) => r.relation === 'same_site')
  const campaign = related.filter((r) => r.relation !== 'same_site')
  const indicatorEntries = Object.entries(report.extracted_indicators).filter(([, v]) => v.length > 0)

  const ran = report.checks.filter((c) => c.status === 'ok').length
  const serious = allFindings.filter((f) => RANK[f.severity] >= 3).length
  const warnings = allFindings.filter((f) => f.severity === 'medium').length
  const target = report.input_type === 'message' ? 'Pasted message' : (report.normalized_target ?? report.input)

  return (
    <div>
      {/* Where you are */}
      <Rise i={0} className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[13px]">
        <Link to="/check" className="link text-muted">
          Check another
        </Link>
        <span className="text-line-strong">/</span>
        <span className="min-w-0 max-w-full truncate font-mono text-faint">{target}</span>
        <span className="ml-auto font-mono text-faint">
          {new Date(report.created_at).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })}
        </span>
      </Rise>

      {/* The verdict */}
      <Rise i={1} className="mt-10">
        <RiskBadge level={report.risk_level} size="lg" />
        <h1 className="t-h2 mt-6 max-w-[22ch]">{RISK_META[report.risk_level].description}</h1>
        <p className="t-lead mt-4 max-w-[62ch]">{verdictReason(report, allFindings)}</p>
      </Rise>

      {/* The numbers behind it, all straight from the report */}
      <Rise i={2}>
        <dl className="mt-10 grid grid-cols-2 gap-px overflow-hidden rounded-xl border border-line bg-line lg:grid-cols-4">
          <Stat label="Checks that ran" value={`${ran} of ${report.checks.length}`} sub={`${Math.round(report.coverage * 100)}% coverage`} />
          <Stat label="Serious findings" value={serious} tone={serious ? 'text-risk-high' : undefined} sub="Danger or Serious" />
          <Stat label="Warnings" value={warnings} tone={warnings ? 'text-risk-suspicious' : undefined} sub="Worth a closer look" />
          <Stat
            label="Blockchain seal"
            value={report.chain ? `#${report.chain.chain_report_id}` : 'None'}
            sub={report.chain ? `On ${report.chain.network}` : 'Not sealed yet'}
          />
        </dl>
      </Rise>

      {/* How the report was made: the pipeline, compact */}
      <Rise i={3} className="mt-8">
        <p className="mb-4 text-[13px] text-faint">How this was checked</p>
        <PipelineSummary report={report} />
      </Rise>

      <div className="mt-14 grid gap-12 lg:grid-cols-12 lg:gap-6">
        <div className="min-w-0 space-y-14 lg:col-span-8">
          {report.explanation && (
            <Rise i={3}>
              <section aria-labelledby="explain-h">
                <h2 id="explain-h" className="text-[22px] font-medium tracking-[-0.02em]">What this means</h2>
                <p className="mt-4 max-w-[64ch] border-l-2 border-link pl-5 text-[18px] leading-relaxed text-ink">
                  {report.explanation.summary}
                </p>
                {report.explanation.key_points.length > 0 && (
                  <ul className="mt-6 divide-y divide-line border-y border-line">
                    {report.explanation.key_points.map((k) => (
                      <KeyPoint key={k} text={k} findings={findingsById} />
                    ))}
                  </ul>
                )}
                <p className="mt-3 text-[13px] text-faint">
                  Written by AI from the findings below. It explains the verdict; it does not decide it.
                </p>
              </section>
            </Rise>
          )}

          {report.input_type === 'message' && (
            <Rise i={4}>
              <section aria-labelledby="message-h">
                <h2 id="message-h" className="text-[22px] font-medium tracking-[-0.02em]">The message</h2>
                <p className="mt-4 whitespace-pre-wrap rounded-lg border border-line bg-sunken p-5 text-[15px] leading-relaxed text-muted">
                  {report.input}
                </p>
                {indicatorEntries.length > 0 && (
                  <dl className="mt-5 grid gap-3 text-[14px]">
                    {indicatorEntries.map(([kind, values]) => (
                      <div key={kind} className="grid grid-cols-[110px_1fr] gap-4">
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
            </Rise>
          )}

          <Rise i={5}>
            <section aria-labelledby="checks-h">
              <h2 id="checks-h" className="text-[22px] font-medium tracking-[-0.02em]">The checks at a glance</h2>
              <p className="mt-1 text-[15px] text-muted">Each ran on its own. Select one to see its evidence.</p>
              <div className="mt-5">
                <CheckOverview checks={report.checks} />
              </div>
            </section>
          </Rise>

          <EvidenceConsole checks={report.checks} />
        </div>

        <aside className="space-y-8 lg:col-span-4">
          <Rise i={4}>
            <RegistryPanel report={report} onRegistered={(chain) => setReport({ ...report, chain })} />
          </Rise>

          {report.recommendations.length > 0 && (
            <SideBlock title="What to do">
              <ul className="grid gap-3">
                {report.recommendations.map((r) => (
                  <li key={r} className="flex gap-3 text-[14px] leading-relaxed text-muted">
                    <span className="mt-[9px] h-1 w-1 shrink-0 rounded-full bg-link" aria-hidden="true" />
                    {r}
                  </li>
                ))}
              </ul>
            </SideBlock>
          )}

          {sameSite.length > 0 && (
            <SideBlock title={`Checked ${sameSite.length} other time${sameSite.length > 1 ? 's' : ''}`}>
              <p className="mb-3 text-[13px] text-faint">Earlier results for this exact address.</p>
              <RelatedList items={sameSite} showShared={false} />
            </SideBlock>
          )}

          {campaign.length > 0 && (
            <SideBlock title="Possibly the same campaign">
              <p className="mb-3 text-[13px] text-faint">Other reports that share a server, certificate, phone number or UPI ID.</p>
              <RelatedList items={campaign} showShared />
            </SideBlock>
          )}

          {report.limitations.length > 0 && (
            <details className="group border-t border-line pt-6">
              <summary className="flex cursor-pointer list-none items-center justify-between text-[15px] font-medium text-ink">
                What could not be checked
                <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true" className="text-faint transition-transform duration-200 group-open:rotate-180">
                  <path d="M3 4.5l3 3 3-3" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </summary>
              <ul className="mt-3 grid gap-2 text-[13px] leading-relaxed text-faint">
                {report.limitations.map((l) => {
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
            </details>
          )}
        </aside>
      </div>
    </div>
  )
}
