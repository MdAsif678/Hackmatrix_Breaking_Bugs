// Full investigation report. Owner: P1 (RegistryPanel is P4's).
import { useEffect, useState, type ReactNode } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api/client'
import { CHECK_LABEL } from '../components/labels'
import { RiskBadge } from '../components/RiskBadge'
import { SeverityTag } from '../components/Severity'
import { EvidenceConsole } from '../components/EvidenceConsole'
import { OverviewStatCards } from '../components/dashboard/OverviewStatCards'
import { SecurityPostureGauge } from '../components/dashboard/SecurityPostureGauge'
import { ThreatDistributionCard } from '../components/dashboard/ThreatDistributionCard'
import { PipelineTimeline } from '../components/dashboard/PipelineTimeline'
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
  const sameSite = related.filter((r) => r.relation === 'same_site')
  const campaign = related.filter((r) => r.relation !== 'same_site')
  const indicatorEntries = Object.entries(report.extracted_indicators).filter(([, v]) => v.length > 0)

  const targetLabel =
    report.input_type === 'message'
      ? 'Pasted Message / SMS'
      : report.normalized_target ?? report.input

  return (
    <div className="space-y-8">
      {/* Top Breadcrumb & Metadata */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line pb-4">
        <div className="flex items-center gap-3">
          <Link to="/check" className="link text-[13px] text-muted">
            ← Back to Checker
          </Link>
          <span className="text-line-strong">/</span>
          <span className="font-mono text-[13px] text-faint truncate max-w-md">
            {targetLabel}
          </span>
        </div>
        <div className="flex items-center gap-3 text-xs text-faint font-mono">
          <span>Analyzed {new Date(report.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
          <span>·</span>
          <span>{report.id.slice(0, 8)}</span>
        </div>
      </div>

      {/* 1. Overview Stat Cards Row (Inspired by CyberShield Dashboard Top Cards) */}
      <div id="overview-top">
        <OverviewStatCards report={report} findings={allFindings} />
      </div>

      {/* 2. Visual Intelligence Split (Security Posture Gauge + Analyzer Distribution) */}
      <div id="posture-gauge" className="grid gap-6 lg:grid-cols-2">
        <SecurityPostureGauge report={report} reason={verdictReason(report, allFindings)} />
        <ThreatDistributionCard checks={report.checks} />
      </div>

      {/* 3. Main Workspace: Evidence Console (Left) + Intelligence Actions (Right) */}
      <div className="grid gap-8 lg:grid-cols-12 lg:gap-6">
        <div className="min-w-0 space-y-8 lg:col-span-8">
          {report.explanation && (
            <section id="ai-grounding" className="panel border border-line bg-raised p-5 sm:p-6">
              <h2 className="text-[14px] font-medium text-ink">AI Evidence Grounding & Threat Synthesis</h2>
              <p className="mt-3 max-w-[64ch] border-l-2 border-link pl-4 text-[16px] leading-relaxed text-ink">
                {report.explanation.summary}
              </p>
              {report.explanation.key_points.length > 0 && (
                <ul className="mt-5 divide-y divide-line border-t border-line">
                  {report.explanation.key_points.map((k) => (
                    <KeyPoint key={k} text={k} findings={findingsById} />
                  ))}
                </ul>
              )}
            </section>
          )}

          {report.input_type === 'message' && (
            <section className="panel border border-line bg-raised p-5 sm:p-6">
              <h2 className="text-[14px] font-medium text-ink">Extracted Message Content & Telemetry</h2>
              <p className="mt-3 whitespace-pre-wrap rounded-md border border-line bg-sunken p-4 font-mono text-[13px] leading-relaxed text-muted">
                {report.input}
              </p>
              {indicatorEntries.length > 0 && (
                <dl className="mt-4 grid gap-2.5 text-[13px]">
                  {indicatorEntries.map(([kind, values]) => (
                    <div key={kind} className="grid grid-cols-[120px_1fr] gap-3">
                      <dt className="capitalize text-faint">{kind.replace('_', ' ')}</dt>
                      <dd className="grid gap-1 break-all font-mono text-[12px] text-ink">
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

          {/* Interactive Evidence Console with Filter Tabs and Check Chips */}
          <div id="evidence-console">
            <EvidenceConsole checks={report.checks} />
          </div>
        </div>

        {/* Sidebar: Pipeline, Registry, Recommendations, Correlations, Limitations */}
        <aside className="space-y-6 lg:col-span-4">
          {/* Top-to-Bottom Animated Pipeline Stepper at the side of screen */}
          <PipelineTimeline report={report} />

          <div id="registry-panel">
            <RegistryPanel report={report} onRegistered={(chain) => setReport({ ...report, chain })} />
          </div>

          {report.recommendations.length > 0 && (
            <SideBlock title="Security Recommendations">
              <ul className="grid gap-2.5">
                {report.recommendations.map((r) => (
                  <li key={r} className="flex gap-3 text-[13px] leading-relaxed text-muted">
                    <span className="mt-[7px] h-1.5 w-1.5 shrink-0 rounded-full bg-link" aria-hidden="true" />
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
            <SideBlock title="Correlated Infrastructure">
              <p className="mb-3 text-[13px] text-faint">
                Other investigations sharing infrastructure (IP, domain, or certificates).
              </p>
              <RelatedList items={campaign} showShared />
            </SideBlock>
          )}

          <details className="panel group border-line bg-raised/70 p-4">
            <summary className="flex cursor-pointer list-none items-center justify-between text-[13px] font-medium text-muted transition-colors hover:text-ink">
              <span className="flex items-center gap-2">
                <svg className="h-4 w-4 text-faint" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10" />
                  <path d="M12 16v-4" />
                  <path d="M12 8h.01" />
                </svg>
                Audit Scope & Limitations ({report.limitations.length})
              </span>
              <svg className="h-4 w-4 text-faint transition-transform duration-200 group-open:rotate-180" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="m6 9 6 6 6-6" />
              </svg>
            </summary>
            <ul className="mt-3 grid gap-2 border-t border-line pt-3 text-[12px] leading-relaxed text-faint">
              {report.limitations.map((l) => {
                const m = l.match(/^\[(\w+)\]\s*(.*)$/)
                const name = m && m[1] in CHECK_LABEL ? CHECK_LABEL[m[1] as keyof typeof CHECK_LABEL] : null
                return (
                  <li key={l}>
                    {name && <span className="font-medium text-muted">{name}: </span>}
                    {m ? m[2] : l}
                  </li>
                )
              })}
            </ul>
          </details>
        </aside>
      </div>
    </div>
  )
}
