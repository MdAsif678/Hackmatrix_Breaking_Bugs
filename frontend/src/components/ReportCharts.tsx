// Report charts, in the dashboard style of the reference (dark cards, big numbers, quiet charts). Owner: P1.
// Both percentages are computed from the report, never estimated:
// - Evidence coverage: the share of checks that ran (the risk engine calls anything under 50% Inconclusive).
// - Where the warnings came from: each check's share of all warning signs, weighted by severity
//   (Danger 8, Serious 4, Warning 2, Minor 1; Notes count 0). 0% everywhere means no warning signs at all,
//   which is still not proof that a site is safe.
import { animate, motion, useInView, useMotionValue, useReducedMotion, useTransform } from 'motion/react'
import { useEffect, useRef, type ReactNode } from 'react'
import type { AnalysisReport, CheckResult, Severity } from '../types'
import { CHECK_LABEL } from './labels'

const ease = [0.22, 1, 0.36, 1] as const
const SHORT: Record<CheckResult['check'], string> = {
  url: 'Lookalike names',
  dns: 'Domain age',
  threat_intel: 'Phishing lists',
  tls: 'Certificate',
  headers: 'Website and page',
  message: 'Scam patterns',
}
const WEIGHT: Record<Severity, number> = { critical: 8, high: 4, medium: 2, low: 1, info: 0 }
const RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
const SEV_COLOR: Record<Severity, string> = {
  critical: 'var(--color-risk-malicious)',
  high: 'var(--color-risk-high)',
  medium: 'var(--color-risk-suspicious)',
  low: 'var(--color-muted)',
  info: 'var(--color-muted)',
}

/** A dark rounded card with a label row on top, as in the reference. */
export function Card({ label, aside, children, className = '' }: { label: ReactNode; aside?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <div className={`rounded-2xl border border-line bg-raised p-5 sm:p-6 ${className}`}>
      <div className="flex items-center justify-between gap-3">
        <span className="truncate text-[14px] text-muted">{label}</span>
        {aside}
      </div>
      {children}
    </div>
  )
}

/** The small status pill in a card's corner: a coloured dot and a short value. */
export function Pill({ tone, children }: { tone: 'good' | 'bad' | 'warn' | 'neutral'; children: ReactNode }) {
  const c = { good: 'var(--color-risk-low)', bad: 'var(--color-risk-high)', warn: 'var(--color-risk-suspicious)', neutral: 'var(--color-faint)' }[tone]
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-[13px] font-medium" style={{ color: c }}>
      <span className="flex h-3.5 w-3.5 items-center justify-center rounded-full" style={{ background: c }}>
        <span className="h-1 w-1 rounded-full bg-ground" />
      </span>
      {children}
    </span>
  )
}

/** A number that counts up once when it comes into view. */
export function CountUp({ value, suffix = '' }: { value: number; suffix?: string }) {
  const ref = useRef<HTMLSpanElement>(null)
  const inView = useInView(ref, { once: true })
  const reduce = useReducedMotion()
  const mv = useMotionValue(reduce ? value : 0)
  const text = useTransform(mv, (v) => `${Math.round(v)}${suffix}`)
  useEffect(() => {
    if (!inView || reduce) return
    const ctl = animate(mv, value, { duration: 1.1, ease })
    return () => ctl.stop()
  }, [inView, reduce, value, mv])
  return <motion.span ref={ref}>{text}</motion.span>
}

/** Ring with the evidence coverage percentage in the middle. */
export function CoverageRing({ report }: { report: AnalysisReport }) {
  const ref = useRef<HTMLDivElement>(null)
  const inView = useInView(ref, { once: true })
  const reduce = useReducedMotion()
  const pct = Math.round(report.coverage * 100)
  const ran = report.checks.filter((c) => c.status === 'ok').length
  const failed = report.checks.length - ran
  const r = 52
  const tone = pct >= 80 ? 'var(--color-ink)' : pct >= 50 ? 'var(--color-risk-suspicious)' : 'var(--color-risk-high)'

  return (
    <Card
      label="Evidence coverage"
      aside={<Pill tone={pct >= 80 ? 'good' : pct >= 50 ? 'warn' : 'bad'}>{ran} of {report.checks.length} ran</Pill>}
      className="flex flex-col"
    >
      <div ref={ref} className="mt-5 flex flex-1 flex-col items-center justify-center gap-5 text-center sm:flex-row sm:text-left lg:flex-col lg:text-center">
        <div className="relative shrink-0">
          <svg width="128" height="128" viewBox="0 0 128 128" className="-rotate-90" aria-hidden="true">
            <circle cx="64" cy="64" r={r} fill="none" stroke="var(--color-line)" strokeWidth="8" />
            <motion.circle
              cx="64"
              cy="64"
              r={r}
              fill="none"
              stroke={tone}
              strokeWidth="8"
              strokeLinecap="round"
              initial={{ pathLength: reduce ? report.coverage : 0 }}
              animate={{ pathLength: inView ? report.coverage : reduce ? report.coverage : 0 }}
              transition={{ duration: 1.2, ease }}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-[30px] font-medium leading-none tracking-[-0.03em] tabular-nums text-ink">
              <CountUp value={pct} suffix="%" />
            </span>
            <span className="mt-1 text-[12px] text-faint">of checks</span>
          </div>
        </div>
        <div className="min-w-0 text-[14px] leading-relaxed text-muted">
          {failed === 0 ? 'Every check ran.' : `${failed} check${failed > 1 ? 's' : ''} could not run, usually because a source did not answer in time.`}
          <p className="mt-2 text-[13px] text-faint">Under 50% the verdict is Inconclusive instead of a guess.</p>
        </div>
      </div>
    </Card>
  )
}

/** One line per check: its share of the warning signs, weighted by severity, coloured by its worst finding. */
export function WarningShare({ checks, className }: { checks: CheckResult[]; className?: string }) {
  const ref = useRef<HTMLDivElement>(null)
  const inView = useInView(ref, { once: true })
  const reduce = useReducedMotion()

  // Merge repeated checks (a message with several links runs the URL checks once per link).
  const byCheck = new Map<string, CheckResult[]>()
  for (const c of checks) byCheck.set(c.check, [...(byCheck.get(c.check) ?? []), c])
  const rows = [...byCheck.entries()].map(([name, cs]) => {
    const findings = cs.flatMap((c) => c.findings)
    const weight = findings.reduce((s, f) => s + WEIGHT[f.severity], 0)
    const worst = findings.filter((f) => f.severity !== 'info').sort((a, b) => RANK[b.severity] - RANK[a.severity])[0]
    const ran = cs.some((c) => c.status === 'ok')
    return { name: name as CheckResult['check'], weight, worst, ran }
  })
  const total = rows.reduce((s, r) => s + r.weight, 0)
  const top = [...rows].sort((a, b) => b.weight - a.weight)[0]

  return (
    <Card
      className={className}
      label="Where the warnings came from"
      aside={total ? <Pill tone="bad">Most from {SHORT[top.name]}</Pill> : <Pill tone="good">No warning signs</Pill>}
    >
      <p className="mt-1 text-[13px] text-faint">Share of all warning signs per check, weighted by severity.</p>
      <div ref={ref} className="mt-5 grid gap-4">
        {rows.map((r, i) => {
          const pct = total ? Math.round((r.weight / total) * 100) : 0
          return (
            <div key={r.name}>
              <div className="flex items-baseline justify-between gap-3 text-[14px]">
                <span className={r.ran ? 'text-ink' : 'text-faint'}>{CHECK_LABEL[r.name]}</span>
                <span className="font-mono text-[13px] tabular-nums text-muted">
                  {r.ran ? <CountUp value={pct} suffix="%" /> : <span className="font-sans text-faint">Did not run</span>}
                </span>
              </div>
              <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-line">
                <motion.div
                  className="h-full origin-left rounded-full"
                  style={{
                    width: `${Math.max(pct, 0)}%`,
                    background: r.worst
                      ? `linear-gradient(90deg, color-mix(in oklab, ${SEV_COLOR[r.worst.severity]} 55%, transparent), ${SEV_COLOR[r.worst.severity]})`
                      : 'var(--color-line-strong)',
                  }}
                  initial={{ scaleX: reduce ? 1 : 0 }}
                  animate={{ scaleX: inView || reduce ? 1 : 0 }}
                  transition={{ duration: 0.9, ease, delay: 0.08 * i }}
                />
              </div>
            </div>
          )
        })}
      </div>
      <p className="mt-5 border-t border-line pt-4 text-[12px] text-faint">
        Weights: Danger 8, Serious 4, Warning 2, Minor 1. 0% everywhere means no warning signs, not proof of safety.
      </p>
    </Card>
  )
}
