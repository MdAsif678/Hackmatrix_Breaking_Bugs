// The live pipeline shown under the form while a check runs. Owner: P1.
// Five stages, in the order the backend runs them. While waiting it shows the stage the backend must be in (the
// five checks run in parallel with an 8 s limit each, so after ~8.5 s they are done and the explanation is being
// written). When the report arrives, each stage fills in with what really happened (which checks ran, how long
// they took, the verdict), the line finishes drawing, and onDone() opens the report.
// Nothing here is invented: no fake latencies or scores; the only timer is the real elapsed time.
import { AnimatePresence, motion, useReducedMotion } from 'motion/react'
import { useEffect, useRef, useState, type ReactNode } from 'react'
import type { AnalysisReport, CheckName, CheckResult, Severity } from '../types'
import { RiskBadge } from './RiskBadge'
import { SeverityTag } from './Severity'

const ease = [0.22, 1, 0.36, 1] as const
const RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }

const SHORT: Record<CheckName, string> = {
  url: 'Lookalike names',
  dns: 'Domain age',
  threat_intel: 'Phishing lists',
  tls: 'Certificate',
  headers: 'Website and page',
  message: 'Scam patterns',
}
const URL_CHECKS: CheckName[] = ['url', 'dns', 'threat_intel', 'tls', 'headers']

type Mode = 'url' | 'message'
type Row = { key: string; label: string; result?: ReactNode }

/** Worst finding as a severity tag, "No issues", or "Could not run". */
function outcome(checks: CheckResult[]): ReactNode {
  if (!checks.length) return <span className="text-faint">Not run</span>
  if (checks.every((c) => c.status !== 'ok')) return <span className="text-faint">Could not run</span>
  const worst = checks
    .flatMap((c) => c.findings)
    .filter((f) => f.severity !== 'info')
    .sort((a, b) => RANK[b.severity] - RANK[a.severity])[0]
  return worst ? <SeverityTag sev={worst.severity} /> : <span className="text-muted">No issues</span>
}
const seconds = (checks: CheckResult[]) => `${(Math.max(0, ...checks.map((c) => c.duration_ms)) / 1000).toFixed(1)} s`

function subRows(mode: Mode, report: AnalysisReport | null): Row[] {
  if (mode === 'url') {
    return URL_CHECKS.map((name) => {
      const checks = report?.checks.filter((c) => c.check === name) ?? []
      return {
        key: name,
        label: SHORT[name],
        result: report && (
          <>
            {outcome(checks)}
            {checks.length > 0 && <span className="w-12 text-right font-mono text-[12px] text-faint">{seconds(checks)}</span>}
          </>
        ),
      }
    })
  }
  const message = report?.checks.filter((c) => c.check === 'message') ?? []
  const linkChecks = report?.checks.filter((c) => c.check !== 'message') ?? []
  const links = Math.min(3, report?.extracted_indicators.urls?.length ?? 0)
  return [
    { key: 'message', label: SHORT.message, result: report && outcome(message) },
    {
      key: 'links',
      label: report ? (links ? `${links} link${links > 1 ? 's' : ''} inside` : 'Links inside') : 'Links inside the message',
      result: report && (links ? outcome(linkChecks) : <span className="text-faint">None found</span>),
    },
  ]
}

function Spinner({ className = '' }: { className?: string }) {
  return (
    <svg className={`spin ${className}`} width="14" height="14" viewBox="0 0 14 14" aria-hidden="true">
      <circle cx="7" cy="7" r="5.5" fill="none" stroke="currentColor" strokeOpacity="0.2" strokeWidth="1.6" />
      <path d="M7 1.5a5.5 5.5 0 0 1 5.5 5.5" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  )
}
function Tick({ size = 12 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 14 14" aria-hidden="true">
      <path d="M3 7.2l2.6 2.6L11 4.4" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

type State = 'waiting' | 'active' | 'done' | 'failed'

function Node({ state }: { state: State }) {
  return (
    <span
      className={`relative z-10 flex h-[22px] w-[22px] items-center justify-center rounded-full border bg-raised transition-colors duration-500 ${
        state === 'done'
          ? 'border-link/60 text-link'
          : state === 'active'
            ? 'border-link text-link'
            : state === 'failed'
              ? 'border-risk-malicious text-risk-malicious'
              : 'border-line-strong text-faint'
      }`}
    >
      <AnimatePresence mode="wait" initial={false}>
        <motion.span
          key={state}
          className="flex"
          initial={{ opacity: 0, scale: 0.6 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0, scale: 0.6 }}
          transition={{ duration: 0.2 }}
        >
          {state === 'done' && <Tick />}
          {state === 'active' && <span className="h-1.5 w-1.5 rounded-full bg-link shadow-[0_0_10px_2px_rgb(141_177_255/0.6)]" />}
          {state === 'failed' && (
            <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
              <path d="M2 2l6 6M8 2L2 8" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
            </svg>
          )}
          {state === 'waiting' && <span className="h-1 w-1 rounded-full bg-line-strong" />}
        </motion.span>
      </AnimatePresence>
    </span>
  )
}

export function CheckPipeline({
  mode,
  target,
  report,
  error,
  onDone,
}: {
  mode: Mode
  target: string
  report: AnalysisReport | null
  error: string | null
  onDone: (report: AnalysisReport) => void
}) {
  const reduce = useReducedMotion()
  // 1..5 = that stage is running, 6 = all done
  const [stage, setStage] = useState(1)
  const [elapsed, setElapsed] = useState(0)
  const started = useRef(0)
  const doneRef = useRef(onDone)
  useEffect(() => {
    doneRef.current = onDone
  }, [onDone])

  // While waiting: stage 1 is instant (address check), then the parallel checks, then the explanation.
  useEffect(() => {
    started.current = performance.now()
    const t = [
      setTimeout(() => setStage((s) => Math.max(s, 2)), 600),
      setTimeout(() => setStage((s) => Math.max(s, 3)), 8500),
      setTimeout(() => setStage((s) => Math.max(s, 4)), 8900),
    ]
    return () => t.forEach(clearTimeout)
  }, [])

  // Real elapsed time, until the result or an error arrives.
  useEffect(() => {
    if (report || error) return
    const id = setInterval(() => setElapsed((performance.now() - started.current) / 1000), 100)
    return () => clearInterval(id)
  }, [report, error])

  // Result in: finish the remaining stages one by one, hold on the finished pipeline, then open the report.
  useEffect(() => {
    if (!report) return
    let cancelled = false
    const step = reduce ? 0 : 280
    const run = async () => {
      const wait = (ms: number) => new Promise((r) => setTimeout(r, ms))
      for (let s = 2; s <= 6; s++) {
        await wait(step)
        if (cancelled) return
        setStage((cur) => Math.max(cur, s))
      }
      await wait(reduce ? 300 : 1100)
      if (!cancelled) doneRef.current(report)
    }
    run()
    return () => {
      cancelled = true
    }
  }, [report, reduce])

  const failedAt = error ? stage : null
  const state = (n: number): State =>
    failedAt === n ? 'failed' : stage > n ? 'done' : stage === n && !error ? 'active' : 'waiting'

  const rows = subRows(mode, report)
  const explanation = report ? (report.explanation ? 'Written by Gemini from the findings only' : 'Written from the findings (AI unavailable)') : null

  const stages: { title: string; detail: string; body?: ReactNode }[] = [
    {
      title: mode === 'url' ? 'Checking the address is public' : 'Reading the message',
      detail:
        mode === 'url'
          ? 'Only public websites are visited. Private and internal addresses are refused.'
          : 'Links, phone numbers and UPI IDs are pulled out. Personal details are masked before the AI sees them.',
    },
    {
      title: mode === 'url' ? 'Running five checks at once' : 'Checking the message and its links',
      detail: 'Each check works on its own, with an 8 second limit.',
      body: (
        <ul className="mt-3 divide-y divide-line rounded-lg border border-line bg-sunken">
          {rows.map((r) => {
            const s = state(2)
            return (
              <li key={r.key} className="flex h-10 items-center gap-3 px-3 text-[13px]">
                <span className="flex w-3.5 justify-center">
                  {r.result ? (
                    <span className="text-link"><Tick /></span>
                  ) : s === 'active' ? (
                    <Spinner className="text-link" />
                  ) : (
                    <span className="h-1 w-1 rounded-full bg-line-strong" />
                  )}
                </span>
                <span className={s === 'waiting' ? 'text-faint' : 'text-ink'}>{r.label}</span>
                <AnimatePresence initial={false}>
                  {r.result && (
                    <motion.span
                      className="ml-auto flex items-center gap-3 text-[13px]"
                      initial={{ opacity: 0, x: 8 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ duration: 0.35, ease }}
                    >
                      {r.result}
                    </motion.span>
                  )}
                </AnimatePresence>
              </li>
            )
          })}
        </ul>
      ),
    },
    {
      title: 'Applying the risk rules',
      detail: 'Fixed rules turn the findings into a verdict. The AI does not decide it.',
      body: report && stage > 3 && (
        <motion.div className="mt-3" initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4, ease }}>
          <RiskBadge level={report.risk_level} />
        </motion.div>
      ),
    },
    {
      title: 'Writing the explanation',
      detail: explanation && stage > 4 ? explanation : 'Every sentence has to point to a finding.',
    },
    {
      title: 'Saving the report',
      detail:
        report && stage > 5
          ? `Saved as ${report.id.slice(0, 8)}. Ready to seal on the blockchain.`
          : 'Stored so it can be verified and linked to similar scams later.',
    },
  ]

  const status = error ? 'Check failed' : stage >= 6 ? 'Done. Opening the report' : 'Investigating'

  return (
    <div className="window" role="status" aria-live="polite">
      <div className="flex h-12 items-center gap-3 border-b border-line px-5">
        <span className="relative flex h-2 w-2">
          {!error && stage < 6 && <span className="absolute inset-0 animate-ping rounded-full bg-link/60" />}
          <span className={`relative h-2 w-2 rounded-full ${error ? 'bg-risk-malicious' : stage >= 6 ? 'bg-risk-low' : 'bg-link'}`} />
        </span>
        <span className="text-[14px] font-medium text-ink">{status}</span>
        <span className="min-w-0 flex-1 truncate font-mono text-[12px] text-faint">{target}</span>
        <span className="font-mono text-[12px] tabular-nums text-faint">{elapsed.toFixed(1)} s</span>
      </div>

      {/* A check normally takes 5 to 15 s. Much longer means the free server was asleep: say so, so it never looks stuck. */}
      {!report && !error && elapsed > 18 && (
        <p className="border-b border-line bg-sunken px-5 py-3 text-[13px] leading-relaxed text-muted">
          Taking longer than usual: the server was asleep and is starting up. This happens after a quiet spell and
          can take up to a minute. Your check will continue on its own.
        </p>
      )}

      <ol className="p-5 sm:p-6">
        {stages.map((s, i) => {
          const n = i + 1
          const st = state(n)
          const last = n === stages.length
          return (
            <li key={s.title} className={`relative grid grid-cols-[22px_1fr] gap-4 ${last ? '' : 'pb-7'}`}>
              {/* The line to the next stage: grey track, fills in blue once this stage is done, a light runs down
                  it while this stage is working. It belongs to this row, so it always meets both nodes exactly. */}
              {!last && (
                <span className="absolute bottom-0 left-[10.5px] top-[22px] w-px overflow-hidden bg-line" aria-hidden="true">
                  <motion.span
                    className="absolute inset-0 origin-top bg-link/70"
                    initial={false}
                    animate={{ scaleY: st === 'done' ? 1 : 0 }}
                    transition={{ duration: reduce ? 0 : 0.5, ease }}
                  />
                  {st === 'active' && !reduce && <span className="pipeline-flow absolute inset-x-0 h-10 bg-gradient-to-b from-transparent via-link to-transparent" />}
                </span>
              )}
              <Node state={st} />
              <div className="min-w-0 pt-px">
                <p className={`text-[15px] font-medium leading-snug transition-colors duration-300 ${st === 'waiting' ? 'text-faint' : 'text-ink'}`}>
                  {s.title}
                </p>
                <p className="mt-1 text-[13px] leading-relaxed text-faint">{s.detail}</p>
                {s.body}
                {failedAt === n && error && (
                  <p className="mt-3 rounded-md border border-risk-malicious/30 bg-risk-malicious/10 px-3 py-2 text-[13px] text-risk-malicious">
                    {error}
                  </p>
                )}
              </div>
            </li>
          )
        })}
      </ol>
    </div>
  )
}
