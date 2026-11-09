// A compact version of the check pipeline for the report page: the five stages in one row, each with its real
// outcome, the line drawing through them once when the report opens. Owner: P1.
// The full live version is CheckPipeline (check page). Everything here comes from the report.
import { motion, useReducedMotion } from 'motion/react'
import type { AnalysisReport } from '../types'
import { RISK_META } from './labels'

const ease = [0.22, 1, 0.36, 1] as const

export function PipelineSummary({ report }: { report: AnalysisReport }) {
  const reduce = useReducedMotion()
  const ran = report.checks.filter((c) => c.status === 'ok').length
  const links = report.extracted_indicators.urls?.length ?? 0
  const message = report.input_type === 'message'

  const steps = [
    message
      ? { title: 'Message read', sub: links ? `${Math.min(3, links)} link${links > 1 ? 's' : ''} found` : 'No links found' }
      : { title: 'Address checked', sub: 'Public website' },
    { title: 'Checks ran', sub: `${ran} of ${report.checks.length}` },
    { title: 'Rules applied', sub: RISK_META[report.risk_level].label },
    { title: 'Explained', sub: report.explanation ? 'By Gemini' : 'From the rules' },
    { title: 'Saved', sub: report.chain ? `Sealed #${report.chain.chain_report_id}` : report.id.slice(0, 8) },
  ]

  return (
    <div aria-label="How this report was made" className="overflow-x-auto">
      <ol className="grid min-w-[560px] grid-cols-5">
        {steps.map((s, i) => {
          const last = i === steps.length - 1
          return (
            <li key={s.title} className="relative pr-3">
              {/* line from this node to the next one: draws left to right, one stage after another */}
              {!last && (
                <span className="absolute left-[22px] right-0 top-[10.5px] h-px bg-line" aria-hidden="true">
                  <motion.span
                    className="absolute inset-0 origin-left bg-link/60"
                    initial={{ scaleX: reduce ? 1 : 0 }}
                    animate={{ scaleX: 1 }}
                    transition={{ duration: 0.45, ease, delay: 0.35 + i * 0.22 }}
                  />
                </span>
              )}
              <motion.span
                className="relative flex h-[22px] w-[22px] items-center justify-center rounded-full border border-link/60 bg-ground text-link"
                initial={{ scale: reduce ? 1 : 0.6, opacity: reduce ? 1 : 0 }}
                animate={{ scale: 1, opacity: 1 }}
                transition={{ duration: 0.35, ease, delay: 0.2 + i * 0.22 }}
              >
                <svg width="11" height="11" viewBox="0 0 14 14" aria-hidden="true">
                  <path d="M3 7.2l2.6 2.6L11 4.4" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </motion.span>
              <p className="mt-3 text-[13px] font-medium text-ink">{s.title}</p>
              <p className="mt-0.5 truncate font-mono text-[12px] text-faint">{s.sub}</p>
            </li>
          )
        })}
      </ol>
    </div>
  )
}
