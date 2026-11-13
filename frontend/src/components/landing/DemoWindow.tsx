// The checker as live HTML, driven by a step (from the scroll): the five checks run in turn, then the verdict lands.
// step 0 = waiting, 1..5 = check N running (earlier ones done), 6 = all done + verdict. Owner: P1.
import { AnimatePresence, motion } from 'motion/react'
import { RiskBadge } from '../RiskBadge'
import { SeverityTag } from '../Severity'

export const DEMO_ROWS = [
  { name: 'Lookalike names', result: 'Imitates paypal.com', sev: 'high' },
  { name: 'Domain age', result: 'Registered 4 days ago', sev: 'high' },
  { name: 'Known phishing lists', result: 'Not listed yet', sev: 'info' },
  { name: 'Certificate', result: 'Valid, first issued 3 days ago', sev: 'medium' },
  { name: 'Website and page', result: '2 protections missing', sev: 'low' },
] as const

const ease = [0.22, 1, 0.36, 1] as const

function Check() {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true">
      <path d="M3 7.2l2.6 2.6L11 4.4" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function Spinner() {
  return (
    <svg className="spin" width="14" height="14" viewBox="0 0 14 14" aria-hidden="true">
      <circle cx="7" cy="7" r="5.5" fill="none" stroke="currentColor" strokeOpacity="0.25" strokeWidth="1.6" />
      <path d="M7 1.5a5.5 5.5 0 0 1 5.5 5.5" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  )
}

export function DemoWindow({ step }: { step: number }) {
  return (
    <div className="window relative" role="img" aria-label="TrustLens checking paypa1-secure-login.com: five checks, verdict High Risk">
      <div className="flex h-11 items-center gap-2 border-b border-line px-4">
        <span className="h-2.5 w-2.5 rounded-full bg-line-strong" />
        <span className="h-2.5 w-2.5 rounded-full bg-line-strong" />
        <span className="h-2.5 w-2.5 rounded-full bg-line-strong" />
        <span className="ml-3 font-mono text-[13px] text-faint">trustlens / check</span>
      </div>

      <div className="p-4 sm:p-6">
        <div className="flex gap-2">
          <div className="field flex h-11 min-w-0 flex-1 items-center px-3 font-mono text-[14px] text-ink">
            <span className="truncate">https://paypa1-secure-login.com/verify</span>
          </div>
          <span className="btn btn-primary pointer-events-none h-11 px-4">{step > 0 && step < 6 ? 'Checking' : 'Check'}</span>
        </div>

        <ul className="mt-5 divide-y divide-line rounded-lg border border-line bg-sunken">
          {DEMO_ROWS.map((row, i) => {
            const state = step > i + 1 || step >= 6 ? 'done' : step === i + 1 ? 'running' : 'waiting'
            return (
              <li key={row.name} className="flex h-11 items-center gap-2.5 px-3 text-[13px] sm:h-12 sm:gap-3 sm:px-4 sm:text-[14px]">
                <span className="inline-flex h-4 w-4 items-center justify-center">
                  {state === 'done' && <span className="text-ink"><Check /></span>}
                  {state === 'running' && <span className="text-link"><Spinner /></span>}
                  {state === 'waiting' && <span className="h-1.5 w-1.5 rounded-full bg-line-strong" />}
                </span>
                <span className={`min-w-0 flex-1 truncate sm:w-44 sm:flex-none ${state === 'waiting' ? 'text-faint' : 'text-ink'}`}>
                  {row.name}
                </span>
                <span className="flex shrink-0 items-center justify-end gap-3 sm:min-w-0 sm:flex-1">
                  <AnimatePresence initial={false}>
                    {state === 'done' && (
                      <motion.span
                        key="r"
                        className="flex min-w-0 items-center gap-3"
                        initial={{ opacity: 0, x: 8 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0 }}
                        transition={{ duration: 0.35, ease }}
                      >
                        <span className="hidden truncate text-muted sm:inline">{row.result}</span>
                        <SeverityTag sev={row.sev} />
                      </motion.span>
                    )}
                  </AnimatePresence>
                </span>
              </li>
            )
          })}
        </ul>

        <motion.div
          className="mt-5 border-t border-line pt-5"
          animate={{ opacity: step >= 6 ? 1 : 0.15, y: step >= 6 ? 0 : 6 }}
          transition={{ duration: 0.5, ease }}
        >
          <div className="flex flex-wrap items-center gap-3">
            <RiskBadge level="high_risk" size="lg" />
            <span className="text-[14px] text-faint">2 serious findings, 5 of 5 checks ran</span>
          </div>
          <p className="mt-3 hidden text-[15px] leading-relaxed text-muted sm:block">
            This page copies PayPal’s name with a 1 in place of the l, and the domain is four days old. Do not sign in
            or enter card details.
          </p>
        </motion.div>
      </div>
    </div>
  )
}
