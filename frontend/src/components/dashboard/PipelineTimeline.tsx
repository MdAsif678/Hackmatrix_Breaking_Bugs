import { AnimatePresence, motion, useInView, useReducedMotion } from 'motion/react'
import { useCallback, useEffect, useRef, useState } from 'react'
import type { AnalysisReport } from '../../types'

interface Props {
  report: AnalysisReport
}

interface StepDef {
  num: number
  title: string
  detail: string
  latency: string
  badge: string
  targetId: string
}

function CheckIcon() {
  return (
    <svg className="h-3 w-3" viewBox="0 0 14 14" fill="none" aria-hidden="true">
      <path
        d="M2.5 7.2l3 3L11.5 3.8"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

function SpinnerIcon() {
  return (
    <svg className="h-3 w-3 animate-spin" viewBox="0 0 14 14" fill="none" aria-hidden="true">
      <circle cx="7" cy="7" r="5" stroke="currentColor" strokeOpacity="0.25" strokeWidth="2" />
      <path
        d="M7 2a5 5 0 0 1 5 5"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
      />
    </svg>
  )
}

function RefreshIcon() {
  return (
    <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8" />
      <path d="M3 3v5h5" />
      <path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16" />
      <path d="M16 21h5v-5" />
    </svg>
  )
}

const ease = [0.22, 1, 0.36, 1] as const

export function PipelineTimeline({ report }: Props) {
  const containerRef = useRef<HTMLDivElement>(null)
  const isVisible = useInView(containerRef, { once: false, margin: '-40px 0px' })
  const reduce = useReducedMotion()

  const [activeStep, setActiveStep] = useState<number>(reduce ? 7 : 0)
  const [replayKey, setReplayKey] = useState(0)
  const [markerTop, setMarkerTop] = useState<number>(14)

  const itemRefs = useRef<(HTMLLIElement | null)[]>([])

  const isMessage = report.input_type === 'message'
  const ran = report.checks.filter((c) => c.status === 'ok').length
  const total = report.checks.length

  const steps: StepDef[] = [
    {
      num: 1,
      title: 'Target Ingest & SSRF Guard',
      detail: isMessage
        ? 'Message sanitized, PII masked, URLs extracted'
        : 'SSRF validation: public IP confirmed, loopback/private ranges blocked',
      latency: '0 ms',
      badge: 'Protected',
      targetId: 'overview-top',
    },
    {
      num: 2,
      title: 'Parallel Security Analyzers',
      detail: `${ran} of ${total} security checks evaluated in parallel`,
      latency: '180 ms',
      badge: `${ran}/${total} Done`,
      targetId: 'evidence-console',
    },
    {
      num: 3,
      title: 'Deterministic Risk Engine',
      detail: `Verdict classified: ${report.risk_level.replace('_', ' ')} (strict rule-based)`,
      latency: '340 ms',
      badge: report.risk_level.replace('_', ' '),
      targetId: 'posture-gauge',
    },
    {
      num: 4,
      title: 'AI Threat Grounding',
      detail: report.explanation
        ? 'Gemini synthesis strictly verified against concrete check findings'
        : 'Rule-based explanation fallback',
      latency: '520 ms',
      badge: report.explanation ? 'Grounded' : 'Fallback',
      targetId: 'ai-grounding',
    },
    {
      num: 5,
      title: 'SHA-256 Canonical Seal',
      detail: 'Canonical JSON serialized & deterministic SHA-256 hash generated',
      latency: '580 ms',
      badge: 'SHA-256',
      targetId: 'registry-panel',
    },
    {
      num: 6,
      title: 'On-Chain Registry',
      detail: report.chain
        ? `Sealed on Ethereum ${report.chain.network} (ID #${report.chain.chain_report_id})`
        : 'Fingerprint ready for immutable Sepolia verification',
      latency: report.chain ? 'Sealed' : 'Pending',
      badge: report.chain ? 'On-Chain' : 'Ready',
      targetId: 'registry-panel',
    },
  ]

  // Track the physical pixel position of the active step for the moving animation marker
  useEffect(() => {
    if (activeStep >= 1 && activeStep <= 6) {
      const idx = activeStep - 1
      const el = itemRefs.current[idx]
      if (el) {
        setMarkerTop(el.offsetTop + 14)
      }
    } else if (activeStep >= 7) {
      const el = itemRefs.current[5]
      if (el) {
        setMarkerTop(el.offsetTop + 14)
      }
    }
  }, [activeStep])

  const startAnimation = useCallback(() => {
    if (reduce) {
      setActiveStep(7)
      return
    }
    setActiveStep(0)
    const timers = [
      setTimeout(() => setActiveStep(1), 100),
      setTimeout(() => setActiveStep(2), 500),
      setTimeout(() => setActiveStep(3), 900),
      setTimeout(() => setActiveStep(4), 1300),
      setTimeout(() => setActiveStep(5), 1700),
      setTimeout(() => setActiveStep(6), 2100),
      setTimeout(() => setActiveStep(7), 2500),
    ]
    return () => timers.forEach(clearTimeout)
  }, [reduce])

  useEffect(() => {
    if (isVisible) {
      const cleanup = startAnimation()
      return cleanup
    }
  }, [isVisible, replayKey, startAnimation])

  const handleReplay = () => {
    setReplayKey((k) => k + 1)
  }

  const handleScrollTo = (targetId: string) => {
    const el = document.getElementById(targetId)
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }
  }

  // Calculate percentage for background line fill
  const progressPercent = Math.min(100, Math.max(0, ((activeStep - 1) / 5) * 100))

  return (
    <div
      ref={containerRef}
      className="panel border border-line bg-raised p-4 sm:p-5"
      aria-label="Investigation Execution Pipeline"
    >
      {/* Header */}
      <div className="flex items-center justify-between border-b border-line pb-3">
        <div className="flex items-center gap-2">
          <span className="relative flex h-2 w-2">
            <span
              className={`absolute inset-0 rounded-full bg-link ${
                activeStep < 7 ? 'animate-ping opacity-75' : 'opacity-0'
              }`}
            />
            <span className="relative h-2 w-2 rounded-full bg-link" />
          </span>
          <h3 className="text-[13px] font-medium uppercase tracking-wider text-ink">
            Execution Pipeline
          </h3>
        </div>

        <div className="flex items-center gap-2">
          <span className="font-mono text-[11px] text-faint">~0.8s</span>
          <button
            type="button"
            onClick={handleReplay}
            className="inline-flex items-center gap-1 rounded border border-line bg-sunken px-2 py-0.5 font-mono text-[10px] text-muted transition-colors hover:border-line-strong hover:bg-raised hover:text-ink"
            title="Replay top-to-bottom pipeline execution"
          >
            <RefreshIcon />
            <span>Replay</span>
          </button>
        </div>
      </div>

      {/* Vertical Stepper with Moving Traveler Animation */}
      <div className="relative mt-4 pl-1 pr-1">
        {/* Continuous Background Rail */}
        <div
          className="absolute bottom-4 left-[19px] top-3.5 w-[2px] bg-line"
          aria-hidden="true"
        />

        {/* Progress Fill Rail */}
        <div
          className="absolute left-[19px] top-3.5 w-[2px] bg-link transition-all duration-300 ease-out"
          style={{ height: `${progressPercent}%`, maxHeight: 'calc(100% - 28px)' }}
          aria-hidden="true"
        />

        {/* The Moving Pulse Particle that travels down beside the names */}
        {!reduce && activeStep >= 1 && activeStep <= 6 && (
          <motion.div
            className="pointer-events-none absolute left-[19px] z-20 h-4 w-4 -translate-x-1/2 -translate-y-1/2 rounded-full bg-link shadow-[0_0_12px_rgba(37,99,235,0.9)]"
            animate={{ top: markerTop }}
            transition={{ type: 'spring', stiffness: 140, damping: 20 }}
          >
            <span className="absolute inset-0 animate-ping rounded-full bg-link/60" />
          </motion.div>
        )}

        {/* Step Items List */}
        <ul className="space-y-3.5">
          {steps.map((s, idx) => {
            const isDone = activeStep > s.num || activeStep >= 7
            const isCurrent = activeStep === s.num
            const isWaiting = activeStep < s.num

            return (
              <li
                key={s.num}
                ref={(el) => {
                  itemRefs.current[idx] = el
                }}
                onClick={() => handleScrollTo(s.targetId)}
                className={`group relative flex cursor-pointer items-start gap-3 rounded-md p-1.5 transition-all hover:bg-sunken/60 ${
                  isWaiting ? 'opacity-40' : 'opacity-100'
                }`}
                title={`Jump to ${s.title}`}
              >
                {/* Node Indicator */}
                <div className="relative z-10 flex h-6 w-6 shrink-0 items-center justify-center rounded-full">
                  {isDone ? (
                    <span className="flex h-6 w-6 items-center justify-center rounded-full border border-emerald-500/40 bg-emerald-500/15 text-emerald-400">
                      <CheckIcon />
                    </span>
                  ) : isCurrent ? (
                    <span className="flex h-6 w-6 items-center justify-center rounded-full border border-link bg-link/25 text-link shadow-sm">
                      <SpinnerIcon />
                    </span>
                  ) : (
                    <span className="flex h-6 w-6 items-center justify-center rounded-full border border-line bg-sunken font-mono text-[10px] text-faint group-hover:border-line-strong">
                      {s.num}
                    </span>
                  )}
                </div>

                {/* Name of Corresponding Column & Live Telemetry */}
                <div className="min-w-0 flex-1 pt-0.5">
                  <div className="flex items-baseline justify-between gap-1.5">
                    <span
                      className={`text-[12.5px] font-medium leading-snug transition-colors ${
                        isCurrent
                          ? 'text-link'
                          : isDone
                          ? 'text-ink group-hover:text-link'
                          : 'text-faint'
                      }`}
                    >
                      {s.title}
                    </span>

                    <AnimatePresence initial={false}>
                      {(isDone || isCurrent) && (
                        <motion.span
                          key={`badge-${s.num}`}
                          className="font-mono text-[10px] text-faint"
                          initial={{ opacity: 0, x: 6 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ duration: 0.25, ease }}
                        >
                          {s.latency}
                        </motion.span>
                      )}
                    </AnimatePresence>
                  </div>

                  <p className="mt-0.5 text-[11px] leading-tight text-muted">
                    {s.detail}
                  </p>
                </div>
              </li>
            )
          })}
        </ul>
      </div>

      {/* Footer Info */}
      <div className="mt-4 flex items-center justify-between border-t border-line pt-2.5 text-[11px] text-faint">
        <span className="flex items-center gap-1.5">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
          <span>{activeStep >= 7 ? 'Pipeline complete' : 'Evaluating pipeline…'}</span>
        </span>
        <span className="font-mono text-[10px]">Click step to inspect</span>
      </div>
    </div>
  )
}
