// The checker: paste a link or a message. Owner: P1.
import { AnimatePresence, motion } from 'motion/react'
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api/client'
import { CheckPipeline } from '../components/CheckPipeline'
import { scrollToTarget } from '../components/motion/smooth'
import type { AnalysisReport } from '../types'
import { Arrow } from '../components/Brand'

type Mode = 'url' | 'message'

const URL_EXAMPLES = ['github.com', 'expired-rsa-dv.ssl.com', 'revoked-rsa-dv.ssl.com', 'paypa1-secure-login.com']
const MESSAGE_EXAMPLE =
  'Dear customer, your SBI account KYC expires today. Update now at http://sbi-kyc-verify.example/login or your account will be blocked. Share the OTP sent to you to complete verification.'

const ease = [0.22, 1, 0.36, 1] as const

/** Animates its own height to fit whatever is inside, so swapping the form does not make the page jump. */
function AutoHeight({ children }: { children: ReactNode }) {
  const inner = useRef<HTMLDivElement>(null)
  const [height, setHeight] = useState<number | 'auto'>('auto')
  useEffect(() => {
    const el = inner.current
    if (!el) return
    const ro = new ResizeObserver(() => setHeight(el.offsetHeight))
    ro.observe(el)
    return () => ro.disconnect()
  }, [])
  return (
    <motion.div className="-m-1 overflow-hidden" animate={{ height }} transition={{ duration: 0.4, ease }}>
      {/* 4px of room so the focus ring is not clipped */}
      <div ref={inner} className="p-1">
        {children}
      </div>
    </motion.div>
  )
}

const STEPS = ['Lookalike names', 'Domain age', 'Known phishing lists', 'Certificate', 'Website and page content', 'Explanation']

export default function CheckPage() {
  const navigate = useNavigate()
  const [mode, setMode] = useState<Mode>('url')
  const [url, setUrl] = useState('')
  const [text, setText] = useState('')
  const [error, setError] = useState<string | null>(null)
  // The current (or last) check: the pipeline under the form shows it.
  const [run, setRun] = useState<{ id: number; mode: Mode; target: string; report: AnalysisReport | null; error: string | null } | null>(null)
  const loading = !!run && !run.error

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    if (loading) return
    const value = mode === 'url' ? url.trim() : text.trim()
    if (!value) {
      setError(mode === 'url' ? 'Paste a link or a domain, for example example.com' : 'Paste the message you received')
      return
    }
    setError(null)
    const id = Date.now()
    const target = mode === 'url' ? value : value.replace(/\s+/g, ' ').slice(0, 80)
    setRun({ id, mode, target, report: null, error: null })
    // Bring the pipeline into view once it has opened.
    setTimeout(() => scrollToTarget('#pipeline', -96), 350)
    try {
      const report = mode === 'url' ? await api.analyzeUrl(value) : await api.analyzeMessage(value)
      setRun((r) => (r && r.id === id ? { ...r, report } : r))
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Something went wrong. Try again.'
      setRun((r) => (r && r.id === id ? { ...r, error: message } : r))
    }
  }

  return (
    <div className="grid gap-12 lg:grid-cols-12 lg:gap-6">
      <div className="lg:col-span-7">
        <h1 className="t-h2">Check a link or message</h1>
        <p className="t-lead mt-3 max-w-[52ch]">
          Paste what you received. TrustLens runs five checks and explains what it found.
        </p>

        <div className="mt-8 inline-flex isolate rounded-full border border-line p-1" role="tablist" aria-label="What to check">
          {(['url', 'message'] as const).map((m) => (
            <button
              key={m}
              type="button"
              role="tab"
              aria-selected={mode === m}
              aria-label={m === 'url' ? 'Link or website' : 'Message or email'}
              onClick={() => {
                setMode(m)
                setError(null)
              }}
              className="group relative h-9 rounded-full px-4 text-[15px] font-medium"
            >
              {/* One pill that slides between the two options */}
              {mode === m && (
                <motion.span
                  layoutId="check-mode-pill"
                  className="absolute inset-0 rounded-full bg-ink"
                  transition={{ type: 'spring', stiffness: 420, damping: 36 }}
                />
              )}
              {/* White text in "difference" mode: dark exactly where the pill is under it, light elsewhere, even mid-slide */}
              <span
                className={`relative text-white mix-blend-difference transition-opacity duration-300 ${
                  mode === m ? 'opacity-100' : 'opacity-60 group-hover:opacity-100'
                }`}
              >
                {m === 'url' ? 'Link or website' : 'Message or email'}
              </span>
            </button>
          ))}
        </div>

        <form onSubmit={onSubmit} className="mt-6" noValidate>
          <AutoHeight>
          <AnimatePresence mode="wait" initial={false}>
          <motion.div
            key={mode}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0, transition: { duration: 0.3, ease } }}
            exit={{ opacity: 0, y: -6, transition: { duration: 0.16, ease: 'easeIn' } }}
          >
          {mode === 'url' ? (
            <>
              <label htmlFor="target" className="t-label block">
                Link or domain
              </label>
              <input
                id="target"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://suspicious-site.example/login"
                className="field mt-2 h-14 px-4 font-mono text-[15px]"
                maxLength={2048}
                autoComplete="off"
                spellCheck={false}
                aria-invalid={!!error}
                aria-describedby={error ? 'target-error' : undefined}
                autoFocus
              />
              <div className="mt-3 flex flex-wrap items-center gap-2 text-[13px] text-faint">
                <span>Try one:</span>
                {URL_EXAMPLES.map((ex) => (
                  <button
                    key={ex}
                    type="button"
                    onClick={() => setUrl(ex)}
                    className="rounded-sm border border-line px-2 py-1 font-mono text-muted transition-colors hover:border-line-strong hover:text-ink"
                  >
                    {ex}
                  </button>
                ))}
              </div>
            </>
          ) : (
            <>
              <label htmlFor="message" className="t-label block">
                Message text
              </label>
              <textarea
                id="message"
                value={text}
                onChange={(e) => setText(e.target.value)}
                placeholder="Paste the SMS, WhatsApp message or email here"
                rows={7}
                maxLength={10000}
                className="field mt-2 resize-none p-4 leading-relaxed"
                aria-invalid={!!error}
                aria-describedby={error ? 'target-error' : undefined}
              />
              <button type="button" onClick={() => setText(MESSAGE_EXAMPLE)} className="link mt-3 text-[14px]">
                Use an example scam message
              </button>
            </>
          )}
          </motion.div>
          </AnimatePresence>
          </AutoHeight>

          {error && (
            <p id="target-error" className="mt-3 text-[14px] text-risk-malicious">
              {error}
            </p>
          )}

          <div className="mt-6">
            <button type="submit" disabled={loading} className="btn btn-primary w-full sm:w-auto">
              {loading ? 'Checking…' : mode === 'url' ? 'Check this link' : 'Check this message'}
              {!loading && <Arrow />}
            </button>
          </div>
        </form>

        {/* The live pipeline: opens under the form when a check starts */}
        <AnimatePresence>
          {run && (
            <motion.div
              id="pipeline"
              key={run.id}
              className="mt-10"
              initial={{ opacity: 0, y: 24 }}
              animate={{ opacity: 1, y: 0, transition: { duration: 0.6, ease } }}
              exit={{ opacity: 0, transition: { duration: 0.2 } }}
            >
              <CheckPipeline
                mode={run.mode}
                target={run.target}
                report={run.report}
                error={run.error}
                onDone={(report) => navigate(`/report/${report.id}`)}
              />
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      <aside className="lg:sticky lg:top-[calc(var(--nav)+48px)] lg:col-span-4 lg:col-start-9 lg:self-start">
        <div className="panel p-6">
          <h2 className="text-[16px] font-medium">What gets checked</h2>
          <ul className="mt-3 divide-y divide-line text-[15px] text-muted">
            {STEPS.map((s) => (
              <li key={s} className="py-2.5">
                {s}
              </li>
            ))}
          </ul>
          <p className="mt-4 border-t border-line pt-4 text-[14px] leading-relaxed text-faint">
            Never paste a password, OTP or card number. No check needs them.
          </p>
        </div>
      </aside>
    </div>
  )
}
