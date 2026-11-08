// Submit page: URL / domain tab and message tab. Owner: P1.
import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api/client'

type Mode = 'url' | 'message'

const URL_EXAMPLES = ['github.com', 'expired.badssl.com', 'paypa1-secure-login.com']
const MESSAGE_EXAMPLE =
  'Dear customer, your SBI account KYC expires today. Update now at http://sbi-kyc-verify.example/login or your account will be blocked. Share the OTP sent to you to complete verification.'

export default function HomePage() {
  const navigate = useNavigate()
  const [mode, setMode] = useState<Mode>('url')
  const [url, setUrl] = useState('')
  const [text, setText] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setLoading(true)
    try {
      const report = mode === 'url' ? await api.analyzeUrl(url) : await api.analyzeMessage(text)
      navigate(`/report/${report.id}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong')
    } finally {
      setLoading(false)
    }
  }

  const canSubmit = !loading && (mode === 'url' ? url.trim() : text.trim())

  return (
    <div className="mx-auto max-w-3xl">
      <h1 className="text-3xl font-bold tracking-tight">Is this link or message safe to trust?</h1>
      <p className="mt-2 text-slate-400">
        Paste a suspicious link, domain, email or SMS. We check phishing indicators, TLS certificates, threat
        intelligence and scam patterns, then explain the evidence.
      </p>

      <div className="mt-8 inline-flex rounded-lg border border-slate-800 p-1">
        {(['url', 'message'] as const).map((m) => (
          <button
            key={m}
            type="button"
            onClick={() => setMode(m)}
            className={`rounded-md px-4 py-1.5 text-sm ${mode === m ? 'bg-sky-600 text-white' : 'text-slate-400 hover:text-white'}`}
          >
            {m === 'url' ? 'URL / Domain' : 'Message / Email'}
          </button>
        ))}
      </div>

      <form onSubmit={onSubmit} className="mt-4 grid gap-3">
        {mode === 'url' ? (
          <>
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://suspicious-site.example/login"
              className="w-full rounded-lg border border-slate-700 bg-slate-900 px-4 py-3 font-mono text-sm outline-none focus:border-sky-500"
              maxLength={2048}
              autoFocus
            />
            <div className="flex flex-wrap gap-2 text-xs text-slate-500">
              Try:
              {URL_EXAMPLES.map((ex) => (
                <button key={ex} type="button" onClick={() => setUrl(ex)} className="text-sky-400 hover:underline">
                  {ex}
                </button>
              ))}
            </div>
          </>
        ) : (
          <>
            <textarea
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder="Paste the suspicious SMS, WhatsApp message or email text here…"
              rows={7}
              maxLength={10000}
              className="w-full rounded-lg border border-slate-700 bg-slate-900 px-4 py-3 text-sm outline-none focus:border-sky-500"
            />
            <button
              type="button"
              onClick={() => setText(MESSAGE_EXAMPLE)}
              className="justify-self-start text-xs text-sky-400 hover:underline"
            >
              Use an example scam message
            </button>
          </>
        )}

        <button
          type="submit"
          disabled={!canSubmit}
          className="rounded-lg bg-sky-600 px-4 py-3 font-semibold text-white hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {loading ? 'Investigating…' : 'Investigate'}
        </button>
        {error && <p className="rounded-lg bg-red-500/10 px-4 py-2 text-sm text-red-300">{error}</p>}
      </form>

      <p className="mt-6 text-xs text-slate-600">
        We never ask for passwords, OTPs or card details. Don't paste them here.
      </p>
    </div>
  )
}
