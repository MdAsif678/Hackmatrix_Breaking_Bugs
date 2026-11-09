// Independent integrity check of a sealed report. Owner: P4 (restyled by P1 for the new design).
// TODO(P4): Etherscan links once deployed to Sepolia.
import { useEffect, useState, type FormEvent } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api } from '../../api/client'
import type { VerifyResult } from '../../types'

const HEADLINE: Record<string, { text: string; tone: string }> = {
  verified: { text: 'The report matches its seal', tone: 'text-risk-low' },
  mismatch: { text: 'The report was changed after it was sealed', tone: 'text-risk-malicious' },
  untrusted_submitter: { text: 'The seal was not made by TrustLens', tone: 'text-risk-malicious' },
  registered_late: { text: 'The seal was added too late to trust', tone: 'text-risk-malicious' },
  not_registered: { text: 'This report has not been sealed yet', tone: 'text-muted' },
}

export default function VerifyPage() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [input, setInput] = useState(id ?? '')
  const [result, setResult] = useState<VerifyResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!id) return
    api.verifyReport(id).then(setResult).catch((e: Error) => setError(e.message))
  }, [id])

  function onSubmit(e: FormEvent) {
    e.preventDefault()
    if (!input.trim()) return
    setResult(null)
    setError(null)
    navigate(`/verify/${input.trim()}`)
  }

  const head = result ? HEADLINE[result.status] ?? { text: result.status, tone: 'text-muted' } : null

  return (
    <div className="max-w-3xl">
      <h1 className="t-h2">Verify a report</h1>
      <p className="t-lead mt-3 max-w-[56ch]">
        TrustLens recomputes the report’s fingerprint and compares it with the record on the blockchain, which
        nobody can edit.
      </p>

      <form onSubmit={onSubmit} className="mt-8">
        <label htmlFor="report-id" className="t-label block">
          Report ID
        </label>
        <div className="mt-2 flex flex-col gap-3 sm:flex-row">
          <input
            id="report-id"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="e.g. 7719b4fd-…"
            className="field h-11 flex-1 px-4 font-mono text-[14px]"
            spellCheck={false}
          />
          <button type="submit" className="btn btn-primary">
            Verify report
          </button>
        </div>
      </form>

      {error && <p className="mt-6 text-risk-suspicious">{error}</p>}

      {result && head && (
        <section className="panel mt-8 overflow-hidden">
          <div className="border-b border-line p-6">
            <p className={`text-[22px] font-medium tracking-[-0.02em] ${head.tone}`}>{head.text}</p>
            {result.detail && result.status !== 'not_registered' && (
              <p className="mt-2 text-[15px] leading-relaxed text-muted">{result.detail}</p>
            )}
            {result.status === 'not_registered' && (
              <p className="mt-2 text-[15px] leading-relaxed text-muted">
                Open the report and choose Seal this report, then verify it here.
              </p>
            )}
          </div>
          {result.status !== 'not_registered' && (
          <dl className="grid gap-3 p-6 text-[14px]">
            {[
              ['Fingerprint now', result.recomputed_hash],
              ['Fingerprint on chain', result.onchain_hash ?? 'none'],
              ['Sealed by', result.submitter ?? 'none'],
              ['Sealed at', result.block_timestamp ? new Date(result.block_timestamp * 1000).toLocaleString() : 'none'],
              ['Transaction', result.tx_hash ?? 'none'],
            ].map(([k, v]) => (
              <div key={k} className="grid gap-1 sm:grid-cols-[170px_1fr] sm:gap-4">
                <dt className="text-faint">{k}</dt>
                <dd className="break-all font-mono text-[13px] text-muted">{v}</dd>
              </div>
            ))}
          </dl>
          )}
          {id && (
            <div className="border-t border-line bg-sunken px-6 py-4 text-[14px]">
              <Link to={`/report/${id}`} className="link">
                Open the report
              </Link>
            </div>
          )}
        </section>
      )}
    </div>
  )
}
