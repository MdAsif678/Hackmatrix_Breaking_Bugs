// Independent integrity check of a sealed report. Owner: P4 (polished for Sepolia testnet).
import { useEffect, useState, type FormEvent } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api } from '../../api/client'
import type { VerifyResult } from '../../types'

interface OutcomeMeta {
  headline: string
  subheadline: string
  tone: string
  bgTone: string
  icon: string
}

const OUTCOMES: Record<string, OutcomeMeta> = {
  verified: {
    headline: 'The report matches its seal',
    subheadline: 'Cryptographic integrity confirmed. The report content is identical to the record sealed on-chain.',
    tone: 'text-risk-low',
    bgTone: 'bg-risk-low/10 border-risk-low/30',
    icon: '✓',
  },
  mismatch: {
    headline: 'This report was changed after it was sealed',
    subheadline: 'Tamper warning: The calculated report fingerprint does not match the hash sealed on the blockchain.',
    tone: 'text-risk-malicious',
    bgTone: 'bg-risk-malicious/10 border-risk-malicious/30',
    icon: '✗',
  },
  untrusted_submitter: {
    headline: 'Sealed by someone other than TrustLens (fake seal)',
    subheadline: 'Untrusted submitter: The on-chain seal was created by an unapproved wallet, not the official TrustLens key.',
    tone: 'text-risk-malicious',
    bgTone: 'bg-risk-malicious/10 border-risk-malicious/30',
    icon: '✗',
  },
  registered_late: {
    headline: 'Sealed long after the report was made (possible edited version)',
    subheadline: 'Timing violation: The seal was placed beyond the allowed registration window, indicating potential post-creation tampering.',
    tone: 'text-risk-malicious',
    bgTone: 'bg-risk-malicious/10 border-risk-malicious/30',
    icon: '✗',
  },
  not_registered: {
    headline: 'This report has not been sealed yet',
    subheadline: 'No blockchain record exists for this report yet. Open the report and click "Seal this report on-chain" to seal it.',
    tone: 'text-muted',
    bgTone: 'bg-sunken border-line',
    icon: '○',
  },
}

function formatTimestamp(ts?: number | null): string {
  if (!ts) return 'Not available'
  const date = new Date(ts * 1000)
  return `${date.toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })} at ${date.toLocaleTimeString(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })}`
}

function CopyBtn({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false)

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // fallback if clipboard API unavailable
    }
  }

  return (
    <button
      type="button"
      onClick={handleCopy}
      title={`Copy ${label}`}
      className="inline-flex items-center px-1.5 py-0.5 text-[11px] font-mono text-muted hover:text-ink rounded border border-line hover:border-line-strong hover:bg-white/5 transition-colors cursor-pointer select-none"
    >
      {copied ? <span className="text-risk-low font-sans">Copied</span> : 'Copy'}
    </button>
  )
}

export default function VerifyPage() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [input, setInput] = useState(id ?? '')
  const [result, setResult] = useState<VerifyResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (!id) return
    setLoading(true)
    setError(null)
    api.verifyReport(id)
      .then(setResult)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false))
  }, [id])

  function onSubmit(e: FormEvent) {
    e.preventDefault()
    if (!input.trim()) return
    setResult(null)
    setError(null)
    navigate(`/verify/${input.trim()}`)
  }

  const outcome = result
    ? OUTCOMES[result.status] ?? {
        headline: result.status,
        subheadline: 'Status reported by verification engine.',
        tone: 'text-muted',
        bgTone: 'bg-sunken border-line',
        icon: 'ℹ',
      }
    : null

  const explorerTxUrl = result?.explorer_url || (result?.tx_hash ? `https://sepolia.etherscan.io/tx/${result.tx_hash}` : null)

  return (
    <div className="max-w-3xl">
      <h1 className="t-h2">Verify a report</h1>
      <p className="t-lead mt-3 max-w-[62ch]">
        Cryptographic sealing records an immutable SHA-256 fingerprint of the report on the Sepolia Ethereum blockchain,
        guaranteeing that anyone can mathematically verify that the investigation and findings have never been modified.
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
          <button type="submit" disabled={loading} className="btn btn-primary">
            {loading ? 'Verifying…' : 'Verify report'}
          </button>
        </div>
      </form>

      {error && <p className="mt-6 text-risk-suspicious">{error}</p>}

      {result && outcome && (
        <section className="panel mt-8 overflow-hidden">
          <div className="border-b border-line p-6">
            <div className="flex items-start gap-4">
              <div
                className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border text-xl font-bold select-none ${outcome.bgTone} ${outcome.tone}`}
              >
                {outcome.icon}
              </div>
              <div className="flex-1 min-w-0">
                <h2 className={`text-[22px] font-medium tracking-[-0.02em] ${outcome.tone}`}>
                  {outcome.headline}
                </h2>
                <p className="mt-1 text-[14px] text-faint">
                  {outcome.subheadline}
                </p>
                {result.detail && (
                  <div className="mt-3 rounded-md bg-sunken border border-line p-3 text-[14px] leading-relaxed text-ink">
                    <span className="text-faint font-medium">Verification detail: </span>
                    {result.detail}
                  </div>
                )}
              </div>
            </div>
          </div>

          {result.status !== 'not_registered' && (
            <dl className="grid gap-3.5 p-6 text-[14px]">
              <div className="grid gap-1 sm:grid-cols-[180px_1fr] sm:gap-4 items-center">
                <dt className="text-faint">Fingerprint now</dt>
                <dd className="flex items-center gap-2 min-w-0">
                  <span className="break-all font-mono text-[13px] text-muted">{result.recomputed_hash}</span>
                  <CopyBtn text={result.recomputed_hash} label="current fingerprint" />
                </dd>
              </div>

              <div className="grid gap-1 sm:grid-cols-[180px_1fr] sm:gap-4 items-center">
                <dt className="text-faint">Fingerprint on-chain</dt>
                <dd className="flex items-center gap-2 min-w-0">
                  <span className="break-all font-mono text-[13px] text-muted">{result.onchain_hash ?? 'none'}</span>
                  {result.onchain_hash && <CopyBtn text={result.onchain_hash} label="on-chain fingerprint" />}
                </dd>
              </div>

              <div className="grid gap-1 sm:grid-cols-[180px_1fr] sm:gap-4 items-center">
                <dt className="text-faint">Sealed at</dt>
                <dd className="font-mono text-[13px] text-muted">
                  {formatTimestamp(result.block_timestamp)}
                </dd>
              </div>

              <div className="grid gap-1 sm:grid-cols-[180px_1fr] sm:gap-4 items-center">
                <dt className="text-faint">Sealed by</dt>
                <dd className="flex items-center gap-2 min-w-0">
                  {result.submitter ? (
                    <>
                      <a
                        href={`https://sepolia.etherscan.io/address/${result.submitter}`}
                        target="_blank"
                        rel="noreferrer"
                        className="link link-accent font-mono text-[13px] break-all"
                        title="View submitter address on Sepolia Etherscan"
                      >
                        {result.submitter} ↗
                      </a>
                      <CopyBtn text={result.submitter} label="submitter address" />
                    </>
                  ) : (
                    <span className="font-mono text-[13px] text-muted">none</span>
                  )}
                </dd>
              </div>

              <div className="grid gap-1 sm:grid-cols-[180px_1fr] sm:gap-4 items-center">
                <dt className="text-faint">Transaction</dt>
                <dd className="flex items-center gap-2 min-w-0">
                  {result.tx_hash ? (
                    <>
                      <a
                        href={explorerTxUrl!}
                        target="_blank"
                        rel="noreferrer"
                        className="link link-accent font-mono text-[13px] break-all"
                        title="View transaction on Sepolia Etherscan"
                      >
                        {result.tx_hash} ↗
                      </a>
                      <CopyBtn text={result.tx_hash} label="transaction hash" />
                    </>
                  ) : (
                    <span className="font-mono text-[13px] text-muted">none</span>
                  )}
                </dd>
              </div>

              {result.chain_status && (
                <div className="grid gap-1 sm:grid-cols-[180px_1fr] sm:gap-4 items-center">
                  <dt className="text-faint">Record status</dt>
                  <dd className="font-mono text-[13px] text-muted uppercase">
                    {result.chain_status}
                  </dd>
                </div>
              )}
            </dl>
          )}

          <div className="border-t border-line bg-sunken px-6 py-4 flex flex-wrap items-center justify-between gap-4 text-[14px]">
            {id && (
              <Link to={`/report/${id}`} className="link">
                ← Open the report
              </Link>
            )}
            {explorerTxUrl && (
              <a
                href={explorerTxUrl}
                target="_blank"
                rel="noreferrer"
                className="link link-accent"
              >
                View transaction on Sepolia Etherscan ↗
              </a>
            )}
          </div>
        </section>
      )}
    </div>
  )
}
