import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../../api/client'
import type { AnalysisReport, ChainRecord } from '../../types'

interface Props {
  report: AnalysisReport
  onRegistered: (chain: ChainRecord) => void
}

const short = (h: string) => (h.length > 18 ? `${h.slice(0, 10)}…${h.slice(-8)}` : h)

export function RegistryPanel({ report, onRegistered }: Props) {
  const [busy, setBusy] = useState(false)
  const [copied, setCopied] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function register() {
    setBusy(true)
    setError(null)
    try {
      onRegistered(await api.submitToRegistry(report.id))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Sealing failed')
    } finally {
      setBusy(false)
    }
  }

  function copyHash(hash: string) {
    navigator.clipboard.writeText(hash)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <section className="panel overflow-hidden border border-line bg-raised p-5">
      <div className="flex items-center justify-between border-b border-line pb-3">
        <div className="flex items-center gap-2">
          <svg className="h-4 w-4 text-link" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect width="18" height="11" x="3" y="11" rx="2" ry="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
          </svg>
          <h2 className="text-[14px] font-medium text-ink">Blockchain Integrity Seal</h2>
        </div>
        <span className="rounded-full border border-line bg-sunken px-2 py-0.5 font-mono text-[11px] text-faint">
          {report.chain ? report.chain.network : 'Sepolia / EVM'}
        </span>
      </div>

      <p className="mt-3 text-[13px] leading-relaxed text-muted">
        Registers an immutable SHA-256 fingerprint on-chain for tamper-proof verification. No raw URLs or PII are stored on-chain.
      </p>

      {report.chain ? (
        <div className="mt-4 rounded-md border border-line bg-sunken p-3.5">
          <div className="flex items-center justify-between">
            <span className="inline-flex items-center gap-1.5 text-[12px] font-medium text-risk-low">
              <span className="h-1.5 w-1.5 rounded-full bg-risk-low" />
              Sealed On-Chain
            </span>
            <button
              type="button"
              onClick={() => copyHash(report.chain?.report_hash || '')}
              className="text-[11px] font-mono text-link hover:underline"
            >
              {copied ? 'Copied!' : 'Copy Hash'}
            </button>
          </div>

          <dl className="mt-3 grid gap-1.5 text-[12px]">
            <div className="flex justify-between gap-2">
              <dt className="text-faint">Hash</dt>
              <dd className="font-mono text-muted" title={report.chain.report_hash}>
                {short(report.chain.report_hash)}
              </dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt className="text-faint">Record ID</dt>
              <dd className="font-mono text-muted">#{report.chain.chain_report_id}</dd>
            </div>
            <div className="flex justify-between gap-2">
              <dt className="text-faint">Transaction</dt>
              <dd className="font-mono text-muted" title={report.chain.tx_hash}>
                {short(report.chain.tx_hash)}
              </dd>
            </div>
          </dl>

          <Link
            to={`/verify/${report.id}`}
            className="btn btn-secondary mt-3 flex w-full items-center justify-center gap-2 py-2 text-[13px]"
          >
            Verify Cryptographic Seal
          </Link>
        </div>
      ) : (
        <button
          type="button"
          onClick={register}
          disabled={busy}
          className="btn btn-primary mt-4 flex w-full items-center justify-center gap-2 py-2.5 text-[13px]"
        >
          {busy ? (
            <>
              <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-white/20 border-t-white" />
              Sealing on Blockchain…
            </>
          ) : (
            <>
              <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
              Seal Report on Blockchain
            </>
          )}
        </button>
      )}

      {error && (
        <p className="mt-2.5 rounded-sm border border-risk-suspicious/30 bg-risk-suspicious/10 p-2 text-[12px] text-risk-suspicious">
          {error}
        </p>
      )}
    </section>
  )
}
