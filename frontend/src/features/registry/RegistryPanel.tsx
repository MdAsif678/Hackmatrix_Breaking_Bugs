// "Blockchain seal" block in the report sidebar. Owner: P4 (styled by P1 to match the site).
// Seal the report (its SHA-256 fingerprint goes on Ethereum), copy the fingerprint, verify it later.
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

  async function copyHash(hash: string) {
    try {
      await navigator.clipboard.writeText(hash)
      setCopied(true)
      setTimeout(() => setCopied(false), 1800)
    } catch {
      /* clipboard blocked: the full hash is still in the tooltip */
    }
  }

  return (
    <section className="panel p-5" aria-labelledby="seal-h">
      <div className="flex items-center justify-between gap-3">
        <h2 id="seal-h" className="whitespace-nowrap text-[15px] font-medium">
          Blockchain seal
        </h2>
        <span className="whitespace-nowrap font-mono text-[12px] capitalize text-faint">{report.chain ? report.chain.network : 'Sepolia'}</span>
      </div>
      <p className="mt-2 text-[14px] leading-relaxed text-faint">
        Stores a SHA-256 fingerprint of this report on Ethereum, so anyone can later prove it was not changed. The link
        and any personal details stay off-chain.
      </p>

      {report.chain ? (
        <>
          <div className="mt-4 flex items-center gap-2 text-[13px] text-risk-low">
            <span className="h-1.5 w-1.5 rounded-full bg-risk-low" />
            Sealed
          </div>
          <dl className="mt-3 grid gap-2 border-t border-line pt-3 text-[13px]">
            <div className="flex items-center justify-between gap-3">
              <dt className="text-faint">Fingerprint</dt>
              <dd className="flex items-center gap-2">
                <span className="font-mono text-muted" title={report.chain.report_hash}>
                  {short(report.chain.report_hash)}
                </span>
                <button
                  type="button"
                  onClick={() => copyHash(report.chain!.report_hash)}
                  className="rounded-full border border-line px-2 py-0.5 text-[12px] text-muted transition-colors hover:border-line-strong hover:text-ink"
                  aria-label="Copy the full fingerprint"
                >
                  {copied ? 'Copied' : 'Copy'}
                </button>
              </dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt className="text-faint">Record</dt>
              <dd className="font-mono text-muted">#{report.chain.chain_report_id}</dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt className="text-faint">Transaction</dt>
              <dd className="font-mono text-muted" title={report.chain.tx_hash}>
                {short(report.chain.tx_hash)}
              </dd>
            </div>
          </dl>
          <Link to={`/verify/${report.id}`} className="btn btn-secondary mt-4 w-full">
            Verify this report
          </Link>
        </>
      ) : (
        <button type="button" onClick={register} disabled={busy} className="btn btn-secondary mt-4 w-full">
          {busy && (
            <svg className="spin" width="14" height="14" viewBox="0 0 14 14" aria-hidden="true">
              <circle cx="7" cy="7" r="5.5" fill="none" stroke="currentColor" strokeOpacity="0.25" strokeWidth="1.6" />
              <path d="M7 1.5a5.5 5.5 0 0 1 5.5 5.5" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
            </svg>
          )}
          {busy ? 'Sealing' : 'Seal this report'}
        </button>
      )}

      {error && <p className="mt-3 text-[13px] leading-relaxed text-risk-suspicious">{error}</p>}
    </section>
  )
}
