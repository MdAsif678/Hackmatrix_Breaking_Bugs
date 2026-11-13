// "Blockchain seal" block in the report sidebar. Owner: P4 (polished for Sepolia testnet).
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../../api/client'
import type { AnalysisReport, ChainRecord } from '../../types'

interface Props {
  report: AnalysisReport
  onRegistered: (chain: ChainRecord) => void
}

const short = (h: string) => (h.length > 18 ? `${h.slice(0, 10)}…${h.slice(-8)}` : h)

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

export function RegistryPanel({ report, onRegistered }: Props) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  // Seconds since sealing started: a Sepolia transaction takes 15 to 30 s, so show what is happening meanwhile.
  const [elapsed, setElapsed] = useState(0)
  useEffect(() => {
    if (!busy) return
    const started = Date.now()
    const id = setInterval(() => setElapsed(Math.floor((Date.now() - started) / 1000)), 500)
    return () => {
      clearInterval(id)
      setElapsed(0)
    }
  }, [busy])

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

  const etherscanTxUrl = report.chain
    ? `https://sepolia.etherscan.io/tx/${report.chain.tx_hash}`
    : null
  const etherscanContractUrl = report.chain
    ? `https://sepolia.etherscan.io/address/${report.chain.contract_address}`
    : null

  return (
    <section className="panel p-5" aria-labelledby="seal-h">
      <div className="flex items-center justify-between gap-3">
        <h2 id="seal-h" className="whitespace-nowrap text-[15px] font-medium">
          Blockchain seal
        </h2>
        <span className="whitespace-nowrap font-mono text-[12px] capitalize text-faint">
          {report.chain ? report.chain.network : 'Sepolia'}
        </span>
      </div>

      <p className="mt-2 text-[14px] leading-relaxed text-faint">
        Cryptographic sealing commits a tamper-proof SHA-256 fingerprint of this investigation to the Ethereum Sepolia
        testnet, creating permanent mathematical proof that the evidence has not been altered.
      </p>

      {report.chain ? (
        <>
          <div className="mt-4 flex items-center gap-2 text-[13px] text-risk-low">
            <span className="h-1.5 w-1.5 rounded-full bg-risk-low" />
            Sealed on Sepolia
          </div>

          <dl className="mt-3 grid gap-2.5 border-t border-line pt-3 text-[13px]">
            <div className="flex items-center justify-between gap-3">
              <dt className="text-faint">Fingerprint</dt>
              <dd className="flex items-center gap-1.5">
                <span className="font-mono text-muted" title={report.chain.report_hash}>
                  {short(report.chain.report_hash)}
                </span>
                <CopyBtn text={report.chain.report_hash} label="fingerprint hash" />
              </dd>
            </div>

            <div className="flex items-center justify-between gap-3">
              <dt className="text-faint">Record ID</dt>
              <dd className="font-mono text-muted">#{report.chain.chain_report_id}</dd>
            </div>

            <div className="flex items-center justify-between gap-3">
              <dt className="text-faint">Transaction</dt>
              <dd className="flex items-center gap-1.5">
                <a
                  href={etherscanTxUrl!}
                  target="_blank"
                  rel="noreferrer"
                  className="link link-accent font-mono text-muted"
                  title="View transaction on Sepolia Etherscan"
                >
                  {short(report.chain.tx_hash)} ↗
                </a>
                <CopyBtn text={report.chain.tx_hash} label="transaction hash" />
              </dd>
            </div>

            <div className="flex items-center justify-between gap-3">
              <dt className="text-faint">Contract</dt>
              <dd className="flex items-center gap-1.5">
                <a
                  href={etherscanContractUrl!}
                  target="_blank"
                  rel="noreferrer"
                  className="link link-accent font-mono text-muted"
                  title="View contract on Sepolia Etherscan"
                >
                  {short(report.chain.contract_address)} ↗
                </a>
                <CopyBtn text={report.chain.contract_address} label="contract address" />
              </dd>
            </div>

            <div className="flex items-center justify-between gap-3">
              <dt className="text-faint">Network</dt>
              <dd className="font-mono text-muted uppercase">{report.chain.network}</dd>
            </div>
          </dl>

          <div className="mt-4 flex flex-col gap-2">
            <Link to={`/verify/${report.id}`} className="btn btn-secondary w-full">
              Verify this report
            </Link>
            <a
              href={etherscanTxUrl!}
              target="_blank"
              rel="noreferrer"
              className="inline-flex justify-center text-[12px] text-faint hover:text-ink transition-colors mt-1"
            >
              View on Sepolia Etherscan ↗
            </a>
          </div>
        </>
      ) : (
        <button
          type="button"
          onClick={register}
          disabled={busy}
          className="btn btn-secondary mt-4 w-full"
        >
          {busy && (
            <svg className="spin mr-2" width="14" height="14" viewBox="0 0 14 14" aria-hidden="true">
              <circle cx="7" cy="7" r="5.5" fill="none" stroke="currentColor" strokeOpacity="0.25" strokeWidth="1.6" />
              <path d="M7 1.5a5.5 5.5 0 0 1 5.5 5.5" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
            </svg>
          )}
          {busy ? 'Sealing on Sepolia…' : 'Seal this report on-chain'}
        </button>
      )}

      {busy && (
        <ol className="mt-3 grid gap-1.5 text-[13px]" aria-live="polite">
          {[
            ['Fingerprint computed (SHA-256)', 0],
            ['Transaction sent to Ethereum Sepolia', 2],
            ['Waiting for the network to confirm it (usually 15 to 30 s)', 4],
          ].map(([label, from]) => (
            <li key={label as string} className={`flex items-center gap-2 ${elapsed >= (from as number) ? 'text-muted' : 'text-faint/60'}`}>
              <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${elapsed >= (from as number) ? 'bg-link' : 'bg-line-strong'}`} />
              {label}
            </li>
          ))}
          <li className="pl-3.5 font-mono text-[12px] text-faint">{elapsed} s</li>
        </ol>
      )}

      {error && <p className="mt-3 text-[13px] leading-relaxed text-risk-suspicious">{error}</p>}
    </section>
  )
}
