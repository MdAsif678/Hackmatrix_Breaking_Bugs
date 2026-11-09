// "Seal on the blockchain" block in the report sidebar. Owner: P4 (restyled by P1 for the new design).
// TODO(P4): Etherscan links once deployed to Sepolia, copy buttons.
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

  return (
    <section className="border-t border-line pt-5">
      <h2 className="text-[15px] font-medium">Blockchain seal</h2>
      <p className="mt-2 text-[14px] leading-relaxed text-faint">
        Stores a fingerprint of this report on Ethereum so anyone can later prove it was not changed. The link and
        any personal details stay off-chain.
      </p>

      {report.chain ? (
        <div className="panel mt-4 p-4">
          <dl className="grid gap-2 text-[13px]">
            <div className="flex justify-between gap-3">
              <dt className="text-faint">Fingerprint</dt>
              <dd className="font-mono text-muted" title={report.chain.report_hash}>{short(report.chain.report_hash)}</dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt className="text-faint">Record</dt>
              <dd className="font-mono text-muted">#{report.chain.chain_report_id}</dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt className="text-faint">Transaction</dt>
              <dd className="font-mono text-muted" title={report.chain.tx_hash}>{short(report.chain.tx_hash)}</dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt className="text-faint">Network</dt>
              <dd className="text-muted">{report.chain.network}</dd>
            </div>
          </dl>
          <Link to={`/verify/${report.id}`} className="btn btn-secondary mt-4 w-full">
            Verify this report
          </Link>
        </div>
      ) : (
        <button type="button" onClick={register} disabled={busy} className="btn btn-secondary mt-4 w-full">
          {busy ? 'Sealing…' : 'Seal this report'}
        </button>
      )}
      {error && <p className="mt-3 text-[13px] leading-relaxed text-risk-suspicious">{error}</p>}
    </section>
  )
}
