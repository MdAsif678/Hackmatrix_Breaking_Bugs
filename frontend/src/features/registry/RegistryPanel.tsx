// "Register on-chain" panel shown at the bottom of a report. Owner: P4.
// TODO(P4): Etherscan links, nicer states, tamper demo.
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../../api/client'
import type { AnalysisReport, ChainRecord } from '../../types'

interface Props {
  report: AnalysisReport
  onRegistered: (chain: ChainRecord) => void
}

export function RegistryPanel({ report, onRegistered }: Props) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function register() {
    setBusy(true)
    setError(null)
    try {
      onRegistered(await api.submitToRegistry(report.id))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Registration failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="rounded-xl border border-violet-900/60 bg-violet-950/20 p-5">
      <h2 className="font-semibold text-violet-300">Threat-intelligence registry (blockchain)</h2>
      <p className="mt-1 text-sm text-slate-400">
        Registering stores only a cryptographic fingerprint (hash) of this report on a public blockchain, so anyone can
        later prove it was not altered. No URLs, messages or personal data go on-chain. It proves integrity, not that
        the report is true.
      </p>

      {report.chain ? (
        <dl className="mt-3 grid gap-1 text-sm">
          <div className="flex gap-2"><dt className="w-32 text-slate-500">Report hash</dt><dd className="break-all font-mono text-xs">{report.chain.report_hash}</dd></div>
          <div className="flex gap-2"><dt className="w-32 text-slate-500">On-chain ID</dt><dd>{report.chain.chain_report_id}</dd></div>
          <div className="flex gap-2"><dt className="w-32 text-slate-500">Transaction</dt><dd className="break-all font-mono text-xs">{report.chain.tx_hash}</dd></div>
          <div className="flex gap-2"><dt className="w-32 text-slate-500">Network</dt><dd>{report.chain.network}</dd></div>
          <Link to={`/verify/${report.id}`} className="mt-2 text-sky-400 hover:underline">Verify integrity →</Link>
        </dl>
      ) : (
        <button
          type="button"
          onClick={register}
          disabled={busy}
          className="mt-3 rounded-lg bg-violet-600 px-4 py-2 text-sm font-semibold text-white hover:bg-violet-500 disabled:opacity-50"
        >
          {busy ? 'Registering…' : 'Register report on-chain'}
        </button>
      )}
      {error && <p className="mt-2 text-sm text-red-300">{error}</p>}
    </section>
  )
}
