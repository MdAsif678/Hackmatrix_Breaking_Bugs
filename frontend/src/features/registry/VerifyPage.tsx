// Independent integrity verification of a registered report. Owner: P4.
// TODO(P4): show block timestamp, Etherscan link, tamper demo.
import { useEffect, useState, type FormEvent } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { api } from '../../api/client'
import type { VerifyResult } from '../../types'

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

  return (
    <div className="mx-auto max-w-3xl">
      <h1 className="text-2xl font-bold">Verify a report</h1>
      <p className="mt-2 text-slate-400">
        Recomputes the report's fingerprint and compares it with the value recorded on the blockchain.
      </p>
      <form onSubmit={onSubmit} className="mt-6 flex gap-2">
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Report ID"
          className="flex-1 rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 font-mono text-sm outline-none focus:border-sky-500"
        />
        <button type="submit" className="rounded-lg bg-sky-600 px-4 py-2 text-sm font-semibold text-white hover:bg-sky-500">
          Verify
        </button>
      </form>

      {error && <p className="mt-4 text-red-300">{error}</p>}
      {result && (
        <div className={`mt-6 rounded-xl border p-5 ${result.match ? 'border-emerald-700 bg-emerald-950/30' : 'border-amber-700 bg-amber-950/20'}`}>
          <p className="text-lg font-semibold">
            {result.match ? '✓ Integrity verified' : result.status === 'not_registered' ? 'Not registered on-chain yet' : '✗ Hash mismatch — report may have been altered'}
          </p>
          <dl className="mt-3 grid gap-1 text-sm">
            <div className="flex gap-2"><dt className="w-36 text-slate-500">Recomputed hash</dt><dd className="break-all font-mono text-xs">{result.recomputed_hash}</dd></div>
            <div className="flex gap-2"><dt className="w-36 text-slate-500">On-chain hash</dt><dd className="break-all font-mono text-xs">{result.onchain_hash ?? '—'}</dd></div>
            <div className="flex gap-2"><dt className="w-36 text-slate-500">Transaction</dt><dd className="break-all font-mono text-xs">{result.tx_hash ?? '—'}</dd></div>
          </dl>
        </div>
      )}
    </div>
  )
}
