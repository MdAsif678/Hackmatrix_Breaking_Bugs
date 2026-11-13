// "Checked in your browser": the same three checks as Verify, done without trusting the TrustLens server for the
// result. The server only supplies the stored report text; everything else happens here. Owner: P1.
import { useEffect, useState } from 'react'
import { api } from '../../api/client'
import { readSeal, SEPOLIA, sha256Hex, type OnchainRecord } from './onchain'

type Outcome = {
  record: OnchainRecord
  recomputed: string
  createdAt: number
  matches: boolean
  official: boolean
  inTime: boolean
}

function Row({ ok, label, detail }: { ok: boolean; label: string; detail: string }) {
  return (
    <li className="flex gap-3 py-2.5">
      <span className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full ${ok ? 'bg-risk-low/15 text-risk-low' : 'bg-risk-malicious/15 text-risk-malicious'}`}>
        <svg width="11" height="11" viewBox="0 0 14 14" aria-hidden="true">
          {ok ? (
            <path d="M3 7.2l2.6 2.6L11 4.4" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
          ) : (
            <path d="M4 4l6 6M10 4l-6 6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
          )}
        </svg>
      </span>
      <span>
        <span className="block text-[14px] text-ink">{label}</span>
        <span className="block break-all font-mono text-[12px] text-faint">{detail}</span>
      </span>
    </li>
  )
}

export function BrowserVerify({ reportId }: { reportId: string }) {
  const [outcome, setOutcome] = useState<Outcome | null>(null)
  const [state, setState] = useState<'checking' | 'done' | 'unsealed' | 'error'>('checking')
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const { canonical, chain } = await api.canonical(reportId)
        if (!chain) {
          if (!cancelled) setState('unsealed')
          return
        }
        const [record, recomputed] = await Promise.all([readSeal(chain.chain_report_id), sha256Hex(canonical)])
        const createdAt = Date.parse(JSON.parse(canonical).created_at) / 1000
        const result: Outcome = {
          record,
          recomputed,
          createdAt,
          matches: record.hash.toLowerCase() === recomputed.toLowerCase(),
          official: record.submitter.toLowerCase() === SEPOLIA.official.toLowerCase(),
          inTime: record.timestamp - createdAt <= SEPOLIA.windowHours * 3600,
        }
        if (!cancelled) {
          setOutcome(result)
          setState('done')
        }
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : String(e))
          setState('error')
        }
      }
    })()
    return () => {
      cancelled = true
    }
  }, [reportId])

  if (state === 'unsealed') return null
  const all = outcome && outcome.matches && outcome.official && outcome.inTime

  return (
    <section className="panel mt-6 p-6" aria-labelledby="browser-verify-h">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 id="browser-verify-h" className="text-[16px] font-medium">
          Checked in your browser
        </h2>
        {state === 'done' && (
          <span className={`text-[13px] font-medium ${all ? 'text-risk-low' : 'text-risk-malicious'}`}>
            {all ? 'Matches the blockchain' : 'Does not match'}
          </span>
        )}
      </div>
      <p className="mt-1 text-[14px] leading-relaxed text-faint">
        Your browser read the seal directly from Ethereum Sepolia and recomputed the fingerprint itself, so this result
        does not depend on trusting the TrustLens server.
      </p>

      {state === 'checking' && <p className="mt-4 text-[14px] text-muted">Reading the blockchain…</p>}
      {state === 'error' && (
        <p className="mt-4 text-[14px] text-risk-suspicious">Could not read the blockchain from your browser: {error}</p>
      )}
      {outcome && (
        <ul className="mt-3 divide-y divide-line">
          <Row
            ok={outcome.matches}
            label={outcome.matches ? 'Fingerprint matches the one on-chain' : 'Fingerprint differs: the report was changed after sealing'}
            detail={`computed ${outcome.recomputed.slice(0, 18)}…  ·  on-chain ${outcome.record.hash.slice(0, 18)}…`}
          />
          <Row
            ok={outcome.official}
            label={outcome.official ? 'Sealed by the official TrustLens wallet' : 'Sealed by a different wallet'}
            detail={outcome.record.submitter}
          />
          <Row
            ok={outcome.inTime}
            label={outcome.inTime ? `Sealed within ${SEPOLIA.windowHours} hours of the report` : `Sealed more than ${SEPOLIA.windowHours} hours after the report`}
            detail={new Date(outcome.record.timestamp * 1000).toLocaleString()}
          />
        </ul>
      )}
      <p className="mt-3 font-mono text-[11px] text-faint">
        Contract {SEPOLIA.contract} via {new URL(SEPOLIA.rpc).host}
      </p>
    </section>
  )
}
