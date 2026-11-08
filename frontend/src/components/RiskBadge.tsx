import type { RiskLevel } from '../types'
import { RISK_META } from './labels'

export function RiskBadge({ level, size = 'sm' }: { level: RiskLevel; size?: 'sm' | 'lg' }) {
  const meta = RISK_META[level]
  const sizing = size === 'lg' ? 'px-4 py-1.5 text-lg' : 'px-2.5 py-0.5 text-xs'
  return (
    <span className={`inline-flex items-center rounded-full font-semibold ring-1 ring-inset ${sizing} ${meta.className}`}>
      {meta.label}
    </span>
  )
}
