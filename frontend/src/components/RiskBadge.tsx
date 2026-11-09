import type { RiskLevel } from '../types'
import { RISK_META } from './labels'

export function RiskBadge({ level, size = 'sm' }: { level: RiskLevel; size?: 'sm' | 'lg' }) {
  const sizing = size === 'lg' ? 'h-9 px-4 text-[15px]' : 'h-6 px-2.5 text-[13px]'
  return (
    <span className={`risk ${sizing}`} data-level={level}>
      {RISK_META[level].label}
    </span>
  )
}
