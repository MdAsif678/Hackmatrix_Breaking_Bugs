// Logo mark + wordmark. Owner: P1.
import { Link } from 'react-router-dom'

export function Mark({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true" className="shrink-0">
      <circle cx="10.5" cy="10.5" r="6.75" fill="none" stroke="currentColor" strokeWidth="2.2" />
      <path d="M15.6 15.6l5.2 5.2" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" />
      <path
        d="M7.6 10.6l2 2 3.6-3.9"
        fill="none"
        stroke="var(--color-action)"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

export function Logo({ to = '/' }: { to?: string }) {
  return (
    <Link to={to} className="flex h-11 items-center gap-2 text-[20px] font-medium tracking-[-0.02em] text-ink" aria-label="TrustLens home">
      <Mark />
      TrustLens
    </Link>
  )
}

export function Arrow() {
  return (
    <svg className="arrow" width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
      <path d="M3 8h9.5M8.5 4l4 4-4 4" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}
