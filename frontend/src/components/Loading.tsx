// Loading states. Owner: P1.
// Skeletons in the shape of what is coming (a light sweep runs across them), a small turning lens with a label for
// screen readers, and <Swap>, which fades the skeleton out and the real content in once it has arrived.
// Only transform and opacity animate. Reduced motion: no sweep, no turning (see index.css).
import { AnimatePresence, motion } from 'motion/react'
import type { CSSProperties, ReactNode } from 'react'

/** A grey placeholder block; size and shape come from className (h-4 w-40 rounded-full ...). */
export function Skeleton({ className = '', style }: { className?: string; style?: CSSProperties }) {
  return <span aria-hidden="true" className={`skeleton block ${className}`} style={style} />
}

/** The TrustLens mark with a blue arc turning around the lens, plus a label. */
export function LensSpinner({ label, className = '' }: { label: string; className?: string }) {
  return (
    <span role="status" className={`inline-flex items-center gap-2.5 text-[13px] text-faint ${className}`}>
      <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true" className="shrink-0">
        <circle cx="10.5" cy="10.5" r="6.75" fill="none" stroke="currentColor" strokeOpacity="0.35" strokeWidth="2.2" />
        <path d="M15.6 15.6l5.2 5.2" stroke="currentColor" strokeOpacity="0.35" strokeWidth="2.2" strokeLinecap="round" />
        <circle
          className="lens-arc"
          cx="10.5"
          cy="10.5"
          r="6.75"
          fill="none"
          stroke="var(--color-link)"
          strokeWidth="2.2"
          strokeLinecap="round"
          pathLength="100"
          strokeDasharray="28 72"
        />
      </svg>
      {label}
    </span>
  )
}

const ease = [0.22, 1, 0.36, 1] as const

/** Shows `skeleton` while loading, then cross-fades to `children`. */
export function Swap({ loading, skeleton, children }: { loading: boolean; skeleton: ReactNode; children: ReactNode }) {
  return (
    <AnimatePresence mode="wait" initial={false}>
      {loading ? (
        <motion.div key="loading" exit={{ opacity: 0, transition: { duration: 0.18, ease: 'easeIn' } }}>
          {skeleton}
        </motion.div>
      ) : (
        <motion.div key="ready" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.35, ease }}>
          {children}
        </motion.div>
      )}
    </AnimatePresence>
  )
}
