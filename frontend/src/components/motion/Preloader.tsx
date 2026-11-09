// Intro, first visit of a session only. The TrustLens lens draws itself in the middle of a dark screen, its glass
// clears so the page shows through it, then the lens opens until it fills the screen while the hero zooms out into
// place behind it (Hero listens to onReveal). One continuous shot: the page never "switches". About 2 s.
// The dark screen is one element whose circular hole is a clip-path, so the opening costs no layout. Skipped under
// reduced motion. Owner: P1.
import { animate, motion, useMotionValue, useTransform } from 'motion/react'
import { useEffect, useState } from 'react'
import { prefersReducedMotion, stopScroll } from './smooth'

const KEY = 'trustlens-intro-seen'
export const introWillPlay = () => {
  try {
    return !prefersReducedMotion() && !sessionStorage.getItem(KEY)
  } catch {
    return false
  }
}

const R = 58 // lens radius in px
const ink = '#ededef'
const ground = '#060606'

/** A rectangle covering the screen with a round hole of radius r at its centre (evenodd = the hole is cut out). */
function screenWithHole(r: number) {
  const w = window.innerWidth
  const h = window.innerHeight
  const cx = w / 2
  const cy = h / 2
  return `path(evenodd, 'M0 0H${w}V${h}H0Z M${cx - r} ${cy}a${r} ${r} 0 1 0 ${2 * r} 0a${r} ${r} 0 1 0 ${-2 * r} 0Z')`
}

export function Preloader({ onReveal }: { onReveal: () => void }) {
  const [show] = useState(introWillPlay)
  const [gone, setGone] = useState(false)
  const [phase, setPhase] = useState<'draw' | 'clear' | 'open'>('draw')
  const hole = useMotionValue(R)
  const clip = useTransform(hole, (r) => screenWithHole(r))
  const lensScale = useTransform(hole, (r) => Math.max(1, r / R))
  const lensOpacity = useTransform(hole, [R, R * 3], [1, 0])

  useEffect(() => {
    if (!show) {
      onReveal()
      return
    }
    // The intro always opens onto the hero, even after a reload half-way down the page.
    if ('scrollRestoration' in history) history.scrollRestoration = 'manual'
    window.scrollTo(0, 0)
    stopScroll(true)
    let cancelled = false
    const wait = (ms: number) => new Promise((r) => setTimeout(r, ms))
    const fonts = Promise.race([document.fonts?.ready ?? Promise.resolve(), wait(1500)])
    const run = async () => {
      await Promise.all([wait(850), fonts]) // the lens draws itself meanwhile
      if (cancelled) return
      setPhase('clear') // the glass fades clear: it is now a window onto the page
      await wait(520)
      if (cancelled) return
      setPhase('open')
      onReveal()
      try {
        sessionStorage.setItem(KEY, '1')
      } catch {
        /* private mode */
      }
      await animate(hole, Math.hypot(window.innerWidth, window.innerHeight) / 2 + 40, {
        duration: 1.15,
        ease: [0.76, 0, 0.24, 1],
      })
      stopScroll(false)
      if (!cancelled) setGone(true)
    }
    run()
    return () => {
      cancelled = true
      stopScroll(false)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  if (!show || gone) return null
  const draw = (delay: number, duration = 0.7) => ({
    initial: { pathLength: 0, opacity: 0 },
    animate: { pathLength: 1, opacity: 1 },
    transition: { duration, delay, ease: [0.65, 0, 0.35, 1] as const },
  })

  return (
    <div aria-hidden="true" className="fixed inset-0 z-[60]">
      {/* the dark screen with the lens-shaped hole */}
      <motion.div className="absolute inset-0" style={{ background: ground, clipPath: clip }} />

      {/* the lens drawing, centred on the hole */}
      <motion.div
        className="absolute left-1/2 top-1/2"
        style={{ scale: lensScale, opacity: lensOpacity, width: 0, height: 0 }}
      >
        <svg
          width="200"
          height="200"
          viewBox="-100 -100 200 200"
          className="absolute -left-[100px] -top-[100px] overflow-visible"
          fill="none"
        >
          <motion.circle
            r={R}
            fill={ground}
            stroke="none"
            initial={{ opacity: 1 }}
            animate={{ opacity: phase === 'draw' ? 1 : 0 }}
            transition={{ duration: 0.5, ease: 'easeOut' }}
          />
          <motion.circle r={R} stroke={ink} strokeWidth="2" {...draw(0, 0.75)} />
          <motion.circle
            r={R + 7}
            stroke="#8db1ff"
            strokeOpacity="0.35"
            strokeWidth="1"
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: phase === 'draw' ? 0 : 1, scale: 1 }}
            transition={{ duration: 0.5 }}
          />
          <motion.path
            d={`M${R * 0.72} ${R * 0.72}L${R * 1.35} ${R * 1.35}`}
            stroke={ink}
            strokeWidth="2"
            strokeLinecap="round"
            {...draw(0.45, 0.35)}
            animate={{ pathLength: 1, opacity: phase === 'open' ? 0 : 1 }}
          />
          <motion.path
            d="M-17 1l11 11 23-25"
            stroke="#2563eb"
            strokeWidth="3"
            strokeLinecap="round"
            strokeLinejoin="round"
            {...draw(0.6, 0.4)}
            animate={{ pathLength: 1, opacity: phase === 'draw' ? 1 : 0 }}
          />
        </svg>
      </motion.div>

      <motion.p
        className="absolute inset-x-0 top-[calc(50%+96px)] text-center font-mono text-[12px] tracking-[0.14em] text-faint"
        initial={{ opacity: 0 }}
        animate={{ opacity: phase === 'draw' ? 1 : 0 }}
        transition={{ duration: 0.4, delay: phase === 'draw' ? 0.3 : 0 }}
      >
        TRUSTLENS
      </motion.p>
    </div>
  )
}
