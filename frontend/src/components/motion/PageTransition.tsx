// Page transitions, built on the lens. Owner: P1.
// Landing <-> checker: a dark lens with a blue rim opens from the point you clicked until it covers the page; the
// new page then fades in while settling from a slight zoom, as if you had looked through the lens and stepped in.
// Inside the checker, pages cross-fade with a small rise.
// Only transform and opacity animate, run by the browser's compositor (no repaint per frame, no layout), so the
// transition stays smooth on slow phones and laptops too. Reduced motion: no lens, no zoom.
import { AnimatePresence, motion, MotionConfig, usePresence, useReducedMotion } from 'motion/react'
import { useEffect, useState, type ReactNode } from 'react'
import { useLocation, useOutlet } from 'react-router-dom'
import { ScrollBar } from './ScrollBar'

// Where the last click happened (the exit lens opens from there).
const point = { x: 0, y: 0 }
// Set after the first page has mounted: the very first page load gets no transition (the intro covers it).
let booted = false

const farthest = (x: number, y: number) =>
  Math.max(Math.hypot(x, y), Math.hypot(window.innerWidth - x, y), Math.hypot(x, window.innerHeight - y), Math.hypot(window.innerWidth - x, window.innerHeight - y))

const EASE_IN_OUT = [0.7, 0, 0.3, 1] as const
const EASE_OUT = [0.22, 1, 0.36, 1] as const

/** On leaving: the dark lens grows from the click point, its blue rim leading, until the screen is covered. */
function LensExit() {
  const [isPresent, safeToRemove] = usePresence()
  const reduce = useReducedMotion()

  useEffect(() => {
    if (!isPresent && reduce) safeToRemove()
  }, [isPresent, reduce, safeToRemove])

  if (isPresent || reduce) return null
  // One full-size disc, scaled up from nothing: drawn once, then only transformed.
  const R = farthest(point.x, point.y) + 40
  return (
    <motion.div
      aria-hidden="true"
      className="pointer-events-none fixed z-[70] rounded-full"
      style={{
        left: point.x - R,
        top: point.y - R,
        width: 2 * R,
        height: 2 * R,
        background: 'radial-gradient(circle closest-side, #060606 0 97.5%, rgba(141,177,255,0.6) 98.6%, rgba(141,177,255,0) 100%)',
      }}
      initial={{ transform: 'scale(0)' }}
      animate={{ transform: 'scale(1)' }}
      transition={{ duration: 0.4, ease: EASE_IN_OUT }}
      onAnimationComplete={() => safeToRemove()}
    />
  )
}

/** On arriving: the page fades in and settles from a slight zoom into place. */
function LensPage({ children }: { children: ReactNode }) {
  const reduce = useReducedMotion()
  const [enter] = useState(() => booted && !reduce)

  return (
    <>
      {enter ? (
        <motion.div
          style={{ transformOrigin: `50% ${window.innerHeight / 2}px` }}
          initial={{ opacity: 0, transform: 'scale(1.05)' }}
          // Back to no transform at the end: a leftover transform would pin fixed elements (the navbar) to this box.
          animate={{ opacity: 1, transform: 'scale(1)', transitionEnd: { transform: 'none' } }}
          transition={{ duration: 0.55, ease: EASE_OUT }}
        >
          {children}
        </motion.div>
      ) : (
        <div>{children}</div>
      )}
      <LensExit />
    </>
  )
}

export function RootTransition() {
  const { pathname } = useLocation()
  const outlet = useOutlet()
  const key = pathname === '/' ? 'landing' : 'app'

  useEffect(() => {
    booted = true
    point.x = window.innerWidth / 2
    point.y = window.innerHeight / 2
    const onDown = (e: PointerEvent) => {
      point.x = e.clientX
      point.y = e.clientY
    }
    // Keyboard navigation (Enter on a link) opens the lens from the centre.
    const onKey = () => {
      point.x = window.innerWidth / 2
      point.y = window.innerHeight / 2
    }
    window.addEventListener('pointerdown', onDown, { capture: true, passive: true })
    window.addEventListener('keydown', onKey, { capture: true, passive: true })
    return () => {
      window.removeEventListener('pointerdown', onDown, { capture: true })
      window.removeEventListener('keydown', onKey, { capture: true })
    }
  }, [])

  return (
    <MotionConfig reducedMotion="user">
      <AnimatePresence mode="wait" onExitComplete={() => window.scrollTo(0, 0)}>
        <LensPage key={key}>{outlet}</LensPage>
      </AnimatePresence>
      <ScrollBar />
    </MotionConfig>
  )
}

/** Cross-fade for the pages inside the checker shell. */
export function PageFade() {
  const { pathname } = useLocation()
  const outlet = useOutlet()
  return (
    <AnimatePresence mode="wait" onExitComplete={() => window.scrollTo(0, 0)}>
      <motion.div
        key={pathname}
        initial={{ opacity: 0, transform: 'translateY(12px)' }}
        animate={{ opacity: 1, transform: 'translateY(0px)', transitionEnd: { transform: 'none' }, transition: { duration: 0.4, ease: EASE_OUT } }}
        exit={{ opacity: 0, transform: 'translateY(-6px)', transition: { duration: 0.16, ease: 'easeIn' } }}
      >
        {outlet}
      </motion.div>
    </AnimatePresence>
  )
}
