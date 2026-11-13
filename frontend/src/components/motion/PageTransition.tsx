// Page transitions, built on the lens. Owner: P1.
// Landing <-> checker: a dark lens with a blue rim opens from the point you clicked until it covers the page; the
// new page then appears through a lens opening from the centre of the screen, zooming out from 112% to 100%, as if
// you had looked through the lens and stepped in. Inside the checker, pages cross-fade with a small rise.
// Only clip-path and transform animate (no layout). Reduced motion: no lens, no zoom.
import { animate, AnimatePresence, motion, MotionConfig, useMotionValue, usePresence, useReducedMotion, useTransform } from 'motion/react'
import { useEffect, useState, type ReactNode } from 'react'
import { useLocation, useOutlet } from 'react-router-dom'
import { ScrollBar } from './ScrollBar'

// Where the last click happened (the exit lens opens from there).
const point = { x: 0, y: 0 }
// Set after the first page has mounted: the very first page load gets no transition (the intro covers it).
let booted = false

const diag = () => Math.hypot(window.innerWidth, window.innerHeight)
const farthest = (x: number, y: number) =>
  Math.max(Math.hypot(x, y), Math.hypot(window.innerWidth - x, y), Math.hypot(x, window.innerHeight - y), Math.hypot(window.innerWidth - x, window.innerHeight - y))

/** A ring between radius r and r + band around (cx, cy), as a clip-path (evenodd cuts the inner circle out). */
function ring(cx: number, cy: number, r: number, band: number) {
  const o = r + band
  const c = (rad: number) => `M${cx - rad} ${cy}a${rad} ${rad} 0 1 0 ${2 * rad} 0a${rad} ${rad} 0 1 0 ${-2 * rad} 0Z`
  return `path(evenodd, '${c(o)} ${r > 0 ? c(r) : ''}')`
}

/** On leaving: the dark lens opens from the click point, its blue rim leading, until the screen is covered. */
function LensExit() {
  const [isPresent, safeToRemove] = usePresence()
  const reduce = useReducedMotion()
  const r = useMotionValue(0)
  const disc = useTransform(r, (v) => `circle(${v}px at ${point.x}px ${point.y}px)`)
  const rim = useTransform(r, (v) => ring(point.x, point.y, v, 12))

  useEffect(() => {
    if (isPresent) return
    if (reduce) {
      safeToRemove()
      return
    }
    const ctl = animate(r, farthest(point.x, point.y) + 30, { duration: 0.42, ease: [0.7, 0, 0.3, 1] })
    ctl.then(() => safeToRemove())
    return () => ctl.stop()
  }, [isPresent, reduce, r, safeToRemove])

  if (isPresent || reduce) return null
  return (
    <>
      <motion.div aria-hidden="true" className="pointer-events-none fixed inset-0 z-[70] bg-link/45" style={{ clipPath: rim }} />
      <motion.div aria-hidden="true" className="pointer-events-none fixed inset-0 z-[71] bg-[#060606]" style={{ clipPath: disc }} />
    </>
  )
}

/** On arriving: the page shows through a lens that opens from the centre, and zooms out into place. */
function LensPage({ children }: { children: ReactNode }) {
  const reduce = useReducedMotion()
  const [enter] = useState(() => booted && !reduce)
  const [opening, setOpening] = useState(enter)
  const r = useMotionValue(enter ? 0 : -1)
  const cy = () => window.innerHeight / 2
  const clip = useTransform(r, (v) => (v < 0 ? 'none' : `circle(${v}px at 50% ${cy()}px)`))
  const rim = useTransform(r, (v) => ring(window.innerWidth / 2, cy(), Math.max(0, v), 10))

  useEffect(() => {
    if (!enter) return
    const ctl = animate(r, diag() / 2 + 30, { duration: 0.75, ease: [0.22, 1, 0.36, 1] })
    ctl.then(() => {
      r.set(-1) // drop the clip entirely once open
      setOpening(false)
    })
    return () => ctl.stop()
  }, [enter, r])

  return (
    <>
      <motion.div
        style={{ clipPath: clip, transformOrigin: `50% ${cy()}px` }}
        initial={{ scale: enter ? 1.12 : 1 }}
        animate={{ scale: 1 }}
        transition={{ duration: 0.85, ease: [0.22, 1, 0.36, 1] }}
      >
        {children}
      </motion.div>
      {opening && <motion.div aria-hidden="true" className="pointer-events-none fixed inset-0 z-[70] bg-link/35" style={{ clipPath: rim }} />}
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
        initial={{ opacity: 0, y: 14 }}
        animate={{ opacity: 1, y: 0, transition: { duration: 0.45, ease: [0.22, 1, 0.36, 1] } }}
        exit={{ opacity: 0, y: -8, transition: { duration: 0.2, ease: 'easeIn' } }}
      >
        {outlet}
      </motion.div>
    </AnimatePresence>
  )
}
