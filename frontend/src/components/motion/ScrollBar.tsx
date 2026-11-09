// Our own scrollbar (the browser's is hidden on mouse/trackpad devices, see index.css). Owner: P1.
// A hairline on the right edge with a slim thumb. It is nearly invisible at rest; while you scroll, hover near the
// edge or drag, the line shows, the thumb thickens and a small percentage rides beside it. Drag the thumb to scroll,
// or click the line to glide there. Positions are written straight to the DOM (no React re-render per frame).
// Not shown on touch screens, which keep their own bars. Purely visual for assistive tech: keyboard and wheel
// scrolling are unchanged.
import { useEffect, useRef, useState, type PointerEvent as ReactPointerEvent } from 'react'
import { scrollToY } from './smooth'

const INSET = 12 // px of space above and below the track
const MIN_THUMB = 40

export function ScrollBar() {
  const [enabled] = useState(() => typeof window !== 'undefined' && window.matchMedia('(pointer: fine)').matches)
  const [active, setActive] = useState(false)
  const [hover, setHover] = useState(false)
  const [dragging, setDragging] = useState(false)
  const [scrollable, setScrollable] = useState(false)
  const thumb = useRef<HTMLDivElement>(null)
  const label = useRef<HTMLSpanElement>(null)
  const drag = useRef<{ startY: number; startScroll: number } | null>(null)

  const metrics = () => {
    const vh = window.innerHeight
    const doc = document.documentElement.scrollHeight
    const track = vh - INSET * 2
    const size = Math.max(MIN_THUMB, (track * vh) / doc)
    return { vh, doc, track, size, max: doc - vh }
  }

  useEffect(() => {
    if (!enabled) return
    let frame = 0
    let idle = 0
    const paint = () => {
      frame = 0
      const m = metrics()
      setScrollable(m.max > 4)
      const p = m.max > 0 ? Math.min(1, Math.max(0, window.scrollY / m.max)) : 0
      const y = INSET + p * (m.track - m.size)
      if (thumb.current) {
        thumb.current.style.height = `${m.size}px`
        thumb.current.style.transform = `translateY(${y}px)`
      }
      if (label.current) {
        label.current.textContent = `${String(Math.round(p * 100)).padStart(2, '0')}%`
        label.current.style.transform = `translateY(${y + m.size / 2 - 7}px)`
      }
    }
    const request = () => {
      if (!frame) frame = requestAnimationFrame(paint)
    }
    const onScroll = () => {
      request()
      setActive(true)
      clearTimeout(idle)
      idle = window.setTimeout(() => setActive(false), 1100)
    }
    paint()
    window.addEventListener('scroll', onScroll, { passive: true })
    window.addEventListener('resize', request)
    // The page height changes when routes change, images load or sections reveal.
    const ro = new ResizeObserver(request)
    ro.observe(document.body)
    return () => {
      window.removeEventListener('scroll', onScroll)
      window.removeEventListener('resize', request)
      ro.disconnect()
      cancelAnimationFrame(frame)
      clearTimeout(idle)
    }
  }, [enabled])

  if (!enabled) return null

  const onThumbDown = (e: ReactPointerEvent<HTMLDivElement>) => {
    e.preventDefault()
    e.stopPropagation()
    e.currentTarget.setPointerCapture(e.pointerId)
    drag.current = { startY: e.clientY, startScroll: window.scrollY }
    setDragging(true)
  }
  const onThumbMove = (e: ReactPointerEvent<HTMLDivElement>) => {
    if (!drag.current) return
    const m = metrics()
    const perPx = m.max / Math.max(1, m.track - m.size)
    scrollToY(drag.current.startScroll + (e.clientY - drag.current.startY) * perPx, true)
  }
  const onThumbUp = () => {
    drag.current = null
    setDragging(false)
  }
  // Click on the line: glide so the thumb centres on that point.
  const onTrackDown = (e: ReactPointerEvent<HTMLDivElement>) => {
    const m = metrics()
    const p = (e.clientY - INSET - m.size / 2) / Math.max(1, m.track - m.size)
    scrollToY(Math.min(1, Math.max(0, p)) * m.max, false)
  }

  const on = active || hover || dragging
  return (
    <div
      aria-hidden="true"
      className={`fixed bottom-0 right-0 top-0 z-[55] w-5 select-none transition-opacity duration-300 ${scrollable ? '' : 'pointer-events-none opacity-0'}`}
      onPointerEnter={() => setHover(true)}
      onPointerLeave={() => setHover(false)}
      onPointerDown={onTrackDown}
    >
      {/* the line */}
      <div
        className="absolute right-[7px] w-px bg-ink transition-opacity duration-500"
        style={{ top: INSET, bottom: INSET, opacity: on ? 0.12 : 0.04 }}
      />
      {/* the thumb, with a wider invisible grip around it */}
      <div
        ref={thumb}
        className="absolute right-0 top-0 flex w-5 cursor-grab justify-end pr-[5px] active:cursor-grabbing"
        onPointerDown={onThumbDown}
        onPointerMove={onThumbMove}
        onPointerUp={onThumbUp}
        onPointerCancel={onThumbUp}
      >
        <span
          className="block h-full rounded-full transition-[width,background-color,opacity] duration-300 ease-[cubic-bezier(0.22,1,0.36,1)]"
          style={{
            width: on ? 5 : 3,
            marginRight: on ? 0 : 1,
            background: dragging ? 'var(--color-link)' : 'var(--color-ink)',
            opacity: on ? 0.75 : 0.28,
          }}
        />
      </div>
      {/* the percentage beside the thumb */}
      <span
        ref={label}
        className="pointer-events-none absolute right-6 top-0 font-mono text-[10px] tabular-nums tracking-[0.08em] text-faint transition-opacity duration-300"
        style={{ opacity: on ? 1 : 0 }}
      />
    </div>
  )
}
