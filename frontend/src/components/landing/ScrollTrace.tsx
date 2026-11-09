// A trace curve: one line that sweeps in from the side of the screen, arcs out into the page and back off the same
// side, drawing itself as its section scrolls through. Used two or three times on the landing page, alternating
// sides. Along it sit three "hops" (what that part of TrustLens touches, e.g. DNS, TLS) that switch on as the line
// passes them, and a glowing tip leads the line. Behind the content; cheap: one stroke-dashoffset per frame.
// Reduced motion: drawn in full, all hops on, no tip. Owner: P1.
import { motion, useMotionValue, useMotionValueEvent, useReducedMotion, useScroll, useSpring } from 'motion/react'
import { useEffect, useLayoutEffect, useRef, useState } from 'react'

const HOPS = [0.28, 0.5, 0.72] // where the hops sit, as a fraction of the line's length

export function TraceCurve({ side = 'left', labels }: { side?: 'left' | 'right'; labels: [string, string, string] }) {
  const reduce = useReducedMotion()
  const ref = useRef<HTMLDivElement>(null)
  const pathRef = useRef<SVGPathElement>(null)
  const [size, setSize] = useState<{ w: number; h: number } | null>(null)
  const [hops, setHops] = useState<{ x: number; y: number }[]>([])
  const [lit, setLit] = useState(0)
  const total = useRef(0)

  const { scrollYProgress } = useScroll({ target: ref, offset: ['start 85%', 'end 45%'] })
  const p = useSpring(scrollYProgress, { stiffness: 80, damping: 24, restDelta: 0.0005 })
  const tipX = useMotionValue(-100)
  const tipY = useMotionValue(-100)
  const tipOn = useMotionValue(0)

  useEffect(() => {
    const el = ref.current
    if (!el) return
    const ro = new ResizeObserver(([e]) => setSize({ w: e.contentRect.width, h: e.contentRect.height }))
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  // From the side, out to about a third of the width at mid-height, and back off the same side.
  let d = ''
  if (size) {
    const { w, h } = size
    const mobile = w < 640
    const edge = side === 'left' ? -0.06 * w : 1.06 * w
    const peak = side === 'left' ? (mobile ? 0.36 : 0.22) * w : (mobile ? 0.64 : 0.74) * w
    const handle = (peak - 0.25 * edge) / 0.75 // a cubic with both handles at x = handle peaks at x = peak
    d = `M${edge},${0.06 * h} C${handle},${0.02 * h} ${handle},${0.98 * h} ${edge},${0.94 * h}`
  }

  useLayoutEffect(() => {
    const path = pathRef.current
    if (!path || !d) return
    total.current = path.getTotalLength()
    setHops(HOPS.map((f) => {
      const pt = path.getPointAtLength(total.current * f)
      return { x: pt.x, y: pt.y }
    }))
  }, [d])

  useMotionValueEvent(p, 'change', (v) => {
    const path = pathRef.current
    if (!path || !total.current) return
    const pt = path.getPointAtLength(Math.min(1, Math.max(0, v)) * total.current)
    tipX.set(pt.x)
    tipY.set(pt.y)
    tipOn.set(v > 0.005 && v < 0.995 ? 1 : 0)
    setLit(HOPS.filter((f) => v >= f).length)
  })

  const right = side === 'right'
  return (
    <div ref={ref} aria-hidden="true" className="pointer-events-none absolute inset-x-0 -bottom-[12%] -top-[12%] overflow-hidden opacity-60 sm:opacity-100">
      {size && (
        <svg width={size.w} height={size.h} viewBox={`0 0 ${size.w} ${size.h}`} fill="none" className="absolute inset-0">
          {/* soft glow under the line */}
          <motion.path d={d} stroke="rgb(37 99 235 / 0.16)" strokeWidth="8" strokeLinecap="round" style={reduce ? undefined : { pathLength: p }} />
          <motion.path
            ref={pathRef}
            d={d}
            stroke="rgb(141 177 255 / 0.8)"
            strokeWidth="1.5"
            strokeLinecap="round"
            style={reduce ? undefined : { pathLength: p }}
          />
          {hops.map((hop, i) => {
            const on = reduce || i < lit
            return (
              <g key={labels[i]} transform={`translate(${hop.x} ${hop.y})`} className="transition-opacity duration-500" opacity={on ? 1 : 0}>
                <circle r="10" fill="#0a0a0a" stroke="rgb(141 177 255 / 0.45)" />
                <circle r="3.5" fill="#8db1ff" />
                <text
                  x={right ? -20 : 20}
                  y="4"
                  textAnchor={right ? 'end' : 'start'}
                  fontFamily="Geist Mono, monospace"
                  fontSize="11"
                  letterSpacing="0.08em"
                  fill="#8db1ff"
                >
                  {labels[i].toUpperCase()}
                </text>
              </g>
            )
          })}
        </svg>
      )}
      {!reduce && (
        <motion.div className="absolute left-0 top-0" style={{ x: tipX, y: tipY, opacity: tipOn }}>
          <span className="absolute -left-[5px] -top-[5px] h-[10px] w-[10px] rounded-full bg-link shadow-[0_0_22px_6px_rgb(141_177_255/0.5)]" />
        </motion.div>
      )}
    </div>
  )
}
