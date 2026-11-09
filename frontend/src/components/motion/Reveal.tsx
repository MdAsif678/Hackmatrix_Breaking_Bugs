// Reveal helpers. Things settle into place once as they enter the screen; transforms are skipped under reduced
// motion (MotionConfig reducedMotion="user" at the root). Owner: P1.
import { motion, useMotionValue, useSpring } from 'motion/react'
import type { PointerEvent, ReactNode } from 'react'

export const ease = [0.22, 1, 0.36, 1] as const

/** Fades and rises into place once, when it scrolls into view. */
export function Reveal({
  children, delay = 0, y = 28, className, as = 'div', onPointerMove,
}: {
  children: ReactNode
  delay?: number
  y?: number
  className?: string
  as?: 'div' | 'span' | 'li' | 'article' | 'section'
  onPointerMove?: (e: PointerEvent<HTMLElement>) => void
}) {
  const Tag = motion[as] as typeof motion.div
  return (
    <Tag
      className={className}
      onPointerMove={onPointerMove}
      initial={{ opacity: 0, y }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '0px 0px -12% 0px' }}
      transition={{ duration: 0.9, ease, delay }}
    >
      {children}
    </Tag>
  )
}

/** Each word rises out of its own mask, one after another (headlines). */
export function RevealWords({
  text, className, delay = 0, stagger = 0.035, play, inView = true,
}: { text: string; className?: string; delay?: number; stagger?: number; play?: boolean; inView?: boolean }) {
  const words = text.split(' ')
  const variants = {
    hidden: { y: '108%' },
    shown: (i: number) => ({ y: '0%', transition: { duration: 0.9, ease, delay: delay + i * stagger } }),
  }
  return (
    <span className={className}>
      {words.map((w, i) => (
        <span key={`${w}-${i}`} className="inline-block overflow-hidden pb-[0.1em] align-top -mb-[0.1em]">
          <motion.span
            className="inline-block"
            variants={variants}
            custom={i}
            initial="hidden"
            {...(play !== undefined
              ? { animate: play ? 'shown' : undefined }
              : inView
                ? { whileInView: 'shown', viewport: { once: true, margin: '0px 0px -10% 0px' } }
                : { animate: 'shown' })}
          >
            {w}
            {i < words.length - 1 ? ' ' : ''}
          </motion.span>
        </span>
      ))}
    </span>
  )
}

/** Pulls its child a little toward the pointer (fine pointers only), springs back on leave. */
export function Magnetic({ children, strength = 0.28 }: { children: ReactNode; strength?: number }) {
  const x = useMotionValue(0)
  const y = useMotionValue(0)
  const sx = useSpring(x, { stiffness: 220, damping: 18, mass: 0.4 })
  const sy = useSpring(y, { stiffness: 220, damping: 18, mass: 0.4 })
  const fine = typeof window !== 'undefined' && window.matchMedia('(hover: hover) and (pointer: fine)').matches
  const move = (e: PointerEvent<HTMLSpanElement>) => {
    if (!fine) return
    const r = e.currentTarget.getBoundingClientRect()
    x.set((e.clientX - (r.left + r.width / 2)) * strength)
    y.set((e.clientY - (r.top + r.height / 2)) * strength)
  }
  const leave = () => {
    x.set(0)
    y.set(0)
  }
  return (
    <motion.span className="inline-flex" style={{ x: sx, y: sy }} onPointerMove={move} onPointerLeave={leave}>
      {children}
    </motion.span>
  )
}

/** Sets --mx / --my on the element under the pointer, for the .spot glow in index.css. */
export function spotlight(e: PointerEvent<HTMLElement>) {
  const r = e.currentTarget.getBoundingClientRect()
  e.currentTarget.style.setProperty('--mx', `${e.clientX - r.left}px`)
  e.currentTarget.style.setProperty('--my', `${e.clientY - r.top}px`)
}
