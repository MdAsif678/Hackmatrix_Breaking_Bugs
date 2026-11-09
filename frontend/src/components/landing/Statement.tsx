// The page's one dealt moment: a statement whose words light up as its section scrolls through.
// Scrubbed to the scrollbar (runs back on the way up); fully lit under reduced motion. Owner: P1.
import { useEffect, useRef, useState } from 'react'

const TEXT =
  'A padlock only means the connection is encrypted. Scam sites get one in minutes, so TrustLens also checks how old the site is, whose name it copies and who has already reported it.'

export function Statement() {
  const ref = useRef<HTMLHeadingElement>(null)
  const words = TEXT.split(' ')
  const [lit, setLit] = useState(words.length)

  useEffect(() => {
    const el = ref.current
    if (!el || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return
    let frame = 0
    const update = () => {
      frame = 0
      const rect = el.getBoundingClientRect()
      const vh = window.innerHeight
      // 0 when the statement's top reaches 85% of the screen, 1 when its bottom reaches 45%
      const start = vh * 0.85
      const end = vh * 0.45
      const progress = (start - rect.top) / (start - end + rect.height)
      const clamped = Math.min(1, Math.max(0, progress))
      setLit(Math.round(clamped * words.length))
    }
    const onScroll = () => {
      if (!frame) frame = requestAnimationFrame(update)
    }
    frame = requestAnimationFrame(update)
    window.addEventListener('scroll', onScroll, { passive: true })
    window.addEventListener('resize', onScroll)
    return () => {
      window.removeEventListener('scroll', onScroll)
      window.removeEventListener('resize', onScroll)
      cancelAnimationFrame(frame)
    }
  }, [words.length])

  return (
    <h2
      ref={ref}
      className="max-w-[20ch] text-[clamp(32px,3vw+12px,56px)] font-medium leading-[1.12] tracking-[-0.035em] sm:max-w-[26ch]"
    >
      {words.map((w, i) => (
        <span key={`${w}-${i}`} className="statement-word" data-lit={i < lit}>
          {w}{' '}
        </span>
      ))}
    </h2>
  )
}
