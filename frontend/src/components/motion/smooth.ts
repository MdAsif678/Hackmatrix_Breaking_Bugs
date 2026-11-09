// Smooth inertial scrolling (Lenis) for the landing page. Native scroll positions stay correct, so Motion's
// scroll hooks keep working. Off under reduced motion and on touch devices (Lenis leaves touch to the OS). Owner: P1.
import Lenis from 'lenis'
import { useEffect } from 'react'

let current: Lenis | null = null
let locked = false

export const prefersReducedMotion = () =>
  typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches

/** Scroll to an element or y position, smoothly when Lenis is running. */
export function scrollToTarget(target: string | number, offset = 0) {
  if (current) {
    current.scrollTo(target as string, { offset, duration: 1.4 })
    return
  }
  const y = typeof target === 'number' ? target : (document.querySelector(target)?.getBoundingClientRect().top ?? 0) + scrollY + offset
  window.scrollTo({ top: y, behavior: prefersReducedMotion() ? 'auto' : 'smooth' })
}

/** Scroll to a y position: instantly (dragging the scrollbar) or with the smooth glide (clicking its track). */
export function scrollToY(y: number, immediate: boolean) {
  if (current) {
    current.scrollTo(y, immediate ? { immediate: true, force: true } : { duration: 1.1, force: true })
    return
  }
  window.scrollTo({ top: y, behavior: immediate || prefersReducedMotion() ? 'auto' : 'smooth' })
}

export function stopScroll(stop: boolean) {
  locked = stop
  if (stop) current?.stop()
  else current?.start()
  document.documentElement.style.overflow = stop ? 'hidden' : ''
}

export function useSmoothScroll(enabled = true) {
  useEffect(() => {
    if (!enabled || prefersReducedMotion()) return
    const lenis = new Lenis({ duration: 1.15, easing: (t) => 1 - Math.pow(1 - t, 4), wheelMultiplier: 0.9 })
    current = lenis
    if (locked) lenis.stop()
    let frame = 0
    const raf = (time: number) => {
      lenis.raf(time)
      frame = requestAnimationFrame(raf)
    }
    frame = requestAnimationFrame(raf)

    // In-page links (#checks) glide instead of jumping, leaving room for the fixed header.
    const onClick = (e: MouseEvent) => {
      const a = (e.target as HTMLElement).closest('a[href^="#"]') as HTMLAnchorElement | null
      if (!a) return
      const id = a.getAttribute('href')!
      if (id.length < 2 || !document.querySelector(id)) return
      e.preventDefault()
      lenis.scrollTo(id, { offset: -88, duration: 1.4 })
    }
    document.addEventListener('click', onClick)
    return () => {
      document.removeEventListener('click', onClick)
      cancelAnimationFrame(frame)
      lenis.destroy()
      current = null
    }
  }, [enabled])
}
