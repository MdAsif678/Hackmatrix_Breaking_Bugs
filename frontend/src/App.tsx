// App shell for the checker pages (/check, /report, /history, /verify). Shares the site footer with the landing page. Owner: P1.
import { useState } from 'react'
import { Link, NavLink } from 'react-router-dom'
import { Logo } from './components/Brand'
import { PageFade } from './components/motion/PageTransition'
import { SiteFooter } from './components/SiteFooter'

const LINKS = [
  { to: '/check', label: 'Check' },
  { to: '/history', label: 'History' },
  { to: '/verify', label: 'Verify' },
]

export default function App() {
  const [open, setOpen] = useState(false)

  return (
    <div className="flex min-h-svh flex-col">
      <header className="fixed inset-x-0 top-0 z-10 h-[var(--nav)] border-b border-line bg-ground">
        <div className="wrap flex h-full items-center gap-8">
          <Logo />
          <nav className="hidden items-center gap-6 sm:flex" aria-label="Checker">
            {LINKS.map((l) => (
              <NavLink key={l.to} to={l.to} className="nav-link">
                {l.label}
              </NavLink>
            ))}
          </nav>
          <div className="ml-auto flex items-center gap-3">
            <Link to="/" className="nav-link hidden sm:inline">
              About
            </Link>
            <button
              type="button"
              className="btn btn-secondary w-11 px-0 sm:hidden"
              aria-expanded={open}
              aria-label={open ? 'Close menu' : 'Open menu'}
              onClick={() => setOpen((o) => !o)}
            >
              <svg width="18" height="18" viewBox="0 0 18 18" aria-hidden="true">
                {open ? (
                  <path d="M4 4l10 10M14 4L4 14" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
                ) : (
                  <path d="M2 5h14M2 9h14M2 13h14" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
                )}
              </svg>
            </button>
          </div>
        </div>
        {open && (
          <div className="fixed inset-x-0 bottom-0 top-[var(--nav)] z-10 bg-ground sm:hidden" onClick={() => setOpen(false)}>
            <nav className="wrap flex flex-col pt-4" aria-label="Menu">
              {[...LINKS, { to: '/', label: 'About TrustLens' }].map((l) => (
                <Link key={l.to} to={l.to} className="flex h-14 items-center border-b border-line text-[18px]">
                  {l.label}
                </Link>
              ))}
            </nav>
          </div>
        )}
      </header>

      <main className="wrap flex-1 pb-24 pt-[calc(var(--nav)+48px)]">
        <PageFade />
      </main>

      <SiteFooter />
    </div>
  )
}
