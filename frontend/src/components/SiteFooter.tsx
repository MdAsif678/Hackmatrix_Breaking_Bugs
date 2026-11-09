// The site footer, shared by the landing page and the checker pages. Owner: P1.
// Brand + HackMatrix badge, checker links, the team's GitHub profiles, a closing line and the TrustLens wordmark
// that rises as the footer scrolls in. The landing page puts its closing call to action on top (children).
import { motion, useReducedMotion, useScroll, useTransform } from 'motion/react'
import { useRef, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { Logo } from './Brand'

const TEAM = [
  ['Mohammed Asif Ali', 'MdAsif678'],
  ['Md Azhar Khan', 'azhar07kh-design'],
  ['Md Adil Shamim', 'adilsam-anon'],
  ['Md Shahzeb Ali', 'mdshahzebali'],
] as const

function GitHubIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 16 16" aria-hidden="true" className="shrink-0 opacity-70">
      <path
        fill="currentColor"
        d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"
      />
    </svg>
  )
}

/** The closing wordmark: rises out of the page bottom as the footer scrolls in. */
function Wordmark() {
  const ref = useRef<HTMLDivElement>(null)
  const reduce = useReducedMotion()
  const { scrollYProgress } = useScroll({ target: ref, offset: ['start end', 'end end'] })
  const y = useTransform(scrollYProgress, [0, 1], ['45%', '0%'])
  return (
    <div ref={ref} className="overflow-hidden pb-[1.5vw]" aria-hidden="true">
      <motion.p
        className="select-none bg-gradient-to-b from-ink/[0.16] to-ink/[0.02] bg-clip-text text-center text-[22.5vw] font-medium leading-[0.8] tracking-[-0.07em] text-transparent"
        style={reduce ? undefined : { y }}
      >
        TrustLens
      </motion.p>
    </div>
  )
}

export function SiteFooter({ children }: { children?: ReactNode }) {
  return (
    <footer className="border-t border-line">
      <div className={`wrap pb-10 ${children ? 'pt-28' : 'pt-16'}`}>
        {children}

        <div
          className={`grid grid-cols-[auto_1fr] gap-x-12 gap-y-10 sm:grid-cols-2 sm:gap-x-6 lg:grid-cols-12 ${
            children ? 'mt-24 border-t border-line pt-10' : ''
          }`}
        >
          <div className="col-span-2 lg:col-span-5">
            <Logo />
            <p className="mt-3 max-w-[32ch] text-[14px] text-faint">Scam and phishing checks for links, websites and messages.</p>
            <div className="mt-6 inline-flex items-center gap-2 rounded-full border border-line-strong py-1.5 pl-2.5 pr-3.5 text-[13px] text-muted">
              <span className="relative flex h-2 w-2">
                <span className="absolute inset-0 animate-ping rounded-full bg-link/60" />
                <span className="relative h-2 w-2 rounded-full bg-link" />
              </span>
              Built for HackMatrix 2026
            </div>
            <p className="mt-3 max-w-[40ch] text-[13px] leading-relaxed text-faint">
              AI-Powered Web Threat Detection and Digital Trust Intelligence
            </p>
          </div>
          <nav aria-label="Checker" className="lg:col-span-3">
            <h3 className="t-label">Checker</h3>
            <ul className="mt-3 space-y-2 text-[14px] sm:text-[15px]">
              <li><Link to="/check" className="nav-link">Check a link</Link></li>
              <li><Link to="/history" className="nav-link">History</Link></li>
              <li><Link to="/verify" className="nav-link">Verify a report</Link></li>
            </ul>
          </nav>
          <nav aria-label="Made by" className="lg:col-span-4">
            <h3 className="t-label">Made by</h3>
            <ul className="mt-3 space-y-2 text-[14px] sm:text-[15px]">
              {TEAM.map(([name, user]) => (
                <li key={user}>
                  <a
                    href={`https://github.com/${user}`}
                    className="nav-link group inline-flex items-center gap-2"
                    target="_blank"
                    rel="noreferrer"
                    aria-label={`${name} on GitHub`}
                  >
                    <GitHubIcon />
                    {name}
                    <svg
                      width="12"
                      height="12"
                      viewBox="0 0 12 12"
                      aria-hidden="true"
                      className="hidden -translate-x-1 opacity-0 transition-[opacity,transform] duration-150 group-hover:translate-x-0 group-hover:opacity-100 sm:block"
                    >
                      <path d="M3.5 8.5l5-5M4.5 3.5h4v4" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                  </a>
                </li>
              ))}
            </ul>
          </nav>
        </div>

        <div className="mt-12 flex flex-col gap-2 border-t border-line pt-6 text-[13px] text-faint sm:flex-row sm:justify-between">
          <p>TrustLens, 2026. Built for HackMatrix.</p>
          <p>Automated checks cannot prove a website is safe. Never share a password, OTP or card number.</p>
        </div>
      </div>
      <Wordmark />
    </footer>
  )
}
