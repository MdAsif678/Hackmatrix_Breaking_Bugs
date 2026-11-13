// Landing page: what TrustLens does, shown with the product itself. Owner: P1.
// Kind: software (security tool). One accent (blue) on a neutral dark ground, Geist, sharp radius.
// Motion, in order of appearance: intro loader (first visit), the lens field behind the hero, headline words rising,
// a pinned scene where scrolling runs the five checks, a marquee tied to the scroll, sections settling in as they
// arrive, the statement lighting up, a wordmark rising at the end. Smooth scrolling via Lenis.
// Everything degrades to a still, readable page under prefers-reduced-motion.
import {
  AnimatePresence,
  motion,
  useMotionValueEvent,
  useReducedMotion,
  useScroll,
  useTransform,
} from 'motion/react'
import { useRef, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { Arrow, Logo } from '../components/Brand'
import { ChecksDiagram } from '../components/landing/ChecksDiagram'
import { DemoWindow } from '../components/landing/DemoWindow'
import { BlockedVisual, CampaignVisual, ExplainVisual, MessageVisual } from '../components/landing/FeatureVisuals'
import { ProductFrame } from '../components/landing/ProductFrame'
import { TraceCurve } from '../components/landing/ScrollTrace'
import { SiteFooter } from '../components/SiteFooter'
import { Statement } from '../components/landing/Statement'
import { LensField } from '../components/motion/LensField'
import { Preloader } from '../components/motion/Preloader'
import { ease, Magnetic, Reveal, RevealWords, spotlight } from '../components/motion/Reveal'
import { useSmoothScroll } from '../components/motion/smooth'

const NAV = [
  { href: '#demo', label: 'How it works' },
  { href: '#checks', label: 'Checks' },
  { href: '#registry', label: 'Registry' },
  { href: '#faq', label: 'FAQ' },
]

function LandingNav({ ready }: { ready: boolean }) {
  const [open, setOpen] = useState(false)
  const [solid, setSolid] = useState(false)
  const { scrollY } = useScroll()
  useMotionValueEvent(scrollY, 'change', (v) => setSolid(v > 40))

  return (
    <motion.header
      className={`fixed inset-x-0 top-0 z-20 h-[var(--nav)] border-b transition-[background-color,border-color] duration-300 ${
        open
          ? 'border-line bg-ground' // no blur here: backdrop-filter would trap the fixed menu inside the header
          : solid
            ? 'glass'
            : 'border-transparent bg-transparent'
      }`}
      initial={{ opacity: 0, y: -12 }}
      animate={ready ? { opacity: 1, y: 0 } : undefined}
      transition={{ duration: 0.8, ease, delay: 0.5 }}
    >
      <div className="wrap flex h-full items-center gap-10">
        <Logo />
        <nav className="hidden items-center gap-7 md:flex" aria-label="Main">
          {NAV.map((n) => (
            <a key={n.href} href={n.href} className="nav-link">
              {n.label}
            </a>
          ))}
        </nav>
        <div className="ml-auto flex items-center gap-3">
          <Link to="/history" className="nav-link mr-3 hidden md:inline">
            History
          </Link>
          <Link to="/check" className="btn btn-primary hidden sm:inline-flex">
            Check a link
          </Link>
          <button
            type="button"
            className="btn btn-secondary w-11 px-0 md:hidden"
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
      <AnimatePresence>
        {open && (
          <motion.div
            className="fixed inset-x-0 bottom-0 top-[var(--nav)] bg-ground md:hidden"
            onClick={() => setOpen(false)}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.25 }}
          >
            <nav className="wrap flex flex-col pt-4" aria-label="Menu">
              {[...NAV.map((n) => ({ ...n, route: false })), { href: '/history', label: 'History', route: true }].map((n, i) => (
                <motion.div
                  key={n.href}
                  initial={{ opacity: 0, y: 14 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.5, ease, delay: 0.04 * i }}
                >
                  {n.route ? (
                    <Link to={n.href} className="flex h-14 items-center border-b border-line text-[18px]">
                      {n.label}
                    </Link>
                  ) : (
                    <a href={n.href} className="flex h-14 items-center border-b border-line text-[18px]">
                      {n.label}
                    </a>
                  )}
                </motion.div>
              ))}
              <Link to="/check" className="btn btn-primary mt-6 w-full">
                Check a link
              </Link>
            </nav>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.header>
  )
}

const HERO_LINES = ['Scam checks', 'for links', 'and messages']

function Hero({ ready }: { ready: boolean }) {
  const ref = useRef<HTMLElement>(null)
  const reduce = useReducedMotion()
  const { scrollYProgress } = useScroll({ target: ref, offset: ['start start', 'end start'] })
  const y = useTransform(scrollYProgress, [0, 1], [0, 140])
  const fade = useTransform(scrollYProgress, [0, 0.75], [1, 0])
  const fieldScale = useTransform(scrollYProgress, [0, 1], [1, 1.12])
  const up = (delay: number) => ({
    initial: { opacity: 0, y: 16 },
    animate: ready ? { opacity: 1, y: 0 } : undefined,
    transition: { duration: 0.9, ease, delay },
  })

  return (
    <section ref={ref} className="relative h-svh min-h-[640px] overflow-hidden" aria-labelledby="hero-h">
      {/* Zooms out into place as the intro's lens opens, so the intro and the page read as one shot */}
      <motion.div
        className="absolute inset-0"
        initial={{ scale: 1.14 }}
        animate={ready ? { scale: 1 } : undefined}
        transition={{ duration: 1.5, ease: [0.16, 1, 0.3, 1] }}
      >
      <motion.div className="absolute inset-0" style={reduce ? undefined : { scale: fieldScale }}>
        <LensField play={ready} />
      </motion.div>
      <div className="pointer-events-none absolute inset-x-0 bottom-0 h-[45%] bg-gradient-to-t from-ground via-ground/70 to-transparent" />

      <motion.div
        className="wrap relative flex h-full flex-col justify-end pb-[clamp(32px,7vh,88px)] pt-[var(--nav)]"
        style={reduce ? undefined : { y, opacity: fade }}
      >
        <motion.p className="flex items-center gap-2 text-[14px] text-muted" {...up(0.15)}>
          <span className="h-1.5 w-1.5 rounded-full bg-link" />
          Matched against more than 140,000 known phishing domains
        </motion.p>
        <h1 id="hero-h" className="mt-5 text-[clamp(46px,8.2vw,150px)] font-medium leading-[0.94] tracking-[-0.055em]">
          {HERO_LINES.map((line, i) => (
            <span key={line} className="block">
              <RevealWords text={line} play={ready} delay={0.1 + i * 0.09} stagger={0.05} />
            </span>
          ))}
        </h1>
        <div className="mt-10 grid items-end gap-8 lg:grid-cols-12">
          <motion.p className="t-lead max-w-[40ch] lg:col-span-6" {...up(0.55)}>
            Paste a suspicious link, website or SMS. TrustLens runs five checks at the same time and shows you what it
            found, with the evidence behind every finding.
          </motion.p>
          <motion.div className="flex flex-col gap-3 sm:flex-row lg:col-span-5 lg:col-start-8 lg:justify-end" {...up(0.65)}>
            <Magnetic>
              <Link to="/check" className="btn btn-primary w-full sm:w-auto">
                Check a link
                <Arrow />
              </Link>
            </Magnetic>
            <a href="#demo" className="btn btn-secondary">
              See how it works
            </a>
          </motion.div>
        </div>
      </motion.div>
      </motion.div>
    </section>
  )
}

const DEMO_CAPTIONS = [
  ['Paste a link.', 'This one came in an SMS about a blocked PayPal account.'],
  ['Lookalike names', 'paypa1 uses the digit 1 in place of the letter l.'],
  ['Domain age', 'The domain was registered four days ago.'],
  ['Known phishing lists', 'Not listed yet. Most new scam pages are not.'],
  ['Certificate', 'Valid, which only means the connection is encrypted.'],
  ['Website and page', 'Two common protections are missing.'],
  ['High Risk', 'Fixed rules decide the verdict. The AI only explains it.'],
] as const

/** Pinned scene: the window tilts up into place, then scrolling runs the five checks one by one. */
function DemoScene() {
  const ref = useRef<HTMLElement>(null)
  const reduce = useReducedMotion()
  const enter = useScroll({ target: ref, offset: ['start end', 'start start'] }).scrollYProgress
  const pinned = useScroll({ target: ref, offset: ['start start', 'end end'] }).scrollYProgress
  const scale = useTransform(enter, [0, 1], [0.84, 1])
  const rotateX = useTransform(enter, [0, 1], [24, 0])
  const opacity = useTransform(enter, [0, 0.5], [0.2, 1])
  const [step, setStep] = useState(reduce ? 6 : 0)
  useMotionValueEvent(pinned, 'change', (p) => {
    if (reduce) return
    // About 75% of a screen of scrolling per check, then the verdict holds for the last stretch.
    setStep(p < 0.08 ? 0 : Math.min(6, Math.floor((p - 0.08) / 0.13) + 1))
  })
  const [title, text] = DEMO_CAPTIONS[step]

  return (
    <section ref={ref} id="demo" className={reduce ? 'relative' : 'relative h-[620vh]'} aria-labelledby="demo-h">
      <h2 id="demo-h" className="sr-only">
        How a check runs
      </h2>
      <div
        className={
          reduce
            ? 'py-24' // reduced motion: no pinning, the finished check is shown as a normal section
            : 'sticky top-0 flex h-svh items-start overflow-hidden pt-[calc(var(--nav)+20px)] lg:items-center lg:pt-[var(--nav)]'
        }
      >
        <div className="wrap relative grid items-center gap-4 lg:grid-cols-12 lg:gap-6">
          <div className="lg:col-span-4">
            <div className="flex items-center gap-4">
              <span className="font-mono text-[13px] text-faint tabular-nums">
                {String(Math.min(step, 5)).padStart(2, '0')} / 05
              </span>
              <span className="flex flex-1 gap-1" aria-hidden="true">
                {[1, 2, 3, 4, 5].map((n) => (
                  <span key={n} className="h-px flex-1 bg-line-strong">
                    <motion.span
                      className="block h-full origin-left bg-link"
                      animate={{ scaleX: step >= n ? 1 : 0 }}
                      transition={{ duration: 0.4, ease }}
                    />
                  </span>
                ))}
              </span>
            </div>
            <div className="mt-4 min-h-[112px] lg:mt-6 lg:min-h-[180px]" aria-live="polite">
              <AnimatePresence mode="wait" initial={false}>
                <motion.div
                  key={step}
                  initial={{ opacity: 0, y: 18 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -12 }}
                  transition={{ duration: 0.32, ease }}
                >
                  <p
                    className={`text-[clamp(28px,2.4vw+12px,48px)] font-medium leading-[1.05] tracking-[-0.04em] ${
                      step === 6 ? 'text-risk-high' : 'text-ink'
                    }`}
                  >
                    {title}
                  </p>
                  <p className="mt-3 max-w-[34ch] text-[16px] leading-relaxed text-muted">{text}</p>
                </motion.div>
              </AnimatePresence>
            </div>
          </div>
          <div className="relative [perspective:1600px] lg:col-span-7 lg:col-start-6">
            <motion.div
              aria-hidden="true"
              className="pointer-events-none absolute -inset-x-10 -inset-y-16 -z-10 bg-[radial-gradient(closest-side,rgb(37_99_235/0.22),transparent)] blur-2xl"
              animate={{ opacity: step >= 6 ? 1 : 0.45 }}
              transition={{ duration: 0.8, ease }}
            />
            <motion.div
              className="origin-bottom"
              style={reduce ? undefined : { scale, rotateX, opacity }}
            >
              <DemoWindow step={step} />
            </motion.div>
          </div>
        </div>
      </div>
    </section>
  )
}

function SectionHead({ id, title, sub }: { id: string; title: string; sub: string }) {
  return (
    <h2 id={id} className="t-h2 max-w-[34ch]">
      <RevealWords text={title} stagger={0.03} /> <RevealWords text={sub} className="text-faint" delay={0.18} stagger={0.02} />
    </h2>
  )
}

function Feature({ title, children, visual, delay }: { title: string; children: ReactNode; visual: ReactNode; delay: number }) {
  return (
    <Reveal as="article" delay={delay} className="panel spot flex flex-col gap-4 p-6" onPointerMove={spotlight}>
      <div className="min-h-[104px]">{visual}</div>
      <div className="mt-auto">
        <h3 className="t-h3">{title}</h3>
        <p className="mt-2 text-[16px] leading-relaxed text-muted">{children}</p>
      </div>
    </Reveal>
  )
}

const CHECKS = [
  ['Lookalike names', 'Addresses like paypa1 or amaz0n, brand names on domains the brand does not own, foreign letters that look Latin, raw IP addresses and the @ trick.'],
  ['Domain age', 'When the domain was registered. Most scam pages are days old when the first message goes out.'],
  ['Known phishing lists', 'OpenPhish and Phishing Army, which together list more than 140,000 reported phishing domains.'],
  ['Certificate', 'Whether the padlock is expired, revoked, self-signed, issued to another site or issued by an authority browsers distrust.'],
  ['Website and page', 'How the site is set up, and what the page asks for: login forms under a brand it does not own, card or OTP fields, hidden scripts. The AI reads the page too.'],
] as const

const FAQ = [
  [
    'Does TrustLens say a site is safe?',
    'No. The best result is Low Risk: no warning signs in the checks that ran. A scam site set up an hour ago may not be on any list yet, so stay careful with anything that asks for money or codes.',
  ],
  [
    'Is the padlock in my browser enough?',
    'The padlock means the connection is encrypted. It says nothing about who runs the site, and scam sites get one for free. TrustLens checks the certificate and also who the site imitates and how old it is.',
  ],
  [
    'Can the AI get it wrong?',
    'Yes, which is why it never decides the verdict. Fixed rules do. The AI only explains the findings, every sentence has to point to one, and an answer that calls a site safe is thrown away.',
  ],
  [
    'What goes on the blockchain?',
    'A SHA-256 fingerprint of the report and its risk level. The link, the message and anything personal stay off the chain, because a blockchain is public and permanent.',
  ],
  [
    'What happens to what I paste?',
    'The report, including the text you pasted, is stored so it can be verified and linked to similar scams later. Do not paste passwords, OTPs or card numbers; no check needs them.',
  ],
  [
    'What does Inconclusive mean?',
    'Fewer than half of the checks could run, for example because the site is down. TrustLens says so instead of guessing.',
  ],
] as const

const SEALS = [
  { title: 'Original report', ok: true, now: '0x7a3f9c…e2d491c2', chain: '0x7a3f9c…e2d491c2', note: 'Report matches its seal' },
  { title: 'Same report, verdict edited to Low Risk', ok: false, now: '0xe05b17…a84c4d18', chain: '0x7a3f9c…e2d491c2', note: 'Changed after it was sealed' },
]

export default function LandingPage() {
  const [ready, setReady] = useState(false)
  useSmoothScroll()

  return (
    <>
      <Preloader onReveal={() => setReady(true)} />
      <a href="#hero-h" className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-30 focus:bg-ground focus:px-3 focus:py-2">
        Skip to content
      </a>
      <LandingNav ready={ready} />

      <main>
        <Hero ready={ready} />
        <DemoScene />

        {/* Everything below the demo; two trace curves sweep through it */}
        <div className="relative">
        <div className="relative">

        {/* The product, big */}
        <section className="section border-t border-line" aria-labelledby="product">
          <div className="wrap">
            <SectionHead
              id="product"
              title="Every verdict comes with its evidence."
              sub="Each finding says what was seen and where it came from."
            />
            <Reveal className="mt-12" y={48}>
              <ProductFrame />
            </Reveal>
          </div>
        </section>

        {/* The moment */}
        <section className="section relative flex items-center border-t border-line bg-sunken/60" aria-label="Why the padlock is not enough">
          <TraceCurve side="right" labels={['Certificate', 'Domain age', 'Phishing lists']} />
          <div className="wrap relative">
            <Statement />
          </div>
        </section>

        {/* How it works */}
        <section className="section border-t border-line" aria-labelledby="checks">
          <div className="wrap">
            <SectionHead id="checks" title="Five checks run on every link." sub="Each one reports on its own." />
            <div className="mt-12 grid gap-10 lg:grid-cols-12 lg:gap-6">
              <ol className="border-t border-line lg:col-span-5">
                {CHECKS.map(([name, text], i) => (
                  <Reveal as="li" key={name} delay={i * 0.06} y={18} className="grid gap-1 border-b border-line py-4 sm:grid-cols-[170px_1fr] sm:gap-6">
                    <h3 className="text-[16px] font-medium text-ink">{name}</h3>
                    <p className="text-[15px] leading-relaxed text-muted">{text}</p>
                  </Reveal>
                ))}
              </ol>
              <Reveal className="lg:col-span-6 lg:col-start-7" delay={0.15} y={40}>
                <ChecksDiagram />
                <p className="mt-6 max-w-[52ch] text-[16px] leading-relaxed text-muted">
                  Fixed rules turn the findings into one of five verdicts, from Low Risk to Confirmed Malicious. Google
                  Gemini then writes the explanation, using only what the checks found.
                </p>
              </Reveal>
            </div>
          </div>
        </section>

        {/* Features */}
        <section className="section relative border-t border-line" aria-labelledby="report">
          <div className="wrap relative">
            <SectionHead id="report" title="Paste the whole message." sub="Every link inside it gets checked." />
            <div className="mt-10 grid gap-6 md:grid-cols-2">
              <Feature title="Links pulled out of messages" visual={<MessageVisual />} delay={0}>
                Forward the SMS, WhatsApp text or email as it is. Every link in it gets the full set of checks.
              </Feature>
              <Feature title="Explanations that cite their evidence" visual={<ExplainVisual />} delay={0.08}>
                Each sentence of the explanation points to a finding. A sentence the checks cannot back is removed
                before you see it.
              </Feature>
              <Feature title="Repeat scams linked together" visual={<CampaignVisual />} delay={0}>
                Reports that share a server, a certificate, a phone number or a UPI ID are shown side by side as a
                possible campaign.
              </Feature>
              <Feature title="Internal addresses refused" visual={<BlockedVisual />} delay={0.08}>
                The checker only visits public websites, so nobody can point it at the server it runs on.
              </Feature>
            </div>
          </div>
        </section>

        {/* Blockchain registry */}
        <section className="section border-t border-line bg-sunken/60" aria-labelledby="registry">
          <div className="wrap">
            <SectionHead
              id="registry"
              title="Reports you can verify later."
              sub="A fingerprint of each report is stored on Ethereum. Change one word and it stops matching."
            />
            <div className="mt-12 grid gap-10 lg:grid-cols-12 lg:gap-6">
              <ol className="border-t border-line lg:col-span-5">
                {[
                  ['Seal', 'TrustLens computes a SHA-256 fingerprint of the report and records it with the risk level, the time and the TrustLens wallet.'],
                  ['Share', 'Send the report to a bank, a college or the cyber crime cell as evidence.'],
                  ['Verify', 'Anyone can recompute the fingerprint and compare it with the record on the chain, which nobody can edit.'],
                ].map(([step, text], i) => (
                  <Reveal as="li" key={step} delay={i * 0.08} y={18} className="grid grid-cols-[32px_1fr] gap-4 border-b border-line py-5">
                    <span className="font-mono text-[14px] text-faint">0{i + 1}</span>
                    <div>
                      <h3 className="text-[16px] font-medium">{step}</h3>
                      <p className="mt-1 text-[15px] leading-relaxed text-muted">{text}</p>
                    </div>
                  </Reveal>
                ))}
              </ol>
              <Reveal className="lg:col-span-6 lg:col-start-7" delay={0.15} y={40}>
                <div className="window" role="img" aria-label="Two verification results: an untouched report matches its seal, an edited one does not">
                  {SEALS.map((r) => (
                    <div key={r.title} className="border-b border-line p-6 last:border-b-0">
                      <div className="flex items-center justify-between gap-4">
                        <p className="text-[15px] text-ink">{r.title}</p>
                        <span className={`inline-flex items-center gap-2 text-[14px] ${r.ok ? 'text-risk-low' : 'text-risk-malicious'}`}>
                          <svg width="14" height="14" viewBox="0 0 14 14" aria-hidden="true">
                            {r.ok ? (
                              <path d="M3 7.2l2.6 2.6L11 4.4" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
                            ) : (
                              <path d="M4 4l6 6M10 4l-6 6" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" />
                            )}
                          </svg>
                          {r.note}
                        </span>
                      </div>
                      <dl className="mt-4 grid gap-2 font-mono text-[13px]">
                        <div className="flex justify-between gap-4">
                          <dt className="text-faint">Recomputed now</dt>
                          <dd className={r.ok ? 'text-muted' : 'text-risk-malicious'}>{r.now}</dd>
                        </div>
                        <div className="flex justify-between gap-4">
                          <dt className="text-faint">On the chain</dt>
                          <dd className="text-muted">{r.chain}</dd>
                        </div>
                      </dl>
                    </div>
                  ))}
                  <p className="border-t border-line bg-sunken px-6 py-4 text-[13px] text-faint">
                    Links, messages and personal details never go on-chain.
                  </p>
                </div>
              </Reveal>
            </div>
          </div>
        </section>

        {/* FAQ, every answer open */}
        <section className="section relative border-t border-line" aria-labelledby="faq">
          <TraceCurve side="left" labels={['SHA-256', 'Ethereum', 'Verified']} />
          {/* Heading pinned on the left while the questions scroll on the right; the curve sweeps through the space below it */}
          <div className="wrap relative grid gap-12 lg:grid-cols-12 lg:gap-6">
            <div className="lg:sticky lg:top-[calc(var(--nav)+48px)] lg:col-span-4 lg:self-start">
              <SectionHead id="faq" title="Questions about TrustLens." sub="What it can and cannot tell you." />
            </div>
            <dl className="grid gap-y-10 lg:col-span-7 lg:col-start-6">
              {FAQ.map(([q, a]) => (
                <Reveal key={q} y={20} className="border-t border-line pt-6">
                  <dt className="text-[18px] font-medium tracking-[-0.01em]">{q}</dt>
                  <dd className="mt-2 max-w-[56ch] text-[16px] leading-relaxed text-muted">{a}</dd>
                </Reveal>
              ))}
            </dl>
          </div>
        </section>
        </div>
        </div>
      </main>

      {/* Closing call to action on top of the shared footer */}
      <SiteFooter>
        <div className="grid gap-8 lg:grid-cols-12 lg:items-end">
          <p className="text-[clamp(36px,3.6vw+14px,72px)] font-medium leading-[1.04] tracking-[-0.04em] lg:col-span-8">
            <RevealWords text="Check the next link before you tap it." stagger={0.05} />
          </p>
          <div className="lg:col-span-4 lg:justify-self-end">
            <Magnetic>
              <Link to="/check" className="btn btn-primary w-full sm:w-auto">
                Check a link
                <Arrow />
              </Link>
            </Magnetic>
          </div>
        </div>
      </SiteFooter>
    </>
  )
}
