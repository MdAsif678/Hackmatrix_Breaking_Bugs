// Landing page: what TrustLens does, shown with the product itself. Owner: P1.
// Kind: software (security tool). One accent (blue) on a neutral dark ground, Geist, sharp radius.
// Motion: hero entrance once on load, one hero loop (pausable), the statement moment, diagram pulses on hover.
import { useState, type CSSProperties, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { Arrow, Logo } from '../components/Brand'
import { ChecksDiagram } from '../components/landing/ChecksDiagram'
import { BlockedVisual, CampaignVisual, ExplainVisual, MessageVisual } from '../components/landing/FeatureVisuals'
import { HeroWindow } from '../components/landing/HeroWindow'
import { ProductFrame } from '../components/landing/ProductFrame'
import { Statement } from '../components/landing/Statement'

const NAV = [
  { href: '#product', label: 'Product' },
  { href: '#checks', label: 'Checks' },
  { href: '#registry', label: 'Registry' },
  { href: '#faq', label: 'FAQ' },
]

const delay = (ms: number): CSSProperties => ({ animationDelay: `${ms}ms` })

function LandingNav() {
  const [open, setOpen] = useState(false)
  return (
    <header className="fixed inset-x-0 top-0 z-20 h-[var(--nav)] border-b border-line bg-ground">
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
      {open && (
        <div className="fixed inset-x-0 bottom-0 top-[var(--nav)] bg-ground md:hidden" onClick={() => setOpen(false)}>
          <nav className="wrap flex flex-col pt-4" aria-label="Menu">
            {NAV.map((n) => (
              <a key={n.href} href={n.href} className="flex h-14 items-center border-b border-line text-[18px]">
                {n.label}
              </a>
            ))}
            <Link to="/history" className="flex h-14 items-center border-b border-line text-[18px]">
              History
            </Link>
            <Link to="/check" className="btn btn-primary mt-6 w-full">
              Check a link
            </Link>
          </nav>
        </div>
      )}
    </header>
  )
}

function Hero() {
  return (
    <section className="flex min-h-svh items-start pb-16 pt-[calc(var(--nav)+64px)] lg:pt-[calc(var(--nav)+72px)]" aria-labelledby="hero-h">
      <div className="wrap grid gap-12 lg:grid-cols-12 lg:gap-6">
        <div className="lg:col-span-5 lg:pt-6">
          <p className="enter-fade text-[14px] text-muted" style={delay(0)}>
            Matched against more than 140,000 known phishing domains
          </p>
          <h1 id="hero-h" className="t-h1 mt-4">
            <span className="enter-line">
              <span style={delay(0)}>Scam checks</span>
            </span>
            <span className="enter-line">
              <span style={delay(80)}>for links</span>
            </span>
            <span className="enter-line">
              <span style={delay(160)}>and messages</span>
            </span>
          </h1>
          <p className="t-lead enter-fade mt-6 max-w-[34ch]" style={delay(420)}>
            Paste a suspicious link, website or SMS. TrustLens runs five checks at the same time and shows you what it
            found, with the evidence behind every finding.
          </p>
          <div className="mt-8 flex flex-col gap-3 sm:flex-row">
            <Link to="/check" className="btn btn-primary enter-fade" style={delay(480)}>
              Check a link
              <Arrow />
            </Link>
            <a href="#checks" className="btn btn-secondary enter-fade" style={delay(540)}>
              See the five checks
            </a>
          </div>
        </div>
        <div className="enter-settle lg:col-span-6 lg:col-start-7">
          <HeroWindow />
        </div>
      </div>
    </section>
  )
}

function SectionHead({ id, title, sub }: { id: string; title: ReactNode; sub: ReactNode }) {
  return (
    <h2 id={id} className="t-h2 max-w-[34ch]">
      {title} <span className="text-faint">{sub}</span>
    </h2>
  )
}

function Feature({ title, children, visual }: { title: string; children: ReactNode; visual: ReactNode }) {
  return (
    <article className="panel flex flex-col gap-4 p-6">
      <div className="min-h-[104px]">{visual}</div>
      <div className="mt-auto">
        <h3 className="t-h3">{title}</h3>
        <p className="mt-2 text-[16px] leading-relaxed text-muted">{children}</p>
      </div>
    </article>
  )
}

const CHECKS = [
  ['Lookalike names', 'Addresses like paypa1 or amaz0n, brand names on domains the brand does not own, foreign letters that look Latin, raw IP addresses and the @ trick.'],
  ['Domain age', 'When the domain was registered. Most scam pages are days old when the first message goes out.'],
  ['Known phishing lists', 'OpenPhish and Phishing Army, which together list more than 140,000 reported phishing domains.'],
  ['Certificate', 'Whether the padlock is expired, revoked, self-signed, issued to another site or issued by an authority browsers distrust.'],
  ['Security settings', 'How the site is set up: HTTPS redirects, security headers and redirects to other websites.'],
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

export default function LandingPage() {
  return (
    <>
      <a href="#hero-h" className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-30 focus:bg-ground focus:px-3 focus:py-2">
        Skip to content
      </a>
      <LandingNav />

      <main>
        <Hero />

        {/* The product, big */}
        <section className="section border-t border-line" aria-labelledby="product">
          <div className="wrap">
            <SectionHead
              id="product"
              title="Every verdict comes with its evidence."
              sub="Each finding says what was seen and where it came from."
            />
            <div className="mt-12">
              <ProductFrame />
            </div>
          </div>
        </section>

        {/* The moment */}
        <section className="section flex items-center border-t border-line bg-sunken" aria-label="Why the padlock is not enough">
          <div className="wrap">
            <Statement />
          </div>
        </section>

        {/* How it works */}
        <section className="section border-t border-line" aria-labelledby="checks">
          <div className="wrap">
            <SectionHead
              id="checks"
              title="Five checks run on every link."
              sub="Each one reports on its own."
            />
            <div className="mt-12 grid gap-10 lg:grid-cols-12 lg:gap-6">
              <ol className="divide-y divide-line border-y border-line lg:col-span-5">
                {CHECKS.map(([name, text]) => (
                  <li key={name} className="grid gap-1 py-4 sm:grid-cols-[170px_1fr] sm:gap-6">
                    <h3 className="text-[16px] font-medium text-ink">{name}</h3>
                    <p className="text-[15px] leading-relaxed text-muted">{text}</p>
                  </li>
                ))}
              </ol>
              <div className="lg:col-span-6 lg:col-start-7">
                <ChecksDiagram />
                <p className="mt-6 max-w-[52ch] text-[16px] leading-relaxed text-muted">
                  Fixed rules turn the findings into one of five verdicts, from Low Risk to Confirmed Malicious. Google
                  Gemini then writes the explanation, using only what the checks found.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* Features */}
        <section className="section border-t border-line" aria-labelledby="report">
          <div className="wrap">
            <SectionHead
              id="report"
              title="Paste the whole message."
              sub="Every link inside it gets checked."
            />
            <div className="mt-10 grid gap-6 md:grid-cols-2">
              <Feature title="Links pulled out of messages" visual={<MessageVisual />}>
                Forward the SMS, WhatsApp text or email as it is. Every link in it gets the full set of checks.
              </Feature>
              <Feature title="Explanations that cite their evidence" visual={<ExplainVisual />}>
                Each sentence of the explanation points to a finding. A sentence the checks cannot back is removed
                before you see it.
              </Feature>
              <Feature title="Repeat scams linked together" visual={<CampaignVisual />}>
                Reports that share a server, a certificate, a phone number or a UPI ID are shown side by side as a
                possible campaign.
              </Feature>
              <Feature title="Internal addresses refused" visual={<BlockedVisual />}>
                The checker only visits public websites, so nobody can point it at the server it runs on.
              </Feature>
            </div>
          </div>
        </section>

        {/* Blockchain registry */}
        <section id="registry-section" className="section border-t border-line bg-sunken" aria-labelledby="registry">
          <div className="wrap">
            <SectionHead
              id="registry"
              title="Reports you can verify later."
              sub="A fingerprint of each report is stored on Ethereum. Change one word and it stops matching."
            />
            <div className="mt-12 grid gap-10 lg:grid-cols-12 lg:gap-6">
              <ol className="divide-y divide-line border-y border-line lg:col-span-5">
                {[
                  ['Seal', 'TrustLens computes a SHA-256 fingerprint of the report and records it with the risk level, the time and the TrustLens wallet.'],
                  ['Share', 'Send the report to a bank, a college or the cyber crime cell as evidence.'],
                  ['Verify', 'Anyone can recompute the fingerprint and compare it with the record on the chain, which nobody can edit.'],
                ].map(([step, text], i) => (
                  <li key={step} className="grid grid-cols-[32px_1fr] gap-4 py-5">
                    <span className="font-mono text-[14px] text-faint">0{i + 1}</span>
                    <div>
                      <h3 className="text-[16px] font-medium">{step}</h3>
                      <p className="mt-1 text-[15px] leading-relaxed text-muted">{text}</p>
                    </div>
                  </li>
                ))}
              </ol>
              <div className="lg:col-span-6 lg:col-start-7">
                <div className="window" role="img" aria-label="Two verification results: an untouched report matches its seal, an edited one does not">
                  {[
                    {
                      title: 'Original report',
                      ok: true,
                      now: '0x7a3f9c…e2d491c2',
                      chain: '0x7a3f9c…e2d491c2',
                      note: 'Report matches its seal',
                    },
                    {
                      title: 'Same report, verdict edited to Low Risk',
                      ok: false,
                      now: '0xe05b17…a84c4d18',
                      chain: '0x7a3f9c…e2d491c2',
                      note: 'Changed after it was sealed',
                    },
                  ].map((r) => (
                    <div key={r.title} className="border-b border-line p-6 last:border-b-0">
                      <div className="flex items-center justify-between gap-4">
                        <p className="text-[15px] text-ink">{r.title}</p>
                        <span
                          className={`inline-flex items-center gap-2 text-[14px] ${r.ok ? 'text-risk-low' : 'text-risk-malicious'}`}
                        >
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
              </div>
            </div>
          </div>
        </section>

        {/* FAQ, every answer open */}
        <section className="section border-t border-line" aria-labelledby="faq">
          <div className="wrap">
            <SectionHead id="faq" title="Questions about TrustLens." sub="What it can and cannot tell you." />
            <dl className="mt-12 grid gap-x-6 gap-y-10 md:grid-cols-2">
              {FAQ.map(([q, a]) => (
                <div key={q} className="border-t border-line pt-6">
                  <dt className="text-[18px] font-medium tracking-[-0.01em]">{q}</dt>
                  <dd className="mt-2 max-w-[56ch] text-[16px] leading-relaxed text-muted">{a}</dd>
                </div>
              ))}
            </dl>
          </div>
        </section>
      </main>

      {/* Close and footer, one section */}
      <footer className="border-t border-line">
        <div className="wrap pb-10 pt-28">
          <div className="grid gap-8 lg:grid-cols-12 lg:items-end">
            <p className="text-[clamp(36px,3.6vw+14px,72px)] font-medium leading-[1.04] tracking-[-0.04em] lg:col-span-8">
              Check the next link before you tap it.
            </p>
            <div className="lg:col-span-4 lg:justify-self-end">
              <Link to="/check" className="btn btn-primary w-full sm:w-auto">
                Check a link
                <Arrow />
              </Link>
            </div>
          </div>

          <div className="mt-24 grid gap-8 border-t border-line pt-8 sm:grid-cols-3">
            <div>
              <Logo />
              <p className="mt-3 max-w-[30ch] text-[14px] text-faint">
                Scam and phishing checks for links, websites and messages.
              </p>
            </div>
            <nav aria-label="Checker">
              <h3 className="t-label">Checker</h3>
              <ul className="mt-3 space-y-2 text-[15px]">
                <li><Link to="/check" className="nav-link">Check a link</Link></li>
                <li><Link to="/history" className="nav-link">History</Link></li>
                <li><Link to="/verify" className="nav-link">Verify a report</Link></li>
              </ul>
            </nav>
            <nav aria-label="Project">
              <h3 className="t-label">Project</h3>
              <ul className="mt-3 space-y-2 text-[15px]">
                <li>
                  <a href="https://github.com/MdAsif678/Hackmatrix_Breaking_Bugs" className="nav-link" target="_blank" rel="noreferrer">
                    Source on GitHub
                  </a>
                </li>
                <li>
                  <a href="https://github.com/MdAsif678/Hackmatrix_Breaking_Bugs/blob/main/docs/security-methodology.md" className="nav-link" target="_blank" rel="noreferrer">
                    Security methodology
                  </a>
                </li>
              </ul>
            </nav>
          </div>

          <div className="mt-10 flex flex-col gap-2 text-[13px] text-faint sm:flex-row sm:justify-between">
            <p>TrustLens, 2026. Built at HackMatrix.</p>
            <p>Automated checks cannot prove a website is safe.</p>
          </div>
        </div>
      </footer>
    </>
  )
}
