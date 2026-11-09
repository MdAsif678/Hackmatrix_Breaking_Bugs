// Diagram card: one input, the TrustLens hub, five checks in parallel, one verdict.
// Packets loop through it in order (input, hub, the five checks at once, verdict), only while it is on screen;
// the animation is CSS on stroke-dashoffset and stops entirely off screen and under reduced motion. Owner: P1.
import { useInView } from 'motion/react'
import { useRef } from 'react'

const LANES = ['Lookalike names', 'Domain age', 'Phishing lists', 'Certificate', 'Security settings']
const LANE_Y = [50, 120, 190, 260, 330]

export function ChecksDiagram() {
  const inPath = 'M124 190 H164'
  const outPaths = LANE_Y.map((y) => `M276 190 C300 190 300 ${y} 324 ${y}`)
  const joinPaths = LANE_Y.map((y) => `M484 ${y} C508 ${y} 508 190 532 190`)
  const ref = useRef<HTMLDivElement>(null)
  const live = useInView(ref, { margin: '100px 0px' })
  // Stage of each packet in the loop: 0 = into TrustLens, 1 = out to the checks, 2 = into the verdict.
  const packets = [
    { d: inPath, stage: 0 },
    ...outPaths.map((d) => ({ d, stage: 1 })),
    ...joinPaths.map((d) => ({ d, stage: 2 })),
  ]

  return (
    <div ref={ref} className={`panel diagram p-4 sm:p-6 ${live ? 'is-live' : ''}`} role="img" aria-label="A link or SMS goes into TrustLens, which runs five checks in parallel and combines them into one verdict">
      <svg viewBox="0 0 640 380" className="h-auto w-full" aria-hidden="true">
        <g fill="none" stroke="rgb(237 237 239 / 0.22)" strokeWidth="1.2">
          <path d={inPath} />
          {outPaths.map((d) => (
            <path key={d} d={d} />
          ))}
          {joinPaths.map((d) => (
            <path key={d} d={d} />
          ))}
        </g>
        <g fill="none" stroke="var(--color-link)" strokeWidth="2" strokeLinecap="round">
          {packets.map(({ d, stage }) => (
            <path key={`p-${d}`} className="pulse" d={d} pathLength={1} style={{ animationDelay: `${stage * 0.8}s` }} />
          ))}
        </g>

        <g fontFamily="Geist, sans-serif" fontSize="13" textAnchor="middle">
          <rect x="12" y="165" width="112" height="50" rx="8" fill="#0f0f0f" stroke="rgb(237 237 239 / 0.2)" />
          <text x="68" y="194.5" fill="#ededef">Link or SMS</text>

          <rect x="164" y="160" width="112" height="60" rx="8" fill="#141414" stroke="#2563eb" strokeWidth="1.5" />
          <text x="220" y="195" fill="#ededef" fontWeight="500" fontSize="14">TrustLens</text>

          {LANES.map((label, i) => (
            <g key={label}>
              <rect x="324" y={LANE_Y[i] - 18} width="160" height="36" rx="6" fill="#0f0f0f" stroke="rgb(237 237 239 / 0.14)" />
              <text x="404" y={LANE_Y[i] + 4.5} fill="#a1a2a9">
                {label}
              </text>
            </g>
          ))}

          <rect x="532" y="165" width="96" height="50" rx="8" fill="#0f0f0f" stroke="rgb(237 237 239 / 0.2)" />
          <text x="580" y="194.5" fill="#ededef">Verdict</text>
        </g>
      </svg>
    </div>
  )
}
