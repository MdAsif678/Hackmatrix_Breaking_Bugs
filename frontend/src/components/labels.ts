// Display labels shared by the UI. Colours live in index.css (.risk / .sev). Owner: P1.
import type { CheckName, RiskLevel, Severity } from '../types'

export const RISK_META: Record<RiskLevel, { label: string; description: string }> = {
  low_risk: {
    label: 'Low Risk',
    description: 'No significant warning signs in the checks that ran.',
  },
  suspicious: {
    label: 'Suspicious',
    description: 'One or more warning signs need a closer look.',
  },
  high_risk: {
    label: 'High Risk',
    description: 'Several serious warning signs point to a scam or an attack.',
  },
  confirmed_malicious: {
    label: 'Confirmed Malicious',
    description: 'Listed on trusted phishing or malware databases.',
  },
  inconclusive: {
    label: 'Inconclusive',
    description: 'Too few checks could run to judge this one.',
  },
}

export const CHECK_LABEL: Record<CheckName, string> = {
  url: 'Lookalike names and link tricks',
  dns: 'Domain age and DNS',
  threat_intel: 'Known phishing lists',
  tls: 'Certificate and trust',
  headers: 'Website and page content',
  message: 'Message analysis',
}

export const STATUS_LABEL = {
  ok: 'Checked',
  error: 'Could not run',
  skipped: 'Not available yet',
} as const

// Plain-English names for finding severities, most serious first.
export const SEVERITY_META: Record<Severity, { label: string; meaning: string }> = {
  critical: { label: 'Danger', meaning: 'A known scam, or trust that is broken. Do not use the site.' },
  high: { label: 'Serious', meaning: 'A strong sign of a scam or an attack.' },
  medium: { label: 'Warning', meaning: 'Unusual. Worth a closer look before you trust it.' },
  low: { label: 'Minor', meaning: 'A small weakness in how the site is set up. Not a scam sign on its own.' },
  info: { label: 'Note', meaning: 'Information only, not a problem.' },
}

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
