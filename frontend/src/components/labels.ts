// Display labels & colours shared by the UI. Owner: P1.
import type { CheckName, RiskLevel, Severity } from '../types'

export const RISK_META: Record<RiskLevel, { label: string; className: string; description: string }> = {
  low_risk: {
    label: 'Low Risk',
    className: 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/40',
    description: 'No significant malicious indicators identified within the available checks.',
  },
  suspicious: {
    label: 'Suspicious',
    className: 'bg-amber-500/15 text-amber-300 ring-amber-500/40',
    description: 'One or more indicators require further investigation.',
  },
  high_risk: {
    label: 'High Risk',
    className: 'bg-orange-500/15 text-orange-300 ring-orange-500/40',
    description: 'Multiple significant indicators suggest a substantial security threat.',
  },
  confirmed_malicious: {
    label: 'Confirmed Malicious',
    className: 'bg-red-500/20 text-red-300 ring-red-500/50',
    description: 'Supported by authoritative threat intelligence or sufficiently validated evidence.',
  },
  inconclusive: {
    label: 'Inconclusive',
    className: 'bg-slate-500/20 text-slate-300 ring-slate-500/40',
    description: 'Insufficient data or unavailable verification sources.',
  },
}

export const SEVERITY_CLASS: Record<Severity, string> = {
  info: 'bg-sky-500/15 text-sky-300',
  low: 'bg-slate-500/20 text-slate-300',
  medium: 'bg-amber-500/15 text-amber-300',
  high: 'bg-orange-500/20 text-orange-300',
  critical: 'bg-red-500/25 text-red-300',
}

export const CHECK_LABEL: Record<CheckName, string> = {
  url: 'URL & Phishing Indicators',
  dns: 'DNS & Domain Age',
  threat_intel: 'Threat Intelligence',
  tls: 'TLS Certificate & Trust',
  headers: 'Security Headers',
  message: 'Message / Scam Analysis',
}

export const STATUS_CLASS = {
  ok: 'text-emerald-400',
  error: 'text-red-400',
  skipped: 'text-slate-500',
} as const
