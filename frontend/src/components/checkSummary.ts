// One or two plain sentences per check: what it looked at and what it found, built from the check's own data.
// Shown even when a check has no warnings, so "nothing found" still tells the user something. Owner: P1.
import type { CheckResult } from '../types'

type Data = Record<string, unknown>

const str = (v: unknown) => (typeof v === 'string' && v ? v : undefined)
const num = (v: unknown) => (typeof v === 'number' ? v : undefined)
const list = (v: unknown) => (Array.isArray(v) ? (v as unknown[]) : [])
const hostOf = (u: unknown) => {
  try {
    return new URL(String(u)).hostname
  } catch {
    return undefined
  }
}
const date = (v: unknown) => {
  const d = str(v) ? new Date(String(v)) : undefined
  return d && !Number.isNaN(d.getTime()) ? d.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' }) : undefined
}

export function humanAge(days: number): string {
  if (days < 1) return 'less than a day'
  if (days < 60) return `${days} day${days === 1 ? '' : 's'}`
  if (days < 730) return `${Math.round(days / 30)} months`
  return `${Math.floor(days / 365)} years`
}

function url(d: Data, clean: boolean): string {
  const host = str(d.host) ?? 'the address'
  const chain = list(d.redirect_chain)
  const last = hostOf(chain[chain.length - 1])
  const redirect =
    chain.length > 1 && last && last !== host ? `It redirects to ${last}.` : chain.length ? 'It does not redirect to another site.' : ''
  return clean
    ? `Looked at ${host} for copies of known brand names, look-alike or foreign letters, raw IP addresses, the @ trick and link shorteners. None found. ${redirect}`
    : `Looked at ${host} for the tricks used in phishing links. ${redirect}`
}

function dns(d: Data): string {
  const domain = str(d.registered_domain) ?? str(d.host) ?? 'The domain'
  const age = num(d.age_days)
  const registrar = str(d.registrar)
  const records = (d.dns_records ?? {}) as Data
  const servers = list(records.A).length + list(records.AAAA).length
  const parts: string[] = []
  if (age !== undefined) {
    const when = date(d.created)
    parts.push(
      `${domain} was registered ${humanAge(age)} ago${when ? ` (${when})` : ''}${registrar ? ` through ${registrar}` : ''}.` +
        (age >= 365 ? ' Scam sites are usually days or weeks old.' : ''),
    )
  } else {
    parts.push(`The registration date of ${domain} is not available.`)
  }
  parts.push(servers ? `It points to ${servers} server address${servers === 1 ? '' : 'es'}.` : 'It does not point to any server.')
  return parts.join(' ')
}

function threatIntel(d: Data, clean: boolean): string {
  const host = str(d.host) ?? 'The site'
  const sources = list(d.sources_checked).map(String)
  if (!sources.length) return 'No phishing list could be reached for this check.'
  const named = sources.map((s) => (s === 'Phishing Army' ? 'Phishing Army (140,000+ reported phishing domains)' : s))
  return clean
    ? `Looked up ${host} in ${named.join(' and ')}. It is not on them.`
    : `Looked up ${host} in ${named.join(' and ')}.`
}

function tls(d: Data): string {
  if (d.https_available === false) return 'The site does not accept secure (HTTPS) connections.'
  const issuer = str(d.issuer_org) ?? str(d.issuer_cn)
  const until = date(d.not_after)
  const left = num(d.days_left)
  const level = str(d.validation_level)
  if (d.verified) {
    return `Browsers trust this certificate. Issued by ${issuer ?? 'a trusted authority'}${level ? `, ${level}` : ''}, valid until ${until} (${left} days left). A valid certificate only means the connection is encrypted, not that the site is honest.`
  }
  const err = str(d.verify_error)
  return `Browsers would show a warning for this certificate${err ? `: ${err}` : ''}.${issuer ? ` It was issued by ${issuer}` : ''}${until ? `${issuer ? ',' : ' It is'} valid until ${until}` : ''}.`
}

function headers(d: Data, clean: boolean): string {
  const code = num(d.status_code)
  if (code === undefined) return 'The website could not be reached, so its security settings were not checked.'
  const final = hostOf(d.final_url)
  return `The website answered (status ${code}${final ? ` from ${final}` : ''}). Checked its HTTPS setup and five standard security settings${clean ? ': all in place.' : '.'}`
}

function message(d: Data): string {
  const ind = (d.indicators ?? {}) as Data
  const links = list(ind.urls).length
  return links
    ? `Found ${links} link${links === 1 ? '' : 's'} in the message. Each one gets the full set of checks below.`
    : 'Found no links in the message.'
}

export function checkSummary(check: CheckResult): string | null {
  if (check.status !== 'ok') return null
  const clean = !check.findings.some((f) => f.severity !== 'info')
  const d = check.data as Data
  switch (check.check) {
    case 'url':
      return url(d, clean)
    case 'dns':
      return dns(d)
    case 'threat_intel':
      return threatIntel(d, clean)
    case 'tls':
      return tls(d)
    case 'headers':
      return headers(d, clean)
    case 'message':
      return message(d)
  }
}
