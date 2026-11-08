# Security Methodology (Owners: P1 + P2 + P3)

## Safe URL inspection (SSRF protection)

## Phishing indicators & how each is detected

Our lexical URL analyzer (`backend/app/analyzers/url_analyzer.py`) checks suspicious URLs offline using deterministic security heuristics:

| Finding ID | Check & Detection Mechanism | Severity |
|---|---|---|
| `url.ip_host` | Detects IPv4 or IPv6 literals in the host using `ipaddress` parsing. | High |
| `url.at_symbol` | Detects `@` character in URL authority (`userinfo@host`), which obscures the actual destination domain. | High |
| `url.typosquat` | Calculates Levenshtein edit distance between registered domain labels and official brand domains in `brands.json` (distance 1–2, min length 5). | High |
| `url.brand_in_subdomain` | Detects protected brand keywords in host labels or subdomains when registered domain does not match official brand domains. | High |
| `url.punycode` | Detects `xn--` prefix in domain labels indicating Internationalized Domain Names (IDN). | Medium |
| `url.mixed_script` | Decodes IDN with `idna` and inspects Unicode script categories (e.g. Cyrillic characters mixed into Latin words like `аpple`). | High |
| `url.shortener` | Matches hostname against known URL shortener services (`bit.ly`, `tinyurl.com`, `t.co`, etc.) that mask real endpoints. | Medium |
| `url.redirect_param` | Identifies query parameters (`url=`, `redirect=`, `next=`, `dest=`) containing absolute external `http`/`https` URLs. | Medium |
| `url.cross_domain_redirect` | Detects HTTP redirect hops that terminate on a different registered domain than the entry domain. | Medium |
| `url.suspicious_tld` | Flags TLDs statistically correlated with disposable phishing infrastructure (`zip`, `top`, `xyz`, `click`, `tk`, etc.). | Low |
| `url.many_subdomains` | Flags hostnames with more than 3 subdomain levels used to mimic URLs or evade path matching. | Low |
| `url.long_url` | Flags URLs exceeding 100 characters often used for visual overflow masking on mobile viewports. | Low |
| `url.no_https` | Flags unencrypted plain `http://` transport. | Low |
| `url.credential_words` | Identifies sensitive authentication tokens in URL path (`login`, `verify`, `kyc`, `password`, `banking`). | Low |

### Passive Security Headers (`backend/app/analyzers/headers_analyzer.py`)

| Finding ID | Detection Mechanism | Severity |
|---|---|---|
| `headers.no_https_redirect` | HTTP endpoint does not redirect to HTTPS. | Medium |
| `headers.missing_hsts` | HTTPS endpoint lacks `Strict-Transport-Security` header. | Low |
| `headers.missing_csp` | Missing `Content-Security-Policy` header. | Low |
| `headers.missing_frame_protection` | Lacks `X-Frame-Options` and CSP `frame-ancestors`. | Low |
| `headers.missing_nosniff` | Lacks `X-Content-Type-Options: nosniff`. | Info |
| `headers.mixed_content` | HTTPS page loads resources using unencrypted `http://` in `src`. | Low |
| `headers.server_version` | `Server` or `X-Powered-By` header discloses granular version numbers. | Info |

### DNS & Domain Age Intelligence (`backend/app/analyzers/dns_analyzer.py`)

- **Resolution**: Queries `A`, `AAAA`, `MX`, and `NS` records using `dnspython`. Generates `dns.no_resolution` (Medium) if host has no A/AAAA records.
- **Domain Age via RDAP**: Queries standard RDAP registry (`https://rdap.org/domain/<registered_domain>`) to extract `registration` event timestamps.
  - Less than 30 days old: `dns.new_domain` (High).
  - Less than 180 days old: `dns.young_domain` (Medium).

## TLS / certificate trust checks

## Threat-intelligence sources

Our threat intelligence analyzer (`backend/app/analyzers/threat_intel.py`) queries authoritative reputation databases:

1. **URLhaus (abuse.ch)**: Real-time queries for known malware distribution URLs and hosts via URLhaus API. Exact URL matches yield `threat_intel.urlhaus` (Critical, Authoritative); host-only matches yield `threat_intel.urlhaus_host` (High).
2. **OpenPhish**: Ingests the OpenPhish global active phishing feed, cached locally for 1 hour. Exact URL matches produce `threat_intel.openphish` (Critical, Authoritative); host matches produce `threat_intel.openphish_host` (High).
3. **Google Safe Browsing (v4)**: Queries Google ThreatMatches API for malware, social engineering, and unwanted software (Critical, Authoritative).

## AI safety (prompt injection, evidence grounding, privacy)

## Risk classification rules
See AGENTS.md §6.

## Limitations
