# Architecture

## Overview

TrustLens investigates a suspicious **URL/domain** or **pasted message** and returns an evidence-based risk report,
which can be sealed on a blockchain for independent tamper-evidence.

```
                         ┌──────────────────────── backend (FastAPI, Python) ─────────────────────────┐
 Browser (React/Vite)    │                                                                              │
 ┌───────────────┐  /api │  routes.py ──► pipeline.py                                                  │
 │ Investigate   │ ────► │                 │  1. normalise input; refuse internal addresses (SSRF)    │
 │ Report        │ ◄──── │                 │  2. run checks in parallel, each with a timeout:          │
 │ History       │       │                 │       url · dns · threat_intel · tls · headers · message  │
 │ Verify        │       │                 │       (all web requests go through core/safe_fetch.py)    │
 └───────────────┘       │                 │  3. risk/engine.py  → deterministic verdict + coverage    │
                         │                 │  4. ai/explain.py   → Gemini explanation (grounded)       │
                         │                 │  5. correlation     → related reports                      │
                         │                 │  6. db.py           → report + indicator index (Postgres)  │
                         │                                                                              │
                         │  registry/chain.py ──web3.py──► ThreatRegistry.sol (local Hardhat / Sepolia) │
                         └──────────────────────────────────────────────────────────────────────────────┘
       external (read-only): Gemini API · crt.sh / Cert Spotter · OCSP/CRL · URLhaus / OpenPhish / Safe Browsing
```

**User flow (problem statement §5):** Submit → Investigate → Analyse → Assess risk → Report & verify on-chain.

## Backend pipeline

| Component | File | Responsibility |
|---|---|---|
| API | `app/api/routes.py` | Endpoints in AGENTS.md §5; maps errors to 404/409/422/501/502 |
| Pipeline | `app/pipeline.py` | Normalises input, blocks internal targets, runs analyzers concurrently (`asyncio.gather` + per-check timeouts: 8 s, TLS 14 s, message 28 s), builds the `AnalysisReport` |
| Analyzer contract | `app/analyzers/base.py` | `async analyze(target) -> CheckResult`; never raises; findings + raw data + limitations |
| Risk engine | `app/risk/engine.py` | Deterministic verdict from findings and coverage (AGENTS.md §6). The AI never sets the verdict |
| Explanation | `app/ai/explain.py` | Gemini rewrites findings in plain English; uncited/invented points dropped; "safe" claims rejected; rule-based fallback |
| AI wrapper | `app/ai/llm.py` | Single Gemini client: JSON-only, Pydantic validation, model fallback, prompt-injection guard, PII masking |
| SSRF guard | `app/core/safe_fetch.py` | Public-IP-only fetching, IP pinning, per-hop redirect validation, size/time limits |
| TLS analysis | `app/analyzers/tls_analyzer.py` | Certificate trust, identity, strength, revocation (OCSP/CRL), CT history, distrusted CAs |
| Correlation | `app/correlation/engine.py` | Indexes indicators per report; links reports by exact matches; labels each link `same_site` or `campaign` |
| Storage | `app/db.py` | `reports` (full JSON) + `indicators` (kind, value) index. Hosted Postgres (Neon) via `DATABASE_URL`; SQLite file `backend/data/app.db` locally |
| Registry | `app/registry/hashing.py`, `chain.py` | Canonical SHA-256 of a report; submit/verify against the contract with 3 checks |

**Report format:** `app/schemas.py` (mirrored in `frontend/src/types.ts`). Every finding carries severity, evidence,
source, impact and recommendation; every report carries coverage, limitations and a timestamp.

**Failure handling:** a failing or slow check becomes `status="error"` with a limitation instead of breaking the
report; low coverage yields **Inconclusive** rather than a false "Low Risk".

## Security checks

The security suite runs 4 passive, non-intrusive analyzers concurrently:
- **Lexical URL analysis (`app/analyzers/url_analyzer.py`):** Offline heuristic checks for typosquatting (Levenshtein distance vs `data/brands.json`), IDN homoglyphs (`xn--` punycode and mixed Unicode scripts), brand keywords in subdomains, userinfo `@` obfuscation, raw IP hosts, URL shorteners, open redirect parameters, and credential keywords.
- **DNS & Domain Age (`app/analyzers/dns_analyzer.py`):** Concurrent query of `A`, `AAAA`, `MX`, and `NS` records using `dnspython`. Fetches registration timestamps via standard RDAP (`rdap.org`) to flag newly registered domains (<30 days = high, <180 days = medium).
- **Threat Intelligence (`app/analyzers/threat_intel.py`):** Queries authoritative zero-day feeds: OpenPhish (cached 1 hr), URLhaus (abuse.ch API), Google Safe Browsing v4, and the Phishing Army community blocklist (~140k domains, cached 6 hrs). Verified URL matches return `authoritative=True` triggering immediate `confirmed_malicious` classification.
- **Passive Security Headers (`app/analyzers/headers_analyzer.py`):** Live evaluation of transport security and framing policies via `safe_fetch.py` (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and mixed-content detection).

## AI analysis & correlation

**Explanations:** see table above and `docs/security-methodology.md` → AI safety.

**Scam message analysis:** `backend/app/analyzers/message_analyzer.py`
- **Indicator extraction:** Extracts `urls`, `domains`, `emails`, `phones` (Indian mobiles & 1800 numbers), `upi_ids` (strictly differentiated from emails by handle structure), and `amounts` (`₹`, `Rs`, `INR`).
- **Scam-pattern rules:** 10 deterministic rules targeting OTP theft, remote access apps (AnyDesk, TeamViewer), employment upfront fees, brand impersonation, fake KYC/block threats, payment demands, lottery/cashback lures, URL shorteners, artificial urgency (strictly capped at Low), and suspicious personal contact numbers.
- **AI reasoning & Anti-hallucination:** Integrates Gemini through `llm.py` with `mask_pii()` and delimiter blocks. Every AI-detected tactic must contain a verbatim quote present in the input text; ungrounded tactics are automatically dropped. AI-only findings are capped at Medium severity and never set final risk levels alone.

**Correlation:** indicators extracted per report — registrable domain, server IPs, TLS certificate fingerprint,
emails, phone numbers, UPI ids — plus message text similarity (≥ 80%). IPs shared by ≥ 5 different domains are
ignored (CDN/shared hosting). Matches against the same website are shown as **"checked before"**; matches with a
different site or message are shown as **"possibly part of the same campaign"**.

## Blockchain registry & verification

**Contract:** `contracts/contracts/ThreatRegistry.sol` (Solidity 0.8.24, Hardhat 2, 6 tests). Stores per report
only `bytes32` hash, submitter, timestamp, risk label, status (active/disputed/revised) and revision history.

**Flow:**
1. *Register* — backend computes `sha256(canonical JSON of report without chain field)` and calls
   `submitReport(hash, riskLevel)` from the TrustLens registry wallet; the slot id and tx hash are stored with the report.
2. *Verify* — backend recomputes the hash from the stored report and reads the slot. Result is `verified` only if the
   hash matches **and** the slot was submitted by the official wallet **and** within 24 h of report creation;
   otherwise `mismatch`, `untrusted_submitter` or `registered_late`.

**Networks:** local Hardhat chain (`npm run chain`) for development; **Ethereum Sepolia** for the live site:

| | |
|---|---|
| Contract | [`0x089F4b08bcDBDEA5e3328D38676A63017266cb2e`](https://sepolia.etherscan.io/address/0x089F4b08bcDBDEA5e3328D38676A63017266cb2e) |
| Deploy transaction | [`0x36b9…1638`](https://sepolia.etherscan.io/tx/0x36b9736b270e67485ed59a2db27d1970b710774a2fab8d06c2e8757c31451638) |
| Official TrustLens wallet (submitter) | [`0xf4f0a75a18b6F88d04F8564BF472E1EBDAC61256`](https://sepolia.etherscan.io/address/0xf4f0a75a18b6F88d04F8564BF472E1EBDAC61256) |
| RPC | `https://ethereum-sepolia-rpc.publicnode.com` (public, no key) |

One seal costs about 695,000 gas. Details in `contracts/deployments/sepolia.json`.

## Data storage

| Where | What is stored |
|---|---|
| **Postgres (Neon)**, hosted deployments | Every report as full JSON (`reports`) and its indicators for correlation (`indicators`). Set with `DATABASE_URL`. Needed because Render's free plan wipes the server disk on every sleep, restart and redeploy |
| **SQLite** `backend/data/app.db`, local | The same two tables, used when `DATABASE_URL` is empty (development, tests, the tamper demo) |
| **Ethereum Sepolia** | Only each sealed report's SHA-256 fingerprint, its risk level, the time and the sealing wallet. Never the link, the message or any personal data |
| **Browser** | Nothing except a session flag so the intro animation plays once |

## Frontend

React 19 + Vite + TypeScript + Tailwind CSS v4, deployed on Vercel. Pages: landing (`/`), check (`/check`),
report (`/report/:id`), history (`/history`), verify (`/verify/:id`). Checker pages are code-split and load on
first visit. Motion uses `motion` (Framer Motion) and `lenis` (smooth scrolling); the hero background is a small
hand-written WebGL shader. The check page shows the backend pipeline live while a check runs; every number on the
report page is computed from the report itself. Everything degrades to a still page under reduced motion.
