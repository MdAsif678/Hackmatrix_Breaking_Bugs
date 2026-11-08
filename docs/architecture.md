# Architecture (Owner: P1 — everyone adds their section)

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
                         │                 │  6. db.py (SQLite)  → report + indicator index             │
                         │                                                                              │
                         │  registry/chain.py ──web3.py──► ThreatRegistry.sol (local Hardhat / Sepolia) │
                         └──────────────────────────────────────────────────────────────────────────────┘
       external (read-only): Gemini API · crt.sh / Cert Spotter · OCSP/CRL · URLhaus/OpenPhish (P2)
```

**User flow (problem statement §5):** Submit → Investigate → Analyse → Assess risk → Report & verify on-chain.

## Backend pipeline (P1)

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
| Storage | `app/db.py` | SQLite: `reports` (full JSON) + `indicators` (kind, value) index |
| Registry | `app/registry/hashing.py`, `chain.py` | Canonical SHA-256 of a report; submit/verify against the contract with 3 checks |

**Report format:** `app/schemas.py` (mirrored in `frontend/src/types.ts`). Every finding carries severity, evidence,
source, impact and recommendation; every report carries coverage, limitations and a timestamp.

**Failure handling:** a failing or slow check becomes `status="error"` with a limitation instead of breaking the
report; low coverage yields **Inconclusive** rather than a false "Low Risk".

## Security checks (P2)

<!-- P2: url / dns / threat_intel / headers analyzers — inputs, sources, findings -->

## AI analysis & correlation

**Explanations (P1):** see table above and `docs/security-methodology.md` → AI safety.

**Scam message analysis (P3):** <!-- P3: indicator extraction, rules, Gemini classification, quote verification -->

**Correlation (P1):** indicators extracted per report — registrable domain, server IPs, TLS certificate fingerprint,
emails, phone numbers, UPI ids — plus message text similarity (≥ 80%). IPs shared by ≥ 5 different domains are
ignored (CDN/shared hosting). Matches against the same website are shown as **"checked before"**; matches with a
different site or message are shown as **"possibly part of the same campaign"**.

## Blockchain registry & verification

**Contract (P1):** `contracts/contracts/ThreatRegistry.sol` (Solidity 0.8.24, Hardhat 2, 6 tests). Stores per report
only `bytes32` hash, submitter, timestamp, risk label, status (active/disputed/revised) and revision history.

**Flow:**
1. *Register* — backend computes `sha256(canonical JSON of report without chain field)` and calls
   `submitReport(hash, riskLevel)` from the TrustLens registry wallet; the slot id and tx hash are stored with the report.
2. *Verify* — backend recomputes the hash from the stored report and reads the slot. Result is `verified` only if the
   hash matches **and** the slot was submitted by the official wallet **and** within 24 h of report creation;
   otherwise `mismatch`, `untrusted_submitter` or `registered_late`.

**Networks:** local Hardhat chain (`npm run chain`) for development; Sepolia testnet for the demo
(**P4:** deployment address + transaction links go here).
