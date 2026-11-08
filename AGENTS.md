# AGENTS.md — Shared Project Context (READ THIS FIRST)

> **To every AI assistant working in this repo:** this file is the single source of truth.
> Follow the folder ownership, data formats and security rules below exactly.
> Only edit files owned by the person you are helping (see "Ownership").
> If something here seems wrong or missing, tell your human — do not silently change shared files.

---

## 1. What we are building (1 minute version)

A web platform where anyone can submit a **suspicious URL/domain** or **paste a suspicious message/email**
and get an **evidence-based risk report**. Reports can be **registered on a blockchain** (hash only)
so anyone can independently verify the report was never tampered with.

Pipeline: **Submit → Investigate → Analyse → Risk verdict → Report on-chain → Verify**

Hackathon: HackMatrix "AI-Powered Web Threat Detection & Digital Trust Intelligence" — 48 hours.

Judging weights: Cybersecurity 30% · AI 20% · Web3 20% · Technical 20% · UX 10%.
**A working end-to-end flow beats many half-built features.**

---

## 2. Tech stack (fixed — do not introduce alternatives)

| Layer | Choice |
|---|---|
| Backend | Python 3.11+, **FastAPI**, Pydantic v2, `httpx` (async) |
| Security libs | `ssl`, `cryptography`, `dnspython`, `tldextract`, `idna`, `python-whois` (or RDAP over HTTP) |
| Database | **SQLite** (single file `backend/data/app.db`), via `sqlite3` or SQLModel |
| AI | One LLM provider behind a single wrapper `backend/app/ai/llm.py` (provider + key from `.env`) |
| Frontend | **React + Vite + TypeScript + Tailwind CSS** |
| Blockchain | **Solidity** + **Hardhat**, deployed to **Ethereum Sepolia testnet**; backend talks to it with `web3.py` |

---

## 3. Folder structure & ownership

| Person | Role |
|---|---|
| **P1** | Foundation, pipeline, risk engine, dashboard UI, integration, deployment |
| **P2** | Cybersecurity: URL/phishing checks, threat intel, TLS, headers, SSRF-safe fetching |
| **P3** | AI: scam message analysis, evidence-grounded explanations, correlation |
| **P4** | Web3: smart contract, hashing, on-chain registry & verification, registry UI, testing report |

```
/
├── AGENTS.md                      (shared — change only with team agreement)
├── CLAUDE.md                      (points to AGENTS.md)
├── README.md                      (P1 — setup & run instructions)
├── .env.example                   (P1 — add your keys' NAMES here, never real values)
├── backend/
│   ├── requirements.txt           (shared — append only, keep sorted)
│   ├── data/                      (SQLite db, datasets e.g. brand list, distrusted CAs)
│   ├── app/
│   │   ├── main.py                (P1) FastAPI app, CORS, router include
│   │   ├── config.py              (P1) reads .env
│   │   ├── schemas.py             (SHARED CONTRACT — see §4. Change only with team agreement)
│   │   ├── db.py                  (P1) save/load reports
│   │   ├── pipeline.py            (P1) runs analyzers in parallel, builds AnalysisReport
│   │   ├── api/routes.py          (P1) HTTP endpoints (see §5)
│   │   ├── risk/engine.py         (P1) deterministic risk classification (see §6)
│   │   ├── core/safe_fetch.py     (P2) THE ONLY way to make HTTP requests to user-supplied URLs
│   │   ├── analyzers/
│   │   │   ├── url_analyzer.py    (P2) URL normalisation, lexical/phishing indicators, redirects
│   │   │   ├── dns_analyzer.py    (P2) DNS records, domain age (WHOIS/RDAP)
│   │   │   ├── threat_intel.py    (P2) URLhaus / OpenPhish / Google Safe Browsing / PhishTank
│   │   │   ├── tls_analyzer.py    (P2) certificate & chain checks, crt.sh CT lookup
│   │   │   ├── headers_analyzer.py(P2) passive security header / mixed-content checks
│   │   │   └── message_analyzer.py(P3) scam message analysis + indicator extraction
│   │   ├── ai/
│   │   │   ├── llm.py             (P3) single LLM wrapper: llm_json(system, user, schema) -> dict
│   │   │   └── explain.py         (P3) explanation generated ONLY from findings
│   │   ├── correlation/engine.py  (P3) link related reports (shared domains/IPs/indicators)
│   │   └── registry/
│   │       ├── hashing.py         (P4) canonical JSON + SHA-256 (see §7)
│   │       └── chain.py           (P4) web3.py submit / read / verify
│   └── tests/                     (P1 owns conftest.py; each person adds test_<module>.py)
├── frontend/
│   └── src/
│       ├── api/client.ts          (P1) typed API calls — mirrors §4 types
│       ├── types.ts               (P1) TS copies of the §4 schemas
│       ├── pages/                 (P1) HomePage (submit), ReportPage, HistoryPage
│       ├── components/            (P1) shared UI: RiskBadge, FindingCard, CheckSection, labels
│       └── features/registry/     (P4) RegistryPanel ("Register on-chain"), VerifyPage
├── contracts/                     (P4) Hardhat project: ThreatRegistry.sol, tests, deploy script
└── docs/
    ├── architecture.md            (P1, everyone adds their section)
    ├── testing-report.md          (P4, everyone contributes cases)
    └── security-methodology.md    (P2 + P3)
```

**Rule:** your AI edits only your files. Need a change in someone else's file? Ask that person.

---

## 4. Shared data contract (`backend/app/schemas.py`)

Every analyzer returns a `CheckResult`. The pipeline combines them into an `AnalysisReport`.
Frontend `types.ts` mirrors these exactly.

```python
from datetime import datetime
from enum import Enum
from typing import Any, Literal, Optional
from pydantic import BaseModel, Field

class Severity(str, Enum):
    info = "info"; low = "low"; medium = "medium"; high = "high"; critical = "critical"

class RiskLevel(str, Enum):
    low_risk = "low_risk"
    suspicious = "suspicious"
    high_risk = "high_risk"
    confirmed_malicious = "confirmed_malicious"
    inconclusive = "inconclusive"

CheckName = Literal["url", "dns", "threat_intel", "tls", "headers", "message"]

class Finding(BaseModel):
    id: str                       # unique within a report, e.g. "tls.expired", "url.homoglyph"
    check: CheckName
    title: str                    # short human title: "Certificate expired"
    severity: Severity
    evidence: str                 # concrete technical evidence: "notAfter=2024-01-03T00:00:00Z"
    source: str                   # where it came from: "TLS handshake", "URLhaus", "crt.sh", "regex"
    impact: Optional[str] = None
    recommendation: Optional[str] = None
    authoritative: bool = False   # True ONLY for a match in a trusted threat-intel feed

class CheckResult(BaseModel):
    check: CheckName
    status: Literal["ok", "error", "skipped"]
    target: Optional[str] = None  # what was checked (filled in by the pipeline)
    findings: list[Finding] = []
    data: dict[str, Any] = {}     # raw facts for display (cert subject, issuer, IPs, redirect chain...)
    limitations: list[str] = []   # what could not be checked and why
    duration_ms: int = 0

class Explanation(BaseModel):
    summary: str
    key_points: list[str]         # each should reference finding ids, e.g. "[tls.expired] ..."
    recommendations: list[str]

class ChainRecord(BaseModel):
    report_hash: str              # 0x-prefixed SHA-256 hex (see §7)
    chain_report_id: int
    tx_hash: str
    network: str = "sepolia"
    contract_address: str

class AnalysisReport(BaseModel):
    id: str                                   # uuid4
    input_type: Literal["url", "domain", "message"]
    input: str                                # stored in OUR db only — never on-chain
    normalized_target: Optional[str] = None
    created_at: datetime
    risk_level: RiskLevel
    risk_reasons: list[str]                   # why the engine picked this level
    coverage: float = Field(ge=0, le=1)       # fraction of checks that ran successfully
    checks: list[CheckResult]
    extracted_indicators: dict[str, list[str]] = {}  # urls, domains, emails, phones, upi_ids
    explanation: Optional[Explanation] = None
    recommendations: list[str] = []
    limitations: list[str] = []
    related_report_ids: list[str] = []        # from correlation engine
    chain: Optional[ChainRecord] = None       # filled after on-chain registration
```

### Analyzer interface (every analyzer must follow this)

```python
async def analyze(target: str) -> CheckResult: ...
```
- URL analyzers (`url`, `dns`, `threat_intel`, `tls`, `headers`) receive a **normalized absolute URL**,
  e.g. `"https://example.com/login"` — extract the host yourself with `urllib.parse.urlsplit`.
- `message_analyzer` receives the raw pasted text and must put extracted indicators in
  `data["indicators"] = {"urls": [...], "domains": [...], "emails": [...], "phones": [...], "upi_ids": [...]}`.
  The pipeline copies them to `report.extracted_indicators` and runs URL checks on the first 3 `urls`.
- **Never raise.** Catch all exceptions and return `status="error"` with a `limitations` entry.
  Helpers: `skipped()`, `error_result()`, `run_cli()` in `app/analyzers/base.py`.
- Respect a timeout (default 8s per check, set in `config.py`; the pipeline also enforces it).
- Put raw facts in `data`, judgements in `findings`. Finding ids look like `"<check>.<thing>"`.
- Don't set `target` / `duration_ms` — the pipeline fills them in.

---

## 5. API endpoints (`backend/app/api/routes.py`, prefix `/api`)

| Method | Path | Body | Returns |
|---|---|---|---|
| GET | `/api/health` | – | `{"status":"ok"}` |
| POST | `/api/analyze/url` | `{"url": str}` | `AnalysisReport` |
| POST | `/api/analyze/message` | `{"text": str}` | `AnalysisReport` (also analyses extracted URLs, max 3) |
| GET | `/api/reports` | – | `list[AnalysisReport]` (latest first, summary is fine) |
| GET | `/api/reports/{id}` | – | `AnalysisReport` |
| POST | `/api/registry/submit/{id}` | – | `ChainRecord` |
| GET | `/api/registry/verify/{id}` | – | `{"recomputed_hash", "onchain_hash", "match": bool, "tx_hash", "block_timestamp", "status"}` |
| GET | `/api/correlations/{id}` | – | `{"related": [{"report_id", "shared_indicators": [...]}]}` |

Backend runs on `http://localhost:8000`, frontend on `http://localhost:5173`.

---

## 6. Risk classification rules (`risk/engine.py`) — deterministic, NOT decided by the AI

Applied in this order:
1. **confirmed_malicious** — any finding with `authoritative=True` (trusted threat-intel match).
2. **inconclusive** — `coverage < 0.5` and no `high`/`critical` findings.
3. **high_risk** — ≥1 `critical` finding, or ≥2 `high` findings.
4. **suspicious** — ≥1 `high` or ≥2 `medium` findings.
5. **low_risk** — otherwise.

Always add a limitation: *"No known threats found does not prove the site is safe."*
A valid TLS certificate is **never** evidence that a site is safe.
The LLM may *explain* the result but must never set or override `risk_level`.

---

## 7. Hashing & blockchain (P4 owns, everyone must respect)

- **Canonical JSON:** `json.dumps(report.model_dump(mode="json", exclude={"chain"}), sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
- **Hash:** SHA-256 of that UTF-8 string → `"0x" + hexdigest` → stored on-chain as `bytes32`.
  Already implemented in `backend/app/registry/hashing.py` — use it, don't reimplement.
- A report must not be modified after creation (except filling `chain`), or verification will fail.
- **Only the hash + risk level + timestamp go on-chain.** Never raw URLs, messages, emails, phone numbers or personal data.
- A blockchain record proves a report's **integrity and history**, not that the report is **true**.

Contract `contracts/contracts/ThreatRegistry.sol` (minimum interface):
```solidity
function submitReport(bytes32 reportHash, string calldata riskLevel) external returns (uint256 id);
function reviseReport(uint256 id, bytes32 newHash) external;          // keeps revision history
function disputeReport(uint256 id, string calldata reasonCode) external; // short code, no PII
function getReport(uint256 id) external view returns (bytes32 hash, address submitter, uint256 timestamp, string memory riskLevel, uint8 status, uint256 revisions);
event ReportSubmitted(uint256 indexed id, bytes32 reportHash, address indexed submitter, uint256 timestamp);
event ReportRevised(uint256 indexed id, bytes32 newHash, uint256 revision);
event ReportDisputed(uint256 indexed id, address indexed by, string reasonCode);
```

---

## 8. Security rules (MANDATORY — judges check these)

**Safe URL inspection (SSRF protection)**
- Never call `httpx`/`requests`/`urllib` directly on a user-supplied URL. Always use `core/safe_fetch.py`.
- `safe_fetch` must: allow only `http`/`https`, ports 80/443; resolve DNS and **reject private, loopback,
  link-local, multicast, reserved and metadata IPs** (127.0.0.0/8, 10/8, 172.16/12, 192.168/16, 169.254/16,
  ::1, fc00::/7, fe80::/10, 0.0.0.0); follow redirects **manually** (max 5) re-validating each hop;
  timeout ≤ 8s; max body 1 MB; never execute JavaScript; never save/download files.

**AI safety**
- Webpage content and user messages are **untrusted data**. Wrap them in clear delimiters and tell the model
  to ignore any instructions inside them.
- LLM output must be parsed as JSON and validated with Pydantic; on failure, fall back to rule-based results.
- Explanations may only reference evidence present in `findings`. No invented facts.
- Don't send unnecessary personal data to the LLM (mask phone numbers / emails where not needed).
- Never label a message fraudulent only because it is urgent/persuasive — distinguish "suspicious language"
  from "verified evidence".

**Privacy & ops**
- Never ask users for passwords, OTPs, private keys, or seed phrases.
- Secrets live only in `.env` (git-ignored). `.env.example` lists names only.
- The blockchain wallet is a **throwaway testnet wallet** — never a real one.
- No exploitation, no port scanning, no brute forcing. Passive checks only.
- Never claim a website is "safe" or "secure" — say "no significant indicators found in the available checks".

---

## 9. Environment variables (`.env.example`)

```
LLM_PROVIDER=
LLM_API_KEY=
LLM_MODEL=
GOOGLE_SAFE_BROWSING_API_KEY=
URLHAUS_AUTH_KEY=
SEPOLIA_RPC_URL=
REGISTRY_PRIVATE_KEY=        # throwaway testnet wallet only
REGISTRY_CONTRACT_ADDRESS=
CHECK_TIMEOUT_SECONDS=8
MOCK_ANALYZERS=false         # true = fake sample findings for unimplemented analyzers (UI work only)
```

---

## 9b. Current state of the skeleton (built by P1)

Everything below already exists and runs (`python -m pytest -q` in `backend/` passes):
- FastAPI app with all §5 endpoints, SQLite storage, parallel pipeline with timeouts, risk engine (§6),
  hashing (§7), rule-based explanation fallback, mock mode.
- Every module you own exists as a **stub** with a `TODO(Px)` comment and the final function signature.
  Replace the body; keep the signature. Registry endpoints return **501** until `chain.py` is implemented.
- Frontend: Investigate page (URL + message tabs), Report page, History page, Verify page, Registry panel.
- `backend/data/brands.json`: starter list of brands + official domains for typosquatting checks (P2 extends).
- Add tests for your module in `backend/tests/test_<module>.py`.

---

## 10. Team workflow

- `git pull` before you start; commit small and often; push at least every 2–3 hours.
- One branch per person (`p1-foundation`, `p2-security`, `p3-ai`, `p4-web3`), merge into `main` frequently.
- Until a real module is ready, the pipeline uses its **stub** (returns `status="skipped"`). Replace the stub, don't
  change the function signature.
- Each module must work standalone first: `python -m app.analyzers.tls_analyzer example.com` should print a `CheckResult`.

---

## 11. Work plan

### Phase 0 — Kickoff (Hour 0–1, everyone)
Read this file together. Agree or adjust once. After this, `schemas.py` and §5 are frozen unless all agree.

### Phase 1 — Foundation (Hour 0–3)
**P1 builds the skeleton** (see checklist below). Meanwhile, P2/P3/P4 build their modules as standalone scripts.

P1 foundation checklist:
1. Repo + folder structure + `.gitignore` (`.env`, `node_modules`, `__pycache__`, `*.db`, `contracts/artifacts`) + `.env.example`
2. `backend`: `main.py`, `config.py`, `schemas.py` (exact copy of §4), `db.py` (SQLite save/load reports)
3. Stub analyzers for every file in `analyzers/` returning `CheckResult(status="skipped")`
4. `pipeline.py`: run analyzers in parallel with `asyncio.gather` + timeout, compute coverage, call risk engine, save report
5. `risk/engine.py` implementing §6
6. `routes.py` with all §5 endpoints (registry/correlation endpoints can return 501 until P3/P4 plug in)
7. `frontend`: Vite + React + TS + Tailwind; Home page (URL tab + Message tab), Report page rendering a report
8. `README.md` with run steps; confirm `uvicorn app.main:app --reload` and `npm run dev` both work; push to `main`

### Phase 2 — Build modules into the skeleton (Hour 3–16)

**P2 — Cybersecurity (30% of marks)**
1. `safe_fetch.py` (SSRF rules in §8) — top priority, others depend on it
2. `url_analyzer.py`: normalisation (punycode/IDN), IP-as-host, `@` in URL, many subdomains, suspicious TLDs,
   URL shorteners, redirect params, very long URLs, **typosquatting** (Levenshtein vs `data/brands.json`),
   **homoglyphs/mixed scripts**, brand name in subdomain/path; redirect chain via `safe_fetch`
3. `threat_intel.py`: URLhaus API + OpenPhish feed (cached) + Google Safe Browsing (if key) → `authoritative=True` on match
4. `tls_analyzer.py`: validity dates, hostname/SAN match, issuer & chain, self-signed, key type/size, signature
   algorithm, protocol version, crt.sh CT history (recent/unexpected issuance), match against `data/distrusted_cas.json`
5. `dns_analyzer.py`: A/AAAA/MX/NS, domain age (WHOIS/RDAP — new domain < 30 days = finding)
6. `headers_analyzer.py`: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, HTTP→HTTPS, mixed content

**P3 — AI**
1. `llm.py`: `llm_json(system, user, schema)` with timeout + JSON validation + graceful failure
2. `message_analyzer.py`: regex extraction (URLs, domains, emails, phones, UPI IDs, amounts) + rule-based patterns
   (urgency, OTP/password/KYC requests, payment requests, prize/refund/job offers, impersonated brands) + LLM
   classification → findings with evidence quotes. Rules + LLM must agree for `high` severity.
3. `explain.py`: given all findings → `Explanation` citing finding ids; prompt-injection safe (§8)
4. `correlation/engine.py`: link reports sharing domains / IPs / registrable domains / payment IDs / cert fingerprints /
   similar message text (deterministic matching; AI only summarises the link)

**P4 — Web3 + Testing**
1. Hardhat project, `ThreatRegistry.sol` (§7), unit tests, deploy script → Sepolia; save address in `.env` & README
2. `hashing.py` + `chain.py` (submit / getReport / verify) using `web3.py`
3. Wire `/api/registry/submit` and `/api/registry/verify`
4. `frontend/src/features/registry/`: "Register on-chain" button on report page, Verify page showing
   recomputed hash vs on-chain hash, tx link to Sepolia Etherscan, tamper demo (edit report → mismatch)
5. Own `docs/testing-report.md`: collect ≥3 malicious + ≥3 benign cases with observed results

**Target: first full end-to-end flow (submit → report → on-chain → verify) working by Hour 16.**

### Phase 3 — Deepen & polish (Hour 16–36)
Improve detection quality, reduce false positives, correlation UI, history page, better explanations, docs.

### Phase 4 — Freeze & demo (Hour 36–48)
- Hour 36: **feature freeze** — bug fixes only
- Finalise `docs/architecture.md`, `docs/security-methodology.md`, `docs/testing-report.md`, README
- Rehearse the live demo script; record a backup video; make the GitHub repo public; submit

---

## 12. Test cases (use these; never open malicious URLs in a normal browser)

**TLS tests:** `expired.badssl.com`, `wrong.host.badssl.com`, `self-signed.badssl.com`,
`untrusted-root.badssl.com`, `revoked.badssl.com`, `sha1-intermediate.badssl.com`
**Benign:** `google.com`, `github.com`, `onlinesbi.sbi`, a university site
**Malicious:** fresh entries from the URLhaus / OpenPhish feeds at demo time (they go offline fast)
**Lookalike (lexical only):** `paypa1-secure-login.com`, `xn--pple-43d.com` (аpple with Cyrillic а)
**Messages:** fake KYC SMS, fake job offer asking for fee, fake bank OTP request; plus benign OTP/delivery messages
