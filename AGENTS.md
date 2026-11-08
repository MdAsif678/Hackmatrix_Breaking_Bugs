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
| Blockchain | **Solidity 0.8.24** + **Hardhat 2** (`contracts/`): local chain for development, **Ethereum Sepolia testnet** for the demo; backend talks to it with `web3.py` |

---

## 3. Folder structure & ownership

P1 (team lead) owns the hard, tightly-connected parts. P2–P4 own self-contained modules with clear
inputs/outputs and a step-by-step guide in `docs/tasks/`.

| Person | Role | Step-by-step guide |
|---|---|---|
| **P1 — Lead** | Pipeline & risk engine, SSRF-safe fetching, TLS certificate analysis, LLM wrapper & AI explanations, correlation, blockchain backend (`web3.py`), dashboard, integration, demo | [docs/tasks/P1-lead.md](docs/tasks/P1-lead.md) |
| **P2 — Security checks** | URL/phishing indicators, DNS & domain age, threat-intel feeds, security headers | [docs/tasks/P2-security.md](docs/tasks/P2-security.md) |
| **P3 — Scam messages (AI)** | Indicator extraction, scam-pattern rules, sample message dataset, scam-classification prompt | [docs/tasks/P3-ai.md](docs/tasks/P3-ai.md) |
| **P4 — Web3 & testing** | Sepolia deployment (contract already written by P1), registry/verify UI, testing report, demo script | [docs/tasks/P4-web3.md](docs/tasks/P4-web3.md) |

```
/
├── AGENTS.md                      (shared — change only with team agreement)
├── CLAUDE.md                      (points to AGENTS.md)
├── README.md                      (P1 — setup & run instructions)
├── .env.example                   (P1 — add your keys' NAMES here, never real values)
├── backend/
│   ├── requirements.txt           (shared — append only, keep sorted)
│   ├── data/                      brands.json (P2), sample_messages.json (P3), distrusted_cas.json (P1), app.db
│   ├── app/
│   │   ├── main.py                (P1) FastAPI app, CORS, router include
│   │   ├── config.py              (P1) reads .env
│   │   ├── schemas.py             (SHARED CONTRACT — see §4. Change only with team agreement)
│   │   ├── db.py                  (P1) save/load reports
│   │   ├── pipeline.py            (P1) runs analyzers in parallel, builds AnalysisReport
│   │   ├── api/routes.py          (P1) HTTP endpoints (see §5)
│   │   ├── risk/engine.py         (P1) deterministic risk classification (see §6)
│   │   ├── core/safe_fetch.py     (P1) THE ONLY way to make HTTP requests to user-supplied URLs
│   │   ├── analyzers/
│   │   │   ├── url_analyzer.py    (P2) lexical/phishing indicators (typosquatting, homoglyphs...), redirects
│   │   │   ├── dns_analyzer.py    (P2) DNS records, domain age (WHOIS/RDAP)
│   │   │   ├── threat_intel.py    (P2) URLhaus / OpenPhish / Google Safe Browsing / PhishTank
│   │   │   ├── tls_analyzer.py    (P1) certificate & chain checks, crt.sh CT lookup
│   │   │   ├── headers_analyzer.py(P2) passive security header / mixed-content checks
│   │   │   └── message_analyzer.py(P3) indicator extraction, scam-pattern rules, LLM classification
│   │   ├── ai/
│   │   │   ├── llm.py             (P1) single LLM wrapper: llm_json(system, user, schema) -> model | None
│   │   │   └── explain.py         (P1) explanation generated ONLY from findings
│   │   ├── correlation/engine.py  (P1) link related reports (shared domains/IPs/indicators)
│   │   └── registry/
│   │       ├── hashing.py         (P1) canonical JSON + SHA-256 (see §7)
│   │       └── chain.py           (P1) web3.py submit / read / verify (uses P4's ABI + address)
│   └── tests/                     (P1 owns conftest.py; each person adds test_<module>.py)
├── frontend/
│   └── src/
│       ├── api/client.ts          (P1) typed API calls — mirrors §4 types
│       ├── types.ts               (P1) TS copies of the §4 schemas
│       ├── pages/                 (P1) HomePage (submit), ReportPage, HistoryPage
│       ├── components/            (P1) shared UI: RiskBadge, FindingCard, CheckSection, labels
│       └── features/registry/     (P4) RegistryPanel ("Register on-chain"), VerifyPage
├── contracts/                     Hardhat project: contracts/ThreatRegistry.sol + test/ + scripts/deploy.js (P1);
│                                  ThreatRegistry.abi.json + deployments/<network>.json are written by the deploy script (P4 runs it for Sepolia)
└── docs/
    ├── architecture.md            (P1, everyone adds their section)
    ├── testing-report.md          (P4, everyone contributes cases)
    ├── demo-script.md             (P4)
    ├── security-methodology.md    (P1 + P2 + P3)
    └── tasks/                     step-by-step guide per person (P1 maintains)
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
  `data["indicators"] = {"urls": [...], "domains": [...], "emails": [...], "phones": [...], "upi_ids": [...], "amounts": [...]}`.
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

## 7. Hashing & blockchain (contract: P4 · backend hashing/web3.py: P1)

- **Canonical JSON:** `json.dumps(report.model_dump(mode="json", exclude={"chain"}), sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
- **Hash:** SHA-256 of that UTF-8 string → `"0x" + hexdigest` → stored on-chain as `bytes32`.
  Already implemented in `backend/app/registry/hashing.py` — use it, don't reimplement.
- A report must not be modified after creation (except filling `chain`), or verification will fail.
- **Only the hash + risk level + timestamp go on-chain.** Never raw URLs, messages, emails, phone numbers or personal data.
- A blockchain record proves a report's **integrity and history**, not that the report is **true**.

Contract `contracts/contracts/ThreatRegistry.sol` (implemented + tested; extra helpers: `getHistory`, `verify`, `idOfHash`, `disputeCount`):
```solidity
function submitReport(bytes32 reportHash, string calldata riskLevel) external returns (uint256 id);
function reviseReport(uint256 id, bytes32 newHash) external;          // keeps revision history
function disputeReport(uint256 id, string calldata reasonCode) external; // short code, no PII
function getReport(uint256 id) external view returns (bytes32 hash, address submitter, uint256 timestamp, string memory riskLevel, uint8 status, uint256 revisions);
function reportCount() external view returns (uint256);              // ids start at 1; status 0=Active 1=Disputed 2=Revised
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
  Replace the body; keep the signature.
- **Done by P1 (ready to use):**
  - `core/safe_fetch.py` — `safe_fetch(url)` → `FetchResult` (final_url, status_code, lower-cased `headers`, `body`,
    `redirect_chain`, `redirect_statuses`, `resolved_ip`). Raises `UnsafeTargetError` / `httpx` errors — catch them.
    Also `resolve_and_validate(host, port)`.
  - `ai/llm.py` — Gemini. `llm_json(system, user, Model)` → validated model or `None`; `untrusted_block(label, text)`
    to wrap untrusted text; `mask_pii(text)` to hide phones/emails/UPI ids.
  - `analyzers/tls_analyzer.py`, `ai/explain.py`, `correlation/engine.py` (links reports by domain, cert, IP,
    email, phone, UPI id, similar text), `registry/chain.py` + the smart contract (works on the local Hardhat chain; needs `.env` values — until then
    registry endpoints return **501** with the list of what's missing).
  - `backend/scripts/tamper_report.py <id>` — demo: alters a stored report so verification shows a mismatch.
- **Correlation reads these keys if present:** dns `data["a_records"]`/`["aaaa_records"]`, any check's `data["ip"]`,
  message `data["indicators"]` (`emails`, `phones`, `upi_ids`).
- Frontend: Investigate page (URL + message tabs), Report page, History page, Verify page, Registry panel.
- `backend/data/brands.json`: starter list of brands + official domains for typosquatting checks (P2 extends).
- `docs/tasks/`: one step-by-step guide per person — start there.
- Add tests for your module in `backend/tests/test_<module>.py`.

---

## 10. Team workflow

- `git pull` before you start; commit small and often; push at least every 2–3 hours.
- One branch per person (`p1-lead`, `p2-security`, `p3-ai`, `p4-web3`), merge into `main` frequently.
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
6. `routes.py` with all §5 endpoints (registry/correlation endpoints can return 501 until implemented)
7. `frontend`: Vite + React + TS + Tailwind; Home page (URL tab + Message tab), Report page rendering a report
8. `README.md` with run steps; confirm `uvicorn app.main:app --reload` and `npm run dev` both work; push to `main`

### Phase 2 — Build modules into the skeleton (Hour 3–16)

Full step-by-step instructions, examples and "done when" checks are in `docs/tasks/`. Summary:

| Who | Builds (in this order) |
|---|---|
| **P1** | ✅ `safe_fetch.py` → ✅ `llm.py` → ✅ `tls_analyzer.py` → ✅ `explain.py` → ✅ `correlation/engine.py` → ✅ contract + `chain.py` → integration & merges |
| **P2** | `url_analyzer.py` (offline string checks) → `dns_analyzer.py` → `threat_intel.py` → `headers_analyzer.py` → redirect checks (after P1's `safe_fetch`) |
| **P3** | indicator extraction → scam-pattern rules → `data/sample_messages.json` → LLM scam classification (after P1's `llm.py`) |
| **P4** | try it on the local chain → MetaMask + Sepolia test ETH → `npm run deploy:sepolia` → registry/verify UI → testing report → demo script |

**Hand-offs (tell the team in chat when done):**
- P1 `safe_fetch.py` ready → unblocks P2's `headers_analyzer` and redirect checks
- P1 `llm.py` ready → unblocks P3's LLM step
- P4 deploys to Sepolia → shares the contract address (and, privately, the throwaway wallet key) with the team for the live demo

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
