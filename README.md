# TrustLens — AI-Powered Web Threat Detection & Digital Trust Intelligence

> HackMatrix 48-hour hackathon project. ("TrustLens" is a working name.)

Paste a suspicious **URL, domain, email or SMS** and get an **evidence-based risk report**:
phishing indicators, TLS certificate trust, threat-intelligence matches, scam-language analysis and an
AI explanation grounded in that evidence. Reports can be **registered on-chain** (hash only) and
**independently verified** for tamper-evidence.

**Team members & AI assistants: read [AGENTS.md](AGENTS.md) first.** It defines ownership, data formats,
API and security rules.

## Architecture

```
React (Vite) ──/api──▶ FastAPI ──▶ pipeline.py
                                   ├─ analyzers/ (url, dns, threat_intel, tls, headers, message)  ← run in parallel
                                   ├─ risk/engine.py      (deterministic verdict)
                                   ├─ ai/explain.py       (LLM explanation of findings)
                                   ├─ correlation/        (links related reports)
                                   └─ db.py (SQLite)
                     registry/chain.py ──web3.py──▶ ThreatRegistry.sol (Sepolia testnet)
```

## Prerequisites

- Python 3.11+
- Node.js 20+
- Git

## Setup

```bash
git clone <repo-url>
cd Hackmatrix
cp .env.example .env        # then fill in the keys you have
```

### Backend (terminal 1)

```bash
cd backend
python -m venv .venv
# Windows (Git Bash):  source .venv/Scripts/activate
# Windows (PowerShell): .venv\Scripts\Activate.ps1
# macOS/Linux:         source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

API: http://localhost:8000 · Interactive docs: http://localhost:8000/docs

### Frontend (terminal 2)

```bash
cd frontend
npm install
npm run dev
```

App: http://localhost:5173 (calls to `/api` are proxied to the backend)

### Tests

```bash
cd backend && python -m pytest -q
cd frontend && npm run build && npm run lint
```

### Run one analyzer on its own

```bash
cd backend
python -m app.analyzers.tls_analyzer https://expired.badssl.com
python -m app.analyzers.message_analyzer "Your KYC expires today, update at http://bad.example"
```

## Mock mode

Until the real checks are implemented, every analyzer returns `skipped` and reports come out
**Inconclusive**. Set `MOCK_ANALYZERS=true` in `.env` to replace unimplemented analyzers with fake
sample findings (labelled "MOCK DATA") for UI and on-chain work. **Turn it off for the demo.**

## Project status

Each person has a step-by-step guide in [docs/tasks/](docs/tasks/).

| Module | Owner | Status |
|---|---|---|
| Foundation, pipeline, risk engine, dashboard, hashing | P1 | ✅ working |
| SSRF-safe fetch, TLS analysis, LLM wrapper, AI explanation, correlation, web3.py backend | P1 | ⏳ stubs (rule-based explanation fallback works) |
| URL/phishing, DNS & domain age, threat intel, security headers | P2 | ⏳ stubs |
| Scam message analysis (indicators, rules, LLM classification) | P3 | ⏳ stub (basic URL extraction works) |
| Smart contract (Remix → Sepolia), registry/verify UI, testing report, demo script | P4 | ⏳ basic UI done |

## Deliverables checklist

- [ ] Working prototype (URL + message investigation)
- [ ] Public GitHub repo with setup instructions
- [ ] AI demo: scam message analysis with evidence-based explanation
- [ ] Cybersecurity demo: phishing detection + TLS certificate analysis
- [ ] Web3 demo: contract deployed on Sepolia (address + tx in this README)
- [ ] Verification evidence
- [ ] Technical docs: `docs/architecture.md`, `docs/security-methodology.md`
- [ ] Testing report: `docs/testing-report.md` (≥3 suspicious + ≥3 benign cases)
- [ ] Live demo script rehearsed
