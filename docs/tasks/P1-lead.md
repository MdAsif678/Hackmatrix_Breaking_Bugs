# P1 — Lead: step-by-step guide

You own the hard, tightly connected parts: everything other modules depend on, plus the two checks
that need the most security knowledge (SSRF protection and TLS trust). You also merge and integrate everyone's
work and run the demo.

Already done: repo, schemas, pipeline, risk engine, DB, API, hashing, dashboard, mock mode, tests, and ✅ tasks 1–6
below (safe_fetch, Gemini llm.py with model fallback, chain.py + the ThreatRegistry contract on a local Hardhat chain,
tls_analyzer, explain.py, correlation). Remaining: integration, merges, Sepolia demo with P4, docs, demo.

## Your files

`app/main.py`, `config.py`, `schemas.py`, `db.py`, `pipeline.py`, `api/routes.py`, `risk/engine.py`,
`core/safe_fetch.py`, `analyzers/tls_analyzer.py`, `analyzers/base.py`, `analyzers/mock.py`, `ai/llm.py`, `ai/explain.py`,
`correlation/engine.py`, `registry/hashing.py`, `registry/chain.py`, `data/distrusted_cas.json`,
`frontend/src/` (except `features/registry/`), `README.md`, `docs/architecture.md`, `docs/tasks/`.

## Order of work, and who's waiting on you

| # | Task | Unblocks | Target hour |
|---|---|---|---|
| 1 | `safe_fetch.py` | P2 headers + redirect checks | H3–H6 |
| 2 | `llm.py` | P3 Step 4 | H6–H8 |
| 3 | `chain.py` (once P4 deploys) | P4 UI testing, Web3 demo | H8–H12 |
| 4 | `tls_analyzer.py` | Cybersecurity demo | H12–H18 |
| 5 | `explain.py` with the LLM | AI demo | H18–H22 |
| 6 | `correlation/engine.py` + UI | Module 4 | H22–H28 |
| 7 | Merge, integration, bug fixes, docs, deploy, demo | everything | ongoing |

Announce each hand-off in the team chat.

---

## 1. `core/safe_fetch.py` — SSRF-safe fetching

Goal: fetch a user-supplied URL without letting it reach our own server or internal network.

- Add a reusable helper `async def resolve_and_validate(host: str, port: int) -> list[str]`, which TLS will reuse:
  - `loop.getaddrinfo(host, port)` → every resolved IP must pass `ipaddress.ip_address(ip).is_global`
    and must not be multicast, reserved, loopback, link-local or private. Reject `0.0.0.0`, `169.254.169.254` and
    IPv4-mapped IPv6 that maps to a private IP.
  - Raise `UnsafeTargetError` with a clear message, which becomes a limitation in the report.
- `safe_fetch(url)`:
  - Scheme `http`/`https` only, port 80/443 only, no userinfo credentials sent.
  - **Manual redirects:** `httpx.AsyncClient(follow_redirects=False, timeout=settings.check_timeout_seconds)`.
    Loop up to 5 hops, resolving relative `Location` with `urljoin` and re-validating every hop.
  - **DNS rebinding:** validate then connect. Simplest robust option: pin the IP with a custom
    `httpx.AsyncHTTPTransport` / `local_address`, or check `response.extensions["network_stream"].get_extra_info("server_addr")`
    after connecting and abort if it's not in the validated set. Document the choice in `security-methodology.md`.
  - Stream the body (`client.stream`) and stop at 1 MB → `truncated=True`.
  - Generic User-Agent, e.g. `TrustLensScanner/0.1`. Never execute JS, never write to disk.
- Tests: `http://127.0.0.1`, `http://localhost`, `http://169.254.169.254/latest/meta-data`, `http://10.0.0.1`,
  `http://[::1]`, `http://0x7f000001`, `ftp://x`, and a redirect to localhost must all be rejected.

## 2. `ai/llm.py` — LLM wrapper

- `llm_json(system, user, schema)`: call the provider from `.env`, ask for JSON only, strip code fences,
  `schema.model_validate_json(...)`, and return `None` on any error or timeout (~15 s). Log failures; never raise.
- Put user content in delimiters, and state in the system prompt that delimited content is untrusted data.
- Mask what the model doesn't need (e.g. replace phone digits with `XXXXXX1234`) before sending.
- Pick the provider by which key the team has. Keep it behind this one function so swapping is a one-line change.

## 3. `registry/chain.py` — web3.py

- Load ABI from `contracts/ThreatRegistry.abi.json`, address from `.env` (`REGISTRY_CONTRACT_ADDRESS`),
  and RPC from `SEPOLIA_RPC_URL` (Alchemy/Infura, or the public `https://ethereum-sepolia-rpc.publicnode.com`).
- `submit(report)`: `h = report_hash(report)` → build `submitReport(bytes.fromhex(h[2:]), report.risk_level.value)`
  → sign with `REGISTRY_PRIVATE_KEY` → send → `wait_for_transaction_receipt` → read the id from the
  `ReportSubmitted` event → `ChainRecord`.
- `verify(report)`: recompute the hash, call `getReport(id)`, compare, and return `VerifyResult` with the block timestamp.
- Add `backend/scripts/tamper_report.py <id>` (edits one field of a stored report in SQLite) for P4's tamper demo.
- Raise `RegistryNotConfigured` when env vars are missing → the API returns 501 with a clear message.

## 4. `analyzers/tls_analyzer.py` — certificate & trust

- Host/port from the URL; skip with a limitation for `http://` URLs (and add a `tls.no_https` low finding).
  Validate the IP with `resolve_and_validate` first.
- **Verified handshake** with `ssl.create_default_context()`. On `ssl.SSLCertVerificationError`, map
  `verify_message` to findings: expired → `tls.expired` (high), hostname mismatch → `tls.hostname_mismatch` (high),
  self-signed → `tls.self_signed` (high), unknown issuer → `tls.untrusted_root` (high), revoked → `tls.revoked` (critical).
- **Unverified handshake** (`CERT_NONE`) to still read the certificate: `getpeercert(binary_form=True)` →
  `cryptography.x509.load_der_x509_certificate`. Run the blocking socket code in `asyncio.to_thread`.
- `data`: subject, issuer, SANs, not_before/not_after, days_left, serial, signature algorithm, key type/size,
  TLS version, SHA-256 fingerprint.
- Findings: `tls.expiring_soon` (<14 days, low), `tls.weak_key` (RSA <2048, high), `tls.weak_signature`
  (SHA-1/MD5, medium), `tls.old_protocol` (TLS ≤1.1, medium), `tls.distrusted_ca` (issuer matches
  `data/distrusted_cas.json`, critical, `source="CA distrust list"`).
- Always add the info finding `tls.valid_not_proof` when the cert is valid: "A valid certificate encrypts the
  connection but does not prove the site is legitimate."
- **Certificate Transparency:** `GET https://crt.sh/?q=<registered_domain>&output=json` (slow, so use a 6 s timeout).
  `data["ct"]`: count, issuers, most recent issuance. Finding `tls.ct_recent_issuance` (low) if the first cert ever
  was issued under 7 days ago, or `tls.ct_unexpected_issuer` (medium) if the current issuer never appears in CT history.
- `distrusted_cas.json`: CAs distrusted by browsers (e.g. Symantec legacy roots, DigiNotar, WoSign/StartCom,
  Camerfirma, TrustCor, Entrust after Nov 2024, e-Tugra), matched by issuer organisation or root SPKI hash, each with a
  source link. Never claim to detect a CA's key-generation weakness from a URL. Only match known-distrusted CAs.
- Tests against `expired.badssl.com`, `wrong.host.badssl.com`, `self-signed.badssl.com`,
  `untrusted-root.badssl.com`, `sha1-intermediate.badssl.com`, `github.com`.

## 5. `ai/explain.py` — evidence-grounded explanation

- Prompt contains only finding ids, titles, evidence, severities and the risk level. No raw web content.
- Ask for `Explanation` JSON. Reject any key point whose `[finding.id]` doesn't exist in the report, then fall back to
  `fallback_explanation` if nothing valid remains.
- Tell the model it must not change or argue with the risk level, and must not call a site "safe".

## 6. `correlation/engine.py`

- Index table in SQLite: `(report_id, kind, value)` for registrable domains, IPs, emails, phones, UPI IDs, cert fingerprints.
- `find_related`: reports sharing ≥1 strong indicator (domain/IP/UPI/phone/cert) → ids. Add message text similarity
  (`difflib.SequenceMatcher` ratio > 0.8) as a weaker link.
- `related_details`: list of shared indicators per related report. Show it on the Report page.
- Deterministic matching only; AI may summarise the cluster in a sentence.

## 7. Integration duties

- Review and merge teammates' branches. Run `python -m pytest -q` + `npm run build` after each merge.
- Keep `frontend/src/types.ts` in sync with `schemas.py`.
- Turn `MOCK_ANALYZERS` off and test the real flow from H16.
- Feature freeze at H36. Finish `docs/architecture.md` and the README deliverables checklist, then rehearse the demo with P4.
