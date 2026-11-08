# P2 — Security Checks: step-by-step guide

## What you're building (plain words)

When someone pastes a link, the app runs several **checks**, and each check reports what looks wrong.
You build 4 of them. Each check is **one Python file with one function**:

```python
async def analyze(target: str) -> CheckResult
```

- **Input:** a cleaned-up URL, e.g. `"https://paypa1-secure-login.com/verify"`
- **Output:** a `CheckResult` holding a list of **findings**. A finding is one suspicious thing, with proof.

You never touch the website UI, the database or the blockchain. P1 wires your output into everything else.

## Your files

| File | What it checks | Needs internet? |
|---|---|---|
| `backend/app/analyzers/url_analyzer.py` | The URL text itself: lookalike names, weird characters, shorteners | **No** (start here) |
| `backend/app/analyzers/dns_analyzer.py` | Does the domain exist? How old is it? | Yes |
| `backend/app/analyzers/threat_intel.py` | Is the URL on a known-phishing list? | Yes |
| `backend/app/analyzers/headers_analyzer.py` | Does the website send standard security headers? | Yes (via P1's `safe_fetch`) |
| `backend/data/brands.json` | List of brands + their real domains | – |
| `backend/tests/test_url_analyzer.py` etc. | Your tests | – |

Don't edit any other file. If you need something changed, ask P1.

## What a finding looks like

```python
from app.schemas import CheckResult, Finding, Severity

Finding(
    id="url.typosquat",                    # "<check>.<short_name>", unique
    check="url",
    title="Domain imitates paypal.com",    # short, human readable
    severity=Severity.high,                # info / low / medium / high / critical
    evidence="paypa1.com is 1 character away from paypal.com",   # the proof
    source="lexical analysis",             # where the proof came from
    impact="Users may believe they are on the real PayPal site.",
    recommendation="Type paypal.com yourself instead of clicking the link.",
)

return CheckResult(check="url", status="ok", findings=[...], data={"host": host, "registered_domain": "paypa1.com"})
```

**Golden rules:**
1. **Never crash.** The stub already wraps everything in `try/except` and returns `error_result(...)`. Keep that.
2. **Proof in `evidence`.** Never just "looks bad". Say exactly what you saw.
3. **Don't overreact.** One weak sign is `low`. Only strong signs are `high`. Real sites like `google.com` should give **no** findings, or only `info`/`low` ones.
4. **Raw facts go in `data`**, e.g. IP addresses, creation date. Judgements go in `findings`.

## How to run and test your check

```bash
cd backend
source .venv/Scripts/activate        # Windows Git Bash (PowerShell: .venv\Scripts\Activate.ps1)
python -m app.analyzers.url_analyzer https://paypa1-secure-login.com
python -m app.analyzers.url_analyzer https://github.com
python -m pytest -q                  # all tests must still pass
```

To see it in the app: run the backend and frontend (see README), then paste a URL in the browser.

---

## Step 1 — `url_analyzer.py` (no internet needed)

Get the parts of the URL:
```python
from urllib.parse import urlsplit
import tldextract
parts = urlsplit(target)
host = parts.hostname                     # "login.paypa1-secure.com"
ext = tldextract.extract(host)            # subdomain="login", domain="paypa1-secure", suffix="com"
registered = f"{ext.domain}.{ext.suffix}" # "paypa1-secure.com"
```

Add these checks. Each one adds a finding when it matches:

| Finding id | When | Severity |
|---|---|---|
| `url.ip_host` | Host is an IP address (`http://45.12.3.9/login`) | high |
| `url.at_symbol` | `@` in the URL before the host (`https://google.com@evil.com`) | high |
| `url.typosquat` | Registered domain is 1–2 letters different from an official domain in `brands.json`, but not equal | high |
| `url.brand_in_subdomain` | A brand keyword appears in the host (`sbi.kyc-update.in`), but the registered domain is not one of that brand's official domains | high |
| `url.punycode` | Host contains `xn--`, meaning non-English letters are hidden in the name | medium |
| `url.mixed_script` | Host mixes alphabets, e.g. Cyrillic `а` inside `аpple` (decode punycode with `idna`, check `unicodedata.name()`) | high |
| `url.shortener` | Host is a link shortener (`bit.ly`, `tinyurl.com`, `t.co`, `cutt.ly`, `rb.gy`, `is.gd`...) | medium |
| `url.redirect_param` | Query has `url=`, `redirect=`, `next=`, `dest=` whose value starts with `http` | medium |
| `url.suspicious_tld` | TLD is often abused (`zip`, `top`, `xyz`, `click`, `tk`, `ml`, `ga`, `cf`, `gq`, `cyou`, `rest`) | low |
| `url.many_subdomains` | More than 3 subdomain levels | low |
| `url.long_url` | URL longer than 100 characters | low |
| `url.no_https` | Scheme is `http` | low |
| `url.credential_words` | Path contains `login`, `verify`, `update`, `secure`, `account`, `kyc`, `password` | low |

For **typosquatting**, write a small Levenshtein (edit distance) function, or ask your AI for one. Compare
`ext.domain` (e.g. `paypa1`) with each official domain's name part (`paypal`). A distance of 1 or 2 counts as
a match, but skip very short names (under 5 letters) to avoid false alarms.

Put useful facts in `data`: `host`, `registered_domain`, `subdomain`, `tld`, `is_ip`, `decoded_host`.

✅ **Done when:**
- `https://paypa1-secure-login.com` shows `url.typosquat` or `url.brand_in_subdomain`
- `https://xn--pple-43d.com` shows `url.punycode` and `url.mixed_script`
- `https://bit.ly/abc` shows `url.shortener`
- `https://github.com` and `https://www.google.com` show **no** medium/high findings
- These cases are tests in `backend/tests/test_url_analyzer.py` (call `asyncio.run(analyze(url))`)

## Step 2 — `dns_analyzer.py`

1. Look up records with `dnspython` (use these exact `data` keys — P1's correlation reads them:
   `a_records`, `aaaa_records`, `mx_records`, `ns_records`):
   ```python
   import dns.asyncresolver
   answers = await dns.asyncresolver.resolve(registered_domain, "A")
   ```
   Do this for `A`, `AAAA`, `MX`, `NS`. Put the results in `data`. If a record type is missing, just skip it.
2. If the host has **no A/AAAA records at all**: finding `dns.no_resolution` (medium). The site may be down or fake.
3. **Domain age:** call RDAP with `httpx` (a public registry service, OK to call directly):
   `GET https://rdap.org/domain/<registered_domain>`. In the JSON, find the `events` entry with
   `eventAction == "registration"` and read its `eventDate`.
   - Younger than 30 days → `dns.new_domain` (**high**). Most phishing domains are brand new.
   - Younger than 180 days → `dns.young_domain` (medium)
   - Put `created`, `age_days` and `registrar` in `data`.
   - If RDAP fails: add a `limitations` entry ("Domain age unavailable"). This is not an error.
4. Use a timeout: `httpx.AsyncClient(timeout=5)`.

✅ **Done when:** `github.com` shows records and an age of over 15 years with no findings, and a made-up
domain like `this-does-not-exist-12345.com` shows `dns.no_resolution`.

## Step 3 — `threat_intel.py` (known-bad lists)

This is the only check that can prove a site is malicious, so its findings use `authoritative=True`.

1. **URLhaus** (free; get an Auth-Key at https://auth.abuse.ch/ and put it in `.env` as `URLHAUS_AUTH_KEY`):
   ```
   POST https://urlhaus-api.abuse.ch/v1/url/      form data: url=<target>    header: Auth-Key: <key>
   ```
   If `query_status == "ok"` → finding `threat_intel.urlhaus` with severity **critical**, `authoritative=True`
   and evidence like `"listed by URLhaus as malware_download since 2026-11-01, status online"`.
   Also try `POST /v1/host/` with `host=<host>`. A host match without an exact URL match is **high**, not authoritative.
2. **OpenPhish** free feed: `GET https://openphish.com/feed.txt` (one URL per line). Download it **once
   per hour**, keep it in a module-level variable, and compare the exact URL plus the host. An exact URL match →
   `threat_intel.openphish`, critical, authoritative. A host-only match → high.
3. **Google Safe Browsing** is optional, and only if a key is in `.env`.
4. When a source has no key or fails, add a limitation ("URLhaus not checked: no API key") and carry on.
5. Put `data["sources_checked"] = ["URLhaus", "OpenPhish"]` so the report shows what was checked.

Read keys like this: `from app.config import settings` → `settings.urlhaus_auth_key`.

✅ **Done when:** a URL taken from the live OpenPhish feed comes back **Confirmed Malicious** in the app, and
`github.com` has no threat-intel findings. **Never open feed URLs in your browser.**

## Step 4 — `headers_analyzer.py` (website security settings)

✅ P1's `safe_fetch` is **ready**. It downloads the page safely and returns `.final_url`, `.status_code`,
`.headers` (names lower-cased, e.g. `resp.headers.get("strict-transport-security")`), `.body`, `.redirect_chain`.
Write the logic as a plain function first and test it with fake headers:

```python
def check_headers(url: str, headers: dict[str, str], body: str) -> list[Finding]: ...
```

| Finding id | When | Severity |
|---|---|---|
| `headers.no_https_redirect` | `http://` URL that doesn't redirect to `https://` | medium |
| `headers.missing_hsts` | HTTPS site without `Strict-Transport-Security` | low |
| `headers.missing_csp` | No `Content-Security-Policy` | low |
| `headers.missing_frame_protection` | No `X-Frame-Options` and no `frame-ancestors` in the CSP | low |
| `headers.missing_nosniff` | No `X-Content-Type-Options: nosniff` | info |
| `headers.mixed_content` | HTTPS page whose HTML loads `src="http://...` | low |
| `headers.server_version` | `Server` / `X-Powered-By` reveals a version, e.g. `Apache/2.4.29` | info |

These are **configuration weaknesses, not phishing proof**, so keep severities low. Add `impact` and
`recommendation` text to each one. The judges asked for both.

Then call it from `analyze()` (catch `UnsafeTargetError` and `httpx.HTTPError` → add a limitation):
```python
from app.core.safe_fetch import safe_fetch
resp = await safe_fetch(target)
findings = check_headers(resp.final_url, resp.headers, resp.body.decode(errors="ignore"))
```
⚠️ Never use `httpx`/`requests` directly on the user's URL. Always use `safe_fetch`, which blocks attacks on our server.

✅ **Done when:** `github.com` gives few or no findings, and `http://neverssl.com` gives `headers.no_https_redirect`.

## Step 5 — Redirect checks (`safe_fetch` is ready)

In `url_analyzer.py`, call `safe_fetch(target)` and read `resp.redirect_chain`. If the final registered domain
differs from the starting one → `url.cross_domain_redirect` (medium). Put the chain in `data["redirect_chain"]`.

## Step 6 — Extras, if you have time

- Add more brands to `brands.json`: Indian banks, universities, government sites, delivery companies.
- Write the "Phishing indicators" section of `docs/security-methodology.md`: one line per finding, explaining why it matters.
- Give P4 your best test URLs for the testing report.

---

## Prompt to give your AI

> Read AGENTS.md and docs/tasks/P2-security.md. I am P2. Implement Step 1 in
> backend/app/analyzers/url_analyzer.py only. Keep the `analyze(target) -> CheckResult` signature and the
> try/except. Add tests in backend/tests/test_url_analyzer.py. Don't edit any other files.

Do one step per prompt. Run the file after each step and check the output looks right before moving on.
