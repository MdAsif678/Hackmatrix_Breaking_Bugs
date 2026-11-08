"""Passive security-header checks: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, HTTP->HTTPS, mixed content.

Owner: P2. Guide: docs/tasks/P2-security.md
"""
import re
from typing import Any
from urllib.parse import urlsplit

from app.analyzers.base import error_result, run_cli
from app.schemas import CheckResult, Finding, Severity


def check_headers(url: str, headers: dict[str, str], body: str) -> list[Finding]:
    """Inspect HTTP response headers and body for security configuration weaknesses."""
    findings: list[Finding] = []
    h = {k.lower(): v for k, v in headers.items()}
    url_lower = url.lower()
    is_https = url_lower.startswith("https://")

    # 1. HTTP to HTTPS redirect check
    if url_lower.startswith("http://"):
        findings.append(
            Finding(
                id="headers.no_https_redirect",
                check="headers",
                title="HTTP connection does not redirect to HTTPS",
                severity=Severity.medium,
                evidence=f"Connection remained on unencrypted URL: '{url}'.",
                source="HTTP response",
                impact="Traffic is sent unencrypted across the network, vulnerable to eavesdropping and man-in-the-middle attacks.",
                recommendation="Configure the web server to automatically redirect all HTTP traffic to HTTPS (301 Permanent Redirect).",
            )
        )

    # 2. Missing HSTS (Strict-Transport-Security)
    if is_https and "strict-transport-security" not in h:
        findings.append(
            Finding(
                id="headers.missing_hsts",
                check="headers",
                title="Missing HTTP Strict Transport Security (HSTS)",
                severity=Severity.low,
                evidence="The 'Strict-Transport-Security' response header was not found on an HTTPS connection.",
                source="HTTP response headers",
                impact="Without HSTS, initial connections may be downgraded or intercepted via SSL-stripping attacks.",
                recommendation="Enable HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload.",
            )
        )

    # 3. Missing Content Security Policy (CSP)
    csp_val = h.get("content-security-policy", "")
    if not csp_val:
        findings.append(
            Finding(
                id="headers.missing_csp",
                check="headers",
                title="Missing Content Security Policy (CSP)",
                severity=Severity.low,
                evidence="The 'Content-Security-Policy' header was not present in the server response.",
                source="HTTP response headers",
                impact="A missing CSP significantly elevates the risk and impact of cross-site scripting (XSS) and code injection.",
                recommendation="Implement a Content-Security-Policy defining authorized domains for scripts, styles, and media.",
            )
        )

    # 4. Missing Clickjacking Frame Protection
    has_xfo = "x-frame-options" in h
    has_frame_ancestors = "frame-ancestors" in csp_val.lower()
    if not has_xfo and not has_frame_ancestors:
        findings.append(
            Finding(
                id="headers.missing_frame_protection",
                check="headers",
                title="Missing Clickjacking frame protection",
                severity=Severity.low,
                evidence="Neither 'X-Frame-Options' nor CSP 'frame-ancestors' directive was provided.",
                source="HTTP response headers",
                impact="The page can be embedded in an iframe on external sites, exposing users to clickjacking attacks.",
                recommendation="Add 'X-Frame-Options: DENY' (or 'SAMEORIGIN') or CSP 'frame-ancestors 'self''.",
            )
        )

    # 5. Missing X-Content-Type-Options: nosniff
    xcto = h.get("x-content-type-options", "").lower()
    if "nosniff" not in xcto:
        findings.append(
            Finding(
                id="headers.missing_nosniff",
                check="headers",
                title="Missing MIME sniffing protection",
                severity=Severity.info,
                evidence="'X-Content-Type-Options: nosniff' header was not set.",
                source="HTTP response headers",
                impact="Browsers may attempt MIME type sniffing, potentially executing non-script files as JavaScript.",
                recommendation="Add header: 'X-Content-Type-Options: nosniff'.",
            )
        )

    # 6. Mixed Content
    if is_https and body:
        if re.search(r'src=["\']http://', body, re.IGNORECASE):
            findings.append(
                Finding(
                    id="headers.mixed_content",
                    check="headers",
                    title="Mixed content detected on HTTPS page",
                    severity=Severity.low,
                    evidence="HTML body contains resource tags loading unencrypted 'http://' resources.",
                    source="HTML body",
                    impact="Unencrypted resources can be intercepted or manipulated to compromise the secure session.",
                    recommendation="Ensure all embedded assets (images, scripts, frames) are served over HTTPS.",
                )
            )

    # 7. Missing Referrer-Policy
    if "referrer-policy" not in h:
        findings.append(
            Finding(
                id="headers.missing_referrer_policy",
                check="headers",
                title="Missing Referrer-Policy header",
                severity=Severity.info,
                evidence="'Referrer-Policy' header was not present.",
                source="HTTP response headers",
                impact="Browsers may leak sensitive query parameters or URL paths in the Referer header to external destinations.",
                recommendation="Add header: 'Referrer-Policy: strict-origin-when-cross-origin'.",
            )
        )

    # 8. Server Banner / Technology Version Disclosure
    for header_name in ("server", "x-powered-by"):
        if header_name in h:
            val = h[header_name]
            if re.search(r"\d+\.\d+", val):
                findings.append(
                    Finding(
                        id="headers.server_version",
                        check="headers",
                        title=f"Server discloses software version ({val})",
                        severity=Severity.info,
                        evidence=f"Header '{header_name}: {val}' reveals exact software version information.",
                        source="HTTP response headers",
                        impact="Version disclosure assists attackers in fingerprinting known unpatched vulnerabilities.",
                        recommendation="Configure the web server to suppress detailed software versions.",
                    )
                )

    return findings


async def analyze(target: str) -> CheckResult:
    """Analyze HTTP response security headers and passive configuration."""
    try:
        findings: list[Finding] = []
        limitations: list[str] = []
        data: dict[str, Any] = {}

        try:
            from app.core.safe_fetch import safe_fetch
            resp = await safe_fetch(target)
            body_text = resp.body.decode(errors="ignore") if resp.body else ""
            findings = check_headers(resp.final_url, resp.headers, body_text)
            data = {
                "final_url": resp.final_url,
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "redirect_chain": resp.redirect_chain,
            }
        except NotImplementedError:
            limitations.append("Passive security headers check waiting for P1's safe_fetch implementation.")
        except Exception as exc:
            limitations.append(f"HTTP fetch failed: {type(exc).__name__}: {exc}")

        return CheckResult(
            check="headers",
            status="ok",
            findings=findings,
            data=data,
            limitations=limitations,
        )
    except Exception as exc:
        return error_result("headers", exc)


if __name__ == "__main__":
    run_cli(analyze)
