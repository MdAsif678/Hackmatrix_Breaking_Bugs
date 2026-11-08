"""Tests for headers_analyzer.py (P2)."""
import asyncio
from app.analyzers.headers_analyzer import analyze, check_headers
from app.schemas import Severity


def test_check_headers_insecure_site():
    url = "http://neverssl.com"
    headers = {
        "Server": "Apache/2.4.41 (Ubuntu)",
        "Content-Type": "text/html",
    }
    body = "<html><body><img src=\"http://example.com/logo.png\" /></body></html>"

    findings = check_headers(url, headers, body)
    finding_ids = [f.id for f in findings]

    assert "headers.no_https_redirect" in finding_ids
    assert "headers.missing_csp" in finding_ids
    assert "headers.missing_frame_protection" in finding_ids
    assert "headers.missing_nosniff" in finding_ids
    assert "headers.server_version" in finding_ids


def test_check_headers_secure_site():
    url = "https://github.com"
    headers = {
        "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "strict-origin-when-cross-origin",
        "server": "GitHub.com",
    }
    body = "<html><body>Clean body</body></html>"

    findings = check_headers(url, headers, body)
    assert len(findings) == 0


def test_headers_analyzer_stub_safe_fetch_graceful():
    # If safe_fetch is not implemented, analyze() should return ok with limitations, not error or crash
    result = asyncio.run(analyze("https://github.com"))
    assert result.status == "ok"

