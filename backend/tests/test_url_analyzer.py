"""Tests for url_analyzer.py (P2)."""
import asyncio
from app.analyzers.url_analyzer import analyze
from app.schemas import Severity


def test_typosquat_detection():
    result = asyncio.run(analyze("https://paypa1-secure-login.com"))
    assert result.status == "ok"
    finding_ids = [f.id for f in result.findings]
    assert "url.typosquat" in finding_ids or "url.brand_in_subdomain" in finding_ids
    typo_finding = next(f for f in result.findings if f.id == "url.typosquat")
    assert typo_finding.severity == Severity.high


def test_punycode_and_mixed_script():
    result = asyncio.run(analyze("https://xn--pple-43d.com"))
    assert result.status == "ok"
    finding_ids = [f.id for f in result.findings]
    assert "url.punycode" in finding_ids
    assert "url.mixed_script" in finding_ids


def test_link_shortener():
    result = asyncio.run(analyze("https://bit.ly/abc"))
    assert result.status == "ok"
    finding_ids = [f.id for f in result.findings]
    assert "url.shortener" in finding_ids


def test_benign_sites_have_no_high_findings():
    for site in ["https://github.com", "https://www.google.com"]:
        result = asyncio.run(analyze(site))
        assert result.status == "ok"
        high_critical = [f for f in result.findings if f.severity in (Severity.high, Severity.critical)]
        assert len(high_critical) == 0


def test_ip_host_and_at_symbol():
    result = asyncio.run(analyze("http://user@192.168.1.1/login"))
    assert result.status == "ok"
    finding_ids = [f.id for f in result.findings]
    assert "url.ip_host" in finding_ids
    assert "url.at_symbol" in finding_ids
    assert "url.no_https" in finding_ids
    assert "url.credential_words" in finding_ids
