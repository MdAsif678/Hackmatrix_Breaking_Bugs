"""Regression tests for P2 checks: false-positive handling and honest check status (added by P1 during review).

The URL check's redirect lookup is stubbed so these tests run offline and fast.
"""
import asyncio

import pytest

from app.analyzers import headers_analyzer, threat_intel, url_analyzer
from app.config import settings
from app.core import safe_fetch as sf
from app.core.safe_fetch import FetchResult, UnsafeTargetError
from app.schemas import Severity


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def no_network(monkeypatch):
    async def unreachable(url, *a, **kw):
        raise UnsafeTargetError("offline test")

    monkeypatch.setattr(sf, "safe_fetch", unreachable)


def serious(result):
    return {f.id for f in result.findings if f.severity in (Severity.medium, Severity.high, Severity.critical)}


@pytest.mark.parametrize(
    "url",
    [
        "https://www.google.co.in/",  # brand's own regional site
        "https://www.amazon.co.uk/",
        "https://outlook.office365.com/mail/",  # Microsoft-owned
        "https://onlinesbi.sbi.bank.in/",  # new Indian bank domains
        "https://www.hdfc.bank.in/",
        "https://jobs.apply-now.co/",  # "apply" is a word, not a fake "apple"
        "https://accounts.google.com/signin",
        "https://github.com/login",
    ],
)
def test_genuine_sites_not_flagged(no_network, url):
    assert serious(run(url_analyzer.analyze(url))) == set()


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://paypa1-secure-login.com/", "url.typosquat"),  # look-alike digit
        ("https://amaz0n-refund.top/claim", "url.typosquat"),
        ("https://g00gle-account-verify.com/", "url.typosquat"),
        ("https://amazom-refund.com/", "url.typosquat"),  # one letter off in a hyphenated part
        ("https://hdfcbnak.com/", "url.typosquat"),  # swapped letters in a long name
        ("https://sbi-kyc-update.in/verify", "url.brand_in_subdomain"),
        ("https://netflix-billing-update.com/", "url.brand_in_subdomain"),
        ("https://paypal.top/login", "url.brand_unofficial_domain"),
    ],
)
def test_phishing_style_links_flagged_high(no_network, url, expected):
    result = run(url_analyzer.analyze(url))
    f = next(f for f in result.findings if f.id == expected)
    assert f.severity == Severity.high


def test_brand_word_without_scam_words_is_only_medium(no_network):
    result = run(url_analyzer.analyze("https://apple-pie-recipes.com/"))
    assert {f.severity for f in result.findings if f.id == "url.brand_in_subdomain"} == {Severity.medium}


def test_redirect_within_same_brand_not_flagged(monkeypatch):
    async def to_bank_in(url, *a, **kw):
        return FetchResult(final_url="https://www.hdfc.bank.in/", status_code=200, headers={}, body=b"",
                           redirect_chain=[url, "https://www.hdfc.bank.in/"])

    monkeypatch.setattr(sf, "safe_fetch", to_bank_in)
    assert "url.cross_domain_redirect" not in serious(run(url_analyzer.analyze("https://www.hdfcbank.com/")))


def test_redirect_to_unrelated_site_flagged(monkeypatch):
    async def elsewhere(url, *a, **kw):
        return FetchResult(final_url="https://evil-landing.example/", status_code=200, headers={}, body=b"",
                           redirect_chain=[url, "https://evil-landing.example/"])

    monkeypatch.setattr(sf, "safe_fetch", elsewhere)
    assert "url.cross_domain_redirect" in serious(run(url_analyzer.analyze("https://bit.ly/abc")))


def test_redirect_failure_is_reported_not_hidden(no_network):
    result = run(url_analyzer.analyze("https://example.com/"))
    assert any("Redirect check unavailable" in lim for lim in result.limitations)


def test_headers_unreachable_site_is_error_not_ok(no_network):
    result = run(headers_analyzer.analyze("https://unreachable.example/"))
    assert result.status == "error" and "not checked" in result.limitations[0]


def test_threat_intel_with_no_sources_is_error(monkeypatch):
    async def feed_down():
        return set(), set(), "OpenPhish download failed: ConnectError"

    async def army_down():
        return set(), "Phishing Army download failed: ConnectError"

    monkeypatch.setattr(threat_intel, "_get_openphish_feed", feed_down)
    monkeypatch.setattr(threat_intel, "_get_phishing_army", army_down)
    monkeypatch.setattr(settings, "urlhaus_auth_key", "")
    monkeypatch.setattr(settings, "google_safe_browsing_api_key", "")
    result = run(threat_intel.analyze("https://example.com/"))
    assert result.status == "error" and result.data["sources_checked"] == []


def test_phishing_army_host_match(monkeypatch):
    async def feed_empty():
        return set(), set(), None

    async def army():
        return {"fake-bank-login.example"}, None

    monkeypatch.setattr(threat_intel, "_get_openphish_feed", feed_empty)
    monkeypatch.setattr(threat_intel, "_get_phishing_army", army)
    hit = run(threat_intel.analyze("https://www.fake-bank-login.example/verify"))
    assert [(f.id, f.severity, f.authoritative) for f in hit.findings] == [
        ("threat_intel.phishing_army", Severity.high, False)
    ]
    assert "Phishing Army" in hit.data["sources_checked"]
    clean = run(threat_intel.analyze("https://github.com/"))
    assert clean.status == "ok" and clean.findings == []


@pytest.mark.parametrize(
    "host,count,shared",
    [
        ("github.com", None, True),
        ("raw.githubusercontent.com", None, True),
        ("drive.google.com", None, True),
        ("my-scam.pages.dev", None, True),
        ("files.example-cdn.net", 62403, True),  # thousands of reports: a platform, not one bad server
        ("45.168.132.19", 15, False),
        ("evil-downloads.top", 3, False),
    ],
)
def test_shared_platform_detection(host, count, shared):
    assert threat_intel._is_shared_platform(host, count) is shared
