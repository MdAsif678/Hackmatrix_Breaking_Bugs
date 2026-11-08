"""Tests for the SSRF-safe fetcher. Offline: a fake transport stands in for the internet."""
import asyncio

import httpx
import pytest

from app.core import safe_fetch as sf
from app.core.safe_fetch import UnsafeTargetError, is_forbidden_ip, safe_fetch

PUBLIC_IP = "93.184.215.14"


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1", "127.1.2.3", "10.0.0.1", "172.16.5.4", "192.168.1.1", "169.254.169.254",
        "0.0.0.0", "100.64.0.1", "224.0.0.1", "255.255.255.255", "::1", "fe80::1", "fc00::1",
        "::ffff:127.0.0.1", "::ffff:10.0.0.1", "2002:7f00:1::1", "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "not-an-ip",
    ],
)
def test_forbidden_ips(ip):
    assert is_forbidden_ip(ip)


@pytest.mark.parametrize("ip", ["8.8.8.8", "93.184.215.14", "2606:4700:4700::1111", "64:ff9b::14cf:4952"])
def test_public_ips_allowed(ip):
    assert not is_forbidden_ip(ip)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://localhost/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/",
        "http://[::1]/",
        "http://0x7f000001/",  # hex-encoded 127.0.0.1
        "http://2130706433/",  # decimal-encoded 127.0.0.1
        "http://127.1/",  # short form
        "ftp://example.com/",
        "file:///etc/passwd",
        "https://example.com:8443/",  # non-standard port
        "javascript:alert(1)",
    ],
)
def test_unsafe_urls_rejected(url):
    with pytest.raises(UnsafeTargetError):
        asyncio.run(safe_fetch(url))


@pytest.fixture
def fake_dns(monkeypatch):
    """Resolve *.test-public names to a public IP; everything else uses the real resolver."""
    real = sf.resolve_and_validate

    async def fake(host, port):
        if host.endswith("test-public.com"):
            return [PUBLIC_IP]
        return await real(host, port)

    monkeypatch.setattr(sf, "resolve_and_validate", fake)


def _transport(routes):
    """routes: {(host, path): httpx.Response-factory}. Records requests in transport.seen."""
    seen = []

    def handler(request: httpx.Request):
        seen.append(request)
        key = (request.headers["host"], request.url.path)
        return routes[key]()

    t = httpx.MockTransport(handler)
    t.seen = seen
    return t


def test_redirect_to_internal_address_blocked(fake_dns):
    t = _transport({
        ("a.test-public.com", "/"): lambda: httpx.Response(302, headers={"Location": "http://127.0.0.1/admin"}),
    })
    with pytest.raises(UnsafeTargetError):
        asyncio.run(safe_fetch("http://a.test-public.com/", transport=t))


def test_redirect_chain_followed_and_ip_pinned(fake_dns):
    t = _transport({
        ("a.test-public.com", "/"): lambda: httpx.Response(301, headers={"Location": "https://b.test-public.com/x"}),
        ("b.test-public.com", "/x"): lambda: httpx.Response(200, headers={"X-Test": "1"}, content=b"<html>hi</html>"),
    })
    r = asyncio.run(safe_fetch("http://user:pass@a.test-public.com/", transport=t))
    assert r.status_code == 200
    assert r.final_url == "https://b.test-public.com/x"
    assert r.redirect_chain == ["http://a.test-public.com/", "https://b.test-public.com/x"]
    assert r.redirect_statuses == [301]
    assert r.headers["x-test"] == "1"
    assert r.body == b"<html>hi</html>"
    # we connected to the validated IP, kept the hostname in Host, and never sent credentials
    assert all(req.url.host == PUBLIC_IP for req in t.seen)
    assert all("authorization" not in req.headers for req in t.seen)


def test_too_many_redirects(fake_dns):
    t = _transport({("a.test-public.com", "/"): lambda: httpx.Response(302, headers={"Location": "/"})})
    with pytest.raises(UnsafeTargetError, match="Too many redirects"):
        asyncio.run(safe_fetch("http://a.test-public.com/", transport=t))


def test_body_is_capped(fake_dns):
    big = b"a" * (sf.MAX_BODY_BYTES + 5000)
    t = _transport({("a.test-public.com", "/"): lambda: httpx.Response(200, content=big)})
    r = asyncio.run(safe_fetch("http://a.test-public.com/", transport=t))
    assert r.truncated and len(r.body) == sf.MAX_BODY_BYTES
