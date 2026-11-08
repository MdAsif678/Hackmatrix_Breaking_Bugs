"""Threat-intel lookups: URLhaus, OpenPhish, Google Safe Browsing. Set authoritative=True on a match.

Owner: P2. Guide: docs/tasks/P2-security.md
"""
import asyncio
import time
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.analyzers.base import error_result, run_cli
from app.config import settings
from app.schemas import CheckResult, Finding, Severity

# Module-level cache for OpenPhish feed (refreshed at most once per hour)
_openphish_cache: dict[str, Any] = {
    "urls": set(),
    "hosts": set(),
    "timestamp": 0.0,
}
_cache_lock = asyncio.Lock()


async def _get_openphish_feed() -> tuple[set[str], set[str], str | None]:
    """Retrieve OpenPhish free feed, caching for 1 hour."""
    now = time.time()
    async with _cache_lock:
        if _openphish_cache["timestamp"] > 0 and (now - _openphish_cache["timestamp"] < 3600):
            return _openphish_cache["urls"], _openphish_cache["hosts"], None

        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.get("https://openphish.com/feed.txt", follow_redirects=True)
                if resp.status_code == 200:
                    urls = set()
                    hosts = set()
                    for line in resp.text.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            urls.add(line.lower())
                            urls.add(line.lower().rstrip("/"))
                            try:
                                h = urlsplit(line).hostname
                                if h:
                                    hosts.add(h.lower())
                            except Exception:
                                pass
                    _openphish_cache["urls"] = urls
                    _openphish_cache["hosts"] = hosts
                    _openphish_cache["timestamp"] = now
                    return urls, hosts, None
                else:
                    return _openphish_cache["urls"], _openphish_cache["hosts"], f"OpenPhish HTTP status {resp.status_code}"
        except Exception as exc:
            return _openphish_cache["urls"], _openphish_cache["hosts"], f"OpenPhish download failed: {type(exc).__name__}"


async def analyze(target: str) -> CheckResult:
    """Query threat intelligence feeds for target URL and host."""
    try:
        findings: list[Finding] = []
        limitations: list[str] = []
        sources_checked: list[str] = []

        raw_target = target.strip()
        parts = urlsplit(raw_target)
        host = (parts.hostname or "").lower()
        normalized_url = raw_target.lower().rstrip("/")

        # 1. OpenPhish Free Feed
        feed_urls, feed_hosts, feed_err = await _get_openphish_feed()
        if feed_err and not feed_urls:
            limitations.append(f"OpenPhish check unavailable ({feed_err}).")
        else:
            sources_checked.append("OpenPhish")
            if normalized_url in feed_urls or raw_target.lower() in feed_urls:
                findings.append(
                    Finding(
                        id="threat_intel.openphish",
                        check="threat_intel",
                        title="URL listed in OpenPhish feed",
                        severity=Severity.critical,
                        evidence=f"Exact match found for '{target}' in OpenPhish active phishing feed.",
                        source="OpenPhish",
                        impact="OpenPhish tracks verified, active zero-day phishing operations.",
                        recommendation="Block access immediately; do not interact with or submit credentials to this URL.",
                        authoritative=True,
                    )
                )
            elif host and host in feed_hosts:
                findings.append(
                    Finding(
                        id="threat_intel.openphish_host",
                        check="threat_intel",
                        title="Host listed in OpenPhish feed",
                        severity=Severity.high,
                        evidence=f"Host '{host}' is currently hosting active phishing attacks in OpenPhish feed.",
                        source="OpenPhish",
                        impact="While this specific URL path was not listed, the host is actively serving phishing pages.",
                        recommendation="Exercise high caution; avoid visiting this host.",
                        authoritative=False,
                    )
                )

        # 2. URLhaus API
        if settings.urlhaus_auth_key:
            sources_checked.append("URLhaus")
            try:
                headers = {"Auth-Key": settings.urlhaus_auth_key}
                async with httpx.AsyncClient(timeout=settings.check_timeout_seconds) as client:
                    # Query URLhaus URL
                    url_resp = await client.post(
                        "https://urlhaus-api.abuse.ch/v1/url/",
                        data={"url": target},
                        headers=headers,
                    )
                    url_matched = False
                    if url_resp.status_code == 200:
                        url_data = url_resp.json()
                        if url_data.get("query_status") == "ok":
                            threat = url_data.get("threat", "malware_download")
                            date_added = url_data.get("date_added", "unknown")
                            url_status = url_data.get("url_status", "unknown")
                            findings.append(
                                Finding(
                                    id="threat_intel.urlhaus",
                                    check="threat_intel",
                                    title="URL listed in URLhaus malware database",
                                    severity=Severity.critical,
                                    evidence=f"Listed by URLhaus as {threat} since {date_added}, status: {url_status}.",
                                    source="URLhaus",
                                    impact="URLhaus tracks verified active malware distribution sites and payloads.",
                                    recommendation="Block access immediately; do not download any files.",
                                    authoritative=True,
                                )
                            )
                            url_matched = True

                    # Query URLhaus Host if URL did not match
                    if not url_matched and host:
                        host_resp = await client.post(
                            "https://urlhaus-api.abuse.ch/v1/host/",
                            data={"host": host},
                            headers=headers,
                        )
                        if host_resp.status_code == 200:
                            host_data = host_resp.json()
                            if host_data.get("query_status") == "ok":
                                findings.append(
                                    Finding(
                                        id="threat_intel.urlhaus_host",
                                        check="threat_intel",
                                        title="Host listed in URLhaus database",
                                        severity=Severity.high,
                                        evidence=f"Host '{host}' is known to URLhaus with associated malware URLs.",
                                        source="URLhaus",
                                        impact="The host has an active or recent history of distributing malware.",
                                        recommendation="Treat all content from this host as untrusted.",
                                        authoritative=False,
                                    )
                                )
            except Exception as exc:
                limitations.append(f"URLhaus query failed: {type(exc).__name__}.")
        else:
            limitations.append("URLhaus not checked: no API key configured.")

        # 3. Google Safe Browsing API (optional)
        if settings.google_safe_browsing_api_key:
            sources_checked.append("Google Safe Browsing")
            try:
                gsb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.google_safe_browsing_api_key}"
                payload = {
                    "client": {"clientId": "trustlens", "clientVersion": "1.0.0"},
                    "threatInfo": {
                        "threatTypes": [
                            "MALWARE",
                            "SOCIAL_ENGINEERING",
                            "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION",
                        ],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": target}],
                    },
                }
                async with httpx.AsyncClient(timeout=settings.check_timeout_seconds) as client:
                    gsb_resp = await client.post(gsb_url, json=payload)
                    if gsb_resp.status_code == 200:
                        matches = gsb_resp.json().get("matches", [])
                        if matches:
                            threat_type = matches[0].get("threatType", "MALWARE")
                            platform = matches[0].get("platformType", "ANY_PLATFORM")
                            findings.append(
                                Finding(
                                    id="threat_intel.google_safe_browsing",
                                    check="threat_intel",
                                    title=f"Google Safe Browsing match ({threat_type})",
                                    severity=Severity.critical,
                                    evidence=f"Google Safe Browsing classified target as {threat_type} on {platform}.",
                                    source="Google Safe Browsing",
                                    impact="Identified as a malicious resource by Google's automated threat detection.",
                                    recommendation="Do not proceed to this website.",
                                    authoritative=True,
                                )
                            )
            except Exception as exc:
                limitations.append(f"Google Safe Browsing query failed: {type(exc).__name__}.")
        else:
            limitations.append("Google Safe Browsing not checked: no API key configured.")

        data: dict[str, Any] = {
            "sources_checked": sources_checked,
            "host": host,
        }

        return CheckResult(
            check="threat_intel",
            status="ok",
            findings=findings,
            data=data,
            limitations=limitations,
        )
    except Exception as exc:
        return error_result("threat_intel", exc)


if __name__ == "__main__":
    run_cli(analyze)
