"""Tests for threat_intel.py (P2)."""
import asyncio
from unittest.mock import patch
from app.analyzers.threat_intel import analyze
from app.schemas import Severity


def test_benign_site_no_threat_intel_findings():
    result = asyncio.run(analyze("https://github.com"))
    assert result.status == "ok"
    assert len(result.findings) == 0


def test_openphish_exact_match():
    # Mock OpenPhish feed to contain a test malicious URL
    mock_urls = {"http://malicious-test-phish.example/login"}
    mock_hosts = {"malicious-test-phish.example"}
    with patch("app.analyzers.threat_intel._get_openphish_feed", return_value=(mock_urls, mock_hosts, None)):
        result = asyncio.run(analyze("http://malicious-test-phish.example/login"))
        assert result.status == "ok"
        finding_ids = [f.id for f in result.findings]
        assert "threat_intel.openphish" in finding_ids
        finding = next(f for f in result.findings if f.id == "threat_intel.openphish")
        assert finding.severity == Severity.critical
        assert finding.authoritative is True


def test_openphish_host_only_match():
    mock_urls = {"http://malicious-test-phish.example/login"}
    mock_hosts = {"malicious-test-phish.example"}
    with patch("app.analyzers.threat_intel._get_openphish_feed", return_value=(mock_urls, mock_hosts, None)):
        result = asyncio.run(analyze("http://malicious-test-phish.example/other-path"))
        assert result.status == "ok"
        finding_ids = [f.id for f in result.findings]
        assert "threat_intel.openphish_host" in finding_ids
        finding = next(f for f in result.findings if f.id == "threat_intel.openphish_host")
        assert finding.severity == Severity.high
        assert finding.authoritative is False

