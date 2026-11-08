"""Tests for dns_analyzer.py (P2)."""
import asyncio
from app.analyzers.dns_analyzer import analyze
from app.schemas import Severity


def test_benign_domain_dns_resolution():
    result = asyncio.run(analyze("https://github.com"))
    assert result.status == "ok"
    assert "A" in result.data["dns_records"]
    assert len(result.data["dns_records"]["A"]) > 0
    # No findings should be generated for a long-established domain
    assert len(result.findings) == 0
    assert result.data["age_days"] is not None
    assert result.data["age_days"] > 365 * 10


def test_non_existent_domain_no_resolution():
    result = asyncio.run(analyze("https://this-domain-does-not-exist-hackmatrix-9999.com"))
    assert result.status == "ok"
    finding_ids = [f.id for f in result.findings]
    assert "dns.no_resolution" in finding_ids
    finding = next(f for f in result.findings if f.id == "dns.no_resolution")
    assert finding.severity == Severity.medium

