"""Tests for evidence-grounded explanations (the AI is faked)."""
import asyncio
from datetime import datetime, timezone

import pytest

from app.ai import explain as ex
from app.config import settings
from app.schemas import AnalysisReport, CheckResult, Explanation, Finding, RiskLevel, Severity


def _report() -> AnalysisReport:
    findings = [
        Finding(id="dns.new_domain", check="dns", title="Domain registered 3 days ago", severity=Severity.high,
                evidence="created 2026-11-05", source="RDAP"),
        Finding(id="url.typosquat", check="url", title="Imitates paypal.com", severity=Severity.high,
                evidence="paypa1.com vs paypal.com", source="lexical analysis"),
    ]
    return AnalysisReport(
        id="r1", input_type="url", input="https://paypa1.com", normalized_target="https://paypa1.com/",
        created_at=datetime.now(timezone.utc), risk_level=RiskLevel.high_risk,
        risk_reasons=["Multiple high-severity findings"], coverage=1.0,
        checks=[CheckResult(check="dns", status="ok", findings=findings[:1]),
                CheckResult(check="url", status="ok", findings=findings[1:])],
        recommendations=["Do not enter passwords."],
    )


@pytest.fixture
def fake_ai(monkeypatch):
    monkeypatch.setattr(settings, "llm_provider", "gemini")
    monkeypatch.setattr(settings, "llm_api_key", "k")
    holder = {}

    async def fake_llm_json(system, user, schema, **kw):
        holder["system"], holder["user"] = system, user
        return holder.get("answer")

    monkeypatch.setattr(ex, "llm_json", fake_llm_json)
    return holder


def run(coro):
    return asyncio.run(coro)


def test_fallback_without_ai():
    result = run(ex.explain(_report()))
    assert result.summary.startswith("This target shows multiple significant warning signs")
    assert result.key_points[0].startswith("[dns.new_domain]")


def test_grounded_ai_answer_used_and_invented_points_dropped(fake_ai):
    fake_ai["answer"] = Explanation(
        summary="This link is High Risk: it copies PayPal's name and the site is only 3 days old.",
        key_points=[
            "[url.typosquat] The address uses a 1 instead of an l to look like paypal.com.",
            "[dns.new_domain] The domain was registered 3 days ago.",
            "[made.up] The site steals bitcoin.",  # not a real finding -> dropped
            "No citation here",  # -> dropped
        ],
        recommendations=["Type paypal.com yourself."],
    )
    result = run(ex.explain(_report()))
    assert result.summary.startswith("This link is High Risk")
    assert len(result.key_points) == 2
    assert "High Risk" in fake_ai["user"] and "<untrusted_findings_" in fake_ai["user"]


@pytest.mark.parametrize(
    "summary", ["Good news, this website is safe.", "The site appears completely legitimate."]
)
def test_safety_claims_rejected(fake_ai, summary):
    fake_ai["answer"] = Explanation(summary=summary, key_points=["[url.typosquat] x"], recommendations=[])
    assert run(ex.explain(_report())).summary.startswith("This target shows")


def test_ai_failure_falls_back(fake_ai):
    fake_ai["answer"] = None
    assert run(ex.explain(_report())).summary.startswith("This target shows")


def test_ai_ignoring_evidence_falls_back(fake_ai):
    fake_ai["answer"] = Explanation(summary="Be careful.", key_points=["Random text"], recommendations=[])
    assert run(ex.explain(_report())).summary.startswith("This target shows")
