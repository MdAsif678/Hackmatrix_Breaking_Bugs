"""Evidence-grounded explanation of a report. Owner: P1. Guide: docs/tasks/P1-lead.md

The explanation may only use facts present in report.checks[*].findings and must never
change report.risk_level. The rule-based fallback below is used when the LLM is
unavailable or returns invalid output — keep it working.
"""
from typing import Optional

from app.schemas import AnalysisReport, Explanation, RiskLevel, Severity

_LEVEL_TEXT = {
    RiskLevel.confirmed_malicious: "matches trusted threat intelligence and is known to be malicious",
    RiskLevel.high_risk: "shows multiple significant warning signs",
    RiskLevel.suspicious: "shows warning signs that need further investigation",
    RiskLevel.inconclusive: "could not be assessed reliably because too few checks completed",
    RiskLevel.low_risk: "showed no significant malicious indicators in the available checks",
}

_SEVERITY_ORDER = [Severity.critical, Severity.high, Severity.medium, Severity.low, Severity.info]


def fallback_explanation(report: AnalysisReport) -> Explanation:
    findings = [f for c in report.checks for f in c.findings]
    findings.sort(key=lambda f: _SEVERITY_ORDER.index(f.severity))
    key_points = [f"[{f.id}] {f.title} — {f.evidence}" for f in findings[:6]]
    return Explanation(
        summary=f"This target {_LEVEL_TEXT[report.risk_level]}.",
        key_points=key_points or ["No notable findings."],
        recommendations=report.recommendations[:3],
    )


async def explain(report: AnalysisReport) -> Optional[Explanation]:
    # TODO(P1): build a prompt from the findings only, call ai.llm.llm_json(..., Explanation),
    # check every key point cites a real finding id, else fall back.
    return fallback_explanation(report)
