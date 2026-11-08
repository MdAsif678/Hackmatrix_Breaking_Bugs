"""Deterministic risk classification — AGENTS.md §6. Owner: P1.

The LLM never decides the risk level; it only explains it.
"""
from app.schemas import CheckResult, RiskLevel, Severity

NOT_PROOF_OF_SAFETY = "No known threats found does not prove the site is safe."

_LEVEL_RECOMMENDATIONS: dict[RiskLevel, list[str]] = {
    RiskLevel.confirmed_malicious: [
        "Do not open this link or enter any information on it.",
        "If you already entered passwords or payment details, change them and contact your bank immediately.",
        "Report it to cybercrime.gov.in (India) or your local authority.",
    ],
    RiskLevel.high_risk: [
        "Do not enter passwords, OTPs or payment details.",
        "Reach the organisation through its official website or app instead of this link.",
    ],
    RiskLevel.suspicious: [
        "Be careful: verify the sender and website through an official channel before acting.",
        "Never share OTPs, passwords or card details in response to a message.",
    ],
    RiskLevel.inconclusive: [
        "Not enough checks completed to assess this target. Treat it with caution.",
    ],
    RiskLevel.low_risk: [
        "No significant indicators found in the available checks, but stay alert for unusual requests.",
    ],
}


def compute_coverage(checks: list[CheckResult]) -> float:
    if not checks:
        return 0.0
    return round(sum(c.status == "ok" for c in checks) / len(checks), 2)


def classify(checks: list[CheckResult], coverage: float) -> tuple[RiskLevel, list[str]]:
    findings = [f for c in checks for f in c.findings]
    authoritative = [f for f in findings if f.authoritative]
    critical = [f for f in findings if f.severity == Severity.critical]
    high = [f for f in findings if f.severity == Severity.high]
    medium = [f for f in findings if f.severity == Severity.medium]

    def ids(fs) -> str:
        return ", ".join(f.id for f in fs)

    if authoritative:
        return RiskLevel.confirmed_malicious, [f"Matched trusted threat intelligence: {ids(authoritative)}"]
    if coverage < 0.5 and not (critical or high):
        return RiskLevel.inconclusive, [f"Only {coverage:.0%} of checks completed and no high-severity findings"]
    if critical:
        return RiskLevel.high_risk, [f"Critical finding(s): {ids(critical)}"]
    if len(high) >= 2:
        return RiskLevel.high_risk, [f"Multiple high-severity findings: {ids(high)}"]
    if high:
        return RiskLevel.suspicious, [f"High-severity finding: {ids(high)}"]
    if len(medium) >= 2:
        return RiskLevel.suspicious, [f"Multiple medium-severity findings: {ids(medium)}"]
    return RiskLevel.low_risk, ["No significant malicious indicators within the available checks"]


def recommendations_for(level: RiskLevel, checks: list[CheckResult]) -> list[str]:
    recs = list(_LEVEL_RECOMMENDATIONS[level])
    for c in checks:
        for f in c.findings:
            if f.recommendation and f.recommendation not in recs:
                recs.append(f.recommendation)
    return recs
