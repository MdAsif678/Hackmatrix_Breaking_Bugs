from app.risk.engine import classify, compute_coverage
from app.schemas import CheckResult, Finding, RiskLevel, Severity


def _check(status="ok", *findings: Finding) -> CheckResult:
    return CheckResult(check="url", status=status, findings=list(findings))


def _f(sev: Severity, authoritative=False, fid="x") -> Finding:
    return Finding(id=fid, check="url", title="t", severity=sev, evidence="e", source="s",
                   authoritative=authoritative)


def test_authoritative_match_is_confirmed_malicious():
    checks = [_check("ok", _f(Severity.high, authoritative=True))]
    assert classify(checks, compute_coverage(checks))[0] == RiskLevel.confirmed_malicious


def test_low_coverage_without_high_findings_is_inconclusive():
    checks = [_check("ok"), _check("error"), _check("skipped")]
    assert classify(checks, compute_coverage(checks))[0] == RiskLevel.inconclusive


def test_two_highs_is_high_risk():
    checks = [_check("ok", _f(Severity.high, fid="a"), _f(Severity.high, fid="b"))]
    assert classify(checks, 1.0)[0] == RiskLevel.high_risk


def test_one_critical_is_high_risk():
    assert classify([_check("ok", _f(Severity.critical))], 1.0)[0] == RiskLevel.high_risk


def test_one_high_is_suspicious():
    assert classify([_check("ok", _f(Severity.high))], 1.0)[0] == RiskLevel.suspicious


def test_two_mediums_is_suspicious():
    checks = [_check("ok", _f(Severity.medium, fid="a"), _f(Severity.medium, fid="b"))]
    assert classify(checks, 1.0)[0] == RiskLevel.suspicious


def test_clean_is_low_risk():
    assert classify([_check("ok", _f(Severity.low))], 1.0)[0] == RiskLevel.low_risk
