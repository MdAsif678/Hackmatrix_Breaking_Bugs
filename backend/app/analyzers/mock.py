"""FAKE sample results for analyzers that are not implemented yet. Owner: P1.

Only used when MOCK_ANALYZERS=true in .env. Lets us build the UI, risk engine and
on-chain flow before the real checks exist. Never enable this for the final demo.
"""
from urllib.parse import urlsplit

from app.schemas import CheckName, CheckResult, Finding, Severity

_MOCK_NOTE = "MOCK DATA — fake result, real check not implemented yet"
_SUSPICIOUS_WORDS = ("login", "verify", "secure", "account", "kyc", "update", "paypa1", "bank")


def _looks_bad(target: str) -> bool:
    t = target.lower()
    return any(w in t for w in _SUSPICIOUS_WORDS)


def mock_result(check: CheckName, target: str) -> CheckResult:
    host = urlsplit(target).hostname or target
    bad = _looks_bad(target)
    findings: list[Finding] = []
    data: dict = {"mock": True}

    if check == "url":
        data["host"] = host
        if bad:
            findings.append(Finding(
                id="url.brand_keyword", check="url", title="Brand or credential keyword in URL",
                severity=Severity.medium, evidence=f"host={host}", source="mock",
                impact="Common in phishing URLs that imitate login pages.",
                recommendation="Type the official website address yourself instead of clicking links.",
            ))
    elif check == "dns":
        data["a_records"] = ["203.0.113.10"]
        if bad:
            findings.append(Finding(
                id="dns.new_domain", check="dns", title="Recently registered domain",
                severity=Severity.high, evidence="created 6 days ago", source="mock",
                impact="Phishing domains are usually very new.",
            ))
    elif check == "tls":
        data["issuer"] = "CN=Mock CA"
        data["not_after"] = "2027-01-01T00:00:00Z"
        findings.append(Finding(
            id="tls.valid_cert", check="tls", title="Valid certificate (not proof of safety)",
            severity=Severity.info, evidence="chain verified", source="mock",
        ))
    elif check == "headers":
        findings.append(Finding(
            id="headers.missing_csp", check="headers", title="Missing Content-Security-Policy",
            severity=Severity.low, evidence="no CSP header", source="mock",
            recommendation="Site owner should add a Content-Security-Policy header.",
        ))
    elif check == "threat_intel":
        data["sources_checked"] = ["mock-feed"]
    elif check == "message":
        data["indicators"] = {}

    return CheckResult(check=check, status="ok", findings=findings, data=data, limitations=[_MOCK_NOTE])
