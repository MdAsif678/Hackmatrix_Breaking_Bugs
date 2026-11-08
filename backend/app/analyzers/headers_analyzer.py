"""Passive security-header checks: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, HTTP->HTTPS, mixed content.

Owner: P2. Guide: docs/tasks/P2-security.md
STUB: returns status="skipped" until implemented. Keep the signature unchanged.

Run standalone:  python -m app.analyzers.headers_analyzer <target>
"""
from app.analyzers.base import error_result, run_cli, skipped
from app.schemas import CheckResult


async def analyze(target: str) -> CheckResult:
    try:
        # TODO(P2): implement. Return CheckResult(check="headers", status="ok", findings=[...], data={...})
        return skipped("headers")
    except Exception as exc:  # never raise
        return error_result("headers", exc)


if __name__ == "__main__":
    run_cli(analyze)
