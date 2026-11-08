"""DNS records (A/AAAA/MX/NS) and domain age via WHOIS/RDAP.

Owner: P2. Guide: docs/tasks/P2-security.md
STUB: returns status="skipped" until implemented. Keep the signature unchanged.

Run standalone:  python -m app.analyzers.dns_analyzer <target>
"""
from app.analyzers.base import error_result, run_cli, skipped
from app.schemas import CheckResult


async def analyze(target: str) -> CheckResult:
    try:
        # TODO(P2): implement. Return CheckResult(check="dns", status="ok", findings=[...], data={...})
        return skipped("dns")
    except Exception as exc:  # never raise
        return error_result("dns", exc)


if __name__ == "__main__":
    run_cli(analyze)
