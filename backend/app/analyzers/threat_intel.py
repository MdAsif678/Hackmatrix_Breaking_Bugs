"""Threat-intel lookups: URLhaus, OpenPhish, Google Safe Browsing, PhishTank. Set authoritative=True on a match.

Owner: P2. See AGENTS.md §11 for the full task list.
STUB: returns status="skipped" until implemented. Keep the signature unchanged.

Run standalone:  python -m app.analyzers.threat_intel <target>
"""
from app.analyzers.base import error_result, run_cli, skipped
from app.schemas import CheckResult


async def analyze(target: str) -> CheckResult:
    try:
        # TODO(P2): implement. Return CheckResult(check="threat_intel", status="ok", findings=[...], data={...})
        return skipped("threat_intel")
    except Exception as exc:  # never raise
        return error_result("threat_intel", exc)


if __name__ == "__main__":
    run_cli(analyze)
