"""Helpers shared by all analyzers. Owner: P1.

Every analyzer module exposes:

    async def analyze(target: str) -> CheckResult

URL analyzers (url, dns, threat_intel, tls, headers) receive a normalized absolute URL,
e.g. "https://example.com/login". Extract the host yourself (urllib.parse.urlsplit).
The message analyzer receives the raw pasted text.

Rules: never raise (return status="error"), stay within the timeout, raw facts -> `data`,
judgements -> `findings`.
"""
import asyncio
import sys
from typing import Awaitable, Callable

from app.schemas import CheckName, CheckResult

Analyzer = Callable[[str], Awaitable[CheckResult]]


def skipped(check: CheckName, reason: str = "Check not implemented yet") -> CheckResult:
    return CheckResult(check=check, status="skipped", limitations=[reason])


def error_result(check: CheckName, exc: BaseException) -> CheckResult:
    return CheckResult(
        check=check,
        status="error",
        limitations=[f"{check} check failed: {type(exc).__name__}: {exc}"],
    )


def run_cli(analyze: Analyzer) -> None:
    """Lets every analyzer run standalone:

    python -m app.analyzers.tls_analyzer https://example.com
    """
    if len(sys.argv) < 2:
        print(f"usage: python -m {analyze.__module__} <target>")
        raise SystemExit(1)
    target = " ".join(sys.argv[1:])
    result = asyncio.run(analyze(target))
    print(result.model_dump_json(indent=2))
