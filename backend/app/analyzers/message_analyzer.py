"""Scam / social-engineering message analysis.

Owner: P3. Guide: docs/tasks/P3-ai.md
STUB: returns status="skipped" until implemented. Keep the signature unchanged.

Contract with the pipeline: put extracted indicators in
    data["indicators"] = {"urls": [...], "domains": [...], "emails": [...], "phones": [...], "upi_ids": [...]}
The pipeline copies them into report.extracted_indicators and runs the URL checks
on the first few `urls` (settings.max_message_urls).

Run standalone:  python -m app.analyzers.message_analyzer "Your KYC expires today, click http://..."
"""
import re

from app.analyzers.base import error_result, run_cli
from app.schemas import CheckResult

# Placeholder extraction so the message -> URL pipeline works end to end. P3: replace/extend.
_URL_RE = re.compile(r"\b(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)


async def analyze(target: str) -> CheckResult:
    try:
        urls = [u.rstrip(".,;:!?)]}") for u in _URL_RE.findall(target)]
        # TODO(P3): rule-based patterns + LLM classification -> findings; full indicator extraction.
        return CheckResult(
            check="message",
            status="skipped",
            data={"indicators": {"urls": urls}},
            limitations=["Message analysis not implemented yet (only basic URL extraction)"],
        )
    except Exception as exc:  # never raise
        return error_result("message", exc)


if __name__ == "__main__":
    run_cli(analyze)
