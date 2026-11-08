"""Investigation pipeline: runs analyzers in parallel and builds an AnalysisReport. Owner: P1.

Submit -> Investigate (analyzers) -> Assess risk (risk engine) -> Explain (AI) -> Correlate -> Save
"""
import asyncio
import logging
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from app import db
from app.ai.explain import explain
from app.analyzers import (
    dns_analyzer,
    headers_analyzer,
    message_analyzer,
    threat_intel,
    tls_analyzer,
    url_analyzer,
)
from app.analyzers.base import Analyzer, error_result
from app.analyzers.mock import mock_result
from app.config import settings
from app.correlation.engine import find_related, index_report
from app.risk.engine import NOT_PROOF_OF_SAFETY, classify, compute_coverage, recommendations_for
from app.schemas import AnalysisReport, CheckName, CheckResult

log = logging.getLogger(__name__)

URL_ANALYZERS: list[tuple[CheckName, Analyzer]] = [
    ("url", url_analyzer.analyze),
    ("dns", dns_analyzer.analyze),
    ("threat_intel", threat_intel.analyze),
    ("tls", tls_analyzer.analyze),
    ("headers", headers_analyzer.analyze),
]


class InvalidTarget(ValueError):
    pass


def normalize_target(raw: str) -> tuple[str, str]:
    """Return (input_type, normalized_url). Light normalisation only — P2's url_analyzer does the deep work."""
    text = raw.strip()
    if not text:
        raise InvalidTarget("Empty URL")
    if any(ch.isspace() for ch in text):
        raise InvalidTarget("URL must not contain spaces")
    has_scheme = "://" in text
    input_type = "url" if has_scheme else "domain"
    if not has_scheme:
        text = "https://" + text
    parts = urlsplit(text)
    if parts.scheme.lower() not in ("http", "https"):
        raise InvalidTarget("Only http and https URLs can be analysed")
    if not parts.hostname:
        raise InvalidTarget("URL has no hostname")
    if not has_scheme and (parts.path not in ("", "/") or parts.query):
        input_type = "url"
    netloc = parts.netloc.lower() if "@" not in parts.netloc else parts.netloc  # keep userinfo as-is for analysis
    normalized = urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, parts.fragment))
    return input_type, normalized


def _timeout_for(check: CheckName) -> float:
    # The message check may call the LLM, which is slower than a network check.
    # TLS also queries Certificate Transparency + OCSP, which can be slow.
    extra = {"message": settings.llm_timeout_seconds, "tls": 6.0}.get(check, 0.0)
    return settings.check_timeout_seconds + extra


async def _run_check(check: CheckName, analyze: Analyzer, target: str) -> CheckResult:
    start = time.perf_counter()
    timeout = _timeout_for(check)
    try:
        result = await asyncio.wait_for(analyze(target), timeout=timeout)
    except asyncio.TimeoutError:
        result = CheckResult(
            check=check, status="error",
            limitations=[f"{check} check timed out after {timeout:g}s"],
        )
    except Exception as exc:  # analyzers should never raise, but be safe
        result = error_result(check, exc)

    if settings.mock_analyzers and result.status == "skipped" and check != "message":
        result = mock_result(check, target)

    result.target = target
    result.duration_ms = int((time.perf_counter() - start) * 1000)
    return result


async def _run_url_checks(url: str) -> list[CheckResult]:
    return list(await asyncio.gather(*(_run_check(name, fn, url) for name, fn in URL_ANALYZERS)))


async def _finalize(
    *,
    input_type: str,
    raw_input: str,
    normalized_target: str | None,
    checks: list[CheckResult],
    extracted_indicators: dict[str, list[str]] | None = None,
    extra_limitations: list[str] | None = None,
) -> AnalysisReport:
    coverage = compute_coverage(checks)
    risk_level, risk_reasons = classify(checks, coverage)

    limitations: list[str] = []
    for c in checks:
        for lim in c.limitations:
            entry = f"[{c.check}] {lim}"
            if entry not in limitations:
                limitations.append(entry)
    limitations.extend(extra_limitations or [])
    limitations.append(NOT_PROOF_OF_SAFETY)

    report = AnalysisReport(
        id=str(uuid.uuid4()),
        input_type=input_type,
        input=raw_input,
        normalized_target=normalized_target,
        created_at=datetime.now(timezone.utc),
        risk_level=risk_level,
        risk_reasons=risk_reasons,
        coverage=coverage,
        checks=checks,
        extracted_indicators=extracted_indicators or {},
        recommendations=recommendations_for(risk_level, checks),
        limitations=limitations,
    )

    try:
        report.explanation = await asyncio.wait_for(explain(report), timeout=settings.llm_timeout_seconds + 2)
    except asyncio.TimeoutError:
        report.limitations.append("[ai] Explanation timed out")
    except Exception as exc:
        report.limitations.append(f"[ai] Explanation unavailable: {type(exc).__name__}")
    try:
        report.related_report_ids = find_related(report)
    except Exception as exc:
        report.limitations.append(f"[correlation] Correlation unavailable: {type(exc).__name__}")

    db.save_report(report)
    try:
        index_report(report)
    except Exception as exc:  # correlation must never break an analysis
        log.warning("Could not index report %s for correlation: %s", report.id, exc)
    return report


async def analyze_url(raw: str) -> AnalysisReport:
    input_type, url = normalize_target(raw)
    checks = await _run_url_checks(url)
    return await _finalize(input_type=input_type, raw_input=raw, normalized_target=url, checks=checks)


async def analyze_message(text: str) -> AnalysisReport:
    message_check = await _run_check("message", message_analyzer.analyze, text)
    message_check.target = "pasted message"  # don't repeat the whole message in every check
    indicators: dict[str, list[str]] = message_check.data.get("indicators") or {}

    urls: list[str] = []
    skipped_urls: list[str] = []
    for u in indicators.get("urls", []):
        try:
            _, normalized = normalize_target(u)
        except InvalidTarget:
            continue
        if normalized in urls:
            continue
        if len(urls) < settings.max_message_urls:
            urls.append(normalized)
        else:
            skipped_urls.append(normalized)

    url_check_groups = await asyncio.gather(*(_run_url_checks(u) for u in urls))
    checks = [message_check] + [c for group in url_check_groups for c in group]

    extra = []
    if skipped_urls:
        extra.append(f"[pipeline] Only the first {settings.max_message_urls} URLs were investigated; "
                     f"{len(skipped_urls)} more were not checked")

    return await _finalize(
        input_type="message",
        raw_input=text,
        normalized_target=None,
        checks=checks,
        extracted_indicators=indicators,
        extra_limitations=extra,
    )
