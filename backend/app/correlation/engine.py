"""Threat correlation across reports. Owner: P1. Guide: docs/tasks/P1-lead.md

Deterministic matching only (AGENTS.md Module 4): two reports are related when they share
- the same registrable domain (paypa1-login.com, even via different URLs/subdomains)
- the same TLS certificate (SHA-256 fingerprint)
- the same server IP (ignored when we've seen many domains on it: shared hosting/CDN)
- the same email, phone number or UPI payment id
- near-identical message text (similarity >= 0.8)
"""
import difflib
import ipaddress
import re
from urllib.parse import urlsplit

import tldextract

from app import db
from app.schemas import AnalysisReport, CorrelationResult, RelatedReport

_tld = tldextract.TLDExtract(suffix_list_urls=())  # bundled public-suffix list, no network


def registrable_domain(host: str) -> str:
    """'login.sbi-kyc.co.in' -> 'sbi-kyc.co.in'. Falls back to the host for unknown suffixes."""
    ext = _tld(host)
    value = getattr(ext, "top_domain_under_public_suffix", None)
    if value is None:  # older tldextract
        value = ext.registered_domain
    return value or host
TEXT_SIMILARITY = 0.8
SHARED_HOSTING_DOMAINS = 5  # an IP seen with more distinct domains than this is treated as shared
MAX_RELATED = 20

_KIND_LABEL = {
    "domain": "same domain",
    "cert": "same TLS certificate",
    "ip": "same server IP",
    "email": "same email address",
    "phone": "same phone number",
    "upi": "same UPI payment ID",
    "text": "near-identical message text",
}


def _registrable(host: str) -> tuple[str, str]:
    host = host.lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
        return "ip", host
    except ValueError:
        pass
    return "domain", registrable_domain(host)


def _host(url: str) -> str:
    if "://" not in url:
        url = "http://" + url
    try:
        return urlsplit(url).hostname or ""
    except ValueError:
        return ""


def extract_indicators(report: AnalysisReport) -> set[tuple[str, str]]:
    items: set[tuple[str, str]] = set()
    ind = report.extracted_indicators or {}

    urls = [report.normalized_target or ""] + list(ind.get("urls", [])) + list(ind.get("domains", []))
    urls += [c.target for c in report.checks if c.target and c.check != "message"]
    for u in urls:
        host = _host(u) if u else ""
        if host:
            items.add(_registrable(host))

    for email in ind.get("emails", []):
        items.add(("email", email.strip().lower()))
    for phone in ind.get("phones", []):
        digits = re.sub(r"\D", "", phone)
        if len(digits) >= 8:
            items.add(("phone", digits[-10:]))
    for upi in ind.get("upi_ids", []):
        items.add(("upi", upi.strip().lower()))

    for c in report.checks:
        if c.check == "tls" and c.data.get("sha256_fingerprint"):
            items.add(("cert", str(c.data["sha256_fingerprint"]).lower()))
        ips = []
        for key in ("ip", "resolved_ip"):
            if isinstance(c.data.get(key), str):
                ips.append(c.data[key])
        for key in ("a_records", "aaaa_records", "ips"):
            if isinstance(c.data.get(key), list):
                ips.extend(v for v in c.data[key] if isinstance(v, str))
        for ip in ips:
            try:
                items.add(("ip", str(ipaddress.ip_address(ip))))
            except ValueError:
                continue
    return items


def _normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()[:2000]


def _similar_messages(report: AnalysisReport) -> dict[str, float]:
    if report.input_type != "message":
        return {}
    mine = _normalize_text(report.input)
    out: dict[str, float] = {}
    for rid, text in db.recent_messages():
        if rid == report.id:
            continue
        m = difflib.SequenceMatcher(None, mine, _normalize_text(text), autojunk=False)
        if m.real_quick_ratio() >= TEXT_SIMILARITY and m.quick_ratio() >= TEXT_SIMILARITY and m.ratio() >= TEXT_SIMILARITY:
            out[rid] = round(m.ratio(), 2)
    return out


def _matches(report: AnalysisReport) -> dict[str, list[str]]:
    """{related_report_id: ["same domain: x.com", ...]}"""
    items = extract_indicators(report)
    shared_ips = {v for k, v in items if k == "ip" and db.domains_on_ip(v) >= SHARED_HOSTING_DOMAINS}
    items = {(k, v) for k, v in items if not (k == "ip" and v in shared_ips)}

    related: dict[str, list[str]] = {}
    for rid, pairs in db.reports_sharing(items, exclude_id=report.id).items():
        related[rid] = sorted(f"{_KIND_LABEL[k]}: {v}" for k, v in pairs)
    for rid, ratio in _similar_messages(report).items():
        related.setdefault(rid, []).append(f"{_KIND_LABEL['text']} ({ratio:.0%} similar)")
    return related


def index_report(report: AnalysisReport) -> None:
    """Called by the pipeline after a report is saved, so future reports can link to it."""
    db.save_indicators(report.id, extract_indicators(report))


def find_related(report: AnalysisReport) -> list[str]:
    """Called by the pipeline when a report is created. Strongest links first."""
    related = _matches(report)
    ranked = sorted(related.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    return [rid for rid, _ in ranked[:MAX_RELATED]]


def related_details(report: AnalysisReport) -> CorrelationResult:
    """Used by GET /api/correlations/{id}. Computed live, so it also shows reports submitted later."""
    related = _matches(report)
    ranked = sorted(related.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:MAX_RELATED]
    out = []
    for rid, shared in ranked:
        other = db.get_report(rid)
        label = None
        if other is not None:
            label = "Pasted message" if other.input_type == "message" else (other.normalized_target or other.input)
        out.append(RelatedReport(
            report_id=rid, shared_indicators=shared, label=label,
            risk_level=other.risk_level if other else None, created_at=other.created_at if other else None,
        ))
    return CorrelationResult(related=out)
