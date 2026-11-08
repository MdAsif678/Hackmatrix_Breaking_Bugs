"""DNS records (A/AAAA/MX/NS) and domain age via RDAP.

Owner: P2. Guide: docs/tasks/P2-security.md
"""
import asyncio
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx
import tldextract

from app.analyzers.base import error_result, run_cli
from app.schemas import CheckResult, Finding, Severity


def _extract_registrar(rdap_json: dict[str, Any]) -> str | None:
    """Extract registrar name from RDAP entities if available."""
    entities = rdap_json.get("entities", [])
    for entity in entities:
        roles = entity.get("roles", [])
        if "registrar" in roles:
            vcard = entity.get("vcardArray")
            if vcard and len(vcard) > 1:
                for prop in vcard[1]:
                    if prop[0] == "fn" and len(prop) > 3:
                        return str(prop[3])
            if entity.get("handle"):
                return str(entity.get("handle"))
    return None


async def _resolve_record_type(resolver: dns.asyncresolver.Resolver, name: str, rtype: str) -> list[str]:
    try:
        answers = await resolver.resolve(name, rtype)
        results = []
        for rdata in answers:
            if rtype == "MX":
                results.append(f"{rdata.preference} {rdata.exchange.to_text().rstrip('.')}")
            elif rtype == "NS":
                results.append(rdata.target.to_text().rstrip("."))
            else:
                results.append(rdata.to_text())
        return results
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except Exception:
        return []


async def _fetch_rdap(registered_domain: str) -> tuple[dict[str, Any] | None, int | None, str | None]:
    if not registered_domain:
        return None, None, "Domain age unavailable: could not extract registered domain."
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            rdap_url = f"https://rdap.org/domain/{registered_domain}"
            resp = await client.get(rdap_url, follow_redirects=True)
            if resp.status_code == 200:
                return resp.json(), resp.status_code, None
            else:
                return None, resp.status_code, f"Domain age unavailable: RDAP returned status code {resp.status_code}."
    except Exception as exc:
        return None, None, f"Domain age unavailable: RDAP query failed ({type(exc).__name__})."


async def analyze(target: str) -> CheckResult:
    """Resolve DNS records (A, AAAA, MX, NS) and query RDAP for domain age concurrently."""
    try:
        findings: list[Finding] = []
        limitations: list[str] = []

        raw_target = target.strip()
        if "//" not in raw_target:
            raw_target = "https://" + raw_target

        parts = urlsplit(raw_target)
        host = (parts.hostname or "").lower()

        ext = tldextract.extract(host)
        registered_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

        if not host:
            return CheckResult(
                check="dns",
                status="error",
                limitations=["No valid hostname found in target."],
            )

        query_domain = registered_domain or host

        # Configure resolver
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 4.0
        resolver.timeout = 3.0

        # Run DNS resolutions and RDAP query concurrently
        a_task = _resolve_record_type(resolver, host, "A")
        aaaa_task = _resolve_record_type(resolver, host, "AAAA")
        mx_task = _resolve_record_type(resolver, query_domain, "MX")
        ns_task = _resolve_record_type(resolver, query_domain, "NS")
        rdap_task = _fetch_rdap(registered_domain)

        a_records, aaaa_records, mx_records, ns_records, rdap_res = await asyncio.gather(
            a_task, aaaa_task, mx_task, ns_task, rdap_task
        )

        # Fallback A/AAAA lookup on registered_domain if host had none and host differs
        if not a_records and not aaaa_records and registered_domain and registered_domain != host:
            a_fallback, aaaa_fallback = await asyncio.gather(
                _resolve_record_type(resolver, registered_domain, "A"),
                _resolve_record_type(resolver, registered_domain, "AAAA"),
            )
            a_records = a_fallback
            aaaa_records = aaaa_fallback

        # Check resolution
        if not a_records and not aaaa_records:
            findings.append(
                Finding(
                    id="dns.no_resolution",
                    check="dns",
                    title="Domain has no A or AAAA records",
                    severity=Severity.medium,
                    evidence=f"No IPv4 (A) or IPv6 (AAAA) records resolved for '{host}' or '{query_domain}'.",
                    source="dnspython",
                    impact="The domain cannot be contacted via standard HTTP; it may be non-existent, abandoned, or parked.",
                    recommendation="Verify the domain name spelling or wait if DNS changes are propagating.",
                )
            )

        # Process RDAP response
        rdap_data, status_code, rdap_err = rdap_res
        created_str: str | None = None
        age_days: int | None = None
        registrar: str | None = None

        if rdap_err:
            limitations.append(rdap_err)
        elif rdap_data:
            events = rdap_data.get("events", [])
            for event in events:
                action = event.get("eventAction", "").lower()
                if action in ("registration", "created"):
                    created_str = event.get("eventDate")
                    break

            registrar = _extract_registrar(rdap_data)

            if created_str:
                try:
                    clean_dt_str = created_str.replace("Z", "+00:00")
                    created_dt = datetime.fromisoformat(clean_dt_str)
                    now = datetime.now(timezone.utc)
                    age_days = (now - created_dt).days

                    if age_days < 30:
                        findings.append(
                            Finding(
                                id="dns.new_domain",
                                check="dns",
                                title="Domain registered very recently (< 30 days)",
                                severity=Severity.high,
                                evidence=f"Domain '{registered_domain}' is {age_days} days old (registered {created_str}).",
                                source="RDAP",
                                impact="Phishing and scam operations frequently rely on fresh, disposable domains.",
                                recommendation="Exercise elevated caution with new domains before trusting them.",
                            )
                        )
                    elif age_days < 180:
                        findings.append(
                            Finding(
                                id="dns.young_domain",
                                check="dns",
                                title="Domain is relatively young (< 6 months)",
                                severity=Severity.medium,
                                evidence=f"Domain '{registered_domain}' is {age_days} days old (registered {created_str}).",
                                source="RDAP",
                                impact="Young domains have limited established operational history.",
                                recommendation="Confirm the authenticity of the organization through alternate channels.",
                            )
                        )
                except Exception:
                    limitations.append("Could not parse RDAP registration timestamp.")
            else:
                limitations.append("Domain age unavailable: registration event not present in RDAP response.")

        data: dict[str, Any] = {
            "host": host,
            "registered_domain": registered_domain,
            "dns_records": {
                "A": a_records,
                "AAAA": aaaa_records,
                "MX": mx_records,
                "NS": ns_records,
            },
            "created": created_str,
            "age_days": age_days,
            "registrar": registrar,
        }

        return CheckResult(
            check="dns",
            status="ok",
            findings=findings,
            data=data,
            limitations=limitations,
        )
    except Exception as exc:
        return error_result("dns", exc)


if __name__ == "__main__":
    run_cli(analyze)
