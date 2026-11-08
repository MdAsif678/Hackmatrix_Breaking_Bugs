"""URL normalisation, lexical phishing indicators (typosquatting, homoglyphs, IP hosts, shorteners...) and redirect chain.

Owner: P2. Guide: docs/tasks/P2-security.md
"""
import ipaddress
import json
import re
import unicodedata
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qsl, urlsplit

import idna
import tldextract

from app.analyzers.base import error_result, run_cli
from app.config import DATA_DIR
from app.schemas import CheckResult, Finding, Severity

# Commonly abused shorteners
SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "cutt.ly",
    "rb.gy",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "goo.gl",
    "rebrand.ly",
    "bl.ink",
    "shorturl.at",
    "t.ly",
    "s.id",
    "soo.gd",
    "trib.al",
}

# TLDs frequently abused in disposable phishing campaigns
SUSPICIOUS_TLDS = {
    "zip",
    "top",
    "xyz",
    "click",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "cyou",
    "rest",
    "buzz",
    "work",
    "loan",
    "cam",
    "fit",
    "surf",
}

# Open redirect query parameters
REDIRECT_PARAMS = {
    "url",
    "redirect",
    "next",
    "dest",
    "destination",
    "target",
    "r",
    "return",
    "return_url",
    "redir",
    "goto",
    "link",
    "out",
}

# High-risk path keywords targeted by credential stealers
CREDENTIAL_KEYWORDS = {
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "update",
    "secure",
    "account",
    "kyc",
    "password",
    "banking",
    "authenticate",
    "auth",
    "wallet",
}


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def _detect_unicode_scripts(text: str) -> set[str]:
    """Detect distinct alphabetic scripts present in the text."""
    scripts = set()
    for char in text:
        if not char.isalpha():
            continue
        try:
            name = unicodedata.name(char)
            if "LATIN" in name:
                scripts.add("LATIN")
            elif "CYRILLIC" in name:
                scripts.add("CYRILLIC")
            elif "GREEK" in name:
                scripts.add("GREEK")
            elif "ARABIC" in name:
                scripts.add("ARABIC")
            elif "HEBREW" in name:
                scripts.add("HEBREW")
            elif any(k in name for k in ("CJK", "HIRAGANA", "KATAKANA", "HANGUL")):
                scripts.add("CJK")
            else:
                scripts.add(name.split()[0])
        except ValueError:
            pass
    return scripts


def _load_brands() -> list[dict[str, Any]]:
    brands_file = DATA_DIR / "brands.json"
    if not brands_file.exists():
        return []
    try:
        with open(brands_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


async def analyze(target: str) -> CheckResult:
    """Analyze URL text for phishing indicators, lookalikes, homoglyphs, and open redirects."""
    try:
        findings: list[Finding] = []
        limitations: list[str] = []

        parts = urlsplit(target)
        scheme = (parts.scheme or "").lower()
        netloc = parts.netloc or ""
        host = (parts.hostname or "").lower()
        path = parts.path or ""
        query = parts.query or ""

        # Extract domain components
        ext = tldextract.extract(host)
        subdomain = ext.subdomain.lower() if ext.subdomain else ""
        domain = ext.domain.lower() if ext.domain else ""
        suffix = ext.suffix.lower() if ext.suffix else ""
        registered = f"{domain}.{suffix}" if suffix else domain

        # Check for IP address host
        is_ip = False
        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            pass

        if is_ip:
            findings.append(
                Finding(
                    id="url.ip_host",
                    check="url",
                    title="Host is a raw IP address",
                    severity=Severity.high,
                    evidence=f"Host '{host}' is an IP address instead of a domain name.",
                    source="lexical analysis",
                    impact="Phishing attacks frequently use raw IP addresses to bypass domain-based reputation filters.",
                    recommendation="Legitimate services rarely use raw IP addresses in consumer-facing URLs. Do not enter credentials.",
                )
            )

        # Check for @ in authority / URL
        if "@" in netloc:
            findings.append(
                Finding(
                    id="url.at_symbol",
                    check="url",
                    title="URL contains '@' userinfo separator",
                    severity=Severity.high,
                    evidence=f"URL contains '@' in authority component '{netloc}'. Browsers navigate to the domain after '@', treating earlier text as userinfo.",
                    source="lexical analysis",
                    impact="Attackers use '@' to trick users into believing they are visiting the domain before the '@' symbol.",
                    recommendation="Be aware the real destination is the domain following '@', not what precedes it.",
                )
            )

        # Check for Punycode
        has_punycode = "xn--" in host
        decoded_host = host
        try:
            decoded_host = idna.decode(host)
        except Exception:
            pass

        if has_punycode:
            findings.append(
                Finding(
                    id="url.punycode",
                    check="url",
                    title="Host uses Punycode (internationalized domain)",
                    severity=Severity.medium,
                    evidence=f"Host '{host}' uses Punycode encoding ('xn--'), decoding to '{decoded_host}'.",
                    source="lexical analysis",
                    impact="Punycode is frequently used in IDN homograph attacks where lookalike characters impersonate legitimate brands.",
                    recommendation="Verify the true decoded Unicode characters before trusting this domain.",
                )
            )

        # Check for mixed-script homoglyphs
        scripts = _detect_unicode_scripts(decoded_host)
        if len(scripts) > 1 and "LATIN" in scripts:
            other_scripts = sorted(s for s in scripts if s != "LATIN")
            findings.append(
                Finding(
                    id="url.mixed_script",
                    check="url",
                    title="Host mixes multiple alphabets (homoglyph attack)",
                    severity=Severity.high,
                    evidence=f"Decoded host '{decoded_host}' mixes Latin with {', '.join(other_scripts)}, a common homograph technique.",
                    source="lexical analysis",
                    impact="Users see familiar Latin characters while the browser resolves an entirely different internationalized domain.",
                    recommendation="Do not enter passwords or sensitive information on homoglyph domains.",
                )
            )

        # Typosquatting and Brand Spoofing checks
        brands = _load_brands()
        host_tokens = set(re.split(r"[-._]", host))
        domain_tokens = set(re.split(r"[-_]", domain))

        typosquat_found = False
        brand_subdomain_found = False

        for brand in brands:
            brand_name = brand.get("name", "Unknown Brand")
            official_domains = [d.lower() for d in brand.get("official_domains", [])]
            keywords = [k.lower() for k in brand.get("keywords", [])]

            # If this is legitimately the brand's official domain, skip brand attacks
            if registered in official_domains:
                continue

            # 1. Typosquatting check (edit distance 1-2 on domain name, min length 5)
            if not typosquat_found and domain:
                for off_dom in official_domains:
                    off_ext = tldextract.extract(off_dom)
                    off_domain = off_ext.domain.lower()
                    if len(off_domain) < 5:
                        continue

                    # Check overall domain and domain tokens
                    candidates = [domain] + list(domain_tokens)
                    for cand in candidates:
                        if len(cand) >= 5 and cand != off_domain:
                            dist = _levenshtein_distance(cand, off_domain)
                            if 1 <= dist <= 2:
                                findings.append(
                                    Finding(
                                        id="url.typosquat",
                                        check="url",
                                        title=f"Domain imitates {off_dom}",
                                        severity=Severity.high,
                                        evidence=f"Domain label '{cand}' is {dist} character(s) away from official brand domain '{off_dom}'.",
                                        source="lexical analysis",
                                        impact=f"Users may believe they are visiting the legitimate {brand_name} service.",
                                        recommendation=f"Type {off_dom} yourself instead of clicking the link.",
                                    )
                                )
                                typosquat_found = True
                                break
                    if typosquat_found:
                        break

            # 2. Brand in host/subdomain check
            if not brand_subdomain_found:
                for kw in keywords:
                    if kw in host_tokens or (subdomain and kw in subdomain.split(".")):
                        # Make sure kw isn't just matching legitimate domain part
                        findings.append(
                            Finding(
                                id="url.brand_in_subdomain",
                                check="url",
                                title=f"Brand '{brand_name}' keyword in unauthorized domain",
                                severity=Severity.high,
                                evidence=f"Host '{host}' contains brand keyword '{kw}', but registered domain '{registered}' is not in official domains for {brand_name} ({', '.join(official_domains)}).",
                                source="lexical analysis",
                                impact=f"Attackers prepend trusted brand names like '{kw}' to deceive victims.",
                                recommendation=f"Verify official domain is {', '.join(official_domains)}.",
                            )
                        )
                        brand_subdomain_found = True
                        break

        # Check for link shorteners
        if registered in SHORTENERS or host in SHORTENERS:
            findings.append(
                Finding(
                    id="url.shortener",
                    check="url",
                    title="URL uses a link shortening service",
                    severity=Severity.medium,
                    evidence=f"Host '{host}' is a known link shortener, obscuring the destination URL.",
                    source="lexical analysis",
                    impact="Shortened URLs obscure destination domains and bypass basic reputation filtering.",
                    recommendation="Expand the shortened URL with an unshortening service before visiting.",
                )
            )

        # Check for open redirect parameters
        if query:
            qsl = parse_qsl(query, keep_blank_values=True)
            for param_name, param_value in qsl:
                if param_name.lower() in REDIRECT_PARAMS and param_value.lower().startswith(("http://", "https://")):
                    findings.append(
                        Finding(
                            id="url.redirect_param",
                            check="url",
                            title="URL contains open redirect parameter",
                            severity=Severity.medium,
                            evidence=f"Query parameter '{param_name}' points to external URL: '{param_value[:80]}'.",
                            source="lexical analysis",
                            impact="Open redirect parameters can bounce users from a trusted domain to a malicious site.",
                            recommendation="Inspect the final destination URL before following redirects.",
                        )
                    )
                    break

        # Check for suspicious TLD
        if suffix in SUSPICIOUS_TLDS:
            findings.append(
                Finding(
                    id="url.suspicious_tld",
                    check="url",
                    title=f"Suspicious or frequently abused TLD (.{suffix})",
                    severity=Severity.low,
                    evidence=f"TLD '.{suffix}' is frequently associated with disposable, low-cost phishing infrastructure.",
                    source="lexical analysis",
                    impact="While not inherently malicious, domains on this TLD carry elevated statistical correlation with abusive campaigns.",
                    recommendation="Scrutinize the site carefully, especially if prompted for credentials or downloads.",
                )
            )

        # Check for excessive subdomain levels
        if subdomain:
            subdomain_parts = [p for p in subdomain.split(".") if p]
            if len(subdomain_parts) > 3:
                findings.append(
                    Finding(
                        id="url.many_subdomains",
                        check="url",
                        title="Excessive subdomain levels",
                        severity=Severity.low,
                        evidence=f"Host has {len(subdomain_parts)} subdomain levels: '{subdomain}'.",
                        source="lexical analysis",
                        impact="Excessive subdomain nesting is often used to mimic legitimate domains and evade detection.",
                        recommendation="Check the root registered domain rather than relying on visible subdomain prefixes.",
                    )
                )

        # Check for long URL
        if len(target) > 100:
            findings.append(
                Finding(
                    id="url.long_url",
                    check="url",
                    title="Unusually long URL",
                    severity=Severity.low,
                    evidence=f"URL length is {len(target)} characters (threshold: 100).",
                    source="lexical analysis",
                    impact="Phishing kits often use long URLs to hide suspicious domains off-screen on mobile devices.",
                    recommendation="Examine the full domain and path before interacting.",
                )
            )

        # Check for unencrypted HTTP
        if scheme == "http":
            findings.append(
                Finding(
                    id="url.no_https",
                    check="url",
                    title="Insecure HTTP protocol",
                    severity=Severity.low,
                    evidence="URL uses unencrypted 'http://' rather than secure 'https://'.",
                    source="lexical analysis",
                    impact="Traffic is transmitted in plain text, making it vulnerable to interception and tampering.",
                    recommendation="Avoid entering credentials or sensitive data over plain HTTP.",
                )
            )

        # Check for sensitive credential keywords in path
        if path:
            path_tokens = set(re.split(r"[/._-]", path.lower()))
            matched_words = sorted(path_tokens.intersection(CREDENTIAL_KEYWORDS))
            if matched_words:
                findings.append(
                    Finding(
                        id="url.credential_words",
                        check="url",
                        title="Sensitive credential keywords in URL path",
                        severity=Severity.low,
                        evidence=f"Path '{path}' contains sensitive authentication keywords: {', '.join(matched_words)}.",
                        source="lexical analysis",
                        impact="Phishing URLs frequently target logins, account verification, and KYC updates.",
                        recommendation="Ensure the domain is genuinely authentic before entering any login or security credentials.",
                    )
                )

        # Optional redirect chain check (when safe_fetch becomes available)
        data: dict[str, Any] = {
            "host": host,
            "registered_domain": registered,
            "subdomain": subdomain,
            "tld": suffix,
            "is_ip": is_ip,
            "decoded_host": decoded_host,
        }

        try:
            from app.core.safe_fetch import safe_fetch
            resp = await safe_fetch(target)
            if resp.redirect_chain:
                data["redirect_chain"] = resp.redirect_chain
                final_ext = tldextract.extract((urlsplit(resp.final_url).hostname or "").lower())
                final_reg = f"{final_ext.domain}.{final_ext.suffix}" if final_ext.suffix else final_ext.domain
                if final_reg and registered and final_reg.lower() != registered.lower():
                    findings.append(
                        Finding(
                            id="url.cross_domain_redirect",
                            check="url",
                            title="Cross-domain redirect detected",
                            severity=Severity.medium,
                            evidence=f"Starting domain '{registered}' redirects across domains to '{final_reg}' ({resp.final_url}).",
                            source="HTTP redirects",
                            impact="Users may start on one domain and be transparently forwarded to a different entity.",
                            recommendation="Confirm that the redirection destination is trustworthy.",
                        )
                    )
        except (NotImplementedError, Exception):
            pass

        return CheckResult(
            check="url",
            status="ok",
            findings=findings,
            data=data,
            limitations=limitations,
        )
    except Exception as exc:
        return error_result("url", exc)


if __name__ == "__main__":
    run_cli(analyze)
