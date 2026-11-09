"""Scam / social-engineering message analysis.

Owner: P3. Guide: docs/tasks/P3-ai.md

Extracts indicators (urls, domains, emails, phones, upi_ids, amounts),
runs scam-pattern detection rules, and consults an LLM (Gemini via llm.py)
for deep tactical analysis with quote verification.
"""
import json
import logging
import re
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

from pydantic import BaseModel

from app.ai.llm import llm_json, mask_pii, untrusted_block
from app.analyzers.base import error_result, run_cli
from app.config import DATA_DIR
from app.schemas import CheckResult, Finding, Severity

log = logging.getLogger(__name__)

# --- Regex Patterns for Indicators ---
_URL_RE = re.compile(
    r"\b(?:https?://|www\.)[^\s<>\"']+"
    r"|\b[a-zA-Z0-9.-]+\.(?:com|org|net|in|co\.in|gov\.in|edu|xyz|top|site|online|live|link|info|biz|cc|pages\.dev|ru|cn|ly|io|me|co|is|gd|to|app|dev|ai)(?:/[^\s<>\"']*)?",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
# UPI IDs: something@handle where the handle has NO dot (e.g. user@ybl, refund@oksbi, 9876543210@paytm)
_UPI_RE = re.compile(r"\b[A-Za-z0-9._-]+@([A-Za-z]{2,}|[0-9]{2,})\b(?!\.[A-Za-z])")
# Indian mobile numbers and toll-free numbers
_PHONE_RE = re.compile(
    r"(?:(?:\+91|91|0)[-.\s]?)?[6-9]\d{4}[-.\s]?\d{5}\b|1800[-.\s]?\d{3}[-.\s]?\d{3,4}\b"
)
_AMOUNT_RE = re.compile(r"(?:₹|Rs\.?|INR)\s?[\d,]+(?:\.\d{1,2})?", re.IGNORECASE)

# Shortener domains
_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "cutt.ly",
    "rb.gy",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "rebrand.ly",
    "bl.ink",
    "shorturl.at",
    "t.ly",
    "s.id",
    "soo.gd",
}


def extract_indicators(text: str) -> dict[str, list[str]]:
    """Extract URLs, domains, emails, phones, UPI IDs, and amounts from text."""
    # 1. Emails
    emails: list[str] = []
    email_domains = set()
    for em in _EMAIL_RE.findall(text):
        em_clean = em.strip(".,;:!?)]}\"'")
        if em_clean.lower() not in [e.lower() for e in emails]:
            emails.append(em_clean)
            if "@" in em_clean:
                email_domains.add(em_clean.split("@")[-1].lower())

    # 2. UPI IDs (must not be inside extracted emails)
    email_set = {e.lower() for e in emails}
    upi_ids: list[str] = []
    for match in _UPI_RE.finditer(text):
        full_match = match.group(0).strip(".,;:!?)]}\"'")
        if full_match.lower() not in email_set and full_match.lower() not in [u.lower() for u in upi_ids]:
            upi_ids.append(full_match)

    # 3. URLs & Domains
    urls: list[str] = []
    domains: list[str] = []
    for match in _URL_RE.finditer(text):
        raw_url = match.group(0).strip(".,;:!?)]}\"'")
        if raw_url.lower() in email_set:
            continue
        normalized_for_parse = raw_url if "://" in raw_url else f"http://{raw_url}"
        try:
            parts = urlsplit(normalized_for_parse)
            host = (parts.hostname or "").lower()
            if host and "." in host:
                # If it's just the domain portion of an email and was preceded by @ in text, skip
                if raw_url.lower() in email_domains and f"@{raw_url.lower()}" in text.lower():
                    continue
                if raw_url not in urls:
                    urls.append(raw_url)
                if host not in domains:
                    domains.append(host)
        except Exception:
            pass

    # 4. Phones
    phones: list[str] = []
    for ph in _PHONE_RE.findall(text):
        cleaned_ph = re.sub(r"[\s.-]", "", ph)
        if cleaned_ph not in phones:
            phones.append(cleaned_ph)

    # 5. Amounts
    amounts: list[str] = []
    for am in _AMOUNT_RE.findall(text):
        am_clean = am.strip(".,;:!?)]}\"'")
        if am_clean not in amounts:
            amounts.append(am_clean)

    return {
        "urls": urls,
        "domains": domains,
        "emails": emails,
        "phones": phones,
        "upi_ids": upi_ids,
        "amounts": amounts,
    }


def _split_into_sentences(text: str) -> list[str]:
    """Split text into sentences, avoiding splits inside URLs, decimals, and abbreviations."""
    raw = re.split(r"(?<=[.!?])\s+|\n+", text)
    return [s.strip() for s in raw if s.strip()]


def _load_brands() -> list[dict[str, Any]]:
    brands_path = DATA_DIR / "brands.json"
    if not brands_path.exists():
        return []
    try:
        with open(brands_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def run_scam_rules(
    text: str, indicators: dict[str, list[str]], brands: list[dict[str, Any]]
) -> tuple[list[Finding], list[str]]:
    """Evaluate deterministic scam rules and return findings with matched sentences."""
    findings: list[Finding] = []
    matched_rules: list[str] = []
    text_lower = text.lower()
    sentences = _split_into_sentences(text)

    # 1. OTP Request (High)
    # Exclude genuine security warnings (e.g. "never share your OTP", "do not share")
    otp_phrases = ["share otp", "share your otp", "send the otp", "send your otp", "tell us the otp",
                   "enter otp", "provide otp", "share code", "share pin", "share password", "share cvv"]
    otp_sentence = None
    for s in sentences:
        s_low = s.lower()
        if any(neg in s_low for neg in ["never share", "do not share", "don't share", "should not share"]):
            continue
        if any(p in s_low for p in otp_phrases) or (("otp" in s_low or "code" in s_low) and any(w in s_low for w in ["share", "send", "tell", "forward"])):
            otp_sentence = s
            break

    if otp_sentence:
        matched_rules.append("message.otp_request")
        findings.append(
            Finding(
                id="message.otp_request",
                check="message",
                title="Requests you to share an OTP or security code",
                severity=Severity.high,
                evidence=f'"{otp_sentence}"',
                source="rule: otp_request",
                impact="Anyone with your OTP can access your accounts, drain balances, or approve fraudulent transfers.",
                recommendation="Never share an OTP, PIN, or password with anyone, even if they claim to be bank staff.",
            )
        )

    # 2. Remote Access Applications (High)
    remote_apps = ["anydesk", "teamviewer", "quicksupport", "rustdesk", "screen share", "ultraviewer"]
    remote_sentence = None
    for s in sentences:
        s_low = s.lower()
        if any(app in s_low for app in remote_apps):
            remote_sentence = s
            break

    if remote_sentence:
        matched_rules.append("message.remote_access")
        findings.append(
            Finding(
                id="message.remote_access",
                check="message",
                title="Asks to install remote access screen-sharing app",
                severity=Severity.high,
                evidence=f'"{remote_sentence}"',
                source="rule: remote_access",
                impact="Remote access tools give attackers complete control over your mobile device and banking apps.",
                recommendation="Immediately decline and never install remote-control apps requested by unsolicited callers or messages.",
            )
        )

    # 3. Job or Internship Fee Scam (High)
    job_words = ["job", "internship", "selected for job", "selected for", "part time job", "work from home", "hiring", "data entry", "appointment letter"]
    fee_words = ["fee", "deposit", "registration charge", "processing fee", "security deposit", "pay to start", "investment", "refundable registration"]
    job_sentence = None
    has_job = any(j in text_lower for j in job_words)
    has_fee = any(f in text_lower for f in fee_words)
    if has_job and has_fee:
        for s in sentences:
            s_low = s.lower()
            if any(f in s_low for f in fee_words):
                job_sentence = s
                break
        if not job_sentence:
            for s in sentences:
                s_low = s.lower()
                if any(j in s_low for j in job_words):
                    job_sentence = s
                    break

    if job_sentence:
        matched_rules.append("message.job_fee")
        findings.append(
            Finding(
                id="message.job_fee",
                check="message",
                title="Employment offer demanding an upfront fee or deposit",
                severity=Severity.high,
                evidence=f'"{job_sentence}"',
                source="rule: job_fee",
                impact="Legitimate employers never demand upfront fees or security deposits for employment.",
                recommendation="Do not send money or registration charges to secure an employment offer.",
            )
        )

    # 4. Brand Impersonation (High)
    # Mentions a brand keyword but includes an external link not in that brand's official domains
    impersonation_found = False
    for brand in brands:
        b_name = brand.get("name", "Unknown")
        keywords = [k.lower() for k in brand.get("keywords", [])]
        off_domains = [d.lower() for d in brand.get("official_domains", [])]
        brand_mentioned = any(re.search(r"\b" + re.escape(kw) + r"\b", text_lower) for kw in keywords)

        if brand_mentioned and indicators["domains"]:
            # Check if all links belong to the official domains
            suspicious_domains = [
                d for d in indicators["domains"]
                if not any(d == od or d.endswith("." + od) for od in off_domains)
            ]
            if suspicious_domains:
                matched_rules.append("message.impersonation")
                findings.append(
                    Finding(
                        id="message.impersonation",
                        check="message",
                        title=f"Brand impersonation: mentions {b_name} with unauthorized link",
                        severity=Severity.high,
                        evidence=f"Message references brand '{b_name}' but links to external domain '{suspicious_domains[0]}'.",
                        source="rule: impersonation",
                        impact=f"Attackers pose as {b_name} to lure victims onto phishing landing pages.",
                        recommendation=f"Access {b_name} services directly through their official portals ({', '.join(off_domains)}).",
                    )
                )
                impersonation_found = True
                break

    # 5. Fake KYC / PAN / Account Block Threats (Medium)
    kyc_words = ["kyc", "pan update", "aadhaar link", "pan card", "account will be blocked",
                 "sim will be blocked", "electricity power cut", "account suspended", "deactivated"]
    kyc_sentence = None
    for s in sentences:
        s_low = s.lower()
        if any(w in s_low for w in kyc_words):
            kyc_sentence = s
            break

    if kyc_sentence:
        matched_rules.append("message.kyc_update")
        findings.append(
            Finding(
                id="message.kyc_update",
                check="message",
                title="Account suspension threat or urgent KYC/PAN mandate",
                severity=Severity.medium,
                evidence=f'"{kyc_sentence}"',
                source="rule: kyc_update",
                impact="Fraudsters manufacture threats of imminent service termination to provoke hasty compliance.",
                recommendation="Banks and utility providers do not terminate accounts or disconnect electricity via SMS links.",
            )
        )

    # 6. Payment / Money Transfer Demands (Medium)
    payment_words = ["pay now", "transfer", "pay ₹", "pay rs", "send money", "processing fee", "upi pin to receive", "scan qr", "deposit to"]
    payment_sentence = None
    for s in sentences:
        s_low = s.lower()
        if any(w in s_low for w in payment_words):
            payment_sentence = s
            break

    if payment_sentence:
        matched_rules.append("message.payment_request")
        findings.append(
            Finding(
                id="message.payment_request",
                check="message",
                title="Demands payment or money transfer",
                severity=Severity.medium,
                evidence=f'"{payment_sentence}"',
                source="rule: payment_request",
                impact="Coerces victims into transferring money under false pretenses.",
                recommendation="Independently verify any payment request directly with the purported recipient.",
            )
        )

    # 7. Lottery, Lucky Draw, or Unsolicited Refund (Medium)
    prize_words = ["you have won", "lottery", "lucky draw", "cashback", "refund approved", "refund", "prize money",
                   "selected winner", "claim your prize", "won rs", "won ₹", "reward point"]
    prize_sentence = None
    for s in sentences:
        s_low = s.lower()
        if any(w in s_low for w in prize_words):
            prize_sentence = s
            break

    if prize_sentence:
        matched_rules.append("message.prize_or_refund")
        findings.append(
            Finding(
                id="message.prize_or_refund",
                check="message",
                title="Lures with unexpected prize, lottery, or refund",
                severity=Severity.medium,
                evidence=f'"{prize_sentence}"',
                source="rule: prize_or_refund",
                impact="Advance-fee fraud tempts victims with nonexistent windfalls to collect upfront charges or credentials.",
                recommendation="You cannot win a contest or lottery you never entered. Treat unsolicited windfalls as scams.",
            )
        )

    # 8. Shortened Links in Message (Medium)
    shortened_found = [d for d in indicators["domains"] if d in _SHORTENERS]
    if shortened_found:
        matched_rules.append("message.shortened_link")
        findings.append(
            Finding(
                id="message.shortened_link",
                check="message",
                title="Message contains obfuscated shortened link",
                severity=Severity.medium,
                evidence=f"Contains shortened URL domain: '{shortened_found[0]}'.",
                source="rule: shortened_link",
                impact="Shortened links mask the true target domain, hiding phishing infrastructure from initial inspection.",
                recommendation="Do not tap shortened links in SMS or messaging apps.",
            )
        )

    # 9. Artificial Urgency / Pressure Tactics (Low - never higher)
    urgency_words = [
        "urgent",
        "urgently",
        "immediately",
        "today",
        "tonight",
        "within 24 hours",
        "last chance",
        "act now",
        "limited time",
        "expires today",
        "suspended",
        "deactivated",
    ]
    urgency_sentence = None
    for s in sentences:
        s_low = s.lower()
        # Do not flag normal delivery updates as urgent
        if any(deliv in s_low for deliv in ["out for delivery", "arrive today", "arriving today"]):
            continue
        if any(w in s_low for w in urgency_words):
            urgency_sentence = s
            break

    if urgency_sentence:
        matched_rules.append("message.urgency")
        findings.append(
            Finding(
                id="message.urgency",
                check="message",
                title="Artificial urgency and high-pressure language",
                severity=Severity.low,
                evidence=f'"{urgency_sentence}"',
                source="rule: urgency",
                impact="Psychological pressure is applied to rush victims into acting before they can verify.",
                recommendation="Legitimate institutions provide reasonable timeframes; slow down and verify.",
            )
        )

    # 10. Suspicious Personal Contact / WhatsApp Prompt (Low)
    contact_prompts = ["call on this number", "contact manager at", "whatsapp on", "whatsapp at", "call immediately at"]
    contact_sentence = None
    if indicators["phones"]:
        for s in sentences:
            s_low = s.lower()
            if any(p in s_low for p in contact_prompts):
                contact_sentence = s
                break

    if contact_sentence:
        matched_rules.append("message.suspicious_sender_contact")
        findings.append(
            Finding(
                id="message.suspicious_sender_contact",
                check="message",
                title="Directs user to call or message a personal contact number",
                severity=Severity.low,
                evidence=f'"{contact_sentence}"',
                source="rule: suspicious_sender_contact",
                impact="Directing victims to personal phone or WhatsApp channels bypasses corporate oversight.",
                recommendation="Always call verified customer service numbers listed on the company's official website.",
            )
        )

    return findings, matched_rules


# --- Pydantic Schema for AI Assessment ---
class Tactic(BaseModel):
    name: str  # e.g. "otp_request", "impersonation", "urgency", "fake_job_fee"
    quote: str  # exact words from the message
    why: str  # one sentence explanation


class MessageAssessment(BaseModel):
    tactics: list[Tactic] = []
    impersonated_entity: Optional[str] = None
    looks_like_scam: bool = False
    summary: str = ""


AI_SYSTEM_PROMPT = """You are an expert fraud and cybercrime investigator.
Analyze the user message provided inside <untrusted_message> tags.
Identify deceptive social-engineering tactics.

Rules:
1. Quote the exact words from the message in 'quote'. Do not paraphrase or invent quotes.
2. If the message is a genuine, benign message (e.g. an authentic bank OTP with 'Do not share', normal flight notice, friend message), set looks_like_scam to false and list no fraud tactics.
3. Urgent wording alone does not prove fraud.
4. Output must match the specified JSON schema.
"""


async def analyze(target: str) -> CheckResult:
    """Analyze a pasted message or email for scam indicators, patterns, and AI evaluation."""
    try:
        limitations: list[str] = []
        raw_text = target.strip()

        if not raw_text:
            return CheckResult(
                check="message",
                status="error",
                limitations=["Pasted message is empty."],
            )

        # 1. Indicator Extraction
        indicators = extract_indicators(raw_text)

        # 2. Deterministic Rule Matching
        brands = _load_brands()
        findings, matched_rules = run_scam_rules(raw_text, indicators, brands)

        # 3. LLM AI Analysis (Google Gemini via llm.py)
        ai_data: dict[str, Any] = {}
        try:
            # Mask PII (phone numbers, emails) for privacy before sending to AI
            masked = mask_pii(raw_text)
            wrapped_input = untrusted_block("message", masked)
            assessment = await llm_json(AI_SYSTEM_PROMPT, wrapped_input, MessageAssessment)

            if assessment:
                ai_data = {
                    "looks_like_scam": assessment.looks_like_scam,
                    "impersonated_entity": assessment.impersonated_entity,
                    "summary": assessment.summary,
                    "tactics_count": len(assessment.tactics),
                }

                # Verify each quote appears in the original text (Anti-hallucination check)
                existing_finding_ids = {f.id for f in findings}
                for tactic in assessment.tactics:
                    quote = tactic.quote.strip()
                    # Check quote presence in original or masked text
                    if quote and (quote.lower() in raw_text.lower() or quote.lower() in masked.lower()):
                        tactic_id = f"message.ai_{re.sub(r'[^a-z0-9_]', '', tactic.name.lower()) or 'tactic'}"

                        # Check if a deterministic rule already covered this tactic
                        matching_rule_id = next(
                            (rid for rid in existing_finding_ids if tactic.name.lower() in rid.lower()),
                            None,
                        )
                        if matching_rule_id:
                            # Augment the existing rule finding with AI insights
                            for f in findings:
                                if f.id == matching_rule_id:
                                    f.impact = f"{f.impact} (AI assessment: {tactic.why})"
                        else:
                            # AI-only finding is capped at Medium severity per AGENTS.md rules
                            findings.append(
                                Finding(
                                    id=tactic_id,
                                    check="message",
                                    title=f"AI detected: {tactic.name.replace('_', ' ').capitalize()}",
                                    severity=Severity.medium,
                                    evidence=f'"{quote}"',
                                    source="AI analysis",
                                    impact=tactic.why,
                                    recommendation="Scrutinize this message carefully; the AI identified deceptive language patterns.",
                                )
                            )
            else:
                limitations.append("AI analysis unavailable; rule-based analysis only.")
        except Exception as ai_exc:
            log.warning("AI message evaluation failed: %s", ai_exc)
            limitations.append("AI analysis unavailable; rule-based analysis only.")

        data: dict[str, Any] = {
            "indicators": indicators,
            "matched_rules": matched_rules,
            "ai": ai_data,
        }

        return CheckResult(
            check="message",
            status="ok",
            findings=findings,
            data=data,
            limitations=limitations,
        )
    except Exception as exc:
        return error_result("message", exc)


if __name__ == "__main__":
    run_cli(analyze)
