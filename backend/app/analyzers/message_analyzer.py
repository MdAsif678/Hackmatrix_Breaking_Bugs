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


# Words meaning "this is free / we never charge": a fee mentioned in such a sentence is a reassurance, not a demand.
_FEE_NEGATIONS = ("no fee", "no fees", "no charge", "no charges", "free of cost", "free of charge", "never ask",
                  "never charge", "does not charge", "do not charge", "not charge", "no payment", "no registration fee",
                  "without any fee", "zero fee")

# Secrets a scammer wants (an OTP, PIN, password...) and the verbs used to ask for them.
_SECRET_RE = re.compile(
    r"\b(otp|one[- ]time password|pin|m-?pin|upi pin|password|passcode|cvv|verification code|security code|"
    r"\d[- ]?digit code|code (?:shown|sent|received|you received)|code on your screen)\b"
)
_ASK_RE = re.compile(r"\b(share|send|tell|forward|give|provide|enter|type|read out|reply with|confirm)\b")

# Money demands: imperative phrases only ("transfer Rs 500"), never reports ("Rs 500 transferred to you").
_PAYMENT_RES = [
    re.compile(p)
    for p in (
        r"\bpay now\b",
        r"\bpay(?: a| the)?\s*(?:rs\.?|₹|inr)",
        r"\bpay\b[^.]{0,40}\b(?:fee|charge|amount|bill)\b",
        r"\bsend\s+(?:rs\.?|₹|inr|money|the amount|payment)",
        r"\btransfer\s+(?:rs\.?|₹|inr|money|the amount|amount|funds)",
        r"\bprocessing fee\b",
        r"\bscan (?:the |this )?qr\b",
        r"\bdeposit\s+(?:rs\.?|₹|inr)",
        r"\bupi pin to receive\b",
    )
]

# AI tactic names -> the rule that already covers that tactic (so the two merge instead of repeating)
_AI_TO_RULE = (
    (("otp", "credential", "password", "pin"), "message.otp_request"),
    (("remote", "anydesk", "teamviewer", "screen"), "message.remote_access"),
    (("job", "employment", "recruit", "task"), "message.job_fee"),
    (("impersonat", "brand", "spoof"), "message.impersonation"),
    (("kyc", "pan", "aadhaar", "suspension", "block", "deactivat", "threat"), "message.kyc_update"),
    (("payment", "fee", "transfer", "money"), "message.payment_request"),
    (("prize", "lottery", "reward", "refund", "cashback", "lure", "windfall"), "message.prize_or_refund"),
    (("short",), "message.shortened_link"),
    (("urgen", "pressure", "fear", "deadline"), "message.urgency"),
    (("contact", "whatsapp", "call"), "message.suspicious_sender_contact"),
)


def _rule_for_tactic(name: str, rule_ids: set[str]) -> Optional[str]:
    n = name.lower()
    for keys, rule_id in _AI_TO_RULE:
        if rule_id in rule_ids and any(k in n for k in keys):
            return rule_id
    return None


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
    # A secret (OTP, PIN, password, "6 digit code"...) AND a verb asking for it in the same sentence.
    # A plain "code" (referral or promo code) is not a secret; "never share your OTP" is a warning, not a request.
    otp_sentence = None
    for s in sentences:
        s_low = s.lower()
        if any(neg in s_low for neg in ["never share", "do not share", "don't share", "should not share", "not to share"]):
            continue
        if _SECRET_RE.search(s_low) and _ASK_RE.search(s_low):
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
    job_words = ["job", "internship", "selected for job", "selected for", "part time job", "part-time", "work from home",
                 "hiring", "data entry", "appointment letter", "task", "earn rs", "earn ₹", "daily income", "per day",
                 "like videos", "rate products"]
    fee_words = ["fee", "deposit", "registration charge", "processing fee", "security deposit", "pay to start", "investment",
                 "refundable registration", "unlock vip", "recharge"]
    job_sentence = None
    # A fee in a sentence that says "no fee" / "free of cost" reassures; it is not a demand.
    fee_sentences = [s for s in sentences
                     if any(f in s.lower() for f in fee_words) and not any(n in s.lower() for n in _FEE_NEGATIONS)]
    has_job = any(j in text_lower for j in job_words)
    has_fee = bool(fee_sentences)
    if has_job and has_fee:
        job_sentence = fee_sentences[0]
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

    # 6. Payment / Money Transfer Demands
    # Only a demand that comes with a way to pay counts (a link, a UPI ID or a phone number): "pay the semester fee
    # by 15 Nov" in a college notice is not one. Paying a personal UPI ID straight from an SMS is Serious (high).
    payment_sentence = None
    can_pay = bool(indicators["urls"] or indicators["upi_ids"] or indicators["phones"])
    for s in sentences if can_pay else []:
        s_low = s.lower()
        if any(n in s_low for n in _FEE_NEGATIONS):
            continue
        if any(rx.search(s_low) for rx in _PAYMENT_RES):
            payment_sentence = s
            break

    if payment_sentence:
        to_upi = bool(indicators["upi_ids"])
        matched_rules.append("message.payment_request")
        findings.append(
            Finding(
                id="message.payment_request",
                check="message",
                title="Demands payment to a personal UPI ID" if to_upi else "Demands payment or money transfer",
                severity=Severity.high if to_upi else Severity.medium,
                evidence=f'"{payment_sentence}"' + (f" (UPI ID: {indicators['upi_ids'][0]})" if to_upi else ""),
                source="rule: payment_request",
                impact="Banks, colleges, courier and power companies do not collect fees by asking you to send money to "
                       "a UPI ID in a text message." if to_upi else
                       "Coerces victims into transferring money under false pretenses.",
                recommendation="Pay only through the organisation's official website or app, never to a UPI ID sent "
                               "in a message." if to_upi else
                               "Independently verify any payment request directly with the purported recipient.",
            )
        )

    # 7. Lottery, Lucky Draw, or Unsolicited Refund (Medium)
    prize_words = ["you have won", "lottery", "lucky draw", "prize money", "selected winner", "claim your prize",
                   "won rs", "won ₹", "reward point", "reward points"]
    # "Your refund has been processed" is a normal notice; a refund or cashback is only a lure when the message
    # also asks you to click, claim, update or verify something, or carries a link.
    refund_words = ["refund", "cashback"]
    lure_words = ["claim", "click", "update", "verify", "redeem", "link", "share", "submit", "fill"]
    has_lure = bool(indicators["urls"]) or any(w in text_lower for w in lure_words)
    prize_sentence = None
    for s in sentences:
        s_low = s.lower()
        if any(w in s_low for w in prize_words) or (has_lure and any(w in s_low for w in refund_words)):
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

                # The AI never decides the verdict on its own (AGENTS.md section 6):
                # - if it says the message is not a scam, its tactics are not added;
                # - when no rule fired, its findings are Minor (low) and cannot move the verdict;
                # - only next to rule evidence may an AI-only finding be a Warning (medium), never more.
                existing_finding_ids = {f.id for f in findings}
                ai_severity = Severity.medium if findings else Severity.low
                added_ai_ids: set[str] = set()
                for tactic in (assessment.tactics if assessment.looks_like_scam else []):
                    quote = tactic.quote.strip()
                    # Check quote presence in original or masked text
                    if quote and (quote.lower() in raw_text.lower() or quote.lower() in masked.lower()):
                        tactic_id = f"message.ai_{re.sub(r'[^a-z0-9_]', '', tactic.name.lower()) or 'tactic'}"

                        # Check if a deterministic rule already covered this tactic
                        matching_rule_id = _rule_for_tactic(tactic.name, existing_finding_ids)
                        if matching_rule_id:
                            # Augment the existing rule finding with the AI's reasoning (once)
                            for f in findings:
                                if f.id == matching_rule_id and "(AI assessment:" not in (f.impact or ""):
                                    f.impact = f"{f.impact} (AI assessment: {tactic.why})"
                        elif tactic_id not in added_ai_ids and tactic_id not in existing_finding_ids:
                            added_ai_ids.add(tactic_id)
                            findings.append(
                                Finding(
                                    id=tactic_id,
                                    check="message",
                                    title=f"AI detected: {tactic.name.replace('_', ' ').capitalize()}",
                                    severity=ai_severity,
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
