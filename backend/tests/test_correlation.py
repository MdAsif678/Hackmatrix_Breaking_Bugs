"""Tests for threat correlation (deterministic linking of related reports)."""
import uuid
from datetime import datetime, timezone

import pytest

from app import db
from app.correlation import engine
from app.schemas import AnalysisReport, CheckResult, RiskLevel


@pytest.fixture(autouse=True)
def fresh_db():
    db.init_db()


def make(input_type="url", target=None, text="", indicators=None, checks=None) -> AnalysisReport:
    r = AnalysisReport(
        id=str(uuid.uuid4()), input_type=input_type, input=text or target or "", normalized_target=target,
        created_at=datetime.now(timezone.utc), risk_level=RiskLevel.suspicious, risk_reasons=[], coverage=1.0,
        checks=checks or [], extracted_indicators=indicators or {},
    )
    db.save_report(r)
    engine.index_report(r)
    return r


def test_same_registrable_domain_linked_across_subdomains():
    a = make(target="https://login.sbi-kyc-update.com/verify")
    b = make(target="https://secure.sbi-kyc-update.com/")
    assert engine.find_related(b) == [a.id]
    details = engine.related_details(a).related  # live: earlier report sees the later one too
    assert details[0].report_id == b.id and "same domain: sbi-kyc-update.com" in details[0].shared_indicators


def test_different_messages_linked_by_payment_id_and_phone():
    a = make("message", text="You won a prize! Pay fee to lucky@ybl or call 98765 43210",
             indicators={"upi_ids": ["Lucky@ybl"], "phones": ["+91 98765 43210"]})
    b = make("message", text="Refund approved. Send Rs 10 to lucky@ybl to receive it",
             indicators={"upi_ids": ["lucky@ybl"]})
    related = engine.related_details(b).related
    assert related[0].report_id == a.id
    assert "same UPI payment ID: lucky@ybl" in related[0].shared_indicators


def test_near_identical_messages_linked():
    a = make("message", text="Dear customer your SBI account KYC expires today. Update now at the link below.")
    b = make("message", text="Dear customer, your SBI account KYC expires TODAY. Update now at the link below!!")
    shared = engine.related_details(b).related[0].shared_indicators
    assert engine.find_related(b) == [a.id] and "near-identical message text" in shared[0]


def test_same_certificate_linked():
    tls = lambda: [CheckResult(check="tls", status="ok", data={"sha256_fingerprint": "AA:BB:CC"})]
    a = make(target="https://phish-one.com/", checks=tls())
    b = make(target="https://phish-two.net/", checks=tls())
    assert engine.find_related(b) == [a.id]


def test_shared_hosting_ip_not_used_as_link():
    def on_ip(domain):
        return make(target=f"https://{domain}/", checks=[CheckResult(check="tls", status="ok", data={"ip": "104.16.0.1"})])

    first = on_ip("site-a.com")
    second = on_ip("site-b.com")
    assert engine.find_related(second) == [first.id]  # 2 domains on one IP: still a meaningful link
    for i in range(5):
        on_ip(f"other-{i}.com")
    assert engine.find_related(on_ip("site-z.com")) == []  # 8 domains on that IP: CDN/shared hosting, ignored


def test_unrelated_reports_not_linked():
    make(target="https://github.com/")
    b = make(target="https://example.org/")
    assert engine.find_related(b) == []
