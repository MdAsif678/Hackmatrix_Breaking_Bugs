"""Regression tests for the message analyzer: genuine messages that used to misfire, scams that must still be
caught, and the rule that the AI never decides a verdict on its own (added by P1 during review)."""
import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from app.analyzers.message_analyzer import MessageAssessment, Tactic, analyze
from app.risk.engine import classify
from app.schemas import RiskLevel, Severity


def run(msg: str):
    return asyncio.run(analyze(msg))


def ids(result) -> set[str]:
    return {f.id for f in result.findings}


def verdict(result) -> RiskLevel:
    return classify([result], 1.0)[0]


@pytest.mark.parametrize(
    "msg,forbidden",
    [
        ("Use my referral code ANKIT50 on Swiggy and get 50% off your first order. Share this code with your friends!",
         "message.otp_request"),
        ("Hi Priyanka, your interview with the hiring manager is today at 3 PM on Google Meet. There is no fee at any stage.",
         "message.job_fee"),
        ("Rs 10,000 transferred to your account from RAHUL via IMPS. Avl bal Rs 25,340. -SBI", "message.payment_request"),
        ("Rs.2,500.00 debited from A/c XX1234 to VPA swiggy@icici. Not you? Call 18002586161 to block. -HDFC Bank",
         "message.payment_request"),
        ("Your refund of Rs 499 for order 405-1234567 has been processed and will reflect in 3-5 days. - Amazon",
         "message.prize_or_refund"),
        ("Our internship is free of cost. We never charge any registration fee.", "message.job_fee"),
    ],
)
def test_genuine_messages_do_not_trigger(msg, forbidden):
    result = run(msg)
    assert forbidden not in ids(result)
    assert verdict(result) == RiskLevel.low_risk


@pytest.mark.parametrize(
    "msg,expected",
    [
        ("Hello Sir, this is HDFC customer care. Install AnyDesk and tell us the 6 digit code shown.", "message.otp_request"),
        ("Please share the OTP sent to your mobile to cancel the transaction.", "message.otp_request"),
        ("Send your UPI PIN to receive the cashback.", "message.otp_request"),
        ("Earn Rs 3000 daily! Like YouTube videos from home. Join our Telegram task group, deposit Rs 1000 to unlock VIP tasks.",
         "message.job_fee"),
        ("Final last chance: transfer ₹2,500 immediately to accounts.dean@paytm to prevent suspension.", "message.payment_request"),
        ("Your tax refund of ₹12,450 is approved. Update bank details at http://refund-claim.example/claim",
         "message.prize_or_refund"),
    ],
)
def test_scams_still_caught(msg, expected):
    assert expected in ids(run(msg))


def _with_ai(msg: str, assessment: MessageAssessment):
    with patch("app.analyzers.message_analyzer.llm_json", new=AsyncMock(return_value=assessment)):
        return run(msg)


def test_ai_alone_cannot_make_a_message_suspicious():
    msg = "Rs.2,500.00 debited from A/c XX1234. Not you? Call 18002586161 to block. -HDFC Bank"
    ai = MessageAssessment(
        looks_like_scam=True,
        tactics=[
            Tactic(name="fake_fraud_alert", quote="Not you?", why="Mimics a fraud alert."),
            Tactic(name="callback_trap", quote="Call 18002586161 to block", why="Pushes a phone call."),
        ],
    )
    result = _with_ai(msg, ai)
    ai_findings = [f for f in result.findings if f.source == "AI analysis"]
    assert ai_findings and all(f.severity == Severity.low for f in ai_findings)
    assert verdict(result) == RiskLevel.low_risk


def test_ai_saying_not_a_scam_adds_nothing():
    msg = "Your Amazon order is out for delivery today."
    ai = MessageAssessment(looks_like_scam=False, tactics=[Tactic(name="urgency", quote="today", why="Time words.")])
    assert [f for f in _with_ai(msg, ai).findings if f.source == "AI analysis"] == []


def test_ai_duplicates_merge_into_rules_and_each_other():
    msg = "URGENT: your KYC is pending and your account will be blocked today. Update at http://kyc-now.example"
    ai = MessageAssessment(
        looks_like_scam=True,
        tactics=[
            Tactic(name="fear_and_urgency", quote="URGENT", why="Pressure."),
            Tactic(name="account_block_threat", quote="your account will be blocked today", why="Threat."),
            Tactic(name="phishing_link", quote="Update at http://kyc-now.example", why="Link to a fake page."),
            Tactic(name="phishing_link", quote="http://kyc-now.example", why="Same link again."),
        ],
    )
    result = _with_ai(msg, ai)
    found = [f.id for f in result.findings]
    assert len(found) == len(set(found)), found  # no duplicate ids
    assert "message.ai_fear_and_urgency" not in found  # merged into message.urgency
    assert "message.ai_account_block_threat" not in found  # merged into message.kyc_update
    assert found.count("message.ai_phishing_link") == 1


def test_payment_to_personal_upi_is_serious_even_without_ai():
    msg = ("University Exam Notice: Your semester registration fee is unpaid. Final last chance: transfer ₹2,500 "
           "immediately to accounts.dean@paytm to prevent suspension from upcoming exams.")
    result = run(msg)  # AI is off in tests
    f = next(f for f in result.findings if f.id == "message.payment_request")
    assert f.severity == Severity.high and "accounts.dean@paytm" in f.evidence
    assert verdict(result) == RiskLevel.suspicious


def test_payment_notice_without_a_way_to_pay_is_not_flagged():
    msg = "Dear Student, the last date to pay the semester fee is 15 Nov. Pay through the college ERP portal only."
    assert "message.payment_request" not in ids(run(msg))
