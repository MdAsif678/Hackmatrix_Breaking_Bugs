"""Request limits on checks and seals, and the canonical-fingerprint endpoint."""
import hashlib

from app.config import settings
from app.core import rate_limit


def test_checks_are_limited_per_ip(client, monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_enabled", True)
    rate_limit.reset()
    for _ in range(8):  # the per-minute budget
        assert client.post("/api/analyze/message", json={"text": "hello"}).status_code == 200
    blocked = client.post("/api/analyze/message", json={"text": "hello"})
    assert blocked.status_code == 429
    assert "Too many checks" in blocked.json()["detail"]
    assert int(blocked.headers["retry-after"]) > 0
    # another visitor (different IP behind the proxy) is not affected
    other = client.post("/api/analyze/message", json={"text": "hello"}, headers={"X-Forwarded-For": "203.0.113.9"})
    assert other.status_code == 200
    rate_limit.reset()


def test_limits_are_off_when_disabled(client):
    rate_limit.reset()
    for _ in range(12):
        assert client.post("/api/analyze/message", json={"text": "hello"}).status_code == 200


def test_seal_limit_does_not_count_already_sealed_reports(client, monkeypatch):
    """Asking again for a report that is already sealed returns the record and costs nothing."""
    from app import db
    from app.schemas import ChainRecord

    monkeypatch.setattr(settings, "rate_limit_enabled", True)
    rate_limit.reset()
    rid = client.post("/api/analyze/message", json={"text": "hello"}).json()["id"]
    report = db.get_report(rid)
    report.chain = ChainRecord(report_hash="0x" + "ab" * 32, chain_report_id=7, tx_hash="0x" + "cd" * 32,
                               contract_address="0x" + "11" * 20)
    db.save_report(report)
    for _ in range(10):
        assert client.post(f"/api/registry/submit/{rid}").status_code == 200
    rate_limit.reset()


def test_canonical_endpoint_matches_its_hash(client):
    rid = client.post("/api/analyze/message", json={"text": "Your KYC expires today"}).json()["id"]
    body = client.get(f"/api/reports/{rid}/canonical").json()
    assert body["sha256"] == "0x" + hashlib.sha256(body["canonical"].encode("utf-8")).hexdigest()
    assert '"chain"' not in body["canonical"]  # the chain record is never part of the fingerprint
    assert client.get("/api/reports/missing/canonical").status_code == 404
