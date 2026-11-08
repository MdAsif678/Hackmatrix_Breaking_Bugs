"""Tests for the on-chain registry bridge, using an in-memory fake of the ThreatRegistry contract."""
import json
import time
from types import SimpleNamespace

import pytest

from app.config import settings
from app.registry import chain
from app.registry.hashing import report_hash


OFFICIAL = "0x" + "cd" * 20  # TrustLens's registry wallet
HACKER = "0x" + "66" * 20


class FakeRegistry:
    """Mimics ThreatRegistry.sol (AGENTS.md §7) closely enough for web3-style calls."""

    def __init__(self):
        self.records = {}
        self.address = "0x" + "ab" * 20
        self.functions = SimpleNamespace(submitReport=self._submit, getReport=self._get)
        self.events = SimpleNamespace(ReportSubmitted=lambda: SimpleNamespace(process_receipt=self._events))
        self._last_id = 0

    def _submit(self, h: bytes, risk: str):
        assert isinstance(h, bytes) and len(h) == 32
        return SimpleNamespace(kind="submit", args=(h, risk))

    def _get(self, rid: int):
        if rid not in self.records:
            raise ValueError("unknown id")
        h, risk, submitter, ts = self.records[rid]
        return SimpleNamespace(call=lambda: (h, submitter, ts, risk, 0, 0))

    def mine(self, call, submitter=OFFICIAL, timestamp=None):
        self._last_id += 1
        self.records[self._last_id] = (*call.args, submitter, int(timestamp or time.time()))
        return self._last_id

    def _events(self, receipt):
        return [{"args": {"id": receipt["id"]}}]


@pytest.fixture
def fake_chain(monkeypatch):
    registry = FakeRegistry()
    conn = chain._Conn(w3=None, contract=registry, account=SimpleNamespace(address=OFFICIAL), network="sepolia")
    monkeypatch.setattr(chain, "_connection", lambda: conn)
    monkeypatch.setattr(chain, "_send", lambda c, call: ("0x" + "12" * 32, {"status": 1, "id": registry.mine(call)}))
    return registry


def test_not_configured_lists_missing_settings(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "sepolia_rpc_url", "")
    monkeypatch.setattr(settings, "registry_private_key", "")
    monkeypatch.setattr(settings, "registry_contract_address", "")
    monkeypatch.setattr(chain, "ABI_PATH", tmp_path / "missing.json")
    with pytest.raises(chain.RegistryNotConfigured) as exc:
        chain._connection()
    msg = str(exc.value)
    assert "SEPOLIA_RPC_URL" in msg and "REGISTRY_PRIVATE_KEY" in msg and "ThreatRegistry.abi.json" in msg


def test_abi_loader_accepts_remix_and_hardhat_formats(tmp_path):
    abi = [{"type": "function", "name": "getReport"}]
    (tmp_path / "remix.json").write_text(json.dumps(abi))
    (tmp_path / "hardhat.json").write_text(json.dumps({"contractName": "ThreatRegistry", "abi": abi}))
    assert chain.load_abi(tmp_path / "remix.json") == abi == chain.load_abi(tmp_path / "hardhat.json")


def test_to_bytes32():
    assert chain.to_bytes32("0x" + "00" * 31 + "ff")[-1] == 255
    with pytest.raises(ValueError):
        chain.to_bytes32("0x1234")


def test_register_verify_tamper_flow(client, fake_chain):
    rid = client.post("/api/analyze/url", json={"url": "example.com"}).json()["id"]

    record = client.post(f"/api/registry/submit/{rid}").json()
    assert record["chain_report_id"] == 1 and record["network"] == "sepolia"
    stored = client.get(f"/api/reports/{rid}").json()
    assert stored["chain"]["report_hash"] == record["report_hash"]
    # only the hash and risk level reached the "chain" — never the URL
    assert fake_chain.records[1][:2] == (bytes.fromhex(record["report_hash"][2:]), stored["risk_level"])

    ok = client.get(f"/api/registry/verify/{rid}").json()
    assert ok["match"] is True and ok["status"] == "verified" and ok["chain_status"] == "active"
    assert ok["explorer_url"].startswith("https://sepolia.etherscan.io/tx/0x")

    # registering twice returns the existing record instead of paying for a new transaction
    assert client.post(f"/api/registry/submit/{rid}").json()["chain_report_id"] == 1

    # tamper with the stored report (what scripts/tamper_report.py does)
    from app import db
    from app.schemas import RiskLevel

    report = db.get_report(rid)
    report.risk_level = RiskLevel.low_risk
    db.save_report(report)
    bad = client.get(f"/api/registry/verify/{rid}").json()
    assert bad["match"] is False and bad["status"] == "mismatch"
    assert bad["recomputed_hash"] != bad["onchain_hash"] == record["report_hash"]


def test_chain_failure_returns_502(client, monkeypatch):
    def boom(report):
        raise chain.RegistryError("Blockchain transaction failed: ValueError (registry wallet needs Sepolia test ETH)")

    monkeypatch.setattr(chain, "submit", boom)
    rid = client.post("/api/analyze/url", json={"url": "example.com"}).json()["id"]
    r = client.post(f"/api/registry/submit/{rid}")
    assert r.status_code == 502 and "test ETH" in r.json()["detail"]


def test_hash_ignores_chain_field(client, fake_chain):
    rid = client.post("/api/analyze/url", json={"url": "example.com"}).json()["id"]
    from app import db

    before = report_hash(db.get_report(rid))
    client.post(f"/api/registry/submit/{rid}")
    assert report_hash(db.get_report(rid)) == before


def _tamper_and_reseal(rid, fake_chain, submitter, timestamp=None):
    """Hacker edits the stored report, seals the edited version himself and points the report at his seal."""
    from app import db
    from app.schemas import ChainRecord, RiskLevel

    report = db.get_report(rid)
    report.risk_level = RiskLevel.low_risk
    fake_hash = report_hash(report)
    slot = fake_chain.mine(SimpleNamespace(args=(bytes.fromhex(fake_hash[2:]), "low_risk")),
                           submitter=submitter, timestamp=timestamp)
    report.chain = ChainRecord(report_hash=fake_hash, chain_report_id=slot, tx_hash="0x" + "99" * 32,
                               network="sepolia", contract_address=fake_chain.address)
    db.save_report(report)


def test_fake_seal_by_another_wallet_is_rejected(client, fake_chain):
    rid = client.post("/api/analyze/url", json={"url": "example.com"}).json()["id"]
    client.post(f"/api/registry/submit/{rid}")
    _tamper_and_reseal(rid, fake_chain, submitter=HACKER)
    r = client.get(f"/api/registry/verify/{rid}").json()
    assert r["match"] is False and r["status"] == "untrusted_submitter" and HACKER in r["detail"]


def test_late_seal_is_rejected_even_from_official_wallet(client, fake_chain):
    rid = client.post("/api/analyze/url", json={"url": "example.com"}).json()["id"]
    client.post(f"/api/registry/submit/{rid}")
    _tamper_and_reseal(rid, fake_chain, submitter=OFFICIAL, timestamp=time.time() + 30 * 24 * 3600)
    r = client.get(f"/api/registry/verify/{rid}").json()
    assert r["match"] is False and r["status"] == "registered_late"


def test_verified_result_has_plain_english_detail(client, fake_chain):
    rid = client.post("/api/analyze/url", json={"url": "example.com"}).json()["id"]
    assert client.get(f"/api/registry/verify/{rid}").json()["status"] == "not_registered"
    client.post(f"/api/registry/submit/{rid}")
    r = client.get(f"/api/registry/verify/{rid}").json()
    assert r["status"] == "verified" and "exactly as it was" in r["detail"]


def test_old_reports_cannot_be_registered(client, fake_chain):
    from datetime import timedelta

    from app import db

    rid = client.post("/api/analyze/url", json={"url": "example.com"}).json()["id"]
    report = db.get_report(rid)
    report.created_at = report.created_at - timedelta(days=3)
    db.save_report(report)
    r = client.post(f"/api/registry/submit/{rid}")
    assert r.status_code == 409 and "within 24 hours" in r.json()["detail"]
