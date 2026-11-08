from app.config import settings
from app.registry.hashing import report_hash
from app.schemas import AnalysisReport


def test_health(client):
    assert client.get("/api/health").json() == {"status": "ok"}


def test_analyze_url_with_stubs_is_inconclusive_and_saved(client):
    r = client.post("/api/analyze/url", json={"url": "example.com"})
    assert r.status_code == 200
    report = r.json()
    assert report["input_type"] == "domain"
    assert report["normalized_target"] == "https://example.com/"
    assert report["risk_level"] == "inconclusive"
    assert {c["check"] for c in report["checks"]} == {"url", "dns", "threat_intel", "tls", "headers"}
    assert any("does not prove the site is safe" in lim for lim in report["limitations"])

    fetched = client.get(f"/api/reports/{report['id']}").json()
    assert fetched["id"] == report["id"]
    assert client.get("/api/reports").json()[0]["id"] == report["id"]


def test_invalid_url_rejected(client):
    assert client.post("/api/analyze/url", json={"url": "ftp://example.com"}).status_code == 422
    assert client.post("/api/analyze/url", json={"url": "   "}).status_code == 422


def test_message_extracts_and_checks_urls(client):
    text = "URGENT: your KYC expires today. Update at http://sbi-kyc-update.example/verify now!"
    report = client.post("/api/analyze/message", json={"text": text}).json()
    assert report["input_type"] == "message"
    assert report["extracted_indicators"]["urls"] == ["http://sbi-kyc-update.example/verify"]
    checks = [c["check"] for c in report["checks"]]
    assert checks[0] == "message" and "tls" in checks


def test_mock_mode_produces_findings(client, monkeypatch):
    monkeypatch.setattr(settings, "mock_analyzers", True)
    report = client.post("/api/analyze/url", json={"url": "https://paypa1-secure-login.com"}).json()
    assert report["risk_level"] in ("suspicious", "high_risk")
    assert report["coverage"] == 1.0


def test_registry_not_implemented_returns_501(client):
    rid = client.post("/api/analyze/url", json={"url": "example.com"}).json()["id"]
    assert client.post(f"/api/registry/submit/{rid}").status_code == 501
    verify = client.get(f"/api/registry/verify/{rid}").json()
    assert verify["status"] == "not_registered"


def test_hash_is_stable_across_save_and_load(client):
    data = client.post("/api/analyze/url", json={"url": "example.com"}).json()
    loaded = AnalysisReport.model_validate(client.get(f"/api/reports/{data['id']}").json())
    assert report_hash(loaded) == report_hash(AnalysisReport.model_validate(data))


def test_unknown_report_404(client):
    assert client.get("/api/reports/nope").status_code == 404


def test_internal_addresses_blocked_with_clear_message(client):
    for url in ("http://127.0.0.1/admin", "http://localhost:8000/", "http://169.254.169.254/latest/meta-data/",
                "http://10.0.0.5/", "http://[::1]/"):
        r = client.post("/api/analyze/url", json={"url": url})
        assert r.status_code == 422 and "Blocked for safety" in r.json()["detail"], url


def test_internal_links_in_messages_not_opened(client):
    text = "Check http://169.254.169.254/latest/meta-data/ and http://unresolvable-site-zzzz.example/x"
    report = client.post("/api/analyze/message", json={"text": text}).json()
    targets = {c["target"] for c in report["checks"] if c["check"] != "message"}
    assert targets == {"http://unresolvable-site-zzzz.example/x"}
    assert any("private/internal" in lim for lim in report["limitations"])
