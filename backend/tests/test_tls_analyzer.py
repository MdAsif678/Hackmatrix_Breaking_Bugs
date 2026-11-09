"""Offline tests for the TLS analyzer's certificate assessment (certificates are generated on the fly)."""
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from app.analyzers import tls_analyzer as tls
from app.schemas import Severity


def make_cert(cn="example.com", sans=("example.com",), days_valid=(-10, 80), key=None, issuer_org=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = subject if issuer_org is None else x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer_org),
        x509.NameAttribute(NameOID.COMMON_NAME, "Some Issuing CA"),
    ])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + timedelta(days=days_valid[0]))
        .not_valid_after(now + timedelta(days=days_valid[1]))
    )
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    return builder.sign(key, hashes.SHA256())


def ids(findings):
    return {f.id for f in findings}


def hs(verified=True, code=None, msg=None, protocol="TLSv1.3"):
    return tls._Handshake(ip="203.0.113.5", verified=verified, verify_code=code, verify_message=msg, protocol=protocol)


@pytest.mark.parametrize(
    "host,names,expected",
    [
        ("example.com", ["example.com"], True),
        ("www.example.com", ["*.example.com"], True),
        ("a.b.example.com", ["*.example.com"], False),  # wildcard covers one label only
        ("example.com", ["*.example.com"], False),
        ("paypa1.com", ["paypal.com"], False),
        ("EXAMPLE.com.", ["example.COM"], True),
    ],
)
def test_hostname_matching(host, names, expected):
    assert tls.hostname_matches(host, names) is expected


def test_healthy_cert_has_no_warnings():
    findings, data = tls._assess("example.com", hs(), make_cert())
    # generated test certs carry no CT log stamps, so no_sct is the only expected warning
    assert {f.id for f in findings if f.severity != Severity.info} == {"tls.no_sct"}
    assert data["key_type"].startswith("EC") and data["days_left"] >= 79


def test_expired_cert():
    findings, _ = tls._assess("example.com", hs(False, 10, "certificate has expired"), make_cert(days_valid=(-100, -5)))
    assert "tls.expired" in ids(findings)


def test_hostname_mismatch():
    findings, _ = tls._assess("login.paypa1.com", hs(False, 62, "Hostname mismatch"), make_cert())
    assert "tls.hostname_mismatch" in ids(findings)


def test_self_signed():
    findings, _ = tls._assess("example.com", hs(False, 18, "self-signed certificate"), make_cert())
    assert "tls.self_signed" in ids(findings)


def test_untrusted_issuer_from_verify_code():
    cert = make_cert(issuer_org="Unknown CA Ltd")
    findings, _ = tls._assess("example.com", hs(False, 20, "unable to get local issuer certificate"), cert)
    assert "tls.untrusted_issuer" in ids(findings)


def test_weak_rsa_key_and_sha1_signature(monkeypatch):
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    cert = make_cert(key=weak, issuer_org="Some CA")
    monkeypatch.setattr(tls, "_signature_hash", lambda c: "sha1")  # modern libraries refuse to create SHA-1 certs
    findings, data = tls._assess("example.com", hs(protocol="TLSv1"), cert)
    assert {"tls.weak_key", "tls.weak_signature", "tls.old_protocol"} <= ids(findings)
    assert data["key_bits"] == 1024


def test_publicly_trusted_cert_without_sct_flagged():
    findings, _ = tls._assess("example.com", hs(verified=True), make_cert(issuer_org="Some CA"))
    assert "tls.no_sct" in ids(findings)


def test_distrusted_ca_by_org():
    cert = make_cert(issuer_org="TrustCor Systems S. de R.L.")
    findings, _ = tls._assess("example.com", hs(), cert)
    f = next(f for f in findings if f.id == "tls.distrusted_ca")
    assert f.severity == Severity.critical and "TrustCor" in f.evidence


def test_distrust_date_cutoff():
    before = datetime(2024, 6, 1, tzinfo=timezone.utc)
    after = datetime(2025, 1, 1, tzinfo=timezone.utc)
    assert tls.match_distrusted_ca("Entrust, Inc.", before) is None
    assert tls.match_distrusted_ca("Entrust, Inc.", after)["name"] == "Entrust"
    assert tls.match_distrusted_ca("Let's Encrypt", after) is None


def test_ct_findings():
    assert ids(tls._ct_findings({"domain": "x.com", "certificates": 1, "first_seen_days_ago": 2})) == {"tls.ct_new_domain"}
    assert ids(tls._ct_findings({"domain": "x.com", "certificates": 3, "first_seen_days_ago": 20})) == {"tls.ct_young_domain"}
    assert tls._ct_findings({"domain": "x.com", "certificates": 900, "first_seen_days_ago": 4000}) == []
    assert tls._ct_findings({"source": "Cert Spotter", "domain": "x.com", "certificates": 2}) == []


def test_internal_target_rejected():
    import asyncio
    result = asyncio.run(tls.analyze("https://127.0.0.1/"))
    assert result.status == "error" and "non-public" in result.limitations[0]


def test_timeout_is_unreachable_not_no_https(monkeypatch):
    import asyncio

    async def ips(host, port):
        return ["203.0.113.9"]

    def timeout(*a, **k):
        raise TimeoutError("timed out")

    monkeypatch.setattr(tls, "resolve_and_validate", ips)
    monkeypatch.setattr(tls.socket, "create_connection", timeout)
    result = asyncio.run(tls.analyze("https://slow.example/"))
    assert result.status == "error" and not result.findings and "could not be reached" in result.limitations[0]


def test_refused_port_443_means_no_https(monkeypatch):
    import asyncio

    async def ips(host, port):
        return ["203.0.113.9"]

    def refused(*a, **k):
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(tls, "resolve_and_validate", ips)
    monkeypatch.setattr(tls.socket, "create_connection", refused)
    result = asyncio.run(tls.analyze("http://plain-http.example/"))
    assert result.status == "ok" and [f.id for f in result.findings] == ["tls.no_https"]
