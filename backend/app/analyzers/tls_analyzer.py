"""TLS certificate & trust analysis.

Owner: P1. Guide: docs/tasks/P1-lead.md

What it checks (passive only: two normal TLS handshakes + public lookups):
- trust: does the certificate verify against the Mozilla root store (certifi)? expired, not yet valid,
  hostname mismatch, self-signed, unknown/untrusted issuer, incomplete chain
- strength: key type/size, signature algorithm, negotiated TLS version
- revocation: OCSP status when the certificate names a responder (best effort)
- Certificate Transparency: embedded SCTs + crt.sh history (when was the domain first certified?)
- distrusted CAs: issuer matched against data/distrusted_cas.json (browser root-program decisions)

A valid certificate is reported as INFO only: it encrypts the connection, it does not prove legitimacy.
We never claim to detect a CA's internal key-generation weakness from a URL — only known distrust.

Run standalone:  python -m app.analyzers.tls_analyzer https://expired.badssl.com
"""
import asyncio
import base64
import json
import socket
import ssl
import warnings
from collections import Counter
from dataclasses import dataclass
from datetime import date, datetime, timezone
from functools import lru_cache
from typing import Optional
from urllib.parse import quote, urlsplit

import certifi
import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

from app.analyzers.base import error_result, run_cli
from app.config import DATA_DIR
from app.core.safe_fetch import UnsafeTargetError, resolve_and_validate, safe_fetch
from app.correlation.engine import registrable_domain
from app.schemas import CheckResult, Finding, Severity

CONNECT_TIMEOUT = 5.0
CT_TIMEOUT = 5.0
CT_MAX_BYTES = 3_000_000
SCT_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")
_VALIDATION_LEVELS = {
    "2.23.140.1.1": "Extended Validation (EV)",
    "2.23.140.1.2.2": "Organization Validated (OV)",
    "2.23.140.1.2.3": "Individual Validated (IV)",
    "2.23.140.1.2.1": "Domain Validated (DV)",
}
_OLD_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


# ---------------------------------------------------------------- handshakes (blocking, run in a thread)


@dataclass
class _Handshake:
    ip: str
    verified: bool = False
    verify_code: Optional[int] = None
    verify_message: Optional[str] = None
    handshake_error: Optional[str] = None
    der: Optional[bytes] = None
    protocol: Optional[str] = None
    cipher: Optional[str] = None


def _verified_handshake(hs: _Handshake, host: str) -> None:
    ctx = ssl.create_default_context(cafile=certifi.where())
    sock = socket.create_connection((hs.ip, 443), timeout=CONNECT_TIMEOUT)
    try:
        with ctx.wrap_socket(sock, server_hostname=host) as s:
            hs.verified = True
            hs.der = s.getpeercert(binary_form=True)
            hs.protocol = s.version()
            hs.cipher = (s.cipher() or [None])[0]
    except ssl.SSLCertVerificationError as exc:
        hs.verify_code, hs.verify_message = exc.verify_code, exc.verify_message
    except (ssl.SSLError, OSError) as exc:
        hs.handshake_error = f"{type(exc).__name__}: {exc}"
    finally:
        sock.close()


def _unverified_handshake(hs: _Handshake, host: str) -> None:
    """Read the certificate even when it is invalid (and allow legacy protocols to detect them)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with warnings.catch_warnings():  # deliberately allow legacy TLS so we can REPORT it
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        pass
    sock = socket.create_connection((hs.ip, 443), timeout=CONNECT_TIMEOUT)
    try:
        with ctx.wrap_socket(sock, server_hostname=host) as s:
            hs.der = s.getpeercert(binary_form=True)
            hs.protocol = s.version()
            hs.cipher = (s.cipher() or [None])[0]
    except (ssl.SSLError, OSError) as exc:
        hs.handshake_error = hs.handshake_error or f"{type(exc).__name__}: {exc}"
    finally:
        sock.close()


class NoHttpsError(ConnectionError):
    """The server actively refused port 443: the site does not offer HTTPS."""


def _handshakes(host: str, ips: list[str]) -> _Handshake:
    last: Optional[Exception] = None
    refused = False
    for ip in ips[:2]:
        hs = _Handshake(ip=ip)
        try:
            _verified_handshake(hs, host)
            if hs.der is None:
                _unverified_handshake(hs, host)
            return hs
        except OSError as exc:  # could not even open a TCP connection to this IP
            last = exc
            refused = refused or isinstance(exc, ConnectionRefusedError)
    # Refused = the site has no HTTPS (a fact about the site). A timeout or network error only means we could not
    # reach it from here, which says nothing about the site.
    error = NoHttpsError if refused else ConnectionError
    raise error(f"could not connect to port 443 ({type(last).__name__}: {last})")


# ---------------------------------------------------------------- certificate helpers


def _attr(name: x509.Name, oid) -> Optional[str]:
    vals = name.get_attributes_for_oid(oid)
    return str(vals[0].value) if vals else None


def _sans(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    return ext.get_values_for_type(x509.DNSName) + [str(i) for i in ext.get_values_for_type(x509.IPAddress)]


def hostname_matches(host: str, names: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for name in names:
        name = name.lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*.") and "." in host and host.split(".", 1)[1] == name[2:]:
            return True
    return False


def _key_info(cert: x509.Certificate) -> tuple[str, int]:
    pk = cert.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        return "RSA", pk.key_size
    if isinstance(pk, ec.EllipticCurvePublicKey):
        return f"EC ({pk.curve.name})", pk.key_size
    if isinstance(pk, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(pk, ed448.Ed448PublicKey):
        return "Ed448", 456
    if isinstance(pk, dsa.DSAPublicKey):
        return "DSA", pk.key_size
    return type(pk).__name__, 0


def _signature_hash(cert: x509.Certificate) -> str:
    try:
        algo = cert.signature_hash_algorithm
        return algo.name if algo else cert.signature_algorithm_oid._name
    except Exception:
        return cert.signature_algorithm_oid.dotted_string


def _validation_level(cert: x509.Certificate) -> Optional[str]:
    try:
        policies = cert.extensions.get_extension_for_class(x509.CertificatePolicies).value
    except x509.ExtensionNotFound:
        return None
    for p in policies:
        if p.policy_identifier.dotted_string in _VALIDATION_LEVELS:
            return _VALIDATION_LEVELS[p.policy_identifier.dotted_string]
    return None


def _aia(cert: x509.Certificate) -> tuple[list[str], list[str]]:
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
    except x509.ExtensionNotFound:
        return [], []
    ocsp_urls = [d.access_location.value for d in aia if d.access_method == AuthorityInformationAccessOID.OCSP]
    issuers = [d.access_location.value for d in aia if d.access_method == AuthorityInformationAccessOID.CA_ISSUERS]
    return ocsp_urls, issuers


def _embedded_sct_count(cert: x509.Certificate) -> int:
    try:
        return len(cert.extensions.get_extension_for_oid(SCT_OID).value)
    except x509.ExtensionNotFound:
        return 0
    except Exception:
        return 1  # present but not parseable: still counts as logged


def _load_any_cert(body: bytes) -> Optional[x509.Certificate]:
    for loader in (
        x509.load_der_x509_certificate,
        x509.load_pem_x509_certificate,
        lambda b: pkcs7.load_der_pkcs7_certificates(b)[0],
        lambda b: pkcs7.load_pem_pkcs7_certificates(b)[0],
    ):
        try:
            return loader(body)
        except Exception:
            continue
    return None


@lru_cache(maxsize=1)
def _distrusted_cas() -> list[dict]:
    try:
        return json.loads((DATA_DIR / "distrusted_cas.json").read_text(encoding="utf-8"))["authorities"]
    except (OSError, ValueError, KeyError):
        return []


def match_distrusted_ca(issuer_org: Optional[str], not_before: datetime) -> Optional[dict]:
    if not issuer_org:
        return None
    for entry in _distrusted_cas():
        if issuer_org.strip().lower() in (o.lower() for o in entry["issuer_orgs"]):
            after = entry.get("issued_after")
            if after is None or not_before.date() > date.fromisoformat(after):
                return entry
    return None


# ---------------------------------------------------------------- network lookups (async)


def _crl_urls(cert: x509.Certificate) -> list[str]:
    try:
        dps = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
    except x509.ExtensionNotFound:
        return []
    return [n.value for dp in dps for n in (dp.full_name or []) if isinstance(n, x509.UniformResourceIdentifier)]


async def _fetch_issuer(cert: x509.Certificate) -> Optional[x509.Certificate]:
    _, issuer_urls = _aia(cert)
    if not issuer_urls:
        return None
    try:
        return _load_any_cert((await safe_fetch(issuer_urls[0])).body)
    except (UnsafeTargetError, httpx.HTTPError):
        return None


async def _check_ocsp(cert: x509.Certificate, issuer: x509.Certificate, url: str) -> tuple[Optional[str], Optional[str]]:
    req = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA1()).build()
    encoded = base64.b64encode(req.public_bytes(serialization.Encoding.DER)).decode()
    resp = ocsp.load_der_ocsp_response((await safe_fetch(url.rstrip("/") + "/" + quote(encoded, safe=""))).body)
    if resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return None, f"OCSP responder answered {resp.response_status.name}"
    if resp.certificate_status == ocsp.OCSPCertStatus.REVOKED:
        reason = resp.revocation_reason.name if resp.revocation_reason else "unspecified"
        return "revoked", f"OCSP: revoked on {resp.revocation_time_utc:%Y-%m-%d} (reason: {reason})"
    return resp.certificate_status.name.lower(), None


async def _check_crl(cert: x509.Certificate, issuer: Optional[x509.Certificate], url: str) -> tuple[Optional[str], Optional[str]]:
    fetched = await safe_fetch(url)
    if fetched.truncated:
        return None, "CRL too large to download"
    crl = x509.load_der_x509_crl(fetched.body) if not fetched.body.startswith(b"-----") else x509.load_pem_x509_crl(fetched.body)
    if issuer is None:
        return None, "could not verify the CRL signature (issuer certificate unavailable)"
    if not crl.is_signature_valid(issuer.public_key()):
        return None, "CRL signature invalid; ignored"
    entry = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
    if entry is None:
        return "good", None
    return "revoked", f"CRL: revoked on {entry.revocation_date_utc:%Y-%m-%d} ({url})"


async def _check_revocation(cert: x509.Certificate) -> tuple[Optional[str], Optional[str]]:
    """Return (status, note). status: good / revoked / unknown / None (not checked). Tries OCSP, then CRL."""
    ocsp_urls, _ = _aia(cert)
    crl_urls = _crl_urls(cert)
    if not ocsp_urls and not crl_urls:
        return None, "Revocation not checked: the certificate lists no OCSP responder or CRL"
    issuer = await _fetch_issuer(cert)
    notes: list[str] = []
    if ocsp_urls and issuer is not None:
        try:
            status, note = await _check_ocsp(cert, issuer, ocsp_urls[0])
            if status:
                return status, note
            notes.append(note or "OCSP inconclusive")
        except (UnsafeTargetError, httpx.HTTPError, ValueError) as exc:
            notes.append(f"OCSP failed ({type(exc).__name__})")
    if crl_urls:
        try:
            status, note = await _check_crl(cert, issuer, crl_urls[0])
            if status:
                return status, note
            notes.append(note or "CRL inconclusive")
        except (UnsafeTargetError, httpx.HTTPError, ValueError) as exc:
            notes.append(f"CRL failed ({type(exc).__name__})")
    return None, "Revocation not checked: " + "; ".join(notes)


async def _ct_lookup(domain: str) -> dict:
    """Certificate Transparency history: crt.sh (full history), falling back to Cert Spotter (current certs only)."""
    try:
        return await _crtsh_lookup(domain)
    except Exception as crtsh_exc:
        try:
            return await _certspotter_lookup(domain)
        except Exception:
            raise RuntimeError(f"crt.sh {type(crtsh_exc).__name__}; Cert Spotter also failed") from crtsh_exc


async def _certspotter_lookup(domain: str) -> dict:
    async with httpx.AsyncClient(timeout=CT_TIMEOUT, headers={"User-Agent": "TrustLensScanner/0.1"}) as client:
        resp = await client.get("https://api.certspotter.com/v1/issuances", params={"domain": domain, "expand": "issuer"})
    if resp.status_code != 200:
        raise RuntimeError(f"Cert Spotter HTTP {resp.status_code}")
    entries = resp.json()
    issuers = Counter((e.get("issuer") or {}).get("friendly_name") or "?" for e in entries)
    return {
        "source": "Cert Spotter",
        "domain": domain,
        "scope": "currently valid certificates only (full history unavailable)",
        "certificates": len(entries),
        "revoked_in_logs": sum(1 for e in entries if e.get("revoked")),
        "issuers": dict(issuers.most_common(5)),
    }


async def _crtsh_lookup(domain: str) -> dict:
    """Full Certificate Transparency history from crt.sh (a fixed public service)."""
    buf = bytearray()
    async with httpx.AsyncClient(timeout=CT_TIMEOUT, headers={"User-Agent": "TrustLensScanner/0.1"}) as client:
        async with client.stream("GET", "https://crt.sh/", params={"q": domain, "output": "json"}) as resp:
            if resp.status_code != 200:
                raise RuntimeError(f"crt.sh HTTP {resp.status_code}")
            async for chunk in resp.aiter_bytes():
                buf += chunk
                if len(buf) > CT_MAX_BYTES:
                    return {"source": "crt.sh", "domain": domain, "large_history": True,
                            "note": "Thousands of certificates logged: long-established domain"}
    entries = json.loads(bytes(buf) or b"[]")
    if not entries:
        return {"source": "crt.sh", "domain": domain, "certificates": 0}

    def parse(ts: str) -> datetime:
        d = datetime.fromisoformat(ts)
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)

    starts = [parse(e["not_before"]) for e in entries if e.get("not_before")]
    issuers = Counter()
    for e in entries:
        org = next((p.split("=", 1)[1] for p in e.get("issuer_name", "").split(", ") if p.startswith("O=")), None)
        issuers[org or e.get("issuer_name", "?")] += 1
    now = datetime.now(timezone.utc)
    return {
        "source": "crt.sh",
        "domain": domain,
        "certificates": len(entries),
        "first_seen": min(starts).isoformat() if starts else None,
        "first_seen_days_ago": (now - min(starts)).days if starts else None,
        "issued_last_30_days": sum(1 for s in starts if (now - s).days <= 30),
        "issuers": dict(issuers.most_common(5)),
    }


# ---------------------------------------------------------------- findings


def _f(fid: str, title: str, sev: Severity, evidence: str, source: str = "TLS handshake",
       impact: Optional[str] = None, rec: Optional[str] = None) -> Finding:
    return Finding(id=f"tls.{fid}", check="tls", title=title, severity=sev, evidence=evidence, source=source,
                   impact=impact, recommendation=rec)


_VERIFY_CODE_FINDINGS = {
    # OpenSSL X509_V_ERR codes not already covered by our own certificate inspection
    2: ("untrusted_issuer", "Certificate issuer is not trusted", Severity.high),
    19: ("untrusted_issuer", "Certificate chains to an untrusted root", Severity.high),
    20: ("untrusted_issuer", "Certificate issuer is not trusted", Severity.high),
    21: ("incomplete_chain", "Certificate chain is incomplete", Severity.medium),
    23: ("revoked", "Certificate has been revoked", Severity.critical),
    24: ("invalid_ca", "Certificate was signed by an invalid CA certificate", Severity.high),
}
_COVERED_CODES = {9, 10, 18, 62}  # not yet valid, expired, self-signed, hostname mismatch


def _assess(host: str, hs: _Handshake, cert: x509.Certificate) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    now = datetime.now(timezone.utc)
    nb, na = cert.not_valid_before_utc, cert.not_valid_after_utc
    days_left = (na - now).days
    subject_cn = _attr(cert.subject, NameOID.COMMON_NAME)
    issuer_org = _attr(cert.issuer, NameOID.ORGANIZATION_NAME)
    issuer_cn = _attr(cert.issuer, NameOID.COMMON_NAME)
    sans = _sans(cert)
    key_type, key_bits = _key_info(cert)
    sig = _signature_hash(cert)
    level = _validation_level(cert)
    scts = _embedded_sct_count(cert)
    issuer_label = issuer_org or issuer_cn or cert.issuer.rfc4514_string()

    data = {
        "ip": hs.ip,
        "verified": hs.verified,
        "verify_error": hs.verify_message,
        "protocol": hs.protocol,
        "cipher": hs.cipher,
        "subject_cn": subject_cn,
        "subject_org": _attr(cert.subject, NameOID.ORGANIZATION_NAME),
        "issuer_org": issuer_org,
        "issuer_cn": issuer_cn,
        "san_count": len(sans),
        "sans": sans[:20],
        "not_before": nb.isoformat(),
        "not_after": na.isoformat(),
        "days_left": days_left,
        "serial": format(cert.serial_number, "x"),
        "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(":"),
        "signature_hash": sig,
        "key_type": key_type,
        "key_bits": key_bits,
        "validation_level": level,
        "embedded_scts": scts,
    }

    # --- trust / identity
    if now > na:
        findings.append(_f("expired", "Certificate has expired", Severity.high,
                           f"notAfter={na:%Y-%m-%d} ({-days_left} days ago)",
                           impact="Browsers show a security warning; an unmaintained or fake site is likely.",
                           rec="Do not enter any personal information on this site."))
    elif now < nb:
        findings.append(_f("not_yet_valid", "Certificate is not valid yet", Severity.high, f"notBefore={nb:%Y-%m-%d}"))
    elif days_left < 14:
        findings.append(_f("expiring_soon", "Certificate expires very soon", Severity.low,
                           f"notAfter={na:%Y-%m-%d} ({days_left} days left)"))

    names = sans or ([subject_cn] if subject_cn else [])
    if not hostname_matches(host, names):
        shown = ", ".join(names[:5]) + (f" (+{len(names) - 5} more)" if len(names) > 5 else "")
        findings.append(_f("hostname_mismatch", "Certificate was issued for a different website", Severity.high,
                           f"site={host}; certificate is for: {shown or '(no names)'}",
                           impact="The certificate does not prove this site's identity; it may be an impersonation.",
                           rec="Leave the site unless you can confirm the address through an official channel."))

    if cert.issuer == cert.subject and not hs.verified:
        findings.append(_f("self_signed", "Self-signed certificate", Severity.high,
                           f"issuer = subject = {cert.subject.rfc4514_string()[:120]}",
                           impact="No trusted authority vouches for this site; anyone can create such a certificate."))

    if not hs.verified and hs.verify_code is not None and hs.verify_code not in _COVERED_CODES:
        fid, title, sev = _VERIFY_CODE_FINDINGS.get(
            hs.verify_code, ("verification_failed", "Certificate failed verification", Severity.high))
        if not any(f.id == f"tls.{fid}" for f in findings):
            findings.append(_f(fid, title, sev, f"{hs.verify_message} (OpenSSL code {hs.verify_code}); issuer: {issuer_label}",
                               source="TLS verification (Mozilla root store)"))

    distrust = match_distrusted_ca(issuer_org, nb)
    if distrust:
        findings.append(_f("distrusted_ca", "Issued by a Certificate Authority that browsers distrust", Severity.critical,
                           f"issuer O={issuer_org}; {distrust['name']}: {distrust['reason']}",
                           source=f"CA distrust list ({distrust['source']})",
                           impact="Certificates from this authority cannot be relied on to prove identity.",
                           rec="Treat the site's identity as unverified."))

    # --- strength
    if key_type == "RSA" and key_bits < 2048 or key_type == "DSA" or (key_type.startswith("EC") and key_bits < 256):
        findings.append(_f("weak_key", "Weak certificate key", Severity.high, f"{key_type} {key_bits}-bit",
                           impact="Weak keys can be broken, allowing impersonation."))
    if sig.lower() in ("sha1", "md5", "md2"):
        findings.append(_f("weak_signature", "Outdated signature algorithm", Severity.medium, f"signature hash = {sig}"))
    if hs.protocol in _OLD_PROTOCOLS:
        findings.append(_f("old_protocol", "Outdated TLS protocol version", Severity.medium,
                           f"negotiated {hs.protocol}", rec="Site owner should require TLS 1.2 or newer."))

    # --- certificate transparency (only meaningful for publicly trusted certificates)
    if hs.verified and scts == 0:
        findings.append(_f("no_sct", "Certificate not publicly logged (Certificate Transparency)", Severity.medium,
                           "no embedded SCTs in the certificate", source="certificate extensions",
                           impact="Unlogged certificates can hide mis-issuance; Chrome and Safari normally require CT."))
    return findings, data


def _ct_findings(ct: dict) -> list[Finding]:
    days = ct.get("first_seen_days_ago")
    if days is None:
        return []
    evidence = f"first certificate for {ct['domain']} logged {days} day(s) ago ({ct['certificates']} certificates in CT logs)"
    if days < 7:
        return [_f("ct_new_domain", "Domain received its first certificate very recently", Severity.medium, evidence,
                   source="Certificate Transparency (crt.sh)",
                   impact="Phishing sites are typically set up days before use.")]
    if days < 30:
        return [_f("ct_young_domain", "Domain received its first certificate recently", Severity.low, evidence,
                   source="Certificate Transparency (crt.sh)")]
    return []


# ---------------------------------------------------------------- entry point


async def analyze(target: str) -> CheckResult:
    try:
        parts = urlsplit(target)
        host = (parts.hostname or "").rstrip(".")
        try:
            ips = await resolve_and_validate(host, 443)
        except UnsafeTargetError as exc:
            return CheckResult(check="tls", status="error", limitations=[f"Certificate not checked: {exc}."])

        ct_domain = registrable_domain(host)
        ct_task = asyncio.create_task(_ct_lookup(ct_domain))
        limitations: list[str] = []

        try:
            hs = await asyncio.to_thread(_handshakes, host, ips)
        except NoHttpsError as exc:
            ct_task.cancel()
            return CheckResult(
                check="tls", status="ok",
                findings=[_f("no_https", "Site does not accept HTTPS connections", Severity.medium, f"{host}:443 {exc}",
                             impact="Anything you type on this site travels unencrypted.",
                             rec="Never enter passwords or payment details on a site without HTTPS.")],
                data={"https_available": False},
            )
        except ConnectionError as exc:
            ct_task.cancel()
            return CheckResult(check="tls", status="error",
                               limitations=["Certificate not checked: the site could not be reached on its secure "
                                            "(HTTPS) port from our server. It may be offline or blocking us."])

        if hs.der is None:
            ct_task.cancel()
            return CheckResult(check="tls", status="error",
                               limitations=["Certificate not checked: the site answered but a secure connection could "
                                            "not be set up, so its certificate could not be read."])

        cert = x509.load_der_x509_certificate(hs.der)
        findings, data = _assess(host, hs, cert)
        if parts.scheme == "http":
            data["note"] = "URL uses plain HTTP; the certificate was inspected on port 443"

        revocation, note = await _check_revocation(cert) if hs.verified else (None, "Revocation not checked: certificate not trusted")
        data["revocation"] = revocation or "not checked"
        if note and revocation != "revoked":
            limitations.append(note)
        if revocation == "revoked" and not any(f.id == "tls.revoked" for f in findings):
            findings.append(_f("revoked", "Certificate has been revoked", Severity.critical, note or "revoked",
                               source="OCSP/CRL", impact="The issuing authority has withdrawn this certificate.",
                               rec="Do not trust this site's identity or enter any information."))

        try:
            ct = await ct_task
            data["ct"] = ct
            findings.extend(_ct_findings(ct))
        except Exception as exc:
            limitations.append(f"Certificate Transparency history unavailable ({exc})")

        if hs.verified and not any(f.severity in (Severity.high, Severity.critical) for f in findings):
            level = data.get("validation_level") or "unknown validation level"
            findings.append(_f("valid_not_proof", "Valid certificate — not proof the site is legitimate", Severity.info,
                               f"trusted chain, issued by {data.get('issuer_org') or data.get('issuer_cn')}; {level}",
                               impact="HTTPS encrypts the connection, but scammers can get valid certificates too."))
        limitations.append("A valid certificate is never treated as proof that a website is safe.")
        return CheckResult(check="tls", status="ok", findings=findings, data=data, limitations=limitations)
    except Exception as exc:  # never raise
        return error_result("tls", exc)


if __name__ == "__main__":
    run_cli(analyze)
