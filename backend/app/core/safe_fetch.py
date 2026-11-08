"""SSRF-safe HTTP fetching — THE ONLY way to request a user-supplied URL. Owner: P1. Guide: docs/tasks/P1-lead.md

Never call httpx/requests/urllib directly on a user-supplied URL anywhere else.

How it protects the server (AGENTS.md §8):
- only http/https, only ports 80/443, credentials in the URL are never sent
- the hostname is resolved and EVERY resolved IP must be public; private, loopback, link-local,
  multicast, reserved, CGNAT and cloud-metadata addresses are rejected (also when written as
  decimal/hex/IPv4-mapped-IPv6 tricks, because we validate the resolved address, not the text)
- we connect to the exact IP we validated (Host header + TLS SNI keep the real hostname), so a
  DNS-rebinding attacker cannot swap in an internal IP between the check and the connection
- redirects are followed manually (max 5) and every hop is validated again
- per-request timeout, body capped at 1 MB, nothing executed, nothing written to disk

TLS certificates are NOT verified here on purpose: we only read headers/content, never send secrets,
and certificate trust is assessed separately by analyzers/tls_analyzer.py. Bad-certificate sites can
therefore still be inspected.
"""
import asyncio
import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from app.config import settings


class UnsafeTargetError(Exception):
    """Raised when a URL or any redirect hop points to a forbidden destination."""


@dataclass
class FetchResult:
    final_url: str
    status_code: int
    headers: dict[str, str]  # header names lower-cased
    body: bytes  # truncated to MAX_BODY_BYTES
    redirect_chain: list[str] = field(default_factory=list)  # every URL visited, in order (incl. final)
    resolved_ip: Optional[str] = None
    truncated: bool = False
    redirect_statuses: list[int] = field(default_factory=list)  # status code of each redirect hop


MAX_BODY_BYTES = 1_000_000
MAX_REDIRECTS = 5
ALLOWED_PORTS = {"http": 80, "https": 443}
USER_AGENT = "TrustLensScanner/0.1 (+passive security check)"
_REDIRECT_CODES = {301, 302, 303, 307, 308}
_NAT64_PREFIXES = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))


# ---------------------------------------------------------------- IP validation


def is_forbidden_ip(ip_text: str) -> bool:
    """True if the address is not a normal public internet address."""
    try:
        ip = ipaddress.ip_address(ip_text.split("%", 1)[0])  # drop IPv6 zone id
    except ValueError:
        return True
    if isinstance(ip, ipaddress.IPv6Address):
        if any(ip in net for net in _NAT64_PREFIXES):
            # NAT64 (used by many mobile/IPv6-only networks): the real destination is the IPv4 in the last 32 bits.
            return is_forbidden_ip(str(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)))
        embedded = ip.ipv4_mapped or ip.sixtofour or (ip.teredo[1] if ip.teredo else None)
        if embedded is not None and is_forbidden_ip(str(embedded)):
            return True
    return (
        not ip.is_global
        or ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


async def resolve_and_validate(host: str, port: int) -> list[str]:
    """Resolve `host` and return its IPs (IPv4 first). Raises UnsafeTargetError if any IP is forbidden.

    Reused by tls_analyzer before it opens a raw TLS connection.
    """
    if not host:
        raise UnsafeTargetError("URL has no hostname")
    if host.lower() in ("localhost", "localhost.localdomain") or host.lower().endswith(".localhost"):
        raise UnsafeTargetError("Refusing to inspect localhost")
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, port, type=socket.SOCK_STREAM),
            timeout=min(5.0, settings.check_timeout_seconds),
        )
    except (socket.gaierror, asyncio.TimeoutError) as exc:
        raise UnsafeTargetError(f"Could not resolve {host}: {exc.__class__.__name__}") from exc

    ips: list[str] = []
    for family, *_rest, sockaddr in infos:
        ip = sockaddr[0]
        if ip not in ips:
            ips.append(ip)
    if not ips:
        raise UnsafeTargetError(f"{host} did not resolve to any address")
    bad = [ip for ip in ips if is_forbidden_ip(ip)]
    if bad:
        # Any internal address is a red flag (round-robin rebinding trick), so reject the whole host.
        raise UnsafeTargetError(f"{host} resolves to a non-public address ({bad[0]}); refusing to connect")
    ips.sort(key=lambda a: ":" in a)  # IPv4 first: more networks have working IPv4
    return ips


# ---------------------------------------------------------------- URL validation


@dataclass
class _Target:
    url: str  # cleaned URL (no credentials)
    scheme: str
    host: str
    port: int


def validate_url(url: str) -> _Target:
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_PORTS:
        raise UnsafeTargetError(f"Scheme '{scheme or '(none)'}' is not allowed; only http and https")
    try:
        port = parts.port or ALLOWED_PORTS[scheme]
    except ValueError as exc:
        raise UnsafeTargetError("Invalid port in URL") from exc
    if port != ALLOWED_PORTS[scheme]:
        raise UnsafeTargetError(f"Port {port} is not allowed; only 80 (http) and 443 (https)")
    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise UnsafeTargetError("URL has no hostname")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        pass  # leave as is; DNS resolution will fail if it is invalid
    netloc = f"[{host}]" if ":" in host else host  # credentials stripped, default port implied
    clean = urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))
    return _Target(url=clean, scheme=scheme, host=host, port=port)


def _ip_url(target: _Target, ip: str) -> str:
    parts = urlsplit(target.url)
    netloc = f"[{ip}]" if ":" in ip else ip
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, ""))


async def _read_capped(resp: httpx.Response) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    size = 0
    async for chunk in resp.aiter_bytes():
        chunks.append(chunk)
        size += len(chunk)
        if size >= MAX_BODY_BYTES:
            return b"".join(chunks)[:MAX_BODY_BYTES], True
    return b"".join(chunks), False


# ---------------------------------------------------------------- main entry point


async def safe_fetch(
    url: str,
    method: str = "GET",
    max_redirects: int = MAX_REDIRECTS,
    *,
    transport: Optional[httpx.AsyncBaseTransport] = None,  # tests only
) -> FetchResult:
    """Fetch `url` safely. Raises UnsafeTargetError for forbidden targets, httpx errors for network failures."""
    method = method.upper()
    if method not in ("GET", "HEAD"):
        raise UnsafeTargetError("Only GET and HEAD are allowed")

    # Short connect timeout so we can fall back to a second IP within the overall check timeout.
    timeout = httpx.Timeout(settings.check_timeout_seconds, connect=min(3.0, settings.check_timeout_seconds))
    chain: list[str] = []
    statuses: list[int] = []
    current = url

    async with httpx.AsyncClient(
        follow_redirects=False,
        verify=False,  # see module docstring
        trust_env=False,  # ignore proxy env vars
        timeout=timeout,
        transport=transport,
        headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"},
    ) as client:
        for _hop in range(max_redirects + 1):
            target = validate_url(current)
            ips = await resolve_and_validate(target.host, target.port)
            chain.append(target.url)

            last_error: Optional[Exception] = None
            for ip in ips[:2]:
                extensions = {"sni_hostname": target.host} if target.scheme == "https" else {}
                try:
                    async with client.stream(
                        method,
                        _ip_url(target, ip),
                        headers={"Host": target.host},
                        extensions=extensions,
                    ) as resp:
                        location = resp.headers.get("location")
                        if resp.status_code in _REDIRECT_CODES and location:
                            statuses.append(resp.status_code)
                            current = urljoin(target.url, location.strip())
                            break  # follow the redirect (validated at the top of the loop)
                        body, truncated = (b"", False) if method == "HEAD" else await _read_capped(resp)
                        return FetchResult(
                            final_url=target.url,
                            status_code=resp.status_code,
                            headers={k.lower(): v for k, v in resp.headers.items()},
                            body=body,
                            redirect_chain=chain,
                            resolved_ip=ip,
                            truncated=truncated,
                            redirect_statuses=statuses,
                        )
                except (httpx.ConnectError, httpx.ConnectTimeout) as exc:  # try the next validated IP
                    last_error = exc
                    continue
            else:
                raise last_error or httpx.ConnectError(f"Could not connect to {target.host}")

    raise UnsafeTargetError(f"Too many redirects (more than {max_redirects})")
