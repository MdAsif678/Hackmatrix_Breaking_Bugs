"""SSRF-safe HTTP fetching — THE ONLY way to request a user-supplied URL. Owner: P2.

Never call httpx/requests/urllib directly on a user-supplied URL anywhere else.

Required behaviour (AGENTS.md §8):
- only http/https, ports 80/443
- resolve DNS and reject private, loopback, link-local, multicast, reserved and metadata IPs
  (127.0.0.0/8, 10/8, 172.16/12, 192.168/16, 169.254/16, ::1, fc00::/7, fe80::/10, 0.0.0.0)
- connect to the IP you validated (avoid DNS-rebinding), keep the Host header / SNI
- follow redirects MANUALLY (max 5), re-validating every hop
- timeout <= settings.check_timeout_seconds, body capped at 1 MB
- never execute JavaScript, never save files
"""
from dataclasses import dataclass, field


class UnsafeTargetError(Exception):
    """Raised when a URL or any redirect hop points to a forbidden destination."""


@dataclass
class FetchResult:
    final_url: str
    status_code: int
    headers: dict[str, str]
    body: bytes  # truncated to MAX_BODY_BYTES
    redirect_chain: list[str] = field(default_factory=list)  # every URL visited, in order
    resolved_ip: str | None = None
    truncated: bool = False


MAX_BODY_BYTES = 1_000_000
MAX_REDIRECTS = 5


async def safe_fetch(url: str, method: str = "GET", max_redirects: int = MAX_REDIRECTS) -> FetchResult:
    # TODO(P2): implement per the rules above.
    raise NotImplementedError("safe_fetch is not implemented yet")
