"""Request limits for the public API. Owner: P1.

The API is open to anyone, and two endpoints spend something real:
- a check uses the Gemini quota and calls outside services (threat feeds, RDAP, certificate logs);
- a seal sends an Ethereum transaction paid from the TrustLens testnet wallet.
So each client IP gets a sliding-window budget, and there are global caps so even many IPs together cannot drain
the AI quota or the wallet. Limits live in memory: they reset when the server restarts, which is fine for a single
small instance and needs no extra service.

Exceeding a limit returns HTTP 429 with a plain-English message and a Retry-After header.
"""
import math
import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

from app.config import settings

# (name, max requests, window in seconds). Per client IP unless the name starts with "global".
CHECK_RULES = [("check-minute", 8, 60), ("check-hour", 60, 3600), ("global-check-hour", 600, 3600)]
SEAL_RULES = [("seal-hour", 3, 3600), ("global-seal-day", 40, 86400)]

_hits: dict[str, deque[float]] = defaultdict(deque)
_lock = threading.Lock()


def client_ip(request: Request) -> str:
    """The visitor's IP. Behind Render's proxy the real address is the first entry of X-Forwarded-For."""
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _message(rule: str, wait: int) -> str:
    minutes = max(1, math.ceil(wait / 60))
    if rule.startswith("global-seal"):
        return ("TrustLens has sealed the maximum number of reports for today, to protect its testnet wallet. "
                "Try again tomorrow.")
    if rule.startswith("global"):
        return "TrustLens is very busy right now. Try again in a few minutes."
    if rule.startswith("seal"):
        return f"You have sealed several reports in the last hour. Try again in about {minutes} minute{'s' if minutes > 1 else ''}."
    return f"Too many checks from your network in a short time. Try again in about {minutes} minute{'s' if minutes > 1 else ''}."


def enforce(request: Request, rules: list[tuple[str, int, int]]) -> None:
    """Count this request against every rule; raise 429 (and count nothing) if any rule is already full."""
    if not settings.rate_limit_enabled:
        return
    ip = client_ip(request)
    now = time.monotonic()
    with _lock:
        keys = []
        for name, limit, window in rules:
            key = name if name.startswith("global") else f"{name}:{ip}"
            hits = _hits[key]
            while hits and now - hits[0] >= window:
                hits.popleft()
            if len(hits) >= limit:
                wait = int(window - (now - hits[0])) + 1
                raise HTTPException(status_code=429, detail=_message(name, wait), headers={"Retry-After": str(wait)})
            keys.append(key)
        for key in keys:
            _hits[key].append(now)


def reset() -> None:
    """Forget all counts (tests)."""
    with _lock:
        _hits.clear()
