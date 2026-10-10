"""API key authentication and per-IP rate limiting for the HTTP API (audit H-3, M-5)."""

import hashlib
import hmac
import ipaddress
import logging
import math
import time
from collections import deque
from typing import Annotated

from fastapi import Header, HTTPException, Request

from app import config

log = logging.getLogger(__name__)

API_KEY_HEADER = "X-API-Key"
MIN_KEY_LENGTH = 32


def _digest(value: str) -> bytes:
    return hashlib.sha256(value.encode()).digest()


def _valid_keys() -> list[str]:
    return [k for k in config.API_KEYS if len(k) >= MIN_KEY_LENGTH]


def log_auth_config() -> None:
    """Called at startup so a misconfiguration is visible before the first request."""
    if config.AUTH_DISABLED:
        log.warning("API authentication is DISABLED (STACKWATCH_AUTH_DISABLED); bind to localhost")
    elif len(_valid_keys()) < len(config.API_KEYS):
        log.warning("Ignoring STACKWATCH_API_KEYS entries shorter than %d characters",
                    MIN_KEY_LENGTH)
    if not config.AUTH_DISABLED and not _valid_keys():
        log.error("No usable API key configured; protected routes will return 503")


def require_api_key(x_api_key: Annotated[str | None, Header()] = None) -> None:
    if config.AUTH_DISABLED:
        return
    keys = _valid_keys()
    if not keys:
        raise HTTPException(503, "API authentication is not configured")
    # Compare fixed-length digests against every key, so timing reveals neither the key
    # length nor which key matched.
    supplied = _digest(x_api_key or "")
    matched = False
    for key in keys:
        matched |= hmac.compare_digest(supplied, _digest(key))
    if not x_api_key or not matched:
        raise HTTPException(401, "Missing or invalid API key",
                            headers={"WWW-Authenticate": API_KEY_HEADER})


def client_key(host: str | None) -> str:
    """IPv6 clients are bucketed by /64, since one host usually controls the whole prefix."""
    if not host:
        return "unknown"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host
    if ip.version == 6:
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return str(ip)


class RateLimiter:
    """Sliding-window request limit per client, held in process memory.

    Keyed on the socket peer address, never X-Forwarded-For, which any client can forge.
    Behind a reverse proxy every caller shares the proxy's bucket, and with several
    workers each process keeps its own count.
    """

    SWEEP_AT = 10_000

    def __init__(self, window: float = 60.0, clock=time.monotonic):
        self.window = window
        self.clock = clock
        self._hits: dict[str, deque[float]] = {}

    def hit(self, key: str, limit: int) -> float | None:
        """Record a request. Returns seconds until a retry would pass, or None if allowed."""
        now = self.clock()
        if len(self._hits) >= self.SWEEP_AT:
            self._sweep(now)
        hits = self._hits.setdefault(key, deque())
        while hits and hits[0] <= now - self.window:
            hits.popleft()
        if len(hits) >= limit:
            return hits[0] + self.window - now
        hits.append(now)
        return None

    def _sweep(self, now: float) -> None:
        cutoff = now - self.window
        for key in [k for k, h in self._hits.items() if not h or h[-1] <= cutoff]:
            del self._hits[key]

    def reset(self) -> None:
        self._hits.clear()


limiter = RateLimiter()


def rate_limit(request: Request) -> None:
    """Throttles the routes that make the server do outbound or expensive work."""
    limit = config.RATE_LIMIT_PER_MINUTE
    if limit <= 0:
        return
    retry = limiter.hit(client_key(request.client.host if request.client else None), limit)
    if retry is not None:
        raise HTTPException(429, "Rate limit exceeded",
                            headers={"Retry-After": str(max(1, math.ceil(retry)))})
