"""Real liveness checks for proxy nodes.

A bare TCP connect is a weak signal (it succeeds for any open port and is even
terminated locally by some egress tunnels), so every TLS-based node
(REALITY, TLS+WS/gRPC, trojan, vmess+tls) is checked with a full TLS handshake
using the node's own SNI.  Plain TCP nodes (shadowsocks, vless without TLS) get
a TCP connect.  UDP protocols (hysteria2, tuic) cannot be verified from here and
are reported as ``unverified`` rather than guessed.
"""

from __future__ import annotations

import asyncio
import os
import ssl
import time
from collections.abc import Awaitable, Callable

HEALTH_TTL = int(os.getenv("HEALTH_TTL", "900"))
HEALTH_TIMEOUT = float(os.getenv("HEALTH_TIMEOUT", "4"))
HEALTH_CONCURRENCY = int(os.getenv("HEALTH_CONCURRENCY", "150"))
UDP_TYPES = {"hysteria2", "tuic"}

# dedup_key -> {"ts": float, "alive": bool | None, "ms": float | None, "method": str}
_health: dict[str, dict] = {}


def probe_method(c: dict) -> str:
    """Which probe fits this node: ``tls``, ``tcp`` or ``none`` (UDP, cannot verify)."""
    if c.get("type") in UDP_TYPES:
        return "none"
    if c.get("is_tls") or c.get("is_reality") or c.get("security") in ("tls", "reality"):
        return "tls"
    return "tcp"


def _insecure_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def _handshake(host: str, port: int, sni: str, ctx: ssl.SSLContext, timeout: float) -> float:
    start = time.perf_counter()
    _, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ctx, server_hostname=sni or None), timeout
    )
    elapsed = (time.perf_counter() - start) * 1000
    writer.close()
    try:
        await writer.wait_closed()
    except (OSError, ssl.SSLError):
        pass
    return round(elapsed, 1)


async def tls_handshake(host: str, port: int, sni: str = "", timeout: float = HEALTH_TIMEOUT,
                        verify: bool = False) -> tuple[float | None, bool | None]:
    """Full TLS handshake: ``(ms, cert_ok)``; ``ms`` is None if it failed or timed out.

    With ``verify`` the certificate is validated against the SNI first (``cert_ok`` True/False);
    a node whose certificate does not validate is still alive, only ``cert_ok`` is False.
    """
    try:
        if verify and sni:
            try:
                return await _handshake(host, port, sni, ssl.create_default_context(), timeout), True
            except ssl.SSLCertVerificationError:
                return await _handshake(host, port, sni, _insecure_ctx(), timeout), False
        return await _handshake(host, port, sni, _insecure_ctx(), timeout), None
    except (TimeoutError, OSError, ssl.SSLError, ValueError):
        return None, None


async def tcp_connect(host: str, port: int, timeout: float = HEALTH_TIMEOUT) -> float | None:
    start = time.perf_counter()
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (TimeoutError, OSError):
        return None
    elapsed = (time.perf_counter() - start) * 1000
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return round(elapsed, 1)


async def check_node(c: dict, timeout: float = HEALTH_TIMEOUT) -> dict:
    method = probe_method(c)
    if method == "none":
        result = {"alive": None, "ms": None, "method": "none"}
    elif method == "tls":
        ms, cert_ok = await tls_handshake(c["host"], c["port"], c.get("sni") or "", timeout,
                                          verify=not c.get("is_reality"))
        result = {"alive": ms is not None, "ms": ms, "method": "tls", "cert_ok": cert_ok}
    else:
        ms = await tcp_connect(c["host"], c["port"], timeout)
        result = {"alive": ms is not None, "ms": ms, "method": "tcp"}
    result["ts"] = time.time()
    return result


async def check_nodes(
    nodes: list[dict],
    concurrency: int = HEALTH_CONCURRENCY,
    timeout: float = HEALTH_TIMEOUT,
    checker: Callable[[dict, float], Awaitable[dict]] | None = None,
) -> int:
    """Probe nodes concurrently; results land in the cache as each one finishes."""
    checker = checker or check_node
    sem = asyncio.Semaphore(concurrency)

    async def one(c: dict) -> None:
        async with sem:
            _health[c["dedup_key"]] = await checker(c, timeout)
            c["cert_ok"] = _health[c["dedup_key"]].get("cert_ok")

    await asyncio.gather(*(one(c) for c in nodes))
    return len(nodes)


def get(c: dict, now: float | None = None, max_age: float | None = None) -> dict | None:
    h = _health.get(c.get("dedup_key", ""))
    if not h:
        return None
    now = now or time.time()
    if max_age is not None and now - h["ts"] > max_age:
        return None
    return h


def needs_check(c: dict, now: float | None = None) -> bool:
    return get(c, now, HEALTH_TTL) is None


def summary(nodes: list[dict]) -> dict:
    alive = dead = unverified = unchecked = 0
    lat: list[float] = []
    for c in nodes:
        h = get(c, max_age=HEALTH_TTL * 2)
        if h is None:
            unchecked += 1
        elif h["alive"] is None:
            unverified += 1
        elif h["alive"]:
            alive += 1
            if h["ms"] is not None:
                lat.append(h["ms"])
        else:
            dead += 1
    lat.sort()
    return {
        "total": len(nodes),
        "alive": alive,
        "dead": dead,
        "unverified_udp": unverified,
        "unchecked": unchecked,
        "latency_ms_median": lat[len(lat) // 2] if lat else None,
        "latency_ms_p90": lat[max(0, int(len(lat) * 0.9) - 1)] if lat else None,
    }


def clear() -> None:
    _health.clear()
