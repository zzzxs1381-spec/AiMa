"""Network probes that classify each attempt into a `BlockType`.

The probes are deliberately *transport-aware but proxy-agnostic*: they reproduce
the network-level signals that DPI / RKN TSPU operate on, so we can spot the
type of interference without needing a full sing-box / xray client.

Each probe returns a `ProbeReport` with `block_type` filled in.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import time
from datetime import UTC

import dns.asyncresolver
import dns.exception
import httpx

from .types import BlockType, ProbeProfile, ProbeReport, TransportKind, utcnow

# ─── Vantage point metadata ─────────────────────────────────────────────────


class Vantage:
    """A vantage point (where the probe runs from). Filled by deployment env."""

    def __init__(
        self,
        name: str,
        *,
        asn: int | None = None,
        provider: str | None = None,
        region: str | None = None,
    ) -> None:
        self.name = name
        self.asn = asn
        self.provider = provider
        self.region = region


# ─── Helpers ────────────────────────────────────────────────────────────────


def _now_ms() -> float:
    return time.perf_counter() * 1000.0


def _classify_socket_error(exc: BaseException) -> BlockType:
    """Map a low-level network exception to a BlockType."""

    if isinstance(exc, asyncio.TimeoutError | TimeoutError):
        return BlockType.TCP_TIMEOUT
    if isinstance(exc, ConnectionResetError):
        return BlockType.TCP_RST
    if isinstance(exc, ConnectionRefusedError):
        # explicit refusal looks like RST in our terminology
        return BlockType.TCP_RST
    if isinstance(exc, socket.gaierror):
        return BlockType.DNS_BLOCK
    if isinstance(exc, ssl.SSLError):
        # handshake failures during TLS often manifest as RST too, but we keep
        # them in their own bucket so the detector can see the SNI relationship.
        return BlockType.SNI_BLOCK
    return BlockType.UNKNOWN


# ─── Individual probes ──────────────────────────────────────────────────────


def _is_poisoned_answer(address: str) -> bool:
    """Sinkhole / stub answers typical for DPI DNS poisoning and fake-ip resolvers."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return (
        ip.is_unspecified
        or ip.is_loopback
        or ip.is_private
        or ip.is_reserved
        or ip in _FAKE_IP_NET
    )


_FAKE_IP_NET = ipaddress.ip_network("198.18.0.0/15")


async def probe_dns(profile: ProbeProfile, vantage: Vantage) -> ProbeReport:
    started = utcnow()
    t0 = _now_ms()
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = profile.timeout_seconds
    try:
        ans = await resolver.resolve(profile.host, "A")
        addresses = [r.to_text() for r in ans]
        poisoned = bool(addresses) and all(_is_poisoned_answer(a) for a in addresses)
        ok = bool(addresses) and not poisoned
        return ProbeReport(
            profile_id=profile.id,
            vantage=vantage.name,
            asn=vantage.asn,
            provider=vantage.provider,
            region=vantage.region,
            started_at=started.replace(tzinfo=UTC),
            duration_ms=_now_ms() - t0,
            success=ok,
            block_type=BlockType.NONE if ok else BlockType.DNS_BLOCK,
            rtt_ms=_now_ms() - t0,
            error="poisoned DNS answer (sinkhole/fake-ip)" if poisoned else None,
            raw={"addresses": addresses, "poisoned": poisoned},
        )
    except (dns.exception.DNSException, OSError) as exc:
        return ProbeReport(
            profile_id=profile.id,
            vantage=vantage.name,
            asn=vantage.asn,
            provider=vantage.provider,
            region=vantage.region,
            started_at=started.replace(tzinfo=UTC),
            duration_ms=_now_ms() - t0,
            success=False,
            block_type=BlockType.DNS_BLOCK,
            error=f"{type(exc).__name__}: {exc}",
        )


async def probe_tcp(profile: ProbeProfile, vantage: Vantage) -> ProbeReport:
    started = utcnow()
    t0 = _now_ms()
    try:
        async with asyncio.timeout(profile.timeout_seconds):
            reader, writer = await asyncio.open_connection(profile.host, profile.port)
        rtt = _now_ms() - t0
        writer.close()
        try:
            async with asyncio.timeout(1.0):
                await writer.wait_closed()
        except (TimeoutError, Exception):  # noqa: BLE001 — we already got our RTT
            pass
        return ProbeReport(
            profile_id=profile.id,
            vantage=vantage.name,
            asn=vantage.asn,
            provider=vantage.provider,
            region=vantage.region,
            started_at=started.replace(tzinfo=UTC),
            duration_ms=_now_ms() - t0,
            success=True,
            block_type=BlockType.NONE,
            rtt_ms=rtt,
        )
    except BaseException as exc:
        return ProbeReport(
            profile_id=profile.id,
            vantage=vantage.name,
            asn=vantage.asn,
            provider=vantage.provider,
            region=vantage.region,
            started_at=started.replace(tzinfo=UTC),
            duration_ms=_now_ms() - t0,
            success=False,
            block_type=_classify_socket_error(exc),
            error=f"{type(exc).__name__}: {exc}",
        )


async def probe_tls(profile: ProbeProfile, vantage: Vantage) -> ProbeReport:
    """Two-stage probe.

    1) Plain TCP connect — distinguishes IP-block / TCP-RST from SNI-block.
    2) TLS handshake with `profile.sni` (or profile.host) as ServerName.

    A successful TCP that fails on TLS with `sni` → SNI block.
    A successful TCP+TLS that then RSTs the channel within ~3s of any payload
    is reported as a possible REALITY-fingerprint detection.
    """

    sni = profile.sni or profile.host
    started = utcnow()
    t0 = _now_ms()

    # Stage 1: TCP
    try:
        async with asyncio.timeout(profile.timeout_seconds):
            reader, writer = await asyncio.open_connection(profile.host, profile.port)
    except BaseException as exc:
        return ProbeReport(
            profile_id=profile.id,
            vantage=vantage.name,
            asn=vantage.asn,
            provider=vantage.provider,
            region=vantage.region,
            started_at=started.replace(tzinfo=UTC),
            duration_ms=_now_ms() - t0,
            success=False,
            block_type=_classify_socket_error(exc),
            error=f"tcp_stage: {type(exc).__name__}: {exc}",
        )
    rtt = _now_ms() - t0

    # Stage 2: TLS upgrade
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we only care about handshake completion
    handshake_start = _now_ms()
    try:
        async with asyncio.timeout(profile.timeout_seconds):
            await writer.start_tls(ctx, server_hostname=sni)
        handshake_ms = _now_ms() - handshake_start

        # Stage 3 (optional): tiny payload to detect REALITY-style late reset.
        late_reset = False
        try:
            writer.write(b"GET / HTTP/1.1\r\nHost: " + sni.encode() + b"\r\n\r\n")
            await writer.drain()
            async with asyncio.timeout(3.0):
                await reader.read(64)
        except (TimeoutError, ConnectionResetError, ssl.SSLError, OSError):
            late_reset = True

        try:
            writer.close()
            async with asyncio.timeout(1.0):
                await writer.wait_closed()
        except (TimeoutError, Exception):  # noqa: BLE001
            pass

        return ProbeReport(
            profile_id=profile.id,
            vantage=vantage.name,
            asn=vantage.asn,
            provider=vantage.provider,
            region=vantage.region,
            started_at=started.replace(tzinfo=UTC),
            duration_ms=_now_ms() - t0,
            success=not late_reset,
            block_type=BlockType.REALITY_DETECT if late_reset else BlockType.NONE,
            rtt_ms=rtt,
            handshake_ms=handshake_ms,
            raw={"sni": sni, "late_reset": late_reset},
        )
    except BaseException as exc:
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass
        return ProbeReport(
            profile_id=profile.id,
            vantage=vantage.name,
            asn=vantage.asn,
            provider=vantage.provider,
            region=vantage.region,
            started_at=started.replace(tzinfo=UTC),
            duration_ms=_now_ms() - t0,
            success=False,
            block_type=BlockType.SNI_BLOCK,
            rtt_ms=rtt,
            error=f"tls_stage: {type(exc).__name__}: {exc}",
            raw={"sni": sni},
        )


async def probe_https(profile: ProbeProfile, vantage: Vantage) -> ProbeReport:
    """End-to-end HTTPS GET as a baseline. Catches HTTP_TAMPER / RKN block-page."""

    started = utcnow()
    t0 = _now_ms()
    sni = profile.sni or profile.host
    url = f"https://{profile.host}:{profile.port}/"
    try:
        async with httpx.AsyncClient(
            verify=False,  # noqa: S501 — we test transport, not cert chain
            timeout=profile.timeout_seconds,
            follow_redirects=False,
        ) as client:
            resp = await client.get(url, headers={"Host": sni, "User-Agent": "aima-probe/0.1"})
        ok_status = (
            profile.expected_status is None or resp.status_code == profile.expected_status
        )
        body = resp.text[:4096] if resp.headers.get("content-type", "").startswith(
            "text/"
        ) else ""
        tampered = any(
            marker in body.lower()
            for marker in ("rkn", "роскомнадзор", "доступ ограничен", "blocked-by-tspu")
        )
        return ProbeReport(
            profile_id=profile.id,
            vantage=vantage.name,
            asn=vantage.asn,
            provider=vantage.provider,
            region=vantage.region,
            started_at=started.replace(tzinfo=UTC),
            duration_ms=_now_ms() - t0,
            success=ok_status and not tampered,
            block_type=BlockType.HTTP_TAMPER if tampered else BlockType.NONE,
            rtt_ms=_now_ms() - t0,
            raw={"status": resp.status_code, "tampered": tampered},
        )
    except httpx.TimeoutException as exc:
        return ProbeReport(
            profile_id=profile.id,
            vantage=vantage.name,
            asn=vantage.asn,
            provider=vantage.provider,
            region=vantage.region,
            started_at=started.replace(tzinfo=UTC),
            duration_ms=_now_ms() - t0,
            success=False,
            block_type=BlockType.TCP_TIMEOUT,
            error=str(exc),
        )
    except (httpx.ConnectError, OSError, ssl.SSLError) as exc:
        return ProbeReport(
            profile_id=profile.id,
            vantage=vantage.name,
            asn=vantage.asn,
            provider=vantage.provider,
            region=vantage.region,
            started_at=started.replace(tzinfo=UTC),
            duration_ms=_now_ms() - t0,
            success=False,
            block_type=BlockType.SNI_BLOCK if isinstance(exc, ssl.SSLError) else BlockType.TCP_RST,
            error=f"{type(exc).__name__}: {exc}",
        )


async def probe_udp_quic(profile: ProbeProfile, vantage: Vantage) -> ProbeReport:
    """Best-effort UDP/443 reachability check.

    We don't speak QUIC here; we just send a tiny QUIC-Initial-shaped packet and
    see whether *any* response (including an ICMP unreachable that surfaces as
    OSError) comes back within `timeout_seconds`. The intent is to detect
    "UDP/443 100% drop" patterns common with RKN-grade QUIC throttling.
    """

    started = utcnow()
    t0 = _now_ms()
    loop = asyncio.get_event_loop()
    transport: asyncio.DatagramTransport | None = None

    class _Proto(asyncio.DatagramProtocol):
        def __init__(self) -> None:
            self.future: asyncio.Future[bytes] = loop.create_future()

        def datagram_received(self, data: bytes, addr: object) -> None:
            if not self.future.done():
                self.future.set_result(data)

        def error_received(self, exc: Exception) -> None:
            if not self.future.done():
                self.future.set_exception(exc)

    try:
        transport, proto = await loop.create_datagram_endpoint(
            _Proto, remote_addr=(profile.host, profile.port)
        )
        # crude QUIC-Initial-ish: long header byte + version + DCID len byte + 0s
        transport.sendto(bytes([0xC0]) + b"\x00\x00\x00\x01" + b"\x08" + b"\x00" * 16)
        try:
            await asyncio.wait_for(proto.future, timeout=profile.timeout_seconds)
            success = True
        except TimeoutError:
            success = False
        return ProbeReport(
            profile_id=profile.id,
            vantage=vantage.name,
            asn=vantage.asn,
            provider=vantage.provider,
            region=vantage.region,
            started_at=started.replace(tzinfo=UTC),
            duration_ms=_now_ms() - t0,
            success=success,
            block_type=BlockType.NONE if success else BlockType.QUIC_DROP,
            rtt_ms=_now_ms() - t0,
        )
    except OSError as exc:
        return ProbeReport(
            profile_id=profile.id,
            vantage=vantage.name,
            asn=vantage.asn,
            provider=vantage.provider,
            region=vantage.region,
            started_at=started.replace(tzinfo=UTC),
            duration_ms=_now_ms() - t0,
            success=False,
            block_type=BlockType.QUIC_DROP,
            error=f"{type(exc).__name__}: {exc}",
        )
    finally:
        if transport is not None:
            transport.close()


# ─── Dispatcher ─────────────────────────────────────────────────────────────


async def run_one(profile: ProbeProfile, vantage: Vantage) -> ProbeReport:
    if profile.kind is TransportKind.DNS:
        return await probe_dns(profile, vantage)
    if profile.kind is TransportKind.DIRECT_TCP:
        return await probe_tcp(profile, vantage)
    if profile.kind is TransportKind.DIRECT_TLS:
        return await probe_tls(profile, vantage)
    if profile.kind is TransportKind.DIRECT_HTTPS:
        return await probe_https(profile, vantage)
    if profile.kind in (TransportKind.UDP_QUIC, TransportKind.HYSTERIA2):
        return await probe_udp_quic(profile, vantage)
    if profile.kind is TransportKind.VLESS_REALITY:
        # Without a sing-box client locally we approximate VLESS+REALITY by:
        #  TLS handshake to host:port using the configured SNI, plus
        #  a late-reset detection (REALITY_DETECT) — see probe_tls().
        return await probe_tls(profile, vantage)
    return ProbeReport(
        profile_id=profile.id,
        vantage=vantage.name,
        started_at=utcnow(),
        duration_ms=0.0,
        success=False,
        block_type=BlockType.UNKNOWN,
        error=f"unsupported kind: {profile.kind}",
    )


async def run_batch(
    profiles: list[ProbeProfile],
    vantage: Vantage,
    *,
    concurrency: int = 16,
) -> list[ProbeReport]:
    """Run all probes for a vantage with bounded concurrency."""

    sem = asyncio.Semaphore(concurrency)

    async def _one(p: ProbeProfile) -> ProbeReport:
        async with sem:
            return await run_one(p, vantage)

    return await asyncio.gather(*[_one(p) for p in profiles])
