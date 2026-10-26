"""Probe tests against localhost — no external network needed."""

from __future__ import annotations

import asyncio

import pytest

from aima.probe import Vantage, probe_dns, probe_tcp, probe_tls
from aima.types import BlockType, ProbeProfile, TransportKind


@pytest.mark.asyncio
async def test_tcp_to_closed_port_classifies_as_rst_or_timeout() -> None:
    profile = ProbeProfile(
        id="closed",
        label="closed port",
        kind=TransportKind.DIRECT_TCP,
        host="127.0.0.1",
        port=1,  # very unlikely to be open
        timeout_seconds=2.0,
    )
    r = await probe_tcp(profile, Vantage(name="v"))
    assert r.success is False
    assert r.block_type in (BlockType.TCP_RST, BlockType.TCP_TIMEOUT)


async def _close_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:  # noqa: BLE001
        pass


@pytest.mark.asyncio
async def test_tcp_to_listener_succeeds() -> None:
    server = await asyncio.start_server(_close_handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        profile = ProbeProfile(
            id="open",
            label="open port",
            kind=TransportKind.DIRECT_TCP,
            host="127.0.0.1",
            port=port,
            timeout_seconds=2.0,
        )
        r = await probe_tcp(profile, Vantage(name="v"))
        assert r.success is True
        assert r.block_type is BlockType.NONE
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_dns_unresolvable() -> None:
    profile = ProbeProfile(
        id="bad",
        label="unresolvable",
        kind=TransportKind.DNS,
        host="nonexistent-domain-aima-test-12345.invalid",
        timeout_seconds=3.0,
    )
    r = await probe_dns(profile, Vantage(name="v"))
    assert r.success is False
    assert r.block_type is BlockType.DNS_BLOCK


@pytest.mark.asyncio
async def test_tls_to_plain_tcp_classifies_as_sni_block() -> None:
    """A plain (non-TLS) listener should make probe_tls fail at TLS stage."""

    server = await asyncio.start_server(_close_handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        profile = ProbeProfile(
            id="tls-on-tcp",
            label="tls on plain tcp",
            kind=TransportKind.DIRECT_TLS,
            host="127.0.0.1",
            port=port,
            sni="example.com",
            timeout_seconds=2.0,
        )
        r = await probe_tls(profile, Vantage(name="v"))
        assert r.success is False
        # Either SNI block (TLS handshake fails) or REALITY-detect (handshake completed but RST).
        assert r.block_type in (BlockType.SNI_BLOCK, BlockType.REALITY_DETECT)
    finally:
        server.close()
        await server.wait_closed()


def test_poisoned_dns_answers_detected() -> None:
    from aima.probe import _is_poisoned_answer

    for addr in ("0.0.0.0", "127.0.0.1", "198.18.0.1", "10.10.34.36"):
        assert _is_poisoned_answer(addr)
    assert not _is_poisoned_answer("1.1.1.1")
