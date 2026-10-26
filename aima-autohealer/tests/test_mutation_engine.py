"""Tests for the recipe-handler registry."""

from __future__ import annotations

import json

import pytest

from aima.mutation_engine import (
    SNI_POOLS,
    RecipeContext,
    get_handler,
    known_recipes,
)
from aima.types import BlockType


def _reality_inbound(*, port: int = 443, snis: list[str] | None = None) -> dict:
    snis = snis or list(SNI_POOLS[0])
    return {
        "id": 1,
        "port": port,
        "protocol": "vless",
        "streamSettings": json.dumps(
            {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": False,
                    "dest": f"{snis[0]}:443",
                    "serverNames": snis,
                    "shortIds": ["aaaaaaaa", "bbbbbbbb"],
                    "fingerprint": "chrome",
                    "privateKey": "old-priv",
                    "publicKey": "old-pub",
                },
            }
        ),
    }


def _stream(inbound: dict) -> dict:
    return json.loads(inbound["streamSettings"])


@pytest.mark.asyncio
async def test_rotate_sni_pool_advances_pool() -> None:
    ib = _reality_inbound(snis=list(SNI_POOLS[0]))
    ctx = RecipeContext(block_type=BlockType.SNI_BLOCK)
    result = await get_handler("rotate_sni_pool")(ib, ctx)
    assert result.changed
    new = _stream(result.inbound)["realitySettings"]["serverNames"]
    assert new in SNI_POOLS
    assert new != SNI_POOLS[0]


@pytest.mark.asyncio
async def test_rotate_sni_pool_exhausted() -> None:
    ib = _reality_inbound(snis=list(SNI_POOLS[0]))
    exhaust = {host for pool in SNI_POOLS for host in pool}
    ctx = RecipeContext(block_type=BlockType.SNI_BLOCK, exhaust_snis=exhaust)
    result = await get_handler("rotate_sni_pool")(ib, ctx)
    assert not result.changed


@pytest.mark.asyncio
async def test_switch_to_alt_port_picks_unused() -> None:
    ib = _reality_inbound(port=443)
    ctx = RecipeContext(block_type=BlockType.UNKNOWN, exhaust_ports={443, 8443})
    result = await get_handler("switch_to_alt_port_8443_2053")(ib, ctx)
    assert result.changed
    assert result.inbound["port"] not in (443, 8443)


@pytest.mark.asyncio
async def test_disable_udp_outbounds_only_for_udp() -> None:
    h = get_handler("disable_udp_outbounds")
    ib_tcp = _reality_inbound()
    assert not (await h(ib_tcp, RecipeContext(block_type=BlockType.QUIC_DROP))).changed

    ib_udp = {**_reality_inbound(), "protocol": "hysteria2", "enable": True}
    res = await h(ib_udp, RecipeContext(block_type=BlockType.QUIC_DROP))
    assert res.changed
    assert res.inbound["enable"] is False


@pytest.mark.asyncio
async def test_rotate_pubkey_changes_keypair() -> None:
    ib = _reality_inbound()
    ctx = RecipeContext(block_type=BlockType.REALITY_DETECT)
    res = await get_handler("rotate_pubkey")(ib, ctx)
    assert res.changed
    new = _stream(res.inbound)["realitySettings"]
    assert new["privateKey"] != "old-priv"
    assert new["publicKey"] != "old-pub"
    assert res.renderer_overrides == {"force_resub": True}


@pytest.mark.asyncio
async def test_regenerate_short_ids_produces_unique_hex() -> None:
    ib = _reality_inbound()
    res = await get_handler("regenerate_short_ids")(ib, RecipeContext(block_type=BlockType.REALITY_DETECT))
    new = _stream(res.inbound)["realitySettings"]["shortIds"]
    assert len(new) >= 8
    assert all(len(sid) == 8 for sid in new)
    assert len(set(new)) == len(new)


@pytest.mark.asyncio
async def test_fallback_cdn_ws_rewrites_transport(monkeypatch) -> None:
    monkeypatch.setenv("AIMA_CDN_FRONT_HOSTS", "edge.example.workers.dev")
    ib = _reality_inbound()
    res = await get_handler("fallback_cdn_ws")(ib, RecipeContext(block_type=BlockType.SNI_BLOCK))
    assert res.changed
    s = _stream(res.inbound)
    assert s["network"] == "ws"
    assert s["wsSettings"]["path"].startswith("/aima/")
    assert s["wsSettings"]["headers"]["Host"] == "edge.example.workers.dev"


@pytest.mark.asyncio
async def test_fallback_cdn_ws_without_front_host_is_noop(monkeypatch) -> None:
    monkeypatch.delenv("AIMA_CDN_FRONT_HOSTS", raising=False)
    ib = _reality_inbound()
    res = await get_handler("fallback_cdn_ws")(ib, RecipeContext(block_type=BlockType.SNI_BLOCK))
    assert not res.changed
    assert res.inbound == ib


@pytest.mark.asyncio
async def test_mimic_chrome_changes_fingerprint() -> None:
    ib = _reality_inbound()
    res = await get_handler("mimic_chrome_ja3")(ib, RecipeContext(block_type=BlockType.UNKNOWN))
    assert _stream(res.inbound)["realitySettings"]["fingerprint"] == "chrome"


def test_all_recipes_resolvable() -> None:
    for rid in known_recipes():
        assert callable(get_handler(rid))
