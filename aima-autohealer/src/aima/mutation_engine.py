"""Recipe handler registry.

Each recipe knows how to mutate a single 3X-UI inbound dict (and optionally
emit renderer overrides) in response to a classified incident. Handlers are
**pure**: they take an inbound dict and return a new inbound dict. Network
side-effects happen in `apply.py`, never inside a handler.

A handler signature:
    async def handler(inbound: dict, context: RecipeContext) -> RecipeResult

`RecipeResult.changed` indicates whether the handler actually produced a
different inbound; if it didn't (e.g. the SNI pool is already exhausted),
the orchestrator can move on to the next recipe.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from .types import BlockType

logger = logging.getLogger(__name__)


# ─── Curated SNI pools ──────────────────────────────────────────────────────

# Used by REALITY as `serverNames`. Order = priority. Each pool is a single
# TLS host families known to be CDN-served, popular enough that blocking them
# would cause collateral damage on legitimate traffic, and not in the RKN
# reestr at the time of writing.
SNI_POOLS: list[list[str]] = [
    ["www.cloudflare.com", "blog.cloudflare.com", "1.1.1.1"],
    ["www.fastly.com", "fastly.com"],
    ["www.cloudfront.net", "d111111abcdef8.cloudfront.net"],
    ["discord.com", "cdn.discordapp.com"],
    ["www.tiktokcdn.com", "p16-sign-va.tiktokcdn-us.com"],
    ["fonts.googleapis.com", "fonts.gstatic.com"],
    ["www.apple.com", "www.icloud.com"],
    ["www.bing.com", "outlook.office.com"],
    ["github.githubassets.com", "github.com"],
    ["www.gosuslugi.ru", "esia.gosuslugi.ru"],  # last resort for RU mobile
]


def _front_hosts_from_env() -> list[str]:
    """Real CDN front hosts (e.g. your CF Worker domain), comma-separated in AIMA_CDN_FRONT_HOSTS."""
    raw = os.environ.get("AIMA_CDN_FRONT_HOSTS", "")
    return [h.strip() for h in raw.split(",") if h.strip()]


CDN_FRONT_HOSTS: list[str] = _front_hosts_from_env()


ALT_PORTS: list[int] = [443, 8443, 2053, 2083, 2087, 2096]


# ─── Context ────────────────────────────────────────────────────────────────


@dataclass
class RecipeContext:
    block_type: BlockType
    profile_id: str | None = None
    vantage: str | None = None
    asn: int | None = None
    # SNIs/ports/hosts already tried (and failed) recently for this incident
    exhaust_snis: set[str] = field(default_factory=set)
    exhaust_ports: set[int] = field(default_factory=set)
    exhaust_fronts: set[str] = field(default_factory=set)
    note: str = ""


@dataclass
class RecipeResult:
    changed: bool
    inbound: dict
    notes: str = ""
    renderer_overrides: dict = field(default_factory=dict)


Handler = Callable[[dict, RecipeContext], Awaitable[RecipeResult]]


# ─── Registry ───────────────────────────────────────────────────────────────


_REGISTRY: dict[str, Handler] = {}


def register(recipe_id: str) -> Callable[[Handler], Handler]:
    def deco(fn: Handler) -> Handler:
        if recipe_id in _REGISTRY:
            raise RuntimeError(f"recipe {recipe_id!r} already registered")
        _REGISTRY[recipe_id] = fn
        return fn

    return deco


def get_handler(recipe_id: str) -> Handler:
    try:
        return _REGISTRY[recipe_id]
    except KeyError as exc:
        raise KeyError(f"unknown recipe {recipe_id!r}") from exc


def known_recipes() -> list[str]:
    return sorted(_REGISTRY)


# ─── Helpers for inbound dicts ──────────────────────────────────────────────


def _stream_settings(inbound: dict) -> dict:
    raw = inbound.get("streamSettings")
    if isinstance(raw, str):
        return json.loads(raw)
    if isinstance(raw, dict):
        return raw
    return {}


def _put_stream_settings(inbound: dict, settings: dict) -> dict:
    new = dict(inbound)
    new["streamSettings"] = json.dumps(settings, separators=(",", ":"))
    return new


def _settings_dict(inbound: dict) -> dict:
    raw = inbound.get("settings")
    if isinstance(raw, str):
        return json.loads(raw)
    if isinstance(raw, dict):
        return raw
    return {}


def _put_settings(inbound: dict, s: dict) -> dict:
    new = dict(inbound)
    new["settings"] = json.dumps(s, separators=(",", ":"))
    return new


def _next_pool(current: list[str], exhausted: set[str]) -> list[str] | None:
    """Pick the next SNI pool that isn't fully in `exhausted`."""

    for pool in SNI_POOLS:
        if pool == current:
            continue
        if not all(host in exhausted for host in pool):
            return pool
    return None


# ─── Recipes ────────────────────────────────────────────────────────────────


@register("rotate_sni_pool")
async def rotate_sni_pool(inbound: dict, ctx: RecipeContext) -> RecipeResult:
    settings = _stream_settings(inbound)
    reality = settings.get("realitySettings")
    if not isinstance(reality, dict):
        return RecipeResult(changed=False, inbound=inbound, notes="no realitySettings")
    cur = list(reality.get("serverNames") or [])
    new_pool = _next_pool(cur, ctx.exhaust_snis | set(cur))
    if new_pool is None:
        return RecipeResult(changed=False, inbound=inbound, notes="all SNI pools exhausted")
    reality["serverNames"] = new_pool
    reality["dest"] = f"{new_pool[0]}:443"
    settings["realitySettings"] = reality
    return RecipeResult(
        changed=True,
        inbound=_put_stream_settings(inbound, settings),
        notes=f"sni: {cur} → {new_pool}",
    )


@register("rotate_pubkey")
async def rotate_pubkey(inbound: dict, ctx: RecipeContext) -> RecipeResult:
    """Generate a new x25519 private/public key pair for REALITY.

    Note: regenerating REALITY keys invalidates already-distributed subscription URLs.
    The orchestrator must re-render all subs after applying this recipe.
    """

    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
        )
    except ImportError:
        return RecipeResult(
            changed=False,
            inbound=inbound,
            notes="rotate_pubkey requires `cryptography` package",
        )

    settings = _stream_settings(inbound)
    reality = settings.get("realitySettings")
    if not isinstance(reality, dict):
        return RecipeResult(changed=False, inbound=inbound, notes="no realitySettings")
    priv = X25519PrivateKey.generate()
    priv_b64 = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
    pub_b64 = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    reality["privateKey"] = priv_b64
    reality["publicKey"] = pub_b64
    settings["realitySettings"] = reality
    return RecipeResult(
        changed=True,
        inbound=_put_stream_settings(inbound, settings),
        notes="rotated REALITY x25519 keypair",
        renderer_overrides={"force_resub": True},
    )


@register("regenerate_short_ids")
async def regenerate_short_ids(inbound: dict, ctx: RecipeContext) -> RecipeResult:
    settings = _stream_settings(inbound)
    reality = settings.get("realitySettings")
    if not isinstance(reality, dict):
        return RecipeResult(changed=False, inbound=inbound, notes="no realitySettings")
    n = max(8, len(reality.get("shortIds") or []))
    new_ids = [secrets.token_hex(4) for _ in range(n)]
    reality["shortIds"] = new_ids
    settings["realitySettings"] = reality
    return RecipeResult(
        changed=True,
        inbound=_put_stream_settings(inbound, settings),
        notes=f"regenerated {n} shortIds",
        renderer_overrides={"force_resub": True},
    )


@register("change_dest_sni")
async def change_dest_sni(inbound: dict, ctx: RecipeContext) -> RecipeResult:
    settings = _stream_settings(inbound)
    reality = settings.get("realitySettings")
    if not isinstance(reality, dict):
        return RecipeResult(changed=False, inbound=inbound, notes="no realitySettings")
    cur_dest = str(reality.get("dest") or "")
    pool = _next_pool([cur_dest.split(":")[0]], ctx.exhaust_snis)
    if pool is None:
        return RecipeResult(changed=False, inbound=inbound, notes="all dests exhausted")
    reality["dest"] = f"{pool[0]}:443"
    reality["serverNames"] = pool
    settings["realitySettings"] = reality
    return RecipeResult(
        changed=True,
        inbound=_put_stream_settings(inbound, settings),
        notes=f"dest: {cur_dest} → {pool[0]}:443",
    )


@register("switch_to_alt_port_8443_2053")
async def switch_to_alt_port(inbound: dict, ctx: RecipeContext) -> RecipeResult:
    cur_port = int(inbound.get("port") or 0)
    for p in ALT_PORTS:
        if p != cur_port and p not in ctx.exhaust_ports:
            new = dict(inbound)
            new["port"] = p
            return RecipeResult(
                changed=True, inbound=new, notes=f"port: {cur_port} → {p}"
            )
    return RecipeResult(changed=False, inbound=inbound, notes="all alt ports exhausted")


@register("disable_udp_outbounds")
async def disable_udp_outbounds(inbound: dict, ctx: RecipeContext) -> RecipeResult:
    if (inbound.get("protocol") or "").lower() not in ("hysteria2", "tuic", "wireguard"):
        return RecipeResult(changed=False, inbound=inbound, notes="not a UDP transport")
    new = dict(inbound)
    new["enable"] = False
    return RecipeResult(
        changed=True, inbound=new, notes="disabled UDP-only inbound", renderer_overrides={"force_resub": True}
    )


@register("force_tcp_only")
async def force_tcp_only(inbound: dict, ctx: RecipeContext) -> RecipeResult:
    settings = _stream_settings(inbound)
    if settings.get("network") not in ("tcp", "raw", "xhttp"):
        settings["network"] = "tcp"
        return RecipeResult(
            changed=True,
            inbound=_put_stream_settings(inbound, settings),
            notes="network → tcp",
        )
    return RecipeResult(changed=False, inbound=inbound, notes="already TCP")


@register("enable_padding")
async def enable_padding(inbound: dict, ctx: RecipeContext) -> RecipeResult:
    settings = _stream_settings(inbound)
    settings["padding"] = True
    return RecipeResult(
        changed=True,
        inbound=_put_stream_settings(inbound, settings),
        notes="enabled padding",
    )


@register("force_doh_cloudflare")
async def force_doh_cloudflare(inbound: dict, ctx: RecipeContext) -> RecipeResult:
    return RecipeResult(
        changed=True,
        inbound=inbound,
        notes="forced DoH cloudflare via renderer override",
        renderer_overrides={"dns_strategy": "doh_cloudflare"},
    )


@register("force_doh_quad9")
async def force_doh_quad9(inbound: dict, ctx: RecipeContext) -> RecipeResult:
    return RecipeResult(
        changed=True,
        inbound=inbound,
        notes="forced DoH quad9 via renderer override",
        renderer_overrides={"dns_strategy": "doh_quad9"},
    )


@register("switch_doh_endpoint")
async def switch_doh_endpoint(inbound: dict, ctx: RecipeContext) -> RecipeResult:
    return RecipeResult(
        changed=True,
        inbound=inbound,
        notes="advance to next DoH endpoint via renderer override",
        renderer_overrides={"dns_strategy": "rotate"},
    )


@register("activate_backup_inbound")
async def activate_backup_inbound(inbound: dict, ctx: RecipeContext) -> RecipeResult:
    """Emit a renderer override flagging the (already provisioned) backup inbound to be used."""

    return RecipeResult(
        changed=False,
        inbound=inbound,
        notes="renderer override: prefer backup inbound for affected vantage",
        renderer_overrides={
            "prefer_backup": {
                "for_asn": ctx.asn,
                "for_vantage": ctx.vantage,
            }
        },
    )


@register("fallback_cdn_ws")
async def fallback_cdn_ws(inbound: dict, ctx: RecipeContext) -> RecipeResult:
    fronts = [h for h in (CDN_FRONT_HOSTS or _front_hosts_from_env()) if h not in ctx.exhaust_fronts]
    if not fronts:
        return RecipeResult(
            changed=False,
            inbound=inbound,
            notes="no CDN front host configured (set AIMA_CDN_FRONT_HOSTS) or all exhausted",
        )
    settings = _stream_settings(inbound)
    settings["network"] = "ws"
    settings["wsSettings"] = {
        "path": f"/aima/{secrets.token_urlsafe(6)}",
        "headers": {"Host": fronts[0]},
    }
    return RecipeResult(
        changed=True,
        inbound=_put_stream_settings(inbound, settings),
        notes=f"fallback to CDN-WS via {fronts[0]}",
        renderer_overrides={"prefer_cdn_ws": True, "force_resub": True},
    )


@register("switch_to_xhttp_path")
async def switch_to_xhttp_path(inbound: dict, ctx: RecipeContext) -> RecipeResult:
    settings = _stream_settings(inbound)
    settings["network"] = "xhttp"
    settings["xhttpSettings"] = {"path": f"/aima/{secrets.token_urlsafe(6)}", "mode": "auto"}
    return RecipeResult(
        changed=True,
        inbound=_put_stream_settings(inbound, settings),
        notes="switched to xhttp",
        renderer_overrides={"force_resub": True},
    )


@register("add_ipv6")
async def add_ipv6(inbound: dict, ctx: RecipeContext) -> RecipeResult:
    cur_listen = inbound.get("listen") or ""
    if cur_listen in ("::", "::0"):
        return RecipeResult(changed=False, inbound=inbound, notes="already dual-stack")
    new = dict(inbound)
    new["listen"] = "::"
    return RecipeResult(
        changed=True, inbound=new, notes=f"listen: {cur_listen!r} → ':: ' (dual-stack)"
    )


@register("switch_to_warp_relay")
async def switch_to_warp_relay(inbound: dict, ctx: RecipeContext) -> RecipeResult:
    return RecipeResult(
        changed=False,
        inbound=inbound,
        notes="renderer override: chain second hop via WARP relay",
        renderer_overrides={"second_hop": "warp"},
    )


@register("switch_to_hysteria2")
async def switch_to_hysteria2(inbound: dict, ctx: RecipeContext) -> RecipeResult:
    return RecipeResult(
        changed=False,
        inbound=inbound,
        notes="renderer override: prefer hysteria2 outbound",
        renderer_overrides={"prefer_outbound": "hysteria2"},
    )


@register("multipath_outbounds")
async def multipath_outbounds(inbound: dict, ctx: RecipeContext) -> RecipeResult:
    return RecipeResult(
        changed=False,
        inbound=inbound,
        notes="renderer override: enable multipath",
        renderer_overrides={"multipath": True},
    )


@register("mimic_chrome_ja3")
async def mimic_chrome_ja3(inbound: dict, ctx: RecipeContext) -> RecipeResult:
    settings = _stream_settings(inbound)
    reality = settings.get("realitySettings")
    if not isinstance(reality, dict):
        return RecipeResult(changed=False, inbound=inbound, notes="no realitySettings")
    reality["fingerprint"] = "chrome"
    settings["realitySettings"] = reality
    return RecipeResult(
        changed=True,
        inbound=_put_stream_settings(inbound, settings),
        notes="uTLS fingerprint → chrome",
    )


@register("mimic_safari_ja3")
async def mimic_safari_ja3(inbound: dict, ctx: RecipeContext) -> RecipeResult:
    settings = _stream_settings(inbound)
    reality = settings.get("realitySettings")
    if not isinstance(reality, dict):
        return RecipeResult(changed=False, inbound=inbound, notes="no realitySettings")
    reality["fingerprint"] = "safari"
    settings["realitySettings"] = reality
    return RecipeResult(
        changed=True,
        inbound=_put_stream_settings(inbound, settings),
        notes="uTLS fingerprint → safari",
    )
